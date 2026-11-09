# Message history, key rotation and hiding WHEN messages were sent (plan, nothing built yet)

Decisions by the owner (2026-11-09): on **Android** messages are kept by default (default lifetime **1 day**, a message saved by hand is kept until the user deletes it); on **Linux**
the same feature exists as a **setting, off by default** (the terminal and the GUI stay RAM-only until the user switches it on). This plan says how to do it without making the phone
a better evidence box than it has to be. Inputs: an adversarial design review (Opus) of the idea, our own measurements (below), `docs/DELIVERY.md`, `docs/SECURITY_TRACKER.md` (OB-1..OB-10).
**Status: implemented (Rust core, bridge, Android UI, Keystore binding, erase job) and reviewed once (tracker review 33). Every claim marked (verify) still needs a real device.**

## 0. What an attacker with the phone sees, and what we try to hide
Attacker A: has the encrypted files (a copy of the app's private folder, or the whole flash image) but NOT the vault password. Attacker B: also has the password (coerced, or guessed).
We cannot stop B from reading what is currently stored; we CAN limit WHAT is stored (retention), make deletion as real as the platform allows, and keep A from learning WHEN messages were sent.
Not hidden, by design: that the app exists, and roughly when it last RAN (the system's own usage statistics already know that).

## 1. What leaks timing today, measured on ext4 (this machine; Android uses f2fs: verify there)
| Operation (what the store does) | mtime | ctime | birth time (btime) | inode |
|---|---|---|---|---|
| write in place | real time | real time | unchanged | same |
| `utimensat` with a FAKE mtime | **forged** | **real time (cannot be set from user space)** | unchanged | same |
| temp file + rename (our `write_atomic`, `crates/store/src/file.rs`) | real time | real time | **real time of the write** | new |
| plain touch | touch time | touch time | unchanged | same |
So the idea "edit the file every minute so the modified time is meaningless" has four holes, all confirmed or follows directly:
1. **ctime records the real moment of the last change and cannot be forged.** A write at 14:03:17 shows 14:03:17 in ctime even if mtime is forged. Only a rule "the file is ONLY ever touched on a fixed clock grid" removes the information.
2. **Our rename-based atomic write gives every write a new inode whose birth time is the write time.** Later touches do not erase it. Writes must happen in place (see 3) or every tick must rewrite the file.
3. **Heartbeat cadence must equal the grid.** If real writes happen when a message arrives and touches only every 60 s, the LAST timestamp is sometimes a real write time. Every operation on every file belongs on the grid, and every grid point touches every file.
4. **Size and counter also leak.** The rollback counter file is **plaintext** (`file.rs:186` writes `counter.to_le_bytes()`, verified) and it counts every save: with the outbox, and even more with history, it tells how many messages were sent or confirmed. The vault grows in 4 KiB steps.

## 2. Timing cover: grid-gated I/O
**Rule.** While the vault is open, ONE timer (the grid, period G) is the only thing that touches the vault file, the history file and the counter. On every tick, for each file: if there is
pending data, write it (in place); otherwise touch it (`utimensat(now)`, no data written). A message never causes a file operation by itself; it marks the data dirty and waits for the next tick.
Consequence: mtime and ctime of every file are always a grid time, equal to the last tick before the app stopped; they say "the app was running until about T", never "a message was sent at T".

**Choosing G.** The owner suggested 1 minute. Trade-offs:
| G | durable-before-confirm delay | send delay | cost |
|---|---|---|---|
| 60 s | up to 60 s before the contact's phone may confirm; the sender's check mark stays single for up to a minute | up to 60 s if we keep "persist before sending" | negligible I/O |
| 5 s (recommended default) | up to 5 s, inside the existing 1-5 s random confirmation delay | up to 5 s (also quantises our send times: a small plus against timing correlation) | a metadata-only touch every 5 s while the app runs; real data only when dirty |
Setting: "Timing cover: normal (5 s) / strong (60 s)". Never longer than the loss window we accept for a crash.

**Durability rule (from the review).** The receiver must NOT confirm a text before the history write holding it is durable (today `Engine::confirm` is called right after `push_line`, `app.rs` ~1830): otherwise a crash between receive and write loses a text the sender already considers delivered.
Implementation: queue confirmations, release them after the tick's `fsync`. The engine's random 1-5 s delay then runs after that, so network timing keeps its current shape (verify: the confirmation time becomes tick-aligned; use a per-install random phase so the grid is not a fingerprint).

**Writes in place, never rename (fixes hole 2).** `hist.bin` and the vault move to an A/B layout in a PRE-ALLOCATED file: two slots, each self-authenticating (AEAD), plus a small header with a generation number; write the inactive slot, fsync, bump the header
(one sector). Torn writes fall back to the older slot. The inode and its birth time never change. (Linux: same layout. Android f2fs is log-structured: user-visible times behave as above, but the file system keeps its own per-segment write times in internal tables (verify): out of reach of this plan, a raw-flash examiner may still see them.)

**Counter (fixes the plaintext leak).** Increase the counter by a random amount on each save (it only has to be monotone: `vault/src/lib.rs`), fixed-size file, and on Android store it encrypted under a Keystore key so it is opaque. Its times are on the grid too.

**Sizes.** `hist.bin` is padded to a fixed size (start at 1 MiB, grows only in big steps announced by a setting), so its size says nothing about the amount of history. The vault already pads to 4 KiB buckets (it shows roughly how many contacts: accepted).

**What stays visible after all this (honest).** The time the app last ran (to within G); that history exists and its maximum size; the number of contacts (vault size); block-level and file-system-internal timing on flash; and everything outside the files (Android usage statistics, battery stats, Tor traffic timing on the network). It hides WHEN MESSAGES WERE SENT from file metadata, nothing more.

**Wear.** Touch-only ticks write metadata only. If the vault file were still rewritten on every tick (to avoid the A/B step in an early version), 20 KiB x 17,280 ticks/day = ~345 MB/day at G = 5 s, ~29 MB/day at 60 s (before flash write amplification): acceptable only as a stop-gap.

## 3. Key hierarchy and "rotating keys"
**What rotating the vault's data key does and does not do.** The vault wraps one random data key DK under the password key; every saved copy carries its own salt and wrapped DK (`vault/src/lib.rs`, bytes 0..88) and the same password opens every copy. So a fresh DK on each sweep protects only against a stolen DK without the password (a memory dump of an old process), NOT against someone who finds an old copy of the vault on flash and has the password. A fresh salt per save would mean a 512 MiB Argon2 run per save. **Therefore DK rotation alone is not a crypto-erase and the UI must not claim it.** We still rotate DK on password change (exists) and we re-key the history on every epoch (below) because it is cheap and limits what one leaked key opens.

**What does give deletion: a key that can be destroyed without the password.**
```
password -> KEK -> DK (vault: identity keys, contacts, saved messages, settings)         [as today, written rarely]
history file hist.bin, one bucket per 6 h of messages, each bucket AEAD-encrypted under its own random key HK_b
HK_b is stored wrapped TWICE:  outer = under DK  (reading needs the password)
                               inner = under a platform key that EXPIRY can delete      (Android Keystore alias "hist-e<epoch>", AES-256-GCM, non-exportable, StrongBox when available)
```
- Reading history needs the password AND the platform key; **deleting the platform key makes every bucket of that epoch unreadable even for Attacker B with the password and old copies.** Epoch = 24 h; buckets 6 h; an epoch's alias is deleted when its last bucket has expired (real lifetime of a message: retention + up to one bucket, so 24-30 h at the 1-day default).
- Because the Keystore key does not need the vault password, a boot/periodic job can erase expired epochs **while the vault is locked or the app is not running** (without that, "1 day" would only hold while the app runs). Whether a background job runs reliably in Doze (verify) decides how strong the claim can be.
- Whether Keystore deletion is really irreversible depends on the device (hardware-backed, rollback resistance / StrongBox; verify on a Pixel with GrapheneOS). Where it is not, the UI says "best effort".
- Messages saved by hand move OUT of history into the vault (`SavedMsg`, existing caps) and are not subject to expiry. Saving needs a new Android action (not exposed yet: the bridge allowlist excludes `m`/`y`).
- **Linux has no such key store.** There: `HK_b` only under DK; expiry overwrites the bucket's region of the pre-allocated file IN PLACE with random bytes (a real overwrite on ext4/xfs, not on copy-on-write file systems or inside an SSD's remapping) and drops the key. Documented as best effort; recommend full-disk encryption with discard. This is why the Linux default stays OFF.
- Rejected: a hash ratchet whose current state is stored in the vault (old vault copies keep the old state, same weakness as DK rotation); one timestamp per message (more information, no benefit); history inside the main vault payload (every message write would copy every contact's private keys onto flash again).

## 4. Time, expiry, and what the app may promise
- Time source: device clock only, UTC seconds, never a network clock (it would leave Tor's discipline). `effective_now = max(wall_now, highest_time_ever_seen, high_water_at_unlock + monotonic_elapsed)`; the high-water mark is stored in the vault. A clock moved back changes nothing; moved forward expires early (acceptable, but an unsent outbox text that expires shows "EXPIRED, NOT SENT", never silently vanishes).
- Stored time: only the bucket (UTC hour / 6), never per message (an attacker B learns a 6-hour window per message and the high-water mark: roughly when the app last ran).
- Sweep (on unlock, on resume, on the grid every N ticks, and by the locked-erase job): drop buckets with `bucket_end + retention <= now`; delete their keys; mark expired outbox entries and CANCEL them in the engine (needs a new cancel-by-id call: today an expired text could still be delivered later, with no time on it, and look fresh); advance the high-water mark; write once on the grid.
- One global retention setting (Off / 1 day / 7 days) stored in the vault; per-contact overrides later. **No synchronised timers** (a new frame kind, tells the contact your policy, cannot be enforced on their phone). Each side applies its own policy.
- Never promise: "disappearing", "deleted for everyone", "deleted from your phone", "exactly 24 hours". Required text: "Kept on this phone for about a day (24-30 h), encrypted with your vault. Your contact's phone follows its own setting. Deleted messages may survive in the phone's storage. Anyone with your phone and password can read the last day. Messages you save (star) stay until you delete them."
- Documents that currently say the opposite and must change with the feature: README lines 15, 19, 20 ("RAM only", "no automatic history", "nothing is ever saved by itself"), `docs/ANDROID_PORT.md` section 0, the doc comment of `save_selected` (`app.rs` ~909); add to "Honest limits".

## 5. Staged plan (riskiest first; each stage ends with tests and a tracker entry)
| # | Stage | Can be verified here? |
|---|---|---|
| 1 | **Platform-key wrap and locked erase** on Android: Keystore alias per epoch, erase job, test deletion and rollback behaviour on a real Pixel/GrapheneOS. If deletion cannot be shown, ship Android with history default OFF and say why | needs a device |
| 2 | **Counter**: random increments, fixed size, encrypted on Android (small, independent, fixes a leak that exists TODAY with the outbox) | yes (Rust tests) |
| 3 | **Grid-gated I/O + in-place A/B files + touch ticks + padded sizes**, with an automatic TIMING-COVER TEST: run a scripted session that sends and receives messages at random moments, then `statx` every file and assert mtime/ctime/btime are grid times unrelated to the message times, and that sizes did not change | yes on ext4 (btime needs kernel support); f2fs to be checked on a device |
| 4 | **Durable-before-confirm**: queue confirmations until the tick's fsync; crash tests (kill between receive and tick) | yes |
| 5 | **History file** (`hist.bin`, SBS7-style versioned format, buckets, caps ~500 lines/contact and ~2 MiB total), seeding the chat view from it, saved-message move, purge and contact deletion shred it | yes |
| 6 | **Clock logic and sweep** with fuzzed clock jumps; engine cancel-by-id; outbox expiry states | yes |
| 7 | **UI and docs**: Android default ON (1 day), Linux setting OFF, the required texts above, README/ANDROID_PORT changes, tracker entries | partly (screenshots) |
| 8 | **Adversarial review of stages 1-6 by a stronger model BEFORE anything is called safe** | - |

## 6. Open questions for the owner
1. Grid period: 5 s (recommended) or 60 s (what you suggested)? It sets confirmation latency and the crash-loss window.
2. Accept the Android Keystore dependency for real deletion (and "best effort" labelling where the device cannot guarantee it)?
3. Move the existing encrypted outbox out of the vault payload into `hist.bin` (stops every send from re-copying contact keys onto flash; needs a format migration from SBS6)?
4. Linux: when the setting is on, is "best effort overwrite in place" an acceptable promise, or should it be refused on file systems we cannot overwrite (btrfs, ZFS, network mounts)?

## 7. Things this plan could not establish
Keystore deletion semantics per device (StrongBox / rollback resistance); whether f2fs (Android) keeps per-segment times a raw-flash examiner can read; whether deleted blocks are recoverable under Android file-based encryption; real flash and fsync cost and UI stalls on a phone (OB-9); Doze behaviour of the locked erase job; JVM-heap residue of rendered messages.
