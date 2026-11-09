# Security finding tracker

**Rule:** before starting each new stage, re-read this file. Anything `OPEN`/`PARTIAL` that the
new stage touches must be fixed in that stage or explicitly re-deferred here with a reason.
After every adversarial Opus review, append its findings here the same day.
Status: FIXED (with test) · PARTIAL · OPEN · ACCEPTED (documented risk) · INFO

## Review 1 — vault (commit 2ea5998)
| ID | Finding | Status | Notes |
|---|---|---|---|
| R1-C1 | Data key not rotated on credential change (old copy+old pw forges/reads future) | FIXED | `old_copy_cannot_read_or_forge_after_credential_change` |
| R1-H1 | Argon2 memory/H0 not wiped | FIXED | owned buffer, zeroize feature, wiped |
| R1-H2 | No locked/secret memory (mlock, memfd_secret, guard pages) | PARTIAL | MITIGATED by the swap guard (refuses to start with active swap unless `--allow-swap`; no swap => no hibernation image either) + no core dumps + non-dumpable. mlock/memfd_secret deferred: low added value once swap is off; cold-boot/RAM remanence is not addressed by mlock anyway. Dev machine note: a full swapfile means the guard fires until `sudo swapoff -a` |
| R1-M1 | Fixed plaintext header / fingerprintable | FIXED | no header, fixed profiles |
| R1-M1b | Wrap block constant between credential changes -> copies linkable | ACCEPTED | documented; fix needs KEK kept in RAM |
| R1-M2 | Plaintext length visible | FIXED | total file length bucketed (4 KiB) |
| R1-M3 | No rollback protection | PARTIAL | `open_checked` exists; **app must persist min counter outside vault** (open until app layer) |
| R1-M4 | No KDF floors | FIXED | fixed profiles; test profile only under cfg(test)/feature |
| R1-M5 | Header-chosen KDF cost DoS/abort | FIXED | no header params; MemAvailable guard |
| R1-L1 | Empty keyfile == none | FIXED | min 32 B + prehash |
| R1-L2 | Auth error merges wrong-pw/tamper | FIXED | `Tampered` variant |
| R1-L3 | change_credentials misuse | FIXED | returns blob, re-verifies old creds |
| R1-I1 | No version binding | FIXED | domain string in AAD |
| R1-I2 | Argon2 lanes without `parallel` feature | OPEN | calibrate profile on real live-boot HW; consider `parallel` |
| R1-I3 | Non-committing AEAD | ACCEPTED | irrelevant under offline-attacker model; revisit |

## Review 2 — core + vault (commit c321d5d)
| ID | Finding | Status | Notes |
|---|---|---|---|
| R2-H1 | No PQ forward secrecy (static KEM only) | FIXED | ephemeral ML-KEM via KKpsk0+psk2 |
| R2-M1 | Failed send burns counter, desync | FIXED | `failed_send_does_not_desync` |
| R2-M2 | msg1 replay yields live-looking session | FIXED | unconfirmed responder sessions; app MUST honour `is_confirmed()` |
| R2-M2b | No msg1 replay cache | FIXED (link layer) | `HandshakeGuard` replay cache (bounded, TTL, only after success) + confirmation-cell requirement in `net::link::accept`; app must keep ONE guard per onion service |
| R2-M3 | Noise/ML-KEM/plaintext buffers not zeroized | PARTIAL | our buffers+Signed fixed; `snow` is now vendored with Drop-time wiping (cycle 19, see D-3); ml-kem `DecapsulationKey` is `ZeroizeOnDrop` with the enabled `zeroize` feature (verified in the source, cycle 20) |
| R2-M4 | Rollback only informational | PARTIAL | see R1-M3 |
| R2-M5 | OOM kill on low-RAM open | FIXED | MemAvailable check |
| R2-L1 | Low-order X25519 accepted | FIXED | `check_dh_pub` in decode + handshake |
| R2-L2 | Weak Ed25519 / non-strict verify | FIXED | `is_weak` + `verify_strict` |
| R2-L3 | Timestamps trusted / fingerprint sender | FIXED | no timestamp on wire |
| R2-L4 | File size distinguishable | FIXED | |
| R2-L5 | Empty pw / error masking / old-cred check | FIXED | |
| R2-L6 | Initiator auth classical only | FIXED (session level) | responder now also encapsulates to the initiator's STATIC ML-KEM key (psk2 v2): both parties are PQ-authenticated by the session itself (test: classical key theft without the ML-KEM seed cannot impersonate either side). Per-message Ed25519 signatures stay as classical non-repudiation; ML-DSA not needed for authenticity. NEEDS REVIEW (composition) |
| R2-I1 | Noise prologue for version binding | FIXED | |
| R2-I2 | Counter overflow | FIXED | checked_add |
| R2-I3 | One-sided fingerprint | FIXED | `safety_number` (must also cover onion addr + client-auth key once in bundle) |
| R2-I4 | Plan reused signing key as onion identity | FIXED (plan) | implement as separate key in transport stage |
| R2-I5 | Responder CPU DoS per msg1 | PARTIAL | token-bucket rate limit before any crypto in `HandshakeGuard`; still needs Tor onion client-auth (net/tor stage) and a global connection cap |

## Dependency / supply-chain risks (standing)
| ID | Risk | Status | Notes |
|---|---|---|---|
| D-1 | `ml-kem` never independently audited (upstream says so) | ACCEPTED (hybrid with X25519) | revisit on audit |
| D-2 | `spake2` 0.4 (magic-wormhole's crate; not RustCrypto-audited) used for local pairing | ACCEPTED | second factor = safety number compare; revisit with audited CPace |
| D-3 | `snow` has no zeroize-on-drop | PARTIAL (cycle 19) | vendored `vendor/snow` (0.10.0 + Drop-time wiping of DH/cipher keys, chaining key/hash, PSKs, and of HKDF/DH/split temporaries; see vendor/snow/PATCH-NOTES.md). review 15 fixes: DH shared-secret/private-key temporaries, BLAKE2 `result()` temporaries and the Copy checkpoint wiped, per-call ChaCha key copy removed, version pinned `=0.10.0`. OPEN: dalek-internal copies, poly1305 state, blake2 internal buffers, compiler copies, no wipe on `panic=abort` |
| D-4 | all crates need `cargo-deny`/`cargo-vet` + pinned Cargo.lock + reproducible build | PARTIAL | DONE: `rust-toolchain.toml` pin (1.98.1), `scripts/repro-check.sh` (two builds in different dirs, `--locked`, path remapping: IDENTICAL sha256 on this machine). DONE (cycle 21, installed with the user's OK): `cargo deny check` = advisories ok, bans ok (duplicate versions only warn), licenses ok, sources ok; crates are `publish = false`. cargo-vet initialised (cycle 21, supply-chain/, imports from Bytecode Alliance, Google, Mozilla, Embark): 33 of 243 crates covered by imported audits, 210 are only EXEMPTED (nobody has reviewed them: this is bookkeeping, not assurance). OPEN: real audits of the exempted crates (priority: crypto, parsing, network crates) and a pinned set of trusted publishers, reproducibility across different machines/toolchain installs unverified, no CI |

## Exchange stage (pre-review self-notes)
- Pairing code = 10 digits, ONE online guess per code (burned on failure). App MUST regenerate the code after any failure and rate-limit attempts.
- File import yields `verified=false`; UI must force safety-number comparison before first chat.
- Bundle does not yet carry onion address / client-auth key (R2-I3): add in the net stage and cover by signature + safety number.

## Review 3 — exchange crate (commit 8299745)
No Critical/High. Crypto sound (no offline dictionary attack, no reflection, no KDF ambiguity). Findings:
| ID | Finding | Status | Notes |
|---|---|---|---|
| R3-M1 | "One guess per code" not enforced (listener re-parses code -> ~1265 guesses/s) | FIXED (see exchange stage 2) | `PairingOffer` consumed by one attempt, no parse-from-digits for listener, expiry, global failure backoff |
| R3-M2 | Symmetric SPAKE2: two sessions of one device cross-complete | FIXED | asymmetric roles (start_a/start_b), role bound in tags/AAD |
| R3-M3 | `verified=true` after PAKE although code knowledge != identity | FIXED | `Trust` enum: Unverified / CodeAuthenticated / SafetyVerified; never one bool |
| R3-L1 | No proof of possession of bundle secrets; unknown-key-share | FIXED | Ed25519 PoP signature over transcript + full KK handshake over the pairing stream |
| R3-L2 | No final confirmation; asymmetric outcomes | PARTIAL (review 4) | confirmation cells both ways, but the LAST cell is A's, so a dropped final cell can leave A committed / B failed. Docs corrected, useless post-I/O deadline check removed, Esc on the in-person prompt now keeps the pairing. Users must check both sides. |
| R3-L3 | Blocking I/O without deadline; write-before-read deadlock | FIXED (review 4 redo) | first version only bounded each call; now `Bounded` re-arms the timeout before EVERY read/write incl. link::dial/accept (test: slow-drip peer) |
| R3-L4 | Zeroization gaps (code String reallocs, display(), spake2 state) | PARTIAL | our code fixed; **spake2 0.4 does not zeroize** -> D-2 |
| R3-L5 | Trust state publicly mutable | FIXED | private fields, confirmation token |
| R3-I1 | Peer point validation (small-order / non-canonical accepted by spake2) | FIXED | rejected before finish |
| R3-I2 | Active MITM gets 2 guesses/code (not 1) | ACCEPTED | docs corrected; 2/10^10 |
| R3-I3 | Armor not canonical (line lengths, CRLF) | OPEN (low) | tighten or reword docs |
| R3-I4 | SPAKE2 classical: recorded transcript + future DL solver + brute force 10^10 links public keys to pairing event | ACCEPTED | note beside D-2 |
| R3-I5 | LAN attacker can burn codes (inherent DoS) | ACCEPTED | UI must say "pairing interrupted, possible attacker" |
| R3-I6 | Bundle (~1.8 KB armored) too large for easy QR (v37+) | OPEN | QR path later: consider hash-only QR + file |
| R3-I7 | KDF/tag use plain concat | FIXED | length-prefixed (verified by review 4) |

## Store + TUI stage (self-notes before review 4)
- R1-M3 now PARTIAL+: `VaultFile` persists/checks a counter file (default `<vault>.counter`, same disk => weak). Recommend `--counter-file` on the keyfile device. UI warns when no counter file existed.
- R1-I2: measured Strong profile = ~3.8 s create/unlock on 8-core dev box, single-threaded Argon2 (lanes not parallel). Calibrate on target hardware.
- Panic key: App drops vault (secrets zeroize on drop), buffers cleared, terminal screen+scrollback purged (ESC[3J) and process exits. NOT covered: `snow` only PARTIALLY covered (D-3: keys wiped on drop, some temporaries/dalek internals not), RAM remanence, terminal-emulator memory, other processes' copies, swap (no mlock yet: R1-H2).
- Password policy: >=12 chars (or keyfile); 3 wrong unlocks -> exponential UI delay (in-process only; offline attack unaffected — KDF is the defence).
- Dev fixes: tests run with optimized deps; `insecure-test-kdf` feature must never be enabled in release builds (CI check TODO under D-4).
- Not yet in TUI: chat, message history (by design none persisted), password change UI, QR export.

## Review 4 — exchange rework + store + TUI (commit 95c8845)
No Critical/High. Pairing crypto verified (no substitution/reflection/role-desync found). R3-L1/M1/M2/M3/I1 confirmed truly fixed.
| ID | Finding | Status | Notes |
|---|---|---|---|
| R4-M1 | Pairing deadline not total (slow-drip ~33 h); no cancel in TUI | FIXED | `Bounded` stream wrapper; test `slow_drip_peer_cannot_stretch_the_deadline`; TUI `x` cancels (socket shutdown) |
| R4-M2 | Panic wipe misses secrets (worker-thread identity clones, names, code Strings, ratatui buffers, crossterm buffers, stack copies) | PARTIAL | FIXED: workers cancelled+joined on panic, `Contact` names zeroized on drop, borrowed render rows, `pair_info` Zeroizing + drawn from &str, join code in fixed SecretBuf (never in `input`), both ratatui buffers blanked before exit. **OPEN:** crossterm internal 1 KiB tty buffer + parser Vec keep typed bytes for process lifetime; un-wiped stack copies in `identity.rs` (`Seed::from(*k)`, `to_bytes()`); typed contact names pass through `input: String`; per-frame `format!` copies of the pairing line; snow (R2-M3); no mlock (R1-H2) |
| R4-M3 | Import could freeze UI + panic key (FIFO, symlink to /dev/tty) | FIXED | `store::read_regular_file` (O_NOFOLLOW|O_NONBLOCK, fstat is_file, size cap) used for import, vault and counter reads; tests with FIFO/symlink// dev/zero |
| R4-M3b | Argon2 create/unlock runs on the UI thread (~4 s) so the panic key is unresponsive then | FIXED | KDF runs on a worker thread (`Screen::Working`, only F12/signals honoured); test `kdf_runs_off_the_ui_thread_and_panic_works_meanwhile`. Residual: the worker holds a `Zeroizing` copy of the password until Argon2 ends (not interruptible, ~4 s); on panic the process exits right after, and a result already in the channel is dropped (zeroized); a worker still running is killed by `process::exit` WITHOUT destructors, so password copy/Argon2 work area stay in freed RAM (see R8-L3) |
| R4-M4 | `panic=abort` + no core-dump suppression | PARTIAL | FIXED: RLIMIT_CORE=0 and PR_SET_DUMPABLE=0 at startup (rustix, no unsafe), verified via /proc/PID/limits. ACCEPTED: abort still skips Drop/zeroize on a panic; mitigated by no core dumps; mlock later |
| R4-L2 | `insecure-test-kdf` unified into release by `--all-targets` | FIXED | `compile_error!` in release builds (verified: `cargo build --release --all-targets` now fails). Add CI check under D-4 |
| R4-L3 | `write_atomic` predictable temp name, symlink-following | FIXED | random name, create_new, O_NOFOLLOW, chmod 0600, cleanup on error; test with planted symlink |
| R4-L4 | `create` overwrote existing counter file; attacker-lowered counter undetectable | PARTIAL | FIXED: create refuses when a counter file exists (`CounterExists`); UI warns when counter is on the same device. ACCEPTED: a writable counter file can be lowered — by design it is only as strong as the device holding it |
| R4-L5 | Listener banner fingerprint; 0.0.0.0/public listen allowed | FIXED | joiner (B) speaks first; listen only on loopback/private/link-local (test) |
| R4-L6 | Export filename leaked contact name | FIXED | neutral random `bundle-xxxxxxxx.sbc` |
| R4-L7 | SIGTERM/SIGHUP no wipe | FIXED | signal-hook flags -> same wipe as panic key; terminal read error also wipes; verified on release binary (leave-alt-screen, ESC[2J, ESC[3J) |
| R4-I1 | `Contact.trust`/`peer` are `pub` in store (type guarantee ends at exchange crate) | OPEN (low) | make private + `set_*` fns tied to confirm tokens |
| R4-I2 | Mixed-order SPAKE2 points accepted | FIXED | `is_torsion_free` |
| R4-I3 | Joiner can retry the same code (~6e-10) | ACCEPTED | UI never reuses a failed code (buffer cleared) |
| R4-I4 | Names with bidi/format chars | FIXED | rejected |
| R4-I5 | store decode doesn't check id uniqueness | OPEN (info) | needs the vault key to exploit |

## Transport stage (self-notes before review 5)
- Bundle v3 (SBC3) now carries onion pubkey + client-auth pubkey inside the signed body and safety number: **R2-I3 FIXED**.
- `snow` no longer pulls `ring` (C/asm) — musl static build works. Tracker D-4: still need cargo-deny/vet.
- Tor control/SOCKS code is parser-heavy and handles untrusted peers (a local process claiming to be tor): review 5 target.
- Not verifiable here without a real tor: ADD_ONION flag acceptance, ONION_CLIENT_AUTH_ADD syntax, SpawnedTor against real tor, behaviour on Tails. Covered by the ignored live test + `--probe-tor`; results from the user's machines pending.
- Control password auth is not exposed in the CLI yet (code path exists, tested).
- External-mode hosting forwards to a TCP 127.0.0.1 port: any local user can connect to it, so every inbound connection must pass the Noise handshake + HandshakeGuard (rate limit/replay) — the chat engine must wire one guard per onion service.
- **Live Tor test PASSED** on the project owner's machine (Tor 0.4.9.11): ADD_ONION with `Flags=V3Auth` + `ClientAuthV3`, `ONION_CLIENT_AUTH_ADD` (base64 x25519), SAFECOOKIE auth, spawn mode (unix sockets, RAM dir), SOCKS dial with isolation, and the full Noise/ML-KEM handshake over a real onion circuit all work. Tails behaviour still untested (deferred; plan in docs/BUILD_AND_RUN.md §8).

## Review 5 — Tor transport + onion identity (commit b4310a4); checked against a real tor 0.4.9.11 (DisableNetwork)
CONFIRMED CORRECT against real tor: ADD_ONION syntax (V3Auth + ClientAuthV3 + ED25519-V3 base64 key), tor's returned ServiceID == our `service_id()` (proves expanded key, SHA3 checksum, base32), ONION_CLIENT_AUTH_ADD (bare id + base64), SAFECOOKIE. Not testable offline: descriptor publication, SOCKS error codes, Tails/Whonix behaviour, SpawnedTor end-to-end.
| ID | Finding | Status | Notes |
|---|---|---|---|
| R5-H1 | External mode: nothing proves the control socket is really tor; a local squatter on 127.0.0.1:9051 (or a relay to a real tor) receives onion secret key + client-auth secret | FIXED (fix stage 5) | all auth now requires `peer_verified`: unix peer uid via SO_PEERCRED / TCP listener uid via /proc/net/tcp must be us, root or the owner of the system tor cookie; NULL/password never to an unverified peer; cookie path only from an allow-list or `--tor-cookie`; explicit opt-in `--tor-trust-control`; no silent fallback |
| R5-M1 | UTF-8 slicing panic on peer-controlled control reply (abort skips zeroize) | FIXED | byte-level parsing, tests with `ab€x`, `250€` |
| R5-M2 | Shared tor: other controllers can read our client-auth secret (ONION_CLIENT_AUTH_VIEW), see HS_DESC/STREAM events (links all contacts, isolation password) | PARTIAL | docs warn + prefer Spawn; neutral random SOCKS username, random per-process token. ACCEPTED residual: anything with control access to the system tor sees our secrets (inherent to External mode) |
| R5-M3 | `--probe-tor` double PROTOCOLINFO -> always "authentication FAILED" on real cookie tor | FIXED | `authenticate_with(info, ..)`; strict-server test |
| R5-M4 | Client auth does NOT hide the service existence; anyone with the onion address (a bundle!) can watch presence forever; docs wrongly claimed otherwise; 7345 constant port | PARTIAL | docs corrected, bundles are now treated as CONFIDENTIAL; `PoWDefensesEnabled`+`MaxStreams` added (with fallback). FIXED (cycle 16): per-contact onion/auth key rotation over the authenticated channel (`K`, docs/KEY_ROTATION.md; safety number unchanged; old+new service hosted until acked; tests incl. both directions through the TUI). live-Tor rotation test exists and passes (`key_rotation_works_over_real_tor`); a new service that fails to start is retried (cycle 22, test) and proposed only once it runs. ACCEPTED: random virtual port per contact (the port is only visible to the service and its authorized clients, the descriptor's inner layer is encrypted, so the constant 7345 is no remote fingerprint); vanguards: spawned tor ≥0.4.7 runs vanguards-lite by default, the full `vanguards` addon is NOT used (document; external tors do whatever the system does) |
| R5-L1 | Terminal escape injection via peer-supplied control strings in probe/UI | FIXED | control bytes rejected at the parser; all displayed strings sanitized |
| R5-L2 | Onion/auth secrets left in un-wiped heap copies (format!/base64 temporaries, SHA-512 output) | FIXED | commands built in pre-sized Zeroizing buffers, encode_slice, hash wiped |
| R5-L3 | Cookie path is attacker-chosen (probe for existence of 32-byte files, open device nodes) | FIXED | allow-list / explicit only, O_NOCTTY |
| R5-L4 | SOCKS error codes never fire without `ExtendedErrors` in spawn mode | FIXED | `SocksPort ... ExtendedErrors OnionTrafficOnly` |
| R5-L5 | No recovery after I/O error/timeout: stale reply read as the next answer | FIXED | controller marked broken after any I/O/protocol error |
| R5-L6 | Spawn hygiene: torrc-defaults, inherited env, relative PATH entries, no tmpfs check, stale RAM dirs after abort/SIGKILL | FIXED | `--defaults-torrc` empty, `env_clear`, absolute PATH entries + exec bit, tmpfs/ramfs statfs check, stale-dir sweep |
| R5-L7 | Socket path > 108 bytes makes tor fail generically | FIXED | validated up front |
| R5-L8 | Unparsable `--tor-control` silently ignored (falls back to squattable defaults) | FIXED | usage error |
| R5-L9 | `unquote` missed \r and octal escapes (non-ASCII cookie paths) | FIXED | |
| R5-L10 | Password sent in clear to a fake port offering only HASHEDPASSWORD | FIXED | same peer_verified gate |
| R5-I1 | Host onion on `unix:` target instead of 127.0.0.1 (tor accepts it — confirmed live) | FIXED (spawn mode) | `Target::Unix` in a 0700 dir; External mode still needs TCP loopback |
| R5-I2 | Stale doc comment in book.rs; SBS1 vaults fail as Corrupt (no migration) | FIXED / ACCEPTED | dev-only data |
| R5-I3 | Duplicate dependency versions (hmac/sha2/digest/base64/curve25519) | OPEN | add to cargo-deny (D-4) |

## Chat stage (self-notes before review 6)
- New: `nerd-chat-chat` (proto, transport, conn, engine) + TUI chat screens, online/offline toggle, `--tor-*` flags.
- C6-roles FIXED (see role-negotiation notes below): a designated host that cannot host flips to dialing; a dialer lazily hosts after repeated failed dials.
- C6-timing OPEN: 30 s keepalives + reconnect backoff are observable timing patterns; no constant-rate cover traffic.
- C6-queued-label FIXED (cycle 33): when the engine hands the queue to a new connection it emits `Event::Flushed` and the UI drops the "(queued)" label. This means "handed to the live connection", NOT "read by the contact": there are still no delivery receipts, by design.
- C6-flood OPEN (low): an authenticated peer can send messages as fast as the link allows; engine events channel is unbounded (UI drains every 200 ms; chat history capped at 500 lines; each message <= 32 KiB).
- C6-copies PARTIAL: message text lives in `Zeroizing<String>` (engine events, chat lines, outbox) and a fixed-capacity compose buffer; the on-screen copy of a sent message is a second wiped-on-drop String. NOT covered: ratatui's cell buffers (blanked at panic, but live while a chat is open), crossterm input buffer (R4-M2), `snow`'s internal buffers (R2-M3).
- Panic: engine shutdown is awaited for at most 400 ms; connection/acceptor threads end on their own afterwards; the process then exits.
- Verified by tests: both directions, ordering, offline queue, chunking, text cleaning, reconnect after either side restarts, impostor handshakes rejected, silent-peer idle timeout, remove/shutdown, outbox/input limits, two UIs end-to-end over an in-memory network, panic wipe, delete-while-online.

## Review 6 — chat engine + chat screens (commit 68e5b9f)
No Critical. Verified OK: only the pinned peer gets a session; no contact can impersonate or hijack another contact's connection; routing ids are fixed per thread by our side; role rule has no self-connect/impersonation path; two contacts with the same peer bundle do not collide; counters/replay checked; `Event` Debug never prints text; `busy` counter correct on all paths. Reach analysis: with v3 client auth a remote stranger cannot connect; spawn mode uses a 0700 unix socket; the exposed groups are (1) ANY local user in External mode (TCP 127.0.0.1 listener), (2) holders of our client-auth key (other controllers of a shared tor), (3) the contact.
| ID | Finding | Status | Notes |
|---|---|---|---|
| R6-M1 | Per-contact pre-auth token bucket (burst 5, 1 per 10 s) lets anyone who can connect lock the REAL peer out (garbage msg1 costs the same token); reconnect flapping alone throttles | FIXED | no pre-auth refusal per contact any more: replay cache only + an engine-wide CPU budget; External mode drops inbound loopback clients not owned by tor/us/root (`/proc/net/tcp` uid) |
| R6-M2 | Slowloris holds all 4 handshake slots (per-read timeouts only); real peer's streams dropped | FIXED | one TOTAL deadline per handshake (`DeadlineStream`), and when slots are full the OLDEST unauthenticated handshake is aborted so newcomers always get in |
| R6-M3 | Client-auth secrets never removed from tor (stay in the shared tor after delete/offline/exit; UI claimed keys deleted) | FIXED | `ONION_CLIENT_AUTH_REMOVE` on remove_contact, on going offline and in `Drop for Tor` |
| R6-M4 | Contact deleted while `Starting` stays live in the engine; its messages accepted under an invisible id | FIXED | reconcile engine against the vault on `Ready`; events for unknown ids ignored |
| R6-L1 | Events for unknown ids create hidden chat state | FIXED | |
| R6-L2 | Contact imported/paired while `Starting` never connects | FIXED | reconcile on `Ready` |
| R6-L3 | Plaintext left in freed heap while reassembling (buffer grows by realloc) | FIXED | fixed-capacity wiped assembler |
| R6-L4 | `clean()` misses many invisible/format/bidi characters (U+061C, U+2028/9, tag chars, variation selectors, Hangul fillers, private use, unbounded combining marks) | FIXED | shared `core::text` (also used for contact names), combining marks capped |
| R6-L5 | Chat view wraps by char count: wide (CJK) characters silently hidden | FIXED | wrap by display width |
| R6-L6 | Going offline blocks the UI up to 3 s (panic key dead meanwhile); second tor could start during teardown | FIXED | teardown on a worker thread, `Stopping` state |
| R6-L7 | A crafted bundle can reuse another contact's onion address and overwrite our client-auth entry for it | FIXED | contacts whose onion key collides with any other contact's (peer or own) are refused |
| R6-I1 | Stale Up/DialFailed after remove+re-add of the same id attaches an old connection to the new entry | FIXED | per-contact epoch checked on Up/DialFailed |
| R6-I2 | Spawn-mode unix socket files never unlinked (re-add fails with EADDRINUSE) | FIXED | |
| R6-I3 | Pending outbox lost silently if the connection dies before writing; "(queued)" implies more than is promised | FIXED on branch `next` (docs/DELIVERY.md), reviewed in review 24 (findings below) | per-text id + confirmation, unconfirmed texts kept in RAM and resent on every new connection, receiver drops repeats by id; still RAM-only (lost on quit/offline, both warn). NOT part of the audited v0.1.0 tag |

## PQ-auth stage notes (before review 7)
- Wire change: msg2 = ct_e || ct_i || noise2 (2224 bytes); psk2 label v2. Old binaries cannot talk to new ones: restart both sides.
- Swap guard added (`--allow-swap` to override); parse tested; behaviour when /proc/swaps unreadable: allowed.
- Still classical on purpose/for now: Tor itself (circuits, onion service keys), SPAKE2 pairing (transcript link only), Ed25519 message signatures (non-repudiation only).

## Review 7 — PQ initiator authentication (commit 18d13de)
No Critical/High/Medium. VERIFIED against snow 0.10 / ml-kem 0.3.4 sources: psk2 is mixed at the end of msg2 (`Token::Psk(2)` -> `mix_key_and_hash`), so the msg2 AEAD, the transport keys and the session id all depend on `ss_i`; every responder path (`accept`, `accept_shared`, pairing, chat) returns a session only after a valid first cell, which needs the initiator's static ML-KEM secret; KCI now needs two independent breaks; psk framing is unambiguous (fixed lengths, distinct labels); forged `ct_e`/`ct_i` fail identically (implicit rejection, constant-time select); no panic reachable from msg1/msg2; decrypting a recorded session needs (ephemeral ML-KEM secret or ML-KEM break) AND (ephemeral X25519 or DLog break) plus the static secrets.
| ID | Finding | Status | Notes |
|---|---|---|---|
| R7-L1 | `snow` never zeroizes (psk0/psk2, chaining key, DH outputs, transport keys stay in freed heap after a session) — now carries more secrets | PARTIAL (= R2-M3/D-3, cycle 19: vendored patch) | mitigations in place: swap guard, no core dumps, non-dumpable; real fix = patch/replace snow |
| R7-L2 | PQ-impostor test only checked the impostor's own `finish` | FIXED | `link` test: responder returns `Unconfirmed` for an impostor with all classical keys that sends a cell anyway |
| R7-L3 | `respond` returned a session that could already `send` | FIXED | unconfirmed sessions refuse `send` (`Error::Unconfirmed`) until the first valid cell arrives |
| R7-I1 | `finish(me)` did not check it is the identity that initiated | FIXED | |
| R7-I2 | Prologue/version not bumped after the msg2 format change (old initiators block until timeout) | FIXED | prologue `seburity-v2` (mixed versions now fail the handshake outright) |
| R7-I3 | B answers msg1 from anyone who can build one: a classical-key-holding attacker with onion reachability learns "B is online and answers A" (never a session) | ACCEPTED | pre-existing |
| R7-I4 | "ML-DSA not needed for authenticity" holds only INSIDE the session: Ed25519 signatures are forgeable by a quantum attacker, so signed material used OUTSIDE the session AEAD (exported transcripts, forwarded items, file sharing) would not be PQ-authentic | NOTE for file sharing | must authenticate via the session or add ML-DSA there |
| R7-I5 | Not verified by the reviewer: constant-time of ml-kem internals beyond the final select (no KyberSlash audit); PQ security of how `kem_pub` is first established (SPAKE2 pairing and Tor are classical); no fuzzing | OPEN | external audit item |

## Role negotiation notes (before review 8)
- Flip: designated host whose `add_contact(listen)` fails -> dials instead (credentials installed). Lazy hosting: dialer hosts after `host_fallback_after` (default 5) consecutive failed dials, once per contact per session; stays hosted until the contact is removed/offline.
- **DECIDED (see R12): capability bit in the bundle + per-contact opt-in; the timer-based lazy hosting was REMOVED.** Old note: lazy hosting weakens presence privacy; decide default (opt-in per contact? ask user in the UI? longer threshold? only fall back when the peer is known to be unable to host?) before any real use.
- PRIVACY TRADE-OFF (documented): a dialer whose peer is offline for a long time publishes a service for it; anyone holding that bundle (R5-M4) can then see it online. Setting `host_fallback_after = 0` disables it.
- Verified: unit tests (flip + lazy host + reconnect, no fallback when the peer hosts fine, fallback only after the threshold, both-cannot-host notice) and a LIVE test over real Tor where one side's tor refuses to host.

## Review 8 — role negotiation + KDF worker (commits b6e8da8, ea4d8c3)
No Critical/High. Opus review integrated:
| ID | Finding | Status | Notes |
|---|---|---|---|
| R8-M1 | A flipped side could later lazily host too (host+dial on both sides, duplicate connections) | FIXED | `fallback_tried` is set at the flip; test `a_flipped_side_never_starts_hosting_later`. OPEN (low): duplicate-connection tie-break is still "newest wins" (deterministic rule: keep the connection the smaller key dialed) |
| R8-M2 | Any dial failure counted toward lazy hosting (own outage, attacker-induced handshake aborts, own setup failure) | SUPERSEDED by R12 (lazy hosting code removed; PARTIAL before) | FIXED: only failures of the dial itself count (`unreachable`), handshake failures never do, no fallback if dial setup failed. OPEN: still counts SOCKS/network errors of our own (should count only onion-specific Tor extended errors 0xF0/F2/F3 and only when tor is healthy); own outage of ~90 s still makes us host. Part of R8-privacy |
| R8-privacy | Lazy hosting reveals presence to anyone holding our bundle | RESOLVED (see R12/R13) | decided: capability bit + opt-in `h`; timer removed |
| R8-L3 | Panic during `Working` leaves password copy, keyfile clone, Argon2 work area in freed RAM (exit skips destructors) | PARTIAL | `cfg.keyfile` now dropped in `panic_wipe`. Mitigation: boot with `init_on_free=1` (Tails has it). Could make panic wait for the worker (bounded) |
| R8-L4 | Panic during vault CREATE: worker may still write the vault/counter after panic or be cut mid-write (stray .tmp, counter without vault -> CounterExists) | FIXED (cycle 14) | `VaultFile::create_cancellable`: the panic wipe sets a cancel flag that is checked after the KDF and right before any write; test `a_cancelled_create_leaves_nothing_on_disk`. A write already in progress (microseconds) still completes; stray `*.tmp` sweep not done (blobs are encrypted) |
| R8-L5 | ADD_ONION for lazy hosting runs synchronously on the engine thread; a broken control connection silently disables DEL_ONION/auth removal (client-auth secrets stay in a shared tor); shutdown gives up after 3 s but UI says removed | SUPERSEDED by R12 (lazy hosting code removed; PARTIAL before) | FIXED: `Tor::healthy_ctl` opens a fresh authenticated control connection (ownership re-checked) before unhost/forget_dial/Drop when the old one is broken; test `cleanup_uses_a_fresh_control_connection_when_the_old_one_is_broken`. OPEN: ADD_ONION still synchronous on the engine thread; UI says "removed" after the 3 s give-up |
| R8-I6 | `Up` clears `dialing` while an outbound thread is in flight -> two overlapping dials | FIXED (cycle 14) | `dialing` now means 'outbound thread alive' and is cleared only by `DialEnded`, which the thread always sends last |
| R8-I7 | After a flip the designated dialer keeps dialing the never-existing onion | ACCEPTED (analysed after cycle 38) | No signalling is possible: after a flip NEITHER side hosts, so there is no channel to carry a 'I flipped' message, and a dial that fails looks identical for a flipped peer and an offline one. A slower cap (e.g. 10 min) would delay every normal reconnect after a peer was offline. Cost today: one SOCKS/HSDir lookup of the peer's onion address at most every 60 s (max_backoff), visible only to the user's own Tor and the HSDirs, no data of ours. The flipped side's notice already tells the user to set 'host anyway' on the other side, which ends the situation. Revisit if cover-traffic/timing work (C6-timing) changes the dial schedule |
| R8-I8 | "about a minute" is optimistic (SOCKS up to 120 s + 45 s handshake per attempt; sending resets backoff) | OPEN (docs) | |
| R8-I9 | `Screen::Working` has no cancel/timeout on a hung filesystem | OPEN (info) | F12/signals work |
| R8-I10 | `add_onion` error after a 250 reply leaves an untracked live service until control closes | OPEN | |
| R8-tests | missing tests: lazily hosted service removal on remove/offline/shutdown, `fails` reset on connection, create-path KDF + panic, TorTransport cleanup after flip | SUPERSEDED by R12 (lazy hosting code removed; OPEN before) | |

## Review 9 — file sharing (commits 90355cf..42afdf1)
No Critical. Opus review integrated:
| ID | Finding | Status | Notes |
|---|---|---|---|
| R9-H1 | "text" sniff accepted any UTF-8 document (RTF/SVG/EPS/GPX/ASCII PDF) with metadata untouched while UI said nothing to remove | FIXED | `Mode::Auto` (JPEG/PNG only) vs explicit `Mode::PlainText` (key `t`); structured documents refused even then; mode travels in the offer; receiver never auto-accepts text as binary; tests |
| R9-M1 | PNG with ~457k unique chunk types froze the UI/panic key via a giant report in the status line | FIXED | aggregate "other ancillary chunks" line, report capped at 16, status truncated to 300 chars |
| R9-M2 | text cleaner far weaker than `core::text` (tag chars, variation selectors, soft hyphen, ...) | FIXED | uses `is_unsafe_char` + combining cap; lone CR -> LF; test with tag-character payload |
| R9-M3 | allowlisted JPEG/PNG segments copied unvalidated (payload in DQT/DHT/SOS/DAC/DNL, PLTE) | PARTIAL | exact structural validation of DQT/DHT/SOF/SOS/DRI, DAC/arithmetic refused, DNL dropped, IHDR/PLTE/tRNS validated. FIXED later: zlib/deflate validator (exact stream, Adler-32, size from IHDR, bomb-bounded) closes the IDAT polyglot tail. OPEN: PRNU and DQT camera fingerprints, no protection of viewers from malicious image data (documented) |
| R9-L1 | wipe gaps: read buffers, reallocating outputs, conn threads not awaited on panic | PARTIAL | FIXED: `read_regular_file` pre-sized (no realloc copies), PNG/JPEG outputs pre-sized. FIXED later: engine stop waits (bounded) for live connection threads so their buffers drop. OPEN: text cleaner temporaries; typed path in `input: String` |
| R9-L2 | no RAM cap across contacts | FIXED | 24 MiB budget for received files (accepted + in RAM), one file per contact |
| R9-L3 | stale offers, silent replacement of unsaved files, "cleaned" overclaim | FIXED | `FileCancelled` event, offers cleared on disconnect, auto-decline while an offer/unsaved file exists, `r` discards, wording fixed; test |
| R9-L4 | failed save left partial file; relative default name | FIXED | unlink on error; absolute neutral path shown |
| R9-L5 | peer-driven status spam / overwriting warnings | PARTIAL | max 6 notices/min per connection, 6 bad frames then disconnect (test). FIXED (cycle 14): integrity/refusal/unexpected-data notices are `alert`s kept in a sticky red bar until acknowledged with `z` (max 5, wiped on panic) |
| R9-L6 | offer revealed exact length; decline timing is a presence oracle | PARTIAL | offer carries only the bucket (length inside the accepted stream). OPEN: manual vs auto-decline timing (documented) |
| R9-I | TooLarge message, stale doc claims, single-key accept without contact name | FIXED | message says 8 MiB, docs rewritten, accept/decline status names the contact |
| R9-open | fuzz harness / standalone strip / sandboxing | PARTIAL | DONE: deterministic mutation fuzz test (`mutated_inputs_never_panic`, 16k inputs per run), `nerd-chat --strip IN OUT`. FIXED (cycle 26): the parsers run in a helper process under a seccomp allowlist (`crates/sandbox`, one `unsafe` prctl call, user-approved) plus no_new_privs, rlimits, own session, kill-with-parent and a strict decoder for its answer (docs/FILE_SHARING.md). Reviewed by Opus (review 18, 31+ mutants, soundness of the single unsafe block confirmed), fixes in cycle 27. OPEN: x86_64 only (other targets refuse unless `--no-sandbox`), libFuzzer/cargo-fuzz target (needs nightly) |
| R10-self | while testing the new CLI I found the save error path unlinked an EXISTING file the user tried to overwrite (TUI save and `--strip`) and an arithmetic overflow in the PNG size calculation (panic = abort would kill the app) | FIXED | create_new first, only remove a file we created; u128 arithmetic; regression tests |

## Review 10 — file sharing, round 2 (commits b60636e, 8f24120)
No Critical, no panics (326k mutants through the zlib validator; 10,562 Python-zlib PNGs and 11 real JPEGs all accepted). Integrated:
| ID | Finding | Status | Notes |
|---|---|---|---|
| R10-H1 | CPU DoS: valid 8 MiB PNG of ~6.7M empty deflate blocks = 23 s (release) on the UI thread; per-chunk CRC table rebuild; bomb 3 s | FIXED | static fixed-Huffman and CRC tables, 20k-block cap, 4 s deadline inside the validator, raw-size cap 128 MiB, sender-side cleaning moved to a worker thread (`prepare_file`; panic key live); tests |
| R10-M1 | polyglots/payloads survive (ZIP in stored deflate block or after JPEG entropy data, repeated unused tables, PLTE/tRNS payloads); docs over-claimed | PARTIAL | FIXED: PLTE only for palette images, tRNS only with exact legal length, table-count caps, docs now say cleaning stops ACCIDENTAL leaks only. ACCEPTED/OPEN: a cooperating sender can still hide data in pixel streams (needs sandboxed decode + re-encode) |
| R10-M2 | replacing a connection dropped Down/FileCancelled as stale: UI kept "File arriving..." forever and leaked its 24 MiB budget; a contact could do it on purpose | FIXED | `FileCancelled` on replacement; test `replacing_a_connection_tells_the_ui_to_clear_file_state` |
| R10-L1/L2 | plain-text structured check only on input (leading ZWSP hid an RTF); combining cap bypass via removable chars | FIXED | check output too, removed chars no longer reset the run, shared `core::text::is_combining`; idempotence test |
| R10-L3 | `z`/`win`/error buffers not zeroized | FIXED | `Zeroizing` for the IDAT copy and the inflate window |
| R10-L4 | notice limiter swallowed security notices | FIXED | integrity/refusal notices bypass the limiter. FIXED (cycle 14): sticky alert bar |
| R10-I | fuzz test did not reach the validator; `--strip` ignored unknown flags | FIXED | CRC-fixing mutator (12k mutants/run), unknown flags rejected |

## Review 11 — file sharing, round 3 (commit 7f043e6)
No Critical/High; all Review-10 fixes verified (hostile-PNG worst case 2.2 s release; real PIL/libjpeg PNGs and JPEGs all accepted). Integrated:
| ID | Finding | Status | Notes |
|---|---|---|---|
| R11-M1 | deleting a contact left their unsaved received file in RAM (unreachable, counted against the budget) | FIXED | inbox/offers/accepted cleared on delete; test |
| R11-M2 | going offline left stale offers/accepted (UI stuck on "File arriving", later offers auto-declined) | FIXED | cleared on offline and on new engine Ready; `r` also clears a stuck state; test |
| R11-L1 | 20k-block cap refused valid PNGs (memLevel=1, per-row sync flush); 4 s deadline hardware-dependent | FIXED | only EMPTY blocks capped (2000), total 1M, deadline 8 s (cleaning is off the UI thread). Known: a much slower machine may still refuse a huge hostile-shaped valid PNG after transfer |
| R11-L2 | structured-text refusal bypassed by NBSP/ideographic space/combining marks; e-mail headers not caught; docs overclaimed | FIXED | skip all blanks/format/combining chars; RFC822 header detection; test |
| R11-L3 | error-path copies of images not wiped | FIXED | `Zeroizing` output buffers in jpeg/png/text |
| R11-I | misleading palette report text; `--strip` runs before the swap check; replaced-connection transfers vanish without a notice | PARTIAL | report text fixed; FIXED (cycle 14): `--strip` applies the swap refusal (`--allow-swap` to override) and non-dumpable hardening. OPEN: notice on replacement |
Round 4 not run: remaining items are minor; run one before wider use.

## Role decision (R8-privacy resolved) — bundle v4 capability + host-anyway (this commit)
| ID | Item | Status | Notes |
|---|---|---|---|
| R12-1 | Lazy (timer) hosting removed; roles from signed `can_host` bit in bundle v4 (`SBC4`), `--cannot-host`; `h` = per-contact "host anyway" (vault format SBS3, SBS2 still readable) | DONE | tests: capability decides roles with no speculative publishing, `host_anyway` explicit choice, flipped side never hosts, both-cannot notice, vault roundtrip + SBS2 compatibility, bundle signature covers the bit, pairing/file carry it |
| R12-2 | Capability excluded from the fingerprint/safety number (so both sides compute the same number from keys only); authenticated only by the bundle self-signature + the pairing proof | ACCEPTED | |
| R12-3 | A malicious contact can claim "cannot host" to make us host for them (presence visible to holders of their bundle). Inherent (no other way to connect); visible in the UI | ACCEPTED/documented | |
| R12-4 | A wrong bit (claims can host, Tor refuses): the other side must switch on `h`; not automatic by design | ACCEPTED | |
| R12-5 | The capability is chosen by the user (`--cannot-host`); it is not probed automatically at export | FIXED (review 25) | with `--tor-control`, the first export/pairing runs a throwaway ADD_ONION probe on a worker thread; see review 25 for the hardening |

## Review 12 — capability/host-anyway change (commit 8f85714); fixes
No Critical/High. Integrated:
| ID | Finding | Status | Notes |
|---|---|---|---|
| R13-M1 | roles used today's `--cannot-host`, not what we told this contact: later flag changes gave silent no-connect or both-host/nobody-dials | FIXED | per-contact `adv_can_host` fixed at first export/pairing (vault bits 5/6), used for roles and for every later export; tests. FIXED (cycle 14): details pane warns when today's flag differs from what the contact was told. OPEN: a corrected peer bundle still cannot be re-imported (delete + re-pair) |
| R13-M2 | `h` re-added the contact: dropped the queued outbox, the live connection and republished | FIXED | re-add keeps `pending`; `h` re-adds only when we dial (the only case it changes anything); test |
| R13-L1 | `--cannot-host` still published when neither could host | FIXED | a side that cannot host never listens; test |
| R13-L2 | stale signed bundle with the other bit can be replayed (bit not in the safety number) | PARTIAL | exports for one contact always carry the same bit; a replayed OLD bundle file only exists if the user exported differently before this fix. ACCEPTED otherwise |
| R13-L3 | failed save left memory and vault out of step; could not switch host-anyway OFF under --cannot-host | FIXED | revert on failure; OFF always allowed |
| R13-L4 | stale lazy-hosting rows in this tracker | FIXED | marked superseded |
| R13-I | UI did not show our actual role | FIXED | details show "YOU host for it while online" / "you only dial"; wasted dials by a host-anyway side to a flipped peer: OPEN (info) |
Not re-reviewed after these fixes (small, test-covered).

## Review 13 (Opus, commits 195a1d3..b0a26c1) — integrated in cycle 15
| ID | Finding | Status | Notes |
|---|---|---|---|
| R14-M1 | `h` pressed while going online was not applied to the starting engine: the engine published a service while the UI said host-anyway was off | FIXED | `h` is refused while `Starting`/`Stopping`; test |
| R14-M2 | a malicious contact could flood the sticky alert bar with "unexpected file data", evict real alerts; alerts did not name the contact | FIXED | "unexpected file data" is a plain (rate-limited) notice again; alerts name the contact, identical repeats are counted `(xN)`, at most 5 distinct, never evicted, overflow counted; test |
| R14-L1 | vault-create cancel flag misses the write window (F12 mid-write leaves a tmp/vault) | PARTIAL | panic waits up to 1.2 s for a create worker so `write_atomic` can finish or clean its temp file. OPEN (info): a process kill inside the write still can leave a tmp blob (encrypted) |
| R14-L2 | `advertised()` ignored a failed save (memory `Some`, vault `None`) | FIXED | `commit_advertised` reverts and the export is cancelled (file removed) / pairing undone |
| R14-L3 | the advertised bit was fixed even if nothing was sent (export to an existing path, bind failure, failed join) | FIXED | the bit is read-only until the file was written / the pairing was accepted; test |
| R14-I | roles line ignores the engine's flip; `h` while connected drops the connection; `--strip` must be first arg; alert line not wrapped, `z` only on main screen | OPEN (info) | |

## Review 14 (Opus, e53f0c9 key rotation) — integrated in cycle 17
| ID | Finding | Status | Notes |
|---|---|---|---|
| R15-M1 | a contact could force endless OFFER/DONE pairs: vault writes + DEL/ADD_ONION of OUR service (circuit churn) | FIXED | one accepted rotation per contact per hour, DONE never re-adds, 6 frames/connection; test |
| R15-L1 | peer has no fallback to our old onion; a pending rotation cannot be cancelled; if the new service cannot be hosted later the switched contact cannot reach us | PARTIAL (cycle 18) | FIXED: a switched dialer falls back to the old address while `peer_old` is set (client-auth installed for it, forgotten on remove; test). OPEN: retry of ADD_ONION for the new service; no cancel on purpose (strands a switched peer); the old address stays published while pending (documented) |
| R15-L2 | collision check ignored pending/previous keys and auth keys | FIXED | covers our current+pending onion/auth and other contacts' current+previous; test |
| R15-L3 | old signed bundles are indistinguishable from current ones (transport keys left the safety number); export while pending carried the retiring address | ACCEPTED (cycle 18) | export refused while pending. A signed generation counter was evaluated and REJECTED: the replay it targets is a fresh import after deleting a contact, where no earlier generation is remembered, so the counter would protect nothing; within a live relationship the authenticated session already prevents replays. Mitigation = documentation: never re-import old bundle files, exchange a fresh bundle when re-adding someone |
| R15-L4 | a silent contact blocked OUR rotation | FIXED | `peer_old` no longer blocks `K`; test |
| R15-L5 | safety numbers silently changed on upgrade | FIXED | fingerprint domain tag v2 (old numbers do not match); documented. R2-I3 ("must also cover onion addr + client-auth") is deliberately superseded: those keys are authenticated by the bundle signature/pairing and the session itself uses sign/dh/kem |
| R15-L6 | UI said "old service is gone" although DEL_ONION errors are ignored; rotation errors bypass the notice limiter | PARTIAL | wording corrected. OPEN: `unhost` result not surfaced |
| R15-I | MemTransport ignores client auth (peer_old authorization when the DIALER rotates is only traced, not tested); temporary identity copies unzeroized (R2-M3/R4-M2); SBS4 is a one-way vault upgrade | OPEN (info) | |

## Review 16 (Opus, 9e02c15..ec9ad7a: dial fallback + service retry) — integrated in cycle 23
| ID | Finding | Status | Notes |
|---|---|---|---|
| R16-1 | the fallback to the peer's old address (and our client-auth credential for it) survived the end of its rotation: needless dials, stale credential in a shared tor until restart | FIXED | the peer's DONE announcement of keys equal to those we dial drops the fallback and forgets the credential without any re-add; test with a recording transport |
| R16-2 | tests did not prove "proposed only after the service runs" / the fallback credential handling | FIXED | the retry test asserts the new service already ran when the OFFER arrives; the fallback-end test asserts the forget call |
| R16-3 | the retry could never recover from a broken control connection and promised "retrying" | PARTIAL | broken-connection errors stop the retry and say to go offline/online. OPEN: healing swaps the control connection and tor drops all non-detached services (pre-existing `healthy_ctl` hazard, R8-L5 area) |
| R16-4/5 | fixed 60 s retry, no cap/jitter; fallback setup failure was silent | PARTIAL | failure now produces a notice. OPEN (minor): jitter/cap; ADD_ONION still synchronous on the engine thread (R8-L5) |

## Review 17 (Opus, f4e8993 cleaning helper) — integrated in cycle 25
| ID | Finding | Status | Notes |
|---|---|---|---|
| R17-1 | HIGH: docs/code/tracker claimed the rlimits sandbox a compromised parser (they do not: fd slots can be freed, mmap writes, unlink, execve, signals, /dev/tty) | FIXED (claims) | all claims corrected; `no_new_privs`, `setsid`, death signal, all-limits-or-die, refuse root added; real containment = seccomp/Landlock (open, user decision) |
| R17-2 | parent could block forever in `child.wait()` after the helper closed stdout | FIXED | `try_wait` loop under the 25 s deadline, then kill |
| R17-3 | helper could outlive a panic wipe/exit holding plaintext | FIXED | PR_SET_PDEATHSIG(SIGKILL) in the helper (fires when the spawning thread/parent ends) |
| R17-4 | unzeroized copies (decoded data on error paths, worker buffers skipped by `process::exit`) | FIXED | wiped on the error paths; worker drops its buffers before exit |
| R17-I | setrlimit errors ignored; rustix `unshare` (network namespace) is `unsafe` so it was NOT added | FIXED/INFO | limit failures abort the helper; no netns without `unsafe` |

## Review 18 (Opus, 5929fac seccomp sandbox crate) — integrated in cycle 27
| ID | Finding | Status | Notes |
|---|---|---|---|
| R18-M1 | `mmap` accepted any fd: a compromised parser could map (read/write) every inherited non-CLOEXEC descriptor | FIXED | `mmap` only with MAP_ANONYMOUS and without PROT_EXEC; tests (spec, grid, kernel: file-backed private/shared mmap die) |
| R18-M2 | nothing tested that the shipped helper installs the filter | FIXED | tui test asserts `Seccomp: 2` / `Seccomp_filters: 1` of the live helper (verified by mutation: replacing `enter()` now fails the test); `scripts/sandbox-check.sh` runs the static musl binary end to end |
| R18-L1 | `clock_gettime` accepted any clock id incl. other processes' CPU clocks (side channel) | FIXED | only ids 0..=15 (high word 0); kernel test with the parent's CPU clock id |
| R18-L2 | grid missed high words equal to later comparison values (2 surviving mutants) | FIXED | high-word x other-args grid; surviving m+3/m+4 jump mutants proven equivalent (they land on instructions that re-test the same non-zero high word and still KILL) |
| R18-L3 | kernel tests could pass for the wrong reason or hang (getppid forbidden, int80 eax, thread-only kill, missing marker, no_new_privs inherited) | FIXED | pid/exe fd prepared before the filter, int80 uses eax=11 (only the arch check kills it), 20 s deadline, per-case markers, no_nnp skipped when already set |
| R18-L4 | user not told why every file is refused where seccomp is unavailable | FIXED | dedicated exit code 4 -> explicit message mentioning `--no-sandbox` |
| R18-L5 | musl mallocng calls `mprotect` when `brk` fails -> helper killed | ACCEPTED | fails closed, rare (near the 1 GiB cap); documented |
| R18-I | single-unsafe promise not enforced; PDEATHSIG race; seccomp kills are logged; vendor/snow has test-only unsafe | FIXED/INFO | `tests/hygiene.rs` enforces exactly one `unsafe {` + SAFETY comment + no asm/extern/transmute; helper checks it was not re-parented; the kernel log trace is documented; vendor/snow's two test-only unsafe lines are not in the shipped code |

## Review 19 (Opus, 072bfc4 delta re-review of the sandbox) — integrated in cycle 28
Verdict of the reviewer: the filter is exactly the intended allowlist (proved by hand, 41 instructions), the single unsafe block is still sound, 493 instruction-level mutants: 86 survived and all 86 are equivalent (jt/jf on LD/RET instructions the kernel ignores, or jumps that land on a re-test of the same non-zero high word / from one KILL to another).
| ID | Finding | Status | Notes |
|---|---|---|---|
| R19-M1 | a compromised parser can call `exit_group(4)` (allowed) and so FORGE the helper's "no sandbox here" exit code: the app would then advise `--no-sandbox` | FIXED | exit 4 is never taken at face value: a probe helper with a benign request must also exit 4, otherwise the message is "failed abnormally: may be an attack" without any advice to disable the sandbox; 3 unit tests (honest machine, forger, crash) |
| R19-L1 | the `getppid()==init` orphan test refused legitimate setups (app as PID 1 in a container) and missed subreapers | FIXED | the parent passes its pid (`NERD_CHAT_PARENT`), the helper requires `getppid()` to equal it (skipped when started by hand) |
| R19-L2 | `tests/hygiene.rs` was evaded by spacing/comment/attribute/`#[path]` tricks | FIXED | token-based check on comment- and string-stripped source: exactly one `unsafe` token, `unsafe_code` exactly twice, no asm/extern/transmute/include/path/mod/static, single source file, no build script; 8 evasion variants verified to be caught |
| R19-L3 | kernel tests for `execve` (loader died for another reason) and `ptrace` (TRACEME hung the run) could not detect an allowed syscall | FIXED | execve of a nonexistent path, PTRACE_PEEKDATA, bounded kill-and-poll; verified: allowing either syscall now fails the kernel test with code 77 |
| R19-I | jump-bound check skipped JGE; tui test assumed exactly 1 filter; MAP_LOCKED permitted under a raised inherited RLIMIT_MEMLOCK; sandbox-check does not prove `--strip` used the helper | FIXED/INFO | JGE checked; the test compares against the runner's own filter count + 1; the helper sets RLIMIT_MEMLOCK=0; the last item stays (the separate `--clean-worker` probe checks the filter) |

## UI overhaul (cycle 29): privacy screen
| ID | Item | Status | Notes |
|---|---|---|---|
| UI-1 | the 3rd Esc shows a privacy screen (Enter unlocks without a password, q quits); the app keeps running underneath | ACCEPTED (by design) | it is NOT authentication: the vault stays unlocked in RAM and anyone at the keyboard can press Enter; documented in the help popup, GETTING_STARTED and ROADMAP. While locked only the lock view is drawn (no names/messages/counts; tests assert no leak), every key except Enter/q/F12 is swallowed (also for prompts raised underneath). OPEN (optional): idle auto-lock, password-protected unlock |
| UI-2 | typing mode: nothing typed in Insert mode can act as a command; panic key works in every mode/pane/lock | FIXED (REOPENED by review 20 H1, fixed again in cycle 30: a finishing pairing no longer opens a prompt by itself) | tests `typed_text_in_insert_mode_never_acts_as_a_command`, `panic_key_works_in_every_mode_pane_and_in_the_lock` |
| UI-3 | one source of truth for the open contact (`sel`): commands always act on the contact shown (the old `sel`/`chat_with` drift is gone) | FIXED | test `contact_commands_work_in_normal_mode_while_a_chat_is_open_and_act_on_the_shown_contact` |

## Review 20 (Opus, fdae33b TUI overhaul) — integrated in cycle 30
| ID | Finding | Status | Notes |
|---|---|---|---|
| R20-H1 | HIGH: a pairing that finished while the user typed opened the "in person?" prompt, switched them to Normal mode and stole the next keys: a `y` upgraded trust (CodeAuthenticated), then blind typing ran commands (`o`, `h`, `K`, `d`+yes, `e`, `n`...); chat text also landed in the plain `input` String | FIXED | `poll()` never opens a prompt: the finished pairing waits in `pending_pair` and raises a sticky alert; the user answers with `P` (Normal mode only); a second pairing cannot start meanwhile; test with a REAL TCP pairing finishing mid-typing |
| R20-L1 | `q` on the privacy screen skipped the quit guard | FIXED | routed through the guard; the lock screen shows a generic "press q again" line (no counts/names) |
| R20-L2 | quit guard was wrong both ways (`queued` is never cleared, missed files being cleaned, pairing, drafts) | FIXED | counts queued lines only of contacts that are NOT connected, files in RAM or being cleaned, a pairing in progress/unanswered, a draft; wording says "may lose" |
| R20-L3 | scroll offset not clamped in the app (`g` then `j` looked dead) | FIXED | the frame reports the real limit, `poll()` clamps; tests |
| R20-L4 | narrow terminals never showed details; the chat never showed file offers | FIXED | narrow: list over details; chat header shows the file offer/received-file line |
| R20-L5 | Esc used to quit: muscle memory now leaves the vault open behind a screen without a password | ACCEPTED | stated in help/docs and on the lock screen itself ("the vault stays open"); optional idle auto-lock / password unlock remain in ROADMAP |
| R20-I | dead code, per-frame name copy in the sidebar, unread not counted under popups | FIXED | removed; sidebar renders borrowed names; unread counts unless the chat is really shown |
Mutants that survived the review's mutation run (lock view drawing status/pairing code, scroll reset on send, panic keeping quit_armed, guard ignoring files) now have tests.

## Review 21 (Opus, cleanup 3f38afd..HEAD and the rename tooling) — integrated in cycle 31
Verdict of the reviewer: the refactor preserves behaviour, security and privacy (removed API had no callers, the pairing lockout was never global in the TUI, the connection-generation gating is identical, H1 intact, no wire/disk constant changed, 246 tests, test names identical).
| ID | Finding | Status | Notes |
|---|---|---|---|
| R21-M1 | the rename script did chained boundary-free replacements: not idempotent, corrupted trees for overlapping names (`nerd-chats`, `a`, `core`...), swallowed a failing `cargo update` | FIXED | one regex pass with identifier boundaries, names must be >= 4 chars and neither contain nor be contained in the current one, refuses a name that already occurs in the tree, context decides kebab vs snake for single-word names, a failing `cargo update` restores `project-name.txt` and exits non-zero; verified: renaming through `kiwi-talk` -> `talk2chat` -> `symbolon` -> `nerd-chat` restores the tree byte for byte |
| R21-L1 | dangling reference to a renamed vendor patch file | FIXED | neutral name `vendor/snow/PATCH-NOTES.md` |
| R21-L2 | the generic `ramtor-` RAM-directory sweep could delete a foreign tool's directory; stale pre-rename `seburity-` directories never swept | FIXED | only directories with OUR `owner.pid` of a dead process are removed (no timing-based branch any more), both prefixes |
| R21-L3 | default vault path changed (`seburity.vault` -> `nerd-chat.vault`) | FIXED | falls back to an existing `./seburity.vault` with a note; the legacy names are frozen labels |
| R21-L4/L5 | weakened identity-rotation assertion, stale doc comments | FIXED | assertion restored, comments cleaned |
| R21-I | `ConnEvent::Ev` outer/inner id are not tied | OPEN (info) | conn.rs always passes the same id |

## Fuzzing (cycle 32)
| ID | Item | Status | Notes |
|---|---|---|---|
| FZ-1 | libFuzzer targets for the cleaner, the bundle/contact-book decoders and the peer frame parsers (`fuzz/`, `docs/FUZZING.md`) | FIXED | the first runs (3.3 M executions of `strip`, ~175 k of `formats`, ~100 k of `frames`) found ONE bug: text consisting only of removable characters "cleaned" to an empty file that the receiver then refused with an integrity alert (now refused by the sender; regression test). Longer runs: strip 4.9 M, formats 384 k, frames 534 k executions, and a new `tor_parsers` target (control replies, PROTOCOLINFO, SOCKS5; 979 k): no further crash. OPEN: hours-long runs before a release, targets for the vault opener and the Noise handshake responder |

## Saved messages and purge (cycle 33)
| ID | Item | Status | Notes |
|---|---|---|---|
| SV-1 | the user can save single messages into the vault by hand (`m`, `y`); never automatic | ACCEPTED (by design, user decision) | stored encrypted in the vault (SBS5), no timestamp, caps 500 per contact / 4 MiB total, refused in `--ram` mode, shown only in the Saved view (`H`), deleted with `d d` or with the contact, wiped from RAM on panic. Honest limits: whoever has vault + password reads them; messages are signed by the contact, so a saved copy can prove authorship to third parties; old vault copies on flash may keep deleted entries (wear levelling); each save rewrites the vault (counter bump). Saved text sits in RAM (zeroizing) while the vault is open |
| SV-2 | `Store::encode` reserves its final size (no reallocation copies of keys and saved messages in freed heap) | FIXED (re-fixed in cycle 34) | the first estimate was too small for a contact in the middle of a key rotation (review 22 L-1); now computed from the real constants, test asserts the capacity never changes |
| PG-1 | PURGE (Ctrl+] / Shift+F12): panic-lock plus overwrite-and-delete of the vault, rollback counter, keyfile, leftover `<vault>.*.tmp` files and the files exported/saved this session; no confirmation; also from the password prompt | ACCEPTED (by design, user decision) | tests: files gone, foreign files untouched, symlinks only unlinked, report counts. Limits: flash wear levelling may keep old blocks (a purge destroys the keyfile and counter too, so a strong password plus keyfile is what protects an already copied vault); files created outside this session (earlier exports, files you copied) are not known and stay; an accidental Ctrl+] destroys the vault: keep a backup of the vault ONLY if you accept that risk |

## Review 22 (Opus, queued label + manual saving + purge) — integrated in cycle 34
Verdict of the reviewer: nothing CRITICAL/HIGH; in the code nothing reaches the vault or disk without the explicit save key, but the tests did not prove it and four MEDIUM issues remained.
| ID | Finding | Status | Notes |
|---|---|---|---|
| R22-M1 | a message arriving while the message cursor was active shifted the cursor: the WRONG (possibly unread) message could be saved | FIXED | `push_line` keeps the cursor on the same message; if the 500-line cap drops it, the cursor goes away; tests |
| R22-M2 | after "SAVE FAILED" the vault FILE could still contain the message (vault written, counter write failed) | FIXED | memory is rolled back, the save is retried once to bring the file back in line, and the status says so honestly either way; test with a read-only counter directory |
| R22-M3 | purge did not destroy a symlinked keyfile (only the link) yet counted it as destroyed | FIXED | the keyfile path is canonicalized at start-up and every symlink target is shredded before the link; test |
| R22-M4 | docs overclaimed that deleting/purging is final | FIXED (docs) | every save leaves the old vault version in free blocks on ANY filesystem; CoW filesystems are not overwritten at all; keyfile on separate media + strong password is the real protection |
| R22-L1 | the `encode` capacity estimate was too small during a key rotation | FIXED | see SV-2 |
| R22-L2 | the ★ stayed after deleting a saved message and blocked saving it again | FIXED | cleared with the delete; test |
| R22-L3 | `Flushed` cleared "(queued)" on lines whose messages the engine had dropped; going offline left lines "queued" although the queue is gone | FIXED | only the newest `count` lines count as handed over, the rest (and everything after going offline) show "(NOT SENT)"; test |
| R22-L4 | the purge `.tmp` scan matched files like `v.my-notes.tmp` | FIXED | exactly `<vault>.<16 lowercase hex>.tmp` |
| R22-L5 | purge counted missing files as failures | FIXED | missing = nothing to do |
| R22-L6 | purge also shreds exported bundles and saved received files of this session; a shared keyfile is destroyed | ACCEPTED | disclosed in the docs; the owner asked for "everything else" |
| R22-L7 | `H` discards a draft | ACCEPTED | RAM-only text, same as leaving a chat |
| R22-I | shred checks the opened file against the earlier lstat (dev/ino) | FIXED | a swapped-in file is not overwritten (still unlinked) |
| R22-tests | surviving mutants: autosave on receive/send, decode caps, rollbacks, wrong delete index, select kept on panic, purge tracking of saved files, unlink on failed overwrite, small estimate | FIXED | tests drive real traffic and compare the vault FILE bytes, check all three decode caps, the Saved-view delete index, panic wiping the cursor, unlink-after-failure, the capacity |

## Lost terminal (cycle 35)
| ID | Item | Status | Notes |
|---|---|---|---|
| LT-1 | when the terminal vanished (window closed, ssh dropped, tmux killed) the app did NOT exit: crossterm's event reader loops forever on `read(0) = 0` inside ONE `event::poll` call, so our SIGHUP/lost-terminal handling was never reached: the process burned 100% CPU indefinitely with the vault OPEN in RAM (and a Tor child running when it was online). Found when the owner saw seven such processes (left behind by my own UI tests) | FIXED | the main loop checks the terminal itself (`input_ready`: poll for hangup/error and for readable-with-nothing-to-read = EOF) before crossterm is asked to read, so it never reads a dead terminal; a watchdog thread force-exits two seconds after the terminal hangs up if the main loop has not reacted; test with a socket pair (alive / byte waiting / hung up); verified in tmux: the app exits within one second of `tmux kill-server`, offline and online (its Tor child exits with it) |

## Lost terminal (cycle 35)
| ID | Item | Status | Notes |
|---|---|---|---|
| LT-1 | when the terminal vanished (window closed, ssh dropped, tmux killed) the app did NOT exit: crossterm's event reader spins forever inside `event::poll` once its tty returns EOF (`read(0) = 0` in a tight loop), so our SIGHUP/lost-terminal handling was never reached: a process at 100% CPU for hours with the vault open in RAM (found on the owner's machine: 7 leaked instances, each also holding a `tor`) | FIXED | the main loop checks the terminal itself (`input_ready`: hangup/error/EOF = terminal gone -> normal wipe-and-exit path) before crossterm is asked to read; a watchdog thread force-exits two seconds after a hangup if the main loop did not react; test with a socket pair, and verified end to end in tmux (online and offline: exits within 1 s). Honest note: a killed instance (SIGKILL) cannot wipe or remove its RAM directory: the next start sweeps `ramtor-*`/`seburity-*` directories of dead owners |

## Review 23 (Opus, delta 3568db6..f0b62aa, before the first release) — integrated in cycle 36
Verdict of the reviewer: nothing CRITICAL/HIGH; four MEDIUM issues, all reproduced, all fixed.
| ID | Finding | Status | Notes |
|---|---|---|---|
| R23-M1 | purge followed planted symlinks (`v.<hex>.tmp -> ~/thesis.txt`) and destroyed what they point to (regression of R22-M3) | FIXED | links are never followed (only unlinked); created files carry (dev, ino) and are destroyed only if still the same file; test `purge_spares_planted_links_and_files_that_replaced_ours` |
| R23-M2 | a read-only (chmod 400) keyfile was only unlinked, content intact | FIXED | owner chmods 0600 and retries; test with a hard-link witness |
| R23-M3 | the screen kept showing contacts/messages until all shredding finished (seconds for big files / slow sticks) | FIXED | `purge_prepare` (RAM) -> blank screen -> `purge_finish` (files) |
| R23-M4 | pasted text containing byte 0x1D purged the vault (0x1C panic-locks, a pasted Esc switched modes) | FIXED | bracketed paste enabled; a paste is literal text for the message line in Insert mode and ignored everywhere else; test `pasted_text_is_never_a_command`. ACCEPTED: Ctrl+4/Ctrl+5 and Ctrl+\ / Ctrl+] are neighbours, a slip under stress destroys the vault (owner's choice, PG-1) |
| R23-L1 | already-read input was processed at 5 events/s | FIXED | drain without waiting while crossterm has a backlog |
| R23-L2 | watchdog could exit without the wipe | FIXED | it first raises the signal flag, force-exits 3 s later only if the main loop is stuck. RESIDUAL: a hang-up exactly between our check and crossterm's read can still trap the main thread; the watchdog then exits without wipe (no Drop; External-tor client-auth cleanup is skipped) |
| R23-L3 | purge missed counter temp files | FIXED | scanned next to the counter too |
| R23-L4 | stale target list during a vault create | FIXED | targets are looked up after the wipe |
| R23-L5 | Enter in the message cursor saved the newest message | FIXED | only `y` saves |
| R23-L6 | imported bundle files are not purged | ACCEPTED | documented |
| R23-I | OsStr compared lossily; duplicate targets; tracker had LT-1 twice | FIXED (raw bytes, dedup); LT-1 duplicate left as history |

## Delivery confirmation (branch `next`, after the v0.1.0 audit snapshot) — self-notes, review PENDING
Adds `KIND_MSG_ID`/`KIND_MSG_ACK` and resend (docs/DELIVERY.md). For the reviewer: (1) can a peer make us show a text twice or never
confirm one (dedup window 256, replaced connections, re-add carrying `seen`)? (2) can ack/id frames be abused for resource use or as a
side channel (ack for unknown ids is a no-op; malformed ones cut the connection; one extra fixed-size cell each)? (3) is anything now
kept longer in RAM than before (up to 50 x 32 KiB per contact until confirmed, wiped on drop/shutdown)? (4) does the quit guard
and going offline still account for every unconfirmed line? Status: reviewed in review 26 (below).

## Default vault location (branch `next`) — self-notes, review PENDING
`crates/app/src/vault_path.rs`, `main.rs::default_vault`. Trade-off accepted and visible: the default vault now sits on the computer's disk
at a predictable path (easier to find in a forensic look than a vault on a USB stick the user chose); the first run says so and waits for
Enter, and Tails gets an explicit warning (home is erased at shutdown). Checks: the directory is created 0700, an existing one must be a real
directory (no symlink), owned by us and not group/world-writable (other users could swap the vault or its rollback counter). A relative
`$XDG_DATA_HOME` or `$HOME` is ignored (XDG rule). The choice never depends on the current directory once a default vault exists; if a
`./nerd-chat.vault` also exists it is named in a note and ignored. `--ram` now wins over `--vault` (before, `--ram --vault X` silently wrote to X).
Not done: the purge leaves the (empty) directory; the counter file still defaults to sit beside the vault. Status: OPEN until reviewed.

## Review 24 (Opus, delivery confirmation, commit 9282b40) — integrated on branch `next`
No critical/high. Nothing was re-reviewed after the fixes yet.

| # | Finding | Status | Fix / note |
|---|---|---|---|
| R24-M1 | a v0.1.0 peer never confirms: after 50 texts every send says "outbox full", every reconnect resends all of them (and, after the id moved into the text frame, v0.1.0 would have DROPPED the texts: a regression found while fixing this) | FIXED | `KIND_CAPS` on every connection; nothing is written until the peer's capabilities are known; a peer silent for `caps_wait` (5 s) gets plain v0.1.0 frames and written = done. Tests with a raw non-announcing peer + a manual run of the real v0.1.0 binary against this build over Tor (both directions, reconnect: no loss, no duplicates) |
| R24-M2 | the ack was queued when the text entered the UI's event channel: going offline/quitting within ~200 ms confirmed a text the user never saw | FIXED | the UI calls `Engine::confirm` after the line is in its own state; the engine confirms nothing else; test `a_text_the_ui_never_saw_is_not_confirmed_and_arrives_after_the_restart` |
| R24-M3 | the id was its own cell and the reply was immediate: message vs keepalive recognisable by cell count and reply (worsens C6-timing) | FIXED (residual: C6-timing) | id inside the text frame (cell count of a text unchanged); confirmations wait a random 1-5 s, go out batched in one cell (up to 64 ids) and a due keepalive carries them; tests for the delay, the batching and the keepalive rule |
| R24-M4 | going offline marked possibly delivered texts "(NOT SENT)" without warning (conflicting instructions for high-risk users) | FIXED | `o` warns first (second `o` goes); marks say "(NOT CONFIRMED)"; "(NOT SENT)" only for engine refusals |
| R24-L1 | `Delivered`/`Unsent` mapped to lines by position (out-of-order ack, 500-line trim, refusals without event, invalid re-add dropping carried texts) | FIXED | `Engine::send` returns the id, lines carry it, `Delivered`/`Unsent` name it; every refusal emits `Unsent`; `add()` validates the key material before taking `unacked`/`seen`. RESIDUAL: the 500-line trim can drop an unconfirmed line from view (warnings undercount) |
| R24-L2 | both sides resending ~1.9 MB at once could deadlock their writers (no per-turn text budget) | OPEN | not reachable from the TUI (2 KiB draft cap); add a per-turn byte budget for texts before the engine API gets other users |
| R24-I1 | malformed id/ack frames cut the connection, unknown kinds are ignored | ACCEPTED | only the authenticated contact can send them; the format is declared frozen in `proto.rs` |
| R24-I2 | texts stay in RAM longer (until confirmed); if the engine misses the panic key's 400 ms, `unacked` lives until exit | ACCEPTED | every normal path wipes (verified by the reviewer); the UI holds the same text anyway |
| R24-I3 | comments and DELIVERY.md out of date | FIXED | |
| R24-T | test gaps: UI never saw the text, out-of-order/misc mapping, replaced connection | FIXED / PARTIAL | first and third added (the replaced connection by injecting a stale-generation event), mapping covered by real two-app tests; no UI test for an out-of-order ack from a hostile peer |

## Review 25 (Opus, R12-5 automatic hosting probe, commits db70077 + 1c20cca) — fixed in the next commit
No critical. Test coverage: probe classification, a scripted tor end to end (510 / 451 / wrong ServiceID / unreachable), the real probe through the app (stalled tor, keys ignored, Esc, 510 -> alert + bit false).

| # | Finding | Status | Fix / note |
|---|---|---|---|
| R25-H1 | the probe blocked the UI thread (up to ~35 s honest, unbounded with a hostile endpoint): F12 / purge / signal wipe delayed; it also sent PROTOCOLINFO to an unverified owner before refusing | FIXED | worker thread; while it runs only F12/purge/Esc act; 15 s overall deadline; unverified owner -> `Unknown` before any byte is sent |
| R25-M1 | every non-2xx reply (451 transient, 55x, odd codes) became a permanent `Cannot` | FIXED | only `510` is `Cannot`; the rest is `Unknown` (the action is cancelled). Not done: asking the user to confirm a `Cannot` (a sticky alert tells them instead) |
| R25-M2 | export during a running/waiting pairing could store a different bit than the one told to the peer | FIXED | export refused while a pairing runs or waits for P; `finish_pair` discards the pairing if stored and told bits differ |
| R25-L1 | the `Cannot` notice was overwritten by the next status line | FIXED | sticky alert (`z` acknowledges) |
| R25-L2 | with `--tor-trust-control` a short-lived squatter at export time fixes the bit forever | ACCEPTED | inside the documented trust model; 510-only and the alert limit it; delete + re-pair undoes it (R13-M1) |
| R25-L3 | local controllers of a shared tor see a short ADD_ONION/DEL_ONION at export/pairing time | ACCEPTED | random key, not linkable; documented in TRANSPORT.md |
| R25-L4 | probe used port 9, real hosting a random high port | FIXED | random high port |
| R25-I | TRANSPORT.md said "nobody publishes a service just to find out" | FIXED | reworded |

## Review 26 (Opus, default vault location) — fixed in the commit after d33ed03
No critical/high. All vault_path tests pass; new tests: dangling symlink / directory / group-writable directory for `check_existing`, `create` never replaces a dangling symlink.

| # | Finding | Status | Fix / note |
|---|---|---|---|
| R26-M1 | a dangling symlink at `./nerd-chat.vault` (or the default path) counted as "existing", then as "absent" in the UI/store (`Path::exists` follows links): the vault was created in the current directory without confirmation, directory checks or Tails warning | FIXED | `check_existing` refuses anything but a regular file; store/app/main use `symlink_metadata`; any inspect error other than NotFound = refuse |
| R26-L1 | an existing default vault: no check of directory mode/owner or file owner | FIXED | `check_existing` (regular file, ours, absolute parent dir private and ours) |
| R26-L2 | parents not checked, `create_dir_all` follows a symlinked `~/.local`; confirmation shows the unresolved path; window between `prepare_dir` and write | OPEN (low) | idea: show the canonical path, `O_NOFOLLOW` dirfd |
| R26-L3 | any input (also EOF) at the confirmation created the directory | FIXED | only an empty line continues |
| R26-L4 | the directory was created before the password / swap check | PARTIAL | swap is checked before anything is created; an empty directory is still left if the user then quits at the password prompt (stated in the confirmation) |
| R26-L5 | purge leaves the empty directory; names stay in the journal/free blocks | OPEN | rmdir after purge when it is the empty default directory; document remanence |
| R26-L6 | backups/sync copy `~/.local/share`; a restore defeats rollback protection | FIXED (text) | stated in the confirmation; GETTING_STARTED/README updated |
| R26-L7 | running as root with the user's HOME takes over the user's vault | FIXED | `check_existing` requires file and directory to be owned by the effective user |
| R26-L8 | Tails detection fails open; Whonix/other live systems get no warning | OPEN (optional) | statfs tmpfs/overlay or `boot=live` heuristic |
| R26-I1 | the "ignoring ./nerd-chat.vault" notes go to stderr right before the alternate screen and are practically never seen | OPEN | the header shows the path; show the note in the first status line |
| R26-I3 | an inspect error other than NotFound was treated as "no vault" | FIXED | refused |

## Review 27 (Opus, GUI phase 1a: core extraction into crates/app, commit 10fe8a4) — fixed in the commit that follows
No critical/high. Moved files verified byte-identical (`similarity index 100%`); 306 tests passed before and after, no test lost.

| # | Finding | Status | Fix / note |
|---|---|---|---|
| R27-M1 | the moved code lost `#![forbid(unsafe_code)]` (it used to be covered by the tui binary's attribute) | FIXED | `#![forbid(unsafe_code)]` in `crates/app/src/lib.rs` |
| R27-M2 | nothing forced a front end to run the process-level safety nets (cleaner helper dispatch, sandboxed cleaner, hardening); a GUI that forgot `set_cleaner` would parse hostile files in the key-holding process | FIXED | `startup::startup(&args)` does all three; `App::new` asserts that it ran (off only in tests); the order and reasons are in the crate docs. Not done: strip's silent in-process fallback when no cleaner is installed (the assert makes it unreachable through `App`) |
| R27-L1 | "tests only" fields (`Config::transport`, `host_probe_test`) became public | FIXED | `pub(crate)`; a front end can inject a test network only through `Config::with_test_transport`, behind the non-default feature `test-transport` (enabled only by the GUI's developer `demo` feature) |
| R27-L2 | lib.rs doc described `cmd_*` methods that do not exist | FIXED | reworded: the GUI maps widgets to the same `Key`s; a command layer is planned, not built |
| R27-L3 | a dynamic GUI binary doubles as the cleaning helper (re-exec of `/proc/self/exe`) | ACCEPTED (partial) | the binary links only libc/libm/libgcc_s (windowing and GL libraries are `dlopen`ed by the toolkit AFTER `startup`), so the helper loads none of them before seccomp; the cleaner integration tests still run only against the terminal binary: duplicate them for the GUI binary in phase 6 |
| R27-L4 | stale docs | FIXED | BUILD_AND_RUN, PLAN, PROGRESS updated |
| R27-I1 | `parse_args` reads the keyfile before the swap refusal (older) | OPEN (info) | move the swap check before reading the keyfile |
| R27-I2 | design §7 listed `no_new_privs` for the main process; `harden()` sets only RLIMIT_CORE=0 and non-dumpable | ACCEPTED | `no_new_privs` on the main process could break AppArmor transitions for the spawned Tor (Ubuntu `system_tor`); it stays a property of the cleaning helper. Design text corrected |
| R27-I3 | cargo feature unification: `cargo build --workspace` turns `terminal-ui` on for the GUI | NOTED | build the GUI with `-p nerd-chat-gui`, never from a workspace-wide release build |

## D-5 GUI dependencies (owner approved, 2026-11-09)
egui/eframe 0.37 with features `default_fonts, glow, wayland, x11` only (no AccessKit, no clipboard, no web screen reader, no system fonts) enter the project in `crates/gui`; the terminal binary and its static build do not link them. `cargo deny` stays green with ONE narrow exception: `epaint_default_fonts` (bundled fonts) is allowed the SIL OFL 1.1 and the Ubuntu Font Licence. `cargo vet` exemptions grew from about 210 to 395 crates (all UNAUDITED, like the existing ones); `cargo vet` and `cargo deny` pass. Audit backlog is listed by `cargo vet`.

## Review 28 (Opus, SPEC of pairing over Tor, 2026-11-09) — integrated into the spec (section 8)
No critical. The crypto argument holds (one online guess per offer; nothing offline-attackable from the link). Findings fixed IN THE SPEC before any code:

| # | Finding | Status |
|---|---|---|
| R28-H1 | joiner retries cannot work: Tor will not re-ask the same HSDirs for ~15 min after "not found" | SPEC FIXED: publish only after `HS_DESC UPLOADED` (own control connection), bounded joiner retry |
| R28-H2 | "the link is public, safe anywhere" is false (presence probe, rendezvous-circuit confirmation, burning) | SPEC FIXED: presence-sensitive link, publish when the partner is ready, short TTL, count first rendezvous |
| R28-M1 | attacker-caused offer failures feed the process-wide lockout and block ALL pairing | SPEC FIXED: separate remote lockout, counted only after a real SPAKE message; distinct alert |
| R28-M2 | `pair.rs` hard-codes a 300 s TTL | SPEC FIXED: TTL constructor, offer created at publication |
| R28-M3 | cancel/panic cannot interrupt Tor streams (no shutdown, blocking SOCKS connect) | SPEC FIXED: `Stream::shutdown`, early registration, cancel checks |
| R28-M4 | engine command for hosting: races, orphans, no events | SPEC FIXED: `pair_host_fn` with its own control connection; drop = removal |
| R28-M5 | `can_host` probe tests the wrong command form | SPEC FIXED: the real public `ADD_ONION` decides; bit untouched |
| R28-M6 | `nerdchat:pair/` prefix names the app to the link carrier | SPEC FIXED: bare onion id |
| R28-L1..L7, I1..I4 | descriptor lingers ~3 h; random socket name; joiner error classes; clear code after failure; trust wording; online presence; derive nothing from the code | SPEC FIXED / documented |

## Review 29 (Opus, IMPLEMENTATION of pairing over Tor, commits fc1d179..2ffdb49)
No critical/high; 225 tests passed in the reviewed crates. Fixed in the commit that follows (live test result: see PROGRESS).

| # | Finding | Status | Fix / note |
|---|---|---|---|
| R29-M-a | the GUI offer card followed whichever contact was selected: the code/link could be told to the wrong person while the result landed in another contact's entry | FIXED | `TorLink.contact`; the card shows only for that contact; a bar "Pairing with X is open, Cancel" on every screen |
| R29-M-b | a delayed resume (hosting probe) could start a second pairing on top of a running one and orphan it | FIXED | `resume` refuses while a pairing runs or waits (keys are already ignored during a probe; defence in depth) |
| R29-M-c | "2 distinct HSDirs uploaded" is too weak: joiners can hit HSDirs without the right descriptor and be blocked ~15 min (probable cause of the first live failure: the joiner dialed 2 s after the link appeared) | FIXED | `PublishRule`: 4+ uploads and 8 s grace, or 2+ uploads and 30 s |
| R29-L-a | the joiner's lockout grew on EOF/cancelled offers; spec L4 not implemented | FIXED | `join_remote` counts only after a well-formed SPAKE message, on the remote lockout |
| R29-L-b | a tor that rejects SETEVENTS made offering fail (wrong message "cannot create service") | FIXED | continue without events, fixed wait |
| R29-L-c | the remote lockout was checked only after the service was published | FIXED | checked before hosting |
| R29-L-d | the TUI showed link+code on one clipped line | FIXED | two lines, layout grows |
| R29-L-e | spec H2: count the first HS_SERVICE_REND as use | OPEN | silent presence probes stay undetected (documented in TRANSPORT.md) |
| R29-L-f | GUI button said "Yes, in person" for the voice question | FIXED | |
| R29-L-g | CancelToken keeps a dup fd per registered stream until it is dropped | ACCEPTED (low) | the token dies with the pairing |
| R29-L-h | nothing watches the service/control connection after publication | OPEN (low) | a dead link is shown until the TTL |
| R29-I | the code is copied into non-zeroized memory (TUI `format!`, GUI RichText/galley): same class as R4-M2; the link sits in plain Strings | ACCEPTED | the code is worthless once consumed/expired; the link is presence-sensitive, not authenticating |
| R29-I2 | "someone used your link" alert also fires when an honest partner's circuit breaks after a well-formed message | ACCEPTED | counting is right; wording could hedge |

Clipboard (owner decision 2026-11-09): enabled ONLY for the pairing link (explicit Copy button, Ctrl+V in the link field). The GUI drops every paste event and disables selectable labels, so passwords, the code, chat text and everything else stay out of it.

## Review 30 - encrypted outbox (not reviewed by anyone but its author yet)
Code: `store/src/book.rs` (SBS6, `OutMsg`, caps), `chat/src/engine.rs` (`with_outbox`, `send_with_mid`), `app/src/app.rs` (`keep_outbox`, `set_keep_outbox`, `send_compose`, event handling), bridge op `keep_outbox`.
**This touches persistence of message text, the vault format and the offline/quit warnings: it needs the strongest adversarial review before anyone relies on it (see the stage rule above).**
| ID | Finding | Status | Notes |
|---|---|---|---|
| OB-1 | the vault file changes on every send and confirmation: activity timing is visible to someone with the disk | ACCEPTED | opt-in on the desktop; documented in `docs/DELIVERY.md` and in the settings text |
| OB-2 | a removed text may remain in older copies of the vault (flash remnants, backups) | OPEN | encrypted under the vault key; no key rotation per save. Consider re-keying the vault data key when an outbox text is confirmed |
| OB-3 | duplicate display after a restart of the receiver whose confirmation was lost (its `seen` ring is RAM-only) | ACCEPTED | duplicate chosen over loss |
| OB-4 | rollback of the vault resurrects confirmed texts | INFO | the rollback counter detects it; resend is deduplicated by id while the receiver remembers it |
| OB-5 | SBS6 is a one-way upgrade | INFO | written when ANY choice is stored (even OFF) or an outbox is non-empty (R32-S3); tests: `a_vault_that_never_used_the_outbox_stays_sbs5...` |
| OB-6 | hostile SBS6 data (counts, ids, lengths, UTF-8, outbox without a peer) | FIXED | `hostile_sbs6_blobs_are_refused`; total and per-contact caps checked on decode |
| OB-7 | `save()` failure after the text is in memory | PARTIAL (the counter-file case is fixed and tested, R32-S1) | by construction the vault write happens BEFORE the engine gets the text; on failure the draft stays and the in-memory entry is rolled back. **Not tested:** the build environment runs as root, so the permission trick the existing save-failure tests use cannot make a write fail here (those tests fail here for the same reason). Test on a normal user |
| OB-8 | enabling the feature with more waiting texts than fit | PARTIAL | the rest stays RAM-only, the user is told, and going offline still warns about exactly those (`queued_not_kept`); no test of the 1 MiB total through the app |
| OB-9 | each confirmation batch writes the vault and the counter once (fsync) on the poll thread | INFO | measure on a phone; a slow flash could stall the UI thread |
| OB-10 | the Android default is ON: a phone user who never opens Settings keeps unsent texts on flash | ACCEPTED | stated in the chat banner and in Settings |

## Review 31 - timing metadata and message history (owner decision 2026-11-09: history default ON on Android, a setting on Linux; plan in `docs/HISTORY_AND_TIMING_PLAN.md`)
| ID | Finding | Status | Notes |
|---|---|---|---|
| CT-1 | the rollback counter file was **plaintext** and counted every vault save; with the outbox it revealed roughly how many messages were sent or confirmed | FIXED (stage 2) | the counter now grows by a random 1..2^20 per save; the file is fixed 48 bytes, AEAD under a key derived from the vault data key (a fresh nonce every write), old 8-byte files still open and are upgraded; tests `the_counter_file_is_fixed_size_encrypted...`, `an_old_plain_counter_file...`, `a_tampered_or_foreign_counter_file...`. One-way: an older binary cannot read the new counter file. Its file TIMES are still on the grid-gating list (CT-2/CT-4) |
| CT-2 | `ctime` of the vault and counter files cannot be forged and always shows the real time of the last operation | FIXED (stage 3, ext4; f2fs to be checked on a device) | a "touch every minute" heartbeat alone does not hide it: all file operations must happen only on a fixed grid |
| CT-3 | `write_atomic` (temp file + rename) gives each save a new inode whose birth time is the real save time | FIXED for the history file (in-place A/B slots, test `crates/store/tests/timing_cover.rs`); f2fs to be checked | fix: in-place A/B slots in a pre-allocated file |
| CT-4 | vault file mtime/ctime/birth time show WHEN you last sent or confirmed a message (outbox on) | FIXED for messages (history file and touching on a 5 s grid; vault SAVES stay immediate and show their own moment, R33-11) | = OB-1 made precise; grid-gated I/O (plan section 2) |
| CT-5 | a vault data key rotated on every sweep is NOT a crypto-erase: every old copy carries its own wrapped key and the same password opens it | INFO (design review) | deletion needs a key the password does not unlock: Android Keystore per epoch; Linux = best effort |
| CT-6 | documentation said "nothing is written to disk" / "nothing is ever saved by itself" while the encrypted outbox can write unsent texts | FIXED (README, `save_selected` doc comment) | will change again when history exists |
| CT-7 | the receiver confirms a text right after it is in RAM; with persistence a crash before the write loses a text the sender considers delivered | FIXED (confirmations wait for the tick's fsync when messages are kept) | durable-before-confirm: queue confirmations until the tick's fsync (plan stage 4) |
| CT-8 | the Keystore binding has never run on a device; the JNI key callback has no host test | OPEN | first phone test: pair, send, restart, message still there; then check `AndroidKeystoreKeys.level` |
| CT-9 | on a TEE-only phone deleting a Keystore key is not a hardware-grade erase | ACCEPTED (documented) | StrongBox phones give the real guarantee; the Settings text must say "best effort" where StrongBox is absent (not yet shown in the UI) |
| CT-10 | the erase job trusts the wall clock: a clock moved forward destroys younger keys | ACCEPTED | loses history, never exposes it |
| CT-11 | the history used to write an unusable (empty) wrapped key silently if the key store refused | FIXED | the write now fails and is retried; test `a_key_store_that_refuses_writes_nothing_and_loses_nothing` |
| RK-1 | one transport key per connection: a memory leak at time T opens every cell of the connection that was recorded | FIXED (S2) | `KIND_REKEY` ratchet every 32 cells / 10 min; tests `a_rekey_changes_the_key_in_step...`, `the_key_is_ratcheted_inside_a_long_connection_and_the_peer_follows` |
| RK-2 | a ratchet is one-way: it does NOT heal after a leak (the attacker can ratchet too) | ACCEPTED (documented) | healing needs a new handshake: a periodic reconnect is an open idea |
| RK-3 | the ratchet check runs once per loop turn: a burst can put more than `rekey_cells` cells under one key | ACCEPTED | bound is "cells per burst + 32" |
| RK-4 | not tested against the real v0.1.0 binary or over real Tor (`tests/live_chat.rs` is ignored here) | OPEN | run the ignored live tests on a machine with Tor |

## Review 32 - adversarial review of the outbox, the Rust bridge and the Android app (six independent Opus reviewers, 2026-11-09; the sixth is the design review behind review 31)
Reviewed at commit 6be6ddd, each in its own scratch copy; bugs were proved with failing tests before they were fixed. Fixed in the commit that follows 6be6ddd/e9a20fa.
| ID | Finding (reviewer) | Status | Notes |
|---|---|---|---|
| R32-A1 | a text typed while the engine is STARTING (a minute on Android) was kept but never sent in that session; app + engine reviewers, proved | FIXED | the app hands over texts kept during startup when the engine is ready; the engine merges a re-add's kept texts with its own queue; sending the same id twice is queued once. Tests: `a_text_typed_while_the_engine_is_starting...`, engine `a_re_add_keeps...`, `the_same_id_sent_twice...` |
| R32-A2 | `set_keep_outbox(true)` when already on by default claimed texts "did not fit" and, on a save failure, wiped texts that were already kept (app + store reviewers) | FIXED | only the choice is stored; undo removes only what this call added |
| R32-A3 | switching the outbox off while starting mislabelled lines | FIXED | lines are labelled by who still holds the text |
| R32-A4 | a v0.1.0-style peer (or a modern peer whose CAPS frame is slower than 5 s on a slow circuit) gets the kept text as a plain frame, `Delivered` is reported when it is HANDED to the connection thread, and the app deletes the vault copy: a connection that dies right then loses a text the user was told is kept until confirmed (engine reviewer) | OPEN | options: emit `Delivered` only after the socket write, or keep the vault copy for Legacy-mode deliveries until the connection closes cleanly, or a longer `caps_wait` when the outbox is on |
| R32-E1 | every start with kept texts sends a burst right after CAPS, then one batched confirmation 1-5 s later: same pattern as "queued while away", but now after every restart | INFO | belongs to C6-timing |
| R32-B1 | bridge `ack_alert` typed a `z` into the message draft or the PASSWORD (bridge reviewer, proved) | FIXED | only from the main screen in normal mode |
| R32-B2 | a refused send kept a hidden draft; the next send was glued onto it ("helloworld"), and the 2048-byte check was bypassed (bridge reviewer, proved) | FIXED | the bridge clears the draft before and after, and reports the refusal |
| R32-B3 | the snapshot and its Java string are copied without being wiped on every poll (jni makes its own copy; the writer reallocated); the docs claimed otherwise | PARTIAL | writer pre-sized; claim corrected. OPEN: return the snapshot as a byte array the app can wipe, and send chat lines and the pairing code only when they change (revision number) |
| R32-B4 | the decoded `char[]` (password, code) left a freed, unwiped half-copy | FIXED | pre-sized `Zeroizing<String>` |
| R32-B5 | a too-long name or link left its prompt open and the UI could not close it | FIXED | the bridge closes it |
| R32-B6 | `submit` used a denylist; the hygiene test scanned a fixed file list | FIXED | allowlist (new contact name, pairing link); the test walks `src/` recursively and also forbids `export_name`/`link_section` |
| R32-B7 | a second `nInit` while a vault creation is running leaked a core | FIXED | the old core is panic-wiped first |
| R32-B8 | startup warnings (core dumps, dumpable) and the swap result are discarded; the snapshot still carries chat data while `privacy_locked`; the non-dumpable call is `cfg(target_os = "linux")` and does not apply on Android | OPEN (info) | release builds are non-dumpable anyway; surface the warnings when the phone gets a status screen |
| R32-K1 | **HIGH:** Compose never sets `IME_FLAG_NO_PERSONALIZED_LEARNING`/`NO_SUGGESTIONS`: a keyboard such as Gboard may add typed contact names and messages to its personal dictionary, a copy outside the app that panic and purge cannot remove (Android reviewer, checked in the Compose bytecode) | PARTIAL | `MainActivity` now adds both flags (`InterceptPlatformTextInput`) and turns autofill off; it COMPILES, its effect on a real keyboard is NOT VERIFIED on a device (a keyboard may still ignore the flag). Tell users to use a keyboard without cloud/personalisation (GrapheneOS ships one) |
| R32-K2 | the app could lock up after ONE refused text step: the prompt stayed open and nothing, not even going offline, worked (Android reviewer, proved) | FIXED | a chain stops at the first refused step, closes any open prompt, and the reason is shown for a few seconds |
| R32-K3 | **a new contact's keys could be paired into the WRONG contact**: a failed contact creation did not stop the chain, so the pairing step ran against the previously selected contact (Android reviewer, proved) | FIXED | contact creation is ONE bridge operation that fails as a whole |
| R32-K4 | after the safety-number check the chat went blank and sent texts were refused; a too-long text vanished (Android reviewer) | FIXED | the chat is reopened on the way back; the send button refuses over 2048 bytes. PARTIAL: a refused send still clears the Kotlin field (the reason is shown) |
| R32-K5 | the Rust build task could be "up to date" and ship a stale `.so` (it ignored the root manifest, `vendor/snow`, the toolchain pin and the flags) | FIXED | all of them are task inputs |
| R32-K6 | any value of `-Pdemo` (even `false`) turned the fake backend on, with no visible marker | FIXED | only `true` counts, a release build refuses it, the unlock screen says DEMO BUILD |
| R32-K7 | an unknown core screen, or the core's privacy screen, showed the main UI | FIXED | only main/prompt/verify are the app; everything else is an error state |
| R32-K8 | `ChatBackend` docs said arrays are wiped "before this returns"; README said the code is wiped "on both sides" | FIXED (wording) | see R32-B3 for the real limit |
| R32-K9 | hardening: task hijacking (no `taskAffinity`), accessibility exposure, deep JSON nesting, loose `\u` escape | FIXED | `taskAffinity=""`, accessibility-data-sensitive on Android 14+, depth limit 64, exactly four hex digits. OPEN note for the Tor stage: with AGP's default packaging a bundled `libtor.so` is not extracted and `canExecute()` stays false (needs `useLegacyPackaging`) |
| R32-S1 | a failed COUNTER write after the vault file was written made the app roll back a text that is on disk; after a kill it would be sent anyway (store reviewer) | FIXED | `StoreError::CounterWrite`: no rollback, a visible warning, memory equals disk. Test forces it with a directory in place of the counter file (works as root) |
| R32-S3 | any stored choice, even OFF, makes the vault SBS6 for good: an older binary then reports a malformed vault | ACCEPTED | the alternative would forget an explicit OFF on Android; OB-5 wording corrected |
| R32-S4 | no stored choice + kept texts: a front end whose default is off (terminal) showed them but never sent or cleared them | FIXED | kept texts mean the feature is in use |
| R32-S5 | `encode` wrote lengths as u8/u16 without checking: an oversized entry produced a vault that never opens again | FIXED | encode asserts before anything is sealed (a crash while saving loses nothing already on disk) |
| R32-S6 | decoder accepts a few states the encoder never writes; duplicate contact ids are not rejected (predates this work) | INFO | not exploitable without the vault key |
| R32-S7 | over-long text was reported as "stored data is corrupt" | FIXED | `StoreError::BadText` |
The decoder itself held up: 200k byte mutations and truncations of an SBS6 blob produced no panic, every length is bounds-checked, `encoded_size` is a true upper bound, SBS5 output is byte-identical to the old format.


## Review 33 (Opus, `ed528ee..720a0e8`: key ratchet, history file, counter file, app save flows, Android bridge and key store)
The rekey code was checked and found sound (REKEY under the old key, nonces continue, capability inside the authenticated session). Probe tests for R33-3/4/7 live in the code as `review33_regressions`.
| Id | Finding | Status | Notes |
|---|---|---|---|
| R33-1 | HIGH: "about a day" is really ~10 days on Android while the app is not running (the erase job had one bound for every setting) | FIXED (not run on a device) | the job reads the user's setting from a plain preference the app keeps current (`HistoryModeListener`): a day -> keys die 3 epochs after their own, a week -> 10, off -> all, unsent-only -> none. Rust test pins both bounds. OPEN: keys are per 24 h epoch, not per 6 h bucket, so up to ~48 h at the one-day setting; UI text says "about" |
| R33-2 | purge / switching history off never destroyed the Keystore epoch keys | FIXED | `History::erase_all_keys` (also in `shred`), called by `purge_prepare` before the wipe |
| R33-3 | deleted data stayed in the inactive slot until the next write | FIXED (test) | every removal (contact, state drop, Outbox narrowing, eviction) scrubs the other slot |
| R33-4 | one transient Keystore failure destroyed the history and unsent texts silently | FIXED (test) | `Unwrapped::{Key, Gone, Failed}`: Kotlin returns null for gone and an empty array for an error; `Failed` refuses to open (`KeysUnavailable`), the file stays untouched, the app says nothing is kept this session |
| R33-5 | Keystore alias names / creation times reveal which days had messages | PARTIAL | keys for today and tomorrow are created on every start and job run whether or not anything is written (only when the history is on). Not verified on a device what keystore2 records |
| R33-6 | the rollback-counter WARNING was hidden by success messages at most `save()` call sites | FIXED (test) | `ok()` carries the warning until a save succeeds |
| R33-7 | the legacy plain 8-byte counter file is accepted forever and has no integrity | FIXED (test) | such a file opens with the "rollback cannot be detected" warning. The encrypted form gives confidentiality only; replaying an old encrypted file still works (R4-L4) |
| R33-8 | the history file has no rollback binding | FIXED (test `history_rollback`) | the counter file (now v2, 56 bytes: counter + history generation, encrypted; v1 still read) records the newest history generation after every grid tick (written every tick, changed or not, so its times stay on the grid). `History::open_with_floor` refuses a file whose newest slot is older (`HistoryRolledBack`, file left untouched, visible warning; switching the history off and on starts a new one); a deleted file is just empty and continues above the floor. Limits: whoever can also replay the old counter file defeats it (R4-L4), and with no counter file nothing is recorded |
| R33-9 | one contact could evict everybody's history; evicted received lines still got confirmed | PARTIAL | eviction takes from the biggest contact first and scrubs/erases; OPEN: per-contact byte quota, no confirmation for evicted ids |
| R33-10 | `touch()` could block forever on a planted FIFO | FIXED | O_NONBLOCK plus a regular-file check |
| R33-11 | "all writes on a 5 s grid" overclaimed (vault saves are immediate, peer-triggered rotation saves) | FIXED (wording); OPEN: queue vault saves to the grid |
| R33-12 | `history_unsafe_fs` was an incomplete denylist | FIXED | allowlist (ext2/3/4, XFS, tmpfs, ramfs, FAT, exFAT, NTFS); f2fs, bcachefs, nilfs2, overlay, FUSE, SMB2, unknown are refused |
| R33-13 | Outbox mode + erase job lost unsent texts after ~10 days | FIXED | the job does nothing in Outbox mode |
| R33-14 | a failed `finish_migration` save could cause duplicate sends | FIXED | the migration ends only after a successful save; a known id is never pushed again in any state |
| R33-15 | INFO / OPEN | OPEN | a future password change rotates the data key and would orphan the history (no UI calls it yet); texts typed while Tor starts may be handed over before they are durable; parent directory not fsynced after creating the history file; the snapshot copies whole conversations into non-wipeable Java Strings every 250 ms (R32-B3); `tor_offer.code` is in the snapshot; the pairing link on the clipboard is never cleared; Keystore keys lack `setUnlockedDeviceRequired`; Kotlin `AndroidKeystoreKeys` changes are NOT compiled here (no Android SDK), only the pure-JVM modules and the JNI test ran |
