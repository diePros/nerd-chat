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
- C6-queued-label OPEN (cosmetic): a line shown as "(queued)" is not updated when it is finally delivered; there are no delivery receipts by design.
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
| R6-I3 | Pending outbox lost silently if the connection dies before writing; "(queued)" implies more than is promised | ACCEPTED | RAM-only by design, documented in the UI status text |

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
| R8-I7 | After a flip the designated dialer keeps dialing the never-existing onion | OPEN | stop/slow dialing a peer known to have flipped (needs signalling) |
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
| R12-5 | The capability is chosen by the user (`--cannot-host`); it is not probed automatically at export | OPEN | could run the probe at export time when a control port is configured |

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
