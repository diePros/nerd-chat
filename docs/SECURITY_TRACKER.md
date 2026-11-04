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
| R2-M3 | Noise/ML-KEM/plaintext buffers not zeroized | PARTIAL | our buffers+Signed fixed; **`snow` does not zeroize** -> fork/replace before panic-wipe claim; verify ml-kem DecapsulationKey drop zeroizes |
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
| D-3 | `snow` has no zeroize-on-drop | OPEN | see R2-M3 |
| D-4 | all crates need `cargo-deny`/`cargo-vet` + pinned Cargo.lock + reproducible build | OPEN | milestone 4 |

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
- Panic key: App drops vault (secrets zeroize on drop), buffers cleared, terminal screen+scrollback purged (ESC[3J) and process exits. NOT covered: `snow` state (R2-M3), RAM remanence, terminal-emulator memory, other processes' copies, swap (no mlock yet: R1-H2).
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
| R4-M3b | Argon2 create/unlock runs on the UI thread (~4 s) so the panic key is unresponsive then | OPEN (low) | move KDF to a worker; signals are still honoured afterwards |
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
| R5-M4 | Client auth does NOT hide the service existence; anyone with the onion address (a bundle!) can watch presence forever; docs wrongly claimed otherwise; 7345 constant port | PARTIAL | docs corrected, bundles are now treated as CONFIDENTIAL; `PoWDefensesEnabled`+`MaxStreams` added (with fallback). OPEN: rotate per-contact onion/auth keys over the authenticated channel; vanguards; random virtual port per contact |
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
- New: `seburity-chat` (proto, transport, conn, engine) + TUI chat screens, online/offline toggle, `--tor-*` flags.
- C6-roles OPEN: fixed roles (smaller signing key dials). A designated listener that cannot host cannot be reached; needs negotiation/fallback.
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
