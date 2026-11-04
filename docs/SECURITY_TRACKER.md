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
| R1-H2 | No locked/secret memory (mlock, memfd_secret, guard pages) | **OPEN** | needs `vault-mem` crate (only `unsafe`); due milestone 4, REQUIRED before panic-wipe claim |
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
| R2-L6 | Initiator auth classical only | **OPEN** | add ML-DSA + reverse static KEM |
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
| R3-L2 | No final confirmation; asymmetric outcomes | FIXED | transcript-hash confirmation cells both ways before commit |
| R3-L3 | Blocking I/O without deadline; write-before-read deadlock | FIXED | `PairStream` timeouts + overall deadline; role-ordered I/O |
| R3-L4 | Zeroization gaps (code String reallocs, display(), spake2 state) | PARTIAL | our code fixed; **spake2 0.4 does not zeroize** -> D-2 |
| R3-L5 | Trust state publicly mutable | FIXED | private fields, confirmation token |
| R3-I1 | Peer point validation (small-order / non-canonical accepted by spake2) | FIXED | rejected before finish |
| R3-I2 | Active MITM gets 2 guesses/code (not 1) | ACCEPTED | docs corrected; 2/10^10 |
| R3-I3 | Armor not canonical (line lengths, CRLF) | OPEN (low) | tighten or reword docs |
| R3-I4 | SPAKE2 classical: recorded transcript + future DL solver + brute force 10^10 links public keys to pairing event | ACCEPTED | note beside D-2 |
| R3-I5 | LAN attacker can burn codes (inherent DoS) | ACCEPTED | UI must say "pairing interrupted, possible attacker" |
| R3-I6 | Bundle (~1.8 KB armored) too large for easy QR (v37+) | OPEN | QR path later: consider hash-only QR + file |
| R3-I7 | KDF/tag use plain concat | OPEN (low) | move to keyed BLAKE2b/HKDF with length prefixes |
