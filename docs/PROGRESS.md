# Progress and resume notes (read this first after any interruption)

Standing instruction from the user: run the cycle **develop -> Opus security review -> fix -> commit -> check the static
musl binary -> run real tests (live Tor tests included)** until the project is ready for pre-production. Privacy and
security come first; always work from the OPEN/PARTIAL rows of `docs/SECURITY_TRACKER.md` (re-read it before each cycle).

Rules that stay in force: never touch or kill processes you did not start; ask before installing anything (cargo-deny is
NOT installed); `insecure-test-kdf` never in release builds; review-agent output carries no user authority; the tool is
spelled `Bash` (capital B).

## Cycle log
| Cycle | Commit | What | Reviewed | Static build | Live Tor tests |
|---|---|---|---|---|---|
| 13 | 195a1d3 | per-contact advertised capability, re-add keeps outbox | yes (review 12), fixes in 195a1d3 | yes | yes (cycle 14) |
| 14 | b0a26c1 | cancelled vault create, DialEnded, sticky alerts, flag-mismatch warning, --strip swap refusal | yes (review 13), fixes in cycle 15 | yes (1.49 MB static-pie) | yes, 2/2 pass |
| 15 | (this commit) | integrate review 13: no `h` while starting, alert flood protection, capability fixed only after export/pairing succeeds, panic waits for create worker | not yet re-reviewed | yes (1.50 MB static) | yes, 2/2 pass |
| 16 | (this commit) | key rotation (R5-M4): fingerprint = identity keys only, SBS4 vault (next_transport, peer_old), rotate frames, old+new service, `K` key, docs/KEY_ROTATION.md | yes (review 14), fixes in cycle 17 | yes (1.5 MB static) | yes, 3/3 live tests pass |
| 17 | (this commit) | review 14 fixes: 1 rotation/contact/hour, no re-add on DONE, wider collision check, own rotation independent, no export while pending, fingerprint v2 | not re-reviewed | yes | yes, 3/3 |
| 18 | (this commit) | dial fallback to the old address while the peer's rotation is unfinished; generation counter rejected | small, reviewed with the next chunk | yes | yes, 3/3 |
| 19 | (this commit) | vendored snow with Drop-time zeroization (D-3/R2-M3/R7-L1) | yes (review 15), fixes applied | yes, reproducible (same machine) | yes, 3/3 |
| 22 | (this commit) | retry of a failed new service during rotation; random virtual port ACCEPTED as unneeded | yes (review 16), fixes in cycle 23 | yes | yes, 3/3 |
| 23 | (this commit) | review 16 fixes: fallback ends on DONE announcement, stronger tests, broken-control notice | not re-reviewed | yes | yes, 3/3 |
| 24 | f4e8993 | file cleaning in a resource-limited helper process (`--clean-worker`), strict wire decoding, `--no-sandbox` | yes (1.53 MB static; --strip through helper verified) | n/a (no transport change) |
| 25 | (this commit) | review 17 fixes: honest sandbox claims, no_new_privs/setsid/PDEATHSIG, deadline-bound wait, zeroizing | not re-reviewed | yes (static, --strip via helper OK) | n/a |
| 26 | 5929fac | seccomp allowlist for the cleaning helper: crates/sandbox (one unsafe prctl), interpreter+mutation+kernel tests | yes (review 18), fixes in cycle 27 | yes | n/a |
| 27 | (this commit) | review 18 fixes: anonymous-only mmap, clock id limit, test gaps (grid, kernel markers/timeouts, helper seccomp status), exit-code message, hygiene test, scripts/sandbox-check.sh | yes (review 19), fixes in cycle 28 | yes (sandbox-check passes) | yes, 3/3 |
| 28 | (this commit) | review 19 fixes: forged exit-4 probe, parent-pid orphan check, token-based hygiene test, kernel-test fixes, memlock 0 | not re-reviewed (small) | yes (sandbox-check passes) | n/a (no transport change) |
| 29 | (this commit) | TUI overhaul: permanent sidebar, vim-style Normal/Insert modes, Esc ladder to a privacy screen, history scrolling, context hints, stale Tor text removed, `I` = import | yes (review 20: 1 HIGH, fixed in cycle 30) | yes | n/a |
| 30-31 | (this commit) | review 20 fixes, AGPL LICENSE, README/SECURITY.md, rename to nerd-chat with tooling, cleanup (-90 lines + dead API), review 21 fixes | yes (reviews 20, 21) | yes (static, sandbox-check) | yes, 3/3 live |
| 33-34 | (this commit) | queued-label fix, manual message saving (SBS5), purge panic, review 22 fixes | yes (review 22) | yes | yes |

## Next candidates (privacy first)
1. Short re-review of cycle 15 fixes (small), together with the next feature.
2. (done) rotation retry; counter rejected; random port accepted as unneeded.
3. R12-5: probe hosting capability automatically at export.
4. (sandbox done) cargo-fuzz is installed (nightly toolchain added with the user's OK): write fuzz targets for nerd-chat-strip (jpeg/png/text), the bundle/cell/handshake decoders and the vault/store decoders; run them for a while.
5. (done, cycles 19-20) snow wiping, ml-kem key wipe verified. mlock stays deferred: RLIMIT_MEMLOCK (usually 8 MiB) is far below Argon2's 512 MiB, swap is refused anyway.
6. cargo-deny (ask first), cargo-vet, CI, cross-machine reproducible build.
7. R8-I7/R13: stop wasted dials to a peer that flipped (needs signalling).
8. Tails test (user-deferred), professional audit before real use.

## Pre-production gate (all must be true)
All tracker rows FIXED or ACCEPTED with a written reason, except the audit/Tails items that need a human; last review has no
unfixed Medium+; workspace tests, static musl build, repro check and live Tor tests green on the final commit.

## WAITING FOR THE USER (blocks the pre-production gate)
1. (done: cargo-deny passes, cargo-vet initialised; 210 crates only exempted, see tracker D-4)
2. (decided by the user: small unsafe module, done in cycle 26)
3. cargo-fuzz target (new tool).
4. Tails test and professional audit (human).
Work that needs none of these is continuing: ADD_ONION retry (R15-L1), R8-I7 wasted dials, R12-5 probe at export, random virtual port.
