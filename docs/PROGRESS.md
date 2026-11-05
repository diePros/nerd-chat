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
| 19 | (this commit) | vendored snow with Drop-time zeroization (D-3/R2-M3/R7-L1) | review running | yes, reproducible (same machine) | yes, 3/3 |

## Next candidates (privacy first)
1. Short re-review of cycle 15 fixes (small), together with the next feature.
2. Open from review 14: ADD_ONION retry for the new service (R15-L1). Generation counter evaluated and rejected (see tracker R15-L3). Then random virtual port per contact, vanguards.
3. R12-5: probe hosting capability automatically at export.
4. Sandbox the file parsers (seccomp/Landlock) and a cargo-fuzz target (needs the user's OK for new tooling/deps).
5. (done in cycle 19, partial) snow wiping; next: ml-kem DecapsulationKey zeroize check, mlock (R1-H2).
6. cargo-deny (ask first), cargo-vet, CI, cross-machine reproducible build.
7. R8-I7/R13: stop wasted dials to a peer that flipped (needs signalling).
8. Tails test (user-deferred), professional audit before real use.

## Pre-production gate (all must be true)
All tracker rows FIXED or ACCEPTED with a written reason, except the audit/Tails items that need a human; last review has no
unfixed Medium+; workspace tests, static musl build, repro check and live Tor tests green on the final commit.
