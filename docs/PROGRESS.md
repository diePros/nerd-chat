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
| 14 | b0a26c1 | cancelled vault create writes nothing, DialEnded in-flight dials, sticky alerts (`z`), flag-mismatch warning, `--strip` swap refusal | review running | yes (1.49 MB static-pie) | yes, 2/2 pass |

## Next candidates (privacy first)
1. Integrate the review of b0a26c1 (if findings), re-run tests.
2. R5-M4: rotate per-contact onion/auth keys over the authenticated channel; random virtual port per contact.
3. R12-5: probe hosting capability automatically at export.
4. Sandbox the file parsers (seccomp/Landlock) and a cargo-fuzz target (needs the user's OK for new tooling/deps).
5. `snow` does not zeroize: patch or replace.
6. cargo-deny (ask first), cargo-vet, CI, cross-machine reproducible build.
7. R8-I7/R13: stop wasted dials to a peer that flipped (needs signalling).
8. Tails test (user-deferred), professional audit before real use.

## Pre-production gate (all must be true)
All tracker rows FIXED or ACCEPTED with a written reason, except the audit/Tails items that need a human; last review has no
unfixed Medium+; workspace tests, static musl build, repro check and live Tor tests green on the final commit.
