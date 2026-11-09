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
| 35-36 | (this commit) | terminal-loss fix, release prep (--version, scripts/release.sh, RELEASE_TESTING), review 23 fixes (purge never follows links, read-only keyfile, blank-before-shred, bracketed paste) | yes (review 23), fixes applied | yes | yes (net test now uses the tor RAM dir: Ubuntu AppArmor system_tor blocks sockets elsewhere) |
| 38-39 | ff0f8fc | R12-5 automatic hosting probe at export/pairing (worker thread, 510-only, sticky alert, export blocked during pairing), review 25 fixes, tor_live test made robust (d33ed03) | yes (review 25), fixes applied | yes (static-pie) | chat 3/3 pass; net test passed 6 of 7 runs after the test fix (it failed 5/5 before it, also on the commit before this work: Tor can open and drop an early connection; the one failure left was not captured, suspected slow bootstrap) |

## Next candidates (privacy first)
1. Short re-review of cycle 15 fixes (small), together with the next feature.
2. (done) rotation retry; counter rejected; random port accepted as unneeded.
3. (done, cycles 38-39) R12-5: hosting probed automatically at export/pairing when --tor-control is set; review 25 fixed (worker thread, 510 only, export blocked during pairing).
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

## Cycle 37 (after the Tails success)
Tails test passed (user). `.deb` added to `scripts/release.sh` (deterministic: two builds give the same sha256; contents checked with `dpkg-deb -c`,
`--version` works from the extracted binary; not installed, no lintian available). Next: Opus review of the delivery-confirmation work is done (review 24);
remaining candidates are the fuzz targets, R8-I7, R12-5 and the GUI-core extraction (0.2).

## Cycle 38-39 (2026-11-08/09)
Done: R12-5 (see tracker review 25), live Tor tests re-run, `docs/REVIEW_PROMPT_VAULT_PATH.md` written and the Opus review of the default vault
location started (findings go into the tracker as review 26; not yet integrated). Open: re-test R12-5 on Tails (user), review 26 fixes,
R24-L2 (per-turn text budget, not reachable from the TUI), cross-machine reproducible build, CI, cargo-vet audits, professional audit.
GUI status 2026-11-09 (late): pairing over Tor is built and PASSES the live test on the real Tor network (two spawned Tors, real screens: link ready ~11 s, paired ~19 s, second dial fails with a clear message; `cargo test -p nerd-chat-app --test live_pairing -- --ignored --nocapture`). Reviews 27 (extraction), 28 (spec), 29 (implementation) are in the tracker. GUI has: first run, unlock/create, contacts, chat, composer from the core's buffer, auto-connect, offline switch, panic, unverified notice, over-the-internet/Wi-Fi/file add flows, files, settings (hide the menu entry), clipboard for the link only. GUI .deb (menu entry + icon) is in scripts/release.sh. Screenshots for unattended runs: `vblank_mode=0 nerd-chat-gui --demo --skip-notice --screenshot out.png --shot-frame 40000` (vsync stalls an unattended window). NOT done: Tails/Whonix test (user), pairing over Tor on Tails (onion-grater), phase-5 leftovers (key rotation and host-anyway buttons, privacy screen), cleaner tests for the GUI binary, a real audit.

GUI (0.2), approved plan `docs/superpowers/specs/2026-11-09-gui-design.md`: phase 0 spike DONE (go, report in the same folder), phase 1 core extraction DONE (crate `crates/app`, review 27), phase 2 first GUI shell DONE (`crates/gui`, `cargo build -p nerd-chat-gui`; developer demo: `--features demo` and `nerd-chat-gui --demo --screenshot out.png`). Next: phase 3, pairing over Tor (own spec first), then add-contact flows, unverified notice, parity, packaging.

## Release check (2026-11-09, commit d38683f)
`scripts/release.sh` builds the static terminal binary, tarball, terminal .deb AND `nerd-chat-gui_0.1.0_amd64.deb` (binary, `/usr/share/applications/nerd-chat.desktop`, scalable icon, docs). The GUI .deb as built on this machine says `Depends: libc6 (>= 2.43)`: it will NOT install on Tails (Debian 12, glibc 2.36). For a portable GUI package build the release on the OLDEST system to support (the script computes the needed glibc itself). Not yet checked: installing the .deb and launching from a real menu, the reproducibility of the GUI build (dynamic glibc), `lintian`.

## GUI parity steps 1-3 (2026-11-09)
- Contact details: collapsible "Advanced" panel (`App::inspect`, states only, no keys/addresses/names): connection, roles, capability told, saved count, rotation state; buttons "Switch to new keys" (K) and "Host anyway" (h, disabled when impossible).
- "Hide screen (Ctrl+L)" in the status bar (privacy screen; not a lock); Enter or "Show again" brings it back. Only from the main screen (never over a prompt).
- Details pane scrolls. Screenshot: docs/superpowers/specs/gui-advanced.png. Still open: purge button with confirmation, alert history in the inspector.
