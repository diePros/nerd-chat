# Release testing: step by step (for the project owner)

Everything here is checked by YOU on real machines, because that is exactly what automated tests cannot do. Each step says what
you should see. Write down every deviation word for word (and the output of the command): that is what I need to continue.

Binary under test: the file `nerd-chat-<version>-x86_64-linux-musl` from the GitHub draft release (or your own build from
`scripts/release.sh`). Use ONE commit/hash for all steps.

## A. Verify the download (any Linux machine, 3 minutes)
1. Put `nerd-chat-0.1.0-x86_64-linux-musl`, `SHA256SUMS` (and `SHA256SUMS.asc` if present) in a new empty folder.
2. `sha256sum -c SHA256SUMS --ignore-missing` -> `OK`.   (If a signature exists: `gpg --verify SHA256SUMS.asc SHA256SUMS`.)
3. `chmod +x nerd-chat-0.1.0-x86_64-linux-musl && ./nerd-chat-0.1.0-x86_64-linux-musl --version` -> `nerd-chat 0.1.0`.
4. `file nerd-chat-0.1.0-x86_64-linux-musl` -> contains `static-pie linked` (or `statically linked`); `ldd` -> `statically linked` (or `not a dynamic executable`).
5. Reproducibility (the strongest check, 10 minutes, any second machine or WSL): `git clone https://github.com/diePros/nerd-chat && cd nerd-chat && git checkout v0.1.0 && scripts/release.sh`
   (needs a clean tree and rustup; the pinned toolchain installs itself). The printed SHA-256 of `nerd-chat-0.1.0-x86_64-linux-musl` must
   equal the one in the release. Different? Send me both hashes and `rustc -V` of each machine.

## A2. Default vault location
Run `./nerd-chat` WITHOUT `--vault` in a fresh `HOME` (e.g. `HOME=$(mktemp -d) ./nerd-chat`): the text names `~/.local/share/nerd-chat/nerd-chat.vault`, an empty line continues, EOF (`</dev/null`) or any text cancels with nothing created. A dangling `./nerd-chat.vault` symlink is refused. On Tails the WARNING about the erased home appears.

## B. Tails (the open question: can Tails' Tor host onion services for us?)
Use a fresh Tails session with Persistent Storage ON for the vault only, network connected (Tor ready). Do not use `sudo`.
1. Copy the binary to the Tails home (`/home/amnesia/`), `chmod +x`. If "Permission denied" when running from a stick, copy it to `~` first.
2. `cat /proc/swaps` -> only the header line. `free -m` -> note the free RAM.
3. `./nerd-chat --version`, then `./nerd-chat --probe-tor --probe-onion 2>&1 | tee probe.txt`.
   Expected, best case: control port works and `ADD_ONION ... ALLOWED`. If it says the owner of the control port is NOT TRUSTED, repeat
   with `--tor-trust-control` (tee into `probe2.txt`). Keep both files; copy them out (Tor Browser can't upload; use a second stick).
4. Create a vault: `./nerd-chat --vault ~/Persistent/test.vault --low-mem --tor-control unix:/run/tor/control --tor-trust-control`
   (if the probe showed a different control address or cookie path, use that; add `--cannot-host` ONLY if the probe said hosting is blocked).
   Password prompt: 12+ characters. Expect: vault created in about 2 s, UI with an empty contact list.
5. Second party: any other machine (the dev laptop is fine) running the same binary with its own vault. Pair them: on each side `n` (name), then
   `e` export, copy the files across, `I` import, then `v` verify the same safety number on both sides -> `y`.
6. Press `o` on both sides (online). Expect the title/status to go through "starting"/"ONLINE"; the contact dot turns green within 1-3 minutes.
   Note the time it took. No green dot after 5 minutes: write down the status line and alerts text exactly (`z` acknowledges alerts).
7. Chat: select the contact, `i`, type a line, Enter. Both directions. Then `Esc`, `f` and send a JPEG; accept on the other side (`a`), save (`s`). Note anything odd.
8. Panic-lock: press F12. Expect: screen cleared, the program gone, the prompt back. Start again with the same command: the password opens the vault.
9. Purge (use a THROWAWAY vault for this): Ctrl+]. Expect `purge: N file(s) overwritten and deleted`; `ls ~/Persistent/` shows the vault gone.
10. Close the terminal window while the app runs online, then `ps aux | grep nerd-chat` -> no process left (checks the lost-terminal fix).
11. Sandbox on the Tails kernel: `./nerd-chat --strip photo.jpg out.jpg` with any JPEG -> `wrote out.jpg ...`. If it says the sandbox is unavailable
    / killed by SIGSYS, copy the exact message (and `uname -r`).

## C. Normal Linux machine, full behaviour (30 minutes, the dev laptop is fine)
1. `sudo apt install tor && sudo systemctl disable --now tor`, `cat /proc/swaps` empty (`sudo swapoff -a`).
2. Two terminals, two vaults (`--vault ./a.vault`, `./b.vault`), the steps of `docs/GETTING_STARTED.md` sections 3 and 4b (file pairing, verify, online, chat, file).
3. Message while the peer is offline: peer `o` off; type a message -> shows `(queued)`; peer `o` on -> delivered and the `(queued)` tag disappears (it goes away when the peer's app confirms, also while connected). Extra: kill the peer's terminal (close the window) and type 2 messages at once; restart the peer: both arrive, once each.
4. Save a message: in the chat `m`, `j`/`k`, `y` -> star; `H` shows it; `d` `d` deletes it. Quit and reopen: only the starred message is still there.
5. Key rotation: `K` on one side, wait for both sides to say done (about 1-3 minutes), chat still connects.
6. Lost terminal: start the app, then `kill -HUP <pid of the terminal emulator>` or just close the window; `top` shows no process at 100% CPU.
7. Wrong password 3 times: each takes ~4 s, no crash. Copy an old vault copy back over the vault: expect `ROLLBACK DETECTED`.

## C2. Interop with the audited 0.1.0 (only while both versions are in use)
Run the 0.1.0 binary on one side and a build of `next` on the other (two terminals on this laptop are enough), paired as in part C.
1. Messages flow in BOTH directions. On the `next` side a sent line loses `(queued)` within about 5 s (it sees an old peer).
2. Close the 0.1.0 terminal, type two messages on the `next` side, start 0.1.0 again and go online: both arrive, once each, nothing older repeats.
3. Two `next` builds: `(queued)` disappears 1-6 s after sending (the confirmation is delayed on purpose).

## D. What to send back
For every failed or odd step: step number, exact text on screen, `uname -r`, the Tails version, and the probe files. Pass/fail per step is enough for the rest.
