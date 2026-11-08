# nerd-chat

A serverless, Tor-routed, end-to-end encrypted chat for people who have reason to be careful. No server, no accounts, no phone numbers,
no cloud: you exchange keys with each contact in person (file, QR-less local link with a one-time code), every contact gets its own fresh
key pair and its own onion service, and everything runs from a **single static Linux executable** that can be started from a live USB.

> **Status: unaudited.** The code has been reviewed repeatedly (see `docs/SECURITY_TRACKER.md`, every finding and its fix), but it has
> **not** had an independent professional audit, it has not been run on Tails yet, and it is not a replacement for a tool you can trust
> with your life. Read the limits below. Use at your own risk.

## What it does
- **Keys:** per-contact Ed25519 (signing) + X25519 + ML-KEM-768 (post-quantum hybrid) in a Noise `KKpsk0+psk2` handshake; every message is
  signed **and** encrypted; fixed 1 KiB cells; contact keys are exchanged locally (safety numbers to verify).
- **Transport:** one Tor v3 onion service per contact with client authorisation; no server in between; online-only peer to peer
  (messages exist only in RAM, nothing is written to disk). Your own Tor is started in a RAM directory, or an existing one (Tails/Whonix) is used.
- **Vault:** keys live in one password-locked vault (Argon2id, XChaCha20-Poly1305, padded, rollback counter); optional keyfile on another device.
- **Files:** JPEG/PNG (and explicit plain text) are cleaned of metadata by allowlist, in a sandboxed helper process (seccomp), padded to size buckets,
  accepted only by explicit consent, re-cleaned by the receiver and saved under a neutral name.
- **Panic:** F12 or Ctrl+\ (panic-lock) wipes memory and screen and exits immediately; Ctrl+] (purge) additionally overwrites and deletes the vault, counter, keyfile and exported files. No logs, no automatic history, no clipboard.
- **Keeping messages is manual:** nothing is ever saved by itself; you can save a chosen message into the encrypted vault (message cursor `m`, `y`) and delete it again.
- **Key rotation:** you can replace the onion address and auth key of a contact so that old copies of your bundle stop revealing when you are online.
- **UI:** terminal UI with a permanent contact list, a vim-style Normal/Insert input and a privacy screen (3rd Esc). A GUI is planned (`docs/ROADMAP.md`).

## Build
```bash
git clone <this repository> && cd <repository>
cargo test --workspace                                              # expect all green
cargo build --release --locked --target x86_64-unknown-linux-musl -p nerd-chat-tui   # static binary (pinned toolchain, see rust-toolchain.toml)
```
Details, checksums, the reproducible-build check (also on WSL) and live-USB notes: `docs/BUILD_AND_RUN.md`; first steps and the key map: `docs/GETTING_STARTED.md`.
Without `--vault` the vault lives in `~/.local/share/nerd-chat/` on this computer's disk (home backups and sync tools copy it); use `--vault PATH` for a USB stick or Tails Persistent Storage.

Needs `tor` installed for chat (or an existing Tor via `--tor-control`). x86_64 Linux only; the file-cleaning sandbox needs seccomp.

## Honest limits
Endpoint compromise, traffic correlation by a global observer, terminal-emulator memory and RAM remanence are out of reach for any software like this.
The privacy screen only hides the screen (the vault stays open). `docs/SECURITY_TRACKER.md` lists every known open item.

## Documents
`docs/GETTING_STARTED.md`, `docs/BUILD_AND_RUN.md`, `docs/TRANSPORT.md`, `docs/FILE_SHARING.md`, `docs/KEY_ROTATION.md`, `docs/SECURITY_TRACKER.md`,
`docs/EXCHANGING_CONTACTS.md` (how to hand over a contact file safely), `docs/ROADMAP.md`, `docs/NAMES.md` (project name and how to change it), `SECURITY.md` (reporting vulnerabilities).

## License
GNU Affero General Public License v3.0 or later (`LICENSE`). Vendored third-party code keeps its own license (`vendor/`).
