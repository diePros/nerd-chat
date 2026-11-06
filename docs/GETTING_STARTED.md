# Getting started

What works: encrypted vault, per-contact keypairs, contact exchange by file or local one-time-code pairing, safety-number
verification, chat over Tor (one onion service per contact, client-authorised), file sharing with metadata removal, key rotation,
panic wipe. Layout: contact list always on the left, the right side shows the selected contact's details or the conversation.

## 1. Build and test
```bash
cd ~/Documents/Code/nerd-chat
cargo test --workspace            # ~1 min first time; expect all green (60+ tests)
cargo build --release --locked --target x86_64-unknown-linux-musl -p nerd-chat-tui
ls -la target/x86_64-unknown-linux-musl/release/nerd-chat
```

## 2. First run (creates a vault)
```bash
mkdir -p ~/nerd-chat-demo && cd ~/nerd-chat-demo
~/Documents/Code/nerd-chat/target/x86_64-unknown-linux-musl/release/nerd-chat --vault ./alice.vault
```
Type a passphrase of at least 12 characters, Enter, repeat it, Enter (takes ~4 s: that is the memory-hard KDF).
Keys work like vim: **NORMAL** mode (every key is a command) and **INSERT** mode (keys are text only, nothing typed there can trigger a command).
- Contacts / details: Up/Down (or `j`/`k`, Tab/Shift+Tab) select, `Enter` opens the chat, `i` opens it and starts typing.
- Commands (in the details view AND while reading a chat): `n` new contact, `e` export, `I` import (capital i), `l` listen, `c` connect,
  `x` cancel pairing, `v` verify, `d` delete, `o` online/offline, `f` send file, `t` send text, `a`/`r` accept/decline, `s` save,
  `K` rotate keys, `h` host-anyway, `z` acknowledge an alert, `?` help, `q` quit.
- In a chat: `i` or `Enter` starts typing, `Enter` sends, `Esc` leaves typing; `j`/`k`/PageUp/PageDown scroll the history, `g`/`G` oldest/newest,
  Tab/Shift+Tab switch to the next/previous contact.
- **Esc ladder:** typing -> normal mode -> details -> **privacy screen**. On the privacy screen `Enter` unlocks (no password) and `q` quits.
  It only hides the screen: the vault stays open and anyone at the keyboard can press Enter; messages keep arriving underneath. It is not a lock.
- **Keeping messages (by hand, never automatic):** in a chat press `m` (message cursor), `j`/`k` choose a message, `y` saves THAT message into the
  vault (encrypted with it; no timestamp; at most 500 per contact and 4 MiB in total; not possible in `--ram` mode). Saved messages are marked ★ in the chat.
  `H` opens the saved messages of the selected contact (`d` twice deletes one). Whoever gets your vault AND password can read what you saved.
- `q` quits and wipes RAM; if queued messages or unsaved files would be lost it asks you to press `q` a second time.
**Panic-lock: F12 or Ctrl+\\** wipes memory, clears screen + scrollback and exits immediately; the vault file stays, the password opens it again.
**PURGE: Ctrl+] (or Shift+F12)** does the same AND overwrites and deletes the vault, its rollback counter, the keyfile and every file this
session exported or saved: contacts, keys and saved messages are gone for good. No confirmation, no undo. Works from any screen, also at the
password prompt. Honest limits: every save writes a NEW file and renames it over the old one, so EARLIER versions of the vault (with contacts, keys, and messages you
later deleted) stay in free disk blocks on any filesystem, and on copy-on-write filesystems (btrfs, ZFS) the overwrite never touches old blocks at all;
flash media (SSD, USB stick) may also keep blocks through wear levelling. What really protects a vault is the password plus a KEYFILE on separate
media, which the purge destroys: use both. A keyfile that other vaults share (or a photo you reuse as keyfile) is destroyed too. Symlinks are never followed (a link is only unlinked; the keyfile path is resolved once at start-up). Files exported or saved by this session are destroyed only if they are still the very files the session created. Files you imported, and files exported or saved in earlier sessions, stay. Pasted text is never interpreted as keys (a pasted Ctrl+] cannot purge). `purge: N file(s) overwritten and deleted` is printed after the screen was wiped (counts only).

## 3. Try the file exchange with yourself (two terminals)
Terminal 1 (Alice):
```bash
cd ~/nerd-chat-demo && ~/Documents/Code/nerd-chat/target/x86_64-unknown-linux-musl/release/nerd-chat --vault ./alice.vault
```
`n` -> type `bob` -> Enter.  `e` -> the default file name is a neutral random `bundle-xxxxxxxx.sbc` (your contact's name is never put in a file name); Backspace it away and type `alice-for-bob.sbc` for this demo.

Terminal 2 (Bob):
```bash
cd ~/nerd-chat-demo && ~/Documents/Code/nerd-chat/target/x86_64-unknown-linux-musl/release/nerd-chat --vault ./bob.vault
```
`n` -> `alice` -> Enter. `e` -> file name `bob-for-alice.sbc`.

Then in Terminal 1: `I` -> `bob-for-alice.sbc`. In Terminal 2: `I` -> `alice-for-bob.sbc`.
Both now show **UNVERIFIED** and the SAME safety number. Press `v` on both, compare the digits, press `y`.
Status turns **● verified**. (Real use: send the .sbc over any channel; compare the number by voice/in person.)

## 4. Try local one-time-code pairing (no files)
Add a fresh contact on each side (`n`), then:
- Terminal 1: `l` -> Enter (127.0.0.1:0). The status line shows `Listening on 127.0.0.1:PORT - CODE: 12345-67890`.
- Terminal 2: `c` -> type `127.0.0.1:PORT` -> Enter -> type the code -> Enter.
- Both are asked "exchanged in person?": `y` => code-authenticated, `n` => stays UNVERIFIED.
On two real machines use the LAN IP: `l` -> `192.168.x.y:4000` (listening is only allowed on loopback / private LAN addresses). The code works ONCE (burned on any failure); `x` cancels a pairing in progress.

## 4b. Chat over Tor (two people, or two terminals on one machine)
Prerequisite: `tor` installed (`sudo apt install tor`, then `sudo systemctl disable --now tor` — Nerd-chat starts its own copy).
After the contacts have each other's keys (section 3 or 4), in BOTH terminals:
```bash
# press  o   (go online): Nerd-chat starts its own Tor in a private RAM directory; the title bar shows "starting tor NN%"
# when it says ONLINE, the contact list shows a green dot next to a contact once the connection is up
# HOSTING: if your Tor cannot host onion services (Tails with a restricted control port; check ./nerd-chat --probe-tor --probe-onion),
#   start with --cannot-host BEFORE exporting/pairing: your bundle then says so and the contact hosts for you. h on a contact = 'host anyway'
#   (use only if their bundle claims it can host but its Tor refuses; it makes your online status visible to holders of your bundle).
# FILES (select a connected contact, also while reading its chat): f = send a JPEG/PNG (metadata stripped, other formats refused), t = send plain text,
#   a / r = accept / decline an offer (nothing is sent before you accept), s = save under a neutral name (never overwrites), r = discard.
#   Files live in RAM only until saved. Offline cleaning: ./nerd-chat --strip IN OUT   (see docs/FILE_SHARING.md for the limits)
# Enter on a contact opens the chat (i = open and type): Enter sends, Esc leaves typing, Esc again goes back, o goes offline again (it says "stopping..." for a moment)
```
Connection can take 1-3 minutes the first time (Tor publishes the onion service; the dialing side retries by itself).
Using a Tor that is already running (Tails/Whonix/system):
```bash
./nerd-chat --vault ./alice.vault --tor-control unix:/run/tor/control      # add --tor-trust-control only if you vouch for its owner
```
Good to know:
- Messages exist ONLY in RAM: nothing is written to disk, nothing survives quitting. Messages typed while the other person is
  offline are queued in RAM (max 50) and sent when they connect; they are lost if you quit first.
- Who dials: the contact whose signing key is smaller dials, the other one hosts, so normally only one of you publishes an onion service. If the hosting side cannot host (e.g. Tails refusing it) it switches to dialing and the other side starts hosting after about a minute of failed dials; you will see a notice.
- An unverified contact shows a red warning in the chat header. Verify the safety number first (v).
- There are no read receipts, typing indicators or timestamps (metadata). A small keepalive cell is sent every 30 s while idle.

## 5. RAM-only mode (nothing ever written)
```bash
~/Documents/Code/nerd-chat/target/x86_64-unknown-linux-musl/release/nerd-chat --ram
```

## 6. Static binary for live systems (built and checked by me on one machine; the full recipe with checksums is docs/BUILD_AND_RUN.md section 3)
```bash
rustup target add x86_64-unknown-linux-musl
cd ~/Documents/Code/nerd-chat
cargo build --release --target x86_64-unknown-linux-musl -p nerd-chat-tui
ldd target/x86_64-unknown-linux-musl/release/nerd-chat     # want: "statically linked" (or "not a dynamic executable")
```

## 7. On a live USB system (checklist)
```bash
cat /proc/swaps                    # must be EMPTY (swap can write keys to the host disk). If not: sudo swapoff -a
free -m                            # <1.5 GB free? use --low-mem
cp /media/$USER/YOURUSB/nerd-chat /tmp/ && chmod +x /tmp/nerd-chat   # if the USB is mounted noexec
/tmp/nerd-chat --vault /media/$USER/YOURUSB/nerd-chat.vault --low-mem
```
Put the keyfile and counter file on a DIFFERENT device than the vault:
```bash
head -c 64 /dev/urandom > /media/$USER/KEYUSB/key.bin
/tmp/nerd-chat --vault /media/$USER/YOURUSB/s.vault --keyfile /media/$USER/KEYUSB/key.bin --counter-file /media/$USER/KEYUSB/s.counter
```
(The keyfile must be present at creation AND every unlock. Losing it = losing the vault.)

## 8. Prepare for the Tor stage (read-only checks; installs are YOUR call)
```bash
sudo apt install autoconf automake libtool pkg-config libevent-dev zlib1g-dev libssl-dev perl git   # Debian/Ubuntu names
rustup target add x86_64-unknown-linux-musl
git ls-remote --tags https://gitlab.torproject.org/tpo/core/tor.git | tail -5    # pick the newest stable tag
```
Static musl linking of tor additionally needs `musl-tools` and static libevent/zlib/openssl builds — I will script
and verify that in the spike; do not install anything beyond the above until then.

## What the app does for you automatically
- Core dumps disabled and the process marked non-dumpable at startup.
- SIGTERM / SIGHUP (closing the terminal) / SIGINT trigger the same wipe as the panic key.
- Never follows symlinks and never blocks on FIFOs/devices when importing; refuses to create a new vault over an old rollback counter.

## Known limits right now
See docs/SECURITY_TRACKER.md. Biggest: no locked memory, `snow` is only partly wiped (see the tracker), the privacy screen is not an authentication lock,
panic wipe cannot clear RAM remanence or your terminal emulator's own memory (power off for that).
