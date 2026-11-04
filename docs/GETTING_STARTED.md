# Getting started (current stage: vault, contacts, local exchange, TUI — no chat transport yet)

Chat itself needs the Tor transport (next stage). What works today: encrypted vault, per-contact keypairs,
contact exchange by file or local one-time-code pairing, safety-number verification, panic wipe.

## 1. Build and test
```bash
cd ~/Documents/Code/seburity
cargo test --workspace            # ~1 min first time; expect all green (60+ tests)
cargo build --release -p seburity-tui
ls -la target/release/seburity
```

## 2. First run (creates a vault)
```bash
mkdir -p ~/seburity-demo && cd ~/seburity-demo
~/Documents/Code/seburity/target/release/seburity --vault ./alice.vault
```
Type a passphrase of at least 12 characters, Enter, repeat it, Enter (takes ~4 s: that is the memory-hard KDF).
Keys: `n` new contact, `e` export, `i` import, `l` listen, `c` connect, `x` cancel pairing, `v` verify, `d` delete, `?` help, `q` quit.
**Panic: F12 or Ctrl+\\** — locks, clears screen + scrollback, exits immediately.

## 3. Try the file exchange with yourself (two terminals)
Terminal 1 (Alice):
```bash
cd ~/seburity-demo && ~/Documents/Code/seburity/target/release/seburity --vault ./alice.vault
```
`n` -> type `bob` -> Enter.  `e` -> the default file name is a neutral random `bundle-xxxxxxxx.sbc` (your contact's name is never put in a file name); Backspace it away and type `alice-for-bob.sbc` for this demo.

Terminal 2 (Bob):
```bash
cd ~/seburity-demo && ~/Documents/Code/seburity/target/release/seburity --vault ./bob.vault
```
`n` -> `alice` -> Enter. `e` -> file name `bob-for-alice.sbc`.

Then in Terminal 1: `i` -> `bob-for-alice.sbc`. In Terminal 2: `i` -> `alice-for-bob.sbc`.
Both now show **UNVERIFIED** and the SAME safety number. Press `v` on both, compare the digits, press `y`.
Status turns **● verified**. (Real use: send the .sbc over any channel; compare the number by voice/in person.)

## 4. Try local one-time-code pairing (no files)
Add a fresh contact on each side (`n`), then:
- Terminal 1: `l` -> Enter (127.0.0.1:0). The status line shows `Listening on 127.0.0.1:PORT - CODE: 12345-67890`.
- Terminal 2: `c` -> type `127.0.0.1:PORT` -> Enter -> type the code -> Enter.
- Both are asked "exchanged in person?": `y` => code-authenticated, `n` => stays UNVERIFIED.
On two real machines use the LAN IP: `l` -> `192.168.x.y:4000` (listening is only allowed on loopback / private LAN addresses). The code works ONCE (burned on any failure); `x` cancels a pairing in progress.

## 4b. Chat over Tor (two people, or two terminals on one machine)
Prerequisite: `tor` installed (`sudo apt install tor`, then `sudo systemctl disable --now tor` — Seburity starts its own copy).
After the contacts have each other's keys (section 3 or 4), in BOTH terminals:
```bash
# press  o   (go online): Seburity starts its own Tor in a private RAM directory; the title bar shows "starting tor NN%"
# when it says ONLINE, the contact list shows a green dot next to a contact once the connection is up
# Enter on a contact opens the chat: type, Enter sends, Esc goes back, o goes offline again (it says "stopping..." for a moment)
```
Connection can take 1-3 minutes the first time (Tor publishes the onion service; the dialing side retries by itself).
Using a Tor that is already running (Tails/Whonix/system):
```bash
./seburity --vault ./alice.vault --tor-control unix:/run/tor/control      # add --tor-trust-control only if you vouch for its owner
```
Good to know:
- Messages exist ONLY in RAM: nothing is written to disk, nothing survives quitting. Messages typed while the other person is
  offline are queued in RAM (max 50) and sent when they connect; they are lost if you quit first.
- Who dials: the contact whose signing key is smaller dials, the other one hosts, so normally only one of you publishes an onion service. If the hosting side cannot host (e.g. Tails refusing it) it switches to dialing and the other side starts hosting after about a minute of failed dials; you will see a notice.
- An unverified contact shows a red warning in the chat header. Verify the safety number first (v).
- There are no read receipts, typing indicators or timestamps (metadata). A small keepalive cell is sent every 30 s while idle.

## 5. RAM-only mode (nothing ever written)
```bash
~/Documents/Code/seburity/target/release/seburity --ram
```

## 6. Static binary for live systems (NOT yet tested by me — try it and tell me what breaks)
```bash
rustup target add x86_64-unknown-linux-musl
cd ~/Documents/Code/seburity
cargo build --release --target x86_64-unknown-linux-musl -p seburity-tui
ldd target/x86_64-unknown-linux-musl/release/seburity     # want: "not a dynamic executable"
```

## 7. On a live USB system (checklist)
```bash
cat /proc/swaps                    # must be EMPTY (swap can write keys to the host disk). If not: sudo swapoff -a
free -m                            # <1.5 GB free? use --low-mem
cp /media/$USER/YOURUSB/seburity /tmp/ && chmod +x /tmp/seburity   # if the USB is mounted noexec
/tmp/seburity --vault /media/$USER/YOURUSB/seburity.vault --low-mem
```
Put the keyfile and counter file on a DIFFERENT device than the vault:
```bash
head -c 64 /dev/urandom > /media/$USER/KEYUSB/key.bin
/tmp/seburity --vault /media/$USER/YOURUSB/s.vault --keyfile /media/$USER/KEYUSB/key.bin --counter-file /media/$USER/KEYUSB/s.counter
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
See docs/SECURITY_TRACKER.md. Biggest: no locked memory / core-dump protection yet, `snow` does not zeroize,
no chat transport, panic wipe cannot clear RAM remanence or your terminal emulator's own memory (power off for that).
