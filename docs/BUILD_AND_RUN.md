# Build, test and run Seburity (static binary, live systems, Tails)

Honest status first. "Verified" means somebody actually ran it.

| Item | Status |
|---|---|
| `cargo test --workspace` (100+ tests) | verified, green |
| Static musl build (`x86_64-unknown-linux-musl`), runs, panic key works | verified (dev machine) |
| Live Tor test (spawn tor, host onion + client auth, dial, full handshake) | **verified by the project owner on their machine (Tor 0.4.9.11)** |
| Reproducible build (same hash on two machines) | **NOT verified** — procedure in §4 |
| Running on a generic live USB distro | **NOT verified** — checklist in §7 |
| Running on Tails | **NOT verified, deferred** — plan in §8 |
| Chat screens | **not built yet** (vault, contacts, pairing, verification, panic, Tor transport exist) |

---
## 1. Prerequisites (build machine)
Build on a machine you trust, ideally a clean one, **not** on the live system you will use for sensitive work.
```bash
rustup toolchain list                       # we have built with rustc 1.98.1
rustup target add x86_64-unknown-linux-musl # needed once for the static build
# for the live Tor test only:
sudo apt install tor
sudo systemctl disable --now tor            # we start our own private tor; the system service is not needed
```
Pure Rust only: no C compiler or musl-gcc is needed (the earlier failure came from `ring`, now removed from the tree).
If a future dependency ever drags in a C build script again, the musl build will fail with "failed to find tool
x86_64-linux-musl-gcc": treat that as a signal to find and remove the dependency, not just to install a compiler.

## 2. Run the tests
```bash
cd ~/Documents/Code/seburity
cargo test --workspace                       # about 1 min the first time, 20-30 s afterwards
```
Rules:
- Do **not** run `cargo test --release` or `cargo build --release --all-targets`. They enable the insecure fast test KDF
  and the build is *designed* to fail with `feature insecure-test-kdf must never be enabled in release builds`.
- Expect all green. A red test is a security signal: do not ship a binary from a red tree.

Live Tor test (needs `tor` installed and Internet; takes minutes):
```bash
cargo test -p seburity-net --test tor_live -- --ignored --nocapture
```
You should see `bootstrap NN%`, `hosting <address>.onion`, maybe a few `dial not yet`, then `test ... ok`.
Re-run it after any change in `crates/net/src/tor` or after upgrading Tor.

## 3. Build the static binary
```bash
cd ~/Documents/Code/seburity
git status --short                           # must be clean: you want to know exactly what you built
git rev-parse HEAD                           # note the commit
cargo build --release --locked --target x86_64-unknown-linux-musl -p seburity-tui
B=target/x86_64-unknown-linux-musl/release/seburity
file $B                                      # expect: ELF 64-bit ... static-pie linked
ldd $B                                       # expect: statically linked  (or: not a dynamic executable)
ls -la $B                                    # about 1.1 MB
sha256sum $B | tee seburity.sha256           # record next to the commit hash
$B --probe-tor                               # smoke test: runs and prints a report
```
`--locked` makes the build fail instead of silently updating dependencies: `Cargo.lock` is committed on purpose.
The release profile (`opt-level z`, LTO, `panic = abort`, stripped) is in the workspace `Cargo.toml`.

The binary only runs on x86-64 Linux. ARM (Raspberry Pi etc.) needs its own build (`aarch64-unknown-linux-musl`,
not tried); one file cannot serve both.

## 4. Reproducible-build check (do this before trusting a release)
Goal: two independent builds produce the same SHA-256. This is **untested**; the first run may differ because of
embedded absolute paths. Try:
```bash
export RUSTFLAGS="--remap-path-prefix=$PWD=/src --remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$HOME/.rustup=/rustup"
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
cargo build --release --locked --target x86_64-unknown-linux-musl -p seburity-tui
sha256sum target/x86_64-unknown-linux-musl/release/seburity
```
Run it in two different directories (and ideally on two machines with the same toolchain version) and compare. If the
hashes differ, diff with `diffoscope` and fix before claiming reproducibility. Pinning the toolchain with a
`rust-toolchain.toml` (channel `1.98.1`) is recommended and **not yet done** (tracker D-4).

## 5. Integrity and signing (recommended, not yet automated)
- Publish the commit hash, `seburity.sha256` and a **detached signature** made on an offline machine, e.g.
  `gpg --armor --detach-sign seburity` or `minisign -Sm seburity`.
- On the target machine verify BEFORE running: `sha256sum -c seburity.sha256` and the signature. Compare the signing key
  fingerprint over a second channel (voice / in person), the same way you compare safety numbers.
- Never run a binary that arrived through the same channel as its checksum and nothing else.
- Dependency hygiene still to set up: `cargo deny check`, `cargo vet`, `cargo audit`
  (`cargo install cargo-audit cargo-deny` — your call). Review `Cargo.lock` diffs in every update.

## 6. Prepare the USB sticks
Use **two** sticks if you can; their roles must be different devices:
```
STICK-A (the program + vault)            STICK-B (the second factor)
  seburity            (the static file)    key.bin           (keyfile, 64 random bytes)
  seburity.sha256 + .sig                   seburity.counter  (rollback counter)
  seburity.vault      (created on 1st run)
```
```bash
head -c 64 /dev/urandom > /media/$USER/STICK-B/key.bin            # create once; losing it = losing the vault
chmod 600 /media/$USER/STICK-B/key.bin                            # no effect on FAT, harmless
cp seburity seburity.sha256 /media/$USER/STICK-A/
sync
```
Run with the second factor:
```bash
./seburity --vault /media/$USER/STICK-A/seburity.vault \
           --keyfile /media/$USER/STICK-B/key.bin \
           --counter-file /media/$USER/STICK-B/seburity.counter
```
Back up the keyfile separately and offline; without the keyfile AND the passphrase the vault cannot be opened (by design).
FAT/exFAT sticks ignore file permissions: the vault is encrypted, but treat the sticks as sensitive objects.

## 7. Generic live Linux (checklist, untested on real hardware)
```bash
cat /proc/swaps                  # must print only the header. Seburity REFUSES to start otherwise: sudo swapoff -a   (or --allow-swap at your own risk)
free -m                          # little RAM? add --low-mem (128 MiB key derivation instead of 512 MiB)
mount | grep -E "STICK|media"    # 'noexec' on the stick? then:
cp /media/$USER/STICK-A/seburity /tmp/ && chmod +x /tmp/seburity && /tmp/seburity ...
ulimit -c                        # 0 expected; Seburity also sets RLIMIT_CORE=0 and non-dumpable itself
```
Do not mount or touch the computer's internal disks. Prefer a live system that wipes RAM on shutdown. Power off to end
the session; Seburity's panic key cleans its own process, not RAM remanence or the terminal emulator's memory.

## 8. Tails (deferred; this is the plan so the later test is quick)
What exists today vs what will be tested:
- Today you can: start the app, create/unlock the vault, add contacts, export/import bundles, pair over the LAN, verify
  safety numbers, and **probe Tor**. The chat screens do not exist yet, so a Tails test now can only answer the
  *environment* questions below.
- Tails facts (from Tails' own design page): all Internet traffic except Tor is blocked; LAN and loopback are open; applications
  must use Tor explicitly. Not documented there, and therefore **unknown until tested**: whether the `amnesia` user may
  use Tor's control port and `ADD_ONION`; whether the Persistent Storage allows executing programs.

When you do the Tails session:
```bash
# 1. get the binary on (second stick or Persistent Storage), verify it:
sha256sum -c seburity.sha256
chmod +x ./seburity            # if "Permission denied": copy it to /tmp or ~ and chmod there (noexec mounts)
# 2. ask the environment:
./seburity --probe-tor --probe-onion > probe.txt; cat probe.txt
# if the report says the control port's owner is NOT TRUSTED but you know it is Tails' own tor, repeat with:
./seburity --probe-tor --probe-onion --tor-trust-control > probe2.txt; cat probe2.txt
```
Interpret `probe.txt`:
- `RESULT: control port works` and `ADD_ONION ... ALLOWED` -> EXTERNAL mode can host and dial: full chat possible.
- control port refused / auth fails but a SOCKS listener answers -> only dialing possible; hosting blocked.
- nothing reachable -> do not start a second tor on Tails (it cannot reach the network); report the output.
- Send/keep the output: it decides how the external mode is finished.
Other things to note on that day: whether the vault in Persistent Storage opens and saves, how long unlocking takes
(`--low-mem`?), whether LAN pairing (`l` / `c`) works between two machines, and whether `/proc/swaps` is empty.
Do **not** run `sudo` for anything; none of this needs administration rights.

## 9. Best practices
Build and supply chain
- Build on a clean, trusted machine; note the commit hash and keep `seburity.sha256` with it; always `--locked`.
- Rebuild from source rather than trusting binaries from others, until reproducible builds are verified (§4).
- Update dependencies deliberately (`cargo update -p NAME`), read the diff of `Cargo.lock`, re-run all tests incl. the live test.
- Keep a record of the Tor version used for the live test (currently 0.4.9.11) and re-test on upgrades.

Operation
- Passphrase: long and unique (12+ chars is the enforced floor; use 5-6 random words). Never type it where others can see
  or where a keylogger may exist. Add the keyfile on a separate stick for real use.
- Verify EVERY contact: compare the safety number over a different channel (voice/in person) before first chat; trust
  states are shown in the UI (`unverified` / `code-authenticated` / `verified`). A file import is always unverified.
- Pairing code: tell it in person or by voice, only once; if pairing fails for any reason start over with a fresh code
  and ask yourself who else could have heard it.
- One keypair per contact is automatic; do not reuse export files between contacts and delete them after import.
- Panic key (F12 or Ctrl+\\) is for emergencies; closing the terminal or SIGTERM does the same wipe. Then power off.
- Terminal hygiene: avoid tmux/screen logging and terminal "scrollback to file" features; disable screenshots and
  clipboard managers; do not paste passwords.
- Keep the vault, keyfile and counter on different devices; keep keyfile backups offline.
- After any rollback suspicion (`ROLLBACK DETECTED`): stop, do not "fix" it by deleting the counter file; find out why an old copy appeared.
- Treat the machine as untrusted for anything beyond what Seburity can protect: a compromised OS defeats every software
  protection. Prefer a freshly booted amnesic live system.

Tor
- Spawn mode (own tor) is for ordinary machines; on Tails/Whonix use the system Tor (external mode), never a second tor.
- If Tor is blocked where you are, use bridges (planned flag) — and expect that using Tor itself can be visible to an ISP;
  a VPN in front of Tor hides that, Tor over a VPN does not hide you from the VPN.
- An onion address is stable for as long as the contact exists. Delete a contact (`d`) to burn its keys and address.

## 10. Troubleshooting
| Symptom | Cause / fix |
|---|---|
| `failed to find tool "x86_64-linux-musl-gcc"` | a C-building dependency crept in; `cargo tree --target x86_64-unknown-linux-musl -i cc` shows which |
| `feature insecure-test-kdf must never be enabled` | you built/tested with `--release --all-targets`; use the plain commands in §2/§3 |
| `Permission denied` when starting from the stick | stick mounted `noexec`: copy to `/tmp` |
| unlock takes ~4 s | intended (512 MiB memory-hard KDF); `--low-mem` only if RAM is scarce |
| `OutOfMemory` on unlock | not enough free RAM for the profile; close programs or use a `--low-mem` vault |
| `ROLLBACK DETECTED` | older vault copy than the counter file: see §9, do not delete the counter |
| `CounterExists` on create | a counter file from an old vault is in the way; delete it only if you are sure the old vault is gone |
| live test hangs at `bootstrap 0%` | no Internet or Tor blocked; try bridges or another network |
| `dial not yet: onion service not found` | descriptor still uploading; retries up to 3 min are normal |
| `refusing to authenticate: the identity of the control port's owner was not verified` | the control socket is owned by some other account: check who runs it; use spawn mode, a unix socket owned by tor, or `--tor-trust-control` if you vouch for it |

## 11. Known limits (see docs/SECURITY_TRACKER.md for the full list)
No locked memory/swap protection beyond refusing to depend on it (check `/proc/swaps` yourself), `snow` does not zeroize
its state, the panic wipe cannot clear RAM remanence or terminal-emulator memory, post-quantum protection covers
confidentiality only (authentication is classical), `ml-kem` and `spake2` are not independently audited, and the code
has had adversarial AI review but **no professional audit**. Do not rely on it for life-critical secrecy before that.
