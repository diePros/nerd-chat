# Seburity — serverless, Tor-routed, single-binary secure chat (Rust)

## Context
Goal: a chat for high-risk users with **no server in between**, contacts added by **local key exchange** (file / QR / direct BLE-Wi-Fi), per-contact keypairs, a password-locked vault, routable over **Tor** (and WireGuard/VPN if wanted), shipped as **one executable** that runs from a live-booted Linux. Repo is empty (greenfield); nothing to reuse. Decisions made with user: **online-only P2P**, **embedded C `tor`** (Arti later), **terminal TUI**.

Honest framing: "most secure possible" is a process, not a feature. Biggest real risks are endpoint compromise, user error and traffic correlation, not the cipher. The plan therefore minimizes metadata, attack surface and persisted state, and treats audit/reproducible builds as part of v1.

## Research findings

### Rust from a live Linux
- Build `x86_64-unknown-linux-musl` (fully static, no glibc dependency) → runs on any x86_64 Linux kernel regardless of distro/glibc. Also ship `aarch64-unknown-linux-musl` as a **separate** file (one file cannot be both arches). Not runnable on non-Linux/Windows/macOS — out of scope.
- Pitfalls: C deps (openssl) must be avoided/vendored → use pure-Rust crypto (RustCrypto, dalek, `snow`, `ml-kem`, `argon2`) and `rustls`-free design. musl's allocator is slow; fine for chat, optional mimalloc.
- Live-distro caveats (**must verify on real ISOs, not assumed**): some live systems mount USB/persistent storage `noexec` → run from tmpfs, or fall back to `memfd_create` + `fexecve` loader. **Tails** firewalls all non-Tor traffic, so a bundled `tor` cannot reach guards there → app needs a **"use system Tor" mode** (SOCKS 127.0.0.1:9050 + control port) in addition to embedded Tor. Embedded-tor static musl build (libevent/zlib/OpenSSL vendored) is feasible but is the riskiest build task — spike it first.

### Transport options (ranked for this threat model)
| Option | Verdict |
|---|---|
| **Tor v3 onion service per contact** (Ricochet/Cwtch/Briar model) | **Chosen.** No server, NAT-free, hides both IPs, mature. Add **onion client-authorization** (x25519) so the address is unreachable/undiscoverable without the contact's key, plus vanguards. Weakness: global passive adversary timing correlation; Tor hosting needs contact online simultaneously (accepted for v1). |
| Arti (Rust Tor) | Client side OK, but its onion-**service** side is officially experimental, no vanguards/PoW/padding → not for hosting yet. Revisit. |
| I2P (garlic routing; Rust `emissary`) | Truly P2P, good alt; smaller network, weaker anonymity research. Optional future second transport. |
| Nym / Katzenpost mixnets | Best vs. global passive adversary (cover traffic, delays) but need mix infra/tokens = third parties, higher latency. Future "high-paranoia" transport. |
| Veilid, libp2p/DHT, GNUnet | DHT/p2p without onion routing leaks IPs to peers/DHT; Veilid has private routes but young. Not v1. |
| Direct BLE / Wi-Fi Direct / LAN | Use for **key exchange and proximity chat**, not remote. No Internet metadata at all. |
| SimpleX/Matrix-style servers | Violates "no server". |

### WireGuard / VPN
Don't embed WG in v1. Support it at the network layer: (a) **VPN → Tor** (hides Tor use from ISP) = just run VPN, app unaware; (b) **Tor → VPN** is not recommended (exit-side only, irrelevant for onion). App config: `--bind-interface`, upstream SOCKS/HTTP proxy, **Tor bridges (obfs4/snowflake/webtunnel)**. Optional later: userspace WG (boringtun) as a *direct* transport between two known peers with fixed endpoints — leaks IPs, so documented as non-anonymous.

### Prior art to learn from (not copy blindly)
Ricochet Refresh, Cwtch, Briar (audited; multi-transport), Session/SimpleX (server-based). Reuse their lessons: per-contact onion identity, no offline delivery in the pure model, fixed-size messages.

## Design

### Identity & keys
- **One keypair set per contact** (unlinkable across contacts): Ed25519 (message signing ONLY; the Tor onion identity is a SEPARATE per-contact key so the signing key never reaches the C tor process), X25519 (DH), ML-KEM-768 (hybrid post-quantum, Noise PSK-style mixing, PQXDH-like).
- Adding a contact = generate new set locally → create a **bundle**: `{version, ed25519_pub, x25519_pub, mlkem_pub, onion_addr, client_auth_pub, optional BLE/LAN hints, self-signature}` + short **fingerprint (word list + QR)** for verification.

### Contact exchange (all offline-first)
1. **File** (`.sbc`) via USB/sneakernet/air gap — authenticity from physical channel + fingerprint comparison.
2. **QR** (show/scan; text QR fallback for TUI) for in-person.
3. **Direct local link** over BLE / Wi-Fi Direct / LAN: encrypted with **CPace/SPAKE2 PAKE** from a short code read aloud/shown; then exchange bundles; finish with **SAS comparison** (anti-MITM). Never touches Internet.
- Bundles hold only public keys, but since bundle v3 they also contain the onion address: **treat them as confidential** (an address lets anyone watch when the service is online, see docs/TRANSPORT.md). Optional: wrap bundle with a shared passphrase.

### Session protocol
- Noise `KK`/`IK`-style handshake (via `snow`) using the pre-shared static keys + hybrid ML-KEM; **fresh ephemerals every connection** → forward secrecy; periodic in-session rekey (ratchet). Mutual auth at handshake level.
- **Every message is signed AND encrypted** (user requirement): sign with the per-contact Ed25519 key (hybrid with ML-DSA-65 for post-quantum), signature covers `{sender_id, recipient_id, session_id, counter, timestamp, plaintext}`, then AEAD-encrypt inside the Noise session. Receiver: AEAD-decrypt → verify signature against the key pinned from the contact bundle → drop + flag in UI on failure. Counter/session binding prevents replay, reorder and cross-contact forwarding.
- **Tradeoff (documented):** signatures give non-repudiation — a recipient or someone seizing their vault can prove authorship to third parties. Default = signed; optional per-contact **"deniable mode"** relies on Noise authentication only.
- **Fixed-size padded cells** (e.g., 1 KiB), constant-rate optional cover cells, no read receipts/typing indicators, length-hiding for files via chunking. Messages queue locally (encrypted) until peer is online; ephemeral/disappearing default.

### Key storage (vault)
- **What is stored:** one encrypted vault holding per-contact private keys (Ed25519/X25519/ML-KEM), per-contact onion identity, contacts, queued messages. **Never stored:** session/ratchet/ephemeral keys (RAM only → session forward secrecy survives even if old vault copies leak).
- **Hierarchy:** password (+ optional keyfile on separate USB) → Argon2id (memory-hard, calibrated to ≥1 s, 512 MiB–1 GiB if RAM allows; params carried in a few bytes bound as AEAD associated data) → KEK → wraps random vault data key (password change = rewrap only) → XChaCha20-Poly1305. File has **no magic header**, looks random. Atomic writes (temp+fsync+rename).
- **Onion key handling:** passed to tor from memory via control port `ADD_ONION ED25519-V3`; never written by tor to a HiddenServiceDir.
- **In RAM:** `mlock`'d, zeroize-on-drop, guard pages, `memfd_secret` where kernel ≥5.14, `PR_SET_DUMPABLE=0`, no core dumps.
- **Live-OS handling:**
  - **RAM-only mode (default):** vault lives in memory; gone at shutdown unless exported.
  - **Persistent mode:** vault file at a user-chosen path on the USB stick/separate device; on Tails inside Persistent Storage (verify in spike). Keyfile on a different device as optional 2nd factor.
  - **Swap guard:** check `/proc/swaps` at startup, refuse if active (override flag); never mount/touch internal disks.
  - **Cold boot:** panic-wipe hotkey zeroizes and exits (Tails wipes RAM on shutdown; most distros don't — documented).
  - **Screen/clipboard:** TUI alternate screen, no scrollback, no clipboard.
  - **Flash caveat (documented honestly):** wear-levelling may retain old vault copies decryptable with the same password → history not protected vs later password compromise; mitigated by disappearing messages by default, RAM-only mode, keyfile 2nd factor.
- Later: duress password / hidden vault.

### Anti-forensics / hardening
No logs, no telemetry, no auto-update. Seccomp + (where available) Landlock sandbox after startup; drop privileges; separate Tor process confined. `cargo-deny`, `cargo-vet`, `#![forbid(unsafe_code)]` outside small audited modules, fuzzing of parsers, **reproducible builds + signed releases**, written threat model, then **external audit** before recommending to real users.

## Workspace layout (new repo)
```
Cargo.toml (workspace)
crates/core      # protocol, bundle format, Noise+PQ handshake, cells
crates/vault     # Argon2id + AEAD vault, zeroize/mlock
crates/exchange  # file/QR/PAKE local exchange (BLE via bluer/btleplug, LAN)
crates/net       # transport trait; embedded-tor driver; system-tor driver; bridge/proxy cfg
crates/tui       # ratatui front end (core stays UI-agnostic for later GUI)
bin/seburity     # single static binary: embeds tor, loads via memfd
docs/THREAT_MODEL.md, docs/PROTOCOL.md
```

## Milestones
0. **Spikes (de-risk)**: static musl build of embedded `tor` + launch from memfd; boot Tails + one generic live ISO, run binary, confirm exec/noexec and system-Tor mode; BLE exchange proof.
1. `core` + `vault` with test vectors, property tests, fuzzing.
2. Two clients chat over loopback, then over Tor onion services with client auth.
3. Contact exchange: file → QR → PAKE/SAS local link.
4. TUI, **panic shortcut + no-cache guarantees**, `vault-mem` crate (mlock/memfd_secret, the only `unsafe`), RAM-only mode, hardening (seccomp/Landlock), reproducible build.
5. Threat-model review, external audit, then optional I2P/Nym transports and Arti swap.

## Panic shortcut (added by user request)
A single always-active hotkey (e.g. Ctrl+\\, also reachable from every screen and while typing) that, in this order and without confirmation:
1. Locks the vault: zeroize DK/KEK and all per-contact secret keys, drop all sessions and Noise state.
2. Wipes plaintext: zeroize message buffers, input line, scrollback model, fingerprint/QR buffers; clear the terminal and its scrollback (alternate screen + reset sequences).
3. Tears down the network: kill embedded tor / close control port, removing the onion services.
4. Exits via `abort`-safe path after wiping (unlock requires the password again). Also triggered by: SIGTERM/SIGHUP, USB-removal of the vault device (optional), idle timeout, 3 failed unlocks.
**No-cache principle:** nothing is cached by design. No history file, no log, no temp files, no clipboard, no swap (mlock + swap guard), no core dumps; plaintext lives only in mlock'd zeroizing buffers; the vault is the only thing ever written to disk, and in RAM-only mode not even that. Caveat to document: zeroizing userspace memory cannot clear CPU caches/DRAM remanence or terminal-emulator memory outside our process; on a live OS the strongest panic is power-off (Tails wipes RAM at shutdown). Optionally offer "panic + poweroff" where permitted.
Implementation lives with the `vault-mem` crate (locked secret memory) in milestone 4; the zeroize-on-drop discipline starts now.

## Roadmap item (last): secure file sharing with metadata removal
Send files over the same signed + encrypted session, in fixed-size chunks (so file size/timing leak as little as possible), with:
- **Metadata stripping before sending**, on the sender's machine, by default and not optional per file type:
  images (EXIF/GPS/maker notes/ICC/thumbnails/XMP, re-encode instead of copy so hidden data in unknown segments is dropped),
  PDF and Office/ODF documents (author, revision history, comments, tracked changes, embedded files, XMP, creation tools),
  audio/video (ID3/tags, chapters, encoder strings), archives (member timestamps/owners/paths), and filesystem metadata
  (timestamps, permissions, owner, xattrs). Unknown formats are refused unless the user explicitly sends them as an opaque blob
  (clearly labelled "NOT cleaned"). Show a before/after report of what was removed.
- **Neutral file names** (random by default, the real name only inside the encrypted channel and only if the user keeps it),
  no MIME sniffing from peers, size caps, strict parsers in a sandboxed process (seccomp/Landlock), never auto-open.
- **Receiver side**: files land in RAM first (or a user-chosen directory with neutral names), integrity verified end-to-end
  (hash inside the signed session), a quarantine step that re-checks and re-strips, and no preview rendering of untrusted formats.
- **Padding/chunking** to hide exact sizes, optional cover traffic while a transfer runs, resume after reconnect inside the session only.
- Later: stripped-copy verification tooling (`seburity strip FILE` as a standalone command), reproducible test corpus
  (files with planted metadata) proving each stripper, and an audit of every parser used.
Honest limit: stripping cannot remove information that is in the content itself (faces, handwriting, writing style, visible text).

## Verification
- `cargo test` + `cargo fuzz` on bundle/cell/handshake parsers; known-answer tests for KDF/AEAD.
- `ldd bin/seburity` → "not a dynamic executable"; run on Tails, a Debian live and an Alpine/Arch live ISO in QEMU (and on real hardware).
- End-to-end: two VMs, exchange bundles by file, chat over Tor; `tcpdump` confirms only Tor traffic leaves the host; confirm no plaintext/keys on disk (`strings`, entropy check of vault, RAM-only mode leaves nothing).
- Wrong-password and tamper tests (vault must fail closed); reproducible-build hash match across two machines.

## Open items to confirm during spikes
Tails exec/Tor-control-port behavior; BLE availability in live environments; ML-KEM crate maturity; exact Argon2 parameters for low-RAM live systems.

## Security review log & known open gaps
Two adversarial Opus reviews done (vault; core+vault). Fixed: DK rotation, wiped Argon2 memory, no plaintext vault header, total-size padding, rollback check API (`open_checked`), PQ forward secrecy (ephemeral ML-KEM via `KKpsk0+psk2`), counter desync on failed send, msg1 replay (unconfirmed sessions), weak Ed25519 / low-order X25519 rejection, `verify_strict`, no sender timestamps on the wire, combined safety number, Zeroizing message buffers, prologue binding.
**Still open (tracked):**
- `snow` does not zeroize Noise state/keys on drop -> fork/patch snow (ZeroizeOnDrop) or hand-roll KK on zeroizing primitives, before claiming the panic-wipe guarantee.
- Locked secret memory (`vault-mem` crate, mlock/memfd_secret) not written; vault `Vault`/identity secrets still on pageable heap.
- Initiator authentication is classical only (add ML-DSA + reverse static KEM).
- Rollback counter must be persisted OUTSIDE the vault by the app (keyfile device) and passed to `open_checked`.
- Bundle must additionally carry/cover the onion address + client-auth key in the signature and safety number once the transport exists.
- `ml-kem` crate is unaudited upstream.
- Responder CPU cost per unauthenticated msg1 (1 decaps + 2 X25519): rely on onion client-auth + rate limiting.
