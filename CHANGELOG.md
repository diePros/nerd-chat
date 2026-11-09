# Changelog

## Unreleased (branch `next`, not part of the audited 0.1.0)
- Delivery confirmation and resend: every text has an id (inside the text frame, so a short text is still one cell), the contact's UI
  confirms it once it HOLDS the text, unconfirmed texts are resent on every new connection and shown once (`docs/DELIVERY.md`). A message
  written into a dying connection is no longer lost. `(queued)` now means "not yet confirmed"; a full outbox (50) refuses the new message
  instead of dropping an old one; going offline with unconfirmed messages asks first and marks them "(NOT CONFIRMED)". The id travels inside the text frame; a peer
  announces its capabilities first, and a peer that does not (v0.1.0) gets the old plain frames, so the two versions interoperate (tested
  with the real 0.1.0 binary over Tor). Confirmations wait 1-5 s and are batched, so a reply cannot be timed. Tracker: review 24.
- Encrypted outbox (opt-in, key `O`; the Android app turns it on by default): texts the contact has not confirmed yet are kept in the password-locked vault until they are confirmed, survive a restart, and can be written while offline. Vault format SBS6, written only when the feature is used (every other vault stays SBS5). Costs and limits: `docs/DELIVERY.md`; open findings OB-1..OB-10 in the tracker; not yet reviewed adversarially.
- Message history (setting `Persist`: nothing / unsent only / 1 day / 7 days; key `O` cycles it; off by default on Linux, 1 day by default in the Android app): kept messages live in a separate encrypted file `<vault>.hist` made of two fixed-size slots written in place, with a random key per 6-hour bucket wrapped per 24-hour epoch (Android: Keystore; Linux: best-effort overwrite, refused on copy-on-write and network file systems). The unsent-text outbox moved into it. The history file and the touching of the vault files happen on a 5 s grid so their times do not show when you sent a message (vault SAVES are immediate: adding a contact, saving a message, a key rotation show their own moment, tracker R33-11); a text is confirmed to the sender only after it is durably stored. The rollback counter file is now fixed-size, encrypted and grows by random steps; it also records the newest history generation, so an old copy of the history file is refused. Android: bucket keys are wrapped by per-epoch Android Keystore keys (StrongBox when present) and an erase job destroys expired ones even while the phone is locked; a key store that refuses to wrap makes the write fail instead of losing the bucket. Not yet verified on a device: Keystore deletion strength, f2fs behaviour, the erase job under Doze. Plan: `docs/HISTORY_AND_TIMING_PLAN.md`.
- Key ratchet inside a connection: after every 32 cells sent or 10 minutes the sender announces a `KIND_REKEY` frame and both sides replace that direction's transport key by a one-way function of itself (forward secrecy within a long Tor connection). Negotiated by a new capability bit (`CAP_REKEY`); peers without it (v0.1.0, older branch builds) are never sent the frame. Not yet tested against the real v0.1.0 binary or over real Tor.
- `.deb` package: `scripts/release.sh` also builds `nerd-chat_<version>_amd64.deb` (same static binary, deterministic, no maintainer scripts, `Recommends: tor`), listed in SHA256SUMS.
- Default vault location: without `--vault`, an existing `~/.local/share/nerd-chat/nerd-chat.vault` ($XDG_DATA_HOME) is used from any
  directory, else an existing `./nerd-chat.vault`; a new vault is created there only after the user confirms the shown path (Tails gets a
  warning, directory mode 0700, unsafe directories refused, scripts must pass `--vault`). `--ram` now always wins over `--vault`.
- Key-rotation notice no longer reads as a failure when the connection is briefly down; docs: `ldd` says "statically linked".

## 0.1.0 (first public release, unaudited)
First release. Everything in `README.md` is in it: per-contact keys (Noise KKpsk0+psk2 with ML-KEM-768 hybrid), password vault,
Tor onion service per contact with client authorisation, key rotation, sandboxed metadata-stripping file transfer (seccomp helper),
vim-style terminal UI with permanent contact list, manual-only message saving, panic-lock (F12) and purge (Ctrl+]).

Not done and said so: independent audit, Tails test, cross-machine reproducible-build comparison, locked memory, GUI/Android
(see `docs/ROADMAP.md`). Open items: `docs/SECURITY_TRACKER.md`.

Verify the download before running it: `docs/RELEASE_TESTING.md` part A.
