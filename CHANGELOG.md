# Changelog

## Unreleased (branch `next`, not part of the audited 0.1.0)
- Delivery confirmation and resend: every text has an id, the contact's app confirms it, unconfirmed texts are resent on every new
  connection and shown once (`docs/DELIVERY.md`). A message written into a dying connection is no longer lost. `(queued)` now means
  "not yet confirmed"; a full outbox (50) refuses the new message instead of dropping an old one.
- Key-rotation notice no longer reads as a failure when the connection is briefly down; docs: `ldd` says "statically linked".

## 0.1.0 (first public release, unaudited)
First release. Everything in `README.md` is in it: per-contact keys (Noise KKpsk0+psk2 with ML-KEM-768 hybrid), password vault,
Tor onion service per contact with client authorisation, key rotation, sandboxed metadata-stripping file transfer (seccomp helper),
vim-style terminal UI with permanent contact list, manual-only message saving, panic-lock (F12) and purge (Ctrl+]).

Not done and said so: independent audit, Tails test, cross-machine reproducible-build comparison, locked memory, GUI/Android
(see `docs/ROADMAP.md`). Open items: `docs/SECURITY_TRACKER.md`.

Verify the download before running it: `docs/RELEASE_TESTING.md` part A.
