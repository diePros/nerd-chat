# Changelog

## 0.1.0 (first public release, unaudited)
First release. Everything in `README.md` is in it: per-contact keys (Noise KKpsk0+psk2 with ML-KEM-768 hybrid), password vault,
Tor onion service per contact with client authorisation, key rotation, sandboxed metadata-stripping file transfer (seccomp helper),
vim-style terminal UI with permanent contact list, manual-only message saving, panic-lock (F12) and purge (Ctrl+]).

Not done and said so: independent audit, Tails test, cross-machine reproducible-build comparison, locked memory, GUI/Android
(see `docs/ROADMAP.md`). Open items: `docs/SECURITY_TRACKER.md`.

Verify the download before running it: `docs/RELEASE_TESTING.md` part A.
