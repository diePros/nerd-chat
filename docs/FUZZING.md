# Fuzzing (libFuzzer via cargo-fuzz)

Targets live in `fuzz/` (a separate crate, nightly toolchain, never part of a release build):

| Target | What it feeds with hostile bytes | Invariants checked |
|---|---|---|
| `strip` | JPEG / PNG / plain text into the metadata stripper, and the sandbox helper's answer decoder | never panics (release builds abort), cleaning is idempotent |
| `formats` | contact bundle (binary and armored), the vault's contact book | never panics |
| `frames` | everything an authenticated but hostile contact can send: text chunks, file offer/chunk/control frames, padded file streams, key-rotation frames | never panics, reassembly stays consistent |

```bash
rustup toolchain install nightly --profile minimal && cargo install cargo-fuzz     # once
cargo +nightly fuzz run strip fuzz/seeds/strip -- -max_total_time=300                # from the repository root; seeds = small valid PNG/JPEG/text
cargo +nightly fuzz run formats -- -max_total_time=300
cargo +nightly fuzz run frames  -- -max_total_time=300
```
A crash is written to `fuzz/artifacts/<target>/`; reproduce with `cargo +nightly fuzz run <target> <file>`, minimise with `tmin`.
Run them for longer before every release (hours, several cores): the first 75-120 s runs (3.3 M executions of `strip`) found one bug:
a text file made only of removable characters was "cleaned" to an EMPTY file and sent, which the receiver's own cleaning refuses (now refused up front).
Not fuzzed yet (they need the slow Argon2 KDF or a live Tor): the vault opener, the Noise handshake and the Tor control-port parser: candidates for
dedicated targets with the insecure test KDF / a scripted control socket.
