# Fuzzing (libFuzzer via cargo-fuzz)

Targets live in `fuzz/` (a separate crate, nightly toolchain, never part of a release build):

| Target | What it feeds with hostile bytes | Invariants checked |
|---|---|---|
| `strip` | JPEG / PNG / plain text into the metadata stripper, and the sandbox helper's answer decoder | never panics (release builds abort), cleaning is idempotent |
| `formats` | contact bundle (binary and armored), the vault's contact book | never panics |
| `tor_parsers` | what a hostile or squatting process on the Tor control/SOCKS port can answer: control replies, PROTOCOLINFO, GETINFO values, SOCKS5 replies | never panics, never loops or allocates without bound |
| `frames` | everything an authenticated but hostile contact can send: text chunks, file offer/chunk/control frames, padded file streams, key-rotation frames | never panics, reassembly stays consistent |

```bash
rustup toolchain install nightly --profile minimal && cargo install cargo-fuzz     # once
cargo +nightly fuzz run strip fuzz/seeds/strip -- -max_total_time=300                # from the repository root; seeds = small valid PNG/JPEG/text
cargo +nightly fuzz run formats -- -max_total_time=300
cargo +nightly fuzz run frames  -- -max_total_time=300
cargo +nightly fuzz run tor_parsers fuzz/seeds/tor_parsers -- -max_total_time=300
```
A crash is written to `fuzz/artifacts/<target>/`; reproduce with `cargo +nightly fuzz run <target> <file>`, minimise with `tmin`.
Run them for longer before every release (hours, several cores): the first 75-120 s runs (3.3 M executions of `strip`) found one bug:
a text file made only of removable characters was "cleaned" to an EMPTY file and sent, which the receiver's own cleaning refuses (now refused up front).
Long runs so far (7 min each): `strip` 4.9 M, `formats` 384 k, `frames` 534 k executions, `tor_parsers` 979 k (3 min): no crash.
Not fuzzed yet (they need the slow Argon2 KDF): the vault opener and the Noise handshake responder: candidates for dedicated targets with the insecure test KDF.
