# Fuzzing (libFuzzer via cargo-fuzz)

Targets live in `fuzz/` (a separate crate, nightly toolchain, never part of a release build):

| Target | What it feeds with hostile bytes | Invariants checked |
|---|---|---|
| `strip` | JPEG / PNG / plain text into the metadata stripper, and the sandbox helper's answer decoder | never panics (release builds abort), cleaning is idempotent |
| `formats` | contact bundle (binary and armored), the vault's contact book | never panics |
| `handshake` | the Noise responder (`link::accept`) fed hostile bytes as message 1 and first cell | never panics, never completes a handshake. Coverage stays shallow by design: without the keys every input dies at the first authentication check, so this proves robustness of the pre-auth path, not of the post-auth one (that is `frames`) |
| `tor_parsers` | what a hostile or squatting process on the Tor control/SOCKS port can answer: control replies, PROTOCOLINFO, GETINFO values, SOCKS5 replies | never panics, never loops or allocates without bound |
| `frames` | everything an authenticated but hostile contact can send: text chunks (with and without id), delivery confirmations, capability frames, file offer/chunk/control frames, padded file streams, key-rotation frames, and sequences of frames through one reassembler | never panics, reassembled text <= 32 KiB, at most 64 ids per confirmation |

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
Long runs so far (7 min each): `strip` 4.9 M, `formats` 384 k, `frames` 534 k executions, `tor_parsers` 979 k (3 min), `handshake` 23 M (2 min): no crash.
After the delivery-confirmation work (cycle 38) `frames` was extended and run 4 min (310 k sequences): no crash.
The vault opener has no dedicated target on purpose: a mutated blob fails the AEAD check before any parsing, and every failed open runs the real Argon2 profiles (512 MiB), so the fuzzer would only measure the KDF. Its decoded payload (`Store::decode`) is covered by `formats`.
