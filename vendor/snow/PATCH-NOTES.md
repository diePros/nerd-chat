# Local patch of snow 0.10.0 (tracker R2-M3 / D-3 / R7-L1)

Upstream `snow` never zeroizes. Changes (all marked `seburity patch` in the sources), nothing else is modified:
- `zeroize` dependency (no default features, `alloc`); `crates/core` pins `snow = "=0.10.0"` so a registry release can never silently replace this copy.
- **Wiped on drop:** snow-owned X25519 private keys (`Dh25519`), ChaChaPoly/XChaChaPoly/AES-GCM keys, the Noise chaining key and
  hash (`SymmetricState`), pre-shared keys (`PskSlots`).
- **Wiped after use:** HKDF/HMAC locals, the DH shared-secret copies (`dh_out` and the one inside `Dh25519::dh`), split/mix_key
  outputs and derived cipher keys, PSK copies, the private-key temporaries in `Dh25519::set/generate`, the BLAKE2 `result()`
  temporaries, the `Copy` checkpoint of the symmetric state taken on every handshake message.
- The per-call by-value ChaCha key copy was removed (`Key::from_slice`).
- **Not covered:** private-key/shared-secret temporaries inside curve25519-dalek, the poly1305 one-time-key state, the blake2 hashers'
  internal buffers, compiler copies in registers/stack, P256/KEM code (not compiled in). Nothing is wiped when a panic aborts the
  process (release profile `panic = "abort"`). Integrity of this copy rests on git: upstream crates.io checksum of 0.10.0 is
  `599b506...` (see git history of Cargo.lock); audit with `diff -r vendor/snow ~/.cargo/registry/src/*/snow-0.10.0`.
- Reviewed by an independent agent: diff contains only wiping changes; a handshake interop test (patched vs upstream, all pairings,
  late `set_psk`, tampered message, nonce checks) passed.

Verification: `key_material_is_wiped_on_drop` (in `src/resolvers/default.rs`) drops a `Dh25519` and a `CipherChaChaPoly` in place and checks the
bytes are zero. It cannot run inside this workspace (snow's optional/dev dependencies are not in the offline registry), so it was run in a
stripped standalone copy of `vendor/snow/src` with only the dependencies seburity enables (13/13 tests incl. this one pass).
