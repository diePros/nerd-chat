# Local patch of snow 0.10.0 (tracker R2-M3 / D-3 / R7-L1)

Upstream `snow` never zeroizes. Changes (all marked `seburity patch` in the sources), nothing else is modified:
- `zeroize` dependency (no default features, `alloc`).
- Drop-time wiping of: X25519 private key (`Dh25519`), cipher keys (`CipherChaChaPoly`, `CipherXChaChaPoly`, `CipherAesGcm`),
  the Noise chaining key and hash (`SymmetricState`), pre-shared keys (`PskSlots`).
- Wiping of stack temporaries holding secrets: HKDF/HMAC intermediates (`types.rs`), DH outputs, split/mix_key outputs and
  derived cipher keys (`symmetricstate.rs`, `handshakestate.rs`), PSK copies (`builder.rs`).
Not covered: copies made by the compiler on the stack/registers, the `Copy` checkpoint of the symmetric state used for rollback
while reading a handshake message (`SymmetricStateData`), the hash functions' internal buffers (blake2 crate), and anything
outside snow (see docs/SECURITY_TRACKER.md R4-M2). Review the diff against the registry copy to audit: `diff -r vendor/snow ~/.cargo/registry/src/*/snow-0.10.0`.

Verification: `key_material_is_wiped_on_drop` (in `src/resolvers/default.rs`) drops a `Dh25519` and a `CipherChaChaPoly` in place and checks the
bytes are zero. It cannot run inside this workspace (snow's optional/dev dependencies are not in the offline registry), so it was run in a
stripped standalone copy of `vendor/snow/src` with only the dependencies seburity enables (13/13 tests incl. this one pass).
