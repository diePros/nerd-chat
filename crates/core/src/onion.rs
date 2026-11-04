//! Tor v3 onion-service identity helpers (pure, no network): address derivation, Tor's expanded
//! secret key format, and the base32 forms used by the control protocol / client authorization.
//! The onion key is SEPARATE from the Ed25519 message-signing key (the signing key never reaches tor).
use crate::Error;
use sha2::{Digest as _, Sha512};
use sha3::Sha3_256;
use zeroize::Zeroizing;

const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// RFC 4648 base32, no padding. `upper` = control-protocol form for auth keys.
pub fn base32_encode(data: &[u8], upper: bool) -> String {
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            let c = B32[((buf >> (bits - 5)) & 31) as usize] as char;
            out.push(if upper { c.to_ascii_uppercase() } else { c });
            bits -= 5;
        }
    }
    if bits > 0 {
        let c = B32[((buf << (5 - bits)) & 31) as usize] as char;
        out.push(if upper { c.to_ascii_uppercase() } else { c });
    }
    out
}

/// Strict decode of lowercase-or-uppercase base32 without padding. Rejects non-canonical trailing bits.
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let (mut buf, mut bits) = (0u32, 0u32);
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    for c in s.bytes() {
        let v = B32.iter().position(|&x| x == c.to_ascii_lowercase())? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 { out.push((buf >> (bits - 8)) as u8); bits -= 8; }
    }
    if bits > 0 && (buf & ((1 << bits) - 1)) != 0 { return None; }
    Some(out)
}

fn checksum(pubkey: &[u8; 32]) -> [u8; 2] {
    let mut h = Sha3_256::new();
    h.update(b".onion checksum");
    h.update(pubkey);
    h.update([3u8]);
    let d = h.finalize();
    [d[0], d[1]]
}

/// `<56 base32 chars>` (without the `.onion` suffix): base32(pubkey || checksum || 0x03).
pub fn service_id(pubkey: &[u8; 32]) -> String {
    let mut raw = [0u8; 35];
    raw[..32].copy_from_slice(pubkey);
    raw[32..34].copy_from_slice(&checksum(pubkey));
    raw[34] = 3;
    base32_encode(&raw, false)
}

pub fn onion_address(pubkey: &[u8; 32]) -> String { format!("{}.onion", service_id(pubkey)) }

/// Parse and verify a v3 onion address (with or without `.onion`) back to its public key.
pub fn parse_onion_address(s: &str) -> Result<[u8; 32], Error> {
    let id = s.strip_suffix(".onion").unwrap_or(s);
    if id.len() != 56 || id != id.to_ascii_lowercase() { return Err(Error::Malformed); }
    let raw = base32_decode(id).ok_or(Error::Malformed)?;
    if raw.len() != 35 || raw[34] != 3 { return Err(Error::Malformed); }
    let pk: [u8; 32] = raw[..32].try_into().unwrap();
    if raw[32..34] != checksum(&pk) { return Err(Error::Malformed); }
    Ok(pk)
}

/// Tor's 64-byte expanded secret key for `ADD_ONION ED25519-V3:<base64>`: clamped SHA-512(seed) halves.
pub fn expanded_secret(seed: &[u8; 32]) -> Zeroizing<[u8; 64]> {
    use zeroize::Zeroize;
    let mut h = Sha512::digest(seed);
    let mut k = Zeroizing::new([0u8; 64]);
    k.copy_from_slice(&h);
    h[..].zeroize(); // the digest IS the expanded secret key: do not leave a copy behind
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    k
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_known_vectors_and_roundtrip() {
        // RFC 4648 test vectors (lowercase, no padding)
        for (i, o) in [("", ""), ("f", "my"), ("fo", "mzxq"), ("foo", "mzxw6"), ("foob", "mzxw6yq"), ("fooba", "mzxw6ytb"), ("foobar", "mzxw6ytboi")] {
            assert_eq!(base32_encode(i.as_bytes(), false), o);
            assert_eq!(base32_decode(o).unwrap(), i.as_bytes());
        }
        assert_eq!(base32_encode(b"foo", true), "MZXW6");
        assert!(base32_decode("mz!").is_none());
        assert!(base32_decode("mzxr").is_none(), "non-canonical trailing bits");
    }

    #[test]
    fn address_roundtrip_and_tamper() {
        // (structure check only: 56 chars + suffix; the checksum rule is covered by the tamper loop below)
        let pk = [0u8; 32];
        let a = onion_address(&pk);
        assert_eq!(a.len(), 56 + 6);
        assert_eq!(parse_onion_address(&a).unwrap(), pk);
        let pk2 = [7u8; 32];
        let id = service_id(&pk2);
        assert_eq!(parse_onion_address(&id).unwrap(), pk2);
        // every single-character change must be rejected (checksum / canonical form)
        for i in 0..id.len() {
            let mut b = id.clone().into_bytes();
            b[i] = if b[i] == b'a' { b'b' } else { b'a' };
            assert!(parse_onion_address(&String::from_utf8(b).unwrap()).is_err(), "char {i}");
        }
        assert!(parse_onion_address("short").is_err());
        assert!(parse_onion_address(&id.to_ascii_uppercase()).is_err());
        assert!(parse_onion_address(&format!("{id}x")).is_err());
    }

    #[test]
    fn expanded_secret_matches_ed25519_public_key() {
        // tor's expanded key must produce the same public key as the seed does in ed25519
        use ed25519_dalek::SigningKey;
        let seed = [9u8; 32];
        let k = expanded_secret(&seed);
        assert_eq!(k[0] & 7, 0);
        assert_eq!(k[31] & 0x80, 0);
        assert_eq!(k[31] & 0x40, 0x40);
        let vk = SigningKey::from_bytes(&seed).verifying_key();
        // public key = clamped scalar * basepoint; check via dalek's own derivation from the expanded scalar
        let a: [u8; 32] = k[..32].try_into().unwrap();
        let derived = curve_pub(&a);
        assert_eq!(derived, vk.to_bytes());
    }

    fn curve_pub(clamped: &[u8; 32]) -> [u8; 32] {
        use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
        let s = Scalar::from_bytes_mod_order(*clamped);
        (ED25519_BASEPOINT_POINT * s).compress().to_bytes()
    }
}
