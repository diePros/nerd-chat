//! Public contact bundle: what you hand to a contact (file / QR / local link).
//! Contains ONLY public keys. Self-signed so accidental corruption is detected;
//! real authenticity comes from comparing the fingerprint out-of-band.
use crate::{identity::ContactIdentity, Error};
use blake2::{Blake2b, Digest, digest::consts::U32};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};
use ml_kem::{EncapsulationKey768, KeyExport};

pub const KEM_PUB_LEN: usize = 1184;

const MAGIC: &[u8; 4] = b"SBC2";
const BODY_LEN: usize = 4 + 32 + 32 + KEM_PUB_LEN;
pub const BUNDLE_LEN: usize = BODY_LEN + 64;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Bundle {
    pub sign_pub: [u8; 32],
    pub dh_pub: [u8; 32],
    pub kem_pub: [u8; KEM_PUB_LEN],
}

impl Bundle {
    pub fn from_identity(id: &ContactIdentity) -> Self {
        Self {
            sign_pub: id.verifying_key().to_bytes(),
            dh_pub: id.dh_public().to_bytes(),
            kem_pub: id.kem_public().to_bytes().as_slice().try_into().expect("ML-KEM-768 ek length"),
        }
    }

    fn body(&self) -> [u8; BODY_LEN] {
        let mut b = [0u8; BODY_LEN];
        b[..4].copy_from_slice(MAGIC);
        b[4..36].copy_from_slice(&self.sign_pub);
        b[36..68].copy_from_slice(&self.dh_pub);
        b[68..].copy_from_slice(&self.kem_pub);
        b
    }

    /// Serialize and self-sign (domain-separated).
    pub fn encode(&self, id: &ContactIdentity) -> Vec<u8> {
        let body = self.body();
        let sig = id.sign.sign(&[b"seburity-bundle-v1".as_slice(), &body].concat());
        let mut out = body.to_vec();
        out.extend_from_slice(&sig.to_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() != BUNDLE_LEN || &b[..4] != MAGIC { return Err(Error::Malformed); }
        let me = Self {
            sign_pub: b[4..36].try_into().unwrap(),
            dh_pub: b[36..68].try_into().unwrap(),
            kem_pub: b[68..BODY_LEN].try_into().unwrap(),
        };
        // Reject a malformed/invalid ML-KEM key up front rather than at handshake time.
        me.kem_key()?;
        let vk = me.verifying_key()?;
        me.check_dh_pub()?;
        let sig = Signature::from_bytes(b[BODY_LEN..].try_into().unwrap());
        vk.verify_strict(&[b"seburity-bundle-v1".as_slice(), &b[..BODY_LEN]].concat(), &sig)
            .map_err(|_| Error::BadSignature)?;
        Ok(me)
    }

    /// Rebuild a bundle from stored public parts (e.g. from the authenticated vault) applying
    /// the same key validity checks as `decode`.
    pub fn from_parts(sign_pub: [u8; 32], dh_pub: [u8; 32], kem_pub: [u8; KEM_PUB_LEN]) -> Result<Self, Error> {
        let me = Self { sign_pub, dh_pub, kem_pub };
        me.verifying_key()?;
        me.check_dh_pub()?;
        me.kem_key()?;
        Ok(me)
    }

    /// Ed25519 key, rejecting small-order ("weak") keys for which universal signatures exist.
    pub fn verifying_key(&self) -> Result<VerifyingKey, Error> {
        let vk = VerifyingKey::from_bytes(&self.sign_pub).map_err(|_| Error::Malformed)?;
        if vk.is_weak() { return Err(Error::Malformed); }
        Ok(vk)
    }

    /// Strictly verify a domain-prefixed signature made by this bundle's Ed25519 key.
    pub fn verify_domain(&self, msg: &[u8], sig: &[u8; 64]) -> bool {
        match self.verifying_key() {
            Ok(vk) => vk.verify_strict(msg, &Signature::from_bytes(sig)).is_ok(),
            Err(_) => false,
        }
    }

    /// Reject low-order X25519 points (they force an all-zero, public DH output).
    pub fn check_dh_pub(&self) -> Result<(), Error> {
        let probe = StaticSecret::from([0x42u8; 32]);
        if probe.diffie_hellman(&XPublic::from(self.dh_pub)).was_contributory() { Ok(()) } else { Err(Error::Malformed) }
    }

    pub fn kem_key(&self) -> Result<EncapsulationKey768, Error> {
        EncapsulationKey768::new(&self.kem_pub.into()).map_err(|_| Error::Malformed)
    }

    /// 32-byte BLAKE2b fingerprint over the public keys.
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut h = Blake2b::<U32>::new();
        h.update(b"seburity-fingerprint-v1");
        h.update(self.body());
        h.finalize().into()
    }

    /// Human-comparable fingerprint: 8 groups of 5 decimal digits (~133 bits).
    /// Prefer [`safety_number`], which both parties see identically.
    pub fn fingerprint_digits(&self) -> String { digits(&self.fingerprint()) }
}

fn digits(f: &[u8; 32]) -> String {
    {
        f.chunks(4)
            .map(|c| format!("{:05}", u32::from_be_bytes(c.try_into().unwrap()) % 100_000))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Combined, order-independent number over BOTH bundles. Both users read this aloud /
/// compare it and it must be identical on both sides (so a MITM that swaps one bundle shows up).
pub fn safety_number(a: &Bundle, b: &Bundle) -> String {
    let (mut x, mut y) = (a.fingerprint(), b.fingerprint());
    if x > y { std::mem::swap(&mut x, &mut y); }
    let mut h = Blake2b::<U32>::new();
    h.update(b"seburity-safety-number-v1");
    h.update(x);
    h.update(y);
    digits(&h.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tamper() {
        let id = ContactIdentity::generate();
        let b = Bundle::from_identity(&id);
        let enc = b.encode(&id);
        assert_eq!(Bundle::decode(&enc).unwrap(), b);
        for i in 0..enc.len() {
            let mut t = enc.clone();
            t[i] ^= 1;
            assert!(Bundle::decode(&t).is_err(), "byte {i}");
        }
        assert_eq!(Bundle::decode(&enc[..enc.len() - 1]), Err(Error::Malformed));
    }

    #[test]
    fn identities_are_unlinkable_and_fingerprints_differ() {
        let a = Bundle::from_identity(&ContactIdentity::generate());
        let b = Bundle::from_identity(&ContactIdentity::generate());
        assert_ne!(a.fingerprint(), b.fingerprint());
        assert_eq!(a.fingerprint_digits().split(' ').count(), 8);
    }

    #[test]
    fn rejects_weak_keys_and_safety_number_is_symmetric() {
        let id = ContactIdentity::generate();
        let good = Bundle::from_identity(&id);
        // low-order X25519 point (zero) and identity Ed25519 point
        let mut bad = good.clone(); bad.dh_pub = [0; 32];
        assert_eq!(bad.check_dh_pub(), Err(Error::Malformed));
        let mut bad = good.clone(); bad.sign_pub = { let mut p = [0u8; 32]; p[0] = 1; p };
        assert_eq!(bad.verifying_key().err(), Some(Error::Malformed));
        let other = Bundle::from_identity(&ContactIdentity::generate());
        assert_eq!(safety_number(&good, &other), safety_number(&other, &good));
        assert_ne!(safety_number(&good, &other), safety_number(&good, &good));
    }

    #[test]
    fn secret_bytes_roundtrip() {
        let id = ContactIdentity::generate();
        let id2 = ContactIdentity::from_secret_bytes(&id.secret_bytes()).unwrap();
        assert_eq!(Bundle::from_identity(&id), Bundle::from_identity(&id2));
        assert!(ContactIdentity::from_secret_bytes(&[0; 63]).is_none());
    }
}
