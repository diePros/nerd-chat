//! Public contact bundle: what you hand to a contact (file / QR / local link).
//! Contains ONLY public keys. Self-signed so accidental corruption is detected;
//! real authenticity comes from comparing the fingerprint out-of-band.
use crate::{identity::ContactIdentity, Error};
use blake2::{Blake2b, Digest, digest::consts::U32};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
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
        let vk = VerifyingKey::from_bytes(&me.sign_pub).map_err(|_| Error::Malformed)?;
        let sig = Signature::from_bytes(b[BODY_LEN..].try_into().unwrap());
        vk.verify(&[b"seburity-bundle-v1".as_slice(), &b[..BODY_LEN]].concat(), &sig)
            .map_err(|_| Error::BadSignature)?;
        Ok(me)
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

    /// Human-comparable fingerprint: 8 groups of 5 decimal digits (Signal-style),
    /// derived from the first 40 hash bytes' worth of entropy we have (32 bytes -> 8x4 bytes).
    pub fn fingerprint_digits(&self) -> String {
        let f = self.fingerprint();
        f.chunks(4)
            .map(|c| format!("{:05}", u32::from_be_bytes(c.try_into().unwrap()) % 100_000))
            .collect::<Vec<_>>()
            .join(" ")
    }
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
    fn secret_bytes_roundtrip() {
        let id = ContactIdentity::generate();
        let id2 = ContactIdentity::from_secret_bytes(&id.secret_bytes()).unwrap();
        assert_eq!(Bundle::from_identity(&id), Bundle::from_identity(&id2));
        assert!(ContactIdentity::from_secret_bytes(&[0; 63]).is_none());
    }
}
