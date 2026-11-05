//! Public contact bundle: what you hand to a contact (file / QR / local link).
//! Contains ONLY public keys. Self-signed so accidental corruption is detected;
//! real authenticity comes from comparing the fingerprint out-of-band.
use crate::{identity::ContactIdentity, Error};
use blake2::{Blake2b, Digest, digest::consts::U32};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};
use ml_kem::{EncapsulationKey768, KeyExport};

pub const KEM_PUB_LEN: usize = 1184;

const MAGIC: &[u8; 4] = b"SBC4";
const CAP_OFF: usize = 132;
const BODY_LEN: usize = 4 + 32 + 32 + 32 + 32 + 1 + KEM_PUB_LEN;
pub const BUNDLE_LEN: usize = BODY_LEN + 64;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Bundle {
    pub sign_pub: [u8; 32],
    pub dh_pub: [u8; 32],
    /// Public key of the onion service THIS party hosts for the contact (the other side dials it).
    pub onion_pub: [u8; 32],
    /// Client-authorization key: the OTHER party's onion service must authorize this key.
    pub auth_pub: [u8; 32],
    /// Capability, signed with the rest: this party CAN host an onion service (false e.g. on a Tails whose Tor control port
    /// refuses ADD_ONION). The roles are chosen from it, so nobody has to publish a service just to find out. NOT part of the
    /// fingerprint/safety number (it is operational, and both sides must compute the same number from key material only).
    pub can_host: bool,
    pub kem_pub: [u8; KEM_PUB_LEN],
}

impl Bundle {
    pub fn from_identity(id: &ContactIdentity) -> Self {
        Self {
            sign_pub: id.verifying_key().to_bytes(),
            dh_pub: id.dh_public().to_bytes(),
            onion_pub: id.onion_public(),
            auth_pub: id.auth_public().to_bytes(),
            can_host: true,
            kem_pub: id.kem_public().to_bytes().as_slice().try_into().expect("ML-KEM-768 ek length"),
        }
    }

    pub fn with_can_host(mut self, can_host: bool) -> Self { self.can_host = can_host; self }

    /// Same identity, other transport keys (onion service + client-auth key): key rotation (docs/KEY_ROTATION.md).
    pub fn with_transport(mut self, onion_pub: [u8; 32], auth_pub: [u8; 32]) -> Self { self.onion_pub = onion_pub; self.auth_pub = auth_pub; self }

    fn body(&self) -> [u8; BODY_LEN] {
        let mut b = [0u8; BODY_LEN];
        b[..4].copy_from_slice(MAGIC);
        b[4..36].copy_from_slice(&self.sign_pub);
        b[36..68].copy_from_slice(&self.dh_pub);
        b[68..100].copy_from_slice(&self.onion_pub);
        b[100..132].copy_from_slice(&self.auth_pub);
        b[CAP_OFF] = self.can_host as u8;
        b[CAP_OFF + 1..].copy_from_slice(&self.kem_pub);
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
            onion_pub: b[68..100].try_into().unwrap(),
            auth_pub: b[100..132].try_into().unwrap(),
            can_host: match b[CAP_OFF] { 0 => false, 1 => true, _ => return Err(Error::Malformed) },
            kem_pub: b[CAP_OFF + 1..BODY_LEN].try_into().unwrap(),
        };
        // Reject a malformed/invalid ML-KEM key up front rather than at handshake time.
        me.kem_key()?;
        let vk = me.verifying_key()?;
        me.check_dh_pub()?;
        me.check_onion_keys()?;
        let sig = Signature::from_bytes(b[BODY_LEN..].try_into().unwrap());
        vk.verify_strict(&[b"seburity-bundle-v1".as_slice(), &b[..BODY_LEN]].concat(), &sig)
            .map_err(|_| Error::BadSignature)?;
        Ok(me)
    }

    /// Rebuild a bundle from stored public parts (e.g. from the authenticated vault) applying
    /// the same key validity checks as `decode`.
    pub fn from_parts(sign_pub: [u8; 32], dh_pub: [u8; 32], onion_pub: [u8; 32], auth_pub: [u8; 32], can_host: bool, kem_pub: [u8; KEM_PUB_LEN]) -> Result<Self, Error> {
        let me = Self { sign_pub, dh_pub, onion_pub, auth_pub, can_host, kem_pub };
        me.verifying_key()?;
        me.check_dh_pub()?;
        me.check_onion_keys()?;
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

    /// The onion public key must be a valid, non-weak Ed25519 point; the auth key must be contributory.
    pub fn check_onion_keys(&self) -> Result<(), Error> {
        let vk = VerifyingKey::from_bytes(&self.onion_pub).map_err(|_| Error::Malformed)?;
        if vk.is_weak() { return Err(Error::Malformed); }
        let probe = StaticSecret::from([0x24u8; 32]);
        if !probe.diffie_hellman(&XPublic::from(self.auth_pub)).was_contributory() { return Err(Error::Malformed); }
        Ok(())
    }

    /// `<56 chars>.onion` this party hosts for the contact.
    pub fn onion_address(&self) -> String { crate::onion::onion_address(&self.onion_pub) }

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
        h.update(b"seburity-fingerprint-v2"); // v2: identity keys only (v1 also covered onion/auth/capability): old numbers must NOT match
        let mut body = self.body();
        body[CAP_OFF] = 0; // identity key material only: the capability bit and ...
        body[68..132].fill(0); // ... the transport keys (onion + client-auth) are operational and rotate; the session itself
                               // is authenticated by sign/dh/kem, so a swapped onion/auth key can only fail the handshake
        h.update(body);
        h.finalize().into()
    }

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
    fn transport_keys_can_rotate_without_changing_the_safety_number() {
        let a = Bundle::from_identity(&ContactIdentity::generate());
        let b = Bundle::from_identity(&ContactIdentity::generate());
        let rotated = a.clone().with_transport([7; 32], [9; 32]);
        assert_ne!(a, rotated);
        assert_eq!(a.fingerprint(), rotated.fingerprint());
        assert_eq!(safety_number(&a, &b), safety_number(&rotated, &b));
        // ... but changing an identity key does change it
        let mut other = a.clone(); other.dh_pub[0] ^= 1;
        assert_ne!(a.fingerprint(), other.fingerprint());
    }

    #[test]
    fn capability_is_signed_but_not_part_of_the_safety_number() {
        let id = ContactIdentity::generate();
        let yes = Bundle::from_identity(&id);
        let no = yes.clone().with_can_host(false);
        assert!(Bundle::decode(&yes.encode(&id)).unwrap().can_host);
        assert!(!Bundle::decode(&no.encode(&id)).unwrap().can_host);
        assert_eq!(yes.fingerprint(), no.fingerprint(), "both sides must compute the same number whatever the capability");
        let other = Bundle::from_identity(&ContactIdentity::generate());
        assert_eq!(safety_number(&yes, &other), safety_number(&no, &other));
        // flipping the bit without the key breaks the signature; a value other than 0/1 is malformed
        let mut enc = yes.encode(&id); enc[CAP_OFF] = 0;
        assert_eq!(Bundle::decode(&enc), Err(Error::BadSignature));
        enc[CAP_OFF] = 2;
        assert_eq!(Bundle::decode(&enc), Err(Error::Malformed));
    }

    #[test]
    fn identities_are_unlinkable_and_fingerprints_differ() {
        let a = Bundle::from_identity(&ContactIdentity::generate());
        let b = Bundle::from_identity(&ContactIdentity::generate());
        assert_ne!(a.fingerprint(), b.fingerprint());
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
        let mut bad = good.clone(); bad.onion_pub = { let mut p = [0u8; 32]; p[0] = 1; p };
        assert_eq!(bad.check_onion_keys(), Err(Error::Malformed));
        let mut bad = good.clone(); bad.auth_pub = [0; 32];
        assert_eq!(bad.check_onion_keys(), Err(Error::Malformed));
        assert_eq!(good.onion_address().len(), 62);
        assert_ne!(good.onion_pub, good.sign_pub, "onion identity is a separate key from the signing key");
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
