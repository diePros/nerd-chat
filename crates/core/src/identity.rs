//! Per-contact key material. A fresh `ContactIdentity` is generated for EVERY
//! contact so contacts cannot link you across conversations.
use ed25519_dalek::{SigningKey, VerifyingKey};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};
use ml_kem::{DecapsulationKey768, EncapsulationKey768, Seed};
use zeroize::Zeroizing;

pub struct ContactIdentity {
    pub(crate) sign: SigningKey,
    pub(crate) dh: StaticSecret,
    pub(crate) kem: DecapsulationKey768,
    kem_seed: Zeroizing<[u8; 64]>,
}

pub const SECRET_LEN: usize = 32 + 32 + 64;

impl ContactIdentity {
    pub fn generate() -> Self {
        let mut b = Zeroizing::new([0u8; SECRET_LEN]);
        getrandom::fill(&mut *b).expect("OS RNG unavailable");
        Self::from_secret_bytes(&*b).expect("fixed length")
    }

    /// 128 bytes: ed25519 seed || x25519 secret || ML-KEM-768 seed. For storage inside the vault only.
    pub fn secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut v = Zeroizing::new(Vec::with_capacity(SECRET_LEN));
        v.extend_from_slice(&self.sign.to_bytes());
        v.extend_from_slice(&self.dh.to_bytes());
        v.extend_from_slice(&*self.kem_seed);
        v
    }

    pub fn from_secret_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != SECRET_LEN { return None; }
        let s: Zeroizing<[u8; 32]> = Zeroizing::new(b[..32].try_into().ok()?);
        let d: Zeroizing<[u8; 32]> = Zeroizing::new(b[32..64].try_into().ok()?);
        let k: Zeroizing<[u8; 64]> = Zeroizing::new(b[64..].try_into().ok()?);
        let kem = DecapsulationKey768::from_seed(Seed::from(*k));
        Some(Self { sign: SigningKey::from_bytes(&s), dh: StaticSecret::from(*d), kem, kem_seed: k })
    }

    pub fn verifying_key(&self) -> VerifyingKey { self.sign.verifying_key() }
    pub fn dh_public(&self) -> XPublic { XPublic::from(&self.dh) }
    pub fn kem_public(&self) -> EncapsulationKey768 { self.kem.encapsulation_key().clone() }
}
