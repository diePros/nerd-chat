//! Password-locked vault (hardened after adversarial review).
//!
//! File = `salt[16] | wrap_nonce[24] | wrapped_dk[48] | data_nonce[24] | ciphertext`.
//! There are NO plaintext parameters or magic bytes: the file is uniformly random-looking.
//! KDF parameters come from a fixed set of compiled-in profiles tried in order, so a
//! tampered file can neither choose its own cost nor trigger huge allocations.
//!
//! keyfile --BLAKE2b--> 32-byte secret; password + secret --Argon2id(profile, salt)--> KEK
//! KEK wraps a random data key (DK); DK encrypts `counter | len | data | zero padding`.
//! Changing credentials ROTATES the DK and re-seals (an old copy + old password must not
//! unlock or forge future vaults). A monotonic save counter lives inside the plaintext.
//! The format version is bound through the AAD (not stored).
//!
//! Known limits (documented): in-RAM protection (mlock/memfd_secret) is NOT done here
//! (this crate forbids unsafe; it belongs in a separate `vault-mem` crate); the wrap
//! block is constant between credential changes, so two copies of the same vault are linkable.
#![forbid(unsafe_code)]

use argon2::{Algorithm, Argon2, Block, Params, Version};
use blake2::{digest::consts::U32, Blake2b, Digest};
use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

const SALT: usize = 16;
const WRAPPED: usize = 24 + 48;
const PREFIX: usize = SALT + WRAPPED;
const MIN_BLOB: usize = PREFIX + 24 + 16;
const AAD_DOMAIN: &[u8] = b"seburity-vault-v1";
/// Plaintext is padded to a multiple of this, hiding exact contact/message counts.
const PAD_BUCKET: usize = 4096;
pub const MIN_KEYFILE_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("vault is malformed")]
    Malformed,
    #[error("wrong password/keyfile")]
    WrongCredentials,
    #[error("credentials were correct but the vault body failed authentication: file is corrupted or was tampered with")]
    Tampered,
    #[error("keyfile too short (min 32 bytes)")]
    WeakKeyfile,
    #[error("not enough memory for the key derivation")]
    OutOfMemory,
    #[error("payload too large")]
    TooLarge,
}

/// Fixed KDF profiles. Floors are enforced by construction: there is no way to
/// choose weaker parameters in a release build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    /// 512 MiB, t=3. Default.
    Strong,
    /// 128 MiB, t=4. For low-RAM live systems.
    LowMem,
    #[cfg(any(test, feature = "insecure-test-kdf"))]
    InsecureTest,
}

impl Profile {
    /// Profiles tried when opening. Unit tests only try the fast profile (the real
    /// ones would take minutes per failed open in debug builds).
    #[cfg(not(test))]
    const ALL: &'static [Profile] = &[
        Profile::Strong,
        Profile::LowMem,
        #[cfg(feature = "insecure-test-kdf")]
        Profile::InsecureTest,
    ];
    #[cfg(test)]
    const ALL: &'static [Profile] = &[Profile::InsecureTest];
    fn cost(self) -> (u32, u32, u32) {
        match self {
            Profile::Strong => (512 * 1024, 3, 4),
            Profile::LowMem => (128 * 1024, 4, 4),
            #[cfg(any(test, feature = "insecure-test-kdf"))]
            Profile::InsecureTest => (8, 1, 1),
        }
    }
}

pub struct Vault {
    profile: Profile,
    salt: [u8; SALT],
    wrapped: [u8; WRAPPED],
    dk: Box<Zeroizing<[u8; 32]>>,
    counter: u64,
}

fn keyfile_secret(k: &[u8]) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    if k.len() < MIN_KEYFILE_LEN { return Err(VaultError::WeakKeyfile); }
    let mut h = Blake2b::<U32>::new();
    h.update(b"seburity-keyfile-v1");
    h.update(k);
    Ok(Zeroizing::new(h.finalize().into()))
}

fn kek(pw: &[u8], keyfile: Option<&[u8; 32]>, p: Profile, salt: &[u8; SALT]) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let (m, t, l) = p.cost();
    let params = Params::new(m, t, l, Some(32)).expect("compiled-in params are valid");
    let a = match keyfile {
        Some(k) => Argon2::new_with_secret(k, Algorithm::Argon2id, Version::V0x13, params.clone()).expect("valid"),
        None => Argon2::new(Algorithm::Argon2id, Version::V0x13, params.clone()),
    };
    // Own the working memory so it is fallibly allocated and wiped (H1).
    let n = params.block_count();
    let mut mem: Vec<Block> = Vec::new();
    mem.try_reserve_exact(n).map_err(|_| VaultError::OutOfMemory)?;
    mem.resize(n, Block::default());
    let mut out = Zeroizing::new([0u8; 32]);
    let r = a.hash_password_into_with_memory(pw, salt, &mut *out, &mut mem[..]);
    mem.zeroize();
    r.map_err(|_| VaultError::OutOfMemory)?;
    Ok(out)
}

fn aad_wrap(salt: &[u8; SALT]) -> Vec<u8> { [AAD_DOMAIN, b"wrap", salt].concat() }
fn aad_body(prefix: &[u8]) -> Vec<u8> { [AAD_DOMAIN, b"body", prefix].concat() }

fn wrap(kek: &[u8; 32], dk: &[u8; 32], salt: &[u8; SALT]) -> [u8; WRAPPED] {
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ct = XChaCha20Poly1305::new(kek.into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: dk, aad: &aad_wrap(salt) })
        .expect("encrypt");
    let mut out = [0u8; WRAPPED];
    out[..24].copy_from_slice(&nonce);
    out[24..].copy_from_slice(&ct);
    out
}

fn pad(counter: u64, data: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    if data.len() > (u32::MAX as usize) - PAD_BUCKET { return Err(VaultError::TooLarge); }
    let body = 8 + 4 + data.len();
    let total = body.div_ceil(PAD_BUCKET) * PAD_BUCKET;
    let mut v = Zeroizing::new(Vec::with_capacity(total));
    v.extend_from_slice(&counter.to_le_bytes());
    v.extend_from_slice(&(data.len() as u32).to_le_bytes());
    v.extend_from_slice(data);
    v.resize(total, 0);
    Ok(v)
}

impl Vault {
    /// Create a new vault. Nothing is returned to disk until `seal`.
    pub fn create(pw: &[u8], keyfile: Option<&[u8]>, profile: Profile) -> Result<Self, VaultError> {
        let kf = keyfile.map(keyfile_secret).transpose()?;
        Self::fresh(pw, kf.as_deref(), profile, 0)
    }

    fn fresh(pw: &[u8], kf: Option<&[u8; 32]>, profile: Profile, counter: u64) -> Result<Self, VaultError> {
        let mut salt = [0u8; SALT];
        OsRng.fill_bytes(&mut salt);
        let mut dk = Box::new(Zeroizing::new([0u8; 32]));
        OsRng.fill_bytes(&mut **dk);
        let k = kek(pw, kf, profile, &salt)?;
        let wrapped = wrap(&k, &dk, &salt);
        Ok(Self { profile, salt, wrapped, dk, counter })
    }

    /// Save counter of the state last opened/sealed (rollback detection: show it to the user).
    pub fn counter(&self) -> u64 { self.counter }

    /// KDF profile this vault was opened/created with (offer an upgrade if it is `LowMem`).
    pub fn profile(&self) -> Profile { self.profile }

    /// Serialize `data`. Increments the save counter; fresh nonce every call.
    pub fn seal(&mut self, data: &[u8]) -> Result<Vec<u8>, VaultError> {
        self.counter += 1;
        self.encode(data)
    }

    fn encode(&self, data: &[u8]) -> Result<Vec<u8>, VaultError> {
        let pt = pad(self.counter, data)?;
        let mut prefix = Vec::with_capacity(PREFIX);
        prefix.extend_from_slice(&self.salt);
        prefix.extend_from_slice(&self.wrapped);
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let ct = XChaCha20Poly1305::new((&**self.dk).into())
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: &pt, aad: &aad_body(&prefix) })
            .expect("encrypt");
        let mut out = prefix;
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Open a vault blob. Returns the unlocked vault and its payload.
    pub fn open(blob: &[u8], pw: &[u8], keyfile: Option<&[u8]>) -> Result<(Self, Zeroizing<Vec<u8>>), VaultError> {
        if blob.len() < MIN_BLOB { return Err(VaultError::Malformed); }
        let kf = keyfile.map(keyfile_secret).transpose()?;
        let salt: [u8; SALT] = blob[..SALT].try_into().unwrap();
        let wrapped: [u8; WRAPPED] = blob[SALT..PREFIX].try_into().unwrap();
        let mut found = None;
        let mut oom = false;
        for &profile in Profile::ALL {
            let k = match kek(pw, kf.as_deref(), profile, &salt) {
                Ok(k) => k,
                Err(VaultError::OutOfMemory) => { oom = true; continue; }
                Err(e) => return Err(e),
            };
            if let Ok(d) = XChaCha20Poly1305::new((&*k).into())
                .decrypt(XNonce::from_slice(&wrapped[..24]), Payload { msg: &wrapped[24..], aad: &aad_wrap(&salt) })
            {
                found = Some((profile, Zeroizing::new(d)));
                break;
            }
        }
        let Some((profile, dk_bytes)) = found else {
            return Err(if oom { VaultError::OutOfMemory } else { VaultError::WrongCredentials });
        };
        let mut dk = Box::new(Zeroizing::new([0u8; 32]));
        dk.copy_from_slice(&dk_bytes);
        let body = &blob[PREFIX..];
        let pt = Zeroizing::new(
            XChaCha20Poly1305::new((&**dk).into())
                .decrypt(XNonce::from_slice(&body[..24]), Payload { msg: &body[24..], aad: &aad_body(&blob[..PREFIX]) })
                .map_err(|_| VaultError::Tampered)?,
        );
        if pt.len() < 12 { return Err(VaultError::Malformed); }
        let counter = u64::from_le_bytes(pt[..8].try_into().unwrap());
        let len = u32::from_le_bytes(pt[8..12].try_into().unwrap()) as usize;
        if 12 + len > pt.len() { return Err(VaultError::Malformed); }
        let data = Zeroizing::new(pt[12..12 + len].to_vec());
        Ok((Self { profile, salt, wrapped, dk, counter }, data))
    }

    /// Change password/keyfile/profile. Generates a FRESH data key and salt and returns the
    /// new sealed blob; the caller MUST atomically replace the file with it. Requires the
    /// current credentials to be re-verified by the caller (re-`open` first).
    pub fn change_credentials(&mut self, new_pw: &[u8], new_keyfile: Option<&[u8]>, profile: Profile, data: &[u8]) -> Result<Vec<u8>, VaultError> {
        let kf = new_keyfile.map(keyfile_secret).transpose()?;
        let fresh = Self::fresh(new_pw, kf.as_deref(), profile, self.counter)?;
        *self = fresh;
        self.seal(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const P: Profile = Profile::InsecureTest;
    const KF: [u8; 32] = [7; 32];

    #[test]
    fn roundtrip_and_counter() {
        let mut v = Vault::create(b"pw", None, P).unwrap();
        let blob = v.seal(b"secret keys").unwrap();
        let (v2, pt) = Vault::open(&blob, b"pw", None).unwrap();
        assert_eq!(&pt[..], b"secret keys");
        assert_eq!(v2.counter(), 1);
        let mut v2 = v2;
        let b2 = v2.seal(b"x").unwrap();
        assert_eq!(Vault::open(&b2, b"pw", None).unwrap().0.counter(), 2);
    }

    #[test]
    fn wrong_credentials_and_weak_keyfile() {
        let mut v = Vault::create(b"pw", Some(&KF), P).unwrap();
        let blob = v.seal(b"x").unwrap();
        assert!(matches!(Vault::open(&blob, b"bad", Some(&KF)), Err(VaultError::WrongCredentials)));
        assert!(matches!(Vault::open(&blob, b"pw", None), Err(VaultError::WrongCredentials)));
        assert!(Vault::open(&blob, b"pw", Some(&KF)).is_ok());
        assert!(matches!(Vault::create(b"pw", Some(b""), P), Err(VaultError::WeakKeyfile)));
        assert!(matches!(Vault::create(b"pw", Some(&[1; 31]), P), Err(VaultError::WeakKeyfile)));
    }

    #[test]
    fn every_byte_flip_is_rejected_and_body_flip_is_tampered() {
        let mut v = Vault::create(b"pw", None, P).unwrap();
        let blob = v.seal(b"payload").unwrap();
        for i in 0..blob.len() {
            let mut b = blob.clone();
            b[i] ^= 1;
            let e = Vault::open(&b, b"pw", None).err().unwrap_or_else(|| panic!("byte {i} accepted"));
            if i >= PREFIX { assert!(matches!(e, VaultError::Tampered), "byte {i}: {e}"); }
        }
    }

    #[test]
    fn truncated_is_malformed() {
        assert!(matches!(Vault::open(&[0u8; 10], b"pw", None), Err(VaultError::Malformed)));
    }

    #[test]
    fn file_has_no_fixed_prefix_and_is_padded_to_bucket() {
        let mut a = Vault::create(b"pw", None, P).unwrap();
        let mut b = Vault::create(b"pw", None, P).unwrap();
        let (x, y) = (a.seal(b"1").unwrap(), b.seal(b"1").unwrap());
        assert_ne!(x[..6], y[..6]);
        let big = a.seal(&vec![1u8; 100]).unwrap();
        assert_eq!(x.len(), big.len(), "size must not reveal exact length");
        assert_ne!(a.seal(b"1").unwrap().len(), a.seal(&vec![0u8; PAD_BUCKET]).unwrap().len());
    }

    /// C1 regression: an old copy + old password must NOT unlock or forge future vaults.
    #[test]
    fn old_copy_cannot_read_or_forge_after_credential_change() {
        let mut v = Vault::create(b"old", None, P).unwrap();
        let old = v.seal(b"v1").unwrap();
        let (_, _) = Vault::open(&old, b"old", None).unwrap();
        let new = v.change_credentials(b"new", None, P, b"v2").unwrap();
        let old_dk = Vault::open(&old, b"old", None).unwrap().0.dk;
        // attacker with old DK tries to forge a body under the NEW file's prefix
        let nonce = [3u8; 24];
        let forged_ct = XChaCha20Poly1305::new((&**old_dk).into())
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: &pad(99, b"evil").unwrap(), aad: &aad_body(&new[..PREFIX]) })
            .unwrap();
        let mut forged = new[..PREFIX].to_vec();
        forged.extend_from_slice(&nonce);
        forged.extend_from_slice(&forged_ct);
        assert!(matches!(Vault::open(&forged, b"new", None), Err(VaultError::Tampered)));
        // and the old password no longer opens the new file
        assert!(Vault::open(&new, b"old", None).is_err());
        assert_eq!(&Vault::open(&new, b"new", None).unwrap().1[..], b"v2");
    }

    #[test]
    fn real_profiles_meet_floors() {
        for p in [Profile::Strong, Profile::LowMem] {
            let (m, t, l) = p.cost();
            assert!(m >= 128 * 1024 && t >= 3, "{p:?} below floor");
            Params::new(m, t, l, Some(32)).unwrap();
        }
    }

    #[test]
    fn nonces_fresh_per_save() {
        let mut v = Vault::create(b"pw", None, P).unwrap();
        assert_ne!(v.seal(b"d").unwrap(), v.seal(b"d").unwrap());
    }
}
