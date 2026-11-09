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

#[cfg(all(feature = "insecure-test-kdf", not(debug_assertions)))]
compile_error!("feature `insecure-test-kdf` must never be enabled in release builds (build/test release WITHOUT --all-targets/dev-dependencies)");

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
/// The TOTAL file length is padded to a multiple of this, hiding exact contact/message counts.
const PAD_BUCKET: usize = 4096;
/// Bytes in the file besides the padded plaintext: prefix + data nonce + AEAD tag.
const OVERHEAD: usize = PREFIX + 24 + 16;
pub const MIN_KEYFILE_LEN: usize = 32;
/// The save counter grows by 1 to this many per save (random, see `seal`).
pub const COUNTER_STEP: u64 = 1 << 20;

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
    #[error("empty password without a keyfile is not allowed")]
    EmptyPassword,
    #[error("key derivation failed")]
    Kdf,
    #[error("ROLLBACK: vault counter {found} is older than the expected minimum {expected} - an old copy was substituted")]
    Rollback { found: u64, expected: u64 },
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
    #[cfg(all(not(test), not(feature = "insecure-test-kdf")))]
    const ALL: &'static [Profile] = &[Profile::Strong, Profile::LowMem];
    /// With the test feature the fast profile goes FIRST so dependants' tests stay quick.
    #[cfg(all(not(test), feature = "insecure-test-kdf"))]
    const ALL: &'static [Profile] = &[Profile::InsecureTest, Profile::Strong, Profile::LowMem];
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
    // Linux overcommit makes try_reserve succeed even when RAM is short, and the OOM killer
    // would then SIGKILL us (no zeroization). Refuse up front when MemAvailable is too low.
    if let Some(avail_kib) = mem_available_kib() {
        if (m as u64) + (m as u64) / 8 > avail_kib { return Err(VaultError::OutOfMemory); }
    }
    let mut mem: Vec<Block> = Vec::new();
    mem.try_reserve_exact(n).map_err(|_| VaultError::OutOfMemory)?;
    mem.resize(n, Block::default());
    let mut out = Zeroizing::new([0u8; 32]);
    let r = a.hash_password_into_with_memory(pw, salt, &mut *out, &mut mem[..]);
    mem.zeroize();
    r.map_err(|_| VaultError::Kdf)?;
    Ok(out)
}

/// `MemAvailable` from /proc/meminfo in KiB; None if unreadable (then we just try).
fn mem_available_kib() -> Option<u64> {
    let t = std::fs::read_to_string("/proc/meminfo").ok()?;
    t.lines().find(|l| l.starts_with("MemAvailable:"))?.split_whitespace().nth(1)?.parse().ok()
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
    let total = (body + OVERHEAD).div_ceil(PAD_BUCKET) * PAD_BUCKET - OVERHEAD;
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
        if pw.is_empty() && keyfile.is_none() { return Err(VaultError::EmptyPassword); }
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

    /// Serialize `data`. Advances the save counter by a RANDOM amount (1..=COUNTER_STEP) and uses a fresh nonce every call. The counter only has to be monotone; a random
    /// step means that the rollback-counter file (which sits next to the vault) does not reveal HOW MANY times the vault was saved, i.e. roughly how many messages were sent.
    pub fn seal(&mut self, data: &[u8]) -> Result<Vec<u8>, VaultError> {
        let mut r = [0u8; 4];
        OsRng.fill_bytes(&mut r);
        self.counter = self.counter.checked_add(1 + (u32::from_le_bytes(r) as u64 % COUNTER_STEP)).ok_or(VaultError::TooLarge)?;
        self.encode(data)
    }

    /// A 32-byte key for another purpose (a file next to the vault), derived from the data key and a label: unknown to anyone without the password, and different per label.
    pub fn subkey(&self, label: &[u8]) -> Zeroizing<[u8; 32]> {
        let mut h = Blake2b::<U32>::new();
        h.update(b"sine-loco-vault-subkey-v1");
        h.update((label.len() as u32).to_le_bytes());
        h.update(label);
        h.update(&**self.dk);
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&h.finalize());
        out
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

    /// Like [`open`] but fails closed if the vault is older than `min_counter`.
    /// Persist the counter of the last save OUTSIDE the vault (e.g. on the keyfile device) and
    /// pass it here to detect an attacker substituting an older copy.
    pub fn open_checked(blob: &[u8], pw: &[u8], keyfile: Option<&[u8]>, min_counter: u64) -> Result<(Self, Zeroizing<Vec<u8>>), VaultError> {
        let (v, d) = Self::open(blob, pw, keyfile)?;
        if v.counter < min_counter { return Err(VaultError::Rollback { found: v.counter, expected: min_counter }); }
        Ok((v, d))
    }

    /// Open a vault blob. Returns the unlocked vault and its payload.
    /// NOTE: does not detect rollback by itself; use [`open_checked`].
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

    /// Change password/keyfile/profile. Re-verifies the CURRENT credentials against the unlocked
    /// vault's wrap (so an unattended unlocked session cannot silently re-key it), then
    /// generates a FRESH data key and salt and returns the new sealed blob; the caller MUST
    /// atomically replace the file with it.
    pub fn change_credentials(&mut self, old_pw: &[u8], old_keyfile: Option<&[u8]>, new_pw: &[u8], new_keyfile: Option<&[u8]>, profile: Profile, data: &[u8]) -> Result<Vec<u8>, VaultError> {
        let okf = old_keyfile.map(keyfile_secret).transpose()?;
        let k = kek(old_pw, okf.as_deref(), self.profile, &self.salt)?;
        XChaCha20Poly1305::new((&*k).into())
            .decrypt(XNonce::from_slice(&self.wrapped[..24]), Payload { msg: &self.wrapped[24..], aad: &aad_wrap(&self.salt) })
            .map_err(|_| VaultError::WrongCredentials)?;
        if new_pw.is_empty() && new_keyfile.is_none() { return Err(VaultError::EmptyPassword); }
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
        assert!(v2.counter() >= 1 && v2.counter() <= COUNTER_STEP);
        let first = v2.counter();
        let mut v2 = v2;
        let b2 = v2.seal(b"x").unwrap();
        let second = Vault::open(&b2, b"pw", None).unwrap().0.counter();
        assert!(second > first && second - first <= COUNTER_STEP, "monotone, by a random step");
    }

    #[test]
    fn the_counter_does_not_count_saves_and_a_subkey_is_per_label_and_per_vault() {
        let mut v = Vault::create(b"pw", None, P).unwrap();
        let mut steps = std::collections::BTreeSet::new();
        let mut last = v.counter();
        for _ in 0..40 { v.seal(b"x").unwrap(); steps.insert(v.counter() - last); last = v.counter(); }
        assert!(steps.len() > 20, "the increments are random, not +1: {steps:?}");
        assert!(steps.iter().all(|s| (1..=COUNTER_STEP).contains(s)));
        let (a, b) = (v.subkey(b"counter-file"), v.subkey(b"history"));
        assert_ne!(*a, *b, "different labels, different keys");
        assert_eq!(*a, *v.subkey(b"counter-file"), "deterministic for one vault");
        let other = Vault::create(b"pw", None, P).unwrap();
        assert_ne!(*a, *other.subkey(b"counter-file"), "another vault has another key");
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
        let big = a.seal(&[1u8; 100]).unwrap();
        assert_eq!(x.len(), big.len(), "size must not reveal exact length");
        assert_ne!(a.seal(b"1").unwrap().len(), a.seal(&vec![0u8; PAD_BUCKET]).unwrap().len());
        assert_eq!(x.len() % PAD_BUCKET, 0, "TOTAL file length must be a bucket multiple");
        assert_eq!(a.seal(&vec![0u8; 5000]).unwrap().len() % PAD_BUCKET, 0);
    }

    #[test]
    fn rollback_empty_password_and_credential_recheck() {
        let mut v = Vault::create(b"pw", None, P).unwrap();
        let b1 = v.seal(b"1").unwrap(); let c1 = v.counter();
        let b2 = v.seal(b"2").unwrap(); let c2 = v.counter();
        assert!(Vault::open_checked(&b2, b"pw", None, c2).is_ok());
        assert!(matches!(Vault::open_checked(&b1, b"pw", None, c2), Err(VaultError::Rollback { found, expected }) if found == c1 && expected == c2));
        assert!(matches!(Vault::create(b"", None, P), Err(VaultError::EmptyPassword)));
        assert!(matches!(v.change_credentials(b"WRONG", None, b"n", None, P, b"x"), Err(VaultError::WrongCredentials)));
        assert!(matches!(v.change_credentials(b"pw", None, b"", None, P, b"x"), Err(VaultError::EmptyPassword)));
    }

    /// C1 regression: an old copy + old password must NOT unlock or forge future vaults.
    #[test]
    fn old_copy_cannot_read_or_forge_after_credential_change() {
        let mut v = Vault::create(b"old", None, P).unwrap();
        let old = v.seal(b"v1").unwrap();
        let (_, _) = Vault::open(&old, b"old", None).unwrap();
        let new = v.change_credentials(b"old", None, b"new", None, P, b"v2").unwrap();
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
