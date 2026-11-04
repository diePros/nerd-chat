//! Password-locked vault.
//!
//! Layout (no magic bytes; everything after the 6 param bytes is random-looking):
//! `m_cost_kib:u32le | t_cost:u8 | lanes:u8 | salt[16] | wrap_nonce[24] | wrapped_dk[48] | data_nonce[24] | ciphertext`
//!
//! password (+ optional keyfile as Argon2 secret) --Argon2id--> KEK
//! KEK --XChaCha20-Poly1305--> wraps random data key (DK); DK encrypts payload.
//! Changing the password only re-wraps DK. Every save uses a fresh nonce.
#![forbid(unsafe_code)]

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

const HDR: usize = 6 + 16; // params + salt
const WRAPPED: usize = 24 + 48;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("vault is malformed")]
    Malformed,
    #[error("wrong password/keyfile or vault tampered")]
    Auth,
    #[error("invalid KDF parameters")]
    Params,
}

#[derive(Clone, Copy, Debug)]
pub struct KdfParams { pub m_cost_kib: u32, pub t_cost: u8, pub lanes: u8 }

impl KdfParams {
    /// Default for real use: 512 MiB, 3 passes.
    pub const STRONG: Self = Self { m_cost_kib: 512 * 1024, t_cost: 3, lanes: 4 };
    /// Tests only.
    pub const FAST_INSECURE: Self = Self { m_cost_kib: 8, t_cost: 1, lanes: 1 };
}

pub struct Vault {
    params: KdfParams,
    salt: [u8; 16],
    wrapped: [u8; WRAPPED],
    dk: Zeroizing<[u8; 32]>,
}

/// Upper bounds on header-supplied KDF params. They are read *before* any
/// authentication, so without a cap a tampered file could force a huge allocation.
const MAX_M_COST_KIB: u32 = 2 * 1024 * 1024; // 2 GiB
const MAX_T_COST: u8 = 16;
const MAX_LANES: u8 = 16;

fn kek(pw: &[u8], keyfile: Option<&[u8]>, p: KdfParams, salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    if p.m_cost_kib > MAX_M_COST_KIB || p.t_cost > MAX_T_COST || p.lanes > MAX_LANES {
        return Err(VaultError::Params);
    }
    let params = Params::new(p.m_cost_kib, p.t_cost as u32, p.lanes as u32, Some(32)).map_err(|_| VaultError::Params)?;
    let a = match keyfile {
        Some(k) => Argon2::new_with_secret(k, Algorithm::Argon2id, Version::V0x13, params).map_err(|_| VaultError::Params)?,
        None => Argon2::new(Algorithm::Argon2id, Version::V0x13, params),
    };
    let mut out = Zeroizing::new([0u8; 32]);
    a.hash_password_into(pw, salt, &mut *out).map_err(|_| VaultError::Params)?;
    Ok(out)
}

fn header(p: KdfParams, salt: &[u8; 16]) -> [u8; HDR] {
    let mut h = [0u8; HDR];
    h[..4].copy_from_slice(&p.m_cost_kib.to_le_bytes());
    h[4] = p.t_cost;
    h[5] = p.lanes;
    h[6..].copy_from_slice(salt);
    h
}

fn wrap(kek: &[u8; 32], dk: &[u8; 32], hdr: &[u8; HDR]) -> [u8; WRAPPED] {
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ct = XChaCha20Poly1305::new(kek.into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: dk, aad: hdr })
        .expect("encrypt");
    let mut out = [0u8; WRAPPED];
    out[..24].copy_from_slice(&nonce);
    out[24..].copy_from_slice(&ct);
    out
}

impl Vault {
    /// Create a new vault with a fresh salt and data key.
    pub fn create(pw: &[u8], keyfile: Option<&[u8]>, params: KdfParams) -> Result<Self, VaultError> {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let mut dk = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *dk);
        let k = kek(pw, keyfile, params, &salt)?;
        let wrapped = wrap(&k, &dk, &header(params, &salt));
        Ok(Self { params, salt, wrapped, dk })
    }

    /// Serialize with `plaintext` as payload (fresh nonce each call).
    pub fn seal(&self, plaintext: &[u8]) -> Vec<u8> {
        let hdr = header(self.params, &self.salt);
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let mut aad = Vec::with_capacity(HDR + WRAPPED);
        aad.extend_from_slice(&hdr);
        aad.extend_from_slice(&self.wrapped);
        let ct = XChaCha20Poly1305::new((&*self.dk).into())
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad })
            .expect("encrypt");
        let mut out = aad;
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    /// Open a vault blob. Returns the unlocked vault and its payload.
    pub fn open(blob: &[u8], pw: &[u8], keyfile: Option<&[u8]>) -> Result<(Self, Zeroizing<Vec<u8>>), VaultError> {
        if blob.len() < HDR + WRAPPED + 24 + 16 { return Err(VaultError::Malformed); }
        let params = KdfParams {
            m_cost_kib: u32::from_le_bytes(blob[..4].try_into().unwrap()),
            t_cost: blob[4],
            lanes: blob[5],
        };
        let salt: [u8; 16] = blob[6..HDR].try_into().unwrap();
        let hdr: [u8; HDR] = blob[..HDR].try_into().unwrap();
        let wrapped: [u8; WRAPPED] = blob[HDR..HDR + WRAPPED].try_into().unwrap();
        let k = kek(pw, keyfile, params, &salt)?;
        let dk_bytes = Zeroizing::new(
            XChaCha20Poly1305::new((&*k).into())
                .decrypt(XNonce::from_slice(&wrapped[..24]), Payload { msg: &wrapped[24..], aad: &hdr })
                .map_err(|_| VaultError::Auth)?,
        );
        let mut dk = Zeroizing::new([0u8; 32]);
        dk.copy_from_slice(&dk_bytes);
        let body = &blob[HDR + WRAPPED..];
        let pt = XChaCha20Poly1305::new((&*dk).into())
            .decrypt(XNonce::from_slice(&body[..24]), Payload { msg: &body[24..], aad: &blob[..HDR + WRAPPED] })
            .map_err(|_| VaultError::Auth)?;
        Ok((Self { params, salt, wrapped, dk }, Zeroizing::new(pt)))
    }

    /// Re-wrap the data key under a new password/keyfile (new salt).
    pub fn change_credentials(&mut self, new_pw: &[u8], new_keyfile: Option<&[u8]>) -> Result<(), VaultError> {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let k = kek(new_pw, new_keyfile, self.params, &salt)?;
        self.wrapped = wrap(&k, &self.dk, &header(self.params, &salt));
        self.salt = salt;
        Ok(())
    }
}

impl Drop for Vault {
    fn drop(&mut self) { self.salt.zeroize(); }
}

#[cfg(test)]
mod tests {
    use super::*;
    const P: KdfParams = KdfParams::FAST_INSECURE;

    #[test]
    fn roundtrip() {
        let v = Vault::create(b"pw", None, P).unwrap();
        let blob = v.seal(b"secret keys");
        let (_, pt) = Vault::open(&blob, b"pw", None).unwrap();
        assert_eq!(&pt[..], b"secret keys");
    }

    #[test]
    fn wrong_password_and_keyfile_fail() {
        let v = Vault::create(b"pw", Some(b"kf"), P).unwrap();
        let blob = v.seal(b"x");
        assert!(matches!(Vault::open(&blob, b"bad", Some(b"kf")), Err(VaultError::Auth)));
        assert!(matches!(Vault::open(&blob, b"pw", None), Err(VaultError::Auth)));
        assert!(Vault::open(&blob, b"pw", Some(b"kf")).is_ok());
    }

    #[test]
    fn every_byte_flip_is_rejected() {
        let v = Vault::create(b"pw", None, P).unwrap();
        let blob = v.seal(b"payload");
        for i in 0..blob.len() {
            let mut b = blob.clone();
            b[i] ^= 1;
            assert!(Vault::open(&b, b"pw", None).is_err(), "byte {i} accepted");
        }
    }

    #[test]
    fn truncated_is_malformed() {
        assert!(matches!(Vault::open(&[0u8; 10], b"pw", None), Err(VaultError::Malformed)));
    }

    #[test]
    fn password_change_keeps_data_and_fresh_nonce() {
        let mut v = Vault::create(b"old", None, P).unwrap();
        let a = v.seal(b"d");
        let b = v.seal(b"d");
        assert_ne!(a, b);
        v.change_credentials(b"new", None).unwrap();
        let blob = v.seal(b"d");
        assert!(Vault::open(&blob, b"old", None).is_err());
        assert!(Vault::open(&blob, b"new", None).is_ok());
    }
}
