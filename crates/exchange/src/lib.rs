//! Contact exchange: offline file armor and the local PAKE pairing link.
//! Neither path touches the Internet. See `pair` and `file`.
#![forbid(unsafe_code)]

pub mod file;
pub mod pair;

use seburity_core::bundle::Bundle;

/// How a contact's bundle reached us. Governs the initial trust state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// Imported from a file/QR/paste: authenticity UNVERIFIED until the user compares the safety number.
    File,
    /// Exchanged over the local link under a shared one-time pairing code (authenticated by the code).
    Pake,
}

#[derive(Clone, Debug)]
pub struct ImportedContact {
    pub bundle: Bundle,
    pub method: Method,
    /// `File` imports start unverified; a `Pake` import is authenticated by the pairing code.
    pub verified: bool,
}

impl ImportedContact {
    pub fn from_file(bundle: Bundle) -> Self { Self { bundle, method: Method::File, verified: false } }
    pub fn from_pake(bundle: Bundle) -> Self { Self { bundle, method: Method::Pake, verified: true } }
    /// Call ONLY after the user confirmed the safety number out-of-band.
    pub fn mark_verified(&mut self) { self.verified = true; }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExchangeError {
    #[error("malformed or oversized input")]
    Malformed,
    #[error("pairing failed: wrong code or active attacker (this code is now burned)")]
    PairingFailed,
    #[error("peer sent our own bundle/message back (reflection)")]
    Reflection,
    #[error("i/o error")]
    Io,
    #[error("invalid pairing code")]
    BadCode,
}
