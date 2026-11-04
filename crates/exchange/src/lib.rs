//! Contact exchange: offline file armor and the local PAKE pairing link.
//! Neither path touches the Internet. See `pair` and `file`.
#![forbid(unsafe_code)]

pub mod file;
pub mod pair;

use seburity_core::{bundle::{Bundle, safety_number}, trust::Trust};

/// How a contact's bundle reached us.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method { File, Pake }

/// A contact bundle plus how far it is authenticated. Fields are private: the only ways to raise
/// trust are a completed `pair` run (`CodeAuthenticated`) or `confirm` with a `SafetyView`.
#[derive(Clone, Debug)]
pub struct ImportedContact { bundle: Bundle, method: Method, trust: Trust }

/// What the user must be shown (and compare out-of-band) before `confirm`. Only obtainable from the contact itself.
#[derive(Debug)]
pub struct SafetyView { pub number: String, key: [u8; 32] }

impl ImportedContact {
    /// File/QR/paste import: always `Unverified`.
    pub fn from_file(bundle: Bundle) -> Self { Self { bundle, method: Method::File, trust: Trust::Unverified } }
    pub(crate) fn from_pake(bundle: Bundle) -> Self { Self { bundle, method: Method::Pake, trust: Trust::CodeAuthenticated } }

    pub fn bundle(&self) -> &Bundle { &self.bundle }
    pub fn method(&self) -> Method { self.method }
    pub fn trust(&self) -> Trust { self.trust }
    pub fn into_parts(self) -> (Bundle, Trust) { (self.bundle, self.trust) }

    /// Downgrade (e.g. the code travelled over a weak channel, not in person).
    pub fn downgrade_to_unverified(&mut self) { self.trust = Trust::Unverified; }

    pub fn safety_view(&self, mine: &Bundle) -> SafetyView {
        SafetyView { number: safety_number(mine, &self.bundle), key: self.bundle.sign_pub }
    }

    /// Call only after the user confirmed `view.number` matches the other side's screen.
    pub fn confirm(&mut self, mine: &Bundle, view: SafetyView) -> bool {
        if view.key != self.bundle.sign_pub || view.number != safety_number(mine, &self.bundle) { return false; }
        self.trust = Trust::SafetyVerified;
        true
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExchangeError {
    #[error("malformed or oversized input")]
    Malformed,
    #[error("pairing failed: wrong code or active attacker (this code is now burned)")]
    PairingFailed,
    #[error("peer proved nothing about its keys or sent inconsistent data")]
    ProofFailed,
    #[error("i/o error or timeout")]
    Io,
    #[error("invalid pairing code")]
    BadCode,
    #[error("too many failed pairings; try again in {0} s")]
    Locked(u64),
    #[error("pairing offer expired")]
    Expired,
}
