//! seburity-core: identities, contact bundles, signed messages, fixed-size cells.
#![forbid(unsafe_code)]

pub mod bundle;
pub mod cell;
pub mod identity;
pub mod message;
pub mod onion;
pub mod session;
pub mod trust;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("malformed input")]
    Malformed,
    #[error("signature verification failed")]
    BadSignature,
    #[error("message too large")]
    TooLarge,
    #[error("replayed or out-of-order message")]
    Replay,
    #[error("message not addressed to us / wrong session")]
    WrongContext,
}
