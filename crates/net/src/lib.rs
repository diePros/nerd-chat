//! Transport-independent link layer: handshake over any `Read + Write` stream (a Tor onion
//! stream, a LAN socket, BLE...) plus the unauthenticated-input guards the tracker demands
//! (replay cache R2-M2b, rate limit R2-I5). Tor itself plugs in below this layer.
#![forbid(unsafe_code)]

pub mod guard;
pub mod link;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NetError {
    #[error("i/o error or timeout")]
    Io,
    #[error("handshake failed")]
    Handshake,
    #[error("rate limited")]
    RateLimited,
    #[error("replayed handshake")]
    Replay,
    #[error("peer did not confirm the session")]
    Unconfirmed,
}
