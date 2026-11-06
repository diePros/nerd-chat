//! Signed messages. The signature covers sender, recipient, session, counter,
//! timestamp and body, so a message cannot be replayed, reordered, or forwarded
//! to another contact/session. The result is meant to be AEAD-encrypted by the
//! session layer (sign-then-encrypt, signature never visible on the wire).
use crate::{Error, bundle::Bundle, identity::ContactIdentity};
use ed25519_dalek::{Signature, Signer};
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"seburity-msg-v1";
const HEADER: usize = 32 + 32 + 32 + 8 + 8; // sender, recipient, session, counter, ts
pub const MAX_BODY: usize = crate::cell::CELL_PAYLOAD_MAX - HEADER - 2 - 64;

/// Decrypted, verified message. Body is wiped on drop; Debug never prints it.
pub struct Signed { pub counter: u64, pub timestamp: u64, pub body: Zeroizing<Vec<u8>> }
impl std::fmt::Debug for Signed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signed {{ counter: {}, body: <{} bytes redacted> }}", self.counter, self.body.len())
    }
}

pub fn seal(me: &ContactIdentity, peer: &Bundle, session: &[u8; 32], counter: u64, timestamp: u64, body: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if body.len() > MAX_BODY { return Err(Error::TooLarge); }
    let mut m = Zeroizing::new(Vec::with_capacity(HEADER + 2 + body.len() + 64));
    m.extend_from_slice(&me.verifying_key().to_bytes());
    m.extend_from_slice(&peer.sign_pub);
    m.extend_from_slice(session);
    m.extend_from_slice(&counter.to_be_bytes());
    m.extend_from_slice(&timestamp.to_be_bytes());
    m.extend_from_slice(&(body.len() as u16).to_be_bytes());
    m.extend_from_slice(body);
    let sig = me.sign.sign(&Zeroizing::new([DOMAIN, &m].concat()));
    m.extend_from_slice(&sig.to_bytes());
    Ok(m)
}

/// Verify a decrypted message from `peer` addressed to `me` in `session`.
/// `last_counter`: highest counter already accepted from this peer in this session.
pub fn open(me: &ContactIdentity, peer: &Bundle, session: &[u8; 32], last_counter: Option<u64>, data: &[u8]) -> Result<Signed, Error> {
    if data.len() < HEADER + 2 + 64 { return Err(Error::Malformed); }
    let (m, sig) = data.split_at(data.len() - 64);
    let blen = u16::from_be_bytes([m[HEADER], m[HEADER + 1]]) as usize;
    if m.len() != HEADER + 2 + blen { return Err(Error::Malformed); }
    // Verify the signature BEFORE trusting any field.
    let vk = peer.verifying_key()?;
    vk.verify_strict(&Zeroizing::new([DOMAIN, m].concat()), &Signature::from_bytes(sig.try_into().unwrap()))
        .map_err(|_| Error::BadSignature)?;
    if m[..32] != peer.sign_pub
        || m[32..64] != me.verifying_key().to_bytes()
        || m[64..96] != session[..] {
        return Err(Error::WrongContext);
    }
    let counter = u64::from_be_bytes(m[96..104].try_into().unwrap());
    if last_counter.is_some_and(|l| counter <= l) { return Err(Error::Replay); }
    Ok(Signed { counter, timestamp: u64::from_be_bytes(m[104..112].try_into().unwrap()), body: Zeroizing::new(m[HEADER + 2..].to_vec()) })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (ContactIdentity, Bundle, ContactIdentity, Bundle) {
        let a = ContactIdentity::generate(); let b = ContactIdentity::generate();
        let (ab, bb) = (Bundle::from_identity(&a), Bundle::from_identity(&b));
        (a, ab, b, bb)
    }

    #[test]
    fn roundtrip() {
        let (a, ab, b, bb) = pair();
        let s = [9u8; 32];
        let m = seal(&a, &bb, &s, 1, 123, b"hello").unwrap();
        let r = open(&b, &ab, &s, None, &m).unwrap();
        assert_eq!((r.counter, r.timestamp, &r.body[..]), (1, 123, &b"hello"[..]));
    }

    #[test]
    fn rejects_replay_wrong_session_wrong_recipient_and_impostor() {
        let (a, ab, b, bb) = pair();
        let c = ContactIdentity::generate();
        let s = [9u8; 32];
        let m = seal(&a, &bb, &s, 5, 0, b"x").unwrap();
        assert_eq!(open(&b, &ab, &s, Some(5), &m).unwrap_err(), Error::Replay);
        assert_eq!(open(&b, &ab, &s, Some(6), &m).unwrap_err(), Error::Replay);
        assert!(open(&b, &ab, &s, Some(4), &m).is_ok());
        assert_eq!(open(&b, &ab, &[1u8; 32], None, &m).unwrap_err(), Error::WrongContext);
        // forwarded to a different recipient
        assert_eq!(open(&c, &ab, &s, None, &m).unwrap_err(), Error::WrongContext);
        // impostor signs claiming to be A
        let forged = seal(&c, &bb, &s, 1, 0, b"x").unwrap();
        assert!(open(&b, &ab, &s, None, &forged).is_err());
    }

    #[test]
    fn every_byte_flip_rejected_and_size_limits() {
        let (a, ab, b, bb) = pair();
        let s = [0u8; 32];
        let m = seal(&a, &bb, &s, 1, 1, b"payload").unwrap();
        for i in 0..m.len() {
            let mut t = m.clone(); t[i] ^= 1;
            assert!(open(&b, &ab, &s, None, &t).is_err(), "byte {i}");
        }
        assert!(seal(&a, &bb, &s, 1, 1, &vec![0; MAX_BODY]).is_ok());
        assert_eq!(seal(&a, &bb, &s, 1, 1, &vec![0; MAX_BODY + 1]).unwrap_err(), Error::TooLarge);
        assert!(open(&b, &ab, &s, None, &m[..10]).is_err());
    }
}
