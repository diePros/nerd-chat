//! Hybrid post-quantum session.
//!
//! 1. Initiator ML-KEM-768-encapsulates to the responder's pinned KEM key -> (ct, ss).
//! 2. psk = BLAKE2b("seburity-psk-v1" || ss || ct || both static DH pubs || both sign pubs)
//! 3. Noise_KKpsk0_25519_ChaChaPoly_BLAKE2s with that PSK and the pinned static keys.
//!    Fresh ephemerals every connection -> forward secrecy; harvest-now-decrypt-later
//!    needs to break BOTH X25519 and ML-KEM. Authentication is classical (X25519 static
//!    keys + Ed25519 message signatures); ML-DSA is future work.
//! 4. Every message is signed (`message`), padded to a fixed cell (`cell`), then AEAD-encrypted.
//!    Session id = Noise handshake hash, bound into every signature.
use crate::{bundle::Bundle, cell, identity::ContactIdentity, message, Error};
use blake2::{digest::consts::U32, Blake2b, Digest};
use ml_kem::{kem::{Decapsulate, Encapsulate}, Ciphertext, MlKem768};
use snow::{Builder, HandshakeState, StatelessTransportState};
use zeroize::Zeroizing;

const PARAMS: &str = "Noise_KKpsk0_25519_ChaChaPoly_BLAKE2s";
pub const KEM_CT_LEN: usize = 1088;
/// Wire size of every transport cell (plaintext cell + 16-byte AEAD tag).
pub const WIRE_CELL_LEN: usize = cell::CELL_LEN + 16;

fn psk(ss: &[u8], ct: &[u8], init: &Bundle, resp: &Bundle) -> Zeroizing<[u8; 32]> {
    let mut h = Blake2b::<U32>::new();
    h.update(b"seburity-psk-v1");
    h.update(ss);
    h.update(ct);
    for b in [init, resp] { h.update(b.dh_pub); h.update(b.sign_pub); }
    Zeroizing::new(h.finalize().into())
}

pub struct Handshake { hs: HandshakeState, init_is_me: bool, me_pub: Bundle, peer: Bundle }
pub struct Session {
    ts: StatelessTransportState,
    id: [u8; 32],
    send_ctr: u64,
    recv_last: Option<u64>,
    peer: Bundle,
}

fn build(me: &ContactIdentity, peer: &Bundle, psk: &[u8; 32], initiator: bool) -> Result<HandshakeState, Error> {
    let sk = Zeroizing::new(me.dh.to_bytes());
    let b = Builder::new(PARAMS.parse().expect("static params"))
        .local_private_key(&*sk).map_err(|_| Error::Malformed)?
        .remote_public_key(&peer.dh_pub).map_err(|_| Error::Malformed)?
        .psk(0, psk).map_err(|_| Error::Malformed)?;
    (if initiator { b.build_initiator() } else { b.build_responder() }).map_err(|_| Error::Malformed)
}

impl Handshake {
    /// Initiator step 1. Returns the handshake state and message 1 (`kem_ct || noise_msg`).
    pub fn initiate(me: &ContactIdentity, peer: &Bundle) -> Result<(Self, Vec<u8>), Error> {
        let (ct, ss) = peer.kem_key()?.encapsulate();
        let me_pub = Bundle::from_identity(me);
        let k = psk(ss.as_slice(), ct.as_slice(), &me_pub, peer);
        let mut hs = build(me, peer, &k, true)?;
        let mut out = vec![0u8; 512];
        let n = hs.write_message(&[], &mut out).map_err(|_| Error::Malformed)?;
        let mut msg = ct.as_slice().to_vec();
        msg.extend_from_slice(&out[..n]);
        Ok((Self { hs, init_is_me: true, me_pub, peer: peer.clone() }, msg))
    }

    /// Responder: consume message 1, return `(Session, message 2)`.
    pub fn respond(me: &ContactIdentity, peer: &Bundle, msg1: &[u8]) -> Result<(Session, Vec<u8>), Error> {
        if msg1.len() <= KEM_CT_LEN || msg1.len() > KEM_CT_LEN + 512 { return Err(Error::Malformed); }
        let (ct_b, noise) = msg1.split_at(KEM_CT_LEN);
        let ct: Ciphertext<MlKem768> = ct_b.try_into().map_err(|_| Error::Malformed)?;
        let ss = me.kem.decapsulate(&ct); // implicit rejection: bad ct => wrong psk => Noise fails
        let me_pub = Bundle::from_identity(me);
        let k = psk(ss.as_slice(), ct_b, peer, &me_pub);
        let mut hs = build(me, peer, &k, false)?;
        let mut scratch = vec![0u8; 512];
        hs.read_message(noise, &mut scratch).map_err(|_| Error::BadSignature)?;
        let mut out = vec![0u8; 512];
        let n = hs.write_message(&[], &mut out).map_err(|_| Error::Malformed)?;
        out.truncate(n);
        Ok((Session::finish(hs, peer)?, out))
    }

    /// Initiator step 2: consume message 2.
    pub fn finish(mut self, msg2: &[u8]) -> Result<Session, Error> {
        debug_assert!(self.init_is_me);
        let _ = &self.me_pub;
        let mut scratch = vec![0u8; 512];
        self.hs.read_message(msg2, &mut scratch).map_err(|_| Error::BadSignature)?;
        Session::finish(self.hs, &self.peer)
    }
}

impl Session {
    fn finish(hs: HandshakeState, peer: &Bundle) -> Result<Self, Error> {
        if !hs.is_handshake_finished() { return Err(Error::Malformed); }
        let id: [u8; 32] = hs.get_handshake_hash().try_into().map_err(|_| Error::Malformed)?;
        let ts = hs.into_stateless_transport_mode().map_err(|_| Error::Malformed)?;
        Ok(Self { ts, id, send_ctr: 0, recv_last: None, peer: peer.clone() })
    }

    pub fn id(&self) -> &[u8; 32] { &self.id }

    /// Sign, pad and encrypt one message. Output is always `WIRE_CELL_LEN` bytes.
    pub fn send(&mut self, me: &ContactIdentity, timestamp: u64, body: &[u8]) -> Result<Vec<u8>, Error> {
        self.send_ctr = self.send_ctr.checked_add(1).ok_or(Error::Replay)?;
        let signed = message::seal(me, &self.peer, &self.id, self.send_ctr, timestamp, body)?;
        let cell = Zeroizing::new(cell::pad(&signed)?);
        let mut out = vec![0u8; WIRE_CELL_LEN];
        // The Noise nonce is the message counter, so each cell is bound to its position.
        let n = self.ts.write_message(self.send_ctr, &cell[..], &mut out).map_err(|_| Error::Malformed)?;
        debug_assert_eq!(n, WIRE_CELL_LEN);
        Ok(out)
    }

    /// Decrypt, unpad, verify signature and ordering. Strictly increasing counters only.
    pub fn recv(&mut self, me: &ContactIdentity, wire: &[u8]) -> Result<message::Signed, Error> {
        if wire.len() != WIRE_CELL_LEN { return Err(Error::Malformed); }
        // Nonce = expected next counter; no gaps allowed (reliable ordered transport).
        let nonce = self.recv_last.map_or(1, |l| l + 1);
        let mut buf = Zeroizing::new(vec![0u8; WIRE_CELL_LEN]);
        let n = self.ts.read_message(nonce, wire, &mut buf[..]).map_err(|_| Error::BadSignature)?;
        let signed = cell::unpad(&buf[..n])?;
        let m = message::open(me, &self.peer, &self.id, self.recv_last, signed)?;
        if m.counter != nonce { return Err(Error::Replay); }
        self.recv_last = Some(m.counter);
        Ok(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (ContactIdentity, Bundle, ContactIdentity, Bundle) {
        let a = ContactIdentity::generate(); let b = ContactIdentity::generate();
        let (ab, bb) = (Bundle::from_identity(&a), Bundle::from_identity(&b));
        (a, ab, b, bb)
    }

    fn connect(a: &ContactIdentity, ab: &Bundle, b: &ContactIdentity, bb: &Bundle) -> (Session, Session) {
        let (h, m1) = Handshake::initiate(a, bb).unwrap();
        let (sb, m2) = Handshake::respond(b, ab, &m1).unwrap();
        (h.finish(&m2).unwrap(), sb)
    }

    #[test]
    fn chat_both_directions_fixed_size() {
        let (a, ab, b, bb) = setup();
        let (mut sa, mut sb) = connect(&a, &ab, &b, &bb);
        assert_eq!(sa.id(), sb.id());
        let w1 = sa.send(&a, 1, b"hi bob").unwrap();
        let w2 = sa.send(&a, 2, &vec![b'x'; 800]).unwrap();
        assert_eq!((w1.len(), w2.len()), (WIRE_CELL_LEN, WIRE_CELL_LEN));
        assert_eq!(&sb.recv(&b, &w1).unwrap().body[..], b"hi bob");
        assert_eq!(sb.recv(&b, &w2).unwrap().body.len(), 800);
        let r = sb.send(&b, 3, b"hi alice").unwrap();
        assert_eq!(&sa.recv(&a, &r).unwrap().body[..], b"hi alice");
    }

    #[test]
    fn replay_reorder_tamper_rejected() {
        let (a, ab, b, bb) = setup();
        let (mut sa, mut sb) = connect(&a, &ab, &b, &bb);
        let w1 = sa.send(&a, 0, b"1").unwrap();
        let w2 = sa.send(&a, 0, b"2").unwrap();
        assert!(sb.recv(&b, &w2).is_err(), "reorder/skip must fail");
        sb.recv(&b, &w1).unwrap();
        assert!(sb.recv(&b, &w1).is_err(), "replay must fail");
        let mut t = w2.clone(); t[100] ^= 1;
        assert!(sb.recv(&b, &t).is_err(), "tamper must fail");
        sb.recv(&b, &w2).unwrap();
    }

    #[test]
    fn new_session_has_new_id_and_old_cells_dont_replay_across_sessions() {
        let (a, ab, b, bb) = setup();
        let (mut sa1, _) = connect(&a, &ab, &b, &bb);
        let (mut sa2, mut sb2) = connect(&a, &ab, &b, &bb);
        assert_ne!(sa1.id(), sa2.id());
        let old = sa1.send(&a, 0, b"old").unwrap();
        assert!(sb2.recv(&b, &old).is_err());
        let _ = sa2.send(&a, 0, b"ok").unwrap();
    }

    #[test]
    fn impostor_and_wrong_kem_ct_fail() {
        let (a, ab, b, bb) = setup();
        let c = ContactIdentity::generate();
        // Mallory (c) initiates claiming nothing: responder pins A, handshake keyed to c fails.
        let (_, m1) = Handshake::initiate(&c, &bb).unwrap();
        assert!(Handshake::respond(&b, &ab, &m1).is_err());
        // corrupt the KEM ciphertext
        let (_, mut m1) = Handshake::initiate(&a, &bb).unwrap();
        m1[10] ^= 1;
        assert!(Handshake::respond(&b, &ab, &m1).is_err());
        // truncated / oversized
        assert!(Handshake::respond(&b, &ab, &m1[..100]).is_err());
        assert!(Handshake::respond(&b, &ab, &vec![0; 5000]).is_err());
    }
}
