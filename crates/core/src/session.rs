//! Hybrid post-quantum session with PQ forward secrecy.
//!
//! Handshake `Noise_KKpsk0+psk2_25519_ChaChaPoly_BLAKE2s` (prologue binds version + both Ed25519 keys):
//!
//! msg1 (I->R) = `ct_s || noise1(payload = ek_e)`
//!   * `ct_s` = ML-KEM-768 encapsulation to R's STATIC KEM key (R is PQ-authenticated)
//!   * psk0 = H(ss_s, ct_s, both static keys, roles)
//!   * `ek_e` = fresh per-connection ML-KEM encapsulation key, carried INSIDE the
//!     authenticated Noise payload so it cannot be swapped in transit
//! msg2 (R->I) = `ct_e || noise2`
//!   * `ct_e` = encapsulation to `ek_e`; psk2 = H(ss_e, ct_e, H(ek_e), both static keys, roles)
//!
//! The ephemeral ML-KEM secret is dropped after msg2, so a later seizure of a vault (which
//! holds only the static keys) plus a quantum computer cannot decrypt recorded sessions.
//! Initiator authentication is still classical (X25519 static + Ed25519 signatures);
//! ML-DSA and a reverse static KEM are future work.
//!
//! Responder sessions are UNCONFIRMED until a valid cell arrives (msg1 can be replayed by a
//! network attacker; they cannot complete the session). Initiators must send a first cell
//! immediately. Applications must not treat an unconfirmed session as "contact is online".
use crate::{bundle::Bundle, cell, identity::ContactIdentity, message, Error};
use blake2::{digest::consts::U32, Blake2b, Digest};
use ml_kem::{
    kem::{Decapsulate, Encapsulate, Kem},
    Ciphertext, DecapsulationKey768, EncapsulationKey768, KeyExport, MlKem768,
};
use snow::{Builder, HandshakeState, StatelessTransportState};
use zeroize::Zeroizing;

const PARAMS: &str = "Noise_KKpsk0+psk2_25519_ChaChaPoly_BLAKE2s";
pub const KEM_CT_LEN: usize = 1088;
pub const KEM_EK_LEN: usize = 1184;
const NOISE1_LEN: usize = 32 + KEM_EK_LEN + 16; // e || AEAD(payload=ek_e)
const NOISE2_LEN: usize = 32 + 16; // e || AEAD(empty)
pub const MSG1_LEN: usize = KEM_CT_LEN + NOISE1_LEN;
pub const MSG2_LEN: usize = KEM_CT_LEN + NOISE2_LEN;
/// Wire size of every transport cell (plaintext cell + 16-byte AEAD tag).
pub const WIRE_CELL_LEN: usize = cell::CELL_LEN + 16;

fn derive_psk(label: &[u8], ss: &[u8], ct: &[u8], extra: &[u8], init: &Bundle, resp: &Bundle) -> Zeroizing<[u8; 32]> {
    let mut h = Blake2b::<U32>::new();
    h.update(label);
    h.update(ss);
    h.update(ct);
    h.update(extra);
    for b in [init, resp] { h.update(b.dh_pub); h.update(b.sign_pub); }
    Zeroizing::new(h.finalize().into())
}

fn ek_hash(ek: &[u8]) -> [u8; 32] { Blake2b::<U32>::digest(ek).into() }

fn prologue(init: &Bundle, resp: &Bundle) -> Vec<u8> {
    [b"seburity-v1".as_slice(), &init.sign_pub, &resp.sign_pub].concat()
}

fn build(me: &ContactIdentity, peer: &Bundle, psk0: &[u8; 32], plog: &[u8], initiator: bool) -> Result<HandshakeState, Error> {
    let sk = Zeroizing::new(me.dh.to_bytes());
    let b = Builder::new(PARAMS.parse().expect("static params"))
        .local_private_key(&*sk).map_err(|_| Error::Malformed)?
        .remote_public_key(&peer.dh_pub).map_err(|_| Error::Malformed)?
        .prologue(plog).map_err(|_| Error::Malformed)?
        .psk(0, psk0).map_err(|_| Error::Malformed)?;
    (if initiator { b.build_initiator() } else { b.build_responder() }).map_err(|_| Error::Malformed)
}

pub struct Handshake {
    hs: HandshakeState,
    peer: Bundle,
    me: Bundle,
    eph_dk: DecapsulationKey768,
    eph_ek: Vec<u8>,
}

pub struct Session {
    ts: StatelessTransportState,
    id: [u8; 32],
    send_ctr: u64,
    recv_last: Option<u64>,
    peer: Bundle,
    confirmed: bool,
}

impl Handshake {
    /// Initiator step 1. Returns the state and msg1 (exactly `MSG1_LEN` bytes).
    pub fn initiate(me: &ContactIdentity, peer: &Bundle) -> Result<(Self, Vec<u8>), Error> {
        let me_pub = Bundle::from_identity(me);
        peer.check_dh_pub()?;
        let (ct_s, ss_s) = peer.kem_key()?.encapsulate();
        let ss_s = Zeroizing::new(ss_s);
        let psk0 = derive_psk(b"seburity-psk0-v1", ss_s.as_slice(), ct_s.as_slice(), &[], &me_pub, peer);
        let (eph_dk, eph_ek) = MlKem768::generate_keypair();
        let eph_ek_bytes = eph_ek.to_bytes().as_slice().to_vec();
        let mut hs = build(me, peer, &psk0, &prologue(&me_pub, peer), true)?;
        let mut out = vec![0u8; NOISE1_LEN + 64];
        let n = hs.write_message(&eph_ek_bytes, &mut out).map_err(|_| Error::Malformed)?;
        debug_assert_eq!(n, NOISE1_LEN);
        let mut msg = ct_s.as_slice().to_vec();
        msg.extend_from_slice(&out[..n]);
        Ok((Self { hs, peer: peer.clone(), me: me_pub, eph_dk, eph_ek: eph_ek_bytes }, msg))
    }

    /// Responder: consume msg1, return `(unconfirmed Session, msg2)`.
    pub fn respond(me: &ContactIdentity, peer: &Bundle, msg1: &[u8]) -> Result<(Session, Vec<u8>), Error> {
        if msg1.len() != MSG1_LEN { return Err(Error::Malformed); }
        peer.check_dh_pub()?;
        let (ct_b, noise) = msg1.split_at(KEM_CT_LEN);
        let ct: Ciphertext<MlKem768> = ct_b.try_into().map_err(|_| Error::Malformed)?;
        let ss_s = Zeroizing::new(me.kem.decapsulate(&ct)); // implicit rejection => wrong psk0 => Noise fails
        let me_pub = Bundle::from_identity(me);
        let psk0 = derive_psk(b"seburity-psk0-v1", ss_s.as_slice(), ct_b, &[], peer, &me_pub);
        let mut hs = build(me, peer, &psk0, &prologue(peer, &me_pub), false)?;
        let mut payload = Zeroizing::new(vec![0u8; NOISE1_LEN]);
        let n = hs.read_message(noise, &mut payload[..]).map_err(|_| Error::BadSignature)?;
        if n != KEM_EK_LEN { return Err(Error::Malformed); }
        let ek_bytes = payload[..n].to_vec();
        let ek = EncapsulationKey768::new(&ek_bytes[..].try_into().map_err(|_| Error::Malformed)?)
            .map_err(|_| Error::Malformed)?;
        let (ct_e, ss_e) = ek.encapsulate();
        let ss_e = Zeroizing::new(ss_e);
        let psk2 = derive_psk(b"seburity-psk2-v1", ss_e.as_slice(), ct_e.as_slice(), &ek_hash(&ek_bytes), peer, &me_pub);
        hs.set_psk(2, &*psk2).map_err(|_| Error::Malformed)?;
        let mut out = vec![0u8; NOISE2_LEN + 64];
        let n = hs.write_message(&[], &mut out).map_err(|_| Error::Malformed)?;
        debug_assert_eq!(n, NOISE2_LEN);
        let mut msg2 = ct_e.as_slice().to_vec();
        msg2.extend_from_slice(&out[..n]);
        Ok((Session::finish(hs, peer, false)?, msg2))
    }

    /// Initiator step 2: consume msg2. The ephemeral ML-KEM secret is dropped here.
    pub fn finish(mut self, msg2: &[u8]) -> Result<Session, Error> {
        if msg2.len() != MSG2_LEN { return Err(Error::Malformed); }
        let (ct_b, noise) = msg2.split_at(KEM_CT_LEN);
        let ct: Ciphertext<MlKem768> = ct_b.try_into().map_err(|_| Error::Malformed)?;
        let ss_e = Zeroizing::new(self.eph_dk.decapsulate(&ct));
        let psk2 = derive_psk(b"seburity-psk2-v1", ss_e.as_slice(), ct_b, &ek_hash(&self.eph_ek), &self.me, &self.peer);
        self.hs.set_psk(2, &*psk2).map_err(|_| Error::Malformed)?;
        let mut scratch = [0u8; NOISE2_LEN];
        self.hs.read_message(noise, &mut scratch).map_err(|_| Error::BadSignature)?;
        Session::finish(self.hs, &self.peer, true)
    }
}

impl Session {
    fn finish(hs: HandshakeState, peer: &Bundle, confirmed: bool) -> Result<Self, Error> {
        if !hs.is_handshake_finished() { return Err(Error::Malformed); }
        let id: [u8; 32] = hs.get_handshake_hash().try_into().map_err(|_| Error::Malformed)?;
        let ts = hs.into_stateless_transport_mode().map_err(|_| Error::Malformed)?;
        Ok(Self { ts, id, send_ctr: 0, recv_last: None, peer: peer.clone(), confirmed })
    }

    pub fn id(&self) -> &[u8; 32] { &self.id }

    /// False for a responder session until the first valid cell has been received.
    pub fn is_confirmed(&self) -> bool { self.confirmed }

    /// Sign, pad and encrypt one message. Output is always `WIRE_CELL_LEN` bytes.
    /// No sender clock is transmitted (it would fingerprint the sender across contacts).
    /// A failed call leaves the session state untouched.
    pub fn send(&mut self, me: &ContactIdentity, body: &[u8]) -> Result<Vec<u8>, Error> {
        let next = self.send_ctr.checked_add(1).ok_or(Error::Replay)?;
        let signed = message::seal(me, &self.peer, &self.id, next, 0, body)?;
        let cell = Zeroizing::new(cell::pad(&signed)?);
        let mut out = vec![0u8; WIRE_CELL_LEN];
        let n = self.ts.write_message(next, &cell[..], &mut out).map_err(|_| Error::Malformed)?;
        debug_assert_eq!(n, WIRE_CELL_LEN);
        self.send_ctr = next; // commit only after success
        Ok(out)
    }

    /// Decrypt, unpad, verify signature and ordering. Strictly consecutive counters only.
    pub fn recv(&mut self, me: &ContactIdentity, wire: &[u8]) -> Result<message::Signed, Error> {
        if wire.len() != WIRE_CELL_LEN { return Err(Error::Malformed); }
        let nonce = match self.recv_last { None => 1, Some(l) => l.checked_add(1).ok_or(Error::Replay)? };
        let mut buf = Zeroizing::new(vec![0u8; WIRE_CELL_LEN]);
        let n = self.ts.read_message(nonce, wire, &mut buf[..]).map_err(|_| Error::BadSignature)?;
        let signed = cell::unpad(&buf[..n])?;
        let m = message::open(me, &self.peer, &self.id, self.recv_last, signed)?;
        if m.counter != nonce { return Err(Error::Replay); }
        self.recv_last = Some(m.counter);
        self.confirmed = true;
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
        assert_eq!(m1.len(), MSG1_LEN);
        let (sb, m2) = Handshake::respond(b, ab, &m1).unwrap();
        assert_eq!(m2.len(), MSG2_LEN);
        (h.finish(&m2).unwrap(), sb)
    }

    #[test]
    fn chat_both_directions_fixed_size_and_confirmation() {
        let (a, ab, b, bb) = setup();
        let (mut sa, mut sb) = connect(&a, &ab, &b, &bb);
        assert_eq!(sa.id(), sb.id());
        assert!(sa.is_confirmed() && !sb.is_confirmed());
        let w1 = sa.send(&a, b"hi bob").unwrap();
        let w2 = sa.send(&a, &vec![b'x'; 800]).unwrap();
        assert_eq!((w1.len(), w2.len()), (WIRE_CELL_LEN, WIRE_CELL_LEN));
        assert_eq!(&sb.recv(&b, &w1).unwrap().body[..], b"hi bob");
        assert!(sb.is_confirmed());
        assert_eq!(sb.recv(&b, &w2).unwrap().body.len(), 800);
        let r = sb.send(&b, b"hi alice").unwrap();
        assert_eq!(&sa.recv(&a, &r).unwrap().body[..], b"hi alice");
    }

    #[test]
    fn replay_reorder_tamper_rejected() {
        let (a, ab, b, bb) = setup();
        let (mut sa, mut sb) = connect(&a, &ab, &b, &bb);
        let w1 = sa.send(&a, b"1").unwrap();
        let w2 = sa.send(&a, b"2").unwrap();
        assert!(sb.recv(&b, &w2).is_err(), "reorder/skip must fail");
        sb.recv(&b, &w1).unwrap();
        assert!(sb.recv(&b, &w1).is_err(), "replay must fail");
        let mut t = w2.clone(); t[100] ^= 1;
        assert!(sb.recv(&b, &t).is_err(), "tamper must fail");
        sb.recv(&b, &w2).unwrap();
    }

    #[test]
    fn failed_send_does_not_desync() {
        let (a, ab, b, bb) = setup();
        let (mut sa, mut sb) = connect(&a, &ab, &b, &bb);
        assert_eq!(sa.send(&a, &vec![0; message::MAX_BODY + 1]).unwrap_err(), Error::TooLarge);
        let w = sa.send(&a, b"still works").unwrap();
        assert_eq!(&sb.recv(&b, &w).unwrap().body[..], b"still works");
    }

    #[test]
    fn replayed_msg1_never_confirms() {
        let (a, ab, b, bb) = setup();
        let (_h, m1) = Handshake::initiate(&a, &bb).unwrap();
        let (s1, _) = Handshake::respond(&b, &ab, &m1).unwrap();
        let (s2, _) = Handshake::respond(&b, &ab, &m1).unwrap(); // attacker replays msg1
        assert!(!s1.is_confirmed() && !s2.is_confirmed());
    }

    #[test]
    fn sessions_are_independent() {
        let (a, ab, b, bb) = setup();
        let (mut sa1, _) = connect(&a, &ab, &b, &bb);
        let (sa2, mut sb2) = connect(&a, &ab, &b, &bb);
        assert_ne!(sa1.id(), sa2.id());
        let old = sa1.send(&a, b"old").unwrap();
        assert!(sb2.recv(&b, &old).is_err());
    }

    #[test]
    fn impostor_and_corrupt_handshakes_fail() {
        let (a, ab, b, bb) = setup();
        let c = ContactIdentity::generate();
        let (_, m1) = Handshake::initiate(&c, &bb).unwrap();
        assert!(Handshake::respond(&b, &ab, &m1).is_err(), "unpinned initiator");
        // every region of msg1 is authenticated: flip a byte at several offsets
        for off in [0, 10, KEM_CT_LEN - 1, KEM_CT_LEN, KEM_CT_LEN + 40, MSG1_LEN - 1] {
            let (_, mut m1) = Handshake::initiate(&a, &bb).unwrap();
            m1[off] ^= 1;
            assert!(Handshake::respond(&b, &ab, &m1).is_err(), "msg1 flip at {off}");
        }
        assert!(Handshake::respond(&b, &ab, &vec![0; 100]).is_err());
        assert!(Handshake::respond(&b, &ab, &vec![0; 5000]).is_err());
    }

    #[test]
    fn msg2_ct_and_noise_are_authenticated() {
        let (a, ab, b, bb) = setup();
        for off in [0, KEM_CT_LEN - 1, KEM_CT_LEN, MSG2_LEN - 1] {
            let (h, m1) = Handshake::initiate(&a, &bb).unwrap();
            let (_, mut m2) = Handshake::respond(&b, &ab, &m1).unwrap();
            m2[off] ^= 1;
            assert!(h.finish(&m2).is_err(), "msg2 flip at {off}");
        }
        let (h, _) = Handshake::initiate(&a, &bb).unwrap();
        assert!(h.finish(&[0; 10]).is_err());
    }

    #[test]
    fn low_order_peer_keys_rejected_at_handshake() {
        let (a, _ab, _b, bb) = setup();
        let mut bad = bb.clone();
        bad.dh_pub = [0; 32];
        assert!(Handshake::initiate(&a, &bad).is_err());
    }
}
