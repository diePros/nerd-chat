//! Local pairing link (asymmetric SPAKE2 over any `PairStream`).
//!
//! Roles: the OFFER side (shows the code, listens) is role A; the JOIN side (types the code) is role B.
//! Two sessions of the same role can never complete, so cross-wiring a device's own sessions fails.
//!
//! 1. SPAKE2(code) -> K. B (joiner) writes first, A (listener) stays silent until then.
//! 2. Key confirmation tags (role-bound) over the length-prefixed transcript.
//! 3. Self-signed bundles under XChaCha20-Poly1305 (AAD binds role + transcript).
//! 4. Proof of possession: each side signs the transcript+both bundles with its Ed25519 key.
//! 5. A full Noise/ML-KEM session handshake over the same stream (proves possession of the X25519 and
//!    ML-KEM secrets) and an exchanged transcript-hash confirmation cell both ways. Only then is the
//!    contact returned. The last cell is A's, so a dropped final cell can leave A committed and B failed:
//!    users should check the contact appeared on BOTH sides.
//!
//! One-time code: a `PairingOffer` is consumed by exactly ONE attempt (success or failure), has no
//! constructor from digits, expires, and failures feed a process-wide backoff. An active MITM still
//! gets one guess against each side (2 per code, p = 2e-10).
use crate::{ExchangeError, ImportedContact};
use blake2::{digest::consts::U32, Blake2b, Digest};
use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, XChaCha20Poly1305, XNonce};
use curve25519_dalek::edwards::CompressedEdwardsY;
use nerd_chat_core::{bundle::{safety_number, Bundle, BUNDLE_LEN}, identity::ContactIdentity};
use nerd_chat_net::{guard::HandshakeGuard, link};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use std::{
    io::{Read, Write},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const MAX_FRAME: usize = 2048;
const ID_A: &[u8] = b"seburity-pair-v1-offer";
const ID_B: &[u8] = b"seburity-pair-v1-join";
/// 10 decimal digits (~33 bits). Safe because each code allows ~one online guess per side.
pub const CODE_DIGITS: usize = 10;
pub const OFFER_TTL: Duration = Duration::from_secs(300);
pub const PAIR_DEADLINE: Duration = Duration::from_secs(60);
/// Pairing over Tor: the offer may live this long AT MOST (counted from the moment the link is published), and one protocol run gets
/// more time (circuits are slow).
pub const REMOTE_OFFER_MAX_TTL: Duration = Duration::from_secs(600);
pub const REMOTE_PAIR_DEADLINE: Duration = Duration::from_secs(90);

/// A byte stream with a settable I/O timeout (TCP, Unix socket, BLE wrapper...).
pub trait PairStream: Read + Write {
    fn set_timeout(&mut self, d: Duration) -> std::io::Result<()>;
}
impl PairStream for std::net::TcpStream {
    fn set_timeout(&mut self, d: Duration) -> std::io::Result<()> {
        self.set_read_timeout(Some(d))?;
        self.set_write_timeout(Some(d))
    }
}
#[cfg(unix)]
impl PairStream for std::os::unix::net::UnixStream {
    fn set_timeout(&mut self, d: Duration) -> std::io::Result<()> {
        self.set_read_timeout(Some(d))?;
        self.set_write_timeout(Some(d))
    }
}

// ---------- failure backoff ----------
/// Consecutive-failure counter shared by all pairing attempts in the process.
#[derive(Default)]
pub struct Lockout(Mutex<(u32, Option<Instant>)>);

impl Lockout {
    /// Seconds to wait before the next attempt (0 = go). First 2 failures are free, then 30 s * 2^n (cap 1 h).
    pub fn remaining(&self) -> u64 {
        let g = self.0.lock().unwrap();
        match (g.0, g.1) {
            (n, Some(t)) if n >= 3 => {
                let wait = Duration::from_secs((30u64 << (n - 3).min(7)).min(3600));
                wait.saturating_sub(t.elapsed()).as_secs()
            }
            _ => 0,
        }
    }
    fn fail(&self) { let mut g = self.0.lock().unwrap(); g.0 = g.0.saturating_add(1); g.1 = Some(Instant::now()); }
    fn ok(&self) { *self.0.lock().unwrap() = (0, None); }
    fn guard(&self) -> Result<(), ExchangeError> {
        match self.remaining() { 0 => Ok(()), n => Err(ExchangeError::Locked(n)) }
    }
}

fn fresh_digits() -> Zeroizing<[u8; CODE_DIGITS]> {
    let mut d = Zeroizing::new([0u8; CODE_DIGITS]);
    let mut i = 0;
    while i < CODE_DIGITS {
        let mut b = Zeroizing::new([0u8; 16]);
        getrandom::fill(&mut *b).expect("OS RNG unavailable");
        for &x in b.iter() {
            // 250 = 25 * 10: rejection sampling, no modulo bias
            if x < 250 && i < CODE_DIGITS { d[i] = b'0' + x % 10; i += 1; }
        }
    }
    d
}

fn display(d: &[u8; CODE_DIGITS]) -> Zeroizing<String> {
    let mut s = Zeroizing::new(String::with_capacity(CODE_DIGITS + 1));
    for (i, &c) in d.iter().enumerate() {
        if i == CODE_DIGITS / 2 { s.push('-'); }
        s.push(c as char);
    }
    s
}

// ---------- public API ----------
/// Offer side. There is deliberately NO way to rebuild an offer from its digits.
pub struct PairingOffer { code: Zeroizing<[u8; CODE_DIGITS]>, expires: Instant, lockout: Arc<Lockout>, deadline: Duration, can_host: bool }

impl PairingOffer {
    /// Returns the offer and the digits to show the user. Fails while locked out.
    pub fn generate_in(lockout: Arc<Lockout>) -> Result<(Self, Zeroizing<String>), ExchangeError> {
        lockout.guard()?;
        let code = fresh_digits();
        let shown = display(&code);
        Ok((Self { code, expires: Instant::now() + OFFER_TTL, lockout, deadline: PAIR_DEADLINE, can_host: true }, shown))
    }

    /// An offer for a pairing over Tor (docs/superpowers/specs/2026-11-09-tor-pairing-spec.md). Create it when the link is PUBLISHED: the TTL
    /// counts from now (capped at `REMOTE_OFFER_MAX_TTL`). Pass a lockout that is SEPARATE from the local pairing's: an attacker who holds
    /// the link must not be able to lock the user out of every other way of pairing.
    pub fn generate_remote(lockout: Arc<Lockout>, ttl: Duration) -> Result<(Self, Zeroizing<String>), ExchangeError> {
        let (mut o, shown) = Self::generate_in(lockout)?;
        o.expires = Instant::now() + ttl.min(REMOTE_OFFER_MAX_TTL);
        o.deadline = REMOTE_PAIR_DEADLINE;
        Ok((o, shown))
    }

    /// Like `accept`, for the remote offer: consumes the offer, but a failure only counts toward the lockout when a well-formed SPAKE2
    /// message arrived (a real guess at the code). Connect-then-close and garbage burn the offer without growing the lockout. The error
    /// carries `true` when it was a real guess.
    pub fn accept_remote<S: PairStream>(self, s: &mut S, me: &ContactIdentity) -> Result<Paired, (ExchangeError, bool)> {
        if Instant::now() >= self.expires { return Err((ExchangeError::Expired, false)); }
        self.lockout.guard().map_err(|e| (e, false))?;
        let got = std::cell::Cell::new(false);
        let r = run(Role::A, s, me, &self.code, self.deadline, self.can_host, None, &got);
        match r {
            Ok(p) => { self.lockout.ok(); Ok(p) }
            Err(e) => { if got.get() { self.lockout.fail(); } Err((e, got.get())) }
        }
    }

    pub fn expires_in(&self) -> Duration { self.expires.saturating_duration_since(Instant::now()) }
    pub fn with_deadline(mut self, d: Duration) -> Self { self.deadline = d; self }
    /// Our capability, carried in the bundle we send (false = our Tor cannot host onion services).
    pub fn with_can_host(mut self, can_host: bool) -> Self { self.can_host = can_host; self }

    /// Consumes the offer: ONE attempt, success or failure. The listener must stop accepting connections afterwards.
    pub fn accept<S: PairStream>(self, s: &mut S, me: &ContactIdentity) -> Result<Paired, ExchangeError> {
        if Instant::now() >= self.expires { return Err(ExchangeError::Expired); }
        self.lockout.guard()?;
        let r = run(Role::A, s, me, &self.code, self.deadline, self.can_host, None, &std::cell::Cell::new(false));
        if r.is_ok() { self.lockout.ok() } else { self.lockout.fail() }
        r
    }
}

/// Join side: the user types the code.
pub struct PairingJoin { code: Zeroizing<[u8; CODE_DIGITS]>, lockout: Arc<Lockout>, deadline: Duration, can_host: bool }

impl PairingJoin {
    /// Accepts `12345-67890`, spaces, or plain digits.
    pub fn parse_in(input: &str, lockout: Arc<Lockout>) -> Result<Self, ExchangeError> {
        let mut code = Zeroizing::new([0u8; CODE_DIGITS]);
        let mut n = 0;
        for c in input.bytes().filter(|c| !matches!(c, b'-' | b' ')) {
            if n >= CODE_DIGITS || !c.is_ascii_digit() { return Err(ExchangeError::BadCode); }
            code[n] = c;
            n += 1;
        }
        if n != CODE_DIGITS { return Err(ExchangeError::BadCode); }
        Ok(Self { code, lockout, deadline: PAIR_DEADLINE, can_host: true })
    }

    pub fn with_deadline(mut self, d: Duration) -> Self { self.deadline = d; self }
    pub fn with_can_host(mut self, can_host: bool) -> Self { self.can_host = can_host; self }

    pub fn join<S: PairStream>(self, s: &mut S, me: &ContactIdentity) -> Result<Paired, ExchangeError> {
        self.lockout.guard()?;
        let r = run(Role::B, s, me, &self.code, self.deadline, self.can_host, None, &std::cell::Cell::new(false));
        if r.is_ok() { self.lockout.ok() } else { self.lockout.fail() }
        r
    }
}

pub struct Paired { pub contact: ImportedContact, pub safety_number: String }

// ---------- protocol ----------
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role { A, B }
impl Role {
    fn byte(self) -> u8 { if self == Role::A { b'A' } else { b'B' } }
    fn other(self) -> Role { if self == Role::A { Role::B } else { Role::A } }
}

/// Wraps a stream so EVERY read/write call re-arms the socket timeout with the time left until the
/// overall deadline (a per-call timeout alone lets a slow-drip peer stretch a read forever).
struct Bounded<'a, S: PairStream> { s: &'a mut S, end: Instant }

impl<S: PairStream> Bounded<'_, S> {
    fn arm(&mut self) -> std::io::Result<()> {
        let left = self.end.saturating_duration_since(Instant::now());
        if left.is_zero() { return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "pairing deadline")); }
        self.s.set_timeout(left)
    }
}
impl<S: PairStream> Read for Bounded<'_, S> {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> { self.arm()?; self.s.read(b) }
}
impl<S: PairStream> Write for Bounded<'_, S> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> { self.arm()?; self.s.write(b) }
    fn flush(&mut self) -> std::io::Result<()> { self.arm()?; self.s.flush() }
}

fn write_frame<W: Write>(w: &mut W, d: &[u8]) -> Result<(), ExchangeError> {
    if d.len() > MAX_FRAME { return Err(ExchangeError::Malformed); }
    w.write_all(&(d.len() as u16).to_be_bytes()).and_then(|_| w.write_all(d)).and_then(|_| w.flush()).map_err(|_| ExchangeError::Io)
}

fn read_frame<R: Read>(r: &mut R) -> Result<Vec<u8>, ExchangeError> {
    let mut l = [0u8; 2];
    r.read_exact(&mut l).map_err(|_| ExchangeError::Io)?;
    let n = u16::from_be_bytes(l) as usize;
    if n > MAX_FRAME { return Err(ExchangeError::Malformed); }
    let mut v = vec![0u8; n];
    r.read_exact(&mut v).map_err(|_| ExchangeError::Io)?;
    Ok(v)
}

fn lp(h: &mut Blake2b<U32>, x: &[u8]) { h.update((x.len() as u32).to_be_bytes()); h.update(x); }

fn kdf(k: &[u8], label: &[u8], a: &[u8], b: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut h = Blake2b::<U32>::new();
    lp(&mut h, b"seburity-pair-kdf-v2");
    for x in [label, k, a, b] { lp(&mut h, x); }
    Zeroizing::new(h.finalize().into())
}

fn tag(k_conf: &[u8; 32], role: Role, a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h = Blake2b::<U32>::new();
    lp(&mut h, b"seburity-pair-confirm-v2");
    for x in [&[role.byte()][..], k_conf, a, b] { lp(&mut h, x); }
    h.finalize().into()
}

fn transcript(a: &[u8], b: &[u8], enc_a: &[u8], enc_b: &[u8]) -> [u8; 32] {
    let mut h = Blake2b::<U32>::new();
    lp(&mut h, b"seburity-pair-transcript-v2");
    for x in [a, b, enc_a, enc_b] { lp(&mut h, x); }
    h.finalize().into()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// Reject SPAKE2 points that are non-decodable, small-order or non-canonically encoded.
fn check_point(msg: &[u8]) -> Result<(), ExchangeError> {
    if msg.len() != 33 { return Err(ExchangeError::PairingFailed); }
    let raw: [u8; 32] = msg[1..].try_into().unwrap();
    let c = CompressedEdwardsY(raw);
    let p = c.decompress().ok_or(ExchangeError::PairingFailed)?;
    if p.is_small_order() || !p.is_torsion_free() || p.compress().to_bytes() != raw { return Err(ExchangeError::PairingFailed); }
    Ok(())
}

/// `claimed`: test hook letting an adversarial peer present a DIFFERENT bundle than its identity's.
///
/// I/O order: B (the joiner) always speaks first, so a listener stays SILENT until a joiner
/// writes (a port scanner gets no Nerd-chat banner). Outcome note: the last message is A's confirmation
/// cell, so if it is lost A may have committed while B failed; users should confirm on both sides.
fn run<S: PairStream>(role: Role, stream: &mut S, me: &ContactIdentity, code: &[u8; CODE_DIGITS], deadline: Duration, can_host: bool, claimed: Option<Vec<u8>>, got_msg: &std::cell::Cell<bool>) -> Result<Paired, ExchangeError> {
    let mut b = Bounded { s: stream, end: Instant::now() + deadline };
    let pw = Password::new(&code[..]);
    let (st, my_msg) = match role {
        Role::A => Spake2::<Ed25519Group>::start_a(&pw, &Identity::new(ID_A), &Identity::new(ID_B)),
        Role::B => Spake2::<Ed25519Group>::start_b(&pw, &Identity::new(ID_A), &Identity::new(ID_B)),
    };
    // One exchange step: B writes first, A reads first.
    let swap = |b: &mut Bounded<S>, out: &[u8]| -> Result<Vec<u8>, ExchangeError> {
        if role == Role::B { write_frame(b, out)?; read_frame(b) } else { let r = read_frame(b)?; write_frame(b, out)?; Ok(r) }
    };
    // 1. PAKE messages
    let peer_msg = swap(&mut b, &my_msg)?;
    check_point(&peer_msg)?;
    got_msg.set(true); // a well-formed SPAKE2 message arrived: from here on a failure is a real guess
    let k = Zeroizing::new(st.finish(&peer_msg).map_err(|_| ExchangeError::PairingFailed)?);
    let (ma, mb) = if role == Role::A { (&my_msg, &peer_msg) } else { (&peer_msg, &my_msg) };
    let k_conf = kdf(&k, b"conf", ma, mb);
    let k_enc = kdf(&k, b"enc", ma, mb);

    // 2. Key confirmation
    let my_tag = tag(&k_conf, role, ma, mb);
    let their_expected = tag(&k_conf, role.other(), ma, mb);
    let their_tag = swap(&mut b, &my_tag)?;
    if !ct_eq(&their_tag, &their_expected) { return Err(ExchangeError::PairingFailed); }

    // 3. Bundle exchange (encrypted under K, role+transcript in AAD)
    let me_b = Bundle::from_identity(me).with_can_host(can_host);
    let my_enc = claimed.unwrap_or_else(|| me_b.encode(me));
    let cipher = XChaCha20Poly1305::new((&*k_enc).into());
    let seal = |role: Role, pt: &[u8]| -> Result<Vec<u8>, ExchangeError> {
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce).expect("OS RNG unavailable");
        let aad = [b"seburity-pair-frame".as_slice(), &[role.byte()], ma, mb].concat();
        let ct = cipher.encrypt(XNonce::from_slice(&nonce), Payload { msg: pt, aad: &aad }).map_err(|_| ExchangeError::Malformed)?;
        Ok([nonce.as_slice(), &ct].concat())
    };
    let open = |role: Role, f: &[u8]| -> Result<Zeroizing<Vec<u8>>, ExchangeError> {
        if f.len() < 24 + 16 { return Err(ExchangeError::Malformed); }
        let aad = [b"seburity-pair-frame".as_slice(), &[role.byte()], ma, mb].concat();
        cipher.decrypt(XNonce::from_slice(&f[..24]), Payload { msg: &f[24..], aad: &aad }).map(Zeroizing::new).map_err(|_| ExchangeError::PairingFailed)
    };
    let peer_enc_frame = swap(&mut b, &seal(role, &my_enc)?)?;
    let peer_enc = open(role.other(), &peer_enc_frame)?;
    if peer_enc.len() != BUNDLE_LEN { return Err(ExchangeError::Malformed); }
    let theirs = Bundle::decode(&peer_enc).map_err(|_| ExchangeError::Malformed)?;
    if theirs.sign_pub == me_b.sign_pub { return Err(ExchangeError::ProofFailed); } // reflection (compare KEYS, the capability may differ)

    // 4. Proof of possession of the Ed25519 key, bound to this exact transcript and both bundles
    let (ea, eb) = if role == Role::A { (&my_enc[..], &peer_enc[..]) } else { (&peer_enc[..], &my_enc[..]) };
    let t = transcript(ma, mb, ea, eb);
    let pop_msg = |r: Role| [b"seburity-pair-pop-v1".as_slice(), &[r.byte()], &t].concat();
    let my_pop = me.sign_domain(&pop_msg(role));
    let peer_pop_frame = swap(&mut b, &seal(role, &my_pop)?)?;
    let peer_pop = open(role.other(), &peer_pop_frame)?;
    let peer_pop: [u8; 64] = peer_pop[..].try_into().map_err(|_| ExchangeError::ProofFailed)?;
    if !theirs.verify_domain(&pop_msg(role.other()), &peer_pop) { return Err(ExchangeError::ProofFailed); }

    // 5. Prove X25519 + ML-KEM possession with a real session handshake; confirm the transcript both ways.
    // B dials, A accepts. Every read/write below is deadline-bounded by `Bounded`.
    let mut guard = HandshakeGuard::new(0);
    match role {
        Role::B => {
            let mut sess = link::dial(&mut b, me, &theirs, &t).map_err(|_| ExchangeError::ProofFailed)?;
            let mut cell = vec![0u8; nerd_chat_core::session::WIRE_CELL_LEN];
            b.read_exact(&mut cell).map_err(|_| ExchangeError::Io)?;
            let m = sess.recv(me, &cell).map_err(|_| ExchangeError::ProofFailed)?;
            if !ct_eq(&m.body, &t) { return Err(ExchangeError::ProofFailed); }
        }
        Role::A => {
            let (mut sess, first) = link::accept(&mut b, me, &theirs, &mut guard, 0).map_err(|_| ExchangeError::ProofFailed)?;
            if !ct_eq(&first.body, &t) { return Err(ExchangeError::ProofFailed); }
            let reply = sess.send(me, &t).map_err(|_| ExchangeError::ProofFailed)?;
            b.write_all(&reply).and_then(|_| b.flush()).map_err(|_| ExchangeError::Io)?;
        }
    }
    let sn = safety_number(&me_b, &theirs);
    Ok(Paired { contact: ImportedContact::from_pake(theirs), safety_number: sn })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nerd_chat_core::trust::Trust;
    use std::os::unix::net::UnixStream;
    use std::thread;

    fn clone_id(i: &ContactIdentity) -> ContactIdentity { ContactIdentity::from_secret_bytes(&i.secret_bytes()).unwrap() }

    fn lo() -> Arc<Lockout> { Arc::new(Lockout::default()) }

    fn run_pair(code_a: &str, code_b: &str, l: Arc<Lockout>) ->  (Result<Paired, ExchangeError>, Result<Paired, ExchangeError>, ContactIdentity, ContactIdentity) {
        run_pair2(code_a, code_b, l, lo())
    }

    /// Each side has its OWN lockout, as on two real devices.
    fn run_pair2(code_a: &str, code_b: &str, la: Arc<Lockout>, lb: Arc<Lockout>) -> (Result<Paired, ExchangeError>, Result<Paired, ExchangeError>, ContactIdentity, ContactIdentity) {
        let (mut sa, mut sb) = UnixStream::pair().unwrap();
        let (a, b) = (ContactIdentity::generate(), ContactIdentity::generate());
        let (a2, b2) = (clone_id(&a), clone_id(&b));
        let offer = {
            let (mut o, _) = PairingOffer::generate_in(la.clone()).unwrap();
            o.code = PairingJoin::parse_in(code_a, la.clone()).unwrap().code; // test-only: fixed code
            o.with_deadline(Duration::from_secs(10))
        };
        let join = PairingJoin::parse_in(code_b, lb).unwrap().with_deadline(Duration::from_secs(10));
        let ta = thread::spawn(move || { let r = offer.accept(&mut sa, &a2); drop(sa); r });
        let tb = thread::spawn(move || { let r = join.join(&mut sb, &b2); drop(sb); r });
        (ta.join().unwrap(), tb.join().unwrap(), a, b)
    }

    #[test]
    fn matching_code_pairs_with_pop_and_codeauthenticated_trust() {
        let (ra, rb, a, b) = run_pair("1234567890", "12345-67890", lo());
        let (ra, rb) = (ra.unwrap(), rb.unwrap());
        assert_eq!(ra.contact.bundle(), &Bundle::from_identity(&b));
        assert_eq!(rb.contact.bundle(), &Bundle::from_identity(&a));
        assert_eq!(ra.safety_number, rb.safety_number);
        assert_eq!(ra.contact.trust(), Trust::CodeAuthenticated);
    }

    #[test]
    fn safety_confirmation_raises_trust_only_with_matching_view() {
        let (ra, _rb, a, _b) = run_pair("1111111111", "1111111111", lo());
        let mut c = ra.unwrap().contact;
        let mine = Bundle::from_identity(&a);
        let v = c.safety_view(&mine);
        assert!(c.confirm(&mine, v));
        assert_eq!(c.trust(), Trust::SafetyVerified);
        // a view for a different contact is refused
        let other = ImportedContact::from_file(Bundle::from_identity(&ContactIdentity::generate()));
        let mut c2 = ImportedContact::from_file(Bundle::from_identity(&ContactIdentity::generate()));
        assert!(!c2.confirm(&mine, other.safety_view(&mine)));
        assert_eq!(c2.trust(), Trust::Unverified);
    }

    #[test]
    fn wrong_code_fails_both_sides() {
        let (ra, rb, _, _) = run_pair("1111111111", "1111111112", lo());
        assert_eq!(ra.err(), Some(ExchangeError::PairingFailed));
        assert_eq!(rb.err(), Some(ExchangeError::PairingFailed));
    }

    #[test]
    fn same_role_sessions_cannot_cross_complete() {
        // two OFFER-side sessions of the same device relayed to each other (R3-M2)
        let (mut s1, mut s2) = UnixStream::pair().unwrap();
        let l = lo();
        let mk = |l: &Arc<Lockout>| { let (mut o, _) = PairingOffer::generate_in(l.clone()).unwrap(); o.code = Zeroizing::new(*b"4242424242"); o.with_deadline(Duration::from_secs(5)) };
        let (o1, o2) = (mk(&l), mk(&l));
        let (i1, i2) = (ContactIdentity::generate(), ContactIdentity::generate());
        let t1 = thread::spawn(move || o1.accept(&mut s1, &i1).err());
        let t2 = thread::spawn(move || o2.accept(&mut s2, &i2).err());
        assert!(t1.join().unwrap().is_some() && t2.join().unwrap().is_some());
    }

    #[test]
    fn lockout_after_repeated_failures_and_offer_is_single_use() {
        let l = lo();
        for _ in 0..3 { let (a, b, _, _) = run_pair("1111111111", "2222222222", l.clone()); assert!(a.is_err() && b.is_err()); }
        assert!(l.remaining() > 0);
        assert!(matches!(PairingOffer::generate_in(l.clone()), Err(ExchangeError::Locked(_))));
        assert!(matches!(PairingJoin::parse_in("1111111111", l).unwrap().join(&mut UnixStream::pair().unwrap().0, &ContactIdentity::generate()), Err(ExchangeError::Locked(_))));
    }

    #[test]
    fn stalled_peer_times_out() {
        let (mut me, _atk) = UnixStream::pair().unwrap();
        let j = PairingJoin::parse_in("1111111111", lo()).unwrap().with_deadline(Duration::from_millis(300));
        let t = Instant::now();
        assert_eq!(j.join(&mut me, &ContactIdentity::generate()).err(), Some(ExchangeError::Io));
        assert!(t.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn slow_drip_peer_cannot_stretch_the_deadline() {
        // peer dribbles one byte every 100 ms; overall deadline is 400 ms
        let (mut me, mut atk) = UnixStream::pair().unwrap();
        let j = PairingJoin::parse_in("1111111111", lo()).unwrap().with_deadline(Duration::from_millis(400));
        let t = thread::spawn(move || { let id = ContactIdentity::generate(); j.join(&mut me, &id).err() });
        let start = Instant::now();
        let feeder = thread::spawn(move || {
            let mut buf = [0u8; 64];
            let _ = atk.read(&mut buf); // joiner speaks first
            let _ = atk.write_all(&[0x08, 0x00]); // announce a 2048-byte frame, then dribble it
            for _ in 0..40 { if atk.write_all(&[0u8]).is_err() { break; } thread::sleep(Duration::from_millis(100)); }
        });
        assert_eq!(t.join().unwrap(), Some(ExchangeError::Io));
        assert!(start.elapsed() < Duration::from_secs(2), "deadline not enforced: {:?}", start.elapsed());
        let _ = feeder.join();
    }

    #[test]
    fn listener_is_silent_until_the_joiner_speaks() {
        let (mut srv, mut scanner) = UnixStream::pair().unwrap();
        scanner.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let (o, _) = PairingOffer::generate_in(lo()).unwrap();
        let o = o.with_deadline(Duration::from_millis(600));
        let t = thread::spawn(move || o.accept(&mut srv, &ContactIdentity::generate()).err());
        let mut b = [0u8; 1];
        assert!(scanner.read(&mut b).is_err(), "listener must not send a banner");
        assert!(t.join().unwrap().is_some());
    }

    #[test]
    fn small_order_and_garbage_points_rejected() {
        let mut ident = vec![b'A']; ident.extend_from_slice(&{ let mut p = [0u8; 32]; p[0] = 1; p }); // identity point
        assert!(check_point(&ident).is_err());
        assert!(check_point(&[b'A'; 10]).is_err());
        let mut noncanon = vec![b'A']; noncanon.extend_from_slice(&[0xff; 32]);
        assert!(check_point(&noncanon).is_err());
    }

    #[test]
    fn bundle_substitution_without_key_possession_fails() {
        // Mallory knows the code and presents CAROL's (validly signed) bundle but cannot prove possession.
        let carol = ContactIdentity::generate();
        let carol_enc = Bundle::from_identity(&carol).encode(&carol);
        let (mut sa, mut sm) = UnixStream::pair().unwrap();
        let l = lo();
        let (mut o, _) = PairingOffer::generate_in(l).unwrap();
        o.code = Zeroizing::new(*b"5555555555");
        let o = o.with_deadline(Duration::from_secs(10));
        let alice = ContactIdentity::generate();
        let ta = thread::spawn(move || o.accept(&mut sa, &alice).err());
        let mallory = ContactIdentity::generate();
        let r = run(Role::B, &mut sm, &mallory, b"5555555555", Duration::from_secs(10), true, Some(carol_enc), &std::cell::Cell::new(false));
        assert!(r.is_err());
        assert_eq!(ta.join().unwrap(), Some(ExchangeError::ProofFailed));
    }

    #[test]
    fn code_parsing_generation_and_zeroizing_display() {
        let l = lo();
        assert!(PairingJoin::parse_in("12345-6789", l.clone()).is_err());
        assert!(PairingJoin::parse_in("12345-6789a", l.clone()).is_err());
        assert!(PairingJoin::parse_in("12345678901", l.clone()).is_err());
        assert!(PairingJoin::parse_in("123 45-67890", l.clone()).is_ok());
        let (_, d1) = PairingOffer::generate_in(l.clone()).unwrap();
        let (_, d2) = PairingOffer::generate_in(l).unwrap();
        assert_eq!(d1.len(), CODE_DIGITS + 1);
        assert_ne!(*d1, *d2);
    }

    // ---------------------------------------------------------------- remote (Tor) offers, spec 2026-11-09-tor-pairing-spec.md
    fn remote_offer(code: &str, l: Arc<Lockout>) -> PairingOffer {
        let (mut o, _) = PairingOffer::generate_remote(l.clone(), Duration::from_secs(600)).unwrap();
        o.code = PairingJoin::parse_in(code, l).unwrap().code; // test-only: fixed code
        o.with_deadline(Duration::from_secs(5))
    }

    #[test]
    fn a_remote_offer_pairs_like_a_local_one_and_its_ttl_is_capped() {
        let (mut sa, mut sb) = UnixStream::pair().unwrap();
        let (a, b) = (ContactIdentity::generate(), ContactIdentity::generate());
        let (a2, b2) = (clone_id(&a), clone_id(&b));
        let offer = remote_offer("2468013579", lo());
        let join = PairingJoin::parse_in("2468013579", lo()).unwrap().with_deadline(Duration::from_secs(5));
        let ta = thread::spawn(move || offer.accept_remote(&mut sa, &a2));
        let tb = thread::spawn(move || join.join(&mut sb, &b2));
        let (ra, rb) = (ta.join().unwrap().map_err(|e| e.0).unwrap(), tb.join().unwrap().unwrap());
        assert_eq!(ra.safety_number, rb.safety_number);
        let (o, _) = PairingOffer::generate_remote(lo(), Duration::from_secs(36000)).unwrap();
        assert!(o.expires_in() <= REMOTE_OFFER_MAX_TTL, "a remote offer lives at most 10 minutes");
        assert_eq!(o.deadline, REMOTE_PAIR_DEADLINE);
    }

    #[test]
    fn an_expired_remote_offer_is_refused_without_a_guess() {
        let (mut sa, _sb) = UnixStream::pair().unwrap();
        let (o, _) = PairingOffer::generate_remote(lo(), Duration::ZERO).unwrap();
        let e = o.accept_remote(&mut sa, &ContactIdentity::generate()).err().unwrap();
        assert_eq!(e, (ExchangeError::Expired, false));
    }

    #[test]
    fn connect_then_close_and_garbage_burn_the_offer_but_never_grow_the_lockout() {
        let l = lo();
        for i in 0..6 {
            let (mut sa, sb) = UnixStream::pair().unwrap();
            let offer = remote_offer("1357924680", l.clone());
            if i % 2 == 0 { drop(sb); } else { let mut sb = sb; std::io::Write::write_all(&mut sb, &[0, 5, 1, 2, 3, 4, 5]).unwrap(); drop(sb); }
            let e = offer.accept_remote(&mut sa, &ContactIdentity::generate()).err().unwrap();
            assert!(!e.1, "attempt {i}: nothing was guessed ({:?})", e.0);
        }
        assert_eq!(l.remaining(), 0, "an attacker who only has the link must not lock the user out");
        assert!(PairingOffer::generate_remote(l, Duration::from_secs(60)).is_ok());
    }

    #[test]
    fn real_wrong_guesses_do_count_and_end_in_a_lockout() {
        let l = lo();
        for _ in 0..3 {
            let (mut sa, mut sb) = UnixStream::pair().unwrap();
            let (a, b) = (ContactIdentity::generate(), ContactIdentity::generate());
            let offer = remote_offer("1111111111", l.clone());
            let join = PairingJoin::parse_in("2222222222", lo()).unwrap().with_deadline(Duration::from_secs(5));
            let ta = thread::spawn(move || offer.accept_remote(&mut sa, &a));
            let tb = thread::spawn(move || { let r = join.join(&mut sb, &b); drop(sb); r });
            let e = ta.join().unwrap().err().unwrap();
            assert!(e.1, "a wrong code is a real guess");
            let _ = tb.join();
        }
        assert!(matches!(PairingOffer::generate_remote(l.clone(), Duration::from_secs(60)), Err(ExchangeError::Locked(_))), "three real guesses lock the REMOTE lockout");
        assert_eq!(lo().remaining(), 0, "the local pairing lockout is a different object");
    }
}
