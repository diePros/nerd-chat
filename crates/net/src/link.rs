//! Handshake + confirmed session over a byte stream.
//!
//! dial:   write msg1, read msg2, IMMEDIATELY send the first cell (this confirms the session).
//! accept: guard check -> read msg1 -> respond -> write msg2 -> read first cell; only a valid
//!         first cell yields a confirmed session (a replayed msg1 can never get there).
//! The caller sets read/write timeouts on the stream (Tor streams, sockets) and rate limits via `HandshakeGuard`.
use crate::{guard::{HandshakeGuard, Verdict}, NetError};
use seburity_core::{
    bundle::Bundle,
    identity::ContactIdentity,
    message::Signed,
    session::{Handshake, Session, MSG1_LEN, MSG2_LEN, WIRE_CELL_LEN},
};
use std::io::{Read, Write};

fn rd<R: Read>(r: &mut R, n: usize) -> Result<Vec<u8>, NetError> {
    let mut v = vec![0u8; n];
    r.read_exact(&mut v).map_err(|_| NetError::Io)?;
    Ok(v)
}

fn wr<W: Write>(w: &mut W, d: &[u8]) -> Result<(), NetError> {
    w.write_all(d).and_then(|_| w.flush()).map_err(|_| NetError::Io)
}

/// Initiator. `first` is the first message body (sent as the confirmation cell).
pub fn dial<S: Read + Write>(s: &mut S, me: &ContactIdentity, peer: &Bundle, first: &[u8]) -> Result<Session, NetError> {
    let (hs, m1) = Handshake::initiate(me, peer).map_err(|_| NetError::Handshake)?;
    wr(s, &m1)?;
    let m2 = rd(s, MSG2_LEN)?;
    let mut sess = hs.finish(me, &m2).map_err(|_| NetError::Handshake)?;
    let cell = sess.send(me, first).map_err(|_| NetError::Handshake)?;
    wr(s, &cell)?;
    Ok(sess)
}

/// Responder for one pinned contact. Returns the CONFIRMED session and the first message.
pub fn accept<S: Read + Write>(s: &mut S, me: &ContactIdentity, peer: &Bundle, guard: &mut HandshakeGuard, now: u64) -> Result<(Session, Signed), NetError> {
    let m1 = rd(s, MSG1_LEN)?;
    match guard.check(&m1, now) {
        Verdict::Allow => {}
        Verdict::RateLimited => return Err(NetError::RateLimited),
        Verdict::Replay => return Err(NetError::Replay),
    }
    let (mut sess, m2) = Handshake::respond(me, peer, &m1).map_err(|_| NetError::Handshake)?;
    wr(s, &m2)?;
    let cell = rd(s, WIRE_CELL_LEN)?;
    let first = sess.recv(me, &cell).map_err(|_| NetError::Unconfirmed)?;
    debug_assert!(sess.is_confirmed());
    guard.record_success(&m1, now);
    Ok((sess, first))
}

/// Like [`accept`] but the guard is shared between threads and locked only for the quick checks, NEVER across network
/// I/O: a stranger that connects and stalls must not be able to block the real contact's handshake.
///
/// No per-contact volume limit: only the replay cache runs before authentication (garbage must never cost the REAL peer
/// a token). `admit` is the caller's engine-wide CPU budget, asked once a full msg1 has arrived and before any crypto.
pub fn accept_shared<S: Read + Write>(s: &mut S, me: &ContactIdentity, peer: &Bundle, guard: &std::sync::Mutex<HandshakeGuard>, now: u64, admit: &dyn Fn() -> bool) -> Result<(Session, Signed), NetError> {
    let m1 = rd(s, MSG1_LEN)?;
    let verdict = guard.lock().map_err(|_| NetError::Io)?.check_replay(&m1, now);
    match verdict {
        Verdict::Allow => {}
        Verdict::RateLimited => return Err(NetError::RateLimited),
        Verdict::Replay => return Err(NetError::Replay),
    }
    if !admit() { return Err(NetError::RateLimited); }
    let (mut sess, m2) = Handshake::respond(me, peer, &m1).map_err(|_| NetError::Handshake)?;
    wr(s, &m2)?;
    let cell = rd(s, WIRE_CELL_LEN)?;
    let first = sess.recv(me, &cell).map_err(|_| NetError::Unconfirmed)?;
    guard.lock().map_err(|_| NetError::Io)?.record_success(&m1, now);
    Ok((sess, first))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::thread;

    struct Pair { a: ContactIdentity, ab: Bundle, b: ContactIdentity, bb: Bundle }
    fn pair() -> Pair {
        let a = ContactIdentity::generate(); let b = ContactIdentity::generate();
        let (ab, bb) = (Bundle::from_identity(&a), Bundle::from_identity(&b));
        Pair { a, ab, b, bb }
    }
    fn timeout(s: &UnixStream) {
        s.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
    }

    #[test]
    fn dial_accept_then_chat() {
        let p = pair();
        let (mut sa, mut sb) = UnixStream::pair().unwrap();
        timeout(&sa); timeout(&sb);
        let (b, ab) = (ContactIdentity::from_secret_bytes(&p.b.secret_bytes()).unwrap(), p.ab.clone());
        let t = thread::spawn(move || {
            let mut g = HandshakeGuard::new(0);
            let (mut s, first) = accept(&mut sb, &b, &ab, &mut g, 0).unwrap();
            assert!(s.is_confirmed());
            assert_eq!(&first.body[..], b"hello");
            let reply = s.send(&b, b"hi back").unwrap();
            sb.write_all(&reply).unwrap();
        });
        let mut s = dial(&mut sa, &p.a, &p.bb, b"hello").unwrap();
        let wire = rd(&mut sa, WIRE_CELL_LEN).unwrap();
        assert_eq!(&s.recv(&p.a, &wire).unwrap().body[..], b"hi back");
        t.join().unwrap();
    }

    #[test]
    fn replayed_handshake_is_rejected_by_guard() {
        let p = pair();
        // record a genuine msg1 and replay it
        let (_, m1) = Handshake::initiate(&p.a, &p.bb).unwrap();
        let mut g = HandshakeGuard::new(0);
        g.record_success(&m1, 0);
        let (mut atk, mut srv) = UnixStream::pair().unwrap();
        timeout(&srv);
        atk.write_all(&m1).unwrap();
        let r = accept(&mut srv, &p.b, &p.ab, &mut g, 1);
        assert_eq!(r.err(), Some(NetError::Replay));
    }

    #[test]
    fn replayed_msg1_without_confirmation_never_yields_a_session() {
        // attacker replays msg1 (cache cold), reads msg2 but cannot produce a valid first cell
        let p = pair();
        let (_, m1) = Handshake::initiate(&p.a, &p.bb).unwrap();
        let (mut atk, mut srv) = UnixStream::pair().unwrap();
        timeout(&srv);
        let (b, ab) = (ContactIdentity::from_secret_bytes(&p.b.secret_bytes()).unwrap(), p.ab.clone());
        let t = thread::spawn(move || accept(&mut srv, &b, &ab, &mut HandshakeGuard::new(0), 0).err());
        atk.write_all(&m1).unwrap();
        let _m2 = rd(&mut atk, MSG2_LEN).unwrap();
        atk.write_all(&vec![7u8; WIRE_CELL_LEN]).unwrap();
        assert_eq!(t.join().unwrap(), Some(NetError::Unconfirmed));
    }

    #[test]
    fn garbage_and_flood_are_cheap() {
        let p = pair();
        let mut g = HandshakeGuard::with(0, 2.0, 0.0, 16, 100);
        for expect in [NetError::Handshake, NetError::Handshake, NetError::RateLimited] {
            let (mut atk, mut srv) = UnixStream::pair().unwrap();
            timeout(&srv);
            atk.write_all(&vec![0xAB; MSG1_LEN]).unwrap();
            assert_eq!(accept(&mut srv, &p.b, &p.ab, &mut g, 0).err(), Some(expect));
        }
        // short read (peer closes early) is an I/O error, not a panic
        let (atk, mut srv) = UnixStream::pair().unwrap();
        drop(atk);
        assert_eq!(accept(&mut srv, &p.b, &p.ab, &mut g, 100).err(), Some(NetError::Io));
    }
}
