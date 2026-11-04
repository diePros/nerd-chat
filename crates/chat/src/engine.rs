//! The supervisor thread. One engine serves all contacts of one running app.
//!
//! Roles: for each contact the party whose Ed25519 signing key is SMALLER dials, the other listens (hosts its onion
//! service for that contact). So exactly one connection exists per pair and only listeners publish a service.
//! A new AUTHENTICATED inbound connection replaces a stale one; strangers cannot (they fail the handshake).
//! Messages typed while the peer is offline wait in a bounded RAM outbox; nothing is ever written to disk.
//!
//! Availability design (review 6): NO per-contact pre-authentication refusal (it let anyone who could connect lock the real
//! peer out); CPU is bounded by one engine-wide budget instead, every handshake has a TOTAL deadline, and when the handshake
//! slots are full the OLDEST unauthenticated handshake is aborted so a newcomer (possibly the real peer) always gets in.
use crate::{
    conn::{self, DeadlineStream, Out},
    proto,
    transport::{BoxStream, DialFn, Transport},
};
use seburity_core::{bundle::Bundle, identity::ContactIdentity};
use seburity_net::{guard::HandshakeGuard, link};
use std::{
    collections::{HashMap, VecDeque},
    sync::{atomic::{AtomicBool, AtomicU64, Ordering}, mpsc::{channel, Receiver, RecvTimeoutError, Sender}, Arc, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const MAX_PENDING: usize = 50;
const MAX_HANDSHAKE_SLOTS: usize = 4;

#[derive(Clone, Copy, Debug)]
pub struct Timing {
    /// Cell polling tick and engine tick.
    pub poll: Duration,
    /// Keepalive cell every this long when idle (detects dead Tor streams; it is a timing signal, see docs).
    pub keepalive: Duration,
    /// Drop the connection if nothing at all arrives for this long.
    pub idle: Duration,
    pub min_backoff: Duration,
    pub max_backoff: Duration,
    /// TOTAL time allowed for one handshake (inbound and outbound), not a per-read timeout.
    pub handshake: Duration,
    /// Engine-wide cap on handshake attempts per second (bounds CPU against floods without ever refusing by contact).
    pub handshakes_per_sec: f64,
}

impl Default for Timing {
    fn default() -> Self {
        Self { poll: Duration::from_millis(200), keepalive: Duration::from_secs(30), idle: Duration::from_secs(100),
               min_backoff: Duration::from_secs(3), max_backoff: Duration::from_secs(60), handshake: Duration::from_secs(45), handshakes_per_sec: 50.0 }
    }
}

/// Engine-wide token bucket for handshake CPU.
pub(crate) struct Budget { st: Mutex<(f64, Instant)>, cap: f64, rate: f64 }

impl Budget {
    pub(crate) fn new(rate: f64) -> Self { let cap = (rate * 2.0).max(10.0); Self { st: Mutex::new((cap, Instant::now())), cap, rate } }
    pub(crate) fn take(&self) -> bool {
        let Ok(mut g) = self.st.lock() else { return false };
        let now = Instant::now();
        let refill = now.duration_since(g.1).as_secs_f64() * self.rate;
        g.0 = (g.0 + refill).min(self.cap);
        g.1 = now;
        if g.0 >= 1.0 { g.0 -= 1.0; true } else { false }
    }
}

/// Everything the engine needs to serve one contact. The secret is wiped on drop.
pub struct ContactCfg { pub id: [u8; 8], secret: Zeroizing<Vec<u8>>, pub peer: Bundle }

impl ContactCfg {
    pub fn new(id: [u8; 8], identity: &ContactIdentity, peer: Bundle) -> Self { Self { id, secret: identity.secret_bytes(), peer } }
}

pub enum Command { Add(ContactCfg), Remove([u8; 8]), Send { id: [u8; 8], text: Zeroizing<String> }, Shutdown }

#[derive(Debug)]
pub enum Event {
    Connected { id: [u8; 8] },
    Disconnected { id: [u8; 8] },
    Message { id: [u8; 8], text: Zeroizing<String> },
    Notice { id: Option<[u8; 8]>, text: String },
}

pub(crate) enum ConnEvent {
    Up { id: [u8; 8], gen: u64, epoch: u64, tx: Sender<Out> },
    Down { id: [u8; 8], gen: u64 },
    Msg { id: [u8; 8], gen: u64, text: Zeroizing<String> },
    DialFailed { id: [u8; 8], epoch: u64 },
}
pub(crate) enum In { Cmd(Command), Conn(ConnEvent) }

pub struct Engine { tx: Sender<In>, pub events: Receiver<Event>, handle: Option<JoinHandle<()>> }

impl Engine {
    pub fn start(transport: Box<dyn Transport>, contacts: Vec<ContactCfg>, timing: Timing) -> Engine {
        let (tx, rx) = channel();
        let (ev_tx, ev_rx) = channel();
        let tx2 = tx.clone();
        let handle = thread::spawn(move || {
            let dial = transport.dial_fn();
            let mut core = Core {
                transport, dial, rts: HashMap::new(), in_tx: tx2, ev: ev_tx, t: timing, gen: Arc::new(AtomicU64::new(0)),
                epoch: Instant::now(), budget: Arc::new(Budget::new(timing.handshakes_per_sec)), next_epoch: 0,
            };
            for c in contacts { core.add(c); }
            loop {
                match rx.recv_timeout(timing.poll) {
                    Ok(In::Cmd(Command::Shutdown)) | Err(RecvTimeoutError::Disconnected) => break,
                    Ok(m) => core.handle(m),
                    Err(RecvTimeoutError::Timeout) => {}
                }
                core.tick();
            }
            core.shutdown();
        });
        Engine { tx, events: ev_rx, handle: Some(handle) }
    }

    pub fn add(&self, c: ContactCfg) { let _ = self.tx.send(In::Cmd(Command::Add(c))); }
    pub fn remove(&self, id: [u8; 8]) { let _ = self.tx.send(In::Cmd(Command::Remove(id))); }
    pub fn send(&self, id: [u8; 8], text: Zeroizing<String>) { let _ = self.tx.send(In::Cmd(Command::Send { id, text })); }

    /// Stop everything (connections closed, onion services removed, secrets wiped) and wait briefly for the thread.
    pub fn shutdown(mut self) { self.stop(Duration::from_secs(3)); }

    /// Same, but give up waiting after `d` (used by the panic key: stay fast).
    pub fn shutdown_within(mut self, d: Duration) { self.stop(d); }

    fn stop(&mut self, wait: Duration) {
        let _ = self.tx.send(In::Cmd(Command::Shutdown));
        if let Some(h) = self.handle.take() {
            let end = Instant::now() + wait;
            while !h.is_finished() && Instant::now() < end { thread::sleep(Duration::from_millis(10)); }
            if h.is_finished() { let _ = h.join(); }
        }
    }
}

impl Drop for Engine { fn drop(&mut self) { self.stop(Duration::from_secs(3)); } }

struct Rt {
    secret: Zeroizing<Vec<u8>>,
    peer: Bundle,
    my_onion: [u8; 32],
    we_dial: bool,
    /// Distinguishes this registration from an earlier one with the same id (remove + add): stale Up/DialFailed are ignored.
    epoch: u64,
    conn: Option<(u64, Sender<Out>)>,
    pending: VecDeque<Zeroizing<String>>,
    dialing: bool,
    backoff: Duration,
    next_dial: Instant,
    iso: [u8; 16],
    stop: Arc<AtomicBool>,
}

struct Core {
    transport: Box<dyn Transport>,
    dial: DialFn,
    rts: HashMap<[u8; 8], Rt>,
    in_tx: Sender<In>,
    ev: Sender<Event>,
    t: Timing,
    gen: Arc<AtomicU64>,
    epoch: Instant,
    budget: Arc<Budget>,
    next_epoch: u64,
}

fn jitter(d: Duration) -> Duration {
    let mut b = [0u8; 1];
    getrandom::fill(&mut b).expect("OS RNG unavailable");
    d.mul_f64(0.75 + b[0] as f64 / 255.0 * 0.5) // +-25%
}

type Slots = Arc<Mutex<Vec<(u64, Arc<AtomicBool>)>>>;

impl Core {
    fn notice(&self, id: Option<[u8; 8]>, text: impl Into<String>) { let _ = self.ev.send(Event::Notice { id, text: text.into() }); }

    fn add(&mut self, cfg: ContactCfg) {
        self.remove(cfg.id);
        let Some(me) = ContactIdentity::from_secret_bytes(&cfg.secret) else { return self.notice(Some(cfg.id), "invalid contact key material") };
        let we_dial = me.verifying_key().to_bytes() < cfg.peer.sign_pub;
        let my_onion = me.onion_public();
        let stop = Arc::new(AtomicBool::new(false));
        let guard = Arc::new(Mutex::new(HandshakeGuard::new(0)));
        let mut iso = [0u8; 16];
        getrandom::fill(&mut iso).expect("OS RNG unavailable");
        self.next_epoch += 1;
        let epoch = self.next_epoch;
        match self.transport.add_contact(&me, &cfg.peer, !we_dial) {
            Err(e) => self.notice(Some(cfg.id), format!("cannot reach/host for this contact: {e}")),
            Ok(Some(rx)) => self.spawn_acceptor(cfg.id, &cfg, rx, guard, stop.clone(), epoch),
            Ok(None) => {}
        }
        self.rts.insert(cfg.id, Rt {
            secret: cfg.secret, peer: cfg.peer, my_onion, we_dial, epoch, conn: None, pending: VecDeque::new(), dialing: false,
            backoff: self.t.min_backoff, next_dial: Instant::now(), iso, stop,
        });
    }

    fn spawn_acceptor(&self, id: [u8; 8], cfg: &ContactCfg, rx: Receiver<BoxStream>, guard: Arc<Mutex<HandshakeGuard>>, stop: Arc<AtomicBool>, epoch: u64) {
        let (secret, peer) = (cfg.secret.clone(), cfg.peer.clone());
        let (in_tx, gen, started, t, budget) = (self.in_tx.clone(), self.gen.clone(), self.epoch, self.t, self.budget.clone());
        let slots: Slots = Arc::new(Mutex::new(Vec::new()));
        let next_slot = Arc::new(AtomicU64::new(0));
        thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                match rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(stream) => {
                        let abort = Arc::new(AtomicBool::new(false));
                        let slot = next_slot.fetch_add(1, Ordering::SeqCst);
                        {
                            // slots full: abort the OLDEST unauthenticated handshake; the newcomer (maybe the real peer) always gets in
                            let mut s = slots.lock().unwrap();
                            if s.len() >= MAX_HANDSHAKE_SLOTS { if let Some((_, old)) = s.first() { old.store(true, Ordering::SeqCst); } }
                            s.push((slot, abort.clone()));
                        }
                        let (secret, peer, guard, in_tx, gen, slots2, budget) = (secret.clone(), peer.clone(), guard.clone(), in_tx.clone(), gen.clone(), slots.clone(), budget.clone());
                        thread::spawn(move || inbound(stream, secret, peer, guard, started, gen, in_tx, id, epoch, t, budget, abort, slots2, slot));
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }
            // contact removed / engine stopping: abort in-flight handshakes so they release their key copies at once
            for (_, a) in slots.lock().unwrap().iter() { a.store(true, Ordering::SeqCst); }
        });
    }

    fn remove(&mut self, id: [u8; 8]) {
        if let Some(rt) = self.rts.remove(&id) {
            rt.stop.store(true, Ordering::SeqCst);
            if let Some((_, tx)) = &rt.conn { let _ = tx.send(Out::Close); let _ = self.ev.send(Event::Disconnected { id }); }
            self.transport.remove_contact(&rt.my_onion, &rt.peer.onion_pub);
        }
    }

    fn handle(&mut self, m: In) {
        match m {
            In::Cmd(Command::Add(c)) => self.add(c),
            In::Cmd(Command::Remove(id)) => self.remove(id),
            In::Cmd(Command::Send { id, text }) => self.send(id, text),
            In::Cmd(Command::Shutdown) => {}
            In::Conn(ConnEvent::Up { id, gen, epoch, tx }) => {
                let Some(rt) = self.rts.get_mut(&id).filter(|r| r.epoch == epoch) else { let _ = tx.send(Out::Close); return };
                let had = rt.conn.is_some();
                if let Some((_, old)) = rt.conn.replace((gen, tx.clone())) { let _ = old.send(Out::Close); }
                rt.dialing = false;
                rt.backoff = self.t.min_backoff;
                while let Some(m) = rt.pending.pop_front() { let _ = tx.send(Out::Text(m)); }
                if !had { let _ = self.ev.send(Event::Connected { id }); }
            }
            In::Conn(ConnEvent::Down { id, gen }) => {
                let Some(rt) = self.rts.get_mut(&id) else { return };
                if rt.conn.as_ref().is_some_and(|(g, _)| *g == gen) {
                    rt.conn = None;
                    rt.dialing = false;
                    rt.next_dial = Instant::now() + jitter(self.t.min_backoff);
                    let _ = self.ev.send(Event::Disconnected { id });
                }
            }
            In::Conn(ConnEvent::Msg { id, gen, text }) => {
                if self.rts.get(&id).and_then(|r| r.conn.as_ref()).is_some_and(|(g, _)| *g == gen) { let _ = self.ev.send(Event::Message { id, text }); }
            }
            In::Conn(ConnEvent::DialFailed { id, epoch }) => {
                if let Some(rt) = self.rts.get_mut(&id).filter(|r| r.epoch == epoch) {
                    rt.dialing = false;
                    rt.backoff = (rt.backoff * 2).min(self.t.max_backoff);
                    rt.next_dial = Instant::now() + jitter(rt.backoff);
                }
            }
        }
    }

    fn send(&mut self, id: [u8; 8], text: Zeroizing<String>) {
        if text.is_empty() || text.len() > proto::MAX_TEXT_BYTES { return self.notice(Some(id), "message empty or too long (max 32 KiB)"); }
        let Some(rt) = self.rts.get_mut(&id) else { return self.notice(Some(id), "unknown contact") };
        match &rt.conn {
            Some((_, tx)) => { let _ = tx.send(Out::Text(text)); }
            None => {
                let dropped = rt.pending.len() >= MAX_PENDING;
                if dropped { rt.pending.pop_front(); }
                rt.pending.push_back(text);
                if rt.we_dial && !rt.dialing { rt.backoff = self.t.min_backoff; rt.next_dial = Instant::now(); }
                if dropped { self.notice(Some(id), "outbox full: oldest queued message dropped"); }
            }
        }
    }

    fn tick(&mut self) {
        let now = Instant::now();
        let ids: Vec<[u8; 8]> = self.rts.iter().filter(|(_, r)| r.we_dial && r.conn.is_none() && !r.dialing && now >= r.next_dial).map(|(i, _)| *i).collect();
        for id in ids {
            let rt = self.rts.get_mut(&id).expect("exists");
            rt.dialing = true;
            let (dial, secret, peer, iso, in_tx, gen, epoch, t) = (self.dial.clone(), rt.secret.clone(), rt.peer.clone(), rt.iso, self.in_tx.clone(), self.gen.clone(), rt.epoch, self.t);
            thread::spawn(move || outbound(dial, secret, peer, iso, in_tx, gen, id, epoch, t));
        }
    }

    fn shutdown(&mut self) {
        let ids: Vec<_> = self.rts.keys().copied().collect();
        for id in ids { self.remove(id); }
    }
}

#[allow(clippy::too_many_arguments)]
fn inbound(mut stream: BoxStream, secret: Zeroizing<Vec<u8>>, peer: Bundle, guard: Arc<Mutex<HandshakeGuard>>, started: Instant, gen: Arc<AtomicU64>,
           in_tx: Sender<In>, id: [u8; 8], epoch: u64, t: Timing, budget: Arc<Budget>, abort: Arc<AtomicBool>, slots: Slots, slot: u64) {
    let release = |slots: &Slots| slots.lock().unwrap().retain(|(s, _)| *s != slot);
    let Some(me) = ContactIdentity::from_secret_bytes(&secret) else { return release(&slots) };
    let r = {
        let mut ds = DeadlineStream { s: &mut stream, end: Instant::now() + t.handshake, abort };
        link::accept_shared(&mut ds, &me, &peer, &guard, started.elapsed().as_secs(), &|| budget.take())
    };
    release(&slots);
    if let Ok((sess, _first)) = r {
        let g = gen.fetch_add(1, Ordering::SeqCst) + 1;
        let (otx, orx) = channel();
        if in_tx.send(In::Conn(ConnEvent::Up { id, gen: g, epoch, tx: otx })).is_err() { return; }
        conn::run(stream, sess, me, orx, in_tx, id, g, t);
    }
}

#[allow(clippy::too_many_arguments)]
fn outbound(dial: DialFn, secret: Zeroizing<Vec<u8>>, peer: Bundle, iso: [u8; 16], in_tx: Sender<In>, gen: Arc<AtomicU64>, id: [u8; 8], epoch: u64, t: Timing) {
    let fail = |in_tx: &Sender<In>| { let _ = in_tx.send(In::Conn(ConnEvent::DialFailed { id, epoch })); };
    let Some(me) = ContactIdentity::from_secret_bytes(&secret) else { return fail(&in_tx) };
    let Ok(mut stream) = dial(&peer, &iso) else { return fail(&in_tx) };
    let r = {
        let mut ds = DeadlineStream { s: &mut stream, end: Instant::now() + t.handshake, abort: Arc::new(AtomicBool::new(false)) };
        link::dial(&mut ds, &me, &peer, &proto::keepalive())
    };
    let Ok(sess) = r else { return fail(&in_tx) };
    let g = gen.fetch_add(1, Ordering::SeqCst) + 1;
    let (otx, orx) = channel();
    if in_tx.send(In::Conn(ConnEvent::Up { id, gen: g, epoch, tx: otx })).is_err() { return; }
    conn::run(stream, sess, me, orx, in_tx, id, g, t);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::MemNet;

    pub fn fast() -> Timing {
        Timing { poll: Duration::from_millis(20), keepalive: Duration::from_millis(100), idle: Duration::from_millis(700),
                 min_backoff: Duration::from_millis(30), max_backoff: Duration::from_millis(200), handshake: Duration::from_secs(5), handshakes_per_sec: 1000.0 }
    }

    fn ident() -> (ContactIdentity, Bundle) { let i = ContactIdentity::generate(); let b = Bundle::from_identity(&i); (i, b) }

    /// (listener, dialer) by the engine's role rule: the SMALLER signing key dials.
    fn ordered() -> ((ContactIdentity, Bundle), (ContactIdentity, Bundle)) {
        loop {
            let (a, b) = (ident(), ident());
            if a.1.sign_pub > b.1.sign_pub { return (a, b); }
            if b.1.sign_pub > a.1.sign_pub { return (b, a); }
        }
    }

    fn start(net: &MemNet, me: &ContactIdentity, peer: &Bundle, id: [u8; 8]) -> Engine {
        Engine::start(Box::new(net.transport()), vec![ContactCfg::new(id, me, peer.clone())], fast())
    }

    fn wait<F: FnMut(&Event) -> bool>(e: &Engine, f: F) -> bool { wait_for(e, Duration::from_secs(10), f) }

    fn wait_for<F: FnMut(&Event) -> bool>(e: &Engine, limit: Duration, mut f: F) -> bool {
        let end = Instant::now() + limit;
        while Instant::now() < end {
            match e.events.recv_timeout(Duration::from_millis(50)) { Ok(ev) => if f(&ev) { return true }, Err(_) => {} }
        }
        false
    }

    fn connected(e: &Engine) -> bool { wait(e, |ev| matches!(ev, Event::Connected { .. })) }
    fn got(e: &Engine, want: &str) -> bool { wait(e, |ev| matches!(ev, Event::Message { text, .. } if &***text == want)) }
    fn say(e: &Engine, id: [u8; 8], t: &str) { e.send(id, Zeroizing::new(t.to_string())); }

    const ID: [u8; 8] = [1; 8];

    #[test]
    fn two_engines_chat_both_directions() {
        let net = MemNet::new();
        let ((l, lb), (d, db)) = ordered();
        let (el, ed) = (start(&net, &l, &db, ID), start(&net, &d, &lb, ID));
        assert!(connected(&el) && connected(&ed));
        say(&el, ID, "from listener");
        say(&ed, ID, "from dialer");
        assert!(got(&ed, "from listener"));
        assert!(got(&el, "from dialer"));
        for i in 0..20 { say(&ed, ID, &format!("m{i}")); }
        for i in 0..20 { assert!(got(&el, &format!("m{i}")), "order/loss at {i}"); }
    }

    #[test]
    fn messages_typed_while_offline_are_queued_in_ram_and_delivered_in_order() {
        let net = MemNet::new();
        let ((l, lb), (d, db)) = ordered();
        let ed = start(&net, &d, &lb, ID);              // dialer alone: peer offline
        for t in ["one", "two", "three"] { say(&ed, ID, t); }
        std::thread::sleep(Duration::from_millis(200));
        let el = start(&net, &l, &db, ID);              // listener comes online later
        for t in ["one", "two", "three"] { assert!(got(&el, t), "{t}"); }
        // and the other way round: listener-only queue
        drop(el);
        let el = start(&net, &l, &db, ID);
        let _ = connected(&el);
    }

    #[test]
    fn long_text_is_chunked_and_hostile_text_is_neutralised() {
        let net = MemNet::new();
        let ((l, lb), (d, db)) = ordered();
        let (el, ed) = (start(&net, &l, &db, ID), start(&net, &d, &lb, ID));
        assert!(connected(&el) && connected(&ed));
        let long = "héllo €😀 ".repeat(1500);
        say(&ed, ID, &long);
        assert!(got(&el, &long));
        say(&ed, ID, "evil\x1b[2J\x07 text\u{202E}rtl");
        assert!(got(&el, "evil?[2J? text?rtl"));
    }

    #[test]
    fn peer_restart_reconnects_and_chat_resumes() {
        let net = MemNet::new();
        let ((l, lb), (d, db)) = ordered();
        let el = start(&net, &l, &db, ID);
        let ed = start(&net, &d, &lb, ID);
        assert!(connected(&el) && connected(&ed));
        ed.shutdown();                                       // dialer goes away
        assert!(wait(&el, |e| matches!(e, Event::Disconnected { .. })));
        let ed2 = start(&net, &d, &lb, ID);                  // and comes back
        assert!(connected(&ed2));
        assert!(wait(&el, |e| matches!(e, Event::Connected { .. })));
        say(&ed2, ID, "back again");
        assert!(got(&el, "back again"));
    }

    #[test]
    fn listener_restart_is_found_again_by_the_dialer_with_backoff() {
        let net = MemNet::new();
        let ((l, lb), (d, db)) = ordered();
        let el = start(&net, &l, &db, ID);
        let ed = start(&net, &d, &lb, ID);
        assert!(connected(&el) && connected(&ed));
        el.shutdown();
        assert!(wait(&ed, |e| matches!(e, Event::Disconnected { .. })));
        std::thread::sleep(Duration::from_millis(400));      // dialer keeps failing meanwhile
        let el2 = start(&net, &l, &db, ID);
        assert!(connected(&el2) && wait(&ed, |e| matches!(e, Event::Connected { .. })));
        say(&el2, ID, "hello again");
        assert!(got(&ed, "hello again"));
    }

    #[test]
    fn an_impostor_cannot_connect_or_disturb_the_real_peer() {
        let net = MemNet::new();
        let ((l, lb), (d, db)) = ordered();
        let (el, ed) = (start(&net, &l, &db, ID), start(&net, &d, &lb, ID));
        assert!(connected(&el) && connected(&ed));
        // Mallory has a valid identity and knows the listener's public bundle, and dials its service
        let (m, _mb) = ident();
        let dial = net.transport().dial_fn();
        for _ in 0..3 {
            let mut s = dial(&lb, &[9; 16]).unwrap(); // both engines are already Connected, so the listener is registered
            s.set_timeout(Some(Duration::from_secs(2))).unwrap();
            assert!(link::dial(&mut s, &m, &lb, b"x").is_err(), "impostor must fail the handshake");
        }
        say(&ed, ID, "still fine");
        assert!(got(&el, "still fine"), "real connection unaffected");
        assert!(!wait(&el, |e| matches!(e, Event::Message { text, .. } if text.contains('x') && text.len() == 1)));
    }

    #[test]
    fn silent_peer_is_dropped_by_the_idle_timeout_and_keepalives_keep_a_quiet_chat_alive() {
        let net = MemNet::new();
        let ((l, lb), (d, db)) = ordered();
        // quiet but healthy chat: no messages for >2 idle periods, still connected
        let (el, ed) = (start(&net, &l, &db, ID), start(&net, &d, &lb, ID));
        assert!(connected(&el) && connected(&ed));
        assert!(!wait_for(&el, Duration::from_millis(1800), |e| matches!(e, Event::Disconnected { .. })), "keepalives must keep a quiet chat up");
        drop(ed); drop(el);
        // a raw peer that handshakes correctly and then says nothing
        let net = MemNet::new();
        let el = start(&net, &l, &db, ID);
        let dial = net.transport().dial_fn();
        let end = Instant::now() + Duration::from_secs(5); // the engine thread registers its listener asynchronously
        let mut s = loop { match dial(&lb, &[1; 16]) { Ok(s) => break s, Err(_) if Instant::now() < end => std::thread::sleep(Duration::from_millis(20)), Err(e) => panic!("{e}") } };
        s.set_timeout(Some(Duration::from_secs(5))).unwrap();
        let _sess = link::dial(&mut s, &d, &lb, &proto::keepalive()).unwrap();
        assert!(wait(&el, |e| matches!(e, Event::Connected { .. })));
        assert!(wait(&el, |e| matches!(e, Event::Disconnected { .. })), "idle timeout must close a silent connection");
    }

    #[test]
    fn remove_contact_stops_delivery_and_shutdown_is_prompt() {
        let net = MemNet::new();
        let ((l, lb), (d, db)) = ordered();
        let (el, ed) = (start(&net, &l, &db, ID), start(&net, &d, &lb, ID));
        assert!(connected(&el) && connected(&ed));
        el.remove(ID);
        assert!(wait(&el, |e| matches!(e, Event::Disconnected { .. })));
        say(&ed, ID, "nobody listens");
        assert!(!wait(&el, |e| matches!(e, Event::Message { .. })));
        let t = Instant::now();
        ed.shutdown();
        el.shutdown();
        assert!(t.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn bounded_outbox_and_input_limits() {
        let net = MemNet::new();
        let ((_, lb), (d, _)) = ordered();
        let ed = start(&net, &d, &lb, ID);
        for i in 0..(MAX_PENDING + 5) { say(&ed, ID, &format!("q{i}")); }
        assert!(wait(&ed, |e| matches!(e, Event::Notice { text, .. } if text.contains("outbox full"))));
        say(&ed, ID, "");
        assert!(wait(&ed, |e| matches!(e, Event::Notice { text, .. } if text.contains("empty or too long"))));
        say(&ed, ID, &"a".repeat(proto::MAX_TEXT_BYTES + 1));
        assert!(wait(&ed, |e| matches!(e, Event::Notice { text, .. } if text.contains("empty or too long"))));
    }

    /// R6-M1: garbage handshakes must never lock the REAL peer out (the old per-contact token bucket did, for minutes).
    #[test]
    fn a_garbage_flood_does_not_lock_out_the_real_peer() {
        let net = MemNet::new();
        let ((l, lb), (d, db)) = ordered();
        let el = start(&net, &l, &db, ID);
        let dial = net.transport().dial_fn();
        let end = Instant::now() + Duration::from_secs(5);
        while dial(&lb, &[0; 16]).is_err() && Instant::now() < end { std::thread::sleep(Duration::from_millis(20)); }
        for _ in 0..60 {                                        // far beyond the old burst of 5
            if let Ok(mut s) = dial(&lb, &[3; 16]) {
                use std::io::Write;
                let _ = s.write_all(&vec![0xAB; seburity_core::session::MSG1_LEN]);
            }
        }
        let ed = start(&net, &d, &lb, ID);                       // now the real peer arrives
        assert!(connected(&ed) && connected(&el), "real peer was locked out by garbage");
        say(&ed, ID, "through the noise");
        assert!(got(&el, "through the noise"));
    }

    /// R6-M2: trickling connections must neither hold all slots nor outlive the TOTAL deadline.
    #[test]
    fn slowloris_cannot_starve_the_handshake_slots() {
        use std::io::Write;
        let net = MemNet::new();
        let ((l, lb), (d, db)) = ordered();
        let el = start(&net, &l, &db, ID);
        let dial = net.transport().dial_fn();
        let end = Instant::now() + Duration::from_secs(5);
        while dial(&lb, &[0; 16]).is_err() && Instant::now() < end { std::thread::sleep(Duration::from_millis(20)); }
        let stop = Arc::new(AtomicBool::new(false));
        let mut feeders = vec![];
        for _ in 0..8 {                                          // twice the number of slots, one byte every 50 ms
            let mut s = dial(&lb, &[4; 16]).unwrap();
            let stop = stop.clone();
            feeders.push(std::thread::spawn(move || { while !stop.load(Ordering::SeqCst) { if s.write_all(&[0u8]).is_err() { break; } std::thread::sleep(Duration::from_millis(50)); } }));
        }
        let t = Instant::now();
        let ed = start(&net, &d, &lb, ID);
        assert!(connected(&ed) && connected(&el), "slowloris starved the real peer");
        assert!(t.elapsed() < Duration::from_secs(4), "took {:?}", t.elapsed());
        stop.store(true, Ordering::SeqCst);
        for f in feeders { let _ = f.join(); }
    }

    #[test]
    fn engine_wide_budget_refills_and_caps() {
        let b = Budget::new(20.0);                               // cap 40
        let taken = (0..100).filter(|_| b.take()).count();
        assert!((38..=45).contains(&taken), "burst should be about the cap, got {taken}");
        std::thread::sleep(Duration::from_millis(300));
        assert!(b.take(), "tokens refill with time");
    }

    /// R6-I1: replacing a contact (same id, remove + add) must not leave the old registration alive.
    #[test]
    fn re_adding_a_contact_replaces_it_cleanly() {
        let net = MemNet::new();
        let ((l, lb), (d, db)) = ordered();
        let el = start(&net, &l, &db, ID);
        let ed = start(&net, &d, &lb, ID);
        assert!(connected(&el) && connected(&ed));
        el.add(ContactCfg::new(ID, &l, db.clone()));             // same id re-added: old connection closed, new one established
        assert!(wait(&el, |e| matches!(e, Event::Disconnected { .. })));
        assert!(wait(&el, |e| matches!(e, Event::Connected { .. })));
        say(&ed, ID, "after re-add");
        assert!(got(&el, "after re-add"));
    }
}
