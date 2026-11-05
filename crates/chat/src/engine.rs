//! The supervisor thread. One engine serves all contacts of one running app.
//!
//! Roles: for each contact the party whose Ed25519 signing key is SMALLER dials, the other listens (hosts its onion
//! service for that contact). So exactly one connection exists per pair and only listeners publish a service.
//! Role negotiation (no message needed, both sides can compute it): a listener that CANNOT host (e.g. a Tails whose control
//! port refuses ADD_ONION) flips to dialing; a dialer whose dials keep failing starts hosting as well (lazy fallback), which is
//! exactly what a flipped peer needs. At most one side ever dials a host-capable peer, so no duplicate connections arise.
//! A new AUTHENTICATED inbound connection replaces a stale one; strangers cannot (they fail the handshake).
//! Messages typed while the peer is offline wait in a bounded RAM outbox; nothing is ever written to disk.
//!
//! Availability design (review 6): NO per-contact pre-authentication refusal (it let anyone who could connect lock the real
//! peer out); CPU is bounded by one engine-wide budget instead, every handshake has a TOTAL deadline, and when the handshake
//! slots are full the OLDEST unauthenticated handshake is aborted so a newcomer (possibly the real peer) always gets in.
use crate::{
    conn::{self, DeadlineStream, FileOut, Out},
    file,
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
    /// A DIALING contact whose dials failed this many times in a row starts hosting too, so a peer that cannot host
    /// (and therefore flipped to dialing) can reach us. 0 = never (strictest metadata: we only publish when needed).
    pub host_fallback_after: u32,
}

impl Default for Timing {
    fn default() -> Self {
        Self { poll: Duration::from_millis(200), keepalive: Duration::from_secs(30), idle: Duration::from_secs(100),
               min_backoff: Duration::from_secs(3), max_backoff: Duration::from_secs(60), handshake: Duration::from_secs(45), handshakes_per_sec: 50.0, host_fallback_after: 5 }
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

pub enum Command { Add(ContactCfg), Remove([u8; 8]), Send { id: [u8; 8], text: Zeroizing<String> }, SendFile { id: [u8; 8], file: FileOut }, FileReply { id: [u8; 8], xid: file::Xid, accept: bool }, Shutdown }

#[derive(Debug)]
pub enum Event {
    Connected { id: [u8; 8] },
    Disconnected { id: [u8; 8] },
    Message { id: [u8; 8], text: Zeroizing<String> },
    Notice { id: Option<[u8; 8]>, text: String },
    /// The contact offers a file (ONLY the padded size bucket is known, never the exact length). Nothing is received until `reply_file(.., true)`.
    FileOffer { id: [u8; 8], xid: file::Xid, bucket: u32 },
    /// An offer or transfer ended without a file (expired, stalled, refused, failed its check): clear any "offered" state.
    FileCancelled { id: [u8; 8] },
    /// A received, re-cleaned file (RAM only). `resanitised`: our own cleaning found/removed more than the sender's.
    File { id: [u8; 8], data: Zeroizing<Vec<u8>>, format: seburity_strip::Format, report: Vec<String>, resanitised: bool },
    FileSent { id: [u8; 8] },
}

pub(crate) enum ConnEvent {
    Up { id: [u8; 8], gen: u64, epoch: u64, tx: Sender<Out> },
    Down { id: [u8; 8], gen: u64 },
    Msg { id: [u8; 8], gen: u64, text: Zeroizing<String> },
    Notice { id: [u8; 8], gen: u64, text: String },
    FileOffer { id: [u8; 8], gen: u64, xid: file::Xid, bucket: u32 },
    FileCancelled { id: [u8; 8], gen: u64 },
    File { id: [u8; 8], gen: u64, data: Zeroizing<Vec<u8>>, format: seburity_strip::Format, report: Vec<String>, resanitised: bool },
    FileSent { id: [u8; 8], gen: u64 },
    /// `unreachable`: the dial itself failed (peer offline/unreachable). Handshake failures do NOT count (an attacker could cause them).
    DialFailed { id: [u8; 8], epoch: u64, unreachable: bool },
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

    /// Clean (metadata stripped by allowlist, unknown formats refused), pad to a size bucket and offer a file to a CONNECTED
    /// contact. Returns the cleaning report. Files are never queued: if the contact is offline the engine says so.
    pub fn send_file(&self, id: [u8; 8], raw: &[u8], mode: seburity_strip::Mode) -> Result<Vec<String>, seburity_strip::StripError> {
        let c = seburity_strip::clean(raw, mode)?;
        let report = c.report;
        let data = Zeroizing::new(c.data);
        let Some(stream) = file::build_stream(&data) else { return Err(seburity_strip::StripError::TooLarge) };
        let bucket = stream.len() as u32;
        let mut xid = [0u8; 8];
        getrandom::fill(&mut xid).expect("OS RNG unavailable");
        let mode = if mode == seburity_strip::Mode::PlainText { file::MODE_TEXT } else { file::MODE_AUTO };
        let f = FileOut { xid, bucket, mode, hash: file::hash(&data), padded: Zeroizing::new(stream) };
        let _ = self.tx.send(In::Cmd(Command::SendFile { id, file: f }));
        Ok(report)
    }

    /// Answer a `FileOffer`.
    pub fn reply_file(&self, id: [u8; 8], xid: file::Xid, accept: bool) { let _ = self.tx.send(In::Cmd(Command::FileReply { id, xid, accept })); }

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
    /// We currently host an onion service for this contact.
    hosting: bool,
    /// Consecutive failed dials (reset on a connection).
    fails: u32,
    fallback_tried: bool,
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
        let mut we_dial = we_dial;
        let mut hosting = false;
        // never lazily host after a flip (we are the dialer by necessity) or when we cannot even prepare dialing
        let mut no_fallback = false;
        match self.transport.add_contact(&me, &cfg.peer, !we_dial) {
            Err(e) if !we_dial => {
                // we are the designated host but cannot host: FLIP to dialing (the peer will host for us after its dials fail)
                self.notice(Some(cfg.id), format!("cannot host for this contact ({e}): dialing it instead; it must be able to host"));
                we_dial = true;
                no_fallback = true;
                if let Err(e2) = self.transport.add_contact(&me, &cfg.peer, false) { self.notice(Some(cfg.id), format!("cannot prepare dialing either: {e2}")); }
            }
            Err(e) => { no_fallback = true; self.notice(Some(cfg.id), format!("cannot prepare dialing for this contact: {e}")) }
            Ok(Some(rx)) => { hosting = true; self.spawn_acceptor(cfg.id, cfg.secret.clone(), cfg.peer.clone(), rx, guard, stop.clone(), epoch); }
            Ok(None) => {}
        }
        self.rts.insert(cfg.id, Rt {
            secret: cfg.secret, peer: cfg.peer, my_onion, we_dial, epoch, conn: None, pending: VecDeque::new(), dialing: false,
            backoff: self.t.min_backoff, next_dial: Instant::now(), iso, stop, hosting, fails: 0, fallback_tried: no_fallback,
        });
    }

    /// Lazy fallback: start hosting for a contact we normally only dial.
    fn fallback_host(&mut self, id: [u8; 8]) {
        let Some(rt) = self.rts.get_mut(&id) else { return };
        if rt.hosting || rt.fallback_tried { return; }
        rt.fallback_tried = true;
        let (secret, peer, stop, epoch) = (rt.secret.clone(), rt.peer.clone(), rt.stop.clone(), rt.epoch);
        let Some(me) = ContactIdentity::from_secret_bytes(&secret) else { return };
        match self.transport.add_contact(&me, &peer, true) {
            Ok(Some(rx)) => {
                if let Some(rt) = self.rts.get_mut(&id) { rt.hosting = true; }
                self.spawn_acceptor(id, secret, peer, rx, Arc::new(Mutex::new(HandshakeGuard::new(0))), stop, epoch);
                self.notice(Some(id), "could not reach this contact for a while: now hosting for it too, so it can reach you if it cannot host itself");
            }
            Ok(None) => {}
            Err(e) => self.notice(Some(id), format!("cannot host for this contact either: {e}")),
        }
    }

    fn spawn_acceptor(&self, id: [u8; 8], secret: Zeroizing<Vec<u8>>, peer: Bundle, rx: Receiver<BoxStream>, guard: Arc<Mutex<HandshakeGuard>>, stop: Arc<AtomicBool>, epoch: u64) {
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
            In::Cmd(Command::SendFile { id, file }) => match self.rts.get(&id).and_then(|r| r.conn.as_ref()) {
                Some((_, tx)) => { let _ = tx.send(Out::File(file)); }
                None => self.notice(Some(id), "not connected: files are never queued, try again when the contact is online"),
            },
            In::Cmd(Command::FileReply { id, xid, accept }) => { if let Some((_, tx)) = self.rts.get(&id).and_then(|r| r.conn.as_ref()) { let _ = tx.send(Out::Reply { xid, accept }); } }
            In::Cmd(Command::Shutdown) => {}
            In::Conn(ConnEvent::Up { id, gen, epoch, tx }) => {
                let Some(rt) = self.rts.get_mut(&id).filter(|r| r.epoch == epoch) else { let _ = tx.send(Out::Close); return };
                let had = rt.conn.is_some();
                if let Some((_, old)) = rt.conn.replace((gen, tx.clone())) { let _ = old.send(Out::Close); }
                rt.dialing = false;
                rt.fails = 0;
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
            In::Conn(ConnEvent::Notice { id, gen, text }) => { if self.is_current(id, gen) { self.notice(Some(id), text); } }
            In::Conn(ConnEvent::FileOffer { id, gen, xid, bucket }) => { if self.is_current(id, gen) { let _ = self.ev.send(Event::FileOffer { id, xid, bucket }); } }
            In::Conn(ConnEvent::FileCancelled { id, gen }) => { if self.is_current(id, gen) { let _ = self.ev.send(Event::FileCancelled { id }); } }
            In::Conn(ConnEvent::File { id, gen, data, format, report, resanitised }) => { if self.is_current(id, gen) { let _ = self.ev.send(Event::File { id, data, format, report, resanitised }); } }
            In::Conn(ConnEvent::FileSent { id, gen }) => { if self.is_current(id, gen) { let _ = self.ev.send(Event::FileSent { id }); } }
            In::Conn(ConnEvent::DialFailed { id, epoch, unreachable }) => {
                let mut fallback = false;
                if let Some(rt) = self.rts.get_mut(&id).filter(|r| r.epoch == epoch) {
                    rt.dialing = false;
                    if unreachable { rt.fails += 1; }
                    rt.backoff = (rt.backoff * 2).min(self.t.max_backoff);
                    rt.next_dial = Instant::now() + jitter(rt.backoff);
                    fallback = self.t.host_fallback_after > 0 && rt.fails >= self.t.host_fallback_after && !rt.hosting;
                }
                if fallback { self.fallback_host(id); }
            }
        }
    }

    fn is_current(&self, id: [u8; 8], gen: u64) -> bool { self.rts.get(&id).and_then(|r| r.conn.as_ref()).is_some_and(|(g, _)| *g == gen) }

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
    let fail = |in_tx: &Sender<In>, unreachable: bool| { let _ = in_tx.send(In::Conn(ConnEvent::DialFailed { id, epoch, unreachable })); };
    let Some(me) = ContactIdentity::from_secret_bytes(&secret) else { return fail(&in_tx, false) };
    let Ok(mut stream) = dial(&peer, &iso) else { return fail(&in_tx, true) };
    let r = {
        let mut ds = DeadlineStream { s: &mut stream, end: Instant::now() + t.handshake, abort: Arc::new(AtomicBool::new(false)) };
        link::dial(&mut ds, &me, &peer, &proto::keepalive())
    };
    let Ok(sess) = r else { return fail(&in_tx, false) };
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
                 min_backoff: Duration::from_millis(30), max_backoff: Duration::from_millis(200), handshake: Duration::from_secs(5), handshakes_per_sec: 1000.0, host_fallback_after: 3 }
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

    /// Transport that refuses to host (a Tails whose control port refuses ADD_ONION) but can dial.
    struct NoHost(crate::transport::MemTransport);
    impl Transport for NoHost {
        fn add_contact(&mut self, me: &ContactIdentity, peer: &Bundle, listen: bool) -> Result<Option<Receiver<BoxStream>>, String> {
            if listen { Err("hosting refused by this tor".into()) } else { self.0.add_contact(me, peer, false) }
        }
        fn remove_contact(&mut self, a: &[u8; 32], b: &[u8; 32]) { self.0.remove_contact(a, b) }
        fn dial_fn(&self) -> DialFn { self.0.dial_fn() }
    }

    fn start_with(t: Box<dyn Transport>, me: &ContactIdentity, peer: &Bundle) -> Engine {
        Engine::start(t, vec![ContactCfg::new(ID, me, peer.clone())], fast())
    }

    /// The case that motivated negotiation: the DESIGNATED HOST cannot host. It flips to dialing, the designated dialer starts
    /// hosting after its dials fail, and chat works in both directions.
    #[test]
    fn a_peer_that_cannot_host_is_still_reachable_through_role_flip_and_lazy_hosting() {
        let net = MemNet::new();
        let ((l, lb), (d, db)) = ordered();                          // l = designated host, d = designated dialer
        let el = start_with(Box::new(NoHost(net.transport())), &l, &db);
        let ed = start(&net, &d, &lb, ID);
        assert!(connected(&el) && connected(&ed), "no connection although one side cannot host");
        assert!(net.is_hosted(&db.onion_pub), "the dialer started hosting as a fallback");
        say(&el, ID, "from the side that cannot host");
        say(&ed, ID, "from the side that hosts");
        assert!(got(&ed, "from the side that cannot host"));
        assert!(got(&el, "from the side that hosts"));
        // and it survives a reconnect
        ed.shutdown();
        assert!(wait(&el, |e| matches!(e, Event::Disconnected { .. })));
        let ed2 = start(&net, &d, &lb, ID);
        assert!(connected(&ed2));
        say(&ed2, ID, "again");
        assert!(got(&el, "again"));
    }

    /// Normal case stays quiet: a dialer that connects at once never publishes a service.
    #[test]
    fn no_hosting_fallback_when_the_peer_hosts_fine() {
        let net = MemNet::new();
        let ((l, lb), (d, db)) = ordered();
        let (el, ed) = (start(&net, &l, &db, ID), start(&net, &d, &lb, ID));
        assert!(connected(&el) && connected(&ed));
        std::thread::sleep(Duration::from_millis(800));
        assert!(!net.is_hosted(&db.onion_pub), "the dialer must not publish a service when it does not need to");
        assert!(net.is_hosted(&lb.onion_pub), "the designated host does");
    }

    /// A dialer whose peer is simply offline for a long time starts hosting (documented trade-off), and not before the threshold.
    #[test]
    fn dialer_hosts_only_after_repeated_failed_dials() {
        let net = MemNet::new();
        let ((_l, lb), (d, db)) = ordered();
        let ed = start(&net, &d, &lb, ID);
        assert!(!net.is_hosted(&db.onion_pub));
        let end = Instant::now() + Duration::from_secs(10);
        while !net.is_hosted(&db.onion_pub) && Instant::now() < end { std::thread::sleep(Duration::from_millis(50)); }
        assert!(net.is_hosted(&db.onion_pub), "fallback hosting never started");
        assert!(wait(&ed, |e| matches!(e, Event::Notice { text, .. } if text.contains("now hosting"))));
    }

    /// Refuses the FIRST hosting attempt only (e.g. a transient onion-address collision).
    struct FailOnce(crate::transport::MemTransport, bool);
    impl Transport for FailOnce {
        fn add_contact(&mut self, me: &ContactIdentity, peer: &Bundle, listen: bool) -> Result<Option<Receiver<BoxStream>>, String> {
            if listen && !self.1 { self.1 = true; return Err("transient failure".into()); }
            self.0.add_contact(me, peer, listen)
        }
        fn remove_contact(&mut self, a: &[u8; 32], b: &[u8; 32]) { self.0.remove_contact(a, b) }
        fn dial_fn(&self) -> DialFn { self.0.dial_fn() }
    }

    /// Review 8 (M1): a side that flipped to dialing must never lazily host later (no host+dial on both sides).
    #[test]
    fn a_flipped_side_never_starts_hosting_later() {
        let net = MemNet::new();
        let ((l, lb), (_d, db)) = ordered();
        let _el = start_with(Box::new(FailOnce(net.transport(), false)), &l, &db);
        std::thread::sleep(Duration::from_millis(2500)); // far more than host_fallback_after failed dials
        assert!(!net.is_hosted(&lb.onion_pub), "flipped side started hosting");
    }

    // ---------------- file transfer ----------------
    fn seg(m: u8, body: &[u8]) -> Vec<u8> { let mut v = vec![0xFF, m]; v.extend_from_slice(&((body.len() + 2) as u16).to_be_bytes()); v.extend_from_slice(body); v }

    /// A JPEG skeleton with planted metadata and `scan` bytes of image data.
    fn jpeg(scan: usize) -> Vec<u8> {
        let mut v = vec![0xFF, 0xD8];
        v.extend(seg(0xE1, b"Exif\0\0GPS 52.5N 13.4E Canon EOS"));
        v.extend(seg(0xFE, b"secret comment"));
        v.extend(seg(0xDB, &[0; 65]));
        v.extend(seg(0xC0, &[8, 0, 1, 0, 1, 1, 1, 0x11, 0]));
        v.extend(seg(0xC4, &[0; 17]));
        v.extend(seg(0xDA, &[1, 1, 0, 0, 0x3F, 0]));
        v.extend(std::iter::repeat(0x11u8).take(scan));
        v.extend_from_slice(&[0xFF, 0xD9]);
        v
    }
    fn has(d: &[u8], n: &[u8]) -> bool { d.windows(n.len()).any(|w| w == n) }

    fn pair() -> (Engine, Engine) {
        let net = MemNet::new();
        let ((l, lb), (d, db)) = ordered();
        let (el, ed) = (start(&net, &l, &db, ID), start(&net, &d, &lb, ID));
        assert!(connected(&el) && connected(&ed));
        (el, ed)
    }

    fn offer_xid(e: &Engine) -> (file::Xid, u32) {
        let mut r = None;
        assert!(wait(e, |ev| if let Event::FileOffer { xid, bucket, .. } = ev { r = Some((*xid, *bucket)); true } else { false }), "no offer arrived");
        r.unwrap()
    }

    #[test]
    fn file_is_stripped_accepted_padded_and_delivered() {
        let (el, ed) = pair();
        let raw = jpeg(40_000);
        let report = ed.send_file(ID, &raw, seburity_strip::Mode::Auto).unwrap();
        assert!(!report.is_empty(), "report lists what was removed");
        let (xid, bucket) = offer_xid(&el);
        assert_eq!(bucket as usize, 65_536, "offer announces only the padded bucket, not the size");
        el.reply_file(ID, xid, true);
        let mut got_file = None;
        assert!(wait(&el, |ev| if let Event::File { data, resanitised, .. } = ev { got_file = Some((data.to_vec(), *resanitised)); true } else { false }));
        let (data, resan) = got_file.unwrap();
        assert!(!resan, "sender already cleaned it");
        assert!(!has(&data, b"Exif") && !has(&data, b"GPS") && !has(&data, b"secret comment"));
        assert!(data.len() < raw.len() && data.len() > 40_000);
        assert!(wait(&ed, |ev| matches!(ev, Event::FileSent { .. })));
        // chat still works afterwards
        say(&ed, ID, "after the file");
        assert!(got(&el, "after the file"));
    }

    #[test]
    fn declined_file_sends_no_content_and_unsupported_formats_are_refused() {
        let (el, ed) = pair();
        ed.send_file(ID, &jpeg(1000), seburity_strip::Mode::Auto).unwrap();
        let (xid, _) = offer_xid(&el);
        el.reply_file(ID, xid, false);
        assert!(wait(&ed, |ev| matches!(ev, Event::Notice { text, .. } if text.contains("declined"))));
        assert!(!wait_for(&el, Duration::from_millis(500), |ev| matches!(ev, Event::File { .. })));
        assert!(ed.send_file(ID, b"%PDF-1.7\x00\x01", seburity_strip::Mode::Auto).is_err(), "unknown format must be refused");
        assert!(ed.send_file(ID, &[], seburity_strip::Mode::Auto).is_err());
    }

    #[test]
    fn files_are_never_queued_for_offline_contacts() {
        let net = MemNet::new();
        let ((_l, lb), (d, _db)) = ordered();
        let ed = start(&net, &d, &lb, ID);
        ed.send_file(ID, &jpeg(100), seburity_strip::Mode::Auto).unwrap();
        assert!(wait(&ed, |ev| matches!(ev, Event::Notice { text, .. } if text.contains("never queued"))));
    }

    /// A raw authenticated peer that speaks the file protocol badly.
    fn raw_peer() -> (Engine, crate::transport::BoxStream, seburity_core::session::Session, ContactIdentity) {
        let net = MemNet::new();
        let ((l, lb), (d, db)) = ordered();
        let el = start(&net, &l, &db, ID);
        let dial = net.transport().dial_fn();
        let end = Instant::now() + Duration::from_secs(5);
        let mut s = loop { match dial(&lb, &[1; 16]) { Ok(s) => break s, Err(_) if Instant::now() < end => std::thread::sleep(Duration::from_millis(20)), Err(e) => panic!("{e}") } };
        s.set_timeout(Some(Duration::from_secs(5))).unwrap();
        let sess = link::dial(&mut s, &d, &lb, &proto::keepalive()).unwrap();
        assert!(wait(&el, |e| matches!(e, Event::Connected { .. })));
        (el, s, sess, d)
    }

    fn raw_send(s: &mut crate::transport::BoxStream, sess: &mut seburity_core::session::Session, me: &ContactIdentity, body: &[u8]) {
        use std::io::Write;
        let w = sess.send(me, body).unwrap();
        s.write_all(&w).unwrap();
    }

    /// Read cells until the engine's ACCEPT for `xid` arrives (a correct sender never sends content before it).
    fn raw_wait_accept(s: &mut crate::transport::BoxStream, sess: &mut seburity_core::session::Session, me: &ContactIdentity, xid: file::Xid) {
        use std::io::Read;
        for _ in 0..50 {
            let mut cell = vec![0u8; seburity_core::session::WIRE_CELL_LEN];
            s.read_exact(&mut cell).unwrap();
            let m = sess.recv(me, &cell).unwrap();
            if m.body.first() == Some(&file::KIND_FILE_ACCEPT) && file::parse_ctl(&m.body) == Some(xid) { return; }
        }
        panic!("no ACCEPT");
    }

    #[test]
    fn hostile_peer_cannot_push_unsolicited_or_corrupt_files() {
        let (el, mut s, mut sess, me) = raw_peer();
        // 1. content without an accepted offer: cancelled, engine alive
        raw_send(&mut s, &mut sess, &me, &file::encode_chunk(&[9; 8], &[1; 100]));
        assert!(wait(&el, |e| matches!(e, Event::Notice { text, .. } if text.contains("unexpected file data"))));
        // 2. out-of-policy offers (0 bytes, > cap) are declined without bothering the user
        for bucket in [0u32, 100, 20_000, (file::MAX_FILE * 2) as u32] {
            raw_send(&mut s, &mut sess, &me, &file::encode_offer(&file::Offer { xid: [3; 8], bucket, mode: 0, hash: [0; 32] }));
        }
        assert!(!wait_for(&el, Duration::from_millis(400), |e| matches!(e, Event::FileOffer { .. })));
        // 3. a lying offer (wrong hash): user accepts, content is discarded after the integrity check
        raw_send(&mut s, &mut sess, &me, &file::encode_offer(&file::Offer { xid: [4; 8], bucket: file::MIN_BUCKET as u32, mode: 0, hash: [0xAA; 32] }));
        let (xid, _) = offer_xid(&el);
        el.reply_file(ID, xid, true);
        raw_wait_accept(&mut s, &mut sess, &me, xid);
        for c in file::build_stream(b"x").unwrap().chunks(file::CHUNK_DATA) { raw_send(&mut s, &mut sess, &me, &file::encode_chunk(&[4; 8], c)); }
        assert!(wait(&el, |e| matches!(e, Event::Notice { text, .. } if text.contains("integrity"))), "bad file must not be delivered");
        assert!(!wait_for(&el, Duration::from_millis(300), |e| matches!(e, Event::File { .. })));
    }

    #[test]
    fn receiver_recleans_a_file_the_sender_did_not_clean() {
        let (el, mut s, mut sess, me) = raw_peer();
        let dirty = jpeg(3000);
        let stream = file::build_stream(&dirty).unwrap();
        raw_send(&mut s, &mut sess, &me, &file::encode_offer(&file::Offer { xid: [5; 8], bucket: stream.len() as u32, mode: 0, hash: file::hash(&dirty) }));
        let (xid, _) = offer_xid(&el);
        el.reply_file(ID, xid, true);
        raw_wait_accept(&mut s, &mut sess, &me, xid);
        for c in stream.chunks(file::CHUNK_DATA) { raw_send(&mut s, &mut sess, &me, &file::encode_chunk(&[5; 8], c)); }
        let mut r = None;
        assert!(wait(&el, |e| if let Event::File { data, resanitised, .. } = e { r = Some((data.to_vec(), *resanitised)); true } else { false }));
        let (data, resan) = r.unwrap();
        assert!(resan, "receiver must flag that it had to clean the file itself");
        assert!(!has(&data, b"Exif") && !has(&data, b"secret comment"));
    }

    #[test]
    fn plain_text_is_an_explicit_mode_and_structured_documents_are_refused() {
        let (el, ed) = pair();
        assert!(ed.send_file(ID, b"{\\rtf1{\\info{\\author Jane}}}", seburity_strip::Mode::Auto).is_err());
        assert!(ed.send_file(ID, b"{\\rtf1{\\info{\\author Jane}}}", seburity_strip::Mode::PlainText).is_err());
        let report = ed.send_file(ID, "note\u{202E}\u{E0041} plain".as_bytes(), seburity_strip::Mode::PlainText).unwrap();
        assert!(report.iter().any(|l| l.contains("NOT understood")));
        let (xid, _) = offer_xid(&el);
        el.reply_file(ID, xid, true);
        let mut r = None;
        assert!(wait(&el, |ev| if let Event::File { data, format, .. } = ev { r = Some((data.to_vec(), *format)); true } else { false }));
        let (data, f) = r.unwrap();
        assert_eq!(f, seburity_strip::Format::Text);
        assert_eq!(data, b"note plain");
    }

    #[test]
    fn expired_or_failed_transfers_tell_the_ui_to_clear_the_offer() {
        let (el, mut s, mut sess, me) = raw_peer();
        raw_send(&mut s, &mut sess, &me, &file::encode_offer(&file::Offer { xid: [6; 8], bucket: file::MIN_BUCKET as u32, mode: 0, hash: [1; 32] }));
        let (xid, _) = offer_xid(&el);
        el.reply_file(ID, xid, true);
        raw_wait_accept(&mut s, &mut sess, &me, xid);
        for c in file::build_stream(b"x").unwrap().chunks(file::CHUNK_DATA) { raw_send(&mut s, &mut sess, &me, &file::encode_chunk(&[6; 8], c)); }
        assert!(wait(&el, |e| matches!(e, Event::FileCancelled { .. })), "integrity failure must cancel the UI state");
    }

    #[test]
    fn a_peer_that_keeps_sending_garbage_is_disconnected_and_cannot_flood_notices() {
        let (el, mut s, mut sess, me) = raw_peer();
        for _ in 0..12 { raw_send(&mut s, &mut sess, &me, &file::encode_chunk(&[9; 8], &[1; 10])); }
        assert!(wait(&el, |e| matches!(e, Event::Disconnected { .. })), "abusive peer must be cut off");
        let mut notices = 0;
        while let Ok(ev) = el.events.try_recv() { if matches!(ev, Event::Notice { .. }) { notices += 1; } }
        assert!(notices <= 6, "notice flood: {notices}");
    }

    #[test]
    fn two_peers_that_both_cannot_host_get_a_clear_notice_and_no_crash() {
        let net = MemNet::new();
        let ((l, lb), (d, db)) = ordered();
        let el = start_with(Box::new(NoHost(net.transport())), &l, &db);
        let ed = start_with(Box::new(NoHost(net.transport())), &d, &lb);
        assert!(wait(&el, |e| matches!(e, Event::Notice { text, .. } if text.contains("cannot host"))));
        assert!(wait(&ed, |e| matches!(e, Event::Notice { text, .. } if text.contains("cannot host for this contact either"))));
        assert!(!wait_for(&el, Duration::from_millis(600), |e| matches!(e, Event::Connected { .. })));
    }
}
