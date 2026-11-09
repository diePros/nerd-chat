//! The supervisor thread. One engine serves all contacts of one running app.
//!
//! Roles: for each contact the party whose Ed25519 signing key is SMALLER dials, the other listens (hosts its onion
//! service for that contact). So exactly one connection exists per pair and only listeners publish a service.
//! Roles come from the bundles: each bundle carries a signed `can_host` capability (false e.g. on a Tails whose control port
//! refuses ADD_ONION). If exactly one side can host, that side hosts and the other dials; otherwise the smaller signing key
//! dials. Nobody publishes a service just to find out. Safety nets: a designated host whose hosting fails anyway flips to
//! dialing; the USER may set `host_anyway` for a contact (we then host although we would only dial: costs presence privacy).
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
use nerd_chat_core::{bundle::Bundle, identity::ContactIdentity};
use nerd_chat_net::{guard::HandshakeGuard, link};
use std::{
    collections::{HashMap, VecDeque},
    sync::{atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering}, mpsc::{channel, Receiver, RecvTimeoutError, Sender}, Arc, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

/// Texts that are not yet confirmed by the contact (queued or in flight): the sender keeps them in RAM and resends them on every new
/// connection. When full, a NEW text is refused (never silently dropping an older one).
pub const MAX_UNCONFIRMED: usize = 50;
/// Ids of the last texts received per contact, to drop a resent text that was already shown.
const MAX_SEEN: usize = 256;
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
    /// A confirmation waits a random time in `[ack_delay_min, ack_delay_max]` (and is batched) before it is sent.
    pub ack_delay_min: Duration,
    pub ack_delay_max: Duration,
    /// How long after a connection comes up we wait for the peer's capability frame before treating it as a v0.1.0 peer
    /// (plain text frames, no confirmation expected).
    pub caps_wait: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self { poll: Duration::from_millis(200), keepalive: Duration::from_secs(30), idle: Duration::from_secs(100),
               min_backoff: Duration::from_secs(3), max_backoff: Duration::from_secs(60), handshake: Duration::from_secs(45), handshakes_per_sec: 50.0,
               ack_delay_min: Duration::from_secs(1), ack_delay_max: Duration::from_secs(5), caps_wait: Duration::from_secs(5) }
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

/// Who dials for a contact. From the signed capabilities: a side that cannot host never hosts (so it dials); if exactly one
/// can host that one hosts; otherwise the smaller signing key dials.
pub fn we_dial(my_sign_pub: &[u8; 32], peer: &Bundle, our_can_host: bool) -> bool {
    match (our_can_host, peer.can_host) { (false, _) => true, (true, false) => false, (true, true) => my_sign_pub < &peer.sign_pub }
}

/// Everything the engine needs to serve one contact. The secret is wiped on drop.
pub struct ContactCfg {
    pub id: [u8; 8], secret: Zeroizing<Vec<u8>>, pub peer: Bundle, our_can_host: bool, host_anyway: bool,
    /// Our proposed (not yet acknowledged) transport keys as a full identity secret; hosted next to the current service.
    next: Option<Zeroizing<Vec<u8>>>,
    /// The peer's previous (onion, auth): its old auth key stays authorized on our hosted service until its rotation is done.
    peer_old: Option<([u8; 32], [u8; 32])>,
    /// Texts the contact has not confirmed that were kept from an earlier run (the encrypted outbox): they start out as `unacked`, so they are
    /// written (again) on the first connection exactly like texts queued while the contact was away.
    outbox: Vec<(proto::MsgId, Zeroizing<String>)>,
}

impl ContactCfg {
    pub fn new(id: [u8; 8], identity: &ContactIdentity, peer: Bundle) -> Self { Self { id, secret: identity.secret_bytes(), peer, our_can_host: true, host_anyway: false, next: None, peer_old: None, outbox: Vec::new() } }
    /// Unconfirmed texts from an earlier run (oldest first). At most `MAX_UNCONFIRMED` are taken, each must be a valid text; a re-add of a
    /// contact the engine already serves keeps ITS queue instead (it is the newer one).
    pub fn with_outbox(mut self, texts: Vec<(proto::MsgId, Zeroizing<String>)>) -> Self {
        self.outbox = texts.into_iter().filter(|(_, t)| !t.is_empty() && t.len() <= proto::MAX_TEXT_BYTES).take(MAX_UNCONFIRMED).collect();
        self
    }
    /// `our_can_host`: whether OUR Tor can host (what we put in our bundle). `host_anyway`: the user's choice to host for this
    /// contact even when we would only dial (e.g. the contact flipped because it cannot host although its bundle says it can).
    /// Key rotation state from the vault: `next` = our proposed transport secret, `peer_old` = the peer's previous keys.
    pub fn with_rotation(mut self, identity: &ContactIdentity, next: Option<&[u8; 64]>, peer_old: Option<([u8; 32], [u8; 32])>) -> Self {
        self.next = next.and_then(|t| identity.with_transport_secret(t)).map(|i| i.secret_bytes());
        self.peer_old = peer_old;
        self
    }
    pub fn with_caps(mut self, our_can_host: bool, host_anyway: bool) -> Self { self.our_can_host = our_can_host; self.host_anyway = host_anyway; self }
}

pub enum Command { Add(ContactCfg), Remove([u8; 8]), Send { id: [u8; 8], mid: proto::MsgId, text: Zeroizing<String> }, Confirm { id: [u8; 8], mid: proto::MsgId }, SendFile { id: [u8; 8], file: FileOut }, FileReply { id: [u8; 8], xid: file::Xid, accept: bool }, Rotate { id: [u8; 8], kind: u8, keys: Option<[u8; 64]> }, Shutdown }

#[derive(Debug)]
pub enum Event {
    Connected { id: [u8; 8] },
    Disconnected { id: [u8; 8] },
    /// A text from the contact. `mid` is the id it carries (`None` from a peer that sends no ids). The UI MUST call `Engine::confirm`
    /// for it once it holds the text: only then does the engine tell the sender "received" (never before the UI has it).
    Message { id: [u8; 8], mid: Option<proto::MsgId>, text: Zeroizing<String> },
    /// `alert`: security-relevant (integrity failure, refused content): the UI keeps it until acknowledged.
    Notice { id: Option<[u8; 8]>, text: String, alert: bool },
    /// The contact offers a file (ONLY the padded size bucket is known, never the exact length). Nothing is received until `reply_file(.., true)`.
    FileOffer { id: [u8; 8], xid: file::Xid, bucket: u32 },
    /// An offer or transfer ended without a file (expired, stalled, refused, failed its check): clear any "offered" state.
    FileCancelled { id: [u8; 8] },
    /// A received, re-cleaned file (RAM only). `resanitised`: our own cleaning found/removed more than the sender's.
    File { id: [u8; 8], data: Zeroizing<Vec<u8>>, format: nerd_chat_strip::Format, report: Vec<String>, resanitised: bool },
    FileSent { id: [u8; 8] },
    /// The contact's app confirmed the text with this id ("their client has it", not "they read it": no read receipts, by design), or,
    /// for a v0.1.0-style peer that cannot confirm anything, the text was written to the connection (the old meaning of "sent").
    Delivered { id: [u8; 8], mid: proto::MsgId },
    /// The text with this id was refused (outbox full, empty, too long, unknown contact): it was NOT sent and never will be.
    Unsent { id: [u8; 8], mid: proto::MsgId },
    /// The contact sent a key-rotation frame (`kind` = proto::KIND_ROTATE_*) carrying its new (onion, auth) public keys.
    Rotate { id: [u8; 8], kind: u8, onion: [u8; 32], auth: [u8; 32] },
}

pub(crate) enum ConnEvent {
    Up { id: [u8; 8], gen: u64, epoch: u64, tx: Sender<Out> },
    Down { id: [u8; 8], gen: u64 },
    /// An event for the UI, delivered only if `gen` is still the current connection of `id` (messages, notices, file events).
    Ev { id: [u8; 8], gen: u64, ev: Event },
    /// A complete text; `mid` is the id the sender announced (None from a peer that does not send ids).
    Text { id: [u8; 8], gen: u64, mid: Option<proto::MsgId>, text: Zeroizing<String> },
    /// The contact confirmed the text with this id (valid from any connection of the session: it is authenticated).
    Acked { id: [u8; 8], mids: Vec<proto::MsgId> },
    /// The peer announced its capabilities (`proto::CAP_*`) on this connection.
    Caps { id: [u8; 8], gen: u64, flags: u8 },
    Rotate { id: [u8; 8], kind: u8, keys: [u8; 64] },
    DialFailed { id: [u8; 8], epoch: u64 },
    /// The outbound thread has really ended (always sent last): only now may another dial start (R8-I6).
    DialEnded { id: [u8; 8], epoch: u64 },
}
pub(crate) enum In { Cmd(Command), Conn(ConnEvent) }

pub struct Engine { tx: Sender<In>, pub events: Receiver<Event>, handle: Option<JoinHandle<()>>, live: Arc<AtomicUsize>, pair_host: Option<crate::transport::PairHostFn>, pair_dial: Option<crate::transport::PairDialFn> }

/// Counts running connection threads (they hold file buffers of up to 8 MiB): `stop` waits for them so a panic wipe really drops them.
struct LiveGuard(Arc<AtomicUsize>);
impl LiveGuard { fn new(c: &Arc<AtomicUsize>) -> Self { c.fetch_add(1, Ordering::SeqCst); Self(c.clone()) } }
impl Drop for LiveGuard { fn drop(&mut self) { self.0.fetch_sub(1, Ordering::SeqCst); } }

impl Engine {
    pub fn start(transport: Box<dyn Transport>, contacts: Vec<ContactCfg>, timing: Timing) -> Engine {
        let (tx, rx) = channel();
        let (ev_tx, ev_rx) = channel();
        let tx2 = tx.clone();
        let (pair_host, pair_dial) = (transport.pair_host_fn(), transport.pair_dial_fn());
        let live = Arc::new(AtomicUsize::new(0));
        let live2 = live.clone();
        let handle = thread::spawn(move || {
            let dial = transport.dial_fn();
            let mut core = Core {
                transport, dial, rts: HashMap::new(), in_tx: tx2, ev: ev_tx, t: timing, gen: Arc::new(AtomicU64::new(0)),
                epoch: Instant::now(), budget: Arc::new(Budget::new(timing.handshakes_per_sec)), next_epoch: 0, live: live2,
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
        Engine { tx, events: ev_rx, handle: Some(handle), live, pair_host, pair_dial }
    }

    /// Host a one-shot pairing service (clone of the transport's factory; works from any thread; dropping the result removes the service).
    pub fn pair_host_fn(&self) -> Option<crate::transport::PairHostFn> { self.pair_host.clone() }
    /// Dial a pairing service by onion id.
    pub fn pair_dial_fn(&self) -> Option<crate::transport::PairDialFn> { self.pair_dial.clone() }

    pub fn add(&self, c: ContactCfg) { let _ = self.tx.send(In::Cmd(Command::Add(c))); }
    pub fn remove(&self, id: [u8; 8]) { let _ = self.tx.send(In::Cmd(Command::Remove(id))); }
    /// Queue a text for the contact. Returns its message id, so the UI can recognise the later `Delivered`/`Unsent` for exactly this
    /// line (the id is made here, on the caller's thread).
    pub fn send(&self, id: [u8; 8], text: Zeroizing<String>) -> proto::MsgId {
        let mid = proto::new_msg_id();
        self.send_with_mid(id, mid, text);
        mid
    }

    /// Like [`send`](Self::send) with an id the caller made: the app writes the text into the encrypted outbox UNDER that id before it hands
    /// the text over, so a later `Delivered`/`Unsent` finds the stored copy too.
    pub fn send_with_mid(&self, id: [u8; 8], mid: proto::MsgId, text: Zeroizing<String>) {
        let _ = self.tx.send(In::Cmd(Command::Send { id, mid, text }));
    }

    /// The UI holds the text of `Event::Message { mid: Some(mid), .. }`: tell the sender so. NEVER call it before the text is safely in
    /// the UI's own state (the sender wipes its copy when it hears this). If the UI is gone (going offline, quitting) nothing is
    /// confirmed, and the sender simply resends later.
    pub fn confirm(&self, id: [u8; 8], mid: proto::MsgId) { let _ = self.tx.send(In::Cmd(Command::Confirm { id, mid })); }

    /// Clean (metadata stripped by allowlist, unknown formats refused), pad to a size bucket and offer a file to a CONNECTED
    /// contact. Returns the cleaning report. Files are never queued: if the contact is offline the engine says so.
    pub fn send_file(&self, id: [u8; 8], raw: &[u8], mode: nerd_chat_strip::Mode) -> Result<Vec<String>, nerd_chat_strip::StripError> {
        let (f, report) = Self::prepare_file(raw, mode)?;
        self.offer_file(id, f);
        Ok(report)
    }

    /// The CPU-heavy part (cleaning, padding, hashing) as a pure function: run it on a worker thread so the UI/panic key stay live.
    pub fn prepare_file(raw: &[u8], mode: nerd_chat_strip::Mode) -> Result<(FileOut, Vec<String>), nerd_chat_strip::StripError> {
        let c = nerd_chat_strip::clean_hooked(raw, mode)?;
        let report = c.report;
        let data = Zeroizing::new(c.data);
        let Some(stream) = file::build_stream(&data) else { return Err(nerd_chat_strip::StripError::TooLarge) };
        let bucket = stream.len() as u32;
        let mut xid = [0u8; 8];
        getrandom::fill(&mut xid).expect("OS RNG unavailable");
        let mode = if mode == nerd_chat_strip::Mode::PlainText { file::MODE_TEXT } else { file::MODE_AUTO };
        Ok((FileOut { xid, bucket, mode, hash: file::hash(&data), padded: Zeroizing::new(stream) }, report))
    }

    pub fn offer_file(&self, id: [u8; 8], f: FileOut) { let _ = self.tx.send(In::Cmd(Command::SendFile { id, file: f })); }

    /// Key rotation: send our proposal (the new onion/auth keys of the pending rotation) to the connected contact.
    pub fn offer_rotation(&self, id: [u8; 8]) { let _ = self.tx.send(In::Cmd(Command::Rotate { id, kind: proto::KIND_ROTATE_OFFER, keys: None })); }
    /// Acknowledge (`KIND_ROTATE_ACK`) or finish (`KIND_ROTATE_DONE`) a rotation by echoing the keys.
    pub fn answer_rotation(&self, id: [u8; 8], kind: u8, onion: [u8; 32], auth: [u8; 32]) {
        let keys = pack(&onion, &auth);
        let _ = self.tx.send(In::Cmd(Command::Rotate { id, kind, keys: Some(keys) }));
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
            // connection threads end on their own after Close; wait (bounded) so their transfer buffers are dropped (zeroized)
            while self.live.load(Ordering::SeqCst) > 0 && Instant::now() < end { thread::sleep(Duration::from_millis(10)); }
        }
    }
}

impl Drop for Engine { fn drop(&mut self) { self.stop(Duration::from_secs(3)); } }

struct Rt {
    secret: Zeroizing<Vec<u8>>,
    peer: Bundle,
    my_onion: [u8; 32],
    /// Our CURRENT (onion, auth) public keys, announced on every connection (see `Up`): lets the peer learn that a rotation finished.
    my_keys: [u8; 64],
    /// While the peer's rotation is unfinished: the peer's OLD address, tried when the new one cannot be reached (e.g. its new
    /// service failed to start in this session), with our client-auth installed for it.
    fallback: Option<Bundle>,
    /// What a retry of the NEW service needs (rotation pending, we host, but ADD_ONION failed): its identity secret, the extra
    /// authorized client keys, the handshake guard shared with the acceptor, and when to try next.
    retry: Option<NextRetry>,
    /// Pending rotation: (onion pub, auth pub, hosted?) of the NEW transport keys; `hosted` = the new service really runs.
    next: Option<([u8; 32], [u8; 32], bool)>,
    we_dial: bool,
    /// Distinguishes this registration from an earlier one with the same id (remove + add): stale Up/DialFailed are ignored.
    epoch: u64,
    conn: Option<(u64, Sender<Out>)>,
    /// Texts not yet confirmed, oldest first (queued while offline AND already written to a connection that may have died).
    unacked: VecDeque<(proto::MsgId, Zeroizing<String>)>,
    /// What the peer on the CURRENT connection understands (reset on every `Up`): until it says so, texts are only held, never written.
    peer_mode: PeerMode,
    /// When the current connection came up (the `caps_wait` clock).
    up_at: Instant,
    /// Ids of texts already handed to the UI (see `MAX_SEEN`) and whether the UI has CONFIRMED them (only then do we confirm repeats).
    seen: VecDeque<(proto::MsgId, bool)>,
    dialing: bool,
    backoff: Duration,
    next_dial: Instant,
    iso: [u8; 16],
    stop: Arc<AtomicBool>,
}

/// What we know about the peer of the current connection.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PeerMode {
    /// No capability frame yet (new peers send it first; an old one never does).
    Unknown,
    /// New peer: texts carry ids and are confirmed; unconfirmed ones are resent.
    Confirms,
    /// v0.1.0-style peer: plain text frames, no confirmation exists, a text written is a text done.
    Legacy,
}

struct NextRetry { secret: Zeroizing<Vec<u8>>, extra: Vec<[u8; 32]>, guard: Arc<Mutex<HandshakeGuard>>, at: Instant }

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
    live: Arc<AtomicUsize>,
}

/// (onion pub | auth pub) as the 64-byte payload of a rotation frame.
fn pack(onion: &[u8; 32], auth: &[u8; 32]) -> [u8; 64] { let mut k = [0u8; 64]; k[..32].copy_from_slice(onion); k[32..].copy_from_slice(auth); k }

fn jitter(d: Duration) -> Duration {
    let mut b = [0u8; 1];
    getrandom::fill(&mut b).expect("OS RNG unavailable");
    d.mul_f64(0.75 + b[0] as f64 / 255.0 * 0.5) // +-25%
}

type Slots = Arc<Mutex<Vec<(u64, Arc<AtomicBool>)>>>;

impl Core {
    fn notice(&self, id: Option<[u8; 8]>, text: impl Into<String>) { let _ = self.ev.send(Event::Notice { id, text: text.into(), alert: false }); }

    fn add(&mut self, cfg: ContactCfg) {
        // a re-add (settings changed) must not silently drop messages queued for the contact
        // (check the key material FIRST: an invalid re-add must not throw the carried texts away)
        let Some(me) = ContactIdentity::from_secret_bytes(&cfg.secret) else { return self.notice(Some(cfg.id), "invalid contact key material") };
        let (carried, carried_seen) = self.rts.get_mut(&cfg.id).map(|r| (std::mem::take(&mut r.unacked), std::mem::take(&mut r.seen))).unwrap_or_default();
        self.remove(cfg.id);
        // Roles from the signed capabilities; the smaller signing key dials only when both (or neither) can host.
        let mut we_dial = we_dial(&me.verifying_key().to_bytes(), &cfg.peer, cfg.our_can_host);
        if !cfg.our_can_host && !cfg.peer.can_host {
            self.notice(Some(cfg.id), "neither you nor this contact can host an onion service: no connection is possible (one of you needs a Tor that allows hosting)");
        }
        let my_onion = me.onion_public();
        let mut my_keys = [0u8; 64];
        my_keys[..32].copy_from_slice(&my_onion);
        my_keys[32..].copy_from_slice(&me.auth_public().to_bytes());
        let stop = Arc::new(AtomicBool::new(false));
        let guard = Arc::new(Mutex::new(HandshakeGuard::new(0)));
        let mut iso = [0u8; 16];
        getrandom::fill(&mut iso).expect("OS RNG unavailable");
        self.next_epoch += 1;
        let epoch = self.next_epoch;
        let mut hosting = false;
        let extra: Vec<[u8; 32]> = cfg.peer_old.map(|(_, a)| vec![a]).unwrap_or_default();
        match self.transport.add_contact(&me, &cfg.peer, &extra, !we_dial) {
            Err(e) if !we_dial => {
                // designated host but hosting failed anyway (the capability bit was wrong or this is transient): FLIP to dialing
                self.notice(Some(cfg.id), format!("cannot host for this contact ({e}): dialing it instead. The contact must host for us: set 'host anyway' (h) on its side, and export a new bundle with --cannot-host if this Tor never hosts"));
                we_dial = true;
                if let Err(e2) = self.transport.add_contact(&me, &cfg.peer, &extra, false) { self.notice(Some(cfg.id), format!("cannot prepare dialing either: {e2}")); }
            }
            Err(e) => self.notice(Some(cfg.id), format!("cannot prepare dialing for this contact: {e}")),
            Ok(Some(rx)) => { hosting = true; self.spawn_acceptor(cfg.id, cfg.secret.clone(), cfg.peer.clone(), rx, guard.clone(), stop.clone(), epoch); }
            Ok(None) => {}
        }
        // The user's explicit choice (never a timer): also host for a contact we would only dial.
        if we_dial && !hosting && cfg.host_anyway && cfg.our_can_host {
            match self.transport.add_contact(&me, &cfg.peer, &extra, true) {
                Ok(Some(rx)) => { hosting = true; self.spawn_acceptor(cfg.id, cfg.secret.clone(), cfg.peer.clone(), rx, guard.clone(), stop.clone(), epoch); self.notice(Some(cfg.id), "hosting for this contact too (your 'host anyway' setting): holders of its bundle can see when you are online"); }
                Ok(None) => {}
                Err(e) => self.notice(Some(cfg.id), format!("'host anyway' failed: {e}")),
            }
        }
        // Pending rotation: while we host for this contact, ALSO host the proposed new service (same acceptor rules), so the
        // contact reaches us whether it already switched or not. Not hosted -> no proposal is ever sent (see Command::Rotate).
        let mut next = None;
        let mut retry = None;
        if let Some(ns) = cfg.next.as_ref().and_then(|n| ContactIdentity::from_secret_bytes(n)) {
            let (no, na) = (ns.onion_public(), ns.auth_public().to_bytes());
            let mut up = !hosting; // a side that does not host needs no second service
            if hosting {
                match self.transport.add_contact(&ns, &cfg.peer, &extra, true) {
                    Ok(Some(rx)) => { up = true; self.spawn_acceptor(cfg.id, cfg.secret.clone(), cfg.peer.clone(), rx, guard.clone(), stop.clone(), epoch); }
                    Ok(None) => {}
                    Err(e) => {
                        self.notice(Some(cfg.id), format!("key rotation: cannot host the new service yet ({e}); nothing is proposed until it runs, retrying"));
                        if let Some(sec) = cfg.next.clone() { retry = Some(NextRetry { secret: sec, extra: extra.clone(), guard: guard.clone(), at: Instant::now() + self.t.max_backoff }); }
                    }
                }
            }
            next = Some((no, na, up));
        }
        // dial fallback to the peer's previous address (only while its rotation is unfinished)
        let mut fallback = None;
        if we_dial {
            if let Some((o, a)) = cfg.peer_old {
                let fb = cfg.peer.clone().with_transport(o, a);
                match self.transport.add_contact(&me, &fb, &[], false) {
                    Ok(_) => fallback = Some(fb),
                    Err(e) => self.notice(Some(cfg.id), format!("no fallback to the contact's old address ({e}); only its new address is tried")),
                }
            }
        }
        self.rts.insert(cfg.id, Rt {
            secret: cfg.secret, peer: cfg.peer, my_onion, my_keys, fallback, retry, next, we_dial, epoch, conn: None, unacked: if carried.is_empty() { cfg.outbox.into_iter().collect() } else { carried }, seen: carried_seen, peer_mode: PeerMode::Unknown, up_at: Instant::now(), dialing: false,
            backoff: self.t.min_backoff, next_dial: Instant::now(), iso, stop,
        });
    }

    fn spawn_acceptor(&self, id: [u8; 8], secret: Zeroizing<Vec<u8>>, peer: Bundle, rx: Receiver<BoxStream>, guard: Arc<Mutex<HandshakeGuard>>, stop: Arc<AtomicBool>, epoch: u64) {
        let (in_tx, gen, started, t, budget, live) = (self.in_tx.clone(), self.gen.clone(), self.epoch, self.t, self.budget.clone(), self.live.clone());
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
                        let (secret, peer, guard, in_tx, gen, slots2, budget, live) = (secret.clone(), peer.clone(), guard.clone(), in_tx.clone(), gen.clone(), slots.clone(), budget.clone(), live.clone());
                        thread::spawn(move || inbound(stream, secret, peer, guard, started, gen, in_tx, id, epoch, t, budget, abort, slots2, slot, live));
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
            if let Some((no, _, _)) = rt.next { self.transport.remove_contact(&no, &rt.peer.onion_pub); }
            if let Some(fb) = &rt.fallback { self.transport.remove_contact(&[0u8; 32], &fb.onion_pub); } // forget our client-auth for the old address
        }
    }

    fn handle(&mut self, m: In) {
        match m {
            In::Cmd(Command::Add(c)) => self.add(c),
            In::Cmd(Command::Remove(id)) => self.remove(id),
            In::Cmd(Command::Send { id, mid, text }) => self.send(id, mid, text),
            In::Cmd(Command::Confirm { id, mid }) => {
                let Some(rt) = self.rts.get_mut(&id) else { return };
                let Some(entry) = rt.seen.iter_mut().find(|(m, _)| *m == mid) else { return };
                entry.1 = true;
                if let Some((_, tx)) = rt.conn.as_ref() { let _ = tx.send(Out::Ack(mid)); }
            }
            In::Cmd(Command::SendFile { id, file }) => match self.rts.get(&id).and_then(|r| r.conn.as_ref()) {
                Some((_, tx)) => { let _ = tx.send(Out::File(file)); }
                None => self.notice(Some(id), "not connected: files are never queued, try again when the contact is online"),
            },
            In::Cmd(Command::FileReply { id, xid, accept }) => { if let Some((_, tx)) = self.rts.get(&id).and_then(|r| r.conn.as_ref()) { let _ = tx.send(Out::Reply { xid, accept }); } }
            In::Cmd(Command::Rotate { id, kind, keys }) => {
                let Some(rt) = self.rts.get(&id) else { return };
                let payload = match (kind, keys, rt.next) {
                    (proto::KIND_ROTATE_OFFER, _, Some((no, na, true))) => Some(pack(&no, &na)),
                    (proto::KIND_ROTATE_OFFER, _, _) => { self.notice(Some(id), "key rotation: the new service is not running, nothing proposed"); None }
                    (_, Some(k), _) => Some(k),
                    _ => None,
                };
                if let Some(k) = payload {
                    match rt.conn.as_ref() {
                        Some((_, tx)) => { let _ = tx.send(Out::Rotate { kind, keys: k }); }
                        None => self.notice(Some(id), "key rotation: no live connection at this moment; the step is repeated automatically when the contact connects"),
                    }
                }
            }
            In::Cmd(Command::Shutdown) => {}
            In::Conn(ConnEvent::Up { id, gen, epoch, tx }) => {
                let Some(rt) = self.rts.get_mut(&id).filter(|r| r.epoch == epoch) else { let _ = tx.send(Out::Close); return };
                let had = rt.conn.is_some();
                if let Some((_, old)) = rt.conn.replace((gen, tx.clone())) { let _ = old.send(Out::Close); }
                rt.backoff = self.t.min_backoff;
                // WE announce what we understand first; texts are written only once we know what the peer understands (`flush`): a
                // peer that never announces (v0.1.0) would silently DROP the new id frames, so it gets plain ones after `caps_wait`
                rt.peer_mode = PeerMode::Unknown;
                rt.up_at = Instant::now();
                let _ = tx.send(Out::Caps(proto::CAP_CONFIRM));
                // announce our current keys on every connection: a peer holding the NEW keys as pending learns the rotation is done
                // even if the explicit DONE died with a replaced connection (it reveals nothing the peer does not already know)
                let _ = tx.send(Out::Rotate { kind: proto::KIND_ROTATE_DONE, keys: rt.my_keys });
                // an unfinished rotation is (re)proposed on EVERY new connection: the ack of the last one may have been lost
                // together with the connection it travelled on (the peer acks again, idempotently)
                if let Some((no, na, true)) = rt.next {
                    let _ = tx.send(Out::Rotate { kind: proto::KIND_ROTATE_OFFER, keys: pack(&no, &na) });
                }
                if !had { let _ = self.ev.send(Event::Connected { id }); }
                else { let _ = self.ev.send(Event::FileCancelled { id }); } // the replaced connection's transfer state is gone
            }
            In::Conn(ConnEvent::Down { id, gen }) => {
                let Some(rt) = self.rts.get_mut(&id) else { return };
                if rt.conn.as_ref().is_some_and(|(g, _)| *g == gen) {
                    rt.conn = None;
                    rt.next_dial = Instant::now() + jitter(self.t.min_backoff);
                    let _ = self.ev.send(Event::Disconnected { id });
                }
            }
            In::Conn(ConnEvent::Text { id, gen, mid, text }) => {
                // a text from a replaced connection is dropped WITHOUT confirmation: the sender resends it on the new one
                if !self.is_current(id, gen) { return; }
                let Some(rt) = self.rts.get_mut(&id) else { return };
                match mid {
                    None => { let _ = self.ev.send(Event::Message { id, mid: None, text }); }
                    Some(m) => match rt.seen.iter().find(|(s, _)| *s == m).map(|(_, confirmed)| *confirmed) {
                        // new: hand it to the UI. The sender hears "received" only when the UI calls `confirm` (it holds the text then)
                        None => {
                            if rt.seen.len() >= MAX_SEEN { rt.seen.pop_front(); }
                            rt.seen.push_back((m, false));
                            let _ = self.ev.send(Event::Message { id, mid: Some(m), text });
                        }
                        // a repeat the UI already confirmed: confirm again (the first confirmation may have been lost with its connection)
                        Some(true) => { if let Some((_, tx)) = rt.conn.as_ref() { let _ = tx.send(Out::Ack(m)); } }
                        // a repeat the UI has not confirmed yet: its `confirm` is on the way and answers on the then-current connection
                        Some(false) => {}
                    },
                }
            }
            In::Conn(ConnEvent::Caps { id, gen, flags }) => {
                if !self.is_current(id, gen) { return; }
                if let Some(rt) = self.rts.get_mut(&id) { rt.peer_mode = if flags & proto::CAP_CONFIRM != 0 { PeerMode::Confirms } else { PeerMode::Legacy }; }
                self.flush(id);
            }
            In::Conn(ConnEvent::Acked { id, mids }) => {
                let Some(rt) = self.rts.get_mut(&id) else { return };
                if rt.peer_mode == PeerMode::Unknown { rt.peer_mode = PeerMode::Confirms; } // it confirms, so it understands ids
                for mid in mids {
                    if let Some(pos) = rt.unacked.iter().position(|(m, _)| *m == mid) {
                        rt.unacked.remove(pos); // dropping the Zeroizing text wipes it
                        let _ = self.ev.send(Event::Delivered { id, mid });
                    } // an id we never sent (or already had confirmed) changes nothing
                }
            }
            In::Conn(ConnEvent::Ev { id, gen, ev }) => { if self.is_current(id, gen) { let _ = self.ev.send(ev); } }
            In::Conn(ConnEvent::Rotate { id, kind, keys }) => {
                // Authentic (it came through the authenticated, signed session) even if that connection was replaced a moment
                // ago: the ack of a rotation commonly races with the peer's reconnect over the new service.
                let Some(rt) = self.rts.get_mut(&id) else { return };
                let (onion, auth): ([u8; 32], [u8; 32]) = (keys[..32].try_into().unwrap(), keys[32..].try_into().unwrap());
                // The peer announces the keys it runs now: when they are the ones we already dial, its rotation is over, so the
                // fallback to its old address (and our client-auth credential for it) goes away without re-publishing anything.
                let fb = if kind == proto::KIND_ROTATE_DONE && (rt.peer.onion_pub, rt.peer.auth_pub) == (onion, auth) { rt.fallback.take() } else { None };
                if let Some(fb) = fb { self.transport.remove_contact(&[0u8; 32], &fb.onion_pub); }
                let _ = self.ev.send(Event::Rotate { id, kind, onion, auth });
            }
            In::Conn(ConnEvent::DialEnded { id, epoch }) => { if let Some(rt) = self.rts.get_mut(&id).filter(|r| r.epoch == epoch) { rt.dialing = false; } }
            In::Conn(ConnEvent::DialFailed { id, epoch }) => {
                if let Some(rt) = self.rts.get_mut(&id).filter(|r| r.epoch == epoch) {
                    rt.backoff = (rt.backoff * 2).min(self.t.max_backoff);
                    rt.next_dial = Instant::now() + jitter(rt.backoff);
                }
            }
        }
    }

    fn is_current(&self, id: [u8; 8], gen: u64) -> bool { self.rts.get(&id).and_then(|r| r.conn.as_ref()).is_some_and(|(g, _)| *g == gen) }

    /// EVERY refusal reports `Event::Unsent { id, mid }`, so the UI never keeps a line "queued" for a text that is not in the outbox.
    fn send(&mut self, id: [u8; 8], mid: proto::MsgId, text: Zeroizing<String>) {
        let unsent = |s: &Self, why: &str| { let _ = s.ev.send(Event::Unsent { id, mid }); s.notice(Some(id), why); };
        if text.is_empty() || text.len() > proto::MAX_TEXT_BYTES { return unsent(self, "message empty or too long (max 32 KiB)"); }
        let full = match self.rts.get(&id) { None => return unsent(self, "unknown contact"), Some(rt) => rt.unacked.len() >= MAX_UNCONFIRMED };
        if full { return unsent(self, "outbox full: this message was NOT sent, wait until the contact has confirmed the earlier ones"); }
        let Some(rt) = self.rts.get_mut(&id) else { return };
        match (&rt.conn, rt.peer_mode) {
            // an old peer cannot confirm: write the plain frame and consider it done (exactly the v0.1.0 behaviour)
            (Some((_, tx)), PeerMode::Legacy) => { let _ = tx.send(Out::TextPlain(text)); let _ = self.ev.send(Event::Delivered { id, mid }); }
            (Some((_, tx)), PeerMode::Confirms) => { rt.unacked.push_back((mid, text.clone())); let _ = tx.send(Out::Text { mid, text }); }
            // capabilities not known yet: hold it, `flush` writes it as soon as they are
            (Some(_), PeerMode::Unknown) => rt.unacked.push_back((mid, text)),
            (None, _) => {
                rt.unacked.push_back((mid, text));
                if rt.we_dial && !rt.dialing { rt.backoff = self.t.min_backoff; rt.next_dial = Instant::now(); }
            }
        }
    }

    /// Write what is held, now that we know what the peer understands: every unconfirmed text again (new peer; it drops repeats by id
    /// and confirms them again), or, for an old peer, once as plain frames and then forget it (reported as `Delivered`: handed over).
    fn flush(&mut self, id: [u8; 8]) {
        let Some(rt) = self.rts.get_mut(&id) else { return };
        let Some((_, tx)) = rt.conn.as_ref() else { return };
        match rt.peer_mode {
            PeerMode::Unknown => {}
            PeerMode::Confirms => for (mid, text) in &rt.unacked { let _ = tx.send(Out::Text { mid: *mid, text: text.clone() }); },
            PeerMode::Legacy => while let Some((mid, text)) = rt.unacked.pop_front() {
                let _ = tx.send(Out::TextPlain(text));
                let _ = self.ev.send(Event::Delivered { id, mid });
            },
        }
    }

    /// Retry hosting the NEW service of a pending rotation (a transient tor error must not leave the rotation stuck).
    fn retry_next_services(&mut self, now: Instant) {
        let ids: Vec<[u8; 8]> = self.rts.iter().filter(|(_, r)| r.retry.as_ref().is_some_and(|x| now >= x.at)).map(|(i, _)| *i).collect();
        for id in ids {
            let (secret, extra, guard, peer, stop, epoch, rsecret) = {
                let rt = self.rts.get(&id).expect("exists");
                let r = rt.retry.as_ref().expect("filtered");
                (r.secret.clone(), r.extra.clone(), r.guard.clone(), rt.peer.clone(), rt.stop.clone(), rt.epoch, rt.secret.clone())
            };
            let Some(ns) = ContactIdentity::from_secret_bytes(&secret) else { if let Some(rt) = self.rts.get_mut(&id) { rt.retry = None; } continue };
            match self.transport.add_contact(&ns, &peer, &extra, true) {
                Ok(Some(rx)) => {
                    self.spawn_acceptor(id, rsecret, peer, rx, guard, stop, epoch);
                    let rt = self.rts.get_mut(&id).expect("exists");
                    rt.retry = None;
                    if let Some(n) = rt.next.as_mut() { n.2 = true; }
                    // propose it right away if the contact is connected (otherwise it is proposed on the next connection)
                    if let (Some((no, na, true)), Some((_, tx))) = (rt.next, rt.conn.as_ref()) {
                        let _ = tx.send(Out::Rotate { kind: proto::KIND_ROTATE_OFFER, keys: pack(&no, &na) });
                    }
                    self.notice(Some(id), "key rotation: the new onion service is running now");
                }
                Err(e) if e.contains("unusable state") => {
                    // a broken control connection never heals by retrying (and healing would drop every service): say so
                    if let Some(rt) = self.rts.get_mut(&id) { rt.retry = None; }
                    self.notice(Some(id), "key rotation: the control connection to Tor is broken; go offline and online again to finish it");
                }
                _ => { if let Some(x) = self.rts.get_mut(&id).and_then(|r| r.retry.as_mut()) { x.at = now + self.t.max_backoff; } }
            }
        }
    }

    fn tick(&mut self) {
        let now = Instant::now();
        self.retry_next_services(now);
        // a peer that has not announced itself within `caps_wait` is an old (v0.1.0) peer
        let silent: Vec<[u8; 8]> = self.rts.iter().filter(|(_, r)| r.conn.is_some() && r.peer_mode == PeerMode::Unknown && now.duration_since(r.up_at) >= self.t.caps_wait).map(|(i, _)| *i).collect();
        for id in silent {
            if let Some(rt) = self.rts.get_mut(&id) { rt.peer_mode = PeerMode::Legacy; }
            self.flush(id);
        }
        let ids: Vec<[u8; 8]> = self.rts.iter().filter(|(_, r)| r.we_dial && r.conn.is_none() && !r.dialing && now >= r.next_dial).map(|(i, _)| *i).collect();
        for id in ids {
            let rt = self.rts.get_mut(&id).expect("exists");
            rt.dialing = true;
            let (dial, secret, peer, fallback, iso, in_tx, gen, epoch, t) = (self.dial.clone(), rt.secret.clone(), rt.peer.clone(), rt.fallback.clone(), rt.iso, self.in_tx.clone(), self.gen.clone(), rt.epoch, self.t);
            let live = self.live.clone();
            thread::spawn(move || outbound(dial, secret, peer, fallback, iso, in_tx, gen, id, epoch, t, live));
        }
    }

    fn shutdown(&mut self) {
        let ids: Vec<_> = self.rts.keys().copied().collect();
        for id in ids { self.remove(id); }
    }
}

#[allow(clippy::too_many_arguments)]
fn inbound(mut stream: BoxStream, secret: Zeroizing<Vec<u8>>, peer: Bundle, guard: Arc<Mutex<HandshakeGuard>>, started: Instant, gen: Arc<AtomicU64>,
           in_tx: Sender<In>, id: [u8; 8], epoch: u64, t: Timing, budget: Arc<Budget>, abort: Arc<AtomicBool>, slots: Slots, slot: u64, live: Arc<AtomicUsize>) {
    let release = |slots: &Slots| slots.lock().unwrap().retain(|(s, _)| *s != slot);
    let Some(me) = ContactIdentity::from_secret_bytes(&secret) else { return release(&slots) };
    let r = {
        let mut ds = DeadlineStream { s: &mut stream, end: Instant::now() + t.handshake, abort };
        link::accept_shared(&mut ds, &me, &peer, &guard, started.elapsed().as_secs(), &|| budget.take())
    };
    release(&slots);
    if let Ok((sess, _first)) = r {
        let _live = LiveGuard::new(&live);
        let g = gen.fetch_add(1, Ordering::SeqCst) + 1;
        let (otx, orx) = channel();
        if in_tx.send(In::Conn(ConnEvent::Up { id, gen: g, epoch, tx: otx })).is_err() { return; }
        conn::run(stream, sess, me, orx, in_tx, id, g, t);
    }
}

#[allow(clippy::too_many_arguments)]
fn outbound(dial: DialFn, secret: Zeroizing<Vec<u8>>, peer: Bundle, fallback: Option<Bundle>, iso: [u8; 16], in_tx: Sender<In>, gen: Arc<AtomicU64>, id: [u8; 8], epoch: u64, t: Timing, live: Arc<AtomicUsize>) {
    outbound_inner(dial, secret, peer, fallback, iso, &in_tx, gen, id, epoch, t, live);
    let _ = in_tx.send(In::Conn(ConnEvent::DialEnded { id, epoch }));
}

#[allow(clippy::too_many_arguments)]
fn outbound_inner(dial: DialFn, secret: Zeroizing<Vec<u8>>, peer: Bundle, fallback: Option<Bundle>, iso: [u8; 16], in_tx: &Sender<In>, gen: Arc<AtomicU64>, id: [u8; 8], epoch: u64, t: Timing, live: Arc<AtomicUsize>) {
    let in_tx = in_tx.clone();
    let fail = |in_tx: &Sender<In>| { let _ = in_tx.send(In::Conn(ConnEvent::DialFailed { id, epoch })); };
    let Some(me) = ContactIdentity::from_secret_bytes(&secret) else { return fail(&in_tx) };
    let mut stream = match dial(&peer, &iso) {
        Ok(s) => s,
        Err(_) => match fallback.as_ref().map(|fb| dial(fb, &iso)) { Some(Ok(s)) => s, _ => return fail(&in_tx) },
    };
    let r = {
        let mut ds = DeadlineStream { s: &mut stream, end: Instant::now() + t.handshake, abort: Arc::new(AtomicBool::new(false)) };
        link::dial(&mut ds, &me, &peer, &proto::keepalive())
    };
    let Ok(sess) = r else { return fail(&in_tx) };
    let _live = LiveGuard::new(&live);
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
                 min_backoff: Duration::from_millis(30), max_backoff: Duration::from_millis(200), handshake: Duration::from_secs(5), handshakes_per_sec: 1000.0,
                 ack_delay_min: Duration::from_millis(20), ack_delay_max: Duration::from_millis(40), caps_wait: Duration::from_millis(400) }
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
            if let Ok(ev) = e.events.recv_timeout(Duration::from_millis(50)) { if f(&ev) { return true } }
        }
        false
    }

    fn connected(e: &Engine) -> bool { wait(e, |ev| matches!(ev, Event::Connected { .. })) }
    /// Wait for a text AND play the UI's part: confirm it to the sender once it is held (see `Engine::confirm`).
    fn got(e: &Engine, want: &str) -> bool {
        wait(e, |ev| match ev {
            Event::Message { id, mid, text } if &***text == want => { if let Some(m) = mid { e.confirm(*id, *m); } true }
            _ => false,
        })
    }
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
        for n in 1..=3 { assert!(wait(&ed, |e| matches!(e, Event::Delivered { .. })), "the sender must be told that text {n} was confirmed"); }
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
        for i in 0..(MAX_UNCONFIRMED + 5) { say(&ed, ID, &format!("q{i}")); }
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
                let _ = s.write_all(&vec![0xAB; nerd_chat_core::session::MSG1_LEN]);
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
        fn add_contact(&mut self, me: &ContactIdentity, peer: &Bundle, extra: &[[u8; 32]], listen: bool) -> Result<Option<Receiver<BoxStream>>, String> {
            if listen { Err("hosting refused by this tor".into()) } else { self.0.add_contact(me, peer, extra, false) }
        }
        fn remove_contact(&mut self, a: &[u8; 32], b: &[u8; 32]) { self.0.remove_contact(a, b) }
        fn dial_fn(&self) -> DialFn { self.0.dial_fn() }
    }

    fn start_with(t: Box<dyn Transport>, me: &ContactIdentity, peer: &Bundle) -> Engine {
        Engine::start(t, vec![ContactCfg::new(ID, me, peer.clone())], fast())
    }

    fn start_caps(t: Box<dyn Transport>, me: &ContactIdentity, peer: &Bundle, our_can_host: bool, host_anyway: bool) -> Engine {
        Engine::start(t, vec![ContactCfg::new(ID, me, peer.clone()).with_caps(our_can_host, host_anyway)], fast())
    }

    /// The motivating case: one side's Tor cannot host (a Tails). Its bundle says so; the roles follow the capability, the
    /// side that can host hosts, and NOBODY publishes anything speculative.
    #[test]
    fn key_rotation_keeps_the_contact_reachable_and_retires_the_old_service() {
        let net = MemNet::new();
        let ((l, lb), (d, db)) = ordered();                          // l hosts, d dials
        let t = ContactIdentity::fresh_transport_secret();
        let l2 = l.with_transport_secret(&t).unwrap();
        let lb2 = Bundle::from_identity(&l2);
        let ea = Engine::start(Box::new(net.transport()), vec![ContactCfg::new(ID, &l, db.clone()).with_rotation(&l, Some(&t), None)], fast());
        let eb = start(&net, &d, &lb, ID);
        assert!(connected(&ea) && connected(&eb));
        assert!(net.is_hosted(&lb.onion_pub) && net.is_hosted(&lb2.onion_pub), "old AND new service run while the rotation is pending");
        ea.offer_rotation(ID);
        let mut keys = None;
        assert!(wait(&eb, |e| match e { Event::Rotate { kind, onion, auth, .. } if *kind == proto::KIND_ROTATE_OFFER => { keys = Some((*onion, *auth)); true } _ => false }));
        assert_eq!(keys, Some((lb2.onion_pub, lb2.auth_pub)));
        // the dialer switches (ack first: the re-add closes the connection), keeping the old keys for the host's old auth
        eb.answer_rotation(ID, proto::KIND_ROTATE_ACK, lb2.onion_pub, lb2.auth_pub);
        eb.add(ContactCfg::new(ID, &d, lb.clone().with_transport(lb2.onion_pub, lb2.auth_pub)).with_rotation(&d, None, Some((lb.onion_pub, lb.auth_pub))));
        // The first ack may die with the replaced connection; the host re-proposes on the new one and the dialer acks again.
        let mut acked = false;
        for _ in 0..400 {
            while let Ok(e) = ea.events.try_recv() { if matches!(e, Event::Rotate { kind: proto::KIND_ROTATE_ACK, .. }) { acked = true; } }
            while let Ok(e) = eb.events.try_recv() { if let Event::Rotate { kind: proto::KIND_ROTATE_OFFER, onion, auth, .. } = e { eb.answer_rotation(ID, proto::KIND_ROTATE_ACK, onion, auth); } }
            if acked { break; }
            thread::sleep(Duration::from_millis(25));
        }
        assert!(acked, "the host never received an acknowledgement");
        // the host commits: only the new service remains
        ea.answer_rotation(ID, proto::KIND_ROTATE_DONE, lb2.onion_pub, lb2.auth_pub);
        ea.add(ContactCfg::new(ID, &l2, db.clone()));
        assert!(wait(&ea, |e| matches!(e, Event::Connected { .. })) && connected(&eb), "must reconnect over the NEW service");
        assert!(!net.is_hosted(&lb.onion_pub), "the old onion service must be gone");
        assert!(net.is_hosted(&lb2.onion_pub));
        say(&ea, ID, "after rotation");
        assert!(got(&eb, "after rotation"));
        // a rotation that cannot host its new service never proposes it
    }

    #[test]
    fn a_switched_dialer_falls_back_to_the_old_address_while_the_new_one_is_not_hosted() {
        let net = MemNet::new();
        let ((l, lb), (d, db)) = ordered();                          // l hosts (old address only: its new service never started)
        let fresh = ContactIdentity::generate();
        let new_peer = lb.clone().with_transport(fresh.onion_public(), fresh.auth_public().to_bytes());
        let el = start(&net, &l, &db, ID);
        let ed = Engine::start(Box::new(net.transport()), vec![ContactCfg::new(ID, &d, new_peer).with_rotation(&d, None, Some((lb.onion_pub, lb.auth_pub)))], fast());
        assert!(connected(&el) && connected(&ed), "the dialer must reach the old address when the new one is down");
        say(&ed, ID, "via fallback");
        assert!(got(&el, "via fallback"));
        ed.shutdown(); el.shutdown();
    }

    /// Refuses the first attempt to host one particular onion key (a transient ADD_ONION failure), then works.
    struct FailNewOnion { inner: crate::transport::MemTransport, onion: [u8; 32], failed: bool, hosted_now: Arc<AtomicBool> }
    impl Transport for FailNewOnion {
        fn add_contact(&mut self, me: &ContactIdentity, peer: &Bundle, extra: &[[u8; 32]], listen: bool) -> Result<Option<Receiver<BoxStream>>, String> {
            if listen && me.onion_public() == self.onion && !self.failed { self.failed = true; return Err("transient ADD_ONION failure".into()); }
            let r = self.inner.add_contact(me, peer, extra, listen);
            if listen && me.onion_public() == self.onion && r.is_ok() { self.hosted_now.store(true, Ordering::SeqCst); }
            r
        }
        fn remove_contact(&mut self, a: &[u8; 32], b: &[u8; 32]) { self.inner.remove_contact(a, b) }
        fn dial_fn(&self) -> DialFn { self.inner.dial_fn() }
    }

    #[test]
    fn a_new_service_that_failed_to_start_is_retried_and_only_then_proposed() {
        let net = MemNet::new();
        let ((l, lb), (d, db)) = ordered();
        let t = ContactIdentity::fresh_transport_secret();
        let lb2 = Bundle::from_identity(&l.with_transport_secret(&t).unwrap());
        let hosted_now = Arc::new(AtomicBool::new(false));
        let tr = FailNewOnion { inner: net.transport(), onion: lb2.onion_pub, failed: false, hosted_now: hosted_now.clone() };
        let ea = Engine::start(Box::new(tr), vec![ContactCfg::new(ID, &l, db.clone()).with_rotation(&l, Some(&t), None)], fast());
        let eb = start(&net, &d, &lb, ID);
        assert!(connected(&ea) && connected(&eb));
        // while the new service is down nothing may be proposed; once the retry succeeds the offer arrives by itself
        let mut offered = false;
        for _ in 0..200 {
            while let Ok(e) = eb.events.try_recv() { if let Event::Rotate { kind: proto::KIND_ROTATE_OFFER, onion, .. } = e {
                assert_eq!(onion, lb2.onion_pub);
                assert!(hosted_now.load(Ordering::SeqCst), "the new address was proposed BEFORE its service ran");
                offered = true;
            } }
            if offered { break; }
            thread::sleep(Duration::from_millis(25));
        }
        assert!(offered, "the retried new service was never proposed");
        assert!(net.is_hosted(&lb.onion_pub) && net.is_hosted(&lb2.onion_pub));
    }

    /// Records which (peer) onion keys the engine forgot client-auth for.
    struct Recorder { inner: crate::transport::MemTransport, forgotten: Arc<Mutex<Vec<[u8; 32]>>> }
    impl Transport for Recorder {
        fn add_contact(&mut self, me: &ContactIdentity, peer: &Bundle, extra: &[[u8; 32]], listen: bool) -> Result<Option<Receiver<BoxStream>>, String> { self.inner.add_contact(me, peer, extra, listen) }
        fn remove_contact(&mut self, a: &[u8; 32], b: &[u8; 32]) { self.forgotten.lock().unwrap().push(*b); self.inner.remove_contact(a, b) }
        fn dial_fn(&self) -> DialFn { self.inner.dial_fn() }
    }

    #[test]
    fn the_fallback_to_the_old_address_ends_when_the_peer_announces_its_new_keys() {
        let net = MemNet::new();
        let ((l, lb), (d, db)) = ordered();
        let t = ContactIdentity::fresh_transport_secret();
        let l2 = l.with_transport_secret(&t).unwrap();
        let lb2 = Bundle::from_identity(&l2);
        let el = start(&net, &l2, &db, ID);                                  // the host runs ONLY its new keys/address
        let forgotten = Arc::new(Mutex::new(Vec::new()));
        let tr = Recorder { inner: net.transport(), forgotten: forgotten.clone() };
        let ed = Engine::start(Box::new(tr), vec![ContactCfg::new(ID, &d, lb2.clone()).with_rotation(&d, None, Some((lb.onion_pub, lb.auth_pub)))], fast());
        assert!(connected(&el) && connected(&ed));
        // the host's announcement of its current keys on Up == the keys we dial: the old address and our credential for it must go
        let end = Instant::now() + Duration::from_secs(5);
        while Instant::now() < end && !forgotten.lock().unwrap().contains(&lb.onion_pub) { thread::sleep(Duration::from_millis(25)); }
        assert!(forgotten.lock().unwrap().contains(&lb.onion_pub), "client-auth for the retired address was never forgotten");
        assert!(!net.is_hosted(&lb.onion_pub), "nothing is hosted for the old address");
    }

    #[test]
    fn capabilities_decide_the_roles_without_any_lazy_publishing() {
        let net = MemNet::new();
        let ((l, lb), (d, db)) = ordered();                          // by KEY l would host and d would dial
        let lb_cannot = lb.clone().with_can_host(false);
        let el = start_caps(Box::new(NoHost(net.transport())), &l, &db, false, false);
        let ed = start(&net, &d, &lb_cannot, ID);
        assert!(connected(&el) && connected(&ed), "no connection although one side cannot host");
        assert!(net.is_hosted(&db.onion_pub), "the side that CAN host hosts");
        assert!(!net.is_hosted(&lb.onion_pub), "the side that cannot host publishes nothing");
        say(&el, ID, "from the side that cannot host");
        say(&ed, ID, "from the side that hosts");
        assert!(got(&ed, "from the side that cannot host"));
        assert!(got(&el, "from the side that hosts"));
        ed.shutdown();
        assert!(wait(&el, |e| matches!(e, Event::Disconnected { .. })));
        let ed2 = start(&net, &d, &lb_cannot, ID);
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

    /// Option C: a wrong capability bit (it says "can host", the Tor refuses) makes the peer flip to dialing. Nothing is published
    /// speculatively; only the USER's explicit `host_anyway` makes the other side host, at once, and then the chat works.
    #[test]
    fn host_anyway_is_an_explicit_choice_not_a_timer() {
        let net = MemNet::new();
        let ((l, lb), (d, db)) = ordered();
        let el = start_caps(Box::new(NoHost(net.transport())), &l, &db, true, false);      // bundle claims can_host = true, tor refuses
        let ed = start(&net, &d, &lb, ID);                                                  // default: no host_anyway
        assert!(!wait_for(&ed, Duration::from_millis(1500), |e| matches!(e, Event::Connected { .. })), "must not connect without a host");
        assert!(!net.is_hosted(&db.onion_pub), "no speculative publishing, however long the contact stays unreachable");
        assert!(wait(&el, |e| matches!(e, Event::Notice { text, .. } if text.contains("cannot host for this contact"))));
        drop(ed);
        let ed2 = start_caps(Box::new(net.transport()), &d, &lb, true, true);               // the user chose 'host anyway'
        assert!(wait(&ed2, |e| matches!(e, Event::Notice { text, .. } if text.contains("host anyway"))));
        assert!(connected(&el) && connected(&ed2), "host anyway must make the flipped peer reachable");
        assert!(net.is_hosted(&db.onion_pub));
        say(&el, ID, "ping"); assert!(got(&ed2, "ping"));
    }

    /// Refuses the FIRST hosting attempt only (e.g. a transient onion-address collision).
    struct FailOnce(crate::transport::MemTransport, bool);
    impl Transport for FailOnce {
        fn add_contact(&mut self, me: &ContactIdentity, peer: &Bundle, extra: &[[u8; 32]], listen: bool) -> Result<Option<Receiver<BoxStream>>, String> {
            if listen && !self.1 { self.1 = true; return Err("transient failure".into()); }
            self.0.add_contact(me, peer, extra, listen)
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
        std::thread::sleep(Duration::from_millis(1500));
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
        v.extend(std::iter::repeat_n(0x11u8, scan));
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

    #[test]
    fn texts_kept_from_an_earlier_run_are_delivered_in_order_and_confirmed_under_their_own_ids() {
        let net = MemNet::new();
        let ((l, lb), (d, db)) = ordered();
        let (m1, m2) = ([0x11u8; 8], [0x22u8; 8]);
        // the sender "restarts" with two unconfirmed texts from the encrypted outbox; the contact is not even online yet
        let seeded = ContactCfg::new(ID, &d, lb.clone()).with_outbox(vec![(m1, Zeroizing::new("kept one".into())), (m2, Zeroizing::new("kept two".into()))]);
        let ed = Engine::start(Box::new(net.transport()), vec![seeded], fast());
        let el = start(&net, &l, &db, ID);
        assert!(connected(&el) && connected(&ed));
        assert!(got(&el, "kept one") && got(&el, "kept two"), "both arrive, in order, as soon as the contact is there");
        let mut delivered = vec![];
        assert!(wait(&ed, |e| if let Event::Delivered { mid, .. } = e { delivered.push(*mid); delivered.len() == 2 } else { false }), "the sender hears about both");
        assert_eq!(delivered, vec![m1, m2], "confirmed under the ids the outbox stored, so the stored copies can be removed");
    }

    #[test]
    fn a_seeded_outbox_is_bounded_and_invalid_texts_are_dropped() {
        let ids: Vec<(proto::MsgId, Zeroizing<String>)> = (0..MAX_UNCONFIRMED + 7).map(|i| ([i as u8; 8], Zeroizing::new(format!("t{i}")))).collect();
        let (a, _) = ordered();
        let cfg = ContactCfg::new(ID, &a.0, a.1.clone()).with_outbox(ids);
        assert_eq!(cfg.outbox.len(), MAX_UNCONFIRMED, "never more than the engine would hold");
        let cfg = ContactCfg::new(ID, &a.0, a.1.clone()).with_outbox(vec![([1; 8], Zeroizing::new(String::new())), ([2; 8], Zeroizing::new("x".repeat(proto::MAX_TEXT_BYTES + 1))), ([3; 8], Zeroizing::new("ok".into()))]);
        assert_eq!(cfg.outbox.len(), 1, "empty and over-long texts are dropped");
    }

    #[test]
    fn a_caller_chosen_message_id_is_the_one_in_the_events() {
        let (el, ed) = pair();
        let mid = [0x5Au8; 8];
        ed.send_with_mid(ID, mid, Zeroizing::new("with my id".into()));
        assert!(got(&el, "with my id"));
        assert!(wait(&ed, |e| matches!(e, Event::Delivered { mid: m, .. } if *m == mid)));
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
        let report = ed.send_file(ID, &raw, nerd_chat_strip::Mode::Auto).unwrap();
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
        ed.send_file(ID, &jpeg(1000), nerd_chat_strip::Mode::Auto).unwrap();
        let (xid, _) = offer_xid(&el);
        el.reply_file(ID, xid, false);
        assert!(wait(&ed, |ev| matches!(ev, Event::Notice { text, .. } if text.contains("declined"))));
        assert!(!wait_for(&el, Duration::from_millis(500), |ev| matches!(ev, Event::File { .. })));
        assert!(ed.send_file(ID, b"%PDF-1.7\x00\x01", nerd_chat_strip::Mode::Auto).is_err(), "unknown format must be refused");
        assert!(ed.send_file(ID, &[], nerd_chat_strip::Mode::Auto).is_err());
    }

    #[test]
    fn files_are_never_queued_for_offline_contacts() {
        let net = MemNet::new();
        let ((_l, lb), (d, _db)) = ordered();
        let ed = start(&net, &d, &lb, ID);
        ed.send_file(ID, &jpeg(100), nerd_chat_strip::Mode::Auto).unwrap();
        assert!(wait(&ed, |ev| matches!(ev, Event::Notice { text, .. } if text.contains("never queued"))));
    }

    /// The next application frame from the engine, skipping keepalives and the key announcements sent on every connection.
    fn raw_next(s: &mut crate::transport::BoxStream, sess: &mut nerd_chat_core::session::Session, me: &ContactIdentity) -> Vec<u8> {
        use std::io::Read;
        for _ in 0..100 {
            let mut cell = vec![0u8; nerd_chat_core::session::WIRE_CELL_LEN];
            s.read_exact(&mut cell).unwrap();
            let body = sess.recv(me, &cell).unwrap().body;
            let k = body[0];
            if k == proto::KIND_KEEPALIVE || k == proto::KIND_CAPS || (proto::KIND_ROTATE_OFFER..=proto::KIND_ROTATE_DONE).contains(&k) { continue; }
            return body.to_vec();
        }
        panic!("no application frame");
    }

    fn raw_connect(net: &MemNet, lb: &Bundle, d: &ContactIdentity) -> (crate::transport::BoxStream, nerd_chat_core::session::Session) {
        let dial = net.transport().dial_fn();
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            match dial(lb, &[1; 16]) {
                Ok(mut s) => {
                    s.set_timeout(Some(Duration::from_secs(5))).unwrap();
                    let mut sess = link::dial(&mut s, d, lb, &proto::keepalive()).unwrap();
                    raw_send(&mut s, &mut sess, d, &proto::encode_caps(proto::CAP_CONFIRM)); // a NEW peer announces itself first
                    return (s, sess);
                }
                Err(_) if Instant::now() < end => std::thread::sleep(Duration::from_millis(20)),
                Err(e) => panic!("{e}"),
            }
        }
    }

    #[test]
    fn an_unconfirmed_text_is_resent_with_the_same_id_until_the_contact_confirms_it() {
        let net = MemNet::new();
        let ((l, lb), (d, db)) = ordered();
        let el = start(&net, &l, &db, ID);
        let (mut s1, mut sess1) = raw_connect(&net, &lb, &d);
        assert!(connected(&el));
        say(&el, ID, "precious");
        let f = raw_next(&mut s1, &mut sess1, &d);
        assert_eq!(f[0], proto::KIND_TEXT_ID_FINAL, "a short text with its id is ONE cell");
        let mid: proto::MsgId = f[1..9].try_into().unwrap();
        assert_eq!(&f[9..], b"precious");
        drop((s1, sess1)); // the connection dies without a confirmation
        let (mut s2, mut sess2) = raw_connect(&net, &lb, &d);
        let f = raw_next(&mut s2, &mut sess2, &d);
        assert_eq!((f[0], &f[1..9], &f[9..]), (proto::KIND_TEXT_ID_FINAL, &mid[..], &b"precious"[..]), "the SAME id again");
        assert!(!wait_for(&el, Duration::from_millis(300), |e| matches!(e, Event::Delivered { .. })), "no confirmation yet");
        // an ack for an id we never sent changes nothing
        raw_send(&mut s2, &mut sess2, &d, &proto::encode_msg_acks(&[[0xEE; 8]]).unwrap());
        assert!(!wait_for(&el, Duration::from_millis(300), |e| matches!(e, Event::Delivered { .. })));
        raw_send(&mut s2, &mut sess2, &d, &proto::encode_msg_acks(&[[0xEE; 8], mid]).unwrap()); // one frame may confirm several ids
        assert!(wait(&el, |e| matches!(e, Event::Delivered { mid: m, .. } if *m == mid)), "Delivered names the text");
        // once confirmed it is never sent again
        drop((s2, sess2));
        let (mut s3, mut sess3) = raw_connect(&net, &lb, &d);
        assert!(connected(&el));
        say(&el, ID, "next");
        let f = raw_next(&mut s3, &mut sess3, &d);
        assert_eq!(f[0], proto::KIND_TEXT_ID_FINAL);
        assert_ne!(&f[1..9], &mid[..]);
        assert_eq!(&f[9..], b"next", "the confirmed text is not sent again");
    }

    fn id_text(mid: &proto::MsgId, t: &str) -> Vec<u8> { [&[proto::KIND_TEXT_ID_FINAL][..], &mid[..], t.as_bytes()].concat() }

    /// Read frames until a confirmation arrives; the ids it names.
    fn raw_acks(s: &mut crate::transport::BoxStream, sess: &mut nerd_chat_core::session::Session, me: &ContactIdentity) -> Vec<proto::MsgId> {
        loop { let f = raw_next(s, sess, me); if f[0] == proto::KIND_MSG_ACK { return proto::parse_msg_acks(&f).expect("well-formed ack"); } }
    }

    #[test]
    fn a_resent_text_is_shown_once_and_confirmed_only_after_the_ui_confirmed_it() {
        let (el, mut s, mut sess, me) = raw_peer();
        let mid = [9u8; 8];
        raw_send(&mut s, &mut sess, &me, &id_text(&mid, "hello"));
        let mut got_mid = None;
        assert!(wait(&el, |e| matches!(e, Event::Message { mid: Some(m), text, .. } if { got_mid = Some(*m); &***text == "hello" })));
        assert_eq!(got_mid, Some(mid));
        // the UI has not confirmed yet: a repeat is neither shown again nor confirmed (the UI's own confirmation is on its way)
        raw_send(&mut s, &mut sess, &me, &id_text(&mid, "hello"));
        assert!(!wait_for(&el, Duration::from_millis(300), |e| matches!(e, Event::Message { .. })), "a resent text must not appear twice");
        el.confirm(ID, mid);
        assert_eq!(raw_acks(&mut s, &mut sess, &me), vec![mid]);
        // a repeat AFTER the UI confirmed is confirmed again at once (the first confirmation may have been lost)
        raw_send(&mut s, &mut sess, &me, &id_text(&mid, "hello"));
        assert_eq!(raw_acks(&mut s, &mut sess, &me), vec![mid]);
        assert!(!wait_for(&el, Duration::from_millis(200), |e| matches!(e, Event::Message { .. })));
        // a different id is a different text
        raw_send(&mut s, &mut sess, &me, &id_text(&[8; 8], "hello"));
        assert!(got(&el, "hello"));
    }

    /// Review 24 / item 2: "confirmed" must mean the UI HAS the text. A UI that goes away without reading its events confirms nothing.
    #[test]
    fn a_text_the_ui_never_saw_is_not_confirmed_and_arrives_after_the_restart() {
        let net = MemNet::new();
        let ((l, lb), (d, db)) = ordered();
        let (el, ed) = (start(&net, &l, &db, ID), start(&net, &d, &lb, ID));
        assert!(connected(&el) && connected(&ed));
        say(&ed, ID, "unseen");
        std::thread::sleep(Duration::from_millis(300)); // the text sits in el's event channel, unread
        drop(el);                                         // the UI goes offline/quits without reading it
        assert!(!wait_for(&ed, Duration::from_millis(500), |e| matches!(e, Event::Delivered { .. })), "never confirmed: nobody looked at it");
        let el = start(&net, &l, &db, ID);
        assert!(got(&el, "unseen"), "resent and shown after the restart");
        assert!(wait(&ed, |e| matches!(e, Event::Delivered { .. })));
    }

    /// A text that was read on a connection that has since been replaced is dropped: not shown, not remembered, not confirmed there
    /// (the sender resends it on the current connection, where it is shown once).
    #[test]
    fn a_text_read_on_a_replaced_connection_is_dropped_so_the_resend_is_shown_once() {
        let (el, mut s, mut sess, me) = raw_peer();
        let mid = [4u8; 8];
        el.tx.send(In::Conn(ConnEvent::Text { id: ID, gen: u64::MAX, mid: Some(mid), text: Zeroizing::new("from a dead connection".into()) })).unwrap();
        assert!(!wait_for(&el, Duration::from_millis(300), |e| matches!(e, Event::Message { .. })), "stale generation: not shown");
        raw_send(&mut s, &mut sess, &me, &id_text(&mid, "from the live one"));
        assert!(got(&el, "from the live one"), "the same id on the live connection is NOT treated as a repeat");
        assert_eq!(raw_acks(&mut s, &mut sess, &me), vec![mid], "confirmed on the live connection only");
    }

    #[test]
    fn a_peer_without_ids_still_delivers_and_a_malformed_confirmation_cuts_the_connection() {
        let (el, mut s, mut sess, me) = raw_peer();
        raw_send(&mut s, &mut sess, &me, &[&[proto::KIND_TEXT_FINAL][..], b"old style"].concat());
        raw_send(&mut s, &mut sess, &me, &[&[proto::KIND_TEXT_FINAL][..], b"old style"].concat());
        assert!(got(&el, "old style") && got(&el, "old style"), "no id: nothing to deduplicate by, nothing to confirm");
        raw_send(&mut s, &mut sess, &me, &[proto::KIND_MSG_ACK, 1, 2, 3]);
        assert!(wait(&el, |e| matches!(e, Event::Disconnected { .. })), "a malformed ack is a protocol violation");
        let (el, mut s, mut sess, me) = raw_peer();
        raw_send(&mut s, &mut sess, &me, &[proto::KIND_MSG_ACK]);
        assert!(wait(&el, |e| matches!(e, Event::Disconnected { .. })), "an ack without any id too");
    }

    /// The next application frame, or `None` if nothing (but keepalives and announcements) arrives within `wait`.
    fn raw_try_next(s: &mut crate::transport::BoxStream, sess: &mut nerd_chat_core::session::Session, me: &ContactIdentity, wait: Duration) -> Option<Vec<u8>> {
        use std::io::Read;
        let end = Instant::now() + wait;
        s.set_timeout(Some(Duration::from_millis(50))).unwrap();
        while Instant::now() < end {
            let mut cell = vec![0u8; nerd_chat_core::session::WIRE_CELL_LEN];
            if s.read_exact(&mut cell).is_err() { continue; }
            let body = sess.recv(me, &cell).unwrap().body;
            let k = body[0];
            if k == proto::KIND_KEEPALIVE || k == proto::KIND_CAPS || (proto::KIND_ROTATE_OFFER..=proto::KIND_ROTATE_DONE).contains(&k) { continue; }
            return Some(body.to_vec());
        }
        None
    }

    /// A raw peer that does NOT announce capabilities: exactly what a v0.1.0 peer looks like on the wire.
    fn raw_legacy_connect(net: &MemNet, lb: &Bundle, d: &ContactIdentity) -> (crate::transport::BoxStream, nerd_chat_core::session::Session) {
        let dial = net.transport().dial_fn();
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            match dial(lb, &[1; 16]) {
                Ok(mut s) => { let sess = link::dial(&mut s, d, lb, &proto::keepalive()).unwrap(); return (s, sess); }
                Err(_) if Instant::now() < end => std::thread::sleep(Duration::from_millis(20)),
                Err(e) => panic!("{e}"),
            }
        }
    }

    /// v0.1.0 ignores unknown frame kinds, so id frames sent to it would VANISH. A peer that never announces gets the old plain
    /// frames, its texts count as done once written, and the outbox never fills up for lack of confirmations.
    #[test]
    fn a_peer_that_never_announces_itself_gets_plain_frames_and_is_never_blocked() {
        let net = MemNet::new();
        let ((l, lb), (d, db)) = ordered();
        // (a raw peer sends no keepalives: a long idle timeout keeps the engine from dropping it as dead)
        let el = Engine::start(Box::new(net.transport()), vec![ContactCfg::new(ID, &l, db.clone())], Timing { idle: Duration::from_secs(20), ..fast() });
        let (mut s1, mut sess1) = raw_legacy_connect(&net, &lb, &d);
        assert!(connected(&el));
        say(&el, ID, "hello old peer");
        assert!(!wait_for(&el, Duration::from_millis(150), |e| matches!(e, Event::Delivered { .. })), "held while the peer might still announce itself");
        assert_eq!(raw_try_next(&mut s1, &mut sess1, &d, Duration::from_secs(3)), Some([&[proto::KIND_TEXT_FINAL][..], b"hello old peer"].concat()), "plain frame, no id");
        assert!(wait(&el, |e| matches!(e, Event::Delivered { .. })), "written = done for an old peer");
        for i in 0..(MAX_UNCONFIRMED + 10) {
            say(&el, ID, &format!("n{i}"));
            assert_eq!(raw_try_next(&mut s1, &mut sess1, &d, Duration::from_secs(3)), Some([&[proto::KIND_TEXT_FINAL][..], format!("n{i}").as_bytes()].concat()));
        }
        assert!(!wait_for(&el, Duration::from_millis(100), |e| matches!(e, Event::Notice { text, .. } if text.contains("outbox full"))), "never blocked");
        // nothing old is resent on a reconnect
        drop((s1, sess1));
        let (mut s2, mut sess2) = raw_legacy_connect(&net, &lb, &d);
        assert!(connected(&el));
        say(&el, ID, "fresh");
        assert_eq!(raw_try_next(&mut s2, &mut sess2, &d, Duration::from_secs(3)), Some([&[proto::KIND_TEXT_FINAL][..], b"fresh"].concat()), "only the new text");
    }

    #[test]
    fn texts_are_held_until_the_peer_has_announced_itself_and_then_sent_with_ids() {
        let net = MemNet::new();
        let ((l, lb), (d, db)) = ordered();
        let el = Engine::start(Box::new(net.transport()), vec![ContactCfg::new(ID, &l, db.clone())], Timing { caps_wait: Duration::from_secs(30), idle: Duration::from_secs(20), ..fast() });
        let (mut s, mut sess) = raw_legacy_connect(&net, &lb, &d);
        assert!(connected(&el));
        say(&el, ID, "held");
        assert_eq!(raw_try_next(&mut s, &mut sess, &d, Duration::from_millis(600)), None, "nothing is written before we know what the peer understands");
        raw_send(&mut s, &mut sess, &d, &proto::encode_caps(proto::CAP_CONFIRM));
        let f = raw_try_next(&mut s, &mut sess, &d, Duration::from_secs(3)).expect("written after the announcement");
        assert_eq!((f[0], &f[9..]), (proto::KIND_TEXT_ID_FINAL, &b"held"[..]));
    }

    /// Review 24 / M3: the confirmation is not an immediate reply: it waits 1-5 s in production, several are sent in ONE cell.
    #[test]
    fn confirmations_are_delayed_and_sent_together() {
        let (el, mut s, mut sess, me) = raw_peer_with(Timing { ack_delay_min: Duration::from_millis(250), ack_delay_max: Duration::from_millis(300), keepalive: Duration::from_secs(10), idle: Duration::from_secs(20), ..fast() });
        let ids = [[1u8; 8], [2; 8], [3; 8]];
        let t0 = Instant::now();
        for (i, m) in ids.iter().enumerate() { raw_send(&mut s, &mut sess, &me, &id_text(m, &format!("t{i}"))); }
        for i in 0..3 { assert!(got(&el, &format!("t{i}"))); }
        let mut all = Vec::new();
        let mut frames = 0;
        while all.len() < 3 { all.extend(raw_acks(&mut s, &mut sess, &me)); frames += 1; }
        assert!(t0.elapsed() >= Duration::from_millis(240), "not an immediate reply ({:?})", t0.elapsed());
        all.sort();
        assert_eq!(all, ids.to_vec());
        assert_eq!(frames, 1, "all three in one cell");
    }

    /// A pending confirmation takes the place of a keepalive that is due (it is traffic anyway), so it never waits longer than one.
    #[test]
    fn a_pending_confirmation_rides_on_the_next_keepalive() {
        let (el, mut s, mut sess, me) = raw_peer_with(Timing { ack_delay_min: Duration::from_secs(30), ack_delay_max: Duration::from_secs(30), keepalive: Duration::from_millis(150), idle: Duration::from_secs(20), ..fast() });
        raw_send(&mut s, &mut sess, &me, &id_text(&[7; 8], "x"));
        assert!(got(&el, "x"));
        let t0 = Instant::now();
        assert_eq!(raw_acks(&mut s, &mut sess, &me), vec![[7u8; 8]]);
        assert!(t0.elapsed() < Duration::from_secs(5), "{:?}: sent with the keepalive, not after 30 s", t0.elapsed());
    }

    /// The case that motivated all this: the sender writes into a connection whose peer is already gone.
    #[test]
    fn a_text_written_to_a_dead_connection_arrives_after_the_reconnect() {
        for round in 0..5 {
            let net = MemNet::new();
            let ((l, lb), (d, db)) = ordered();
            let (el, ed) = (start(&net, &l, &db, ID), start(&net, &d, &lb, ID));
            assert!(connected(&el) && connected(&ed));
            drop(el); // the contact quits; the sender may not have noticed yet
            for t in ["lost-1", "lost-2"] { say(&ed, ID, t); }
            std::thread::sleep(Duration::from_millis(150 * (round % 3)));
            say(&ed, ID, "lost-3");
            let el = start(&net, &l, &db, ID);
            for t in ["lost-1", "lost-2", "lost-3"] { assert!(got(&el, t), "round {round}: {t}"); }
            for _ in 0..3 { assert!(wait(&ed, |e| matches!(e, Event::Delivered { .. })), "round {round}: confirmations"); }
        }
    }

    #[test]
    fn a_full_outbox_refuses_the_new_text_and_keeps_the_old_ones() {
        let net = MemNet::new();
        let ((l, lb), (d, db)) = ordered();
        let ed = start(&net, &d, &lb, ID);
        for i in 0..MAX_UNCONFIRMED { say(&ed, ID, &format!("q{i}")); }
        say(&ed, ID, "one too many");
        assert!(wait(&ed, |e| matches!(e, Event::Unsent { .. })));
        let el = start(&net, &l, &db, ID);
        for i in 0..MAX_UNCONFIRMED { assert!(got(&el, &format!("q{i}")), "q{i}"); }
        assert!(!wait_for(&el, Duration::from_millis(400), |e| matches!(e, Event::Message { text, .. } if text.contains("too many"))));
    }

    #[test]
    fn unconfirmed_texts_survive_a_settings_change_of_the_contact() {
        let net = MemNet::new();
        let ((l, lb), (d, db)) = ordered();
        let ed = start(&net, &d, &lb, ID);
        say(&ed, ID, "kept");
        std::thread::sleep(Duration::from_millis(100));
        ed.add(ContactCfg::new(ID, &d, lb.clone())); // e.g. key rotation re-registers the contact
        std::thread::sleep(Duration::from_millis(100));
        let el = start(&net, &l, &db, ID);
        assert!(got(&el, "kept"));
    }

    /// A raw authenticated peer that speaks the file protocol badly.
    fn raw_peer() -> (Engine, crate::transport::BoxStream, nerd_chat_core::session::Session, ContactIdentity) { raw_peer_with(fast()) }

    fn raw_peer_with(timing: Timing) -> (Engine, crate::transport::BoxStream, nerd_chat_core::session::Session, ContactIdentity) {
        let net = MemNet::new();
        let ((l, lb), (d, db)) = ordered();
        let el = Engine::start(Box::new(net.transport()), vec![ContactCfg::new(ID, &l, db.clone())], timing);
        let dial = net.transport().dial_fn();
        let end = Instant::now() + Duration::from_secs(5);
        let mut s = loop { match dial(&lb, &[1; 16]) { Ok(s) => break s, Err(_) if Instant::now() < end => std::thread::sleep(Duration::from_millis(20)), Err(e) => panic!("{e}") } };
        s.set_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut sess = link::dial(&mut s, &d, &lb, &proto::keepalive()).unwrap();
        raw_send(&mut s, &mut sess, &d, &proto::encode_caps(proto::CAP_CONFIRM)); // a NEW peer announces itself first
        assert!(wait(&el, |e| matches!(e, Event::Connected { .. })));
        (el, s, sess, d)
    }

    fn raw_send(s: &mut crate::transport::BoxStream, sess: &mut nerd_chat_core::session::Session, me: &ContactIdentity, body: &[u8]) {
        use std::io::Write;
        let w = sess.send(me, body).unwrap();
        let _ = s.write_all(&w); // the engine may already have cut an abusive peer off
    }

    /// Read cells until the engine's ACCEPT for `xid` arrives (a correct sender never sends content before it).
    fn raw_wait_accept(s: &mut crate::transport::BoxStream, sess: &mut nerd_chat_core::session::Session, me: &ContactIdentity, xid: file::Xid) {
        use std::io::Read;
        for _ in 0..50 {
            let mut cell = vec![0u8; nerd_chat_core::session::WIRE_CELL_LEN];
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
        assert!(wait(&el, |e| matches!(e, Event::Notice { text, alert: true, .. } if text.contains("integrity"))), "bad file must not be delivered");
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
    fn replacing_a_connection_tells_the_ui_to_clear_file_state() {
        let net = MemNet::new();
        let ((l, lb), (d, _db)) = ordered();
        let (_, db2) = (0, Bundle::from_identity(&d));
        let el = start(&net, &l, &db2, ID);
        let dial = net.transport().dial_fn();
        let end = Instant::now() + Duration::from_secs(5);
        let connect = || loop {
            match dial(&lb, &[1; 16]) { Ok(mut s) => { s.set_timeout(Some(Duration::from_secs(5))).unwrap(); let sess = link::dial(&mut s, &d, &lb, &proto::keepalive()).unwrap(); return (s, sess); } Err(_) if Instant::now() < end => std::thread::sleep(Duration::from_millis(20)), Err(e) => panic!("{e}") }
        };
        let (mut s1, mut sess1) = connect();
        assert!(wait(&el, |e| matches!(e, Event::Connected { .. })));
        raw_send(&mut s1, &mut sess1, &d, &file::encode_offer(&file::Offer { xid: [8; 8], bucket: file::MIN_BUCKET as u32, mode: 0, hash: [1; 32] }));
        let (xid, _) = offer_xid(&el);
        el.reply_file(ID, xid, true);
        let (_s2, _sess2) = connect(); // the same contact dials again: the old connection is replaced
        assert!(wait(&el, |e| matches!(e, Event::FileCancelled { .. })), "UI would keep 'arriving' forever and leak its RAM budget");
    }

    /// Review 12 (L1): `--cannot-host` means NEVER publish, even where the key order would make us the host.
    #[test]
    fn a_side_that_cannot_host_never_publishes_even_when_neither_can() {
        let net = MemNet::new();
        let ((l, lb), (_d, db)) = ordered();
        let (lb, db) = (lb.with_can_host(false), db.with_can_host(false));
        let _el = start_caps(Box::new(net.transport()), &l, &db, false, false);      // a transport that WOULD host
        std::thread::sleep(Duration::from_millis(400));
        assert!(!net.is_hosted(&lb.onion_pub), "published although our_can_host = false");
    }

    /// Review 12 (M2): changing a contact's settings (re-add) must not drop messages queued for it.
    #[test]
    fn re_adding_a_contact_keeps_its_queued_messages() {
        let net = MemNet::new();
        let ((l, lb), (d, db)) = ordered();
        let ed = start(&net, &d, &lb, ID);                       // peer offline: messages queue
        for t in ["q1", "q2"] { say(&ed, ID, t); }
        std::thread::sleep(Duration::from_millis(200));
        ed.add(ContactCfg::new(ID, &d, lb.clone()).with_caps(true, true));   // settings changed
        std::thread::sleep(Duration::from_millis(200));
        let el = start(&net, &l, &db, ID);
        assert!(got(&el, "q1") && got(&el, "q2"), "queued messages were lost by the re-add");
    }

    #[test]
    fn plain_text_is_an_explicit_mode_and_structured_documents_are_refused() {
        let (el, ed) = pair();
        assert!(ed.send_file(ID, b"{\\rtf1{\\info{\\author Jane}}}", nerd_chat_strip::Mode::Auto).is_err());
        assert!(ed.send_file(ID, b"{\\rtf1{\\info{\\author Jane}}}", nerd_chat_strip::Mode::PlainText).is_err());
        let report = ed.send_file(ID, "note\u{202E}\u{E0041} plain".as_bytes(), nerd_chat_strip::Mode::PlainText).unwrap();
        assert!(report.iter().any(|l| l.contains("NOT understood")));
        let (xid, _) = offer_xid(&el);
        el.reply_file(ID, xid, true);
        let mut r = None;
        assert!(wait(&el, |ev| if let Event::File { data, format, .. } = ev { r = Some((data.to_vec(), *format)); true } else { false }));
        let (data, f) = r.unwrap();
        assert_eq!(f, nerd_chat_strip::Format::Text);
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
        let (lb, db) = (lb.with_can_host(false), db.with_can_host(false));
        let el = start_caps(Box::new(NoHost(net.transport())), &l, &db, false, false);
        let ed = start_caps(Box::new(NoHost(net.transport())), &d, &lb, false, false);
        assert!(wait(&el, |e| matches!(e, Event::Notice { text, .. } if text.contains("neither you nor this contact can host"))));
        assert!(wait(&ed, |e| matches!(e, Event::Notice { text, .. } if text.contains("neither you nor this contact can host"))));
        assert!(!wait_for(&el, Duration::from_millis(600), |e| matches!(e, Event::Connected { .. })));
    }
}
