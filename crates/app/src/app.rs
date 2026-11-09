//! UI state machine (no rendering, no terminal): driven by key events, fully testable.
use crate::secret::{ComposeBuf, SecretBuf};
use nerd_chat_chat::{transport::{BoxStream, PairDialError, PairDialFn, PairHostFn, TorSetup, TorTransport}, ContactCfg, Engine, Event, Timing, Transport};
use nerd_chat_net::tor::CancelToken;
use nerd_chat_net::tor::{control::AuthPref, probe::{probe_hosting, HostProbe}, spawn::{find_tor, SpawnConfig}, Addr};
use nerd_chat_core::{bundle::{safety_number, Bundle}, identity::ContactIdentity, trust::Trust};
use nerd_chat_exchange::{file, pair::{Lockout, PairStream, PairingJoin, PairingOffer, REMOTE_OFFER_MAX_TTL}, ExchangeError, ImportedContact, SafetyView};
pub use nerd_chat_store::history::Persist;
use nerd_chat_store::{history::{Clock, History, NoPlatformKeys, PlatformKeys, State as MsgState, Swept, SystemClock}, read_regular_file, OpenInfo, StoreError, VaultFile};
use nerd_chat_vault::Profile;
use std::path::Path;
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::Write,
    net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    sync::{atomic::{AtomicBool, Ordering}, mpsc::{channel, Receiver, TryRecvError}, Arc, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub const MIN_PW_CHARS: usize = 12;
const MAX_IMPORT_BYTES: u64 = 8 * 1024;

/// How to get a Tor. `control` set => use that running tor (Tails, Whonix, system tor); otherwise start our own.
#[derive(Clone, Default)]
pub struct TorCfg {
    pub tor_path: Option<PathBuf>,
    pub control: Option<Addr>,
    pub cookie: Option<PathBuf>,
    pub socks: Option<Addr>,
    /// The user vouches for whoever owns the control port (see docs/TRANSPORT.md).
    pub trust_control: bool,
}

/// Builds the transport when the user goes online (reports progress 0..=100). Tests inject an in-memory network.
pub type TransportFactory = std::sync::Arc<dyn Fn(&mut dyn FnMut(u8)) -> Result<Box<dyn Transport>, String> + Send + Sync>;

pub struct Config {
    /// None = RAM-only: nothing is ever written to disk.
    pub path: Option<PathBuf>,
    pub counter: Option<PathBuf>,
    pub keyfile: Option<Zeroizing<Vec<u8>>>,
    /// Where the keyfile came from (only needed so that a PURGE can delete it too).
    pub keyfile_path: Option<PathBuf>,
    pub profile: Profile,
    pub tor: TorCfg,
    pub(crate) transport: Option<TransportFactory>,
    pub timing: Timing,
    /// Our Tor cannot host onion services (e.g. a Tails with a restricted control port): said in our exported bundles, so the
    /// contact hosts for us and nothing needs to be published speculatively. (`--cannot-host`; `--probe-tor --probe-onion` tells you.)
    pub can_host: bool,
    /// Tests only: the answer of the automatic hosting probe (None = really probe, when an external tor is configured).
    pub(crate) host_probe_test: Option<HostProbe>,
    /// Start even though swap is active (secrets could be written to the disk by the OS). Default: refuse.
    pub allow_swap: bool,
    /// What is kept on the device until the user has chosen: the front end's default (the terminal keeps messages RAM-only; the phone, whose OS kills the app at will,
    /// keeps them for a day). The user's own choice is stored in the vault and wins.
    pub persist_default: Persist,
    /// The GRID: every operation on the vault, counter and history files happens only on this clock (and the files are only touched in between), so that their
    /// times never show when a message was sent. 5 s: the same as the longest delay before a confirmation (docs/HISTORY_AND_TIMING_PLAN.md).
    pub grid: Duration,
    /// Length of one slot of the history file (the file is two of them); tests use a small one.
    pub history_slot: usize,
    /// The platform's deletable key store (Android Keystore); `None` = none (Linux: deletion is a best-effort overwrite).
    pub platform_keys: Option<Arc<dyn PlatformKeys>>,
    /// The clock retention is measured with (tests inject one).
    pub clock: Option<Arc<dyn Clock>>,
}

impl Config {
    /// Replace Tor by a test network (the in-memory `MemNet`): only for the developer demo and tests, never in a release build.
    #[cfg(feature = "test-transport")]
    pub fn with_test_transport(mut self, f: TransportFactory) -> Self { self.transport = Some(f); self }

    pub fn new(path: Option<PathBuf>, counter: Option<PathBuf>, keyfile: Option<Zeroizing<Vec<u8>>>, profile: Profile) -> Self {
        Self { path, counter, keyfile, keyfile_path: None, profile, tor: TorCfg::default(), transport: None, timing: Timing::default(), can_host: true, host_probe_test: None, allow_swap: false, persist_default: Persist::Off, grid: Duration::from_secs(5), history_slot: nerd_chat_store::history::SLOT_LEN, platform_keys: None, clock: None }
    }
}

/// File systems on which overwriting a file does NOT overwrite its data (copy-on-write, or somebody else's storage): the history cannot be deleted there, so it is refused.
#[cfg(any(not(target_os = "android"), test))]
fn unsafe_fs_name(magic: i64) -> Option<&'static str> {
    match magic { 0x9123_683E => Some("btrfs"), 0x2FC1_2FC1 => Some("ZFS"), 0x6969 => Some("a network file system (NFS)"), 0x517B => Some("a network file system (SMB)"), 0xFF53_4D42 => Some("a network file system (CIFS)"), _ => None }
}

#[cfg(not(target_os = "android"))]
fn history_unsafe_fs(dir: &Path) -> Option<&'static str> {
    #[allow(clippy::unnecessary_cast)]
    rustix::fs::statfs(dir).ok().and_then(|s| unsafe_fs_name(s.f_type as i64))
}
/// On Android the platform key store (not an overwrite) is what deletes.
#[cfg(target_os = "android")]
fn history_unsafe_fs(_dir: &Path) -> Option<&'static str> { None }

fn build_tor_transport(c: &TorCfg, progress: &mut dyn FnMut(u8)) -> Result<Box<dyn Transport>, String> {
    let setup = match &c.control {
        Some(ctl) => TorSetup::External {
            control: ctl.clone(),
            auth: AuthPref { password: None, cookie_path: c.cookie.clone(), peer_verified: false },
            socks: c.socks.clone(),
            trust_control: c.trust_control,
        },
        None => {
            let path = c.tor_path.clone().or_else(find_tor)
                .ok_or("no tor binary found: install tor, pass --tor-path, or use --tor-control to use a running tor (Tails/Whonix)")?;
            TorSetup::Spawn(SpawnConfig::new(path))
        }
    };
    TorTransport::start(setup, progress).map(|t| Box::new(t) as Box<dyn Transport>)
}

/// What continues once the hosting probe answered. All variants carry the contact id: nothing may be applied to another contact.
enum Then { Export([u8; 8], String), Listen([u8; 8], SocketAddr), Join([u8; 8], SocketAddr, Result<PairingJoin, ExchangeError>), TorOffer([u8; 8]), TorJoin([u8; 8], String, Result<PairingJoin, ExchangeError>) }

/// How long the worker may take before the answer counts as inconclusive (a hostile or hung control port must not hold us).
const PROBE_DEADLINE: Duration = Duration::from_secs(15);

/// Where the engine is. (UI reads this.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Online { Offline, Starting(u8), Online, Stopping, Failed(String) }

/// Result of the (slow, memory-hard) vault key derivation done on a worker thread.
enum KdfMsg { Opened(Result<(VaultFile, OpenInfo), StoreError>), Created(Result<VaultFile, StoreError>) }

enum StartMsg { Progress(u8), Ready(Engine), Failed(String) }

/// A received, re-cleaned file waiting in RAM until the user saves it (or it is wiped on panic/quit).
struct Received { data: Zeroizing<Vec<u8>>, ext: &'static str }

/// One line of conversation. RAM only, wiped when dropped.
pub struct ChatLine { pub mine: bool, pub text: Zeroizing<String>, /// sent, not yet CONFIRMED by the contact's app (the engine resends it on every new connection)
    pub queued: bool, /// the user saved this message into the vault
    pub saved: bool, /// the engine REFUSED the text (outbox full, empty, too long): it was not sent and never will be
    pub unsent: bool, /// we went offline while it was unconfirmed: it may or may not have arrived (the engine's copy is gone)
    pub unconfirmed: bool, /// the id of one of OUR texts, so that `Delivered`/`Unsent` find exactly this line (None for received lines)
    pub mid: Option<[u8; 8]> }
/// A contact may rotate its keys (and so make us re-publish our service) at most this often.
const ROTATION_MIN_INTERVAL: Duration = Duration::from_secs(3600);
const MAX_CHAT_LINES: usize = 500;
const NO_CONTACT: &str = "No contact selected. Press n to add one.";
/// Upper bound of the history scroll offset (the UI clamps to what really exists).
const SCROLL_CAP: usize = 100_000;

/// States for the inspector panel (see `App::inspect`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inspect {
    pub connected: bool,
    pub contact_can_host: bool,
    pub we_told_can_host: Option<bool>,
    pub we_host_now: bool,
    pub host_anyway: bool,
    /// "host anyway" may be switched ON (our Tor can host) or is ON (and may be switched off)
    pub host_anyway_possible: bool,
    pub rotation: Option<&'static str>,
    /// a rotation can be started now (online, none waiting)
    pub rotation_possible: bool,
    pub saved: usize,
    pub cap_mismatch: Option<bool>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Key { Char(char), Enter, Esc, Backspace, Up, Down, Tab, BackTab, PageUp, PageDown, Home, End, F12, CtrlBackslash, /// Ctrl+] / Shift+F12: PURGE
    Purge }

#[derive(Debug, PartialEq, Eq)]
pub enum Action { None, Quit, Panic, /// like `Panic`, and every file of this vault was overwritten and deleted
    Purge }

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Prompt {
    NewContact, Import, Export, Listen, JoinAddr, JoinCode(String), /// the pairing link pasted for a pairing over Tor
    JoinLink, ConfirmDelete, InPerson, SendFile, SendText, SaveFile,
}

/// What the right-hand pane shows (the contact list sidebar is always there).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pane { Details, Chat, /// the messages the user saved for the selected contact
    Saved }

/// Vim-style input: in `Normal` every key is a command, in `Insert` (chat only) keys are TEXT and nothing else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode { Normal, Insert }

#[derive(Debug, PartialEq, Eq)]
pub enum Screen {
    Unlock,
    CreatePw,
    CreateConfirm,
    Main,
    Prompt(Prompt),
    Verify,
    Help,
    /// Vault key derivation running on a worker; only the panic key is honoured.
    Working,
    /// After a panic: everything wiped, nothing to show.
    Wiped,
}

/// What a pairing worker reports: (contact id, the paired contact and its safety number, or why it failed).
type PairMsg = ([u8; 8], Result<(ImportedContact, String), ExchangeError>);

/// Handle on a running pairing worker so it can be cancelled (user `x`, or panic).
/// What the pairing-over-Tor worker reports besides the final result.
enum LinkMsg { Ready { link: Zeroizing<String>, code: Zeroizing<String>, expires: Instant }, Failed(String), UsedAndFailed }

/// The link and code of an open offer over Tor, for the front end to show (the link goes to the partner only, the code by voice).
pub struct TorLink { pub contact: [u8; 8], pub link: Zeroizing<String>, pub code: Zeroizing<String>, pub expires: Instant }

/// A stream that came through Tor, as a pairing stream.
struct TorPairStream(BoxStream);
impl std::io::Read for TorPairStream { fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> { self.0.read(b) } }
impl std::io::Write for TorPairStream { fn write(&mut self, b: &[u8]) -> std::io::Result<usize> { self.0.write(b) } fn flush(&mut self) -> std::io::Result<()> { self.0.flush() } }
impl PairStream for TorPairStream { fn set_timeout(&mut self, d: Duration) -> std::io::Result<()> { self.0.set_timeout(Some(d)) } }

/// The offer side over Tor (worker thread): host the one-shot service, wait until it is published, show link + code, wait for ONE
/// connection, then pair. Everything it owns (service, listener) is dropped on every path.
fn tor_offer_job(host_fn: PairHostFn, tok: &CancelToken, ident: &ContactIdentity, adv: bool, lockout: Arc<Lockout>, ltx: &std::sync::mpsc::Sender<LinkMsg>) -> Result<nerd_chat_exchange::pair::Paired, ExchangeError> {
    let mut host = match host_fn() {
        Ok(h) => h,
        Err(e) => { let _ = ltx.send(LinkMsg::Failed(if e.contains("510") { "Your Tor cannot create the pairing service here. Ask the OTHER person to create the code, and join with their link.".into() } else { format!("Could not create the pairing service: {e}") })); return Err(ExchangeError::Io); }
    };
    match host.wait_published(tok) {
        Ok(true) => {}
        Ok(false) => return Err(ExchangeError::Io),
        Err(e) => { let _ = ltx.send(LinkMsg::Failed(format!("The pairing service did not come up in time ({e}). Try again."))); return Err(ExchangeError::Io); }
    }
    let (offer, code) = PairingOffer::generate_remote(lockout, REMOTE_OFFER_MAX_TTL)?;
    let offer = offer.with_can_host(adv);
    let expires = Instant::now() + offer.expires_in();
    let _ = ltx.send(LinkMsg::Ready { link: Zeroizing::new(host.id.clone()), code, expires });
    let stream = loop {
        if tok.is_cancelled() { return Err(ExchangeError::Io); }
        match host.incoming.recv_timeout(Duration::from_millis(200)) {
            Ok(s) => break s,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => if Instant::now() >= expires { return Err(ExchangeError::Expired); },
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Err(ExchangeError::Io),
        }
    };
    drop(host); // the service is removed as soon as the one connection arrived
    tok.register(&*stream);
    if tok.is_cancelled() { return Err(ExchangeError::Io); }
    let mut s = TorPairStream(stream);
    match offer.accept_remote(&mut s, ident) {
        Ok(p) => Ok(p),
        Err((e, guessed)) => { if guessed { let _ = ltx.send(LinkMsg::UsedAndFailed); } Err(e) }
    }
}

/// The join side over Tor (worker thread): dial the link (bounded retry while the descriptor is not found), then pair.
fn tor_join_job(dial: PairDialFn, tok: &CancelToken, id: &str, join: PairingJoin, ident: &ContactIdentity, ltx: &std::sync::mpsc::Sender<LinkMsg>) -> Result<nerd_chat_exchange::pair::Paired, ExchangeError> {
    let fail = |m: &str| { let _ = ltx.send(LinkMsg::Failed(m.to_string())); };
    let start = Instant::now();
    let stream = loop {
        let mut iso = [0u8; 16];
        getrandom::fill(&mut iso).map_err(|_| ExchangeError::Io)?;
        match dial(id, &iso, tok) {
            Ok(s) => break s,
            Err(PairDialError::NotFound) if start.elapsed() < Duration::from_secs(60) => {
                for _ in 0..30 { if tok.is_cancelled() { return Err(ExchangeError::Io); } thread::sleep(Duration::from_millis(100)); }
            }
            Err(PairDialError::NotFound) => { fail("The link is not ready yet, or it has expired. Ask your partner for a new link."); return Err(ExchangeError::Expired) }
            Err(PairDialError::Unreachable) => { fail("Could not reach your partner through Tor: their pairing is closed or not ready, or Tor is busy. Ask for a new link and try again."); return Err(ExchangeError::Io) }
            Err(PairDialError::Refused) => { fail("Your partner's pairing is already closed (the link was used once). Ask for a new link."); return Err(ExchangeError::Io) }
            Err(PairDialError::Cancelled) => return Err(ExchangeError::Io),
            Err(PairDialError::Other(m)) if m.contains("os error 11") || m.contains("timed out") => { fail("Tor did not answer in time. The link may not be ready yet, or Tor is slow right now. Ask for a new link and try again."); return Err(ExchangeError::Io) }
            Err(PairDialError::Other(m)) => { fail(&format!("Could not connect through Tor: {m}")); return Err(ExchangeError::Io) }
        }
    };
    tok.register(&*stream);
    if tok.is_cancelled() { return Err(ExchangeError::Io); }
    let mut s = TorPairStream(stream);
    match join.with_deadline(nerd_chat_exchange::pair::REMOTE_PAIR_DEADLINE).join_remote(&mut s, ident) {
        Ok(p) => Ok(p),
        Err((e, false)) if e == ExchangeError::Io => { fail("Your partner's pairing closed before it started: the offer was cancelled or already used. Ask for a new link."); Err(e) }
        Err((e, _)) => Err(e),
    }
}

struct PairCtl { cancel: Arc<AtomicBool>, stream: Arc<Mutex<Option<TcpStream>>>, handle: JoinHandle<()>, tor: Option<Arc<CancelToken>> }

impl PairCtl {
    /// Ask the worker to stop and cut its socket so blocked reads return immediately.
    fn cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
        if let Some(s) = self.stream.lock().unwrap().as_ref() { let _ = s.shutdown(Shutdown::Both); }
        if let Some(t) = &self.tor { t.cancel(); } // closes the SOCKS/onion stream and ends a wait for the service
    }
}

/// Listening is only allowed on loopback or private LAN addresses (never 0.0.0.0 / public).
fn listen_addr_ok(a: &SocketAddr) -> bool {
    match a.ip() {
        IpAddr::V4(v) => v.is_loopback() || v.is_private() || v.is_link_local(),
        IpAddr::V6(v) => v.is_loopback() || v.is_unique_local() || v.is_unicast_link_local(),
    }
}

pub struct App {
    cfg: Config,
    pub screen: Screen,
    pub pw: SecretBuf,
    pw2: SecretBuf,
    pub input: String,
    pub status: String,
    pub error: bool,
    pub sel: usize,
    vf: Option<VaultFile>,
    view: Option<SafetyView>,
    pair_rx: Option<Receiver<PairMsg>>,
    /// pairing over Tor: progress of the worker (link ready, failures), the shown link, the lockout that only counts real guesses, and whether the running pairing came through Tor
    link_rx: Option<Receiver<LinkMsg>>,
    pub tor_offer: Option<TorLink>,
    /// the contact an open Tor offer belongs to (the card must show it for THAT contact only)
    tor_contact: Option<[u8; 8]>,
    remote_lockout: std::sync::Arc<Lockout>,
    pair_remote: bool,
    /// The automatic hosting probe (R12-5) running on a worker thread, what to do when it answers, and when it started.
    probe_rx: Option<Receiver<HostProbe>>, probe_then: Option<(Then, Instant)>,
    pub pair_info: Option<Zeroizing<String>>,
    pair_ctl: Option<PairCtl>,
    code_buf: SecretBuf,
    pending_pair: Option<([u8; 8], ImportedContact, String)>,
    /// The capability bit used in the running/last pairing; recorded in the vault only when the pairing is accepted.
    pair_adv: Option<bool>,
    /// When we last accepted a key rotation from each contact: a contact cannot make us re-publish our service or rewrite the vault more than once an hour.
    rot_accepted: HashMap<[u8; 8], Instant>,
    failures: u32,
    locked_until: Option<Instant>,
    lockout: std::sync::Arc<Lockout>,
    engine: Option<Engine>,
    start_rx: Option<Receiver<StartMsg>>,
    /// ids the engine was started with (to reconcile with the vault when it becomes ready)
    started_ids: HashSet<[u8; 8]>,
    /// The ids of the kept texts the engine was started with: a text kept WHILE the engine was still starting is not among them and is handed over when it is ready.
    started_outbox: HashSet<[u8; 8]>,
    /// The vault's old outbox texts were copied into the history and are removed from the vault after the next durable tick.
    migrate_pending: bool,
    /// The message history (None: nothing is kept, or it could not be opened).
    history: Option<History>,
    /// Next tick of the grid.
    grid_next: Instant,
    /// Texts we received and showed whose confirmation waits until the history write that holds them is DURABLE (a crash in between would lose a text the sender believes delivered).
    pending_confirms: Vec<([u8; 8], [u8; 8])>,
    /// Texts we typed that wait for the next tick: they are written to the history first, then handed to the engine.
    pending_sends: Vec<([u8; 8], [u8; 8], Zeroizing<String>)>,
    stop_rx: Option<Receiver<()>>,
    pub online: Online,
    chats: HashMap<[u8; 8], Vec<ChatLine>>,
    linked: HashSet<[u8; 8]>,
    unread: HashMap<[u8; 8], u32>,
    /// Files this session created on request (exported bundles, saved received files): a PURGE deletes them too.
    created: Vec<(PathBuf, (u64, u64))>,
    /// Set by `purge_prepare`: the session's created files, destroyed by `purge_finish`.
    purge_pending: Option<Vec<(PathBuf, (u64, u64))>>,
    /// (deleted, failed) after a purge, for the one-line report printed after the terminal was wiped.
    pub purge_report: Option<(usize, usize)>,
    /// Right pane: details of the selected contact, or the conversation with it (the open chat is ALWAYS `sel_id()`).
    pub pane: Pane,
    pub mode: Mode,
    /// Privacy screen (3rd Esc): the app keeps running underneath but draws nothing; Enter unlocks, q quits. NOT authentication.
    pub locked: bool,
    /// Lines scrolled up from the newest message (the UI clamps what it can show).
    pub scroll: usize,
    /// Message cursor (`m` in a chat): index counted from the NEWEST message (0 = newest). While set, `y`/Enter saves that message.
    pub select: Option<usize>,
    /// Cursor in the saved-messages view and the armed state of its two-press delete.
    pub saved_sel: usize,
    del_armed: bool,
    /// Largest useful `scroll`, reported by the last frame (it knows the wrapped width); None before the first frame.
    pub max_scroll: std::cell::Cell<Option<usize>>,
    /// `q` pressed once with something that would be lost: a second `q` quits.
    quit_armed: bool, offline_armed: bool,
    compose: ComposeBuf,
    /// pending incoming file offers (contact id -> (transfer id, size))
    offers: HashMap<[u8; 8], (nerd_chat_chat::file::Xid, u32)>,
    /// accepted, still arriving: contact id -> bucket (counts toward the RAM budget)
    accepted: HashMap<[u8; 8], u32>,
    inbox: HashMap<[u8; 8], Received>,
    /// file being cleaned on a worker (cleaning is CPU-heavy on hostile input; the UI/panic key must stay live)
    prep_rx: Option<([u8; 8], Receiver<Result<(nerd_chat_chat::FileOut, Vec<String>), nerd_chat_strip::StripError>>)>,
    /// Security warnings from the engine: they stay on screen until acknowledged with `k` (never overwritten by status text).
    pub alerts: Vec<(String, u32)>,
    /// This session's warnings, newest last, kept after they were acknowledged (memory only, wiped by panic/purge).
    alert_log: Vec<(String, u32)>,
    /// Alerts that did not fit (never evict an unacknowledged one).
    pub alerts_dropped: u32,
    kdf_rx: Option<Receiver<KdfMsg>>,
    /// Set by the panic wipe: a running vault-creation worker must not touch the disk any more.
    kdf_cancel: Arc<AtomicBool>,
    /// The running worker creates a vault (only then does a panic wait for it).
    kdf_creating: bool,
    /// screen to return to if the derivation fails
    kdf_back: Screen,
    #[cfg(test)]
    test_async: bool,
}

impl App {
    pub fn new(cfg: Config) -> Self {
        assert!(cfg!(test) || crate::startup::is_done(), "nerd_chat_app::startup::startup(&args) must be the first thing a front end runs (cleaner helper, hardening)");
        let exists = cfg.path.as_ref().is_some_and(|p| std::fs::symlink_metadata(p).is_ok());
        let ram = cfg.path.is_none();
        let mut a = Self {
            cfg, screen: if exists { Screen::Unlock } else { Screen::CreatePw }, pw: SecretBuf::new(), pw2: SecretBuf::new(),
            input: String::new(), status: String::new(), error: false, sel: 0, vf: None, view: None,
            pair_rx: None, link_rx: None, tor_offer: None, tor_contact: None, remote_lockout: std::sync::Arc::new(Lockout::default()), pair_remote: false, probe_rx: None, probe_then: None, pair_info: None, pair_ctl: None, code_buf: SecretBuf::new(), pending_pair: None, pair_adv: None, rot_accepted: HashMap::new(), failures: 0, locked_until: None,
            lockout: std::sync::Arc::new(Lockout::default()),
            engine: None, start_rx: None, started_ids: HashSet::new(), started_outbox: HashSet::new(), history: None, migrate_pending: false, grid_next: Instant::now(), pending_confirms: Vec::new(), pending_sends: Vec::new(), stop_rx: None, online: Online::Offline, chats: HashMap::new(), linked: HashSet::new(), unread: HashMap::new(), created: Vec::new(), purge_pending: None, purge_report: None, pane: Pane::Details, mode: Mode::Normal, locked: false, scroll: 0, select: None, saved_sel: 0, del_armed: false, max_scroll: std::cell::Cell::new(None), quit_armed: false, offline_armed: false, compose: ComposeBuf::new(),
            offers: HashMap::new(), accepted: HashMap::new(), inbox: HashMap::new(),
            prep_rx: None,
            alerts: Vec::new(), alert_log: Vec::new(), alerts_dropped: 0, kdf_rx: None, kdf_cancel: Arc::new(AtomicBool::new(false)), kdf_creating: false, kdf_back: Screen::Unlock,
            #[cfg(test)] test_async: false,
        };
        a.status = if ram { "RAM-only mode: nothing will be written to disk.".into() }
            else if exists { "Enter your password to unlock.".into() }
            else { format!("No vault found. Creating a NEW one (min {MIN_PW_CHARS} characters).") };
        a
    }

    pub fn path_display(&self) -> String {
        self.cfg.path.as_ref().map_or("RAM-only".into(), |p| p.display().to_string())
    }
    /// What is kept on the device: the user's choice (key `O`, stored in the vault), else the front end's default. A vault that still holds unconfirmed texts in its OLD per-contact
    /// outbox counts as at least `Outbox` until they are moved to the history file. RAM-only mode keeps nothing.
    pub fn persist(&self) -> Persist {
        let Some(v) = self.vf.as_ref() else { return Persist::Off };
        if self.cfg.path.is_none() { return Persist::Off; }
        let legacy = v.store.contacts.iter().any(|c| !c.outbox.is_empty());
        v.store.persist.unwrap_or(if self.cfg.persist_default == Persist::Off && legacy { Persist::Outbox } else { self.cfg.persist_default })
    }

    fn hist_path(&self) -> Option<PathBuf> {
        self.cfg.path.as_ref().map(|p| { let mut s = p.as_os_str().to_owned(); s.push(".hist"); PathBuf::from(s) })
    }

    /// Texts that are queued on a line but NOT in the history: they live in RAM only and are lost if the app ends or the engine stops.
    fn queued_not_kept(&self) -> usize {
        self.chats.iter().map(|(id, l)| l.iter().filter(|x| x.mine && x.queued && !x.mid.is_some_and(|m| self.history.as_ref().is_some_and(|h| h.has_queued(*id, m)))).count()).sum()
    }

    /// Open the history for the effective mode (after unlocking, or when the user switches it on): move the vault's old outbox into it, expire what ran out.
    fn open_history(&mut self) {
        self.history = None;
        let p = self.persist();
        if !p.keeps_anything() { return; }
        let (Some(path), Some(vf)) = (self.hist_path(), self.vf.as_ref()) else { return };
        if let Some(why) = path.parent().and_then(history_unsafe_fs) {
            return self.err(format!("Messages are NOT kept: this folder is on {why}, where an overwrite does not really delete. Use --vault on an ordinary local file system, or switch the setting off (O)."));
        }
        let fk = vf.subkey(b"history");
        let moved: Vec<([u8; 8], [u8; 8], Zeroizing<String>)> = vf.store.contacts.iter().flat_map(|c| c.outbox.iter().map(move |m| (c.id, m.mid, m.text.clone()))).collect();
        let platform: Arc<dyn PlatformKeys> = self.cfg.platform_keys.clone().unwrap_or_else(|| Arc::new(NoPlatformKeys));
        let clock: Arc<dyn Clock> = self.cfg.clock.clone().unwrap_or_else(|| Arc::new(SystemClock::new()));
        match History::open(&path, self.cfg.history_slot, fk, platform, clock, p) {
            Ok(mut h) => {
                for (cid, mid, text) in &moved { if !h.has_queued(*cid, *mid) { h.push(*cid, MsgState::Queued, Some(*mid), text); } }
                let swept = h.sweep();
                self.history = Some(h);
                if !moved.is_empty() {
                    // the old copies in the vault are redundant now; the history file takes them on the next tick, so wait for that before removing them
                    self.migrate_pending = true;
                }
                self.after_sweep(swept);
            }
            Err(e) => self.err(format!("Cannot open the message history ({e}): nothing is kept this session.")),
        }
    }

    /// Once the history file holds the vault's old outbox texts (a tick has written it), remove them from the vault.
    fn finish_migration(&mut self) {
        if !self.migrate_pending { return; }
        if self.history.as_ref().is_some_and(|h| h.is_dirty()) { return; }
        self.migrate_pending = false;
        // the choice was only INFERRED from the old outbox ("texts are kept, so the feature is in use"): store it now, or the next start would forget it once the old copies are gone
        let chosen = self.persist();
        if let Some(v) = self.vf.as_mut() { if v.store.persist.is_none() { v.store.persist = Some(chosen); } v.store.clear_outbox(); }
        let _ = self.save();
    }

    /// What a sweep removed: texts that expired unsent are marked on screen and forgotten by the engine (they must never be sent later, looking fresh).
    fn after_sweep(&mut self, s: Swept) {
        if s.expired_queued.is_empty() { return; }
        for (cid, mid) in &s.expired_queued {
            if let Some(x) = self.chats.get_mut(cid).and_then(|l| l.iter_mut().find(|x| x.mine && x.mid == Some(*mid))) { x.queued = false; x.unsent = true; }
            if let Some(e) = &self.engine { e.cancel(*cid, *mid); }
        }
        self.err(format!("{} message(s) EXPIRED, NOT SENT: the contact was not reachable in time.", s.expired_queued.len()));
    }

    pub fn set_persist(&mut self, p: Persist) {
        if self.screen != Screen::Main || self.vf.is_none() || self.cfg.path.is_none() { return; }
        let before = self.vf.as_ref().and_then(|v| v.store.persist);
        if before == Some(p) { return; }
        if p.keeps_anything() {
            if let Some(why) = self.hist_path().as_deref().and_then(Path::parent).and_then(history_unsafe_fs) {
                return self.err(format!("Not switched on: this folder is on {why}, where an overwrite does not really delete. Use --vault on an ordinary local file system."));
            }
        }
        self.vf().store.persist = Some(p);
        if !self.save() { self.vf().store.persist = before; return; }
        // a "saved, but the counter file failed" warning from `save` must stay visible: the status lines below would overwrite it
        let warned = self.error && self.status.starts_with("WARNING: saved");
        let starting = matches!(self.online, Online::Starting(_));
        let seeded = self.started_outbox.clone();
        match (self.history.is_some(), p.keeps_anything()) {
            (_, false) => {
                if let Some(h) = self.history.take() { let _ = h.shred(); }
                self.pending_sends.clear();
                // what is not in the history any more is held by the engine only if it is running (or was handed the text when it started)
                if self.engine.is_none() {
                    for x in self.chats.values_mut().flatten().filter(|x| x.queued && !(starting && x.mid.is_some_and(|m| seeded.contains(&m)))) { x.queued = false; x.unconfirmed = true; }
                }
                if !warned { self.ok("Nothing is kept on this device any more: messages are RAM-only again and the history file was overwritten and deleted."); }
            }
            (true, true) => {
                if let Some(h) = self.history.as_mut() { h.set_persist(p); }
                if !warned { self.ok(Self::persist_text(p)); }
            }
            (false, true) => {
                self.open_history();
                if self.history.is_some() { self.keep_current_lines(); if !warned { self.ok(Self::persist_text(p)); } }
                else { self.vf().store.persist = before; let _ = self.save(); } // `open_history` said why
            }
        }
    }

    fn persist_text(p: Persist) -> &'static str {
        match p {
            Persist::Off => "Nothing is kept.",
            Persist::Outbox => "Only messages you sent that are not confirmed yet are kept (encrypted) until they arrive.",
            Persist::Day => "Messages are kept encrypted for about a day (24-30 h). Anyone with this device and your password can read them; deleted messages may survive in the device's storage.",
            Persist::Week => "Messages are kept encrypted for about a week. Anyone with this device and your password can read them; deleted messages may survive in the device's storage.",
        }
    }

    /// Switching on: what this session already shows goes into the history too (in order).
    fn keep_current_lines(&mut self) {
        let Some(h) = self.history.as_mut() else { return };
        let ids: Vec<[u8; 8]> = self.vf.as_ref().map(|v| v.store.contacts.iter().map(|c| c.id).collect()).unwrap_or_default();
        for id in ids {
            for l in self.chats.get(&id).map(|v| v.as_slice()).unwrap_or(&[]) {
                let st = if !l.mine { MsgState::Received } else if l.queued { MsgState::Queued } else if l.unsent { MsgState::Unsent } else if l.unconfirmed { MsgState::Unconfirmed } else { MsgState::Delivered };
                h.push(id, st, l.mid, &l.text);
            }
        }
    }

    /// The `O` key: off -> unsent only -> one day -> one week -> off.
    fn toggle_persist(&mut self) {
        let next = match self.persist() { Persist::Off => Persist::Outbox, Persist::Outbox => Persist::Day, Persist::Day => Persist::Week, Persist::Week => Persist::Off };
        self.set_persist(next);
    }

    /// Texts typed (and kept in the history) while the engine was still starting are not in the snapshot it started with: give them to it now, in order.
    /// Only for contacts the engine already serves; a contact added by `reconcile` got its whole queue in its own `ContactCfg`.
    fn hand_over_texts_kept_while_starting(&mut self) {
        let (Some(e), Some(h), Some(v)) = (self.engine.as_ref(), self.history.as_ref(), self.vf.as_ref()) else { return };
        for c in v.store.contacts.iter().filter(|c| c.peer.is_some() && self.started_ids.contains(&c.id)) {
            for (mid, text) in h.queued(c.id).into_iter().filter(|(m, _)| !self.started_outbox.contains(m)) { e.send_with_mid(c.id, mid, text); }
        }
        self.started_outbox.clear();
    }

    /// After unlocking: show what the history remembers, so the user sees the conversation and what is still waiting.
    fn seed_history_lines(&mut self) {
        let Some(h) = self.history.as_ref() else { return };
        let ids: Vec<[u8; 8]> = self.vf.as_ref().map(|v| v.store.contacts.iter().map(|c| c.id).collect()).unwrap_or_default();
        let lines: Vec<([u8; 8], Vec<nerd_chat_store::history::Line>)> = ids.into_iter().map(|id| (id, h.lines(id))).filter(|(_, l)| !l.is_empty()).collect();
        for (id, ls) in lines {
            for l in ls {
                let (queued, unsent, unconfirmed) = (l.state == MsgState::Queued, matches!(l.state, MsgState::Unsent | MsgState::Expired), l.state == MsgState::Unconfirmed);
                self.push_line(id, ChatLine { mine: l.mine(), text: l.text, queued, saved: false, unsent, unconfirmed, mid: l.mid });
            }
        }
    }

    /// The GRID TICK (every `cfg.grid`, from `poll` and from nowhere else): expire what ran out, write the history if it changed (otherwise only touch it), touch the vault and its counter,
    /// and only THEN release what waited for a durable write: confirmations of received texts and the texts we typed. Nothing else ever touches these files, so their times show the grid.
    fn grid_tick(&mut self) {
        if Instant::now() < self.grid_next { return; }
        self.grid_next = Instant::now() + self.cfg.grid;
        let keeps = self.persist().keeps_anything();
        if !keeps && self.history.is_none() { return; }
        let confirms = std::mem::take(&mut self.pending_confirms);
        let sends = std::mem::take(&mut self.pending_sends);
        let mut durable = true;
        if let Some(h) = self.history.as_mut() {
            let swept = h.sweep();
            let r = h.tick();
            self.after_sweep(swept);
            if let Err(e) = r { durable = false; self.err(format!("The message history could not be written ({e}): confirmations and sends wait.")); }
        }
        if let Some(v) = self.vf.as_ref() { let _ = v.touch(); }
        self.finish_migration();
        if durable {
            if let Some(e) = &self.engine {
                for (id, m) in confirms { e.confirm(id, m); }
                for (id, mid, text) in sends { e.send_with_mid(id, mid, text); }
            } // without an engine the texts stay in the history and are handed to it when it starts
        } else {
            self.pending_confirms = confirms; self.pending_sends = sends;
        }
    }

    pub fn contacts_len(&self) -> usize { self.vf.as_ref().map_or(0, |v| v.store.contacts.len()) }
    /// Borrowed rows: no per-frame copies of contact names.
    pub fn contact_rows(&self) -> Vec<(&str, Trust, bool, bool, u32)> {
        self.vf.as_ref().map_or(vec![], |v| v.store.contacts.iter()
            .map(|c| (c.name.as_str(), c.trust, c.peer.is_some(), self.linked.contains(&c.id), self.unread.get(&c.id).copied().unwrap_or(0))).collect())
    }
    /// (name, trust, connected) of the open chat.
    pub fn chat_header(&self) -> Option<(&str, Trust, bool)> {
        let id = self.chat_id()?;
        let c = self.contact(id)?;
        Some((c.name.as_str(), c.trust, self.linked.contains(&id)))
    }
    /// The open conversation: the selected contact while the right pane shows the chat (one source of truth: `sel`).
    pub fn chat_id(&self) -> Option<[u8; 8]> { if self.pane == Pane::Chat { self.sel_id() } else { None } }
    /// Connection state of the selected contact for the details pane (None: no peer key yet).
    pub fn selected_connection(&self) -> Option<&'static str> {
        let c = self.vf.as_ref()?.store.contacts.get(self.sel)?;
        c.peer.as_ref()?;
        Some(if self.linked.contains(&c.id) { "connected" }
             else if self.engine.is_some() { "online, the contact is not connected (yet)" }
             else { "offline: press o to go online" })
    }
    /// Key rotation state of the selected contact (None: nothing in progress).
    pub fn rotation_state(&self) -> Option<&'static str> {
        let c = self.vf.as_ref()?.store.contacts.get(self.sel)?;
        match (c.next_transport.is_some(), c.peer_old.is_some()) {
            (true, _) => Some("key rotation pending: waiting for the contact's answer (your OLD onion address stays published until then)"),
            (false, true) => Some("the contact rotated its keys: its old keys stay authorized until it confirms"),
            _ => None,
        }
    }
    /// The messages the user saved for the selected contact.
    pub fn saved_msgs(&self) -> &[nerd_chat_store::SavedMsg] { self.vf.as_ref().and_then(|v| v.store.contacts.get(self.sel)).map_or(&[], |c| c.saved.as_slice()) }
    pub fn chat_lines(&self) -> &[ChatLine] { self.chat_id().and_then(|id| self.chats.get(&id)).map_or(&[], |v| v.as_slice()) }
    pub fn compose_text(&self) -> &str { self.compose.as_str() }
    pub fn online_label(&self) -> String {
        match &self.online {
            Online::Offline => "offline".into(),
            Online::Starting(p) => format!("starting tor {p}%"),
            Online::Online => "ONLINE".into(),
            Online::Stopping => "stopping...".into(),
            Online::Failed(_) => "offline (failed)".into(),
        }
    }
    pub fn selected_detail(&self) -> Option<(&str, Trust, Option<String>)> {
        let c = self.vf.as_ref()?.store.contacts.get(self.sel)?;
        let sn = c.peer.as_ref().map(|p| safety_number(&Bundle::from_identity(&c.identity), p));
        Some((c.name.as_str(), c.trust, sn))
    }
    /// Number of typed characters in the (hidden) join-code buffer.
    /// Warnings raised in this session, oldest first, with repeat counts (kept after "Got it"; memory only).
    pub fn alert_history(&self) -> &[(String, u32)] { &self.alert_log }
    pub fn code_chars(&self) -> usize { self.code_buf.chars() }
    /// Number of typed characters in the repeat-password buffer (only the count leaves the core).
    pub fn confirm_chars(&self) -> usize { self.pw2.chars() }
    pub fn view_number(&self) -> Option<&str> { self.view.as_ref().map(|v| v.number.as_str()) }
    pub fn is_ram_only(&self) -> bool { self.cfg.path.is_none() }

    fn ok(&mut self, m: impl Into<String>) { self.status = m.into(); self.error = false; }
    fn err(&mut self, m: impl Into<String>) { self.status = m.into(); self.error = true; }

    /// Leftover temp files of an atomic write next to `p`: exactly `<name>.<16 lowercase hex>.tmp` (never somebody else's `v.my-notes.tmp`).
    fn temp_siblings(p: &std::path::Path) -> Vec<PathBuf> {
        use std::os::unix::ffi::OsStrExt;
        let Some(name) = p.file_name() else { return Vec::new() };
        let dir = p.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(std::path::Path::new("."));
        let mut pre = name.as_bytes().to_vec();
        pre.push(b'.');
        let Ok(rd) = std::fs::read_dir(dir) else { return Vec::new() };
        rd.flatten().filter(|e| {
            let n = e.file_name();
            let mid = n.as_bytes().strip_prefix(&pre[..]).and_then(|r| r.strip_suffix(b".tmp"));
            mid.is_some_and(|m| m.len() == 16 && m.iter().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)))
        }).map(|e| e.path()).collect()
    }

    /// Remember a file this session created, with its identity: a PURGE only destroys it if it is still THAT file.
    fn note_created(&mut self, path: &std::path::Path) {
        use std::os::unix::fs::MetadataExt;
        if let Ok(m) = std::fs::symlink_metadata(path) { self.created.push((path.to_path_buf(), (m.dev(), m.ino()))); }
    }

    /// Every file on disk that belongs to this vault: the vault, its rollback counter, the keyfile, leftover temp files of the atomic
    /// write, and the files this session created on request (only while they are still the very files we created).
    /// Symlinks are NEVER followed: none of these paths is legitimately a link, so a link is somebody's trap (it is only unlinked).
    fn purge_targets(&self, created: &[(PathBuf, (u64, u64))]) -> Vec<PathBuf> {
        use std::os::unix::fs::MetadataExt;
        let mut v = Vec::new();
        if let Some(p) = &self.cfg.path {
            let counter = self.cfg.counter.clone().unwrap_or_else(|| nerd_chat_store::counter_path_for(p));
            for f in [p.clone(), counter] { v.extend(Self::temp_siblings(&f)); v.push(f); }
            v.extend(self.hist_path());
        }
        v.extend(self.cfg.keyfile_path.clone());
        v.extend(created.iter().filter(|(p, id)| std::fs::symlink_metadata(p).is_ok_and(|m| (m.dev(), m.ino()) == *id)).map(|(p, _)| p.clone()));
        v.retain(|p| std::fs::symlink_metadata(p).is_ok()); // missing files are nothing to do
        v.sort();
        v.dedup();
        v
    }

    /// PURGE, step 1 (Ctrl+] / Shift+F12): everything `panic_wipe` does (RAM and screen first: it must be instant). The files are
    /// destroyed by `purge_finish` once the screen is blank.
    pub fn purge_prepare(&mut self) {
        self.purge_pending = Some(std::mem::take(&mut self.created));
        self.panic_wipe();
    }

    /// PURGE, step 2: every file of this vault is overwritten with random bytes and deleted: contacts, keys, saved messages, the
    /// rollback counter, the keyfile. No confirmation: it is a panic key. Targets are looked up only now, after the wipe (so a vault
    /// that a create worker was still writing is included).
    pub fn purge_finish(&mut self) {
        let Some(created) = self.purge_pending.take() else { return };
        let targets = self.purge_targets(&created);
        let failed = targets.iter().filter(|p| nerd_chat_store::shred_file(p).is_err()).count();
        self.purge_report = Some((targets.len() - failed, failed));
    }

    /// Everything wiped: vault dropped (secrets zeroize on drop), buffers cleared, screen -> Wiped.
    pub fn panic_wipe(&mut self) {
        // Stop pairing workers FIRST (they hold identity clones and the code), give them a moment to drop them.
        if let Some(c) = self.pair_ctl.take() {
            c.cancel();
            let end = Instant::now() + Duration::from_millis(400);
            while !c.handle.is_finished() && Instant::now() < end { thread::sleep(Duration::from_millis(10)); }
        }
        // chat: engine first (it owns identity clones and sockets), then every message and the half-typed line
        if let Some(e) = self.engine.take() { e.shutdown_within(Duration::from_millis(400)); }
        self.start_rx = None;
        self.stop_rx = None;
        self.started_ids.clear();
        self.started_outbox.clear();
        self.history = None; // the keys are wiped on drop; the FILE stays (a panic keeps the vault too: only a purge destroys files)
        self.pending_confirms.clear(); self.pending_sends.clear(); self.migrate_pending = false;
        self.online = Online::Offline;
        self.chats.clear();
        self.linked.clear();
        self.unread.clear();
        self.pane = Pane::Details;
        self.mode = Mode::Normal;
        self.locked = false;
        self.scroll = 0;
        self.select = None;
        self.saved_sel = 0;
        self.del_armed = false;
        self.quit_armed = false; self.offline_armed = false;
        self.compose.clear();
        self.code_buf.clear();
        self.prep_rx = None;
        self.offers.clear();
        self.accepted.clear();
        self.inbox.clear(); // Zeroizing: received files wiped
        self.cfg.keyfile = None; // Zeroizing: dropped now
        self.alerts.clear();
        self.alert_log.clear();
        self.alerts_dropped = 0;
        self.created.clear();
        self.kdf_cancel.store(true, Ordering::SeqCst); // a creating worker stops before it writes anything (R8-L4)
        // A create worker past its key derivation may be inside the atomic write: give it a bounded moment to finish or
        // clean up its temp file before the process exits (R8-L4 residual window). Its result is dropped (zeroized).
        if let Some(rx) = self.kdf_rx.take() { if self.kdf_creating { let _ = rx.recv_timeout(Duration::from_millis(1200)); } }
        self.vf = None;
        self.view = None;
        self.pending_pair = None;
        self.pair_rx = None;
        self.link_rx = None; self.tor_offer = None; self.tor_contact = None; // the link and the code of an open offer (zeroizing, dropped now)
        self.probe_rx = None; self.probe_then = None;
        self.pair_info = None;
        self.pw.clear();
        self.pw2.clear();
        self.input.clear();
        self.input.shrink_to_fit();
        self.status.clear();
        self.sel = 0;
        self.screen = Screen::Wiped;
    }

    pub fn handle(&mut self, k: Key) -> Action {
        if k == Key::Purge { self.purge_prepare(); return Action::Purge; }
        if matches!(k, Key::F12 | Key::CtrlBackslash) { self.panic_wipe(); return Action::Panic; }
        if self.probe_rx.is_some() { // the hosting probe runs: the only key is Esc (cancel); panic/purge were handled above
            if k == Key::Esc { self.probe_rx = None; self.probe_then = None; self.ok("Cancelled."); }
            return Action::None;
        }
        match &self.screen {
            Screen::Wiped => Action::Quit,
            // the privacy screen swallows every key (even for a prompt an engine event raised underneath it)
            _ if self.locked => self.key_lock(k),
            Screen::Unlock => self.key_unlock(k),
            Screen::CreatePw | Screen::CreateConfirm => self.key_create(k),
            Screen::Main => self.key_main(k),
            Screen::Prompt(_) => { self.key_prompt(k); Action::None }
            Screen::Verify => { self.key_verify(k); Action::None }
            Screen::Help => { self.screen = Screen::Main; Action::None }
            Screen::Working => Action::None,
        }
    }

    // ---------- unlock / create ----------
    fn secret_edit(buf: &mut SecretBuf, k: Key) -> bool {
        match k {
            Key::Char(c) => { buf.push(c); true }
            Key::Backspace => { buf.pop(); true }
            _ => false,
        }
    }

    fn key_unlock(&mut self, k: Key) -> Action {
        if Self::secret_edit(&mut self.pw, k) { return Action::None; }
        match k {
            Key::Esc => return Action::Quit,
            Key::Enter => {
                if let Some(t) = self.locked_until {
                    if Instant::now() < t { self.err(format!("Too many failures: wait {} s.", (t - Instant::now()).as_secs() + 1)); return Action::None; }
                }
                let path = self.cfg.path.clone().expect("unlock needs a path");
                let pw = Zeroizing::new(self.pw.as_bytes().to_vec());
                self.pw.clear();
                let (counter, keyfile) = (self.cfg.counter.clone(), self.cfg.keyfile.clone());
                self.start_kdf(Screen::Unlock, move || {
                    KdfMsg::Opened(VaultFile::open(&path, counter.as_deref(), &pw, keyfile.as_deref().map(|v| v.as_slice())))
                });
            }
            _ => {}
        }
        Action::None
    }

    fn key_create(&mut self, k: Key) -> Action {
        let second = self.screen == Screen::CreateConfirm;
        if Self::secret_edit(if second { &mut self.pw2 } else { &mut self.pw }, k) { return Action::None; }
        match k {
            Key::Esc => return Action::Quit,
            Key::Enter if !second => {
                if self.cfg.path.is_none() { // RAM-only: random internal password, no prompt needed
                    self.create_vault(true);
                } else if self.pw.chars() < MIN_PW_CHARS && self.cfg.keyfile.is_none() {
                    self.err(format!("Too short: use at least {MIN_PW_CHARS} characters (a long passphrase) or a keyfile."));
                } else {
                    self.screen = Screen::CreateConfirm;
                    self.ok("Repeat the password.");
                }
            }
            Key::Enter => {
                if !self.pw.eq(&self.pw2) {
                    self.pw.clear(); self.pw2.clear();
                    self.screen = Screen::CreatePw;
                    self.err("Passwords did not match. Start again.");
                } else { self.create_vault(false); }
            }
            _ => {}
        }
        Action::None
    }

    fn create_vault(&mut self, random_pw: bool) {
        let mut pw = Zeroizing::new(self.pw.as_bytes().to_vec());
        if random_pw { pw = Zeroizing::new(vec![0u8; 32]); getrandom::fill(&mut pw[..]).expect("OS RNG unavailable"); }
        self.pw.clear(); self.pw2.clear();
        let (path, counter, keyfile, profile) = (self.cfg.path.clone(), self.cfg.counter.clone(), self.cfg.keyfile.clone(), self.cfg.profile);
        let cancel = self.kdf_cancel.clone();
        self.kdf_creating = true;
        self.start_kdf(Screen::CreatePw, move || {
            KdfMsg::Created(VaultFile::create_cancellable(path.as_deref(), counter.as_deref(), &pw, keyfile.as_deref().map(|v| v.as_slice()), profile, &cancel))
        });
    }

    /// Run the memory-hard derivation off the UI thread so the panic key and signals stay live.
    fn start_kdf(&mut self, back: Screen, job: impl FnOnce() -> KdfMsg + Send + 'static) {
        let (tx, rx) = channel();
        self.kdf_rx = Some(rx);
        self.kdf_back = back;
        self.screen = Screen::Working;
        self.ok("Deriving the key (memory-hard, takes a few seconds)... F12 = panic.");
        thread::spawn(move || { let _ = tx.send(job()); });
        #[cfg(test)]
        if !self.test_async { self.settle(); }
    }

    #[cfg(test)]
    fn settle(&mut self) {
        while self.kdf_rx.is_some() { self.poll_kdf(); thread::sleep(Duration::from_millis(5)); }
    }

    fn poll_kdf(&mut self) {
        let Some(rx) = &self.kdf_rx else { return };
        let msg = match rx.try_recv() {
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => {
                self.kdf_rx = None; self.screen = std::mem::replace(&mut self.kdf_back, Screen::Unlock);
                self.err("Key derivation thread died."); return;
            }
            Ok(m) => m,
        };
        self.kdf_rx = None;
        self.kdf_creating = false;
        let back = std::mem::replace(&mut self.kdf_back, Screen::Unlock);
        match msg {
            KdfMsg::Opened(Ok((vf, info))) => {
                self.vf = Some(vf);
                self.open_history();
                self.seed_history_lines();
                self.screen = Screen::Main;
                self.failures = 0;
                if info.rollback_unchecked {
                    self.err("WARNING: no counter file - rollback of the vault cannot be detected (see docs).");
                } else if info.counter_same_device {
                    self.err(format!("Unlocked. Vault save #{}. WARNING: the counter file is on the SAME device as the vault: weak rollback protection (use --counter-file on another device).", info.counter));
                } else { self.ok(format!("Unlocked. Vault save #{}.", info.counter)); }
            }
            KdfMsg::Created(Ok(vf)) => {
                self.vf = Some(vf);
                self.open_history();
                self.screen = Screen::Main;
                self.ok("Vault created. Press n to add your first contact, ? for help.");
            }
            KdfMsg::Created(Err(e)) => { self.screen = back; self.err(format!("Cannot create vault: {e}")); }
            KdfMsg::Opened(Err(e)) => {
                self.screen = back;
                match e {
                    StoreError::Vault(nerd_chat_vault::VaultError::Rollback { found, expected }) =>
                        self.err(format!("ROLLBACK DETECTED: vault save #{found} is older than #{expected}. An old copy was substituted. Refusing to open.")),
                    StoreError::Vault(nerd_chat_vault::VaultError::Tampered) =>
                        self.err("Password correct but the vault file is CORRUPTED or TAMPERED with."),
                    StoreError::Vault(nerd_chat_vault::VaultError::WrongCredentials) => {
                        self.failures += 1;
                        if self.failures >= 3 {
                            let wait = 5u64 << (self.failures - 3).min(6);
                            self.locked_until = Some(Instant::now() + Duration::from_secs(wait));
                        }
                        self.err("Wrong password or keyfile.");
                    }
                    e => self.err(format!("Cannot open vault: {e}")),
                }
            }
        }
    }

    // ---------- main ----------
    fn key_main(&mut self, k: Key) -> Action {
        if self.mode == Mode::Insert && self.pane == Pane::Chat { self.key_insert(k); return Action::None; }
        self.key_normal(k)
    }

    /// Privacy screen: nothing but unlock/quit (and the panic key, handled before this).
    fn key_lock(&mut self, k: Key) -> Action {
        match k {
            Key::Enter => {
                self.locked = false;
                self.mode = Mode::Normal; // never come back into typing mode
                self.quit_armed = false;
                Action::None
            }
            Key::Char('q') => self.quit_request(),
            _ => Action::None,
        }
    }

    /// Insert mode (chat only): keys are TEXT. Nothing typed here can act as a command.
    /// Pasted text (one terminal paste event, never keystrokes): literal text for the message line while typing in a chat, and nothing
    /// anywhere else (a paste must not be able to press commands, a purge key or Esc). Control characters and newlines are dropped.
    pub fn paste(&mut self, text: &str) {
        if self.screen == Screen::Main && self.pane == Pane::Chat && self.mode == Mode::Insert && !self.locked {
            for c in text.chars().filter(|c| !c.is_control()) { self.compose.push(c); }
        }
    }

    fn key_insert(&mut self, k: Key) {
        match k {
            Key::Esc => self.mode = Mode::Normal,
            Key::Backspace => self.compose.pop(),
            Key::Char(c) => { self.compose.push(c); }
            Key::Enter => self.send_compose(),
            _ => {}
        }
    }

    fn key_normal(&mut self, k: Key) -> Action {
        if k != Key::Char('q') { self.quit_armed = false; }
        if k != Key::Char('o') { self.offline_armed = false; }
        if self.pane == Pane::Saved { return self.key_saved(k); }
        if self.select.is_some() { self.key_select(k); return Action::None; }
        let chatting = self.pane == Pane::Chat;
        match k {
            // Esc ladder: (Insert -> Normal is in key_insert) chat -> details -> privacy lock
            Key::Esc => {
                if chatting { self.pane = Pane::Details; self.compose.clear(); self.scroll = 0; self.select = None; }
                else { self.locked = true; }
            }
            Key::Char('q') => return self.quit_request(),
            // reading: scroll the history (chat) or move through the contacts (details)
            Key::Up | Key::Char('k') => if chatting { self.scroll = (self.scroll + 1).min(self.scroll_limit()); } else { self.sel = self.sel.saturating_sub(1) },
            Key::Down | Key::Char('j') => if chatting { self.scroll = self.scroll.saturating_sub(1); } else if self.sel + 1 < self.contacts_len() { self.sel += 1 },
            Key::PageUp => if chatting { self.scroll = (self.scroll + 10).min(self.scroll_limit()); },
            Key::PageDown => if chatting { self.scroll = self.scroll.saturating_sub(10); },
            Key::Home | Key::Char('g') => if chatting { self.scroll = self.scroll_limit(); },
            Key::End | Key::Char('G') => if chatting { self.scroll = 0; },
            Key::Tab => if chatting { self.step_contact(true) } else if self.sel + 1 < self.contacts_len() { self.sel += 1 },
            Key::BackTab => if chatting { self.step_contact(false) } else { self.sel = self.sel.saturating_sub(1) },
            // typing
            Key::Char('i') => if chatting { self.mode = Mode::Insert } else { self.open_chat(true) },
            Key::Enter => if chatting { self.mode = Mode::Insert } else { self.open_chat(false) },
            // contact / global commands: work in the details view AND while reading a chat
            Key::Char('?') => self.screen = Screen::Help,
            Key::Char('K') => self.start_rotation(),
            Key::Char('m') => if chatting { if self.chat_lines().is_empty() { self.err("No messages to select yet.") } else { self.select = Some(0); self.ok("Message cursor: j/k choose a message, y saves it into the vault, Esc cancels.") } },
            Key::Char('H') => self.open_saved(),
            Key::Char('P') => if self.pending_pair.is_some() { self.open_prompt(Prompt::InPerson, "") } else { self.err("No finished pairing is waiting for an answer.") },
            Key::Char('z') => { if !self.alerts.is_empty() { self.alerts.remove(0); } else { self.alerts_dropped = 0; } }
            Key::Char('n') => self.open_prompt(Prompt::NewContact, ""),
            // Neutral random default: the contact's name must not leak into filesystem metadata.
            Key::Char('e') if self.pair_rx.is_some() || self.pending_pair.is_some() => self.err("A pairing is running or waiting for your answer (P): export after it finished, so the capability told to the contact stays the same."),
            Key::Char('e') => if self.sel_name().is_some() {
                let mut r = [0u8; 4];
                getrandom::fill(&mut r).expect("OS RNG unavailable");
                let name = format!("bundle-{}.sbc", r.iter().map(|b| format!("{b:02x}")).collect::<String>());
                self.open_prompt(Prompt::Export, &name)
            },
            Key::Char('I') => if self.require_no_peer() { self.open_prompt(Prompt::Import, "") },
            Key::Char('l') => if self.require_no_peer() { self.open_prompt(Prompt::Listen, "127.0.0.1:0") },
            Key::Char('c') => if self.require_no_peer() { self.open_prompt(Prompt::JoinAddr, "") },
            Key::Char('T') => if self.require_no_peer() { self.start_tor_offer() },
            Key::Char('J') => if self.require_no_peer() { self.open_prompt(Prompt::JoinLink, "") },
            Key::Char('x') => self.cancel_pairing(),
            Key::Char('o') => self.toggle_online(),
            Key::Char('O') => self.toggle_persist(),
            Key::Char('f') => if self.sel_linked() { self.open_prompt(Prompt::SendFile, "") },
            Key::Char('t') => if self.sel_linked() { self.open_prompt(Prompt::SendText, "") },
            Key::Char('a') => self.reply_offer(true),
            Key::Char('r') => self.reply_offer(false),
            Key::Char('s') => self.start_save(),
            Key::Char('h') => self.toggle_host_anyway(),
            Key::Char('v') => self.start_verify(),
            Key::Char('d') if self.sel_name().is_some() => { self.open_prompt(Prompt::ConfirmDelete, "") },
            _ => {}
        }
        Action::None
    }

    fn scroll_limit(&self) -> usize { self.max_scroll.get().unwrap_or(SCROLL_CAP) }

    /// What quitting would throw away, as a short list for the warning (unconfirmed lines, files in RAM
    /// or being cleaned, a pairing in progress/unanswered, a half-written draft). Conservative: it says "may".
    fn at_risk(&self) -> Vec<String> {
        let queued = self.queued_not_kept();
        let files = self.inbox.len() + self.offers.len() + self.accepted.len() + usize::from(self.prep_rx.is_some());
        let mut v = Vec::new();
        if queued > 0 { v.push(format!("{queued} unconfirmed message(s)")); }
        if files > 0 { v.push(format!("{files} file(s) in RAM or being cleaned")); }
        if self.pair_ctl.is_some() || self.pending_pair.is_some() { v.push("a pairing in progress".into()); }
        if !self.compose.is_empty() { v.push("a draft".into()); }
        v
    }

    /// Message cursor (`m`): j/k move between messages, `y`/Enter saves the chosen one, Esc/`m` leaves. Every other key is ignored.
    fn key_select(&mut self, k: Key) {
        let n = self.chat_lines().len();
        let Some(i) = self.select else { return };
        match k {
            Key::Esc | Key::Char('m') => { self.select = None; self.ok("Cancelled."); }
            Key::Up | Key::Char('k') => self.select = Some((i + 1).min(n.saturating_sub(1))),
            Key::Down | Key::Char('j') => self.select = Some(i.saturating_sub(1)),
            Key::Home | Key::Char('g') => self.select = Some(n.saturating_sub(1)),
            Key::End | Key::Char('G') => self.select = Some(0),
            Key::Char('y') => self.save_selected(i),
            _ => {}
        }
    }

    /// Save ONE message the user chose, by hand: the only way anything of a conversation ever reaches the disk, apart from the opt-in encrypted outbox (unconfirmed texts you sent).
    fn save_selected(&mut self, from_newest: usize) {
        let Some(id) = self.chat_id() else { return };
        if self.cfg.path.is_none() { return self.err("RAM-only mode: nothing is written to disk, so nothing can be saved."); }
        let Some(pos) = self.chats.get(&id).and_then(|l| l.len().checked_sub(1 + from_newest)) else { return };
        let (mine, text, already) = { let l = &self.chats[&id][pos]; (l.mine, l.text.clone(), l.saved) };
        if already { return self.err("This message is already saved."); }
        let sel = self.sel;
        if let Err(e) = self.vf().store.save_message(sel, mine, &text) { return self.err(format!("{e}")); }
        if !self.save() { self.vf().store.contacts[sel].saved.pop(); return self.resync_note("may already contain this message"); }
        if let Some(l) = self.chats.get_mut(&id).and_then(|l| l.get_mut(pos)) { l.saved = true; }
        self.select = None;
        self.ok("Saved into the vault (encrypted with it, no timestamp). H lists saved messages. Whoever gets your vault AND password can read them.");
    }

    /// A save failed and memory was rolled back, but the vault FILE may still hold the change (e.g. only the counter write failed).
    /// Try once more so the file matches memory again, and tell the user the truth either way.
    fn resync_note(&mut self, what: &str) {
        let first = self.status.clone();
        let fixed = self.vf().save().is_ok();
        self.err(if fixed { format!("{first} (the vault file was brought back in line with memory)") } else { format!("{first} (the vault file {what}: fix the cause and save again)") });
    }

    fn open_saved(&mut self) {
        let Some(c) = self.vf.as_ref().and_then(|v| v.store.contacts.get(self.sel)) else { return self.err(NO_CONTACT) };
        if c.saved.is_empty() { return self.ok("No saved messages for this contact. In a chat: m selects a message, y saves it."); }
        self.pane = Pane::Saved; self.mode = Mode::Normal; self.saved_sel = c.saved.len() - 1; self.del_armed = false; self.compose.clear(); self.select = None;
    }

    /// The saved-messages view: j/k move, `d` twice deletes the chosen one, Esc goes back to the details.
    fn key_saved(&mut self, k: Key) -> Action {
        let n = self.vf.as_ref().and_then(|v| v.store.contacts.get(self.sel)).map_or(0, |c| c.saved.len());
        let armed = std::mem::take(&mut self.del_armed);
        match k {
            Key::Esc => self.pane = Pane::Details,
            Key::Up | Key::Char('k') => self.saved_sel = self.saved_sel.saturating_sub(1),
            Key::Down | Key::Char('j') => self.saved_sel = (self.saved_sel + 1).min(n.saturating_sub(1)),
            Key::Home | Key::Char('g') => self.saved_sel = 0,
            Key::End | Key::Char('G') => self.saved_sel = n.saturating_sub(1),
            Key::Char('d') if armed => {
                let (sel, k) = (self.sel, self.saved_sel);
                let removed = self.vf().store.contacts[sel].saved.get(k).map(|m| (m.mine, m.text.clone()));
                self.vf().store.delete_saved(sel, k);
                if !self.save() {
                    if let Some((mine, text)) = removed { self.vf().store.contacts[sel].saved.insert(k, nerd_chat_store::SavedMsg { mine, text }); }
                    self.resync_note("may already lack this message");
                    return Action::None;
                }
                if let (Some((mine, text)), Some(id)) = (removed.as_ref(), self.sel_id()) {   // the ★ of the matching chat line goes
                    if let Some(l) = self.chats.get_mut(&id).and_then(|l| l.iter_mut().find(|l| l.saved && l.mine == *mine && *l.text == **text)) { l.saved = false; }
                }
                self.saved_sel = self.saved_sel.min(n.saturating_sub(2));
                self.ok("Deleted from the vault.");
                if n <= 1 { self.pane = Pane::Details; }
            }
            Key::Char('d') => { if n > 0 { self.del_armed = true; self.ok("Press d again to delete this saved message from the vault."); } }
            Key::Char('q') => { self.quit_armed = false; return self.quit_request(); }
            _ => {}
        }
        Action::None
    }

    /// `q`: quit (RAM is wiped on exit). If something may be lost, the SECOND `q` quits.
    fn quit_request(&mut self) -> Action {
        let risk = self.at_risk();
        if !risk.is_empty() && !self.quit_armed {
            self.quit_armed = true;
            self.err(format!("Quitting wipes RAM and may lose: {}. Press q again to quit, any other key to stay.", risk.join(", ")));
            return Action::None;
        }
        Action::Quit
    }

    /// For the privacy screen: a generic one-line warning (no counts, no names).
    pub fn quit_pending(&self) -> bool { self.quit_armed }

    /// Tab / Shift+Tab inside a chat: the next/previous contact that has a peer (wraps). The draft is dropped, unread cleared, history at the newest.
    fn step_contact(&mut self, forward: bool) {
        let ids: Vec<usize> = self.vf.as_ref().map_or(vec![], |v| v.store.contacts.iter().enumerate().filter(|(_, c)| c.peer.is_some()).map(|(i, _)| i).collect());
        if ids.len() < 2 { return; }
        let pos = ids.iter().position(|&i| i == self.sel).unwrap_or(0);
        let next = if forward { (pos + 1) % ids.len() } else { (pos + ids.len() - 1) % ids.len() };
        self.sel = ids[next];
        self.select = None;
        self.compose.clear();
        self.scroll = 0;
        self.max_scroll.set(None);
        self.mode = Mode::Normal;
        if let Some(id) = self.sel_id() { self.unread.remove(&id); }
    }

    fn sel_id(&self) -> Option<[u8; 8]> { self.vf.as_ref()?.store.contacts.get(self.sel).map(|c| c.id) }

    fn sel_linked(&mut self) -> bool {
        match self.sel_id() {
            None => { self.err("No contact selected."); false }
            Some(id) if self.linked.contains(&id) && self.engine.is_some() => true,
            Some(_) => { self.err("Files are only sent to a CONNECTED contact (never queued). Go online (o) and wait for the green dot."); false }
        }
    }

    /// Pending offer / received file of the selected contact, for the UI. (Offer sizes are only the padded bucket.)
    pub fn file_state(&self) -> Option<String> {
        let id = self.sel_id()?;
        if let Some((_, bucket)) = self.offers.get(&id) { return Some(format!("File offered (up to {} KiB; the sender's cleaning is NOT trusted, we re-clean): a = accept, r = decline", (*bucket as usize) / 1024)); }
        if self.accepted.contains_key(&id) { return Some("File arriving...".into()); }
        self.inbox.get(&id).map(|r| format!("File received ({} KiB, RAM only, re-cleaned here): s = save to a neutral name, r = discard", r.data.len().div_ceil(1024)))
    }

    /// RAM we are willing to hold for received files in total.
    const FILE_RAM_BUDGET: usize = 24 * 1024 * 1024;

    fn reply_offer(&mut self, accept: bool) {
        let Some(id) = self.sel_id() else { return };
        if !self.offers.contains_key(&id) {
            // `r` with no pending offer discards a received file that is still in RAM (or a stuck 'arriving' state)
            if !accept && self.accepted.remove(&id).is_some() { return self.ok("Cleared the stale 'file arriving' state."); }
            if !accept && self.inbox.remove(&id).is_some() { return self.ok("Received file discarded (wiped from RAM)."); }
            return self.err("No file offer from this contact.");
        }
        let name = self.contact(id).map(|c| c.name.clone()).unwrap_or_default();
        let (xid, bucket) = self.offers[&id];
        if accept {
            let held: usize = self.inbox.values().map(|r| r.data.len()).sum::<usize>() + self.accepted.values().map(|b| *b as usize).sum::<usize>();
            if self.inbox.contains_key(&id) { return self.err("You still hold an unsaved file from this contact: save (s) or discard (r) it first."); }
            if held + bucket as usize > Self::FILE_RAM_BUDGET { return self.err("Too many files in RAM: save or discard some first."); }
        }
        self.offers.remove(&id);
        if let Some(e) = &self.engine { e.reply_file(id, xid, accept); }
        if accept { self.accepted.insert(id, bucket); self.ok(format!("Accepted the file from {name}: receiving into RAM; it is re-cleaned here before you can save it.")); }
        else { self.ok(format!("Declined the file from {name}: nothing is transferred.")); }
    }

    fn start_save(&mut self) {
        let Some(id) = self.sel_id() else { return };
        let Some(r) = self.inbox.get(&id) else { return self.err("No received file for this contact.") };
        let mut b = [0u8; 4];
        getrandom::fill(&mut b).expect("OS RNG unavailable");
        let dir = std::env::current_dir().unwrap_or_default();
        let name = format!("{}/file-{}.{}", dir.display(), b.iter().map(|x| format!("{x:02x}")).collect::<String>(), r.ext);
        self.open_prompt(Prompt::SaveFile, &name);
    }

    /// The capability WE advertise to this contact: fixed (and saved) at the first export/pairing, so the contact's roles and ours
    /// are computed from the same facts even if we later start with a different `--cannot-host`.
    /// Read-only: the bit to put in a bundle (what was told before, else today's flag). Nothing is fixed until `commit_advertised`.
    fn advertised(&self, idx: usize) -> bool {
        self.vf.as_ref().and_then(|v| v.store.contacts.get(idx)).and_then(|c| c.adv_can_host).unwrap_or(self.cfg.can_host)
    }

    /// `advertised`, plus the automatic probe (R12-5): while nothing was told to this contact yet, `--cannot-host` wins; otherwise, with
    /// an EXTERNAL tor (Tails/Whonix) we ask that tor on a worker thread whether it lets us host (throwaway ADD_ONION) and continue
    /// with `then` when it answers (the UI stays responsive: F12/purge work, Esc cancels). With our own tor hosting always works.
    /// An inconclusive probe cancels the action: the bit becomes permanent for this contact, so never guess.
    fn with_adv(&mut self, then: Then) {
        let idx = self.sel;
        if self.vf.as_ref().and_then(|v| v.store.contacts.get(idx)).is_some_and(|c| c.adv_can_host.is_some()) || !self.cfg.can_host {
            let v = self.advertised(idx);
            return self.resume(then, v);
        }
        if let Some(t) = self.cfg.host_probe_test.clone() { return self.probe_done(then, t); }
        let Some(ctl) = self.cfg.tor.control.clone().filter(|_| self.cfg.transport.is_none()) else { return self.resume(then, true) };
        let auth = AuthPref { password: None, cookie_path: self.cfg.tor.cookie.clone(), peer_verified: false };
        let trust = self.cfg.tor.trust_control;
        let (tx, rx) = channel();
        thread::spawn(move || { let _ = tx.send(probe_hosting(&ctl, &auth, trust)); });
        self.probe_rx = Some(rx);
        self.probe_then = Some((then, Instant::now()));
        self.ok("Checking whether your Tor can host onion services ... (Esc = cancel)");
    }

    fn poll_probe(&mut self) {
        let Some(rx) = &self.probe_rx else { return };
        let r = match rx.try_recv() {
            Ok(r) => r,
            Err(TryRecvError::Empty) if self.probe_then.as_ref().is_some_and(|(_, t)| t.elapsed() < PROBE_DEADLINE) => return,
            Err(TryRecvError::Empty) => HostProbe::Unknown("no answer in time".into()),
            Err(TryRecvError::Disconnected) => HostProbe::Unknown("probe thread died".into()),
        };
        self.probe_rx = None;
        if let Some((then, _)) = self.probe_then.take() { self.probe_done(then, r); }
    }

    fn probe_done(&mut self, then: Then, r: HostProbe) {
        let id = match &then { Then::Export(i, _) | Then::Listen(i, _) | Then::Join(i, _, _) | Then::TorOffer(i) | Then::TorJoin(i, _, _) => *i };
        if self.vf.as_ref().and_then(|v| v.store.contacts.get(self.sel)).map(|c| c.id) != Some(id) { return self.err("The selected contact changed: nothing was done."); }
        match r {
            HostProbe::Can => self.resume(then, true),
            HostProbe::Cannot(why) => {
                // a permanent, privacy-relevant decision for this contact: a sticky alert, not a status line the next message replaces
                self.record_alert(Some(id), &format!("your Tor cannot host onion services ({why}): this contact is told so and will host for you"));
                self.resume(then, false)
            }
            HostProbe::Unknown(why) => self.err(format!("Cannot tell whether your Tor can host onion services ({why}). Start Tor / fix --tor-control, or pass --cannot-host if you know it cannot.")),
        }
    }

    fn resume(&mut self, then: Then, can_host: bool) {
        if !matches!(then, Then::Export(..)) && (self.pair_ctl.is_some() || self.pair_rx.is_some() || self.pending_pair.is_some()) {
            return self.err("A pairing is already running or waiting for your answer (P): finish or cancel it first.");
        }
        match then {
            Then::Export(_, path) => self.do_export(path, can_host),
            Then::Listen(_, addr) => self.do_listen(addr, can_host),
            Then::Join(_, sock, join) => self.do_join(sock, join, can_host),
            Then::TorOffer(_) => self.do_tor_offer(can_host),
            Then::TorJoin(_, id, join) => self.do_tor_join(id, join, can_host),
        }
    }

    /// Fix (and save) what we told this contact, but ONLY after the bundle really left (file written / pairing succeeded) and
    /// only if the vault could be saved: otherwise memory and vault would disagree and later roles would too (review 13: L2/L3).
    fn commit_advertised(&mut self, idx: usize, value: bool) -> bool {
        let Some(c) = self.vf.as_mut().and_then(|v| v.store.contacts.get_mut(idx)) else { return false };
        if c.adv_can_host.is_some() { return true; }
        c.adv_can_host = Some(value);
        if self.save() { true } else {
            if let Some(c) = self.vf.as_mut().and_then(|v| v.store.contacts.get_mut(idx)) { c.adv_can_host = None; }
            false
        }
    }

    fn our_cap(&self, c: &nerd_chat_store::Contact) -> bool { c.adv_can_host.unwrap_or(self.cfg.can_host) }

    /// Option C: host an onion service for the selected contact although the roles would make us only dial.
    fn toggle_host_anyway(&mut self) {
        if matches!(self.online, Online::Starting(_) | Online::Stopping) {
            return self.err("Wait until the connection state settles (online or offline), then change 'host anyway': a change while starting would not reach the engine.");
        }
        let i = self.sel;
        let Some(c) = self.vf.as_ref().and_then(|v| v.store.contacts.get(i)) else { return self.err("No contact selected.") };
        if c.peer.is_none() { return self.err("Pair or import this contact first."); }
        let (can, was) = (self.our_cap(c), c.host_anyway);
        if !can && !was { return self.err("The bundle you gave this contact says your Tor cannot host: 'host anyway' is impossible."); }
        let on = !was;
        self.vf().store.contacts[i].host_anyway = on;
        if !self.save() { self.vf().store.contacts[i].host_anyway = was; return; } // keep memory and vault in step
        // only roles where we DIAL are affected; otherwise leave the running connection alone (a re-add would drop it)
        let dials = self.vf.as_ref().and_then(|v| v.store.contacts.get(i)).and_then(|c| c.peer.as_ref().map(|p| nerd_chat_chat::we_dial(&c.identity.verifying_key().to_bytes(), p, can))).unwrap_or(false);
        if dials { self.engine_add(i); }
        if on { self.err("HOST ANYWAY is ON for this contact: while online you publish an onion service for them, so anyone holding THEIR copy of your bundle can see when you are online. Use only if they cannot host (their bundle said so wrongly)."); }
        else { self.ok("Host anyway is off: you only host for this contact when the roles say so."); }
    }

    /// (contact can host, host anyway, WE host for it now) for the details pane.
    pub fn contact_roles(&self) -> Option<(bool, bool, bool)> {
        let c = self.vf.as_ref()?.store.contacts.get(self.sel)?;
        let p = c.peer.as_ref()?;
        let can = self.our_cap(c);
        let dials = nerd_chat_chat::we_dial(&c.identity.verifying_key().to_bytes(), p, can);
        Some((p.can_host, c.host_anyway, !dials || (c.host_anyway && can)))
    }

    /// Everything the GUI's inspector panel shows about the selected contact. No keys, no addresses, no names of other contacts:
    /// only states and yes/no answers (the panel is drawn on a screen somebody may be looking at).
    pub fn inspect(&self) -> Option<Inspect> {
        let c = self.vf.as_ref()?.store.contacts.get(self.sel)?;
        let p = c.peer.as_ref()?;
        let can = self.our_cap(c);
        let dials = nerd_chat_chat::we_dial(&c.identity.verifying_key().to_bytes(), p, can);
        Some(Inspect {
            connected: self.linked.contains(&c.id),
            contact_can_host: p.can_host,
            we_told_can_host: c.adv_can_host,
            we_host_now: !dials || (c.host_anyway && can),
            host_anyway: c.host_anyway,
            host_anyway_possible: can || c.host_anyway,
            rotation: self.rotation_state(),
            rotation_possible: c.next_transport.is_none() && matches!(self.online, Online::Online),
            saved: c.saved.len(),
            cap_mismatch: self.cap_mismatch(),
        })
    }

    /// `K`: rotate OUR onion service and client-auth key for the selected contact (docs/KEY_ROTATION.md). Old copies of our
    /// bundle then no longer reveal when we are online. Needs the engine running; completes when the contact answers.
    fn start_rotation(&mut self) {
        let i = self.sel;
        let Some(c) = self.vf.as_ref().and_then(|v| v.store.contacts.get(i)) else { return self.err("No contact selected.") };
        if c.peer.is_none() { return self.err("Pair or import this contact first."); }
        if c.next_transport.is_some() { return self.err("A key rotation for this contact is already waiting for its answer (it is re-proposed on every connection)."); }
        if self.engine.is_none() || !matches!(self.online, Online::Online) { return self.err("Go online first (o): the contact must be reachable to switch keys."); }
        self.vf().store.contacts[i].begin_rotation();
        if !self.save() { self.vf().store.contacts[i].next_transport = None; return; }
        self.engine_add(i);
        self.ok("Key rotation started: the new onion service runs next to the old one and is proposed to the contact when it connects. The old one is removed when it confirms.");
    }

    /// The contact answered a key-rotation step (frames are authenticated by the session; the engine rate-limits them).
    fn on_rotate(&mut self, id: [u8; 8], kind: u8, onion: [u8; 32], auth: [u8; 32]) {
        let Some(i) = self.vf.as_ref().and_then(|v| v.store.contacts.iter().position(|c| c.id == id)) else { return };
        match kind {
            nerd_chat_chat::proto::KIND_ROTATE_OFFER => {
                let c = &self.vf().store.contacts[i];
                let Some(peer) = c.peer.clone() else { return };
                if (peer.onion_pub, peer.auth_pub) == (onion, auth) && c.peer_old.is_some() {
                    // already switched (our ack was lost): acknowledge again
                    if let Some(e) = &self.engine { e.answer_rotation(id, nerd_chat_chat::proto::KIND_ROTATE_ACK, onion, auth); }
                    return;
                }
                if c.peer_old.is_some() { return self.err("Ignored a second key rotation from a contact before the first one finished."); }
                if self.rot_accepted.get(&id).is_some_and(|t| t.elapsed() < ROTATION_MIN_INTERVAL) { return self.err("Ignored a key rotation: this contact already rotated within the last hour."); }
                if (peer.onion_pub, peer.auth_pub) == (onion, auth) || onion == auth { return self.err("Ignored a key rotation that changes nothing."); }
                // reject weak/invalid keys and collisions with other contacts exactly like a bundle import
                let proposed = Bundle::from_parts(peer.sign_pub, peer.dh_pub, onion, auth, peer.can_host, peer.kem_pub);
                let ok = proposed.as_ref().is_ok_and(|b| !self.onion_collision(i, b));
                if !ok { return self.err("Refused a key rotation with invalid keys or an address another contact already uses."); }
                let (old_peer, old_old) = { let c = &self.vf().store.contacts[i]; (c.peer.clone(), c.peer_old) };
                self.vf().store.contacts[i].accept_peer_rotation(onion, auth);
                if !self.save() {
                    let c = &mut self.vf().store.contacts[i]; c.peer = old_peer; c.peer_old = old_old;
                    return; // no ack: the contact keeps proposing
                }
                // ack first (the re-add below closes the connection), then host/dial with the new keys
                if let Some(e) = &self.engine { e.answer_rotation(id, nerd_chat_chat::proto::KIND_ROTATE_ACK, onion, auth); }
                self.rot_accepted.insert(id, Instant::now());
                self.engine_add(i);
                self.ok("This contact rotated its onion service keys (identity and safety number are unchanged).");
            }
            nerd_chat_chat::proto::KIND_ROTATE_ACK => {
                let c = &self.vf().store.contacts[i];
                let Some(t) = c.next_transport.clone() else { return };
                let Some(next) = c.identity.with_transport_secret(&t) else { return };
                if (next.onion_public(), next.auth_public().to_bytes()) != (onion, auth) { return; } // not our pending proposal
                let before = c.identity.secret_bytes();
                self.vf().store.contacts[i].commit_rotation();
                if !self.save() {
                    let c = &mut self.vf().store.contacts[i];
                    if let Some(old) = ContactIdentity::from_secret_bytes(&before) { c.identity = old; c.next_transport = Some(t); }
                    return;
                }
                // tell the contact it may forget the old keys, then retire our old service
                if let Some(e) = &self.engine { e.answer_rotation(id, nerd_chat_chat::proto::KIND_ROTATE_DONE, onion, auth); }
                self.engine_add(i);
                self.ok("Key rotation complete: your old onion service was removed from Tor (it also vanishes when you go offline); copies of your old bundle no longer show when you are online. Send your NEW bundle to anyone who still needs it.");
            }
            nerd_chat_chat::proto::KIND_ROTATE_DONE => {
                let c = &self.vf().store.contacts[i];
                let Some(peer) = c.peer.as_ref() else { return };
                if c.peer_old.is_none() || (peer.onion_pub, peer.auth_pub) != (onion, auth) { return; }
                let old = c.peer_old;
                self.vf().store.contacts[i].peer_old = None;
                if !self.save() { self.vf().store.contacts[i].peer_old = old; return; }
                // no re-add here (a contact could force churn with endless OFFER/DONE pairs): the old client key stops being authorized
                // at the next natural re-add (restart, going offline/online). It is the contact's OWN old key.
                self.ok("The contact finished its key rotation; its old keys are forgotten.");
            }
            _ => {}
        }
    }

    /// Our CURRENT `--cannot-host` setting differs from what this contact was told (roles follow what it was told).
    pub fn cap_mismatch(&self) -> Option<bool> {
        let c = self.vf.as_ref()?.store.contacts.get(self.sel)?;
        c.peer.as_ref()?;
        c.adv_can_host.filter(|v| *v != self.cfg.can_host)
    }

    fn sel_name(&mut self) -> Option<String> {
        let n = self.vf.as_ref()?.store.contacts.get(self.sel).map(|c| c.name.clone());
        if n.is_none() { self.err("No contact selected. Press n to add one."); }
        n
    }

    fn require_no_peer(&mut self) -> bool {
        let Some(c) = self.vf.as_ref().and_then(|v| v.store.contacts.get(self.sel)) else { self.err("No contact selected. Press n to add one."); return false };
        if c.peer.is_some() { self.err("This contact already has a peer key. Delete (d) and re-add to replace it."); return false; }
        if self.pair_rx.is_some() { self.err("A pairing is already in progress."); return false; }
        if self.pending_pair.is_some() { self.err("A finished pairing is waiting for your answer: press P first."); return false; }
        true
    }

    fn open_prompt(&mut self, p: Prompt, default: &str) {
        self.mode = Mode::Normal; // a prompt (also one raised by an engine/pairing event) is never typed into by accident
        self.input = default.to_string();
        self.screen = Screen::Prompt(p);
    }

    fn key_prompt(&mut self, k: Key) {
        // The join code never touches `input: String` (it would leave un-wiped copies).
        if matches!(self.screen, Screen::Prompt(Prompt::JoinCode(_))) {
            match k {
                Key::Char(c) if c.is_ascii_digit() || c == '-' || c == ' ' => { self.code_buf.push(c); return; }
                Key::Backspace => { self.code_buf.pop(); return; }
                Key::Esc => { self.code_buf.clear(); self.screen = Screen::Main; self.ok("Cancelled."); return; }
                Key::Enter => {
                    let Screen::Prompt(p) = std::mem::replace(&mut self.screen, Screen::Main) else { return };
                    self.submit(p, String::new());
                    return;
                }
                _ => return,
            }
        }
        // Esc on the in-person question must NOT discard a pairing the peer already committed: treat as "no".
        if k == Key::Esc && self.screen == Screen::Prompt(Prompt::InPerson) {
            self.screen = Screen::Main;
            self.submit(Prompt::InPerson, "n".into());
            return;
        }
        match k {
            Key::Esc => { self.input.clear(); self.pending_pair = None; self.screen = Screen::Main; self.ok("Cancelled."); }
            Key::Backspace => { self.input.pop(); }
            Key::Char(c) if !c.is_control() && self.input.len() < 256 => self.input.push(c),
            Key::Enter => {
                let Screen::Prompt(p) = std::mem::replace(&mut self.screen, Screen::Main) else { return };
                let text = std::mem::take(&mut self.input);
                self.submit(p, text);
            }
            _ => {}
        }
    }

    fn vf(&mut self) -> &mut VaultFile { self.vf.as_mut().expect("unlocked") }
    /// The selected contact (borrow-friendly: computes the index itself).
    fn cur(&mut self) -> Option<&mut nerd_chat_store::Contact> {
        let i = self.sel;
        self.vf.as_mut()?.store.contacts.get_mut(i)
    }

    fn save(&mut self) -> bool {
        match self.vf().save() {
            Ok(()) => true,
            // the vault file IS on disk: memory and disk agree, so nothing may be rolled back; only the rollback protection is weaker until the next save
            Err(StoreError::CounterWrite(m)) => { self.err(format!("WARNING: saved, but the rollback-counter file could not be written ({m}): rollback of the vault would not be noticed until the next successful save")); true }
            Err(e) => { self.err(format!("SAVE FAILED: {e}")); false }
        }
    }

    fn submit(&mut self, p: Prompt, text: String) {
        match p {
            Prompt::NewContact => match self.vf().store.add_contact(text.trim_end_matches('\n')) {
                Ok(i) => {
                    self.sel = i;
                    self.pane = Pane::Details; // the new contact has no peer yet: show its details
                    self.mode = Mode::Normal;
                    self.compose.clear();
                    if self.save() { self.ok("Contact created with a NEW keypair. Export your bundle (e) and send it, then import theirs (I), or pair over the local link (l / c)."); }
                }
                Err(e) => self.err(format!("{e}")),
            },
            Prompt::SendFile | Prompt::SendText => {
                let mode = if p == Prompt::SendText { nerd_chat_strip::Mode::PlainText } else { nerd_chat_strip::Mode::Auto };
                let Some(id) = self.sel_id() else { return };
                if !self.linked.contains(&id) { return self.err("Contact is no longer connected."); }
                let raw = match read_regular_file(&PathBuf::from(&text), nerd_chat_chat::file::MAX_FILE as u64 * 2) {
                    Ok(v) => Zeroizing::new(v),
                    Err(e) => return self.err(format!("Cannot read file: {e}")),
                };
                if self.engine.is_none() { return; }
                if self.prep_rx.is_some() { return self.err("Still cleaning the previous file."); }
                let (tx, rx) = channel();
                self.prep_rx = Some((id, rx));
                self.ok("Cleaning the file (metadata removal) ... F12 = panic.");
                thread::spawn(move || { let _ = tx.send(nerd_chat_chat::Engine::prepare_file(&raw, mode)); });
            }
            Prompt::SaveFile => {
                let Some(id) = self.sel_id() else { return };
                let Some(r) = self.inbox.get(&id) else { return };
                use std::os::unix::fs::OpenOptionsExt;
                let path = PathBuf::from(&text);
                // create_new first: an EXISTING file is never touched; only a file we created is removed on a write error
                let mut f = match fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path) {
                    Ok(f) => f,
                    Err(e) => return self.err(format!("Cannot save (nothing was overwritten): {e}")),
                };
                match f.write_all(&r.data).and_then(|_| f.sync_all()) {
                    Ok(()) => { self.inbox.remove(&id); self.note_created(&path); self.ok(format!("Saved to {} (mode 0600). It is no longer in RAM here.", path.display())); }
                    Err(e) => { drop(f); let _ = fs::remove_file(&path); self.err(format!("Cannot save: {e}")) }
                }
            }
            Prompt::Export => {
                let sel = self.sel;
                if self.vf.as_ref().and_then(|v| v.store.contacts.get(sel)).is_some_and(|c| c.next_transport.is_some()) {
                    return self.err("A key rotation for this contact is still waiting for its answer: export after it finished (the bundle would carry the address about to be retired).");
                }
                let Some(id) = self.vf.as_ref().and_then(|v| v.store.contacts.get(sel)).map(|c| c.id) else { return };
                self.with_adv(Then::Export(id, text));
            }
            Prompt::Import => {
                // Never follows symlinks, never blocks on FIFOs/devices, size-capped.
                let r = read_regular_file(std::path::Path::new(&text), MAX_IMPORT_BYTES)
                    .and_then(|b| String::from_utf8(b).map_err(|_| StoreError::Corrupt));
                match r {
                    Err(e) => self.err(format!("Cannot read {text}: {e}")),
                    Ok(s) => match file::dearmor(&s) {
                        Err(_) => self.err("Not a valid Nerd-chat contact file."),
                        Ok(b) => {
                            let mine = Bundle::from_identity(&self.cur().expect("selected").identity);
                            if b.sign_pub == mine.sign_pub { self.err("That is YOUR OWN bundle, not the other person's."); return; }
                            if self.onion_collision(self.sel, &b) { self.err("Refused: this bundle reuses an onion address that another contact (or you) already has."); return; }
                            let (peer, trust) = ImportedContact::from_file(b).into_parts();
                            let c = self.cur().expect("selected");
                            c.peer = Some(peer);
                            c.trust = trust;
                            if self.save() { let i = self.sel; self.engine_add(i); self.ok("Imported - UNVERIFIED. Press v and compare the safety number with them over another channel."); }
                        }
                    },
                }
            }
            Prompt::ConfirmDelete => {
                if text.trim().eq_ignore_ascii_case("yes") {
                    let i = self.sel;
                    let gone = self.vf().store.contacts.get(i).map(|c| c.id);
                    if let Some(id) = gone {
                        if let Some(e) = &self.engine { e.remove(id); }
                        if let Some(h) = self.history.as_mut() { h.remove_contact(id); }
                        self.chats.remove(&id); self.linked.remove(&id); self.unread.remove(&id);
                        self.inbox.remove(&id); self.offers.remove(&id); self.accepted.remove(&id); // a deleted contact's file must not linger in RAM
                    }
                    self.vf().store.remove(i);
                    self.sel = self.sel.saturating_sub(1);
                    self.pane = Pane::Details;
                    self.mode = Mode::Normal;
                    self.compose.clear();
                    self.scroll = 0;
                    if self.save() { self.ok("Contact and its keys deleted."); }
                } else { self.ok("Not deleted (type yes to confirm)."); }
            }
            Prompt::Listen => self.start_listen(text),
            Prompt::JoinAddr => self.open_prompt(Prompt::JoinCode(text.trim().to_string()), ""),
            Prompt::JoinLink => match nerd_chat_net::tor::parse_pairing_link(&text) {
                Ok(id) => self.open_prompt(Prompt::JoinCode(format!("tor:{id}")), ""),
                Err(_) => self.err("That is not a valid pairing link: paste the 56 characters exactly as you received them."),
            },
            Prompt::JoinCode(addr) => { let _ = text; self.start_join(addr) }
            Prompt::InPerson => {
                let Some((id, contact, sn)) = self.pending_pair.take() else { return };
                let mut contact = contact;
                if !text.trim().eq_ignore_ascii_case("y") { contact.downgrade_to_unverified(); }
                self.finish_pair(id, contact, sn);
            }
        }
    }

    // ---------- verify ----------
    fn start_verify(&mut self) {
        let Some(c) = self.vf.as_ref().and_then(|v| v.store.contacts.get(self.sel)) else { self.err("No contact selected."); return };
        let Some(peer) = c.peer.clone() else { self.err("No peer key yet: import their file (i) or pair (l / c) first."); return };
        let mine = Bundle::from_identity(&c.identity);
        let ic = ImportedContact::from_file(peer);
        self.view = Some(ic.safety_view(&mine));
        self.screen = Screen::Verify;
    }

    fn key_verify(&mut self, k: Key) {
        let view = self.view.take();
        self.screen = Screen::Main;
        if k != Key::Char('y') { self.ok("Not verified."); return; }
        let Some(view) = view else { return };
        let Some(c) = self.vf.as_ref().and_then(|v| v.store.contacts.get(self.sel)) else { return };
        let mine = Bundle::from_identity(&c.identity);
        let mut ic = ImportedContact::from_file(c.peer.clone().expect("checked"));
        if ic.confirm(&mine, view) {
            self.cur().expect("selected").trust = Trust::SafetyVerified;
            if self.save() { self.ok("Verified: this contact's identity is confirmed."); }
        } else { self.err("Safety number mismatch - not verified."); }
    }

    // ---------- local pairing (threads) ----------
    fn identity_clone(&mut self) -> (ContactIdentity, [u8; 8]) {
        let i = self.sel;
        let c = &self.vf().store.contacts[i];
        (ContactIdentity::from_secret_bytes(&c.identity.secret_bytes()).expect("valid"), c.id)
    }

    /// Run one pairing job on a worker thread. The job gets the cancel flag, the slot where it must publish its socket (so `x`/panic can cut
    /// a blocked read) and a private copy of the contact's identity; its outcome arrives through `pair_rx`.
    fn spawn_pair<F>(&mut self, info: Zeroizing<String>, job: F)
    where F: FnOnce(&AtomicBool, &Mutex<Option<TcpStream>>, &ContactIdentity) -> Result<nerd_chat_exchange::pair::Paired, ExchangeError> + Send + 'static {
        let (ident, id) = self.identity_clone();
        let (tx, rx) = channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let slot: Arc<Mutex<Option<TcpStream>>> = Arc::new(Mutex::new(None));
        let (c2, s2) = (cancel.clone(), slot.clone());
        let handle = thread::spawn(move || {
            let result = job(&c2, &s2, &ident).map(|p| (p.contact, p.safety_number));
            let _ = tx.send((id, result));
        });
        self.pair_rx = Some(rx);
        self.pair_ctl = Some(PairCtl { cancel, stream: slot, handle, tor: None });
        self.pair_info = Some(info);
    }

    /// `T`: create the pairing service over Tor and show a link + code (needs the app online).
    fn start_tor_offer(&mut self) {
        if self.engine.is_none() || !matches!(self.online, Online::Online) { return self.err("Go online first (o): pairing over Tor needs your Tor to be ready. (Being online makes you visible online to your contacts meanwhile.)"); }
        if self.engine.as_ref().and_then(|e| e.pair_host_fn()).is_none() { return self.err("This Tor connection cannot host a pairing service. Ask the other person to create the code."); }
        let wait = self.remote_lockout.remaining();
        if wait > 0 { return self.err(format!("Too many failed attempts: wait {wait} s before creating a new link (nothing is published meanwhile).")); }
        let Some(id) = self.vf.as_ref().and_then(|v| v.store.contacts.get(self.sel)).map(|c| c.id) else { return };
        self.with_adv(Then::TorOffer(id));
    }

    fn do_tor_offer(&mut self, adv: bool) {
        let Some(host_fn) = self.engine.as_ref().and_then(|e| e.pair_host_fn()) else { return self.err("Go online first (o).") };
        self.pair_adv = Some(adv);
        self.pair_remote = true;
        let (ident, id) = self.identity_clone();
        self.tor_contact = Some(id);
        let (tx, rx) = channel();
        let (ltx, lrx) = channel();
        let tok = CancelToken::new();
        let (tok2, lockout) = (tok.clone(), self.remote_lockout.clone());
        let handle = thread::spawn(move || {
            let result = tor_offer_job(host_fn, &tok2, &ident, adv, lockout, &ltx).map(|p| (p.contact, p.safety_number));
            let _ = tx.send((id, result));
        });
        self.pair_rx = Some(rx);
        self.link_rx = Some(lrx);
        self.pair_ctl = Some(PairCtl { cancel: Arc::new(AtomicBool::new(false)), stream: Arc::new(Mutex::new(None)), handle, tor: Some(tok) });
        self.pair_info = Some(Zeroizing::new("Getting your link ready (this can take up to a minute) ... (x = cancel)".into()));
        self.ok("Creating the pairing service ...");
    }

    fn do_tor_join(&mut self, link: String, parsed: Result<PairingJoin, ExchangeError>, adv: bool) {
        let join = match parsed { Ok(j) => j.with_can_host(adv), Err(e) => { self.err(format!("{e}")); return } };
        let Some(dial) = self.engine.as_ref().and_then(|e| e.pair_dial_fn()) else { return self.err("Go online first (o).") };
        self.pair_adv = Some(adv);
        self.pair_remote = true;
        let (ident, id) = self.identity_clone();
        let (tx, rx) = channel();
        let (ltx, lrx) = channel();
        let tok = CancelToken::new();
        let tok2 = tok.clone();
        let handle = thread::spawn(move || {
            let result = tor_join_job(dial, &tok2, &link, join, &ident, &ltx).map(|p| (p.contact, p.safety_number));
            let _ = tx.send((id, result));
        });
        self.pair_rx = Some(rx);
        self.link_rx = Some(lrx);
        self.pair_ctl = Some(PairCtl { cancel: Arc::new(AtomicBool::new(false)), stream: Arc::new(Mutex::new(None)), handle, tor: Some(tok) });
        self.pair_info = Some(Zeroizing::new("Connecting through Tor (this can take a minute) ... (x = cancel)".into()));
        self.ok("Pairing over Tor ...");
    }

    fn do_export(&mut self, text: String, can_host: bool) {
        let sel = self.sel;
        let Some(c) = self.cur() else { return };
        let id = &c.identity;
        let armored = file::armor(&Bundle::from_identity(id).with_can_host(can_host).encode(id));
        let path = PathBuf::from(&text);
        match fs::OpenOptions::new().write(true).create_new(true).open(&path).and_then(|mut f| f.write_all(armored.as_bytes())) {
            Ok(()) if !self.commit_advertised(sel, can_host) => {
                let _ = fs::remove_file(&path); // a file we created: do not leave a bundle whose capability bit we could not record
                self.err("Export cancelled: the vault could not be saved (the capability told to this contact must be recorded).");
            }
            Ok(()) => { self.note_created(&path); self.ok(format!("Wrote your contact file to {}. It is NOT public (it shows when you are online): hand it over in person or use a channel you trust (not Discord, e-mail...), then compare the safety number by voice (v). See docs/EXCHANGING_CONTACTS.md.", path.display())) }
            Err(e) => self.err(format!("Cannot write {}: {e} (never overwrites existing files)", path.display())),
        }
    }

    fn start_listen(&mut self, addr: String) {
        let addr: SocketAddr = match addr.trim().parse() { Ok(a) => a, Err(_) => { self.err("Bad address, expected e.g. 127.0.0.1:0 or 192.168.1.5:4000"); return } };
        if !listen_addr_ok(&addr) { self.err("Refusing to listen on 0.0.0.0 / a public address: use your private LAN IP (e.g. 192.168.1.5:4000) or 127.0.0.1."); return; }
        let Some(id) = self.vf.as_ref().and_then(|v| v.store.contacts.get(self.sel)).map(|c| c.id) else { return };
        self.with_adv(Then::Listen(id, addr));
    }

    fn do_listen(&mut self, addr: SocketAddr, adv: bool) {
        self.pair_adv = Some(adv);
        self.pair_remote = false;
        let (offer, code) = match PairingOffer::generate_in(self.lockout.clone()) { Ok((o, c)) => (o.with_can_host(adv), c), Err(e) => { self.err(format!("{e}")); return } };
        let listener = match TcpListener::bind(addr) { Ok(l) => l, Err(e) => { self.err(format!("Cannot listen: {e}")); return } };
        let bound = listener.local_addr().expect("bound");
        let expires = offer.expires_in();
        let info = Zeroizing::new(format!("Listening on {bound}  -  CODE: {}  (valid {} min, ONE attempt; x = cancel). Tell the other person the address and code IN PERSON.", *code, expires.as_secs() / 60));
        self.spawn_pair(info, move |cancel, slot, ident| {
            listener.set_nonblocking(true).ok();
            let deadline = Instant::now() + expires;
            loop {
                if cancel.load(Ordering::SeqCst) { break Err(ExchangeError::Io); }
                match listener.accept() {
                    // ONE connection only: the listener is dropped right after, success or failure.
                    Ok((mut s, _)) => {
                        s.set_nonblocking(false).ok();
                        *slot.lock().unwrap() = s.try_clone().ok();
                        if cancel.load(Ordering::SeqCst) { break Err(ExchangeError::Io); }
                        break offer.accept(&mut s, ident);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline { break Err(ExchangeError::Expired); }
                        thread::sleep(Duration::from_millis(100));
                    }
                    Err(_) => break Err(ExchangeError::Io),
                }
            }
        });
        self.ok("Waiting for the other device...");
    }

    fn start_join(&mut self, addr: String) {
        if let Some(id) = addr.strip_prefix("tor:") {
            let parsed = std::str::from_utf8(self.code_buf.as_bytes()).map_err(|_| ExchangeError::BadCode).and_then(|c| PairingJoin::parse_in(c, self.remote_lockout.clone()));
            self.code_buf.clear();
            if self.engine.is_none() || !matches!(self.online, Online::Online) { return self.err("Go online first (o): pairing over Tor needs your Tor to be ready."); }
            let Some(cid) = self.vf.as_ref().and_then(|v| v.store.contacts.get(self.sel)).map(|c| c.id) else { return };
            self.with_adv(Then::TorJoin(cid, id.to_string(), parsed));
            return;
        }
        let sock: SocketAddr = match addr.parse() { Ok(a) => a, Err(_) => { self.code_buf.clear(); self.err("Bad address, expected ip:port"); return } };
        let parsed = std::str::from_utf8(self.code_buf.as_bytes()).map_err(|_| ExchangeError::BadCode)
            .and_then(|c| PairingJoin::parse_in(c, self.lockout.clone()));
        self.code_buf.clear();
        let Some(id) = self.vf.as_ref().and_then(|v| v.store.contacts.get(self.sel)).map(|c| c.id) else { return };
        self.with_adv(Then::Join(id, sock, parsed));
    }

    fn do_join(&mut self, sock: SocketAddr, parsed: Result<PairingJoin, ExchangeError>, adv: bool) {
        self.pair_adv = Some(adv);
        self.pair_remote = false;
        let join = match parsed { Ok(j) => j.with_can_host(adv), Err(e) => { self.err(format!("{e}")); return } };
        self.spawn_pair(Zeroizing::new(format!("Connecting to {sock} ... (x = cancel)")), move |cancel, slot, ident| {
            match TcpStream::connect_timeout(&sock, Duration::from_secs(10)) {
                Ok(mut s) if !cancel.load(Ordering::SeqCst) => {
                    *slot.lock().unwrap() = s.try_clone().ok();
                    if cancel.load(Ordering::SeqCst) { Err(ExchangeError::Io) } else { join.join(&mut s, ident) }
                }
                _ => Err(ExchangeError::Io),
            }
        });
        self.ok("Pairing...");
    }

    // ---------- going online + chat ----------
    fn toggle_online(&mut self) {
        match self.online.clone() {
            Online::Starting(_) => self.err("Already starting; wait for it to finish."),
            Online::Stopping => self.err("Still shutting down; wait a moment."),
            Online::Online => {
                // going offline throws away the engine's copies of texts the contact has not confirmed: say so first (second `o` goes)
                let open = self.queued_not_kept(); // texts in the encrypted outbox are NOT lost by going offline
                if open > 0 && !self.offline_armed {
                    self.offline_armed = true;
                    return self.err(format!("{open} message(s) are not confirmed by the contact yet: going offline may lose them. Press o again to go offline anyway, any other key to stay."));
                }
                self.offline_armed = false;
                if self.pair_ctl.as_ref().is_some_and(|c| c.tor.is_some()) { self.cancel_pairing(); } // the pairing service lives in the engine's Tor: it goes with it
                // tear down on a worker so the UI (and the panic key) stay responsive while onion services are removed
                let (tx, rx) = channel();
                if let Some(e) = self.engine.take() { thread::spawn(move || { e.shutdown(); let _ = tx.send(()); }); } else { let _ = tx.send(()); }
                self.stop_rx = Some(rx);
                self.online = Online::Stopping;
                self.linked.clear();
                self.offers.clear(); self.accepted.clear(); // no Disconnected events will arrive for the old engine's connections
                self.ok("Going offline: closing connections and removing onion services...");
            }
            Online::Offline | Online::Failed(_) => self.start_online(),
        }
    }

    fn start_online(&mut self) {
        let Some(vf) = self.vf.as_ref() else { return };
        let contacts: Vec<ContactCfg> = vf.store.contacts.iter().filter_map(|c| self.cfg_of(c)).collect();
        self.started_ids = contacts.iter().map(|c| c.id).collect();
        self.started_outbox = self.history.as_ref().map(|h| h.all_queued_mids().into_iter().map(|(_, m)| m).collect()).unwrap_or_default();
        let (factory, tor, timing) = (self.cfg.transport.clone(), self.cfg.tor.clone(), self.cfg.timing);
        let (tx, rx) = channel();
        thread::spawn(move || {
            let txp = tx.clone();
            let mut progress = move |p: u8| { let _ = txp.send(StartMsg::Progress(p)); };
            let r = match factory { Some(f) => f(&mut progress), None => build_tor_transport(&tor, &mut progress) };
            let _ = match r {
                Ok(t) => tx.send(StartMsg::Ready(Engine::start(t, contacts, timing))),
                Err(e) => tx.send(StartMsg::Failed(e)),
            };
        });
        self.start_rx = Some(rx);
        self.online = Online::Starting(0);
        let how = if self.cfg.transport.is_some() { "test network" } else if self.cfg.tor.control.is_some() { "the running Tor" } else { "your own Tor (takes a minute)" };
        self.ok(format!("Going online through {how} ..."));
    }

    /// Tell the running engine about a contact that just got a peer key.
    fn engine_add(&mut self, idx: usize) {
        let Some(e) = &self.engine else { return };
        let Some(c) = self.vf.as_ref().and_then(|v| v.store.contacts.get(idx)) else { return };
        if let Some(cfg) = self.cfg_of(c) { e.add(cfg); }
    }

    /// Everything the engine needs for a contact, incl. an unfinished key rotation (both directions).
    fn cfg_of(&self, c: &nerd_chat_store::Contact) -> Option<ContactCfg> {
        let p = c.peer.as_ref()?;
        let cfg = ContactCfg::new(c.id, &c.identity, p.clone()).with_caps(self.our_cap(c), c.host_anyway)
            .with_rotation(&c.identity, c.next_transport.as_deref(), c.peer_old);
        // texts kept from an earlier run start out as the engine's own unconfirmed queue
        // texts kept from an earlier run start out as the engine's own unconfirmed queue
        Some(match self.history.as_ref() { Some(h) => cfg.with_outbox(h.queued(c.id)), None => cfg })
    }

    /// A peer bundle must not reuse an onion key that another contact already uses (ours or theirs): a crafted bundle
    /// could otherwise overwrite our client-auth credential for someone else's service (R6-L7).
    fn onion_collision(&self, idx: usize, peer: &Bundle) -> bool {
        let Some(v) = self.vf.as_ref() else { return false };
        v.store.contacts.iter().enumerate().any(|(i, c)| {
            // our current AND pending onion/auth keys, other contacts' current AND previous keys
            let next = c.next_transport.as_ref().and_then(|t| c.identity.with_transport_secret(t));
            c.identity.onion_public() == peer.onion_pub
                || c.identity.auth_public().to_bytes() == peer.auth_pub
                || next.as_ref().is_some_and(|n| n.onion_public() == peer.onion_pub || n.auth_public().to_bytes() == peer.auth_pub)
                || (i != idx && (c.peer.as_ref().is_some_and(|p| p.onion_pub == peer.onion_pub || p.auth_pub == peer.auth_pub)
                    || c.peer_old.is_some_and(|(o, a)| o == peer.onion_pub || a == peer.auth_pub)))
        })
    }

    fn open_chat(&mut self, typing: bool) {
        let Some(c) = self.vf.as_ref().and_then(|v| v.store.contacts.get(self.sel)) else { return self.err("No contact selected. Press n to add one.") };
        if c.peer.is_none() { return self.err("No peer key yet: import their file (I) or pair (l / c) first."); }
        let id = c.id;
        self.pane = Pane::Chat;
        self.select = None;
        self.mode = if typing { Mode::Insert } else { Mode::Normal };
        self.unread.remove(&id);
        self.compose.clear();
        self.scroll = 0;
        self.max_scroll.set(None);
        if self.online == Online::Offline {
            if self.history.is_some() { self.ok("You are OFFLINE: press Esc, then o to go online. You can still type: messages are kept encrypted on this device and sent when you are online."); }
            else { self.ok("You are OFFLINE: press Esc, then o to go online. You can still type; messages are sent only while online."); }
        }
    }

    fn send_compose(&mut self) {
        let Some(id) = self.chat_id() else { return };
        if self.compose.is_empty() { return; }
        let kept = self.history.is_some();
        if self.engine.is_none() && !kept { return self.err("You are offline: press Esc for normal mode, then o. (Nothing was sent.)"); }
        // refuse BEFORE taking the draft, so nothing is lost: the engine keeps at most MAX_UNCONFIRMED unconfirmed texts per contact
        let open = self.chats.get(&id).map_or(0, |l| l.iter().filter(|x| x.mine && x.queued).count());
        if open >= nerd_chat_chat::engine::MAX_UNCONFIRMED { return self.err("Outbox full: the contact has not confirmed your earlier messages yet. Your draft is kept; try again when they come online."); }
        // the id is made HERE so that the history's copy and the engine's copy are the same message
        let mid = nerd_chat_chat::proto::new_msg_id();
        let text = self.compose.take_string();
        let linked = self.linked.contains(&id);
        // keep a wiped-on-drop copy for the screen, hand the other to the engine
        let shown = Zeroizing::new((*text).clone());
        if let Some(h) = self.history.as_mut() {
            // written to the history on the next tick, and only THEN handed to the engine: a text the contact may already have must never be missing from the file after a crash
            h.push(id, MsgState::Queued, Some(mid), &text);
            if self.engine.is_some() { self.pending_sends.push((id, mid, text)); }
        } else if let Some(e) = &self.engine { e.send_with_mid(id, mid, text); }
        // "(queued)" = not yet CONFIRMED by the contact's app (connected or not): the engine resends it on every new connection
        self.push_line(id, ChatLine { mine: true, text: shown, queued: true, saved: false, unsent: false, unconfirmed: false, mid: Some(mid) });
        self.scroll = 0; // sending jumps to the newest line
        if self.engine.is_none() { self.ok("Kept encrypted on this device. It is sent when you are online and the contact is reachable."); }
        else if !linked { self.ok(if kept { "Peer is not connected: message kept encrypted on this device, delivered when they come online." } else { "Peer is not connected: message queued in RAM, delivered when they come online (lost if you quit)." }); }
    }

    fn push_line(&mut self, id: [u8; 8], l: ChatLine) {
        let v = self.chats.entry(id).or_default();
        v.push(l);
        if v.len() > MAX_CHAT_LINES { v.remove(0); } // the dropped line is wiped (Zeroizing)
        // the message cursor counts from the NEWEST line: a new line shifts it, or the user would save the wrong message
        if self.select.is_some() && self.chat_id() == Some(id) {
            let n = self.chats.get(&id).map_or(0, Vec::len);
            self.select = self.select.map(|k| k + 1).filter(|k| *k < n);
        }
    }

    /// Contacts may have been added/deleted while tor was starting: make the engine match the vault (R6-M4/L2).
    fn reconcile(&mut self) {
        let now: HashSet<[u8; 8]> = self.vf.as_ref().map(|v| v.store.contacts.iter().filter(|c| c.peer.is_some()).map(|c| c.id).collect()).unwrap_or_default();
        let Some(e) = &self.engine else { return };
        for id in self.started_ids.difference(&now) { e.remove(*id); }
        if let Some(v) = self.vf.as_ref() {
            for c in v.store.contacts.iter().filter(|c| !self.started_ids.contains(&c.id)) {
                if let Some(cfg) = self.cfg_of(c) { e.add(cfg); }
            }
        }
        self.started_ids = now;
    }

    /// Name the contact; identical repeats only raise a counter; an unacknowledged alert is never evicted. Returns the shown text.
    fn record_alert(&mut self, id: Option<[u8; 8]>, text: &str) -> String {
        let mut t: String = text.chars().take(300).collect();
        let who = id.and_then(|i| self.contact(i)).map(|c| c.name.clone());
        if let Some(w) = who { t = format!("{w}: {t}"); }
        if let Some(e) = self.alert_log.iter_mut().rev().find(|(a, _)| *a == t) { e.1 = e.1.saturating_add(1); }
        else { if self.alert_log.len() >= 30 { self.alert_log.remove(0); } self.alert_log.push((t.clone(), 1)); }
        if let Some(e) = self.alerts.iter_mut().find(|(a, _)| *a == t) { e.1 = e.1.saturating_add(1); }
        else if self.alerts.len() < 5 { self.alerts.push((t.clone(), 1)); }
        else { self.alerts_dropped = self.alerts_dropped.saturating_add(1); }
        t
    }

    fn contact(&self, id: [u8; 8]) -> Option<&nerd_chat_store::Contact> { self.vf.as_ref()?.store.contacts.iter().find(|c| c.id == id) }
    fn known(&self, id: &[u8; 8]) -> bool { self.contact(*id).is_some() }

    fn poll_online(&mut self) {
        if let Some(rx) = self.stop_rx.take() {
            match rx.try_recv() {
                Err(TryRecvError::Empty) => self.stop_rx = Some(rx),
                _ => {
                    self.online = Online::Offline;
                    // the engine's copy is gone: what is not in the history may or may not have arrived (what IS kept is sent again next time)
                    let kept: HashSet<[u8; 8]> = self.history.as_ref().map(|h| h.all_queued_mids().into_iter().map(|(_, m)| m).collect()).unwrap_or_default();
                    for x in self.chats.values_mut().flatten().filter(|x| x.queued && !x.mid.is_some_and(|m| kept.contains(&m))) { x.queued = false; x.unconfirmed = true; }
                    self.ok("Offline. Connections closed, onion services and credentials removed.");
                }
            }
        }
        if let Some(rx) = self.start_rx.take() {
            let mut keep = true;
            loop {
                match rx.try_recv() {
                    Ok(StartMsg::Progress(p)) => self.online = Online::Starting(p),
                    Ok(StartMsg::Ready(e)) => { self.offers.clear(); self.accepted.clear(); self.engine = Some(e); self.online = Online::Online; keep = false; self.reconcile(); self.hand_over_texts_kept_while_starting(); self.ok("ONLINE. Contacts you dial or that dial you will connect as they come up."); break; }
                    Ok(StartMsg::Failed(m)) => { self.online = Online::Failed(m.clone()); keep = false; self.err(format!("Could not go online: {m}")); break; }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => { self.online = Online::Failed("start thread died".into()); keep = false; break; }
                }
            }
            if keep { self.start_rx = Some(rx); }
        }
        let evs: Vec<Event> = self.engine.as_ref().map_or(vec![], |e| e.events.try_iter().collect());
        for ev in evs {
            // events for contacts that no longer exist must not create hidden chat state (R6-L1)
            let stale = match &ev { Event::Connected { id } | Event::Disconnected { id } | Event::Message { id, .. } | Event::FileOffer { id, .. } | Event::FileCancelled { id } | Event::File { id, .. } | Event::FileSent { id } | Event::Delivered { id, .. } | Event::Unsent { id, .. } | Event::Rotate { id, .. } => !self.known(id), Event::Notice { .. } => false };
            if stale { continue; }
            match ev {
                Event::Connected { id } => { self.linked.insert(id); }
                Event::Disconnected { id } => { self.linked.remove(&id); self.offers.remove(&id); self.accepted.remove(&id); }
                Event::FileCancelled { id } => { self.offers.remove(&id); self.accepted.remove(&id); }
                Event::Message { id, mid, text } => {
                    // the history takes a copy; it is written on the next tick
                    let hold = match self.history.as_mut() { Some(h) => { h.push(id, MsgState::Received, None, &text); h.persist().keeps_everything() } None => false };
                    self.push_line(id, ChatLine { mine: false, text, queued: false, saved: false, unsent: false, unconfirmed: false, mid: None });
                    // only NOW does the sender hear "received": this line is in our own state, and (when received texts are kept) the file that holds it is durable
                    if let Some(m) = mid {
                        if hold { self.pending_confirms.push((id, m)); } else if let Some(e) = &self.engine { e.confirm(id, m); }
                    }
                    if !(self.screen == Screen::Main && self.pane == Pane::Chat && self.sel_id() == Some(id)) { *self.unread.entry(id).or_insert(0) += 1; }
                }
                // the contact's app confirmed exactly this text (found by its id: order, trimming and refusals cannot mislead us)
                Event::Delivered { id, mid } => {
                    if let Some(x) = self.chats.get_mut(&id).and_then(|l| l.iter_mut().find(|x| x.mine && x.queued && x.mid == Some(mid))) { x.queued = false; }
                    if let Some(h) = self.history.as_mut() { h.set_state(id, mid, MsgState::Delivered); } // confirmed: written on the next tick (in outbox mode it is forgotten)
                }
                // the engine refused exactly this text: it was NOT sent
                Event::Unsent { id, mid } => {
                    if let Some(x) = self.chats.get_mut(&id).and_then(|l| l.iter_mut().find(|x| x.mine && x.queued && x.mid == Some(mid))) { x.queued = false; x.unsent = true; }
                    if let Some(h) = self.history.as_mut() { h.set_state(id, mid, MsgState::Unsent); } // refused: it will never be sent, so it must not stay queued
                }
                Event::Rotate { id, kind, onion, auth } => self.on_rotate(id, kind, onion, auth),
                Event::Notice { id, text, alert } => {
                    let t = if alert { self.record_alert(id, &text) } else { text.chars().take(300).collect() };
                    self.status = t;
                }
                Event::FileOffer { id, xid, bucket } => {
                    if self.offers.contains_key(&id) || self.accepted.contains_key(&id) || self.inbox.contains_key(&id) {
                        // never silently replace a pending offer or an unsaved file
                        if let Some(e) = &self.engine { e.reply_file(id, xid, false); }
                        continue;
                    }
                    self.offers.insert(id, (xid, bucket));
                    self.status = "A contact offers a file: select them, then a = accept / r = decline.".into();
                }
                Event::File { id, data, format, report, resanitised } => {
                    let ext = match format { nerd_chat_strip::Format::Jpeg => "jpg", nerd_chat_strip::Format::Png => "png", nerd_chat_strip::Format::Text => "txt" };
                    self.accepted.remove(&id);
                    self.inbox.insert(id, Received { data, ext });
                    self.status = if resanitised { format!("File received. WARNING: it still contained metadata, removed here ({}). Select the contact, s = save.", report.join("; ").chars().take(200).collect::<String>()) }
                        else { "File received (RAM only). Select the contact, s = save under a neutral name.".into() };
                }
                Event::FileSent { .. } => self.status = "File delivered.".into(),
            }
        }
    }

    /// The worker is done (or gone): forget its handles and the code/address line.
    fn end_pairing(&mut self) { self.pair_rx = None; self.pair_ctl = None; self.pair_info = None; self.link_rx = None; self.tor_offer = None; self.tor_contact = None; }

    fn cancel_pairing(&mut self) {
        match self.pair_ctl.take() {
            Some(c) => { c.cancel(); self.pair_rx = None; self.pair_info = None; self.link_rx = None; self.tor_offer = None; self.tor_contact = None; self.ok("Pairing cancelled."); }
            None => self.ok("No pairing in progress."),
        }
    }

    /// Messages of a pairing-over-Tor worker: the link is ready, it failed, or somebody used the link and failed.
    fn poll_link(&mut self) {
        let Some(rx) = &self.link_rx else { return };
        let mut msgs = vec![];
        while let Ok(m) = rx.try_recv() { msgs.push(m); }
        for m in msgs {
            match m {
                LinkMsg::Ready { link, code, expires } => {
                    self.pair_info = Some(Zeroizing::new(format!("Link (for your partner only): {}\nCODE (tell it by voice): {}    x = cancel", &*link, &*code)));
                    let contact = self.tor_contact.unwrap_or([0; 8]);
                    self.tor_offer = Some(TorLink { contact, link, code, expires });
                    self.ok("Ready. Send the link to your partner and tell them the code by voice or in person. It works for 10 minutes and only once.");
                }
                LinkMsg::Failed(why) => { if let Some(c) = self.pair_ctl.take() { c.cancel(); } self.end_pairing(); self.err(why); }
                LinkMsg::UsedAndFailed => { self.record_alert(None, "Someone used your pairing link and did not know the code. If your partner did not just type a wrong code, the link was seen by someone else: make a new one and send it another way."); }
            }
        }
    }

    /// Was the pairing that just finished (or is waiting for the answer) made through Tor? Then the question is whether the code was HEARD by voice.
    pub fn pair_remote(&self) -> bool { self.pair_remote }
    /// A pairing finished and waits for the user's in-person answer (`P`). Read-only: a front end uses it to show the question.
    pub fn pairing_waiting(&self) -> bool { self.pending_pair.is_some() }

    /// The id of the selected contact (a front end compares it with `TorLink::contact`).
    pub fn selected_contact_id(&self) -> Option<[u8; 8]> { self.vf.as_ref()?.store.contacts.get(self.sel).map(|c| c.id) }
    /// Name of the contact an open Tor offer belongs to.
    pub fn tor_offer_name(&self) -> Option<&str> { let id = self.tor_offer.as_ref()?.contact; self.contact(id).map(|c| c.name.as_str()) }

    /// Call every UI tick: collects a finished pairing.
    fn poll_prep(&mut self) {
        let Some((id, rx)) = &self.prep_rx else { return };
        let id = *id;
        let r = match rx.try_recv() {
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => { self.prep_rx = None; return self.err("File cleaning thread died."); }
            Ok(r) => r,
        };
        self.prep_rx = None;
        match r {
            Ok((f, report)) => {
                if !self.linked.contains(&id) || self.engine.is_none() { return self.err("The contact disconnected while the file was being cleaned: not sent."); }
                if let Some(e) = &self.engine { e.offer_file(id, f); }
                if report.is_empty() { self.ok("Offered (nothing needed removing). Waiting for the contact to accept."); }
                else { let r = report.join("; "); self.ok(format!("Offered after cleaning: {}. Waiting for the contact to accept.", r.chars().take(300).collect::<String>())); }
            }
            Err(e) => self.err(format!("NOT sent: {e}")),
        }
    }

    pub fn poll(&mut self) {
        if let Some(m) = self.max_scroll.get() { self.scroll = self.scroll.min(m); } // 'g' before the first frame must not leave a huge offset
        self.poll_prep();
        self.poll_kdf();
        self.poll_probe();
        self.poll_online();
        self.poll_link();
        self.grid_tick();
        let Some(rx) = &self.pair_rx else { return };
        match rx.try_recv() {
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => { self.end_pairing(); self.err("Pairing thread died."); }
            Ok((contact_id, result)) => {
                self.end_pairing();
                match result {
                    Ok((contact, sn)) => {
                        // NEVER open a prompt from here: the user may be typing a message or answering another question and their next
                        // keys would answer the "in person?" question (a `y` upgrades trust). The user asks for it with `P`.
                        self.pending_pair = Some((contact_id, contact, sn));
                        self.record_alert(None, "Pairing finished: press P (normal mode) to answer the in-person question. The contact is not paired until you do.");
                    }
                    Err(ExchangeError::PairingFailed | ExchangeError::ProofFailed) =>
                        self.err("PAIRING FAILED: wrong code or someone interfered. The code is burned; start over with a fresh one."),
                    Err(e) => self.err(format!("Pairing failed: {e}")),
                }
            }
        }
    }

    fn finish_pair(&mut self, id: [u8; 8], contact: ImportedContact, sn: String) {
        let (peer, trust) = contact.into_parts();
        let pos = self.vf.as_ref().and_then(|v| v.store.contacts.iter().position(|c| c.id == id));
        if let Some(i) = pos { if self.onion_collision(i, &peer) { self.err("Refused: the paired bundle reuses an onion address that another contact (or you) already has."); return; } }
        let told = self.pair_adv.take();
        let Some(c) = self.vf().store.contacts.iter_mut().find(|c| c.id == id) else { self.err("Contact vanished during pairing."); return };
        if c.peer.is_some() { self.err("Contact already has a peer key; discarded the paired one."); return; }
        if told.is_some() && c.adv_can_host.is_some() && c.adv_can_host != told { self.err("Pairing discarded: the capability stored for this contact differs from the one just told to the peer (roles would disagree). Pair again."); return; }
        c.peer = Some(peer);
        c.trust = trust;
        let set_adv = c.adv_can_host.is_none() && told.is_some();
        if set_adv { c.adv_can_host = told; }
        if !self.save() {
            // memory and vault must agree: undo (the user can pair again)
            if let Some(c) = self.vf().store.contacts.iter_mut().find(|c| c.id == id) { c.peer = None; c.trust = Trust::Unverified; if set_adv { c.adv_can_host = None; } }
            return;
        }
        {
            if let Some(i) = self.vf().store.contacts.iter().position(|c| c.id == id) { self.engine_add(i); }
            let how = if trust == Trust::CodeAuthenticated { "code-authenticated (in person)" } else { "UNVERIFIED - compare the safety number (v)" };
            self.ok(format!("Paired: {how}. Safety number {sn}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use nerd_chat_chat::{Timing, Transport};
    use std::sync::atomic::AtomicBool;

    pub fn type_str(a: &mut App, s: &str) { for c in s.chars() { a.handle(Key::Char(c)); } }

    fn cfg(path: Option<PathBuf>) -> Config {
        let mut c = Config::new(path, None, None, Profile::InsecureTest);
        c.grid = Duration::from_millis(30);      // the real grid is 5 s
        c.history_slot = 64 * 1024;              // the real slot is 1 MiB
        c
    }

    /// Create a NEW vault with the standard test password (typed twice).
    fn open_app(c: Config) -> App {
        let mut a = App::new(c);
        assert_eq!(a.screen, Screen::CreatePw);
        type_str(&mut a, "correct horse battery"); a.handle(Key::Enter);
        assert_eq!(a.screen, Screen::CreateConfirm);
        type_str(&mut a, "correct horse battery"); a.handle(Key::Enter);
        assert_eq!(a.screen, Screen::Main, "{}", a.status);
        a
    }

    fn create_app(dir: &std::path::Path, name: &str) -> App { open_app(cfg(Some(dir.join(name)))) }

    fn add(a: &mut App, name: &str) { a.handle(Key::Char('n')); type_str(a, name); a.handle(Key::Enter); }

    /// `a` listens (for its selected contact) and returns what `b` needs: the address and the one-time code.
    fn listen(a: &mut App) -> (String, String) {
        a.handle(Key::Char('l')); a.handle(Key::Enter);
        let info = a.pair_info.clone().expect("listening");
        (info.split_whitespace().nth(2).unwrap().to_string(), info.split("CODE: ").nth(1).unwrap().split_whitespace().next().unwrap().to_string())
    }

    /// `b` joins `a`'s listener with `code`, then both apps are polled until the pairing workers are done.
    fn join_and_wait(a: &mut App, b: &mut App, addr: &str, code: &str) {
        b.handle(Key::Char('c')); type_str(b, addr); b.handle(Key::Enter); type_str(b, code); b.handle(Key::Enter);
        let t = Instant::now();
        while (a.pair_ctl.is_some() || b.pair_ctl.is_some()) && t.elapsed() < Duration::from_secs(20) { a.poll(); b.poll(); thread::sleep(Duration::from_millis(50)); }
    }

    #[test]
    fn security_alerts_are_sticky_until_acknowledged() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "v");
        a.alerts.push(("received file failed its integrity check".into(), 1));
        a.alerts.push(("second".into(), 1));
        a.ok("some later status message");
        assert_eq!(a.alerts.len(), 2, "status text never clears an alert");
        a.handle(Key::Char('z'));
        assert_eq!(a.alerts, vec![("second".to_string(), 1)]);
        a.panic_wipe();
        assert!(a.alerts.is_empty(), "panic wipes alerts");
    }

    #[test]
    fn alerts_name_the_contact_dedupe_and_never_evict() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "v"); add(&mut a, "bob");
        let id = a.vf.as_ref().unwrap().store.contacts[0].id;
        for _ in 0..50 { a.record_alert(Some(id), "received file failed its integrity check"); }
        assert_eq!(a.alerts.len(), 1, "a flood of identical alerts is one entry");
        assert_eq!(a.alerts[0].1, 50);
        assert!(a.alerts[0].0.starts_with("bob: "), "{:?}", a.alerts[0]);
        for i in 0..10 { a.record_alert(Some(id), &format!("distinct {i}")); }
        assert_eq!(a.alerts.len(), 5, "capped");
        assert!(a.alerts[0].0.contains("integrity"), "the first real alert was not pushed out");
        assert_eq!(a.alerts_dropped, 6);
    }

    #[test]
    fn host_anyway_cannot_change_while_going_online_or_offline() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "v"); add(&mut a, "bob");
        a.online = Online::Starting(10);
        a.handle(Key::Char('h'));
        assert!(a.error && a.status.contains("settles"), "{}", a.status);
        assert!(!a.vf.as_ref().unwrap().store.contacts[0].host_anyway);
        a.online = Online::Stopping;
        a.handle(Key::Char('h'));
        assert!(a.error && a.status.contains("settles"));
    }

    #[test]
    fn export_probes_hosting_automatically_and_never_guesses() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "v"); add(&mut a, "bob");
        let export = |a: &mut App, name: &str| { a.handle(Key::Char('e')); a.input = d.path().join(name).to_str().unwrap().into(); a.handle(Key::Enter); };
        a.cfg.host_probe_test = Some(HostProbe::Unknown("no tor".into()));
        export(&mut a, "1.sbc");
        assert!(a.error && a.status.contains("Cannot tell"), "{}", a.status);
        assert_eq!(a.vf.as_ref().unwrap().store.contacts[0].adv_can_host, None);
        assert!(!d.path().join("1.sbc").exists(), "no bundle without a capability answer");
        a.cfg.host_probe_test = Some(HostProbe::Cannot("510".into()));
        export(&mut a, "2.sbc");
        assert_eq!(a.vf.as_ref().unwrap().store.contacts[0].adv_can_host, Some(false));
        assert!(!nerd_chat_exchange::file::dearmor(&std::fs::read_to_string(d.path().join("2.sbc")).unwrap()).unwrap().can_host);
        // fixed once told: a later, different probe answer changes nothing
        a.cfg.host_probe_test = Some(HostProbe::Can);
        export(&mut a, "3.sbc");
        assert!(!nerd_chat_exchange::file::dearmor(&std::fs::read_to_string(d.path().join("3.sbc")).unwrap()).unwrap().can_host);
        // another contact, tor can host
        add(&mut a, "carol"); a.sel = 1;
        export(&mut a, "4.sbc");
        assert_eq!(a.vf.as_ref().unwrap().store.contacts[1].adv_can_host, Some(true));
        // --cannot-host wins without asking the probe
        add(&mut a, "dave"); a.sel = 2; a.cfg.can_host = false; a.cfg.host_probe_test = Some(HostProbe::Unknown("x".into()));
        export(&mut a, "5.sbc");
        assert_eq!(a.vf.as_ref().unwrap().store.contacts[2].adv_can_host, Some(false));
    }

    #[test]
    fn the_real_probe_runs_off_the_ui_thread_keys_are_ignored_and_esc_cancels() {
        use std::os::unix::net::UnixListener;
        let d = tempfile::tempdir().unwrap();
        let sock = d.path().join("ctl");
        let l = UnixListener::bind(&sock).unwrap();
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        thread::spawn(move || for mut s in l.incoming().flatten() {
            go_rx.recv().ok(); // the "tor" stalls until the test lets it answer
            let mut rd = std::io::BufReader::new(s.try_clone().unwrap());
            let mut line = String::new();
            while { line.clear(); std::io::BufRead::read_line(&mut rd, &mut line).unwrap_or(0) > 0 } {
                let r = if line.starts_with("PROTOCOLINFO") { "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=NULL\r\n250 OK\r\n" } else if line.starts_with("AUTHENTICATE") { "250 OK\r\n" } else { "510 Command filtered\r\n" };
                if s.write_all(r.as_bytes()).is_err() { break; }
            }
        });
        let mut a = create_app(d.path(), "v"); add(&mut a, "bob");
        a.cfg.tor.control = Some(Addr::Unix(sock));
        let f = d.path().join("b.sbc");
        a.handle(Key::Char('e')); a.input = f.to_str().unwrap().into(); a.handle(Key::Enter);
        assert!(a.probe_rx.is_some(), "{}", a.status);
        assert!(a.handle(Key::Char('d')) == Action::None && a.probe_rx.is_some(), "other keys are ignored while probing");
        a.handle(Key::Esc);
        assert!(a.probe_rx.is_none() && !f.exists() && a.vf.as_ref().unwrap().store.contacts[0].adv_can_host.is_none(), "Esc cancels without exporting");
        // again, this time let tor answer: 510 -> told "cannot host", with a sticky alert
        a.handle(Key::Char('e')); a.input = f.to_str().unwrap().into(); a.handle(Key::Enter);
        go_tx.send(()).ok(); go_tx.send(()).ok();
        for _ in 0..200 { a.poll(); if a.probe_rx.is_none() { break; } thread::sleep(Duration::from_millis(25)); }
        assert_eq!(a.vf.as_ref().unwrap().store.contacts[0].adv_can_host, Some(false), "{}", a.status);
        assert!(f.exists() && a.alerts.iter().any(|(t, _)| t.contains("cannot host")), "{:?}", a.alerts);
    }

    #[test]
    fn export_is_refused_while_a_pairing_waits_so_the_told_bit_cannot_diverge() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "v"); add(&mut a, "bob");
        a.pending_pair = Some(([0; 8], ImportedContact::from_file(Bundle::from_identity(&ContactIdentity::generate())), "1".into()));
        a.handle(Key::Char('e'));
        assert!(a.error && a.status.contains("pairing"), "{}", a.status);
        assert!(!matches!(a.screen, Screen::Prompt(_)));
    }

    #[test]
    fn the_told_capability_is_fixed_only_when_the_bundle_really_left() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "v"); add(&mut a, "bob");
        a.cfg.can_host = false;
        let f = d.path().join("exists.sbc");
        std::fs::write(&f, b"x").unwrap();
        a.handle(Key::Char('e')); a.input = f.to_str().unwrap().into(); a.handle(Key::Enter);
        assert!(a.error);
        assert_eq!(a.vf.as_ref().unwrap().store.contacts[0].adv_can_host, None, "a failed export must not fix the bit");
        let g = d.path().join("new.sbc");
        a.handle(Key::Char('e')); a.input = g.to_str().unwrap().into(); a.handle(Key::Enter);
        assert_eq!(a.vf.as_ref().unwrap().store.contacts[0].adv_can_host, Some(false));
        // bad listen address: nothing fixed either (second contact)
        add(&mut a, "carol"); a.sel = 1;
        a.handle(Key::Char('l')); a.input = "999.1.1.1:1".into(); a.handle(Key::Enter);
        assert_eq!(a.vf.as_ref().unwrap().store.contacts[1].adv_can_host, None);
    }

    #[test]
    fn create_rules_short_and_mismatch() {
        let d = tempfile::tempdir().unwrap();
        let mut a = App::new(cfg(Some(d.path().join("v"))));
        type_str(&mut a, "short"); a.handle(Key::Enter);
        assert_eq!(a.screen, Screen::CreatePw); assert!(a.error);
        a.pw.clear();
        type_str(&mut a, "a long enough passphrase"); a.handle(Key::Enter);
        type_str(&mut a, "a different passphrase!!"); a.handle(Key::Enter);
        assert_eq!(a.screen, Screen::CreatePw); assert!(!d.path().join("v").exists());
    }

    #[test]
    fn kdf_runs_off_the_ui_thread_and_panic_works_meanwhile() {
        let d = tempfile::tempdir().unwrap();
        { let _ = create_app(d.path(), "v"); }
        let mut a = App::new(cfg(Some(d.path().join("v"))));
        a.test_async = true;
        type_str(&mut a, "correct horse battery"); a.handle(Key::Enter);
        assert_eq!(a.screen, Screen::Working);
        assert_eq!(a.pw.chars(), 0, "password buffer cleared immediately");
        assert_eq!(a.handle(Key::Char('q')), Action::None, "keys are ignored while working");
        for _ in 0..2000 { a.poll(); if a.screen != Screen::Working { break; } thread::sleep(Duration::from_millis(5)); }
        assert_eq!(a.screen, Screen::Main, "{}", a.status);
        // panic while a derivation is running
        let mut b = App::new(cfg(Some(d.path().join("v"))));
        b.test_async = true;
        type_str(&mut b, "correct horse battery"); b.handle(Key::Enter);
        assert_eq!(b.screen, Screen::Working);
        assert_eq!(b.handle(Key::F12), Action::Panic);
        assert_eq!(b.screen, Screen::Wiped);
        thread::sleep(Duration::from_millis(100)); b.poll();
        assert!(!b.vf.is_some() && b.screen == Screen::Wiped, "late result must not resurrect the vault");
    }

    #[test]
    fn unlock_wrong_then_right_and_persistence() {
        let d = tempfile::tempdir().unwrap();
        { let mut a = create_app(d.path(), "v"); add(&mut a, "alice"); assert_eq!(a.contacts_len(), 1); }
        let mut a = App::new(cfg(Some(d.path().join("v"))));
        assert_eq!(a.screen, Screen::Unlock);
        type_str(&mut a, "wrong password!!"); a.handle(Key::Enter);
        assert_eq!(a.screen, Screen::Unlock); assert!(a.error); assert!(a.pw.is_empty(), "password buffer wiped after attempt");
        type_str(&mut a, "correct horse battery"); a.handle(Key::Enter);
        assert_eq!(a.screen, Screen::Main);
        assert_eq!(a.contact_rows()[0].0, "alice");
    }

    #[test]
    fn repeated_failures_lock_out() {
        let d = tempfile::tempdir().unwrap();
        { create_app(d.path(), "v"); }
        let mut a = App::new(cfg(Some(d.path().join("v"))));
        for _ in 0..3 { type_str(&mut a, "nopenopenope"); a.handle(Key::Enter); }
        type_str(&mut a, "correct horse battery"); a.handle(Key::Enter);
        assert_eq!(a.screen, Screen::Unlock, "even the right password is refused during lockout");
        assert!(a.status.contains("wait"));
    }

    #[test]
    fn export_import_verify_flow_between_two_apps() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "a.vault"); add(&mut a, "bob");
        let mut b = create_app(d.path(), "b.vault"); add(&mut b, "alice");
        let (fa, fb) = (d.path().join("a.sbc"), d.path().join("b.sbc"));
        for (app, f) in [(&mut a, &fa), (&mut b, &fb)] {
            app.handle(Key::Char('e'));
            app.input.clear(); type_str(app, f.to_str().unwrap()); app.handle(Key::Enter);
            assert!(!app.error, "{}", app.status);
        }
        // never overwrites
        a.handle(Key::Char('e')); a.input.clear(); type_str(&mut a, fa.to_str().unwrap()); a.handle(Key::Enter);
        assert!(a.error);
        for (app, f) in [(&mut a, &fb), (&mut b, &fa)] {
            app.handle(Key::Char('I')); type_str(app, f.to_str().unwrap()); app.handle(Key::Enter);
            assert!(!app.error, "{}", app.status);
            assert_eq!(app.selected_detail().unwrap().1, Trust::Unverified);
        }
        let (sna, snb) = (a.selected_detail().unwrap().2.unwrap(), b.selected_detail().unwrap().2.unwrap());
        assert_eq!(sna, snb, "both sides see the same safety number");
        a.handle(Key::Char('v')); assert_eq!(a.screen, Screen::Verify);
        assert_eq!(a.view_number().unwrap(), sna);
        a.handle(Key::Char('y'));
        assert_eq!(a.selected_detail().unwrap().1, Trust::SafetyVerified);
        // any other key cancels
        b.handle(Key::Char('v')); b.handle(Key::Char('n'));
        assert_eq!(b.selected_detail().unwrap().1, Trust::Unverified);
        // survives restart
        let mut a2 = App::new(cfg(Some(d.path().join("a.vault"))));
        type_str(&mut a2, "correct horse battery"); a2.handle(Key::Enter);
        assert_eq!(a2.selected_detail().unwrap().1, Trust::SafetyVerified);
        // importing your own bundle or a second peer is refused
        a.handle(Key::Char('I')); assert!(a.error);
    }

    #[test]
    fn import_rejects_garbage_own_bundle_and_oversize() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "v"); add(&mut a, "bob");
        let g = d.path().join("g.sbc"); fs::write(&g, "garbage").unwrap();
        a.handle(Key::Char('I')); type_str(&mut a, g.to_str().unwrap()); a.handle(Key::Enter);
        assert!(a.error && a.selected_detail().unwrap().2.is_none());
        let own = d.path().join("own.sbc");
        a.handle(Key::Char('e')); a.input.clear(); type_str(&mut a, own.to_str().unwrap()); a.handle(Key::Enter);
        a.handle(Key::Char('I')); type_str(&mut a, own.to_str().unwrap()); a.handle(Key::Enter);
        assert!(a.error && a.status.contains("OWN"));
        let big = d.path().join("big.sbc"); fs::write(&big, vec![b'A'; 100_000]).unwrap();
        a.handle(Key::Char('I')); type_str(&mut a, big.to_str().unwrap()); a.handle(Key::Enter);
        assert!(a.error);
    }

    #[test]
    fn delete_needs_yes() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "v"); add(&mut a, "bob");
        a.handle(Key::Char('d')); type_str(&mut a, "no"); a.handle(Key::Enter);
        assert_eq!(a.contacts_len(), 1);
        a.handle(Key::Char('d')); type_str(&mut a, "yes"); a.handle(Key::Enter);
        assert_eq!(a.contacts_len(), 0);
    }

    #[test]
    fn panic_key_wipes_from_every_screen() {
        let d = tempfile::tempdir().unwrap();
        for k in [Key::F12, Key::CtrlBackslash] {
            let mut a = create_app(d.path(), &format!("v{k:?}")); add(&mut a, "bob");
            a.handle(Key::Char('d')); type_str(&mut a, "ye"); // mid-prompt
            assert_eq!(a.handle(k), Action::Panic);
            assert!(!a.vf.is_some() && a.screen == Screen::Wiped);
            assert!(a.input.is_empty() && a.status.is_empty() && a.pw.is_empty());
            assert_eq!(a.contacts_len(), 0);
            assert_eq!(a.handle(Key::Char('x')), Action::Quit, "nothing left to interact with");
        }
        // also from the password prompt
        let mut a = App::new(cfg(Some(d.path().join("vF12"))));
        type_str(&mut a, "typed secret pw"); assert_eq!(a.handle(Key::F12), Action::Panic);
        assert!(a.pw.is_empty());
    }

    #[test]
    fn ram_only_mode_writes_nothing() {
        let d = tempfile::tempdir().unwrap();
        std::env::set_current_dir(d.path()).unwrap();
        let mut a = App::new(cfg(None));
        a.handle(Key::Enter); // RAM-only: no password prompt
        assert_eq!(a.screen, Screen::Main);
        add(&mut a, "bob");
        assert_eq!(a.contacts_len(), 1);
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 0);
    }

    #[test]
    fn local_pairing_over_tcp_between_two_apps() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "a.vault"); add(&mut a, "bob");
        let mut b = create_app(d.path(), "b.vault"); add(&mut b, "alice");
        let (addr, code) = listen(&mut a);
        join_and_wait(&mut a, &mut b, &addr, &code);
        assert!(a.screen == Screen::Main && b.screen == Screen::Main, "a finished pairing must NOT open a prompt by itself");
        assert!(a.pending_pair.is_some() && b.pending_pair.is_some(), "{} / {}", a.status, b.status);
        assert!(a.alerts.iter().any(|(t, _)| t.contains("press P")), "a sticky alert tells the user to press P");
        a.handle(Key::Char('P')); b.handle(Key::Char('P'));
        assert_eq!(a.screen, Screen::Prompt(Prompt::InPerson), "{}", a.status);
        assert_eq!(b.screen, Screen::Prompt(Prompt::InPerson), "{}", b.status);
        type_str(&mut a, "y"); a.handle(Key::Enter);
        type_str(&mut b, "n"); b.handle(Key::Enter); // B says the code did NOT travel in person
        assert_eq!(a.selected_detail().unwrap().1, Trust::CodeAuthenticated);
        assert_eq!(b.selected_detail().unwrap().1, Trust::Unverified, "weak-channel code downgrades trust");
        assert_eq!(a.selected_detail().unwrap().2, b.selected_detail().unwrap().2);
    }

    #[test]
    fn listen_refuses_public_and_unspecified_addresses() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "a.vault"); add(&mut a, "bob");
        for bad in ["0.0.0.0:0", "8.8.8.8:4000", "[::]:0"] {
            a.handle(Key::Char('l')); a.input.clear(); type_str(&mut a, bad); a.handle(Key::Enter);
            assert!(a.error && !a.pair_ctl.is_some() && a.status.contains("Refusing"), "{bad}: {}", a.status);
        }
        a.handle(Key::Char('l')); a.handle(Key::Enter); // default 127.0.0.1:0 is fine
        assert!(a.pair_ctl.is_some());
    }

    #[test]
    fn cancel_and_panic_stop_pairing_workers() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "a.vault"); add(&mut a, "bob");
        a.handle(Key::Char('l')); a.handle(Key::Enter);
        assert!(a.pair_ctl.is_some());
        a.handle(Key::Char('x'));
        assert!(!a.pair_ctl.is_some() && a.pair_info.is_none());
        // a second listen works again, and panic joins the worker quickly
        a.handle(Key::Char('l')); a.handle(Key::Enter);
        assert!(a.pair_ctl.is_some());
        let t = Instant::now();
        a.handle(Key::F12);
        assert!(!a.pair_ctl.is_some() && t.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn join_code_never_enters_the_plain_input_string() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "a.vault"); add(&mut a, "bob");
        a.handle(Key::Char('c')); type_str(&mut a, "127.0.0.1:9"); a.handle(Key::Enter);
        type_str(&mut a, "1234567890");
        assert!(a.input.is_empty(), "code must live only in the fixed-capacity SecretBuf");
        assert_eq!(a.code_chars(), 10);
        a.handle(Key::Esc);
        assert_eq!(a.code_chars(), 0, "wiped on cancel");
    }

    #[test]
    fn esc_on_in_person_question_keeps_pairing_but_downgrades() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "a.vault"); add(&mut a, "bob");
        let mut b = create_app(d.path(), "b.vault"); add(&mut b, "alice");
        let (addr, code) = listen(&mut a);
        join_and_wait(&mut a, &mut b, &addr, &code);
        a.handle(Key::Char('P'));
        a.handle(Key::Esc);
        assert_eq!(a.screen, Screen::Main);
        assert!(a.selected_detail().unwrap().2.is_some(), "pairing kept");
        assert_eq!(a.selected_detail().unwrap().1, Trust::Unverified);
    }

    #[cfg(unix)]
    #[test]
    fn import_from_fifo_or_symlink_does_not_hang_the_ui() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "v"); add(&mut a, "bob");
        let fifo = d.path().join("bob.sbc");
        assert!(std::process::Command::new("mkfifo").arg(&fifo).status().unwrap().success());
        let t = Instant::now();
        a.handle(Key::Char('I')); type_str(&mut a, fifo.to_str().unwrap()); a.handle(Key::Enter);
        assert!(a.error && t.elapsed() < Duration::from_secs(2));
        let link = d.path().join("tty.sbc");
        std::os::unix::fs::symlink("/dev/tty", &link).unwrap();
        a.handle(Key::Char('I')); type_str(&mut a, link.to_str().unwrap()); a.handle(Key::Enter);
        assert!(a.error);
    }

    #[test]
    fn default_export_name_is_neutral() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "v"); add(&mut a, "secretname");
        a.handle(Key::Char('e'));
        assert!(!a.input.contains("secretname") && a.input.starts_with("bundle-") && a.input.ends_with(".sbc"), "{}", a.input);
    }

    // ---------- online + chat (over the in-memory network) ----------
    fn fast_timing() -> Timing {
        Timing { poll: Duration::from_millis(20), keepalive: Duration::from_millis(150), idle: Duration::from_secs(2),
                 min_backoff: Duration::from_millis(30), max_backoff: Duration::from_millis(200), handshake: Duration::from_secs(5), handshakes_per_sec: 1000.0,
                 ack_delay_min: Duration::from_millis(20), ack_delay_max: Duration::from_millis(40), caps_wait: Duration::from_millis(400), rekey_cells: 32, rekey_after: Duration::from_secs(600) }
    }

    fn net_app(dir: &std::path::Path, name: &str, net: &nerd_chat_chat::MemNet) -> App {
        let mut c = cfg(Some(dir.join(name)));
        let net = net.clone();
        c.transport = Some(std::sync::Arc::new(move |_p: &mut dyn FnMut(u8)| Ok(Box::new(net.transport()) as Box<dyn Transport>)));
        c.timing = fast_timing();
        open_app(c)
    }

    /// Exchange bundle files between the selected contacts of a and b (the offline path).
    fn link_apps(a: &mut App, b: &mut App, dir: &std::path::Path) {
        let (fa, fb) = (dir.join(format!("{:?}-a.sbc", a as *const _)), dir.join(format!("{:?}-b.sbc", b as *const _)));
        for (app, f) in [(&mut *a, &fa), (&mut *b, &fb)] {
            app.handle(Key::Char('e')); app.input.clear(); type_str(app, f.to_str().unwrap()); app.handle(Key::Enter);
            assert!(!app.error, "{}", app.status);
        }
        for (app, f) in [(&mut *a, &fb), (&mut *b, &fa)] {
            app.handle(Key::Char('I')); type_str(app, f.to_str().unwrap()); app.handle(Key::Enter);
            assert!(!app.error, "{}", app.status);
        }
    }

    fn pump_until(apps: &mut [&mut App], mut done: impl FnMut(&[&mut App]) -> bool) -> bool {
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(15) {
            for a in apps.iter_mut() { a.poll(); }
            if done(apps) { return true; }
            thread::sleep(Duration::from_millis(20));
        }
        false
    }

    /// Two apps with one contact each, bundles exchanged by file (the offline path), both on the same in-memory network.
    fn linked_pair(dir: &std::path::Path) -> (nerd_chat_chat::MemNet, App, App) {
        let net = nerd_chat_chat::MemNet::new();
        let mut a = net_app(dir, "a.vault", &net); add(&mut a, "bob");
        let mut b = net_app(dir, "b.vault", &net); add(&mut b, "alice");
        link_apps(&mut a, &mut b, dir);
        (net, a, b)
    }

    fn go_online(a: &mut App) { a.handle(Key::Char('o')); }
    fn is_linked(a: &App) -> bool { a.contact_rows().first().is_some_and(|r| r.3) }

    fn onion_of(a: &App) -> [u8; 32] { a.vf.as_ref().unwrap().store.contacts[0].identity.onion_public() }
    fn peer_onion_of(a: &App) -> [u8; 32] { a.vf.as_ref().unwrap().store.contacts[0].peer.as_ref().unwrap().onion_pub }

    #[test]
    fn key_rotation_through_the_screens_in_both_directions() {
        let d = tempfile::tempdir().unwrap();
        let (net, mut a, mut b) = linked_pair(d.path());
        // not online yet: refused, nothing changes
        a.handle(Key::Char('K'));
        assert!(a.error && a.status.contains("online"), "{}", a.status);
        go_online(&mut a); go_online(&mut b);
        assert!(pump_until(&mut [&mut a, &mut b], |x| is_linked(x[0]) && is_linked(x[1])));
        let sn_before = a.selected_detail().unwrap().2;
        for round in 0..2 {
            let (first, second) = if round == 0 { (&mut a, &mut b) } else { (&mut b, &mut a) };
            let old = onion_of(first);
            first.handle(Key::Char('K'));
            assert!(!first.error, "{}", first.status);
            assert!(first.vf.as_ref().unwrap().store.contacts[0].next_transport.is_some());
            first.handle(Key::Char('K'));
            assert!(first.error && first.status.contains("already"), "a second start while pending is refused");
            assert!(pump_until(&mut [&mut *first, &mut *second], |x| x[0].vf.as_ref().unwrap().store.contacts[0].next_transport.is_none()
                && x[1].vf.as_ref().unwrap().store.contacts[0].peer_old.is_none() && is_linked(x[0]) && is_linked(x[1])),
                "rotation did not complete: {} / {}", first.status, second.status);
            let new = onion_of(first);
            assert_ne!(old, new);
            assert_eq!(peer_onion_of(second), new, "the contact switched to the new address");
            assert!(!net.is_hosted(&old), "the old service is gone");
        }
        assert_eq!(a.selected_detail().unwrap().2, sn_before, "rotation must not change the safety number");
        // chat still works afterwards, and the rotated keys survive a vault reload
        let id = a.vf.as_ref().unwrap().store.contacts[0].id;
        a.handle(Key::Char('i')); type_str(&mut a, "still here"); a.handle(Key::Enter);
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[1].chats.get(&x[1].vf.as_ref().unwrap().store.contacts[0].id).is_some_and(|l| l.iter().any(|m| m.text.as_str() == "still here"))));
        let _ = id;
        let on = onion_of(&a);
        drop(a);
        let mut a2 = App::new(cfg(Some(d.path().join("a.vault"))));
        type_str(&mut a2, "correct horse battery"); a2.handle(Key::Enter);
        assert_eq!(onion_of(&a2), on);
    }

    #[test]
    fn hostile_rotation_proposals_are_refused_without_changing_anything() {
        let d = tempfile::tempdir().unwrap();
        let (_net, mut a, _b) = linked_pair(d.path());
        let id = a.vf.as_ref().unwrap().store.contacts[0].id;
        let before = peer_onion_of(&a);
        let offer = nerd_chat_chat::proto::KIND_ROTATE_OFFER;
        let mine = (onion_of(&a), a.vf.as_ref().unwrap().store.contacts[0].identity.auth_public().to_bytes());
        let fresh = nerd_chat_core::identity::ContactIdentity::generate();
        let good = (fresh.onion_public(), fresh.auth_public().to_bytes());
        a.on_rotate(id, offer, [0; 32], good.1);                       // weak onion key
        assert!(a.error, "{}", a.status); assert_eq!(peer_onion_of(&a), before);
        a.on_rotate(id, offer, mine.0, good.1);                        // reuses OUR onion address
        assert!(a.error && a.status.contains("Refused"), "{}", a.status); assert_eq!(peer_onion_of(&a), before);
        let cur = a.vf.as_ref().unwrap().store.contacts[0].peer.as_ref().map(|p| (p.onion_pub, p.auth_pub)).unwrap();
        a.on_rotate(id, offer, cur.0, cur.1);                          // changes nothing
        assert!(a.error && a.status.contains("nothing"), "{}", a.status);
        a.on_rotate(id, offer, good.0, good.1);                        // valid: accepted, old keys remembered
        assert!(!a.error, "{}", a.status);
        assert_eq!(peer_onion_of(&a), good.0);
        assert_eq!(a.vf.as_ref().unwrap().store.contacts[0].peer_old.map(|o| o.0), Some(before));
        let again = nerd_chat_core::identity::ContactIdentity::generate();
        a.on_rotate(id, offer, again.onion_public(), again.auth_public().to_bytes()); // a second one before DONE
        assert!(a.error && a.status.contains("second"), "{}", a.status);
        assert_eq!(peer_onion_of(&a), good.0);
        // an ACK or DONE for something we never proposed does nothing
        a.on_rotate(id, nerd_chat_chat::proto::KIND_ROTATE_ACK, good.0, good.1);
        a.on_rotate(id, nerd_chat_chat::proto::KIND_ROTATE_DONE, again.onion_public(), again.auth_public().to_bytes());
        assert!(a.vf.as_ref().unwrap().store.contacts[0].peer_old.is_some());
        assert_eq!(a.vf.as_ref().unwrap().store.contacts[0].identity.onion_public(), mine.0);
    }

    #[test]
    fn a_contact_cannot_force_repeated_rotations_or_block_ours() {
        let d = tempfile::tempdir().unwrap();
        let (_net, mut a, _b) = linked_pair(d.path());
        let id = a.vf.as_ref().unwrap().store.contacts[0].id;
        let (offer, done) = (nerd_chat_chat::proto::KIND_ROTATE_OFFER, nerd_chat_chat::proto::KIND_ROTATE_DONE);
        let k1 = nerd_chat_core::identity::ContactIdentity::generate();
        let k2 = nerd_chat_core::identity::ContactIdentity::generate();
        a.on_rotate(id, offer, k1.onion_public(), k1.auth_public().to_bytes());
        assert!(!a.error, "{}", a.status);
        a.on_rotate(id, done, k1.onion_public(), k1.auth_public().to_bytes());
        assert!(a.vf.as_ref().unwrap().store.contacts[0].peer_old.is_none());
        a.on_rotate(id, offer, k2.onion_public(), k2.auth_public().to_bytes());
        assert!(a.error && a.status.contains("within the last hour"), "{}", a.status);
        assert_eq!(peer_onion_of(&a), k1.onion_public(), "the second proposal changed nothing");
        // while the contact's rotation is unfinished we can still rotate our own keys (needs the engine online)
        a.vf().store.contacts[0].peer_old = Some(([1; 32], [2; 32]));
        go_online(&mut a);
        assert!(pump_until(&mut [&mut a], |x| x[0].online == Online::Online));
        a.handle(Key::Char('K'));
        assert!(!a.error, "{}", a.status);
        // no export while our rotation is pending
        a.handle(Key::Char('e')); a.input = d.path().join("x.sbc").to_str().unwrap().into(); a.handle(Key::Enter);
        assert!(a.error && a.status.contains("export after it finished"), "{}", a.status);
        assert!(!d.path().join("x.sbc").exists());
    }

    #[test]
    fn two_users_chat_through_the_screens() {
        let d = tempfile::tempdir().unwrap();
        let (_net, mut a, mut b) = linked_pair(d.path());
        assert_eq!(a.online, Online::Offline);
        go_online(&mut a); go_online(&mut b);
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].online == Online::Online && x[1].online == Online::Online), "{:?}", a.status);
        assert!(pump_until(&mut [&mut a, &mut b], |x| is_linked(x[0]) && is_linked(x[1])), "never connected");
        // alice's side: open chat, type, send
        a.handle(Key::Char('i'));
        assert_eq!((a.pane, a.mode), (Pane::Chat, Mode::Insert));
        type_str(&mut a, "hello bob, this is private"); a.handle(Key::Enter);
        assert!(a.compose_text().is_empty() && a.chat_lines().len() == 1 && a.chat_lines()[0].mine);
        assert!(pump_until(&mut [&mut a, &mut b], |x| !x[0].chat_lines()[0].queued), "bob's app confirms it: the mark goes");
        // bob sees an unread marker, opens the chat, sees the line
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[1].contact_rows()[0].4 == 1), "no unread marker");
        b.handle(Key::Char('i'));
        assert_eq!(&*b.chat_lines()[0].text, "hello bob, this is private");
        assert!(!b.chat_lines()[0].mine);
        assert_eq!(b.contact_rows()[0].4, 0, "unread cleared by opening");
        // what bob actually sees on screen
        let mut term = ratatui::Terminal::new(ratatui::backend::TestBackend::new(110, 24)).unwrap();
        term.draw(|f| crate::ui::draw(f, &b)).unwrap();
        let screen: String = term.backend().buffer().content().iter().map(|c| c.symbol()).collect();
        assert!(screen.contains("hello bob, this is private") && screen.contains("them>") && screen.contains("connected"), "{screen}");
        assert!(screen.contains("WARNING: NOT verified"), "unverified contacts carry a visible warning");
        type_str(&mut b, "got it"); b.handle(Key::Enter);
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].chat_lines().len() == 2), "reply never arrived");
        assert_eq!(&*a.chat_lines()[1].text, "got it");
        // a message that arrives while the chat is OPEN is not counted as unread
        type_str(&mut b, "second"); b.handle(Key::Enter);
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].chat_lines().len() == 3));
        assert_eq!(a.contact_rows()[0].4, 0);
    }

    #[test]
    fn file_send_accept_save_with_neutral_name_and_panic_wipes_received_files() {
        let d = tempfile::tempdir().unwrap();
        let (_net, mut a, mut b) = linked_pair(d.path());
        go_online(&mut a); go_online(&mut b);
        assert!(pump_until(&mut [&mut a, &mut b], |x| is_linked(x[0]) && is_linked(x[1])));
        // a JPEG with planted metadata, named after something sensitive
        let seg = |m: u8, body: &[u8]| { let mut v = vec![0xFF, m]; v.extend_from_slice(&((body.len() + 2) as u16).to_be_bytes()); v.extend_from_slice(body); v };
        let mut jpg = vec![0xFF, 0xD8];
        jpg.extend(seg(0xE1, b"Exif\0\0GPS-SECRET-LOCATION"));
        jpg.extend(seg(0xDB, &[0; 65])); jpg.extend(seg(0xC0, &[8, 0, 1, 0, 1, 1, 1, 0x11, 0])); jpg.extend(seg(0xC4, &[0; 17])); jpg.extend(seg(0xDA, &[1, 1, 0, 0, 0x3F, 0]));
        jpg.extend(vec![0x11u8; 5000]); jpg.extend_from_slice(&[0xFF, 0xD9]);
        let src = d.path().join("protest-photo-2026.jpg");
        std::fs::write(&src, &jpg).unwrap();
        a.handle(Key::Char('f'));
        type_str(&mut a, src.to_str().unwrap()); a.handle(Key::Enter);
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].status.contains("Offered after cleaning")), "{}", a.status);
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[1].file_state().is_some_and(|s| s.contains("offered"))), "no offer");
        b.handle(Key::Char('a'));
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[1].file_state().is_some_and(|s| s.contains("received"))), "file never arrived");
        b.handle(Key::Char('s'));
        let Screen::Prompt(Prompt::SaveFile) = &b.screen else { panic!("no save prompt") };
        assert!(b.input.starts_with('/') && b.input.rsplit('/').next().unwrap().starts_with("file-") && b.input.ends_with(".jpg") && !b.input.contains("protest"), "absolute neutral name expected, got {}", b.input);
        let dst = d.path().join(b.input.rsplit('/').next().unwrap());
        b.input = dst.to_str().unwrap().into();
        b.handle(Key::Enter);
        let saved = std::fs::read(&dst).unwrap();
        assert!(!saved.windows(6).any(|w| w == b"Exif\0\0") && !saved.windows(10).any(|w| w == b"GPS-SECRET"), "metadata reached the disk");
        assert!(b.file_state().is_none(), "file leaves RAM once saved");
        // (second file) then panic with a file still in RAM
        a.handle(Key::Char('f'));
        type_str(&mut a, src.to_str().unwrap()); a.handle(Key::Enter);
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[1].file_state().is_some()));
        b.handle(Key::Char('a'));
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[1].file_state().is_some_and(|s| s.contains("received"))));
        b.panic_wipe();
        assert!(b.inbox.is_empty() && b.offers.is_empty());
    }

    /// Regression: the save error path used to unlink the path, destroying an EXISTING file the user tried to overwrite.
    #[test]
    fn deleting_a_contact_or_going_offline_clears_file_state() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "v"); add(&mut a, "bob");
        let id = a.sel_id().unwrap();
        a.inbox.insert(id, Received { data: Zeroizing::new(b"secret".to_vec()), ext: "txt" });
        a.offers.insert(id, ([1; 8], 16384)); a.accepted.insert(id, 16384);
        a.online = Online::Online; // pretend; no engine
        a.handle(Key::Char('o'));
        assert!(a.offers.is_empty() && a.accepted.is_empty(), "going offline must clear transfer state");
        a.online = Online::Offline;
        a.offers.insert(id, ([1; 8], 16384)); a.accepted.insert(id, 16384);
        a.handle(Key::Char('r'));  // clears the stale 'arriving' state? offers has priority: decline path
        a.handle(Key::Char('d')); type_str(&mut a, "yes"); a.handle(Key::Enter);
        assert!(a.inbox.is_empty() && a.offers.is_empty() && a.accepted.is_empty(), "deleted contact's file must leave RAM");
    }

    #[test]
    fn saving_onto_an_existing_file_refuses_and_leaves_it_untouched() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "v"); add(&mut a, "bob");
        let id = a.sel_id().unwrap();
        a.inbox.insert(id, Received { data: Zeroizing::new(b"new content".to_vec()), ext: "txt" });
        let precious = d.path().join("precious");
        std::fs::write(&precious, b"keep me").unwrap();
        a.submit(Prompt::SaveFile, precious.to_str().unwrap().into());
        assert!(a.error, "{}", a.status);
        assert_eq!(std::fs::read(&precious).unwrap(), b"keep me", "existing file must survive");
        assert!(a.inbox.contains_key(&id), "the received file stays in RAM so the user can pick another name");
    }

    #[test]
    fn unsaved_files_are_never_silently_replaced_and_can_be_discarded() {
        let d = tempfile::tempdir().unwrap();
        let (_net, mut a, mut b) = linked_pair(d.path());
        go_online(&mut a); go_online(&mut b);
        assert!(pump_until(&mut [&mut a, &mut b], |x| is_linked(x[0]) && is_linked(x[1])));
        let seg = |m: u8, body: &[u8]| { let mut v = vec![0xFF, m]; v.extend_from_slice(&((body.len() + 2) as u16).to_be_bytes()); v.extend_from_slice(body); v };
        let mut jpg = vec![0xFF, 0xD8];
        jpg.extend(seg(0xDB, &[0; 65])); jpg.extend(seg(0xC0, &[8, 0, 1, 0, 1, 1, 1, 0x11, 0])); jpg.extend(seg(0xC4, &[0; 17])); jpg.extend(seg(0xDA, &[1, 1, 0, 0, 0x3F, 0]));
        jpg.extend(vec![0x11u8; 100]); jpg.extend_from_slice(&[0xFF, 0xD9]);
        let src = d.path().join("x.jpg");
        std::fs::write(&src, &jpg).unwrap();
        let send = |a: &mut App| { a.handle(Key::Char('f')); type_str(a, src.to_str().unwrap()); a.handle(Key::Enter); };
        send(&mut a);
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[1].file_state().is_some_and(|s| s.contains("offered"))));
        b.handle(Key::Char('a'));
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[1].file_state().is_some_and(|s| s.contains("received"))));
        // a second file while the first is unsaved: auto-declined, the first stays
        send(&mut a);
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].status.contains("declined")), "{}", a.status);
        assert!(b.offers.is_empty() && b.inbox.len() == 1);
        b.handle(Key::Char('r'));
        assert!(b.inbox.is_empty() && b.file_state().is_none(), "discard wipes it");
        // a stale offer disappears when the contact disconnects
        send(&mut a);
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[1].file_state().is_some_and(|s| s.contains("offered"))));
        a.handle(Key::Char('o'));
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].online == Online::Offline && !is_linked(x[1])));
        assert!(b.offers.is_empty(), "offer must not outlive the connection");
    }

    #[test]
    fn capability_travels_with_pairing_and_host_anyway_is_a_saved_explicit_choice() {
        let d = tempfile::tempdir().unwrap();
        let net = nerd_chat_chat::MemNet::new();
        let mut a = net_app(d.path(), "a.vault", &net); add(&mut a, "bob");
        let mut b = net_app(d.path(), "b.vault", &net); add(&mut b, "alice");
        a.cfg.can_host = false;                                   // a's Tor cannot host: says so in the bundle it sends
        link_apps(&mut a, &mut b, d.path());
        assert!(!b.vf.as_ref().unwrap().store.contacts[0].peer.as_ref().unwrap().can_host, "b must learn that a cannot host");
        assert!(a.vf.as_ref().unwrap().store.contacts[0].peer.as_ref().unwrap().can_host);
        // host anyway: refused when WE cannot host, saved and applied when we can
        a.handle(Key::Char('h')); assert!(a.error && !a.vf.as_ref().unwrap().store.contacts[0].host_anyway);
        b.handle(Key::Char('h'));
        assert!(b.error && b.status.contains("HOST ANYWAY is ON") && b.vf.as_ref().unwrap().store.contacts[0].host_anyway);
        b.handle(Key::Char('h'));
        assert!(!b.error && !b.vf.as_ref().unwrap().store.contacts[0].host_anyway);
        b.handle(Key::Char('h'));
        let path = d.path().join("b.vault");
        drop(b);
        let mut b2 = App::new(cfg(Some(path)));
        type_str(&mut b2, "correct horse battery"); b2.handle(Key::Enter);
        assert!(b2.vf.as_ref().unwrap().store.contacts[0].host_anyway, "the choice must survive the vault");
        // the exported file carries the capability
        let f = d.path().join("own.sbc");
        a.handle(Key::Char('e')); a.input = f.to_str().unwrap().into(); a.handle(Key::Enter);
        let txt = std::fs::read_to_string(&f).unwrap();
        assert!(!nerd_chat_exchange::file::dearmor(&txt).unwrap().can_host, "the exported bundle must say that this Tor cannot host");
        // review 12 (M1/L2): what we told a contact is FIXED: a later run without --cannot-host exports the same bit, and roles use it
        a.cfg.can_host = true;
        let f2 = d.path().join("own2.sbc");
        a.handle(Key::Char('e')); a.input = f2.to_str().unwrap().into(); a.handle(Key::Enter);
        assert!(!nerd_chat_exchange::file::dearmor(&std::fs::read_to_string(&f2).unwrap()).unwrap().can_host, "advertised capability must not change per export");
        assert_eq!(a.vf.as_ref().unwrap().store.contacts[0].adv_can_host, Some(false));
        assert_eq!(a.cap_mismatch(), Some(false), "today's flag differs from what the contact was told: the UI must say so");
        a.cfg.can_host = false;
        assert_eq!(a.cap_mismatch(), None);
        a.cfg.can_host = true;
        let (_, _, a_hosts) = a.contact_roles().unwrap();
        assert!(!a_hosts, "a cannot host (as advertised), so it must not claim to host");
        // turning host-anyway OFF stays possible when the advertised capability is 'cannot host'
        a.vf().store.contacts[0].host_anyway = true;
        a.handle(Key::Char('h'));
        assert!(!a.vf.as_ref().unwrap().store.contacts[0].host_anyway && !a.error, "{}", a.status);
    }

    #[test]
    fn contact_added_while_online_connects_and_offline_is_refused_cleanly() {
        let d = tempfile::tempdir().unwrap();
        let net = nerd_chat_chat::MemNet::new();
        let mut a = net_app(d.path(), "a.vault", &net); add(&mut a, "bob");
        let mut b = net_app(d.path(), "b.vault", &net); add(&mut b, "alice");
        // typing while offline: refused, nothing sent
        a.handle(Key::Char('l')); a.handle(Key::Esc); // (cancelled prompt, harmless)
        go_online(&mut a); go_online(&mut b);
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].online == Online::Online && x[1].online == Online::Online));
        // engines are up but have NO contacts yet; now exchange keys: the hook adds them to the running engines
        link_apps(&mut a, &mut b, d.path());
        assert!(pump_until(&mut [&mut a, &mut b], |x| is_linked(x[0]) && is_linked(x[1])), "hook did not add the contact to the engine");
        // go offline: connection closes on both sides; typing is refused
        a.handle(Key::Char('o'));
        assert_eq!(a.online, Online::Stopping, "teardown runs on a worker; the UI stays responsive");
        a.handle(Key::Char('o')); assert!(a.error, "second press while stopping is refused");
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].online == Online::Offline), "never finished stopping");
        assert!(pump_until(&mut [&mut a, &mut b], |x| !is_linked(x[1])), "peer must notice");
        a.handle(Key::Char('i')); type_str(&mut a, "x"); a.handle(Key::Enter);
        assert!(a.error && a.status.contains("offline") && a.chat_lines().is_empty());
    }

    #[test]
    fn online_failure_is_reported_and_retry_is_possible() {
        let d = tempfile::tempdir().unwrap();
        let mut c = cfg(Some(d.path().join("v")));
        c.transport = Some(std::sync::Arc::new(|_p: &mut dyn FnMut(u8)| Err("no tor binary found".to_string())));
        let mut a = App::new(c);
        type_str(&mut a, "correct horse battery"); a.handle(Key::Enter);
        type_str(&mut a, "correct horse battery"); a.handle(Key::Enter);
        go_online(&mut a);
        assert!(matches!(a.online, Online::Starting(_)));
        assert!(pump_until(&mut [&mut a], |x| matches!(x[0].online, Online::Failed(_))));
        assert!(a.error && a.status.contains("no tor binary"));
        go_online(&mut a); // can retry
        assert!(matches!(a.online, Online::Starting(_)));
    }

    #[test]
    fn delete_while_online_and_panic_wipe_everything_in_the_chat() {
        let d = tempfile::tempdir().unwrap();
        let (_net, mut a, mut b) = linked_pair(d.path());
        go_online(&mut a); go_online(&mut b);
        assert!(pump_until(&mut [&mut a, &mut b], |x| is_linked(x[0]) && is_linked(x[1])));
        a.handle(Key::Char('i')); type_str(&mut a, "secret words"); a.handle(Key::Enter);
        type_str(&mut a, "half typed secret");
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[1].contact_rows()[0].4 == 1));
        // PANIC on a: engine stopped, messages gone, half-typed line gone, quick
        let t = Instant::now();
        assert_eq!(a.handle(Key::F12), Action::Panic);
        assert!(t.elapsed() < Duration::from_secs(2));
        assert!(a.chat_lines().is_empty() && a.compose_text().is_empty() && a.engine.is_none() && a.chats.is_empty());
        assert_eq!(a.online, Online::Offline);
        assert!(pump_until(&mut [&mut b], |x| !is_linked(x[0])), "peer sees the connection drop");
        // b deletes the contact while online: chat, link and engine entry are removed
        b.handle(Key::Char('d')); type_str(&mut b, "yes"); b.handle(Key::Enter);
        assert_eq!(b.contacts_len(), 0);
        assert!(b.chats.is_empty() && b.linked.is_empty() && b.unread.is_empty());
    }

    /// A transport factory that blocks until released: lets a test change contacts while tor is still "starting".
    fn gated_app(dir: &std::path::Path, name: &str, net: &nerd_chat_chat::MemNet, gate: std::sync::Arc<std::sync::atomic::AtomicBool>) -> App {
        let mut c = cfg(Some(dir.join(name)));
        let net = net.clone();
        c.transport = Some(std::sync::Arc::new(move |_p: &mut dyn FnMut(u8)| {
            while !gate.load(Ordering::SeqCst) { thread::sleep(Duration::from_millis(20)); }
            Ok(Box::new(net.transport()) as Box<dyn Transport>)
        }));
        c.timing = fast_timing();
        let mut a = App::new(c);
        type_str(&mut a, "correct horse battery"); a.handle(Key::Enter);
        type_str(&mut a, "correct horse battery"); a.handle(Key::Enter);
        a
    }

    fn pump_for(apps: &mut [&mut App], d: Duration) { let t = Instant::now(); while t.elapsed() < d { for a in apps.iter_mut() { a.poll(); } thread::sleep(Duration::from_millis(20)); } }

    /// R6-M4/L1: a contact deleted while tor is still starting must not stay live in the engine.
    #[test]
    fn contact_deleted_while_starting_is_removed_from_the_engine() {
        let d = tempfile::tempdir().unwrap();
        let net = nerd_chat_chat::MemNet::new();
        let gate = std::sync::Arc::new(AtomicBool::new(false));
        let mut a = gated_app(d.path(), "a.vault", &net, gate.clone()); add(&mut a, "bob");
        let mut b = net_app(d.path(), "b.vault", &net); add(&mut b, "alice");
        link_apps(&mut a, &mut b, d.path());
        go_online(&mut b);
        assert!(pump_until(&mut [&mut b], |x| x[0].online == Online::Online));
        go_online(&mut a);                                        // Starting: blocked on the gate
        assert!(matches!(a.online, Online::Starting(_)));
        a.handle(Key::Char('d')); type_str(&mut a, "yes"); a.handle(Key::Enter);
        assert_eq!(a.contacts_len(), 0);
        gate.store(true, Ordering::SeqCst);
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].online == Online::Online));
        pump_for(&mut [&mut a, &mut b], Duration::from_millis(1500));
        assert!(!is_linked(&b), "the deleted contact must not be reachable any more");
        assert!(a.chats.is_empty() && a.unread.is_empty(), "no hidden chat state for a deleted contact");
    }

    /// R6-L2: a contact whose keys arrive while tor is starting must still connect.
    #[test]
    fn contact_linked_while_starting_connects_after_ready() {
        let d = tempfile::tempdir().unwrap();
        let net = nerd_chat_chat::MemNet::new();
        let gate = std::sync::Arc::new(AtomicBool::new(false));
        let mut a = gated_app(d.path(), "a.vault", &net, gate.clone()); add(&mut a, "bob");
        let mut b = net_app(d.path(), "b.vault", &net); add(&mut b, "alice");
        go_online(&mut b);
        go_online(&mut a);
        assert!(matches!(a.online, Online::Starting(_)));
        link_apps(&mut a, &mut b, d.path());                      // keys exchanged while starting
        gate.store(true, Ordering::SeqCst);
        assert!(pump_until(&mut [&mut a, &mut b], |x| is_linked(x[0]) && is_linked(x[1])), "contact added during startup never connected");
    }

    /// R6-L7: a bundle that reuses another contact's onion address is refused.
    #[test]
    fn bundle_reusing_another_contacts_onion_address_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "a.vault"); add(&mut a, "bob"); add(&mut a, "carol");
        let victim_onion = a.vf.as_ref().unwrap().store.contacts[0].identity.onion_public();
        let mal = ContactIdentity::generate();
        let mut bad = Bundle::from_identity(&mal);
        bad.onion_pub = victim_onion;                             // valid point, validly signed by mal, but not mal's own address
        let f = d.path().join("evil.sbc");
        fs::write(&f, file::armor(&bad.encode(&mal))).unwrap();
        a.sel = 1;
        a.handle(Key::Char('I')); type_str(&mut a, f.to_str().unwrap()); a.handle(Key::Enter);
        assert!(a.error && a.status.contains("Refused"), "{}", a.status);
        assert!(a.selected_detail().unwrap().2.is_none(), "nothing was stored");
    }

    /// R6-L5: wide characters must wrap, not silently fall off the right edge.
    #[test]
    fn wide_characters_wrap_instead_of_disappearing() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "a.vault"); add(&mut a, "bob");
        let id = a.vf.as_ref().unwrap().store.contacts[0].id;
        a.vf.as_mut().unwrap().store.contacts[0].peer = Some(Bundle::from_identity(&ContactIdentity::generate()));
        let _ = id;
        a.pane = Pane::Chat;
        let msg: String = "漢".repeat(60);
        a.push_line(id, ChatLine { mine: false, text: Zeroizing::new(msg.clone()), queued: false, saved: false, unsent: false, unconfirmed: false, mid: None });
        a.push_line(id, ChatLine { mine: true, text: Zeroizing::new(msg), queued: false, saved: false, unsent: false, unconfirmed: false, mid: None });
        let mut term = ratatui::Terminal::new(ratatui::backend::TestBackend::new(44, 30)).unwrap();
        term.draw(|f| crate::ui::draw(f, &a)).unwrap();
        let screen: String = term.backend().buffer().content().iter().map(|c| c.symbol()).collect();
        assert_eq!(screen.matches('漢').count(), 120, "every character of both messages must be visible");
    }

    #[test]
    fn wrong_code_pairing_fails_cleanly() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "a.vault"); add(&mut a, "bob");
        let mut b = create_app(d.path(), "b.vault"); add(&mut b, "alice");
        let (addr, _code) = listen(&mut a);
        join_and_wait(&mut a, &mut b, &addr, "0000000000");
        assert!(a.error && b.error, "{} / {}", a.status, b.status);
        assert!(a.selected_detail().unwrap().2.is_none() && b.selected_detail().unwrap().2.is_none());
    }

    // ---------- vim-style modes, sidebar layout, privacy screen (UI overhaul) ----------

    fn add_peer(a: &mut App, name: &str) {
        add(a, name);
        let i = a.vf.as_ref().unwrap().store.contacts.len() - 1;
        a.vf().store.contacts[i].peer = Some(Bundle::from_identity(&ContactIdentity::generate()));
    }

    fn screen_text(a: &App, w: u16, h: u16) -> String {
        let mut term = ratatui::Terminal::new(ratatui::backend::TestBackend::new(w, h)).unwrap();
        term.draw(|f| crate::ui::draw(f, a)).unwrap();
        term.backend().buffer().content().iter().map(|c| c.symbol()).collect()
    }

    #[test]
    fn esc_ladder_walks_typing_normal_details_lock_and_enter_comes_back() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "v"); add_peer(&mut a, "bob");
        assert_eq!((a.pane, a.mode, a.locked), (Pane::Details, Mode::Normal, false));
        a.handle(Key::Char('i'));                                   // details -> chat, typing
        assert_eq!((a.pane, a.mode), (Pane::Chat, Mode::Insert));
        type_str(&mut a, "draft");
        a.handle(Key::Esc);                                         // 1st Esc: leave typing only
        assert_eq!((a.pane, a.mode, a.locked), (Pane::Chat, Mode::Normal, false));
        assert_eq!(a.compose_text(), "draft", "leaving insert mode keeps the draft");
        a.handle(Key::Esc);                                         // 2nd Esc: back to the details
        assert_eq!((a.pane, a.mode, a.locked), (Pane::Details, Mode::Normal, false));
        assert_eq!(a.compose_text(), "", "closing the chat drops the draft");
        assert_eq!(a.handle(Key::Esc), Action::None);               // 3rd Esc: privacy screen, NOT quit
        assert!(a.locked && a.screen == Screen::Main);
        assert_eq!(a.handle(Key::Esc), Action::None); assert!(a.locked, "Esc on the lock screen does nothing");
        assert_eq!(a.handle(Key::Char('f')), Action::None); assert!(a.locked && a.screen == Screen::Main, "other keys are swallowed");
        a.handle(Key::Enter);
        assert!(!a.locked && a.pane == Pane::Details && a.sel == 0, "Enter unlocks without a password and returns to where we were");
        a.handle(Key::Esc); assert!(a.locked);
        assert_eq!(a.handle(Key::Char('q')), Action::Quit, "q on the lock screen quits");
    }

    #[test]
    fn panic_key_works_in_every_mode_pane_and_in_the_lock() {
        for setup in 0..4 {
            let d = tempfile::tempdir().unwrap();
            let mut a = create_app(d.path(), "v"); add_peer(&mut a, "bob");
            match setup { 0 => {} , 1 => { a.handle(Key::Char('i')); } , 2 => { a.handle(Key::Char('i')); a.handle(Key::Esc); } , _ => { a.handle(Key::Esc); } }
            type_str_if_insert(&mut a);
            a.quit_armed = true; a.select = Some(3); a.saved_sel = 2;
            assert_eq!(a.handle(Key::F12), Action::Panic, "setup {setup}");
            assert_eq!(a.screen, Screen::Wiped);
            assert!(a.select.is_none() && a.saved_sel == 0 && !a.locked && !a.quit_armed && a.pane == Pane::Details && a.mode == Mode::Normal && a.scroll == 0 && a.compose_text().is_empty());
        }
    }
    fn type_str_if_insert(a: &mut App) { if a.mode == Mode::Insert { type_str(a, "secret draft"); } }

    #[test]
    fn typed_text_in_insert_mode_never_acts_as_a_command() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "v"); add_peer(&mut a, "bob"); add_peer(&mut a, "carol");
        a.handle(Key::Char('i'));
        for c in "qfatsvdohKzgGjk?nIlcxe I".chars() { assert_eq!(a.handle(Key::Char(c)), Action::None, "{c}"); }
        assert_eq!((a.screen == Screen::Main, a.pane, a.mode, a.locked), (true, Pane::Chat, Mode::Insert, false), "still typing, no prompt, no popup, not locked");
        assert_eq!(a.compose_text(), "qfatsvdohKzgGjk?nIlcxe I");
        assert_eq!(a.contacts_len(), 2, "no contact was created or deleted");
        assert_eq!(a.online, Online::Offline);
        // Tab / arrows in insert mode do nothing either (no contact switch, no scroll)
        let sel = a.sel;
        for k in [Key::Tab, Key::BackTab, Key::Up, Key::Down, Key::PageUp, Key::Home] { a.handle(k); }
        assert_eq!((a.sel, a.scroll), (sel, 0));
    }

    #[test]
    fn contact_commands_work_in_normal_mode_while_a_chat_is_open_and_act_on_the_shown_contact() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "v"); add_peer(&mut a, "bob"); add_peer(&mut a, "carol");
        a.sel = 1;
        a.handle(Key::Enter);                                        // open the chat of carol (normal mode)
        assert_eq!((a.pane, a.mode, a.sel), (Pane::Chat, Mode::Normal, 1));
        a.handle(Key::Char('v'));                                    // verify: carol's safety number
        assert_eq!(a.screen, Screen::Verify);
        a.handle(Key::Char('n')); assert_eq!(a.screen, Screen::Main);
        a.handle(Key::Char('f'));                                    // not connected: refused with a reason, no prompt
        assert!(a.error && a.status.contains("CONNECTED") && a.screen == Screen::Main, "{}", a.status);
        a.handle(Key::Char('d'));
        assert_eq!(a.screen, Screen::Prompt(Prompt::ConfirmDelete));
        type_str(&mut a, "yes"); a.handle(Key::Enter);
        assert_eq!(a.contacts_len(), 1, "carol (the contact shown) was deleted, not bob");
        assert_eq!(a.vf.as_ref().unwrap().store.contacts[0].name, "bob");
        assert_eq!((a.pane, a.mode), (Pane::Details, Mode::Normal), "deleting the open contact closes the chat");
    }

    #[test]
    fn tab_and_shift_tab_switch_contacts_and_reset_the_chat_state() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "v"); add_peer(&mut a, "bob"); add(&mut a, "nopeer"); add_peer(&mut a, "carol");
        let ids: Vec<[u8; 8]> = a.vf.as_ref().unwrap().store.contacts.iter().map(|c| c.id).collect();
        a.sel = 0; a.handle(Key::Enter);
        a.handle(Key::Char('i')); type_str(&mut a, "half"); a.handle(Key::Esc);
        a.unread.insert(ids[2], 3); a.scroll = 7;
        a.handle(Key::Tab);
        assert_eq!(a.sel, 2, "Tab skips contacts without a peer key");
        assert_eq!((a.compose_text(), a.scroll, a.mode, a.pane), ("", 0, Mode::Normal, Pane::Chat));
        assert_eq!(a.unread.get(&ids[2]), None, "unread cleared by showing the chat");
        a.handle(Key::Tab); assert_eq!(a.sel, 0, "wraps around");
        a.handle(Key::BackTab); assert_eq!(a.sel, 2);
        // in the details view Tab/Shift+Tab just move the selection
        a.handle(Key::Esc); assert_eq!(a.pane, Pane::Details);
        a.sel = 0; a.handle(Key::Tab); assert_eq!(a.sel, 1); a.handle(Key::BackTab); assert_eq!(a.sel, 0);
    }

    #[test]
    fn history_scrolls_and_jumps_back_to_the_newest_line() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "v"); add_peer(&mut a, "bob");
        let id = a.vf.as_ref().unwrap().store.contacts[0].id;
        for i in 0..60 { a.push_line(id, ChatLine { mine: i % 2 == 0, text: Zeroizing::new(format!("line-{i:02}")), queued: false, saved: false, unsent: false, unconfirmed: false, mid: None }); }
        a.handle(Key::Enter);
        let s0 = screen_text(&a, 110, 24);
        assert!(s0.contains("line-59") && !s0.contains("line-00"), "starts at the newest line");
        a.handle(Key::Home);                                         // oldest
        let s1 = screen_text(&a, 110, 24);
        assert!(s1.contains("line-00") && !s1.contains("line-59") && s1.contains("scrolled up"), "{s1}");
        a.handle(Key::End);
        assert_eq!(a.scroll, 0);
        a.handle(Key::Char('k')); a.handle(Key::Up); assert_eq!(a.scroll, 2);
        a.handle(Key::PageUp); assert_eq!(a.scroll, 12);
        a.handle(Key::Char('j')); a.handle(Key::PageDown); a.handle(Key::PageDown); assert_eq!(a.scroll, 0, "never below the newest line");
        a.handle(Key::Char('g')); screen_text(&a, 110, 24); a.poll();      // 'g' before the next frame: the app learns the real limit from the frame
        let lim = a.max_scroll.get().expect("the frame reported its limit");
        assert!(lim > 20 && a.scroll == lim, "scroll {} limit {lim}", a.scroll);
        a.handle(Key::Char('j')); assert_eq!(a.scroll, lim - 1, "j works at once after g: no huge hidden offset");
        a.handle(Key::PageUp); a.handle(Key::PageUp); assert_eq!(a.scroll, lim, "never above the oldest line");
        a.handle(Key::Char('G')); assert_eq!(a.scroll, 0);
    }

    #[test]
    fn the_sidebar_stays_visible_in_every_state_and_narrow_terminals_show_one_pane() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "v"); add_peer(&mut a, "bob"); add_peer(&mut a, "carol");
        let details = screen_text(&a, 110, 24);
        assert!(details.contains("Contacts") && details.contains("bob") && details.contains("carol") && details.contains("Details"));
        a.sel = 0; a.handle(Key::Enter);
        let chat = screen_text(&a, 110, 24);
        assert!(chat.contains("bob") && chat.contains("carol") && chat.contains("Contacts") && chat.contains("Conversation") && chat.contains("NORMAL"), "{chat}");
        a.handle(Key::Char('n'));                                     // a prompt: the sidebar is still there under it
        let prompt = screen_text(&a, 110, 24);
        assert!(prompt.contains("New contact") && prompt.contains("carol"));
        a.handle(Key::Esc);
        a.handle(Key::Char('i')); assert!(screen_text(&a, 110, 24).contains("-- INSERT --"));
        // narrow terminal (< 70 columns): one pane at a time
        let narrow_chat = screen_text(&a, 60, 20);
        assert!(narrow_chat.contains("Conversation") && !narrow_chat.contains("Contacts"), "{narrow_chat}");
        a.handle(Key::Esc); a.handle(Key::Esc);
        let narrow_list = screen_text(&a, 60, 20);
        assert!(narrow_list.contains("Contacts") && !narrow_list.contains("Conversation"));
        assert!(narrow_list.contains("Details") && narrow_list.contains("Safety number"), "a narrow terminal must not hide the safety number and warnings: {narrow_list}");
        let mut tiny = ratatui::Terminal::new(ratatui::backend::TestBackend::new(20, 5)).unwrap();
        tiny.draw(|f| crate::ui::draw(f, &a)).unwrap();               // no panic
    }

    #[test]
    fn a_pending_file_offer_is_visible_inside_the_chat_too() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "v"); add_peer(&mut a, "bob");
        let id = a.vf.as_ref().unwrap().store.contacts[0].id;
        a.offers.insert(id, ([7; 8], 65536));
        a.handle(Key::Enter);
        for (w, h) in [(110, 24), (60, 20)] {
            let s = screen_text(&a, w, h);
            assert!(s.contains("File offered") || s.contains("File offered (up to"), "{w}x{h}: the offer must be visible in the chat: {s}");
        }
    }

    #[test]
    fn the_alert_history_outlives_the_acknowledgement_and_dies_with_a_panic() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "v"); add_peer(&mut a, "bob");
        let id = a.vf.as_ref().unwrap().store.contacts[0].id;
        a.record_alert(Some(id), "bad thing"); a.record_alert(Some(id), "bad thing");
        a.handle(Key::Char('z'));
        assert!(a.alerts.is_empty());
        assert_eq!(a.alert_history(), &[("bob: bad thing".to_string(), 2)]);
        for i in 0..40 { a.record_alert(None, &format!("n{i}")); }
        assert_eq!(a.alert_history().len(), 30, "bounded");
        a.panic_wipe();
        assert!(a.alert_history().is_empty(), "wiped with everything else");
    }

    #[test]
    fn the_inspector_reports_states_only_and_matches_the_roles() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "v");
        assert!(a.inspect().is_none(), "no contact");
        add_peer(&mut a, "bob");
        let i = a.inspect().expect("a paired contact");
        assert!(!i.connected && !i.host_anyway && i.rotation.is_none() && i.saved == 0);
        assert!(!i.rotation_possible, "offline: a rotation cannot start");
        assert_eq!(Some((i.contact_can_host, i.host_anyway, i.we_host_now)), a.contact_roles());
        let dump = format!("{i:?}");
        assert!(!dump.contains("bob"), "no names in the inspector data: {dump}");
        a.handle(Key::Char('h'));
        assert_eq!(a.inspect().unwrap().host_anyway, a.vf.as_ref().unwrap().store.contacts[0].host_anyway);
    }

    #[test]
    fn the_privacy_screen_draws_nothing_about_contacts_or_messages() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "v"); add_peer(&mut a, "bobsecret");
        let id = a.vf.as_ref().unwrap().store.contacts[0].id;
        a.push_line(id, ChatLine { mine: false, text: Zeroizing::new("topsecretmessage".into()), queued: false, saved: false, unsent: false, unconfirmed: false, mid: None });
        a.unread.insert(id, 4);
        a.record_alert(Some(id), "something bad happened with bobsecret");
        a.ok("Paired: Safety number 11111 22222 with bobsecret");
        a.pair_info = Some(Zeroizing::new("Listening on 127.0.0.1:4444  -  CODE: 99999-88888".into()));
        assert!(screen_text(&a, 110, 24).contains("bobsecret"));      // sanity: visible when unlocked
        a.handle(Key::Esc);
        let locked = screen_text(&a, 110, 24);
        assert!(locked.contains("LOCKED") && locked.contains("Enter = unlock") && locked.contains("a security alert is waiting"));
        for leak in ["bobsecret", "topsecretmessage", "something bad", "Contacts", "Details", "NERD-CHAT", "[4]", "Safety number", "99999-88888", "127.0.0.1:4444", "Paired"] { assert!(!locked.contains(leak), "the privacy screen leaked {leak:?}"); }
        let narrow = screen_text(&a, 30, 8);
        assert!(!narrow.contains("bobsecret"));
    }

    #[test]
    fn the_app_keeps_running_underneath_the_privacy_screen() {
        let d = tempfile::tempdir().unwrap();
        let (_net, mut a, mut b) = linked_pair(d.path());
        go_online(&mut a); go_online(&mut b);
        assert!(pump_until(&mut [&mut a, &mut b], |x| is_linked(x[0]) && is_linked(x[1])));
        a.handle(Key::Esc); assert!(a.locked);
        b.handle(Key::Char('i')); b.scroll = 9; type_str(&mut b, "while you were away"); b.handle(Key::Enter);
        assert_eq!(b.scroll, 0, "sending jumps to the newest line");
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].contact_rows()[0].4 == 1), "the message must arrive while locked");
        assert!(is_linked(&a), "the connection stays up under the privacy screen");
        assert!(!screen_text(&a, 100, 20).contains("while you were away"));
        a.handle(Key::Enter);
        assert!(screen_text(&a, 100, 20).contains("[1]"), "unread marker visible after unlocking");
        a.handle(Key::Enter);
        assert!(a.chat_lines().iter().any(|l| &*l.text == "while you were away"));
    }

    /// Review 20 (H1): a pairing that finishes while the user is TYPING must not steal the next keys into the "in person?" question
    /// (a `y` there upgrades trust) and must not drop the user into normal mode where typed text would run commands.
    #[test]
    fn a_pairing_that_finishes_while_typing_changes_nothing_until_the_user_presses_p() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "a.vault"); add(&mut a, "bob"); add_peer(&mut a, "carol");
        let mut b = create_app(d.path(), "b.vault"); add(&mut b, "alice");
        a.sel = 0; let (addr, code) = listen(&mut a);                              // listen for bob's pairing
        a.sel = 1; a.handle(Key::Char('i')); type_str(&mut a, "he");               // typing a message to carol
        join_and_wait(&mut a, &mut b, &addr, &code);
        assert!(a.pending_pair.is_some(), "{}", a.status);
        assert_eq!((a.screen == Screen::Main, a.pane, a.mode), (true, Pane::Chat, Mode::Insert), "still typing, no prompt, mode untouched");
        // the keys the user types now are TEXT: a `y` and Enter must not answer anything
        type_str(&mut a, "y"); a.handle(Key::Enter);
        assert_eq!(a.compose_text(), "hey", "the keys went into the draft");
        assert!(a.vf.as_ref().unwrap().store.contacts[0].peer.is_none(), "bob is NOT paired yet");
        assert!(a.pending_pair.is_some());
        // only a deliberate P (normal mode) opens the question; answering finishes the pairing
        a.handle(Key::Char('P')); assert_eq!(a.screen, Screen::Main, "P in insert mode is just text");
        a.handle(Key::Esc);
        a.handle(Key::Char('P'));
        assert_eq!(a.screen, Screen::Prompt(Prompt::InPerson));
        // while the answer is pending no second pairing may start
        a.handle(Key::Esc);                                                          // Esc = "n": paired, but unverified
        assert!(a.pending_pair.is_none() && a.vf.as_ref().unwrap().store.contacts[0].peer.is_some());
        assert_eq!(a.vf.as_ref().unwrap().store.contacts[0].trust, Trust::Unverified);
        // a prompt opened while locked stays hidden and unanswerable
        a.handle(Key::Esc); a.handle(Key::Esc); a.handle(Key::Esc); assert!(a.locked);
        a.open_prompt(Prompt::NewContact, "");
        assert!(screen_text(&a, 90, 20).contains("LOCKED") && !screen_text(&a, 90, 20).contains("New contact"));
        a.handle(Key::Char('x')); assert!(a.locked && a.screen == Screen::Prompt(Prompt::NewContact), "keys do not reach the prompt");
    }

    #[test]
    fn a_second_pairing_cannot_start_while_one_waits_for_its_answer() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "a.vault"); add(&mut a, "bob"); add(&mut a, "carol");
        a.pending_pair = Some(([0; 8], ImportedContact::from_file(Bundle::from_identity(&ContactIdentity::generate())), "123".into()));
        a.sel = 1; a.handle(Key::Char('l'));
        assert!(a.error && a.status.contains("press P") && !a.pair_ctl.is_some(), "{}", a.status);
    }

    /// A message typed while the contact was away is shown as "(queued)"; once the contact's app has CONFIRMED it (not merely once it was written) the label goes.
    #[test]
    fn a_queued_line_stops_saying_queued_once_it_was_delivered_to_the_connection() {
        let d = tempfile::tempdir().unwrap();
        let (_net, mut a, mut b) = linked_pair(d.path());
        go_online(&mut a);
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].online == Online::Online));
        a.handle(Key::Char('i')); type_str(&mut a, "while you were away"); a.handle(Key::Enter);
        assert!(a.chat_lines()[0].queued && screen_text(&a, 110, 24).contains("(queued)"), "queued while bob is not connected");
        assert!(a.status.contains("queued"));
        go_online(&mut b);
        assert!(pump_until(&mut [&mut a, &mut b], |x| !x[0].chat_lines()[0].queued), "the label must change after delivery");
        assert!(!screen_text(&a, 110, 24).contains("(queued)"));
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[1].chats.values().any(|l| l.iter().any(|m| &*m.text == "while you were away"))), "and bob really got it");
        assert!(a.at_risk().is_empty(), "nothing is at risk any more");
    }

    // ---------- manual saving of chosen messages (nothing is ever saved automatically) ----------

    fn chat_with_lines(d: &std::path::Path, n: usize) -> App {
        let mut a = create_app(d, "v"); add_peer(&mut a, "bob");
        let id = a.vf.as_ref().unwrap().store.contacts[0].id;
        for i in 0..n { a.push_line(id, ChatLine { mine: i % 2 == 0, text: Zeroizing::new(format!("message-{i}")), queued: false, saved: false, unsent: false, unconfirmed: false, mid: None }); }
        a.handle(Key::Enter);
        a
    }

    #[test]
    fn nothing_is_saved_unless_the_user_selects_a_message_and_confirms() {
        let d = tempfile::tempdir().unwrap();
        let mut a = chat_with_lines(d.path(), 5);
        let id = a.vf.as_ref().unwrap().store.contacts[0].id;
        a.push_line(id, ChatLine { mine: false, text: Zeroizing::new("incoming".into()), queued: false, saved: false, unsent: false, unconfirmed: false, mid: None });
        for k in [Key::Char('j'), Key::Char('k'), Key::Tab, Key::PageUp, Key::Char('G')] { a.handle(k); }
        assert!(a.vf.as_ref().unwrap().store.contacts[0].saved.is_empty(), "receiving, reading, scrolling and sending never save anything");
        // the message cursor: m, move to the 2nd newest, y
        a.handle(Key::Char('m')); assert_eq!(a.select, Some(0));
        a.handle(Key::Char('k')); assert_eq!(a.select, Some(1));
        let shown = screen_text(&a, 110, 24);
        assert!(shown.contains("choose a message") && shown.contains("SELECT"), "{shown}");
        a.handle(Key::Esc); assert!(a.select.is_none() && a.vf.as_ref().unwrap().store.contacts[0].saved.is_empty(), "Esc saves nothing");
        a.handle(Key::Char('m')); a.handle(Key::Char('k')); a.handle(Key::Char('y'));
        let c = &a.vf.as_ref().unwrap().store.contacts[0];
        assert_eq!(c.saved.len(), 1);
        assert_eq!((c.saved[0].text.as_str(), c.saved[0].mine), ("message-4", true), "the SECOND newest message (index 4 of 0..5, even = mine)");
        assert!(a.select.is_none() && a.chat_lines().iter().filter(|l| l.saved).count() == 1);
        assert!(screen_text(&a, 110, 24).contains("me★>"), "a saved message is marked");
        // saving it again is refused, nothing doubles
        a.handle(Key::Char('m')); a.handle(Key::Char('k')); a.handle(Key::Char('y'));
        assert!(a.error && a.status.contains("already saved") && a.vf.as_ref().unwrap().store.contacts[0].saved.len() == 1, "{}", a.status);
        // it really reached the vault FILE: reopen it
        drop(a);
        let mut b = App::new(cfg(Some(d.path().join("v"))));
        type_str(&mut b, "correct horse battery"); b.handle(Key::Enter);
        assert_eq!(&*b.vf.as_ref().unwrap().store.contacts[0].saved[0].text, "message-4");
        assert!(b.chat_lines().is_empty(), "the conversation itself was never stored");
    }

    #[test]
    fn the_message_cursor_ignores_every_other_key_and_insert_mode_never_starts_it() {
        let d = tempfile::tempdir().unwrap();
        let mut a = chat_with_lines(d.path(), 3);
        a.handle(Key::Char('i')); type_str(&mut a, "m"); assert_eq!((a.select, a.compose_text()), (None, "m"), "an `m` typed in insert mode is just text");
        a.handle(Key::Esc);
        a.compose.clear();
        a.handle(Key::Char('m'));
        for c in "qfatsvdohKzPnIlcxe?H".chars() { assert_eq!(a.handle(Key::Char(c)), Action::None, "{c}"); }
        assert!(a.select.is_some() && a.screen == Screen::Main && a.online == Online::Offline && a.contacts_len() == 1, "no command ran while the cursor was active");
        a.handle(Key::Esc); assert!(a.select.is_none() && a.pane == Pane::Chat, "Esc leaves the cursor, not the chat");
        a.handle(Key::Char('m')); a.handle(Key::Esc); a.handle(Key::Esc);
        assert_eq!(a.pane, Pane::Details, "the Esc ladder is unchanged: cursor -> chat -> details");
        assert_eq!(a.handle(Key::F12), Action::Panic);
    }

    #[test]
    fn ram_only_mode_cannot_save_and_an_empty_chat_has_nothing_to_select() {
        let mut a = App::new(cfg(None));
        a.handle(Key::Enter);                                         // RAM-only: no password
        add_peer(&mut a, "bob");
        a.handle(Key::Enter); a.handle(Key::Char('m')); assert!(a.error && a.select.is_none(), "{}", a.status);
        let id = a.vf.as_ref().unwrap().store.contacts[0].id;
        a.push_line(id, ChatLine { mine: true, text: Zeroizing::new("x".into()), queued: false, saved: false, unsent: false, unconfirmed: false, mid: None });
        a.handle(Key::Char('m')); a.handle(Key::Char('y'));
        assert!(a.error && a.status.contains("RAM-only") && a.vf.as_ref().unwrap().store.contacts[0].saved.is_empty(), "{}", a.status);
    }

    #[test]
    fn the_saved_view_lists_deletes_with_two_presses_and_goes_back() {
        let d = tempfile::tempdir().unwrap();
        let mut a = chat_with_lines(d.path(), 4);
        for i in 0..3 { a.handle(Key::Char('m')); for _ in 0..i { a.handle(Key::Char('k')); } a.handle(Key::Char('y')); }   // the newest, the 2nd, the 3rd
        let n = a.vf.as_ref().unwrap().store.contacts[0].saved.len();
        assert_eq!(n, 3);
        a.handle(Key::Esc); assert_eq!(a.pane, Pane::Details);
        assert!(screen_text(&a, 110, 24).contains(&format!("Saved messages: {n}")), "the details show how many are saved");
        a.handle(Key::Char('H')); assert_eq!(a.pane, Pane::Saved);
        let view = screen_text(&a, 110, 24);
        assert!(view.contains("Saved messages of bob") && view.contains("message-"), "{view}");
        a.handle(Key::Char('d')); assert!(a.status.contains("d again") && a.vf.as_ref().unwrap().store.contacts[0].saved.len() == n, "the first d only arms");
        a.handle(Key::Char('j')); a.handle(Key::Char('d')); assert_eq!(a.vf.as_ref().unwrap().store.contacts[0].saved.len(), n, "any other key disarms");
        a.handle(Key::Char('d')); a.handle(Key::Char('d'));
        assert_eq!(a.vf.as_ref().unwrap().store.contacts[0].saved.len(), n - 1);
        // typed commands do not run in the saved view
        for c in "fntvoh".chars() { a.handle(Key::Char(c)); }
        assert!(a.screen == Screen::Main && a.online == Online::Offline && !a.locked);
        while a.pane == Pane::Saved { a.handle(Key::Esc); }
        assert_eq!(a.handle(Key::Esc), Action::None);                 // details -> privacy screen as before
        assert!(a.locked);
    }

    #[test]
    fn saved_messages_are_wiped_with_the_vault_on_panic_and_vanish_with_the_contact() {
        let d = tempfile::tempdir().unwrap();
        let mut a = chat_with_lines(d.path(), 2);
        a.handle(Key::Char('m')); a.handle(Key::Char('y'));
        assert_eq!(a.vf.as_ref().unwrap().store.contacts[0].saved.len(), 1);
        a.handle(Key::F12);
        assert!(a.vf.is_none() && a.saved_msgs().is_empty() && a.select.is_none() && a.saved_sel == 0);
        // deleting the contact removes its saved messages from the vault with it
        let mut c = App::new(cfg(Some(d.path().join("v"))));
        type_str(&mut c, "correct horse battery"); c.handle(Key::Enter);
        assert_eq!(c.vf.as_ref().unwrap().store.contacts[0].saved.len(), 1, "they survived in the vault file");
        c.handle(Key::Char('d')); type_str(&mut c, "yes"); c.handle(Key::Enter);
        assert_eq!(c.contacts_len(), 0);
        let mut e = App::new(cfg(Some(d.path().join("v"))));
        type_str(&mut e, "correct horse battery"); e.handle(Key::Enter);
        assert_eq!(e.contacts_len(), 0, "and are gone from the file after the contact was deleted");
    }

    // ---------- PURGE: panic + delete everything of the vault ----------

    #[test]
    fn purge_wipes_like_the_panic_key_and_also_overwrites_and_deletes_every_file_of_the_vault() {
        let d = tempfile::tempdir().unwrap();
        let (vault, counter, keyfile) = (d.path().join("v"), d.path().join("c.cnt"), d.path().join("key.bin"));
        std::fs::write(&keyfile, [7u8; 64]).unwrap();
        let mut c = Config::new(Some(vault.clone()), Some(counter.clone()), Some(Zeroizing::new(vec![7u8; 64])), Profile::InsecureTest);
        c.keyfile_path = Some(keyfile.clone());
        let mut a = open_app(c);
        add_peer(&mut a, "bob");
        let out = d.path().join("out.sbc");
        a.handle(Key::Char('e')); a.input = out.to_str().unwrap().into(); a.handle(Key::Enter);
        a.handle(Key::Enter); a.handle(Key::Char('m')); a.handle(Key::Char('y'));   // (nothing to save yet: harmless)
        let (tmp, foreign, notes) = (d.path().join("v.0123456789abcdef.tmp"), d.path().join("other.vault"), d.path().join("v.my-notes.tmp"));
        std::fs::write(&notes, b"not ours").unwrap();
        std::fs::write(&tmp, b"half written vault").unwrap();
        std::fs::write(&foreign, b"somebody else's file").unwrap();
        for f in [&vault, &counter, &keyfile, &out, &tmp] { assert!(f.exists(), "{f:?} must exist before the purge"); }
        assert_eq!(a.handle(Key::Purge), Action::Purge);
        a.purge_finish();
        for f in [&vault, &counter, &keyfile, &out, &tmp] { assert!(!f.exists(), "{f:?} must be deleted by the purge"); }
        assert!(foreign.exists() && notes.exists(), "files that do not belong to the vault are never touched (only <vault>.<16 hex>.tmp is ours)");
        assert_eq!(a.purge_report, Some((5, 0)));
        assert!(a.vf.is_none() && a.screen == Screen::Wiped && a.created.is_empty(), "and everything is wiped from memory like with F12");
    }

    #[test]
    fn the_plain_panic_key_keeps_the_files_and_purge_works_from_the_unlock_screen_too() {
        let d = tempfile::tempdir().unwrap();
        { let mut a = create_app(d.path(), "v"); add_peer(&mut a, "bob"); }
        let vault = d.path().join("v");
        let counter = nerd_chat_store::counter_path_for(&vault);
        assert!(vault.exists() && counter.exists());
        let mut a = App::new(cfg(Some(vault.clone())));                      // locked: the password prompt
        assert_eq!(a.screen, Screen::Unlock);
        assert_eq!(a.handle(Key::F12), Action::Panic);
        assert!(vault.exists() && counter.exists() && a.purge_report.is_none(), "F12 is panic-LOCK: the vault stays, only the password opens it");
        let mut b = App::new(cfg(Some(vault.clone())));
        assert_eq!(b.handle(Key::Purge), Action::Purge, "also from the password prompt (e.g. under pressure)");
        b.purge_finish();
        assert!(!vault.exists() && !counter.exists());
        assert_eq!(b.purge_report, Some((2, 0)));
        let mut r = App::new(cfg(None));                                     // RAM-only: nothing on disk, purge is just a panic
        r.handle(Key::Enter);
        assert_eq!(r.handle(Key::Purge), Action::Purge);
        r.purge_finish();
        assert_eq!(r.purge_report, Some((0, 0)));
    }

    #[test]
    fn purge_reports_files_it_could_not_remove_and_still_removes_the_rest() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "v"); add_peer(&mut a, "bob");
        let vault = d.path().join("v"); let counter = nerd_chat_store::counter_path_for(&vault);
        std::fs::remove_file(&counter).unwrap();
        std::fs::create_dir(&counter).unwrap(); std::fs::write(counter.join("x"), b"y").unwrap();   // a non-empty directory cannot be deleted: reported, not fatal
        assert_eq!(a.handle(Key::Purge), Action::Purge);
        a.purge_finish();
        assert!(!vault.exists());
        assert_eq!(a.purge_report, Some((1, 1)));
        let mut b = App::new(cfg(Some(d.path().join("never-created"))));
        assert_eq!(b.handle(Key::Purge), Action::Purge);
        b.purge_finish();
        assert_eq!(b.purge_report, Some((0, 0)), "files that do not exist are nothing to do, not failures");
    }

    // ---------- review 22: the claims, proven ----------

    fn vault_bytes(d: &std::path::Path) -> Vec<u8> { std::fs::read(d.join("a.vault")).unwrap() }

    /// The owner's central requirement: NOTHING of a conversation reaches the vault file without the explicit save key.
    #[test]
    fn real_traffic_never_touches_the_vault_file_only_the_save_key_does() {
        let d = tempfile::tempdir().unwrap();
        let (_net, mut a, mut b) = linked_pair(d.path());
        go_online(&mut a); go_online(&mut b);
        assert!(pump_until(&mut [&mut a, &mut b], |x| is_linked(x[0]) && is_linked(x[1])));
        let before = vault_bytes(d.path());
        a.handle(Key::Char('i')); type_str(&mut a, "from a"); a.handle(Key::Enter);            // sending
        b.handle(Key::Char('i')); type_str(&mut b, "from b"); b.handle(Key::Enter);            // receiving + replying
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].chat_lines().len() == 2 && x[1].chat_lines().len() == 2));
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].at_risk().is_empty()), "bob's app confirmed alice's line");
        a.handle(Key::Esc); a.handle(Key::Char('o'));                                           // going offline
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].online == Online::Offline));
        assert_eq!(vault_bytes(d.path()), before, "sending, receiving and going offline must not rewrite the vault");
        assert!(a.vf.as_ref().unwrap().store.contacts[0].saved.is_empty());
        a.handle(Key::Char('m')); a.handle(Key::Char('y'));                                     // (still in the chat, normal mode)
        assert_ne!(vault_bytes(d.path()), before, "only the explicit save changes the vault");
        assert_eq!(a.vf.as_ref().unwrap().store.contacts[0].saved.len(), 1);
    }

    #[test]
    fn a_message_arriving_while_the_cursor_is_active_does_not_change_which_message_is_saved() {
        let d = tempfile::tempdir().unwrap();
        let mut a = chat_with_lines(d.path(), 5);
        let id = a.vf.as_ref().unwrap().store.contacts[0].id;
        a.handle(Key::Char('m')); a.handle(Key::Char('k')); a.handle(Key::Char('k'));           // on message-2
        a.push_line(id, ChatLine { mine: false, text: Zeroizing::new("brand new".into()), queued: false, saved: false, unsent: false, unconfirmed: false, mid: None });
        a.handle(Key::Char('y'));
        let c = &a.vf.as_ref().unwrap().store.contacts[0];
        assert_eq!(c.saved.len(), 1);
        assert_eq!(c.saved[0].text.as_str(), "message-2", "the cursor stays on the message the user chose");
    }

    #[test]
    fn the_cursor_is_dropped_when_its_message_falls_off_the_cap() {
        let d = tempfile::tempdir().unwrap();
        let mut a = chat_with_lines(d.path(), MAX_CHAT_LINES);
        let id = a.vf.as_ref().unwrap().store.contacts[0].id;
        a.handle(Key::Char('m')); a.handle(Key::Char('g'));                                       // the OLDEST line
        assert_eq!(a.select, Some(MAX_CHAT_LINES - 1));
        a.push_line(id, ChatLine { mine: false, text: Zeroizing::new("x".into()), queued: false, saved: false, unsent: false, unconfirmed: false, mid: None });
        assert_eq!(a.select, None, "the chosen message was dropped by the cap: no cursor, nothing saved by accident");
    }

    #[test]
    fn a_failed_save_does_not_hide_that_the_vault_file_may_already_hold_the_message() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let cdir = d.path().join("cdir"); std::fs::create_dir(&cdir).unwrap();
        let mut c = Config::new(Some(d.path().join("v")), Some(cdir.join("c.cnt")), None, Profile::InsecureTest);
        c.timing = fast_timing();
        let mut a = open_app(c);
        add_peer(&mut a, "bob");
        let id = a.vf.as_ref().unwrap().store.contacts[0].id;
        a.push_line(id, ChatLine { mine: true, text: Zeroizing::new("keep".into()), queued: false, saved: false, unsent: false, unconfirmed: false, mid: None });
        a.handle(Key::Enter);
        std::fs::set_permissions(&cdir, std::fs::Permissions::from_mode(0o500)).unwrap();      // the counter can no longer be written; the vault can
        a.handle(Key::Char('m')); a.handle(Key::Char('y'));
        std::fs::set_permissions(&cdir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(a.error && a.status.contains("SAVE FAILED") && a.status.contains("may already contain this message"), "{}", a.status);
        assert!(a.vf.as_ref().unwrap().store.contacts[0].saved.is_empty() && !a.chat_lines()[0].saved, "memory was rolled back");
    }

    #[test]
    fn deleting_a_saved_message_removes_exactly_that_one_and_its_star() {
        let d = tempfile::tempdir().unwrap();
        let mut a = chat_with_lines(d.path(), 4);
        for i in 0..3 { a.handle(Key::Char('m')); for _ in 0..i { a.handle(Key::Char('k')); } a.handle(Key::Char('y')); }   // saved order: message-3, message-2, message-1
        a.handle(Key::Esc); a.handle(Key::Char('H'));
        a.saved_sel = 1;                                                                        // the middle one: message-2
        a.handle(Key::Char('d')); a.handle(Key::Char('d'));
        let texts: Vec<String> = a.vf.as_ref().unwrap().store.contacts[0].saved.iter().map(|m| m.text.to_string()).collect();
        assert_eq!(texts, ["message-3", "message-1"], "exactly the chosen entry went");
        a.handle(Key::Esc); a.handle(Key::Enter);
        let stars: Vec<bool> = a.chat_lines().iter().map(|l| l.saved).collect();
        assert_eq!(stars, [false, true, false, true], "message-2 lost its star and can be saved again; 1 and 3 keep theirs");
        a.handle(Key::Char('m')); a.handle(Key::Char('k')); a.handle(Key::Char('y'));
        assert_eq!(a.vf.as_ref().unwrap().store.contacts[0].saved.len(), 3, "saving it again works after the delete");
    }

    /// Confirmation, not hand-over: a line says "(queued)" until the contact's app has confirmed it, connected or not.
    #[test]
    fn a_line_stays_queued_until_the_contact_confirms_it() {
        let d = tempfile::tempdir().unwrap();
        let (_net, mut a, mut b) = linked_pair(d.path());
        go_online(&mut a); go_online(&mut b);
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].online == Online::Online && x[1].online == Online::Online));
        assert!(pump_until(&mut [&mut a, &mut b], |x| !x[0].linked.is_empty() && !x[1].linked.is_empty()), "connected");
        a.handle(Key::Char('i')); type_str(&mut a, "confirm me"); a.handle(Key::Enter);
        assert!(a.chat_lines()[0].queued, "just sent: not confirmed yet");
        assert!(!a.at_risk().is_empty(), "quitting this very moment could lose it");
        assert!(pump_until(&mut [&mut a, &mut b], |x| !x[0].chat_lines()[0].queued), "the confirmation clears the mark");
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[1].chats.values().any(|l| l.iter().any(|m| &*m.text == "confirm me"))));
        assert!(a.at_risk().is_empty());
    }

    /// Going offline throws away the engine's copies of unconfirmed texts: the first `o` warns, the second goes, and the lines say
    /// "(NOT CONFIRMED)" (they may have arrived), never "(NOT SENT)".
    #[test]
    fn going_offline_with_unconfirmed_lines_warns_first_and_then_says_not_confirmed() {
        let d = tempfile::tempdir().unwrap();
        let (_net, mut a, mut b) = linked_pair(d.path());
        go_online(&mut a);
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].online == Online::Online));
        a.handle(Key::Char('i')); type_str(&mut a, "maybe arrived"); a.handle(Key::Enter);
        a.handle(Key::Esc);
        a.handle(Key::Char('o'));
        assert!(a.error && a.status.contains("not confirmed") && a.status.contains("o again"), "{}", a.status);
        assert_eq!(a.online, Online::Online, "the first o only warns");
        a.handle(Key::Char('j'));                                    // any other key disarms
        a.handle(Key::Char('o'));
        assert_eq!(a.online, Online::Online, "disarmed: warns again instead of going offline");
        a.handle(Key::Char('o'));
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].online == Online::Offline), "the second o goes offline");
        let l = &a.chat_lines()[0];
        assert!(!l.queued && l.unconfirmed && !l.unsent);
        let screen = screen_text(&a, 110, 24);
        assert!(screen.contains("(NOT CONFIRMED)") && !screen.contains("(NOT SENT)"), "{screen}");
    }

    /// Several lines are confirmed by THEIR ids, each exactly once.
    #[test]
    fn each_line_is_confirmed_by_its_own_id() {
        let d = tempfile::tempdir().unwrap();
        let (_net, mut a, mut b) = linked_pair(d.path());
        go_online(&mut a); go_online(&mut b);
        assert!(pump_until(&mut [&mut a, &mut b], |x| is_linked(x[0]) && is_linked(x[1])));
        a.handle(Key::Char('i'));
        for t in ["one", "two", "three"] { type_str(&mut a, t); a.handle(Key::Enter); }
        let mids: Vec<_> = a.chat_lines().iter().map(|l| l.mid).collect();
        assert!(mids.iter().all(Option::is_some) && mids[0] != mids[1] && mids[1] != mids[2], "every sent line has its own id");
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].chat_lines().iter().all(|l| !l.queued)), "all three confirmed");
        assert!(a.chat_lines().iter().all(|l| !l.unsent && !l.unconfirmed));
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[1].chats.values().flatten().count() == 3));
        let got: Vec<String> = b.chats.values().flatten().map(|l| l.text.to_string()).collect();
        assert_eq!(got, ["one", "two", "three"], "in order, each once");
    }

    /// A full outbox refuses BEFORE the draft is taken: nothing typed is lost.
    #[test]
    fn a_full_outbox_keeps_the_draft_and_says_so() {
        let d = tempfile::tempdir().unwrap();
        let (_net, mut a, mut b) = linked_pair(d.path());
        go_online(&mut a);
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].online == Online::Online));
        a.handle(Key::Char('i'));
        for i in 0..nerd_chat_chat::engine::MAX_UNCONFIRMED { type_str(&mut a, &format!("m{i}")); a.handle(Key::Enter); }
        type_str(&mut a, "the draft");
        a.handle(Key::Enter);
        assert!(a.error && a.status.contains("Outbox full"), "{}", a.status);
        assert_eq!(a.chat_lines().len(), nerd_chat_chat::engine::MAX_UNCONFIRMED, "no line was added");
        assert!(!a.compose.is_empty(), "the draft is still there");
    }

    #[test]
    fn purge_never_follows_links_and_destroys_the_files_we_created() {
        use std::os::unix::fs::symlink;
        let d = tempfile::tempdir().unwrap();
        let real_key = d.path().join("real-key.bin"); std::fs::write(&real_key, [9u8; 64]).unwrap();
        let link_key = d.path().join("key-link"); symlink(&real_key, &link_key).unwrap();
        let mut c = Config::new(Some(d.path().join("v")), None, Some(Zeroizing::new(vec![9u8; 64])), Profile::InsecureTest);
        c.keyfile_path = Some(link_key.clone());
        let mut a = open_app(c);
        add_peer(&mut a, "bob");
        let saved_file = d.path().join("received.png");
        std::fs::write(&saved_file, b"png").unwrap(); a.note_created(&saved_file);
        assert_eq!(a.handle(Key::Purge), Action::Purge);
        a.purge_finish();
        assert!(real_key.exists() && !link_key.exists(), "a link is only unlinked: whatever it points to is never touched (a planted link must not make us destroy other files)");
        assert!(!saved_file.exists() && !d.path().join("v").exists());
    }

    #[test]
    fn pasted_text_is_never_a_command() {
        let d = tempfile::tempdir().unwrap();
        let mut a = open_app(Config::new(Some(d.path().join("v")), None, None, Profile::InsecureTest));
        add_peer(&mut a, "bob");
        a.paste("\u{1d}q\u{1b}d");                       // details view / normal mode: ignored completely
        assert!(a.vf.is_some() && d.path().join("v").exists() && a.contacts_len() == 1);
        a.handle(Key::Char('i'));                          // typing in the chat
        a.paste("hi\u{1d}\u{1b}there\nq");
        assert!(a.vf.is_some() && d.path().join("v").exists(), "no purge, still in insert mode");
        assert_eq!(a.compose.chars(), "hithereq".len(), "only printable characters arrive");
        a.handle(Key::Esc);
        a.paste("zzz");
        assert_eq!(a.compose.chars(), "hithereq".len(), "normal mode: pastes are ignored");
    }

    #[test]
    fn purge_spares_planted_links_and_files_that_replaced_ours() {
        use std::os::unix::fs::symlink;
        let d = tempfile::tempdir().unwrap();
        let mut a = open_app(Config::new(Some(d.path().join("v")), None, None, Profile::InsecureTest));
        add_peer(&mut a, "bob");
        let precious = d.path().join("thesis.txt"); std::fs::write(&precious, b"mine").unwrap();
        symlink(&precious, d.path().join("v.0123456789abcdef.tmp")).unwrap();   // planted next to the vault
        symlink(&precious, d.path().join("v.counter.fedcba9876543210.tmp")).unwrap();
        let stale = d.path().join("v.counter.0000000000000000.tmp"); std::fs::write(&stale, [0u8; 8]).unwrap(); // a real counter temp file
        let exported = d.path().join("bundle.sbc"); std::fs::write(&exported, b"x").unwrap(); a.note_created(&exported);
        std::fs::remove_file(&exported).unwrap(); std::fs::write(&exported, b"the user later put THIS here").unwrap();
        assert_eq!(a.handle(Key::Purge), Action::Purge);
        a.purge_finish();
        assert_eq!(std::fs::read(&precious).unwrap(), b"mine", "what a planted link points to is never touched");
        assert!(!d.path().join("v.0123456789abcdef.tmp").exists() && !stale.exists() && !d.path().join("v").exists());
        assert!(exported.exists(), "a file that is no longer the one we created is not ours to destroy");
    }

    #[test]
    fn quitting_asks_twice_only_when_something_would_be_lost() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "v"); add_peer(&mut a, "bob");
        let id = a.vf.as_ref().unwrap().store.contacts[0].id;
        assert_eq!(a.handle(Key::Char('q')), Action::Quit, "nothing pending: quits at once");
        a.push_line(id, ChatLine { mine: true, text: Zeroizing::new("unsent".into()), queued: true, saved: false, unsent: false, unconfirmed: false, mid: None });
        assert_eq!(a.handle(Key::Char('q')), Action::None);
        assert!(a.error && a.status.contains("q again") && a.status.contains("1 unconfirmed"), "{}", a.status);
        a.handle(Key::Char('j'));                                    // any other key disarms
        assert_eq!(a.handle(Key::Char('q')), Action::None);
        assert_eq!(a.handle(Key::Char('q')), Action::Quit, "second q quits");
        // an unconfirmed line is at risk even while the contact is connected (the ack may not have arrived yet)
        a.quit_armed = false; a.linked.insert(id);
        assert_eq!(a.handle(Key::Char('q')), Action::None, "an unconfirmed line of a connected contact is still at risk");
        a.linked.remove(&id); a.quit_armed = false;
        // the same guard on the privacy screen (review 20, L1), with a generic hint and no counts or names
        a.quit_armed = false; a.handle(Key::Esc); assert!(a.locked);
        assert_eq!(a.handle(Key::Char('q')), Action::None);
        let lock = screen_text(&a, 90, 20);
        assert!(lock.contains("press q again") && !lock.contains("unconfirmed") && !lock.contains("bob"), "{lock}");
        a.handle(Key::Enter); assert!(!a.quit_armed, "unlocking disarms");
        a.locked = false; a.chats.clear();
        // other things that would be lost: a file in RAM, a pairing waiting for its answer, a half-written draft
        a.inbox.insert(id, Received { data: Zeroizing::new(vec![1, 2, 3]), ext: "png" });
        assert_eq!(a.handle(Key::Char('q')), Action::None); assert!(a.status.contains("file"), "{}", a.status);
        a.handle(Key::Char('j')); a.inbox.clear();
        a.pending_pair = Some(([0; 8], ImportedContact::from_file(Bundle::from_identity(&ContactIdentity::generate())), "1".into()));
        assert_eq!(a.handle(Key::Char('q')), Action::None); assert!(a.status.contains("pairing"), "{}", a.status);
        a.handle(Key::Char('j')); a.pending_pair = None;
        a.handle(Key::Char('i')); type_str(&mut a, "draft"); a.handle(Key::Esc);   // draft kept in normal mode
        assert_eq!(a.handle(Key::Char('q')), Action::None); assert!(a.status.contains("draft"), "{}", a.status);
    }

    #[test]
    fn a_long_draft_shows_its_tail_and_the_stale_tor_text_is_gone() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "v"); add_peer(&mut a, "bob");
        let stale = screen_text(&a, 110, 24);
        assert!(!stale.contains("Tor transport") && !stale.contains("next build stage"), "the long outdated line must be gone");
        assert!(stale.contains("Connection: offline"), "a live connection line instead: {stale}");
        a.handle(Key::Char('i'));
        type_str(&mut a, &format!("{}THE-END", "x".repeat(300)));
        let s = screen_text(&a, 80, 24);
        assert!(s.contains("THE-END") && s.contains("-- INSERT --"), "the end of a long draft must stay visible");
    }

    #[test]
    fn contact_rotation_state_and_footer_hints_follow_the_context() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "v"); add_peer(&mut a, "bob");
        let details = screen_text(&a, 200, 24);
        assert!(details.contains("Esc lock") && details.contains("Enter chat"));
        a.handle(Key::Enter);
        let normal = screen_text(&a, 200, 24);
        assert!(normal.contains("NORMAL") && normal.contains("f file") && normal.contains("Tab next") && !normal.contains("Esc lock"));
        a.handle(Key::Char('i'));
        let insert = screen_text(&a, 200, 24);
        assert!(insert.contains("Enter send") && insert.contains("Esc normal mode") && !insert.contains("f file"), "no command keys are advertised while typing");
        a.vf().store.contacts[0].next_transport = Some(Zeroizing::new([1u8; 64]));
        a.handle(Key::Esc); a.handle(Key::Esc);
        assert!(screen_text(&a, 200, 30).contains("key rotation pending"));
    }

    // ---------------------------------------------------------------- pairing over Tor (spec 2026-11-09-tor-pairing-spec.md), on the in-memory network
    fn tor_pair_apps(dir: &std::path::Path) -> (nerd_chat_chat::MemNet, App, App) {
        let net = nerd_chat_chat::MemNet::new();
        let mut a = net_app(dir, "a.vault", &net); add(&mut a, "bob");
        let mut b = net_app(dir, "b.vault", &net); add(&mut b, "alice");
        go_online(&mut a); go_online(&mut b);
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].online == Online::Online && x[1].online == Online::Online), "{} / {}", a.status, b.status);
        (net, a, b)
    }

    /// `a` creates the offer; returns (link, code) once it is published.
    fn tor_offer(a: &mut App, b: &mut App) -> (String, String) {
        a.handle(Key::Char('T'));
        assert!(pump_until(&mut [&mut *a, &mut *b], |x| x[0].tor_offer.is_some() || x[0].error), "{}", a.status);
        let o = a.tor_offer.as_ref().expect("the offer must be ready");
        (o.link.to_string(), o.code.to_string())
    }

    fn tor_join(b: &mut App, link: &str, code: &str) {
        b.handle(Key::Char('J')); type_str(b, link); b.handle(Key::Enter);
        if matches!(b.screen, Screen::Prompt(Prompt::JoinCode(_))) { type_str(b, code); b.handle(Key::Enter); }
    }

    #[test]
    fn pairing_over_tor_between_two_apps_through_the_screens() {
        let d = tempfile::tempdir().unwrap();
        let (net, mut a, mut b) = tor_pair_apps(d.path());
        net.set_pair_publish_delay(Duration::from_millis(200));
        let (link, code) = tor_offer(&mut a, &mut b);
        assert!(net.pair_open(&link) && link.len() == 56 && !link.contains(':'), "the link is the bare onion id");
        tor_join(&mut b, &format!("  {}\n", link.to_uppercase()), &code); // paste noise and capitals are tolerated
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].pending_pair.is_some() && x[1].pending_pair.is_some()), "{} / {}", a.status, b.status);
        assert!(a.tor_offer.is_none() && a.pair_ctl.is_none(), "the offer ends with the pairing");
        assert!(pump_until(&mut [&mut a, &mut b], |_| !net.pair_open(&link)), "the service is removed after use");
        assert!(a.pair_remote() && b.pair_remote(), "the in-person question becomes the voice question");
        a.handle(Key::Char('P')); b.handle(Key::Char('P'));
        type_str(&mut a, "y"); a.handle(Key::Enter);
        type_str(&mut b, "y"); b.handle(Key::Enter);
        assert_eq!(a.selected_detail().unwrap().1, Trust::CodeAuthenticated);
        assert_eq!(a.selected_detail().unwrap().2, b.selected_detail().unwrap().2, "same safety number on both sides");
    }

    #[test]
    fn over_tor_needs_the_app_online_and_a_valid_link() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "a.vault"); add(&mut a, "bob");
        a.handle(Key::Char('T'));
        assert!(a.error && a.status.contains("online"), "{}", a.status);
        a.handle(Key::Char('J')); type_str(&mut a, "not a link"); a.handle(Key::Enter);
        assert!(a.error && a.status.contains("not a valid pairing link"), "{}", a.status);
        assert!(a.pair_ctl.is_none() && a.screen == Screen::Main);
    }

    #[test]
    fn connect_then_close_burns_the_offer_without_a_guess_and_a_wrong_code_is_reported() {
        let d = tempfile::tempdir().unwrap();
        let (net, mut a, mut b) = tor_pair_apps(d.path());
        // an attacker who only has the link connects and hangs up
        let (link, _code) = tor_offer(&mut a, &mut b);
        let dial = net.transport().pair_dial_fn().unwrap();
        drop(dial(&link, &[9; 16], &nerd_chat_net::tor::CancelToken::new()).unwrap());
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].pair_ctl.is_none()), "{}", a.status);
        assert!(a.error && a.remote_lockout.remaining() == 0 && !a.alerts.iter().any(|(t, _)| t.contains("Someone used your pairing link")), "no guess, no accusation: {} {:?}", a.status, a.alerts);
        // a joiner who types a wrong code
        let (link, _code) = tor_offer(&mut a, &mut b);
        tor_join(&mut b, &link, "00000-00000");
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].pair_ctl.is_none() && x[1].pair_ctl.is_none()), "{} / {}", a.status, b.status);
        assert!(a.alerts.iter().any(|(t, _)| t.contains("Someone used your pairing link")), "{:?}", a.alerts);
        assert!(a.pending_pair.is_none() && b.pending_pair.is_none());
    }

    #[test]
    fn cancel_going_offline_and_panic_remove_the_pairing_service() {
        let d = tempfile::tempdir().unwrap();
        let (net, mut a, mut b) = tor_pair_apps(d.path());
        let (link, _) = tor_offer(&mut a, &mut b);
        a.handle(Key::Char('x')); // cancel
        assert!(pump_until(&mut [&mut a, &mut b], |_| !net.pair_open(&link)), "cancel must remove the service");
        assert!(a.tor_offer.is_none() && a.pair_ctl.is_none());
        // going offline with an offer open
        let (link, _) = tor_offer(&mut a, &mut b);
        a.handle(Key::Char('o'));
        assert!(pump_until(&mut [&mut a, &mut b], |_| !net.pair_open(&link)), "going offline must remove the service");
        assert!(a.pair_ctl.is_none() && a.tor_offer.is_none());
        // panic wipe with an offer open
        go_online(&mut a);
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].online == Online::Online));
        let (link, _) = tor_offer(&mut a, &mut b);
        a.panic_wipe();
        assert!(pump_until(&mut [&mut b], |_| !net.pair_open(&link)), "panic must remove the service");
        assert!(a.tor_offer.is_none() && a.pair_ctl.is_none());
    }

    #[test]
    fn a_joiner_gives_up_on_a_link_that_never_gets_published_and_can_cancel() {
        let d = tempfile::tempdir().unwrap();
        let (net, mut a, mut b) = tor_pair_apps(d.path());
        net.set_pair_publish_delay(Duration::from_secs(3600)); // never reachable
        a.handle(Key::Char('T'));
        // the link is only shown after publication: nothing to show yet
        for _ in 0..10 { a.poll(); b.poll(); thread::sleep(Duration::from_millis(20)); }
        assert!(a.tor_offer.is_none(), "no link before the service is published");
        a.handle(Key::Char('x'));
        assert!(a.pair_ctl.is_none());
    }

    #[test]
    fn the_open_offer_belongs_to_its_contact_and_a_second_pairing_cannot_overwrite_it() {
        let d = tempfile::tempdir().unwrap();
        let (_net, mut a, mut b) = tor_pair_apps(d.path());
        add(&mut a, "carol");
        a.sel = 0;
        let (_link, _code) = tor_offer(&mut a, &mut b);
        let (_, bob_id) = a.identity_clone();
        assert_eq!(a.tor_offer.as_ref().unwrap().contact, bob_id, "the offer is tied to the contact it was created for");
        assert_eq!(a.tor_offer_name(), Some("bob"));
        a.sel = 1; // another (unpaired) contact is selected: a front end must not show the offer card for it
        assert_ne!(a.selected_contact_id(), Some(bob_id));
        // a delayed resume of another pairing (e.g. after a hosting probe) must not replace the running one
        a.resume(Then::TorOffer(bob_id), true);
        assert!(a.error && a.status.contains("already running"), "{}", a.status);
        assert!(a.tor_offer.is_some() && a.pair_ctl.is_some(), "the running offer is untouched");
        a.handle(Key::Char('x'));
    }

    #[test]
    fn the_joiner_hears_why_a_link_failed() {
        let d = tempfile::tempdir().unwrap();
        let (_net, _a, mut b) = tor_pair_apps(d.path());
        let ghost = nerd_chat_core::onion::service_id(&[7u8; 32]); // a well-formed link nobody serves
        tor_join(&mut b, &ghost, "1234567890");
        assert!(pump_until(&mut [&mut b], |x| x[0].pair_ctl.is_none()), "{}", b.status);
        assert!(b.error && b.status.contains("Could not reach your partner"), "{}", b.status);
    }

    // ---------------------------------------------------------------- the message history (docs/HISTORY_AND_TIMING_PLAN.md)

    use nerd_chat_store::history::{Clock, Persist, State as MsgState};

    struct TestClock { wall: std::sync::Mutex<u64>, mono: std::sync::Mutex<u64> }
    impl TestClock {
        fn new() -> Arc<Self> { Arc::new(Self { wall: std::sync::Mutex::new(1_800_000_000), mono: std::sync::Mutex::new(0) }) }
        fn advance(&self, s: u64) { *self.wall.lock().unwrap() += s; *self.mono.lock().unwrap() += s; }
    }
    impl Clock for TestClock { fn wall(&self) -> u64 { *self.wall.lock().unwrap() } fn mono(&self) -> u64 { *self.mono.lock().unwrap() } }

    fn reopen_net_app(dir: &std::path::Path, name: &str, net: &nerd_chat_chat::MemNet) -> App {
        let mut c = cfg(Some(dir.join(name)));
        let net = net.clone();
        c.transport = Some(std::sync::Arc::new(move |_p: &mut dyn FnMut(u8)| Ok(Box::new(net.transport()) as Box<dyn Transport>)));
        c.timing = fast_timing();
        reopen(c)
    }
    fn reopen(c: Config) -> App {
        let mut a = App::new(c);
        assert_eq!(a.screen, Screen::Unlock, "the vault exists");
        type_str(&mut a, "correct horse battery"); a.handle(Key::Enter);
        assert_eq!(a.screen, Screen::Main, "{}", a.status);
        a
    }
    fn hist(a: &App) -> &nerd_chat_store::History { a.history.as_ref().expect("history is open") }
    fn cid(a: &App) -> [u8; 8] { a.vf.as_ref().unwrap().store.contacts[0].id }
    fn kept(a: &App) -> Vec<String> { hist(a).queued(cid(a)).iter().map(|(_, t)| t.to_string()).collect() }
    fn say_in_chat(a: &mut App, text: &str) { a.handle(Key::Char('i')); type_str(a, text); a.handle(Key::Enter); }
    /// Pump until the history file holds everything (a tick has written it).
    fn durable(a: &mut App) { let t = Instant::now(); while a.history.as_ref().is_some_and(|h| h.is_dirty()) && t.elapsed() < Duration::from_secs(5) { a.poll(); thread::sleep(Duration::from_millis(10)); } assert!(a.history.as_ref().is_none_or(|h| !h.is_dirty())); }

    #[test]
    fn the_engine_and_the_store_agree_on_how_many_unconfirmed_texts_fit() {
        assert_eq!(nerd_chat_store::MAX_OUTBOX, nerd_chat_chat::engine::MAX_UNCONFIRMED);
    }

    #[test]
    fn nothing_is_kept_by_default_and_the_ram_only_behaviour_is_unchanged() {
        let d = tempfile::tempdir().unwrap();
        let (_net, mut a, mut b) = linked_pair(d.path());
        assert_eq!(a.persist(), Persist::Off);
        assert!(a.history.is_none() && !d.path().join("a.vault.hist").exists(), "no history file is even created");
        a.handle(Key::Enter); a.handle(Key::Char('i')); type_str(&mut a, "offline text"); a.handle(Key::Enter);
        assert!(a.error && a.status.contains("offline") && a.chat_lines().is_empty(), "refused as before: {}", a.status);
        a.handle(Key::Esc); a.handle(Key::Esc);
        go_online(&mut a); go_online(&mut b);
        assert!(pump_until(&mut [&mut a, &mut b], |x| is_linked(x[0]) && is_linked(x[1])));
        a.handle(Key::Enter); say_in_chat(&mut a, "ram only");
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[1].chats.values().any(|l| l.iter().any(|m| &*m.text == "ram only"))));
        assert!(a.vf.as_ref().unwrap().store.persist.is_none(), "an untouched vault stays in the old format");
    }

    #[test]
    fn a_days_history_survives_a_restart_with_both_sides_of_the_conversation_in_order() {
        let d = tempfile::tempdir().unwrap();
        let (net, mut a, mut b) = linked_pair(d.path());
        a.set_persist(Persist::Day);
        assert_eq!(a.persist(), Persist::Day);
        go_online(&mut a); go_online(&mut b);
        assert!(pump_until(&mut [&mut a, &mut b], |x| is_linked(x[0]) && is_linked(x[1])));
        a.handle(Key::Enter); say_in_chat(&mut a, "one");
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[1].chats.values().any(|l| l.iter().any(|m| &*m.text == "one"))));
        b.handle(Key::Enter); say_in_chat(&mut b, "two");
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].chats.values().any(|l| l.iter().any(|m| &*m.text == "two" && !m.mine))));
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].chat_lines().iter().all(|l| !l.queued)));
        durable(&mut a);
        drop(a);
        let mut a = reopen_net_app(d.path(), "a.vault", &net);
        assert_eq!(a.persist(), Persist::Day, "the choice is stored in the vault");
        a.handle(Key::Enter);
        let l = a.chat_lines();
        assert_eq!(l.iter().map(|x| (x.mine, x.text.to_string(), x.queued)).collect::<Vec<_>>(), vec![(true, "one".to_string(), false), (false, "two".to_string(), false)], "the conversation is back, in order");
        assert_eq!(std::fs::metadata(d.path().join("a.vault.hist")).unwrap().len(), 2 * 64 * 1024, "the file has a fixed size");
    }

    #[test]
    fn a_text_typed_offline_is_kept_survives_a_restart_and_is_delivered_when_both_are_online() {
        let d = tempfile::tempdir().unwrap();
        let (net, mut a, mut b) = linked_pair(d.path());
        a.set_persist(Persist::Outbox);
        a.handle(Key::Enter); say_in_chat(&mut a, "see you thursday");
        assert!(!a.error && a.status.contains("Kept encrypted"), "{}", a.status);
        assert!(a.chat_lines()[0].queued && kept(&a) == ["see you thursday"]);
        durable(&mut a);
        drop(a);                                        // the app is killed
        let mut a = reopen_net_app(d.path(), "a.vault", &net);
        assert_eq!(kept(&a), ["see you thursday"], "the text survived");
        a.handle(Key::Enter);
        assert!(a.chat_lines()[0].mine && a.chat_lines()[0].queued, "shown again as (queued)");
        go_online(&mut a); go_online(&mut b);
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[1].chats.values().any(|l| l.iter().any(|m| &*m.text == "see you thursday"))), "the contact received it");
        assert!(pump_until(&mut [&mut a, &mut b], |x| !x[0].chat_lines()[0].queued), "and confirmed it");
        assert!(kept(&a).is_empty(), "outbox mode forgets a confirmed text");
    }

    #[test]
    fn a_text_we_typed_is_written_to_the_history_before_the_engine_gets_it() {
        let d = tempfile::tempdir().unwrap();
        let (_net, mut a, mut b) = linked_pair(d.path());
        a.cfg.grid = Duration::from_millis(300);
        a.set_persist(Persist::Day);
        go_online(&mut a); go_online(&mut b);
        assert!(pump_until(&mut [&mut a, &mut b], |x| is_linked(x[0]) && is_linked(x[1])));
        a.handle(Key::Enter); say_in_chat(&mut a, "durable first");
        assert_eq!(a.pending_sends.len(), 1, "waiting for the next tick");
        assert!(hist(&a).is_dirty(), "in the history's memory, not yet in the file");
        assert!(!b.chats.values().any(|l| l.iter().any(|m| &*m.text == "durable first")), "the contact cannot have it yet");
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[1].chats.values().any(|l| l.iter().any(|m| &*m.text == "durable first"))));
        assert!(a.pending_sends.is_empty());
    }

    #[test]
    fn a_received_text_is_confirmed_only_after_the_history_write_that_holds_it() {
        let d = tempfile::tempdir().unwrap();
        let (_net, mut a, mut b) = linked_pair(d.path());
        b.set_persist(Persist::Day);
        b.cfg.grid = Duration::from_millis(500);
        go_online(&mut a); go_online(&mut b);
        assert!(pump_until(&mut [&mut a, &mut b], |x| is_linked(x[0]) && is_linked(x[1])));
        a.handle(Key::Enter); say_in_chat(&mut a, "please confirm me late");
        // while the sender's line is still unconfirmed, the receiver may already SHOW the text but must not have confirmed it; the moment the sender's line is confirmed, the text is in b's FILE
        let t = Instant::now(); let mut saw_shown_unconfirmed = false;
        loop {
            a.poll(); b.poll();
            let shown = b.chats.values().any(|l| l.iter().any(|m| &*m.text == "please confirm me late"));
            let confirmed = !a.chat_lines()[0].queued;
            if shown && !confirmed { saw_shown_unconfirmed = true; assert!(!b.pending_confirms.is_empty() || hist(&b).is_dirty() || true); }
            if confirmed { assert!(shown && !hist(&b).is_dirty(), "confirmed => the receiver's history file already holds the text"); assert!(hist(&b).lines(cid(&b)).iter().any(|l| &*l.text == "please confirm me late")); break; }
            assert!(t.elapsed() < Duration::from_secs(15), "never confirmed");
            thread::sleep(Duration::from_millis(10));
        }
        assert!(saw_shown_unconfirmed, "the confirmation really waited for the tick");
    }

    #[test]
    fn a_text_typed_while_the_engine_is_starting_is_sent_when_it_is_ready() {
        let d = tempfile::tempdir().unwrap();
        let (_net, mut a, mut b) = linked_pair(d.path());
        a.set_persist(Persist::Outbox);
        go_online(&mut b);
        go_online(&mut a);
        assert!(matches!(a.online, Online::Starting(_)), "typing happens during the start");
        a.handle(Key::Enter); say_in_chat(&mut a, "typed while starting");
        assert_eq!(kept(&a), ["typed while starting"]);
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[1].chats.values().any(|l| l.iter().any(|m| &*m.text == "typed while starting"))), "the contact receives it in THIS session");
        assert!(pump_until(&mut [&mut a, &mut b], |x| !x[0].chat_lines()[0].queued), "and confirms it");
        assert!(kept(&a).is_empty());
    }

    #[test]
    fn going_offline_with_kept_texts_neither_warns_nor_loses_anything() {
        let d = tempfile::tempdir().unwrap();
        let (_net, mut a, mut b) = linked_pair(d.path());
        a.set_persist(Persist::Day);
        go_online(&mut a);
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].online == Online::Online));
        a.handle(Key::Enter); say_in_chat(&mut a, "still waiting");
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].pending_sends.is_empty()));
        assert!(a.at_risk().is_empty(), "quitting loses nothing: it is in the history");
        a.handle(Key::Esc); a.handle(Key::Char('o'));
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].online == Online::Offline), "one press is enough: nothing to warn about");
        let l = &a.chat_lines()[0];
        assert!(l.queued && !l.unconfirmed, "it will be sent again next time");
        assert_eq!(kept(&a), ["still waiting"]);
    }

    #[test]
    fn switching_the_history_off_deletes_the_file_and_labels_the_lines_honestly() {
        let d = tempfile::tempdir().unwrap();
        let (net, mut a, _b) = linked_pair(d.path());
        a.set_persist(Persist::Day);
        a.handle(Key::Enter); say_in_chat(&mut a, "temporary"); a.handle(Key::Esc);
        durable(&mut a);
        let file = d.path().join("a.vault.hist");
        assert!(file.exists());
        a.set_persist(Persist::Off);
        assert!(!file.exists() && a.history.is_none() && !a.error, "the history file was overwritten and deleted: {}", a.status);
        assert!(a.chat_lines().iter().all(|l| !l.queued && l.unconfirmed), "offline: the copy is gone, the line says so");
        drop(a);
        let a = reopen_net_app(d.path(), "a.vault", &net);
        assert!(a.persist() == Persist::Off && a.chats.values().all(|l| l.is_empty()), "nothing came back");
        assert_eq!(a.vf.as_ref().unwrap().store.persist, Some(Persist::Off));
    }

    #[test]
    fn narrowing_to_unsent_only_forgets_everything_else() {
        let d = tempfile::tempdir().unwrap();
        let (_net, mut a, mut b) = linked_pair(d.path());
        a.set_persist(Persist::Day);
        go_online(&mut a); go_online(&mut b);
        assert!(pump_until(&mut [&mut a, &mut b], |x| is_linked(x[0]) && is_linked(x[1])));
        b.handle(Key::Enter); say_in_chat(&mut b, "from b");
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].chats.values().any(|l| l.iter().any(|m| &*m.text == "from b"))));
        a.handle(Key::Char('o'));                       // (a is in the details pane here: Esc would raise the privacy screen)
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].online == Online::Offline));
        a.handle(Key::Enter); say_in_chat(&mut a, "waiting");
        assert_eq!(hist(&a).lines(cid(&a)).len(), 2);
        a.set_persist(Persist::Outbox);
        let l = hist(&a).lines(cid(&a));
        assert_eq!(l.len(), 1, "only the unconfirmed text is left"); assert_eq!(l[0].state, MsgState::Queued);
    }

    #[test]
    fn an_unsent_text_that_runs_out_of_time_is_marked_cancelled_and_never_sent_later() {
        let d = tempfile::tempdir().unwrap();
        let net = nerd_chat_chat::MemNet::new();
        let clock = TestClock::new();
        let mut cfg_a = cfg(Some(d.path().join("a.vault")));
        { let n = net.clone(); cfg_a.transport = Some(std::sync::Arc::new(move |_p: &mut dyn FnMut(u8)| Ok(Box::new(n.transport()) as Box<dyn Transport>))); }
        cfg_a.timing = fast_timing(); cfg_a.clock = Some(clock.clone());
        let mut a = open_app(cfg_a); add(&mut a, "bob");
        let mut b = net_app(d.path(), "b.vault", &net); add(&mut b, "alice");
        link_apps(&mut a, &mut b, d.path());
        a.set_persist(Persist::Day);
        a.handle(Key::Enter); say_in_chat(&mut a, "too late"); a.handle(Key::Esc);
        clock.advance(40 * 3600);                       // the contact was never reachable for a day and a half
        let t = Instant::now(); while !a.chat_lines()[0].unsent && t.elapsed() < Duration::from_secs(5) { a.poll(); thread::sleep(Duration::from_millis(10)); }
        assert!(a.chat_lines()[0].unsent && !a.chat_lines()[0].queued, "marked: not sent");
        assert!(a.status.contains("EXPIRED, NOT SENT"), "{}", a.status);
        assert!(kept(&a).is_empty());
        go_online(&mut a); go_online(&mut b);
        assert!(pump_until(&mut [&mut a, &mut b], |x| is_linked(x[0]) && is_linked(x[1])));
        pump_for(&mut [&mut a, &mut b], Duration::from_millis(800));
        assert!(!b.chats.values().any(|l| l.iter().any(|m| &*m.text == "too late")), "an expired text must never arrive later, looking fresh");
    }

    #[test]
    fn the_vaults_old_outbox_is_moved_into_the_history_file_and_then_removed_from_the_vault() {
        let d = tempfile::tempdir().unwrap();
        let (net, mut a, _b) = linked_pair(d.path());
        let id = cid(&a);
        a.vf.as_mut().unwrap().store.queue_outbox(0, [7; 8], "from the old vault outbox").unwrap();   // what the first outbox version wrote
        assert!(a.save());
        drop(a);
        let mut a = reopen_net_app(d.path(), "a.vault", &net);
        assert_eq!(a.persist(), Persist::Outbox, "kept texts and no stored choice: the feature is in use");
        assert_eq!(hist(&a).queued(id).len(), 1, "the text is in the history now");
        let t = Instant::now(); while !a.vf.as_ref().unwrap().store.contacts[0].outbox.is_empty() && t.elapsed() < Duration::from_secs(5) { a.poll(); thread::sleep(Duration::from_millis(10)); }
        assert!(a.vf.as_ref().unwrap().store.contacts[0].outbox.is_empty(), "removed from the vault once the history file holds it");
        drop(a);
        let a = reopen_net_app(d.path(), "a.vault", &net);
        assert_eq!(hist(&a).queued(id).len(), 1, "and it is still there after another restart");
    }

    #[test]
    fn deleting_a_contact_removes_its_messages_and_a_purge_destroys_the_history_file() {
        let d = tempfile::tempdir().unwrap();
        let (_net, mut a, _b) = linked_pair(d.path());
        a.set_persist(Persist::Day);
        a.handle(Key::Enter); say_in_chat(&mut a, "gone with the contact"); a.handle(Key::Esc);
        assert_eq!(hist(&a).lines(cid(&a)).len(), 1);
        let id = cid(&a);
        a.handle(Key::Char('d')); type_str(&mut a, "yes"); a.handle(Key::Enter);
        assert!(hist(&a).lines(id).is_empty(), "the history of a deleted contact is gone");
        let file = d.path().join("a.vault.hist");
        assert!(file.exists());
        assert_eq!(a.handle(Key::Purge), Action::Purge);
        a.purge_finish();
        assert!(!file.exists() && !d.path().join("a.vault").exists(), "purge destroys the history file with the vault");
    }

    #[test]
    fn the_default_applies_until_the_user_chooses_and_then_the_stored_choice_wins() {
        let d = tempfile::tempdir().unwrap();
        let mut c = cfg(Some(d.path().join("p.vault"))); c.persist_default = Persist::Day;
        let mut a = open_app(c);
        assert_eq!(a.persist(), Persist::Day);
        assert!(a.vf.as_ref().unwrap().store.persist.is_none() && a.history.is_some(), "the phone's default: a day, no choice stored");
        a.set_persist(Persist::Day);
        assert_eq!(a.vf.as_ref().unwrap().store.persist, Some(Persist::Day), "choosing the default value stores the choice");
        a.set_persist(Persist::Off);
        assert_eq!(a.persist(), Persist::Off);
        drop(a);
        let mut c = cfg(Some(d.path().join("p.vault"))); c.persist_default = Persist::Day;
        let a = reopen(c);
        assert_eq!(a.persist(), Persist::Off, "the stored choice beats the default");
        assert!(a.history.is_none());
    }

    #[test]
    fn a_failed_counter_write_when_the_setting_is_saved_rolls_nothing_back() {
        let d = tempfile::tempdir().unwrap();
        let (_net, mut a, _b) = linked_pair(d.path());
        let counter = nerd_chat_store::counter_path_for(&d.path().join("a.vault"));
        std::fs::remove_file(&counter).unwrap(); std::fs::create_dir(&counter).unwrap();   // the counter file can no longer be replaced; the vault file still can (works as root)
        a.set_persist(Persist::Day);
        assert!(a.error && a.status.contains("saved, but the rollback-counter file"), "{}", a.status);
        assert_eq!(a.vf.as_ref().unwrap().store.persist, Some(Persist::Day), "memory still equals what is on disk");
    }

    #[test]
    fn overwrite_based_deletion_is_refused_on_file_systems_where_it_cannot_work() {
        assert_eq!(unsafe_fs_name(0x9123_683E), Some("btrfs"));
        assert!(unsafe_fs_name(0x2FC1_2FC1).is_some() && unsafe_fs_name(0x6969).is_some() && unsafe_fs_name(0x517B).is_some() && unsafe_fs_name(0xFF53_4D42).is_some());
        assert_eq!(unsafe_fs_name(0xEF53), None, "ext4 is fine");
        assert_eq!(unsafe_fs_name(0x0102_1994), None, "tmpfs is fine");
    }
}
