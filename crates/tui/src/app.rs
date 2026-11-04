//! UI state machine (no rendering, no terminal): driven by key events, fully testable.
use crate::secret::{ComposeBuf, SecretBuf};
use seburity_chat::{transport::{TorSetup, TorTransport}, ContactCfg, Engine, Event, Timing, Transport};
use seburity_net::tor::{control::AuthPref, spawn::{find_tor, SpawnConfig}, Addr};
use seburity_core::{bundle::{safety_number, Bundle}, identity::ContactIdentity, trust::Trust};
use seburity_exchange::{file, pair::{Lockout, PairingJoin, PairingOffer}, ExchangeError, ImportedContact, SafetyView};
use seburity_store::{read_regular_file, StoreError, VaultFile};
use seburity_vault::Profile;
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
    pub profile: Profile,
    pub tor: TorCfg,
    pub transport: Option<TransportFactory>,
    pub timing: Timing,
    /// Start even though swap is active (secrets could be written to the disk by the OS). Default: refuse.
    pub allow_swap: bool,
}

impl Config {
    pub fn new(path: Option<PathBuf>, counter: Option<PathBuf>, keyfile: Option<Zeroizing<Vec<u8>>>, profile: Profile) -> Self {
        Self { path, counter, keyfile, profile, tor: TorCfg::default(), transport: None, timing: Timing::default(), allow_swap: false }
    }
}

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
    TorTransport::start(setup, |p| progress(p)).map(|t| Box::new(t) as Box<dyn Transport>)
}

/// Where the engine is. (UI reads this.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Online { Offline, Starting(u8), Online, Stopping, Failed(String) }

enum StartMsg { Progress(u8), Ready(Engine), Failed(String) }

/// One line of conversation. RAM only, wiped when dropped.
pub struct ChatLine { pub mine: bool, pub text: Zeroizing<String>, pub queued: bool }
const MAX_CHAT_LINES: usize = 500;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Key { Char(char), Enter, Esc, Backspace, Up, Down, Tab, F12, CtrlBackslash }

#[derive(Debug, PartialEq, Eq)]
pub enum Action { None, Quit, Panic }

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Prompt {
    NewContact, Import, Export, Listen, JoinAddr, JoinCode(String), ConfirmDelete, InPerson,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Screen {
    Unlock,
    CreatePw,
    CreateConfirm,
    Main,
    Prompt(Prompt),
    Verify,
    Help,
    Chat,
    /// After a panic: everything wiped, nothing to show.
    Wiped,
}

enum PairMsg { Done { contact_id: [u8; 8], result: Result<(ImportedContact, String), ExchangeError> } }

/// Handle on a running pairing worker so it can be cancelled (user `x`, or panic).
struct PairCtl { cancel: Arc<AtomicBool>, stream: Arc<Mutex<Option<TcpStream>>>, handle: JoinHandle<()> }

impl PairCtl {
    /// Ask the worker to stop and cut its socket so blocked reads return immediately.
    fn cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
        if let Some(s) = self.stream.lock().unwrap().as_ref() { let _ = s.shutdown(Shutdown::Both); }
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
    pub pair_info: Option<Zeroizing<String>>,
    pair_ctl: Option<PairCtl>,
    code_buf: SecretBuf,
    pending_pair: Option<([u8; 8], ImportedContact, String)>,
    failures: u32,
    locked_until: Option<Instant>,
    lockout: std::sync::Arc<Lockout>,
    engine: Option<Engine>,
    start_rx: Option<Receiver<StartMsg>>,
    /// ids the engine was started with (to reconcile with the vault when it becomes ready)
    started_ids: HashSet<[u8; 8]>,
    stop_rx: Option<Receiver<()>>,
    pub online: Online,
    chats: HashMap<[u8; 8], Vec<ChatLine>>,
    linked: HashSet<[u8; 8]>,
    unread: HashMap<[u8; 8], u32>,
    chat_with: Option<[u8; 8]>,
    compose: ComposeBuf,
}

impl App {
    pub fn new(cfg: Config) -> Self {
        let exists = cfg.path.as_ref().is_some_and(|p| p.exists());
        let ram = cfg.path.is_none();
        let mut a = Self {
            cfg, screen: if exists { Screen::Unlock } else { Screen::CreatePw }, pw: SecretBuf::new(), pw2: SecretBuf::new(),
            input: String::new(), status: String::new(), error: false, sel: 0, vf: None, view: None,
            pair_rx: None, pair_info: None, pair_ctl: None, code_buf: SecretBuf::new(), pending_pair: None, failures: 0, locked_until: None,
            lockout: std::sync::Arc::new(Lockout::default()),
            engine: None, start_rx: None, started_ids: HashSet::new(), stop_rx: None, online: Online::Offline, chats: HashMap::new(), linked: HashSet::new(), unread: HashMap::new(), chat_with: None, compose: ComposeBuf::new(),
        };
        a.status = if ram { "RAM-only mode: nothing will be written to disk.".into() }
            else if exists { "Enter your password to unlock.".into() }
            else { format!("No vault found. Creating a NEW one (min {MIN_PW_CHARS} characters).") };
        a
    }

    pub fn path_display(&self) -> String {
        self.cfg.path.as_ref().map_or("RAM-only".into(), |p| p.display().to_string())
    }
    pub fn contacts_len(&self) -> usize { self.vf.as_ref().map_or(0, |v| v.store.contacts.len()) }
    /// Borrowed rows: no per-frame copies of contact names.
    pub fn contact_rows(&self) -> Vec<(&str, Trust, bool, bool, u32)> {
        self.vf.as_ref().map_or(vec![], |v| v.store.contacts.iter()
            .map(|c| (c.name.as_str(), c.trust, c.peer.is_some(), self.linked.contains(&c.id), self.unread.get(&c.id).copied().unwrap_or(0))).collect())
    }
    /// (name, trust, connected) of the open chat.
    pub fn chat_header(&self) -> Option<(&str, Trust, bool)> {
        let id = self.chat_with?;
        let c = self.vf.as_ref()?.store.contacts.iter().find(|c| c.id == id)?;
        Some((c.name.as_str(), c.trust, self.linked.contains(&id)))
    }
    pub fn chat_lines(&self) -> &[ChatLine] { self.chat_with.and_then(|id| self.chats.get(&id)).map_or(&[], |v| v.as_slice()) }
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
    pub fn code_chars(&self) -> usize { self.code_buf.chars() }
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn pairing_active(&self) -> bool { self.pair_ctl.is_some() }
    pub fn view_number(&self) -> Option<&str> { self.view.as_ref().map(|v| v.number.as_str()) }
    pub fn is_ram_only(&self) -> bool { self.cfg.path.is_none() }
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn unlocked(&self) -> bool { self.vf.is_some() }

    fn ok(&mut self, m: impl Into<String>) { self.status = m.into(); self.error = false; }
    fn err(&mut self, m: impl Into<String>) { self.status = m.into(); self.error = true; }

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
        self.online = Online::Offline;
        self.chats.clear();
        self.linked.clear();
        self.unread.clear();
        self.chat_with = None;
        self.compose.clear();
        self.code_buf.clear();
        self.vf = None;
        self.view = None;
        self.pending_pair = None;
        self.pair_rx = None;
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
        if matches!(k, Key::F12 | Key::CtrlBackslash) { self.panic_wipe(); return Action::Panic; }
        match &self.screen {
            Screen::Wiped => Action::Quit,
            Screen::Unlock => self.key_unlock(k),
            Screen::CreatePw | Screen::CreateConfirm => self.key_create(k),
            Screen::Main => self.key_main(k),
            Screen::Prompt(_) => { self.key_prompt(k); Action::None }
            Screen::Verify => { self.key_verify(k); Action::None }
            Screen::Help => { self.screen = Screen::Main; Action::None }
            Screen::Chat => { self.key_chat(k); Action::None }
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
                let r = VaultFile::open(&path, self.cfg.counter.as_deref(), self.pw.as_bytes(), self.cfg.keyfile.as_deref().map(|v| v.as_slice()));
                self.pw.clear();
                match r {
                    Ok((vf, info)) => {
                        self.vf = Some(vf);
                        self.screen = Screen::Main;
                        self.failures = 0;
                        if info.rollback_unchecked {
                            self.err("WARNING: no counter file - rollback of the vault cannot be detected (see docs).");
                        } else if info.counter_same_device {
                            self.err(format!("Unlocked. Vault save #{}. WARNING: the counter file is on the SAME device as the vault: weak rollback protection (use --counter-file on another device).", info.counter));
                        } else { self.ok(format!("Unlocked. Vault save #{}.", info.counter)); }
                    }
                    Err(StoreError::Vault(seburity_vault::VaultError::Rollback { found, expected })) =>
                        self.err(format!("ROLLBACK DETECTED: vault save #{found} is older than #{expected}. An old copy was substituted. Refusing to open.")),
                    Err(StoreError::Vault(seburity_vault::VaultError::Tampered)) =>
                        self.err("Password correct but the vault file is CORRUPTED or TAMPERED with."),
                    Err(StoreError::Vault(seburity_vault::VaultError::WrongCredentials)) => {
                        self.failures += 1;
                        if self.failures >= 3 {
                            let wait = 5u64 << (self.failures - 3).min(6);
                            self.locked_until = Some(Instant::now() + Duration::from_secs(wait));
                        }
                        self.err("Wrong password or keyfile.");
                    }
                    Err(e) => self.err(format!("Cannot open vault: {e}")),
                }
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
        let mut rnd = Zeroizing::new([0u8; 32]);
        if random_pw { getrandom::fill(&mut *rnd).expect("OS RNG unavailable"); }
        let pw: &[u8] = if random_pw { &rnd[..] } else { self.pw.as_bytes() };
        let r = VaultFile::create(self.cfg.path.as_deref(), self.cfg.counter.as_deref(), pw, self.cfg.keyfile.as_deref().map(|v| v.as_slice()), self.cfg.profile);
        self.pw.clear(); self.pw2.clear();
        match r {
            Ok(vf) => {
                self.vf = Some(vf);
                self.screen = Screen::Main;
                self.ok("Vault created. Press n to add your first contact, ? for help.");
            }
            Err(e) => { self.screen = Screen::CreatePw; self.err(format!("Cannot create vault: {e}")); }
        }
    }

    // ---------- main ----------
    fn key_main(&mut self, k: Key) -> Action {
        let n = self.contacts_len();
        match k {
            Key::Char('q') | Key::Esc => return Action::Quit,
            Key::Up | Key::Char('k') => self.sel = self.sel.saturating_sub(1),
            Key::Down | Key::Char('j') => { if self.sel + 1 < n { self.sel += 1 } }
            Key::Char('?') => self.screen = Screen::Help,
            Key::Char('n') => self.open_prompt(Prompt::NewContact, ""),
            // Neutral random default: the contact's name must not leak into filesystem metadata.
            Key::Char('e') => if self.sel_name().is_some() {
                let mut r = [0u8; 4];
                getrandom::fill(&mut r).expect("OS RNG unavailable");
                let name = format!("bundle-{}.sbc", r.iter().map(|b| format!("{b:02x}")).collect::<String>());
                self.open_prompt(Prompt::Export, &name)
            },
            Key::Char('i') => if self.require_no_peer() { self.open_prompt(Prompt::Import, "") },
            Key::Char('l') => if self.require_no_peer() { self.open_prompt(Prompt::Listen, "127.0.0.1:0") },
            Key::Char('c') => if self.require_no_peer() { self.open_prompt(Prompt::JoinAddr, "") },
            Key::Char('x') => self.cancel_pairing(),
            Key::Char('o') => self.toggle_online(),
            Key::Enter => self.open_chat(),
            Key::Char('v') => self.start_verify(),
            Key::Char('d') => if self.sel_name().is_some() { self.open_prompt(Prompt::ConfirmDelete, "") },
            _ => {}
        }
        Action::None
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
        true
    }

    fn open_prompt(&mut self, p: Prompt, default: &str) {
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
    fn cur(&mut self) -> Option<&mut seburity_store::Contact> {
        let i = self.sel;
        self.vf.as_mut()?.store.contacts.get_mut(i)
    }

    fn save(&mut self) -> bool {
        match self.vf().save() { Ok(()) => true, Err(e) => { self.err(format!("SAVE FAILED: {e}")); false } }
    }

    fn submit(&mut self, p: Prompt, text: String) {
        match p {
            Prompt::NewContact => match self.vf().store.add_contact(text.trim_end_matches('\n')) {
                Ok(i) => {
                    self.sel = i;
                    if self.save() { self.ok("Contact created with a NEW keypair. Export your bundle (e) and send it, then import theirs (i), or pair over the local link (l / c)."); }
                }
                Err(e) => self.err(format!("{e}")),
            },
            Prompt::Export => {
                let Some(c) = self.cur() else { return };
                let id = &c.identity;
                let armored = file::armor(&Bundle::from_identity(id).encode(id));
                let path = PathBuf::from(&text);
                match fs::OpenOptions::new().write(true).create_new(true).open(&path).and_then(|mut f| f.write_all(armored.as_bytes())) {
                    Ok(()) => self.ok(format!("Wrote your PUBLIC bundle to {}. Send it over a channel you trust, then compare the safety number (v).", path.display())),
                    Err(e) => self.err(format!("Cannot write {}: {e} (never overwrites existing files)", path.display())),
                }
            }
            Prompt::Import => {
                // Never follows symlinks, never blocks on FIFOs/devices, size-capped.
                let r = read_regular_file(std::path::Path::new(&text), MAX_IMPORT_BYTES)
                    .and_then(|b| String::from_utf8(b).map_err(|_| StoreError::Corrupt));
                match r {
                    Err(e) => self.err(format!("Cannot read {text}: {e}")),
                    Ok(s) => match file::dearmor(&s) {
                        Err(_) => self.err("Not a valid Seburity contact file."),
                        Ok(b) => {
                            let mine = Bundle::from_identity(&self.cur().expect("selected").identity);
                            if b == mine { self.err("That is YOUR OWN bundle, not the other person's."); return; }
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
                        self.chats.remove(&id); self.linked.remove(&id); self.unread.remove(&id);
                    }
                    self.vf().store.remove(i);
                    self.sel = self.sel.saturating_sub(1);
                    if self.save() { self.ok("Contact and its keys deleted."); }
                } else { self.ok("Not deleted (type yes to confirm)."); }
            }
            Prompt::Listen => self.start_listen(text),
            Prompt::JoinAddr => self.open_prompt(Prompt::JoinCode(text.trim().to_string()), ""),
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

    fn start_listen(&mut self, addr: String) {
        let addr: SocketAddr = match addr.trim().parse() { Ok(a) => a, Err(_) => { self.err("Bad address, expected e.g. 127.0.0.1:0 or 192.168.1.5:4000"); return } };
        if !listen_addr_ok(&addr) { self.err("Refusing to listen on 0.0.0.0 / a public address: use your private LAN IP (e.g. 192.168.1.5:4000) or 127.0.0.1."); return; }
        let (offer, code) = match PairingOffer::generate_in(self.lockout.clone()) { Ok(x) => x, Err(e) => { self.err(format!("{e}")); return } };
        let listener = match TcpListener::bind(addr) { Ok(l) => l, Err(e) => { self.err(format!("Cannot listen: {e}")); return } };
        let bound = listener.local_addr().expect("bound");
        let (ident, id) = self.identity_clone();
        let (tx, rx) = channel();
        let expires = offer.expires_in();
        let cancel = Arc::new(AtomicBool::new(false));
        let slot: Arc<Mutex<Option<TcpStream>>> = Arc::new(Mutex::new(None));
        let (c2, s2) = (cancel.clone(), slot.clone());
        let handle = thread::spawn(move || {
            listener.set_nonblocking(true).ok();
            let deadline = Instant::now() + expires;
            let result = loop {
                if c2.load(Ordering::SeqCst) { break Err(ExchangeError::Io); }
                match listener.accept() {
                    // ONE connection only: the listener is dropped right after, success or failure.
                    Ok((mut s, _)) => {
                        s.set_nonblocking(false).ok();
                        *s2.lock().unwrap() = s.try_clone().ok();
                        if c2.load(Ordering::SeqCst) { break Err(ExchangeError::Io); }
                        break pair_result(offer.accept(&mut s, &ident), &ident);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline { break Err(ExchangeError::Expired); }
                        thread::sleep(Duration::from_millis(100));
                    }
                    Err(_) => break Err(ExchangeError::Io),
                }
            };
            let _ = tx.send(PairMsg::Done { contact_id: id, result });
        });
        self.pair_rx = Some(rx);
        self.pair_ctl = Some(PairCtl { cancel, stream: slot, handle });
        self.pair_info = Some(Zeroizing::new(format!("Listening on {bound}  -  CODE: {}  (valid {} min, ONE attempt; x = cancel). Tell the other person the address and code IN PERSON.", &*code, expires.as_secs() / 60)));
        self.ok("Waiting for the other device...");
    }

    fn start_join(&mut self, addr: String) {
        let sock: SocketAddr = match addr.parse() { Ok(a) => a, Err(_) => { self.code_buf.clear(); self.err("Bad address, expected ip:port"); return } };
        let parsed = std::str::from_utf8(self.code_buf.as_bytes()).map_err(|_| ExchangeError::BadCode)
            .and_then(|c| PairingJoin::parse_in(c, self.lockout.clone()));
        self.code_buf.clear();
        let join = match parsed { Ok(j) => j, Err(e) => { self.err(format!("{e}")); return } };
        let (ident, id) = self.identity_clone();
        let (tx, rx) = channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let slot: Arc<Mutex<Option<TcpStream>>> = Arc::new(Mutex::new(None));
        let (c2, s2) = (cancel.clone(), slot.clone());
        let handle = thread::spawn(move || {
            let result = match TcpStream::connect_timeout(&sock, Duration::from_secs(10)) {
                Ok(mut s) if !c2.load(Ordering::SeqCst) => {
                    *s2.lock().unwrap() = s.try_clone().ok();
                    if c2.load(Ordering::SeqCst) { Err(ExchangeError::Io) } else { pair_result(join.join(&mut s, &ident), &ident) }
                }
                _ => Err(ExchangeError::Io),
            };
            let _ = tx.send(PairMsg::Done { contact_id: id, result });
        });
        self.pair_rx = Some(rx);
        self.pair_ctl = Some(PairCtl { cancel, stream: slot, handle });
        self.pair_info = Some(Zeroizing::new(format!("Connecting to {sock} ... (x = cancel)")));
        self.ok("Pairing...");
    }

    // ---------- going online + chat ----------
    fn toggle_online(&mut self) {
        match self.online.clone() {
            Online::Starting(_) => self.err("Already starting; wait for it to finish."),
            Online::Stopping => self.err("Still shutting down; wait a moment."),
            Online::Online => {
                // tear down on a worker so the UI (and the panic key) stay responsive while onion services are removed
                let (tx, rx) = channel();
                if let Some(e) = self.engine.take() { thread::spawn(move || { e.shutdown(); let _ = tx.send(()); }); } else { let _ = tx.send(()); }
                self.stop_rx = Some(rx);
                self.online = Online::Stopping;
                self.linked.clear();
                self.ok("Going offline: closing connections and removing onion services...");
            }
            Online::Offline | Online::Failed(_) => self.start_online(),
        }
    }

    fn start_online(&mut self) {
        let Some(vf) = self.vf.as_ref() else { return };
        let contacts: Vec<ContactCfg> = vf.store.contacts.iter().filter_map(|c| c.peer.as_ref().map(|p| ContactCfg::new(c.id, &c.identity, p.clone()))).collect();
        self.started_ids = contacts.iter().map(|c| c.id).collect();
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
        if let Some(p) = &c.peer { e.add(ContactCfg::new(c.id, &c.identity, p.clone())); }
    }

    /// A peer bundle must not reuse an onion key that another contact already uses (ours or theirs): a crafted bundle
    /// could otherwise overwrite our client-auth credential for someone else's service (R6-L7).
    fn onion_collision(&self, idx: usize, peer: &Bundle) -> bool {
        let Some(v) = self.vf.as_ref() else { return false };
        v.store.contacts.iter().enumerate().any(|(i, c)| {
            c.identity.onion_public() == peer.onion_pub || (i != idx && c.peer.as_ref().is_some_and(|p| p.onion_pub == peer.onion_pub))
        })
    }

    fn open_chat(&mut self) {
        let Some(c) = self.vf.as_ref().and_then(|v| v.store.contacts.get(self.sel)) else { return self.err("No contact selected. Press n to add one.") };
        if c.peer.is_none() { return self.err("No peer key yet: import their file (i) or pair (l / c) first."); }
        let id = c.id;
        self.chat_with = Some(id);
        self.unread.remove(&id);
        self.compose.clear();
        self.screen = Screen::Chat;
        if self.online == Online::Offline { self.ok("You are OFFLINE: press Esc, then o to go online. You can still type; messages are sent only while online."); }
    }

    fn key_chat(&mut self, k: Key) {
        match k {
            Key::Esc | Key::Tab => { self.compose.clear(); self.chat_with = None; self.screen = Screen::Main; }
            Key::Backspace => self.compose.pop(),
            Key::Char(c) => { self.compose.push(c); }
            Key::Enter => self.send_compose(),
            _ => {}
        }
    }

    fn send_compose(&mut self) {
        let Some(id) = self.chat_with else { return };
        if self.compose.is_empty() { return; }
        if self.engine.is_none() { return self.err("You are offline: press Esc, then o. (Nothing was sent.)"); }
        let text = self.compose.take_string();
        let queued = !self.linked.contains(&id);
        // keep a wiped-on-drop copy for the screen, hand the other to the engine
        let shown = Zeroizing::new((*text).clone());
        if let Some(e) = &self.engine { e.send(id, text); }
        self.push_line(id, ChatLine { mine: true, text: shown, queued });
        if queued { self.ok("Peer is not connected: message queued in RAM, delivered when they come online (lost if you quit)."); }
    }

    fn push_line(&mut self, id: [u8; 8], l: ChatLine) {
        let v = self.chats.entry(id).or_default();
        v.push(l);
        if v.len() > MAX_CHAT_LINES { v.remove(0); } // the dropped line is wiped (Zeroizing)
    }

    /// Contacts may have been added/deleted while tor was starting: make the engine match the vault (R6-M4/L2).
    fn reconcile(&mut self) {
        let now: HashSet<[u8; 8]> = self.vf.as_ref().map(|v| v.store.contacts.iter().filter(|c| c.peer.is_some()).map(|c| c.id).collect()).unwrap_or_default();
        let Some(e) = &self.engine else { return };
        for id in self.started_ids.difference(&now) { e.remove(*id); }
        if let Some(v) = self.vf.as_ref() {
            for c in v.store.contacts.iter().filter(|c| !self.started_ids.contains(&c.id)) {
                if let Some(p) = &c.peer { e.add(ContactCfg::new(c.id, &c.identity, p.clone())); }
            }
        }
        self.started_ids = now;
    }

    fn known(&self, id: &[u8; 8]) -> bool { self.vf.as_ref().is_some_and(|v| v.store.contacts.iter().any(|c| c.id == *id)) }

    fn poll_online(&mut self) {
        if let Some(rx) = self.stop_rx.take() {
            match rx.try_recv() {
                Err(TryRecvError::Empty) => self.stop_rx = Some(rx),
                _ => { self.online = Online::Offline; self.ok("Offline. Connections closed, onion services and credentials removed."); }
            }
        }
        if let Some(rx) = self.start_rx.take() {
            let mut keep = true;
            loop {
                match rx.try_recv() {
                    Ok(StartMsg::Progress(p)) => self.online = Online::Starting(p),
                    Ok(StartMsg::Ready(e)) => { self.engine = Some(e); self.online = Online::Online; keep = false; self.reconcile(); self.ok("ONLINE. Contacts you dial or that dial you will connect as they come up."); break; }
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
            let stale = match &ev { Event::Connected { id } | Event::Disconnected { id } | Event::Message { id, .. } => !self.known(id), Event::Notice { .. } => false };
            if stale { continue; }
            match ev {
                Event::Connected { id } => { self.linked.insert(id); }
                Event::Disconnected { id } => { self.linked.remove(&id); }
                Event::Message { id, text } => {
                    self.push_line(id, ChatLine { mine: false, text, queued: false });
                    if !(self.screen == Screen::Chat && self.chat_with == Some(id)) { *self.unread.entry(id).or_insert(0) += 1; }
                }
                Event::Notice { text, .. } => self.status = text,
            }
        }
    }

    fn cancel_pairing(&mut self) {
        match self.pair_ctl.take() {
            Some(c) => { c.cancel(); self.pair_rx = None; self.pair_info = None; self.ok("Pairing cancelled."); }
            None => self.ok("No pairing in progress."),
        }
    }

    /// Call every UI tick: collects a finished pairing.
    pub fn poll(&mut self) {
        self.poll_online();
        let Some(rx) = &self.pair_rx else { return };
        match rx.try_recv() {
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => { self.pair_rx = None; self.pair_ctl = None; self.pair_info = None; self.err("Pairing thread died."); }
            Ok(PairMsg::Done { contact_id, result }) => {
                self.pair_rx = None;
                self.pair_ctl = None;
                self.pair_info = None;
                match result {
                    Ok((contact, sn)) => {
                        self.pending_pair = Some((contact_id, contact, sn));
                        self.open_prompt(Prompt::InPerson, "");
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
        let Some(c) = self.vf().store.contacts.iter_mut().find(|c| c.id == id) else { self.err("Contact vanished during pairing."); return };
        if c.peer.is_some() { self.err("Contact already has a peer key; discarded the paired one."); return; }
        c.peer = Some(peer);
        c.trust = trust;
        if self.save() {
            if let Some(i) = self.vf().store.contacts.iter().position(|c| c.id == id) { self.engine_add(i); }
            let how = if trust == Trust::CodeAuthenticated { "code-authenticated (in person)" } else { "UNVERIFIED - compare the safety number (v)" };
            self.ok(format!("Paired: {how}. Safety number {sn}"));
        }
    }
}

fn pair_result(r: Result<seburity_exchange::pair::Paired, ExchangeError>, _me: &ContactIdentity) -> Result<(ImportedContact, String), ExchangeError> {
    r.map(|p| (p.contact, p.safety_number))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use seburity_chat::{Timing, Transport};
    use std::sync::atomic::AtomicBool;

    pub fn type_str(a: &mut App, s: &str) { for c in s.chars() { a.handle(Key::Char(c)); } }

    fn cfg(path: Option<PathBuf>) -> Config {
        Config::new(path, None, None, Profile::InsecureTest)
    }

    fn create_app(dir: &std::path::Path, name: &str) -> App {
        let mut a = App::new(cfg(Some(dir.join(name))));
        assert_eq!(a.screen, Screen::CreatePw);
        type_str(&mut a, "correct horse battery"); a.handle(Key::Enter);
        assert_eq!(a.screen, Screen::CreateConfirm);
        type_str(&mut a, "correct horse battery"); a.handle(Key::Enter);
        assert_eq!(a.screen, Screen::Main, "{}", a.status);
        a
    }

    fn add(a: &mut App, name: &str) { a.handle(Key::Char('n')); type_str(a, name); a.handle(Key::Enter); }

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
            app.handle(Key::Char('i')); type_str(app, f.to_str().unwrap()); app.handle(Key::Enter);
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
        a.handle(Key::Char('i')); assert!(a.error);
    }

    #[test]
    fn import_rejects_garbage_own_bundle_and_oversize() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "v"); add(&mut a, "bob");
        let g = d.path().join("g.sbc"); fs::write(&g, "garbage").unwrap();
        a.handle(Key::Char('i')); type_str(&mut a, g.to_str().unwrap()); a.handle(Key::Enter);
        assert!(a.error && a.selected_detail().unwrap().2.is_none());
        let own = d.path().join("own.sbc");
        a.handle(Key::Char('e')); a.input.clear(); type_str(&mut a, own.to_str().unwrap()); a.handle(Key::Enter);
        a.handle(Key::Char('i')); type_str(&mut a, own.to_str().unwrap()); a.handle(Key::Enter);
        assert!(a.error && a.status.contains("OWN"));
        let big = d.path().join("big.sbc"); fs::write(&big, vec![b'A'; 100_000]).unwrap();
        a.handle(Key::Char('i')); type_str(&mut a, big.to_str().unwrap()); a.handle(Key::Enter);
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
            assert!(!a.unlocked() && a.screen == Screen::Wiped);
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
        // A listens
        a.handle(Key::Char('l')); a.handle(Key::Enter);
        let info = a.pair_info.clone().expect("listening");
        let addr = info.split_whitespace().nth(2).unwrap().to_string();
        let code = info.split("CODE: ").nth(1).unwrap().split_whitespace().next().unwrap().to_string();
        // B joins
        b.handle(Key::Char('c')); type_str(&mut b, &addr); b.handle(Key::Enter);
        type_str(&mut b, &code); b.handle(Key::Enter);
        let t = Instant::now();
        while (a.pairing_active() || b.pairing_active()) && t.elapsed() < Duration::from_secs(20) {
            a.poll(); b.poll(); thread::sleep(Duration::from_millis(50));
        }
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
            assert!(a.error && !a.pairing_active() && a.status.contains("Refusing"), "{bad}: {}", a.status);
        }
        a.handle(Key::Char('l')); a.handle(Key::Enter); // default 127.0.0.1:0 is fine
        assert!(a.pairing_active());
    }

    #[test]
    fn cancel_and_panic_stop_pairing_workers() {
        let d = tempfile::tempdir().unwrap();
        let mut a = create_app(d.path(), "a.vault"); add(&mut a, "bob");
        a.handle(Key::Char('l')); a.handle(Key::Enter);
        assert!(a.pairing_active());
        a.handle(Key::Char('x'));
        assert!(!a.pairing_active() && a.pair_info.is_none());
        // a second listen works again, and panic joins the worker quickly
        a.handle(Key::Char('l')); a.handle(Key::Enter);
        assert!(a.pairing_active());
        let t = Instant::now();
        a.handle(Key::F12);
        assert!(!a.pairing_active() && t.elapsed() < Duration::from_secs(2));
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
        a.handle(Key::Char('l')); a.handle(Key::Enter);
        let info = a.pair_info.clone().unwrap();
        let addr = info.split_whitespace().nth(2).unwrap().to_string();
        let code = info.split("CODE: ").nth(1).unwrap().split_whitespace().next().unwrap().to_string();
        b.handle(Key::Char('c')); type_str(&mut b, &addr); b.handle(Key::Enter); type_str(&mut b, &code); b.handle(Key::Enter);
        let t = Instant::now();
        while (a.pairing_active() || b.pairing_active()) && t.elapsed() < Duration::from_secs(20) { a.poll(); b.poll(); thread::sleep(Duration::from_millis(50)); }
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
        a.handle(Key::Char('i')); type_str(&mut a, fifo.to_str().unwrap()); a.handle(Key::Enter);
        assert!(a.error && t.elapsed() < Duration::from_secs(2));
        let link = d.path().join("tty.sbc");
        std::os::unix::fs::symlink("/dev/tty", &link).unwrap();
        a.handle(Key::Char('i')); type_str(&mut a, link.to_str().unwrap()); a.handle(Key::Enter);
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
                 min_backoff: Duration::from_millis(30), max_backoff: Duration::from_millis(200), handshake: Duration::from_secs(5), handshakes_per_sec: 1000.0, host_fallback_after: 3 }
    }

    fn net_app(dir: &std::path::Path, name: &str, net: &seburity_chat::MemNet) -> App {
        let mut c = cfg(Some(dir.join(name)));
        let net = net.clone();
        c.transport = Some(std::sync::Arc::new(move |_p: &mut dyn FnMut(u8)| Ok(Box::new(net.transport()) as Box<dyn Transport>)));
        c.timing = fast_timing();
        let mut a = App::new(c);
        type_str(&mut a, "correct horse battery"); a.handle(Key::Enter);
        type_str(&mut a, "correct horse battery"); a.handle(Key::Enter);
        assert_eq!(a.screen, Screen::Main, "{}", a.status);
        a
    }

    /// Exchange bundle files between the selected contacts of a and b (the offline path).
    fn link_apps(a: &mut App, b: &mut App, dir: &std::path::Path) {
        let (fa, fb) = (dir.join(format!("{:?}-a.sbc", a as *const _)), dir.join(format!("{:?}-b.sbc", b as *const _)));
        for (app, f) in [(&mut *a, &fa), (&mut *b, &fb)] {
            app.handle(Key::Char('e')); app.input.clear(); type_str(app, f.to_str().unwrap()); app.handle(Key::Enter);
            assert!(!app.error, "{}", app.status);
        }
        for (app, f) in [(&mut *a, &fb), (&mut *b, &fa)] {
            app.handle(Key::Char('i')); type_str(app, f.to_str().unwrap()); app.handle(Key::Enter);
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

    fn go_online(a: &mut App) { a.handle(Key::Char('o')); }
    fn is_linked(a: &App) -> bool { a.contact_rows().first().is_some_and(|r| r.3) }

    #[test]
    fn two_users_chat_through_the_screens() {
        let d = tempfile::tempdir().unwrap();
        let net = seburity_chat::MemNet::new();
        let mut a = net_app(d.path(), "a.vault", &net); add(&mut a, "bob");
        let mut b = net_app(d.path(), "b.vault", &net); add(&mut b, "alice");
        link_apps(&mut a, &mut b, d.path());
        assert_eq!(a.online, Online::Offline);
        go_online(&mut a); go_online(&mut b);
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].online == Online::Online && x[1].online == Online::Online), "{:?}", a.status);
        assert!(pump_until(&mut [&mut a, &mut b], |x| is_linked(x[0]) && is_linked(x[1])), "never connected");
        // alice's side: open chat, type, send
        a.handle(Key::Enter);
        assert_eq!(a.screen, Screen::Chat);
        type_str(&mut a, "hello bob, this is private"); a.handle(Key::Enter);
        assert!(a.compose_text().is_empty() && a.chat_lines().len() == 1 && a.chat_lines()[0].mine && !a.chat_lines()[0].queued);
        // bob sees an unread marker, opens the chat, sees the line
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[1].contact_rows()[0].4 == 1), "no unread marker");
        b.handle(Key::Enter);
        assert_eq!(&*b.chat_lines()[0].text, "hello bob, this is private");
        assert!(!b.chat_lines()[0].mine);
        assert_eq!(b.contact_rows()[0].4, 0, "unread cleared by opening");
        // what bob actually sees on screen
        let mut term = ratatui::Terminal::new(ratatui::backend::TestBackend::new(110, 24)).unwrap();
        term.draw(|f| crate::ui::draw(f, &b)).unwrap();
        let screen: String = term.backend().buffer().content().iter().map(|c| c.symbol()).collect();
        assert!(screen.contains("hello bob, this is private") && screen.contains("them>") && screen.contains("connected"), "{screen}");
        assert!(screen.contains("WARNING: identity not verified"), "unverified contacts carry a visible warning");
        type_str(&mut b, "got it"); b.handle(Key::Enter);
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].chat_lines().len() == 2), "reply never arrived");
        assert_eq!(&*a.chat_lines()[1].text, "got it");
        // a message that arrives while the chat is OPEN is not counted as unread
        type_str(&mut b, "second"); b.handle(Key::Enter);
        assert!(pump_until(&mut [&mut a, &mut b], |x| x[0].chat_lines().len() == 3));
        assert_eq!(a.contact_rows()[0].4, 0);
    }

    #[test]
    fn contact_added_while_online_connects_and_offline_is_refused_cleanly() {
        let d = tempfile::tempdir().unwrap();
        let net = seburity_chat::MemNet::new();
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
        a.handle(Key::Enter); type_str(&mut a, "x"); a.handle(Key::Enter);
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
        let net = seburity_chat::MemNet::new();
        let mut a = net_app(d.path(), "a.vault", &net); add(&mut a, "bob");
        let mut b = net_app(d.path(), "b.vault", &net); add(&mut b, "alice");
        link_apps(&mut a, &mut b, d.path());
        go_online(&mut a); go_online(&mut b);
        assert!(pump_until(&mut [&mut a, &mut b], |x| is_linked(x[0]) && is_linked(x[1])));
        a.handle(Key::Enter); type_str(&mut a, "secret words"); a.handle(Key::Enter);
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
    fn gated_app(dir: &std::path::Path, name: &str, net: &seburity_chat::MemNet, gate: std::sync::Arc<std::sync::atomic::AtomicBool>) -> App {
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
        let net = seburity_chat::MemNet::new();
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
        let net = seburity_chat::MemNet::new();
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
        a.handle(Key::Char('i')); type_str(&mut a, f.to_str().unwrap()); a.handle(Key::Enter);
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
        a.chat_with = Some(id);
        a.screen = Screen::Chat;
        let msg: String = "漢".repeat(60);
        a.push_line(id, ChatLine { mine: false, text: Zeroizing::new(msg.clone()), queued: false });
        a.push_line(id, ChatLine { mine: true, text: Zeroizing::new(msg), queued: false });
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
        a.handle(Key::Char('l')); a.handle(Key::Enter);
        let addr = a.pair_info.clone().unwrap().split_whitespace().nth(2).unwrap().to_string();
        b.handle(Key::Char('c')); type_str(&mut b, &addr); b.handle(Key::Enter);
        type_str(&mut b, "0000000000"); b.handle(Key::Enter);
        let t = Instant::now();
        while (a.pairing_active() || b.pairing_active()) && t.elapsed() < Duration::from_secs(20) { a.poll(); b.poll(); thread::sleep(Duration::from_millis(50)); }
        assert!(a.error && b.error, "{} / {}", a.status, b.status);
        assert!(a.selected_detail().unwrap().2.is_none() && b.selected_detail().unwrap().2.is_none());
    }
}
