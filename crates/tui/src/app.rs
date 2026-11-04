//! UI state machine (no rendering, no terminal): driven by key events, fully testable.
use crate::secret::SecretBuf;
use seburity_core::{bundle::{safety_number, Bundle}, identity::ContactIdentity, trust::Trust};
use seburity_exchange::{file, pair::{Lockout, PairingJoin, PairingOffer}, ExchangeError, ImportedContact, SafetyView};
use seburity_store::{read_regular_file, StoreError, VaultFile};
use seburity_vault::Profile;
use std::{
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

pub struct Config {
    /// None = RAM-only: nothing is ever written to disk.
    pub path: Option<PathBuf>,
    pub counter: Option<PathBuf>,
    pub keyfile: Option<Zeroizing<Vec<u8>>>,
    pub profile: Profile,
}

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
    pub fn contact_rows(&self) -> Vec<(&str, Trust, bool)> {
        self.vf.as_ref().map_or(vec![], |v| v.store.contacts.iter().map(|c| (c.name.as_str(), c.trust, c.peer.is_some())).collect())
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
                            let (peer, trust) = ImportedContact::from_file(b).into_parts();
                            let c = self.cur().expect("selected");
                            c.peer = Some(peer);
                            c.trust = trust;
                            if self.save() { self.ok("Imported - UNVERIFIED. Press v and compare the safety number with them over another channel."); }
                        }
                    },
                }
            }
            Prompt::ConfirmDelete => {
                if text.trim().eq_ignore_ascii_case("yes") {
                    let i = self.sel;
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

    fn cancel_pairing(&mut self) {
        match self.pair_ctl.take() {
            Some(c) => { c.cancel(); self.pair_rx = None; self.pair_info = None; self.ok("Pairing cancelled."); }
            None => self.ok("No pairing in progress."),
        }
    }

    /// Call every UI tick: collects a finished pairing.
    pub fn poll(&mut self) {
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
        let Some(c) = self.vf().store.contacts.iter_mut().find(|c| c.id == id) else { self.err("Contact vanished during pairing."); return };
        if c.peer.is_some() { self.err("Contact already has a peer key; discarded the paired one."); return; }
        c.peer = Some(peer);
        c.trust = trust;
        if self.save() {
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

    pub fn type_str(a: &mut App, s: &str) { for c in s.chars() { a.handle(Key::Char(c)); } }

    fn cfg(path: Option<PathBuf>) -> Config {
        Config { path, counter: None, keyfile: None, profile: Profile::InsecureTest }
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
