//! The command layer: what a tap or a typed line means for the core. Every operation is a short string (`"select"`, `"send"`...) so that
//! the JNI surface stays two functions, and every operation is GUARDED: text only reaches the core where the core itself takes text
//! (a typed letter anywhere else would be a one-key command, e.g. `q` or `o`), and only an allowlist of commands can be sent.
use crate::snapshot::{snapshot, Extra};
use sine_loco_app::{
    app::{Action, App, Config, Key, Mode, Online, Pane, Persist, Prompt, Screen},
    startup, vault_path,
};
use sine_loco_vault::Profile;
use std::{path::{Path, PathBuf}, time::{Duration, Instant}};
use zeroize::Zeroizing;

/// The core's compose buffer holds this many bytes and silently drops the rest: a longer text is refused here instead of truncated.
pub const COMPOSE_MAX_BYTES: usize = 2048;
/// Commands a screen may send (the core's normal-mode letters). NOT included: `q` quit, `o` (use "online"), `e`/`I`/`l`/`c`/`f`/`t`/`s`
/// (files and the local link do not exist on the phone), `P` (use "in_person").
const COMMANDS: &[char] = &['n', 'T', 'J', 'x', 'v', 'd', 'K', 'h', 'z'];

pub struct Options {
    /// 128 MiB key derivation instead of 512 MiB (phones with little RAM)
    pub low_mem: bool,
    /// the tor executable to start (`libtor.so` in the app's native library directory); None = the core looks in PATH and will fail
    pub tor_path: Option<PathBuf>,
    /// what the encrypted outbox does until the user chooses (the phone turns it on: the OS kills the app at will); the user's choice is stored in the vault and wins
    pub persist_default: Persist,
    /// the deletable key store for the history's bucket keys (the Android Keystore); None = keys are stored inside the encrypted history file (cannot be erased cryptographically)
    pub platform_keys: Option<std::sync::Arc<dyn sine_loco_store::history::PlatformKeys>>,
}

pub struct Bridge {
    app: App,
    user_offline: bool,
    started: bool,
    retry_at: Option<Instant>,
    retries: u32,
    auto_online: bool,
    purge: Option<(usize, usize)>,
    /// tor's runtime base inside the app's private storage (None without a tor executable)
    tor_base: Option<PathBuf>,
    /// The phone's network, as the Kotlin side reports it. While it is DOWN tor's network is disabled (tor then neither marks its guards unreachable and moves on to more of them,
    /// nor burns battery on doomed attempts). Coming back is delayed by a random 3-15 s: a flapping network must not make us re-announce ourselves in lock step with it.
    network_up: bool,
    network_up_at: Option<Instant>,
    /// Applies the desired network state to our tor(s) on its OWN thread (the core thread must never wait for a control socket: the panic path shares it).
    net: NetWorker,
}

/// Sets tor's network on/off on a worker thread. It remembers, per tor (pid), what that tor has CONFIRMED and keeps trying until the desired state is confirmed: an "up" that never
/// arrived would leave tor silent while the screen says "Tor connected". A tor it has not told anything is assumed to be enabled (that is how tor starts), so a tor that appears
/// during an outage is told once, and nothing is re-sent while nothing changed. The thread ends when the bridge is dropped.
struct NetWorker { desired: std::sync::Arc<std::sync::atomic::AtomicBool>, kick: std::sync::mpsc::Sender<()> }

type LiveFn = std::sync::Arc<dyn Fn() -> Vec<(u32, PathBuf)> + Send + Sync>;
type ApplyFn = std::sync::Arc<dyn Fn(&Path, bool) -> bool + Send + Sync>;

impl NetWorker {
    fn real() -> Self {
        Self::new(
            std::sync::Arc::new(sine_loco_net::tor::spawn::live_tors),
            std::sync::Arc::new(|dir, enabled| sine_loco_net::tor::spawn::set_network_for(dir, enabled, Duration::from_secs(2)).is_ok()),
            Duration::from_secs(2),
        )
    }
    fn new(live: LiveFn, apply: ApplyFn, period: Duration) -> Self {
        use std::sync::atomic::{AtomicBool, Ordering};
        let desired = std::sync::Arc::new(AtomicBool::new(true));
        let (kick, rx) = std::sync::mpsc::channel::<()>();
        let d = desired.clone();
        std::thread::Builder::new().name("sineloco-net".into()).spawn(move || {
            let mut confirmed: std::collections::HashMap<u32, bool> = std::collections::HashMap::new();
            loop {
                if let Err(std::sync::mpsc::RecvTimeoutError::Disconnected) = rx.recv_timeout(period) { break; }
                let want = d.load(Ordering::SeqCst);
                let tors = live();
                confirmed.retain(|pid, _| tors.iter().any(|(p, _)| p == pid));
                for (pid, dir) in tors {
                    if *confirmed.get(&pid).unwrap_or(&true) != want && apply(&dir, want) { confirmed.insert(pid, want); }
                }
            }
        }).expect("thread");
        Self { desired, kick }
    }
    fn set(&self, up: bool) { self.desired.store(up, std::sync::atomic::Ordering::SeqCst); let _ = self.kick.send(()); }
}

impl Bridge {
    pub fn new(dir: &Path, o: Options) -> Result<Self, String> {
        Self::with_profile(dir, o.tor_path, if o.low_mem { Profile::LowMem } else { Profile::Strong }, o.persist_default, o.platform_keys)
    }

    pub(crate) fn with_profile(dir: &Path, tor_path: Option<PathBuf>, profile: Profile, persist_default: Persist, platform_keys: Option<std::sync::Arc<dyn sine_loco_store::history::PlatformKeys>>) -> Result<Self, String> {
        // `--no-sandbox`: the core's file cleaner re-executes /proc/self/exe, which on Android is app_process, not us. The phone app exposes no file
        // feature, so the cleaner is never called; the isolated-process cleaner (docs/ANDROID_PORT.md 3.3) replaces this before files arrive.
        let _ = startup::startup(&["sine-loco".into(), "--no-sandbox".into()]);
        vault_path::prepare_dir(dir)?;
        let path = dir.join(vault_path::FILE);
        if std::fs::symlink_metadata(&path).is_ok() { vault_path::check_existing(&path)?; }
        let mut cfg = Config::new(Some(path), None, None, profile);
        cfg.tor.tor_path = tor_path.clone();
        let mut tor_base = None;
        if tor_path.is_some() {
            // there is no tmpfs for an app: tor's runtime directory (sockets, its state) lives in the app's private storage, next to the vault directory, and is removed when tor ends
            // (a stale one left by a kill is swept at the next start)
            let base = dir.parent().unwrap_or(dir).join("tor");
            vault_path::prepare_dir(&base)?;
            // nothing of ours can be running yet: whatever an earlier session left (state with guards, consensus times, cookie) goes now, not at the next going-online
            sine_loco_net::tor::spawn::remove_runtime_dirs(&base);
            tor_base = Some(base.clone());
            cfg.tor.runtime_base = Some(base);
            cfg.tor.allow_disk = true;
        }
        cfg.can_host = true;
        cfg.persist_default = persist_default;
        // the real lock of the phone app: erase from memory after 8 hours locked, and after 5 wrong passwords (files stay: this is a panic, not a purge)
        cfg.lock_timeout_secs = Some(8 * 3600);
        cfg.lock_max_attempts = Some(5);
        cfg.platform_keys = platform_keys;
        Ok(Self { app: App::new(cfg), user_offline: false, started: false, retry_at: None, retries: 0, auto_online: tor_path.is_some(), purge: None, tor_base, network_up: true, network_up_at: None, net: NetWorker::real() })
    }

    pub fn app(&self) -> &App { &self.app }

    /// Panic-wipe the core (used when the bridge is re-initialised: a half-finished vault creation must not outlive its replacement).
    pub fn wipe(&mut self) { self.app.panic_wipe(); }

    /// Remove whatever is in the message draft (Backspace in insert mode): a refused send must never leave text that the NEXT send is glued onto.
    fn clear_draft(&mut self) {
        for _ in 0..=COMPOSE_MAX_BYTES { if self.app.compose_text().is_empty() { break; } self.app.handle(Key::Backspace); }
    }

    fn takes_secret(&self) -> bool {
        (!self.app.locked && matches!(self.app.screen, Screen::Unlock | Screen::CreatePw | Screen::CreateConfirm | Screen::Prompt(Prompt::JoinCode(_))))
            || (self.app.lock_auth() && matches!(self.app.screen, Screen::Main))
    }
    fn in_main(&self) -> bool { self.app.screen == Screen::Main && !self.app.locked }

    // the core's modes are hidden from the user: put it into the mode a tap needs (same helpers as the Linux GUI)
    fn ensure_normal(&mut self) { if self.app.screen == Screen::Main && self.app.mode == Mode::Insert { self.app.handle(Key::Esc); } }
    fn ensure_insert(&mut self) { if self.app.screen == Screen::Main && self.app.pane == Pane::Chat && self.app.mode == Mode::Normal { self.app.handle(Key::Char('i')); } }

    /// Poll the core and, like the GUI, connect by itself once the vault is open (only when a tor executable is configured; never after
    /// the user switched offline on purpose; a failed start is retried with a growing delay).
    pub fn tick(&mut self) {
        self.app.lock_deadline_check();
        self.app.poll();
        self.network_tick();
        // a tor that died on its own must show as NOT reachable (the automatic restart below then brings it back)
        let (alive, dead) = sine_loco_net::tor::spawn::spawned_status();
        if dead > 0 && alive == 0 { self.app.tor_died(); }
        // (also while LOCKED: reconnecting needs no password. It is a direct call, never a key press: a key would land in the lock's password prompt)
        // no automatic start or restart while the phone has no network: a tor started into an outage would sit at a few percent, time out after 5 minutes with advice about bridges,
        // be thrown away with its data directory and come back with a fresh set of guards (the retry loop restarts on "network up")
        if !self.auto_online || self.app.screen != Screen::Main || self.user_offline || !self.network_up { return; }
        match &self.app.online {
            Online::Offline if !self.started => { self.started = true; self.app.go_online(); }
            Online::Failed(_) => {
                let due = *self.retry_at.get_or_insert_with(|| Instant::now() + Duration::from_secs((5u64 << self.retries.min(4)).min(60)));
                if Instant::now() >= due { self.retry_at = None; self.retries = self.retries.saturating_add(1); self.app.go_online(); }
            }
            Online::Online => { self.retries = 0; self.retry_at = None; }
            _ => {}
        }
    }

    /// The debounce of "the network is back": after the random wait the desired state becomes UP, and a restart that was waiting for a network starts counting from here.
    fn network_tick(&mut self) {
        if self.network_up_at.is_some_and(|t| Instant::now() >= t) {
            self.network_up_at = None; self.network_up = true;
            self.retries = 0; self.retry_at = None; // the automatic restart (which does not run while the network is down) starts afresh
            self.net.set(true);
        }
    }

    pub fn snapshot(&self, rejected: Option<&str>) -> Zeroizing<String> {
        snapshot(&self.app, &Extra { rejected, purge: self.purge, user_offline: self.user_offline, network_up: self.network_up })
    }

    /// One operation; always answers with the new snapshot. `arg` is zeroizing text for the ops that take any.
    pub fn call(&mut self, op: &str, arg: &Zeroizing<String>) -> Zeroizing<String> {
        // first of all: a locked app whose time is up erases itself before it answers anything (also when this call is a lock request or a snapshot)
        self.app.lock_deadline_check();
        let rejected = self.run(op, arg).err();
        self.tick();
        self.snapshot(rejected)
    }

    fn run(&mut self, op: &str, arg: &Zeroizing<String>) -> Result<(), &'static str> {
        const NOT_NOW: &str = "not possible on this screen";
        match op {
            "snapshot" => {}
            "secret" => {
                if !self.takes_secret() { return Err("this screen takes no password or code"); }
                for c in arg.chars().filter(|c| !c.is_control()) { self.app.handle(Key::Char(c)); }
            }
            "backspace" => { if !self.takes_secret() { return Err(NOT_NOW); } self.app.handle(Key::Backspace); }
            "enter" => {
                if !self.takes_secret() { return Err(NOT_NOW); }
                self.app.handle(Key::Enter);
                // a refused "too short" password stays in the core's buffer: retyping would APPEND to it and silently make a different
                // password. A phone user cannot see the dots to notice, so clear it here (the screen shows the reason).
                if self.app.screen == Screen::CreatePw && self.app.pw.chars() > 0 { self.app.pw.clear(); }
            }
            "select" => {
                if !self.in_main() { return Err(NOT_NOW); }
                let i: usize = arg.trim().parse().map_err(|_| "bad index")?;
                if i >= self.app.contacts_len() { return Err("no such contact"); }
                self.ensure_normal();
                if self.app.pane != Pane::Details { self.app.handle(Key::Esc); }
                for _ in 0..self.app.contacts_len() { if self.app.sel == i { break; } self.app.handle(if self.app.sel < i { Key::Down } else { Key::Up }); }
            }
            "open_chat" => { if !self.in_main() { return Err(NOT_NOW); } self.ensure_normal(); self.app.handle(Key::Enter); self.ensure_insert(); }
            "back" => {
                // only from a chat: in the details pane Esc would raise the privacy screen
                if !self.in_main() || self.app.pane != Pane::Chat { return Err(NOT_NOW); }
                self.ensure_normal(); self.app.handle(Key::Esc);
            }
            "send" => {
                if !self.in_main() || self.app.pane != Pane::Chat { return Err("open a chat first"); }
                if arg.len() > COMPOSE_MAX_BYTES { return Err("message too long"); }
                self.ensure_insert();
                if self.app.mode != Mode::Insert { return Err(NOT_NOW); }
                self.clear_draft(); // a stale draft from an earlier refused send must not be glued onto this one
                for c in arg.chars().filter(|c| !c.is_control()) { self.app.handle(Key::Char(c)); }
                self.app.handle(Key::Enter);
                // the core KEEPS the draft when it refuses (offline with the outbox off, outbox full, vault write failed): the screen has cleared its own field already
                if !self.app.compose_text().is_empty() { self.clear_draft(); return Err("the message was NOT sent: see the status line"); }
            }
            "cmd" => {
                let mut cs = arg.chars();
                let (Some(ch), None) = (cs.next(), cs.next()) else { return Err("one command letter expected") };
                if !COMMANDS.contains(&ch) { return Err("command not available on the phone"); }
                if !self.in_main() { return Err(NOT_NOW); }
                self.ensure_normal(); self.app.handle(Key::Char(ch));
            }
            "new_contact" => {
                // ONE operation for "create a contact": a failed creation (duplicate or invalid name) must not let the next step run against the WRONG selected contact
                if !self.in_main() { return Err(NOT_NOW); }
                if arg.len() > 64 { return Err("name too long"); }
                let before = self.app.contacts_len();
                self.ensure_normal(); self.app.handle(Key::Char('n'));
                if self.app.screen != Screen::Prompt(Prompt::NewContact) { return Err(NOT_NOW); }
                self.app.input = arg.to_string(); self.app.handle(Key::Enter);
                if self.app.contacts_len() == before { return Err("the contact was NOT created: see the status line"); }
            }
            "submit" => {
                // only the two prompts the phone uses (a new contact's name, a pairing link); the join code is a secret and goes through "secret" + "enter"
                if !matches!(&self.app.screen, Screen::Prompt(Prompt::NewContact | Prompt::JoinLink)) || self.app.locked { return Err("no text prompt is open"); }
                if arg.len() > 256 { self.app.handle(Key::Esc); return Err("text too long"); } // and close the prompt: nothing on the screen could do it
                self.app.input = arg.to_string();
                self.app.handle(Key::Enter);
            }
            "cancel" => { if !matches!(self.app.screen, Screen::Prompt(_)) || self.app.locked { return Err("nothing to cancel"); } self.app.handle(Key::Esc); }
            "verify" => {
                if self.app.screen != Screen::Verify { return Err("no verification is open"); }
                self.app.handle(Key::Char(if arg.as_str() == "1" { 'y' } else { 'n' }));
            }
            "in_person" => {
                if !self.in_main() || !self.app.pairing_waiting() { return Err("no pairing is waiting"); }
                self.ensure_normal(); self.app.handle(Key::Char('P'));
                if self.app.screen == Screen::Prompt(Prompt::InPerson) {
                    self.app.input = if arg.as_str() == "1" { "y" } else { "n" }.to_string();
                    self.app.handle(Key::Enter);
                }
            }
            "online" => {
                if !self.in_main() { return Err(NOT_NOW); }
                let want = arg.as_str() == "1";
                let was = self.user_offline;
                self.user_offline = !want; self.started = true;
                let on = matches!(self.app.online, Online::Online | Online::Starting(_));
                if want != on {
                    let moved = if want { self.app.go_online(); matches!(self.app.online, Online::Online | Online::Starting(_)) } else { self.app.go_offline(false) };
                    // the core may ask for a second confirmation first (unconfirmed texts): then NOTHING changed, and the automatic restart must not be told that the user went offline
                    if !moved { self.user_offline = was; }
                }
            }
            // The way out for a user in a hurry (the notification button, the lock screen): NO password and NO question. It is allowed in every state except a wiped app,
            // because going offline only ever reduces exposure. A tor that is still starting is cancelled.
            "offline_now" => {
                if self.app.screen == Screen::Wiped { return Err(NOT_NOW); }
                self.user_offline = true; self.started = true;
                self.app.go_offline(true);
            }
            "hide" => {
                if self.app.screen != Screen::Main { return Err(NOT_NOW); }
                self.ensure_normal();
                for _ in 0..5 { if self.app.locked { break; } self.app.handle(Key::Esc); }
            }
            "unhide" => { if !self.app.locked { return Err(NOT_NOW); } self.app.handle(Key::Enter); }
            "ack_alert" => {
                // `z` is a COMMAND in normal mode but a letter in insert mode and on the password screens: only from the main screen, in normal mode
                if !self.in_main() { return Err(NOT_NOW); }
                self.ensure_normal(); self.app.handle(Key::Char('z'));
            }
            "persist" => {
                if !self.in_main() { return Err(NOT_NOW); }
                let p = match arg.as_str() { "off" => Persist::Off, "outbox" => Persist::Outbox, "day" => Persist::Day, "week" => Persist::Week, _ => return Err("unknown setting") };
                self.app.set_persist(p);
            }
            // The phone's network went away / came back ("down" | "up"). Allowed in every state but Wiped: it only ever REDUCES activity or restores what the user asked for.
            "net" => {
                if self.app.screen == Screen::Wiped { return Err(NOT_NOW); }
                match arg.as_str() {
                    "down" => { self.network_up = false; self.network_up_at = None; self.net.set(false); }
                    "up" => {
                        if !self.network_up && self.network_up_at.is_none() {
                            let mut r = [0u8; 1];
                            let _ = getrandom::fill(&mut r);
                            self.network_up_at = Some(Instant::now() + Duration::from_secs(3 + (r[0] as u64 % 13)));
                        }
                    }
                    _ => return Err("unknown network state"),
                }
            }
            // from EVERY screen: the core closes an open prompt or the safety-number view first, and remembers the request while a derivation runs
            "lock" => { self.ensure_normal(); self.app.lock(); }
            "panic" => { let _ = self.app.handle(Key::F12); }
            "purge" => {
                if self.app.handle(Key::Purge) == Action::Purge {
                    self.app.panic_wipe();
                    self.app.purge_finish();
                    self.purge = self.app.purge_report;
                    if let Some(b) = &self.tor_base { sine_loco_net::tor::spawn::remove_runtime_dirs(b); }
                }
            }
            _ => return Err("unknown operation"),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// The vault directory must not be writable by others; a test directory inherits the umask of whoever runs the tests.
    fn private(dir: &Path) { use std::os::unix::fs::PermissionsExt; std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap(); }
    fn z(s: &str) -> Zeroizing<String> { Zeroizing::new(s.to_string()) }
    fn bridge(dir: &Path) -> Bridge { private(dir); Bridge::with_profile(dir, None, Profile::InsecureTest, Persist::Off, None).unwrap() }
    fn bridge_keep(dir: &Path) -> Bridge { private(dir); Bridge::with_profile(dir, None, Profile::InsecureTest, Persist::Day, None).unwrap() }
    /// Run `op` and wait until the (threaded) key derivation is over.
    fn call(b: &mut Bridge, op: &str, arg: &str) -> String {
        let mut s = b.call(op, &z(arg));
        for _ in 0..12_000 { if !s.contains("\"screen\":\"working\"") { break; } std::thread::sleep(Duration::from_millis(5)); s = b.call("snapshot", &z("")); }
        s.to_string()
    }
    const PW: &str = "correct horse battery staple";
    fn create(b: &mut Bridge) {
        call(b, "secret", PW); call(b, "enter", "");
        call(b, "secret", PW);
        let s = call(b, "enter", "");
        assert!(s.contains("\"screen\":\"main\""), "{s}");
    }

    #[test]
    fn the_lock_hides_everything_takes_the_password_again_and_leaves_the_state_alone() {
        let d = tempfile::tempdir().unwrap();
        let mut b = bridge(d.path());
        create(&mut b);
        call(&mut b, "new_contact", "Mira");
        let s = call(&mut b, "lock", "");
        assert!(s.contains("\"screen\":\"unlock\"") && s.contains("\"locked\":true"), "{s}");
        assert!(!s.contains("Mira"), "no contact name leaves the core while locked: {s}");
        assert!(s.contains("\"contacts\":[]"), "{s}");
        assert!(call(&mut b, "cmd", "d").contains("not possible"), "no command reaches the app under the lock");
        call(&mut b, "secret", "wrong wrong wrong");
        let s = call(&mut b, "enter", "");
        assert!(s.contains("\"locked\":true") && s.contains("Wrong password"), "{s}");
        call(&mut b, "secret", PW);
        let s = call(&mut b, "enter", "");
        assert!(s.contains("\"screen\":\"main\"") && s.contains("\"locked\":false") && s.contains("Mira"), "{s}");
    }

    #[test]
    fn the_lock_works_from_a_prompt_and_the_locked_snapshot_shows_only_the_locks_own_text() {
        let d = tempfile::tempdir().unwrap();
        let mut b = bridge(d.path());
        create(&mut b);
        call(&mut b, "new_contact", "Mira");
        call(&mut b, "cmd", "n"); // a prompt is open now
        assert!(call(&mut b, "snapshot", "").contains("\"screen\":\"prompt\""));
        // things an event could put on the screen
        b.app.alerts.push(("Mira: received file failed its integrity check".into(), 1));
        let s = call(&mut b, "lock", "");
        assert!(s.contains("\"screen\":\"unlock\"") && s.contains("\"locked\":true"), "locked from the prompt: {s}");
        assert!(!s.contains("Mira") && !s.contains("integrity") && s.contains("\"alerts\":[]"), "{s}");
        assert!(s.contains("Locked. Enter the vault password. The app erases itself from memory after 8 h locked."), "{s}");
        assert!(s.contains("\"tor_offer\":null") && s.contains("\"verify_number\":null"), "{s}");
    }

    #[test]
    fn a_lock_requested_during_the_key_derivation_is_applied_when_it_ends() {
        let d = tempfile::tempdir().unwrap();
        { let mut b = bridge(d.path()); create(&mut b); }
        let mut b2 = bridge(d.path());
        call(&mut b2, "secret", PW);
        b2.call("enter", &z(""));
        call(&mut b2, "lock", "");
        let end = std::time::Instant::now() + Duration::from_secs(20);
        let mut s = String::new();
        while std::time::Instant::now() < end { s = call(&mut b2, "snapshot", ""); if s.contains("\"locked\":true") { break; } std::thread::sleep(Duration::from_millis(50)); }
        assert!(s.contains("\"locked\":true") && s.contains("\"screen\":\"unlock\""), "the vault must not end up unlocked in the background: {s}");
    }

    #[test]
    fn reconnecting_under_the_lock_never_types_into_the_password_and_offline_needs_no_password() {
        let d = tempfile::tempdir().unwrap();
        // a tor path that does not exist: the test must never start the host's real tor. The vault directory is INSIDE the temp dir: tor's runtime base is created next to it
        let vault_dir = d.path().join("vault");
        let mut b = Bridge::with_profile(&vault_dir, Some(PathBuf::from("/nonexistent/tor")), Profile::InsecureTest, Persist::Off, None).unwrap();
        create(&mut b);
        b.started = true;
        call(&mut b, "lock", "");
        b.app.online = Online::Failed("test".into());
        b.retry_at = Some(Instant::now() - Duration::from_secs(1));
        let s = call(&mut b, "snapshot", "");
        assert!(s.contains("\"pw_chars\":0"), "no synthetic key reached the password prompt: {s}");
        assert!(!matches!(b.app.online, Online::Failed(_)), "the restart still ran under the lock");
        let s = call(&mut b, "offline_now", "");
        assert!(s.contains("\"user_offline\":true") && s.contains("\"locked\":true"), "{s}");
        assert!(matches!(b.app.online, Online::Offline | Online::Stopping), "offline needs no password");
    }

    #[test]
    fn a_lock_requested_during_the_locks_own_password_check_keeps_the_app_locked() {
        let d = tempfile::tempdir().unwrap();
        let mut b = bridge(d.path());
        create(&mut b);
        call(&mut b, "new_contact", "Mira");
        call(&mut b, "lock", "");
        call(&mut b, "secret", PW);
        b.call("enter", &z(""));                 // the check runs on its thread: the screen is "working"
        let during = call(&mut b, "lock", "");   // the user presses power / home right now
        assert!(during.contains("\"locked\":true") || during.contains("\"screen\":\"working\""), "{during}");
        let end = std::time::Instant::now() + Duration::from_secs(20);
        let mut s = String::new();
        while std::time::Instant::now() < end { s = call(&mut b, "snapshot", ""); if !s.contains("\"screen\":\"working\"") { break; } std::thread::sleep(Duration::from_millis(50)); }
        assert!(s.contains("\"locked\":true") && s.contains("\"screen\":\"unlock\"") && !s.contains("Mira"), "the right password must NOT unlock an app the user already left: {s}");
        // and the password is still good afterwards
        call(&mut b, "secret", PW);
        b.call("enter", &z(""));
        let end = std::time::Instant::now() + Duration::from_secs(20);
        while std::time::Instant::now() < end { s = call(&mut b, "snapshot", ""); if !s.contains("\"screen\":\"working\"") { break; } std::thread::sleep(Duration::from_millis(50)); }
        assert!(s.contains("\"locked\":false") && s.contains("Mira"), "{s}");
    }

    #[test]
    fn the_locked_screen_shows_its_own_error_bit_and_never_the_apps() {
        let d = tempfile::tempdir().unwrap();
        let mut b = bridge(d.path());
        create(&mut b);
        b.app.error = true; b.app.status = "something with Mira".into();
        let s = call(&mut b, "lock", "");
        assert!(s.contains("\"error\":false") && !s.contains("Mira"), "{s}");
        call(&mut b, "secret", "wrong wrong wrong");
        let s = call(&mut b, "enter", "");
        assert!(s.contains("\"error\":true") && s.contains("Wrong password"), "a wrong password must be SHOWN as an error: {s}");
    }

    #[test]
    fn the_network_going_away_is_remembered_and_coming_back_waits_a_random_moment() {
        let d = tempfile::tempdir().unwrap();
        let mut b = bridge(d.path());
        assert!(call(&mut b, "snapshot", "").contains("\"network_up\":true"));
        assert!(call(&mut b, "net", "down").contains("\"network_up\":false"));
        let s = call(&mut b, "net", "up");
        assert!(s.contains("\"network_up\":false") && b.network_up_at.is_some(), "back, but only after a random 3-15 s: {s}");
        let due = b.network_up_at.unwrap().duration_since(Instant::now());
        assert!(due >= Duration::from_secs(2) && due <= Duration::from_secs(16), "{due:?}");
        b.network_up_at = Some(Instant::now() - Duration::from_secs(1));
        assert!(call(&mut b, "snapshot", "").contains("\"network_up\":true"));
        call(&mut b, "net", "down"); call(&mut b, "net", "up");
        call(&mut b, "net", "down");
        assert!(b.network_up_at.is_none() && !b.network_up, "a new down cancels a pending up");
        assert!(call(&mut b, "net", "sideways").contains("unknown network state"));
    }

    #[test]
    fn no_automatic_start_or_restart_runs_while_the_network_is_down_and_the_retry_loop_starts_afresh_when_it_is_back() {
        let d = tempfile::tempdir().unwrap();
        let mut b = Bridge::with_profile(&d.path().join("vault"), Some(PathBuf::from("/nonexistent/tor")), Profile::InsecureTest, Persist::Off, None).unwrap();
        create(&mut b);
        call(&mut b, "net", "down");
        b.started = false; b.app.online = Online::Offline;
        for _ in 0..3 { call(&mut b, "snapshot", ""); }
        assert!(matches!(b.app.online, Online::Offline) && !b.started, "no start into an outage");
        b.app.online = Online::Failed("x".into()); b.retries = 4; b.retry_at = Some(Instant::now() - Duration::from_secs(1));
        call(&mut b, "snapshot", "");
        assert!(matches!(b.app.online, Online::Failed(_)), "no retry into an outage");
        b.network_up_at = Some(Instant::now() - Duration::from_secs(1));
        call(&mut b, "snapshot", "");
        assert!(b.network_up && b.retries <= 1, "the growing delay starts over when the network is back: {}", b.retries);
    }

    #[test]
    fn the_net_worker_retries_until_confirmed_tells_a_new_tor_once_and_never_resends() {
        use std::sync::{atomic::{AtomicUsize, Ordering}, Arc, Mutex};
        let live: Arc<Mutex<Vec<(u32, PathBuf)>>> = Arc::new(Mutex::new(vec![(1, PathBuf::from("/one"))]));
        let calls: Arc<Mutex<Vec<(u32, bool)>>> = Arc::new(Mutex::new(Vec::new()));
        let fail_next = Arc::new(AtomicUsize::new(2)); // the first two attempts fail (a busy tor)
        let (l2, c2, f2) = (live.clone(), calls.clone(), fail_next.clone());
        let w = NetWorker::new(
            Arc::new(move || l2.lock().unwrap().clone()),
            Arc::new(move |dir: &Path, en| {
                let pid = if dir == Path::new("/one") { 1 } else { 2 };
                c2.lock().unwrap().push((pid, en));
                f2.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1)).is_err()
            }),
            Duration::from_millis(20),
        );
        w.set(false);
        std::thread::sleep(Duration::from_millis(400));
        let c = calls.lock().unwrap().clone();
        assert_eq!(c, vec![(1, false), (1, false), (1, false)], "two failures are retried, the third attempt is confirmed, then nothing is re-sent: {c:?}");
        live.lock().unwrap().push((2, PathBuf::from("/two")));        // a tor that started during the outage
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(calls.lock().unwrap().iter().filter(|(p, _)| *p == 2).count(), 1, "told once");
        w.set(true);                                                    // the network is back
        std::thread::sleep(Duration::from_millis(300));
        let c = calls.lock().unwrap().clone();
        assert_eq!(c.iter().filter(|(_, en)| *en).count(), 2, "both tors are told 'up' exactly once: {c:?}");
        live.lock().unwrap().retain(|(p, _)| *p != 1);                  // tor 1 died: forgotten, nothing is sent to it
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(calls.lock().unwrap().len(), c.len());
    }

    #[test]
    fn first_run_creates_a_vault_and_a_second_run_unlocks_it_with_the_contact_still_there() {
        let d = tempfile::tempdir().unwrap();
        let mut b = bridge(d.path());
        assert!(b.snapshot(None).contains("\"screen\":\"create_pw\""));
        create(&mut b);
        call(&mut b, "cmd", "n");
        let s = call(&mut b, "submit", "Mira");
        assert!(s.contains("\"name\":\"Mira\"") && s.contains("\"trust\":\"unverified\"") && s.contains("\"paired\":false"), "{s}");
        drop(b);
        let mut b = bridge(d.path());
        assert!(b.snapshot(None).contains("\"screen\":\"unlock\""));
        call(&mut b, "secret", "wrong password entirely");
        let s = call(&mut b, "enter", "");
        assert!(s.contains("\"screen\":\"unlock\"") && s.contains("\"error\":true"), "{s}");
        call(&mut b, "secret", PW);
        let s = call(&mut b, "enter", "");
        assert!(s.contains("\"screen\":\"main\"") && s.contains("\"name\":\"Mira\""), "persisted: {s}");
    }

    #[test]
    fn short_and_mismatching_passwords_are_refused_with_a_reason() {
        let d = tempfile::tempdir().unwrap();
        let mut b = bridge(d.path());
        call(&mut b, "secret", "short");
        let s = call(&mut b, "enter", "");
        assert!(s.contains("\"screen\":\"create_pw\"") && s.contains("Too short"), "{s}");
        assert!(s.contains("\"pw_chars\":0"), "the refused short password was cleared, retyping must not append to it: {s}");
        call(&mut b, "secret", PW); call(&mut b, "enter", "");
        call(&mut b, "secret", "a different long passphrase");
        let s = call(&mut b, "enter", "");
        assert!(s.contains("\"screen\":\"create_pw\"") && s.contains("did not match"), "{s}");
        assert!(!d.path().join(vault_path::FILE).exists(), "nothing written for a refused password");
    }

    #[test]
    fn the_snapshot_never_contains_a_password_only_how_many_characters_were_typed() {
        let d = tempfile::tempdir().unwrap();
        let mut b = bridge(d.path());
        let s = call(&mut b, "secret", "hunter2-hunter2");
        assert!(s.contains("\"pw_chars\":15") && !s.contains("hunter2"), "{s}");
    }

    #[test]
    fn text_reaches_the_core_only_where_the_core_takes_text() {
        let d = tempfile::tempdir().unwrap();
        let mut b = bridge(d.path());
        create(&mut b);
        // in the main screen a typed letter would be a one-key command (q = quit, o = online ...): every text path refuses
        for (op, arg) in [("secret", "q"), ("enter", ""), ("backspace", ""), ("submit", "x"), ("send", "hi"), ("verify", "1"), ("in_person", "1"), ("back", ""), ("unhide", "")] {
            let s = call(&mut b, op, arg);
            assert!(s.contains("\"rejected\":\""), "{op} must be refused here: {s}");
            assert!(s.contains("\"screen\":\"main\""), "{op} must not change the screen");
        }
        // the command allowlist
        for bad in ["q", "o", "e", "I", "l", "c", "f", "t", "s", "P", "?", "qq", ""] { assert!(call(&mut b, "cmd", bad).contains("\"rejected\":\""), "cmd {bad:?} must be refused"); }
        for good in ["n", "T", "J", "x", "v", "d", "K", "h", "z"] { assert!(call(&mut b, "cmd", good).contains("\"rejected\":null"), "cmd {good:?} must be accepted"); call(&mut b, "cancel", ""); }
        assert!(call(&mut b, "no_such_op", "").contains("\"rejected\":\"unknown operation\""));
    }

    #[test]
    fn a_name_with_quotes_backslashes_and_unicode_survives_the_json() {
        let d = tempfile::tempdir().unwrap();
        let mut b = bridge(d.path());
        create(&mut b);
        call(&mut b, "cmd", "n");
        let s = call(&mut b, "submit", "A \"q\" \\ ü 😀");
        assert!(s.contains(r#""name":"A \"q\" \\ ü 😀""#), "{s}");
    }

    #[test]
    fn panic_wipes_and_purge_deletes_the_vault_files() {
        let d = tempfile::tempdir().unwrap();
        let mut b = bridge(d.path());
        create(&mut b);
        let vault = d.path().join(vault_path::FILE);
        assert!(vault.exists());
        let s = call(&mut b, "panic", "");
        assert!(s.contains("\"screen\":\"wiped\"") && s.contains("\"contacts\":[]") && vault.exists(), "panic keeps the vault: {s}");
        let d2 = tempfile::tempdir().unwrap();
        let mut b2 = bridge(d2.path());
        create(&mut b2);
        let v2 = d2.path().join(vault_path::FILE);
        let s = call(&mut b2, "purge", "");
        assert!(s.contains("\"screen\":\"wiped\"") && s.contains("\"deleted\":") && !s.contains("\"purge\":null"), "{s}");
        assert!(!v2.exists(), "purge removed the vault");
    }

    #[test]
    fn overlong_messages_are_refused_not_truncated() {
        // the compose limit is checked before any key is sent (a chat needs a paired contact, so test the guard order directly)
        let d = tempfile::tempdir().unwrap();
        let mut b = bridge(d.path());
        create(&mut b);
        let s = call(&mut b, "send", &"x".repeat(COMPOSE_MAX_BYTES + 1));
        assert!(s.contains("\"rejected\":\"open a chat first\""), "guard order: chat first, then length: {s}");
    }

    #[test]
    fn going_online_without_a_tor_executable_fails_with_a_message_instead_of_hanging() {
        let d = tempfile::tempdir().unwrap();
        private(d.path());
        let mut b = Bridge::with_profile(&d.path().join("vault"), Some(PathBuf::from("/nonexistent/tor")), Profile::InsecureTest, Persist::Off, None).unwrap();
        create(&mut b);
        // the bridge connects by itself because a tor path was configured: it must end in a visible failure, not a stuck "starting"
        let mut s = String::new();
        for _ in 0..600 { s = call(&mut b, "snapshot", ""); if s.contains("\"online\":\"failed\"") { break; } std::thread::sleep(Duration::from_millis(20)); }
        assert!(s.contains("\"online\":\"failed\"") && s.contains("\"online_error\":\""), "{s}");
    }

    #[test]
    fn what_is_kept_has_a_default_from_the_options_and_the_users_choice_is_stored() {
        let d = tempfile::tempdir().unwrap();
        let mut b = bridge_keep(d.path());
        create(&mut b);
        assert!(b.snapshot(None).contains("\"persist\":\"day\""), "the phone's default is a day until the user chooses");
        let s = call(&mut b, "persist", "off");
        assert!(s.contains("\"persist\":\"off\"") && s.contains("\"rejected\":null"), "{s}");
        drop(b);
        // the same default, a second run: the stored choice wins
        let mut b = bridge_keep(d.path());
        call(&mut b, "secret", PW);
        let s = call(&mut b, "enter", "");
        assert!(s.contains("\"screen\":\"main\"") && s.contains("\"persist\":\"off\""), "the choice survived the restart: {s}");
        for (arg, want) in [("outbox", "outbox"), ("week", "week"), ("day", "day")] {
            let s = call(&mut b, "persist", arg);
            assert!(s.contains(&format!("\"persist\":\"{want}\"")), "{arg}: {s}");
        }
        assert!(call(&mut b, "persist", "forever").contains("\"rejected\":\"unknown setting\""));
    }

    #[test]
    fn the_setting_is_refused_outside_the_main_screen() {
        let d = tempfile::tempdir().unwrap();
        let mut b = bridge(d.path());
        let s = call(&mut b, "persist", "day");
        assert!(s.contains("\"rejected\":\"not possible on this screen\"") && s.contains("\"persist\":\"off\""), "{s}");
    }

    // ---- regressions found by the adversarial review of the bridge (review 30)

    #[test]
    fn acknowledging_an_alert_never_types_a_letter_anywhere() {
        let d = tempfile::tempdir().unwrap();
        let mut b = bridge(d.path());
        let s = call(&mut b, "ack_alert", "");
        assert!(s.contains("\"rejected\":\"not possible on this screen\"") && s.contains("\"pw_chars\":0"), "on the password screen: {s}");
        create(&mut b);
        assert!(call(&mut b, "ack_alert", "").contains("\"rejected\":null"), "from the main screen it is the command it should be");
    }

    #[test]
    fn a_failed_contact_creation_is_reported_and_leaves_no_prompt_behind() {
        let d = tempfile::tempdir().unwrap();
        let mut b = bridge(d.path());
        create(&mut b);
        assert!(call(&mut b, "new_contact", "Bob").contains("\"rejected\":null"));
        let s = call(&mut b, "new_contact", "Bob");
        assert!(s.contains("\"rejected\":\"the contact was NOT created") && s.contains("\"screen\":\"main\""), "duplicate: {s}");
        let s = call(&mut b, "new_contact", &"x".repeat(65));
        assert!(s.contains("name too long") && s.contains("\"screen\":\"main\""), "{s}");
        // the selection did not move to anything but the contact that exists
        assert_eq!(b.app().contacts_len(), 1);
    }

    #[test]
    fn a_too_long_text_closes_its_prompt_and_only_two_prompts_take_text() {
        let d = tempfile::tempdir().unwrap();
        let mut b = bridge(d.path());
        create(&mut b);
        call(&mut b, "cmd", "n");
        let s = call(&mut b, "submit", &"y".repeat(300));
        assert!(s.contains("text too long") && s.contains("\"screen\":\"main\""), "the prompt is closed again: {s}");
        // the delete confirmation is a prompt the phone never uses: text is refused there, cancel works
        call(&mut b, "new_contact", "Zed");
        let s = call(&mut b, "cmd", "d");
        assert!(s.contains("\"prompt\":\"confirm_delete\""), "{s}");
        assert!(call(&mut b, "submit", "y").contains("no text prompt is open"));
        assert!(call(&mut b, "cancel", "").contains("\"screen\":\"main\""));
        assert_eq!(b.app().contacts_len(), 1, "nothing was deleted");
    }

    #[test]
    fn a_refused_send_leaves_no_draft_that_the_next_send_is_glued_onto() {
        // two vaults, a bundle exchanged by file so that A has a paired contact; A is offline with the outbox off: the core refuses and keeps the draft
        let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (mut a, mut b) = (bridge(da.path()), bridge(db.path()));
        create(&mut a); create(&mut b);
        call(&mut a, "new_contact", "bob"); call(&mut b, "new_contact", "alice");
        let fb = db.path().join("b.sbc");
        b.app.handle(Key::Char('e')); b.app.input = fb.to_str().unwrap().into(); b.app.handle(Key::Enter);
        a.app.handle(Key::Char('I')); a.app.input = fb.to_str().unwrap().into(); a.app.handle(Key::Enter);
        call(&mut a, "select", "0");
        let s = call(&mut a, "open_chat", "");
        assert!(s.contains("\"pane\":\"chat\""), "{s}");
        let s = call(&mut a, "send", "hello");
        assert!(s.contains("the message was NOT sent") && s.contains("\"error\":true"), "refused offline: {s}");
        assert!(a.app().compose_text().is_empty(), "no hidden draft is left");
        let s = call(&mut a, "send", "world");
        assert!(s.contains("the message was NOT sent"));
        assert!(a.app().compose_text().is_empty(), "so the next attempt cannot become 'helloworld'");
    }

    #[test]
    fn re_initialising_wipes_the_old_core_first() {
        let d = tempfile::tempdir().unwrap();
        let mut old = bridge(d.path());
        create(&mut old);
        old.wipe();
        assert!(old.snapshot(None).contains("\"screen\":\"wiped\""));
    }
}
