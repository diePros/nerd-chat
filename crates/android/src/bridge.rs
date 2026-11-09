//! The command layer: what a tap or a typed line means for the core. Every operation is a short string (`"select"`, `"send"`...) so that
//! the JNI surface stays two functions, and every operation is GUARDED: text only reaches the core where the core itself takes text
//! (a typed letter anywhere else would be a one-key command, e.g. `q` or `o`), and only an allowlist of commands can be sent.
use crate::snapshot::{snapshot, Extra};
use nerd_chat_app::{
    app::{Action, App, Config, Key, Mode, Online, Pane, Prompt, Screen},
    startup, vault_path,
};
use nerd_chat_vault::Profile;
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
    pub keep_outbox_default: bool,
}

pub struct Bridge {
    app: App,
    user_offline: bool,
    started: bool,
    retry_at: Option<Instant>,
    retries: u32,
    auto_online: bool,
    purge: Option<(usize, usize)>,
}

impl Bridge {
    pub fn new(dir: &Path, o: Options) -> Result<Self, String> {
        Self::with_profile(dir, o.tor_path, if o.low_mem { Profile::LowMem } else { Profile::Strong }, o.keep_outbox_default)
    }

    pub(crate) fn with_profile(dir: &Path, tor_path: Option<PathBuf>, profile: Profile, keep_outbox_default: bool) -> Result<Self, String> {
        // `--no-sandbox`: the core's file cleaner re-executes /proc/self/exe, which on Android is app_process, not us. The phone app exposes no file
        // feature, so the cleaner is never called; the isolated-process cleaner (docs/ANDROID_PORT.md 3.3) replaces this before files arrive.
        let _ = startup::startup(&["nerd-chat".into(), "--no-sandbox".into()]);
        vault_path::prepare_dir(dir)?;
        let path = dir.join(vault_path::FILE);
        if std::fs::symlink_metadata(&path).is_ok() { vault_path::check_existing(&path)?; }
        let mut cfg = Config::new(Some(path), None, None, profile);
        cfg.tor.tor_path = tor_path.clone();
        cfg.can_host = true;
        cfg.keep_outbox_default = keep_outbox_default;
        Ok(Self { app: App::new(cfg), user_offline: false, started: false, retry_at: None, retries: 0, auto_online: tor_path.is_some(), purge: None })
    }

    pub fn app(&self) -> &App { &self.app }

    fn takes_secret(&self) -> bool {
        !self.app.locked && matches!(self.app.screen, Screen::Unlock | Screen::CreatePw | Screen::CreateConfirm | Screen::Prompt(Prompt::JoinCode(_)))
    }
    fn in_main(&self) -> bool { self.app.screen == Screen::Main && !self.app.locked }

    // the core's modes are hidden from the user: put it into the mode a tap needs (same helpers as the Linux GUI)
    fn ensure_normal(&mut self) { if self.app.screen == Screen::Main && self.app.mode == Mode::Insert { self.app.handle(Key::Esc); } }
    fn ensure_insert(&mut self) { if self.app.screen == Screen::Main && self.app.pane == Pane::Chat && self.app.mode == Mode::Normal { self.app.handle(Key::Char('i')); } }

    /// Poll the core and, like the GUI, connect by itself once the vault is open (only when a tor executable is configured; never after
    /// the user switched offline on purpose; a failed start is retried with a growing delay).
    pub fn tick(&mut self) {
        self.app.poll();
        if !self.auto_online || self.app.screen != Screen::Main || self.user_offline { return; }
        match &self.app.online {
            Online::Offline if !self.started => { self.started = true; self.ensure_normal(); self.app.handle(Key::Char('o')); }
            Online::Failed(_) => {
                let due = *self.retry_at.get_or_insert_with(|| Instant::now() + Duration::from_secs((5u64 << self.retries.min(4)).min(60)));
                if Instant::now() >= due { self.retry_at = None; self.retries = self.retries.saturating_add(1); self.ensure_normal(); self.app.handle(Key::Char('o')); }
            }
            Online::Online => { self.retries = 0; self.retry_at = None; }
            _ => {}
        }
    }

    pub fn snapshot(&self, rejected: Option<&str>) -> Zeroizing<String> {
        snapshot(&self.app, &Extra { rejected, purge: self.purge, user_offline: self.user_offline })
    }

    /// One operation; always answers with the new snapshot. `arg` is zeroizing text for the ops that take any.
    pub fn call(&mut self, op: &str, arg: &Zeroizing<String>) -> Zeroizing<String> {
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
                for c in arg.chars().filter(|c| !c.is_control()) { self.app.handle(Key::Char(c)); }
                self.app.handle(Key::Enter);
            }
            "cmd" => {
                let mut cs = arg.chars();
                let (Some(ch), None) = (cs.next(), cs.next()) else { return Err("one command letter expected") };
                if !COMMANDS.contains(&ch) { return Err("command not available on the phone"); }
                if !self.in_main() { return Err(NOT_NOW); }
                self.ensure_normal(); self.app.handle(Key::Char(ch));
            }
            "submit" => {
                // a non-secret prompt (contact name, pairing link); the join code is a secret and goes through "secret" + "enter"
                if !matches!(&self.app.screen, Screen::Prompt(p) if !matches!(p, Prompt::JoinCode(_) | Prompt::InPerson)) || self.app.locked { return Err("no text prompt is open"); }
                if arg.len() > 256 { return Err("text too long"); }
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
                self.user_offline = !want; self.started = true;
                let on = matches!(self.app.online, Online::Online | Online::Starting(_));
                if want != on { self.ensure_normal(); self.app.handle(Key::Char('o')); }
            }
            "hide" => {
                if self.app.screen != Screen::Main { return Err(NOT_NOW); }
                self.ensure_normal();
                for _ in 0..5 { if self.app.locked { break; } self.app.handle(Key::Esc); }
            }
            "unhide" => { if !self.app.locked { return Err(NOT_NOW); } self.app.handle(Key::Enter); }
            "ack_alert" => { self.app.handle(Key::Char('z')); }
            "keep_outbox" => {
                if !self.in_main() { return Err(NOT_NOW); }
                self.app.set_keep_outbox(arg.as_str() == "1");
            }
            "panic" => { let _ = self.app.handle(Key::F12); }
            "purge" => {
                if self.app.handle(Key::Purge) == Action::Purge {
                    self.app.panic_wipe();
                    self.app.purge_finish();
                    self.purge = self.app.purge_report;
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

    fn z(s: &str) -> Zeroizing<String> { Zeroizing::new(s.to_string()) }
    fn bridge(dir: &Path) -> Bridge { Bridge::with_profile(dir, None, Profile::InsecureTest, false).unwrap() }
    fn bridge_keep(dir: &Path) -> Bridge { Bridge::with_profile(dir, None, Profile::InsecureTest, true).unwrap() }
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
        let mut b = Bridge::with_profile(d.path(), Some(PathBuf::from("/nonexistent/tor")), Profile::InsecureTest, false).unwrap();
        create(&mut b);
        // the bridge connects by itself because a tor path was configured: it must end in a visible failure, not a stuck "starting"
        let mut s = String::new();
        for _ in 0..600 { s = call(&mut b, "snapshot", ""); if s.contains("\"online\":\"failed\"") { break; } std::thread::sleep(Duration::from_millis(20)); }
        assert!(s.contains("\"online\":\"failed\"") && s.contains("\"online_error\":\""), "{s}");
    }

    #[test]
    fn the_encrypted_outbox_default_comes_from_the_options_and_the_users_choice_is_stored() {
        let d = tempfile::tempdir().unwrap();
        let mut b = bridge_keep(d.path());
        create(&mut b);
        assert!(b.snapshot(None).contains("\"keep_outbox\":true"), "the phone's default is on until the user chooses");
        let s = call(&mut b, "keep_outbox", "0");
        assert!(s.contains("\"keep_outbox\":false") && s.contains("\"rejected\":null"), "{s}");
        drop(b);
        // the same default, a second run: the stored choice wins
        let mut b = bridge_keep(d.path());
        call(&mut b, "secret", PW);
        let s = call(&mut b, "enter", "");
        assert!(s.contains("\"screen\":\"main\"") && s.contains("\"keep_outbox\":false"), "the choice survived the restart: {s}");
        let s = call(&mut b, "keep_outbox", "1");
        assert!(s.contains("\"keep_outbox\":true"), "{s}");
    }

    #[test]
    fn the_outbox_switch_is_refused_outside_the_main_screen() {
        let d = tempfile::tempdir().unwrap();
        let mut b = bridge(d.path());
        let s = call(&mut b, "keep_outbox", "1");
        assert!(s.contains("\"rejected\":\"not possible on this screen\"") && s.contains("\"keep_outbox\":false"), "{s}");
    }
}
