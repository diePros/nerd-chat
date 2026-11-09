//! sine-loco: terminal UI. Usage:
//!   sine-loco [--vault PATH] [--ram] [--low-mem] [--keyfile PATH] [--counter-file PATH]
#![forbid(unsafe_code)]


use sine_loco_app::{app::{self, Action, App, Config, Key}, hardening::{harden, swap_problem}, ui, vault_path};
use ratatui::crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{Clear, ClearType},
};
use sine_loco_vault::Profile;
use std::{io::stdout, path::PathBuf, sync::{atomic::{AtomicBool, Ordering}, Arc}, time::Duration};
use zeroize::Zeroizing;

fn usage() -> ! {
    eprintln!("usage: sine-loco [--version] [--vault PATH] [--ram] [--low-mem] [--keyfile PATH] [--counter-file PATH]\n\
  --vault PATH         vault file. Default: ~/.local/share/sine-loco/sine-loco.vault ($XDG_DATA_HOME), or an existing ./sine-loco.vault.\n\
                       On a USB stick or Tails Persistent Storage pass the path yourself.\n\
  --ram                RAM-only: never write anything to disk\n\
  --low-mem            use the 128 MiB key-derivation profile (low-RAM live systems)\n\
  --keyfile PATH       second factor file (>= 32 bytes), keep it on a SEPARATE device\n\
  --counter-file PATH  rollback counter file (default <vault>.counter; best on the keyfile device)\n\
  --tor-path PATH      tor binary to start when going online (default: `tor` from PATH)\n\
  --tor-control ADDR   use an already running tor (127.0.0.1:9051 or unix:/run/tor/control) instead of starting one;\n\
                       with --tor-cookie PATH, --tor-socks ADDR, --tor-trust-control (see docs/TRANSPORT.md)\n\
  --cannot-host        say cannot-host in the bundles you export/pair (with --tor-control this is probed\n\
                       automatically at export; check by hand with --probe-tor --probe-onion)\n\
  --allow-swap         start even if swap is active (default: refuse: the OS could write secrets to disk)\n  --no-sandbox         clean received/sent files in this process instead of the resource-limited helper process\n\
\
  --strip IN OUT       clean one JPEG/PNG offline (add --text for plain text) into a NEW file, then exit (same swap rule, --allow-swap)\n\
  --probe-tor          report what the Tor on this machine allows (Tails/Whonix/system tor), then exit\n\
                       add --probe-onion to also test hosting an onion service; --tor-control ADDR / --tor-cookie PATH to override;\n\
                       --tor-trust-control = you vouch for whoever owns the control port (e.g. a filtered port on Tails)");
    std::process::exit(2)
}

/// `sine-loco --probe-tor [--probe-onion] [--tor-control ADDR] [--tor-cookie PATH]`: report what the Tor on this
/// machine allows, then exit. Passive unless --probe-onion (creates and removes one throwaway onion service).
fn probe_tor(args: &[String]) -> ! {
    use sine_loco_net::tor::{control::AuthPref, probe::{probe, Candidates}, Addr};
    let (mut onion, mut ctl, mut cookie, mut trust) = (false, None, None, false);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--probe-tor" => {}
            "--probe-onion" => onion = true,
            "--tor-control" => match it.next().and_then(|s| Addr::parse(s)) { Some(a) => ctl = Some(a), None => { eprintln!("--tor-control needs 127.0.0.1:PORT or unix:/absolute/path"); usage() } },
            "--tor-trust-control" => trust = true,
            "--tor-cookie" => cookie = it.next().map(PathBuf::from),
            _ => usage(),
        }
    }
    let mut c = Candidates::standard();
    if let Some(a) = ctl { c.control = vec![a]; }
    for l in probe(&c, onion, &AuthPref { password: None, cookie_path: cookie, peer_verified: false }, trust) { println!("{l}"); }
    std::process::exit(0)
}

/// `sine-loco --strip IN OUT [--text]`: clean one file offline (no network, no vault), write to a NEW file (0600), print the report.
fn strip_cmd(args: &[String]) -> ! {
    use std::os::unix::fs::OpenOptionsExt;
    use std::io::Write;
    if args.iter().any(|a| a.starts_with("--") && a != "--text" && a != "--allow-swap" && a != "--no-sandbox") { eprintln!("unknown option for --strip"); usage() }
    let text = args.iter().any(|a| a == "--text");
    let files: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    let [input, output] = files[..] else { usage() };
    // the file contents sit in this process' memory: same swap and core-dump rules as the chat itself
    for w in harden() { eprintln!("warning: {w}"); }
    if !args.iter().any(|a| a == "--allow-swap") { refuse_if_swap(); }
    let raw = match sine_loco_store::read_regular_file(&PathBuf::from(input), sine_loco_strip::MAX_INPUT as u64) {
        Ok(v) => Zeroizing::new(v),
        Err(e) => { eprintln!("cannot read {input}: {e}"); std::process::exit(1) }
    };
    let mode = if text { sine_loco_strip::Mode::PlainText } else { sine_loco_strip::Mode::Auto };
    let c = match sine_loco_strip::clean_hooked(&raw, mode) { Ok(c) => c, Err(e) => { eprintln!("REFUSED: {e}"); std::process::exit(1) } };
    // create_new first: an EXISTING file is never touched, and only a file WE created is removed on a write error
    let mut f = match std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(output) {
        Ok(f) => f,
        Err(e) => { eprintln!("cannot create {output}: {e}"); std::process::exit(1) }
    };
    if let Err(e) = f.write_all(&c.data).and_then(|_| f.sync_all()) { drop(f); let _ = std::fs::remove_file(output); eprintln!("cannot write {output}: {e}"); std::process::exit(1) }
    println!("wrote {output} ({} -> {} bytes)", raw.len(), c.data.len());
    if c.report.is_empty() { println!("nothing needed removing"); }
    for l in &c.report { println!("removed: {l}"); }
    println!("limits: pixel data, sensor noise and visible content are NOT cleaned (docs/FILE_SHARING.md)");
    std::process::exit(0)
}

/// The vault to use when there is no `--vault`: an existing one (see `vault_path`), or a NEW one at the default place after the user
/// confirmed that place (it is on this computer's disk, and on Tails it would be erased at shutdown).
fn default_vault(allow_swap: bool) -> PathBuf {
    use std::io::IsTerminal;
    let env = |k: &str| std::env::var_os(k).map(PathBuf::from);
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    match vault_path::resolve(env("XDG_DATA_HOME").as_deref(), env("HOME").as_deref(), &cwd, &|p| match std::fs::symlink_metadata(p) { Err(e) => e.kind() != std::io::ErrorKind::NotFound, Ok(_) => true }) {
        vault_path::Choice::Existing { path, note } => {
            if let Err(e) = vault_path::check_existing(&path) { eprintln!("{e}"); std::process::exit(2) }
            if let Some(n) = note { eprintln!("{n}"); }
            path
        }
        vault_path::Choice::Unusable(why) => { eprintln!("{why}"); std::process::exit(2) }
        vault_path::Choice::New { dir, path } => {
            if !allow_swap { refuse_if_swap(); } // before anything is created on disk
            let tails = std::fs::read_to_string("/etc/os-release").is_ok_and(|s| vault_path::is_tails(&s));
            eprintln!("{}", vault_path::confirm_text(&path, tails));
            if !std::io::stdin().is_terminal() { eprintln!("not interactive: pass --vault PATH to say where the new vault goes"); std::process::exit(2) }
            let mut line = String::new();
            if std::io::stdin().read_line(&mut line).is_err() || !line.trim().is_empty() { eprintln!("cancelled: nothing was created"); std::process::exit(2) } // EOF or any text = cancel
            if let Err(e) = vault_path::prepare_dir(&dir) { eprintln!("{e}"); std::process::exit(2) }
            path
        }
    }
}

fn parse_args() -> Config {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.first().is_some_and(|a| a == "--version" || a == "-V") {
        println!("sine-loco {}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0)
    }
    if raw.first().is_some_and(|a| a == "--help" || a == "-h") { usage() }
    if raw.first().is_some_and(|a| a == "--strip") { strip_cmd(&raw[1..]); }
    if raw.iter().any(|a| a == "--probe-tor") { probe_tor(&raw); }
    let (mut path, mut ram) = (None, false);
    let (mut counter, mut keyfile, mut keyfile_path, mut profile) = (None, None, None, Profile::Strong);
    let mut tor = app::TorCfg::default();
    let mut allow_swap = false;
    let mut cannot_host = false;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--vault" => path = Some(it.next().unwrap_or_else(|| usage()).into()),
            "--ram" => ram = true,
            "--low-mem" => profile = Profile::LowMem,
            "--allow-swap" => allow_swap = true,
            "--no-sandbox" => {} // handled at startup: clean files in-process instead of in the limited helper
            "--cannot-host" => cannot_host = true,
            "--tor-path" => tor.tor_path = Some(PathBuf::from(it.next().unwrap_or_else(|| usage()))),
            "--tor-control" => match it.next().and_then(|s| sine_loco_net::tor::Addr::parse(&s)) { Some(a) => tor.control = Some(a), None => { eprintln!("--tor-control needs 127.0.0.1:PORT or unix:/absolute/path"); usage() } },
            "--tor-socks" => match it.next().and_then(|s| sine_loco_net::tor::Addr::parse(&s)) { Some(a) => tor.socks = Some(a), None => { eprintln!("--tor-socks needs 127.0.0.1:PORT or unix:/absolute/path"); usage() } },
            "--tor-cookie" => tor.cookie = Some(PathBuf::from(it.next().unwrap_or_else(|| usage()))),
            "--tor-trust-control" => tor.trust_control = true,
            "--counter-file" => counter = Some(PathBuf::from(it.next().unwrap_or_else(|| usage()))),
            "--keyfile" => {
                let p = it.next().unwrap_or_else(|| usage());
                match std::fs::read(&p) {
                    Ok(b) => { keyfile = Some(Zeroizing::new(b)); keyfile_path = Some(std::fs::canonicalize(&p).unwrap_or_else(|_| PathBuf::from(&p))); } // the real file, not a symlink to it
                    Err(e) => { eprintln!("cannot read keyfile {p}: {e}"); std::process::exit(2) }
                }
            }
            _ => usage(),
        }
    }
    // --ram always wins (it promises that nothing is written); without --vault the default location applies (see vault_path.rs)
    let path = if ram { None } else { Some(path.unwrap_or_else(|| default_vault(allow_swap))) };
    let mut cfg = Config::new(path, counter, keyfile, profile);
    cfg.keyfile_path = keyfile_path;
    cfg.tor = tor;
    cfg.allow_swap = allow_swap;
    cfg.can_host = !cannot_host;
    cfg
}

fn map_key(k: event::KeyEvent) -> Option<Key> {
    if k.kind != KeyEventKind::Press { return None; }
    Some(match k.code {
        KeyCode::F(12) if k.modifiers.contains(KeyModifiers::SHIFT) => Key::Purge,
        KeyCode::F(12) => Key::F12,
        // Ctrl+] is byte 0x1d, right next to Ctrl+\\ (0x1c, panic-lock): works on every terminal; Ctrl+5 sends the same byte
        KeyCode::Char(']') | KeyCode::Char('5') if k.modifiers.contains(KeyModifiers::CONTROL) => Key::Purge,
        KeyCode::Char('\\') if k.modifiers.contains(KeyModifiers::CONTROL) => Key::CtrlBackslash,
        // Ctrl+4 is the same byte as Ctrl+\ on many terminals
        KeyCode::Char('4') if k.modifiers.contains(KeyModifiers::CONTROL) => Key::CtrlBackslash,
        KeyCode::Char(c) if !k.modifiers.contains(KeyModifiers::CONTROL) => Key::Char(c),
        KeyCode::Enter => Key::Enter,
        KeyCode::Esc => Key::Esc,
        KeyCode::Backspace => Key::Backspace,
        KeyCode::Up => Key::Up,
        KeyCode::Down => Key::Down,
        KeyCode::Tab => Key::Tab,
        KeyCode::BackTab => Key::BackTab,
        KeyCode::PageUp => Key::PageUp,
        KeyCode::PageDown => Key::PageDown,
        KeyCode::Home => Key::Home,
        KeyCode::End => Key::End,
        _ => return None,
    })
}

/// Clear screen AND scrollback, leave the alternate screen, restore the terminal.
fn wipe_terminal() {
    let _ = execute!(stdout(), event::DisableBracketedPaste);
    ratatui::restore();
    let _ = execute!(stdout(), Clear(ClearType::All), Clear(ClearType::Purge), ratatui::crossterm::cursor::MoveTo(0, 0));
}

/// Wait up to `timeout` for input on `fd`. `Err(UnexpectedEof)` = the terminal is GONE (window closed, ssh dropped, tmux killed: hangup, error or
/// end-of-file). We look ourselves because crossterm's event reader spins forever inside `event::poll` once its tty returns EOF (observed: a
/// process at 100% CPU for hours that never reaches our SIGHUP check), so it must never be asked to read from a dead terminal.
fn input_ready(fd: impl std::os::fd::AsFd, timeout: Duration) -> std::io::Result<bool> {
    use rustix::event::{poll, PollFd, PollFlags, Timespec};
    let mut fds = [PollFd::new(&fd, PollFlags::IN)];
    let ts = Timespec { tv_sec: timeout.as_secs() as i64, tv_nsec: timeout.subsec_nanos() as i64 };
    match poll(&mut fds, Some(&ts)) {
        Ok(_) => {}
        Err(rustix::io::Errno::INTR) => return Ok(false), // a signal arrived: the loop looks at the flag
        Err(e) => return Err(e.into()),
    }
    let r = fds[0].revents();
    let gone = || std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "the terminal is gone");
    if r.intersects(PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL) { return Err(gone()); }
    if r.contains(PollFlags::IN) {
        // readable with nothing to read = end-of-file
        return if rustix::io::ioctl_fionread(&fd).map_err(std::io::Error::from)? == 0 { Err(gone()) } else { Ok(true) };
    }
    Ok(false)
}

/// Last line of defence: if the terminal is gone and the main loop has not reacted within two seconds (stuck in a library, or busy), the
/// process ends instead of lingering with the vault open in RAM. A dead terminal has no screen left to wipe.
fn spawn_terminal_watchdog(sig: Arc<AtomicBool>) {
    std::thread::spawn(move || loop {
        use rustix::event::{poll, PollFd, PollFlags, Timespec};
        let stdin = std::io::stdin();
        let mut fds = [PollFd::new(&stdin, PollFlags::empty())]; // only hangup / error conditions are reported
        let ts = Timespec { tv_sec: 0, tv_nsec: 500_000_000 };
        if poll(&mut fds, Some(&ts)).is_ok() && !fds[0].revents().is_empty() {
            sig.store(true, Ordering::SeqCst);                 // first ask the main loop for the normal wipe-and-exit ...
            std::thread::sleep(Duration::from_secs(3));
            std::process::exit(1);                             // ... and only force the exit if it is stuck
        }
    });
}

fn panic_exit(app: &mut App, term: &mut ratatui::DefaultTerminal) -> ! {
    app.panic_wipe();
    // Draw the blank Wiped screen twice so BOTH of ratatui's buffers are overwritten.
    for _ in 0..2 { let _ = term.draw(|f| ui::draw(f, app)); }
    let _ = term.clear();
    wipe_terminal();
    app.purge_finish(); // a purge destroys its files only now, with the screen already blank (large files / slow sticks take a while)
    // after the wipe, counts only (a path printed here would stay in the scrollback)
    if let Some((ok, failed)) = app.purge_report { eprintln!("purge: {ok} file(s) overwritten and deleted{}", if failed > 0 { format!(", {failed} could NOT be removed (delete them yourself)") } else { String::new() }); }
    std::process::exit(0)
}

fn refuse_if_swap() {
    if let Some(active) = swap_problem() {
        eprintln!("REFUSING TO START: swap is active ({}).\n\
The operating system may write parts of this program's memory (keys, messages) to that swap space, where it can\n\
survive power-off and be recovered later. Turn swap off first:\n\
    sudo swapoff -a\n\
(on a live system booted from USB there is normally none). To start anyway at your own risk: --allow-swap", active.join(", "));
        std::process::exit(2);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let started = sine_loco_app::startup::startup(&args); // FIRST: cleaner helper dispatch, sandboxed cleaner, hardening
    for w in started.warnings { eprintln!("warning: {w}"); }
    let cfg = parse_args();
    if !cfg.allow_swap { refuse_if_swap(); }
    if cfg.path.as_ref().is_some_and(|p| std::fs::symlink_metadata(p).is_err()) {
        eprintln!("No vault at {:?}: a NEW one will be created.", cfg.path.as_ref().unwrap());
    }
    // SIGTERM / SIGHUP (terminal closed) / SIGINT trigger the same wipe as the panic key.
    let sig = Arc::new(AtomicBool::new(false));
    for s in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGHUP, signal_hook::consts::SIGINT] {
        let _ = signal_hook::flag::register(s, sig.clone());
    }
    let mut app = App::new(cfg);
    spawn_terminal_watchdog(sig.clone());
    let mut term = ratatui::init(); // raw mode + alternate screen + panic hook that restores the terminal
    // pasted text arrives as ONE Paste event (never as keystrokes: a pasted 0x1D must not be a purge key, a pasted Esc no mode switch)
    let _ = execute!(stdout(), event::EnableBracketedPaste);
    let mut backlog = false; // crossterm may hold already-read events that the fd no longer shows: drain them without waiting
    let result = loop {
        if sig.load(Ordering::SeqCst) { panic_exit(&mut app, &mut term); }
        if let Err(e) = term.draw(|f| ui::draw(f, &app)) { break Err(e); }
        app.poll();
        // (waits up to 200 ms; crossterm is only asked once we know the terminal is alive, and then without blocking)
        match input_ready(std::io::stdin(), if backlog { Duration::ZERO } else { Duration::from_millis(200) }).and_then(|_| event::poll(Duration::ZERO)) {
            Ok(true) => { backlog = true; match event::read() {
                Ok(Event::Key(k)) => if let Some(k) = map_key(k) {
                    match app.handle(k) {
                        Action::None => {}
                        Action::Quit => break Ok(()),
                        Action::Panic => panic_exit(&mut app, &mut term),
                        Action::Purge => panic_exit(&mut app, &mut term),
                    }
                },
                Ok(Event::Paste(t)) => app.paste(&t),
                Ok(_) => {}
                Err(e) => break Err(e),
            } },
            Ok(false) => backlog = false,
            Err(e) => break Err(e),
        }
    };
    if result.is_err() { panic_exit(&mut app, &mut term); } // lost terminal: wipe, don't just exit
    app.panic_wipe(); // locks: vault and keys zeroized, workers stopped
    drop(app);
    wipe_terminal();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_vanished_terminal_is_detected_instead_of_being_read_forever() {
        use std::{io::Write, os::unix::net::UnixStream};
        let (mine, mut peer) = UnixStream::pair().unwrap();
        assert!(!input_ready(&mine, Duration::from_millis(30)).unwrap(), "alive and quiet: just no input yet");
        peer.write_all(b"x").unwrap();
        assert!(input_ready(&mine, Duration::from_millis(30)).unwrap(), "a byte is waiting");
        let mut buf = [0u8; 1];
        std::io::Read::read_exact(&mut &mine, &mut buf).unwrap();
        drop(peer);                                                  // the other end hangs up: what a closed terminal looks like
        let e = input_ready(&mine, Duration::from_millis(30)).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof, "{e}");
        // and it stays detected (never reports 'ready' for an endless stream of EOFs)
        for _ in 0..3 { assert!(input_ready(&mine, Duration::from_millis(1)).is_err()); }
    }

    #[test]
    fn panic_lock_and_purge_have_different_keys() {
        use ratatui::crossterm::event::{KeyEvent, KeyEventState};
        let key = |code, mods| map_key(KeyEvent { code, modifiers: mods, kind: KeyEventKind::Press, state: KeyEventState::NONE });
        assert_eq!(key(KeyCode::F(12), KeyModifiers::NONE), Some(Key::F12));
        assert_eq!(key(KeyCode::Char('\\'), KeyModifiers::CONTROL), Some(Key::CtrlBackslash));
        assert_eq!(key(KeyCode::F(12), KeyModifiers::SHIFT), Some(Key::Purge));
        assert_eq!(key(KeyCode::Char(']'), KeyModifiers::CONTROL), Some(Key::Purge));
        assert_eq!(key(KeyCode::Char('5'), KeyModifiers::CONTROL), Some(Key::Purge), "Ctrl+5 is the same byte as Ctrl+] on terminals");
        assert_eq!(key(KeyCode::Char(']'), KeyModifiers::NONE), Some(Key::Char(']')), "a plain ] is just text");
    }

}
