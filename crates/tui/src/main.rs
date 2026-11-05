//! seburity: terminal UI. Usage:
//!   seburity [--vault PATH] [--ram] [--low-mem] [--keyfile PATH] [--counter-file PATH]
#![forbid(unsafe_code)]

mod app;
mod secret;
mod ui;

use app::{Action, App, Config, Key};
use ratatui::crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{Clear, ClearType},
};
use seburity_vault::Profile;
use std::{io::stdout, path::PathBuf, sync::{atomic::{AtomicBool, Ordering}, Arc}, time::Duration};
use zeroize::Zeroizing;

fn usage() -> ! {
    eprintln!("usage: seburity [--vault PATH] [--ram] [--low-mem] [--keyfile PATH] [--counter-file PATH]\n\
  --vault PATH         vault file (default ./seburity.vault). Put it on your USB stick.\n\
  --ram                RAM-only: never write anything to disk\n\
  --low-mem            use the 128 MiB key-derivation profile (low-RAM live systems)\n\
  --keyfile PATH       second factor file (>= 32 bytes), keep it on a SEPARATE device\n\
  --counter-file PATH  rollback counter file (default <vault>.counter; best on the keyfile device)\n\
  --tor-path PATH      tor binary to start when going online (default: `tor` from PATH)\n\
  --tor-control ADDR   use an already running tor (127.0.0.1:9051 or unix:/run/tor/control) instead of starting one;\n\
                       with --tor-cookie PATH, --tor-socks ADDR, --tor-trust-control (see docs/TRANSPORT.md)\n\
  --cannot-host        our Tor cannot host onion services (Tails with a restricted control port): bundles you export/pair say so,\n\
                       so the contact hosts for you (check with --probe-tor --probe-onion)\n\
  --allow-swap         start even if swap is active (default: refuse: the OS could write secrets to disk)\n\
  --strip IN OUT       clean one JPEG/PNG offline (add --text for plain text) into a NEW file, then exit (same swap rule, --allow-swap)\n\
  --probe-tor          report what the Tor on this machine allows (Tails/Whonix/system tor), then exit\n\
                       add --probe-onion to also test hosting an onion service; --tor-control ADDR / --tor-cookie PATH to override;\n\
                       --tor-trust-control = you vouch for whoever owns the control port (e.g. a filtered port on Tails)");
    std::process::exit(2)
}

/// `seburity --probe-tor [--probe-onion] [--tor-control ADDR] [--tor-cookie PATH]`: report what the Tor on this
/// machine allows, then exit. Passive unless --probe-onion (creates and removes one throwaway onion service).
fn probe_tor(args: &[String]) -> ! {
    use seburity_net::tor::{control::AuthPref, probe::{probe, Candidates}, Addr};
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

/// `seburity --strip IN OUT [--text]`: clean one file offline (no network, no vault), write to a NEW file (0600), print the report.
fn strip_cmd(args: &[String]) -> ! {
    use std::os::unix::fs::OpenOptionsExt;
    use std::io::Write;
    if args.iter().any(|a| a.starts_with("--") && a != "--text" && a != "--allow-swap") { eprintln!("unknown option for --strip"); usage() }
    let text = args.iter().any(|a| a == "--text");
    let files: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    let [input, output] = files[..] else { usage() };
    // the file contents sit in this process' memory: same swap and core-dump rules as the chat itself
    for w in harden() { eprintln!("warning: {w}"); }
    if !args.iter().any(|a| a == "--allow-swap") { refuse_if_swap(); }
    let raw = match seburity_store::read_regular_file(&PathBuf::from(input), seburity_strip::MAX_INPUT as u64) {
        Ok(v) => Zeroizing::new(v),
        Err(e) => { eprintln!("cannot read {input}: {e}"); std::process::exit(1) }
    };
    let mode = if text { seburity_strip::Mode::PlainText } else { seburity_strip::Mode::Auto };
    let c = match seburity_strip::clean(&raw, mode) { Ok(c) => c, Err(e) => { eprintln!("REFUSED: {e}"); std::process::exit(1) } };
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

fn parse_args() -> Config {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.first().is_some_and(|a| a == "--strip") { strip_cmd(&raw[1..]); }
    if raw.iter().any(|a| a == "--probe-tor") { probe_tor(&raw); }
    let mut path = Some(PathBuf::from("seburity.vault"));
    let (mut counter, mut keyfile, mut profile) = (None, None, Profile::Strong);
    let mut tor = app::TorCfg::default();
    let mut allow_swap = false;
    let mut cannot_host = false;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--vault" => path = Some(it.next().unwrap_or_else(|| usage()).into()),
            "--ram" => path = None,
            "--low-mem" => profile = Profile::LowMem,
            "--allow-swap" => allow_swap = true,
            "--cannot-host" => cannot_host = true,
            "--tor-path" => tor.tor_path = Some(PathBuf::from(it.next().unwrap_or_else(|| usage()))),
            "--tor-control" => match it.next().and_then(|s| seburity_net::tor::Addr::parse(&s)) { Some(a) => tor.control = Some(a), None => { eprintln!("--tor-control needs 127.0.0.1:PORT or unix:/absolute/path"); usage() } },
            "--tor-socks" => match it.next().and_then(|s| seburity_net::tor::Addr::parse(&s)) { Some(a) => tor.socks = Some(a), None => { eprintln!("--tor-socks needs 127.0.0.1:PORT or unix:/absolute/path"); usage() } },
            "--tor-cookie" => tor.cookie = Some(PathBuf::from(it.next().unwrap_or_else(|| usage()))),
            "--tor-trust-control" => tor.trust_control = true,
            "--counter-file" => counter = Some(PathBuf::from(it.next().unwrap_or_else(|| usage()))),
            "--keyfile" => {
                let p = it.next().unwrap_or_else(|| usage());
                match std::fs::read(&p) {
                    Ok(b) => keyfile = Some(Zeroizing::new(b)),
                    Err(e) => { eprintln!("cannot read keyfile {p}: {e}"); std::process::exit(2) }
                }
            }
            _ => usage(),
        }
    }
    let mut cfg = Config::new(path, counter, keyfile, profile);
    cfg.tor = tor;
    cfg.allow_swap = allow_swap;
    cfg.can_host = !cannot_host;
    cfg
}

fn map_key(k: event::KeyEvent) -> Option<Key> {
    if k.kind != KeyEventKind::Press { return None; }
    Some(match k.code {
        KeyCode::F(12) => Key::F12,
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
        _ => return None,
    })
}

/// Clear screen AND scrollback, leave the alternate screen, restore the terminal.
fn wipe_terminal() {
    ratatui::restore();
    let _ = execute!(stdout(), Clear(ClearType::All), Clear(ClearType::Purge), ratatui::crossterm::cursor::MoveTo(0, 0));
}

/// Process hardening that needs no `unsafe`: no core dumps (a dump of the unlocked heap would put
/// keys on disk), and not ptrace/proc-mem readable by same-user processes.
/// Returns human-readable warnings for anything that could not be applied.
fn harden() -> Vec<String> {
    use rustix::process::{setrlimit, Resource, Rlimit};
    let mut w = Vec::new();
    if setrlimit(Resource::Core, Rlimit { current: Some(0), maximum: Some(0) }).is_err() {
        w.push("could not disable core dumps".to_string());
    }
    #[cfg(target_os = "linux")]
    if rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable).is_err() {
        w.push("could not mark the process non-dumpable".to_string());
    }
    w
}

fn panic_exit(app: &mut App, term: &mut ratatui::DefaultTerminal) -> ! {
    app.panic_wipe();
    // Draw the blank Wiped screen twice so BOTH of ratatui's buffers are overwritten.
    for _ in 0..2 { let _ = term.draw(|f| ui::draw(f, app)); }
    let _ = term.clear();
    wipe_terminal();
    std::process::exit(0)
}

/// Active swap devices/files from `/proc/swaps` text (everything after the header line).
fn parse_swaps(text: &str) -> Vec<String> {
    text.lines().skip(1).filter_map(|l| l.split_whitespace().next()).map(str::to_string).collect()
}

/// Refuse to run with swap active: the kernel may write our memory (keys, plaintext) to disk, where it survives power-off.
/// (Without swap there is also no hibernation image.) `None` = unknown (can't read /proc/swaps): treated as OK.
fn swap_problem() -> Option<Vec<String>> {
    let active = parse_swaps(&std::fs::read_to_string("/proc/swaps").ok()?);
    if active.is_empty() { None } else { Some(active) }
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
    for w in harden() { eprintln!("warning: {w}"); }
    let cfg = parse_args();
    if !cfg.allow_swap { refuse_if_swap(); }
    if cfg.path.as_ref().is_some_and(|p| !p.exists()) {
        eprintln!("No vault at {:?}: a NEW one will be created.", cfg.path.as_ref().unwrap());
    }
    // SIGTERM / SIGHUP (terminal closed) / SIGINT trigger the same wipe as the panic key.
    let sig = Arc::new(AtomicBool::new(false));
    for s in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGHUP, signal_hook::consts::SIGINT] {
        let _ = signal_hook::flag::register(s, sig.clone());
    }
    let mut app = App::new(cfg);
    let mut term = ratatui::init(); // raw mode + alternate screen + panic hook that restores the terminal
    let result = loop {
        if sig.load(Ordering::SeqCst) { panic_exit(&mut app, &mut term); }
        if let Err(e) = term.draw(|f| ui::draw(f, &app)) { break Err(e); }
        app.poll();
        match event::poll(Duration::from_millis(200)) {
            Ok(true) => match event::read() {
                Ok(Event::Key(k)) => if let Some(k) = map_key(k) {
                    match app.handle(k) {
                        Action::None => {}
                        Action::Quit => break Ok(()),
                        Action::Panic => panic_exit(&mut app, &mut term),
                    }
                },
                Ok(_) => {}
                Err(e) => break Err(e),
            },
            Ok(false) => {}
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
    fn swaps_are_parsed_from_proc_text() {
        let none = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n";
        assert!(parse_swaps(none).is_empty());
        let some = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n/swapfile                               file\t\t524284\t\t524280\t\t-1\n/dev/zram0                              partition\t1024\t0\t100\n";
        assert_eq!(parse_swaps(some), vec!["/swapfile", "/dev/zram0"]);
        assert!(parse_swaps("").is_empty());
    }
}
