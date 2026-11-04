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

fn parse_args() -> Config {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.iter().any(|a| a == "--probe-tor") { probe_tor(&raw); }
    let mut path = Some(PathBuf::from("seburity.vault"));
    let (mut counter, mut keyfile, mut profile) = (None, None, Profile::Strong);
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--vault" => path = Some(it.next().unwrap_or_else(|| usage()).into()),
            "--ram" => path = None,
            "--low-mem" => profile = Profile::LowMem,
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
    Config { path, counter, keyfile, profile }
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

fn main() {
    for w in harden() { eprintln!("warning: {w}"); }
    let cfg = parse_args();
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
