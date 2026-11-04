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
use std::{io::stdout, path::PathBuf, time::Duration};
use zeroize::Zeroizing;

fn usage() -> ! {
    eprintln!("usage: seburity [--vault PATH] [--ram] [--low-mem] [--keyfile PATH] [--counter-file PATH]\n\
  --vault PATH         vault file (default ./seburity.vault). Put it on your USB stick.\n\
  --ram                RAM-only: never write anything to disk\n\
  --low-mem            use the 128 MiB key-derivation profile (low-RAM live systems)\n\
  --keyfile PATH       second factor file (>= 32 bytes), keep it on a SEPARATE device\n\
  --counter-file PATH  rollback counter file (default <vault>.counter; best on the keyfile device)");
    std::process::exit(2)
}

fn parse_args() -> Config {
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

fn main() {
    // Never leave a core dump with secrets: handled at the OS level in a later hardening stage (vault-mem).
    let cfg = parse_args();
    if cfg.path.as_ref().is_some_and(|p| !p.exists()) {
        eprintln!("No vault at {:?}: a NEW one will be created.", cfg.path.as_ref().unwrap());
    }
    let mut app = App::new(cfg);
    let mut term = ratatui::init(); // raw mode + alternate screen + panic hook that restores the terminal
    let result = loop {
        if let Err(e) = term.draw(|f| ui::draw(f, &app)) { break Err(e); }
        app.poll();
        match event::poll(Duration::from_millis(200)) {
            Ok(true) => match event::read() {
                Ok(Event::Key(k)) => if let Some(k) = map_key(k) {
                    match app.handle(k) {
                        Action::None => {}
                        Action::Quit => break Ok(()),
                        Action::Panic => { drop(app); wipe_terminal(); std::process::exit(0); }
                    }
                },
                Ok(_) => {}
                Err(e) => break Err(e),
            },
            Ok(false) => {}
            Err(e) => break Err(e),
        }
    };
    drop(app); // locks: vault and keys zeroized on drop
    wipe_terminal();
    if let Err(e) = result { eprintln!("terminal error: {e}"); std::process::exit(1); }
}
