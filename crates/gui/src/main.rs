//! sine-loco-gui: the graphical front end (docs/superpowers/specs/2026-11-09-gui-design.md, phase 2).
//!
//! A SECOND SKIN over the same state machine as the terminal version (`sine-loco-app`). The rules that matter:
//!  * Passwords, the pairing code and the message draft are NEVER held by the toolkit: typed characters are forwarded to the app
//!    core's zeroizing buffers (`App::handle(Key::Char)`), and the screen only shows how many there are (dots) or a borrowed `&str`
//!    of the draft. There is no egui `TextEdit` for a secret or a message.
//!  * Panic (F12, Ctrl+\) and purge (Ctrl+]) are forwarded on every screen, exactly like the terminal version, and the process exits.
//!  * Process hardening, the swap refusal and the sandboxed file-cleaning helper are set up before any secret exists.
//!  * No AccessKit (a screen reader would get a copy of every message), no notifications; the clipboard is used ONLY for the pairing link
//!    (explicit Copy button, Ctrl+V in the link field): paste events never reach a secret and labels are not selectable.
mod menu;
mod shell;
mod view;

fn main() -> eframe::Result {
    shell::run()
}
