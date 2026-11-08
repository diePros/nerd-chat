//! The application core shared by every front end (terminal today, GUI next).
//!
//! `app` is the state machine: vault lifecycle, contacts, pairing, the chat engine glue, files, the hosting probe, panic wipe and
//! purge. Front ends drive it with `App::handle(Key)` (the terminal) or the command methods (`App::cmd_*`, the GUI) and render it
//! from the read-only queries. Nothing in here knows about a terminal or a window; the ratatui renderer in `ui` is an optional
//! feature (`terminal-ui`) that only the terminal binary enables.
pub mod app;
pub mod cleaner;
pub mod hardening;
pub mod secret;
#[cfg(any(feature = "terminal-ui", test))]
pub mod ui;
pub mod vault_path;
