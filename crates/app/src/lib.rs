#![forbid(unsafe_code)]
//! The application core shared by every front end (terminal today, GUI next).
//!
//! `app` is the state machine: vault lifecycle, contacts, pairing, the chat engine glue, files, the hosting probe, panic wipe and
//! purge. A front end drives it with `App::handle(Key)` and renders it from the read-only queries and public state; the terminal
//! binary maps key events, the GUI maps widgets to the very same `Key`s, so the two cannot drift apart. (A command layer on top of
//! the keys is planned, not built.) Nothing in here knows about a terminal or a window; the ratatui renderer in `ui` is an optional
//! feature (`terminal-ui`) that only the terminal binary enables.
//!
//! # Every front end MUST start like this (order matters, all before any secret exists)
//! 1. `startup::startup(&args)` as the FIRST statement of `main`: it dispatches the file-cleaning helper (the helper is this very
//!    binary re-executed with `--clean-worker`; it never returns there), installs the sandboxed cleaner (without it hostile
//!    JPEG/PNG would be parsed inside the process that holds the keys), and applies process hardening (no core dumps, not
//!    ptrace-readable). `App::new` refuses to run if it was not called.
//! 2. Refuse to run with swap active unless the user passed `--allow-swap` (`Startup::swap`, `hardening::swap_problem`).
//! 3. Exit on SIGTERM/SIGHUP/SIGINT through the same wipe as the panic key (`App::panic_wipe`, then `purge_finish`).
//! 4. After a panic/purge: draw nothing, wipe the toolkit's caches, end the process at once.
pub mod app;
pub mod cleaner;
pub mod hardening;
pub mod secret;
pub mod startup;
#[cfg(any(feature = "terminal-ui", test))]
pub mod ui;
pub mod vault_path;
