# Roadmap (ideas, NOT scheduled: the terminal UI is the supported front end today)

## Release plan (decision, 0.1.0 era)
- **0.1.x:** the terminal UI only; audit findings, the Tails result and hardening. The TUI stays a first-class, fully maintained front end
  in every later release (it is the one that runs from a live USB with nothing but a terminal).
- **0.2 / next major:** the GUI, built only after the UI-agnostic core is extracted (below) and after the first audit, so that the audited
  security-critical code is not rewritten while it is being audited. Every feature lands in the core first and then in BOTH front ends.
- **Toolkit recommendation:** a native Rust toolkit (egui/eframe or iced) in a second binary `nerd-chat-gui`: still one static-ish executable, no web
  view, no JavaScript, no IPC to a separate backend. Tauri/Electron are rejected for the memory-wiping and attack-surface reasons below.

## Real GUI (future)
Goal: usability for people who do not live in a terminal, without hiding anything from the people who do.
- **Layout:** the familiar chat-platform layout, kept minimal: contact list on the left, conversation in the middle, composer at the bottom.
- **Inspector ("nerd panel"):** a toggleable side panel that shows everything the TUI details view shows and more: safety number and key
  fingerprints, onion address and hosting role, Tor/connection state, key-rotation state, per-transfer file-cleaning reports, per-contact
  settings (host-anyway, capability), raw status/alert history.
- **Same invariants as the TUI:** messages in RAM only, a panic key that wipes and exits, only sanitised text rendered, no clipboard by default,
  no per-frame copies of secrets, the privacy screen is documented as "hides the screen", not as a lock.
- **Toolkit:** open decision. Prefer a native Rust toolkit; avoid embedding a web view (large attack surface, hard to reason about memory wiping).
- **Prerequisite:** extract the UI-agnostic state machine out of `crates/tui/src/app.rs` (screens/modes, key handling as commands, events from
  the engine, vault access) into its own crate, so the TUI and a GUI are two front ends over the same tested core. `App::handle(Key)` is already
  shaped like that; the work is mostly moving code and separating `Key` from rendering concerns.

## Android app (end goal, far away)
Only after the GUI exists. Known constraints to solve first, nothing built:
- aarch64-linux-android build of all crates (pure Rust except Tor), embedded Tor (a cross-built `tor`, or Arti once its onion-service side is mature),
- the cleaning helper's seccomp filter needs an Android variant (different syscall numbers for aarch64, app sandbox/SELinux rules),
- an online-only P2P app needs a foreground service on Android (background execution limits), battery and Tor-circuit trade-offs,
- no swap/`mlock` story comparable to a live Linux; panic wipe semantics differ (process death vs RAM remanence),
- distribution outside the big app stores (F-Droid style, reproducible builds, signed releases).

## Smaller UI ideas (after the overhaul)
Idle auto-lock for the privacy screen, an optional password-protected privacy screen, per-contact drafts, in-line cursor editing of the draft,
search in the conversation.
