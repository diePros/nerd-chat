# Nerd-chat GUI (release 0.2) — design

Status: DRAFT for approval. Nothing of this is built. Decisions made by the project owner are marked **[decided]**; everything else
is a call made by the author of this document, marked **[call]**, and can be overruled.

## 1. Intent
Nerd-chat today is a terminal program. It is built for people at high risk, but only people who are comfortable in a terminal can use
it. The GUI makes the same app usable by regular people. **[decided]** It must be *understandable by instinct*: someone who has used
any chat app should find their way without a manual, and without having to know what Tor, an onion address or a safety number is.

The GUI is a second front end over the same engine. It does not weaken any protection of the terminal version, and it does not replace
it: the terminal version stays fully maintained, because it is the one that runs from any live USB stick with nothing but a terminal.

## 2. Goals, non-goals, anti-goals
**Goals**
1. A regular person can install it, open it from the app menu, create a vault, add a contact and chat, without reading documentation.
2. Adding a contact and being online are the two steps that need the most care (they are where newcomers get stuck). **[decided]**
3. Every protection of the terminal version holds: messages in RAM only, panic wipe, purge, sanitised text only, no clipboard by default,
   no automatic history, no logs, swap refusal, the file-cleaning helper process.
4. Everything a power user can see in the terminal version stays reachable (an "inspector" panel).

**Non-goals (for 0.2)**
- macOS and Windows builds. **[decided: postponed]** Several protections are Linux-only today (seccomp helper, swap refusal via `/proc`, control-port owner check via `/proc/net`, Tor RAM directory); they need honest equivalents first.
- Android, a web view, Tauri or Electron, Bluetooth or Wi-Fi Direct pairing, group chats, voice/video, a cloud or account of any kind.
- Auto-update. Updating is installing a newer package; the vault is not touched.

**Anti-goals (failures even if everything "works")**
- A GUI that is more convenient but leaks more: clipboard use by default, thumbnails or notifications that show message text, window titles with contact names, screenshots/recent-file entries naming the vault, crash dumps with secrets.
- A warning screen that people learn to click away without reading.
- Features that exist in the GUI but not in the shared core (every feature lands in the core first, then in both front ends).

## 3. Decisions by the project owner
| # | Decision |
|---|---|
| D1 | Audience: regular users; "understandable by instinct". |
| D2 | Hardest steps get the most design effort: adding a contact, going online. |
| D3 | Unverified contacts: chatting is allowed; the app warns loudly. Form: **full-screen notice with a good explanation** when the chat is opened (mockup B), not a permanent banner. |
| D4 | If installed from a package, the app appears in the app menu **with its own name**, and there is an **option to hide it**. |
| D5 | Online state: the app **connects by itself** once the vault is unlocked and **reconnects automatically**. A **visible switch** lets the user go offline on purpose. |
| D6 | In the same room (usual case) or far apart (sometimes). Devices are **not** guaranteed to share a network. |
| D7 | Main way to add someone: **pairing over Tor**. Also offered: pairing on the same Wi-Fi (easier when it applies) and the contact file. |
| D8 | Documentation for the contact file must warn against chat platforms such as Discord (written: `docs/EXCHANGING_CONTACTS.md`). |
| D9 | macOS and Windows are postponed; the focus is the GUI. |
| D10 | Larger development steps get reviewed by a model matched to their difficulty (section 9). |
| D11 | Pairing over Tor is built **early**: right after the basic GUI works (phase 3), and the core is shaped for it from phase 1. |
| D12 | Tails (live USB): **tested early, best effort**. Not a release blocker. If the GUI does not run there, the terminal version stays the documented live-USB path and the README says so. |
| D13 | New GUI libraries (egui/eframe, winit, AccessKit and dependencies): **allowed for a throwaway spike first**, in a separate folder; the owner is asked again before they enter the main project. They then follow the project rules (`cargo deny` green, new crates added to the `cargo vet` exemptions like the others). |
| D14 | Secrets in the GUI: acceptance bar **strict everywhere**: no toolkit that keeps copies of typed or shown text that the app cannot wipe. This may rule out screen-reader support and may force a different toolkit. |

## 4. Constraints
- Same security rules as the project: privacy and security first, no `unsafe` outside `crates/sandbox`, reproducible and reviewable code, AGPL-3.0-or-later, vendored/audited dependencies only (`cargo deny` and `cargo vet` stay green; new dependencies are asked for first).
- The GUI binary cannot be the fully static musl binary of today: windowing and GPU access need system libraries. **[call]** It is a dynamically linked binary built against an old glibc so that it runs on current Debian/Ubuntu-based systems and on Tails. The terminal binary stays static.
- A live-USB run on Tails is a target but **unverified**; the first milestone includes a test on real Tails. If the GUI does not run there, the terminal version remains the documented live-USB path and this is stated in the README.
- Messages and secrets exist only in zeroized memory; the GUI toolkit must not keep copies of them (section 7, D14).
- **Honest limit of D14:** any toolkit that draws text puts it in glyph caches, GPU textures and the window system's buffers at some point, so a literal "no copy anywhere" cannot be proven for shown text. The spike therefore measures and the bar is: no copy of typed or shown text that persists after it leaves the screen and that the app has no way to clear (caches are cleared on lock, panic and when a chat closes; the accessibility tree is built only from wiped buffers or switched off). **Stop condition:** if no mainstream toolkit can meet this, work on the GUI stops after the spike and the owner decides (accept a documented residual risk, drop the screen-reader support, or stay terminal-only).

## 5. Architecture
### 5.1 A UI-agnostic core crate (prerequisite)
Move the state machine out of `crates/tui/src/app.rs` (3,300 lines incl. tests) into a new crate `crates/app` (`nerd-chat-app`) with no
terminal and no GUI dependency: screens and modes, vault access, engine events, pairing, the Tor hosting probe, the panic/purge logic.
- **As built (phase 1/2, a deliberate deviation):** input stays the core's existing `Key` interface; the GUI maps widgets to the same `Key`s (and reads the same public state), so there is ONE state machine with ONE set of tests and no new entry points. Passwords, the pairing code and the message draft are therefore held only by the core's zeroizing buffers; the GUI never gives them to the toolkit. A real command layer (`Command::OpenChat(id)`, ...) is optional later work.
- Output is a **view model** (read-only queries like today's `contact_rows`, `chat_lines`, `online_label`, `selected_detail`) plus a list of **notices** (alerts, status).
- All existing `app.rs` tests move with the code and must pass unchanged against the TUI front end before any GUI work starts.
- This step touches panic wipe, purge, the pairing worker and the probe: it is security-critical (reviewed by the strongest model, section 9).

### 5.2 Toolkit **[call]**
A native Rust toolkit in a second binary `nerd-chat-gui`: **egui/eframe** (already a candidate in `docs/ROADMAP.md`). Reasons from reading its source (to be confirmed in the spike): it supports custom text buffers (`TextBuffer`), so the message composer and the password field can use zeroizing storage; clipboard support is a feature that can be left out; accessibility (AccessKit) is available; no web view, no JavaScript, no IPC to a backend. iced is the fallback if the spike shows a blocker (for example text-input copies that cannot be avoided).
A **throwaway spike** comes first (section 8, phase 0), in a separate folder outside the workspace (D13): a window with a zeroizing text field, software rendering on a machine without a GPU, the linked libraries, a start on Tails (D12), and the D14 measurements (what copies of typed and shown text remain, and whether AccessKit has to be off for secret fields).

### 5.3 Pairing over Tor (new protocol, own spec) **[call]**
D7 needs a new way to pair: one device creates a temporary onion service and shows a short code and a link; the other connects over Tor; the code proves the other person (same pairing proof as today's LAN pairing); the contact is created as code-authenticated. Hard parts that need their own design document and the strongest review: how the link and the code combine (the onion address is public, the code is the secret), brute-force limits (one attempt, short expiry), who hosts when one side cannot host (Tails with a restricted control port), what an observer of the link sees, and cleanup of the temporary service. Until it exists the GUI offers only the other two ways; it must not be announced as done.

## 6. What the user sees
### 6.1 Layout **[call]**
Contact list on the left, conversation in the middle, composer at the bottom, a status area with the connection state and the **offline switch** in one fixed place. An **inspector panel** (toggleable) shows what the terminal details view shows and more: safety number and fingerprints, onion address and hosting role, rotation state, per-transfer cleaning reports, per-contact settings (host-anyway, capability), alert history.

### 6.2 First run and unlocking
- First run without a vault: a dialog (replaces the terminal confirmation): where the vault will be (`~/.local/share/nerd-chat/`), that it is on this computer's disk, that backups and sync tools copy it, a Tails warning, and a way to choose another place (USB stick, Persistent Storage). Remembering a chosen place leaves a marker on disk: **[call]** the choice is not remembered, and there is no recent-files list. The app asks again unless the default vault exists; `--vault PATH`, `--ram` and the other terminal options are honoured when the GUI is started from a terminal or from a launcher the user wrote, so a USB-stick user can make their own launcher (the menu entry itself carries no path).
- Password creation and unlocking as today (12+ characters, optional keyfile, low-memory profile for low-RAM live systems, swap refusal with a plain explanation and an explicit override).

### 6.3 Going online **[decided D5]**
After unlocking, Tor starts and connects automatically; the status area shows *Connecting / Online / Trying again* in plain words; a failure to start Tor gets one plain sentence and a details link. A visible switch goes offline on purpose. **[call]** Turning it off asks for confirmation the first time per session because unconfirmed messages are marked "not confirmed" (as in the terminal version). The switch state is for the current session; the next start connects again.

### 6.4 Adding a contact **[decided D6, D7]**
"Add someone" offers three ways, in this order, with the recommended one pre-selected:
1. *Over the internet* (pairing over Tor, section 5.3): shows a short code (to tell in person or by phone) and a link (to send by any channel; useless without the code). Waits with a visible expiry. Available once 5.3 exists.
2. *On the same Wi-Fi*: the existing local pairing (code and local address), shown as one readable string. The app never searches for nearby devices, so nothing on the network shows that it is used. **[call]**
3. *With a file*: save/import the contact file; the screen links to the safe-exchange advice (D8) and says plainly: not Discord, e-mail or social media; hand it over in person if you can.
After a code exchanged in person the contact is *verified*; after a file it stays *unverified*.

### 6.5 Unverified contacts **[decided D3]**
Opening the chat with an unverified contact shows a **full-screen notice**: plain explanation (anyone could be pretending to be this person; check once, in person or by phone, that your two codes match), buttons *Check the code* and *Chat anyway*. After *Chat anyway* the contact list keeps a warning symbol. **[call]** The chat header keeps a small "not verified" label. **[call]** The rule: the notice is shown the first time the chat with a still-unverified contact is opened in each app session (once per contact per session), so it cannot be forgotten and does not nag; opening the same chat again in that session shows only the header label.
The *Check the code* screen shows the safety number big and readable, in groups, with the sentence what to do if the numbers differ.

### 6.6 Everything else
Files: send/receive with the existing cleaning helper and the plain report of what was removed. Key rotation, host-anyway and other advanced items live in the inspector, not on the main screen. **Panic**: a button (and F12 / Ctrl+\ shortcuts as today) that wipes and exits at once; purge behind the inspector with a confirmation. **Privacy screen**: documented as "hides the screen", not a lock, as in the terminal version. Text is always the sanitised text the engine delivers.

### 6.7 Installation and menu **[decided D4]**
The .deb for the GUI installs a menu entry (`.desktop` file) named *Nerd-chat* with its own icon. A setting hides the entry: **[call]** implemented as a per-user override file in `~/.local/share/applications/` with `NoDisplay=true` (that file is itself a trace; the setting says so, and the docs mention the alternative of removing the package's menu file by hand or using the terminal package, which has no menu entry at all). The terminal package stays as it is. Packaging for the GUI is a separate, dynamically linked artifact in `scripts/release.sh`; the static terminal artifacts are unchanged.

## 7. Security rules specific to the GUI
- No clipboard by default (no clipboard feature in the toolkit build); an explicit "copy" is allowed only for the pairing link and the contact file text, with a notice.
- Message text, passwords and the composer use zeroizing buffers; the spike proves the toolkit does not keep copies (undo history, per-frame layout caches, IME buffers). If it cannot, the toolkit decision is revisited.
- No notifications that contain message text or names; no contact names in window titles; no thumbnails or recent-file entries that name the vault.
- Core dumps off, not ptrace-readable, swap refusal and the sandboxed file-cleaning helper (which alone runs under `no_new_privs` and seccomp) as in the terminal version, all through `nerd_chat_app::startup::startup`; the GUI process itself parses no hostile files.
- Screenshots and screen-capture exposure are documented as outside what the app can control.
- The panic path must work while the GUI is busy (probe, pairing, Tor start run on worker threads; the UI thread never blocks on I/O).

## 8. Plan in phases (each ends with tests, a review, a commit)
| Phase | Content | Done when |
|---|---|---|
| 0 | Throwaway spike: egui window, zeroizing text buffer, software rendering, library list, Tails start | go/no-go on the toolkit and on the live-USB claim. **DONE 2026-11-09: GO** (spike report) |
| 1 | Extract `crates/app` (section 5.1); TUI rebuilt on it | all existing tests pass unchanged; static terminal build identical in behaviour. **DONE 2026-11-09** (review 27) |
| 2 | **(first version DONE 2026-11-09)** GUI shell: first-run dialog, create/unlock, contact list, chat, composer, status and offline switch, automatic connect/reconnect | **presentable milestone M1**: a person can unlock, see contacts, chat with one over Tor |
| 3 | **Pairing over Tor (D11)**: own spec first, then protocol, tests, live Tor test, GUI screens | the main way to add contacts works end to end. **DONE 2026-11-09** (reviews 28, 29; live test passes) |
| 4 | Add contact via file and same Wi-Fi; verify screen; unverified notice (D3) | M1 plus all three ways to add someone. **DONE** |
| 5 | Files, inspector, settings, panic/purge, privacy screen | feature parity with the terminal version. **PARTLY DONE**: files, settings, panic; open: key rotation / host-anyway buttons, privacy screen |
| 6 | **(GUI .deb with menu entry and icon DONE in release.sh)** Packaging: dynamic release artifact, .deb with menu entry and icon, hide-entry option, Tails test report, docs | **release candidate** |

M1 (end of phase 2) is the first thing worth showing to people. Phase 1 shapes the core's pairing API for the Tor protocol from the start (D11), so that phase 3 does not have to retrofit it.

## 9. Review plan (D10): model by difficulty
| Step | Why hard | Reviewer |
|---|---|---|
| Phase 1 core extraction | touches panic wipe, purge, pairing, probe; a mistake silently weakens the app | strongest model (Opus), adversarial, plus a second pass with the tests mutated |
| Phase 3 pairing over Tor (spec AND code) | new protocol, new network exposure | strongest model for the spec, again for the code; live Tor tests |
| Phase 0/5 memory handling in the GUI (zeroizing buffers, copies, panic while busy) | secrets in a framework we do not control | strongest model |
| Packaging and menu entry (phase 6) | file permissions, traces on disk, release reproducibility | strong model (Opus) |
| Layout, texts, screens, accessibility (phases 2, 4, 5) | usability, not security | a mid-size model (Sonnet) reads the UI code and the copy for clarity and for leaks of names in titles/notifications; the project owner judges the look |
| Docs, typos, tracker edits | low risk | a small model (Haiku) |
Each review's findings go into `docs/SECURITY_TRACKER.md`; the cycle stays develop → review → fix → commit → static/dynamic build check → live Tor tests.

## 10. Left to the builder
Exact visual design and wording (within the sections above), the widget structure, theming and the icon, keyboard shortcuts, window sizing, how the core's view model is shaped, the file layout of the new crate, test tooling for the GUI, and how the phases split into commits.

## 11. Open points
Answered by the owner (builder check, 2026-11-09): Tor pairing early (D11), Tails best effort (D12), spike dependencies allowed first (D13), strict secret handling with a stop condition (D14).
Still for the owner to approve with this document: the toolkit call (egui, iced as fallback) and the dynamic-binary decision (section 4); that the vault location choice is not remembered (6.2); that the offline switch resets at the next start (6.3); the notice rule in 6.5; the hide option as described in 6.7.
