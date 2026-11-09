//! Drawing and input mapping. Everything shown is read from the app core (`nerd-chat-app`); everything the user does becomes the same
//! `Key` events the terminal version uses, so the two front ends cannot drift apart.
use eframe::egui::{self, Align2, Color32, Event, RichText, Stroke};
use nerd_chat_app::app::{App, Key, Mode, Online, Pane, Prompt, Screen};
use nerd_chat_core::trust::Trust;

#[cfg(feature = "demo")]
pub mod demo;

const RED: Color32 = Color32::from_rgb(200, 60, 50);
const GREEN: Color32 = Color32::from_rgb(52, 160, 96);
const AMBER: Color32 = Color32::from_rgb(214, 160, 40);
const MUTED: Color32 = Color32::from_gray(140);

pub fn style(ctx: &egui::Context) {
    ctx.set_visuals(egui::Visuals::dark());
    // the clipboard exists ONLY for the pairing link (explicit Copy button, Ctrl+V in the link field): nothing else may be selected and copied
    ctx.global_style_mut(|s| { s.spacing.item_spacing = egui::vec2(8.0, 8.0); s.spacing.button_padding = egui::vec2(12.0, 6.0); s.interaction.selectable_labels = false; });
}

// ---------------------------------------------------------------- commands (what a click means)
pub enum Cmd {
    /// select the contact at this index (and show its details)
    Select(usize),
    OpenChat,
    /// put the open chat's draft in focus
    Insert,
    /// leave the chat view for the contact's details
    BackToDetails,
    /// one of the core's normal-mode commands (n new, e export, I import, l listen, c join, v verify, d delete, z acknowledge ...)
    Command(char),
    Keys(Vec<Key>),
    /// the text of a (non-secret) prompt, then Enter
    Submit(String),
    CancelPrompt,
    SetOnline(bool),
    /// hide the screen (the terminal version's privacy screen): back out of any chat first, then lock
    Hide,
}
#[derive(Default)]
pub struct Cmds { v: Vec<Cmd>, pub panic: bool, pub settings: bool }
impl Cmds { fn push(&mut self, c: Cmd) { self.v.push(c); } pub fn take(&mut self) -> Vec<Cmd> { std::mem::take(&mut self.v) } }

pub fn apply(app: &mut App, c: Cmd, user_offline: &mut bool, started: &mut bool) {
    use crate::shell::Gui;
    match c {
        Cmd::Select(i) => {
            Gui::ensure_normal(app);
            if app.pane != Pane::Details { app.handle(Key::Esc); }
            for _ in 0..app.contacts_len() { if app.sel == i { break; } app.handle(if app.sel < i { Key::Down } else { Key::Up }); }
        }
        Cmd::Insert => Gui::ensure_insert(app),
        Cmd::BackToDetails => { Gui::ensure_normal(app); app.handle(Key::Esc); }
        Cmd::OpenChat => { Gui::ensure_normal(app); app.handle(Key::Enter); Gui::ensure_insert(app); }
        Cmd::Command(ch) => { Gui::ensure_normal(app); app.handle(Key::Char(ch)); }
        Cmd::Keys(ks) => { for k in ks { app.handle(k); } }
        Cmd::Submit(t) => { app.input = t; app.handle(Key::Enter); }
        Cmd::CancelPrompt => { app.handle(Key::Esc); }
        Cmd::Hide => {
            if app.screen != Screen::Main { return; } // a prompt or a pairing question is open: nothing is hidden behind it
            Gui::ensure_normal(app);
            for _ in 0..5 { if app.locked { break; } app.handle(Key::Esc); } // chat / saved view -> details -> privacy screen
        }
        Cmd::SetOnline(want) => {
            *user_offline = !want;
            *started = true;
            let on = matches!(app.online, Online::Online | Online::Starting(_));
            if want != on { Gui::ensure_normal(app); app.handle(Key::Char('o')); }
        }
    }
}

// ---------------------------------------------------------------- input mapping
/// Keys for the core. Text is forwarded ONLY where the core itself takes text (password screens, the hidden pairing-code prompt, the
/// draft of an open chat): in every other state a typed letter would be a one-key command, which a GUI must never trigger by typing.
pub fn notice_pending(app: &App, seen: &std::collections::HashSet<[u8; 8]>) -> bool {
    app.screen == Screen::Main && app.pane == Pane::Chat
        && matches!((app.chat_id(), app.chat_header()), (Some(id), Some((_, Trust::Unverified, _))) if !seen.contains(&id))
}

pub fn collect_input(ctx: &egui::Context, app: &App, block_text: bool) -> (Vec<Key>, Option<String>) {
    let takes_text = !block_text && (matches!(app.screen, Screen::Unlock | Screen::CreatePw | Screen::CreateConfirm | Screen::Prompt(Prompt::JoinCode(_)))
        || (app.screen == Screen::Main && app.pane == Pane::Chat && app.mode == Mode::Insert));
    let mut keys = vec![];
    let pasted: Option<String> = None;
    ctx.input(|i| for e in &i.events {
        match e {
            Event::Text(s) if takes_text => keys.extend(s.chars().filter(|c| !c.is_control()).map(Key::Char)),
            // a clipboard paste never reaches the passwords, the pairing code or the message draft (only the link field takes Ctrl+V, through its own widget)
            Event::Paste(_) => {}
            Event::Key { key, pressed: true, modifiers, .. } => match key {
                egui::Key::F12 if modifiers.shift => keys.push(Key::Purge),
                egui::Key::F12 => keys.push(Key::F12),
                egui::Key::Backslash if modifiers.command => keys.push(Key::CtrlBackslash),
                egui::Key::CloseBracket | egui::Key::Num5 if modifiers.command => keys.push(Key::Purge),
                egui::Key::Backspace if takes_text => keys.push(Key::Backspace),
                egui::Key::Enter if takes_text => keys.push(Key::Enter),
                // Esc closes a popup; in a chat it is ignored (the GUI hides the terminal version's modes)
                egui::Key::Escape if matches!(app.screen, Screen::Prompt(_) | Screen::Verify | Screen::Help) => keys.push(Key::Esc),
                _ => {}
            },
            _ => {}
        }
    });
    (keys, pasted)
}

// ---------------------------------------------------------------- simple shell screens
pub fn refused(ui: &mut egui::Ui, msg: &str) -> bool {
    let mut quit = false;
    egui::CentralPanel::default().show(ui, |ui| {
        ui.vertical_centered(|ui| {
            ui.add_space(80.0);
            ui.heading("Nerd-chat cannot start");
            ui.add_space(12.0);
            ui.add_sized([560.0, 0.0], egui::Label::new(msg).wrap());
            ui.add_space(16.0);
            quit = ui.button("Quit").clicked();
        });
    });
    quit
}

pub enum Choice { None, Continue, Quit }

pub fn first_run_text(path: &std::path::Path, tails: bool) -> String {
    let mut s = format!("Your vault (your contacts and keys, encrypted with your password) will be created here:\n\n{}\n\nThat is on THIS computer's disk. Backups and sync tools that copy your home folder will copy it too, and a restored backup brings back an old vault. To keep it elsewhere (a USB stick, or Persistent Storage on Tails), quit and start the program with --vault PATH.", path.display());
    if tails { s.push_str("\n\nThis looks like Tails: your home folder is ERASED when you shut down, so this vault would be gone after the next restart. Use the Persistent Storage instead (--vault ~/Persistent/nerd-chat.vault)."); }
    s
}

pub fn first_run(ui: &mut egui::Ui, text: &str, tails: bool) -> Choice {
    let mut c = Choice::None;
    egui::CentralPanel::default().show(ui, |ui| {
        ui.vertical_centered(|ui| {
            ui.add_space(60.0);
            ui.heading("Welcome to Nerd-chat");
            ui.add_space(12.0);
            ui.add_sized([620.0, 0.0], egui::Label::new(text).wrap());
            ui.add_space(18.0);
            ui.horizontal(|ui| {
                ui.add_space((ui.available_width() - 300.0).max(0.0) / 2.0);
                if ui.add(egui::Button::new(RichText::new("Create my vault here").strong()).fill(if tails { Color32::from_gray(60) } else { Color32::from_rgb(40, 100, 170) })).clicked() { c = Choice::Continue; }
                if ui.button("Quit").clicked() { c = Choice::Quit; }
            });
        });
    });
    c
}

// ---------------------------------------------------------------- the main drawing
fn trust_info(t: Trust, has_peer: bool) -> (&'static str, Color32) {
    if !has_peer { return ("no key yet", MUTED); }
    match t { Trust::Unverified => ("not verified", RED), Trust::CodeAuthenticated => ("verified in person", AMBER), Trust::SafetyVerified => ("verified", GREEN) }
}

/// a small filled (or hollow) status dot drawn as a shape: the default font has no such glyph
fn dot(ui: &mut egui::Ui, col: Color32, filled: bool) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(12.0, 12.0), egui::Sense::hover());
    if filled { ui.painter().circle_filled(rect.center(), 4.5, col); } else { ui.painter().circle_stroke(rect.center(), 4.5, Stroke::new(1.5, col)); }
}

fn trust_dot(ui: &mut egui::Ui, t: Trust, has_peer: bool) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(14.0, 14.0), egui::Sense::hover());
    let (c, p) = (rect.center(), ui.painter());
    if !has_peer { p.circle_stroke(c, 5.0, Stroke::new(1.5, MUTED)); return; }
    match t {
        Trust::Unverified => { p.circle_stroke(c, 5.5, Stroke::new(2.0, RED)); p.line_segment([c + egui::vec2(0.0, -2.5), c + egui::vec2(0.0, 1.0)], Stroke::new(2.0, RED)); p.circle_filled(c + egui::vec2(0.0, 3.0), 1.0, RED); }
        Trust::CodeAuthenticated => { p.circle_filled(c, 5.5, AMBER); }
        Trust::SafetyVerified => { p.circle_filled(c, 5.5, GREEN); }
    }
}

pub fn draw(ui: &mut egui::Ui, app: &mut App, prompt_text: &mut String, prompt_for: &mut Option<Prompt>, notice_seen: &mut std::collections::HashSet<[u8; 8]>, cmds: &mut Cmds) {
    match &app.screen {
        Screen::Wiped => return,
        Screen::Unlock | Screen::CreatePw | Screen::CreateConfirm | Screen::Working => { secret_screen(ui, app, cmds); return; }
        _ => {}
    }
    if app.locked { lock_screen(ui, cmds); return; }
    if app.screen == Screen::Main && ui.input(|i| i.modifiers.command && i.key_pressed(egui::Key::L)) { cmds.push(Cmd::Hide); }
    // D3: the full-screen "not verified" notice, once per contact per session, before the chat with an unverified contact opens
    if app.screen == Screen::Main && app.pane == Pane::Chat {
        if let (Some(id), Some((name, Trust::Unverified, _))) = (app.chat_id(), app.chat_header()) {
            if !notice_seen.contains(&id) {
                match unverified_notice(ui, name) { NoticeChoice::Check => { notice_seen.insert(id); cmds.push(Cmd::Command('v')); } NoticeChoice::ChatAnyway => { notice_seen.insert(id); } NoticeChoice::Back => { cmds.push(Cmd::BackToDetails); } NoticeChoice::None => {} }
                popups(ui, app, prompt_text, prompt_for, cmds);
                return;
            }
        }
    }
    status_bar(ui, app, cmds);
    egui::Panel::left("contacts").default_size(230.0).min_size(180.0).show(ui, |ui| contacts(ui, app, cmds));
    egui::CentralPanel::default().show(ui, |ui| match app.pane {
        Pane::Chat => chat(ui, app, cmds),
        _ => { egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| details(ui, app, cmds)); }
    });
    popups(ui, app, prompt_text, prompt_for, cmds);
}

fn lock_screen(ui: &mut egui::Ui, cmds: &mut Cmds) {
    egui::CentralPanel::default().show(ui, |ui| ui.vertical_centered(|ui| {
        ui.add_space(120.0);
        ui.heading("Hidden");
        ui.label(RichText::new("The screen is hidden. The vault stays open in memory.").color(MUTED));
        if ui.button("Show again").clicked() || ui.input(|i| i.key_pressed(egui::Key::Enter)) { cmds.push(Cmd::Keys(vec![Key::Enter])); }
    }));
}

fn secret_screen(ui: &mut egui::Ui, app: &App, cmds: &mut Cmds) {
    let (title, label, dots, hint, button) = match app.screen {
        Screen::Unlock => ("Unlock your vault", "Password", app.pw.chars(), "", "Unlock"),
        Screen::CreatePw => ("Create your vault", "Choose a password (a long passphrase: at least 12 characters)", app.pw.chars(), "There is no way to recover a forgotten password.", "Continue"),
        Screen::CreateConfirm => ("Create your vault", "Repeat the password", 0, "", "Create"),
        _ => ("Working", "Deriving the key. This takes a few seconds and is deliberately slow.", 0, "F12 = panic", ""),
    };
    egui::CentralPanel::default().show(ui, |ui| ui.vertical_centered(|ui| {
        ui.add_space(110.0);
        ui.heading(title);
        ui.add_space(8.0);
        ui.label(label);
        let n = if app.screen == Screen::CreateConfirm { app.confirm_chars() } else { dots };
        // the field only draws dots: the password itself exists only in the core's zeroizing buffer
        let (rect, _) = ui.allocate_exact_size(egui::vec2(420.0, 34.0), egui::Sense::hover());
        ui.painter().rect(rect, 6.0, Color32::from_gray(24), Stroke::new(1.0, Color32::from_gray(90)), egui::StrokeKind::Inside);
        ui.painter().text(rect.left_center() + egui::vec2(10.0, 0.0), Align2::LEFT_CENTER, "\u{2022}".repeat(n.min(48)) + "|", egui::FontId::proportional(18.0), Color32::WHITE);
        if !hint.is_empty() { ui.label(RichText::new(hint).color(MUTED)); }
        if !button.is_empty() && ui.button(button).clicked() { cmds.push(Cmd::Keys(vec![Key::Enter])); }
        if !app.status.is_empty() { ui.label(RichText::new(&app.status).color(if app.error { RED } else { MUTED })); }
    }));
}

fn status_bar(ui: &mut egui::Ui, app: &App, cmds: &mut Cmds) {
    egui::Panel::bottom("status").show(ui, |ui| {
        // an open pairing service is public for a while: it must be visible and cancellable from EVERY screen, not only from its own contact
        if let Some(name) = app.tor_offer_name() {
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("Pairing with {name} is open (a public link exists)")).color(Color32::BLACK).background_color(AMBER).strong());
                if ui.button("Cancel pairing").clicked() { cmds.push(Cmd::Command('x')); }
            });
        }
        if let Some((a, n)) = app.alerts.first() {
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("! {a}{}", if *n > 1 { format!(" (x{n})") } else { String::new() })).color(Color32::WHITE).background_color(RED).strong());
                if ui.button("Got it").clicked() { cmds.push(Cmd::Command('z')); }
            });
        }
        if !app.status.is_empty() { ui.add(egui::Label::new(RichText::new(&app.status).color(if app.error { RED } else { MUTED })).wrap()); }
        ui.horizontal(|ui| {
            let (word, col) = match &app.online { Online::Online => ("Online", GREEN), Online::Starting(p) if *p > 0 => ("Connecting\u{2026}", AMBER), Online::Starting(_) => ("Connecting\u{2026}", AMBER), Online::Stopping => ("Going offline\u{2026}", AMBER), Online::Failed(_) => ("Could not connect, trying again", RED), Online::Offline => ("Offline", MUTED) };
            dot(ui, col, true);
            ui.label(RichText::new(word).color(col).strong());
            let mut on = matches!(app.online, Online::Online | Online::Starting(_));
            if ui.checkbox(&mut on, "Connected").changed() { cmds.push(Cmd::SetOnline(on)); }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.add(egui::Button::new(RichText::new("Panic: wipe and exit").color(Color32::WHITE)).fill(Color32::from_rgb(140, 40, 40))).clicked() { cmds.panic = true; }
                if ui.button("Hide screen (Ctrl+L)").on_hover_text("Blanks the window so nobody next to you can read it. The app keeps running. This is NOT a lock: anyone can click Show again.").clicked() { cmds.push(Cmd::Hide); }
            });
        });
    });
}

fn contacts(ui: &mut egui::Ui, app: &App, cmds: &mut Cmds) {
    ui.add_space(4.0);
    ui.heading("Nerd-chat");
    ui.label(RichText::new(if app.is_ram_only() { "RAM only: nothing is saved" } else { "vault open" }).color(MUTED).small());
    ui.separator();
    egui::ScrollArea::vertical().show(ui, |ui| {
        for (i, (name, trust, has_peer, linked, unread)) in app.contact_rows().into_iter().enumerate() {
            let selected = i == app.sel;
            let resp = ui.horizontal(|ui| {
                trust_dot(ui, trust, has_peer);
                let r = ui.selectable_label(selected, RichText::new(name).strong().color(if linked { GREEN } else { Color32::WHITE }));
                if unread > 0 { ui.label(RichText::new(format!(" {unread} "))); }
                r
            }).inner;
            if resp.clicked() { cmds.push(Cmd::Select(i)); if has_peer { cmds.push(Cmd::OpenChat); } }
        }
        if app.contacts_len() == 0 { ui.label(RichText::new("No contacts yet.").color(MUTED)); }
    });
    ui.add_space(6.0);
    if ui.button("+  Add someone").clicked() { cmds.push(Cmd::Command('n')); }
    ui.add_space(4.0);
    if ui.button("Settings").clicked() { cmds.settings = true; }
}

fn details(ui: &mut egui::Ui, app: &App, cmds: &mut Cmds) {
    let Some((name, trust, sn)) = app.selected_detail() else {
        ui.vertical_centered(|ui| { ui.add_space(120.0); ui.heading("Nobody here yet"); ui.label("Press \"Add someone\" to get started."); });
        return;
    };
    ui.heading(name);
    let (word, col) = trust_info(trust, sn.is_some());
    ui.label(RichText::new(word).color(col).strong());
    ui.separator();
    if sn.is_none() {
        ui.label(format!("{name} is not connected to you yet. Pick a way to add them:"));
        ui.add_space(6.0);
        ui.group(|ui| {
            ui.label(RichText::new("Over the internet").strong().color(GREEN));
            ui.label("Works anywhere, in the same room or far apart. One of you creates a link and a code, the other types them in. Both of you need to be online.");
            if let Some(o) = app.tor_offer.as_ref().filter(|o| Some(o.contact) == app.selected_contact_id()) { offer_card(ui, name, o, cmds); } else if app.tor_offer.is_some() { ui.label(RichText::new("Another pairing over the internet is open. Finish or cancel it first (see the bar at the bottom).").color(AMBER)); } else {
                ui.horizontal(|ui| {
                    if ui.add(egui::Button::new(RichText::new("Create a link and code").strong().color(Color32::WHITE)).fill(Color32::from_rgb(40, 100, 170))).clicked() { cmds.push(Cmd::Command('T')); }
                    if ui.button("I have a link").clicked() { cmds.push(Cmd::Command('J')); }
                });
            }
        });
        ui.group(|ui| {
            ui.label(RichText::new("On the same Wi-Fi").strong());
            ui.label("One of you shows a code, the other types it. Nothing goes over the internet.");
            ui.horizontal(|ui| {
                if ui.button("Show a code").clicked() { cmds.push(Cmd::Command('l')); }
                if ui.button("Enter a code").clicked() { cmds.push(Cmd::Command('c')); }
            });
        });
        ui.group(|ui| {
            ui.label(RichText::new("With a file").strong());
            ui.label("Not Discord, e-mail or social media: hand it over in person if you can (see docs/EXCHANGING_CONTACTS.md).");
            ui.horizontal(|ui| {
                if ui.button("Save my contact file").clicked() { cmds.push(Cmd::Command('e')); }
                if ui.button(format!("Open {name}'s file")).clicked() { cmds.push(Cmd::Command('I')); }
            });
        });
    } else {
        if let Some(c) = app.selected_connection() { ui.label(c); }
        if let Some(r) = app.rotation_state() { ui.label(RichText::new(r).color(AMBER)); }
        if let Some(n) = &sn { ui.label("Safety number:"); ui.label(RichText::new(n).monospace().size(18.0)); }
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui.button("Open chat").clicked() { cmds.push(Cmd::OpenChat); }
            if ui.button("Check the code").clicked() { cmds.push(Cmd::Command('v')); }
        });
        advanced(ui, app, cmds);
    }
    ui.add_space(20.0);
    if ui.button(RichText::new("Delete this contact").color(RED)).clicked() { cmds.push(Cmd::Command('d')); }
}

/// The inspector: what the terminal version's details view shows and the expert switches (key rotation, host anyway). Collapsed by default.
fn advanced(ui: &mut egui::Ui, app: &App, cmds: &mut Cmds) {
    let Some(i) = app.inspect() else { return };
    let yes = |b: bool| if b { "yes" } else { "no" };
    ui.add_space(8.0);
    egui::CollapsingHeader::new("Advanced").default_open(cfg!(feature = "demo") && std::env::args().any(|a| a == "--demo-advanced")).show(ui, |ui| {
        egui::Grid::new("inspect").num_columns(2).show(ui, |ui| {
            ui.label("Connected now"); ui.label(yes(i.connected)); ui.end_row();
            ui.label("Their Tor can host"); ui.label(yes(i.contact_can_host)); ui.end_row();
            ui.label("Told them ours can"); ui.label(match i.we_told_can_host { Some(b) => yes(b), None => "not yet" }); ui.end_row();
            ui.label("We host for them now"); ui.label(yes(i.we_host_now)); ui.end_row();
            ui.label("Messages you saved"); ui.label(i.saved.to_string()); ui.end_row();
        });
        if let Some(b) = i.cap_mismatch {
            ui.label(RichText::new(format!("You now run as \"{}\", but this contact was told the opposite when you paired. Its roles follow what it was told.", if b { "can host" } else { "cannot host" })).color(AMBER));
        }
        ui.separator();
        ui.label(RichText::new("New keys").strong());
        ui.label("Creates a new hidden address for this contact. Old copies of your contact file then stop showing when you are online. The contact has to be reachable.");
        if let Some(r) = i.rotation { ui.label(RichText::new(r).color(AMBER)); }
        if ui.add_enabled(i.rotation_possible, egui::Button::new("Switch to new keys")).on_disabled_hover_text("Go online first, and wait for an earlier switch to finish.").clicked() { cmds.push(Cmd::Command('K')); }
        ui.separator();
        ui.label(RichText::new("Host for this contact anyway").strong());
        ui.label("Only if their Tor cannot host but says it can. While on, anyone with their copy of your contact file can see when you are online.");
        let mut on = i.host_anyway;
        if ui.add_enabled(i.host_anyway_possible, egui::Checkbox::new(&mut on, "Host anyway")).on_disabled_hover_text("Your own Tor cannot host, so this is impossible.").changed() { cmds.push(Cmd::Command('h')); }
    });
}

fn chat(ui: &mut egui::Ui, app: &App, cmds: &mut Cmds) {
    if let Some((name, trust, linked)) = app.chat_header() {
        ui.horizontal(|ui| {
            ui.heading(name);
            let (word, col) = trust_info(trust, true);
            ui.label(RichText::new(word).color(col).strong());
            dot(ui, if linked { GREEN } else { MUTED }, linked);
            ui.label(RichText::new(if linked { "connected" } else { "not connected" }).color(if linked { GREEN } else { MUTED }));
        });
        ui.separator();
    }
    if app.screen == Screen::Main && app.mode == Mode::Normal { cmds.push(Cmd::Insert); } // typing always goes to the draft: the GUI has no modes
    egui::Panel::bottom("composer").show(ui, |ui| {
        // files: the same cleaning pipeline as the terminal version (JPEG/PNG metadata stripped, text sanitised, always re-cleaned here)
        if let Some(fs) = app.file_state() {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(if fs.contains("a = accept") { "A file is being offered. Accept it? It is cleaned again here and kept in memory until you save it." } else if fs.contains("s = save") { "A file arrived (cleaned, in memory)." } else { "A file is arriving ..." }).color(AMBER));
                if fs.contains("a = accept") { if ui.button("Accept").clicked() { cmds.push(Cmd::Command('a')); } if ui.button("Decline").clicked() { cmds.push(Cmd::Command('r')); } }
                if fs.contains("s = save") { if ui.button("Save to a file").clicked() { cmds.push(Cmd::Command('s')); } if ui.button("Discard").clicked() { cmds.push(Cmd::Command('r')); } }
            });
        }
        ui.horizontal(|ui| {
            if ui.small_button("Send a photo (JPEG/PNG)").clicked() { cmds.push(Cmd::Command('f')); }
            if ui.small_button("Send a text file").clicked() { cmds.push(Cmd::Command('t')); }
        });
        let (rect, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 38.0), egui::Sense::click());
        ui.painter().rect(rect, 6.0, Color32::from_gray(24), Stroke::new(1.0, Color32::from_gray(90)), egui::StrokeKind::Inside);
        // the draft is drawn from the core's zeroizing buffer (borrowed, never copied into a widget state)
        let draft = app.compose_text();
        let shown = if draft.is_empty() { RichText::new("Write a message \u{2026}").color(MUTED) } else { RichText::new(tail(draft, 90)) };
        ui.painter().text(rect.left_center() + egui::vec2(10.0, 0.0), Align2::LEFT_CENTER, shown.text(), egui::FontId::proportional(16.0), if draft.is_empty() { MUTED } else { Color32::WHITE });
        if resp.clicked() { cmds.push(Cmd::Insert); }
    });
    egui::ScrollArea::vertical().stick_to_bottom(true).auto_shrink([false, false]).show(ui, |ui| {
        for l in app.chat_lines() {
            let (who, col) = if l.mine { ("you", MUTED) } else { ("", Color32::WHITE) };
            let mut note = String::new();
            if l.mine { if l.unsent { note = "  (NOT SENT)".into(); } else if l.unconfirmed { note = "  (not confirmed)".into(); } else if l.queued { note = "  (sending\u{2026})".into(); } }
            ui.horizontal_wrapped(|ui| {
                if !who.is_empty() { ui.label(RichText::new(who).color(MUTED)); }
                ui.label(RichText::new(l.text.as_str()).color(col));
                if !note.is_empty() { ui.label(RichText::new(note).color(AMBER).small()); }
            });
        }
    });
}

/// The last `max` characters of the draft (a long draft shows its tail, as in the terminal version).
fn tail(s: &str, max: usize) -> &str {
    let n = s.chars().count();
    if n <= max { return s; }
    let skip = s.char_indices().nth(n - max).map_or(0, |(b, _)| b);
    &s[skip..]
}

fn popups(ui: &mut egui::Ui, app: &App, text: &mut String, prompt_for: &mut Option<Prompt>, cmds: &mut Cmds) {
    let ctx = ui.ctx().clone();
    let window = |title: &str| egui::Window::new(title.to_string()).collapsible(false).resizable(false).anchor(Align2::CENTER_CENTER, [0.0, 0.0]);
    match &app.screen {
        Screen::Prompt(p) => {
            if prompt_for.as_ref() != Some(p) { *prompt_for = Some(p.clone()); *text = app.input.clone(); }
            let (title, help): (&str, &str) = match p {
                Prompt::NewContact => ("Add someone", "What do you want to call them? (only you see this name)"),
                Prompt::Import => ("Open a contact file", "Path of the contact file you received:"),
                Prompt::Export => ("Save my contact file", "Where to save it (a file name; an existing file is never overwritten). It is NOT public: it shows when you are online."),
                Prompt::Listen => ("Show a code on this Wi-Fi", "Your local address (use your Wi-Fi IP like 192.168.1.5:4000, or 127.0.0.1:0 to try on one machine):"),
                Prompt::JoinAddr => ("Enter a code", "The address the other person sees:"),
                Prompt::JoinLink => ("Add someone over the internet", "Paste the link they sent you (56 letters and numbers, exactly as received):"),
                Prompt::JoinCode(a) if a.starts_with("tor:") => ("Add someone over the internet", "The code they told you by voice (hidden while you type):"),
                Prompt::JoinCode(_) => ("Enter a code", "The code the other person sees (hidden while you type):"),
                Prompt::ConfirmDelete => ("Delete this contact?", "Their keys and saved messages are deleted for good."),
                Prompt::InPerson if app.pair_remote() => ("Did you hear the code by voice?", "Answer yes only if this person told you the code by voice or in person, not as a text message. If yes, the contact counts as verified."),
                Prompt::InPerson => ("Did you exchange the code in person?", "If yes, the contact counts as verified."),
                Prompt::SendFile => ("Send a file", "Path of the file:"),
                Prompt::SendText => ("Send a text", "Text:"),
                Prompt::SaveFile => ("Save the received file", "Where to save it:"),
            };
            window(title).show(&ctx, |ui| {
                ui.set_min_width(420.0);
                ui.label(help);
                match p {
                    Prompt::ConfirmDelete => { ui.horizontal(|ui| {
                        if ui.add(egui::Button::new(RichText::new("Delete").color(Color32::WHITE)).fill(Color32::from_rgb(140, 40, 40))).clicked() { cmds.push(Cmd::Submit("yes".into())); }
                        if ui.button("Cancel").clicked() { cmds.push(Cmd::CancelPrompt); } }); }
                    Prompt::InPerson => { ui.horizontal(|ui| {
                        if ui.button(if app.pair_remote() { "Yes, I heard it by voice" } else { "Yes, in person" }).clicked() { cmds.push(Cmd::Keys(vec![Key::Char('y')])); }
                        if ui.button("No").clicked() { cmds.push(Cmd::Keys(vec![Key::Char('n')])); } }); }
                    Prompt::JoinCode(_) => {
                        let dots = "\u{2022}".repeat(app.code_chars().min(40));
                        ui.label(RichText::new(dots + "|").size(20.0));
                        ui.horizontal(|ui| { if ui.button("OK").clicked() { cmds.push(Cmd::Keys(vec![Key::Enter])); } if ui.button("Cancel").clicked() { cmds.push(Cmd::CancelPrompt); } });
                    }
                    _ => {
                        let r = ui.add(egui::TextEdit::singleline(text).desired_width(400.0));
                        if !r.has_focus() && !r.lost_focus() { r.request_focus(); }
                        let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        ui.horizontal(|ui| {
                            if ui.button("OK").clicked() || enter { cmds.push(Cmd::Submit(std::mem::take(text))); *prompt_for = None; }
                            if ui.button("Cancel").clicked() { cmds.push(Cmd::CancelPrompt); *prompt_for = None; }
                        });
                    }
                }
            });
        }
        Screen::Verify => {
            *prompt_for = None;
            window("Check the code").show(&ctx, |ui| {
                ui.set_min_width(460.0);
                ui.label("Call the person or meet them and read this number to each other. It must be exactly the same on both screens.");
                ui.label(RichText::new(app.view_number().unwrap_or("")).monospace().size(22.0).strong());
                ui.label(RichText::new("If it differs, stop: someone changed the contact file on the way. Delete the contact and start again.").color(RED));
                ui.horizontal(|ui| {
                    if ui.add(egui::Button::new(RichText::new("They match").color(Color32::WHITE)).fill(Color32::from_rgb(40, 110, 70))).clicked() { cmds.push(Cmd::Keys(vec![Key::Char('y')])); }
                    if ui.button("They do not match").clicked() { cmds.push(Cmd::Keys(vec![Key::Esc])); }
                });
            });
        }
        _ => { *prompt_for = None; }
    }
}

enum NoticeChoice { None, Check, ChatAnyway, Back }

/// The full-screen notice for a contact whose identity was never checked (design D3): plain words, one clear action, an honest way to go on.
fn unverified_notice(ui: &mut egui::Ui, name: &str) -> NoticeChoice {
    let mut c = NoticeChoice::None;
    egui::CentralPanel::default().show(ui, |ui| {
        ui.vertical_centered(|ui| {
            ui.add_space(70.0);
            egui::Frame::new().stroke(Stroke::new(2.0, RED)).corner_radius(10.0).inner_margin(24.0).show(ui, |ui| {
                ui.set_max_width(560.0);
                ui.label(RichText::new(format!("Before you chat with {name}")).size(24.0).strong().color(RED));
                ui.add_space(10.0);
                ui.label(RichText::new(format!("You have not checked yet that this really is {name}.")).size(17.0).strong());
                ui.add_space(6.0);
                ui.label(format!("When you added {name}, nothing proved who is on the other end. Someone could have swapped the contact file on its way and be pretending to be {name}. You can still chat, but whatever you write could then be read by that someone."));
                ui.add_space(6.0);
                ui.label(format!("Checking takes a minute: call {name} or meet them and read your two codes to each other. If they are exactly the same, nobody is in between. You only need to do this once per person."));
                ui.add_space(14.0);
                ui.horizontal(|ui| {
                    if ui.add(egui::Button::new(RichText::new("Check the code").strong().color(Color32::WHITE)).fill(Color32::from_rgb(40, 100, 170))).clicked() { c = NoticeChoice::Check; }
                    if ui.button("Chat anyway").clicked() { c = NoticeChoice::ChatAnyway; }
                    if ui.button("Back").clicked() { c = NoticeChoice::Back; }
                });
            });
        });
    });
    c
}

/// The open offer over Tor: the link goes to ONE person over any channel, the code only by voice. (No clipboard: the link is shown in groups to read or retype.)
fn offer_card(ui: &mut egui::Ui, name: &str, o: &nerd_chat_app::app::TorLink, cmds: &mut Cmds) {
    ui.add_space(6.0);
    ui.label(RichText::new(format!("1. Send this link to {name} only (any way you like, but not to a group):")).strong());
    let l: &str = &o.link;
    let grouped: Vec<&str> = (0..l.len()).step_by(14).map(|i| &l[i..(i + 14).min(l.len())]).collect();
    ui.label(RichText::new(grouped.join(" ")).monospace().size(15.0));
    if ui.button("Copy link").on_hover_text("Puts the link on the system clipboard (clipboard managers may keep it). Only the link is ever copied.").clicked() { ui.ctx().copy_text(l.to_string()); }
    ui.label(RichText::new(format!("2. Tell {name} this code by voice or in person, NOT in the same message:")).strong());
    ui.label(RichText::new(o.code.as_str()).monospace().size(28.0).strong().color(AMBER));
    let left = o.expires.saturating_duration_since(std::time::Instant::now()).as_secs();
    ui.label(RichText::new(format!("Works once, for {} more minutes. Anyone holding the link could see that you are online, so keep it private.", left / 60 + 1)).color(MUTED));
    if ui.button("Cancel").clicked() { cmds.push(Cmd::Command('x')); }
}

/// Settings window: the application-menu entry, and what the program does and does not protect (plain words).
/// Returns true when the user confirmed a PURGE.
pub fn settings(ctx: &egui::Context, app: &mut App, open: &mut bool, hidden: &mut bool, entry: Option<&std::path::Path>, note: &mut String, purge_ok: &mut bool) -> bool {
    let mut purge = false;
    egui::Window::new("Settings").collapsible(false).resizable(false).anchor(Align2::CENTER_CENTER, [0.0, 0.0]).show(ctx, |ui| {
        ui.set_min_width(460.0);
        ui.label(RichText::new("Application menu").strong());
        match entry {
            Some(p) => {
                let mut h = *hidden;
                if ui.checkbox(&mut h, "Hide Nerd-chat from the application menu").changed() {
                    match crate::menu::set_hidden(p, h) { Ok(()) => { *hidden = h; note.clear(); } Err(e) => *note = e }
                }
                ui.label(RichText::new("Hiding writes a small file in your user folder (it shows that the program is installed); showing it again removes the file. The program still starts with the command nerd-chat-gui.").color(MUTED).small());
            }
            None => { ui.label(RichText::new("No home folder found: the menu entry cannot be changed.").color(MUTED)); }
        }
        if !note.is_empty() { ui.label(RichText::new(note.as_str()).color(RED)); }
        ui.separator();
        ui.label(RichText::new("Warnings in this session").strong());
        if app.alert_history().is_empty() { ui.label(RichText::new("None.").color(MUTED)); }
        egui::ScrollArea::vertical().max_height(120.0).show(ui, |ui| for (t, n) in app.alert_history().iter().rev() {
            ui.label(RichText::new(format!("{t}{}", if *n > 1 { format!(" (x{n})") } else { String::new() })).small());
        });
        ui.label(RichText::new("Kept in memory only, until you close the app or press panic.").color(MUTED).small());
        ui.separator();
        ui.label(RichText::new("Messages on this computer").strong());
        let mut p = app.persist();
        let before = p;
        ui.radio_value(&mut p, nerd_chat_app::app::Persist::Off, "Keep nothing (messages exist only in memory)");
        ui.radio_value(&mut p, nerd_chat_app::app::Persist::Outbox, "Keep only unsent messages until they arrive");
        ui.radio_value(&mut p, nerd_chat_app::app::Persist::Day, "Keep all messages for about a day");
        ui.radio_value(&mut p, nerd_chat_app::app::Persist::Week, "Keep all messages for about a week");
        if p != before { app.set_persist(p); }
        ui.label(RichText::new("Kept messages are encrypted in a separate file next to your vault and only written every few seconds. Anyone with this computer and your password can read what is kept; a deleted message may survive in the disk's storage (an overwrite does not reach copy-on-write file systems or an SSD's spare blocks). Texts never carry a timestamp.").color(MUTED).small());
        ui.separator();
        ui.label(RichText::new("Purge").strong().color(RED));
        ui.label(RichText::new("Like panic, and in addition every file this session made (your vault, saved contact files, saved received files) is overwritten and deleted. This cannot be undone.").color(MUTED).small());
        ui.checkbox(purge_ok, "I understand: my vault and these files will be destroyed");
        if ui.add_enabled(*purge_ok, egui::Button::new(RichText::new("Purge everything and exit").color(Color32::WHITE)).fill(Color32::from_rgb(140, 40, 40))).clicked() { purge = true; }
        ui.separator();
        ui.label(RichText::new("About").strong());
        ui.label(format!("Nerd-chat {}. Unaudited software: read SECURITY.md before you rely on it.", env!("CARGO_PKG_VERSION")));
        ui.label(RichText::new("Messages exist only in memory unless you keep unsent ones in the encrypted outbox. There is no screen-reader support on purpose: a screen reader would receive a copy of every message. The panic button wipes everything and exits.").color(MUTED).small());
        ui.add_space(8.0);
        if ui.button("Close").clicked() { *open = false; *purge_ok = false; }
    });
    purge
}
