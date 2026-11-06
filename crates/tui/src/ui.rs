//! Rendering only. Reads `App`, never mutates it. Passwords are shown as dots only.
use crate::app::{App, Mode, Pane, Prompt, Screen};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Clear, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};
use nerd_chat_core::trust::Trust;

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect { x: area.x + (area.width - w) / 2, y: area.y + (area.height - h) / 2, width: w, height: h }
}

fn trust_label(t: Trust, has_peer: bool) -> (&'static str, Color) {
    if !has_peer { return ("○ no peer key", Color::DarkGray); }
    match t {
        Trust::Unverified => ("◔ UNVERIFIED", Color::Red),
        Trust::CodeAuthenticated => ("◑ code-authenticated", Color::Yellow),
        Trust::SafetyVerified => ("● verified", Color::Green),
    }
}

pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();
    if app.screen == Screen::Wiped { f.render_widget(Clear, area); return; }
    // Privacy screen: ONLY this is drawn (the app underneath is not rendered at all, so no name or message stays in the terminal buffer).
    if app.locked { lock_view(f, area, app); return; }
    let rows = Layout::default().direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(3), Constraint::Length(if app.alerts.is_empty() { 2 } else { 3 }), Constraint::Length(1)]).split(area);
    let mode = if app.is_ram_only() { "RAM-ONLY" } else { "vault" };
    f.render_widget(Paragraph::new(Line::from(vec![
        Span::styled(" NERD-CHAT ", Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)),
        Span::raw(format!("  {mode}: {}   ", app.path_display())),
        Span::styled(app.online_label(), Style::default().fg(match app.online { crate::app::Online::Online => Color::Green, crate::app::Online::Failed(_) => Color::Red, _ => Color::Yellow })),
    ])), rows[0]);

    match &app.screen {
        Screen::Unlock => secret_box(f, rows[1], "Unlock vault", "Password", app.pw.chars()),
        Screen::CreatePw => secret_box(f, rows[1], "Create new vault", "New password (long passphrase)", app.pw.chars()),
        Screen::CreateConfirm => secret_box(f, rows[1], "Create new vault", "Repeat password", 0),
        Screen::Working => secret_box(f, rows[1], "Working", "Deriving the key... (F12 = panic)", 0),
        _ => body(f, rows[1], app),
    }

    // Security warnings are sticky: shown above the status line until acknowledged (z), never overwritten.
    let rows2 = if let Some((a, n)) = app.alerts.first() {
        let sub = Layout::default().direction(Direction::Vertical).constraints([Constraint::Length(1), Constraint::Length(1)]).split(rows[2]);
        let more = if app.alerts.len() > 1 || app.alerts_dropped > 0 { format!(" (+{} more)", app.alerts.len() - 1 + app.alerts_dropped as usize) } else { String::new() };
        let times = if *n > 1 { format!(" (x{n})") } else { String::new() };
        f.render_widget(Paragraph::new(format!("[z] ! {a}{times}{more}")).style(Style::default().fg(Color::White).bg(Color::Red).add_modifier(Modifier::BOLD)), sub[0]);
        sub[1]
    } else { rows[2] };
    let style = if app.error { Style::default().fg(Color::Red) } else { Style::default().fg(Color::Cyan) };
    // Rendered straight from borrowed &str (no per-frame String copies of the pairing code).
    if let Some(p) = &app.pair_info {
        let sub = Layout::default().direction(Direction::Vertical).constraints([Constraint::Length(1), Constraint::Length(1)]).split(rows2);
        f.render_widget(Paragraph::new(&***p).style(Style::default().fg(Color::Yellow)), sub[0]);
        f.render_widget(Paragraph::new(app.status.as_str()).style(style), sub[1]);
    } else {
        f.render_widget(Paragraph::new(app.status.as_str()).style(style).wrap(Wrap { trim: true }), rows2);
    }
    f.render_widget(Paragraph::new(footer_hint(app)).style(Style::default().fg(Color::DarkGray)), rows[3]);

    match &app.screen {
        Screen::Prompt(p) => {
            let shown = if matches!(p, Prompt::JoinCode(_)) { "•".repeat(app.code_chars().min(40)) } else { app.input.clone() };
            prompt_popup(f, area, p, &shown)
        }
        Screen::Verify => verify_popup(f, area, app.view_number().unwrap_or("")),
        Screen::Help => help_popup(f, area),
        _ => {}
    }
}

/// Only keys that really work in the current state (mode / pane), most important first; the terminal clips the rest.
fn footer_hint(app: &App) -> &'static str {
    match (&app.screen, app.pane, app.mode) {
        (Screen::Prompt(_), _, _) => " Enter ok  Esc cancel   F12 PANIC-LOCK  Ctrl+] PURGE",
        (Screen::Main, Pane::Chat, Mode::Insert) => " -- INSERT --  Enter send  Esc normal mode   F12 PANIC-LOCK  Ctrl+] PURGE",
        (Screen::Main, Pane::Saved, _) => " SAVED  j/k move  d d delete  Esc back   F12 PANIC-LOCK  Ctrl+] PURGE",
        (Screen::Main, Pane::Chat, Mode::Normal) if app.select.is_some() => " SELECT  j/k choose a message  y save it  Esc cancel   F12 PANIC",
        (Screen::Main, Pane::Chat, Mode::Normal) => " NORMAL  i type  m select+save  j/k scroll  Tab next  f file  t text  a/r accept  s save  v verify  o online  Esc back  ? help  q quit  F12 PANIC  Ctrl+] PURGE",
        (Screen::Main, Pane::Details, _) => " Up/Down select  Enter chat  i type  H saved  n new  e export  I import  l/c pair  v verify  o online  ? help  Esc lock  q quit  F12 PANIC  Ctrl+] PURGE",
        _ => " F12 PANIC-LOCK  Ctrl+] PURGE",
    }
}

fn trust_glyph(t: Trust, has_peer: bool) -> (&'static str, Color) {
    if !has_peer { return ("○", Color::DarkGray); }
    match t { Trust::Unverified => ("◔", Color::Red), Trust::CodeAuthenticated => ("◑", Color::Yellow), Trust::SafetyVerified => ("●", Color::Green) }
}

fn secret_box(f: &mut Frame, area: Rect, title: &str, label: &str, n: usize) {
    let r = centered(area, 60, 5);
    let dots = "•".repeat(n.min(50));
    f.render_widget(Paragraph::new(vec![Line::from(label), Line::from(Span::styled(format!("{dots}_"), Style::default().add_modifier(Modifier::BOLD)))])
        .block(Block::bordered().title(title)), r);
}

/// Privacy screen: a shaded pattern over the whole terminal, nothing about contacts or messages.
fn lock_view(f: &mut Frame, area: Rect, app: &App) {
    let w = area.width as usize;
    let rows: Vec<Line> = (0..area.height as usize).map(|y| Line::from(Span::styled("░▒".repeat(w / 2 + 1).chars().skip(y % 2).take(w).collect::<String>(), Style::default().fg(Color::DarkGray)))).collect();
    f.render_widget(Paragraph::new(rows), area);
    let mut lines = vec![Line::from(Span::styled("LOCKED", Style::default().add_modifier(Modifier::BOLD))), Line::from("Enter = unlock    q = quit")];
    lines.push(Line::from(if app.quit_pending() { "quitting may lose something: press q again to quit" } else if app.alerts.is_empty() { "" } else { "! a security alert is waiting: unlock to read it" }));
    lines.push(Line::from(Span::styled("privacy screen only: the vault stays open. F12 = panic-lock  Ctrl+] = purge all", Style::default().fg(Color::DarkGray))));
    let r = centered(area, 56, 6);
    f.render_widget(Clear, r);
    f.render_widget(Paragraph::new(lines).alignment(Alignment::Center).block(Block::bordered()), r);
}

/// Sidebar (always) + right pane (details or conversation). Narrow terminals show one pane at a time.
fn body(f: &mut Frame, area: Rect, app: &App) {
    if area.width < 70 {
        if app.pane == Pane::Chat { chat_view(f, area, app) }
        else if app.pane == Pane::Saved { saved_view(f, area, app) }
        else {
            // one column: the list on top, the selected contact's details below (nothing is hidden on a narrow terminal)
            let r = Layout::default().direction(Direction::Vertical).constraints([Constraint::Percentage(40), Constraint::Percentage(60)]).split(area);
            sidebar(f, r[0], app);
            details_view(f, r[1], app);
        }
        return;
    }
    let side_w = (area.width / 4).clamp(24, 34);
    let cols = Layout::default().direction(Direction::Horizontal).constraints([Constraint::Length(side_w), Constraint::Min(20)]).split(area);
    sidebar(f, cols[0], app);
    match app.pane { Pane::Chat => chat_view(f, cols[1], app), Pane::Saved => saved_view(f, cols[1], app), Pane::Details => details_view(f, cols[1], app) }
}

fn sidebar(f: &mut Frame, area: Rect, app: &App) {
    let items: Vec<ListItem> = app.contact_rows().iter().map(|(n, t, p, linked, unread)| {
        let (g, c) = trust_glyph(*t, *p);
        let dot = if *linked { Span::styled("● ", Style::default().fg(Color::Green)) } else { Span::raw("  ") };
        let mut v = vec![dot, Span::raw(*n), Span::raw(" "), Span::styled(g, Style::default().fg(c))];
        if *unread > 0 { v.push(Span::styled(format!(" [{unread}]"), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))); }
        ListItem::new(Line::from(v))
    }).collect();
    let mut st = ListState::default();
    if !items.is_empty() { st.select(Some(app.sel)); }
    f.render_stateful_widget(List::new(items).block(Block::bordered().title("Contacts"))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED)), area, &mut st);
}

fn details_view(f: &mut Frame, area: Rect, app: &App) {
    let detail = match app.selected_detail() {
        None => vec![Line::from("No contacts yet. Press n to add one: a NEW keypair is generated for each contact.")],
        Some((name, trust, sn)) => {
            let (l, c) = trust_label(trust, sn.is_some());
            let mut v = vec![Line::from(Span::styled(name, Style::default().add_modifier(Modifier::BOLD))), Line::from(Span::styled(l, Style::default().fg(c))), Line::from("")];
            match sn {
                Some(n) => {
                    v.push(Line::from("Safety number (both of you must see the SAME digits):"));
                    for chunk in n.split(' ').collect::<Vec<_>>().chunks(4) { v.push(Line::from(Span::styled(chunk.join("  "), Style::default().add_modifier(Modifier::BOLD)))); }
                    if trust != Trust::SafetyVerified { v.push(Line::from("")); v.push(Line::from("Compare these digits over a DIFFERENT channel (voice/in person), then press v.")); }
                    v.push(Line::from(""));
                    if let Some(conn) = app.selected_connection() { v.push(Line::from(format!("Connection: {conn}"))); }
                    v.push(Line::from("Enter = open the chat, i = open it and start typing."));
                }
                None => {
                    v.push(Line::from("Next: e = export YOUR public bundle and send it,"));
                    v.push(Line::from("      I = import THEIR bundle file, or"));
                    v.push(Line::from("      l / c = pair directly over LAN with a one-time code."));
                }
            }
            if let Some((peer_can_host, anyway, we_host)) = app.contact_roles() {
                v.push(Line::from(""));
                v.push(Line::from(format!("Roles: contact {} host; {}.", if peer_can_host { "CAN" } else { "CANNOT" },
                    if we_host { "YOU host for it while online (holders of its copy of your bundle can see when you are online)" } else { "you only dial (your online status is not published for it)" })));
                if anyway { v.push(Line::from("Host anyway: ON (h to switch off)")); }
                if let Some(told) = app.cap_mismatch() {
                    v.push(Line::from(Span::styled(format!("NOTE: this contact was told you {} host, but you started now with {}. Roles keep following what it was told; if that is wrong, delete the contact and pair again.",
                        if told { "CAN" } else { "CANNOT" }, if told { "--cannot-host" } else { "hosting enabled" }), Style::default().fg(Color::Yellow))));
                }
            }
            let saved = app.saved_msgs().len();
            if saved > 0 { v.push(Line::from("")); v.push(Line::from(format!("Saved messages: {saved} (H shows them; they are stored encrypted in the vault, only what YOU saved)"))); }
            if let Some(r) = app.rotation_state() { v.push(Line::from("")); v.push(Line::from(Span::styled(r, Style::default().fg(Color::Yellow)))); }
            if let Some(fs) = app.file_state() { v.push(Line::from("")); v.push(Line::from(Span::styled(fs, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)))); }
            v
        }
    };
    f.render_widget(Paragraph::new(detail).block(Block::bordered().title("Details")).wrap(Wrap { trim: false }), area);
}

/// The last `cols` display columns of `t` (a borrowed slice: no copy of the draft), so the end of a long draft is always visible.
fn tail(t: &str, cols: usize) -> &str {
    let mut used = 0;
    for (i, ch) in t.char_indices().rev() {
        let cw = Span::raw(&t[i..i + ch.len_utf8()]).width().max(1);
        if used + cw > cols { return &t[i + ch.len_utf8()..]; }
        used += cw;
    }
    t
}

/// Wrap one message by DISPLAY width (wide CJK characters take two cells): nothing may silently fall off the right edge (R6-L5).
/// Borrowed slices of the (sanitised) text, no per-frame copy; `marked` = the message cursor is on it.
fn wrap_msg<'a>(text: &'a str, tag: &str, style: Style, w: usize, marked: bool) -> Vec<Line<'a>> {
    let tw = Span::raw(tag).width();
    let avail = w.saturating_sub(tw).max(2);
    let mut chunks: Vec<&str> = Vec::new();
    let (mut start, mut cols) = (0usize, 0usize);
    for (i, ch) in text.char_indices() {
        let cw = Span::raw(&text[i..i + ch.len_utf8()]).width().max(1);
        if cols + cw > avail && i > start { chunks.push(&text[start..i]); start = i; cols = 0; }
        cols += cw;
    }
    if start < text.len() || chunks.is_empty() { chunks.push(&text[start..]); }
    chunks.iter().enumerate().map(|(i, c)| {
        let l = Line::from(vec![Span::styled(if i == 0 { tag.to_string() } else { " ".repeat(tw) }, style), Span::raw(*c)]);
        if marked { l.style(Style::default().add_modifier(Modifier::REVERSED)) } else { l }
    }).collect()
}

/// The messages the user saved for the selected contact (read from the vault's copy in RAM).
fn saved_view(f: &mut Frame, area: Rect, app: &App) {
    let (name, msgs) = (app.selected_detail().map_or("", |d| d.0), app.saved_msgs());
    let w = area.width.saturating_sub(4).max(8) as usize;
    let h = area.height.saturating_sub(2) as usize;
    let per: Vec<Vec<Line>> = msgs.iter().enumerate().map(|(i, m)| wrap_msg(&m.text, if m.mine { "me> " } else { "them> " }, Style::default().fg(if m.mine { Color::Cyan } else { Color::Green }), w, i == app.saved_sel)).collect();
    let total: usize = per.iter().map(Vec::len).sum();
    let sel = app.saved_sel.min(per.len().saturating_sub(1));
    let first: usize = per[..sel].iter().map(Vec::len).sum();
    let last = first + per.get(sel).map_or(0, Vec::len);
    let mut end = last.max(h).min(total);
    if end.saturating_sub(first) > h { end = first + h; }
    let lines: Vec<Line> = per.into_iter().flatten().skip(end.saturating_sub(h)).take(h).collect();
    f.render_widget(Paragraph::new(lines).block(Block::bordered().title(format!("Saved messages of {name} ({} in the encrypted vault, no timestamps): j/k move, d d delete, Esc back", msgs.len()))), area);
}

fn chat_view(f: &mut Frame, area: Rect, app: &App) {
    let file_line = app.file_state();
    let rows = Layout::default().direction(Direction::Vertical)
        .constraints([Constraint::Length(if file_line.is_some() { 3 } else { 2 }), Constraint::Min(2), Constraint::Length(4)]).split(area);
    let Some((name, trust, linked)) = app.chat_header() else { return };
    let (tl, tc) = trust_label(trust, true);
    let conn = if linked { Span::styled("● connected", Style::default().fg(Color::Green)) } else { Span::styled("○ not connected (messages queue in RAM)", Style::default().fg(Color::Yellow)) };
    let mut head = vec![Line::from(vec![Span::styled(name, Style::default().add_modifier(Modifier::BOLD)), Span::raw("   "), Span::styled(tl, Style::default().fg(tc)), Span::raw("   "), conn])];
    head.push(Line::from(if trust == Trust::SafetyVerified { "" } else { "WARNING: NOT verified: compare the safety number (v)" }));
    if let Some(fl) = file_line { head.push(Line::from(Span::styled(fl, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)))); }
    f.render_widget(Paragraph::new(head).style(Style::default()), rows[0]);

    // messages: newest at the bottom (shifted up by `scroll`), wrapped by hand (no per-frame String copies of message text)
    let w = rows[1].width.saturating_sub(4).max(8) as usize;
    let h = rows[1].height.saturating_sub(2) as usize;
    let n = app.chat_lines().len();
    let mut msgs: Vec<Vec<Line>> = app.chat_lines().iter().enumerate().map(|(i, l)| {
        let who = if l.mine { "me" } else { "them" };
        let tag = format!("{who}{}{}> ", if l.saved { "★" } else { "" }, if l.queued { " (queued)" } else if l.unsent { " (NOT SENT)" } else { "" });
        wrap_msg(&l.text, &tag, Style::default().fg(if l.mine { Color::Cyan } else { Color::Green }), w, app.select == Some(n - 1 - i))
    }).collect();
    let total: usize = msgs.iter().map(Vec::len).sum();
    let (begin, end, eff) = match app.select {
        Some(k) if k < n => {   // the message cursor: show the chosen message (the top of it when it is taller than the window)
            let first: usize = msgs[..n - 1 - k].iter().map(Vec::len).sum();
            let last = first + msgs[n - 1 - k].len();
            let mut end = last.max(h).min(total);
            if end - first > h { end = first + h; }
            (end.saturating_sub(h), end, 0)
        }
        _ => {
            app.max_scroll.set(Some(total.saturating_sub(h)));        // tell the app how far up it can go
            let eff = app.scroll.min(total.saturating_sub(h));         // never scroll past the oldest line we have
            ((total - eff).saturating_sub(h), total - eff, eff)
        }
    };
    let title = if app.select.is_some() { "Conversation: choose a message (j/k), y saves it, Esc cancels".to_string() }
        else if eff > 0 { format!("Conversation (RAM only) - scrolled up {eff} line(s), G = newest") } else { "Conversation (RAM only, wiped on exit/panic; m = select a message to save)".to_string() };
    let lines: Vec<Line> = msgs.drain(..).flatten().skip(begin).take(end - begin).collect();
    f.render_widget(Paragraph::new(lines).block(Block::bordered().title(title)), rows[1]);

    let insert = app.mode == Mode::Insert;
    let inner = rows[2].width.saturating_sub(4) as usize;
    let mut input = vec![Span::styled("> ", Style::default().fg(Color::Yellow)), Span::raw(tail(app.compose_text(), inner.saturating_sub(1)))];
    if insert { input.push(Span::styled("_", Style::default().add_modifier(Modifier::BOLD))); }
    let (mode_title, border) = if insert { ("-- INSERT --", Style::default().fg(Color::Yellow)) } else { ("NORMAL", Style::default().fg(Color::DarkGray)) };
    let hint = if insert { "Enter send  |  Esc normal mode  |  F12 panic" } else { "i or Enter to type  |  f file  t text  |  Esc back  |  F12 panic" };
    f.render_widget(Paragraph::new(vec![Line::from(input), Line::from(Span::styled(hint, Style::default().fg(Color::DarkGray)))]).block(Block::bordered().title(mode_title).border_style(border)), rows[2]);
}

fn popup(f: &mut Frame, area: Rect, title: &str, lines: Vec<Line>, w: u16, h: u16) {
    let r = centered(area, w, h);
    f.render_widget(Clear, r);
    f.render_widget(Paragraph::new(lines).block(Block::bordered().title(title)).wrap(Wrap { trim: false }), r);
}

fn prompt_popup(f: &mut Frame, area: Rect, p: &Prompt, input: &str) {
    let (title, hint) = match p {
        Prompt::NewContact => ("New contact", "Name (a new keypair is generated):".to_string()),
        Prompt::Export => ("Export your public bundle", "Write to file (never overwrites):".into()),
        Prompt::Import => ("Import their bundle", "Path of their .sbc file:".into()),
        Prompt::Listen => ("Pair: listen", "Listen address (use your LAN IP and a port, e.g. 192.168.1.5:4000):".into()),
        Prompt::JoinAddr => ("Pair: connect", "Their address ip:port:".into()),
        Prompt::JoinCode(a) => ("Pair: connect", format!("One-time code shown on their screen (hidden as you type; connecting to {a}):")),
        Prompt::ConfirmDelete => ("Delete contact", "Type yes to delete this contact AND its keys:".into()),
        Prompt::SendFile => ("Send a file", "Path of a JPEG or PNG (metadata is stripped; every other format is refused):".into()),
        Prompt::SendText => ("Send plain text", "Path of a text file (ONLY invisible/control characters removed; document metadata is NOT understood; RTF/PDF/XML/HTML refused):".into()),
        Prompt::SaveFile => ("Save received file", "Write to (never overwrites; neutral name suggested):".into()),
        Prompt::InPerson => ("Pairing succeeded", "Was the code exchanged IN PERSON (same room)? y/n  (n = stays UNVERIFIED):".into()),
    };
    popup(f, area, title, vec![Line::from(hint), Line::from(""), Line::from(Span::styled(format!("{input}_"), Style::default().add_modifier(Modifier::BOLD))), Line::from(""), Line::from("Enter = ok   Esc = cancel")], 76, 9);
}

fn verify_popup(f: &mut Frame, area: Rect, number: &str) {
    let mut lines = vec![Line::from("Read these digits to the other person (voice/in person) and check they see the SAME:"), Line::from("")];
    for chunk in number.split(' ').collect::<Vec<_>>().chunks(4) { lines.push(Line::from(Span::styled(chunk.join("  "), Style::default().add_modifier(Modifier::BOLD)))); }
    lines.push(Line::from(""));
    lines.push(Line::from("They match: press y.   Anything else cancels."));
    popup(f, area, "Verify identity", lines, 76, 11);
}

fn help_popup(f: &mut Frame, area: Rect) {
    let t = [
        "Each contact = a NEW keypair. Nothing is cached; messages never hit disk.",
        "",
        "Add someone:  n (name)  ->  e (export your bundle)  ->  send it",
        "              I (import theirs)  ->  v (compare safety number)",
        "   or in person on one network:  l (listen) here, c (connect) there.",
        "",
        "Two modes, like vim. NORMAL: every key is a command. INSERT: keys are text only.",
        "  Enter / i  open the chat, or start typing      Esc  leave typing, then the chat",
        "  j k PgUp PgDn  scroll   g / G  oldest / newest   Tab / Shift+Tab  next / previous contact",
        "  f send JPEG/PNG   t send plain text   a / r accept / decline   s save   r also discards a file",
        "  v verify   d delete   o online/offline   K rotate keys   h host-anyway   z acknowledge alert   P answer a finished pairing",
        "",
        "Esc, Esc, Esc: typing -> normal -> details -> PRIVACY SCREEN (Enter unlocks, q quits).",
        "  The privacy screen only hides the screen: the vault stays open, anyone can press Enter.",
        "Keeping messages: NOTHING is saved automatically. In a chat: m = message cursor, j/k choose, y saves THAT message into the",
        "  vault (encrypted, no timestamp). H = saved messages of this contact (d d deletes one). Whoever gets vault + password can read them.",
        "q quits (wipes RAM; asks again if queued messages or unsaved files would be lost).",
        "",
        "PANIC-LOCK: F12 or Ctrl+\\  wipes memory, screen and scrollback and exits at once; the vault stays (the password opens it again).",
        "PURGE: Ctrl+] (or Shift+F12) does the same AND overwrites + deletes the vault, rollback counter, keyfile and the files exported/saved",
        "  this session: contacts, keys, saved messages gone for good. No confirmation. Press any key to close this help.",
    ];
    popup(f, area, "Help", t.iter().map(|s| Line::from(*s)).collect(), 100, 26);
    let _ = Alignment::Left;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{Config, Key, Pane};
    use ratatui::{backend::TestBackend, Terminal};
    use nerd_chat_vault::Profile;

    fn text(t: &Terminal<TestBackend>) -> String {
        t.backend().buffer().content().iter().map(|c| c.symbol()).collect()
    }

    #[test]
    fn password_is_never_rendered_and_screens_draw() {
        let d = tempfile::tempdir().unwrap();
        let mut a = App::new(Config::new(Some(d.path().join("v")), None, None, Profile::InsecureTest));
        let mut t = Terminal::new(TestBackend::new(110, 30)).unwrap();
        for c in "hunter2hunter2".chars() { a.handle(Key::Char(c)); }
        t.draw(|f| draw(f, &a)).unwrap();
        let s = text(&t);
        assert!(!s.contains("hunter2"), "password leaked to screen");
        assert!(s.contains("••••••••••••••"));
        a.handle(Key::Enter);
        for c in "hunter2hunter2".chars() { a.handle(Key::Char(c)); }
        a.handle(Key::Enter);
        assert_eq!(a.screen, Screen::Main);
        a.handle(Key::Char('n'));
        for c in "bob".chars() { a.handle(Key::Char(c)); }
        t.draw(|f| draw(f, &a)).unwrap();
        assert!(text(&t).contains("New contact"));
        a.handle(Key::Enter);
        t.draw(|f| draw(f, &a)).unwrap();
        let s = text(&t);
        assert!(s.contains("bob") && s.contains("no peer key"));
        a.handle(Key::Char('?'));
        t.draw(|f| draw(f, &a)).unwrap();
        assert!(text(&t).contains("PANIC"));
        // tiny terminal must not panic
        let mut tiny = Terminal::new(TestBackend::new(20, 5)).unwrap();
        tiny.draw(|f| draw(f, &a)).unwrap();
    }

    #[test]
    fn chat_screen_renders_conversation_warning_and_wraps_long_lines() {
        let d = tempfile::tempdir().unwrap();
        let net = nerd_chat_chat::MemNet::new();
        let mut c = Config::new(Some(d.path().join("v")), None, None, Profile::InsecureTest);
        let n = net.clone();
        c.transport = Some(std::sync::Arc::new(move |_p: &mut dyn FnMut(u8)| Ok(Box::new(n.transport()) as Box<dyn nerd_chat_chat::Transport>)));
        let mut a = App::new(c);
        for _ in 0..2 { for c in "correct horse battery".chars() { a.handle(Key::Char(c)); } a.handle(Key::Enter); }
        a.handle(Key::Char('n')); for c in "bob".chars() { a.handle(Key::Char(c)); } a.handle(Key::Enter);
        // no peer yet: opening the chat is refused
        a.handle(Key::Enter);
        assert_eq!(a.pane, Pane::Details, "opening a chat without a peer key is refused");
        let mut t = Terminal::new(TestBackend::new(70, 20)).unwrap();
        t.draw(|f| draw(f, &a)).unwrap();
        assert!(text(&t).contains("offline"), "online indicator in the title bar");
    }

    #[test]
    fn wiped_screen_is_blank() {
        let mut a = App::new(Config::new(None, None, None, Profile::InsecureTest));
        a.handle(Key::Enter);
        a.handle(Key::F12);
        let mut t = Terminal::new(TestBackend::new(60, 10)).unwrap();
        t.draw(|f| draw(f, &a)).unwrap();
        assert!(text(&t).trim().is_empty());
    }
}
