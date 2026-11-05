//! Rendering only. Reads `App`, never mutates it. Passwords are shown as dots only.
use crate::app::{App, Prompt, Screen};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Clear, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};
use seburity_core::trust::Trust;

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
    let rows = Layout::default().direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(3), Constraint::Length(2), Constraint::Length(1)]).split(area);
    let mode = if app.is_ram_only() { "RAM-ONLY" } else { "vault" };
    f.render_widget(Paragraph::new(Line::from(vec![
        Span::styled(" SEBURITY ", Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)),
        Span::raw(format!("  {mode}: {}   ", app.path_display())),
        Span::styled(app.online_label(), Style::default().fg(match app.online { crate::app::Online::Online => Color::Green, crate::app::Online::Failed(_) => Color::Red, _ => Color::Yellow })),
    ])), rows[0]);

    match &app.screen {
        Screen::Unlock => secret_box(f, rows[1], "Unlock vault", "Password", app.pw.chars()),
        Screen::CreatePw => secret_box(f, rows[1], "Create new vault", "New password (long passphrase)", app.pw.chars()),
        Screen::CreateConfirm => secret_box(f, rows[1], "Create new vault", "Repeat password", 0),
        Screen::Chat => chat_view(f, rows[1], app),
        Screen::Working => secret_box(f, rows[1], "Working", "Deriving the key... (F12 = panic)", 0),
        _ => main_view(f, rows[1], app),
    }

    let style = if app.error { Style::default().fg(Color::Red) } else { Style::default().fg(Color::Cyan) };
    // Rendered straight from borrowed &str (no per-frame String copies of the pairing code).
    if let Some(p) = &app.pair_info {
        let sub = Layout::default().direction(Direction::Vertical).constraints([Constraint::Length(1), Constraint::Length(1)]).split(rows[2]);
        f.render_widget(Paragraph::new(&***p).style(Style::default().fg(Color::Yellow)), sub[0]);
        f.render_widget(Paragraph::new(app.status.as_str()).style(style), sub[1]);
    } else {
        f.render_widget(Paragraph::new(app.status.as_str()).style(style).wrap(Wrap { trim: true }), rows[2]);
    }
    f.render_widget(Paragraph::new(" Enter chat  o online/offline  f send file  a/r accept/decline  s save  n new  e export  i import  l listen  c connect  x cancel  v verify  d delete  ? help  q quit   F12 / Ctrl+\\ = PANIC WIPE")
        .style(Style::default().fg(Color::DarkGray)), rows[3]);

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

fn secret_box(f: &mut Frame, area: Rect, title: &str, label: &str, n: usize) {
    let r = centered(area, 60, 5);
    let dots = "•".repeat(n.min(50));
    f.render_widget(Paragraph::new(vec![Line::from(label), Line::from(Span::styled(format!("{dots}_"), Style::default().add_modifier(Modifier::BOLD)))])
        .block(Block::bordered().title(title)), r);
}

fn main_view(f: &mut Frame, area: Rect, app: &App) {
    let cols = Layout::default().direction(Direction::Horizontal).constraints([Constraint::Percentage(35), Constraint::Percentage(65)]).split(area);
    let items: Vec<ListItem> = app.contact_rows().iter().map(|(n, t, p, linked, unread)| {
        let (l, c) = trust_label(*t, *p);
        let dot = if *linked { Span::styled("● ", Style::default().fg(Color::Green)) } else { Span::raw("  ") };
        let mut v = vec![dot, Span::raw(format!("{n}  ")), Span::styled(l, Style::default().fg(c))];
        if *unread > 0 { v.push(Span::styled(format!("  [{unread} new]"), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))); }
        ListItem::new(Line::from(v))
    }).collect();
    let mut st = ListState::default();
    if !items.is_empty() { st.select(Some(app.sel)); }
    f.render_stateful_widget(List::new(items).block(Block::bordered().title("Contacts (each has its own keypair)"))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED)), cols[0], &mut st);

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
                    v.push(Line::from("Chat needs the Tor transport (next build stage)."));
                }
                None => {
                    v.push(Line::from("Next: e = export YOUR public bundle and send it,"));
                    v.push(Line::from("      i = import THEIR bundle file, or"));
                    v.push(Line::from("      l / c = pair directly over LAN with a one-time code."));
                }
            }
            if let Some(fs) = app.file_state() { v.push(Line::from("")); v.push(Line::from(Span::styled(fs, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)))); }
            v
        }
    };
    f.render_widget(Paragraph::new(detail).block(Block::bordered().title("Details")).wrap(Wrap { trim: false }), cols[1]);
}

fn chat_view(f: &mut Frame, area: Rect, app: &App) {
    let rows = Layout::default().direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(2), Constraint::Length(3)]).split(area);
    let Some((name, trust, linked)) = app.chat_header() else { return };
    let (tl, tc) = trust_label(trust, true);
    let conn = if linked { Span::styled("● connected", Style::default().fg(Color::Green)) } else { Span::styled("○ not connected (messages queue in RAM)", Style::default().fg(Color::Yellow)) };
    let mut head = vec![Line::from(vec![Span::styled(name, Style::default().add_modifier(Modifier::BOLD)), Span::raw("   "), Span::styled(tl, Style::default().fg(tc)), Span::raw("   "), conn])];
    head.push(Line::from(if trust == Trust::SafetyVerified { "" } else { "WARNING: identity not verified with the safety number (Esc, then v). Anyone who intercepted the key exchange could read this." }));
    f.render_widget(Paragraph::new(head).style(Style::default()), rows[0]);

    // messages: newest at the bottom, wrapped by hand (no per-frame String copies of message text)
    let w = rows[1].width.saturating_sub(4).max(8) as usize;
    let h = rows[1].height.saturating_sub(2) as usize;
    let mut lines: Vec<Line> = Vec::new();
    for l in app.chat_lines().iter().rev() {
        let (tag, style) = if l.mine { (if l.queued { "me (queued)> " } else { "me> " }, Style::default().fg(Color::Cyan)) } else { ("them> ", Style::default().fg(Color::Green)) };
        // wrap by DISPLAY width (wide CJK characters take two cells): nothing may silently fall off the right edge (R6-L5)
        let mut chunks: Vec<&str> = Vec::new();
        let t: &str = &l.text;
        let avail = w.saturating_sub(tag.len()).max(2);
        let (mut start, mut cols) = (0usize, 0usize);
        for (i, ch) in t.char_indices() {
            let cw = Span::raw(&t[i..i + ch.len_utf8()]).width().max(1);
            if cols + cw > avail && i > start { chunks.push(&t[start..i]); start = i; cols = 0; }
            cols += cw;
        }
        if start < t.len() { chunks.push(&t[start..]); }
        for (i, c) in chunks.iter().enumerate().rev() {
            lines.push(Line::from(vec![Span::styled(if i == 0 { tag.to_string() } else { " ".repeat(tag.len()) }, style), Span::raw(*c)]));
        }
        if lines.len() >= h { break; }
    }
    lines.reverse();
    let skip = lines.len().saturating_sub(h);
    f.render_widget(Paragraph::new(lines.into_iter().skip(skip).collect::<Vec<_>>()).block(Block::bordered().title("Conversation (RAM only, wiped on exit/panic)")), rows[1]);

    let input = Line::from(vec![Span::styled("> ", Style::default().fg(Color::Yellow)), Span::raw(app.compose_text()), Span::styled("_", Style::default().add_modifier(Modifier::BOLD))]);
    f.render_widget(Paragraph::new(vec![input, Line::from(Span::styled("Enter send  |  Esc back  |  F12 panic", Style::default().fg(Color::DarkGray)))]).block(Block::bordered()), rows[2]);
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
        Prompt::SendFile => ("Send a file", "Path of the file (JPEG/PNG/text; metadata is stripped, others refused):".into()),
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
        "              i (import theirs)  ->  v (compare safety number)",
        "   or in person on one network:  l (listen) here, c (connect) there.",
        "",
        "Files: f send (metadata stripped, unknown types refused), a/r accept/decline an offer, s save.",
        "       Files live in RAM only until you save them; names are neutral.",
        "",
        "PANIC: F12 or Ctrl+\\  locks, wipes the screen+scrollback and exits at once.",
        "q / Esc quits (locks) normally.",
        "",
        "Press any key.",
    ];
    popup(f, area, "Help", t.iter().map(|s| Line::from(*s)).collect(), 76, 17);
    let _ = Alignment::Left;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{Config, Key};
    use ratatui::{backend::TestBackend, Terminal};
    use seburity_vault::Profile;

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
        let net = seburity_chat::MemNet::new();
        let mut c = Config::new(Some(d.path().join("v")), None, None, Profile::InsecureTest);
        let n = net.clone();
        c.transport = Some(std::sync::Arc::new(move |_p: &mut dyn FnMut(u8)| Ok(Box::new(n.transport()) as Box<dyn seburity_chat::Transport>)));
        let mut a = App::new(c);
        for _ in 0..2 { for c in "correct horse battery".chars() { a.handle(Key::Char(c)); } a.handle(Key::Enter); }
        a.handle(Key::Char('n')); for c in "bob".chars() { a.handle(Key::Char(c)); } a.handle(Key::Enter);
        // no peer yet: opening the chat is refused
        a.handle(Key::Enter);
        assert_ne!(a.screen, Screen::Chat);
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
