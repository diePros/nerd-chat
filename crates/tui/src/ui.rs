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
        Span::raw(format!("  {mode}: {}", app.path_display())),
    ])), rows[0]);

    match &app.screen {
        Screen::Unlock => secret_box(f, rows[1], "Unlock vault", "Password", app.pw.chars()),
        Screen::CreatePw => secret_box(f, rows[1], "Create new vault", "New password (long passphrase)", app.pw.chars()),
        Screen::CreateConfirm => secret_box(f, rows[1], "Create new vault", "Repeat password", 0),
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
    f.render_widget(Paragraph::new(" n new  e export  i import  l listen  c connect  x cancel  v verify  d delete  ? help  q quit   F12 / Ctrl+\\ = PANIC WIPE")
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
    let items: Vec<ListItem> = app.contact_rows().iter().map(|(n, t, p)| {
        let (l, c) = trust_label(*t, *p);
        ListItem::new(Line::from(vec![Span::raw(format!("{n}  ")), Span::styled(l, Style::default().fg(c))]))
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
            v
        }
    };
    f.render_widget(Paragraph::new(detail).block(Block::bordered().title("Details")).wrap(Wrap { trim: false }), cols[1]);
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
        "PANIC: F12 or Ctrl+\\  locks, wipes the screen+scrollback and exits at once.",
        "q / Esc quits (locks) normally.",
        "",
        "Press any key.",
    ];
    popup(f, area, "Help", t.iter().map(|s| Line::from(*s)).collect(), 76, 14);
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
        let mut a = App::new(Config { path: Some(d.path().join("v")), counter: None, keyfile: None, profile: Profile::InsecureTest });
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
    fn wiped_screen_is_blank() {
        let mut a = App::new(Config { path: None, counter: None, keyfile: None, profile: Profile::InsecureTest });
        a.handle(Key::Enter);
        a.handle(Key::F12);
        let mut t = Terminal::new(TestBackend::new(60, 10)).unwrap();
        t.draw(|f| draw(f, &a)).unwrap();
        assert!(text(&t).trim().is_empty());
    }
}
