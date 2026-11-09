//! The visible state of the core as one JSON document (`"v": 1`). Only what a screen needs: passwords and the pairing code never appear
//! (only how many characters were typed), chat lines only for the OPEN chat, like the Linux GUI.
use crate::json::W;
use nerd_chat_app::app::{App, Mode, Online, Pane, Prompt, Screen};
use nerd_chat_core::trust::Trust;
use std::time::Instant;
use zeroize::Zeroizing;

pub const VERSION: i64 = 1;

/// What the bridge adds to the core's own state.
#[derive(Default)]
pub struct Extra<'a> {
    /// why the last command was refused by the bridge's guards (None: accepted)
    pub rejected: Option<&'a str>,
    /// (files overwritten and deleted, failed) after a purge
    pub purge: Option<(usize, usize)>,
    /// the user switched offline on purpose (no automatic reconnect)
    pub user_offline: bool,
}

pub fn trust_str(t: Trust) -> &'static str {
    match t { Trust::Unverified => "unverified", Trust::CodeAuthenticated => "code", Trust::SafetyVerified => "verified" }
}

fn screen_str(s: &Screen) -> (&'static str, Option<&'static str>) {
    match s {
        Screen::Unlock => ("unlock", None),
        Screen::CreatePw => ("create_pw", None),
        Screen::CreateConfirm => ("create_confirm", None),
        Screen::Main => ("main", None),
        Screen::Verify => ("verify", None),
        Screen::Help => ("help", None),
        Screen::Working => ("working", None),
        Screen::Wiped => ("wiped", None),
        Screen::Prompt(p) => ("prompt", Some(match p {
            Prompt::NewContact => "new_contact", Prompt::Import => "import", Prompt::Export => "export", Prompt::Listen => "listen",
            Prompt::JoinAddr => "join_addr", Prompt::JoinCode(_) => "join_code", Prompt::JoinLink => "join_link",
            Prompt::ConfirmDelete => "confirm_delete", Prompt::InPerson => "in_person", Prompt::SendFile => "send_file",
            Prompt::SendText => "send_text", Prompt::SaveFile => "save_file",
        })),
    }
}

pub fn snapshot(app: &App, x: &Extra) -> Zeroizing<String> {
    let mut w = W::new();
    w.obj();
    w.f_num("v", VERSION);
    let (screen, prompt) = screen_str(&app.screen);
    w.f_str("screen", screen);
    w.f_opt_str("prompt", prompt);
    w.f_str("status", &app.status);
    w.f_bool("error", app.error);
    w.f_opt_str("rejected", x.rejected);
    // typed secrets: counts only
    w.f_num("pw_chars", app.pw.chars() as i64);
    w.f_num("confirm_chars", app.confirm_chars() as i64);
    w.f_num("code_chars", app.code_chars() as i64);
    w.f_bool("privacy_locked", app.locked);
    w.f_bool("ram_only", app.is_ram_only());
    w.f_bool("keep_outbox", app.keep_outbox());
    w.f_bool("user_offline", x.user_offline);

    let (online, pct, fail) = match &app.online {
        Online::Offline => ("offline", 0, None),
        Online::Starting(p) => ("starting", *p as i64, None),
        Online::Online => ("online", 100, None),
        Online::Stopping => ("stopping", 0, None),
        Online::Failed(e) => ("failed", 0, Some(e.as_str())),
    };
    w.f_str("online", online);
    w.f_num("online_pct", pct);
    w.f_opt_str("online_error", fail);

    w.f_num("sel", app.sel as i64);
    w.f_str("pane", match app.pane { Pane::Details => "details", Pane::Chat => "chat", Pane::Saved => "saved" });
    w.f_str("mode", match app.mode { Mode::Normal => "normal", Mode::Insert => "insert" });

    let main = app.screen == Screen::Main || matches!(app.screen, Screen::Prompt(_) | Screen::Verify);
    w.f_arr("contacts");
    if main {
        for (name, trust, paired, connected, unread) in app.contact_rows() {
            w.arr_item_obj();
            w.f_str("name", name); w.f_str("trust", trust_str(trust)); w.f_bool("paired", paired);
            w.f_bool("connected", connected); w.f_num("unread", unread as i64);
            w.end_obj();
        }
    }
    w.end_arr();

    match app.chat_header().filter(|_| main) {
        Some((name, trust, connected)) => {
            w.f_obj("chat");
            w.f_str("name", name); w.f_str("trust", trust_str(trust)); w.f_bool("connected", connected);
            w.f_arr("lines");
            for l in app.chat_lines() {
                w.arr_item_obj();
                w.f_bool("mine", l.mine); w.f_str("text", &l.text);
                w.f_bool("queued", l.queued); w.f_bool("unsent", l.unsent); w.f_bool("unconfirmed", l.unconfirmed); w.f_bool("saved", l.saved);
                w.end_obj();
            }
            w.end_arr();
            w.end_obj();
        }
        None => w.f_null("chat"),
    }

    match app.selected_detail().filter(|_| main) {
        Some((name, trust, safety)) => {
            w.f_obj("detail");
            w.f_str("name", name); w.f_str("trust", trust_str(trust)); w.f_opt_str("safety", safety.as_deref());
            w.f_opt_str("connection", app.selected_connection());
            match app.inspect() {
                Some(i) => { w.f_bool("we_host_now", i.we_host_now); w.f_bool("contact_can_host", i.contact_can_host); w.f_opt_str("rotation", i.rotation); }
                None => { w.f_null("we_host_now"); w.f_null("contact_can_host"); w.f_null("rotation"); }
            }
            w.end_obj();
        }
        None => w.f_null("detail"),
    }

    w.f_opt_str("verify_number", app.view_number());

    match &app.tor_offer {
        Some(o) => {
            w.f_obj("tor_offer");
            w.f_str("link", &o.link); w.f_str("code", &o.code);
            w.f_num("expires_in", o.expires.saturating_duration_since(Instant::now()).as_secs() as i64);
            w.f_opt_str("for", app.tor_offer_name());
            w.end_obj();
        }
        None => w.f_null("tor_offer"),
    }
    w.f_bool("pairing_waiting", app.pairing_waiting());

    w.f_arr("alerts");
    for (text, count) in &app.alerts { w.arr_item_obj(); w.f_str("text", text); w.f_num("count", *count as i64); w.end_obj(); }
    w.end_arr();

    match x.purge {
        Some((ok, failed)) => { w.f_obj("purge"); w.f_num("deleted", ok as i64); w.f_num("failed", failed as i64); w.end_obj(); }
        None => w.f_null("purge"),
    }
    w.end_obj();
    w.finish()
}
