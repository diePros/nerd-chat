//! Start-up (arguments, hardening, swap refusal, the first-run vault dialog) and the eframe application object.
use crate::view;
use eframe::egui;
use sine_loco_app::{app::{Action, App, Config, Key, Mode, Online, Pane, Screen}, vault_path};
use sine_loco_vault::Profile;
use std::{path::PathBuf, time::{Duration, Instant}};

/// What the window shows before (or instead of) the app core.
pub enum Shell {
    /// Refused to start (swap active, no home directory...): one plain explanation and a Quit button.
    Refused(String),
    /// First run: where the vault will be, asked once before anything is created on disk.
    FirstRun { dir: PathBuf, path: PathBuf, tails: bool },
    /// The app core runs.
    Run,
}

pub struct Gui {
    pub shell: Shell,
    cfg: Option<Config>,
    pub app: Option<App>,
    /// the user switched offline on purpose: do not reconnect by themselves
    pub user_offline: bool,
    /// next automatic (re)connect attempt after a failed Tor start, and how many failed in a row
    retry_at: Option<Instant>,
    retries: u32,
    started: bool,
    /// text of the single-line, NON-secret prompt currently shown (contact name, file path, address)
    pub prompt_text: String,
    pub prompt_for: Option<sine_loco_app::app::Prompt>,
    /// contacts whose "not verified" notice was already shown in this session (D3: once per contact per session); nothing is stored
    pub notice_seen: std::collections::HashSet<[u8; 8]>,
    /// developer option: never show the notice (for screenshots of the chat itself)
    skip_notice: bool,
    settings_open: bool,
    menu_hidden: bool,
    menu_note: String,
    purge_ok: bool,
    /// developer options
    shot: Option<(PathBuf, u32)>,
    frames: u32,
    #[cfg(feature = "demo")]
    demo: Option<crate::view::demo::Demo>,
}

pub fn run() -> eframe::Result {
    // FIRST: the cleaner helper dispatch (this binary re-executed), the sandboxed cleaner, process hardening (the app core refuses to run without it)
    let args: Vec<String> = std::env::args().collect();
    let started = sine_loco_app::startup::startup(&args);
    for w in started.warnings { eprintln!("warning: {w}"); }

    let mut g = Gui::from_args(&args, started.swap);
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([980.0, 640.0]).with_min_inner_size([640.0, 420.0]).with_title("Sine Loco").with_app_id("sine-loco"),
        ..Default::default()
    };
    g.frames = 0;
    eframe::run_native("Sine Loco", opts, Box::new(move |cc| { view::style(&cc.egui_ctx); Ok(Box::new(g)) }))
}

impl Gui {
    fn from_args(args: &[String], swap: Option<Vec<String>>) -> Gui {
        let has = |f: &str| args.iter().any(|a| a == f);
        let val = |f: &str| args.iter().position(|a| a == f).and_then(|i| args.get(i + 1)).cloned();
        let (mut path, ram) = (val("--vault").map(PathBuf::from), has("--ram") || has("--demo"));
        let profile = if has("--low-mem") || has("--demo") { Profile::LowMem } else { Profile::Strong };
        let mut shell = Shell::Run;
        // 3. the swap refusal (same rule as the terminal version), shown in the window because a menu launch has no terminal
        if !has("--allow-swap") {
            if let Some(active) = swap {
                shell = Shell::Refused(format!("Swap is active ({}). The system may write parts of this program's memory (keys, messages) to that swap space, where it can survive power-off. Turn swap off first (sudo swapoff -a). On a live USB system there is normally none. To start anyway at your own risk: start with --allow-swap.", active.join(", ")));
            }
        }
        if matches!(shell, Shell::Run) && !ram && path.is_none() {
            let env = |k: &str| std::env::var_os(k).map(PathBuf::from);
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            match vault_path::resolve(env("XDG_DATA_HOME").as_deref(), env("HOME").as_deref(), &cwd, &|p| match std::fs::symlink_metadata(p) { Err(e) => e.kind() != std::io::ErrorKind::NotFound, Ok(_) => true }) {
                vault_path::Choice::Existing { path: p, .. } => match vault_path::check_existing(&p) { Ok(()) => path = Some(p), Err(e) => shell = Shell::Refused(e) },
                vault_path::Choice::Unusable(why) => shell = Shell::Refused(why),
                vault_path::Choice::New { dir, path: p } => {
                    let tails = std::fs::read_to_string("/etc/os-release").is_ok_and(|s| vault_path::is_tails(&s));
                    path = Some(p.clone()); // the dialog only confirms WHERE: the vault itself must be created there (not RAM-only)
                    shell = Shell::FirstRun { dir, path: p, tails };
                }
            }
        }
        let mut cfg = Config::new(if ram { None } else { path.clone() }, val("--counter-file").map(PathBuf::from), None, profile);
        cfg.keys = false; // the GUI has buttons: no "press v" in its messages
        cfg.allow_swap = has("--allow-swap");
        cfg.can_host = !has("--cannot-host");
        if let Some(a) = val("--tor-control").and_then(|s| sine_loco_net::tor::Addr::parse(&s)) { cfg.tor.control = Some(a); }
        if let Some(a) = val("--tor-socks").and_then(|s| sine_loco_net::tor::Addr::parse(&s)) { cfg.tor.socks = Some(a); }
        cfg.tor.trust_control = has("--tor-trust-control");
        let shot = val("--screenshot").map(|p| (PathBuf::from(p), val("--shot-frame").and_then(|s| s.parse().ok()).unwrap_or(40)));
        let mut g = Gui { shell, cfg: Some(cfg), app: None, user_offline: false, retry_at: None, retries: 0, started: false, prompt_text: String::new(), prompt_for: None, notice_seen: Default::default(), skip_notice: has("--skip-notice"), settings_open: false, menu_hidden: crate::menu::user_entry_path().is_some_and(|p| crate::menu::is_hidden(&p)), menu_note: String::new(), purge_ok: false, shot, frames: 0,
            #[cfg(feature = "demo")] demo: None };
        #[cfg(feature = "demo")]
        if has("--demo") { g.demo = Some(crate::view::demo::Demo::new()); }
        if matches!(g.shell, Shell::Run) { g.start_app(); }
        g
    }

    /// Create the app core (after the first-run dialog, or at once when the vault is known).
    pub fn start_app(&mut self) {
        if let Some(cfg) = self.cfg.take() {
            #[cfg(feature = "demo")]
            if let Some(d) = &mut self.demo { self.app = Some(d.make_app(cfg)); return; }
            self.app = Some(App::new(cfg));
        }
    }

    pub fn first_run_continue(&mut self) {
        if let Shell::FirstRun { dir, .. } = &self.shell {
            match vault_path::prepare_dir(dir) {
                Ok(()) => { self.shell = Shell::Run; self.start_app(); }
                Err(e) => self.shell = Shell::Refused(e),
            }
        }
    }

    // The GUI hides the terminal version's vim-style modes: it puts the core into the mode a click needs.
    pub fn ensure_normal(app: &mut App) { if app.screen == Screen::Main && app.mode == Mode::Insert { app.handle(Key::Esc); } }
    pub fn ensure_insert(app: &mut App) { if app.screen == Screen::Main && app.pane == Pane::Chat && app.mode == Mode::Normal { app.handle(Key::Char('i')); } }

    /// Panic / purge exit: wipe the core, drop every toolkit cache, end the process at once (no window left to repaint).
    fn wipe_and_exit(&mut self, ctx: &egui::Context, _purge: bool) -> ! {
        if let Some(app) = self.app.as_mut() {
            app.panic_wipe(); // a purge wipes first, then destroys its files below
            ctx.data_mut(|d| d.clear());
            ctx.memory_mut(|m| m.reset_areas());
            app.purge_finish();
            if let Some((ok, failed)) = app.purge_report { eprintln!("purge: {ok} file(s) overwritten and deleted{}", if failed > 0 { format!(", {failed} could NOT be removed") } else { String::new() }); }
        }
        std::process::exit(0)
    }

    /// Automatic connection and reconnection (D5): once the vault is open, go online by ourselves; after a failed Tor start retry with a
    /// growing delay; never when the user switched offline on purpose.
    fn auto_connect(&mut self) {
        let Some(app) = self.app.as_mut() else { return };
        if app.screen != Screen::Main || self.user_offline { return; }
        match &app.online {
            Online::Offline if !self.started => { self.started = true; Self::ensure_normal(app); app.handle(Key::Char('o')); }
            Online::Failed(_) => {
                let due = *self.retry_at.get_or_insert_with(|| Instant::now() + Duration::from_secs((5u64 << self.retries.min(4)).min(60)));
                if Instant::now() >= due { self.retry_at = None; self.retries = self.retries.saturating_add(1); Self::ensure_normal(app); app.handle(Key::Char('o')); }
            }
            Online::Online => { self.retries = 0; self.retry_at = None; }
            _ => {}
        }
    }
}

impl eframe::App for Gui {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.frames += 1;
        // keep polling the core (Tor start, engine events, key derivation) even without input
        ctx.request_repaint_after(Duration::from_millis(100));
        match &self.shell {
            Shell::Refused(msg) => { if view::refused(ui, msg) { ctx.send_viewport_cmd(egui::ViewportCommand::Close); } }
            Shell::FirstRun { path, tails, .. } => {
                let text = view::first_run_text(path, *tails);
                match view::first_run(ui, &text, *tails) { view::Choice::Continue => self.first_run_continue(), view::Choice::Quit => ctx.send_viewport_cmd(egui::ViewportCommand::Close), view::Choice::None => {} }
            }
            Shell::Run => self.run_frame(ui, &ctx),
        }
        self.maybe_screenshot(&ctx);
    }
}

impl Gui {
    fn run_frame(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        #[cfg(feature = "demo")]
        if let (Some(d), Some(app)) = (self.demo.as_mut(), self.app.as_mut()) { d.step(app, self.frames); }
        let Some(app) = self.app.as_mut() else { return };
        app.poll();
        // keyboard: forwarded to the core only where the core takes text (secret screens, prompts, a chat in insert mode) + the panic keys
        let (keys, pasted) = view::collect_input(ctx, app, !self.skip_notice && view::notice_pending(app, &self.notice_seen));
        let mut action = Action::None;
        for k in keys { let a = app.handle(k); if a != Action::None { action = a; break; } }
        if let Some(t) = pasted { app.paste(&t); }
        match action {
            Action::Quit => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
            Action::Panic => self.wipe_and_exit(ctx, false),
            Action::Purge => self.wipe_and_exit(ctx, true),
            Action::None => {}
        }
        let mut cmds = view::Cmds::default();
        if let Some(app) = self.app.as_mut() { if self.skip_notice { if let Some(id) = app.chat_id() { self.notice_seen.insert(id); } }
            view::draw(ui, app, &mut self.prompt_text, &mut self.prompt_for, &mut self.notice_seen, &mut cmds); }
        if let Some(app) = self.app.as_mut() {
            for c in cmds.take() { view::apply(app, c, &mut self.user_offline, &mut self.started); }
        }
        if cmds.settings { self.settings_open = true; }
        if self.settings_open {
            let entry = crate::menu::user_entry_path();
            let purge = match self.app.as_mut() { Some(app) => view::settings(ctx, app, &mut self.settings_open, &mut self.menu_hidden, entry.as_deref(), &mut self.menu_note, &mut self.purge_ok), None => false };
            if purge { if let Some(app) = self.app.as_mut() { if app.handle(Key::Purge) == Action::Purge { self.wipe_and_exit(ctx, true); } } }
        }
        if cmds.panic { self.wipe_and_exit(ctx, false); }
        self.auto_connect();
    }

    fn maybe_screenshot(&mut self, ctx: &egui::Context) {
        let Some((path, at)) = self.shot.clone() else { return };
        if self.frames == at {
            ctx.request_screenshot(move |img| {
                if let Ok(f) = std::fs::File::create(&path) {
                    let mut e = png::Encoder::new(f, img.size[0] as u32, img.size[1] as u32);
                    e.set_color(png::ColorType::Rgba); e.set_depth(png::BitDepth::Eight);
                    if let Ok(mut w) = e.write_header() { let bytes: Vec<u8> = img.pixels.iter().flat_map(|p| p.to_array()).collect(); let _ = w.write_image_data(&bytes); }
                }
            });
        }
        if self.frames == at + 8 { std::process::exit(0); }
        ctx.request_repaint();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: after the first-run dialog the app was started RAM-only (no path), so a vault and its contacts were never saved.
    #[test]
    fn first_run_gives_the_app_the_default_vault_path_not_ram_only() {
        let home = tempfile::tempdir().unwrap();
        let (old_home, old_xdg) = (std::env::var_os("HOME"), std::env::var_os("XDG_DATA_HOME"));
        std::env::set_var("HOME", home.path());
        std::env::remove_var("XDG_DATA_HOME");
        let g = Gui::from_args(&["sine-loco-gui".into(), "--allow-swap".into()], None);
        let (shell_path, cfg_path) = (match &g.shell { Shell::FirstRun { path, .. } => Some(path.clone()), _ => None }, g.cfg.as_ref().and_then(|c| c.path.clone()));
        match old_home { Some(v) => std::env::set_var("HOME", v), None => std::env::remove_var("HOME") }
        if let Some(v) = old_xdg { std::env::set_var("XDG_DATA_HOME", v); }
        assert!(shell_path.is_some(), "a fresh home must show the first-run dialog");
        assert_eq!(cfg_path, shell_path, "the vault must be created where the dialog said, not RAM-only");
    }
}
