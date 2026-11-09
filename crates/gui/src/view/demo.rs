//! DEVELOPER DEMO (cargo feature `demo`, never in a release build): two other accounts living in this process, linked to the real
//! app core over the in-memory test network, so that every screen can be shown without Tor. It only presses the same keys a user would.
use nerd_chat_app::app::{App, Config, Key, Screen};
use nerd_chat_chat::{MemNet, Timing, Transport};
use nerd_chat_vault::Profile;
use std::{path::PathBuf, sync::Arc, time::Duration};

fn typed(app: &mut App, s: &str) { for c in s.chars() { app.handle(Key::Char(c)); } }
fn fast() -> Timing {
    Timing { poll: Duration::from_millis(20), keepalive: Duration::from_millis(500), idle: Duration::from_secs(5), min_backoff: Duration::from_millis(30), max_backoff: Duration::from_millis(300),
             handshake: Duration::from_secs(5), handshakes_per_sec: 1000.0, ack_delay_min: Duration::from_millis(20), ack_delay_max: Duration::from_millis(40), caps_wait: Duration::from_millis(400) }
}
fn select(app: &mut App, i: usize) { for _ in 0..8 { if app.sel == i { break; } app.handle(if app.sel < i { Key::Down } else { Key::Up }); } }

pub struct Demo { net: MemNet, peers: Vec<(&'static str, App)>, stage: u32, wait: u32, dir: PathBuf }

impl Demo {
    pub fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("nerd-chat-demo-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        Demo { net: MemNet::new(), peers: vec![], stage: 0, wait: 0, dir }
    }

    fn with_net(&self, mut cfg: Config) -> Config {
        let net = self.net.clone();
        cfg = cfg.with_test_transport(Arc::new(move |_p: &mut dyn FnMut(u8)| Ok(Box::new(net.transport()) as Box<dyn Transport>)));
        cfg.timing = fast();
        cfg
    }

    pub fn make_app(&mut self, cfg: Config) -> App { App::new(self.with_net(cfg)) }

    /// advance the scripted conversation by one small step per frame
    pub fn step(&mut self, me: &mut App, _frame: u32) {
        for (_, p) in &mut self.peers { p.poll(); }
        let ready = |a: &App| a.screen == Screen::Main;
        match self.stage {
            0 => { if me.screen == Screen::CreatePw { me.handle(Key::Enter); } else if ready(me) { self.stage = 1; } }
            1 => {
                for name in ["Alex", "Sam"] {
                    let mut p = App::new(self.with_net(Config::new(None, None, None, Profile::LowMem)));
                    p.handle(Key::Enter);
                    self.peers.push((name, p));
                }
                self.stage = 2;
            }
            2 => { if self.peers.iter().all(|(_, p)| ready(p)) { self.stage = 3; } }
            3 => {
                for n in ["Alex", "Sam", "Robin"] { me.handle(Key::Char('n')); typed(me, n); me.handle(Key::Enter); }
                for (_, p) in &mut self.peers { p.handle(Key::Char('n')); typed(p, "Me"); p.handle(Key::Enter); }
                self.stage = 4;
            }
            4 => {
                for (i, (name, p)) in self.peers.iter_mut().enumerate() {
                    select(me, i);
                    let (fm, fp) = (self.dir.join(format!("{name}-me.sbc")), self.dir.join(format!("{name}-peer.sbc")));
                    me.handle(Key::Char('e')); me.input = fm.to_string_lossy().into_owned(); me.handle(Key::Enter);
                    p.handle(Key::Char('e')); p.input = fp.to_string_lossy().into_owned(); p.handle(Key::Enter);
                    me.handle(Key::Char('I')); me.input = fp.to_string_lossy().into_owned(); me.handle(Key::Enter);
                    p.handle(Key::Char('I')); p.input = fm.to_string_lossy().into_owned(); p.handle(Key::Enter);
                }
                // Sam counts as verified, Alex stays unverified
                select(me, 1); me.handle(Key::Char('v')); me.handle(Key::Char('y'));
                select(me, 0);
                for (_, p) in &mut self.peers { p.handle(Key::Char('o')); }
                self.stage = 5;
            }
            5 => { // wait for the app's own auto-connect and the link
                self.wait += 1;
                if me.contact_rows().first().is_some_and(|r| r.3) || self.wait > 400 { self.stage = 6; self.wait = 0; }
            }
            6 => {
                if let Some((_, p)) = self.peers.first_mut() { p.handle(Key::Enter); p.handle(Key::Char('i')); typed(p, "hi, it's me! new phone, who dis?"); p.handle(Key::Enter); }
                self.stage = 7;
            }
            7 => {
                self.wait += 1;
                if self.wait > 30 {
                    select(me, 0); me.handle(Key::Enter); me.handle(Key::Char('i'));
                    typed(me, "Hey Alex. Which number did you have before?"); me.handle(Key::Enter);
                    self.stage = 8;
                }
            }
            _ => {}
        }
    }
}

impl Drop for Demo { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.dir); } }
