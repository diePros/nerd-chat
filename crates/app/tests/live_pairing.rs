//! LIVE test (needs `tor` in PATH and Internet): two apps, each with its OWN spawned Tor, pair over the real Tor network through the
//! real screens: offer (public one-shot onion service, link shown only after the descriptor was uploaded) and join (SOCKS dial).
//!   cargo test -p sine-loco-app --test live_pairing -- --ignored --nocapture
use sine_loco_app::app::{App, Config, Key, Online, Screen};
use sine_loco_vault::Profile;
use std::{thread, time::{Duration, Instant}};

fn typed(a: &mut App, s: &str) { for c in s.chars() { a.handle(Key::Char(c)); } }

fn new_app() -> App {
    let mut a = App::new(Config::new(None, None, None, Profile::LowMem)); // RAM-only: random internal password
    a.handle(Key::Enter);
    let t = Instant::now();
    while a.screen != Screen::Main && t.elapsed() < Duration::from_secs(60) { a.poll(); thread::sleep(Duration::from_millis(50)); }
    assert_eq!(a.screen, Screen::Main, "{}", a.status);
    a
}

fn pump(apps: &mut [&mut App], secs: u64, mut done: impl FnMut(&[&mut App]) -> bool) -> bool {
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(secs) {
        for a in apps.iter_mut() { a.poll(); }
        if done(apps) { return true; }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

#[test]
#[ignore = "needs tor and network"]
fn pairing_over_the_real_tor_network_through_the_screens() {
    sine_loco_app::startup::startup(&[]); // what every front end runs first
    let mut a = new_app(); a.handle(Key::Char('n')); typed(&mut a, "bob"); a.handle(Key::Enter);
    let mut b = new_app(); b.handle(Key::Char('n')); typed(&mut b, "alice"); b.handle(Key::Enter);
    a.handle(Key::Char('o')); b.handle(Key::Char('o'));
    assert!(pump(&mut [&mut a, &mut b], 420, |x| x[0].online == Online::Online && x[1].online == Online::Online), "tor did not come up: {} / {}", a.status, b.status);
    eprintln!("both online");

    let start = Instant::now();
    a.handle(Key::Char('T'));
    assert!(pump(&mut [&mut a, &mut b], 300, |x| x[0].tor_offer.is_some() || x[0].error), "no link: {}", a.status);
    let o = a.tor_offer.as_ref().unwrap_or_else(|| panic!("offer failed: {}", a.status));
    let (link, code) = (o.link.to_string(), o.code.to_string());
    eprintln!("link ready after {:?}: {link}", start.elapsed());

    b.handle(Key::Char('J')); typed(&mut b, &link); b.handle(Key::Enter);
    typed(&mut b, &code); b.handle(Key::Enter);
    let finished = |x: &[&mut App]| x.iter().all(|a| a.alerts.iter().any(|(t, _)| t.contains("Pairing finished")));
    assert!(pump(&mut [&mut a, &mut b], 420, finished), "pairing did not finish: {} / {}", a.status, b.status);
    eprintln!("paired after {:?}", start.elapsed());
    a.handle(Key::Char('P')); b.handle(Key::Char('P'));
    typed(&mut a, "y"); a.handle(Key::Enter); typed(&mut b, "y"); b.handle(Key::Enter);
    assert_eq!(a.selected_detail().unwrap().2, b.selected_detail().unwrap().2, "same safety number");
    assert!(a.tor_offer.is_none(), "the offer is over");
    // the one-shot service must be gone: a second dial of the same link must fail
    b.handle(Key::Char('n')); typed(&mut b, "carol"); b.handle(Key::Enter);
    b.handle(Key::Char('J')); typed(&mut b, &link); b.handle(Key::Enter); typed(&mut b, &code); b.handle(Key::Enter);
    assert!(pump(&mut [&mut a, &mut b], 200, |x| x[1].error && x[1].status.contains("new link")), "a second dial must fail with a clear message: {}", b.status);
}
