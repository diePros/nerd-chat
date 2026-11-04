//! LIVE test: two engines, each with its OWN tor, chat over the real Tor network. Needs `tor` in PATH + Internet.
//!   cargo test -p seburity-chat --test live_chat -- --ignored --nocapture
use seburity_chat::{transport::{TorSetup, TorTransport}, ContactCfg, Engine, Event, Timing};
use seburity_core::{bundle::Bundle, identity::ContactIdentity};
use seburity_net::tor::spawn::{find_tor, SpawnConfig};
use std::{thread, time::{Duration, Instant}};
use zeroize::Zeroizing;

fn wait<F: FnMut(&Event) -> bool>(e: &Engine, limit: Duration, mut f: F) -> bool {
    let end = Instant::now() + limit;
    while Instant::now() < end {
        if let Ok(ev) = e.events.recv_timeout(Duration::from_millis(200)) {
            if let Event::Notice { text, .. } = &ev { eprintln!("notice: {text}"); }
            if f(&ev) { return true; }
        }
    }
    false
}

#[test]
#[ignore = "needs tor and network"]
fn two_engines_chat_over_the_real_tor_network() {
    let tor = find_tor().expect("`tor` not found in PATH");
    let (a, b) = (ContactIdentity::generate(), ContactIdentity::generate());
    let (ab, bb) = (Bundle::from_identity(&a), Bundle::from_identity(&b));
    let start = |name: &'static str, tor: std::path::PathBuf| thread::spawn(move || {
        TorTransport::start(TorSetup::Spawn(SpawnConfig::new(tor)), move |p| if p % 20 == 0 { eprintln!("{name}: tor {p}%") }).expect("tor start")
    });
    let (ta, tb) = (start("A", tor.clone()), start("B", tor));
    let (ta, tb) = (ta.join().unwrap(), tb.join().unwrap());
    eprintln!("both tors ready");
    let id = [7u8; 8];
    let ea = Engine::start(Box::new(ta), vec![ContactCfg::new(id, &a, bb)], Timing::default());
    let eb = Engine::start(Box::new(tb), vec![ContactCfg::new(id, &b, ab)], Timing::default());
    let limit = Duration::from_secs(420); // descriptor publication + retries with backoff
    assert!(wait(&ea, limit, |e| matches!(e, Event::Connected { .. })), "A never connected");
    assert!(wait(&eb, limit, |e| matches!(e, Event::Connected { .. })), "B never connected");
    eprintln!("connected over Tor");
    ea.send(id, Zeroizing::new("hello from A over tor".into()));
    eb.send(id, Zeroizing::new("hello from B over tor".into()));
    assert!(wait(&eb, Duration::from_secs(90), |e| matches!(e, Event::Message { text, .. } if &***text == "hello from A over tor")));
    assert!(wait(&ea, Duration::from_secs(90), |e| matches!(e, Event::Message { text, .. } if &***text == "hello from B over tor")));
    ea.shutdown();
    eb.shutdown();
}
