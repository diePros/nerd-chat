//! LIVE test: two engines, each with its OWN tor, chat over the real Tor network. Needs `tor` in PATH + Internet.
//!   cargo test -p seburity-chat --test live_chat -- --ignored --nocapture
use seburity_chat::{transport::{BoxStream, DialFn, TorSetup, TorTransport}, ContactCfg, Engine, Event, Timing, Transport};
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

/// A real Tor that refuses to host onion services (what a Tails with a restricted control port would look like).
struct NoHostTor(TorTransport);
impl Transport for NoHostTor {
    fn add_contact(&mut self, me: &ContactIdentity, peer: &Bundle, listen: bool) -> Result<Option<std::sync::mpsc::Receiver<BoxStream>>, String> {
        if listen { Err("this tor refuses ADD_ONION".into()) } else { self.0.add_contact(me, peer, false) }
    }
    fn remove_contact(&mut self, a: &[u8; 32], b: &[u8; 32]) { self.0.remove_contact(a, b) }
    fn dial_fn(&self) -> DialFn { self.0.dial_fn() }
}

#[test]
#[ignore = "needs tor and network"]
fn chat_works_over_real_tor_when_one_side_cannot_host() {
    let tor = find_tor().expect("`tor` not found in PATH");
    // make `host` the designated host (the LARGER signing key) and let it be the one whose tor refuses to host
    let (host, dialer) = loop {
        let (x, y) = (ContactIdentity::generate(), ContactIdentity::generate());
        let (bx, by) = (Bundle::from_identity(&x), Bundle::from_identity(&y));
        if bx.sign_pub > by.sign_pub { break (x, y); }
        if by.sign_pub > bx.sign_pub { break (y, x); }
    };
    // the side whose tor refuses to host says so in its (signed) bundle: the roles follow, nothing is published speculatively
    let (hb, db) = (Bundle::from_identity(&host).with_can_host(false), Bundle::from_identity(&dialer));
    let start = |tor: std::path::PathBuf| thread::spawn(move || TorTransport::start(TorSetup::Spawn(SpawnConfig::new(tor)), |_| {}).expect("tor start"));
    let (t1, t2) = (start(tor.clone()), start(tor));
    let (t_host, t_dialer) = (t1.join().unwrap(), t2.join().unwrap());
    let id = [9u8; 8];
    let timing = Timing { min_backoff: Duration::from_secs(2), ..Timing::default() };
    let e_host = Engine::start(Box::new(NoHostTor(t_host)), vec![ContactCfg::new(id, &host, db).with_caps(false, false)], timing);
    let e_dialer = Engine::start(Box::new(t_dialer), vec![ContactCfg::new(id, &dialer, hb)], timing);
    let limit = Duration::from_secs(420);
    assert!(wait(&e_host, limit, |e| matches!(e, Event::Connected { .. })), "the side that cannot host never connected");
    assert!(wait(&e_dialer, limit, |e| matches!(e, Event::Connected { .. })), "the side that can host never connected");
    e_host.send(id, Zeroizing::new("from the side that cannot host".into()));
    e_dialer.send(id, Zeroizing::new("from the side that hosts".into()));
    assert!(wait(&e_dialer, Duration::from_secs(90), |e| matches!(e, Event::Message { text, .. } if &***text == "from the side that cannot host")));
    assert!(wait(&e_host, Duration::from_secs(90), |e| matches!(e, Event::Message { text, .. } if &***text == "from the side that hosts")));
    e_host.shutdown();
    e_dialer.shutdown();
}
