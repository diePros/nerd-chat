//! LIVE test: two engines, each with its OWN tor, chat over the real Tor network. Needs `tor` in PATH + Internet.
//!   cargo test -p sine-loco-chat --test live_chat -- --ignored --nocapture
use sine_loco_chat::{transport::{BoxStream, DialFn, TorSetup, TorTransport}, ContactCfg, Engine, Event, Timing, Transport};
use sine_loco_core::{bundle::Bundle, identity::ContactIdentity};
use sine_loco_net::tor::spawn::{find_tor, SpawnConfig};
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
    fn add_contact(&mut self, me: &ContactIdentity, peer: &Bundle, extra: &[[u8; 32]], listen: bool) -> Result<Option<std::sync::mpsc::Receiver<BoxStream>>, String> {
        if listen { Err("this tor refuses ADD_ONION".into()) } else { self.0.add_contact(me, peer, extra, false) }
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

/// Key rotation over the REAL Tor network: the host runs old + new onion service, the dialer switches to the new one after the
/// offer, the host retires the old service, and chat works again over the new address.
#[test]
#[ignore = "needs tor and network"]
fn key_rotation_works_over_real_tor() {
    use sine_loco_chat::proto::{KIND_ROTATE_ACK, KIND_ROTATE_DONE, KIND_ROTATE_OFFER};
    let tor = find_tor().expect("`tor` not found in PATH");
    let (host, dialer) = loop {
        let (x, y) = (ContactIdentity::generate(), ContactIdentity::generate());
        let (bx, by) = (Bundle::from_identity(&x), Bundle::from_identity(&y));
        if bx.sign_pub > by.sign_pub { break (x, y); }   // both can host: the SMALLER key dials, so `host` hosts
        if by.sign_pub > bx.sign_pub { break (y, x); }
    };
    let (hb, db) = (Bundle::from_identity(&host), Bundle::from_identity(&dialer));
    let t = ContactIdentity::fresh_transport_secret();
    let host2 = host.with_transport_secret(&t).unwrap();
    let hb2 = Bundle::from_identity(&host2);
    let start = |tor: std::path::PathBuf| thread::spawn(move || TorTransport::start(TorSetup::Spawn(SpawnConfig::new(tor)), |_| {}).expect("tor start"));
    let (t1, t2) = (start(tor.clone()), start(tor));
    let (t_host, t_dialer) = (t1.join().unwrap(), t2.join().unwrap());
    let id = [11u8; 8];
    let timing = Timing { min_backoff: Duration::from_secs(2), max_backoff: Duration::from_secs(20), ..Timing::default() };
    let e_host = Engine::start(Box::new(t_host), vec![ContactCfg::new(id, &host, db.clone()).with_rotation(&host, Some(&t), None)], timing);
    let e_dialer = Engine::start(Box::new(t_dialer), vec![ContactCfg::new(id, &dialer, hb.clone())], timing);
    let end = Instant::now() + Duration::from_secs(900);
    let (mut switched, mut committed, mut done_seen, mut reconnected) = (false, false, false, false);
    while Instant::now() < end && !(committed && done_seen && reconnected) {
        while let Ok(ev) = e_dialer.events.try_recv() {
            match ev {
                Event::Notice { text, .. } => eprintln!("dialer notice: {text}"),
                Event::Rotate { kind: KIND_ROTATE_OFFER, onion, auth, .. } if (onion, auth) == (hb2.onion_pub, hb2.auth_pub) => {
                    e_dialer.answer_rotation(id, KIND_ROTATE_ACK, onion, auth);
                    e_dialer.add(ContactCfg::new(id, &dialer, hb.clone().with_transport(onion, auth)).with_rotation(&dialer, None, Some((hb.onion_pub, hb.auth_pub))));
                    switched = true;
                    eprintln!("dialer switched to the new onion service");
                }
                Event::Rotate { kind: KIND_ROTATE_DONE, onion, auth, .. } if switched && (onion, auth) == (hb2.onion_pub, hb2.auth_pub) => done_seen = true,
                _ => {}
            }
        }
        while let Ok(ev) = e_host.events.try_recv() {
            match ev {
                Event::Notice { text, .. } => eprintln!("host notice: {text}"),
                Event::Connected { .. } if committed => { reconnected = true; eprintln!("host: connected again over the new service"); }
                Event::Rotate { kind: KIND_ROTATE_ACK, onion, auth, .. } if !committed && (onion, auth) == (hb2.onion_pub, hb2.auth_pub) => {
                    e_host.answer_rotation(id, KIND_ROTATE_DONE, onion, auth);
                    e_host.add(ContactCfg::new(id, &host2, db.clone()));
                    committed = true;
                    eprintln!("host committed: old onion service retired");
                }
                _ => {}
            }
        }
        thread::sleep(Duration::from_millis(200));
    }
    assert!(committed, "the host never received the acknowledgement");
    assert!(reconnected, "no connection over the NEW onion service (committed={committed}, done_seen={done_seen})");
    e_host.send(id, Zeroizing::new("after rotation, from the host".into()));
    assert!(wait(&e_dialer, Duration::from_secs(120), |e| matches!(e, Event::Message { text, .. } if &***text == "after rotation, from the host")));
    e_dialer.shutdown();
    e_host.shutdown();
}
