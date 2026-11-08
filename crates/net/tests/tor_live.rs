//! LIVE test: needs a real `tor` binary in PATH and Internet access. Run explicitly:
//!   cargo test -p nerd-chat-net --test tor_live -- --ignored --nocapture
//! It spawns tor (RAM dir), hosts contact A's onion service (authorizing contact B), dials it as B, runs the full
//! handshake over the real Tor circuit and exchanges a message each way.
use nerd_chat_core::{bundle::Bundle, identity::ContactIdentity};
use nerd_chat_net::{guard::HandshakeGuard, link, tor::{spawn::{find_tor, SpawnConfig}, Target, Tor}};
use std::{os::unix::net::UnixListener, thread, time::{Duration, Instant}};

#[test]
#[ignore = "needs tor and network"]
fn two_contacts_chat_over_real_onion_service_with_client_auth() {
    let tor_path = find_tor().expect("`tor` not found in PATH (sudo apt install tor; sudo systemctl disable --now tor is fine)");
    let (a, b) = (ContactIdentity::generate(), ContactIdentity::generate());
    let (ab, bb) = (Bundle::from_identity(&a), Bundle::from_identity(&b));

    let mut tor = Tor::spawn(&SpawnConfig::new(tor_path), Duration::from_secs(240), |p| eprintln!("bootstrap {p}%")).expect("spawn tor");

    // A: listener that tor forwards to: a UNIX socket in a private directory (no TCP port any local user could reach)
    // (the same place the app uses: tor's own RAM directory. Distribution AppArmor profiles such as Ubuntu's `system_tor`
    // stop tor from connecting to sockets anywhere else, e.g. /dev/shm: "connection refused by the target")
    let sock = tor.spawn_dir().expect("spawned tor has a directory").join("a.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let local = Target::Unix(sock);
    let a2 = ContactIdentity::from_secret_bytes(&a.secret_bytes()).unwrap();
    let bb2 = bb.clone();
    let server = thread::spawn(move || {
        // Tor may open (and drop) a connection before the real dialer arrives: keep listening until one completes the handshake
        let mut guard = HandshakeGuard::new(0);
        let (mut s, mut sess, first) = loop {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
            match link::accept(&mut s, &a2, &bb2, &mut guard, 0) {
                Ok((sess, first)) => break (s, sess, first),
                Err(e) => eprintln!("early/failed inbound connection ignored: {e:?}"),
            }
        };
        assert_eq!(&first.body[..], b"hello from B");
        use std::io::Write;
        s.write_all(&sess.send(&a2, b"hello from A").unwrap()).unwrap();
    });

    let id = tor.host_with(&a, &bb, &[], &local).expect("ADD_ONION");
    eprintln!("hosting {id}.onion for the contact");
    tor.allow_dial(&b, &ab).expect("client auth add");

    // descriptor upload takes a while: retry the dial
    let start = Instant::now();
    let mut stream = loop {
        match tor.dialer().dial(&ab, &[7u8; 16]) {
            Ok(s) => break s,
            Err(e) if start.elapsed() < Duration::from_secs(180) => { eprintln!("dial not yet: {e}"); thread::sleep(Duration::from_secs(5)); }
            Err(e) => panic!("could not dial: {e}"),
        }
    };
    let mut sess = link::dial(&mut stream, &b, &ab, b"hello from B").expect("handshake over tor");
    let mut cell = vec![0u8; nerd_chat_core::session::WIRE_CELL_LEN];
    use std::io::Read;
    stream.read_exact(&mut cell).unwrap();
    assert_eq!(&sess.recv(&b, &cell).unwrap().body[..], b"hello from A");
    server.join().unwrap();
}
