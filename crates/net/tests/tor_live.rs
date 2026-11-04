//! LIVE test: needs a real `tor` binary in PATH and Internet access. Run explicitly:
//!   cargo test -p seburity-net --test tor_live -- --ignored --nocapture
//! It spawns tor (RAM dir), hosts contact A's onion service (authorizing contact B), dials it as B, runs the full
//! handshake over the real Tor circuit and exchanges a message each way.
use seburity_core::{bundle::Bundle, identity::ContactIdentity};
use seburity_net::{guard::HandshakeGuard, link, tor::{spawn::{find_tor, SpawnConfig}, Target, Tor}};
use std::{os::unix::net::UnixListener, thread, time::{Duration, Instant}};

#[test]
#[ignore = "needs tor and network"]
fn two_contacts_chat_over_real_onion_service_with_client_auth() {
    let tor_path = find_tor().expect("`tor` not found in PATH (sudo apt install tor; sudo systemctl disable --now tor is fine)");
    let (a, b) = (ContactIdentity::generate(), ContactIdentity::generate());
    let (ab, bb) = (Bundle::from_identity(&a), Bundle::from_identity(&b));

    let mut tor = Tor::spawn(&SpawnConfig::new(tor_path), Duration::from_secs(240), |p| eprintln!("bootstrap {p}%")).expect("spawn tor");

    // A: listener that tor forwards to: a UNIX socket in a private directory (no TCP port any local user could reach)
    let dir = tempfile::Builder::new().prefix("sbt-").tempdir_in(if std::path::Path::new("/dev/shm").is_dir() { "/dev/shm" } else { "/tmp" }).unwrap();
    let sock = dir.path().join("a.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let local = Target::Unix(sock);
    let a2 = ContactIdentity::from_secret_bytes(&a.secret_bytes()).unwrap();
    let bb2 = bb.clone();
    let server = thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
        let (mut sess, first) = link::accept(&mut s, &a2, &bb2, &mut HandshakeGuard::new(0), 0).expect("accept");
        assert_eq!(&first.body[..], b"hello from B");
        use std::io::Write;
        s.write_all(&sess.send(&a2, b"hello from A").unwrap()).unwrap();
    });

    let id = tor.host(&a, &bb, &local).expect("ADD_ONION");
    eprintln!("hosting {id}.onion for the contact");
    tor.allow_dial(&b, &ab).expect("client auth add");

    // descriptor upload takes a while: retry the dial
    let start = Instant::now();
    let mut stream = loop {
        match tor.dial(&ab, &[7u8; 16]) {
            Ok(s) => break s,
            Err(e) if start.elapsed() < Duration::from_secs(180) => { eprintln!("dial not yet: {e}"); thread::sleep(Duration::from_secs(5)); }
            Err(e) => panic!("could not dial: {e}"),
        }
    };
    let mut sess = link::dial(&mut stream, &b, &ab, b"hello from B").expect("handshake over tor");
    let mut cell = vec![0u8; seburity_core::session::WIRE_CELL_LEN];
    use std::io::Read;
    stream.read_exact(&mut cell).unwrap();
    assert_eq!(&sess.recv(&b, &cell).unwrap().body[..], b"hello from A");
    server.join().unwrap();
}
