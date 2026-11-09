//! A hostile or squatting process on the Tor control port / SOCKS port answers with arbitrary bytes. Everything we parse from that
//! side (control replies, PROTOCOLINFO, GETINFO values, SOCKS5 replies) must never panic, never loop, never allocate without bound.
#![no_main]
use libfuzzer_sys::fuzz_target;
use sine_loco_net::tor::{control::Controller, socks};
use std::io::{Cursor, Read, Write};

/// What the "server" says (the fuzz input); everything we send is swallowed.
struct Fake { rx: Cursor<Vec<u8>> }
impl Read for Fake { fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> { self.rx.read(b) } }
impl Write for Fake {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> { Ok(b.len()) }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

fuzz_target!(|d: &[u8]| {
    let fake = || Fake { rx: Cursor::new(d.to_vec()) };
    let mut c = Controller::new(fake());
    let _ = c.read_reply();
    let mut c = Controller::new(fake());
    let _ = c.protocolinfo();
    let mut c = Controller::new(fake());
    let _ = c.get_info("status/bootstrap-phase");
    let mut c = Controller::new(fake());
    let _ = c.socks_listeners();
    let mut c = Controller::new(fake());
    let _ = c.bootstrap_progress();
    let _ = socks::connect(&mut fake(), "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion", 7345, Some((b"user", b"pass")));
    let _ = socks::connect(&mut fake(), "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion", 7345, None);
});
