//! The responder side of the Noise handshake, fed hostile bytes as message 1 and as the first cell (what anyone who can reach an onion
//! service and holds its client-auth key can send). Identities are generated once per process; only the input varies. Must never panic and never succeed.
#![no_main]
use libfuzzer_sys::fuzz_target;
use nerd_chat_core::{bundle::Bundle, identity::ContactIdentity};
use nerd_chat_net::{guard::HandshakeGuard, link};
use std::{io::{Cursor, Read, Write}, sync::OnceLock};

struct Pipe(Cursor<Vec<u8>>);
impl Read for Pipe { fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> { self.0.read(b) } }
impl Write for Pipe { fn write(&mut self, b: &[u8]) -> std::io::Result<usize> { Ok(b.len()) } fn flush(&mut self) -> std::io::Result<()> { Ok(()) } }

static IDS: OnceLock<(ContactIdentity, Bundle)> = OnceLock::new();

fuzz_target!(|d: &[u8]| {
    let (me, peer) = IDS.get_or_init(|| (ContactIdentity::generate(), Bundle::from_identity(&ContactIdentity::generate())));
    let mut s = Pipe(Cursor::new(d.to_vec()));
    let r = link::accept(&mut s, me, peer, &mut HandshakeGuard::new(0), 0);
    assert!(r.is_err(), "random bytes must never complete a handshake");
});
