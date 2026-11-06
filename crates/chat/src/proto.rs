//! Application framing inside one signed message body: `kind(1) | payload`.
//! Long texts are split into chunks (a body is at most `MAX_BODY` bytes); the receiver reassembles with hard caps.
use nerd_chat_core::message::MAX_BODY;
use zeroize::{Zeroize, Zeroizing};

pub const KIND_TEXT_FINAL: u8 = 1;
pub const KIND_KEEPALIVE: u8 = 2;
pub const KIND_TEXT_CONT: u8 = 4;
/// Key rotation (docs/KEY_ROTATION.md): payload = new onion public key (32) | new client-auth public key (32); ACK and DONE echo it.
pub const KIND_ROTATE_OFFER: u8 = 0x20;
pub const KIND_ROTATE_ACK: u8 = 0x21;
pub const KIND_ROTATE_DONE: u8 = 0x22;

/// Body of a rotation frame.
pub fn encode_rotate(kind: u8, keys: &[u8; 64]) -> Vec<u8> { let mut v = Vec::with_capacity(65); v.push(kind); v.extend_from_slice(keys); v }
/// `Some(keys)` only for an exact-length frame.
pub fn parse_rotate(body: &[u8]) -> Option<[u8; 64]> { body.get(1..).and_then(|p| <[u8; 64]>::try_from(p).ok()) }
/// Payload bytes per chunk (one byte of the body is the kind).
pub const MAX_CHUNK: usize = MAX_BODY - 1;
/// Hard cap for one reassembled message.
pub const MAX_TEXT_BYTES: usize = 32 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum ProtoError { Empty, TooLong, BadUtf8 }

pub enum Incoming { Text(Zeroizing<String>), Keepalive, Ignored }

pub fn keepalive() -> Vec<u8> { vec![KIND_KEEPALIVE] }

/// Split `text` into chunk bodies on char boundaries. Empty text yields nothing.
pub fn encode_text(text: &str) -> Vec<Zeroizing<Vec<u8>>> {
    let mut out = Vec::new();
    let mut start = 0;
    while start < text.len() {
        let mut end = (start + MAX_CHUNK).min(text.len());
        while !text.is_char_boundary(end) { end -= 1; }
        let last = end == text.len();
        let mut body = Zeroizing::new(Vec::with_capacity(1 + end - start));
        body.push(if last { KIND_TEXT_FINAL } else { KIND_TEXT_CONT });
        body.extend_from_slice(&text.as_bytes()[start..end]);
        out.push(body);
        start = end;
    }
    out
}

/// Reassembles chunked texts. The buffer has its FINAL capacity from the start and never reallocates, so no
/// partial plaintext is ever left behind in freed heap (R6-L3).
pub struct Assembler { buf: Zeroizing<Vec<u8>> }

impl Default for Assembler { fn default() -> Self { Self::new() } }

impl Assembler {
    pub fn new() -> Self { Self { buf: Zeroizing::new(Vec::with_capacity(MAX_TEXT_BYTES)) } }

    pub fn feed(&mut self, body: &[u8]) -> Result<Incoming, ProtoError> {
        let (&kind, payload) = body.split_first().ok_or(ProtoError::Empty)?;
        match kind {
            KIND_KEEPALIVE => Ok(Incoming::Keepalive),
            KIND_TEXT_CONT | KIND_TEXT_FINAL => {
                if self.buf.len() + payload.len() > MAX_TEXT_BYTES { self.buf.zeroize(); self.buf.clear(); return Err(ProtoError::TooLong); }
                self.buf.extend_from_slice(payload);
                if kind == KIND_TEXT_CONT { return Ok(Incoming::Ignored); }
                // peer text can never steer a terminal or spoof direction (see `nerd_chat_core::text`)
                let r = std::str::from_utf8(&self.buf).map(nerd_chat_core::text::sanitize).map_err(|_| ProtoError::BadUtf8);
                self.buf.zeroize();
                self.buf.clear();
                r.map(Incoming::Text)
            }
            _ => Ok(Incoming::Ignored), // unknown kinds (future file transfer etc.) are skipped, never fatal
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(t: &str) -> String {
        let mut a = Assembler::new();
        let mut got = None;
        for c in encode_text(t) { if let Incoming::Text(s) = a.feed(&c).unwrap() { got = Some(s.to_string()); } }
        got.unwrap()
    }

    #[test]
    fn chunking_roundtrip_incl_unicode_boundaries() {
        assert_eq!(roundtrip("hi"), "hi");
        let long = "x".repeat(5000);
        assert_eq!(roundtrip(&long), long);
        // multi-byte chars straddling the chunk boundary must not be split
        let uni = "ü€😀".repeat(900);
        assert_eq!(roundtrip(&uni), uni);
        for c in encode_text(&uni) { assert!(c.len() <= MAX_BODY && std::str::from_utf8(&c[1..]).is_ok()); }
        assert_eq!(encode_text("").len(), 0);
        assert_eq!(encode_text(&"a".repeat(MAX_CHUNK)).len(), 1);
        assert_eq!(encode_text(&"a".repeat(MAX_CHUNK + 1)).len(), 2);
    }

    #[test]
    fn hostile_input_is_bounded_and_cleaned() {
        let mut a = Assembler::new();
        assert_eq!(a.feed(&[]).err(), Some(ProtoError::Empty));
        assert!(matches!(a.feed(&[KIND_KEEPALIVE]).unwrap(), Incoming::Keepalive));
        assert!(matches!(a.feed(&[99, 1, 2]).unwrap(), Incoming::Ignored), "unknown kinds are skipped");
        // endless continuation chunks hit the cap
        let chunk = [&[KIND_TEXT_CONT][..], &vec![b'a'; MAX_CHUNK]].concat();
        let mut err = None;
        for _ in 0..100 { if let Err(e) = a.feed(&chunk) { err = Some(e); break; } }
        assert_eq!(err, Some(ProtoError::TooLong));
        assert_eq!(a.feed(&[KIND_TEXT_FINAL, 0xff, 0xfe]).err(), Some(ProtoError::BadUtf8));
        // terminal escapes and bidi overrides are neutralised
        match a.feed(&[&[KIND_TEXT_FINAL][..], "a\x1b[2Jb\u{202E}c\x07".as_bytes()].concat()).unwrap() {
            Incoming::Text(t) => assert_eq!(&*t, "a?[2Jb?c?"),
            _ => panic!(),
        }
        // invisible / hidden-payload characters the first version missed (R6-L4)
        match a.feed(&[&[KIND_TEXT_FINAL][..], "x\u{061C}\u{2028}\u{E0041}\u{3164}\u{FE0F}y".as_bytes()].concat()).unwrap() {
            Incoming::Text(t) => assert_eq!(&*t, "x?????y"),
            _ => panic!(),
        }
        // the assembler never reallocates: its capacity is fixed from the start (no plaintext left in freed heap)
        let before = a.buf.as_ptr();
        for _ in 0..30 { let _ = a.feed(&[KIND_TEXT_CONT, b'z']); }
        assert_eq!(a.buf.as_ptr(), before);
        // keepalives may interleave with chunks
        let mut a = Assembler::new();
        a.feed(&[KIND_TEXT_CONT, b'a']).unwrap();
        a.feed(&[KIND_KEEPALIVE]).unwrap();
        match a.feed(&[KIND_TEXT_FINAL, b'b']).unwrap() { Incoming::Text(t) => assert_eq!(&*t, "ab"), _ => panic!() }
    }
}
