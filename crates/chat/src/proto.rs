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
/// Delivery confirmation (docs/DELIVERY.md). A text with an id travels in `TEXT_ID_CONT`/`TEXT_ID_FINAL` frames (`kind | id(8) | payload`,
/// EVERY chunk carries the id, so a short text is still ONE cell, exactly like a text without id). The receiver answers with
/// `MSG_ACK | id(8) * k` (1..=MAX_ACKS ids) once ITS UI has the text. A peer without these frames still works (no ids, no acks).
pub const KIND_MSG_ACK: u8 = 0x31;
pub const KIND_TEXT_ID_CONT: u8 = 0x32;
pub const KIND_TEXT_ID_FINAL: u8 = 0x33;
/// Capability announcement, the FIRST frame our side sends on every connection: `CAPS | flags`. A peer that never sends it (v0.1.0, which
/// ignores unknown kinds) gets only the old plain text frames and no confirmation is expected from it.
pub const KIND_CAPS: u8 = 0x34;
/// Flag: "I understand `TEXT_ID_*` frames and will confirm them" (further bytes/flags are ignored, never an error).
pub const CAP_CONFIRM: u8 = 1;
pub fn encode_caps(flags: u8) -> Vec<u8> { vec![KIND_CAPS, flags] }
/// The flags byte of a capability frame; extra bytes of a later version are ignored.
pub fn parse_caps(body: &[u8]) -> Option<u8> { body.get(1).copied() }
/// Ids per confirmation frame (a frame is one cell: 1 + 8 * k <= MAX_BODY).
pub const MAX_ACKS: usize = 64;

/// Random per-message id (inside the encrypted session only; it never appears on the network).
pub type MsgId = [u8; 8];
pub fn new_msg_id() -> MsgId { let mut id = [0u8; 8]; getrandom::fill(&mut id).expect("OS RNG unavailable"); id }
/// Confirmation frame for 1..=MAX_ACKS ids (an empty or oversized list yields `None`: nothing to send).
pub fn encode_msg_acks(ids: &[MsgId]) -> Option<Vec<u8>> {
    if ids.is_empty() || ids.len() > MAX_ACKS { return None; }
    let mut v = Vec::with_capacity(1 + 8 * ids.len());
    v.push(KIND_MSG_ACK);
    for i in ids { v.extend_from_slice(i); }
    Some(v)
}
/// The ids of a confirmation frame; `None` unless it carries 1..=MAX_ACKS whole ids.
pub fn parse_msg_acks(body: &[u8]) -> Option<Vec<MsgId>> {
    let p = body.get(1..)?;
    if p.is_empty() || p.len() % 8 != 0 || p.len() / 8 > MAX_ACKS { return None; }
    Some(p.chunks_exact(8).map(|c| <MsgId>::try_from(c).expect("8 bytes")).collect())
}

/// Body of a rotation frame.
pub fn encode_rotate(kind: u8, keys: &[u8; 64]) -> Vec<u8> { let mut v = Vec::with_capacity(65); v.push(kind); v.extend_from_slice(keys); v }
/// `Some(keys)` only for an exact-length frame.
pub fn parse_rotate(body: &[u8]) -> Option<[u8; 64]> { body.get(1..).and_then(|p| <[u8; 64]>::try_from(p).ok()) }
/// NOTE: the delivery frames (0x31-0x33) are a FROZEN format of this release: a wrong length cuts the connection (conn.rs), so a later
/// change must use NEW kinds, never new lengths of these.
/// Payload bytes per chunk (one byte of the body is the kind).
pub const MAX_CHUNK: usize = MAX_BODY - 1;
/// Payload bytes per chunk of a text WITH an id.
pub const MAX_CHUNK_ID: usize = MAX_BODY - 9;
/// Hard cap for one reassembled message.
pub const MAX_TEXT_BYTES: usize = 32 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum ProtoError { Empty, TooLong, BadUtf8, /// chunks of one text disagree about the id, or an id chunk is shorter than its id
    BadId }

/// `Text(text, id)`: `id` is `None` for a peer that sends no ids.
pub enum Incoming { Text(Zeroizing<String>, Option<MsgId>), Keepalive, Ignored }

pub fn keepalive() -> Vec<u8> { vec![KIND_KEEPALIVE] }

/// Split `text` into chunk bodies on char boundaries. Empty text yields nothing.
pub fn encode_text(text: &str) -> Vec<Zeroizing<Vec<u8>>> { encode_chunks(text, None) }

/// Same, but every chunk carries the message id (`kind | id | payload`): the cell count of a text does not change.
pub fn encode_text_with_id(text: &str, id: &MsgId) -> Vec<Zeroizing<Vec<u8>>> { encode_chunks(text, Some(id)) }

fn encode_chunks(text: &str, id: Option<&MsgId>) -> Vec<Zeroizing<Vec<u8>>> {
    let (max, head) = if id.is_some() { (MAX_CHUNK_ID, 9) } else { (MAX_CHUNK, 1) };
    let mut out = Vec::new();
    let mut start = 0;
    while start < text.len() {
        let mut end = (start + max).min(text.len());
        while !text.is_char_boundary(end) { end -= 1; }
        let last = end == text.len();
        let mut body = Zeroizing::new(Vec::with_capacity(head + end - start));
        body.push(match (id.is_some(), last) { (false, true) => KIND_TEXT_FINAL, (false, false) => KIND_TEXT_CONT, (true, true) => KIND_TEXT_ID_FINAL, (true, false) => KIND_TEXT_ID_CONT });
        if let Some(id) = id { body.extend_from_slice(id); }
        body.extend_from_slice(&text.as_bytes()[start..end]);
        out.push(body);
        start = end;
    }
    out
}

/// Reassembles chunked texts. The buffer has its FINAL capacity from the start and never reallocates, so no
/// partial plaintext is ever left behind in freed heap (R6-L3).
pub struct Assembler { buf: Zeroizing<Vec<u8>>, /// the id of the text being assembled; `started` = a chunk of it was seen
    id: Option<MsgId>, started: bool }

impl Default for Assembler { fn default() -> Self { Self::new() } }

impl Assembler {
    pub fn new() -> Self { Self { buf: Zeroizing::new(Vec::with_capacity(MAX_TEXT_BYTES)), id: None, started: false } }

    fn reset(&mut self) { self.buf.zeroize(); self.buf.clear(); self.id = None; self.started = false; }

    pub fn feed(&mut self, body: &[u8]) -> Result<Incoming, ProtoError> {
        let (&kind, payload) = body.split_first().ok_or(ProtoError::Empty)?;
        match kind {
            KIND_KEEPALIVE => Ok(Incoming::Keepalive),
            KIND_TEXT_CONT | KIND_TEXT_FINAL | KIND_TEXT_ID_CONT | KIND_TEXT_ID_FINAL => {
                let with_id = matches!(kind, KIND_TEXT_ID_CONT | KIND_TEXT_ID_FINAL);
                let (id, payload) = if with_id {
                    let Some((i, rest)) = payload.split_first_chunk::<8>() else { self.reset(); return Err(ProtoError::BadId) };
                    (Some(*i), rest)
                } else { (None, payload) };
                // all chunks of one text agree about the id (or about having none): a mix is a protocol violation, never a way to
                // attach one text to another text's id
                if self.started && self.id != id { self.reset(); return Err(ProtoError::BadId); }
                self.started = true;
                self.id = id;
                if self.buf.len() + payload.len() > MAX_TEXT_BYTES { self.reset(); return Err(ProtoError::TooLong); }
                self.buf.extend_from_slice(payload);
                if matches!(kind, KIND_TEXT_CONT | KIND_TEXT_ID_CONT) { return Ok(Incoming::Ignored); }
                // peer text can never steer a terminal or spoof direction (see `nerd_chat_core::text`)
                let r = std::str::from_utf8(&self.buf).map(nerd_chat_core::text::sanitize).map_err(|_| ProtoError::BadUtf8);
                let id = self.id;
                self.reset();
                r.map(|t| Incoming::Text(t, id))
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
        for c in encode_text(t) { if let Incoming::Text(s, _) = a.feed(&c).unwrap() { got = Some(s.to_string()); } }
        got.unwrap()
    }

    #[test]
    fn confirmation_frames_carry_whole_ids_only() {
        let (a, b) = ([7, 1, 2, 3, 4, 5, 6, 8], [9u8; 8]);
        let f = encode_msg_acks(&[a, b]).unwrap();
        assert_eq!((f[0], f.len()), (KIND_MSG_ACK, 17));
        assert_eq!(parse_msg_acks(&f), Some(vec![a, b]));
        for n in 0..f.len() { if n != 9 { assert_eq!(parse_msg_acks(&f[..n]), None, "truncated to {n}"); } }
        assert_eq!(parse_msg_acks(&f[..9]), Some(vec![a]), "one whole id is a valid frame");
        assert_eq!(parse_msg_acks(&[f.as_slice(), &[0]].concat()), None, "a trailing byte");
        assert_eq!(encode_msg_acks(&[]), None);
        assert_eq!(encode_msg_acks(&vec![a; MAX_ACKS + 1]), None);
        let full = encode_msg_acks(&vec![a; MAX_ACKS]).unwrap();
        assert!(full.len() <= MAX_BODY, "a full list is still ONE cell");
        assert_eq!(parse_msg_acks(&full).map(|v| v.len()), Some(MAX_ACKS));
        assert_ne!(new_msg_id(), new_msg_id());
        // an old peer's assembler skips the confirmation frame (unknown kinds are never fatal)
        assert!(matches!(Assembler::new().feed(&f).unwrap(), Incoming::Ignored));
    }

    #[test]
    fn a_text_with_an_id_is_the_same_number_of_cells_as_without() {
        let id = [5u8; 8];
        for t in ["hi", "x".repeat(MAX_CHUNK_ID).as_str(), "ü".repeat(400).as_str()] {
            assert_eq!(encode_text_with_id(t, &id).len(), encode_text(t).len(), "{} bytes", t.len());
        }
        for c in encode_text_with_id(&"€".repeat(3000), &id) { assert!(c.len() <= MAX_BODY && c[1..9] == id); }
        let mut a = Assembler::new();
        let mut got = None;
        for c in encode_text_with_id(&"é€😀".repeat(700), &id) { if let Incoming::Text(s, i) = a.feed(&c).unwrap() { got = Some((s.to_string(), i)); } }
        assert_eq!(got, Some(("é€😀".repeat(700), Some(id))));
        // a text without id comes out without id
        let mut got = None;
        for c in encode_text("plain") { if let Incoming::Text(s, i) = a.feed(&c).unwrap() { got = Some((s.to_string(), i)); } }
        assert_eq!(got, Some(("plain".to_string(), None)));
    }

    #[test]
    fn chunks_of_one_text_must_agree_about_the_id() {
        let mut a = Assembler::new();
        assert!(matches!(a.feed(&[&[KIND_TEXT_ID_CONT][..], &[1; 8], b"abc"].concat()).unwrap(), Incoming::Ignored));
        assert_eq!(a.feed(&[&[KIND_TEXT_ID_FINAL][..], &[2; 8], b"def"].concat()).err(), Some(ProtoError::BadId), "another id mid-text");
        assert!(matches!(a.feed(&[&[KIND_TEXT_ID_CONT][..], &[1; 8], b"abc"].concat()).unwrap(), Incoming::Ignored));
        assert_eq!(a.feed(&[KIND_TEXT_FINAL, b'x']).err(), Some(ProtoError::BadId), "no id after an id");
        assert_eq!(a.feed(&[KIND_TEXT_ID_FINAL, 1, 2, 3]).err(), Some(ProtoError::BadId), "id shorter than 8 bytes");
        // after an error the assembler is clean: nothing of the broken text leaks into the next one
        match a.feed(&[&[KIND_TEXT_ID_FINAL][..], &[3; 8], b"ok"].concat()).unwrap() { Incoming::Text(t, i) => assert_eq!((t.as_str(), i), ("ok", Some([3; 8]))), _ => panic!() }
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
            Incoming::Text(t, _) => assert_eq!(&*t, "a?[2Jb?c?"),
            _ => panic!(),
        }
        // invisible / hidden-payload characters the first version missed (R6-L4)
        match a.feed(&[&[KIND_TEXT_FINAL][..], "x\u{061C}\u{2028}\u{E0041}\u{3164}\u{FE0F}y".as_bytes()].concat()).unwrap() {
            Incoming::Text(t, _) => assert_eq!(&*t, "x?????y"),
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
        match a.feed(&[KIND_TEXT_FINAL, b'b']).unwrap() { Incoming::Text(t, _) => assert_eq!(&*t, "ab"), _ => panic!() }
    }
}
