//! File transfer frames (all travel inside the signed + encrypted session cells; nothing is ever written to disk here).
//!
//! Privacy/security rules:
//! * NO file name and no MIME type ever goes on the wire (the receiver names the file itself).
//! * The sender strips metadata first (`sine-loco-strip`); the receiver re-strips (quarantine) and uses ITS copy.
//! * The receiver must ACCEPT an offer before a single content byte is sent (no unsolicited bulk data, no RAM exhaustion).
//! * The stream is `len(4) | content | zeros`, padded to a power-of-two bucket: the offer carries ONLY the bucket, so neither the
//!   network nor the receiver-before-accepting learns the exact length (the length travels inside the accepted stream).
//! * Integrity: BLAKE2s-256 of the true content is in the (signed) offer; one transfer at a time per connection; hard caps.
use blake2::{Blake2s256, Digest};
use sine_loco_core::message::MAX_BODY;

pub const KIND_FILE_OFFER: u8 = 5;
pub const KIND_FILE_CHUNK: u8 = 6;
pub const KIND_FILE_ACCEPT: u8 = 7;
pub const KIND_FILE_REJECT: u8 = 8;

pub const MAX_FILE: usize = 8 * 1024 * 1024;
pub const MIN_BUCKET: usize = 16 * 1024;
pub const CHUNK_DATA: usize = MAX_BODY - 1 - 8;
pub const OFFER_LEN: usize = 1 + 8 + 4 + 1 + 32;
/// Content limit: the 4-byte length prefix must fit in the largest bucket.
pub const MAX_CONTENT: usize = MAX_FILE - 4;
/// Offer `mode`: how the receiver must clean (it never trusts the sender's cleaning).
pub const MODE_AUTO: u8 = 0;
pub const MODE_TEXT: u8 = 1;

pub type Xid = [u8; 8];

/// Bucket (power of two, >= 16 KiB) for `content_len` bytes of content (+4 length prefix). `None` if empty or too big.
pub fn bucket_for(content_len: usize) -> Option<usize> {
    if content_len == 0 || content_len > MAX_CONTENT { return None; }
    Some((content_len + 4).next_power_of_two().max(MIN_BUCKET))
}

pub fn valid_bucket(b: usize) -> bool { b.is_power_of_two() && (MIN_BUCKET..=MAX_FILE).contains(&b) }

/// `len(4 BE) | content | zero padding` up to the bucket.
pub fn build_stream(content: &[u8]) -> Option<Vec<u8>> {
    let b = bucket_for(content.len())?;
    let mut v = Vec::with_capacity(b);
    v.extend_from_slice(&(content.len() as u32).to_be_bytes());
    v.extend_from_slice(content);
    v.resize(b, 0);
    Some(v)
}

/// Inverse of `build_stream`: returns the content slice if the layout, bucket and zero padding are exactly right.
pub fn parse_stream(stream: &[u8]) -> Option<&[u8]> {
    if !valid_bucket(stream.len()) { return None; }
    let len = u32::from_be_bytes(stream[..4].try_into().ok()?) as usize;
    if len == 0 || bucket_for(len)? != stream.len() { return None; }
    let (content, pad) = stream[4..].split_at(len);
    if pad.iter().any(|&b| b != 0) { return None; }
    Some(content)
}

pub fn hash(data: &[u8]) -> [u8; 32] { Blake2s256::digest(data).into() }

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Offer { pub xid: Xid, /// padded stream size (a valid bucket)
    pub bucket: u32, pub mode: u8, pub hash: [u8; 32] }

pub fn encode_offer(o: &Offer) -> Vec<u8> {
    let mut v = Vec::with_capacity(OFFER_LEN);
    v.push(KIND_FILE_OFFER); v.extend_from_slice(&o.xid); v.extend_from_slice(&o.bucket.to_be_bytes()); v.push(o.mode); v.extend_from_slice(&o.hash);
    v
}

pub fn parse_offer(body: &[u8]) -> Option<Offer> {
    if body.len() != OFFER_LEN || body[0] != KIND_FILE_OFFER { return None; }
    let mode = body[13];
    if mode > MODE_TEXT { return None; }
    Some(Offer { xid: body[1..9].try_into().ok()?, bucket: u32::from_be_bytes(body[9..13].try_into().ok()?), mode, hash: body[14..46].try_into().ok()? })
}

pub fn encode_ctl(kind: u8, xid: &Xid) -> Vec<u8> { let mut v = vec![kind]; v.extend_from_slice(xid); v }
pub fn parse_ctl(body: &[u8]) -> Option<Xid> { if body.len() == 9 { body[1..9].try_into().ok() } else { None } }

pub fn encode_chunk(xid: &Xid, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(9 + data.len());
    v.push(KIND_FILE_CHUNK); v.extend_from_slice(xid); v.extend_from_slice(data);
    v
}
pub fn parse_chunk(body: &[u8]) -> Option<(Xid, &[u8])> {
    if body.len() < 10 || body[0] != KIND_FILE_CHUNK || body.len() > 9 + CHUNK_DATA { return None; }
    Some((body[1..9].try_into().ok()?, &body[9..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_hide_exact_size_and_the_stream_layout_is_strict() {
        assert_eq!(bucket_for(0), None);
        assert_eq!(bucket_for(MAX_CONTENT + 1), None);
        assert_eq!(bucket_for(1), Some(MIN_BUCKET));
        assert_eq!(bucket_for(MIN_BUCKET - 4), Some(MIN_BUCKET));
        assert_eq!(bucket_for(MIN_BUCKET - 3), Some(2 * MIN_BUCKET));
        assert_eq!(bucket_for(MAX_CONTENT), Some(MAX_FILE));
        assert_eq!(bucket_for(3_000_000), bucket_for(4_000_000));
        let s = build_stream(b"hello").unwrap();
        assert_eq!(s.len(), MIN_BUCKET);
        assert_eq!(parse_stream(&s), Some(&b"hello"[..]));
        let mut bad = s.clone(); bad[100] = 1; assert!(parse_stream(&bad).is_none(), "non-zero padding");
        let mut bad = s.clone(); bad[..4].copy_from_slice(&0u32.to_be_bytes()); assert!(parse_stream(&bad).is_none(), "zero length");
        let mut bad = s.clone(); bad[..4].copy_from_slice(&(MIN_BUCKET as u32).to_be_bytes()); assert!(parse_stream(&bad).is_none(), "length beyond bucket");
        let mut bad = s.clone(); bad[..4].copy_from_slice(&40_000u32.to_be_bytes()); assert!(parse_stream(&bad).is_none(), "bucket does not match length");
        assert!(parse_stream(&s[..s.len() - 1]).is_none());
        assert!(!valid_bucket(MIN_BUCKET + 1) && !valid_bucket(MIN_BUCKET / 2) && !valid_bucket(MAX_FILE * 2) && valid_bucket(MAX_FILE));
    }

    #[test]
    fn frames_roundtrip_and_reject_garbage() {
        let o = Offer { xid: [1; 8], bucket: 16384, mode: MODE_AUTO, hash: hash(b"x") };
        assert_eq!(parse_offer(&encode_offer(&o)), Some(o));
        assert_eq!(parse_offer(&[KIND_FILE_OFFER; 10]), None);
        let mut bad = encode_offer(&o); bad[13] = 9; assert_eq!(parse_offer(&bad), None, "unknown mode");
        assert_eq!(parse_ctl(&encode_ctl(KIND_FILE_ACCEPT, &[7; 8])), Some([7; 8]));
        assert_eq!(parse_ctl(&[KIND_FILE_ACCEPT]), None);
        let c = encode_chunk(&[2; 8], &[9; 100]);
        assert_eq!(parse_chunk(&c).unwrap().1.len(), 100);
        assert!(parse_chunk(&encode_chunk(&[2; 8], &[])).is_none(), "empty chunk");
        assert!(parse_chunk(&encode_chunk(&[2; 8], &vec![0; CHUNK_DATA + 1])).is_none(), "oversize chunk");
        assert!(encode_chunk(&[2; 8], &vec![0; CHUNK_DATA]).len() <= MAX_BODY);
    }
}
