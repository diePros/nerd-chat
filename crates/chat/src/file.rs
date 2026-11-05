//! File transfer frames (all travel inside the signed + encrypted session cells; nothing is ever written to disk here).
//!
//! Privacy/security rules:
//! * NO file name and no MIME type ever goes on the wire (the receiver names the file itself).
//! * The sender strips metadata first (`seburity-strip`); the receiver re-strips (quarantine) and uses ITS copy.
//! * The receiver must ACCEPT an offer before a single content byte is sent (no unsolicited bulk data, no RAM exhaustion).
//! * The stream is zero-padded to a size bucket, so only the bucket (not the exact length) is visible as traffic volume.
//! * Integrity: BLAKE2s-256 of the true content is in the (signed) offer; one transfer at a time per connection; hard caps.
use blake2::{Blake2s256, Digest};
use seburity_core::message::MAX_BODY;

pub const KIND_FILE_OFFER: u8 = 5;
pub const KIND_FILE_CHUNK: u8 = 6;
pub const KIND_FILE_ACCEPT: u8 = 7;
pub const KIND_FILE_REJECT: u8 = 8;

pub const MAX_FILE: usize = 8 * 1024 * 1024;
pub const MIN_BUCKET: usize = 16 * 1024;
pub const CHUNK_DATA: usize = MAX_BODY - 1 - 8;
pub const OFFER_LEN: usize = 1 + 8 + 4 + 32;

pub type Xid = [u8; 8];

/// Size bucket (power of two, >= 16 KiB) the stream is padded to. `None` if `len` is 0 or above `MAX_FILE`.
pub fn padded_len(len: usize) -> Option<usize> {
    if len == 0 || len > MAX_FILE { return None; }
    Some(len.next_power_of_two().max(MIN_BUCKET))
}

pub fn hash(data: &[u8]) -> [u8; 32] { Blake2s256::digest(data).into() }

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Offer { pub xid: Xid, pub len: u32, pub hash: [u8; 32] }

pub fn encode_offer(o: &Offer) -> Vec<u8> {
    let mut v = Vec::with_capacity(OFFER_LEN);
    v.push(KIND_FILE_OFFER); v.extend_from_slice(&o.xid); v.extend_from_slice(&o.len.to_be_bytes()); v.extend_from_slice(&o.hash);
    v
}

pub fn parse_offer(body: &[u8]) -> Option<Offer> {
    if body.len() != OFFER_LEN || body[0] != KIND_FILE_OFFER { return None; }
    Some(Offer { xid: body[1..9].try_into().ok()?, len: u32::from_be_bytes(body[9..13].try_into().ok()?), hash: body[13..45].try_into().ok()? })
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
    fn buckets_hide_exact_size() {
        assert_eq!(padded_len(0), None);
        assert_eq!(padded_len(MAX_FILE + 1), None);
        assert_eq!(padded_len(1), Some(MIN_BUCKET));
        assert_eq!(padded_len(16 * 1024), Some(16 * 1024));
        assert_eq!(padded_len(16 * 1024 + 1), Some(32 * 1024));
        assert_eq!(padded_len(MAX_FILE), Some(MAX_FILE));
        assert_eq!(padded_len(3_000_000), padded_len(4_000_000));
    }

    #[test]
    fn frames_roundtrip_and_reject_garbage() {
        let o = Offer { xid: [1; 8], len: 1234, hash: hash(b"x") };
        assert_eq!(parse_offer(&encode_offer(&o)), Some(o));
        assert_eq!(parse_offer(&[KIND_FILE_OFFER; 10]), None);
        assert_eq!(parse_ctl(&encode_ctl(KIND_FILE_ACCEPT, &[7; 8])), Some([7; 8]));
        assert_eq!(parse_ctl(&[KIND_FILE_ACCEPT]), None);
        let c = encode_chunk(&[2; 8], &[9; 100]);
        assert_eq!(parse_chunk(&c).unwrap().1.len(), 100);
        assert!(parse_chunk(&encode_chunk(&[2; 8], &[])).is_none(), "empty chunk");
        assert!(parse_chunk(&encode_chunk(&[2; 8], &vec![0; CHUNK_DATA + 1])).is_none(), "oversize chunk");
        assert!(encode_chunk(&[2; 8], &vec![0; CHUNK_DATA]).len() <= MAX_BODY);
    }
}
