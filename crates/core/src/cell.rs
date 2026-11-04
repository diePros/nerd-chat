//! Fixed-size cells: every ciphertext on the wire is exactly CELL_LEN bytes
//! so message length is hidden. Payload is length-prefixed and zero-padded.
use crate::Error;

pub const CELL_LEN: usize = 1024;
pub const CELL_PAYLOAD_MAX: usize = CELL_LEN - 2;

pub fn pad(payload: &[u8]) -> Result<[u8; CELL_LEN], Error> {
    if payload.len() > CELL_PAYLOAD_MAX { return Err(Error::TooLarge); }
    let mut c = [0u8; CELL_LEN];
    c[..2].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    c[2..2 + payload.len()].copy_from_slice(payload);
    Ok(c)
}

/// Strict: length must fit and ALL padding must be zero (no covert channel / malleability).
pub fn unpad(cell: &[u8]) -> Result<&[u8], Error> {
    if cell.len() != CELL_LEN { return Err(Error::Malformed); }
    let n = u16::from_be_bytes([cell[0], cell[1]]) as usize;
    if n > CELL_PAYLOAD_MAX { return Err(Error::Malformed); }
    if cell[2 + n..].iter().any(|&b| b != 0) { return Err(Error::Malformed); }
    Ok(&cell[2..2 + n])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_all_sizes_edges() {
        for n in [0, 1, 100, CELL_PAYLOAD_MAX] {
            let p = vec![7u8; n];
            assert_eq!(unpad(&pad(&p).unwrap()).unwrap(), &p[..]);
        }
        assert_eq!(pad(&vec![0; CELL_PAYLOAD_MAX + 1]).unwrap_err(), Error::TooLarge);
    }
    #[test]
    fn rejects_bad_length_and_dirty_padding() {
        let mut c = pad(b"hi").unwrap();
        c[500] = 1;
        assert!(unpad(&c).is_err());
        let mut c = pad(b"hi").unwrap();
        c[0] = 0xff; c[1] = 0xff;
        assert!(unpad(&c).is_err());
        assert!(unpad(&[0u8; 10]).is_err());
    }
}
