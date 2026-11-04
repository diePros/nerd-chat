//! Text armor for bundles (`.sbc` file / paste / QR payload).
//! Strict parser: exact header/footer, canonical base64, hard size cap.
use crate::ExchangeError;
use base64::{engine::general_purpose::STANDARD, Engine};
use seburity_core::bundle::{Bundle, BUNDLE_LEN};

const HEAD: &str = "-----BEGIN SEBURITY CONTACT-----";
const FOOT: &str = "-----END SEBURITY CONTACT-----";
/// Anything larger than this is rejected before parsing.
const MAX_ARMOR: usize = 4096;

/// `bundle_bytes` is the output of `Bundle::encode` (self-signed).
pub fn armor(bundle_bytes: &[u8]) -> String {
    let b64 = STANDARD.encode(bundle_bytes);
    let mut out = String::from(HEAD);
    out.push('\n');
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap());
        out.push('\n');
    }
    out.push_str(FOOT);
    out.push('\n');
    out
}

pub fn dearmor(text: &str) -> Result<Bundle, ExchangeError> {
    if text.len() > MAX_ARMOR { return Err(ExchangeError::Malformed); }
    let mut lines = text.lines();
    if lines.next() != Some(HEAD) { return Err(ExchangeError::Malformed); }
    let mut b64 = String::new();
    let mut footer = false;
    for l in lines.by_ref() {
        if l == FOOT { footer = true; break; }
        if l.len() > 64 || l.is_empty() { return Err(ExchangeError::Malformed); }
        b64.push_str(l);
    }
    // nothing but (at most) blank trailing lines may follow the footer
    if !footer || lines.any(|l| !l.trim().is_empty()) { return Err(ExchangeError::Malformed); }
    let raw = STANDARD.decode(b64.as_bytes()).map_err(|_| ExchangeError::Malformed)?;
    if raw.len() != BUNDLE_LEN { return Err(ExchangeError::Malformed); }
    // Re-encoding must reproduce the input exactly (rejects non-canonical base64).
    if STANDARD.encode(&raw) != b64 { return Err(ExchangeError::Malformed); }
    Bundle::decode(&raw).map_err(|_| ExchangeError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use seburity_core::identity::ContactIdentity;

    #[test]
    fn roundtrip_and_rejections() {
        let id = ContactIdentity::generate();
        let b = Bundle::from_identity(&id);
        let text = armor(&b.encode(&id));
        assert_eq!(dearmor(&text).unwrap(), b);
        assert!(dearmor(&text.replace("BEGIN", "BEG1N")).is_err());
        assert!(dearmor(&text.replace(FOOT, "")).is_err());
        assert!(dearmor(&format!("{text}garbage")).is_err());
        assert!(dearmor(&"A".repeat(MAX_ARMOR + 1)).is_err());
        assert!(dearmor("").is_err());
        // flipping any base64 char must be rejected (self-signature / canonical form)
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate().skip(1).take(lines.len() - 2) {
            let mut c: Vec<u8> = line.bytes().collect();
            c[0] = if c[0] == b'A' { b'B' } else { b'A' };
            let mut v = lines.clone();
            let s = String::from_utf8(c).unwrap();
            v[i] = &s;
            assert!(dearmor(&(v.join("\n") + "\n")).is_err(), "line {i}");
        }
    }
}
