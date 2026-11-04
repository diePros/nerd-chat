//! Fixed-capacity secret input buffer: never reallocates (so no stale copies), wiped on drop/clear.
use zeroize::Zeroizing;

pub const SECRET_MAX: usize = 256;

pub struct SecretBuf(Zeroizing<Vec<u8>>);

impl Default for SecretBuf { fn default() -> Self { Self::new() } }

impl SecretBuf {
    pub fn new() -> Self { Self(Zeroizing::new(Vec::with_capacity(SECRET_MAX))) }
    pub fn push(&mut self, c: char) -> bool {
        let mut b = [0u8; 4];
        let s = c.encode_utf8(&mut b);
        if c.is_control() || self.0.len() + s.len() > SECRET_MAX { return false; }
        self.0.extend_from_slice(s.as_bytes());
        true
    }
    pub fn pop(&mut self) {
        while let Some(b) = self.0.pop() { if b & 0xC0 != 0x80 { break; } }
    }
    pub fn as_bytes(&self) -> &[u8] { &self.0 }
    pub fn chars(&self) -> usize { String::from_utf8_lossy(&self.0).chars().count() }
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn is_empty(&self) -> bool { self.0.is_empty() }
    pub fn eq(&self, o: &SecretBuf) -> bool { self.0.len() == o.0.len() && self.0.iter().zip(o.0.iter()).fold(0u8, |d, (a, b)| d | (a ^ b)) == 0 }
    pub fn clear(&mut self) { use zeroize::Zeroize; self.0.zeroize(); self.0.clear(); }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_capacity_never_reallocates_and_wipes() {
        let mut s = SecretBuf::new();
        let p = s.0.as_ptr();
        for _ in 0..SECRET_MAX { assert!(s.push('a')); }
        assert!(!s.push('a'), "cap enforced");
        assert_eq!(s.0.as_ptr(), p, "no reallocation => no stale copies");
        s.clear();
        assert!(s.is_empty());
    }
    #[test]
    fn multibyte_pop_and_control_rejected() {
        let mut s = SecretBuf::new();
        s.push('a'); s.push('ü'); s.push('€');
        assert_eq!(s.chars(), 3);
        s.pop(); s.pop();
        assert_eq!(s.as_bytes(), b"a");
        assert!(!s.push('\n') && !s.push('\x1b'));
    }
}
