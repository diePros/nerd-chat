//! Fixed-capacity input buffers: never reallocate (so no stale copies), wiped on drop/clear.
use zeroize::Zeroizing;

pub const SECRET_MAX: usize = 256;
pub const COMPOSE_MAX: usize = 2048;

pub struct FixedBuf<const N: usize>(Zeroizing<Vec<u8>>);

/// Passwords, codes.
pub type SecretBuf = FixedBuf<SECRET_MAX>;
/// The message being typed.
pub type ComposeBuf = FixedBuf<COMPOSE_MAX>;

impl<const N: usize> Default for FixedBuf<N> { fn default() -> Self { Self::new() } }

impl<const N: usize> FixedBuf<N> {
    pub fn new() -> Self { Self(Zeroizing::new(Vec::with_capacity(N))) }
    pub fn push(&mut self, c: char) -> bool {
        let mut b = [0u8; 4];
        let s = c.encode_utf8(&mut b);
        if c.is_control() || self.0.len() + s.len() > N { return false; }
        self.0.extend_from_slice(s.as_bytes());
        true
    }
    pub fn pop(&mut self) {
        while let Some(b) = self.0.pop() { if b & 0xC0 != 0x80 { break; } }
    }
    pub fn as_bytes(&self) -> &[u8] { &self.0 }
    /// The text as a borrowed &str (empty if somehow invalid): rendering needs no copy.
    pub fn as_str(&self) -> &str { std::str::from_utf8(&self.0).unwrap_or("") }
    pub fn chars(&self) -> usize { self.as_str().chars().count() }
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn is_empty(&self) -> bool { self.0.is_empty() }
    pub fn eq(&self, o: &Self) -> bool { self.0.len() == o.0.len() && self.0.iter().zip(o.0.iter()).fold(0u8, |d, (a, b)| d | (a ^ b)) == 0 }
    pub fn clear(&mut self) { use zeroize::Zeroize; self.0.zeroize(); self.0.clear(); }
    /// Move the text out as a wiped-on-drop String (the old buffer is wiped). Used to hand a message to the engine.
    pub fn take_string(&mut self) -> Zeroizing<String> {
        let s = String::from_utf8(self.0.to_vec()).unwrap_or_default();
        self.clear();
        Zeroizing::new(s)
    }
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
    fn multibyte_pop_control_rejected_and_take_string() {
        let mut s = ComposeBuf::new();
        s.push('a'); s.push('ü'); s.push('€');
        assert_eq!(s.chars(), 3);
        s.pop(); s.pop();
        assert_eq!(s.as_bytes(), b"a");
        assert!(!s.push('\n') && !s.push('\x1b'));
        s.push('b');
        let t = s.take_string();
        assert_eq!(&*t, "ab");
        assert!(s.is_empty());
    }
}
