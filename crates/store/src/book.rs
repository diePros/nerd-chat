use crate::StoreError;
use seburity_core::{bundle::{Bundle, KEM_PUB_LEN}, identity::{ContactIdentity, SECRET_LEN}, trust::Trust};
use zeroize::Zeroizing;

pub const MAX_CONTACTS: usize = 1024;
pub const MAX_NAME: usize = 64;
const MAGIC: &[u8; 4] = b"SBS1";

/// One contact = one fresh keypair set (unlinkable across contacts) + the peer's public bundle once known.
pub struct Contact {
    pub id: [u8; 8],
    pub name: String,
    pub identity: ContactIdentity,
    pub peer: Option<Bundle>,
    /// How far the peer's identity is authenticated (never a single bool).
    pub trust: Trust,
}

impl std::fmt::Debug for Contact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Contact({:?}, peer={}, trust={:?})", self.name, self.peer.is_some(), self.trust)
    }
}

#[derive(Default, Debug)]
pub struct Store { pub contacts: Vec<Contact> }

/// Controls and invisible/bidirectional formatting characters can spoof what the user sees.
fn bad_char(c: char) -> bool {
    c.is_control() || matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}')
}

fn valid_name(n: &str) -> bool {
    let t = n.trim();
    !t.is_empty() && t == n && n.len() <= MAX_NAME && !n.chars().any(bad_char)
}

impl Drop for Contact {
    /// Contact names are sensitive metadata (who you talk to): wipe them.
    fn drop(&mut self) { use zeroize::Zeroize; self.name.zeroize(); }
}

impl Store {
    pub fn new() -> Self { Self::default() }

    /// Generate a brand-new keypair set for a new contact.
    pub fn add_contact(&mut self, name: &str) -> Result<usize, StoreError> {
        if !valid_name(name) { return Err(StoreError::BadName); }
        if self.contacts.len() >= MAX_CONTACTS { return Err(StoreError::TooMany); }
        if self.contacts.iter().any(|c| c.name == name) { return Err(StoreError::Duplicate); }
        let mut id = [0u8; 8];
        getrandom::fill(&mut id).expect("OS RNG unavailable");
        self.contacts.push(Contact { id, name: name.to_string(), identity: ContactIdentity::generate(), peer: None, trust: Trust::Unverified });
        Ok(self.contacts.len() - 1)
    }

    pub fn remove(&mut self, idx: usize) { if idx < self.contacts.len() { self.contacts.remove(idx); } }

    /// Serialize (wiped on drop). Format: magic | count:u16 | per contact:
    /// id[8] | name_len:u8 | name | identity[128] | flags:u8 (bit0 peer, bit1 verified) | [sign[32] dh[32] kem[1184]]
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut v = Zeroizing::new(Vec::new());
        v.extend_from_slice(MAGIC);
        v.extend_from_slice(&(self.contacts.len() as u16).to_be_bytes());
        for c in &self.contacts {
            v.extend_from_slice(&c.id);
            v.push(c.name.len() as u8);
            v.extend_from_slice(c.name.as_bytes());
            v.extend_from_slice(&c.identity.secret_bytes());
            let t = match c.trust { Trust::Unverified => 0, Trust::CodeAuthenticated => 1 << 1, Trust::SafetyVerified => 1 << 2 };
            v.push(c.peer.is_some() as u8 | t);
            if let Some(p) = &c.peer {
                v.extend_from_slice(&p.sign_pub);
                v.extend_from_slice(&p.dh_pub);
                v.extend_from_slice(&p.kem_pub);
            }
        }
        v
    }

    pub fn decode(b: &[u8]) -> Result<Self, StoreError> {
        let mut r = Reader(b);
        if r.take(4)? != MAGIC { return Err(StoreError::Corrupt); }
        let n = u16::from_be_bytes(r.take(2)?.try_into().unwrap()) as usize;
        if n > MAX_CONTACTS { return Err(StoreError::Corrupt); }
        let mut s = Store::new();
        for _ in 0..n {
            let id: [u8; 8] = r.take(8)?.try_into().unwrap();
            let nl = r.take(1)?[0] as usize;
            let name = std::str::from_utf8(r.take(nl)?).map_err(|_| StoreError::Corrupt)?.to_string();
            if !valid_name(&name) || s.contacts.iter().any(|c| c.name == name) { return Err(StoreError::Corrupt); }
            let identity = ContactIdentity::from_secret_bytes(r.take(SECRET_LEN)?).ok_or(StoreError::Corrupt)?;
            let flags = r.take(1)?[0];
            if flags & !0b111 != 0 || (flags & 0b110) == 0b110 { return Err(StoreError::Corrupt); }
            if flags & 1 == 0 && flags != 0 { return Err(StoreError::Corrupt); } // trust without a peer
            let peer = if flags & 1 != 0 {
                let sign: [u8; 32] = r.take(32)?.try_into().unwrap();
                let dh: [u8; 32] = r.take(32)?.try_into().unwrap();
                let kem: [u8; KEM_PUB_LEN] = r.take(KEM_PUB_LEN)?.try_into().unwrap();
                Some(Bundle::from_parts(sign, dh, kem).map_err(|_| StoreError::Corrupt)?)
            } else { None };
            let trust = match flags & 0b110 { 0b010 => Trust::CodeAuthenticated, 0b100 => Trust::SafetyVerified, _ => Trust::Unverified };
            s.contacts.push(Contact { id, name, identity, peer, trust });
        }
        if !r.0.is_empty() { return Err(StoreError::Corrupt); }
        Ok(s)
    }
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], StoreError> {
        if self.0.len() < n { return Err(StoreError::Corrupt); }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_with_and_without_peer() {
        let mut s = Store::new();
        let a = s.add_contact("alice").unwrap();
        let b = s.add_contact("bob").unwrap();
        let other = Bundle::from_identity(&ContactIdentity::generate());
        s.contacts[b].peer = Some(other.clone());
        s.contacts[b].trust = Trust::SafetyVerified;
        let enc = s.encode();
        let d = Store::decode(&enc).unwrap();
        assert_eq!(d.contacts.len(), 2);
        assert!(d.contacts[a].peer.is_none() && d.contacts[a].trust == Trust::Unverified);
        assert_eq!(d.contacts[b].peer.as_ref().unwrap(), &other);
        assert_eq!(d.contacts[b].trust, Trust::SafetyVerified);
        assert_eq!(Bundle::from_identity(&d.contacts[a].identity), Bundle::from_identity(&s.contacts[a].identity));
    }

    #[test]
    fn names_validated_and_unique() {
        let mut s = Store::new();
        for bad in ["", " x", "x ", "a\nb", "evil\u{202E}name", "zero\u{200B}width", &"x".repeat(MAX_NAME + 1)] {
            assert!(matches!(s.add_contact(bad), Err(StoreError::BadName)), "{bad:?}");
        }
        s.add_contact("ok").unwrap();
        assert!(matches!(s.add_contact("ok"), Err(StoreError::Duplicate)));
    }

    #[test]
    fn contacts_have_distinct_keys() {
        let mut s = Store::new();
        s.add_contact("a").unwrap(); s.add_contact("b").unwrap();
        assert_ne!(Bundle::from_identity(&s.contacts[0].identity), Bundle::from_identity(&s.contacts[1].identity));
    }

    #[test]
    fn decode_rejects_corruption_without_panicking() {
        let mut s = Store::new();
        s.add_contact("alice").unwrap();
        s.contacts[0].peer = Some(Bundle::from_identity(&ContactIdentity::generate()));
        let enc = s.encode().to_vec();
        for cut in 0..enc.len() { assert!(Store::decode(&enc[..cut]).is_err(), "truncated at {cut}"); }
        let mut t = enc.clone(); t.push(0);
        assert!(Store::decode(&t).is_err());
        let mut t = enc.clone(); t[0] ^= 1;
        assert!(Store::decode(&t).is_err());
        // unknown flag bits
        let flag_pos = 4 + 2 + 8 + 1 + "alice".len() + SECRET_LEN;
        let mut t = enc.clone(); t[flag_pos] |= 0x80;
        assert!(Store::decode(&t).is_err());
        // both trust bits set
        let mut t = enc.clone(); t[flag_pos] |= 0b110;
        assert!(Store::decode(&t).is_err());
        // low-order peer key smuggled into the vault payload
        let mut t = enc.clone(); for b in &mut t[flag_pos + 1 + 32..flag_pos + 1 + 64] { *b = 0; }
        assert!(Store::decode(&t).is_err());
    }
}
