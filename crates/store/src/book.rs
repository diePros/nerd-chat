use crate::StoreError;
use seburity_core::{bundle::{Bundle, KEM_PUB_LEN}, identity::{ContactIdentity, SECRET_LEN}, trust::Trust};
use zeroize::Zeroizing;

pub const MAX_CONTACTS: usize = 1024;
pub const MAX_NAME: usize = 64;
const MAGIC: &[u8; 4] = b"SBS3";
/// Older vaults (no capability / host-anyway bits) are still read; they are written back as SBS3.
const MAGIC_V2: &[u8; 4] = b"SBS2";

/// One contact = one fresh keypair set (unlinkable across contacts) + the peer's public bundle once known.
pub struct Contact {
    pub id: [u8; 8],
    pub name: String,
    pub identity: ContactIdentity,
    pub peer: Option<Bundle>,
    /// How far the peer's identity is authenticated (never a single bool).
    pub trust: Trust,
    /// User choice: host an onion service for this contact even when the roles would make us only dial (e.g. the contact
    /// flipped to dialing because its Tor cannot host but its bundle claims it can). Exposes our presence to holders of the bundle.
    pub host_anyway: bool,
    /// The `can_host` value WE put into the bundle we gave this contact (fixed at the first export/pairing). Roles use THIS, not
    /// whatever flag we run with today, because the contact computes its roles from what we told it.
    pub adv_can_host: Option<bool>,
}

impl std::fmt::Debug for Contact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Contact({:?}, peer={}, trust={:?})", self.name, self.peer.is_some(), self.trust)
    }
}

#[derive(Default, Debug)]
pub struct Store { pub contacts: Vec<Contact> }

fn valid_name(n: &str) -> bool {
    let t = n.trim();
    !t.is_empty() && t == n && n.len() <= MAX_NAME && !n.chars().any(seburity_core::text::is_unsafe_char)
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
        self.contacts.push(Contact { id, name: name.to_string(), identity: ContactIdentity::generate(), peer: None, trust: Trust::Unverified, host_anyway: false, adv_can_host: None });
        Ok(self.contacts.len() - 1)
    }

    pub fn remove(&mut self, idx: usize) { if idx < self.contacts.len() { self.contacts.remove(idx); } }

    /// Serialize (wiped on drop). Format: magic | count:u16 | per contact:
    /// id[8] | name_len:u8 | name | identity[128] | flags:u8 (bit0 peer, bit1/2 trust, bit3 host_anyway, bit4 peer can_host, bit5/6 advertised can_host set/value) | [sign[32] dh[32] kem[1184]]
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
            v.push(c.peer.is_some() as u8 | t | (c.host_anyway as u8) << 3 | (c.peer.as_ref().is_some_and(|p| p.can_host) as u8) << 4 | (c.adv_can_host.is_some() as u8) << 5 | ((c.adv_can_host == Some(true)) as u8) << 6);
            if let Some(p) = &c.peer {
                v.extend_from_slice(&p.sign_pub);
                v.extend_from_slice(&p.dh_pub);
                v.extend_from_slice(&p.onion_pub);
                v.extend_from_slice(&p.auth_pub);
                v.extend_from_slice(&p.kem_pub);
            }
        }
        v
    }

    pub fn decode(b: &[u8]) -> Result<Self, StoreError> {
        let mut r = Reader(b);
        let magic = r.take(4)?;
        let v3 = magic == MAGIC;
        if !v3 && magic != MAGIC_V2 { return Err(StoreError::Corrupt); }
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
            let allowed = if v3 { 0b111_1111 } else { 0b111 };
            if flags & !allowed != 0 || (flags & 0b110) == 0b110 { return Err(StoreError::Corrupt); }
            // trust or a capability without a peer is corrupt; host_anyway may exist without one
            if flags & 1 == 0 && flags & !0b110_1000 != 0 { return Err(StoreError::Corrupt); }
            if flags & 0b100_0000 != 0 && flags & 0b10_0000 == 0 { return Err(StoreError::Corrupt); } // value without 'set'
            let adv_can_host = if flags & 0b10_0000 != 0 { Some(flags & 0b100_0000 != 0) } else { None };
            let (host_anyway, peer_can_host) = (flags & 0b1000 != 0, !v3 || flags & 0b1_0000 != 0);
            let peer = if flags & 1 != 0 {
                let sign: [u8; 32] = r.take(32)?.try_into().unwrap();
                let dh: [u8; 32] = r.take(32)?.try_into().unwrap();
                let onion: [u8; 32] = r.take(32)?.try_into().unwrap();
                let auth: [u8; 32] = r.take(32)?.try_into().unwrap();
                let kem: [u8; KEM_PUB_LEN] = r.take(KEM_PUB_LEN)?.try_into().unwrap();
                Some(Bundle::from_parts(sign, dh, onion, auth, peer_can_host, kem).map_err(|_| StoreError::Corrupt)?)
            } else { None };
            let trust = match flags & 0b110 { 0b010 => Trust::CodeAuthenticated, 0b100 => Trust::SafetyVerified, _ => Trust::Unverified };
            s.contacts.push(Contact { id, name, identity, peer, trust, host_anyway, adv_can_host });
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
    fn capability_and_host_anyway_roundtrip_and_old_vaults_still_load() {
        let mut s = Store::new();
        let a = s.add_contact("alice").unwrap();
        let b = s.add_contact("bob").unwrap();
        s.contacts[a].host_anyway = true;                                              // allowed without a peer
        s.contacts[a].adv_can_host = Some(false);
        s.contacts[b].adv_can_host = Some(true);
        s.contacts[b].peer = Some(Bundle::from_identity(&ContactIdentity::generate()).with_can_host(false));
        let d = Store::decode(&s.encode()).unwrap();
        assert!(d.contacts[a].host_anyway && !d.contacts[b].host_anyway);
        assert_eq!((d.contacts[a].adv_can_host, d.contacts[b].adv_can_host), (Some(false), Some(true)));
        assert!(!d.contacts[b].peer.as_ref().unwrap().can_host, "peer's 'cannot host' must survive the vault");
        // an SBS2 vault (written before these bits existed) loads with can_host = true, host_anyway = false
        let mut s2 = Store::new();
        let i = s2.add_contact("carol").unwrap();
        s2.contacts[i].peer = Some(Bundle::from_identity(&ContactIdentity::generate()));
        let mut old = s2.encode().to_vec(); old[..4].copy_from_slice(b"SBS2");
        // SBS2 had flags with bit4 clear; our SBS3 encode set it (can_host = true): clear it as the old writer would have
        let flags_at = 4 + 2 + 8 + 1 + "carol".len() + SECRET_LEN;
        old[flags_at] &= !0b1_0000;
        let d2 = Store::decode(&old).unwrap();
        assert!(d2.contacts[0].peer.as_ref().unwrap().can_host && !d2.contacts[0].host_anyway);
        // new bits in an SBS2 vault are corrupt
        let mut bad = old.clone(); bad[flags_at] |= 0b1000; assert!(Store::decode(&bad).is_err());
        // a capability bit without a peer is corrupt
        let mut e = Store::new(); e.add_contact("dave").unwrap();
        let mut enc = e.encode().to_vec(); let at = 4 + 2 + 8 + 1 + "dave".len() + SECRET_LEN; enc[at] |= 0b1_0000;
        assert!(Store::decode(&enc).is_err());
    }

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
