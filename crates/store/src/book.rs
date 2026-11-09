use crate::{history::Persist, StoreError};
use sine_loco_core::{bundle::{Bundle, KEM_PUB_LEN}, identity::{ContactIdentity, SECRET_LEN}, trust::Trust};
use zeroize::Zeroizing;

pub const MAX_CONTACTS: usize = 1024;
pub const MAX_NAME: usize = 64;
/// Messages the USER chose to keep (and nothing else is ever written): at most this many per contact ...
pub const MAX_SAVED: usize = 500;
/// ... and at most this many bytes of text in the whole vault.
pub const MAX_SAVED_TOTAL: usize = 4 * 1024 * 1024;
/// One saved message is at most one chat message (the chat caps a message at 32 KiB).
const MAX_SAVED_LEN: usize = 32 * 1024;

/// A message the user saved by hand. Order = order of saving; there is deliberately NO timestamp.
pub struct SavedMsg { pub mine: bool, pub text: Zeroizing<String> }

/// The ENCRYPTED OUTBOX (opt-in): texts we sent that the contact's app has not confirmed yet, kept in the vault so that they survive a restart
/// or the OS killing the app. At most this many per contact (the same number as the engine's `MAX_UNCONFIRMED`: a test pins that) ...
pub const MAX_OUTBOX: usize = 50;
/// ... and at most this many bytes of text in the whole vault (a delivered text is removed again at once) ...
pub const MAX_OUTBOX_TOTAL: usize = 1024 * 1024;
/// ... one text is at most one chat message (the chat caps a message at 32 KiB).
const MAX_OUTBOX_LEN: usize = 32 * 1024;

/// One unconfirmed text of OUR side: the message id the engine and the contact know it by, and the text. Order = order of sending; NO timestamp.
pub struct OutMsg { pub mid: [u8; 8], pub text: Zeroizing<String> }

const MAGIC_V6: &[u8; 4] = b"SBS6";
const MAGIC: &[u8; 4] = b"SBS5";
/// SBS6 (vault flags + the encrypted outbox) is written ONLY when the outbox feature was chosen or an outbox is not empty: any other vault stays SBS5 and
/// stays readable by older binaries. SBS4 (no saved messages) and SBS3 (no rotation state either) are still read.
const MAGIC_V4: &[u8; 4] = b"SBS4";
const MAGIC_V3: &[u8; 4] = b"SBS3";
/// Older vaults (no capability / host-anyway bits) are still read; they are written back as SBS5 on the next save (a ONE-WAY upgrade: older binaries cannot open it).
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
    /// Key rotation, OUR side: the new onion/client-auth secret (onion seed | auth) we proposed; kept until the contact acknowledged.
    /// While set, the engine hosts the OLD and the NEW service so the contact reaches us whichever it knows.
    pub next_transport: Option<Zeroizing<[u8; 64]>>,
    /// Key rotation, THEIR side: the peer's previous (onion, auth) public keys, kept (authorized on our hosted service) until its DONE.
    pub peer_old: Option<([u8; 32], [u8; 32])>,
    /// Messages of this conversation that the user saved by hand (never automatic). Encrypted with the rest of the vault.
    pub saved: Vec<SavedMsg>,
    /// Texts not yet confirmed by this contact (only filled while the encrypted outbox is on): resent on every new connection until confirmed.
    pub outbox: Vec<OutMsg>,
}

impl std::fmt::Debug for Contact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Contact({:?}, peer={}, trust={:?})", self.name, self.peer.is_some(), self.trust)
    }
}

#[derive(Default, Debug)]
pub struct Store {
    pub contacts: Vec<Contact>,
    /// What the user chose to keep on the device (`None` = never chosen: the front end's default applies). The messages themselves live in the HISTORY file (`history.rs`),
    /// not in this payload; the per-contact `outbox` below is the older place for unconfirmed texts and is only read (and moved to the history file) now.
    pub persist: Option<Persist>,
}

fn valid_name(n: &str) -> bool {
    let t = n.trim();
    !t.is_empty() && t == n && n.len() <= MAX_NAME && !n.chars().any(sine_loco_core::text::is_unsafe_char)
}

impl Contact {
    /// OUR rotation, step 1: remember a fresh transport secret (hosted next to the old one until acknowledged).
    pub fn begin_rotation(&mut self) -> Zeroizing<[u8; 64]> {
        let t = ContactIdentity::fresh_transport_secret();
        self.next_transport = Some(t.clone());
        t
    }

    /// OUR rotation, final step (the contact acknowledged): the new keys become THE keys, the old ones are dropped (zeroized).
    pub fn commit_rotation(&mut self) -> bool {
        let Some(t) = self.next_transport.as_ref() else { return false };
        let Some(id) = self.identity.with_transport_secret(t) else { return false };
        self.identity = id;
        self.next_transport = None;
        true
    }

    /// THEIR rotation: switch to the proposed keys now, remember the old public ones (still authorized on our service until DONE).
    pub fn accept_peer_rotation(&mut self, onion: [u8; 32], auth: [u8; 32]) -> bool {
        let Some(p) = self.peer.as_ref() else { return false };
        let old = (p.onion_pub, p.auth_pub);
        self.peer = Some(p.clone().with_transport(onion, auth));
        if self.peer_old.is_none() { self.peer_old = Some(old); }
        true
    }
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
        self.contacts.push(Contact { id, name: name.to_string(), identity: ContactIdentity::generate(), peer: None, trust: Trust::Unverified, host_anyway: false, adv_can_host: None, next_transport: None, peer_old: None, saved: Vec::new(), outbox: Vec::new() });
        Ok(self.contacts.len() - 1)
    }

    pub fn remove(&mut self, idx: usize) { if idx < self.contacts.len() { self.contacts.remove(idx); } }

    /// Total bytes of saved text in the whole vault.
    pub fn saved_bytes(&self) -> usize { self.contacts.iter().flat_map(|c| &c.saved).map(|m| m.text.len()).sum() }

    /// Delete saved message `k` of contact `idx` (zeroized on drop).
    pub fn delete_saved(&mut self, idx: usize, k: usize) -> bool {
        match self.contacts.get_mut(idx) { Some(c) if k < c.saved.len() => { c.saved.remove(k); true } _ => false }
    }

    /// Keep one message of contact `idx` (the user pressed save). Refuses beyond the caps instead of dropping anything silently.
    pub fn save_message(&mut self, idx: usize, mine: bool, text: &str) -> Result<(), StoreError> {
        if text.is_empty() || text.len() > MAX_SAVED_LEN { return Err(StoreError::Corrupt); }
        if self.saved_bytes() + text.len() > MAX_SAVED_TOTAL { return Err(StoreError::SavedFull); }
        let c = self.contacts.get_mut(idx).ok_or(StoreError::Corrupt)?;
        if c.saved.len() >= MAX_SAVED { return Err(StoreError::SavedFull); }
        c.saved.push(SavedMsg { mine, text: Zeroizing::new(text.to_string()) });
        Ok(())
    }

    /// Total bytes of unconfirmed text in the encrypted outbox of the whole vault.
    pub fn outbox_bytes(&self) -> usize { self.contacts.iter().flat_map(|c| &c.outbox).map(|m| m.text.len()).sum() }

    /// Keep one unconfirmed text of contact `idx` in the vault. Refuses beyond the caps and for a contact without a peer instead of dropping anything silently.
    pub fn queue_outbox(&mut self, idx: usize, mid: [u8; 8], text: &str) -> Result<(), StoreError> {
        if text.is_empty() || text.len() > MAX_OUTBOX_LEN { return Err(StoreError::BadText); }
        if self.outbox_bytes() + text.len() > MAX_OUTBOX_TOTAL { return Err(StoreError::OutboxFull); }
        let c = self.contacts.get_mut(idx).ok_or(StoreError::Corrupt)?;
        if c.peer.is_none() || c.outbox.len() >= MAX_OUTBOX || c.outbox.iter().any(|m| m.mid == mid) { return Err(StoreError::OutboxFull); }
        c.outbox.push(OutMsg { mid, text: Zeroizing::new(text.to_string()) });
        Ok(())
    }

    /// The contact confirmed (or the engine refused) text `mid` of the contact with this id: forget it (the text is zeroized). `false`: it was not there.
    pub fn outbox_done(&mut self, contact: [u8; 8], mid: [u8; 8]) -> bool {
        let Some(c) = self.contacts.iter_mut().find(|c| c.id == contact) else { return false };
        match c.outbox.iter().position(|m| m.mid == mid) { Some(k) => { c.outbox.remove(k); true } None => false }
    }

    /// Forget every kept text (the user switched the outbox off): each is zeroized.
    pub fn clear_outbox(&mut self) { for c in &mut self.contacts { c.outbox.clear(); } }

    /// Exact upper bound of the encoding (every optional part counted), so `encode` never reallocates.
    fn encoded_size(&self) -> usize {
        7 + self.contacts.iter().map(|c| 8 + 1 + c.name.len() + SECRET_LEN + 1 + (32 * 4 + KEM_PUB_LEN) + 1 + 64 + 64 + 2 + c.saved.iter().map(|m| 3 + m.text.len()).sum::<usize>()
            + 2 + c.outbox.iter().map(|m| 8 + 2 + m.text.len()).sum::<usize>()).sum::<usize>()
    }

    /// Serialize (wiped on drop). Format: magic | count:u16 | per contact:
    /// id[8] | name_len:u8 | name | identity[128] | flags:u8 (bit0 peer, bit1/2 trust, bit3 host_anyway, bit4 peer can_host, bit5/6 advertised can_host set/value) | [sign[32] dh[32] kem[1184]]
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        // the lengths below are written as u8/u16: a value that does not fit would be saved silently and the vault would never open again, so fail LOUDLY before anything is sealed
        for c in &self.contacts {
            assert!(c.name.len() <= u8::MAX as usize && c.saved.len() <= u16::MAX as usize && c.outbox.len() <= u16::MAX as usize, "contact record too large to encode");
            assert!(c.saved.iter().all(|m| m.text.len() <= u16::MAX as usize) && c.outbox.iter().all(|m| m.text.len() <= u16::MAX as usize), "message too large to encode");
        }
        assert!(self.contacts.len() <= u16::MAX as usize, "too many contacts to encode");
        // reserve the final size up front: a growing Vec would leave copies of keys and saved messages in freed heap
        let mut v = Zeroizing::new(Vec::with_capacity(self.encoded_size()));
        // SBS6 only when the feature is in use: every other vault stays SBS5 and stays readable by older binaries
        let sbs6 = self.persist.is_some() || self.contacts.iter().any(|c| !c.outbox.is_empty());
        v.extend_from_slice(if sbs6 { MAGIC_V6 } else { MAGIC });
        v.extend_from_slice(&(self.contacts.len() as u16).to_be_bytes());
        // SBS6: vault flags: bit0 = a choice was made, bits1-2 = what to keep (0 nothing, 1 unsent texts only, 2 one day, 3 one week; 0/1 are what the first SBS6 wrote as off/on)
        if sbs6 { v.push(self.persist.is_some() as u8 | (match self.persist { None | Some(Persist::Off) => 0, Some(Persist::Outbox) => 1, Some(Persist::Day) => 2, Some(Persist::Week) => 3 }) << 1); }
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
            // SBS4: rotation state. flags2: bit0 next_transport, bit1 peer_old (needs a peer)
            v.push(c.next_transport.is_some() as u8 | (c.peer_old.is_some() as u8) << 1);
            if let Some(t) = &c.next_transport { v.extend_from_slice(&**t); }
            if let Some((o, a)) = &c.peer_old { v.extend_from_slice(o); v.extend_from_slice(a); }
            // SBS5: the messages the user saved: count:u16 | per message: flags:u8 (bit0 mine) | len:u16 | text
            v.extend_from_slice(&(c.saved.len() as u16).to_be_bytes());
            for m in &c.saved { v.push(m.mine as u8); v.extend_from_slice(&(m.text.len() as u16).to_be_bytes()); v.extend_from_slice(m.text.as_bytes()); }
            // SBS6: the unconfirmed texts: count:u16 | per text: mid[8] | len:u16 | text
            if sbs6 {
                v.extend_from_slice(&(c.outbox.len() as u16).to_be_bytes());
                for m in &c.outbox { v.extend_from_slice(&m.mid); v.extend_from_slice(&(m.text.len() as u16).to_be_bytes()); v.extend_from_slice(m.text.as_bytes()); }
            }
        }
        v
    }

    pub fn decode(b: &[u8]) -> Result<Self, StoreError> {
        let mut r = Reader(b);
        let magic = r.take(4)?;
        let v6 = magic == MAGIC_V6;
        let v5 = v6 || magic == MAGIC;
        let v4 = v5 || magic == MAGIC_V4;
        let v3 = v4 || magic == MAGIC_V3;
        if !v3 && magic != MAGIC_V2 { return Err(StoreError::Corrupt); }
        let n = u16::from_be_bytes(r.take(2)?.try_into().unwrap()) as usize;
        if n > MAX_CONTACTS { return Err(StoreError::Corrupt); }
        let mut s = Store::new();
        if v6 {
            let vf = r.take(1)?[0];
            if vf & !0b111 != 0 || (vf & 0b110 != 0 && vf & 1 == 0) { return Err(StoreError::Corrupt); } // unknown bits, or a value without 'set'
            if vf & 1 != 0 { s.persist = Some(match (vf >> 1) & 3 { 0 => Persist::Off, 1 => Persist::Outbox, 2 => Persist::Day, _ => Persist::Week }); }
        }
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
            let (mut next_transport, mut peer_old) = (None, None);
            if v4 {
                let f2 = r.take(1)?[0];
                if f2 & !0b11 != 0 || (f2 & 0b10 != 0 && peer.is_none()) { return Err(StoreError::Corrupt); }
                if f2 & 1 != 0 { next_transport = Some(Zeroizing::new(<[u8; 64]>::try_from(r.take(64)?).unwrap())); }
                if f2 & 0b10 != 0 {
                    let o: [u8; 32] = r.take(32)?.try_into().unwrap();
                    let a: [u8; 32] = r.take(32)?.try_into().unwrap();
                    peer_old = Some((o, a));
                }
            }
            let mut saved = Vec::new();
            if v5 {
                let n = u16::from_be_bytes(r.take(2)?.try_into().unwrap()) as usize;
                if n > MAX_SAVED { return Err(StoreError::Corrupt); }
                for _ in 0..n {
                    let flags = r.take(1)?[0];
                    let len = u16::from_be_bytes(r.take(2)?.try_into().unwrap()) as usize;
                    if flags > 1 || len == 0 || len > MAX_SAVED_LEN { return Err(StoreError::Corrupt); }
                    let text = std::str::from_utf8(r.take(len)?).map_err(|_| StoreError::Corrupt)?;
                    saved.push(SavedMsg { mine: flags == 1, text: Zeroizing::new(text.to_string()) });
                }
            }
            let mut outbox: Vec<OutMsg> = Vec::new();
            if v6 {
                let n = u16::from_be_bytes(r.take(2)?.try_into().unwrap()) as usize;
                // texts waiting for a contact that has no peer key could never be sent: corrupt
                if n > MAX_OUTBOX || (n > 0 && peer.is_none()) { return Err(StoreError::Corrupt); }
                for _ in 0..n {
                    let mid: [u8; 8] = r.take(8)?.try_into().unwrap();
                    let len = u16::from_be_bytes(r.take(2)?.try_into().unwrap()) as usize;
                    if len == 0 || len > MAX_OUTBOX_LEN || outbox.iter().any(|m| m.mid == mid) { return Err(StoreError::Corrupt); }
                    let text = std::str::from_utf8(r.take(len)?).map_err(|_| StoreError::Corrupt)?;
                    outbox.push(OutMsg { mid, text: Zeroizing::new(text.to_string()) });
                }
            }
            s.contacts.push(Contact { id, name, identity, peer, trust, host_anyway, adv_can_host, next_transport, peer_old, saved, outbox });
        }
        if !r.0.is_empty() || s.saved_bytes() > MAX_SAVED_TOTAL || s.outbox_bytes() > MAX_OUTBOX_TOTAL { return Err(StoreError::Corrupt); }
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

    fn paired(s: &mut Store, name: &str) -> usize {
        let i = s.add_contact(name).unwrap();
        s.contacts[i].peer = Some(Bundle::from_identity(&ContactIdentity::generate()));
        i
    }

    #[test]
    fn a_vault_that_never_used_the_outbox_stays_sbs5_and_old_binaries_keep_working() {
        let mut s = Store::new(); paired(&mut s, "alice");
        assert_eq!(&s.encode()[..4], b"SBS5", "untouched vaults keep the old format");
        let d = Store::decode(&s.encode()).unwrap();
        assert_eq!(d.persist, None); assert!(d.contacts[0].outbox.is_empty());
    }

    #[test]
    fn the_outbox_roundtrips_in_sbs6_in_order_with_its_flags() {
        let mut s = Store::new();
        let a = paired(&mut s, "alice"); let b = paired(&mut s, "bob");
        s.persist = Some(Persist::Outbox);
        s.queue_outbox(a, [1; 8], "first \u{1F600}").unwrap(); s.queue_outbox(a, [2; 8], "second").unwrap(); s.queue_outbox(b, [3; 8], "for bob").unwrap();
        let enc = s.encode();
        assert_eq!(&enc[..4], b"SBS6");
        let d = Store::decode(&enc).unwrap();
        assert_eq!(d.persist, Some(Persist::Outbox));
        assert_eq!(d.contacts[a].outbox.iter().map(|m| (m.mid, m.text.to_string())).collect::<Vec<_>>(), vec![([1; 8], "first \u{1F600}".to_string()), ([2; 8], "second".to_string())]);
        assert_eq!(d.contacts[b].outbox.len(), 1, "an outbox belongs to one contact only");
        // an explicit "off" is remembered too (so the front end's default does not come back)
        let mut off = Store::new(); paired(&mut off, "carol"); off.persist = Some(Persist::Off);
        assert_eq!(Store::decode(&off.encode()).unwrap().persist, Some(Persist::Off));
        for p in [Persist::Day, Persist::Week] { let mut s = Store::new(); paired(&mut s, "dan"); s.persist = Some(p); assert_eq!(Store::decode(&s.encode()).unwrap().persist, Some(p), "{p:?}"); }
    }

    #[test]
    fn confirming_removes_a_text_and_switching_off_clears_everything() {
        let mut s = Store::new(); let a = paired(&mut s, "alice"); let id = s.contacts[a].id;
        s.queue_outbox(a, [1; 8], "x").unwrap(); s.queue_outbox(a, [2; 8], "y").unwrap();
        assert!(s.outbox_done(id, [1; 8]) && !s.outbox_done(id, [1; 8]), "removed once");
        assert!(!s.outbox_done([9; 8], [2; 8]), "unknown contact");
        assert_eq!(s.contacts[a].outbox.len(), 1);
        s.clear_outbox(); assert!(s.contacts[a].outbox.is_empty());
    }

    #[test]
    fn the_outbox_caps_are_enforced_and_nothing_is_dropped_silently() {
        let mut s = Store::new(); let a = paired(&mut s, "alice"); let b = paired(&mut s, "bob");
        for k in 0..MAX_OUTBOX { s.queue_outbox(a, [k as u8; 8], "x").unwrap(); }
        assert!(matches!(s.queue_outbox(a, [200; 8], "x"), Err(StoreError::OutboxFull)), "per contact");
        assert!(matches!(s.queue_outbox(a, [0; 8], "x"), Err(StoreError::OutboxFull)), "a repeated id is refused");
        let big = "y".repeat(32 * 1024);
        let mut n = 0u8; while s.outbox_bytes() + big.len() <= MAX_OUTBOX_TOTAL { s.queue_outbox(b, [100 + n; 8], &big).unwrap(); n += 1; }
        assert!(matches!(s.queue_outbox(b, [250; 8], &big), Err(StoreError::OutboxFull)), "in total");
        assert!(matches!(s.queue_outbox(b, [251; 8], ""), Err(StoreError::BadText)) && matches!(s.queue_outbox(b, [252; 8], &"q".repeat(32 * 1024 + 1)), Err(StoreError::BadText)));
        let mut np = Store::new(); let c = np.add_contact("nopeer").unwrap();
        assert!(matches!(np.queue_outbox(c, [1; 8], "x"), Err(StoreError::OutboxFull)), "no peer key: it could never be sent");
    }

    #[test]
    #[should_panic(expected = "message too large to encode")]
    fn encode_refuses_to_truncate_a_length_instead_of_writing_a_vault_that_never_opens() {
        let mut s = Store::new(); let a = paired(&mut s, "alice");
        s.contacts[a].outbox.push(OutMsg { mid: [1; 8], text: Zeroizing::new("x".repeat(70_000)) }); // bypasses queue_outbox on purpose
        let _ = s.encode();
    }

    #[test]
    fn an_over_long_text_is_a_bad_text_not_corruption() {
        let mut s = Store::new(); let a = paired(&mut s, "alice");
        assert!(matches!(s.queue_outbox(a, [1; 8], &"q".repeat(32 * 1024 + 1)), Err(StoreError::BadText)));
    }

    #[test]
    fn hostile_sbs6_blobs_are_refused() {
        let mut s = Store::new(); let a = paired(&mut s, "alice");
        s.persist = Some(Persist::Outbox); s.queue_outbox(a, [7; 8], "ab").unwrap();
        let enc = s.encode().to_vec();
        let at = enc.len() - (8 + 2 + 2);                                // mid(8) len(2) "ab"(2)
        let mutate = |f: &dyn Fn(&mut Vec<u8>)| { let mut t = enc.clone(); f(&mut t); Store::decode(&t) };
        assert!(mutate(&|_| {}).is_ok());
        assert!(mutate(&|t| t[6] = 0b1000).is_err(), "unknown vault flag");
        assert!(mutate(&|t| t[6] = 0b10).is_err(), "a value without 'set'");
        assert!(mutate(&|t| t[6] = 0b101).is_ok(), "mode 'day' with 'set' is a valid flag byte");
        assert!(mutate(&|t| { t[at + 8] = 0; t[at + 9] = 0; }).is_err(), "zero length");
        assert!(mutate(&|t| t[at + 9] = 3).is_err(), "length larger than the data left");
        assert!(mutate(&|t| t[at + 10] = 0xff).is_err(), "invalid UTF-8");
        assert!(mutate(&|t| { let l = t.len(); t.truncate(l - 1); }).is_err(), "truncated");
        assert!(mutate(&|t| t.push(0)).is_err(), "trailing data");
        // count above the cap
        assert!(mutate(&|t| { t[at - 2] = 0; t[at - 1] = (MAX_OUTBOX + 1) as u8; }).is_err());
        // an outbox for a contact without a peer, and a duplicate id
        let mut np = Store::new(); let c = np.add_contact("nopeer").unwrap(); np.persist = Some(Persist::Outbox);
        np.contacts[c].outbox.push(OutMsg { mid: [1; 8], text: Zeroizing::new("x".into()) });
        assert!(Store::decode(&np.encode()).is_err());
        let mut dup = Store::new(); let d = paired(&mut dup, "dave");
        for _ in 0..2 { dup.contacts[d].outbox.push(OutMsg { mid: [5; 8], text: Zeroizing::new("x".into()) }); }
        assert!(Store::decode(&dup.encode()).is_err());
    }

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
        old.truncate(old.len() - 3); // the SBS4 'flags2' byte and the SBS5 saved-message count did not exist in SBS2/SBS3
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
    fn rotation_state_roundtrips_and_commits() {
        let mut s = Store::new();
        let i = s.add_contact("alice").unwrap();
        s.contacts[i].peer = Some(Bundle::from_identity(&ContactIdentity::generate()));
        let before = Bundle::from_identity(&s.contacts[i].identity);
        let t = s.contacts[i].begin_rotation();
        let peer_before = s.contacts[i].peer.clone().unwrap();
        let np = ContactIdentity::generate();
        let (no, na) = (np.onion_public(), np.auth_public().to_bytes());
        assert!(s.contacts[i].accept_peer_rotation(no, na));
        let d = Store::decode(&s.encode()).unwrap();
        assert_eq!(d.contacts[i].next_transport.as_deref(), Some(&*t));
        assert_eq!(d.contacts[i].peer_old, Some((peer_before.onion_pub, peer_before.auth_pub)));
        assert_eq!(d.contacts[i].peer.as_ref().unwrap().onion_pub, no);
        let mut d = d;
        assert!(d.contacts[i].commit_rotation() && d.contacts[i].next_transport.is_none());
        let after = Bundle::from_identity(&d.contacts[i].identity);
        assert_ne!(before.onion_pub, after.onion_pub);
        assert_eq!((before.sign_pub, before.dh_pub), (after.sign_pub, after.dh_pub));
        assert!(!d.contacts[i].commit_rotation(), "nothing pending");
        // peer_old without a peer is corrupt
        let mut e = Store::new(); e.add_contact("bob").unwrap();
        e.contacts[0].peer_old = Some(([1; 32], [2; 32]));
        assert!(Store::decode(&e.encode()).is_err());
    }

    #[test]
    fn saved_messages_roundtrip_respect_the_caps_and_old_vaults_still_load() {
        let mut s = Store::new();
        let a = s.add_contact("alice").unwrap();
        let b = s.add_contact("bob").unwrap();
        s.save_message(a, false, "hello \u{1F600}").unwrap();
        s.save_message(a, true, "reply").unwrap();
        let d = Store::decode(&s.encode()).unwrap();
        assert_eq!(d.contacts[a].saved.len(), 2);
        assert!(!d.contacts[a].saved[0].mine && &*d.contacts[a].saved[0].text == "hello \u{1F600}" && d.contacts[a].saved[1].mine);
        assert!(d.contacts[b].saved.is_empty(), "saved messages belong to one contact only");
        // an SBS4 vault (no saved messages) loads with an empty list
        let mut s4 = Store::new(); s4.add_contact("carol").unwrap();
        let mut old = s4.encode().to_vec(); old[..4].copy_from_slice(b"SBS4"); old.truncate(old.len() - 2);
        assert!(Store::decode(&old).unwrap().contacts[0].saved.is_empty());
        // caps: per contact and in total, never a silent drop
        let mut f = Store::new(); let i = f.add_contact("dave").unwrap();
        for _ in 0..MAX_SAVED { f.save_message(i, true, "x").unwrap(); }
        assert!(matches!(f.save_message(i, true, "x"), Err(StoreError::SavedFull)));
        let mut g = Store::new(); let j = g.add_contact("erin").unwrap(); let k = g.add_contact("frank").unwrap();
        let big = "y".repeat(32 * 1024);
        for n in 0..(MAX_SAVED_TOTAL / big.len()) { g.save_message(if n % 2 == 0 { j } else { k }, false, &big).unwrap(); }
        assert!(matches!(g.save_message(j, false, "z"), Err(StoreError::SavedFull)), "total byte cap");
        assert!(matches!(g.save_message(j, false, ""), Err(StoreError::Corrupt)) && matches!(g.save_message(j, false, &"q".repeat(32 * 1024 + 1)), Err(StoreError::Corrupt)));
        // hostile blob: bad flag, zero length, invalid UTF-8, too many, truncated
        let mut one = Store::new(); let o = one.add_contact("gina").unwrap(); one.save_message(o, true, "ab").unwrap();
        let enc = one.encode().to_vec();
        let at = enc.len() - 5;                                         // flags(1) len(2) "ab"(2)
        let mutate = |f: &dyn Fn(&mut Vec<u8>)| { let mut t = enc.clone(); f(&mut t); Store::decode(&t) };
        assert!(mutate(&|t| t[at] = 2).is_err(), "unknown flag bits");
        assert!(mutate(&|t| { t[at + 1] = 0; t[at + 2] = 0; }).is_err(), "zero length");
        assert!(mutate(&|t| t[at + 2] = 3).is_err(), "length larger than the data left");
        assert!(mutate(&|t| t[at + 2] = 1).is_err(), "length shorter: trailing bytes");
        let mut t = enc.clone(); let n = t.len(); t[n - 2] = 0xff; t[n - 1] = 0xfe; assert!(Store::decode(&t).is_err(), "invalid UTF-8");
        for cut in 0..enc.len() { assert!(Store::decode(&enc[..cut]).is_err(), "truncated at {cut}"); }
    }

    #[test]
    fn decode_enforces_the_saved_message_caps_even_for_a_vault_written_by_something_else() {
        let push = |s: &mut Store, i: usize, n: usize, len: usize| for _ in 0..n { s.contacts[i].saved.push(SavedMsg { mine: false, text: Zeroizing::new("x".repeat(len)) }); };
        let mut many = Store::new(); let i = many.add_contact("a").unwrap();
        push(&mut many, i, MAX_SAVED + 1, 1);
        assert!(Store::decode(&many.encode()).is_err(), "too many messages for one contact");
        let mut big = Store::new(); let (a, b) = (big.add_contact("a").unwrap(), big.add_contact("b").unwrap());
        push(&mut big, a, 65, 32 * 1024); push(&mut big, b, 65, 32 * 1024);
        assert!(big.saved_bytes() > MAX_SAVED_TOTAL && Store::decode(&big.encode()).is_err(), "too many bytes in the whole vault");
        let mut long = Store::new(); let l = long.add_contact("a").unwrap();
        push(&mut long, l, 1, 32 * 1024 + 1);
        assert!(Store::decode(&long.encode()).is_err(), "a message longer than one chat message");
        let mut ok = Store::new(); let o = ok.add_contact("a").unwrap();
        push(&mut ok, o, MAX_SAVED, 1);
        assert_eq!(Store::decode(&ok.encode()).unwrap().contacts[0].saved.len(), MAX_SAVED, "exactly at the cap is fine");
    }

    #[test]
    fn encode_never_reallocates_so_no_copy_of_a_key_is_left_in_freed_heap() {
        let mut s = Store::new();
        let i = s.add_contact("alice").unwrap();
        s.contacts[i].peer = Some(Bundle::from_identity(&ContactIdentity::generate()));
        s.contacts[i].begin_rotation();                                   // next_transport set
        let np = ContactIdentity::generate();
        s.contacts[i].accept_peer_rotation(np.onion_public(), np.auth_public().to_bytes());   // peer_old set
        s.save_message(i, true, "a saved message").unwrap();
        let enc = s.encode();
        assert!(enc.len() <= s.encoded_size(), "the estimate must cover the real size ({} > {})", enc.len(), s.encoded_size());
        assert_eq!(enc.capacity(), s.encoded_size(), "the buffer kept its reserved capacity: it never grew");
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
