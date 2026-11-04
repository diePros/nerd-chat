//! Local pairing link: SPAKE2 over any `Read + Write` stream (TCP/LAN now; BLE/Wi-Fi Direct later).
//!
//! 1. Both sides run symmetric SPAKE2 on the one-time `PairingCode` -> shared key K.
//! 2. Key confirmation: each sends MAC(K_conf, own pake msg || peer pake msg); the peer verifies
//!    it. A wrong code or an active attacker is detected here. An attacker gets exactly ONE
//!    guess per code, so the code is consumed (taken by value) and must be regenerated after
//!    any failure.
//! 3. Each side sends its self-signed bundle under XChaCha20-Poly1305 keyed from K, with the
//!    full transcript (sender's msg || receiver's msg) as AAD, which also stops reflection.
//! 4. Both sides then show `safety_number` (optional extra check if the code travelled over a
//!    weak channel).
use crate::{ExchangeError, ImportedContact};
use blake2::{digest::consts::U32, Blake2b, Digest};
use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, XChaCha20Poly1305, XNonce};
use seburity_core::{bundle::{Bundle, BUNDLE_LEN, safety_number}, identity::ContactIdentity};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use std::io::{Read, Write};
use zeroize::Zeroizing;

const MAX_FRAME: usize = 2048;
const ID: &[u8] = b"seburity-pair-v1";
/// 10 decimal digits (~33 bits): fine because every code allows ONE online guess and burns on failure.
pub const CODE_DIGITS: usize = 10;

pub struct PairingCode(Zeroizing<String>);

impl PairingCode {
    pub fn generate() -> Self {
        let mut s = String::new();
        let mut b = [0u8; 16];
        getrandom::fill(&mut b).expect("OS RNG unavailable");
        for x in b {
            // rejection sampling: no modulo bias
            if x < 250 && s.len() < CODE_DIGITS { s.push((b'0' + x % 10) as char); }
        }
        // 16 bytes make >=10 accepted digits overwhelmingly likely; top up if not
        while s.len() < CODE_DIGITS {
            let mut o = [0u8; 1];
            getrandom::fill(&mut o).expect("OS RNG unavailable");
            if o[0] < 250 { s.push((b'0' + o[0] % 10) as char); }
        }
        Self(Zeroizing::new(s))
    }

    /// Accepts `12345-67890`, spaces, or plain digits.
    pub fn parse(input: &str) -> Result<Self, ExchangeError> {
        let d: String = input.chars().filter(|c| !matches!(c, '-' | ' ')).collect();
        if d.len() != CODE_DIGITS || !d.bytes().all(|c| c.is_ascii_digit()) { return Err(ExchangeError::BadCode); }
        Ok(Self(Zeroizing::new(d)))
    }

    /// Human display `12345-67890`.
    pub fn display(&self) -> String { format!("{}-{}", &self.0[..5], &self.0[5..]) }
}

pub struct Paired { pub contact: ImportedContact, pub safety_number: String }

fn write_frame<W: Write>(w: &mut W, data: &[u8]) -> Result<(), ExchangeError> {
    if data.len() > MAX_FRAME { return Err(ExchangeError::Malformed); }
    w.write_all(&(data.len() as u16).to_be_bytes()).map_err(|_| ExchangeError::Io)?;
    w.write_all(data).map_err(|_| ExchangeError::Io)?;
    w.flush().map_err(|_| ExchangeError::Io)
}

fn read_frame<R: Read>(r: &mut R) -> Result<Vec<u8>, ExchangeError> {
    let mut l = [0u8; 2];
    r.read_exact(&mut l).map_err(|_| ExchangeError::Io)?;
    let n = u16::from_be_bytes(l) as usize;
    if n > MAX_FRAME { return Err(ExchangeError::Malformed); }
    let mut v = vec![0u8; n];
    r.read_exact(&mut v).map_err(|_| ExchangeError::Io)?;
    Ok(v)
}

fn kdf(k: &[u8], label: &[u8], lo: &[u8], hi: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut h = Blake2b::<U32>::new();
    h.update(b"seburity-pair-kdf-v1");
    h.update(label);
    h.update(k);
    h.update(lo);
    h.update(hi);
    Zeroizing::new(h.finalize().into())
}

fn tag(k_conf: &[u8; 32], own: &[u8], peer: &[u8]) -> [u8; 32] {
    let mut h = Blake2b::<U32>::new();
    h.update(b"seburity-pair-confirm-v1");
    h.update(k_conf);
    h.update((own.len() as u32).to_be_bytes());
    h.update(own);
    h.update(peer);
    h.finalize().into()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// Run the pairing. Consumes the code: it can never be reused. Blocking; set stream timeouts at the transport.
pub fn pair<S: Read + Write>(stream: &mut S, me: &ContactIdentity, code: PairingCode) -> Result<Paired, ExchangeError> {
    let (st, my_msg) = Spake2::<Ed25519Group>::start_symmetric(&Password::new(code.0.as_bytes()), &Identity::new(ID));
    drop(code);
    write_frame(stream, &my_msg)?;
    let peer_msg = read_frame(stream)?;
    if peer_msg == my_msg { return Err(ExchangeError::Reflection); }
    let k = Zeroizing::new(st.finish(&peer_msg).map_err(|_| ExchangeError::PairingFailed)?);
    // Order-independent transcript for key derivation.
    let (lo, hi) = if my_msg < peer_msg { (&my_msg, &peer_msg) } else { (&peer_msg, &my_msg) };
    let k_conf = kdf(&k, b"conf", lo, hi);
    let k_enc = kdf(&k, b"enc", lo, hi);

    // Key confirmation (detects wrong code / MITM before any bundle is sent).
    write_frame(stream, &tag(&k_conf, &my_msg, &peer_msg))?;
    let their_tag = read_frame(stream)?;
    if !ct_eq(&their_tag, &tag(&k_conf, &peer_msg, &my_msg)) { return Err(ExchangeError::PairingFailed); }

    // Bundle exchange under the PAKE-derived key.
    let me_b = Bundle::from_identity(me);
    let cipher = XChaCha20Poly1305::new((&*k_enc).into());
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).expect("OS RNG unavailable");
    let aad_send = [b"seburity-pair-bundle".as_slice(), &my_msg, &peer_msg].concat();
    let ct = cipher.encrypt(XNonce::from_slice(&nonce), Payload { msg: &me_b.encode(me), aad: &aad_send }).map_err(|_| ExchangeError::Malformed)?;
    write_frame(stream, &[nonce.as_slice(), &ct].concat())?;

    let f = read_frame(stream)?;
    if f.len() != 24 + BUNDLE_LEN + 16 { return Err(ExchangeError::Malformed); }
    let aad_recv = [b"seburity-pair-bundle".as_slice(), &peer_msg, &my_msg].concat();
    let pt = cipher.decrypt(XNonce::from_slice(&f[..24]), Payload { msg: &f[24..], aad: &aad_recv }).map_err(|_| ExchangeError::PairingFailed)?;
    let theirs = Bundle::decode(&pt).map_err(|_| ExchangeError::Malformed)?;
    if theirs == me_b { return Err(ExchangeError::Reflection); }
    let sn = safety_number(&me_b, &theirs);
    Ok(Paired { contact: ImportedContact::from_pake(theirs), safety_number: sn })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::thread;

    fn run(code_a: PairingCode, code_b: PairingCode) -> (Result<Paired, ExchangeError>, Result<Paired, ExchangeError>, ContactIdentity, ContactIdentity) {
        let (mut sa, mut sb) = UnixStream::pair().unwrap();
        let (a, b) = (ContactIdentity::generate(), ContactIdentity::generate());
        let (a2, b2) = (ContactIdentity::from_secret_bytes(&a.secret_bytes()).unwrap(), ContactIdentity::from_secret_bytes(&b.secret_bytes()).unwrap());
        let ta = thread::spawn(move || { let r = pair(&mut sa, &a2, code_a); drop(sa); r });
        let tb = thread::spawn(move || { let r = pair(&mut sb, &b2, code_b); drop(sb); r });
        (ta.join().unwrap(), tb.join().unwrap(), a, b)
    }

    #[test]
    fn matching_code_exchanges_bundles_and_safety_numbers() {
        let c = PairingCode::generate();
        let c2 = PairingCode::parse(&c.display()).unwrap();
        let (ra, rb, a, b) = run(c, c2);
        let (ra, rb) = (ra.unwrap(), rb.unwrap());
        assert_eq!(ra.contact.bundle, Bundle::from_identity(&b));
        assert_eq!(rb.contact.bundle, Bundle::from_identity(&a));
        assert_eq!(ra.safety_number, rb.safety_number);
        assert!(ra.contact.verified);
    }

    #[test]
    fn wrong_code_fails_on_both_sides_before_any_bundle() {
        let (ra, rb, _, _) = run(PairingCode::parse("1111111111").unwrap(), PairingCode::parse("1111111112").unwrap());
        assert_eq!(ra.err(), Some(ExchangeError::PairingFailed));
        assert_eq!(rb.err(), Some(ExchangeError::PairingFailed));
    }

    #[test]
    fn reflection_is_rejected() {
        // attacker echoes our own first frame back
        let (mut me, mut atk) = UnixStream::pair().unwrap();
        let id = ContactIdentity::generate();
        let t = thread::spawn(move || pair(&mut me, &id, PairingCode::generate()));
        let f = read_frame(&mut atk).unwrap();
        write_frame(&mut atk, &f).unwrap();
        assert_eq!(t.join().unwrap().err(), Some(ExchangeError::Reflection));
    }

    #[test]
    fn code_parsing_and_generation() {
        assert!(PairingCode::parse("12345-6789").is_err());
        assert!(PairingCode::parse("12345-6789a").is_err());
        assert!(PairingCode::parse("123 45-67890").is_ok());
        let c = PairingCode::generate();
        assert_eq!(c.display().len(), CODE_DIGITS + 1);
        assert_ne!(PairingCode::generate().display(), c.display());
    }

    #[test]
    fn oversized_frame_rejected() {
        let (mut me, mut atk) = UnixStream::pair().unwrap();
        let id = ContactIdentity::generate();
        let t = thread::spawn(move || pair(&mut me, &id, PairingCode::generate()));
        let _ = read_frame(&mut atk);
        atk.write_all(&[0xff, 0xff]).unwrap();
        assert_eq!(t.join().unwrap().err(), Some(ExchangeError::Malformed));
    }
}
