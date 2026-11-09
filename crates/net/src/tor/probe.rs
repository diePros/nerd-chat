//! `sine-loco --probe-tor`: find out what the Tor on THIS machine allows (Tails, Whonix, system tor...).
//! Passive by default; `try_onion` additionally creates and removes one throwaway onion service.
use super::{control::{sanitize, AuthPref, Controller}, open, open_control, Addr, Target, TorError};
use sine_loco_core::{bundle::Bundle, identity::ContactIdentity};
use std::{net::SocketAddr, path::PathBuf, time::Duration};

pub struct Candidates { pub control: Vec<Addr>, pub socks: Vec<Addr> }

impl Candidates {
    pub fn standard() -> Self {
        let tcp = |p: u16| Addr::Tcp(SocketAddr::from(([127, 0, 0, 1], p)));
        Self {
            control: vec![tcp(9051), tcp(9151), Addr::Unix(PathBuf::from("/run/tor/control")), Addr::Unix(PathBuf::from("/var/run/tor/control"))],
            socks: vec![tcp(9050), tcp(9150), Addr::Unix(PathBuf::from("/run/tor/socks"))],
        }
    }
}

fn show(a: &Addr) -> String { match a { Addr::Tcp(s) => s.to_string(), Addr::Unix(p) => format!("unix:{}", p.display()) } }

/// Returns human-readable report lines. Never prints cookie contents.
/// `trust_control`: the user vouches for the control port's owner (like `--tor-trust-control`).
pub fn probe(c: &Candidates, try_onion: bool, auth: &AuthPref, trust_control: bool) -> Vec<String> {
    let mut out = vec![];
    match super::spawn::find_tor() { Some(p) => out.push(format!("tor binary in PATH: {}", p.display())), None => out.push("tor binary in PATH: none (spawn mode unavailable unless you pass --tor-path)".into()) }
    let mut working_ctl: Option<Addr> = None;
    for a in &c.control {
        match open_control(a, Duration::from_secs(2)) {
            Err(e) => out.push(format!("control {}: not reachable ({})", show(a), sanitize(&e.to_string()))),
            Ok((s, check)) => {
                let mut ctl = Controller::new(s);
                match ctl.protocolinfo() {
                    Err(e) => out.push(format!("control {}: reachable but not a tor control port ({})", show(a), sanitize(&e.to_string()))),
                    Ok(pi) => {
                        out.push(format!("control {}: tor {} offers auth methods [{}]", show(a), sanitize(pi.version.as_deref().unwrap_or("?")), sanitize(&pi.methods.join(","))));
                        out.push(format!("  owner check: {} -> {}", sanitize(&check.detail), if check.verified { "TRUSTED" } else if trust_control { "NOT verified, trusted by --tor-trust-control" } else { "NOT TRUSTED (will not authenticate)" }));
                        if let Some(cf) = &pi.cookie_file {
                            let known = super::trust::cookie_path_allowed(std::path::Path::new(cf), auth.cookie_path.as_ref());
                            match super::control::read_cookie(std::path::Path::new(cf)) {
                                Ok(_) => out.push(format!("  cookie file {}: readable by this user{}", sanitize(cf), if known { "" } else { " (but NOT a known location: pass --tor-cookie to use it)" })),
                                Err(e) => out.push(format!("  cookie file {}: NOT usable ({})", sanitize(cf), sanitize(&e.to_string()))),
                            }
                        }
                        let pref = AuthPref { password: auth.password.clone(), cookie_path: auth.cookie_path.clone(), peer_verified: check.verified || trust_control };
                        // reuse the PROTOCOLINFO we already have: tor allows it only once before authentication
                        match ctl.authenticate_with(&pi, &pref) {
                            Ok(()) => { out.push("  authentication: OK".into()); working_ctl.get_or_insert(a.clone()); }
                            Err(e) => out.push(format!("  authentication: FAILED ({})", sanitize(&e.to_string()))),
                        }
                        if ctl.authenticated {
                            if let Ok(l) = ctl.socks_listeners() { out.push(format!("  tor's SOCKS listeners: {}", l.iter().map(show).collect::<Vec<_>>().join(", "))); }
                            if let Ok(p) = ctl.bootstrap_progress() { out.push(format!("  bootstrap: {p}%")); }
                            if try_onion { out.push(onion_test(&mut ctl)); }
                        }
                    }
                }
            }
        }
    }
    for a in &c.socks {
        match open(a, Duration::from_secs(2)) {
            Err(e) => out.push(format!("socks {}: not reachable ({e})", show(a))),
            Ok(mut s) => {
                use std::io::{Read, Write};
                let ok = s.write_all(&[5, 1, 0]).is_ok() && { let mut r = [0u8; 2]; s.read_exact(&mut r).is_ok() && r == [5, 0] };
                out.push(format!("socks {}: {}", show(a), if ok { "answers SOCKS5 (no-auth)" } else { "open but did not answer like a SOCKS5 proxy" }));
            }
        }
    }
    if working_ctl.is_none() { out.push("RESULT: no authenticated control port. Sine Loco can still DIAL contacts through a SOCKS port, but cannot HOST onion services here.".into()); }
    else { out.push("RESULT: control port works: both dialing and hosting are possible".into()); }
    out
}

/// What a quiet hosting probe found out (used automatically at export/pairing, R12-5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostProbe {
    /// tor accepted and removed a throwaway onion service: we can host.
    Can,
    /// tor answered but refused to host (filtered control port): we cannot host, say so in the bundle.
    Cannot(String),
    /// no answer we can rely on (tor not running, auth failed, owner not verified...): do NOT fix a capability on this.
    Unknown(String),
}

/// Ask the tor behind `control` whether it lets us host onion services, by creating and removing one throwaway service.
/// Only the reply 510 ("command filtered / unrecognized": what a restricted control port such as Tails' answers) counts as `Cannot`;
/// every other failure (451 resource exhausted, 55x internal errors, auth failure, timeouts, odd codes) is `Unknown`, because the
/// bit that follows from it is permanent per contact. Nothing is sent unless the owner of the control port is verified (or trusted).
/// Blocking: call it from a worker thread.
pub fn probe_hosting(control: &Addr, auth: &AuthPref, trust_control: bool) -> HostProbe {
    let unknown = |what: &str, e: &dyn std::fmt::Display| HostProbe::Unknown(format!("{what}: {}", sanitize(&e.to_string())));
    let (s, check) = match open_control(control, Duration::from_secs(5)) { Ok(x) => x, Err(e) => return unknown("tor control port not reachable", &e) };
    if !(auth.peer_verified || check.verified || trust_control) {
        return HostProbe::Unknown(format!("the owner of the control port is not verified ({}); pass --tor-trust-control only if you vouch for it", sanitize(&check.detail)));
    }
    let mut ctl = Controller::new(s);
    let pref = AuthPref { password: auth.password.clone(), cookie_path: auth.cookie_path.clone(), peer_verified: true };
    if let Err(e) = ctl.authenticate(&pref) { return unknown("cannot authenticate to the tor control port", &e); }
    classify(onion_attempt(&mut ctl))
}

fn classify(r: Result<(), TorError>) -> HostProbe {
    match r {
        Ok(()) => HostProbe::Can,
        Err(TorError::Rejected { code: 510, msg }) => HostProbe::Cannot(format!("tor refused to host (510 {})", sanitize(&msg))),
        Err(e) => HostProbe::Unknown(format!("hosting test failed: {}", sanitize(&e.to_string()))),
    }
}

fn onion_attempt<S: std::io::Read + std::io::Write>(ctl: &mut Controller<S>) -> Result<(), TorError> {
    let id = ContactIdentity::generate();
    let dummy = Bundle::from_identity(&ContactIdentity::generate());
    let mut r = [0u8; 2];
    getrandom::fill(&mut r).map_err(|_| TorError::Other("no OS randomness".into()))?;
    let target = Target::Tcp(SocketAddr::from(([127, 0, 0, 1], 49152 + u16::from_be_bytes(r) % 16000))); // like real hosting: a high port
    let sid = ctl.add_onion(&id.onion_expanded_secret(), super::VIRT_PORT, &target, &[dummy.auth_pub], &id.onion_public())?;
    let _ = ctl.del_onion(&sid);
    Ok(())
}

/// Create one throwaway onion service (with a dummy authorized client) and remove it again.
fn onion_test<S: std::io::Read + std::io::Write>(ctl: &mut Controller<S>) -> String {
    match onion_attempt(ctl) {
        Ok(()) => "  ADD_ONION (hosting onion services): ALLOWED".into(),
        Err(TorError::Rejected { code, msg }) => format!("  ADD_ONION: REFUSED by tor ({code} {}) - hosting not possible through this control port", sanitize(&msg)),
        Err(e) => format!("  ADD_ONION: failed ({})", sanitize(&e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::{Read, Write}, os::unix::net::UnixListener, thread};

    #[test]
    fn probe_reports_unreachable_and_non_tor_ports_without_panicking() {
        let d = tempfile::tempdir().unwrap();
        let sock = d.path().join("notor");
        let l = UnixListener::bind(&sock).unwrap();
        thread::spawn(move || { for mut s in l.incoming().flatten() { let _ = s.write_all(b"SSH-2.0-nope\r\n"); let mut b = [0u8; 64]; let _ = s.read(&mut b); } });
        let c = Candidates { control: vec![Addr::Unix(d.path().join("missing")), Addr::Unix(sock)], socks: vec![Addr::Unix(d.path().join("nosocks"))] };
        let r = probe(&c, false, &AuthPref::default(), false).join("\n");
        assert!(r.contains("not reachable"), "{r}");
        assert!(r.contains("not a tor control port") || r.contains("reachable but"), "{r}");
        assert!(r.contains("RESULT: no authenticated control port"), "{r}");
    }

    #[test]
    fn only_510_is_cannot_everything_else_is_unknown() {
        let rej = |code: u16| classify(Err(TorError::Rejected { code, msg: "x".into() }));
        assert!(matches!(rej(510), HostProbe::Cannot(_)));
        for c in [451, 512, 513, 515, 550, 551, 552, 400, 300, 700] { assert!(matches!(rej(c), HostProbe::Unknown(_)), "{c}"); }
        assert!(matches!(classify(Err(TorError::Other("boom".into()))), HostProbe::Unknown(_)));
        assert_eq!(classify(Ok(())), HostProbe::Can);
    }

    /// A scripted tor on a unix socket we own (so the owner check passes): NULL auth, then the given ADD_ONION answer twice (hardened + plain).
    fn scripted(answer: &'static str) -> (tempfile::TempDir, Addr) {
        let d = tempfile::tempdir().unwrap();
        let sock = d.path().join("ctl");
        let l = UnixListener::bind(&sock).unwrap();
        thread::spawn(move || {
            for mut s in l.incoming().flatten() {
                let mut rd = std::io::BufReader::new(s.try_clone().unwrap());
                let mut line = String::new();
                while { line.clear(); std::io::BufRead::read_line(&mut rd, &mut line).unwrap_or(0) > 0 } {
                    let r: &str = if line.starts_with("PROTOCOLINFO") { "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=NULL\r\n250-VERSION Tor=\"0.4.8.9\"\r\n250 OK\r\n" }
                        else if line.starts_with("AUTHENTICATE") { "250 OK\r\n" } else { answer };
                    if s.write_all(r.as_bytes()).is_err() { break; }
                }
            }
        });
        (d, Addr::Unix(sock))
    }

    #[test]
    fn probe_hosting_end_to_end_against_a_scripted_tor() {
        let (_d, a) = scripted("510 Command filtered\r\n");
        assert!(matches!(probe_hosting(&a, &AuthPref::default(), false), HostProbe::Cannot(_)));
        let (_d, a) = scripted("451 Resource exhausted\r\n");
        assert!(matches!(probe_hosting(&a, &AuthPref::default(), false), HostProbe::Unknown(_)), "451 is transient, never a permanent Cannot");
        let (_d, a) = scripted("250-ServiceID=aaaa\r\n250 OK\r\n");
        assert!(matches!(probe_hosting(&a, &AuthPref::default(), false), HostProbe::Unknown(_)), "a wrong ServiceID is not Can");
        let d = tempfile::tempdir().unwrap();
        assert!(matches!(probe_hosting(&Addr::Unix(d.path().join("nothing")), &AuthPref::default(), false), HostProbe::Unknown(_)));
    }
}
