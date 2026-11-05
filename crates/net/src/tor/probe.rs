//! `nerd-chat --probe-tor`: find out what the Tor on THIS machine allows (Tails, Whonix, system tor...).
//! Passive by default; `try_onion` additionally creates and removes one throwaway onion service.
use super::{control::{sanitize, AuthPref, Controller}, open, open_control, Addr, Target, TorError};
use nerd_chat_core::{bundle::Bundle, identity::ContactIdentity};
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
    if working_ctl.is_none() { out.push("RESULT: no authenticated control port. Nerd-chat can still DIAL contacts through a SOCKS port, but cannot HOST onion services here.".into()); }
    else { out.push("RESULT: control port works: both dialing and hosting are possible".into()); }
    out
}

/// Create one throwaway onion service (with a dummy authorized client) and remove it again.
fn onion_test<S: std::io::Read + std::io::Write>(ctl: &mut Controller<S>) -> String {
    let id = ContactIdentity::generate();
    let dummy = Bundle::from_identity(&ContactIdentity::generate());
    let target = Target::Tcp(SocketAddr::from(([127, 0, 0, 1], 9)));
    match ctl.add_onion(&id.onion_expanded_secret(), super::VIRT_PORT, &target, &[dummy.auth_pub], &id.onion_public()) {
        Ok(sid) => { let _ = ctl.del_onion(&sid); "  ADD_ONION (hosting onion services): ALLOWED".into() }
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
        thread::spawn(move || { for s in l.incoming() { if let Ok(mut s) = s { let _ = s.write_all(b"SSH-2.0-nope\r\n"); let mut b = [0u8; 64]; let _ = s.read(&mut b); } } });
        let c = Candidates { control: vec![Addr::Unix(d.path().join("missing")), Addr::Unix(sock)], socks: vec![Addr::Unix(d.path().join("nosocks"))] };
        let r = probe(&c, false, &AuthPref::default(), false).join("\n");
        assert!(r.contains("not reachable"), "{r}");
        assert!(r.contains("not a tor control port") || r.contains("reachable but"), "{r}");
        assert!(r.contains("RESULT: no authenticated control port"), "{r}");
    }
}
