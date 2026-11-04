//! Who is on the other end of the control socket? (review R5-H1)
//! SAFECOOKIE proves the far end can reach a tor that knows the cookie, NOT that it is the tor we think it is: a local
//! process squatting 127.0.0.1:9051 can relay to a real tor. So before we send any secret we check the OS-level owner of
//! the endpoint: a unix socket's peer uid (SO_PEERCRED) or a TCP listener's uid (/proc/net/tcp*). The owner must be us,
//! root, or the owner of the system tor's cookie file in a root-controlled directory.
use std::{net::SocketAddr, os::unix::fs::MetadataExt, path::{Path, PathBuf}};

/// Cookie locations we accept from a tor's PROTOCOLINFO without the user naming them (root-controlled directories).
pub const TRUSTED_COOKIE_PATHS: &[&str] = &["/run/tor/control.authcookie", "/var/run/tor/control.authcookie"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCheck {
    pub verified: bool,
    pub detail: String,
}

fn us() -> u32 { rustix::process::geteuid().as_raw() }

/// uids we accept as "the tor": ours, root, and the owner of the trusted system cookie file (e.g. debian-tor).
fn allowed_uids(extra: &[u32]) -> Vec<u32> {
    let mut v = vec![us(), 0];
    for p in TRUSTED_COOKIE_PATHS {
        if let Ok(m) = std::fs::symlink_metadata(p) { v.push(m.uid()); }
    }
    v.extend_from_slice(extra);
    v.sort_unstable();
    v.dedup();
    v
}

pub fn check_unix_peer(stream: &std::os::unix::net::UnixStream, sock_path: &Path) -> PeerCheck {
    let cred = match rustix::net::sockopt::socket_peercred(stream) {
        Ok(c) => c,
        Err(e) => return PeerCheck { verified: false, detail: format!("cannot read the peer credentials of the control socket ({e})") },
    };
    let peer = cred.uid.as_raw();
    // the socket file's owner is also acceptable (a tor running under its own account in its own directory)
    let owner = std::fs::metadata(sock_path).map(|m| m.uid()).ok();
    let ok = allowed_uids(&owner.into_iter().collect::<Vec<_>>()).contains(&peer);
    PeerCheck { verified: ok, detail: if ok { format!("control socket peer uid {peer} is trusted") } else { format!("control socket peer uid {peer} is NOT us/root/the tor account") } }
}

/// Parse `/proc/net/tcp`-style text: returns the uid of the LISTEN socket bound to `port` on `ip_hex` (or any address).
fn listener_uid_in(table: &str, port: u16, want_ip_hex: &str) -> Option<u32> {
    table.lines().skip(1).find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() < 8 || f[3] != "0A" { return None; }
        let (ip, p) = f[1].rsplit_once(':')?;
        if u16::from_str_radix(p, 16).ok()? != port { return None; }
        if ip != want_ip_hex && !ip.bytes().all(|b| b == b'0') { return None; } // exact ip or the wildcard address
        f[7].parse().ok()
    })
}

pub fn check_tcp_listener(addr: &SocketAddr) -> PeerCheck {
    let (file, ip_hex) = match addr {
        SocketAddr::V4(a) => ("/proc/net/tcp", { let o = a.ip().octets(); format!("{:02X}{:02X}{:02X}{:02X}", o[3], o[2], o[1], o[0]) }),
        SocketAddr::V6(a) => ("/proc/net/tcp6", {
            let o = a.ip().octets();
            (0..4).map(|i| format!("{:02X}{:02X}{:02X}{:02X}", o[i * 4 + 3], o[i * 4 + 2], o[i * 4 + 1], o[i * 4])).collect::<String>()
        }),
    };
    let Ok(t) = std::fs::read_to_string(file) else { return PeerCheck { verified: false, detail: format!("cannot read {file} to find who owns {addr}") } };
    match listener_uid_in(&t, addr.port(), &ip_hex) {
        None => PeerCheck { verified: false, detail: format!("no listening socket found for {addr} (or not owned by a known account)") },
        Some(uid) if allowed_uids(&[]).contains(&uid) => PeerCheck { verified: true, detail: format!("{addr} is owned by trusted uid {uid}") },
        Some(uid) => PeerCheck { verified: false, detail: format!("{addr} is owned by uid {uid}, who is NOT us/root/the tor account: possible squatter") },
    }
}

/// Cookie path acceptable to use? Only an explicit user choice or a well-known root-controlled location.
pub fn cookie_path_allowed(announced: &Path, explicit: Option<&PathBuf>) -> bool {
    explicit.is_some_and(|e| e == announced) || TRUSTED_COOKIE_PATHS.iter().any(|t| Path::new(t) == announced)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::TcpListener, os::unix::net::{UnixListener, UnixStream}};

    #[test]
    fn proc_net_tcp_parsing() {
        let t = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                 0: 0100007F:238B 00000000:0000 0A 00000000:00000000 00:00000000 00000000   108        0 1 1 0 100 0 0 10 0\n\
                 1: 0100007F:2382 00000000:0000 01 00000000:00000000 00:00000000 00000000  1000        0 1 1 0 100 0 0 10 0\n\
                 2: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 1 1 0 100 0 0 10 0\n";
        assert_eq!(listener_uid_in(t, 0x238B, "0100007F"), Some(108));
        assert_eq!(listener_uid_in(t, 0x2382, "0100007F"), None, "only LISTEN rows count");
        assert_eq!(listener_uid_in(t, 0x1F90, "0100007F"), Some(1001), "wildcard bind counts");
        assert_eq!(listener_uid_in(t, 0x238B, "0200007F"), None, "different ip");
        assert_eq!(listener_uid_in("garbage\nnot a table", 1, "0100007F"), None);
    }

    #[test]
    fn our_own_listener_and_unix_peer_are_trusted_unknown_port_is_not() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = l.local_addr().unwrap();
        let c = check_tcp_listener(&a);
        assert!(c.verified, "{}", c.detail);
        let closed = { let t = TcpListener::bind("127.0.0.1:0").unwrap(); t.local_addr().unwrap() };
        assert!(!check_tcp_listener(&closed).verified);

        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("s");
        let ul = UnixListener::bind(&p).unwrap();
        let client = UnixStream::connect(&p).unwrap();
        let _srv = ul.accept().unwrap();
        let c = check_unix_peer(&client, &p);
        assert!(c.verified, "{}", c.detail);
    }

    #[test]
    fn cookie_paths_only_from_the_allow_list_or_explicit_choice() {
        assert!(cookie_path_allowed(Path::new("/run/tor/control.authcookie"), None));
        assert!(!cookie_path_allowed(Path::new("/home/victim/.ssh/id_ed25519"), None));
        assert!(!cookie_path_allowed(Path::new("/etc/passwd"), None));
        let e = PathBuf::from("/media/usb/cookie");
        assert!(cookie_path_allowed(&e, Some(&e)));
        assert!(!cookie_path_allowed(Path::new("/other"), Some(&e)));
    }
}
