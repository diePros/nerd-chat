//! Tor transport, two ways to get a Tor:
//!  * EXTERNAL: use a Tor that is already running (Tails, Whonix, system `tor`, Tor Browser's tor): talk to its
//!    control port (to host onion services) and SOCKS port (to dial).
//!  * SPAWN: start our own `tor` process in a private RAM directory (any machine).
//! Both end in the same `Tor` handle: the only difference is who owns the process.
pub mod control;
pub mod probe;
pub mod socks;
pub mod spawn;
pub mod trust;

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    time::Duration,
};

/// Virtual port our onion services expose (arbitrary, same on both sides).
pub const VIRT_PORT: u16 = 7345;

#[derive(Debug, thiserror::Error)]
pub enum TorError {
    #[error("i/o error: {0}")]
    Io(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("tor refused the command ({code}): {msg}")]
    Rejected { code: u16, msg: String },
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("{0}")]
    Other(String),
}

impl From<std::io::Error> for TorError { fn from(e: std::io::Error) -> Self { TorError::Io(e.to_string()) } }

/// Where our onion service forwards accepted connections. Prefer `Unix` (inside a 0700 directory) when tor runs as us.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target { Tcp(SocketAddr), Unix(PathBuf) }

impl Target {
    /// The `Port=VIRT,<this>` target argument; refuses anything that could alter the command.
    pub fn arg(&self) -> Result<String, TorError> {
        match self {
            Target::Tcp(a) => Ok(a.to_string()),
            Target::Unix(p) => {
                let s = p.to_str().filter(|s| s.starts_with('/') && s.len() <= 100 && s.bytes().all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\'));
                s.map(|s| format!("unix:{s}")).ok_or_else(|| TorError::Other("unsafe or too long unix socket path for an onion target".into()))
            }
        }
    }
}

/// Where a Tor port lives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Addr { Tcp(SocketAddr), Unix(PathBuf) }

/// A byte stream with an adjustable timeout (TCP or Unix socket).
pub trait Stream: Read + Write + Send {
    fn set_timeout(&mut self, d: Option<Duration>) -> std::io::Result<()> { self.set_read_timeout_(d)?; self.set_write_timeout_(d) }
    fn set_read_timeout_(&mut self, d: Option<Duration>) -> std::io::Result<()>;
    fn set_write_timeout_(&mut self, d: Option<Duration>) -> std::io::Result<()>;
}
impl Stream for TcpStream {
    fn set_read_timeout_(&mut self, d: Option<Duration>) -> std::io::Result<()> { self.set_read_timeout(d) }
    fn set_write_timeout_(&mut self, d: Option<Duration>) -> std::io::Result<()> { self.set_write_timeout(d) }
}
#[cfg(unix)]
impl Stream for std::os::unix::net::UnixStream {
    fn set_read_timeout_(&mut self, d: Option<Duration>) -> std::io::Result<()> { self.set_read_timeout(d) }
    fn set_write_timeout_(&mut self, d: Option<Duration>) -> std::io::Result<()> { self.set_write_timeout(d) }
}

impl Addr {
    /// `127.0.0.1:9051`, `[::1]:9051` or `unix:/run/tor/control`.
    pub fn parse(s: &str) -> Option<Addr> {
        match s.strip_prefix("unix:") {
            Some(p) if p.starts_with('/') && !p.contains('\0') => Some(Addr::Unix(PathBuf::from(p))),
            Some(_) => None,
            None => s.parse().ok().map(Addr::Tcp),
        }
    }
}

/// Open a CONTROL connection and check who owns the other end (R5-H1). The verdict decides whether we may authenticate.
pub fn open_control(a: &Addr, timeout: Duration) -> Result<(Box<dyn Stream>, trust::PeerCheck), TorError> {
    match a {
        Addr::Tcp(sa) => {
            let mut t = TcpStream::connect_timeout(sa, timeout)?;
            t.set_timeout(Some(timeout))?;
            let check = trust::check_tcp_listener(sa);
            Ok((Box::new(t), check))
        }
        Addr::Unix(p) => {
            let mut u = std::os::unix::net::UnixStream::connect(p)?;
            u.set_timeout(Some(timeout))?;
            let check = trust::check_unix_peer(&u, p);
            Ok((Box::new(u), check))
        }
    }
}

pub fn open(a: &Addr, timeout: Duration) -> Result<Box<dyn Stream>, TorError> {
    match a {
        Addr::Tcp(s) => {
            let mut t = TcpStream::connect_timeout(s, timeout)?;
            t.set_timeout(Some(timeout))?;
            Ok(Box::new(t))
        }
        #[cfg(unix)]
        Addr::Unix(p) => {
            let mut u = std::os::unix::net::UnixStream::connect(p)?;
            u.set_timeout(Some(timeout))?;
            Ok(Box::new(u))
        }
        #[cfg(not(unix))]
        Addr::Unix(_) => Err(TorError::Other("unix sockets unsupported here".into())),
    }
}

use control::{AuthPref, Controller};
use seburity_core::{bundle::Bundle, identity::ContactIdentity, onion::service_id};

/// A connection to a running tor (ours or someone else's) that can host and dial contact onion services.
pub struct Tor {
    ctl: Controller<Box<dyn Stream>>,
    socks: Addr,
    hosted: Vec<String>,
    /// Peer services whose client-auth credential we installed in this tor (removed again on forget/drop).
    dialed: Vec<String>,
    /// Random per-process SOCKS username (isolation); never a recognisable constant.
    iso_user: String,
    _spawned: Option<spawn::SpawnedTor>,
    /// Opens a FRESH authenticated control connection (used for cleanup when the current one is broken).
    reconnect: Option<Reconnect>,
}

type Reconnect = Box<dyn Fn() -> Result<Controller<Box<dyn Stream>>, TorError> + Send>;

impl Tor {
    pub(crate) fn from_parts(ctl: Controller<Box<dyn Stream>>, socks: Addr, spawned: Option<spawn::SpawnedTor>) -> Self {
        let mut r = [0u8; 8];
        getrandom::fill(&mut r).expect("OS RNG unavailable");
        Self { ctl, socks, hosted: vec![], dialed: vec![], iso_user: r.iter().map(|b| format!("{b:02x}")).collect(), _spawned: spawned, reconnect: None }
    }

    pub(crate) fn with_reconnect(mut self, f: Reconnect) -> Self { self.reconnect = Some(f); self }

    /// After an error the control connection is poisoned and every later DEL_ONION / ONION_CLIENT_AUTH_REMOVE would fail
    /// silently, leaving our client-auth secrets in a (possibly shared) tor. Swap in a fresh connection first. Dropping the
    /// old one also makes tor remove the (non-detached) services it created.
    fn healthy_ctl(&mut self) {
        if !self.ctl.is_broken() { return; }
        if let Some(f) = &self.reconnect {
            if let Ok(c) = f() { self.ctl = c; }
        }
    }

    /// EXTERNAL mode: authenticate to an already running tor. SOCKS defaults to what tor itself reports.
    /// We only authenticate (and so only ever send onion secrets) if the control endpoint's OWNER is verified
    /// (unix peer uid / TCP listener uid is us, root or the system tor account), or `trust_control` is set.
    /// NOTE: everything with control access to this tor can read our client-auth keys and see our onion traffic.
    pub fn connect_external(control: &Addr, auth: &AuthPref, socks: Option<Addr>, trust_control: bool) -> Result<Self, TorError> {
        let (stream, check) = open_control(control, Duration::from_secs(10))?;
        let pref = AuthPref { password: auth.password.clone(), cookie_path: auth.cookie_path.clone(), peer_verified: auth.peer_verified || check.verified || trust_control };
        if !pref.peer_verified { return Err(TorError::Auth(format!("{} - refusing to talk secrets to it (override with --tor-trust-control only if you trust every local process)", control::sanitize(&check.detail)))); }
        let mut ctl = Controller::new(stream);
        ctl.authenticate(&pref)?;
        let socks = match socks {
            Some(s) => s,
            None => ctl.socks_listeners()?.into_iter().next().ok_or_else(|| TorError::Other("tor reports no SOCKS listener".into()))?,
        };
        let (control, password, cookie) = (control.clone(), pref.password.clone(), pref.cookie_path.clone());
        Ok(Self::from_parts(ctl, socks, None).with_reconnect(Box::new(move || {
            // the endpoint was verified (or trusted) when we first connected; re-check ownership anyway
            let (stream, check) = open_control(&control, Duration::from_secs(10))?;
            if !check.verified && !trust_control { return Err(TorError::Auth("control endpoint no longer verified".into())); }
            let mut c = Controller::new(stream);
            c.authenticate(&AuthPref { password: password.clone(), cookie_path: cookie.clone(), peer_verified: true })?;
            Ok(c)
        })))
    }

    /// SPAWN mode: start our own tor, wait until it has bootstrapped (reports progress 0..=100).
    pub fn spawn(cfg: &spawn::SpawnConfig, timeout: Duration, mut progress: impl FnMut(u8)) -> Result<Self, TorError> {
        let sp = spawn::SpawnedTor::start(cfg)?;
        // we created the sockets in our own 0700 directory: the endpoint is ours by construction
        let pref = AuthPref { password: None, cookie_path: Some(sp.cookie_path()), peer_verified: true };
        let mut ctl = Controller::new(open(&sp.control, Duration::from_secs(10))?);
        ctl.authenticate(&pref)?;
        let end = std::time::Instant::now() + timeout;
        loop {
            let p = ctl.bootstrap_progress()?;
            progress(p);
            if p >= 100 { break; }
            if std::time::Instant::now() > end { return Err(TorError::Other(format!("tor bootstrap stalled at {p}% (offline? needs bridges?)"))); }
            std::thread::sleep(Duration::from_millis(500));
        }
        let socks = sp.socks.clone();
        let (control, cookie) = (sp.control.clone(), sp.cookie_path());
        Ok(Self::from_parts(ctl, socks, Some(sp)).with_reconnect(Box::new(move || {
            let mut c = Controller::new(open(&control, Duration::from_secs(10))?);
            c.authenticate(&AuthPref { password: None, cookie_path: Some(cookie.clone()), peer_verified: true })?;
            Ok(c)
        })))
    }

    pub fn bootstrap_progress(&mut self) -> Result<u8, TorError> { self.ctl.bootstrap_progress() }

    /// The private (0700, RAM) directory of our own spawned tor, if any: a safe place for our onion-target unix sockets.
    pub fn spawn_dir(&self) -> Option<&std::path::Path> { self._spawned.as_ref().map(|s| s.dir()) }

    /// Stop hosting a service (best effort).
    pub fn unhost(&mut self, service_id: &str) {
        self.healthy_ctl();
        if let Some(i) = self.hosted.iter().position(|h| h == service_id) {
            let id = self.hosted.remove(i);
            let _ = self.ctl.del_onion(&id);
        }
    }

    /// Host OUR onion service for this contact: reachable only by the peer's authorized client key.
    /// `target` is where our listener accepts the (Noise) connections tor forwards: prefer a unix socket in a 0700 dir
    /// when tor runs as us (spawn mode); external tors need TCP loopback.
    pub fn host(&mut self, me: &ContactIdentity, peer: &Bundle, target: &Target) -> Result<String, TorError> {
        let id = self.ctl.add_onion(&me.onion_expanded_secret(), VIRT_PORT, target, &[peer.auth_pub], &me.onion_public())?;
        debug_assert_eq!(id, service_id(&me.onion_public()));
        self.hosted.push(id.clone());
        Ok(id)
    }

    /// Give tor our private client-auth key for the PEER's onion service (needed before dialing it).
    pub fn allow_dial(&mut self, me: &ContactIdentity, peer: &Bundle) -> Result<(), TorError> {
        let id = service_id(&peer.onion_pub);
        self.ctl.client_auth_add(&id, &me.auth_secret_bytes())?;
        if !self.dialed.contains(&id) { self.dialed.push(id); }
        Ok(())
    }

    /// Remove the credential installed by `allow_dial` (best effort).
    pub fn forget_dial(&mut self, peer_onion_pub: &[u8; 32]) {
        self.healthy_ctl();
        let id = service_id(peer_onion_pub);
        if let Some(i) = self.dialed.iter().position(|d| *d == id) {
            let id = self.dialed.remove(i);
            let _ = self.ctl.client_auth_remove(&id);
        }
    }

    /// A cheap, thread-safe handle that can dial through this tor's SOCKS port without the control connection.
    pub fn dialer(&self) -> Dialer { Dialer { socks: self.socks.clone(), user: self.iso_user.clone() } }

    /// Dial the peer's onion service. `isolation` makes tor use a separate circuit per value (use one per contact).
    pub fn dial(&mut self, peer: &Bundle, isolation: &[u8; 16]) -> Result<Box<dyn Stream>, TorError> { self.dialer().dial(peer, isolation) }
}

/// Dials contact onion services through a tor's SOCKS port (clone it into worker threads).
#[derive(Clone, Debug)]
pub struct Dialer { socks: Addr, user: String }

impl Dialer {
    pub fn dial(&self, peer: &Bundle, isolation: &[u8; 16]) -> Result<Box<dyn Stream>, TorError> {
        let mut s = open(&self.socks, Duration::from_secs(10))?;
        s.set_timeout(Some(Duration::from_secs(120)))?; // circuit + rendezvous can be slow
        let pass: String = isolation.iter().map(|b| format!("{b:02x}")).collect();
        socks::connect(&mut s, &peer.onion_address(), VIRT_PORT, Some((self.user.as_bytes(), pass.as_bytes())))
            .map_err(|e| TorError::Other(e.to_string()))?;
        Ok(s)
    }
}

impl Drop for Tor {
    fn drop(&mut self) {
        self.healthy_ctl();
        for id in std::mem::take(&mut self.hosted) { let _ = self.ctl.del_onion(&id); }
        for id in std::mem::take(&mut self.dialed) { let _ = self.ctl.client_auth_remove(&id); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::{Read, Write}, os::unix::net::UnixListener, thread};

    /// R6-M3: client-auth secrets must not outlive the contact/session inside a shared tor.
    #[test]
    fn dialed_credentials_are_removed_on_forget_and_on_drop() {
        let me = ContactIdentity::generate();
        let (p1, p2) = (Bundle::from_identity(&ContactIdentity::generate()), Bundle::from_identity(&ContactIdentity::generate()));
        let (id1, id2) = (service_id(&p1.onion_pub), service_id(&p2.onion_pub));
        let (ctl, h) = control::tests::fake(vec![
            ("ONION_CLIENT_AUTH_ADD ", "250 OK\r\n".into()),
            ("ONION_CLIENT_AUTH_ADD ", "250 OK\r\n".into()),
            ("ONION_CLIENT_AUTH_REMOVE ", "250 OK\r\n".into()),
            ("ONION_CLIENT_AUTH_REMOVE ", "250 OK\r\n".into()),
        ]);
        let (sock, _keep) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut tor = Tor::from_parts(Controller::new(Box::new(ctl.into_inner()) as Box<dyn Stream>), Addr::Unix("/nonexistent".into()), None);
        drop(sock);
        tor.allow_dial(&me, &p1).unwrap();
        tor.allow_dial(&me, &p2).unwrap();
        tor.forget_dial(&p1.onion_pub);   // contact deleted
        drop(tor);                        // session over: the other one goes too
        let seen = h.join().unwrap();
        assert_eq!(seen[2], format!("ONION_CLIENT_AUTH_REMOVE {id1}"));
        assert_eq!(seen[3], format!("ONION_CLIENT_AUTH_REMOVE {id2}"));
    }

    /// R8-L5: after a control-connection error, cleanup must still reach tor (fresh connection), not fail silently.
    #[test]
    fn cleanup_uses_a_fresh_control_connection_when_the_old_one_is_broken() {
        let me = ContactIdentity::generate();
        let p1 = Bundle::from_identity(&ContactIdentity::generate());
        let id1 = service_id(&p1.onion_pub);
        let (ctl, h) = control::tests::fake(vec![("ONION_CLIENT_AUTH_ADD ", "250 OK\r\n".into())]);
        let (fresh, h2) = control::tests::fake(vec![("ONION_CLIENT_AUTH_REMOVE ", "250 OK\r\n".into())]);
        let fresh = std::sync::Mutex::new(Some(fresh.into_inner()));
        let (sock, _keep) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut tor = Tor::from_parts(Controller::new(Box::new(ctl.into_inner()) as Box<dyn Stream>), Addr::Unix("/nonexistent".into()), None)
            .with_reconnect(Box::new(move || Ok(Controller::new(Box::new(fresh.lock().unwrap().take().ok_or(TorError::Io("once".into()))?) as Box<dyn Stream>))));
        drop(sock);
        tor.allow_dial(&me, &p1).unwrap();
        h.join().unwrap(); // the first fake is gone: the next command on it fails and poisons it
        let _ = tor.ctl.command("GETINFO version");
        assert!(tor.ctl.is_broken());
        tor.forget_dial(&p1.onion_pub);
        assert_eq!(h2.join().unwrap()[0], format!("ONION_CLIENT_AUTH_REMOVE {id1}"));
    }

    #[test]
    fn addr_parsing() {
        assert_eq!(Addr::parse("127.0.0.1:9051"), Some(Addr::Tcp("127.0.0.1:9051".parse().unwrap())));
        assert_eq!(Addr::parse("unix:/run/tor/control"), Some(Addr::Unix("/run/tor/control".into())));
        for bad in ["unix:relative", "localhost:9051", "", "unix:", "9051"] { assert_eq!(Addr::parse(bad), None, "{bad}"); }
    }

    #[test]
    fn dial_goes_through_socks_with_isolation_and_returns_a_usable_stream() {
        let d = tempfile::tempdir().unwrap();
        let sock = d.path().join("socks");
        let l = UnixListener::bind(&sock).unwrap();
        let h = thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            let mut g = [0u8; 3]; c.read_exact(&mut g).unwrap(); assert_eq!(g, [5, 1, 2]); c.write_all(&[5, 2]).unwrap();
            let mut a = [0u8; 2]; c.read_exact(&mut a).unwrap(); assert_eq!(a, [1, 16]);
            let mut u = [0u8; 16]; c.read_exact(&mut u).unwrap();
            assert!(u.iter().all(u8::is_ascii_hexdigit) && &u != b"seburity\0\0\0\0\0\0\0\0", "neutral random username");
            let mut pl = [0u8; 1]; c.read_exact(&mut pl).unwrap(); assert_eq!(pl[0], 32);
            let mut p = [0u8; 32]; c.read_exact(&mut p).unwrap(); assert_eq!(&p[..], "ab".repeat(16).as_bytes());
            c.write_all(&[1, 0]).unwrap();
            let mut req = [0u8; 5]; c.read_exact(&mut req).unwrap(); assert_eq!(&req[..4], &[5, 1, 0, 3]);
            let mut rest = vec![0u8; req[4] as usize + 2]; c.read_exact(&mut rest).unwrap();
            let host = String::from_utf8(rest[..rest.len() - 2].to_vec()).unwrap();
            assert!(host.ends_with(".onion") && host.len() == 62, "{host}");
            assert_eq!(&rest[rest.len() - 2..], &VIRT_PORT.to_be_bytes());
            c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
            c.write_all(b"hello").unwrap(); // application data right after the SOCKS reply
        });
        let (ctl_a, _ctl_b) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut tor = Tor::from_parts(Controller::new(Box::new(ctl_a)), Addr::Unix(sock), None);
        let peer = Bundle::from_identity(&ContactIdentity::generate());
        let mut s = tor.dial(&peer, &[0xab; 16]).unwrap();
        let mut b = [0u8; 5]; s.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"hello", "SOCKS reply fully consumed; stream positioned at app data");
        h.join().unwrap();
    }
}
