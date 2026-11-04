//! Tor transport, two ways to get a Tor:
//!  * EXTERNAL: use a Tor that is already running (Tails, Whonix, system `tor`, Tor Browser's tor): talk to its
//!    control port (to host onion services) and SOCKS port (to dial).
//!  * SPAWN: start our own `tor` process in a private RAM directory (any machine).
//! Both end in the same `Tor` handle: the only difference is who owns the process.
pub mod control;
pub mod probe;
pub mod socks;
pub mod spawn;

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

/// Where a Tor port lives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Addr { Tcp(SocketAddr), Unix(PathBuf) }

/// A byte stream with an adjustable timeout (TCP or Unix socket).
pub trait Stream: Read + Write + Send {
    fn set_timeout(&mut self, d: Option<Duration>) -> std::io::Result<()>;
}
impl Stream for TcpStream {
    fn set_timeout(&mut self, d: Option<Duration>) -> std::io::Result<()> { self.set_read_timeout(d)?; self.set_write_timeout(d) }
}
#[cfg(unix)]
impl Stream for std::os::unix::net::UnixStream {
    fn set_timeout(&mut self, d: Option<Duration>) -> std::io::Result<()> { self.set_read_timeout(d)?; self.set_write_timeout(d) }
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
    _spawned: Option<spawn::SpawnedTor>,
}

impl Tor {
    pub(crate) fn from_parts(ctl: Controller<Box<dyn Stream>>, socks: Addr, spawned: Option<spawn::SpawnedTor>) -> Self {
        Self { ctl, socks, hosted: vec![], _spawned: spawned }
    }

    /// EXTERNAL mode: authenticate to an already running tor. SOCKS defaults to what tor itself reports.
    pub fn connect_external(control: &Addr, auth: &AuthPref, socks: Option<Addr>) -> Result<Self, TorError> {
        let mut ctl = Controller::new(open(control, Duration::from_secs(10))?);
        ctl.authenticate(auth)?;
        let socks = match socks {
            Some(s) => s,
            None => ctl.socks_listeners()?.into_iter().next().ok_or_else(|| TorError::Other("tor reports no SOCKS listener".into()))?,
        };
        Ok(Self::from_parts(ctl, socks, None))
    }

    /// SPAWN mode: start our own tor, wait until it has bootstrapped (reports progress 0..=100).
    pub fn spawn(cfg: &spawn::SpawnConfig, timeout: Duration, mut progress: impl FnMut(u8)) -> Result<Self, TorError> {
        let sp = spawn::SpawnedTor::start(cfg)?;
        let pref = AuthPref { password: None, cookie_path: Some(sp.cookie_path()) };
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
        Ok(Self::from_parts(ctl, socks, Some(sp)))
    }

    pub fn bootstrap_progress(&mut self) -> Result<u8, TorError> { self.ctl.bootstrap_progress() }

    /// Host OUR onion service for this contact: reachable only by the peer's authorized client key.
    /// `local` is where our listener accepts the (Noise) connections tor forwards.
    pub fn host(&mut self, me: &ContactIdentity, peer: &Bundle, local: SocketAddr) -> Result<String, TorError> {
        let id = self.ctl.add_onion(&me.onion_expanded_secret(), VIRT_PORT, local, &[peer.auth_pub], &me.onion_public())?;
        debug_assert_eq!(id, service_id(&me.onion_public()));
        self.hosted.push(id.clone());
        Ok(id)
    }

    /// Give tor our private client-auth key for the PEER's onion service (needed before dialing it).
    pub fn allow_dial(&mut self, me: &ContactIdentity, peer: &Bundle) -> Result<(), TorError> {
        self.ctl.client_auth_add(&service_id(&peer.onion_pub), &me.auth_secret_bytes())
    }

    /// Dial the peer's onion service. `isolation` makes tor use a separate circuit per value (use one per contact).
    pub fn dial(&mut self, peer: &Bundle, isolation: &[u8; 16]) -> Result<Box<dyn Stream>, TorError> {
        let mut s = open(&self.socks, Duration::from_secs(10))?;
        s.set_timeout(Some(Duration::from_secs(120)))?; // circuit + rendezvous can be slow
        let pass: String = isolation.iter().map(|b| format!("{b:02x}")).collect();
        socks::connect(&mut s, &peer.onion_address(), VIRT_PORT, Some((b"seburity", pass.as_bytes()))).map_err(|e| TorError::Other(e.to_string()))?;
        Ok(s)
    }
}

impl Drop for Tor {
    fn drop(&mut self) {
        for id in std::mem::take(&mut self.hosted) { let _ = self.ctl.del_onion(&id); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::{Read, Write}, os::unix::net::UnixListener, thread};

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
            let mut a = [0u8; 2]; c.read_exact(&mut a).unwrap(); assert_eq!(a, [1, 8]);
            let mut u = [0u8; 8]; c.read_exact(&mut u).unwrap(); assert_eq!(&u, b"seburity");
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
