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
    /// Close both directions NOW (wakes a thread blocked in `read`): cancel and panic use it. The default does nothing (streams that
    /// cannot be interrupted must not be used for pairing).
    fn shutdown(&self) {}
    /// A handle that closes this stream from ANOTHER thread (cancel/panic while a worker is blocked in `read`). `None` = cannot.
    fn killer(&self) -> Option<Box<dyn Fn() + Send + Sync>> { None }
}
impl Stream for TcpStream {
    fn shutdown(&self) { let _ = TcpStream::shutdown(self, std::net::Shutdown::Both); }
    fn killer(&self) -> Option<Box<dyn Fn() + Send + Sync>> { let c = self.try_clone().ok()?; Some(Box::new(move || { let _ = c.shutdown(std::net::Shutdown::Both); })) }
    fn set_read_timeout_(&mut self, d: Option<Duration>) -> std::io::Result<()> { self.set_read_timeout(d) }
    fn set_write_timeout_(&mut self, d: Option<Duration>) -> std::io::Result<()> { self.set_write_timeout(d) }
}
#[cfg(unix)]
impl Stream for std::os::unix::net::UnixStream {
    fn shutdown(&self) { let _ = std::os::unix::net::UnixStream::shutdown(self, std::net::Shutdown::Both); }
    fn killer(&self) -> Option<Box<dyn Fn() + Send + Sync>> { let c = self.try_clone().ok()?; Some(Box::new(move || { let _ = c.shutdown(std::net::Shutdown::Both); })) }
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
use nerd_chat_core::{bundle::Bundle, identity::ContactIdentity, onion::service_id};

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

type Reconnect = std::sync::Arc<dyn Fn() -> Result<Controller<Box<dyn Stream>>, TorError> + Send + Sync>;

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
        Ok(Self::from_parts(ctl, socks, None).with_reconnect(std::sync::Arc::new(move || {
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
        Ok(Self::from_parts(ctl, socks, Some(sp)).with_reconnect(std::sync::Arc::new(move || {
            let mut c = Controller::new(open(&control, Duration::from_secs(10))?);
            c.authenticate(&AuthPref { password: None, cookie_path: Some(cookie.clone()), peer_verified: true })?;
            Ok(c)
        })))
    }

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
    /// `extra_auth`: further client keys to authorize (the peer's previous key during a key rotation).
    pub fn host_with(&mut self, me: &ContactIdentity, peer: &Bundle, extra_auth: &[[u8; 32]], target: &Target) -> Result<String, TorError> {
        let mut auth = vec![peer.auth_pub];
        for a in extra_auth.iter().take(2) { if !auth.contains(a) { auth.push(*a); } }
        let id = self.ctl.add_onion(&me.onion_expanded_secret(), VIRT_PORT, target, &auth, &me.onion_public())?;
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

// ---------------------------------------------------------------- one-shot pairing service (docs/superpowers/specs/2026-11-09-tor-pairing-spec.md)
use std::sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex};

/// Parse what a joiner pastes: the bare 56-character onion id, `nerdchat:pair/<id>` or `<id>.onion`; whitespace is trimmed and the text
/// lowercased first (some apps capitalise), then the strict v3 check (length, base32, version byte, checksum) applies.
pub fn parse_pairing_link(s: &str) -> Result<String, TorError> {
    let t = s.trim().to_ascii_lowercase();
    let t = t.strip_prefix("nerdchat:pair/").unwrap_or(&t);
    let t = t.strip_suffix(".onion").unwrap_or(t);
    nerd_chat_core::onion::parse_onion_address(t).map_err(|_| TorError::Other("that is not a valid pairing link".into()))?;
    Ok(t.to_string())
}

/// Cancels a pairing from another thread: sets a flag and closes every stream registered with it (a worker blocked in a SOCKS
/// handshake or in `read` wakes up with an error). Cancel is permanent for this token.
#[derive(Default)]
pub struct CancelToken { flag: AtomicBool, killers: Mutex<Vec<Box<dyn Fn() + Send + Sync>>> }
impl CancelToken {
    pub fn new() -> Arc<Self> { Arc::new(Self::default()) }
    pub fn is_cancelled(&self) -> bool { self.flag.load(Ordering::SeqCst) }
    /// Register a stream so that `cancel` closes it. If the token was cancelled already the stream is closed at once.
    pub fn register(&self, s: &dyn Stream) {
        if let Some(k) = s.killer() {
            if self.is_cancelled() { k(); return; }
            self.killers.lock().unwrap().push(k);
            if self.is_cancelled() { self.cancel(); }
        }
    }
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
        for k in self.killers.lock().unwrap().drain(..) { k(); }
    }
}

impl Dialer {
    /// Dial a pairing service by its onion id (the joiner side). The raw SOCKS connection is registered with `cancel` BEFORE the
    /// handshake, so cancel/panic interrupt even a stuck connect. The error is the SOCKS error so that the caller can tell
    /// "descriptor not found" (retryable for a while) from "unreachable" and "refused".
    pub fn dial_pairing(&self, id: &str, isolation: &[u8; 16], cancel: &CancelToken) -> Result<Box<dyn Stream>, socks::SocksError> {
        if cancel.is_cancelled() { return Err(socks::SocksError::Io("cancelled".into())); }
        let mut s = open(&self.socks, Duration::from_secs(10)).map_err(|e| socks::SocksError::Io(e.to_string()))?;
        cancel.register(&*s);
        s.set_timeout(Some(Duration::from_secs(90))).map_err(|e| socks::SocksError::Io(e.to_string()))?;
        let pass: String = isolation.iter().map(|b| format!("{b:02x}")).collect();
        socks::connect(&mut s, &format!("{id}.onion"), VIRT_PORT, Some((self.user.as_bytes(), pass.as_bytes())))?;
        if cancel.is_cancelled() { return Err(socks::SocksError::Io("cancelled".into())); }
        Ok(s)
    }
}

/// The hosted pairing service. It owns ITS OWN authenticated control connection: dropping it closes that connection, and tor then
/// removes the (non-detached) service: on cancel, on panic, on a crash or a kill, and even if the main control connection is broken.
pub struct PairService { ctl: Controller<Box<dyn Stream>>, pub id: String }

pub type PairHostFactory = Arc<dyn Fn(&Target) -> Result<PairService, TorError> + Send + Sync>;

impl PairService {
    /// Block until tor reports our descriptor uploaded to at least two HSDirs (`HS_DESC UPLOADED`). If tor sends no `HS_DESC` event
    /// for our id at all (events filtered) the fixed `fallback` wait is used. `Ok(true)` = ready; `Ok(false)` = cancelled;
    /// `Err` = not published within `max` or the control connection failed.
    pub fn wait_published(&mut self, max: Duration, fallback: Duration, cancel: &CancelToken) -> Result<bool, TorError> {
        self.ctl.set_poll_timeout(Duration::from_millis(500)).map_err(TorError::from)?;
        let (start, mut dirs, mut saw_event) = (std::time::Instant::now(), std::collections::HashSet::new(), false);
        loop {
            if cancel.is_cancelled() { return Ok(false); }
            if let Some(lines) = self.ctl.poll_event()? {
                for l in &lines {
                    let t: Vec<&str> = l.split_whitespace().collect();
                    if t.len() >= 5 && t[0] == "HS_DESC" && t[2] == self.id {
                        saw_event = true;
                        if t[1] == "UPLOADED" { dirs.insert(t[4].to_string()); }
                    }
                }
                if dirs.len() >= 2 { return Ok(true); }
            }
            let el = start.elapsed();
            if !saw_event && el >= fallback { return Ok(true); }
            if el >= max { return Err(TorError::Other("tor did not publish the pairing service in time".into())); }
        }
    }
}

impl Drop for PairService {
    fn drop(&mut self) { let _ = self.ctl.del_onion(&self.id); } // dropping the control connection removes it anyway
}

impl Tor {
    /// A factory (clone it into the engine and worker threads) that hosts a pairing service on a FRESH control connection.
    /// `None` when this Tor handle cannot open a second control connection.
    pub fn pair_host_factory(&self) -> Option<PairHostFactory> {
        let reconnect = self.reconnect.clone()?;
        Some(Arc::new(move |target: &Target| {
            let mut ctl = reconnect()?;
            ctl.set_events(&["HS_DESC"])?; // before ADD_ONION: no upload event may be missed
            let id = ctl.add_public_ephemeral_onion(VIRT_PORT, target)?;
            Ok(PairService { ctl, id })
        }))
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
    use std::{io::{Read, Write}, os::unix::net::{UnixListener, UnixStream}, thread};

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
            .with_reconnect(std::sync::Arc::new(move || Ok(Controller::new(Box::new(fresh.lock().unwrap().take().ok_or(TorError::Io("once".into()))?) as Box<dyn Stream>))));
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
            assert!(u.iter().all(u8::is_ascii_hexdigit) && !u.starts_with(b"nerd-chat"), "neutral random username");
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
        let tor = Tor::from_parts(Controller::new(Box::new(ctl_a)), Addr::Unix(sock), None);
        let peer = Bundle::from_identity(&ContactIdentity::generate());
        let mut s = tor.dialer().dial(&peer, &[0xab; 16]).unwrap();
        let mut b = [0u8; 5]; s.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"hello", "SOCKS reply fully consumed; stream positioned at app data");
        h.join().unwrap();
    }

    // ---------------------------------------------------------------- pairing service (spec 2026-11-09-tor-pairing-spec.md)
    fn valid_id() -> String { service_id(&ContactIdentity::generate().onion_public()) }

    #[test]
    fn the_public_pairing_service_command_has_exactly_the_specified_shape() {
        let id = valid_id();
        let (mut c, h) = control::tests::fake(vec![("ADD_ONION ", format!("250-ServiceID={id}\r\n250 OK\r\n"))]);
        let got = c.add_public_ephemeral_onion(VIRT_PORT, &Target::Unix("/run/user/1000/x/pair.sock".into())).unwrap();
        assert_eq!(got, id);
        let seen = h.join().unwrap();
        assert_eq!(seen, vec!["ADD_ONION NEW:ED25519-V3 Flags=DiscardPK,MaxStreamsCloseCircuit MaxStreams=1 PoWDefensesEnabled=1 Port=7345,unix:/run/user/1000/x/pair.sock"]);
        for bad in ["Detach", "ClientAuth", "NonAnonymous", "V3Auth"] { assert!(!seen[0].contains(bad), "{bad}"); }
    }

    #[test]
    fn a_filtered_tor_is_not_retried_but_an_old_tor_gets_the_plain_form() {
        // 510 = filtered / unknown command: the answer is final (no second attempt, nothing else is tried)
        let (mut c, h) = control::tests::fake(vec![("ADD_ONION ", "510 Command filtered\r\n".into())]);
        assert!(matches!(c.add_public_ephemeral_onion(VIRT_PORT, &Target::Tcp("127.0.0.1:9".parse().unwrap())), Err(TorError::Rejected { code: 510, .. })));
        h.join().unwrap();
        // 512 on the PoW option: retried once without it
        let id = valid_id();
        let (mut c, h) = control::tests::fake(vec![("ADD_ONION ", "512 Unknown option\r\n".into()), ("ADD_ONION ", format!("250-ServiceID={id}\r\n250 OK\r\n"))]);
        assert_eq!(c.add_public_ephemeral_onion(VIRT_PORT, &Target::Tcp("127.0.0.1:9".parse().unwrap())).unwrap(), id);
        let seen = h.join().unwrap();
        assert!(seen[0].contains("PoWDefensesEnabled=1") && !seen[1].contains("PoWDefensesEnabled"), "{seen:?}");
    }

    #[test]
    fn a_bad_service_id_from_tor_is_refused() {
        let (mut c, h) = control::tests::fake(vec![("ADD_ONION ", "250-ServiceID=notvalid\r\n250 OK\r\n".into())]);
        assert!(c.add_public_ephemeral_onion(VIRT_PORT, &Target::Tcp("127.0.0.1:9".parse().unwrap())).is_err());
        h.join().unwrap();
    }

    fn event_ctl() -> (Controller<Box<dyn Stream>>, UnixStream) {
        let (a, b) = UnixStream::pair().unwrap();
        let mut c = Controller::new(Box::new(a) as Box<dyn Stream>);
        c.set_poll_timeout(Duration::from_millis(60)).unwrap();
        (c, b)
    }

    #[test]
    fn poll_event_times_out_without_poisoning_and_returns_events() {
        let (mut c, mut peer) = event_ctl();
        assert_eq!(c.poll_event().unwrap(), None);
        assert!(!c.is_broken(), "a timeout with nothing buffered must not poison the connection");
        peer.write_all(b"650 HS_DESC UPLOADED abc UNKNOWN dir1 d1\r\n").unwrap();
        assert_eq!(c.poll_event().unwrap().unwrap(), vec!["HS_DESC UPLOADED abc UNKNOWN dir1 d1"]);
        peer.write_all(b"250 OK\r\n").unwrap(); // a command reply where an event is expected: protocol error
        assert!(c.poll_event().is_err() && c.is_broken());
    }

    fn event_line(id: &str, what: &str, dir: &str) -> Vec<u8> { format!("650 HS_DESC {what} {id} UNKNOWN {dir} desc\r\n").into_bytes() }

    #[test]
    fn wait_published_needs_two_distinct_uploads_and_ignores_other_services() {
        let (ctl, mut peer) = event_ctl();
        let id = valid_id();
        let mut svc = PairService { ctl, id: id.clone() };
        peer.write_all(&event_line(&valid_id(), "UPLOADED", "dirX")).unwrap(); // somebody else's service
        peer.write_all(&event_line(&id, "UPLOAD", "dir1")).unwrap();             // started, not finished
        peer.write_all(&event_line(&id, "UPLOADED", "dir1")).unwrap();
        peer.write_all(&event_line(&id, "UPLOADED", "dir1")).unwrap();           // the same dir twice is still one
        let tok = CancelToken::new();
        let t = std::time::Instant::now();
        let r = std::thread::scope(|sc| {
            let h = sc.spawn(|| svc.wait_published(Duration::from_secs(5), Duration::from_secs(60), &tok));
            std::thread::sleep(Duration::from_millis(250));
            peer.write_all(&event_line(&id, "UPLOADED", "dir2")).unwrap();
            h.join().unwrap()
        });
        assert!(r.unwrap(), "two distinct HSDirs");
        assert!(t.elapsed() >= Duration::from_millis(200), "must not report ready after one directory");
    }

    #[test]
    fn wait_published_falls_back_cancels_and_times_out() {
        let tok = CancelToken::new();
        // no HS_DESC events at all (filtered): the fixed wait
        let (ctl, _peer) = event_ctl();
        let mut svc = PairService { ctl, id: valid_id() };
        assert!(svc.wait_published(Duration::from_secs(5), Duration::from_millis(150), &tok).unwrap());
        // events for our id are arriving (so no fallback) but never two directories: the maximum applies
        let (ctl, mut peer) = event_ctl();
        let id = valid_id();
        let mut svc = PairService { ctl, id: id.clone() };
        peer.write_all(&event_line(&id, "UPLOADED", "dir1")).unwrap();
        assert!(svc.wait_published(Duration::from_millis(300), Duration::from_millis(100), &tok).is_err());
        // cancel
        let (ctl, _peer) = event_ctl();
        let mut svc = PairService { ctl, id: valid_id() };
        let tok2 = CancelToken::new();
        tok2.cancel();
        assert_eq!(svc.wait_published(Duration::from_secs(5), Duration::from_secs(5), &tok2).unwrap(), false);
    }

    #[test]
    fn the_pairing_link_parser_is_strict_but_forgiving_about_paste_noise() {
        let id = valid_id();
        for ok in [id.clone(), format!("{id}.onion"), format!("nerdchat:pair/{id}"), format!("  {}\n", id.to_uppercase()), format!("NERDCHAT:PAIR/{}.ONION", id.to_uppercase())] {
            assert_eq!(parse_pairing_link(&ok).unwrap(), id, "{ok:?}");
        }
        let mut bad_sum = id.clone(); bad_sum.replace_range(10..11, if &id[10..11] == "a" { "b" } else { "a" });
        for bad in ["", "abc", &format!("{id}x"), &format!("x{id}"), &format!("{id}.onionx"), &bad_sum, &id[..55], "https://example.com", &format!("{id} {id}"), &format!("\u{200b}{id}")] {
            assert!(parse_pairing_link(bad).is_err(), "{bad:?}");
        }
        // a v2-length address is not accepted
        assert!(parse_pairing_link("abcdefghijklmnop.onion").is_err());
    }

    #[test]
    fn cancel_wakes_a_blocked_reader_and_closes_late_registrations() {
        let (a, b) = UnixStream::pair().unwrap();
        let tok = CancelToken::new();
        tok.register(&a);
        let mut a2 = a;
        let h = std::thread::spawn(move || { let mut buf = [0u8; 4]; std::io::Read::read(&mut a2, &mut buf) });
        std::thread::sleep(Duration::from_millis(100));
        tok.cancel();
        assert!(matches!(h.join().unwrap(), Ok(0) | Err(_)), "the blocked read must end");
        let (c, mut d) = UnixStream::pair().unwrap();
        tok.register(&c); // registered after the cancel: closed at once
        assert_eq!(std::io::Read::read(&mut d, &mut [0u8; 1]).unwrap(), 0);
        drop(b);
    }
}
