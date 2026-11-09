//! How streams reach a contact. The engine only sees `Transport`; Tor and the in-memory test network both implement it.
//! Role per contact (decided by the engine): the LISTENER hosts its onion service for that contact, the DIALER only dials.
//! Only listeners publish a service, so a user is not visible online for contacts that never need to dial them.
use nerd_chat_core::{bundle::Bundle, identity::ContactIdentity};
use nerd_chat_net::tor::{
    control::AuthPref,
    spawn::SpawnConfig,
    Addr, Dialer, Stream, Target, Tor,
};
use std::{
    collections::HashMap,
    net::TcpListener,
    os::unix::net::{UnixListener, UnixStream},
    sync::{atomic::{AtomicBool, Ordering}, mpsc::{channel, Receiver, Sender}, Arc, Mutex},
    thread,
    time::Duration,
};

pub type BoxStream = Box<dyn Stream>;
/// `dial(peer_bundle, isolation_token)`
pub type DialFn = Arc<dyn Fn(&Bundle, &[u8; 16]) -> Result<BoxStream, String> + Send + Sync>;

/// Why a pairing dial failed (the joiner treats them differently, see docs/superpowers/specs/2026-11-09-tor-pairing-spec.md).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairDialError {
    /// the service descriptor is not (yet) available: retryable for a short while
    NotFound,
    /// introduction/rendezvous failed or the service is gone
    Unreachable,
    /// the target refused (the offer is closed)
    Refused,
    Cancelled,
    Other(String),
}

/// A running one-shot pairing service. Dropping it removes the service and closes its listener.
pub struct PairHost {
    /// the 56-character onion id (the link)
    pub id: String,
    /// the ONE accepted (and, for loopback TCP, verified) connection
    pub incoming: Receiver<BoxStream>,
    wait: Box<dyn FnMut(&nerd_chat_net::tor::CancelToken) -> Result<bool, String> + Send>,
    _guard: Box<dyn Send>,
}
impl PairHost {
    pub fn new(id: String, incoming: Receiver<BoxStream>, wait: Box<dyn FnMut(&nerd_chat_net::tor::CancelToken) -> Result<bool, String> + Send>, guard: Box<dyn Send>) -> Self { Self { id, incoming, wait, _guard: guard } }
    /// Block until the service is reachable by others (tor reported the descriptor uploaded). `Ok(false)` = cancelled.
    pub fn wait_published(&mut self, cancel: &nerd_chat_net::tor::CancelToken) -> Result<bool, String> { (self.wait)(cancel) }
}
pub type PairHostFn = Arc<dyn Fn() -> Result<PairHost, String> + Send + Sync>;
/// `dial_pairing(onion id, isolation token, cancel)`
pub type PairDialFn = Arc<dyn Fn(&str, &[u8; 16], &nerd_chat_net::tor::CancelToken) -> Result<BoxStream, PairDialError> + Send + Sync>;

pub trait Transport: Send {
    /// Host a one-shot pairing service (None: this transport cannot). Cloned out at engine start, like `dial_fn`.
    fn pair_host_fn(&self) -> Option<PairHostFn> { None }
    /// Dial a pairing service by onion id (None: cannot).
    fn pair_dial_fn(&self) -> Option<PairDialFn> { None }
    /// Register a contact. `listen = true`: host our service for it and return the receiver of accepted streams. `extra_auth`: further
    /// client keys to authorize on the hosted service (the peer's previous key while its key rotation is unfinished).
    fn add_contact(&mut self, me: &ContactIdentity, peer: &Bundle, extra_auth: &[[u8; 32]], listen: bool) -> Result<Option<Receiver<BoxStream>>, String>;
    /// Stop hosting the service whose onion public key is `my_onion_pub` and forget any credentials we installed to dial
    /// the peer's service (`peer_onion_pub`). Nothing of a deleted contact may stay behind in a shared tor.
    fn remove_contact(&mut self, my_onion_pub: &[u8; 32], peer_onion_pub: &[u8; 32]);
    fn dial_fn(&self) -> DialFn;
}

// ---------------------------------------------------------------- in-memory network (tests, demos)
#[derive(Clone, Default)]
pub struct MemNet(Arc<Mutex<HashMap<[u8; 32], Sender<BoxStream>>>>, Arc<Mutex<HashMap<String, (Sender<BoxStream>, bool)>>>, Arc<Mutex<Duration>>);

impl MemNet {
    pub fn new() -> Self { Self::default() }
    pub fn transport(&self) -> MemTransport { MemTransport { net: self.clone(), hosted: vec![] } }
    /// Is a service registered under this onion key? (tests)
    pub fn is_hosted(&self, onion_pub: &[u8; 32]) -> bool { self.0.lock().unwrap().contains_key(onion_pub) }
    /// Is a pairing service registered under this id? (tests)
    pub fn pair_open(&self, id: &str) -> bool { self.1.lock().unwrap().contains_key(id) }
    /// How long a new pairing service stays unreachable (models the HSDir upload delay). Default: none.
    pub fn set_pair_publish_delay(&self, d: Duration) { *self.2.lock().unwrap() = d; }
}

pub struct MemTransport { net: MemNet, hosted: Vec<[u8; 32]> }

impl Transport for MemTransport {
    fn add_contact(&mut self, me: &ContactIdentity, _peer: &Bundle, _extra_auth: &[[u8; 32]], listen: bool) -> Result<Option<Receiver<BoxStream>>, String> {
        if !listen { return Ok(None); }
        let (tx, rx) = channel();
        let key = me.onion_public();
        self.net.0.lock().unwrap().insert(key, tx);
        self.hosted.push(key);
        Ok(Some(rx))
    }
    fn remove_contact(&mut self, k: &[u8; 32], _peer: &[u8; 32]) { self.net.0.lock().unwrap().remove(k); self.hosted.retain(|h| h != k); }
    fn pair_host_fn(&self) -> Option<PairHostFn> {
        let net = self.net.clone();
        Some(Arc::new(move || {
            let mut raw = [0u8; 32];
            getrandom::fill(&mut raw).map_err(|_| "no OS randomness".to_string())?;
            let id = nerd_chat_core::onion::service_id(&raw);
            let (tx, rx) = channel::<BoxStream>();
            net.1.lock().unwrap().insert(id.clone(), (tx, false));
            let (net2, id2, delay) = (net.clone(), id.clone(), *net.2.lock().unwrap());
            let started = std::time::Instant::now();
            let wait = Box::new(move |cancel: &nerd_chat_net::tor::CancelToken| -> Result<bool, String> {
                loop {
                    if cancel.is_cancelled() { return Ok(false); }
                    if started.elapsed() >= delay { if let Some(e) = net2.1.lock().unwrap().get_mut(&id2) { e.1 = true; } return Ok(true); }
                    thread::sleep(Duration::from_millis(5));
                }
            });
            struct Guard(MemNet, String);
            impl Drop for Guard { fn drop(&mut self) { self.0 .1.lock().unwrap().remove(&self.1); } }
            Ok(PairHost::new(id.clone(), rx, wait, Box::new(Guard(net.clone(), id))))
        }))
    }
    fn pair_dial_fn(&self) -> Option<PairDialFn> {
        let net = self.net.clone();
        Some(Arc::new(move |id: &str, _iso: &[u8; 16], cancel: &nerd_chat_net::tor::CancelToken| {
            if cancel.is_cancelled() { return Err(PairDialError::Cancelled); }
            let tx = match net.1.lock().unwrap().get(id) { Some((tx, true)) => tx.clone(), Some((_, false)) => return Err(PairDialError::NotFound), None => return Err(PairDialError::Unreachable) };
            let (a, b) = UnixStream::pair().map_err(|e| PairDialError::Other(e.to_string()))?;
            tx.send(Box::new(a)).map_err(|_| PairDialError::Unreachable)?;
            let b: BoxStream = Box::new(b);
            cancel.register(&*b);
            Ok(b)
        }))
    }
    fn dial_fn(&self) -> DialFn {
        let net = self.net.clone();
        Arc::new(move |peer: &Bundle, _iso: &[u8; 16]| {
            let tx = net.0.lock().unwrap().get(&peer.onion_pub).cloned().ok_or_else(|| "peer is offline".to_string())?;
            let (a, b) = UnixStream::pair().map_err(|e| e.to_string())?;
            tx.send(Box::new(a)).map_err(|_| "peer is offline".to_string())?;
            Ok(Box::new(b) as BoxStream)
        })
    }
}

impl Drop for MemTransport {
    fn drop(&mut self) { for k in std::mem::take(&mut self.hosted) { self.net.0.lock().unwrap().remove(&k); } }
}

// ---------------------------------------------------------------- Tor
pub enum TorSetup {
    /// Start our own tor in a private RAM directory.
    Spawn(SpawnConfig),
    /// Use a running tor. `trust_control`: the user vouches for the control port's owner.
    External { control: Addr, auth: AuthPref, socks: Option<Addr>, trust_control: bool },
}

pub struct TorTransport {
    tor: Tor,
    dialer: Dialer,
    spawn_dir: Option<std::path::PathBuf>,
    /// External tor: the user vouched for local processes (otherwise inbound loopback clients must be owned by us/root/tor).
    trust_local: bool,
    /// onion pub -> (service id, stop flag of its acceptor, unix socket file to unlink)
    services: HashMap<[u8; 32], (String, Arc<AtomicBool>, Option<std::path::PathBuf>)>,
}

impl TorTransport {
    /// Blocks until tor is usable (spawn mode waits for bootstrap, reporting progress 0..=100).
    pub fn start(setup: TorSetup, progress: impl FnMut(u8)) -> Result<Self, String> {
        let trust_local = matches!(&setup, TorSetup::External { trust_control: true, .. });
        let tor = match setup {
            TorSetup::Spawn(cfg) => Tor::spawn(&cfg, Duration::from_secs(300), progress).map_err(|e| e.to_string())?,
            TorSetup::External { control, auth, socks, trust_control } => Tor::connect_external(&control, &auth, socks, trust_control).map_err(|e| e.to_string())?,
        };
        let dialer = tor.dialer();
        let spawn_dir = tor.spawn_dir().map(|p| p.to_path_buf());
        Ok(Self { tor, dialer, spawn_dir, trust_local, services: HashMap::new() })
    }
}

fn hex8(b: &[u8]) -> String { b.iter().take(8).map(|x| format!("{x:02x}")).collect() }

impl Transport for TorTransport {
    fn add_contact(&mut self, me: &ContactIdentity, peer: &Bundle, extra_auth: &[[u8; 32]], listen: bool) -> Result<Option<Receiver<BoxStream>>, String> {
        if !listen {
            self.tor.allow_dial(me, peer).map_err(|e| e.to_string())?;
            return Ok(None);
        }
        let (tx, rx) = channel::<BoxStream>();
        let stop = Arc::new(AtomicBool::new(false));
        // where tor forwards accepted connections: a unix socket in our private dir (spawn mode) or loopback TCP (external tor)
        let mut sock_file = None;
        let trust_local = self.trust_local;
        let (target, acceptor): (Target, Box<dyn FnMut() -> Option<BoxStream> + Send>) = match &self.spawn_dir {
            Some(dir) => {
                let path = dir.join(format!("{}.sock", hex8(&me.onion_public())));
                let _ = std::fs::remove_file(&path); // a socket file left by an earlier add of the same contact
                let l = UnixListener::bind(&path).map_err(|e| e.to_string())?;
                sock_file = Some(path.clone());
                l.set_nonblocking(true).map_err(|e| e.to_string())?;
                (Target::Unix(path), Box::new(move || l.accept().ok().map(|(s, _)| { let _ = s.set_nonblocking(false); Box::new(s) as BoxStream })))
            }
            None => {
                let l = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
                l.set_nonblocking(true).map_err(|e| e.to_string())?;
                let addr = l.local_addr().map_err(|e| e.to_string())?;
                // ANY local user can connect to this port: only tor (its account), root or we may, unless the user vouched for all
                (Target::Tcp(addr), Box::new(move || l.accept().ok().and_then(|(s, from)| {
                    if !trust_local && !nerd_chat_net::tor::trust::check_tcp_client(&from).verified { return None; } // dropped unread
                    let _ = s.set_nonblocking(false);
                    Some(Box::new(s) as BoxStream)
                })))
            }
        };
        let id = match self.tor.host_with(me, peer, extra_auth, &target) {
            Ok(id) => id,
            Err(e) => { if let Some(p) = &sock_file { let _ = std::fs::remove_file(p); } return Err(e.to_string()); }
        };
        let stop2 = stop.clone();
        thread::spawn(move || {
            let mut accept = acceptor;
            while !stop2.load(Ordering::SeqCst) {
                match accept() {
                    Some(s) => { if tx.send(s).is_err() { break; } }
                    None => thread::sleep(Duration::from_millis(100)),
                }
            }
        });
        self.services.insert(me.onion_public(), (id, stop, sock_file));
        Ok(Some(rx))
    }

    fn remove_contact(&mut self, k: &[u8; 32], peer: &[u8; 32]) {
        if let Some((id, stop, sock)) = self.services.remove(k) {
            stop.store(true, Ordering::SeqCst);
            self.tor.unhost(&id);
            if let Some(p) = sock { let _ = std::fs::remove_file(p); }
        }
        self.tor.forget_dial(peer); // ONION_CLIENT_AUTH_REMOVE: our auth secret must not outlive the contact (R6-M3)
    }

    fn pair_dial_fn(&self) -> Option<PairDialFn> {
        use nerd_chat_net::tor::socks::SocksError as S;
        let d = self.dialer.clone();
        Some(Arc::new(move |id: &str, iso: &[u8; 16], cancel: &nerd_chat_net::tor::CancelToken| d.dial_pairing(id, iso, cancel).map_err(|e| match e {
            S::OnionNotFound => PairDialError::NotFound,
            S::OnionUnreachable => PairDialError::Unreachable,
            S::Refused => PairDialError::Refused,
            S::Io(m) if m == "cancelled" => PairDialError::Cancelled,
            e => PairDialError::Other(e.to_string()),
        })))
    }

    fn pair_host_fn(&self) -> Option<PairHostFn> {
        let factory = self.tor.pair_host_factory()?;
        let (spawn_dir, trust_local) = (self.spawn_dir.clone(), self.trust_local);
        Some(Arc::new(move || {
            // where tor forwards the ONE connection: a unix socket with a RANDOM name in our private dir (spawn mode) or loopback TCP
            // that only tor, root or we (or everybody, if the user vouched for the machine) may use. An unverified connection is
            // dropped unread and does NOT consume the offer.
            let (target, mut accept, sock_file): (Target, Box<dyn FnMut() -> Option<BoxStream> + Send>, Option<std::path::PathBuf>) = match &spawn_dir {
                Some(dir) => {
                    let mut r = [0u8; 8];
                    getrandom::fill(&mut r).map_err(|_| "no OS randomness".to_string())?;
                    let path = dir.join(format!("p{}.sock", r.iter().map(|b| format!("{b:02x}")).collect::<String>()));
                    let l = UnixListener::bind(&path).map_err(|e| e.to_string())?;
                    l.set_nonblocking(true).map_err(|e| e.to_string())?;
                    (Target::Unix(path.clone()), Box::new(move || l.accept().ok().map(|(s, _)| { let _ = s.set_nonblocking(false); Box::new(s) as BoxStream })), Some(path))
                }
                None => {
                    let l = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
                    l.set_nonblocking(true).map_err(|e| e.to_string())?;
                    let addr = l.local_addr().map_err(|e| e.to_string())?;
                    (Target::Tcp(addr), Box::new(move || l.accept().ok().and_then(|(s, from)| {
                        if !trust_local && !nerd_chat_net::tor::trust::check_tcp_client(&from).verified { return None; }
                        let _ = s.set_nonblocking(false);
                        Some(Box::new(s) as BoxStream)
                    })), None)
                }
            };
            let mut svc = match factory(&target) { Ok(s) => s, Err(e) => { if let Some(p) = &sock_file { let _ = std::fs::remove_file(p); } return Err(e.to_string()); } };
            let id = svc.id.clone();
            let (tx, rx) = channel::<BoxStream>();
            let stop = Arc::new(AtomicBool::new(false));
            let stop2 = stop.clone();
            thread::spawn(move || {
                while !stop2.load(Ordering::SeqCst) {
                    match accept() { Some(s) => { let _ = tx.send(s); break; } None => thread::sleep(Duration::from_millis(100)) } // ONE connection, then the listener closes
                }
            });
            struct Guard(Arc<AtomicBool>, Option<std::path::PathBuf>);
            impl Drop for Guard { fn drop(&mut self) { self.0.store(true, Ordering::SeqCst); if let Some(p) = &self.1 { let _ = std::fs::remove_file(p); } } }
            let wait = Box::new(move |cancel: &nerd_chat_net::tor::CancelToken| svc.wait_published(Duration::from_secs(180), Duration::from_secs(60), cancel).map_err(|e| e.to_string()));
            Ok(PairHost::new(id, rx, wait, Box::new(Guard(stop, sock_file))))
        }))
    }

    fn dial_fn(&self) -> DialFn {
        let d = self.dialer.clone();
        Arc::new(move |peer: &Bundle, iso: &[u8; 16]| d.dial(peer, iso).map_err(|e| e.to_string()))
    }
}

impl Drop for TorTransport {
    fn drop(&mut self) { for (_, (_, stop, sock)) in self.services.drain() { stop.store(true, Ordering::SeqCst); if let Some(p) = sock { let _ = std::fs::remove_file(p); } } }
}

#[cfg(test)]
mod pairing_tests {
    use super::*;
    use nerd_chat_net::tor::CancelToken;

    #[test]
    fn memory_pairing_service_models_publication_delay_one_shot_use_and_removal() {
        let net = MemNet::new();
        net.set_pair_publish_delay(Duration::from_millis(150));
        let t = net.transport();
        let (host_fn, dial) = (t.pair_host_fn().unwrap(), t.pair_dial_fn().unwrap());
        let tok = CancelToken::new();
        let mut host = host_fn().unwrap();
        assert!(net.pair_open(&host.id));
        // dialing before the service is published fails the way Tor does (descriptor not found)
        assert_eq!(dial(&host.id, &[1; 16], &tok).err(), Some(PairDialError::NotFound));
        assert!(host.wait_published(&tok).unwrap());
        let mut s = dial(&host.id, &[1; 16], &tok).unwrap();
        let mut got = host.incoming.recv_timeout(Duration::from_secs(1)).expect("the host receives the stream");
        use std::io::{Read, Write};
        s.write_all(b"hi").unwrap();
        let mut b = [0u8; 2];
        got.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"hi");
        // an unknown id is unreachable; dropping the host removes the service
        let id = host.id.clone();
        assert_eq!(dial("nosuchid", &[1; 16], &tok).err(), Some(PairDialError::Unreachable));
        drop(host);
        assert!(!net.pair_open(&id));
        assert_eq!(dial(&id, &[1; 16], &tok).err(), Some(PairDialError::Unreachable));
    }

    #[test]
    fn cancel_stops_waiting_dialing_and_closes_the_dialed_stream() {
        let net = MemNet::new();
        let t = net.transport();
        let (host_fn, dial) = (t.pair_host_fn().unwrap(), t.pair_dial_fn().unwrap());
        let mut host = host_fn().unwrap();
        let tok = CancelToken::new();
        assert!(host.wait_published(&tok).unwrap());
        let mut s = dial(&host.id, &[2; 16], &tok).unwrap();
        let tok2 = CancelToken::new();
        tok.cancel();
        assert_eq!(host.wait_published(&tok).unwrap(), false);
        assert_eq!(dial(&host.id, &[2; 16], &tok).err(), Some(PairDialError::Cancelled));
        // the stream registered with the cancelled token is closed: reads end
        use std::io::Read;
        let _ = tok2;
        assert_eq!(s.read(&mut [0u8; 1]).unwrap_or(0), 0);
    }

    #[test]
    fn the_engine_hands_out_the_pairing_functions_of_its_transport() {
        let net = MemNet::new();
        let e = crate::engine::Engine::start(Box::new(net.transport()), vec![], crate::engine::Timing::default());
        assert!(e.pair_host_fn().is_some() && e.pair_dial_fn().is_some());
    }
}
