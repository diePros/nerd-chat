//! How streams reach a contact. The engine only sees `Transport`; Tor and the in-memory test network both implement it.
//! Role per contact (decided by the engine): the LISTENER hosts its onion service for that contact, the DIALER only dials.
//! Only listeners publish a service, so a user is not visible online for contacts that never need to dial them.
use seburity_core::{bundle::Bundle, identity::ContactIdentity};
use seburity_net::tor::{
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

pub trait Transport: Send {
    /// Register a contact. `listen = true`: host our service for it and return the receiver of accepted streams.
    fn add_contact(&mut self, me: &ContactIdentity, peer: &Bundle, listen: bool) -> Result<Option<Receiver<BoxStream>>, String>;
    /// Stop hosting the service whose onion public key is `my_onion_pub`.
    fn remove_contact(&mut self, my_onion_pub: &[u8; 32]);
    fn dial_fn(&self) -> DialFn;
}

// ---------------------------------------------------------------- in-memory network (tests, demos)
#[derive(Clone, Default)]
pub struct MemNet(Arc<Mutex<HashMap<[u8; 32], Sender<BoxStream>>>>);

impl MemNet {
    pub fn new() -> Self { Self::default() }
    pub fn transport(&self) -> MemTransport { MemTransport { net: self.clone(), hosted: vec![] } }
}

pub struct MemTransport { net: MemNet, hosted: Vec<[u8; 32]> }

impl Transport for MemTransport {
    fn add_contact(&mut self, me: &ContactIdentity, _peer: &Bundle, listen: bool) -> Result<Option<Receiver<BoxStream>>, String> {
        if !listen { return Ok(None); }
        let (tx, rx) = channel();
        let key = me.onion_public();
        self.net.0.lock().unwrap().insert(key, tx);
        self.hosted.push(key);
        Ok(Some(rx))
    }
    fn remove_contact(&mut self, k: &[u8; 32]) { self.net.0.lock().unwrap().remove(k); self.hosted.retain(|h| h != k); }
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
    services: HashMap<[u8; 32], (String, Arc<AtomicBool>)>, // onion pub -> (service id, stop flag of its acceptor)
}

impl TorTransport {
    /// Blocks until tor is usable (spawn mode waits for bootstrap, reporting progress 0..=100).
    pub fn start(setup: TorSetup, progress: impl FnMut(u8)) -> Result<Self, String> {
        let tor = match setup {
            TorSetup::Spawn(cfg) => Tor::spawn(&cfg, Duration::from_secs(300), progress).map_err(|e| e.to_string())?,
            TorSetup::External { control, auth, socks, trust_control } => Tor::connect_external(&control, &auth, socks, trust_control).map_err(|e| e.to_string())?,
        };
        let dialer = tor.dialer();
        let spawn_dir = tor.spawn_dir().map(|p| p.to_path_buf());
        Ok(Self { tor, dialer, spawn_dir, services: HashMap::new() })
    }
}

fn hex8(b: &[u8]) -> String { b.iter().take(8).map(|x| format!("{x:02x}")).collect() }

impl Transport for TorTransport {
    fn add_contact(&mut self, me: &ContactIdentity, peer: &Bundle, listen: bool) -> Result<Option<Receiver<BoxStream>>, String> {
        if !listen {
            self.tor.allow_dial(me, peer).map_err(|e| e.to_string())?;
            return Ok(None);
        }
        let (tx, rx) = channel::<BoxStream>();
        let stop = Arc::new(AtomicBool::new(false));
        // where tor forwards accepted connections: a unix socket in our private dir (spawn mode) or loopback TCP (external tor)
        let (target, acceptor): (Target, Box<dyn FnMut() -> Option<BoxStream> + Send>) = match &self.spawn_dir {
            Some(dir) => {
                let path = dir.join(format!("{}.sock", hex8(&me.onion_public())));
                let l = UnixListener::bind(&path).map_err(|e| e.to_string())?;
                l.set_nonblocking(true).map_err(|e| e.to_string())?;
                (Target::Unix(path), Box::new(move || l.accept().ok().map(|(s, _)| { let _ = s.set_nonblocking(false); Box::new(s) as BoxStream })))
            }
            None => {
                let l = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
                l.set_nonblocking(true).map_err(|e| e.to_string())?;
                let addr = l.local_addr().map_err(|e| e.to_string())?;
                (Target::Tcp(addr), Box::new(move || l.accept().ok().map(|(s, _)| { let _ = s.set_nonblocking(false); Box::new(s) as BoxStream })))
            }
        };
        let id = self.tor.host(me, peer, &target).map_err(|e| e.to_string())?;
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
        self.services.insert(me.onion_public(), (id, stop));
        Ok(Some(rx))
    }

    fn remove_contact(&mut self, k: &[u8; 32]) {
        if let Some((id, stop)) = self.services.remove(k) {
            stop.store(true, Ordering::SeqCst);
            self.tor.unhost(&id);
        }
    }

    fn dial_fn(&self) -> DialFn {
        let d = self.dialer.clone();
        Arc::new(move |peer: &Bundle, iso: &[u8; 16]| d.dial(peer, iso).map_err(|e| e.to_string()))
    }
}

impl Drop for TorTransport {
    fn drop(&mut self) { for (_, (_, stop)) in self.services.drain() { stop.store(true, Ordering::SeqCst); } }
}
