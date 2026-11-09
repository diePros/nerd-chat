//! SPAWN mode: run our own `tor` in a private RAM directory (works on any machine that has a tor binary).
//! Control and SOCKS are UNIX sockets inside a 0700 directory, so other local users cannot reach them.
//! Tor exits by itself if we die (`__OwningControllerProcess`), and the directory is removed on drop.
use super::{Addr, TorError};
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub struct SpawnConfig {
    pub tor_path: PathBuf,
    /// Where to create the private directory. Default: `$XDG_RUNTIME_DIR`, else `/dev/shm` (both RAM).
    pub runtime_base: Option<PathBuf>,
    /// Allow a non-RAM base (the temp dir on disk). Off by default: tor's state would touch the disk.
    pub allow_disk: bool,
    /// Extra torrc lines, e.g. `UseBridges 1` / `Bridge obfs4 ...`. Single-line, validated.
    pub extra_torrc: Vec<String>,
    /// The generation (see [`generation`]) read by the CALLER when it decided to start: a kill that happened between that decision and the spawn is then noticed. `None`: read it at the start.
    pub generation: Option<u64>,
}

impl SpawnConfig {
    pub fn new(tor_path: PathBuf) -> Self { Self { tor_path, runtime_base: None, allow_disk: false, extra_torrc: vec![], generation: None } }
}

/// First executable `tor` in PATH. Relative/empty PATH entries ('.', '') are ignored (no `./tor` hijack).
pub fn find_tor() -> Option<PathBuf> { find_tor_in(&std::env::var_os("PATH")?) }

pub fn find_tor_in(path_var: &std::ffi::OsStr) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    std::env::split_paths(path_var)
        .filter(|d| d.is_absolute())
        .map(|d| d.join("tor"))
        .find(|c| fs::metadata(c).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0))
}

const TMPFS_MAGIC: i64 = 0x0102_1994;
const RAMFS_MAGIC: i64 = 0x8584_58f6;

/// Is `dir` on RAM-backed storage (tmpfs/ramfs)? tor's consensus cache and state must not touch a disk.
fn is_ram_backed(dir: &Path) -> bool {
    // `f_type` is i64 on Linux but u64 on Android (bionic): compare as i64 on both
    #[allow(clippy::unnecessary_cast)]
    rustix::fs::statfs(dir).is_ok_and(|st| { let t = st.f_type as i64; t == TMPFS_MAGIC || t == RAMFS_MAGIC })
}

/// Unix socket paths are limited to ~108 bytes; fail early with a clear message instead of a generic tor exit.
const MAX_SOCKET_PATH: usize = 100;

fn safe_path(p: &Path) -> bool {
    p.is_absolute() && p.to_str().is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_graphic() && !matches!(b, b'"' | b'\\' | b'#' | b'%')))
}

/// torrc for a private directory `dir`. Fails closed on any path/extra line that could alter the config.
pub fn torrc(dir: &Path, owning_pid: u32, extra: &[String]) -> Result<String, TorError> {
    if !safe_path(dir) { return Err(TorError::Other("runtime directory path contains characters unsafe for torrc".into())); }
    for l in extra {
        if l.is_empty() || l.bytes().any(|b| b < 0x20 || b == 0x7f) { return Err(TorError::Other("illegal character in extra torrc line".into())); }
    }
    let d = dir.display();
    let mut t = format!(
        "DataDirectory {d}/data\nControlPort unix:{d}/ctl\nCookieAuthentication 1\nCookieAuthFile {d}/cookie\n\
         SocksPort unix:{d}/socks ExtendedErrors OnionTrafficOnly\nClientOnly 1\nAvoidDiskWrites 1\nSafeLogging 1\nLog err stderr\n__OwningControllerProcess {owning_pid}\n"
    );
    for l in extra { t.push_str(l); t.push('\n'); }
    Ok(t)
}

/// Every tor this process started that is still meant to run: (pid, runtime directory). Lets a panic kill tor and remove its directory SYNCHRONOUSLY, without waiting for a Drop that
/// may never come (the process is about to be killed, or the owner is a start thread that is still waiting), and lets the app notice a tor that died on its own.
static LIVE: std::sync::Mutex<Vec<(u32, PathBuf)>> = std::sync::Mutex::new(Vec::new());

/// SIGKILL every tor we spawned and delete its directory (state with guard fingerprints, consensus times, cookie), right now. For panic and purge.
/// Bumped by every kill: a start that began before it and spawns tor AFTER it (a panic or a cancel that raced the start) sees the change and kills its own tor at once.
static GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The current kill generation: read it BEFORE starting a thread that will start tor, and pass it in [`SpawnConfig::generation`].
pub fn generation() -> u64 { GENERATION.load(std::sync::atomic::Ordering::SeqCst) }

pub fn kill_spawned() {
    let v = {
        let mut live = LIVE.lock().unwrap_or_else(|e| e.into_inner());
        GENERATION.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::mem::take(&mut *live)
    };
    for (pid, dir) in v {
        if let Some(p) = rustix::process::Pid::from_raw(pid as i32) { let _ = rustix::process::kill_process(p, rustix::process::Signal::KILL); }
        let _ = fs::remove_dir_all(&dir);
    }
}

/// The tors we spawned and still expect to run: (pid, runtime directory).
pub fn live_tors() -> Vec<(u32, PathBuf)> { LIVE.lock().unwrap_or_else(|e| e.into_inner()).clone() }

/// Tell ONE tor of ours (its runtime directory) whether its network may be used (`SETCONF DisableNetwork=0|1`) over a FRESH control connection (the engine owns its own, and tor accepts
/// several). Every step has a short timeout, so a busy tor costs a second or two, not a hang. The caller keeps what it has confirmed per tor and retries until this succeeds: a "network is
/// back" that never arrived would leave tor silent while the app believes it is reachable.
/// With the network disabled tor closes its SOCKS listener and every outgoing connection, publishes and fetches nothing, and does not mark its guards unreachable and move on to more of them.
pub fn set_network_for(dir: &Path, enabled: bool, timeout: Duration) -> Result<(), TorError> {
    let (stream, _) = super::open_control(&Addr::Unix(dir.join("ctl")), timeout)?;
    let mut c = super::control::Controller::new(stream);
    // the endpoint is the unix socket inside OUR 0700 directory of OUR tor: verified by construction (spawn mode); the SAFECOOKIE server proof is still enforced
    c.authenticate(&super::control::AuthPref { password: None, cookie_path: Some(dir.join("cookie")), peer_verified: true })?;
    c.command(if enabled { "SETCONF DisableNetwork=0" } else { "SETCONF DisableNetwork=1" })?;
    Ok(())
}

/// (running, dead): how many of the tors we spawned are alive. A zombie counts as dead. `/proc/<pid>/stat` is readable for our own children, also on Android.
pub fn spawned_status() -> (usize, usize) {
    let v = LIVE.lock().unwrap_or_else(|e| e.into_inner());
    let alive = v.iter().filter(|(pid, _)| {
        fs::read_to_string(format!("/proc/{pid}/stat")).ok().and_then(|s| s.rsplit_once(')').map(|(_, rest)| rest.trim_start().chars().next())).flatten().is_some_and(|st| st != 'Z' && st != 'X')
    }).count();
    (alive, v.len() - alive)
}

/// Delete EVERY `ramtor-*` directory in `base`, whether or not its owner still runs. Only for an app that knows no tor of its own can be running yet (the Android bridge at its start)
/// or no longer (purge). Directories not owned by us, and anything not named like ours, are left alone.
pub fn remove_runtime_dirs(base: &Path) {
    use std::os::unix::fs::MetadataExt;
    let me = rustix::process::geteuid().as_raw();
    let Ok(rd) = fs::read_dir(base) else { return };
    for e in rd.flatten() {
        if !e.file_name().to_str().is_some_and(|n| n.starts_with("ramtor-")) { continue; }
        let Ok(md) = fs::symlink_metadata(e.path()) else { continue };
        if md.is_dir() && md.uid() == me { let _ = fs::remove_dir_all(e.path()); }
    }
}

pub struct SpawnedTor {
    child: Child,
    dir: PathBuf,
    pub control: Addr,
    pub socks: Addr,
}

/// Remove leftover `ramtor-*` (and pre-rename `seburity-*`) directories of OUR user whose owning process is gone (e.g. after SIGKILL/abort,
/// where Drop never ran). Only a directory with OUR `owner.pid` marker qualifies: a foreign tool's `ramtor-*` directory is never touched.
fn sweep_stale(base: &Path) {
    use std::os::unix::fs::MetadataExt;
    let me = rustix::process::geteuid().as_raw();
    let Ok(rd) = fs::read_dir(base) else { return };
    for e in rd.flatten() {
        let name = e.file_name();
        if !name.to_str().is_some_and(|n| n.starts_with("ramtor-") || n.starts_with("seburity-")) { continue; }
        let Ok(md) = fs::symlink_metadata(e.path()) else { continue };
        if !md.is_dir() || md.uid() != me { continue; }
        let Some(pid) = fs::read_to_string(e.path().join("owner.pid")).ok().and_then(|t| t.trim().parse::<u32>().ok()) else { continue };
        if !Path::new(&format!("/proc/{pid}")).exists() { let _ = fs::remove_dir_all(e.path()); }
    }
}

fn private_dir(cfg: &SpawnConfig) -> Result<PathBuf, TorError> {
    let ram_dir = |p: PathBuf| (p.is_dir() && is_ram_backed(&p)).then_some(p);
    let base = cfg.runtime_base.clone().filter(|p| cfg.allow_disk || is_ram_backed(p))
        .or_else(|| if cfg.runtime_base.is_none() { std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).and_then(ram_dir) } else { None })
        .or_else(|| if cfg.runtime_base.is_none() { ram_dir(PathBuf::from("/dev/shm")) } else { None })
        .or_else(|| cfg.allow_disk.then(std::env::temp_dir))
        .ok_or_else(|| TorError::Other("no RAM-backed (tmpfs) runtime directory (XDG_RUNTIME_DIR, /dev/shm); refusing to put tor's state on disk without --allow-disk".into()))?;
    sweep_stale(&base);
    let mut r = [0u8; 8];
    getrandom::fill(&mut r).map_err(|_| TorError::Other("no OS randomness".into()))?;
    let dir = base.join(format!("ramtor-{}", r.iter().map(|b| format!("{b:02x}")).collect::<String>()));
    if dir.join("socks").to_str().is_none_or(|p| p.len() > MAX_SOCKET_PATH) {
        return Err(TorError::Other(format!("runtime directory path is too long for unix sockets (max {MAX_SOCKET_PATH} bytes): {}", dir.display())));
    }
    fs::DirBuilder::new().mode(0o700).create(&dir)?; // fails if it already exists: never reuse someone else's directory
    fs::write(dir.join("owner.pid"), std::process::id().to_string())?;
    Ok(dir)
}

impl SpawnedTor {
    pub fn start(cfg: &SpawnConfig) -> Result<Self, TorError> {
        let generation = cfg.generation.unwrap_or_else(generation);
        if self::generation() != generation { return Err(TorError::Other("cancelled".into())); } // cancelled before anything was created
        let dir = private_dir(cfg)?;
        let result = (|| {
            let rc = torrc(&dir, std::process::id(), &cfg.extra_torrc)?;
            fs::write(dir.join("torrc"), rc)?;
            fs::DirBuilder::new().mode(0o700).create(dir.join("data"))?;
            fs::write(dir.join("torrc-defaults"), "")?; // never read /etc/tor/torrc-defaults
            // clean environment: tor needs nothing from ours (no proxy variables, no secrets)
            let child = Command::new(&cfg.tor_path).arg("-f").arg(dir.join("torrc")).arg("--defaults-torrc").arg(dir.join("torrc-defaults"))
                .env_clear()
                .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()
                .map_err(|e| TorError::Other(format!("cannot start {}: {e}", cfg.tor_path.display())))?;
            Ok(child)
        })();
        let child = match result { Ok(c) => c, Err(e) => { let _ = fs::remove_dir_all(&dir); return Err(e); } };
        {
            let mut live = LIVE.lock().unwrap_or_else(|e| e.into_inner());
            if GENERATION.load(std::sync::atomic::Ordering::SeqCst) != generation {
                // a panic or a cancel happened while this start was under way: this tor must not live
                let mut child = child; let _ = child.kill(); let _ = child.wait(); let _ = fs::remove_dir_all(&dir);
                return Err(TorError::Other("cancelled".into()));
            }
            live.push((child.id(), dir.clone()));
        }
        let mut me = Self { control: Addr::Unix(dir.join("ctl")), socks: Addr::Unix(dir.join("socks")), child, dir };
        // wait for the control socket to appear (tor exits early on a bad config)
        let end = Instant::now() + Duration::from_secs(30);
        loop {
            if let Ok(Some(st)) = me.child.try_wait() { return Err(TorError::Other(format!("tor exited during startup ({st}); check the tor binary / bridge lines"))); }
            if me.dir.join("ctl").exists() && me.dir.join("cookie").exists() { return Ok(me); }
            if Instant::now() > end { return Err(TorError::Other("tor did not create its control socket in 30 s".into())); }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    pub fn cookie_path(&self) -> PathBuf { self.dir.join("cookie") }
    pub fn dir(&self) -> &Path { &self.dir }
}

impl Drop for SpawnedTor {
    fn drop(&mut self) {
        let pid = self.child.id();
        LIVE.lock().unwrap_or_else(|e| e.into_inner()).retain(|(p, _)| *p != pid);
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// the registry of live tors is process-wide: the tests that use it run one at a time
    static REGISTRY_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A fake tor control port for ONE connection: SAFECOOKIE server side (`lie`: a wrong server proof). Returns the lines it received. It gives up after 3 s, so a client that never
    /// connects fails the test instead of hanging it.
    fn fake_control(dir: &Path, lie: bool) -> std::thread::JoinHandle<Vec<String>> {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixListener;
        fs::write(dir.join("cookie"), [7u8; 32]).unwrap();
        let l = UnixListener::bind(dir.join("ctl")).unwrap();
        l.set_nonblocking(true).unwrap();
        let cookie_path = dir.join("cookie");
        std::thread::spawn(move || {
            use hmac::{Hmac, KeyInit, Mac};
            let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
            let end = Instant::now() + Duration::from_secs(3);
            let s = loop {
                match l.accept() { Ok((s, _)) => break s, Err(_) if Instant::now() < end => std::thread::sleep(Duration::from_millis(10)), Err(_) => return vec!["NO CONNECTION".to_string()] }
            };
            s.set_nonblocking(false).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut w = s.try_clone().unwrap();
            let mut r = BufReader::new(s);
            let mut seen = Vec::new();
            loop {
                let mut line = String::new();
                if r.read_line(&mut line).unwrap_or(0) == 0 { break; }
                let line = line.trim().to_string();
                if line.starts_with("PROTOCOLINFO") {
                    w.write_all(format!("250-PROTOCOLINFO 1\r\n250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE=\"{}\"\r\n250-VERSION Tor=\"0.4.9.16\"\r\n250 OK\r\n", cookie_path.display()).as_bytes()).unwrap();
                } else if let Some(cn_hex) = line.strip_prefix("AUTHCHALLENGE SAFECOOKIE ") {
                    let cn: Vec<u8> = (0..cn_hex.len() / 2).map(|i| u8::from_str_radix(&cn_hex[2 * i..2 * i + 2], 16).unwrap()).collect();
                    let (cookie, sn) = (if lie { [8u8; 32] } else { [7u8; 32] }, [9u8; 32]);
                    let mut m = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(b"Tor safe cookie authentication server-to-controller hash").unwrap();
                    m.update(&cookie); m.update(&cn); m.update(&sn);
                    w.write_all(format!("250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n", hex(&m.finalize().into_bytes()), hex(&sn)).as_bytes()).unwrap();
                } else { w.write_all(b"250 OK\r\n").unwrap(); }
                seen.push(line);
                if seen.last().is_some_and(|l| l.starts_with("SETCONF")) { break; }
            }
            seen
        })
    }

    #[test]
    fn set_network_for_sends_setconf_disablenetwork_after_an_authenticated_handshake() {
        for (enabled, want) in [(false, "SETCONF DisableNetwork=1"), (true, "SETCONF DisableNetwork=0")] {
            let base = tempfile::tempdir().unwrap();
            let server = fake_control(base.path(), false);
            set_network_for(base.path(), enabled, Duration::from_secs(2)).unwrap();
            let seen = server.join().unwrap();
            assert!(seen.iter().any(|l| l == want), "{seen:?}");
            let auth = seen.iter().position(|l| l.starts_with("AUTHENTICATE ")).expect("authenticated first");
            assert!(auth < seen.iter().position(|l| l == want).unwrap(), "SETCONF only AFTER the handshake: {seen:?}");
        }
    }

    #[test]
    fn a_control_port_that_fails_the_safecookie_proof_gets_no_setconf_and_no_cookie_answer() {
        let base = tempfile::tempdir().unwrap();
        let server = fake_control(base.path(), true);
        assert!(set_network_for(base.path(), false, Duration::from_secs(2)).is_err());
        let seen = server.join().unwrap();
        assert!(!seen.iter().any(|l| l.starts_with("SETCONF") || l.starts_with("AUTHENTICATE ")), "nothing is sent to a peer that cannot prove it knows the cookie: {seen:?}");
    }

    #[test]
    fn a_missing_or_silent_control_socket_is_an_error_not_a_hang() {
        let base = tempfile::tempdir().unwrap();
        let t = Instant::now();
        assert!(set_network_for(&base.path().join("gone"), false, Duration::from_secs(1)).is_err());
        assert!(t.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn a_kill_that_happens_before_the_start_reaches_the_spawn_is_noticed() {
        let _g = REGISTRY_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let base = tempfile::tempdir().unwrap();
        let before = generation();          // the caller decides to start ...
        kill_spawned();                     // ... a cancel or panic comes in before the start thread gets to spawn ...
        let cfg = SpawnConfig { runtime_base: Some(base.path().into()), allow_disk: true, generation: Some(before), ..SpawnConfig::new("sleep".into()) };
        let r = SpawnedTor::start(&cfg);    // ... so this start must refuse (and leave nothing behind), whatever tor it would have spawned
        assert!(r.is_err());
        assert_eq!(fs::read_dir(base.path()).unwrap().count(), 0, "no directory left");
        assert_eq!(spawned_status(), (0, 0));
    }

    #[test]
    fn kill_spawned_kills_the_process_and_removes_its_directory_and_the_status_sees_it() {
        let _g = REGISTRY_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("ramtor-0123456789abcdef");
        fs::create_dir(&dir).unwrap(); fs::write(dir.join("state"), "Guard x").unwrap();
        let mut child = Command::new("sleep").arg("60").spawn().unwrap();
        LIVE.lock().unwrap().push((child.id(), dir.clone()));
        assert_eq!(spawned_status().0 >= 1, true, "the live child is counted");
        kill_spawned();
        assert!(!dir.exists(), "directory gone");
        let st = child.wait().unwrap();
        assert!(!st.success(), "killed by a signal, not a normal exit: {st}");
        assert!(LIVE.lock().unwrap().iter().all(|(p, _)| *p != child.id()));
    }

    #[test]
    fn a_tor_that_exited_by_itself_is_reported_dead_even_before_it_is_reaped() {
        let _g = REGISTRY_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let mut child = Command::new("true").spawn().unwrap();
        let pid = child.id();
        LIVE.lock().unwrap().push((pid, PathBuf::from("/nonexistent/x")));
        std::thread::sleep(Duration::from_millis(300)); // exited, not yet waited for: a zombie
        let (_, dead) = spawned_status();
        assert!(dead >= 1, "zombie counts as dead");
        LIVE.lock().unwrap().retain(|(p, _)| *p != pid);
        let _ = child.wait();
    }

    #[test]
    fn remove_runtime_dirs_removes_only_directories_named_like_ours() {
        let base = tempfile::tempdir().unwrap();
        for n in ["ramtor-aaaa", "ramtor-bbbb", "somebody-else", "ramtor-file"] { let p = base.path().join(n); if n == "ramtor-file" { fs::write(&p, "x").unwrap(); } else { fs::create_dir(&p).unwrap(); fs::write(p.join("owner.pid"), "1").unwrap(); } }
        remove_runtime_dirs(base.path());
        assert!(!base.path().join("ramtor-aaaa").exists() && !base.path().join("ramtor-bbbb").exists());
        assert!(base.path().join("somebody-else").exists(), "a foreign name is never touched");
        assert!(base.path().join("ramtor-file").exists(), "a plain file is not a directory of ours");
    }

    #[test]
    fn torrc_is_private_and_fail_closed() {
        let t = torrc(Path::new("/dev/shm/ramtor-ab12"), 4242, &["UseBridges 1".into()]).unwrap();
        assert!(t.contains("ControlPort unix:/dev/shm/ramtor-ab12/ctl"));
        assert!(t.contains("SocksPort unix:/dev/shm/ramtor-ab12/socks ExtendedErrors OnionTrafficOnly"), "tor's onion error codes + no clearnet dials");
        assert!(t.contains("__OwningControllerProcess 4242"));
        assert!(t.contains("AvoidDiskWrites 1") && t.contains("ClientOnly 1") && t.contains("CookieAuthentication 1"));
        assert!(!t.contains("ControlPort 9051") && !t.contains("SocksPort 9050"), "no TCP listeners");
        assert!(t.ends_with("UseBridges 1\n"));
        for bad in ["/dev/shm/a b", "/dev/shm/a\nSocksPort 0.0.0.0:1", "relative", "/dev/shm/a\"b", "/dev/shm/a#b"] {
            assert!(torrc(Path::new(bad), 1, &[]).is_err(), "{bad:?}");
        }
        assert!(torrc(Path::new("/dev/shm/x"), 1, &["Line\nSocksPort 0.0.0.0:9".into()]).is_err());
        assert!(torrc(Path::new("/dev/shm/x"), 1, &["".into()]).is_err());
    }

    #[test]
    fn private_dir_is_0700_unique_and_refuses_disk_by_default() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let cfg = SpawnConfig { runtime_base: Some(base.path().into()), allow_disk: true, ..SpawnConfig::new("tor".into()) };
        let (a, b) = (private_dir(&cfg).unwrap(), private_dir(&cfg).unwrap());
        assert_ne!(a, b);
        assert_eq!(fs::metadata(&a).unwrap().permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn start_with_missing_binary_fails_cleanly_and_leaves_nothing_behind() {
        let base = tempfile::tempdir().unwrap();
        let cfg = SpawnConfig { runtime_base: Some(base.path().into()), allow_disk: true, ..SpawnConfig::new("/nonexistent/tor".into()) };
        assert!(SpawnedTor::start(&cfg).is_err());
        assert_eq!(fs::read_dir(base.path()).unwrap().count(), 0, "directory cleaned up");
    }

    #[test]
    fn find_tor_ignores_relative_path_entries_and_non_executables() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let tor = d.path().join("tor");
        fs::write(&tor, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&tor, fs::Permissions::from_mode(0o644)).unwrap();
        let path = std::env::join_paths([d.path()]).unwrap();
        assert_eq!(find_tor_in(&path), None, "not executable");
        fs::set_permissions(&tor, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(find_tor_in(&path), Some(tor));
        let rel = std::ffi::OsString::from(".:relative/bin::");
        assert_eq!(find_tor_in(&rel), None, "relative and empty PATH entries are never searched");
    }

    #[test]
    fn long_runtime_paths_fail_early_with_a_clear_message_and_disk_is_refused_by_default() {
        let d = tempfile::tempdir().unwrap();
        let long = d.path().join("x".repeat(90));
        fs::create_dir(&long).unwrap();
        let cfg = SpawnConfig { runtime_base: Some(long), allow_disk: true, ..SpawnConfig::new("tor".into()) };
        let e = private_dir(&cfg).unwrap_err().to_string();
        assert!(e.contains("too long"), "{e}");
        // a non-tmpfs base without allow_disk is refused (only when this checkout's temp dir is really on disk)
        if !is_ram_backed(d.path()) {
            let cfg = SpawnConfig { runtime_base: Some(d.path().into()), allow_disk: false, ..SpawnConfig::new("tor".into()) };
            assert!(private_dir(&cfg).is_err());
        }
    }

    #[test]
    fn stale_directories_of_dead_owners_are_swept_but_live_ones_are_kept() {
        let d = tempfile::tempdir().unwrap();
        let dead = d.path().join("ramtor-dead");
        let live = d.path().join("ramtor-live");
        let other = d.path().join("unrelated");
        for p in [&dead, &live, &other] { fs::create_dir(p).unwrap(); }
        fs::write(dead.join("owner.pid"), "4294967290").unwrap(); // no such process
        fs::write(live.join("owner.pid"), std::process::id().to_string()).unwrap();
        sweep_stale(d.path());
        assert!(!dead.exists() && live.exists() && other.exists());
    }
}
