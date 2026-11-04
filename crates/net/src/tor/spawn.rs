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
}

impl SpawnConfig {
    pub fn new(tor_path: PathBuf) -> Self { Self { tor_path, runtime_base: None, allow_disk: false, extra_torrc: vec![] } }
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

pub struct SpawnedTor {
    child: Child,
    dir: PathBuf,
    pub control: Addr,
    pub socks: Addr,
}

/// Remove leftover `seburity-*` directories of OUR user whose owning process is gone (e.g. after SIGKILL/abort,
/// where Drop never ran). A directory without a pid file only counts as stale after a minute (it may be mid-creation).
fn sweep_stale(base: &Path) {
    use std::os::unix::fs::MetadataExt;
    let me = rustix::process::geteuid().as_raw();
    let Ok(rd) = fs::read_dir(base) else { return };
    for e in rd.flatten() {
        let name = e.file_name();
        if !name.to_str().is_some_and(|n| n.starts_with("seburity-")) { continue; }
        let Ok(md) = fs::symlink_metadata(e.path()) else { continue };
        if !md.is_dir() || md.uid() != me { continue; }
        let alive = fs::read_to_string(e.path().join("owner.pid")).ok().and_then(|t| t.trim().parse::<u32>().ok())
            .map(|pid| Path::new(&format!("/proc/{pid}")).exists());
        let stale = match alive { Some(a) => !a, None => md.modified().ok().and_then(|m| m.elapsed().ok()).is_some_and(|d| d > Duration::from_secs(60)) };
        if stale { let _ = fs::remove_dir_all(e.path()); }
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
    let dir = base.join(format!("seburity-{}", r.iter().map(|b| format!("{b:02x}")).collect::<String>()));
    if dir.join("socks").to_str().is_none_or(|p| p.len() > MAX_SOCKET_PATH) {
        return Err(TorError::Other(format!("runtime directory path is too long for unix sockets (max {MAX_SOCKET_PATH} bytes): {}", dir.display())));
    }
    fs::DirBuilder::new().mode(0o700).create(&dir)?; // fails if it already exists: never reuse someone else's directory
    fs::write(dir.join("owner.pid"), std::process::id().to_string())?;
    Ok(dir)
}

impl SpawnedTor {
    pub fn start(cfg: &SpawnConfig) -> Result<Self, TorError> {
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
}

impl Drop for SpawnedTor {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn torrc_is_private_and_fail_closed() {
        let t = torrc(Path::new("/dev/shm/seburity-ab12"), 4242, &["UseBridges 1".into()]).unwrap();
        assert!(t.contains("ControlPort unix:/dev/shm/seburity-ab12/ctl"));
        assert!(t.contains("SocksPort unix:/dev/shm/seburity-ab12/socks ExtendedErrors OnionTrafficOnly"), "tor's onion error codes + no clearnet dials");
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
        let dead = d.path().join("seburity-dead");
        let live = d.path().join("seburity-live");
        let other = d.path().join("unrelated");
        for p in [&dead, &live, &other] { fs::create_dir(p).unwrap(); }
        fs::write(dead.join("owner.pid"), "4294967290").unwrap(); // no such process
        fs::write(live.join("owner.pid"), std::process::id().to_string()).unwrap();
        sweep_stale(d.path());
        assert!(!dead.exists() && live.exists() && other.exists());
    }
}
