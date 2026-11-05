use crate::{book::Store, StoreError};
use nerd_chat_vault::{Profile, Vault, VaultError};
use std::{fs, io::Write, path::{Path, PathBuf}, sync::atomic::{AtomicBool, Ordering}};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

/// An open (unlocked) vault bound to a file (or RAM-only when `path` is None).
pub struct VaultFile {
    path: Option<PathBuf>,
    counter_path: Option<PathBuf>,
    vault: Vault,
    pub store: Store,
}

#[derive(Debug, PartialEq, Eq)]
pub struct OpenInfo {
    /// No counter file existed, so rollback of the vault file could NOT be checked.
    pub rollback_unchecked: bool,
    pub counter: u64,
    /// The counter file shares a filesystem with the vault: weak rollback protection.
    pub counter_same_device: bool,
}

fn io<E: std::fmt::Display>(e: E) -> StoreError { StoreError::Io(e.to_string()) }

fn default_counter_path(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".counter");
    PathBuf::from(s)
}

/// Read a REGULAR file safely: never follows a symlink, never blocks on a FIFO/device (so a hostile
/// USB stick cannot freeze the UI or swallow keystrokes via /dev/tty), size-capped.
pub fn read_regular_file(path: &Path, max: u64) -> Result<Vec<u8>, StoreError> {
    use std::io::Read;
    let mut o = fs::OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    o.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let f = o.open(path).map_err(io)?;
    let md = f.metadata().map_err(io)?;
    if !md.is_file() { return Err(StoreError::Io("not a regular file".into())); }
    if md.len() > max { return Err(StoreError::Io(format!("file larger than {max} bytes"))); }
    // Pre-sized from fstat: read_to_end into a growing Vec would leave copies of the plaintext in freed heap.
    let mut v = vec![0u8; md.len() as usize];
    let mut f = f;
    f.read_exact(&mut v).map_err(io)?;
    let mut extra = [0u8; 1];
    if f.read(&mut extra).map_err(io)? != 0 { return Err(StoreError::Io("file changed while reading".into())); }
    Ok(v)
}

const MAX_VAULT_BYTES: u64 = 64 * 1024 * 1024;

/// Write `data` atomically: random temp name (create_new: never follows a planted symlink or reuses
/// an attacker's file) -> chmod 0600 -> fsync -> rename -> fsync(dir). Temp file removed on error.
fn write_atomic(path: &Path, data: &[u8]) -> Result<(), StoreError> {
    let mut rnd = [0u8; 8];
    getrandom::fill(&mut rnd).expect("OS RNG unavailable");
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".{}.tmp", rnd.iter().map(|b| format!("{b:02x}")).collect::<String>()));
    let tmp = PathBuf::from(tmp);
    let r = (|| -> Result<(), StoreError> {
        let mut o = fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        o.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        let mut f = o.open(&tmp).map_err(io)?;
        #[cfg(unix)]
        { use std::os::unix::fs::PermissionsExt; f.set_permissions(fs::Permissions::from_mode(0o600)).map_err(io)?; }
        f.write_all(data).map_err(io)?;
        f.sync_all().map_err(io)?;
        drop(f);
        fs::rename(&tmp, path).map_err(io)?;
        if let Some(dir) = path.parent() {
            let dir = if dir.as_os_str().is_empty() { Path::new(".") } else { dir };
            if let Ok(d) = fs::File::open(dir) { let _ = d.sync_all(); }
        }
        Ok(())
    })();
    if r.is_err() { let _ = fs::remove_file(&tmp); }
    r
}

/// True if both paths live on the same filesystem device (then the counter file adds little
/// against someone who can restore the whole disk).
#[cfg(unix)]
fn same_device(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let dir = |p: &Path| p.parent().filter(|d| !d.as_os_str().is_empty()).map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
    match (fs::metadata(dir(a)), fs::metadata(dir(b))) { (Ok(x), Ok(y)) => x.dev() == y.dev(), _ => true }
}
#[cfg(not(unix))]
fn same_device(_: &Path, _: &Path) -> bool { true }

impl VaultFile {
    /// Brand-new vault. Refuses to overwrite an existing file. `path = None` -> RAM-only: never touches disk.
    pub fn create(path: Option<&Path>, counter_path: Option<&Path>, pw: &[u8], keyfile: Option<&[u8]>, profile: Profile) -> Result<Self, StoreError> {
        Self::create_cancellable(path, counter_path, pw, keyfile, profile, &AtomicBool::new(false))
    }

    /// Like `create`, but `cancel` is checked after the (slow) key derivation and right before anything
    /// touches the disk: a panic wipe that arrives while the worker derives the key must not leave a
    /// vault, a counter file or a half-written temp file behind (R8-L4).
    pub fn create_cancellable(path: Option<&Path>, counter_path: Option<&Path>, pw: &[u8], keyfile: Option<&[u8]>, profile: Profile, cancel: &AtomicBool) -> Result<Self, StoreError> {
        if let Some(p) = path { if p.exists() { return Err(StoreError::Exists); } }
        // A leftover counter file means a vault existed: creating over it would silently reset rollback protection.
        let cp = counter_path.map(Path::to_path_buf).or_else(|| path.map(default_counter_path));
        if cp.as_ref().is_some_and(|c| c.exists()) { return Err(StoreError::CounterExists); }
        let vault = Vault::create(pw, keyfile, profile)?;
        if cancel.load(Ordering::SeqCst) { return Err(StoreError::Cancelled); }
        let mut vf = Self {
            path: path.map(Path::to_path_buf),
            counter_path: counter_path.map(Path::to_path_buf).or_else(|| path.map(default_counter_path)),
            vault,
            store: Store::new(),
        };
        vf.save_unless(cancel)?;
        Ok(vf)
    }

    pub fn open(path: &Path, counter_path: Option<&Path>, pw: &[u8], keyfile: Option<&[u8]>) -> Result<(Self, OpenInfo), StoreError> {
        let blob = read_regular_file(path, MAX_VAULT_BYTES)?;
        let cpath = counter_path.map(Path::to_path_buf).unwrap_or_else(|| default_counter_path(path));
        let min = if cpath.exists() {
            let b = read_regular_file(&cpath, 8)?;
            Some(u64::from_le_bytes(b.try_into().map_err(|_| StoreError::Corrupt)?))
        } else { None };
        let (vault, data) = Vault::open_checked(&blob, pw, keyfile, min.unwrap_or(0))?;
        let store = Store::decode(&data).map_err(|_| StoreError::Vault(VaultError::Malformed))?;
        let info = OpenInfo { rollback_unchecked: min.is_none(), counter: vault.counter(), counter_same_device: same_device(path, &cpath) };
        Ok((Self { path: Some(path.to_path_buf()), counter_path: Some(cpath), vault, store }, info))
    }

    /// Persist the store (atomic) and advance the external rollback counter.
    /// RAM-only vaults skip all disk I/O.
    pub fn save(&mut self) -> Result<(), StoreError> { self.save_unless(&AtomicBool::new(false)) }

    fn save_unless(&mut self, cancel: &AtomicBool) -> Result<(), StoreError> {
        let data = self.store.encode();
        let blob = self.vault.seal(&data)?;
        if let Some(p) = &self.path {
            if cancel.load(Ordering::SeqCst) { return Err(StoreError::Cancelled); }
            write_atomic(p, &blob)?;
            if let Some(c) = &self.counter_path { write_atomic(c, &self.vault.counter().to_le_bytes())?; }
        }
        Ok(())
    }

    pub fn is_ram_only(&self) -> bool { self.path.is_none() }
    pub fn counter_same_device(&self) -> bool {
        match (&self.path, &self.counter_path) { (Some(p), Some(c)) => same_device(p, c), _ => false }
    }
    pub fn counter(&self) -> u64 { self.vault.counter() }

    /// Re-verifies the old password, rotates the data key, saves.
    pub fn change_password(&mut self, old_pw: &[u8], old_kf: Option<&[u8]>, new_pw: &[u8], new_kf: Option<&[u8]>, profile: Profile) -> Result<(), StoreError> {
        let data = self.store.encode();
        let blob = self.vault.change_credentials(old_pw, old_kf, new_pw, new_kf, profile, &data)?;
        if let Some(p) = &self.path {
            write_atomic(p, &blob)?;
            if let Some(c) = &self.counter_path { write_atomic(c, &self.vault.counter().to_le_bytes())?; }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const P: Profile = Profile::InsecureTest;

    #[test]
    fn create_save_reopen() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("v.vault");
        let mut vf = VaultFile::create(Some(&p), None, b"pw", None, P).unwrap();
        vf.store.add_contact("alice").unwrap();
        vf.save().unwrap();
        let (vf2, info) = VaultFile::open(&p, None, b"pw", None).unwrap();
        assert_eq!(vf2.store.contacts[0].name, "alice");
        assert!(!info.rollback_unchecked);
        assert_eq!(info.counter, vf.counter());
        assert!(matches!(VaultFile::open(&p, None, b"bad", None), Err(StoreError::Vault(VaultError::WrongCredentials))));
        assert!(matches!(VaultFile::create(Some(&p), None, b"pw", None, P), Err(StoreError::Exists)));
    }

    #[test]
    fn a_cancelled_create_leaves_nothing_on_disk() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("v.vault");
        let cancel = AtomicBool::new(true);
        assert!(matches!(VaultFile::create_cancellable(Some(&p), None, b"pw", None, P, &cancel), Err(StoreError::Cancelled)));
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 0, "no vault, counter or temp file");
        // and a later normal create is not blocked by a stray counter file
        VaultFile::create(Some(&p), None, b"pw", None, P).unwrap();
    }

    #[test]
    fn rollback_to_older_copy_is_detected() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("v.vault");
        let mut vf = VaultFile::create(Some(&p), None, b"pw", None, P).unwrap();
        vf.store.add_contact("alice").unwrap();
        vf.save().unwrap();
        let old = fs::read(&p).unwrap();
        vf.store.add_contact("bob").unwrap();
        vf.save().unwrap();
        fs::write(&p, old).unwrap(); // attacker restores older vault
        assert!(matches!(VaultFile::open(&p, None, b"pw", None), Err(StoreError::Vault(VaultError::Rollback { .. }))));
    }

    #[test]
    fn missing_counter_file_is_reported_not_silent() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("v.vault");
        VaultFile::create(Some(&p), None, b"pw", None, P).unwrap();
        fs::remove_file(default_counter_path(&p)).unwrap();
        let (_, info) = VaultFile::open(&p, None, b"pw", None).unwrap();
        assert!(info.rollback_unchecked);
    }

    #[test]
    fn ram_only_never_touches_disk() {
        let d = tempfile::tempdir().unwrap();
        std::env::set_current_dir(d.path()).unwrap();
        let mut vf = VaultFile::create(None, None, b"pw", None, P).unwrap();
        vf.store.add_contact("x").unwrap();
        vf.save().unwrap();
        assert!(vf.is_ram_only());
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 0);
    }

    #[test]
    fn change_password_persists_and_old_fails() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("v.vault");
        let mut vf = VaultFile::create(Some(&p), None, b"old", None, P).unwrap();
        vf.store.add_contact("alice").unwrap();
        vf.change_password(b"old", None, b"new", None, P).unwrap();
        assert!(VaultFile::open(&p, None, b"old", None).is_err());
        assert_eq!(VaultFile::open(&p, None, b"new", None).unwrap().0.store.contacts.len(), 1);
        assert!(vf.change_password(b"WRONG", None, b"x", None, P).is_err());
    }

    #[test]
    fn create_refuses_when_counter_file_exists_and_no_temp_leftovers() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("v.vault");
        fs::write(default_counter_path(&p), 5u64.to_le_bytes()).unwrap();
        assert!(matches!(VaultFile::create(Some(&p), None, b"pw", None, P), Err(StoreError::CounterExists)));
        fs::remove_file(default_counter_path(&p)).unwrap();
        VaultFile::create(Some(&p), None, b"pw", None, P).unwrap();
        let names: Vec<_> = fs::read_dir(d.path()).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        assert!(names.iter().all(|n| !n.ends_with(".tmp")), "{names:?}");
    }

    #[cfg(unix)]
    #[test]
    fn hostile_files_cannot_block_or_redirect_reads() {
        use std::os::unix::fs::symlink;
        let d = tempfile::tempdir().unwrap();
        // symlink -> refused (O_NOFOLLOW)
        let target = d.path().join("real"); fs::write(&target, b"x").unwrap();
        let link = d.path().join("link"); symlink(&target, &link).unwrap();
        assert!(read_regular_file(&link, 100).is_err());
        // FIFO -> returns immediately with an error instead of blocking forever
        let fifo = d.path().join("fifo");
        assert!(std::process::Command::new("mkfifo").arg(&fifo).status().unwrap().success());
        let t = std::time::Instant::now();
        assert!(read_regular_file(&fifo, 100).is_err());
        assert!(t.elapsed() < std::time::Duration::from_secs(2));
        // device, oversize, ok
        assert!(read_regular_file(Path::new("/dev/zero"), 100).is_err());
        fs::write(d.path().join("big"), vec![0u8; 101]).unwrap();
        assert!(read_regular_file(&d.path().join("big"), 100).is_err());
        assert_eq!(read_regular_file(&target, 100).unwrap(), b"x");
    }

    #[cfg(unix)]
    #[test]
    fn planted_temp_symlink_is_not_followed() {
        use std::os::unix::fs::symlink;
        let d = tempfile::tempdir().unwrap();
        let victim = d.path().join("victim"); fs::write(&victim, b"precious").unwrap();
        // attacker plants the OLD predictable temp name
        symlink(&victim, d.path().join("v.vault.tmp")).unwrap();
        let p = d.path().join("v.vault");
        VaultFile::create(Some(&p), None, b"pw", None, P).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"precious");
    }

    #[cfg(unix)]
    #[test]
    fn vault_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("v.vault");
        VaultFile::create(Some(&p), None, b"pw", None, P).unwrap();
        assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
