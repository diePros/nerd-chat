use crate::{book::Store, StoreError};
use seburity_vault::{Profile, Vault, VaultError};
use std::{fs, io::Write, path::{Path, PathBuf}};
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
}

fn io<E: std::fmt::Display>(e: E) -> StoreError { StoreError::Io(e.to_string()) }

fn default_counter_path(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".counter");
    PathBuf::from(s)
}

/// Write `data` atomically with 0600 permissions: temp file -> fsync -> rename -> fsync(dir).
fn write_atomic(path: &Path, data: &[u8]) -> Result<(), StoreError> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let mut o = fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    o.mode(0o600);
    let mut f = o.open(&tmp).map_err(io)?;
    f.write_all(data).map_err(io)?;
    f.sync_all().map_err(io)?;
    drop(f);
    fs::rename(&tmp, path).map_err(io)?;
    if let Some(dir) = path.parent() {
        let dir = if dir.as_os_str().is_empty() { Path::new(".") } else { dir };
        if let Ok(d) = fs::File::open(dir) { let _ = d.sync_all(); }
    }
    Ok(())
}

impl VaultFile {
    /// Brand-new vault. Refuses to overwrite an existing file. `path = None` -> RAM-only: never touches disk.
    pub fn create(path: Option<&Path>, counter_path: Option<&Path>, pw: &[u8], keyfile: Option<&[u8]>, profile: Profile) -> Result<Self, StoreError> {
        if let Some(p) = path { if p.exists() { return Err(StoreError::Exists); } }
        let vault = Vault::create(pw, keyfile, profile)?;
        let mut vf = Self {
            path: path.map(Path::to_path_buf),
            counter_path: counter_path.map(Path::to_path_buf).or_else(|| path.map(default_counter_path)),
            vault,
            store: Store::new(),
        };
        vf.save()?;
        Ok(vf)
    }

    pub fn open(path: &Path, counter_path: Option<&Path>, pw: &[u8], keyfile: Option<&[u8]>) -> Result<(Self, OpenInfo), StoreError> {
        let blob = fs::read(path).map_err(io)?;
        let cpath = counter_path.map(Path::to_path_buf).unwrap_or_else(|| default_counter_path(path));
        let min = match fs::read(&cpath) {
            Ok(b) if b.len() == 8 => Some(u64::from_le_bytes(b.try_into().unwrap())),
            Ok(_) => return Err(StoreError::Corrupt),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(io(e)),
        };
        let (vault, data) = Vault::open_checked(&blob, pw, keyfile, min.unwrap_or(0))?;
        let store = Store::decode(&data).map_err(|_| StoreError::Vault(VaultError::Malformed))?;
        let info = OpenInfo { rollback_unchecked: min.is_none(), counter: vault.counter() };
        Ok((Self { path: Some(path.to_path_buf()), counter_path: Some(cpath), vault, store }, info))
    }

    /// Persist the store (atomic) and advance the external rollback counter.
    /// RAM-only vaults skip all disk I/O.
    pub fn save(&mut self) -> Result<(), StoreError> {
        let data = self.store.encode();
        let blob = self.vault.seal(&data)?;
        if let Some(p) = &self.path {
            write_atomic(p, &blob)?;
            if let Some(c) = &self.counter_path { write_atomic(c, &self.vault.counter().to_le_bytes())?; }
        }
        Ok(())
    }

    pub fn is_ram_only(&self) -> bool { self.path.is_none() }
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
