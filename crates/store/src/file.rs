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

/// Where the rollback counter of the vault at `p` lives unless `--counter-file` says otherwise.
pub fn counter_path_for(p: &Path) -> PathBuf { default_counter_path(p) }

fn default_counter_path(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".counter");
    PathBuf::from(s)
}

/// Overwrite a regular file with random bytes (synced), then delete it. A symlink is only unlinked, never followed. Best effort and
/// honest about it: on flash media (SSD/USB stick) wear levelling may keep old blocks, so this is not a guarantee: the real protection
/// of a vault is its password (and keyfile), which a purge destroys together with the vault and the counter.
pub fn shred_file(path: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::MetadataExt;
    let md = fs::symlink_metadata(path).map_err(io)?;
    if !md.is_file() { return fs::remove_file(path).map_err(io); } // a symlink or special file: unlink only
    let overwrite = (|| -> std::io::Result<()> {
        let mut o = fs::OpenOptions::new();
        o.write(true);
        #[cfg(unix)]
        o.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        // a read-only file we own (chmod 400 keyfiles are common) must still be overwritten, not merely unlinked
        let f0 = match o.open(path) {
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
                o.open(path)?
            }
            r => r?,
        };
        // the file we opened must be the one we looked at (a swapped-in file is not ours to overwrite)
        { let m = f0.metadata()?; if (m.dev(), m.ino()) != (md.dev(), md.ino()) { return Err(std::io::Error::other("the file changed while being shredded")); } }
        let mut f = f0;
        let mut left = md.len().min(1 << 30);
        let mut buf = vec![0u8; 64 * 1024];
        while left > 0 {
            let n = left.min(buf.len() as u64) as usize;
            getrandom::fill(&mut buf[..n]).map_err(|_| std::io::Error::other("no OS randomness"))?;
            f.write_all(&buf[..n])?;
            left -= n as u64;
        }
        f.sync_all()
    })();
    let removed = fs::remove_file(path).map_err(io); // delete even when the overwrite failed
    overwrite.map_err(io).and(removed)
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
/// The rollback-counter file: `nonce[24] | AEAD(counter u64 LE)[8+16]` = 48 bytes, ALWAYS the same size, under a key only the unlocked vault has, a fresh nonce on every write.
/// (Before, it was the 8 plain bytes of the counter: anyone who could look at the folder saw how many times the vault had been saved.)
const COUNTER_FILE_LEN: usize = 24 + 8 + 16;
const COUNTER_AAD: &[u8] = b"nerd-chat-counter-file-v1";

fn counter_file(vault: &Vault) -> Vec<u8> {
    use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, XChaCha20Poly1305, XNonce};
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).expect("OS RNG unavailable");
    let key = vault.subkey(b"counter-file");
    let ct = XChaCha20Poly1305::new((&*key).into()).encrypt(XNonce::from_slice(&nonce), Payload { msg: &vault.counter().to_le_bytes(), aad: COUNTER_AAD }).expect("encrypt");
    [nonce.as_slice(), ct.as_slice()].concat()
}

/// Read the counter file (new 48-byte form, or the old 8 plain bytes: it is rewritten in the new form on the next save).
fn read_counter(path: &Path, vault: &Vault) -> Result<u64, StoreError> {
    use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, XChaCha20Poly1305, XNonce};
    let b = read_regular_file(path, COUNTER_FILE_LEN as u64)?;
    if b.len() == 8 { return Ok(u64::from_le_bytes(b.try_into().map_err(|_| StoreError::Corrupt)?)); }
    if b.len() != COUNTER_FILE_LEN { return Err(StoreError::Corrupt); }
    let key = vault.subkey(b"counter-file");
    let pt = XChaCha20Poly1305::new((&*key).into()).decrypt(XNonce::from_slice(&b[..24]), Payload { msg: &b[24..], aad: COUNTER_AAD }).map_err(|_| StoreError::Corrupt)?;
    Ok(u64::from_le_bytes(pt.try_into().map_err(|_| StoreError::Corrupt)?))
}

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
        if let Some(p) = path { if fs::symlink_metadata(p).is_ok() { return Err(StoreError::Exists); } } // a dangling symlink is NOT 'absent' (R26-M1)
        // A leftover counter file means a vault existed: creating over it would silently reset rollback protection.
        let cp = counter_path.map(Path::to_path_buf).or_else(|| path.map(default_counter_path));
        if cp.as_ref().is_some_and(|c| fs::symlink_metadata(c).is_ok()) { return Err(StoreError::CounterExists); }
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
        // open first, THEN read the counter: its file is encrypted under a key that only the unlocked vault has
        let (vault, data) = Vault::open_checked(&blob, pw, keyfile, 0)?;
        let min = if cpath.exists() { Some(read_counter(&cpath, &vault)?) } else { None };
        if let Some(m) = min { if vault.counter() < m { return Err(StoreError::Vault(VaultError::Rollback { found: vault.counter(), expected: m })); } }
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
            // the vault file IS written at this point: a failure of the counter file must be told apart (the caller must not roll its memory back)
            if let Some(c) = &self.counter_path { write_atomic(c, &counter_file(&self.vault)).map_err(|e| StoreError::CounterWrite(e.to_string()))?; }
        }
        Ok(())
    }

    /// Re-verifies the old password, rotates the data key, saves.
    pub fn change_password(&mut self, old_pw: &[u8], old_kf: Option<&[u8]>, new_pw: &[u8], new_kf: Option<&[u8]>, profile: Profile) -> Result<(), StoreError> {
        let data = self.store.encode();
        let blob = self.vault.change_credentials(old_pw, old_kf, new_pw, new_kf, profile, &data)?;
        if let Some(p) = &self.path {
            write_atomic(p, &blob)?;
            if let Some(c) = &self.counter_path { write_atomic(c, &counter_file(&self.vault))?; }
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
        assert_eq!(info.counter, vf.vault.counter());
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
    fn shred_overwrites_the_data_then_deletes_and_never_follows_a_symlink() {
        let d = tempfile::tempdir().unwrap();
        let (p, twin) = (d.path().join("secret"), d.path().join("twin"));
        fs::write(&p, vec![0xAAu8; 200_000]).unwrap();
        fs::hard_link(&p, &twin).unwrap();                 // a second name of the SAME data: shows what the overwrite left behind
        shred_file(&p).unwrap();
        assert!(!p.exists());
        let left = fs::read(&twin).unwrap();
        assert_eq!(left.len(), 200_000);
        assert!(left.iter().filter(|&&b| b == 0xAA).count() < 2000, "the original bytes must be overwritten, not just unlinked");
        // a symlink is only unlinked: its target is untouched
        let (target, link) = (d.path().join("target"), d.path().join("link"));
        fs::write(&target, b"keep me").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        shred_file(&link).unwrap();
        assert!(!link.exists() && fs::read(&target).unwrap() == b"keep me");
        assert!(shred_file(&d.path().join("missing")).is_err(), "a missing file is reported");
    }

    #[test]
    fn shred_overwrites_a_read_only_file_we_own_before_deleting_it() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let (p, witness) = (d.path().join("key.bin"), d.path().join("witness"));
        fs::write(&p, [7u8; 4096]).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o400)).unwrap();    // chmod 400 keyfiles are common
        fs::hard_link(&p, &witness).unwrap();                                     // keeps the same inode alive to look at it afterwards
        shred_file(&p).unwrap();
        assert!(!p.exists());
        assert_ne!(fs::read(&witness).unwrap(), vec![7u8; 4096], "the content was overwritten, not merely unlinked");
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
        assert!(vf.path.is_none());
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

    #[test]
    fn create_never_replaces_a_dangling_symlink() {
        let d = tempfile::tempdir().unwrap();
        let link = d.path().join("v.vault");
        std::os::unix::fs::symlink(d.path().join("nowhere"), &link).unwrap();
        let r = VaultFile::create(Some(&link), None, b"a password of 12+", None, Profile::LowMem);
        assert!(matches!(r, Err(StoreError::Exists)), "{:?}", r.err());
        assert!(!d.path().join("nowhere").exists());
    }

    #[test]
    fn the_counter_file_is_fixed_size_encrypted_and_does_not_count_the_saves() {
        let d = tempfile::tempdir().unwrap(); let p = d.path().join("v");
        let mut vf = VaultFile::create(Some(&p), None, b"pw", None, Profile::InsecureTest).unwrap();
        let cp = default_counter_path(&p);
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..12 {
            vf.save().unwrap();
            let raw = fs::read(&cp).unwrap();
            assert_eq!(raw.len(), COUNTER_FILE_LEN, "always the same size");
            assert!(!raw.windows(8).any(|w| w == vf.vault.counter().to_le_bytes()), "the counter value is not in the file in the clear");
            seen.insert(raw);
        }
        assert_eq!(seen.len(), 12, "a fresh nonce every time: no two writes look alike");
        let (again, info) = VaultFile::open(&p, None, b"pw", None).unwrap();
        assert!(!info.rollback_unchecked && info.counter == again.vault.counter());
    }

    #[test]
    fn an_old_plain_counter_file_still_opens_and_is_upgraded_on_the_next_save() {
        let d = tempfile::tempdir().unwrap(); let p = d.path().join("v");
        let vf = VaultFile::create(Some(&p), None, b"pw", None, Profile::InsecureTest).unwrap();
        let cp = default_counter_path(&p);
        fs::write(&cp, vf.vault.counter().to_le_bytes()).unwrap();                 // what the previous version wrote
        let (mut vf2, info) = VaultFile::open(&p, None, b"pw", None).unwrap();
        assert!(!info.rollback_unchecked);
        vf2.save().unwrap();
        assert_eq!(fs::read(&cp).unwrap().len(), COUNTER_FILE_LEN, "rewritten in the new form");
        // and the old form still catches a rollback: a plain counter FAR ahead of the vault
        fs::write(&cp, u64::MAX.to_le_bytes()).unwrap();
        assert!(matches!(VaultFile::open(&p, None, b"pw", None), Err(StoreError::Vault(VaultError::Rollback { .. }))));
    }

    #[test]
    fn a_tampered_or_foreign_counter_file_is_refused_not_trusted() {
        let d = tempfile::tempdir().unwrap(); let p = d.path().join("v");
        let mut vf = VaultFile::create(Some(&p), None, b"pw", None, Profile::InsecureTest).unwrap();
        vf.save().unwrap();
        let cp = default_counter_path(&p);
        let good = fs::read(&cp).unwrap();
        let mut bad = good.clone(); bad[30] ^= 1;
        fs::write(&cp, &bad).unwrap();
        assert!(matches!(VaultFile::open(&p, None, b"pw", None), Err(StoreError::Corrupt)), "flipped bit");
        fs::write(&cp, &good[..40]).unwrap();
        assert!(matches!(VaultFile::open(&p, None, b"pw", None), Err(StoreError::Corrupt)), "wrong length");
        // a counter file made by ANOTHER vault does not decrypt (different key): refused
        let d2 = tempfile::tempdir().unwrap(); let p2 = d2.path().join("w");
        let mut other = VaultFile::create(Some(&p2), None, b"pw", None, Profile::InsecureTest).unwrap(); other.save().unwrap();
        fs::copy(default_counter_path(&p2), &cp).unwrap();
        assert!(matches!(VaultFile::open(&p, None, b"pw", None), Err(StoreError::Corrupt)));
    }
}
