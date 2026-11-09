//! Where the vault lives when the user gives no `--vault`.
//!
//! Order (the first match wins, and the choice never depends on the current directory once a default vault exists):
//!   1. `<data dir>/nerd-chat/nerd-chat.vault` exists  -> use it (`$XDG_DATA_HOME`, else `~/.local/share`)
//!   2. `./nerd-chat.vault` or the old `./seburity.vault` exists -> use it (vaults made before this default existed keep working)
//!   3. nothing exists -> a NEW vault in the data dir, only after the user confirmed the location (`main.rs`)
//! Pure decisions live here so they can be tested without touching the real home directory.
use std::path::{Path, PathBuf};

pub const FILE: &str = "nerd-chat.vault";
const LEGACY_FILE: &str = "seburity.vault";
const DIR: &str = "nerd-chat";

pub enum Choice {
    /// An existing vault; `note` (if any) is printed to the user.
    Existing { path: PathBuf, note: Option<String> },
    /// No vault yet: this is where a new one would go.
    New { dir: PathBuf, path: PathBuf },
    /// No usable default (no home directory): the user must pass `--vault`.
    Unusable(String),
}

/// The directory for the default vault: `$XDG_DATA_HOME/nerd-chat` if that variable is an ABSOLUTE path (the XDG rule), else
/// `$HOME/.local/share/nerd-chat`; `None` if there is no absolute home either.
pub fn default_dir(xdg_data_home: Option<&Path>, home: Option<&Path>) -> Option<PathBuf> {
    let abs = |p: &&Path| p.is_absolute() && !p.as_os_str().is_empty();
    match xdg_data_home.filter(abs) {
        Some(x) => Some(x.join(DIR)),
        None => home.filter(abs).map(|h| h.join(".local").join("share").join(DIR)),
    }
}

pub fn resolve(xdg_data_home: Option<&Path>, home: Option<&Path>, cwd: &Path, exists: &dyn Fn(&Path) -> bool) -> Choice {
    let dir = default_dir(xdg_data_home, home);
    let in_cwd = [FILE, LEGACY_FILE].into_iter().map(|f| cwd.join(f)).find(|p| exists(p));
    if let Some(dir) = &dir {
        let p = dir.join(FILE);
        if exists(&p) {
            let note = in_cwd.map(|c| format!("note: using {} ; ignoring {} in this directory (pass --vault {} to use that one)", p.display(), c.display(), c.display()));
            return Choice::Existing { path: p, note };
        }
    }
    if let Some(c) = in_cwd {
        // a relative path as before: it keeps meaning "this directory's file", and the old note for the renamed file stays
        let rel = PathBuf::from(c.file_name().expect("has a file name"));
        let note = match &dir {
            Some(d) if rel.as_os_str() == LEGACY_FILE => Some(format!("note: using the existing ./{LEGACY_FILE} (the default is now {})", d.join(FILE).display())),
            Some(d) => Some(format!("note: using ./{FILE} in this directory (the default for new vaults is now {})", d.join(FILE).display())),
            None => None,
        };
        return Choice::Existing { path: rel, note };
    }
    match dir {
        Some(dir) => Choice::New { path: dir.join(FILE), dir },
        None => Choice::Unusable("no home directory found (HOME is not set to an absolute path): pass --vault PATH".into()),
    }
}

/// `true` for Tails (its os-release carries `TAILS_PRODUCT_NAME`): there `~` is erased at shutdown.
pub fn is_tails(os_release: &str) -> bool { os_release.lines().any(|l| l.trim_start().starts_with("TAILS_PRODUCT_NAME=")) }

/// The text shown before a NEW vault is created at the default place.
pub fn confirm_text(path: &Path, tails: bool) -> String {
    let mut s = format!("No vault found. A NEW one will be created at:\n  {}\nThat is on THIS computer's disk. To keep it elsewhere (a USB stick) use --vault PATH.\n", path.display());
    if tails { s.push_str("WARNING: this looks like Tails: your home directory is ERASED at shutdown, so this vault would be gone after the next restart.\nUse the Persistent Storage instead: --vault ~/Persistent/nerd-chat.vault\n"); }
    s.push_str("Home-directory backups and sync tools copy this folder too, and a restored backup brings back an old vault (rollback goes unnoticed).\n");
    s.push_str("Press Enter (an empty line) to continue; anything else cancels.");
    s
}

/// Create the vault directory (mode 0700) or check an existing one: it must be a real directory (not a symlink), owned by us and not
/// writable by anyone else, because other users could otherwise swap or watch the vault and its rollback counter.
pub fn prepare_dir(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    match std::fs::symlink_metadata(dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new().mode(0o700).create(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))
        }
        Err(e) => Err(format!("cannot inspect {}: {e}", dir.display())),
        Ok(m) => check_dir_meta(dir, &m),
    }
}

fn check_dir_meta(dir: &Path, m: &std::fs::Metadata) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    if !m.is_dir() { Err(format!("{} exists but is not a real directory (a symlink or a file): refusing to use it for the vault", dir.display())) }
    else if m.uid() != rustix::process::getuid().as_raw() { Err(format!("{} is not owned by you: refusing to use it for the vault", dir.display())) }
    else if m.mode() & 0o022 != 0 { Err(format!("{} is writable by other users (mode {:o}): run chmod 700 on it or pass --vault", dir.display(), m.mode() & 0o7777)) }
    else { Ok(()) }
}

/// An EXISTING vault chosen without `--vault` (R26-M1/L1/L7/I3): it must be a regular file (never a symlink, FIFO, directory or a path we
/// cannot inspect: such a path would be treated as "absent" later and replaced by a new vault), owned by us, and when it lies in an
/// absolute directory (the default data dir) that directory gets the same checks as for a new vault.
pub fn check_existing(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(path).map_err(|e| format!("cannot inspect {}: {e}", path.display()))?;
    if !m.is_file() { return Err(format!("{} exists but is not a regular file (a symlink, directory or device): refusing to use or replace it; pass --vault PATH", path.display())); }
    if m.uid() != rustix::process::getuid().as_raw() { return Err(format!("{} is not owned by you: refusing to use it", path.display())); }
    if let Some(dir) = path.parent().filter(|d| d.is_absolute()) {
        let dm = std::fs::symlink_metadata(dir).map_err(|e| format!("cannot inspect {}: {e}", dir.display()))?;
        check_dir_meta(dir, &dm)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn p(s: &str) -> PathBuf { PathBuf::from(s) }
    fn set(v: &[&str]) -> HashSet<PathBuf> { v.iter().map(|s| p(s)).collect() }

    #[test]
    fn the_xdg_variable_wins_only_when_it_is_absolute() {
        assert_eq!(default_dir(Some(&p("/data")), Some(&p("/home/u"))), Some(p("/data/nerd-chat")));
        assert_eq!(default_dir(None, Some(&p("/home/u"))), Some(p("/home/u/.local/share/nerd-chat")));
        assert_eq!(default_dir(Some(&p("relative/dir")), Some(&p("/home/u"))), Some(p("/home/u/.local/share/nerd-chat")), "XDG says: ignore a relative value");
        assert_eq!(default_dir(Some(&p("")), Some(&p("/home/u"))), Some(p("/home/u/.local/share/nerd-chat")));
        assert_eq!(default_dir(None, Some(&p("home"))), None, "a relative HOME is not trusted");
        assert_eq!(default_dir(None, None), None);
    }

    #[test]
    fn a_fresh_machine_gets_a_new_vault_in_the_data_dir() {
        let none = set(&[]);
        match resolve(None, Some(&p("/home/u")), &p("/work"), &|x| none.contains(x)) {
            Choice::New { dir, path } => { assert_eq!(dir, p("/home/u/.local/share/nerd-chat")); assert_eq!(path, p("/home/u/.local/share/nerd-chat/nerd-chat.vault")); }
            _ => panic!("expected New"),
        }
        assert!(matches!(resolve(None, None, &p("/work"), &|_| false), Choice::Unusable(_)));
    }

    #[test]
    fn an_existing_default_vault_is_used_from_any_directory() {
        let have = set(&["/home/u/.local/share/nerd-chat/nerd-chat.vault"]);
        for cwd in ["/work", "/tmp", "/"] {
            match resolve(None, Some(&p("/home/u")), &p(cwd), &|x| have.contains(x)) {
                Choice::Existing { path, note } => { assert_eq!(path, p("/home/u/.local/share/nerd-chat/nerd-chat.vault")); assert!(note.is_none()); }
                _ => panic!("expected Existing"),
            }
        }
    }

    #[test]
    fn vaults_made_before_the_default_existed_keep_working_and_say_so() {
        let have = set(&["/work/nerd-chat.vault"]);
        match resolve(None, Some(&p("/home/u")), &p("/work"), &|x| have.contains(x)) {
            Choice::Existing { path, note } => { assert_eq!(path, p("nerd-chat.vault"), "relative, exactly as before"); assert!(note.unwrap().contains("default for new vaults")); }
            _ => panic!("expected Existing"),
        }
        let old = set(&["/work/seburity.vault"]);
        match resolve(None, Some(&p("/home/u")), &p("/work"), &|x| old.contains(x)) {
            Choice::Existing { path, note } => { assert_eq!(path, p("seburity.vault")); assert!(note.unwrap().contains("seburity.vault")); }
            _ => panic!("expected Existing"),
        }
        // no home at all: the current directory still works, silently as before
        match resolve(None, None, &p("/work"), &|x| have.contains(x)) { Choice::Existing { path, note } => { assert_eq!(path, p("nerd-chat.vault")); assert!(note.is_none()); } _ => panic!() }
    }

    #[test]
    fn when_both_exist_the_default_wins_and_the_other_is_named() {
        let have = set(&["/home/u/.local/share/nerd-chat/nerd-chat.vault", "/work/nerd-chat.vault"]);
        match resolve(None, Some(&p("/home/u")), &p("/work"), &|x| have.contains(x)) {
            Choice::Existing { path, note } => {
                assert_eq!(path, p("/home/u/.local/share/nerd-chat/nerd-chat.vault"));
                let n = note.unwrap();
                assert!(n.contains("ignoring /work/nerd-chat.vault") && n.contains("--vault"), "{n}");
            }
            _ => panic!("expected Existing"),
        }
    }

    #[test]
    fn tails_is_recognised_and_warned_about() {
        assert!(is_tails("NAME=\"Debian\"\nTAILS_PRODUCT_NAME=\"Tails\"\n"));
        assert!(!is_tails("NAME=\"Ubuntu\"\nID=ubuntu\n"));
        let t = confirm_text(&p("/home/amnesia/.local/share/nerd-chat/nerd-chat.vault"), true);
        assert!(t.contains("ERASED") && t.contains("Persistent") && t.contains("cancels"));
        assert!(!confirm_text(&p("/x/nerd-chat.vault"), false).contains("ERASED"));
    }

    #[test]
    fn the_directory_is_created_private_and_unsafe_ones_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("a/b/nerd-chat");
        prepare_dir(&d).unwrap();
        assert_eq!(std::fs::metadata(&d).unwrap().permissions().mode() & 0o777, 0o700);
        prepare_dir(&d).unwrap(); // a second run accepts its own directory
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(prepare_dir(&d).unwrap_err().contains("writable by other users"));
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o702)).unwrap();
        assert!(prepare_dir(&d).is_err(), "other-write is refused too");
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        prepare_dir(&d).unwrap(); // readable by others is harmless: the vault file itself is 0600
    }

    #[test]
    fn a_symlink_or_a_file_in_place_of_the_directory_is_refused() {
        use std::os::unix::fs::symlink;
        let t = tempfile::tempdir().unwrap();
        let real = t.path().join("real"); std::fs::create_dir(&real).unwrap();
        let link = t.path().join("nerd-chat"); symlink(&real, &link).unwrap();
        assert!(prepare_dir(&link).unwrap_err().contains("not a real directory"));
        let file = t.path().join("f"); std::fs::write(&file, b"x").unwrap();
        assert!(prepare_dir(&file).unwrap_err().contains("not a real directory"));
    }

    #[test]
    fn an_existing_vault_must_be_a_regular_file_in_a_private_directory() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("nerd-chat");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let v = dir.join(FILE);
        std::fs::write(&v, b"x").unwrap();
        assert!(check_existing(&v).is_ok());
        // a dangling symlink must be refused, never treated as "absent" (it would be replaced by a new vault elsewhere)
        let link = dir.join("link.vault");
        symlink(d.path().join("nowhere"), &link).unwrap();
        assert!(check_existing(&link).unwrap_err().contains("not a regular file"));
        // a directory, and a missing path
        assert!(check_existing(&dir).is_err());
        assert!(check_existing(&dir.join("missing")).is_err());
        // a group-writable directory
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(check_existing(&v).unwrap_err().contains("writable by other users"));
    }
}
