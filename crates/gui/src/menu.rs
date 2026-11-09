//! "Hide Sine Loco from the application menu" (design D4): a per-user override of the packaged `.desktop` entry with `NoDisplay=true`.
//! The override file is itself a trace on the disk (it says the program is installed): the setting says so, and turning it off removes the file.
use std::path::{Path, PathBuf};

const FILE: &str = "sine-loco.desktop";
const ENTRY: &str = "[Desktop Entry]\nType=Application\nName=Sine Loco\nGenericName=Private chat\nComment=Serverless chat over Tor, messages only in memory\nExec=sine-loco-gui\nIcon=sine-loco\nTerminal=false\nCategories=Network;InstantMessaging;Chat;\nStartupWMClass=Sine Loco\n";

/// `<data dir>/applications/sine-loco.desktop` for the user: `$XDG_DATA_HOME` if absolute, else `$HOME/.local/share` (the XDG rule).
pub fn user_entry_path() -> Option<PathBuf> {
    let abs = |p: PathBuf| p.is_absolute().then_some(p);
    let data = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).and_then(abs)
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from).and_then(abs).map(|h| h.join(".local/share")))?;
    Some(data.join("applications").join(FILE))
}

pub fn is_hidden(path: &Path) -> bool { std::fs::read_to_string(path).is_ok_and(|s| s.lines().any(|l| l.trim() == "NoDisplay=true")) }

pub fn set_hidden(path: &Path, hide: bool) -> Result<(), String> {
    if hide {
        if let Some(dir) = path.parent() { std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?; }
        // never follow a link planted at that name
        if std::fs::symlink_metadata(path).is_ok_and(|m| !m.is_file()) { return Err(format!("{} exists but is not a regular file", path.display())); }
        std::fs::write(path, format!("{ENTRY}NoDisplay=true\n")).map_err(|e| format!("cannot write {}: {e}", path.display()))
    } else {
        match std::fs::symlink_metadata(path) {
            Ok(m) if m.is_file() => std::fs::remove_file(path).map_err(|e| format!("cannot remove {}: {e}", path.display())),
            Ok(_) => Err(format!("{} is not a regular file: left alone", path.display())),
            Err(_) => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hiding_writes_a_no_display_override_and_showing_removes_it() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("applications").join(FILE);
        assert!(!is_hidden(&p));
        set_hidden(&p, true).unwrap();
        assert!(is_hidden(&p));
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("Exec=sine-loco-gui") && text.contains("NoDisplay=true"));
        set_hidden(&p, false).unwrap();
        assert!(!p.exists() && !is_hidden(&p));
        set_hidden(&p, false).unwrap(); // already gone: fine
    }

    #[test]
    fn a_link_or_directory_at_that_name_is_never_followed_or_removed() {
        let d = tempfile::tempdir().unwrap();
        let apps = d.path().join("applications");
        std::fs::create_dir_all(&apps).unwrap();
        let victim = d.path().join("victim");
        std::fs::write(&victim, "keep").unwrap();
        let p = apps.join(FILE);
        std::os::unix::fs::symlink(&victim, &p).unwrap();
        assert!(set_hidden(&p, true).is_err());
        assert!(set_hidden(&p, false).is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
    }
}
