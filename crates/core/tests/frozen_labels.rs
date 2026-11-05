//! The project can be renamed with `scripts/rename-project.py`, but some strings contain the ORIGINAL codename and are part of the
//! disk/wire formats and the cryptographic domain separation (vault, bundles, messages, handshake, pairing, safety numbers). Renaming
//! one of them silently breaks every existing vault/bundle and changes the cryptography. This test keeps `scripts/frozen-labels.txt`
//! (which the rename script protects) and the sources in sync in BOTH directions.
use std::{collections::BTreeSet, fs, path::{Path, PathBuf}};

fn root() -> PathBuf { Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap() }

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() { rs_files(&p, out); } else if p.extension().is_some_and(|x| x == "rs") { out.push(p); }
    }
}

fn frozen() -> BTreeSet<String> {
    fs::read_to_string(root().join("scripts/frozen-labels.txt")).unwrap().lines()
        .map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).map(String::from).collect()
}

/// Every double-quoted string of the sources that starts with the legacy codename (or is the contact-file armor).
fn labels_in_sources() -> BTreeSet<String> {
    let mut files = Vec::new();
    for c in fs::read_dir(root().join("crates")).unwrap() { let p = c.unwrap().path().join("src"); if p.is_dir() { rs_files(&p, &mut files); } }
    let mut found = BTreeSet::new();
    for f in files {
        let text = fs::read_to_string(&f).unwrap();
        for line in text.lines() {
            if line.trim_start().starts_with("//") { continue; } // doc comments may mention a label
            let mut rest = line;
            while let Some(i) = rest.find('"') {
                let after = &rest[i + 1..];
                let Some(j) = after.find('"') else { break };
                let s = &after[..j];
                if s.starts_with("seburity-") || s.contains("SEBURITY CONTACT") { found.insert(s.to_string()); }
                rest = &after[j + 1..];
            }
        }
    }
    found
}

#[test]
fn every_label_in_the_sources_is_listed_as_frozen() {
    let (list, found) = (frozen(), labels_in_sources());
    let unlisted: Vec<_> = found.difference(&list).collect();
    assert!(unlisted.is_empty(), "these strings embed the legacy codename but are not in scripts/frozen-labels.txt (a rename would corrupt them): {unlisted:?}");
}

#[test]
fn every_frozen_label_is_still_used_and_unchanged() {
    let (list, found) = (frozen(), labels_in_sources());
    let missing: Vec<_> = list.difference(&found).collect();
    assert!(missing.is_empty(), "frozen labels that no source uses any more (renamed by accident, or removed?): {missing:?}");
    assert!(list.len() >= 18, "the frozen list was truncated");
}
