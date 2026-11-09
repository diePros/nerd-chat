//! R33-8: an OLDER copy of the history file put back is noticed through the counter file.
use nerd_chat_store::{history::{History, NoPlatformKeys, Persist, State, SystemClock}, StoreError, VaultFile};
use nerd_chat_vault::Profile;
use std::{fs, sync::Arc};

fn open(p: &std::path::Path, vf: &VaultFile) -> Result<History, StoreError> {
    History::open_with_floor(p, 8192, vf.subkey(b"history"), Arc::new(NoPlatformKeys), Arc::new(SystemClock::new()), Persist::Day, vf.history_floor())
}

#[test]
fn an_old_copy_of_the_history_file_is_refused_and_a_deleted_one_is_just_empty() {
    let d = tempfile::tempdir().unwrap();
    let vp = d.path().join("v");
    let hp = d.path().join("v.hist");
    let mut vf = VaultFile::create(Some(&vp), None, b"pw", None, Profile::InsecureTest).unwrap();
    let mut h = open(&hp, &vf).unwrap();
    h.push([1; 8], State::Queued, Some([5; 8]), "unsent");
    h.tick().unwrap();
    vf.record_history_gen(h.generation()).unwrap();
    let old = fs::read(&hp).unwrap();                         // a copy an attacker keeps
    h.set_state([1; 8], [5; 8], State::Delivered);
    h.tick().unwrap();
    vf.record_history_gen(h.generation()).unwrap();
    drop(h); drop(vf);
    let (vf, _) = VaultFile::open(&vp, None, b"pw", None).unwrap();
    assert!(open(&hp, &vf).is_ok(), "the real file opens");
    fs::write(&hp, &old).unwrap();                            // put the old copy back
    assert!(matches!(open(&hp, &vf), Err(StoreError::HistoryRolledBack)), "the old copy brings back an unsent text that was delivered");
    assert_eq!(fs::read(&hp).unwrap(), old, "refusing leaves the file as it is");
    // deleting the file is just an empty history; new generations continue above the floor
    fs::remove_file(&hp).unwrap();
    let mut h = open(&hp, &vf).unwrap();
    assert!(h.is_empty() && h.generation() >= vf.history_floor());
    h.push([1; 8], State::Received, None, "new"); h.tick().unwrap();
    assert!(h.generation() > vf.history_floor());
}
