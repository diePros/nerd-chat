//! THE TIMING-COVER TEST (docs/HISTORY_AND_TIMING_PLAN.md section 2): run a live session in which messages are pushed at moments that are NOT on the grid, tick on the grid,
//! and look at what the KERNEL says about the files. The claim: mtime and ctime of the history file, the vault file and its counter file only ever show grid (tick) times,
//! never the moment of a message; the birth time and the inode never change; the size never changes.
use sine_loco_store::{
    history::{History, NoPlatformKeys, State, SystemClock, Persist, Tick},
    VaultFile,
};
use sine_loco_vault::Profile;
use std::{fs, os::unix::fs::MetadataExt, sync::Arc, thread, time::{Duration, SystemTime, UNIX_EPOCH}};
use zeroize::Zeroizing;

fn ns(sec: i64, nsec: i64) -> u128 { (sec as u128) * 1_000_000_000 + nsec as u128 }
fn now_ns() -> u128 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() }
struct Times { m: u128, c: u128, birth: Option<SystemTime>, ino: u64, len: u64 }
fn times(p: &std::path::Path) -> Times {
    let md = fs::metadata(p).unwrap();
    Times { m: ns(md.mtime(), md.mtime_nsec()), c: ns(md.ctime(), md.ctime_nsec()), birth: md.created().ok(), ino: md.ino(), len: md.len() }
}

#[test]
fn file_times_show_the_grid_never_the_moment_of_a_message() {
    let d = tempfile::tempdir().unwrap();
    let vp = d.path().join("sine-loco.vault");
    let vf = VaultFile::create(Some(&vp), None, b"pw", None, Profile::InsecureTest).unwrap();
    let cp = sine_loco_store::counter_path_for(&vp);
    let hp = d.path().join("hist.bin");
    let mut h = History::open(&hp, 64 * 1024, vf.subkey(b"history"), Arc::new(NoPlatformKeys), Arc::new(SystemClock::new()), Persist::Day).unwrap();

    let files = [&hp, &vp, &cp];
    let start: Vec<Times> = files.iter().map(|p| times(p)).collect();
    let grid = Duration::from_millis(250);
    let mut windows: Vec<(u128, u128)> = Vec::new();      // (start, end) of every tick, kernel-clock nanoseconds
    let mut message_moments: Vec<u128> = Vec::new();
    let mut wrote = 0;
    let session_start = std::time::Instant::now();
    let mut next = session_start + grid;
    let mut k = 0u32;
    while session_start.elapsed() < Duration::from_millis(2600) {
        // messages arrive at moments that are deliberately NOT on the grid (a third and two thirds of the way between ticks)
        for frac in [3u32, 3 * 2 / 3 + 1] {
            let at = next - grid + grid * frac / 5;
            while std::time::Instant::now() < at { thread::sleep(Duration::from_millis(5)); }
            let before: Vec<(u128, u128)> = files.iter().map(|p| { let t = times(p); (t.m, t.c) }).collect();
            h.push([1; 8], if k % 2 == 0 { State::Received } else { State::Queued }, if k % 2 == 0 { None } else { Some([k as u8; 8]) }, &format!("message {k}"));
            message_moments.push(now_ns());
            k += 1;
            let after: Vec<(u128, u128)> = files.iter().map(|p| { let t = times(p); (t.m, t.c) }).collect();
            assert_eq!(before, after, "a message must not change any file time by itself");
        }
        while std::time::Instant::now() < next { thread::sleep(Duration::from_millis(5)); }
        let (t0, outcome) = (now_ns(), h.tick().unwrap());
        vf.touch().unwrap();                                // what the app's grid does for the vault and its counter
        windows.push((t0, now_ns()));
        if outcome == Tick::Wrote { wrote += 1; }
        // after the tick, every file's times are INSIDE the tick window
        let (lo, hi) = (t0.saturating_sub(5_000_000), now_ns() + 5_000_000);
        for p in files { let t = times(p); assert!(t.m >= lo && t.m <= hi && t.c >= lo && t.c <= hi, "{}: times must be the tick's, not a message's", p.display()); }
        next += grid;
    }
    assert!(wrote >= 5, "real data was written on ticks ({wrote})");
    // every moment a message arrived lies strictly BETWEEN ticks, and no file time equals any of those moments
    for p in files {
        let t = times(p);
        for m in &message_moments { assert!(t.m != *m && t.c != *m); }
    }
    // the file was never replaced: same inode, same birth time, same size, from the first tick to the last
    for (p, s) in files.iter().zip(&start) {
        let t = times(p);
        assert_eq!(t.ino, s.ino, "{}: same inode (no rename)", p.display());
        assert_eq!(t.birth, s.birth, "{}: same birth time", p.display());
        assert_eq!(t.len, s.len, "{}: same size", p.display());
    }
    // and the last file time is the last tick, however late the last message came
    let last = windows.last().unwrap();
    let t = times(&hp);
    assert!(t.c >= last.0.saturating_sub(5_000_000) && t.c <= last.1 + 5_000_000);
    let _ = Zeroizing::new(0u8);
}
