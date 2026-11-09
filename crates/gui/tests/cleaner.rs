//! The GUI binary's cleaning helper process (same checks as crates/tui/tests/cleaner.rs; the GUI has no --strip command): it works, refuses what it must, and really runs under hard resource limits.
use sine_loco_strip::wire;
use std::{io::{Read, Write}, process::{Command, Stdio}};

const EXE: &str = env!("CARGO_BIN_EXE_sine-loco-gui");

fn run_worker(request: &[u8]) -> (Vec<u8>, bool) {
    let mut c = Command::new(EXE).arg("--clean-worker").env_clear().stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
    c.stdin.take().unwrap().write_all(request).unwrap();
    let mut out = Vec::new();
    c.stdout.take().unwrap().read_to_end(&mut out).unwrap();
    (out, c.wait().unwrap().success())
}

#[test]
fn the_helper_cleans_and_refuses_like_the_in_process_cleaner() {
    let (out, ok) = run_worker(&wire::encode_request(sine_loco_strip::Mode::PlainText, "hi\u{200B}there\u{202E}".as_bytes()));
    assert!(ok);
    let c = wire::decode_response(&out).unwrap();
    assert_eq!(String::from_utf8(c.data).unwrap(), "hi?there?".replace('?', "")); // invisible/bidi characters are removed
    let (out, ok) = run_worker(&wire::encode_request(sine_loco_strip::Mode::Auto, b"MZ not an image"));
    assert!(ok);
    assert!(matches!(wire::decode_response(&out), Err(sine_loco_strip::StripError::Unsupported)));
    let (out, ok) = run_worker(&[9, 9, 9]); // garbage request
    assert!(ok && matches!(wire::decode_response(&out), Err(sine_loco_strip::StripError::Refused(_))));
}

#[test]
fn the_helper_runs_under_hard_resource_limits() {
    let mut c = Command::new(EXE).arg("--clean-worker").env_clear().stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    // it blocks on stdin: inspect its limits while it waits
    let path = format!("/proc/{}/limits", c.id());
    let mut limits = String::new();
    for _ in 0..100 {
        limits = std::fs::read_to_string(&path).unwrap_or_default();
        if limits.contains("Max open files") && limits.lines().any(|l| l.starts_with("Max open files") && l.split_whitespace().nth(3) == Some("3")) { break; }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let get = |name: &str| limits.lines().find(|l| l.starts_with(name)).map(|l| l.split_whitespace().skip(name.split_whitespace().count()).take(2).collect::<Vec<_>>().join(" ")).unwrap_or_default();
    // the seccomp filter is installed right before the helper blocks on stdin: wait for it (it comes after the rlimits)
    let mut status = String::new();
    for _ in 0..250 {
        status = std::fs::read_to_string(format!("/proc/{}/status", c.id())).unwrap_or_default();
        if status.lines().any(|l| l.starts_with("Seccomp:") && l.ends_with('2')) { break; }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(status.lines().any(|l| l.starts_with("Seccomp:") && l.ends_with('2')), "the helper must run under a seccomp FILTER: {status}");
    // one more filter than this test process itself runs under (a CI runner/container may already apply its own)
    let count = |t: &str| t.lines().find(|l| l.starts_with("Seccomp_filters:")).and_then(|l| l.split_whitespace().nth(1)).and_then(|n| n.parse::<u32>().ok()).unwrap_or(0);
    let mine = count(&std::fs::read_to_string("/proc/self/status").unwrap());
    assert_eq!(count(&status), mine + 1, "{status}");
    assert_eq!(get("Max open files"), "3 3", "{limits}");
    assert_eq!(get("Max file size"), "0 0", "{limits}");
    assert_eq!(get("Max processes"), "0 0", "{limits}");
    assert_eq!(get("Max core file size"), "0 0", "{limits}");
    assert_eq!(get("Max cpu time"), "30 30", "{limits}");
    assert_eq!(get("Max address space"), "1073741824 1073741824", "{limits}");
    let status = std::fs::read_to_string(format!("/proc/{}/status", c.id())).unwrap_or_default();
    assert!(status.lines().any(|l| l.starts_with("NoNewPrivs:") && l.ends_with('1')), "no_new_privs must be set: {status}");
    drop(c.stdin.take());
    let _ = c.wait();
}
