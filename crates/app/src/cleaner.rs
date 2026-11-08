//! Cleaning of hostile files in a sandboxed CHILD PROCESS (this same binary started with `--clean-worker`) instead of inside the process
//! that holds your keys, with resource limits, `no_new_privs`, its own session and a kill-with-parent signal (a network namespace via `unshare` would need `unsafe`).
//!
//! What this IS: containment of parser CRASHES and runaway CPU/memory/time. A crash (`panic = "abort"`), an endless loop or a
//! memory bomb only kills the helper and the file is refused; the helper never sees keys, the vault or the environment, and its
//! answer is decoded as untrusted input (`nerd_chat_strip::wire`).
//!
//! On top of that the helper installs a seccomp-BPF ALLOWLIST (crate `nerd-chat-sandbox`, x86_64 only) BEFORE it reads a single
//! untrusted byte: afterwards it can only read fd 0, write fd 1/2, manage memory (no PROT_EXEC) and exit. Any other syscall
//! (open, socket, execve, unlink, kill, ptrace, mprotect, close, fork...) kills it with SIGSYS and the file is refused. A
//! compromised parser can therefore no longer read files, reach the network, change files or signal the parent. Where no
//! filter exists (other architectures, kernels without seccomp) the helper refuses to run (`--no-sandbox` is the explicit way out).
//! Remaining weakness: the parser still shares the pipe to the parent, so it can lie in its answer (hence the strict decoder) and
//! it can burn CPU/memory up to the limits (hence the rlimits and the timeout).
use nerd_chat_strip::{wire, Cleaned, Mode, StripError, MAX_INPUT};
use std::{io::{Read, Write}, path::Path, process::{Command, Stdio}, sync::mpsc::channel, thread, time::Duration};
use zeroize::Zeroizing;

const WORKER_FLAG: &str = "--clean-worker";
/// Exit status of a helper that could not install its sandbox (no filter for this platform, kernel refused): the parent explains.
const EXIT_NO_SANDBOX: i32 = 4;
/// The parent tells the helper its pid so the helper can notice that it was orphaned before the death signal was armed.
const PARENT_ENV: &str = "NERD_CHAT_PARENT";
/// Hard wall-clock limit for one cleaning job (the cleaner itself stops after ~8 s of validation work).
const JOB_TIMEOUT: Duration = Duration::from_secs(25);
const ANSWER_CAP: u64 = MAX_INPUT as u64 + 8192;

pub fn is_worker_invocation(args: &[String]) -> bool { args.len() == 2 && args[1] == WORKER_FLAG }

/// Entry point of the helper process. Never returns.
pub fn worker_main() -> ! {
    use rustix::process::{setrlimit, Resource, Rlimit};
    let die = |why: &str| -> ! { eprintln!("clean-worker: {why}"); std::process::exit(2) };
    if rustix::process::geteuid().is_root() { die("refusing to run as root"); }
    // limits and hardening: failing to apply ANY of them means we do not touch hostile data
    let lim = |r: Resource, n: u64| if setrlimit(r, Rlimit { current: Some(n), maximum: Some(n) }).is_err() { die("could not apply a resource limit") };
    lim(Resource::Core, 0);
    lim(Resource::Cpu, 30);
    lim(Resource::As, 1 << 30);
    lim(Resource::Fsize, 0);
    lim(Resource::Nofile, 3);
    lim(Resource::Nproc, 0);
    lim(Resource::Memlock, 0); // MAP_LOCKED must not pin memory even if the launcher raised the inherited limit
    #[cfg(target_os = "linux")]
    {
        if rustix::thread::set_no_new_privs(true).is_err() { die("could not set no_new_privs"); }
        let _ = rustix::process::setsid(); // no controlling terminal (/dev/tty)
        // killed together with the parent (panic wipe / exit): no helper outlives the app holding plaintext
        if rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::KILL)).is_err() { die("could not set the death signal"); }
        // the parent may have died between spawn and the line above (then nobody would signal us): our parent must still be the
        // process that started us (it passes its pid; absent when run by hand). Re-parenting goes to init OR a subreaper, so
        // "parent is pid 1" would be the wrong test (and wrong when the app itself is pid 1 in a container).
        if let Some(expect) = std::env::var(PARENT_ENV).ok().and_then(|v| v.parse::<u32>().ok()) {
            if rustix::process::getppid().map(|p| p.as_raw_nonzero().get() as u32) != Some(expect) { die("the parent is gone"); }
        }
        if rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable).is_err() { die("could not mark the helper non-dumpable"); }
    }
    // the allowlist is installed BEFORE any untrusted byte is read: from here on only read(0)/write(1,2)/memory/exit are possible
    if nerd_chat_sandbox::enter().is_err() { std::process::exit(EXIT_NO_SANDBOX); }
    let mut input = Zeroizing::new(Vec::with_capacity(MAX_INPUT + 16));
    if std::io::stdin().take(MAX_INPUT as u64 + 16).read_to_end(&mut input).is_err() { std::process::exit(2); }
    let answer = Zeroizing::new(match wire::decode_request(&input) {
        Some((mode, data)) => wire::encode_response(&nerd_chat_strip::clean(data, mode)),
        None => wire::encode_response(&Err(StripError::Refused("bad request".into()))),
    });
    let mut out = std::io::stdout();
    let ok = out.write_all(&answer).and_then(|_| out.flush()).is_ok();
    drop(answer);
    drop(input); // `process::exit` skips destructors: wipe explicitly
    std::process::exit(if ok { 0 } else { 3 })
}

/// The cleaner the app installs: run the job in a helper started from this very executable.
pub fn sandboxed_clean(d: &[u8], mode: Mode) -> Result<Cleaned, StripError> {
    run_helper(Path::new("/proc/self/exe"), d, mode)
}

/// Run the helper on a harmless request: does it end with `EXIT_NO_SANDBOX` (the genuine "cannot sandbox here" answer)?
fn probe_says_no_sandbox(exe: &Path) -> bool {
    let Ok(mut c) = Command::new(exe).arg(WORKER_FLAG).env_clear().env(PARENT_ENV, std::process::id().to_string())
        .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn() else { return false };
    if let Some(mut si) = c.stdin.take() { let _ = si.write_all(&wire::encode_request(Mode::PlainText, b"probe")); }
    let end = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match c.try_wait() {
            Ok(Some(s)) => return s.code() == Some(EXIT_NO_SANDBOX),
            Ok(None) if std::time::Instant::now() < end => thread::sleep(Duration::from_millis(10)),
            _ => { let _ = c.kill(); let _ = c.wait(); return false; }
        }
    }
}

pub fn run_helper(exe: &Path, d: &[u8], mode: Mode) -> Result<Cleaned, StripError> {
    let refuse = |m: String| StripError::Refused(m);
    if d.len() > MAX_INPUT { return Err(StripError::TooLarge); }
    let started = std::time::Instant::now();
    let mut child = Command::new(exe).arg(WORKER_FLAG).env_clear().env(PARENT_ENV, std::process::id().to_string())
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())
        .spawn().map_err(|e| refuse(format!("the cleaning helper could not start ({e}); start with --no-sandbox to clean in-process")))?;
    let (mut stdin, mut stdout) = (child.stdin.take().expect("piped"), child.stdout.take().expect("piped"));
    let req = Zeroizing::new(wire::encode_request(mode, d));
    thread::spawn(move || { let _ = stdin.write_all(&req); }); // dropping `stdin` closes it
    let (tx, rx) = channel();
    thread::spawn(move || {
        let mut buf = Zeroizing::new(Vec::with_capacity(ANSWER_CAP as usize)); // fixed capacity: no realloc copies of the file
        let _ = (&mut stdout).take(ANSWER_CAP).read_to_end(&mut buf);
        let _ = tx.send(buf);
    });
    match rx.recv_timeout(JOB_TIMEOUT) {
        Ok(buf) => {
            // EOF on stdout does not mean the helper ended: bound the wait by the same deadline (a stuck helper is killed)
            let status = loop {
                match child.try_wait() {
                    Ok(Some(s)) => break Ok(s),
                    Ok(None) if started.elapsed() < JOB_TIMEOUT => thread::sleep(Duration::from_millis(10)),
                    Ok(None) => { let _ = child.kill(); let _ = child.wait(); return Err(refuse("the cleaning helper did not exit and was killed".into())); }
                    Err(e) => break Err(e),
                }
            };
            match (wire::decode_response(&buf), status) {
                (r, Ok(s)) if s.success() => r,
                (r, Ok(s)) if s.code() == Some(EXIT_NO_SANDBOX) => {
                    if let Ok(mut c) = r { zeroize::Zeroize::zeroize(&mut c.data); }
                    // exit 4 can be FORGED by a compromised parser (`exit_group` is allowed): never take it at face value. A probe
                    // helper that sees only a benign request shows whether this machine really cannot sandbox.
                    if probe_says_no_sandbox(exe) {
                        Err(refuse("the sandbox of the cleaning helper could not be installed here (needs Linux x86_64 with seccomp); the file was refused. Start nerd-chat with --no-sandbox to clean files in-process (less safe).".into()))
                    } else {
                        Err(refuse("the cleaning helper failed abnormally on this file: it may be an attack; the file was refused".into()))
                    }
                }
                (r, Ok(s)) => { if let Ok(mut c) = r { zeroize::Zeroize::zeroize(&mut c.data); } Err(refuse(format!("the cleaning helper died ({s}): the file was refused"))) }
                (r, Err(e)) => { if let Ok(mut c) = r { zeroize::Zeroize::zeroize(&mut c.data); } Err(refuse(format!("the cleaning helper failed ({e})"))) }
            }
        }
        Err(_) => { let _ = child.kill(); let _ = child.wait(); Err(refuse("the cleaning helper timed out and was killed".into())) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn fake_helper(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    /// A helper that says "exit 4" for EVERY request is a machine that cannot sandbox: the advice to use --no-sandbox is honest.
    #[test]
    fn a_machine_that_really_cannot_sandbox_gets_the_no_sandbox_advice() {
        let d = tempfile::tempdir().unwrap();
        let exe = fake_helper(d.path(), "always4", "cat >/dev/null; exit 4");
        match run_helper(&exe, b"hello", Mode::PlainText) {
            Err(StripError::Refused(m)) => assert!(m.contains("--no-sandbox"), "{m}"),
            other => panic!("{other:?}"),
        }
    }

    /// Review 19 (M1): a COMPROMISED parser can call exit_group(4) itself. Then the benign probe does not exit 4, and the app must
    /// say "possible attack" and must NOT recommend disabling the sandbox.
    #[test]
    fn a_forged_exit_4_never_makes_the_app_recommend_disabling_the_sandbox() {
        let d = tempfile::tempdir().unwrap();
        // exits 4 for anything except the probe request (which contains the word "probe")
        let exe = fake_helper(d.path(), "forger", "if grep -aq probe; then exit 0; else exit 4; fi");
        match run_helper(&exe, b"a hostile image", Mode::PlainText) {
            Err(StripError::Refused(m)) => { assert!(!m.contains("--no-sandbox"), "{m}"); assert!(m.contains("attack"), "{m}"); }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn other_helper_failures_are_plain_refusals() {
        let d = tempfile::tempdir().unwrap();
        let exe = fake_helper(d.path(), "crash", "cat >/dev/null; kill -SEGV $$");
        match run_helper(&exe, b"x", Mode::PlainText) {
            Err(StripError::Refused(m)) => assert!(!m.contains("--no-sandbox") && m.contains("refused"), "{m}"),
            other => panic!("{other:?}"),
        }
    }
}
