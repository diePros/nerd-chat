//! Cleaning of hostile files in a CHILD PROCESS (this same binary started with `--clean-worker`) instead of inside the process
//! that holds your keys, with resource limits, `no_new_privs`, its own session and a kill-with-parent signal (a network namespace via `unshare` would need `unsafe`).
//!
//! What this IS: containment of parser CRASHES and runaway CPU/memory/time. A crash (`panic = "abort"`), an endless loop or a
//! memory bomb only kills the helper and the file is refused; the helper never sees keys, the vault or the environment, and its
//! answer is decoded as untrusted input (`seburity_strip::wire`).
//!
//! What this is NOT: a sandbox against a COMPROMISED parser. RLIMIT_NOFILE only caps descriptor numbers (a helper can close
//! stdin/stderr and open a file or socket with the freed numbers), RLIMIT_FSIZE does not stop writes through a shared mmap,
//! unlink or rename, and NPROC does not stop execve. A compromised helper can therefore still read files the user can read,
//! reach the network, signal the parent and modify the user's files. Real containment needs seccomp or Landlock (a dependency or
//! `unsafe`, see docs/FILE_SHARING.md).
use seburity_strip::{wire, Cleaned, Mode, StripError, MAX_INPUT};
use std::{io::{Read, Write}, path::Path, process::{Command, Stdio}, sync::mpsc::channel, thread, time::Duration};
use zeroize::Zeroizing;

const WORKER_FLAG: &str = "--clean-worker";
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
    #[cfg(target_os = "linux")]
    {
        if rustix::thread::set_no_new_privs(true).is_err() { die("could not set no_new_privs"); }
        let _ = rustix::process::setsid(); // no controlling terminal (/dev/tty)
        // killed together with the parent (panic wipe / exit): no helper outlives the app holding plaintext
        if rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::KILL)).is_err() { die("could not set the death signal"); }
        if rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable).is_err() { die("could not mark the helper non-dumpable"); }
    }
    let mut input = Zeroizing::new(Vec::with_capacity(MAX_INPUT + 16));
    if std::io::stdin().take(MAX_INPUT as u64 + 16).read_to_end(&mut input).is_err() { std::process::exit(2); }
    let answer = Zeroizing::new(match wire::decode_request(&input) {
        Some((mode, data)) => wire::encode_response(&seburity_strip::clean(data, mode)),
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

pub fn run_helper(exe: &Path, d: &[u8], mode: Mode) -> Result<Cleaned, StripError> {
    let refuse = |m: String| StripError::Refused(m);
    if d.len() > MAX_INPUT { return Err(StripError::TooLarge); }
    let started = std::time::Instant::now();
    let mut child = Command::new(exe).arg(WORKER_FLAG).env_clear()
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
                (r, Ok(s)) => { if let Ok(mut c) = r { zeroize::Zeroize::zeroize(&mut c.data); } Err(refuse(format!("the cleaning helper died ({s}): the file was refused"))) }
                (r, Err(e)) => { if let Ok(mut c) = r { zeroize::Zeroize::zeroize(&mut c.data); } Err(refuse(format!("the cleaning helper failed ({e})"))) }
            }
        }
        Err(_) => { let _ = child.kill(); let _ = child.wait(); Err(refuse("the cleaning helper timed out and was killed".into())) }
    }
}
