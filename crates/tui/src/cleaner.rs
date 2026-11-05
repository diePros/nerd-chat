//! Cleaning of hostile files in a sandboxed CHILD PROCESS (this same binary started with `--clean-worker`) instead of inside the process
//! that holds your keys, with resource limits, `no_new_privs`, its own session and a kill-with-parent signal (a network namespace via `unshare` would need `unsafe`).
//!
//! What this IS: containment of parser CRASHES and runaway CPU/memory/time. A crash (`panic = "abort"`), an endless loop or a
//! memory bomb only kills the helper and the file is refused; the helper never sees keys, the vault or the environment, and its
//! answer is decoded as untrusted input (`seburity_strip::wire`).
//!
//! On top of that the helper installs a seccomp-BPF ALLOWLIST (crate `seburity-sandbox`, x86_64 only) BEFORE it reads a single
//! untrusted byte: afterwards it can only read fd 0, write fd 1/2, manage memory (no PROT_EXEC) and exit. Any other syscall
//! (open, socket, execve, unlink, kill, ptrace, mprotect, close, fork...) kills it with SIGSYS and the file is refused. A
//! compromised parser can therefore no longer read files, reach the network, change files or signal the parent. Where no
//! filter exists (other architectures, kernels without seccomp) the helper refuses to run (`--no-sandbox` is the explicit way out).
//! Remaining weakness: the parser still shares the pipe to the parent, so it can lie in its answer (hence the strict decoder) and
//! it can burn CPU/memory up to the limits (hence the rlimits and the timeout).
use seburity_strip::{wire, Cleaned, Mode, StripError, MAX_INPUT};
use std::{io::{Read, Write}, path::Path, process::{Command, Stdio}, sync::mpsc::channel, thread, time::Duration};
use zeroize::Zeroizing;

const WORKER_FLAG: &str = "--clean-worker";
/// Exit status of a helper that could not install its sandbox (no filter for this platform, kernel refused): the parent explains.
const EXIT_NO_SANDBOX: i32 = 4;
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
        // the parent may have died between spawn and the line above (then nobody would signal us): we were re-parented to init/a subreaper
        if rustix::process::getppid().is_some_and(|p| p.is_init()) { die("the parent is gone"); }
        if rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable).is_err() { die("could not mark the helper non-dumpable"); }
    }
    // the allowlist is installed BEFORE any untrusted byte is read: from here on only read(0)/write(1,2)/memory/exit are possible
    if seburity_sandbox::enter().is_err() { std::process::exit(EXIT_NO_SANDBOX); }
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
                (r, Ok(s)) if s.code() == Some(EXIT_NO_SANDBOX) => {
                    if let Ok(mut c) = r { zeroize::Zeroize::zeroize(&mut c.data); }
                    Err(refuse("the sandbox of the cleaning helper could not be installed here (needs Linux x86_64 with seccomp); the file was refused. Start seburity with --no-sandbox to clean files in-process (less safe).".into()))
                }
                (r, Ok(s)) => { if let Ok(mut c) = r { zeroize::Zeroize::zeroize(&mut c.data); } Err(refuse(format!("the cleaning helper died ({s}): the file was refused"))) }
                (r, Err(e)) => { if let Ok(mut c) = r { zeroize::Zeroize::zeroize(&mut c.data); } Err(refuse(format!("the cleaning helper failed ({e})"))) }
            }
        }
        Err(_) => { let _ = child.kill(); let _ = child.wait(); Err(refuse("the cleaning helper timed out and was killed".into())) }
    }
}
