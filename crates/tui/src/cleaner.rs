//! Sandboxed file cleaning: hostile JPEG/PNG/text from a contact (or a file you were handed) is parsed in a CHILD PROCESS (this
//! same binary started with `--clean-worker`) that has hard resource limits, instead of inside the process that holds your keys.
//! What this buys: a parser crash (`panic = "abort"`), runaway memory or CPU only kills the helper; the helper cannot open
//! files or sockets (RLIMIT_NOFILE = 3: just stdin/stdout/stderr), cannot write files (RLIMIT_FSIZE = 0), cannot fork
//! (RLIMIT_NPROC = 0), has no environment, no core dump, is non-dumpable, and has a CPU and an address-space cap.
//! What it does NOT buy: no seccomp/Landlock (that needs a dependency or `unsafe`, see docs/FILE_SHARING.md): a helper that is
//! actually compromised could still use syscalls that are not covered by an rlimit (e.g. `execve` of a program it can name).
//! The helper's answer is parsed as untrusted input (`seburity_strip::wire`).
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
    // limits first: nothing below needs more than the three standard descriptors
    let lim = |r: Resource, n: u64| { let _ = setrlimit(r, Rlimit { current: Some(n), maximum: Some(n) }); };
    lim(Resource::Core, 0);
    lim(Resource::Cpu, 30);
    lim(Resource::As, 1 << 30);
    lim(Resource::Fsize, 0);
    lim(Resource::Nofile, 3);
    lim(Resource::Nproc, 0);
    #[cfg(target_os = "linux")]
    let _ = rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable);
    let mut input = Zeroizing::new(Vec::with_capacity(MAX_INPUT + 16));
    if std::io::stdin().take(MAX_INPUT as u64 + 16).read_to_end(&mut input).is_err() { std::process::exit(2); }
    let answer = match wire::decode_request(&input) {
        Some((mode, data)) => wire::encode_response(&seburity_strip::clean(data, mode)),
        None => wire::encode_response(&Err(StripError::Refused("bad request".into()))),
    };
    let mut out = std::io::stdout();
    let ok = out.write_all(&answer).and_then(|_| out.flush()).is_ok();
    std::process::exit(if ok { 0 } else { 3 })
}

/// The cleaner the app installs: run the job in a helper started from this very executable.
pub fn sandboxed_clean(d: &[u8], mode: Mode) -> Result<Cleaned, StripError> {
    run_helper(Path::new("/proc/self/exe"), d, mode)
}

pub fn run_helper(exe: &Path, d: &[u8], mode: Mode) -> Result<Cleaned, StripError> {
    let refuse = |m: String| StripError::Refused(m);
    if d.len() > MAX_INPUT { return Err(StripError::TooLarge); }
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
            let status = child.wait();
            match (wire::decode_response(&buf), status) {
                (r, Ok(s)) if s.success() => r,
                (_, Ok(s)) => Err(refuse(format!("the cleaning helper died ({s}): the file was refused"))),
                (_, Err(e)) => Err(refuse(format!("the cleaning helper failed ({e})"))),
            }
        }
        Err(_) => { let _ = child.kill(); let _ = child.wait(); Err(refuse("the cleaning helper timed out and was killed".into())) }
    }
}
