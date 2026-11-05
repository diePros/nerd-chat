//! The filter against the REAL kernel. Each case re-executes this test binary as a child that installs the filter and then
//! performs ONE syscall; the parent checks that forbidden calls kill the child with SIGSYS and allowed ones work. Every child
//! prints a marker before the filter is installed, so a case that never ran (renamed test, wrong filter) cannot pass vacuously, and
//! every child is killed after a deadline (a mutated filter that only kills a THREAD would otherwise hang the run).
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(unsafe_code)] // raw syscalls are the point of this test

use std::{io::Read, os::unix::process::ExitStatusExt, process::{Command, Stdio}, time::{Duration, Instant}};

const SIGSYS: i32 = 31;

fn nnp() { assert_eq!(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) }, 0); }

/// Runs inside the child process only.
#[test]
fn child_dispatch() {
    let Ok(case) = std::env::var("NERD_CHAT_SANDBOX_CASE") else { return };
    println!("CHILD-RAN:{case}");
    if case == "no_nnp" {
        // without no_new_privs the kernel must refuse (EACCES) and we must report it, never run unprotected
        let r = nerd_chat_sandbox::enter();
        println!("NNP-RESULT:{r:?}");
        unsafe { libc::syscall(libc::SYS_exit_group, if r == Err(nerd_chat_sandbox::Error::Kernel(libc::EACCES)) { 0 } else { 1 }) };
    }
    // everything a case needs from the OS is prepared BEFORE the filter (several of these calls are forbidden afterwards)
    let ppid = unsafe { libc::getppid() };
    let file = std::fs::File::open("/proc/self/exe").unwrap();
    let fd = std::os::fd::AsRawFd::as_raw_fd(&file);
    nnp();
    nerd_chat_sandbox::enter().expect("install");
    unsafe {
        let z = std::ptr::null::<u8>();
        match case.as_str() {
            "allowed" => {
                let msg = b"sandbox-ok\n";
                assert_eq!(libc::write(1, msg.as_ptr().cast(), msg.len()), msg.len() as isize);
                let m = libc::mmap(std::ptr::null_mut(), 1 << 20, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0);
                assert_ne!(m, libc::MAP_FAILED);
                *(m as *mut u8) = 1;
                assert_eq!(libc::munmap(m, 1 << 20), 0);
                let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
                assert_eq!(libc::syscall(libc::SYS_clock_gettime, libc::CLOCK_MONOTONIC, &mut ts as *mut libc::timespec), 0);
                assert_eq!(libc::syscall(libc::SYS_clock_gettime, libc::CLOCK_PROCESS_CPUTIME_ID, &mut ts as *mut libc::timespec), 0); // our OWN cpu time is fine
                let mut buf = [0u8; 4];
                assert_eq!(libc::syscall(libc::SYS_read, 0, buf.as_mut_ptr(), buf.len()), 0); // stdin is /dev/null in the test
                libc::syscall(libc::SYS_exit_group, 0);
            }
            "open" => { libc::syscall(libc::SYS_openat, libc::AT_FDCWD, b"/etc/hostname\0".as_ptr(), libc::O_RDONLY); }
            "socket" => { libc::syscall(libc::SYS_socket, libc::AF_INET, libc::SOCK_STREAM, 0); }
            "execve" => { let argv = [z, z]; libc::syscall(libc::SYS_execve, b"/nonexistent-nerd-chat-path\0".as_ptr(), argv.as_ptr(), argv.as_ptr()); }  // ENOENT if it were allowed: exit 77, never a loader dying for another reason
            "kill_parent" => { libc::syscall(libc::SYS_kill, ppid, 0); }
            "mprotect" => { libc::syscall(libc::SYS_mprotect, 0, 0, 0); }
            "mmap_exec" => { libc::syscall(libc::SYS_mmap, 0, 4096, libc::PROT_READ | libc::PROT_EXEC, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1i64, 0); }
            "mmap_file_private" => { libc::syscall(libc::SYS_mmap, 0, 4096, libc::PROT_READ, libc::MAP_PRIVATE, fd as i64, 0); }
            "mmap_file_shared_rw" => { libc::syscall(libc::SYS_mmap, 0, 4096, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED, fd as i64, 0); }
            "clock_other_process" => {
                // CPU clock of the parent: clockid = (~pid << 3) | 2 (CPUCLOCK_SCHED, process-wide)
                let id: i32 = ((!ppid) << 3) | 2;
                let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
                libc::syscall(libc::SYS_clock_gettime, id, &mut ts as *mut libc::timespec);
            }
            "write_fd3" => { libc::syscall(libc::SYS_write, 3, b"x".as_ptr(), 1); }
            "read_fd1" => { let mut b = [0u8; 1]; libc::syscall(libc::SYS_read, 1, b.as_mut_ptr(), 1); }
            "close" => { libc::syscall(libc::SYS_close, 2); }
            "unlink" => { libc::syscall(libc::SYS_unlink, b"/tmp/nerd-chat-sandbox-nonexistent\0".as_ptr()); }
            "fork" => { libc::syscall(libc::SYS_fork); }
            "ptrace" => { libc::syscall(libc::SYS_ptrace, 2 /* PTRACE_PEEKDATA */, 1, 0, 0); } // returns EPERM/ESRCH if it were allowed (TRACEME would hang the run)
            "prctl" => { libc::syscall(libc::SYS_prctl, libc::PR_SET_DUMPABLE, 1, 0, 0, 0); }
            "seccomp_again" => { libc::syscall(libc::SYS_seccomp, 0, 0, 0); }
            // 32-bit compat entry. eax = 11 is i386 `execve` but x86_64 `munmap` (an ALLOWED number): only the architecture check kills this
            "int80" => { std::arch::asm!("mov eax, 11", "int 0x80", out("eax") _); }
            other => panic!("unknown case {other}"),
        }
    }
    // reaching this line means the forbidden syscall RETURNED: the filter failed
    std::process::exit(77);
}

struct Outcome { status: std::process::ExitStatus, stdout: String }

fn run_case(case: &str) -> Outcome {
    let mut c = Command::new(std::env::current_exe().unwrap()).args(["--exact", "child_dispatch", "--nocapture", "--test-threads=1"])
        .env("NERD_CHAT_SANDBOX_CASE", case).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
    let mut out = c.stdout.take().unwrap();
    let reader = std::thread::spawn(move || { let mut s = String::new(); let _ = out.read_to_string(&mut s); s });
    let end = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(s) = c.try_wait().unwrap() { break s; }
        if Instant::now() > end {
            let _ = c.kill();
            for _ in 0..500 { if c.try_wait().unwrap().is_some() { break; } std::thread::sleep(Duration::from_millis(10)); } // bounded: a traced zombie can be unreapable
            panic!("case {case}: the child HUNG (a filter that kills only a thread?)");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let stdout = reader.join().unwrap();
    assert!(stdout.contains(&format!("CHILD-RAN:{case}")), "case {case} never ran in the child: {stdout}");
    Outcome { status, stdout }
}

#[test]
fn allowed_calls_work() {
    let o = run_case("allowed");
    assert!(o.status.success(), "{:?}", o.status);
    assert!(o.stdout.contains("sandbox-ok"));
}

#[test]
fn forbidden_calls_kill_the_process_with_sigsys() {
    for case in ["open", "socket", "execve", "kill_parent", "mprotect", "mmap_exec", "mmap_file_private", "mmap_file_shared_rw", "clock_other_process",
                 "write_fd3", "read_fd1", "close", "unlink", "fork", "ptrace", "prctl", "seccomp_again", "int80"] {
        let o = run_case(case);
        assert_eq!(o.status.signal(), Some(SIGSYS), "case {case}: expected SIGSYS, got {:?} (code 77 = the call returned!)", o.status);
    }
}

#[test]
fn installing_without_no_new_privs_fails_closed() {
    // a runner that already has no_new_privs (systemd NoNewPrivileges, bwrap, some CI) is inherited by the child: nothing to test
    if std::fs::read_to_string("/proc/self/status").unwrap().lines().any(|l| l.starts_with("NoNewPrivs:") && l.ends_with('1')) {
        eprintln!("skipped: this process already has no_new_privs");
        return;
    }
    let o = run_case("no_nnp");
    assert!(o.status.success() && o.stdout.contains("NNP-RESULT:Err(Kernel(13))"), "{:?} {}", o.status, o.stdout);
}
