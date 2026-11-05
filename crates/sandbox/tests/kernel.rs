//! The filter against the REAL kernel. Each case re-executes this test binary as a child that installs the filter and then
//! performs one syscall; the parent checks that forbidden calls kill the child with SIGSYS and allowed ones work.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(unsafe_code)] // raw syscalls are the point of this test

use std::{os::unix::process::ExitStatusExt, process::Command};

const SIGSYS: i32 = 31;

fn nnp() { assert_eq!(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) }, 0); }

/// Runs inside the child process only.
#[test]
fn child_dispatch() {
    let Ok(case) = std::env::var("SEBURITY_SANDBOX_CASE") else { return };
    if case == "no_nnp" {
        // without no_new_privs the kernel must refuse (EACCES) and we must report it, never run unprotected
        let ok = seburity_sandbox::enter() == Err(seburity_sandbox::Error::Kernel(libc::EACCES));
        unsafe { libc::syscall(libc::SYS_exit_group, if ok { 0 } else { 1 }) };
    }
    nnp();
    seburity_sandbox::enter().expect("install");
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
                let mut buf = [0u8; 4];
                libc::syscall(libc::SYS_read, 0, buf.as_mut_ptr(), buf.len()); // stdin is /dev/null in the test: returns 0
                libc::syscall(libc::SYS_exit_group, 0);
            }
            "open" => { libc::syscall(libc::SYS_openat, libc::AT_FDCWD, b"/etc/hostname\0".as_ptr(), libc::O_RDONLY); }
            "socket" => { libc::syscall(libc::SYS_socket, libc::AF_INET, libc::SOCK_STREAM, 0); }
            "execve" => { let argv = [z, z]; libc::syscall(libc::SYS_execve, b"/bin/true\0".as_ptr(), argv.as_ptr(), argv.as_ptr()); }
            "kill_parent" => { libc::syscall(libc::SYS_kill, libc::getppid(), 0); }
            "mprotect" => { libc::syscall(libc::SYS_mprotect, 0, 0, 0); }
            "mmap_exec" => { libc::syscall(libc::SYS_mmap, 0, 4096, libc::PROT_READ | libc::PROT_EXEC, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1i64, 0); }
            "write_fd3" => { libc::syscall(libc::SYS_write, 3, b"x".as_ptr(), 1); }
            "read_fd1" => { let mut b = [0u8; 1]; libc::syscall(libc::SYS_read, 1, b.as_mut_ptr(), 1); }
            "close" => { libc::syscall(libc::SYS_close, 2); }
            "unlink" => { libc::syscall(libc::SYS_unlink, b"/tmp/seburity-sandbox-nonexistent\0".as_ptr()); }
            "fork" => { libc::syscall(libc::SYS_fork); }
            "ptrace" => { libc::syscall(libc::SYS_ptrace, 0, 0, 0, 0); }
            "prctl" => { libc::syscall(libc::SYS_prctl, libc::PR_SET_DUMPABLE, 1, 0, 0, 0); }
            "seccomp_again" => { libc::syscall(libc::SYS_seccomp, 0, 0, 0); }
            "int80" => { std::arch::asm!("mov eax, 1", "int 0x80", out("eax") _); } // 32-bit compat entry: wrong arch
            other => panic!("unknown case {other}"),
        }
    }
    // reaching this line means the forbidden syscall RETURNED: the filter failed
    std::process::exit(77);
}

fn run_case(case: &str) -> std::process::ExitStatus {
    Command::new(std::env::current_exe().unwrap()).args(["--exact", "child_dispatch", "--nocapture", "--test-threads=1"])
        .env("SEBURITY_SANDBOX_CASE", case).stdin(std::process::Stdio::null()).output().map(|o| { if case == "allowed" { assert!(String::from_utf8_lossy(&o.stdout).contains("sandbox-ok")); } o.status }).unwrap()
}

#[test]
fn allowed_calls_work() { assert!(run_case("allowed").success()); }

#[test]
fn forbidden_calls_kill_the_process_with_sigsys() {
    for case in ["open", "socket", "execve", "kill_parent", "mprotect", "mmap_exec", "write_fd3", "read_fd1", "close", "unlink", "fork", "ptrace", "prctl", "seccomp_again", "int80"] {
        let st = run_case(case);
        assert_eq!(st.signal(), Some(SIGSYS), "case {case}: expected SIGSYS, got {st:?} (code 77 = the call returned!)");
    }
}

#[test]
fn installing_without_no_new_privs_fails_closed() { assert!(run_case("no_nnp").success()); }
