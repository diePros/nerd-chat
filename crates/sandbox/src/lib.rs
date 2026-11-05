//! A seccomp-BPF allowlist for the file-cleaning helper process. This is the ONLY crate of the project that contains `unsafe`
//! code, and it contains exactly ONE `unsafe` block: the `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)` call in `install`.
//! Everything else (building the filter) is safe code that is checked by an in-test BPF interpreter against every syscall number.
//!
//! The filter KILLS THE PROCESS (SECCOMP_RET_KILL_PROCESS) on any syscall that is not on the list, on a foreign architecture and
//! on the x32 ABI. Allowed (x86_64 only): `read` on fd 0, `write` on fd 1 and 2, `mmap` without PROT_EXEC, `munmap`, `mremap`,
//! `madvise`, `brk`, `sigaltstack` (Rust's runtime teardown), `clock_gettime`, `getrandom`, `exit_group`. Nothing else: no
//! `open*`, `socket`, `connect`, `execve`, `unlink*`, `rename*`, `kill`, `ptrace`, `mprotect`, `close`, `fcntl`, `clone`...
//!
//! The caller must have set `no_new_privs` (seccomp refuses to install without it, and we never set it here so that this file
//! needs no second unsafe call). The filter applies to the calling THREAD only: call it in a single-threaded process.
#![deny(unsafe_code)]

use libc::sock_filter as Insn;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Not Linux/x86_64: there is no filter for this platform (we never run unprotected silently).
    Unsupported,
    /// The kernel refused (no seccomp, `no_new_privs` missing, ...): the errno.
    Kernel(i32),
}

// classic BPF opcodes (linux/filter.h, linux/bpf_common.h)
const LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
const JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
const JSET_K: u16 = 0x45; // BPF_JMP | BPF_JSET | BPF_K
const RET_K: u16 = 0x06; // BPF_RET | BPF_K

const RET_ALLOW: u32 = 0x7fff_0000; // SECCOMP_RET_ALLOW
const RET_KILL: u32 = 0x8000_0000; // SECCOMP_RET_KILL_PROCESS
// struct seccomp_data { int nr; __u32 arch; __u64 ip; __u64 args[6]; }  (little endian: low word at the lower offset)
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
const fn off_arg_lo(i: u32) -> u32 { 16 + 8 * i }
const fn off_arg_hi(i: u32) -> u32 { 20 + 8 * i }
const PROT_EXEC: u32 = 4;

fn ld(k: u32) -> Insn { Insn { code: LD_W_ABS, jt: 0, jf: 0, k } }
fn jeq(k: u32, jt: u8, jf: u8) -> Insn { Insn { code: JEQ_K, jt, jf, k } }
fn jset(k: u32, jt: u8, jf: u8) -> Insn { Insn { code: JSET_K, jt, jf, k } }
fn ret(k: u32) -> Insn { Insn { code: RET_K, jt: 0, jf: 0, k } }

/// Syscalls allowed without any argument check.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn plain() -> Vec<u32> {
    use libc::*;
    [SYS_munmap, SYS_mremap, SYS_madvise, SYS_brk, SYS_sigaltstack, SYS_clock_gettime, SYS_getrandom, SYS_exit_group].iter().map(|&n| n as u32).collect()
}
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn plain() -> Vec<u32> { Vec::new() }

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const ARCH: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
const ARCH: u32 = 0;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SYS_READ: u32 = libc::SYS_read as u32;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SYS_WRITE: u32 = libc::SYS_write as u32;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SYS_MMAP: u32 = libc::SYS_mmap as u32;
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
const SYS_READ: u32 = 0;
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
const SYS_WRITE: u32 = 0;
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
const SYS_MMAP: u32 = 0;

/// Layout (every jump goes FORWARD to the final ALLOW or past a block):
/// `[arch check] [load nr] [plain rules] [read rule] [write rule] [mmap rule] KILL ALLOW`.
/// A block that loads an argument ends in its own `KILL`/`ALLOW`, so the accumulator (which then no longer holds the syscall
/// number) is never compared against a later rule: a block is either skipped entirely (nr did not match) or decides.
pub fn filter() -> Vec<Insn> {
    let mut p: Vec<Insn> = Vec::new();
    // arch: anything but the native one (32-bit compat, x32 and foreign numbering) dies
    p.push(ld(OFF_ARCH));
    p.push(jeq(ARCH, 1, 0)); // equal: skip the next instruction
    p.push(ret(RET_KILL));
    p.push(ld(OFF_NR));
    // instructions whose TRUE branch must reach the final ALLOW; patched below
    let mut to_allow: Vec<usize> = Vec::new();
    for n in plain() { to_allow.push(p.len()); p.push(jeq(n, 0, 0)); }
    // read(fd 0) and write(fd 1 or 2): the 64-bit first argument must be exactly the fd (high word 0 AND low word listed)
    for (nr, fds) in [(SYS_READ, &[0u32][..]), (SYS_WRITE, &[1u32, 2][..])] {
        let m = fds.len();
        let mut b: Vec<Insn> = Vec::with_capacity(4 + m);
        b.push(ld(off_arg_hi(0)));                 // 0
        b.push(jeq(0, 0, (m + 1) as u8));          // 1: high word == 0 ? continue : jump to the block's final KILL (index m + 3)
        b.push(ld(off_arg_lo(0)));                 // 2
        let first_fd = b.len();                    // 3 .. 3+m-1: fd == X ? ALLOW : next
        for &fd in fds { b.push(jeq(fd, 0, 0)); }
        b.push(ret(RET_KILL));                     // m + 3
        debug_assert_eq!(b.len(), m + 4);
        p.push(jeq(nr, 0, b.len() as u8));         // not this syscall: skip the whole block
        let base = p.len();
        for k in 0..m { to_allow.push(base + first_fd + k); }
        p.extend(b);
    }
    // mmap: allowed unless PROT_EXEC is requested (arg 2 = prot, low word: the kernel reads an int)
    {
        let b: Vec<Insn> = vec![ld(off_arg_lo(2)), jset(PROT_EXEC, 1, 0), ret(RET_ALLOW), ret(RET_KILL)];
        p.push(jeq(SYS_MMAP, 0, b.len() as u8));
        p.extend(b);
    }
    // the default for everything else, then the single ALLOW that all positive jumps share
    p.push(ret(RET_KILL));
    let allow = p.len();
    p.push(ret(RET_ALLOW));
    for i in to_allow { let d = allow - i - 1; assert!(d <= 255, "jump too far"); p[i].jt = d as u8; }
    assert!(p.len() <= 255, "program too long for u8 jumps");
    p
}

/// Install the filter on the calling thread. Irreversible. `no_new_privs` must already be set.
pub fn enter() -> Result<(), Error> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    { install(&filter()) }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    { Err(Error::Unsupported) }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(unsafe_code)]
fn install(prog: &[Insn]) -> Result<(), Error> {
    assert!(!prog.is_empty() && prog.len() <= 4096, "BPF program length is out of range");
    let fprog = libc::sock_fprog { len: prog.len() as u16, filter: prog.as_ptr() as *mut Insn };
    // SAFETY: `fprog` points to `prog.len()` valid, initialised instructions that outlive this call (the kernel copies the
    // program during the call and keeps no pointer); all other arguments are plain integers as documented for PR_SET_SECCOMP.
    let r = unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER as libc::c_ulong, &fprog as *const libc::sock_fprog as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong) };
    if r == 0 { Ok(()) } else { Err(Error::Kernel(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))) }
}
