//! The filter program is checked WITHOUT a kernel: a tiny classic-BPF interpreter runs it against every syscall number, foreign
//! architectures, argument edge cases and 200k pseudo-random inputs, and the result is compared with an independently written
//! specification of what is allowed.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
use sine_loco_sandbox::filter;

const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
const ALLOW: u32 = 0x7fff_0000;
const KILL: u32 = 0x8000_0000;

/// struct seccomp_data: nr(i32) arch(u32) ip(u64) args[6](u64), little endian, 64 bytes
fn data(nr: u32, arch: u32, args: [u64; 6]) -> [u8; 64] {
    let mut d = [0u8; 64];
    d[0..4].copy_from_slice(&nr.to_le_bytes());
    d[4..8].copy_from_slice(&arch.to_le_bytes());
    for (i, a) in args.iter().enumerate() { d[16 + 8 * i..24 + 8 * i].copy_from_slice(&a.to_le_bytes()); }
    d
}

/// Classic BPF subset used by the filter: LD W ABS, JEQ K, JSET K, JGE K, RET K. Anything else, an out-of-range load or a jump outside
/// the program is a test failure (the kernel would reject such a program).
fn run(prog: &[libc::sock_filter], d: &[u8; 64]) -> u32 {
    let (mut a, mut pc) = (0u32, 0usize);
    for _ in 0..10_000 {
        let i = prog.get(pc).unwrap_or_else(|| panic!("fell off the program at {pc}"));
        pc += 1;
        match i.code {
            0x20 => { let k = i.k as usize; assert!(k.is_multiple_of(4) && k + 4 <= 64, "bad load offset {k}"); a = u32::from_le_bytes(d[k..k + 4].try_into().unwrap()); }
            0x15 => pc += if a == i.k { i.jt } else { i.jf } as usize,
            0x45 => pc += if a & i.k != 0 { i.jt } else { i.jf } as usize,
            0x35 => pc += if a >= i.k { i.jt } else { i.jf } as usize,
            0x06 => return i.k,
            c => panic!("unexpected opcode {c:#x}"),
        }
    }
    panic!("program did not terminate");
}

/// What must be allowed, written down independently of the implementation.
fn spec(nr: u32, arch: u32, args: [u64; 6]) -> u32 {
    if arch != AUDIT_ARCH_X86_64 { return KILL; }
    let plain = [libc::SYS_munmap, libc::SYS_mremap, libc::SYS_madvise, libc::SYS_brk, libc::SYS_sigaltstack, libc::SYS_getrandom, libc::SYS_exit_group];
    let ok = if plain.iter().any(|&n| n as u32 == nr) { true }
        else if nr == libc::SYS_read as u32 { args[0] == 0 }
        else if nr == libc::SYS_write as u32 { args[0] == 1 || args[0] == 2 }
        else if nr == libc::SYS_clock_gettime as u32 { args[0] < 16 } // high word must be 0 and the id 0..=15
        else if nr == libc::SYS_mmap as u32 { (args[3] as u32) & 0x20 != 0 && (args[2] as u32) & 4 == 0 } // anonymous, never exec
        else { false };
    if ok { ALLOW } else { KILL }
}

#[test]
fn structure_is_sane() {
    let p = filter();
    assert!(p.len() < 100 && p.len() >= 10, "{}", p.len());
    assert_eq!((p[p.len() - 1].code, p[p.len() - 1].k), (0x06, ALLOW));
    assert_eq!((p[p.len() - 2].code, p[p.len() - 2].k), (0x06, KILL));
    // every conditional jump stays inside the program
    for (i, ins) in p.iter().enumerate() {
        if ins.code == 0x15 || ins.code == 0x45 || ins.code == 0x35 { assert!(i + 1 + (ins.jt.max(ins.jf) as usize) < p.len(), "jump out of range at {i}"); }
    }
}

#[test]
fn every_syscall_number_matches_the_specification() {
    let p = filter();
    for nr in 0..2048u32 {
        for nr in [nr, nr | 0x4000_0000, nr | 0x8000_0000] { // x32 flag and garbage high bits
            for args in [[0; 6], [1, 0, 0, 0, 0, 0], [2, 0, 0, 0, 0, 0], [3, 0, 0, 0, 0, 0], [0, 0, 4, 0, 0, 0], [0, 0, 7, 0, 0, 0], [0, 0, 3, 0x22, 0, 0], [0, 0, 5, 0x22, 0, 0], [0, 0, 3, 0x02, 0, 0], [15, 0, 0, 0, 0, 0], [16, 0, 0, 0, 0, 0], [u64::MAX; 6]] {
                assert_eq!(run(&p, &data(nr, AUDIT_ARCH_X86_64, args)), spec(nr, AUDIT_ARCH_X86_64, args), "nr {nr:#x} args {args:?}");
            }
        }
    }
}

#[test]
fn the_exact_allowed_set_is_what_we_think() {
    let p = filter();
    let allowed: Vec<u32> = (0..2048u32).filter(|&nr| run(&p, &data(nr, AUDIT_ARCH_X86_64, [0; 6])) == ALLOW).collect();
    let mut want: Vec<u32> = [libc::SYS_read, libc::SYS_munmap, libc::SYS_mremap, libc::SYS_madvise, libc::SYS_brk, libc::SYS_sigaltstack, libc::SYS_clock_gettime, libc::SYS_getrandom, libc::SYS_exit_group].iter().map(|&n| n as u32).collect();
    want.sort();
    assert_eq!(allowed, want, "with args all zero: read(0), clock_gettime(0) and the plain list, and NOTHING else (write needs fd 1/2, mmap needs MAP_ANONYMOUS)");
    // none of the dangerous calls is allowed whatever the arguments
    for nr in [libc::SYS_open, libc::SYS_openat, libc::SYS_openat2, libc::SYS_socket, libc::SYS_connect, libc::SYS_bind, libc::SYS_execve, libc::SYS_execveat, libc::SYS_unlink, libc::SYS_unlinkat,
               libc::SYS_rename, libc::SYS_renameat, libc::SYS_renameat2, libc::SYS_kill, libc::SYS_tkill, libc::SYS_tgkill, libc::SYS_ptrace, libc::SYS_mprotect, libc::SYS_close, libc::SYS_fcntl,
               libc::SYS_clone, libc::SYS_clone3, libc::SYS_fork, libc::SYS_vfork, libc::SYS_dup, libc::SYS_dup2, libc::SYS_dup3, libc::SYS_pipe, libc::SYS_prctl, libc::SYS_seccomp, libc::SYS_setsid,
               libc::SYS_prlimit64, libc::SYS_setrlimit, libc::SYS_ioctl, libc::SYS_mount, libc::SYS_chdir, libc::SYS_chmod, libc::SYS_ftruncate, libc::SYS_sendfile, libc::SYS_process_vm_readv,
               libc::SYS_pidfd_open, libc::SYS_memfd_create, libc::SYS_io_uring_setup, libc::SYS_bpf, libc::SYS_userfaultfd, libc::SYS_socketpair, libc::SYS_sendto, libc::SYS_recvfrom,
               libc::SYS_readv, libc::SYS_writev, libc::SYS_pread64, libc::SYS_pwrite64, libc::SYS_preadv, libc::SYS_pwritev, libc::SYS_splice, libc::SYS_exit] {
        for args in [[0; 6], [1, 1, 1, 1, 1, 1], [u64::MAX; 6], [0, 0, 7, 0, 0, 0]] {
            assert_eq!(run(&p, &data(nr as u32, AUDIT_ARCH_X86_64, args)), KILL, "syscall {nr} must always be killed");
        }
    }
}

#[test]
fn foreign_architectures_always_die() {
    let p = filter();
    for arch in [0u32, 0x4000_0003 /* i386 */, 0xC000_00B7 /* aarch64 */, 0x4000_003E /* x86_64 without the 64-bit flag */, 0xC000_003F, u32::MAX] {
        for nr in 0..600u32 { assert_eq!(run(&p, &data(nr, arch, [0; 6])), KILL, "arch {arch:#x} nr {nr}"); }
        assert_eq!(run(&p, &data(libc::SYS_exit_group as u32, arch, [0; 6])), KILL);
    }
}

#[test]
fn fd_arguments_are_compared_exactly_including_the_high_word() {
    let p = filter();
    let r = |nr: i64, fd: u64| run(&p, &data(nr as u32, AUDIT_ARCH_X86_64, [fd, 0, 0, 0, 0, 0]));
    for (fd, rd, wr) in [(0u64, ALLOW, KILL), (1, KILL, ALLOW), (2, KILL, ALLOW), (3, KILL, KILL), (4, KILL, KILL), (255, KILL, KILL), (u32::MAX as u64, KILL, KILL),
                         (1 << 32, KILL, KILL), ((1 << 32) | 1, KILL, KILL), ((1 << 32) | 2, KILL, KILL), (u64::MAX, KILL, KILL), (0x8000_0000_0000_0000, KILL, KILL)] {
        assert_eq!(r(libc::SYS_read, fd), rd, "read fd {fd:#x}");
        assert_eq!(r(libc::SYS_write, fd), wr, "write fd {fd:#x}");
    }
}

#[test]
fn fd_high_words_that_look_like_allowed_values_are_still_killed() {
    // review 18 (L2): mutants that mis-jump after the high-word test only differ for high words that are non-zero AND hit a later
    // comparison (an allowed fd / nr); sweep a grid of those
    let p = filter();
    let nrs: Vec<u64> = [libc::SYS_read, libc::SYS_write, libc::SYS_mmap, libc::SYS_clock_gettime, libc::SYS_munmap, libc::SYS_exit_group].iter().map(|&n| n as u64).collect();
    let mut highs = vec![0u64, 1, 2, 3, 9, 0x20, 0xffff_ffff];
    highs.extend(nrs.iter().copied());
    for &nr in &[libc::SYS_read, libc::SYS_write, libc::SYS_clock_gettime] {
        for &hi in &highs {
            for lo in [0u64, 1, 2, 3, 5, 15, 16, 0x20] {
                let a0 = (hi << 32) | lo;
                // the other arguments matter too: a mis-jump that lands in the mmap or clock block is only visible when they look
                // like a legal mmap (flags with MAP_ANONYMOUS, prot without EXEC) or a legal clock call
                for (a2, a3) in [(0u64, 0u64), (3, 0x22), (0, 0x22), (4, 0x22), (3, 0x02)] {
                    let args = [a0, 0, a2, a3, 0, 0];
                    assert_eq!(run(&p, &data(nr as u32, AUDIT_ARCH_X86_64, args)), spec(nr as u32, AUDIT_ARCH_X86_64, args), "nr {nr} args {args:?}");
                }
            }
        }
    }
}

#[test]
fn mmap_is_anonymous_only_and_never_exec() {
    let p = filter();
    let m = |prot: u64, flags: u64, fd: u64| run(&p, &data(libc::SYS_mmap as u32, AUDIT_ARCH_X86_64, [0, 4096, prot, flags, fd, 0]));
    for prot in 0..64u64 {
        for flags in [0x02u64 /* MAP_PRIVATE, file-backed */, 0x01 /* MAP_SHARED, file-backed */, 0x22, 0x21, 0x32 /* + FIXED */, 0x20, 0x0, 0x10] {
            for fd in [u64::MAX, 0, 1, 5] {
                let want = if prot & 4 == 0 && flags & 0x20 != 0 { ALLOW } else { KILL };
                assert_eq!(m(prot, flags, fd), want, "prot {prot} flags {flags:#x} fd {fd}");
            }
        }
    }
}

#[test]
fn clock_gettime_accepts_only_static_clock_ids() {
    let p = filter();
    let c = |id: u64| run(&p, &data(libc::SYS_clock_gettime as u32, AUDIT_ARCH_X86_64, [id, 0, 0, 0, 0, 0]));
    for id in 0..16u64 { assert_eq!(c(id), ALLOW, "clock {id}"); }
    // 16.., negative ids (per-process / per-thread CPU clocks: another process' CPU time is a side channel), garbage high words
    for id in [16u64, 17, 255, 0x7fff_ffff, 0x8000_0000, u32::MAX as u64, (-1i32) as i64 as u64, ((!1i32) << 3 | 2) as i64 as u64, ((!1i32) << 3 | 2) as u32 as u64, 1 << 32, (1 << 32) | 1, u64::MAX] {
        assert_eq!(c(id), KILL, "clock id {id:#x}");
    }
}

#[test]
fn four_hundred_thousand_random_inputs_agree_with_the_specification() {
    let p = filter();
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
    for _ in 0..400_000 {
        let nr = match next() % 4 { 0 => (next() % 512) as u32, 1 => [0u32, 1, 9, 11, 12, 25, 28, 131, 228, 231, 318][(next() % 11) as usize] | if next() % 4 == 0 { 0x4000_0000 } else { 0 }, _ => next() as u32 };
        let arch = if next() % 8 == 0 { next() as u32 } else { AUDIT_ARCH_X86_64 };
        let mut args = [0u64; 6];
        for a in args.iter_mut() { *a = match next() % 5 { 0 => 0, 1 => next() % 4, 2 => next() % 16, 3 => next(), _ => (next() % 4) | (next() << 32) }; }
        assert_eq!(run(&p, &data(nr, arch, args)), spec(nr, arch, args), "nr {nr:#x} arch {arch:#x} args {args:?}");
    }
}
