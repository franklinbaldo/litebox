// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host-level seccomp sandbox for litebox components.
//!
//! This module provides an allowlist-based seccomp-BPF filter that restricts
//! the host syscalls available to the forker and forker-spawned workers.  The
//! goal is to minimise the kernel attack surface: if guest code escapes the
//! virtual syscall layer, it still cannot call dangerous syscalls like
//! `execve`, `socket`, `connect`, `openat`, etc.
//!
//! # Filter design
//!
//! The forker installs a tight filter before entering its recv loop.  Workers
//! inherit it across `fork()`.  The runner does NOT install a filter because
//! its filter would be inherited by exec worker children (spawned via
//! posix_spawn), which need many init-time syscalls (socket, connect,
//! ftruncate, sendmsg for SCM_RIGHTS, etc).
//!
//! # Key syscalls BLOCKED (the security wins for forker-spawned workers)
//!
//! - `execve` / `execveat` — no process replacement
//! - `socket` / `connect` / `bind` / `listen` / `accept` — no new network connections
//! - `openat` / `open` (for worker; runner needs open for CoW) — no file access
//! - `ptrace` — no debugging/tracing other processes
//! - `mount` / `umount` / `pivot_root` / `chroot` — no namespace escapes
//! - `init_module` / `finit_module` / `delete_module` — no kernel module loading
//! - `reboot` / `kexec_load` — no system control
//! - `keyctl` / `request_key` — no kernel keyring access

/// Install the seccomp sandbox filter for the **forker** process.
///
/// This filter is inherited by workers via `fork()`. It does NOT allow
/// `execve` or `execveat`, which is the main security win for forker-spawned
/// workers.
pub fn install_forker_sandbox_filter() {
    let prog = build_allowlist_filter();
    apply_bpf_filter(&prog);
}

// ---------------------------------------------------------------------------
// BPF filter construction
// ---------------------------------------------------------------------------

// BPF instruction encoding (struct sock_filter)
#[repr(C)]
#[derive(Clone, Copy)]
struct BpfInsn {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

// BPF program header (struct sock_fprog)
#[repr(C)]
struct BpfProg {
    len: u16,
    filter: *const BpfInsn,
}

// BPF opcodes
const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;

// seccomp data offsets (struct seccomp_data)
const SECCOMP_DATA_NR: u32 = 0; // offsetof(struct seccomp_data, nr)
const SECCOMP_DATA_ARCH: u32 = 4; // offsetof(struct seccomp_data, arch)

// Architecture audit values
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

// seccomp return values
const SECCOMP_RET_ALLOW: u32 = 0x7FFF_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
// const SECCOMP_RET_LOG: u32 = 0x7FFC_0000; // useful for debugging

// seccomp operation for the seccomp() syscall
const SECCOMP_SET_MODE_FILTER: u32 = 1;

fn bpf_stmt(code: u16, k: u32) -> BpfInsn {
    BpfInsn {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> BpfInsn {
    BpfInsn { code, jt, jf, k }
}

/// Build the allowlist BPF filter program.
fn build_allowlist_filter() -> Vec<BpfInsn> {
    // Strace-minimal allowlist for forker + forker-spawned workers.
    //
    // This filter is installed by the forker before its recv loop and
    // inherited by workers via fork().  Every syscall here was observed
    // via `strace -f` on the forker process tree during the
    // test_context_switch integration test (the only test that exercises
    // the delayed-fork → forker-spawn → worker path).
    //
    // Methodology: absolute strace-minimal.  If strace didn't observe it
    // in the forker tree, it isn't here.  Exceptions: prctl + seccomp
    // which are needed to install this very filter (disabled during the
    // strace run).
    let mut allowed: Vec<u32> = vec![
        // ── Basic I/O ──────────────────────────────────────────────
        libc::SYS_read as u32,  //  0  [F][W] pipe I/O, host fd reads
        libc::SYS_write as u32, //  1  [F][W] pipe I/O, host fd writes, debug
        libc::SYS_close as u32, //  3  [F][W] fd cleanup
        libc::SYS_lseek as u32, //  8  [WI]   memfd rewind after snapshot write
        // ── Memory management ──────────────────────────────────────
        libc::SYS_mmap as u32, //  9  [W]  guest memory, CoW mapping, thread stacks
        libc::SYS_mprotect as u32, // 10  [W]  guest page permission changes
        libc::SYS_munmap as u32, // 11  [W]  guest memory deallocation
        libc::SYS_brk as u32,  // 12  [RT] glibc malloc fallback
        libc::SYS_madvise as u32, // 28  [RT] Rust std thread stack advice
        // ── Signals ────────────────────────────────────────────────
        libc::SYS_rt_sigaction as u32, // 13  [W]  signal handler management
        libc::SYS_rt_sigprocmask as u32, // 14  [W]  signal mask management
        libc::SYS_sigaltstack as u32,  // 131 [W]  alternate signal stack setup
        // ── Synchronization ────────────────────────────────────────
        libc::SYS_futex as u32, // 202 [W]  core sync primitive (mutex/condvar)
        // ── Fd management ──────────────────────────────────────────
        libc::SYS_dup2 as u32,  // 33  [WI] stdio wiring in worker_entry
        libc::SYS_fcntl as u32, // 72  [W]  F_DUPFD_CLOEXEC, F_SETFD, F_SETFL
        libc::SYS_pipe2 as u32, // 293 [F]  forker pid-pipe creation
        // ── Forker recv loop ───────────────────────────────────────
        libc::SYS_sendmsg as u32, // 46  [F]  send spawn responses via SCM_RIGHTS
        libc::SYS_recvmsg as u32, // 47  [F]  receive spawn requests via SCM_RIGHTS
        libc::SYS_clone as u32,   // 56  [F]  forker double-fork
        libc::SYS_wait4 as u32,   // 61  [F]  reap intermediate child
        // ── Time ───────────────────────────────────────────────────
        libc::SYS_clock_nanosleep as u32, // 230 [W] mux dispatcher anti-spin (std::thread::sleep)
        // ── Thread / process lifecycle ─────────────────────────────
        libc::SYS_clone3 as u32, // 435 [W]   Rust std::thread::spawn (worker threads)
        libc::SYS_exit as u32,   // 60  [W]   thread exit
        libc::SYS_exit_group as u32, // 231 [F][W] process exit
        // ── Thread init (glibc/Rust runtime) ───────────────────────
        libc::SYS_set_robust_list as u32, // 273 [RT] glibc thread init
        libc::SYS_rseq as u32,            // 334 [RT] glibc restartable sequences
        libc::SYS_sched_getaffinity as u32, // 204 [RT] Rust std thread pool sizing
        // ── Seccomp self-install (not observed in strace because
        //    the filter was disabled during tracing, but mandatory) ──
        libc::SYS_prctl as u32,   // 157 [F] PR_SET_NO_NEW_PRIVS
        libc::SYS_seccomp as u32, // 317 [F] install the filter itself
        // ── System info ────────────────────────────────────────────
        libc::SYS_getpid as u32,    // 39  [RT] glibc getpid() cache
        libc::SYS_gettid as u32,    // 186 [W]  thread ID for tgkill / signal delivery
        libc::SYS_getrandom as u32, // 318 [W]  entropy (Rust HashMap seed)
        // ── Worker init ────────────────────────────────────────────
        libc::SYS_statx as u32, // 332 [WI] Rust std file metadata
    ];

    // Sort and deduplicate for efficient comparison
    allowed.sort_unstable();
    allowed.dedup();

    // Build the BPF program.
    // Structure:
    //   1. Validate architecture (x86_64)
    //   2. Load syscall number
    //   3. Linear scan through allowed list (for simplicity; ~60 insns is fine)
    //   4. KILL if not found, ALLOW if found

    let num_allowed = allowed.len();
    let mut insns: Vec<BpfInsn> = Vec::with_capacity(4 + num_allowed + 2);

    // [0] Load architecture
    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH));
    // [1] Check x86_64 — if not, kill
    insns.push(bpf_jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        AUDIT_ARCH_X86_64,
        1, // jt: skip next insn (proceed to load nr)
        0, // jf: fall through to kill
    ));
    // [2] Kill (wrong arch)
    insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    // [3] Load syscall number
    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR));

    // [4..4+N-1] Check each allowed syscall
    // For each: if nr == allowed[i], jump to ALLOW (at end)
    for (i, &nr) in allowed.iter().enumerate() {
        let remaining = num_allowed - i - 1; // comparisons left after this one
        let allow_offset = remaining + 1; // +1 for the KILL insn at the end
        insns.push(bpf_jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            nr,
            allow_offset as u8, // jt: jump to ALLOW
            0,                  // jf: continue checking
        ));
    }

    // [4+N] Default: KILL
    insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    // [4+N+1] ALLOW
    insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    insns
}

/// Apply a BPF seccomp filter to the current process.
fn apply_bpf_filter(insns: &[BpfInsn]) {
    // First, set PR_SET_NO_NEW_PRIVS (required for unprivileged seccomp).
    // SAFETY: prctl with PR_SET_NO_NEW_PRIVS is always safe.
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    assert!(
        ret == 0,
        "prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
        std::io::Error::last_os_error()
    );

    let prog = BpfProg {
        len: insns.len() as u16,
        filter: insns.as_ptr(),
    };

    // SAFETY: prog points to a valid BPF program, insns is alive for the duration
    // of this call. SECCOMP_SET_MODE_FILTER installs the filter atomically.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER as u64,
            0u64, // flags
            &raw const prog as *const libc::c_void,
        )
    };
    assert!(
        ret == 0,
        "seccomp(SECCOMP_SET_MODE_FILTER) failed: {}",
        std::io::Error::last_os_error()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forker_filter_builds_without_panic() {
        let insns = build_allowlist_filter();
        // Arch check (3 insns) + load nr (1) + one per allowed syscall + kill + allow
        assert!(insns.len() > 10, "filter too short: {} insns", insns.len());
        // BPF programs have a max of 4096 instructions
        assert!(
            insns.len() <= 4096,
            "filter too long: {} insns",
            insns.len()
        );
    }

    /// Helper: extract syscall numbers from the BPF JEQ comparisons in a filter.
    fn extract_allowed_syscalls(insns: &[BpfInsn]) -> Vec<u32> {
        insns
            .iter()
            .filter(|i| i.code == (BPF_JMP | BPF_JEQ | BPF_K))
            .map(|i| i.k)
            .collect()
    }

    /// Syscalls that must NEVER appear in any filter variant (namespace escapes,
    /// kernel module loading, system control).
    fn assert_dangerous_syscalls_blocked(syscall_nrs: &[u32]) {
        let dangerous = [
            (libc::SYS_execve as u32, "execve"),
            (libc::SYS_execveat as u32, "execveat"),
            (libc::SYS_socket as u32, "socket"),
            (libc::SYS_connect as u32, "connect"),
            (libc::SYS_bind as u32, "bind"),
            (libc::SYS_listen as u32, "listen"),
            (libc::SYS_accept as u32, "accept"),
            (libc::SYS_openat as u32, "openat"),
            (libc::SYS_ptrace as u32, "ptrace"),
            (libc::SYS_mount as u32, "mount"),
            (libc::SYS_umount2 as u32, "umount2"),
            (libc::SYS_pivot_root as u32, "pivot_root"),
            (libc::SYS_chroot as u32, "chroot"),
            (libc::SYS_init_module as u32, "init_module"),
            (libc::SYS_finit_module as u32, "finit_module"),
            (libc::SYS_delete_module as u32, "delete_module"),
            (libc::SYS_reboot as u32, "reboot"),
            (libc::SYS_kexec_load as u32, "kexec_load"),
            (libc::SYS_keyctl as u32, "keyctl"),
            (libc::SYS_request_key as u32, "request_key"),
        ];
        for (nr, name) in &dangerous {
            assert!(
                !syscall_nrs.contains(nr),
                "{} (nr {}) must not be in allowlist",
                name,
                nr
            );
        }
    }

    #[test]
    fn forker_filter_blocks_dangerous_syscalls() {
        let insns = build_allowlist_filter();
        let syscall_nrs = extract_allowed_syscalls(&insns);

        // Must have these for the forker
        assert!(syscall_nrs.contains(&(libc::SYS_recvmsg as u32)));
        assert!(syscall_nrs.contains(&(libc::SYS_sendmsg as u32)));
        assert!(syscall_nrs.contains(&(libc::SYS_clone as u32)));
        assert!(syscall_nrs.contains(&(libc::SYS_pipe2 as u32)));
        assert!(syscall_nrs.contains(&(libc::SYS_wait4 as u32)));

        // Must have these for workers
        assert!(syscall_nrs.contains(&(libc::SYS_mmap as u32)));
        assert!(syscall_nrs.contains(&(libc::SYS_futex as u32)));
        assert!(syscall_nrs.contains(&(libc::SYS_read as u32)));
        assert!(syscall_nrs.contains(&(libc::SYS_write as u32)));
        assert!(syscall_nrs.contains(&(libc::SYS_exit_group as u32)));

        // All dangerous syscalls must be blocked
        assert_dangerous_syscalls_blocked(&syscall_nrs);
    }

    #[test]
    fn forker_filter_size_guard() {
        // Guard against allowlist bloat. If you need to raise this,
        // add a comment justifying the new syscall with [F], [W], [WI], or [RT].
        let insns = build_allowlist_filter();
        let count = extract_allowed_syscalls(&insns).len();
        assert!(
            count <= 35,
            "forker allowlist has {count} syscalls — expected <= 35. \
             Justify any additions with [F]/[W]/[WI]/[RT] tags."
        );
    }
}
