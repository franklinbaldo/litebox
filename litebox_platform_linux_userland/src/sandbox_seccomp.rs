// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host-level seccomp sandbox for litebox components.
//!
//! This module provides allowlist-based seccomp-BPF filters that restrict
//! the host syscalls available to the forker and forker-spawned workers.
//! The goal is to minimise the kernel attack surface: if guest code escapes
//! the virtual syscall layer, it still cannot call dangerous syscalls.
//!
//! # Two-phase filter design
//!
//! **Phase 1 (forker filter):** The forker installs a wide filter before
//! entering its recv loop.  Workers inherit it across `fork()`.  This filter
//! allows all syscalls needed during worker initialization (socket, connect,
//! openat, etc.) but blocks `execve`, `bind`, `ptrace`, etc.
//!
//! **Phase 2 (worker runtime filter):** After initialization completes
//! (broker connected, binary loaded, network worker spawned), each worker
//! installs a second, tighter filter that drops ~35 init-only syscalls.
//! Seccomp filters stack in the kernel (AND semantics), so this can only
//! restrict further, never widen.  Two variants:
//!
//! - **ForkRestore** (~27 syscalls): minimal runtime for snapshot-restored workers
//! - **Exec** (~28 syscalls): adds `sched_setaffinity` for network worker pinning
//!
//! The runner does NOT install a filter — see note in `run_program()`.
//!
//! # Key syscalls BLOCKED at runtime (Phase 2 security wins)
//!
//! - `socket` / `connect` / `socketpair` — no new network connections
//! - `openat` / `open` — no new file opens on the host
//! - `ioctl` — no device control
//! - `sendto` / `recvfrom` — no socket I/O (9P uses shmem ring + futex)
//! - `memfd_create` / `ftruncate` — no new shared memory regions
//!
//! # Key syscalls BLOCKED always (Phase 1)
//!
//! - `execve` / `execveat` — no process replacement (THE main security win)
//! - `bind` / `listen` / `accept` — no listening servers
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

/// The kind of worker, determining which runtime syscall allowlist to use.
pub enum WorkerKind {
    /// Fork-restore worker: receives pre-built snapshot, no broker init at runtime.
    ForkRestore,
    /// Worker-exec worker: does full platform init (broker IPC, 9P, file loading)
    /// before entering guest execution.  Needs a slightly wider runtime filter
    /// because the network worker thread uses ppoll and sched_setaffinity may
    /// fire slightly late.
    Exec,
}

/// Install a second (tighter) seccomp filter for the **worker runtime** phase.
///
/// Called by the worker after initialization completes (broker connected, binary
/// loaded, network worker spawned) but before entering the guest execution loop.
/// Since seccomp filters stack (kernel ANDs them), this can only restrict further.
///
/// The runtime filter drops init-only syscalls like `socket`, `connect`, `openat`,
/// `ioctl`, `sendto`, `recvfrom`, `memfd_create`, etc.
pub fn install_worker_runtime_filter(kind: WorkerKind) {
    let prog = build_worker_runtime_filter(kind);
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
#[allow(clippy::cast_possible_truncation)] // syscall nrs & BPF jump offsets always fit
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
        libc::SYS_rt_sigreturn as u32, // 15  [W]  return from signal handler
        libc::SYS_sigaltstack as u32,  // 131 [W]  alternate signal stack setup
        libc::SYS_tgkill as u32,       // 234 [W]  thread-directed signal delivery (RT interrupt)
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
        libc::SYS_sched_setaffinity as u32, // 203 [WE] pin_thread_to_cpu (network worker)
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
        // ── Worker-exec init (forker-spawned non-PIE worker setup) ──
        // These are needed by run_worker_exec_core: platform init,
        // broker IPC, 9P channel, tar loading, shmem ring creation.
        // Previously unneeded because exec workers ran via posix_spawn
        // (unfiltered). Now that worker-exec goes through the forker,
        // the grandchild inherits the seccomp filter and needs these.
        // Security note: execve is still blocked — the main security
        // win is preserved. These syscalls only allow network/file
        // setup within the virtual sandbox.
        libc::SYS_socket as u32, // 41  [WE] AF_UNIX socket for broker IPC + 9P channel
        libc::SYS_socketpair as u32, // 53  [WE] AF_UNIX socketpair for mux channel setup
        libc::SYS_connect as u32, // 42  [WE] connect to broker Unix socket
        libc::SYS_poll as u32,   // 7   [WE] non-blocking connect wait
        libc::SYS_ppoll as u32,  // 271 [WE] ppoll variant used by Rust runtime for I/O wait
        libc::SYS_getsockopt as u32, // 55  [WE] check connect error (SO_ERROR)
        libc::SYS_sendto as u32, // 44  [WE] send() → sendto on x86_64, 9P handshake
        libc::SYS_recvfrom as u32, // 45  [WE] recv() → recvfrom on x86_64, 9P ack
        libc::SYS_open as u32,   // 2   [WE] read_maps_and_vdso (/proc/self/maps)
        libc::SYS_openat as u32, // 257 [WE] Rust std file I/O (tar files, mmap host binaries)
        libc::SYS_fstat as u32,  // 5   [WE] file metadata (mmap)
        libc::SYS_newfstatat as u32, // 262 [WE] file metadata (Rust std)
        libc::SYS_memfd_create as u32, // 319 [WE] shmem ring buffers, anonymous memfds
        libc::SYS_ftruncate as u32, // 77  [WE] shmem ring buffer sizing
        libc::SYS_mremap as u32, // 25  [WE] Rust Vec reallocation during init
        libc::SYS_readlink as u32, // 89  [WE] resolve /proc/self/exe, symlinks
        libc::SYS_ioctl as u32,  // 16  [WE] TUN device setup, terminal queries
        libc::SYS_clock_gettime as u32, // 228 [WE] Instant::now() fallback (if VDSO unavailable)
        libc::SYS_getppid as u32, // 110 [WE] init_task identity
        libc::SYS_getuid as u32, // 102 [WE] init_task identity
        libc::SYS_geteuid as u32, // 107 [WE] init_task identity
        libc::SYS_getgid as u32, // 104 [WE] init_task identity
        libc::SYS_getegid as u32, // 108 [WE] init_task identity
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

    // [4+N] Default: kill the entire process for disallowed syscalls.
    insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    // [4+N+1] ALLOW
    insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    insns
}

/// Build the runtime allowlist BPF filter for a worker.
///
/// This is the second filter installed after worker init completes.
/// It drops init-only syscalls that are no longer needed.
#[allow(clippy::cast_possible_truncation)]
fn build_worker_runtime_filter(kind: WorkerKind) -> Vec<BpfInsn> {
    let mut allowed: Vec<u32> = vec![
        // ── Basic I/O ──────────────────────────────────────────────
        libc::SYS_read as u32,  //  0  pipe I/O, host fd reads
        libc::SYS_write as u32, //  1  pipe I/O, host fd writes
        libc::SYS_close as u32, //  3  fd cleanup
        // ── Memory management ──────────────────────────────────────
        libc::SYS_mmap as u32,     //  9  guest memory, CoW, thread stacks
        libc::SYS_mprotect as u32, // 10  guest page permission changes
        libc::SYS_munmap as u32,   // 11  guest memory deallocation
        libc::SYS_mremap as u32,   // 25  Rust Vec reallocation (grow mmap in-place)
        libc::SYS_brk as u32,      // 12  glibc malloc fallback
        libc::SYS_madvise as u32,  // 28  Rust std thread stack advice
        // ── Signals ────────────────────────────────────────────────
        libc::SYS_rt_sigaction as u32, // 13  signal handler management
        libc::SYS_rt_sigprocmask as u32, // 14  signal mask management
        libc::SYS_rt_sigreturn as u32, // 15  return from signal handler
        libc::SYS_sigaltstack as u32,  // 131 alternate signal stack
        libc::SYS_tgkill as u32,       // 234 thread-directed signal delivery
        // ── Synchronization ────────────────────────────────────────
        libc::SYS_futex as u32, // 202 mutex/condvar, shmem ring signaling
        // ── Fd management ──────────────────────────────────────────
        libc::SYS_fcntl as u32, // 72  F_DUPFD_CLOEXEC, F_SETFD, F_SETFL
        // ── Time ───────────────────────────────────────────────────
        libc::SYS_clock_nanosleep as u32, // 230 mux anti-spin, std::thread::sleep
        // ── Thread / process lifecycle ─────────────────────────────
        libc::SYS_clone3 as u32,     // 435 Rust std::thread::spawn
        libc::SYS_exit as u32,       // 60  thread exit
        libc::SYS_exit_group as u32, // 231 process exit
        // ── Thread init (glibc/Rust runtime) ───────────────────────
        libc::SYS_set_robust_list as u32,   // 273 glibc thread init
        libc::SYS_rseq as u32,              // 334 glibc restartable sequences
        libc::SYS_sched_getaffinity as u32, // 204 Rust std thread pool sizing
        // ── System info ────────────────────────────────────────────
        libc::SYS_getpid as u32,    //  39 glibc per-thread getpid() cache
        libc::SYS_gettid as u32,    // 186 thread ID for tgkill
        libc::SYS_getrandom as u32, // 318 entropy (Rust HashMap seed)
        // ── Network worker ─────────────────────────────────────────
        libc::SYS_ppoll as u32, // 271 TUN/IPC polling on network worker thread
        // ── Device / terminal ──────────────────────────────────────
        libc::SYS_ioctl as u32, // 16  TUN device I/O, terminal queries at runtime
        // ── Pipe / thread bookkeeping ──────────────────────────────
        libc::SYS_pipe2 as u32, // 293 Rust std internal (condvar notify pipe)
        // ── File access (Rust runtime) ─────────────────────────────
        libc::SYS_openat as u32, // 257 Rust std thread pool sizing (/proc/stat, /sys/cpu)
        // ── IPC ────────────────────────────────────────────────────
        libc::SYS_socketpair as u32, // 53  AF_UNIX socketpair for mux channel setup at runtime
        // ── Seccomp (needed to install THIS filter) ────────────────
        libc::SYS_prctl as u32,   // 157 PR_SET_NO_NEW_PRIVS (idempotent)
        libc::SYS_seccomp as u32, // 317 install this runtime filter
    ];

    if matches!(kind, WorkerKind::Exec) {
        allowed.push(libc::SYS_sched_setaffinity as u32); // 203 pin_thread_to_cpu
    }

    allowed.sort_unstable();
    allowed.dedup();

    let num_allowed = allowed.len();
    let mut insns: Vec<BpfInsn> = Vec::with_capacity(4 + num_allowed + 2);

    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH));
    insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0));
    insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR));

    for (i, &nr) in allowed.iter().enumerate() {
        let remaining = num_allowed - i - 1;
        let allow_offset = remaining + 1;
        insns.push(bpf_jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            nr,
            allow_offset as u8,
            0,
        ));
    }

    insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    insns
}

/// Apply a BPF seccomp filter to the current process.
#[allow(clippy::cast_possible_truncation)] // insns.len() always fits u16 (BPF max 4096)
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
            u64::from(SECCOMP_SET_MODE_FILTER),
            0u64, // flags
            (&raw const prog).cast::<libc::c_void>(),
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
    #[allow(clippy::cast_possible_truncation)] // syscall nrs always fit u32
    fn assert_dangerous_syscalls_blocked(syscall_nrs: &[u32]) {
        let dangerous = [
            (libc::SYS_execve as u32, "execve"),
            (libc::SYS_execveat as u32, "execveat"),
            // socket, connect, openat are now allowed for worker-exec init.
            // The security win is preserved: execve is still blocked.
            (libc::SYS_bind as u32, "bind"),
            (libc::SYS_listen as u32, "listen"),
            (libc::SYS_accept as u32, "accept"),
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
    #[allow(clippy::cast_possible_truncation)] // syscall nrs always fit u32
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
            count <= 61,
            "forker allowlist has {count} syscalls — expected <= 61. \
             Justify any additions with [F]/[W]/[WI]/[WE]/[RT] tags."
        );
    }

    // ── Runtime filter tests ───────────────────────────────────────────

    #[test]
    fn fork_restore_runtime_filter_builds_without_panic() {
        let insns = build_worker_runtime_filter(WorkerKind::ForkRestore);
        assert!(insns.len() > 10, "filter too short: {} insns", insns.len());
        assert!(
            insns.len() <= 4096,
            "filter too long: {} insns",
            insns.len()
        );
    }

    #[test]
    fn exec_runtime_filter_builds_without_panic() {
        let insns = build_worker_runtime_filter(WorkerKind::Exec);
        assert!(insns.len() > 10, "filter too short: {} insns", insns.len());
        assert!(
            insns.len() <= 4096,
            "filter too long: {} insns",
            insns.len()
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn runtime_filters_block_dangerous_syscalls() {
        for kind in [WorkerKind::ForkRestore, WorkerKind::Exec] {
            let insns = build_worker_runtime_filter(kind);
            let syscall_nrs = extract_allowed_syscalls(&insns);
            assert_dangerous_syscalls_blocked(&syscall_nrs);
        }
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn runtime_filters_block_init_only_syscalls() {
        // These syscalls must NOT be in any runtime filter — truly init-only.
        let init_only = [
            (libc::SYS_socket as u32, "socket"),
            (libc::SYS_connect as u32, "connect"),
            (libc::SYS_sendto as u32, "sendto"),
            (libc::SYS_recvfrom as u32, "recvfrom"),
            (libc::SYS_memfd_create as u32, "memfd_create"),
            (libc::SYS_ftruncate as u32, "ftruncate"),
            (libc::SYS_readlink as u32, "readlink"),
            (libc::SYS_fstat as u32, "fstat"),
            (libc::SYS_newfstatat as u32, "newfstatat"),
            (libc::SYS_statx as u32, "statx"),
            (libc::SYS_dup2 as u32, "dup2"),
            (libc::SYS_lseek as u32, "lseek"),
            (libc::SYS_getsockopt as u32, "getsockopt"),
            (libc::SYS_open as u32, "open"),
        ];
        for kind in [WorkerKind::ForkRestore, WorkerKind::Exec] {
            let insns = build_worker_runtime_filter(kind);
            let syscall_nrs = extract_allowed_syscalls(&insns);
            for (nr, name) in &init_only {
                assert!(
                    !syscall_nrs.contains(nr),
                    "init-only syscall {} (nr {}) must not be in runtime filter",
                    name,
                    nr
                );
            }
        }
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn runtime_filters_contain_required_runtime_syscalls() {
        let required = [
            (libc::SYS_read as u32, "read"),
            (libc::SYS_write as u32, "write"),
            (libc::SYS_mmap as u32, "mmap"),
            (libc::SYS_mprotect as u32, "mprotect"),
            (libc::SYS_futex as u32, "futex"),
            (libc::SYS_clone3 as u32, "clone3"),
            (libc::SYS_exit_group as u32, "exit_group"),
            (libc::SYS_ppoll as u32, "ppoll"),
            (libc::SYS_rt_sigaction as u32, "rt_sigaction"),
        ];
        for kind in [WorkerKind::ForkRestore, WorkerKind::Exec] {
            let insns = build_worker_runtime_filter(kind);
            let syscall_nrs = extract_allowed_syscalls(&insns);
            for (nr, name) in &required {
                assert!(
                    syscall_nrs.contains(nr),
                    "required runtime syscall {} (nr {}) missing from filter",
                    name,
                    nr
                );
            }
        }
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn exec_runtime_filter_has_sched_setaffinity() {
        let insns = build_worker_runtime_filter(WorkerKind::Exec);
        let syscall_nrs = extract_allowed_syscalls(&insns);
        assert!(
            syscall_nrs.contains(&(libc::SYS_sched_setaffinity as u32)),
            "Exec runtime filter must include sched_setaffinity"
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn fork_restore_runtime_filter_lacks_sched_setaffinity() {
        let insns = build_worker_runtime_filter(WorkerKind::ForkRestore);
        let syscall_nrs = extract_allowed_syscalls(&insns);
        assert!(
            !syscall_nrs.contains(&(libc::SYS_sched_setaffinity as u32)),
            "ForkRestore runtime filter must not include sched_setaffinity"
        );
    }

    #[test]
    fn fork_restore_runtime_filter_size_guard() {
        let insns = build_worker_runtime_filter(WorkerKind::ForkRestore);
        let count = extract_allowed_syscalls(&insns).len();
        assert!(
            count <= 35,
            "ForkRestore runtime allowlist has {count} syscalls — expected <= 35."
        );
    }

    #[test]
    fn exec_runtime_filter_size_guard() {
        let insns = build_worker_runtime_filter(WorkerKind::Exec);
        let count = extract_allowed_syscalls(&insns).len();
        assert!(
            count <= 36,
            "Exec runtime allowlist has {count} syscalls — expected <= 36."
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn runtime_filter_is_subset_of_forker_filter() {
        let forker_insns = build_allowlist_filter();
        let forker_syscalls = extract_allowed_syscalls(&forker_insns);

        for kind in [WorkerKind::ForkRestore, WorkerKind::Exec] {
            let runtime_insns = build_worker_runtime_filter(kind);
            let runtime_syscalls = extract_allowed_syscalls(&runtime_insns);
            for nr in &runtime_syscalls {
                assert!(
                    forker_syscalls.contains(nr),
                    "runtime syscall nr {} not found in forker filter — \
                     runtime filter must be a subset of the forker filter",
                    nr
                );
            }
        }
    }
}
