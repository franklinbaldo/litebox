# Two-Phase Seccomp Tightening Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** After worker initialization completes, install a second seccomp filter that drops ~35 init-only syscalls, blocking `socket`/`connect`/`openat`/`ioctl`/`sendto`/`recvfrom` at runtime.

**Architecture:** Workers already inherit the forker's wide seccomp filter. After init (broker connected, binary loaded, network worker spawned), each worker installs a second BPF filter via `seccomp(SECCOMP_SET_MODE_FILTER)`. Seccomp filters stack (kernel ANDs them), so this can only restrict further. Two filter variants: one for fork-restore workers (~24 syscalls), one for worker-exec workers (~25 syscalls).

**Tech Stack:** Rust, seccomp-BPF (Linux kernel), x86_64

---

### Task 1: Add runtime filter builder functions to sandbox_seccomp.rs

**Files:**
- Modify: `litebox_platform_linux_userland/src/sandbox_seccomp.rs:103-251`

**Step 1: Add the `WorkerKind` enum and two public install functions**

After the existing `install_forker_sandbox_filter()` at line 44, add:

```rust
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
    // apply_bpf_filter calls prctl(PR_SET_NO_NEW_PRIVS) which is idempotent
    // (already set by the forker's filter), then installs the new filter.
    apply_bpf_filter(&prog);
}
```

**Step 2: Add the `build_worker_runtime_filter` function**

After the existing `build_allowlist_filter()` function, add a new function that builds a tighter runtime allowlist. Use the same BPF construction pattern (arch check, load nr, linear scan, kill/allow).

```rust
/// Build the runtime allowlist BPF filter for a worker.
///
/// This is the second filter installed after worker init completes.
/// It drops init-only syscalls that are no longer needed.
#[allow(clippy::cast_possible_truncation)]
fn build_worker_runtime_filter(kind: WorkerKind) -> Vec<BpfInsn> {
    // Core runtime syscalls needed by ALL workers during guest execution.
    let mut allowed: Vec<u32> = vec![
        // ── Basic I/O ──────────────────────────────────────────────
        libc::SYS_read as u32,           //  0  pipe I/O, host fd reads
        libc::SYS_write as u32,          //  1  pipe I/O, host fd writes
        libc::SYS_close as u32,          //  3  fd cleanup
        // ── Memory management ──────────────────────────────────────
        libc::SYS_mmap as u32,           //  9  guest memory, CoW, thread stacks
        libc::SYS_mprotect as u32,       // 10  guest page permission changes
        libc::SYS_munmap as u32,         // 11  guest memory deallocation
        libc::SYS_brk as u32,            // 12  glibc malloc fallback
        libc::SYS_madvise as u32,        // 28  Rust std thread stack advice
        // ── Signals ────────────────────────────────────────────────
        libc::SYS_rt_sigaction as u32,   // 13  signal handler management
        libc::SYS_rt_sigprocmask as u32, // 14  signal mask management
        libc::SYS_rt_sigreturn as u32,   // 15  return from signal handler
        libc::SYS_sigaltstack as u32,    // 131 alternate signal stack
        libc::SYS_tgkill as u32,         // 234 thread-directed signal delivery
        // ── Synchronization ────────────────────────────────────────
        libc::SYS_futex as u32,          // 202 mutex/condvar, shmem ring signaling
        // ── Fd management ──────────────────────────────────────────
        libc::SYS_fcntl as u32,          // 72  F_DUPFD_CLOEXEC, F_SETFD, F_SETFL
        // ── Time ───────────────────────────────────────────────────
        libc::SYS_clock_nanosleep as u32, // 230 mux anti-spin, std::thread::sleep
        // ── Thread / process lifecycle ─────────────────────────────
        libc::SYS_clone3 as u32,         // 435 Rust std::thread::spawn
        libc::SYS_exit as u32,           // 60  thread exit
        libc::SYS_exit_group as u32,     // 231 process exit
        // ── Thread init (glibc/Rust runtime) ───────────────────────
        libc::SYS_set_robust_list as u32,   // 273 glibc thread init
        libc::SYS_rseq as u32,             // 334 glibc restartable sequences
        libc::SYS_sched_getaffinity as u32, // 204 Rust std thread pool sizing
        // ── System info ────────────────────────────────────────────
        libc::SYS_gettid as u32,         // 186 thread ID for tgkill
        libc::SYS_getrandom as u32,      // 318 entropy (Rust HashMap seed)
        // ── Network worker ─────────────────────────────────────────
        libc::SYS_ppoll as u32,          // 271 TUN/IPC polling on network worker thread
        // ── Seccomp (needed to install THIS filter) ────────────────
        libc::SYS_prctl as u32,          // 157 PR_SET_NO_NEW_PRIVS (idempotent)
        libc::SYS_seccomp as u32,        // 317 install this runtime filter
    ];

    // Worker-exec gets slightly wider: network worker CPU pinning may
    // happen just before runtime begins.
    if matches!(kind, WorkerKind::Exec) {
        allowed.push(libc::SYS_sched_setaffinity as u32); // 203 pin_thread_to_cpu
    }

    allowed.sort_unstable();
    allowed.dedup();

    // Build BPF program (same structure as build_allowlist_filter).
    let num_allowed = allowed.len();
    let mut insns: Vec<BpfInsn> = Vec::with_capacity(4 + num_allowed + 2);

    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH));
    insns.push(bpf_jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        AUDIT_ARCH_X86_64,
        1,
        0,
    ));
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
```

**Step 3: Run the build to verify compilation**

Run: `cargo build -p litebox_platform_linux_userland 2>&1`
Expected: compiles without errors (new code is not called yet)

**Step 4: Commit**

```
feat(seccomp): add two-phase runtime filter builders for fork-restore and worker-exec
```

---

### Task 2: Add unit tests for the runtime filters

**Files:**
- Modify: `litebox_platform_linux_userland/src/sandbox_seccomp.rs` (test module)

**Step 1: Add tests for runtime filters**

Add to the `mod tests` block:

```rust
#[test]
fn fork_restore_runtime_filter_builds_without_panic() {
    let insns = build_worker_runtime_filter(WorkerKind::ForkRestore);
    assert!(insns.len() > 10, "filter too short: {} insns", insns.len());
    assert!(insns.len() <= 4096, "filter too long: {} insns", insns.len());
}

#[test]
fn exec_runtime_filter_builds_without_panic() {
    let insns = build_worker_runtime_filter(WorkerKind::Exec);
    assert!(insns.len() > 10, "filter too short: {} insns", insns.len());
    assert!(insns.len() <= 4096, "filter too long: {} insns", insns.len());
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
    // These syscalls must NOT be in any runtime filter — they are init-only.
    let init_only = [
        (libc::SYS_socket as u32, "socket"),
        (libc::SYS_socketpair as u32, "socketpair"),
        (libc::SYS_connect as u32, "connect"),
        (libc::SYS_getsockopt as u32, "getsockopt"),
        (libc::SYS_sendto as u32, "sendto"),
        (libc::SYS_recvfrom as u32, "recvfrom"),
        (libc::SYS_open as u32, "open"),
        (libc::SYS_openat as u32, "openat"),
        (libc::SYS_fstat as u32, "fstat"),
        (libc::SYS_newfstatat as u32, "newfstatat"),
        (libc::SYS_statx as u32, "statx"),
        (libc::SYS_memfd_create as u32, "memfd_create"),
        (libc::SYS_ftruncate as u32, "ftruncate"),
        (libc::SYS_readlink as u32, "readlink"),
        (libc::SYS_ioctl as u32, "ioctl"),
        (libc::SYS_dup2 as u32, "dup2"),
        (libc::SYS_lseek as u32, "lseek"),
        (libc::SYS_mremap as u32, "mremap"),
    ];
    for kind in [WorkerKind::ForkRestore, WorkerKind::Exec] {
        let insns = build_worker_runtime_filter(kind);
        let syscall_nrs = extract_allowed_syscalls(&insns);
        for (nr, name) in &init_only {
            assert!(
                !syscall_nrs.contains(nr),
                "{name} (nr {nr}) must not be in runtime allowlist",
            );
        }
    }
}

#[test]
#[allow(clippy::cast_possible_truncation)]
fn runtime_filters_contain_required_runtime_syscalls() {
    // All runtime filters must include these core syscalls.
    let required = [
        libc::SYS_read as u32,
        libc::SYS_write as u32,
        libc::SYS_mmap as u32,
        libc::SYS_mprotect as u32,
        libc::SYS_futex as u32,
        libc::SYS_clone3 as u32,
        libc::SYS_exit_group as u32,
        libc::SYS_ppoll as u32,
        libc::SYS_rt_sigaction as u32,
    ];
    for kind in [WorkerKind::ForkRestore, WorkerKind::Exec] {
        let insns = build_worker_runtime_filter(kind);
        let syscall_nrs = extract_allowed_syscalls(&insns);
        for &nr in &required {
            assert!(
                syscall_nrs.contains(&nr),
                "syscall nr {nr} must be in runtime allowlist",
            );
        }
    }
}

#[test]
#[allow(clippy::cast_possible_truncation)]
fn exec_runtime_filter_has_sched_setaffinity() {
    let insns = build_worker_runtime_filter(WorkerKind::Exec);
    let syscall_nrs = extract_allowed_syscalls(&insns);
    assert!(syscall_nrs.contains(&(libc::SYS_sched_setaffinity as u32)));
}

#[test]
#[allow(clippy::cast_possible_truncation)]
fn fork_restore_runtime_filter_lacks_sched_setaffinity() {
    let insns = build_worker_runtime_filter(WorkerKind::ForkRestore);
    let syscall_nrs = extract_allowed_syscalls(&insns);
    assert!(!syscall_nrs.contains(&(libc::SYS_sched_setaffinity as u32)));
}

#[test]
fn fork_restore_runtime_filter_size_guard() {
    let insns = build_worker_runtime_filter(WorkerKind::ForkRestore);
    let count = extract_allowed_syscalls(&insns).len();
    assert!(
        count <= 28,
        "fork-restore runtime has {count} syscalls — expected <= 28. \
         Runtime filters should be tight."
    );
}

#[test]
fn exec_runtime_filter_size_guard() {
    let insns = build_worker_runtime_filter(WorkerKind::Exec);
    let count = extract_allowed_syscalls(&insns).len();
    assert!(
        count <= 29,
        "exec runtime has {count} syscalls — expected <= 29. \
         Runtime filters should be tight."
    );
}

#[test]
#[allow(clippy::cast_possible_truncation)]
fn runtime_filter_is_subset_of_forker_filter() {
    // Every syscall in the runtime filter must also be in the forker filter.
    let forker_insns = build_allowlist_filter();
    let forker_nrs = extract_allowed_syscalls(&forker_insns);

    for kind in [WorkerKind::ForkRestore, WorkerKind::Exec] {
        let runtime_insns = build_worker_runtime_filter(kind);
        let runtime_nrs = extract_allowed_syscalls(&runtime_insns);
        for nr in &runtime_nrs {
            assert!(
                forker_nrs.contains(nr),
                "runtime syscall nr {nr} not in forker filter — runtime filter \
                 must be a subset of the forker filter",
            );
        }
    }
}
```

**Step 2: Run the tests**

Run: `cargo test -p litebox_platform_linux_userland -- seccomp 2>&1`
Expected: ALL seccomp tests pass (existing 3 + new 9 = 12)

**Step 3: Commit**

```
test(seccomp): add unit tests for two-phase runtime filters
```

---

### Task 3: Install the runtime filter in fork-restore workers

**Files:**
- Modify: `litebox_runner_linux_userland/src/lib.rs:3326-3370` (fork-restore path in `run_forked_worker`)

**Step 1: Add the runtime filter installation call**

In `run_forked_worker()`, the fork-restore path has two branches:
- With 9P broker (line 3293): calls `fork_restore_and_ack` then `run_program`
- Without 9P broker (line 3345): calls `fork_restore_and_ack` then `run_program`

In BOTH branches, add the seccomp tightening call **after** `fork_restore_and_ack` succeeds and **before** `run_program`:

Branch 1 (with 9P, around line 3336):
```rust
Ok((program, mux_handle)) => {
    litebox_platform_linux_userland::sandbox_seccomp::install_worker_runtime_filter(
        litebox_platform_linux_userland::sandbox_seccomp::WorkerKind::ForkRestore,
    );
    let wait_status =
        run_program(program, shutdown, net_worker, result_fd, mux_handle);
    terminate_host_with_guest_wait_status(wait_status);
}
```

Branch 2 (without 9P, around line 3361):
```rust
Ok((program, mux_handle)) => {
    litebox_platform_linux_userland::sandbox_seccomp::install_worker_runtime_filter(
        litebox_platform_linux_userland::sandbox_seccomp::WorkerKind::ForkRestore,
    );
    let wait_status =
        run_program(program, shutdown, net_worker, result_fd, mux_handle);
    terminate_host_with_guest_wait_status(wait_status);
}
```

**Step 2: Build to verify compilation**

Run: `cargo build -p litebox_runner_linux_userland 2>&1`
Expected: compiles without errors

**Step 3: Commit**

```
feat(seccomp): install runtime filter in fork-restore workers before guest execution
```

---

### Task 4: Install the runtime filter in worker-exec workers

**Files:**
- Modify: `litebox_runner_linux_userland/src/lib.rs:2123-2288` (`run_worker_exec_core`)

**Step 1: Find the right insertion point**

`run_worker_exec_core` has two branches:
- With 9P (line 2250): calls `finish_run_with_nine_p`
- Without 9P (line 2263): calls `shim.load_program_with_exec_filename` then `run_program`

For the non-9P branch, insert the filter **after** `load_program_with_exec_filename` and **before** `run_program` (around line 2280):

```rust
let program = shim.load_program_with_exec_filename(
    initial_file_system,
    guest_task,
    load_prog_path,
    load_prog_path,
    guest_argv,
    guest_envp,
    cli_args.working_directory.clone(),
)?;

litebox_platform_linux_userland::sandbox_seccomp::install_worker_runtime_filter(
    litebox_platform_linux_userland::sandbox_seccomp::WorkerKind::Exec,
);

Ok(run_program(
    program,
    shutdown,
    net_worker,
    cli_args.worker_result_fd,
    None,
))
```

For the 9P branch, we need to modify `finish_run_with_nine_p`. In that function (line 874), insert the filter call after `load_program_with_exec_filename` and before `run_program` in both the IPC branch (line 921) and the TUN branch.

BUT `finish_run_with_nine_p` is called by BOTH the runner (non-worker path) and worker-exec. We need a way to know if we're in a forker grandchild. The `forker_grandchild` parameter exists on `run_worker_exec_core` but not on `finish_run_with_nine_p`.

**Solution:** Add an `install_runtime_seccomp: bool` parameter to `finish_run_with_nine_p`. When true, install the exec runtime filter before `run_program`. The runner path passes `false`, the worker-exec path passes `true`.

Alternatively, simpler approach: Add `forker_grandchild: bool` parameter to `finish_run_with_nine_p`.

Look at all call sites of `finish_run_with_nine_p`:
- `run_worker_exec_core` at line 2251 — called from forker grandchild when `forker_grandchild=true`
- `run()` at line ~790 — runner, not a forker grandchild

So: add `forker_grandchild: bool` to `finish_run_with_nine_p`, install filter when true.

**Step 2: Modify `finish_run_with_nine_p` signature and body**

Add parameter `forker_grandchild: bool` to the function signature.

In the IPC branch (line 921-937), after `load_program_with_exec_filename` and before `run_program`:
```rust
let program = shim.load_program_with_exec_filename(
    combined_fs, ...
)?;

if forker_grandchild {
    litebox_platform_linux_userland::sandbox_seccomp::install_worker_runtime_filter(
        litebox_platform_linux_userland::sandbox_seccomp::WorkerKind::Exec,
    );
}

return Ok(guest_wait_status_to_exit_code(run_program(
    program, ...
)));
```

In the TUN branch, same pattern after `load_program_with_exec_filename` and before `run_program`.

**Step 3: Update all call sites of `finish_run_with_nine_p`**

- In `run_worker_exec_core` (line 2251): pass `true` for `forker_grandchild`
- In `run()` (the runner's main path): pass `false`

Find the runner call site:
```
grep for "finish_run_with_nine_p" in lib.rs
```

**Step 4: Build to verify compilation**

Run: `cargo build -p litebox_runner_linux_userland 2>&1`
Expected: compiles without errors

**Step 5: Commit**

```
feat(seccomp): install runtime filter in worker-exec workers before guest execution
```

---

### Task 5: Update module documentation and the run_program comment

**Files:**
- Modify: `litebox_platform_linux_userland/src/sandbox_seccomp.rs:1-35` (module doc)
- Modify: `litebox_runner_linux_userland/src/lib.rs:2303-2315` (run_program comment)

**Step 1: Update module doc in sandbox_seccomp.rs**

Replace the module doc to describe the two-phase architecture:

```rust
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
//! entering its recv loop. Workers inherit it across `fork()`. This filter
//! allows all syscalls needed during worker initialization (socket, connect,
//! openat, etc.) but blocks `execve`, `bind`, `ptrace`, etc.
//!
//! **Phase 2 (worker runtime filter):** After initialization completes
//! (broker connected, binary loaded, network worker spawned), each worker
//! installs a second, tighter filter that drops ~35 init-only syscalls.
//! Seccomp filters stack in the kernel (AND semantics), so this can only
//! restrict further, never widen.  Two variants:
//!
//! - **ForkRestore** (~26 syscalls): minimal runtime for snapshot-restored workers
//! - **Exec** (~27 syscalls): adds `sched_setaffinity` for network worker pinning
//!
//! The runner does NOT install a filter — see note in `run_program()`.
//!
//! # Key syscalls BLOCKED at runtime (the Phase 2 security wins)
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
```

**Step 2: Update the run_program comment**

Update the comment in `run_program()` (line 2303-2315) to reflect the new two-phase design:

```rust
// NOTE: We intentionally do NOT install a seccomp filter on the runner.
//
// The runner spawns the forker, which installs a Phase 1 filter (wide
// allowlist) before its recv loop.  Workers inherit this filter via
// fork() and then install a Phase 2 filter (tight runtime allowlist)
// after their initialization completes.  The runner itself is not
// sandboxed because it needs full syscall access for platform setup,
// and its filter would be inherited by workers before their own Phase 2
// filter could be installed.
```

**Step 3: Commit**

```
docs(seccomp): update module docs and comments for two-phase filter architecture
```

---

### Task 6: Run clippy and fix any warnings

**Files:**
- Modify: `litebox_platform_linux_userland/src/sandbox_seccomp.rs` (if needed)
- Modify: `litebox_runner_linux_userland/src/lib.rs` (if needed)

**Step 1: Run clippy on both crates**

Run: `cargo clippy -p litebox_platform_linux_userland -p litebox_runner_linux_userland -- -D warnings 2>&1`
Expected: 0 warnings

**Step 2: Fix any warnings found**

**Step 3: Commit (if any fixes needed)**

```
fix: resolve clippy warnings from two-phase seccomp changes
```

---

### Task 7: Integration test — fork-restore path (delayed fork / bash)

Test the fork-restore worker path by running bash commands that trigger `commit_delayed_fork` → forker spawn → worker execution. This exercises the fork-restore runtime filter.

**Step 1: Test basic command execution**

Run: `podman run --rm ubuntu:latest /bin/bash -c 'echo hello world'`
Expected: prints `hello world`, exit 0

**Step 2: Test pipe-in-command-substitution (exercises fork-restore)**

Run: `podman run --rm ubuntu:latest /bin/bash -c 'X=$(echo foo | cat); echo $X'`
Expected: prints `foo`, exit 0

**Step 3: Test multi-pipe (exercises multiple fork-restores)**

Run: `podman run --rm ubuntu:latest /bin/bash -c 'echo abc | cat | rev | cat'`
Expected: prints `cba`, exit 0

---

### Task 8: Integration test — worker-exec path (copilot-cli)

Test the worker-exec path by running copilot-cli, which exercises full platform init inside a forker grandchild.

**Step 1: Run copilot with a simple prompt**

Run: `./dev_tools/run_copilot_ipc.sh -p "say hello"`
Expected: completes successfully with exit 0 (or copilot's normal exit code)

**Step 2: Run copilot with a heavier prompt (3 times for confidence)**

Run (3 times):
```
./dev_tools/run_copilot_ipc.sh -p "explain this repo"
```
Expected: all 3 complete successfully, no SIGSYS or unexpected crashes

---

### Task 9: Integration test — OCI runtime tests

Run the full OCI runtime test suite to verify nothing is broken.

**Step 1: Run OCI tests**

Run: `cargo test -p litebox_runner_oci 2>&1`
Expected: 62/62 tests pass (or whatever the current count is)

**Step 2: Run seccomp unit tests one final time**

Run: `cargo test -p litebox_platform_linux_userland -- seccomp 2>&1`
Expected: 12/12 tests pass
