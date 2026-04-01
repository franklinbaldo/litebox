# Micro-Local Fast-Path Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Eliminate the shared-memory round-trip for ~30 syscalls that central always stamps `EXEC_LOCAL` with zero work — micro executes them directly via raw syscall.

**Architecture:** Add an `is_micro_local()` predicate in `handler.rs` that short-circuits before `submit_and_wait`. For matching syscalls, micro calls the raw syscall directly (reusing the existing `execute_locally` match arms or inlined equivalents) and returns immediately. No `report_local_result` is sent — central never sees these syscalls. `brk` is included with a post-execve guard (`guest_brk != 0`).

**Tech Stack:** Rust, `litebox_micro` crate, raw syscall wrappers.

---

### Task 1: Add `is_micro_local()` predicate to handler.rs

**Files:**
- Modify: `litebox_micro/src/handler.rs:300-308` (before `submit_and_wait`)

**Step 1: Add the `is_micro_local` function**

Add this function before `micro_handle_syscall`:

```rust
/// Returns `true` if this syscall can be executed entirely within micro
/// without consulting central. These are syscalls where central provably
/// does zero work — it always returns `EXEC_LOCAL` with no shim dispatch,
/// no state update, and no side effects.
#[allow(clippy::cast_possible_truncation)]
fn is_micro_local(nr: u32) -> bool {
    matches!(
        i64::from(nr),
        // Process/user identity: return kernel constants
        libc::SYS_getpid
            | libc::SYS_getppid
            | libc::SYS_getuid
            | libc::SYS_getgid
            | libc::SYS_geteuid
            | libc::SYS_getegid
            // Time: read-only kernel state, writes to guest buffer
            | libc::SYS_clock_gettime
            | libc::SYS_gettimeofday
            | libc::SYS_time
            | libc::SYS_clock_getres
            // Sleep: blocking, no shared state
            | libc::SYS_nanosleep
            | libc::SYS_clock_nanosleep
            // Thread setup: thread-local only
            | libc::SYS_arch_prctl
            | libc::SYS_set_tid_address
            | libc::SYS_set_robust_list
            | libc::SYS_rseq
            // Signals: process-local signal state
            | libc::SYS_rt_sigaction
            | libc::SYS_rt_sigprocmask
            | libc::SYS_sigaltstack
            | libc::SYS_rt_sigsuspend
            | libc::SYS_alarm
            // Random/info: write to guest buffer, no shared state
            | libc::SYS_getrandom
            | libc::SYS_sched_getaffinity
            | libc::SYS_prlimit64
            | libc::SYS_uname
            | libc::SYS_sysinfo
            | libc::SYS_getrlimit
            | libc::SYS_mincore
            // Process wait: must run in micro's PID namespace
            | libc::SYS_wait4
            // Pipe creation: real OS pipes, no shim state
            | libc::SYS_pipe2
            // Filesystem sync: no arguments
            | libc::SYS_sync
    )
}
```

**Step 2: Add `execute_micro_local` function to local_exec.rs**

Add a new public function in `litebox_micro/src/local_exec.rs` that handles just the micro-local syscalls. This is a subset of `execute_locally` that doesn't need a `CqEntry`, `ring_base`, `layout`, or `syscall_entry_point`:

```rust
/// Execute a micro-local syscall directly, without consulting central.
///
/// These syscalls never touch central's shim state. They are executed
/// via raw kernel syscalls in the guest's address space.
///
/// # Safety
///
/// The caller must ensure `syscall_nr` and `args` describe a valid syscall
/// that is in the micro-local set.
#[allow(
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines
)]
pub unsafe fn execute_micro_local(syscall_nr: u32, args: &[u64; 6]) -> i64 {
    match syscall_nr {
        // Process/user identity
        nr if nr == libc::SYS_getpid as u32 => unsafe { raw_syscall::syscall0(libc::SYS_getpid) },
        nr if nr == libc::SYS_getppid as u32 => unsafe { raw_syscall::syscall0(libc::SYS_getppid) },
        nr if nr == libc::SYS_getuid as u32 => unsafe { raw_syscall::syscall0(libc::SYS_getuid) },
        nr if nr == libc::SYS_getgid as u32 => unsafe { raw_syscall::syscall0(libc::SYS_getgid) },
        nr if nr == libc::SYS_geteuid as u32 => unsafe { raw_syscall::syscall0(libc::SYS_geteuid) },
        nr if nr == libc::SYS_getegid as u32 => unsafe { raw_syscall::syscall0(libc::SYS_getegid) },
        // Time
        nr if nr == libc::SYS_clock_gettime as u32 => unsafe {
            raw_syscall::syscall2(libc::SYS_clock_gettime, args[0], args[1])
        },
        nr if nr == libc::SYS_gettimeofday as u32 => unsafe {
            raw_syscall::syscall2(libc::SYS_gettimeofday, args[0], args[1])
        },
        nr if nr == libc::SYS_time as u32 => unsafe {
            raw_syscall::syscall1(libc::SYS_time, args[0])
        },
        nr if nr == libc::SYS_clock_getres as u32 => unsafe {
            raw_syscall::syscall2(libc::SYS_clock_getres, args[0], args[1])
        },
        // Sleep
        nr if nr == libc::SYS_nanosleep as u32 => unsafe {
            raw_syscall::syscall2(libc::SYS_nanosleep, args[0], args[1])
        },
        nr if nr == libc::SYS_clock_nanosleep as u32 => unsafe {
            raw_syscall::syscall4(libc::SYS_clock_nanosleep, args[0], args[1], args[2], args[3])
        },
        // Thread setup
        nr if nr == libc::SYS_arch_prctl as u32 => unsafe {
            raw_syscall::arch_prctl(args[0] as i32, args[1] as usize)
        },
        nr if nr == libc::SYS_set_tid_address as u32 => unsafe {
            raw_syscall::syscall1(libc::SYS_set_tid_address, args[0])
        },
        nr if nr == libc::SYS_set_robust_list as u32 => unsafe {
            raw_syscall::syscall2(libc::SYS_set_robust_list, args[0], args[1])
        },
        nr if nr == libc::SYS_rseq as u32 => unsafe {
            raw_syscall::syscall4(libc::SYS_rseq, args[0], args[1], args[2], args[3])
        },
        // Signals
        nr if nr == libc::SYS_rt_sigaction as u32 => unsafe {
            raw_syscall::syscall4(libc::SYS_rt_sigaction, args[0], args[1], args[2], args[3])
        },
        nr if nr == libc::SYS_rt_sigprocmask as u32 => unsafe {
            raw_syscall::syscall4(libc::SYS_rt_sigprocmask, args[0], args[1], args[2], args[3])
        },
        nr if nr == libc::SYS_sigaltstack as u32 => unsafe {
            raw_syscall::syscall2(libc::SYS_sigaltstack, args[0], args[1])
        },
        nr if nr == libc::SYS_rt_sigsuspend as u32 => unsafe {
            raw_syscall::syscall2(libc::SYS_rt_sigsuspend, args[0], args[1])
        },
        nr if nr == libc::SYS_alarm as u32 => unsafe {
            raw_syscall::syscall1(libc::SYS_alarm, args[0])
        },
        // Random/info
        nr if nr == libc::SYS_getrandom as u32 => unsafe {
            raw_syscall::syscall3(libc::SYS_getrandom, args[0], args[1], args[2])
        },
        nr if nr == libc::SYS_sched_getaffinity as u32 => unsafe {
            raw_syscall::syscall3(libc::SYS_sched_getaffinity, args[0], args[1], args[2])
        },
        nr if nr == libc::SYS_prlimit64 as u32 => unsafe {
            raw_syscall::syscall4(libc::SYS_prlimit64, args[0], args[1], args[2], args[3])
        },
        nr if nr == libc::SYS_uname as u32 => unsafe {
            raw_syscall::syscall1(libc::SYS_uname, args[0])
        },
        nr if nr == libc::SYS_sysinfo as u32 => unsafe {
            raw_syscall::syscall1(libc::SYS_sysinfo, args[0])
        },
        nr if nr == libc::SYS_getrlimit as u32 => unsafe {
            raw_syscall::syscall2(libc::SYS_getrlimit, args[0], args[1])
        },
        nr if nr == libc::SYS_mincore as u32 => unsafe {
            raw_syscall::syscall3(libc::SYS_mincore, args[0], args[1], args[2])
        },
        // Process wait
        nr if nr == libc::SYS_wait4 as u32 => unsafe {
            raw_syscall::syscall4(libc::SYS_wait4, args[0], args[1], args[2], args[3])
        },
        // Pipe creation
        nr if nr == libc::SYS_pipe2 as u32 => unsafe {
            raw_syscall::syscall2(libc::SYS_pipe2, args[0], args[1])
        },
        // Filesystem sync
        nr if nr == libc::SYS_sync as u32 => unsafe { raw_syscall::syscall0(libc::SYS_sync) },
        _ => unreachable!("is_micro_local returned true for unknown syscall {syscall_nr}"),
    }
}
```

**Step 3: Wire the fast-path into `micro_handle_syscall`**

In `litebox_micro/src/handler.rs`, modify `micro_handle_syscall` (line 300) to check `is_micro_local` before `submit_and_wait`. Insert after the execve check (line 308) and before the `submit_and_wait` call (line 310):

```rust
    // Micro-local fast-path: syscalls that central always stamps EXEC_LOCAL
    // with zero work. Execute directly without any ring-buffer round-trip.
    #[allow(clippy::cast_possible_truncation)]
    let nr = args.nr as u32;
    if is_micro_local(nr) {
        // Special case: brk is micro-local only post-execve (guest_brk != 0).
        // Pre-execve brk still needs the real kernel brk via the same local path.
        if nr == libc::SYS_brk as u32 {
            let state = unsafe { crate::state::global_micro_state() };
            let current = state.guest_brk.load(core::sync::atomic::Ordering::Acquire);
            if current != 0 {
                return unsafe { crate::local_exec::execute_micro_local(nr, &args.args) };
            }
            // Pre-execve: fall through to central round-trip.
        } else {
            return unsafe { crate::local_exec::execute_micro_local(nr, &args.args) };
        }
    }
```

Wait — `brk` is not in the `is_micro_local` match. Handle it separately:

```rust
    // Micro-local fast-path: syscalls that central always stamps EXEC_LOCAL
    // with zero work. Execute directly without any ring-buffer round-trip.
    #[allow(clippy::cast_possible_truncation)]
    let nr = args.nr as u32;
    if is_micro_local(nr) {
        return unsafe { crate::local_exec::execute_micro_local(nr, &args.args) };
    }

    // brk fast-path: post-execve, brk is entirely managed by micro's
    // guest_brk watermark. Central does zero work for brk.
    if nr == libc::SYS_brk as u32 {
        let state = unsafe { crate::state::global_micro_state() };
        let current = state.guest_brk.load(core::sync::atomic::Ordering::Acquire);
        if current != 0 {
            return unsafe { crate::local_exec::execute_micro_local(nr, &args.args) };
        }
        // Pre-execve: fall through to central round-trip.
    }
```

And add `SYS_brk` to `execute_micro_local` as well (copy the existing brk handler from `execute_locally`).

**Step 4: Build and verify compilation**

Run: `cargo build -p litebox_micro`
Expected: Compiles without errors or warnings.

**Step 5: Run existing unit tests**

Run: `cargo nextest run -p litebox_micro`
Expected: All existing tests pass.

**Step 6: Commit**

```bash
git add litebox_micro/src/handler.rs litebox_micro/src/local_exec.rs
git commit -m "feat: add micro-local fast-path to skip ring-buffer round-trip for stateless syscalls"
```

---

### Task 2: Run clippy and fix any warnings

**Files:**
- Modify: `litebox_micro/src/handler.rs`, `litebox_micro/src/local_exec.rs` (if needed)

**Step 1: Run clippy**

Run: `cargo clippy -p litebox_micro`
Expected: No new warnings. If there are warnings about unused match arms in `execute_locally` (since those syscalls now go through `execute_micro_local` instead), that's fine — they remain as fallback for the `EXEC_LOCAL` path from central.

**Step 2: Fix any warnings and commit if needed**

---

### Task 3: Build in release mode and run the syscall benchmark

**Step 1: Build everything in release**

Run: `cargo build --release -p litebox_micro -p litebox_launcher && cargo build --release -p litebox_central`
Expected: Clean build.

**Step 2: Run the `syscall` benchmark (getpid loop) — this is the primary target**

Run:
```bash
cd /workspace/litebox-mu/dev_bench/unixbench
python3 run_unixbench.py --mode both --release --benchmarks syscall --duration 10 --iterations 3
```

Expected: Significant improvement in micro's `syscall` benchmark score (was 190,423 lps). The getpid loop should now skip the ring buffer entirely.

**Step 3: Run the full 10-benchmark regression**

Run:
```bash
cd /workspace/litebox-mu/dev_bench/unixbench
python3 run_unixbench.py --mode micro --release --benchmarks dhry2reg whetstone-double pipe syscall spawn execl context1 fstime shell1 shell8 --duration 10 --iterations 1
```

Expected: All 10 benchmarks produce nonzero scores. `syscall` should improve dramatically. CPU-bound benchmarks (`dhry2reg`, `whetstone-double`) should be similar. Other benchmarks may improve slightly due to fewer round-trips during setup (signal handlers, getpid calls, etc.).

**Step 4: Record before/after numbers in commit message or design doc**

---

### Task 4: Update design doc with fast-path description and new benchmark numbers

**Files:**
- Modify: `docs/design/micro-litebox.md`

**Step 1: Add a "Micro-Local Fast-Path" subsection under Implementation**

Describe the optimization: which syscalls are in the micro-local set, the flow change (skip ring buffer entirely), and the performance impact.

**Step 2: Update the benchmark results table with new numbers**

**Step 3: Commit**

```bash
git add docs/design/micro-litebox.md
git commit -m "docs: update design doc with micro-local fast-path and new benchmark results"
```
