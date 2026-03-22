# Replay All Syscalls Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Refactor RR to replay ALL syscalls from trace (like rr's PTRACE_SYSEMU), instead of only nondeterministic ones. This solves the blocking-syscall problem (nanosleep/poll/ppoll block during replay) and enables alarm/timer signal replay.

**Architecture:** During replay, only "structural" syscalls execute (memory management + process lifecycle + sigreturn). Everything else is skipped — return value and side-effect data are injected from the trace. During recording, every syscall's return value and side-effect data are captured.

**Tech Stack:** Rust, `no_std`, litebox_rr crate, `#[cfg(feature = "rr")]` feature flags.

---

### Structural syscalls (execute during replay)

These syscalls MUST execute during replay because they modify process/memory state:

- **Memory**: `mmap`, `mremap`, `munmap`, `mprotect`, `brk`, `madvise`
- **Process**: `exit`, `exit_group`, `clone`, `clone3`, `execve`
- **Signal frame**: `rt_sigreturn`, `sigreturn` (x86)

ALL other syscalls are replayed from trace.

---

### Task 1: Replace `is_nondeterministic()` with `is_structural()`

**Files:**
- Modify: `litebox_shim_linux/src/rr.rs`

**Step 1: Replace the function**

Delete `is_nondeterministic()` and `is_nondeterministic_arch()`. Add `is_structural()`:

```rust
/// Returns `true` if this syscall is structural and must execute even during
/// replay. These syscalls modify process memory layout or lifecycle state
/// that cannot be captured as simple return-value + side-effect bytes.
///
/// All other syscalls are replayed from trace (return value + side-effect
/// data injected, actual implementation skipped).
pub fn is_structural(syscall_nr: u32) -> bool {
    matches!(
        syscall_nr,
        nr::MMAP
            | nr::MREMAP
            | nr::MUNMAP
            | nr::MPROTECT
            | nr::BRK
            | nr::MADVISE
            | nr::EXIT
            | nr::EXIT_GROUP
            | nr::CLONE
            | nr::CLONE3
            | nr::EXECVE
            | nr::RT_SIGRETURN
    ) || is_structural_arch(syscall_nr)
}

#[cfg(target_arch = "x86_64")]
fn is_structural_arch(_syscall_nr: u32) -> bool {
    false
}

#[cfg(target_arch = "x86")]
fn is_structural_arch(syscall_nr: u32) -> bool {
    matches!(syscall_nr, nr::SIGRETURN)
}
```

Add the new syscall number constants to the `nr` module:

```rust
pub const MMAP: u32 = Sysno::mmap.id() as u32;
pub const MREMAP: u32 = Sysno::mremap.id() as u32;
pub const MUNMAP: u32 = Sysno::munmap.id() as u32;
pub const MPROTECT: u32 = Sysno::mprotect.id() as u32;
pub const BRK: u32 = Sysno::brk.id() as u32;
pub const MADVISE: u32 = Sysno::madvise.id() as u32;
pub const EXIT: u32 = Sysno::exit.id() as u32;
pub const EXIT_GROUP: u32 = Sysno::exit_group.id() as u32;
pub const CLONE: u32 = Sysno::clone.id() as u32;
pub const CLONE3: u32 = Sysno::clone3.id() as u32;
pub const EXECVE: u32 = Sysno::execve.id() as u32;
pub const RT_SIGRETURN: u32 = Sysno::rt_sigreturn.id() as u32;
#[cfg(target_arch = "x86")]
pub const SIGRETURN: u32 = Sysno::sigreturn.id() as u32;
```

**Step 2: Update the dispatch in `lib.rs`**

In `handle_syscall_request_record`: remove the `if rr::is_nondeterministic(syscall_nr)` check. Record ALL syscalls unconditionally (structural ones too — the trace needs to be complete so replay can validate event ordering).

```rust
#[cfg(feature = "rr")]
fn handle_syscall_request_record(&self, ctx: &mut litebox_common_linux::PtRegs) {
    let syscall_nr = rr::get_syscall_nr(ctx);

    // Execute the syscall normally.
    let return_value = match self.do_syscall(ctx) {
        Ok(v) => v,
        Err(err) => (err.as_neg() as isize).reinterpret_as_unsigned(),
    };

    // Write return value to guest context.
    rr::set_return_value(ctx, return_value);

    // Capture any side-effect data written to guest memory.
    let data = rr::capture_side_effects(syscall_nr, ctx, return_value);

    // Record the event.
    #[allow(clippy::cast_possible_wrap)]
    let result_i64 = return_value as isize as i64;
    self.global
        .rr_state
        .record_event(syscall_nr, result_i64, data);
}
```

In `handle_syscall_request_replay`: invert the logic — structural syscalls execute, everything else replays.

```rust
#[cfg(feature = "rr")]
fn handle_syscall_request_replay(&self, ctx: &mut litebox_common_linux::PtRegs) {
    let syscall_nr = rr::get_syscall_nr(ctx);

    if rr::is_structural(syscall_nr) {
        // Structural syscall — execute normally, but still consume
        // the trace event to keep the replay cursor in sync.
        self.handle_syscall_request_normal(ctx);
        // Consume and validate the trace event (ignore recorded data).
        match self.global.rr_state.replay_event(syscall_nr) {
            Ok(_event) => {}
            Err(e) => panic!("replay divergence on structural syscall: {e:?}"),
        }
        return;
    }

    // Non-structural — replay from trace.
    match self.global.rr_state.replay_event(syscall_nr) {
        Ok(event) => {
            if !event.data.is_empty() {
                rr::inject_side_effects(syscall_nr, ctx, &event.data);
            }
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let return_value = event.result as usize;
            rr::set_return_value(ctx, return_value);
        }
        Err(e) => {
            panic!("replay error: {e:?}");
        }
    }
}
```

**Step 3: Verify**

Run: `cargo build --features rr -p litebox_shim_linux`
Expected: Compiles with no errors.

Run: `cargo clippy --features rr -p litebox_shim_linux`
Expected: No warnings.

---

### Task 2: Add missing side-effect capture for newly-replayed syscalls

**Files:**
- Modify: `litebox_shim_linux/src/rr.rs`

Add new syscall number constants to `nr` module and expand `capture_side_effects` and `inject_side_effects` for syscalls that write to guest memory.

**New nr constants needed:**

```rust
// Signal syscalls
pub const RT_SIGPROCMASK: u32 = Sysno::rt_sigprocmask.id() as u32;
pub const RT_SIGACTION: u32 = Sysno::rt_sigaction.id() as u32;
pub const SIGALTSTACK: u32 = Sysno::sigaltstack.id() as u32;

// Process info syscalls
pub const GETRLIMIT: u32 = Sysno::getrlimit.id() as u32;
pub const PRLIMIT64: u32 = Sysno::prlimit64.id() as u32;
pub const PRCTL: u32 = Sysno::prctl.id() as u32;
pub const SCHED_GETAFFINITY: u32 = Sysno::sched_getaffinity.id() as u32;
pub const CLOCK_GETRES: u32 = Sysno::clock_getres.id() as u32;
pub const CLOCK_NANOSLEEP: u32 = Sysno::clock_nanosleep.id() as u32;

// Network syscalls
pub const RECVFROM: u32 = Sysno::recvfrom.id() as u32;
pub const ACCEPT: u32 = Sysno::accept.id() as u32;  // if exists
pub const ACCEPT4: u32 = Sysno::accept4.id() as u32;
pub const GETSOCKOPT: u32 = Sysno::getsockopt.id() as u32;
pub const GETSOCKNAME: u32 = Sysno::getsockname.id() as u32;
pub const GETPEERNAME: u32 = Sysno::getpeername.id() as u32;
pub const SOCKETPAIR: u32 = Sysno::socketpair.id() as u32;

// Blocking I/O
pub const PPOLL: u32 = Sysno::ppoll.id() as u32;
pub const PSELECT6: u32 = Sysno::pselect6.id() as u32;
pub const EPOLL_PWAIT: u32 = Sysno::epoll_pwait.id() as u32;

// Misc
pub const IOCTL: u32 = Sysno::ioctl.id() as u32;
pub const CAPGET: u32 = Sysno::capget.id() as u32;
pub const GET_ROBUST_LIST: u32 = Sysno::get_robust_list.id() as u32;
```

For each new syscall, add capture/inject arms following the existing pattern. Key cases:

**Simple fixed-size output buffers** (capture = read N bytes at argX, inject = write N bytes at argX):
- `rt_sigprocmask`: arg2, 8 bytes (SigSet)
- `rt_sigaction`: arg2, 32 bytes on x86_64 / 20 bytes on x86 (SigAction)
- `sigaltstack`: arg1, 24 bytes on x86_64 / 12 bytes on x86 (SigAltStack)
- `getrlimit`: arg1, `2 * size_of::<usize>()` bytes (Rlimit)
- `prlimit64`: arg3, 16 bytes (Rlimit64)
- `clock_getres`: arg1, 16 bytes (timespec)
- `socketpair`: arg3, 8 bytes (two i32s) — already captured by pipe2 pattern
- `get_robust_list`: arg1, `size_of::<usize>()` bytes (pointer), arg2 = `size_of::<usize>()` bytes (len)

**Variable-size output buffers** (need return value or arg to compute size):
- `epoll_pwait`: arg1, `return_value * 12` bytes (EpollEvent array)
- `sched_getaffinity`: arg2, `return_value` bytes (cpuset mask)
- `recvfrom`: arg1, `return_value` bytes (buf) + addr/addrlen (complex — use flat capture)
- `accept`/`accept4`: addr/addrlen (use flat capture)
- `getsockopt`: arg3, variable bytes (optval) + arg4, 4 bytes (optlen)
- `getsockname`/`getpeername`: arg1/arg2, variable bytes (addr + addrlen)

**Scattered writes** (ppoll revents, pselect fd_sets):
- `ppoll`: Capture the entire pollfd array (`nfds * 8` bytes at arg0). This captures more than just revents, but it's simpler and correct.
- `pselect`: Capture each non-null fd_set (`ceil(nfds / (bits_per_usize)) * size_of::<usize>()` bytes). Concatenate all 3 fd_sets into one data blob.

**ioctl sub-commands**: The ioctl number is encoded in arg1. Need to match on common TCGETS/TIOCGWINSZ patterns. For unknown ioctls, capture nothing (they return ENOTTY or don't write).

**Tricky cases**:
- `clock_nanosleep`: Only writes `remain` on EINTR+relative. Check return value is -EINTR before capturing.
- `capget`: Version-dependent sizes. Read header.version from arg0 to determine data size.
- `prctl/PR_GET_NAME`: Sub-command is arg0. Only PR_GET_NAME (16) writes to memory.

**Strategy for addr/addrlen patterns (accept, getsockname, getpeername, recvfrom):**
For simplicity, use a flat capture approach:
1. After syscall, read the `addrlen` output (4 bytes at addrlen pointer)
2. Read `actual_len` bytes at addr pointer
3. Concatenate: `[addrlen_bytes (4)] + [addr_bytes (actual_len)]`
On inject: split data, write addrlen then addr.

**Step 1: Add all new nr constants**
**Step 2: Add capture arms for each new syscall**
**Step 3: Add inject arms for each new syscall**
**Step 4: Verify compilation**

Run: `cargo build --features rr -p litebox_shim_linux`
Run: `cargo clippy --features rr -p litebox_shim_linux`

---

### Task 3: Verify existing tests still pass

**Step 1: Run unit tests**

Run: `cargo nextest run -p litebox_rr`
Expected: 13 tests pass.

**Step 2: Run integration tests**

Run: `cargo nextest run -p litebox_runner_linux_userland --features rr -- rr`
Expected: `test_rr_record_replay_hello`, `test_rr_record_replay_signal`, `test_rr_record_replay_sigint` all pass.

**Step 3: Run full test suite**

Run: `cargo nextest run --features rr`
Expected: No regressions.

---

### Task 4: Add alarm.c integration test

**Files:**
- Modify: `litebox_runner_linux_userland/tests/run.rs`

**Step 1: Add the test**

```rust
#[cfg(feature = "rr")]
#[test]
fn test_rr_record_replay_alarm() {
    let test_bin = compile_c_test("alarm.c");
    let trace_path = test_bin.with_extension("trace");

    // Record
    let record_output = Runner::new(&test_bin)
        .runner_arg("--rr-record")
        .runner_arg(trace_path.to_str().unwrap())
        .run();
    assert!(record_output.status.success(), "record failed: {}", String::from_utf8_lossy(&record_output.stderr));

    // Replay
    let replay_output = Runner::new(&test_bin)
        .runner_arg("--rr-replay")
        .runner_arg(trace_path.to_str().unwrap())
        .run();
    assert!(replay_output.status.success(), "replay failed: {}", String::from_utf8_lossy(&replay_output.stderr));

    // Stdout should match
    assert_eq!(record_output.stdout, replay_output.stdout, "stdout mismatch");
}
```

**Step 2: Run the test**

Run: `cargo nextest run -p litebox_runner_linux_userland --features rr -- test_rr_record_replay_alarm`
Expected: PASS

---

### Task 5: Final verification and commit

**Step 1: Format**
Run: `cargo fmt`

**Step 2: Clippy (with and without rr)**
Run: `cargo clippy --all-targets`
Run: `cargo clippy --all-targets --features rr`

**Step 3: Full test suite**
Run: `cargo nextest run --features rr`

**Step 4: Commit**
```bash
git add -A
git commit -m "feat(rr): replay all non-structural syscalls from trace

Refactor RR to replay ALL syscalls from trace instead of only
nondeterministic ones, matching rr's PTRACE_SYSEMU approach. Only
structural syscalls (memory management, process lifecycle, sigreturn)
execute during replay. This solves the blocking-syscall problem where
nanosleep/poll/ppoll blocked during replay, preventing alarm/timer
signal delivery.

- Replace is_nondeterministic() with is_structural() (inverted logic)
- Record every syscall during recording (not just nondeterministic)
- Add side-effect capture for ~20 additional syscalls
- Add alarm.c integration test for SIGALRM + sleep/poll replay"
```
