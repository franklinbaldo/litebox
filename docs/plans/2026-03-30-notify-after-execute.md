# Notify-After-Execute Pattern Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add fire-and-forget notifications from micro to central for stateful micro-local syscalls, ensuring central can track all guest-visible state for fork reconstruction.

**Architecture:** Micro executes Tier 2 syscalls locally (they must run in micro's process), then publishes a one-way SQ notification with a new `NOTIFY_ONLY` flag. Central reads the notification, updates its per-process state tracking, and skips writing a CQ response. This gives micro-local performance without breaking central's state invariants.

**Tech Stack:** Rust, litebox_ipc shared-memory ring, litebox_central server, litebox_micro handler

---

## Background: Three-Tier Syscall Classification

### Tier 1 — Silent micro-local (no notification)
Stateless or memory-only state (fork-copies correctly):
`getpid`, `getppid`, `getuid`, `getgid`, `geteuid`, `getegid`, `nanosleep`, `clock_nanosleep`, `arch_prctl`, `set_tid_address`, `set_robust_list`, `rseq`, `rt_sigsuspend`, `mincore`, `sync`, `brk`

### Tier 2 — Notify-after-execute (fire-and-forget)
Must execute in micro, creates state central needs:
`rt_sigaction`, `rt_sigprocmask`, `sigaltstack`, `alarm`, `pipe2`, `wait4`

### Tier 3 — Full round-trip (unchanged)
Everything else (fdtable ops, vfs, network, mmap, fork, execve, etc.)

---

## Task 1: Add NOTIFY_ONLY SQ flag to IPC crate

**Files:**
- Modify: `litebox_ipc/src/ring.rs:31-38` (sq_flags module)

**Step 1: Add the new flag constant**

In `litebox_ipc/src/ring.rs`, add to the `sq_flags` module:

```rust
/// This entry is a one-way notification — central should process it
/// but NOT write a CQ entry or wake the sender.
pub const NOTIFY_ONLY: u16 = 1 << 3;
```

**Step 2: Run tests**

Run: `cargo nextest run -p litebox_ipc`
Expected: PASS (additive change)

**Step 3: Commit**

```bash
git add litebox_ipc/src/ring.rs
git commit -m "feat(ipc): add NOTIFY_ONLY SQ flag for fire-and-forget notifications"
```

---

## Task 2: Add notify_central() function in micro handler

**Files:**
- Modify: `litebox_micro/src/handler.rs` (add `notify_central` function)

**Step 1: Implement notify_central**

Add a new function alongside `report_local_result`:

```rust
/// Send a fire-and-forget notification to central.
///
/// Publishes an SQ entry with the `NOTIFY_ONLY` flag. Central will process
/// the notification (update state tracking) but will NOT write a CQ response.
/// Micro returns immediately without waiting.
///
/// # Safety
///
/// - `tls` must point to a valid, initialized `MicroTls`.
/// - The ring buffer referenced by the TLS must be valid and properly mapped.
#[allow(clippy::cast_possible_truncation)]
pub(crate) unsafe fn notify_central(
    tls: *mut MicroTls,
    syscall_nr: u32,
    args: &[u64; 6],
) {
    let micro = unsafe { &*(*tls).micro };
    let (header, sq_entries, _cq_entries) = unsafe { ring_ptrs(micro.ring_base, &micro.layout) };

    let seq = unsafe { (*tls).seq_counter };
    unsafe { (*tls).seq_counter += 1 };

    let thread_slot = unsafe { (*tls).thread_slot as u16 };

    let slot_idx = unsafe { sq_acquire_slot(header) };
    let entry = unsafe { &mut *sq_entries.add(slot_idx as usize) };

    entry.seq = seq;
    entry.syscall_nr = syscall_nr;
    entry.thread_slot = thread_slot;
    entry.flags = sq_flags::NOTIFY_ONLY;
    entry.args = *args;
    entry.data_offset = 0;
    entry.data_len = 0;

    sq_publish(entry);
    header.sq_notify.fetch_add(1, core::sync::atomic::Ordering::Release);
    futex_wake(&header.sq_notify);
    // No CQ wait — fire and forget.
}
```

**Step 2: Run tests**

Run: `cargo nextest run -p litebox_micro`
Expected: PASS (new function not yet called)

**Step 3: Commit**

```bash
git add litebox_micro/src/handler.rs
git commit -m "feat(micro): add notify_central() for fire-and-forget SQ notifications"
```

---

## Task 3: Central skips CQ for NOTIFY_ONLY entries

**Files:**
- Modify: `litebox_central/src/server.rs:91-186` (main `run()` loop)

**Step 1: Add NOTIFY_ONLY check to the main loop**

In the `run()` method, after dispatching, check if the entry has `NOTIFY_ONLY` set. If so, skip CQ push and thread wake:

```rust
// After the dispatch (handle_control_message / handle_syscall):
let is_notify_only = entry.flags & sq_flags::NOTIFY_ONLY != 0;

if is_notify_only {
    // Notification-only entry: central processed it, but no CQ response.
    // Just advance the SQ head and continue.
    sq_advance_head(header, entry);
    if self.primary_task.is_exiting() {
        break;
    }
    continue;
}

// Existing CQ push + thread wake code follows...
```

**Step 2: Run tests**

Run: `cargo build -p litebox_central`
Expected: PASS (compiles, no behavioral change yet — no NOTIFY_ONLY entries are sent)

**Step 3: Commit**

```bash
git add litebox_central/src/server.rs
git commit -m "feat(central): skip CQ response for NOTIFY_ONLY SQ entries"
```

---

## Task 4: Add notification control messages to IPC

**Files:**
- Modify: `litebox_ipc/src/messages.rs` (add new MSG_* constants)

**Step 1: Add notification message types**

Add new control message constants for each Tier 2 notification:

```rust
/// Notification: micro executed rt_sigaction locally.
/// args[0] = signum, args[1] = handler address, args[2] = sa_flags,
/// args[3] = sa_mask, args[4] = result (0 or -errno).
pub const MSG_NOTIFY_SIGACTION: u32 = MSG_BASE + 6;

/// Notification: micro executed rt_sigprocmask locally.
/// args[0] = how (SIG_BLOCK/UNBLOCK/SETMASK), args[1] = new mask bits,
/// args[2] = result.
pub const MSG_NOTIFY_SIGPROCMASK: u32 = MSG_BASE + 7;

/// Notification: micro executed sigaltstack locally.
/// args[0] = ss_sp, args[1] = ss_size, args[2] = ss_flags, args[3] = result.
pub const MSG_NOTIFY_SIGALTSTACK: u32 = MSG_BASE + 8;

/// Notification: micro executed alarm locally.
/// args[0] = seconds requested, args[1] = return value (remaining seconds).
pub const MSG_NOTIFY_ALARM: u32 = MSG_BASE + 9;

/// Notification: micro executed pipe2 locally.
/// args[0] = fd[0] (read end), args[1] = fd[1] (write end),
/// args[2] = flags, args[3] = result (0 or -errno).
pub const MSG_NOTIFY_PIPE2: u32 = MSG_BASE + 10;

/// Notification: micro executed wait4 locally.
/// args[0] = pid arg, args[1] = returned pid, args[2] = status,
/// args[3] = options, args[4] = result.
pub const MSG_NOTIFY_WAIT4: u32 = MSG_BASE + 11;
```

**Step 2: Run tests**

Run: `cargo nextest run -p litebox_ipc`
Expected: PASS

**Step 3: Commit**

```bash
git add litebox_ipc/src/messages.rs
git commit -m "feat(ipc): add MSG_NOTIFY_* control messages for Tier 2 syscalls"
```

---

## Task 5: Add ProcessNotificationState to central

**Files:**
- Create: `litebox_central/src/notification_state.rs`
- Modify: `litebox_central/src/server.rs` (add state field to Server, integrate with dispatch)

**Step 1: Create notification state structures**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Per-process state tracked from Tier 2 fire-and-forget notifications.
//!
//! Central records these so it can reconstruct guest-visible state when
//! forking micro.

use litebox_ipc::ring::MAX_THREADS;

/// Signal action as reported by micro via MSG_NOTIFY_SIGACTION.
#[derive(Clone, Copy, Default)]
pub(crate) struct SignalAction {
    pub handler: u64,
    pub flags: u64,
    pub mask: u64,
}

/// Alternate signal stack as reported by micro via MSG_NOTIFY_SIGALTSTACK.
#[derive(Clone, Copy, Default)]
pub(crate) struct AltStack {
    pub sp: u64,
    pub size: u64,
    pub flags: u64,
}

/// Pipe created by micro via MSG_NOTIFY_PIPE2.
#[derive(Clone, Copy)]
pub(crate) struct MicroPipe {
    pub read_fd: i32,
    pub write_fd: i32,
    pub flags: i32,
}

/// Per-process notification state.
///
/// Updated by central's notification handler when it receives Tier 2
/// fire-and-forget messages from micro. Used for fork reconstruction.
pub(crate) struct ProcessNotificationState {
    /// Signal disposition table (indexed by signal number, 0-63).
    pub signal_actions: [Option<SignalAction>; 64],

    /// Per-thread signal mask (indexed by thread_slot).
    pub signal_masks: [u64; MAX_THREADS],

    /// Per-thread alternate signal stack.
    pub alt_stacks: [Option<AltStack>; MAX_THREADS],

    /// Pending alarm in seconds, or 0 if none.
    pub alarm_seconds: u32,

    /// Pipes created by micro (not tracked in shim's fdtable).
    pub micro_pipes: Vec<MicroPipe>,

    /// Children reaped by micro via wait4: (pid, exit_status).
    pub reaped_children: Vec<(i32, i32)>,
}

impl Default for ProcessNotificationState {
    fn default() -> Self {
        Self {
            signal_actions: [None; 64],
            signal_masks: [0; MAX_THREADS],
            alt_stacks: [None; MAX_THREADS],
            alarm_seconds: 0,
            micro_pipes: Vec::new(),
            reaped_children: Vec::new(),
        }
    }
}
```

**Step 2: Add field to Server struct**

In `server.rs`, add a `notification_state: RefCell<ProcessNotificationState>` field to the `Server` struct and initialize it in the constructor.

**Step 3: Run tests**

Run: `cargo build -p litebox_central`
Expected: PASS

**Step 4: Commit**

```bash
git add litebox_central/src/notification_state.rs litebox_central/src/server.rs
git commit -m "feat(central): add ProcessNotificationState for Tier 2 state tracking"
```

---

## Task 6: Central notification dispatch handler

**Files:**
- Modify: `litebox_central/src/server.rs` (handle_control_message, add notification processing)

**Step 1: Add notification handling to handle_control_message**

Add match arms for each MSG_NOTIFY_* message that update `ProcessNotificationState`:

```rust
MSG_NOTIFY_SIGACTION => {
    let signum = entry.args[0] as usize;
    let result = entry.args[4] as i64;
    if result == 0 && signum < 64 {
        let mut state = self.notification_state.borrow_mut();
        state.signal_actions[signum] = Some(SignalAction {
            handler: entry.args[1],
            flags: entry.args[2],
            mask: entry.args[3],
        });
    }
    0
}
MSG_NOTIFY_SIGPROCMASK => {
    let how = entry.args[0] as i32;
    let new_mask = entry.args[1];
    let result = entry.args[2] as i64;
    if result == 0 {
        let slot = entry.thread_slot as usize;
        let mut state = self.notification_state.borrow_mut();
        match how {
            libc::SIG_BLOCK => state.signal_masks[slot] |= new_mask,
            libc::SIG_UNBLOCK => state.signal_masks[slot] &= !new_mask,
            libc::SIG_SETMASK => state.signal_masks[slot] = new_mask,
            _ => {}
        }
    }
    0
}
MSG_NOTIFY_SIGALTSTACK => {
    let result = entry.args[3] as i64;
    if result == 0 {
        let slot = entry.thread_slot as usize;
        let mut state = self.notification_state.borrow_mut();
        state.alt_stacks[slot] = Some(AltStack {
            sp: entry.args[0],
            size: entry.args[1],
            flags: entry.args[2],
        });
    }
    0
}
MSG_NOTIFY_ALARM => {
    let mut state = self.notification_state.borrow_mut();
    state.alarm_seconds = entry.args[0] as u32;
    0
}
MSG_NOTIFY_PIPE2 => {
    let result = entry.args[3] as i64;
    if result == 0 {
        let mut state = self.notification_state.borrow_mut();
        state.micro_pipes.push(MicroPipe {
            read_fd: entry.args[0] as i32,
            write_fd: entry.args[1] as i32,
            flags: entry.args[2] as i32,
        });
    }
    0
}
MSG_NOTIFY_WAIT4 => {
    let returned_pid = entry.args[1] as i32;
    let status = entry.args[2] as i32;
    if returned_pid > 0 {
        let mut state = self.notification_state.borrow_mut();
        state.reaped_children.push((returned_pid, status));
    }
    0
}
```

**Step 2: Run tests**

Run: `cargo build -p litebox_central`
Expected: PASS

**Step 3: Commit**

```bash
git add litebox_central/src/server.rs
git commit -m "feat(central): dispatch Tier 2 notifications and update ProcessNotificationState"
```

---

## Task 7: Convert Tier 2 syscalls in micro to notify-after-execute

**Files:**
- Modify: `litebox_micro/src/handler.rs` (split is_micro_local into tier 1 and tier 2)
- Modify: `litebox_micro/src/local_exec.rs` (update execute_micro_local)

**Step 1: Split is_micro_local into two functions**

```rust
/// Tier 1: Syscalls that execute locally with NO notification to central.
/// These create no state, or only state that lives in micro's memory.
pub(crate) fn is_tier1_micro_local(nr: u32) -> bool {
    matches!(
        i64::from(nr),
        libc::SYS_getpid | libc::SYS_getppid
        | libc::SYS_getuid | libc::SYS_getgid
        | libc::SYS_geteuid | libc::SYS_getegid
        | libc::SYS_nanosleep | libc::SYS_clock_nanosleep
        | libc::SYS_arch_prctl | libc::SYS_set_tid_address
        | libc::SYS_set_robust_list | libc::SYS_rseq
        | libc::SYS_rt_sigsuspend
        | libc::SYS_mincore
        | libc::SYS_sync
    )
}

/// Tier 2: Syscalls that execute locally but MUST notify central of the
/// state change for fork reconstruction.
pub(crate) fn is_tier2_notify(nr: u32) -> bool {
    matches!(
        i64::from(nr),
        libc::SYS_rt_sigaction | libc::SYS_rt_sigprocmask
        | libc::SYS_sigaltstack | libc::SYS_alarm
        | libc::SYS_pipe2 | libc::SYS_wait4
    )
}
```

**Step 2: Update micro_handle_syscall dispatch**

Replace the single `is_micro_local` check with:

```rust
// Tier 1: silent micro-local (no notification).
if is_tier1_micro_local(nr) {
    return unsafe { crate::local_exec::execute_micro_local(nr, &args.args) };
}

// Tier 2: execute locally, then notify central.
if is_tier2_notify(nr) {
    let result = unsafe { crate::local_exec::execute_micro_local(nr, &args.args) };
    let notify_nr = crate::local_exec::tier2_notify_message(nr);
    let notify_args = crate::local_exec::tier2_notify_args(nr, &args.args, result);
    unsafe { notify_central(tls, notify_nr, &notify_args) };
    return result;
}
```

**Step 3: Add tier2_notify_message and tier2_notify_args helper functions**

In `local_exec.rs`:

```rust
/// Map a Tier 2 syscall number to its MSG_NOTIFY_* control message number.
pub(crate) fn tier2_notify_message(nr: u32) -> u32 {
    match i64::from(nr) {
        libc::SYS_rt_sigaction => litebox_ipc::messages::MSG_NOTIFY_SIGACTION,
        libc::SYS_rt_sigprocmask => litebox_ipc::messages::MSG_NOTIFY_SIGPROCMASK,
        libc::SYS_sigaltstack => litebox_ipc::messages::MSG_NOTIFY_SIGALTSTACK,
        libc::SYS_alarm => litebox_ipc::messages::MSG_NOTIFY_ALARM,
        libc::SYS_pipe2 => litebox_ipc::messages::MSG_NOTIFY_PIPE2,
        libc::SYS_wait4 => litebox_ipc::messages::MSG_NOTIFY_WAIT4,
        _ => unreachable!("tier2_notify_message called for non-Tier-2 syscall {nr}"),
    }
}

/// Build the notification args for a Tier 2 syscall.
///
/// Packs the relevant arguments and result into a 6-element array
/// matching the MSG_NOTIFY_* protocol.
pub(crate) fn tier2_notify_args(nr: u32, args: &[u64; 6], result: i64) -> [u64; 6] {
    match i64::from(nr) {
        libc::SYS_rt_sigaction => {
            // signum, handler, flags, mask, result, 0
            // Note: handler/flags/mask must be read from the sigaction
            // struct pointed to by args[1]. For now, pass the pointer —
            // central cannot dereference it. This needs the HAS_DATA
            // pattern or shmem serialization. See "Known limitation" below.
            [args[0], args[1], args[2], 0, result.cast_unsigned(), 0]
        }
        libc::SYS_rt_sigprocmask => {
            // how, set_ptr (for mask bits), result, 0, 0, 0
            // Same limitation: set is a pointer in micro's address space.
            [args[0], args[1], result.cast_unsigned(), 0, 0, 0]
        }
        libc::SYS_sigaltstack => {
            // ss_sp, ss_size, ss_flags, result, 0, 0
            // Same pointer limitation.
            [args[0], args[1], 0, result.cast_unsigned(), 0, 0]
        }
        libc::SYS_alarm => {
            // seconds, remaining (return value), 0, 0, 0, 0
            [args[0], result.cast_unsigned(), 0, 0, 0, 0]
        }
        libc::SYS_pipe2 => {
            // read_fd, write_fd, flags, result, 0, 0
            // fds must be read from the int[2] pointed to by args[0]
            // after the syscall succeeds.
            let (fd0, fd1) = if result == 0 {
                let fds_ptr = args[0] as *const i32;
                unsafe { (*fds_ptr as u64, *fds_ptr.add(1) as u64) }
            } else {
                (0, 0)
            };
            [fd0, fd1, args[1], result.cast_unsigned(), 0, 0]
        }
        libc::SYS_wait4 => {
            // pid_arg, returned_pid (result), status, options, 0, 0
            let status = if result > 0 {
                let status_ptr = args[1] as *const i32;
                if !status_ptr.is_null() {
                    unsafe { *status_ptr as u64 }
                } else {
                    0
                }
            } else {
                0
            };
            [args[0], result.cast_unsigned(), status, args[2], 0, 0]
        }
        _ => unreachable!(),
    }
}
```

**Step 4: Remove is_micro_local, update tests**

Remove the old `is_micro_local` function. Update the test `micro_local_covers_all_listed` to test both `is_tier1_micro_local` and `is_tier2_notify` separately.

**Step 5: Run tests**

Run: `cargo nextest run -p litebox_micro`
Expected: PASS

**Step 6: Commit**

```bash
git add litebox_micro/src/handler.rs litebox_micro/src/local_exec.rs
git commit -m "feat(micro): convert Tier 2 syscalls to notify-after-execute pattern"
```

---

## Task 8: Integration test — end-to-end notification

**Files:**
- Modify: `litebox_micro/src/local_exec.rs` (add integration test)

**Step 1: Write test that verifies pipe2 notification**

This is an integration test that runs micro+central and verifies that after a pipe2 syscall, central's ProcessNotificationState contains the pipe fds. This requires the full harness (launcher + central + micro), so it should use the existing benchmark infrastructure.

For now, a manual verification step:
1. Run the `pipe` benchmark with strace on central to verify MSG_NOTIFY_PIPE2 arrives
2. Add a debug log in central's notification handler

**Step 2: Run the pipe benchmark**

```bash
cd /workspace/litebox-mu/dev_bench/unixbench
python3 run_unixbench.py --mode micro --release --duration 10 --iterations 1 --benchmarks pipe
```

Expected: benchmark completes, performance is similar or better than before (we eliminated one CQ round-trip for the pipe2 setup call).

**Step 3: Commit**

```bash
git commit -m "test: verify notify-after-execute with pipe benchmark"
```

---

## Known Limitation: Pointer arguments in notifications

`rt_sigaction`, `rt_sigprocmask`, and `sigaltstack` take pointer arguments (e.g., `const struct sigaction *act`). These point into micro's address space, which central cannot dereference.

**Options (deferred to future task):**
1. **Copy to shmem data region**: Like the existing HAS_DATA pattern, serialize the struct into the data region before publishing the notification. Central reads from shmem.
2. **Read via /proc/pid/mem**: Central reads the struct from micro's memory via procfs.
3. **Extract key fields**: Micro extracts the essential fields (handler address, flags, mask) and packs them directly into the SQ args array (no pointers).

Option 3 is simplest and is what the `tier2_notify_args` implementation should eventually use. For the initial implementation, signal syscalls can remain as Tier 3 (full round-trip) until the serialization is implemented, while `alarm`, `pipe2`, and `wait4` (which don't have the pointer problem) move to Tier 2 immediately.

---

## Phased rollout

**Phase 1 (this plan):**
- IPC: NOTIFY_ONLY flag + MSG_NOTIFY_* constants
- Central: Skip CQ for NOTIFY_ONLY, ProcessNotificationState, notification dispatch
- Micro: notify_central(), Tier 2 for `alarm`, `pipe2`, `wait4` (no pointer args)
- Signal syscalls (`rt_sigaction`, `rt_sigprocmask`, `sigaltstack`) stay Tier 1 (silent micro-local) until shmem serialization is added

**Phase 2 (future):**
- Serialize signal syscall arguments into shmem data region
- Move `rt_sigaction`, `rt_sigprocmask`, `sigaltstack` to Tier 2
- Fork reconstruction protocol using ProcessNotificationState

**Phase 3 (future):**
- Eliminate MSG_LOCAL_RESULT for existing EXEC_LOCAL syscalls (separate optimization)
- Category B localizations (munmap, mprotect, madvise, etc.)
