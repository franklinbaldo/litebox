# Phase F: Mach Semaphore Emulation

## Overview

Implement 4 Mach semaphore traps that macOS binaries use for inter-thread
synchronization: `semaphore_signal_trap`, `semaphore_signal_all_trap`,
`semaphore_wait_trap`, and `semaphore_timedwait_trap`.

These are direct traps (not MIG messages via `mach_msg`), dispatched via
negative x16 values.

## Architecture

### No changes to `litebox` crate

All semaphore-specific logic lives in `litebox_shim_macos`. The existing
`Waker` / `WaitContext` API from `litebox::event::wait` is used as the
blocking primitive — no new code is added to the core `litebox` crate.

### MachSemaphoreManager

A new module `litebox_shim_macos/src/semaphore.rs` provides:

```rust
pub(crate) struct MachSemaphoreManager {
    semaphores: litebox::sync::Mutex<Platform, BTreeMap<u32, SemaphoreState>>,
}

struct SemaphoreState {
    count: i32,            // signed: negative means waiters blocked
    waiters: VecDeque<Waker<Platform>>,
}
```

The manager is stored as a field on `GlobalState`, shared across all threads.

### Lazy Creation

`semaphore_create` is a MIG call via `mach_msg_trap` (trap 31), which
currently returns `MACH_SEND_INVALID_DEST`. Rather than implementing the
full MIG protocol, semaphores are lazily created on first use: if a trap
references an unknown port name, a new semaphore with count=0 is
auto-created.

### Why not FutexManager

The existing `FutexManager` uses value-check-then-block semantics (wait only
if `*addr == expected_value`), which does not map cleanly to counting
semaphore semantics where the count is managed internally. Using `Waker`
directly is simpler and more correct.

## Traps

| Trap | Number (positive) | XNU x16 value | Signature | Behavior |
|------|-------------------|---------------|-----------|----------|
| `semaphore_signal_trap` | 36 | -36 | `(mach_port_name_t signal_name)` | Increment count. If count was < 0, pop one waiter and wake it. |
| `semaphore_signal_all_trap` | 37 | -37 | `(mach_port_name_t signal_name)` | Wake all waiters. Set count to max(count, 0). |
| `semaphore_wait_trap` | 39 | -39 | `(mach_port_name_t wait_name)` | Decrement count. If count < 0, push waker and block until woken. |
| `semaphore_timedwait_trap` | 40 | -40 | `(mach_port_name_t wait_name, unsigned int sec, clock_res_t nsec)` | Same as wait but with timeout. Returns `KERN_OPERATION_TIMED_OUT` (49) on timeout. |

### Return values

- `KERN_SUCCESS` (0) on success
- `KERN_OPERATION_TIMED_OUT` (49) when timedwait expires
- `KERN_ABORTED` (14) if wait is interrupted

### Register conventions (aarch64)

- x0 = port name (all 4 traps)
- x1 = seconds (timedwait only)
- x2 = nanoseconds (timedwait only)

## Files Modified

1. **`litebox_common_macos/src/syscall.rs`** — add 4 constants to `mod mach_trap`:
   - `SEMAPHORE_SIGNAL_TRAP: usize = 36`
   - `SEMAPHORE_SIGNAL_ALL_TRAP: usize = 37`
   - `SEMAPHORE_WAIT_TRAP: usize = 39`
   - `SEMAPHORE_TIMEDWAIT_TRAP: usize = 40`

2. **`litebox_shim_macos/src/semaphore.rs`** (new) — `MachSemaphoreManager`
   and `SemaphoreState`.

3. **`litebox_shim_macos/src/lib.rs`** — add `mod semaphore;`, add
   `semaphore_manager: semaphore::MachSemaphoreManager` field to
   `GlobalState`, initialize in `build()`.

4. **`litebox_shim_macos/src/syscalls/stubs.rs`** — add 4 match arms in
   `do_mach_trap()`. The wait traps use `self.wait_cx()` for blocking.

## Tests

1 C test file compiled with `compile_macho_dynamic`, run with
`run_macho_dynamic`, exit-code verification only:

- **`tests/mach_semaphore.c`** — Uses inline assembly to invoke semaphore
  traps directly (cannot use libc wrappers since `semaphore_create` goes
  through MIG). Tests:
  1. Signal then wait: signal a semaphore, then wait — should not block.
  2. Signal-all: signal-all on a semaphore with no waiters — should succeed.
  3. Timedwait with timeout: timedwait on a semaphore with 0 count and
     short timeout — should return `KERN_OPERATION_TIMED_OUT` (49).

1 corresponding test function appended to `tests/loader.rs`.

## Task Breakdown

1. Add 4 constants to `mod mach_trap`
2. Create `semaphore.rs` with `MachSemaphoreManager`
3. Wire into `GlobalState` + 4 match arms in `do_mach_trap()`
4. Add test (C file + Rust test function)
