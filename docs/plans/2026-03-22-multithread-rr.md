# Multithreaded Record-Replay Design

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Extend litebox-rr to record and replay multithreaded guest programs. Threads are serialized at syscall and signal boundaries — only one thread runs guest code at a time. This eliminates shared-memory races without hardware performance counters.

**Key insight:** LiteBox is a library OS. Guest threads can only share memory with other guest threads in the same process. There is no external process (PulseAudio, X server, GPU driver, vdso) writing into the guest address space. Serializing at syscall boundaries gives complete determinism over shared memory.

**Tech Stack:** Rust, `no_std`, litebox_rr crate, `#[cfg(feature = "rr")]` feature flags.

---

## Background: LiteBox Threading Model

- **1:1 threading**: each guest thread maps to a host OS thread (`std::thread::spawn` in `spawn_thread`)
- **No internal scheduler**: the host kernel's CFS scheduler handles thread scheduling; `sched_yield` is a no-op
- **Thread creation**: `clone`/`clone3` require `CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FILES` (threads only, no fork)
- **TID assignment**: `GlobalState::next_thread_id` is an `AtomicI32` that increments
- **Signal delivery**: only at `prepare_to_run_guest` and `check_for_interrupt` — never mid-instruction in guest code
- **Guest preemption**: `interrupt_thread` sends a real-time signal via `pthread_kill`, used only for `exit_group` and signal delivery — not scheduling

## Design Decisions

### Serialization at syscall boundaries

Since LiteBox only delivers signals at syscall boundaries and guest threads share memory only with each other, serializing thread execution at syscall boundaries provides complete determinism. No hardware performance counters are needed.

Between syscall boundaries, exactly one thread runs guest code. All loads, stores, and atomic operations are totally ordered by the trace.

### Explicit coordinator thread

An explicit coordinator thread manages which guest thread runs next:

- **Recording**: after each syscall completes, the coordinator picks the next runnable thread (any policy — round-robin, FIFO, etc.) and records which thread ran
- **Replay**: the coordinator reads the next trace event's `tid` and wakes only that thread

### TID preservation via serialized `next_thread_id`

`clone`/`clone3` are structural syscalls. Since all clones are serialized (one thread at a time), `next_thread_id` increments in the same order during record and replay, producing identical TIDs. No patching needed — determinism follows from serialization.

### No changes to structural/non-structural classification

The `is_structural()` list stays the same. Futex does not need to be structural during replay — threads are serialized by the coordinator, so there is no real concurrency and no real blocking. `futex_wait` just returns the recorded result.

---

## Trace Format v2

The event header grows from 20 bytes to 28 bytes:

```
v1 (current):  event_id(4) + syscall_nr(4) + result(8) + data_len(4) = 20 bytes
v2 (proposed): event_id(4) + syscall_nr(4) + result(8) + data_len(4) + tid(4) + kind(1) + pad(3) = 28 bytes
```

New fields:

| Field | Type | Description |
|-------|------|-------------|
| `tid` | `u32` | Thread ID that produced this event |
| `kind` | `u8` | Event kind (see below) |
| `pad` | `[u8; 3]` | Reserved, zero-filled, for alignment |

Event kinds:

| Value | Name | Description |
|-------|------|-------------|
| 0 | `COMPLETE` | Non-blocking syscall, single event |
| 1 | `ENTRY` | Blocking syscall entered, run token released. `result` field unused. |
| 2 | `EXIT` | Blocking syscall resumed, run token reacquired. `result` + side-effects captured. |
| 3 | `SIGNAL` | Signal delivery (replaces `SIGNAL_DELIVERY_NR` sentinel, now with `tid`) |

The trace header gains a version field to distinguish v1 (single-threaded) from v2 (multi-threaded). Single-threaded programs produce v2 traces with constant `tid` and `kind = 0`.

---

## Run Token and Serialization

### Data structure

```rust
struct RunCoordinator {
    mutex: Mutex<CoordinatorState>,
    condvar: Condvar,
}

struct CoordinatorState {
    /// TID of the thread currently holding the run token, or 0 if no thread holds it.
    current_tid: i32,
    /// Set of TIDs that are runnable (not blocked in a syscall).
    runnable: BTreeSet<i32>,
    /// Set of TIDs that are blocked inside a syscall (released the token).
    blocked: BTreeSet<i32>,
}
```

### Thread lifecycle

1. **Thread creation**: `clone`/`clone3` spawns a new host thread. The new thread registers itself as runnable and immediately blocks waiting for the coordinator.
2. **Running**: coordinator sets `current_tid = tid` and notifies the condvar. The selected thread wakes, executes `prepare_to_run_guest`, returns to guest code, runs until the next syscall.
3. **Syscall completion**: thread records the event, sets `current_tid = 0`, and notifies the condvar. Coordinator picks the next thread.
4. **Thread exit**: `exit` syscall executes, thread removes itself from runnable set and terminates.
5. **Process exit**: `exit_group` executes, coordinator marks all remaining threads as terminated. Replay ends.

### Blocking syscalls

Blocking syscalls (futex_wait, nanosleep, read on blocking fd, poll, etc.) must release the run token while blocked, otherwise other threads cannot make progress (deadlock).

Protocol:

1. Thread enters blocking syscall, records an `ENTRY` event `(tid, syscall_nr, kind=ENTRY)`
2. Thread releases run token: moves itself from `runnable` to `blocked`, sets `current_tid = 0`, notifies condvar
3. Thread blocks inside `do_syscall` (futex_wait, nanosleep, etc.)
4. Thread wakes up (futex_wake from another thread, timer expiry, etc.)
5. Thread reacquires run token: moves itself from `blocked` to `runnable`, waits for coordinator to schedule it
6. Thread records an `EXIT` event `(tid, syscall_nr, result, side_effects, kind=EXIT)`
7. Thread returns to guest

During replay, blocking syscalls are non-structural — the thread doesn't actually block. The coordinator sees the `ENTRY` event, marks the thread as "logically blocked", processes other threads' events, and when the `EXIT` event appears in the trace, wakes the thread to receive the recorded result.

### Identifying blocking syscalls

A syscall is blocking if it enters the wait system (`wait_cx`, `check_for_interrupt`). The set:

- `futex` (WAIT, WAIT_BITSET)
- `nanosleep` / `clock_nanosleep`
- `read` / `readv` / `recvfrom` / `recvmsg` (on blocking fds)
- `write` / `writev` / `sendto` / `sendmsg` (on blocking fds, buffer full)
- `poll` / `ppoll` / `epoll_wait`
- `accept` / `accept4`
- `connect` (blocking)
- `rt_sigtimedwait`

Note: whether a syscall actually blocks depends on runtime conditions (fd readiness, futex value, timeout). The `ENTRY`/`EXIT` split only occurs when the syscall actually blocks. If a "potentially blocking" syscall completes immediately (e.g., `read` on a ready fd), it produces a single `COMPLETE` event.

---

## Signal Delivery

The existing signal recording mechanism is unchanged in structure. Each signal event now carries the `tid` of the delivering thread.

- **Thread-directed signals** (`tgkill`): structural, queue into target thread's `pending` set. Target receives at next `prepare_to_run_guest` when the coordinator schedules it.
- **Process-wide signals** (`kill`): structural, queue into `shared_pending`. Whichever thread the coordinator schedules next drains it. The trace records which `tid` delivered it.
- **Timer signals** (`SIGALRM`): arrive as host signals, drained in `prepare_to_run_guest` by the currently running thread. Trace records which `tid`.

Determinism: since only one thread runs at a time, signal delivery is fully determined by the coordinator's scheduling order, which is captured in the trace.

---

## Thread Lifecycle Details

### `clone`/`clone3` (structural)

1. Parent thread holds run token, executes `clone`/`clone3`
2. New host thread spawns, registers with coordinator as runnable, blocks
3. Parent records the clone event `(tid=parent, nr=CLONE, result=child_tid, kind=COMPLETE)`
4. Parent continues (or coordinator schedules the child next, depending on what was recorded)

TIDs are deterministic: `next_thread_id` increments under serialization, same order in record and replay.

### `exit` (structural)

1. Thread holds run token, executes `exit`
2. Thread records exit event, removes itself from coordinator's runnable set
3. Host thread terminates
4. Coordinator never schedules this tid again

### `exit_group` (structural)

1. Thread holds run token, executes `exit_group`
2. `kill_other_threads()` sends interrupts to sibling threads — but they are all blocked waiting on the coordinator (not running guest code), so the interrupt is delivered when they next check
3. Coordinator marks all threads as terminated
4. Replay ends

### `set_tid_address` (non-structural)

Returns the thread's tid. Replayed from trace. Since tids match between record and replay, the recorded value is correct.

---

## What Doesn't Change

- `is_structural()` list: no additions or removals
- `capture_side_effects` / `inject_side_effects`: unchanged
- `mmap` MAP_FIXED replay: unchanged
- Single-threaded programs: still work, produce v2 traces with constant tid and kind=COMPLETE
- `execve` handling: re-executes the real binary (binary must be present and identical)

---

## Implementation Tasks

### Task 1: Trace format v2

**Files:** `litebox_rr/src/trace.rs`, `litebox_rr/src/recorder.rs`, `litebox_rr/src/replayer.rs`

- Add `tid: u32`, `kind: u8` fields to `Event`
- Add `EventKind` enum (Complete, Entry, Exit, Signal)
- Update serialization/deserialization (28-byte header)
- Add version field to `TraceHeader`
- Update `Recorder::record()` signature to accept `tid` and `kind`
- Update `Replayer::next_event()` to parse new fields
- Update `peek_event_nr()` and `peek_event_result()` for new offsets
- Add `peek_event_tid()` method
- Update all existing unit tests

### Task 2: Run token and coordinator infrastructure

**Files:** `litebox_shim_linux/src/rr.rs` (new `RunCoordinator` struct)

- Implement `RunCoordinator` with `Mutex<CoordinatorState>` and `Condvar`
- `acquire_token(tid)`: block until coordinator grants this tid the token
- `release_token(tid)`: release token, notify coordinator
- `register_thread(tid)`: add to runnable set
- `remove_thread(tid)`: remove from all sets
- `enter_blocking(tid)`: move from runnable to blocked, release token
- `exit_blocking(tid)`: move from blocked to runnable, wait for token
- Integrate into `RRState`: create coordinator when mode is Record or Replay

### Task 3: Recording integration — serialization and blocking split

**Files:** `litebox_shim_linux/src/lib.rs`, `litebox_shim_linux/src/rr.rs`

- Wrap `handle_syscall_request_record` with token acquire/release
- Identify blocking syscalls at entry (before `do_syscall`)
- For blocking syscalls: record ENTRY event, release token before blocking, reacquire after wake, record EXIT event
- For non-blocking syscalls: record single COMPLETE event (current behavior + tid)
- Pass `tid` to all `record_event` calls

### Task 4: Replay coordinator

**Files:** `litebox_shim_linux/src/lib.rs`, `litebox_shim_linux/src/rr.rs`

- During replay, coordinator reads `peek_event_tid()` to determine next thread
- Wake only the matching thread via `acquire_token`
- For ENTRY events: mark thread as logically blocked, skip to next event
- For EXIT events: wake the blocked thread, inject recorded result
- For COMPLETE events: wake thread, let it handle the syscall (structural or replay from trace)
- For SIGNAL events: deliver to the specified tid

### Task 5: Thread lifecycle — clone, exit, exit_group

**Files:** `litebox_shim_linux/src/lib.rs`, `litebox_shim_linux/src/syscalls/process.rs`

- On `clone`/`clone3`: new thread calls `register_thread(child_tid)` and blocks on coordinator
- On `exit`: thread calls `remove_thread(tid)` after executing
- On `exit_group`: coordinator terminates all remaining threads
- Verify TID determinism: assert `child_tid` matches trace during replay

### Task 6: Signal delivery with tid

**Files:** `litebox_shim_linux/src/wait.rs`, `litebox_shim_linux/src/rr.rs`

- Pass `tid` when recording signal events
- During replay, coordinator ensures the correct thread delivers each signal
- Update signal replay injection to use `tid` from trace event

### Task 7: Multithreaded test program

**Files:** `litebox_runner_linux_userland/tests/threads_rr.c`, `litebox_runner_linux_userland/tests/run.rs`

- Write C test program: spawn 2-3 threads, use futex for synchronization, shared memory counter, join all threads, verify result
- Write `test_rr_record_replay_threads` integration test
- Verify record produces a valid trace and replay completes with same exit code
