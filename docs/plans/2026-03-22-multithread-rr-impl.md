# Multithreaded Record-Replay Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Extend litebox-rr to record and replay multithreaded guest programs by serializing threads at syscall boundaries.

**Architecture:** Trace format v2 adds `tid` and `kind` fields to events. A `RunCoordinator` serializes thread execution — only one thread runs guest code at a time. Blocking syscalls produce entry/exit event pairs. During replay, the coordinator enforces the recorded thread ordering.

**Tech Stack:** Rust, `no_std`, litebox_rr crate, `#[cfg(feature = "rr")]` feature flags.

**Design doc:** `docs/plans/2026-03-22-multithread-rr.md`

---

### Task 1: Add `EventKind` enum and `tid`/`kind` fields to trace format

**Files:**
- Modify: `litebox_rr/src/trace.rs`

**Step 1: Add `EventKind` enum**

After the `SIGNAL_DELIVERY_NR` constant (line 19), add:

```rust
/// The kind of a trace event.
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum EventKind {
    /// Non-blocking syscall completed in a single event.
    Complete = 0,
    /// Blocking syscall entered; run token released. `result` field is unused.
    Entry = 1,
    /// Blocking syscall resumed; run token reacquired. `result` + side-effects captured.
    Exit = 2,
    /// Async signal delivery event.
    Signal = 3,
}

impl EventKind {
    /// Convert a raw byte to an [`EventKind`].
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Complete),
            1 => Some(Self::Entry),
            2 => Some(Self::Exit),
            3 => Some(Self::Signal),
            _ => None,
        }
    }
}
```

**Step 2: Bump `TRACE_VERSION` and update `Event` struct**

Change `TRACE_VERSION` from 1 to 2.

Update `Event` struct to add `tid: u32` and `kind: EventKind` fields.

Update `EVENT_FIXED_SIZE` from 24 to 32 (adding tid:4 + kind:1 + pad:3 = 8 bytes).

Update the doc comment wire format to:
```text
[0..8]              event_id:   u64 LE
[8..12]             syscall_nr: u32 LE
[12..20]            result:     i64 LE
[20..24]            data_len:   u32 LE
[24..28]            tid:        u32 LE
[28]                kind:       u8
[29..32]            pad:        [u8; 3] (zero)
[32..32+data_len]   data:       [u8]
```

**Step 3: Update `Event::to_bytes()`**

After the `data_len` line, append:
```rust
buf.extend_from_slice(&self.tid.to_le_bytes());
buf.push(self.kind as u8);
buf.extend_from_slice(&[0u8; 3]); // padding
```

**Step 4: Update `Event::from_bytes()`**

After parsing `data_len`, parse:
```rust
let tid = u32::from_le_bytes(data[24..28].try_into().unwrap());
let kind = EventKind::from_byte(data[28])
    .ok_or(TraceError::InvalidEventKind(data[28]))?;
// bytes [29..32] are padding, skip them
```

Add `InvalidEventKind(u8)` variant to `TraceError`.

Update the payload slice from `data[EVENT_FIXED_SIZE..total]` (now starts at 32).

**Step 5: Update `TraceHeader::from_bytes()` to accept version 1 or 2**

Change the version check from `version != TRACE_VERSION` to `version != 1 && version != 2`. Store the version in `TraceHeader` so the replayer knows which format to parse.

**Step 6: Update all tests in `trace.rs`**

Add `tid: 0, kind: EventKind::Complete` to all `Event` constructions in tests. Update `EVENT_FIXED_SIZE` assertions from 24 to 32.

**Step 7: Run tests**

Run: `cargo nextest run -p litebox_rr`
Expected: All tests pass

**Step 8: Commit**

```
git add litebox_rr/src/trace.rs
git commit -m "feat(litebox_rr): add EventKind enum and tid/kind fields to trace format v2"
```

---

### Task 2: Update Recorder to accept `tid` and `kind`

**Files:**
- Modify: `litebox_rr/src/recorder.rs`

**Step 1: Update `Recorder::record()` signature**

Change from:
```rust
pub fn record(&mut self, syscall_nr: u32, result: i64, data: Vec<u8>)
```
To:
```rust
pub fn record(&mut self, syscall_nr: u32, result: i64, data: Vec<u8>, tid: u32, kind: EventKind)
```

Update the `Event` construction inside to include `tid` and `kind`.

Import `EventKind` from `crate::trace`.

**Step 2: Add convenience method for backward compat**

Add a method for single-threaded recording that defaults `tid=0, kind=Complete`:
```rust
/// Record a syscall event with default tid=0 and kind=Complete.
/// Convenience for single-threaded recording.
pub fn record_simple(&mut self, syscall_nr: u32, result: i64, data: Vec<u8>) {
    self.record(syscall_nr, result, data, 0, EventKind::Complete);
}
```

**Step 3: Update all tests in `recorder.rs`**

Change all `recorder.record(nr, result, data)` calls to `recorder.record(nr, result, data, 0, EventKind::Complete)`. Update `Event` assertions to include `tid: 0, kind: EventKind::Complete`.

**Step 4: Run tests**

Run: `cargo nextest run -p litebox_rr`
Expected: All tests pass

**Step 5: Commit**

```
git commit -m "feat(litebox_rr): update Recorder to accept tid and kind parameters"
```

---

### Task 3: Update Replayer for v2 event format

**Files:**
- Modify: `litebox_rr/src/replayer.rs`

**Step 1: Update `peek_event_nr()` offset**

The `syscall_nr` field is still at `[8..12]` — unchanged. No change needed.

**Step 2: Update `peek_event_result()` offset**

The `result` field is still at `[12..20]` — unchanged. No change needed.

**Step 3: Add `peek_event_tid()` method**

```rust
/// Peek at the `tid` field of the next event without consuming it.
/// Returns `None` if the trace is exhausted.
pub fn peek_event_tid(&self) -> Option<u32> {
    if self.offset >= self.data.len() {
        return None;
    }
    // tid is at bytes [24..28] within the v2 event.
    let start = self.offset + 24;
    if start + 4 > self.data.len() {
        return None;
    }
    Some(u32::from_le_bytes(
        self.data[start..start + 4].try_into().unwrap(),
    ))
}
```

**Step 4: Add `peek_event_kind()` method**

```rust
/// Peek at the `kind` field of the next event without consuming it.
/// Returns `None` if the trace is exhausted.
pub fn peek_event_kind(&self) -> Option<EventKind> {
    if self.offset >= self.data.len() {
        return None;
    }
    // kind is at byte [28] within the v2 event.
    let start = self.offset + 28;
    if start >= self.data.len() {
        return None;
    }
    EventKind::from_byte(self.data[start])
}
```

**Step 5: Store trace version in Replayer**

Add `version: u32` field to `Replayer`. Set it from `header.version` in `from_bytes()`. Add `pub fn version(&self) -> u32` accessor.

**Step 6: Update all tests in `replayer.rs`**

Update all `recorder.record(...)` calls to include `tid` and `kind`. Update all `Event` field assertions. Add a test for `peek_event_tid()` and `peek_event_kind()`.

**Step 7: Run tests**

Run: `cargo nextest run -p litebox_rr`
Expected: All tests pass

**Step 8: Commit**

```
git commit -m "feat(litebox_rr): update Replayer for v2 format with peek_event_tid/kind"
```

---

### Task 4: Update `lib.rs` re-exports

**Files:**
- Modify: `litebox_rr/src/lib.rs`

**Step 1: Add `EventKind` to re-exports**

Add `EventKind` to the `pub use trace::` line:
```rust
pub use trace::{Event, EventKind, SIGNAL_DELIVERY_NR, TraceArch, TraceError, TraceHeader};
```

**Step 2: Run all litebox_rr tests**

Run: `cargo nextest run -p litebox_rr`
Expected: All 14+ tests pass

**Step 3: Commit**

```
git commit -m "feat(litebox_rr): re-export EventKind from crate root"
```

---

### Task 5: Update shim `RRState` to pass `tid` and `kind`

**Files:**
- Modify: `litebox_shim_linux/src/rr.rs`
- Modify: `litebox_shim_linux/src/lib.rs`
- Modify: `litebox_shim_linux/src/wait.rs`

**Step 1: Update `RRState::record_event()` signature**

Change from:
```rust
pub fn record_event(&self, syscall_nr: u32, result: i64, data: Vec<u8>)
```
To:
```rust
pub fn record_event(&self, syscall_nr: u32, result: i64, data: Vec<u8>, tid: u32, kind: litebox_rr::EventKind)
```

Update the inner call from `recorder.lock().record(syscall_nr, result, data)` to `recorder.lock().record(syscall_nr, result, data, tid, kind)`.

**Step 2: Update `RRState::record_signal()` to accept `tid`**

Change from:
```rust
pub fn record_signal(&self, signal_nr: i32, siginfo_bytes: Vec<u8>)
```
To:
```rust
pub fn record_signal(&self, signal_nr: i32, siginfo_bytes: Vec<u8>, tid: u32)
```

Update the inner call to pass `tid` and `EventKind::Signal`.

**Step 3: Add `peek_event_tid()` and `peek_event_kind()` to `RRState`**

```rust
pub fn peek_event_tid(&self) -> Option<u32> {
    self.replayer
        .as_ref()
        .and_then(|r| r.lock().peek_event_tid())
}

pub fn peek_event_kind(&self) -> Option<litebox_rr::EventKind> {
    self.replayer
        .as_ref()
        .and_then(|r| r.lock().peek_event_kind())
}
```

**Step 4: Update callers in `lib.rs`**

In `handle_syscall_request_record()` (line 595), update the `record_event` call to pass `tid: 0, kind: EventKind::Complete` (hardcoded for now — single-threaded still works):

```rust
self.global
    .rr_state
    .record_event(syscall_nr, result_i64, data, 0, litebox_rr::EventKind::Complete);
```

**Step 5: Update callers in `wait.rs`**

In the signal recording block (line 86), update:
```rust
self.global
    .rr_state
    .record_signal(signal.as_i32(), alloc::vec![], 0);
```

**Step 6: Run all tests**

Run: `cargo nextest run --features rr -p litebox_runner_linux_userland -E 'test(rr)'`
Expected: All 5 RR tests pass (hello, signal, sigint, alarm, mmap)

Run: `cargo nextest run -p litebox_rr`
Expected: All unit tests pass

Run: `cargo clippy --all-targets --features rr`
Expected: No warnings

**Step 7: Commit**

```
git commit -m "feat(rr): thread RRState API through tid and EventKind for v2 format"
```

---

### Task 6: Implement `RunCoordinator`

**Files:**
- Modify: `litebox_shim_linux/src/rr.rs`

This task adds the `RunCoordinator` struct but does NOT integrate it into the syscall dispatch yet. Pure infrastructure.

**Step 1: Add imports**

At the top of `rr.rs`, add `use alloc::collections::BTreeSet;`.

**Step 2: Add `RunCoordinator` and `CoordinatorState`**

After the `RRState` impl block (after line 180), add:

```rust
/// Serializes guest thread execution so only one thread runs at a time.
///
/// During recording, any runnable thread may be granted the token.
/// During replay, only the thread matching the next trace event's tid
/// is granted the token.
pub struct RunCoordinator {
    inner: Mutex<CoordinatorInner>,
}

struct CoordinatorInner {
    /// TID of the thread currently holding the run token, or 0 if idle.
    current_tid: i32,
    /// Threads that are runnable (waiting for the token).
    runnable: BTreeSet<i32>,
    /// Threads that are blocked inside a syscall (released the token).
    blocked: BTreeSet<i32>,
    /// When true, all threads should exit.
    shutdown: bool,
}

impl RunCoordinator {
    /// Create a new coordinator. The initial thread is registered and
    /// immediately granted the token.
    pub fn new(initial_tid: i32) -> Self {
        let mut runnable = BTreeSet::new();
        runnable.insert(initial_tid);
        Self {
            inner: Mutex::new(CoordinatorInner {
                current_tid: initial_tid,
                runnable,
                blocked: BTreeSet::new(),
                shutdown: false,
            }),
        }
    }

    /// Register a new thread as runnable. It will not run until granted
    /// the token.
    pub fn register_thread(&self, tid: i32) {
        let mut inner = self.inner.lock();
        inner.runnable.insert(tid);
    }

    /// Remove a thread from all sets (on exit).
    pub fn remove_thread(&self, tid: i32) {
        let mut inner = self.inner.lock();
        inner.runnable.remove(&tid);
        inner.blocked.remove(&tid);
        if inner.current_tid == tid {
            inner.current_tid = 0;
        }
    }

    /// Release the run token after a syscall completes. The caller must
    /// hold the token (current_tid == tid).
    pub fn release_token(&self, tid: i32) {
        let mut inner = self.inner.lock();
        assert_eq!(inner.current_tid, tid, "release_token: tid mismatch");
        inner.current_tid = 0;
    }

    /// Wait until this thread is granted the run token.
    /// Returns false if the coordinator has been shut down.
    pub fn acquire_token(&self, tid: i32) -> bool {
        let mut inner = self.inner.lock();
        loop {
            if inner.shutdown {
                return false;
            }
            if inner.current_tid == tid {
                return true;
            }
            // Spin-wait: release the lock, yield, re-acquire.
            // TODO: Replace with condvar when available in no_std context.
            drop(inner);
            core::hint::spin_loop();
            inner = self.inner.lock();
        }
    }

    /// Grant the token to a specific thread (used by replay coordinator).
    pub fn grant_token(&self, tid: i32) {
        let mut inner = self.inner.lock();
        assert_eq!(inner.current_tid, 0, "grant_token: token already held");
        inner.current_tid = tid;
    }

    /// Pick the next runnable thread and grant it the token.
    /// Used during recording (any runnable thread is fine).
    /// Returns the tid that was granted, or 0 if no threads are runnable.
    pub fn grant_next_runnable(&self) -> i32 {
        let mut inner = self.inner.lock();
        assert_eq!(inner.current_tid, 0, "grant_next: token already held");
        if let Some(&tid) = inner.runnable.iter().next() {
            inner.current_tid = tid;
            tid
        } else {
            0
        }
    }

    /// Move a thread from runnable to blocked (entering a blocking syscall).
    pub fn enter_blocking(&self, tid: i32) {
        let mut inner = self.inner.lock();
        assert_eq!(inner.current_tid, tid, "enter_blocking: not token holder");
        inner.runnable.remove(&tid);
        inner.blocked.insert(tid);
        inner.current_tid = 0;
    }

    /// Move a thread from blocked to runnable (woke up from blocking syscall).
    pub fn exit_blocking(&self, tid: i32) {
        let mut inner = self.inner.lock();
        inner.blocked.remove(&tid);
        inner.runnable.insert(tid);
    }

    /// Signal all threads to shut down.
    pub fn shutdown(&self) {
        let mut inner = self.inner.lock();
        inner.shutdown = true;
    }

    /// Check if a thread is currently registered (runnable or blocked).
    pub fn is_registered(&self, tid: i32) -> bool {
        let inner = self.inner.lock();
        inner.runnable.contains(&tid) || inner.blocked.contains(&tid) || inner.current_tid == tid
    }
}
```

**Step 3: Add `coordinator` field to `RRState`**

Add `coordinator: Option<RunCoordinator>` to `RRState`. Initialize it as `None` in `new()` and `new_replay()` for now (will be wired up in Task 7).

**Step 4: Run clippy and tests**

Run: `cargo clippy --all-targets --features rr`
Run: `cargo nextest run --features rr -p litebox_runner_linux_userland -E 'test(rr)'`
Expected: Clean clippy, all 5 RR tests pass

**Step 5: Commit**

```
git commit -m "feat(rr): add RunCoordinator for serializing thread execution"
```

---

### Task 7: Write multithreaded C test program

**Files:**
- Create: `litebox_runner_linux_userland/tests/threads_rr.c`
- Modify: `litebox_runner_linux_userland/tests/run.rs`

**Step 1: Write `threads_rr.c`**

A C program using pthreads that:
1. Spawns 2 worker threads
2. Each worker increments a shared atomic counter 1000 times
3. Main thread joins both workers
4. Verifies final counter == 2000
5. Exits 0 on success, 1 on failure

```c
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Multithreaded RR test: spawn threads, shared atomic counter, join.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdatomic.h>

#define NUM_THREADS 2
#define ITERS_PER_THREAD 1000

static atomic_int counter = 0;

static void *worker(void *arg) {
    (void)arg;
    for (int i = 0; i < ITERS_PER_THREAD; i++) {
        atomic_fetch_add(&counter, 1);
    }
    return NULL;
}

int main(void) {
    printf("Starting threads RR test...\n");

    pthread_t threads[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        int rc = pthread_create(&threads[i], NULL, worker, NULL);
        if (rc != 0) {
            fprintf(stderr, "FAIL: pthread_create returned %d\n", rc);
            return 1;
        }
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    int final_val = atomic_load(&counter);
    if (final_val != NUM_THREADS * ITERS_PER_THREAD) {
        fprintf(stderr, "FAIL: counter=%d, expected %d\n",
                final_val, NUM_THREADS * ITERS_PER_THREAD);
        return 1;
    }

    printf("threads_rr: PASS (counter=%d)\n", final_val);
    return 0;
}
```

**Step 2: Add integration test to `run.rs`**

```rust
/// Record a multithreaded test program (spawns 2 threads, shared atomic
/// counter, join), replay it, and verify successful completion.
#[cfg(feature = "rr")]
#[test]
fn test_rr_record_replay_threads() {
    let unique_name = "threads_rr";
    let target = common::compile("./tests/threads_rr.c", unique_name, true, false);
    let dir = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let trace_path = dir.join("threads_rr.trace");

    // --- Record ---
    Runner::new(Backend::Rewriter, &target, &format!("{unique_name}_record"))
        .runner_arg("--rr-record")
        .runner_arg(&trace_path)
        .run();

    assert!(trace_path.exists(), "trace file was not created");

    // --- Replay ---
    Runner::new(Backend::Rewriter, &target, &format!("{unique_name}_replay"))
        .runner_arg("--rr-replay")
        .runner_arg(&trace_path)
        .run();
}
```

**Step 3: Commit (test will fail until serialization is wired up — that's expected)**

```
git commit -m "test(rr): add multithreaded record-replay test program

The test will fail until the RunCoordinator is integrated into the
syscall dispatch path. This is the target test for Tasks 8+."
```

---

### Task 8: Wire up RunCoordinator in recording path

**Files:**
- Modify: `litebox_shim_linux/src/rr.rs`
- Modify: `litebox_shim_linux/src/lib.rs`

**Step 1: Initialize RunCoordinator in `RRState`**

In `RRState::new(RRMode::Record)`, create the coordinator with `initial_tid` passed as a parameter. Update `new()` signature to accept `initial_tid: i32`. Same for `new_replay()`.

**Step 2: Add `tid()` helper to `Task`**

In `lib.rs`, add a helper that returns the current task's tid as `u32`:
```rust
#[cfg(feature = "rr")]
fn rr_tid(&self) -> u32 {
    self.tid as u32
}
```

**Step 3: Update `handle_syscall_request_record()`**

Replace the current single-path recording with:
1. Get `tid = self.rr_tid()`
2. Execute the syscall normally via `do_syscall(ctx)`
3. Capture side-effects
4. Record the event with `tid` and `kind = Complete`
5. Release the run token
6. Wait to reacquire the token (coordinator picks next thread)

For now, skip the blocking syscall entry/exit split — all syscalls are COMPLETE events. Blocking support comes in Task 9.

**Step 4: Update `handle_syscall_request_replay()`**

Add coordinator integration:
1. Token is already held (acquired in `prepare_to_run_guest` or after previous syscall)
2. Process the syscall (structural or replay from trace)
3. Release token
4. Reacquire token (coordinator grants based on next event's tid)

**Step 5: Update `prepare_to_run_guest` in `wait.rs`**

After signal processing, before returning to guest: ensure the token is held. This is where the coordinator grants the token for the first syscall of a newly scheduled thread.

**Step 6: Run all existing single-threaded RR tests**

Run: `cargo nextest run --features rr -p litebox_runner_linux_userland -E 'test(rr)'`
Expected: hello, signal, sigint, alarm, mmap all still pass (single-threaded, tid=constant)

**Step 7: Commit**

```
git commit -m "feat(rr): wire RunCoordinator into record/replay syscall dispatch"
```

---

### Task 9: Blocking syscall entry/exit split (recording)

**Files:**
- Modify: `litebox_shim_linux/src/rr.rs`
- Modify: `litebox_shim_linux/src/lib.rs`

**Step 1: Add `is_potentially_blocking()` function to `rr.rs`**

```rust
pub fn is_potentially_blocking(syscall_nr: u32) -> bool {
    matches!(
        syscall_nr,
        nr::FUTEX
            | nr::NANOSLEEP
            | nr::CLOCK_NANOSLEEP
            | nr::READ
            | nr::READV
            | nr::WRITE
            | nr::WRITEV
            | nr::RECVFROM
            | nr::RECVMSG
            | nr::SENDTO
            | nr::SENDMSG
            | nr::POLL
            | nr::PPOLL
            | nr::EPOLL_WAIT
            | nr::ACCEPT
            | nr::ACCEPT4
            | nr::CONNECT
            | nr::RT_SIGTIMEDWAIT
    )
}
```

Add the missing constants to `mod nr`.

**Step 2: Implement blocking-aware recording in `handle_syscall_request_record()`**

For potentially blocking syscalls:
1. Record ENTRY event `(tid, syscall_nr, result=0, data=[], kind=Entry)`
2. Release token via `coordinator.enter_blocking(tid)`
3. Execute `do_syscall(ctx)` — thread blocks here
4. Thread wakes up, calls `coordinator.exit_blocking(tid)`
5. Wait for coordinator to grant token back: `coordinator.acquire_token(tid)`
6. Capture side-effects, record EXIT event `(tid, syscall_nr, result, data, kind=Exit)`

For non-blocking syscalls: unchanged (single COMPLETE event).

**Step 3: Run single-threaded RR tests**

Run: `cargo nextest run --features rr -p litebox_runner_linux_userland -E 'test(rr)'`
Expected: All 5 pass (blocking syscalls in alarm test now produce entry/exit pairs but replay still works since single-threaded replay doesn't use the coordinator yet)

**Step 4: Commit**

```
git commit -m "feat(rr): split blocking syscalls into entry/exit event pairs during recording"
```

---

### Task 10: Replay coordinator — tid-driven thread scheduling

**Files:**
- Modify: `litebox_shim_linux/src/lib.rs`
- Modify: `litebox_shim_linux/src/rr.rs`

**Step 1: Update replay dispatch to use tid from trace**

In `handle_syscall_request_replay()`:
1. After processing a syscall, release token
2. Peek at next event's tid via `peek_event_tid()`
3. Grant token to that tid via `coordinator.grant_token(next_tid)`

**Step 2: Handle ENTRY/EXIT events during replay**

When the coordinator sees an ENTRY event for a tid:
- The thread "enters" the blocking syscall (but doesn't actually block — it's replayed)
- Immediately look at the next event. If it's for a different tid, grant that tid the token.
- When the EXIT event for the original tid comes up, grant it the token and inject the recorded result.

**Step 3: Thread creation during replay**

When `clone`/`clone3` structural syscall completes:
- The new thread spawns and calls `coordinator.register_thread(child_tid)`
- New thread calls `coordinator.acquire_token(child_tid)` — blocks until scheduled

**Step 4: Run the multithreaded test**

Run: `cargo nextest run --features rr -p litebox_runner_linux_userland -E 'test(threads_rr)'`
Expected: PASS

Run all RR tests to verify no regressions:
Run: `cargo nextest run --features rr -p litebox_runner_linux_userland -E 'test(rr)'`
Expected: All 6 pass

**Step 5: Commit**

```
git commit -m "feat(rr): implement replay coordinator with tid-driven thread scheduling"
```

---

### Task 11: Signal delivery with tid

**Files:**
- Modify: `litebox_shim_linux/src/wait.rs`
- Modify: `litebox_shim_linux/src/rr.rs`

**Step 1: Pass actual tid when recording signals**

In `wait.rs` signal recording block, replace `0` with `self.tid as u32`:
```rust
self.global
    .rr_state
    .record_signal(signal.as_i32(), alloc::vec![], self.tid as u32);
```

**Step 2: During replay, verify signal tid matches**

When replaying signal events, the coordinator ensures the correct thread is running (it already holds the token). The signal's tid in the trace should match the current thread's tid. Add an assertion.

**Step 3: Run all RR tests**

Run: `cargo nextest run --features rr -p litebox_runner_linux_userland -E 'test(rr)'`
Expected: All 6 pass

**Step 4: Commit**

```
git commit -m "feat(rr): record and verify signal delivery tid"
```

---

### Task 12: Final verification and cleanup

**Step 1: Run full test suite**

Run: `cargo fmt`
Run: `cargo clippy --all-targets --features rr`
Run: `cargo nextest run --features rr -p litebox_rr`
Run: `cargo nextest run --features rr -p litebox_runner_linux_userland -E 'test(rr)'`
Expected: All clean, all pass

**Step 2: Run full project tests for regressions**

Run: `cargo nextest run --features rr`
Expected: No new failures (pre-existing failures are known: test_node_with_rewriter, test_tun_*, nine_p)

**Step 3: Commit any final cleanup**

```
git commit -m "chore(rr): final cleanup for multithreaded record-replay"
```
