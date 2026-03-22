# Async Signal Record/Replay Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Record asynchronous signal deliveries during RR recording and replay them deterministically at the same trace position.

**Architecture:** Async signals (SIGINT, SIGALRM, etc.) are recorded as events in the existing trace stream using a sentinel syscall number (`SIGNAL_DELIVERY_NR = 0xFFFF_FFFE`). During recording, after `process_signals()` delivers a signal, we record a signal event. During replay, we suppress host signal processing and instead inject recorded signals from the trace. Synchronous signals (SIGSEGV, SIGFPE, SIGBUS, SIGILL, SIGTRAP) are excluded — they re-trigger deterministically.

**Tech Stack:** Rust, `#![no_std]` with `alloc`, `litebox_rr` crate, `litebox_shim_linux` crate, `zerocopy` for `Siginfo` serialization.

---

### Task 1: Add `peek_event_nr()` to Replayer + signal event constant

**Files:**
- Modify: `litebox_rr/src/trace.rs` — add `SIGNAL_DELIVERY_NR` constant
- Modify: `litebox_rr/src/replayer.rs` — add `peek_event_nr()` method
- Modify: `litebox_rr/src/lib.rs` — re-export `SIGNAL_DELIVERY_NR`
- Test: `litebox_rr/src/replayer.rs` (inline tests)

**Step 1: Write the failing test in `litebox_rr/src/replayer.rs`**

Add to the `tests` module:

```rust
#[test]
fn test_replayer_peek_event_nr() {
    let mut recorder = Recorder::new(TraceArch::X86_64);
    recorder.record(42, 0, alloc::vec![]);
    recorder.record(crate::SIGNAL_DELIVERY_NR, 14, alloc::vec![0xAA; 128]);
    recorder.record(99, 1, alloc::vec![]);
    let bytes = recorder.finish();

    let mut replayer = Replayer::from_bytes(bytes).unwrap();

    // Peek should show 42 without consuming
    assert_eq!(replayer.peek_event_nr(), Some(42));
    assert_eq!(replayer.peek_event_nr(), Some(42)); // idempotent
    let _ = replayer.next_event().unwrap(); // consume

    // Peek should show signal sentinel
    assert_eq!(replayer.peek_event_nr(), Some(crate::SIGNAL_DELIVERY_NR));
    let _ = replayer.next_event().unwrap(); // consume

    // Peek should show 99
    assert_eq!(replayer.peek_event_nr(), Some(99));
    let _ = replayer.next_event().unwrap(); // consume

    // Exhausted
    assert_eq!(replayer.peek_event_nr(), None);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --package litebox_rr`
Expected: FAIL — `SIGNAL_DELIVERY_NR` doesn't exist, `peek_event_nr` doesn't exist.

**Step 3: Write minimal implementation**

In `litebox_rr/src/trace.rs`, add after the existing constants:

```rust
/// Sentinel syscall number used for signal delivery events in the trace.
/// This is well outside the range of real Linux syscall numbers.
pub const SIGNAL_DELIVERY_NR: u32 = 0xFFFF_FFFE;
```

In `litebox_rr/src/lib.rs`, add to re-exports:

```rust
pub use trace::SIGNAL_DELIVERY_NR;
```

In `litebox_rr/src/replayer.rs`, add method to `Replayer`:

```rust
/// Peek at the `syscall_nr` of the next event without consuming it.
/// Returns `None` if the trace is exhausted.
pub fn peek_event_nr(&self) -> Option<u32> {
    if self.offset >= self.data.len() {
        return None;
    }
    // syscall_nr is at bytes [8..12] within the event (after event_id).
    let start = self.offset + 8;
    if start + 4 > self.data.len() {
        return None;
    }
    Some(u32::from_le_bytes(
        self.data[start..start + 4].try_into().unwrap(),
    ))
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test --package litebox_rr`
Expected: PASS (all 13 tests including the new one).

**Step 5: Commit**

```
feat(litebox_rr): add SIGNAL_DELIVERY_NR sentinel and peek_event_nr()
```

---

### Task 2: Add `record_signal()` and `replay_signal()` to `RRState`

**Files:**
- Modify: `litebox_shim_linux/src/rr.rs` — add signal recording/replay methods

**Step 1: Add `record_signal()` method to `RRState`**

In `litebox_shim_linux/src/rr.rs`, in the `impl RRState` block, add:

```rust
/// Record a signal delivery event during recording mode.
///
/// `signal_nr` is the signal number (e.g., 14 for SIGALRM).
/// `siginfo_bytes` is the raw `Siginfo` struct serialized as bytes.
pub fn record_signal(&self, signal_nr: i32, siginfo_bytes: Vec<u8>) {
    if let Some(ref recorder) = self.recorder {
        recorder.lock().record(
            litebox_rr::SIGNAL_DELIVERY_NR,
            i64::from(signal_nr),
            siginfo_bytes,
        );
    }
}
```

**Step 2: Add `peek_is_signal()` method to `RRState`**

```rust
/// During replay, check if the next trace event is a signal delivery.
pub fn peek_is_signal(&self) -> bool {
    self.replayer
        .as_ref()
        .is_some_and(|r| r.lock().peek_event_nr() == Some(litebox_rr::SIGNAL_DELIVERY_NR))
}
```

**Step 3: Add `replay_signal()` method to `RRState`**

```rust
/// During replay, consume the next signal event from the trace.
/// Returns `(signal_nr, siginfo_bytes)`.
pub fn replay_signal(&self) -> Result<(i32, Vec<u8>), litebox_rr::ReplayError> {
    if let Some(ref replayer) = self.replayer {
        let event = replayer
            .lock()
            .expect_event(litebox_rr::SIGNAL_DELIVERY_NR)?;
        #[allow(clippy::cast_possible_truncation)]
        let signal_nr = event.result as i32;
        Ok((signal_nr, event.data))
    } else {
        Err(litebox_rr::ReplayError::EndOfTrace)
    }
}
```

**Step 4: Build to verify compilation**

Run: `cargo build --package litebox_shim_linux --features rr`
Expected: compiles with no errors.

**Step 5: Commit**

```
feat(rr): add record_signal/replay_signal to RRState
```

---

### Task 3: Add `is_synchronous_signal()` helper

**Files:**
- Modify: `litebox_shim_linux/src/rr.rs`

**Step 1: Add the helper function**

In `litebox_shim_linux/src/rr.rs`, add a public function:

```rust
/// Returns `true` if the signal is synchronous (caused deterministically by
/// an instruction) and does not need recording. These signals will re-trigger
/// naturally during replay from the same faulting instruction.
pub fn is_synchronous_signal(signal: litebox_common_linux::signal::Signal) -> bool {
    use litebox_common_linux::signal::Signal;
    matches!(
        signal,
        Signal::SIGSEGV | Signal::SIGBUS | Signal::SIGFPE | Signal::SIGILL | Signal::SIGTRAP
    )
}
```

**Step 2: Build**

Run: `cargo build --package litebox_shim_linux --features rr`
Expected: compiles.

**Step 3: Commit**

```
feat(rr): add is_synchronous_signal helper
```

---

### Task 4: Hook signal recording into `process_signals()`

This is the core recording change. We need to make `process_signals()` aware of RR mode
so it records each async signal delivery. The challenge is that `process_signals()` lives
in `syscalls/signal/mod.rs` while `RRState` is on `GlobalState`.

The cleanest approach: `process_signals()` already has access to `self` (a `Task`), which
has `self.global.rr_state`. We add recording calls inline in `process_signals()`.

**Files:**
- Modify: `litebox_shim_linux/src/syscalls/signal/mod.rs` — add recording in `process_signals()`

**Step 1: Add recording after each signal delivery in `process_signals()`**

In the `process_signals()` function at `litebox_shim_linux/src/syscalls/signal/mod.rs:554`,
after the `deliver_signal()` call succeeds, add recording logic. The signal delivery
branch currently looks like:

```rust
_ => {
    if let Err(DeliverFault) =
        self.signals.deliver_signal(signal, &siginfo, &action, ctx)
    {
        self.force_signal(Signal::SIGSEGV, signal == Signal::SIGSEGV);
    }
}
```

Change it to:

```rust
_ => {
    if let Err(DeliverFault) =
        self.signals.deliver_signal(signal, &siginfo, &action, ctx)
    {
        self.force_signal(Signal::SIGSEGV, signal == Signal::SIGSEGV);
    } else {
        // Record async signal deliveries for RR replay.
        #[cfg(feature = "rr")]
        if self.global.rr_state.mode() == crate::rr::RRMode::Record
            && !crate::rr::is_synchronous_signal(signal)
        {
            use zerocopy::IntoBytes as _;
            let siginfo_bytes = siginfo.as_bytes().to_vec();
            self.global
                .rr_state
                .record_signal(signal.as_i32(), siginfo_bytes);
        }
    }
}
```

**Step 2: Build**

Run: `cargo build --package litebox_shim_linux --features rr`
Expected: compiles. May need to add `zerocopy` import — check the file's existing imports.

**Step 3: Also build without rr feature**

Run: `cargo build --package litebox_shim_linux`
Expected: compiles (the `#[cfg(feature = "rr")]` block is compiled out).

**Step 4: Commit**

```
feat(rr): record async signal deliveries in process_signals
```

---

### Task 5: Hook signal replay into `prepare_to_run_guest()`

During replay, before returning to the guest, we need to check if the next trace
event is a signal delivery and inject it instead of processing real host signals.

**Files:**
- Modify: `litebox_shim_linux/src/wait.rs` — add replay signal injection in `prepare_to_run_guest()`

**Step 1: Modify `prepare_to_run_guest()`**

The current function at `litebox_shim_linux/src/wait.rs:38`:

```rust
pub(crate) fn prepare_to_run_guest(&self, ctx: &mut litebox_common_linux::PtRegs) -> bool {
    self.wait_state.0.prepare_to_run_guest(|| {
        use litebox::platform::SignalProvider as _;
        self.global.platform.take_pending_signals(|signal| {
            self.queue_signals(signal);
        });
        self.check_alarm_deadline();
        self.process_signals(ctx);
        !self.is_exiting()
    })
}
```

Change it to:

```rust
pub(crate) fn prepare_to_run_guest(&self, ctx: &mut litebox_common_linux::PtRegs) -> bool {
    self.wait_state.0.prepare_to_run_guest(|| {
        #[cfg(feature = "rr")]
        if self.global.rr_state.mode() == crate::rr::RRMode::Replay {
            // During replay, inject signals from the trace instead of
            // processing real host signals. Loop to handle multiple
            // consecutive signal events.
            while self.global.rr_state.peek_is_signal() {
                match self.global.rr_state.replay_signal() {
                    Ok((signal_nr, siginfo_bytes)) => {
                        crate::rr::inject_signal(self, signal_nr, &siginfo_bytes, ctx);
                    }
                    Err(e) => panic!("replay signal error: {e:?}"),
                }
            }
            return !self.is_exiting();
        }

        use litebox::platform::SignalProvider as _;
        self.global.platform.take_pending_signals(|signal| {
            self.queue_signals(signal);
        });
        self.check_alarm_deadline();
        self.process_signals(ctx);
        !self.is_exiting()
    })
}
```

**Step 2: Add `inject_signal()` to `rr.rs`**

In `litebox_shim_linux/src/rr.rs`, add:

```rust
/// During replay, deliver a recorded signal to the guest.
///
/// This looks up the guest's signal handler for the given signal and
/// invokes the shim's `deliver_signal()` with the recorded `Siginfo`.
pub fn inject_signal<FS: crate::ShimFS>(
    task: &crate::Task<FS>,
    signal_nr: i32,
    siginfo_bytes: &[u8],
    ctx: &mut litebox_common_linux::PtRegs,
) {
    use litebox_common_linux::signal::Signal;
    use zerocopy::FromBytes as _;

    let signal = Signal::try_from(signal_nr).expect("invalid signal number in trace");
    let siginfo = litebox_common_linux::signal::Siginfo::read_from_bytes(siginfo_bytes)
        .expect("invalid siginfo data in trace");

    task.replay_deliver_signal(signal, &siginfo, ctx);
}
```

**Step 3: Add `replay_deliver_signal()` to `Task` in signal/mod.rs**

This method needs to look up the handler and call `deliver_signal()`, mirroring
what `process_signals()` does for a single signal. Add to the `Task` impl in
`litebox_shim_linux/src/syscalls/signal/mod.rs`:

```rust
/// Deliver a single signal during RR replay.
///
/// Looks up the current handler and delivers the signal. This mirrors the
/// per-signal logic in `process_signals()` but for a single recorded signal.
#[cfg(feature = "rr")]
pub(crate) fn replay_deliver_signal(
    &self,
    signal: Signal,
    siginfo: &Siginfo,
    ctx: &mut PtRegs,
) {
    use litebox_common_linux::signal::{SIG_DFL, SIG_IGN};

    let action = self.signals.handlers.borrow().inner.lock()[signal].action;
    match action.sigaction {
        SIG_DFL => {
            match signal.default_disposition() {
                SignalDisposition::Terminate | SignalDisposition::Core | SignalDisposition::Stop => {
                    litebox::log_println!(
                        self.global.platform,
                        "-- Fatal signal {:?}: terminating task {}:{} (replay)",
                        signal,
                        self.pid,
                        self.tid,
                    );
                    self.exit_group(ExitStatus::Signal(signal));
                }
                SignalDisposition::Ignore | SignalDisposition::Continue => {}
            }
        }
        SIG_IGN => {}
        _ => {
            if let Err(DeliverFault) =
                self.signals.deliver_signal(signal, siginfo, &action, ctx)
            {
                self.force_signal(Signal::SIGSEGV, signal == Signal::SIGSEGV);
            }
        }
    }
}
```

**Step 4: Build both with and without rr**

Run: `cargo build --package litebox_shim_linux --features rr`
Run: `cargo build --package litebox_shim_linux`
Expected: both compile.

**Step 5: Commit**

```
feat(rr): replay async signals from trace in prepare_to_run_guest
```

---

### Task 6: Suppress host signal draining during replay in `check_for_interrupt()`

During replay, `check_for_interrupt()` also drains `pending_host_signals`. We
should suppress this to avoid spurious signal queuing during replay.

**Files:**
- Modify: `litebox_shim_linux/src/wait.rs` — gate host signal draining in `check_for_interrupt()`

**Step 1: Modify `check_for_interrupt()`**

Current code:

```rust
fn check_for_interrupt(&self) -> bool {
    use litebox::platform::SignalProvider as _;
    self.global.platform.take_pending_signals(|sig| {
        self.queue_signals(sig);
    });
    self.check_alarm_deadline();
    self.is_exiting() || self.has_pending_signals()
}
```

Change to:

```rust
fn check_for_interrupt(&self) -> bool {
    #[cfg(feature = "rr")]
    if self.global.rr_state.mode() == crate::rr::RRMode::Replay {
        // During replay, signals come from the trace, not from the host.
        // Don't drain host signals — they would cause divergence.
        return self.is_exiting();
    }

    use litebox::platform::SignalProvider as _;
    self.global.platform.take_pending_signals(|sig| {
        self.queue_signals(sig);
    });
    self.check_alarm_deadline();
    self.is_exiting() || self.has_pending_signals()
}
```

**Step 2: Build**

Run: `cargo build --package litebox_shim_linux --features rr`
Expected: compiles.

**Step 3: Commit**

```
feat(rr): suppress host signal draining during replay
```

---

### Task 7: Integration test with signal.c

**Files:**
- Modify: `litebox_runner_linux_userland/tests/run.rs` — add `test_rr_record_replay_signal`

**Step 1: Write the test**

Add to `run.rs` after the existing `test_rr_record_replay_hello`:

```rust
/// Record the signal test program (exercises SIGSEGV handler + recovery),
/// replay it, and verify identical stdout output.
#[cfg(feature = "rr")]
#[test]
fn test_rr_record_replay_signal() {
    let unique_name = "signal_rr";
    let target = common::compile("./tests/signal.c", unique_name, true, false);
    let dir = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let trace_path = dir.join("signal_rr.trace");

    // --- Record ---
    let record_output = Runner::new(Backend::Rewriter, &target, &format!("{unique_name}_record"))
        .runner_arg("--rr-record")
        .runner_arg(&trace_path)
        .output();

    assert!(trace_path.exists(), "trace file was not created");

    // --- Replay ---
    let replay_output = Runner::new(Backend::Rewriter, &target, &format!("{unique_name}_replay"))
        .runner_arg("--rr-replay")
        .runner_arg(&trace_path)
        .output();

    // --- Compare ---
    let record_str = String::from_utf8_lossy(&record_output);
    let replay_str = String::from_utf8_lossy(&replay_output);
    assert_eq!(
        record_str, replay_str,
        "Record and replay stdout differ.\n--- Record ---\n{record_str}\n--- Replay ---\n{replay_str}"
    );
}
```

Note: `signal.c` uses a synchronous SIGSEGV, which re-triggers deterministically
without needing async signal replay. This test validates that signal handling works
end-to-end under RR mode without interfering.

**Step 2: Run test**

Run: `cargo test --package litebox_runner_linux_userland --features rr --test run test_rr_record_replay_signal -- --nocapture`
Expected: PASS

**Step 3: Also test with alarm.c if it exists (uses SIGALRM — truly async)**

Check `tests/alarm.c`. If it uses `alarm()` + SIGALRM handler, add a similar test
`test_rr_record_replay_alarm`. This is the real async signal test.

**Step 4: Commit**

```
test(rr): add signal record-replay integration tests
```

---

### Task 8: Full verification

**Step 1: Format**

Run: `cargo fmt -- --check`
Expected: clean

**Step 2: Clippy with rr**

Run: `cargo clippy --all-targets --features rr`
Expected: clean

**Step 3: Clippy without rr**

Run: `cargo clippy --all-targets`
Expected: clean

**Step 4: Unit tests**

Run: `cargo test --package litebox_rr`
Expected: all pass (13+ tests)

**Step 5: Integration tests**

Run: `cargo test --package litebox_runner_linux_userland --features rr --test run test_rr -- --nocapture`
Expected: all rr tests pass

**Step 6: Regression tests**

Run: `cargo test --package litebox_runner_linux_userland --test run -- test_static_exec_with_rewriter test_dynamic_lib_with_rewriter --nocapture`
Expected: pass (no regressions)

**Step 7: Commit**

```
chore: verify signal rr passes all checks
```
