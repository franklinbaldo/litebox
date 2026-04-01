# Central Batch Drain Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Restructure central's server run loop to drain all ready SQ entries before issuing futex_wake calls, reducing wake/sleep churn for concurrent workloads.

**Architecture:** Central currently wakes the guest thread after every CQ push via futex_wake. When multiple SQ entries are ready (multiple threads, multiple processes, or rapid sequential submissions), this creates N futex_wake syscalls where 1 batch wake suffices. The batch drain collects thread_slots to wake in a u64 bitmap, processes all ready entries, then wakes all pending threads at once.

**Tech Stack:** Rust, litebox_central, litebox_ipc ring protocol (no IPC changes needed).

---

### Task 1: Restructure server.rs run loop for batch drain

**Files:**
- Modify: `litebox_central/src/server.rs:108-196` (the `run()` method)

**Change:**

Replace the current pattern:
```
process entry → cq_push → cq_notify_thread → futex_wake → sq_advance_head
```

With:
```
loop {
    process entry → cq_push → cq_notify_thread (no wake) → sq_advance_head
    peek next: if ready, continue draining
    if not ready: wake all pending threads, then spin/wait
}
```

Key details:
- `pending_wakes: u64` bitmap — one bit per thread_slot (0..63)
- After processing each non-NOTIFY_ONLY entry, set `pending_wakes |= 1 << thread_slot`
- After the drain loop, iterate set bits and futex_wake each
- CRITICAL: must also flush pending wakes before the spin/wait (otherwise threads hang while central sleeps)
- CRITICAL: must also flush pending wakes on exit (is_exiting check)

### Task 2: Verify with clippy, tests, and benchmarks

**Commands:**
```bash
cargo clippy -p litebox_central
cargo nextest run -p litebox_ipc
cargo build --release -p litebox_central -p litebox_micro -p litebox_launcher
pkill -9 litebox_central; pkill -9 litebox
python3 dev_bench/unixbench/run_unixbench.py --mode micro --release --no-build --duration 10 --iterations 1
```
