# litebox_ipc Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the `litebox_ipc` crate — shared-memory ring buffer IPC types and logic for communication between micro-LiteBox (in-process guest agent) and central LiteBox (host process).

**Architecture:** `litebox_ipc` is a standalone crate with zero LiteBox-internal dependencies. It defines the shared-memory layout (SQ/CQ ring buffers), entry types (`SqEntry`, `CqEntry`), synchronization primitives (futex-based spin-then-wait), and shared data region management. Both `litebox_micro` and `litebox_central` will depend on this crate.

**Tech Stack:** Rust (edition 2024), `#![no_std]` compatible with `alloc` feature gate for setup code. Uses `zerocopy` for `repr(C)` types, raw atomics for lock-free ring buffer protocol, Linux futex for cross-process wake/wait.

**Design docs:** `docs/plans/2026-03-27-micro-litebox-01-ring-buffer-ipc.md`, `docs/plans/2026-03-27-micro-litebox-05-concurrency.md`

---

### Task 1: Create `litebox_ipc` crate skeleton

**Files:**
- Create: `litebox_ipc/Cargo.toml`
- Create: `litebox_ipc/src/lib.rs`
- Modify: `Cargo.toml` (workspace root — add to `members` and `default-members`)

**Step 1: Create the crate directory**

```bash
mkdir -p litebox_ipc/src
```

**Step 2: Create `litebox_ipc/Cargo.toml`**

```toml
[package]
name = "litebox_ipc"
version = "0.1.0"
edition = "2024"

[dependencies]

[lints]
workspace = true
```

No dependencies yet — we'll add them as needed in subsequent tasks.

**Step 3: Create `litebox_ipc/src/lib.rs`**

```rust
// Copyright (c) LiteBox Authors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root.

//! Shared-memory ring buffer IPC for communication between micro-LiteBox
//! (in-process guest agent) and central LiteBox (host process).
//!
//! This crate defines the wire format and synchronization protocol for
//! an io_uring-style submission/completion queue pair that operates across
//! process boundaries via shared memory.

#![no_std]

extern crate alloc;
```

**Step 4: Add to workspace**

In root `Cargo.toml`, add `"litebox_ipc"` to both `members` and `default-members` arrays.

**Step 5: Verify it compiles**

```bash
cargo check -p litebox_ipc
```

Expected: success, no errors.

**Step 6: Commit**

```bash
git add litebox_ipc/ Cargo.toml
git commit -m "feat(ipc): add litebox_ipc crate skeleton"
```

---

### Task 2: Define ring buffer constants and `SqEntry` type

**Files:**
- Create: `litebox_ipc/src/ring.rs`
- Modify: `litebox_ipc/src/lib.rs` (add module declaration)
- Modify: `litebox_ipc/Cargo.toml` (add `zerocopy` dependency)

**Step 1: Add `zerocopy` dependency**

In `litebox_ipc/Cargo.toml`:
```toml
[dependencies]
zerocopy = { version = "0.8", default-features = false, features = ["derive"] }
```

**Step 2: Create `litebox_ipc/src/ring.rs` with constants and `SqEntry`**

```rust
// Copyright (c) LiteBox Authors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root.

//! Ring buffer types and constants.

use core::sync::atomic::AtomicU8;
use zerocopy::{FromBytes, IntoBytes, Immutable, KnownLayout};

/// Number of entries in each ring (SQ and CQ). Must be a power of two.
pub const RING_SIZE: usize = 256;

/// Mask for converting a monotonic index to a ring slot: `index & RING_MASK`.
pub const RING_MASK: usize = RING_SIZE - 1;

/// Maximum number of guest threads per process that can submit concurrently.
pub const MAX_THREADS: usize = 64;

/// Default size of the shared data region (4 MiB).
pub const DEFAULT_DATA_REGION_SIZE: usize = 4 * 1024 * 1024;

/// Flags for `SqEntry::flags`.
pub mod sq_flags {
    /// This entry is part of a batch; central should not sleep between entries.
    pub const BATCH: u16 = 1 << 0;
    /// Request requires authorization before local execution.
    pub const NEED_AUTH: u16 = 1 << 1;
    /// Micro will report the result of local execution back.
    pub const REPORT_RESULT: u16 = 1 << 2;
}

/// Flags for `CqEntry::flags`.
pub mod cq_flags {
    /// Central authorizes micro to execute this syscall locally.
    pub const EXEC_LOCAL: u16 = 1 << 0;
    /// The shared data region contains result data at `data_offset`.
    pub const HAS_DATA: u16 = 1 << 1;
}

/// A submission queue entry. Written by micro-LiteBox, read by central.
///
/// Aligned to 64 bytes (one cache line on x86) to avoid false sharing
/// between adjacent entries.
///
/// # Memory ordering
///
/// The `ready` flag is the synchronization point. The writer (micro) must
/// write all other fields before storing `ready = 1` with `Release`
/// ordering. The reader (central) must load `ready` with `Acquire` ordering
/// before reading other fields.
#[repr(C, align(64))]
pub struct SqEntry {
    /// Monotonic sequence number assigned by the submitting thread.
    /// Used to correlate CQ responses with SQ requests.
    pub seq: u64,
    /// Syscall number (e.g., `SYS_read`, `SYS_mmap`).
    pub syscall_nr: u32,
    /// Thread slot index (0..MAX_THREADS-1). Determines which CQ notify
    /// slot to wake on completion.
    pub thread_slot: u16,
    /// Flags (see `sq_flags`).
    pub flags: u16,
    /// Syscall arguments (up to 6), matching the Linux syscall ABI.
    pub args: [u64; 6],
    /// Offset into the shared data region for bulk data.
    pub data_offset: u32,
    /// Length of data referenced in the shared data region.
    pub data_len: u32,
    /// Ready flag. Set to 1 (with Release) when the entry is fully written.
    /// Central checks this (with Acquire) before reading other fields.
    pub ready: AtomicU8,
    /// Padding to fill the 64-byte cache line.
    pub _pad: [u8; 7],
}

// SqEntry is 64 bytes. Verify at compile time.
const _: () = assert!(core::mem::size_of::<SqEntry>() == 64);

/// A completion queue entry. Written by central, read by micro-LiteBox.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct CqEntry {
    /// Matches `SqEntry::seq` for correlation.
    pub seq: u64,
    /// Syscall return value, or negative errno on failure.
    pub result: i64,
    /// Flags (see `cq_flags`).
    pub flags: u16,
    /// Thread slot (copied from SqEntry for demux).
    pub thread_slot: u16,
    /// Padding.
    pub _pad: [u8; 4],
    /// Offset into shared data region for result data.
    pub data_offset: u32,
    /// Length of result data.
    pub data_len: u32,
}

// CqEntry is 32 bytes. Verify at compile time.
const _: () = assert!(core::mem::size_of::<CqEntry>() == 32);
```

**Step 3: Add module to `lib.rs`**

Add `pub mod ring;` to `litebox_ipc/src/lib.rs`.

**Step 4: Verify it compiles**

```bash
cargo check -p litebox_ipc
```

Expected: success. Note: `SqEntry` cannot derive `FromBytes`/`IntoBytes` because it contains `AtomicU8`. This is intentional — `SqEntry` is accessed field-by-field with explicit atomic operations, never copied wholesale.

**Step 5: Commit**

```bash
git add litebox_ipc/
git commit -m "feat(ipc): define SqEntry and CqEntry ring buffer types"
```

---

### Task 3: Define `RingHeader` and shared memory layout

**Files:**
- Modify: `litebox_ipc/src/ring.rs` (add `RingHeader`, `SharedRingLayout`)

**Step 1: Add `RingHeader` and layout types to `ring.rs`**

Append to `litebox_ipc/src/ring.rs`:

```rust
use core::sync::atomic::{AtomicU32, AtomicU64};

/// Ring buffer header, stored at the start of the shared memory region.
///
/// All fields are atomics because they are accessed concurrently from
/// different processes (micro and central) via shared memory.
#[repr(C, align(64))]
pub struct RingHeader {
    // -- SQ control (cache line 1) --
    /// SQ head: index of next entry for central to consume.
    /// Written by central, read by micro (to check if SQ is full).
    pub sq_head: AtomicU64,
    /// SQ tail: index of next entry for micro to write.
    /// Advanced by micro via `fetch_add`.
    pub sq_tail: AtomicU64,
    /// Futex for central to sleep on when SQ is empty.
    /// Micro wakes this after submitting entries.
    pub sq_notify: AtomicU32,
    _pad_sq: [u8; 44], // pad to 64 bytes

    // -- CQ control (cache line 2) --
    /// CQ head: index of next entry for micro to consume.
    /// Advanced by micro after reading completions.
    pub cq_head: AtomicU64,
    /// CQ tail: index of next entry for central to write.
    /// Advanced by central via `fetch_add` (with Release).
    pub cq_tail: AtomicU64,
    _pad_cq: [u8; 48], // pad to 64 bytes

    // -- Per-thread CQ notification slots (cache lines 3+) --
    /// Each guest thread waits on its own slot to avoid thundering herd.
    /// Central increments `notify_slots[thread_slot]` and does
    /// `futex_wake` on it after writing a CQ entry for that thread.
    pub cq_notify_slots: [AtomicU32; MAX_THREADS],
}

/// Byte offsets of each section within the shared memory region.
///
/// Layout (contiguous in shared memory):
/// 1. `RingHeader` (at offset 0)
/// 2. `SqEntry[RING_SIZE]` (immediately after header)
/// 3. `CqEntry[RING_SIZE]` (immediately after SQ entries)
/// 4. Shared data region (remainder, for bulk data transfer)
pub struct SharedRingLayout {
    /// Total size of the shared memory region in bytes.
    pub total_size: usize,
    /// Byte offset of the SQ entries array.
    pub sq_entries_offset: usize,
    /// Byte offset of the CQ entries array.
    pub cq_entries_offset: usize,
    /// Byte offset of the shared data region.
    pub data_region_offset: usize,
    /// Size of the shared data region in bytes.
    pub data_region_size: usize,
}

impl SharedRingLayout {
    /// Compute the layout for a given data region size.
    ///
    /// # Panics
    ///
    /// Panics if `data_region_size` is 0.
    #[must_use]
    pub const fn new(data_region_size: usize) -> Self {
        assert!(data_region_size > 0, "data region size must be > 0");

        let header_size = core::mem::size_of::<RingHeader>();
        // Align SQ entries to 64-byte boundary (SqEntry is align(64))
        let sq_entries_offset = (header_size + 63) & !63;
        let sq_entries_size = RING_SIZE * core::mem::size_of::<SqEntry>();
        let cq_entries_offset = sq_entries_offset + sq_entries_size;
        let cq_entries_size = RING_SIZE * core::mem::size_of::<CqEntry>();
        // Align data region to page boundary (4096)
        let data_region_offset = (cq_entries_offset + cq_entries_size + 4095) & !4095;
        let total_size = data_region_offset + data_region_size;

        Self {
            total_size,
            sq_entries_offset,
            cq_entries_offset,
            data_region_offset,
            data_region_size,
        }
    }

    /// Compute the default layout (4 MiB data region).
    #[must_use]
    pub const fn default_layout() -> Self {
        Self::new(DEFAULT_DATA_REGION_SIZE)
    }
}
```

**Step 2: Verify it compiles**

```bash
cargo check -p litebox_ipc
```

**Step 3: Commit**

```bash
git add litebox_ipc/
git commit -m "feat(ipc): add RingHeader and SharedRingLayout"
```

---

### Task 4: Implement `SqEntry` producer/consumer operations

**Files:**
- Create: `litebox_ipc/src/sq.rs`
- Modify: `litebox_ipc/src/lib.rs` (add module)

**Step 1: Create `litebox_ipc/src/sq.rs`**

This implements the lock-free SQ protocol from the design doc:
- Micro (producer): `fetch_add` on tail, write entry, set ready flag
- Central (consumer): check head, wait for ready flag, process, advance head

```rust
// Copyright (c) LiteBox Authors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root.

//! Submission queue producer/consumer operations.
//!
//! The SQ is a multi-producer (multiple guest threads), single-consumer
//! (central's worker thread) ring buffer.

use core::sync::atomic::Ordering;

use crate::ring::{RingHeader, SqEntry, RING_MASK, RING_SIZE};

/// Acquire an SQ slot for writing. Returns the slot index (0..RING_SIZE-1).
///
/// This uses `fetch_add` on `sq_tail` for the fast path (no contention on
/// the slot itself, only on the tail counter). If the SQ is full
/// (tail - head >= RING_SIZE), this spins until a slot is available.
///
/// # Safety
///
/// `header` must point to a valid `RingHeader` in shared memory.
/// `sq_entries` must point to a valid array of `RING_SIZE` `SqEntry`s.
pub unsafe fn sq_acquire_slot(header: &RingHeader) -> u64 {
    loop {
        let tail = header.sq_tail.load(Ordering::Relaxed);
        let head = header.sq_head.load(Ordering::Acquire);
        if tail.wrapping_sub(head) < RING_SIZE as u64 {
            // Try to claim this slot
            match header.sq_tail.compare_exchange_weak(
                tail,
                tail.wrapping_add(1),
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return tail & RING_MASK as u64,
                Err(_) => continue, // Another thread got it, retry
            }
        }
        // SQ is full, spin briefly
        core::hint::spin_loop();
    }
}

/// Mark an SQ entry as ready for central to consume.
///
/// Must be called AFTER all other fields of the entry have been written.
/// Uses `Release` ordering to ensure all prior writes are visible.
pub fn sq_publish(entry: &SqEntry) {
    entry.ready.store(1, Ordering::Release);
}

/// Try to consume the next SQ entry. Returns `true` if an entry was ready.
///
/// Central calls this in its event loop. If the entry at `sq_head` has its
/// ready flag set, this returns `true` and the caller should process it.
/// After processing, call `sq_advance_head` to move to the next entry.
///
/// Uses `Acquire` on the ready flag to ensure all entry fields are visible.
pub fn sq_try_consume(entry: &SqEntry) -> bool {
    entry.ready.load(Ordering::Acquire) != 0
}

/// Advance the SQ head after consuming an entry. Clears the ready flag.
///
/// Central calls this after fully processing an SQ entry.
pub fn sq_advance_head(header: &RingHeader, entry: &SqEntry) {
    entry.ready.store(0, Ordering::Release);
    // We use Release here so the cleared ready flag is visible before
    // head advances (micro checks head to know if SQ is full).
    header.sq_head.fetch_add(1, Ordering::Release);
}

/// Get the current SQ head index (the next slot for central to consume).
pub fn sq_head_index(header: &RingHeader) -> u64 {
    header.sq_head.load(Ordering::Acquire)
}
```

**Step 2: Add module to `lib.rs`**

Add `pub mod sq;` to `litebox_ipc/src/lib.rs`.

**Step 3: Verify it compiles**

```bash
cargo check -p litebox_ipc
```

**Step 4: Commit**

```bash
git add litebox_ipc/
git commit -m "feat(ipc): implement SQ producer/consumer operations"
```

---

### Task 5: Implement `CqEntry` producer/consumer operations

**Files:**
- Create: `litebox_ipc/src/cq.rs`
- Modify: `litebox_ipc/src/lib.rs` (add module)

**Step 1: Create `litebox_ipc/src/cq.rs`**

CQ is single-producer (central), multi-consumer (guest threads, but each
thread only reads its own entries identified by `thread_slot`).

```rust
// Copyright (c) LiteBox Authors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root.

//! Completion queue producer/consumer operations.
//!
//! The CQ is single-producer (central's worker thread), multi-consumer
//! (guest threads each reading their own completions by seq number).

use core::sync::atomic::Ordering;

use crate::ring::{CqEntry, RingHeader, RING_MASK, RING_SIZE};

/// Write a completion entry to the CQ. Called by central after processing
/// an SQ entry.
///
/// # Safety
///
/// `cq_entries` must point to a valid array of `RING_SIZE` `CqEntry`s in
/// shared memory. Caller must ensure CQ is not full (single-producer, so
/// central controls the rate).
pub unsafe fn cq_push(header: &RingHeader, cq_entries: *mut CqEntry, entry: CqEntry) {
    let tail = header.cq_tail.load(Ordering::Relaxed);
    let slot = (tail & RING_MASK as u64) as usize;
    // Write the entry
    cq_entries.add(slot).write(entry);
    // Advance tail with Release so the entry is visible before tail moves
    header.cq_tail.store(tail.wrapping_add(1), Ordering::Release);
}

/// Notify a specific guest thread that a completion is available.
///
/// Increments the thread's notify slot (so the guest can detect the change)
/// but does NOT perform the actual futex wake — that's platform-specific
/// and done by the caller.
///
/// Returns the address of the notify slot (for the caller to futex_wake on).
pub fn cq_notify_thread(header: &RingHeader, thread_slot: u16) -> &AtomicU32 {
    let slot = &header.cq_notify_slots[thread_slot as usize];
    slot.fetch_add(1, Ordering::Release);
    slot
}

use core::sync::atomic::AtomicU32;

/// Scan the CQ for a completion matching the given sequence number.
///
/// Called by a guest thread after being woken. Scans from `start_index`
/// up to `cq_tail`. Returns the matching `CqEntry` and its index, or
/// `None` if not found.
///
/// # Safety
///
/// `cq_entries` must point to a valid array of `RING_SIZE` `CqEntry`s.
pub unsafe fn cq_find_by_seq(
    header: &RingHeader,
    cq_entries: *const CqEntry,
    start_index: u64,
    target_seq: u64,
) -> Option<CqEntry> {
    let tail = header.cq_tail.load(Ordering::Acquire);
    let mut idx = start_index;
    while idx != tail {
        let slot = (idx & RING_MASK as u64) as usize;
        let entry = cq_entries.add(slot).read();
        if entry.seq == target_seq {
            return Some(entry);
        }
        idx = idx.wrapping_add(1);
    }
    None
}

/// Get the current CQ tail (the next write position, owned by central).
pub fn cq_tail(header: &RingHeader) -> u64 {
    header.cq_tail.load(Ordering::Acquire)
}
```

**Step 2: Add module to `lib.rs`**

Add `pub mod cq;` to `litebox_ipc/src/lib.rs`.

**Step 3: Verify it compiles**

```bash
cargo check -p litebox_ipc
```

**Step 4: Commit**

```bash
git add litebox_ipc/
git commit -m "feat(ipc): implement CQ producer/consumer operations"
```

---

### Task 6: Implement adaptive spin-then-wait

**Files:**
- Create: `litebox_ipc/src/wait.rs`
- Modify: `litebox_ipc/src/lib.rs` (add module)

**Step 1: Create `litebox_ipc/src/wait.rs`**

Platform-agnostic spin logic. The actual futex syscall is provided by a
callback (since this crate is `no_std` and futex is OS-specific).

```rust
// Copyright (c) LiteBox Authors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root.

//! Adaptive spin-then-wait synchronization.
//!
//! Provides a spin loop that tries to avoid kernel sleep (futex_wait)
//! when the other side is actively producing/consuming. Falls back to
//! a caller-provided wait function when spinning is insufficient.

use core::sync::atomic::{AtomicU32, Ordering};

/// Number of busy-spin iterations before exponential backoff.
const SPIN_ITERS: u32 = 200;

/// Number of exponential backoff rounds before calling the wait function.
const BACKOFF_ROUNDS: u32 = 8;

/// Spin on an `AtomicU32`, falling back to `wait_fn` if the value doesn't
/// change from `expected`.
///
/// `wait_fn` receives the atomic reference and the expected value. It should
/// perform a futex-wait or equivalent blocking operation.
///
/// Returns when the value at `addr` is no longer equal to `expected`.
pub fn spin_then_wait(
    addr: &AtomicU32,
    expected: u32,
    wait_fn: impl Fn(&AtomicU32, u32),
) {
    // Phase 1: Busy spin with pause hints
    for _ in 0..SPIN_ITERS {
        if addr.load(Ordering::Acquire) != expected {
            return;
        }
        core::hint::spin_loop();
    }

    // Phase 2: Exponential backoff
    for round in 0..BACKOFF_ROUNDS {
        let iters = 1u32 << round.min(6);
        for _ in 0..iters {
            core::hint::spin_loop();
        }
        if addr.load(Ordering::Acquire) != expected {
            return;
        }
    }

    // Phase 3: Kernel wait (futex or equivalent)
    loop {
        wait_fn(addr, expected);
        if addr.load(Ordering::Acquire) != expected {
            return;
        }
    }
}

/// Spin on an `AtomicU32` without a fallback wait function.
///
/// Useful when the caller knows the value will change soon (e.g., central
/// spinning on SQ in a hot loop). Returns when the value changes.
///
/// **Warning:** This busy-waits indefinitely. Only use when the producer
/// is guaranteed to be running concurrently.
pub fn spin_only(addr: &AtomicU32, expected: u32) {
    while addr.load(Ordering::Acquire) == expected {
        core::hint::spin_loop();
    }
}
```

**Step 2: Add module to `lib.rs`**

Add `pub mod wait;` to `litebox_ipc/src/lib.rs`.

**Step 3: Verify it compiles**

```bash
cargo check -p litebox_ipc
```

**Step 4: Commit**

```bash
git add litebox_ipc/
git commit -m "feat(ipc): implement adaptive spin-then-wait"
```

---

### Task 7: Define IPC message types (beyond raw syscalls)

**Files:**
- Create: `litebox_ipc/src/messages.rs`
- Modify: `litebox_ipc/src/lib.rs` (add module)

**Step 1: Create `litebox_ipc/src/messages.rs`**

Control messages between micro and central that aren't raw syscalls:

```rust
// Copyright (c) LiteBox Authors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root.

//! IPC message types for control communication between micro and central.
//!
//! These use the same SQ/CQ ring as syscalls, distinguished by
//! `syscall_nr` values in a reserved range above the Linux syscall range.

/// Base value for IPC control messages. All control message "syscall numbers"
/// are >= this value. Real Linux syscall numbers are well below this.
pub const MSG_BASE: u32 = 0x8000_0000;

/// Thread registration request. Sent by a new guest thread to get a
/// thread slot assignment.
///
/// SQ args: none
/// CQ result: assigned thread_slot in `CqEntry::thread_slot`
pub const MSG_THREAD_REGISTER: u32 = MSG_BASE;

/// Thread deregistration. Sent when a guest thread is exiting.
///
/// SQ args: none
/// CQ result: 0 on success
pub const MSG_THREAD_DEREGISTER: u32 = MSG_BASE + 1;

/// Fork result report. Sent by the parent after executing fork locally.
///
/// SQ args[0]: child PID (as returned by clone)
/// CQ result: 0 on success (central has noted the child PID)
pub const MSG_FORK_RESULT: u32 = MSG_BASE + 2;

/// Child ready notification. Sent by the child process after fork,
/// once it has mapped its new ring buffer and is ready to operate.
///
/// SQ args: none
/// CQ result: 0 on success (central acknowledges the child)
pub const MSG_CHILD_READY: u32 = MSG_BASE + 3;

/// Local execution result report. Sent by micro after executing a
/// locally-authorized syscall (mmap, munmap, etc.).
///
/// SQ args[0]: original SQ seq number this is reporting on
/// SQ args[1]: result value (the return of the local syscall)
/// CQ result: 0 (central has recorded the result)
pub const MSG_LOCAL_RESULT: u32 = MSG_BASE + 4;

/// Returns `true` if the given syscall_nr is a control message (not a real syscall).
#[must_use]
pub const fn is_control_message(syscall_nr: u32) -> bool {
    syscall_nr >= MSG_BASE
}
```

**Step 2: Add module to `lib.rs`**

Add `pub mod messages;` to `litebox_ipc/src/lib.rs`.

**Step 3: Verify it compiles**

```bash
cargo check -p litebox_ipc
```

**Step 4: Commit**

```bash
git add litebox_ipc/
git commit -m "feat(ipc): define IPC control message types"
```

---

### Task 8: Add unit tests for ring buffer types

**Files:**
- Modify: `litebox_ipc/src/ring.rs` (add `#[cfg(test)] mod tests`)

**Step 1: Write tests**

Append to `litebox_ipc/src/ring.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sq_entry_is_64_bytes() {
        assert_eq!(core::mem::size_of::<SqEntry>(), 64);
    }

    #[test]
    fn sq_entry_is_cache_line_aligned() {
        assert_eq!(core::mem::align_of::<SqEntry>(), 64);
    }

    #[test]
    fn cq_entry_is_32_bytes() {
        assert_eq!(core::mem::size_of::<CqEntry>(), 32);
    }

    #[test]
    fn ring_size_is_power_of_two() {
        assert!(RING_SIZE.is_power_of_two());
    }

    #[test]
    fn ring_mask_matches_ring_size() {
        assert_eq!(RING_MASK, RING_SIZE - 1);
    }

    #[test]
    fn default_layout_sections_dont_overlap() {
        let layout = SharedRingLayout::default_layout();
        let header_end = core::mem::size_of::<RingHeader>();
        assert!(layout.sq_entries_offset >= header_end);

        let sq_end = layout.sq_entries_offset + RING_SIZE * core::mem::size_of::<SqEntry>();
        assert!(layout.cq_entries_offset >= sq_end);

        let cq_end = layout.cq_entries_offset + RING_SIZE * core::mem::size_of::<CqEntry>();
        assert!(layout.data_region_offset >= cq_end);

        assert_eq!(
            layout.total_size,
            layout.data_region_offset + layout.data_region_size
        );
    }

    #[test]
    fn layout_data_region_is_page_aligned() {
        let layout = SharedRingLayout::default_layout();
        assert_eq!(layout.data_region_offset % 4096, 0);
    }

    #[test]
    fn layout_sq_entries_are_cache_line_aligned() {
        let layout = SharedRingLayout::default_layout();
        assert_eq!(layout.sq_entries_offset % 64, 0);
    }

    #[test]
    fn layout_with_custom_data_size() {
        let layout = SharedRingLayout::new(8 * 1024 * 1024); // 8 MiB
        assert_eq!(layout.data_region_size, 8 * 1024 * 1024);
        assert_eq!(
            layout.total_size,
            layout.data_region_offset + 8 * 1024 * 1024
        );
    }
}
```

**Step 2: Run tests**

```bash
cargo nextest run -p litebox_ipc
```

Expected: all tests pass.

**Step 3: Commit**

```bash
git add litebox_ipc/
git commit -m "test(ipc): add unit tests for ring buffer types and layout"
```

---

### Task 9: Add unit tests for SQ and CQ operations

**Files:**
- Modify: `litebox_ipc/src/sq.rs` (add tests)
- Modify: `litebox_ipc/src/cq.rs` (add tests)

**Step 1: Write SQ tests**

Append to `litebox_ipc/src/sq.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::Ordering;

    /// Create a zeroed RingHeader for testing.
    fn make_header() -> RingHeader {
        // Safety: RingHeader is all atomics + padding, zero-init is valid.
        unsafe { core::mem::zeroed() }
    }

    /// Create a zeroed SqEntry array for testing.
    fn make_sq_entries() -> [SqEntry; RING_SIZE] {
        // Safety: SqEntry fields are all primitives/atomics, zero-init is valid.
        unsafe { core::mem::zeroed() }
    }

    #[test]
    fn acquire_slot_returns_sequential_indices() {
        let header = make_header();
        unsafe {
            let slot0 = sq_acquire_slot(&header);
            assert_eq!(slot0, 0);
            let slot1 = sq_acquire_slot(&header);
            assert_eq!(slot1, 1);
            let slot2 = sq_acquire_slot(&header);
            assert_eq!(slot2, 2);
        }
    }

    #[test]
    fn publish_sets_ready_flag() {
        let entries = make_sq_entries();
        assert_eq!(entries[0].ready.load(Ordering::Relaxed), 0);
        sq_publish(&entries[0]);
        assert_eq!(entries[0].ready.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn try_consume_returns_false_when_not_ready() {
        let entries = make_sq_entries();
        assert!(!sq_try_consume(&entries[0]));
    }

    #[test]
    fn try_consume_returns_true_when_ready() {
        let entries = make_sq_entries();
        sq_publish(&entries[0]);
        assert!(sq_try_consume(&entries[0]));
    }

    #[test]
    fn advance_head_clears_ready_and_increments_head() {
        let header = make_header();
        let entries = make_sq_entries();

        sq_publish(&entries[0]);
        assert!(sq_try_consume(&entries[0]));

        sq_advance_head(&header, &entries[0]);
        assert_eq!(entries[0].ready.load(Ordering::Relaxed), 0);
        assert_eq!(header.sq_head.load(Ordering::Relaxed), 1);
    }
}
```

**Step 2: Write CQ tests**

Append to `litebox_ipc/src/cq.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ring::{RingHeader, CqEntry, RING_SIZE};
    use core::sync::atomic::Ordering;

    fn make_header() -> RingHeader {
        unsafe { core::mem::zeroed() }
    }

    fn make_cq_entries() -> [CqEntry; RING_SIZE] {
        [CqEntry {
            seq: 0,
            result: 0,
            flags: 0,
            thread_slot: 0,
            _pad: [0; 4],
            data_offset: 0,
            data_len: 0,
        }; RING_SIZE]
    }

    #[test]
    fn push_and_find_single_entry() {
        let header = make_header();
        let mut entries = make_cq_entries();
        let entry = CqEntry {
            seq: 42,
            result: 100,
            flags: 0,
            thread_slot: 3,
            _pad: [0; 4],
            data_offset: 0,
            data_len: 0,
        };

        unsafe {
            cq_push(&header, entries.as_mut_ptr(), entry);
        }

        assert_eq!(header.cq_tail.load(Ordering::Relaxed), 1);

        let found = unsafe { cq_find_by_seq(&header, entries.as_ptr(), 0, 42) };
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(found.seq, 42);
        assert_eq!(found.result, 100);
        assert_eq!(found.thread_slot, 3);
    }

    #[test]
    fn find_returns_none_for_missing_seq() {
        let header = make_header();
        let entries = make_cq_entries();
        let found = unsafe { cq_find_by_seq(&header, entries.as_ptr(), 0, 999) };
        assert!(found.is_none());
    }

    #[test]
    fn notify_thread_increments_slot() {
        let header = make_header();
        let slot = cq_notify_thread(&header, 5);
        assert_eq!(slot.load(Ordering::Relaxed), 1);
        let slot = cq_notify_thread(&header, 5);
        assert_eq!(slot.load(Ordering::Relaxed), 2);
    }
}
```

**Step 3: Run tests**

```bash
cargo nextest run -p litebox_ipc
```

Expected: all tests pass.

**Step 4: Commit**

```bash
git add litebox_ipc/
git commit -m "test(ipc): add unit tests for SQ and CQ operations"
```

---

### Task 10: Run full workspace build and clippy

**Step 1: Run clippy on litebox_ipc**

```bash
cargo clippy -p litebox_ipc -- -D warnings
```

Fix any clippy warnings.

**Step 2: Run full workspace build**

```bash
cargo check
```

Ensure adding the new crate doesn't break anything.

**Step 3: Run all tests**

```bash
cargo nextest run -p litebox_ipc
```

**Step 4: Commit any fixes**

```bash
git add -A
git commit -m "chore(ipc): fix clippy warnings in litebox_ipc"
```

(Only if there were fixes needed.)
