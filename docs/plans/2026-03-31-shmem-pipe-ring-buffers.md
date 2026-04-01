# Shmem-Backed Pipe Ring Buffers — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace real OS pipes with LiteBox-owned shmem ring buffers so pipe read/write bypass the central round-trip entirely, improving the pipe benchmark from 0.29x to near-native.

**Architecture:** Central's shim creates virtual pipes (existing `Pipes::create_pipe()`) and allocates an SPSC ring buffer slot in the shmem free zone. Micro maps pipe fds to shmem offsets and performs read/write directly on the ring buffer — zero round-trips. Close still goes through central (fd lifecycle). The ring buffer uses lock-free atomic head/tail cursors in MAP_SHARED memory, with futex for blocking.

**Tech Stack:** Rust, `#![no_std]` for IPC crate, `core::sync::atomic` for lock-free ring, `futex` for blocking, existing shmem infrastructure.

---

## Task 1: Add shmem pipe constants and header type to `litebox_ipc`

**Files:**
- Modify: `litebox_ipc/src/ring.rs`

**Step 1: Add pipe zone constants and `ShmemPipeHeader` struct**

After the existing constants (line 28), add:

```rust
/// Base offset within the data region where pipe ring buffers start.
///
/// Layout: [pathnames: 1 MiB][write data: 4 MiB][pipe zone: 3 MiB]
pub const PIPE_ZONE_BASE_OFFSET: usize = 5 * 1024 * 1024; // 0x500000

/// Size of each pipe slot (header + data buffer).
/// Header: 64 bytes (cache-line aligned). Data: 64 KiB (power-of-2).
pub const PIPE_SLOT_SIZE: usize = 64 + 65536;

/// Capacity of the pipe data buffer (must be power-of-2).
pub const PIPE_DATA_CAPACITY: usize = 65536;

/// Maximum number of concurrent pipe slots.
/// floor((8 MiB - 5 MiB) / PIPE_SLOT_SIZE) = floor(3145728 / 65600) = 47
pub const MAX_PIPE_SLOTS: usize = 47;
```

Add the shmem pipe header struct:

```rust
/// Header for a shmem-backed pipe ring buffer.
///
/// Lives at the start of each pipe slot in the pipe zone. Both micro and
/// central access this through the shared memory mapping. The ring buffer
/// data immediately follows this header.
///
/// Invariants:
/// - `tail - head` = bytes available to read (always non-negative)
/// - `capacity - (tail - head)` = bytes available to write
/// - Data index: `cursor & (capacity - 1)` (power-of-2 masking)
#[repr(C, align(64))]
pub struct ShmemPipeHeader {
    /// Consumer (reader) position — byte offset of next read.
    pub head: AtomicU64,
    /// Producer (writer) position — byte offset of next write.
    pub tail: AtomicU64,
    /// Usable buffer capacity in bytes (always power-of-2).
    pub capacity: u64,
    /// Pipe status flags (bitwise OR of `pipe_flags::*`).
    pub flags: AtomicU32,
    /// The read-end fd number (for identification).
    pub read_fd: i32,
    /// The write-end fd number (for identification).
    pub write_fd: i32,
    /// Padding to fill to 64 bytes (one cache line).
    pub _pad: [u8; 24],
}
```

Add pipe flag constants:

```rust
/// Flags for `ShmemPipeHeader::flags`.
pub mod pipe_flags {
    /// The read end has been closed. Writers should get EPIPE/SIGPIPE.
    pub const READER_CLOSED: u32 = 1 << 0;
    /// The write end has been closed. Readers should get EOF (0) when buffer empty.
    pub const WRITER_CLOSED: u32 = 1 << 1;
    /// The pipe is non-blocking (O_NONBLOCK was set).
    pub const NONBLOCK: u32 = 1 << 2;
}
```

Add a static assert:

```rust
const _: () = assert!(size_of::<ShmemPipeHeader>() == 64);
```

**Step 2: Run tests**

Run: `cargo nextest run -p litebox_ipc`
Expected: All existing tests pass. The new constants are compile-checked by the static assert.

**Step 3: Add unit tests for pipe zone layout**

In the `#[cfg(test)] mod tests` block of `ring.rs`, add:

```rust
#[test]
fn pipe_zone_fits_in_default_data_region() {
    let end = PIPE_ZONE_BASE_OFFSET + MAX_PIPE_SLOTS * PIPE_SLOT_SIZE;
    assert!(
        end <= DEFAULT_DATA_REGION_SIZE,
        "pipe zone end ({end}) exceeds data region size ({DEFAULT_DATA_REGION_SIZE})"
    );
}

#[test]
fn pipe_data_capacity_is_power_of_two() {
    assert!(PIPE_DATA_CAPACITY.is_power_of_two());
}

#[test]
fn shmem_pipe_header_size() {
    assert_eq!(size_of::<ShmemPipeHeader>(), 64);
}

#[test]
fn pipe_slot_size_matches_header_plus_data() {
    assert_eq!(PIPE_SLOT_SIZE, size_of::<ShmemPipeHeader>() + PIPE_DATA_CAPACITY);
}
```

**Step 4: Run tests**

Run: `cargo nextest run -p litebox_ipc`
Expected: All tests pass (existing + 4 new).

**Step 5: Commit**

```bash
git add litebox_ipc/src/ring.rs
git commit -m "ipc: add ShmemPipeHeader and pipe zone constants for shmem-backed pipes"
```

---

## Task 2: Add `Pipe2Response` to IPC messages

**Files:**
- Modify: `litebox_ipc/src/messages.rs`

**Step 1: Add `Pipe2Response` struct and update `MSG_NOTIFY_PIPE2` docs**

At the end of `messages.rs`, add:

```rust
/// Response data written to the shmem data region by central after creating
/// a pipe via `pipe2`. Micro reads this when it receives a CQ with `HAS_DATA`
/// for a `SYS_pipe2` request.
///
/// Central writes this at offset 0 of the data region (same location used
/// for other data-producing responses).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Pipe2Response {
    /// Read-end file descriptor number.
    pub read_fd: i32,
    /// Write-end file descriptor number.
    pub write_fd: i32,
    /// Offset within the data region to the pipe's `ShmemPipeHeader`.
    /// The ring buffer data starts at `pipe_slot_offset + 64`.
    pub pipe_slot_offset: u32,
    /// Reserved padding.
    pub _pad: u32,
}
```

Add a static assert:

```rust
const _: () = assert!(size_of::<Pipe2Response>() == 16);
```

**Step 2: Run tests**

Run: `cargo nextest run -p litebox_ipc`
Expected: All tests pass.

**Step 3: Commit**

```bash
git add litebox_ipc/src/messages.rs
git commit -m "ipc: add Pipe2Response struct for shmem pipe slot communication"
```

---

## Task 3: Add pipe fd tracking to `MicroState`

**Files:**
- Modify: `litebox_micro/src/state.rs`

**Step 1: Add `PipeFdEntry` struct and pipe tracking fields**

After the existing imports, add:

```rust
use litebox_ipc::ring::MAX_PIPE_SLOTS;
```

Before `MicroState`, add:

```rust
/// Entry in micro's local pipe fd tracking table.
///
/// Maps a file descriptor to the shmem offset of its pipe ring buffer.
#[derive(Clone, Copy)]
pub struct PipeFdEntry {
    /// The file descriptor number.
    pub fd: i32,
    /// Offset within the data region to the pipe's `ShmemPipeHeader`.
    pub shmem_offset: u32,
    /// `true` if this fd is the write end, `false` if read end.
    pub is_write_end: bool,
}
```

Add new fields to `MicroState` (at the end, before the closing brace):

```rust
    /// Pipe fd tracking table. Each entry maps a guest fd to a shmem pipe
    /// ring buffer. Linear scan is fine — at most MAX_PIPE_SLOTS entries.
    pub pipe_fds: [Option<PipeFdEntry>; MAX_PIPE_SLOTS],
```

Update the static `MICRO_STATE` initializer to include:

```rust
        pipe_fds: [None; MAX_PIPE_SLOTS],
```

Update `MicroState::zeroed()` in the `#[cfg(test)]` block to include:

```rust
            pipe_fds: [None; MAX_PIPE_SLOTS],
```

**Step 2: Add lookup and insert/remove methods**

Add an `impl MicroState` block (or extend the existing one) with:

```rust
impl MicroState {
    /// Look up a pipe fd in the tracking table.
    /// Returns `(shmem_offset, is_write_end)` if found.
    pub fn find_pipe_fd(&self, fd: i32) -> Option<(u32, bool)> {
        for entry in &self.pipe_fds {
            if let Some(e) = entry {
                if e.fd == fd {
                    return Some((e.shmem_offset, e.is_write_end));
                }
            }
        }
        None
    }

    /// Register a pipe fd in the tracking table. Returns `true` on success.
    pub fn register_pipe_fd(&mut self, fd: i32, shmem_offset: u32, is_write_end: bool) -> bool {
        for slot in &mut self.pipe_fds {
            if slot.is_none() {
                *slot = Some(PipeFdEntry { fd, shmem_offset, is_write_end });
                return true;
            }
        }
        false // table full
    }

    /// Remove a pipe fd from the tracking table. Returns `true` if found.
    pub fn unregister_pipe_fd(&mut self, fd: i32) -> bool {
        for slot in &mut self.pipe_fds {
            if let Some(e) = slot {
                if e.fd == fd {
                    *slot = None;
                    return true;
                }
            }
        }
        false
    }
}
```

**Step 3: Add tests**

```rust
#[test]
fn pipe_fd_register_and_find() {
    let mut state = MicroState::zeroed();
    assert!(state.find_pipe_fd(5).is_none());
    assert!(state.register_pipe_fd(5, 0x500000, false));
    let (offset, is_write) = state.find_pipe_fd(5).unwrap();
    assert_eq!(offset, 0x500000);
    assert!(!is_write);
}

#[test]
fn pipe_fd_unregister() {
    let mut state = MicroState::zeroed();
    state.register_pipe_fd(5, 0x500000, false);
    assert!(state.unregister_pipe_fd(5));
    assert!(state.find_pipe_fd(5).is_none());
    assert!(!state.unregister_pipe_fd(5)); // already removed
}

#[test]
fn pipe_fd_register_both_ends() {
    let mut state = MicroState::zeroed();
    assert!(state.register_pipe_fd(3, 0x500000, false)); // read end
    assert!(state.register_pipe_fd(4, 0x500000, true));  // write end
    let (off_r, wr_r) = state.find_pipe_fd(3).unwrap();
    let (off_w, wr_w) = state.find_pipe_fd(4).unwrap();
    assert_eq!(off_r, off_w); // same pipe slot
    assert!(!wr_r);
    assert!(wr_w);
}
```

**Step 4: Run tests**

Run: `cargo nextest run -p litebox_micro`
Expected: All tests pass (existing 36 + 3 new).

**Step 5: Commit**

```bash
git add litebox_micro/src/state.rs
git commit -m "micro: add pipe fd tracking table to MicroState"
```

---

## Task 4: Implement shmem SPSC pipe ring buffer operations in IPC crate

**Files:**
- Create: `litebox_ipc/src/pipe.rs`
- Modify: `litebox_ipc/src/lib.rs`

This task adds the core read/write/init functions that both micro and central can call on `ShmemPipeHeader`. These are `unsafe` functions operating on raw pointers into shared memory.

**Step 1: Create `pipe.rs` with init, read, write functions**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Lock-free SPSC pipe ring buffer operations on shared memory.
//!
//! Both micro and central call these functions to interact with pipe ring
//! buffers that live in the shmem data region. The ring buffer is a classic
//! single-producer/single-consumer design with atomic head/tail cursors.

use core::sync::atomic::Ordering::{Acquire, Relaxed, Release};

use crate::ring::{pipe_flags, ShmemPipeHeader, PIPE_DATA_CAPACITY};

/// Initialize a `ShmemPipeHeader` at the given pointer.
///
/// # Safety
///
/// `header` must point to a valid, writable, 64-byte-aligned region of at
/// least `PIPE_SLOT_SIZE` bytes in shared memory. The caller must ensure
/// exclusive access during initialization.
pub unsafe fn pipe_init(
    header: *mut ShmemPipeHeader,
    read_fd: i32,
    write_fd: i32,
    nonblock: bool,
) {
    unsafe {
        (*header).head = core::sync::atomic::AtomicU64::new(0);
        (*header).tail = core::sync::atomic::AtomicU64::new(0);
        (*header).capacity = PIPE_DATA_CAPACITY as u64;
        let flags = if nonblock { pipe_flags::NONBLOCK } else { 0 };
        (*header).flags = core::sync::atomic::AtomicU32::new(flags);
        (*header).read_fd = read_fd;
        (*header).write_fd = write_fd;
        (*header)._pad = [0u8; 24];
    }
}

/// Attempt a non-blocking write to the pipe ring buffer.
///
/// Returns the number of bytes written (may be less than `len` if the buffer
/// is full), or a negated errno:
/// - `-EPIPE` (32): reader closed
/// - `-EAGAIN` (11): buffer full and would block
///
/// # Safety
///
/// `header` must point to a valid `ShmemPipeHeader` in shared memory,
/// followed by `capacity` bytes of ring buffer data. `buf` must be a valid
/// readable slice.
pub unsafe fn pipe_try_write(header: *mut ShmemPipeHeader, buf: &[u8]) -> i64 {
    let h = unsafe { &*header };
    let flags = h.flags.load(Relaxed);
    if flags & pipe_flags::READER_CLOSED != 0 {
        return -i64::from(libc::EPIPE);
    }

    let capacity = h.capacity as usize;
    let mask = capacity - 1; // power-of-2

    let head = h.head.load(Acquire);
    let tail = h.tail.load(Relaxed); // writer owns tail
    let available = capacity - (tail.wrapping_sub(head)) as usize;

    if available == 0 {
        return -i64::from(libc::EAGAIN);
    }

    let to_write = buf.len().min(available);
    let data_base = unsafe { (header as *mut u8).add(core::mem::size_of::<ShmemPipeHeader>()) };

    let start = (tail as usize) & mask;
    let first_chunk = to_write.min(capacity - start); // bytes before wrap
    unsafe {
        core::ptr::copy_nonoverlapping(buf.as_ptr(), data_base.add(start), first_chunk);
        if to_write > first_chunk {
            // Wrap around
            core::ptr::copy_nonoverlapping(
                buf.as_ptr().add(first_chunk),
                data_base,
                to_write - first_chunk,
            );
        }
    }

    // Publish new tail
    h.tail.store(tail.wrapping_add(to_write as u64), Release);

    to_write as i64
}

/// Attempt a non-blocking read from the pipe ring buffer.
///
/// Returns the number of bytes read, or a negated errno:
/// - `0`: writer closed and buffer empty (EOF)
/// - `-EAGAIN` (11): buffer empty and would block
///
/// # Safety
///
/// `header` must point to a valid `ShmemPipeHeader` in shared memory,
/// followed by `capacity` bytes of ring buffer data. `buf` must be a valid
/// writable slice.
pub unsafe fn pipe_try_read(header: *mut ShmemPipeHeader, buf: &mut [u8]) -> i64 {
    let h = unsafe { &*header };
    let capacity = h.capacity as usize;
    let mask = capacity - 1;

    let head = h.head.load(Relaxed); // reader owns head
    let tail = h.tail.load(Acquire);
    let available = (tail.wrapping_sub(head)) as usize;

    if available == 0 {
        let flags = h.flags.load(Acquire);
        if flags & pipe_flags::WRITER_CLOSED != 0 {
            return 0; // EOF
        }
        return -i64::from(libc::EAGAIN);
    }

    let to_read = buf.len().min(available);
    let data_base = unsafe { (header as *mut u8).add(core::mem::size_of::<ShmemPipeHeader>()) };

    let start = (head as usize) & mask;
    let first_chunk = to_read.min(capacity - start);
    unsafe {
        core::ptr::copy_nonoverlapping(data_base.add(start), buf.as_mut_ptr(), first_chunk);
        if to_read > first_chunk {
            core::ptr::copy_nonoverlapping(
                data_base,
                buf.as_mut_ptr().add(first_chunk),
                to_read - first_chunk,
            );
        }
    }

    // Publish new head
    h.head.store(head.wrapping_add(to_read as u64), Release);

    to_read as i64
}

/// Set a flag on the pipe header (e.g., `READER_CLOSED`, `WRITER_CLOSED`).
pub fn pipe_set_flag(header: *mut ShmemPipeHeader, flag: u32) {
    let h = unsafe { &*header };
    h.flags.fetch_or(flag, Release);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ring::PIPE_SLOT_SIZE;

    /// Helper: allocate an aligned pipe slot on the heap for testing.
    fn alloc_pipe_slot() -> Vec<u8> {
        vec![0u8; PIPE_SLOT_SIZE + 64] // extra for alignment
    }

    fn aligned_header(buf: &mut [u8]) -> *mut ShmemPipeHeader {
        let addr = buf.as_mut_ptr() as usize;
        let aligned = (addr + 63) & !63;
        aligned as *mut ShmemPipeHeader
    }

    #[test]
    fn pipe_init_sets_fields() {
        let mut buf = alloc_pipe_slot();
        let h = aligned_header(&mut buf);
        unsafe { pipe_init(h, 3, 4, false) };
        unsafe {
            assert_eq!((*h).head.load(Relaxed), 0);
            assert_eq!((*h).tail.load(Relaxed), 0);
            assert_eq!((*h).capacity, PIPE_DATA_CAPACITY as u64);
            assert_eq!((*h).flags.load(Relaxed), 0);
            assert_eq!((*h).read_fd, 3);
            assert_eq!((*h).write_fd, 4);
        }
    }

    #[test]
    fn pipe_init_nonblock() {
        let mut buf = alloc_pipe_slot();
        let h = aligned_header(&mut buf);
        unsafe { pipe_init(h, 3, 4, true) };
        unsafe {
            assert_eq!((*h).flags.load(Relaxed), pipe_flags::NONBLOCK);
        }
    }

    #[test]
    fn pipe_write_then_read() {
        let mut buf = alloc_pipe_slot();
        let h = aligned_header(&mut buf);
        unsafe { pipe_init(h, 3, 4, false) };

        let data = b"hello world";
        let written = unsafe { pipe_try_write(h, data) };
        assert_eq!(written, 11);

        let mut out = [0u8; 64];
        let read = unsafe { pipe_try_read(h, &mut out) };
        assert_eq!(read, 11);
        assert_eq!(&out[..11], b"hello world");
    }

    #[test]
    fn pipe_read_empty_returns_eagain() {
        let mut buf = alloc_pipe_slot();
        let h = aligned_header(&mut buf);
        unsafe { pipe_init(h, 3, 4, false) };

        let mut out = [0u8; 64];
        let result = unsafe { pipe_try_read(h, &mut out) };
        assert_eq!(result, -i64::from(libc::EAGAIN));
    }

    #[test]
    fn pipe_read_empty_after_writer_closed_returns_eof() {
        let mut buf = alloc_pipe_slot();
        let h = aligned_header(&mut buf);
        unsafe { pipe_init(h, 3, 4, false) };

        pipe_set_flag(h, pipe_flags::WRITER_CLOSED);
        let mut out = [0u8; 64];
        let result = unsafe { pipe_try_read(h, &mut out) };
        assert_eq!(result, 0); // EOF
    }

    #[test]
    fn pipe_write_reader_closed_returns_epipe() {
        let mut buf = alloc_pipe_slot();
        let h = aligned_header(&mut buf);
        unsafe { pipe_init(h, 3, 4, false) };

        pipe_set_flag(h, pipe_flags::READER_CLOSED);
        let result = unsafe { pipe_try_write(h, b"data") };
        assert_eq!(result, -i64::from(libc::EPIPE));
    }

    #[test]
    fn pipe_fills_to_capacity() {
        let mut buf = alloc_pipe_slot();
        let h = aligned_header(&mut buf);
        unsafe { pipe_init(h, 3, 4, false) };

        let big = vec![0xABu8; PIPE_DATA_CAPACITY];
        let written = unsafe { pipe_try_write(h, &big) };
        assert_eq!(written as usize, PIPE_DATA_CAPACITY);

        // Buffer full — next write should return EAGAIN
        let result = unsafe { pipe_try_write(h, b"x") };
        assert_eq!(result, -i64::from(libc::EAGAIN));
    }

    #[test]
    fn pipe_wraparound() {
        let mut buf = alloc_pipe_slot();
        let h = aligned_header(&mut buf);
        unsafe { pipe_init(h, 3, 4, false) };

        // Fill most of the buffer
        let fill = vec![0u8; PIPE_DATA_CAPACITY - 10];
        let w = unsafe { pipe_try_write(h, &fill) };
        assert_eq!(w as usize, PIPE_DATA_CAPACITY - 10);

        // Read it all back to advance head
        let mut drain = vec![0u8; PIPE_DATA_CAPACITY];
        let r = unsafe { pipe_try_read(h, &mut drain) };
        assert_eq!(r as usize, PIPE_DATA_CAPACITY - 10);

        // Now write 20 bytes — wraps around the buffer boundary
        let wrap_data = [0x42u8; 20];
        let w2 = unsafe { pipe_try_write(h, &wrap_data) };
        assert_eq!(w2, 20);

        let mut out = [0u8; 20];
        let r2 = unsafe { pipe_try_read(h, &mut out) };
        assert_eq!(r2, 20);
        assert_eq!(out, [0x42u8; 20]);
    }
}
```

**Step 2: Add `pub mod pipe;` to `lib.rs`**

In `litebox_ipc/src/lib.rs`, add:

```rust
pub mod pipe;
```

**Step 3: Run tests**

Run: `cargo nextest run -p litebox_ipc`
Expected: All tests pass (existing + 8 new pipe tests).

**Step 4: Commit**

```bash
git add litebox_ipc/src/pipe.rs litebox_ipc/src/lib.rs
git commit -m "ipc: implement lock-free SPSC pipe ring buffer operations on shmem"
```

---

## Task 5: Add pipe slot allocator to central

**Files:**
- Modify: `litebox_central/src/notification_state.rs`

**Step 1: Add pipe slot bitset and allocator**

Replace the `MicroPipe` struct and update `ProcessNotificationState`:

```rust
use litebox_ipc::ring::{MAX_PIPE_SLOTS, PIPE_ZONE_BASE_OFFSET, PIPE_SLOT_SIZE};

/// A shmem-backed pipe tracked by central.
#[derive(Clone, Copy)]
#[allow(dead_code)]
pub(crate) struct ShmemPipe {
    pub read_fd: i32,
    pub write_fd: i32,
    /// Slot index in the pipe zone (0..MAX_PIPE_SLOTS).
    pub slot_index: u8,
    /// Reference count: how many fd endpoints are still open (0, 1, or 2).
    pub open_ends: u8,
}
```

Add to `ProcessNotificationState`:

```rust
    /// Shmem pipe slot allocation bitset. Bit N = 1 means slot N is in use.
    pub pipe_slot_bitset: u64,

    /// Active shmem-backed pipes.
    pub shmem_pipes: Vec<ShmemPipe>,
```

Add methods:

```rust
impl ProcessNotificationState {
    /// Allocate a free pipe slot. Returns the slot index and data-region offset.
    pub fn alloc_pipe_slot(&mut self) -> Option<(u8, u32)> {
        if self.pipe_slot_bitset == u64::MAX {
            return None; // all 64 bits set (though only 47 are valid)
        }
        let free_bit = self.pipe_slot_bitset.trailing_ones();
        if free_bit as usize >= MAX_PIPE_SLOTS {
            return None;
        }
        self.pipe_slot_bitset |= 1u64 << free_bit;
        let offset = PIPE_ZONE_BASE_OFFSET + (free_bit as usize) * PIPE_SLOT_SIZE;
        Some((free_bit as u8, offset as u32))
    }

    /// Free a pipe slot.
    pub fn free_pipe_slot(&mut self, slot_index: u8) {
        self.pipe_slot_bitset &= !(1u64 << slot_index);
    }

    /// Find a shmem pipe by fd (either read or write end).
    pub fn find_shmem_pipe(&self, fd: i32) -> Option<&ShmemPipe> {
        self.shmem_pipes.iter().find(|p| p.read_fd == fd || p.write_fd == fd)
    }

    /// Find a mutable shmem pipe by fd.
    pub fn find_shmem_pipe_mut(&mut self, fd: i32) -> Option<&mut ShmemPipe> {
        self.shmem_pipes.iter_mut().find(|p| p.read_fd == fd || p.write_fd == fd)
    }
}
```

Update `Default` to initialize the new fields:

```rust
            pipe_slot_bitset: 0,
            shmem_pipes: Vec::new(),
```

Keep `micro_pipes` for now (will be removed in cleanup later), or remove it if nothing else references it.

**Step 2: Add tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_pipe_slot_returns_sequential_indices() {
        let mut state = ProcessNotificationState::default();
        let (idx0, off0) = state.alloc_pipe_slot().unwrap();
        let (idx1, off1) = state.alloc_pipe_slot().unwrap();
        assert_eq!(idx0, 0);
        assert_eq!(idx1, 1);
        assert_eq!(off0 as usize, PIPE_ZONE_BASE_OFFSET);
        assert_eq!(off1 as usize, PIPE_ZONE_BASE_OFFSET + PIPE_SLOT_SIZE);
    }

    #[test]
    fn free_pipe_slot_allows_reuse() {
        let mut state = ProcessNotificationState::default();
        let (idx, _) = state.alloc_pipe_slot().unwrap();
        state.free_pipe_slot(idx);
        let (idx2, _) = state.alloc_pipe_slot().unwrap();
        assert_eq!(idx, idx2); // reused
    }

    #[test]
    fn alloc_pipe_slot_exhaustion() {
        let mut state = ProcessNotificationState::default();
        for _ in 0..MAX_PIPE_SLOTS {
            assert!(state.alloc_pipe_slot().is_some());
        }
        assert!(state.alloc_pipe_slot().is_none()); // full
    }
}
```

**Step 3: Run tests**

Run: `cargo nextest run -p litebox_central`
Expected: All tests pass.

**Step 4: Commit**

```bash
git add litebox_central/src/notification_state.rs
git commit -m "central: add pipe slot allocator with bitset for shmem pipe management"
```

---

## Task 6: Wire up pipe2 in central to create shmem-backed pipes

**Files:**
- Modify: `litebox_central/src/server.rs`

This is the critical change: when central receives a `pipe2` syscall, instead of returning `EXEC_LOCAL`, it:
1. Dispatches to the shim (which creates virtual pipe fds)
2. Allocates a shmem pipe slot
3. Initializes the ring buffer header
4. Writes a `Pipe2Response` to the data region
5. Returns the CQ with `HAS_DATA`

**Step 1: Remove `SYS_pipe2` from `needs_local_exec()`**

In `server.rs`, find `needs_local_exec()` and remove `| libc::SYS_pipe2` from the match.

**Step 2: Add pipe2 handling in `handle_syscall()`**

Before the `needs_local_exec()` check (after the dup/fcntl block, around line 328), add:

```rust
        // pipe2: create virtual pipes in shim's fd table, allocate shmem
        // ring buffer slot, return fd pair + slot offset to micro.
        #[allow(clippy::cast_possible_truncation)]
        if nr == libc::SYS_pipe2 as u32 {
            return self.handle_pipe2(entry);
        }
```

**Step 3: Implement `handle_pipe2()`**

Add a new method to the `impl Server` block:

```rust
    /// Handle `pipe2` by creating virtual pipes in the shim and allocating a
    /// shmem ring buffer slot.
    #[allow(clippy::cast_possible_truncation)]
    fn handle_pipe2(&self, entry: &SqEntry) -> CqEntry {
        let mut cq = Self::base_cq(entry);
        let flags = entry.args[1] as i32;

        // Dispatch to shim — creates virtual pipe fds in the fd table.
        let mut regs = crate::dispatch::sq_entry_to_ptregs(entry);
        let shim_result = self.dispatch_to_task(entry.thread_slot, &mut regs);
        if shim_result < 0 {
            cq.result = shim_result;
            return cq;
        }

        // shim_result is 0 on success. The shim wrote the fd pair into
        // PtRegs (rax = packed result). For pipe2, the shim returns a
        // packed u64 with (read_fd, write_fd). We need to extract them.
        // Actually: the shim's sys_pipe2 returns (read_fd, write_fd) as a
        // tuple. The dispatch layer packs this as: rax = read_fd (low 32),
        // rdx = write_fd (high 32)... 
        // 
        // TODO: Need to check how the shim returns pipe2 results. The shim
        // returns `Result<(u32, u32), Errno>`. The dispatch layer needs to
        // encode both fd values in the return. Check dispatch.rs for how
        // two-value returns are handled.
        //
        // For now, we read the fd values from regs after dispatch.
        let read_fd = (regs.rax & 0xFFFF_FFFF) as i32;
        let write_fd = ((regs.rax >> 32) & 0xFFFF_FFFF) as i32;

        // Allocate a shmem pipe slot.
        let mut notif = self.notification_state.borrow_mut();
        let Some((slot_index, slot_offset)) = notif.alloc_pipe_slot() else {
            // No free pipe slots — close the virtual pipes and return EMFILE.
            // TODO: close the shim fds
            cq.result = -i64::from(libc::EMFILE);
            return cq;
        };

        // Initialize the shmem ring buffer header.
        let nonblock = flags & libc::O_NONBLOCK != 0;
        let header_ptr = unsafe {
            self.region.as_ptr()
                .add(self.region.layout().data_region_offset)
                .add(slot_offset as usize)
                .cast::<litebox_ipc::ring::ShmemPipeHeader>()
        };
        unsafe {
            litebox_ipc::pipe::pipe_init(header_ptr, read_fd, write_fd, nonblock);
        }

        // Track the pipe.
        notif.shmem_pipes.push(crate::notification_state::ShmemPipe {
            read_fd,
            write_fd,
            slot_index,
            open_ends: 2,
        });
        drop(notif);

        // Write Pipe2Response to the data region at offset 0.
        let response = litebox_ipc::messages::Pipe2Response {
            read_fd,
            write_fd,
            pipe_slot_offset: slot_offset,
            _pad: 0,
        };
        let data = self.region.data_region_mut();
        let resp_bytes = unsafe {
            core::slice::from_raw_parts(
                &response as *const _ as *const u8,
                core::mem::size_of::<litebox_ipc::messages::Pipe2Response>(),
            )
        };
        data[..resp_bytes.len()].copy_from_slice(resp_bytes);

        cq.result = 0;
        cq.flags = cq_flags::EXEC_LOCAL | cq_flags::HAS_DATA;
        cq.data_offset = 0;
        cq.data_len = resp_bytes.len() as u32;
        cq
    }
```

**Important note:** The exact mechanism for extracting `(read_fd, write_fd)` from the shim's return value depends on how `dispatch_to_task` encodes tuple returns from `sys_pipe2`. This needs investigation during implementation — check `dispatch.rs` and the shim's syscall dispatch for `SYS_pipe2`.

**Step 4: Run build**

Run: `cargo build -p litebox_central`
Expected: Compiles without errors. (Full integration testing comes in Task 8.)

**Step 5: Commit**

```bash
git add litebox_central/src/server.rs
git commit -m "central: handle pipe2 by creating shmem-backed pipes in shim + ring buffer"
```

---

## Task 7: Wire up micro to use shmem pipes for read/write

**Files:**
- Modify: `litebox_micro/src/handler.rs`
- Modify: `litebox_micro/src/local_exec.rs`

**Step 1: Remove `SYS_pipe2` from `is_tier2_notify()` in `handler.rs`**

Remove `| libc::SYS_pipe2` from the match in `is_tier2_notify()` (line 543). pipe2 is now Tier 3 (goes to central).

**Step 2: Add pipe2 response handling in the EXEC_LOCAL block**

In `micro_handle_syscall()`, in the `EXEC_LOCAL` block (after line 600), add special handling for pipe2:

```rust
        // pipe2: central created shmem pipe, read response from data region.
        if nr == libc::SYS_pipe2 as u32 && cq.flags & cq_flags::HAS_DATA != 0 {
            let micro = unsafe { &mut *(*tls).micro };
            let data_base = unsafe { micro.ring_base.add(micro.layout.data_region_offset) };
            let resp = unsafe {
                &*(data_base.add(cq.data_offset as usize)
                    as *const litebox_ipc::messages::Pipe2Response)
            };
            // Register both pipe fds for fast-path read/write.
            micro.register_pipe_fd(resp.read_fd, resp.pipe_slot_offset, false);
            micro.register_pipe_fd(resp.write_fd, resp.pipe_slot_offset, true);
            // Write fd pair to guest's output pointer.
            let fds_ptr = args.args[0] as *mut i32;
            unsafe {
                *fds_ptr = resp.read_fd;
                *fds_ptr.add(1) = resp.write_fd;
            }
            return 0; // success
        }
```

**Step 3: Add pipe fast-path check before `submit_and_wait`**

Before the `submit_and_wait` call in `micro_handle_syscall()` (around line 597), add:

```rust
    // Shmem pipe fast-path: read/write on pipe fds bypass central entirely.
    {
        let micro = unsafe { &*(*tls).micro };
        let fd = args.args[0] as i32;
        if let Some((shmem_offset, is_write_end)) = micro.find_pipe_fd(fd) {
            match i64::from(nr) {
                libc::SYS_write | libc::SYS_pwrite64 if is_write_end => {
                    let buf = args.args[1] as *const u8;
                    let count = args.args[2] as usize;
                    return unsafe {
                        shmem_pipe_write(micro, shmem_offset, buf, count)
                    };
                }
                libc::SYS_read | libc::SYS_pread64 if !is_write_end => {
                    let buf = args.args[1] as *mut u8;
                    let count = args.args[2] as usize;
                    return unsafe {
                        shmem_pipe_read(micro, shmem_offset, buf, count)
                    };
                }
                libc::SYS_writev if is_write_end => {
                    // For writev on pipes, gather iovec then write.
                    return unsafe {
                        shmem_pipe_writev(micro, shmem_offset, args.args[1], args.args[2] as usize)
                    };
                }
                _ => {} // fall through to central for close, dup, etc.
            }
        }
    }
```

**Step 4: Implement `shmem_pipe_write` and `shmem_pipe_read`**

Add helper functions in `handler.rs`:

```rust
/// Write to a shmem pipe ring buffer with blocking support.
///
/// # Safety
///
/// `buf_ptr` must point to valid readable memory of at least `count` bytes.
unsafe fn shmem_pipe_write(
    micro: &crate::state::MicroState,
    shmem_offset: u32,
    buf_ptr: *const u8,
    count: usize,
) -> i64 {
    if count == 0 {
        return 0;
    }
    let header = unsafe {
        micro.ring_base
            .add(micro.layout.data_region_offset)
            .add(shmem_offset as usize)
            .cast::<litebox_ipc::ring::ShmemPipeHeader>()
    };
    let buf = unsafe { core::slice::from_raw_parts(buf_ptr, count) };
    let mut total_written = 0usize;

    loop {
        let result = unsafe { litebox_ipc::pipe::pipe_try_write(header, &buf[total_written..]) };
        if result == -i64::from(libc::EPIPE) {
            if total_written > 0 {
                return total_written as i64;
            }
            // TODO: send SIGPIPE to current thread
            return -i64::from(libc::EPIPE);
        }
        if result > 0 {
            total_written += result as usize;
            if total_written >= count {
                return total_written as i64;
            }
            // Partial write — continue for blocking pipes
            continue;
        }
        // result == -EAGAIN: buffer full
        let flags = unsafe { (*header).flags.load(core::sync::atomic::Ordering::Relaxed) };
        if flags & litebox_ipc::ring::pipe_flags::NONBLOCK != 0 {
            if total_written > 0 {
                return total_written as i64;
            }
            return -i64::from(libc::EAGAIN);
        }
        // Blocking: spin briefly then futex-wait on head (reader will advance it)
        let head_ptr = unsafe { &(*header).head };
        let current_head = head_ptr.load(core::sync::atomic::Ordering::Relaxed);
        // Spin a few times before futex
        for _ in 0..100 {
            core::hint::spin_loop();
            if head_ptr.load(core::sync::atomic::Ordering::Relaxed) != current_head {
                break;
            }
        }
        if head_ptr.load(core::sync::atomic::Ordering::Relaxed) == current_head {
            // Still no progress — futex wait
            unsafe {
                crate::raw_syscall::futex4(
                    core::ptr::from_ref(head_ptr) as *const _ as usize,
                    libc::FUTEX_WAIT,
                    current_head as u32, // compare low 32 bits
                    0,
                );
            }
        }
    }
}

/// Read from a shmem pipe ring buffer with blocking support.
///
/// # Safety
///
/// `buf_ptr` must point to valid writable memory of at least `count` bytes.
unsafe fn shmem_pipe_read(
    micro: &crate::state::MicroState,
    shmem_offset: u32,
    buf_ptr: *mut u8,
    count: usize,
) -> i64 {
    if count == 0 {
        return 0;
    }
    let header = unsafe {
        micro.ring_base
            .add(micro.layout.data_region_offset)
            .add(shmem_offset as usize)
            .cast::<litebox_ipc::ring::ShmemPipeHeader>()
    };
    let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr, count) };

    loop {
        let result = unsafe { litebox_ipc::pipe::pipe_try_read(header, buf) };
        if result >= 0 {
            // Wake writer (may be blocked on full buffer)
            let tail_ptr = unsafe { &(*header).tail };
            unsafe {
                crate::raw_syscall::futex4(
                    core::ptr::from_ref(tail_ptr) as *const _ as usize,
                    libc::FUTEX_WAKE,
                    1,
                    0,
                );
            }
            return result; // 0 = EOF, >0 = bytes read
        }
        // result == -EAGAIN: buffer empty
        let flags = unsafe { (*header).flags.load(core::sync::atomic::Ordering::Relaxed) };
        if flags & litebox_ipc::ring::pipe_flags::NONBLOCK != 0 {
            return -i64::from(libc::EAGAIN);
        }
        // Blocking: spin briefly then futex-wait on tail (writer will advance it)
        let tail_ptr = unsafe { &(*header).tail };
        let current_tail = tail_ptr.load(core::sync::atomic::Ordering::Relaxed);
        for _ in 0..100 {
            core::hint::spin_loop();
            if tail_ptr.load(core::sync::atomic::Ordering::Relaxed) != current_tail {
                break;
            }
        }
        if tail_ptr.load(core::sync::atomic::Ordering::Relaxed) == current_tail {
            unsafe {
                crate::raw_syscall::futex4(
                    core::ptr::from_ref(tail_ptr) as *const _ as usize,
                    libc::FUTEX_WAIT,
                    current_tail as u32,
                    0,
                );
            }
        }
    }
}
```

**Step 5: Handle close for pipe fds**

In the EXEC_LOCAL block for `close`, after micro executes `close(fd)` locally, add unregistration:

Actually, with shmem pipes, close should NOT execute locally (there's no real OS fd to close). Instead, close goes to central (which closes the shim fd and sets flags). After the CQ response, micro just unregisters the fd:

In the `handle_syscall` EXEC_LOCAL block, add before the generic `execute_locally` call:

```rust
        // close on pipe fd: central already closed the shim fd and set
        // shmem flags. Just unregister from micro's tracking table.
        if nr == libc::SYS_close as u32 {
            let micro = unsafe { &mut *(*tls).micro };
            micro.unregister_pipe_fd(args.args[0] as i32);
            // Still execute locally in case the fd is real (non-pipe).
            // For shmem pipes, there's no real OS fd, so close() will
            // return EBADF — but we ignore the result.
        }
```

Wait — this is wrong. With shmem pipes, there IS no real OS fd. Central's close already handled the virtual fd. Micro just needs to unregister. We should detect this case.

Better approach: when central handles `close()` on a pipe fd, it can set the shmem flags and return `result = 0` directly (no EXEC_LOCAL). Micro then just unregisters the fd. Let me revise this in Task 6's close path.

**Step 6: Run build and tests**

Run: `cargo build -p litebox_micro -p litebox_launcher && cargo build -p litebox_central`
Expected: Compiles.

Run: `cargo nextest run -p litebox_micro`
Expected: All existing tests pass.

**Step 7: Commit**

```bash
git add litebox_micro/src/handler.rs litebox_micro/src/local_exec.rs
git commit -m "micro: shmem pipe fast-path for read/write bypassing central round-trip"
```

---

## Task 8: Update close handling for shmem pipes in central

**Files:**
- Modify: `litebox_central/src/server.rs`

**Step 1: Update close dispatch for pipe fds**

In `handle_syscall`, the close block (line 290-301) currently dispatches to shim and returns `EXEC_LOCAL` on EBADF. For shmem pipes, the shim WILL recognize the fd (since we created it there), so it will return success. But we also need to update the shmem flags.

After the shim successfully closes a pipe fd, set the appropriate shmem flag:

```rust
        if nr == libc::SYS_close as u32 {
            let fd = entry.args[0] as i32;
            let mut regs = crate::dispatch::sq_entry_to_ptregs(entry);
            let shim_result = self.dispatch_to_task(entry.thread_slot, &mut regs);
            if shim_result >= 0 {
                // Shim recognized and closed the fd. Check if it's a shmem pipe
                // and update flags + bookkeeping.
                self.maybe_close_shmem_pipe_end(fd);
                cq.result = 0;
                return cq;
            }
            // EBADF: not in shim — real OS fd, let micro close.
            cq.flags = cq_flags::EXEC_LOCAL | cq_flags::NO_REPORT;
            return cq;
        }
```

**Step 2: Implement `maybe_close_shmem_pipe_end`**

```rust
    /// If `fd` is one end of a shmem pipe, set the appropriate close flag
    /// and potentially free the pipe slot.
    fn maybe_close_shmem_pipe_end(&self, fd: i32) {
        let mut notif = self.notification_state.borrow_mut();
        let Some(pipe) = notif.find_shmem_pipe_mut(fd) else {
            return; // not a shmem pipe fd
        };

        // Set the appropriate close flag in the shmem header.
        let slot_offset = PIPE_ZONE_BASE_OFFSET + pipe.slot_index as usize * PIPE_SLOT_SIZE;
        let header_ptr = unsafe {
            self.region.as_ptr()
                .add(self.region.layout().data_region_offset)
                .add(slot_offset)
                .cast::<litebox_ipc::ring::ShmemPipeHeader>()
        };
        let flag = if fd == pipe.read_fd {
            litebox_ipc::ring::pipe_flags::READER_CLOSED
        } else {
            litebox_ipc::ring::pipe_flags::WRITER_CLOSED
        };
        litebox_ipc::pipe::pipe_set_flag(header_ptr, flag);

        // Futex-wake any blocked reader/writer on the pipe.
        unsafe {
            let head_ptr = &(*header_ptr).head;
            let tail_ptr = &(*header_ptr).tail;
            libc::syscall(libc::SYS_futex, head_ptr as *const _ as *const u8, libc::FUTEX_WAKE, i32::MAX, std::ptr::null::<libc::timespec>());
            libc::syscall(libc::SYS_futex, tail_ptr as *const _ as *const u8, libc::FUTEX_WAKE, i32::MAX, std::ptr::null::<libc::timespec>());
        }

        pipe.open_ends -= 1;
        let slot_index = pipe.slot_index;
        if pipe.open_ends == 0 {
            // Both ends closed — free the pipe slot.
            notif.shmem_pipes.retain(|p| p.slot_index != slot_index);
            notif.free_pipe_slot(slot_index);
        }
    }
```

**Step 3: Run build**

Run: `cargo build -p litebox_central`
Expected: Compiles.

**Step 4: Commit**

```bash
git add litebox_central/src/server.rs
git commit -m "central: update close handling to set shmem pipe flags and free slots"
```

---

## Task 9: Remove pipe2 from Tier 2 notification infrastructure

**Files:**
- Modify: `litebox_micro/src/local_exec.rs` — remove `SYS_pipe2` from `tier2_notify_message()` and `tier2_notify_args()`
- Modify: `litebox_ipc/src/messages.rs` — update `MSG_NOTIFY_PIPE2` doc comment to note it's deprecated
- Modify: `litebox_central/src/server.rs` — remove/update the `MSG_NOTIFY_PIPE2` handler

pipe2 is no longer Tier 2. The old `MSG_NOTIFY_PIPE2` notification path is dead code.

**Step 1: Remove pipe2 from tier2 functions in `local_exec.rs`**

Remove the `libc::SYS_pipe2 => litebox_ipc::messages::MSG_NOTIFY_PIPE2` arm from `tier2_notify_message()`.

Remove the `libc::SYS_pipe2 => { ... }` arm from `tier2_notify_args()`.

Remove `SYS_pipe2` from `execute_micro_local()` if it has a dedicated arm there.

**Step 2: Update tests**

Update any tests that reference pipe2 as Tier 2 (e.g., `tier2_pipe2_notify_args_success`, `tier2_pipe2_is_tier2`).

**Step 3: Run tests**

Run: `cargo nextest run -p litebox_micro`
Run: `cargo nextest run -p litebox_ipc`
Expected: All pass.

**Step 4: Commit**

```bash
git add litebox_micro/src/local_exec.rs litebox_ipc/src/messages.rs litebox_central/src/server.rs
git commit -m "cleanup: remove pipe2 from Tier 2 notification path (now Tier 3 with shmem)"
```

---

## Task 10: Integration test — run pipe benchmark

**Step 1: Build release**

```bash
cargo build --release -p litebox_micro -p litebox_launcher && cargo build --release -p litebox_central
```

**Step 2: Clean up and run pipe benchmark**

```bash
pkill -9 litebox_central; pkill -9 litebox
cd /workspace/litebox-mu/dev_bench/unixbench
python3 run_unixbench.py --mode micro --release --no-build --duration 10 --iterations 1 --benchmarks pipe
```

Expected: Significantly improved pipe throughput (target: >1.0x native, up from 0.29x).

**Step 3: Run other benchmarks to check for regressions**

```bash
python3 run_unixbench.py --mode micro --release --no-build --duration 10 --iterations 1 --benchmarks dhry2reg syscall context1
```

Expected: No regressions on dhry2reg, syscall, context1.

**Step 4: Run shell1 benchmark**

```bash
python3 run_unixbench.py --mode micro --release --no-build --duration 10 --iterations 1 --benchmarks shell1
```

Expected: May not improve (shell1 is dominated by fork/execve), but should not regress.

---

## Implementation Notes

### How pipe2 return values work in the shim dispatch

The shim's `sys_pipe2` returns `Result<(u32, u32), Errno>`. The dispatch layer in `litebox_central/src/dispatch.rs` needs to encode both fd values. **Investigate during Task 6 implementation** how the dispatch layer returns two values — it may pack them into `regs.rax` and `regs.rdx`, or it may use a different mechanism. This is a critical implementation detail.

### Futex correctness on shmem atomics

Futex works on `MAP_SHARED` memory between processes (the `FUTEX_WAIT`/`FUTEX_WAKE` system calls compare physical pages, not virtual addresses). Since our shmem is `MAP_SHARED` from a memfd, futex operations on `ShmemPipeHeader.head` and `.tail` will correctly wake cross-process waiters. This is important for the blocking read/write path.

### Single-process vs cross-process pipes

This implementation handles **single-process pipes** (one process has both read and write ends in the same shmem). For cross-process pipes (after fork, where parent and child each have one end), the shmem ring buffer lives in the parent's shmem region, which the child doesn't have access to. Phase B will address this with dedicated per-pipe memfd mappings.

### PIPE_BUF atomicity

Linux guarantees that writes ≤ `PIPE_BUF` (4096 bytes) are atomic (not interleaved with other writers). For SPSC pipes (single writer, single reader), this is naturally satisfied since there's only one writer. For `dup()`'d write ends shared across threads, a mutex would be needed. The pipe benchmark is single-threaded, so SPSC is sufficient for now.
