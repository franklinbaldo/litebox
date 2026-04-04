# Shmem Socket Rings: Bypass SQ/CQ for Socket Data Transfer

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Eliminate 2 data copies per direction and the SQ/CQ futex round-trip for socket read/write by placing socket channel ring buffers in shared memory, allowing micro to access them directly (like pipes).

**Architecture:** Each accepted/connected TCP stream socket gets a pair of SPSC ring buffers (RX + TX) in a pre-allocated shmem zone. Micro reads/writes these rings directly using atomic head/tail cursors with futex-based blocking. The net-worker thread drains TX rings into smoltcp and fills RX rings from smoltcp. Control operations (accept, connect, close, epoll) still use SQ/CQ. The existing pipe shmem implementation is the template.

**Tech Stack:** `litebox_ipc` (no_std SPSC ring), `litebox_micro` (direct shmem access), `litebox_central` (slot allocation, net-worker integration), smoltcp, futex

---

## Background

### Current data path (per socket read)

```
kernel → TUN read → stack buf → smoltcp RX ring → HeapRb channel RX → shmem scratch → guest buffer
         copy #1                  copy #2            copy #3             copy #4         copy #5
                                                  (net mutex)         (net mutex)
                                                                    + futex SQ/CQ
```

### Target data path (per socket read)

```
kernel → TUN read → stack buf → smoltcp RX ring → shmem socket RX ring → guest buffer
         copy #1                  copy #2              copy #3              copy #4
                                                    (net mutex)         (direct, no SQ/CQ)
```

Eliminates: 1 data copy + futex SQ/CQ round-trip per read. Same for write.

### Key invariants
- `litebox`, `litebox_shim_linux`, `litebox_micro`, `litebox_ipc` are `#![no_std]`
- Only `litebox_central` and `litebox_launcher` have `std`
- Copyright header: `// Copyright (c) Microsoft Corporation.\n// Licensed under the MIT license.`
- Clippy: `cargo clippy -p litebox -p litebox_shim_linux -p litebox_micro -p litebox_launcher` and `cargo clippy -p litebox_central`
- Tests: `cargo nextest run -p litebox_ipc`
- Stack in micro syscall handler is only 8-byte aligned — use `MaybeUninit` for stack buffers
- In micro's syscall handler context, the stack is only 8-byte aligned (not 16-byte) — the compiler may emit SSE `movaps` instructions for stack array zeroing which require 16-byte alignment — use `MaybeUninit` for stack buffers to avoid GPF crashes

### Key reference files (pipe implementation as template)
- `litebox_ipc/src/pipe.rs` — `ShmemPipeHeader`, `pipe_try_read`, `pipe_try_write`, `pipe_init`, `pipe_set_flag`
- `litebox_ipc/src/ring.rs` — Layout constants, `SharedRingLayout`, `ShmemPipeHeader` struct
- `litebox_ipc/src/messages.rs` — `Pipe2Response`
- `litebox_central/src/notification_state.rs` — `ShmemPipe`, `alloc_pipe_slot`, `free_pipe_slot`
- `litebox_central/src/server.rs` — `handle_pipe2`, `maybe_close_shmem_pipe_end`
- `litebox_central/src/shmem.rs` — `SharedRegion`, memfd creation
- `litebox_micro/src/handler.rs` — `shmem_pipe_read`, `shmem_pipe_write`, pipe2 response handling
- `litebox_micro/src/state.rs` — `MicroState`, `PipeFdEntry`

---

## Task 1: Add socket ring buffer types to `litebox_ipc`

Define the shmem socket ring header and try_read/try_write functions, modeled on the existing pipe implementation but with two rings (RX + TX) per slot.

**Files:**
- Create: `litebox_ipc/src/socket_ring.rs`
- Modify: `litebox_ipc/src/lib.rs` (add `pub mod socket_ring;`)
- Modify: `litebox_ipc/src/ring.rs` (add socket zone constants)
- Modify: `litebox_ipc/src/messages.rs` (add `AcceptResponse` message type)

**Step 1: Add socket zone constants to `litebox_ipc/src/ring.rs`**

Add after the existing pipe constants (line ~44):

```rust
/// Size of socket ring data buffer per direction (must be power-of-2).
/// 256 KiB matches the current HeapRb socket channel size.
pub const SOCKET_RING_CAPACITY: usize = 256 * 1024;

/// Size of the socket ring header (cache-line aligned).
/// Contains RX header, TX header, and control flags.
pub const SOCKET_RING_HEADER_SIZE: usize = 192; // 3 cache lines

/// Size of each socket slot: header + RX data + TX data.
pub const SOCKET_SLOT_SIZE: usize = SOCKET_RING_HEADER_SIZE + 2 * SOCKET_RING_CAPACITY;

/// Base offset within the data region where socket ring buffers start.
/// Placed after the pipe zone. The data region must be enlarged to accommodate.
/// Pipe zone ends at: 5 MiB + 47 * 65600 = 5 MiB + 3083200 ≈ 7.94 MiB
/// Round up to 8 MiB boundary.
pub const SOCKET_ZONE_BASE_OFFSET: usize = 8 * 1024 * 1024;

/// Maximum number of concurrent socket slots.
/// Each slot is ~512 KiB. With 32 MiB socket zone: 32 MiB / 512 KiB = 64 slots.
pub const MAX_SOCKET_SLOTS: usize = 64;

/// Total data region size including socket zone.
/// 8 MiB (existing) + 32 MiB (socket zone) = 40 MiB.
pub const SOCKET_DATA_REGION_SIZE: usize = SOCKET_ZONE_BASE_OFFSET + MAX_SOCKET_SLOTS * SOCKET_SLOT_SIZE;
```

**Step 2: Create `litebox_ipc/src/socket_ring.rs` with header struct**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared-memory SPSC ring buffers for TCP stream socket data transfer
//! between micro-LiteBox (guest) and central LiteBox (net-worker).
//!
//! Each accepted/connected socket gets a slot containing two rings:
//! - **RX ring**: net-worker produces (from smoltcp), micro consumes (guest `read()`)
//! - **TX ring**: micro produces (guest `write()`), net-worker consumes (into smoltcp)
//!
//! The design mirrors `pipe.rs` but with bidirectional rings and socket-specific
//! control flags (shutdown, error, EOF).

#![allow(clippy::pub_underscore_fields)]

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::ring::{SOCKET_RING_CAPACITY, SOCKET_RING_HEADER_SIZE};

/// Status flags for a shmem socket slot.
pub mod socket_flags {
    /// The RX (read) direction has been shut down (SHUT_RD or peer sent FIN).
    /// When set with an empty RX ring, `read()` returns 0 (EOF).
    pub const RX_SHUTDOWN: u32 = 1 << 0;
    /// The TX (write) direction has been shut down (SHUT_WR).
    /// When set, `write()` returns -EPIPE.
    pub const TX_SHUTDOWN: u32 = 1 << 1;
    /// The socket has been closed by central (e.g., connection reset).
    pub const CLOSED: u32 = 1 << 2;
    /// The socket is in non-blocking mode.
    pub const NONBLOCK: u32 = 1 << 3;
    /// An error occurred. The error code is in `ShmemSocketHeader::error`.
    pub const ERROR: u32 = 1 << 4;
}

/// Shared-memory header for a socket slot.
///
/// Layout in memory (3 cache lines = 192 bytes):
/// ```text
/// [Cache line 0: RX ring cursors]
///   rx_head (u64) — consumer (micro) position
///   rx_tail (u64) — producer (net-worker) position
///   padding to 64 bytes
///
/// [Cache line 1: TX ring cursors]
///   tx_head (u64) — consumer (net-worker) position
///   tx_tail (u64) — producer (micro) position
///   padding to 64 bytes
///
/// [Cache line 2: Control/flags]
///   flags (u32)
///   error (u32) — errno value if ERROR flag is set
///   capacity (u64) — ring buffer capacity (same for RX and TX)
///   fd (i32) — guest fd number (for debugging/lookup)
///   padding to 64 bytes
/// ```
///
/// Data buffers follow the header:
/// ```text
/// [header: 192 bytes][RX data: SOCKET_RING_CAPACITY][TX data: SOCKET_RING_CAPACITY]
/// ```
#[repr(C, align(64))]
pub struct ShmemSocketHeader {
    // --- Cache line 0: RX ring (net-worker → micro) ---
    /// RX consumer position. Micro (reader) advances this.
    pub rx_head: AtomicU64,
    /// RX producer position. Net-worker (writer) advances this.
    pub rx_tail: AtomicU64,
    pub _rx_pad: [u8; 48],

    // --- Cache line 1: TX ring (micro → net-worker) ---
    /// TX consumer position. Net-worker (reader) advances this.
    pub tx_head: AtomicU64,
    /// TX producer position. Micro (writer) advances this.
    pub tx_tail: AtomicU64,
    pub _tx_pad: [u8; 48],

    // --- Cache line 2: Control ---
    /// Socket status flags (see [`socket_flags`]).
    pub flags: AtomicU32,
    /// Error code (errno) when `ERROR` flag is set.
    pub error: AtomicU32,
    /// Ring buffer capacity (same for both RX and TX). Must be power-of-2.
    pub capacity: u64,
    /// Guest fd number (for debugging/cross-reference).
    pub fd: i32,
    pub _ctrl_pad: [u8; 36],
}

const _: () = assert!(core::mem::size_of::<ShmemSocketHeader>() == SOCKET_RING_HEADER_SIZE);
const _: () = assert!(core::mem::align_of::<ShmemSocketHeader>() == 64);

/// Initialize a socket slot header. Called by central after allocating a slot.
///
/// # Safety
/// `header` must point to a valid, exclusively-owned `ShmemSocketHeader`.
pub unsafe fn socket_init(header: *mut ShmemSocketHeader, fd: i32, nonblock: bool) {
    let h = &mut *header;
    h.rx_head = AtomicU64::new(0);
    h.rx_tail = AtomicU64::new(0);
    h._rx_pad = [0; 48];
    h.tx_head = AtomicU64::new(0);
    h.tx_tail = AtomicU64::new(0);
    h._tx_pad = [0; 48];
    h.flags = AtomicU32::new(if nonblock { socket_flags::NONBLOCK } else { 0 });
    h.error = AtomicU32::new(0);
    h.capacity = SOCKET_RING_CAPACITY as u64;
    h.fd = fd;
    h._ctrl_pad = [0; 36];
}

/// Pointer to the RX data buffer (immediately after the header).
///
/// # Safety
/// `header` must point to a valid `ShmemSocketHeader` with sufficient
/// allocated space after it for `SOCKET_RING_CAPACITY` bytes.
#[inline]
pub unsafe fn rx_data_ptr(header: *mut ShmemSocketHeader) -> *mut u8 {
    header.cast::<u8>().add(SOCKET_RING_HEADER_SIZE)
}

/// Pointer to the TX data buffer (after the RX data buffer).
///
/// # Safety
/// `header` must point to a valid `ShmemSocketHeader` with sufficient
/// allocated space for both RX and TX data buffers.
#[inline]
pub unsafe fn tx_data_ptr(header: *mut ShmemSocketHeader) -> *mut u8 {
    header
        .cast::<u8>()
        .add(SOCKET_RING_HEADER_SIZE + SOCKET_RING_CAPACITY)
}

/// Try to read from the RX ring (micro consumes data produced by net-worker).
///
/// Returns:
/// - Positive: number of bytes read
/// - `0`: EOF (RX_SHUTDOWN set and ring empty)
/// - `-EAGAIN` (11): ring is empty, would block
/// - `-ECONNRESET` (104): socket closed/error
///
/// # Safety
/// `header` must point to a valid, initialized `ShmemSocketHeader`.
/// `buf` must be a valid slice.
pub unsafe fn socket_try_read(header: *mut ShmemSocketHeader, buf: &mut [u8]) -> i64 {
    let h = &*header;

    // Check for errors first.
    let flags = h.flags.load(Ordering::Acquire);
    if flags & socket_flags::CLOSED != 0 {
        return -104; // ECONNRESET
    }
    if flags & socket_flags::ERROR != 0 {
        let err = h.error.load(Ordering::Relaxed);
        return -(err as i64);
    }

    let capacity = h.capacity as usize;
    let mask = capacity - 1;

    // Reader owns rx_head.
    let head = h.rx_head.load(Ordering::Relaxed);
    let tail = h.rx_tail.load(Ordering::Acquire);

    let available = tail.wrapping_sub(head) as usize;
    if available == 0 {
        // Ring empty. Check for EOF.
        if flags & socket_flags::RX_SHUTDOWN != 0 {
            return 0; // EOF
        }
        return -11; // EAGAIN
    }

    let to_read = buf.len().min(available);
    let data = rx_data_ptr(header);
    let start = (head as usize) & mask;
    let first_chunk = to_read.min(capacity - start);

    core::ptr::copy_nonoverlapping(data.add(start), buf.as_mut_ptr(), first_chunk);
    if to_read > first_chunk {
        core::ptr::copy_nonoverlapping(data, buf.as_mut_ptr().add(first_chunk), to_read - first_chunk);
    }

    h.rx_head.store(head.wrapping_add(to_read as u64), Ordering::Release);
    to_read as i64
}

/// Try to write to the TX ring (micro produces data for net-worker to consume).
///
/// Returns:
/// - Positive: number of bytes written
/// - `-EPIPE` (32): TX_SHUTDOWN or CLOSED
/// - `-EAGAIN` (11): ring is full, would block
///
/// # Safety
/// `header` must point to a valid, initialized `ShmemSocketHeader`.
/// `buf` must be a valid slice.
pub unsafe fn socket_try_write(header: *mut ShmemSocketHeader, buf: &[u8]) -> i64 {
    let h = &*header;

    let flags = h.flags.load(Ordering::Relaxed);
    if flags & (socket_flags::TX_SHUTDOWN | socket_flags::CLOSED) != 0 {
        return -32; // EPIPE
    }

    let capacity = h.capacity as usize;
    let mask = capacity - 1;

    // Writer owns tx_tail.
    let tail = h.tx_tail.load(Ordering::Relaxed);
    let head = h.tx_head.load(Ordering::Acquire);

    let available = capacity - (tail.wrapping_sub(head)) as usize;
    if available == 0 {
        return -11; // EAGAIN
    }

    let to_write = buf.len().min(available);
    let data = tx_data_ptr(header);
    let start = (tail as usize) & mask;
    let first_chunk = to_write.min(capacity - start);

    core::ptr::copy_nonoverlapping(buf.as_ptr(), data.add(start), first_chunk);
    if to_write > first_chunk {
        core::ptr::copy_nonoverlapping(buf.as_ptr().add(first_chunk), data, to_write - first_chunk);
    }

    h.tx_tail.store(tail.wrapping_add(to_write as u64), Ordering::Release);
    to_write as i64
}

/// Try to read from the TX ring (net-worker consumes data produced by micro).
///
/// Returns:
/// - Positive: number of bytes read
/// - `0`: no data and TX_SHUTDOWN (micro finished writing)
/// - `-EAGAIN` (11): ring is empty
///
/// # Safety
/// `header` must point to a valid, initialized `ShmemSocketHeader`.
pub unsafe fn socket_tx_drain(header: *mut ShmemSocketHeader, buf: &mut [u8]) -> i64 {
    let h = &*header;

    let capacity = h.capacity as usize;
    let mask = capacity - 1;

    // Net-worker owns tx_head.
    let head = h.tx_head.load(Ordering::Relaxed);
    let tail = h.tx_tail.load(Ordering::Acquire);

    let available = tail.wrapping_sub(head) as usize;
    if available == 0 {
        let flags = h.flags.load(Ordering::Acquire);
        if flags & socket_flags::TX_SHUTDOWN != 0 {
            return 0; // EOF
        }
        return -11; // EAGAIN
    }

    let to_read = buf.len().min(available);
    let data = tx_data_ptr(header);
    let start = (head as usize) & mask;
    let first_chunk = to_read.min(capacity - start);

    core::ptr::copy_nonoverlapping(data.add(start), buf.as_mut_ptr(), first_chunk);
    if to_read > first_chunk {
        core::ptr::copy_nonoverlapping(data, buf.as_mut_ptr().add(first_chunk), to_read - first_chunk);
    }

    h.tx_head.store(head.wrapping_add(to_read as u64), Ordering::Release);
    to_read as i64
}

/// Try to write to the RX ring (net-worker produces data for micro to consume).
///
/// Returns:
/// - Positive: number of bytes written
/// - `-EAGAIN` (11): ring is full
///
/// # Safety
/// `header` must point to a valid, initialized `ShmemSocketHeader`.
pub unsafe fn socket_rx_fill(header: *mut ShmemSocketHeader, buf: &[u8]) -> i64 {
    let h = &*header;

    let capacity = h.capacity as usize;
    let mask = capacity - 1;

    // Net-worker owns rx_tail.
    let tail = h.rx_tail.load(Ordering::Relaxed);
    let head = h.rx_head.load(Ordering::Acquire);

    let available = capacity - (tail.wrapping_sub(head)) as usize;
    if available == 0 {
        return -11; // EAGAIN
    }

    let to_write = buf.len().min(available);
    let data = rx_data_ptr(header);
    let start = (tail as usize) & mask;
    let first_chunk = to_write.min(capacity - start);

    core::ptr::copy_nonoverlapping(buf.as_ptr(), data.add(start), first_chunk);
    if to_write > first_chunk {
        core::ptr::copy_nonoverlapping(buf.as_ptr().add(first_chunk), data, to_write - first_chunk);
    }

    h.rx_tail.store(tail.wrapping_add(to_write as u64), Ordering::Release);
    to_write as i64
}

/// Set a flag on the socket header and return the previous flags value.
pub unsafe fn socket_set_flag(header: *mut ShmemSocketHeader, flag: u32) -> u32 {
    (*header).flags.fetch_or(flag, Ordering::Release)
}

/// Check if the RX ring has data available (for epoll POLLIN check).
pub unsafe fn socket_rx_available(header: *const ShmemSocketHeader) -> usize {
    let h = &*header;
    let head = h.rx_head.load(Ordering::Relaxed);
    let tail = h.rx_tail.load(Ordering::Acquire);
    tail.wrapping_sub(head) as usize
}

/// Check if the TX ring has space available (for epoll POLLOUT check).
pub unsafe fn socket_tx_space(header: *const ShmemSocketHeader) -> usize {
    let h = &*header;
    let capacity = h.capacity as usize;
    let tail = h.tx_tail.load(Ordering::Relaxed);
    let head = h.tx_head.load(Ordering::Acquire);
    capacity - (tail.wrapping_sub(head)) as usize
}
```

**Step 3: Add `AcceptResponse` to `litebox_ipc/src/messages.rs`**

Add after `Pipe2Response` (around line 151):

```rust
/// Response payload for `SYS_accept4` when a shmem socket slot is allocated.
///
/// Central writes this to the data region. Micro reads it to learn the
/// shmem offset for the new socket's ring buffers.
#[repr(C)]
pub struct AcceptResponse {
    /// The new fd number returned by accept.
    pub fd: i32,
    /// Offset within the data region to the `ShmemSocketHeader`.
    pub socket_slot_offset: u32,
    /// Peer address (raw `sockaddr_in` bytes, network byte order).
    pub peer_addr: [u8; 16],
    /// Length of valid peer address data in `peer_addr`.
    pub peer_addr_len: u32,
    pub _pad: u32,
}
const _: () = assert!(core::mem::size_of::<AcceptResponse>() == 32);
```

**Step 4: Register the module in `litebox_ipc/src/lib.rs`**

Add `pub mod socket_ring;` alongside the existing `pub mod pipe;`.

**Step 5: Run clippy and tests**

```bash
cargo clippy -p litebox_ipc
cargo nextest run -p litebox_ipc
```

**Step 6: Commit**

```bash
git add litebox_ipc/src/socket_ring.rs litebox_ipc/src/lib.rs litebox_ipc/src/ring.rs litebox_ipc/src/messages.rs
git commit -m "feat: add shmem socket ring buffer types to litebox_ipc"
```

---

## Task 2: Enlarge the shmem data region and add socket slot allocator

The existing 8 MiB data region doesn't have room for socket slots. Enlarge it and add allocation/deallocation to `ProcessNotificationState`.

**Files:**
- Modify: `litebox_ipc/src/ring.rs:28` (change `DEFAULT_DATA_REGION_SIZE`)
- Modify: `litebox_central/src/notification_state.rs` (add socket slot allocation)
- Modify: `litebox_central/src/shmem.rs` (verify memfd sizing uses the constant)

**Step 1: Increase `DEFAULT_DATA_REGION_SIZE`**

In `litebox_ipc/src/ring.rs`, change line 28:

```rust
// Old:
pub const DEFAULT_DATA_REGION_SIZE: usize = 8 * 1024 * 1024;

// New:
pub const DEFAULT_DATA_REGION_SIZE: usize = SOCKET_DATA_REGION_SIZE;
```

This expands the shmem from 8 MiB to ~40 MiB. The extra 32 MiB is for 64 socket slots.

**Step 2: Add socket slot tracking to `ProcessNotificationState`**

In `litebox_central/src/notification_state.rs`, add fields and methods mirroring the pipe pattern:

```rust
/// Tracking info for a shmem-backed socket.
pub(crate) struct ShmemSocket {
    pub fd: i32,           // Guest fd number
    pub slot_index: u8,    // 0..MAX_SOCKET_SLOTS
}
```

Add to `ProcessNotificationState`:
```rust
pub socket_slot_bitset: u64,             // Bit N = 1 means slot N is in use
pub shmem_sockets: Vec<ShmemSocket>,     // Active shmem-backed sockets
```

Add methods:
```rust
pub fn alloc_socket_slot(&mut self) -> Option<(u8, u32)> {
    let free_bit = self.socket_slot_bitset.trailing_ones();
    if free_bit as usize >= MAX_SOCKET_SLOTS {
        return None;
    }
    self.socket_slot_bitset |= 1u64 << free_bit;
    let offset = SOCKET_ZONE_BASE_OFFSET + (free_bit as usize) * SOCKET_SLOT_SIZE;
    Some((free_bit as u8, offset as u32))
}

pub fn free_socket_slot(&mut self, slot_index: u8) {
    self.socket_slot_bitset &= !(1u64 << slot_index);
}
```

**Step 3: Verify shmem creation uses `DEFAULT_DATA_REGION_SIZE`**

Check `litebox_central/src/shmem.rs` — the `SharedRegion::new()` and `create_child_ring()` should use `SharedRingLayout::new(DEFAULT_DATA_REGION_SIZE)`. If they hardcode `8 * 1024 * 1024`, update them to use the constant.

Also check `litebox_micro/src/state.rs` — `micro_init()` computes the layout from the ring size it receives. Since the ring size comes from the memfd's ftruncated size, this should work automatically.

**Step 4: Run clippy and tests**

```bash
cargo clippy -p litebox_ipc
cargo clippy -p litebox_central
cargo nextest run -p litebox_ipc
```

**Step 5: Commit**

```bash
git commit -m "feat: enlarge shmem data region for socket zone and add slot allocator"
```

---

## Task 3: Wire `accept()` to allocate shmem socket slots

When a guest calls `accept()` and gets a new connected socket fd, central allocates a shmem socket slot, initializes it, and returns the slot offset to micro via the CQ response.

**Files:**
- Modify: `litebox_central/src/server.rs` (intercept `SYS_accept`/`SYS_accept4` result)
- Modify: `litebox_micro/src/handler.rs` (handle accept response, register socket fd)
- Modify: `litebox_micro/src/state.rs` (add `SocketFdEntry` tracking, like `PipeFdEntry`)

**Step 1: Add `SocketFdEntry` to micro's state**

In `litebox_micro/src/state.rs`, add:

```rust
#[derive(Clone, Copy)]
pub struct SocketFdEntry {
    pub fd: i32,
    pub shmem_offset: u32,
}
```

Add to `MicroState`:
```rust
pub socket_fds: [Option<SocketFdEntry>; MAX_SOCKET_SLOTS],
```

Add lookup/register/unregister methods matching the pipe pattern:
```rust
pub fn find_socket_fd(&self, fd: i32) -> Option<u32>  // returns shmem_offset
pub fn register_socket_fd(&mut self, fd: i32, shmem_offset: u32) -> bool
pub fn unregister_socket_fd(&mut self, fd: i32) -> bool
```

**Step 2: Central — allocate slot on accept success**

In `litebox_central/src/server.rs`, after a successful `SYS_accept` or `SYS_accept4` dispatch:

1. Check if result > 0 (successful accept returns new fd)
2. Call `notification_state.alloc_socket_slot()`
3. Initialize the slot header: `socket_init(header_ptr, new_fd, nonblock)`
4. Track: push `ShmemSocket { fd: new_fd, slot_index }`
5. Write `AcceptResponse` to data region at a scratch offset
6. Return CQ with `HAS_DATA` flag and the data offset/len

This mirrors `handle_pipe2`'s pattern. May need a dedicated `handle_accept` method.

**Step 3: Micro — handle accept response**

In `litebox_micro/src/handler.rs`, after receiving the CQ for accept:

1. Check for `HAS_DATA` flag
2. Read `AcceptResponse` from data region
3. Call `micro.register_socket_fd(resp.fd, resp.socket_slot_offset)`

**Step 4: Central — free slot on close**

In the close handler, add `maybe_close_shmem_socket` logic:
1. Find socket in `shmem_sockets` by fd
2. Set `CLOSED` flag on the header
3. `FUTEX_WAKE` on both `rx_tail` (wake reader) and `tx_head` (wake writer)
4. Remove from `shmem_sockets`, call `free_socket_slot`

**Step 5: Run clippy and manual test**

```bash
cargo clippy -p litebox_central
cargo clippy -p litebox_micro
cargo clippy -p litebox -p litebox_shim_linux -p litebox_micro -p litebox_launcher
# Manual: start nginx, curl to verify accept still works
```

**Step 6: Commit**

```bash
git commit -m "feat: allocate shmem socket slots on accept and track in micro"
```

---

## Task 4: Micro — bypass SQ/CQ for socket read/write

This is the core change. When micro detects a `read()`/`write()`/`recvfrom()`/`sendto()` on a socket fd that has a shmem slot, it reads/writes the shmem ring directly instead of submitting to SQ/CQ.

**Files:**
- Modify: `litebox_micro/src/handler.rs` (add fast-path dispatch for socket read/write)

**Step 1: Add `shmem_socket_read` function**

Model on `shmem_pipe_read`. Key differences from pipe:
- Uses `socket_try_read` (reads from RX ring)
- Blocking: spin 100 iters on `rx_tail`, then `FUTEX_WAIT` on `rx_tail`
- Wake writer after consuming: `FUTEX_WAKE` on `rx_head`
- Handle EOF (returns 0) and errors (returns -errno)

```rust
unsafe fn shmem_socket_read(
    micro: &MicroState,
    shmem_offset: u32,
    buf_ptr: *mut u8,
    count: usize,
) -> i64 {
    let header = micro.ring_base
        .add(micro.layout.data_region_offset)
        .add(shmem_offset as usize)
        .cast::<ShmemSocketHeader>();

    let buf = core::slice::from_raw_parts_mut(buf_ptr, count);

    loop {
        let result = socket_try_read(header, buf);
        if result > 0 {
            // Wake net-worker (it may be waiting for TX space via futex on rx_head)
            // Actually net-worker doesn't futex-wait on rx_head, but we wake
            // in case future optimizations add it.
            return result;
        }
        if result == 0 {
            return 0; // EOF
        }
        if result != -11 {
            return result; // error
        }
        // -EAGAIN: buffer empty
        let flags = (*header).flags.load(Ordering::Relaxed);
        if flags & socket_flags::NONBLOCK != 0 {
            return -11; // EAGAIN
        }
        // Spin then futex-wait on rx_tail
        let current_tail = (*header).rx_tail.load(Ordering::Relaxed);
        // Spin 100 iterations
        for _ in 0..100 {
            if (*header).rx_tail.load(Ordering::Acquire) != current_tail {
                continue; // outer loop - retry read
            }
            core::hint::spin_loop();
        }
        if (*header).rx_tail.load(Ordering::Acquire) != current_tail {
            continue;
        }
        // FUTEX_WAIT on rx_tail (low 32 bits)
        libc::syscall(
            libc::SYS_futex,
            &(*header).rx_tail as *const AtomicU64,
            libc::FUTEX_WAIT,
            current_tail as u32,
            core::ptr::null::<libc::timespec>(),
        );
    }
}
```

**Step 2: Add `shmem_socket_write` function**

Model on `shmem_pipe_write`:
- Uses `socket_try_write` (writes to TX ring)
- Blocking: spin 100 iters on `tx_head`, then `FUTEX_WAIT` on `tx_head`
- Wake net-worker after producing: no explicit wake needed — net-worker polls TUN in a loop. But for future optimization, could `FUTEX_WAKE` on `tx_tail`.
- Handle partial writes (accumulate written bytes)
- Handle EPIPE (returns -EPIPE or total written)

**Step 3: Wire fast-path dispatch**

In `litebox_micro/src/handler.rs`, in the syscall dispatch path (around line 1284 where pipe fast-path exists), add socket fast-path:

```rust
if let Some(shmem_offset) = micro.find_socket_fd(fd) {
    match i64::from(nr) {
        libc::SYS_read | libc::SYS_recvfrom => {
            return unsafe { shmem_socket_read(micro, shmem_offset, buf, count) };
        }
        libc::SYS_write | libc::SYS_sendto => {
            return unsafe { shmem_socket_write(micro, shmem_offset, buf, count) };
        }
        libc::SYS_close => {
            micro_mut.unregister_socket_fd(fd);
            // fall through to central for shim fd close + shmem cleanup
        }
        _ => {} // setsockopt, getsockopt, etc. — fall through to central
    }
}
```

**Important**: Check for `recvfrom` with a non-null `src_addr` argument — if the guest wants the peer address, we need to either store it in the header or fall through to SQ/CQ. For nginx, `recvfrom` on TCP stream sockets doesn't use `src_addr`, so this can be a follow-up.

**Step 4: Run clippy and manual test**

```bash
cargo clippy -p litebox_micro
cargo clippy -p litebox -p litebox_shim_linux -p litebox_micro -p litebox_launcher
# Manual: start nginx, curl, wrk — verify data flows correctly
```

**Step 5: Commit**

```bash
git commit -m "feat: bypass SQ/CQ for socket read/write via shmem rings"
```

---

## Task 5: Central net-worker — drain/fill shmem socket rings instead of HeapRb

Currently the net-worker calls `drain_all_socket_channel_buffers()` which copies between HeapRb and smoltcp. Change this to copy between shmem rings and smoltcp.

**Files:**
- Modify: `litebox/src/net/mod.rs` (modify `drain_socket_channel_buffers` to support shmem mode)
- Modify: `litebox/src/net/socket_channel.rs` (add shmem pointer to `StreamSocketChannel`)
- Modify: `litebox_central/src/server.rs` (pass shmem base to network operations)
- Possibly modify: `litebox_shim_linux/src/lib.rs` or `litebox_shim_linux/src/syscalls/net.rs`

**Step 1: Add shmem pointer to socket handles**

The `SocketHandle<Platform>` in `litebox/src/net/mod.rs` needs to know the shmem header pointer for its socket (if it has one). Add an optional field:

```rust
pub(crate) struct SocketHandle<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    // ... existing fields ...
    /// Pointer to the shmem socket ring header, if this socket has a shmem slot.
    /// When Some, the net-worker drains/fills the shmem rings instead of the
    /// HeapRb socket channel.
    shmem_header: Option<*mut litebox_ipc::socket_ring::ShmemSocketHeader>,
}
```

**CRITICAL**: `litebox` is `#![no_std]`. The `ShmemSocketHeader` type is in `litebox_ipc` which is also `#![no_std]`. This should work as long as `litebox` depends on `litebox_ipc`. Check if it does — if not, we may need to use a raw `*mut u8` and size constant instead.

**Step 2: Modify `drain_socket_channel_buffers` for shmem mode**

When `shmem_header` is `Some`, instead of locking `rx_prod`/`tx_cons` Mutex and copying to/from HeapRb:
- **RX fill**: Read from smoltcp socket RX ring → write to shmem RX ring via `socket_rx_fill`
- **TX drain**: Read from shmem TX ring via `socket_tx_drain` → write to smoltcp socket TX ring
- After filling RX: `FUTEX_WAKE` on `rx_tail` (wake micro if blocked)
- After draining TX: `FUTEX_WAKE` on `tx_head` (wake micro if blocked on full TX)

**NOTE**: `FUTEX_WAKE` is a Linux syscall. `litebox` is `#![no_std]` and platform-agnostic. The futex wake needs to be done through a platform trait method or handled in `litebox_central` after the drain returns. The cleanest approach: `drain_socket_channel_buffers` returns a flag indicating "rx was filled" or "tx was drained", and the caller (net-worker in server.rs) does the futex wake.

Alternatively, add a `wake_rx`/`wake_tx` method to `IPInterfaceProvider` or a new platform trait. But adding to the trait changes the `#![no_std]` crate — check feasibility.

**Simpler approach**: The drain function can return `(bool, bool)` — `(rx_filled, tx_drained)`. The net-worker in `server.rs` does the futex wakes.

**Step 3: Set `shmem_header` on accept**

When central handles a successful `accept()` and allocates a shmem slot, it needs to communicate the shmem pointer to the `SocketHandle`. This could be done by:
- Having the accept handler set a flag on the `SocketHandle` after it's created
- Or passing the shmem pointer through the accept code path

This requires coordination between `server.rs` (which knows the shmem pointer) and `net/mod.rs` (which creates the `SocketHandle`). One approach: add a post-accept hook that sets the shmem pointer.

**Step 4: Handle epoll readiness with shmem rings**

When shmem rings are active, epoll readiness for `POLLIN` (readable) should check the shmem RX ring head/tail (data available?). For `POLLOUT` (writable), check shmem TX ring space.

The `Pollee::notify_observers()` mechanism can still be used — the net-worker calls `notify` after filling RX or draining TX, same as before.

**Step 5: Run clippy and manual test**

```bash
cargo clippy -p litebox -p litebox_shim_linux -p litebox_micro -p litebox_launcher
cargo clippy -p litebox_central
# Manual: start nginx, wrk benchmark, compare with pre-change numbers
```

**Step 6: Commit**

```bash
git commit -m "feat: net-worker drains/fills shmem socket rings instead of HeapRb channels"
```

---

## Task 6: Handle `connect()`, `shutdown()`, and edge cases

Wire up remaining socket lifecycle operations with shmem ring awareness.

**Files:**
- Modify: `litebox_central/src/server.rs` (connect response, shutdown handling)
- Modify: `litebox_micro/src/handler.rs` (connect response handling)
- Modify: `litebox/src/net/mod.rs` (shutdown sets shmem flags)

**Step 1: Wire `connect()` to allocate shmem slot**

Similar to accept: when `connect()` succeeds (or for non-blocking connect, when the socket becomes connected), allocate a shmem slot and return the offset.

For blocking connect: allocate on success, return via CQ `HAS_DATA`.
For non-blocking connect: allocate at `connect()` call time (before connection completes), so the fd is ready for immediate read/write after `POLLOUT` fires.

**Step 2: Wire `shutdown()` to set shmem flags**

When guest calls `shutdown(fd, SHUT_RD)`:
- Set `RX_SHUTDOWN` flag on shmem header
- `FUTEX_WAKE` on `rx_tail` (wake any blocked reader)

When guest calls `shutdown(fd, SHUT_WR)`:
- Set `TX_SHUTDOWN` flag on shmem header
- `FUTEX_WAKE` on `tx_head` (wake any blocked writer)

**Step 3: Handle FIN from peer (smoltcp side)**

When smoltcp detects the peer closed the connection (FIN received):
- Net-worker sets `RX_SHUTDOWN` flag
- `FUTEX_WAKE` on `rx_tail`

When smoltcp detects connection reset:
- Net-worker sets `CLOSED` flag
- `FUTEX_WAKE` on both `rx_tail` and `tx_head`

**Step 4: Handle dup/dup2/fcntl for socket fds**

If the guest dups a socket fd, micro needs to register the new fd with the same shmem offset. These operations go through SQ/CQ — the response should include shmem offset info.

For nginx, dup on socket fds is uncommon, so this can be a follow-up if needed.

**Step 5: Handle fork**

On fork:
- Parent's socket shmem registrations should not be inherited by the child (child gets fresh Network with fresh sockets via accept)
- Clear `socket_fds` in the child after fork (like `pipe_fds`)
- Note: the parent might also need its registrations cleared if the fork/exec pattern means the parent's shmem region is replaced. Check how pipe_fds handles this.

**Step 6: Run full test suite and benchmark**

```bash
cargo clippy -p litebox -p litebox_shim_linux -p litebox_micro -p litebox_launcher
cargo clippy -p litebox_central
cargo nextest run -p litebox_ipc
# Full benchmark: nginx with wrk
```

**Step 7: Commit**

```bash
git commit -m "feat: connect/shutdown/lifecycle integration for shmem socket rings"
```

---

## Task 7: End-to-end benchmark and comparison

**Step 1: Build everything in release mode**

```bash
cargo build --release -p litebox_micro -p litebox_launcher
cargo build --release -p litebox_central
```

**Step 2: Run nginx benchmark**

```bash
sudo pkill -9 -f litebox_central; sudo pkill -9 -f litebox_launcher; sudo pkill -9 -f litebox
sudo ip link set tun0 down 2>/dev/null; sudo ip tuntap del mode tun dev tun0 2>/dev/null; sleep 1

sudo timeout 120 /workspace/litebox-mu/target/release/litebox_launcher \
  --rootfs-tar=nginx_alpine_final.tar \
  --rootfs-prefix=nginx_rootfs_fixed \
  --tun-device=tun0 \
  nginx_rootfs_fixed/usr/sbin/nginx > /dev/null 2>/dev/null &
sleep 25
cat /tmp/central_stderr.log
curl -s -o /dev/null -w "%{http_code}" http://10.0.0.2/
wrk -t4 -c50 -d10s http://10.0.0.2/
wrk -t4 -c100 -d10s http://10.0.0.2/
wrk -t4 -c200 -d10s http://10.0.0.2/
```

**Step 3: Compare results**

| Config | Before shmem rings | After shmem rings | Improvement |
|--------|-------------------|-------------------|-------------|
| 2w/50c | ~10k req/s | ? | ? |
| 2w/100c | ~55k req/s | ? | ? |
| 2w/200c | ~57k req/s | ? | ? |

Expected improvement: 20-40% from eliminating 2 copies per direction + SQ/CQ futex overhead. The net mutex is still present for smoltcp operations, which limits the ceiling.

**Step 4: Commit benchmark results**

```bash
git commit -m "bench: shmem socket ring performance results"
```

---

## Risk Assessment

### High risk: Task 5 (net-worker shmem integration)
The `litebox` crate is `#![no_std]` and platform-agnostic. Adding shmem awareness requires careful trait design to avoid platform-specific code in the core crate. The futex wake needs to happen outside the `#![no_std]` boundary. The `shmem_header` pointer in `SocketHandle` may need to be a generic type parameter or use a platform trait.

### Medium risk: Task 3 (accept wiring)
The accept code path touches multiple layers (shim → net → server). Correctly intercepting the accept result and injecting the shmem slot allocation without breaking the existing flow requires understanding the full accept dispatch chain.

### Medium risk: Task 4 (micro fast-path)
The `recvfrom` / `sendto` syscalls have additional arguments (flags, address) that the simple fast-path bypass doesn't handle. Need to carefully check which argument combinations can be fast-pathed and which must fall through.

### Low risk: Tasks 1-2 (types and allocation)
Pure additions, no behavioral change. Low risk of breaking anything.

### Low risk: Task 6 (edge cases)
Shutdown, connect, dup are less common in the hot path. Can be implemented incrementally.

### Constraint: Memory usage
The shmem region grows from 8 MiB to ~40 MiB. This is acceptable for a development/benchmark scenario but may need a configuration option for production (smaller ring sizes, fewer slots).
