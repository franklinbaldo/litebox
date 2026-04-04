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
/// `header` must point to a valid, exclusively-owned `ShmemSocketHeader`
/// with at least `SOCKET_SLOT_SIZE` bytes of backing memory.
#[allow(clippy::used_underscore_binding)]
pub unsafe fn socket_init(header: *mut ShmemSocketHeader, fd: i32, nonblock: bool) {
    unsafe {
        (*header).rx_head = AtomicU64::new(0);
        (*header).rx_tail = AtomicU64::new(0);
        (*header)._rx_pad = [0; 48];
        (*header).tx_head = AtomicU64::new(0);
        (*header).tx_tail = AtomicU64::new(0);
        (*header)._tx_pad = [0; 48];
        (*header).flags = AtomicU32::new(if nonblock { socket_flags::NONBLOCK } else { 0 });
        (*header).error = AtomicU32::new(0);
        (*header).capacity = SOCKET_RING_CAPACITY as u64;
        (*header).fd = fd;
        (*header)._ctrl_pad = [0; 36];
    }
}

/// Pointer to the RX data buffer (immediately after the header).
///
/// # Safety
/// `header` must point to a valid `ShmemSocketHeader` with sufficient
/// allocated space after it for `SOCKET_RING_CAPACITY` bytes.
#[inline]
pub unsafe fn rx_data_ptr(header: *mut ShmemSocketHeader) -> *mut u8 {
    unsafe { header.cast::<u8>().add(SOCKET_RING_HEADER_SIZE) }
}

/// Pointer to the TX data buffer (after the RX data buffer).
///
/// # Safety
/// `header` must point to a valid `ShmemSocketHeader` with sufficient
/// allocated space for both RX and TX data buffers.
#[inline]
pub unsafe fn tx_data_ptr(header: *mut ShmemSocketHeader) -> *mut u8 {
    unsafe {
        header
            .cast::<u8>()
            .add(SOCKET_RING_HEADER_SIZE + SOCKET_RING_CAPACITY)
    }
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
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe fn socket_try_read(header: *mut ShmemSocketHeader, buf: &mut [u8]) -> i64 {
    let h = unsafe { &*header };

    // Check for errors first.
    let flags = h.flags.load(Ordering::Acquire);
    if flags & socket_flags::CLOSED != 0 {
        return -i64::from(libc::ECONNRESET);
    }
    if flags & socket_flags::ERROR != 0 {
        let err = h.error.load(Ordering::Relaxed);
        return -i64::from(err);
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
        return -i64::from(libc::EAGAIN);
    }

    let to_read = buf.len().min(available);
    let data = unsafe { rx_data_ptr(header) };
    let start = (head as usize) & mask;
    let first_chunk = to_read.min(capacity - start);

    unsafe {
        core::ptr::copy_nonoverlapping(data.add(start), buf.as_mut_ptr(), first_chunk);
        if to_read > first_chunk {
            core::ptr::copy_nonoverlapping(
                data,
                buf.as_mut_ptr().add(first_chunk),
                to_read - first_chunk,
            );
        }
    }

    h.rx_head
        .store(head.wrapping_add(to_read as u64), Ordering::Release);
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
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe fn socket_try_write(header: *mut ShmemSocketHeader, buf: &[u8]) -> i64 {
    let h = unsafe { &*header };

    let flags = h.flags.load(Ordering::Acquire);
    if flags & (socket_flags::TX_SHUTDOWN | socket_flags::CLOSED) != 0 {
        return -i64::from(libc::EPIPE);
    }

    let capacity = h.capacity as usize;
    let mask = capacity - 1;

    // Writer owns tx_tail.
    let tail = h.tx_tail.load(Ordering::Relaxed);
    let head = h.tx_head.load(Ordering::Acquire);

    let available = capacity - (tail.wrapping_sub(head)) as usize;
    if available == 0 {
        return -i64::from(libc::EAGAIN);
    }

    let to_write = buf.len().min(available);
    let data = unsafe { tx_data_ptr(header) };
    let start = (tail as usize) & mask;
    let first_chunk = to_write.min(capacity - start);

    unsafe {
        core::ptr::copy_nonoverlapping(buf.as_ptr(), data.add(start), first_chunk);
        if to_write > first_chunk {
            core::ptr::copy_nonoverlapping(
                buf.as_ptr().add(first_chunk),
                data,
                to_write - first_chunk,
            );
        }
    }

    h.tx_tail
        .store(tail.wrapping_add(to_write as u64), Ordering::Release);
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
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe fn socket_tx_drain(header: *mut ShmemSocketHeader, buf: &mut [u8]) -> i64 {
    let h = unsafe { &*header };

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
        return -i64::from(libc::EAGAIN);
    }

    let to_read = buf.len().min(available);
    let data = unsafe { tx_data_ptr(header) };
    let start = (head as usize) & mask;
    let first_chunk = to_read.min(capacity - start);

    unsafe {
        core::ptr::copy_nonoverlapping(data.add(start), buf.as_mut_ptr(), first_chunk);
        if to_read > first_chunk {
            core::ptr::copy_nonoverlapping(
                data,
                buf.as_mut_ptr().add(first_chunk),
                to_read - first_chunk,
            );
        }
    }

    h.tx_head
        .store(head.wrapping_add(to_read as u64), Ordering::Release);
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
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe fn socket_rx_fill(header: *mut ShmemSocketHeader, buf: &[u8]) -> i64 {
    let h = unsafe { &*header };

    let capacity = h.capacity as usize;
    let mask = capacity - 1;

    // Net-worker owns rx_tail.
    let tail = h.rx_tail.load(Ordering::Relaxed);
    let head = h.rx_head.load(Ordering::Acquire);

    let available = capacity - (tail.wrapping_sub(head)) as usize;
    if available == 0 {
        return -i64::from(libc::EAGAIN);
    }

    let to_write = buf.len().min(available);
    let data = unsafe { rx_data_ptr(header) };
    let start = (tail as usize) & mask;
    let first_chunk = to_write.min(capacity - start);

    unsafe {
        core::ptr::copy_nonoverlapping(buf.as_ptr(), data.add(start), first_chunk);
        if to_write > first_chunk {
            core::ptr::copy_nonoverlapping(
                buf.as_ptr().add(first_chunk),
                data,
                to_write - first_chunk,
            );
        }
    }

    h.rx_tail
        .store(tail.wrapping_add(to_write as u64), Ordering::Release);
    to_write as i64
}

/// Set a flag on the socket header and return the previous flags value.
///
/// # Safety
/// `header` must point to a valid `ShmemSocketHeader` in shared memory.
pub unsafe fn socket_set_flag(header: *mut ShmemSocketHeader, flag: u32) -> u32 {
    unsafe { (*header).flags.fetch_or(flag, Ordering::Release) }
}

/// Check if the RX ring has data available (for epoll POLLIN check).
///
/// # Safety
/// `header` must point to a valid `ShmemSocketHeader` in shared memory.
#[allow(clippy::cast_possible_truncation)]
pub unsafe fn socket_rx_available(header: *const ShmemSocketHeader) -> usize {
    let h = unsafe { &*header };
    let head = h.rx_head.load(Ordering::Relaxed);
    let tail = h.rx_tail.load(Ordering::Acquire);
    tail.wrapping_sub(head) as usize
}

/// Check if the TX ring has space available (for epoll POLLOUT check).
///
/// # Safety
/// `header` must point to a valid `ShmemSocketHeader` in shared memory.
#[allow(clippy::cast_possible_truncation)]
pub unsafe fn socket_tx_space(header: *const ShmemSocketHeader) -> usize {
    let h = unsafe { &*header };
    let capacity = h.capacity as usize;
    let tail = h.tx_tail.load(Ordering::Relaxed);
    let head = h.tx_head.load(Ordering::Acquire);
    capacity - (tail.wrapping_sub(head)) as usize
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;
    use crate::ring::SOCKET_SLOT_SIZE;

    /// Helper: allocate an aligned socket slot on the heap for testing.
    fn alloc_socket_slot() -> Vec<u8> {
        vec![0u8; SOCKET_SLOT_SIZE + 64] // extra for alignment
    }

    fn aligned_header(buf: &mut [u8]) -> *mut ShmemSocketHeader {
        let addr = buf.as_mut_ptr() as usize;
        let aligned = (addr + 63) & !63;
        aligned as *mut ShmemSocketHeader
    }

    #[test]
    fn socket_header_size() {
        assert_eq!(
            core::mem::size_of::<ShmemSocketHeader>(),
            SOCKET_RING_HEADER_SIZE
        );
    }

    #[test]
    fn socket_header_alignment() {
        assert_eq!(core::mem::align_of::<ShmemSocketHeader>(), 64);
    }

    #[test]
    fn socket_init_sets_fields() {
        let mut buf = alloc_socket_slot();
        let h = aligned_header(&mut buf);
        unsafe { socket_init(h, 5, false) };
        unsafe {
            assert_eq!((*h).rx_head.load(Ordering::Relaxed), 0);
            assert_eq!((*h).rx_tail.load(Ordering::Relaxed), 0);
            assert_eq!((*h).tx_head.load(Ordering::Relaxed), 0);
            assert_eq!((*h).tx_tail.load(Ordering::Relaxed), 0);
            assert_eq!((*h).capacity, SOCKET_RING_CAPACITY as u64);
            assert_eq!((*h).flags.load(Ordering::Relaxed), 0);
            assert_eq!((*h).error.load(Ordering::Relaxed), 0);
            assert_eq!((*h).fd, 5);
        }
    }

    #[test]
    fn socket_init_nonblock() {
        let mut buf = alloc_socket_slot();
        let h = aligned_header(&mut buf);
        unsafe { socket_init(h, 5, true) };
        unsafe {
            assert_eq!((*h).flags.load(Ordering::Relaxed), socket_flags::NONBLOCK);
        }
    }

    #[test]
    fn socket_rx_write_then_read() {
        let mut buf = alloc_socket_slot();
        let h = aligned_header(&mut buf);
        unsafe { socket_init(h, 5, false) };

        // Net-worker fills RX ring.
        let data = b"hello socket";
        let written = unsafe { socket_rx_fill(h, data) };
        assert_eq!(written, 12);

        // Micro reads from RX ring.
        let mut out = [0u8; 64];
        let read = unsafe { socket_try_read(h, &mut out) };
        assert_eq!(read, 12);
        assert_eq!(&out[..12], b"hello socket");
    }

    #[test]
    fn socket_tx_write_then_drain() {
        let mut buf = alloc_socket_slot();
        let h = aligned_header(&mut buf);
        unsafe { socket_init(h, 5, false) };

        // Micro writes to TX ring.
        let data = b"outgoing data";
        let written = unsafe { socket_try_write(h, data) };
        assert_eq!(written, 13);

        // Net-worker drains TX ring.
        let mut out = [0u8; 64];
        let read = unsafe { socket_tx_drain(h, &mut out) };
        assert_eq!(read, 13);
        assert_eq!(&out[..13], b"outgoing data");
    }

    #[test]
    fn socket_read_empty_returns_eagain() {
        let mut buf = alloc_socket_slot();
        let h = aligned_header(&mut buf);
        unsafe { socket_init(h, 5, false) };

        let mut out = [0u8; 64];
        let result = unsafe { socket_try_read(h, &mut out) };
        assert_eq!(result, -11); // EAGAIN
    }

    #[test]
    fn socket_read_eof_after_rx_shutdown() {
        let mut buf = alloc_socket_slot();
        let h = aligned_header(&mut buf);
        unsafe { socket_init(h, 5, false) };

        unsafe { socket_set_flag(h, socket_flags::RX_SHUTDOWN) };
        let mut out = [0u8; 64];
        let result = unsafe { socket_try_read(h, &mut out) };
        assert_eq!(result, 0); // EOF
    }

    #[test]
    fn socket_read_closed_returns_econnreset() {
        let mut buf = alloc_socket_slot();
        let h = aligned_header(&mut buf);
        unsafe { socket_init(h, 5, false) };

        unsafe { socket_set_flag(h, socket_flags::CLOSED) };
        let mut out = [0u8; 64];
        let result = unsafe { socket_try_read(h, &mut out) };
        assert_eq!(result, -104); // ECONNRESET
    }

    #[test]
    fn socket_write_tx_shutdown_returns_epipe() {
        let mut buf = alloc_socket_slot();
        let h = aligned_header(&mut buf);
        unsafe { socket_init(h, 5, false) };

        unsafe { socket_set_flag(h, socket_flags::TX_SHUTDOWN) };
        let result = unsafe { socket_try_write(h, b"data") };
        assert_eq!(result, -32); // EPIPE
    }

    #[test]
    fn socket_write_closed_returns_epipe() {
        let mut buf = alloc_socket_slot();
        let h = aligned_header(&mut buf);
        unsafe { socket_init(h, 5, false) };

        unsafe { socket_set_flag(h, socket_flags::CLOSED) };
        let result = unsafe { socket_try_write(h, b"data") };
        assert_eq!(result, -32); // EPIPE
    }

    #[test]
    fn socket_tx_drain_empty_returns_eagain() {
        let mut buf = alloc_socket_slot();
        let h = aligned_header(&mut buf);
        unsafe { socket_init(h, 5, false) };

        let mut out = [0u8; 64];
        let result = unsafe { socket_tx_drain(h, &mut out) };
        assert_eq!(result, -11); // EAGAIN
    }

    #[test]
    fn socket_tx_drain_eof_after_tx_shutdown() {
        let mut buf = alloc_socket_slot();
        let h = aligned_header(&mut buf);
        unsafe { socket_init(h, 5, false) };

        unsafe { socket_set_flag(h, socket_flags::TX_SHUTDOWN) };
        let mut out = [0u8; 64];
        let result = unsafe { socket_tx_drain(h, &mut out) };
        assert_eq!(result, 0); // EOF
    }

    #[test]
    fn socket_fills_rx_to_capacity() {
        let mut buf = alloc_socket_slot();
        let h = aligned_header(&mut buf);
        unsafe { socket_init(h, 5, false) };

        let big = vec![0xABu8; SOCKET_RING_CAPACITY];
        let written = unsafe { socket_rx_fill(h, &big) };
        assert_eq!(written as usize, SOCKET_RING_CAPACITY);

        // RX ring full — next fill should return EAGAIN.
        let result = unsafe { socket_rx_fill(h, b"x") };
        assert_eq!(result, -11); // EAGAIN
    }

    #[test]
    fn socket_fills_tx_to_capacity() {
        let mut buf = alloc_socket_slot();
        let h = aligned_header(&mut buf);
        unsafe { socket_init(h, 5, false) };

        let big = vec![0xCDu8; SOCKET_RING_CAPACITY];
        let written = unsafe { socket_try_write(h, &big) };
        assert_eq!(written as usize, SOCKET_RING_CAPACITY);

        // TX ring full — next write should return EAGAIN.
        let result = unsafe { socket_try_write(h, b"x") };
        assert_eq!(result, -11); // EAGAIN
    }

    #[test]
    fn socket_rx_wraparound() {
        let mut buf = alloc_socket_slot();
        let h = aligned_header(&mut buf);
        unsafe { socket_init(h, 5, false) };

        // Fill most of the RX ring.
        let fill = vec![0u8; SOCKET_RING_CAPACITY - 10];
        let w = unsafe { socket_rx_fill(h, &fill) };
        assert_eq!(w as usize, SOCKET_RING_CAPACITY - 10);

        // Read it all back to advance head.
        let mut drain = vec![0u8; SOCKET_RING_CAPACITY];
        let r = unsafe { socket_try_read(h, &mut drain) };
        assert_eq!(r as usize, SOCKET_RING_CAPACITY - 10);

        // Now write 20 bytes — wraps around the buffer boundary.
        let wrap_data = [0x42u8; 20];
        let w2 = unsafe { socket_rx_fill(h, &wrap_data) };
        assert_eq!(w2, 20);

        let mut out = [0u8; 20];
        let r2 = unsafe { socket_try_read(h, &mut out) };
        assert_eq!(r2, 20);
        assert_eq!(out, [0x42u8; 20]);
    }

    #[test]
    fn socket_tx_wraparound() {
        let mut buf = alloc_socket_slot();
        let h = aligned_header(&mut buf);
        unsafe { socket_init(h, 5, false) };

        // Fill most of the TX ring.
        let fill = vec![0u8; SOCKET_RING_CAPACITY - 10];
        let w = unsafe { socket_try_write(h, &fill) };
        assert_eq!(w as usize, SOCKET_RING_CAPACITY - 10);

        // Drain it all to advance head.
        let mut drain = vec![0u8; SOCKET_RING_CAPACITY];
        let r = unsafe { socket_tx_drain(h, &mut drain) };
        assert_eq!(r as usize, SOCKET_RING_CAPACITY - 10);

        // Now write 20 bytes — wraps around.
        let wrap_data = [0x42u8; 20];
        let w2 = unsafe { socket_try_write(h, &wrap_data) };
        assert_eq!(w2, 20);

        let mut out = [0u8; 20];
        let r2 = unsafe { socket_tx_drain(h, &mut out) };
        assert_eq!(r2, 20);
        assert_eq!(out, [0x42u8; 20]);
    }

    #[test]
    fn socket_rx_available_and_tx_space() {
        let mut buf = alloc_socket_slot();
        let h = aligned_header(&mut buf);
        unsafe { socket_init(h, 5, false) };

        // Initially: RX available = 0, TX space = capacity.
        assert_eq!(unsafe { socket_rx_available(h) }, 0);
        assert_eq!(unsafe { socket_tx_space(h) }, SOCKET_RING_CAPACITY);

        // Fill 100 bytes into RX.
        let data = vec![0u8; 100];
        unsafe { socket_rx_fill(h, &data) };
        assert_eq!(unsafe { socket_rx_available(h) }, 100);

        // Write 200 bytes into TX.
        let data2 = vec![0u8; 200];
        unsafe { socket_try_write(h, &data2) };
        assert_eq!(unsafe { socket_tx_space(h) }, SOCKET_RING_CAPACITY - 200);
    }

    #[test]
    fn socket_set_flag_returns_previous() {
        let mut buf = alloc_socket_slot();
        let h = aligned_header(&mut buf);
        unsafe { socket_init(h, 5, false) };

        let prev = unsafe { socket_set_flag(h, socket_flags::RX_SHUTDOWN) };
        assert_eq!(prev, 0);

        let prev2 = unsafe { socket_set_flag(h, socket_flags::TX_SHUTDOWN) };
        assert_eq!(prev2, socket_flags::RX_SHUTDOWN);
    }

    #[test]
    fn socket_slot_size_matches() {
        assert_eq!(
            SOCKET_SLOT_SIZE,
            SOCKET_RING_HEADER_SIZE + 2 * SOCKET_RING_CAPACITY
        );
    }

    #[test]
    fn socket_ring_capacity_is_power_of_two() {
        assert!(SOCKET_RING_CAPACITY.is_power_of_two());
    }
}
