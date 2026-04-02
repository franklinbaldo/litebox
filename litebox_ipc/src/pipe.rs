// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Lock-free SPSC pipe ring buffer operations on shared memory.
//!
//! Both micro and central call these functions to interact with pipe ring
//! buffers that live in the shmem data region. The ring buffer is a classic
//! single-producer/single-consumer design with atomic head/tail cursors.

use core::sync::atomic::Ordering::{Acquire, Relaxed, Release};

use crate::ring::{PIPE_DATA_CAPACITY, ShmemPipeHeader, pipe_flags};

/// Initialize a `ShmemPipeHeader` at the given pointer.
///
/// # Safety
///
/// `header` must point to a valid, writable, 64-byte-aligned region of at
/// least `PIPE_SLOT_SIZE` bytes in shared memory. The caller must ensure
/// exclusive access during initialization.
#[allow(clippy::used_underscore_binding)]
pub unsafe fn pipe_init(header: *mut ShmemPipeHeader, read_fd: i32, write_fd: i32, nonblock: bool) {
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
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
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
    let data_base = unsafe { header.cast::<u8>().add(size_of::<ShmemPipeHeader>()) };

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
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
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
    let data_base = unsafe { header.cast::<u8>().add(size_of::<ShmemPipeHeader>()) };

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
///
/// # Safety
///
/// `header` must point to a valid `ShmemPipeHeader` in shared memory.
pub unsafe fn pipe_set_flag(header: *mut ShmemPipeHeader, flag: u32) {
    let h = unsafe { &*header };
    h.flags.fetch_or(flag, Release);
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

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

        unsafe { pipe_set_flag(h, pipe_flags::WRITER_CLOSED) };
        let mut out = [0u8; 64];
        let result = unsafe { pipe_try_read(h, &mut out) };
        assert_eq!(result, 0); // EOF
    }

    #[test]
    fn pipe_write_reader_closed_returns_epipe() {
        let mut buf = alloc_pipe_slot();
        let h = aligned_header(&mut buf);
        unsafe { pipe_init(h, 3, 4, false) };

        unsafe { pipe_set_flag(h, pipe_flags::READER_CLOSED) };
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
