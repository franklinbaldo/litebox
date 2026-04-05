// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Lightweight profiling helpers for no_std micro.
//!
//! Uses raw syscalls to avoid any glibc/TLS dependency.  All output goes to
//! `/tmp/litebox_micro_perf.log` via raw `openat`/`write`.

use core::sync::atomic::{AtomicI32, Ordering};

use crate::raw_syscall;

/// Sentinel: file not yet opened.
const FD_UNINIT: i32 = -1;

/// Global fd for the perf log file.  Opened lazily on first use.
static PERF_FD: AtomicI32 = AtomicI32::new(FD_UNINIT);

/// Open the perf log file if not already open.  Returns the fd, or -1 on
/// failure.
#[allow(clippy::cast_possible_truncation)]
fn perf_fd() -> i32 {
    let fd = PERF_FD.load(Ordering::Relaxed);
    if fd != FD_UNINIT {
        return fd;
    }
    // Try to open/create the file.
    let new_fd = unsafe {
        raw_syscall::syscall4(
            libc::SYS_openat,
            (-100i64).cast_unsigned(), // AT_FDCWD
            c"/tmp/litebox_micro_perf.log".as_ptr() as u64,
            (libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND) as u64,
            0o644u64,
        )
    };
    if raw_syscall::is_error(new_fd) {
        return -1;
    }
    let new_fd = new_fd as i32;
    // Race-safe: if another thread opened it first, close ours and use theirs.
    match PERF_FD.compare_exchange(FD_UNINIT, new_fd, Ordering::Release, Ordering::Acquire) {
        Ok(_) => new_fd,
        Err(existing) => {
            unsafe { raw_syscall::close(new_fd) };
            existing
        }
    }
}

/// Read `CLOCK_MONOTONIC` via raw syscall.  Returns nanoseconds since boot.
#[inline]
pub fn now_ns() -> u64 {
    // Use MaybeUninit to avoid alignment issues on the 8-byte-aligned
    // syscall-handler stack.
    let mut ts = core::mem::MaybeUninit::<[u64; 2]>::uninit();
    let ret = unsafe {
        raw_syscall::syscall2(
            libc::SYS_clock_gettime,
            libc::CLOCK_MONOTONIC as u64,
            ts.as_mut_ptr() as u64,
        )
    };
    if raw_syscall::is_error(ret) {
        return 0;
    }
    let ts = unsafe { ts.assume_init() };
    // ts[0] = tv_sec, ts[1] = tv_nsec
    ts[0].wrapping_mul(1_000_000_000).wrapping_add(ts[1])
}

/// Write a profiling line to the perf log.
///
/// Format: `PERF:MICRO_EXEC serial=<n> <label>=<ns> ...\n`
///
/// `entries` is an array of `(label, elapsed_ns)` pairs.
pub fn write_perf_line(serial: u64, entries: &[(&str, u64)]) {
    let fd = perf_fd();
    if fd < 0 {
        return;
    }

    // Format into a stack buffer.  We need ~200 bytes max.
    let mut buf = [0u8; 512];
    let mut pos = 0usize;

    // "PERF:MICRO_EXEC serial=<n>"
    pos = append_str(&mut buf, pos, "PERF:MICRO_EXEC serial=");
    pos = append_u64(&mut buf, pos, serial);

    for &(label, ns) in entries {
        pos = append_str(&mut buf, pos, " ");
        pos = append_str(&mut buf, pos, label);
        pos = append_str(&mut buf, pos, "=");
        pos = append_u64(&mut buf, pos, ns);
    }

    pos = append_str(&mut buf, pos, "\n");

    // Write in one shot (best-effort, ignore errors).
    unsafe { raw_syscall::write(fd, buf.as_ptr(), pos) };
}

/// Append a string to the buffer.  Returns the new position.
#[inline]
fn append_str(buf: &mut [u8], pos: usize, s: &str) -> usize {
    let bytes = s.as_bytes();
    let end = (pos + bytes.len()).min(buf.len());
    let n = end - pos;
    buf[pos..end].copy_from_slice(&bytes[..n]);
    end
}

/// Append a u64 as decimal to the buffer.  Returns the new position.
#[inline]
fn append_u64(buf: &mut [u8], pos: usize, val: u64) -> usize {
    if val == 0 {
        if pos < buf.len() {
            buf[pos] = b'0';
            return pos + 1;
        }
        return pos;
    }
    // Format into a small temp buffer (max 20 digits for u64).
    let mut tmp = [0u8; 20];
    let mut n = 0usize;
    let mut v = val;
    while v > 0 {
        tmp[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    // Reverse into the output buffer.
    let end = (pos + n).min(buf.len());
    let count = end - pos;
    for i in 0..count {
        buf[pos + i] = tmp[n - 1 - i];
    }
    end
}
