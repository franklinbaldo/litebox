// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Fork handling: execute a real `fork()` and reconnect the child to central
//! via a new ring buffer.
//!
//! Central creates a memfd for the child's ring and returns the central PID
//! and the fd number in central's fd table.  Micro opens the child ring via
//! `/proc/<central_pid>/fd/<N>`, dup2s it to a reserved fd, then calls the
//! real `fork()`.

use litebox_ipc::messages::MSG_CHILD_READY;
use litebox_ipc::ring::{CqEntry, SharedRingLayout};

/// Reserved file descriptor number for passing the child's ring buffer fd
/// across `fork()`.
const RESERVED_CHILD_FD: i32 = 200;

/// Execute a fork authorized by central.
///
/// The CqEntry carries:
/// - `result`: central PID (so micro can construct `/proc/<pid>/fd/...`)
/// - `data_offset`: child PID assigned by central
/// - `data_len`: child ring fd number in central's fd table
///
/// Returns: child PID in parent, 0 in child, or negative errno on failure.
///
/// # Safety
///
/// - The global [`MicroState`] must be initialized.
/// - TLS must be initialized for the calling thread.
/// - `cq` must contain valid fork parameters from central.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]
pub unsafe fn handle_fork(cq: &CqEntry) -> i64 {
    let central_pid = cq.result as u32;
    let child_pid_from_central = cq.data_offset;
    let child_ring_fd_in_central = cq.data_len.cast_signed();

    // Open the child ring fd via /proc/<central_pid>/fd/<N>.
    // Central created the memfd WITHOUT MFD_CLOEXEC so it is accessible here.
    let mut path_buf = [0u8; 64];
    format_proc_fd_path(&mut path_buf, central_pid, child_ring_fd_in_central);
    let local_fd = unsafe { libc::open(path_buf.as_ptr().cast(), libc::O_RDWR) };
    if local_fd < 0 {
        return -i64::from(unsafe { *libc::__errno_location() });
    }

    // dup2 to reserved fd so both parent and child have a well-known fd number.
    let dup_ret = unsafe { libc::dup2(local_fd, RESERVED_CHILD_FD) };
    if dup_ret < 0 {
        let e = -i64::from(unsafe { *libc::__errno_location() });
        unsafe { libc::close(local_fd) };
        return e;
    }
    if local_fd != RESERVED_CHILD_FD {
        unsafe { libc::close(local_fd) };
    }

    let pid = unsafe { libc::fork() };

    if pid < 0 {
        let errno = unsafe { *libc::__errno_location() };
        unsafe { libc::close(RESERVED_CHILD_FD) };
        return -i64::from(errno);
    }

    if pid == 0 {
        // CHILD
        unsafe { post_fork_child(RESERVED_CHILD_FD, child_pid_from_central) };
        0
    } else {
        // PARENT
        unsafe { libc::close(RESERVED_CHILD_FD) };
        // Return the real OS child PID so the guest can waitpid() on it.
        // Central's assigned PID is used only for internal bookkeeping.
        i64::from(pid)
    }
}

/// Format a `/proc/<pid>/fd/<fd>` path into a stack buffer (null-terminated).
fn format_proc_fd_path(buf: &mut [u8; 64], pid: u32, fd: i32) {
    // Manual integer-to-string formatting to avoid pulling in std::fmt
    // machinery.  The buffer is large enough for any realistic PID + fd.
    let mut pos = 0usize;

    let prefix = b"/proc/";
    buf[pos..pos + prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();

    pos = write_u32(buf, pos, pid);

    let mid = b"/fd/";
    buf[pos..pos + mid.len()].copy_from_slice(mid);
    pos += mid.len();

    // fd is non-negative in practice; treat as unsigned for formatting.
    pos = write_u32(buf, pos, fd.cast_unsigned());

    buf[pos] = 0; // null-terminate
}

/// Write a `u32` as decimal ASCII into `buf` starting at `pos`. Returns new pos.
fn write_u32(buf: &mut [u8], start: usize, mut val: u32) -> usize {
    if val == 0 {
        buf[start] = b'0';
        return start + 1;
    }
    // Write digits in reverse, then flip.
    let begin = start;
    let mut pos = start;
    while val > 0 {
        buf[pos] = b'0' + (val % 10) as u8;
        val /= 10;
        pos += 1;
    }
    buf[begin..pos].reverse();
    pos
}

/// Post-fork child initialization.
///
/// # Safety
///
/// Must be called in the child immediately after fork() returns 0.
unsafe fn post_fork_child(child_ring_fd: i32, child_pid: u32) {
    let micro = unsafe { crate::state::global_micro_state_mut() };

    // 1. Unmap parent's ring buffer.
    if !micro.ring_base.is_null() && micro.ring_size > 0 {
        unsafe { libc::munmap(micro.ring_base.cast(), micro.ring_size) };
    }

    // 2. Map child's new ring buffer.
    let layout = SharedRingLayout::default_layout();
    let new_base = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            layout.total_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            child_ring_fd,
            0,
        )
    };
    assert_ne!(new_base, libc::MAP_FAILED, "child: mmap of new ring failed");

    // 3. Update global micro state.
    micro.ring_base = new_base.cast();
    micro.ring_size = layout.total_size;
    micro.ring_fd = child_ring_fd;
    micro.pid = child_pid;
    micro.ppid = unsafe { libc::getppid().cast_unsigned() };
    // central_pid stays the same — same central process serves the child.
    micro.layout = layout;

    // 4. Reset TLS.
    let tls = unsafe { crate::tls::current_tls() };
    unsafe {
        (*tls).micro = crate::state::global_micro_state_ptr();
        (*tls).thread_slot = 0;
        (*tls).seq_counter = 0;
    }

    // 5. Send MSG_CHILD_READY to central via new ring.
    let args = [u64::from(child_pid), 0, 0, 0, 0, 0];
    unsafe {
        crate::handler::submit_and_wait(tls, MSG_CHILD_READY, &args, 0);
    }

    // 6. Close the reserved fd — the ring is now mapped, fd no longer needed.
    unsafe { libc::close(child_ring_fd) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_proc_fd_path_basic() {
        let mut buf = [0u8; 64];
        format_proc_fd_path(&mut buf, 1234, 5);
        let s = core::str::from_utf8(&buf[..16]).unwrap();
        assert_eq!(&s[..15], "/proc/1234/fd/5");
        assert_eq!(buf[15], 0); // null-terminated
    }

    #[test]
    fn format_proc_fd_path_large() {
        let mut buf = [0u8; 64];
        format_proc_fd_path(&mut buf, 999999, 42);
        let end = buf.iter().position(|&b| b == 0).unwrap();
        let s = core::str::from_utf8(&buf[..end]).unwrap();
        assert_eq!(s, "/proc/999999/fd/42");
    }
}
