// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Fork handling: execute a real `fork()` and reconnect the child to central
//! via a new ring buffer.

use litebox_ipc::messages::MSG_CHILD_READY;
use litebox_ipc::ring::{CqEntry, SharedRingLayout};

/// Reserved file descriptor number for passing the child's ring buffer fd
/// across `fork()`.
const RESERVED_CHILD_FD: i32 = 200;

/// Execute a fork authorized by central.
///
/// `cq.result` contains the child ring fd (already open in this process).
/// `cq.data_offset` is reused to carry the child PID assigned by central.
///
/// Returns: child PID in parent, 0 in child, or negative errno on failure.
///
/// # Safety
///
/// - The global [`MicroState`] must be initialized.
/// - TLS must be initialized for the calling thread.
/// - `cq` must contain a valid child ring fd in `result`.
#[allow(clippy::cast_possible_truncation)] // child ring fd fits in i32
pub unsafe fn handle_fork(cq: &CqEntry) -> i64 {
    let child_ring_fd = cq.result as i32;
    let child_pid_from_central = cq.data_offset;

    // Place child ring fd at a well-known number for both parent and child.
    let dup_ret = unsafe { libc::dup2(child_ring_fd, RESERVED_CHILD_FD) };
    if dup_ret < 0 {
        return -i64::from(unsafe { *libc::__errno_location() });
    }

    // Close the original fd — RESERVED_CHILD_FD now owns the file description.
    // Without this, both parent and child would leak child_ring_fd.
    if child_ring_fd != RESERVED_CHILD_FD {
        unsafe { libc::close(child_ring_fd) };
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
        i64::from(pid)
    }
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

    // 6. Close the reserved fd.
    unsafe { libc::close(child_ring_fd) };
}
