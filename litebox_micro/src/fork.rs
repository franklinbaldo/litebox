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

/// Clone flags for vfork fast-path.
const CLONE_VM: u64 = 0x100;
const CLONE_VFORK: u64 = 0x4000;
const SIGCHLD: u64 = 17;

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
    let local_fd = unsafe { crate::raw_syscall::open(path_buf.as_ptr(), libc::O_RDWR) };
    if crate::raw_syscall::is_error(local_fd) {
        return local_fd;
    }

    // dup2 to reserved fd so both parent and child have a well-known fd number.
    // Use raw dup3 syscall to avoid glibc wrappers (which access TLS for errno).
    let dup_ret = unsafe {
        crate::raw_syscall::syscall3(
            libc::SYS_dup3,
            local_fd as u64,
            RESERVED_CHILD_FD as u64,
            0, // no flags
        )
    };
    if crate::raw_syscall::is_error(dup_ret) {
        unsafe { crate::raw_syscall::close(local_fd as i32) };
        return dup_ret;
    }
    if local_fd as i32 != RESERVED_CHILD_FD {
        unsafe { crate::raw_syscall::close(local_fd as i32) };
    }

    // Use raw SYS_clone instead of libc::fork() to avoid glibc's atfork
    // handlers, which access internal state that is invalid in the guest
    // context (causes SIGSEGV at address 0x8 in the child).
    let pid = unsafe { crate::raw_syscall::syscall2(libc::SYS_clone, SIGCHLD, 0) };

    if crate::raw_syscall::is_error(pid) {
        unsafe { crate::raw_syscall::close(RESERVED_CHILD_FD) };
        return pid;
    }

    if pid == 0 {
        // CHILD — use raw syscalls only from here.
        unsafe { post_fork_child(RESERVED_CHILD_FD, child_pid_from_central) };
        0
    } else {
        // PARENT
        unsafe { crate::raw_syscall::close(RESERVED_CHILD_FD) };
        // Return the real OS child PID so the guest can waitpid() on it.
        // Central's assigned PID is used only for internal bookkeeping.
        pid
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

/// Saved parent state for vfork.
///
/// Because `CLONE_VM | CLONE_VFORK` shares the address space, the child will
/// reuse (and overwrite) the parent's stack frames as it returns through the
/// syscall handler and eventually calls `execve`.  Storing the parent's saved
/// state on the stack would therefore be corrupted by the time the parent
/// resumes.  A static avoids this — safe because micro is single-threaded and
/// `CLONE_VFORK` blocks the parent while the child runs.
struct SavedVforkState {
    ring_base: *mut u8,
    ring_size: usize,
    ring_fd: i32,
    pid: u32,
    ppid: u32,
    layout: SharedRingLayout,
    pipe_fds: [Option<crate::state::PipeFdEntry>; litebox_ipc::ring::MAX_PIPE_SLOTS],
    parent_pipe_zone: *mut u8,
    parent_pipe_zone_size: usize,
    guest_brk: usize,
    file_fds: [Option<crate::state::FileFdEntry>; litebox_ipc::ring::MAX_FILE_SLOTS],
    socket_fds: [Option<crate::state::SocketFdEntry>; litebox_ipc::ring::MAX_SOCKET_SLOTS],
    thread_slot: u64,
    seq_counter: u64,
}

/// Static storage for the parent's vfork-saved state.
///
/// Only one vfork can be in progress at a time (parent is blocked), so a
/// single static slot is sufficient.
static mut SAVED_VFORK: core::mem::MaybeUninit<SavedVforkState> = core::mem::MaybeUninit::uninit();

/// Restore parent's MicroState + TLS from the static `SAVED_VFORK` slot.
///
/// This is a separate `#[inline(never)]` function to ensure the compiler
/// generates a fresh stack frame that does NOT depend on any stack state
/// from before the `clone()` call. With `CLONE_VM | CLONE_VFORK`, the child
/// shares the parent's stack and will have corrupted it by the time the
/// parent resumes.
#[inline(never)]
unsafe fn restore_parent_vfork_state() {
    let saved = unsafe { &*(&raw const SAVED_VFORK).cast::<SavedVforkState>() };

    let micro = unsafe { crate::state::global_micro_state_mut() };
    micro.ring_base = saved.ring_base;
    micro.ring_size = saved.ring_size;
    micro.ring_fd = saved.ring_fd;
    micro.pid = saved.pid;
    micro.ppid = saved.ppid;
    micro.layout = saved.layout;
    micro.pipe_fds = saved.pipe_fds;
    micro.parent_pipe_zone = saved.parent_pipe_zone;
    micro.parent_pipe_zone_size = saved.parent_pipe_zone_size;
    micro
        .guest_brk
        .store(saved.guest_brk, core::sync::atomic::Ordering::Release);
    micro.file_fds = saved.file_fds;
    micro.socket_fds = saved.socket_fds;

    let tls = unsafe { crate::tls::current_tls() };
    unsafe {
        (*tls).thread_slot = saved.thread_slot;
        (*tls).seq_counter = saved.seq_counter;
    }
}

/// Execute a vfork authorized by central — fast-path using
/// `clone(CLONE_VM|CLONE_VFORK|SIGCHLD)` with parent's stack.
///
/// The CqEntry carries the same fields as [`handle_fork`].
///
/// Returns: child OS PID in parent, 0 in child, or negative errno on failure.
///
/// # Safety
///
/// - The global [`MicroState`] must be initialized.
/// - TLS must be initialized for the calling thread.
/// - `cq` must contain valid fork parameters from central.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::similar_names
)]
pub unsafe fn handle_vfork(cq: &CqEntry) -> i64 {
    let central_pid = cq.result as u32;
    let child_pid_from_central = cq.data_offset;
    let child_ring_fd_in_central = cq.data_len.cast_signed();

    // Open the child ring fd via /proc/<central_pid>/fd/<N>.
    let mut path_buf = [0u8; 64];
    format_proc_fd_path(&mut path_buf, central_pid, child_ring_fd_in_central);
    let local_fd = unsafe { crate::raw_syscall::open(path_buf.as_ptr(), libc::O_RDWR) };
    if crate::raw_syscall::is_error(local_fd) {
        return local_fd;
    }

    // dup2 to reserved fd so both parent and child have a well-known fd number.
    // Use raw dup3 syscall to avoid glibc wrappers.
    let dup_ret = unsafe {
        crate::raw_syscall::syscall3(libc::SYS_dup3, local_fd as u64, RESERVED_CHILD_FD as u64, 0)
    };
    if crate::raw_syscall::is_error(dup_ret) {
        unsafe { crate::raw_syscall::close(local_fd as i32) };
        return dup_ret;
    }
    if local_fd as i32 != RESERVED_CHILD_FD {
        unsafe { crate::raw_syscall::close(local_fd as i32) };
    }

    // Save parent's MicroState + TLS fields into the static SAVED_VFORK slot.
    // We use a static instead of stack locals because CLONE_VM shares the
    // address space: the child will reuse and overwrite parent stack frames
    // as it returns through the syscall handler before calling execve.
    unsafe {
        save_parent_vfork_state();
    }

    // clone(CLONE_VM | CLONE_VFORK | SIGCHLD, 0)
    // Passing 0 for stack makes the child share the parent's stack.
    // CLONE_VFORK blocks the parent until the child calls execve or _exit,
    // so sharing the stack is safe.  The child WILL overwrite parent stack
    // frames as it returns through the syscall handler — that's why we saved
    // state into a static above, not into stack locals.
    let flags = CLONE_VM | CLONE_VFORK | SIGCHLD;

    let ret = unsafe { crate::raw_syscall::syscall2(libc::SYS_clone, flags, 0) };

    if crate::raw_syscall::is_error(ret) {
        unsafe { crate::raw_syscall::close(RESERVED_CHILD_FD) };
        return ret;
    }

    if ret == 0 {
        // CHILD — running on parent's stack (safe because CLONE_VFORK blocks parent).
        unsafe {
            post_fork_child_vfork(RESERVED_CHILD_FD, child_pid_from_central);
        }
        0
    } else {
        // PARENT — resumed after child called execve or _exit.
        // Restore state from the static slot via a separate function to avoid
        // depending on any stack locals that the child may have overwritten.
        unsafe { restore_parent_vfork_state() };

        // Close the reserved fd — child has its own ring mapped.
        unsafe { crate::raw_syscall::close(RESERVED_CHILD_FD) };

        // Return child's OS PID.
        ret
    }
}

/// Save parent's MicroState + TLS into the static `SAVED_VFORK` slot.
///
/// Separate function to keep `handle_vfork` lean — all the large struct
/// copies happen here and won't occupy `handle_vfork`'s stack frame across
/// the `clone()` syscall.
#[inline(never)]
unsafe fn save_parent_vfork_state() {
    let micro = unsafe { crate::state::global_micro_state_mut() };
    let tls = unsafe { crate::tls::current_tls() };

    unsafe {
        (&raw mut SAVED_VFORK)
            .cast::<SavedVforkState>()
            .write(SavedVforkState {
                ring_base: micro.ring_base,
                ring_size: micro.ring_size,
                ring_fd: micro.ring_fd,
                pid: micro.pid,
                ppid: micro.ppid,
                layout: micro.layout,
                pipe_fds: micro.pipe_fds,
                parent_pipe_zone: micro.parent_pipe_zone,
                parent_pipe_zone_size: micro.parent_pipe_zone_size,
                guest_brk: micro.guest_brk.load(core::sync::atomic::Ordering::Acquire),
                file_fds: micro.file_fds,
                socket_fds: micro.socket_fds,
                thread_slot: (*tls).thread_slot,
                seq_counter: (*tls).seq_counter,
            });
    }
}

/// Post-fork child initialization for vfork (CLONE_VM path).
///
/// Unlike [`post_fork_child`], this does **not** munmap the parent's ring
/// because `CLONE_VM` shares the address space — unmapping would corrupt the
/// parent's mappings.
///
/// # Safety
///
/// Must be called in the child immediately after `clone(CLONE_VM|CLONE_VFORK)`
/// returns 0.
#[allow(clippy::cast_sign_loss)]
unsafe fn post_fork_child_vfork(child_ring_fd: i32, child_pid: u32) {
    let micro = unsafe { crate::state::global_micro_state_mut() };

    // 1. Map child's new ring buffer at a NEW address (let kernel choose).
    //    Do NOT munmap the parent ring — we share address space.
    let layout = SharedRingLayout::default_layout();
    let new_base = unsafe {
        crate::raw_syscall::mmap(
            0,
            layout.total_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            child_ring_fd,
            0,
        )
    };
    assert!(
        !crate::raw_syscall::is_error(new_base),
        "vfork child: mmap of new ring failed"
    );

    // 2. Update global micro state to point at child ring.
    micro.ring_base = new_base as *mut u8;
    micro.ring_size = layout.total_size;
    micro.ring_fd = child_ring_fd;
    micro.pid = child_pid;
    micro.ppid = unsafe { libc::getppid().cast_unsigned() };
    micro.layout = layout;

    // 3. Clear pipe fd tracking table.
    micro.pipe_fds = [None; litebox_ipc::ring::MAX_PIPE_SLOTS];
    micro.parent_pipe_zone = core::ptr::null_mut();
    micro.parent_pipe_zone_size = 0;
    // Clear file and socket fd tables — entries point into the parent ring.
    micro.file_fds = [None; litebox_ipc::ring::MAX_FILE_SLOTS];
    micro.socket_fds = [None; litebox_ipc::ring::MAX_SOCKET_SLOTS];

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
    unsafe { crate::raw_syscall::close(child_ring_fd) };
}

/// Post-fork child initialization.
///
/// # Safety
///
/// Must be called in the child immediately after fork() returns 0.
unsafe fn post_fork_child(child_ring_fd: i32, child_pid: u32) {
    let micro = unsafe { crate::state::global_micro_state_mut() };

    // Save parent ring fd before we overwrite it — needed for pipe zone mmap.
    let parent_ring_fd = micro.ring_fd;
    // Check if there are active pipes before we lose the old pointers.
    let has_parent_pipes = micro.pipe_fds.iter().any(Option::is_some);
    // Save old pipe zone base for pointer rebasing.
    let old_pipe_zone_base = unsafe {
        micro
            .ring_base
            .add(micro.layout.data_region_offset)
            .add(litebox_ipc::ring::PIPE_ZONE_BASE_OFFSET)
    };

    // 1. Unmap parent's ring buffer.
    if !micro.ring_base.is_null() && micro.ring_size > 0 {
        unsafe { crate::raw_syscall::munmap(micro.ring_base as usize, micro.ring_size) };
    }

    // 2. Map child's new ring buffer.
    let layout = SharedRingLayout::default_layout();
    let new_base = unsafe {
        crate::raw_syscall::mmap(
            0,
            layout.total_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            child_ring_fd,
            0,
        )
    };
    if crate::raw_syscall::is_error(new_base) {
        unsafe { crate::raw_syscall::syscall1(libc::SYS_exit_group, 99) };
        unreachable!();
    }

    // 3. Update global micro state.
    micro.ring_base = new_base as *mut u8;
    micro.ring_size = layout.total_size;
    micro.ring_fd = child_ring_fd;
    micro.pid = child_pid;
    // Use raw syscall for getppid to avoid glibc TLS issues
    let ppid = unsafe { crate::raw_syscall::syscall0(libc::SYS_getppid) };
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    {
        micro.ppid = ppid as u32;
    }
    // central_pid stays the same — same central process serves the child.
    micro.layout = layout;

    // 3b. Re-establish pipe shmem access.
    if has_parent_pipes {
        // Map the parent's pipe zone so pipe header pointers remain valid.
        let pipe_zone_file_offset =
            layout.data_region_offset + litebox_ipc::ring::PIPE_ZONE_BASE_OFFSET;
        let pipe_zone_size = litebox_ipc::ring::PIPE_ZONE_SIZE;
        #[allow(clippy::cast_possible_wrap)]
        let parent_zone = unsafe {
            crate::raw_syscall::mmap(
                0,
                pipe_zone_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                parent_ring_fd,
                pipe_zone_file_offset as i64,
            )
        };
        if crate::raw_syscall::is_error(parent_zone) {
            // Failed to map parent pipe zone — clear pipes as fallback.
            micro.pipe_fds = [None; litebox_ipc::ring::MAX_PIPE_SLOTS];
            micro.parent_pipe_zone = core::ptr::null_mut();
            micro.parent_pipe_zone_size = 0;
        } else {
            // Rewrite pipe_fds header pointers to the new mapping.
            let new_zone_base = parent_zone as *mut u8;
            for entry in micro.pipe_fds.iter_mut().flatten() {
                let offset_in_zone = (entry.header_ptr as usize) - (old_pipe_zone_base as usize);
                entry.header_ptr = unsafe { new_zone_base.add(offset_in_zone) };
            }
            micro.parent_pipe_zone = new_zone_base;
            micro.parent_pipe_zone_size = pipe_zone_size;
        }
    } else {
        micro.pipe_fds = [None; litebox_ipc::ring::MAX_PIPE_SLOTS];
        micro.parent_pipe_zone = core::ptr::null_mut();
        micro.parent_pipe_zone_size = 0;
    }

    // Close parent ring fd — the pipe zone is now independently mapped.
    unsafe { crate::raw_syscall::close(parent_ring_fd) };

    // Clear file fd table — entries point into the parent ring's data region
    // which was unmapped. The child gets fresh file slots as it opens/dups
    // files. Without this, writes via FILE_SHMEM use stale offsets and
    // central can't find the TX ring header (child's shmem_files is empty).
    micro.file_fds = [None; litebox_ipc::ring::MAX_FILE_SLOTS];
    // Socket fds also point into the old ring — clear them too.
    micro.socket_fds = [None; litebox_ipc::ring::MAX_SOCKET_SLOTS];

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
    unsafe { crate::raw_syscall::close(child_ring_fd) };
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
