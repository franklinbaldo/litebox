// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Global per-process micro-LiteBox state.

use core::sync::atomic::{AtomicU32, AtomicUsize};
use litebox_ipc::ring::{SharedRingLayout, MAX_PIPE_SLOTS};

use crate::stack_pool::StackPool;

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

#[repr(C)]
pub struct MicroState {
    pub ring_base: *mut u8,
    pub ring_size: usize,
    pub ring_fd: i32,
    pub pid: u32,
    pub ppid: u32,
    /// PID of the central process, used to open child ring fds via `/proc/<pid>/fd/<N>`.
    pub central_pid: u32,
    pub layout: SharedRingLayout,
    /// Address of `micro_syscall_entry` — the assembly trampoline that
    /// intercepts rewritten `syscall` instructions. Written into the first
    /// 8 bytes of each trampoline page so the rewritten `JMP [RIP+disp]`
    /// reaches the handler.
    pub syscall_entry_point: usize,
    /// Emulated program break for the guest. After execve, the kernel's real
    /// brk cannot be moved to the new binary's address range (it stays at the
    /// host's original brk). This field tracks a virtual brk that starts at
    /// the end of the new binary's segments and grows via mmap.
    pub guest_brk: AtomicUsize,
    /// Emulated umask for the guest. Micro doesn't use the OS filesystem
    /// (central does), so we track the umask purely in libOS state. Default
    /// is 0o022 (matching central's shim default).
    pub umask: AtomicU32,
    /// Bump allocator for anonymous `mmap(NULL, ...)` fast-path.
    /// Next address to hand out (grows upward). 0 means bump allocator is
    /// not yet initialized (pre-execve).
    pub mmap_bump_next: AtomicUsize,
    /// Upper bound (exclusive) of the bump allocator range. When
    /// `mmap_bump_next >= mmap_bump_end`, the bump allocator is exhausted
    /// and mmap falls through to the normal central round-trip.
    pub mmap_bump_end: usize,
    /// Pipe fd tracking table. Each entry maps a guest fd to a shmem pipe
    /// ring buffer. Linear scan is fine — at most MAX_PIPE_SLOTS entries.
    pub pipe_fds: [Option<PipeFdEntry>; MAX_PIPE_SLOTS],
}

unsafe impl Send for MicroState {}
unsafe impl Sync for MicroState {}

static mut MICRO_STATE: MicroState = MicroState {
    ring_base: core::ptr::null_mut(),
    ring_size: 0,
    ring_fd: -1,
    pid: 0,
    ppid: 0,
    central_pid: 0,
    layout: SharedRingLayout::new(0),
    syscall_entry_point: 0,
    guest_brk: AtomicUsize::new(0),
    umask: AtomicU32::new(0o022),
    mmap_bump_next: AtomicUsize::new(0),
    mmap_bump_end: 0,
    pipe_fds: [None; MAX_PIPE_SLOTS],
};

/// Initialize the global micro-LiteBox state.
///
/// # Safety
///
/// Must be called exactly once, before any guest code runs and before any
/// threads are spawned.
pub unsafe fn micro_init(
    ring_fd: i32,
    ring_base: *mut u8,
    ring_size: usize,
    pid: u32,
    parent_pid: u32,
    central_pid: u32,
    syscall_entry_point: usize,
) {
    unsafe {
        MICRO_STATE.ring_base = ring_base;
        MICRO_STATE.ring_size = ring_size;
        MICRO_STATE.ring_fd = ring_fd;
        MICRO_STATE.pid = pid;
        MICRO_STATE.ppid = parent_pid;
        MICRO_STATE.central_pid = central_pid;
        MICRO_STATE.syscall_entry_point = syscall_entry_point;
        // Compute the layout from the ring_size. The data_region_size is the
        // remaining space after header + SQ + CQ entries.
        let base_layout = SharedRingLayout::new(0);
        let data_size = ring_size.saturating_sub(base_layout.total_size);
        MICRO_STATE.layout = SharedRingLayout::new(data_size);
    }
}

// ── Stack pool for vfork children ──────────────────────────────────────

static mut STACK_POOL: Option<StackPool> = None;

/// Initialize the global stack pool.
///
/// Must be called once, after `micro_init`, before any vfork/clone calls.
pub fn init_stack_pool() {
    unsafe {
        let ptr = &raw mut STACK_POOL;
        (*ptr) = Some(StackPool::new());
    }
}

/// Returns a mutable reference to the global stack pool.
///
/// # Panics
///
/// Panics if `init_stack_pool` has not been called.
pub fn global_stack_pool() -> &'static mut StackPool {
    unsafe {
        let ptr = &raw mut STACK_POOL;
        (*ptr).as_mut().expect("stack pool not initialized")
    }
}

#[inline]
pub fn global_micro_state_ptr() -> *mut MicroState {
    &raw mut MICRO_STATE
}

#[inline]
/// # Safety
///
/// The caller must ensure no mutable references to the global state exist.
pub unsafe fn global_micro_state() -> &'static MicroState {
    unsafe { &*global_micro_state_ptr() }
}

#[inline]
/// # Safety
///
/// The caller must ensure exclusive access to the global state (no other
/// references exist).
pub unsafe fn global_micro_state_mut() -> &'static mut MicroState {
    unsafe { &mut *global_micro_state_ptr() }
}

impl MicroState {
    /// Look up a pipe fd in the tracking table.
    /// Returns `(shmem_offset, is_write_end)` if found.
    pub fn find_pipe_fd(&self, fd: i32) -> Option<(u32, bool)> {
        for e in self.pipe_fds.iter().flatten() {
            if e.fd == fd {
                return Some((e.shmem_offset, e.is_write_end));
            }
        }
        None
    }

    /// Register a pipe fd in the tracking table. Returns `true` on success.
    pub fn register_pipe_fd(&mut self, fd: i32, shmem_offset: u32, is_write_end: bool) -> bool {
        for slot in &mut self.pipe_fds {
            if slot.is_none() {
                *slot = Some(PipeFdEntry {
                    fd,
                    shmem_offset,
                    is_write_end,
                });
                return true;
            }
        }
        false // table full
    }

    /// Remove a pipe fd from the tracking table. Returns `true` if found.
    pub fn unregister_pipe_fd(&mut self, fd: i32) -> bool {
        for slot in &mut self.pipe_fds {
            if let Some(e) = slot
                && e.fd == fd
            {
                *slot = None;
                return true;
            }
        }
        false
    }

    #[cfg(test)]
    pub fn zeroed() -> Self {
        Self {
            ring_base: core::ptr::null_mut(),
            ring_size: 0,
            ring_fd: -1,
            pid: 0,
            ppid: 0,
            central_pid: 0,
            layout: SharedRingLayout::new(0),
            syscall_entry_point: 0,
            guest_brk: AtomicUsize::new(0),
            umask: AtomicU32::new(0o022),
            mmap_bump_next: AtomicUsize::new(0),
            mmap_bump_end: 0,
            pipe_fds: [None; MAX_PIPE_SLOTS],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn micro_state_is_plain_data() {
        let state = MicroState::zeroed();
        assert!(state.ring_base.is_null());
        assert_eq!(state.ring_fd, -1);
        assert_eq!(state.pid, 0);
    }

    #[test]
    fn global_micro_state_ptr_is_stable() {
        let p1 = global_micro_state_ptr();
        let p2 = global_micro_state_ptr();
        assert_eq!(p1, p2);
    }

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
        assert!(state.register_pipe_fd(4, 0x500000, true)); // write end
        let (off_r, wr_r) = state.find_pipe_fd(3).unwrap();
        let (off_w, wr_w) = state.find_pipe_fd(4).unwrap();
        assert_eq!(off_r, off_w); // same pipe slot
        assert!(!wr_r);
        assert!(wr_w);
    }
}
