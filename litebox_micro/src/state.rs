// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Global per-process micro-LiteBox state.

use litebox_ipc::ring::SharedRingLayout;

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
) {
    unsafe {
        MICRO_STATE.ring_base = ring_base;
        MICRO_STATE.ring_size = ring_size;
        MICRO_STATE.ring_fd = ring_fd;
        MICRO_STATE.pid = pid;
        MICRO_STATE.ppid = parent_pid;
        MICRO_STATE.central_pid = central_pid;
        // Compute the layout from the ring_size. The data_region_size is the
        // remaining space after header + SQ + CQ entries.
        let base_layout = SharedRingLayout::new(0);
        let data_size = ring_size.saturating_sub(base_layout.total_size);
        MICRO_STATE.layout = SharedRingLayout::new(data_size);
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
}
