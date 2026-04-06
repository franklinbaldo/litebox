// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Global per-process micro-LiteBox state.

use core::sync::atomic::{AtomicU32, AtomicUsize};
use litebox_ipc::ring::{MAX_FILE_SLOTS, MAX_PIPE_SLOTS, MAX_SOCKET_SLOTS, SharedRingLayout};

use crate::stack_pool::StackPool;

/// Entry in micro's local socket fd tracking table.
///
/// Maps a file descriptor to the shmem offset of its socket ring buffer.
#[derive(Clone, Copy)]
pub struct SocketFdEntry {
    /// The file descriptor number.
    pub fd: i32,
    /// Offset within the data region to the socket's `ShmemSocketHeader`.
    pub shmem_offset: u32,
}

/// Tracks a file fd that has a shmem ring buffer slot for data transport.
#[derive(Clone, Copy)]
pub struct FileFdEntry {
    pub fd: i32,
    /// Offset within the data region to the file slot header (reuses ShmemSocketHeader layout).
    pub shmem_offset: u32,
    /// Byte offset into tar shmem where file data starts (0 = not tar-backed).
    pub tar_offset: u64,
    /// File size in tar.
    pub tar_len: u64,
    /// Current file position for sequential read().
    pub cursor: u64,
}

/// Entry in micro's local pipe fd tracking table.
///
/// Maps a file descriptor to the shmem pipe ring buffer header.
#[derive(Clone, Copy)]
pub struct PipeFdEntry {
    /// The file descriptor number.
    pub fd: i32,
    /// Direct pointer to the pipe's `ShmemPipeHeader` in shmem.
    pub header_ptr: *mut u8,
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
    /// Socket fd tracking table. Each entry maps a guest fd to a shmem socket
    /// ring buffer. Linear scan is fine — at most MAX_SOCKET_SLOTS entries.
    pub socket_fds: [Option<SocketFdEntry>; MAX_SOCKET_SLOTS],
    /// File fd tracking table. Each entry maps a guest fd to a shmem file
    /// ring buffer slot. Linear scan is fine — at most MAX_FILE_SLOTS entries.
    pub file_fds: [Option<FileFdEntry>; MAX_FILE_SLOTS],
    /// Base pointer of the tar shmem region (null if no tar).
    pub tar_base: *const u8,
    /// Size of the tar shmem region in bytes.
    pub tar_size: usize,
    /// File descriptor for the aligned data memfd (for mmap during exec).
    /// -1 if no aligned data available.
    pub aligned_fd: i32,
    /// Base pointer of the aligned data memfd mapping (null if none).
    pub aligned_base: *const u8,
    /// Size of the aligned data memfd in bytes.
    pub aligned_size: usize,
    /// Base pointer of the parent's pipe zone mapping (null if no parent pipes).
    /// After fork, the child mmaps the parent's shmem pipe zone so both
    /// processes share the same SPSC ring buffers for pipe I/O.
    pub parent_pipe_zone: *mut u8,
    /// Size of the parent pipe zone mapping in bytes (for munmap cleanup).
    pub parent_pipe_zone_size: usize,
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
    socket_fds: [None; MAX_SOCKET_SLOTS],
    file_fds: [None; MAX_FILE_SLOTS],
    tar_base: core::ptr::null(),
    tar_size: 0,
    aligned_fd: -1,
    aligned_base: core::ptr::null(),
    aligned_size: 0,
    parent_pipe_zone: core::ptr::null_mut(),
    parent_pipe_zone_size: 0,
};

/// Initialize the global micro-LiteBox state.
///
/// # Safety
///
/// Must be called exactly once, before any guest code runs and before any
/// threads are spawned.
#[allow(clippy::too_many_arguments)]
pub unsafe fn micro_init(
    ring_fd: i32,
    ring_base: *mut u8,
    ring_size: usize,
    pid: u32,
    parent_pid: u32,
    central_pid: u32,
    syscall_entry_point: usize,
    tar_base: *const u8,
    tar_size: usize,
    aligned_fd: i32,
    aligned_base: *const u8,
    aligned_size: usize,
) {
    unsafe {
        MICRO_STATE.ring_base = ring_base;
        MICRO_STATE.ring_size = ring_size;
        MICRO_STATE.ring_fd = ring_fd;
        MICRO_STATE.pid = pid;
        MICRO_STATE.ppid = parent_pid;
        MICRO_STATE.central_pid = central_pid;
        MICRO_STATE.syscall_entry_point = syscall_entry_point;
        MICRO_STATE.tar_base = tar_base;
        MICRO_STATE.tar_size = tar_size;
        MICRO_STATE.aligned_fd = aligned_fd;
        MICRO_STATE.aligned_base = aligned_base;
        MICRO_STATE.aligned_size = aligned_size;
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
    /// Returns `(header_ptr, is_write_end)` if found.
    pub fn find_pipe_fd(&self, fd: i32) -> Option<(*mut u8, bool)> {
        for e in self.pipe_fds.iter().flatten() {
            if e.fd == fd {
                return Some((e.header_ptr, e.is_write_end));
            }
        }
        None
    }

    /// Register a pipe fd in the tracking table. Returns `true` on success.
    pub fn register_pipe_fd(&mut self, fd: i32, header_ptr: *mut u8, is_write_end: bool) -> bool {
        for slot in &mut self.pipe_fds {
            if slot.is_none() {
                *slot = Some(PipeFdEntry {
                    fd,
                    header_ptr,
                    is_write_end,
                });
                return true;
            }
        }
        false // table full
    }

    /// Check if any pipe fds are still registered.
    pub fn has_any_pipe_fd(&self) -> bool {
        self.pipe_fds.iter().any(Option::is_some)
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

    /// Look up a socket fd in the tracking table.
    /// Returns the shmem offset if found.
    pub fn find_socket_fd(&self, fd: i32) -> Option<u32> {
        for e in self.socket_fds.iter().flatten() {
            if e.fd == fd {
                return Some(e.shmem_offset);
            }
        }
        None
    }

    /// Register a socket fd in the tracking table. Returns `true` on success.
    pub fn register_socket_fd(&mut self, fd: i32, shmem_offset: u32) -> bool {
        for slot in &mut self.socket_fds {
            if slot.is_none() {
                *slot = Some(SocketFdEntry { fd, shmem_offset });
                return true;
            }
        }
        false // table full
    }

    /// Remove a socket fd from the tracking table. Returns `true` if found.
    pub fn unregister_socket_fd(&mut self, fd: i32) -> bool {
        for slot in &mut self.socket_fds {
            if let Some(e) = slot
                && e.fd == fd
            {
                *slot = None;
                return true;
            }
        }
        false
    }

    /// Find a file fd's shmem offset.
    pub fn find_file_fd(&self, fd: i32) -> Option<u32> {
        for e in self.file_fds.iter().flatten() {
            if e.fd == fd {
                return Some(e.shmem_offset);
            }
        }
        None
    }

    /// Register a file fd with its shmem slot offset and optional tar backing.
    pub fn register_file_fd(
        &mut self,
        fd: i32,
        shmem_offset: u32,
        tar_offset: u64,
        tar_len: u64,
    ) -> bool {
        for slot in &mut self.file_fds {
            if slot.is_none() {
                *slot = Some(FileFdEntry {
                    fd,
                    shmem_offset,
                    tar_offset,
                    tar_len,
                    cursor: 0,
                });
                return true;
            }
        }
        false // table full
    }

    /// Unregister a file fd. Returns true if found and removed.
    pub fn unregister_file_fd(&mut self, fd: i32) -> bool {
        for slot in &mut self.file_fds {
            if let Some(e) = slot
                && e.fd == fd
            {
                *slot = None;
                return true;
            }
        }
        false
    }

    /// Find a tar-backed file fd entry (mutable reference for cursor updates).
    pub fn find_tar_file_fd_mut(&mut self, fd: i32) -> Option<&mut FileFdEntry> {
        self.file_fds
            .iter_mut()
            .flatten()
            .find(|entry| entry.fd == fd && entry.tar_offset != 0)
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
            socket_fds: [None; MAX_SOCKET_SLOTS],
            file_fds: [None; MAX_FILE_SLOTS],
            tar_base: core::ptr::null(),
            tar_size: 0,
            aligned_fd: -1,
            aligned_base: core::ptr::null(),
            aligned_size: 0,
            parent_pipe_zone: core::ptr::null_mut(),
            parent_pipe_zone_size: 0,
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
        let fake_ptr = 0x500000 as *mut u8;
        assert!(state.register_pipe_fd(5, fake_ptr, false));
        let (ptr, is_write) = state.find_pipe_fd(5).unwrap();
        assert_eq!(ptr, fake_ptr);
        assert!(!is_write);
    }

    #[test]
    fn pipe_fd_unregister() {
        let mut state = MicroState::zeroed();
        let fake_ptr = 0x500000 as *mut u8;
        state.register_pipe_fd(5, fake_ptr, false);
        assert!(state.unregister_pipe_fd(5));
        assert!(state.find_pipe_fd(5).is_none());
        assert!(!state.unregister_pipe_fd(5)); // already removed
    }

    #[test]
    fn pipe_fd_register_both_ends() {
        let mut state = MicroState::zeroed();
        let fake_ptr = 0x500000 as *mut u8;
        assert!(state.register_pipe_fd(3, fake_ptr, false)); // read end
        assert!(state.register_pipe_fd(4, fake_ptr, true)); // write end
        let (ptr_r, wr_r) = state.find_pipe_fd(3).unwrap();
        let (ptr_w, wr_w) = state.find_pipe_fd(4).unwrap();
        assert_eq!(ptr_r, ptr_w); // same pipe slot
        assert!(!wr_r);
        assert!(wr_w);
    }

    #[test]
    fn socket_fd_register_and_find() {
        let mut state = MicroState::zeroed();
        assert!(state.find_socket_fd(5).is_none());
        assert!(state.register_socket_fd(5, 0x800000));
        let offset = state.find_socket_fd(5).unwrap();
        assert_eq!(offset, 0x800000);
    }

    #[test]
    fn socket_fd_unregister() {
        let mut state = MicroState::zeroed();
        state.register_socket_fd(5, 0x800000);
        assert!(state.unregister_socket_fd(5));
        assert!(state.find_socket_fd(5).is_none());
        assert!(!state.unregister_socket_fd(5)); // already removed
    }

    #[test]
    fn socket_fd_table_full() {
        let mut state = MicroState::zeroed();
        for i in 0..litebox_ipc::ring::MAX_SOCKET_SLOTS {
            assert!(state.register_socket_fd(i as i32, (i * 0x1000) as u32));
        }
        // Table is full — next registration should fail.
        assert!(!state.register_socket_fd(999, 0xDEAD));
        assert!(state.find_socket_fd(999).is_none());
    }
}
