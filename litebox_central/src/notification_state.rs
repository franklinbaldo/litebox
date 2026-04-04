// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Per-process state tracked from Tier 2 fire-and-forget notifications.
//!
//! Central records these so it can reconstruct guest-visible state when
//! forking micro.

use litebox_ipc::ring::{
    MAX_PIPE_SLOTS, MAX_SOCKET_SLOTS, MAX_THREADS, PIPE_SLOT_SIZE, PIPE_ZONE_BASE_OFFSET,
    SOCKET_SLOT_SIZE, SOCKET_ZONE_BASE_OFFSET,
};

/// A VMA change event recorded from a Tier 2 notification.
/// Used as an event log for fork/CoW reconstruction.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)] // Fields read during fork reconstruction (future task).
pub(crate) enum VmaEvent {
    Mmap { addr: u64, len: u64, prot: u32 },
    Munmap { addr: u64, len: u64 },
    Mprotect { addr: u64, len: u64, prot: u32 },
    Madvise { addr: u64, len: u64, advice: u32 },
}

/// Signal action as reported by micro via MSG_NOTIFY_SIGACTION.
#[derive(Clone, Copy, Default)]
#[allow(dead_code)] // Fields read during fork reconstruction (future task).
pub(crate) struct SignalAction {
    pub handler: u64,
    pub flags: u64,
    pub mask: u64,
}

/// Alternate signal stack as reported by micro via MSG_NOTIFY_SIGALTSTACK.
#[derive(Clone, Copy, Default)]
#[allow(dead_code)] // Fields read during fork reconstruction (future task).
pub(crate) struct AltStack {
    pub sp: u64,
    pub size: u64,
    pub flags: u64,
}

/// A shmem-backed pipe tracked by central.
#[derive(Clone, Copy)]
pub(crate) struct ShmemPipe {
    pub read_fd: i32,
    pub write_fd: i32,
    /// Slot index in the pipe zone (0..MAX_PIPE_SLOTS).
    pub slot_index: u8,
    /// Reference count: how many fd endpoints are still open (0, 1, or 2).
    pub open_ends: u8,
}

/// Tracking info for a shmem-backed socket.
#[derive(Clone, Copy)]
pub(crate) struct ShmemSocket {
    /// Guest fd number.
    pub fd: i32,
    /// Slot index in the socket zone (0..MAX_SOCKET_SLOTS).
    pub slot_index: u8,
}

/// Per-process notification state.
///
/// Updated by central's notification handler when it receives Tier 2
/// fire-and-forget messages from micro. Used for fork reconstruction.
pub(crate) struct ProcessNotificationState {
    /// Signal disposition table (indexed by signal number, 0-63).
    pub signal_actions: [Option<SignalAction>; 64],

    /// Per-thread signal mask (indexed by thread_slot).
    pub signal_masks: [u64; MAX_THREADS],

    /// Per-thread alternate signal stack.
    pub alt_stacks: [Option<AltStack>; MAX_THREADS],

    /// Pending alarm in seconds, or 0 if none.
    pub alarm_seconds: u32,

    /// Children reaped by micro via wait4: (pid, exit_status).
    pub reaped_children: Vec<(i32, i32)>,

    /// VMA change events (munmap, mprotect, madvise) from Tier 2 notifications.
    pub vma_events: Vec<VmaEvent>,

    /// Shmem pipe slot allocation bitset. Bit N = 1 means slot N is in use.
    pub pipe_slot_bitset: u64,

    /// Active shmem-backed pipes.
    pub shmem_pipes: Vec<ShmemPipe>,

    /// Shmem socket slot allocation bitset. Bit N = 1 means slot N is in use.
    pub socket_slot_bitset: u64,

    /// Active shmem-backed sockets.
    pub shmem_sockets: Vec<ShmemSocket>,
}

impl Default for ProcessNotificationState {
    fn default() -> Self {
        Self {
            signal_actions: [None; 64],
            signal_masks: [0; MAX_THREADS],
            alt_stacks: [None; MAX_THREADS],
            alarm_seconds: 0,
            reaped_children: Vec::new(),
            vma_events: Vec::new(),
            pipe_slot_bitset: 0,
            shmem_pipes: Vec::new(),
            socket_slot_bitset: 0,
            shmem_sockets: Vec::new(),
        }
    }
}

impl ProcessNotificationState {
    /// Allocate a free pipe slot. Returns the slot index and data-region offset.
    pub fn alloc_pipe_slot(&mut self) -> Option<(u8, u32)> {
        if self.pipe_slot_bitset == u64::MAX {
            return None; // all 64 bits set (though only 47 are valid)
        }
        let free_bit = self.pipe_slot_bitset.trailing_ones();
        if free_bit as usize >= MAX_PIPE_SLOTS {
            return None;
        }
        self.pipe_slot_bitset |= 1u64 << free_bit;
        let offset = PIPE_ZONE_BASE_OFFSET + (free_bit as usize) * PIPE_SLOT_SIZE;
        #[allow(clippy::cast_possible_truncation)]
        Some((free_bit as u8, offset as u32))
    }

    /// Free a pipe slot.
    pub fn free_pipe_slot(&mut self, slot_index: u8) {
        self.pipe_slot_bitset &= !(1u64 << slot_index);
    }

    /// Find a shmem pipe by fd (either read or write end).
    #[allow(dead_code)] // Used when pipe read/write handlers are wired up (future task).
    pub fn find_shmem_pipe(&self, fd: i32) -> Option<&ShmemPipe> {
        self.shmem_pipes
            .iter()
            .find(|p| p.read_fd == fd || p.write_fd == fd)
    }

    /// Find a mutable shmem pipe by fd.
    pub fn find_shmem_pipe_mut(&mut self, fd: i32) -> Option<&mut ShmemPipe> {
        self.shmem_pipes
            .iter_mut()
            .find(|p| p.read_fd == fd || p.write_fd == fd)
    }

    /// Allocate a free socket slot. Returns the slot index and data-region offset.
    pub fn alloc_socket_slot(&mut self) -> Option<(u8, u32)> {
        if self.socket_slot_bitset == u64::MAX {
            return None;
        }
        let free_bit = self.socket_slot_bitset.trailing_ones();
        if free_bit as usize >= MAX_SOCKET_SLOTS {
            return None;
        }
        self.socket_slot_bitset |= 1u64 << free_bit;
        let offset = SOCKET_ZONE_BASE_OFFSET + (free_bit as usize) * SOCKET_SLOT_SIZE;
        #[allow(clippy::cast_possible_truncation)]
        Some((free_bit as u8, offset as u32))
    }

    /// Free a socket slot.
    pub fn free_socket_slot(&mut self, slot_index: u8) {
        debug_assert!(
            (slot_index as usize) < MAX_SOCKET_SLOTS,
            "slot_index {slot_index} out of range (max {MAX_SOCKET_SLOTS})"
        );
        self.socket_slot_bitset &= !(1u64 << slot_index);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_pipe_slot_returns_sequential_indices() {
        let mut state = ProcessNotificationState::default();
        let (idx0, off0) = state.alloc_pipe_slot().unwrap();
        let (idx1, off1) = state.alloc_pipe_slot().unwrap();
        assert_eq!(idx0, 0);
        assert_eq!(idx1, 1);
        assert_eq!(off0 as usize, PIPE_ZONE_BASE_OFFSET);
        assert_eq!(off1 as usize, PIPE_ZONE_BASE_OFFSET + PIPE_SLOT_SIZE);
    }

    #[test]
    fn free_pipe_slot_allows_reuse() {
        let mut state = ProcessNotificationState::default();
        let (idx, _) = state.alloc_pipe_slot().unwrap();
        state.free_pipe_slot(idx);
        let (idx2, _) = state.alloc_pipe_slot().unwrap();
        assert_eq!(idx, idx2); // reused
    }

    #[test]
    fn alloc_pipe_slot_exhaustion() {
        let mut state = ProcessNotificationState::default();
        for _ in 0..MAX_PIPE_SLOTS {
            assert!(state.alloc_pipe_slot().is_some());
        }
        assert!(state.alloc_pipe_slot().is_none()); // full
    }

    #[test]
    fn alloc_socket_slot_returns_sequential_indices() {
        let mut state = ProcessNotificationState::default();
        let (idx0, off0) = state.alloc_socket_slot().unwrap();
        let (idx1, off1) = state.alloc_socket_slot().unwrap();
        assert_eq!(idx0, 0);
        assert_eq!(idx1, 1);
        assert_eq!(off0 as usize, SOCKET_ZONE_BASE_OFFSET);
        assert_eq!(off1 as usize, SOCKET_ZONE_BASE_OFFSET + SOCKET_SLOT_SIZE);
    }

    #[test]
    fn free_socket_slot_allows_reuse() {
        let mut state = ProcessNotificationState::default();
        let (idx, _) = state.alloc_socket_slot().unwrap();
        state.free_socket_slot(idx);
        let (idx2, _) = state.alloc_socket_slot().unwrap();
        assert_eq!(idx, idx2); // reused
    }

    #[test]
    fn alloc_socket_slot_exhaustion() {
        let mut state = ProcessNotificationState::default();
        for _ in 0..MAX_SOCKET_SLOTS {
            assert!(state.alloc_socket_slot().is_some());
        }
        assert!(state.alloc_socket_slot().is_none()); // full
    }
}
