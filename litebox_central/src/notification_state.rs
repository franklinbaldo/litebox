// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Per-process state tracked from Tier 2 fire-and-forget notifications.
//!
//! Central records these so it can reconstruct guest-visible state when
//! forking micro.

use litebox_ipc::ring::MAX_THREADS;

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

/// Pipe created by micro via MSG_NOTIFY_PIPE2.
#[derive(Clone, Copy)]
#[allow(dead_code)] // Fields read during fork reconstruction (future task).
pub(crate) struct MicroPipe {
    pub read_fd: i32,
    pub write_fd: i32,
    pub flags: i32,
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

    /// Pipes created by micro (not tracked in shim's fdtable).
    pub micro_pipes: Vec<MicroPipe>,

    /// Children reaped by micro via wait4: (pid, exit_status).
    pub reaped_children: Vec<(i32, i32)>,
}

impl Default for ProcessNotificationState {
    fn default() -> Self {
        Self {
            signal_actions: [None; 64],
            signal_masks: [0; MAX_THREADS],
            alt_stacks: [None; MAX_THREADS],
            alarm_seconds: 0,
            micro_pipes: Vec::new(),
            reaped_children: Vec::new(),
        }
    }
}
