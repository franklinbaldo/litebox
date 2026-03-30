// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! IPC control message types that share the SQ/CQ ring alongside raw syscalls.
//!
//! Control messages use `syscall_nr` values at or above [`MSG_BASE`]
//! (`0x8000_0000`) to avoid collisions with real Linux syscall numbers.

/// Base value for control message IDs.
///
/// All control messages have `syscall_nr >= MSG_BASE`.
pub const MSG_BASE: u32 = 0x8000_0000;

/// Register a new guest thread with central.
///
/// **SQ args:**
/// - `args[0]`: requested thread slot index (or `u64::MAX` for auto-assign).
///
/// **CQ result:**
/// - `result`: assigned thread slot index on success, or negated errno on
///   failure.
pub const MSG_THREAD_REGISTER: u32 = MSG_BASE;

/// De-register a guest thread from central.
///
/// **SQ args:**
/// - `args[0]`: thread slot index to release.
///
/// **CQ result:**
/// - `result`: 0 on success, or negated errno on failure.
pub const MSG_THREAD_DEREGISTER: u32 = MSG_BASE + 1;

/// Notify central of the result of a `fork()` performed in the guest.
///
/// **SQ args:**
/// - `args[0]`: child PID (or 0 if fork failed).
/// - `args[1]`: errno if fork failed.
///
/// **CQ result:**
/// - `result`: 0 on acknowledgement.
pub const MSG_FORK_RESULT: u32 = MSG_BASE + 2;

/// Signal from a child process that it has finished initialising after fork.
///
/// **SQ args:**
/// - `args[0]`: child PID.
///
/// **CQ result:**
/// - `result`: 0 on acknowledgement.
pub const MSG_CHILD_READY: u32 = MSG_BASE + 3;

/// Report the result of a locally-executed syscall back to central.
///
/// Sent by micro-LiteBox after executing a syscall that central authorized
/// for local execution (e.g., mmap, munmap, mprotect). Central uses this
/// to keep its state (page table metadata, etc.) consistent.
///
/// **SQ args:**
/// - `args[0]`: original SQ sequence number this is reporting on.
/// - `args[1]`: syscall return value (or negated errno on failure).
///
/// **CQ result:**
/// - `result`: 0 on acknowledgement (central recorded the result).
pub const MSG_LOCAL_RESULT: u32 = MSG_BASE + 4;

/// Micro signals readiness for the next execve data chunk.
///
/// **SQ args:**
/// - `args[0]`: chunk index being requested.
///
/// **CQ result:**
/// - Contains chunk data in the data region (HAS_DATA flag set).
pub const MSG_EXECVE_READY: u32 = MSG_BASE + 5;

/// Notification: micro executed rt_sigaction locally.
/// args[0] = signum, args[1] = handler address, args[2] = sa_flags,
/// args[3] = sa_mask, args[4] = result (0 or -errno).
pub const MSG_NOTIFY_SIGACTION: u32 = MSG_BASE + 6;

/// Notification: micro executed rt_sigprocmask locally.
/// args[0] = how (SIG_BLOCK/UNBLOCK/SETMASK), args[1] = new mask bits,
/// args[2] = result.
pub const MSG_NOTIFY_SIGPROCMASK: u32 = MSG_BASE + 7;

/// Notification: micro executed sigaltstack locally.
/// args[0] = ss_sp, args[1] = ss_size, args[2] = ss_flags, args[3] = result.
pub const MSG_NOTIFY_SIGALTSTACK: u32 = MSG_BASE + 8;

/// Notification: micro executed alarm locally.
/// args[0] = seconds requested, args[1] = return value (remaining seconds).
pub const MSG_NOTIFY_ALARM: u32 = MSG_BASE + 9;

/// Notification: micro executed pipe2 locally.
/// args[0] = fd[0] (read end), args[1] = fd[1] (write end),
/// args[2] = flags, args[3] = result (0 or -errno).
pub const MSG_NOTIFY_PIPE2: u32 = MSG_BASE + 10;

/// Notification: micro executed wait4 locally.
/// args[0] = pid arg, args[1] = returned pid (or -errno),
/// args[2] = status, args[3] = options.
pub const MSG_NOTIFY_WAIT4: u32 = MSG_BASE + 11;

/// Notification: micro executed munmap locally.
/// args[0] = addr, args[1] = len, args[2] = result (0 or -errno).
pub const MSG_NOTIFY_MUNMAP: u32 = MSG_BASE + 12;

/// Notification: micro executed mprotect locally.
/// args[0] = addr, args[1] = len, args[2] = prot, args[3] = result (0 or -errno).
pub const MSG_NOTIFY_MPROTECT: u32 = MSG_BASE + 13;

/// Notification: micro executed madvise locally.
/// args[0] = addr, args[1] = len, args[2] = advice, args[3] = result (0 or -errno).
pub const MSG_NOTIFY_MADVISE: u32 = MSG_BASE + 14;

/// Returns `true` if `syscall_nr` is a control message (>= [`MSG_BASE`])
/// rather than a real Linux syscall number.
pub const fn is_control_message(syscall_nr: u32) -> bool {
    syscall_nr >= MSG_BASE
}
