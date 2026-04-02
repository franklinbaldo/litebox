// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Process-related syscall handlers for the macOS shim.

use core::sync::atomic::Ordering;

use crate::{ShimFS, Task};

impl<FS: ShimFS> Task<FS> {
    /// Handle `exit(status)` — mark the task as terminated and record the exit code.
    pub(crate) fn sys_exit(&self, status: i32) {
        self.exit_code.store(status, Ordering::Release);
        self.terminated.set(true);
    }

    /// Handle `getpid()` — return a fixed PID (single-process phase 1).
    pub(crate) fn sys_getpid(&self) -> i32 {
        1
    }

    /// Handle `getuid()`.
    pub(crate) fn sys_getuid(&self) -> u32 {
        0
    }

    /// Handle `geteuid()`.
    pub(crate) fn sys_geteuid(&self) -> u32 {
        0
    }

    /// Handle `getgid()`.
    pub(crate) fn sys_getgid(&self) -> u32 {
        0
    }

    /// Handle `getegid()`.
    pub(crate) fn sys_getegid(&self) -> u32 {
        0
    }

    /// Handle `issetugid()` — always returns 0 (not setuid/setgid).
    pub(crate) fn sys_issetugid(&self) -> i32 {
        0
    }
}
