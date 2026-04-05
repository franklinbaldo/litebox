// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Process-related syscall handlers for the macOS shim.

use core::sync::atomic::Ordering;

use crate::{ShimFS, Task};
use litebox_common_macos::errno::Errno;

impl<FS: ShimFS> Task<FS> {
    /// Handle `exit(status)` — mark the task as terminated and record the exit code.
    pub(crate) fn sys_exit(&self, status: i32) {
        self.process.exit_code.store(status, Ordering::Release);
        self.process.group_exit.store(true, Ordering::Release);
        self.terminated.store(true, Ordering::Release);
    }

    /// Handle `getpid()` — return a fixed PID.
    ///
    /// We use PID 42 instead of PID 1 because macOS dyld treats PID 1
    /// as the init process (launchd) and triggers the libignition boot
    /// sequence, which fails in the emulated environment and causes dyld
    /// to fall into a simulator fallback code path.
    pub(crate) fn sys_getpid(&self) -> i32 {
        42
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

    /// Handle `gettimeofday(tv, tz)` — return wall-clock time.
    #[allow(clippy::similar_names)]
    pub(crate) fn sys_gettimeofday(&self, tv_addr: usize, tz_addr: usize) -> Result<usize, Errno> {
        use crate::MutPtr;
        use litebox::platform::{
            RawConstPointer as _, RawMutPointer as _, SystemTime, TimeProvider,
        };

        if tv_addr != 0 {
            let system_time = <_ as TimeProvider>::current_time(self.global.platform);
            let duration = SystemTime::duration_since(
                &system_time,
                &<<crate::Platform as TimeProvider>::SystemTime as SystemTime>::UNIX_EPOCH,
            )
            .map_err(|_| Errno::EINVAL)?;
            #[allow(clippy::cast_possible_wrap)]
            let tv_sec = duration.as_secs() as i64;
            #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
            let tv_usec = duration.subsec_micros() as i32;
            let sec_ptr: MutPtr<i64> = MutPtr::from_usize(tv_addr);
            sec_ptr.write_at_offset(0, tv_sec).ok_or(Errno::EFAULT)?;
            let usec_ptr: MutPtr<i32> = MutPtr::from_usize(tv_addr + 8);
            usec_ptr.write_at_offset(0, tv_usec).ok_or(Errno::EFAULT)?;
        }
        if tz_addr != 0 {
            // Timezone is obsolete. Zero out the 8-byte struct timezone.
            let tz_ptr: MutPtr<u64> = MutPtr::from_usize(tz_addr);
            tz_ptr.write_at_offset(0, 0u64).ok_or(Errno::EFAULT)?;
        }
        Ok(0)
    }

    /// Handle `__getcwd(buf, size)` — return current working directory.
    pub(crate) fn sys_getcwd(&self, buf_addr: usize, size: usize) -> Result<usize, Errno> {
        use crate::MutPtr;
        use litebox::platform::{RawConstPointer as _, RawMutPointer as _};

        // Always "/" — no chdir support yet.
        if size < 2 {
            return Err(Errno::ERANGE);
        }
        let ptr: MutPtr<u8> = MutPtr::from_usize(buf_addr);
        ptr.copy_from_slice(0, b"/\0").ok_or(Errno::EFAULT)?;
        Ok(0) // macOS __getcwd returns 0 on success
    }
}
