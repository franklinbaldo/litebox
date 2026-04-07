// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Process-related syscall handlers for the macOS shim.

use alloc::ffi::CString;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::{ConstPtr, ShimFS, Task};
use litebox::platform::RawConstPointer as _;
use litebox_common_macos::PtRegs;
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

    /// Handle `getppid()` — return parent process ID.
    ///
    /// Litebox runs a single process, so we return 1 (init).
    pub(crate) fn sys_getppid(&self) -> i32 {
        1
    }

    /// Handle `umask(cmask)` — set and return previous file creation mask.
    pub(crate) fn sys_umask(&self, cmask: u32) -> u32 {
        use core::sync::atomic::Ordering;
        self.process.umask.swap(cmask & 0o777, Ordering::Relaxed)
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

    /// Handle `getrlimit(resource, rlim)`.
    pub(crate) fn sys_getrlimit(&self, resource: u32, rlim_addr: usize) -> Result<usize, Errno> {
        use crate::MutPtr;
        use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
        use litebox_common_macos::{Rlimit, RlimitResource};

        let res = RlimitResource::from_raw(resource).ok_or(Errno::EINVAL)?;
        let lim = *self.process.rlimits[res as usize].lock();
        let ptr: MutPtr<Rlimit> = MutPtr::from_usize(rlim_addr);
        ptr.write_at_offset(0, lim).ok_or(Errno::EFAULT)?;
        Ok(0)
    }

    /// Handle `setrlimit(resource, rlim)`.
    pub(crate) fn sys_setrlimit(&self, resource: u32, rlim_addr: usize) -> Result<usize, Errno> {
        use crate::ConstPtr;
        use litebox::platform::RawConstPointer as _;
        use litebox_common_macos::{Rlimit, RlimitResource};

        let res = RlimitResource::from_raw(resource).ok_or(Errno::EINVAL)?;
        let ptr: ConstPtr<Rlimit> = ConstPtr::from_usize(rlim_addr);
        let new_lim: Rlimit = ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;

        // Soft limit must not exceed hard limit.
        if new_lim.rlim_cur > new_lim.rlim_max {
            return Err(Errno::EINVAL);
        }
        // Cannot raise hard limit (no CAP_SYS_RESOURCE equivalent).
        let mut stored = self.process.rlimits[res as usize].lock();
        if new_lim.rlim_max > stored.rlim_max {
            return Err(Errno::EPERM);
        }
        *stored = new_lim;
        Ok(0)
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

    /// Handle `execve(path, argv, envp)` (BSD syscall 59).
    ///
    /// Replaces the current process image with a new program:
    /// 1. Copy path, argv, envp from guest memory.
    /// 2. Read the executable from the virtual filesystem.
    /// 3. Kill all other threads in the process.
    /// 4. Release existing memory mappings.
    /// 5. Reset signal handlers to defaults, clear altstack.
    /// 6. Close CLOEXEC file descriptors.
    /// 7. Load the new Mach-O binary.
    /// 8. Reset registers to the new entry point.
    ///
    /// On success, `ctx` is rewritten to the new program's entry point
    /// and this returns `Ok(())`.  The caller must NOT call
    /// `set_syscall_return` after a successful execve.
    #[allow(clippy::cast_sign_loss, clippy::too_many_lines)]
    pub(crate) fn sys_execve(
        &self,
        path_addr: usize,
        argv_addr: usize,
        envp_addr: usize,
        ctx: &mut PtRegs,
    ) -> Result<(), Errno> {
        // ── 1. Copy path, argv, envp from guest memory ──

        let path_ptr: ConstPtr<u8> = ConstPtr::from_usize(path_addr);
        let path_str =
            crate::syscalls::file::read_cstring_from_guest(path_ptr, 4096).ok_or(Errno::EFAULT)?;

        let argv_vec = self.copy_user_string_array(argv_addr)?;
        let envp_vec = self.copy_user_string_array(envp_addr)?;

        // ── 2. Read the executable from the virtual filesystem ──

        let cpath = CString::new(path_str.as_bytes()).map_err(|_| Errno::EINVAL)?;
        let typed_fd = self
            .global
            .fs
            .open(
                &cpath,
                litebox::fs::OFlags::RDONLY,
                litebox::fs::Mode::empty(),
            )
            .map_err(|_| Errno::ENOENT)?;

        let stat = self
            .global
            .fs
            .fd_file_status(&typed_fd)
            .map_err(|_| Errno::EIO)?;
        let file_size = stat.size;

        let mut program_bytes = alloc::vec![0u8; file_size];
        let mut total_read = 0;
        while total_read < file_size {
            let n = self
                .global
                .fs
                .read(
                    &typed_fd,
                    &mut program_bytes[total_read..],
                    Some(total_read),
                )
                .map_err(|_| Errno::EIO)?;
            if n == 0 {
                break;
            }
            total_read += n;
        }
        let _ = self.global.fs.close(&typed_fd);

        // ── 3. Signal other threads to terminate ──
        //
        // In a single-threaded process (the common case for execve in
        // litebox), this is a no-op. For multi-threaded, we set
        // group_exit which causes other threads to notice and exit in
        // their next enter_shim() call.
        self.process.group_exit.store(true, Ordering::Release);
        // Wait briefly for other threads. In the litebox model, spawned
        // threads check should_terminate() on each shim entry, so they
        // will exit promptly.
        // NOTE: a full implementation would block here until nr_threads == 1.
        // For now we proceed optimistically (the guest should be single-threaded
        // at execve time in typical usage).

        // ── 4. Release existing memory mappings ──

        // Preserve only the shared cache — it is host-mapped memory that
        // must survive across execve.  dyld is NOT preserved: it will be
        // freshly re-loaded by load_macho (matching real macOS kernel
        // behavior where dyld is mapped from disk with pristine __DATA
        // segments on every execve).
        #[allow(clippy::cast_possible_truncation)]
        let cache_base = self.global.shared_cache_base.load(Ordering::Acquire) as usize;
        #[allow(clippy::cast_possible_truncation)]
        let cache_end = self.global.shared_cache_end.load(Ordering::Acquire) as usize;
        let release = |range: core::ops::Range<usize>, vm: litebox::mm::linux::VmFlags| {
            if vm.is_empty() {
                return false;
            }
            // Skip any mapping that overlaps with the shared cache region.
            if cache_base != 0 && range.start < cache_end && range.end > cache_base {
                return false;
            }
            true
        };
        unsafe {
            self.global
                .pm
                .release_memory(release)
                .map_err(|_| Errno::ENOMEM)?;
        }

        // ── 5. Reset signal handlers to defaults ──
        {
            let mut handlers = self.process.signal_handlers.lock();
            for h in handlers.iter_mut() {
                *h = crate::SignalHandler::default();
            }
        }
        // Clear the per-thread signal mask and altstack.
        self.blocked_signals.store(0, Ordering::Relaxed);
        {
            let mut alt = self.altstack.lock();
            *alt = litebox_common_macos::SigAltStack::DISABLED;
        }

        // ── 6. Close CLOEXEC file descriptors ──
        // TODO: close CLOEXEC descriptors. RawDescriptorStorage does not
        // currently track the CLOEXEC flag, so we skip this step for now.
        // In practice, most litebox guests do not rely on CLOEXEC semantics
        // across execve.

        // ── 7. Load the new Mach-O binary ──
        //
        // Reset group_exit since we're now running the new program.
        self.process.group_exit.store(false, Ordering::Release);

        let load_info = crate::loader::load_macho(self, &program_bytes, argv_vec, envp_vec, None)
            .map_err(|e| {
            log_unsupported!("execve: Mach-O load failed: {}", e);
            Errno::ENOEXEC
        })?;

        // ── 8. Reset registers to the new entry point ──

        *ctx = PtRegs::default();
        ctx.pc = load_info.entry_point;
        ctx.sp = load_info.user_stack_top;

        if load_info.is_lc_main {
            // LC_MAIN: argc, argv, envp, apple passed in x0–x3.
            // The stack layout is: [argc, argv[0..n], NULL, envp[0..m], NULL, apple[0..], NULL].
            // argc is at [sp], argv at sp+8, etc.
            let sp = load_info.user_stack_top;
            let argc_ptr: ConstPtr<usize> = ConstPtr::from_usize(sp);
            if let Some(argc) = argc_ptr.read_at_offset(0) {
                ctx.regs[0] = argc; // x0 = argc
                ctx.regs[1] = sp + 8; // x1 = &argv[0]
                // envp = argv + argc + 1 (skip NULL terminator)
                ctx.regs[2] = sp + 8 + (argc + 1) * 8; // x2 = &envp[0]
                // apple = after envp NULL terminator — skip to find it
                let envp_start = ctx.regs[2];
                let mut apple_ptr_addr = envp_start;
                for _ in 0..1024 {
                    let envp_entry: ConstPtr<usize> = ConstPtr::from_usize(apple_ptr_addr);
                    if let Some(0) = envp_entry.read_at_offset(0) {
                        apple_ptr_addr += 8; // skip past the NULL
                        break;
                    }
                    apple_ptr_addr += 8;
                }
                ctx.regs[3] = apple_ptr_addr; // x3 = apple
            }
        }
        // For LC_UNIXTHREAD, the stack is already set up by the loader and
        // we jump directly to the entry point with no register arguments.

        if load_info.has_dylinker {
            // The entry point is dyld's entry, which will find the main
            // binary's entry via the Mach-O headers already loaded in memory.
        }

        Ok(())
    }

    /// Read a NULL-terminated array of C string pointers from guest memory.
    fn copy_user_string_array(&self, base_addr: usize) -> Result<Vec<CString>, Errno> {
        const MAX_ENTRIES: usize = 4096;
        const MAX_TOTAL_BYTES: usize = 2 * 1024 * 1024; // 2 MiB

        if base_addr == 0 {
            return Ok(Vec::new());
        }
        let mut result = Vec::new();
        let mut ptr_addr = base_addr;
        let mut total = 0usize;

        for _ in 0..MAX_ENTRIES {
            let entry_ptr: ConstPtr<usize> = ConstPtr::from_usize(ptr_addr);
            let str_addr = entry_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
            if str_addr == 0 {
                break; // NULL terminator
            }
            let str_ptr: ConstPtr<u8> = ConstPtr::from_usize(str_addr);
            let s = crate::syscalls::file::read_cstring_from_guest(str_ptr, 4096)
                .ok_or(Errno::EFAULT)?;
            total += s.len() + 1;
            if total > MAX_TOTAL_BYTES {
                return Err(Errno::E2BIG);
            }
            let cs = CString::new(s.into_bytes()).map_err(|_| Errno::EINVAL)?;
            result.push(cs);
            ptr_addr += core::mem::size_of::<usize>();
        }
        Ok(result)
    }
}
