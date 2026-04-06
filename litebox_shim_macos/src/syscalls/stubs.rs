// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Stub syscall handlers for macOS shim Phase 2.
//!
//! These handlers provide minimal implementations sufficient for dyld
//! bootstrap and hello.c execution.

use alloc::boxed::Box;
use litebox::platform::{
    Instant as _, RawConstPointer as _, RawMutPointer as _, ThreadProvider as _, TimeProvider as _,
};
use litebox_common_macos::errno::Errno;
use litebox_common_macos::syscall::mach_trap;
use litebox_common_macos::PtRegs;

use crate::{MutPtr, ShimFS, Task};

impl<FS: ShimFS> Task<FS> {
    /// Handle `madvise()` — stub: return success.
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn sys_madvise(
        &self,
        _addr: usize,
        _length: usize,
        _advice: i32,
    ) -> Result<usize, Errno> {
        Ok(0)
    }

    /// Handle `csops()` — stub: return success (not code-signed).
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn sys_csops(
        &self,
        _pid: i32,
        _ops: u32,
        _useraddr: usize,
        _usersize: usize,
    ) -> Result<usize, Errno> {
        Ok(0)
    }

    /// Handle `shared_region_check_np()` — return cache base if installed, EINVAL otherwise.
    pub(crate) fn sys_shared_region_check_np(&self, start_address: usize) -> Result<usize, Errno> {
        let base = self
            .global
            .shared_cache_base
            .load(core::sync::atomic::Ordering::Acquire);
        if base != 0 {
            // Guard: skip writing to clearly invalid pointers (e.g. 0xFFFF...) that
            // would crash the host via TransparentMutPtr's unchecked write.  The dead
            // code in dyld's `start()` (which runs after `restartWithDyldInCache`
            // returns) calls `shared_region_check_np(0xFFFFFFFFFFFFFFFF)`.  Returning
            // EFAULT makes the dead code think no cache exists, triggering assertion
            // failures in shared cache libraries.  Returning success (without writing)
            // keeps the code on the "cache is installed" path.
            if start_address > 0x0000_7FFF_FFFF_FFF8 {
                log_unsupported!(
                    "shared_region_check_np: invalid address {:#x}, skipping write but returning success (cache at {:#x})",
                    start_address,
                    base,
                );
                return Ok(0);
            }
            let ptr: MutPtr<u64> = MutPtr::from_usize(start_address);
            ptr.write_at_offset(0, base).ok_or(Errno::EFAULT)?;
            log_unsupported!("shared_region_check_np: cache installed at {:#x}", base);
            Ok(0)
        } else {
            log_unsupported!("shared_region_check_np: no cache installed, returning EINVAL");
            Err(Errno::EINVAL)
        }
    }

    /// Handle `getentropy()` — fill buffer with cryptographically random bytes.
    pub(crate) fn sys_getentropy(&self, buf_addr: usize, count: usize) -> Result<usize, Errno> {
        if count > 256 {
            return Err(Errno::EIO);
        }
        let mut kbuf = [0u8; 256];
        <_ as litebox::platform::CrngProvider>::fill_bytes_crng(
            self.global.platform,
            &mut kbuf[..count],
        );
        let dest: MutPtr<u8> = MutPtr::from_usize(buf_addr);
        dest.copy_from_slice(0, &kbuf[..count])
            .ok_or(Errno::EFAULT)?;
        Ok(0)
    }

    /// Handle `sysctl()` — return ENOENT for most queries, log the name.
    pub(crate) fn sys_sysctl(
        &self,
        name: usize,
        namelen: u32,
        _old: usize,
        _oldlenp: usize,
        new_val: usize,
        newlen: usize,
    ) -> Result<usize, Errno> {
        // Log the sysctl name integers for debugging.
        let name_ptr: crate::ConstPtr<i32> = crate::ConstPtr::from_usize(name);
        let mut name_ints = alloc::vec::Vec::new();
        for i in 0..namelen.min(6) {
            #[allow(clippy::cast_possible_wrap)]
            if let Some(val) = name_ptr.read_at_offset(i as isize) {
                name_ints.push(val);
            }
        }
        log_unsupported!(
            "sysctl(name={name_ints:?}, namelen={namelen}, new_val={new_val:#x}, newlen={newlen})"
        );
        // If name=[0,3] (sysctl name2oid), log the string name from new_val.
        if name_ints.len() >= 2
            && name_ints[0] == 0
            && name_ints[1] == 3
            && new_val != 0
            && newlen > 0
        {
            let str_ptr: crate::ConstPtr<u8> = crate::ConstPtr::from_usize(new_val);
            // The sysctl name2oid `newlen` is the string length WITHOUT the NUL
            // terminator. We pass `newlen + 1` so `read_cstring_from_guest` can
            // find the NUL byte at position `newlen`.
            if let Some(s) =
                crate::syscalls::file::read_cstring_from_guest(str_ptr, (newlen + 1).min(256))
            {
                log_unsupported!("sysctl name2oid({s:?})");
            } else {
                log_unsupported!(
                    "sysctl name2oid: failed to read string at {new_val:#x} len={newlen}"
                );
            }
        } else {
            log_unsupported!("sysctl(name={name_ints:?}, namelen={namelen})");
        }
        Err(Errno::ENOENT)
    }

    /// Handle `ioctl()` — return ENOTTY for all requests.
    pub(crate) fn sys_ioctl(&self, _fd: i32, _request: usize, _arg: usize) -> Result<usize, Errno> {
        Err(Errno::ENOTTY)
    }

    /// Handle `statfs64(path, buf)` — return a fake filesystem stat.
    ///
    /// dyld calls `statfs64("/", ...)` during ignition to check the root
    /// filesystem type. We fill the buffer with plausible values.
    pub(crate) fn sys_statfs64(&self, _path: usize, buf: usize) -> Result<usize, Errno> {
        // macOS struct statfs (2168 bytes = 0x878):
        //   uint32_t  f_bsize       (offset 0x00)  - block size
        //   int32_t   f_iosize      (offset 0x04)  - optimal I/O size
        //   uint64_t  f_blocks      (offset 0x08)  - total blocks
        //   uint64_t  f_bfree       (offset 0x10)  - free blocks
        //   uint64_t  f_bavail      (offset 0x18)  - available blocks
        //   uint64_t  f_files       (offset 0x20)  - total file nodes
        //   uint64_t  f_ffree       (offset 0x28)  - free file nodes
        //   fsid_t    f_fsid        (offset 0x30)  - 8 bytes
        //   uid_t     f_owner       (offset 0x38)  - 4 bytes
        //   uint32_t  f_type        (offset 0x3c)  - type of filesystem
        //   uint32_t  f_flags       (offset 0x40)  - mount flags
        //   uint32_t  f_fssubtype   (offset 0x44)  - subtype
        //   char      f_fstypename[16]   (offset 0x48)
        //   char      f_mntonname[1024]  (offset 0x58)
        //   char      f_mntfromname[1024](offset 0x458)
        //   uint32_t  f_flags_ext   (offset 0x858)
        //   uint32_t  f_reserved[7] (offset 0x85c)
        const STATFS_SIZE: usize = 0x878;

        // Zero-fill the entire struct first.
        let zeros = alloc::vec![0u8; STATFS_SIZE];
        let dest: MutPtr<u8> = MutPtr::from_usize(buf);
        dest.copy_from_slice(0, &zeros).ok_or(Errno::EFAULT)?;

        // Fill in plausible values.
        let buf32: MutPtr<u32> = MutPtr::from_usize(buf);
        buf32.write_at_offset(0, 4096).ok_or(Errno::EFAULT)?; // f_bsize = 4096
        buf32.write_at_offset(1, 4096).ok_or(Errno::EFAULT)?; // f_iosize = 4096

        let buf64: MutPtr<u64> = MutPtr::from_usize(buf);
        buf64.write_at_offset(1, 1_000_000).ok_or(Errno::EFAULT)?; // f_blocks
        buf64.write_at_offset(2, 500_000).ok_or(Errno::EFAULT)?; // f_bfree
        buf64.write_at_offset(3, 500_000).ok_or(Errno::EFAULT)?; // f_bavail
        buf64.write_at_offset(4, 100_000).ok_or(Errno::EFAULT)?; // f_files
        buf64.write_at_offset(5, 50_000).ok_or(Errno::EFAULT)?; // f_ffree

        // f_fstypename at offset 0x48: "apfs\0"
        let fstypename = b"apfs\0";
        let fstypename_dest: MutPtr<u8> = MutPtr::from_usize(buf + 0x48);
        fstypename_dest
            .copy_from_slice(0, fstypename)
            .ok_or(Errno::EFAULT)?;

        // f_mntonname at offset 0x58: "/\0"
        let mntonname = b"/\0";
        let mntonname_dest: MutPtr<u8> = MutPtr::from_usize(buf + 0x58);
        mntonname_dest
            .copy_from_slice(0, mntonname)
            .ok_or(Errno::EFAULT)?;

        // f_mntfromname at offset 0x458: "litebox\0"
        let mntfromname = b"litebox\0";
        let mntfromname_dest: MutPtr<u8> = MutPtr::from_usize(buf + 0x458);
        mntfromname_dest
            .copy_from_slice(0, mntfromname)
            .ok_or(Errno::EFAULT)?;

        Ok(0)
    }

    /// Handle `thread_selfid()` — return the thread ID for this task.
    ///
    /// This is used by dyld during bootstrap. The exact value doesn't matter
    /// as long as it's nonzero and consistent within the process.
    #[allow(clippy::unnecessary_wraps, clippy::cast_sign_loss)]
    pub(crate) fn sys_thread_selfid(&self) -> Result<usize, Errno> {
        Ok(self.tid as usize)
    }

    /// Handle `mach_msg2_trap()` — modern Mach IPC (macOS 12+).
    ///
    /// Returns `MACH_SEND_INVALID_DEST` (0x10000003) to indicate the message
    /// could not be delivered. dyld uses this for task port communication but
    /// handles failure gracefully.
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn sys_mach_msg2_trap(&self) -> Result<usize, Errno> {
        Ok(0x1000_0003) // MACH_SEND_INVALID_DEST
    }

    /// Dispatch a Mach trap by trap number.
    pub(crate) fn do_mach_trap(&self, number: usize, ctx: &mut PtRegs) -> Result<usize, Errno> {
        match number {
            mach_trap::MACH_ABSOLUTE_TIME_TRAP => {
                // mach_absolute_time() returns nanoseconds since boot on Apple Silicon
                // (timebase is 1:1).
                let now = self.global.platform.now();
                let elapsed = now.duration_since(&self.global.boot_time);
                #[allow(clippy::cast_possible_truncation)]
                Ok(elapsed.as_nanos() as usize)
            }
            mach_trap::MACH_TIMEBASE_INFO_TRAP => {
                // mach_timebase_info_trap(mach_timebase_info_t info)
                // x0 = pointer to struct { uint32_t numer; uint32_t denom; }
                // On Apple Silicon: numer=1, denom=1.
                let info_ptr = MutPtr::<u32>::from_usize(ctx.regs[0]);
                let _ = info_ptr.write_at_offset(0, 1_u32); // numer
                let _ = info_ptr.write_at_offset(1, 1_u32); // denom
                Ok(0) // KERN_SUCCESS
            }
            mach_trap::KERNELRPC_MACH_VM_ALLOCATE_TRAP => self.sys_mach_vm_allocate(ctx),
            mach_trap::KERNELRPC_MACH_VM_DEALLOCATE_TRAP => self.sys_mach_vm_deallocate(ctx),
            mach_trap::KERNELRPC_MACH_VM_PROTECT_TRAP => self.sys_mach_vm_protect(ctx),
            mach_trap::KERNELRPC_MACH_VM_MAP_TRAP => self.sys_mach_vm_map(ctx),
            mach_trap::KERNELRPC_MACH_PORT_DEALLOCATE_TRAP => {
                // _kernelrpc_mach_port_deallocate_trap(target, name)
                // No-op stub — we don't track port reference counts.
                log_unsupported!(
                    "mach_port_deallocate_trap(target={:#x}, name={:#x}) → KERN_SUCCESS",
                    ctx.regs[0],
                    ctx.regs[1]
                );
                Ok(0) // KERN_SUCCESS
            }
            mach_trap::MACH_PORT_CONSTRUCT_TRAP => {
                // mach_port_construct_trap(target, options, context, name_out)
                // Used by dyld for port construction. Return KERN_SUCCESS.
                // x3 is a pointer to write the port name, but we don't
                // implement real Mach ports yet — dyld handles failure
                // gracefully when the port is never actually used.
                log_unsupported!(
                    "mach_port_construct_trap(target={:#x}, options={:#x}, context={:#x}, name_out={:#x}) → KERN_SUCCESS",
                    ctx.regs[0],
                    ctx.regs[1],
                    ctx.regs[2],
                    ctx.regs[3]
                );
                Ok(0) // KERN_SUCCESS
            }
            mach_trap::MACH_REPLY_PORT => Ok(0x0703),
            mach_trap::THREAD_SELF_TRAP => {
                if self.tid == 1 {
                    Ok(0x0303)
                } else {
                    #[allow(clippy::cast_sign_loss)] // tid is always positive
                    let port = ((self.tid as usize) + 2) << 8 | 0x03;
                    Ok(port)
                }
            }
            mach_trap::TASK_SELF_TRAP => Ok(0x0103),
            mach_trap::HOST_SELF_TRAP => Ok(0x0503),
            mach_trap::MACH_MSG_TRAP => {
                // Return MACH_SEND_INVALID_DEST (0x10000003)
                Ok(0x1000_0003)
            }
            mach_trap::SEMAPHORE_SIGNAL_TRAP => {
                #[allow(clippy::cast_possible_truncation)]
                let port = ctx.regs[0] as u32;
                Ok(self.global.semaphore_manager.signal(port))
            }
            mach_trap::SEMAPHORE_SIGNAL_ALL_TRAP => {
                #[allow(clippy::cast_possible_truncation)]
                let port = ctx.regs[0] as u32;
                Ok(self.global.semaphore_manager.signal_all(port))
            }
            mach_trap::SEMAPHORE_WAIT_TRAP => {
                #[allow(clippy::cast_possible_truncation)]
                let port = ctx.regs[0] as u32;
                Ok(self.sys_semaphore_wait(port))
            }
            mach_trap::SEMAPHORE_TIMEDWAIT_TRAP => {
                #[allow(clippy::cast_possible_truncation)]
                let port = ctx.regs[0] as u32;
                #[allow(clippy::cast_possible_truncation)]
                let sec = ctx.regs[1] as u32;
                #[allow(clippy::cast_possible_truncation)]
                let nsec = ctx.regs[2] as u32;
                Ok(self.sys_semaphore_timedwait(port, sec, nsec))
            }
            mach_trap::THREAD_GET_SPECIAL_REPLY_PORT => Ok(0x0903),
            _ => {
                log_unsupported!("Mach trap {number}");
                Ok(0)
            }
        }
    }

    /// Handle `bsdthread_register` — one-time pthread library registration.
    ///
    /// Stores the `_thread_start` trampoline address and pthread struct size
    /// in the shared `Process` so that future `bsdthread_create` calls know
    /// where to set new threads' PC and how to find TSD.
    ///
    /// # Arguments
    /// - `threadstart`: address of `_thread_start` asm trampoline
    /// - `wqthread`: address of `_start_wqthread` asm trampoline
    /// - `pthsize`: `sizeof(struct pthread_s)`
    /// - `pthread_init_data`: pointer to `_pthread_registration_data` struct
    /// - `pthread_init_data_size`: size of the registration data struct
    pub(crate) fn sys_bsdthread_register(
        &self,
        threadstart: usize,
        wqthread: usize,
        pthsize: u32,
        pthread_init_data: usize,
        pthread_init_data_size: usize,
    ) -> Result<usize, Errno> {
        use core::sync::atomic::Ordering;

        log_unsupported!(
            "bsdthread_register(threadstart={threadstart:#x}, wqthread={wqthread:#x}, \
             pthsize={pthsize}, init_data={pthread_init_data:#x}, init_data_size={pthread_init_data_size})"
        );

        self.process
            .threadstart
            .store(threadstart as u64, Ordering::Release);
        self.process
            .wqthread
            .store(wqthread as u64, Ordering::Release);
        self.process.pthsize.store(pthsize, Ordering::Release);

        // Parse the _pthread_registration_data struct to extract tsd_offset.
        if pthread_init_data != 0 && pthread_init_data_size >= 24 {
            // Read tsd_offset at offset 16 (8 bytes)
            let ptr: crate::ConstPtr<u8> = crate::ConstPtr::from_usize(pthread_init_data + 16);
            let mut tsd_offset_bytes = [0u8; 8];
            for (i, byte) in tsd_offset_bytes.iter_mut().enumerate() {
                *byte = ptr.read_at_offset(i.cast_signed()).ok_or(Errno::EFAULT)?;
            }
            #[allow(clippy::cast_possible_truncation)] // TSD offset fits in u32 on aarch64
            let tsd_offset = u64::from_le_bytes(tsd_offset_bytes) as u32;
            self.process.tsd_offset.store(tsd_offset, Ordering::Release);
            log_unsupported!("bsdthread_register: tsd_offset={tsd_offset:#x}");

            // Write back the reply data (version/size acknowledgment).
            let version_bytes = (pthread_init_data_size as u64).to_le_bytes();
            let dest: MutPtr<u8> = MutPtr::from_usize(pthread_init_data);
            for i in 0..8isize {
                dest.write_at_offset(i, version_bytes[i.cast_unsigned()])
                    .ok_or(Errno::EFAULT)?;
            }
        }

        // Return 0 for minimal pthread feature support.
        Ok(0)
    }

    /// Handle `bsdthread_create` — create a new thread.
    ///
    /// # Panics
    ///
    /// Panics if `bsdthread_register` has not been called (threadstart == 0).
    pub(crate) fn sys_bsdthread_create(
        &self,
        func: usize,
        func_arg: usize,
        stack: usize,
        pthread: usize,
        flags: u32,
        ctx: &PtRegs,
    ) -> Result<usize, Errno> {
        use core::sync::atomic::Ordering;

        #[allow(clippy::cast_possible_truncation)] // aarch64: usize == u64
        let threadstart = self.process.threadstart.load(Ordering::Acquire) as usize;
        if threadstart == 0 {
            log_unsupported!("bsdthread_create called before bsdthread_register");
            return Err(Errno::EINVAL);
        }

        let tid = self.process.next_tid.fetch_add(1, Ordering::Relaxed);
        let mach_port = self
            .process
            .next_mach_port
            .fetch_add(0x100, Ordering::Relaxed);
        let tsd_offset = self.process.tsd_offset.load(Ordering::Acquire);

        log_unsupported!(
            "bsdthread_create(func={func:#x}, arg={func_arg:#x}, stack={stack:#x}, \
             pthread={pthread:#x}, flags={flags:#x}) → tid={tid}, port={mach_port:#x}"
        );

        // Increment thread count before spawning.
        self.process.nr_threads.fetch_add(1, Ordering::Release);

        // Set PTHREAD_START_TSD_BASE_SET (0x10000000) in flags to tell
        // libpthread that we pre-configured the TSD base.
        let flags_with_tsd = flags | 0x1000_0000;

        let child_task = crate::Task {
            global: self.global.clone(),
            process: self.process.clone(),
            tid,
            terminated: core::sync::atomic::AtomicBool::new(false),
            patch_cache: litebox::sync::Mutex::new(alloc::collections::BTreeMap::new()),
            init_state: litebox::sync::Mutex::new(crate::ThreadInitState::BsdThread {
                threadstart,
                func,
                func_arg,
                stack,
                pthread,
                flags: flags_with_tsd,
                mach_port,
                tsd_offset,
            }),
            blocked_signals: core::sync::atomic::AtomicU32::new(0),
            wait_state: crate::wait::WaitState::new(self.global.platform),
        };

        let r = unsafe {
            self.global
                .platform
                .spawn_thread(ctx, Box::new(crate::NewThreadArgs { task: child_task }))
        };

        if let Err(err) = r {
            self.process.nr_threads.fetch_sub(1, Ordering::Release);
            log_unsupported!("bsdthread_create: spawn_thread failed: {err}");
            return Err(Errno::EAGAIN);
        }

        // Return the pthread address (what the kernel returns on success).
        Ok(pthread)
    }

    /// Handle `bsdthread_terminate` — terminate the calling thread.
    ///
    /// On real macOS, the kernel frees the thread's stack, deallocates its
    /// Mach port, and signals a semaphore/ulock. We skip stack freeing
    /// (the host thread owns its stack) and just mark the thread terminated.
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn sys_bsdthread_terminate(
        &self,
        _stackaddr: usize,
        _freesize: usize,
        _port: u32,
        _sema_or_ulock: usize,
    ) -> Result<usize, Errno> {
        use core::sync::atomic::Ordering;

        log_unsupported!("bsdthread_terminate(tid={})", self.tid);

        // Decrement thread count.
        let prev = self.process.nr_threads.fetch_sub(1, Ordering::Release);
        if prev <= 1 {
            // Last thread exiting — treat as process exit with code 0.
            self.process
                .exit_code
                .compare_exchange(0, 0, Ordering::AcqRel, Ordering::Acquire)
                .ok();
            self.process.group_exit.store(true, Ordering::Release);
        }

        self.terminated.store(true, Ordering::Release);
        Ok(0)
    }

    /// Handle `bsdthread_ctl` — thread control operations.
    ///
    /// Most commands are stubs. We handle the minimum needed for libpthread.
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn sys_bsdthread_ctl(
        &self,
        cmd: usize,
        _arg1: usize,
        _arg2: usize,
        _arg3: usize,
    ) -> Result<usize, Errno> {
        const BSDTHREAD_CTL_SET_QOS: usize = 0x10;
        const BSDTHREAD_CTL_GET_QOS: usize = 0x20;
        const BSDTHREAD_CTL_SET_SELF: usize = 0x100;
        const BSDTHREAD_CTL_QOS_MAX_PARALLELISM: usize = 0x800;

        match cmd {
            BSDTHREAD_CTL_QOS_MAX_PARALLELISM => Ok(1),
            BSDTHREAD_CTL_SET_SELF | BSDTHREAD_CTL_SET_QOS | BSDTHREAD_CTL_GET_QOS => Ok(0),
            _ => {
                log_unsupported!("bsdthread_ctl(cmd={cmd:#x}): unsupported");
                Ok(0)
            }
        }
    }

    /// Handle `__semwait_signal(cond_sem, mutex_sem, timeout, relative, tv_sec, tv_nsec)`.
    ///
    /// Used by `usleep()` in libSystem. If `timeout` is non-zero, sleeps for the
    /// requested duration. Otherwise returns immediately.
    #[allow(clippy::unnecessary_wraps, clippy::similar_names)]
    pub(crate) fn sys_semwait_signal(
        &self,
        _cond_sem: i32,
        _mutex_sem: i32,
        timeout: i32,
        _relative: i32,
        tv_sec: i64,
        tv_nsec: i32,
    ) -> Result<usize, Errno> {
        if timeout != 0 && (tv_sec > 0 || tv_nsec > 0) {
            #[allow(clippy::cast_sign_loss)] // We guard tv_sec > 0 and tv_nsec > 0 above
            let duration =
                core::time::Duration::new(tv_sec.cast_unsigned(), tv_nsec.cast_unsigned());
            // Use the wait state to perform an interruptible sleep.
            // If the process is exiting, this will return early.
            let cx = self.wait_cx().with_timeout(duration);
            let _ = cx.sleep(); // returns WaitError::TimedOut or Interrupted
        }
        Ok(0)
    }

    /// Handle `getfsstat64(buf, bufsize, flags)` — enumerate mounted filesystems.
    ///
    /// dyld calls this during startup to discover mounted volumes.  We report
    /// a single root filesystem so dyld gets a valid count and can proceed.
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn sys_getfsstat64(
        &self,
        buf: usize,
        bufsize: usize,
        flags: i32,
    ) -> Result<usize, Errno> {
        const STATFS_SIZE: usize = 0x878;

        log_unsupported!("getfsstat64(buf={buf:#x}, bufsize={bufsize:#x}, flags={flags})");

        if buf == 0 {
            // Query mode: return count of mounted filesystems (just root).
            return Ok(1);
        }

        if bufsize < STATFS_SIZE {
            return Err(Errno::EINVAL);
        }

        // Fill one statfs64 struct for the root filesystem "/" (same as sys_statfs64).
        let zeros = alloc::vec![0u8; STATFS_SIZE];
        let dest: MutPtr<u8> = MutPtr::from_usize(buf);
        dest.copy_from_slice(0, &zeros).ok_or(Errno::EFAULT)?;

        let buf32: MutPtr<u32> = MutPtr::from_usize(buf);
        buf32.write_at_offset(0, 4096).ok_or(Errno::EFAULT)?; // f_bsize
        buf32.write_at_offset(1, 4096).ok_or(Errno::EFAULT)?; // f_iosize

        let buf64: MutPtr<u64> = MutPtr::from_usize(buf);
        buf64.write_at_offset(1, 1_000_000).ok_or(Errno::EFAULT)?; // f_blocks
        buf64.write_at_offset(2, 500_000).ok_or(Errno::EFAULT)?; // f_bfree
        buf64.write_at_offset(3, 500_000).ok_or(Errno::EFAULT)?; // f_bavail
        buf64.write_at_offset(4, 100_000).ok_or(Errno::EFAULT)?; // f_files
        buf64.write_at_offset(5, 50_000).ok_or(Errno::EFAULT)?; // f_ffree

        // f_fstypename at offset 0x48
        let fstypename = b"apfs\0";
        let fstypename_dest: MutPtr<u8> = MutPtr::from_usize(buf + 0x48);
        fstypename_dest
            .copy_from_slice(0, fstypename)
            .ok_or(Errno::EFAULT)?;

        // f_mntonname at offset 0x58
        let mntonname = b"/\0";
        let mntonname_dest: MutPtr<u8> = MutPtr::from_usize(buf + 0x58);
        mntonname_dest
            .copy_from_slice(0, mntonname)
            .ok_or(Errno::EFAULT)?;

        // f_mntfromname at offset 0x458
        let mntfromname = b"litebox\0";
        let mntfromname_dest: MutPtr<u8> = MutPtr::from_usize(buf + 0x458);
        mntfromname_dest
            .copy_from_slice(0, mntfromname)
            .ok_or(Errno::EFAULT)?;

        // Return count of entries filled (1).
        Ok(1)
    }

    /// Handle `fsgetpath(buf, bufsize, fsid, objid)` — get filesystem path.
    ///
    /// dyld uses this to discover the path of the shared cache file on disk.
    /// We return ENOTSUP since our shared cache is directly mapped into memory
    /// and doesn't have a meaningful on-disk path in the guest FS.
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn sys_fsgetpath(
        &self,
        buf: usize,
        bufsize: usize,
        fsid: usize,
        objid: u64,
    ) -> Result<usize, Errno> {
        log_unsupported!(
            "fsgetpath(buf={buf:#x}, bufsize={bufsize:#x}, fsid={fsid:#x}, objid={objid:#x})"
        );
        Err(Errno::ENOTSUP)
    }

    /// Handle `__ulock_wait(operation, addr, value, timeout_us)` — wait on a userspace lock.
    ///
    /// In a single-threaded guest, no other thread can wake us, so blocking
    /// would deadlock. Instead we implement compare-and-wait semantics:
    ///
    /// - If `*addr != value`, return 0 (spurious wakeup — value already changed).
    /// - If `*addr == value`, also return 0 (pretend we were woken) to prevent
    ///   the caller from blocking forever. The caller will retry its CAS loop
    ///   and either succeed or call ulock_wait again.
    ///
    /// This is sufficient for dyld bootstrap where `os_unfair_lock` contention
    /// is caused by our NOP of `findAndRunAllInitializers`, leaving an internal
    /// lock in a "locked" state that was never actually contended.
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn sys_ulock_wait(
        &self,
        operation: u32,
        addr: usize,
        value: u64,
        timeout_us: u32,
    ) -> Result<usize, Errno> {
        const UL_COMPARE_AND_WAIT: u32 = 1;
        const UL_COMPARE_AND_WAIT_SHARED: u32 = 3;
        const UL_COMPARE_AND_WAIT64: u32 = 5;
        const UL_COMPARE_AND_WAIT64_SHARED: u32 = 6;

        // Strip flags from operation to get the base operation type.
        let op = operation & 0x0000_FFFF;

        match op {
            UL_COMPARE_AND_WAIT | UL_COMPARE_AND_WAIT_SHARED => {
                // 32-bit compare-and-wait: read the 32-bit value at addr.
                let ptr: crate::ConstPtr<u32> = crate::ConstPtr::from_usize(addr);
                let current = u64::from(ptr.read_at_offset(0).unwrap_or(0));
                if current == value {
                    // Value matches — lock is still held. In single-threaded mode,
                    // no other thread will ever unlock it. Force-clear the lock word
                    // to 0 (unlocked) so the caller's next CAS attempt succeeds.
                    let wptr: MutPtr<u32> = MutPtr::from_usize(addr);
                    let _ = wptr.write_at_offset(0, 0_u32);
                    log_unsupported!(
                        "ulock_wait(op={operation:#x}, addr={addr:#x}, value={value:#x}, \
                         timeout={timeout_us}): force-unlocked for single-threaded guest"
                    );
                } else {
                    // Value already changed — spurious wakeup.
                    log_unsupported!(
                        "ulock_wait(op={operation:#x}, addr={addr:#x}, value={value:#x}, \
                         timeout={timeout_us}): current={current:#x} != value, spurious wakeup"
                    );
                }
                Ok(0)
            }
            UL_COMPARE_AND_WAIT64 | UL_COMPARE_AND_WAIT64_SHARED => {
                // 64-bit compare-and-wait: read the 64-bit value at addr.
                let ptr: crate::ConstPtr<u64> = crate::ConstPtr::from_usize(addr);
                let current = ptr.read_at_offset(0).unwrap_or(0);
                if current == value {
                    // Force-clear for single-threaded guest.
                    let wptr: MutPtr<u64> = MutPtr::from_usize(addr);
                    let _ = wptr.write_at_offset(0, 0_u64);
                    log_unsupported!(
                        "ulock_wait64(op={operation:#x}, addr={addr:#x}, value={value:#x}, \
                         timeout={timeout_us}): force-unlocked for single-threaded guest"
                    );
                } else {
                    log_unsupported!(
                        "ulock_wait64(op={operation:#x}, addr={addr:#x}, value={value:#x}, \
                         timeout={timeout_us}): current={current:#x} != value, spurious wakeup"
                    );
                }
                Ok(0)
            }
            _ => {
                log_unsupported!(
                    "ulock_wait(op={operation:#x}, addr={addr:#x}, value={value:#x}, \
                     timeout={timeout_us}): unsupported operation"
                );
                Err(Errno::ENOTSUP)
            }
        }
    }

    /// Handle `__ulock_wake(operation, addr, wake_value)` — wake waiters on a userspace lock.
    ///
    /// In a single-threaded guest, there are no waiters to wake. Return 0 (success).
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn sys_ulock_wake(
        &self,
        operation: u32,
        addr: usize,
        wake_value: u64,
    ) -> Result<usize, Errno> {
        log_unsupported!(
            "ulock_wake(op={operation:#x}, addr={addr:#x}, wake_value={wake_value:#x}): no-op"
        );
        Ok(0)
    }
}
