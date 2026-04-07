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
use litebox_common_macos::PtRegs;
use litebox_common_macos::errno::Errno;
use litebox_common_macos::syscall::mach_trap;

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
                // Return the real kernel mach port stored during thread init.
                // This must match tl_thport (pthread+248) so that os_unfair_lock
                // deadlock detection sees a consistent thread identity.
                let port = self
                    .real_mach_port
                    .load(core::sync::atomic::Ordering::Acquire);
                Ok(port as usize)
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
            altstack: litebox::sync::Mutex::new(litebox_common_macos::SigAltStack::DISABLED),
            wait_state: crate::wait::WaitState::new(self.global.platform),
            dir_positions: litebox::sync::Mutex::new(alloc::collections::BTreeMap::new()),
            // Initialized to 0; handle_init_request will set to real mach_thread_self().
            real_mach_port: core::sync::atomic::AtomicU32::new(0),
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

        // Record this pthread address so we can suppress premature
        // mach_vm_deallocate on the thread's stack allocation.
        self.process.thread_pthreads.lock().insert(pthread);

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
        stackaddr: usize,
        freesize: usize,
        port: u32,
        sema_or_ulock: usize,
    ) -> Result<usize, Errno> {
        use core::sync::atomic::Ordering;

        log_unsupported!(
            "bsdthread_terminate(tid={}, stackaddr={stackaddr:#x}, freesize={freesize:#x}, port={port:#x}, sema={sema_or_ulock:#x})",
            self.tid
        );

        // On real macOS, the kernel atomically frees the thread stack,
        // signals the join semaphore/ulock, and terminates the thread.
        // We replicate the stack freeing here so that the guest's
        // pthread_join can access the pthread struct (which is above the
        // freed stack region, not inside it) without it being double-freed.
        //
        // Important: The kernel frees [stackaddr, stackaddr+freesize).
        // The pthread struct lives ABOVE this region (at higher addresses)
        // and is NOT freed — pthread_join reads it after the thread exits.

        // Remove this thread's pthread from the tracking set.  The
        // pthread struct sits at stackaddr+freesize (just above the
        // freed region), so check a generous range.
        if stackaddr != 0 {
            let mut pthreads = self.process.thread_pthreads.lock();
            // Remove any tracked pthread whose address falls in
            // [stackaddr, stackaddr + freesize + pthsize_margin].
            // On macOS the pthread is at the top of the mach_vm_map
            // allocation, right above the freed stack region.
            let pthsize = self.process.pthsize.load(Ordering::Acquire) as usize;
            let range_end = stackaddr
                .saturating_add(freesize)
                .saturating_add(pthsize)
                .saturating_add(0x1000);
            let to_remove: alloc::vec::Vec<usize> = pthreads
                .iter()
                .copied()
                .filter(|&p| p >= stackaddr && p < range_end)
                .collect();
            for p in to_remove {
                log_unsupported!("bsdthread_terminate: removing tracked pthread {p:#x}");
                pthreads.remove(&p);
            }
        }

        if stackaddr != 0 && freesize != 0 {
            // On real macOS the kernel atomically frees the stack AND
            // terminates the thread in a single syscall.  We cannot
            // replicate that atomicity: if we munmap the stack here,
            // the current thread (or another guest thread whose
            // allocation is adjacent) may crash accessing the freed
            // region before we finish terminating.  Since the entire
            // child process will \_exit(0) shortly, leaking the stack
            // is harmless.
            log_unsupported!(
                "bsdthread_terminate: skipping stack free at {stackaddr:#x}, size {freesize:#x} (will leak; process exits soon)"
            );
        }

        // Signal the ulock/semaphore to wake pthread_join.
        //
        // On real macOS, `bsdthread_terminate`'s last parameter is either:
        //   - 0 (MACH_PORT_NULL): no joiner to wake
        //   - A valid ulock/semaphore address: wake the joiner
        //   - A small integer like 0x1: a sentinel/flag, not a real address
        //
        // Only attempt the ulock wake if the value looks like a plausible
        // address (above the low guard region).
        if sema_or_ulock > 0x1000 {
            log_unsupported!("bsdthread_terminate: waking ulock at {sema_or_ulock:#x}");
            // Write MACH_PORT_DEAD (0xFFFFFFFF) to the exit_gate word to
            // indicate thread completion, then wake any waiters.
            let ulock_ptr: MutPtr<u32> = MutPtr::from_usize(sema_or_ulock);
            if let Some(()) = ulock_ptr.write_at_offset(0, 0xFFFF_FFFFu32) {
                // UL_COMPARE_AND_WAIT = 1, ULF_WAKE_ALL = 0x100
                let _ = self.sys_ulock_wake(0x100 | 1, sema_or_ulock, 0);
            }
        } else if sema_or_ulock != 0 {
            log_unsupported!(
                "bsdthread_terminate: ignoring non-address sema_or_ulock={sema_or_ulock:#x}"
            );
        }

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
    /// Uses the `FutexManager` for real blocking so that multi-threaded guests
    /// (e.g. `pthread_join` waiting on `tl_exit_gate`) work correctly.
    ///
    /// All 32-bit ulock operations (UL_COMPARE_AND_WAIT, UL_UNFAIR_LOCK, etc.)
    /// have identical compare-and-wait semantics from the kernel's perspective:
    /// compare `*addr` (32-bit) with `value` (truncated to 32 bits), and block
    /// if they match until woken by `__ulock_wake` on the same address.
    pub(crate) fn sys_ulock_wait(
        &self,
        operation: u32,
        addr: usize,
        value: u64,
        timeout_us: u32,
    ) -> Result<usize, Errno> {
        use litebox::sync::futex::FutexError;

        // Strip flags from operation to get the base operation type.
        let op = operation & 0x0000_FFFF;

        // All 32-bit ulock operations use the same compare-and-wait
        // mechanism on a 32-bit word.  UL_UNFAIR_LOCK (2) is used by
        // pthread_join for tl_exit_gate; UL_COMPARE_AND_WAIT (1) is
        // used by os_unfair_lock and other synchronization primitives.
        //
        // 64-bit variants (5, 6) are not yet supported with real blocking
        // but fall through to a stub that force-clears for dyld bootstrap.
        match op {
            1..=4 => {
                // 32-bit compare-and-wait via FutexManager.
                #[allow(clippy::cast_possible_truncation)]
                let expected = value as u32;
                let futex_addr: MutPtr<u32> = MutPtr::from_usize(addr);

                // Read current value at lock address for diagnostic.
                let current_val = futex_addr.read_at_offset(0).unwrap_or(0xDEAD);

                // Build a wait context, optionally with a timeout.
                let base_cx = self.wait_cx();
                let timeout = if timeout_us == 0 {
                    None
                } else {
                    Some(core::time::Duration::from_micros(u64::from(timeout_us)))
                };
                let cx = base_cx.with_timeout(timeout);

                log_unsupported!(
                    "ulock_wait(op={operation:#x}, addr={addr:#x}, expected={expected:#x},                       current={current_val:#x}, tid={}, timeout={timeout_us}): blocking via futex",
                    self.tid
                );

                match self
                    .global
                    .futex_manager
                    .wait(&cx, futex_addr, expected, None)
                {
                    Ok(()) => {
                        let after_val = futex_addr.read_at_offset(0).unwrap_or(0xDEAD);
                        log_unsupported!(
                            "ulock_wait(addr={addr:#x}, tid={}): WOKEN, lock now={after_val:#x}",
                            self.tid
                        );
                        Ok(0)
                    }
                    Err(FutexError::ImmediatelyWokenBecauseValueMismatch) => {
                        let after_val = futex_addr.read_at_offset(0).unwrap_or(0xDEAD);
                        log_unsupported!(
                            "ulock_wait(addr={addr:#x}, tid={}): VALUE_MISMATCH expected={expected:#x} current={current_val:#x} now={after_val:#x}",
                            self.tid
                        );
                        // Value already changed — spurious wakeup (thread exited).
                        Ok(0)
                    }
                    Err(FutexError::WaitError(_)) => {
                        // Interrupted or timed out.
                        Err(Errno::EINTR)
                    }
                    Err(FutexError::Fault) => Err(Errno::EFAULT),
                    Err(FutexError::NotAligned) => Err(Errno::EINVAL),
                }
            }
            5 | 6 => {
                // 64-bit compare-and-wait: not yet backed by FutexManager
                // (which operates on 32-bit words).  Fall back to the
                // force-clear stub for dyld bootstrap compatibility.
                let ptr: crate::ConstPtr<u64> = crate::ConstPtr::from_usize(addr);
                let current = ptr.read_at_offset(0).unwrap_or(0);
                if current == value {
                    let wptr: MutPtr<u64> = MutPtr::from_usize(addr);
                    let _ = wptr.write_at_offset(0, 0_u64);
                    log_unsupported!(
                        "ulock_wait64(op={operation:#x}, addr={addr:#x}, value={value:#x},                          timeout={timeout_us}): force-unlocked (64-bit stub)"
                    );
                } else {
                    log_unsupported!(
                        "ulock_wait64(op={operation:#x}, addr={addr:#x}, value={value:#x},                          timeout={timeout_us}): current={current:#x} != value, spurious wakeup"
                    );
                }
                Ok(0)
            }
            _ => {
                log_unsupported!(
                    "ulock_wait(op={operation:#x}, addr={addr:#x}, value={value:#x},                      timeout={timeout_us}): unsupported operation"
                );
                Err(Errno::ENOTSUP)
            }
        }
    }

    /// Handle `__ulock_wake(operation, addr, wake_value)` — wake waiters on a userspace lock.
    ///
    /// Uses the `FutexManager` to wake threads blocked in `sys_ulock_wait`.
    pub(crate) fn sys_ulock_wake(
        &self,
        operation: u32,
        addr: usize,
        _wake_value: u64,
    ) -> Result<usize, Errno> {
        use litebox::sync::futex::FutexError;

        let flags = operation & 0xFFFF_0000;
        let wake_all = flags & 0x0000_0100 != 0; // ULF_WAKE_ALL

        let futex_addr: MutPtr<u32> = MutPtr::from_usize(addr);
        let count = if wake_all {
            core::num::NonZeroU32::new(u32::MAX).unwrap()
        } else {
            core::num::NonZeroU32::new(1).unwrap()
        };

        log_unsupported!(
            "ulock_wake(op={operation:#x}, addr={addr:#x}, wake_all={wake_all}, tid={})",
            self.tid
        );

        match self.global.futex_manager.wake(futex_addr, count, None) {
            Ok(woken) => {
                if woken > 0 {
                    log_unsupported!(
                        "ulock_wake(addr={addr:#x}, tid={}): woke {woken} waiters",
                        self.tid
                    );
                }
                Ok(0)
            }
            Err(FutexError::NotAligned) => Err(Errno::EINVAL),
            Err(FutexError::Fault) => Err(Errno::EFAULT),
            Err(_) => Ok(0), // Other errors: treat as no waiters
        }
    }
}
