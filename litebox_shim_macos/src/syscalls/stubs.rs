// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Stub syscall handlers for macOS shim Phase 2.
//!
//! These handlers provide minimal implementations sufficient for dyld
//! bootstrap and hello.c execution.

use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_macos::errno::Errno;
use litebox_common_macos::syscall::mach_trap;
use litebox_common_macos::PtRegs;

use crate::{MutPtr, ShimFS, Task};

impl<FS: ShimFS> Task<FS> {
    /// Handle `sigaction()` — stub: record but don't deliver signals.
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn sys_sigaction(
        &self,
        _signum: i32,
        _new_act: usize,
        _old_act: usize,
    ) -> Result<usize, Errno> {
        Ok(0)
    }

    /// Handle `sigprocmask()` — stub: return success.
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn sys_sigprocmask(
        &self,
        _how: i32,
        _set: usize,
        _oldset: usize,
    ) -> Result<usize, Errno> {
        Ok(0)
    }

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
            let ptr: MutPtr<u64> = MutPtr::from_usize(start_address);
            ptr.write_at_offset(0, base).ok_or(Errno::EFAULT)?;
            log_unsupported!("shared_region_check_np: cache installed at {:#x}", base);
            Ok(0)
        } else {
            log_unsupported!("shared_region_check_np: no cache installed, returning EINVAL");
            Err(Errno::EINVAL)
        }
    }

    /// Handle `getentropy()` — fill buffer with pseudo-random bytes.
    pub(crate) fn sys_getentropy(&self, buf_addr: usize, count: usize) -> Result<usize, Errno> {
        if count > 256 {
            return Err(Errno::EIO);
        }
        let data: alloc::vec::Vec<u8> = (0..count)
            .map(|i| {
                #[allow(clippy::cast_possible_truncation)]
                let b = (i as u8).wrapping_mul(7).wrapping_add(13);
                b
            })
            .collect();
        let dest: MutPtr<u8> = MutPtr::from_usize(buf_addr);
        dest.copy_from_slice(0, &data).ok_or(Errno::EFAULT)?;
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
    #[allow(clippy::unnecessary_wraps)]
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
            mach_trap::KERNELRPC_MACH_VM_ALLOCATE_TRAP => self.sys_mach_vm_allocate(ctx),
            mach_trap::KERNELRPC_MACH_VM_DEALLOCATE_TRAP => self.sys_mach_vm_deallocate(ctx),
            mach_trap::KERNELRPC_MACH_VM_PROTECT_TRAP => self.sys_mach_vm_protect(ctx),
            mach_trap::KERNELRPC_MACH_VM_MAP_TRAP => self.sys_mach_vm_map(ctx),
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
            mach_trap::THREAD_SELF_TRAP => Ok(0x0303),
            mach_trap::TASK_SELF_TRAP => Ok(0x0103),
            mach_trap::HOST_SELF_TRAP => Ok(0x0503),
            mach_trap::MACH_MSG_TRAP => {
                // Return MACH_SEND_INVALID_DEST (0x10000003)
                Ok(0x1000_0003)
            }
            mach_trap::THREAD_GET_SPECIAL_REPLY_PORT => Ok(0x0903),
            _ => {
                log_unsupported!("Mach trap {number}");
                Ok(0)
            }
        }
    }
}
