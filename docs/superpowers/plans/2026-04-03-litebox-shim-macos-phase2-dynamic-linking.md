# Phase 2: Dynamic Linking via mmap-hook Rewriting — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run a dynamically linked macOS `hello.c` (printf, clock_gettime, argv/envp) through litebox by loading real dyld, intercepting its syscalls, and patching dylib code segments on the fly.

**Architecture:** Real dyld loads inside the guest with its SVC sites rewritten at load time. The shim intercepts all BSD syscalls and Mach traps. When dyld mmaps a dylib's executable segment, the mmap-hook patches SVC sites in that segment before execution. Dylibs are extracted from the shared cache into a local sysroot; `open()` calls are redirected there.

**Tech Stack:** Rust (edition 2024), `object` crate for Mach-O parsing, aarch64 assembly for trampolines, macOS Xcode toolchain for compilation.

---

### Task 1: Extend syscall numbers and request decoding

Add new BSD syscall numbers and Mach trap constants. Extend `MacosSyscallRequest` enum with all new variants needed for dyld bootstrap and hello.c execution.

**Files:**
- Modify: `litebox_common_macos/src/syscall.rs`

- [ ] **Step 1: Add new BSD syscall number constants**

In `litebox_common_macos/src/syscall.rs`, add these constants to the `nr` module after the existing ones:

```rust
    pub const SIGACTION: usize = 46;
    // GETGID = 47 already exists
    pub const SIGPROCMASK: usize = 48;
    pub const IOCTL: usize = 54;
    // MUNMAP = 73 already exists
    // MPROTECT = 74 already exists
    pub const MADVISE: usize = 75;
    pub const FCNTL: usize = 92;
    pub const PREAD: usize = 153;
    pub const CSOPS: usize = 169;
    // MMAP = 197 already exists
    pub const LSEEK: usize = 199;
    pub const SYSCTL: usize = 202;
    pub const SHARED_REGION_CHECK_NP: usize = 294;
    // ISSETUGID = 327 already exists
    // FSTAT64 = 339 already exists
    pub const GETENTROPY: usize = 500;
```

Note: `SIGACTION`, `SIGPROCMASK`, `IOCTL`, `MADVISE`, `LSEEK`, `SYSCTL`, and `FSTAT64` constants already exist in the nr module. Only add the ones that are truly new: `FCNTL`, `PREAD`, `CSOPS`, `SHARED_REGION_CHECK_NP`, `GETENTROPY`.

- [ ] **Step 2: Add Mach trap number constants**

Add a new `mach_trap` module inside `syscall.rs`, after the `nr` module:

```rust
/// Mach trap numbers (negative x16 values, stored as positive constants).
/// The actual x16 value is the negation of these.
pub mod mach_trap {
    pub const MACH_REPLY_PORT: usize = 26;
    pub const THREAD_SELF_TRAP: usize = 27;
    pub const TASK_SELF_TRAP: usize = 28;
    pub const HOST_SELF_TRAP: usize = 29;
    pub const MACH_MSG_TRAP: usize = 31;
    pub const THREAD_GET_SPECIAL_REPLY_PORT: usize = 50;
}
```

- [ ] **Step 3: Add new MacosSyscallRequest variants**

Extend the `MacosSyscallRequest` enum with:

```rust
    Open { path: usize, flags: i32, mode: u32 },
    Sigaction { signum: i32, new_act: usize, old_act: usize },
    Sigprocmask { how: i32, set: usize, oldset: usize },
    Ioctl { fd: i32, request: usize, arg: usize },
    Madvise { addr: usize, length: usize, advice: i32 },
    Fcntl { fd: i32, cmd: i32, arg: usize },
    Pread { fd: i32, buf: usize, count: usize, offset: i64 },
    Csops { pid: i32, ops: u32, useraddr: usize, usersize: usize },
    Lseek { fd: i32, offset: i64, whence: i32 },
    Sysctl { name: usize, namelen: u32, old: usize, oldlenp: usize, new_val: usize, newlen: usize },
    SharedRegionCheckNp { start_address: usize },
    Fstat64 { fd: i32, buf: usize },
    Getentropy { buf: usize, count: usize },
    /// A Mach trap (negative x16 value).
    MachTrap { number: usize },
```

- [ ] **Step 4: Update `try_from_raw` to decode new syscalls and Mach traps**

Update the match in `try_from_raw` to handle: (a) negative x16 → `MachTrap`, (b) new BSD syscall numbers → respective variants. Check the sign of `nr` first:

```rust
    pub fn try_from_raw(ctx: &PtRegs) -> Self {
        let nr_raw = ctx.regs[16];
        // Check for Mach traps (negative x16 values).
        // On aarch64, a negative i64 stored in a usize has the high bit set.
        let nr_signed = nr_raw as i64;
        if nr_signed < 0 {
            let trap_nr = nr_signed.unsigned_abs() as usize;
            return MacosSyscallRequest::MachTrap { number: trap_nr };
        }

        let nr = nr_raw;
        let a0 = ctx.regs[0];
        let a1 = ctx.regs[1];
        let a2 = ctx.regs[2];
        let a3 = ctx.regs[3];
        let a4 = ctx.regs[4];
        let a5 = ctx.regs[5];

        match nr {
            // ... existing matches unchanged ...
            nr::OPEN => MacosSyscallRequest::Open { path: a0, flags: a0_as_i32, mode: a2 as u32 },
            // ... etc for all new variants ...
```

Actually, for `Open`, the arguments are: `path` in x0 (a0), `flags` in x1 (a1 as i32), `mode` in x2 (a2 as u32):

```rust
            nr::OPEN => MacosSyscallRequest::Open {
                path: a0,
                flags: a1 as i32,
                mode: a2 as u32,
            },
            nr::SIGACTION => MacosSyscallRequest::Sigaction {
                signum: a0 as i32,
                new_act: a1,
                old_act: a2,
            },
            nr::SIGPROCMASK => MacosSyscallRequest::Sigprocmask {
                how: a0 as i32,
                set: a1,
                oldset: a2,
            },
            nr::IOCTL => MacosSyscallRequest::Ioctl {
                fd: a0 as i32,
                request: a1,
                arg: a2,
            },
            nr::MADVISE => MacosSyscallRequest::Madvise {
                addr: a0,
                length: a1,
                advice: a2 as i32,
            },
            nr::FCNTL => MacosSyscallRequest::Fcntl {
                fd: a0 as i32,
                cmd: a1 as i32,
                arg: a2,
            },
            nr::PREAD => MacosSyscallRequest::Pread {
                fd: a0 as i32,
                buf: a1,
                count: a2,
                offset: a3 as i64,
            },
            nr::CSOPS => MacosSyscallRequest::Csops {
                pid: a0 as i32,
                ops: a1 as u32,
                useraddr: a2,
                usersize: a3,
            },
            nr::LSEEK => MacosSyscallRequest::Lseek {
                fd: a0 as i32,
                offset: a1 as i64,
                whence: a2 as i32,
            },
            nr::SYSCTL => MacosSyscallRequest::Sysctl {
                name: a0,
                namelen: a1 as u32,
                old: a2,
                oldlenp: a3,
                new_val: a4,
                newlen: a5,
            },
            nr::SHARED_REGION_CHECK_NP => MacosSyscallRequest::SharedRegionCheckNp {
                start_address: a0,
            },
            nr::FSTAT64 => MacosSyscallRequest::Fstat64 {
                fd: a0 as i32,
                buf: a1,
            },
            nr::GETENTROPY => MacosSyscallRequest::Getentropy {
                buf: a0,
                count: a1,
            },
```

- [ ] **Step 5: Build and verify**

Run: `cargo build -p litebox_common_macos`
Expected: Compiles successfully (warnings about unused variants are fine, they'll be used in later tasks).

- [ ] **Step 6: Commit**

```bash
git add litebox_common_macos/src/syscall.rs
git commit -m "common_macos: add syscall/mach-trap numbers and request variants for dynamic linking"
```

---

### Task 2: Add new errno variants and syscall dispatch skeleton

Extend errno with values needed for new syscalls. Update `do_syscall` dispatch to route all new variants (initially returning ENOSYS for unimplemented ones). Add Mach trap dispatch.

**Files:**
- Modify: `litebox_common_macos/src/errno.rs`
- Modify: `litebox_shim_macos/src/syscalls/mod.rs`

- [ ] **Step 1: Add missing errno variants**

In `litebox_common_macos/src/errno.rs`, verify these exist (add if missing):
- `ENOENT = 2` (already exists)
- `ENOTTY = 25` (already exists)
- `ESPIPE = 29` (already exists)

All needed errnos already exist. No changes needed.

- [ ] **Step 2: Update do_syscall to dispatch new BSD syscall variants**

In `litebox_shim_macos/src/syscalls/mod.rs`, extend the match in `do_syscall`:

```rust
    pub(crate) fn do_syscall(
        &self,
        request: MacosSyscallRequest,
        _ctx: &mut PtRegs,
    ) -> Result<usize, Errno> {
        match request {
            // Existing handlers unchanged...
            MacosSyscallRequest::Exit { status } => { self.sys_exit(status); Ok(0) }
            MacosSyscallRequest::Read { fd, buf, count } => self.sys_read(fd, buf, count),
            MacosSyscallRequest::Write { fd, buf, count } => self.sys_write(fd, buf, count),
            MacosSyscallRequest::Close { fd } => self.sys_close(fd).map(|()| 0),
            MacosSyscallRequest::Getpid => Ok(self.sys_getpid() as usize),
            MacosSyscallRequest::Getuid => Ok(self.sys_getuid() as usize),
            MacosSyscallRequest::Geteuid => Ok(self.sys_geteuid() as usize),
            MacosSyscallRequest::Getgid => Ok(self.sys_getgid() as usize),
            MacosSyscallRequest::Getegid => Ok(self.sys_getegid() as usize),
            MacosSyscallRequest::Issetugid => Ok(self.sys_issetugid() as usize),
            MacosSyscallRequest::Mmap { addr, length, prot, flags, fd, offset } => {
                self.sys_mmap(addr, length, prot, flags, fd, offset)
            }
            MacosSyscallRequest::Munmap { addr, length } => self.sys_munmap(addr, length),
            MacosSyscallRequest::Mprotect { addr, length, prot } => {
                self.sys_mprotect(addr, length, prot)
            }
            // New handlers:
            MacosSyscallRequest::Open { path, flags, mode } => self.sys_open(path, flags, mode),
            MacosSyscallRequest::Sigaction { signum, new_act, old_act } => {
                self.sys_sigaction(signum, new_act, old_act)
            }
            MacosSyscallRequest::Sigprocmask { how, set, oldset } => {
                self.sys_sigprocmask(how, set, oldset)
            }
            MacosSyscallRequest::Ioctl { fd, request, arg } => self.sys_ioctl(fd, request, arg),
            MacosSyscallRequest::Madvise { addr, length, advice } => {
                self.sys_madvise(addr, length, advice)
            }
            MacosSyscallRequest::Fcntl { fd, cmd, arg } => self.sys_fcntl(fd, cmd, arg),
            MacosSyscallRequest::Pread { fd, buf, count, offset } => {
                self.sys_pread(fd, buf, count, offset)
            }
            MacosSyscallRequest::Csops { pid, ops, useraddr, usersize } => {
                self.sys_csops(pid, ops, useraddr, usersize)
            }
            MacosSyscallRequest::Lseek { fd, offset, whence } => self.sys_lseek(fd, offset, whence),
            MacosSyscallRequest::Sysctl { name, namelen, old, oldlenp, new_val, newlen } => {
                self.sys_sysctl(name, namelen, old, oldlenp, new_val, newlen)
            }
            MacosSyscallRequest::SharedRegionCheckNp { start_address } => {
                self.sys_shared_region_check_np(start_address)
            }
            MacosSyscallRequest::Fstat64 { fd, buf } => self.sys_fstat64(fd, buf),
            MacosSyscallRequest::Getentropy { buf, count } => self.sys_getentropy(buf, count),
            MacosSyscallRequest::MachTrap { number } => self.do_mach_trap(number),
            MacosSyscallRequest::Unknown { number } => {
                log_unsupported!("macOS syscall", number);
                Err(Errno::ENOSYS)
            }
        }
    }
```

- [ ] **Step 3: Add stub implementations for all new syscalls**

Create a new file `litebox_shim_macos/src/syscalls/stubs.rs` with initial stub implementations for the simpler syscalls that just need stub behavior:

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Stub syscall handlers for macOS shim Phase 2.
//!
//! These handlers provide minimal implementations sufficient for dyld
//! bootstrap and hello.c execution.

use litebox_common_macos::errno::Errno;
use litebox_common_macos::syscall::mach_trap;
use crate::{ShimFS, Task, log_unsupported};

impl<FS: ShimFS> Task<FS> {
    /// Handle `sigaction()` — stub: record but don't deliver signals.
    pub(crate) fn sys_sigaction(
        &self,
        _signum: i32,
        _new_act: usize,
        _old_act: usize,
    ) -> Result<usize, Errno> {
        // Stub: pretend we installed the handler. If old_act is non-null,
        // we should write a zeroed sigaction struct there, but for now
        // dyld doesn't check the old action.
        Ok(0)
    }

    /// Handle `sigprocmask()` — stub: return success.
    pub(crate) fn sys_sigprocmask(
        &self,
        _how: i32,
        _set: usize,
        _oldset: usize,
    ) -> Result<usize, Errno> {
        Ok(0)
    }

    /// Handle `madvise()` — stub: return success.
    pub(crate) fn sys_madvise(
        &self,
        _addr: usize,
        _length: usize,
        _advice: i32,
    ) -> Result<usize, Errno> {
        Ok(0)
    }

    /// Handle `csops()` — stub: return success (not code-signed).
    pub(crate) fn sys_csops(
        &self,
        _pid: i32,
        _ops: u32,
        _useraddr: usize,
        _usersize: usize,
    ) -> Result<usize, Errno> {
        Ok(0)
    }

    /// Handle `shared_region_check_np()` — return EINVAL to force dyld's fallback path.
    pub(crate) fn sys_shared_region_check_np(
        &self,
        _start_address: usize,
    ) -> Result<usize, Errno> {
        Err(Errno::EINVAL)
    }

    /// Handle `getentropy()` — fill buffer with pseudo-random bytes.
    pub(crate) fn sys_getentropy(
        &self,
        buf_addr: usize,
        count: usize,
    ) -> Result<usize, Errno> {
        use litebox::platform::RawMutPointer as _;
        if count > 256 {
            return Err(Errno::EIO);
        }
        // Fill with a simple pattern. Not cryptographically secure,
        // but sufficient for stack canary initialization.
        let data: alloc::vec::Vec<u8> = (0..count).map(|i| (i as u8).wrapping_mul(7).wrapping_add(13)).collect();
        let dest: crate::MutPtr<u8> = crate::MutPtr::from_usize(buf_addr);
        dest.copy_from_slice(0, &data).ok_or(Errno::EFAULT)?;
        Ok(0)
    }

    /// Handle `sysctl()` — return canned values for common queries.
    pub(crate) fn sys_sysctl(
        &self,
        _name: usize,
        _namelen: u32,
        _old: usize,
        _oldlenp: usize,
        _new_val: usize,
        _newlen: usize,
    ) -> Result<usize, Errno> {
        // Stub: return ENOENT for all sysctl queries. dyld should handle
        // this gracefully by using fallback values.
        Err(Errno::ENOENT)
    }

    /// Handle `ioctl()` — minimal support for terminal queries.
    pub(crate) fn sys_ioctl(
        &self,
        _fd: i32,
        _request: usize,
        _arg: usize,
    ) -> Result<usize, Errno> {
        // Return ENOTTY for all ioctl requests. This tells callers
        // that the fd is not a terminal.
        Err(Errno::ENOTTY)
    }

    /// Dispatch a Mach trap by trap number.
    pub(crate) fn do_mach_trap(&self, number: usize) -> Result<usize, Errno> {
        match number {
            mach_trap::MACH_REPLY_PORT => Ok(0x0703),
            mach_trap::THREAD_SELF_TRAP => Ok(0x0303),
            mach_trap::TASK_SELF_TRAP => Ok(0x0103),
            mach_trap::HOST_SELF_TRAP => Ok(0x0503),
            mach_trap::MACH_MSG_TRAP => {
                // Return MACH_SEND_INVALID_DEST (0x10000003)
                // Mach traps don't use the carry flag convention, but since
                // we route through the same return path, we return this as
                // a "success" value in x0 (dyld checks x0 directly).
                Ok(0x1000_0003)
            }
            mach_trap::THREAD_GET_SPECIAL_REPLY_PORT => Ok(0x0903),
            _ => {
                log_unsupported!("Mach trap", number);
                Ok(0) // Unknown traps return 0
            }
        }
    }
}
```

- [ ] **Step 4: Add `stubs` module to syscalls/mod.rs**

Add `mod stubs;` to `litebox_shim_macos/src/syscalls/mod.rs` alongside the existing modules.

- [ ] **Step 5: Build and verify**

Run: `cargo build -p litebox_shim_macos`
Expected: Compiles (will have errors for missing sys_open, sys_fstat64, sys_lseek, sys_fcntl, sys_pread — those are implemented in Task 3).

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "shim_macos: add syscall dispatch skeleton and stub handlers for dyld bootstrap"
```

---

### Task 3: Implement file I/O syscalls (open, lseek, fstat64, fcntl, pread)

Implement the file I/O syscalls that dyld needs to open and read dylib files. Add sysroot path rewriting to `sys_open`.

**Files:**
- Modify: `litebox_shim_macos/src/lib.rs` (add `sysroot` to GlobalState and builder)
- Modify: `litebox_shim_macos/src/syscalls/file.rs` (add open, lseek, fstat64, fcntl, pread)

- [ ] **Step 1: Add sysroot to GlobalState and MacosShimBuilder**

In `litebox_shim_macos/src/lib.rs`:

1. Add `sysroot: Option<alloc::string::String>` field to `GlobalState`.
2. Add `sysroot: Option<String>` field to `MacosShimBuilder`.
3. Add `pub fn set_sysroot(&mut self, path: String)` method to `MacosShimBuilder`.
4. Pass sysroot through `build()` into `GlobalState`.

```rust
// In MacosShimBuilder:
pub fn set_sysroot(&mut self, path: String) {
    self.sysroot = Some(path);
}

// In build():
let global = Arc::new(GlobalState {
    // ... existing fields ...
    sysroot: self.sysroot,
});

// In GlobalState:
/// Optional sysroot path for dylib redirection.
sysroot: Option<alloc::string::String>,
```

- [ ] **Step 2: Implement sys_open with sysroot path rewriting**

In `litebox_shim_macos/src/syscalls/file.rs`, add:

```rust
use alloc::string::String;
use alloc::ffi::CString;

impl<FS: ShimFS> Task<FS> {
    /// Handle `open(path, flags, mode)` with sysroot path rewriting.
    pub(crate) fn sys_open(&self, path_addr: usize, flags: i32, _mode: u32) -> Result<usize, Errno> {
        // Read the path string from guest memory
        let path_ptr: ConstPtr<u8> = ConstPtr::from_usize(path_addr);
        let path = read_cstring_from_guest(path_ptr, 4096).ok_or(Errno::EFAULT)?;

        // Apply sysroot rewriting if configured
        let actual_path = if let Some(ref sysroot) = self.global.sysroot {
            if path.starts_with("/usr/lib/") || path.starts_with("/System/Library/") {
                let mut redirected = String::from(sysroot.as_str());
                redirected.push_str(&path);
                redirected
            } else {
                path
            }
        } else {
            path
        };

        // Determine read/write from flags (O_RDONLY=0, O_WRONLY=1, O_RDWR=2)
        let access_mode = flags & 0x3;
        let for_reading = access_mode == 0 || access_mode == 2; // O_RDONLY or O_RDWR
        let for_writing = access_mode == 1 || access_mode == 2; // O_WRONLY or O_RDWR

        let cpath = CString::new(actual_path.as_bytes()).map_err(|_| Errno::EINVAL)?;
        let litebox_path = litebox::fs::Path::try_from(cpath.as_ref()).map_err(|_| Errno::EINVAL)?;

        let fd = self.global.fs.open(&litebox_path, for_reading, for_writing)
            .map_err(|e| Self::open_error_to_errno(e))?;

        let raw_fd = {
            let mut rds = self.global.raw_descriptors.write();
            rds.assign_fd(fd).map_err(|_| Errno::EMFILE)?
        };

        Ok(raw_fd)
    }

    /// Convert an `OpenError` to a macOS errno.
    fn open_error_to_errno(e: litebox::fs::errors::OpenError) -> Errno {
        match e {
            litebox::fs::errors::OpenError::NotFound => Errno::ENOENT,
            litebox::fs::errors::OpenError::IsADirectory => Errno::EISDIR,
            litebox::fs::errors::OpenError::PermissionDenied => Errno::EACCES,
            _ => Errno::EIO,
        }
    }
}

/// Read a C string from guest memory (up to max_len bytes).
fn read_cstring_from_guest(ptr: ConstPtr<u8>, max_len: usize) -> Option<String> {
    use litebox::platform::RawConstPointer as _;
    let bytes = ptr.to_owned_slice(max_len)?;
    let nul_pos = bytes.iter().position(|&b| b == 0)?;
    String::from_utf8(bytes[..nul_pos].to_vec()).ok()
}
```

- [ ] **Step 3: Implement sys_lseek**

```rust
    /// Handle `lseek(fd, offset, whence)`.
    pub(crate) fn sys_lseek(&self, fd: i32, offset: i64, whence: i32) -> Result<usize, Errno> {
        let raw_fd = fd_to_usize(fd)?;
        let typed_fd = {
            let rds = self.global.raw_descriptors.read();
            rds.fd_from_raw_integer::<FS>(raw_fd).map_err(|_| Errno::EBADF)?
        };

        let seek_from = match whence {
            0 => litebox::fs::SeekFrom::Start(offset as u64),    // SEEK_SET
            1 => litebox::fs::SeekFrom::Current(offset),          // SEEK_CUR
            2 => litebox::fs::SeekFrom::End(offset),              // SEEK_END
            _ => return Err(Errno::EINVAL),
        };

        let new_pos = self.global.fs.seek(&typed_fd, seek_from).map_err(|_| Errno::ESPIPE)?;
        Ok(new_pos as usize)
    }
```

- [ ] **Step 4: Implement sys_pread**

```rust
    /// Handle `pread(fd, buf, count, offset)` — positional read.
    pub(crate) fn sys_pread(
        &self,
        fd: i32,
        buf_addr: usize,
        count: usize,
        offset: i64,
    ) -> Result<usize, Errno> {
        let raw_fd = fd_to_usize(fd)?;
        let typed_fd = {
            let rds = self.global.raw_descriptors.read();
            rds.fd_from_raw_integer::<FS>(raw_fd).map_err(|_| Errno::EBADF)?
        };

        let read_len = count.min(MAX_KERNEL_BUF_SIZE);
        let mut kernel_buf = vec![0u8; read_len];
        let size = self.global.fs
            .read(&typed_fd, &mut kernel_buf, Some(offset as u64))
            .map_err(Self::read_error_to_errno)?;

        let user_buf: MutPtr<u8> = MutPtr::from_usize(buf_addr);
        user_buf.copy_from_slice(0, &kernel_buf[..size]).ok_or(Errno::EFAULT)?;

        Ok(size)
    }
```

- [ ] **Step 5: Implement sys_fstat64**

```rust
    /// Handle `fstat64(fd, buf)`.
    ///
    /// Writes a macOS `stat64` structure to the buffer.
    /// The struct layout on aarch64 macOS is 144 bytes.
    pub(crate) fn sys_fstat64(&self, fd: i32, buf_addr: usize) -> Result<usize, Errno> {
        let raw_fd = fd_to_usize(fd)?;
        let typed_fd = {
            let rds = self.global.raw_descriptors.read();
            rds.fd_from_raw_integer::<FS>(raw_fd).map_err(|_| Errno::EBADF)?
        };

        let metadata = self.global.fs.fstat(&typed_fd).map_err(|_| Errno::EBADF)?;

        // Build a macOS stat64 struct (144 bytes on aarch64).
        // Most fields are zero; we fill in st_size and st_mode.
        let mut stat_buf = [0u8; 144];
        let size = metadata.size();
        let mode: u16 = 0o100644; // S_IFREG | 0644

        // st_mode at offset 4 (u16)
        stat_buf[4..6].copy_from_slice(&mode.to_le_bytes());
        // st_size at offset 96 (i64)
        stat_buf[96..104].copy_from_slice(&(size as i64).to_le_bytes());

        let dest: MutPtr<u8> = MutPtr::from_usize(buf_addr);
        dest.copy_from_slice(0, &stat_buf).ok_or(Errno::EFAULT)?;

        Ok(0)
    }
```

- [ ] **Step 6: Implement sys_fcntl**

```rust
    /// Handle `fcntl(fd, cmd, arg)` — minimal support.
    pub(crate) fn sys_fcntl(&self, fd: i32, cmd: i32, _arg: usize) -> Result<usize, Errno> {
        let _raw_fd = fd_to_usize(fd)?;

        // F_GETFL = 3, F_SETFL = 4, F_GETPATH = 50
        match cmd {
            3 => Ok(0),       // F_GETFL: return O_RDONLY
            4 => Ok(0),       // F_SETFL: pretend success
            50 => Err(Errno::EBADF), // F_GETPATH: not supported yet
            _ => Err(Errno::EINVAL),
        }
    }
```

- [ ] **Step 7: Build and verify**

Run: `cargo build -p litebox_shim_macos`
Expected: Compiles successfully.

- [ ] **Step 8: Run existing tests to verify no regression**

Run: `cargo test -p litebox_runner_macos_on_macos_userland`
Expected: All 3 existing tests pass.

- [ ] **Step 9: Commit**

```bash
git add -A
git commit -m "shim_macos: implement file I/O syscalls (open, lseek, pread, fstat64, fcntl) with sysroot path rewriting"
```

---

### Task 4: Add `patch_code_segment` API to the Mach-O rewriter

Add the segment-level rewriting API that the mmap-hook will call at runtime to patch individual code segments.

**Files:**
- Modify: `litebox_syscall_rewriter_macho/src/arm64.rs` (make instruction encoders and emit functions pub(crate) → pub as needed)
- Modify: `litebox_syscall_rewriter_macho/src/lib.rs` (add `patch_code_segment` public function)

- [ ] **Step 1: Make `arm64` module public**

In `litebox_syscall_rewriter_macho/src/lib.rs`, change:
```rust
mod arm64;
```
to:
```rust
pub mod arm64;
```

This exposes `SVC_0X80`, `find_patch_sites`, `TextSectionInfo`, `PatchSite`, `PatchKind`, and the trampoline emission functions.

- [ ] **Step 2: Make trampoline emission functions public**

In `litebox_syscall_rewriter_macho/src/arm64.rs`, change visibility of:
- `emit_shared_svc_handler_macos` → `pub`
- `emit_svc_gate_macos` → `pub`
- `encode_b` → `pub` (needed for patching original instructions)
- `SHARED_SVC_HANDLER_OFFSET` → `pub`
- `SHARED_SVC_HANDLER_SIZE` → `pub`
- `SVC_GATE_SIZE` → `pub`
- `HEADER_CALLBACK_OFFSET` → already `pub`
- `HEADER_TLS_TABLE_OFFSET` → already `pub`

- [ ] **Step 3: Implement `patch_code_segment`**

Add to `litebox_syscall_rewriter_macho/src/lib.rs`:

```rust
/// Patch `SVC #0x80` sites in a single mapped code segment.
///
/// This function is used by the mmap-hook at runtime to patch dylib code
/// segments as they are loaded by dyld. Unlike `hook_syscalls_in_macho` which
/// operates on a complete Mach-O file, this function works on a raw code buffer
/// at a known virtual address.
///
/// # Arguments
/// - `code`: Mutable code segment bytes. SVC instructions are replaced in-place with `B` to stubs.
/// - `code_vaddr`: Virtual address where this code segment is mapped.
/// - `trampoline_buf`: Mutable buffer for writing trampoline stubs (must be pre-allocated).
/// - `trampoline_vaddr`: Virtual address of the trampoline buffer start.
/// - `trampoline_cursor`: Current write offset in the trampoline buffer (stubs are appended here).
/// - `syscall_entry`: Address of the shim's syscall entry point (written at trampoline offset 0).
///
/// # Returns
/// The new trampoline cursor position (byte offset past the last written stub).
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub fn patch_code_segment(
    code: &mut [u8],
    code_vaddr: u64,
    trampoline_buf: &mut [u8],
    trampoline_vaddr: u64,
    trampoline_cursor: usize,
    syscall_entry: u64,
) -> Result<usize> {
    // Scan for SVC #0x80 sites in the code buffer
    let mut sites = Vec::new();
    let mut offset = 0usize;
    while offset + 4 <= code.len() {
        let insn = u32::from_le_bytes(code[offset..offset + 4].try_into().unwrap());
        if insn == arm64::SVC_0X80 {
            sites.push(arm64::PatchSite {
                file_offset: offset,
                vaddr: code_vaddr + offset as u64,
                kind: arm64::PatchKind::Svc,
            });
        }
        offset += 4;
    }

    if sites.is_empty() {
        return Ok(trampoline_cursor);
    }

    // If this is the first call (cursor is at the header position), emit the
    // shared handler first.
    let mut cursor = trampoline_cursor;
    let need_shared_handler = cursor <= arm64::SHARED_SVC_HANDLER_OFFSET;

    if need_shared_handler {
        // Write header: callback addr at offset 0, TLS table ptr at offset 8
        trampoline_buf[arm64::HEADER_CALLBACK_OFFSET..arm64::HEADER_CALLBACK_OFFSET + 8]
            .copy_from_slice(&syscall_entry.to_le_bytes());
        // TLS table ptr will be filled in by the loader's trampoline init
        // (offset 8 stays zero for now — the runtime will set it)

        // Emit shared SVC handler
        let mut handler_data = Vec::new();
        // We need the handler at SHARED_SVC_HANDLER_OFFSET in the trampoline
        // First, pad handler_data to match offset within trampoline_buf
        arm64::emit_shared_svc_handler_macos(
            &mut handler_data,
            0,
            trampoline_vaddr,
        )?;
        let handler_start = arm64::SHARED_SVC_HANDLER_OFFSET;
        let handler_end = handler_start + handler_data.len();
        if handler_end > trampoline_buf.len() {
            return Err(Error::ParseError("trampoline buffer too small for shared handler".into()));
        }
        trampoline_buf[handler_start..handler_end].copy_from_slice(&handler_data);
        cursor = handler_end;
    }

    // Emit per-site SVC gates
    for site in &sites {
        let gate_offset = cursor;
        let gate_vaddr = trampoline_vaddr + gate_offset as u64;

        // Build the gate
        let mut gate_data = Vec::new();
        arm64::emit_svc_gate_macos(
            &mut gate_data,
            0,           // offset within gate_data
            trampoline_vaddr, // need to adjust: the gate uses trampoline_base for handler ref
            site,
        )?;

        // Wait — emit_svc_gate_macos uses trampoline_base_addr to compute the
        // B to shared_svc_handler. But the gate_offset parameter is the offset
        // within trampoline_data, and it uses trampoline_base_addr + SHARED_SVC_HANDLER_OFFSET
        // for the branch target. This works because the shared handler is always
        // at SHARED_SVC_HANDLER_OFFSET from the trampoline base.
        //
        // However, emit_svc_gate_macos expects gate_offset to be the offset of
        // this gate within the trampoline_data vec. We're passing 0 because we're
        // building into a fresh vec. We need to re-emit with the correct offsets.

        // Actually, let's just use the existing functions correctly:
        // emit_svc_gate_macos appends to a Vec and computes addresses from
        // (trampoline_base_addr + gate_offset). We need to match that.
        let mut gate_vec = Vec::new();
        arm64::emit_svc_gate_macos(
            &mut gate_vec,
            0,
            // The gate's virtual address for address computation:
            // We pass gate_vaddr as the base, and 0 as the offset,
            // but the function computes gate_vaddr = base + offset = gate_vaddr + 0
            // For the B to shared handler, it computes:
            //   handler_vaddr = base + SHARED_SVC_HANDLER_OFFSET
            // So we need base = trampoline_vaddr (not gate_vaddr)
            trampoline_vaddr,
            // But then gate_offset should be `gate_offset` not 0...
            // Let me re-read the function signature:
            // emit_svc_gate_macos(trampoline_data, gate_offset, trampoline_base_addr, site)
            // gate_vaddr = trampoline_base_addr + gate_offset
            // So: emit with gate_offset = cursor, but we can't because trampoline_data
            // starts from empty. The function does:
            //   trampoline_data.extend_from_slice(...)
            // and expects trampoline_data.len() - gate_offset == SVC_GATE_SIZE at the end.
            //
            // Solution: we need a temporary vec and then copy.
            site,
        )?;

        // Hmm, the existing emit functions are designed to append to a Vec, not
        // write at arbitrary offsets in a slice. For patch_code_segment we need
        // to write into a pre-allocated mutable slice. Let me take a different
        // approach: build a temporary Vec, then copy into the slice.

        if gate_offset + gate_vec.len() > trampoline_buf.len() {
            return Err(Error::ParseError("trampoline buffer too small for gate".into()));
        }
        trampoline_buf[gate_offset..gate_offset + gate_vec.len()].copy_from_slice(&gate_vec);

        // Patch the original SVC instruction with B <gate>
        let b_offset = gate_vaddr as i64 - site.vaddr as i64;
        let b_insn = arm64::encode_b(b_offset).ok_or_else(|| {
            Error::DisassemblyFailure(format!(
                "B offset {b_offset:#x} out of ±128MB range for SVC at {:#x}",
                site.vaddr
            ))
        })?;
        code[site.file_offset..site.file_offset + 4].copy_from_slice(&b_insn.to_le_bytes());

        cursor = gate_offset + gate_vec.len();
    }

    Ok(cursor)
}
```

Wait — I realize the approach above has a fundamental issue. The `emit_svc_gate_macos` function takes a `gate_offset` parameter that represents the offset of the gate within the trampoline vec, and uses it to compute absolute addresses. When we call it with `gate_offset=0` on a fresh vec, the address computation for the `B` to shared handler will be wrong.

Let me rethink. The cleanest approach is to create a new `patch_code_segment` function in `arm64.rs` that directly writes to slices:

- [ ] **Step 3 (revised): Implement patch_code_segment in arm64.rs**

Add a new public function to `arm64.rs`:

```rust
/// Patch SVC #0x80 sites in a code buffer, emitting stubs into a trampoline slice.
///
/// Returns the new trampoline cursor (byte offset past last written data).
#[allow(clippy::cast_possible_wrap)]
pub fn patch_code_segment(
    code: &mut [u8],
    code_vaddr: u64,
    trampoline: &mut [u8],
    trampoline_vaddr: u64,
    mut cursor: usize,
    syscall_entry: u64,
) -> Result<usize> {
    // Scan for SVC #0x80
    let mut sites = Vec::new();
    {
        let mut off = 0usize;
        while off + 4 <= code.len() {
            let insn = u32::from_le_bytes(code[off..off + 4].try_into().unwrap());
            if insn == SVC_0X80 {
                sites.push(PatchSite {
                    file_offset: off,
                    vaddr: code_vaddr + off as u64,
                    kind: PatchKind::Svc,
                });
            }
            off += 4;
        }
    }

    if sites.is_empty() {
        return Ok(cursor);
    }

    // If header not yet written (cursor == 0), write header + shared handler.
    if cursor == 0 {
        if trampoline.len() < SHARED_SVC_HANDLER_OFFSET + SHARED_SVC_HANDLER_SIZE {
            return Err(Error::ParseError("trampoline too small".into()));
        }
        // Write syscall entry at offset 0
        trampoline[0..8].copy_from_slice(&syscall_entry.to_le_bytes());
        // TLS table ptr at offset 8 — left as zero, caller fills it in.

        // Emit shared handler into a temp vec, then copy
        let mut handler_vec = Vec::new();
        emit_shared_svc_handler_macos(&mut handler_vec, 0, trampoline_vaddr)?;
        trampoline[SHARED_SVC_HANDLER_OFFSET..SHARED_SVC_HANDLER_OFFSET + handler_vec.len()]
            .copy_from_slice(&handler_vec);
        cursor = SHARED_SVC_HANDLER_OFFSET + handler_vec.len();
    }

    // Emit per-site gates
    for site in &sites {
        let gate_vaddr = trampoline_vaddr + cursor as u64;

        // Build gate into temp vec. We pass trampoline_vaddr as base and cursor as
        // gate_offset, then collect into a fresh vec by using a wrapper approach.
        //
        // Actually, emit_svc_gate_macos appends to the vec. If we give it a vec
        // that already has `cursor` bytes, then gate_offset = cursor, it will work.
        // But that wastes memory. Instead, let's just build the 7 instructions directly.
        let return_addr = site.vaddr + 4;

        let mut gate = [0u8; SVC_GATE_SIZE];
        let mut gi = 0usize;
        let put = |gate: &mut [u8], gi: &mut usize, insn: u32| {
            gate[*gi..*gi + 4].copy_from_slice(&insn.to_le_bytes());
            *gi += 4;
        };

        // [0] SUB SP, SP, #48
        put(&mut gate, &mut gi, encode_sub_sp_imm(48).expect("48 fits"));
        // [1] STP X16, X17, [SP]
        put(&mut gate, &mut gi, encode_stp_offset(16, 17, 31, 0).expect("valid"));
        // [2] STR X30, [SP, #16]
        put(&mut gate, &mut gi, encode_str_imm_unsigned(30, 31, 16).expect("valid"));
        // [3] STR X18, [SP, #32]
        put(&mut gate, &mut gi, encode_str_imm_unsigned(18, 31, 32).expect("valid"));
        // [4] ADRP X30, <return_page>
        let adrp_vaddr = gate_vaddr + 4 * 4;
        let adrp_base = adrp_vaddr & !0xFFF;
        let return_page = return_addr & !0xFFF;
        let page_offset = (return_page as i64 - adrp_base as i64) >> 12;
        let adrp_insn = encode_adrp(30, page_offset).ok_or_else(|| {
            Error::DisassemblyFailure(format!("ADRP out of range for SVC at {:#x}", site.vaddr))
        })?;
        put(&mut gate, &mut gi, adrp_insn);
        // [5] ADD X30, X30, #pageoff
        let pageoff = (return_addr & 0xFFF) as u16;
        put(&mut gate, &mut gi, encode_add_imm(30, 30, pageoff).expect("fits"));
        // [6] B <shared_svc_handler>
        let handler_vaddr = trampoline_vaddr + SHARED_SVC_HANDLER_OFFSET as u64;
        let b_to_handler = handler_vaddr as i64 - (gate_vaddr + 6 * 4) as i64;
        let b_insn = encode_b(b_to_handler).ok_or_else(|| {
            Error::DisassemblyFailure(format!("B to handler out of range for gate at {gate_vaddr:#x}"))
        })?;
        put(&mut gate, &mut gi, b_insn);

        debug_assert_eq!(gi, SVC_GATE_SIZE);

        // Copy gate into trampoline
        if cursor + SVC_GATE_SIZE > trampoline.len() {
            return Err(Error::ParseError("trampoline buffer too small for gate".into()));
        }
        trampoline[cursor..cursor + SVC_GATE_SIZE].copy_from_slice(&gate);

        // Patch original SVC → B <gate>
        let b_offset = gate_vaddr as i64 - site.vaddr as i64;
        let b_insn = encode_b(b_offset).ok_or_else(|| {
            Error::DisassemblyFailure(format!(
                "B offset {b_offset:#x} out of ±128MB for SVC at {:#x}", site.vaddr
            ))
        })?;
        code[site.file_offset..site.file_offset + 4].copy_from_slice(&b_insn.to_le_bytes());

        cursor += SVC_GATE_SIZE;
    }

    Ok(cursor)
}
```

- [ ] **Step 4: Add re-export in lib.rs**

In `litebox_syscall_rewriter_macho/src/lib.rs`, add:

```rust
pub use arm64::patch_code_segment;
```

- [ ] **Step 5: Build and verify**

Run: `cargo build -p litebox_syscall_rewriter_macho`
Expected: Compiles successfully.

- [ ] **Step 6: Run existing tests**

Run: `cargo test -p litebox_runner_macos_on_macos_userland`
Expected: All 3 existing tests still pass.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "rewriter_macho: add patch_code_segment API for runtime mmap-hook patching"
```

---

### Task 5: Implement mmap-hook in the shim's mmap handler

Add `MachoPatchState` tracking and intercept `mmap(PROT_EXEC)` calls to patch code segments on the fly.

**Files:**
- Modify: `litebox_shim_macos/src/lib.rs` (add patch_cache to Task)
- Modify: `litebox_shim_macos/src/syscalls/mm.rs` (add mmap-hook logic)
- Modify: `litebox_shim_macos/Cargo.toml` (add litebox_syscall_rewriter_macho dependency)

- [ ] **Step 1: Add litebox_syscall_rewriter_macho dependency to shim**

In `litebox_shim_macos/Cargo.toml`, add:

```toml
litebox_syscall_rewriter_macho = { version = "0.1.0", path = "../litebox_syscall_rewriter_macho" }
```

- [ ] **Step 2: Add MachoPatchState and patch_cache to Task**

In `litebox_shim_macos/src/lib.rs`:

```rust
use alloc::collections::BTreeMap;

/// Per-fd state for tracking mmap-hook code patching.
pub(crate) struct MachoPatchState {
    /// VA of the allocated trampoline region.
    pub(crate) trampoline_addr: usize,
    /// Next write offset in the trampoline buffer.
    pub(crate) trampoline_cursor: usize,
    /// Whether the trampoline page has been allocated.
    pub(crate) trampoline_mapped: bool,
}

// Add to Task:
struct Task<FS: ShimFS> {
    global: Arc<GlobalState<FS>>,
    terminated: Cell<bool>,
    exit_code: Arc<AtomicI32>,
    /// Per-fd patch state for the mmap-hook. Tracks trampoline allocation
    /// and cursor for each fd that has had executable segments mapped.
    patch_cache: core::cell::RefCell<BTreeMap<i32, MachoPatchState>>,
}
```

Update the Task constructor in `load_program` to initialize `patch_cache: core::cell::RefCell::new(BTreeMap::new())`.

- [ ] **Step 3: Add mmap-hook logic to sys_mmap**

In `litebox_shim_macos/src/syscalls/mm.rs`, modify `sys_mmap` to detect PROT_EXEC + file-backed mappings and patch them:

```rust
    pub(crate) fn sys_mmap(
        &self,
        addr: usize,
        length: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> Result<usize, Errno> {
        // ... existing validation ...

        let is_anon = (flags & MAP_ANON as i32) != 0;
        let has_exec = (prot & PROT_EXEC as i32) != 0;

        if is_anon {
            // Anonymous mapping — existing logic unchanged
            // ...
        } else if has_exec && fd >= 0 {
            // File-backed executable mapping — mmap-hook!
            self.sys_mmap_exec_hook(addr, length, prot, flags, fd, offset)
        } else {
            // File-backed non-exec mapping — existing logic
            // ...
        }
    }

    /// mmap-hook: intercept file-backed PROT_EXEC mappings and patch SVC sites.
    fn sys_mmap_exec_hook(
        &self,
        addr: usize,
        length: usize,
        _prot: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> Result<usize, Errno> {
        let aligned_length = align_up(length, PAGE_SIZE);

        // Determine target address
        let is_fixed = (flags & MAP_FIXED as i32) != 0;
        let target_addr = if is_fixed && addr != 0 {
            addr
        } else {
            // Let the page manager pick an address
            0
        };

        // Allocate anonymous RW pages
        let rw_flags = litebox_common_linux::MapFlags::MAP_ANONYMOUS
            | litebox_common_linux::MapFlags::MAP_PRIVATE
            | if is_fixed { litebox_common_linux::MapFlags::MAP_FIXED } else { litebox_common_linux::MapFlags::empty() };
        let mapped_addr = litebox_common_linux::mm::do_mmap(
            &self.global.pm,
            if target_addr != 0 { Some(target_addr) } else { None },
            aligned_length,
            litebox_common_linux::ProtFlags::PROT_READ_WRITE,
            rw_flags,
            false,
            |_| Ok(0),
        ).map_err(|_| Errno::ENOMEM)?.as_usize();

        // Read file content into a buffer
        let raw_fd_usize = usize::try_from(fd).map_err(|_| Errno::EBADF)?;
        let typed_fd = {
            let rds = self.global.raw_descriptors.read();
            rds.fd_from_raw_integer::<FS>(raw_fd_usize).map_err(|_| Errno::EBADF)?
        };

        let mut code_buf = alloc::vec![0u8; length];
        let _bytes_read = self.global.fs
            .read(&typed_fd, &mut code_buf, Some(offset as u64))
            .map_err(|_| Errno::EIO)?;

        // Allocate trampoline if not yet done for this fd
        let syscall_entry = litebox_platform_multiplex::platform().get_syscall_entry_point();
        let mut cache = self.patch_cache.borrow_mut();
        let state = cache.entry(fd).or_insert_with(|| {
            // Allocate trampoline page near the code (within ±128MB for B instruction)
            // Use a 16KB page for the trampoline
            let trampoline_size = 16384; // 16KB — enough for many stubs
            let trampoline_hint = mapped_addr.wrapping_add(aligned_length);
            let trampoline_flags = litebox_common_linux::MapFlags::MAP_ANONYMOUS
                | litebox_common_linux::MapFlags::MAP_PRIVATE;
            let trampoline_addr = litebox_common_linux::mm::do_mmap(
                &self.global.pm,
                Some(trampoline_hint),
                trampoline_size,
                litebox_common_linux::ProtFlags::PROT_READ_WRITE,
                trampoline_flags,
                false,
                |_| Ok(0),
            ).expect("trampoline allocation").as_usize();

            MachoPatchState {
                trampoline_addr,
                trampoline_cursor: 0,
                trampoline_mapped: true,
            }
        });

        // Patch the code buffer
        let trampoline_size = 16384usize;
        let trampoline_slice = unsafe {
            core::slice::from_raw_parts_mut(
                state.trampoline_addr as *mut u8,
                trampoline_size,
            )
        };

        let new_cursor = litebox_syscall_rewriter_macho::patch_code_segment(
            &mut code_buf,
            mapped_addr as u64,
            trampoline_slice,
            state.trampoline_addr as u64,
            state.trampoline_cursor,
            syscall_entry as u64,
        ).map_err(|_| Errno::EINVAL)?;

        state.trampoline_cursor = new_cursor;

        // Copy patched code into the mapped pages
        let dest: crate::MutPtr<u8> = crate::MutPtr::from_usize(mapped_addr);
        dest.copy_from_slice(0, &code_buf).ok_or(Errno::EFAULT)?;

        // Set final protection to R-X
        litebox_common_linux::mm::sys_mprotect(
            &self.global.pm,
            crate::MutPtr::from_usize(mapped_addr),
            aligned_length,
            litebox_common_linux::ProtFlags::PROT_READ_EXEC,
        ).map_err(|_| Errno::ENOMEM)?;

        Ok(mapped_addr)
    }
```

- [ ] **Step 4: Finalize trampoline on close(fd)**

In `litebox_shim_macos/src/syscalls/file.rs`, modify `sys_close` to finalize the trampoline:

```rust
    pub(crate) fn sys_close(&self, fd: i32) -> Result<(), Errno> {
        // Finalize any mmap-hook trampoline for this fd
        if let Some(state) = self.patch_cache.borrow_mut().remove(&fd) {
            if state.trampoline_mapped && state.trampoline_cursor > 0 {
                // mprotect trampoline from RW to RX
                let trampoline_size = 16384usize;
                let _ = litebox_common_linux::mm::sys_mprotect(
                    &self.global.pm,
                    crate::MutPtr::from_usize(state.trampoline_addr),
                    trampoline_size,
                    litebox_common_linux::ProtFlags::PROT_READ_EXEC,
                );
            }
        }

        // Existing close logic
        let raw_fd = fd_to_usize(fd)?;
        let typed_fd = {
            let mut rds = self.global.raw_descriptors.write();
            rds.fd_consume_raw_integer::<FS>(raw_fd).map_err(|_| Errno::EBADF)?
        };
        self.global.fs.close(&typed_fd).map_err(|_| Errno::EIO)
    }
```

- [ ] **Step 5: Build and verify**

Run: `cargo build -p litebox_shim_macos`
Expected: Compiles successfully.

- [ ] **Step 6: Verify no regression**

Run: `cargo test -p litebox_runner_macos_on_macos_userland`
Expected: All 3 existing tests still pass (they don't use file-backed exec mmaps).

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "shim_macos: implement mmap-hook for on-the-fly code patching of dylib executable segments"
```

---

### Task 6: Implement dyld loading (universal binary parsing, segment mapping, apple stack)

Extend the loader to parse `/usr/lib/dyld` (fat/universal binary), rewrite and map it, set up the apple array on the stack, and select dyld's entry point.

**Files:**
- Modify: `litebox_shim_macos/src/loader/mod.rs` (add `DyldLoadInfo`, extend `MachoLoadInfo`)
- Modify: `litebox_shim_macos/src/loader/macho.rs` (add `load_dyld`, fat binary parsing, detect LC_LOAD_DYLINKER)
- Modify: `litebox_shim_macos/src/loader/stack.rs` (add apple array support)
- Modify: `litebox_shim_macos/src/lib.rs` (pass dyld bytes to loader)

- [ ] **Step 1: Add fat/universal binary parsing**

In `litebox_shim_macos/src/loader/macho.rs`, add a function to extract the arm64 slice from a universal binary:

```rust
/// Extract the arm64/arm64e slice from a universal (fat) Mach-O binary.
///
/// Returns the byte range (offset, size) of the arm64 slice within the input.
/// If the input is not a fat binary, returns None.
pub(crate) fn extract_arm64_slice(data: &[u8]) -> Option<(usize, usize)> {
    if data.len() < 8 {
        return None;
    }
    let magic = u32::from_be_bytes(data[0..4].try_into().ok()?);
    if magic != 0xCAFEBABE && magic != 0xBEBAFECA {
        return None; // Not a fat binary
    }
    let nfat_arch = u32::from_be_bytes(data[4..8].try_into().ok()?);

    // Each fat_arch entry is 20 bytes: cputype(4), cpusubtype(4), offset(4), size(4), align(4)
    for i in 0..nfat_arch as usize {
        let entry_offset = 8 + i * 20;
        if entry_offset + 20 > data.len() {
            return None;
        }
        let cputype = u32::from_be_bytes(data[entry_offset..entry_offset + 4].try_into().ok()?);
        // CPU_TYPE_ARM64 = 0x0100000C (16777228)
        if cputype == 0x0100000C {
            let offset = u32::from_be_bytes(
                data[entry_offset + 8..entry_offset + 12].try_into().ok()?,
            ) as usize;
            let size = u32::from_be_bytes(
                data[entry_offset + 12..entry_offset + 16].try_into().ok()?,
            ) as usize;
            return Some((offset, size));
        }
    }
    None
}
```

- [ ] **Step 2: Add load_dyld function**

Add a function that loads dyld's segments, rewriting SVC sites and extracting the LC_UNIXTHREAD entry:

```rust
/// Information about the loaded dyld.
pub(crate) struct DyldLoadInfo {
    /// The entry point address (from LC_UNIXTHREAD, with slide applied).
    pub(crate) entry_point: usize,
    /// The slide applied to dyld's segments.
    pub(crate) slide: usize,
}

/// Load `/usr/lib/dyld` into the guest address space.
///
/// Parses the fat binary, extracts the arm64 slice, rewrites SVC sites,
/// maps segments with the reserve-then-map pattern, and returns the entry point.
pub(crate) fn load_dyld<FS: ShimFS>(
    task: &Task<FS>,
    dyld_data: &[u8],
) -> Result<DyldLoadInfo, MachoLoaderError> {
    // Extract arm64 slice from universal binary
    let slice_data = if let Some((offset, size)) = extract_arm64_slice(dyld_data) {
        &dyld_data[offset..offset + size]
    } else {
        // Maybe it's already a thin binary
        dyld_data
    };

    // Rewrite SVC #0x80 instructions in dyld
    let rewritten = litebox_syscall_rewriter_macho::hook_syscalls_in_macho(slice_data)
        .map_err(|e| MachoLoaderError::ParseError(alloc::format!("rewrite dyld: {e}")))?;

    // Parse the rewritten dyld (same as load() but we only need segments + LC_UNIXTHREAD)
    let header = macho::MachHeader64::<Endianness>::parse(&rewritten, 0)
        .map_err(|e| MachoLoaderError::ParseError(alloc::format!("dyld header: {e}")))?;
    let endian = header.endian()
        .map_err(|e| MachoLoaderError::ParseError(alloc::format!("dyld endianness: {e}")))?;

    // dyld is MH_DYLINKER (7), not MH_EXECUTE
    let filetype = header.filetype(endian);
    if filetype != 0x7 {
        // MH_DYLINKER = 7
        return Err(MachoLoaderError::UnsupportedFormat);
    }

    let mut segments = Vec::new();
    let mut entry_point_raw: Option<u64> = None;

    let mut commands = header.load_commands(endian, &rewritten, 0)
        .map_err(|e| MachoLoaderError::ParseError(alloc::format!("dyld commands: {e}")))?;

    while let Some(cmd) = commands.next()
        .map_err(|e| MachoLoaderError::ParseError(alloc::format!("dyld iterate: {e}")))?
    {
        if let Some((seg, _)) = cmd.segment_64()
            .map_err(|e| MachoLoaderError::ParseError(alloc::format!("dyld segment: {e}")))?
        {
            let name = &seg.segname;
            if *name == *b"__PAGEZERO\0\0\0\0\0\0" {
                continue;
            }
            segments.push(SegmentInfo {
                vmaddr: seg.vmaddr.get(endian),
                vmsize: seg.vmsize.get(endian),
                fileoff: seg.fileoff.get(endian),
                filesize: seg.filesize.get(endian),
                initprot: seg.initprot.get(endian),
                segname: *name,
            });
        }

        // LC_UNIXTHREAD for dyld entry
        if cmd.cmd() == macho::LC_UNIXTHREAD {
            let cmd_data = cmd.raw_data();
            let pc_offset = 16 + 32 * 8;
            if cmd_data.len() >= pc_offset + 8 {
                let pc = u64::from_le_bytes(cmd_data[pc_offset..pc_offset + 8].try_into().unwrap());
                entry_point_raw = Some(pc);
            }
        }
    }

    if segments.is_empty() {
        return Err(MachoLoaderError::NoTextSegment);
    }

    // Reserve-then-map (same pattern as load())
    let min_vmaddr = segments.iter().filter(|s| s.vmsize > 0).map(|s| s.vmaddr as usize).min().unwrap_or(DEFAULT_LOW_ADDR);
    let max_vmend = segments.iter().filter(|s| s.vmsize > 0).map(|s| (s.vmaddr + s.vmsize) as usize).max().unwrap_or(DEFAULT_LOW_ADDR);
    let page_aligned_min = min_vmaddr & !(PAGE_SIZE - 1);
    let page_aligned_max = max_vmend.next_multiple_of(PAGE_SIZE);
    let total_span = page_aligned_max - page_aligned_min;

    let reserve_flags = litebox_common_linux::MapFlags::MAP_ANONYMOUS | litebox_common_linux::MapFlags::MAP_PRIVATE;
    let reserved_base = litebox_common_linux::mm::do_mmap(
        &task.global.pm,
        Some(DEFAULT_LOW_ADDR + 0x1000_0000), // Hint: 256MB above default to avoid main binary
        total_span,
        litebox_common_linux::ProtFlags::PROT_NONE,
        reserve_flags,
        false,
        |_| Ok(0),
    ).map_err(|e| MachoLoaderError::MappingError(alloc::format!("reserve dyld: {e:?}")))?.as_usize();

    let slide = reserved_base.wrapping_sub(page_aligned_min);

    // Map segments
    for seg in &segments {
        if seg.vmsize == 0 { continue; }
        let vm_addr = (seg.vmaddr as usize).wrapping_add(slide);
        let vm_size = (seg.vmsize as usize).next_multiple_of(PAGE_SIZE);
        let flags = litebox_common_linux::MapFlags::MAP_ANONYMOUS | litebox_common_linux::MapFlags::MAP_PRIVATE | litebox_common_linux::MapFlags::MAP_FIXED;

        litebox_common_linux::mm::do_mmap(&task.global.pm, Some(vm_addr), vm_size, litebox_common_linux::ProtFlags::PROT_READ_WRITE, flags, false, |_| Ok(0))
            .map_err(|e| MachoLoaderError::MappingError(alloc::format!("map dyld seg: {e:?}")))?;

        let file_size = seg.filesize as usize;
        if file_size > 0 {
            let file_off = seg.fileoff as usize;
            if file_off + file_size > rewritten.len() {
                return Err(MachoLoaderError::ParseError("dyld segment past EOF".into()));
            }
            let dest: MutPtr<u8> = MutPtr::from_usize(vm_addr);
            dest.copy_from_slice(0, &rewritten[file_off..file_off + file_size])
                .ok_or(MachoLoaderError::MemoryError("copy dyld segment".into()))?;
        }

        let final_prot = prot_from_macho(seg.initprot);
        if final_prot != litebox_common_linux::ProtFlags::PROT_READ_WRITE {
            litebox_common_linux::mm::sys_mprotect(&task.global.pm, MutPtr::from_usize(vm_addr), vm_size, final_prot)
                .map_err(|e| MachoLoaderError::MappingError(alloc::format!("mprotect dyld: {e:?}")))?;
        }
    }

    // Initialize __LITEBOX trampoline in dyld (same pattern as main binary)
    if let Some(litebox_seg) = segments.iter().find(|s| s.segname.starts_with(b"__LITEBOX")) {
        // Same trampoline initialization as in load() - callback addr + TLS table
        // ... (copy the trampoline init code from load(), adjusted for dyld segments)
    }

    let entry_point = (entry_point_raw.ok_or(MachoLoaderError::NoEntryPoint)? as usize).wrapping_add(slide);

    Ok(DyldLoadInfo { entry_point, slide })
}
```

- [ ] **Step 3: Add apple array support to UserStack**

In `litebox_shim_macos/src/loader/stack.rs`, add a method for the apple array and modify `init` to accept optional apple entries:

```rust
    /// Initialize the stack with argc/argv/envp and optional apple entries.
    ///
    /// The apple array is a set of key-value strings passed by the kernel to dyld.
    pub fn init_with_apple(
        &mut self,
        argv: Vec<CString>,
        envp: Vec<CString>,
        apple: Vec<CString>,
    ) -> Option<()> {
        // Push string data (same as init)
        self.push_usize(0)?; // end marker
        let env_ptrs: Vec<usize> = envp.iter().map(|s| {
            self.push_cstring(s);
            self.get_cur_stack_top()
        }).collect();
        let argv_ptrs: Vec<usize> = argv.iter().map(|s| {
            self.push_cstring(s);
            self.get_cur_stack_top()
        }).collect();
        let apple_ptrs: Vec<usize> = apple.iter().map(|s| {
            self.push_cstring(s);
            self.get_cur_stack_top()
        }).collect();

        // Align
        let argc = argv.len();
        let total_pointers = 1 + argc + 1 + envp.len() + 1 + apple.len() + 1;
        let pointer_bytes = total_pointers * core::mem::size_of::<usize>();
        let current = self.pos;
        let aligned = (current - pointer_bytes) & !(STACK_ALIGNMENT - 1);
        self.pos = aligned + pointer_bytes;

        // Push apple[] pointers (NULL terminated)
        self.push_pointers(&apple_ptrs)?;
        // Push envp pointers (NULL terminated)
        self.push_pointers(&env_ptrs)?;
        // Push argv pointers (NULL terminated)
        self.push_pointers(&argv_ptrs)?;
        // Push argc
        self.push_usize(argc)?;

        assert!(self.pos % STACK_ALIGNMENT == 0, "stack not 16-byte aligned");
        Some(())
    }
```

- [ ] **Step 4: Modify load() to detect LC_LOAD_DYLINKER and load dyld**

In the main `load()` function in `macho.rs`, add detection of `LC_LOAD_DYLINKER` during command iteration:

```rust
    let mut has_dylinker = false;

    // In the load command loop:
    if cmd.cmd() == macho::LC_LOAD_DYLINKER {
        has_dylinker = true;
    }
```

Then after the main binary is loaded, if `has_dylinker` is true:
1. Read `/usr/lib/dyld` from the host filesystem
2. Call `load_dyld()`
3. Set entry point to dyld's entry instead of main binary's
4. Use `init_with_apple()` instead of `init()` for the stack

- [ ] **Step 5: Extend MachoLoadInfo and load_macho signature**

Add an optional `dyld_path` parameter to `load_macho` (or read it from GlobalState), and add `has_dylinker` to `MachoLoadInfo` so the caller knows whether dyld was loaded.

- [ ] **Step 6: Build and verify**

Run: `cargo build -p litebox_shim_macos`
Expected: Compiles.

- [ ] **Step 7: Verify no regression**

Run: `cargo test -p litebox_runner_macos_on_macos_userland`
Expected: All 3 existing tests still pass (static binaries have no LC_LOAD_DYLINKER).

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "shim_macos: load dyld from universal binary, set up apple stack, select dyld entry point"
```

---

### Task 7: Extract dylibs from shared cache and set up test infrastructure

Extract the minimal set of dylibs from the macOS shared cache, compile a dynamically linked `hello.c`, and set up the test infrastructure.

**Files:**
- Create: `litebox_runner_macos_on_macos_userland/extract_sysroot.sh` (extraction script)
- Modify: `litebox_runner_macos_on_macos_userland/tests/common/mod.rs` (add dynamic binary helpers)
- Modify: `litebox_runner_macos_on_macos_userland/tests/loader.rs` (add test_hello_dynamic)

- [ ] **Step 1: Create sysroot extraction script**

Since `dyld_shared_cache_util` is not available, we need an alternative approach. On modern macOS, we can use the `dyld_shared_cache_extract` API or build a simple Rust tool. However, the simplest approach for testing is to check if individual dylib files exist on the system (some macOS versions still have them) or use `dsc_extractor`.

Alternative: Use `jtool2` or `dyldex` if available, or write a minimal extractor.

For now, create a script that tries multiple approaches:

```bash
#!/bin/bash
# extract_sysroot.sh — Extract minimal dylibs for testing
set -e

SYSROOT="$1"
if [ -z "$SYSROOT" ]; then
    echo "Usage: $0 <sysroot-dir>"
    exit 1
fi

mkdir -p "$SYSROOT/usr/lib" "$SYSROOT/usr/lib/system"

# Try to copy dylibs from the filesystem (works on some macOS versions)
LIBS=(
    "/usr/lib/libSystem.B.dylib"
    "/usr/lib/system/libsystem_c.dylib"
    "/usr/lib/system/libsystem_kernel.dylib"
    "/usr/lib/system/libsystem_platform.dylib"
    "/usr/lib/system/libsystem_pthread.dylib"
    "/usr/lib/system/libdyld.dylib"
    "/usr/lib/system/libsystem_malloc.dylib"
    "/usr/lib/system/libcompiler_rt.dylib"
    "/usr/lib/system/libsystem_blocks.dylib"
    "/usr/lib/system/libsystem_info.dylib"
    "/usr/lib/system/libcorecrypto.dylib"
)

for lib in "${LIBS[@]}"; do
    dest="$SYSROOT$lib"
    if [ -f "$lib" ] && file "$lib" | grep -q "Mach-O"; then
        cp "$lib" "$dest"
        echo "Copied: $lib"
    else
        echo "SKIP (not a real file): $lib"
    fi
done

echo "Sysroot extraction complete: $SYSROOT"
```

- [ ] **Step 2: Run the extraction and assess results**

Run the script. If the dylibs are only in the shared cache (which is likely on modern macOS), we'll need a different approach — potentially writing a minimal Rust-based shared cache extractor or using a pre-built extraction tool.

If extraction fails, consider alternative: compile hello.c as a dynamically linked binary against a custom minimal libSystem that we provide, rather than using the system libSystem.

- [ ] **Step 3: Add test helper for dynamic binaries**

In `tests/common/mod.rs`, add:

```rust
/// Compile a C file to a dynamically linked Mach-O binary.
pub fn compile_macho_dynamic(c_source: &str, name: &str) -> PathBuf {
    let dir = std::env::var("OUT_DIR")
        .unwrap_or_else(|_| std::env::temp_dir().to_str().unwrap().to_string());
    let dir = Path::new(&dir);
    let src_path = dir.join(format!("{name}.c"));
    let bin_path = dir.join(name);

    std::fs::write(&src_path, c_source).expect("write C source");

    let output = std::process::Command::new("clang")
        .args([
            "-arch", "arm64",
            "-Wl,-headerpad,0x1000",
            "-o", bin_path.to_str().unwrap(),
            src_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run clang");
    assert!(
        output.status.success(),
        "clang failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    bin_path
}

/// Run a dynamically linked Mach-O binary through litebox with dyld support.
pub fn run_macho_dynamic(binary_data: &[u8], argv: &[&str], sysroot: &str) -> (i32, Vec<u8>) {
    use litebox::fs::{FileSystem as _, Mode};

    let _guard = TEST_LOCK.lock().unwrap();
    ensure_platform();
    litebox_common_linux::HOST_TLS_TABLE_ADDR.store(0, std::sync::atomic::Ordering::Release);

    let mut shim_builder =
        litebox_shim_macos::MacosShimBuilder::<litebox_shim_macos::DefaultFS>::new();
    shim_builder.set_sysroot(sysroot.to_string());

    let litebox = shim_builder.litebox();
    let mut in_mem_fs = litebox::fs::in_mem::FileSystem::new(litebox);
    in_mem_fs.with_root_privileges(|fs| {
        let mode = Mode::RWXU | Mode::RWXG | Mode::RWXO;
        let _ = fs.mkdir("/tmp", mode);
    });
    let tar_ro_fs = litebox::fs::tar_ro::FileSystem::new(litebox, litebox::fs::tar_ro::EMPTY_TAR_FILE.into());
    let fs = shim_builder.default_fs(in_mem_fs, tar_ro_fs);
    shim_builder.set_fs(fs);
    let shim = shim_builder.build();

    let argv_cstrings: Vec<std::ffi::CString> = argv.iter().map(|s| std::ffi::CString::new(*s).unwrap()).collect();
    let envp = vec![std::ffi::CString::new("PATH=/bin").unwrap()];

    let program = shim.load_program(binary_data, argv_cstrings, envp).expect("load_program failed");

    let litebox_shim_macos::LoadedProgram { entrypoints, process, mut initial_ctx } = program;
    unsafe { litebox_platform_macos_userland::run_thread(entrypoints, &mut initial_ctx); }

    let exit_code = process.wait();
    (exit_code, Vec::new())
}
```

- [ ] **Step 4: Add test_hello_dynamic test**

In `tests/loader.rs`:

```rust
const HELLO_DYNAMIC_C: &str = r#"
#include <stdio.h>
#include <time.h>

int main(int argc, char *argv[], char *envp[]) {
    for (int i = 0; i < argc; i++) {
        printf("argv[%d] = %s\n", i, argv[i]);
    }
    for (int i = 0; envp[i] != NULL; i++) {
        printf("envp[%d] = %s\n", i, envp[i]);
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < 100000000; i++);
    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("Elapsed time: %f seconds\n", elapsed);

    return 0;
}
"#;

#[test]
fn test_hello_dynamic() {
    let bin_path = common::compile_macho_dynamic(HELLO_DYNAMIC_C, "hello_dynamic");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    // Rewrite the main binary
    let rewritten = litebox_syscall_rewriter_macho::hook_syscalls_in_macho(&binary_data)
        .expect("rewrite failed");

    let sysroot = std::env::var("LITEBOX_MACOS_SYSROOT")
        .unwrap_or_else(|_| {
            let dir = std::env::var("OUT_DIR")
                .unwrap_or_else(|_| std::env::temp_dir().to_str().unwrap().to_string());
            format!("{dir}/macos-sysroot")
        });

    let (exit_code, _stdout) = common::run_macho_dynamic(&rewritten, &["hello_dynamic"], &sysroot);
    assert_eq!(exit_code, 0, "process exited with non-zero code");
}
```

- [ ] **Step 5: Run test (expected to fail initially — this is the integration target)**

Run: `cargo test -p litebox_runner_macos_on_macos_userland test_hello_dynamic`
Expected: Will fail due to missing sysroot, dyld loading issues, or missing syscalls. This is the integration test we'll iterate on.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "runner_macos: add test infrastructure for dynamic linking (sysroot extraction, test_hello_dynamic)"
```

---

### Task 8: Integration debugging and iteration

This task is inherently iterative. Run the dynamic hello test, observe failures, and fix them one by one. Common issues to expect:

1. **Sysroot extraction**: dylibs may not exist as individual files. May need to build a shared cache extractor or use a different approach (e.g., compile against a custom minimal libc).
2. **dyld MH_DYLINKER validation**: The rewriter currently only accepts `MH_EXECUTE`. Need to extend it to accept `MH_DYLINKER`.
3. **Missing syscalls**: dyld will call syscalls we haven't implemented yet. Add them as discovered.
4. **Mach trap handling**: dyld may need additional Mach traps beyond the 6 we stubbed.
5. **TLS table sharing**: dyld and the main binary need to share TLS state. The trampoline init may need adjustment.
6. **apple array format**: dyld may require specific apple entries we didn't anticipate.
7. **clock_gettime implementation**: Need `gettimeofday` or `clock_gettime_nsec_np` syscall support.
8. **printf/write path**: libSystem's printf goes through multiple layers before reaching `write`.

**Files:** Various, depending on what fails.

- [ ] **Step 1: Extend rewriter to accept MH_DYLINKER**

In `litebox_syscall_rewriter_macho/src/lib.rs`, change the filetype check in `parse_text_sections`:

```rust
    if filetype != macho::MH_EXECUTE && filetype != 0x7 /* MH_DYLINKER */ {
        return Err(Error::UnsupportedObjectFile);
    }
```

Do the same in `find_max_segment_end` if it validates filetype.

- [ ] **Step 2: Iteratively run test and fix issues**

Run `cargo test -p litebox_runner_macos_on_macos_userland test_hello_dynamic -- --nocapture` repeatedly, fixing each failure:

For each failure:
1. Identify the failing syscall or crash
2. Implement or fix the handler
3. Re-run

- [ ] **Step 3: Add clock_gettime / gettimeofday support**

macOS hello.c uses `clock_gettime(CLOCK_MONOTONIC)`. This goes through libsystem_kernel which calls `gettimeofday` (syscall 116) or `clock_gettime` (if available). Add:

```rust
// In nr module:
pub const GETTIMEOFDAY: usize = 116;
pub const CLOCK_GETTIME: usize = 232; // __mac_syscall on macOS, or use commpage

// In stubs.rs or a new time.rs:
pub(crate) fn sys_gettimeofday(&self, tv_addr: usize, _tz_addr: usize) -> Result<usize, Errno> {
    let now = self.global.platform.now();
    let duration = now.duration_since_boot(&self.global.boot_time);
    let secs = duration.as_secs();
    let usecs = duration.subsec_micros();

    let dest: MutPtr<u8> = MutPtr::from_usize(tv_addr);
    let mut buf = [0u8; 16]; // struct timeval { time_t tv_sec; suseconds_t tv_usec; }
    buf[0..8].copy_from_slice(&(secs as i64).to_le_bytes());
    buf[8..16].copy_from_slice(&(usecs as i64).to_le_bytes());
    dest.copy_from_slice(0, &buf).ok_or(Errno::EFAULT)?;
    Ok(0)
}
```

- [ ] **Step 4: Final verification**

Run: `cargo test -p litebox_runner_macos_on_macos_userland`
Expected: All tests pass including `test_hello_dynamic`.

Run: `cargo clippy -p litebox_shim_macos -p litebox_syscall_rewriter_macho -p litebox_common_macos -p litebox_runner_macos_on_macos_userland`
Expected: No warnings.

Run: `cargo fmt --check`
Expected: No formatting issues.

- [ ] **Step 5: Commit all remaining fixes**

```bash
git add -A
git commit -m "shim_macos phase 2: dynamic linking via mmap-hook — all tests passing"
```

---

### Task 9: Final verification and cleanup

Run the full test suite, clippy, and fmt across the workspace. Verify no regressions in Linux shim tests.

**Files:** None (verification only).

- [ ] **Step 1: Run all macOS shim tests**

Run: `cargo test -p litebox_runner_macos_on_macos_userland`
Expected: All tests pass (3 Phase 1 + 1 Phase 2).

- [ ] **Step 2: Run Linux-on-macOS tests (regression check)**

Run: `cargo test -p litebox_runner_linux_on_macos_userland`
Expected: Passes (the pre-existing flaky test_dynamic_linked_hello_thread may fail ~30% of the time — that's known and unrelated).

- [ ] **Step 3: Run workspace clippy**

Run: `cargo clippy --workspace`
Expected: Clean (no warnings from our crates).

- [ ] **Step 4: Run workspace fmt check**

Run: `cargo fmt --check`
Expected: No formatting issues.

- [ ] **Step 5: Commit if any cleanup was needed**

```bash
git add -A
git commit -m "phase 2: final cleanup and verification"
```
