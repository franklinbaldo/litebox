# macOS Shim Phase A: FD Dispatch, Pipes, Filesystem, Thread Exit — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `litebox_shim_macos` with unified FD dispatch across subsystems (filesystem + pipes), pipe syscall, filesystem operations (unlink/mkdir/rmdir/ftruncate/access/fchmod/getdirentries64), `__semwait_signal`, and end-to-end tests for pipes, filesystem, and thread exit.

**Architecture:** Add a `StrongFd<FS>` enum to dispatch read/write/close across filesystem and pipe FDs (following the Linux shim's pattern). Implement 9 new BSD syscall variants. Pipe syscall uses dual-register return (x0/x1) intercepted before `set_syscall_return`. Add `WaitState` to the macOS `Task` for pipe blocking I/O. Wire new filesystem syscalls to existing `FileSystem` trait methods. Three new C test files exercise all functionality via exit-code verification.

**Tech Stack:** Rust (edition 2024), `litebox` framework (Pipes, FileSystem, fd subsystem), macOS aarch64 BSD ABI, C test programs compiled with `compile_macho_dynamic`.

**Design Spec:** `docs/superpowers/specs/2026-04-04-litebox-macos-phase-a-design.md`

**Test Commands:**
```bash
cargo test -p litebox_runner_macos_on_macos_userland -- --nocapture
cargo clippy -p litebox_common_macos -p litebox_shim_macos -p litebox_runner_macos_on_macos_userland -- -D warnings
```

---

## File Structure

### Files to modify

| File | Responsibility |
|------|---------------|
| `litebox_common_macos/src/errno.rs` | Add `ENOTEMPTY` errno |
| `litebox_common_macos/src/syscall.rs` | Add 9 new syscall numbers + variants + decoding |
| `litebox_shim_macos/src/lib.rs` | Add `StrongFd` enum, `WaitState` for Task, intercept `Pipe` in `handle_syscall_request`, add `sys_pipe`, `sys_semwait_signal`, remove `dead_code` expects |
| `litebox_shim_macos/src/syscalls/mod.rs` | Add dispatch arms for 9 new syscalls |
| `litebox_shim_macos/src/syscalls/file.rs` | Refactor read/write/close to use `StrongFd`, add 7 filesystem syscall handlers |
| `litebox_runner_macos_on_macos_userland/tests/loader.rs` | Add 3 new test functions |

### Files to create

| File | Responsibility |
|------|---------------|
| `litebox_shim_macos/src/wait.rs` | `WaitState` wrapper and `wait_cx()` method (following Linux shim pattern) |
| `litebox_runner_macos_on_macos_userland/tests/pipe.c` | Pipe IPC test |
| `litebox_runner_macos_on_macos_userland/tests/filesystem.c` | Filesystem operations test |
| `litebox_runner_macos_on_macos_userland/tests/thread_exit.c` | Thread exit test |

---

## Task 1: Add ENOTEMPTY errno and new syscall numbers

**Files:**
- Modify: `litebox_common_macos/src/errno.rs:46` (add ENOTEMPTY before ENOSYS)
- Modify: `litebox_common_macos/src/syscall.rs:10-60` (add 9 new `nr::*` constants)

- [ ] **Step 1: Add ENOTEMPTY errno**

In `litebox_common_macos/src/errno.rs`, add `ENOTEMPTY = 66` before the `ENOSYS` line:

```rust
    EAGAIN = 35,
    ENOTEMPTY = 66,
    ENOSYS = 78,
```

- [ ] **Step 2: Add 9 new syscall number constants**

In `litebox_common_macos/src/syscall.rs`, add these constants inside `pub mod nr { ... }` after the existing `SIGRETURN` line (line 59):

```rust
    pub const UNLINK: usize = 10;
    pub const ACCESS: usize = 33;
    pub const PIPE: usize = 42;
    pub const FCHMOD: usize = 124;
    pub const MKDIR: usize = 136;
    pub const RMDIR: usize = 137;
    pub const FTRUNCATE: usize = 201;
    pub const SEMWAIT_SIGNAL: usize = 334;
    pub const GETDIRENTRIES64: usize = 344;
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check -p litebox_common_macos`
Expected: compiles with no errors.

- [ ] **Step 4: Commit**

```bash
git add litebox_common_macos/src/errno.rs litebox_common_macos/src/syscall.rs
git commit -m "feat(macos): add Phase A syscall numbers and ENOTEMPTY errno"
```

---

## Task 2: Add syscall request variants and decoding

**Files:**
- Modify: `litebox_common_macos/src/syscall.rs:82-277` (add 9 new `MacosSyscallRequest` variants)
- Modify: `litebox_common_macos/src/syscall.rs:301-470` (add 9 decoding match arms in `try_from_raw`)

- [ ] **Step 1: Add 9 new variants to MacosSyscallRequest enum**

In `litebox_common_macos/src/syscall.rs`, add these variants to the `MacosSyscallRequest` enum, before the `Unknown` variant (line 274):

```rust
    Unlink {
        path: usize,
    },
    Access {
        path: usize,
        amode: i32,
    },
    Pipe,
    Fchmod {
        fd: i32,
        mode: u32,
    },
    Mkdir {
        path: usize,
        mode: u32,
    },
    Rmdir {
        path: usize,
    },
    Ftruncate {
        fd: i32,
        length: i64,
    },
    SemwaitSignal {
        cond_sem: i32,
        mutex_sem: i32,
        timeout: i32,
        relative: i32,
        tv_sec: i64,
        tv_nsec: i32,
    },
    Getdirentries64 {
        fd: i32,
        buf: usize,
        bufsize: usize,
        basep: usize,
    },
```

- [ ] **Step 2: Add decoding match arms in try_from_raw**

In the `match nr_raw { ... }` block inside `try_from_raw`, add these arms before the `_ => MacosSyscallRequest::Unknown` catch-all (line 469):

```rust
            nr::UNLINK => MacosSyscallRequest::Unlink { path: a0 },
            nr::ACCESS => MacosSyscallRequest::Access {
                path: a0,
                amode: a1 as i32,
            },
            nr::PIPE => MacosSyscallRequest::Pipe,
            nr::FCHMOD => MacosSyscallRequest::Fchmod {
                fd: a0 as i32,
                mode: a1 as u32,
            },
            nr::MKDIR => MacosSyscallRequest::Mkdir {
                path: a0,
                mode: a1 as u32,
            },
            nr::RMDIR => MacosSyscallRequest::Rmdir { path: a0 },
            nr::FTRUNCATE => MacosSyscallRequest::Ftruncate {
                fd: a0 as i32,
                length: a1 as i64,
            },
            nr::SEMWAIT_SIGNAL => MacosSyscallRequest::SemwaitSignal {
                cond_sem: a0 as i32,
                mutex_sem: a1 as i32,
                timeout: a2 as i32,
                relative: a3 as i32,
                tv_sec: a4 as i64,
                tv_nsec: a5 as i32,
            },
            nr::GETDIRENTRIES64 => MacosSyscallRequest::Getdirentries64 {
                fd: a0 as i32,
                buf: a1,
                bufsize: a2,
                basep: a3,
            },
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check -p litebox_common_macos`
Expected: compiles with no errors (the new variants are unused for now — match exhaustiveness will be enforced when dispatch is added).

- [ ] **Step 4: Commit**

```bash
git add litebox_common_macos/src/syscall.rs
git commit -m "feat(macos): add Phase A syscall request variants and decoding"
```

---

## Task 3: Add WaitState module to macOS shim

**Files:**
- Create: `litebox_shim_macos/src/wait.rs`
- Modify: `litebox_shim_macos/src/lib.rs` (add `mod wait`, add `wait_state` field to `Task`, construct it)

This follows the Linux shim's `wait.rs` pattern exactly (`litebox_shim_linux/src/wait.rs`). The macOS shim needs `WaitContext` for pipe blocking I/O.

- [ ] **Step 1: Create `litebox_shim_macos/src/wait.rs`**

Create this new file:

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Wait state management.
//!
//! Use a dedicated module to prevent code from accidentally accessing
//! `wait_state` without going through `wait_cx()`.

use crate::{Platform, ShimFS, Task};

pub(crate) struct WaitState(litebox::event::wait::WaitState<Platform>);

impl WaitState {
    pub(crate) fn new(platform: &'static Platform) -> Self {
        WaitState(litebox::event::wait::WaitState::new(platform))
    }
}

impl<FS: ShimFS> Task<FS> {
    /// Returns a wait context to use to perform interruptible waits.
    pub(crate) fn wait_cx(&self) -> litebox::event::wait::WaitContext<'_, Platform> {
        self.wait_state.0.context()
    }
}
```

Note: Unlike the Linux shim, we omit `with_check_for_interrupt`, `enter_from_guest`, `prepare_to_run_guest`, and `CheckForInterrupt` impl — those are for signal-aware blocking which the macOS shim doesn't need yet. We can add them later.

- [ ] **Step 2: Add `mod wait` declaration to `lib.rs`**

In `litebox_shim_macos/src/lib.rs`, add this module declaration near the other `mod` declarations at the top of the file (find the existing module declarations like `mod syscalls;` and add after them):

```rust
mod wait;
```

- [ ] **Step 3: Add `wait_state` field to `Task` struct**

In `litebox_shim_macos/src/lib.rs`, add a `wait_state` field to the `Task` struct (line 830-845). Add it after the `blocked_signals` field:

```rust
    /// Per-thread wait state for interruptible waits (pipes, futexes, etc.).
    wait_state: wait::WaitState,
```

- [ ] **Step 4: Construct `wait_state` in Task creation**

Search for where `Task` is constructed (likely in a `new` method or inline struct literal). Find where `blocked_signals: AtomicU32::new(0)` appears and add:

```rust
    wait_state: wait::WaitState::new(global.platform),
```

Run: `cargo check -p litebox_shim_macos`

Look for compilation errors — if `Task` is constructed in multiple places, update all of them. The `Task` struct construction should be searchable via `blocked_signals:` since that's the last field.

- [ ] **Step 5: Verify it compiles**

Run: `cargo check -p litebox_shim_macos`
Expected: compiles with no errors.

- [ ] **Step 6: Commit**

```bash
git add litebox_shim_macos/src/wait.rs litebox_shim_macos/src/lib.rs
git commit -m "feat(macos): add WaitState module for pipe blocking I/O"
```

---

## Task 4: Add StrongFd enum and refactor sys_read/sys_write/sys_close

**Files:**
- Modify: `litebox_shim_macos/src/lib.rs` (add `StrongFd` enum, remove `dead_code` expect on `pipes`)
- Modify: `litebox_shim_macos/src/syscalls/file.rs` (refactor `sys_read`, `sys_write`, `sys_close` to dispatch via `StrongFd`)

- [ ] **Step 1: Add StrongFd enum and from_raw to lib.rs**

In `litebox_shim_macos/src/lib.rs`, add the `StrongFd` enum and `from_raw` method. Place it after the `GlobalState` struct definition (after line 816, before the `MachoPatchState` struct):

```rust
/// A strongly-typed FD that can represent any subsystem's file descriptor.
///
/// Used by read/write/close to dispatch to the correct subsystem.
enum StrongFd<FS: ShimFS> {
    FileSystem(Arc<TypedFd<FS>>),
    Pipes(Arc<TypedFd<Pipes<Platform>>>),
}

impl<FS: ShimFS> StrongFd<FS> {
    /// Resolve a raw integer FD to a strongly-typed FD, trying each subsystem.
    fn from_raw(rds: &RawDescriptorStorage, fd: usize) -> Result<Self, Errno> {
        if let Ok(fd) = rds.fd_from_raw_integer::<FS>(fd) {
            return Ok(StrongFd::FileSystem(fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer::<Pipes<Platform>>(fd) {
            return Ok(StrongFd::Pipes(fd));
        }
        Err(Errno::EBADF)
    }
}
```

Make sure the following imports are present at the top of `lib.rs` (they likely already are):
- `litebox::fd::TypedFd` (check if already imported)
- `litebox::pipes::Pipes` (check if already imported)

Also add `use litebox_common_macos::errno::Errno;` if not already imported in `lib.rs`.

- [ ] **Step 2: Remove `dead_code` expect from `pipes` field**

In `litebox_shim_macos/src/lib.rs`, find the `pipes` field in `GlobalState` (line 796-797) and remove the `#[expect(dead_code, ...)]` attribute:

Change:
```rust
    /// The anonymous pipe implementation.
    #[expect(dead_code, reason = "will be used when pipe syscalls are added")]
    pipes: Pipes<Platform>,
```
To:
```rust
    /// The anonymous pipe implementation.
    pipes: Pipes<Platform>,
```

- [ ] **Step 3: Refactor sys_read to dispatch via StrongFd**

In `litebox_shim_macos/src/syscalls/file.rs`, replace the current `sys_read` method (lines 74-96) with:

```rust
    /// Handle `read(fd, buf, count)`.
    ///
    /// Dispatches to filesystem or pipe subsystem based on FD type.
    pub(crate) fn sys_read(&self, fd: i32, buf_addr: usize, count: usize) -> Result<usize, Errno> {
        let raw_fd = fd_to_usize(fd)?;
        let strong_fd = {
            let rds = self.global.raw_descriptors.read();
            crate::StrongFd::from_raw(&rds, raw_fd)?
        };

        let read_len = count.min(MAX_KERNEL_BUF_SIZE);
        let mut kernel_buf = vec![0u8; read_len];

        let size = match strong_fd {
            crate::StrongFd::FileSystem(ref typed_fd) => self
                .global
                .fs
                .read(typed_fd, &mut kernel_buf, None)
                .map_err(Self::read_error_to_errno)?,
            crate::StrongFd::Pipes(ref typed_fd) => {
                let cx = self.wait_cx();
                self.global
                    .pipes
                    .read(&cx, typed_fd, &mut kernel_buf)
                    .map_err(Self::pipe_read_error_to_errno)?
            }
        };

        let user_buf: MutPtr<u8> = MutPtr::from_usize(buf_addr);
        user_buf
            .copy_from_slice(0, &kernel_buf[..size])
            .ok_or(Errno::EFAULT)?;

        Ok(size)
    }
```

- [ ] **Step 4: Refactor sys_write to dispatch via StrongFd**

Replace the current `sys_write` method (lines 101-132) with:

```rust
    /// Handle `write(fd, buf, count)`.
    ///
    /// Dispatches to filesystem or pipe subsystem based on FD type.
    pub(crate) fn sys_write(&self, fd: i32, buf_addr: usize, count: usize) -> Result<usize, Errno> {
        // Debug: log write calls to see dyld error messages (written to fd -1, 1, or 2)
        if fd == -1 || fd == 1 || fd == 2 {
            let user_buf_dbg: ConstPtr<u8> = ConstPtr::from_usize(buf_addr);
            if let Some(data) = user_buf_dbg.to_owned_slice(count.min(256))
                && let Ok(s) = core::str::from_utf8(&data)
            {
                log_unsupported!("write(fd={fd}, count={count}): {s:?}");
            }
        }

        // fd -1 is invalid — return EBADF (but we've already logged the diagnostic above).
        let raw_fd = fd_to_usize(fd)?;

        let strong_fd = {
            let rds = self.global.raw_descriptors.read();
            crate::StrongFd::from_raw(&rds, raw_fd)?
        };

        let user_buf: ConstPtr<u8> = ConstPtr::from_usize(buf_addr);
        let write_len = count.min(MAX_KERNEL_BUF_SIZE);
        let data = user_buf.to_owned_slice(write_len).ok_or(Errno::EFAULT)?;

        let size = match strong_fd {
            crate::StrongFd::FileSystem(ref typed_fd) => self
                .global
                .fs
                .write(typed_fd, &data, None)
                .map_err(Self::write_error_to_errno)?,
            crate::StrongFd::Pipes(ref typed_fd) => {
                let cx = self.wait_cx();
                self.global
                    .pipes
                    .write(&cx, typed_fd, &data)
                    .map_err(Self::pipe_write_error_to_errno)?
            }
        };

        Ok(size)
    }
```

- [ ] **Step 5: Refactor sys_close to dispatch via StrongFd**

Replace the current `sys_close` method (lines 135-167) with:

```rust
    /// Handle `close(fd)`.
    ///
    /// Dispatches to filesystem or pipe subsystem based on FD type.
    pub(crate) fn sys_close(&self, fd: i32) -> Result<(), Errno> {
        // Finalize any mmap-hook trampoline for this fd
        if let Some(state) = self.patch_cache.lock().remove(&fd)
            && state.trampoline_cursor > 0
        {
            // mprotect trampoline from RW to RX
            if let Err(e) = litebox_common_linux::mm::sys_mprotect(
                &self.global.pm,
                crate::MutPtr::from_usize(state.trampoline_addr),
                crate::MMAP_HOOK_TRAMPOLINE_SIZE,
                litebox_common_linux::ProtFlags::PROT_READ_EXEC,
            ) {
                log_unsupported!("mprotect trampoline RW->RX failed: {e:?}");
            }
        }

        let raw_fd = fd_to_usize(fd)?;

        // Remove the path entry for F_GETPATH tracking.
        {
            let mut paths = self.global.fd_paths.write();
            paths.remove(&raw_fd);
        }

        // Try filesystem first, then pipes.
        {
            let mut rds = self.global.raw_descriptors.write();
            if let Ok(typed_fd) = rds.fd_consume_raw_integer::<FS>(raw_fd) {
                return self.global.fs.close(&typed_fd).map_err(|_| Errno::EIO);
            }
            if let Ok(typed_fd) = rds.fd_consume_raw_integer::<Pipes<Platform>>(raw_fd) {
                return self.global.pipes.close(&typed_fd).map_err(|_| Errno::EIO);
            }
        }

        Err(Errno::EBADF)
    }
```

Add the necessary import at the top of `file.rs`:

```rust
use litebox::pipes::Pipes;
use crate::Platform;
```

- [ ] **Step 6: Add pipe error-to-errno conversion helpers**

In `litebox_shim_macos/src/syscalls/file.rs`, add these helper methods to the `impl<FS: ShimFS> Task<FS>` block, after the existing `write_error_to_errno` method:

```rust
    /// Convert a pipe `ReadError` to a macOS errno.
    fn pipe_read_error_to_errno(e: litebox::pipes::errors::ReadError) -> Errno {
        match e {
            litebox::pipes::errors::ReadError::ClosedFd => Errno::EBADF,
            litebox::pipes::errors::ReadError::NotForReading => Errno::EBADF,
            litebox::pipes::errors::ReadError::WouldBlock => Errno::EAGAIN,
            _ => Errno::EIO,
        }
    }

    /// Convert a pipe `WriteError` to a macOS errno.
    fn pipe_write_error_to_errno(e: litebox::pipes::errors::WriteError) -> Errno {
        match e {
            litebox::pipes::errors::WriteError::ClosedFd => Errno::EBADF,
            litebox::pipes::errors::WriteError::ReadEndClosed => Errno::EPIPE,
            litebox::pipes::errors::WriteError::NotForWriting => Errno::EBADF,
            litebox::pipes::errors::WriteError::WouldBlock => Errno::EAGAIN,
            _ => Errno::EIO,
        }
    }
```

- [ ] **Step 7: Update sys_dup2 to handle pipe FDs**

The current `sys_dup2` (file.rs lines 411-463) uses `fd_consume_raw_integer::<FS>` to close the existing newfd. It also validates oldfd via `fd_from_raw_integer::<FS>`. Both need to handle pipe FDs too.

Replace the validation of oldfd (lines 416-420):

```rust
        // Validate that oldfd exists (any subsystem).
        {
            let rds = self.global.raw_descriptors.read();
            crate::StrongFd::from_raw(&rds, raw_oldfd)?;
        }
```

Replace the close of existing newfd (lines 436-442):

```rust
        // If newfd is already open, close it first (try all subsystems).
        {
            let mut rds = self.global.raw_descriptors.write();
            if let Ok(existing_fd) = rds.fd_consume_raw_integer::<FS>(raw_newfd) {
                let _ = self.global.fs.close(&existing_fd);
            } else if let Ok(existing_fd) = rds.fd_consume_raw_integer::<Pipes<Platform>>(raw_newfd) {
                let _ = self.global.pipes.close(&existing_fd);
            }
        }
```

The `duplicate()` call at line 428-433 uses `old_typed_fd` which was a `TypedFd<FS>`. Since we now validate via `StrongFd`, we need to handle the duplication differently. Actually, `descriptor_table_mut().duplicate()` operates on any `TypedFd<T>` and is subsystem-agnostic. We need the actual `TypedFd` to duplicate it. Refactor to:

```rust
    /// Handle `dup2(oldfd, newfd)`.
    ///
    /// Duplicates `oldfd` onto `newfd`. If `newfd` is already open, it is
    /// silently closed first. If `oldfd == newfd`, just validates oldfd and
    /// returns it.
    pub(crate) fn sys_dup2(&self, oldfd: i32, newfd: i32) -> Result<usize, Errno> {
        let raw_oldfd = fd_to_usize(oldfd)?;
        let raw_newfd = fd_to_usize(newfd)?;

        // Resolve the old fd to a StrongFd to validate it exists.
        let strong_fd = {
            let rds = self.global.raw_descriptors.read();
            crate::StrongFd::from_raw(&rds, raw_oldfd)?
        };

        // If oldfd == newfd, dup2 is a no-op (just validates oldfd).
        if raw_oldfd == raw_newfd {
            return Ok(raw_newfd);
        }

        // Duplicate the underlying descriptor (subsystem-agnostic).
        let new_typed_result = match &strong_fd {
            crate::StrongFd::FileSystem(typed_fd) => {
                self.global
                    .litebox
                    .descriptor_table_mut()
                    .duplicate(typed_fd)
                    .map(crate::StrongFd::FileSystem)
            }
            crate::StrongFd::Pipes(typed_fd) => {
                self.global
                    .litebox
                    .descriptor_table_mut()
                    .duplicate(typed_fd)
                    .map(crate::StrongFd::Pipes)
            }
        };
        let new_strong_fd = new_typed_result.ok_or(Errno::EBADF)?;

        // If newfd is already open, close it first (try all subsystems).
        {
            let mut rds = self.global.raw_descriptors.write();
            if let Ok(existing_fd) = rds.fd_consume_raw_integer::<FS>(raw_newfd) {
                let _ = self.global.fs.close(&existing_fd);
            } else if let Ok(existing_fd) = rds.fd_consume_raw_integer::<Pipes<Platform>>(raw_newfd)
            {
                let _ = self.global.pipes.close(&existing_fd);
            }
        }

        // Insert the duplicated fd at the specific newfd slot.
        {
            let mut rds = self.global.raw_descriptors.write();
            let success = match new_strong_fd {
                crate::StrongFd::FileSystem(typed_fd) => {
                    rds.fd_into_specific_raw_integer(Arc::try_unwrap(typed_fd).unwrap_or_else(|arc| {
                        // This shouldn't happen — we just created this TypedFd
                        panic!("dup2: unexpected extra reference to duplicated fd");
                    }), raw_newfd)
                }
                crate::StrongFd::Pipes(typed_fd) => {
                    rds.fd_into_specific_raw_integer(Arc::try_unwrap(typed_fd).unwrap_or_else(|arc| {
                        panic!("dup2: unexpected extra reference to duplicated fd");
                    }), raw_newfd)
                }
            };
            if !success {
                return Err(Errno::EBADF);
            }
        }

        // Copy the path entry from oldfd to newfd for F_GETPATH support.
        {
            let mut paths = self.global.fd_paths.write();
            if let Some(path) = paths.get(&raw_oldfd).cloned() {
                paths.insert(raw_newfd, path);
            }
        }

        log_unsupported!("dup2({oldfd}, {newfd}) → {raw_newfd}");
        Ok(raw_newfd)
    }
```

**Important:** `descriptor_table_mut().duplicate()` returns `Option<TypedFd<T>>` (not wrapped in `Arc`). The `TypedFd` is the owned value. `fd_into_specific_raw_integer` takes `TypedFd<Subsystem>` (owned). So the `Arc::try_unwrap` approach above is wrong — `duplicate()` already returns an owned `TypedFd`. Let me fix:

Actually, looking at the existing code more carefully, `rds.fd_from_raw_integer::<FS>(raw_oldfd)` returns `Arc<TypedFd<FS>>`, and `duplicate()` takes `&TypedFd<FS>` and returns `Option<TypedFd<FS>>` (owned, no Arc). And `fd_into_specific_raw_integer` takes `TypedFd<Subsystem>` (owned). So:

```rust
    pub(crate) fn sys_dup2(&self, oldfd: i32, newfd: i32) -> Result<usize, Errno> {
        let raw_oldfd = fd_to_usize(oldfd)?;
        let raw_newfd = fd_to_usize(newfd)?;

        // Resolve the old fd to validate it exists.
        let strong_fd = {
            let rds = self.global.raw_descriptors.read();
            crate::StrongFd::from_raw(&rds, raw_oldfd)?
        };

        // If oldfd == newfd, dup2 is a no-op (just validates oldfd).
        if raw_oldfd == raw_newfd {
            return Ok(raw_newfd);
        }

        // Duplicate the underlying descriptor.
        // duplicate() is subsystem-agnostic — it works at the DescriptorEntry level.
        let duplicated = match &strong_fd {
            crate::StrongFd::FileSystem(typed_fd) => self
                .global
                .litebox
                .descriptor_table_mut()
                .duplicate(typed_fd)
                .ok_or(Errno::EBADF)
                .map(DuplicatedFd::FileSystem),
            crate::StrongFd::Pipes(typed_fd) => self
                .global
                .litebox
                .descriptor_table_mut()
                .duplicate(typed_fd)
                .ok_or(Errno::EBADF)
                .map(DuplicatedFd::Pipes),
        }?;

        // If newfd is already open, close it first (try all subsystems).
        {
            let mut rds = self.global.raw_descriptors.write();
            if let Ok(existing_fd) = rds.fd_consume_raw_integer::<FS>(raw_newfd) {
                let _ = self.global.fs.close(&existing_fd);
            } else if let Ok(existing_fd) =
                rds.fd_consume_raw_integer::<Pipes<Platform>>(raw_newfd)
            {
                let _ = self.global.pipes.close(&existing_fd);
            }
        }

        // Insert the duplicated fd at the specific newfd slot.
        {
            let mut rds = self.global.raw_descriptors.write();
            let success = match duplicated {
                DuplicatedFd::FileSystem(typed_fd) => {
                    rds.fd_into_specific_raw_integer(typed_fd, raw_newfd)
                }
                DuplicatedFd::Pipes(typed_fd) => {
                    rds.fd_into_specific_raw_integer(typed_fd, raw_newfd)
                }
            };
            if !success {
                return Err(Errno::EBADF);
            }
        }

        // Copy the path entry from oldfd to newfd for F_GETPATH support.
        {
            let mut paths = self.global.fd_paths.write();
            if let Some(path) = paths.get(&raw_oldfd).cloned() {
                paths.insert(raw_newfd, path);
            }
        }

        log_unsupported!("dup2({oldfd}, {newfd}) → {raw_newfd}");
        Ok(raw_newfd)
    }
```

And add this helper enum at the file level (inside `file.rs`, near the top):

```rust
/// Owned duplicated FD, used by sys_dup2 to hold the result of descriptor_table.duplicate().
enum DuplicatedFd<FS: ShimFS> {
    FileSystem(litebox::fd::TypedFd<FS>),
    Pipes(litebox::fd::TypedFd<Pipes<Platform>>),
}
```

Add import:
```rust
use litebox::fd::TypedFd;
```

- [ ] **Step 8: Verify it compiles**

Run: `cargo check -p litebox_shim_macos`
Expected: compiles. May need to fix import paths.

- [ ] **Step 9: Verify existing tests still pass**

Run: `cargo test -p litebox_runner_macos_on_macos_userland -- --nocapture`
Expected: all existing tests pass (hello_dynamic, thread, signal, etc.)

- [ ] **Step 10: Commit**

```bash
git add litebox_shim_macos/src/lib.rs litebox_shim_macos/src/syscalls/file.rs
git commit -m "feat(macos): add StrongFd dispatch for read/write/close across subsystems"
```

---

## Task 5: Implement sys_pipe with dual-register return

**Files:**
- Modify: `litebox_shim_macos/src/lib.rs` (add `sys_pipe`, intercept `Pipe` in `handle_syscall_request`)
- Modify: `litebox_shim_macos/src/syscalls/mod.rs` (add `Pipe` dispatch arm)

- [ ] **Step 1: Add sys_pipe method to Task**

In `litebox_shim_macos/src/lib.rs`, add this method to the `impl<FS: ShimFS> Task<FS>` block (after `handle_init_request`, before `handle_syscall_request`):

```rust
    /// Handle `pipe()` — create an anonymous pipe.
    ///
    /// Returns `(read_fd, write_fd)` as raw integer FDs.
    fn sys_pipe(&self) -> Result<(usize, usize), Errno> {
        use core::num::NonZeroUsize;

        let (sender, receiver) = self.global.pipes.create_pipe(
            65536,                                  // capacity (standard pipe buffer)
            litebox::pipes::Flags::empty(),         // blocking mode
            NonZeroUsize::new(4096),                // PIPE_BUF atomic guarantee
        );

        let mut rds = self.global.raw_descriptors.write();
        let read_fd = rds.fd_into_raw_integer(receiver);
        let write_fd = rds.fd_into_raw_integer(sender);

        log_unsupported!("pipe() → read_fd={read_fd}, write_fd={write_fd}");
        Ok((read_fd, write_fd))
    }
```

- [ ] **Step 2: Intercept Pipe in handle_syscall_request**

In `litebox_shim_macos/src/lib.rs`, modify `handle_syscall_request` (line 906-944). The `Pipe` syscall needs dual-register return (x0=read_fd, x1=write_fd), so it must be intercepted before `do_syscall`/`set_syscall_return`, similar to `Sigreturn`.

Change the current code from:

```rust
        // Sigreturn restores the full register set (including pstate) and must
        // NOT be followed by set_syscall_return, which would overwrite x0 and
        // the carry flag.
        if let litebox_common_macos::syscall::MacosSyscallRequest::Sigreturn { uctx, .. } = &request
        {
            self.sys_sigreturn(ctx, *uctx);
            return;
        }

        let result = self.do_syscall(request, ctx);
        litebox_common_macos::syscall::set_syscall_return(ctx, result);
```

To:

```rust
        // Sigreturn restores the full register set (including pstate) and must
        // NOT be followed by set_syscall_return, which would overwrite x0 and
        // the carry flag.
        if let litebox_common_macos::syscall::MacosSyscallRequest::Sigreturn { uctx, .. } = &request
        {
            self.sys_sigreturn(ctx, *uctx);
            return;
        }

        // Pipe returns two values (read_fd in x0, write_fd in x1) via the macOS
        // dual-register return convention. set_syscall_return only sets x0, so
        // we handle pipe specially.
        if let litebox_common_macos::syscall::MacosSyscallRequest::Pipe = &request {
            match self.sys_pipe() {
                Ok((read_fd, write_fd)) => {
                    ctx.regs[0] = read_fd;
                    ctx.regs[1] = write_fd;
                    ctx.pstate &= !litebox_common_macos::syscall::CARRY_BIT;
                }
                Err(errno) => {
                    litebox_common_macos::syscall::set_syscall_return(ctx, Err(errno));
                }
            }
            return;
        }

        let result = self.do_syscall(request, ctx);
        litebox_common_macos::syscall::set_syscall_return(ctx, result);
```

- [ ] **Step 3: Add Pipe arm to do_syscall dispatch**

In `litebox_shim_macos/src/syscalls/mod.rs`, add a `Pipe` arm in the `do_syscall` match. Since `Pipe` is intercepted in `handle_syscall_request` before reaching `do_syscall`, make it unreachable:

```rust
            MacosSyscallRequest::Pipe => {
                unreachable!("Pipe is handled in handle_syscall_request before do_syscall")
            }
```

Add this before the `MacosSyscallRequest::Unknown` arm.

- [ ] **Step 4: Verify it compiles**

Run: `cargo check -p litebox_shim_macos`
Expected: compiles with no errors.

- [ ] **Step 5: Commit**

```bash
git add litebox_shim_macos/src/lib.rs litebox_shim_macos/src/syscalls/mod.rs
git commit -m "feat(macos): implement pipe() syscall with dual-register return"
```

---

## Task 6: Create pipe.c test and test_pipe function

**Files:**
- Create: `litebox_runner_macos_on_macos_userland/tests/pipe.c`
- Modify: `litebox_runner_macos_on_macos_userland/tests/loader.rs` (add `test_pipe`)

- [ ] **Step 1: Create pipe.c test program**

Create `litebox_runner_macos_on_macos_userland/tests/pipe.c`:

```c
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Test: pipe() syscall — create pipe, write, read, verify data, close.
// Exit codes: 0 = success, 1-4 = specific failure.

#include <unistd.h>
#include <string.h>

int main(void) {
    int fds[2];
    if (pipe(fds) != 0) _exit(1);

    const char *msg = "hello pipe";
    ssize_t msg_len = (ssize_t)strlen(msg);

    // Write to write-end (fds[1])
    ssize_t written = write(fds[1], msg, (size_t)msg_len);
    if (written != msg_len) _exit(2);

    // Read from read-end (fds[0])
    char buf[64];
    ssize_t nread = read(fds[0], buf, sizeof(buf));
    if (nread != msg_len) _exit(3);
    if (memcmp(buf, msg, (size_t)nread) != 0) _exit(4);

    close(fds[0]);
    close(fds[1]);

    _exit(0);
}
```

- [ ] **Step 2: Add test_pipe function to loader.rs**

In `litebox_runner_macos_on_macos_userland/tests/loader.rs`, add this test after the existing `test_signal` test:

```rust
#[test]
#[allow(clippy::cast_precision_loss)]
fn test_pipe() {
    let cache_dir = std::path::Path::new("/System/Cryptexes/OS/System/Library/dyld");
    assert!(
        cache_dir.exists(),
        "Shared cache not found at {}. This test requires macOS with dyld shared cache.",
        cache_dir.display()
    );

    let map_path = cache_dir.join("dyld_shared_cache_arm64e.map");
    let map_text = std::fs::read_to_string(&map_path).unwrap();
    let cache_map = common::shared_cache::CacheMap::parse(&map_text);
    let system_dylibs = cache_map.system_dylib_paths();
    let dylib_refs: Vec<&str> = system_dylibs
        .iter()
        .map(std::string::String::as_str)
        .collect();
    let cache_result = common::shared_cache::collect_regions(cache_dir, &cache_map, &dylib_refs);

    let bin_path = common::compile_macho_dynamic("./tests/pipe.c", "pipe");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    let (exit_code, _stdout) =
        common::run_macho_dynamic(&binary_data, &["/usr/bin/pipe"], &cache_result, "pipe");
    assert_eq!(exit_code, 0, "pipe test failed with exit code {exit_code}");
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check -p litebox_runner_macos_on_macos_userland --tests`
Expected: compiles.

- [ ] **Step 4: Run the test**

Run: `cargo test -p litebox_runner_macos_on_macos_userland test_pipe -- --nocapture`
Expected: test passes (exit code 0).

- [ ] **Step 5: Commit**

```bash
git add litebox_runner_macos_on_macos_userland/tests/pipe.c litebox_runner_macos_on_macos_userland/tests/loader.rs
git commit -m "test(macos): add pipe() end-to-end test"
```

---

## Task 7: Implement filesystem syscalls (unlink, mkdir, rmdir, access, fchmod, ftruncate)

**Files:**
- Modify: `litebox_shim_macos/src/syscalls/file.rs` (add 6 new handler methods)
- Modify: `litebox_shim_macos/src/syscalls/mod.rs` (add 6 dispatch arms)

- [ ] **Step 1: Add sys_unlink**

In `litebox_shim_macos/src/syscalls/file.rs`, add to the `impl<FS: ShimFS> Task<FS>` block:

```rust
    /// Handle `unlink(path)`.
    pub(crate) fn sys_unlink(&self, path_addr: usize) -> Result<usize, Errno> {
        let path_ptr: ConstPtr<u8> = ConstPtr::from_usize(path_addr);
        let path = read_cstring_from_guest(path_ptr, 4096).ok_or(Errno::EFAULT)?;
        log_unsupported!("unlink({path:?})");

        let cpath = alloc::ffi::CString::new(path.as_bytes()).map_err(|_| Errno::EINVAL)?;
        self.global.fs.unlink(&cpath).map_err(|e| match e {
            litebox::fs::errors::UnlinkError::PathError(ref pe) => {
                use litebox::fs::errors::PathError;
                match pe {
                    PathError::NoSuchFileOrDirectory => Errno::ENOENT,
                    PathError::ComponentNotADirectory => Errno::ENOTDIR,
                    _ => Errno::EINVAL,
                }
            }
            litebox::fs::errors::UnlinkError::IsADirectory => Errno::EPERM,
            litebox::fs::errors::UnlinkError::NoWritePerms => Errno::EACCES,
            litebox::fs::errors::UnlinkError::ReadOnlyFileSystem => Errno::EROFS,
            _ => Errno::EIO,
        })?;
        Ok(0)
    }
```

- [ ] **Step 2: Add sys_mkdir**

```rust
    /// Handle `mkdir(path, mode)`.
    pub(crate) fn sys_mkdir(&self, path_addr: usize, mode: u32) -> Result<usize, Errno> {
        let path_ptr: ConstPtr<u8> = ConstPtr::from_usize(path_addr);
        let path = read_cstring_from_guest(path_ptr, 4096).ok_or(Errno::EFAULT)?;
        log_unsupported!("mkdir({path:?}, mode={mode:#o})");

        let cpath = alloc::ffi::CString::new(path.as_bytes()).map_err(|_| Errno::EINVAL)?;
        let fs_mode = litebox::fs::Mode::from_bits_truncate(mode);
        self.global.fs.mkdir(&cpath, fs_mode).map_err(|e| match e {
            litebox::fs::errors::MkdirError::PathError(ref pe) => {
                use litebox::fs::errors::PathError;
                match pe {
                    PathError::NoSuchFileOrDirectory => Errno::ENOENT,
                    PathError::ComponentNotADirectory => Errno::ENOTDIR,
                    _ => Errno::EINVAL,
                }
            }
            litebox::fs::errors::MkdirError::AlreadyExists => Errno::EEXIST,
            litebox::fs::errors::MkdirError::NoWritePerms => Errno::EACCES,
            litebox::fs::errors::MkdirError::ReadOnlyFileSystem => Errno::EROFS,
            _ => Errno::EIO,
        })?;
        Ok(0)
    }
```

- [ ] **Step 3: Add sys_rmdir**

```rust
    /// Handle `rmdir(path)`.
    pub(crate) fn sys_rmdir(&self, path_addr: usize) -> Result<usize, Errno> {
        let path_ptr: ConstPtr<u8> = ConstPtr::from_usize(path_addr);
        let path = read_cstring_from_guest(path_ptr, 4096).ok_or(Errno::EFAULT)?;
        log_unsupported!("rmdir({path:?})");

        let cpath = alloc::ffi::CString::new(path.as_bytes()).map_err(|_| Errno::EINVAL)?;
        self.global.fs.rmdir(&cpath).map_err(|e| match e {
            litebox::fs::errors::RmdirError::PathError(ref pe) => {
                use litebox::fs::errors::PathError;
                match pe {
                    PathError::NoSuchFileOrDirectory => Errno::ENOENT,
                    PathError::ComponentNotADirectory => Errno::ENOTDIR,
                    _ => Errno::EINVAL,
                }
            }
            litebox::fs::errors::RmdirError::NotEmpty => Errno::ENOTEMPTY,
            litebox::fs::errors::RmdirError::NotADirectory => Errno::ENOTDIR,
            litebox::fs::errors::RmdirError::NoWritePerms => Errno::EACCES,
            litebox::fs::errors::RmdirError::Busy => Errno::EBUSY,
            litebox::fs::errors::RmdirError::ReadOnlyFileSystem => Errno::EROFS,
            _ => Errno::EIO,
        })?;
        Ok(0)
    }
```

- [ ] **Step 4: Add sys_access**

```rust
    /// Handle `access(path, amode)` — check file accessibility.
    ///
    /// Stub: F_OK checks existence via `file_status()`, R_OK/W_OK/X_OK always succeed.
    pub(crate) fn sys_access(&self, path_addr: usize, amode: i32) -> Result<usize, Errno> {
        let path_ptr: ConstPtr<u8> = ConstPtr::from_usize(path_addr);
        let path = read_cstring_from_guest(path_ptr, 4096).ok_or(Errno::EFAULT)?;
        log_unsupported!("access({path:?}, amode={amode})");

        let cpath = alloc::ffi::CString::new(path.as_bytes()).map_err(|_| Errno::EINVAL)?;
        // F_OK (0) or any mode — just check existence.
        self.global
            .fs
            .file_status(&cpath)
            .map_err(|e| match e {
                litebox::fs::errors::FileStatusError::PathError(ref pe) => {
                    use litebox::fs::errors::PathError;
                    match pe {
                        PathError::NoSuchFileOrDirectory => Errno::ENOENT,
                        PathError::ComponentNotADirectory => Errno::ENOTDIR,
                        _ => Errno::EINVAL,
                    }
                }
                _ => Errno::EIO,
            })?;
        // R_OK/W_OK/X_OK: always succeed in sandbox.
        Ok(0)
    }
```

- [ ] **Step 5: Add sys_fchmod**

```rust
    /// Handle `fchmod(fd, mode)` — stub: return success.
    ///
    /// Permissions are not enforced in the sandbox, so this is a no-op.
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn sys_fchmod(&self, fd: i32, mode: u32) -> Result<usize, Errno> {
        log_unsupported!("fchmod(fd={fd}, mode={mode:#o}) → stub Ok(0)");
        // Validate fd exists
        let raw_fd = fd_to_usize(fd)?;
        let rds = self.global.raw_descriptors.read();
        crate::StrongFd::from_raw(&rds, raw_fd)?;
        Ok(0)
    }
```

- [ ] **Step 6: Add sys_ftruncate**

```rust
    /// Handle `ftruncate(fd, length)`.
    pub(crate) fn sys_ftruncate(&self, fd: i32, length: i64) -> Result<usize, Errno> {
        let raw_fd = fd_to_usize(fd)?;
        let typed_fd = {
            let rds = self.global.raw_descriptors.read();
            rds.fd_from_raw_integer::<FS>(raw_fd)
                .map_err(|_| Errno::EBADF)?
        };

        let len = usize::try_from(length).map_err(|_| Errno::EINVAL)?;
        self.global
            .fs
            .truncate(&typed_fd, len, false)
            .map_err(|e| match e {
                litebox::fs::errors::TruncateError::ClosedFd => Errno::EBADF,
                litebox::fs::errors::TruncateError::IsDirectory => Errno::EINVAL,
                litebox::fs::errors::TruncateError::NotForWriting => Errno::EINVAL,
                litebox::fs::errors::TruncateError::IsTerminalDevice => Errno::EINVAL,
                litebox::fs::errors::TruncateError::Io => Errno::EIO,
            })?;
        Ok(0)
    }
```

- [ ] **Step 7: Add dispatch arms in mod.rs**

In `litebox_shim_macos/src/syscalls/mod.rs`, add these arms to `do_syscall` match (before the `Unknown` arm):

```rust
            MacosSyscallRequest::Unlink { path } => self.sys_unlink(path),
            MacosSyscallRequest::Access { path, amode } => self.sys_access(path, amode),
            MacosSyscallRequest::Fchmod { fd, mode } => self.sys_fchmod(fd, mode),
            MacosSyscallRequest::Mkdir { path, mode } => self.sys_mkdir(path, mode),
            MacosSyscallRequest::Rmdir { path } => self.sys_rmdir(path),
            MacosSyscallRequest::Ftruncate { fd, length } => self.sys_ftruncate(fd, length),
```

- [ ] **Step 8: Verify it compiles**

Run: `cargo check -p litebox_shim_macos`
Expected: compiles with no errors.

- [ ] **Step 9: Commit**

```bash
git add litebox_shim_macos/src/syscalls/file.rs litebox_shim_macos/src/syscalls/mod.rs
git commit -m "feat(macos): implement filesystem syscalls (unlink, mkdir, rmdir, access, fchmod, ftruncate)"
```

---

## Task 8: Implement getdirentries64 syscall

**Files:**
- Modify: `litebox_shim_macos/src/syscalls/file.rs` (add `sys_getdirentries64`)
- Modify: `litebox_shim_macos/src/syscalls/mod.rs` (add dispatch arm)

This is the most complex filesystem syscall — it requires serializing `DirEntry` values into macOS `struct dirent` format.

- [ ] **Step 1: Add sys_getdirentries64 handler**

In `litebox_shim_macos/src/syscalls/file.rs`, add:

```rust
    /// Handle `getdirentries64(fd, buf, bufsize, basep)`.
    ///
    /// Reads directory entries from the directory FD and serializes them as
    /// macOS `struct dirent` records into the user buffer. Returns the number
    /// of bytes written.
    ///
    /// macOS `struct dirent` layout (aarch64):
    /// - offset 0: d_ino (u64, 8 bytes)
    /// - offset 8: d_seekoff (u64, 8 bytes)
    /// - offset 16: d_reclen (u16, 2 bytes) — total record length including padding
    /// - offset 18: d_namlen (u16, 2 bytes) — length of d_name (excluding NUL)
    /// - offset 20: d_type (u8, 1 byte) — DT_REG=8, DT_DIR=4, DT_CHR=2
    /// - offset 21: d_name (variable) — NUL-terminated name
    /// - padding to 8-byte alignment
    #[allow(clippy::cast_possible_truncation)]
    pub(crate) fn sys_getdirentries64(
        &self,
        fd: i32,
        buf_addr: usize,
        bufsize: usize,
        basep: usize,
    ) -> Result<usize, Errno> {
        let raw_fd = fd_to_usize(fd)?;
        let typed_fd = {
            let rds = self.global.raw_descriptors.read();
            rds.fd_from_raw_integer::<FS>(raw_fd)
                .map_err(|_| Errno::EBADF)?
        };

        let entries = self
            .global
            .fs
            .read_dir(&typed_fd)
            .map_err(|e| match e {
                litebox::fs::errors::ReadDirError::ClosedFd => Errno::EBADF,
                litebox::fs::errors::ReadDirError::NotADirectory => Errno::ENOTDIR,
                litebox::fs::errors::ReadDirError::Io => Errno::EIO,
            })?;

        // Serialize entries into macOS dirent format.
        let mut output = alloc::vec::Vec::with_capacity(bufsize.min(MAX_KERNEL_BUF_SIZE));
        let mut seek_offset: u64 = 1;

        for entry in &entries {
            let name_bytes = entry.name.as_bytes();
            let namlen = name_bytes.len();
            // d_reclen = header (21 bytes) + name + NUL, rounded up to 8-byte alignment
            let reclen = (21 + namlen + 1 + 7) & !7;
            if output.len() + reclen > bufsize {
                break; // buffer full
            }

            let ino: u64 = entry
                .ino_info
                .as_ref()
                .map_or(seek_offset, |info| info.ino as u64);
            let d_type: u8 = match entry.file_type {
                litebox::fs::FileType::RegularFile => 8, // DT_REG
                litebox::fs::FileType::Directory => 4,   // DT_DIR
                litebox::fs::FileType::CharacterDevice => 2, // DT_CHR
            };

            // d_ino (8 bytes)
            output.extend_from_slice(&ino.to_le_bytes());
            // d_seekoff (8 bytes)
            output.extend_from_slice(&seek_offset.to_le_bytes());
            // d_reclen (2 bytes)
            output.extend_from_slice(&(reclen as u16).to_le_bytes());
            // d_namlen (2 bytes)
            output.extend_from_slice(&(namlen as u16).to_le_bytes());
            // d_type (1 byte)
            output.push(d_type);
            // d_name (NUL-terminated)
            output.extend_from_slice(name_bytes);
            output.push(0); // NUL terminator
            // Pad to 8-byte alignment
            while output.len() % 8 != 0 {
                output.push(0);
            }

            seek_offset += 1;
        }

        // Write output to user buffer
        if !output.is_empty() {
            let user_buf: MutPtr<u8> = MutPtr::from_usize(buf_addr);
            user_buf
                .copy_from_slice(0, &output)
                .ok_or(Errno::EFAULT)?;
        }

        // Write basep (position) if non-null
        if basep != 0 {
            let basep_ptr: MutPtr<u64> = MutPtr::from_usize(basep);
            basep_ptr
                .write_at_offset(0, seek_offset)
                .ok_or(Errno::EFAULT)?;
        }

        Ok(output.len())
    }
```

- [ ] **Step 2: Add dispatch arm in mod.rs**

In `litebox_shim_macos/src/syscalls/mod.rs`, add:

```rust
            MacosSyscallRequest::Getdirentries64 {
                fd,
                buf,
                bufsize,
                basep,
            } => self.sys_getdirentries64(fd, buf, bufsize, basep),
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check -p litebox_shim_macos`
Expected: compiles.

- [ ] **Step 4: Commit**

```bash
git add litebox_shim_macos/src/syscalls/file.rs litebox_shim_macos/src/syscalls/mod.rs
git commit -m "feat(macos): implement getdirentries64 syscall"
```

---

## Task 9: Create filesystem.c test and test_filesystem function

**Files:**
- Create: `litebox_runner_macos_on_macos_userland/tests/filesystem.c`
- Modify: `litebox_runner_macos_on_macos_userland/tests/loader.rs`

- [ ] **Step 1: Create filesystem.c**

Create `litebox_runner_macos_on_macos_userland/tests/filesystem.c`:

```c
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Test: filesystem operations — mkdir, open/write/read, ftruncate, unlink, rmdir.
// Exit codes: 0 = success, 1-12 = specific failure.

#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

int main(void) {
    // Test mkdir
    if (mkdir("/tmp/testdir", 0755) != 0) _exit(1);

    // Test creating a file in the directory
    int fd = open("/tmp/testdir/hello.txt", O_CREAT | O_WRONLY, 0644);
    if (fd < 0) _exit(2);
    const char *data = "hello filesystem";
    ssize_t data_len = (ssize_t)strlen(data);
    ssize_t w = write(fd, data, (size_t)data_len);
    if (w != data_len) _exit(20);
    close(fd);

    // Test reading back
    fd = open("/tmp/testdir/hello.txt", O_RDONLY);
    if (fd < 0) _exit(3);
    char buf[64];
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n != data_len) _exit(4);
    if (memcmp(buf, data, (size_t)n) != 0) _exit(5);
    close(fd);

    // Test ftruncate
    fd = open("/tmp/testdir/hello.txt", O_WRONLY);
    if (fd < 0) _exit(6);
    if (ftruncate(fd, 5) != 0) _exit(7);
    close(fd);
    fd = open("/tmp/testdir/hello.txt", O_RDONLY);
    if (fd < 0) _exit(8);
    n = read(fd, buf, sizeof(buf));
    if (n != 5) _exit(9);
    close(fd);

    // Test unlink
    if (unlink("/tmp/testdir/hello.txt") != 0) _exit(10);

    // Test rmdir
    if (rmdir("/tmp/testdir") != 0) _exit(11);

    // Verify directory is gone — re-creating should succeed
    if (mkdir("/tmp/testdir", 0755) != 0) _exit(12);
    rmdir("/tmp/testdir"); // cleanup

    _exit(0);
}
```

- [ ] **Step 2: Add test_filesystem to loader.rs**

In `litebox_runner_macos_on_macos_userland/tests/loader.rs`, add this test:

```rust
#[test]
#[allow(clippy::cast_precision_loss)]
fn test_filesystem() {
    let cache_dir = std::path::Path::new("/System/Cryptexes/OS/System/Library/dyld");
    assert!(
        cache_dir.exists(),
        "Shared cache not found at {}. This test requires macOS with dyld shared cache.",
        cache_dir.display()
    );

    let map_path = cache_dir.join("dyld_shared_cache_arm64e.map");
    let map_text = std::fs::read_to_string(&map_path).unwrap();
    let cache_map = common::shared_cache::CacheMap::parse(&map_text);
    let system_dylibs = cache_map.system_dylib_paths();
    let dylib_refs: Vec<&str> = system_dylibs
        .iter()
        .map(std::string::String::as_str)
        .collect();
    let cache_result = common::shared_cache::collect_regions(cache_dir, &cache_map, &dylib_refs);

    let bin_path = common::compile_macho_dynamic("./tests/filesystem.c", "filesystem");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    let (exit_code, _stdout) = common::run_macho_dynamic(
        &binary_data,
        &["/usr/bin/filesystem"],
        &cache_result,
        "filesystem",
    );
    assert_eq!(
        exit_code, 0,
        "filesystem test failed with exit code {exit_code}"
    );
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check -p litebox_runner_macos_on_macos_userland --tests`
Expected: compiles.

- [ ] **Step 4: Run the test**

Run: `cargo test -p litebox_runner_macos_on_macos_userland test_filesystem -- --nocapture`
Expected: test passes (exit code 0).

- [ ] **Step 5: Commit**

```bash
git add litebox_runner_macos_on_macos_userland/tests/filesystem.c litebox_runner_macos_on_macos_userland/tests/loader.rs
git commit -m "test(macos): add filesystem operations end-to-end test"
```

---

## Task 10: Implement __semwait_signal syscall

**Files:**
- Modify: `litebox_shim_macos/src/lib.rs` or `litebox_shim_macos/src/syscalls/stubs.rs` (add `sys_semwait_signal`)
- Modify: `litebox_shim_macos/src/syscalls/mod.rs` (add dispatch arm)

The `__semwait_signal` syscall is used by `usleep()` on macOS. It's needed for the thread_exit test. We implement it as a real timed wait using `std::thread::sleep`.

- [ ] **Step 1: Add sys_semwait_signal to stubs.rs**

In `litebox_shim_macos/src/syscalls/stubs.rs`, add:

```rust
    /// Handle `__semwait_signal(cond_sem, mutex_sem, timeout, relative, tv_sec, tv_nsec)`.
    ///
    /// Used by `usleep()` in libSystem. If `timeout` is non-zero, sleeps for the
    /// requested duration. Otherwise returns immediately.
    #[allow(clippy::unnecessary_wraps)]
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
            let duration = core::time::Duration::new(tv_sec as u64, tv_nsec as u32);
            // Use the wait state to perform an interruptible sleep.
            // If the process is exiting, this will return early.
            let cx = self.wait_cx().with_timeout(duration);
            let _ = cx.sleep(); // returns WaitError::TimedOut or Interrupted
        }
        Ok(0)
    }
```

- [ ] **Step 2: Add dispatch arm in mod.rs**

In `litebox_shim_macos/src/syscalls/mod.rs`, add:

```rust
            MacosSyscallRequest::SemwaitSignal {
                cond_sem,
                mutex_sem,
                timeout,
                relative,
                tv_sec,
                tv_nsec,
            } => self.sys_semwait_signal(cond_sem, mutex_sem, timeout, relative, tv_sec, tv_nsec),
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check -p litebox_shim_macos`
Expected: compiles.

- [ ] **Step 4: Commit**

```bash
git add litebox_shim_macos/src/syscalls/stubs.rs litebox_shim_macos/src/syscalls/mod.rs
git commit -m "feat(macos): implement __semwait_signal syscall for usleep support"
```

---

## Task 11: Create thread_exit.c test and test_thread_exit function

**Files:**
- Create: `litebox_runner_macos_on_macos_userland/tests/thread_exit.c`
- Modify: `litebox_runner_macos_on_macos_userland/tests/loader.rs`

- [ ] **Step 1: Create thread_exit.c**

Create `litebox_runner_macos_on_macos_userland/tests/thread_exit.c`:

```c
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Test: process-wide _exit() terminates all threads.
// Spawns threads in different states (spin, yield, sleep), then one thread
// calls _exit(0). If the process exits cleanly with code 0, all threads
// were successfully torn down.

#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>

static void *spin_thread(void *arg) {
    (void)arg;
    volatile int x = 0;
    while (1) { x++; }
    return NULL;
}

static void *yield_thread(void *arg) {
    (void)arg;
    while (1) { sched_yield(); }
    return NULL;
}

static void *sleep_thread(void *arg) {
    (void)arg;
    while (1) { usleep(100000); } // 100ms
    return NULL;
}

static void *exit_thread(void *arg) {
    (void)arg;
    // Brief sleep to let other threads start
    usleep(10000); // 10ms
    _exit(0);
    return NULL; // unreachable
}

int main(void) {
    pthread_t t;

    // Spawn 2 threads of each type
    pthread_create(&t, NULL, spin_thread, NULL);
    pthread_create(&t, NULL, spin_thread, NULL);
    pthread_create(&t, NULL, yield_thread, NULL);
    pthread_create(&t, NULL, yield_thread, NULL);
    pthread_create(&t, NULL, sleep_thread, NULL);
    pthread_create(&t, NULL, sleep_thread, NULL);

    // Spawn the exit thread
    pthread_create(&t, NULL, exit_thread, NULL);

    // Main thread also sleeps — exit_thread will call _exit(0)
    while (1) { usleep(100000); }

    // Should never reach here
    _exit(99);
}
```

- [ ] **Step 2: Add test_thread_exit to loader.rs**

In `litebox_runner_macos_on_macos_userland/tests/loader.rs`, add:

```rust
#[test]
#[allow(clippy::cast_precision_loss)]
fn test_thread_exit() {
    let cache_dir = std::path::Path::new("/System/Cryptexes/OS/System/Library/dyld");
    assert!(
        cache_dir.exists(),
        "Shared cache not found at {}. This test requires macOS with dyld shared cache.",
        cache_dir.display()
    );

    let map_path = cache_dir.join("dyld_shared_cache_arm64e.map");
    let map_text = std::fs::read_to_string(&map_path).unwrap();
    let cache_map = common::shared_cache::CacheMap::parse(&map_text);
    let system_dylibs = cache_map.system_dylib_paths();
    let dylib_refs: Vec<&str> = system_dylibs
        .iter()
        .map(std::string::String::as_str)
        .collect();
    let cache_result = common::shared_cache::collect_regions(cache_dir, &cache_map, &dylib_refs);

    let bin_path = common::compile_macho_dynamic("./tests/thread_exit.c", "thread_exit");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    let (exit_code, _stdout) = common::run_macho_dynamic(
        &binary_data,
        &["/usr/bin/thread_exit"],
        &cache_result,
        "thread_exit",
    );
    assert_eq!(
        exit_code, 0,
        "thread_exit test failed with exit code {exit_code}"
    );
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check -p litebox_runner_macos_on_macos_userland --tests`
Expected: compiles.

- [ ] **Step 4: Run the test**

Run: `cargo test -p litebox_runner_macos_on_macos_userland test_thread_exit -- --nocapture`
Expected: test passes (exit code 0). The process should complete in under 5 seconds.

- [ ] **Step 5: Commit**

```bash
git add litebox_runner_macos_on_macos_userland/tests/thread_exit.c litebox_runner_macos_on_macos_userland/tests/loader.rs
git commit -m "test(macos): add thread exit end-to-end test"
```

---

## Task 12: Final verification — all tests pass + clippy clean

**Files:** None (verification only)

- [ ] **Step 1: Run all tests**

Run: `cargo test -p litebox_runner_macos_on_macos_userland -- --nocapture`
Expected: All tests pass (existing + 3 new: test_pipe, test_filesystem, test_thread_exit).

- [ ] **Step 2: Run clippy**

Run: `cargo clippy -p litebox_common_macos -p litebox_shim_macos -p litebox_runner_macos_on_macos_userland -- -D warnings`
Expected: No warnings or errors.

- [ ] **Step 3: Run fmt check**

Run: `cargo fmt --check -p litebox_common_macos -p litebox_shim_macos -p litebox_runner_macos_on_macos_userland`
Expected: No formatting issues.

- [ ] **Step 4: Fix any issues found**

If any test fails, clippy warning, or fmt issue is found, fix it and re-run the checks.

- [ ] **Step 5: Final commit (if fixes were needed)**

```bash
git add -A
git commit -m "fix(macos): address Phase A final verification issues"
```
