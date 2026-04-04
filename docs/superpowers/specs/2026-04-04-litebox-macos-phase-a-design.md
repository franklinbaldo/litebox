# macOS Shim Phase A: FD Dispatch, Pipes, Filesystem, Thread Exit

## Goal

Extend `litebox_shim_macos` with foundational capabilities that non-GUI macOS applications require:

1. **Unified FD dispatch** — read/write/close work across filesystem, pipe, and (future) socket FDs
2. **Pipes** — `pipe()` syscall for basic IPC
3. **Filesystem operations** — `unlink`, `mkdir`, `rmdir`, `read_dir` (getdirentries64), `truncate`, `access`, `chmod`/`fchmod`
4. **Thread exit test** — verify process-wide `exit()` correctly terminates all threads

This is Phase A of a three-phase plan to support real non-GUI macOS applications:
- **Phase A** (this spec): FD dispatch + pipes + filesystem + thread exit
- **Phase B** (future): Sockets (AF_UNIX + AF_INET)
- **Phase C** (future): Process lifecycle (fork/exec/waitpid) + I/O multiplexing (select/poll/kqueue)

## Approach

Follow existing patterns: the `litebox` crate already provides `Pipes<Platform>` and `Network<Platform>` types with full FD subsystem integration. The macOS shim's `GlobalState` already initializes both (marked `#[expect(dead_code)]`). The Linux shim's `StrongFd` + `run_on_raw_fd` pattern demonstrates exactly how to dispatch read/write/close across subsystems.

The `FileSystem` trait already provides `unlink`, `mkdir`, `rmdir`, `read_dir`, `truncate`, `chmod` methods. We wire new BSD syscall numbers to these existing trait methods.

## 1. Unified FD Dispatch

### Problem

Currently `sys_read`, `sys_write`, `sys_close` in `litebox_shim_macos/src/syscalls/file.rs` assume all FDs are filesystem FDs (`TypedFd<FS>`). They call `rds.fd_from_raw_integer::<FS>(fd)` directly. Pipe FDs and (future) socket FDs would fail with `EBADF`.

### Design

Add a `StrongFd<FS>` enum and `resolve_fd` helper to the macOS shim, following the Linux shim's pattern (`litebox_shim_linux/src/lib.rs:535-569`):

```rust
enum StrongFd<FS: ShimFS> {
    FileSystem(Arc<TypedFd<FS>>),
    Pipes(Arc<TypedFd<Pipes<Platform>>>),
    // Network variant added in Phase B
}

impl<FS: ShimFS> StrongFd<FS> {
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

### Affected syscalls

| Syscall | Change |
|---------|--------|
| `sys_read` | Dispatch via `StrongFd`: FS → `fs.read()`, Pipes → `pipes.read()` |
| `sys_write` | Dispatch via `StrongFd`: FS → `fs.write()`, Pipes → `pipes.write()` |
| `sys_close` | Try each subsystem: FS → `fs.close()`, Pipes → `pipes.close()` |
| `sys_dup2` | Must work across subsystems — duplicate the underlying descriptor regardless of type |
| `sys_fstat64` | Pipes return `ESPIPE`; only FS FDs support fstat |
| `sys_pread` | Pipes return `ESPIPE` |
| `sys_lseek` | Pipes return `ESPIPE` |
| `sys_fcntl` | Pipes: `F_GETFL`/`F_SETFL` work (map to `pipes.get_flags()`/`update_flags()`), `F_GETPATH` returns `EBADF` |

### `dup2` across subsystems

The current `sys_dup2` implementation uses `descriptor_table_mut().duplicate()` which works at the `DescriptorEntry` level — it's subsystem-agnostic. The only issue is `fd_into_specific_raw_integer` needs to store the correct `TypeId` for the new slot. Since `duplicate()` returns a `TypedFd` of the same subsystem type, this should work correctly as-is. Verify during implementation.

## 2. Pipe Syscall

### macOS BSD `pipe()` — Syscall 42

macOS `pipe()` (BSD number 42) takes no user-space arguments. It returns two file descriptors via a dual-register return:
- **x0** = read-end FD
- **x1** = write-end FD
- **carry flag** cleared (success)

This is different from Linux `pipe2` which writes to a user-space `int[2]` array.

### `set_syscall_return` limitation

The current `set_syscall_return` (`litebox_common_macos/src/syscall.rs:481`) only sets `ctx.regs[0]` (x0) and the carry bit. It cannot set x1. For `pipe()`, we need to set both x0 and x1.

**Solution:** Handle `Pipe` in `handle_syscall_request` before calling `do_syscall`/`set_syscall_return`, similar to how `Sigreturn` is intercepted. After `sys_pipe()` succeeds, manually set `ctx.regs[0]`, `ctx.regs[1]`, and clear the carry bit.

### Syscall variant

```
// litebox_common_macos/src/syscall.rs
nr::PIPE = 42

MacosSyscallRequest::Pipe
// No arguments — macOS pipe() takes none
```

### Implementation

```rust
fn sys_pipe(&self) -> Result<(usize, usize), Errno> {
    let (sender, receiver) = self.global.pipes.create_pipe(
        65536,              // capacity (standard pipe buffer size)
        Flags::empty(),     // no flags (macOS pipe() has no flag argument)
        4096,               // atomic slice guarantee (PIPE_BUF on macOS)
    );

    let mut rds = self.global.raw_descriptors.write();
    let read_fd = rds.fd_into_raw_integer(receiver)?;
    let write_fd = rds.fd_into_raw_integer(sender)?;

    Ok((read_fd, write_fd))
}
```

### WaitContext requirement

`Pipes::read()` and `Pipes::write()` require a `&WaitContext` parameter for blocking semantics. The Linux shim obtains this from its wait infrastructure. Need to check how the macOS shim handles blocking — currently all FS reads/writes are non-blocking (in-memory). For pipes, blocking is essential (read blocks when pipe is empty, write blocks when pipe is full).

If the macOS shim doesn't have `WaitContext` yet, we may need to add it or use a simpler non-blocking approach initially and return `EAGAIN` when the pipe would block. For this spec, we'll implement blocking pipe I/O if `WaitContext` is available, or non-blocking with `EAGAIN` if not.

## 3. Filesystem Syscalls

### Available FS trait methods

The `FileSystem` trait (`litebox/src/fs/mod.rs:46-149`) provides these methods that we can wire to macOS BSD syscalls:

| FS Trait Method | Signature |
|-----------------|-----------|
| `unlink` | `fn unlink(&self, path: impl path::Arg) -> Result<(), UnlinkError>` |
| `mkdir` | `fn mkdir(&self, path: impl path::Arg, mode: Mode) -> Result<(), MkdirError>` |
| `rmdir` | `fn rmdir(&self, path: impl path::Arg) -> Result<(), RmdirError>` |
| `read_dir` | `fn read_dir(&self, fd: &TypedFd<Self>) -> Result<Vec<DirEntry>, ReadDirError>` |
| `truncate` | `fn truncate(&self, fd: &TypedFd<Self>, length: usize, reset_offset: bool) -> Result<(), TruncateError>` |
| `chmod` | `fn chmod(&self, path: impl path::Arg, mode: Mode) -> Result<(), ChmodError>` |
| `file_status` | `fn file_status(&self, path: impl path::Arg) -> Result<FileStatus, FileStatusError>` |

**Not in the FS trait:** `rename`, `readlink`, `symlink`, `link`. These are deferred from Phase A. The in-memory FS may not support symlinks. `rename` could be emulated as read+write+unlink but that's fragile — better to add it to the FS trait if needed.

### New BSD syscall mappings

| BSD Syscall | Number | Handler | Implementation |
|-------------|--------|---------|----------------|
| `unlink` | 10 | `sys_unlink(path)` | `fs.unlink(&cpath)` |
| `access` | 33 | `sys_access(path, amode)` | `fs.file_status(&cpath)`, check mode bits; stub: return `Ok(0)` for existing files |
| `fchmod` | 124 | `sys_fchmod(fd, mode)` | Stub: return `Ok(0)`. Permissions are not enforced in the sandbox. |
| `rename` | 128 | Defer to Phase B or later | Not in FS trait |
| `mkdir` | 136 | `sys_mkdir(path, mode)` | `fs.mkdir(&cpath, mode)` |
| `rmdir` | 137 | `sys_rmdir(path)` | `fs.rmdir(&cpath)` |
| `ftruncate` | 201 | `sys_ftruncate(fd, length)` | `fs.truncate(&typed_fd, length, false)` |
| `getdirentries64` | 344 | `sys_getdirentries64(fd, buf, bufsize, basep)` | `fs.read_dir(&typed_fd)`, serialize to macOS `dirent64` structs |

### macOS `struct dirent64` layout (aarch64)

For `getdirentries64`, we need to serialize `DirEntry` values into macOS `dirent64` format:

```c
struct dirent {
    __uint64_t  d_ino;      // offset 0, 8 bytes — inode number
    __uint64_t  d_seekoff;  // offset 8, 8 bytes — seek offset (opaque)
    __uint16_t  d_reclen;   // offset 16, 2 bytes — length of this record
    __uint16_t  d_namlen;   // offset 18, 2 bytes — length of d_name
    __uint8_t   d_type;     // offset 20, 1 byte — file type (DT_REG=8, DT_DIR=4, etc.)
    char        d_name[1024]; // offset 21, variable — NUL-terminated name
};
// Total minimum: 21 + namelen + 1 (NUL) + padding to 8-byte alignment
```

`d_reclen` is the total record length including padding. Records are packed contiguously in the buffer. The `basep` argument points to a `long` that receives the "position" (we can use the count of entries returned). Return value is the number of bytes written to the buffer, or 0 when no more entries.

### access() semantics

macOS `access(2)` (syscall 33) takes `(path, amode)` where `amode` is a bitmask of `R_OK(4)`, `W_OK(2)`, `X_OK(1)`, `F_OK(0)`. For the in-memory FS, we can:
- `F_OK`: check if the file exists via `fs.file_status()`
- `R_OK/W_OK/X_OK`: return `Ok(0)` (all files readable/writable in the sandbox)

### Error mapping

FS trait errors need mapping to `Errno`. Common pattern from the Linux shim:
- `UnlinkError::NotFound` → `ENOENT`
- `UnlinkError::IsDirectory` → `EISDIR` (or `EPERM` on macOS for unlink on dirs)
- `MkdirError::AlreadyExists` → `EEXIST`
- `MkdirError::NotFound` → `ENOENT` (parent doesn't exist)
- `RmdirError::NotFound` → `ENOENT`
- `RmdirError::NotEmpty` → `ENOTEMPTY`

Check the actual error variant names during implementation and map accordingly.

## 4. Thread Exit Test

### Concept

Test that `exit()` (or `_exit()`) from any thread terminates the entire process, including threads in various blocking states. This validates the macOS shim's process teardown semantics.

### Test design (`thread_exit.c`)

```c
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>

// Thread functions for different blocking states:
// 1. Spin loop (CPU-bound)
// 2. Yield loop (sched_yield)
// 3. Sleep (usleep)

// Spawn N threads of each type
// Have one "exit thread" that sleeps briefly then calls _exit(0)
// If we reach _exit(0), process exits cleanly — all threads are torn down
// If any thread somehow prevents exit, the test would hang (timeout = failure)
```

No Linux-specific APIs — uses only POSIX pthreads, `_exit()`, `sched_yield()`, `usleep()`.

### Required syscall support

The test needs `usleep()` to work, which on macOS goes through `__semwait_signal` (BSD syscall 334) or `__semwait_signal_nocancel` (423) inside libSystem.

**`__semwait_signal` signature:**
```c
int __semwait_signal(int cond_sem, int mutex_sem, int timeout, int relative,
                     __int64_t tv_sec, __int32_t tv_nsec);
```

For `usleep(N)`, libSystem calls `__semwait_signal(0, 0, 1, 1, sec, nsec)` with `timeout=1` (absolute=0, relative=1).

**Implementation:** The simplest approach is a real host-side sleep using the platform's time primitives. Since this is a sandbox, sleeping the host thread for the requested duration is acceptable.

Alternatively, if the macOS shim doesn't yet have blocking/wait infrastructure, we can stub `__semwait_signal` to return immediately (sleep duration = 0). The thread_exit test would still work because the exit thread just needs to run after the other threads are spawned — exact timing doesn't matter.

For this spec, implement `__semwait_signal` as a real timed wait if the platform provides sleep primitives, or as a no-op stub returning `Ok(0)` if not. The test should pass either way since `_exit()` is the mechanism being tested, not sleep accuracy.

### Test runner integration

Add `test_thread_exit` to `litebox_runner_macos_on_macos_userland/tests/loader.rs`, following the same pattern as `test_signal`:
- Compile with `compile_macho_dynamic`
- Run with `run_macho_dynamic`
- Verify exit code is 0

## 5. Pipe Test

### Test design (`pipe.c`)

```c
#include <unistd.h>
#include <string.h>

int main(void) {
    int fds[2];
    // macOS pipe() stores read-fd and write-fd in fds[0], fds[1]
    // but the libc wrapper handles the dual-register return for us
    if (pipe(fds) != 0) _exit(1);

    const char *msg = "hello pipe";
    char buf[64];

    // Write to write-end
    ssize_t written = write(fds[1], msg, strlen(msg));
    if (written != (ssize_t)strlen(msg)) _exit(2);

    // Read from read-end
    ssize_t nread = read(fds[0], buf, sizeof(buf));
    if (nread != (ssize_t)strlen(msg)) _exit(3);
    if (memcmp(buf, msg, nread) != 0) _exit(4);

    // Close both ends
    close(fds[0]);
    close(fds[1]);

    _exit(0);
}
```

**Note on libc `pipe()` wrapper:** The macOS libc `pipe()` wrapper handles the dual-register return convention. The wrapper receives x0 (read-fd) and x1 (write-fd) from the kernel, then stores them into the user's `int[2]` array. So from C code, `pipe(fds)` works normally. The dual-register handling is only needed at the shim's syscall dispatch level.

**Important:** Since the guest uses the shared cache's `libSystem`, the `pipe()` libc wrapper is already in the shared cache. The wrapper will issue `SVC #0x80` with x16=42, and the shim intercepts it. The wrapper then reads x0 and x1 from the return and stores them in the user's array. So the shim must correctly set both x0 and x1 on return.

### Pipe test runner integration

Add `test_pipe` to `loader.rs`, same pattern as other dynamic tests.

## 6. Filesystem Test

### Test design (`filesystem.c`)

```c
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
    write(fd, data, strlen(data));
    close(fd);

    // Test reading back
    fd = open("/tmp/testdir/hello.txt", O_RDONLY);
    if (fd < 0) _exit(3);
    char buf[64];
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n != (ssize_t)strlen(data)) _exit(4);
    if (memcmp(buf, data, n) != 0) _exit(5);
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

    // Verify directory is gone
    if (mkdir("/tmp/testdir", 0755) != 0) _exit(12);  // should succeed since we rmdir'd it
    rmdir("/tmp/testdir");  // cleanup

    _exit(0);
}
```

### Filesystem test runner integration

Add `test_filesystem` to `loader.rs`.

## 7. Summary of New Syscalls

| BSD # | Name | MacosSyscallRequest variant | Category |
|-------|------|-----------------------------|----------|
| 10 | `unlink` | `Unlink { path }` | Filesystem |
| 33 | `access` | `Access { path, amode }` | Filesystem |
| 42 | `pipe` | `Pipe` | Pipes |
| 124 | `fchmod` | `Fchmod { fd, mode }` | Filesystem |
| 136 | `mkdir` | `Mkdir { path, mode }` | Filesystem |
| 137 | `rmdir` | `Rmdir { path }` | Filesystem |
| 201 | `ftruncate` | `Ftruncate { fd, length }` | Filesystem |
| 334 | `__semwait_signal` | `SemwaitSignal { cond_sem, mutex_sem, timeout, relative, tv_sec, tv_nsec }` | Time/sleep |
| 344 | `getdirentries64` | `Getdirentries64 { fd, buf, bufsize, basep }` | Filesystem |

Total: 9 new syscall variants.

## 8. Files Modified

| File | Changes |
|------|---------|
| `litebox_common_macos/src/syscall.rs` | Add 9 new `nr::*` constants, 9 new `MacosSyscallRequest` variants, decoding match arms |
| `litebox_shim_macos/src/syscalls/mod.rs` | Add dispatch arms for all 9 new syscalls |
| `litebox_shim_macos/src/syscalls/file.rs` | Refactor read/write/close to use `StrongFd` dispatch; add `sys_unlink`, `sys_mkdir`, `sys_rmdir`, `sys_access`, `sys_fchmod`, `sys_ftruncate`, `sys_getdirentries64` |
| `litebox_shim_macos/src/lib.rs` | Add `StrongFd` enum; intercept `Pipe` in `handle_syscall_request` for dual-register return; remove `#[expect(dead_code)]` from `pipes` field; add `sys_semwait_signal` (or stub) |
| `litebox_shim_macos/src/syscalls/stubs.rs` | Possibly add `sys_semwait_signal` if it's a stub |

## 9. Files Created

| File | Purpose |
|------|---------|
| `litebox_runner_macos_on_macos_userland/tests/thread_exit.c` | Thread exit test |
| `litebox_runner_macos_on_macos_userland/tests/pipe.c` | Pipe test |
| `litebox_runner_macos_on_macos_userland/tests/filesystem.c` | Filesystem operations test |

## 10. Test Commands

```bash
# Run all macOS tests including new ones
cargo test -p litebox_runner_macos_on_macos_userland -- --nocapture

# Run specific new tests
cargo test -p litebox_runner_macos_on_macos_userland test_thread_exit -- --nocapture
cargo test -p litebox_runner_macos_on_macos_userland test_pipe -- --nocapture
cargo test -p litebox_runner_macos_on_macos_userland test_filesystem -- --nocapture

# Clippy and fmt verification
cargo clippy -p litebox_common_macos -p litebox_shim_macos -p litebox_runner_macos_on_macos_userland -- -D warnings
cargo fmt --check -p litebox_common_macos -p litebox_shim_macos -p litebox_runner_macos_on_macos_userland
```
