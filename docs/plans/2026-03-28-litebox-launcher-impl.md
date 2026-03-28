# litebox_launcher Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a host launcher binary that ties litebox_central and litebox_micro together — creates shared memory, forks central as a child process, loads a packaged guest ELF into the current process, initializes micro, and jumps to the guest entry point.

**Architecture:** The launcher is the initial process. It creates shared memory (memfd_create + mmap), forks a child that exec()s litebox_central, then continues as the guest process: initializes micro, loads the ELF using litebox_common_linux's trait-based loader with real libc implementations, patches the trampoline with micro_syscall_entry, sets up the user stack, and jumps to the entry point. The launcher depends on litebox_micro, litebox_ipc, and litebox_common_linux.

**Tech Stack:** Rust (edition 2024), libc, litebox_common_linux::loader traits (ReadAt, MapMemory, AccessMemory), litebox_micro, litebox_ipc

---

### Task 1: Crate skeleton

**Files:**
- Create: `litebox_launcher/Cargo.toml`
- Create: `litebox_launcher/src/main.rs`
- Modify: `Cargo.toml` (workspace root — add to `members` and `default-members`)

**Step 1: Create Cargo.toml**

```toml
[package]
name = "litebox_launcher"
version = "0.1.0"
edition = "2024"

[dependencies]
litebox_ipc = { path = "../litebox_ipc" }
litebox_micro = { path = "../litebox_micro" }
litebox_common_linux = { path = "../litebox_common_linux" }
libc = "0.2"
anyhow = "1"

[lints]
workspace = true
```

**Step 2: Create stub main.rs**

Minimal main function that prints "litebox_launcher: starting" and exits.

**Step 3: Add to workspace**

Add `"litebox_launcher"` to both `members` and `default-members` arrays in root `Cargo.toml`.

**Step 4: Verify**

Run: `cargo check -p litebox_launcher`
Expected: PASS

**Step 5: Commit**

---

### Task 2: Shared memory creation (shmem.rs)

**Files:**
- Create: `litebox_launcher/src/shmem.rs`
- Modify: `litebox_launcher/src/main.rs` (add mod declaration)

Implement shared memory region creation. This is the launcher's copy — creates the memfd, mmaps it, and can pass the fd to both central and micro.

The key difference from litebox_central's shmem.rs: the launcher needs to keep the fd inheritable (no CLOEXEC) so the forked central child can use it. Also, the launcher needs to return the raw fd number for passing to central and micro.

**Implementation:**

```rust
use litebox_ipc::ring::SharedRingLayout;
use std::os::fd::{FromRawFd, OwnedFd};

pub struct LauncherSharedRegion {
    fd: OwnedFd,
    ptr: *mut u8,
    layout: SharedRingLayout,
}
```

Methods:
- `new() -> anyhow::Result<Self>` — memfd_create (WITHOUT MFD_CLOEXEC so child inherits), ftruncate, mmap MAP_SHARED, zero-init header
- `fd_raw(&self) -> i32` — raw fd for passing to central/micro
- `base_ptr(&self) -> *mut u8`
- `layout(&self) -> &SharedRingLayout`
- Drop impl: munmap + fd auto-closed

**Test:** Create region, verify header is zeroed, verify fd is valid.

**Verify:** `cargo nextest run -p litebox_launcher`

---

### Task 3: Real-file ReadAt + MapMemory + AccessMemory implementations (loader.rs)

**Files:**
- Create: `litebox_launcher/src/loader.rs`
- Modify: `litebox_launcher/src/main.rs` (add mod declaration)

Implement the three loader traits from `litebox_common_linux::loader` backed by real libc calls. This is the core of ELF loading in the guest process.

**ReadAt impl:**

```rust
pub struct RealFile {
    fd: i32,
    size: u64,
}

impl RealFile {
    pub fn open(path: &str) -> Result<Self, i32> {
        let c_path = std::ffi::CString::new(path).map_err(|_| libc::EINVAL)?;
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if fd < 0 { return Err(unsafe { *libc::__errno_location() }); }
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut stat) } < 0 {
            let err = unsafe { *libc::__errno_location() };
            unsafe { libc::close(fd) };
            return Err(err);
        }
        Ok(Self { fd, size: stat.st_size as u64 })
    }
}

impl Drop for RealFile {
    fn drop(&mut self) { unsafe { libc::close(self.fd); } }
}
```

`ReadAt` for `&RealFile`: use `libc::pread` in a loop.

**MapMemory impl:**

```rust
pub struct RealMapper {
    fd: i32, // the ELF file fd for file-backed mappings
}
```

- `reserve(len, align)`: `mmap(NULL, len+align-PAGE_SIZE, PROT_NONE, MAP_ANONYMOUS|MAP_PRIVATE)`, trim edges with munmap, return aligned address
- `map_file(addr, len, offset, prot)`: `mmap(addr, len, prot_flags, MAP_PRIVATE|MAP_FIXED, fd, offset)`
- `map_zero(addr, len, prot)`: `mmap(addr, len, prot_flags, MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, -1, 0)`
- `protect(addr, len, prot)`: `mprotect(addr, len, prot_flags)`

**AccessMemory impl:**

```rust
pub struct RealMemory;
```

- `read(addr, buf)`: `std::ptr::copy_nonoverlapping(addr as *const u8, buf.as_mut_ptr(), buf.len())`
- `write(addr, data)`: `std::ptr::copy_nonoverlapping(data.as_ptr(), addr as *mut u8, data.len())`
- `zero(addr, len)`: `std::ptr::write_bytes(addr as *mut u8, 0, len)`

**Tests:**
- Test `RealFile::open` on `/proc/self/exe`
- Test `ReadAt::read_at` reads expected ELF magic
- Test `RealMapper::reserve` + `map_zero` creates accessible memory

**Verify:** `cargo nextest run -p litebox_launcher`

---

### Task 4: ELF loading orchestration (load_elf.rs)

**Files:**
- Create: `litebox_launcher/src/load_elf.rs`
- Modify: `litebox_launcher/src/main.rs` (add mod declaration)

Orchestrate the full ELF loading sequence: parse main binary, parse interpreter (if dynamic), load both, set up user stack with argv/envp/auxv.

```rust
pub struct LoadedElf {
    pub entry_point: usize,
    pub stack_pointer: usize,
}
```

The loading sequence:
1. Open main ELF file via `RealFile::open(path)`
2. Parse: `ElfParsedFile::parse(&mut &file)`
3. Parse trampoline: `parsed.parse_trampoline(&mut &file, syscall_entry_point)`
4. Check for interpreter: `parsed.interp(&mut &file)`
5. If interpreter exists: open/parse/parse_trampoline for it too
6. Load main: `parsed.load(&mut RealMapper{fd: file.fd}, &mut RealMemory)`
7. Load interpreter (if any): same
8. Allocate stack: `mmap(NULL, 8MB, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE|MAP_STACK|MAP_GROWSDOWN)`
9. Build auxv: AT_PAGESZ, AT_PHDR, AT_PHENT, AT_PHNUM, AT_ENTRY, AT_BASE (if interp), AT_UID/EUID/GID/EGID, AT_RANDOM, AT_CLKTCK
10. Init stack: write argc, argv pointers, envp pointers, auxv, string data (reimplement UserStack logic using raw pointers)
11. Return `LoadedElf { entry_point, stack_pointer }`

Note: The stack initialization requires reimplementing the `UserStack` logic from `litebox_shim_linux/src/loader/stack.rs` since that version uses `MutPtr<u8>` (platform-specific). The launcher version uses raw `*mut u8`.

**Test:** Load `/proc/self/exe` (or a test binary if available) and verify entry_point is non-zero.

**Verify:** `cargo nextest run -p litebox_launcher`

---

### Task 5: Central process management (central.rs)

**Files:**
- Create: `litebox_launcher/src/central.rs`
- Modify: `litebox_launcher/src/main.rs` (add mod declaration)

Fork a child process to run litebox_central. The child inherits the shared memory fd and execs the central binary.

```rust
pub struct CentralProcess {
    pid: i32,
}

impl CentralProcess {
    pub fn spawn(shmem_fd: i32) -> anyhow::Result<Self> {
        let pid = unsafe { libc::fork() };
        match pid {
            -1 => anyhow::bail!("fork failed: {}", std::io::Error::last_os_error()),
            0 => {
                // Child: exec litebox_central with the shmem fd as an argument
                // Convention: pass fd number as first CLI arg
                // For now, just exit since litebox_central doesn't accept fd args yet
                // TODO: modify litebox_central to accept --shmem-fd=N
                std::process::exit(0);
            }
            _ => Ok(CentralProcess { pid }),
        }
    }

    pub fn pid(&self) -> i32 { self.pid }
}
```

Note: litebox_central currently creates its own shared memory. For the launcher model, central needs to accept a shared memory fd from the launcher instead. This is a TODO — for the initial implementation, we'll have the launcher create shmem and central will be modified later to accept it. For now, Task 5 provides the fork/exec scaffolding.

**Test:** Spawn a child that immediately exits, verify pid > 0, waitpid succeeds.

**Verify:** `cargo nextest run -p litebox_launcher`

---

### Task 6: Guest entry (entry.rs) — jump to ELF entry point

**Files:**
- Create: `litebox_launcher/src/entry.rs`
- Modify: `litebox_launcher/src/main.rs` (add mod declaration)

Implement the assembly to jump to the loaded ELF's entry point with the correct register state. On x86_64, the kernel-to-user transition sets:
- RSP = user stack pointer (pointing to argc)
- RIP = entry point
- All other registers = 0
- Flags cleared

This is a `noreturn` function implemented in inline assembly.

```rust
/// Jump to the guest ELF entry point. Does not return.
///
/// # Safety
///
/// `entry_point` must be a valid executable address.
/// `stack_pointer` must be a valid, aligned stack pointer with
/// argc/argv/envp/auxv properly initialized.
pub unsafe fn jump_to_guest(entry_point: usize, stack_pointer: usize) -> ! {
    core::arch::asm!(
        "xor rax, rax",
        "xor rbx, rbx",
        "xor rcx, rcx",
        "xor rdx, rdx",
        "xor rsi, rsi",
        "xor rdi, rdi",
        "xor rbp, rbp",
        "xor r8, r8",
        "xor r9, r9",
        "xor r10, r10",
        "xor r11, r11",
        "xor r12, r12",
        "xor r13, r13",
        "xor r14, r14",
        "xor r15, r15",
        "mov rsp, {stack}",
        "jmp {entry}",
        stack = in(reg) stack_pointer,
        entry = in(reg) entry_point,
        options(noreturn),
    );
}
```

**Test:** Not easily testable in isolation (it's noreturn). Verified by integration test in Phase C.

---

### Task 7: Main function — full launch sequence

**Files:**
- Modify: `litebox_launcher/src/main.rs`

Wire everything together:

```
fn main():
    1. Parse CLI args: launcher <tar-or-elf-path> [args...]
    2. Create shared memory region
    3. Spawn central process (passing shmem fd)
    4. Initialize micro: micro_init(fd, base, size, pid=1, ppid=0)
    5. Initialize main thread TLS: micro_init_thread(0)
    6. Load ELF (with micro_syscall_entry as trampoline entry)
    7. Jump to guest entry point (noreturn)
```

Note: For the initial implementation, central spawn is a TODO (it doesn't yet accept external shmem). The launcher will still set up micro and load the ELF correctly.

**Verify:** `cargo check -p litebox_launcher && cargo clippy -p litebox_launcher -- -D warnings`

---

### Task 8: Workspace validation + ratchet

**Files:**
- Modify: `dev_tests/src/ratchet.rs` — add litebox_launcher entry if any static muts

**Verify:**
- `cargo check` (full workspace)
- `cargo clippy -p litebox_launcher -- -D warnings`
- `cargo nextest run -p litebox_launcher -p litebox_micro -p litebox_ipc -p dev_tests`

**Commit** the complete launcher crate.

---

## Notes

- The launcher does NOT use litebox_shim_linux or any platform crate — it loads ELFs directly using litebox_common_linux's loader traits with real libc.
- Guest memory access is direct (raw pointers) since the launcher IS the guest process.
- Central will need to be modified to accept an external shmem fd (deferred to integration phase).
- The `UserStack` logic is reimplemented in the launcher because the shim's version depends on `MutPtr<u8>` (platform-abstracted). The launcher's version uses `*mut u8` directly.
- The launcher currently loads from raw ELF paths. Loading from litebox_packager tarballs is deferred.
