# litebox_central Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build `litebox_platform_central` and `litebox_central` — a new platform implementation and server binary that hosts the full LiteBox shim and serves syscalls from guest processes over the `litebox_ipc` shared-memory ring buffer.

**Architecture:** The existing shim (`litebox_shim_linux`) is platform-agnostic via the `litebox_platform_multiplex` type-alias pattern. We add a new platform (`CentralPlatform`) that implements the `Provider` trait using standard host OS primitives (no seccomp, no fs/gs swapping, no ptrace). Then `litebox_central` is a binary that: (1) creates shared memory + ring buffers, (2) initializes the shim with `CentralPlatform`, (3) runs a server loop consuming `SqEntry`s, converting them to `SyscallRequest`s, dispatching through the existing shim handlers, and writing `CqEntry` results. Central does NOT run guest code — it only processes syscall requests on behalf of guest processes running in separate address spaces.

**Tech Stack:** Rust (edition 2024), `std` (both crates need host OS access), depends on `litebox`, `litebox_ipc`, `litebox_shim_linux`, `litebox_common_linux`, `litebox_platform_multiplex`. Uses Linux `memfd_create` for shared memory, futex for cross-process synchronization.

**Design docs:**
- `docs/plans/2026-03-27-micro-litebox-00-overview.md` — Architecture
- `docs/plans/2026-03-27-micro-litebox-07-central-refactoring.md` — Central refactoring plan
- `docs/plans/2026-03-27-micro-litebox-03-fork-flow.md` — Fork flow

**Key discovery:** The shim uses `litebox_platform_multiplex::Platform` as a concrete type alias (not a generic parameter) — switched at compile time via Cargo features. Adding `CentralPlatform` follows the exact same pattern as the 4 existing platforms. This means the entire shim (all ~94 syscall handlers, state management, ELF loader) works with zero code changes once the platform is wired up.

**Critical constraint:** `RawPointerProvider` is the most challenging trait to implement. The existing platforms use raw pointers (`*const T` / `*mut T`) because the guest runs in the same address space. In central's model, the guest runs in a **separate process** — central cannot dereference guest pointers. This requires either: (a) mapping the guest's memory into central's address space, or (b) implementing `RawConstPointer`/`RawMutPointer` to read/write guest memory via `/proc/<pid>/mem` or shared memory. For Phase 3 (this plan), we start with a **stub approach** that panics on pointer dereference, since the initial focus is the server loop for non-pointer syscalls (getpid, close, dup, etc.) and the infrastructure for dispatching `SqEntry → SyscallRequest → handler`. The pointer implementation is deferred.

---

### Task 1: Create `litebox_platform_central` crate skeleton

**Files:**
- Create: `litebox_platform_central/Cargo.toml`
- Create: `litebox_platform_central/src/lib.rs`
- Modify: `Cargo.toml` (workspace root — add to `members` and `default-members`)

**Step 1: Create the crate directory**

```bash
mkdir -p litebox_platform_central/src
```

**Step 2: Create `litebox_platform_central/Cargo.toml`**

```toml
[package]
name = "litebox_platform_central"
version = "0.1.0"
edition = "2024"

[dependencies]
litebox = { path = "../litebox/", version = "0.1.0" }
zerocopy = { version = "0.8", default-features = false, features = ["derive"] }

[lints]
workspace = true
```

**Step 3: Create `litebox_platform_central/src/lib.rs`**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Platform implementation for central LiteBox — the host process that
//! serves syscalls on behalf of guest processes via shared-memory IPC.
//!
//! Unlike `LinuxUserland`, this platform does NOT run guest code. It does
//! not install signal handlers, swap segment registers, or intercept
//! syscalls. Instead, it provides the trait implementations needed by the
//! shim to process syscall requests that arrive over the ring buffer.

extern crate alloc;

pub struct CentralPlatform;
```

**Step 4: Add to workspace**

In root `Cargo.toml`, add `"litebox_platform_central"` to both `members` and `default-members`.

**Step 5: Verify**

```bash
cargo check -p litebox_platform_central
```

Expected: success.

**Step 6: Commit**

```bash
git add litebox_platform_central/ Cargo.toml Cargo.lock
git commit -m "feat(central): add litebox_platform_central crate skeleton"
```

---

### Task 2: Implement `DebugLogProvider` and `IPInterfaceProvider`

These are the two simplest `Provider` subtraits. They establish the pattern.

**Files:**
- Modify: `litebox_platform_central/src/lib.rs`

**Step 1: Implement the traits**

```rust
use litebox::platform::{DebugLogProvider, IPInterfaceProvider, SendError, ReceiveError};

impl DebugLogProvider for CentralPlatform {
    fn debug_log_print(&self, msg: &str) {
        eprint!("{msg}");
    }
}

impl IPInterfaceProvider for CentralPlatform {
    fn send_ip_packet(&self, _packet: &[u8]) -> Result<(), SendError> {
        // Central does not handle raw IP packets. Networking is handled
        // through the host kernel's socket API, not a TUN device.
        Err(SendError::Disconnected)
    }

    fn receive_ip_packet(&self, _packet: &mut [u8]) -> Result<usize, ReceiveError> {
        Err(ReceiveError::Disconnected)
    }
}
```

**Step 2: Verify**

```bash
cargo check -p litebox_platform_central
```

**Step 3: Commit**

```bash
git add litebox_platform_central/
git commit -m "feat(central): implement DebugLogProvider and IPInterfaceProvider"
```

---

### Task 3: Implement `TimeProvider`

**Files:**
- Modify: `litebox_platform_central/src/lib.rs`

**Step 1: Define time types and implement traits**

```rust
use litebox::platform::{TimeProvider, Instant as InstantTrait, SystemTime as SystemTimeTrait};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CentralInstant(std::time::Instant);

impl InstantTrait for CentralInstant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<core::time::Duration> {
        self.0.checked_duration_since(earlier.0)
    }

    fn checked_add(&self, duration: core::time::Duration) -> Option<Self> {
        self.0.checked_add(duration).map(CentralInstant)
    }
}

pub struct CentralSystemTime(std::time::SystemTime);

impl SystemTimeTrait for CentralSystemTime {
    const UNIX_EPOCH: Self = CentralSystemTime(std::time::SystemTime::UNIX_EPOCH);

    fn duration_since(&self, earlier: &Self) -> Result<core::time::Duration, core::time::Duration> {
        match self.0.duration_since(earlier.0) {
            Ok(d) => Ok(d),
            Err(e) => Err(e.duration()),
        }
    }
}

// Safety: std::time::SystemTime is Send + Sync
unsafe impl Send for CentralSystemTime {}
unsafe impl Sync for CentralSystemTime {}

impl TimeProvider for CentralPlatform {
    type Instant = CentralInstant;
    type SystemTime = CentralSystemTime;

    fn now(&self) -> Self::Instant {
        CentralInstant(std::time::Instant::now())
    }

    fn current_time(&self) -> Self::SystemTime {
        CentralSystemTime(std::time::SystemTime::now())
    }
}
```

**Step 2: Verify**

```bash
cargo check -p litebox_platform_central
```

**Step 3: Commit**

```bash
git add litebox_platform_central/
git commit -m "feat(central): implement TimeProvider using std::time"
```

---

### Task 4: Implement `RawMutexProvider`

This is critical — the shim's `Mutex<Platform, T>` and `RwLock<Platform, T>` depend on it. We implement `RawMutex` using Linux futex syscalls for cross-process compatibility.

**Files:**
- Modify: `litebox_platform_central/src/lib.rs`

**Step 1: Implement `CentralRawMutex` using futex**

```rust
use core::sync::atomic::{AtomicU32, Ordering};
use litebox::platform::{
    RawMutexProvider, RawMutex as RawMutexTrait,
    ImmediatelyWokenUp, UnblockedOrTimedOut,
};

pub struct CentralRawMutex {
    futex: AtomicU32,
}

impl CentralRawMutex {
    fn futex_wait(&self, val: u32, timeout: Option<core::time::Duration>) -> i64 {
        let timespec = timeout.map(|d| libc::timespec {
            tv_sec: d.as_secs() as libc::time_t,
            tv_nsec: d.subsec_nanos() as libc::c_long,
        });
        let ts_ptr = match &timespec {
            Some(ts) => ts as *const libc::timespec,
            None => core::ptr::null(),
        };
        // Safety: valid atomic, standard futex usage
        unsafe {
            libc::syscall(
                libc::SYS_futex,
                self.futex.as_ptr(),
                libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
                val,
                ts_ptr,
            ) as i64
        }
    }

    fn futex_wake(&self, n: i32) -> i64 {
        // Safety: valid atomic, standard futex usage
        unsafe {
            libc::syscall(
                libc::SYS_futex,
                self.futex.as_ptr(),
                libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
                n,
            ) as i64
        }
    }
}

// Safety: AtomicU32 is Send + Sync
unsafe impl Send for CentralRawMutex {}
unsafe impl Sync for CentralRawMutex {}

impl RawMutexTrait for CentralRawMutex {
    const INIT: Self = CentralRawMutex { futex: AtomicU32::new(0) };

    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.futex
    }

    fn wake_many(&self, n: usize) -> usize {
        let n = n.min(i32::MAX as usize) as i32;
        let woken = self.futex_wake(n);
        woken.max(0) as usize
    }

    fn block(&self, val: u32) -> Result<(), ImmediatelyWokenUp> {
        let current = self.futex.load(Ordering::Acquire);
        if current != val {
            return Err(ImmediatelyWokenUp);
        }
        let _ = self.futex_wait(val, None);
        // Re-check: futex_wait can return spuriously
        Ok(())
    }

    fn block_or_timeout(
        &self,
        val: u32,
        time: core::time::Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        let current = self.futex.load(Ordering::Acquire);
        if current != val {
            return Err(ImmediatelyWokenUp);
        }
        let ret = self.futex_wait(val, Some(time));
        if ret == -(libc::ETIMEDOUT as i64) {
            Ok(UnblockedOrTimedOut::TimedOut)
        } else {
            Ok(UnblockedOrTimedOut::Unblocked)
        }
    }
}

impl RawMutexProvider for CentralPlatform {
    type RawMutex = CentralRawMutex;
}
```

**Step 2: Add `libc` dependency**

In `litebox_platform_central/Cargo.toml`, add:
```toml
libc = "0.2"
```

**Step 3: Verify**

```bash
cargo check -p litebox_platform_central
```

**Step 4: Commit**

```bash
git add litebox_platform_central/
git commit -m "feat(central): implement RawMutexProvider using futex"
```

---

### Task 5: Implement `RawPointerProvider` (stub)

Guest memory access from central is architecturally complex (guest runs in a different process). For now, we implement stub pointer types that track addresses but panic on dereference. This is sufficient for syscalls that don't need to read/write guest memory (getpid, close, dup, etc.) and lets us wire up the full dispatch pipeline. Real guest memory access is a later task.

**Files:**
- Modify: `litebox_platform_central/src/lib.rs`

**Step 1: Define stub pointer types**

```rust
use litebox::platform::{RawPointerProvider, RawConstPointer, RawMutPointer};
use zerocopy::{FromBytes, IntoBytes, Immutable, KnownLayout};

/// A pointer to guest memory. Stores the guest virtual address but cannot
/// dereference it (guest is in a separate process). Operations that need
/// the address value (as_usize, from_usize) work. Dereference operations
/// (read_at_offset, write_at_offset, etc.) panic with a clear message.
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(transparent)]
pub struct GuestConstPtr<T: FromBytes> {
    addr: usize,
    _marker: core::marker::PhantomData<*const T>,
}

#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(transparent)]
pub struct GuestMutPtr<T: FromBytes + IntoBytes> {
    addr: usize,
    _marker: core::marker::PhantomData<*mut T>,
}

impl<T: FromBytes> RawConstPointer<T> for GuestConstPtr<T> {
    fn as_usize(&self) -> usize {
        self.addr
    }

    fn from_usize(addr: usize) -> Self {
        Self { addr, _marker: core::marker::PhantomData }
    }

    fn read_at_offset(self, _count: isize) -> Option<T> {
        unimplemented!(
            "CentralPlatform: cannot dereference guest pointer {:#x} from central process",
            self.addr
        );
    }

    fn to_owned_slice(self, _len: usize) -> Option<alloc::boxed::Box<[T]>> {
        unimplemented!(
            "CentralPlatform: cannot read guest memory slice at {:#x} from central process",
            self.addr
        );
    }
}

impl<T: FromBytes + IntoBytes> RawConstPointer<T> for GuestMutPtr<T> {
    fn as_usize(&self) -> usize {
        self.addr
    }

    fn from_usize(addr: usize) -> Self {
        Self { addr, _marker: core::marker::PhantomData }
    }

    fn read_at_offset(self, _count: isize) -> Option<T> {
        unimplemented!(
            "CentralPlatform: cannot dereference guest pointer {:#x} from central process",
            self.addr
        );
    }

    fn to_owned_slice(self, _len: usize) -> Option<alloc::boxed::Box<[T]>> {
        unimplemented!(
            "CentralPlatform: cannot read guest memory slice at {:#x} from central process",
            self.addr
        );
    }
}

impl<T: FromBytes + IntoBytes> RawMutPointer<T> for GuestMutPtr<T> {
    fn write_at_offset(self, _count: isize, _value: T) -> Option<()> {
        unimplemented!(
            "CentralPlatform: cannot write guest memory at {:#x} from central process",
            self.addr
        );
    }

    fn mutate_subslice_with<R>(
        self,
        _range: impl core::ops::RangeBounds<isize>,
        _f: impl FnOnce(&mut [T]) -> R,
    ) -> Option<R> {
        unimplemented!(
            "CentralPlatform: cannot mutate guest memory at {:#x} from central process",
            self.addr
        );
    }
}

impl RawPointerProvider for CentralPlatform {
    type RawConstPointer<T: FromBytes> = GuestConstPtr<T>;
    type RawMutPointer<T: FromBytes + IntoBytes> = GuestMutPtr<T>;
}
```

Note: The `PhantomData` field in `GuestConstPtr`/`GuestMutPtr` may need to be excluded from `FromBytes`/`IntoBytes` derives. If zerocopy does not support `PhantomData`, use `#[repr(transparent)]` with just the `addr: usize` field and carry the phantom data differently (e.g., via a separate type parameter on the methods). Adjust based on what compiles.

**Step 2: Verify**

```bash
cargo check -p litebox_platform_central
```

Fix any zerocopy derive issues. The key requirement is that `GuestConstPtr<T>` must implement `FromBytes + IntoBytes + Copy + Debug`.

**Step 3: Commit**

```bash
git add litebox_platform_central/
git commit -m "feat(central): implement RawPointerProvider with stub guest pointers"
```

---

### Task 6: Implement `PunchthroughProvider` and complete `Provider`

**Files:**
- Modify: `litebox_platform_central/src/lib.rs`

**Step 1: Implement PunchthroughProvider**

Central does not support punchthroughs (those are platform-local operations like `arch_prctl(SET_FS)` that only make sense in-process). All punchthrough requests return `None`.

```rust
use litebox::platform::{
    PunchthroughProvider, PunchthroughToken, Punchthrough, PunchthroughError,
};

/// A punchthrough type that is never constructed (central rejects all punchthroughs).
pub enum CentralPunchthrough {}

impl Punchthrough for CentralPunchthrough {
    type ReturnSuccess = core::convert::Infallible;
    type ReturnFailure = core::convert::Infallible;
}

/// A token that is never constructed.
pub enum CentralPunchthroughToken {}

impl PunchthroughToken for CentralPunchthroughToken {
    type Punchthrough = CentralPunchthrough;

    fn execute(self) -> Result<
        core::convert::Infallible,
        PunchthroughError<core::convert::Infallible>,
    > {
        match self {} // unreachable — enum has no variants
    }
}

impl PunchthroughProvider for CentralPlatform {
    type PunchthroughToken<'a> = CentralPunchthroughToken;

    fn get_punchthrough_token_for(
        &self,
        _punchthrough: CentralPunchthrough,
    ) -> Option<CentralPunchthroughToken> {
        match _punchthrough {} // unreachable — enum has no variants
    }
}
```

Note: The `PunchthroughProvider` trait uses a GAT `PunchthroughToken<'a>` where the `Punchthrough` associated type on the token determines the argument type of `get_punchthrough_token_for`. The exact types need to match the trait bounds. If `Infallible` causes issues with the `Error` bound on `ReturnFailure`, use a custom empty error type instead. Adjust based on what compiles.

**Step 2: Implement the Provider blanket**

```rust
impl litebox::platform::Provider for CentralPlatform {}
```

**Step 3: Verify**

```bash
cargo check -p litebox_platform_central
```

This is the first time the full `Provider` bound is checked. Fix any missing trait implementations.

**Step 4: Commit**

```bash
git add litebox_platform_central/
git commit -m "feat(central): implement PunchthroughProvider and complete Provider trait"
```

---

### Task 7: Wire `CentralPlatform` into `litebox_platform_multiplex`

This task adds the feature flag that makes the entire shim work with `CentralPlatform`.

**Files:**
- Modify: `litebox_platform_multiplex/Cargo.toml` (add optional dep + feature)
- Modify: `litebox_platform_multiplex/src/lib.rs` (add cfg_if branch)
- Modify: `litebox_shim_linux/Cargo.toml` (add feature passthrough)

**Step 1: Add to multiplex Cargo.toml**

In `litebox_platform_multiplex/Cargo.toml`, add to `[dependencies]`:
```toml
litebox_platform_central = { path = "../litebox_platform_central/", version = "0.1.0", default-features = false, optional = true }
```

Add to `[features]`:
```toml
platform_central = ["dep:litebox_platform_central"]
```

**Step 2: Add cfg_if branch**

In `litebox_platform_multiplex/src/lib.rs`, add a new branch to the `cfg_if!` block BEFORE the `compile_error!` fallback:

```rust
} else if #[cfg(feature = "platform_central")] {
    pub type Platform = litebox_platform_central::CentralPlatform;
```

**Step 3: Add feature to shim**

In `litebox_shim_linux/Cargo.toml`, add to `[features]`:
```toml
platform_central = ["litebox_platform_multiplex/platform_central"]
```

**Step 4: Verify the shim compiles with the new platform**

```bash
cargo check -p litebox_shim_linux --no-default-features --features platform_central
```

This is the critical moment — the entire shim (all ~94 syscall handlers) must type-check with `CentralPlatform`. Expect compilation errors from:
- Traits that the shim uses beyond `Provider` (e.g., `ThreadProvider`, `StdioProvider`, `PageManagementProvider`) — these need stub implementations added to `CentralPlatform` in a follow-up step.

Note any missing trait implementations. If there are errors, **do not fix them in this task**. Just record them. Task 8 handles the additional trait implementations.

**Step 5: Commit**

```bash
git add litebox_platform_multiplex/ litebox_shim_linux/Cargo.toml
git commit -m "feat(central): wire CentralPlatform into platform multiplex"
```

---

### Task 8: Implement additional traits required by the shim

The shim requires traits beyond `Provider`: `ThreadProvider`, `StdioProvider`, `PageManagementProvider`, and `SystemInfoProvider`. These are discovered from compilation errors in Task 7.

**Files:**
- Modify: `litebox_platform_central/src/lib.rs`

**Step 1: Implement `ThreadProvider` (stub)**

Central does not spawn guest threads. Thread creation requests (`clone` with `CLONE_VM|CLONE_THREAD`) will be handled via IPC messages from micro-LiteBox, not by actually spawning threads. For now, stub it.

```rust
use litebox::platform::ThreadProvider;

impl ThreadProvider for CentralPlatform {
    type ExecutionContext = (); // Central never executes guest code
    type ThreadSpawnError = std::io::Error;
    type ThreadHandle = ();

    unsafe fn spawn_thread(
        &self,
        _ctx: &Self::ExecutionContext,
        _init_thread: alloc::boxed::Box<
            dyn litebox::shim::InitThread<ExecutionContext = Self::ExecutionContext>,
        >,
    ) -> Result<(), Self::ThreadSpawnError> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "CentralPlatform does not spawn guest threads",
        ))
    }

    fn current_thread(&self) -> Self::ThreadHandle {}

    fn interrupt_thread(&self, _thread: &Self::ThreadHandle) {}
}
```

**Step 2: Implement `StdioProvider` (stub)**

```rust
use litebox::platform::{StdioProvider, StdioStream, StdioOutStream, StdioReadError, StdioWriteError};

impl StdioProvider for CentralPlatform {
    fn read_from_stdin(&self, _buf: &mut [u8]) -> Result<usize, StdioReadError> {
        // Guest stdin will be routed via ring buffer, not process stdio
        Err(StdioReadError::Eof)
    }

    fn write_to(&self, _stream: StdioOutStream, buf: &[u8]) -> Result<usize, StdioWriteError> {
        // For now, forward to central's stderr for debugging
        use std::io::Write;
        std::io::stderr().write_all(buf).map_err(|_| StdioWriteError::BrokenPipe)?;
        Ok(buf.len())
    }

    fn is_a_tty(&self, _stream: StdioStream) -> bool {
        false
    }
}
```

**Step 3: Implement `PageManagementProvider` (stub)**

Central does not manage guest pages — those are managed by micro-LiteBox locally. However, the shim's `mmap`/`munmap` handlers need this trait to compile.

```rust
use litebox::platform::page_mgmt::{
    PageManagementProvider, MemoryRegionPermissions, FixedAddressBehavior,
    AllocationError, DeallocationError, RemapError, PermissionUpdateError,
};
use core::ops::Range;

// PAGE_SIZE used by the shim is 4096
impl PageManagementProvider<4096> for CentralPlatform {
    const TASK_ADDR_MIN: usize = 0x1_0000;
    const TASK_ADDR_MAX: usize = 0x7FFF_FFFF_F000;

    fn allocate_pages(
        &self,
        _suggested_range: Range<usize>,
        _initial_permissions: MemoryRegionPermissions,
        _can_grow_down: bool,
        _populate_pages_immediately: bool,
        _fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, AllocationError> {
        // Memory allocation happens in guest's address space via micro-LiteBox
        Err(AllocationError::OutOfAddressSpace)
    }

    unsafe fn deallocate_pages(&self, _range: Range<usize>) -> Result<(), DeallocationError> {
        Err(DeallocationError::InvalidRange)
    }

    unsafe fn update_permissions(
        &self,
        _range: Range<usize>,
        _new_permissions: MemoryRegionPermissions,
    ) -> Result<(), PermissionUpdateError> {
        Err(PermissionUpdateError::InvalidRange)
    }

    fn reserved_pages(&self) -> impl Iterator<Item = &Range<usize>> {
        core::iter::empty()
    }
}
```

**Step 4: Implement any other missing traits**

Check compilation output and implement stubs for any other traits the shim requires. Likely candidates: `SystemInfoProvider`, `CrngProvider`, `TimerProvider`, `SignalProvider`. For each one, provide a minimal stub implementation.

**Step 5: Verify the shim compiles**

```bash
cargo check -p litebox_shim_linux --no-default-features --features platform_central
```

Keep iterating until this passes. Every new trait implementation goes into `litebox_platform_central/src/lib.rs`.

**Step 6: Run clippy**

```bash
cargo clippy -p litebox_platform_central -- -D warnings
```

**Step 7: Commit**

```bash
git add litebox_platform_central/
git commit -m "feat(central): implement ThreadProvider, StdioProvider, PageManagementProvider stubs"
```

---

### Task 9: Create `litebox_central` binary crate skeleton

**Files:**
- Create: `litebox_central/Cargo.toml`
- Create: `litebox_central/src/main.rs`
- Modify: `Cargo.toml` (workspace root)

**Step 1: Create the crate directory**

```bash
mkdir -p litebox_central/src
```

**Step 2: Create `litebox_central/Cargo.toml`**

```toml
[package]
name = "litebox_central"
version = "0.1.0"
edition = "2024"

[dependencies]
litebox = { path = "../litebox/", version = "0.1.0" }
litebox_ipc = { path = "../litebox_ipc/", version = "0.1.0" }
litebox_shim_linux = { path = "../litebox_shim_linux/", version = "0.1.0", default-features = false, features = ["platform_central"] }
litebox_common_linux = { path = "../litebox_common_linux/", version = "0.1.0" }
litebox_platform_multiplex = { path = "../litebox_platform_multiplex/", version = "0.1.0", default-features = false, features = ["platform_central"] }
litebox_platform_central = { path = "../litebox_platform_central/", version = "0.1.0" }
libc = "0.2"
anyhow = "1"

[lints]
workspace = true
```

**Step 3: Create `litebox_central/src/main.rs`**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Central LiteBox — host process serving syscalls for guest processes
//! via shared-memory ring buffer IPC.

fn main() -> anyhow::Result<()> {
    eprintln!("litebox_central: starting");
    Ok(())
}
```

**Step 4: Add to workspace**

In root `Cargo.toml`, add `"litebox_central"` to both `members` and `default-members`.

**Step 5: Verify**

```bash
cargo check -p litebox_central
cargo build -p litebox_central
```

**Step 6: Commit**

```bash
git add litebox_central/ Cargo.toml Cargo.lock
git commit -m "feat(central): add litebox_central binary crate skeleton"
```

---

### Task 10: Implement shared memory setup

Central creates the shared memory region and maps it. This is the foundation for ring buffer IPC.

**Files:**
- Create: `litebox_central/src/shmem.rs`
- Modify: `litebox_central/src/main.rs`

**Step 1: Create `litebox_central/src/shmem.rs`**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared memory region management for ring buffer IPC.

use std::os::fd::{FromRawFd, OwnedFd};
use litebox_ipc::ring::SharedRingLayout;

/// A shared memory region backing a ring buffer pair.
pub struct SharedRegion {
    /// The file descriptor for the shared memory (memfd).
    pub fd: OwnedFd,
    /// The mapped memory region.
    pub ptr: *mut u8,
    /// The layout of the region.
    pub layout: SharedRingLayout,
}

impl SharedRegion {
    /// Create a new shared memory region with the default layout.
    pub fn new() -> anyhow::Result<Self> {
        Self::with_layout(SharedRingLayout::default_layout())
    }

    /// Create a new shared memory region with a custom layout.
    pub fn with_layout(layout: SharedRingLayout) -> anyhow::Result<Self> {
        // Create anonymous shared memory via memfd_create
        let name = c"litebox_ring";
        let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
        if fd < 0 {
            return Err(anyhow::anyhow!(
                "memfd_create failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };

        // Set the size
        use std::os::fd::AsRawFd;
        let ret = unsafe { libc::ftruncate(fd.as_raw_fd(), layout.total_size as libc::off_t) };
        if ret < 0 {
            return Err(anyhow::anyhow!(
                "ftruncate failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Map the region
        let ptr = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                layout.total_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(anyhow::anyhow!(
                "mmap failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Zero-initialize the region
        unsafe {
            core::ptr::write_bytes(ptr as *mut u8, 0, layout.total_size);
        }

        Ok(Self {
            fd,
            ptr: ptr as *mut u8,
            layout,
        })
    }

    /// Get a reference to the ring header at the start of the region.
    ///
    /// # Safety
    ///
    /// The caller must ensure no mutable aliasing of the header.
    pub unsafe fn header(&self) -> &litebox_ipc::ring::RingHeader {
        &*(self.ptr as *const litebox_ipc::ring::RingHeader)
    }

    /// Get a pointer to the SQ entries array.
    pub fn sq_entries(&self) -> *mut litebox_ipc::ring::SqEntry {
        unsafe { self.ptr.add(self.layout.sq_entries_offset) as *mut litebox_ipc::ring::SqEntry }
    }

    /// Get a pointer to the CQ entries array.
    pub fn cq_entries(&self) -> *mut litebox_ipc::ring::CqEntry {
        unsafe { self.ptr.add(self.layout.cq_entries_offset) as *mut litebox_ipc::ring::CqEntry }
    }

    /// Get a pointer to the data region.
    pub fn data_region(&self) -> *mut u8 {
        unsafe { self.ptr.add(self.layout.data_region_offset) }
    }
}

impl Drop for SharedRegion {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.layout.total_size);
        }
    }
}

// Safety: SharedRegion's mmap pointer is process-local but the underlying
// fd-backed memory is safe to access from multiple threads (with proper
// synchronization via the ring protocol).
unsafe impl Send for SharedRegion {}
```

**Step 2: Add module to main.rs**

```rust
mod shmem;
```

**Step 3: Verify**

```bash
cargo check -p litebox_central
```

**Step 4: Write a test**

Add to `shmem.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_shared_region() {
        let region = SharedRegion::new().expect("failed to create shared region");
        assert!(!region.ptr.is_null());
        assert!(region.layout.total_size > 0);
    }

    #[test]
    fn shared_region_header_is_zeroed() {
        let region = SharedRegion::new().expect("failed to create shared region");
        let header = unsafe { region.header() };
        use core::sync::atomic::Ordering;
        assert_eq!(header.sq_head.load(Ordering::Relaxed), 0);
        assert_eq!(header.sq_tail.load(Ordering::Relaxed), 0);
        assert_eq!(header.cq_head.load(Ordering::Relaxed), 0);
        assert_eq!(header.cq_tail.load(Ordering::Relaxed), 0);
    }
}
```

**Step 5: Run tests**

```bash
cargo nextest run -p litebox_central
```

**Step 6: Commit**

```bash
git add litebox_central/
git commit -m "feat(central): implement shared memory region setup"
```

---

### Task 11: Implement `SqEntry` → `SyscallRequest` conversion

This is the bridge between the ring buffer IPC and the existing shim dispatch. We build a function that constructs a synthetic `PtRegs` from `SqEntry.args[]` and calls `SyscallRequest::try_from_raw()`.

**Files:**
- Create: `litebox_central/src/dispatch.rs`
- Modify: `litebox_central/src/main.rs`

**Step 1: Create `litebox_central/src/dispatch.rs`**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Syscall dispatch: converts SqEntry from the ring buffer into
//! SyscallRequest and dispatches through the existing shim handlers.

use litebox_common_linux::{PtRegs, SyscallRequest};
use litebox_ipc::ring::SqEntry;
use litebox_platform_multiplex::Platform;

/// Build a synthetic `PtRegs` from an `SqEntry`'s arguments.
///
/// Maps `args[0..6]` to the Linux x86_64 syscall register convention:
/// `rdi, rsi, rdx, r10, r8, r9`. Sets `orig_rax` to the syscall number.
fn sq_entry_to_ptregs(entry: &SqEntry) -> PtRegs {
    let mut regs = PtRegs::default();

    // Set the syscall number (used by try_from_raw)
    #[cfg(target_arch = "x86_64")]
    {
        regs.orig_rax = entry.syscall_nr as usize;
        regs.rdi = entry.args[0] as usize;
        regs.rsi = entry.args[1] as usize;
        regs.rdx = entry.args[2] as usize;
        regs.r10 = entry.args[3] as usize;
        regs.r8 = entry.args[4] as usize;
        regs.r9 = entry.args[5] as usize;
    }

    #[cfg(target_arch = "x86")]
    {
        regs.orig_eax = entry.syscall_nr as usize;
        regs.ebx = entry.args[0] as usize;
        regs.ecx = entry.args[1] as usize;
        regs.edx = entry.args[2] as usize;
        regs.esi = entry.args[3] as usize;
        regs.edi = entry.args[4] as usize;
        regs.ebp = entry.args[5] as usize;
    }

    regs
}

/// Convert an SqEntry to a typed SyscallRequest.
///
/// Returns `Err(errno)` for unsupported or unrecognized syscall numbers.
pub fn parse_sq_entry(entry: &SqEntry) -> Result<SyscallRequest<Platform>, litebox_common_linux::errno::Errno> {
    let regs = sq_entry_to_ptregs(entry);
    SyscallRequest::<Platform>::try_from_raw(
        entry.syscall_nr as usize,
        &regs,
        |args| eprintln!("unsupported syscall: {args}"),
    )
}
```

Note: The exact field names on `PtRegs` may differ. Check `litebox_common_linux/src/lib.rs` for the `PtRegs` struct definition and adjust field names accordingly. The key is that `syscall_arg(0)` maps to `rdi` on x86_64, `syscall_arg(1)` to `rsi`, etc.

**Step 2: Add module to main.rs**

```rust
mod dispatch;
```

**Step 3: Verify**

```bash
cargo check -p litebox_central
```

**Step 4: Write a test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use litebox_ipc::ring::SqEntry;
    use core::sync::atomic::AtomicU8;

    fn make_sq_entry(syscall_nr: u32, args: [u64; 6]) -> SqEntry {
        // Safety: zero-init is valid for SqEntry
        let mut entry: SqEntry = unsafe { core::mem::zeroed() };
        entry.syscall_nr = syscall_nr;
        entry.args = args;
        entry
    }

    #[test]
    fn parse_getpid() {
        // SYS_getpid = 39 on x86_64
        let entry = make_sq_entry(39, [0; 6]);
        let result = parse_sq_entry(&entry);
        assert!(result.is_ok(), "getpid should parse: {result:?}");
    }

    #[test]
    fn parse_unknown_syscall() {
        let entry = make_sq_entry(0xFFFF, [0; 6]);
        let result = parse_sq_entry(&entry);
        assert!(result.is_err(), "unknown syscall should fail");
    }
}
```

**Step 5: Run tests**

```bash
cargo nextest run -p litebox_central
```

**Step 6: Commit**

```bash
git add litebox_central/
git commit -m "feat(central): implement SqEntry to SyscallRequest conversion"
```

---

### Task 12: Implement the server loop (single-process)

This is the core of central LiteBox. A worker thread spins on the SQ, parses entries, dispatches them through the shim, and writes CQ results.

**Files:**
- Create: `litebox_central/src/server.rs`
- Modify: `litebox_central/src/main.rs`

**Step 1: Create `litebox_central/src/server.rs`**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Server loop: consumes SqEntry from the ring buffer, dispatches through
//! the shim's syscall handlers, and writes CqEntry results back.

use litebox_ipc::ring::{CqEntry, RingHeader, SqEntry, RING_MASK};
use litebox_ipc::{cq, sq};
use litebox_ipc::messages;

use crate::shmem::SharedRegion;

/// Per-process server context.
pub struct ProcessServer {
    region: SharedRegion,
    // The shim and Task will be added when we integrate with the shim.
    // For now, this is a framework for the server loop.
}

impl ProcessServer {
    pub fn new(region: SharedRegion) -> Self {
        Self { region }
    }

    /// Run the server loop. This blocks the current thread.
    pub fn run(&self) -> anyhow::Result<()> {
        loop {
            let header = unsafe { self.region.header() };
            let head_val = sq::sq_head_index(header);
            let slot = (head_val & RING_MASK as u64) as usize;
            let sq_entries = self.region.sq_entries();

            // Get the entry at the current head position
            let entry = unsafe { &*sq_entries.add(slot) };

            // Wait for the entry to be ready
            if !sq::sq_try_consume(entry) {
                // Use adaptive wait: spin briefly, then futex-wait on sq_notify
                litebox_ipc::wait::spin_then_wait(
                    &header.sq_notify,
                    header.sq_notify.load(core::sync::atomic::Ordering::Relaxed),
                    |addr, expected| {
                        // Futex wait
                        unsafe {
                            libc::syscall(
                                libc::SYS_futex,
                                addr as *const core::sync::atomic::AtomicU32,
                                libc::FUTEX_WAIT,
                                expected,
                                core::ptr::null::<libc::timespec>(),
                            );
                        }
                    },
                );
                continue; // Re-check after waking
            }

            // Entry is ready — process it
            let seq = entry.seq;
            let thread_slot = entry.thread_slot;
            let syscall_nr = entry.syscall_nr;

            let result = if messages::is_control_message(syscall_nr) {
                self.handle_control_message(entry)
            } else {
                self.handle_syscall(entry)
            };

            // Write completion
            let cq_entry = CqEntry {
                seq,
                result,
                flags: 0,
                thread_slot,
                _pad: [0; 4],
                data_offset: 0,
                data_len: 0,
            };

            unsafe {
                cq::cq_push(header, self.region.cq_entries(), cq_entry);
            }

            // Notify the guest thread
            let notify_slot = cq::cq_notify_thread(header, thread_slot);
            // Futex wake on the notify slot
            unsafe {
                libc::syscall(
                    libc::SYS_futex,
                    notify_slot as *const core::sync::atomic::AtomicU32,
                    libc::FUTEX_WAKE,
                    1i32,
                );
            }

            // Advance the SQ head
            sq::sq_advance_head(header, entry);
        }
    }

    fn handle_syscall(&self, entry: &SqEntry) -> i64 {
        match crate::dispatch::parse_sq_entry(entry) {
            Ok(_request) => {
                // TODO: dispatch through Task::do_syscall()
                // For now, return -ENOSYS for all syscalls
                -(libc::ENOSYS as i64)
            }
            Err(errno) => -(errno.0 as i64),
        }
    }

    fn handle_control_message(&self, entry: &SqEntry) -> i64 {
        match entry.syscall_nr {
            messages::MSG_THREAD_REGISTER => {
                eprintln!("central: thread register from slot {}", entry.thread_slot);
                0 // success
            }
            messages::MSG_THREAD_DEREGISTER => {
                eprintln!("central: thread deregister from slot {}", entry.thread_slot);
                0
            }
            messages::MSG_CHILD_READY => {
                eprintln!("central: child ready");
                0
            }
            messages::MSG_FORK_RESULT => {
                let child_pid = entry.args[0] as i64;
                eprintln!("central: fork result, child_pid={child_pid}");
                0
            }
            messages::MSG_LOCAL_RESULT => {
                let orig_seq = entry.args[0];
                let result = entry.args[1] as i64;
                eprintln!("central: local result for seq={orig_seq}, result={result}");
                0
            }
            _ => {
                eprintln!("central: unknown control message {:#x}", entry.syscall_nr);
                -(libc::ENOSYS as i64)
            }
        }
    }
}
```

**Step 2: Add module and update main.rs**

```rust
mod dispatch;
mod server;
mod shmem;

fn main() -> anyhow::Result<()> {
    eprintln!("litebox_central: creating shared memory region");
    let region = shmem::SharedRegion::new()?;
    eprintln!(
        "litebox_central: shared region created, {} bytes",
        region.layout.total_size
    );

    let server = server::ProcessServer::new(region);
    eprintln!("litebox_central: starting server loop");
    server.run()
}
```

**Step 3: Verify**

```bash
cargo check -p litebox_central
cargo build -p litebox_central
```

**Step 4: Commit**

```bash
git add litebox_central/
git commit -m "feat(central): implement server loop with SQ consumption and CQ completion"
```

---

### Task 13: Integrate shim initialization into the server

Wire up `LinuxShimBuilder` + `LinuxShim` so the server can dispatch parsed `SyscallRequest`s through the real shim handlers.

**Files:**
- Modify: `litebox_central/src/server.rs`
- Modify: `litebox_central/src/main.rs`

**Step 1: Add shim initialization**

Update `ProcessServer` to hold a `LinuxShim`:

```rust
use litebox_shim_linux::{LinuxShimBuilder, LinuxShim};

pub struct ProcessServer {
    region: SharedRegion,
    shim: LinuxShim</* FS type from default_fs() */>,
}
```

The exact FS type depends on how the filesystem is configured. For the initial version, create a minimal filesystem (in-memory only, no tar overlay). Follow the pattern from `litebox_runner_linux_userland/src/lib.rs`.

**Step 2: Initialize the shim in main.rs**

```rust
fn main() -> anyhow::Result<()> {
    // Set up the platform
    let platform = Box::leak(Box::new(litebox_platform_central::CentralPlatform));
    litebox_platform_multiplex::set_platform(platform);

    // Build the shim
    let shim_builder = litebox_shim_linux::LinuxShimBuilder::new();
    // ... create filesystem, build shim ...

    // Create shared memory and server
    let region = shmem::SharedRegion::new()?;
    let server = server::ProcessServer::new(region, shim);
    server.run()
}
```

Note: This will likely require understanding the exact `DefaultFS` type and how to construct it. The implementation must match what the runner does. If the FS types are complex, consider starting with a simpler approach and iterating.

**Step 3: Dispatch through the shim**

In `handle_syscall`, use `Task::do_syscall()` to process the request. This requires creating a `Task` for the guest process. The exact mechanism depends on how `load_program` and `Task` interact.

This task is expected to be the most iterative. The key challenges:
1. `Task::do_syscall` takes `&mut self` + `&mut PtRegs` — we need a `Task` instance
2. `Task` is created by `load_program()` — but central doesn't load programs (micro does that)
3. We may need to create a `Task` without loading a program

**Step 4: Verify**

```bash
cargo check -p litebox_central
```

**Step 5: Commit**

```bash
git add litebox_central/
git commit -m "feat(central): integrate shim initialization and syscall dispatch"
```

---

### Task 14: Run full workspace build and clippy

**Step 1: Run clippy on new crates**

```bash
cargo clippy -p litebox_platform_central -- -D warnings
cargo clippy -p litebox_central -- -D warnings
```

**Step 2: Run full workspace build**

Ensure the default platform (linux_userland) still compiles:

```bash
cargo check
```

**Step 3: Run all existing tests**

```bash
cargo nextest run -p litebox_ipc
cargo nextest run -p litebox_central
cargo nextest run -p dev_tests
```

**Step 4: Fix any issues**

Address clippy warnings, test failures, and compilation errors.

**Step 5: Commit**

```bash
git add -A
git commit -m "chore: fix clippy warnings and ensure full workspace builds"
```

---

## Notes for the implementer

### Platform trait bound discovery

Task 8 is inherently iterative. The exact set of traits required depends on what the shim's code paths touch. The approach is:
1. Try to compile the shim with `--features platform_central`
2. Read the error messages — they'll say "the trait `FooProvider` is not implemented for `CentralPlatform`"
3. Implement a stub for that trait
4. Repeat until it compiles

### Pointer types are the biggest challenge

The `RawPointerProvider` trait requires `RawConstPointer<T>` and `RawMutPointer<T>` to implement `FromBytes + IntoBytes + Copy + Debug`. These derive macros from `zerocopy` have strict requirements (all fields must also implement the traits). `PhantomData` does implement `FromBytes`/`IntoBytes` in zerocopy 0.8, but if there are issues, use a bare `usize` wrapper with the type parameter only on the method level.

### PtRegs field names

The `PtRegs` struct in `litebox_common_linux` may use different field names than standard Linux. Check the actual struct definition before writing the `sq_entry_to_ptregs` function. The fields might be named `rdi`/`rsi`/etc. or `arg0`/`arg1`/etc.

### Feature flag isolation

When `litebox_central` is compiled, it pulls in `litebox_shim_linux` with `features = ["platform_central"]` and `default-features = false`. This means the shim is compiled against `CentralPlatform`, NOT `LinuxUserland`. The two are mutually exclusive in the same binary. The existing runner (`litebox_runner_linux_userland`) continues to use the default `platform_linux_userland` feature — unaffected.

### The `Errno` type

`litebox_common_linux::errno::Errno` wraps a raw `i32`. To convert it to a ring buffer result, use `-(errno.0 as i64)`. Check the actual type definition.
