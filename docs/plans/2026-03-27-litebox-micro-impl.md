# litebox_micro Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the `litebox_micro` crate — a forkable in-process agent that intercepts guest syscalls via the binary rewriter's trampoline mechanism, proxies them to central LiteBox over shared-memory ring buffer IPC, and executes locally-authorized operations.

**Architecture:** Micro is a library crate depending only on `litebox_ipc` + `libc`. It provides an x86_64 assembly trampoline entry point compatible with the syscall rewriter, GS-based per-thread TLS, an IPC handler that submits SqEntries and waits for CqEntries, local execution of memory-management syscalls, and fork handling with post-fork ring buffer reconnection.

**Tech Stack:** Rust (edition 2024), x86_64 `global_asm!`, `litebox_ipc`, `libc`, `cargo nextest`

**Workspace conventions:**
- Copyright header: `// Copyright (c) Microsoft Corporation.\n// Licensed under the MIT license.`
- No `[workspace.dependencies]` — each crate manages its own deps
- Workspace-level pedantic clippy lints
- Tests: `cargo nextest run -p litebox_micro`
- `litebox_ipc` is `#![no_std]`; `litebox_micro` uses `std`

---

### Task 1: Crate Skeleton

**Files:**
- Create: `litebox_micro/Cargo.toml`
- Create: `litebox_micro/src/lib.rs`
- Modify: `Cargo.toml` (workspace root — add to members and default-members)

**Step 1: Create Cargo.toml**

```toml
[package]
name = "litebox_micro"
version = "0.1.0"
edition = "2024"

[dependencies]
litebox_ipc = { path = "../litebox_ipc" }
libc = "0.2"
```

**Step 2: Create src/lib.rs**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Micro-LiteBox: a lightweight, forkable in-process agent that intercepts
//! guest syscalls and proxies them to central LiteBox via shared-memory ring
//! buffer IPC.

mod handler;
mod local_exec;
mod state;
mod tls;
mod trampoline;

pub use state::{micro_init, MicroState};
pub use tls::micro_init_thread;
pub use trampoline::get_syscall_entry_point;
```

Note: modules will be created as stubs (empty or minimal) in this task, then filled in subsequent tasks. Create each as an empty file with just the copyright header.

**Step 3: Add to workspace Cargo.toml**

Add `"litebox_micro"` to both `members` and `default-members` arrays.

**Step 4: Verify**

Run: `cargo check -p litebox_micro`
Expected: PASS (with warnings about unused modules)

**Step 5: Commit**

```
feat(micro): add litebox_micro crate skeleton
```

---

### Task 2: GS-Based Thread-Local Storage (`tls.rs`)

**Files:**
- Create: `litebox_micro/src/tls.rs`

**Context:**
- Uses GS segment register for per-thread micro state
- Guest uses FS for its own TLS (glibc); GS is unused on x86_64 Linux
- `arch_prctl(ARCH_SET_GS, addr)` sets the GS base
- The assembly trampoline accesses fields at fixed offsets: `gs:0x00` (self_ptr), `gs:0x08` (micro ptr), `gs:0x10` (thread_slot), `gs:0x18` (seq_counter), `gs:0x20` (return_addr)

**Step 1: Write the implementation**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! GS-based thread-local storage for micro-LiteBox.
//!
//! Each thread gets a [`MicroTls`] struct whose address is stored in the GS
//! segment base register. The assembly trampoline accesses fields at fixed
//! offsets via `gs:` prefixed memory operands.

use crate::state::MicroState;

/// Per-thread micro-LiteBox state, pointed to by GS base.
///
/// **ABI contract**: the assembly trampoline in `trampoline.rs` accesses
/// fields by their byte offsets. Do not reorder fields.
#[repr(C)]
pub struct MicroTls {
    /// Self-pointer for sanity checks (offset 0x00).
    pub self_ptr: *mut MicroTls,
    /// Pointer to the global [`MicroState`] (offset 0x08).
    pub micro: *mut MicroState,
    /// Thread slot assigned by central (offset 0x10).
    /// Stored as u64 for alignment; actual range is 0..64.
    pub thread_slot: u64,
    /// Monotonic sequence counter for SQ entries (offset 0x18).
    pub seq_counter: u64,
    /// Return address save slot used by the asm trampoline (offset 0x20).
    pub return_addr: u64,
}

const _: () = {
    assert!(core::mem::offset_of!(MicroTls, self_ptr) == 0x00);
    assert!(core::mem::offset_of!(MicroTls, micro) == 0x08);
    assert!(core::mem::offset_of!(MicroTls, thread_slot) == 0x10);
    assert!(core::mem::offset_of!(MicroTls, seq_counter) == 0x18);
    assert!(core::mem::offset_of!(MicroTls, return_addr) == 0x20);
};

/// Size of the mmap allocation for a single [`MicroTls`] instance.
/// We allocate a full page even though the struct is smaller, to avoid
/// sharing a page with guest data.
const TLS_ALLOC_SIZE: usize = 4096;

/// Initialize GS-based TLS for the current thread.
///
/// Allocates a page via `mmap`, fills in the [`MicroTls`] struct, and sets
/// the GS base via `arch_prctl(ARCH_SET_GS, ...)`.
///
/// # Safety
///
/// - Must be called exactly once per thread, before any guest code runs.
/// - `micro_state` must be a valid pointer that outlives the thread.
/// - Must not be called after seccomp filters are installed (unless the
///   `arch_prctl` syscall is allowlisted).
pub unsafe fn micro_init_thread_inner(
    micro_state: *mut MicroState,
    thread_slot: u16,
) -> *mut MicroTls {
    // Allocate a page for the TLS struct.
    let ptr = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            TLS_ALLOC_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(ptr, libc::MAP_FAILED, "mmap for MicroTls failed");

    let tls = ptr.cast::<MicroTls>();
    unsafe {
        (*tls).self_ptr = tls;
        (*tls).micro = micro_state;
        (*tls).thread_slot = u64::from(thread_slot);
        (*tls).seq_counter = 0;
        (*tls).return_addr = 0;
    }

    // Set GS base to point to our TLS struct.
    // ARCH_SET_GS = 0x1001
    let ret = unsafe { libc::syscall(libc::SYS_arch_prctl, 0x1001i32, tls as usize) };
    assert_eq!(ret, 0, "arch_prctl(ARCH_SET_GS) failed: {ret}");

    tls
}

/// Public convenience wrapper: initialize TLS for the current thread.
///
/// # Safety
///
/// See [`micro_init_thread_inner`].
pub unsafe fn micro_init_thread(thread_slot: u16) {
    let micro_state = crate::state::global_micro_state_ptr();
    unsafe {
        micro_init_thread_inner(micro_state, thread_slot);
    }
}

/// Read the current thread's [`MicroTls`] pointer from GS base.
///
/// # Safety
///
/// GS base must have been set by [`micro_init_thread`] on this thread.
#[inline]
pub unsafe fn current_tls() -> *mut MicroTls {
    let ptr: usize;
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[0x00]",
            out(reg) ptr,
            options(nostack, preserves_flags, readonly),
        );
    }
    ptr as *mut MicroTls
}
```

**Step 2: Write tests**

Add tests at the bottom of `tls.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_field_offsets() {
        // Verified by const asserts above, but double-check at runtime.
        assert_eq!(core::mem::offset_of!(MicroTls, self_ptr), 0x00);
        assert_eq!(core::mem::offset_of!(MicroTls, micro), 0x08);
        assert_eq!(core::mem::offset_of!(MicroTls, thread_slot), 0x10);
        assert_eq!(core::mem::offset_of!(MicroTls, seq_counter), 0x18);
        assert_eq!(core::mem::offset_of!(MicroTls, return_addr), 0x20);
    }

    #[test]
    fn tls_struct_size() {
        assert_eq!(core::mem::size_of::<MicroTls>(), 40);
    }

    #[test]
    fn init_and_read_tls() {
        // Create a dummy MicroState on the stack.
        let mut dummy_state = crate::state::MicroState::zeroed();
        let tls = unsafe {
            micro_init_thread_inner(&mut dummy_state as *mut _, 7)
        };
        assert!(!tls.is_null());

        // Verify fields were set correctly.
        unsafe {
            assert_eq!((*tls).self_ptr, tls);
            assert_eq!((*tls).micro, &mut dummy_state as *mut _);
            assert_eq!((*tls).thread_slot, 7);
            assert_eq!((*tls).seq_counter, 0);
            assert_eq!((*tls).return_addr, 0);
        }

        // Verify GS-based read.
        let read_tls = unsafe { current_tls() };
        assert_eq!(read_tls, tls);

        // Clean up: unmap the TLS page.
        unsafe { libc::munmap(tls.cast(), TLS_ALLOC_SIZE) };
    }
}
```

**Step 3: Verify**

Run: `cargo nextest run -p litebox_micro`
Expected: 3 tests pass

**Step 4: Commit**

```
feat(micro): add GS-based thread-local storage
```

---

### Task 3: Global Micro State (`state.rs`)

**Files:**
- Create: `litebox_micro/src/state.rs`

**Context:**
- Global per-process state: ring buffer base pointer, size, fd, PID, PPID
- Stored as a `static mut` — only accessed from micro code paths
- Must be forkable: no Arc/Mutex, just plain data
- `MicroState::zeroed()` needed for tests

**Step 1: Write the implementation**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Global per-process micro-LiteBox state.
//!
//! A single [`MicroState`] instance is stored in a `static mut` and accessed
//! by the syscall handler. All fields are plain data — no `Arc`, no `Mutex` —
//! so the state survives `fork()` correctly via CoW.

use litebox_ipc::ring::SharedRingLayout;

/// Global per-process micro-LiteBox state.
#[repr(C)]
pub struct MicroState {
    /// Base address of the mmap'd shared memory region.
    pub ring_base: *mut u8,
    /// Size of the shared memory region in bytes.
    pub ring_size: usize,
    /// File descriptor for the shared memory (memfd).
    pub ring_fd: i32,
    /// Process ID (updated in child after fork).
    pub pid: u32,
    /// Parent process ID (updated in child after fork).
    pub ppid: u32,
    /// Cached ring layout so we don't recompute offsets on every syscall.
    pub layout: SharedRingLayout,
}

/// SAFETY: MicroState contains raw pointers but is only accessed by the
/// owning process (single-writer via the syscall handler path).
unsafe impl Send for MicroState {}
unsafe impl Sync for MicroState {}

/// The global micro-LiteBox state.
///
/// # Safety
///
/// Access is safe because:
/// - Before `micro_init`, the state is zeroed and unused.
/// - After `micro_init`, access is single-threaded from the syscall handler
///   (each thread reads the shared ring_base/layout but writes only to its
///   own TLS and ring buffer slots).
/// - During fork, only the forking thread is active in the child.
static mut MICRO_STATE: MicroState = MicroState {
    ring_base: core::ptr::null_mut(),
    ring_size: 0,
    ring_fd: -1,
    pid: 0,
    ppid: 0,
    layout: SharedRingLayout::new(0),
};

/// Initialize the global micro-LiteBox state.
///
/// # Safety
///
/// Must be called exactly once, before any guest code runs and before any
/// threads are spawned.
pub unsafe fn micro_init(
    ring_fd: i32,
    ring_base: *mut u8,
    ring_size: usize,
    pid: u32,
    ppid: u32,
) {
    unsafe {
        MICRO_STATE.ring_base = ring_base;
        MICRO_STATE.ring_size = ring_size;
        MICRO_STATE.ring_fd = ring_fd;
        MICRO_STATE.pid = pid;
        MICRO_STATE.ppid = ppid;
        MICRO_STATE.layout =
            SharedRingLayout::new(ring_size.saturating_sub(SharedRingLayout::new(0).total_size));
    }
}

/// Get a raw pointer to the global [`MicroState`].
///
/// # Safety
///
/// The caller must ensure `micro_init` has been called.
#[inline]
pub fn global_micro_state_ptr() -> *mut MicroState {
    unsafe { core::ptr::addr_of_mut!(MICRO_STATE) }
}

/// Get a reference to the global [`MicroState`].
///
/// # Safety
///
/// The caller must ensure `micro_init` has been called and that no mutable
/// reference to `MICRO_STATE` exists concurrently.
#[inline]
pub unsafe fn global_micro_state() -> &'static MicroState {
    unsafe { &*core::ptr::addr_of!(MICRO_STATE) }
}

/// Get a mutable reference to the global [`MicroState`].
///
/// # Safety
///
/// The caller must ensure exclusive access (e.g., during `micro_init` or
/// in the child process immediately after `fork()` before any threads are
/// spawned).
#[inline]
pub unsafe fn global_micro_state_mut() -> &'static mut MicroState {
    unsafe { &mut *core::ptr::addr_of_mut!(MICRO_STATE) }
}

impl MicroState {
    /// Create a zeroed `MicroState` for testing.
    #[cfg(test)]
    pub fn zeroed() -> Self {
        Self {
            ring_base: core::ptr::null_mut(),
            ring_size: 0,
            ring_fd: -1,
            pid: 0,
            ppid: 0,
            layout: SharedRingLayout::new(0),
        }
    }
}
```

**Step 2: Write tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn micro_state_is_plain_data() {
        // Ensure MicroState doesn't accidentally contain non-Copy types.
        let state = MicroState::zeroed();
        assert!(state.ring_base.is_null());
        assert_eq!(state.ring_fd, -1);
        assert_eq!(state.pid, 0);
    }

    #[test]
    fn global_micro_state_ptr_is_stable() {
        let p1 = global_micro_state_ptr();
        let p2 = global_micro_state_ptr();
        assert_eq!(p1, p2);
    }
}
```

**Step 3: Verify**

Run: `cargo nextest run -p litebox_micro`
Expected: All tests pass (TLS tests + state tests)

**Step 4: Commit**

```
feat(micro): add global MicroState
```

---

### Task 4: Assembly Trampoline (`trampoline.rs`)

**Files:**
- Create: `litebox_micro/src/trampoline.rs`

**Context:**
- Entry point compatible with syscall rewriter: `RCX` = return addr, `RAX` = syscall nr, `RDI/RSI/RDX/R10/R8/R9` = args
- Saves return address to `gs:[0x20]`, builds `SyscallArgs` on stack, calls Rust handler, returns via `jmp rcx`
- The handler function `micro_handle_syscall` is defined in `handler.rs` (Task 5)
- For this task, create a stub handler that returns `-ENOSYS` so the trampoline can be tested

**Step 1: Write the implementation**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! x86_64 assembly trampoline for micro-LiteBox syscall interception.
//!
//! The syscall rewriter replaces `syscall` instructions with `JMP` to a
//! per-binary trampoline stub that loads the return address into `RCX` and
//! performs an indirect jump through the address at trampoline offset 0.
//! At load time, that address is patched to [`micro_syscall_entry`].

/// The syscall arguments as laid out on the stack by the assembly trampoline.
///
/// **ABI contract**: the assembly code pushes fields in this exact order.
/// Do not reorder.
#[repr(C)]
pub struct SyscallArgs {
    /// Linux syscall number (from `RAX`).
    pub nr: u64,
    /// arg0 (from `RDI`).
    pub args: [u64; 6],
}

const _: () = assert!(core::mem::size_of::<SyscallArgs>() == 56);

core::arch::global_asm!(
    ".text",
    ".globl micro_syscall_entry",
    ".type micro_syscall_entry, @function",
    // Align to 16 bytes for branch target performance.
    ".balign 16",
    "micro_syscall_entry:",
    // Save return address (RCX) to GS-based TLS slot at offset 0x20.
    "mov gs:[0x20], rcx",
    // Build SyscallArgs struct on the stack (7 * 8 = 56 bytes).
    "sub rsp, 56",
    "mov [rsp+0x00], rax",       // nr
    "mov [rsp+0x08], rdi",       // arg0
    "mov [rsp+0x10], rsi",       // arg1
    "mov [rsp+0x18], rdx",       // arg2
    "mov [rsp+0x20], r10",       // arg3
    "mov [rsp+0x28], r8",        // arg4
    "mov [rsp+0x30], r9",        // arg5
    // Call Rust handler: micro_handle_syscall(args: *const SyscallArgs) -> i64
    // First C argument (RDI) = pointer to SyscallArgs on stack.
    "mov rdi, rsp",
    "call micro_handle_syscall",
    // Result is in RAX. Clean up stack.
    "add rsp, 56",
    // Restore return address and jump back to guest code.
    "mov rcx, gs:[0x20]",
    "jmp rcx",
    ".size micro_syscall_entry, . - micro_syscall_entry",
);

extern "C" {
    /// The assembly entry point. Its address is written into the trampoline
    /// region at offset 0 during ELF loading.
    fn micro_syscall_entry();
}

/// Return the address of the micro syscall entry point.
///
/// This value is what gets written to the trampoline's offset 0 at load time.
pub fn get_syscall_entry_point() -> usize {
    micro_syscall_entry as usize
}
```

**Step 2: Write test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscall_args_size() {
        assert_eq!(core::mem::size_of::<SyscallArgs>(), 56);
    }

    #[test]
    fn entry_point_is_nonzero() {
        let ep = get_syscall_entry_point();
        assert_ne!(ep, 0);
    }
}
```

**Step 3: Verify**

Run: `cargo nextest run -p litebox_micro`
Expected: All tests pass

Note: the trampoline itself cannot be directly unit-tested (it requires an actual rewritten binary). The entry point address test confirms the symbol exists and links.

**Step 4: Commit**

```
feat(micro): add x86_64 assembly trampoline
```

---

### Task 5: Syscall Handler (`handler.rs`)

**Files:**
- Create: `litebox_micro/src/handler.rs`

**Context:**
- Called from the assembly trampoline via `call micro_handle_syscall`
- Reads per-thread state from GS-based TLS
- Builds SqEntry, pushes to SQ, wakes central, waits for CqEntry
- If CqEntry has `FLAG_EXEC_LOCAL`, calls into `local_exec.rs` and reports result
- Uses `litebox_ipc::{sq, cq, wait, ring, messages}` for ring operations
- For futex operations, uses raw `libc::syscall(SYS_futex, ...)`

**Step 1: Write the implementation**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Core syscall handler called from the assembly trampoline.

use core::sync::atomic::Ordering::{Acquire, Relaxed};

use litebox_ipc::cq::{cq_find_by_seq, cq_tail};
use litebox_ipc::ring::{cq_flags, CqEntry, RingHeader, SharedRingLayout, SqEntry};
use litebox_ipc::sq::{sq_acquire_slot, sq_publish};
use litebox_ipc::wait::spin_then_wait;

use crate::local_exec::execute_locally;
use crate::tls::MicroTls;
use crate::trampoline::SyscallArgs;

/// Futex wait: block if `*addr == expected`.
fn futex_wait(addr: &core::sync::atomic::AtomicU32, expected: u32) {
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            addr as *const _ as usize,
            libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
            expected,
            core::ptr::null::<libc::timespec>(),
        );
    }
    // Ignore errors — spurious wakeups and EAGAIN are both fine.
}

/// Futex wake: wake one waiter on `addr`.
fn futex_wake(addr: &core::sync::atomic::AtomicU32) {
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            addr as *const _ as usize,
            libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
            1i32,
        );
    }
}

/// Obtain pointers to the ring header and entry arrays from the shared memory
/// base address and layout.
///
/// # Safety
///
/// `base` must point to a valid shared memory region of at least
/// `layout.total_size` bytes that is properly initialized.
#[inline]
unsafe fn ring_ptrs(
    base: *mut u8,
    layout: &SharedRingLayout,
) -> (&'static RingHeader, *mut SqEntry, *mut CqEntry) {
    let header = unsafe { &*(base.cast::<RingHeader>()) };
    let sq_entries = unsafe { base.add(layout.sq_entries_offset).cast::<SqEntry>() };
    let cq_entries = unsafe { base.add(layout.cq_entries_offset).cast::<CqEntry>() };
    (header, sq_entries, cq_entries)
}

/// Submit an SqEntry and wait for the corresponding CqEntry.
///
/// # Safety
///
/// - `tls` must point to a valid, initialized [`MicroTls`].
/// - The shared memory region must be properly initialized.
unsafe fn submit_and_wait(
    tls: *mut MicroTls,
    syscall_nr: u32,
    args: &[u64; 6],
    flags: u16,
) -> CqEntry {
    let micro = unsafe { &*(*tls).micro };
    let (header, sq_entries, cq_entries) = unsafe { ring_ptrs(micro.ring_base, &micro.layout) };

    // Allocate sequence number.
    let seq = unsafe { (*tls).seq_counter };
    unsafe { (*tls).seq_counter += 1 };

    // Acquire an SQ slot.
    let slot_idx = unsafe { sq_acquire_slot(header) };
    let entry = unsafe { &mut *sq_entries.add(slot_idx as usize) };

    // Fill in the SqEntry fields.
    entry.seq = seq;
    entry.syscall_nr = syscall_nr;
    entry.thread_slot = unsafe { (*tls).thread_slot as u16 };
    entry.flags = flags;
    entry.args = *args;
    entry.data_offset = 0;
    entry.data_len = 0;

    // Publish the entry (sets ready flag with Release ordering).
    sq_publish(entry);

    // Wake central's server thread.
    futex_wake(&header.sq_notify);

    // Wait for the CQ entry matching our sequence number.
    let thread_slot = unsafe { (*tls).thread_slot as u16 };
    let notify_slot = &header.cq_notify_slots[thread_slot as usize];
    let mut search_start = cq_tail(header);

    loop {
        // Check if our completion has arrived.
        if let Some(cq) = unsafe { cq_find_by_seq(header, cq_entries, search_start, seq) } {
            return cq;
        }
        // Wait for notification from central.
        let current = notify_slot.load(Acquire);
        // Re-check before blocking (avoid missed wake).
        if let Some(cq) =
            unsafe { cq_find_by_seq(header, cq_entries, search_start, seq) }
        {
            return cq;
        }
        spin_then_wait(notify_slot, current, |addr, exp| futex_wait(addr, exp));
        // Update search start to avoid re-scanning old entries.
        search_start = cq_tail(header);
    }
}

/// Submit a control message reporting the result of a locally-executed syscall.
///
/// # Safety
///
/// Same requirements as [`submit_and_wait`].
unsafe fn report_local_result(tls: *mut MicroTls, original_seq: u64, result: i64) {
    let args = [original_seq, result as u64, 0, 0, 0, 0];
    // We wait for the ack but ignore its content.
    unsafe {
        submit_and_wait(tls, litebox_ipc::messages::MSG_LOCAL_RESULT, &args, 0);
    }
}

/// The Rust syscall handler called from the assembly trampoline.
///
/// # Safety
///
/// - Called from assembly with `args` pointing to a valid [`SyscallArgs`] on
///   the caller's stack.
/// - GS base must have been initialized by [`crate::tls::micro_init_thread`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn micro_handle_syscall(args: *const SyscallArgs) -> i64 {
    let args = unsafe { &*args };
    let tls = unsafe { crate::tls::current_tls() };

    let cq = unsafe {
        submit_and_wait(
            tls,
            args.nr as u32,
            &args.args,
            litebox_ipc::ring::sq_flags::NEED_AUTH,
        )
    };

    if cq.flags & cq_flags::EXEC_LOCAL != 0 {
        // Central authorized local execution.
        let result = unsafe { execute_locally(args.nr as u32, &args.args, &cq) };
        // Report the result back to central.
        unsafe { report_local_result(tls, cq.seq, result) };
        result
    } else {
        // Central handled it remotely; return the result directly.
        cq.result
    }
}
```

**Step 2: Verify**

Run: `cargo check -p litebox_micro`
Expected: PASS (handler compiles; cannot be directly unit-tested since it requires a live ring buffer)

**Step 3: Commit**

```
feat(micro): add core syscall handler with IPC round-trip
```

---

### Task 6: Local Execution (`local_exec.rs`)

**Files:**
- Create: `litebox_micro/src/local_exec.rs`

**Context:**
- Executes memory-management syscalls in the guest's address space when central authorizes with `FLAG_EXEC_LOCAL`
- Supported syscalls for v1: `mmap`, `munmap`, `mprotect`, `mremap`, `madvise`, `brk`, `arch_prctl`
- Fork/clone is handled separately in `fork.rs` (Task 7)
- Uses raw `libc::syscall()` for actual execution
- CqEntry's `result` field may carry parameter overrides from central

**Step 1: Write the implementation**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Local execution of syscalls authorized by central.
//!
//! When central returns a [`CqEntry`] with [`cq_flags::EXEC_LOCAL`], micro
//! executes the real host syscall in the guest's address space and reports
//! the result back.

use litebox_ipc::ring::CqEntry;

/// Execute a locally-authorized syscall.
///
/// Returns the syscall result (or negated errno on failure).
///
/// # Safety
///
/// The caller must ensure that `args` contains valid arguments for the given
/// `syscall_nr` and that central has authorized the operation.
pub unsafe fn execute_locally(syscall_nr: u32, args: &[u64; 6], _cq: &CqEntry) -> i64 {
    match syscall_nr {
        nr if nr == libc::SYS_mmap as u32 => unsafe {
            libc::syscall(
                libc::SYS_mmap,
                args[0] as usize, // addr
                args[1] as usize, // length
                args[2] as i32,   // prot
                args[3] as i32,   // flags
                args[4] as i32,   // fd
                args[5] as i64,   // offset
            )
        },
        nr if nr == libc::SYS_munmap as u32 => unsafe {
            libc::syscall(
                libc::SYS_munmap,
                args[0] as usize, // addr
                args[1] as usize, // length
            )
        },
        nr if nr == libc::SYS_mprotect as u32 => unsafe {
            libc::syscall(
                libc::SYS_mprotect,
                args[0] as usize, // addr
                args[1] as usize, // length
                args[2] as i32,   // prot
            )
        },
        nr if nr == libc::SYS_mremap as u32 => unsafe {
            libc::syscall(
                libc::SYS_mremap,
                args[0] as usize, // old_addr
                args[1] as usize, // old_size
                args[2] as usize, // new_size
                args[3] as i32,   // flags
                args[4] as usize, // new_addr (optional, only if MREMAP_FIXED)
            )
        },
        nr if nr == libc::SYS_madvise as u32 => unsafe {
            libc::syscall(
                libc::SYS_madvise,
                args[0] as usize, // addr
                args[1] as usize, // length
                args[2] as i32,   // advice
            )
        },
        nr if nr == libc::SYS_brk as u32 => unsafe {
            libc::syscall(libc::SYS_brk, args[0] as usize)
        },
        nr if nr == libc::SYS_arch_prctl as u32 => unsafe {
            libc::syscall(
                libc::SYS_arch_prctl,
                args[0] as i32,   // code (ARCH_SET_FS, ARCH_GET_FS, etc.)
                args[1] as usize, // addr
            )
        },
        _ => {
            // Unknown syscall for local execution — this shouldn't happen
            // if central is well-behaved. Return -ENOSYS.
            -(libc::ENOSYS as i64)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_ipc::ring::CqEntry;

    fn dummy_cq() -> CqEntry {
        CqEntry {
            seq: 0,
            result: 0,
            flags: 0,
            thread_slot: 0,
            _pad: [0; 4],
            data_offset: 0,
            data_len: 0,
        }
    }

    #[test]
    fn local_exec_mmap_anonymous() {
        let args = [
            0u64,                                                   // addr = NULL
            4096u64,                                                // length
            (libc::PROT_READ | libc::PROT_WRITE) as u64,           // prot
            (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,      // flags
            u64::MAX,                                               // fd = -1
            0u64,                                                   // offset
        ];
        let cq = dummy_cq();
        let result = unsafe { execute_locally(libc::SYS_mmap as u32, &args, &cq) };
        assert_ne!(result, -1, "mmap failed");
        assert_ne!(result, 0, "mmap returned NULL");

        // Clean up.
        let unmap_args = [result as u64, 4096u64, 0, 0, 0, 0];
        let unmap_result =
            unsafe { execute_locally(libc::SYS_munmap as u32, &unmap_args, &cq) };
        assert_eq!(unmap_result, 0, "munmap failed");
    }

    #[test]
    fn local_exec_unknown_returns_enosys() {
        let args = [0u64; 6];
        let cq = dummy_cq();
        let result = unsafe { execute_locally(0xFFFF, &args, &cq) };
        assert_eq!(result, -(libc::ENOSYS as i64));
    }
}
```

**Step 2: Verify**

Run: `cargo nextest run -p litebox_micro`
Expected: All tests pass

**Step 3: Commit**

```
feat(micro): add local execution for memory-management syscalls
```

---

### Task 7: Fork Handling (`fork.rs`)

**Files:**
- Create: `litebox_micro/src/fork.rs`

**Context:**
- Handles the fork flow: central sends back `FLAG_EXEC_LOCAL` + child ring fd info
- Micro calls real `fork()`, then in the child:
  - Unmaps parent's ring buffer
  - Maps child's new ring buffer (fd from CqEntry data)
  - Updates MicroState (pid, ppid, ring_base)
  - Resets TLS (thread_slot=0, seq_counter=0)
  - Sends MSG_CHILD_READY, waits for ack
- For v1, the child ring fd is communicated via CqEntry fields:
  - `result` field = child ring fd (pre-created by central, inherited across fork)
  - `data_offset` field reused to carry child PID assigned by central

**Step 1: Write the implementation**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Fork handling: execute a real `fork()` and reconnect the child to central
//! via a new ring buffer.

use litebox_ipc::messages::{MSG_CHILD_READY, MSG_LOCAL_RESULT};
use litebox_ipc::ring::{CqEntry, SharedRingLayout};

/// Reserved file descriptor number for passing the child's ring buffer fd
/// across `fork()`.
///
/// We `dup2()` the child ring fd to this number before forking so that both
/// parent and child have it at a known location after fork.
const RESERVED_CHILD_FD: i32 = 200;

/// Execute a fork authorized by central.
///
/// `cq.result` contains the child ring fd (already open in this process,
/// created by central via memfd_create and shared via SCM_RIGHTS or direct
/// fd passing).
///
/// `cq.data_offset` is reused to carry the child PID assigned by central.
///
/// Returns: child PID in parent, 0 in child, or negative errno on failure.
///
/// # Safety
///
/// - The global [`MicroState`] must be initialized.
/// - TLS must be initialized for the calling thread.
/// - `cq` must be a valid response from central with `FLAG_EXEC_LOCAL` set
///   and containing a valid child ring fd in `result`.
pub unsafe fn handle_fork(cq: &CqEntry) -> i64 {
    let child_ring_fd = cq.result as i32;
    let child_pid_from_central = cq.data_offset;

    // Place the child ring fd at a well-known number so both parent and
    // child have it after fork.
    let dup_ret = unsafe { libc::dup2(child_ring_fd, RESERVED_CHILD_FD) };
    if dup_ret < 0 {
        return -(unsafe { *libc::__errno_location() } as i64);
    }

    // Perform the real fork.
    let pid = unsafe { libc::fork() };

    if pid < 0 {
        // Fork failed.
        let errno = unsafe { *libc::__errno_location() };
        unsafe { libc::close(RESERVED_CHILD_FD) };
        return -(errno as i64);
    }

    if pid == 0 {
        // CHILD process.
        unsafe { post_fork_child(RESERVED_CHILD_FD, child_pid_from_central) };
        0
    } else {
        // PARENT process.
        // Close the child's ring fd — parent doesn't need it.
        unsafe { libc::close(RESERVED_CHILD_FD) };
        i64::from(pid)
    }
}

/// Post-fork child initialization: disconnect from parent's ring and connect
/// to the child's own ring buffer.
///
/// # Safety
///
/// Must be called in the child process immediately after `fork()` returns 0,
/// before any other syscalls are proxied through the ring buffer.
unsafe fn post_fork_child(child_ring_fd: i32, child_pid: u32) {
    let micro = unsafe { crate::state::global_micro_state_mut() };

    // 1. Unmap parent's ring buffer.
    if !micro.ring_base.is_null() && micro.ring_size > 0 {
        unsafe { libc::munmap(micro.ring_base.cast(), micro.ring_size) };
    }

    // 2. Map child's new ring buffer.
    let layout = SharedRingLayout::default_layout();
    let new_base = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            layout.total_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            child_ring_fd,
            0,
        )
    };
    assert_ne!(
        new_base,
        libc::MAP_FAILED,
        "child: mmap of new ring buffer failed"
    );

    // 3. Update global micro state.
    micro.ring_base = new_base.cast();
    micro.ring_size = layout.total_size;
    micro.ring_fd = child_ring_fd;
    micro.pid = child_pid;
    micro.ppid = unsafe {
        // Use the real ppid — it's the parent process that just forked us.
        libc::getppid() as u32
    };
    micro.layout = layout;

    // 4. Reset the calling thread's TLS.
    let tls = unsafe { crate::tls::current_tls() };
    unsafe {
        (*tls).micro = crate::state::global_micro_state_ptr();
        (*tls).thread_slot = 0;
        (*tls).seq_counter = 0;
    }

    // 5. Send MSG_CHILD_READY to central via the new ring.
    // We reuse submit_and_wait which will push an SqEntry and wait for ack.
    let args = [u64::from(child_pid), 0, 0, 0, 0, 0];
    unsafe {
        crate::handler::submit_and_wait(tls, MSG_CHILD_READY, &args, 0);
    }

    // 6. Close the reserved fd (no longer needed after mmap).
    unsafe { libc::close(child_ring_fd) };
}
```

Note: `submit_and_wait` in `handler.rs` must be made `pub(crate)` for this to work. Update the visibility in Task 5's code.

**Step 2: Verify**

Run: `cargo check -p litebox_micro`
Expected: PASS

Note: fork handling cannot be meaningfully unit-tested without a live central process. Integration tests are deferred to Phase 5.

**Step 3: Commit**

```
feat(micro): add fork handling with post-fork ring reconnection
```

---

### Task 8: Wire Up lib.rs and Final Integration

**Files:**
- Modify: `litebox_micro/src/lib.rs` — update module declarations and re-exports
- Modify: `litebox_micro/src/handler.rs` — make `submit_and_wait` `pub(crate)`

**Step 1: Update lib.rs**

Ensure all modules are declared and the public API is clean:

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Micro-LiteBox: a lightweight, forkable in-process agent that intercepts
//! guest syscalls and proxies them to central LiteBox via shared-memory ring
//! buffer IPC.
//!
//! # Architecture
//!
//! Micro is the in-process half of the LiteBox split architecture. It
//! provides:
//!
//! - An x86_64 assembly trampoline compatible with the syscall rewriter
//! - GS-based per-thread TLS for zero-overhead thread-local state
//! - SQ/CQ ring buffer IPC to central LiteBox
//! - Local execution of memory-management syscalls (mmap, munmap, etc.)
//! - Fork handling with post-fork ring buffer reconnection
//!
//! All state is plain data (no Arc, no Mutex) — the process can be forked
//! and the child's micro state is correctly duplicated via CoW.

pub mod fork;
pub mod handler;
pub mod local_exec;
pub mod state;
pub mod tls;
pub mod trampoline;

pub use state::micro_init;
pub use tls::micro_init_thread;
pub use trampoline::get_syscall_entry_point;
```

**Step 2: Run full verification**

```bash
cargo check -p litebox_micro
cargo clippy -p litebox_micro -- -D warnings
cargo nextest run -p litebox_micro
cargo check  # full workspace default-members
```

Expected: All pass, clippy clean, all tests pass.

**Step 3: Update ratchet test if needed**

Check `dev_tests/src/ratchet.rs` — if `litebox_micro` introduces any thread-local statics or global statics that the ratchet test counts, add an entry.

**Step 4: Run dev_tests**

```bash
cargo nextest run -p dev_tests
```

Expected: PASS

**Step 5: Commit**

```
feat(micro): wire up all modules and finalize public API
```

---

### Task 9: Workspace Build Validation

**Files:**
- Possibly modify: `Cargo.toml` (if `litebox_micro` causes feature unification issues)
- Possibly modify: `dev_tests/src/ratchet.rs`

**Step 1: Full workspace check**

```bash
cargo check
cargo clippy -- -D warnings
```

If there are feature unification issues (like `litebox_central`), move `litebox_micro` out of `default-members`.

**Step 2: Run all tests**

```bash
cargo nextest run -p litebox_micro -p litebox_ipc -p dev_tests
```

**Step 3: Commit (if any fixes needed)**

```
fix(micro): workspace build fixes
```
