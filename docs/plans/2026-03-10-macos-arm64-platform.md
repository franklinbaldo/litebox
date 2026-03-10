# macOS ARM64 Platform Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Create `litebox_platform_macos_userland` — a macOS ARM64 (Apple Silicon) host platform for running rewritten Linux ARM64 binaries, forked from `litebox_platform_linux_userland`.

**Architecture:** Fork-and-adapt from the Linux ARM64 platform. The Linux guest ABI (`litebox_common_linux`) is reused unchanged. The syscall rewriter (`litebox_syscall_rewriter`) is reused unchanged — same SVC + MSR interception, same TLS table (conservative approach). Platform-specific subsystems (memory maps, mutex, signals, TUN) are adapted for Darwin/XNU.

**Tech Stack:** Rust (stable), `libc` crate (Darwin target), Mach VM APIs, `os_unfair_lock`, POSIX signals (no RT signals), AArch64 inline asm.

---

## Context

### Key differences from Linux ARM64

| Component | Linux | macOS |
|---|---|---|
| Memory map discovery | `/proc/self/maps` | `mach_vm_region_recurse` |
| Mutex blocking | `futex(FUTEX_WAIT/WAKE)` | `os_unfair_lock` + `__ulock_wait/__ulock_wake` |
| TUN networking | `/dev/net/tun` + `TUNSETIFF` | Deferred (stubbed) |
| Thread interrupt signal | `SIGRTMIN+n` (RT signal) | `SIGUSR1` |
| Signal context struct | `libc::ucontext_t` → `mcontext.regs[]`, `.sp`, `.pc`, `.pstate`, `.fault_address` | `libc::ucontext_t` → `__darwin_mcontext64.__ss.__x[]`, `.__sp`, `.__pc`, `.__cpsr`, `.__es.__far` |
| TLS variable sections | `.section .tbss,"awT",@nobits` (ELF) | `.section __DATA,__thread_bss,thread_local_zerofill` (Mach-O) |
| `mremap` | Linux syscall | Not available — use `mmap` + copy + `munmap` |
| VDSO | Discovered from `/proc/self/maps` | No VDSO on macOS (return `None`) |
| seccomp / systrap | Optional feature | Not applicable (removed) |
| Raw syscall wrappers | `syscalls::syscall*()` | `libc::*()` |
| TPIDR_EL0 | Host TLS register, swapped on guest entry/exit | Conservative: same TLS table approach as Linux |
| Sigreturn trampoline | `MOV X8, #139; SVC #0` (intercepted by rewriter) | Identical — SVC is intercepted before reaching kernel |

### What's reused unchanged
- `litebox_common_linux` (guest ABI: `PtRegs`, syscall definitions, signals, ELF loader)
- `litebox_syscall_rewriter` (SVC + MSR interception, TLS table, shared trampoline)
- `litebox_shim_linux` (syscall emulation layer)
- Thread spawning (`std::thread` + `pthread_kill`)
- Time (`clock_gettime` works on macOS)
- Stdio, debug logging, CRNG, raw pointer providers
- `VmapManager` (no-op), `VmemPageFaultHandler` (no-op)
- Guest context switch asm (mostly — TLS variable declarations change)
- Alt-stack trick for host TLS recovery in signal handlers

### Source files reference
- **Linux platform (source):** `litebox_platform_linux_userland/src/lib.rs` (3232 lines)
- **Windows platform (pattern reference):** `litebox_platform_windows_userland/src/lib.rs` (1956 lines)
- **Multiplex:** `litebox_platform_multiplex/src/lib.rs` (71 lines)

---

## Task 1: Scaffold the crate and wire into workspace

**Files:**
- Create: `litebox_platform_macos_userland/Cargo.toml`
- Create: `litebox_platform_macos_userland/src/lib.rs`
- Modify: `Cargo.toml` (workspace root, lines 3-44)
- Modify: `litebox_platform_multiplex/Cargo.toml` (lines 6-25)
- Modify: `litebox_platform_multiplex/src/lib.rs` (lines 29-43)

**Step 1: Create Cargo.toml**

```toml
[package]
name = "litebox_platform_macos_userland"
version = "0.1.0"
edition = "2024"

[target.'cfg(target_os = "macos")'.dependencies]
getrandom = "0.3.4"
libc = { version = "0.2.169", default-features = false }
litebox = { path = "../litebox/", version = "0.1.0" }
litebox_common_linux = { path = "../litebox_common_linux", version = "0.1.0" }
zerocopy = { version = "0.8", default-features = false }

[features]
default = ["linux_syscall"]
linux_syscall = []

[lints]
workspace = true
```

Note: No `syscalls` crate (Linux-only), no `seccompiler`, no `spin`, no `cfg-if`, no `litebox_common_optee`.

**Step 2: Create minimal lib.rs**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox on userland macOS (Apple Silicon).

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

extern crate alloc;

/// The userland macOS platform.
pub struct MacosUserland;
```

**Step 3: Add to workspace root Cargo.toml**

Add `"litebox_platform_macos_userland"` to `members` list (after `litebox_platform_windows_userland`). Do NOT add to `default-members` — it only compiles on macOS.

**Step 4: Wire into multiplex**

In `litebox_platform_multiplex/Cargo.toml`, add:
```toml
litebox_platform_macos_userland = { path = "../litebox_platform_macos_userland/", version = "0.1.0", default-features = false, optional = true }
```
And feature:
```toml
platform_macos_userland = ["dep:litebox_platform_macos_userland"]
```

In `litebox_platform_multiplex/src/lib.rs`, add a new branch before the `compile_error!`:
```rust
} else if #[cfg(all(feature = "platform_macos_userland", target_os = "macos"))] {
    pub type Platform = litebox_platform_macos_userland::MacosUserland;
}
```

**Step 5: Verify it compiles**

Run: `cargo check -p litebox_platform_macos_userland` (will be a no-op on Linux due to cfg gate, but should not error).
Run: `cargo check -p litebox_platform_multiplex` (should still compile with default features).

**Step 6: Commit**

```
feat(macos): scaffold litebox_platform_macos_userland crate and wire into workspace
```

---

## Task 2: Fork lib.rs from Linux and strip Linux-only code

**Files:**
- Modify: `litebox_platform_macos_userland/src/lib.rs`
- Reference: `litebox_platform_linux_userland/src/lib.rs`

**Step 1: Copy the Linux lib.rs**

Copy `litebox_platform_linux_userland/src/lib.rs` to `litebox_platform_macos_userland/src/lib.rs`.

**Step 2: Update crate-level attributes**

Change:
```rust
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")
))]
```
To:
```rust
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]
```

Update the doc comment to say "macOS (Apple Silicon)" instead of "userland Linux".

**Step 3: Strip all x86_64 and x86 code**

Remove ALL code gated behind:
- `#[cfg(target_arch = "x86_64")]`
- `#[cfg(target_arch = "x86")]`
- `#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]`

This includes:
- x86_64/x86 `global_asm!` blocks (TLS vars, lines 435-461 and 1101-1122)
- x86_64/x86 `run_thread_arch` (lines 552-853 and similar)
- x86_64/x86 `switch_to_guest` (lines 1055-1168)
- x86_64/x86 `signal_handler_exit_guest` (lines 2547-2636)
- x86_64/x86 `copy_signal_context` (lines 2806-2902)
- x86_64/x86 `set_signal_return` (lines 2919-2954)
- All `#[cfg(target_arch = "x86_64")]` / `#[cfg(target_arch = "x86")]` branches inside shared functions
- x86-specific helpers (`set_guest_fsbase`, `get_guest_fsbase`, `syscall_handler_fast`)
- x86-specific structs (`UserDesc` references if any)

**Step 4: Strip seccomp/systrap code**

Remove:
- `mod syscall_intercept;` declaration
- All references to `syscall_intercept::SYSCALL_ARG_MAGIC` and `syscall_intercept::MMAP_FLAG_MAGIC`
- `#[cfg(feature = "systrap_backend")]` gated fields and code
- `enable_seccomp_based_syscall_interception()` method
- VDSO-related code in `read_maps_and_vdso()` (the systrap_backend VDSO search)

**Step 5: Strip syscalls crate usage (placeholder)**

Replace `use syscalls` with TODO comments. The actual replacement happens in Task 5.

**Step 6: Rename LinuxUserland to MacosUserland**

Global rename: `LinuxUserland` → `MacosUserland` throughout the file.

**Step 7: Remove cfg gates on remaining aarch64 code**

Since this crate is aarch64-only, remove all `#[cfg(target_arch = "aarch64")]` attributes — the code is unconditional now.

**Step 8: Verify**

The file won't compile yet (missing macOS-specific implementations), but the structure should be clean. This is expected — subsequent tasks fill in the gaps.

**Step 9: Commit**

```
feat(macos): fork lib.rs from Linux platform, strip x86/seccomp/Linux-only code
```

---

## Task 3: Replace /proc/self/maps with mach_vm_region_recurse

**Files:**
- Modify: `litebox_platform_macos_userland/src/lib.rs` (the `read_maps_and_vdso` function, ~lines 252-316 in the Linux original)

**Step 1: Add Mach FFI declarations**

At the top of `lib.rs`, add `extern "C"` declarations for:
```rust
extern "C" {
    fn mach_task_self() -> u32;  // mach_port_t
    fn mach_vm_region_recurse(
        target_task: u32,
        address: *mut u64,
        size: *mut u64,
        nesting_depth: *mut u32,
        info: *mut vm_region_submap_info_64,
        info_count: *mut u32,
    ) -> i32;  // kern_return_t
}
```

And the `vm_region_submap_info_64` struct (or use the `mach2` crate if available — check first).

**Step 2: Rewrite `read_maps_and_vdso`**

Replace the `/proc/self/maps` parsing with a `mach_vm_region_recurse` loop:
```rust
fn read_maps() -> alloc::vec::Vec<core::ops::Range<usize>> {
    let mut reserved_pages = alloc::vec::Vec::new();
    let mut address: u64 = 0;
    loop {
        let mut size: u64 = 0;
        let mut depth: u32 = 0;
        let mut info: vm_region_submap_info_64 = unsafe { core::mem::zeroed() };
        let mut count = VM_REGION_SUBMAP_INFO_COUNT_64;
        let kr = unsafe {
            mach_vm_region_recurse(
                mach_task_self(),
                &mut address,
                &mut size,
                &mut depth,
                &mut info,
                &mut count,
            )
        };
        if kr != 0 { break; } // KERN_SUCCESS = 0
        reserved_pages.push(address as usize..(address + size) as usize);
        address += size;
    }
    reserved_pages
}
```

No VDSO search (macOS has no VDSO). The `vdso_address` field becomes always `None`.

**Step 3: Update constructor**

Change `let (reserved_pages, vdso_address) = Self::read_maps_and_vdso();` to `let reserved_pages = Self::read_maps();` and hardcode `vdso_address: None`.

**Step 4: Commit**

```
feat(macos): replace /proc/self/maps with mach_vm_region_recurse for memory map discovery
```

---

## Task 4: Replace raw syscall wrappers with libc calls

**Files:**
- Modify: `litebox_platform_macos_userland/src/lib.rs`

**Step 1: Replace all `syscalls::syscall*()` calls**

Every `syscalls::syscall*(Sysno::foo, ...)` becomes `libc::foo(...)`. Key replacements:

| Linux (raw syscall) | macOS (libc) |
|---|---|
| `syscalls::syscall4(Sysno::openat, ...)` | `libc::openat(...)` |
| `syscalls::syscall3(Sysno::read, ...)` | `libc::read(...)` |
| `syscalls::syscall3(Sysno::write, ...)` | `libc::write(...)` |
| `syscalls::syscall1(Sysno::close, ...)` | `libc::close(...)` |
| `syscalls::syscall3(Sysno::ioctl, ...)` | `libc::ioctl(...)` |
| `syscalls::syscall6(Sysno::mmap, ...)` | `libc::mmap(...)` |
| `syscalls::syscall2(Sysno::munmap, ...)` | `libc::munmap(...)` |
| `syscalls::syscall3(Sysno::mprotect, ...)` | `libc::mprotect(...)` |
| `syscalls::syscall*(Sysno::futex, ...)` | Replaced in Task 6 |
| `syscalls::syscall*(Sysno::gettid, ...)` | `libc::pthread_self()` or `libc::getpid()` |
| `syscalls::syscall0(Sysno::getppid, ...)` | `libc::getppid()` |

**Step 2: Remove the `syscalls` import**

Remove `use syscalls` and any `syscalls::Errno` usage. Replace with `std::io::Error::last_os_error()` for error handling.

**Step 3: Remove SYSCALL_ARG_MAGIC / MMAP_FLAG_MAGIC**

These are seccomp-related and not needed on macOS. Remove all `| syscall_intercept::MMAP_FLAG_MAGIC` from mmap flags and all `SYSCALL_ARG_MAGIC` arguments.

**Step 4: Commit**

```
feat(macos): replace raw Linux syscall wrappers with libc calls
```

---

## Task 5: Replace futex mutex with os_unfair_lock + __ulock

**Files:**
- Modify: `litebox_platform_macos_userland/src/lib.rs` (the `RawMutex` struct and impl, ~lines 1332-1413 in the Linux original)

**Step 1: Add FFI declarations**

```rust
extern "C" {
    fn __ulock_wait(operation: u32, addr: *mut libc::c_void, value: u64, timeout_us: u32) -> libc::c_int;
    fn __ulock_wake(operation: u32, addr: *mut libc::c_void, wake_value: u64) -> libc::c_int;
}

const UL_COMPARE_AND_WAIT: u32 = 1;
const ULF_WAKE_ALL: u32 = 0x00000100;
```

**Step 2: Rewrite RawMutex**

The `RawMutex` struct stays the same (wraps `AtomicU32`). Replace `block_or_maybe_timeout`:

```rust
fn block_or_maybe_timeout(
    &self,
    val: u32,
    timeout: Option<Duration>,
) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
    if self.inner.load(Ordering::SeqCst) != val {
        return Err(ImmediatelyWokenUp);
    }
    let timeout_us = timeout
        .map(|d| u32::try_from(d.as_micros()).unwrap_or(u32::MAX))
        .unwrap_or(0); // 0 = infinite for __ulock_wait
    loop {
        let ret = unsafe {
            __ulock_wait(
                UL_COMPARE_AND_WAIT,
                &self.inner as *const AtomicU32 as *mut libc::c_void,
                u64::from(val),
                timeout_us,
            )
        };
        if ret >= 0 {
            return Ok(UnblockedOrTimedOut::Unblocked);
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EAGAIN) => return Err(ImmediatelyWokenUp),
            Some(libc::ETIMEDOUT) => return Ok(UnblockedOrTimedOut::TimedOut),
            Some(libc::EINTR) => continue,
            _ => panic!("Unexpected error for __ulock_wait: {err}"),
        }
    }
}
```

Replace `wake_many` to use `__ulock_wake`:

```rust
fn wake_many(&self, n: usize) -> usize {
    assert!(n > 0);
    let flags = if n > 1 { ULF_WAKE_ALL } else { 0 };
    let ret = unsafe {
        __ulock_wake(
            UL_COMPARE_AND_WAIT | flags,
            &self.inner as *const AtomicU32 as *mut libc::c_void,
            0,
        )
    };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOENT) {
            return 0; // no waiters
        }
        panic!("Unexpected error for __ulock_wake: {err}");
    }
    ret as usize
}
```

**Step 3: Remove futex helper functions**

Remove `futex_timeout`, `futex_val2`, `FutexOperation`, and any other futex-specific code.

**Step 4: Commit**

```
feat(macos): replace futex-based mutex with __ulock_wait/__ulock_wake
```

---

## Task 6: Adapt signal handling for Darwin ucontext_t + SIGUSR1

**Files:**
- Modify: `litebox_platform_macos_userland/src/lib.rs`

This is the largest task. Three functions need Darwin-specific register access, and the interrupt signal changes from RT signal to `SIGUSR1`.

**Step 1: Fix `copy_signal_context`**

Linux aarch64 (`mcontext_t`):
```rust
regs.regs[i] = mctx.regs[i] as usize;
regs.sp = mctx.sp as usize;
regs.pc = mctx.pc as usize;
regs.pstate = mctx.pstate as usize;
```

Darwin aarch64 (`__darwin_mcontext64`):
```rust
fn copy_signal_context(regs: &mut litebox_common_linux::PtRegs, context: &libc::ucontext_t) {
    let mctx = unsafe { &*context.uc_mcontext };
    // __ss.__x[0..29] maps to regs[0..29]
    for i in 0..29 {
        regs.regs[i] = mctx.__ss.__x[i] as usize;
    }
    regs.regs[29] = mctx.__ss.__fp as usize;  // x29 = frame pointer
    regs.regs[30] = mctx.__ss.__lr as usize;  // x30 = link register
    regs.sp = mctx.__ss.__sp as usize;
    regs.pc = mctx.__ss.__pc as usize;
    regs.pstate = mctx.__ss.__cpsr as usize;
}
```

**Step 2: Fix `set_signal_return`**

```rust
fn set_signal_return(
    context: &mut libc::ucontext_t,
    f: unsafe extern "C" fn(),
    p0: isize, p1: isize, p2: isize, p3: isize,
) {
    let mctx = unsafe { &mut *context.uc_mcontext };
    mctx.__ss.__pc = f as usize as u64;
    mctx.__ss.__x[0] = p0 as u64;
    mctx.__ss.__x[1] = p1 as u64;
    mctx.__ss.__x[2] = p2 as u64;
    mctx.__ss.__x[3] = p3 as u64;
}
```

**Step 3: Fix exception_signal_handler**

Change the aarch64 fault address access:
```rust
// Linux: sigctx.fault_address
// macOS:
let mctx = unsafe { &*context.uc_mcontext };
let fault_addr = mctx.__es.__far;  // Fault Address Register
```

**Step 4: Fix interrupt_signal_handler IP access**

```rust
// Linux: context.uc_mcontext.pc as usize
// macOS:
let mctx = unsafe { &*context.uc_mcontext };
let ip = mctx.__ss.__pc as usize;
```

**Step 5: Fix next_signal_handler IP access**

Same pattern — read/write `mctx.__ss.__pc` instead of `context.uc_mcontext.pc`.

**Step 6: Replace RT signal with SIGUSR1**

In `register_exception_handlers`:
```rust
// Linux: scans SIGRTMIN..SIGRTMAX for available RT signal
// macOS: use SIGUSR1 directly
let interrupt_signal = {
    let sig = libc::SIGUSR1;
    let mut sa: libc::sigaction = unsafe { core::mem::zeroed() };
    sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
    sa.sa_sigaction = interrupt_signal_handler as *const () as usize;
    let mut old_sa = unsafe { core::mem::zeroed() };
    sigaction(sig, Some(&sa), &mut old_sa);
    INTERRUPT_SIGNAL_NUMBER.store(sig, Ordering::Relaxed);
    sig
};
```

**Step 7: Fix signal_handler_exit_guest (aarch64)**

The alt-stack trick is mostly the same. The one change: replace the raw `SVC #0` sigaltstack syscall (Linux `__NR_sigaltstack = 132`) with `libc::sigaltstack()`:

```rust
// Linux: raw SVC #0 with x8=132 (inline asm)
// macOS: use libc wrapper (safe because we only need ss_flags check,
// and the libc wrapper doesn't touch TPIDR_EL0 in a way that matters
// since we immediately recover host TLS from the alt-stack)
let mut current_ss: libc::stack_t = core::mem::zeroed();
let ret = libc::sigaltstack(std::ptr::null(), &mut current_ss);
if ret != 0 || current_ss.ss_flags & libc::SS_ONSTACK == 0 {
    return None;
}
```

**CAUTION:** The Linux version uses a raw syscall specifically to avoid touching TLS/errno while TPIDR_EL0 may still point to guest TLS. On macOS, `libc::sigaltstack()` may internally use TPIDRRO_EL0 (not TPIDR_EL0) for TLS, which is safe since we don't touch TPIDRRO_EL0. However, if the libc wrapper uses TPIDR_EL0, we would need to use a raw syscall on macOS too (macOS AArch64 syscall convention: number in X16, `SVC #0x80`). Investigate and adapt as needed.

If raw syscall is needed on macOS:
```asm
"mov x16, #0x2000000 + 53",  // SYS_sigaltstack = 53 on macOS (0x2000035)
"mov x0, #0",
"mov x1, {oss}",
"svc #0x80",
"mov {ret}, x0",
```

**Step 8: Commit**

```
feat(macos): adapt signal handling for Darwin ucontext_t layout and SIGUSR1 interrupt
```

---

## Task 7: Adapt context switch asm for macOS TLS model

**Files:**
- Modify: `litebox_platform_macos_userland/src/lib.rs`

This task adapts the `global_asm!` TLS variable declarations and TLS offset helpers for Mach-O.

**Step 1: Update TLS variable declarations**

Linux ELF:
```asm
.section .tbss,"awT",@nobits
.align 8
scratch: .quad 0
host_sp: .quad 0
...
```

macOS Mach-O — **this is the tricky part**. Mach-O does not support `.tbss` or `@tpoff` relocations in the same way as ELF. macOS uses a "TLV" (Thread Local Variable) model with `__thread_vars` and `__thread_bss` sections. The inline asm TLS access pattern (`mrs tpidr_el0` + offset) does NOT work on macOS because:

1. macOS uses `TPIDRRO_EL0` for its own TLS, not `TPIDR_EL0`
2. The `#:tprel_g1:symbol` / `#:tprel_g0_nc:symbol` relocations are ELF-specific

**Alternative approach: use explicit thread-local storage via pthread keys or thread_local! macro.**

Since the conservative approach uses the TLS table (same as Linux), and the TLS table already handles the TPIDR_EL0 mapping, we can use a different mechanism for the host-side TLS variables (`in_guest`, `interrupt`, `host_sp`, `guest_context_top`, `guest_tpidr`):

**Option A (recommended): Use `#[thread_local]` static variables instead of asm-declared .tbss**

```rust
#[thread_local]
static mut HOST_SP: usize = 0;
#[thread_local]
static mut GUEST_CONTEXT_TOP: usize = 0;
#[thread_local]
static mut GUEST_TPIDR: usize = 0;
#[thread_local]
static mut IN_GUEST: u8 = 0;
#[no_mangle]
#[thread_local]
static mut INTERRUPT: u8 = 0;
```

Then the inline asm accesses these via `adrp` + `add` + `ldr`/`str` (the compiler handles TLV descriptor calls for `#[thread_local]` on macOS). However, naked functions cannot use `#[thread_local]` statics directly in asm — the compiler emits calls to `_tlv_get_addr` which is not usable from naked asm.

**Option B: Store host-side variables on the alt-stack or in a per-thread struct**

Since the alt-stack already stores host TLS at a known offset, we could extend it to store `host_sp`, `guest_context_top`, etc. at fixed offsets from the aligned base. The signal handler already recovers the base via SP masking.

For the context switch asm (`switch_to_guest`, `run_thread_arch`), we need `host_sp` and `guest_context_top` to be accessible via TPIDR_EL0 + offset (since host TPIDR_EL0 is set at that point). The current approach works if:
- We set TPIDR_EL0 to point to a per-thread control block that we allocate ourselves
- The control block contains `host_sp`, `guest_context_top`, `in_guest`, `interrupt`, `guest_tpidr` at fixed offsets

**Option C (simplest): Use TPIDR_EL0 as our own TLS register**

Since macOS likely doesn't use TPIDR_EL0 (it uses TPIDRRO_EL0), we can claim TPIDR_EL0 for litebox's own use — point it to a per-thread struct. This is essentially what the TLS table approach already requires. The asm code would use `mrs x18, tpidr_el0` followed by fixed-offset loads/stores, identical to the Linux code's `.tbss` access pattern but with manually managed offsets instead of linker-computed `@tpoff`.

**Recommended: Option C**

Define a per-thread struct:
```rust
#[repr(C)]
struct ThreadControlBlock {
    scratch: usize,     // offset 0
    host_sp: usize,     // offset 8
    guest_context_top: usize, // offset 16
    guest_tpidr: usize, // offset 24
    in_guest: u8,       // offset 32
    interrupt: u8,      // offset 33
}
```

Allocate this per-thread (e.g., `Box::leak(Box::new(ThreadControlBlock::default()))`) and set TPIDR_EL0 to point to it before entering the guest. On return, restore the original TPIDR_EL0.

The asm then uses hardcoded offsets:
```asm
mrs x18, tpidr_el0
str x9, [x18, #8]   // store host_sp at offset 8
```

This replaces the Linux `movz/movk #:tprel_g1:host_sp / #:tprel_g0_nc:host_sp` pattern.

**Step 2: Define the ThreadControlBlock struct**

```rust
#[repr(C)]
pub(crate) struct ThreadControlBlock {
    pub scratch: usize,
    pub host_sp: usize,
    pub guest_context_top: usize,
    pub guest_tpidr: usize,
    pub in_guest: u8,
    pub interrupt: u8,
    _pad: [u8; 6], // align to 8 bytes
}
```

**Step 3: Update run_thread_arch asm**

Replace all `movz/movk #:tprel_g1:foo / #:tprel_g0_nc:foo` patterns with direct offsets from the control block base in TPIDR_EL0.

Example — saving host_sp:
```asm
// Linux:
"mrs x8, tpidr_el0"
"movz x10, #:tprel_g1:host_sp"
"movk x10, #:tprel_g0_nc:host_sp"
"str x9, [x8, x10]"

// macOS:
"mrs x8, tpidr_el0"
"str x9, [x8, #8]"   // TCB.host_sp at offset 8
```

**Step 4: Update switch_to_guest asm**

Same pattern — replace `tprel` relocations with fixed offsets.

**Step 5: Update TLS offset helpers**

Replace the `tls_offset_*()` functions that use `movz/movk #:tprel` asm with simple const functions:
```rust
const fn tcb_offset_in_guest() -> isize { 32 }
const fn tcb_offset_interrupt() -> isize { 33 }
const fn tcb_offset_guest_context_top() -> isize { 16 }
const fn tcb_offset_guest_tpidr() -> isize { 24 }
const fn tcb_offset_host_sp() -> isize { 8 }
```

**Step 6: Update signal_handler_exit_guest**

Replace `(host_tls as *mut u8).byte_offset(tls_offset_in_guest())` with `(host_tls as *mut u8).byte_offset(tcb_offset_in_guest())`. The host_tls recovery from the alt-stack remains the same.

**Step 7: Allocate TCB per thread and manage TPIDR_EL0**

In `with_signal_alt_stack` or `run_thread_inner`, allocate a `ThreadControlBlock`, store it at a known location, and set TPIDR_EL0 to point to it before entering the guest. Store the original TPIDR_EL0 value so it can be restored.

The alt-stack host_tls slot stores the TCB pointer (same as Linux stores the TPIDR_EL0 value).

**Step 8: Remove the global_asm! .tbss block**

The `.tbss` variables are replaced by the `ThreadControlBlock` struct.

**Step 9: Commit**

```
feat(macos): replace ELF .tbss TLS with explicit ThreadControlBlock for macOS TLS model
```

---

## Task 8: Replace mremap with mmap + copy + munmap

**Files:**
- Modify: `litebox_platform_macos_userland/src/lib.rs` (`remap_pages` method, ~line 1860 in Linux original)

**Step 1: Implement remap_pages without mremap**

```rust
unsafe fn remap_pages(
    &self,
    old_range: core::ops::Range<usize>,
    new_range: core::ops::Range<usize>,
    permissions: MemoryRegionPermissions,
) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::RemapError> {
    // Allocate new region
    let new_ptr = unsafe {
        libc::mmap(
            new_range.start as *mut libc::c_void,
            new_range.len(),
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
            -1,
            0,
        )
    };
    assert!(new_ptr != libc::MAP_FAILED, "mmap failed for remap");

    // Copy data (only copy up to the smaller of old and new sizes)
    let copy_len = old_range.len().min(new_range.len());
    unsafe {
        core::ptr::copy_nonoverlapping(
            old_range.start as *const u8,
            new_ptr as *mut u8,
            copy_len,
        );
    }

    // Set final permissions
    if permissions != MemoryRegionPermissions::READ_WRITE {
        unsafe {
            libc::mprotect(
                new_ptr,
                new_range.len(),
                prot_flags(permissions).bits() as i32,
            );
        }
    }

    // Unmap old region
    unsafe {
        libc::munmap(old_range.start as *mut libc::c_void, old_range.len());
    }

    Ok(UserMutPtr::from_usize(new_ptr as usize))
}
```

**Step 2: Commit**

```
feat(macos): replace mremap with mmap+copy+munmap for page remapping
```

---

## Task 9: Stub TUN networking

**Files:**
- Modify: `litebox_platform_macos_userland/src/lib.rs`

**Step 1: Remove TUN device opening from constructor**

Replace the entire TUN setup block in `MacosUserland::new()` with:
```rust
let tun_socket_fd = std::sync::RwLock::new(None);
if tun_device_name.is_some() {
    // TODO: implement macOS utun support
    unimplemented!("macOS TUN (utun) networking not yet implemented");
}
```

**Step 2: Stub IP interface methods**

The `send_ip_packet` and `receive_ip_packet` already fall through to `unimplemented!()` when no TUN is opened. Keep this behavior.

**Step 3: Remove TUN-related structs**

Remove `Ifreq`, `Ifru`, `IFF_TUN`, `IFF_NO_PI` and the `iow!` macro usage.

**Step 4: Stub `wait_on_tun`**

Return `ImmediatelyWokenUp` (same as when TUN is disabled on Linux).

**Step 5: Commit**

```
feat(macos): stub TUN networking (utun support deferred)
```

---

## Task 10: Remaining provider adaptations and cleanup

**Files:**
- Modify: `litebox_platform_macos_userland/src/lib.rs`

**Step 1: SystemInfoProvider**

`get_vdso_address()` returns 0 (no VDSO on macOS).

**Step 2: Page management — switch to libc calls**

Replace remaining raw syscall mmap/munmap/mprotect in `allocate_pages`, `deallocate_pages`, `update_permissions`, and `try_allocate_cow_pages` with `libc::mmap`, `libc::munmap`, `libc::mprotect`.

Remove `Sysno::mmap2` references (x86-only, already removed in Task 2).

**Step 3: MAP_FIXED_NOREPLACE**

`MAP_FIXED_NOREPLACE` may not be available on all macOS versions. Check `libc` crate support. If not available, use `MAP_FIXED` with a prior `mmap` probe, or define the constant manually if the kernel supports it (macOS 10.14+).

**Step 4: ThreadProvider**

Verify `pthread_self()` and `pthread_kill()` work the same on macOS (they do — POSIX). No changes needed.

**Step 5: Commit**

```
feat(macos): finalize remaining provider implementations for macOS
```

---

## Task 11: Clippy + fmt + cross-check

**Files:**
- Modify: `litebox_platform_macos_userland/src/lib.rs` (any clippy fixes)

**Step 1: Run cargo fmt**

```bash
cargo fmt -p litebox_platform_macos_userland
```

**Step 2: Run clippy**

On macOS (or with cross-compilation target):
```bash
RUSTFLAGS="-Dwarnings" cargo clippy -p litebox_platform_macos_userland --all-targets
```

Note: This can only run natively on macOS due to the `#![cfg(all(target_os = "macos", ...))]` gate. On Linux, the crate is empty and will pass trivially.

**Step 3: Verify Linux workspace still builds**

```bash
RUSTFLAGS="-Dwarnings" cargo clippy --all-targets --all-features --workspace \
    --exclude litebox_runner_lvbs --exclude litebox_runner_snp \
    --exclude litebox_runner_linux_on_windows_userland \
    --exclude litebox_runner_optee_on_linux_userland \
    --exclude litebox_platform_lvbs \
    --exclude litebox_platform_windows_userland
```

The macOS crate should be a no-op on Linux (cfg-gated out).

**Step 4: Commit**

```
fix(macos): clippy and formatting fixes
```

---

## Task 12: Runner crate (optional, deferred)

Create `litebox_runner_macos_userland/` — a minimal binary that wires together the macOS platform + multiplex + shim. This follows the same pattern as `litebox_runner_linux_userland/` but is deferred until the platform crate is tested on actual macOS hardware.

---

## Implementation order and dependencies

```
Task 1 (scaffold) ──────────────────────┐
                                         │
Task 2 (fork + strip) ──────────────────┤
                                         │
    ┌────────────────────────────────────┤
    │         │         │        │       │
Task 3    Task 4    Task 5   Task 6   Task 7
(mach_vm)  (libc)   (mutex)  (signals) (TLS asm)
    │         │         │        │       │
    └────────┴─────────┴────────┴───────┘
                                         │
Task 8 (mremap) ────────────────────────┤
Task 9 (TUN stub) ─────────────────────┤
Task 10 (cleanup) ─────────────────────┤
                                         │
Task 11 (clippy + fmt) ────────────────┘
```

Tasks 3-7 are independent of each other and can be done in any order after Task 2. Tasks 8-10 are also independent. Task 11 is the final pass.
