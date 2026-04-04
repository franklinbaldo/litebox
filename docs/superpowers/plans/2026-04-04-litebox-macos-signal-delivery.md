# macOS Signal Delivery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement macOS-native signal delivery (sigaction, sigprocmask, signal frame construction, sigreturn) so guest Mach-O programs can register SIGSEGV handlers, receive signals from hardware exceptions, modify ucontext, and resume execution.

**Architecture:** XNU-faithful signal frame layout with macOS ABI structs (4-byte sigset_t, pointer-based uc_mcontext, 816-byte mcontext64). Signal handlers are registered via `sigaction(46)`, the `exception()` entrypoint looks up handlers and pushes an XNU signal frame on the guest stack, `_sigtramp` (from shared cache) calls the handler then `sigreturn(184)` restores context. The platform layer passes Linux signal numbers in `ExceptionInfo.esr`; the shim reverse-maps to macOS signal numbers.

**Tech Stack:** Rust (`#![no_std]`), `litebox::sync::Mutex<Platform, T>`, `core::sync::atomic`, `ConstPtr`/`MutPtr` for guest memory access. C test program compiled with `clang -arch arm64`.

---

### Task 1: Add `SIGRETURN` syscall number and `Sigreturn` variant

**Files:**
- Modify: `litebox_common_macos/src/syscall.rs:58` (add constant after `BSDTHREAD_CTL`)
- Modify: `litebox_common_macos/src/syscall.rs:271` (add enum variant before `Unknown`)
- Modify: `litebox_common_macos/src/syscall.rs:453-458` (add match arm before `BSDTHREAD_CTL`)

- [ ] **Step 1: Add SIGRETURN constant to the `nr` module**

In `litebox_common_macos/src/syscall.rs`, after line 58 (`pub const BSDTHREAD_CTL: usize = 478;`), add:

```rust
    pub const SIGRETURN: usize = 184;
```

- [ ] **Step 2: Add `Sigreturn` variant to `MacosSyscallRequest`**

In `litebox_common_macos/src/syscall.rs`, before the `Unknown { number: usize }` variant (line 268-270), add:

```rust
    /// `sigreturn(uctx, infostyle, token)` — restore context after signal handler.
    Sigreturn {
        uctx: usize,
        infostyle: i32,
    },
```

- [ ] **Step 3: Add decoding match arm in `try_from_raw`**

In `litebox_common_macos/src/syscall.rs`, in the `match nr_raw` block, before the `nr::BSDTHREAD_CTL` arm (line 453), add:

```rust
            nr::SIGRETURN => MacosSyscallRequest::Sigreturn {
                uctx: a0,
                infostyle: a1 as i32,
            },
```

- [ ] **Step 4: Verify it compiles**

Run: `cargo build -p litebox_common_macos`
Expected: successful compilation, no errors.

- [ ] **Step 5: Commit**

```bash
git add litebox_common_macos/src/syscall.rs
git commit -m "feat(macos): add SIGRETURN(184) syscall number and Sigreturn variant"
```

---

### Task 2: Add signal data structures to `Process` and `Task`

**Files:**
- Modify: `litebox_shim_macos/src/lib.rs:19` (add `Ordering` import if not present — already imported)
- Modify: `litebox_shim_macos/src/lib.rs:89-110` (add fields to `Process`)
- Modify: `litebox_shim_macos/src/lib.rs:112-126` (update `Process::new()`)
- Modify: `litebox_shim_macos/src/lib.rs:782-796` (add field to `Task`)
- Modify: `litebox_shim_macos/src/lib.rs:278-286` (add field to main task construction)
- Modify: `litebox_shim_macos/src/lib.rs:384-400` (add field to child task construction)

- [ ] **Step 1: Add `SignalHandler` struct and `signal_handlers` field to `Process`**

In `litebox_shim_macos/src/lib.rs`, before the `Process` struct (before line 89), add the `SignalHandler` struct:

```rust
/// Per-signal handler registration (matches macOS kernel-facing struct __sigaction layout).
#[derive(Clone, Copy)]
struct SignalHandler {
    /// Signal handler address, or SIG_DFL(0)/SIG_IGN(1).
    handler: u64,
    /// Address of `_sigtramp` from libsystem_platform (passed via sa_tramp).
    tramp: u64,
    /// Signal mask to apply during handler execution (macOS 32-bit sigset_t).
    mask: u32,
    /// SA_* flags (SA_SIGINFO, SA_NODEFER, etc.).
    flags: u32,
}

impl Default for SignalHandler {
    fn default() -> Self {
        Self {
            handler: 0, // SIG_DFL
            tramp: 0,
            mask: 0,
            flags: 0,
        }
    }
}
```

Then add the `signal_handlers` field to the `Process` struct, after `next_mach_port` (line 109):

```rust
    /// Per-signal handler table. Indexed by signal number (1-31; index 0 unused).
    signal_handlers: litebox::sync::Mutex<Platform, [SignalHandler; 32]>,
```

- [ ] **Step 2: Initialize `signal_handlers` in `Process::new()`**

In `Process::new()` (line 114-125), add after `next_mach_port: AtomicU32::new(0x0403),`:

```rust
            signal_handlers: litebox::sync::Mutex::new([SignalHandler::default(); 32]),
```

- [ ] **Step 3: Add `blocked_signals` field to `Task`**

In the `Task` struct (line 782-796), after `init_state` (line 795):

```rust
    /// Per-thread blocked signal mask (macOS 32-bit sigset_t).
    blocked_signals: AtomicU32,
```

- [ ] **Step 4: Add `blocked_signals` initialization to main task construction**

In `load_program` (line 278-287), in the `Task` construction, add after `init_state`:

```rust
                blocked_signals: AtomicU32::new(0),
```

- [ ] **Step 5: Add `blocked_signals` initialization to child task construction**

In `sys_bsdthread_create` (line 384-400 in stubs.rs), in the child `Task` construction, add after `init_state`:

```rust
            blocked_signals: core::sync::atomic::AtomicU32::new(0),
```

- [ ] **Step 6: Verify it compiles**

Run: `cargo build -p litebox_shim_macos`
Expected: successful compilation. There may be warnings about unused fields — that's fine, they'll be used in later tasks.

- [ ] **Step 7: Commit**

```bash
git add litebox_shim_macos/src/lib.rs litebox_shim_macos/src/syscalls/stubs.rs
git commit -m "feat(macos): add SignalHandler struct and signal state to Process/Task"
```

---

### Task 3: Create `signal.rs` module with signal frame structs and helpers

**Files:**
- Create: `litebox_shim_macos/src/syscalls/signal.rs`
- Modify: `litebox_shim_macos/src/syscalls/mod.rs:9` (add `mod signal;`)

- [ ] **Step 1: Add the `signal` module declaration**

In `litebox_shim_macos/src/syscalls/mod.rs`, after line 9 (`pub(crate) mod stubs;`), add:

```rust
pub(crate) mod signal;
```

- [ ] **Step 2: Create `signal.rs` with constants and signal number mapping**

Create `litebox_shim_macos/src/syscalls/signal.rs`:

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! macOS signal handling: sigaction, sigprocmask, signal delivery, and sigreturn.

use core::sync::atomic::Ordering;
use litebox::platform::RawConstPointer as _;
use litebox::platform::RawMutPointer as _;
use litebox_common_macos::errno::Errno;
use litebox_common_macos::PtRegs;

use crate::{ConstPtr, MutPtr, ShimFS, Task};

// macOS signal constants.
const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;
const _SIGKILL: i32 = 9;
const _SIGSTOP: i32 = 17;

// SA_* flag constants.
const SA_SIGINFO: u32 = 0x0040;
const SA_NODEFER: u32 = 0x0010;

// sigprocmask `how` constants.
const SIG_BLOCK: i32 = 1;
const SIG_UNBLOCK: i32 = 2;
const SIG_SETMASK: i32 = 3;

// Signals that cannot be caught or blocked.
const UNCATCHABLE_MASK: u32 = (1 << (9 - 1)) | (1 << (17 - 1)); // SIGKILL | SIGSTOP

// UC_FLAVOR for aarch64 (used by _sigtramp and sigreturn).
const UC_FLAVOR: u64 = 30;

// Signal frame component sizes (bytes).
const SIGINFO_SIZE: usize = 104;
const UCONTEXT_SIZE: usize = 56;
const MCONTEXT_SIZE: usize = 816;
const REDZONE_SIZE: usize = 128;

// Offsets within ucontext_t (56 bytes).
const UCTX_ONSTACK: usize = 0;
const UCTX_SIGMASK: usize = 4;
// uc_stack at offset 8, 24 bytes (ss_sp, ss_size, ss_flags, pad)
const UCTX_LINK: usize = 32;
const UCTX_MCSIZE: usize = 40;
const UCTX_MCONTEXT: usize = 48;

// Offsets within __darwin_mcontext64 (816 bytes).
// __es: exception state at offset 0, 16 bytes.
const MCTX_ES_FAR: usize = 0;
const MCTX_ES_ESR: usize = 8;
// __ss: thread state at offset 16, 272 bytes.
const MCTX_SS_BASE: usize = 16;
// Within __ss: x[0..29] at offset 0, fp at 232, lr at 240, sp at 248, pc at 256, cpsr at 264.
const SS_X_BASE: usize = 0;    // x[0..29], 8 bytes each
const SS_FP: usize = 232;      // x29
const SS_LR: usize = 240;      // x30
const SS_SP: usize = 248;
const SS_PC: usize = 256;
const SS_CPSR: usize = 264;
// __ns: NEON state at offset 288, 528 bytes — zeroed (not saved).

// Offsets within siginfo_t (104 bytes).
const SI_SIGNO: usize = 0;
const SI_ERRNO: usize = 4;
const SI_CODE: usize = 8;
const SI_ADDR: usize = 24;

// Signal codes.
const SEGV_MAPERR: i32 = 1;

/// Map a Linux signal number (from the platform's ExceptionInfo.esr) to a macOS signal number.
///
/// Most signals have the same number on both platforms. The notable
/// exception is SIGBUS (Linux 7 → macOS 10).
pub(crate) fn linux_to_macos_signal(linux_sig: i32) -> i32 {
    match linux_sig {
        7 => 10,  // Linux SIGBUS=7 → macOS SIGBUS=10
        _ => linux_sig, // SIGILL(4), SIGTRAP(5), SIGFPE(8), SIGSEGV(11) are the same
    }
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo build -p litebox_shim_macos`
Expected: successful compilation (warnings about unused constants are fine).

- [ ] **Step 4: Commit**

```bash
git add litebox_shim_macos/src/syscalls/signal.rs litebox_shim_macos/src/syscalls/mod.rs
git commit -m "feat(macos): add signal.rs module with constants and signal number mapping"
```

---

### Task 4: Implement `sys_sigaction`

**Files:**
- Modify: `litebox_shim_macos/src/syscalls/signal.rs` (append implementation)
- Modify: `litebox_shim_macos/src/syscalls/stubs.rs:17-27` (remove old stub)

- [ ] **Step 1: Add `sys_sigaction` to `signal.rs`**

Append to `litebox_shim_macos/src/syscalls/signal.rs`:

```rust
impl<FS: ShimFS> Task<FS> {
    /// Handle `sigaction()` (BSD syscall 46).
    ///
    /// Reads the kernel-facing `struct __sigaction` (24 bytes) from `new_act`
    /// and writes the user-facing `struct sigaction` (16 bytes) to `old_act`.
    pub(crate) fn sys_sigaction(
        &self,
        signum: i32,
        new_act: usize,
        old_act: usize,
    ) -> Result<usize, Errno> {
        if signum < 1 || signum > 31 {
            return Err(Errno::EINVAL);
        }
        // SIGKILL and SIGSTOP cannot have their handlers changed.
        if signum == _SIGKILL || signum == _SIGSTOP {
            return Err(Errno::EINVAL);
        }

        let mut handlers = self.process.signal_handlers.lock();
        let idx = signum as usize;

        // Write old handler to user space (struct sigaction, 16 bytes):
        //   [0..8]  sa_handler/sa_sigaction
        //   [8..12] sa_mask
        //   [12..16] sa_flags
        if old_act != 0 {
            let old = &handlers[idx];
            let ptr: MutPtr<u8> = MutPtr::from_usize(old_act);
            let handler_bytes = old.handler.to_le_bytes();
            ptr.copy_from_slice(0, &handler_bytes).ok_or(Errno::EFAULT)?;
            let mask_bytes = old.mask.to_le_bytes();
            ptr.copy_from_slice(8, &mask_bytes).ok_or(Errno::EFAULT)?;
            let flags_bytes = old.flags.to_le_bytes();
            ptr.copy_from_slice(12, &flags_bytes).ok_or(Errno::EFAULT)?;
        }

        // Read new handler from user space (struct __sigaction, 24 bytes):
        //   [0..8]   sa_handler/sa_sigaction
        //   [8..16]  sa_tramp
        //   [16..20] sa_mask
        //   [20..24] sa_flags
        if new_act != 0 {
            let ptr: ConstPtr<u8> = ConstPtr::from_usize(new_act);
            let mut buf = [0u8; 24];
            for i in 0..24 {
                buf[i] = ptr.read_at_offset(i as isize).ok_or(Errno::EFAULT)?;
            }
            handlers[idx] = crate::SignalHandler {
                handler: u64::from_le_bytes(buf[0..8].try_into().unwrap()),
                tramp: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
                mask: u32::from_le_bytes(buf[16..20].try_into().unwrap()),
                flags: u32::from_le_bytes(buf[20..24].try_into().unwrap()),
            };
        }

        Ok(0)
    }
}
```

- [ ] **Step 2: Remove `sys_sigaction` stub from `stubs.rs`**

In `litebox_shim_macos/src/syscalls/stubs.rs`, remove lines 17-27 (the `sys_sigaction` stub method). The `impl<FS: ShimFS> Task<FS>` block in stubs.rs starts at line 17; remove only the `sys_sigaction` method body, keeping the `impl` block for the remaining methods.

Specifically, remove:

```rust
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
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo build -p litebox_shim_macos`
Expected: successful compilation.

- [ ] **Step 4: Commit**

```bash
git add litebox_shim_macos/src/syscalls/signal.rs litebox_shim_macos/src/syscalls/stubs.rs
git commit -m "feat(macos): implement sys_sigaction with kernel-facing struct __sigaction"
```

---

### Task 5: Implement `sys_sigprocmask`

**Files:**
- Modify: `litebox_shim_macos/src/syscalls/signal.rs` (append to existing `impl`)
- Modify: `litebox_shim_macos/src/syscalls/stubs.rs:29-38` (remove old stub)

- [ ] **Step 1: Add `sys_sigprocmask` to the `impl` block in `signal.rs`**

Append inside the `impl<FS: ShimFS> Task<FS>` block in `signal.rs`:

```rust
    /// Handle `sigprocmask()` (BSD syscall 48).
    ///
    /// Reads/writes a 4-byte `sigset_t` (macOS 32-bit signal mask).
    pub(crate) fn sys_sigprocmask(
        &self,
        how: i32,
        set: usize,
        oldset: usize,
    ) -> Result<usize, Errno> {
        let current = self.blocked_signals.load(Ordering::Relaxed);

        // Write old mask to user space.
        if oldset != 0 {
            let ptr: MutPtr<u8> = MutPtr::from_usize(oldset);
            ptr.copy_from_slice(0, &current.to_le_bytes())
                .ok_or(Errno::EFAULT)?;
        }

        // Read and apply new mask.
        if set != 0 {
            let ptr: ConstPtr<u8> = ConstPtr::from_usize(set);
            let mut buf = [0u8; 4];
            for i in 0..4 {
                buf[i] = ptr.read_at_offset(i as isize).ok_or(Errno::EFAULT)?;
            }
            let new_mask = u32::from_le_bytes(buf);

            let updated = match how {
                SIG_BLOCK => current | new_mask,
                SIG_UNBLOCK => current & !new_mask,
                SIG_SETMASK => new_mask,
                _ => return Err(Errno::EINVAL),
            };

            // Never allow blocking SIGKILL or SIGSTOP.
            self.blocked_signals
                .store(updated & !UNCATCHABLE_MASK, Ordering::Relaxed);
        }

        Ok(0)
    }
```

- [ ] **Step 2: Remove `sys_sigprocmask` stub from `stubs.rs`**

In `litebox_shim_macos/src/syscalls/stubs.rs`, remove the `sys_sigprocmask` stub method:

```rust
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
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo build -p litebox_shim_macos`
Expected: successful compilation.

- [ ] **Step 4: Commit**

```bash
git add litebox_shim_macos/src/syscalls/signal.rs litebox_shim_macos/src/syscalls/stubs.rs
git commit -m "feat(macos): implement sys_sigprocmask with 4-byte sigset_t"
```

---

### Task 6: Implement `deliver_signal` (signal frame construction)

**Files:**
- Modify: `litebox_shim_macos/src/syscalls/signal.rs` (append to existing `impl`)

- [ ] **Step 1: Add `deliver_signal` method**

Append inside the `impl<FS: ShimFS> Task<FS>` block in `signal.rs`:

```rust
    /// Build an XNU signal frame on the guest stack and set registers for `_sigtramp`.
    ///
    /// The frame layout (high to low addresses):
    /// ```text
    /// [original SP]
    ///   128-byte red zone
    ///   mcontext64_t (816 bytes)   ← at new_sp + 160
    ///   ucontext_t   (56 bytes)    ← at new_sp + 104
    ///   siginfo_t    (104 bytes)   ← at new_sp + 0
    /// [new SP, 16-byte aligned]
    /// ```
    pub(crate) fn deliver_signal(
        &self,
        ctx: &mut PtRegs,
        signum: i32,
        fault_address: usize,
        handler: &crate::SignalHandler,
    ) {
        // 1. Compute new stack pointer.
        let frame_size = SIGINFO_SIZE + UCONTEXT_SIZE + MCONTEXT_SIZE; // 976
        let new_sp = (ctx.sp - REDZONE_SIZE - frame_size) & !0xF; // 16-byte aligned

        let siginfo_addr = new_sp;
        let ucontext_addr = new_sp + SIGINFO_SIZE;         // new_sp + 104
        let mcontext_addr = new_sp + SIGINFO_SIZE + UCONTEXT_SIZE; // new_sp + 160

        // 2. Build mcontext64 (816 bytes) — zero-fill then populate.
        let mctx_zeros = [0u8; MCONTEXT_SIZE];
        let mctx_ptr: MutPtr<u8> = MutPtr::from_usize(mcontext_addr);
        mctx_ptr.copy_from_slice(0, &mctx_zeros).expect("deliver_signal: write mcontext zeros");

        // __es: exception state (16 bytes)
        let mctx_u64: MutPtr<u64> = MutPtr::from_usize(mcontext_addr);
        mctx_u64.write_at_offset((MCTX_ES_FAR / 8) as isize, fault_address as u64)
            .expect("deliver_signal: write __far");
        // __esr and __exception left as 0.

        // __ss: thread state (272 bytes at offset 16)
        let ss_base = mcontext_addr + MCTX_SS_BASE;
        let ss_u64: MutPtr<u64> = MutPtr::from_usize(ss_base);

        // x0-x28 (29 registers, 8 bytes each)
        for i in 0..29 {
            ss_u64.write_at_offset(((SS_X_BASE / 8) + i) as isize, ctx.regs[i] as u64)
                .expect("deliver_signal: write x reg");
        }
        // fp (x29), lr (x30), sp, pc
        ss_u64.write_at_offset((SS_FP / 8) as isize, ctx.regs[29] as u64)
            .expect("deliver_signal: write fp");
        ss_u64.write_at_offset((SS_LR / 8) as isize, ctx.regs[30] as u64)
            .expect("deliver_signal: write lr");
        ss_u64.write_at_offset((SS_SP / 8) as isize, ctx.sp as u64)
            .expect("deliver_signal: write sp");
        ss_u64.write_at_offset((SS_PC / 8) as isize, ctx.pc as u64)
            .expect("deliver_signal: write pc");
        // cpsr (4 bytes at offset 264 within __ss)
        let cpsr_ptr: MutPtr<u32> = MutPtr::from_usize(ss_base + SS_CPSR);
        #[allow(clippy::cast_possible_truncation)]
        cpsr_ptr.write_at_offset(0, ctx.pstate as u32)
            .expect("deliver_signal: write cpsr");

        // __ns: NEON state (528 bytes at offset 288) — already zeroed.

        // 3. Build ucontext (56 bytes) — zero-fill then populate.
        let uctx_zeros = [0u8; UCONTEXT_SIZE];
        let uctx_ptr: MutPtr<u8> = MutPtr::from_usize(ucontext_addr);
        uctx_ptr.copy_from_slice(0, &uctx_zeros).expect("deliver_signal: write ucontext zeros");

        // uc_onstack (4 bytes at offset 0) = 0 (already zero)
        // uc_sigmask (4 bytes at offset 4) = current blocked mask
        let uctx_mask_ptr: MutPtr<u32> = MutPtr::from_usize(ucontext_addr + UCTX_SIGMASK);
        uctx_mask_ptr.write_at_offset(0, self.blocked_signals.load(Ordering::Relaxed))
            .expect("deliver_signal: write uc_sigmask");
        // uc_stack (24 bytes at offset 8) = zeros (no altstack)
        // uc_link (8 bytes at offset 32) = 0
        // uc_mcsize (8 bytes at offset 40) = 816
        let uctx_u64: MutPtr<u64> = MutPtr::from_usize(ucontext_addr);
        uctx_u64.write_at_offset((UCTX_MCSIZE / 8) as isize, MCONTEXT_SIZE as u64)
            .expect("deliver_signal: write uc_mcsize");
        // uc_mcontext (8 bytes at offset 48) = pointer to mcontext on stack
        uctx_u64.write_at_offset((UCTX_MCONTEXT / 8) as isize, mcontext_addr as u64)
            .expect("deliver_signal: write uc_mcontext");

        // 4. Build siginfo (104 bytes) — zero-fill then populate.
        let si_zeros = [0u8; SIGINFO_SIZE];
        let si_ptr: MutPtr<u8> = MutPtr::from_usize(siginfo_addr);
        si_ptr.copy_from_slice(0, &si_zeros).expect("deliver_signal: write siginfo zeros");

        let si_i32: MutPtr<i32> = MutPtr::from_usize(siginfo_addr);
        si_i32.write_at_offset((SI_SIGNO / 4) as isize, signum)
            .expect("deliver_signal: write si_signo");
        // si_errno = 0 (already zero)
        si_i32.write_at_offset((SI_CODE / 4) as isize, SEGV_MAPERR)
            .expect("deliver_signal: write si_code");
        let si_u64: MutPtr<u64> = MutPtr::from_usize(siginfo_addr);
        si_u64.write_at_offset((SI_ADDR / 8) as isize, fault_address as u64)
            .expect("deliver_signal: write si_addr");

        // 5. Update blocked mask: add handler.mask | signal bit (unless SA_NODEFER).
        let mut block_add = handler.mask;
        if handler.flags & SA_NODEFER == 0 {
            #[allow(clippy::cast_sign_loss)]
            {
                block_add |= 1u32 << (signum as u32 - 1);
            }
        }
        let old_blocked = self.blocked_signals.load(Ordering::Relaxed);
        self.blocked_signals
            .store((old_blocked | block_add) & !UNCATCHABLE_MASK, Ordering::Relaxed);

        // 6. Set registers for _sigtramp entry.
        ctx.regs[0] = handler.handler as usize;  // x0 = catcher (user handler)
        ctx.regs[1] = UC_FLAVOR as usize;        // x1 = infostyle = 30
        ctx.regs[2] = signum as usize;            // x2 = signal number
        ctx.regs[3] = siginfo_addr;               // x3 = &siginfo
        ctx.regs[4] = ucontext_addr;              // x4 = &ucontext
        ctx.regs[5] = 0;                          // x5 = token (ignored)
        ctx.pc = handler.tramp as usize;          // pc = _sigtramp
        ctx.sp = new_sp;                          // sp = bottom of frame
    }
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo build -p litebox_shim_macos`
Expected: successful compilation.

- [ ] **Step 3: Commit**

```bash
git add litebox_shim_macos/src/syscalls/signal.rs
git commit -m "feat(macos): implement deliver_signal with XNU signal frame construction"
```

---

### Task 7: Change `exception()` to look up handler and deliver signal

**Files:**
- Modify: `litebox_shim_macos/src/lib.rs:687-712` (rewrite `exception()` method)

- [ ] **Step 1: Rewrite the `exception()` method**

In `litebox_shim_macos/src/lib.rs`, replace the entire `exception()` method (lines 687-712) with:

```rust
    fn exception(
        &self,
        ctx: &mut Self::ExecutionContext,
        info: &litebox::shim::ExceptionInfo,
    ) -> ContinueOperation {
        // The platform passes the Linux signal number in info.esr.
        // Convert to macOS signal number for the guest.
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        let macos_signum = syscalls::signal::linux_to_macos_signal(info.esr as i32);

        // Look up the handler for this signal.
        let handler = {
            let handlers = self.task.process.signal_handlers.lock();
            handlers[macos_signum as usize]
        };

        match handler.handler {
            0 => {
                // SIG_DFL: terminate (default behavior for SIGSEGV, SIGBUS, etc.)
                log_unsupported!(
                    "EXCEPTION at pc={:#x} sp={:#x} signal={} (SIG_DFL → terminate)",
                    ctx.pc,
                    ctx.sp,
                    macos_signum
                );
                log_unsupported!(
                    "  x0={:#x} x1={:#x} x2={:#x} x3={:#x} x16={:#x} fault_addr={:#x}",
                    ctx.regs[0],
                    ctx.regs[1],
                    ctx.regs[2],
                    ctx.regs[3],
                    ctx.regs[16],
                    info.fault_address
                );
                self.task.process.group_exit.store(true, Ordering::Release);
                self.task.terminated.store(true, Ordering::Release);
                ContinueOperation::Terminate
            }
            1 => {
                // SIG_IGN: ignore and resume.
                log_unsupported!(
                    "EXCEPTION at pc={:#x} signal={} (SIG_IGN → ignore)",
                    ctx.pc,
                    macos_signum
                );
                ContinueOperation::Resume
            }
            _ => {
                // User handler: deliver signal via XNU signal frame.
                self.task.deliver_signal(ctx, macos_signum, info.fault_address, &handler);
                ContinueOperation::Resume
            }
        }
    }
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo build -p litebox_shim_macos`
Expected: successful compilation.

- [ ] **Step 3: Commit**

```bash
git add litebox_shim_macos/src/lib.rs
git commit -m "feat(macos): exception() now looks up signal handlers and delivers signals"
```

---

### Task 8: Implement `sys_sigreturn` and route it in the syscall dispatch

**Files:**
- Modify: `litebox_shim_macos/src/syscalls/signal.rs` (append `sys_sigreturn`)
- Modify: `litebox_shim_macos/src/syscalls/mod.rs:26` (add `Sigreturn` match arm)
- Modify: `litebox_shim_macos/src/lib.rs:857-884` (handle sigreturn specially)

This task requires careful coordination: `sigreturn` restores the full register set including `pstate`, so `set_syscall_return` must NOT be called after it. The approach: handle `Sigreturn` before calling `do_syscall` in `handle_syscall_request`, and return early.

- [ ] **Step 1: Add `sys_sigreturn` to `signal.rs`**

Append inside the `impl<FS: ShimFS> Task<FS>` block in `signal.rs`:

```rust
    /// Handle `sigreturn()` (BSD syscall 184).
    ///
    /// Reads the saved `ucontext_t` and `mcontext64_t` from the guest stack,
    /// restores all general registers, pstate/cpsr, and the signal mask.
    ///
    /// This modifies `ctx` directly and must NOT be followed by `set_syscall_return`.
    pub(crate) fn sys_sigreturn(&self, ctx: &mut PtRegs, uctx_addr: usize) {
        // 1. Read uc_sigmask (4 bytes at offset 4 in ucontext_t).
        let sigmask_ptr: ConstPtr<u32> = ConstPtr::from_usize(uctx_addr + UCTX_SIGMASK);
        let sigmask = sigmask_ptr.read_at_offset(0).expect("sigreturn: read uc_sigmask");
        self.blocked_signals
            .store(sigmask & !UNCATCHABLE_MASK, Ordering::Relaxed);

        // 2. Read uc_mcontext pointer (8 bytes at offset 48 in ucontext_t).
        let mctx_ptr_ptr: ConstPtr<u64> = ConstPtr::from_usize(uctx_addr + UCTX_MCONTEXT);
        let mcontext_addr = mctx_ptr_ptr.read_at_offset(0).expect("sigreturn: read uc_mcontext") as usize;

        // 3. Restore registers from mcontext.__ss (272 bytes at offset 16).
        let ss_addr = mcontext_addr + MCTX_SS_BASE;
        let ss_u64: ConstPtr<u64> = ConstPtr::from_usize(ss_addr);

        // x0-x28
        for i in 0..29 {
            ctx.regs[i] = ss_u64
                .read_at_offset(((SS_X_BASE / 8) + i) as isize)
                .expect("sigreturn: read x reg") as usize;
        }
        // fp (x29)
        ctx.regs[29] = ss_u64
            .read_at_offset((SS_FP / 8) as isize)
            .expect("sigreturn: read fp") as usize;
        // lr (x30)
        ctx.regs[30] = ss_u64
            .read_at_offset((SS_LR / 8) as isize)
            .expect("sigreturn: read lr") as usize;
        // sp
        ctx.sp = ss_u64
            .read_at_offset((SS_SP / 8) as isize)
            .expect("sigreturn: read sp") as usize;
        // pc
        ctx.pc = ss_u64
            .read_at_offset((SS_PC / 8) as isize)
            .expect("sigreturn: read pc") as usize;
        // cpsr → pstate
        let cpsr_ptr: ConstPtr<u32> = ConstPtr::from_usize(ss_addr + SS_CPSR);
        ctx.pstate = cpsr_ptr.read_at_offset(0).expect("sigreturn: read cpsr") as usize;
    }
```

- [ ] **Step 2: Modify `handle_syscall_request` to handle `Sigreturn` specially**

In `litebox_shim_macos/src/lib.rs`, replace the `handle_syscall_request` method (lines 857-885) with:

```rust
    fn handle_syscall_request(&self, ctx: &mut PtRegs) {
        // Debug: trace all syscall numbers
        if cfg!(debug_assertions) {
            let nr = ctx.regs[16];
            if (nr as i64) < 0 {
                let trap = (-(nr as i64)) as usize;
                log_unsupported!(
                    "TRACE: mach_trap({trap}) x0={:#x} x1={:#x} x2={:#x} x3={:#x}",
                    ctx.regs[0],
                    ctx.regs[1],
                    ctx.regs[2],
                    ctx.regs[3]
                );
            } else {
                log_unsupported!(
                    "TRACE: syscall({nr}) x0={:#x} x1={:#x} x2={:#x} x3={:#x} x4={:#x} x5={:#x}",
                    ctx.regs[0],
                    ctx.regs[1],
                    ctx.regs[2],
                    ctx.regs[3],
                    ctx.regs[4],
                    ctx.regs[5]
                );
            }
        }
        let request = litebox_common_macos::syscall::MacosSyscallRequest::try_from_raw(ctx);

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
    }
```

- [ ] **Step 3: Remove the `Sigreturn` arm from `do_syscall` if it was added, or add a dead-code arm**

In `litebox_shim_macos/src/syscalls/mod.rs`, the `do_syscall` match statement does not yet have a `Sigreturn` arm (it will get a compile error for non-exhaustive match after Task 1). Add this arm to `do_syscall` to satisfy exhaustiveness, even though it will never be reached (sigreturn is handled before `do_syscall` is called):

In the `match request` block in `do_syscall`, before the `MacosSyscallRequest::Unknown` arm, add:

```rust
            MacosSyscallRequest::Sigreturn { .. } => {
                unreachable!("Sigreturn is handled in handle_syscall_request before do_syscall")
            }
```

- [ ] **Step 4: Verify it compiles**

Run: `cargo build -p litebox_shim_macos`
Expected: successful compilation.

- [ ] **Step 5: Commit**

```bash
git add litebox_shim_macos/src/syscalls/signal.rs litebox_shim_macos/src/lib.rs litebox_shim_macos/src/syscalls/mod.rs
git commit -m "feat(macos): implement sys_sigreturn and special-case it in syscall dispatch"
```

---

### Task 9: Create `signal.c` test source

**Files:**
- Create: `litebox_runner_macos_on_macos_userland/tests/signal.c`

- [ ] **Step 1: Create the signal.c test program**

Create `litebox_runner_macos_on_macos_userland/tests/signal.c`:

```c
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static void *recover_ip;

void segv_handler(int sig, siginfo_t *info, void *ctx) {
    printf("Caught signal %d (Segmentation fault)\n", sig);
    printf("  Fault address: %p\n", info->si_addr);

    if (info->si_addr != (void *)0xdeadbeef) {
        printf("FAIL: unexpected fault address\n");
        _exit(1);
    }

    ucontext_t *uctx = (ucontext_t *)ctx;
    uctx->uc_mcontext->__ss.__pc = (uint64_t)recover_ip;
}

int main() {
    struct sigaction sa = {0};
    sa.sa_sigaction = segv_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);

    recover_ip = &&after_fault;

    printf("About to trigger SIGSEGV...\n");

    volatile int *p = (volatile int *)0xdeadbeef;
    *p = 42;

after_fault:
    printf("Resumed after skipping faulting instruction.\n");
    printf("Test succeeded; continuing normal execution.\n");
    return 0;
}
```

- [ ] **Step 2: Commit**

```bash
git add litebox_runner_macos_on_macos_userland/tests/signal.c
git commit -m "test: add macOS signal.c test (SIGSEGV handler with ucontext PC modification)"
```

---

### Task 10: Add `test_signal` integration test

**Files:**
- Modify: `litebox_runner_macos_on_macos_userland/tests/loader.rs` (append test function)

- [ ] **Step 1: Add the `test_signal` test function**

Append to the end of `litebox_runner_macos_on_macos_userland/tests/loader.rs`:

```rust

#[test]
#[allow(clippy::cast_precision_loss)]
fn test_signal() {
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

    let bin_path = common::compile_macho_dynamic("./tests/signal.c", "signal");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    let (exit_code, stdout_bytes) = common::run_macho_dynamic(
        &binary_data,
        &["/usr/bin/signal"],
        &cache_result,
        "signal",
    );
    let stdout = String::from_utf8_lossy(&stdout_bytes);
    assert!(
        stdout.contains("Caught signal 11"),
        "Expected 'Caught signal 11' in output, got: {stdout}"
    );
    assert!(
        stdout.contains("Fault address: 0xdeadbeef"),
        "Expected 'Fault address: 0xdeadbeef' in output, got: {stdout}"
    );
    assert!(
        stdout.contains("Test succeeded"),
        "Expected 'Test succeeded' in output, got: {stdout}"
    );
    assert_eq!(exit_code, 0, "process exited with non-zero code");
}
```

- [ ] **Step 2: Run the test**

Run: `cargo test -p litebox_runner_macos_on_macos_userland test_signal -- --nocapture`
Expected: test passes with output showing signal catch and recovery.

- [ ] **Step 3: Run all tests to check for regressions**

Run: `cargo test -p litebox_runner_macos_on_macos_userland -- --nocapture`
Expected: all tests pass.

- [ ] **Step 4: Run clippy and fmt**

Run: `cargo clippy -p litebox_shim_macos -p litebox_common_macos -p litebox_runner_macos_on_macos_userland -- -D warnings && cargo fmt --check -p litebox_shim_macos -p litebox_common_macos -p litebox_runner_macos_on_macos_userland`
Expected: no clippy warnings, no format issues.

- [ ] **Step 5: Commit**

```bash
git add litebox_runner_macos_on_macos_userland/tests/loader.rs
git commit -m "test: add test_signal integration test for macOS SIGSEGV delivery and recovery"
```
