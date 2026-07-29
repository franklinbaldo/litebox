# AArch64 Support for `litebox_platform_linux_userland` — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Run a rewritten static hello-world guest end to end under `litebox_runner_linux_userland` on `aarch64-unknown-linux-gnu`.

**Architecture:** `TPIDR_EL0` permanently holds the host thread pointer; the rewriter virtualizes the guest thread pointer into a runtime-reserved slot at `[TPIDR_EL0 + 16]`. The platform reserves that slot by emitting its control block into `.tdata` (which links ahead of `.tbss`), pins the layout with a startup assertion, and addresses it with literal offsets from the transition assembly. See `docs/plans/2026-07-29-aarch64-linux-userland-design.md` for the full rationale.

**Tech Stack:** Rust 1.94 (edition 2024), `core::arch::{global_asm, asm, naked_asm}`, `syscalls` 0.6, `libc`, `seccompiler` 0.5, `cargo nextest`.

---

## Orientation for the implementer

Read `docs/plans/2026-07-29-aarch64-linux-userland-design.md` first. It is short and it explains *why* each of the odd-looking constraints below exists. In particular do not "clean up" the literal TLS offsets into relocation pairs, and do not "fix" the unrestored `x16` — both are deliberate and documented.

Everything lives in one file: `litebox_platform_linux_userland/src/lib.rs` (2646 lines, no submodules). The x86-64 code you are paralleling:

- `.tbss` block: lines 692–722
- `run_thread_arch`: lines 758–894
- `switch_to_guest`: lines 905–948
- `signal_handler_exit_guest`: lines 2054–2096
- `copy_signal_context`: lines 2100–2150
- `set_signal_return`: lines 2153–2168
- `exception_signal_handler`: lines 2171–2224
- `interrupt_signal_handler`: lines 2318–2431

Build and test commands:

```bash
cargo build -p litebox_platform_linux_userland
cargo nextest run -p litebox_platform_linux_userland
cargo clippy -p litebox_platform_linux_userland --all-targets
```

Two repo-hygiene tests will bite you:

- `dev_tests/src/boilerplate.rs` requires `// Copyright (c) Microsoft Corporation.\n// Licensed under the MIT license.\n\n` at the top of every `.rs` file.
- `dev_tests/src/ratchet.rs` counts lint-debt markers per crate. `litebox_platform_linux_userland/` appears at lines 16, 41 and 78. If you add `#[allow]` / `#[expect]` items you must bump those counters. Prefer not adding them.

Run `cargo nextest run -p dev_tests` before each commit.

---

## Task 1: Unblock the crate gate and prove the TLS layout

This task is the foundation. `guest_tpidr` must land at exactly `TPIDR_EL0 + 16` or nothing else works, so we pin it with a test before writing any assembly.

**Files:**
- Modify: `litebox_platform_linux_userland/src/lib.rs:8` (crate `cfg`)
- Modify: `litebox_platform_linux_userland/src/lib.rs` (add TLS block + assertions near line 692)

**Step 1: Widen the crate gate**

Replace line 8:

```rust
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
```

**Step 2: Add the AArch64 TLS control block**

Add next to the existing x86-64 `global_asm!` block (after line 722). Note `.tdata`, **not** `.tbss` — this is what forces the block to the head of the static TLS area. `.align 4` means 16 bytes on AArch64.

```rust
/// Byte offsets of the AArch64 TLS control block from `TPIDR_EL0`.
///
/// These are hardcoded rather than materialized through `#:tprel_g1:` /
/// `#:tprel_g0_nc:` relocation pairs because `syscall_callback` is entered with
/// only `x16` free and cannot spare the second scratch register a relocation
/// pair needs. [`assert_tls_layout`] verifies them at startup.
#[cfg(target_arch = "aarch64")]
mod tls_offset {
    /// Guest thread pointer. Fixed by the rewriter ABI: must equal
    /// `litebox_syscall_rewriter::arm64::GUEST_TPIDR_OFFSET`.
    pub(super) const GUEST_TPIDR: usize = 16;
    pub(super) const HOST_SP: usize = 24;
    pub(super) const GUEST_CONTEXT_TOP: usize = 32;
    pub(super) const IN_GUEST: usize = 40;
    pub(super) const INTERRUPT: usize = 41;
    pub(super) const PENDING_HOST_SIGNALS: usize = 44;
    pub(super) const WAIT_WAKER_ADDR: usize = 48;
}

// The block is emitted into `.tdata` so the linker places it ahead of every
// `.tbss` object, putting it at the head of the main executable's static TLS
// area and therefore at a known offset from the thread pointer. A `.tbss`
// placement measures at +48 instead of +16 on a stock Rust binary.
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    "
    .section .tdata.litebox_tls, \"awT\", @progbits
    .align 4
.globl guest_tpidr
guest_tpidr:
    .quad 0
host_sp:
    .quad 0
guest_context_top:
    .quad 0
in_guest:
    .byte 0
.globl interrupt
interrupt:
    .byte 0
    .align 2
.globl pending_host_signals
pending_host_signals:
    .long 0
    .align 3
.globl wait_waker_addr
wait_waker_addr:
    .quad 0
    "
);

/// Returns the true thread-pointer-relative offset of a TLS symbol in the
/// control block, as computed by the linker.
#[cfg(target_arch = "aarch64")]
macro_rules! tprel_offset {
    ($var:literal) => {{
        let offset: usize;
        // SAFETY: reads no memory; just materializes a link-time constant.
        unsafe {
            core::arch::asm!(
                concat!("movz {0}, #:tprel_g1:", $var),
                concat!("movk {0}, #:tprel_g0_nc:", $var),
                out(reg) offset,
                options(pure, nomem, nostack, preserves_flags)
            );
        }
        offset
    }};
}

/// Verifies that the linker placed the TLS control block where the transition
/// assembly assumes it is.
///
/// The transition assembly addresses the block with literal offsets, so a shift
/// in TLS link order would silently corrupt either host TLS or the guest thread
/// pointer. Panicking here converts that into an immediate, legible failure.
#[cfg(target_arch = "aarch64")]
fn assert_tls_layout() {
    let checks = [
        ("guest_tpidr", tprel_offset!("guest_tpidr"), tls_offset::GUEST_TPIDR),
        ("host_sp", tprel_offset!("host_sp"), tls_offset::HOST_SP),
        ("guest_context_top", tprel_offset!("guest_context_top"), tls_offset::GUEST_CONTEXT_TOP),
        ("in_guest", tprel_offset!("in_guest"), tls_offset::IN_GUEST),
        ("interrupt", tprel_offset!("interrupt"), tls_offset::INTERRUPT),
        ("pending_host_signals", tprel_offset!("pending_host_signals"), tls_offset::PENDING_HOST_SIGNALS),
        ("wait_waker_addr", tprel_offset!("wait_waker_addr"), tls_offset::WAIT_WAKER_ADDR),
    ];
    for (name, actual, expected) in checks {
        assert_eq!(
            actual, expected,
            "TLS control block moved: `{name}` is at TPIDR_EL0+{actual}, expected +{expected}. \
             Another TLS object was linked ahead of `.tdata.litebox_tls`."
        );
    }
}
```

**Step 3: Add the pinning test**

Add to `mod tests` (around line 2509):

```rust
#[cfg(target_arch = "aarch64")]
#[test]
fn test_tls_layout() {
    super::assert_tls_layout();
}
```

**Step 4: Run it**

```bash
cargo nextest run -p litebox_platform_linux_userland test_tls_layout
```

Expected: PASS. If it fails reporting `guest_tpidr` at an offset other than 16, stop and re-read section 2 of the design doc — do not adjust the constant to match.

**Step 5: Call it from `LinuxUserland::new`**

`LinuxUserland::new` is around line 180 and already has a `std::sync::Once`-guarded `register_exception_handlers()` call. Add `#[cfg(target_arch = "aarch64")] assert_tls_layout();` immediately before it.

**Step 6: Commit**

```bash
git add litebox_platform_linux_userland/src/lib.rs docs/plans/
git commit -m "feat(platform-linux-userland): reserve the aarch64 guest thread-pointer slot

The rewriter virtualizes the guest thread pointer to [TPIDR_EL0 + 16], so the
runtime must reserve that slot. Emit the TLS control block into .tdata so it
lands at the head of the static TLS area, and assert the layout at startup
since the transition assembly addresses it with literal offsets."
```

---

## Task 2: Architecture-generic cleanups

Small independent changes that let the rest of the crate compile. Do these before the assembly so that later build failures are all in code you just wrote.

**Files:**
- Modify: `litebox_platform_linux_userland/src/lib.rs` lines 187, 323, 1679, 2635 (`Sysno::open`)
- Modify: `litebox_platform_linux_userland/src/lib.rs:593` (seccomp target arch)
- Modify: `litebox_platform_linux_userland/src/lib.rs` lines 1478–1481, 1512–1515, 1580–1585, 1697–1712 (`cfg` widening)
- Modify: `litebox_platform_linux_userland/src/lib.rs:1550-1551` (`TASK_ADDR_MAX`)
- Modify: `litebox_platform_linux_userland/src/lib.rs` lines 1328, 1341 (`cfg_attr`)

**Step 1: Replace `open` with `openat`**

AArch64 has no `open` syscall. `openat` is correct on both architectures, so this is an unconditional replacement, not a `cfg`. At each of the four sites turn `syscallN(Sysno::open, path, flags, mode)` into `syscallN+1(Sysno::openat, AT_FDCWD, path, flags, mode)` where:

```rust
const AT_FDCWD: usize = (-100isize).cast_unsigned();
```

Define that constant once near the top of the file rather than repeating the cast.

**Step 2: Make seccomp architecture-generic**

At line 593 replace `seccompiler::TargetArch::x86_64` with:

```rust
#[cfg(target_arch = "x86_64")]
{ seccompiler::TargetArch::x86_64 }
#[cfg(target_arch = "aarch64")]
{ seccompiler::TargetArch::aarch64 }
```

**Step 3: Widen the remaining `cfg`s**

`futex` and `mmap` both exist on AArch64, and `Duration::new`'s conversions are equally useless there, so change every `#[cfg(target_arch = "x86_64")]` at lines 1478, 1512, 1580, 1697, 1707 and every `#[cfg_attr(target_arch = "x86_64", ...)]` at 1328, 1341 to `any(target_arch = "x86_64", target_arch = "aarch64")`.

**Step 4: Add `TASK_ADDR_MAX`**

Next to line 1550:

```rust
/// 48-bit user virtual address space.
#[cfg(target_arch = "aarch64")]
const TASK_ADDR_MAX: usize = 0x0000_FFFF_FFFF_F000;
```

**Step 5: Verify x86-64 is undisturbed**

These edits touch shared code, so confirm you have not regressed the working architecture:

```bash
cargo build -p litebox_platform_linux_userland --target x86_64-unknown-linux-gnu
```

If that target is not installed, at minimum run `cargo clippy -p litebox_platform_linux_userland` on AArch64 and reason carefully about the `openat` change, which is the only one affecting x86-64 behaviour.

**Step 6: Commit**

```bash
git add litebox_platform_linux_userland/src/lib.rs
git commit -m "refactor(platform-linux-userland): make syscall and mmap paths architecture-generic

AArch64 has no open(2), so move to openat(AT_FDCWD, ...), which is correct on
both architectures. Widen the futex/mmap/seccomp/time cfgs to admit aarch64."
```

---

## Task 3: `run_thread_arch` and `syscall_callback`

**Files:**
- Modify: `litebox_platform_linux_userland/src/lib.rs` (add after the x86-64 `run_thread_arch`, line 894)

**Step 1: Write the naked function**

Register convention on entry is the C ABI: `x0` = `thread_ctx`, `x1` = `ctx`, `w2` = `reenter`.

Entry state at `syscall_callback` is set by the rewriter's shared handler (`BR X16`) and is documented in section 1 of the design doc. Reproduce that table as a comment above the label — the next person to read this needs it.

```rust
/// Runs the guest thread until it terminates.
///
/// Parallels the x86-64 version, but performs no thread-pointer swapping:
/// `TPIDR_EL0` holds the host anchor for the entire lifetime of this call
/// stack, including while guest code runs. The rewriter redirects guest
/// thread-pointer accesses to `[TPIDR_EL0 + 16]`.
#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
unsafe extern "C-unwind" fn run_thread_arch(
    thread_ctx: &mut ThreadContext,
    ctx: *mut litebox_common_linux::PtRegs,
    reenter: u8,
) {
    core::arch::naked_asm!(/* see steps below */);
}
```

Prologue:

```
.cfi_startproc
stp x29, x30, [sp, #-96]!
.cfi_def_cfa_offset 96
.cfi_offset x29, -96
.cfi_offset x30, -88
mov x29, sp
stp x19, x20, [sp, #16]
stp x21, x22, [sp, #32]
stp x23, x24, [sp, #48]
stp x25, x26, [sp, #64]
stp x27, x28, [sp, #80]
sub sp, sp, #16
str x0, [sp]                    // thread_ctx, read back by every callback
mrs x8, tpidr_el0
mov x9, sp
str x9, [x8, #{HOST_SP}]
add x9, x1, #{GUEST_CONTEXT_SIZE}
str x9, [x8, #{GUEST_CONTEXT_TOP}]
cbnz w2, 1f
bl {init_handler}
b .Ldone_aarch64
1:
bl {reenter_handler}
b .Ldone_aarch64
```

`syscall_callback` — the body is given verbatim in section 3 of the design doc. Two invariants you must not reorder:

1. `strb wzr, [x16, #IN_GUEST]` must be reachable within the first instruction *pair*, because `interrupt_signal_handler` case 1 recognizes this callback by comparing the faulting PC against `syscall_callback`.
2. Guest `x30` must be stored to `regs[30]` before the `bl {syscall_handler}`, which clobbers it.

`exception_callback` and `interrupt_callback` restore the host stack from TLS and call their handlers:

```
exception_callback:
    mrs x18, tpidr_el0
    ldr x9, [x18, #{HOST_SP}]
    mov sp, x9
    ldr x0, [sp]
    bl {exception_handler}
    b .Ldone_aarch64
```

Epilogue:

```
.Ldone_aarch64:
    add sp, sp, #16
    ldp x19, x20, [sp, #16]
    ldp x21, x22, [sp, #32]
    ldp x23, x24, [sp, #48]
    ldp x25, x26, [sp, #64]
    ldp x27, x28, [sp, #80]
    ldp x29, x30, [sp], #96
    .cfi_def_cfa_offset 0
    ret
.cfi_endproc
```

Operands:

```rust
GUEST_CONTEXT_SIZE = const core::mem::size_of::<litebox_common_linux::PtRegs>(),
HOST_SP = const tls_offset::HOST_SP,
GUEST_CONTEXT_TOP = const tls_offset::GUEST_CONTEXT_TOP,
IN_GUEST = const tls_offset::IN_GUEST,
init_handler = sym init_handler,
reenter_handler = sym reenter_handler,
syscall_handler = sym syscall_handler,
exception_handler = sym exception_handler,
interrupt_handler = sym interrupt_handler,
```

**Step 2: Verify the PtRegs offsets you are hardcoding**

The assembly hardcodes `PtRegs` field offsets. Pin them with a test so a future field reorder is caught:

```rust
#[cfg(target_arch = "aarch64")]
#[test]
fn test_ptregs_layout() {
    use litebox_common_linux::PtRegs;
    assert_eq!(core::mem::size_of::<PtRegs>(), 288);
    let r = PtRegs::default();
    let base = &raw const r as usize;
    assert_eq!(&raw const r.regs[16] as usize - base, 128);
    assert_eq!(&raw const r.sp as usize - base, 248);
    assert_eq!(&raw const r.pc as usize - base, 256);
    assert_eq!(&raw const r.pstate as usize - base, 264);
    assert_eq!(&raw const r.orig_x0 as usize - base, 272);
    assert_eq!(&raw const r.syscallno as usize - base, 280);
}
```

**Step 3: Run**

```bash
cargo nextest run -p litebox_platform_linux_userland test_ptregs_layout
cargo build -p litebox_platform_linux_userland
```

Expected: the test passes; the build still fails, because `switch_to_guest` does not exist yet. That is fine.

**Step 4: Commit**

```bash
git add litebox_platform_linux_userland/src/lib.rs
git commit -m "feat(platform-linux-userland): add aarch64 guest entry and syscall callback"
```

---

## Task 4: `switch_to_guest`

**Files:**
- Modify: `litebox_platform_linux_userland/src/lib.rs` (add after the x86-64 `switch_to_guest`, line 948)

**Step 1: Write it**

```rust
/// Switches to the provided guest context.
///
/// # Safety
/// The context must be a valid guest context, and `run_thread_arch` must be on
/// the stack. Do not call this where the stack needs unwinding for destructors.
///
/// Guest `x16` (IP0) is deliberately *not* restored. AArch64 has no
/// memory-indirect branch, so the branch target must occupy a register that
/// would otherwise hold guest state; restoring all 31 GPRs and branching is
/// impossible. `x16`/`x17` are AAPCS intra-procedure-call scratch registers
/// that linker veneers may clobber at any branch, and the rewriter's gate has
/// already clobbered `x16` before the callback runs.
///
/// TODO: have the rewriter emit a per-site outbound stub
/// (`ldr x16, [sp, #0]; add sp, sp, #16; b site+4`) so `x16` is restored. See
/// `docs/plans/2026-07-29-aarch64-linux-userland-design.md` section 3.
#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
unsafe extern "C" fn switch_to_guest(ctx: &litebox_common_linux::PtRegs) -> ! {
    core::arch::naked_asm!(/* below */);
}
```

Body. `x0` is `ctx` and stays live until the final two loads:

```
switch_to_guest_start:
    mrs  x17, tpidr_el0
    mov  w16, #1
    strb w16, [x17, #{IN_GUEST}]
    ldrb w16, [x17, #{INTERRUPT}]
    cbnz w16, interrupt_callback
    ldr  x16, [x0, #264]          // pstate
    msr  nzcv, x16
    ldr  x16, [x0, #248]          // guest sp
    mov  sp, x16
    ldr  x1,  [x0, #8]
    ldp  x2,  x3,  [x0, #16]
    ldp  x4,  x5,  [x0, #32]
    ldp  x6,  x7,  [x0, #48]
    ldp  x8,  x9,  [x0, #64]
    ldp  x10, x11, [x0, #80]
    ldp  x12, x13, [x0, #96]
    ldp  x14, x15, [x0, #112]
    ldr  x17, [x0, #136]
    ldr  x18, [x0, #144]
    ldp  x19, x20, [x0, #152]
    ldp  x21, x22, [x0, #168]
    ldp  x23, x24, [x0, #184]
    ldp  x25, x26, [x0, #200]
    ldp  x27, x28, [x0, #216]
    ldr  x29, [x0, #232]
    ldr  x30, [x0, #240]
    ldr  x16, [x0, #256]          // guest PC (x16 is the branch register)
    ldr  x0,  [x0, #0]            // guest x0, last use of ctx
    br   x16
switch_to_guest_end:
```

The `switch_to_guest_start` / `switch_to_guest_end` labels are load-bearing: `interrupt_signal_handler` case 3 tests whether the interrupted PC lies between them to detect a partially restored guest context. Keep them and keep the existing `extern` declarations at lines 1773–1780 working.

**Step 2: Handle `call_shim`'s `interrupt` clear**

`ThreadContext::call_shim` at line 1841 clears the `interrupt` byte with an x86 `asm!`. Add:

```rust
#[cfg(target_arch = "aarch64")]
// SAFETY: writes a single byte in this thread's own TLS control block.
core::arch::asm!(
    "mrs {tmp}, tpidr_el0",
    "strb wzr, [{tmp}, #{off}]",
    tmp = out(reg) _,
    off = const tls_offset::INTERRUPT,
    options(nostack, preserves_flags)
);
```

**Step 3: Port the remaining small `asm!` sites**

Same pattern (`mrs` then a literal offset) for:

- `take_pending_host_signals`, line 622 — AArch64 has no `xchg`; use `ldaxr`/`stlxr` or `swpal` on `[x_tp, #PENDING_HOST_SIGNALS]`. `swpal` needs LSE (ARMv8.1); prefer the `ldaxr`/`stlxr` loop for portability.
- `RawMutexProvider::update_waker`, line 1180 — same, on `WAIT_WAKER_ADDR`.
- `get_guest_tpidr` / `set_guest_tpidr` — plain `ldr`/`str` at `GUEST_TPIDR`, replacing the x86-64 `get_guest_fsbase` / `set_guest_fsbase` pair.

**Step 4: Build**

```bash
cargo build -p litebox_platform_linux_userland
```

Remaining errors should now be confined to the signal-handling functions.

**Step 5: Commit**

```bash
git add litebox_platform_linux_userland/src/lib.rs
git commit -m "feat(platform-linux-userland): add aarch64 guest resume path"
```

---

## Task 5: Signal handling

**Files:**
- Modify: `litebox_platform_linux_userland/src/lib.rs` lines 2054–2096, 2100–2168, 2171–2246, 2318–2431
- Modify: `litebox/src/platform/arch.rs:49-51`

**Step 1: `ArchSpecificRegister::TpidrEl0`**

`litebox/src/platform/arch.rs:49` currently declares an empty enum. Replace with:

```rust
/// Architecture-specific registers for AArch64.
#[cfg(target_arch = "aarch64")]
#[non_exhaustive]
pub enum ArchSpecificRegister {
    /// The guest thread pointer. AArch64 has no `arch_prctl`, so this is how
    /// the shim services `CLONE_SETTLS`.
    TpidrEl0,
}
```

**Step 2: Implement `ArchSpecificProvider` for AArch64**

Parallel the x86-64 impl at lines 1382–1425. `TpidrEl0` reads and writes the `guest_tpidr` slot, validating writes with `litebox_common_linux::arch::USER_ADDR_END` exactly as `is_valid_user_fs_base` does on x86-64, returning `ArchSpecificError::RegisterUnpermittedValue` on failure.

**Step 3: `signal_handler_exit_guest`**

Far simpler than x86-64: `TPIDR_EL0` is already the host anchor, so ordinary TLS access works with no recovery step.

```rust
#[cfg(target_arch = "aarch64")]
fn signal_handler_exit_guest(
    _context: &libc::ucontext_t,
    set_interrupt: bool,
) -> Option<*mut litebox_common_linux::PtRegs> {
    let tp: usize;
    // SAFETY: reads the host thread pointer, which is always valid here.
    unsafe {
        core::arch::asm!("mrs {}, tpidr_el0", out(reg) tp, options(nostack, nomem, preserves_flags));
    }
    // SAFETY: `tp` addresses this thread's own TLS control block, whose layout
    // is asserted by `assert_tls_layout`.
    unsafe {
        let in_guest = (tp + tls_offset::IN_GUEST) as *mut u8;
        let was_in_guest = in_guest.read_volatile();
        in_guest.write_volatile(0);
        if set_interrupt {
            ((tp + tls_offset::INTERRUPT) as *mut u8).write_volatile(1);
        }
        if was_in_guest == 0 {
            return None;
        }
        let top = ((tp + tls_offset::GUEST_CONTEXT_TOP) as *const usize).read_volatile();
        Some((top as *mut litebox_common_linux::PtRegs).sub(1))
    }
}
```

**Step 4: Context marshalling**

```rust
#[cfg(target_arch = "aarch64")]
fn copy_signal_context(regs: &mut litebox_common_linux::PtRegs, context: &libc::ucontext_t) {
    let m = &context.uc_mcontext;
    for (dst, src) in regs.regs.iter_mut().zip(m.regs.iter()) {
        *dst = *src as usize;
    }
    regs.sp = m.sp as usize;
    regs.pc = m.pc as usize;
    regs.pstate = m.pstate;
}

#[cfg(target_arch = "aarch64")]
fn set_signal_return(
    context: &mut libc::ucontext_t,
    f: unsafe extern "C" fn(),
    p0: isize, p1: isize, p2: isize, p3: isize,
) {
    let m = &mut context.uc_mcontext;
    m.pc = f as usize as u64;
    m.regs[0] = p0 as u64;
    m.regs[1] = p1 as u64;
    m.regs[2] = p2 as u64;
    m.regs[3] = p3 as u64;
}
```

Prefer `zip` over an index loop so the array lengths cannot drift.

**Step 5: `exception_signal_handler` and `exception_handler`**

AArch64 has no `REG_TRAPNO` / `REG_ERR` / `REG_CR2`. Keep the four-argument `exception_handler` shape and pass `(signum, 0, fault_address)`, then rebuild `ExceptionInfo` inside `exception_handler`:

```rust
#[cfg(target_arch = "aarch64")]
{
    let exception = match trapno as i32 {
        libc::SIGSEGV | libc::SIGBUS => litebox::shim::Exception::DATA_ABORT_LOWER_EL,
        libc::SIGILL => litebox::shim::Exception::INSTRUCTION_ABORT_LOWER_EL,
        libc::SIGTRAP => litebox::shim::Exception::BRK64,
        _ => litebox::shim::Exception::DATA_ABORT_LOWER_EL,
    };
    let info = litebox::shim::ExceptionInfo {
        exception,
        fault_address: cr2,
        // We recover the exception class from the signal number; the real
        // ESR_EL1 is not exposed to userspace, so synthesize it.
        esr: u64::from(exception.0) << 26,
        kernel_mode: false,
    };
    thread_ctx.call_shim(|shim, ctx| shim.exception(ctx, &info));
}
```

Take `fault_address` from `siginfo.si_addr` (`context.uc_mcontext.fault_address` is also available and is what the kernel wrote).

**Step 6: `next_signal_handler` and `interrupt_signal_handler`**

Both read the interrupted PC. Add `#[cfg(target_arch = "aarch64")] let ip = context.uc_mcontext.pc as usize;` alongside the existing arms, and write `context.uc_mcontext.pc = fixup_addr as u64;` in the exception-table fixup path at line 2242. The four-case analysis in `interrupt_signal_handler` needs no structural change; only the `rdgsbase` guest-thread probe at line 2364 goes away, since on AArch64 every thread's `TPIDR_EL0` is valid and `in_guest` alone distinguishes guest threads.

**Step 7: Build and test**

```bash
cargo build -p litebox_platform_linux_userland
cargo nextest run -p litebox_platform_linux_userland
cargo clippy -p litebox_platform_linux_userland --all-targets
```

Expected: clean build; `test_tls_layout`, `test_ptregs_layout`, `test_raw_mutex`, `test_reserved_pages` and `test_seccomp_filter` all pass.

If `test_seccomp_filter` fails, check that the AArch64 syscall numbers in the filter's allow-list match — it references `pread`/`pwrite`/`shutdown`/`mkdir`/`open`, and `mkdir` and `open` do not exist on AArch64.

**Step 8: Commit**

```bash
git add litebox_platform_linux_userland/src/lib.rs litebox/src/platform/arch.rs
git commit -m "feat(platform-linux-userland): add aarch64 signal handling and TpidrEl0 register

TPIDR_EL0 always holds the host anchor, so signal handlers can use ordinary TLS
with no alt-stack recovery machinery."
```

---

## Task 6: Make `litebox_shim_linux` build

Roughly 51 errors. Work file by file, smallest first, committing per file, so a regression is easy to bisect.

**Files, in order:**
- `litebox_shim_linux/src/syscalls/file.rs` (1 error)
- `litebox_shim_linux/src/syscalls/misc.rs` (1)
- `litebox_shim_linux/src/syscalls/mm.rs` (4)
- `litebox_shim_linux/src/lib.rs` (9)
- `litebox_shim_linux/src/syscalls/process.rs` (13)
- `litebox_shim_linux/src/syscalls/signal/mod.rs` (23)

**Step 1: Get the current error list**

```bash
cargo build -p litebox_shim_linux --message-format=short 2>&1 | grep error
```

**Step 2: Fix one file, rebuild, repeat**

Guidance on the recurring categories:

- `E0609` / `E0560` (unknown field) — x86-only `ExceptionInfo` fields (`cr2`, `error_code`). Use the AArch64 shape from `litebox/src/shim.rs:117-129`.
- `E0433` (unresolved path) — x86-only `Sysno` variants. AArch64 has no `open`, `mkdir`, `stat`, `fork`, `arch_prctl`, `getpid`-family aliases; use the `*at` forms.
- `E0063` (missing field) — mostly `ExceptionInfo` again.
- `process.rs` — `sys_arch_prctl` (lines 397–412) must be `cfg`-gated off for AArch64. `CLONE_SETTLS` (lines 642–643, 703, 1614, 1628–1631) routes to `ArchSpecificRegister::TpidrEl0`. Note `litebox_common_linux/src/lib.rs:2860` already selects `CLONE_BACKWARDS` argument ordering for arm64.
- `signal/mod.rs` — `litebox_common_linux/src/signal/aarch64.rs` already provides `Sigcontext`, and `signal/mod.rs:333-334` already knows the AArch64 `ucontext` field order. Most errors are register-name mismatches.

Where AArch64 behaviour is genuinely unimplemented, prefer an explicit `unimplemented!("aarch64: ...")` over a silently wrong value. Hello-world will not reach those paths, and a panic is far easier to diagnose later than a bad register.

**Step 3: Verify**

```bash
cargo build -p litebox_shim_linux
cargo nextest run -p litebox_shim_linux
```

**Step 4: Commit per file**

```bash
git commit -m "fix(shim-linux): build <file> on aarch64"
```

---

## Task 7: End-to-end hello world

**Files:**
- Modify: `litebox_runner_linux_userland/tests/run.rs:31` (hardcoded `lib/x86_64-linux-gnu`), `:113` (`guest_program_path` is `cfg(target_arch = "x86_64")`), `:86`, `:101`
- Test: `litebox_runner_linux_userland/tests/hello.c` (exists; no change)

**Step 1: Build the runner**

```bash
cargo build -p litebox_runner_linux_userland
```

**Step 2: Rewrite hello world by hand first**

Before touching the harness, confirm the rewriter and runner agree, in isolation:

```bash
aarch64-linux-gnu-gcc -static -o /tmp/hello litebox_runner_linux_userland/tests/hello.c
# or plain `gcc` since we are native aarch64
cargo run -p litebox_syscall_rewriter -- /tmp/hello /tmp/hello.hooked
./target/debug/litebox_runner_linux_userland --unstable /tmp/hello.hooked
```

Expected: `Hello, world!` on stdout, exit 0.

This is the milestone the whole plan exists for. If it fails, the likely suspects in order are: the `guest_tpidr` slot (run `test_tls_layout`), the `PtRegs` field offsets in `syscall_callback`, and `switch_to_guest`'s register ordering. Use @superpowers:systematic-debugging rather than guessing.

**Step 3: Teach the harness about AArch64**

In `tests/run.rs`, replace the hardcoded `lib/x86_64-linux-gnu` at line 31 with a `cfg`-selected constant (`aarch64-linux-gnu` on AArch64), and widen the `cfg(target_arch = "x86_64")` gates at lines 86, 101 and 113 to include `aarch64`.

**Step 4: Run the hello-world integration test**

```bash
cargo nextest run -p litebox_runner_linux_userland hello
```

**Step 5: Repo hygiene**

```bash
cargo fmt
cargo nextest run -p dev_tests
cargo clippy --all-targets --workspace \
  --exclude litebox_runner_lvbs \
  --exclude litebox_runner_optee_on_linux_userland \
  --exclude litebox_runner_snp
```

Bump `dev_tests/src/ratchet.rs` counters only if you genuinely could not avoid new lint-debt markers.

**Step 6: Commit**

```bash
git add litebox_runner_linux_userland/tests/run.rs
git commit -m "test(runner-linux-userland): run hello world on aarch64"
```

---

## Task 8: Update the rewriter's runtime contract note

**Files:**
- Modify: `litebox_syscall_rewriter/src/arm64.rs` (module docs, "Runtime contract" section around lines 113–119, and `emit_svc_gate` docs around 734–743)

The rewriter currently documents that "the callback ... restores X16 from `[SP, #0]`". The implementation deliberately does not. Correct the documentation to state the actual contract and reference the outbound-stub TODO, so the next reader is not misled.

```bash
git commit -m "docs(syscall-rewriter): record that the aarch64 callback does not restore x16"
```

---

## Definition of done

- `cargo build`, `cargo clippy --all-targets` and `cargo nextest run` are clean on `aarch64-unknown-linux-gnu` for `litebox`, `litebox_common_linux`, `litebox_platform_linux_userland`, `litebox_shim_linux` and `litebox_runner_linux_userland`.
- A rewritten static hello-world prints `Hello, world!` under the runner on AArch64.
- x86-64 is unregressed.
- `docs/plans/2026-07-29-aarch64-linux-userland-design.md` still matches the code, including the `x16` deviation and its TODO.
