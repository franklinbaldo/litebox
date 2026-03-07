# ARM64 Windows Rewriter Design

## Context

The ARM64 syscall rewriter currently targets Linux, where:
- `TPIDR_EL0` is the thread-local storage register used by both host and guest.
- `X18` is a general-purpose caller-saved register with no platform reservation.

On Windows ARM64, both assumptions break:
- `X18` is a **reserved platform register** pointing to the Thread Environment
  Block (TEB). Windows code must not clobber it.
- `TPIDR_EL0` is listed as **"Reserved"** in the Windows ABI docs. It may trap
  if accessed from EL0, or it may be used internally by the kernel. Either way,
  guest code cannot safely execute `MRS`/`MSR TPIDR_EL0` instructions.

A Linux ARM64 binary uses X18 as a scratch register throughout (GCC/clang do
not reserve it on Linux) and accesses TPIDR_EL0 freely for TLS. Running such a
binary unmodified on Windows ARM64 would corrupt the TEB (via X18 writes) and
potentially fault on every TPIDR_EL0 access.

## Goal

Extend the ARM64 rewriter so that a Linux ARM64 binary can run on a Windows
ARM64 host under litebox, with the same shared-trampoline architecture used on
Linux. The rewriter must handle three classes of instructions:

1. **SVC #0** -- syscall interception (same as Linux).
2. **MRS/MSR TPIDR_EL0** -- virtualize the TLS register into memory.
3. **X18 references** -- spill the guest's virtual X18 to memory so the real X18
   (TEB pointer) is never clobbered.

## Design

### Overview

On Windows ARM64, X18 always points to the TEB throughout guest execution. The
rewriter guarantees this by intercepting every instruction that references X18
and redirecting those accesses to a memory-backed "virtual X18" slot at a known
offset from the TEB.

Similarly, TPIDR_EL0 accesses are rewritten into loads/stores to a "virtual
TPIDR" memory slot, also at a known TEB offset.

Because X18 (TEB) is always valid, the trampoline can use it directly as the
per-thread anchor -- no TLS lookup table or loop required.

### Per-thread memory slots

Two slots are allocated per thread at fixed offsets from the TEB (via
`TlsAlloc` or a reserved TEB region):

| Slot              | TEB Offset            | Contents                          |
|-------------------|-----------------------|-----------------------------------|
| `virt_x18_off`    | `[X18, #VIRT_X18]`   | Guest's virtual X18 value         |
| `virt_tpidr_off`  | `[X18, #VIRT_TPIDR]` | Guest's virtual TPIDR_EL0 value   |
| `scratch_off`     | `[X18, #SCRATCH]`    | Scratch register spill for gates  |

The exact offsets depend on the TEB layout and TLS slot allocation strategy.
This is resolved at load time; the rewriter emits relocatable offset
placeholders or the loader patches the offsets after allocation.

### Rewrite class 1: SVC #0

Identical to the Linux rewriter. Replace `SVC #0` with `B <svc_gate>`. The
per-site SVC gate and shared SVC handler are structurally the same, except the
shared SVC handler is much simpler on Windows (see below).

### Rewrite class 2: MRS/MSR TPIDR_EL0

These are **in-place 1:1 replacements** (4 bytes -> 4 bytes), no gate needed:

```asm
// MRS Xn, TPIDR_EL0  -->  LDR Xn, [X18, #virt_tpidr_off]
// MSR TPIDR_EL0, Xn  -->  STR Xn, [X18, #virt_tpidr_off]
```

Edge cases where `Xn` is X18 itself (e.g., `MSR TPIDR_EL0, X18`) overlap with
class 3 -- the X18 reference in the source register must also be virtualized.
These become:

```asm
// MSR TPIDR_EL0, X18:
//   LDR Xtmp, [X18, #virt_x18_off]    // load virtual X18
//   STR Xtmp, [X18, #virt_tpidr_off]  // store to virtual TPIDR
// (requires a gate for the 2-instruction expansion)

// MRS X18, TPIDR_EL0:
//   LDR Xtmp, [X18, #virt_tpidr_off]  // load virtual TPIDR
//   STR Xtmp, [X18, #virt_x18_off]    // store to virtual X18
// (requires a gate)
```

### Rewrite class 3: X18 references

Every instruction that encodes register 18 in any field (Rd, Rn, Rm, Rt, Rt2,
Ra, Rs, etc.) must be rewritten. Since the replacement sequence is larger than
4 bytes, the original instruction is replaced with `B <x18_gate>`, and the gate
contains the expanded sequence.

The general strategy: use X16 as a scratch register to hold the virtual X18
value. Save X16 to a TEB scratch slot before use, restore after.

#### X18 as source only (Rn, Rm, etc.)

Example: `ADD X5, X18, X3`

```asm
x18_gate:
  STR  X16, [X18, #scratch_off]       // save scratch
  LDR  X16, [X18, #virt_x18_off]      // X16 = virtual X18
  ADD  X5, X16, X3                     // original insn with X18 -> X16
  LDR  X16, [X18, #scratch_off]       // restore scratch
  B    <return_addr>                   // back to guest (site.vaddr + 4)
```

5 instructions, 20 bytes per gate.

#### X18 as destination only (Rd)

Example: `ADD X18, X5, X3`

```asm
x18_gate:
  STR  X16, [X18, #scratch_off]       // save scratch
  ADD  X16, X5, X3                     // original insn with X18 -> X16
  STR  X16, [X18, #virt_x18_off]      // write result to virtual X18
  LDR  X16, [X18, #scratch_off]       // restore scratch
  B    <return_addr>
```

5 instructions, 20 bytes per gate.

#### X18 as both source and destination

Example: `ADD X18, X18, #1`

```asm
x18_gate:
  STR  X16, [X18, #scratch_off]       // save scratch
  LDR  X16, [X18, #virt_x18_off]      // X16 = virtual X18
  ADD  X16, X16, #1                    // original insn with X18 -> X16
  STR  X16, [X18, #virt_x18_off]      // write result to virtual X18
  LDR  X16, [X18, #scratch_off]       // restore scratch
  B    <return_addr>
```

6 instructions, 24 bytes per gate.

#### Conflict: instruction also uses X16

Example: `ADD X5, X18, X16`

When the original instruction references both X18 and X16, use X17 as the
scratch register instead:

```asm
x18_gate:
  STR  X17, [X18, #scratch_off]       // save X17 as scratch
  LDR  X17, [X18, #virt_x18_off]      // X17 = virtual X18
  ADD  X5, X17, X16                    // original insn with X18 -> X17
  LDR  X17, [X18, #scratch_off]       // restore X17
  B    <return_addr>
```

#### Conflict: instruction uses X16, X17, and X18

Example: `MADD X5, X18, X16, X17`

When the original instruction references X16, X17, and X18, neither X16 nor
X17 is available as scratch. Fall back to a stack spill:

```asm
x18_gate:
  SUB  SP, SP, #16                     // allocate stack frame
  STR  X16, [SP]                       // save X16 to stack
  LDR  X16, [X18, #virt_x18_off]      // X16 = virtual X18
  MADD X5, X16, X16_orig?, X17        // problem: X16 is now virtual X18
```

This case is pathological -- an instruction using X16, X17, and X18
simultaneously. The solution requires saving two registers to the stack and
loading virtual X18 into one of them, while the other holds its original value.
The exact expansion depends on which fields contain X18:

```asm
x18_gate:
  STP  X16, X17, [SP, #-16]!          // save both
  LDR  X16, [X18, #virt_x18_off]      // X16 = virtual X18
  LDP  X17, XZR, [SP]                 // X17 = original X16 (from stack)
  // Now: X16 = virtual X18, X17 = original X16
  // But we lost original X17...
```

In practice, this triple-register case requires per-instruction analysis to
determine the correct register shuffling. The rewriter must decode which fields
contain X18, X16, and X17, and generate a custom sequence. This is rare enough
(compilers almost never use X16/X17/X18 simultaneously in one instruction) that
a case-by-case handler is acceptable.

**Note**: X16 and X17 are the "intra-procedure-call" scratch registers on ARM64.
Compilers rarely emit them in normal code; they appear mainly in linker-generated
veneers and PLT stubs. The triple-conflict case is extremely unlikely in practice.

### Shared SVC handler (Windows ARM64)

Because X18 (TEB) is always valid and provides a direct per-thread anchor, the
shared SVC handler is dramatically simpler than the Linux version -- no TLS
table loop:

```asm
shared_svc_handler:
  // Guest TPIDR is in memory, not in a register.
  // Load it from the virtual TPIDR slot for the stack frame.
  LDR  X16, [X18, #virt_tpidr_off]    // X16 = guest virtual TPIDR
  STR  X16, [SP, #24]                 // save to frame [SP+24]
  LDR  X16, [X18, #host_ctx_off]      // X16 = host context pointer
  LDR  X17, [X16, #callback_off]      // X17 = callback address
  BR   X17                            // jump to callback
```

5 instructions, 20 bytes. Compare to 14 instructions / 56 bytes on Linux.

The callback ABI is similar but the meaning of X18 changes:

| Register | Linux                  | Windows                      |
|----------|------------------------|------------------------------|
| X18      | Host TPIDR_EL0 base    | TEB pointer (native Windows) |
| X30      | Guest return address   | Guest return address         |
| SP frame | Same layout            | Same layout                  |

The callback implementation is platform-specific: on Linux it uses X18 as
TPIDR_EL0; on Windows it uses X18 as TEB. Both provide access to host
thread-local state.

### Shared MSR handler (Windows ARM64)

On Windows, MSR TPIDR_EL0 is fully virtualized in memory (rewrite class 2).
There is **no shared MSR handler** needed. The in-place `STR` replacement
handles the common case, and the gate-based expansion handles the X18 edge
case. No TLS table update is required because there is no TLS table.

### Trampoline layout (Windows ARM64)

```
Offset 0:     [8 bytes]   Host context pointer (or callback address)
Offset 8:     [8 bytes]   (unused, reserved for alignment)
Offset 16:    [8 bytes]   Sigreturn preamble (MOV X8, #139 + B .+4)
Offset 24:    [24 bytes]  Sigreturn SVC gate
Offset 48:    [20 bytes]  Shared SVC handler
Offset 68:    Per-site SVC gates (24 bytes each)
              Per-site X18 gates (20-24 bytes each)
```

No shared MSR handler. No TLS table pointer. Smaller overall.

## Comparison: Linux vs Windows ARM64 rewriter

| Aspect                  | Linux ARM64                          | Windows ARM64                        |
|-------------------------|--------------------------------------|--------------------------------------|
| SVC rewriting           | B to SVC gate                        | B to SVC gate (same)                 |
| MSR TPIDR_EL0 writes    | B to MSR gate (TLS table update)     | STR in-place (1 insn) or gate if X18 |
| MRS TPIDR_EL0 reads     | Not rewritten                        | LDR in-place (1 insn) or gate if X18 |
| X18 references          | Not rewritten                        | B to X18 gate (5-6+ insn per site)   |
| Per-thread anchor       | TPIDR_EL0 + TLS table loop           | X18 (TEB) direct offset              |
| Shared SVC handler      | 14 insn, 56 bytes (TLS loop)         | 5 insn, 20 bytes (direct TEB access) |
| Shared MSR handler      | 16 insn, 64 bytes                    | Not needed                           |
| TLS table               | Required (guest TPIDR -> host TPIDR) | Not needed                           |
| Rewrite-time cost       | Low (SVC + MSR only)                 | High (SVC + TPIDR + every X18 ref)   |
| Runtime trampoline cost | Higher (TLS loop on every syscall)   | Lower (direct TEB offset)            |

## Implementation notes

### Instruction decoding for X18

The rewriter must identify X18 in all ARM64 instruction encodings. Register
fields appear at fixed bit positions depending on the instruction class:

| Field | Typical bit range | Instructions                    |
|-------|-------------------|---------------------------------|
| Rd    | [4:0]             | Most data-processing            |
| Rn    | [9:5]             | Most data-processing, loads     |
| Rm    | [20:16]           | Register-register ops           |
| Rt    | [4:0]             | Loads/stores                    |
| Rt2   | [14:10]           | LDP/STP                         |
| Ra    | [14:10]           | MADD/MSUB                       |
| Rs    | [20:16]           | Atomic ops (LDADD, CAS, etc.)   |

The rewriter already decodes instructions to find SVC and MSR TPIDR_EL0. The
X18 detection extends this to check all register fields for the value 18.

Some instruction classes that need attention:
- **LDP/STP with X18**: may have X18 as Rt, Rt2, or Rn (base register). If X18
  is the base register, the semantics are complex (address computation uses X18).
- **LDR/STR with X18 as base**: `LDR X5, [X18, #imm]` -- the gate must load
  virtual X18 into scratch, then do `LDR X5, [scratch, #imm]`.
- **ADR/ADRP into X18**: rare but possible -- the result is a PC-relative
  address that should go to virtual X18.
- **Branches**: `BR X18`, `BLR X18` -- load virtual X18 into scratch, then
  branch through scratch.

### Conditional compilation

The X18 rewriting is needed on both Windows and macOS (both reserve X18). The
TPIDR_EL0 memory virtualization is Windows-specific (macOS uses TPIDR_EL0 like
Linux, so the existing TLS table swap applies). Use `#[cfg]` gates:

```rust
#[cfg(not(target_os = "linux"))]
fn find_x18_sites(code: &[u8], base_vaddr: u64) -> Vec<PatchSite> { ... }

#[cfg(not(target_os = "linux"))]
fn emit_x18_gate(...) -> Result<(), Error> { ... }

#[cfg(target_os = "windows")]
fn find_tpidr_read_sites(code: &[u8], base_vaddr: u64) -> Vec<PatchSite> { ... }
```

The Linux rewriter is unchanged. The `hook_syscalls_aarch64` function
conditionally includes X18/TPIDR rewriting based on the target OS.

### Testing strategy

- Unit tests for X18 detection across all instruction classes.
- Unit tests for each gate variant (source-only, dest-only, both, X16 conflict,
  X17 conflict, triple conflict).
- Integration test with a synthetic binary containing X18 instructions.
- Cross-compilation tests (build for `aarch64-pc-windows-msvc`, run on Windows
  ARM64 hardware or in a VM).

## Open questions

1. **TEB offset allocation**: How do we reserve TEB slots for virtual X18,
   virtual TPIDR, and scratch? `TlsAlloc` returns an index, and TLS values are
   accessed via `TEB.TlsSlots[index]` or the `TEB.TlsExpansionSlots` pointer.
   The exact memory offset from X18 depends on the TLS index. This may need to
   be resolved at load time with the loader patching immediate fields in the
   rewritten instructions.

2. **TPIDR_EL0 actual behavior on Windows**: Need to verify empirically whether
   `MRS TPIDR_EL0` traps or returns a value on Windows ARM64. If it returns a
   usable value (even if "reserved"), the TPIDR rewriting could potentially be
   simplified, but we should design for the worst case (traps).

3. **Performance impact of X18 spilling**: Every X18 reference becomes 5-6
   instructions with two memory accesses (scratch save/restore). For X18-heavy
   code, this could be significant. Profile on real workloads to determine if
   optimization is needed (e.g., caching virtual X18 in a register across basic
   blocks).

4. **Multi-region support**: Same >128MB binary concern as Linux. Deferred for
   the same reason -- no real-world binaries this large.

## macOS ARM64 (Apple Silicon) -- future target

### XNU kernel source findings

Analysis of XNU source (`osfmk/arm64/locore.s`, `osfmk/arm64/pcb.c`) reveals
that macOS ARM64 differs significantly from both our earlier assumptions and
from Windows ARM64.

#### X18 is NOT a reserved platform register on macOS

Contrary to initial assumption, Apple does **not** reserve X18 as a platform
register in the way Windows does (TEB pointer). XNU's `pcb.c` shows:

- X18 preservation across context switches is **opt-in**, controlled by the
  per-thread flag `ARM_MACHINE_THREAD_PRESERVE_X18`.
- This flag is only set for:
  - **Rosetta (x86_64 translation) tasks** -- because x86_64 translated code
    may depend on X18 being preserved.
  - Tasks that explicitly set `task->preserve_x18`.
  - 32-bit tasks.
- For normal native ARM64 tasks, **X18 is not preserved** across context
  switches.
- On devices with `__ARM_KERNEL_PROTECT__` (most Apple Silicon), the kernel
  exception entry path **destructively clobbers X18** to switch TTBR0_EL1
  (page table base register) for kernel/user ASID isolation.
- The kernel also **zeroes X18** on EL0 exception entry (`mov x18, #0` in
  `locore.s`) to prevent leaking kernel data to userspace saved state.

This means a Linux guest binary's use of X18 as a GPR is compatible with macOS
-- the kernel doesn't expect X18 to hold any particular value. **No X18
rewriting is needed on macOS.**

However, litebox must ensure its own X18 usage (if any) accounts for the kernel
trashing X18 on every syscall/exception entry. If the trampoline or callback
uses X18, the value will not survive a kernel round-trip.

#### TPIDR_EL0 is likely unused by macOS userspace

Apple uses **TPIDRRO_EL0** (the read-only variant) for thread-local storage,
not TPIDR_EL0. The `machine_thread_set_tsd_base` function in `pcb.c`:

```c
thread->machine.cthread_self = tsd_base;
if (thread == current_thread()) {
    set_tpidrro(tsd_base);  // writes TPIDRRO_EL0, not TPIDR_EL0
}
```

Apple's libpthread reads TLS via `MRS Xn, TPIDRRO_EL0`. This means TPIDR_EL0
(the read-write variant) may be entirely free on macOS.

If TPIDR_EL0 is free and the kernel saves/restores it on context switches, the
Linux guest can use it natively for its own TLS -- no TLS table swap needed, no
MSR rewriting needed.

**Open question**: Does XNU save/restore TPIDR_EL0 on context switches? The
save/restore logic is in the `SPILL_REGISTERS` macro (defined in
`exception_asm.h`, not in the files we analyzed). If the kernel does NOT
save/restore TPIDR_EL0, multi-threaded guests would see TPIDR_EL0 corruption
across preemptions.

If XNU does not save/restore TPIDR_EL0, litebox could potentially request this
via the `preserve_x18`-style mechanism, or manage the save/restore itself at
guest entry/exit points.

### Revised platform comparison

| Aspect              | Linux            | Windows               | macOS (Apple Silicon)       |
|---------------------|------------------|-----------------------|-----------------------------|
| X18                 | Free GPR         | TEB pointer, must virtualize | Volatile, kernel trashes it. No rewriting needed |
| TPIDR_EL0           | TLS (host+guest) | Reserved, may trap    | Likely unused by userspace (Apple uses TPIDRRO_EL0) |
| TPIDRRO_EL0         | CPU number       | CPU number            | TLS base (set by kernel)    |
| TLS table needed    | Yes              | No                    | Probably not (if TPIDR_EL0 is free) |
| X18 rewriting       | No               | Yes (pervasive)       | No                          |
| MSR TPIDR_EL0 rewrite | Yes (writes)  | Yes (reads + writes)  | Probably not needed         |
| Trampoline anchor   | TPIDR_EL0        | X18 (TEB)             | TPIDR_EL0 (if kernel preserves it) |

macOS may be the **simplest** target: if TPIDR_EL0 is free and preserved by
the kernel, the rewriter only needs to handle SVC interception -- identical to
a Linux rewriter without the TLS table complexity.

### Remaining investigation

1. **Verify TPIDR_EL0 kernel save/restore**: Check XNU's `exception_asm.h`
   `SPILL_REGISTERS` macro and `machine_switch_context` for TPIDR_EL0 handling.
   Alternatively, write a test program on macOS that sets TPIDR_EL0 per-thread
   and verifies it survives preemption.

2. **Verify TPIDR_EL0 is not used by macOS libraries**: Confirm that no macOS
   system library reads/writes TPIDR_EL0 (as opposed to TPIDRRO_EL0).

3. **`preserve_x18` API**: Investigate whether litebox can set
   `task->preserve_x18` on macOS if needed for any reason. The XNU code shows
   this is a per-task flag checked in `machine_thread_process_signature`.

4. **Kernel Protect impact**: On `__ARM_KERNEL_PROTECT__` devices, the kernel
   uses X18 as scratch during exception entry (TTBR switching). Verify this
   doesn't affect the trampoline -- since the trampoline runs in userspace
   before any SVC, X18 should still be in the guest's state at that point.
