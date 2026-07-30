// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! AArch64 (ARM64) syscall rewriting support for Linux ELF binaries.
//!
//! Every AArch64 instruction is 4 bytes including a direct branch (`B imm26`)
//! with a ±128MB range. This lets us replace a single instruction with
//! a branch into the trampoline without instruction borrowing.
//!
//! The trampoline is placed just past the highest mapped segment, so every
//! site-to-gate branch points forward. A site farther than the `B imm26`
//! ±128MB reach from its gate cannot redirect; it is replaced with a sentinel
//! `BRK #TRAP_BRK_IMM` and reported as a trapped site. Any trapped site makes
//! the rewrite incomplete, so the ELF-level caller rejects the binary with
//! `Error::UnpatchableSyscalls`, mirroring the x86-64 unpatchable-syscall path.
//! Executing the `BRK` raises a synchronous debug exception, so a trapped site
//! faults the guest rather than letting the unpatched instruction escape to the
//! host kernel. Recognizing the `TRAP_BRK_IMM` immediate in the runtime — to
//! attribute the trap to the rewriter rather than a guest breakpoint — is
//! planned but not yet implemented.
//!
//! ### Assumption: executable sections contain only instructions
//!
//! The patch scan walks each executable section word-by-word and treats every
//! 4-byte word that matches the `SVC`/`MSR TPIDR_EL0`/`MRS TPIDR_EL0` bit
//! patterns as that instruction. It does **not** distinguish inline data — literal
//! pools or jump tables embedded in `.text` — from code, because a fixed-width
//! decode cannot tell a data word from an instruction with the same bits. In
//! practice this is safe: default AArch64 codegen places constants in `.rodata`,
//! not `.text`, and the odds of an unrelated data word colliding with these
//! patterns are tiny. A binary that stores such a word inside an executable section
//! would have it rewritten; bounding the scan to symbol-defined function ranges
//! (via `STT_FUNC` extents) would remove the assumption (TODO).
//!
//! Two kinds of access are involved, three forms of instruction gated:
//!
//! * `SVC #imm` — the syscall instruction (any immediate; Linux ignores it).
//!   Replaced with a branch to a per-site *SVC gate* that records the return
//!   address and falls through to the shared SVC handler, a thin shim that
//!   tail-jumps to the syscall callback.
//! * `MSR TPIDR_EL0, Xn` — a write to the thread pointer. Replaced with a branch
//!   to a per-site *MSR gate* that stores the guest value into the guest
//!   thread-pointer slot at `[TPIDR_EL0 + guest_tpidr_offset]`.
//! * `MRS Xd, TPIDR_EL0` — a read of the thread pointer. Replaced with a branch
//!   to a per-site *MRS gate* that loads the guest value from the same slot.
//!   `MRS XZR, TPIDR_EL0` is a discarded read and is left native.
//!
//! ## Thread-pointer virtualization
//!
//! The host owns the hardware `TPIDR_EL0` as a per-thread anchor; the guest's
//! logical thread pointer is a host-managed memory slot at `[TPIDR_EL0 +
//! guest_tpidr_offset]`. Every gated guest read/write of the thread pointer
//! addresses that slot with a scaled `LDR`/`STR` off the anchor:
//!
//! * the MSR gate reads the anchor (`MRS X16, TPIDR_EL0`) and stores the guest
//!   value into the slot;
//! * the MRS gate reads the anchor and loads the guest value from the slot.
//!
//! This mirrors the x64 model: the host keeps the native thread-pointer anchor,
//! the guest is statically relegated off it, and the gates emit nothing
//! TLS-related to the callback.
//!
//! ## Gate scratch storage and the stack invariant
//!
//! `SVC` and `MSR TPIDR_EL0` clobber no general-purpose registers, so a gate has
//! no free scratch register on entry. The SVC and MSR gates therefore spill their
//! scratch registers (and, for SVC, the computed return address the callback
//! reads back) to a frame carved out of the guest stack with `SUB SP, SP, #frame`
//! / `ADD SP, SP, #frame`. The MRS gate needs no frame: it reuses its own
//! destination register as scratch and never touches the stack.
//!
//! Consequently the SVC and MSR gates **require `SP` to hold a valid, writable,
//! 16-byte-aligned stack at the patched site** — the same condition the kernel
//! relies on when it writes a signal frame below `SP`, and which every conforming
//! AArch64 caller already satisfies at a syscall boundary. The gate decrements
//! `SP` before storing, so nothing (signal delivery included) writes into the
//! frame while it is live; there is no red-zone hazard. A site reached with `SP`
//! pointing at unmapped or guard memory would fault where the native instruction
//! would not. AArch64 offers no cheaper alternative: with no segment-relative
//! store (unlike x86's `gs:`-relative spill) and no free register, reaching any
//! runtime-owned scratch area would itself require first clobbering an unsaved
//! guest register to materialize a base pointer.
//!
//! ## Callback register contract: `X16` is preserved across an `SVC`
//!
//! The Linux AArch64 syscall ABI preserves every general-purpose register across
//! an `SVC` except `x0`. That includes `X16`/`X17` (IP0/IP1): `SVC` is not a
//! function call, so the AAPCS allowance that lets a linker-inserted veneer
//! clobber IP0/IP1 does not apply, and glibc's `INTERNAL_SYSCALL` clobbers only
//! `"memory"` — a compiler may legitimately keep a live value in `X16` across an
//! inlined `SVC`. The gates therefore have to preserve it.
//!
//! `X17` is easy: no gate touches it. `X16` is not, because it is the only
//! scratch register the SVC gate has. The gate spills the guest `X16` to
//! `[SP, #0]`, records the post-`SVC` return address at `[SP, #8]` and the
//! address of this site's *outbound stub* at `[SP, #16]`, then enters the
//! callback. The runtime returns to the guest through that stub:
//!
//! ```text
//! outbound_N:
//!     ldr x16, [sp, #0]      // restore guest X16
//!     add sp, sp, #32        // pop the gate frame
//!     b   site+4             // static direct branch; needs no scratch register
//! ```
//!
//! The stub exists because AArch64 has no memory-indirect branch — there is no
//! `BR [mem]` — so a runtime-side branch back into the guest must first
//! materialize its target into a general-purpose register, and that register is
//! by definition one that would otherwise hold restored guest state. Restoring
//! all 31 GPRs *and* branching is impossible **from the runtime side**. Moving
//! the final hop into guest-adjacent code the rewriter emits removes the
//! problem entirely: the stub's branch target is a *static* address, so it needs
//! no register at all.
//!
//! The runtime does not depend on the gate frame's contents surviving its round
//! trip through the host. Before branching to a stub, `switch_to_guest` sets
//! `SP` to `PtRegs::sp - 32` (the stub pops the frame, so `PtRegs::sp` keeps
//! meaning the true guest `SP` throughout) and re-writes `[SP, #0]` from
//! `PtRegs::regs[16]`, so a shim that legitimately modifies `regs[16]` is
//! honoured and nothing relies on guest memory below `SP` being untouched.
//!
//! **Scope: the stub only resumes at the original syscall site.** When the shim
//! redirects `PtRegs::pc` — signal delivery, `execve`, and so on — the runtime
//! detects the mismatch against the site's recorded return address and falls
//! back to branching through `X16`, clobbering it. That is harmless there: the
//! guest is not resuming the interrupted instruction stream, and restoring an
//! arbitrary PC *with* full register state is what an `rt_sigreturn` frame is
//! for.
//!
//! See `docs/plans/2026-07-29-aarch64-linux-userland-design.md` section 3 for
//! the full reasoning, and `litebox_platform_linux_userland`'s
//! `switch_to_guest` for the runtime side of this contract.
//!
//! ## Trampoline layout (Linux)
//!
//! ```text
//! Offset 0:   [8 bytes]  syscall callback address (filled at load time)
//! Offset 8:   [8 bytes]  shared SVC handler (LDR X16,<callback>; BR X16)
//! Offset 16:  per-site gates (SVC: 32 bytes + a 12-byte outbound stub,
//!                             MSR: 36 bytes, MRS: 12 bytes)
//! ```
//!
//! A binary with **no** patch sites gets no trampoline at all: the rewriter
//! appends only a size-0 sentinel header (matching the x86-64 path), recording
//! that the image was checked and needs no redirection. Signal returns are
//! handled by the runtime (see "Signal returns" below).
//!
//! The offset-0 callback address is **filled in by the loader/runtime, not by
//! this crate.** The emitted trampolines are therefore *not runnable as-is*: a
//! loader must write the syscall-callback address at offset 0 before any guest
//! `SVC` reaches a gate. (`callback` may be passed to [`hook_syscalls_aarch64`]
//! to prefill offset 0.) The callback reads host TLS from `TPIDR_EL0` and the
//! guest thread pointer from `[TPIDR_EL0 + guest_tpidr_offset]` itself.
//!
//! ## The guest thread-pointer offset is *not* baked in
//!
//! `guest_tpidr_offset` above is not a constant of this crate. It is the
//! thread-pointer-relative address of the host runtime's own TLS control block,
//! fixed by the *host* binary's link — and the same rewritten guest binary has
//! to run under any host build. So the gates are emitted carrying
//! [`GUEST_TPIDR_OFFSET_PLACEHOLDER`], and the loader calls
//! [`patch_guest_tpidr_offset`] with the offset the runtime measured for
//! itself, after reading the blob and before mapping it executable.
//!
//! The patch sites need no side table: everything from
//! [`SHARED_SVC_HANDLER_OFFSET`] onwards is an instruction word this module
//! emitted (the header's callback slot is the blob's only data), and the
//! placeholder saturates the scaled immediate, so a linear scan for it finds
//! exactly the gates' slot accesses. The scan additionally checks that each hit
//! has one of the two register shapes a gate emits, so a blob this crate did not
//! produce is rejected rather than silently mangled.
//!
//! The placeholder saturates the immediate to make that scan exact, and for no
//! other reason — it buys no run-time safety, because an unpatched gate does
//! not fault. See [`GUEST_TPIDR_OFFSET_PLACEHOLDER`]. A loader must therefore
//! call [`find_guest_tpidr_placeholder`] and refuse to map the trampoline if
//! anything is left.
//!
//! ## Signal returns
//!
//! This crate emits no sigreturn gate; `rt_sigreturn` is handled by the runtime.
//! The runtime installs its own sigreturn trampoline address into the signal
//! frame's return slot; because that is an absolute address (not a `B`), a
//! single runtime-owned gate is reachable from any guest regardless of the
//! ±128MB branch range, so no per-binary gate is required.
//!
//! ## Runtime contract
//!
//! Per thread, the runtime sets the hardware `TPIDR_EL0` to the host anchor and
//! reserves the guest thread-pointer slot at a fixed offset from it, which it
//! reports to the loader for [`patch_guest_tpidr_offset`].
//! No new callback ABI is introduced: the callback reaches host TLS through
//! `TPIDR_EL0` directly. Multi-threaded correctness depends only on the runtime
//! keeping the anchor valid and the slot reachable for every thread it starts;
//! no process-global table is involved, so concurrent threads never contend.
//!
//! ## Host-OS scope
//!
//! This module fully virtualizes the guest thread pointer against a stable
//! per-thread host anchor register. The model is host-OS-agnostic; only the
//! choice of anchor register varies per host, selected by [`Host`] (a gate names
//! its anchor through [`Host::anchor_read`]). On a Linux host the anchor is
//! `TPIDR_EL0` itself: the kernel preserves it across host execution, so the host
//! can keep its own value there as the anchor while the guest thread pointer
//! lives in the slot beside it. The instruction encoders and gate framing here
//! are host-agnostic; see [`Host`] for the per-host anchor registers and what
//! each additional host requires.

use alloc::format;
use alloc::vec::Vec;

use crate::{Error, Result, TextSectionInfo, checked_add_u64};

// ============================================================
// Constants
// ============================================================

/// `SVC #0` (supervisor call) — the canonical syscall instruction.
const SVC_0: u32 = 0xD400_0001;

/// Mask/match for *any* `SVC #imm16`. Linux dispatches every `SVC64` exception
/// to the syscall handler regardless of the immediate (the syscall number comes
/// from `x8`), so all immediates are rewritten, not just `svc #0`. The `imm16`
/// field occupies bits \[20:5]; masking it out leaves bits \[4:0] = `0b00001`,
/// which distinguishes `SVC` from `HVC` (`…0b10`) and `SMC` (`…0b11`).
const SVC_OPCODE_MASK: u32 = 0xFFE0_001F;
const SVC_OPCODE_BITS: u32 = SVC_0;

/// Mask/match for `MSR TPIDR_EL0, Xt` (`0xD51BD04t`, the low 5 bits select Xt).
const MSR_TPIDR_EL0_MASK: u32 = 0xFFFF_FFE0;
const MSR_TPIDR_EL0_BITS: u32 = 0xD51B_D040;

/// Mask/match for `MRS Xd, TPIDR_EL0` (`0xD53BD04d`, the low 5 bits select Xd).
const MRS_TPIDR_EL0_MASK: u32 = 0xFFFF_FFE0;
const MRS_TPIDR_EL0_BITS: u32 = 0xD53B_D040;

/// `BRK` immediate planted at a patch site whose gate lies outside the `B`
/// instruction's ±128MB reach. Executing the site raises a synchronous debug
/// exception (`SIGTRAP`) carrying this immediate, faulting the guest rather than
/// letting the unpatched instruction escape to the host kernel; the site is also
/// reported as a trapped site so the ELF-level caller can reject the binary.
///
/// Recognizing this immediate in the runtime — to attribute the trap to the
/// rewriter rather than a guest breakpoint — is planned but not yet implemented.
const TRAP_BRK_IMM: u16 = 0xB10B;

// --- Register operands used by the emitted gates/handlers ---
//
// X16/X17 are the intra-procedure scratch registers (IP0/IP1), and register
// number 31 names the stack pointer in a base-register position.

/// First scratch register (IP0).
const X16: u8 = 16;
/// Second scratch register (IP1).
const X17: u8 = 17;
/// Stack pointer (encoded as register 31 in a base-register field).
const SP: u8 = 31;
/// Zero register (register 31 in a transfer-register field, where it reads as
/// zero / discards writes — distinct from `SP`'s base-register meaning).
const XZR: u8 = 31;

// --- Guest thread-pointer virtualization ---
//
// The host owns the hardware `TPIDR_EL0` as a per-thread anchor; the guest's
// logical thread pointer is a memory slot the runtime reserves at some byte
// offset from that anchor. Every gated guest read/write of the thread pointer
// addresses the slot with a scaled `LDR`/`STR` off `TPIDR_EL0`. The rewriter
// does not know the offset -- it is a property of the *host* runtime's link, not
// of the guest binary -- so it emits a placeholder that the loader overwrites.

/// Largest value the `imm12` field of an unsigned-offset `LDR`/`STR` can hold.
///
/// The field is 12 bits wide and unsigned, so it counts `0..=0xFFF` *scaled
/// units*, not bytes.
const LDST_UIMM12_IMM_MAX: u16 = (1 << 12) - 1;

/// Scale applied to that `imm12` by the 64-bit form of the instruction, i.e.
/// the operand width in bytes.
///
/// A 64-bit `LDR Xt, [Xn, #imm]` multiplies the encoded immediate by 8, which
/// is both why the reachable offsets are sparse and why any offset the gates
/// address must be 8-aligned.
const LDST_UIMM12_SCALE_64BIT: u16 = 8;

/// Largest byte offset a 64-bit unsigned-offset `LDR`/`STR` can encode:
/// `0xFFF * 8 = 32760`.
///
/// Derived from the encoding rather than written out, because that is the only
/// thing that makes it true.
const LDR_UIMM12_MAX_BYTE_OFFSET: u16 = LDST_UIMM12_IMM_MAX * LDST_UIMM12_SCALE_64BIT;

/// Scale of the guest thread-pointer slot's `LDR`/`STR` immediate, i.e. the
/// alignment a runtime's slot must satisfy.
///
/// The gates address the slot with the 64-bit unsigned-offset `LDR`/`STR` form,
/// so this is exactly that form's scale. Re-exported as
/// [`crate::AARCH64_GUEST_TPIDR_OFFSET_ALIGN`].
pub const GUEST_TPIDR_OFFSET_ALIGN: u16 = LDST_UIMM12_SCALE_64BIT;

/// Largest byte offset from the host anchor at which a runtime may place the
/// guest thread-pointer slot. Re-exported as
/// [`crate::AARCH64_MAX_GUEST_TPIDR_OFFSET`].
///
/// This is not an independent policy choice: the gates reach the slot with a
/// single 64-bit unsigned-offset `LDR`/`STR`, so the bound *is*
/// `LDR_UIMM12_MAX_BYTE_OFFSET` and the two must not drift apart.
///
/// Far beyond any plausible static-TLS offset, so in practice this bound only
/// exists to be asserted.
pub const MAX_GUEST_TPIDR_OFFSET: u16 = LDR_UIMM12_MAX_BYTE_OFFSET;

/// Placeholder byte offset baked into every emitted gate's guest thread-pointer
/// access, to be replaced at load time by [`patch_guest_tpidr_offset`].
///
/// Deliberately [`MAX_GUEST_TPIDR_OFFSET`] — equivalently
/// `LDR_UIMM12_MAX_BYTE_OFFSET`, the largest value the field can hold —
/// because it cannot collide with a real runtime offset (a static TLS
/// control block 32KB past the thread pointer is not a thing). That makes a
/// scan for it exact: it can never mistake an already-patched gate for an
/// unpatched one, which is what lets both [`patch_guest_tpidr_offset`] and
/// [`find_guest_tpidr_placeholder`] work off the emitted words alone, with no
/// side table of patch sites.
///
/// It buys **no** safety at run time. An unpatched gate does not fault: it
/// reads and writes the same address 32KB past the host thread pointer, so it
/// is self-consistent and a guest using it behaves correctly while quietly
/// corrupting eight bytes of whatever the host happens to have mapped there.
/// Nothing may rely on an unpatched gate trapping. A loader must instead prove
/// no placeholder survives — see [`find_guest_tpidr_placeholder`] — before
/// making a trampoline executable.
pub const GUEST_TPIDR_OFFSET_PLACEHOLDER: u16 = MAX_GUEST_TPIDR_OFFSET;

// --- SVC gate stack frame ---
//
// The SVC gate touches only X16, so the frame holds just three words: the saved
// guest X16, the computed post-SVC return address, and the address of this
// site's outbound stub (which the runtime branches to in order to restore X16).
// Rounded up to the 16-byte stack alignment that makes 32.

/// SVC gate frame size (`SUB/ADD SP, SP, #SVC_FRAME_BYTES`). 16-byte aligned.
///
/// Part of the rewriter/runtime ABI: `switch_to_guest` sets `SP` to
/// `PtRegs::sp - SVC_FRAME_BYTES` before entering an outbound stub, because the
/// stub pops this frame. Re-exported as [`crate::AARCH64_SVC_FRAME_BYTES`].
pub const SVC_FRAME_BYTES: u16 = 32;
/// Saved guest X16. The outbound stub reloads `X16` from here, so this offset is
/// also ABI; re-exported as [`crate::AARCH64_SVC_FRAME_X16_OFFSET`].
pub const SVC_FRAME_OFF_X16: u16 = 0;
/// Computed post-SVC return address. Read by the runtime's syscall callback,
/// which publishes it as the guest resume PC, so this offset is also ABI;
/// re-exported as [`crate::AARCH64_SVC_FRAME_RETADDR_OFFSET`].
pub const SVC_FRAME_OFF_RETADDR: u16 = 8;
/// Address of this site's outbound stub. Read by the runtime's syscall callback
/// and used as the branch target when resuming at the original syscall site, so
/// this offset is ABI; re-exported as [`crate::AARCH64_SVC_FRAME_STUB_OFFSET`].
pub const SVC_FRAME_OFF_STUB: u16 = 16;

// The gate carves the frame out of the guest stack with `SUB SP`, so the frame
// must keep `SP` 16-byte aligned, and it must be large enough for the three
// words the gate writes into it.
const _: () = assert!(
    SVC_FRAME_BYTES.is_multiple_of(16),
    "the SVC gate frame must keep SP 16-byte aligned"
);
const _: () = assert!(
    SVC_FRAME_OFF_STUB + 8 <= SVC_FRAME_BYTES,
    "the SVC gate frame must hold the saved X16, the return address and the stub address"
);

/// Size of the SVC gate proper, i.e. the distance from the gate's first
/// instruction to its outbound stub. The gate is
/// `SUB SP / STR X16 / ADRP / ADD / STR / ADR / STR / B` = 8 instructions.
const SVC_GATE_BYTES: usize = 8 * 4;
/// Size of the per-site outbound stub (`LDR X16 / ADD SP / B`).
const SVC_OUTBOUND_STUB_BYTES: usize = 3 * 4;

// --- MSR gate stack frame ---
//
// The MSR gate spills X16/X17 (one `STP`/`LDP` pair) and stages the captured
// guest value so the source register needs no special-casing.

/// MSR gate frame size (`SUB/ADD SP, SP, #MSR_FRAME_BYTES`). 16-byte aligned.
const MSR_FRAME_BYTES: u16 = 32;
/// Saved X16 (and, +8, X17 via the `STP`/`LDP` pair).
const MSR_FRAME_OFF_X16: u16 = 0;
/// Captured guest thread-pointer value, staged while all guest registers are
/// still pristine.
const MSR_FRAME_OFF_VALUE: u16 = 16;

// --- Trampoline layout offsets (all in bytes) ---

/// Callback address slot.
const HEADER_CALLBACK_OFFSET: usize = 0;

/// Shared SVC handler, placed just past the 8-byte callback slot. Per-site gates
/// follow it and are each appended dynamically, so this shared prologue is the
/// only fixed-offset region the emitters reference.
const SHARED_SVC_HANDLER_OFFSET: usize = HEADER_CALLBACK_OFFSET + 8;

/// Size of the shared SVC handler (`LDR X16, =callback ; BR X16`).
const SHARED_SVC_HANDLER_BYTES: usize = 2 * 4;

/// First byte of the per-site gates, i.e. the total size of the shared prologue.
/// Everything from [`SHARED_SVC_HANDLER_OFFSET`] onwards is instructions this
/// module emitted, which is what lets [`patch_guest_tpidr_offset`] scan for its
/// patch sites instead of carrying a side table of them.
const GATES_START_OFFSET: usize = SHARED_SVC_HANDLER_OFFSET + SHARED_SVC_HANDLER_BYTES;

// ============================================================
// Instruction encoders
//
// Each encoder returns the 32-bit little-endian instruction word. Encoders that
// can fail range checks return `Option`; callers convert `None` into an
// `Error::AddressOverflow` with context.
//
// Each encoder ORs an [`Opcode`] base with its shifted, masked operands. The
// `IMM*_MASK` values isolate the immediate fields shared by several encoders.
// ============================================================

/// 26-bit `imm26` branch-offset field (`B`/`BL`), bits \[25:0].
const IMM26_MASK: u32 = 0x03FF_FFFF;
/// 19-bit `imm19` offset field (`B.cond`/`LDR`-literal/`ADRP` immhi), bits \[18:0].
const IMM19_MASK: u32 = 0x0007_FFFF;

/// Base opcode of an emitted instruction: every fixed bit set with all operand
/// fields zeroed. An encoder selects a variant and ORs in its operands via
/// [`Opcode::bits`]. (`MRS TPIDR_EL0` is encoded from [`Opcode::MrsTpidrEl0`],
/// whose bits equal [`MRS_TPIDR_EL0_BITS`] — the scan-detection pattern in
/// [`find_patch_sites`].)
#[repr(u32)]
#[derive(Clone, Copy)]
enum Opcode {
    B = 0x1400_0000,
    LdrLiteral = 0x5800_0000,
    Adr = 0x1000_0000,
    Adrp = 0x9000_0000,
    Br = 0xD61F_0000,
    SubImm = 0xD100_0000,
    AddImm = 0x9100_0000,
    StrUimm = 0xF900_0000,
    LdrUimm = 0xF940_0000,
    Stp = 0xA900_0000,
    Ldp = 0xA940_0000,
    MrsTpidrEl0 = MRS_TPIDR_EL0_BITS,
    Brk = 0xD420_0000,
}

impl Opcode {
    /// The base opcode word, for ORing in operand fields.
    const fn bits(self) -> u32 {
        self as u32
    }
}

// --- Shared instruction-format encoders ---
//
// Several instructions share one field layout and differ only by opcode, so
// each layout is encoded once here and selected by an `Opcode`. [`Insn::encode`]
// dispatches each variant to its format here; every range check lives in exactly
// one place per format.

/// `op | imm26` — PC-relative branch (`B`/`BL`), ±128MB, 4-byte aligned.
fn branch_imm26(op: Opcode, offset: i64) -> Option<u32> {
    if offset % 4 != 0 {
        return None;
    }
    let imm26 = i32::try_from(offset >> 2).ok()?;
    if !(-(1 << 25)..(1 << 25)).contains(&imm26) {
        return None;
    }
    Some(op.bits() | (imm26.cast_unsigned() & IMM26_MASK))
}

/// `op | imm19<<5 | low` — PC-relative imm19 form (`B.cond`/`LDR`-literal), ±1MB,
/// 4-byte aligned. `low` is the instruction's 5-bit \[4:0] field: `Rt`, or the
/// condition code for `B.cond`.
fn pcrel_imm19(op: Opcode, offset: i64, low: u32) -> Option<u32> {
    if offset % 4 != 0 {
        return None;
    }
    let imm19 = i32::try_from(offset >> 2).ok()?;
    if !(-(1 << 18)..(1 << 18)).contains(&imm19) {
        return None;
    }
    Some(op.bits() | ((imm19.cast_unsigned() & IMM19_MASK) << 5) | low)
}

/// `op | immlo<<29 | immhi<<5 | rd` — 21-bit-signed PC-relative address form
/// (`ADR`/`ADRP`). The units of `imm` are the instruction's own: bytes for
/// `ADR` (±1MB), 4KB pages for `ADRP` (±4GB).
fn pcrel_imm21(op: Opcode, rd: u8, imm: i64) -> Option<u32> {
    let imm = i32::try_from(imm).ok()?;
    if !(-(1 << 20)..(1 << 20)).contains(&imm) {
        return None;
    }
    let imm = imm.cast_unsigned();
    let immlo = (imm & 0x3) << 29;
    let immhi = ((imm >> 2) & IMM19_MASK) << 5;
    Some(op.bits() | immlo | immhi | u32::from(rd))
}

/// `op | rn<<5` — instruction whose only operand is a register in the `Rn` field
/// (`BR`/`RET`).
fn reg_in_rn(op: Opcode, rn: u8) -> u32 {
    op.bits() | (u32::from(rn) << 5)
}

/// `op | imm12<<10 | rn<<5 | rd` — 12-bit-immediate add/sub form
/// (`ADD`/`SUB`/`ADDS`). The caller supplies an already-scaled `imm12`.
fn data_imm12(op: Opcode, rd: u8, rn: u8, imm12: u16) -> Option<u32> {
    if imm12 >= (1 << 12) {
        return None;
    }
    Some(op.bits() | (u32::from(imm12) << 10) | (u32::from(rn) << 5) | u32::from(rd))
}

/// `op | imm12<<10 | rn<<5 | rt` — unsigned scaled (×8) 64-bit load/store
/// (`STR`/`LDR [Xn, #imm]`). `imm_bytes` must be a multiple of
/// `LDST_UIMM12_SCALE_64BIT` and at most `LDR_UIMM12_MAX_BYTE_OFFSET`.
fn ldst_uimm12(op: Opcode, rt: u8, rn: u8, imm_bytes: u16) -> Option<u32> {
    if !imm_bytes.is_multiple_of(LDST_UIMM12_SCALE_64BIT) || imm_bytes > LDR_UIMM12_MAX_BYTE_OFFSET
    {
        return None;
    }
    let imm12 = imm_bytes / LDST_UIMM12_SCALE_64BIT;
    Some(
        op.bits()
            | (u32::from(imm12) << LDST_UIMM12_IMM_SHIFT)
            | (u32::from(rn) << 5)
            | u32::from(rt),
    )
}

/// `op | imm7<<15 | rt2<<10 | rn<<5 | rt` — signed scaled (×8) 64-bit load/store
/// pair (`STP`/`LDP`). `imm_bytes` must be a multiple of 8 within ±512 bytes.
fn ldst_pair(op: Opcode, rt: u8, rt2: u8, rn: u8, imm_bytes: i16) -> Option<u32> {
    if imm_bytes % 8 != 0 {
        return None;
    }
    let imm7 = imm_bytes / 8;
    if !(-64..=63).contains(&imm7) {
        return None;
    }
    let imm7_u = u32::from(imm7.cast_unsigned() & 0x7F);
    Some(op.bits() | (imm7_u << 15) | (u32::from(rt2) << 10) | (u32::from(rn) << 5) | u32::from(rt))
}

/// `base | rt` — system-register move (`MRS`/`MSR`); `base` already encodes the
/// system register and transfer direction.
fn sysreg_move(base: u32, rt: u8) -> u32 {
    base | u32::from(rt)
}

/// A single AArch64 instruction emitted into a trampoline, described by its
/// mnemonic and operands. [`Insn::encode`] produces the 32-bit little-endian
/// word; range-checked forms return `None` when an operand is out of range.
///
/// Register operands are register numbers (`X16`, `SP`, ...). This enum, with
/// the format helpers above, is the only place instruction bit layouts live;
/// the gate emitters build `Insn` values and never touch raw opcodes.
#[derive(Clone, Copy)]
enum Insn {
    /// `B` (unconditional branch), PC-relative, ±128MB, 4-byte aligned.
    B(i64),
    /// `ADR Xd, #byte_off` — PC-relative address, ±1MB (byte granularity).
    Adr { rd: u8, byte_off: i64 },
    /// `ADRP Xd, #page_off` — page-relative address, ±4GB (in 4KB pages).
    Adrp { rd: u8, page_off: i64 },
    /// `LDR Xt, <literal>` (PC-relative literal load), ±1MB, 4-byte aligned.
    LdrLiteral { rt: u8, off: i64 },
    /// `BR Xn` (branch to register).
    Br(u8),
    /// `SUB SP, SP, #imm12`.
    SubSp(u16),
    /// `ADD SP, SP, #imm12`.
    AddSp(u16),
    /// `ADD Xd, Xn, #imm12`.
    AddImm { rd: u8, rn: u8, imm12: u16 },
    /// `STR Xt, [Xn, #imm_bytes]` (unsigned scaled; `imm_bytes` multiple of 8).
    StrUimm { rt: u8, rn: u8, imm_bytes: u16 },
    /// `LDR Xt, [Xn, #imm_bytes]` (unsigned scaled; `imm_bytes` multiple of 8).
    LdrUimm { rt: u8, rn: u8, imm_bytes: u16 },
    /// `STP Xt, Xt2, [Xn, #imm_bytes]` (signed scaled; `imm_bytes` multiple of 8).
    Stp {
        rt: u8,
        rt2: u8,
        rn: u8,
        imm_bytes: i16,
    },
    /// `LDP Xt, Xt2, [Xn, #imm_bytes]` (signed scaled; `imm_bytes` multiple of 8).
    Ldp {
        rt: u8,
        rt2: u8,
        rn: u8,
        imm_bytes: i16,
    },
    /// `MRS Xt, TPIDR_EL0` (read thread pointer).
    MrsTpidrEl0(u8),
    /// `BRK #imm16` — software breakpoint raising a synchronous debug exception.
    Brk(u16),
}

impl Insn {
    /// Encode to a 32-bit little-endian instruction word, or `None` if an
    /// operand is outside the instruction's encodable range.
    fn encode(self) -> Option<u32> {
        match self {
            Insn::B(off) => branch_imm26(Opcode::B, off),
            Insn::Adr { rd, byte_off } => pcrel_imm21(Opcode::Adr, rd, byte_off),
            Insn::Adrp { rd, page_off } => pcrel_imm21(Opcode::Adrp, rd, page_off),
            Insn::LdrLiteral { rt, off } => pcrel_imm19(Opcode::LdrLiteral, off, u32::from(rt)),
            Insn::Br(rn) => Some(reg_in_rn(Opcode::Br, rn)),
            Insn::SubSp(imm12) => data_imm12(Opcode::SubImm, SP, SP, imm12),
            Insn::AddSp(imm12) => data_imm12(Opcode::AddImm, SP, SP, imm12),
            Insn::AddImm { rd, rn, imm12 } => data_imm12(Opcode::AddImm, rd, rn, imm12),
            Insn::StrUimm { rt, rn, imm_bytes } => ldst_uimm12(Opcode::StrUimm, rt, rn, imm_bytes),
            Insn::LdrUimm { rt, rn, imm_bytes } => ldst_uimm12(Opcode::LdrUimm, rt, rn, imm_bytes),
            Insn::Stp {
                rt,
                rt2,
                rn,
                imm_bytes,
            } => ldst_pair(Opcode::Stp, rt, rt2, rn, imm_bytes),
            Insn::Ldp {
                rt,
                rt2,
                rn,
                imm_bytes,
            } => ldst_pair(Opcode::Ldp, rt, rt2, rn, imm_bytes),
            Insn::MrsTpidrEl0(rt) => Some(sysreg_move(Opcode::MrsTpidrEl0.bits(), rt)),
            Insn::Brk(imm) => Some(Opcode::Brk.bits() | (u32::from(imm) << 5)),
        }
    }
}

// ============================================================
// Host anchor selection
// ============================================================

/// The host OS the rewritten guest runs under.
///
/// The guest thread pointer is virtualized the same way on every host; only the
/// *anchor register* a gate reads to reach the host's per-thread block varies.
/// [`Host`] selects that register, so a gate names the anchor through
/// [`Host::anchor_read`] rather than hardcoding a system register. Adding a host
/// is a new variant plus its anchor-read arm.
///
/// Other host OSes need a different stable anchor register (a future variant
/// supplying its own [`Host::anchor_read`]), and beyond that a host-specific
/// shared SVC handler — not just a different trampoline base address:
///
/// * **Linux-on-macOS** (Apple Silicon): XNU clobbers `TPIDR_EL0` on
///   signals/preemption and zeroes `x18` on every exception entry, so neither
///   register survives a host transition. The stable anchor becomes the
///   read-only `TPIDRRO_EL0` (which XNU keeps per-pthread), and *both*
///   `TPIDR_EL0` and `x18` must be fully virtualized — `x18` via per-site gates.
/// * **Linux-on-Windows** (Windows on ARM64): Windows does not preserve
///   `TPIDR_EL0` across context switches and reserves `x18` as the TEB pointer
///   (always valid). The TEB is the stable anchor: the per-thread TLS state is
///   reached through a TEB TLS slot, and `TPIDR_EL0` (plus guest `x18`, where the
///   guest uses it) is virtualized against that.
#[derive(Clone, Copy)]
pub(crate) enum Host {
    /// Linux host. The kernel preserves `TPIDR_EL0` across host execution, so the
    /// host keeps its anchor there and the guest thread-pointer slot lives beside
    /// it; the anchor read is `MRS Xd, TPIDR_EL0`.
    Linux,
}

impl Host {
    /// The instruction a gate uses to read this host's per-thread anchor into
    /// `rd`.
    fn anchor_read(self, rd: u8) -> Insn {
        match self {
            Host::Linux => Insn::MrsTpidrEl0(rd),
        }
    }
}

// ============================================================
// Patch-site scanning
// ============================================================

/// A located instruction to rewrite.
struct PatchSite {
    /// Byte offset of the instruction within the ELF file image.
    file_offset: usize,
    /// Virtual address of the instruction.
    vaddr: u64,
    kind: PatchKind,
}

/// The kind of instruction at a [`PatchSite`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PatchKind {
    /// `SVC #imm` for any immediate. Linux dispatches every `SVC64` to the
    /// syscall handler regardless of the immediate (the number comes from `x8`),
    /// so the immediate is not significant and is not recorded.
    Svc,
    /// `MSR TPIDR_EL0, Xt`; the `u8` is the source register (0-31).
    MsrTpidr(u8),
    /// `MRS Xd, TPIDR_EL0`; the `u8` is the destination register (0-30).
    MrsTpidr(u8),
}

/// Scan all executable sections for `SVC #imm`, `MSR TPIDR_EL0` (thread-pointer
/// writes), and `MRS TPIDR_EL0` (thread-pointer reads). AArch64 instructions are
/// always 4-byte aligned, so we step in 4-byte units. Returns sites in ascending
/// file order.
///
/// `MRS XZR, TPIDR_EL0` is a discarded read (register 31 as an `LDR` base would
/// mean `SP`), so it is left native; every other `MRS Xd, TPIDR_EL0` is gated.
fn find_patch_sites(sections: &[TextSectionInfo], buf: &[u8]) -> Result<Vec<PatchSite>> {
    let mut sites = Vec::new();

    for section in sections {
        let start = usize::try_from(section.file_offset)
            .map_err(|_| Error::ParseError("section file offset too large".into()))?;
        let size = usize::try_from(section.size)
            .map_err(|_| Error::ParseError("section size too large".into()))?;
        let end = start
            .checked_add(size)
            .filter(|&e| e <= buf.len())
            .ok_or_else(|| Error::ParseError("section extends beyond file".into()))?;
        let section_data = &buf[start..end];

        for i in (0..section_data.len()).step_by(4) {
            if i + 4 > section_data.len() {
                break;
            }
            let insn = u32::from_le_bytes(section_data[i..i + 4].try_into().unwrap());
            let kind = if (insn & SVC_OPCODE_MASK) == SVC_OPCODE_BITS {
                PatchKind::Svc
            } else if (insn & MSR_TPIDR_EL0_MASK) == MSR_TPIDR_EL0_BITS {
                PatchKind::MsrTpidr((insn & 0x1F) as u8)
            } else if (insn & MRS_TPIDR_EL0_MASK) == MRS_TPIDR_EL0_BITS {
                let rd = (insn & 0x1F) as u8;
                // `MRS XZR, TPIDR_EL0` discards its result (a no-op read); gating
                // it would mean using register 31 as an `LDR` base (= SP), so
                // leave it native.
                if rd == XZR {
                    continue;
                }
                PatchKind::MrsTpidr(rd)
            } else {
                continue;
            };
            sites.push(PatchSite {
                file_offset: start + i,
                vaddr: checked_add_u64(section.vaddr, i as u64, "patch site")?,
                kind,
            });
        }
    }

    Ok(sites)
}

// ============================================================
// Main hooking entry point
// ============================================================

/// Outcome of rewriting one AArch64 image's patch sites.
pub(crate) struct HookOutcome {
    /// Trampoline blob the caller appends after the ELF (page-aligned).
    pub trampoline: Vec<u8>,
    /// Virtual addresses of patch sites that could not be redirected to their
    /// gate — the inbound `B` or one of the gate's own branches fell outside the
    /// branch's ±128MB range — and were replaced with a trap instead of a
    /// redirect. A non-empty list means the rewrite is incomplete: those sites
    /// fault at runtime rather than entering the trampoline.
    pub trapped_sites: Vec<u64>,
}

/// Hook all `SVC #imm`, `MSR TPIDR_EL0` writes, and `MRS TPIDR_EL0` reads in an
/// AArch64 ELF image. (`MRS XZR, TPIDR_EL0` is a discarded read and is left
/// native — see the module docs.)
///
/// `buf` is patched in place; the returned [`HookOutcome::trampoline`] is the
/// blob that the caller appends after the ELF (page-aligned).
/// `trampoline_base_addr` is the virtual address the trampoline will be mapped
/// at; `callback` is the absolute address stored in the callback slot (0 if the
/// loader fills it in later).
///
/// Returns `Ok(None)` when the image contains no patch sites: no trampoline is
/// needed and the caller emits a size-0 sentinel header instead (matching the
/// x86-64 path). Signal returns are handled by the runtime — not a per-binary
/// gate — so a syscall-free binary needs no trampoline at all.
///
/// Otherwise returns `Ok(Some(outcome))`. A site whose inbound `B` cannot reach
/// its gate, or whose gate cannot branch back within the `B` instruction's
/// ±128MB reach, cannot be redirected; it is replaced with a trap and listed in
/// [`HookOutcome::trapped_sites`] so the caller can reject the incomplete
/// rewrite, mirroring the x86-64 unpatchable-syscall path.
pub(crate) fn hook_syscalls_aarch64(
    buf: &mut [u8],
    text_sections: &[TextSectionInfo],
    trampoline_base_addr: u64,
    callback: u64,
    host: Host,
) -> Result<Option<HookOutcome>> {
    let sites = find_patch_sites(text_sections, buf)?;

    if sites.is_empty() {
        // No patch sites: nothing to redirect, so no trampoline is
        // emitted. The caller writes a size-0 sentinel header instead.
        return Ok(None);
    }

    let mut trampoline_data: Vec<u8> = Vec::new();
    emit_shared_prologue(&mut trampoline_data, trampoline_base_addr, callback)?;

    let mut trapped_sites: Vec<u64> = Vec::new();

    for site in &sites {
        let gate_offset = trampoline_data.len();
        let gate_vaddr =
            checked_add_u64(trampoline_base_addr, gate_offset as u64, "trampoline gate")?;

        // A site is redirected to its gate with a single in-place `B` (±128MB
        // forward reach), and each gate branches back to `site + 4` (the SVC gate
        // also reaches its shared handler). The gate's return branch spans a wider
        // displacement than the inbound one, so the inbound branch encoding is
        // necessary but not sufficient: the gate is built only when the inbound
        // branch fits, and a gate whose own branches are out of range reports
        // `GateBuild::Unreachable` and appends nothing. If either the inbound
        // branch or the gate is unreachable, replace the site with the sentinel
        // trap, record it as unpatchable, and emit no gate.
        let b_offset = gate_vaddr
            .cast_signed()
            .saturating_sub(site.vaddr.cast_signed());
        let inbound = Insn::B(b_offset).encode();

        let build = if inbound.is_some() {
            match site.kind {
                PatchKind::Svc => emit_svc_gate(
                    &mut trampoline_data,
                    gate_offset,
                    trampoline_base_addr,
                    site,
                )?,
                PatchKind::MsrTpidr(rt) => emit_msr_gate(
                    &mut trampoline_data,
                    gate_offset,
                    trampoline_base_addr,
                    site,
                    rt,
                    host,
                )?,
                PatchKind::MrsTpidr(rd) => emit_mrs_gate(
                    &mut trampoline_data,
                    gate_offset,
                    trampoline_base_addr,
                    site,
                    rd,
                    host,
                )?,
            }
        } else {
            GateBuild::Unreachable
        };

        if let (Some(b_insn), GateBuild::Emitted) = (inbound, build) {
            // Replace the original instruction with `B <gate>`.
            buf[site.file_offset..site.file_offset + 4].copy_from_slice(&b_insn.to_le_bytes());
        } else {
            let brk = Insn::Brk(TRAP_BRK_IMM)
                .encode()
                .expect("BRK always encodes");
            buf[site.file_offset..site.file_offset + 4].copy_from_slice(&brk.to_le_bytes());
            trapped_sites.push(site.vaddr);
        }
    }

    Ok(Some(HookOutcome {
        trampoline: trampoline_data,
        trapped_sites,
    }))
}

/// Emit the header slot and the shared SVC handler — the fixed-size shared
/// prologue that per-site gates follow.
fn emit_shared_prologue(
    trampoline_data: &mut Vec<u8>,
    trampoline_base_addr: u64,
    callback: u64,
) -> Result<()> {
    // Offset 0: callback address.
    trampoline_data.extend_from_slice(&callback.to_le_bytes());

    emit_shared_svc_handler(
        trampoline_data,
        SHARED_SVC_HANDLER_OFFSET,
        trampoline_base_addr,
    )?;

    Ok(())
}

// ============================================================
// SVC gate + shared SVC handler
// ============================================================

/// Whether a gate was fully emitted or could not be placed within reach.
///
/// A gate redirects back to the guest (and, for the SVC gate, out to the shared
/// handler) with PC-relative branches. When any of those branches is out of
/// range the gate emits nothing and reports [`GateBuild::Unreachable`], leaving
/// the trampoline blob untouched so the caller can trap the originating site.
enum GateBuild {
    Emitted,
    Unreachable,
}

/// Per-site SVC gate (8 instructions, 32 bytes, 32-byte frame) plus its
/// outbound stub (3 instructions, 12 bytes) — 44 bytes emitted per site.
///
/// The gate saves only X16 (already a scratch register), computes the post-SVC
/// return address into X16 and records it on the frame, records the address of
/// this site's outbound stub alongside it, then branches to the shared SVC
/// handler. Guest X17/X18/LR and NZCV are untouched.
///
/// Frame layout (relative to the decremented SP):
/// `[0]=X16 [8]=return_addr [16]=outbound_stub [24]=pad`.
/// Requires `SP` to address a valid writable stack at the site (see the module
/// docs, "Gate scratch storage and the stack invariant").
///
/// ## The outbound stub
///
/// The stub is emitted immediately after the gate and is the runtime's normal
/// way back into the guest. Its listing, why it exists, and the limits of its
/// validity are in the module docs, "Callback register contract: `X16` is
/// preserved across an `SVC`".
fn emit_svc_gate(
    trampoline_data: &mut Vec<u8>,
    gate_offset: usize,
    trampoline_base_addr: u64,
    site: &PatchSite,
) -> Result<GateBuild> {
    let gate_vaddr = checked_add_u64(trampoline_base_addr, gate_offset as u64, "SVC gate")?;
    let mut asm = Asm::new(gate_vaddr);

    // SUB SP, SP, #32 ; STR X16, [SP] — save the guest X16.
    asm.emit(Insn::SubSp(SVC_FRAME_BYTES));
    asm.emit(Insn::StrUimm {
        rt: X16,
        rn: SP,
        imm_bytes: SVC_FRAME_OFF_X16,
    });

    // ADRP X16, <return_page>; ADD X16, X16, #<page offset> — post-SVC return
    // address.
    let return_addr = checked_add_u64(site.vaddr, 4, "SVC return")?;
    if !asm.adrp(X16, return_addr)? {
        return Ok(GateBuild::Unreachable);
    }
    let page_lo = u16::try_from(return_addr & 0xFFF).expect("masked to 12 bits");
    asm.emit(Insn::AddImm {
        rd: X16,
        rn: X16,
        imm12: page_lo,
    });

    // STR X16, [SP, #8] — record the return address.
    asm.emit(Insn::StrUimm {
        rt: X16,
        rn: SP,
        imm_bytes: SVC_FRAME_OFF_RETADDR,
    });

    // ADR X16, <outbound stub> ; STR X16, [SP, #16] — record the stub. The stub
    // starts right after this gate's last instruction, well within ADR's ±1MB
    // reach, so a single ADR suffices (no ADRP/ADD pair).
    let stub_vaddr = checked_add_u64(gate_vaddr, SVC_GATE_BYTES as u64, "SVC outbound stub")?;
    if !asm.adr(X16, stub_vaddr)? {
        return Ok(GateBuild::Unreachable);
    }
    asm.emit(Insn::StrUimm {
        rt: X16,
        rn: SP,
        imm_bytes: SVC_FRAME_OFF_STUB,
    });

    // B <shared SVC handler>.
    let handler_vaddr = checked_add_u64(
        trampoline_base_addr,
        SHARED_SVC_HANDLER_OFFSET as u64,
        "SVC handler",
    )?;
    if !asm.branch_to(handler_vaddr)? {
        return Ok(GateBuild::Unreachable);
    }

    debug_assert_eq!(
        asm.here()?,
        stub_vaddr,
        "the outbound stub must start immediately after the gate"
    );

    // The outbound stub: LDR X16, [SP] ; ADD SP, SP, #32 ; B <site+4>.
    asm.emit(Insn::LdrUimm {
        rt: X16,
        rn: SP,
        imm_bytes: SVC_FRAME_OFF_X16,
    });
    asm.emit(Insn::AddSp(SVC_FRAME_BYTES));
    if !asm.branch_to(return_addr)? {
        return Ok(GateBuild::Unreachable);
    }

    debug_assert_eq!(
        asm.here()?,
        checked_add_u64(stub_vaddr, SVC_OUTBOUND_STUB_BYTES as u64, "SVC stub end")?,
        "the outbound stub must be SVC_OUTBOUND_STUB_BYTES long"
    );

    trampoline_data.extend_from_slice(&asm.finish());
    Ok(GateBuild::Emitted)
}

/// Shared SVC handler (2 instructions, 8 bytes).
///
/// A thin shim that conveys nothing TLS-related: it loads the syscall-callback
/// pointer from the trampoline header and tail-jumps to it. The callback reads
/// host TLS from `TPIDR_EL0` (the host anchor) and the guest thread pointer from
/// `[TPIDR_EL0 + guest_tpidr_offset]` itself, so the handler carries no TLS state.
///
/// Nothing in the handler clobbers NZCV, so the guest's pre-svc flags reach the
/// callback unchanged with no save/restore.
fn emit_shared_svc_handler(
    trampoline_data: &mut Vec<u8>,
    handler_offset: usize,
    trampoline_base_addr: u64,
) -> Result<()> {
    let handler_vaddr =
        checked_add_u64(trampoline_base_addr, handler_offset as u64, "SVC handler")?;
    let callback_vaddr = checked_add_u64(
        trampoline_base_addr,
        HEADER_CALLBACK_OFFSET as u64,
        "callback slot",
    )?;
    let mut asm = Asm::new(handler_vaddr);

    // LDR X16, =callback ; BR X16. Nothing here clobbers NZCV, so the guest's
    // pre-svc flags reach the callback unchanged with no save/restore.
    asm.ldr_literal(X16, callback_vaddr)?;
    asm.emit(Insn::Br(X16));

    trampoline_data.extend_from_slice(&asm.finish());
    Ok(())
}

// ============================================================
// MSR + MRS gates
// ============================================================

/// Per-site MSR gate (9 instructions, 36 bytes, 32-byte frame).
///
/// Virtualizes a guest `MSR TPIDR_EL0, Xn` write. The hardware register holds the
/// host anchor, so the gate stores the guest value into the guest thread-pointer
/// slot at `[TPIDR_EL0 + guest_tpidr_offset]`:
///
/// 1. spill X16/X17 and capture the guest value `Xn` to the frame while all guest
///    registers are still pristine (so `Xn` needs no special-casing, even when it
///    is one of the scratch registers just spilled (X16/X17) or XZR);
/// 2. `MRS X16, TPIDR_EL0` reads the host anchor;
/// 3. reload the captured value into X17 and `STR X17, [X16, #guest_tpidr_offset]`
///    stores it into the guest thread-pointer slot;
/// 4. restore X16/X17 and branch back to the instruction after the original MSR.
///
/// The slot is always reachable because `TPIDR_EL0` is the host anchor the
/// runtime keeps valid, so a guest value of `0` (XZR) is an ordinary store — never
/// a fault.
///
/// The X16/X17 spill and the captured value use a guest-stack frame, so this gate
/// requires `SP` to address a valid writable stack at the site (see the module
/// docs, "Gate scratch storage and the stack invariant").
///
/// `MSR TPIDR_EL0` does not touch the condition flags and the gate uses only
/// plain loads/stores and `B` (never `BL`), so NZCV and X30 reach the guest
/// unchanged with no save/restore.
fn emit_msr_gate(
    trampoline_data: &mut Vec<u8>,
    gate_offset: usize,
    trampoline_base_addr: u64,
    site: &PatchSite,
    rt: u8,
    host: Host,
) -> Result<GateBuild> {
    let gate_vaddr = checked_add_u64(trampoline_base_addr, gate_offset as u64, "MSR gate")?;
    let mut asm = Asm::new(gate_vaddr);

    // SUB SP, SP, #32 ; STP X16, X17, [SP] — spill the gate's scratch registers.
    asm.emit(Insn::SubSp(MSR_FRAME_BYTES));
    asm.emit(Insn::Stp {
        rt: X16,
        rt2: X17,
        rn: SP,
        imm_bytes: MSR_FRAME_OFF_X16.cast_signed(),
    });

    // STR Xn, [SP, #16] — capture the guest value while all guest registers are
    // still pristine, so Xn needs no special-casing even when it is one of the
    // scratch registers just spilled (X16/X17) or XZR.
    asm.emit(Insn::StrUimm {
        rt,
        rn: SP,
        imm_bytes: MSR_FRAME_OFF_VALUE,
    });

    // MRS X16, <host anchor> — read the host anchor.
    asm.emit(host.anchor_read(X16));

    // LDR X17, [SP, #16] ; STR X17, [X16, #<tpidr offset>] — store the guest
    // value into its slot off the host anchor.
    asm.emit(Insn::LdrUimm {
        rt: X17,
        rn: SP,
        imm_bytes: MSR_FRAME_OFF_VALUE,
    });
    asm.emit(Insn::StrUimm {
        rt: X17,
        rn: X16,
        imm_bytes: GUEST_TPIDR_OFFSET_PLACEHOLDER,
    });

    // Restore: LDP X16, X17, [SP] ; ADD SP, SP, #32.
    asm.emit(Insn::Ldp {
        rt: X16,
        rt2: X17,
        rn: SP,
        imm_bytes: MSR_FRAME_OFF_X16.cast_signed(),
    });
    asm.emit(Insn::AddSp(MSR_FRAME_BYTES));

    // B <return_addr>.
    if !asm.branch_to(checked_add_u64(site.vaddr, 4, "MSR return")?)? {
        return Ok(GateBuild::Unreachable);
    }

    trampoline_data.extend_from_slice(&asm.finish());
    Ok(GateBuild::Emitted)
}

/// Per-site MRS gate (3 instructions, 12 bytes).
///
/// Virtualizes a guest `MRS Xd, TPIDR_EL0` read. The hardware register holds the
/// host anchor, so the gate reads the anchor and then loads the guest thread
/// pointer from its slot, reusing `Xd` as scratch (no frame needed):
/// `MRS Xd, TPIDR_EL0 ; LDR Xd, [Xd, #guest_tpidr_offset] ; B <site+4>`.
fn emit_mrs_gate(
    trampoline_data: &mut Vec<u8>,
    gate_offset: usize,
    trampoline_base_addr: u64,
    site: &PatchSite,
    rd: u8,
    host: Host,
) -> Result<GateBuild> {
    let gate_vaddr = checked_add_u64(trampoline_base_addr, gate_offset as u64, "MRS gate")?;
    let mut asm = Asm::new(gate_vaddr);
    asm.emit(host.anchor_read(rd));
    asm.emit(Insn::LdrUimm {
        rt: rd,
        rn: rd,
        imm_bytes: GUEST_TPIDR_OFFSET_PLACEHOLDER,
    });
    if !asm.branch_to(checked_add_u64(site.vaddr, 4, "MRS return")?)? {
        return Ok(GateBuild::Unreachable);
    }
    trampoline_data.extend_from_slice(&asm.finish());
    Ok(GateBuild::Emitted)
}

// ============================================================
// Load-time guest thread-pointer offset patching
// ============================================================

/// Bits \[31:10] of an unsigned-offset load/store: everything except `Rn`
/// (\[9:5]) and `Rt` (\[4:0]), i.e. the opcode *and* the scaled `imm12`.
const LDST_UIMM12_OPCODE_AND_IMM_MASK: u32 = 0xFFFF_FC00;
/// The scaled 12-bit immediate field of an unsigned-offset load/store, \[21:10].
const LDST_UIMM12_IMM_MASK: u32 = 0x003F_FC00;
/// Bit position of that immediate field.
const LDST_UIMM12_IMM_SHIFT: u32 = 10;

/// Rewrites the guest thread-pointer offset in every gate of one emitted
/// trampoline, replacing [`GUEST_TPIDR_OFFSET_PLACEHOLDER`] with `offset`.
///
/// The rewriter cannot know this offset: it is the thread-pointer-relative
/// address of the *host* runtime's TLS control block, fixed by the host
/// binary's link, and the same rewritten guest binary must run under any host
/// build. So the gates are emitted with a placeholder and the loader supplies
/// the runtime's measured offset here, before the trampoline is made
/// executable and before any guest code runs.
///
/// Returns the number of instructions patched. Zero is normal and not an error:
/// a binary whose only patch sites are `SVC` has no thread-pointer gate.
///
/// # Errors
///
/// Fails if `offset` is not addressable by a gate (not a multiple of
/// [`GUEST_TPIDR_OFFSET_ALIGN`], or above [`MAX_GUEST_TPIDR_OFFSET`]), or if
/// the blob is not a well-formed trampoline — either too short to hold the
/// shared prologue, not a whole number of instruction words, or containing a
/// placeholder-bearing instruction in a shape no gate emits. All three mean the
/// caller is about to run something this rewriter did not produce, so failing
/// is the only safe answer.
pub(crate) fn patch_guest_tpidr_offset(trampoline: &mut [u8], offset: u16) -> Result<usize> {
    if !offset.is_multiple_of(GUEST_TPIDR_OFFSET_ALIGN) || offset > MAX_GUEST_TPIDR_OFFSET {
        return Err(Error::TrampolinePatchFailure(format!(
            "guest thread-pointer offset {offset} is not addressable by a gate: it must be a \
             multiple of {GUEST_TPIDR_OFFSET_ALIGN} and at most {MAX_GUEST_TPIDR_OFFSET}"
        )));
    }

    // Skip the header: its callback slot holds an arbitrary 64-bit address,
    // which — unlike everything from the shared SVC handler onwards — is data
    // and could bit-for-bit resemble an instruction. Everything at or after
    // `SHARED_SVC_HANDLER_OFFSET` is a word the emitters above produced.
    if trampoline.len() < GATES_START_OFFSET {
        return Err(Error::TrampolinePatchFailure(format!(
            "trampoline is {} bytes, too short to hold the {GATES_START_OFFSET}-byte shared \
             prologue",
            trampoline.len()
        )));
    }
    if !trampoline.len().is_multiple_of(4) {
        return Err(Error::TrampolinePatchFailure(format!(
            "trampoline is {} bytes, not a whole number of AArch64 instructions",
            trampoline.len()
        )));
    }

    let placeholder_imm = placeholder_imm_field();
    let ldr_pattern = Opcode::LdrUimm.bits() | placeholder_imm;
    let str_pattern = Opcode::StrUimm.bits() | placeholder_imm;
    let new_imm = u32::from(offset / GUEST_TPIDR_OFFSET_ALIGN) << LDST_UIMM12_IMM_SHIFT;

    let mut patched = 0usize;
    for (index, word) in trampoline[SHARED_SVC_HANDLER_OFFSET..]
        .chunks_exact_mut(4)
        .enumerate()
    {
        let insn = u32::from_le_bytes(word.try_into().expect("chunks_exact_mut(4) yields 4 bytes"));
        let opcode_and_imm = insn & LDST_UIMM12_OPCODE_AND_IMM_MASK;
        if opcode_and_imm != ldr_pattern && opcode_and_imm != str_pattern {
            continue;
        }

        // Only two shapes carry the placeholder: the MRS gate's
        // `LDR Xd, [Xd, #off]` (destination reused as its own base) and the MSR
        // gate's `STR X17, [X16, #off]`. Anything else means the blob is not
        // one of ours — refuse rather than corrupt an unknown instruction.
        let rt = (insn & 0x1F) as u8;
        let rn = ((insn >> 5) & 0x1F) as u8;
        let well_formed = if opcode_and_imm == ldr_pattern {
            rt == rn && rt != XZR
        } else {
            rt == X17 && rn == X16
        };
        if !well_formed {
            let vaddr_offset = SHARED_SVC_HANDLER_OFFSET + index * 4;
            return Err(Error::TrampolinePatchFailure(format!(
                "trampoline byte {vaddr_offset}: instruction {insn:#010x} carries the guest \
                 thread-pointer placeholder but is not a shape any gate emits"
            )));
        }

        let patched_insn = (insn & !LDST_UIMM12_IMM_MASK) | new_imm;
        word.copy_from_slice(&patched_insn.to_le_bytes());
        patched += 1;
    }

    Ok(patched)
}

/// The `imm12` field, already shifted into place, that an unpatched gate's
/// `LDR`/`STR` carries.
fn placeholder_imm_field() -> u32 {
    u32::from(GUEST_TPIDR_OFFSET_PLACEHOLDER / GUEST_TPIDR_OFFSET_ALIGN) << LDST_UIMM12_IMM_SHIFT
}

/// Byte offset of the first instruction in `trampoline` that still carries
/// [`GUEST_TPIDR_OFFSET_PLACEHOLDER`], or `None` if no gate is left unpatched.
///
/// This is the loader's proof obligation: an unpatched gate does not fault, so
/// its absence has to be checked rather than assumed. See
/// [`GUEST_TPIDR_OFFSET_PLACEHOLDER`].
///
/// Like [`patch_guest_tpidr_offset`] this skips the header's callback slot,
/// which is a 64-bit address and could bit-for-bit resemble a gate
/// instruction. Only the shape-independent opcode-and-immediate pattern is
/// matched: a placeholder-bearing word in a shape no gate emits is still a
/// reason to refuse, not to ignore.
pub(crate) fn find_guest_tpidr_placeholder(trampoline: &[u8]) -> Option<usize> {
    let placeholder_imm = placeholder_imm_field();
    let ldr_pattern = Opcode::LdrUimm.bits() | placeholder_imm;
    let str_pattern = Opcode::StrUimm.bits() | placeholder_imm;

    trampoline
        .get(SHARED_SVC_HANDLER_OFFSET..)?
        .chunks_exact(4)
        .position(|word| {
            let insn = u32::from_le_bytes(word.try_into().expect("chunks_exact(4) yields 4 bytes"));
            let opcode_and_imm = insn & LDST_UIMM12_OPCODE_AND_IMM_MASK;
            opcode_and_imm == ldr_pattern || opcode_and_imm == str_pattern
        })
        .map(|index| SHARED_SVC_HANDLER_OFFSET + index * 4)
}

// ============================================================
// Small helpers
// ============================================================

/// A position-tracking assembler for one trampoline fragment (a gate or a shared
/// handler). It owns the emitted words and the base virtual address of the first
/// word, so the current vaddr — [`Asm::here`] — is always known without manual
/// instruction counting.
///
/// Branches and loads to an absolute target ([`Asm::branch_to`],
/// [`Asm::ldr_literal`], [`Asm::adrp`]) resolve immediately against
/// [`Asm::here`]. The per-site branches ([`Asm::branch_to`], [`Asm::adrp`])
/// report an out-of-range target by emitting nothing and returning `false`, so
/// the caller can trap the site; [`Asm::ldr_literal`] (used only by the fixed
/// prologue) instead errors, since a prologue that cannot be placed is fatal.
struct Asm {
    base_vaddr: u64,
    code: Vec<u8>,
}

impl Asm {
    fn new(base_vaddr: u64) -> Self {
        Asm {
            base_vaddr,
            code: Vec::new(),
        }
    }

    /// Virtual address of the next instruction to be emitted.
    fn here(&self) -> Result<u64> {
        checked_add_u64(
            self.base_vaddr,
            self.code.len() as u64,
            "trampoline gate next-instruction",
        )
    }

    /// Append a raw little-endian word.
    fn push_word(&mut self, word: u32) {
        self.code.extend_from_slice(&word.to_le_bytes());
    }

    /// Append a fixed-operand instruction. Every operand at the call sites is a
    /// compile-time-known register or frame offset, so encoding cannot fail; a
    /// `None` would be a rewriter bug rather than an unencodable program.
    fn emit(&mut self, insn: Insn) {
        let word = insn.encode().expect("statically valid instruction");
        self.push_word(word);
    }

    /// `B <target>` — unconditional branch to an absolute address. Returns
    /// whether the target was within the branch's ±128MB reach: an out-of-range
    /// target emits nothing and yields `false`, so the caller can trap the
    /// originating site instead of failing the whole rewrite.
    fn branch_to(&mut self, target_vaddr: u64) -> Result<bool> {
        let offset = self.delta_to(target_vaddr)?;
        let Some(word) = Insn::B(offset).encode() else {
            return Ok(false);
        };
        self.push_word(word);
        Ok(true)
    }

    /// `LDR Xt, =target` — PC-relative literal load of an absolute address.
    fn ldr_literal(&mut self, rt: u8, target_vaddr: u64) -> Result<()> {
        let offset = self.delta_to(target_vaddr)?;
        let word = Insn::LdrLiteral { rt, off: offset }
            .encode()
            .ok_or_else(|| {
                Error::AddressOverflow(format!("LDR literal offset {offset:#x} out of ±1MB range"))
            })?;
        self.push_word(word);
        Ok(())
    }

    /// `ADR Xd, <target>` — byte-granular PC-relative address of an absolute
    /// target, ±1MB. Returns whether the target was in reach (see
    /// [`Asm::branch_to`] for the out-of-range contract).
    fn adr(&mut self, rd: u8, target_vaddr: u64) -> Result<bool> {
        let byte_off = self.delta_to(target_vaddr)?;
        let Some(word) = Insn::Adr { rd, byte_off }.encode() else {
            return Ok(false);
        };
        self.push_word(word);
        Ok(true)
    }

    /// `ADRP Xd, <target>` — page-relative address of an absolute target.
    /// Returns whether the target's page was within ADRP's ±4GB reach (see
    /// [`Asm::branch_to`] for the out-of-range contract).
    fn adrp(&mut self, rd: u8, target_vaddr: u64) -> Result<bool> {
        let here = self.here()?;
        let page_off = (target_vaddr & !0xFFF)
            .cast_signed()
            .saturating_sub((here & !0xFFF).cast_signed())
            >> 12;
        let Some(word) = Insn::Adrp { rd, page_off }.encode() else {
            return Ok(false);
        };
        self.push_word(word);
        Ok(true)
    }

    /// Signed byte distance from [`Asm::here`] to `target_vaddr`. The subtraction
    /// saturates so a pathological address can't overflow it; a distance the
    /// branch can't encode is rejected by the encoder's range check at the call
    /// site, with the saturated value reported for diagnostics.
    fn delta_to(&self, target_vaddr: u64) -> Result<i64> {
        Ok(target_vaddr
            .cast_signed()
            .saturating_sub(self.here()?.cast_signed()))
    }

    /// Return the emitted bytes.
    fn finish(self) -> Vec<u8> {
        self.code
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    // Gate and shared-handler sizes. The emitters append each gate dynamically
    // (`gate_offset = trampoline_data.len()`), so these sizes drive no emission;
    // the tests use them to slice individual gates out of the trampoline blob and
    // to assert its total length.
    /// Bytes emitted per SVC site: the gate proper plus its outbound stub.
    const SVC_GATE_SIZE: usize = SVC_GATE_BYTES + SVC_OUTBOUND_STUB_BYTES;
    const SHARED_SVC_HANDLER_INSNS: usize = SHARED_SVC_HANDLER_BYTES / 4;
    const MSR_GATE_INSNS: usize = 9;
    const MSR_GATE_SIZE: usize = MSR_GATE_INSNS * 4;
    const MRS_GATE_INSNS: usize = 3;
    const MRS_GATE_SIZE: usize = MRS_GATE_INSNS * 4;

    /// Top-6 opcode bits, isolating the `B`/`BL` major opcode for read-back checks.
    const OPCODE_TOP6_MASK: u32 = 0xFC00_0000;

    fn word_at(data: &[u8], byte_off: usize) -> u32 {
        u32::from_le_bytes(data[byte_off..byte_off + 4].try_into().unwrap())
    }

    /// `MSR TPIDR_EL0, Xrt` guest instruction word (the low 5 bits select Xrt).
    /// The rewriter only matches/scans this form; it never emits it, so the
    /// encoder lives only here for building test inputs.
    fn msr_tpidr_el0(rt: u8) -> u32 {
        MSR_TPIDR_EL0_BITS | u32::from(rt)
    }

    /// Helper: emit just the shared SVC handler and return its instruction words.
    fn shared_svc_handler_words() -> vec::Vec<u32> {
        let mut buf = vec::Vec::new();
        emit_shared_svc_handler(&mut buf, 0, 0x1000).unwrap();
        buf.chunks_exact(4)
            .map(|w| u32::from_le_bytes(w.try_into().unwrap()))
            .collect()
    }

    #[test]
    fn svc_handler_jumps_to_callback_without_tls() {
        let words = shared_svc_handler_words();
        assert_eq!(words.len(), SHARED_SVC_HANDLER_INSNS);
        // The handler conveys nothing TLS-related: it loads the callback pointer
        // and tail-jumps. The callback reads host TLS from TPIDR_EL0 itself.
        assert_eq!(
            words[1],
            Insn::Br(X16).encode().unwrap(),
            "handler ends in BR X16"
        );
        // No MRS TPIDR_EL0 anywhere in the handler.
        assert!(
            !words
                .iter()
                .any(|&w| w & MRS_TPIDR_EL0_MASK == MRS_TPIDR_EL0_BITS)
        );
    }

    #[test]
    fn encoders_match_known_words() {
        // `B #0`.
        assert_eq!(Insn::B(0).encode().unwrap(), 0x1400_0000);
        // `B #4` advances one instruction.
        assert_eq!(Insn::B(4).encode().unwrap(), 0x1400_0001);
        // `B #-4` is the all-ones imm26.
        assert_eq!(Insn::B(-4).encode().unwrap(), 0x17FF_FFFF);
        // `BR X16`.
        assert_eq!(Insn::Br(16).encode().unwrap(), 0xD61F_0200);
        // `ADR X16, .+12` — how an SVC gate names its outbound stub.
        assert_eq!(
            Insn::Adr {
                rd: 16,
                byte_off: 12
            }
            .encode()
            .unwrap(),
            0x1000_0070
        );
        // TPIDR_EL0 accessor.
        assert_eq!(Insn::MrsTpidrEl0(9).encode().unwrap(), 0xD53B_D049);
        // `MSR TPIDR_EL0, X9` guest word (scanned, never emitted).
        assert_eq!(msr_tpidr_el0(9), 0xD51B_D049);
        // Scaled (×8) 64-bit load/store: `ldr x9,[x9,#16]` / `str x17,[x16,#16]`.
        assert_eq!(
            Insn::LdrUimm {
                rt: 9,
                rn: 9,
                imm_bytes: 16
            }
            .encode()
            .unwrap(),
            0xF940_0929
        );
        assert_eq!(
            Insn::StrUimm {
                rt: 17,
                rn: 16,
                imm_bytes: 16
            }
            .encode()
            .unwrap(),
            0xF900_0A11
        );
        // The guest thread-pointer slot is emitted with the placeholder offset
        // that `patch_guest_tpidr_offset` overwrites at load time; pin both the
        // value and the emitted words. The placeholder saturates the scaled
        // 12-bit immediate (`imm12 = 0xFFF`).
        assert_eq!(GUEST_TPIDR_OFFSET_PLACEHOLDER, 32760);
        // Slot access: `ldr x9,[x9,#32760]` / `str x17,[x16,#32760]`.
        assert_eq!(
            Insn::LdrUimm {
                rt: 9,
                rn: 9,
                imm_bytes: GUEST_TPIDR_OFFSET_PLACEHOLDER
            }
            .encode()
            .unwrap(),
            0xF97F_FD29
        );
        assert_eq!(
            Insn::StrUimm {
                rt: 17,
                rn: 16,
                imm_bytes: GUEST_TPIDR_OFFSET_PLACEHOLDER
            }
            .encode()
            .unwrap(),
            0xF93F_FE11
        );
        // `BRK #0xB10B`, the trap that replaces an out-of-range patch site.
        assert_eq!(Insn::Brk(TRAP_BRK_IMM).encode().unwrap(), 0xD436_2160);
    }

    #[test]
    fn encoder_range_checks() {
        assert!(Insn::B(2).encode().is_none()); // not 4-aligned
        assert!(Insn::B(1 << 27).encode().is_none()); // out of ±128MB
        assert!(
            Insn::StrUimm {
                rt: 0,
                rn: 0,
                imm_bytes: 4
            }
            .encode()
            .is_none()
        ); // not 8-scaled
    }

    #[test]
    fn asm_ldr_literal_computes_pc_relative_offset() {
        let mut asm = Asm::new(0x1000);
        asm.emit(Insn::Br(30)); // [0] at 0x1000
        asm.ldr_literal(16, 0x1010).unwrap(); // [1] at 0x1004, target 0x1010 => +0xC
        let code = asm.finish();
        assert_eq!(
            word_at(&code, 4),
            Insn::LdrLiteral { rt: 16, off: 0xC }.encode().unwrap()
        );
    }

    /// Build a one-section image whose section data == the supplied words and
    /// run the hooker. Returns `(patched_section, trampoline)`. Panics if the
    /// input has no patch sites (use [`hook_words_opt`] for that case).
    fn hook_words(words: &[u32], base: u64, tramp_base: u64) -> (Vec<u8>, Vec<u8>) {
        let (patched, outcome) = hook_words_opt(words, base, tramp_base);
        (
            patched,
            outcome
                .expect("expected a trampoline (input has patch sites)")
                .trampoline,
        )
    }

    /// Like [`hook_words`] but prefills the trampoline's callback slot, so a
    /// test can plant arbitrary data there.
    fn hook_words_with_callback(
        words: &[u32],
        base: u64,
        tramp_base: u64,
        callback: u64,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        for w in words {
            buf.extend_from_slice(&w.to_le_bytes());
        }
        let sections = vec![TextSectionInfo {
            vaddr: base,
            file_offset: 0,
            size: buf.len() as u64,
        }];
        hook_syscalls_aarch64(&mut buf, &sections, tramp_base, callback, Host::Linux)
            .unwrap()
            .expect("expected a trampoline (input has patch sites)")
            .trampoline
    }

    /// Like [`hook_words`] but returns the raw `Option` outcome so callers can
    /// assert the "no patch sites" (`None`) sentinel and trapped-site cases.
    fn hook_words_opt(words: &[u32], base: u64, tramp_base: u64) -> (Vec<u8>, Option<HookOutcome>) {
        let mut buf = Vec::new();
        for w in words {
            buf.extend_from_slice(&w.to_le_bytes());
        }
        let sections = vec![TextSectionInfo {
            vaddr: base,
            file_offset: 0,
            size: buf.len() as u64,
        }];
        let outcome =
            hook_syscalls_aarch64(&mut buf, &sections, tramp_base, 0, Host::Linux).unwrap();
        (buf, outcome)
    }

    #[test]
    fn no_patch_sites_emit_no_trampoline() {
        // No patch sites: a NOP-only section yields no trampoline at all, so the
        // caller emits a size-0 sentinel (matching the x86-64 path).
        let (_patched, tramp) = hook_words_opt(&[0xD503_201F], 0x1000, 0x100000);
        assert!(tramp.is_none());
    }

    #[test]
    fn svc_is_replaced_with_branch_into_gate() {
        let base = 0x1000;
        let tramp_base = 0x200000;
        let (patched, tramp) = hook_words(&[SVC_0], base, tramp_base);

        // The SVC word became a `B`.
        let patched_word = word_at(&patched, 0);
        assert_eq!(
            patched_word & OPCODE_TOP6_MASK,
            Opcode::B.bits(),
            "expected B opcode"
        );

        // It targets the first per-site gate at GATES_START_OFFSET.
        let imm26 = i64::from(patched_word & IMM26_MASK);
        let disp = imm26 << 2; // positive here
        let target = base + disp.cast_unsigned();
        assert_eq!(target, tramp_base + GATES_START_OFFSET as u64);

        // The gate's first instruction is SUB SP, SP, #SVC_FRAME_BYTES.
        assert_eq!(
            word_at(&tramp, GATES_START_OFFSET),
            Insn::SubSp(SVC_FRAME_BYTES).encode().unwrap()
        );
        // Total = prologue + one SVC gate.
        assert_eq!(tramp.len(), GATES_START_OFFSET + SVC_GATE_SIZE);
    }

    #[test]
    fn svc_with_nonzero_immediate_is_also_rewritten() {
        // Linux dispatches every `SVC64` exception to the syscall handler
        // regardless of the immediate (the syscall number comes from x8), so
        // `svc #imm` with imm != 0 must be rewritten too. imm16 occupies bits
        // [20:5], so `svc #1` is `SVC_0 | (1 << 5)`.
        let svc_imm1 = SVC_0 | (1 << 5);
        let (patched, tramp) = hook_words(&[svc_imm1], 0x1000, 0x200000);
        // The SVC word became a `B` into the gate.
        assert_eq!(word_at(&patched, 0) & OPCODE_TOP6_MASK, Opcode::B.bits());
        assert_eq!(tramp.len(), GATES_START_OFFSET + SVC_GATE_SIZE);
    }

    #[test]
    fn site_beyond_branch_range_is_trapped() {
        // The trampoline sits 256MB above the section, past the `B` instruction's
        // ±128MB reach, so the site cannot branch into its gate. It is replaced
        // with the sentinel `BRK`, surfaced as a trapped site, and no gate is
        // emitted for it, leaving the trampoline at the prologue-only size.
        let (patched, outcome) = hook_words_opt(&[SVC_0], 0x1000, 0x1000_0000);
        let outcome = outcome.expect("expected a trampoline (input has patch sites)");
        assert_eq!(
            word_at(&patched, 0),
            Insn::Brk(TRAP_BRK_IMM).encode().unwrap()
        );
        assert_eq!(outcome.trapped_sites, vec![0x1000]);
        assert_eq!(outcome.trampoline.len(), GATES_START_OFFSET);
    }

    #[test]
    fn msr_gate_return_branch_out_of_range_is_trapped() {
        // Boundary window where the site can reach its gate but the gate cannot
        // reach back. The MSR gate's return `B` is its last instruction, at
        // `gate + 32`, branching to `site + 4`; its displacement magnitude is
        // `b_offset + 28`, larger than the inbound `B`'s `b_offset`. Placing the
        // gate at the maximum encodable forward offset (`2^27 - 4`) makes the
        // inbound branch encode while the return needs `-(2^27 + 24)`, just past
        // the `-2^27` reach. The site must still be trapped gracefully — replaced
        // with `BRK` and surfaced through `trapped_sites` — not error out.
        let base = 0x1000u64;
        let max_fwd = (1u64 << 27) - 4; // largest 4-aligned forward `B` offset
        let tramp_base = base + max_fwd - GATES_START_OFFSET as u64;
        let (patched, outcome) = hook_words_opt(&[msr_tpidr_el0(5)], base, tramp_base);
        let outcome = outcome.expect("expected a trampoline (input has patch sites)");
        assert_eq!(
            word_at(&patched, 0),
            Insn::Brk(TRAP_BRK_IMM).encode().unwrap()
        );
        assert_eq!(outcome.trapped_sites, vec![base]);
        // No gate emitted for the trapped site: prologue-only trampoline.
        assert_eq!(outcome.trampoline.len(), GATES_START_OFFSET);
    }

    #[test]
    fn hvc_and_smc_are_not_treated_as_svc() {
        // `HVC #0` (…02) and `SMC #0` (…03) share the SVC opcode base but differ
        // in bits [1:0]; they must not be rewritten as syscalls.
        let hvc_0 = 0xD400_0002u32;
        let smc_0 = 0xD400_0003u32;
        let (_p, tramp) = hook_words_opt(&[hvc_0, smc_0], 0x1000, 0x200000);
        assert!(tramp.is_none(), "HVC/SMC must not be matched as SVC");
    }

    #[test]
    fn msr_and_mrs_both_get_gates() {
        let base = 0x1000;
        let tramp_base = 0x300000;
        // MSR TPIDR_EL0, X5  then  MRS X9, TPIDR_EL0.
        let words = [msr_tpidr_el0(5), Insn::MrsTpidrEl0(9).encode().unwrap()];
        let (patched, tramp) = hook_words(&words, base, tramp_base);
        // Both the write and the read are rewritten to a branch into their gate.
        assert_eq!(word_at(&patched, 0) & OPCODE_TOP6_MASK, Opcode::B.bits());
        assert_eq!(word_at(&patched, 4) & OPCODE_TOP6_MASK, Opcode::B.bits());
        // Trampoline = prologue + one MSR gate + one MRS gate.
        assert_eq!(
            tramp.len(),
            GATES_START_OFFSET + MSR_GATE_SIZE + MRS_GATE_SIZE
        );
    }

    #[test]
    fn mrs_with_xzr_dest_is_left_native() {
        // `MRS XZR, TPIDR_EL0` reads-and-discards; it must not be rewritten.
        let mrs_xzr = Insn::MrsTpidrEl0(31).encode().unwrap();
        let (_p, tramp) = hook_words_opt(&[mrs_xzr], 0x1000, 0x200000);
        assert!(tramp.is_none(), "MRS XZR, TPIDR_EL0 must be left native");
    }

    #[test]
    fn msr_gate_stores_guest_value_to_slot_for_any_register() {
        const BL_TOP6: u32 = 0x9400_0000;
        for n in [5u8, 16, 17, 30, 31] {
            let (_p, tramp) = hook_words(&[msr_tpidr_el0(n)], 0x1000, 0x500000);
            let gate = &tramp[GATES_START_OFFSET..GATES_START_OFFSET + MSR_GATE_SIZE];
            // Self-contained: never BL out.
            assert!(
                (0..MSR_GATE_INSNS).all(|i| word_at(gate, i * 4) & OPCODE_TOP6_MASK != BL_TOP6)
            );
            // Capture the guest value while pristine: STR Xn, [SP, #16].
            let capture = Insn::StrUimm {
                rt: n,
                rn: SP,
                imm_bytes: MSR_FRAME_OFF_VALUE,
            }
            .encode()
            .unwrap();
            let cap_i = (0..MSR_GATE_INSNS)
                .find(|&i| word_at(gate, i * 4) == capture)
                .expect("MSR gate must capture the guest value (incl. XZR=0) while pristine");
            // Read the host anchor: MRS X16, TPIDR_EL0.
            let anchor = Insn::MrsTpidrEl0(X16).encode().unwrap();
            let anc_i = (0..MSR_GATE_INSNS)
                .find(|&i| word_at(gate, i * 4) == anchor)
                .expect("MSR gate must read the host anchor");
            // Store to the slot: STR X17, [X16, #<placeholder>].
            let store = Insn::StrUimm {
                rt: X17,
                rn: X16,
                imm_bytes: GUEST_TPIDR_OFFSET_PLACEHOLDER,
            }
            .encode()
            .unwrap();
            let st_i = (0..MSR_GATE_INSNS)
                .find(|&i| word_at(gate, i * 4) == store)
                .expect("MSR gate must store the guest value into its slot");
            assert!(
                cap_i < anc_i && anc_i < st_i,
                "capture -> anchor -> store order"
            );
            // Ends in B back to the guest (not the last word being the store).
            assert_eq!(
                word_at(gate, (MSR_GATE_INSNS - 1) * 4) & OPCODE_TOP6_MASK,
                Opcode::B.bits()
            );
        }
    }

    #[test]
    fn mrs_gate_loads_guest_tp_from_slot() {
        for d in [5u8, 16, 17, 30] {
            let (_p, tramp) =
                hook_words(&[Insn::MrsTpidrEl0(d).encode().unwrap()], 0x1000, 0x400000);
            let gate = &tramp[GATES_START_OFFSET..GATES_START_OFFSET + MRS_GATE_SIZE];
            assert_eq!(word_at(gate, 0), Insn::MrsTpidrEl0(d).encode().unwrap());
            assert_eq!(
                word_at(gate, 4),
                Insn::LdrUimm {
                    rt: d,
                    rn: d,
                    imm_bytes: GUEST_TPIDR_OFFSET_PLACEHOLDER
                }
                .encode()
                .unwrap()
            );
            assert_eq!(word_at(gate, 8) & OPCODE_TOP6_MASK, Opcode::B.bits());
        }
    }

    #[test]
    fn svc_gate_saves_only_x16_and_records_return() {
        let base = 0x1000;
        let tramp_base = 0x600000;
        let (_p, tramp) = hook_words(&[SVC_0], base, tramp_base);
        let gate = &tramp[GATES_START_OFFSET..GATES_START_OFFSET + SVC_GATE_SIZE];
        // SUB SP,#32 ; STR X16,[SP] ; ADRP X16,.. ; ADD X16,X16,#.. ;
        // STR X16,[SP,#8] ; ADR X16,stub ; STR X16,[SP,#16] ; B <handler>
        assert_eq!(
            word_at(gate, 0),
            Insn::SubSp(SVC_FRAME_BYTES).encode().unwrap()
        );
        assert_eq!(
            word_at(gate, 4),
            Insn::StrUimm {
                rt: X16,
                rn: SP,
                imm_bytes: SVC_FRAME_OFF_X16
            }
            .encode()
            .unwrap()
        );
        assert_eq!(
            word_at(gate, 16),
            Insn::StrUimm {
                rt: X16,
                rn: SP,
                imm_bytes: SVC_FRAME_OFF_RETADDR
            }
            .encode()
            .unwrap()
        );
        // ADR X16, <stub>. The stub starts 12 bytes past this instruction (two
        // more gate instructions then the `B`), so the encoded displacement is
        // +12 regardless of where the trampoline is placed.
        assert_eq!(
            word_at(gate, 20),
            Insn::Adr {
                rd: X16,
                byte_off: 12
            }
            .encode()
            .unwrap()
        );
        assert_eq!(
            word_at(gate, 24),
            Insn::StrUimm {
                rt: X16,
                rn: SP,
                imm_bytes: SVC_FRAME_OFF_STUB
            }
            .encode()
            .unwrap()
        );
        // Self-contained tail branch to the shared handler (B, never BL).
        assert_eq!(word_at(gate, 28) & OPCODE_TOP6_MASK, Opcode::B.bits());
        assert_eq!(tramp.len(), GATES_START_OFFSET + SVC_GATE_SIZE);
    }

    #[test]
    fn svc_outbound_stub_restores_x16_pops_the_frame_and_returns_to_the_site() {
        // The stub is what makes `X16` survive an `SVC`: it reloads the guest
        // value the runtime staged at `[SP, #0]`, pops the gate frame so `SP`
        // becomes the true guest `SP` again, and branches to `site + 4` with a
        // static direct branch that needs no scratch register.
        let base = 0x1000;
        let tramp_base = 0x600000;
        let (_p, tramp) = hook_words(&[SVC_0], base, tramp_base);
        let stub_off = GATES_START_OFFSET + SVC_GATE_BYTES;
        let stub = &tramp[stub_off..stub_off + SVC_OUTBOUND_STUB_BYTES];

        assert_eq!(
            word_at(stub, 0),
            Insn::LdrUimm {
                rt: X16,
                rn: SP,
                imm_bytes: SVC_FRAME_OFF_X16
            }
            .encode()
            .unwrap()
        );
        assert_eq!(
            word_at(stub, 4),
            Insn::AddSp(SVC_FRAME_BYTES).encode().unwrap()
        );

        // The final `B` targets `site + 4`.
        let branch = word_at(stub, 8);
        assert_eq!(branch & OPCODE_TOP6_MASK, Opcode::B.bits());
        let imm26 = i64::from(branch & IMM26_MASK);
        // Sign-extend the 26-bit field, then scale by 4.
        let disp = ((imm26 << 38) >> 38) * 4;
        let branch_vaddr = tramp_base + (stub_off + 8) as u64;
        assert_eq!(
            branch_vaddr.cast_signed() + disp,
            (base + 4).cast_signed(),
            "outbound stub must return to site + 4"
        );
    }

    // --- Load-time guest thread-pointer offset patching ---

    /// The offset a real host runtime might measure for itself: not the
    /// placeholder, and not the value this code used to hardcode.
    const MEASURED_OFFSET: u16 = 96;

    #[test]
    fn patch_rewrites_both_gate_shapes_and_leaves_everything_else_alone() {
        // One MSR site and one MRS site, so both patchable shapes are present.
        let (_p, mut tramp) = hook_words(
            &[msr_tpidr_el0(3), Insn::MrsTpidrEl0(9).encode().unwrap()],
            0x1000,
            0x400000,
        );
        let before = tramp.clone();

        let patched = patch_guest_tpidr_offset(&mut tramp, MEASURED_OFFSET).unwrap();
        assert_eq!(patched, 2, "one MSR store and one MRS load");

        // Exactly two words changed, and each became the same instruction with
        // the measured offset in place of the placeholder.
        let changed: alloc::vec::Vec<usize> = (0..tramp.len() / 4)
            .filter(|&i| word_at(&tramp, i * 4) != word_at(&before, i * 4))
            .collect();
        assert_eq!(changed.len(), 2);
        for i in changed {
            let old = word_at(&before, i * 4);
            let new = word_at(&tramp, i * 4);
            assert_eq!(
                old & !LDST_UIMM12_IMM_MASK,
                new & !LDST_UIMM12_IMM_MASK,
                "only the immediate field may change"
            );
            assert_eq!(
                (new & LDST_UIMM12_IMM_MASK) >> LDST_UIMM12_IMM_SHIFT,
                u32::from(MEASURED_OFFSET / GUEST_TPIDR_OFFSET_ALIGN)
            );
        }

        // Spot-check the exact encodings the gates must now hold.
        let msr_store = Insn::StrUimm {
            rt: X17,
            rn: X16,
            imm_bytes: MEASURED_OFFSET,
        }
        .encode()
        .unwrap();
        let mrs_load = Insn::LdrUimm {
            rt: 9,
            rn: 9,
            imm_bytes: MEASURED_OFFSET,
        }
        .encode()
        .unwrap();
        let words: alloc::vec::Vec<u32> = (0..tramp.len() / 4)
            .map(|i| word_at(&tramp, i * 4))
            .collect();
        assert!(words.contains(&msr_store), "MSR gate store must be patched");
        assert!(words.contains(&mrs_load), "MRS gate load must be patched");

        // Patching is idempotent in the sense that a second pass finds nothing:
        // the placeholder is gone.
        assert_eq!(
            patch_guest_tpidr_offset(&mut tramp, MEASURED_OFFSET).unwrap(),
            0
        );
    }

    #[test]
    fn patch_leaves_an_svc_only_trampoline_untouched() {
        // The SVC gate and its outbound stub are full of `LDR`/`STR` words with
        // an `SP` base. None of them may be mistaken for a thread-pointer
        // access, and the header's callback slot is data that must be skipped.
        let (_p, mut tramp) = hook_words(&[SVC_0], 0x1000, 0x400000);
        let before = tramp.clone();
        assert_eq!(
            patch_guest_tpidr_offset(&mut tramp, MEASURED_OFFSET).unwrap(),
            0
        );
        assert_eq!(tramp, before);
    }

    #[test]
    fn patch_skips_a_callback_slot_that_looks_like_a_gate_instruction() {
        // The callback address is arbitrary data. Prefill it with two copies of
        // a word that *is* a placeholder-bearing gate load, and check the patch
        // pass does not touch the header.
        let decoy = Insn::LdrUimm {
            rt: 9,
            rn: 9,
            imm_bytes: GUEST_TPIDR_OFFSET_PLACEHOLDER,
        }
        .encode()
        .unwrap();
        let callback = (u64::from(decoy) << 32) | u64::from(decoy);
        let mut tramp = hook_words_with_callback(&[SVC_0], 0x1000, 0x400000, callback);
        assert_eq!(
            patch_guest_tpidr_offset(&mut tramp, MEASURED_OFFSET).unwrap(),
            0
        );
        assert_eq!(
            u64::from_le_bytes(tramp[..8].try_into().unwrap()),
            callback,
            "the callback slot is data and must survive verbatim"
        );
    }

    /// The check a loader needs: an unpatched gate is *detectable*, because it
    /// is not detectable any other way — it does not fault when executed. See
    /// [`GUEST_TPIDR_OFFSET_PLACEHOLDER`].
    #[test]
    fn find_placeholder_reports_gates_before_patching_and_none_after() {
        let (_p, mut tramp) = hook_words(
            &[msr_tpidr_el0(3), Insn::MrsTpidrEl0(9).encode().unwrap()],
            0x1000,
            0x400000,
        );

        let at = find_guest_tpidr_placeholder(&tramp).expect("an unpatched gate must be found");
        assert!(at >= SHARED_SVC_HANDLER_OFFSET && at.is_multiple_of(4));

        assert_eq!(
            patch_guest_tpidr_offset(&mut tramp, MEASURED_OFFSET).unwrap(),
            2
        );
        assert_eq!(
            find_guest_tpidr_placeholder(&tramp),
            None,
            "patching must leave no gate on the placeholder"
        );
    }

    #[test]
    fn find_placeholder_ignores_svc_gates_and_the_callback_slot() {
        // An SVC-only trampoline has no thread-pointer gate at all, and its
        // `LDR`/`STR` words off `SP` must not be mistaken for one.
        let (_p, tramp) = hook_words(&[SVC_0], 0x1000, 0x400000);
        assert_eq!(find_guest_tpidr_placeholder(&tramp), None);

        // The callback slot is a 64-bit address, i.e. data. Even when it
        // happens to spell a placeholder-bearing gate load, it is not one.
        let decoy = Insn::LdrUimm {
            rt: 9,
            rn: 9,
            imm_bytes: GUEST_TPIDR_OFFSET_PLACEHOLDER,
        }
        .encode()
        .unwrap();
        let callback = (u64::from(decoy) << 32) | u64::from(decoy);
        let tramp = hook_words_with_callback(&[SVC_0], 0x1000, 0x400000, callback);
        assert_eq!(find_guest_tpidr_placeholder(&tramp), None);
    }

    #[test]
    fn patch_rejects_an_offset_a_gate_cannot_address() {
        let (_p, mut tramp) =
            hook_words(&[Insn::MrsTpidrEl0(9).encode().unwrap()], 0x1000, 0x400000);
        for bad in [4u16, 12, MAX_GUEST_TPIDR_OFFSET + 8] {
            assert!(
                matches!(
                    patch_guest_tpidr_offset(&mut tramp, bad),
                    Err(Error::TrampolinePatchFailure(_))
                ),
                "offset {bad} must be rejected"
            );
        }
        // The bounds themselves are accepted.
        assert!(patch_guest_tpidr_offset(&mut tramp, MAX_GUEST_TPIDR_OFFSET).is_ok());
    }

    #[test]
    fn patch_rejects_a_blob_that_is_not_a_trampoline() {
        // Shorter than the shared prologue.
        let mut short = vec![0u8; GATES_START_OFFSET - 4];
        assert!(matches!(
            patch_guest_tpidr_offset(&mut short, MEASURED_OFFSET),
            Err(Error::TrampolinePatchFailure(_))
        ));

        // Not a whole number of instructions.
        let mut ragged = vec![0u8; GATES_START_OFFSET + 2];
        assert!(matches!(
            patch_guest_tpidr_offset(&mut ragged, MEASURED_OFFSET),
            Err(Error::TrampolinePatchFailure(_))
        ));

        // A placeholder-bearing instruction in a shape no gate emits.
        let mut foreign = vec![0u8; GATES_START_OFFSET + 4];
        let bogus = Insn::LdrUimm {
            rt: 1,
            rn: 2,
            imm_bytes: GUEST_TPIDR_OFFSET_PLACEHOLDER,
        }
        .encode()
        .unwrap();
        foreign[GATES_START_OFFSET..].copy_from_slice(&bogus.to_le_bytes());
        assert!(matches!(
            patch_guest_tpidr_offset(&mut foreign, MEASURED_OFFSET),
            Err(Error::TrampolinePatchFailure(_))
        ));
    }
}
