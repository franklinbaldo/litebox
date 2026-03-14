# macOS ARM64: Full x18 and TPIDR_EL0 Virtualization

## 1. Problem Statement and Approach

Litebox runs Linux ARM64 binaries on macOS using a syscall rewriter (shim layer).
Linux apps use `TPIDR_EL0` for TLS and `x18` as a general-purpose register. macOS
(XNU) **clobbers both** on every kernel-to-userspace transition:

- **x18:** Zeroed on return to userspace (`return_to_user` in `locore.s`). Only
  restored for Rosetta/entitled tasks with `ARM_MACHINE_THREAD_PRESERVE_X18`.
  Sigreturn also does not restore x18.
- **TPIDR_EL0:** Overwritten with a per-CPU encoded value (`cpu_data_t.cpu_tpidr_el0`)
  on every return to userspace. The user's value is destroyed with no save/restore.

**TPIDRRO_EL0** is macOS's actual TLS mechanism. It is set via
`machine_thread_set_tsd_base()` to the pthread TSD base. It is stable, per-thread,
read-only to userspace, unique per pthread, and never clobbered.

### Approach

- Use **TPIDRRO_EL0 as the TLS table lookup key** (replacing guest_tpidr/TPIDR_EL0).
- Save/restore **guest x18 in per-site SVC gates** via the TCB.
- **Full x18 instruction rewrite** using yaxpeax-arm for instruction decoding. Every
  instruction referencing x18 gets a gate that loads/stores x18 from a per-thread
  cell in the TCB.
- **Shared x18 load/save handlers** to amortize the TPIDRRO_EL0 table lookup cost.
- Store `guest_x18` in TCB at offset 40, accessed via TPIDRRO_EL0 table lookup.
- Dedicated per-thread `guest_tpidr` cell in TCB (offset 24), with MSR handler
  writing directly to TCB via TPIDRRO_EL0 lookup.
- MRS TPIDR_EL0 gates read `guest_tpidr` from TCB via shared MRS handler.
- Signal handlers detect clobbered state and restore from TCB before resuming guest.
- All changes are **macOS-only** (`#[cfg(target_os = "macos")]`). Linux rewriter
  keeps its working TPIDR_EL0-based approach unchanged.

## 2. TLS Table and TCB Layout

### TLS Table Entry Format (macOS)

Each entry is 16 bytes. The key changes from `guest_tpidr` to `tpidrro_el0`:

```
Current (Linux & macOS):  [guest_tpidr: u64, host_tls: u64]
New (macOS only):         [tpidrro_el0: u64, host_tls: u64]
```

- `tpidrro_el0`: The value of TPIDRRO_EL0 for this pthread. Stable, unique, never
  clobbered. Used as the lookup key by all shared handlers.
- `host_tls`: Pointer to the thread's `ThreadControlBlock` (TCB).
- Sentinel: `0xFFFFFFFFFFFFFFFF` in the first u64 marks end-of-table.

Linux retains the `[guest_tpidr, host_tls]` format unchanged.

### TCB Layout (macOS)

```
offset  0: scratch           (usize)
offset  8: host_sp            (usize)
offset 16: guest_context_top  (usize)
offset 24: guest_tpidr        (usize)    -- authoritative guest TPIDR value
offset 32: in_guest           (u8)
offset 33: interrupt          (u8)
offset 34: _pad               ([u8; 6])
offset 40: guest_x18          (usize)    -- NEW: virtualized guest x18
```

Total: 48 bytes (up from 40). No existing offsets shift.

### Trampoline Header (unchanged)

```
offset  0: callback address   (8 bytes)
offset  8: TLS table pointer  (8 bytes)
offset 16: sigreturn preamble (8 bytes = 2 instructions)
offset 24: sigreturn SVC gate (24 bytes)
offset 48: shared handlers begin
```

## 3. Shared Handler Redesign (macOS)

The core change: the TLS table lookup key switches from TPIDR_EL0 to TPIDRRO_EL0.
Since TPIDRRO_EL0 is never clobbered, the lookup always succeeds — no fallback path
needed. The sentinel path becomes a hard error (unknown thread) rather than a
best-effort recovery.

### 3.1 Shared SVC Handler (macOS)

The current handler reads TPIDR_EL0, searches for a matching `guest_tpidr` entry,
and falls back to entry[0] if clobbered. The new macOS handler:

1. Reads TPIDRRO_EL0 (always correct)
2. Searches TLS table for matching `tpidrro_el0` key
3. On match: loads `host_tls` from entry, saves guest x18 to TCB, loads guest_tpidr
   from TCB to frame
4. On sentinel: traps (BRK) — this is a bug, not a recoverable condition

**Instruction sequence** (~17 instructions, 68 bytes):

```
 [0]  MRS  X17, TPIDRRO_EL0       ; stable per-thread key
 [1]  LDR  X16, [PC, #off]        ; X16 = TLS table base
 [2]  LDR  X18, [X16, #0]         ; .Lloop: X18 = entry.tpidrro_el0
 [3]  CMN  X18, #1                ; sentinel?
 [4]  B.EQ .Ltrap                 ; -> [16] (unknown thread = bug)
 [5]  CMP  X18, X17               ; match tpidrro?
 [6]  B.EQ .Lfound                ; -> [9]
 [7]  ADD  X16, X16, #16          ; next entry
 [8]  B    .Lloop                 ; -> [2]
 [9]  LDR  X18, [X16, #8]         ; .Lfound: X18 = host_tls (TCB ptr)
[10]  LDR  X17, [X18, #24]        ; X17 = TCB.guest_tpidr
[11]  STR  X17, [SP, #24]         ; frame.guest_tpidr = guest_tpidr
[12]  LDR  X17, [SP, #32]         ; X17 = guest x18 (saved by gate)
[13]  STR  X17, [X18, #40]        ; TCB.guest_x18 = guest x18
[14]  LDR  X16, [PC, #off]        ; callback addr
[15]  BR   X16                    ; jump to callback
[16]  BRK  #1                     ; .Ltrap: unreachable (unknown thread)
```

### 3.2 Shared MSR Handler (macOS)

Finds entry by TPIDRRO_EL0 and updates `TCB.guest_tpidr`. Still executes
`MSR TPIDR_EL0` for belt-and-suspenders.

**Instruction sequence** (~17 instructions, 68 bytes):

```
 [0]  STR  X30, [SP, #32]         ; save BL return addr
 [1]  MRS  X16, TPIDRRO_EL0       ; stable lookup key
 [2]  LDR  X17, [PC, #off]        ; X17 = TLS table base
 [3]  LDR  X30, [X17, #0]         ; .Lloop: X30 = entry.tpidrro_el0
 [4]  CMN  X30, #1                ; sentinel?
 [5]  B.EQ .Ltrap                 ; -> [16] (unknown thread = bug)
 [6]  CMP  X30, X16               ; match tpidrro?
 [7]  B.EQ .Lfound                ; -> [10]
 [8]  ADD  X17, X17, #16          ; next entry
 [9]  B    .Lloop                 ; -> [3]
[10]  LDR  X17, [X17, #8]         ; .Lfound: X17 = host_tls (TCB ptr)
[11]  LDR  X16, [SP, #24]         ; X16 = new guest_tpidr (from gate)
[12]  STR  X16, [X17, #24]        ; TCB.guest_tpidr = new value
[13]  MSR  TPIDR_EL0, X16         ; set hardware register (best-effort)
[14]  LDR  X30, [SP, #32]         ; restore BL return addr
[15]  RET
[16]  BRK  #1                     ; .Ltrap: unreachable
```

### 3.3 Shared MRS Handler (macOS, NEW)

Looks up TCB via TPIDRRO_EL0, reads `TCB.guest_tpidr`, writes it to `[SP+24]`
for the gate to load into Xd.

Uses the same TPIDRRO_EL0 scan loop pattern. Called via BL from per-site MRS gates.

### 3.4 Shared x18 Load Handler (macOS, NEW)

Looks up TCB via TPIDRRO_EL0, reads `TCB.guest_x18` (offset 40), writes it to
`[SP+24]` for the gate to load into the scratch register.

### 3.5 Shared x18 Save Handler (macOS, NEW)

Looks up TCB via TPIDRRO_EL0, reads `[SP+24]` (new x18 value from gate), writes
it to `TCB.guest_x18` (offset 40).

## 4. Per-site Gate Designs (macOS)

All gate changes are macOS-only. Linux gates remain unchanged.

### 4.1 SVC Gate (macOS)

**New:** 7 instructions, 28 bytes. Frame expands to 48 bytes to hold guest x18:

```
[SP+ 0] = X16         (scratch)
[SP+ 8] = X17         (scratch)
[SP+16] = X30         (guest LR / return addr)
[SP+24] = guest_tpidr (written by shared handler from TCB)
[SP+32] = X18         (guest x18, saved by gate)
[SP+40] = (available)
```

```
[0] SUB  SP, SP, #48            ; 48-byte frame (was 32)
[1] STP  X16, X17, [SP]         ; save X16, X17
[2] STR  X30, [SP, #16]         ; save guest LR
[3] STR  X18, [SP, #32]         ; save guest x18 (NEW)
[4] ADRP X30, <return_page>     ; return addr high bits
[5] ADD  X30, X30, #<pageoff>   ; return addr low 12 bits
[6] B    <shared_svc_handler>   ; branch to shared handler
```

### 4.2 MSR Gate (macOS)

**Unchanged in structure.** Still 9/10 instructions (36/40 bytes). The gate stores
the new TPIDR value at `[SP+24]` and calls the shared MSR handler via BL. The
shared handler internals changed but the gate interface is the same.

### 4.3 MRS Gate (macOS)

**New:** 9 instructions, 36 bytes. Now calls shared MRS handler via BL instead of
inline TLS table read.

General case (Xd not in {X16, X17}):

```
[0] SUB  SP, SP, #32            ; 32-byte frame
[1] STP  X16, X17, [SP]         ; save scratch
[2] STR  X30, [SP, #16]         ; save LR (for BL)
[3] BL   <shared_mrs_handler>   ; handler writes guest_tpidr to [SP+24]
[4] LDR  Xd,  [SP, #24]         ; Xd = guest_tpidr
[5] LDP  X16, X17, [SP]         ; restore scratch
[6] LDR  X30, [SP, #16]         ; restore LR
[7] ADD  SP, SP, #32            ; deallocate
[8] B    <return_addr>           ; back to guest
```

Special cases for Xd = X16/X17/X30 need minor adjustments (same pattern as MSR
gate special cases).

### 4.4 x18 Gate (macOS, NEW)

Every instruction referencing x18 is rewritten to a gate. The original instruction
is modified to use a scratch register (X17 by default, X16 if instruction uses X17).

**x18-read-only** (x18 is source, not destination) — 10 insns / 40 bytes:

```
[0] SUB  SP, SP, #32
[1] STP  X16, X17, [SP]
[2] STR  X30, [SP, #16]
[3] BL   <shared_x18_load>      ; writes guest_x18 to [SP+24]
[4] LDR  X17, [SP, #24]         ; X17 = guest_x18
[5] <rewritten instruction>     ; original insn with x18 -> X17
[6] LDP  X16, X17, [SP]
[7] LDR  X30, [SP, #16]
[8] ADD  SP, SP, #32
[9] B    <return_addr>
```

**x18-write-only** (x18 is destination) — 10 insns / 40 bytes:

```
[0] SUB  SP, SP, #32
[1] STP  X16, X17, [SP]
[2] STR  X30, [SP, #16]
[3] <rewritten instruction>     ; original insn with x18 -> X17
[4] STR  X17, [SP, #24]         ; frame[24] = new x18 value
[5] BL   <shared_x18_save>      ; reads [SP+24], stores to TCB.guest_x18
[6] LDP  X16, X17, [SP]
[7] LDR  X30, [SP, #16]
[8] ADD  SP, SP, #32
[9] B    <return_addr>
```

**x18-read-write** (x18 is both source and destination) — 12 insns / 48 bytes:

```
[0]  SUB  SP, SP, #32
[1]  STP  X16, X17, [SP]
[2]  STR  X30, [SP, #16]
[3]  BL   <shared_x18_load>      ; [SP+24] = guest_x18
[4]  LDR  X17, [SP, #24]         ; X17 = guest_x18
[5]  <rewritten instruction>     ; x18 -> X17
[6]  STR  X17, [SP, #24]         ; store updated value
[7]  BL   <shared_x18_save>      ; TCB.guest_x18 = [SP+24]
[8]  LDP  X16, X17, [SP]
[9]  LDR  X30, [SP, #16]
[10] ADD  SP, SP, #32
[11] B    <return_addr>
```

**Scratch register choice:** X17 by default. X16 if instruction uses X17. X15 (with
extra save/restore) if both X16 and X17 are used — extremely rare.

## 5. x18 Instruction Detection

### 5.1 The Problem

ARM64 register x18 can appear in any instruction form — arithmetic, loads, stores,
moves, compares, bitwise ops. x18 can be encoded in different bit positions:

- **Rd** (destination): bits [4:0]
- **Rn** (first source): bits [9:5]
- **Rm** (second source): bits [20:16]
- **Rt** (load/store transfer): bits [4:0]
- **Rt2** (load/store pair second): bits [14:10]

We use **yaxpeax-arm** (0.4.0) for reliable instruction decoding rather than
fragile bitmask matching.

### 5.2 PatchKind Variant

```rust
enum PatchKind {
    Svc,
    MsrTpidr(u8),
    MrsTpidr(u8),
    #[cfg(target_os = "macos")]
    X18Use {
        insn: u32,       // original instruction word
        rewritten: u32,  // instruction with x18 replaced by scratch
        scratch: u8,     // scratch register (17 or 16)
        is_read: bool,   // x18 is read by this instruction
        is_write: bool,  // x18 is written by this instruction
    },
}
```

The `rewritten` field is computed at scan time by flipping register bits in the raw
instruction word.

### 5.3 Scanning Logic

The scan loop in `find_patch_sites` gains a macOS-only branch after the existing
SVC/MSR/MRS checks:

```rust
#[cfg(target_os = "macos")]
{
    if references_x18(insn) {
        let (rewritten, scratch, is_read, is_write) = rewrite_x18(insn);
        sites.push(PatchSite {
            kind: PatchKind::X18Use { insn, rewritten, scratch, is_read, is_write },
            ..
        });
    }
}
```

### 5.4 `references_x18`

Uses yaxpeax-arm to decode the instruction and inspect operands for register 18.

### 5.5 `rewrite_x18`

Performs bit-level replacement on the raw instruction word. Checks each standard
register field position (Rd, Rn, Rm, Rt2) for value 18 and replaces with the
scratch register number. Uses the yaxpeax decode to determine read vs write
semantics (e.g., LDR Rd is write, STR Rt is read).

### 5.6 Edge Cases

- **`MOV X18, X18`**: Both read and write. Scratch replaces all positions.
- **`STP X18, X3, [SP]`**: x18 in Rt position (bits [4:0]), read.
- **`LDP X5, X18, [SP]`**: x18 in Rt2 position (bits [14:10]), write.
- **X16+X17+X18 simultaneous**: Use X15 as scratch with extra save/restore.
- **`BR X18` / `BLR X18`**: Load guest_x18 into scratch, execute `BR scratch`.
- **SVC/MSR/MRS instructions**: Already handled by their own gates; x18 scanning skips.

## 6. Platform-side Changes (macOS)

### 6.1 TCB Extension

Add `guest_x18: usize` at offset 40. Add `tcb_offset_guest_x18() -> isize { 40 }`.
Initialize to 0 in thread setup. No existing offsets shift.

### 6.2 `update_host_tls_entry` Rewrite

Simplifies drastically with TPIDRRO_EL0-keyed lookup:

1. Read TPIDRRO_EL0 (always available, stable)
2. Search table for matching key
3. If found: update `host_tls` field
4. If sentinel: write new `[tpidrro_el0, host_tls]` entry

Removed complexity:
- Phantom entry cleanup (no longer possible)
- Reverse lookup by host_tls
- guest_tpidr sync from table to TCB (MSR handler writes TCB directly)

~15 lines vs ~130 lines today.

### 6.3 In-trampoline TPIDR Fixup Removal

The `call_shim` block (current lines 2172-2192) that patches x18/x16 when a signal
interrupts the shared SVC/MSR handler mid-execution is removed. With TPIDRRO_EL0-
based handlers, there is no stale TPIDR register to fix up.

### 6.4 `syscall_callback` Changes

The callback continues reading `guest_tpidr` from `[SP+24]` (unchanged frame slot).
The shared SVC handler populates this from TCB.

### 6.5 `switch_to_guest` Changes

Load `guest_x18` from `TCB.guest_x18` (offset 40) for the stash-below-SP
restoration, replacing the current approach that stashes the host_tls value as x18.

### 6.6 `copy_signal_context` Changes

Patch `regs[18]` from `TCB.guest_x18` instead of the mach context's x18 (which the
kernel zeroes):

```rust
let tcb = TCB_PTR.get();
if !tcb.is_null() {
    regs.regs[18] = unsafe { (*tcb).guest_x18 };
}
```

### 6.7 Signal Return Path

`set_signal_return` writing `host_tls` into x9 in the ucontext is unchanged.
Sigreturn clobbers TPIDR_EL0, so the callback still needs host_tls to restore it.

## 7. Conditional Compilation Strategy

### 7.1 Separate Handler Functions

Rather than inline `cfg` inside emit functions, use separate functions per platform:

```rust
fn emit_shared_svc_handler(...) {
    #[cfg(target_os = "linux")]
    emit_shared_svc_handler_linux(...)?;
    #[cfg(target_os = "macos")]
    emit_shared_svc_handler_macos(...)?;
}
```

Similarly for MSR handler. Current code is renamed to `_linux` variants.

### 7.2 Gated PatchKind Variant

`PatchKind::X18Use` is gated with `#[cfg(target_os = "macos")]` on the variant
itself, so match exhaustiveness enforces that Linux code never handles x18.

### 7.3 Divergent Layout Constants

macOS gets additional shared handlers and different sizes/offsets. Constants are
gated per-platform.

### 7.4 Platform Crate

All platform changes are in `litebox_platform_macos_userland` (macOS-only crate),
so no `cfg` gating needed at file level.

### 7.5 yaxpeax-arm Dependency

Added as unconditional dependency in `litebox_syscall_rewriter/Cargo.toml` (pure
Rust crate). Usage gated with `#[cfg(target_os = "macos")]`.

## 8. Implementation Plan

### Phase 1: Foundation (no behavioral change)

| Task | Description |
|------|-------------|
| 1 | Add yaxpeax-arm dependency to Cargo.toml |
| 2 | Extend TCB with `guest_x18` at offset 40 |
| 3 | Add `PatchKind::X18Use` variant (placeholder match arms) |

### Phase 2: TLS Table Key Migration (atomic, macOS)

| Task | Description |
|------|-------------|
| 4 | Rewrite `update_host_tls_entry` to TPIDRRO_EL0-keyed lookup |
| 5 | Add `emit_shared_svc_handler_macos` (TPIDRRO_EL0, x18 save, guest_tpidr load) |
| 6 | Add `emit_shared_msr_handler_macos` (TPIDRRO_EL0, TCB write) |
| 7 | Expand SVC gate to 7 insns / 28 bytes (add x18 save) |

Tasks 4-7 must land together — they change the TLS table format atomically.

### Phase 3: MRS Handler (macOS)

| Task | Description |
|------|-------------|
| 8 | Add shared MRS handler (TPIDRRO_EL0 -> TCB -> guest_tpidr -> [SP+24]) |
| 9 | Rewrite MRS gates to BL-based 9-insn gates |

### Phase 4: x18 Virtualization

| Task | Description |
|------|-------------|
| 10 | Add shared x18 load/save handlers |
| 11 | Implement `references_x18` and `rewrite_x18` using yaxpeax-arm |
| 12 | Add x18 scanning to `find_patch_sites` |
| 13 | Implement `emit_x18_gate` (read/write/read-write templates) |

### Phase 5: Platform Integration

| Task | Description |
|------|-------------|
| 14 | Update `switch_to_guest` to load guest_x18 from TCB offset 40 |
| 15 | Update `copy_signal_context` to patch x18 from TCB |
| 16 | Remove in-trampoline TPIDR fixup from `call_shim` |

### Phase 6: Testing

| Task | Description |
|------|-------------|
| 17 | Update existing unit tests for new handler/gate sequences |
| 18 | Add x18 detection, rewriting, gate emission, and handler unit tests |
| 19 | Integration testing (TLS, multi-thread, signals) |

### Dependency Graph

```
Task 1 --+
Task 2 --+
Task 3 --+-- Tasks 4-7 (atomic) --+-- Tasks 8-9 --+-- Tasks 14-16
                                   |                |
                                   +-- Task 10 -----+-- Tasks 11-13
                                                         |
                                                    Tasks 17-19
```

### Risk Areas

1. **Tasks 4-7 atomicity:** TLS table format change must land with all consumers
   updated simultaneously.
2. **x18 instruction coverage:** yaxpeax-arm may not decode every form. Fallback:
   manual bit-position check for register 18 if decode fails.
3. **`BR X18` / `BLR X18`:** Gate loads guest_x18 into scratch, executes
   `BR scratch`. Works with standard template.
4. **Performance:** Each x18 reference adds ~10 instructions. Real Linux ARM64
   compilers rarely use x18 (platform register), so usage should be sparse.

## Relevant Files

| File | Role |
|------|------|
| `litebox_syscall_rewriter/src/arm64.rs` | Main rewriter: handlers, gates, scanning |
| `litebox_platform_macos_userland/src/lib.rs` | macOS platform: TCB, signals, TLS |
| `litebox_syscall_rewriter/Cargo.toml` | Add yaxpeax-arm dependency |
| `litebox_common_linux/src/loader.rs` | ELF loader, TLS table allocation |

## Implementation Status

All 6 phases are **complete and committed** on `sanghle/macos_2`. Beyond the original
plan, numerous runtime bugs were discovered and fixed during macOS integration testing.

### Completed (34 commits)

| Commit | Description |
|--------|-------------|
| `ef857eb8` | Design document (this file) |
| `59e79dfd` | Phase 1: yaxpeax-arm dep, TCB guest_x18 field, PatchKind::X18Use |
| `78702694` | Phase 2: macOS TPIDRRO_EL0-keyed SVC/MSR shared handlers |
| `d128ff5c` | Phase 3: Shared MRS handler for macOS |
| `5ebca66d` | Phase 4: Full x18 virtualization in rewriter |
| `22ffab4f` | Phase 5: macOS platform integration |
| `97377d38` | Fix: `syscall_callback` frame size 32→48 |
| `fa79b561` | Fix: Save/restore NZCV condition flags in macOS gates |
| `fdfef697` | Fix: `adjust_sp_relative_offset()` for 48-byte gate frame |
| `ccf69a53` | Fix: SP-restore strategy for offset overflow |
| `8f9abb75` | Fix: Per-sub-page edge page tracking (ported from old litebox) |
| `0d974a91` | Fix: NZCV restore moved before guest instruction in all gate paths |
| `3aef8f36` | Fix: rtld_audit platform-adaptive dual-path `do_syscall` |
| `cac170a1` | Fix: Signal-delivery x18 race in `syscall_callback` |
| `2766f639` | Fix: TLS table write race — AtomicU64 CAS for slot claiming |
| `b38bba72` | Fix: `switch_to_guest` x18 preemption race |
| `d82c8bb8` | Fix: SVC shared handler preemption — use x16 instead of x18 |
| `2885f023` | Fix: Remove all 7 host-side TPIDR_EL0 writes |
| `756bc33f` | Fix: `switch_to_guest` guest SP via x1 instead of x18 |
| `abd300ec` | Fix: rtld_audit macOS x18 race in TLS lookup |
| `69578730` | Fix: brk ENOMEM — remove bypass in `insert_mapping` |
| `34c4f6ad` | Fix: Clippy warnings |
| `29787b4e` | Fix: Remaining clippy warnings |
| `8f438dd5` | Fix: brk ENOMEM — `evict_reserved_from_brk_zone()` |
| `06b8898a` | Diag: rtld_audit mprotect integrity check |
| `b3413bf1` | Fix: icache invalidation in rtld_audit |
| `114beb26` | Fix: EACCES from mprotect on codesigned host pages |
| `4b948427` | Fix: mmap ENOMEM fallback — bottom-up gap search |
| `21abdcff` | Fix: diagnostic log borrow issue |
| `091f8ef0` | Fix: hint=0 retry in insert_mapping (later superseded) |
| `2f56688f` | Fix: mach_vm_allocate 3-level fallback in macOS allocate_pages |
| `47ab6fc6` | Diag: `mm_diag!` macro + macOS-only tracing |
| `9a2a9f93` | Fix: brk-zone retry uses Hint instead of NoReplace (root cause) |
| `1a56f702` | Fix: clippy pedantic warnings |

### Key Discoveries

1. **XNU zeros x18** on ALL kernel→userspace transitions (preemptive context switches,
   not just signals). No signal involved. x18 must NEVER be used as a temp register.
2. **XNU overwrites TPIDR_EL0** with a per-CPU value on every return to userspace.
   TPIDR_EL0 must never be written on host-side code paths (libsystem_malloc uses it).
3. **NZCV condition flags** are clobbered by shared handler CMP/CMN instructions. Must
   be restored BEFORE the rewritten guest instruction, not in the epilogue.
4. **macOS ignores mmap hints** aggressively — CONFIG_MAP_RANGES forces anonymous mmaps
   into a randomly-placed 1 TB heap range. The brk-zone retry must use Hint behavior
   (not MAP_FIXED) because the VMA tree doesn't track invisible host mappings.
5. **TPIDRRO_EL0** is stable per-pthread, read-only, unique, and never clobbered —
   the correct key for per-thread TLS table lookup on macOS.

### Current State

- **rtld_audit.so now loads successfully** — the mmap ENOMEM root cause (brk-zone
  retry using NoReplace on invisible host mappings) is fixed.
- All 116 rewriter unit tests pass on Linux.
- Clippy clean (zero warnings).
- macOS platform crate compiles on Linux (`cargo check` passes).
