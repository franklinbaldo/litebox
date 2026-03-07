# ARM64 Shared Trampoline Design

## Motivation

The current ARM64 rewriter (`litebox_syscall_rewriter/src/arm64.rs`) generates
self-contained per-site snippets for every `SVC #0` (76 bytes each) and
`MSR TPIDR_EL0` (96 bytes each) patch site. This has two weaknesses compared to
the approach used by [svc-hook](https://github.com/retrage/svc-hook):

1. **Memory footprint** -- The TLS lookup loop and callback dispatch logic are
   duplicated across every snippet. For a binary with 728 SVCs, this totals
   ~55 KB of trampoline code.

2. **No central control** -- Changing the TLS table walk or callback protocol
   requires updating every inline snippet pattern. Bug-prone and hard to maintain.

3. **No support for >128MB binaries** -- If patch sites span more than 128 MB
   (the range of ARM64 `B imm26`), the rewriter fails. svc-hook handles this by
   creating multiple trampoline regions.

## Design

### Core idea

Factor common code into **shared handlers** (one for SVC, one for MSR). Each
patch site gets a small **per-site gate** that sets up site-specific values and
branches to the shared handler.

### Register protocol

**SVC gates -> shared SVC handler -> callback:**

| Register | Value at shared handler entry |
|----------|------------------------------|
| X16      | Saved to `[SP, #0]` by gate  |
| X17      | Saved to `[SP, #8]` by gate  |
| X30      | Guest return address (set by gate via ADRP+ADD) |
| SP       | Decremented by 32 (frame: `[0]=X16, [8]=X17, [16]=guest_LR, [24]=guest_TPIDR`) |

The shared SVC handler fills `[SP, #24]` with guest TPIDR and loads host TLS
into X18 via the TLS lookup table, then jumps to the callback. The callback ABI
is **unchanged** from the current design.

**MSR gates -> shared MSR handler -> return to guest:**

| Register | Value at shared handler entry |
|----------|------------------------------|
| X16      | Saved to `[SP, #0]` by gate  |
| X17      | Saved to `[SP, #8]` by gate  |
| X30      | Return-to-gate address (set by BL instruction) |
| SP       | Decremented by 32 (frame: `[0]=X16, [8]=X17, [16]=guest_LR, [24]=new_TPIDR`) |

The shared MSR handler updates the TLS table, executes the actual MSR, and
returns via `RET` to the gate's epilogue. The gate restores all registers and
branches back to guest code.

### Trampoline layout

```
Offset 0:     [8 bytes]   syscall_callback address (filled at load time)
Offset 8:     [8 bytes]   TLS lookup table pointer (filled at load time)
Offset 16:    [8 bytes]   Sigreturn preamble (MOV X8, #139 + B .+4)
Offset 24:    [24 bytes]  Sigreturn SVC gate
Offset 48:    [56 bytes]  Shared SVC handler
Offset 104:   [56 bytes]  Shared MSR handler
Offset 160:   [24 bytes]  Per-site SVC gate #1
Offset 184:   [24 bytes]  Per-site SVC gate #2
              ...
              [36 bytes]  Per-site MSR gate #1 (size varies 36-40 by source reg)
              ...
```

### Per-site SVC gate (6 instructions, 24 bytes)

```asm
SUB  SP, SP, #32             // allocate 32-byte frame
STP  X16, X17, [SP]          // save X16, X17 at [SP+0], [SP+8]
STR  X30, [SP, #16]          // save guest LR at [SP+16]
ADRP X30, <return_page>      // return address = site.vaddr + 4 (high bits)
ADD  X30, X30, #<page_off>   // return address (low 12 bits)
B    <shared_svc_handler>    // branch to shared handler
```

### Shared SVC handler (14 instructions, 56 bytes)

```asm
shared_svc_handler:
  MRS  X18, TPIDR_EL0        // X18 = guest TPIDR
  STR  X18, [SP, #24]        // save guest TPIDR to [SP+24]
  LDR  X17, [PC, #off]       // load TLS table pointer from header offset 8
.Lloop:
  LDR  X16, [X17, #0]        // load guest_tpidr from table entry
  CMN  X16, #1               // sentinel check (-1 / 0xFFFFFFFFFFFFFFFF)
  B.EQ .Ldone                // not found -> use guest TPIDR as-is
  CMP  X16, X18              // compare with current guest TPIDR
  B.EQ .Lfound               // match -> load host TLS
  ADD  X17, X17, #16         // advance to next 16-byte entry
  B    .Lloop
.Lfound:
  LDR  X18, [X17, #8]        // X18 = host TLS base
.Ldone:
  LDR  X16, [PC, #off]       // load callback address from header offset 0
  BR   X16                   // jump to syscall_callback
```

### Per-site MSR gate (general case: 9 instructions, 36 bytes)

```asm
  SUB  SP, SP, #32
  STP  X16, X17, [SP]        // [0]=X16, [8]=X17
  STR  X30, [SP, #16]        // [16]=guest LR
  STR  Xt,  [SP, #24]        // [24]=new TPIDR value (site-specific register)
  BL   shared_msr_handler    // call shared handler (X30 set to return addr by BL)
  LDP  X16, X17, [SP]        // restore X16, X17
  LDR  X30, [SP, #16]        // restore guest LR
  ADD  SP, SP, #32           // deallocate frame
  B    <return_addr>          // branch back to site.vaddr + 4
```

**Special register cases** for the `STR Xt, [SP, #24]` instruction:

- **X16**: `LDR Xt_tmp, [SP, #0]` + `STR Xt_tmp, [SP, #24]` (reload from saved slot, 2 insns, gate = 40 bytes)
- **X17**: `LDR Xt_tmp, [SP, #8]` + `STR Xt_tmp, [SP, #24]` (2 insns, 40 bytes)
- **X30**: `LDR Xt_tmp, [SP, #16]` + `STR Xt_tmp, [SP, #24]` (2 insns, 40 bytes)
- **XZR**: `STR XZR, [SP, #24]` (1 insn, 36 bytes -- same as general case)

### Shared MSR handler (14 instructions, 56 bytes)

```asm
shared_msr_handler:
  MRS  X16, TPIDR_EL0        // X16 = old guest TPIDR
  LDR  X17, [PC, #off]       // X17 = TLS table pointer from header offset 8
.Lloop:
  LDR  X30, [X17, #0]        // load table entry guest_tpidr (X30 as scratch -- BL saved return addr)
  CMN  X30, #1               // sentinel?
  B.EQ .Ldone
  CMP  X30, X16              // match old TPIDR?
  B.EQ .Lfound
  ADD  X17, X17, #16
  B    .Lloop
.Lfound:
  LDR  X16, [SP, #24]        // load new TPIDR from stack
  STR  X16, [X17, #0]        // update table entry
.Ldone:
  LDR  X16, [SP, #24]        // load new TPIDR
  MSR  TPIDR_EL0, X16        // execute actual MSR
  RET                         // return to gate epilogue (X30 from BL)
```

Note: X30 is used as scratch inside the shared MSR handler. This is safe because
BL saved the return-to-gate address in X30, and we preserve it through the loop
(the B.EQ .Lfound branch only taken when X30 holds a table value, but after RET
X30 has the BL return address -- wait, we clobber X30 in the loop).

**Correction**: X30 is clobbered by the loop. We need to save the BL return
address. Options:
1. Save X30 (BL return addr) to an extra stack slot before the loop.
2. Use a different scratch register in the loop.

Option 2 is cleaner. We can't use X16 (holds old TPIDR) or X17 (holds table
ptr). But we already saved X16's original value to the stack. Reorder:

```asm
shared_msr_handler:
  // At entry: X30 = return-to-gate (from BL). Must preserve X30.
  STR  X30, [SP, #-8]!       // push BL return addr (SP -= 8)
  MRS  X16, TPIDR_EL0        // X16 = old guest TPIDR
  LDR  X17, [PC, #off]       // X17 = TLS table pointer
.Lloop:
  LDR  X30, [X17, #0]        // X30 as scratch for table reads
```

No, this still clobbers X30. And [SP, #24] offsets shift with the push.

Better: just save/restore BL return via the frame. Since the MSR gate allocates
32 bytes but only uses [0..31], we can't easily add a slot. Alternative: use
the existing [SP, #16] slot -- but that holds guest LR.

Simplest fix: **make the MSR frame 48 bytes**, add slot [32] for BL return addr.

Revised per-site MSR gate:

```asm
  SUB  SP, SP, #48           // 48-byte frame
  STP  X16, X17, [SP]
  STR  X30, [SP, #16]        // guest LR
  STR  Xt,  [SP, #24]        // new TPIDR
  BL   shared_msr_handler    // X30 = return-to-gate
  LDP  X16, X17, [SP]
  LDR  X30, [SP, #16]        // restore guest LR
  ADD  SP, SP, #48
  B    <return_addr>
```

Revised shared MSR handler:

```asm
shared_msr_handler:
  STR  X30, [SP, #32]        // save BL return addr at [SP+32]
  MRS  X16, TPIDR_EL0
  LDR  X17, [PC, #off]       // TLS table pointer
.Lloop:
  LDR  X30, [X17, #0]
  CMN  X30, #1
  B.EQ .Ldone
  CMP  X30, X16
  B.EQ .Lfound
  ADD  X17, X17, #16
  B    .Lloop
.Lfound:
  LDR  X16, [SP, #24]
  STR  X16, [X17, #0]
.Ldone:
  LDR  X16, [SP, #24]
  MSR  TPIDR_EL0, X16
  LDR  X30, [SP, #32]        // restore BL return addr
  RET                         // 16 instructions, 64 bytes
```

### Multi-region support (>128MB)

Group patch sites by overlapping reachable ranges. Sites whose +/-128MB windows
overlap go in the same group. Each group gets its own trampoline region (with
its own shared handlers and per-site gates), allocated within the group's
reachable window via `mmap` at load time (same approach as svc-hook).

The rewriter returns multiple trampoline regions instead of a single blob. The
loader allocates each region within its reachable window.

This is a separate implementation task and can be deferred if >128MB binaries
are not yet encountered.

## Size comparison

| Component           | Current  | Proposed |
|---------------------|----------|----------|
| Per SVC site        | 76 bytes | 24 bytes |
| Per MSR site        | 96 bytes | 40 bytes (worst case) |
| Shared SVC handler  | 0        | 56 bytes |
| Shared MSR handler  | 0        | 64 bytes |
| 728 SVCs + 3 MSRs   | 55,616 B | 17,752 B |
| Reduction           |          | 3.1x     |

## Implementation tasks

1. Implement shared SVC handler emission
2. Implement per-site SVC gate emission (replacing current `emit_svc_snippet`)
3. Implement shared MSR handler emission
4. Implement per-site MSR gate emission (replacing current `emit_msr_tpidr_snippet`)
5. Update trampoline layout constants (header offsets)
6. Update all existing unit tests for new layout
7. Verify snapshot tests pass
8. Run full test suite, clippy, fmt
9. (Deferred) Multi-region support for >128MB binaries
