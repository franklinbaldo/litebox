# LITEBOX WINDOWS USERLAND PLATFORM - ARM64 PORTING QUICK REFERENCE

## DOCUMENT SUMMARY

Two comprehensive guides have been created in /litebox/:
1. **ARM64_PORTING_GUIDE.md** (15.8 KB)
   - Complete code listings from source files
   - Line-by-line assembly reference
   - PtRegs structure definitions
   - Architecture differences table

2. **ARM64_MIGRATION_DETAILED.md** (14.5 KB)
   - Step-by-step implementation roadmap
   - Code snippets for each change
   - Testing strategy
   - Compiler intrinsics reference

---

## CRITICAL FILES TO MODIFY

### File 1: litebox_platform_windows_userland/src/lib.rs

| Line Range | Section | Changes Required |
|-----------|---------|-------------------|
| 8 | cfg gate | Change x86_64 to aarch64 |
| 73-96 | FS base helpers | No change (uses wrfsbase) |
| 99-165 | Exception handler | Test with ARM64 CONTEXT struct |
| 167-213 | save_guest_context | Map Windows ARM64 CONTEXT to PtRegs |
| 425-587 | **run_thread_arch** | COMPLETE REWRITE - naked assembly |
| 496-497 | TLS slot access | Change GS segment to TPIDR_EL0 |
| 505-526 | Stack building | Update for ARM64 PtRegs layout |
| 599-704 | switch_to_guest | Rewrite assembly (sysret → br) |
| 807-933 | interrupt handling | Update register context access |
| 938-948 | set_context_to_interrupt | Update register names (Rip → Pc, Rsp → Sp) |
| 1366-1367 | TASK_ADDR_MIN/MAX | Update for ARM64 address space |
| 1689-1710 | exception mapping | Add ARM64-specific exception codes |
| 1681-1759 | handler functions | Should work as-is (generic C-unwind ABI) |

### File 2: litebox_common_linux/src/lib.rs

| Line Range | Section | Changes Required |
|-----------|---------|-------------------|
| 1131-1142 | rdfsbase() | ADD #[cfg(target_arch = "aarch64")] variant |
| 1154-1162 | wrfsbase() | ADD #[cfg(target_arch = "aarch64")] variant |
| 3352-3367 | PtRegs ARM64 | ALREADY DEFINED! No changes needed |
| 3414-3425 | syscall_arg() ARM64 | ALREADY DEFINED! No changes needed |
| 3450-3454 | get_ip() ARM64 | ALREADY DEFINED! No changes needed |

---

## KEY ASSEMBLY TRANSLATIONS

### Prologue: Save Non-Volatile Registers

**X86-64** (x86_64 has 7 non-volatile + 10 XMM):
`sm
push rbp
push rbx
push rdi
push rsi
push r12
push r13
push r14
push r15
sub rsp, 168  ; 10 XMM * 16 bytes
`

**ARM64** (aarch64 has 10 non-volatile + 8 NEON):
`sm
stp x29, x30, [sp, #-16]!    ; FP, LR
stp x27, x26, [sp, #-16]!
stp x25, x24, [sp, #-16]!
stp x23, x22, [sp, #-16]!
stp x21, x20, [sp, #-16]!
stp x19, x28, [sp, #-16]!    ; x28 is BP alternative
stp d8, d9, [sp, #-16]!      ; 8 NEON registers
stp d10, d11, [sp, #-16]!
stp d12, d13, [sp, #-16]!
stp d14, d15, [sp, #-16]!
`

### TLS Slot Access

**X86-64** (GS segment):
`sm
mov r11d, DWORD PTR [rip + TLS_INDEX]
mov r11, QWORD PTR gs:[r11 * 8 + TEB_TLS_SLOTS_OFFSET]  ; GS + offset
`

**ARM64** (TPIDR_EL0):
`sm
adr x11, TLS_INDEX                    ; or use RIP-relative
ldr w12d, [x11]                       ; Load TLS index
mrs x13, tpidr_el0                    ; Get thread pointer
ldr x11, [x13, x12, lsl #3]           ; Load from thread pointer
`

### Context Switching

**X86-64** (sysret path):
`sm
mov rsp, rcx        ; rcx points to pt_regs
pop r15
... (15 more pops)
pop rsp
jmp rcx
`

**ARM64** (EREt/branch path):
`sm
; x0 points to PtRegs
ldp x0, x1, [x0, ...]    ; Load registers from PtRegs
ldp x2, x3, [x0, ...]
... (continue unloading)
ldr x30, [x0]            ; Load PC into LR
ldr sp, [x0, #offset]    ; Restore SP
eret                      ; or br x30
`

---

## REGISTER MAPPING: X86-64 → ARM64

| Purpose | X86-64 | ARM64 | Notes |
|---------|--------|-------|-------|
| **Argument 0** | RCX | X0 | thread_ctx |
| **Argument 1** | RDX | X1 | tls_state |
| **Return Address** | Stack (RIP) | X30 (LR) | Implicit |
| **Stack Pointer** | RSP | SP | Special register |
| **Frame Pointer** | RBP | X29 (FP) | Callee-saved |
| **Non-volatiles** | RBX, R12-R15 | X19-X28 | 7 vs 10 regs |
| **Vector reg NV** | XMM6-XMM15 | V8-V15 | 10 vs 8 regs |
| **TLS Base** | GS:OFFSET | TPIDR_EL0 | Register read |
| **Return Value** | RAX | X0 | First 64 bits |
| **Temp/Volatile** | R8-R11, RAX-RDI | X0-X18 | Can be clobbered |

---

## WINDOWS API CONTEXT STRUCTURE MAPPING

### X86-64 CONTEXT Fields Used:
`
R15, R14, R13, R12, Rbp, Rbx, R11, R10, R9, R8
Rax, Rcx, Rdx, Rsi, Rdi
orig_rax (actually Rax), Rip, Cs, EFlags, Rsp, Ss
`

### ARM64 CONTEXT Fields Needed:
`
X30, X29, X28, X27, X26, X25, X24, X23, X22, X21, X20, X19
X18, X17, X16, X15, X14, X13, X12, X11, X10, X9, X8
X7, X6, X5, X4, X3, X2, X1, X0
Sp, Pc, Cpsr (flags)
`

---

## OFFSET CALCULATIONS FOR TlsState (offset_of! macros)

These are **already correct** and architecture-independent:
`ust
HOST_SP = core::mem::offset_of!(TlsState, host_sp)       // 0
HOST_BP = core::mem::offset_of!(TlsState, host_bp)       // 8
GUEST_CONTEXT_TOP = core::mem::offset_of!(TlsState, guest_context_top) // 16
SCRATCH = core::mem::offset_of!(TlsState, scratch)       // 24
IS_IN_GUEST = core::mem::offset_of!(TlsState, is_in_guest) // 32
`

No changes needed - they're calculated at compile time!

---

## PTREG MEMORY LAYOUT ON STACK

### X86-64: 168 bytes (21 registers × 8 bytes)
`
[sp+0]   = r15, [sp+8]   = r14, [sp+16]  = r13, [sp+24]  = r12
[sp+32]  = rbp, [sp+40]  = rbx,  [sp+48]  = r11, [sp+56]  = r10
[sp+64]  = r9,  [sp+72]  = r8,   [sp+80]  = rax, [sp+88]  = rcx
[sp+96]  = rdx, [sp+104] = rsi,  [sp+112] = rdi, [sp+120] = orig_ax
[sp+128] = rip, [sp+136] = cs,   [sp+144] = eflags, [sp+152] = rsp
[sp+160] = ss
`

### ARM64: 272 bytes (34 registers × 8 bytes)
`
[sp+0]   = x0, [sp+8]   = x1, ..., [sp+240] = x30
[sp+248] = sp, [sp+256] = pc, [sp+264] = pstate
`

---

## EXCEPTION CODE MAPPING

### Windows → LiteBox Exception Types

| Windows Code | X86-64 LiteBox | ARM64 LiteBox | Notes |
|--------------|----------------|---------------|-------|
| EXCEPTION_ACCESS_VIOLATION | PAGE_FAULT | PAGE_FAULT | Map from ExceptionInformation |
| EXCEPTION_ILLEGAL_INSTRUCTION | INVALID_OPCODE | INVALID_OPCODE | Illegal/undefined instruction |
| EXCEPTION_BREAKPOINT | BREAKPOINT | BREAKPOINT | INT3/BRK instruction |
| EXCEPTION_INT_DIVIDE_BY_ZERO | DIVIDE_ERROR | DIVIDE_ERROR | DIV by zero (if arm64 gen) |
| (ARM64-specific) | N/A | May vary | Need to check Windows ARM64 docs |

---

## QUICK START: MINIMAL CHANGES LIST

1. **Change cfg gate** (Line 8)
   `ust
   #![cfg(all(target_os = "windows", target_arch = "aarch64"))]
   `

2. **Add ARM64 TLS functions** (after line 1162 in litebox_common_linux)
   `ust
   #[cfg(target_arch = "aarch64")]
   pub unsafe fn rdfsbase() -> usize {
       let ret: usize;
       core::arch::asm!("mrs {}, tpidr_el0", out(reg) ret, ...);
       ret
   }
   
   #[cfg(target_arch = "aarch64")]
   pub unsafe fn wrfsbase(fs_base: usize) {
       core::arch::asm!("msr tpidr_el0, {}", in(reg) fs_base, ...);
   }
   `

3. **Rewrite run_thread_arch** (Lines 425-587)
   - ~400 lines of ARM64 assembly
   - See ARM64_MIGRATION_DETAILED.md for exact syntax

4. **Rewrite switch_to_guest** (Lines 599-704)
   - ~100 lines of ARM64 assembly
   - Uses branch instead of sysret

5. **Update save_guest_context** (Lines 167-213)
   - Map Windows ARM64 CONTEXT → PtRegs
   - Check field names in Windows SDK

6. **Update register offsets** (Lines 936-948)
   - Rip → Pc, Rsp → Sp, Rbp → Fp
   - For set_context_to_interrupt_callback

7. **Update TASK_ADDR_MIN/MAX** (Lines 1366-1367)
   - Query from system or use ARM64 defaults

---

## FILES CREATED FOR REFERENCE

1. **ARM64_PORTING_GUIDE.md**
   - Complete code listings from both files
   - Line-by-line breakdowns
   - Register mappings
   - Assembly syntax

2. **ARM64_MIGRATION_DETAILED.md**
   - Implementation roadmap
   - Code examples for each section
   - Checklist of changes
   - Testing strategy
   - Compiler intrinsics

3. **ARM64_QUICK_REFERENCE.md** (this file)
   - Summary tables
   - Key translations
   - Offset calculations
   - Quick start guide

---

## IMPORTANT NOTES FOR WINDOWS ON ARM64

1. **Windows ARM64 is real**: Windows 11 supports ARM64 (Snapdragon X Elite/Plus)
2. **TLS mechanism**: Windows likely uses TPIDR_EL0 similar to Linux
3. **Exception handling**: Windows ARM64 exception codes may differ from x86
4. **API compatibility**: Most Windows APIs (VirtualAlloc, etc.) work on ARM64
5. **Assembly constraints**: Must use ARM64 assembler syntax (not x86 inline asm)

---

## ESTIMATED EFFORT

| Component | Hours | Complexity |
|-----------|-------|------------|
| cfg changes | 0.5 | Trivial |
| TLS functions | 1 | Simple |
| save_guest_context | 1 | Simple |
| run_thread_arch | 8-12 | Complex (naked asm) |
| switch_to_guest | 2-3 | Medium (naked asm) |
| Exception handling | 1-2 | Medium |
| Handler updates | 0.5 | Simple |
| Memory mgmt | 1 | Simple |
| Testing | 8-10 | Complex |
| **TOTAL** | **24-30 hours** | Medium-Hard |

---

Generated: 2026-03-14 21:33:11
