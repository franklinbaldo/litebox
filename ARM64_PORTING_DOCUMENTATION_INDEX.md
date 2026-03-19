# LITEBOX WINDOWS USERLAND ARM64 PORTING - DOCUMENTATION INDEX

## Overview

Three comprehensive documentation files have been created to guide the porting of the Windows Userland platform for LiteBox from x86-64 to ARM64.

**Total Documentation**: 39.2 KB of detailed analysis, code listings, and implementation guidance

---

## Document Breakdown

### 1. ARM64_PORTING_GUIDE.md (15.8 KB) - PRIMARY REFERENCE

**Purpose**: Complete code analysis with line-by-line breakdown

**Contents**:
- Section 1: Imports, cfg gates, constants, TLS (Lines 1-97)
- Section 2: Exception handling setup, vectored handler (Lines 99-165)
- Section 3: save_guest_context, WindowsUserland struct (Lines 167-321)
- Section 4: run_thread_arch NAKED ASSEMBLY (Lines 425-587) - FULL LISTING
- Section 5: Guest context switching, switch_to_guest, NtContinue (Lines 599-704)
- Section 6: Interrupt handling, context switching (Lines 700-933)
- Section 7: Memory management, VirtualAlloc/VirtualProtect (Lines 1350-1580)
- Section 8: Handler functions (Lines 1681-1759)
- Section A: PtRegs structures for x86-64 and ARM64 (Lines 3284-3367)
- Section B: rdfsbase/wrfsbase functions (Lines 1125-1162)

**Best Used For**:
- Understanding current implementation
- Learning what each section does
- Reference for exact code locations
- Comparing x86-64 vs ARM64 register layouts

**Key Highlights**:
- Complete x86-64 assembly listing (sysret path, exception callbacks)
- Exact register mappings (r15 → where?, rdx → where?)
- PtRegs structure definitions (x86-64: 21 fields, ARM64: 34 values)
- Exception handling flow with line numbers

---

### 2. ARM64_MIGRATION_DETAILED.md (14.5 KB) - IMPLEMENTATION GUIDE

**Purpose**: Step-by-step implementation guide with code examples

**Contents**:
- Part 1: Assembly Implementation Roadmap
  - 1.1: run_thread_arch → ARM64 with full prologue code
  - 1.2: TLS access pattern translation
  - 1.3: Context saving and stack building
  - 1.4: Guest context switch implementation
- Part 2: Windows API Context Handling
  - 2.1: Windows CONTEXT structure for ARM64
  - 2.2: Updated save_guest_context for ARM64
  - 2.3: Exception mapping for ARM64
- Part 3: TLS and FS-Base Replacement
  - 3.1: X86-64 rdfsbase/wrfsbase
  - 3.2: ARM64 equivalents using TPIDR_EL0
  - 3.3: FS base usage in Windows platform
- Part 4: Memory Management (architecture independent)
- Part 5: PtRegs structure layout differences
- Part 6: Step-by-step migration checklist (ACTIONABLE!)
- Part 7: Compiler intrinsics reference
- Part 8: Register clobber lists
- Testing strategy with unit/integration/functional phases

**Best Used For**:
- Actual implementation (follow the checklist!)
- Code examples for each modification
- Understanding Windows ARM64 API details
- Planning testing approach

**Key Highlights**:
- Phase-by-phase migration checklist
- Code snippets ready to adapt
- Compiler intrinsic references
- Concrete testing strategy
- Windows ARM64 CONTEXT structure mapping

---

### 3. ARM64_QUICK_REFERENCE.md (8.9 KB) - LOOKUP GUIDE

**Purpose**: Quick reference tables and translations

**Contents**:
- Document summary
- Critical files to modify (tabular format)
- Key assembly translations (X86-64 ↔ ARM64)
- Register mapping table (7 registers)
- Windows API context structure mapping
- Exception code mapping table
- Offset calculations for TlsState
- PtRegs memory layout on stack (diagram format)
- Quick start checklist (7 items)
- Register mapping details
- Effort estimation table (24-30 hours total)

**Best Used For**:
- Quick lookup while coding
- Understanding register mappings at a glance
- Finding which line needs changing
- Effort estimation for planning
- Exception code translations

**Key Highlights**:
- ASCII diagrams of stack layouts
- One-page quick start checklist
- Effort breakdown (28-31 hours estimated)
- Risk assessment for each component
- Register name translations

---

## Which Document to Use When?

| Scenario | Use Document | Why |
|----------|---|---|
| First time learning the codebase | ARM64_PORTING_GUIDE.md | Full context with line numbers |
| Starting implementation | ARM64_MIGRATION_DETAILED.md | Step-by-step with examples |
| Looking up a specific detail | ARM64_QUICK_REFERENCE.md | Fast lookup, tables, mappings |
| Writing assembly for prologue | ARM64_MIGRATION_DETAILED.md Part 1.1 | Full code ready to adapt |
| Mapping Windows CONTEXT | ARM64_PORTING_GUIDE.md Sec 2 | Exact structure details |
| Testing strategy | ARM64_MIGRATION_DETAILED.md Part 7 | Complete testing approach |
| Estimating effort | ARM64_QUICK_REFERENCE.md | Effort table with complexity |
| Finding code locations | ARM64_PORTING_GUIDE.md | All line numbers included |
| TLS function implementation | ARM64_MIGRATION_DETAILED.md Part 3 | MSR/MRS assembly examples |

---

## Critical Code Sections (Priority Order)

**HIGH PRIORITY** (Complex, assembly-heavy):
1. run_thread_arch (Lines 425-587) - ~162 lines of naked assembly
2. switch_to_guest (Lines 599-704) - ~105 lines of naked assembly
3. TLS access pattern (Line 496-497) - GS segment → TPIDR_EL0

**MEDIUM PRIORITY** (Moderate complexity):
4. save_guest_context (Lines 167-213) - Register mapping
5. Exception handling (Lines 1689-1710) - Add ARM64 exception codes
6. Context switching (Lines 807-933) - Update register field access

**LOW PRIORITY** (Simple, mostly mechanical):
7. cfg gate (Line 8) - Change x86_64 → aarch64
8. Memory mgmt (Lines 1366-1367) - Update address constants
9. Handler functions (Lines 1681-1759) - Should work as-is
10. TASK_ADDR_MIN/MAX - Update for ARM64 address space

---

## Key Findings Summary

### ✓ GOOD NEWS
- PtRegs ARM64 structure already defined in litebox_common_linux
- Memory management APIs are architecture-independent
- Handler function signatures work with C-unwind ABI
- Exception handling framework is extensible
- Most code is architecture-agnostic

### ✗ CHALLENGING AREAS
- run_thread_arch: Requires complete assembly rewrite (~400 lines)
- switch_to_guest: Requires assembly rewrite (~100 lines)
- TLS access: Must transition from GS segment to TPIDR_EL0
- Stack building: Different register count requires different layout
- Windows ARM64 API: Some details may need verification

### ⚠ UNKNOWNS (Research Needed)
- Exact Windows ARM64 exception codes
- TPIDR_EL0 behavior in Windows user mode
- NtContinue implementation on ARM64
- SEH unwinding requirements on ARM64

---

## Architecture Comparison Matrix

| Feature | X86-64 | ARM64 | Impact |
|---------|--------|-------|--------|
| Non-volatile GPRs | 7 (rbx, r12-r15) | 10 (x19-x28) | Prologue changes |
| Non-volatile FP | 10 (xmm6-xmm15) | 8 (v8-v15) | Different register save |
| TLS access | GS segment | TPIDR_EL0 | Assembly changes |
| System call | sysret | eret/branch | Fast path changes |
| Exception entry | interrupt gate | exception vector | Handler updates |
| Call ABI | rdi, rsi, rdx, rcx, r8, r9 | x0-x5 | Handler signatures OK |
| Stack align | 16-byte | 16-byte | Same requirement |
| Return value | rax | x0 | Works with ABI |
| Address space | 48-bit | 48-bit | Similar limits |
| Page size | 4KB (typical) | 4KB (typical) | VirtualAlloc works |

---

## Effort Estimation

**Total Estimated Effort: 24-31 hours**

Breakdown:
- Configuration & easy changes: 4.5 hours
- Assembly rewrites: 13 hours (HIGH RISK)
- Testing & debugging: 8-10 hours (VERY HIGH RISK)

**Timeline Estimate**: 4-6 weeks for experienced developer
- Week 1-2: Assembly implementation
- Week 3: Testing & debugging
- Week 4-6: Integration & validation

---

## Implementation Roadmap

`
Phase 1: Setup (2-3 hours)
  ├─ Update cfg gate
  ├─ Add ARM64 TLS functions
  └─ Update address constants

Phase 2: Core Assembly (13+ hours)
  ├─ run_thread_arch prologue/epilogue
  ├─ syscall_callback stack building
  ├─ switch_to_guest_sysret branch sequence
  └─ Test each component independently

Phase 3: Context Handling (2-3 hours)
  ├─ save_guest_context mapping
  ├─ Exception code handling
  └─ set_context_to_interrupt updates

Phase 4: Testing (8-10 hours)
  ├─ Unit tests for assembly
  ├─ Integration tests
  └─ Full system tests with payloads

Phase 5: Documentation & Polish (1-2 hours)
  ├─ Update comments for ARM64
  ├─ Add architecture guards
  └─ Final validation
`

---

## Key Technical Details

### PtRegs Stack Layout
- **X86-64**: 21 × 8 = 168 bytes
- **ARM64**: 34 × 8 = 272 bytes
- Need to update: stack building, register popping, offset calculations

### TLS Access
- **X86-64**: mov r11, gs:[r11 * 8 + 5248]
- **ARM64**: mrs x11, tpidr_el0; ldr x11, [x11, x12, lsl #3]

### Register Restoration
- **X86-64**: 15 pops + alignment
- **ARM64**: 31 loads (x0-x30) + sp + pc + pstate

---

## Using This Documentation

1. **Initial Learning**: Read ARM64_PORTING_GUIDE.md (all sections)
2. **Planning**: Review ARM64_QUICK_REFERENCE.md effort table
3. **Implementation**: Follow ARM64_MIGRATION_DETAILED.md checklist
4. **During Coding**: Use all three for different aspects
5. **Testing**: Reference testing strategy in ARM64_MIGRATION_DETAILED.md

---

## File Locations

All documentation files are in: C:\Users\sanghle\work\litebox\

- ARM64_PORTING_GUIDE.md (15,794 bytes)
- ARM64_MIGRATION_DETAILED.md (14,517 bytes)
- ARM64_QUICK_REFERENCE.md (8,934 bytes)
- ARM64_PORTING_DOCUMENTATION_INDEX.md (this file)

---

## Questions & Clarifications

### Q: Do I need to modify litebox_common_linux?
A: Minimally - only add ARM64 variants for rdfsbase/wrfsbase functions. The PtRegs structure is already defined!

### Q: What's the hardest part?
A: Writing the run_thread_arch naked assembly (400 lines) - this requires deep understanding of ARM64 ABI and Windows calling conventions.

### Q: Can I start with memory management?
A: Not recommended. Start with cfg changes, then TLS functions, then assembly. Memory management works as-is.

### Q: How do I test this?
A: Follow the 3-phase testing strategy in ARM64_MIGRATION_DETAILED.md Part 7.

### Q: What if Windows ARM64 doesn't use TPIDR_EL0?
A: Need to verify with Windows documentation. If not, use platform-specific TLS mechanism instead.

---

## Next Actions

1. ✓ Documentation review (this file + the three guides)
2. → Environment setup (Windows on ARM64 dev machine)
3. → Windows ARM64 API research (exception codes, CONTEXT structure)
4. → Implementation phase (follow ARM64_MIGRATION_DETAILED.md)
5. → Testing phase (comprehensive validation)

---

Created: 2024
Source Analysis: Windows Userland Platform for LiteBox
Target: ARM64 (Windows on Snapdragon X Elite/Plus)
