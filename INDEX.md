# Windows ARM64 TLS Implementation - Reference Document Index

## Quick Links by Task

### I need to understand the big picture
→ Start with: **README_WINDOWS_ARM64_SUMMARY.txt**
- Overview of all differences (macOS vs Linux vs Windows)
- Integration checklist
- Implementation roadmap
- Key findings summary

### I need to see memory layouts visually
→ Read: **TLS_TABLE_VISUAL_REFERENCE.txt**
- TLS table entry memory layout (16 bytes per entry)
- ThreadControlBlock memory map with offsets
- Register assignment diagrams
- Example TLS table with 3 threads
- Assembly pseudocode

### I need exact code to copy
→ Use: **WINDOWS_ARM64_IMPLEMENTATION_TEMPLATE.txt**
- Ready-to-implement Rust functions
- Copy-paste compatible code
- Assembly template for switch_to_guest
- Integration points marked
- Validation checklist

### I need to find code in the repository
→ Reference: **EXACT_CODE_LOCATIONS.txt**
- File paths and line numbers
- Section breakdowns
- Line-by-line explanations
- Summary table of all offsets
- Critical vs optional distinctions

### I need comprehensive explanations
→ Deep dive: **TLS_REGISTRATION_COMPLETE_REFERENCE.txt**
- Full function implementations with all details
- Comments explaining each step
- Assembly code with instructions
- Thread safety explanations
- Design patterns and rationale

---

## Key Findings (Summarized)

**ThreadControlBlock Offsets (FIXED):**
`
Offset  Size  Field           Purpose
------  ----  -----           -------
8       8B    host_sp         Host stack pointer
16      8B    guest_context_top  Points past PtRegs
24      8B    guest_tpidr     ★ Load to TPIDR_EL0 before guest
32      1B    in_guest        Boolean: 1 = executing guest
33      1B    interrupt       Boolean: 1 = interrupt pending
40      8B    guest_x18       ★ Guest x18 (virtualized)
`

**TLS Table Entry Format:**
`
Entry Size: 16 bytes
Index 0..255:
  Offset 0: u64 key (TPIDRRO_EL0)
  Offset 8: u64 value (TCB pointer)
`

**Registration Before Guest Entry:**
1. Call update_host_tls_entry()
2. Linear scan table [0..255] for matching key
3. Use atomic CAS to claim free slots
4. Support tombstone (0) for freed entries

**Critical Assembly:**
`sm
ldr x16, [x1, #24]    // Load TCB.guest_tpidr
msr tpidr_el0, x16    // Write TPIDR_EL0 ★ CRITICAL
`

---

## Implementation Checklist

### Phase 1: Prepare
- [ ] Review README_WINDOWS_ARM64_SUMMARY.txt
- [ ] Study TLS_TABLE_VISUAL_REFERENCE.txt
- [ ] Understand offset requirements (24 for guest_tpidr, 40 for guest_x18)

### Phase 2: Copy Structure & Constants
- [ ] Copy ThreadControlBlock struct (EXACT offsets must match)
- [ ] Define TLS_TABLE_ENTRIES = 256
- [ ] Define TLS_TABLE_SENTINEL = 0xFFFF_FFFF_FFFF_FFFF

### Phase 3: Implement Functions
- [ ] update_host_tls_entry() with linear scan
- [ ] Implement atomic CAS logic
- [ ] remove_host_tls_entries() with tombstone cleanup

### Phase 4: Assembly
- [ ] Implement switch_to_guest() 
- [ ] Load guest_tpidr from offset 24
- [ ] Write to TPIDR_EL0
- [ ] Restore guest_x18 from offset 40

### Phase 5: Integration
- [ ] Call update_host_tls_entry() before switch_to_guest
- [ ] Call remove_host_tls_entries() on thread exit

### Phase 6: Testing
- [ ] Concurrent thread creation
- [ ] TLS table doesn't overflow
- [ ] Tombstone slots are reclaimed
- [ ] guest_tpidr correctly set before guest entry

---

## Reference Architecture

`
TLS Registration Flow:
┌─────────────────────────────────────┐
│ Before entering guest code          │
└─────────────────────────────────────┘
            ↓
┌─────────────────────────────────────┐
│ Call update_host_tls_entry()        │
│ - Read TPIDRRO_EL0                  │
│ - Linear scan table [0..255]        │
│ - Find or claim slot via CAS        │
│ - Store TCB pointer                 │
└─────────────────────────────────────┘
            ↓
┌─────────────────────────────────────┐
│ Call switch_to_guest()              │
│ - Load guest_tpidr from TCB[24]    │
│ - Write TPIDR_EL0                   │
│ - Load guest_x18 from TCB[40]      │
│ - Branch to guest code              │
└─────────────────────────────────────┘
            ↓
┌─────────────────────────────────────┐
│ Guest executes...                   │
│ TPIDR_EL0 = guest_tpidr             │
└─────────────────────────────────────┘
`

---

## Cross-Reference to Source

### macOS Reference Implementation
- File: litebox_platform_macos_userland/src/lib.rs
- ThreadControlBlock: lines 582-593
- update_host_tls_entry(): lines 2377-2446
- remove_host_tls_entries(): lines 2461-2507
- switch_to_guest(): lines 1114-1221

### Linux Common Loader
- File: litebox_common_linux/src/loader.rs
- TLS table allocation: lines 526-595
- Sentinel initialization: lines 573-577

### Linux Userland Variant
- File: litebox_platform_linux_userland/src/lib.rs
- update_host_tls_entry(): lines 2125-2168 (Linux variant)
- set/get_guest_tpidr(): lines 485-516 (thread-local patterns)

---

## Important Distinctions

### Windows vs macOS
- SAME: Both clobber TPIDR_EL0 on context switches
- SAME: Both need explicit TCB argument
- SAME: Both use atomic CAS for slot claiming
- SAME: Both support tombstone reclamation
- FOLLOW: macOS implementation exactly

### Windows vs Linux
- DIFFERENT: Windows doesn't preserve TPIDR_EL0 (like macOS)
- DIFFERENT: Linux uses thread-local storage for guest_tpidr
- FOLLOW: macOS pattern, NOT Linux pattern

### Key: TPIDRRO_EL0 vs guest_tpidr
- TPIDRRO_EL0: Stable per-thread, system TLS register (macOS uses)
- guest_tpidr: Guest application TPIDR value (Linux uses)
- Windows should use: TPIDRRO_EL0 (like macOS, more stable)

---

## Validation Points

Before considering implementation complete:
- [ ] All 256 TLS entries initialize with sentinel 0xFFFF...FFFF
- [ ] update_host_tls_entry() uses linear scan (not binary search)
- [ ] Atomic CAS uses correct offsets (index * 16 for key pointer)
- [ ] Tombstone cleanup doesn't lose higher entries (sentinels stop scan)
- [ ] Assembly loads TCB offset 24 (not 0, 8, 16, etc.)
- [ ] Assembly loads TCB offset 40 for x18
- [ ] TPIDR_EL0 write happens BEFORE jump to guest
- [ ] Thread-local TCB pointer used in Rust code
- [ ] No reliance on TPIDR_EL0 to find TCB (read it in assembly only)

---

## Document Index

| Document | Purpose | Size | Best For |
|----------|---------|------|----------|
| README_WINDOWS_ARM64_SUMMARY.txt | Orientation | 9 KB | Getting started, understanding big picture |
| TLS_TABLE_VISUAL_REFERENCE.txt | Memory layouts | 9 KB | Understanding offsets and memory maps |
| WINDOWS_ARM64_IMPLEMENTATION_TEMPLATE.txt | Implementation | 10 KB | Copy-paste code and templates |
| EXACT_CODE_LOCATIONS.txt | Source references | 10 KB | Finding code in repository |
| TLS_REGISTRATION_COMPLETE_REFERENCE.txt | Full reference | 14 KB | Comprehensive explanations |

---

## Quick Command Reference

### Read ThreadControlBlock definition
File: litebox_platform_macos_userland/src/lib.rs, lines 582-593

### Find update_host_tls_entry
File: litebox_platform_macos_userland/src/lib.rs, lines 2377-2446

### Find switch_to_guest
File: litebox_platform_macos_userland/src/lib.rs, lines 1114-1221

### Find TLS table allocation
File: litebox_common_linux/src/loader.rs, lines 526-595

### Find TLS table constants
File: litebox_platform_macos_userland/src/lib.rs, lines 2374-2375
File: litebox_common_linux/src/loader.rs, lines 530-533

---

Generated: TLS Registration Exploration for Windows ARM64
Last Updated: 2025 (based on repository inspection)
