================================================================================
                    WINDOWS ARM64 TLS EXPLORATION - COMPLETE
================================================================================

You now have FOUR comprehensive reference documents covering macOS and Linux 
ARM64 thread control block and TLS table registration patterns.

DOCUMENTS CREATED:
================================================================================

1. TLS_REGISTRATION_COMPLETE_REFERENCE.txt (13,957 bytes)
   └─ Complete code implementations with full function bodies
   └─ All 7 key areas covered:
      • TLS table initialization (Linux loader)
      • ThreadControlBlock structure (macOS)
      • TLS table registration with CAS logic (macOS)
      • switch_to_guest assembly (macOS)
      • TLS access patterns (Linux)
      • Thread cleanup (macOS)
      • Assembly entry point structure

2. TLS_TABLE_VISUAL_REFERENCE.txt (9,301 bytes)
   └─ Visual memory layout diagrams
   └─ Memory maps showing offset calculations
   └─ Example TLS table with 3 threads
   └─ Assembly pseudocode for switch_to_guest
   └─ Synchronization flow diagrams

3. WINDOWS_ARM64_IMPLEMENTATION_TEMPLATE.txt (15,247 bytes)
   └─ Ready-to-implement code templates
   └─ Copy-paste compatible Rust functions
   └─ Direct assembly template for switch_to_guest
   └─ Call sites showing integration points
   └─ Validation checklist

4. EXACT_CODE_LOCATIONS.txt (17,954 bytes)
   └─ File paths and line numbers for ALL code
   └─ Cross-references between implementations
   └─ Line-by-line breakdown of key functions
   └─ Summary of critical offsets

================================================================================
KEY FINDINGS FOR WINDOWS ARM64
================================================================================

THREAD CONTROL BLOCK OFFSETS (EXACT):
  TCB.guest_tpidr    @ byte offset 24  ← Load to TPIDR_EL0 before guest entry
  TCB.guest_x18      @ byte offset 40  ← Guest x18 (fully virtualized)
  TCB.host_sp        @ byte offset 8   ← Restore when returning to host
  TCB.in_guest       @ byte offset 32  ← Flag: 1 = executing guest
  TCB.interrupt      @ byte offset 33  ← Flag: 1 = interrupt pending

TLS TABLE FORMAT:
  Entry size: 16 bytes per thread
  Supports: 256 concurrent threads maximum
  Stored: [TPIDRRO_EL0 (u64) @ +0] [TCB pointer (u64) @ +8]
  Sentinel: 0xFFFFFFFFFFFFFFFF (marks end of valid entries)
  Tombstone: 0 (marks freed slots for reclamation)

REGISTRATION ALGORITHM:
  1. Read TPIDRRO_EL0 as lookup key (stable per-thread)
  2. Linear scan table from index 0 to 255
  3. If key matches: update TCB value and return
  4. If sentinel found: claim slot via atomic CAS
  5. If tombstone (0) found: remember as candidate, keep scanning
  6. On CAS failure: retry entire scan (another thread claimed slot)

CRITICAL FUNCTION CALLS:
  Before every switch_to_guest() → call update_host_tls_entry()
  On thread exit before TCB freed → call remove_host_tls_entries()

ASSEMBLY OPERATIONS:
  ldr x16, [x1, #24]      // Load TCB.guest_tpidr (offset 24)
  msr tpidr_el0, x16      // ★ Write to TPIDR_EL0
  ldr x17, [x1, #40]      // Load TCB.guest_x18 (offset 40)

================================================================================
DIFFERENCES: macOS vs Linux vs Windows
================================================================================

ASPECT                  macOS           Linux           Windows (SAME AS)
------                  -----           -----           ----------------
TPIDR_EL0 preservation  NO (clobbers)   YES (kernel)    NO (clobbers)
TCB pointer passing     Explicit (x1)   TPIDR_EL0       Explicit (x1)
TLS table key           TPIDRRO_EL0     guest_tpidr     TPIDRRO_EL0 → macOS
guest_tpidr location    TCB memory      thread-local     TCB memory → macOS
Thread safety (CAS)     YES             NO (kernel)     YES (like macOS)
Tombstone support       YES             NO              YES (like macOS)
TLS table entries       256             256             256
Entry size              16 bytes        16 bytes        16 bytes
Sentinel value          0xFFFF...FFFF   0xFFFF...FFFF   0xFFFF...FFFF

IMPLEMENTATION RECOMMENDATION FOR WINDOWS:
  Follow the macOS pattern exactly because:
  1. Both systems clobber TPIDR_EL0 on context switches
  2. Both require explicit TCB argument to switch_to_guest
  3. Both need CAS logic for thread-safe slot claiming
  4. Both support tombstone-based slot reclamation
  5. TPIDRRO_EL0 is stable and suitable as key on both

================================================================================
INTEGRATION CHECKLIST
================================================================================

BEFORE STARTING IMPLEMENTATION:

[ ] Copy ThreadControlBlock struct definition (lines 582-593 from macOS)
[ ] Verify offset calculations:
    - guest_tpidr must be at byte offset 24
    - guest_x18 must be at byte offset 40
[ ] Set up HOST_TLS_TABLE_ADDR atomic in common code
[ ] Allocate TLS table with 256 entries, 16 bytes each
[ ] Initialize all entries with sentinel 0xFFFFFFFFFFFFFFFF

DURING IMPLEMENTATION:

[ ] Implement update_host_tls_entry() following macOS pattern (lines 2377-2446)
[ ] Implement remove_host_tls_entries() following macOS pattern (lines 2461-2507)
[ ] Implement switch_to_guest assembly (reference lines 1114-1221)
[ ] Ensure TPIDRRO_EL0 read works (see litebox_common_linux::read_tpidrro_el0)
[ ] Add update_host_tls_entry() call before every switch_to_guest

AFTER IMPLEMENTATION:

[ ] Test concurrent thread creation (verify TLS table doesn't overflow)
[ ] Test thread cleanup (verify tombstones are created)
[ ] Test thread reuse (verify tombstone slots are reclaimed)
[ ] Verify guest_tpidr is correctly set before guest entry
[ ] Verify guest_x18 is correctly set before guest entry
[ ] Verify assembly addresses are correct (offsets 24, 40, 32, 33)

================================================================================
FILES TO REFERENCE WHILE CODING
================================================================================

Primary References:
  - litebox_platform_macos_userland/src/lib.rs
    • Lines 582-593: ThreadControlBlock struct
    • Lines 2374-2375: TLS constants
    • Lines 2377-2446: update_host_tls_entry() (primary reference)
    • Lines 2461-2507: remove_host_tls_entries()
    • Lines 1114-1221: switch_to_guest assembly

  - litebox_common_linux/src/loader.rs
    • Lines 526-595: TLS table initialization
    • Lines 530-533: Size/entry constants
    • Lines 573-577: Sentinel initialization
    • Lines 579: HOST_TLS_TABLE_ADDR storage

  - litebox_platform_linux_userland/src/lib.rs
    • Lines 2125-2168: update_host_tls_entry (Linux variant)
    • Lines 485-498: set_guest_tpidr (thread-local access)
    • Lines 501-516: get_guest_tpidr (thread-local access)

Secondary References:
  - Assembly instruction references
  - Atomic operations in Rust
  - TPREL relocation patterns (Linux)

================================================================================
QUICK START: COPY-PASTE IMPLEMENTATIONS
================================================================================

All implementations are ready in WINDOWS_ARM64_IMPLEMENTATION_TEMPLATE.txt:

Section 1: TCB Structure → copy-paste into your lib.rs
Section 2: TLS Table Constants → copy-paste into your lib.rs
Section 3: update_host_tls_entry() → copy-paste with modifications
Section 4: remove_host_tls_entries() → copy-paste with modifications
Section 5: switch_to_guest assembly → adapt to your calling conventions
Section 6: Call sites → shows where to invoke update_host_tls_entry()
Section 7: Thread initialization → shows TCB_PTR setup pattern

================================================================================

NEXT STEPS:

1. Review TLS_TABLE_VISUAL_REFERENCE.txt to understand memory layout
2. Study EXACT_CODE_LOCATIONS.txt to see how all pieces fit together
3. Use WINDOWS_ARM64_IMPLEMENTATION_TEMPLATE.txt as your coding guide
4. Reference TLS_REGISTRATION_COMPLETE_REFERENCE.txt for detailed explanations
5. Implement in this order:
   a) ThreadControlBlock struct
   b) TLS table allocation (like Linux loader)
   c) update_host_tls_entry() function
   d) remove_host_tls_entries() function
   e) switch_to_guest assembly
   f) Integration: call update_host_tls_entry() before switch

The macOS implementation in litebox_platform_macos_userland is your gold standard.
It handles all the thread safety and edge cases you need.

================================================================================
