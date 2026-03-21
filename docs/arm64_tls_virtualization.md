# ARM64 TLS Virtualization Across Platforms

This document describes how litebox virtualizes thread-local storage (TLS)
registers on ARM64 across Linux, macOS, and Windows hosts. Each platform
has different kernel behavior around `TPIDR_EL0` and `X18`, requiring
platform-specific strategies.

## Register Behavior by Platform

| Register | Linux | macOS | Windows |
|---|---|---|---|
| `TPIDR_EL0` | Preserved across context switches | **Clobbered** by XNU on signals/preemption | **Not preserved** across context switches |
| `TPIDRRO_EL0` | Unused (always 0) | **Stable** per-pthread (set by XNU) | Unused |
| `X18` | General-purpose register | **Zeroed** by XNU on exception entry | **Reserved** as TEB pointer (always valid) |

## Virtualization Strategy

### Linux ARM64

**Anchor register**: `TPIDR_EL0` (kernel preserves it)

No register virtualization is needed. Host and guest share the same hardware
`TPIDR_EL0`. The rewriter intercepts `MRS/MSR TPIDR_EL0` and `SVC` instructions:

- **MRS gate** (5 insns): Reads `entry[0].guest_tpidr` from the TLS lookup
  table. Avoids reading hardware directly because the host may have a different
  TPIDR value between syscalls.
- **SVC handler** (21 insns): Reads hardware `TPIDR_EL0` as the TLS table
  lookup key, hashes into the table (see below), stores `host_tls` for
  `syscall_callback`. Falls back to `entry[0]` if no match (sentinel hit).
- **MSR handler** (22 insns): Hashes the old `TPIDR_EL0` to find the
  existing TLS table entry, updates it with the new guest TPIDR value in-place,
  and writes hardware `MSR TPIDR_EL0`. Falls back to writing `entry[0]` on
  sentinel (no match).
- **X18**: Not virtualized — Linux treats X18 as a free GPR on both host
  and guest.
- **Lookup cost**: **O(1) amortized** — hash-based open-addressing with
  bounded linear probing (up to 8 probes).

### macOS ARM64

**Anchor register**: `TPIDRRO_EL0` (XNU preserves it per-pthread)

Both `X18` and `TPIDR_EL0` must be fully virtualized because the kernel
clobbers them.

- **Storage**: `ThreadControlBlock` (TCB) struct, accessed via TPIDRRO_EL0-keyed
  TLS table scan.
  - `TCB.guest_tpidr` at offset 24
  - `TCB.guest_x18` at offset 40
- **MRS gate** (13 insns): `BL` to shared handler → TPIDRRO_EL0 scan →
  read `TCB.guest_tpidr` → store to frame `[SP+24]`.
- **SVC handler** (18 insns): TPIDRRO_EL0 scan → find TCB → save guest X18
  from frame to `TCB.guest_x18` → store `host_tls` at `[SP+40]`.
- **X18 gate** (14-16 insns per site): Every instruction referencing X18 is
  rewritten to use a scratch register. `BL` to shared load/save handlers
  that read/write `TCB.guest_x18` via TPIDRRO_EL0 scan.
- **Lookup cost**: O(n) linear scan of TLS table (up to 256 entries).

### Windows ARM64

**Anchor register**: `X18` / TEB pointer (Windows guarantees it is always valid)

Both `X18` and `TPIDR_EL0` must be fully virtualized. The approach mirrors
macOS but uses a fundamentally simpler lookup mechanism.

- **Storage**: `TlsState` struct, accessed via Windows TEB TLS slot.
  - `TlsState.virt_x18` at offset 40
  - `TlsState.guest_tpidr` at offset 64
- **Lookup path**: `LDR offset, [header+16]` → `LDR TlsState*, [X18, offset]`
  where the precomputed offset = `TEB_TLS_SLOTS_OFFSET (5248) + TLS_INDEX * 8`.
- **MRS gate** (11 insns): TEB → TlsState → `guest_tpidr`. Fallback to
  TLS table `entry[0]` if TlsState is NULL.
- **SVC handler** (20 insns): TEB → TlsState* → store at `[SP+24]` for
  `syscall_callback`. Fallback to `entry[0].host_tls`.
- **MSR handler** (19 insns): TEB → write `guest_tpidr` to TlsState,
  TLS table `entry[0]`, and hardware `MSR TPIDR_EL0`.
- **X18 gate**: Same per-site rewriting as macOS. Shared load/save handlers
  use TEB → TlsState instead of TPIDRRO_EL0 → TLS table scan.
- **Lookup cost**: **O(1)** — direct pointer dereference via TEB slot.
- **rtld_audit**: Runtime detection (`teb_tls_offset != 0`) to choose
  between TEB path (Windows) and TPIDR_EL0 path (Linux).

## Trampoline Header Layout

```
Offset 0:  Callback address (syscall entry point)
Offset 8:  TLS lookup table pointer
Offset 16: TEB TLS slot offset (Windows ARM64 only; sigreturn preamble on Linux)
Offset 24: Sigreturn SVC gate (Linux/macOS only)
```

## TLS Lookup Table

Shared by all trampolines (main binary + ld-linux). Allocated on first
trampoline load, reused by subsequent loads.

- **Entry size**: 16 bytes — `[key: u64, host_tls: u64]`
- **Key**: Platform-dependent (TPIDR_EL0 on Linux, TPIDRRO_EL0 on macOS,
  guest_tpidr on Windows)
- **Sentinel**: `0xFFFFFFFFFFFFFFFF` marks end of valid entries / empty slot
- **Tombstone**: `0` marks a freed slot (reclaimable by CAS or insertion)
- **Capacity**: 264 entries (256 usable + 8 overflow sentinels)

### Hash-Based Lookup (Linux ARM64)

On Linux ARM64, the SVC and MSR handlers use a hash-based open-addressing
scheme instead of linear scan:

- **Hash function**: `(guest_tpidr >> 4) & 0xFF` — computed in 3 instructions
  (LSR, AND, ADD with LSL #4). The right-shift by 4 discards low alignment
  bits; the 8-bit mask selects one of 256 buckets.
- **Probe strategy**: Open-addressing with linear probing. Starting at the
  hash bucket, the handler checks each entry sequentially: sentinel → fallback
  to `entry[0]`; match → use entry; otherwise advance. The loop is unbounded
  in the emitted assembly, but the 8 overflow sentinel entries at positions
  256–263 guarantee termination within 8 probes of any bucket.
- **Overflow sentinels**: The table allocates 264 entries (not 256). Positions
  256–263 are permanently initialized to sentinel (`0xFFFFFFFFFFFFFFFF`). This
  means a probe starting at bucket 255 will hit a sentinel by position 263 at
  the latest, eliminating the need for wrap-around or explicit probe counting
  in the assembly.
- **Tombstone semantics**: When a thread exits, its TLS entry key is set to
  `0` (tombstone). The Rust-side `update_host_tls_entry()` treats tombstones
  as reclaimable during insertion. The assembly handlers skip tombstones
  during probing (they only stop on sentinel or match).
- **Rust-side insertion** (`update_host_tls_entry()`): Uses the same hash
  function `(guest_tpidr >> 4) & 0xFF`. Probes up to `TLS_MAX_PROBES` (8)
  entries from the hash position. If the entry already exists, updates
  `host_tls` in-place. Otherwise inserts at the first free (tombstone or
  sentinel) slot. Also detects stale entries left by MSR handler in-place
  key updates (where `host_tls` matches but key doesn't) and tombstones them.
- **`entry[0]` fallback**: Both SVC and MSR handlers maintain `entry[0]`
  as a single-thread fallback for the rtld_audit bootstrap path (before
  threads are created and before `update_host_tls_entry()` runs).

### Linear Scan (macOS ARM64)

On macOS, the handlers still use O(n) linear scan of the TLS table (up to
256 entries), keyed by TPIDRRO_EL0.

### Scaling Beyond 256 Threads

The current 8-bit hash (`& 0xFF`) limits the table to 256 usable entries,
supporting up to 256 concurrent guest threads per process. If this becomes
insufficient, several approaches are available (in order of complexity):

**Option 1: Widen the hash mask (recommended first step).**
Change the mask from `& 0xFF` to `& 0x3FF` (10-bit, 1024 buckets) or
`& 0xFFF` (12-bit, 4096 buckets). The assembly stays 3 instructions — only
the `AND` immediate and table allocation change. A 1024-entry table is ~16KB;
a 4096-entry table is ~64KB. The compile-time assert
`TLS_TABLE_SIZE <= PAGE_SIZE * 2` will catch oversized tables. Both the
assembly mask (`encode_and_bitmask`) and the Rust mask in
`update_host_tls_entry()` must be updated together.

**Option 2: Two-level lookup.**
Use the hash to index a first-level table of pointers to per-bucket
sub-tables allocated on demand. Removes the hard cap entirely but adds one
extra `LDR` to the hot path and requires a bump allocator for sub-table
allocation in the trampoline's address space. Significantly more assembly
complexity.

**Option 3: Kernel-assisted TPIDR assignment.**
If litebox intercepts `clone`/`clone3`, it could assign TPIDR_EL0 values
with guaranteed-unique low bits, eliminating hash collisions entirely.
Does not work for threads created by the guest's own libc without
interception.

**Option 4: CPU-indexed table.**
Index by CPU ID instead of TPIDR. Table size is bounded by CPU count
(typically 64-256), not thread count. Requires re-validating entries on
thread migration (a thread moving between CPUs must update the table).
Reading CPU ID from userspace on ARM64 is non-trivial (MPIDR_EL1 is
privileged; `sched_getcpu()` is a vDSO call).

## Known Pitfalls and Weaknesses

### 1. `virt_x18` and `guest_tpidr` offsets are compile-time asserted

Both `guest_tpidr` at offset 64 and `virt_x18` at offset 40 are validated by
`const _: () = assert!(offset_of!(...) == N)` in the platform crate. Adding
a field that shifts either offset will produce a compile error.

### 2. TPIDR source of truth

On Windows, `TlsState.guest_tpidr` is the single authoritative copy. The MSR
handler writes it directly via TEB, and `call_shim` reads it back from
TlsState without scanning the TLS table. `THREAD_TPIDR` (Rust thread-local)
is kept in sync as a convenience for Rust code but is not authoritative.

On Linux/macOS, the TLS table entry key is the authoritative copy, and
`call_shim` must scan the table to discover MSR handler updates.

### 3. TLS table entry[0] fallback is single-thread only

All fallback paths (sentinel hit on Linux, CBZ on Windows/macOS → read
`entry[0]`) assume single-threaded execution. This is correct during early
ELF loading (rtld_audit runs before threads are created), but would break
if `ld-linux` ever spawns threads during initialization.

### 4. TLS table key/value write is not atomic

`update_host_tls_entry()` uses CAS on the key slot, then a separate volatile
write on the value slot. A concurrent reader could observe a valid key with
a stale or zero value pointer. The TEB-based path (Windows) is immune because
it doesn't scan the TLS table, but the table-based paths (Linux hash probe,
macOS linear scan) could theoretically hit this window.

### 5. Hardware TPIDR_EL0 is never written on Windows

No handler writes hardware `TPIDR_EL0` on Windows — not `switch_to_guest`,
not the MSR handler. All paths use TlsState via TEB. The TLS table
`entry[0].guest_tpidr` is still maintained for the rtld_audit fallback path.

### 6. TEB slot cleanup on TlsState drop

When `run_thread_inner` returns, the `TlsState` on the stack is dropped.
The cleanup guard calls `remove_host_tls_entries()` to tombstone the TLS
table entry **and** `TlsSetValue(index, NULL)` to clear the TEB slot.
Both are handled by defer guards in `run_thread_inner`.

### 7. Parallel cargo test failures

Running multiple test binaries in the same process (cargo test default) can
cause TLS table contention — multiple test threads share the same global
`HOST_TLS_TABLE_ADDR`. Using `cargo nextest` (process-per-test) avoids this.
Not a production issue since litebox runs one guest per process.

---

## Future: Cross-Platform Guest×Host Matrix

Currently litebox only runs **Linux guests**. Future work will add Windows
and macOS shims, enabling Windows PE and macOS Mach-O guests. Each guest
type has different expectations from the ARM64 TLS registers, and each host
platform has different kernel behavior. The TLS virtualization strategy must
handle all 9 combinations.

### Guest OS Register Expectations

| Register | Linux Guest | Windows Guest | macOS Guest |
|---|---|---|---|
| `TPIDR_EL0` | TLS pointer (glibc/musl) | Not used for guest TLS | pthread TLS pointer |
| `X18` | General-purpose register | TEB pointer (must be valid) | Reserved (ABI, `-ffixed-x18`) |
| `TPIDRRO_EL0` | Not used | Not used | pthread key (read-only, set by kernel) |

### Host OS Register Guarantees

| Register | Linux Host | macOS Host | Windows Host |
|---|---|---|---|
| `TPIDR_EL0` | ✅ Preserved | ❌ Clobbered | ❌ Not preserved |
| `X18` | ✅ Free GPR | ❌ Zeroed on exception | ✅ TEB (stable) |
| `TPIDRRO_EL0` | Always 0 | ✅ Stable per-pthread | Unused |
| **Stable anchor** | `TPIDR_EL0` | `TPIDRRO_EL0` | `X18` (TEB) |

### 3×3 Virtualization Matrix

#### TPIDR_EL0 Virtualization

| Guest↓ Host→ | Linux | macOS | Windows |
|---|---|---|---|
| **Linux** | Gate only¹ | Full virtualize | Full virtualize |
| **Windows** | None² | None² | None² |
| **macOS** | Gate only¹ | Full virtualize | Full virtualize |

¹ MRS/MSR gates needed to separate host and guest TPIDR values, but hardware
is reliable.

² Windows guests don't use TPIDR_EL0 for TLS. However, if the guest binary
contains MRS/MSR TPIDR_EL0 instructions (e.g., from linked Linux libraries
or CRT), they should still be gated.

#### X18 Virtualization

| Guest↓ Host→ | Linux | macOS | Windows |
|---|---|---|---|
| **Linux** | None | Full virtualize | Full virtualize |
| **Windows** | Provide fake TEB | Provide fake TEB | Native TEB ✅ |
| **macOS** | None³ | None³ | Virtualize⁴ |

³ macOS guest never references X18 (ABI reserves it, compiler uses
`-ffixed-x18`). No rewriting needed.

⁴ Windows reserves X18 for TEB, but macOS guest doesn't use it. However, the
rewriter must still avoid generating code that uses X18 (scratch registers
should be X16/X17 only).

#### TPIDRRO_EL0 Handling

| Guest↓ Host→ | Linux | macOS | Windows |
|---|---|---|---|
| **Linux** | N/A | N/A | N/A |
| **Windows** | N/A | N/A | N/A |
| **macOS** | Emulate⁵ | Native ✅ | Emulate⁵ |

⁵ macOS guests read TPIDRRO_EL0 for pthread_self(). On non-macOS hosts, the
shim must write a valid value via `MSR TPIDRRO_EL0` (requires EL1, so this
likely needs a different approach — e.g., rewriting MRS TPIDRRO_EL0 to read
from a memory location).

### Key Challenge: Windows Guest X18 (Fake TEB)

When running Windows PE guests on Linux or macOS hosts, the guest expects
`X18 = TEB` at all times. Two approaches:

**Option A: Set X18 = fake TEB, no rewriting**
- Allocate a TEB-like structure, set X18 to its address before entering guest
- Works on Linux (X18 preserved as GPR) — X18 stays valid naturally
- Fails on macOS (XNU zeros X18 on exception entry) — would need
  the rewriter to restore X18 after every signal/preemption, or use
  VEH-equivalent to catch and fix

**Option B: Full X18 virtualization (like Linux-on-macOS/Windows)**
- Rewrite all X18 accesses to read/write from a memory-backed fake TEB pointer
- More overhead but works on all hosts
- Requires teaching the rewriter about PE binary X18 access patterns

**Recommendation**: Option A for Linux host (simple), Option B for macOS host
(X18 is unreliable). Windows host is free (native TEB).

### Key Challenge: macOS Guest TPIDRRO_EL0

macOS guests call `pthread_self()` which reads TPIDRRO_EL0. This is a
**read-only** system register that can only be written from EL1 (kernel mode).
On non-macOS hosts:

- Cannot write TPIDRRO_EL0 from userspace
- Must rewrite `MRS Xd, TPIDRRO_EL0` instructions to read from a
  memory-backed emulated value (similar to TPIDR_EL0 virtualization)
- The rewriter already has the infrastructure for this (PatchKind for MRS)

### Abstraction: Rewriter Configuration

The current code uses `TargetOs` to select behavior. For the 3×3 matrix, the
rewriter needs to know:

```
struct RewriterConfig {
    /// Stable register for TLS table/state lookup
    anchor: Anchor,           // TPIDR_EL0 | TPIDRRO_EL0 | X18_TEB

    /// Whether to intercept guest X18 accesses
    virtualize_x18: bool,     // true when guest X18 semantics ≠ host X18

    /// Whether to intercept guest TPIDR_EL0 accesses
    virtualize_tpidr: bool,   // true when host clobbers TPIDR_EL0

    /// Whether to intercept guest TPIDRRO_EL0 accesses
    virtualize_tpidrro: bool, // true when guest reads it but host doesn't provide

    /// Guest X18 mode
    guest_x18: GuestX18,      // GPR | TEB | Reserved
}
```

This decouples the rewriter from the `TargetOs` enum and allows clean
expression of all 9 combinations. The current `TargetOs`-based dispatch
maps to specific `RewriterConfig` values:

```
Linux-on-Linux:   { anchor: TPIDR,    virt_x18: false, virt_tpidr: false, virt_tpidrro: false }
Linux-on-macOS:   { anchor: TPIDRRO,  virt_x18: true,  virt_tpidr: true,  virt_tpidrro: false }
Linux-on-Windows: { anchor: X18_TEB,  virt_x18: true,  virt_tpidr: true,  virt_tpidrro: false }
Win-on-Linux:     { anchor: TPIDR,    virt_x18: false, virt_tpidr: false, virt_tpidrro: false }
Win-on-macOS:     { anchor: TPIDRRO,  virt_x18: true,  virt_tpidr: false, virt_tpidrro: false }
Win-on-Windows:   { anchor: X18_TEB,  virt_x18: false, virt_tpidr: false, virt_tpidrro: false }
macOS-on-Linux:   { anchor: TPIDR,    virt_x18: false, virt_tpidr: false, virt_tpidrro: true  }
macOS-on-macOS:   { anchor: TPIDRRO,  virt_x18: false, virt_tpidr: false, virt_tpidrro: false }
macOS-on-Windows: { anchor: X18_TEB,  virt_x18: false, virt_tpidr: true,  virt_tpidrro: true  }
```

### Multi-Shim Scenario: Dynamic TLS Handling

A single litebox platform may host multiple guest types simultaneously
(e.g., a Linux guest launching a Windows subprocess, or a mixed workload
scheduler). This means the TLS virtualization strategy cannot be a
compile-time constant — it must be **per-thread** at runtime.

#### What works per-binary (no change needed)

The **rewriter** already runs per-binary. Each rewritten ELF/PE/Mach-O gets
its own trampoline with its own shared handlers, configured by
`RewriterConfig`. A Linux ELF gets X18-virtualized handlers; a Windows PE
on the same host gets non-virtualized X18 handlers. The trampoline is
self-contained — no conflict.

#### What needs to become dynamic

The **platform-side code** (`syscall_callback`, `switch_to_guest`,
`call_shim`) is compiled once per host platform. In a multi-shim scenario,
`syscall_callback` must handle both a Linux guest (whose X18 is virtualized,
whose TPIDR is in TlsState) and a Windows guest (whose X18 IS the TEB,
whose TPIDR is unused) on successive calls.

**Design: per-thread guest type tag in TlsState**

```rust
#[repr(u8)]
enum GuestType { Linux, Windows, MacOs }

struct TlsState {
    // ... existing fields ...
    guest_type: Cell<GuestType>,
}
```

The tag is set when the thread enters `run_thread` and is readable from
`syscall_callback` via the host_tls pointer. Each handler branches on it:

```
switch_to_guest:
  match tls.guest_type {
    Linux   → set virt_x18 in PtRegs, write TPIDR_EL0, skip restoring X18
    Windows → set X18 = TEB (real), skip TPIDR_EL0
    MacOs   → skip X18, write TPIDRRO emulation slot
  }
```

#### What about the SVC handler (in the trampoline)?

The SVC handler runs in rewriter-generated code, not in Rust. It's already
per-binary (each binary's trampoline has its own SVC handler). So a Linux
binary's SVC handler always does the Linux TLS dance, and a Windows binary's
SVC handler always does the Windows TLS dance. No dynamic dispatch needed
in the trampoline.

#### What about mixed-shim threads?

If a Linux guest's `clone()` creates a thread that `exec()`s a Windows PE:
- The thread starts with `guest_type = Linux`
- On `exec()`, the shim reloads the binary, switches to the Windows shim,
  and updates `tls.guest_type = Windows`
- The new binary's trampoline has Windows-configured handlers
- `switch_to_guest` now uses the Windows path for this thread

The key invariant: **`guest_type` and the trampoline handlers must agree**.
The shim is responsible for keeping them in sync across `exec()` boundaries.

#### Summary of what's static vs dynamic

| Component | Scope | Static or Dynamic |
|---|---|---|
| Rewriter config | Per-binary | Static (set at rewrite time) |
| Trampoline handlers | Per-binary | Static (emitted at rewrite time) |
| TlsState.guest_type | Per-thread | Dynamic (set at run_thread, updated on exec) |
| switch_to_guest path | Per-call | Dynamic (branches on guest_type) |
| syscall_callback | Per-call | Dynamic (reads guest_type from host_tls) |
