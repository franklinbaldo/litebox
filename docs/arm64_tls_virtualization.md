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
- **SVC handler** (18 insns): Reads hardware `TPIDR_EL0` as the TLS table
  lookup key, scans for a matching entry, stores `host_tls` for
  `syscall_callback`.
- **MSR handler** (19 insns): Updates the TLS table entry with the new
  guest TPIDR value and writes hardware `MSR TPIDR_EL0`.
- **X18**: Not virtualized — Linux treats X18 as a free GPR on both host
  and guest.

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
- **Sentinel**: `0xFFFFFFFFFFFFFFFF` marks end of valid entries
- **Tombstone**: `0` marks a freed slot (reclaimable by CAS)
- **Capacity**: 256 entries (one page)

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

All NULL-check fallback paths (CBZ → read `entry[0]`) assume single-threaded
execution. This is correct during early ELF loading (rtld_audit runs before
threads are created), but would break if `ld-linux` ever spawns threads
during initialization.

### 4. TLS table key/value write is not atomic

`update_host_tls_entry()` uses CAS on the key slot, then a separate volatile
write on the value slot. A concurrent reader could observe a valid key with
a stale or zero value pointer. The TEB-based path (Windows) is immune because
it doesn't scan the TLS table, but the scan-based paths (Linux, macOS) could
theoretically hit this window.

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
