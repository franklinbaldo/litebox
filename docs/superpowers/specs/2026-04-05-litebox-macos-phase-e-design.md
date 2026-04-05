# Phase E: High-Frequency Mach Traps

## Overview

Add 3 Mach traps that are commonly invoked by dynamically-linked macOS binaries:
`mach_absolute_time`, `mach_timebase_info_trap`, and
`_kernelrpc_mach_port_deallocate_trap`.

## Traps

| Trap | Number (positive) | XNU x16 value | Behavior |
|------|-------------------|---------------|----------|
| `mach_absolute_time` | 3 | -3 | Return nanoseconds since boot in x0 |
| `mach_timebase_info_trap` | 6 | -6 | Write `{numer:1, denom:1}` to address in x0; return KERN_SUCCESS |
| `_kernelrpc_mach_port_deallocate_trap` | 18 | -18 | No-op stub; return KERN_SUCCESS |

## Design Details

### mach_absolute_time (trap 3)

On Apple Silicon the Mach timebase is 1:1 (numer=denom=1), so
`mach_absolute_time()` returns nanoseconds since boot.

Implementation:
- Access `self.global.platform.now()` and `self.global.boot_time`
- Compute `duration_since(boot_time).as_nanos() as u64`
- Return the value — the dispatch caller writes it to x0

The `boot_time` field in `GlobalState` already exists (captured at shim init)
but is marked `dead_code`. Remove that annotation.

### mach_timebase_info_trap (trap 6)

Signature: `kern_return_t mach_timebase_info_trap(mach_timebase_info_t info)`

- x0 = pointer to `struct mach_timebase_info { uint32_t numer; uint32_t denom; }`
- Write numer=1 at offset 0, denom=1 at offset 4
- Return KERN_SUCCESS (0)

On Apple Silicon this is always 1:1. If we ever target Intel Macs, these
values would differ.

### _kernelrpc_mach_port_deallocate_trap (trap 18)

Signature: `kern_return_t _kernelrpc_mach_port_deallocate_trap(target, name)`

- x0 = target task port, x1 = port name to deallocate
- No-op stub returning KERN_SUCCESS (0)
- Log parameters via `log_unsupported!`
- Consistent with existing port approach (no port table, no reference counting)

## Files Modified

1. **`litebox_common_macos/src/syscall.rs`** — add 3 constants to `mod mach_trap`:
   - `MACH_ABSOLUTE_TIME_TRAP: usize = 3`
   - `MACH_TIMEBASE_INFO_TRAP: usize = 6`
   - `KERNELRPC_MACH_PORT_DEALLOCATE_TRAP: usize = 18`

2. **`litebox_shim_macos/src/syscalls/stubs.rs`** — add 3 match arms in
   `do_mach_trap()`. The `mach_absolute_time` handler needs access to
   `self.global` (already available on `Task`).

3. **`litebox_shim_macos/src/lib.rs`** — remove `#[expect(dead_code)]` from
   `boot_time` field.

## Tests

3 C test files compiled with `compile_macho_dynamic`, run with
`run_macho_dynamic`, exit-code verification only:

- **`tests/mach_absolute_time.c`** — call `mach_absolute_time()` twice, verify
  both values are nonzero and the second >= the first (monotonic).
- **`tests/mach_timebase_info.c`** — call `mach_timebase_info()`, verify
  numer==1 and denom==1.
- **`tests/mach_port_deallocate.c`** — call
  `mach_port_deallocate(mach_task_self(), mach_task_self())`, verify return
  is KERN_SUCCESS (0).

3 corresponding test functions appended to `tests/loader.rs`.

## Task Breakdown

1. Add 3 constants to `mod mach_trap`
2. Implement 3 handlers in `stubs.rs` + remove `dead_code` on `boot_time`
3. Add 3 tests (C files + Rust test functions)
