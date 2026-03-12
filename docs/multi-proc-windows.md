# Multi-Process Support for Windows Userland Platform

## Goal

Enable multi-process support (fork/exec/waitpid) on the Windows userland
platform (`litebox_platform_windows_userland`), mirroring the approach already
implemented on the Linux userland platform. All guest processes run in a single
host address space, using VA partitioning to give each process a non-overlapping
memory region.

## Current State

### Windows Userland Platform (`litebox_platform_windows_userland/src/lib.rs`)
- **Single file** platform (~2433 lines), x86_64 only (`#![cfg(all(target_os = "windows", target_arch = "x86_64"))]`)
- **VA range:** `TASK_ADDR_MIN = 0x1_0000`, `TASK_ADDR_MAX = 0x7FFF_FFFE_F000`
  (~128 TiB, same as Linux — fits 127 × 1 TiB partitions).
  Note: these are currently hardcoded magic numbers with a TODO to read from
  `GetSystemInfo()` at runtime.
- **Memory:** `VirtualAlloc2` for reserve/commit, `VirtualProtect` for permission
  changes, `VirtualFree` for decommit. Aligned to system allocation granularity.
- **Threads:** `std::thread::Builder::spawn()` with Windows TLS slot (`TlsAlloc`).
  Per-thread `TlsState` holds host/guest stack pointers and context.
- **Syscall interception:** Guest `syscall` instruction jumps to `syscall_callback`
  (asm trampoline). No ptrace/seccomp — direct instruction redirection.
- **Exceptions:** `AddVectoredExceptionHandler` catches access violations, illegal
  instructions. Maps Win32 exceptions to Linux signals.
- **FS base:** Per-thread `THREAD_FS_BASE` thread-local, restored via `wrfsbase`
  on guest entry. Windows periodically clears FS base; handler restores it.
- **AddressSpaceProvider:** Stub — `type AddressSpaceId = u32`, all methods
  default to `NotSupported`.
- **No multi-process support** — single process only.

### Linux Userland Reference Implementation
The Linux platform already has full multi-process support:
- VA partitioning: 127 × 1 TiB slots, `PartitionState` bitmap allocator
- `AddressSpaceProvider`: create/destroy/fork/activate/address_space_range
- Fork returns `SharedWithParent(child_id)` — vfork semantics
- CoW lazy page snapshot for writable pages during vfork
- Fork→vfork libc patch in syscall rewriter

### What the Shim Already Handles (Platform-Agnostic)
The Linux shim (`litebox_shim_linux`) already has all multi-process logic:
- `ProcessRegistry`, `ProcessState`, `ProcessId`
- `do_fork()` with `SharedWithParent` vs `Independent` branching
- CoW state management (`CowState`, `try_handle_cow_fault`)
- `VforkDone` synchronization
- Pipe FDs, process groups, waitpid
- Fork→vfork libc patch in syscall rewriter

**The shim is platform-agnostic.** It uses `AddressSpaceProvider` to get VA
ranges and `PageManagementProvider` for memory operations. The Windows platform
just needs to implement these traits.

**Guest programs are cross-compiled Linux ELF binaries** (the runner is named
`litebox_runner_linux_on_windows_userland`). The syscall rewriter operates on
Linux ELF binaries with glibc — the fork→vfork patch works identically to the
Linux platform.

## Analysis: What's Different on Windows

### Same as Linux
- VA range math: 127 × 1 TiB partitions (identical calculation)
- `AddressSpaceProvider` trait: same interface, same semantics
- `activate_address_space`: must return `Ok(())` (not the default `NotSupported`)
- `fork_address_space` → `SharedWithParent(child_id)` (vfork semantics)
- Shim fork/exec/waitpid logic: unchanged (already platform-agnostic)
- Syscall rewriter fork→vfork patch: identical (guest is Linux ELF with glibc)
- VirtualAlloc2 alignment: 1 TiB partition base addresses are automatically
  aligned to the system allocation granularity (64 KB), so no alignment issues.

### Different from Linux

1. **Memory allocation API:** `VirtualAlloc2` instead of `mmap`. The shim calls
   `PageManagementProvider::allocate_pages()` which already abstracts this.
   No changes needed in the shim.

2. **Permission model:** Windows lacks write-only and execute-only pages. The
   existing `prot_flags()` mapping (line 1271) already handles this. CoW
   `update_permissions` calls go through `VirtualProtect`, which is already
   implemented. Note: `VirtualProtect` may fail on `MEM_RESERVE` (not committed)
   pages — the CoW path only operates on committed pages, so this is fine.

3. **Exception error codes (CRITICAL):** The CoW fault handler checks
   `(error_code & 0x3) == 0x3` (present + write). The Windows exception handler
   (line 1708) synthesizes: `error_code = 4 | (write << 1)`. **Bit 0 (present)
   is never set.** Windows `EXCEPTION_ACCESS_VIOLATION` does not distinguish
   "page present but permission denied" from "page not present." As a result,
   write faults produce `error_code = 0b110`, and `0b110 & 0b011 = 0b010 ≠ 0b011`.
   **CoW faults will never be detected.** This requires a concrete fix (see
   Step 3).

4. **FS base handling:** Windows periodically clears FS base (line 140-143).
   The existing exception handler restores it. For child threads after fork,
   the parent's guest fsbase is read via `GetFsBase` punchthrough (which reads
   the thread-local `THREAD_FS_BASE` on the calling/parent thread) and passed
   to the child's `ThreadInitState`.

5. **`reserved_pages` and partition cleanliness:** `read_memory_maps()` scans
   the entire VA space at startup via `VirtualQuery`. The `PageManager` for
   each child process clamps `reserved_pages` to its partition range
   (`litebox/src/mm/linux.rs:337-344`). However, Windows ASLR can place DLLs,
   heap, and system allocations at arbitrary VA addresses — including high
   partitions (e.g., `ntdll.dll` is typically near `0x7FFx_xxxx_xxxx`,
   partition ~127). **Partitions are not guaranteed clean.** Needs runtime
   probing (see Step 4).

6. **`TASK_ADDR_MAX` is a hardcoded magic number.** The platform code has a
   TODO to read from `GetSystemInfo().lpMaximumApplicationAddress` at runtime.
   This can vary across Windows versions and configurations. Should be resolved
   as part of this work (see Step 1).

7. **Process exit does not release mappings.** The shim's exit path
   (`process.rs:548`) calls `destroy_address_space(id)` but does NOT call
   `PageManager::release_memory()` first. The `release_memory` call only
   happens in the `execve` path (`process.rs:2016-2018`). On Linux userland,
   this "works" because destroying a partition just frees a bitmap slot — the
   `mmap`'d pages remain but are unreachable. On Windows, `VirtualAlloc2`-
   committed pages in the freed partition would leak. This is a pre-existing
   bug on Linux too, but more impactful on Windows. Needs fix (see Step 5).

8. **No `MAP_GROWSDOWN`:** Windows doesn't support auto-growing stacks via
   mmap flags. The platform uses `VirtualAlloc2` with explicit guard pages
   instead. This is already handled — the shim passes `can_grow_down` through
   `PageManagementProvider` and the Windows impl ignores it (line 1432).

## Implementation Plan

### Step 0: Single-Process Smoke Gate

**Files:** `litebox_platform_windows_userland/src/lib.rs`

The `LinuxShimBuilder::build()` already calls `create_address_space()` and
`address_space_range()` unconditionally. With the current stub (returns
`NotSupported`), this will panic at runtime. Before any multi-process work,
implement the minimal `AddressSpaceProvider` methods needed for single-process
bring-up:

0.1. Implement `create_address_space()` and `address_space_range()` returning
     partition 0's range.
0.2. Implement `activate_address_space()` as `Ok(())` (no-op).
0.3. Verify the existing single-process tests still pass on Windows.

### Step 1: Add VA Partition Module (Shared)

**Files:** `litebox/src/platform/va_partitions.rs` (new shared module),
`litebox_platform_linux_userland/src/lib.rs`, `litebox_platform_windows_userland/src/lib.rs`

Extract `PartitionState` into a shared module in `litebox/src/platform/`:

1.1. **Windows has its own inline `mod va_partitions`** with `PartitionState`
   using `Vec<bool>` so `num_slots` can be computed at runtime from the
   platform's actual `VA_MAX`. The planned shared module at
   `litebox/src/platform/va_partitions.rs` was not created — both platforms
   have independent copies. This is acceptable for now.
   - `PARTITION_SIZE: usize = 1 << 40` (1 TiB, constant).
   - Methods: `allocate`, `allocate_probed`, `deallocate`, `is_allocated`,
     `range_of`.

1.2. **Resolve `TASK_ADDR_MAX` TODO on Windows.** Read
     `GetSystemInfo().lpMaximumApplicationAddress` at runtime and pass to
     `PartitionState::new()`.

1.3. **Linux was not migrated** to a shared `PartitionState`. Linux still uses
     `[bool; NUM_SLOTS]` with a compile-time constant. This can be revisited
     later.

1.4. **Add `partitions: std::sync::Mutex<PartitionState>`** field to
     `WindowsUserland`, initialized in `WindowsUserland::new()`.

### Step 2: Implement Full AddressSpaceProvider for WindowsUserland

**Files:** `litebox_platform_windows_userland/src/lib.rs`

Mirror the Linux implementation:

2.1. **`type AddressSpaceId = u32`** (slot index).

2.2. **`create_address_space()`** — `partitions.lock().allocate()` → slot index.
     Uses un-probed `allocate()` because it is only called once for the init
     process (slot 0), which is expected to contain host allocations.
     `fork_address_space()` uses `allocate_probed()` for all child address
     spaces. This is intentional and safe.

2.3. **`destroy_address_space(id)`** — `partitions.lock().deallocate(id)`.

2.4. **`fork_address_space(parent)`** — validate parent allocated, allocate child
     (with probing), return `SharedWithParent(child)`.
     Note: the Linux impl has a TOCTOU race (validates parent, drops lock,
     re-acquires in `create_address_space`). Fix: do both validation and child
     allocation under a single lock acquisition.

2.5. **`activate_address_space(id)`** — `Ok(())` (no-op, single host address space).

2.6. **`address_space_range(id)`** — `PartitionState::range_of(id)`.

### Step 3: Fix Exception Error Codes for CoW

**Files:** `litebox_platform_windows_userland/src/lib.rs` (exception handler)

This is **required** — without it, CoW faults are silently undetected.

3.1. **Fix error_code synthesis** in the vectored exception handler. When
     `EXCEPTION_ACCESS_VIOLATION` occurs, use `VirtualQuery` on the faulting
     address to determine if the page is committed (present):
     ```rust
     let is_present = {
         let mut mbi = MEMORY_BASIC_INFORMATION::default();
         VirtualQuery(fault_addr as _, &mut mbi, size_of_val(&mbi)) != 0
             && mbi.State == MEM_COMMIT
     };
     let error_code = (if is_present { 1 } else { 0 })   // bit 0: present
         | match read_write_flag {
             0 => 0,                                       // read
             8 => 1 << 4,                                  // DEP (exec fault)
             _ => 1 << 1,                                  // write
         }
         | 4;                                              // bit 2: user-mode
     ```

3.2. **Unit test:** Commit a read-only page, trigger a write fault, verify
     `error_code` has bits 0 and 1 set (`0b111`).

3.3. **VirtualProtect round-trip test:** Verify the CoW permission cycle:
     - `PAGE_READWRITE` → `PAGE_READONLY` → `PAGE_READWRITE` succeeds.
     - `PAGE_EXECUTE_READWRITE` → `PAGE_EXECUTE_READ` → `PAGE_EXECUTE_READWRITE`
       succeeds (EXEC preservation).

### Step 4: Handle `reserved_pages` with Partitioning

**Files:** `litebox_platform_windows_userland/src/lib.rs`

4.1. **`reserved_pages` remains global** (platform-level, scanned once at boot).
     The `PageManager` for each child process clamps these to its partition range
     automatically (`Vmem::new()` at `litebox/src/mm/linux.rs:337-344`).

4.2. **Runtime probing at partition allocation** (Step 2.2). Before allocating
     a slot, `VirtualQuery`-scan the slot's entire 1 TiB range. Skip slots
     with any `MEM_COMMIT` or `MEM_RESERVE` regions. This is the runtime safety
     net for ASLR-placed DLLs, lazy-loaded libraries, and system allocations.

4.3. **Document known limitation:** `reserved_pages` is a snapshot at boot time.
     Post-boot host allocations (lazy `LoadLibrary`, thread stacks) are not
     reflected. The partition-time probing (4.2) catches these, but only at
     partition creation time, not at every page allocation.

### Note: `EAGER_COW_FOR_VFORK`

The `AddressSpaceProvider` trait has an `EAGER_COW_FOR_VFORK` associated const
(defaults to `false`). Windows overrides it to `true`, causing all writable
pages to be eagerly copied on vfork rather than relying on lazy CoW faults.
The shim branches on this const instead of using `#[cfg(target_os = "windows")]`,
keeping the platform abstraction clean.

### Step 5: Fix Process-Exit Teardown

**Files:** `litebox_shim_linux/src/syscalls/process.rs`

This is a pre-existing bug (affects Linux too, but worse on Windows where
committed pages leak).

5.1. **Add `release_memory` before `destroy_address_space` on process exit.**
     In `prepare_for_exit()`, before the `destroy_address_space` call at
     line 548, release all process mappings:
     ```rust
     let release = |_, _| true;
     unsafe { self.process_state.borrow().pm.release_memory(release) }
         .expect("failed to release memory on exit");
     ```
     The simpler `|_, _| true` filter releases all mappings unconditionally.
     Both this and `|_r, vm| !vm.is_empty()` are correct at exit time; the
     simpler filter was chosen. This mirrors the `execve` path (line 2016-2018).

5.2. **Verify on Linux.** Run the full test suite on Linux to ensure the
     additional `release_memory` doesn't break existing behavior.

### Step 6: Integration Testing

**Files:** `litebox_runner_linux_on_windows_userland/` (tests)

6.1. **Self-contained multiprocess tests first.** Start with small binaries
     that don't depend on bash:
     - `test_fork_exec_wait`: fork, child execs a simple program, parent waits.
     - `test_pipe_cross_process`: parent creates pipe, fork, child writes, parent
       reads.
     - `test_cow_write_after_fork`: fork, child writes to a global variable
       (triggers CoW), parent verifies its copy is unchanged.

6.2. **Bash tests (extended coverage).** Port `test_bash_echo` and
     `test_bash_pipe_cat` from the Linux runner. These require bash + coreutils
     staged as rewritten ELF binaries.

6.3. **High-VA allocation smoke test.** `VirtualAlloc2` at addresses 1 TiB,
     2 TiB, ..., 10 TiB to verify Windows allows allocations in high partitions.
     Run this as a platform-level unit test.

## Risk Assessment

| Risk | Likelihood | Mitigation | Rationale |
|------|------------|------------|-----------|
| Exception error codes incompatible | **Confirmed** | Step 3 — VirtualQuery fix | Code analysis proves bit 0 never set |
| Host allocations in high VA partitions | Medium | Step 2.2/4.2 — VirtualQuery probing | ASLR + ntdll near 0x7FFx |
| `VirtualAlloc2` fails in high VA | Low | Step 6.3 — smoke test | 64-bit Windows should allow full range |
| `VirtualProtect` CoW round-trip fails | Low | Step 3.3 — explicit test | VirtualProtect is well-documented |
| Post-boot host allocations in partition | Low | Step 4.2 — probing at alloc time | Unlikely in >1 TiB ranges |
| No Windows CI runners | Medium | Step 6 — self-contained tests + manual | Check CI config before starting |

## Notes

- **No new dependencies.** The shared partition module is pure Rust.
- **No new `unsafe`** beyond existing Win32 FFI.
- **Guest binaries are Linux ELF.** The syscall rewriter and fork→vfork patch
  apply identically to Linux and Windows platforms.
- **32-bit:** Not supported. Windows platform is x86_64 only.
- **Windows CI:** Determine availability before starting Step 6. If unavailable,
  define manual test acceptance criteria.
