# litebox_shim_macos — Phase 2 Design: Dynamic Linking via mmap-hook Rewriting

Run dynamically linked macOS (Mach-O) aarch64 executables on top of LiteBox, starting with `hello.c` (printf, clock_gettime, argv/envp printing).

## Approach

Let real dyld (`/usr/lib/dyld`) perform dynamic linking inside the guest. Rewrite dyld at load time (same as the main binary). Intercept dyld's `mmap` calls to patch dylib code segments on the fly using the mmap-hook pattern from `wdcui/multi-proc/stacked`. Extract dylibs from the macOS shared cache into a local sysroot to avoid shared cache complexity.

## Architecture Overview

```
Runner loads main binary + /usr/lib/dyld
         │
         ▼
    hook_syscalls_in_macho() on both
         │
         ▼
    Loader maps both into guest address space
    Stack: argc/argv/envp/apple[]
    Entry → dyld's LC_UNIXTHREAD entry
         │
         ▼
    dyld bootstrap (all syscalls intercepted)
    ├── Mach traps → stub responses
    ├── shared_region_check_np → EINVAL (force fallback)
    ├── open("/usr/lib/libSystem.B.dylib") → path rewrite to sysroot
    ├── mmap(PROT_EXEC) → mmap-hook patches SVC sites in dylib code
    └── symbol binding, fixups → jump to LC_MAIN
         │
         ▼
    hello.c: printf → write, clock_gettime → shim handles
         │
         ▼
    exit(0) → shim terminates
```

## Key Design Decisions

1. **Real dyld, not custom linker** — dyld is complex (~100K lines). Writing a replacement is impractical. Instead, we run the real dyld and intercept its syscalls.

2. **mmap-hook runtime patching** — When dyld maps a dylib's executable segment, the shim intercepts the `mmap(PROT_EXEC)` call, reads the file content, rewrites `SVC #0x80` sites to trampolines, and serves patched pages. This avoids pre-rewriting every dylib on disk.

3. **Extracted sysroot, not shared cache** — On modern macOS, individual dylib files don't exist on disk (they're in the ~1.5GB `dyld_shared_cache`). We extract the minimal set of dylibs to a local sysroot and redirect dyld's `open()` calls there. This mirrors how the Linux runner ships pre-compiled `libc.so.6` and `ld-linux-aarch64.so.1` in `tests/test-bins/`.

4. **Stub Mach traps** — dyld uses a handful of Mach traps during bootstrap. We stub them with fake constant values rather than implementing Mach IPC.

## New: dyld Loading

### Loading dyld from `/usr/lib/dyld`

`/usr/lib/dyld` is a universal (fat) binary containing x86_64 and arm64e slices. The loader must:

1. Parse the fat header, find the arm64/arm64e slice
2. Read the slice into memory
3. Call `hook_syscalls_in_macho()` on the slice bytes to rewrite SVC sites
4. Map the rewritten dyld segments using the existing reserve-then-map pattern
5. Extract the entry point from dyld's `LC_UNIXTHREAD` load command (dyld always uses `LC_UNIXTHREAD`, not `LC_MAIN`)

New function: `load_dyld(data: &[u8], page_manager, syscall_entry) -> DyldLoadInfo`

Returns `DyldLoadInfo { entry_point, slide }`.

### Stack Layout for dyld

dyld expects the kernel to set up the stack with argc/argv/envp plus an "apple" array of metadata strings. Extend `UserStack` to emit:

```
[top of stack]
  argc                          (existing)
  argv[0] ... argv[n], NULL     (existing)
  envp[0] ... envp[m], NULL     (existing)
  apple[0] ... apple[k], NULL   (new)
[stack grows down]
```

Required apple entries:
- `executable_path=<path>` — tells dyld which binary to link
- `ptr_munge=0000000000000000` — pointer mangling cookie (0 = disabled)

Optional (add if dyld requires them):
- `main_stack=<addr>,<size>` — stack bounds
- `executable_cdhash=<hex>` — code directory hash (stub with zeros)

### Entry Point Selection

When the main binary has `LC_LOAD_DYLINKER`:
- Set entry to dyld's `LC_UNIXTHREAD` entry (not the main binary's `LC_MAIN`)
- dyld will discover and jump to the main binary's entry after linking

When the main binary has no `LC_LOAD_DYLINKER`:
- Existing Phase 1 behavior — enter at main binary's `LC_MAIN` / `LC_UNIXTHREAD`

## New: mmap-hook Runtime Code Patching

### Trigger

Any `mmap` call where `prot` includes `PROT_EXEC` and `fd >= 0` (file-backed executable mapping).

### Per-fd State

```rust
struct MachoPatchState {
    /// Base VA of the Mach-O (from first mmap at offset 0)
    base_addr: usize,
    /// VA of the allocated trampoline region
    trampoline_addr: usize,
    /// Next write offset in the trampoline buffer
    trampoline_cursor: usize,
    /// Whether the trampoline page has been allocated
    trampoline_mapped: bool,
}
```

Stored in `BTreeMap<i32, MachoPatchState>` on the `Task`. Single-threaded for Phase 2 (no threading support), so no sharing concerns.

### Flow

1. **`open()` of a dylib** → normal open, create fd entry. No `MachoPatchState` yet.

2. **`mmap(PROT_READ, fd, offset=0)`** → map normally. Initialize `MachoPatchState` with `base_addr` = mapped address.

3. **`mmap(PROT_READ|PROT_EXEC, fd, offset)`** → hook fires:
   a. Allocate anonymous RW pages at the requested address (`MAP_FIXED`)
   b. Read file content for this offset+size into a temporary buffer
   c. If trampoline not yet allocated: allocate a trampoline page (RW) near the code (within ±128MB for aarch64 `B` instruction range). Write `syscall_entry_point` at offset 0. Set cursor to 8.
   d. Call `patch_code_segment_macho()` — scans buffer for `SVC #0x80` (`0xD4001001`), replaces each with `B` to a stub in the trampoline. Each stub: save x16/x17/lr, load return address, branch to shared handler at trampoline[0].
   e. Copy patched buffer into the mapped pages
   f. `mprotect` to `PROT_READ|PROT_EXEC`

4. **`mprotect(..., PROT_READ|PROT_EXEC)`** → apply normally. Code is already patched from step 3.

5. **`close(fd)`** → finalize: `mprotect` trampoline from RW to RX, remove `MachoPatchState` entry.

### New Rewriter API

Add to `litebox_syscall_rewriter_macho`:

```rust
/// Patch SVC #0x80 sites in a single mapped code segment.
///
/// Scans `code` for SVC #0x80 instructions. Each found site is replaced
/// with a B (branch) instruction targeting a generated stub in `trampoline_buf`.
///
/// Returns the new trampoline cursor position.
pub fn patch_code_segment(
    code: &mut [u8],
    code_vaddr: u64,
    trampoline_buf: &mut [u8],
    trampoline_vaddr: u64,
    trampoline_cursor: usize,
    syscall_entry: u64,
) -> Result<usize, RewriterError>
```

This mirrors the Linux `patch_code_segment` API from `wdcui/multi-proc/stacked` but operates on `SVC #0x80` (encoding `0xD4001001`) and emits aarch64 `B` instructions (±128MB range) instead of x86 `JMP rel32`.

## New: Path Rewriting (Sysroot Redirect)

### Configuration

`GlobalState` gains a sysroot path:

```rust
pub struct GlobalState {
    // ... existing fields ...
    /// Path to extracted dylib sysroot. When set, open() calls for
    /// /usr/lib/... are redirected to <sysroot>/usr/lib/...
    sysroot: Option<String>,
}
```

### Redirect Logic

In `sys_open()`:
1. If `sysroot` is `Some` and the path starts with `/usr/lib/` or `/System/Library/`:
   - Prepend the sysroot path
   - Open the redirected path instead
2. Otherwise open normally

This is transparent to dyld — it thinks it's opening system libraries from their standard locations.

### Extracted Sysroot Contents

Minimal set of dylibs needed for `hello.c` (printf + clock_gettime):

```
tests/test-bins/macos-sysroot/
  usr/lib/
    libSystem.B.dylib          (umbrella library)
    system/
      libsystem_c.dylib        (printf, string functions)
      libsystem_kernel.dylib   (syscall wrappers)
      libsystem_platform.dylib (low-level platform support)
      libsystem_pthread.dylib  (pthread stubs, required by libSystem)
      libdyld.dylib            (dyld support functions)
      libsystem_malloc.dylib   (malloc/free)
      libsystem_blocks.dylib   (blocks runtime)
      libsystem_info.dylib     (getpwnam etc. — may not be needed)
      libcorecrypto.dylib      (crypto — may not be needed)
      libcompiler_rt.dylib     (compiler builtins)
```

Extracted using `dyld_shared_cache_util -extract <dir>` or equivalent tool. Exact set determined empirically — start with the minimum, add as dyld reports missing libraries.

## New: Syscall Additions

### BSD Syscalls

| Syscall | Nr | Status | Implementation |
|---------|----|--------|----------------|
| `exit` | 1 | Existing | — |
| `read` | 3 | Existing | — |
| `write` | 4 | Existing | — |
| `open` | 5 | **New** | Open file, create fd, path rewrite for sysroot |
| `close` | 6 | Existing | Extend: finalize `MachoPatchState` on close |
| `getpid` | 20 | Existing | — |
| `getuid` | 24 | Existing | — |
| `geteuid` | 25 | Existing | — |
| `getegid` | 43 | Existing | — |
| `sigaction` | 46 | **New** | Stub: record but don't deliver signals |
| `getgid` | 47 | Existing | — |
| `sigprocmask` | 48 | **New** | Stub: return success, no actual masking |
| `ioctl` | 54 | **New** | Handle `TIOCGWINSZ` and `FIONREAD`; return `ENOTTY` for unknown fds |
| `munmap` | 73 | Existing | — |
| `mprotect` | 74 | Existing | — |
| `madvise` | 75 | **New** | Stub: return success |
| `fcntl` | 92 | **New** | Handle `F_GETPATH`, `F_GETFL`, `F_SETFL` |
| `pread` | 153 | **New** | Positional read (dyld uses heavily) |
| `csops` | 169 | **New** | Stub: return 0 (not signed) or `CS_VALID` minimally |
| `mmap` | 197 | Existing | Extend: mmap-hook for PROT_EXEC |
| `lseek` | 199 | **New** | Seek within file |
| `sysctl` | 202 | **New** | Return canned values for hw.ncpu, kern.osversion, etc. |
| `shared_region_check_np` | 294 | **New** | Return `EINVAL` to force dyld's fallback path |
| `issetugid` | 327 | Existing | — |
| `fstat64` | 339 | **New** | File stat, translate to macOS stat64 layout |
| `getentropy` | 500 | **New** | Fill buffer with random bytes (for stack canary init) |

### Mach Traps (negative x16)

| Trap | Nr (x16) | Implementation |
|------|----------|----------------|
| `mach_reply_port` | -26 | Return constant `0x0703` |
| `thread_self_trap` | -27 | Return constant `0x0303` |
| `task_self_trap` | -28 | Return constant `0x0103` |
| `host_self_trap` | -29 | Return constant `0x0503` |
| `mach_msg_trap` | -31 | Return `MACH_SEND_INVALID_DEST` (0x10000003) |
| `thread_get_special_reply_port` | -50 | Return constant `0x0903` |

### Mach Trap Dispatch

The current `do_syscall` reads x16 and assumes all values are positive BSD syscall numbers. Extend to check the sign of x16:

```rust
fn do_syscall(&mut self, ctx: &mut PtRegs) {
    let nr = ctx.regs[16] as i64;
    if nr < 0 {
        self.do_mach_trap(nr, ctx);
    } else {
        self.do_bsd_syscall(nr as u64, ctx);
    }
}
```

Mach trap return convention: result in x0, no carry flag.

## Changes to Existing Code

### `litebox_syscall_rewriter_macho`

- Add `pub fn patch_code_segment(...)` — segment-level rewriting API (see above)
- Existing `hook_syscalls_in_macho()` continues to work for whole-binary rewriting at load time

### `litebox_shim_macos/src/loader/macho.rs`

- Add `load_dyld()` function for loading `/usr/lib/dyld`
- Add fat/universal binary parsing (extract arm64 slice)
- Modify `load_program()` to detect `LC_LOAD_DYLINKER` and load dyld when present
- Entry point selection: dyld entry when dynamically linked, main binary entry when static

### `litebox_shim_macos/src/loader/stack.rs`

- Add apple array support to `UserStack`
- New method: `push_apple_entries(executable_path, ptr_munge_cookie)`

### `litebox_shim_macos/src/syscalls/mod.rs`

- Split dispatch into `do_bsd_syscall()` and `do_mach_trap()` based on sign of x16
- Add new syscall handlers

### `litebox_shim_macos/src/syscalls/mm.rs`

- Add mmap-hook logic: detect `PROT_EXEC` + file-backed, call `patch_code_segment()`
- Add `MachoPatchState` and `BTreeMap<i32, MachoPatchState>` to `Task`

### `litebox_common_macos/src/syscall.rs`

- Add new syscall number constants
- Add Mach trap number constants (negative values)
- Extend `MacosSyscallRequest` enum with new variants

### `litebox_runner_macos_on_macos_userland`

- Update runner to configure sysroot path in `GlobalState`
- Add sysroot extraction build step or pre-extracted test fixtures
- Add `test_hello_dynamic` integration test

## Sysroot Extraction

### Build-time Extraction

A script or build.rs step extracts dylibs from the shared cache:

```bash
# Using dyld_shared_cache_util (ships with Xcode command line tools)
dyld_shared_cache_util -extract tests/test-bins/macos-sysroot \
    /System/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e
```

If `dyld_shared_cache_util` is not available, use the `dsc_extractor` library or a custom extraction tool based on the shared cache format.

The extracted dylibs are normal Mach-O files that the rewriter handles.

### Minimal Extraction

For CI/testing, extract only the libraries needed for `hello.c`. The exact set is determined by running dyld under the shim and observing which `open()` calls it makes. Start with:
1. `libSystem.B.dylib`
2. `libsystem_c.dylib`
3. `libsystem_kernel.dylib`
4. `libsystem_platform.dylib`
5. `libsystem_pthread.dylib`
6. `libdyld.dylib`
7. `libsystem_malloc.dylib`
8. `libcompiler_rt.dylib`

Add more as needed based on runtime errors.

## End-to-End Flow

### Setup (test infrastructure)
1. Extract dylibs from shared cache → `tests/test-bins/macos-sysroot/`
2. Compile `hello.c` with `clang -arch arm64` → `tests/test-bins/hello_macos_dyn`

### Runtime
1. Runner reads `hello_macos_dyn` and `/usr/lib/dyld` from disk
2. `hook_syscalls_in_macho()` rewrites both (SVC → trampoline)
3. Shim builder creates `GlobalState` with sysroot path, empty patch cache
4. Loader maps main binary segments (existing)
5. Loader maps dyld segments (new)
6. Loader sets up stack with argc/argv/envp/apple (extended)
7. Entry → dyld's `LC_UNIXTHREAD` entry
8. dyld calls `task_self_trap` (x16=-28) → shim returns `0x0103`
9. dyld calls `shared_region_check_np` → shim returns `EINVAL`
10. dyld opens `libSystem.B.dylib` → shim redirects to sysroot, returns fd
11. dyld mmaps code segment (PROT_EXEC) → hook patches SVC sites in dylib
12. Repeat for sub-libraries
13. dyld performs symbol binding → jumps to main binary's `LC_MAIN`
14. `printf("Hello")` → libsystem_c → `write(1, ...)` → shim → host
15. `clock_gettime()` → libsystem_kernel → shim returns host time
16. `main()` returns → `exit(0)` → shim terminates

## Not In Scope

- Threading (`bsdthread_create`, `bsdthread_register`, `pthread_create`)
- Full Mach IPC / `mach_msg` message passing
- Shared cache direct mapping
- arm64e pointer authentication enforcement
- Signal delivery (only stub registration)
- Networking syscalls
- `execve` / process spawning
- x86_64 support
- Multi-process support
- Code signing enforcement

## Success Criteria

1. `cargo test -p litebox_runner_macos_on_macos_userland` passes all tests (Phase 1 + Phase 2)
2. `test_hello_dynamic`: compiles `hello.c` (with printf, clock_gettime, argv/envp) using `clang -arch arm64`, runs it through the full dynamic linking pipeline (rewrite → load dyld → dyld bootstrap → mmap-hook patching → execute), produces correct stdout output, exits 0
3. Phase 1 tests continue to pass (no regression)
4. `cargo clippy` clean, `cargo fmt` clean
