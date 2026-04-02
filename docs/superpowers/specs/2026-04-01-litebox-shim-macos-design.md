# litebox_shim_macos — Phase 1 Design

Run macOS (Mach-O) aarch64 static executables on top of LiteBox.

## Approach

Syscall rewriter approach (LiteBox's default): build a new Mach-O syscall rewriter that patches `svc #0x80` instructions to branch to trampoline gates, identical in principle to how the existing ELF rewriter works for Linux binaries. The trampoline gates route through `_syscall_callback` to the shim's `EnterShim::syscall()` implementation, which dispatches BSD syscalls.

## New Crates

### `litebox_common_macos`

macOS-specific ABI definitions. `#![no_std]`.

**Contents:**

- `MacosSyscallRequest` enum — Decoded from `PtRegs.regs[16]` (x16, not x8 like Linux). `try_from_raw(syscall_number, ctx)` pattern matching `litebox_common_linux::SyscallRequest`. Arguments from x0-x5 (same registers as Linux).

- `MacosErrno` enum — BSD errno values. Mostly overlap with Linux but some differ (e.g., `ENOTSUP` = 45 on macOS vs 95 on Linux).

- Carry flag helpers — macOS syscall ABI signals errors via the carry bit (NZCV bit 29) in CPSR/PSTATE:
  - Success: `ctx.regs[0] = result`, `ctx.pstate &= !(1 << 29)`
  - Error: `ctx.regs[0] = errno_value`, `ctx.pstate |= 1 << 29`

- `PtRegs` — Re-exported from `litebox_common_linux`. Same aarch64 struct: `{ regs: [usize; 31], sp, pc, pstate }`. No duplication.

**Phase 1 syscalls:**

| Syscall | Number | Purpose |
|---------|--------|---------|
| `exit` | 1 | Process termination |
| `read` | 3 | Basic I/O |
| `write` | 4 | Hello world output |
| `open` | 5 | File access |
| `close` | 6 | File cleanup |
| `getpid` | 20 | Process info |
| `getuid` | 24 | Credentials |
| `geteuid` | 25 | Credentials |
| `getegid` | 43 | Credentials |
| `sigaction` | 46 | Signal setup (stub) |
| `getgid` | 47 | Credentials |
| `sigprocmask` | 48 | Signal masking (stub) |
| `ioctl` | 54 | Terminal queries (isatty) |
| `munmap` | 73 | Memory cleanup |
| `mprotect` | 74 | Memory protection |
| `madvise` | 75 | Memory hints |
| `mmap` | 197 | Memory allocation |
| `lseek` | 199 | File seeking |
| `sysctl` | 202 | System info |
| `issetugid` | 327 | Security check (libc init) |
| `fstat64` | 339 | File metadata |

Unknown syscalls return `ENOSYS`.

### `litebox_syscall_rewriter_macho`

Mach-O binary rewriter. Separate crate from the ELF rewriter — Mach-O and ELF have fundamentally different binary layouts, segment structures, and modification strategies.

**Input:** Raw `MH_EXECUTE` aarch64 Mach-O bytes.

**Processing steps:**

1. **Parse** — Use the `object` crate's `MachOFile64` to enumerate load commands. Find `LC_SEGMENT_64` segments with executable sections (`__text`, `__stubs`, `__stub_helper`).

2. **Scan** — Walk executable sections instruction-by-instruction:
   - `svc #0x80` — Patch to branch to per-site SVC gate
   - `msr TPIDR_EL0, Xn` / `mrs Xd, TPIDR_EL0` — Patch for TLS interception
   - Instructions referencing x18 — Patch for x18 save/restore (macOS zeros x18 on exception return)

3. **Emit trampoline** — Generate a `__LITEBOX` segment containing:
   - Per-site SVC gates (same structure as `emit_svc_gate_macos` in the ELF rewriter)
   - Shared SVC handler (same structure as `emit_shared_svc_handler_macos`)
   - Shared MSR/MRS handlers for TPIDR_EL0
   - Shared x18 load/save handlers
   - TLS lookup table

4. **Patch binary** — Append a new `LC_SEGMENT_64` load command to the Mach-O header pointing to the trampoline data appended at the end of the file. Error if header space is insufficient (unlikely for phase 1's simple static binaries).

**Output:** Modified Mach-O bytes.

**Trampoline code reuse:** The gate/handler assembly generation functions are copied from `litebox_syscall_rewriter/src/arm64.rs` into this crate. Refactoring into a shared crate deferred to a later phase.

**No code signing needed:** The runner loads the rewritten binary into litebox-managed anonymous pages via `PageManager`, not via the host kernel's Mach-O loader. macOS code signature checks do not apply to anonymous memory.

### `litebox_shim_macos`

The shim implementing `EnterShim` for macOS guests. `#![no_std]`, `extern crate alloc`.

**Crate structure:**

```
litebox_shim_macos/
  src/
    lib.rs          MacosShimBuilder, MacosShim, MacosShimEntrypoints, Task, GlobalState
    loader/
      mod.rs        DEFAULT_STACK_SIZE, DEFAULT_LOW_ADDR (0x1_0000_0000)
      macho.rs      Mach-O loader
      stack.rs      UserStack
    syscalls/
      mod.rs        do_syscall dispatch
      file.rs       open, close, read, write, lseek, fstat, ioctl
      mm.rs         mmap, munmap, mprotect, madvise, brk
      process.rs    exit, getpid, getuid/gid/euid/egid, issetugid
      signal.rs     sigaction, sigprocmask (stubs that succeed silently)
```

**Key types (mirroring Linux shim):**

- `MacosShimBuilder` — Holds `Platform`, `LiteBox`, filesystem. `build()` produces `MacosShim`.
- `MacosShim` — Holds `Arc<GlobalState>`. `load_program()` invokes the Mach-O loader.
- `MacosShimEntrypoints` — Implements `EnterShim<ExecutionContext = PtRegs>`. Holds `Task`.
- `GlobalState` — Shared: `PageManager`, filesystem, `FutexManager`, `Pipes`, `Network`, boot time.
- `Task` — Per-thread: reference to `GlobalState`, `do_syscall()` dispatches `MacosSyscallRequest`.

**Syscall dispatch:**

`do_syscall` reads `ctx.regs[16]` for the syscall number, decodes via `MacosSyscallRequest::try_from_raw`, dispatches to `sys_*` methods, then sets carry flag and x0 per the macOS ABI.

**Syscall implementations** call into the same `litebox` core APIs (`PageManager`, `FileSystem`, etc.) as the Linux shim. Written fresh — no premature code sharing with `litebox_shim_linux`.

**Mach-O loader:**

Processes the rewritten Mach-O in memory:

1. Validate `MH_MAGIC_64`, `CPU_TYPE_ARM64`, `MH_EXECUTE`.
2. Iterate load commands:
   - `LC_SEGMENT_64` — Reserve address range via `sys_mmap`, copy segment data, set protections. Skip `__PAGEZERO`.
   - `LC_MAIN` — Extract `entryoff` (offset from `__TEXT` base) for entry point address.
   - `LC_UNIXTHREAD` — Legacy entry point fallback.
3. Set up stack: `argc` at top, then `argv` pointers (null-terminated), `envp` pointers (null-terminated), `apple[]` array (minimal/empty for phase 1).
4. Entry convention: `LC_MAIN` is called as `main(argc, argv, envp, apple)` with arguments in x0-x3. `LC_UNIXTHREAD` is a raw jump with args on stack.
5. Allocate brk region after highest mapped segment.

### `litebox_runner_macos_on_macos_userland`

CLI runner and test harness.

**Orchestration:**

1. Read Mach-O from disk
2. Rewrite via `litebox_syscall_rewriter_macho::hook_syscalls_in_macho()`
3. Build shim (`MacosShimBuilder` → filesystem → `build()`)
4. Load program (`shim.load_program(rewritten_bytes, argv, envp)`)
5. Run thread via platform
6. Wait for exit, return exit code

**Test progression:**

| Test | Description | Syscalls |
|------|-------------|----------|
| `hello_nolibc.s` | aarch64 asm: `write(1, "hello\n", 6)` + `exit(0)` via `svc #0x80` | write, exit |
| `hello_nolibc.c` | C with raw syscall wrappers, no libc | write, exit |

Test binaries compiled at test time using `as`/`ld` (Xcode toolchain). No cross-compilation — macOS-on-macOS.

**Test helper functions:**

- `compile_macho_asm(source) -> Vec<u8>` — Assemble + link to static MH_EXECUTE
- `run_static_prog(bytes, args) -> (i32, String)` — Full pipeline: rewrite, load, run, capture stdout + exit code

## Platform Changes

### `switch_to_guest` NZCV restoration

`litebox_platform_macos_userland/src/lib.rs` — `switch_to_guest` currently does not restore `PtRegs.pstate` before jumping to the guest. Add `msr NZCV, xN` to restore condition flags from `PtRegs.pstate`.

Required for the macOS carry-flag error convention. Backward-compatible with the Linux shim (which stores `pstate = 0`, resulting in all flags clear — the current implicit behavior).

Implementation: load `PtRegs.pstate` before x0 is clobbered, stash below guest SP alongside other values, restore via `msr NZCV` before final `br x16`. Adds ~3 instructions.

### Workspace Cargo.toml

Add new crates to workspace members:
- `litebox_common_macos`
- `litebox_syscall_rewriter_macho`
- `litebox_shim_macos`
- `litebox_runner_macos_on_macos_userland`

### No changes to `litebox` core

`EnterShim`, `PageManager`, `FileSystem`, `Network` are shim-agnostic.

### No changes to `litebox_syscall_rewriter`

Trampoline functions copied to the new crate. No modifications to the ELF rewriter.

## Not In Scope (Future Phases)

- Dynamic linking / dyld / `LC_LOAD_DYLIB`
- `MH_DYLIB`, `MH_BUNDLE` file types
- Mach traps (negative x16 syscall numbers)
- Threading (`bsdthread_create`, `bsdthread_register`)
- Signals beyond stubs
- Networking syscalls
- `execve` / process spawning
- x86_64 support
- Sharing syscall code between Linux and macOS shims
- Extracting trampoline emission into a shared crate
- Refactoring `PtRegs` into an arch-specific crate

## Success Criteria

1. `cargo test -p litebox_runner_macos_on_macos_userland` passes
2. Nolibc asm test: assembles minimal aarch64 Mach-O doing `write` + `exit` via `svc #0x80`, runs through full pipeline (rewrite → load → dispatch → exit), exits 0, stdout = "hello\n"
3. Nolibc C test: C file with raw syscall wrappers, compiled to static MH_EXECUTE, same result
