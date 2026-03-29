# Micro-LiteBox: Design, Implementation, and Evaluation

## Overview

Micro-LiteBox is a split-process architecture for running unmodified Linux
binaries under LiteBox's syscall interception. It separates the guest
process (which runs the original program) from the central process (which
enforces policy and maintains a virtual filesystem), communicating through a
shared-memory ring buffer.

This design solves a fundamental limitation of LiteBox's single-process
runner: the runner cannot support `fork()`, because forking a process that
contains both the guest code and the LiteBox runtime would duplicate the
runtime's internal state in ways that are difficult to reconcile. By
splitting guest and runtime into separate OS processes, `fork()` in the
guest creates only a new guest — the central process remains singular and
spawns a new server thread for each child.

### Design Goals

1. **Run unmodified binaries** — no source changes, no recompilation. The
   platform adapts to the binary, not the other way around.
2. **Maintain a security boundary** — every syscall requires central's
   authorization before it can execute. Micro is a local execution agent,
   not an independent policy maker.
3. **Support fork/exec** — the primary motivation for the split architecture.
4. **Minimize overhead for compute-bound workloads** — syscall interception
   should add negligible cost when the guest is not making syscalls.

## Architecture

Micro-LiteBox comprises five components:

```
                        ┌─────────────────────────────────┐
                        │         Central Process          │
                        │  ┌───────────┐  ┌────────────┐  │
                        │  │   Shim    │  │  Layered   │  │
                        │  │ (LinuxABI)│  │ Filesystem │  │
                        │  └─────┬─────┘  └──────┬─────┘  │
                        │        │               │         │
                        │  ┌─────┴───────────────┴─────┐  │
                        │  │    ProcessServer (per      │  │
                        │  │    guest process)          │  │
                        │  └────────────┬──────────────┘  │
                        └───────────────┼──────────────────┘
                                        │ shared memory
                                        │ (ring buffer)
                        ┌───────────────┼──────────────────┐
                        │               │                   │
                        │  ┌────────────┴──────────────┐   │
                        │  │     Micro Agent            │   │
                        │  │  (trampoline + local exec) │   │
                        │  └────────────┬──────────────┘   │
                        │               │                   │
                        │  ┌────────────┴──────────────┐   │
                        │  │   Guest Binary (rewritten) │   │
                        │  └───────────────────────────┘   │
                        │         Guest Process             │
                        └───────────────────────────────────┘
```

**Packager** (`litebox_packager` + `litebox_syscall_rewriter`) — an offline
tool that rewrites ELF binaries, replacing `syscall` instructions with
jumps to trampoline stubs.

**Launcher** (`litebox_launcher`) — bootstraps execution. Creates the
shared memory region, loads the rewritten guest ELF, forks (parent =
guest, child = central), initializes the micro agent, and jumps to the
guest entry point.

**Central** (`litebox_central`) — the policy and filesystem process. Runs
a `ProcessServer` per guest process on its own OS thread. Each server
reads syscall requests from the shared ring, routes them through the shim,
and writes responses back.

**Micro** (`litebox_micro`) — a library linked into the guest process. It
provides the trampoline entry point that all rewritten syscalls jump to,
manages the guest side of the ring buffer, and executes syscalls locally
when central authorizes it.

**Shim** (`litebox_shim_linux`) — a `#![no_std]` crate that implements
the Linux syscall ABI against LiteBox's virtual abstractions: layered
filesystem, virtual fd table, process table, page tracking, signal state.
Central calls into the shim; the shim never makes real host syscalls.

### Shared Memory Layout

The guest and central communicate through a `memfd`-backed shared memory
region mapped `MAP_SHARED` in both processes:

```
Offset 0:        RingHeader
                   sq_head, sq_tail, sq_notify        (cache-line aligned)
                   cq_head, cq_tail
                   cq_notify_slots[64]                (per-thread futex words)

                 SqEntry[256]                          (128 bytes each, 64-aligned)
                   seq, syscall_nr, thread_slot, flags
                   args[6], data_offset, data_len, ready

                 CqEntry[256]                          (32 bytes each)
                   seq, result, flags, thread_slot
                   data_offset, data_len

Page-aligned:    Data Region (8 MiB)
                   [0 .. 256K)       per-thread pathname slots (slot * 4096)
                   [1M .. 5M)        per-thread write data (1M + slot * 64K)
                   [remainder]       read data, stat results, ELF segments
```

Wake/sleep coordination uses Linux futexes on the `sq_notify` and
per-thread `cq_notify_slots` words, with an adaptive 3-phase wait strategy:
200 busy-spins, 8 rounds of exponential backoff, then futex sleep.

## Implementation

### Binary Rewriting

The packager scans all `.text` sections of the guest ELF (and its shared
library dependencies, discovered via `ldd`) for `syscall` and `int 0x80`
instructions. Each syscall site is replaced with a 5-byte `JMP rel32` to a
per-site trampoline stub appended after the original ELF content. Remaining
bytes at the original site are filled with NOPs.

Each trampoline stub:
1. Copies any displaced instruction bytes
2. Loads the return address into RCX via `LEA RCX, [RIP+disp32]`
3. Executes `JMP [RIP+disp]` through an indirect pointer

The indirect pointer targets offset 0 of a trampoline data page, which
starts as zero. At load time, micro patches this pointer to
`micro_syscall_entry`. A 32-byte `TrampolineHeader64` (magic `LITEBOX0`)
is appended at EOF so the loader can locate the trampoline region.

The packager bundles all rewritten ELFs plus `litebox_rtld_audit.so`
(which intercepts dynamic linker activity) into a `.tar` archive.

### Launcher and Fork Model

The launcher (`litebox_launcher/src/main.rs`):
1. Creates shared memory via `memfd_create` (without `MFD_CLOEXEC` so the
   fd survives exec)
2. Loads the guest ELF — maps PT_LOAD segments, resolves the dynamic
   linker from PT_INTERP, constructs the user stack with argc/argv/envp/auxv
3. Obtains the address of `micro_syscall_entry`
4. **Forks** — the parent becomes the guest process; the child execs
   `litebox_central --shmem-fd=N --initial-brk=N`
5. Initializes the micro agent (`micro_init` sets up global state;
   `micro_init_thread` allocates GS-based TLS for the initial thread)
6. Zeroes all GPRs, sets RSP to the guest stack, and jumps to the guest
   entry point

The fork-then-exec model means the parent (guest) retains the original
memory mappings and PID. Central runs as a separate binary, receiving
the shared memory fd as a command-line argument.

### Syscall Interception Path

When the guest executes a rewritten syscall site:

```
Guest code → JMP to trampoline stub → JMP [entry_point] → micro_syscall_entry
```

`micro_syscall_entry` (assembly in `litebox_micro/src/trampoline.rs`) saves
the return address to GS-based TLS, moves the stack pointer past the
128-byte red zone, saves all six argument registers plus the syscall number
as a `SyscallArgs` struct on the stack, and calls `micro_handle_syscall`.

`rt_sigreturn` (syscall 15) is special-cased as a fast path that issues a
real syscall directly, bypassing IPC entirely.

### Syscall Routing in Central

`ProcessServer::handle_syscall` (`litebox_central/src/server.rs`) routes
each syscall into one of several categories:

| Category | Examples | Behavior |
|---|---|---|
| Auth-only, execute locally | `arch_prctl`, signals, time, `getpid` | Return `EXEC_LOCAL` flag |
| Shim dispatch | `open`, `unlink`, `mkdir`, `rename` | Call shim, return result |
| Data-producing I/O | `read`, `fstat`, `getdents64`, `getcwd` | Call shim, write output to data region, return `HAS_DATA` |
| Data-consuming I/O | `write`, `pwrite64` | Read input from data region, call shim |
| Dual-dispatch | `close`, `dup`, `fcntl` | Try shim; if `EBADF` (real OS fd), return `EXEC_LOCAL` |
| Fork | `clone` (no `CLONE_VM`), `fork`, `vfork` | Create child ring, fork shim task, spawn server thread |
| Execve | `execve` | Load new ELF, pack segments into data region |
| Trampoline-bearing mmap | `mmap` (file-backed, executable) | After shim dispatch, detect `TrampolineHeader64` at EOF, append descriptor |

The "needs local exec" predicate (`needs_local_exec` in `server.rs`)
identifies syscalls that must execute in the guest's address space because
they dereference guest pointers, manipulate guest memory, or require access
to real OS state (signals, PID, etc.).

### Local Execution in Micro

When micro receives a CQ entry with `EXEC_LOCAL`, it calls
`execute_locally` (`litebox_micro/src/local_exec.rs`), which performs the
real syscall via inline assembly wrappers that bypass glibc. This function
handles:

- **Memory management**: `mmap` (with trampoline patching for newly-loaded
  libraries), `munmap`, `mprotect`, `madvise`, `brk` (emulated via a
  guest-brk watermark and `mmap`)
- **Signals**: `rt_sigaction`, `rt_sigprocmask`, `rt_sigsuspend`,
  `sigaltstack`, `alarm`
- **Time**: `clock_gettime`, `gettimeofday`, `nanosleep`,
  `clock_nanosleep`
- **Process identity**: `getpid`, `getppid`, `getuid`, `getgid`,
  `geteuid`, `getegid`
- **I/O on real OS fds**: `read`, `write`, `readv`, `writev`, `close`,
  `dup`, `dup2`, `dup3`, `fcntl`, `pipe2`, `ioctl`
- **Other**: `sched_getaffinity`, `getrandom`, `sysinfo`, `mincore`,
  `sync`

After local execution completes, micro reports the result back to central
via a `MSG_LOCAL_RESULT` control message so central can update its internal
state (e.g., page tracking after mmap).

### Fork Support

Fork is the most complex operation in the micro architecture:

1. **Central** (`handle_fork` in `server.rs`):
   - Creates a new `memfd`-backed shared memory region for the child
   - Calls `shim.fork_task()` to create a child task that inherits the
     parent's open file descriptors (duplicated via `fork_files_state`)
     and current working directory
   - Writes the child's shmem fd and pid into the CQ entry
   - Spawns a new `ProcessServer::run()` on a dedicated OS thread

2. **Micro** (`handle_fork` in `fork.rs`):
   - Opens the child's shmem fd (from the CQ entry)
   - Performs a real `fork()` via raw syscall
   - **Parent**: returns the child PID to the guest
   - **Child**: unmaps the parent's ring, maps the child's ring, sends
     `MSG_CHILD_READY` to central, continues execution

3. **Central** (child server thread):
   - Waits for `MSG_CHILD_READY` before processing the child's syscalls
   - Runs independently with its own shim task, virtual fd table, and
     filesystem view

### Execve Support

In-process execve (`handle_execve` in `execve.rs`):

1. Micro serializes pathname, argv, and envp into the shmem data region
2. Central loads the new ELF, packs PT_LOAD segments plus the trampoline
   into the data region
3. Micro maps the new segments with `MAP_FIXED` over the old guest code
   (point of no return), patches all trampoline entry points to
   `micro_syscall_entry`, resets the FS base, and jumps to the new entry
   point

### Layered Filesystem

Central's shim operates on a layered filesystem
(`litebox/src/fs/layered.rs`):

```
   Writes  ──►  In-memory filesystem (writable)
                        │
   Devices ──►  /dev/stdin, /dev/stdout, /dev/stderr, /dev/null, /dev/urandom
                        │
   Reads   ──►  Tar read-only layer (from packager output)
```

Files opened from the lower (tar) layer get independent file descriptors
per open() call, so concurrent readers don't interfere with each other's
seek positions. Writes to lower-layer files trigger copy-on-write migration
to the upper (in-memory) layer.

The root directory is chmod'd world-writable at startup so the guest (uid
1000) can create files. `/tmp` is pre-created on the in-memory layer.

## Evaluation

We evaluate micro-LiteBox using all 10 non-graphical UnixBench benchmarks,
running each unmodified (the benchmarks are not adapted to LiteBox in any
way). The single-process LiteBox runner is included where it works, to show
the cost of the split-process architecture specifically.

### Environment

- Platform: Linux (codespace)
- Build: Rust release profile
- Duration: 10 seconds per iteration, 3 iterations averaged

### Results

| Benchmark | Unit | Native | LiteBox | LB vs Native | Micro | Micro vs Native |
|---|---|---:|---:|---:|---:|---:|
| dhry2reg | lps | 345,816,480 | 345,173,152 | 0.998x | 338,742,160 | 0.980x |
| whetstone-double | MWIPS | 7,435 | 7,437 | 1.000x | 7,142 | 0.961x |
| pipe | lps | 5,343,639 | 16,314,771 | 3.053x | 290,827 | 0.054x |
| syscall | lps | 3,411,871 | 13,373,002 | 3.920x | 190,423 | 0.056x |
| spawn | lps | 10,463 | -- | -- | 3,336 | 0.319x |
| execl | lps | 13,525 | 2,449 | 0.181x | 1,171 | 0.087x |
| context1 | lps | 953,734 | -- | -- | 47,516 | 0.050x |
| fstime | KBps | 610,660 | 2,910,093 | 4.766x | 92,530 | 0.152x |
| shell1 | lpm | 565 | -- | -- | 65 | 0.115x |
| shell8 | lpm | 302 | -- | -- | 29 | 0.096x |

`--` indicates the benchmark fails on the single-process runner (no
fork/SIGPIPE support).

### Analysis

**CPU-bound workloads** (dhry2reg, whetstone-double) show 2-4% overhead
in micro. The binary rewriting trampoline adds a small cost on occasional
syscalls (e.g., gettimeofday for timing), but the inner compute loops are
untouched. The single-process runner achieves near-zero overhead here
because its shim handles syscalls in-process without any IPC.

**Syscall-intensive workloads** (pipe, syscall, context1) show 94-95%
overhead in micro. Every syscall requires a shared-memory round-trip:
the guest writes an SQ entry, wakes central via futex, central processes
the request, writes a CQ entry, and wakes the guest back. The
single-process runner is actually *faster* than native for pipe and
syscall because it handles `close()` and `getpid()` entirely in
userspace without entering the kernel.

**I/O workloads** (fstime) show 85% overhead in micro. Write data must be
copied into the shared memory data region, central processes it through
the virtual filesystem, and the result is communicated back. The
single-process runner is 4.8x faster than native because it writes to an
in-memory filesystem with no kernel involvement.

**Process-creation workloads** (spawn, execl) show 68-91% overhead.
Fork requires allocating a new shared memory region, forking the shim
task (duplicating all file descriptors), and spawning a new server
thread. Execve requires loading the new ELF in central, packing segments
into shared memory, and remapping them in the guest. The single-process
runner shows 82% overhead for execl due to binary re-rewriting.

**Shell benchmarks** (shell1, shell8) show 88-90% overhead. These
combine fork, exec, pipe, and file I/O — every category of overhead
stacks. The single-process runner cannot run these at all.

### Overhead Breakdown

The dominant cost in micro-LiteBox is the **shmem round-trip per syscall**.
Each round-trip involves:

1. Guest writes 128-byte SQ entry (cached memory write)
2. Guest issues `futex_wake` to notify central (kernel transition)
3. Central reads the SQ entry, processes through shim
4. Central writes 32-byte CQ entry
5. Central issues `futex_wake` on the per-thread slot (kernel transition)
6. Guest reads CQ entry

Steps 2 and 5 each require a kernel transition (futex syscall), making
the minimum cost approximately **2 kernel round-trips per intercepted
syscall**. For syscalls that would otherwise be a single kernel
transition (getpid, close, pipe read/write), this roughly doubles the
cost at minimum, and the shim processing time adds further overhead.

For `EXEC_LOCAL` syscalls (the majority), there is an additional cost:
after central authorizes the syscall, micro executes it locally and then
sends a `MSG_LOCAL_RESULT` back to central — adding a third round-trip
for state synchronization.

### Micro-Local Fast-Path Optimization

The overhead breakdown above reveals that for many `EXEC_LOCAL` syscalls,
central does **zero work**: it receives the request, immediately returns
`EXEC_LOCAL` with no shim dispatch, no state update, and no side effects.
The guest then executes the syscall, reports back via `MSG_LOCAL_RESULT`,
and central discards the result. The entire central round-trip is wasted.

The **micro-local fast-path** eliminates this overhead for ~30 stateless
syscalls. When micro recognizes a syscall in the micro-local set (via a
compile-time `matches!` check), it executes the syscall directly without
any ring-buffer communication. Central is never consulted.

**Micro-local syscall categories:**

- **Process/user identity** (getpid, getppid, getuid, getgid, geteuid,
  getegid): Simple kernel queries, return constants.
- **Time** (clock_gettime, gettimeofday, time, clock_getres): Read-only
  kernel state, write to guest buffer.
- **Sleep** (nanosleep, clock_nanosleep): Blocking, no shared state.
- **Thread setup** (arch_prctl, set_tid_address, set_robust_list, rseq):
  Thread-local operations only.
- **Signals** (rt_sigaction, rt_sigprocmask, sigaltstack, rt_sigsuspend,
  alarm): Process-local signal state.
- **Random/info** (getrandom, sched_getaffinity, prlimit64, uname,
  sysinfo, getrlimit, mincore): Write to guest buffer, no shared state.
- **Process wait** (wait4): Must run in micro's PID namespace.
- **Pipe creation** (pipe2): Real OS pipes, no shim state involvement.
- **Filesystem sync** (sync): No arguments, globally visible operation.
- **brk** (post-execve only): Managed by micro's `guest_brk` watermark
  via mmap/munmap.

**Design principles:**
- **Stateless only**: Every micro-local syscall was verified against
  central's `handle_syscall` — central does zero shim dispatch, zero
  state updates, and the `MSG_LOCAL_RESULT` handler is a no-op.
- **No fd-aware syscalls**: Syscalls that interact with file descriptors
  (other than pipe2) are excluded to preserve the virtual fd abstraction.
- **No mm syscalls**: mmap, munmap, mprotect, madvise remain centrally
  managed via the PageManager.

#### Post-Fast-Path Results

| Benchmark | Unit | Native | Micro (before) | Micro (after) | Improvement |
|---|---|---:|---:|---:|---|
| dhry2reg | lps | 348,543,199 | 338,742,160 | 344,684,715 | ~same |
| whetstone-double | MWIPS | 7,364 | 7,142 | 7,414 | ~same |
| pipe | lps | 5,453,790 | 290,827 | 321,205 | 1.1x |
| syscall | lps | 3,357,451 | 190,423 | 900,513 | **4.7x** |
| spawn | lps | 10,191 | 3,336 | 3,427 | ~same |
| execl | lps | 13,574 | 1,171 | 1,252 | ~same |
| context1 | lps | 935,063 | 47,516 | 64,211 | 1.4x |
| fstime | KBps | 634,676 | 92,530 | 132,581 | 1.4x |
| shell1 | lpm | 558 | 65 | 69 | ~same |
| shell8 | lpm | 302 | 29 | 30 | ~same |

The `syscall` benchmark (a tight `getpid()` loop) improved **4.7x**
because getpid is now micro-local — zero ring-buffer round-trips. The
remaining gap to native (0.27x) is the cost of the binary rewriting
trampoline (JMP to stub + register save/restore + match check + JMP back)
versus a bare `syscall` instruction.

`context1` and `fstime` improved ~1.4x because their inner loops include
micro-local syscalls (pipe read/write still goes through central, but
clock_gettime and close are fast-pathed or were already local).

The other benchmarks show negligible change because their bottleneck is
not in micro-local syscalls — `pipe` is dominated by read/write
round-trips, `spawn`/`execl` by fork/exec overhead, and `shell1`/`shell8`
by the combination of all costs.

### Functional Coverage

Micro-LiteBox runs all 10 UnixBench benchmarks without modifying the
benchmark source code. This required implementing:

- Fork with fd inheritance (parent's virtual fd table duplicated to child)
- In-process execve (ELF loading via shared memory)
- Shebang (`#!`) support for shell script execution
- Concurrent filesystem access (independent lower-layer fds per open)
- Dual-dispatch for fds that may be virtual (shim) or real (OS pipes)
- Shell packaging (rewriting /bin/sh and system utilities)

The single-process runner handles 6 of 10 benchmarks; the remaining 4
require fork, which only the micro architecture supports.

## Comparison with LiteShield

LiteShield (USENIX ATC '25, Manakkal et al.) is a userspace isolation
architecture for secure containers that decouples guest kernel functionality
into modular userspace microkernel (µkernel) services. Both micro-LiteBox
and LiteShield share the same fundamental insight — serve most syscalls in
userspace via shared-memory IPC between guest and service processes — but
differ significantly in goals, mechanisms, and trade-offs.

### Architectural Comparison

| Dimension | Micro-LiteBox | LiteShield |
|---|---|---|
| **Goal** | Sandboxed execution of individual binaries | Secure multi-tenant container isolation |
| **Language** | Rust (~20K LOC across crates) | C/C++ (~7K LOC) |
| **Service topology** | Single central process (one server thread per guest process) | Multiple composable µkernel service processes |
| **Syscall interception** | Offline binary rewriting (packager) | Runtime injection (LD_PRELOAD + libsyscall_intercept) |
| **Static binary support** | Native (syscall instructions rewritten at packaging time) | Not supported (LD_PRELOAD bypass); "hotpatching" noted as future work |
| **Direct syscall blocking** | Binary rewriting (removes syscall instructions) + static seccomp whitelist | seccomp blocks all direct syscalls from guest |
| **Non-delegable syscalls** | Central authorizes, micro executes locally (EXEC_LOCAL flag) | ptrace-based arbitration (15–35µs overhead per call) |
| **IPC mechanism** | Shared-memory ring buffer (SQ/CQ, 128B/32B entries) with futex-based adaptive wait | Shared-memory buffer with dedicated polling threads on separate cores |
| **IPC wake strategy** | 3-phase adaptive: 200 busy spins → exponential backoff → futex sleep | Continuous polling (dedicated core per direction) |
| **Filesystem** | Layered: tar read-only lower + in-memory writable upper | Userspace ext2-like filesystem (persistent, disk-backed) |
| **Networking** | Host passthrough (real OS fds for pipes/sockets) | Integrated f-stack (DPDK-based userspace network stack) |
| **Fork handling** | New shmem region + shim task fork + server thread spawn | Classified as non-delegable; runs in guest process, monitored via ptrace |
| **Execve handling** | In-process: central loads ELF, packs segments to shmem, guest remaps with MAP_FIXED | Standard execve (new process inherits seccomp + LD_PRELOAD) |
| **Host interface** | Static seccomp whitelist on guest; central makes host syscalls on behalf of guest | 22 syscalls (explicit thin interface, comparable to VM hypercalls) |

### Syscall Interception

**LiteShield** uses `LD_PRELOAD` combined with `libsyscall_intercept` to
hook syscalls at runtime. This is transparent and requires no binary
modifications, but has a fundamental limitation: statically linked binaries
(or those with inline `syscall` instructions) bypass the interception
library entirely. LiteShield relies on `seccomp` as a safety net — any
direct syscall from the guest is killed. The authors acknowledge this gap
and mention "hotpatching" (runtime binary rewriting of `syscall`
instructions) as future work.

**Micro-LiteBox** takes the opposite approach: an offline packager
(`litebox_packager`) scans ELF `.text` sections for `syscall` and
`int 0x80` instructions and replaces each with a `JMP` to a trampoline
stub. This handles both dynamically and statically linked binaries
uniformly. No `seccomp` is needed because no `syscall` instructions remain
in the guest code. The trade-off is that every binary must be packaged
before execution, and any `syscall` instruction generated dynamically (e.g.,
JIT compilers emitting syscall instructions) would bypass interception.

### Non-Delegable Syscall Handling

Both systems must handle syscalls that cannot be delegated to an external
process — `mmap`, `mprotect`, `fork`, `brk`, signals, etc. — because they
operate on the calling process's own address space or process state.

**LiteShield** uses Linux's `ptrace` mechanism: the guest is registered as
a tracee of the core µkernel service, and non-delegable syscalls are
trapped, inspected, and allowed to proceed. This adds 15–35µs per
non-delegable syscall (Table 1 in the paper: mmap 25µs, fork 36µs,
clock_nanosleep 23µs, futex 15µs). For lightweight syscalls like `mmap`
and `futex`, ptrace overhead dominates (99% and 98% overhead
respectively).

**Micro-LiteBox** avoids ptrace entirely. When central determines a
syscall needs local execution (via the `needs_local_exec` predicate), it
returns an `EXEC_LOCAL` flag in the CQ entry. Micro then performs the real
syscall in the guest's address space and reports the result back to central
via `MSG_LOCAL_RESULT`. The overhead is a shared-memory round-trip
(~microseconds, dominated by two futex wake/sleep pairs), but the actual
syscall executes without any ptrace interposition. Additionally, the
**micro-local fast-path** allows ~30 stateless syscalls to execute without
any central round-trip at all — the trampoline recognizes them and issues
the raw syscall directly.

### IPC Performance Model

**LiteShield** dedicates polling threads on separate cores for IPC — one
in the guest process polling for responses, one in the µkernel service
polling for requests. This achieves low, predictable latency (cache-to-cache
transfers, tens of CPU cycles) but at the cost of consuming entire cores for
polling. Their getpid latency (Figure 4a) is competitive with native.

**Micro-LiteBox** uses a futex-based adaptive wait: 200 busy spins,
exponential backoff, then futex sleep. This is core-efficient (no dedicated
polling cores) but adds latency when the peer isn't spinning — the worst
case requires a kernel futex wake transition. The UnixBench `syscall`
benchmark (getpid loop) shows micro-LiteBox at 5.6% of native throughput,
reflecting the cost of two futex round-trips per syscall. LiteShield's
polling approach would likely perform better on this microbenchmark but
at the cost of dedicating cores to polling.

The fundamental trade-off: LiteShield trades CPU cores for latency;
micro-LiteBox trades latency for CPU efficiency.

### Filesystem Design

**LiteShield** implements a persistent userspace ext2-like filesystem,
backed by real disk storage. This enables realistic workloads (fio, Redis
persistence) and achieves performance competitive with native ext4 — and
sometimes better, because the userspace filesystem eliminates
kernel-crossing overhead and double caching. LiteShield also integrates
f-stack (DPDK) for userspace networking, enabling end-to-end userspace I/O.

**Micro-LiteBox** uses a layered filesystem: a tar read-only lower layer
(from the packager) and an in-memory writable upper layer. Files opened
from the lower layer get independent descriptors per `open()` call (copy on
read for seek position isolation). Writes trigger copy-on-write migration to
the upper layer. This is simple and fast for benchmarking (the single-process
runner achieves 4.8x native on `fstime` because writes are pure memory
operations) but not persistent — all state is lost when the process exits.
The micro architecture adds shmem round-trip overhead for every filesystem
operation, bringing `fstime` to 15% of native.

### Fork and Process Management

**LiteShield** classifies `fork` as non-delegable — it must execute in
the guest's address space (you can't fork a different process). Fork is
monitored via ptrace: the core µkernel service traps the fork syscall,
performs validation, and allows it to proceed. The child inherits the
parent's seccomp profile and LD_PRELOAD library, so interception continues
automatically. The ptrace overhead for fork is 36µs (Table 1), which is
modest relative to fork's inherent cost (~41µs native).

**Micro-LiteBox** implements fork as a coordinated multi-step operation:
central creates a new `memfd`-backed shared memory region, forks the shim
task (duplicating the virtual fd table and cwd), and spawns a new server
thread. Then micro opens the child's shmem fd, performs a real `fork()`,
and the child unmaps the parent's ring, maps its own, and signals readiness.
This is more complex but enables central to maintain accurate state for each
child process independently. The UnixBench `spawn` benchmark shows 32% of
native throughput, with the overhead dominated by shmem allocation and
server thread creation rather than any ptrace tax.

### Execve

**LiteShield** handles `execve` naturally: the new process image inherits
the seccomp profile and LD_PRELOAD environment, so interception restarts
automatically. There's minimal additional mechanism required.

**Micro-LiteBox** must perform in-process execve because `syscall`
instructions have been physically rewritten — a real `execve` would load
an unmodified binary without trampoline hooks. Instead, micro serializes
the path/argv/envp into shmem, central loads the new (packaged) ELF and
packs its PT_LOAD segments into the data region, and micro remaps them with
`MAP_FIXED` over the old guest code, patches trampoline entry points, and
jumps to the new entry point. This is significantly more complex but handles
static binaries that LiteShield cannot intercept at all.

### Security Model

**LiteShield** provides a formally analyzed thin user-to-host interface
(22 syscalls), comparable to VM hypercall surfaces. seccomp enforces this
at the kernel level — even if the interception library is bypassed, the
guest process cannot make unauthorized syscalls. Defense-in-depth: even
exploiting a µkernel service only grants access to a restricted userspace
process.

**Micro-LiteBox** employs defense-in-depth with two layers. The primary
layer is binary rewriting — `syscall` instructions are physically replaced
with JMPs to trampoline stubs, so the guest code contains no syscall
instructions. The secondary layer is a static seccomp filter applied to
the guest process that whitelists only the specific syscalls micro needs
to execute locally (mmap, munmap, mprotect, clock_gettime, futex, etc.)
and blocks everything else. This means even if the guest manages to emit
a raw `syscall` instruction (e.g., via JIT compilation or ROP gadgets),
seccomp will kill the process. The combination provides comparable
assurance to LiteShield's seccomp-only approach, with the binary rewriting
layer additionally preventing the guest from even attempting unauthorized
syscalls in the normal case.

### Summary of Trade-offs

| Trade-off | Micro-LiteBox advantage | LiteShield advantage |
|---|---|---|
| Static binaries | Full support via offline rewriting | Not supported (LD_PRELOAD bypass) |
| Dynamic binaries | Requires pre-packaging step | Transparent runtime injection |
| CPU efficiency | No dedicated polling cores | — |
| IPC latency | — | Polling achieves lower, more predictable latency |
| Non-delegable syscalls | No ptrace overhead (EXEC_LOCAL) | — |
| Host interface hardening | Binary rewriting + static seccomp (defense-in-depth) | Formally reduced to 22 syscalls via seccomp |
| Filesystem realism | — | Persistent ext2, disk-backed |
| Networking | — | Integrated userspace stack (f-stack/DPDK) |
| Composability | — | Modular µkernel services, independently deployable |
| Fork cost | Shmem allocation (~moderate) | ptrace monitoring (~low for fork specifically) |
| Implementation safety | Memory-safe Rust | C/C++ |
| Scope | Single-binary sandbox | Multi-tenant container isolation |

The systems are more complementary than competing. LiteShield targets
production container deployments where a thin, auditable host interface is
the primary security requirement and dedicated polling cores are acceptable.
Micro-LiteBox targets development and testing scenarios where running
unmodified binaries (including static ones) under controlled syscall
interception is the priority, and core efficiency matters more than raw
IPC latency.
