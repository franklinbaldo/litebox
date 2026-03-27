# Micro-LiteBox Design — Part 0: Overview

## Problem Statement

LiteBox cannot support `fork()` today. The core `GlobalState` structure
(at `litebox_shim_linux/src/lib.rs:1040`) contains `PageManager`,
`FutexManager`, `Network`, `Pipes`, and other components — all wrapped
in `Arc` with interior mutability locks. These structures cannot survive
process duplication because:

- `Arc` reference counts become invalid across process boundaries
- Lock state (Mutex/RwLock) cannot be shared between forked processes
- The platform layer (`LinuxUserland`) relies on TLS, signal alt stacks,
  and pthread handles that are non-forkable

The current `do_clone` implementation (`litebox_shim_linux/src/syscalls/process.rs:605`)
explicitly rejects fork (only CLONE_VM|CLONE_THREAD is supported).

## Solution: Split Architecture

Split LiteBox into two cooperating components:

```text
┌─────────────────────────────────────┐
│         Guest Process(es)           │
│  ┌───────────────────────────────┐  │
│  │       Micro-LiteBox           │  │
│  │  - Syscall interception       │  │
│  │  - Local exec (mmap, fork)    │  │
│  │  - Forkable state only        │  │
│  └──────────┬────────────────────┘  │
│             │ Shared-memory rings    │
│             │ (SQ/CQ io_uring-style) │
└─────────────┼───────────────────────┘
              │
┌─────────────┼───────────────────────┐
│  Central LiteBox (host process)      │
│  ┌──────────┴────────────────────┐  │
│  │  Full shim (reused handlers)  │  │
│  │  - File system operations     │  │
│  │  - Networking                 │  │
│  │  - Pipes, IPC                 │  │
│  │  - Process tree management    │  │
│  │  - Policy & authorization     │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
```

### Micro-LiteBox (`litebox_micro`)

A minimal, forkable in-process agent. Lives inside each guest process.
Intercepts syscalls via seccomp/SIGSYS, executes locally-authorized
operations (mmap, fork, clone), and forwards everything else to central
via shared-memory ring buffers.

**Key property**: All state is plain data — no Arc, no locks, no
cross-process references. Survives `fork()` cleanly.

### Central LiteBox (`litebox_central`)

A separate host process containing the full LiteBox shim. Manages complex
state (fd tables, network connections, pipes, page table metadata) on
behalf of all guest processes. One central process per guest application.

## Design Principles

1. **Central is the authority** — ALL syscalls, including locally-executed
   ones (mmap, fork), require central's authorization first. Micro-LiteBox
   is a local execution agent, not an independent policy maker.

2. **Result reporting** — Micro-LiteBox always reports the result of every
   local execution back to central, so central maintains accurate state.

3. **Forkability over performance** — Micro-LiteBox's state is designed
   for fork safety first. Performance optimizations (caching, batching)
   are layered on top without compromising forkability.

4. **Minimal refactoring** — Central reuses existing `litebox_shim_linux`
   syscall handlers. The change is in how requests arrive (ring buffer
   vs platform registers), not in how they're processed.

5. **Untrusted boundary** — Shared memory between micro and central is
   treated as an untrusted input boundary. Central validates everything.

## Syscall Split

| Category | Examples | Execution | Why |
|----------|----------|-----------|-----|
| Memory ops | mmap, munmap, mremap, mprotect, brk, madvise | Local (after central auth) | Must execute in guest address space |
| Fork/clone | fork, vfork, clone (without CLONE_VM) | Local (after central auth) | Must execute in guest process |
| Thread creation | clone (with CLONE_VM) | Local (after central auth) | Must execute in guest process |
| File I/O | open, read, write, close, stat | Remote (central) | Central owns fd table and host fds |
| Networking | socket, connect, bind, send, recv | Remote (central) | Central owns network state |
| Pipes/IPC | pipe, pipe2, dup, dup2 | Remote (central) | Central owns pipe endpoints |
| Signals | kill, sigaction, sigprocmask | Remote (central) | Central manages signal state |
| Process mgmt | wait, waitpid, exit | Remote (central) | Central manages process tree |
| Cached values | getpid, gettid, getuid, uname | Local (no round-trip) | Read-only, set by central at setup |

## New Crates

| Crate | Purpose |
|-------|---------|
| `litebox_ipc` | Ring buffer layout, SqEntry/CqEntry types, shared memory setup. Standalone — no LiteBox deps. |
| `litebox_micro` | In-process forkable agent, syscall interception, local execution. Depends on `litebox_ipc`. |
| `litebox_central` | Server binary hosting the full shim. Depends on `litebox_ipc`, `litebox_shim_linux`, `litebox`. |

## Document Index

- [Part 1: Ring Buffer IPC](2026-03-27-micro-litebox-01-ring-buffer-ipc.md)
- [Part 2: Micro-LiteBox Internals](2026-03-27-micro-litebox-02-micro-litebox.md)
- [Part 3: Fork Flow](2026-03-27-micro-litebox-03-fork-flow.md)
- [Part 4: Exec Flow](2026-03-27-micro-litebox-04-exec-flow.md)
- [Part 5: Concurrency](2026-03-27-micro-litebox-05-concurrency.md)
- [Part 6: Security](2026-03-27-micro-litebox-06-security.md)
- [Part 7: Central Refactoring](2026-03-27-micro-litebox-07-central-refactoring.md)
- [Part 8: Performance](2026-03-27-micro-litebox-08-performance.md)
