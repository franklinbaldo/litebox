# Forker Process Design — Eliminating execve/openat from Fork-Restore

## Problem

When a guest process calls `fork()` without immediately calling `exec()` (the "slow path"), litebox's fork-restore mechanism spawns a new OS process via `posix_spawn("/proc/self/exe", "--fork-restore", ...)`. This re-invokes the entire runner binary, which causes the new process to execute:

- `execve` — loads the runner binary from disk
- Dynamic linker syscalls — `openat("/etc/ld.so.cache")`, `openat("libc.so.6")`, `mmap`, `mprotect`, `arch_prctl(SET_FS)`, `brk`
- Rust runtime init — `getrandom`, `sigaction(SIGPIPE)`, `prlimit64`, `rseq`, `set_tid_address`
- Platform re-init — `openat("/proc/self/maps")` (twice), `openat("/dev/null")`, `sched_getaffinity`
- Broker reconnection — `socket(AF_UNIX)`, `connect("/tmp/litebox-broker.sock")`, LBNP handshake
- Tar reload — `openat("/tmp/file.tar")`, `mmap`
- 9P channel setup — `memfd_create` x2, `socket(AF_UNIX)`, `connect`, `sendmsg(SCM_RIGHTS)`

These are real host kernel syscalls. A guest exploit that escapes the virtual syscall layer could use `execve` to run a real binary, `openat` to read host files, or `socket`+`connect` to make real network connections. A tight seccomp policy should forbid all of them — but the current fork-restore path requires them.

## Solution: The Forker Process

Replace `posix_spawn` + `execve` with a dedicated **forker process** that stays single-threaded and forks workers on demand.

### Architecture

```
                    ┌──────────────────┐
                    │     Runner       │
                    │  (multi-threaded) │
                    │                  │
                    │  guest threads   │
                    │  net worker      │
                    │  9P worker       │
                    └──────┬───────────┘
                           │ Unix socketpair
                           │ (commands + SCM_RIGHTS)
                    ┌──────▼───────────┐
                    │     Forker       │
                    │ (single-threaded) │
                    │                  │
                    │  Inherits:       │
                    │  - tar mmap      │
                    │  - signal hdlrs  │
                    │  - platform      │
                    │  - /dev/null fd  │
                    └──────┬───────────┘
                           │ double-fork on demand
              ┌────────────┼────────────┐
              ▼            ▼            ▼
         ┌─────────┐ ┌─────────┐ ┌─────────┐
         │ Worker 1 │ │ Worker 2 │ │ Worker N │
         └─────────┘ └─────────┘ └─────────┘
```

### Lifecycle

1. Runner starts, completes all init while single-threaded: platform creation, broker connection, tar mmap, signal handlers, filesystem setup.
2. Runner pre-opens `/dev/null`, calls `prctl(PR_SET_CHILD_SUBREAPER, 1)`, creates a `socketpair(AF_UNIX)`, and `fork()`s the forker process.
3. Forker closes the runner's socketpair end and the broker socket (it doesn't use it). Enters its main loop.
4. Runner continues: starts threads (network worker, 9P worker), loads guest, runs.
5. On `commit_delayed_fork`: runner builds the snapshot, pre-creates all fds the worker will need (broker connection, 9P channel, pipes), sends a `ForkRequest` + `SCM_RIGHTS` to the forker.
6. Forker receives the request, double-forks a worker, sends back the child PID.
7. Worker restores guest state from the inherited snapshot memfd, acks, runs.

## Detailed Design

### Runner Startup Sequence (Modified)

The runner's init sequence gains three new steps between platform setup and thread spawning:

```
 1. Parse CLI args
 2. mmap program binary
 3. mmap tar file
 4. Create platform (signal handlers, /proc/self/maps, address spaces)
 5. Connect to broker (socket + connect + handshake)
 6. Register CoW regions, set global platform
 7. Register worker spawn flags
 ── NEW ──────────────────────────────────────────
 8. Pre-open /dev/null
 9. prctl(PR_SET_CHILD_SUBREAPER, 1)
10. socketpair(AF_UNIX) → (runner_sock, forker_sock)
11. fork() → forker process
    Forker: close(runner_sock), close(broker_fd), enter forker_main()
    Runner: close(forker_sock), store runner_sock as ForkerHandle
 ── END NEW ──────────────────────────────────────
12. Build shim + filesystem
13. Start network worker thread       ← first thread
14. Start 9P worker thread (if 9P)
15. Load guest program
16. Run guest
```

Steps 8-11 happen while the runner is still single-threaded, making `fork()` safe (no pthread mutex deadlock risk).

### Forker Process

The forker is a minimal event loop:

```rust
fn forker_main(cmd_sock: RawFd, dev_null_fd: RawFd) -> ! {
    loop {
        // 1. Block waiting for a ForkRequest + SCM_RIGHTS fds
        let (req, fds) = recv_fork_request(cmd_sock);

        // 2. Double-fork to produce a worker re-parented to the runner
        match fork() {
            Ok(0) => {
                // Intermediate child
                match fork() {
                    Ok(0) => {
                        // Worker (grandchild)
                        close(cmd_sock);
                        worker_main(req, fds, dev_null_fd);
                        // never returns
                    }
                    Ok(grandchild_pid) => {
                        // Send grandchild PID to forker via inherited pipe,
                        // then exit immediately.
                        write(pid_pipe_wr, &grandchild_pid);
                        _exit(0);
                    }
                    Err(_) => _exit(1),
                }
            }
            Ok(intermediate_pid) => {
                // Forker: reap intermediate child
                waitpid(intermediate_pid, 0);
                let grandchild_pid = read(pid_pipe_rd);
                // Close all fds that belong to the worker
                close_worker_fds(&fds);
                // Send response
                send_fork_response(cmd_sock, grandchild_pid);
            }
            Err(e) => {
                close_worker_fds(&fds);
                send_fork_error(cmd_sock, e);
            }
        }
    }
}
```

Properties:
- **Always single-threaded.** Never calls `exec`, never creates threads. Safe to `fork()` indefinitely.
- **Minimal fd table.** Holds only: `cmd_sock`, `dev_null_fd`, and the inherited tar mmap (which has no fd — the `File` was closed after mmap).
- **No broker socket.** Closed during init. Workers get their own connections via `SCM_RIGHTS`.

### Double-Fork and Worker Re-parenting

Workers must be `waitpid`-able by the runner (the existing `wait_worker_host` at platform `lib.rs:2007` uses `waitpid`). Since the forker is the direct parent of workers, the runner cannot `waitpid` them.

Solution: **double-fork + `PR_SET_CHILD_SUBREAPER`**.

1. Runner calls `prctl(PR_SET_CHILD_SUBREAPER, 1)` before forking the forker.
2. Forker does `fork()` → intermediate child → `fork()` → worker.
3. Intermediate child exits immediately.
4. Worker's parent (the intermediate child) is dead, so the worker re-parents to the nearest subreaper — the runner.
5. Runner can `waitpid(worker_pid)` as before.

Cost: one extra `fork()` + `_exit()` + `waitpid()` per fork-restore. Negligible.

### ForkRequest Protocol

Communication over the Unix socketpair uses `sendmsg`/`recvmsg` with `SCM_RIGHTS` for fd passing.

**ForkRequest** (runner → forker):

Message body (structured, serialized):
- Stdio binding descriptors: which passed fds map to stdin/stdout/stderr, which get `/dev/null`
- Mux stream specs: `(stream_id, guest_fd, direction, flags)` per stream
- Pipe bridge specs: `(guest_fd, direction, pair_id)` per bridge
- Local pipe specs: `(guest_fd_pair, drain_data_offset, drain_data_len)` per local pipe
- 9P spec: which fds in the SCM_RIGHTS array are the 9P memfds and broker socket

SCM_RIGHTS ancillary data (fd array):
- `snapshot_fd` — memfd with serialized `ForkSnapshot`
- `ack_write_fd` — write end of ack pipe
- `result_write_fd` — write end of result pipe
- `broker_fd` — pre-connected broker socket for this worker
- `9p_memfd_1`, `9p_memfd_2` — pre-created shared-memory ring memfds
- `mux_fd` — socketpair end for multiplexed I/O (if applicable)
- Pipe bridge host fds
- Local pipe drain memfds

**ForkResponse** (forker → runner):

Message body:
- `child_pid: i32` — the worker's PID (grandchild), or negative errno on error

### Worker Child — What Changes

The current `run_fork_restore()` (runner `lib.rs:988`) does full startup:

```
Current fork-restore child:          New worker child:

execve(runner binary)                (doesn't exist)
  dynamic linker loads libc
  Rust runtime init
  parse CLI args
  read snapshot from memfd           read snapshot from memfd ✓
  create platform  ← REAL SYSCALLS   inherited from forker ✓
    sigaction × 8
    open(/proc/self/maps)
    read, close
  connect to broker ← REAL SYSCALLS  inherited fd via SCM_RIGHTS ✓
    socket(AF_UNIX)
    connect(broker.sock)
    sendto/recvfrom (handshake)
  build filesystem                   build from inherited tar mmap ✓
    (virtual, no real syscalls)
  open tar file ← REAL SYSCALL       inherited mmap ✓
  setup 9P channel ← REAL SYSCALLS   inherited fds via SCM_RIGHTS ✓
    memfd_create × 2
    socket(AF_UNIX)
    connect(broker.sock)
    sendmsg(SCM_RIGHTS)
  spawn 9P worker thread             spawn 9P worker thread (same)
  restore_process (virtual)          restore_process (virtual, same)
  install pipes (same)               install pipes (same)
  ack (write to ack_fd)              ack (same)
  run_program                        run_program (same)
```

The worker entry point:

```rust
fn worker_main(req: ForkRequest, fds: &[RawFd], dev_null_fd: RawFd) -> ! {
    // 1. Wire stdio (dup2 from passed fds, /dev/null for mux slots)
    wire_stdio(&req.stdio_bindings, fds, dev_null_fd);

    // 2. Read snapshot from inherited memfd
    let snapshot = read_fork_snapshot_from_fd(fds[req.snapshot_fd_idx]);

    // 3. Platform: grab the inherited global ref
    let platform = litebox_platform_multiplex::get_platform();

    // 4. Build filesystem from inherited tar mmap (virtual, no syscalls)
    let (in_mem, tar_ro) = build_initial_fs(platform, &snapshot);

    // 5. Setup 9P from inherited fds (mmap the memfds, spawn response thread)
    let nine_p_fs = setup_nine_p_from_fds(fds, &req.nine_p_spec);

    // 6. Build shim (virtual, just data structures)
    let shim = build_shim(platform, in_mem, tar_ro, nine_p_fs);

    // 7. fork_restore_and_ack — unchanged
    let (program, _) = fork_restore_and_ack(&shim, snapshot, ...);

    // 8. run_program — unchanged
    run_program(program);
}
```

### Inherited State Detail

What the forker inherits from the runner at fork time, and what workers inherit from the forker:

| State | Forker inherits? | Worker inherits? | Notes |
|-------|-------------------|-------------------|-------|
| Tar mmap (`'static` leaked) | Yes | Yes | Read-only, no fd (File closed after mmap) |
| Signal handlers (SIGSEGV etc.) | Yes | Yes | Process-wide, work correctly in workers |
| Platform struct (`'static` leaked) | Yes | Yes | Mutexes clean (no threads at fork time) |
| `/proc/self/maps` cache | Yes | Yes | Read-only after init |
| Address space manager | Yes | Yes | Worker allocates its own VA partition |
| Broker socket | Closed by forker | No | Worker gets its own via SCM_RIGHTS |
| `/dev/null` fd | Yes | Yes | Pre-opened in runner before fork |
| CoW region metadata | Yes | Yes | Read-only `BTreeMap` |
| Worker spawn flags | Yes | Yes | Read-only after init |

### Signal Handlers in the Forker

The runner installs handlers for SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGTRAP (exception) and SIGINT, SIGALRM (interrupt). The forker inherits them.

This is safe:
- The forker never touches guest memory, so VA-fault handlers won't fire.
- Exception handlers check thread-local guest state. In the forker, there's no guest TLS, so a fault would be treated as a host crash — correct behavior.
- Workers inherit the handlers from the forker. Once the worker sets up guest state, the handlers work correctly (same as current fork-restore children).

### Pthread Mutex Safety

The forker is forked while the runner is single-threaded. All mutexes (platform address space manager, worker process registry, etc.) are unlocked at fork time. The forker inherits clean mutex state. Workers inherit clean mutex state from the forker (also single-threaded). No deadlock risk.

## Seccomp Payoff

### Eliminated Syscalls

These syscalls are removed from the fork-restore worker's real syscall surface:

| Syscall | Current fork-restore | New worker |
|---------|---------------------|------------|
| `execve` / `execveat` | Yes | **Eliminated** |
| `openat` (ld.so.cache, libc, /proc/self/maps, tar, /dev/null) | Yes (6+ calls) | **Eliminated** |
| `socket` + `connect` (broker) | Yes | **Eliminated** |
| `memfd_create` (9P rings) | Yes | **Eliminated** |
| `brk` (libc init) | Yes | **Eliminated** |
| `arch_prctl` (TLS setup) | Yes | **Eliminated** |
| `getrandom` (Rust init) | Yes | **Eliminated** |
| `prlimit64`, `rseq`, `set_tid_address` (libc init) | Yes | **Eliminated** |

### Remaining Syscalls in Workers

After the forker design, the worker's real syscall surface is:

- `dup2`, `close` — stdio wiring and fd cleanup
- `read`, `write` — snapshot read, ack write
- `mmap`, `mprotect`, `munmap` — guest memory restore at fixed VA addresses
- `clone3` — 9P response worker thread
- `rt_sigaction` — may need minor adjustment (likely inherited)
- `recvfrom`, `sendto`, `ppoll` — network worker steady-state loop
- `recvmsg`, `sendmsg` — 9P worker
- `sigreturn`, `rt_sigreturn` — signal return

### Forker Syscall Surface

The forker's allowlist is minimal:

- `recvmsg` — receive ForkRequest
- `clone` — fork()
- `waitpid` / `wait4` — reap intermediate child
- `read`, `write` — pid pipe for double-fork
- `close` — cleanup worker fds in parent
- `sendmsg` — send ForkResponse
- `exit_group` — shutdown
- `sigreturn`, `rt_sigreturn` — signal return

### Security Impact

An attacker who achieves code execution inside the guest and escapes the virtual syscall layer would hit seccomp. They cannot:
- `execve` a real binary (not in allowlist)
- `openat` real host files (not in allowlist)
- `socket` + `connect` to make real network connections (not in allowlist)

The attack surface is reduced to memory-management syscalls (`mmap`, `mprotect`) and the network worker's `recvfrom`/`sendto` on an already-connected fd.

## Error Handling

### Forker Death

If the forker crashes or exits, the runner detects it when `sendmsg` returns `EPIPE` or `recvmsg` returns 0. The runner falls back to the current `posix_spawn` path. This makes the forker a pure optimization and security hardening — not a correctness requirement. A config flag can enable strict mode (refuse to fork on forker death) for production.

### Fork Failure

If `fork()` in the forker fails (`ENOMEM`, `EAGAIN`), the forker closes all received fds and sends a `ForkResponse` with a negative errno. The runner propagates the error to the guest as `fork()` returning `-ENOMEM`.

### Fd Leak Prevention

The forker must close all SCM_RIGHTS fds on every error path (fork failure, request parse error, etc.) before looping back. The cleanup path iterates the received fd array and closes each one.

### Concurrent Fork Requests

The forker is single-threaded and handles one request at a time. The runner serializes access to the forker socketpair via a `Mutex<ForkerHandle>` in the platform struct. This is natural — `commit_delayed_fork` already parks sibling threads, so concurrency is limited. If two independent guest processes fork simultaneously, the mutex serializes them.

## Files to Modify

### New Code

- `litebox_platform_linux_userland/src/forker.rs` — Forker process main loop, ForkRequest/ForkResponse protocol, worker entry point
- `litebox_platform_linux_userland/src/forker_protocol.rs` — Message serialization, SCM_RIGHTS helpers

### Modified Code

- `litebox_platform_linux_userland/src/lib.rs`
  - `Platform::with_network()`: add forker spawn after platform init
  - `spawn_worker_host_for_fork_restore()`: replace `posix_spawn` with `sendmsg` to forker, `recvmsg` response; keep as fallback if forker is dead
  - Add `ForkerHandle` struct (socketpair fd + mutex)
  - Add `pre_create_broker_connection()` and `pre_create_nine_p_channel()` helpers

- `litebox_runner_linux_userland/src/lib.rs`
  - `run()`: add `prctl(PR_SET_CHILD_SUBREAPER)`, `/dev/null` pre-open, socketpair, fork before thread spawning
  - Add `worker_main()` entry point (lighter than `run_fork_restore`)
  - `run_fork_restore()`: keep as fallback path

- `litebox_shim_linux/src/syscalls/process.rs`
  - `commit_delayed_fork()`: the snapshot and pipe-bridging logic is unchanged. Only the final `platform.spawn_worker_host_for_fork_restore()` call changes, and that's inside the platform layer.

## Non-Goals

- **Seccomp policy implementation.** This design enables tight seccomp policies but does not implement them. That is a separate task.
- **Broker seccomp hardening.** The broker runs trusted code and handles adversarial network input, but seccomp for it is lower priority.
- **Worker pool / pre-fork N workers.** The forker forks on demand. No pool sizing, no replenishment logic.
- **Copy-on-write memory snapshots.** The snapshot remains a full memcpy. CoW optimization is orthogonal.
