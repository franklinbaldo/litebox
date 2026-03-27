# Micro-LiteBox Design — Part 2: Micro-LiteBox Internals

## Role

Micro-LiteBox is the in-process agent that lives inside each guest
process. It intercepts syscalls, decides whether they need remote
authorization or can be served from cache, communicates with central
via shared-memory ring buffers, and executes locally-authorized
operations.

**Critical invariant**: All micro-LiteBox state is plain, forkable data.
No Arc, no Mutex, no cross-process references. When `fork()` duplicates
the process, micro-LiteBox's state is duplicated correctly by CoW.

## Components

```text
struct MicroLiteBox {
    /// Ring buffer handle (SQ + CQ + shared data)
    ring: RingHandle,

    /// Per-thread state (thread-local, not shared)
    thread_slot: u16,
    seq_counter: u64,

    /// Cached read-only values (set by central at setup)
    cached: CachedValues,

    /// Process identity (updated on fork)
    pid: u32,
    ppid: u32,
}

struct CachedValues {
    pid: u32,
    tid: u32,
    uid: u32,
    gid: u32,
    euid: u32,
    egid: u32,
    uname: UtsName,
    cwd: [u8; PATH_MAX],
    cwd_len: usize,
}
```

## What Micro-LiteBox Excludes

These components exist ONLY in central, never in micro:

- **PageManager** — page table metadata, VMA tracking
- **FutexManager** — futex wait queues (cross-process coordination)
- **Network** — socket state, connection tracking
- **Pipes** — pipe buffer management, reader/writer tracking
- **File descriptor table** — fd-to-file mappings, open file descriptions
- **Signal state** — signal dispositions, pending signal queues
- **Process tree** — parent-child relationships, zombie tracking

## Syscall Interception

Micro-LiteBox reuses the existing seccomp-based interception from
`litebox_platform_linux_userland/src/syscall_intercept/`. The SIGSYS
handler is modified to:

1. Check if the syscall is in the cached-values set → return immediately
2. Write an SqEntry to the ring buffer
3. Wait for the CqEntry response
4. If response says "execute locally" → perform the syscall and report
   result back
5. If response contains the result directly → return it to guest

```text
fn handle_syscall(regs: &PtRegs) -> i64 {
    let nr = regs.syscall_nr();

    // Fast path: cached read-only values
    if let Some(val) = check_cache(nr) {
        return val;
    }

    // Submit to central
    let seq = submit_request(nr, regs);

    // Wait for response
    let cq = wait_completion(seq);

    if cq.flags & FLAG_EXEC_LOCAL != 0 {
        // Central authorized local execution
        let result = execute_locally(nr, regs, &cq);
        // Report result back to central
        report_result(seq, result);
        result
    } else {
        // Central handled it remotely
        cq.result
    }
}
```

## Local Execution

When central authorizes local execution (for mmap, munmap, mremap,
mprotect, brk, madvise, fork, clone), micro-LiteBox executes the
actual host syscall in the guest's address space:

```text
fn execute_locally(nr: u32, regs: &PtRegs, auth: &CqEntry) -> i64 {
    match nr {
        SYS_mmap => {
            // Central may have adjusted parameters (e.g., forced MAP_FIXED)
            let addr = auth.args_override.unwrap_or(regs.arg0());
            let len = regs.arg1();
            let prot = regs.arg2();
            let flags = regs.arg3();
            // Execute real mmap in guest address space
            unsafe { libc::syscall(SYS_mmap, addr, len, prot, flags, -1, 0) }
        }
        SYS_clone => {
            // Fork: central has prepared child's ring buffer
            let child_pid = unsafe { libc::syscall(SYS_clone, SIGCHLD, 0, 0, 0, 0) };
            if child_pid == 0 {
                // In child: update local state
                post_fork_child(auth);
            }
            child_pid
        }
        // ... other locally-executed syscalls
    }
}
```

## Post-Fork Child Setup

After `fork()` returns in the child process:

```text
fn post_fork_child(auth: &CqEntry) {
    // 1. Update cached PID/PPID
    micro.pid = getpid_real();
    micro.ppid = auth.parent_pid;

    // 2. Map new ring buffer (fd provided by central in CQ)
    let new_ring_fd = auth.child_ring_fd;
    micro.ring = RingHandle::from_fd(new_ring_fd);

    // 3. Reset thread slot to 0 (child starts single-threaded)
    micro.thread_slot = 0;
    micro.seq_counter = 0;

    // 4. Send "child ready" message to central via new ring
    submit_child_ready();
}
```

## Thread Registration

When a new thread is created (clone with CLONE_VM), micro-LiteBox
registers it with central to get a thread slot assignment:

```text
fn register_thread() -> u16 {
    let seq = submit_request(MSG_THREAD_REGISTER, &[]);
    let cq = wait_completion(seq);
    cq.thread_slot  // Central assigns the slot
}
```

The thread slot determines:
- Which CQ notify futex to wait on (avoids thundering herd)
- Which bump-allocator region in shared data to use
- Thread identity for central's per-thread tracking

## State After Fork

```text
Parent process:               Child process:
┌─────────────────────┐       ┌─────────────────────┐
│ MicroLiteBox        │       │ MicroLiteBox (copy)  │
│  ring: parent_ring ─┼──X    │  ring: child_ring ──┼── new shared mem
│  pid: 100           │       │  pid: 101            │
│  thread_slot: 0     │       │  thread_slot: 0      │
│  cached: {...}      │       │  cached: {...}       │
└─────────────────────┘       └─────────────────────┘
         │                             │
    parent's SQ/CQ                child's SQ/CQ
         │                             │
    ┌────┴──────────────────────────────┴────┐
    │           Central LiteBox              │
    │  processes[100] ─── GlobalState(parent) │
    │  processes[101] ─── GlobalState(child)  │
    └────────────────────────────────────────┘
```

The parent's ring becomes invalid in the child (it's the parent's
shared memory mapping). The child must establish its own ring
connection to central before making any further syscalls.
