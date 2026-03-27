# Micro-LiteBox Design — Part 7: Central Refactoring

## New Crate Structure

Three new crates join the workspace:

| Crate | Purpose | Dependencies |
|-------|---------|-------------|
| `litebox_ipc` | Ring buffer layout, SqEntry/CqEntry types, shared memory setup | Standalone, no LiteBox deps |
| `litebox_micro` | In-process forkable agent, local syscall execution | `litebox_ipc` |
| `litebox_central` | Server binary hosting the full shim | `litebox_ipc`, `litebox_shim_linux`, `litebox` |

`litebox_ipc` is deliberately dependency-free (relative to LiteBox internals)
so both micro and central can link it without pulling in each other's world.

## SyscallRequest Abstraction

Today, shim syscall handlers receive arguments via platform registers (`PtRegs`).
Central receives them as deserialized `SqEntry` fields from the ring buffer.
To reuse existing handlers with minimal changes:

```text
enum SyscallSource {
    /// In-process (legacy path, platform registers)
    Local { regs: PtRegs },
    /// Remote from ring buffer
    Remote { entry: SqEntry, process: Pid },
}
```

Each handler extracts arguments from `SyscallSource` instead of reading
`PtRegs` directly. A thin adapter layer converts between the two:

- `SyscallSource::arg0(&self) -> u64` — returns register a0 or entry.args[0]
- `SyscallSource::arg1(&self) -> u64` — returns register a1 or entry.args[1]
- ...up to arg5

This keeps handler bodies unchanged. Only the argument extraction preamble
is swapped out.

## Per-Process GlobalState

Central maintains process-scoped state:

```text
struct CentralState {
    /// One GlobalState per guest process
    processes: HashMap<Pid, ProcessContext>,
    /// Parent-child relationships
    process_tree: ProcessTree,
}

struct ProcessContext {
    global_state: Arc<GlobalState>,
    task: Task,
    ring: RingHandle,         // SQ/CQ for this process
    shared_region: SharedMem, // Data region for this process
}
```

On fork:
1. Clone parent's `GlobalState` (deep copy of page table metadata, fd table,
   signal dispositions — but NOT the actual memory pages, which are CoW in
   the kernel)
2. Allocate new ring buffer pair for the child
3. Register child in process tree
4. Create new `ProcessContext` for child PID

On exec:
1. Reset the process's `GlobalState` to fresh defaults
2. Preserve fd table (close-on-exec honored)
3. Reuse existing ring buffer (no reallocation needed)

## Process Tree Manager

```text
struct ProcessTree {
    parent: HashMap<Pid, Pid>,
    children: HashMap<Pid, Vec<Pid>>,
    zombies: HashSet<Pid>,
    exit_status: HashMap<Pid, i32>,
}
```

Responsibilities:
- **wait/waitpid**: When a parent calls wait, central checks zombies set.
  If no zombie child matches, the parent's CQ entry is deferred until a
  child exits.
- **Zombie reaping**: When a child exits, it enters zombie state. Central
  stores exit status and notifies parent (if parent is blocked in wait).
- **Orphan reparenting**: If a parent exits before children, children are
  reparented to PID 1 (or central handles them directly).
- **Signal forwarding**: SIGCHLD delivered to parent's signal queue when
  child state changes.

## Ring Buffer Server Loop

Central runs one worker thread per guest process (simple 1:1 model):

```text
fn serve_process(ctx: &mut ProcessContext) {
    loop {
        // 1. Spin briefly checking SQ head != tail
        let entry = spin_then_wait(&ctx.ring.sq);

        // 2. Validate entry (untrusted input!)
        let request = validate_sq_entry(entry, &ctx.shared_region)?;

        // 3. Dispatch to existing shim handler
        let source = SyscallSource::Remote {
            entry,
            process: ctx.task.pid(),
        };
        let result = dispatch_syscall(source, &ctx.global_state, &ctx.task);

        // 4. Write completion
        ctx.ring.cq.push(CqEntry {
            seq: entry.seq,
            result,
            flags: 0,
        });

        // 5. Wake the guest thread (futex on CQ notify slot)
        futex_wake(&ctx.ring.cq.notify_slots[entry.thread_slot]);
    }
}
```

Future optimization: thread pool with work-stealing across processes.
Initial 1:1 model is simple and avoids lock contention on GlobalState.

## Platform Adaptation

Central does NOT use `LinuxUserland` (that's the in-process platform for
guest context switching, TLS, signal trampolines, etc.).

Instead, central uses a `CentralPlatform` that:
- Executes host syscalls directly (open, read, write, socket, etc.)
  on behalf of guest processes
- Manages file descriptors in its own process (guest fds map to real
  host fds tracked in GlobalState's fd table)
- Performs network operations using host kernel's network stack
- Handles pipe operations between guest processes (both endpoints
  are in central's fd table)

The `CentralPlatform` is simpler than `LinuxUserland` because it doesn't
need TLS swapping, signal alt stacks, or syscall interception — it IS the
host process making real syscalls.

## Migration Path

1. **Phase 1**: Extract `SyscallSource` abstraction in `litebox_shim_linux`
   (backward compatible — `Local` variant is default)
2. **Phase 2**: Build `litebox_ipc` crate with ring buffer types
3. **Phase 3**: Build `litebox_central` using existing shim + new
   SyscallSource::Remote path
4. **Phase 4**: Build `litebox_micro` as the in-process agent
5. **Phase 5**: Integration testing with fork-heavy workloads
