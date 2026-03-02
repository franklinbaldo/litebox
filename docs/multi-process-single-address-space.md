# Design: Multi-Process Support (Single Address Space)

## 1. Problem Statement

LiteBox currently operates as a **single-process** library OS. Each LiteBox
instance manages one process worth of resources: one address space, one FD
table, one futex namespace, one network stack. The Linux shim supports
`clone()` for creating threads (with `CLONE_VM | CLONE_THREAD | CLONE_SIGHAND
| CLONE_FILES`), but multi-process support (`fork()`, `execve()`, `waitpid()`)
is limited. Many real-world Linux programs — shells, build systems, server
daemons, test harnesses — require multi-process support to function.

### Goal

Enable LiteBox to run multi-process Linux programs by:

1. Supporting `fork()` + `execve()` to spawn child processes.
2. Running multiple guest processes **in a single host address space** on
   userland platforms (linux_userland, windows_userland).
3. Running multiple guest processes in **separate address spaces** on kernel
   platforms (LVBS, linux_kernel/SNP) using hardware page table isolation.
4. Providing a platform-agnostic process abstraction in core that both Linux
   and OP-TEE shims can use.
5. Handling process lifecycle correctly: exit, waitpid, signals, process
   groups.

### Assumptions

- **PIE-only binaries.** We only support position-independent executables on
  userland platforms. This eliminates VA-collision problems, since PIE
  binaries can be loaded at any base address. On kernel platforms (separate
  address spaces), `ET_EXEC` (non-PIE) binaries work normally. On userland,
  `execve()` of an `ET_EXEC` binary whose load address falls outside the
  process's VA partition returns `ENOEXEC`.
- **Same trust boundary.** Guest processes are from the same trust boundary,
  so intra-process memory isolation is a non-goal. On userland platforms,
  processes may access each other's memory.
- **Userland: single address space.** On userland platforms, all guest
  processes share one host address space. Each process gets a non-overlapping
  VA range partition.
- **Kernel: separate address spaces.** On kernel platforms, each guest process
  gets its own page tables with hardware-enforced isolation.

### Scope

This design applies to all platforms. The core abstractions are
platform-agnostic. The address space management strategy differs by platform
type (single vs. separate address spaces), abstracted behind a new
`AddressSpaceProvider` trait.

---

## 2. Architecture

### 2.1 Linux Kernel–Inspired Resource Model

The design borrows Linux's per-process resource model. In Linux,
`task_struct` holds **pointers to independently reference-counted** structs:

| Resource | Linux struct | Sharing behavior |
|---|---|---|
| FD table | `files_struct` | `CLONE_FILES` → share; fork → copy |
| Address space | `mm_struct` | `CLONE_VM` → share; fork → COW copy |
| Signal handlers | `sighand_struct` | `CLONE_SIGHAND` → share; fork → copy |
| cwd/root/umask | `fs_struct` | `CLONE_FS` → share; fork → copy |

Each struct has its own refcount. `clone()` flags control share-vs-copy.
This unifies threads and processes:

- **Thread** = `clone` with everything shared
- **Fork** = `clone` with everything copied
- Anything in between is valid

### 2.2 LiteBox Resource Model

Applying this pattern to LiteBox:

```
┌───────────────────────────────────────────────────────────┐
│           LiteBox<Platform>  (singleton "kernel")         │
│  Global shared subsystems                                 │
│                                                           │
│  • Descriptors<Platform>  (open-file-object registry)     │
│  • Filesystem (VFS equivalent)                            │
│  • Network stack                                          │
│  • Pipe registry                                          │
│  • Futex manager                                          │
│  • ProcessRegistry                                        │
└──────────┬──────────────┬─────────────────────────────────┘
           │              │
    ┌──────┴───┐   ┌──────┴───┐
    │Process A │   │Process B │
    │          │   │          │
    │ Arc<FilesState>   │ Arc<FilesState>    ← per-process FD table
    │ Arc<PageManager>  │ Arc<PageManager>   ← fork: new; thread: shared
    │ Arc<SignalState>  │ Arc<SignalState>
    │ brk, pid, ...     │ brk, pid, ...
    └──────────┘   └──────────┘
```

**`LiteBox<Platform>`** = the kernel. **Exactly one instance** (singleton
assertion retained). Owns global subsystems (filesystem, network, pipes,
futexes, process registry) and the core open-file-object registry
(`Descriptors<Platform>`). Any process calls into it.

**Per-process resources** = `Arc`-wrapped, independently clonable. Each
process holds `Arc<FilesState>`, `Arc<PageManager>`, etc. The `clone()`
flags determine share-vs-copy per resource:

- `CLONE_FILES` → share `Arc<FilesState>`; no flag → clone the FD table
- `CLONE_VM` → share `Arc<PageManager>`; no flag → new PageManager (COW or fresh)
- `CLONE_SIGHAND` → share signal state; no flag → copy signal dispositions

This naturally supports the full `clone()` flag space without special cases.

### 2.3 Two-Layer File Descriptor Model

LiteBox has two independent descriptor layers, analogous to Linux's
separation between the file table (kernel-global, `struct file`) and the
FD table (per-process, `struct files_struct`):

**Core layer — `Descriptors<Platform>` (global, in `LiteBoxX`):**
- Typed, subsystem-generic open-file-object registry.
- Entries are `Arc`-wrapped (`DescriptorEntry`), supporting shared ownership.
- Subsystems (FS, network, pipes) register their open objects here.
- This layer stays in `LiteBox` — it is **not** per-process.

**Shim layer — `FilesState<FS>` (per-process):**
- Linux-style integer FD table mapping `fd: u32` → `Descriptor<FS>` enum
  variants (`LiteBoxRawFd`, `Eventfd`, `Epoll`, `Unix`).
- `RawDescriptorStorage` bridges shim FD integers to core `TypedFd` handles.
- Currently held via `RefCell<Arc<FilesState>>` in each `Task`. The
  `RefCell` wrapper is correct (single-thread-per-task invariant) and does
  not need changing.

**FD resolution path:**
`fd (u32)` → shim `Descriptor` → `RawDescriptorStorage` → core `TypedFd`
→ core `DescriptorEntry` (Arc-shared).

**Fork behavior:**
- On `fork()`: clone `FilesState` (new FD mapping). Both parent and child
  entries point to the **same** `Arc<DescriptorEntry>` in core — sharing
  file offsets and status flags, matching POSIX semantics.
- On `CLONE_FILES`: share the `Arc<FilesState>` (same FD table, like threads).
- On `execve()`: close FDs marked `O_CLOEXEC` in the process's `FilesState`.

**Required refactoring:** `Descriptor`, `Descriptors`, `RawDescriptorStorage`,
and `FilesState` must implement clone-for-fork semantics (sharing underlying
`Arc` file objects while copying the FD-number mapping and `close_on_exec`
flags).

### 2.4 Shared vs. Per-Process State

| Resource | Shared (in LiteBox) | Per-Process |
|---|---|---|
| Filesystem (file data, inodes, mounts) | ✓ | |
| Network stack | ✓ | |
| Pipe registry | ✓ | |
| Futex manager | ✓ | |
| Process registry | ✓ | |
| Core descriptors (open-file objects) | ✓ | |
| FD table (FilesState) | | ✓ |
| Address space (PageManager/Vmem) | | ✓ |
| Signal dispositions | | ✓ |
| brk pointer | | ✓ |
| Thread list / thread group | | ✓ |
| PID, PPID, PGID, SID | | ✓ |

**Pipe buffers** use the Rust global allocator (`alloc::` crate). On LVBS,
this is the `SafeZoneAllocator` (kernel heap, mapped in all TA page tables
via shared kernel PML4 entries). On userland, this is the host process heap
(shared in the single address space). Pipe ring buffers are therefore
accessible from all processes/TAs on all platforms without additional
shared-memory infrastructure.

**Futex manager** keys waiters by raw virtual address. On userland (single
address space with non-overlapping per-process VA ranges), this works
correctly because addresses don't alias between processes. On kernel
platforms (separate address spaces), futex keys must include the address
space identity to prevent false aliasing. See §4.5.

### 2.5 Layer Responsibilities

The three-layer separation (shim / core / platform) is preserved:

| Layer | Multi-process responsibility |
|---|---|
| **Core** | Process registry (PID allocation, parent-child tracking, wait/notify). Per-process `PageManager` ownership. Process lifecycle state machine. Core `Descriptors` remains global (open-file-object registry). |
| **Shim** | Per-process `FilesState` (FD table). Syscall dispatch (`fork`, `execve`, `waitpid`, `kill`, `getpid`). Per-process signal dispositions, brk, thread group management. ELF loading into a specific process's address space. Driving the fork/exec sequence. |
| **Platform** | Address space primitives: create, destroy, activate, fork. Page allocation within an address space. Thread spawning. |

Core orchestrates. Platform provides primitives. Shim drives the sequence.

---

## 3. Core Abstractions

### 3.1 Identity Model

LiteBox uses an internal PID/TID namespace fully decoupled from host PIDs
on all platforms. This avoids leaking host identity to the guest and ensures
consistent behavior across platforms.

**Process ID (tgid):** Assigned by `ProcessRegistry` via monotonic counter.
The thread-group leader's TID equals the process's tgid. `getpid()` returns
the tgid.

**Thread ID (tid):** Assigned per-thread. `gettid()` returns the calling
thread's tid. The thread-group leader has `tid == tgid`.

**ID allocation:** Monotonic counter starting at 1. No reuse — IDs are not
recycled. (With `u32`, this supports ~4 billion process/thread creations
before wrapping, which is sufficient for sandbox lifetimes.)

**Mapping rules:**
- `getpid()` → tgid of calling thread's process
- `gettid()` → tid of calling thread
- `getppid()` → tgid of parent process
- `tgkill(tgid, tid, sig)` → look up thread by (tgid, tid) in process table
- `wait*()` → wait for child process identified by tgid
- `kill(pid, sig)` → send signal to process identified by tgid

**PID 1:** The initial guest process (e.g., a shell). It has **normal**
signal semantics (can be killed, receives default dispositions). If orphan
reaping requires a persistent init process, it is handled internally by the
`ProcessRegistry` (not as a guest-visible process).

### 3.2 ProcessContext (Platform-Agnostic)

`ProcessContext` is pure identity and lifecycle data, with no platform
dependency. Process group and session IDs are included from the start
(defaulting to `pgid = pid, sid = pid`) to avoid migration later:

```rust
pub struct ProcessId(u32);
pub struct ProcessGroupId(u32);
pub struct SessionId(u32);

pub enum ProcessState {
    Running,
    Zombie(i32),  // exit status
}

pub struct ProcessContext {
    id: ProcessId,
    parent: Option<ProcessId>,
    pgid: ProcessGroupId,       // default: same as pid
    sid: SessionId,             // default: same as pid
    exit_signal: i32,           // signal sent to parent on exit (SIGCHLD for fork, 0 for threads)
    state: ProcessState,
    child_exit_notify: ...,     // per-process condvar for waitpid
}
```

### 3.3 ProcessRegistry (in Core)

`ProcessRegistry<Platform>` is a **concrete struct** in core (not a platform
trait). It manages process contexts and provides PID allocation,
parent-child tracking, and wait/notify:

```rust
pub struct ProcessRegistry<Platform: RawSyncPrimitivesProvider> {
    table: RwLock<Platform, HashMap<ProcessId, ProcessContext>>,
    next_pid: AtomicU32,
}

impl<Platform: RawSyncPrimitivesProvider> ProcessRegistry<Platform> {
    pub fn create_process(&self, parent: Option<ProcessId>) -> ProcessId;
    pub fn exit_process(&self, id: ProcessId, status: i32);
    pub fn wait_for_child(
        &self,
        parent: ProcessId,
        target: WaitTarget,
        options: WaitOptions,
    ) -> Result<(ProcessId, i32), WaitError>;
    pub fn send_signal(&self, target: ProcessId, signal: i32) -> Result<(), SignalError>;
    pub fn get_parent(&self, id: ProcessId) -> Option<ProcessId>;
    pub fn reparent_children(&self, dying: ProcessId, new_parent: ProcessId);
    pub fn set_pgid(&self, id: ProcessId, pgid: ProcessGroupId) -> Result<(), ...>;
    pub fn set_sid(&self, id: ProcessId) -> Result<SessionId, ...>;
}
```

All lifecycle logic (PID allocation, parent-child, wait/notify, orphan
reparenting) is platform-agnostic, using core's sync primitives.

**Locking granularity:** Each `ProcessContext` has its own condvar for
`waitpid()` notification (per-parent wait queue). When a child exits, only
the parent's condvar is signaled — avoiding thundering-herd wakeups on a
global condvar.

### 3.4 Wait Semantics

```rust
pub enum WaitTarget {
    Pid(ProcessId),             // wait for specific child
    AnyChild,                   // wait for any child (pid == -1)
    ProcessGroup(ProcessGroupId), // wait for child in group (pid == 0 or pid < -1)
}

bitflags! {
    pub struct WaitOptions: u32 {
        const WNOHANG    = 1;
        const WUNTRACED  = 2;
        const WCONTINUED = 8;
    }
}
```

### 3.5 Per-Process FD Table

Core `Descriptors<Platform>` stays global in `LiteBox` — it is the
open-file-object registry (like Linux's file table). The per-process FD
table is the **shim's** `FilesState<FS>`:

- Each process owns its own `Arc<RwLock<FilesState<FS>>>`.
- On `fork()`: clone `FilesState` (new FD mapping). Entries share
  `Arc<DescriptorEntry>` with the parent (shared file offsets/flags,
  matching POSIX `fork()` semantics).
- On `execve()`: close FDs marked `O_CLOEXEC` in the process's `FilesState`.
- On `clone(CLONE_FILES)`: share the `Arc` (same FD table, like threads).

### 3.6 Per-Process PageManager

`PageManager<Platform, ALIGN>` is already per-instance. The change is:

- **`PageManager::new()` gains a `range: Range<usize>` parameter** specifying
  the VA range this process can use.
- The `Vmem` inside tracks and enforces allocations within this range.
  Allocations outside the range are rejected.
- The range comes from `AddressSpaceProvider::address_space_range()`.

```rust
// Single process (current behavior):
let range = Platform::TASK_ADDR_MIN..Platform::TASK_ADDR_MAX;
let pm = PageManager::new(&litebox, range);

// Multi-process:
let as_id = platform.create_address_space()?;
let range = platform.address_space_range(as_id)?;
let pm = PageManager::new(&litebox, range);
```

On kernel platforms, `address_space_range()` returns the full
`TASK_ADDR_MIN..TASK_ADDR_MAX` (each process gets the entire range in its
own page tables). On userland, it returns a partition of the single address
space.

---

## 4. New Platform Trait: AddressSpaceProvider

### 4.1 Trait Definition

A new **optional** South interface trait for managing per-process address
spaces. All methods provide a default implementation that returns
`Err(AddressSpaceError::NotSupported)`, so platforms that do not yet
support multi-process need only specify the `AddressSpaceId` associated
type. The trait is a supertrait of `Provider`.

```rust
pub enum ForkedAddressSpace<Id> {
    /// Kernel: independent COW copy with full address range.
    Independent(Id),
    /// Userland: new VA range partition, parent memory shared (vfork semantics).
    SharedWithParent(Id),
}

pub trait AddressSpaceProvider {
    type AddressSpaceId: Copy + Eq + Send + Sync + Debug;

    /// Create a new empty address space for a new process.
    fn create_address_space(&self) -> Result<Self::AddressSpaceId, AddressSpaceError>;

    /// Destroy an address space when a process exits.
    fn destroy_address_space(
        &self,
        id: Self::AddressSpaceId,
    ) -> Result<(), AddressSpaceError>;

    /// Fork an address space. Returns an enum indicating what happened:
    /// - `Independent(id)`: kernel platforms — COW copy, separate address space.
    /// - `SharedWithParent(id)`: userland platforms — new VA range, parent
    ///   memory shared.
    /// The caller does not need to handle `NotSupported` — every platform
    /// that implements `AddressSpaceProvider` must support forking.
    fn fork_address_space(
        &self,
        parent: Self::AddressSpaceId,
    ) -> Result<ForkedAddressSpace<Self::AddressSpaceId>, AddressSpaceError>;

    /// Activate an address space for the current thread.
    /// Kernel: switch CR3. Userland: no-op or lightweight bookkeeping.
    fn activate_address_space(
        &self,
        id: Self::AddressSpaceId,
    ) -> Result<(), AddressSpaceError>;

    /// Execute a closure with the given address space active. Ensures
    /// activation/deactivation is structured and cannot be forgotten.
    ///
    /// **Restore contract:** On kernel platforms (where activation mutates
    /// hardware state like CR3), implementations **must** restore the
    /// previously active address space after `f` returns. Use a guard/RAII
    /// pattern to avoid state leaks in nested or panicking paths. Userland
    /// platforms may keep this as a no-op wrapper.
    fn with_address_space<R>(
        &self,
        id: Self::AddressSpaceId,
        f: impl FnOnce() -> R,
    ) -> Result<R, AddressSpaceError> {
        self.activate_address_space(id)?;
        let result = f();
        // Platform must restore previous address space here.
        Ok(result)
    }

    /// Get the VA range available to this address space.
    /// Kernel: full TASK_ADDR_MIN..TASK_ADDR_MAX.
    /// Userland: a partition of the total range.
    fn address_space_range(
        &self,
        id: Self::AddressSpaceId,
    ) -> Result<Range<usize>, AddressSpaceError>;
}
```

### 4.2 Platform Implementations

| Method | LVBS (kernel) | Linux Userland |
|---|---|---|
| `create_address_space` | Allocate P4 frame, copy kernel PML4 entries (`create_task_page_table`) | Assign a free sub-range of the VA space |
| `destroy_address_space` | Free page table frames (`delete_task_page_table`) | Release the sub-range |
| `fork_address_space` | COW-copy page tables → `Independent(id)` | Allocate new range → `SharedWithParent(id)` |
| `activate_address_space` | Write CR3 (`load_task`) | No-op |
| `address_space_range` | Full `TASK_ADDR_MIN..TASK_ADDR_MAX` | Sub-range partition |

### 4.3 Address Space Partitioning (Userland)

On userland platforms, the single host address space is divided into
fixed-size, non-overlapping partitions for guest processes:

- **Partition size:** Fixed power-of-2 (e.g., 1 TiB per partition on x86_64).
- **Maximum processes:** Determined by total VA range / partition size.
  With a 47-bit userland address space (~128 TiB) and 1 TiB partitions,
  this gives ~128 concurrent processes.
- **Allocation:** Free-list of partition slots. `create_address_space()`
  claims a slot; `destroy_address_space()` returns it.
- **Exhaustion:** Returns `AddressSpaceError::NoSpace` (mapped to `ENOMEM`
  by the shim).
- **ASLR:** PIE base address randomized within the partition.
- **Enforcement:** All page allocations use `MAP_FIXED_NOREPLACE` within
  the partition range, or equivalent VA reservation + fixed mappings.
  `Vmem` validates all returned addresses are within the process's
  sub-range; out-of-range addresses are rejected.
- **`mmap` with address hints:** Hints outside the process's partition are
  remapped to fall within the partition. `MAP_FIXED` with an address
  outside the partition returns `EINVAL`.

### 4.4 Existing Trait: PageManagementProvider

**No changes to `PageManagementProvider`.** The trait retains its
`TASK_ADDR_MIN`/`TASK_ADDR_MAX` associated constants, which describe the
platform's total available VA capacity. `PageManager` accepts a runtime
range parameter that may be the full range (single process, or kernel
multi-process) or a sub-range (userland multi-process).

`allocate_pages` / `deallocate_pages` / `update_permissions` continue to
operate on the currently-active address space. On kernel platforms, the
caller should use `with_address_space()` to ensure the correct address
space is active before performing page operations.

### 4.5 Futex Keying

The current `FutexManager` keys waiters by raw virtual address only. This
is sufficient for single-process use and for userland multi-process (where
non-overlapping VA partitions prevent address aliasing between processes).

On kernel platforms with separate address spaces, the same VA in different
processes would alias, causing incorrect cross-process wakeups. The futex
key model must be extended:

- **Private futex key** = `(AddressSpaceId, addr)`. Default for all futex
  operations. On userland, `AddressSpaceId` can be omitted or a constant
  (VAs don't overlap). On kernel, it discriminates per-process.
- **Shared futex key** = backing object identity (future work, for
  `mmap(MAP_SHARED)` pages).

`FutexManager::wait()` and `FutexManager::wake()` gain an
`AddressSpaceId` parameter. On userland, the shim can pass a constant.

### 4.6 Existing Trait: ThreadProvider

**No changes to `ThreadProvider`.** Thread-to-process association is managed
by the shim. The shim calls `activate_address_space()` (or
`with_address_space()`) before resuming guest execution for a thread,
ensuring the correct address space is active. The platform doesn't need to
know which process a thread belongs to.

---

## 5. Syscall Semantics

### 5.1 Fork Semantics by Platform

#### Userland: Vfork Semantics (Parent Suspended)

On userland platforms, `fork()` uses **vfork semantics**: the parent is
**suspended** until the child calls `execve()` or `_exit()`. This avoids
the stack/heap corruption that would occur with concurrent CLONE_VM
execution (both processes sharing the same stack and heap simultaneously).

Behavior:
- Parent and child **share all guest pages** (CLONE_VM-like).
- Per-process state is duplicated: FD table (cloned with shared file
  descriptions), signal dispositions (copied), PID (new), thread list (new).
- **Parent thread blocks** until the child calls `execve()` or `_exit()`.
- During the vfork window, only one process (the child) executes, so
  shared stack/heap access is safe.
- After the child execs: the child gets a new address space (via
  `create_address_space()`), and the parent resumes.

**Address-space lifecycle:** `fork_address_space()` at fork time returns
`SharedWithParent(child_asid)` and **reserves** the child's VA partition
immediately. During the vfork window, child execution still uses parent
mappings (parent blocked). On successful `execve()`, the child activates
`child_asid` and loads the new image into the reserved partition. If the
child exits before `execve()`, the reserved `child_asid` partition is
released. This makes fork reserve and exec activate/populate — a single
source of truth for address-space ownership.

**Parent-unblock events** (exhaustive list):
1. Child successful `execve()` (new image installed in child partition).
2. Child `_exit()` / `exit_group()`.
3. Child fatal termination by signal.
4. Child `execve()` **failure**: handled as forced `_exit(127)`. The parent
   is unblocked and the child does not continue guest execution in
   shared-VM mode. This prevents returning execution to a child that
   shares parent VM while the parent resumes.

This matches POSIX `vfork()` behavior and covers the dominant `fork()+exec()`
pattern (shells, build systems, daemons).

**ABI limitation:** Programs that `fork()` without calling `execve()` or
`_exit()` and expect independent memory will not work on userland platforms.
This is a documented, platform-specific limitation. Such programs work
correctly on kernel platforms (true COW fork).

On userland, all processes share a single host page table. Each process
gets a different VA partition (e.g., 1 TiB slots on x86_64). A `fork()`
cannot give the child the same virtual addresses as the parent — only
different ones. Since all internal pointers (stack return addresses, heap
pointers, globals) in the parent's memory reference the parent's VA range,
a simple memory copy into the child's range would leave the child with
dangling pointers. True address-space duplication requires per-process page
tables (kernel platforms).

**Consequence for glibc `fork()` wrapper:** Glibc's `fork()` calls
`clone(CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | SIGCHLD)` and expects
the child to return from `clone` with its own stack copy. On userland, we
treat all fork-like clones as vfork (shared stack, parent blocked). The
child's post-fork code in glibc (atfork handlers, etc.) runs while the
parent is blocked, so stack corruption does not occur. However, the child
**must** call `execve()` or `_exit()` — any attempt to return from `fork()`
and continue normal execution with independent memory will fail because the
child has no independent address space. In practice this means glibc
`fork()` + `execve()` works correctly on userland, but `fork()` without
`execve()` does not. Programs that fork children which do not exec (e.g.,
daemon-style double-fork, `fork()`-based parallelism) require kernel
platforms.

**Post-fork child operations:** Between `fork()` and `execve()`, the child
may safely perform async-signal-safe operations that go through the shim:
`dup2()`, `close()`, `setpgid()`, `sigprocmask()`, `chdir()`. These modify
per-task shim state and do not corrupt the shared guest memory. This covers
the standard shell job-control setup pattern.

#### Userland: fork + exec (Optimized Spawn Path)

The sequence for `fork()` followed by `execve()`:

1. `fork()`: Create child process (new PID, cloned FD table, cloned signals).
   Child shares parent's address space. Parent is suspended.
2. Child runs post-fork setup code (FD rewrites, `setpgid()`, signal mask
   changes, etc.) — safe because parent is blocked.
3. `execve()`: Create new address space via `create_address_space()`. Load
   the new binary (PIE, at any base within the child's new VA range). Close
   `O_CLOEXEC` FDs, reset signals. Spawn child thread. **Unblock parent.**
4. Both processes now run concurrently in separate VA ranges.

#### Kernel: COW Fork

On kernel platforms, `fork()` provides true fork semantics:

1. `fork_address_space()` → `Independent(id)`: COW-copy page tables. Child
   gets identical VA layout with copy-on-write pages.
2. Core: New `PageManager` with the full `TASK_ADDR_MIN..TASK_ADDR_MAX` range,
   initialized with copied Vmem metadata.
3. Per-process state duplicated as above.
4. Platform: New thread spawned, `activate_address_space()` before entering
   guest.
5. Both parent and child run concurrently — address spaces are
   hardware-isolated.

Fork-without-exec works correctly on kernel platforms.

#### vfork (Explicit)

`vfork()` uses vfork semantics on **all** platforms (parent suspended until
child execs or exits). On kernel platforms, this is an optimization over
full COW fork — it avoids copying page tables for the common fork+exec case.

#### clone() Flag Dispatch

The shim inspects `clone()` flags to determine behavior:

| Flags | Behavior |
|---|---|
| `CLONE_VM \| CLONE_THREAD \| CLONE_SIGHAND \| CLONE_FILES` | Thread creation (existing behavior) |
| No `CLONE_VM`, no `CLONE_THREAD` | Fork: vfork semantics on userland, COW on kernel |
| `CLONE_VM \| CLONE_VFORK` (no `CLONE_THREAD`) | vfork semantics on all platforms (glibc `vfork()`) |
| `CLONE_VM` without `CLONE_THREAD` or `CLONE_VFORK` | **Unsupported** (returns `EINVAL`). This would create a process sharing the parent's address space without blocking the parent — a rarely used Linux feature with no standard libc wrapper. |

**Platform-driven fork behavior:** The shim's `do_fork` does not hard-code
whether to use vfork or real fork semantics. Instead, it calls
`fork_address_space()` and branches on the result:

- `SharedWithParent(id)`: Child temporarily shares the parent's
  `ProcessState` (address space) but gets an independent FD table at fork
  time. Parent blocks (`VforkDone`). On `execve()`, the child detaches
  into its own VA partition.
- `Independent(id)`: Child gets its own `ProcessState` and duplicated FD
  table at fork time. Parent continues immediately. No `ForkContext`.

This keeps the shim platform-agnostic — the platform's return value drives
the behavior.

#### Fork Limitations Summary

| Limitation | Platforms | Details |
|---|---|---|
| `fork()` without `execve()` | Userland only | Child shares parent's address space; independent memory not available. Use kernel platforms for fork-without-exec workloads. |
| `CLONE_VM` without `CLONE_THREAD` or `CLONE_VFORK` | All | Returns `EINVAL`. No standard libc function uses this combination. |
| `setpgid()` after child `execve()` | All | Returns success instead of `EACCES`. Harmless — shells tolerate this for race-avoidance. |
| `fork()` + long-running child pre-exec code | Userland only | Parent is blocked during child's pre-exec phase. Acceptable for typical fork+exec patterns (shells, build systems). |

#### Fork→Vfork Libc Patch (Userland)

On userland platforms, the syscall rewriter patches `__libc_fork` in libc.so
to jump directly to `__libc_vfork`. This is a 5-byte `JMP rel32` instruction
at the entry point of `__libc_fork`, redirecting to `__libc_vfork`'s code.

**Why:** glibc's `__libc_fork` wrapper (~0x490 bytes) runs post-fork handlers
that modify global state (`_rtld_global`, `__fork_generation`, lock resets).
In the shared-address-space model, these modifications corrupt the parent's
globals. glibc's `__libc_vfork` wrapper (~0x39 bytes) is minimal — it only
issues the vfork syscall and checks the return value.

**Mechanism:** The rewriter finds `fork`/`__libc_fork` and `vfork`/`__libc_vfork`
symbols in the ELF's dynamic symbol table, computes the relative offset, and
patches the first 5 bytes of `__libc_fork` with `E9 <rel32>`. This catches
all callers (both external via PLT and internal direct calls within libc).

**Calling convention compatibility:** `vfork()` saves the return address in
`%rdi` (via `pop %rdi`) before the syscall and restores it after (`push %rdi`).
When called from `fork()`'s call site (which used `call fork@plt`), the return
address is already on the stack for `vfork` to pop.

**Writable page snapshot/restore:** Even with the fork→vfork patch, the child
still runs on the parent's guest stack and may modify globals between fork-return
and execve. The shim snapshots all writable guest VMAs before spawning the child
and restores them after the child signals vfork_done. This snapshot must be taken
*before* `spawn_thread` to capture clean, pre-modification state.

### 5.2 execve

`execve()` operates on the **calling process's** per-process state:

1. Unmap calling process's guest pages (per-process `PageManager`).
2. Close `O_CLOEXEC` FDs (per-process `FilesState`).
3. Reset signal dispositions to defaults (except `SIG_IGN`).
4. Clear pending signals.
5. Reset thread state to single thread.
6. Load new binary into calling process's VA range.
7. If the caller was a vfork child: unblock the parent.

The LiteBox runtime (platform, heap, shim infrastructure) survives — only
guest-visible state is reset.

### 5.3 Process Exit Sequence

When a process exits (via `_exit()`, `exit_group()`, or fatal signal):

1. Set process state to exiting. Prevent new thread creation.
2. Terminate all other threads in the thread group.
3. If this was a vfork child that hasn't exec'd: unblock the parent.
4. **Drop** the process's reference to `FilesState`. If this process is
   the last owner (no `CLONE_FILES` sharing), all FDs are closed. If
   shared, the FD table remains open for other owners.
5. **Drop** the process's reference to `PageManager`. If last owner
   (no `CLONE_VM` sharing), deallocate all guest pages. If shared, pages
   remain mapped for other owners.
6. **Drop** the process's address-space reference. If last owner, call
   `destroy_address_space()` to release the VA partition (userland) or
   free page tables (kernel). If shared (`CLONE_VM`), the address space
   remains for other owners.
7. Reparent children: reassign orphaned children's parent to PID 1 (the
   initial guest process), matching Linux default behavior. If PID 1
   itself has exited, `ProcessRegistry` auto-reaps the zombies internally
   to prevent accumulation. Future work: support
   `PR_SET_CHILD_SUBREAPER` to allow intermediate processes to opt in as
   subreapers, matching Linux ≥3.4 behavior where orphans are reparented
   to the nearest ancestor subreaper rather than PID 1.
8. Record exit status, transition to Zombie state.
9. Deliver `exit_signal` to parent (typically `SIGCHLD` for forked
   processes, 0 for threads).
10. Signal parent's per-process condvar (wake `waitpid()`).
11. Zombie reaped by parent's `waitpid()` → free `ProcessContext`, release
    PID.

**Note:** Steps 4–6 are **reference-based** via `Arc` drop semantics.
Resources shared via `CLONE_FILES` or `CLONE_VM` are only destroyed when
the last owning process exits. This preserves correctness for all `clone()`
flag combinations.

---

## 6. OP-TEE Shim Generalization

The OP-TEE shim currently manages multiple TAs with LVBS-specific code:

- `TaInstance` holds a `task_page_table_id` (LVBS page table ID).
- The runner/shim directly calls `create_task_page_table()` and `load_task()`
  on the LVBS platform.
- Inter-TA sessions are `todo!()`.

With `AddressSpaceProvider`, the OP-TEE shim becomes platform-agnostic:

- Each TA instance gets a `ProcessContext` from `ProcessRegistry` and an
  `AddressSpaceId` from `AddressSpaceProvider`.
- Loading a TA uses the `PageManager` initialized with
  `address_space_range(as_id)`.
- Switching to a TA calls `activate_address_space(as_id)`.
- No direct LVBS API calls in the shim.

This enables running OP-TEE TAs on other platforms (e.g., linux_userland for
testing) without shim changes.

---

## 7. Phased Implementation Plan

### Phase 1: Process Abstraction (Foundation)

**Goal:** Introduce the concept of multiple processes. The initial process
(PID 1) works exactly as before, but all state is properly scoped per-process.

**Step 1.1 — Process identity, registry, and current-process accessor (Core → Shim)**
- Define `ProcessId`, `ProcessGroupId`, `SessionId`, `ProcessState`,
  `ProcessContext` in core (with pgid/sid from the start).
- Define `WaitTarget`, `WaitOptions` types.
- Implement `ProcessRegistry<Platform>` with PID allocation, parent-child
  tracking, and per-process condvar wait/notify.
- Shim: Define a "current process" accessor for the syscall dispatch path.
  This must exist before per-process state can be threaded through syscall
  handlers.

**Step 1.2 — Per-process FD table (Shim)**
- Implement `clone_for_fork()` on `FilesState<FS>`, `Descriptors<FS>`,
  `Descriptor<FS>`, and `RawDescriptorStorage` — sharing underlying `Arc`
  file objects (POSIX shared-file-description semantics) while copying the
  FD-number mapping and `close_on_exec` flags.
- The `RefCell<Arc<FilesState>>` wrapper in `Task` is correct as-is
  (single-thread-per-task invariant holds) — no change needed.
- Core `Descriptors<Platform>` stays in `LiteBoxX` (global open-file-object
  registry) — **no extraction needed**.

**Step 1.3 — Per-process PageManager (Core → Platform)**
- `PageManager::new()` gains a `range: Range<usize>` parameter.
- `Vmem` validates all allocations are within the process's sub-range.
- Each process owns its own `PageManager` initialized with its VA range.
- Define the `AddressSpaceProvider` trait in core.
- Stub implementations on all platforms (return `NotSupported`).
- The initial process uses the full platform range (preserving current
  behavior).

**Step 1.4 — Per-process state in shim (Shim only)**
- Introduce `ProcessState` struct holding per-process `PageManager`.
  Threads of the same process share `Arc<ProcessState>`.
- Move `pm` from `GlobalState` to `ProcessState`. `GlobalState` retains
  truly global state (LiteBox, filesystem, network, futex, pipes, etc.).
- `LinuxShim` becomes a named-field struct holding `Arc<GlobalState>` +
  `Arc<ProcessState>` (for the initial process).
- `Task` gains an `Arc<ProcessState>` field; all `self.global.pm`
  references become `self.process_state.pm`.
- Thread clone inherits the parent's `Arc<ProcessState>`.
- **Deferred note from Step 1.4:** Moving `FilesState`, signal handlers,
  `credentials`, and `comm` into `ProcessState` was considered but
  rejected. Following the Linux kernel model, these remain as independent
  `Arc`-wrapped pointers in `Task` (analogous to `task_struct` holding
  `files_struct*`, `sighand_struct*`, `cred*`). `ProcessState` stays lean —
  only `PageManager` (analogous to `mm_struct`), the one structure that is
  always shared by all threads in a process and never independently
  shareable. Fork orchestration in `sys_clone` clones or shares each `Arc`
  based on clone flags.

**Step 1.5 — LiteBox restructuring (Core)**
- Add `ProcessRegistry` to `LiteBoxX`.
- `LiteBox::new()` creates the init process (PID 1) in the registry
  automatically, mirroring how Linux creates PID 1 during kernel boot
  before any user code runs. The shim loads the user program into this
  pre-existing process.
- Add `process_registry()` public accessor on `LiteBox`.
- Retain the `enforce_singleton_litebox_instance` assertion — `LiteBox`
  remains a singleton. It no longer owns per-process state, but it IS
  still "the kernel."

**Step 1.6 — Futex keying extension (Core)**
- Add `AddressSpaceId` parameter to `FutexManager::wait()` and `wake()`.
- On userland: pass a constant (addresses don't overlap between processes).
- On kernel: pass the process's `AddressSpaceId` to prevent false aliasing.

**End state:** System runs as before. One process exists (PID 1). All
per-process state is properly scoped. Infrastructure supports multiple
processes.

---

### Phase 2: Process Creation and Lifecycle

**Goal:** A guest can `fork()` + `exec()` to create a child process, wait
for it, and get its exit status. This is the "run a shell command" milestone.

**Step 2.1 — AddressSpaceProvider: Linux userland (Platform)**
- VA space partitioning with fixed-size partitions.
  `create_address_space()` claims a partition from the free-list.
  `fork_address_space()` → `SharedWithParent(id)`.
  Use `MAP_FIXED_NOREPLACE` for all allocations within partition.
- LVBS implementation deferred to Phase 3.

**Step 2.2 — Process creation API (Core)** ✅ Already covered by Step 1.1a.
- `ProcessRegistry::create_process(parent, exit_signal)` already allocates a
  PID, creates `ProcessContext` (inheriting `pgid`/`sid` from parent), and
  records the parent-child link.
- A separate `create_child` wrapper was considered but deemed unnecessary:
  the shim's `sys_fork`/`sys_clone` (Step 2.4) is the natural orchestration
  point that composes process creation + VA partition allocation + FD table
  cloning. Keeping `ProcessRegistry` focused on identity/lifecycle avoids
  coupling it to `AddressSpaceProvider`.

**Step 2.3 — ELF loading into a target process (Shim)**
- Parameterize the ELF loader to load into a given process's `PageManager`.
- PIE binary: loader picks a randomized base address within the target
  process's VA range.
- Reject `ET_EXEC` binaries on userland if the load address falls outside
  the process's VA partition (return `ENOEXEC`).
- Stack setup (argv, envp, auxv) targets the child's address space.

**Step 2.4 — sys_fork / sys_clone wiring (Shim)**

Per-process state architecture decision: `ProcessState` remains lean
(only `PageManager`), following the Linux kernel model. `Task` holds
independent `Arc`-wrapped pointers to `FilesState`, `SignalHandlers`,
`Credentials`, etc. — each independently shareable/clonable at clone time.

On userland, fork uses **vfork semantics**: the child shares the parent's
entire state (same `ProcessState`, same Arcs) until it calls `execve()`
or `_exit()`. The parent blocks. The child's own VA partition is allocated
but empty until `execve()` loads a new binary into it.

Sub-steps:

*Step 2.4a — Fork detection in sys_clone:*
- Add a new code path in `sys_clone` for fork-like calls
  (`!CLONE_VM && !CLONE_THREAD`).
- Distinguish fork (new process) from thread clone (same process).
- Scaffold the fork path: detect, log, return `ENOSYS` initially.
- Enforce Linux flag compatibility: `CLONE_SIGHAND` requires `CLONE_VM`.
- **Deferred:** `CLONE_VM` without `CLONE_THREAD` (share address space,
  separate process) and `CLONE_VFORK` (glibc's `vfork()` uses
  `CLONE_VM | CLONE_VFORK`) currently fall to the thread path and fail.
  Handle in Step 2.4b or 2.4c.

*Step 2.4b — Child process creation:*
- In the fork path, orchestrate:
  1. `ProcessRegistry::create_process(Some(parent), SIGCHLD)` → child PID.
  2. `platform.fork_address_space(parent_id)` → child partition.
  3. Create child `Task` with vfork sharing: child uses the **parent's**
     `ProcessState` (PM, files, signals, etc.) temporarily.
  4. Parent returns child PID; child returns 0.
- The child `Task` holds both a reference to the parent's `ProcessState`
  (for immediate use) and the child's partition ID (for later `execve`).

*Step 2.4c — vfork parent blocking:*
- After fork, the parent blocks on a per-process synchronization
  primitive (e.g., a futex/condvar in `ProcessState` or `Task`).
- The child unblocks the parent when it calls `execve()` or `_exit()`.
- Wire the unblock into `sys_execve` and `sys_exit_group` paths.

**Step 2.5 — sys_execve scoping (Shim)**
- Scope `execve()` to the calling process's state:
  - Unmap calling process's guest pages (per-process `PageManager`).
  - Close `O_CLOEXEC` FDs (per-process `FilesState`).
  - Reset signal dispositions.
  - Load new binary into calling process's VA range.
- If caller was a vfork child: unblock parent.

**Step 2.6 — Process exit and waitpid (Core → Shim)**
- Implement the full process exit sequence (§5.3).
- `ProcessRegistry::exit_process(id, status)` — mark as zombie, store
  exit status, deliver `exit_signal`, notify parent's condvar.
- `ProcessRegistry::wait_for_child(parent, target, options)` — block
  until child exits, return status. Handle `WNOHANG`, `WUNTRACED`.
- Shim: `sys_exit_group()` calls per-process exit.
  `sys_wait4()` calls core `wait_for_child`.

**Step 2.7 — getpid / getppid / gettid (Shim)**
- `getpid()` → tgid from current process context.
- `getppid()` → parent's tgid from `ProcessRegistry`.
- `gettid()` → current thread's tid.

**End state:** A guest shell can do `fork() → exec("/bin/ls") → waitpid()`.
Basic multi-process works.

---

### Phase 3: Inter-Process Communication and Signals

**Goal:** Processes can communicate and signal each other. Process groups
and job control work.

**Step 3.1 — Cross-process pipes (Core)**
- Pipe ring buffers use the Rust global allocator, which allocates from
  kernel/host-shared memory on all platforms (SafeZoneAllocator on LVBS,
  host heap on userland). Both pipe ends are therefore accessible from
  any process without additional shared-memory infrastructure.
- The work here is **routing**: when a process creates a pipe before fork,
  both parent and child inherit FD entries pointing to the same pipe
  endpoints (via shared `Arc<DescriptorEntry>` in core). Reads and writes
  go through the same ring buffer.
- No platform changes needed.

**Step 3.2 — kill() signal routing (Core → Shim)**
- `ProcessRegistry::send_signal(target_pid, signal)` — look up target
  process, queue the signal.
- Shim: `sys_kill()` with pid ≠ current → core signal routing.
- `sys_tgkill(tgid, tid, sig)` → look up specific thread in process.
- Target process picks up queued signals on next check.

**Step 3.3 — Process groups and sessions (Core → Shim)**
- `ProcessContext` already has `pgid`, `sid` fields (from Phase 1).
- Implement `setpgid()`, `getpgid()`, `setsid()`, `getsid()` as
  `ProcessRegistry` operations.
- `kill()` with negative PID → iterate process group members.
- Shim: wire `sys_setpgid()`, `sys_setsid()`, etc.

**Step 3.4 — Orphan handling and zombie reaping (Core)**
- When a parent exits, reparent children to PID 1 (matching Linux default).
- If PID 1 has also exited, `ProcessRegistry` auto-reaps zombies internally.
- `SIGCHLD` delivery to parent on child exit (using `exit_signal` stored
  per-process).
- Future: `PR_SET_CHILD_SUBREAPER` support — orphans reparented to nearest
  ancestor subreaper instead of PID 1 (Linux ≥3.4 semantics, used by
  containers and service managers like `systemd`).

**Step 3.5 — Pure fork without exec (Shim → Platform)**
- Userland: vfork semantics — child shares parent's memory, parent blocked.
  Gets its own FD table / signals / PID. Parent unblocked on `_exit()`.
- Kernel: COW fork via `fork_address_space()` → `Independent(id)`.
  Both run concurrently.
- Test and document the behavioral difference.

**Step 3.6 — AddressSpaceProvider: LVBS (Platform)**
- Wrap existing `PageTableManager` behind `AddressSpaceProvider`.
  `create_address_space()` → `create_task_page_table()`.
  `activate_address_space()` → `load_task()`.
  `fork_address_space()` → COW-copy → `Independent(id)`.
- Other kernel platforms (linux_kernel, windows_userland): implement or
  extend stubs as needed.

**End state:** Full multi-process support — shells, build systems, daemons
with process trees, signal-based job control.

---

## 8. Summary of Changes by Crate

| Crate | Changes |
|---|---|
| **litebox (core)** | `ProcessId`, `ProcessGroupId`, `SessionId`, `ProcessContext`, `ProcessRegistry`. `PageManager` accepts runtime VA range. Define `AddressSpaceProvider` trait and `ForkedAddressSpace` enum. Add `ProcessRegistry` to `LiteBox`. Extend `FutexManager` with `AddressSpaceId` keying. Core `Descriptors` stays in `LiteBoxX` (unchanged). |
| **litebox_shim_linux** | Per-process `FilesState` (`Arc<RwLock<...>>`). Per-process signals, brk, thread group. Fork/vfork/exec/waitpid/kill/tgkill/getpid/gettid syscall handlers. ELF loader parameterized by target process. Reject `ET_EXEC` on userland multi-process. Vfork parent suspension logic. `exit_signal` handling. |
| **litebox_shim_optee** | Replace direct LVBS page table calls with `AddressSpaceProvider`. Per-TA `ProcessContext`. (Enables OP-TEE on non-LVBS platforms.) |
| **litebox_platform_linux_userland** | Implement `AddressSpaceProvider`: fixed-size VA partitioning, `MAP_FIXED_NOREPLACE` enforcement, `fork_address_space()` → `SharedWithParent`. |
| **litebox_platform_lvbs** | Implement `AddressSpaceProvider`: wrap `PageTableManager` (`create_task_page_table`, `load_task`, `delete_task_page_table`). COW page table copy for `fork_address_space()` → `Independent`. |
| **litebox_platform_windows_userland** | Implement `AddressSpaceProvider`: VA space partitioning (similar to linux_userland). |
| **litebox_platform_linux_kernel** | Implement `AddressSpaceProvider`: page table management for SNP. |
| **litebox_common_linux** | Add `Fork`, `Vfork`, `Wait4`, `Execve` variants to `SyscallRequest` (if not already present). |
| **Runners** | Minimal changes — runners create the initial process (PID 1) with the full platform range. |

---

## Appendix A: Implementation Guardrails

### A.1 `AddressSpaceProvider` Support Policy Across Phases

Trait support policy is:

- In early bring-up, platforms may have temporary stubs that return
  `AddressSpaceError::NotSupported`.
- Before Phase 2 completion for a platform, all required methods for that
  platform's declared multi-process mode must be implemented.
- Once a platform is marked multi-process-capable, `fork_address_space()` must
  not return `NotSupported` on normal supported paths.

Shims should map unsupported platform capability to clear syscall errors
(`ENOSYS`/`EINVAL`) until the platform is upgraded.
