# Phase D: Multi-Thread + Fork Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enable guest programs to create threads (clone with CLONE_VM|CLONE_THREAD) and fork child processes through the micro-LiteBox ↔ central architecture.

**Architecture:** Threading works by having central's shim handle the clone bookkeeping (allocate TID, create ThreadState, register in Process) while micro executes the real `clone()` syscall locally and initializes GS-based TLS for the new thread. Fork works by having central prepare a new shared-memory ring + deep-copy state, then micro executes real `fork()`, and the child reinitializes its ring connection. Central spawns a new server thread per child process.

**Tech Stack:** Rust, x86_64 asm, libc, litebox_ipc ring buffers, litebox_micro GS-based TLS, litebox_central ProcessServer

---

## Overview

Phase D has two parts:

**Part 1 — Threading (Tasks 1-5):** Guest calls `clone(CLONE_VM|CLONE_THREAD|...)`. Central's shim currently tries to call `platform.spawn_thread()` which returns `CentralThreadSpawnError`. Instead, central must: (a) do all the shim-side bookkeeping (allocate TID, create ThreadState), (b) return EXEC_LOCAL with the TID and thread-slot, (c) micro executes real `clone()`, (d) child thread initializes GS-TLS and sends MSG_THREAD_REGISTER, (e) micro reports the clone result back.

**Part 2 — Fork (Tasks 6-9):** Guest calls `fork()` (clone with SIGCHLD, no CLONE_VM). Central must: (a) allocate child PID, create new shmem ring, (b) return EXEC_LOCAL with child ring fd + child PID, (c) micro executes real `fork()`, child reconnects to new ring, (d) central spawns a new server thread for the child. The micro-side fork code (`litebox_micro/src/fork.rs`) is already implemented.

### Key Design Decisions

1. **Central intercepts clone before `do_clone` reaches `spawn_thread`**: We add a new method `handle_clone_for_micro` that does the Task/ThreadState bookkeeping but returns the TID instead of spawning a platform thread.
2. **Thread registration uses MSG_THREAD_REGISTER**: After micro's new thread is running, it sends MSG_THREAD_REGISTER to central. Central assigns and returns a thread_slot.
3. **Fork creates a new shmem + ProcessServer on a new std::thread**: Central's main server thread creates the child shmem, spawns `std::thread::spawn` with a new `ProcessServer` for the child.
4. **CqEntry encodes clone/fork response data**: For clone: `result = child_tid`, `data_offset = assigned_thread_slot`. For fork: `result = child_ring_fd`, `data_offset = child_pid`.

---

### Task 1: Central — Thread-aware clone dispatch

**Goal:** When central receives a clone syscall with CLONE_VM|CLONE_THREAD, perform the shim's bookkeeping (allocate TID, create ThreadState) without calling `spawn_thread`, and return EXEC_LOCAL so micro can execute the real clone.

**Files:**
- Modify: `litebox_shim_linux/src/lib.rs` — Add `create_thread_task` method on `LinuxShimTask`
- Modify: `litebox_central/src/server.rs` — Add clone interception in `handle_syscall`

**Step 1: Add `create_thread_task` to `LinuxShimTask`**

In `litebox_shim_linux/src/lib.rs`, add a method that creates a new `LinuxShimTask` for a child thread, doing the same bookkeeping as `do_clone` but without calling `spawn_thread`:

```rust
impl<FS: ShimFS> LinuxShimTask<FS> {
    /// Create a new task handle for a child thread.
    ///
    /// Performs the same bookkeeping as `do_clone` (allocate TID, create
    /// ThreadState, attach to Process) but does NOT spawn a platform thread.
    /// The caller is responsible for using the returned TID to set up the
    /// actual thread via micro-LiteBox.
    ///
    /// Returns `(child_tid, child_task)` on success.
    pub fn create_thread_task(&self) -> Result<(i32, LinuxShimTask<FS>), litebox_common_linux::errno::Errno> {
        let child_tid = self.task.global.next_thread_id.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        let thread = self.task.thread.new_thread(child_tid)
            .ok_or(litebox_common_linux::errno::Errno::EBUSY)?;

        let child_task = LinuxShimTask {
            task: Task {
                global: self.task.global.clone(),
                wait_state: crate::wait::WaitState::new(self.task.global.platform),
                thread,
                pid: self.task.pid,
                ppid: self.task.ppid,
                tid: child_tid,
                credentials: self.task.credentials.clone(),
                comm: self.task.comm.clone(),
                fs: self.task.fs.clone(),
                files: self.task.files.clone(),
                signals: self.task.signals.clone_for_new_task(),
            },
        };

        Ok((child_tid, child_task))
    }
}
```

**Step 2: Add clone interception in `handle_syscall`**

In `litebox_central/src/server.rs`, detect clone syscalls and handle them specially. The server needs to become multi-task-aware — store tasks in a `BTreeMap<u16, LinuxShimTask>` keyed by thread_slot so each thread's syscalls are dispatched to its own task.

First, change `ProcessServer` to hold multiple tasks:

```rust
pub struct ProcessServer<FS: ShimFS> {
    region: SharedRegion,
    tasks: std::sync::Mutex<std::collections::BTreeMap<u16, litebox_shim_linux::LinuxShimTask<FS>>>,
}
```

In `handle_syscall`, detect `SYS_clone` / `SYS_clone3`:

```rust
#[allow(clippy::cast_possible_truncation)]
if nr == libc::SYS_clone as u32 || nr == libc::SYS_clone3 as u32 {
    // Extract flags from args[0] for clone, or from the clone_args struct for clone3
    let flags = entry.args[0];
    let clone_flags = litebox_common_linux::CloneFlags::from_bits_truncate(flags);
    if clone_flags.contains(litebox_common_linux::CloneFlags::VM)
        && clone_flags.contains(litebox_common_linux::CloneFlags::THREAD)
    {
        // Threading: allocate a new task in the shim, return EXEC_LOCAL
        let tasks = self.tasks.lock().unwrap();
        let parent_task = tasks.get(&entry.thread_slot).expect("unknown thread_slot");
        match parent_task.create_thread_task() {
            Ok((child_tid, _child_task)) => {
                // child_task will be registered when MSG_THREAD_REGISTER arrives
                // For now store it in a pending map
                return (i64::from(child_tid), cq_flags::EXEC_LOCAL);
            }
            Err(e) => return (i64::from(e.as_neg()), 0),
        }
    }
    // Non-thread clone (fork) handled in Task 6
}
```

**Step 3: Verify it compiles**

Run: `cargo build -p litebox_central -p litebox_shim_linux`

**Step 4: Commit**

```
feat(central): add thread-aware clone dispatch for micro-LiteBox threading
```

---

### Task 2: Micro — Local clone execution

**Goal:** When micro receives EXEC_LOCAL for a clone syscall, execute the real `clone()` syscall on the host. The new thread starts at the guest's specified stack + entry point, but first initializes GS-TLS and registers with central.

**Files:**
- Modify: `litebox_micro/src/local_exec.rs` — Add SYS_clone to `execute_locally`
- Create: `litebox_micro/src/thread.rs` — Thread initialization for cloned threads
- Modify: `litebox_micro/src/lib.rs` — Add `pub mod thread`
- Modify: `litebox_micro/src/handler.rs` — Wire clone result reporting

**Step 1: Create `thread.rs` with new-thread entry point**

The cloned thread needs a wrapper that:
1. Initializes GS-based TLS for the new thread
2. Sends MSG_THREAD_REGISTER to central
3. Jumps to the guest's intended entry point

```rust
// litebox_micro/src/thread.rs

use litebox_ipc::messages::MSG_THREAD_REGISTER;

/// Arguments passed to the new thread's entry function.
#[repr(C)]
struct NewThreadBootstrap {
    /// The guest's intended child stack pointer.
    child_stack: usize,
    /// The guest's TLS pointer (if CLONE_SETTLS).
    tls_ptr: usize,
    /// The child TID assigned by central.
    child_tid: i64,
    /// The pointer where to write the child TID (CLONE_CHILD_SETTID).
    child_tid_ptr: usize,
    /// The pointer for CLONE_CHILD_CLEARTID.
    clear_child_tid_ptr: usize,
}

/// Entry function for a cloned thread. Called via clone()'s child entry.
///
/// # Safety
///
/// `arg` must point to a valid `NewThreadBootstrap`.
unsafe extern "C" fn thread_entry(arg: *mut libc::c_void) -> libc::c_int {
    let bootstrap = unsafe { &*(arg.cast::<NewThreadBootstrap>()) };
    let child_tid = bootstrap.child_tid;

    // 1. Register with central to get a thread_slot.
    // We need a temporary TLS to communicate with central.
    // Use thread_slot=0 temporarily, then update after registration.
    let micro_state = crate::state::global_micro_state_ptr();
    let tls = unsafe { crate::tls::micro_init_thread_inner(micro_state, 0) };

    // 2. Send MSG_THREAD_REGISTER to get our real slot.
    let args = [u64::MAX, 0, 0, 0, 0, 0]; // auto-assign
    let cq = unsafe { crate::handler::submit_and_wait(tls, MSG_THREAD_REGISTER, &args, 0) };
    let thread_slot = cq.result as u16;
    unsafe { (*tls).thread_slot = u64::from(thread_slot) };

    // 3. Handle CLONE_CHILD_SETTID: write child TID to the specified address.
    if bootstrap.child_tid_ptr != 0 {
        unsafe { *(bootstrap.child_tid_ptr as *mut i32) = child_tid as i32 };
    }

    // 4. Handle CLONE_SETTLS: set FS base for the guest's TLS.
    if bootstrap.tls_ptr != 0 {
        unsafe { libc::syscall(libc::SYS_arch_prctl, 0x1002i32 /*ARCH_SET_FS*/, bootstrap.tls_ptr) };
    }

    // 5. Drop bootstrap, switch to child stack, and "return" to guest code.
    // The guest expects to resume from clone() returning 0.
    // The trampoline will handle this — the child's return address was
    // saved in the parent's rcx, and clone() returns 0 in the child.
    //
    // For now, the child thread runs guest code via the normal trampoline
    // path. The parent's clone call returns child_tid.
    // The child just returns 0 — the clone wrapper in the guest handles it.
    0
}
```

Note: The actual thread creation mechanism is more complex because `clone()` with CLONE_VM shares the address space, so the child thread starts at the stack pointer provided by the guest. The trampoline's `micro_handle_syscall` returns the child_tid to the parent, and the child thread starts fresh on its stack. We'll use `libc::clone()` with the guest's stack.

**Step 2: Add SYS_clone handling to `execute_locally`**

In `litebox_micro/src/local_exec.rs`, the clone EXEC_LOCAL case uses the CQ entry to get the child_tid from central, then calls real `clone()`:

```rust
nr if nr == libc::SYS_clone as u32 => {
    // CQ result = child_tid assigned by central
    // args[0] = flags, args[1] = child_stack, args[2] = parent_tidptr,
    // args[3] = child_tidptr, args[4] = tls
    unsafe { crate::thread::handle_clone(args, _cq) }
},
```

**Step 3: Add module declaration**

In `litebox_micro/src/lib.rs`, add `pub mod thread;`.

**Step 4: Verify it compiles**

Run: `cargo build -p litebox_micro`

**Step 5: Commit**

```
feat(micro): add local clone execution for guest thread creation
```

---

### Task 3: Central — Thread registration and per-thread dispatch

**Goal:** Central properly handles MSG_THREAD_REGISTER by assigning a thread_slot, and dispatches syscalls from each thread to the correct task. Also handle MSG_THREAD_DEREGISTER for cleanup.

**Files:**
- Modify: `litebox_central/src/server.rs` — Real thread registration logic, per-thread task map

**Step 1: Add thread management state to ProcessServer**

```rust
pub struct ProcessServer<FS: ShimFS> {
    region: SharedRegion,
    /// Primary task (thread_slot 0, the initial/main thread).
    primary_task: litebox_shim_linux::LinuxShimTask<FS>,
    /// Additional thread tasks, keyed by thread_slot.
    thread_tasks: std::sync::Mutex<std::collections::BTreeMap<u16, litebox_shim_linux::LinuxShimTask<FS>>>,
    /// Pending child tasks from create_thread_task, keyed by child_tid.
    pending_threads: std::sync::Mutex<std::collections::BTreeMap<i32, litebox_shim_linux::LinuxShimTask<FS>>>,
    /// Next available thread slot (starts at 1, slot 0 = main thread).
    next_thread_slot: std::sync::atomic::AtomicU16,
}
```

**Step 2: Implement MSG_THREAD_REGISTER handler**

When a new thread sends MSG_THREAD_REGISTER:
1. Assign the next available thread_slot
2. Move its `LinuxShimTask` from `pending_threads` to `thread_tasks`
3. Return the slot in `CqEntry.result`

```rust
MSG_THREAD_REGISTER => {
    let slot = self.next_thread_slot.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // The child_tid was sent in the registration message if needed
    // For now, just assign the slot
    i64::from(slot)
}
```

**Step 3: Implement MSG_THREAD_DEREGISTER handler**

When a thread sends MSG_THREAD_DEREGISTER:
1. Remove its task from `thread_tasks`
2. Free the thread_slot for reuse

```rust
MSG_THREAD_DEREGISTER => {
    let slot = entry.thread_slot;
    self.thread_tasks.lock().unwrap().remove(&slot);
    0
}
```

**Step 4: Route syscalls to per-thread tasks**

In the main `handle_syscall`, look up the task by `entry.thread_slot`:

```rust
fn get_task_for_slot(&self, slot: u16) -> ... {
    if slot == 0 {
        &self.primary_task
    } else {
        // Look up in thread_tasks
    }
}
```

**Step 5: Verify it compiles and tests pass**

Run: `cargo build -p litebox_central`

**Step 6: Commit**

```
feat(central): add thread registration and per-thread syscall dispatch
```

---

### Task 4: Micro — Thread exit and cleanup

**Goal:** When a guest thread calls `exit()` (not `exit_group()`), the thread should deregister from central and clean up its TLS.

**Files:**
- Modify: `litebox_micro/src/local_exec.rs` — Differentiate exit vs exit_group
- Modify: `litebox_micro/src/handler.rs` — Add thread exit flow

**Step 1: Add SYS_exit handling in micro_handle_syscall**

When the syscall is `SYS_exit` (single thread exit, not group exit), after dispatching to central, send MSG_THREAD_DEREGISTER before executing locally:

```rust
// In micro_handle_syscall, after getting cq back from central:
if args.nr as u32 == libc::SYS_exit as u32 {
    // Deregister this thread from central
    let dereg_args = [u64::from(unsafe { (*tls).thread_slot } as u16), 0, 0, 0, 0, 0];
    unsafe { submit_and_wait(tls, MSG_THREAD_DEREGISTER, &dereg_args, 0) };
}
```

**Step 2: Verify it compiles**

Run: `cargo build -p litebox_micro`

**Step 3: Commit**

```
feat(micro): add thread exit with MSG_THREAD_DEREGISTER cleanup
```

---

### Task 5: Integration test — Multi-threaded guest

**Goal:** Write a nolibc test binary that creates a thread using raw clone() syscall, the thread writes a message, then exits. Verify both messages appear.

**Files:**
- Create: `litebox_launcher/tests/thread_nolibc.c` — Test binary
- Modify: `litebox_launcher/tests/integration.rs` — Add test case

**Step 1: Write the nolibc threaded test binary**

```c
// thread_nolibc.c — minimal threading test for micro-LiteBox
#include <asm/unistd.h>
#include <linux/sched.h>

#define STACK_SIZE 65536

static char child_stack[STACK_SIZE] __attribute__((aligned(16)));

static void write_msg(int fd, const char *msg, int len) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "0"(__NR_write), "D"(fd), "S"(msg), "d"(len)
                 : "rcx", "r11", "memory");
}

static void thread_exit(int code) {
    asm volatile("syscall" : : "a"(__NR_exit), "D"(code) : "rcx", "r11", "memory");
    __builtin_unreachable();
}

static int child_fn(void *arg) {
    (void)arg;
    const char msg[] = "Hello from child thread!\n";
    write_msg(1, msg, sizeof(msg) - 1);
    thread_exit(0);
}

void _start(void) {
    const char msg[] = "Hello from main thread!\n";
    write_msg(1, msg, sizeof(msg) - 1);

    // clone(CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FILES | CLONE_FS,
    //       child_stack + STACK_SIZE, NULL, NULL, 0)
    unsigned long flags = 0x00010100 | 0x00000100 | 0x00000800 | 0x00000400 | 0x00000200;
    // CLONE_VM=0x100, CLONE_FS=0x200, CLONE_FILES=0x400, CLONE_SIGHAND=0x800, CLONE_THREAD=0x10000
    long ret;
    asm volatile("syscall"
                 : "=a"(ret)
                 : "0"(__NR_clone), "D"(flags),
                   "S"(child_stack + STACK_SIZE),
                   "d"(0), /* parent_tid */
                   "r"((long)0) /* child_tid (r10) */
                 : "rcx", "r11", "memory");

    // Wait a bit for child to finish (crude, but works for testing)
    // Use nanosleep or just spin
    for (volatile long i = 0; i < 10000000; i++) {}

    // exit_group(0)
    asm volatile("syscall" : : "a"(__NR_exit_group), "D"(0) : "rcx", "r11", "memory");
    __builtin_unreachable();
}
```

**Step 2: Add integration test**

Add a test in `integration.rs` similar to the existing one but with the threaded binary.

**Step 3: Build and run**

Run: `cargo nextest run -p litebox_launcher -- --ignored test_thread_nolibc`

**Step 4: Commit**

```
test(launcher): add multi-threaded nolibc integration test
```

---

### Task 6: Central — Fork preparation (new shmem + child state)

**Goal:** When central receives a clone syscall that is a fork (no CLONE_VM), prepare a new shared memory ring for the child process and return the necessary info to micro.

**Files:**
- Modify: `litebox_central/src/server.rs` — Fork handling in `handle_syscall`
- Modify: `litebox_central/src/shmem.rs` — Add `SharedRegion::create_for_child()` that returns the fd

**Step 1: Add `create_for_child` to SharedRegion**

Create a new shmem region and return both the region and its raw fd (for passing to micro):

```rust
impl SharedRegion {
    /// Create a new shared memory region for a child process after fork.
    /// Returns the region and the raw fd number (which can be sent to micro
    /// for dup2-ing before fork).
    pub fn create_for_child() -> anyhow::Result<(Self, i32)> {
        let region = Self::new()?;
        use std::os::fd::AsRawFd;
        let raw_fd = region.fd().as_raw_fd();
        Ok((region, raw_fd))
    }
}
```

**Step 2: Add fork handling in `handle_syscall`**

When clone flags do NOT include CLONE_VM (i.e., it's a fork):

```rust
// Fork: no CLONE_VM
// 1. Allocate child PID
// 2. Create new shmem for child
// 3. Send the child ring fd to micro via /proc/self/fd/N or by dup2
// 4. Return EXEC_LOCAL with (child_ring_fd, child_pid)
let child_pid = self.next_pid.fetch_add(1, Ordering::Relaxed);
let (child_region, child_ring_fd) = shmem::SharedRegion::create_for_child()?;

// Send child_ring_fd to micro process via SCM_RIGHTS or by
// having the fd inherited. Since central is a SEPARATE process from
// micro/guest, we need a mechanism to send the fd.
//
// Approach: Use the data region of the ring buffer to communicate
// the fd path: /proc/<central_pid>/fd/<child_ring_fd>
// Then micro opens it. This avoids needing SCM_RIGHTS.
```

**Important design decision**: Central and micro are in different processes. Central cannot directly give micro a file descriptor. Options:
1. **`/proc/<central_pid>/fd/<N>`**: Micro opens this path to get a dup of central's fd. Simple but requires `/proc` access.
2. **Pre-create memfd with a known name**: Micro creates the memfd by name.
3. **Pass fd number in shmem data region, have micro use `pidfd_getfd()`**.

**Chosen approach**: Central writes the path `/proc/self/fd/<N>` into the CqEntry data. But actually, simpler: central can set `MFD_ALLOW_SEALING` and communicate the memfd name. Even simpler: **central puts the raw memfd fd number in CqEntry.result**, and micro opens `/proc/<central_pid>/fd/<result>`. Central's PID is communicated at startup.

Actually, the cleanest approach: the data region of the shared ring buffer IS shared memory. Central can write the child ring fd number + its own PID into the CQ entry:
- `result`: central's PID (so micro can construct `/proc/<pid>/fd/...`)
- `data_offset`: child PID
- `data_len`: child ring fd number in central's fd table

Then micro opens `/proc/<central_pid>/fd/<child_ring_fd>` to get its own fd.

**Step 3: Verify it compiles**

Run: `cargo build -p litebox_central`

**Step 4: Commit**

```
feat(central): add fork preparation with new child shmem ring
```

---

### Task 7: Micro — Wire fork into the handler + fd passing

**Goal:** Connect the existing `handle_fork` implementation to the main syscall handler, including the fd-passing mechanism to get the child's ring fd from central.

**Files:**
- Modify: `litebox_micro/src/handler.rs` — Route fork to `handle_fork`
- Modify: `litebox_micro/src/local_exec.rs` — Add clone/fork to local_exec
- Modify: `litebox_micro/src/fork.rs` — Adapt to use `/proc` fd passing
- Modify: `litebox_micro/src/state.rs` — Add `central_pid` field

**Step 1: Add central_pid to MicroState**

Micro needs to know central's PID so it can open `/proc/<central_pid>/fd/<N>`:

```rust
pub struct MicroState {
    pub ring_base: *mut u8,
    pub ring_size: usize,
    pub ring_fd: i32,
    pub pid: u32,
    pub ppid: u32,
    pub central_pid: u32,  // NEW
    pub layout: SharedRingLayout,
}
```

Update `micro_init` to accept `central_pid`.

**Step 2: Adapt handle_fork for /proc fd passing**

In `fork.rs`, instead of receiving the child ring fd directly in `cq.result`, open it via `/proc`:

```rust
let central_pid = cq.result; // central's PID
let child_pid = cq.data_offset; // child PID assigned by central
let child_ring_fd_in_central = cq.data_len; // fd number in central's table

// Open the child ring fd via /proc
let path = format!("/proc/{}/fd/{}\0", central_pid, child_ring_fd_in_central);
let fd = libc::open(path.as_ptr().cast(), libc::O_RDWR);
```

**Step 3: Wire clone-as-fork into local_exec**

In `execute_locally`, when syscall_nr is SYS_clone and the CQ indicates fork (no CLONE_VM in flags):

```rust
nr if nr == libc::SYS_clone as u32 => {
    let flags = args[0];
    if flags & 0x100 != 0 { // CLONE_VM
        // Threading — handled by thread.rs
        unsafe { crate::thread::handle_clone(args, _cq) }
    } else {
        // Fork
        unsafe { crate::fork::handle_fork(_cq) }
    }
},
```

**Step 4: Verify it compiles**

Run: `cargo build -p litebox_micro`

**Step 5: Commit**

```
feat(micro): wire fork handling into main syscall dispatch
```

---

### Task 8: Central — Spawn child server thread after fork

**Goal:** After micro executes fork and the child sends MSG_CHILD_READY on the new ring, central spawns a new server thread to serve the child process.

**Files:**
- Modify: `litebox_central/src/server.rs` — Add child process server spawning
- Modify: `litebox_central/src/main.rs` — Support multi-process serving

**Step 1: Add child server management**

After creating the child shmem in Task 6, central holds onto the `SharedRegion`. When MSG_CHILD_READY arrives on the child's ring, spawn a new server thread:

```rust
// In ProcessServer, after fork preparation:
// Store the child region and create a new ProcessServer for it.
// Spawn a std::thread that runs child_server.run().
fn spawn_child_server(&self, child_region: SharedRegion, child_pid: i32) {
    // Create a new task for the child process
    let child_task = self.shim.create_task(self.fs.clone(), TaskParams {
        pid: child_pid,
        ppid: self.primary_task.pid(),
        ..
    });
    let child_server = ProcessServer::new(child_region, child_task);
    std::thread::spawn(move || {
        let _ = child_server.run();
    });
}
```

**Step 2: Handle MSG_CHILD_READY on child ring**

The child's ring needs a separate consumption loop. The child server thread polls its own ring and handles MSG_CHILD_READY as the initial message.

**Step 3: Verify it compiles**

Run: `cargo build -p litebox_central`

**Step 4: Commit**

```
feat(central): spawn child server thread after fork
```

---

### Task 9: Integration test — Fork guest

**Goal:** Write a nolibc test binary that calls fork(), parent waits, child writes a message and exits. Verify both parent and child messages appear.

**Files:**
- Create: `litebox_launcher/tests/fork_nolibc.c` — Test binary
- Modify: `litebox_launcher/tests/integration.rs` — Add fork test case

**Step 1: Write the nolibc fork test binary**

```c
// fork_nolibc.c — minimal fork test for micro-LiteBox
#include <asm/unistd.h>

static void write_msg(int fd, const char *msg, int len) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "0"(__NR_write), "D"(fd), "S"(msg), "d"(len)
                 : "rcx", "r11", "memory");
}

static void exit_group(int code) {
    asm volatile("syscall" : : "a"(__NR_exit_group), "D"(code) : "rcx", "r11", "memory");
    __builtin_unreachable();
}

void _start(void) {
    // fork via clone(SIGCHLD, 0, 0, 0, 0)
    long pid;
    asm volatile("syscall"
                 : "=a"(pid)
                 : "0"(__NR_clone), "D"(17 /* SIGCHLD */), "S"(0), "d"(0)
                 : "rcx", "r11", "memory");

    if (pid == 0) {
        // Child
        const char msg[] = "Hello from fork child!\n";
        write_msg(1, msg, sizeof(msg) - 1);
        exit_group(0);
    } else {
        // Parent — wait for child then print
        // Simple busy-wait (no waitpid in nolibc)
        for (volatile long i = 0; i < 10000000; i++) {}
        const char msg[] = "Hello from fork parent!\n";
        write_msg(1, msg, sizeof(msg) - 1);
        exit_group(0);
    }
}
```

**Step 2: Add integration test**

```rust
#[test]
#[ignore]
fn test_fork_nolibc_end_to_end() {
    // Similar structure to test_hello_nolibc_end_to_end
    // Compile fork_nolibc.c, rewrite, run through launcher
    // Assert stdout contains both "Hello from fork child!" and "Hello from fork parent!"
}
```

**Step 3: Build and run**

Run: `cargo nextest run -p litebox_launcher -- --ignored test_fork_nolibc`

**Step 4: Debug any issues**

Fork is the most complex path. Expect to fix multiple integration issues. Common problems:
- Child's ring not properly initialized
- Central not detecting MSG_CHILD_READY on the new ring (different shmem!)
- `/proc` fd access issues
- Child process not inheriting the launcher's stdout

**Step 5: Commit**

```
test(launcher): add fork nolibc integration test
```

---

## Task Dependencies

```
Task 1 (central clone dispatch)
  └─→ Task 2 (micro clone exec)
       └─→ Task 3 (central thread registration)
            └─→ Task 4 (micro thread exit)
                 └─→ Task 5 (thread integration test)

Task 6 (central fork prep)
  └─→ Task 7 (micro fork wiring)
       └─→ Task 8 (central child server)
            └─→ Task 9 (fork integration test)
```

Tasks 1-5 (threading) and Tasks 6-9 (fork) are independent tracks that can be developed in parallel once the shared infrastructure (Task 1) is done.

## Testing Strategy

- **Unit tests**: Each task should have targeted unit tests where feasible (e.g., thread_slot allocation, fork state preparation).
- **Integration tests**: Tasks 5 and 9 are end-to-end integration tests that exercise the full pipeline.
- **Run all existing tests** after each task to prevent regressions: `cargo nextest run` (excluding litebox_central due to feature unification).

## Risk Areas

1. **fd passing across processes**: Central and micro are separate processes. The `/proc/<pid>/fd/<N>` approach requires procfs mounted in the guest's filesystem view. Alternative: use SCM_RIGHTS over a Unix socket.
2. **Clone child entry**: When `clone(CLONE_VM|CLONE_THREAD)` creates a new thread, the child starts executing at the return point of clone() (on x86_64, clone returns in both parent and child, child gets 0). Since we rewrite `syscall` → JMP, the child resumes at the trampoline's `jmp rcx` instruction — but the child's rcx is 0 (it was the return address only in the parent). Need to handle this carefully.
3. **Red zone in child thread**: Same red zone issue as Phase C Bug 9 — already handled by the trampoline.
4. **Multi-threaded central access**: The `ProcessServer` will be accessed from multiple central threads (one per child process) but each server has its own ring, so no sharing issues.
