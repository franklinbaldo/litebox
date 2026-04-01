# Ring Pool & Vfork Fast-Path — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Speed up shell1 benchmark (currently 0.094x native) by eliminating per-fork `memfd_create`/`ftruncate`/`mmap` costs via a ring pool, and avoiding OS page table copy via `clone(CLONE_VM|CLONE_VFORK)`.

**Architecture:** Two independent optimizations composed together. (1) Central pre-allocates a pool of `SharedRegion` objects; `handle_fork` pops from the pool instead of creating rings. Child server threads return rings to the pool on exit. (2) Micro uses `clone(CLONE_VM|CLONE_VFORK|SIGCHLD)` for `SYS_vfork` instead of `libc::fork()`, with a pooled child stack. Parent saves/restores `MicroState` + TLS around the clone since the child mutates shared state while the parent is kernel-blocked.

**Tech Stack:** Rust, `#![no_std]` for IPC crate, `core::sync::atomic` for ring header reset, raw `SYS_clone` syscall, `Mutex<Vec<...>>` for cross-thread pool.

---

## Task 1: Ring pool in central — `RingPool` struct and allocation

**Files:**
- Modify: `litebox_central/src/shmem.rs`

**Step 1: Add `RingPool` struct after `SharedRegion`**

After the existing `create_child_ring()` method (line ~107), add:

```rust
use std::sync::{Arc, Mutex};

/// Pre-allocated pool of shared memory rings for child processes.
///
/// Rings are created eagerly at startup and recycled when child servers exit.
/// If the pool is empty, `acquire()` falls back to fresh allocation.
/// Thread-safe: the main server thread acquires, child server threads release.
pub struct RingPool {
    /// Available rings. Each entry is (SharedRegion, raw_fd).
    /// The raw_fd is the memfd file descriptor number (without MFD_CLOEXEC)
    /// so micro can access it via `/proc/<pid>/fd/<N>`.
    rings: Mutex<Vec<(SharedRegion, i32)>>,
}

impl RingPool {
    /// Create a new pool with `initial_count` pre-allocated rings.
    pub fn new(initial_count: usize) -> Self {
        let mut rings = Vec::with_capacity(initial_count);
        for _ in 0..initial_count {
            match SharedRegion::create_child_ring() {
                Ok(entry) => rings.push(entry),
                Err(e) => {
                    eprintln!("ring pool: failed to pre-allocate ring: {e}");
                    break;
                }
            }
        }
        Self {
            rings: Mutex::new(rings),
        }
    }

    /// Acquire a ring from the pool, or create a fresh one if empty.
    pub fn acquire(&self) -> std::io::Result<(SharedRegion, i32)> {
        if let Some(entry) = self.rings.lock().unwrap().pop() {
            Ok(entry)
        } else {
            SharedRegion::create_child_ring()
        }
    }

    /// Return a ring to the pool for reuse.
    ///
    /// Resets the ring header (SQ/CQ head/tail, notify slots) so the next
    /// user gets a clean ring. The data region and SQ/CQ entries are not
    /// zeroed — they are written before read.
    pub fn release(&self, region: SharedRegion, fd: i32) {
        // Reset ring header to initial state
        let header = region.header();
        header.sq_head.store(0, std::sync::atomic::Ordering::Relaxed);
        header.sq_tail.store(0, std::sync::atomic::Ordering::Relaxed);
        header.sq_notify.store(0, std::sync::atomic::Ordering::Relaxed);
        header.cq_head.store(0, std::sync::atomic::Ordering::Relaxed);
        header.cq_tail.store(0, std::sync::atomic::Ordering::Relaxed);
        for slot in &header.cq_notify_slots {
            slot.store(0, std::sync::atomic::Ordering::Relaxed);
        }
        // Reset all SQ entry ready flags
        for i in 0..litebox_ipc::ring::RING_SIZE {
            let sq = region.sq_entry(i);
            sq.ready.store(0, std::sync::atomic::Ordering::Relaxed);
        }
        self.rings.lock().unwrap().push((region, fd));
    }
}
```

**Step 2: Add `header()` accessor to `SharedRegion` if not already present**

Verify that `SharedRegion` has a method to get `&RingHeader`. If not, add:

```rust
/// Get a reference to the ring header at the start of the shared region.
pub fn header(&self) -> &litebox_ipc::ring::RingHeader {
    unsafe { &*(self.base as *const litebox_ipc::ring::RingHeader) }
}

/// Get a reference to the SQ entry at the given index.
pub fn sq_entry(&self, index: usize) -> &litebox_ipc::ring::SqEntry {
    let offset = self.layout.sq_entries_offset + index * core::mem::size_of::<litebox_ipc::ring::SqEntry>();
    unsafe { &*((self.base as usize + offset) as *const litebox_ipc::ring::SqEntry) }
}
```

**Step 3: Verify it compiles**

Run: `cargo build -p litebox_central`

**Step 4: Commit**

```bash
git add litebox_central/src/shmem.rs
git commit -m "central: add RingPool for pre-allocated child rings"
```

---

## Task 2: Integrate ring pool into `ProcessServer`

**Files:**
- Modify: `litebox_central/src/server.rs`

**Step 1: Add `ring_pool` field to `ProcessServer`**

Add to the struct (after `child_handles` field, line ~61):

```rust
    ring_pool: Arc<RingPool>,
```

**Step 2: Update `ProcessServer::new()` to accept pool**

Add `ring_pool: Arc<RingPool>` parameter to `new()` (line ~69). Store it in the struct.

**Step 3: Update `handle_fork()` to use pool**

Replace the `SharedRegion::create_child_ring()` call (line ~519) with:

```rust
let Ok((child_region, child_ring_fd)) = self.ring_pool.acquire() else {
    // ... existing error handling ...
};
```

Pass `Arc::clone(&self.ring_pool)` when constructing child `ProcessServer` (line ~557).

**Step 4: Return ring to pool on child server exit**

At the end of `run()` (after the main loop exits, before joining children, line ~196), add ring release logic. The `ProcessServer` owns its `region` — when `run()` returns, the region can be released to the pool.

We need to restructure slightly: extract `region` and `ring_pool` before the join loop so we can release after:

```rust
// After the main loop exits and children are joined:
// self.ring_pool.release(self.region, self.ring_fd);
```

We'll need to store `ring_fd` in `ProcessServer`. Add a field:

```rust
    ring_fd: i32,  // raw fd of this process's ring memfd (-1 for root process)
```

Set it to the child_ring_fd in `new()` for child servers, and -1 for the root server (root server's ring is owned by the launcher, not the pool).

Only release if `ring_fd >= 0` (i.e., not the root server).

**Step 5: Update the root server construction**

Wherever the root `ProcessServer` is created (likely in `main` or launcher integration), pass the `Arc<RingPool>` and set `ring_fd = -1`.

**Step 6: Verify it compiles and tests pass**

Run: `cargo build -p litebox_central && cargo nextest run -p litebox_central`

**Step 7: Commit**

```bash
git add litebox_central/src/server.rs
git commit -m "central: integrate RingPool into ProcessServer fork path"
```

---

## Task 3: Pool initial size and root server wiring

**Files:**
- Modify: `litebox_central/src/server.rs` (or wherever root `ProcessServer` is created)
- Modify: `litebox_central/src/shmem.rs` (if needed)

**Step 1: Find root server construction and wire the pool**

Search for where `ProcessServer::new(...)` is first called for the root process. Create the pool there:

```rust
let ring_pool = Arc::new(RingPool::new(8)); // pre-allocate 8 rings
```

Pass it to the root `ProcessServer::new(...)`.

**Step 2: Run the full build and a quick benchmark**

```bash
cargo build --release -p litebox_micro -p litebox_launcher && cargo build --release -p litebox_central
pkill -9 litebox_central; pkill -9 litebox
cd /workspace/litebox-mu/dev_bench/unixbench
python3 run_unixbench.py --mode micro --release --no-build --duration 10 --iterations 1 --benchmarks shell1
```

The ring pool alone should show some improvement since `memfd_create`/`ftruncate`/`mmap` are avoided for the first 8 forks. Beyond 8, it falls back to fresh allocation but recycled rings fill the pool back up.

**Step 3: Commit**

```bash
git add litebox_central/
git commit -m "central: wire ring pool at startup with 8 pre-allocated rings"
```

---

## Task 4: Stack pool in micro — `StackPool` struct

**Files:**
- Create: `litebox_micro/src/stack_pool.rs`
- Modify: `litebox_micro/src/lib.rs` (add `mod stack_pool;`)

**Step 1: Implement `StackPool`**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Pre-allocated stack pool for vfork children.
//!
//! Each stack is a 64 KiB mmap'd anonymous region. Stacks are acquired
//! before `clone(CLONE_VM|CLONE_VFORK)` and released by the parent after
//! the clone returns (the parent is unblocked when the child calls execve
//! or _exit, at which point the child no longer uses the stack).

use crate::raw_syscall;

/// Size of each pooled stack (64 KiB).
const STACK_SIZE: usize = 64 * 1024;

/// Maximum number of pre-allocated stacks.
const INITIAL_POOL_SIZE: usize = 4;

/// A stack allocation: base address and size.
#[derive(Clone, Copy)]
pub struct PooledStack {
    pub base: *mut u8,   // mmap base (low address)
    pub size: usize,
}

impl PooledStack {
    /// Returns the stack top (high address), suitable for clone's child_stack arg.
    /// x86_64 stacks grow downward, so clone needs the top of the region.
    pub fn top(&self) -> *mut u8 {
        unsafe { self.base.add(self.size) }
    }
}

/// Pool of pre-allocated stacks for vfork children.
///
/// Single-threaded access only (micro's syscall handler is single-threaded
/// per process). No synchronization needed.
pub struct StackPool {
    stacks: Vec<PooledStack>,
}

impl StackPool {
    /// Create a new pool, pre-allocating `INITIAL_POOL_SIZE` stacks.
    pub fn new() -> Self {
        let mut stacks = Vec::with_capacity(INITIAL_POOL_SIZE);
        for _ in 0..INITIAL_POOL_SIZE {
            if let Some(s) = Self::alloc_stack() {
                stacks.push(s);
            }
        }
        Self { stacks }
    }

    /// Acquire a stack from the pool, or allocate a fresh one.
    pub fn acquire(&mut self) -> Option<PooledStack> {
        if let Some(s) = self.stacks.pop() {
            Some(s)
        } else {
            Self::alloc_stack()
        }
    }

    /// Return a stack to the pool for reuse.
    pub fn release(&mut self, stack: PooledStack) {
        self.stacks.push(stack);
    }

    fn alloc_stack() -> Option<PooledStack> {
        let base = unsafe {
            raw_syscall::mmap(
                0,                          // addr: let kernel choose
                STACK_SIZE,                 // length
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,                         // fd: anonymous
                0,                          // offset
            )
        };
        if base == raw_syscall::MAP_FAILED || raw_syscall::is_error(base) {
            None
        } else {
            Some(PooledStack {
                base: base as *mut u8,
                size: STACK_SIZE,
            })
        }
    }
}
```

**Step 2: Add module declaration**

In `litebox_micro/src/lib.rs`, add:

```rust
pub mod stack_pool;
```

**Step 3: Verify it compiles**

Run: `cargo build -p litebox_micro`

**Step 4: Commit**

```bash
git add litebox_micro/src/stack_pool.rs litebox_micro/src/lib.rs
git commit -m "micro: add StackPool for vfork child stacks"
```

---

## Task 5: Wire stack pool into MicroState

**Files:**
- Modify: `litebox_micro/src/state.rs`

**Step 1: Add stack pool to global state**

We can't put `StackPool` inside `MicroState` (which is `#[repr(C)]` with fixed layout). Instead, use a separate global:

```rust
static mut STACK_POOL: Option<StackPool> = None;

pub fn init_stack_pool() {
    unsafe {
        STACK_POOL = Some(StackPool::new());
    }
}

pub fn global_stack_pool() -> &'static mut StackPool {
    unsafe { STACK_POOL.as_mut().expect("stack pool not initialized") }
}
```

**Step 2: Call `init_stack_pool()` during micro initialization**

Find where `micro_init()` is called (in the micro entry point) and add `init_stack_pool()` after it.

**Step 3: Verify it compiles**

Run: `cargo build -p litebox_micro`

**Step 4: Commit**

```bash
git add litebox_micro/src/state.rs
git commit -m "micro: wire StackPool into global state"
```

---

## Task 6: Vfork fast-path — `handle_vfork()` in micro

**Files:**
- Modify: `litebox_micro/src/fork.rs`

This is the core change. Add a new `handle_vfork()` function that uses `clone(CLONE_VM|CLONE_VFORK|SIGCHLD)` instead of `libc::fork()`.

**Step 1: Add `handle_vfork()` function**

After the existing `handle_fork()` (line ~82), add:

```rust
/// Handle vfork via clone(CLONE_VM|CLONE_VFORK|SIGCHLD).
///
/// The parent blocks (CLONE_VFORK) until the child calls execve() or _exit().
/// The child shares the parent's address space (CLONE_VM) — no page table copy.
/// The child runs on a pooled stack and uses the parent's ring temporarily
/// until post_fork_child_vfork() remaps to the child's own ring.
///
/// # Safety
///
/// The child must not modify parent state except through the documented
/// save/restore protocol. The parent saves MicroState + TLS before clone
/// and restores after clone returns.
pub unsafe fn handle_vfork(cq: &litebox_ipc::ring::CqEntry) -> i64 {
    let micro = global_micro_state_mut();
    let tls = crate::tls::current_tls();

    let central_pid = cq.result as u32;
    let child_pid_from_central = cq.data_offset;
    let child_ring_fd_in_central = cq.data_len as i32;

    // Open the child ring memfd via /proc/<central_pid>/fd/<N>
    let mut path_buf = [0u8; 64];
    format_proc_fd_path(&mut path_buf, central_pid, child_ring_fd_in_central);
    let local_fd = crate::raw_syscall::open(path_buf.as_ptr(), libc::O_RDWR);
    if crate::raw_syscall::is_error(local_fd) {
        return local_fd;
    }
    let local_fd = local_fd as i32;

    // dup2 to well-known fd number so child can find it
    let dup_ret = libc::dup2(local_fd, RESERVED_CHILD_FD);
    if dup_ret < 0 {
        crate::raw_syscall::close(local_fd as i64);
        return -(*libc::__errno_location()) as i64;
    }
    if local_fd != RESERVED_CHILD_FD {
        crate::raw_syscall::close(local_fd as i64);
    }

    // Acquire a stack for the child from the pool
    let stack_pool = crate::state::global_stack_pool();
    let child_stack = match stack_pool.acquire() {
        Some(s) => s,
        None => {
            crate::raw_syscall::close(RESERVED_CHILD_FD as i64);
            return -(libc::ENOMEM as i64);
        }
    };

    // Save parent's MicroState and TLS fields (child will mutate them)
    let saved_ring_base = micro.ring_base;
    let saved_ring_size = micro.ring_size;
    let saved_ring_fd = micro.ring_fd;
    let saved_pid = micro.pid;
    let saved_ppid = micro.ppid;
    let saved_layout = micro.layout;
    let saved_pipe_fds = micro.pipe_fds;
    let saved_thread_slot = (*tls).thread_slot;
    let saved_seq_counter = (*tls).seq_counter;

    // clone(CLONE_VM | CLONE_VFORK | SIGCHLD, child_stack_top)
    // CLONE_VM (0x100): share address space — no page table copy
    // CLONE_VFORK (0x4000): parent blocks until child execve/exit
    // SIGCHLD (17): send SIGCHLD to parent on child exit
    const CLONE_VM: u64 = 0x100;
    const CLONE_VFORK: u64 = 0x4000;
    const SIGCHLD: u64 = 17;
    let flags = CLONE_VM | CLONE_VFORK | SIGCHLD;

    let ret = crate::raw_syscall::syscall2(
        libc::SYS_clone,
        flags,
        child_stack.top() as u64,
    );

    if crate::raw_syscall::is_error(ret) {
        // Clone failed — restore is unnecessary (nothing was mutated),
        // but release the stack and close the fd.
        stack_pool.release(child_stack);
        crate::raw_syscall::close(RESERVED_CHILD_FD as i64);
        return ret;
    }

    if ret == 0 {
        // === CHILD ===
        // We're on the pooled stack, sharing parent's address space.
        // Run post-fork initialization (mmap child ring, update state,
        // send MSG_CHILD_READY). Do NOT munmap parent ring — it would
        // affect the parent's address space.
        post_fork_child_vfork(RESERVED_CHILD_FD, child_pid_from_central);
        // Return 0 — guest sees vfork child returning 0
        return 0;
    }

    // === PARENT (resumed after child's execve/exit) ===
    let child_os_pid = ret;

    // Restore MicroState — child mutated it to point at child ring
    micro.ring_base = saved_ring_base;
    micro.ring_size = saved_ring_size;
    micro.ring_fd = saved_ring_fd;
    micro.pid = saved_pid;
    micro.ppid = saved_ppid;
    micro.layout = saved_layout;

    // Restore TLS
    (*tls).thread_slot = saved_thread_slot;
    (*tls).seq_counter = saved_seq_counter;

    // Clear parent's pipe_fds (same as regular fork — post-fork pipe I/O
    // goes through central to avoid shmem/shim mismatch)
    micro.pipe_fds = saved_pipe_fds;
    // Note: pipe_fds clearing happens in handler.rs for regular fork,
    // but for vfork we do the restore here. Handler.rs will still clear
    // pipe_fds for the parent — that's fine (idempotent).

    // Release the child stack back to the pool.
    // Safe because: CLONE_VFORK guarantees the child has called execve
    // (which replaces the address space, destroying all stack mappings)
    // or _exit before we get here.
    let stack_pool = crate::state::global_stack_pool();
    stack_pool.release(child_stack);

    // Close the reserved fd (child has its own mapping now)
    crate::raw_syscall::close(RESERVED_CHILD_FD as i64);

    child_os_pid
}
```

**Step 2: Add `post_fork_child_vfork()` function**

This is a variant of `post_fork_child()` that does NOT munmap the parent ring:

```rust
/// Post-fork initialization for vfork children (CLONE_VM path).
///
/// Like `post_fork_child()` but does NOT munmap the parent's ring —
/// since CLONE_VM shares the address space, unmapping would affect
/// the parent. The child maps its own ring at a new address. When
/// the child calls execve, the kernel destroys the entire address
/// space (both the parent ring mapping and child ring mapping in
/// the child's view disappear; the parent's mappings are unaffected
/// because execve only affects the calling process).
///
/// # Safety
///
/// Must be called only in the vfork child, on the pooled stack.
unsafe fn post_fork_child_vfork(child_ring_fd: i32, child_pid: u32) {
    let micro = global_micro_state_mut();
    let tls = crate::tls::current_tls();
    let layout = micro.layout;

    // Map the child's ring at a NEW address (don't munmap parent's ring)
    let new_base = crate::raw_syscall::mmap(
        0,  // let kernel choose address
        layout.total_size,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_SHARED,
        child_ring_fd as i64,
        0,
    );
    if new_base == crate::raw_syscall::MAP_FAILED
        || crate::raw_syscall::is_error(new_base)
    {
        // Fatal: can't map child ring. Exit immediately.
        crate::raw_syscall::syscall1(libc::SYS_exit, 127);
        core::hint::unreachable_unchecked();
    }

    // Update MicroState to point at child ring
    micro.ring_base = new_base as *mut u8;
    micro.ring_size = layout.total_size;
    micro.ring_fd = child_ring_fd;
    micro.pid = child_pid;
    micro.ppid = micro.pid; // parent's PID becomes our ppid

    // Clear pipe fd table — parent's shmem pipe offsets are invalid
    // for the child (different data region)
    micro.pipe_fds = [None; litebox_ipc::ring::MAX_PIPE_SLOTS];

    // Reset TLS for child
    (*tls).micro = global_micro_state_ptr();
    (*tls).thread_slot = 0;
    (*tls).seq_counter = 0;

    // Send MSG_CHILD_READY to central on the child's ring
    let cq = crate::local_exec::submit_and_wait(
        tls,
        litebox_ipc::messages::MSG_CHILD_READY,
        [child_pid as u64, 0, 0, 0, 0, 0],
        0,
    );
    let _ = cq;

    // Close the reserved fd — ring is mapped, fd no longer needed
    crate::raw_syscall::close(child_ring_fd as i64);
}
```

**Step 3: Verify it compiles**

Run: `cargo build -p litebox_micro`

**Step 4: Commit**

```bash
git add litebox_micro/src/fork.rs
git commit -m "micro: implement vfork fast-path with clone(CLONE_VM|CLONE_VFORK)"
```

---

## Task 7: Route SYS_vfork to the fast-path

**Files:**
- Modify: `litebox_micro/src/local_exec.rs`
- Modify: `litebox_micro/src/handler.rs`

**Step 1: Update `execute_locally()` in `local_exec.rs`**

Find the vfork dispatch (line ~285) that currently routes to `fork::handle_fork(cq)`. Change it to route to `fork::handle_vfork(cq)`:

```rust
// Before:
libc::SYS_vfork => unsafe { crate::fork::handle_fork(cq) },

// After:
libc::SYS_vfork => unsafe { crate::fork::handle_vfork(cq) },
```

Leave `SYS_fork` and `SYS_clone` (without CLONE_VM) routing to `handle_fork` — we'll promote those later.

**Step 2: Update post-fork handling in `handler.rs`**

The handler at line ~677-695 detects fork children and clears pipe_fds. For vfork, the parent's save/restore in `handle_vfork()` already handles state restoration. But the handler's `is_fork` detection and pipe_fds clearing still runs — we need to make sure it doesn't interfere.

The handler checks `result == 0` to detect the child. For vfork, the child returns 0 from `handle_vfork()`, so `is_fork_child` will be true. The child should skip `report_local_result` — which already happens (line ~693). Good.

For the parent, `result > 0`, and the handler clears `pipe_fds`. But `handle_vfork()` already restored `pipe_fds` from the saved copy. The handler then clears them again — which is the correct behavior (same as regular fork: parent clears pipe_fds post-fork). So no change needed in handler.rs for correctness.

However, verify that `is_fork` correctly includes `SYS_vfork`:

```rust
let is_fork = nr == libc::SYS_fork as u32
    || nr == libc::SYS_vfork as u32
    || (nr == libc::SYS_clone as u32 && args.args[0] & 0x100 == 0);
```

This already includes `SYS_vfork`. No change needed.

**Step 3: Verify it compiles**

Run: `cargo build -p litebox_micro`

**Step 4: Run tests**

Run: `cargo nextest run -p litebox_micro`

**Step 5: Commit**

```bash
git add litebox_micro/src/local_exec.rs litebox_micro/src/handler.rs
git commit -m "micro: route SYS_vfork to vfork fast-path"
```

---

## Task 8: Integration test — vfork + execve

**Files:**
- Modify: `litebox_micro/src/fork.rs` (add test) or use an existing integration test

**Step 1: Test with the shell1 benchmark (functional correctness)**

Run shell1 with a short duration to verify it works:

```bash
cargo build --release -p litebox_micro -p litebox_launcher && cargo build --release -p litebox_central
pkill -9 litebox_central; pkill -9 litebox
cd /workspace/litebox-mu/dev_bench/unixbench
python3 run_unixbench.py --mode micro --release --no-build --duration 10 --iterations 1 --benchmarks shell1
```

If shell1 doesn't use `vfork` (dash uses `fork`), also test with a benchmark that does use vfork, or test manually:

```bash
# Test with a simple vfork-using program if available
# Or test context1 which uses fork+exec patterns:
python3 run_unixbench.py --mode micro --release --no-build --duration 10 --iterations 1 --benchmarks context1
```

**Step 2: Run all non-graphics benchmarks to check for regressions**

```bash
pkill -9 litebox_central; pkill -9 litebox
python3 run_unixbench.py --mode micro --release --no-build --duration 10 --iterations 1 --benchmarks dhry2reg
pkill -9 litebox_central; pkill -9 litebox
python3 run_unixbench.py --mode micro --release --no-build --duration 10 --iterations 1 --benchmarks pipe
pkill -9 litebox_central; pkill -9 litebox
python3 run_unixbench.py --mode micro --release --no-build --duration 10 --iterations 1 --benchmarks syscall
```

**Step 3: Commit if all tests pass**

```bash
git add -A
git commit -m "test: verify vfork fast-path with benchmarks"
```

---

## Task 9: Performance benchmark and tuning

**Step 1: Run shell1 benchmark comparison**

```bash
# Native baseline
cd /workspace/litebox-mu/dev_bench/unixbench
python3 run_unixbench.py --mode native --duration 10 --iterations 1 --benchmarks shell1

# Micro-LiteBox with ring pool + vfork
pkill -9 litebox_central; pkill -9 litebox
python3 run_unixbench.py --mode micro --release --no-build --duration 10 --iterations 1 --benchmarks shell1
```

**Step 2: Compare results**

Previous: 117 lpm (0.094x native)
Target: Significant improvement. The ring pool eliminates memfd_create/ftruncate/mmap per fork. The vfork path (if triggered) eliminates page table copy.

Note: shell1 improvement may be limited since dash uses `fork()` not `vfork()`. The ring pool helps all fork paths though. Full shell1 improvement requires fork-to-vfork promotion (future task).

**Step 3: Document results**

Record benchmark numbers for reference.

---

## Task 10 (Future): Fork-to-vfork promotion

**NOT IMPLEMENTED IN THIS PLAN.** Design note for future work:

After confirming vfork works, promote `SYS_fork` to use the vfork fast-path when the child only does "safe" syscalls (close, dup2, sigaction, sigprocmask) before execve. This is the pattern dash uses, and would give shell1 the full vfork benefit.

Approach: In micro's handler, when `SYS_fork` arrives, speculatively use `clone(CLONE_VM|CLONE_VFORK)`. The child runs on the pooled stack. If it hits execve, great — same as vfork. If it hits a "dangerous" operation (memory write, mmap, etc.), fall back to... TBD (this is the hard part). One option: the child does a real `fork()` at that point to get its own address space, but this is complex. Another option: just accept that the speculative approach only works for the fork+exec pattern and abort if it doesn't match.

This is deferred until vfork is confirmed working and benchmarked.
