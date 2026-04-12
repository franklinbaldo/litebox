# Multi-Threaded Checkpoint/Restore Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Extend checkpoint/restore to capture and restore all threads in a multi-threaded process, not just the checkpointing thread.

**Architecture:** Each sibling thread cooperatively snapshots its own execution context (registers, TLS, signal mask, altstack) into its `ThreadRemote` before parking for checkpoint. The checkpointing thread collects all snapshots into a `Vec<ThreadSnapshot>`. On restore, all threads are recreated via `platform.spawn_thread()`.

**Tech Stack:** Rust, no_std (litebox_shim_linux), custom binary serialization format.

**Known Limitation:** Threads that never make syscalls will never reach the `prepare_to_run_guest` checkpoint and will not self-snapshot. The checkpointing thread will spin forever waiting for `parked_count` to reach the expected value. This affects purely compute-bound threads with no I/O, sleeps, or futex operations. A future fix could use platform-level interrupts (e.g., sending a signal to the OS thread) to force compute-bound threads into the syscall boundary, but that is out of scope for this plan.

---

### Task 1: Add `checkpoint_mode` flag to `VforkParking`

**Files:**
- Modify: `litebox_shim_linux/src/lib.rs:3407-3422` (VforkParking struct)

**Step 1: Add the checkpoint_mode field**

In the `VforkParking` struct at `lib.rs:3407-3422`, add a new field:

```rust
pub(crate) struct VforkParking {
    pub park: <Platform as litebox::platform::RawMutexProvider>::RawMutex,
    pub parked_count: <Platform as litebox::platform::RawMutexProvider>::RawMutex,
    pub deferred_lie_count: core::sync::atomic::AtomicU32,
    /// When true, threads should save their execution state before parking.
    /// Set by the checkpointing thread before parking, cleared on unpark.
    pub checkpoint_mode: core::sync::atomic::AtomicBool,
}
```

**Step 2: Update all `VforkParking` construction sites**

There are two construction sites:
1. `restore_process` in `lib.rs:912-916` — add `checkpoint_mode: AtomicBool::new(false)`
2. Search for any other `VforkParking {` construction sites and update them.

**Step 3: Build to verify no compilation errors**

Run: `cargo build -p litebox_shim_linux --lib 2>&1 | head -20`
Expected: Compilation errors from missing field at construction sites — fix all of them.

**Step 4: Commit**

```
feat(shim): add checkpoint_mode flag to VforkParking
```

---

### Task 2: Add `checkpoint_snapshot` storage to `ThreadRemote`

**Files:**
- Modify: `litebox_shim_linux/src/syscalls/process.rs:147-175` (ThreadRemote struct)
- Modify: `litebox_shim_linux/src/syscalls/fork_snapshot.rs:103-115` (ThreadSnapshot struct)

**Step 1: Add per-thread signal fields to ThreadSnapshot**

In `fork_snapshot.rs`, add `blocked_signals` and `altstack` to `ThreadSnapshot` and a `tid` field:

```rust
pub struct ThreadSnapshot {
    /// Thread ID (for multi-threaded restore).
    pub tid: i32,
    /// Full guest execution context (registers + FP state).
    pub execution_context: litebox_common_linux::ExecutionContext,
    /// Guest TLS base address (FS base on x86-64).
    pub tls_base: Option<usize>,
    /// Address for `CLONE_CHILD_SETTID`.
    pub set_child_tid: Option<usize>,
    /// Address for `CLONE_CHILD_CLEARTID`.
    pub clear_child_tid: Option<usize>,
    /// Robust futex list head pointer.
    pub robust_list: Option<usize>,
    /// Per-thread blocked signal mask.
    pub blocked_signals: litebox_common_linux::signal::SigSet,
    /// Per-thread alternate signal stack.
    pub altstack: litebox_common_linux::signal::SigAltStack,
}
```

**Step 2: Add checkpoint_snapshot to ThreadRemote**

In `process.rs`, add a field to `ThreadRemote`:

```rust
pub(crate) struct ThreadRemote {
    is_exiting: AtomicBool,
    is_suspended: AtomicBool,
    pub(crate) pending_signals: Mutex<Platform, crate::syscalls::signal::PendingSignals>,
    handle: once_cell::race::OnceBox<litebox::event::wait::ThreadHandle<Platform>>,
    /// Saved thread snapshot for multi-threaded checkpoint.
    /// Each sibling thread populates this before parking when checkpoint_mode is set.
    pub(crate) checkpoint_snapshot: Mutex<Platform, Option<super::fork_snapshot::ThreadSnapshot>>,
}
```

Update `ThreadRemote::new()` to initialize the field:

```rust
pub(crate) fn new() -> Self {
    Self {
        is_exiting: AtomicBool::new(false),
        is_suspended: AtomicBool::new(false),
        pending_signals: Mutex::new(crate::syscalls::signal::PendingSignals::new()),
        handle: once_cell::race::OnceBox::new(),
        checkpoint_snapshot: Mutex::new(None),
    }
}
```

**Step 3: Build to verify (will fail due to serialization changes — that's expected)**

Run: `cargo build -p litebox_shim_linux --lib 2>&1 | head -40`
Expected: Errors from ThreadSnapshot construction sites missing new fields.

**Step 4: Commit**

```
feat(shim): add checkpoint_snapshot storage to ThreadRemote and extend ThreadSnapshot
```

---

### Task 3: Update ThreadSnapshot serialization/deserialization

**Files:**
- Modify: `litebox_shim_linux/src/syscalls/fork_snapshot.rs:773-849` (ThreadSnapshot::write/read)
- Modify: `litebox_shim_linux/src/syscalls/fork_snapshot.rs:470-473` (SNAPSHOT_VERSION)

**Step 1: Bump SNAPSHOT_VERSION**

Change `SNAPSHOT_VERSION` from `1` to `2` at `fork_snapshot.rs:473`.

**Step 2: Update ThreadSnapshot::write**

After the existing `robust_list` write (line 810), add:

```rust
// Per-thread signal state (new in v2).
w.write_i32(self.tid);
w.write_u64(self.blocked_signals.as_u64());
// SigAltStack
w.write_usize(self.altstack.sp);
w.write_u32(self.altstack.flags.bits());
w.write_usize(self.altstack.size);
```

**Step 3: Update ThreadSnapshot::read**

After the existing `robust_list` read (line 846), add:

```rust
let tid = r.read_i32()?;
let blocked_signals = SigSet::from_u64(r.read_u64()?);
let alt_sp = r.read_usize()?;
let alt_flags_raw = r.read_u32()?;
let alt_size = r.read_usize()?;
let altstack = litebox_common_linux::signal::SigAltStack {
    sp: alt_sp,
    flags: litebox_common_linux::signal::SsFlags::from_bits_retain(alt_flags_raw),
    #[cfg(target_pointer_width = "64")]
    __pad: 0,
    size: alt_size,
};
```

And update the `Ok(Self { ... })` to include `tid, blocked_signals, altstack`.

**Step 4: Add `write_i32` / `read_i32` to SnapshotWriter/SnapshotReader if they don't exist**

Check if these methods exist. If not, add them (they're trivial — 4-byte LE encoding).

**Step 5: Build to verify**

Run: `cargo build -p litebox_shim_linux --lib 2>&1 | head -40`
Expected: Errors from ThreadSnapshot construction sites — we'll fix those in subsequent tasks.

**Step 6: Commit**

```
feat(shim): update ThreadSnapshot serialization with tid, blocked_signals, altstack (v2)
```

---

### Task 4: Change ForkSnapshot from singular thread to Vec<ThreadSnapshot>

**Files:**
- Modify: `litebox_shim_linux/src/syscalls/fork_snapshot.rs:26-39` (ForkSnapshot struct)
- Modify: `litebox_shim_linux/src/syscalls/fork_snapshot.rs:656-694` (ForkSnapshot serialize/deserialize)
- Modify: `litebox_shim_linux/src/syscalls/fork_snapshot.rs:121-132` (SignalSnapshot — remove per-thread fields)

**Step 1: Change ForkSnapshot.thread to threads**

```rust
pub struct ForkSnapshot {
    pub identity: ProcessIdentitySnapshot,
    pub process_wide: ProcessWideSnapshot,
    /// All thread snapshots. First entry is the checkpointing thread.
    pub threads: Vec<ThreadSnapshot>,
    /// Process-wide signal state (handlers only — blocked mask and altstack
    /// are per-thread and stored in each ThreadSnapshot).
    pub signal: SignalSnapshot,
    pub fs: FsSnapshot,
    pub fd_table: FdTableSnapshot,
    pub memory: MemorySnapshot,
    pub is_delayed_fork: bool,
}
```

**Step 2: Remove blocked and altstack from SignalSnapshot**

```rust
pub struct SignalSnapshot {
    /// Signal handlers (one per signal, indexed by signal number - 1).
    /// These are process-wide (shared across all threads).
    pub handlers: Vec<SignalHandlerSnapshot>,
}
```

Update `SignalSnapshot::write` to remove the blocked/altstack writes.
Update `SignalSnapshot::read` to remove the blocked/altstack reads.

**Step 3: Update ForkSnapshot::serialize**

Replace `self.thread.write(&mut w)` with:

```rust
w.write_u32(self.threads.len() as u32);
for thread in &self.threads {
    thread.write(&mut w);
}
```

**Step 4: Update ForkSnapshot::deserialize**

Replace `thread: ThreadSnapshot::read(&mut r)?` with:

```rust
let thread_count = r.read_u32()? as usize;
let mut threads = Vec::with_capacity(thread_count);
for _ in 0..thread_count {
    threads.push(ThreadSnapshot::read(&mut r)?);
}
```

And use `threads` in the `Ok(Self { ... })`.

**Step 5: Build to see remaining compilation errors**

Run: `cargo build -p litebox_shim_linux --lib 2>&1 | head -60`
Expected: Errors from code accessing `snapshot.thread` (now `snapshot.threads`), `snapshot.signal.blocked`, `snapshot.signal.altstack`.

**Step 6: Commit**

```
feat(shim): change ForkSnapshot to hold Vec<ThreadSnapshot>, process-wide SignalSnapshot
```

---

### Task 5: Update snapshot_signal and snapshot_thread_for_checkpoint

**Files:**
- Modify: `litebox_shim_linux/src/syscalls/process.rs:6267-6326` (snapshot_thread_for_checkpoint, snapshot_signal)

**Step 1: Update snapshot_signal to be process-wide only**

Remove `blocked` and `altstack` from `snapshot_signal`. It should now return only handlers:

```rust
fn snapshot_signal(&self) -> super::fork_snapshot::SignalSnapshot {
    let handlers = self.signals.snapshot_handlers();
    super::fork_snapshot::SignalSnapshot { handlers }
}
```

**Step 2: Update snapshot_thread_for_checkpoint to include tid, blocked, altstack**

Add the new fields to the returned `ThreadSnapshot`:

```rust
fn snapshot_thread_for_checkpoint(
    &self,
    ctx: &litebox_common_linux::ExecutionContext,
) -> super::fork_snapshot::ThreadSnapshot {
    // ... existing TLS, clear_child_tid, robust_list, exec_ctx rewind code ...

    super::fork_snapshot::ThreadSnapshot {
        tid: self.tid,
        execution_context: exec_ctx,
        tls_base,
        set_child_tid: None,
        clear_child_tid,
        robust_list,
        blocked_signals: self.signals.get_blocked(),
        altstack: self.signals.altstack(),
    }
}
```

**Step 3: Update all other ThreadSnapshot construction sites**

Search for `ThreadSnapshot {` across fork_snapshot.rs and process.rs. Every construction site needs `tid`, `blocked_signals`, and `altstack` fields. For the true-fork path (non-checkpoint), use the calling thread's blocked mask and altstack.

**Step 4: Build to verify**

Run: `cargo build -p litebox_shim_linux --lib 2>&1 | head -40`

**Step 5: Commit**

```
feat(shim): update snapshot_signal and snapshot_thread_for_checkpoint for multi-thread
```

---

### Task 6: Update checkpoint_to_file to collect all thread snapshots

**Files:**
- Modify: `litebox_shim_linux/src/syscalls/process.rs:6069-6153` (checkpoint_to_file)
- Modify: `litebox_shim_linux/src/syscalls/process.rs:6819-6921` (park_other_threads — set checkpoint_mode)

**Step 1: Add checkpoint_mode setting to park_other_threads flow**

Create a new method `park_other_threads_for_checkpoint` that wraps `park_other_threads` and sets checkpoint_mode before parking. Or, modify `checkpoint_to_file` to set checkpoint_mode on VforkParking before calling `park_other_threads`:

In `checkpoint_to_file`, before the `park_other_threads` call:

```rust
// Set checkpoint mode so sibling threads save their state before parking.
{
    let ps = self.process_state.borrow();
    ps.vfork_parking.checkpoint_mode.store(true, Ordering::Release);
}

let did_park = self.park_other_threads().unwrap_or(false);
```

**Step 2: Collect sibling thread snapshots**

After `park_other_threads` returns (all siblings are parked and have saved their state), collect their snapshots:

```rust
let mut threads = Vec::new();

// Add checkpointing thread's snapshot first.
threads.push(self.snapshot_thread_for_checkpoint(ctx));

// Collect sibling thread snapshots from ThreadRemote.
if did_park {
    let inner = self.thread.process.inner.lock();
    for (&tid, thread_remote) in &inner.threads {
        if tid != self.tid {
            let mut snapshot_slot = thread_remote.checkpoint_snapshot.lock();
            if let Some(snapshot) = snapshot_slot.take() {
                threads.push(snapshot);
            } else {
                litebox::log_println!(
                    self.global.platform,
                    "[CHECKPOINT] pid={}: sibling tid={} did not save snapshot",
                    self.pid,
                    tid,
                );
            }
        }
    }
    drop(inner);
}
```

**Step 3: Update ForkSnapshot construction**

Replace `thread: self.snapshot_thread_for_checkpoint(ctx)` with `threads`:

```rust
let snapshot = ForkSnapshot {
    identity,
    process_wide,
    threads,
    signal,
    fs,
    fd_table,
    memory,
    is_delayed_fork: true,
};
```

**Step 4: Clear checkpoint_mode in unpark**

In `unpark_other_threads` (process.rs:6929-6992), clear `checkpoint_mode` before clearing the park flag:

```rust
// Clear checkpoint mode.
ps.vfork_parking.checkpoint_mode.store(false, Ordering::Release);
```

Note: For checkpoint, we actually call `exit_group` so unpark doesn't happen. But clear it anyway for correctness if checkpoint is rejected and threads are unparked.

**Step 5: Build to verify**

Run: `cargo build -p litebox_shim_linux --lib 2>&1 | head -40`

**Step 6: Commit**

```
feat(shim): collect all thread snapshots in checkpoint_to_file
```

---

### Task 7: Make sibling threads self-snapshot when parking for checkpoint

**Files:**
- Modify: `litebox_shim_linux/src/wait.rs:111-210` (park_for_vfork_if_requested)
- Modify: `litebox_shim_linux/src/wait.rs:38-96` (prepare_to_run_guest — pass ctx)

**Step 1: Pass ExecutionContext to park_for_vfork_if_requested**

Currently `park_for_vfork_if_requested` takes `&self`. It needs access to the thread's `ExecutionContext` to snapshot it. Change the signature:

```rust
pub(crate) fn park_for_vfork_if_requested(
    &self,
    ctx: &litebox_common_linux::ExecutionContext,
) {
```

Update the call site in `prepare_to_run_guest` to pass `ctx`.

**Step 2: Add checkpoint self-snapshot logic**

After the fast-path check (line 158), before incrementing `parked_count` (line 182), add checkpoint self-snapshot:

```rust
// If checkpoint mode is active, save our execution state before parking.
if ps.vfork_parking.checkpoint_mode.load(Ordering::Acquire) {
    let snapshot = self.snapshot_thread_for_checkpoint(ctx);
    let inner = self.thread.process.inner.lock();
    if let Some(remote) = inner.threads.get(&self.tid) {
        *remote.checkpoint_snapshot.lock() = Some(snapshot);
    }
    drop(inner);
}
```

This must happen BEFORE incrementing `parked_count`, so the checkpointing thread sees the snapshot when it wakes up.

The same logic should be added to the deferred-lie path (lines 124-143) if checkpoint_mode is active — though in practice, deferred lies happen in the transport layer which may not have access to ctx. For now, add it to the normal park path only. Document this as a limitation if deferred lies can occur during checkpoint.

**Step 3: Handle the deferred_vfork_park path**

For the deferred park path (lines 124-143), the thread entered from a transport spin loop and doesn't have its execution context readily available in the same form. For now, skip self-snapshot in the deferred path — this is safe because deferred lies are about transport-layer parking, and checkpoint_mode is only set briefly. If a thread has a deferred lie, it will be settled before reaching the normal park check where it can self-snapshot.

**Step 4: Make snapshot_thread_for_checkpoint accessible from Task**

Currently it's defined in the `impl` block that handles syscalls. It needs to be callable from `wait.rs` context (which has `&self` as `Task`). Check if it's already accessible. If not, move it or add a forwarding method.

`snapshot_thread_for_checkpoint` is on the `Task` impl in process.rs — since `wait.rs` also has access to `Task` (via `impl<FS: ShimFS> Task<FS>`), it should be callable. Verify by checking the module visibility. The method is `fn snapshot_thread_for_checkpoint` (no `pub`) — it may need `pub(crate)`.

**Step 5: Build and fix any visibility issues**

Run: `cargo build -p litebox_shim_linux --lib 2>&1 | head -40`

**Step 6: Commit**

```
feat(shim): sibling threads self-snapshot before parking in checkpoint mode
```

---

### Task 8: Update restore_process to restore multiple threads

**Files:**
- Modify: `litebox_shim_linux/src/lib.rs:598-1230` (restore_process)

This is the most complex task. Currently `restore_process` creates one `Task` and returns it as `LoadedProgram.entrypoints`. For multi-thread, it needs to:

1. Pick the first thread snapshot as the "main" thread (runs synchronously on the initial OS thread).
2. For each additional thread, create a `Task` and spawn it via `platform.spawn_thread()`.

**Step 1: Change restore_process to handle Vec<ThreadSnapshot>**

Replace `let th = &snapshot.thread;` with:

```rust
let threads = &snapshot.threads;
assert!(!threads.is_empty(), "snapshot must have at least one thread");
let main_thread = &threads[0]; // First thread is the checkpointing thread
```

**Step 2: Build the main thread as before**

Use `main_thread` everywhere `th` was used (identity, process state, thread state, etc). The main difference: signal blocked mask and altstack now come from `main_thread.blocked_signals` and `main_thread.altstack` instead of `snapshot.signal.blocked` and `snapshot.signal.altstack`.

```rust
// Signal state for the main thread.
let rebased_altstack = /* rebase main_thread.altstack */;
let child_signals = syscalls::signal::SignalState::new_from_restore(
    main_thread.blocked_signals,
    &sig.handlers,
    rebased_altstack,
);
```

**Step 3: Create the Process with correct thread count**

Change `thread_count: AtomicI32::new(1)` to:

```rust
thread_count: AtomicI32::new(threads.len() as i32),
```

And add all thread remotes to the `ProcessInner.threads` BTreeMap upfront:

```rust
// Create ThreadRemote for each thread.
let mut thread_remotes = Vec::with_capacity(threads.len());
let mut threads_map = BTreeMap::new();
for th in threads {
    let remote = Arc::new(syscalls::process::ThreadRemote::new());
    threads_map.insert(th.tid, remote.clone());
    thread_remotes.push(remote);
}

let child_process = Arc::new(syscalls::process::Process::new_with_rlimits_and_threads(
    id.pid,
    threads_map,
    &pw.rlimits,
    pw.thp_disabled,
));
```

This requires a new constructor `Process::new_with_rlimits_and_threads` that takes a pre-built `BTreeMap<i32, Arc<ThreadRemote>>` instead of a single remote. Add it near `new_with_rlimits` (process.rs:243-271).

**Step 4: Build the main Task as today**

Use `thread_remotes[0]` for the main thread's remote.

**Step 5: Spawn additional threads**

After building the main task and setting its init state, for each additional thread snapshot:

```rust
for (i, th) in threads.iter().enumerate().skip(1) {
    let sibling_remote = thread_remotes[i].clone();

    let sibling_thread = syscalls::process::ThreadState::new_from_restore(
        th.tid,
        child_process.clone(),
        sibling_remote,
        th.clear_child_tid.map(rb),
        th.robust_list.map(rb),
    );

    // Build per-thread signal state.
    let sibling_altstack = /* rebase th.altstack */;
    let sibling_signals = syscalls::signal::SignalState::new_from_restore(
        th.blocked_signals,
        &sig.handlers,  // handlers are shared (process-wide)
        sibling_altstack,
    );

    // Build execution context.
    let mut sibling_exec_ctx = th.execution_context.clone();
    if va_rebase != 0 {
        // Rebase address-valued registers (same as main thread).
        #[cfg(target_arch = "x86_64")]
        {
            let rb_reg = |v: usize| (v as isize + va_rebase) as usize;
            sibling_exec_ctx.regs.rip = rb_reg(sibling_exec_ctx.regs.rip);
            sibling_exec_ctx.regs.rsp = rb_reg(sibling_exec_ctx.regs.rsp);
            sibling_exec_ctx.regs.rbp = rb_reg(sibling_exec_ctx.regs.rbp);
            sibling_exec_ctx.regs.rcx = rb_reg(sibling_exec_ctx.regs.rcx);
            sibling_exec_ctx.regs.r11 = rb_reg(sibling_exec_ctx.regs.r11);
        }
    }

    sibling_thread.init_state.set(
        syscalls::process::ThreadInitState::ForkRestore {
            exec_ctx: Box::new(sibling_exec_ctx),
            tls_base: th.tls_base.map(rb),
            set_child_tid: th.set_child_tid.map(rb),
        },
    );

    // Build the sibling Task.
    let sibling_task = Task {
        global: self.global.clone(),
        process_state: child_process_state.clone().into(),
        thread: sibling_thread,
        wait_state: wait::WaitState::new(self.global.platform),
        process_id: litebox::process::ProcessId::INIT,
        pid: id.pid,       // same PID (same process)
        ppid: id.ppid,
        tid: th.tid,
        credentials: child_credentials.clone(),
        comm: Cell::new(comm),
        fs: child_fs.clone().into(),
        files: child_files.clone().into(),
        signals: sibling_signals,
        fork_context: RefCell::new(None),
        last_shell_write: RefCell::new(None),
        last_syscall: Cell::new(None),
        syscall_restartable: Cell::new(false),
        in_syscall: Cell::new(false),
        deferred_vfork_park: Cell::new(false),
        delayed_fork_pending: Cell::new(false),
        migrated_to_remote: Cell::new(false),
        mux_pipe_pair_ids: RefCell::new(Vec::new()),
        checkpoint_requested: Cell::new(false),
    };

    // Spawn the sibling thread on a new OS thread.
    let spawn_ctx = litebox_common_linux::ExecutionContext::default();
    unsafe {
        self.global.platform.spawn_thread(
            &spawn_ctx,
            Box::new(NewThreadArgs { task: sibling_task }),
        ).expect("failed to spawn restored sibling thread");
    }
}
```

Note: `NewThreadArgs` is the struct that implements `InitThread`. Check its definition to ensure it's accessible from `restore_process`. It's used in `do_clone` at process.rs:1973.  Look for `struct NewThreadArgs` — it likely wraps a `Task` and implements `InitThread`. It may be in process.rs or lib.rs.

Also note: `child_fs` and `child_files` must be wrapped in `RefCell` properly (they're `RefCell<Arc<...>>` in the Task struct). The main thread builds them as `child_fs.into()` — for sibling threads, clone the `Arc` and wrap similarly.

**Step 6: Ensure shared_pending is shared across all threads' SignalState**

Currently `SignalState::new_from_restore` creates a fresh `shared_pending: Arc::new(Mutex::new(PendingSignals::new()))`. For multi-thread, all threads must share the same `shared_pending`. Either:
- Create one `shared_pending` Arc upfront and pass it to each SignalState, or
- Add a `new_from_restore_with_shared` constructor.

The simplest approach: build the main thread's `SignalState` first, then for siblings call `clone_for_new_task()` style construction but with the restored blocked mask and altstack. Or just add a parameter.

**Step 7: Build and fix all compilation errors**

Run: `cargo build -p litebox_shim_linux --lib 2>&1 | head -80`

**Step 8: Commit**

```
feat(shim): restore multiple threads from checkpoint snapshot
```

---

### Task 9: Update true-fork snapshot path for new ThreadSnapshot fields

**Files:**
- Modify: `litebox_shim_linux/src/syscalls/process.rs` — `snapshot_thread` (the true-fork version, used by `do_fork`/`snapshot_for_delayed_fork`)

**Step 1: Find all ThreadSnapshot construction sites outside checkpoint**

Search for `ThreadSnapshot {` in process.rs and fork_snapshot.rs. The true-fork path has its own `snapshot_thread` method that creates ThreadSnapshot for the fork child. Update it to include `tid`, `blocked_signals`, and `altstack`.

For true fork, the child is always single-threaded (POSIX semantics), so `tid` = child pid, `blocked_signals` = calling thread's blocked mask, `altstack` = calling thread's altstack.

**Step 2: Update snapshot_for_delayed_fork if it constructs ThreadSnapshot directly**

Check if `snapshot_for_delayed_fork` uses `snapshot_thread` or constructs ThreadSnapshot directly. Update accordingly.

**Step 3: Update the ForkSnapshot construction in the true-fork path**

Change `thread: snapshot` to `threads: vec![snapshot]`. The true-fork path should now wrap the single ThreadSnapshot in a Vec.

Also update `signal` to not include `blocked`/`altstack`:

```rust
let signal = SignalSnapshot { handlers };
```

**Step 4: Build and verify**

Run: `cargo build -p litebox_shim_linux --lib 2>&1 | head -40`

**Step 5: Run existing tests**

Run: `cargo test -p litebox_shim_linux --lib 2>&1 | tail -20`
(Note: some tests are pre-broken — focus on new regressions.)

Run: `cargo test -p litebox_runner_oci 2>&1 | tail -20`
Expected: 62/62 passing.

**Step 6: Commit**

```
feat(shim): update true-fork path for new ThreadSnapshot and SignalSnapshot layout
```

---

### Task 10: Update restore_process for true-fork (single-thread) backward compat

**Files:**
- Modify: `litebox_shim_linux/src/lib.rs:598-1230` (restore_process)

**Step 1: Verify restore_process works for single-thread snapshots**

The true-fork path now produces `threads: vec![single_thread]`. Verify that `restore_process` handles this correctly (it should — `threads[0]` is the main thread, `threads.iter().skip(1)` is empty so no siblings are spawned).

**Step 2: Build and run OCI tests**

Run: `cargo test -p litebox_runner_oci 2>&1 | tail -20`
Expected: 62/62 passing.

**Step 3: Commit if any fixes were needed**

```
fix(shim): ensure single-thread fork snapshots work with Vec<ThreadSnapshot>
```

---

### Task 11: Fix all cargo clippy warnings

**Files:**
- All modified crates

**Step 1: Run clippy on all modified crates**

```bash
cargo clippy -p litebox_shim_linux --lib -- -D warnings 2>&1 | head -40
cargo clippy -p litebox_runner_oci -- -D warnings 2>&1 | head -40
```

**Step 2: Fix any warnings**

**Step 3: Commit**

```
fix: resolve clippy warnings from multi-thread checkpoint changes
```

---

### Task 12: End-to-end test with multi-threaded program

**Step 1: Create a simple multi-threaded C program**

Write a small C program that spawns 2-3 threads, each doing periodic I/O (e.g., writing to a file or sleeping in a loop). Compile it statically for Alpine.

**Step 2: Test checkpoint**

```bash
# Run the multi-threaded program in a container
podman run -d --name mt-test alpine /path/to/mt-program

# Checkpoint
litebox-oci checkpoint --image-path /tmp/mt-ckpt $CID
```

Verify the checkpoint image is created and contains multiple thread snapshots (check the serialized size — should be noticeably larger than single-thread).

**Step 3: Test restore**

```bash
# Remount overlay, then restore
litebox-oci restore --bundle $BUNDLE --image-path /tmp/mt-ckpt restored-mt
```

Verify all threads resume and produce expected output.

**Step 4: Commit any fixes discovered during testing**

---

## Summary of files modified

| File | Changes |
|------|---------|
| `litebox_shim_linux/src/lib.rs` | VforkParking: add `checkpoint_mode`. restore_process: handle Vec<ThreadSnapshot>, spawn sibling threads. |
| `litebox_shim_linux/src/syscalls/fork_snapshot.rs` | ThreadSnapshot: add `tid`, `blocked_signals`, `altstack`. ForkSnapshot: `thread` → `threads: Vec`. SignalSnapshot: remove `blocked`, `altstack`. Bump SNAPSHOT_VERSION. Update serialize/deserialize. |
| `litebox_shim_linux/src/syscalls/process.rs` | ThreadRemote: add `checkpoint_snapshot`. checkpoint_to_file: set checkpoint_mode, collect all snapshots. snapshot_signal: process-wide only. snapshot_thread_for_checkpoint: add new fields. unpark_other_threads: clear checkpoint_mode. Add `Process::new_with_rlimits_and_threads`. |
| `litebox_shim_linux/src/wait.rs` | park_for_vfork_if_requested: take `ctx` param, self-snapshot in checkpoint mode. |
