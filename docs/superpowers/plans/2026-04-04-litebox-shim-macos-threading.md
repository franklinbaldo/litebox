# macOS Shim Threading Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add full pthread support to the macOS shim so dynamically linked programs can create, join, and terminate threads via `pthread_create`/`pthread_join`.

**Architecture:** Implement `bsdthread_register` (one-time pthread library registration), `bsdthread_create` (thread creation via `platform.spawn_thread()`), `bsdthread_terminate` (thread exit + cleanup), and `bsdthread_ctl` (thread control stubs). Refactor `Task` from single-threaded (`Cell`/`RefCell`) to multi-threaded (`Arc<Process>` + per-thread state). Follow the Linux shim's proven pattern: shared `Process` via `Arc`, per-thread `Task`, `NewThreadArgs` implementing `InitThread`.

**Tech Stack:** Rust, macOS aarch64 BSD syscall ABI, `litebox` platform threading traits (`ThreadProvider`, `InitThread`, `EnterShim`)

---

### Task 1: Add bsdthread syscall numbers and enum variants

**Files:**
- Modify: `litebox_common_macos/src/syscall.rs`

- [ ] **Step 1: Add syscall number constants**

Add to `pub mod nr` in `litebox_common_macos/src/syscall.rs` (after the existing constants, before the closing `}`):

```rust
    pub const BSDTHREAD_CREATE: usize = 360;
    pub const BSDTHREAD_TERMINATE: usize = 361;
    pub const BSDTHREAD_REGISTER: usize = 366;
    pub const BSDTHREAD_CTL: usize = 478;
```

- [ ] **Step 2: Add enum variants to `MacosSyscallRequest`**

Add before the `Unknown` variant in `MacosSyscallRequest`:

```rust
    /// `bsdthread_register(threadstart, wqthread, pthsize, pthread_init_data, pthread_init_data_size, dispatchqueue_offset, tsd_offset)`
    BsdthreadRegister {
        threadstart: usize,
        wqthread: usize,
        pthsize: u32,
        pthread_init_data: usize,
        pthread_init_data_size: usize,
    },
    /// `bsdthread_create(func, func_arg, stack, pthread, flags)`
    BsdthreadCreate {
        func: usize,
        func_arg: usize,
        stack: usize,
        pthread: usize,
        flags: u32,
    },
    /// `bsdthread_terminate(stackaddr, freesize, port, sema_or_ulock)`
    BsdthreadTerminate {
        stackaddr: usize,
        freesize: usize,
        port: u32,
        sema_or_ulock: usize,
    },
    /// `bsdthread_ctl(cmd, arg1, arg2, arg3)`
    BsdthreadCtl {
        cmd: usize,
        arg1: usize,
        arg2: usize,
        arg3: usize,
    },
```

- [ ] **Step 3: Add decoding arms to `try_from_raw`**

Add to the positive-syscall match in `try_from_raw`, before the `_ =>` default arm:

```rust
            nr::BSDTHREAD_REGISTER => Self::BsdthreadRegister {
                threadstart: a0,
                wqthread: a1,
                pthsize: a2 as u32,
                pthread_init_data: a3,
                pthread_init_data_size: a4,
            },
            nr::BSDTHREAD_CREATE => Self::BsdthreadCreate {
                func: a0,
                func_arg: a1,
                stack: a2,
                pthread: a3,
                flags: a4 as u32,
            },
            nr::BSDTHREAD_TERMINATE => Self::BsdthreadTerminate {
                stackaddr: a0,
                freesize: a1,
                port: a2 as u32,
                sema_or_ulock: a3,
            },
            nr::BSDTHREAD_CTL => Self::BsdthreadCtl {
                cmd: a0,
                arg1: a1,
                arg2: a2,
                arg3: a3,
            },
```

- [ ] **Step 4: Verify it compiles**

Run: `cargo check -p litebox_common_macos`
Expected: compiles with no errors

- [ ] **Step 5: Commit**

```
feat(litebox_common_macos): add bsdthread syscall numbers and enum variants
```

---

### Task 2: Refactor Task to support multi-threading

Replace the single-threaded `Task` with a multi-threaded design: shared `Process` (via `Arc`) + per-thread `Task`. This follows the Linux shim's pattern.

**Files:**
- Modify: `litebox_shim_macos/src/lib.rs`
- Modify: `litebox_shim_macos/src/syscalls/process.rs`
- Modify: `litebox_shim_macos/src/syscalls/stubs.rs`
- Modify: `litebox_shim_macos/src/syscalls/mm.rs`
- Modify: `litebox_shim_macos/src/syscalls/file.rs`
- Modify: `litebox_shim_macos/src/syscalls/mod.rs`

- [ ] **Step 1: Add `Process` struct and thread-init state to `lib.rs`**

Add below the existing imports in `litebox_shim_macos/src/lib.rs`:

```rust
use std::sync::Mutex;

/// Per-thread initialization state, set before the thread is resumed.
#[derive(Default)]
enum ThreadInitState {
    #[default]
    None,
    /// A new thread created via `bsdthread_create`.
    BsdThread {
        /// Address of the `_thread_start` trampoline (from bsdthread_register).
        threadstart: usize,
        /// User's start function pointer.
        func: usize,
        /// User's function argument.
        func_arg: usize,
        /// Stack top (SP will be set to this).
        stack: usize,
        /// Address of the pthread_t struct.
        pthread: usize,
        /// Combined flags|policy|importance.
        flags: u32,
        /// Mach thread port for this thread.
        mach_port: u32,
        /// Offset from pthread_t base to TSD array.
        tsd_offset: u32,
    },
}

/// Shared process state, accessible from all threads via `Arc`.
struct Process {
    /// Number of live threads. When this reaches 0, the process has exited.
    nr_threads: AtomicI32,
    /// Process exit code.
    exit_code: AtomicI32,
    /// Whether a group exit has been initiated (exit() as opposed to
    /// bsdthread_terminate for a single thread).
    group_exit: AtomicBool,
    /// Address of the `_thread_start` asm trampoline, registered once by
    /// libpthread via `bsdthread_register`. Zero if not yet registered.
    threadstart: AtomicU64,
    /// Address of the `_start_wqthread` asm trampoline.
    wqthread: AtomicU64,
    /// Size of the pthread struct (`pthsize`).
    pthsize: AtomicU32,
    /// Offset from pthread_t to TSD base (set by bsdthread_register).
    tsd_offset: AtomicU32,
}

impl Process {
    fn new() -> Self {
        Self {
            nr_threads: AtomicI32::new(1),
            exit_code: AtomicI32::new(0),
            group_exit: AtomicBool::new(false),
            threadstart: AtomicU64::new(0),
            wqthread: AtomicU64::new(0),
            pthsize: AtomicU32::new(0),
            tsd_offset: AtomicU32::new(0),
        }
    }
}
```

- [ ] **Step 2: Refactor `Task` struct**

Replace the existing `Task` struct with:

```rust
/// Per-thread task state.
struct Task<FS: ShimFS> {
    global: Arc<GlobalState<FS>>,
    /// Shared process state.
    process: Arc<Process>,
    /// Thread ID for this thread.
    tid: i32,
    /// Whether this thread has been terminated.
    terminated: AtomicBool,
    /// Per-fd patch state for the mmap-hook.
    patch_cache: Mutex<BTreeMap<i32, MachoPatchState>>,
    /// Initialization state for this thread (set before first entry).
    init_state: Mutex<ThreadInitState>,
}
```

- [ ] **Step 3: Update `should_terminate`**

```rust
fn should_terminate(&self) -> bool {
    self.terminated.load(Ordering::Acquire) || self.process.group_exit.load(Ordering::Acquire)
}
```

- [ ] **Step 4: Update `sys_exit` in `process.rs`**

`sys_exit` should initiate a group exit (all threads terminate):

```rust
pub(crate) fn sys_exit(&self, status: i32) {
    self.process.exit_code.store(status, Ordering::Release);
    self.process.group_exit.store(true, Ordering::Release);
    self.terminated.store(true, Ordering::Release);
}
```

- [ ] **Step 5: Update `handle_init_request`**

```rust
fn handle_init_request(&self, ctx: &mut PtRegs) {
    let state = {
        let mut guard = self.init_state.lock().unwrap();
        core::mem::take(&mut *guard)
    };
    match state {
        ThreadInitState::None => {}
        ThreadInitState::BsdThread {
            threadstart,
            func,
            func_arg,
            stack,
            pthread,
            flags,
            mach_port,
            tsd_offset,
        } => {
            // Set up registers per the macOS bsdthread ABI:
            // PC = _thread_start, SP = stack
            // x0 = pthread_t, x1 = mach_port, x2 = func, x3 = arg,
            // x4 = stack, x5 = flags
            ctx.pc = threadstart;
            ctx.sp = stack;
            ctx.regs[0] = pthread;
            ctx.regs[1] = mach_port as usize;
            ctx.regs[2] = func;
            ctx.regs[3] = func_arg;
            ctx.regs[4] = stack;
            ctx.regs[5] = flags as usize;

            // Set TSD base if tsd_offset is known.
            if tsd_offset > 0 {
                let tsd_base = pthread + tsd_offset as usize;
                let punchthrough =
                    litebox_common_linux::PunchthroughSyscall::SetTpidr { value: tsd_base };
                let token = self
                    .global
                    .platform
                    .get_punchthrough_token_for(punchthrough)
                    .expect("Failed to get punchthrough token for SetTpidr");
                token.execute().map(|_| ()).unwrap();
            }
        }
    }
}
```

- [ ] **Step 6: Update `MacosShimEntrypoints` — remove `_not_send`**

```rust
pub struct MacosShimEntrypoints<FS: ShimFS> {
    task: Task<FS>,
}
```

Remove the `PhantomData<*const ()>` field. The `Task` is now `Send` + `Sync` since it uses `AtomicBool`/`Mutex` instead of `Cell`/`RefCell`.

- [ ] **Step 7: Update `MacosShimProcess`**

Change from wrapping `Arc<AtomicI32>` to wrapping `Arc<Process>`:

```rust
pub struct MacosShimProcess(Arc<Process>);

impl MacosShimProcess {
    pub fn exit_code(&self) -> i32 {
        self.0.exit_code.load(Ordering::Acquire)
    }

    /// Wait for the process to exit.
    ///
    /// In phase 3 (multi-threaded), this spins until `group_exit` is set
    /// or `nr_threads` reaches 0.
    pub fn wait(&self) -> i32 {
        loop {
            if self.0.group_exit.load(Ordering::Acquire) {
                return self.0.exit_code.load(Ordering::Acquire);
            }
            if self.0.nr_threads.load(Ordering::Acquire) <= 0 {
                return self.0.exit_code.load(Ordering::Acquire);
            }
            std::thread::yield_now();
        }
    }
}
```

- [ ] **Step 8: Update `load_program` to create `Process`**

Replace the `exit_code` creation and `Task` construction:

```rust
let process = Arc::new(Process::new());
let entrypoints = MacosShimEntrypoints {
    task: Task {
        global: self.0.clone(),
        process: process.clone(),
        tid: 1,
        terminated: AtomicBool::new(false),
        patch_cache: Mutex::new(BTreeMap::new()),
        init_state: Mutex::new(ThreadInitState::None),
    },
};
// ... (rest unchanged)
Ok(LoadedProgram {
    entrypoints,
    process: MacosShimProcess(process),
    initial_ctx,
})
```

- [ ] **Step 9: Update all `Cell`/`RefCell` accesses in syscall handlers**

In `mm.rs` — change `self.patch_cache.borrow()` → `self.patch_cache.lock().unwrap()` and `self.patch_cache.borrow_mut()` → `self.patch_cache.lock().unwrap()`.

In `process.rs` — `self.terminated.set(true)` → `self.terminated.store(true, Ordering::Release)`.

In `stubs.rs` — `sys_thread_selfid` should return the per-thread `tid`:
```rust
pub(crate) fn sys_thread_selfid(&self) -> Result<usize, Errno> {
    Ok(self.tid as usize)
}
```

- [ ] **Step 10: Verify it compiles and existing tests pass**

Run: `cargo test -p litebox_runner_macos_on_macos_userland -- --nocapture`
Expected: 5 passed (including `test_hello_dynamic`), 1 ignored, 0 failed

- [ ] **Step 11: Commit**

```
refactor(litebox_shim_macos): make Task multi-thread capable with shared Process
```

---

### Task 3: Implement bsdthread_register syscall

**Files:**
- Modify: `litebox_shim_macos/src/syscalls/mod.rs`
- Modify: `litebox_shim_macos/src/syscalls/stubs.rs`

- [ ] **Step 1: Add dispatch arm in `mod.rs`**

Add to the `do_syscall` match, before the `Unknown` arm:

```rust
MacosSyscallRequest::BsdthreadRegister {
    threadstart,
    wqthread,
    pthsize,
    pthread_init_data,
    pthread_init_data_size,
} => self
    .sys_bsdthread_register(
        threadstart,
        wqthread,
        pthsize,
        pthread_init_data,
        pthread_init_data_size,
    )
    .map(|v| v as usize),
```

- [ ] **Step 2: Implement `sys_bsdthread_register` in `stubs.rs`**

```rust
/// Handle `bsdthread_register` — one-time pthread library registration.
///
/// Stores the `_thread_start` trampoline address and pthread struct size
/// in the shared `Process` so that future `bsdthread_create` calls know
/// where to set new threads' PC and how to find TSD.
///
/// # Arguments
/// - `threadstart`: address of `_thread_start` asm trampoline
/// - `wqthread`: address of `_start_wqthread` asm trampoline
/// - `pthsize`: `sizeof(struct pthread_s)`
/// - `pthread_init_data`: pointer to `_pthread_registration_data` struct
/// - `pthread_init_data_size`: size of the registration data struct
pub(crate) fn sys_bsdthread_register(
    &self,
    threadstart: usize,
    wqthread: usize,
    pthsize: u32,
    pthread_init_data: usize,
    pthread_init_data_size: usize,
) -> Result<i32, Errno> {
    use core::sync::atomic::Ordering;

    log_unsupported!(
        "bsdthread_register(threadstart={threadstart:#x}, wqthread={wqthread:#x}, \
         pthsize={pthsize}, init_data={pthread_init_data:#x}, init_data_size={pthread_init_data_size})"
    );

    self.process
        .threadstart
        .store(threadstart as u64, Ordering::Release);
    self.process
        .wqthread
        .store(wqthread as u64, Ordering::Release);
    self.process.pthsize.store(pthsize, Ordering::Release);

    // Parse the _pthread_registration_data struct to extract tsd_offset.
    // Layout (from xnu/bsd/pthread/bsdthread_private.h):
    //   uint64_t version;                // offset 0
    //   uint64_t dispatch_queue_offset;  // offset 8
    //   /* ... more fields ... */
    // The tsd_offset field is at offset 16 in the struct.
    if pthread_init_data != 0 && pthread_init_data_size >= 24 {
        let pm = &self.global.pm;
        // Read tsd_offset at offset 16 (8 bytes)
        let tsd_offset_bytes: [u8; 8] = pm
            .read_bytes(pthread_init_data + 16)
            .ok_or(Errno::EFAULT)?;
        let tsd_offset = u64::from_le_bytes(tsd_offset_bytes) as u32;
        self.process.tsd_offset.store(tsd_offset, Ordering::Release);
        log_unsupported!("bsdthread_register: tsd_offset={tsd_offset:#x}");

        // Write back the reply data if the struct is large enough.
        // The kernel writes back version, main_qos, stack_addr_hint, etc.
        // For now, write version = size (indicating we support the struct).
        let version_bytes = (pthread_init_data_size as u64).to_le_bytes();
        let _ = pm.write_bytes(pthread_init_data, &version_bytes);
    }

    // Return PTHREAD_FEATURE_SUPPORTED flags.
    // Bit 0x01 = QoS support. Return 0 for minimal support.
    Ok(0)
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check -p litebox_shim_macos`

- [ ] **Step 4: Commit**

```
feat(litebox_shim_macos): implement bsdthread_register syscall
```

---

### Task 4: Implement bsdthread_create syscall

**Files:**
- Modify: `litebox_shim_macos/src/lib.rs`
- Modify: `litebox_shim_macos/src/syscalls/mod.rs`
- Modify: `litebox_shim_macos/src/syscalls/stubs.rs`

- [ ] **Step 1: Add `NewThreadArgs` and `InitThread` impl in `lib.rs`**

```rust
/// Arguments for spawning a new macOS thread.
struct NewThreadArgs<FS: ShimFS> {
    task: Task<FS>,
}

impl<FS: ShimFS> litebox::shim::InitThread for NewThreadArgs<FS> {
    type ExecutionContext = litebox_common_linux::PtRegs;

    fn init(
        self: Box<Self>,
    ) -> Box<dyn litebox::shim::EnterShim<ExecutionContext = Self::ExecutionContext>> {
        let Self { task } = *self;
        Box::new(MacosShimEntrypoints { task })
    }
}
```

- [ ] **Step 2: Add a next-thread-id counter to `Process`**

Add to `Process`:
```rust
    /// Next thread ID to allocate (starts at 2; main thread is 1).
    next_tid: AtomicI32,
```

In `Process::new()`:
```rust
    next_tid: AtomicI32::new(2),
```

- [ ] **Step 3: Add a next-mach-port counter to `Process`**

Each thread needs a unique fake Mach port. Add to `Process`:
```rust
    /// Next Mach thread port to allocate.
    next_mach_port: AtomicU32,
```

In `Process::new()`:
```rust
    next_mach_port: AtomicU32::new(0x0403),
```

(Main thread uses `0x0303`, so child threads start at `0x0403`.)

- [ ] **Step 4: Add dispatch arm in `mod.rs`**

```rust
MacosSyscallRequest::BsdthreadCreate {
    func,
    func_arg,
    stack,
    pthread,
    flags,
} => self.sys_bsdthread_create(func, func_arg, stack, pthread, flags, ctx),
```

- [ ] **Step 5: Implement `sys_bsdthread_create` in `stubs.rs`**

```rust
/// Handle `bsdthread_create` — create a new thread.
///
/// # Panics
///
/// Panics if `bsdthread_register` has not been called (threadstart == 0).
pub(crate) fn sys_bsdthread_create(
    &self,
    func: usize,
    func_arg: usize,
    stack: usize,
    pthread: usize,
    flags: u32,
    ctx: &PtRegs,
) -> Result<usize, Errno> {
    use core::sync::atomic::Ordering;

    let threadstart = self.process.threadstart.load(Ordering::Acquire) as usize;
    if threadstart == 0 {
        log_unsupported!("bsdthread_create called before bsdthread_register");
        return Err(Errno::EINVAL);
    }

    let tid = self.process.next_tid.fetch_add(1, Ordering::Relaxed);
    let mach_port = self.process.next_mach_port.fetch_add(0x100, Ordering::Relaxed);
    let tsd_offset = self.process.tsd_offset.load(Ordering::Acquire);

    log_unsupported!(
        "bsdthread_create(func={func:#x}, arg={func_arg:#x}, stack={stack:#x}, \
         pthread={pthread:#x}, flags={flags:#x}) → tid={tid}, port={mach_port:#x}"
    );

    // Increment thread count before spawning.
    self.process.nr_threads.fetch_add(1, Ordering::Release);

    // Set PTHREAD_START_TSD_BASE_SET (0x10000000) in flags to tell
    // libpthread that we pre-configured the TSD base.
    let flags_with_tsd = flags | 0x1000_0000;

    let child_task = Task {
        global: self.global.clone(),
        process: self.process.clone(),
        tid,
        terminated: AtomicBool::new(false),
        patch_cache: Mutex::new(BTreeMap::new()),
        init_state: Mutex::new(crate::ThreadInitState::BsdThread {
            threadstart,
            func,
            func_arg,
            stack,
            pthread,
            flags: flags_with_tsd,
            mach_port,
            tsd_offset,
        }),
    };

    let r = unsafe {
        self.global.platform.spawn_thread(
            ctx,
            Box::new(crate::NewThreadArgs { task: child_task }),
        )
    };

    if let Err(err) = r {
        self.process.nr_threads.fetch_sub(1, Ordering::Release);
        log_unsupported!("bsdthread_create: spawn_thread failed: {err}");
        return Err(Errno::EAGAIN);
    }

    // Return the pthread address (what the kernel returns on success).
    Ok(pthread)
}
```

- [ ] **Step 6: Update `do_mach_trap` to return per-thread ports**

In `stubs.rs`, change the `THREAD_SELF_TRAP` arm:

```rust
mach_trap::THREAD_SELF_TRAP => {
    // Return a unique fake Mach port per thread.
    // Main thread = 0x0303, child threads = 0x0403, 0x0503, etc.
    // For the main thread (tid=1), return the legacy 0x0303.
    if self.tid == 1 {
        Ok(0x0303)
    } else {
        // Derive port from tid. This is a simplification;
        // in reality the port was assigned at bsdthread_create time.
        // TODO: store the mach port on the Task for exactness.
        Ok(((self.tid as usize) + 2) << 8 | 0x03)
    }
}
```

- [ ] **Step 7: Verify it compiles**

Run: `cargo check -p litebox_shim_macos`

- [ ] **Step 8: Commit**

```
feat(litebox_shim_macos): implement bsdthread_create syscall
```

---

### Task 5: Implement bsdthread_terminate and bsdthread_ctl

**Files:**
- Modify: `litebox_shim_macos/src/syscalls/mod.rs`
- Modify: `litebox_shim_macos/src/syscalls/stubs.rs`

- [ ] **Step 1: Add dispatch arms in `mod.rs`**

```rust
MacosSyscallRequest::BsdthreadTerminate {
    stackaddr,
    freesize,
    port,
    sema_or_ulock,
} => {
    self.sys_bsdthread_terminate(stackaddr, freesize, port, sema_or_ulock);
    // bsdthread_terminate never returns — the thread is dead.
    // Return Terminate to exit the run loop.
    return;
},
MacosSyscallRequest::BsdthreadCtl {
    cmd,
    arg1,
    arg2,
    arg3,
} => self.sys_bsdthread_ctl(cmd, arg1, arg2, arg3),
```

Note: `bsdthread_terminate` needs special handling because it doesn't return. The syscall dispatch should set the return value and then check `should_terminate`. Since `sys_bsdthread_terminate` sets `terminated = true`, the `enter_shim` wrapper will return `ContinueOperation::Terminate`.

Actually, let's handle it cleanly: `sys_bsdthread_terminate` sets `self.terminated = true` and returns `Ok(0)`. The existing `should_terminate` check in `enter_shim` will do the rest.

Revise: the dispatch arm is simply:

```rust
MacosSyscallRequest::BsdthreadTerminate {
    stackaddr,
    freesize,
    port,
    sema_or_ulock,
} => self.sys_bsdthread_terminate(stackaddr, freesize, port, sema_or_ulock),
MacosSyscallRequest::BsdthreadCtl {
    cmd,
    arg1,
    arg2,
    arg3,
} => self.sys_bsdthread_ctl(cmd, arg1, arg2, arg3),
```

- [ ] **Step 2: Implement `sys_bsdthread_terminate` in `stubs.rs`**

```rust
/// Handle `bsdthread_terminate` — terminate the calling thread.
///
/// On real macOS, the kernel frees the thread's stack, deallocates its
/// Mach port, and signals a semaphore/ulock. We skip stack freeing
/// (the host thread owns its stack) and just mark the thread terminated.
pub(crate) fn sys_bsdthread_terminate(
    &self,
    _stackaddr: usize,
    _freesize: usize,
    _port: u32,
    _sema_or_ulock: usize,
) -> Result<usize, Errno> {
    log_unsupported!(
        "bsdthread_terminate(tid={})",
        self.tid,
    );

    // Decrement thread count. If this was the last thread and no
    // group_exit was called, the process is done.
    let prev = self.process.nr_threads.fetch_sub(1, Ordering::Release);
    if prev <= 1 {
        // Last thread exiting — treat as process exit with code 0.
        self.process
            .exit_code
            .compare_exchange(0, 0, Ordering::AcqRel, Ordering::Acquire)
            .ok();
        self.process.group_exit.store(true, Ordering::Release);
    }

    self.terminated.store(true, Ordering::Release);
    Ok(0)
}
```

- [ ] **Step 3: Implement `sys_bsdthread_ctl` in `stubs.rs`**

```rust
/// Handle `bsdthread_ctl` — thread control operations.
///
/// Most commands are stubs. We handle the minimum needed for libpthread.
pub(crate) fn sys_bsdthread_ctl(
    &self,
    cmd: usize,
    _arg1: usize,
    _arg2: usize,
    _arg3: usize,
) -> Result<usize, Errno> {
    // Commands from bsdthread_private.h:
    const BSDTHREAD_CTL_SET_QOS: usize = 0x10;
    const BSDTHREAD_CTL_GET_QOS: usize = 0x20;
    const BSDTHREAD_CTL_SET_SELF: usize = 0x100;
    const BSDTHREAD_CTL_QOS_MAX_PARALLELISM: usize = 0x800;

    match cmd {
        BSDTHREAD_CTL_SET_SELF => {
            // libpthread calls this to set QoS on the current thread.
            // Stub: return success.
            Ok(0)
        }
        BSDTHREAD_CTL_QOS_MAX_PARALLELISM => {
            // Return the number of CPUs.
            Ok(1)
        }
        BSDTHREAD_CTL_SET_QOS | BSDTHREAD_CTL_GET_QOS => Ok(0),
        _ => {
            log_unsupported!("bsdthread_ctl(cmd={cmd:#x}): unsupported");
            Ok(0)
        }
    }
}
```

- [ ] **Step 4: Verify it compiles and existing tests pass**

Run: `cargo test -p litebox_runner_macos_on_macos_userland -- --nocapture`
Expected: 5 passed, 1 ignored, 0 failed

- [ ] **Step 5: Commit**

```
feat(litebox_shim_macos): implement bsdthread_terminate and bsdthread_ctl
```

---

### Task 6: Create thread.c test and run it

**Files:**
- Create: `litebox_runner_macos_on_macos_userland/tests/thread.c`
- Modify: `litebox_runner_macos_on_macos_userland/tests/loader.rs`

- [ ] **Step 1: Create `tests/thread.c`**

```c
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#define NUM_THREADS 50

void* thread_func(void* arg) {
    int thread_id = *(int*)arg;
    printf("Hello from thread %d (TID: %lu)\n", thread_id, (unsigned long)pthread_self());
    return NULL;
}

int main() {
    pthread_t threads[NUM_THREADS];
    int thread_ids[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        thread_ids[i] = i;
        int rc = pthread_create(&threads[i], NULL, thread_func, &thread_ids[i]);
        if (rc) {
            fprintf(stderr, "Error creating thread %d\n", i);
            exit(EXIT_FAILURE);
        }
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("All threads finished!\n");
    return 0;
}
```

- [ ] **Step 2: Add `test_hello_thread` to `loader.rs`**

```rust
#[test]
#[allow(clippy::cast_precision_loss)]
fn test_hello_thread() {
    let cache_dir = std::path::Path::new("/System/Cryptexes/OS/System/Library/dyld");
    assert!(
        cache_dir.exists(),
        "Shared cache not found at {}. This test requires macOS with dyld shared cache.",
        cache_dir.display()
    );

    let map_path = cache_dir.join("dyld_shared_cache_arm64e.map");
    let map_text = std::fs::read_to_string(&map_path).unwrap();
    let cache_map = common::shared_cache::CacheMap::parse(&map_text);
    let system_dylibs = cache_map.system_dylib_paths();
    let dylib_refs: Vec<&str> = system_dylibs
        .iter()
        .map(std::string::String::as_str)
        .collect();
    let cache_result = common::shared_cache::collect_regions(cache_dir, &cache_map, &dylib_refs);

    let bin_path = common::compile_macho_dynamic("./tests/thread.c", "hello_thread");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    let (exit_code, _stdout) = common::run_macho_dynamic(
        &binary_data,
        &["/usr/bin/hello_thread"],
        &cache_result,
    );
    assert_eq!(exit_code, 0, "process exited with non-zero code");
}
```

- [ ] **Step 3: Run the test**

Run: `cargo test -p litebox_runner_macos_on_macos_userland test_hello_thread -- --nocapture`
Expected: The test should pass (exit code 0) with 50 "Hello from thread N" lines printed.

- [ ] **Step 4: Run ALL tests to verify no regressions**

Run: `cargo test -p litebox_runner_macos_on_macos_userland -- --nocapture`
Expected: 6 passed, 1 ignored, 0 failed

- [ ] **Step 5: Run clippy**

Run: `cargo clippy -p litebox_shim_macos -p litebox_common_macos -p litebox_runner_macos_on_macos_userland --tests`
Expected: No new warnings from our crates

- [ ] **Step 6: Commit**

```
feat: add pthread thread test with 50 threads for macOS shim
```

---

### Task 7: Fix issues discovered during testing

This task is a placeholder for any syscalls, Mach traps, or edge cases that surface when running the 50-thread test. Common issues to expect:

- Additional Mach traps for thread lifecycle (e.g., `mach_port_deallocate_trap`)
- `__ulock_wait` / `__ulock_wake` syscalls (used by pthread_join on modern macOS)
- `proc_info` or other introspection syscalls
- Stack guard page setup (`mmap` with `PROT_NONE`)
- Thread-local storage writes via the TSD mechanism

- [ ] **Step 1: Run the thread test and capture output**

Run the test with `--nocapture` and look for `ENOSYS` or `Unknown` log messages to identify missing syscalls.

- [ ] **Step 2: Add stubs for each missing syscall**

For each missing syscall, add the number to `litebox_common_macos/src/syscall.rs`, add the enum variant and decoding, add the dispatch arm, and implement a minimal stub.

- [ ] **Step 3: Iterate until the test passes**

Re-run after each fix until all 50 threads complete and the test passes.

- [ ] **Step 4: Run all tests + clippy**

Run: `cargo test -p litebox_runner_macos_on_macos_userland -- --nocapture`
Run: `cargo clippy -p litebox_shim_macos -p litebox_common_macos --tests`

- [ ] **Step 5: Commit**

```
fix(litebox_shim_macos): add missing syscall stubs for pthread support
```

---

### Task 8: Final cleanup and verification

- [ ] **Step 1: Run the full test suite**

Run: `cargo test -p litebox_runner_macos_on_macos_userland -- --nocapture`
Expected: All tests pass (6+ passed, 1 ignored, 0 failed)

- [ ] **Step 2: Run clippy across all affected crates**

Run: `cargo clippy -p litebox_shim_macos -p litebox_common_macos -p litebox_syscall_rewriter_macho -p litebox_runner_macos_on_macos_userland --tests`
Expected: Zero warnings from our crates

- [ ] **Step 3: Run cargo fmt**

Run: `cargo fmt -p litebox_shim_macos -p litebox_common_macos -p litebox_runner_macos_on_macos_userland`

- [ ] **Step 4: Commit any final cleanup**

```
chore: final cleanup after threading support
```
