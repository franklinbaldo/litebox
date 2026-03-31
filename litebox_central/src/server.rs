// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Single-process server loop for central LiteBox.
//!
//! Consumes submission queue entries, dispatches them to either syscall
//! handlers or control message handlers, and writes completion queue results.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::ptr::null;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::thread::JoinHandle;

use litebox_ipc::cq::{cq_notify_thread, cq_push};
use litebox_ipc::messages::{
    self, MSG_CHILD_READY, MSG_FORK_RESULT, MSG_LOCAL_RESULT, MSG_NOTIFY_ALARM, MSG_NOTIFY_MADVISE,
    MSG_NOTIFY_MPROTECT, MSG_NOTIFY_MUNMAP, MSG_NOTIFY_SIGACTION, MSG_NOTIFY_SIGALTSTACK,
    MSG_NOTIFY_SIGPROCMASK, MSG_NOTIFY_UMASK, MSG_NOTIFY_WAIT4, MSG_THREAD_DEREGISTER,
    MSG_THREAD_REGISTER,
};
use litebox_ipc::ring::{
    cq_flags, pipe_flags, sq_flags, CqEntry, SqEntry, TrampolineDescriptor, PIPE_SLOT_SIZE,
    PIPE_ZONE_BASE_OFFSET, RING_MASK,
};
use litebox_ipc::sq::{sq_advance_head, sq_head_index, sq_try_consume};
use litebox_ipc::wait::spin_then_wait;
use litebox_shim_linux::ShimFS;

use crate::shmem::{RingPool, SharedRegion};

/// The central server that processes SQ entries and produces CQ completions.
///
/// Manages one primary task (the main thread at slot 0) plus additional
/// per-thread tasks created via `clone` and registered via
/// `MSG_THREAD_REGISTER`.
///
/// The server loop is single-threaded, so interior mutability uses `RefCell`
/// and `Cell` rather than `Mutex`.
pub struct ProcessServer<FS: ShimFS> {
    region: SharedRegion,
    /// Pre-allocated ring pool shared across all `ProcessServer` instances.
    ring_pool: Arc<RingPool>,
    /// Raw fd of this process's ring memfd (`-1` for the root process whose
    /// ring did not come from the pool).
    ring_fd: i32,
    /// Primary task (main thread, slot 0). Always present.
    primary_task: litebox_shim_linux::LinuxShimTask<FS>,
    /// Active thread tasks keyed by thread_slot. Does not include slot 0.
    thread_tasks: RefCell<HashMap<u16, litebox_shim_linux::LinuxShimTask<FS>>>,
    /// Pending child tasks from `create_thread_task`, awaiting registration.
    /// When `MSG_THREAD_REGISTER` arrives, the most recent pending task is
    /// moved to `thread_tasks`.
    pending_tasks: RefCell<Vec<litebox_shim_linux::LinuxShimTask<FS>>>,
    /// Next available thread slot (starts at 1; slot 0 is the primary task).
    next_thread_slot: Cell<u16>,
    /// Next child PID to assign (starts at 2 since the main process is 1).
    next_child_pid: Cell<i32>,
    /// Reference to the shim for creating child tasks.
    shim: Arc<litebox_shim_linux::LinuxShim<FS>>,
    /// Filesystem for creating child tasks.
    fs: Arc<FS>,
    /// Join handles for child server threads spawned by `handle_fork`.
    /// Joined when this server's `run()` loop exits, preventing premature
    /// central process termination while children are still running.
    child_handles: RefCell<Vec<JoinHandle<()>>>,
    /// Per-process state from Tier 2 fire-and-forget notifications.
    notification_state: RefCell<crate::notification_state::ProcessNotificationState>,
}

impl<FS: ShimFS> ProcessServer<FS> {
    /// Create a new `ProcessServer` backed by the given shared memory region.
    #[must_use]
    pub fn new(
        region: SharedRegion,
        task: litebox_shim_linux::LinuxShimTask<FS>,
        shim: Arc<litebox_shim_linux::LinuxShim<FS>>,
        fs: Arc<FS>,
        ring_pool: Arc<RingPool>,
        ring_fd: i32,
    ) -> Self {
        Self {
            region,
            ring_pool,
            ring_fd,
            primary_task: task,
            thread_tasks: RefCell::new(HashMap::new()),
            pending_tasks: RefCell::new(Vec::new()),
            next_thread_slot: Cell::new(1),
            next_child_pid: Cell::new(2),
            shim,
            fs,
            child_handles: RefCell::new(Vec::new()),
            notification_state: RefCell::new(
                crate::notification_state::ProcessNotificationState::default(),
            ),
        }
    }

    /// Run the server loop.
    ///
    /// This loop runs indefinitely, consuming SQ entries, dispatching them,
    /// writing CQ results, and notifying guest threads.
    ///
    /// # Errors
    ///
    /// Returns `Ok(())` when the guest exits cleanly.
    #[allow(clippy::unnecessary_wraps)] // Result kept for future error paths
    pub fn run(self) -> anyhow::Result<()> {
        let header = self.region.header();
        let sq_entries = self.region.sq_entries();

        loop {
            let head = sq_head_index(header);

            #[allow(clippy::cast_possible_truncation)] // masked to RING_MASK (8 bits)
            let slot = (head as usize) & RING_MASK;
            let entry = &sq_entries[slot];

            if !sq_try_consume(entry) {
                // Entry not ready — wait for the producer to publish it.
                let expected = header.sq_notify.load(Relaxed);
                // Re-check after reading the notify counter. If the producer
                // published the entry AND incremented sq_notify between our
                // initial `sq_try_consume` and the `load` above, we would
                // otherwise wait forever on an already-stale expected value.
                if sq_try_consume(entry) {
                    // Entry became ready — fall through to process it.
                } else {
                    spin_then_wait(&header.sq_notify, expected, |addr, exp| {
                        // SAFETY: We pass a valid pointer to an AtomicU32 in the
                        // shared memory region. The futex syscall reads the u32 at
                        // that address and blocks the thread if it still equals
                        // `exp`. The timeout is null (infinite wait).
                        unsafe {
                            libc::syscall(
                                libc::SYS_futex,
                                addr.as_ptr(),
                                libc::FUTEX_WAIT,
                                exp.cast_signed(),
                                null::<libc::timespec>(),
                            );
                        }
                    });
                    continue;
                }
            }

            // Entry is ready — extract fields and dispatch.
            let syscall_nr = entry.syscall_nr;

            let cq_entry = if messages::is_control_message(syscall_nr) {
                self.handle_control_message(entry)
            } else {
                self.handle_syscall(entry)
            };

            // Notification-only: central processed it, skip CQ response.
            let is_notify_only = entry.flags & sq_flags::NOTIFY_ONLY != 0;

            if is_notify_only {
                sq_advance_head(header, entry);
                if self.primary_task.is_exiting() {
                    break;
                }
                continue;
            }

            // SAFETY: `cq_entries` points to a valid array of RING_SIZE CqEntry
            // values in the shared memory region. We are the sole CQ producer
            // (single-process server loop), satisfying the single-producer
            // discipline required by `cq_push`.
            unsafe {
                cq_push(
                    header,
                    self.region.cq_entries().as_ptr().cast_mut(),
                    cq_entry,
                );
            }

            // Notify the guest thread that a completion is available.
            let notify_slot = cq_notify_thread(header, cq_entry.thread_slot);

            // SAFETY: `notify_slot` points to a valid AtomicU32 in the shared
            // memory region's `cq_notify_slots` array. The futex syscall wakes
            // at most one waiter blocked on that address.
            unsafe {
                libc::syscall(
                    libc::SYS_futex,
                    notify_slot.as_ptr(),
                    libc::FUTEX_WAKE,
                    1i32,
                );
            }

            sq_advance_head(header, entry);

            // Check if the guest process is exiting (exit_group sets this on
            // the primary task).
            if self.primary_task.is_exiting() {
                break;
            }
        }

        // Wait for all child server threads to finish before returning.
        // This prevents the central process from exiting while children
        // are still processing syscalls (the OS would kill child threads,
        // leaving child guest processes hanging on dead rings).
        let handles: Vec<_> = self.child_handles.into_inner().drain(..).collect();
        for handle in handles {
            let _ = handle.join();
        }

        // Return this process's ring to the pool so it can be reused by a
        // future fork.  The root server (ring_fd == -1) did not get its ring
        // from the pool, so it skips the release.
        if self.ring_fd >= 0 {
            self.ring_pool.release(self.region, self.ring_fd);
        }

        Ok(())
    }

    /// Construct a base `CqEntry` from an `SqEntry` with zeroed data fields.
    fn base_cq(entry: &SqEntry) -> CqEntry {
        CqEntry {
            seq: entry.seq,
            result: 0,
            flags: 0,
            thread_slot: entry.thread_slot,
            _pad: [0; 4],
            data_offset: 0,
            data_len: 0,
        }
    }

    /// Dispatch a regular syscall from an SQ entry.
    ///
    /// Returns a full `CqEntry`. If the syscall involves guest memory
    /// pointers that central cannot dereference (the guest is in a separate
    /// address space), central returns `EXEC_LOCAL` telling micro to
    /// execute the syscall locally.
    fn handle_syscall(&self, entry: &SqEntry) -> CqEntry {
        let nr = entry.syscall_nr;
        let mut cq = Self::base_cq(entry);

        // Execve: custom handler that parses ELF and sends segment data to micro.
        #[allow(clippy::cast_possible_truncation)]
        if nr == libc::SYS_execve as u32 {
            return self.handle_execve(entry);
        }

        // Exit syscalls: dispatch through the shim (to set the exiting flag)
        // AND tell micro to execute locally (to actually terminate the guest).
        #[allow(clippy::cast_possible_truncation)]
        if nr == libc::SYS_exit_group as u32 || nr == libc::SYS_exit as u32 {
            let mut regs = crate::dispatch::sq_entry_to_ptregs(entry);
            cq.result = self.dispatch_to_task(entry.thread_slot, &mut regs);
            cq.flags = cq_flags::EXEC_LOCAL | cq_flags::NO_REPORT;
            return cq;
        }

        // Clone handling: thread creation vs fork.
        #[allow(clippy::cast_possible_truncation)]
        if nr == libc::SYS_clone as u32 {
            let flags = entry.args[0];
            // CLONE_VM = 0x100, CLONE_THREAD = 0x10000
            if flags & 0x100 != 0 && flags & 0x1_0000 != 0 {
                // Thread clone (CLONE_VM | CLONE_THREAD)
                let result = if entry.thread_slot == 0 {
                    self.primary_task.create_thread_task()
                } else {
                    let tasks = self.thread_tasks.borrow();
                    match tasks.get(&entry.thread_slot) {
                        Some(task) => task.create_thread_task(),
                        None => Err(litebox_common_linux::errno::Errno::ESRCH),
                    }
                };
                match result {
                    Ok((child_tid, child_task)) => {
                        self.pending_tasks.borrow_mut().push(child_task);
                        cq.result = i64::from(child_tid);
                        cq.flags = cq_flags::EXEC_LOCAL | cq_flags::NO_REPORT;
                    }
                    Err(e) => {
                        cq.result = i64::from(e.as_neg());
                    }
                }
                return cq;
            }

            // Fork: no CLONE_VM
            return self.handle_fork(entry);
        }

        // fork/vfork: treat as fork (same as clone without CLONE_VM).
        #[allow(clippy::cast_possible_truncation)]
        if nr == libc::SYS_fork as u32 || nr == libc::SYS_vfork as u32 {
            return self.handle_fork(entry);
        }

        // Close: dual-dispatch. Try shim first for fd table cleanup.
        // If shim recognized the fd (returned success), the fd is virtual
        // (tar_ro filesystem) — return 0 directly without local exec.
        // If shim returned EBADF, the fd is a real OS fd (pipe, etc.) —
        // tell micro to close it locally.
        #[allow(clippy::cast_possible_truncation)]
        if nr == libc::SYS_close as u32 {
            let fd = entry.args[0] as i32;
            let mut regs = crate::dispatch::sq_entry_to_ptregs(entry);
            let shim_result = self.dispatch_to_task(entry.thread_slot, &mut regs);
            if shim_result >= 0 {
                // Shim recognized and closed the fd — return success directly.
                // If this fd was a shmem pipe end, update flags and free slot.
                self.maybe_close_shmem_pipe_end(fd);
                cq.result = 0;
                return cq;
            }
            // EBADF from shim: fd is a real OS fd, let micro close it.
            cq.flags = cq_flags::EXEC_LOCAL | cq_flags::NO_REPORT;
            return cq;
        }

        // FD manipulation (dup/dup2/dup3/fcntl): dual-dispatch like close.
        // The source fd may be a virtual fd in the shim (tar_ro file) or a
        // real OS fd (pipe from pipe2). Try the shim first; if it returns
        // EBADF (fd not in shim's table), fall back to local exec so micro
        // performs the operation on the real OS fd.
        #[allow(clippy::cast_possible_truncation)]
        if matches!(
            i64::from(nr),
            libc::SYS_dup | libc::SYS_dup2 | libc::SYS_dup3 | libc::SYS_fcntl
        ) {
            let mut regs = crate::dispatch::sq_entry_to_ptregs(entry);
            let shim_result = self.dispatch_to_task(entry.thread_slot, &mut regs);
            if shim_result >= 0 {
                // Shim handled it (virtual fd) — return result directly.
                cq.result = shim_result;
                return cq;
            }
            if shim_result == -i64::from(libc::EBADF) {
                // Real OS fd — let micro execute locally.
                cq.flags = cq_flags::EXEC_LOCAL | cq_flags::NO_REPORT;
                return cq;
            }
            // Other error from shim — pass through.
            cq.result = shim_result;
            return cq;
        }

        // fadvise64: pure hint, always succeeds.  Cannot be dispatched
        // locally because the fd may be a virtual shim fd.
        if i64::from(nr) == libc::SYS_fadvise64 {
            cq.result = 0;
            return cq;
        }

        // Data-consuming I/O (write to virtual fds): micro copies write buffer
        // into shmem, central reads it and dispatches through shim.
        // If shim returns EBADF (real OS fd), fall back to local exec.
        if Self::is_data_consuming_io(nr) {
            return self.handle_data_consuming_io(entry);
        }

        // Process/user identity: return virtual values directly.
        // Micro's fast-path also handles these, but if they reach central
        // (e.g., from execute_locally path), return the virtual values.
        #[allow(clippy::cast_possible_truncation)]
        match i64::from(nr) {
            libc::SYS_getpid => {
                // Guest is always PID 1.
                cq.result = 1;
                return cq;
            }
            libc::SYS_getppid => {
                // Guest's parent is PID 0 (no parent).
                cq.result = 0;
                return cq;
            }
            libc::SYS_getuid | libc::SYS_getgid | libc::SYS_geteuid | libc::SYS_getegid => {
                // Virtual root identity (uid=0, gid=0).
                cq.result = 0;
                return cq;
            }
            _ => {}
        }

        // pipe2: create virtual pipes in shim's fd table, allocate shmem
        // ring buffer slot, return fd pair + slot offset to micro.
        #[allow(clippy::cast_possible_truncation)]
        if nr == libc::SYS_pipe2 as u32 {
            return self.handle_pipe2(entry);
        }

        if Self::needs_local_exec(nr) {
            cq.flags = cq_flags::EXEC_LOCAL | cq_flags::NO_REPORT;
            return cq;
        }

        // File I/O that produces data: dispatch through shim with a buffer
        // in the shmem data region, then return EXEC_LOCAL | HAS_DATA so
        // micro copies the data into the guest's buffer.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        if Self::is_data_producing_io(nr) {
            return self.handle_data_producing_io(entry);
        }

        // Memory management: mmap/mremap dispatch through shim (PageManager
        // state) then EXEC_LOCAL so micro creates the real mapping. brk
        // returns EXEC_LOCAL immediately (micro manages guest_brk).
        // Note: munmap/mprotect/madvise are now Tier 2 in micro.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        if Self::is_mm_syscall(nr) {
            // For brk: skip shim dispatch entirely. In micro, the guest
            // runs in a separate address space (the launcher process).
            // For brk, the shim's PageManager shrink path calls
            // deallocate_pages with huge ranges that overlap central's
            // memory. Just return EXEC_LOCAL so micro handles brk
            // directly in the guest's address space.
            // Note: munmap/mprotect/madvise are now Tier 2 in micro
            // (notify-after-execute) and no longer reach central.
            #[allow(clippy::cast_possible_truncation)]
            if nr == libc::SYS_brk as u32 {
                cq.flags = cq_flags::EXEC_LOCAL | cq_flags::NO_REPORT;
                return cq;
            }

            // For mmap (and mremap): still dispatch through shim. The shim's
            // PageManager tracks allocations, and for file-backed mmap the
            // shim reads file data from tar_ro and populates memory that
            // central then copies into the shmem data region.
            let mut regs = crate::dispatch::sq_entry_to_ptregs(entry);
            cq.result = self.dispatch_to_task(entry.thread_slot, &mut regs);
            if cq.result < 0 {
                // Shim returned an error — pass it through without EXEC_LOCAL.
                return cq;
            }
            cq.flags = cq_flags::EXEC_LOCAL | cq_flags::NO_REPORT;

            // For file-backed mmap: copy the populated data into the data region.
            // Also detect rewritten ELF trampolines and include trampoline data
            // so micro can map the trampoline page in the guest address space.
            if nr == libc::SYS_mmap as u32 {
                let flags = entry.args[3] as i32;
                if flags & libc::MAP_ANONYMOUS == 0 {
                    // File-backed mmap: shim populated memory at cq.result.
                    let addr = cq.result as usize;
                    let len = entry.args[1] as usize;
                    let data_region = self.region.data_region_mut();
                    let copy_len = len.min(data_region.len());
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            addr as *const u8,
                            data_region.as_mut_ptr(),
                            copy_len,
                        );
                    }
                    cq.flags |= cq_flags::HAS_DATA;
                    cq.data_offset = 0;
                    cq.data_len = copy_len as u32;

                    // For the initial reservation mmap (no MAP_FIXED), check if
                    // the file is a rewritten ELF with a trampoline section.
                    #[allow(clippy::cast_possible_truncation)]
                    if flags & libc::MAP_FIXED == 0 {
                        let fd = entry.args[4] as i32;
                        self.try_append_trampoline(entry.thread_slot, fd, copy_len, &mut cq);
                    }
                }
            }
            return cq;
        }

        // For pathname syscalls, micro copies the pathname string into the
        // shared data region (micro's address space holds the guest's memory;
        // central cannot dereference guest pointers directly). If data_len > 0,
        // copy the pathname into a local buffer and rewrite the PtRegs argument
        // to point to it before dispatching to the shim.
        let mut pathname_buf: Vec<u8> = Vec::new();
        let mut regs = crate::dispatch::sq_entry_to_ptregs(entry);

        if entry.data_len > 0 {
            let data = self.region.data_region();
            let offset = entry.data_offset as usize;
            let len = entry.data_len as usize;
            if offset + len <= data.len() {
                pathname_buf.extend_from_slice(&data[offset..offset + len]);
                let buf_ptr = pathname_buf.as_ptr() as usize;
                // Determine which register holds the pathname pointer.
                match i64::from(nr) {
                    libc::SYS_openat
                    | libc::SYS_newfstatat
                    | libc::SYS_faccessat
                    | libc::SYS_faccessat2
                    | libc::SYS_readlinkat
                    | libc::SYS_unlinkat => {
                        regs.rsi = buf_ptr; // arg1
                    }
                    libc::SYS_access
                    | libc::SYS_stat
                    | libc::SYS_lstat
                    | libc::SYS_readlink
                    | libc::SYS_unlink
                    | libc::SYS_chdir
                    | libc::SYS_mkdir
                    | libc::SYS_open
                    | libc::SYS_creat => {
                        regs.rdi = buf_ptr; // arg0
                    }
                    _ => {} // Unknown — dispatch as-is.
                }
            }
        }

        cq.result = self.dispatch_to_task(entry.thread_slot, &mut regs);
        cq
    }

    /// Handle a fork (clone without CLONE_VM).
    ///
    /// Creates a new shared memory ring for the child, assigns a child PID,
    /// creates a child task via the shim, and spawns a new server thread for
    /// the child process.
    ///
    /// The CqEntry returned carries:
    /// - `result`: central's PID (so micro can construct `/proc/<pid>/fd/...`)
    /// - `flags`: `EXEC_LOCAL` (micro must execute the real fork)
    /// - `data_offset`: child PID assigned by central
    /// - `data_len`: child ring fd number in central's fd table
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn handle_fork(&self, entry: &SqEntry) -> CqEntry {
        let mut cq = Self::base_cq(entry);

        // 1. Acquire a ring for the child from the pool.
        let Ok((child_region, child_ring_fd)) = self.ring_pool.acquire() else {
            cq.result = -i64::from(libc::ENOMEM);
            return cq;
        };

        // 2. Assign child PID.
        let child_pid = self.next_child_pid.get();
        self.next_child_pid.set(child_pid + 1);

        // 3. Create child task via the shim, inheriting parent's fds and cwd.
        let params = litebox_common_linux::TaskParams {
            pid: child_pid,
            ppid: 1, // parent is the main process
            uid: 0,
            euid: 0,
            gid: 0,
            egid: 0,
        };
        let child_task = if entry.thread_slot == 0 {
            self.shim
                .fork_task(self.fs.clone(), params, &self.primary_task)
        } else {
            let tasks = self.thread_tasks.borrow();
            if let Some(parent) = tasks.get(&entry.thread_slot) {
                self.shim.fork_task(self.fs.clone(), params, parent)
            } else {
                // Shouldn't happen — the forking thread must exist.
                cq.result = -i64::from(libc::ESRCH);
                return cq;
            }
        };

        // 4. Spawn the child server immediately.
        //
        // The child process will send MSG_CHILD_READY on the *child's* ring
        // after post-fork initialization.  The child server must already be
        // running its event loop so it can consume that message (and all
        // subsequent syscalls from the child).
        {
            let shim = self.shim.clone();
            let fs = self.fs.clone();
            let pool = Arc::clone(&self.ring_pool);
            let child_server =
                ProcessServer::new(child_region, child_task, shim, fs, pool, child_ring_fd);
            child_server.next_child_pid.set(self.next_child_pid.get());

            let handle = std::thread::spawn(move || {
                if let Err(e) = child_server.run() {
                    eprintln!("litebox_central: child server error: {e}");
                }
            });
            self.child_handles.borrow_mut().push(handle);
        }

        // 5. Return info to micro.
        let central_pid = std::process::id();
        cq.result = i64::from(central_pid);
        cq.flags = cq_flags::EXEC_LOCAL | cq_flags::NO_REPORT;
        cq.data_offset = child_pid as u32;
        cq.data_len = child_ring_fd as u32;
        cq
    }

    /// Dispatch a syscall to the correct task based on thread slot.
    ///
    /// Slot 0 dispatches to `primary_task`; other slots look up `thread_tasks`.
    /// Returns `-ESRCH` if the thread slot is not found.
    fn dispatch_to_task(&self, thread_slot: u16, regs: &mut litebox_common_linux::PtRegs) -> i64 {
        if thread_slot == 0 {
            self.primary_task.dispatch_syscall(regs)
        } else {
            let tasks = self.thread_tasks.borrow();
            if let Some(task) = tasks.get(&thread_slot) {
                task.dispatch_syscall(regs)
            } else {
                -i64::from(libc::ESRCH)
            }
        }
    }

    /// Check if the file behind `fd` is a rewritten ELF with a trampoline.
    /// If so, read the trampoline code and append a `TrampolineDescriptor`
    /// followed by the trampoline code bytes to the data region (after the
    /// mmap data that starts at offset 0).
    ///
    /// On success, sets `cq_flags::TRAMPOLINE` on the CQ entry.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_possible_wrap,
        clippy::field_reassign_with_default
    )]
    fn try_append_trampoline(
        &self,
        thread_slot: u16,
        fd: i32,
        mmap_data_len: usize,
        cq: &mut CqEntry,
    ) {
        /// Trampoline magic: `b"LITEBOX0"` as a little-endian u64.
        const LITEBOX0_MAGIC: u64 = u64::from_le_bytes(*b"LITEBOX0");
        /// 64-bit trampoline header size (magic + file_offset + vaddr + size).
        const HEADER_SIZE: usize = 32;

        // Get file size via fstat (syscall 5).
        // fstat(fd, statbuf): rdi=fd, rsi=statbuf.
        // We allocate a local buffer and dispatch through the task.
        let mut stat_buf = [0u8; 144]; // struct stat is 144 bytes on x86_64
        {
            let mut regs = litebox_common_linux::PtRegs::default();
            regs.orig_rax = libc::SYS_fstat as usize;
            regs.rdi = fd as usize;
            regs.rsi = stat_buf.as_mut_ptr() as usize;
            let result = self.dispatch_to_task(thread_slot, &mut regs);
            if result < 0 {
                return;
            }
        }
        // st_size is at offset 48 in struct stat on x86_64 (i64).
        let file_size = i64::from_le_bytes(stat_buf[48..56].try_into().unwrap());
        if (file_size as usize) < HEADER_SIZE {
            return;
        }

        // Read the trampoline header from the end of the file via pread64.
        let mut header_buf = [0u8; HEADER_SIZE];
        let header_offset = file_size - HEADER_SIZE as i64;
        {
            let mut regs = litebox_common_linux::PtRegs::default();
            regs.orig_rax = libc::SYS_pread64 as usize;
            regs.rdi = fd as usize;
            regs.rsi = header_buf.as_mut_ptr() as usize;
            regs.rdx = HEADER_SIZE;
            regs.r10 = header_offset as usize;
            let result = self.dispatch_to_task(thread_slot, &mut regs);
            if result < HEADER_SIZE as i64 {
                return;
            }
        }

        // Check magic.
        let magic = u64::from_le_bytes(header_buf[0..8].try_into().unwrap());
        if magic != LITEBOX0_MAGIC {
            return;
        }

        // Parse header fields (64-bit): file_offset, vaddr, trampoline_size.
        let tramp_file_offset = u64::from_le_bytes(header_buf[8..16].try_into().unwrap());
        let tramp_vaddr = u64::from_le_bytes(header_buf[16..24].try_into().unwrap()) as u32;
        let tramp_size = u64::from_le_bytes(header_buf[24..32].try_into().unwrap()) as usize;

        if tramp_size == 0 {
            return;
        }

        // Check that the data region has enough space for the trampoline
        // descriptor + code after the mmap data.
        let desc_size = size_of::<TrampolineDescriptor>();
        let needed = mmap_data_len + desc_size + tramp_size;
        let data_region = self.region.data_region_mut();
        if needed > data_region.len() {
            eprintln!(
                "[central] trampoline: data region too small ({needed} > {})",
                data_region.len()
            );
            return;
        }

        // Write the TrampolineDescriptor (2 × u32 LE) manually to avoid
        // depending on zerocopy in this crate.
        data_region[mmap_data_len..mmap_data_len + 4].copy_from_slice(&tramp_vaddr.to_le_bytes());
        data_region[mmap_data_len + 4..mmap_data_len + desc_size]
            .copy_from_slice(&(tramp_size as u32).to_le_bytes());

        // Read trampoline code from the file into the data region via pread64.
        let tramp_dest_ptr = data_region[mmap_data_len + desc_size..].as_mut_ptr();
        {
            let mut regs = litebox_common_linux::PtRegs::default();
            regs.orig_rax = libc::SYS_pread64 as usize;
            regs.rdi = fd as usize;
            regs.rsi = tramp_dest_ptr as usize;
            regs.rdx = tramp_size;
            regs.r10 = tramp_file_offset as usize;
            let result = self.dispatch_to_task(thread_slot, &mut regs);
            if result < tramp_size as i64 {
                eprintln!("[central] trampoline: pread64 returned {result}, expected {tramp_size}");
                return;
            }
        }

        cq.flags |= cq_flags::TRAMPOLINE;
    }

    /// Returns `true` for syscalls that involve guest memory pointers
    /// but do NOT need data transfer through the shmem data region.
    ///
    /// Central cannot dereference guest pointers (separate address space),
    /// so these must be executed locally by micro-LiteBox.
    ///
    /// Note: `read`, `pread64`, `fstat`, `newfstatat` are NOT here — they go
    /// through `is_data_producing_io` instead, which dispatches through the
    /// shim and transfers data via the shmem data region.
    fn needs_local_exec(nr: u32) -> bool {
        matches!(
            i64::from(nr),
            // Socket I/O: micro handles locally (central can't
            // dereference guest sockaddr/msghdr pointers).
            libc::SYS_recvfrom
                | libc::SYS_sendto
                | libc::SYS_recvmsg
                | libc::SYS_sendmsg
                // Arch/thread syscalls: must execute in guest context
                // (set kernel thread-local state in micro's threads).
                | libc::SYS_arch_prctl
                | libc::SYS_set_tid_address
                | libc::SYS_set_robust_list
                | libc::SYS_rseq
                // Sleep: must block in micro's thread.
                | libc::SYS_nanosleep
                | libc::SYS_clock_nanosleep
                // Signal syscalls: must execute locally in micro's process
                // where real kernel signal delivery happens. The guest
                // relies on real alarm() timers and real sigaction handlers.
                | libc::SYS_rt_sigaction
                | libc::SYS_rt_sigprocmask
                | libc::SYS_sigaltstack
                | libc::SYS_rt_sigsuspend
                | libc::SYS_alarm
                // Filesystem sync: no arguments, must execute locally.
                | libc::SYS_sync
                // Process wait: must run in micro's PID namespace where
                // the real child process lives (central has no children).
                | libc::SYS_wait4
                // Memory query: mincore checks page residency on real OS
                // pages in the guest's address space — cannot be done from
                // central's address space.
                | libc::SYS_mincore
        )
    }

    /// Returns `true` for memory management syscalls that central still handles:
    /// mmap/mremap need dual-dispatch (shim for PageManager + EXEC_LOCAL for
    /// micro), brk returns EXEC_LOCAL immediately.
    ///
    /// Note: munmap/mprotect/madvise are now Tier 2 in micro
    /// (notify-after-execute) and no longer reach central.
    fn is_mm_syscall(nr: u32) -> bool {
        matches!(
            i64::from(nr),
            libc::SYS_mmap | libc::SYS_mremap | libc::SYS_brk
        )
    }

    /// Returns `true` for syscalls where central reads/produces data that must
    /// be transferred to micro via the shmem data region.
    ///
    /// These syscalls are dispatched through the shim (to use central's fd
    /// table and filesystem), but the output buffer is redirected to the shmem
    /// data region so micro can copy the result into the guest's memory.
    fn is_data_producing_io(nr: u32) -> bool {
        matches!(
            i64::from(nr),
            libc::SYS_read
                | libc::SYS_pread64
                | libc::SYS_readv
                | libc::SYS_preadv
                | libc::SYS_preadv2
                | libc::SYS_fstat
                | libc::SYS_newfstatat
                | libc::SYS_stat
                | libc::SYS_lstat
                | libc::SYS_readlink
                | libc::SYS_readlinkat
                | libc::SYS_getdents64
                | libc::SYS_getcwd
                // Info queries: shim implements these with virtual values;
                // results are written to the shmem data region and copied
                // to the guest buffer by micro.
                | libc::SYS_uname
                | libc::SYS_sysinfo
                | libc::SYS_getrlimit
                | libc::SYS_prlimit64
                | libc::SYS_sched_getaffinity
                | libc::SYS_getrandom
                | libc::SYS_clock_gettime
                | libc::SYS_gettimeofday
                | libc::SYS_time
                | libc::SYS_clock_getres
        )
    }

    /// Handle a data-producing I/O syscall by dispatching through the shim
    /// with the output buffer pointing into the shmem data region.
    ///
    /// Central dispatches the syscall normally (using the shim's fd table),
    /// but rewrites the guest buffer pointer to point into the data region.
    /// The shim writes the output there, and central returns `EXEC_LOCAL |
    /// HAS_DATA` so micro copies the data into the guest's actual buffer.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn handle_data_producing_io(&self, entry: &SqEntry) -> CqEntry {
        let nr = entry.syscall_nr;
        let mut cq = Self::base_cq(entry);

        // Get a pointer to the data region for output.
        let data_region = self.region.data_region_mut();
        let data_ptr = data_region.as_mut_ptr() as usize;

        let mut regs = crate::dispatch::sq_entry_to_ptregs(entry);

        // For pathname syscalls (newfstatat, stat, lstat, readlink,
        // readlinkat), micro copies the pathname into the data region.
        // Only read it for those syscalls — bidirectional syscalls also use
        // data_len for input struct data, which is a different format.
        let mut pathname_buf: Vec<u8> = Vec::new();
        let is_pathname_syscall = matches!(
            i64::from(nr),
            libc::SYS_newfstatat
                | libc::SYS_stat
                | libc::SYS_lstat
                | libc::SYS_readlink
                | libc::SYS_readlinkat
        );
        if is_pathname_syscall && entry.data_len > 0 {
            let data = self.region.data_region();
            let offset = entry.data_offset as usize;
            let len = entry.data_len as usize;
            if offset + len <= data.len() {
                pathname_buf.extend_from_slice(&data[offset..offset + len]);
            }
        }

        match i64::from(nr) {
            libc::SYS_read => {
                // read(fd, buf, count) — rewrite buf (rsi) to data region.
                let count = entry.args[2] as usize;
                let capped = count.min(data_region.len());
                regs.rsi = data_ptr;
                regs.rdx = capped;
                cq.result = self.dispatch_to_task(entry.thread_slot, &mut regs);
                if cq.result > 0 {
                    cq.flags = cq_flags::EXEC_LOCAL | cq_flags::HAS_DATA | cq_flags::NO_REPORT;
                    cq.data_offset = 0;
                    cq.data_len = cq.result as u32;
                } else if cq.result == 0 {
                    // EOF — still tell micro, result=0.
                    cq.flags = cq_flags::EXEC_LOCAL | cq_flags::NO_REPORT;
                } else if cq.result == -i64::from(libc::EBADF) {
                    // Fd not in shim's table — it's a real OS fd (e.g. pipe).
                    // Let micro execute the read locally. Keep result as -EBADF
                    // so micro can distinguish from EOF.
                    cq.flags = cq_flags::EXEC_LOCAL | cq_flags::NO_REPORT;
                }
                // Other negative: error, pass through directly.
            }
            libc::SYS_pread64 => {
                // pread64(fd, buf, count, offset) — rewrite buf (rsi).
                let count = entry.args[2] as usize;
                let capped = count.min(data_region.len());
                regs.rsi = data_ptr;
                regs.rdx = capped;
                cq.result = self.dispatch_to_task(entry.thread_slot, &mut regs);
                if cq.result > 0 {
                    cq.flags = cq_flags::EXEC_LOCAL | cq_flags::HAS_DATA | cq_flags::NO_REPORT;
                    cq.data_offset = 0;
                    cq.data_len = cq.result as u32;
                } else if cq.result == 0 {
                    cq.flags = cq_flags::EXEC_LOCAL | cq_flags::NO_REPORT;
                }
            }
            libc::SYS_fstat => {
                // fstat(fd, statbuf) — rewrite statbuf (rsi) to data region.
                // struct stat is ~144 bytes on x86_64.
                regs.rsi = data_ptr;
                cq.result = self.dispatch_to_task(entry.thread_slot, &mut regs);
                if cq.result >= 0 {
                    cq.flags = cq_flags::EXEC_LOCAL | cq_flags::HAS_DATA | cq_flags::NO_REPORT;
                    cq.data_offset = 0;
                    // struct stat is 144 bytes on x86_64 Linux.
                    cq.data_len = 144;
                }
            }
            libc::SYS_newfstatat => {
                // newfstatat(dirfd, pathname, statbuf, flags).
                // Rewrite pathname (rsi) if we have it, statbuf (rdx) to data region.
                if !pathname_buf.is_empty() {
                    regs.rsi = pathname_buf.as_ptr() as usize;
                }
                regs.rdx = data_ptr;
                cq.result = self.dispatch_to_task(entry.thread_slot, &mut regs);
                if cq.result >= 0 {
                    cq.flags = cq_flags::EXEC_LOCAL | cq_flags::HAS_DATA | cq_flags::NO_REPORT;
                    cq.data_offset = 0;
                    cq.data_len = 144; // struct stat
                }
            }
            libc::SYS_stat => {
                // stat(pathname, statbuf) — rewrite pathname (rdi) if we have
                // it, statbuf (rsi) to data region.
                if !pathname_buf.is_empty() {
                    regs.rdi = pathname_buf.as_ptr() as usize;
                }
                regs.rsi = data_ptr;
                cq.result = self.dispatch_to_task(entry.thread_slot, &mut regs);
                if cq.result >= 0 {
                    cq.flags = cq_flags::EXEC_LOCAL | cq_flags::HAS_DATA | cq_flags::NO_REPORT;
                    cq.data_offset = 0;
                    cq.data_len = 144; // struct stat
                }
            }
            libc::SYS_lstat => {
                // lstat(pathname, statbuf) — same layout as stat.
                if !pathname_buf.is_empty() {
                    regs.rdi = pathname_buf.as_ptr() as usize;
                }
                regs.rsi = data_ptr;
                cq.result = self.dispatch_to_task(entry.thread_slot, &mut regs);
                if cq.result >= 0 {
                    cq.flags = cq_flags::EXEC_LOCAL | cq_flags::HAS_DATA | cq_flags::NO_REPORT;
                    cq.data_offset = 0;
                    cq.data_len = 144; // struct stat
                }
            }
            libc::SYS_readlink => {
                // readlink(pathname, buf, bufsiz) — rewrite pathname (rdi) if
                // we have it, buf (rsi) to data region.
                if !pathname_buf.is_empty() {
                    regs.rdi = pathname_buf.as_ptr() as usize;
                }
                let bufsiz = entry.args[2] as usize;
                let capped = bufsiz.min(data_region.len());
                regs.rsi = data_ptr;
                regs.rdx = capped;
                cq.result = self.dispatch_to_task(entry.thread_slot, &mut regs);
                if cq.result > 0 {
                    cq.flags = cq_flags::EXEC_LOCAL | cq_flags::HAS_DATA | cq_flags::NO_REPORT;
                    cq.data_offset = 0;
                    cq.data_len = cq.result as u32;
                }
            }
            libc::SYS_readlinkat => {
                // readlinkat(dirfd, pathname, buf, bufsiz) — rewrite pathname
                // (rsi) if we have it, buf (rdx) to data region.
                if !pathname_buf.is_empty() {
                    regs.rsi = pathname_buf.as_ptr() as usize;
                }
                let bufsiz = entry.args[3] as usize;
                let capped = bufsiz.min(data_region.len());
                regs.rdx = data_ptr;
                regs.r10 = capped;
                cq.result = self.dispatch_to_task(entry.thread_slot, &mut regs);
                if cq.result > 0 {
                    cq.flags = cq_flags::EXEC_LOCAL | cq_flags::HAS_DATA | cq_flags::NO_REPORT;
                    cq.data_offset = 0;
                    cq.data_len = cq.result as u32;
                }
            }
            libc::SYS_getdents64 => {
                // getdents64(fd, dirp, count) — rewrite dirp (rsi) to data
                // region.
                let count = entry.args[2] as usize;
                let capped = count.min(data_region.len());
                regs.rsi = data_ptr;
                regs.rdx = capped;
                cq.result = self.dispatch_to_task(entry.thread_slot, &mut regs);
                if cq.result > 0 {
                    cq.flags = cq_flags::EXEC_LOCAL | cq_flags::HAS_DATA | cq_flags::NO_REPORT;
                    cq.data_offset = 0;
                    cq.data_len = cq.result as u32;
                } else if cq.result == 0 {
                    // End of directory.
                    cq.flags = cq_flags::EXEC_LOCAL | cq_flags::NO_REPORT;
                }
            }
            libc::SYS_getcwd => {
                // getcwd(buf, size) — rewrite buf (rdi) to data region.
                let size = entry.args[1] as usize;
                let capped = size.min(data_region.len());
                regs.rdi = data_ptr;
                regs.rsi = capped;
                cq.result = self.dispatch_to_task(entry.thread_slot, &mut regs);
                if cq.result > 0 {
                    cq.flags = cq_flags::EXEC_LOCAL | cq_flags::HAS_DATA | cq_flags::NO_REPORT;
                    cq.data_offset = 0;
                    cq.data_len = cq.result as u32;
                }
            }
            // ── Info queries ────────────────────────────────────────────
            // The shim implements these with virtual values; output is
            // written into the shmem data region and copied to the guest
            // buffer by micro.
            libc::SYS_uname => {
                // uname(buf) — rewrite buf (rdi) to data region.
                // struct utsname = 6 × 65 = 390 bytes.
                const UTSNAME_SIZE: u32 = 390;
                regs.rdi = data_ptr;
                cq.result = self.dispatch_to_task(entry.thread_slot, &mut regs);
                if cq.result >= 0 {
                    cq.flags = cq_flags::EXEC_LOCAL | cq_flags::HAS_DATA | cq_flags::NO_REPORT;
                    cq.data_offset = 0;
                    cq.data_len = UTSNAME_SIZE;
                }
            }
            libc::SYS_sysinfo => {
                // sysinfo(info) — rewrite info (rdi) to data region.
                // struct sysinfo = 112 bytes on x86_64.
                const SYSINFO_SIZE: u32 =
                    core::mem::size_of::<litebox_common_linux::Sysinfo>() as u32;
                regs.rdi = data_ptr;
                cq.result = self.dispatch_to_task(entry.thread_slot, &mut regs);
                if cq.result >= 0 {
                    cq.flags = cq_flags::EXEC_LOCAL | cq_flags::HAS_DATA | cq_flags::NO_REPORT;
                    cq.data_offset = 0;
                    cq.data_len = SYSINFO_SIZE;
                }
            }
            libc::SYS_getrlimit => {
                // getrlimit(resource, rlim) — rewrite rlim (rsi) to data region.
                // struct rlimit = 16 bytes on x86_64.
                const RLIMIT_SIZE: u32 =
                    core::mem::size_of::<litebox_common_linux::Rlimit>() as u32;
                regs.rsi = data_ptr;
                cq.result = self.dispatch_to_task(entry.thread_slot, &mut regs);
                if cq.result >= 0 {
                    cq.flags = cq_flags::EXEC_LOCAL | cq_flags::HAS_DATA | cq_flags::NO_REPORT;
                    cq.data_offset = 0;
                    cq.data_len = RLIMIT_SIZE;
                }
            }
            libc::SYS_prlimit64 => {
                // prlimit64(pid, resource, new_limit, old_limit)
                // Bidirectional: new_limit is input (ConstPtr, arg2/rdx),
                // old_limit is output (MutPtr, arg3/r10).
                // struct rlimit64 = 16 bytes.
                const RLIMIT64_SIZE: usize = core::mem::size_of::<litebox_common_linux::Rlimit64>();
                // If micro sent input data (new_limit != NULL), read from the
                // correct data region offset into a local copy (micro writes
                // at WRITE_DATA_BASE_OFFSET + thread_slot * 65536, not at 0).
                let mut input_buf: Vec<u8> = Vec::new();
                if entry.data_len > 0 {
                    let data = self.region.data_region();
                    let offset = entry.data_offset as usize;
                    let len = entry.data_len as usize;
                    if offset + len <= data.len() {
                        input_buf.extend_from_slice(&data[offset..offset + len]);
                    }
                }
                if !input_buf.is_empty() {
                    // Point new_limit (rdx) at the local copy.
                    regs.rdx = input_buf.as_ptr() as usize;
                }
                // Point old_limit (r10) at offset 0 of the data region for output.
                let old_limit_arg = entry.args[3]; // original r10 from guest
                if old_limit_arg != 0 {
                    regs.r10 = data_ptr;
                }
                cq.result = self.dispatch_to_task(entry.thread_slot, &mut regs);
                if cq.result >= 0 && old_limit_arg != 0 {
                    cq.flags = cq_flags::EXEC_LOCAL | cq_flags::HAS_DATA | cq_flags::NO_REPORT;
                    cq.data_offset = 0;
                    cq.data_len = RLIMIT64_SIZE as u32;
                } else if cq.result >= 0 {
                    // No output requested (old_limit was NULL), just success.
                    cq.flags = cq_flags::EXEC_LOCAL | cq_flags::NO_REPORT;
                }
            }
            libc::SYS_sched_getaffinity => {
                // sched_getaffinity(pid, cpusetsize, mask) — rewrite
                // mask (rdx) to data region.
                let cpusetsize = entry.args[1] as usize;
                let capped = cpusetsize.min(data_region.len());
                regs.rdx = data_ptr;
                regs.rsi = capped;
                cq.result = self.dispatch_to_task(entry.thread_slot, &mut regs);
                if cq.result > 0 {
                    cq.flags = cq_flags::EXEC_LOCAL | cq_flags::HAS_DATA | cq_flags::NO_REPORT;
                    cq.data_offset = 0;
                    cq.data_len = cq.result as u32;
                }
            }
            libc::SYS_getrandom => {
                // getrandom(buf, buflen, flags) — rewrite buf (rdi) to
                // data region.
                let buflen = entry.args[1] as usize;
                let capped = buflen.min(data_region.len());
                regs.rdi = data_ptr;
                regs.rsi = capped;
                cq.result = self.dispatch_to_task(entry.thread_slot, &mut regs);
                if cq.result > 0 {
                    cq.flags = cq_flags::EXEC_LOCAL | cq_flags::HAS_DATA | cq_flags::NO_REPORT;
                    cq.data_offset = 0;
                    cq.data_len = cq.result as u32;
                }
            }
            // ── Time queries ────────────────────────────────────────────
            libc::SYS_clock_gettime => {
                // clock_gettime(clockid, tp) — rewrite tp (rsi) to data
                // region. struct timespec = 16 bytes on x86_64.
                const TIMESPEC_SIZE: u32 = 16;
                regs.rsi = data_ptr;
                cq.result = self.dispatch_to_task(entry.thread_slot, &mut regs);
                if cq.result >= 0 {
                    cq.flags = cq_flags::EXEC_LOCAL | cq_flags::HAS_DATA | cq_flags::NO_REPORT;
                    cq.data_offset = 0;
                    cq.data_len = TIMESPEC_SIZE;
                }
            }
            libc::SYS_clock_getres => {
                // clock_getres(clockid, res) — rewrite res (rsi) to data
                // region. struct timespec = 16 bytes on x86_64.
                const TIMESPEC_SIZE: u32 = 16;
                let res_arg = entry.args[1]; // original rsi from guest
                if res_arg != 0 {
                    regs.rsi = data_ptr;
                }
                cq.result = self.dispatch_to_task(entry.thread_slot, &mut regs);
                if cq.result >= 0 && res_arg != 0 {
                    cq.flags = cq_flags::EXEC_LOCAL | cq_flags::HAS_DATA | cq_flags::NO_REPORT;
                    cq.data_offset = 0;
                    cq.data_len = TIMESPEC_SIZE;
                } else if cq.result >= 0 {
                    cq.flags = cq_flags::EXEC_LOCAL | cq_flags::NO_REPORT;
                }
            }
            libc::SYS_gettimeofday => {
                // gettimeofday(tv, tz) — rewrite tv (rdi) to data region.
                // struct timeval = 16 bytes on x86_64.
                // tz is obsolete and usually NULL; we don't rewrite it.
                const TIMEVAL_SIZE: u32 =
                    core::mem::size_of::<litebox_common_linux::TimeVal>() as u32;
                let tv_arg = entry.args[0]; // original rdi from guest
                if tv_arg != 0 {
                    regs.rdi = data_ptr;
                }
                cq.result = self.dispatch_to_task(entry.thread_slot, &mut regs);
                if cq.result >= 0 && tv_arg != 0 {
                    cq.flags = cq_flags::EXEC_LOCAL | cq_flags::HAS_DATA | cq_flags::NO_REPORT;
                    cq.data_offset = 0;
                    cq.data_len = TIMEVAL_SIZE;
                } else if cq.result >= 0 {
                    cq.flags = cq_flags::EXEC_LOCAL | cq_flags::NO_REPORT;
                }
            }
            libc::SYS_time => {
                // time(tloc) — rewrite tloc (rdi) to data region.
                // time_t = 8 bytes on x86_64. Return value is also the time.
                const TIME_T_SIZE: u32 =
                    core::mem::size_of::<litebox_common_linux::time_t>() as u32;
                let tloc_arg = entry.args[0]; // original rdi from guest
                if tloc_arg != 0 {
                    regs.rdi = data_ptr;
                }
                cq.result = self.dispatch_to_task(entry.thread_slot, &mut regs);
                if cq.result >= 0 && tloc_arg != 0 {
                    cq.flags = cq_flags::EXEC_LOCAL | cq_flags::HAS_DATA | cq_flags::NO_REPORT;
                    cq.data_offset = 0;
                    cq.data_len = TIME_T_SIZE;
                } else if cq.result >= 0 {
                    // tloc was NULL; result is the time value directly.
                    cq.flags = cq_flags::EXEC_LOCAL | cq_flags::NO_REPORT;
                }
            }
            _ => {
                // For readv/preadv/preadv2 — not yet implemented, fall back
                // to EXEC_LOCAL (micro will attempt local execution).
                cq.flags = cq_flags::EXEC_LOCAL | cq_flags::NO_REPORT;
            }
        }

        cq
    }

    /// Returns `true` for syscalls where micro sends write data to central
    /// via the shmem data region, and central dispatches through the shim.
    ///
    /// If the shim returns EBADF (fd not in shim's table), central falls back
    /// to `EXEC_LOCAL` so micro writes to the real OS fd.
    fn is_data_consuming_io(nr: u32) -> bool {
        matches!(
            i64::from(nr),
            libc::SYS_write
                | libc::SYS_pwrite64
                | libc::SYS_writev
                | libc::SYS_pwritev
                | libc::SYS_pwritev2
        )
    }

    /// Handle a data-consuming I/O syscall (write family).
    ///
    /// Micro has already copied the write buffer into the shmem data region.
    /// Central reads it from there, rewrites the buffer pointer in `PtRegs`
    /// to point to the local copy, and dispatches through the shim.
    ///
    /// - If the fd is a standard I/O fd (0, 1, 2): skip shim dispatch and
    ///   go directly to `EXEC_LOCAL` — the shim maps these to virtual
    ///   `/dev/std{in,out,err}` devices, but the guest needs the real OS fds.
    /// - If the shim succeeds (result >= 0): return the result directly.
    /// - If the shim returns -EBADF: the fd is a real OS fd — set `EXEC_LOCAL`
    ///   so micro performs the write locally.
    /// - Other errors: pass through directly.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn handle_data_consuming_io(&self, entry: &SqEntry) -> CqEntry {
        let nr = entry.syscall_nr;
        let mut cq = Self::base_cq(entry);

        // Standard I/O fds (0=stdin, 1=stdout, 2=stderr) must always be
        // handled locally by micro. The shim maps these to virtual /dev/std*
        // devices in the in-memory filesystem, but the guest process needs
        // writes to reach its real OS stdout/stderr (pipes, terminals, etc.).
        let fd = entry.args[0] as i32;
        if (0..=2).contains(&fd) {
            cq.flags = cq_flags::EXEC_LOCAL | cq_flags::NO_REPORT;
            return cq;
        }

        // Read the write data that micro placed in the data region.
        let data = self.region.data_region();
        let offset = entry.data_offset as usize;
        let len = entry.data_len as usize;

        // Validate data region bounds.
        if len == 0 || offset + len > data.len() {
            // No data or invalid bounds — fall back to local exec.
            cq.flags = cq_flags::EXEC_LOCAL | cq_flags::NO_REPORT;
            return cq;
        }

        // Make a local copy of the write data so we have a stable pointer
        // for the shim dispatch (the data region is shared memory).
        let write_buf: Vec<u8> = data[offset..offset + len].to_vec();
        let buf_ptr = write_buf.as_ptr() as usize;

        let mut regs = crate::dispatch::sq_entry_to_ptregs(entry);

        match i64::from(nr) {
            libc::SYS_write => {
                // write(fd, buf, count) — rewrite buf (rsi) to local copy.
                regs.rsi = buf_ptr;
                regs.rdx = len;
            }
            libc::SYS_pwrite64 => {
                // pwrite64(fd, buf, count, offset) — rewrite buf (rsi) to local copy.
                regs.rsi = buf_ptr;
                regs.rdx = len;
            }
            libc::SYS_writev => {
                // writev(fd, iov, iovcnt) — micro gathered iov data into flat buffer.
                // Dispatch as write(fd, buf, count) through shim.
                regs.orig_rax = libc::SYS_write as usize;
                regs.rsi = buf_ptr;
                regs.rdx = len;
            }
            libc::SYS_pwritev => {
                // pwritev(fd, iov, iovcnt, offset) — dispatch as pwrite64(fd, buf, count, offset).
                regs.orig_rax = libc::SYS_pwrite64 as usize;
                regs.rsi = buf_ptr;
                regs.rdx = len;
                // r10 = offset (args[3]), already set from sq_entry_to_ptregs.
            }
            libc::SYS_pwritev2 => {
                // pwritev2(fd, iov, iovcnt, offset, flags).
                // If offset == -1, acts like writev (current file position).
                let offset = entry.args[3].cast_signed();
                if offset == -1 {
                    regs.orig_rax = libc::SYS_write as usize;
                } else {
                    regs.orig_rax = libc::SYS_pwrite64 as usize;
                }
                regs.rsi = buf_ptr;
                regs.rdx = len;
            }
            _ => {
                // Unexpected syscall — fall back to local exec.
                cq.flags = cq_flags::EXEC_LOCAL | cq_flags::NO_REPORT;
                return cq;
            }
        }

        cq.result = self.dispatch_to_task(entry.thread_slot, &mut regs);

        if cq.result >= 0 {
            // Shim handled the write to a virtual fd — return result directly.
        } else if cq.result == -i64::from(libc::EBADF) {
            // Fd not in shim's table — it's a real OS fd (e.g. stdout, pipe).
            // Tell micro to execute the write locally.
            cq.flags = cq_flags::EXEC_LOCAL | cq_flags::NO_REPORT;
        }
        // Other negative: error from shim, pass through directly.

        cq
    }

    /// Handle a `pipe2` syscall by creating virtual pipe fds in the shim's
    /// fd table, allocating a shmem ring buffer slot, and returning the fd
    /// pair + slot offset to micro via the data region.
    ///
    /// The guest's `pipefd` pointer (arg0/rdi) is in micro's address space
    /// and cannot be dereferenced by central. We redirect it to a local
    /// `[u32; 2]` buffer so the shim writes fd values into central's memory,
    /// then package them in a `Pipe2Response` for micro.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_possible_wrap
    )]
    fn handle_pipe2(&self, entry: &SqEntry) -> CqEntry {
        let mut cq = Self::base_cq(entry);
        let flags = entry.args[1] as i32;

        // Create a local buffer for the shim to write the fd pair into.
        // This avoids the guest pointer problem — the shim writes to
        // central's memory instead of micro's address space.
        let mut fd_buf: [u32; 2] = [0; 2];
        let mut regs = crate::dispatch::sq_entry_to_ptregs(entry);
        regs.rdi = fd_buf.as_mut_ptr() as usize; // redirect pipefd pointer

        let shim_result = self.dispatch_to_task(entry.thread_slot, &mut regs);
        if shim_result < 0 {
            cq.result = shim_result;
            return cq;
        }

        // Extract fd pair from our local buffer.
        let read_fd = fd_buf[0] as i32;
        let write_fd = fd_buf[1] as i32;

        // Allocate a shmem pipe slot for the ring buffer.
        let mut ns = self.notification_state.borrow_mut();
        let Some((slot_index, slot_offset)) = ns.alloc_pipe_slot() else {
            // No free pipe slots — return EMFILE.
            cq.result = -i64::from(libc::EMFILE);
            return cq;
        };

        // Initialize the ring buffer header in shmem.
        let nonblock = flags & libc::O_NONBLOCK != 0;
        {
            let data_region = self.region.data_region_mut();
            #[allow(clippy::cast_ptr_alignment)] // slot offsets are 64-byte aligned by design
            let header_ptr = unsafe {
                data_region
                    .as_mut_ptr()
                    .add(slot_offset as usize)
                    .cast::<litebox_ipc::ring::ShmemPipeHeader>()
            };
            unsafe {
                litebox_ipc::pipe::pipe_init(header_ptr, read_fd, write_fd, nonblock);
            }
        }

        // Track the pipe in notification state.
        ns.shmem_pipes.push(crate::notification_state::ShmemPipe {
            read_fd,
            write_fd,
            slot_index,
            open_ends: 2,
        });

        // Write a Pipe2Response to the data region at offset 0 for micro.
        let response = litebox_ipc::messages::Pipe2Response {
            read_fd,
            write_fd,
            pipe_slot_offset: slot_offset,
            _pad: 0,
        };
        {
            let data_region = self.region.data_region_mut();
            let resp_bytes: &[u8] = unsafe {
                core::slice::from_raw_parts(
                    (&raw const response).cast::<u8>(),
                    core::mem::size_of::<litebox_ipc::messages::Pipe2Response>(),
                )
            };
            data_region[..resp_bytes.len()].copy_from_slice(resp_bytes);
        }

        // Return CQ with EXEC_LOCAL | HAS_DATA | NO_REPORT.
        // EXEC_LOCAL tells micro to enter its local-exec block where it
        // detects HAS_DATA for pipe2 and reads the Pipe2Response.
        cq.result = 0;
        cq.flags = cq_flags::EXEC_LOCAL | cq_flags::HAS_DATA | cq_flags::NO_REPORT;
        cq.data_offset = 0;
        cq.data_len = core::mem::size_of::<litebox_ipc::messages::Pipe2Response>() as u32;
        cq
    }

    /// If `fd` is one end of a shmem pipe, set the appropriate closed flag,
    /// futex-wake blocked readers/writers, and decrement `open_ends`. When
    /// both ends are closed, free the pipe slot.
    fn maybe_close_shmem_pipe_end(&self, fd: i32) {
        let mut ns = self.notification_state.borrow_mut();
        let Some(pipe) = ns.find_shmem_pipe_mut(fd) else {
            return;
        };

        // Determine which flag to set based on which end is being closed.
        let flag = if fd == pipe.read_fd {
            pipe_flags::READER_CLOSED
        } else {
            pipe_flags::WRITER_CLOSED
        };

        let slot_offset = PIPE_ZONE_BASE_OFFSET + pipe.slot_index as usize * PIPE_SLOT_SIZE;

        // Set the closed flag in the shmem pipe header.
        let data_region = self.region.data_region_mut();
        #[allow(clippy::cast_ptr_alignment)] // slot offsets are 64-byte aligned by design
        let header_ptr = unsafe {
            data_region
                .as_mut_ptr()
                .add(slot_offset)
                .cast::<litebox_ipc::ring::ShmemPipeHeader>()
        };
        unsafe {
            litebox_ipc::pipe::pipe_set_flag(header_ptr, flag);
        }

        // Futex-wake any blocked readers/writers on both head and tail.
        unsafe {
            let head_ptr = &raw const (*header_ptr).head;
            let tail_ptr = &raw const (*header_ptr).tail;
            libc::syscall(
                libc::SYS_futex,
                head_ptr,
                libc::FUTEX_WAKE,
                i32::MAX,
                std::ptr::null::<libc::timespec>(),
            );
            libc::syscall(
                libc::SYS_futex,
                tail_ptr,
                libc::FUTEX_WAKE,
                i32::MAX,
                std::ptr::null::<libc::timespec>(),
            );
        }

        // Decrement open_ends; free slot when both ends are closed.
        pipe.open_ends -= 1;
        if pipe.open_ends == 0 {
            let slot_index = pipe.slot_index;
            // Remove the pipe entry from the vec.
            let idx = ns
                .shmem_pipes
                .iter()
                .position(|p| p.slot_index == slot_index)
                .expect("pipe must exist");
            ns.shmem_pipes.swap_remove(idx);
            ns.free_pipe_slot(slot_index);
        }
    }

    /// Handle an execve syscall by deserializing the path/argv/envp from the
    /// data region and delegating to `handle_execve_inner`.
    ///
    /// The data region from micro contains serialized path/argv/envp.
    /// Central reads the ELF file, parses it, and packs all segment data into
    /// the data region for micro to consume.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_possible_wrap,
        clippy::too_many_lines,
        clippy::field_reassign_with_default
    )]
    fn handle_execve(&self, entry: &SqEntry) -> CqEntry {
        let mut cq = Self::base_cq(entry);

        // Read serialized path/argv/envp from the data region.
        let data = self.region.data_region();
        let data_len = entry.data_len as usize;
        if data_len == 0 || data_len > data.len() {
            cq.result = -i64::from(libc::EFAULT);
            return cq;
        }
        let serialized = &data[..data_len];

        let Some((path_bytes, after_path)) = deserialize_execve_path(serialized) else {
            cq.result = -i64::from(libc::EINVAL);
            return cq;
        };

        let Some((argv_strs, after_argv)) = deserialize_string_vector(serialized, after_path)
        else {
            cq.result = -i64::from(libc::EINVAL);
            return cq;
        };

        let Some((envp_strs, _after_envp)) = deserialize_string_vector(serialized, after_argv)
        else {
            cq.result = -i64::from(libc::EINVAL);
            return cq;
        };

        self.handle_execve_inner(entry, path_bytes, &argv_strs, &envp_strs)
    }

    /// Inner execve handler: opens the target binary, checks for shebang
    /// scripts, parses ELF, and packs segment data into the data region.
    ///
    /// Separated from `handle_execve` so shebang scripts can re-dispatch
    /// with the interpreter binary as the target.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_possible_wrap,
        clippy::too_many_lines,
        clippy::field_reassign_with_default
    )]
    fn handle_execve_inner(
        &self,
        entry: &SqEntry,
        path_bytes: &[u8],
        argv_strs: &[&[u8]],
        envp_strs: &[&[u8]],
    ) -> CqEntry {
        let mut cq = Self::base_cq(entry);
        let thread_slot = entry.thread_slot;

        // Open the file via shim dispatch (SYS_openat with AT_FDCWD).
        // Build a null-terminated path in a local buffer.
        let mut path_cstr = vec![0u8; path_bytes.len() + 1];
        path_cstr[..path_bytes.len()].copy_from_slice(path_bytes);
        // Ensure null terminated — path_bytes may already include NUL.
        if path_bytes.last() == Some(&0) {
            path_cstr.truncate(path_bytes.len());
        } else {
            path_cstr[path_bytes.len()] = 0;
        }

        let fd = {
            let mut regs = litebox_common_linux::PtRegs::default();
            regs.orig_rax = libc::SYS_openat as usize;
            regs.rdi = libc::AT_FDCWD as usize;
            regs.rsi = path_cstr.as_ptr() as usize;
            regs.rdx = libc::O_RDONLY as usize;
            self.dispatch_to_task(thread_slot, &mut regs)
        };
        if fd < 0 {
            cq.result = fd;
            return cq;
        }
        let fd = fd as i32;

        // Get file size via fstat.
        let file_size = {
            let mut stat_buf = [0u8; 144];
            let mut regs = litebox_common_linux::PtRegs::default();
            regs.orig_rax = libc::SYS_fstat as usize;
            regs.rdi = fd as usize;
            regs.rsi = stat_buf.as_mut_ptr() as usize;
            let result = self.dispatch_to_task(thread_slot, &mut regs);
            if result < 0 {
                self.close_fd(thread_slot, fd);
                cq.result = result;
                return cq;
            }
            i64::from_le_bytes(stat_buf[48..56].try_into().unwrap()) as usize
        };

        // Read the entire file.
        let mut file_data = vec![0u8; file_size];
        {
            let mut offset = 0usize;
            while offset < file_size {
                let chunk = (file_size - offset).min(1024 * 1024); // 1 MiB chunks
                let mut regs = litebox_common_linux::PtRegs::default();
                regs.orig_rax = libc::SYS_pread64 as usize;
                regs.rdi = fd as usize;
                regs.rsi = file_data[offset..].as_mut_ptr() as usize;
                regs.rdx = chunk;
                regs.r10 = offset;
                let result = self.dispatch_to_task(thread_slot, &mut regs);
                if result <= 0 {
                    self.close_fd(thread_slot, fd);
                    cq.result = if result == 0 {
                        -i64::from(libc::EIO)
                    } else {
                        result
                    };
                    return cq;
                }
                offset += result as usize;
            }
        }
        self.close_fd(thread_slot, fd);

        // Check for shebang (#!) scripts.
        //
        // If the file starts with `#!`, parse the interpreter path and optional
        // argument, rebuild argv per Linux convention, and re-dispatch with the
        // interpreter binary as the target. Limited to one level of indirection
        // (the interpreter must be an ELF binary).
        if let Some((interp_path, interp_arg)) = parse_shebang(&file_data) {
            let mut new_argv: Vec<&[u8]> = Vec::new();
            new_argv.push(interp_path);
            if let Some(arg) = interp_arg {
                new_argv.push(arg);
            }
            new_argv.push(path_bytes);
            for a in argv_strs.iter().skip(1) {
                new_argv.push(a);
            }
            // Recursive call — the interpreter must be an ELF binary.
            // If it's another shebang script, parse_shebang will fire again,
            // but Linux limits this to a small number of levels. We allow
            // one level of recursion here (interpreter must be ELF).
            return self.handle_execve_inner(entry, interp_path, &new_argv, envp_strs);
        }

        // Parse the ELF.
        let mut reader = MemReader(&file_data);
        let Ok(mut parsed) = litebox_common_linux::loader::ElfParsedFile::parse(&mut reader) else {
            cq.result = -i64::from(libc::ENOEXEC);
            return cq;
        };

        // Get the syscall entry point (central returns 0, but micro needs
        // the real value — we'll get it from the existing trampoline handling).
        // For central, the platform returns 0 for syscall_entry_point. But
        // micro needs the real entry point. We'll use the same value that the
        // launcher would use — this is set by micro's trampoline assembly.
        // Since we don't have it here, we pass a non-zero sentinel (1) to
        // enable trampoline parsing. Micro will patch the actual value.
        let syscall_entry_point = 1usize; // sentinel — micro patches the real value

        // Parse trampoline for the main binary.
        let _ = parsed.parse_trampoline(&mut reader, syscall_entry_point);

        // Check for interpreter.
        let interp_name = parsed.interp(&mut reader).ok().flatten();
        let interp_data: Option<(Vec<u8>, litebox_common_linux::loader::ElfParsedFile)> =
            if let Some(ref name) = interp_name {
                let interp_path_bytes = name.to_bytes_with_nul();
                let mut interp_cstr = vec![0u8; interp_path_bytes.len()];
                interp_cstr.copy_from_slice(interp_path_bytes);

                let interp_fd = {
                    let mut regs = litebox_common_linux::PtRegs::default();
                    regs.orig_rax = libc::SYS_openat as usize;
                    regs.rdi = libc::AT_FDCWD as usize;
                    regs.rsi = interp_cstr.as_ptr() as usize;
                    regs.rdx = libc::O_RDONLY as usize;
                    self.dispatch_to_task(thread_slot, &mut regs)
                };
                if interp_fd < 0 {
                    cq.result = interp_fd;
                    return cq;
                }
                let interp_fd = interp_fd as i32;

                let interp_size = {
                    let mut stat_buf = [0u8; 144];
                    let mut regs = litebox_common_linux::PtRegs::default();
                    regs.orig_rax = libc::SYS_fstat as usize;
                    regs.rdi = interp_fd as usize;
                    regs.rsi = stat_buf.as_mut_ptr() as usize;
                    let result = self.dispatch_to_task(thread_slot, &mut regs);
                    if result < 0 {
                        self.close_fd(thread_slot, interp_fd);
                        cq.result = result;
                        return cq;
                    }
                    i64::from_le_bytes(stat_buf[48..56].try_into().unwrap()) as usize
                };

                let mut interp_file_data = vec![0u8; interp_size];
                {
                    let mut offset = 0usize;
                    while offset < interp_size {
                        let chunk = (interp_size - offset).min(1024 * 1024);
                        let mut regs = litebox_common_linux::PtRegs::default();
                        regs.orig_rax = libc::SYS_pread64 as usize;
                        regs.rdi = interp_fd as usize;
                        regs.rsi = interp_file_data[offset..].as_mut_ptr() as usize;
                        regs.rdx = chunk;
                        regs.r10 = offset;
                        let result = self.dispatch_to_task(thread_slot, &mut regs);
                        if result <= 0 {
                            self.close_fd(thread_slot, interp_fd);
                            cq.result = if result == 0 {
                                -i64::from(libc::EIO)
                            } else {
                                result
                            };
                            return cq;
                        }
                        offset += result as usize;
                    }
                }
                self.close_fd(thread_slot, interp_fd);

                let mut ireader = MemReader(&interp_file_data);
                let Ok(mut iparsed) =
                    litebox_common_linux::loader::ElfParsedFile::parse(&mut ireader)
                else {
                    cq.result = -i64::from(libc::ENOEXEC);
                    return cq;
                };
                let _ = iparsed.parse_trampoline(&mut ireader, syscall_entry_point);
                Some((interp_file_data, iparsed))
            } else {
                None
            };

        // Build segment list by simulating the load.
        // We use SimpleMapper to capture the segments without actually mapping.
        let mut main_mapper = SimpleMapper::new();
        let mut main_mem = SimpleMem::new();
        let Ok(main_info) = parsed.load(&mut main_mapper, &mut main_mem) else {
            cq.result = -i64::from(libc::ENOEXEC);
            return cq;
        };

        let interp_info = if let Some((ref _idata, ref iparsed)) = interp_data {
            // Start the interpreter after the main binary's segments so they
            // don't overlap.  Align up to page boundary.
            let interp_start = (main_mapper.next_addr + 0xFFF) & !0xFFF;
            let mut imapper = SimpleMapper::new_at(interp_start);
            let mut imem = SimpleMem::new();
            if let Ok(info) = iparsed.load(&mut imapper, &mut imem) {
                Some((info, imapper, imem))
            } else {
                cq.result = -i64::from(libc::ENOEXEC);
                return cq;
            }
        } else {
            None
        };

        // Now pack everything into the data region for micro.
        let data_region = self.region.data_region_mut();
        let data_region_size = data_region.len();

        // Collect segments from main + interp.
        let mut segments: Vec<SegmentInfo> = Vec::new();

        // Main ELF segments.
        for seg in &main_mapper.segments {
            segments.push(SegmentInfo {
                vaddr: seg.address as u64,
                map_len: seg.len as u64,
                data_len: seg.file_len as u64,
                prot: seg.prot_flags() as u32,
                file_data_offset: seg.file_offset,
                file_data_source: FileSource::Main,
                has_trampoline: seg.is_trampoline,
                trampoline_base: if seg.is_trampoline {
                    main_mapper.base_addr
                } else {
                    0
                },
            });
        }

        // Interp segments.
        if let Some((ref _iinfo, ref imapper, _)) = interp_info {
            for seg in &imapper.segments {
                segments.push(SegmentInfo {
                    vaddr: seg.address as u64,
                    map_len: seg.len as u64,
                    data_len: seg.file_len as u64,
                    prot: seg.prot_flags() as u32,
                    file_data_offset: seg.file_offset,
                    file_data_source: FileSource::Interp,
                    has_trampoline: seg.is_trampoline,
                    trampoline_base: if seg.is_trampoline {
                        imapper.base_addr
                    } else {
                        0
                    },
                });
            }
        }

        let num_segments = segments.len();

        // Compute layout.
        let header_size = size_of::<ExecveHeaderCentral>();
        let segments_size = num_segments * size_of::<ExecveSegmentCentral>();
        let after_segments = header_size + segments_size;

        // Serialize argv strings (NUL-separated).
        let mut argv_bytes: Vec<u8> = Vec::new();
        for s in argv_strs {
            argv_bytes.extend_from_slice(s);
            // Ensure NUL termination.
            if s.last() != Some(&0) {
                argv_bytes.push(0);
            }
        }

        // Serialize envp strings (NUL-separated).
        let mut envp_bytes: Vec<u8> = Vec::new();
        for s in envp_strs {
            envp_bytes.extend_from_slice(s);
            if s.last() != Some(&0) {
                envp_bytes.push(0);
            }
        }

        let argv_offset = after_segments;
        let envp_offset = argv_offset + argv_bytes.len();
        let mut data_cursor = envp_offset + envp_bytes.len();

        // Compute data offsets for each segment's file data and trampoline data.
        let mut seg_layouts: Vec<SegLayout> = Vec::with_capacity(num_segments);

        for seg in &segments {
            let seg_data_offset = data_cursor;
            data_cursor += seg.data_len as usize;

            let tramp_desc_len = if seg.has_trampoline {
                // We need to compute the trampoline descriptor size.
                // The trampoline data is embedded in the file data of the source ELF.
                // Actually, we use the parse_trampoline info from the parsed ELF.
                // For simplicity in this first implementation, compute from file data.
                let source_data = match seg.file_data_source {
                    FileSource::Main => &file_data,
                    FileSource::Interp => {
                        if let Some((ref idata, _)) = interp_data {
                            idata.as_slice()
                        } else {
                            &[]
                        }
                    }
                };
                // Read trampoline header from end of file.
                let tramp_info = read_trampoline_header(source_data);
                if let Some((_, tramp_size)) = tramp_info {
                    8 + tramp_size // descriptor (8 bytes) + code
                } else {
                    0
                }
            } else {
                0
            };
            data_cursor += tramp_desc_len;
            seg_layouts.push(SegLayout {
                data_offset: seg_data_offset,
                tramp_desc_len,
            });
        }

        let total_data_len = data_cursor;

        if total_data_len > data_region_size {
            cq.result = -i64::from(libc::E2BIG);
            return cq;
        }

        // Determine entry points.
        let main_entry = main_info.entry_point as u64;
        let jump_entry = interp_info
            .as_ref()
            .map_or(main_entry, |(iinfo, _, _)| iinfo.entry_point as u64);

        let interp_base = interp_info
            .as_ref()
            .map_or(0u64, |(iinfo, _, _)| iinfo.base_addr as u64);

        // The brk must be past ALL mapped segments (main binary + interpreter).
        // Using only main_info.brk would place it inside the interpreter's
        // address range since the interpreter is loaded right after the main
        // binary.  When the new ld-linux calls brk(0), the kernel returns the
        // current brk — if it falls inside the interpreter, the allocator
        // corrupts interpreter data and crashes.
        let brk = interp_info
            .as_ref()
            .map_or(main_info.brk, |(iinfo, _, _)| main_info.brk.max(iinfo.brk));

        // Write ExecveHeader.
        let hdr = ExecveHeaderCentral {
            num_segments: num_segments as u32,
            _pad0: 0,
            entry_point: jump_entry,
            at_entry: main_entry,
            brk: brk as u64,
            phdr_addr: main_info.phdrs_addr as u64,
            phnum: main_info.num_phdrs as u32,
            phent: main_info.phent_size() as u32,
            interp_base,
            argc: argv_strs.len() as u32,
            envc: envp_strs.len() as u32,
            argv_offset: argv_offset as u32,
            argv_len: argv_bytes.len() as u32,
            envp_offset: envp_offset as u32,
            envp_len: envp_bytes.len() as u32,
            syscall_entry_point: 0, // micro will patch this from its own trampoline
        };

        // Copy header bytes.
        let hdr_bytes: &[u8] = unsafe {
            core::slice::from_raw_parts(
                (&raw const hdr).cast::<u8>(),
                size_of::<ExecveHeaderCentral>(),
            )
        };
        data_region[..header_size].copy_from_slice(hdr_bytes);

        // Write ExecveSegment entries.
        for (i, seg) in segments.iter().enumerate() {
            let layout = &seg_layouts[i];
            let seg_entry = ExecveSegmentCentral {
                vaddr: seg.vaddr,
                map_len: seg.map_len,
                data_len: seg.data_len,
                prot: seg.prot,
                has_trampoline: u32::from(seg.has_trampoline && layout.tramp_desc_len > 0),
                data_offset: layout.data_offset as u64,
            };
            let seg_bytes: &[u8] = unsafe {
                core::slice::from_raw_parts(
                    (&raw const seg_entry).cast::<u8>(),
                    size_of::<ExecveSegmentCentral>(),
                )
            };
            let offset = header_size + i * size_of::<ExecveSegmentCentral>();
            data_region[offset..offset + size_of::<ExecveSegmentCentral>()]
                .copy_from_slice(seg_bytes);
        }

        // Write argv strings.
        data_region[argv_offset..argv_offset + argv_bytes.len()].copy_from_slice(&argv_bytes);

        // Write envp strings.
        data_region[envp_offset..envp_offset + envp_bytes.len()].copy_from_slice(&envp_bytes);

        // Write segment file data + trampoline data.
        for (i, seg) in segments.iter().enumerate() {
            let layout = &seg_layouts[i];
            let source_data = match seg.file_data_source {
                FileSource::Main => &file_data,
                FileSource::Interp => {
                    if let Some((ref idata, _)) = interp_data {
                        idata.as_slice()
                    } else {
                        &[]
                    }
                }
            };

            // Copy file-backed data for this segment.
            let file_offset = seg.file_data_offset as usize;
            let copy_len = seg.data_len as usize;
            if copy_len > 0 && file_offset + copy_len <= source_data.len() {
                data_region[layout.data_offset..layout.data_offset + copy_len]
                    .copy_from_slice(&source_data[file_offset..file_offset + copy_len]);
            } else if copy_len > 0 {
                // File data shorter than expected — zero-fill.
                let available = source_data.len().saturating_sub(file_offset);
                if available > 0 {
                    data_region[layout.data_offset..layout.data_offset + available]
                        .copy_from_slice(&source_data[file_offset..file_offset + available]);
                }
                // Rest is already zeroed (or will be by mmap on micro side).
            }

            // Copy trampoline data if present.
            if seg.has_trampoline && layout.tramp_desc_len > 0 {
                let tramp_info = read_trampoline_header(source_data);
                if let Some((tramp_file_offset, tramp_size)) = tramp_info {
                    let desc_start = layout.data_offset + copy_len;
                    // Read vaddr from trampoline header.
                    let tramp_hdr_offset = source_data.len() - 32;
                    let tramp_vaddr = u64::from_le_bytes(
                        source_data[tramp_hdr_offset + 16..tramp_hdr_offset + 24]
                            .try_into()
                            .unwrap(),
                    );
                    // Write descriptor: [u32 LE: absolute trampoline address] [u32 LE: size]
                    let tramp_absolute = seg.trampoline_base as u64 + tramp_vaddr;
                    data_region[desc_start..desc_start + 4]
                        .copy_from_slice(&(tramp_absolute as u32).to_le_bytes());
                    data_region[desc_start + 4..desc_start + 8]
                        .copy_from_slice(&(tramp_size as u32).to_le_bytes());

                    // Copy trampoline code from the file.
                    let tramp_src_start = tramp_file_offset as usize;
                    if tramp_src_start + tramp_size <= source_data.len() {
                        data_region[desc_start + 8..desc_start + 8 + tramp_size].copy_from_slice(
                            &source_data[tramp_src_start..tramp_src_start + tramp_size],
                        );
                    }
                }
            }
        }

        // Zero BSS regions in the packed data.
        //
        // The ELF loader records BSS (zero-fill) ranges via SimpleMem::zero().
        // These correspond to the gap between p_filesz and p_memsz within
        // file-backed pages. Without zeroing, those bytes contain whatever
        // happens to follow in the ELF file (section headers, string tables,
        // trampoline data), which corrupts BSS variables like ld-linux's
        // internal allocator state.
        let all_bss: Vec<(usize, usize)> = {
            let mut ranges = main_mem.bss_ranges;
            if let Some((_, _, ref imem)) = interp_info {
                ranges.extend_from_slice(&imem.bss_ranges);
            }
            ranges
        };
        for (bss_addr, bss_len) in &all_bss {
            // Find which segment contains this BSS address and zero it
            // in the packed data region.
            for (i, seg) in segments.iter().enumerate() {
                let seg_start = seg.vaddr as usize;
                let seg_end = seg_start + seg.data_len as usize;
                if *bss_addr >= seg_start && *bss_addr < seg_end {
                    let offset_in_seg = *bss_addr - seg_start;
                    let zero_end = (offset_in_seg + bss_len).min(seg.data_len as usize);
                    let data_start = seg_layouts[i].data_offset + offset_in_seg;
                    let data_end = seg_layouts[i].data_offset + zero_end;
                    data_region[data_start..data_end].fill(0);
                    break;
                }
            }
        }

        cq.result = 0;
        cq.flags = cq_flags::EXEC_LOCAL | cq_flags::HAS_DATA | cq_flags::NO_REPORT;
        cq.data_offset = 0;
        cq.data_len = total_data_len as u32;
        cq
    }

    /// Close a file descriptor via the shim.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn close_fd(&self, thread_slot: u16, fd: i32) {
        let mut regs = litebox_common_linux::PtRegs {
            orig_rax: libc::SYS_close as usize,
            rdi: fd as usize,
            ..litebox_common_linux::PtRegs::default()
        };
        let _ = self.dispatch_to_task(thread_slot, &mut regs);
    }

    /// Dispatch a control message from an SQ entry.
    ///
    /// Handles thread lifecycle messages (`MSG_THREAD_REGISTER`,
    /// `MSG_THREAD_DEREGISTER`), fork lifecycle messages (`MSG_LOCAL_RESULT`
    /// for fork results, `MSG_CHILD_READY`), and stubs for other known
    /// control messages.
    fn handle_control_message(&self, entry: &SqEntry) -> CqEntry {
        let mut cq = Self::base_cq(entry);
        #[allow(clippy::match_same_arms)] // arms will diverge as bookkeeping is added
        let result = match entry.syscall_nr {
            MSG_THREAD_REGISTER => {
                // Assign the next available thread slot.
                let slot = self.next_thread_slot.get();
                self.next_thread_slot.set(slot + 1);

                // Move the most recent pending task to the active map.
                // The child thread registers shortly after clone, so
                // pending_tasks should have an entry.
                if let Some(task) = self.pending_tasks.borrow_mut().pop() {
                    self.thread_tasks.borrow_mut().insert(slot, task);
                }

                i64::from(slot)
            }
            MSG_THREAD_DEREGISTER => {
                // Remove the task for the given thread slot.
                #[allow(clippy::cast_possible_truncation)]
                let slot = entry.args[0] as u16;
                self.thread_tasks.borrow_mut().remove(&slot);
                0
            }
            MSG_LOCAL_RESULT => {
                // Micro reports the result of a locally-executed syscall.
                // We may need to do bookkeeping here (e.g. page table updates)
                // but for now just acknowledge.
                0
            }
            MSG_CHILD_READY => {
                // The child process has finished post-fork initialization.
                // The child server was already spawned in handle_fork(), so
                // this is just an acknowledgement — no action needed.
                0
            }
            // MSG_FORK_RESULT is a no-op acknowledgement.
            MSG_FORK_RESULT => 0,
            MSG_NOTIFY_SIGACTION => {
                #[allow(clippy::cast_possible_truncation)]
                let signum = entry.args[0] as usize;
                #[allow(clippy::cast_possible_wrap)]
                let result = entry.args[4].cast_signed();
                if result == 0 && signum < 64 {
                    let mut state = self.notification_state.borrow_mut();
                    state.signal_actions[signum] = Some(crate::notification_state::SignalAction {
                        handler: entry.args[1],
                        flags: entry.args[2],
                        mask: entry.args[3],
                    });
                }
                0
            }
            MSG_NOTIFY_SIGPROCMASK => {
                #[allow(clippy::cast_possible_truncation)]
                let how = entry.args[0] as i32;
                let new_mask = entry.args[1];
                let result = entry.args[2].cast_signed();
                if result == 0 {
                    let slot = entry.thread_slot as usize;
                    let mut state = self.notification_state.borrow_mut();
                    match how {
                        libc::SIG_BLOCK => state.signal_masks[slot] |= new_mask,
                        libc::SIG_UNBLOCK => state.signal_masks[slot] &= !new_mask,
                        libc::SIG_SETMASK => state.signal_masks[slot] = new_mask,
                        _ => {}
                    }
                }
                0
            }
            MSG_NOTIFY_SIGALTSTACK => {
                let result = entry.args[3].cast_signed();
                if result == 0 {
                    let slot = entry.thread_slot as usize;
                    let mut state = self.notification_state.borrow_mut();
                    state.alt_stacks[slot] = Some(crate::notification_state::AltStack {
                        sp: entry.args[0],
                        size: entry.args[1],
                        flags: entry.args[2],
                    });
                }
                0
            }
            MSG_NOTIFY_ALARM => {
                let mut state = self.notification_state.borrow_mut();
                #[allow(clippy::cast_possible_truncation)]
                {
                    state.alarm_seconds = entry.args[0] as u32;
                }
                0
            }
            // MSG_NOTIFY_PIPE2 removed: pipe2 is now Tier 3 (full round-trip),
            // handled via shmem-backed pipes. No Tier 2 notification path.
            MSG_NOTIFY_WAIT4 => {
                #[allow(clippy::cast_possible_truncation)]
                let returned_pid = entry.args[1] as i32;
                #[allow(clippy::cast_possible_truncation)]
                let status = entry.args[2] as i32;
                if returned_pid > 0 {
                    let mut state = self.notification_state.borrow_mut();
                    state.reaped_children.push((returned_pid, status));
                }
                0
            }
            MSG_NOTIFY_MUNMAP => {
                #[allow(clippy::cast_possible_wrap)]
                let result = entry.args[2].cast_signed();
                if result == 0 {
                    let mut state = self.notification_state.borrow_mut();
                    state
                        .vma_events
                        .push(crate::notification_state::VmaEvent::Munmap {
                            addr: entry.args[0],
                            len: entry.args[1],
                        });
                }
                0
            }
            MSG_NOTIFY_MPROTECT => {
                #[allow(clippy::cast_possible_wrap)]
                let result = entry.args[3].cast_signed();
                if result == 0 {
                    let mut state = self.notification_state.borrow_mut();
                    #[allow(clippy::cast_possible_truncation)]
                    state
                        .vma_events
                        .push(crate::notification_state::VmaEvent::Mprotect {
                            addr: entry.args[0],
                            len: entry.args[1],
                            prot: entry.args[2] as u32,
                        });
                }
                0
            }
            MSG_NOTIFY_MADVISE => {
                #[allow(clippy::cast_possible_wrap)]
                let result = entry.args[3].cast_signed();
                if result == 0 {
                    let mut state = self.notification_state.borrow_mut();
                    #[allow(clippy::cast_possible_truncation)]
                    state
                        .vma_events
                        .push(crate::notification_state::VmaEvent::Madvise {
                            addr: entry.args[0],
                            len: entry.args[1],
                            advice: entry.args[2] as u32,
                        });
                }
                0
            }
            MSG_NOTIFY_UMASK => {
                // Micro executed umask locally. Update the shim's stored umask
                // so that subsequent open/creat/mkdir on central apply the
                // correct permission mask.
                #[allow(clippy::cast_possible_truncation)]
                let new_mask = entry.args[0] as u32;
                #[allow(clippy::cast_possible_truncation)]
                let mut regs = litebox_common_linux::PtRegs {
                    orig_rax: libc::SYS_umask as usize,
                    rdi: new_mask as usize,
                    ..litebox_common_linux::PtRegs::default()
                };
                let _ = self.dispatch_to_task(entry.thread_slot, &mut regs);
                0
            }
            _ => -i64::from(libc::ENOSYS),
        };
        cq.result = result;
        cq
    }
}

// ── Execve helper types ─────────────────────────────────────────────────────

/// Parse a `#!` shebang line from the start of a file.
///
/// Returns `Some((interpreter_path, optional_arg))` if the file starts with
/// `#!`. The interpreter path and optional argument are byte slices without
/// leading/trailing whitespace. Returns `None` if the file is not a shebang
/// script.
///
/// Linux limits shebang parsing to the first 256 bytes.
fn parse_shebang(data: &[u8]) -> Option<(&[u8], Option<&[u8]>)> {
    if data.len() < 3 || data[0] != b'#' || data[1] != b'!' {
        return None;
    }

    // Find the end of the first line (max 256 bytes per Linux convention).
    let max_len = data.len().min(256);
    let line_end = data[2..max_len]
        .iter()
        .position(|&b| b == b'\n')
        .map_or(max_len, |p| p + 2);
    let line = &data[2..line_end];

    // Skip leading whitespace after #!
    let start = line
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(line.len());
    let line = &line[start..];
    if line.is_empty() {
        return None;
    }

    // Interpreter path: up to first whitespace.
    let interp_end = line
        .iter()
        .position(u8::is_ascii_whitespace)
        .unwrap_or(line.len());
    let interp = &line[..interp_end];
    if interp.is_empty() {
        return None;
    }

    // Optional argument: rest of line, trimmed.
    let rest = &line[interp_end..];
    let rest_start = rest
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(rest.len());
    let rest = &rest[rest_start..];
    let rest_end = rest
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(0, |p| p + 1);
    let rest = &rest[..rest_end];

    let arg = if rest.is_empty() { None } else { Some(rest) };
    Some((interp, arg))
}

/// Mirror of `ExecveHeader` from `litebox_micro::execve` (central cannot import micro).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ExecveHeaderCentral {
    num_segments: u32,
    _pad0: u32,
    entry_point: u64,
    at_entry: u64,
    brk: u64,
    phdr_addr: u64,
    phnum: u32,
    phent: u32,
    interp_base: u64,
    argc: u32,
    envc: u32,
    argv_offset: u32,
    argv_len: u32,
    envp_offset: u32,
    envp_len: u32,
    syscall_entry_point: u64,
}

/// Mirror of `ExecveSegment` from `litebox_micro::execve`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ExecveSegmentCentral {
    vaddr: u64,
    map_len: u64,
    data_len: u64,
    prot: u32,
    has_trampoline: u32,
    data_offset: u64,
}

/// Which source file a segment's data comes from.
#[derive(Clone, Copy)]
enum FileSource {
    Main,
    Interp,
}

/// Layout of a segment's data in the data region.
struct SegLayout {
    data_offset: usize,
    tramp_desc_len: usize, // 0 if no trampoline, else 8 + trampoline_code_size
}

/// Collected segment info before packing into the data region.
struct SegmentInfo {
    vaddr: u64,
    map_len: u64,
    data_len: u64,
    prot: u32,
    file_data_offset: u64,
    file_data_source: FileSource,
    has_trampoline: bool,
    trampoline_base: usize,
}

/// A `ReadAt` implementation that reads from an in-memory byte slice.
struct MemReader<'a>(&'a [u8]);

impl litebox_common_linux::loader::ReadAt for MemReader<'_> {
    type Error = litebox_common_linux::errno::Errno;

    #[allow(clippy::cast_possible_truncation)]
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), Self::Error> {
        let start = offset as usize;
        let end = start
            .checked_add(buf.len())
            .ok_or(litebox_common_linux::errno::Errno::EINVAL)?;
        if end > self.0.len() {
            return Err(litebox_common_linux::errno::Errno::EIO);
        }
        buf.copy_from_slice(&self.0[start..end]);
        Ok(())
    }

    fn size(&mut self) -> Result<u64, Self::Error> {
        Ok(self.0.len() as u64)
    }
}

/// `ReadAt` for `&MemReader` (the ELF parser takes `&mut F` where `F: ReadAt`).
impl litebox_common_linux::loader::ReadAt for &MemReader<'_> {
    type Error = litebox_common_linux::errno::Errno;

    #[allow(clippy::cast_possible_truncation)]
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), Self::Error> {
        let start = offset as usize;
        let end = start
            .checked_add(buf.len())
            .ok_or(litebox_common_linux::errno::Errno::EINVAL)?;
        if end > self.0.len() {
            return Err(litebox_common_linux::errno::Errno::EIO);
        }
        buf.copy_from_slice(&self.0[start..end]);
        Ok(())
    }

    fn size(&mut self) -> Result<u64, Self::Error> {
        Ok(self.0.len() as u64)
    }
}

// ── Simple mapper for simulating ELF load ───────────────────────────────────

/// A recorded segment from the simple mapper.
struct RecordedSegment {
    address: usize,
    len: usize,
    file_len: usize,
    file_offset: u64,
    prot: litebox_common_linux::loader::Protection,
    is_trampoline: bool,
}

impl RecordedSegment {
    fn prot_flags(&self) -> i32 {
        let mut flags = 0i32;
        if self.prot.read {
            flags |= libc::PROT_READ;
        }
        if self.prot.write {
            flags |= libc::PROT_WRITE;
        }
        if self.prot.execute {
            flags |= libc::PROT_EXEC;
        }
        flags
    }
}

/// A mapper that records segment information without actually mapping memory.
///
/// This is used by central to figure out what segments the ELF loader would
/// create, so we can pack the data into the data region for micro.
struct SimpleMapper {
    segments: Vec<RecordedSegment>,
    base_addr: usize,
    next_addr: usize,
}

impl SimpleMapper {
    fn new() -> Self {
        // Start at a high address that won't conflict.
        // This is for ET_DYN binaries that need a base address.
        Self {
            segments: Vec::new(),
            base_addr: 0,
            next_addr: 0x0040_0000, // 4 MiB — typical PIE base
        }
    }

    /// Create a mapper that starts allocating at `addr`.
    ///
    /// Used for the interpreter so its segments don't overlap the main binary.
    fn new_at(addr: usize) -> Self {
        Self {
            segments: Vec::new(),
            base_addr: 0,
            next_addr: addr,
        }
    }
}

impl litebox_common_linux::loader::MapMemory for SimpleMapper {
    type Error = litebox_common_linux::errno::Errno;

    fn reserve(&mut self, len: usize, align: usize) -> Result<usize, Self::Error> {
        // Align up the next address.
        let aligned = (self.next_addr + align - 1) & !(align - 1);
        self.next_addr = aligned + len;
        self.base_addr = aligned;
        Ok(aligned)
    }

    fn map_file(
        &mut self,
        address: usize,
        len: usize,
        offset: u64,
        prot: &litebox_common_linux::loader::Protection,
    ) -> Result<(), Self::Error> {
        self.segments.push(RecordedSegment {
            address,
            len,
            file_len: len,
            file_offset: offset,
            prot: *prot,
            is_trampoline: false,
        });
        Ok(())
    }

    fn map_zero(
        &mut self,
        address: usize,
        len: usize,
        prot: &litebox_common_linux::loader::Protection,
    ) -> Result<(), Self::Error> {
        self.segments.push(RecordedSegment {
            address,
            len,
            file_len: 0,
            file_offset: 0,
            prot: *prot,
            is_trampoline: false,
        });
        Ok(())
    }

    fn protect(
        &mut self,
        _address: usize,
        _len: usize,
        prot: &litebox_common_linux::loader::Protection,
    ) -> Result<(), Self::Error> {
        // Track protection changes — mark the last segment as trampoline
        // since `load_trampoline` calls `map_file` then `protect`.
        // `protect` is only called from `load_trampoline`, so the last
        // segment recorded by `map_file` is always the trampoline.
        if let Some(last) = self.segments.last_mut() {
            last.prot = *prot;
            last.is_trampoline = true;
        }
        Ok(())
    }
}

/// A no-op memory accessor for the simple mapper.
/// Records BSS (zero-fill) ranges emitted by the ELF loader.
///
/// The loader calls `mem.zero(address, len)` to zero BSS within file-backed
/// pages. We record these so that the packed segment data can have those
/// regions zeroed before sending to micro.
struct SimpleMem {
    /// (address, len) pairs of BSS ranges.
    bss_ranges: Vec<(usize, usize)>,
}

impl SimpleMem {
    fn new() -> Self {
        Self {
            bss_ranges: Vec::new(),
        }
    }
}

impl litebox_common_linux::loader::AccessMemory for SimpleMem {
    fn read(
        &mut self,
        _address: usize,
        buf: &mut [u8],
    ) -> Result<usize, litebox_common_linux::loader::Fault> {
        // Return zeroes — we don't actually read memory.
        buf.fill(0);
        Ok(buf.len())
    }

    fn write(
        &mut self,
        _address: usize,
        _data: &[u8],
    ) -> Result<(), litebox_common_linux::loader::Fault> {
        // No-op — trampoline patching writes the entry point here,
        // but we don't need to record it (micro patches it).
        Ok(())
    }

    fn zero(
        &mut self,
        address: usize,
        len: usize,
    ) -> Result<(), litebox_common_linux::loader::Fault> {
        self.bss_ranges.push((address, len));
        Ok(())
    }
}

// ── Deserialization helpers ─────────────────────────────────────────────────

/// Deserialize the pathname from the serialized execve args.
///
/// Returns `(path_bytes, bytes_consumed)`.
fn deserialize_execve_path(data: &[u8]) -> Option<(&[u8], usize)> {
    if data.len() < 4 {
        return None;
    }
    let path_len = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;
    if 4 + path_len > data.len() {
        return None;
    }
    Some((&data[4..4 + path_len], 4 + path_len))
}

/// Deserialize a string vector (argv or envp) from the serialized execve args.
///
/// Returns `(Vec<byte_slices>, new_position)`.
fn deserialize_string_vector(data: &[u8], mut pos: usize) -> Option<(Vec<&[u8]>, usize)> {
    if pos + 4 > data.len() {
        return None;
    }
    let count = u32::from_le_bytes(data[pos..pos + 4].try_into().ok()?) as usize;
    pos += 4;
    let mut result = Vec::with_capacity(count);
    for _ in 0..count {
        if pos + 4 > data.len() {
            return None;
        }
        let len = u32::from_le_bytes(data[pos..pos + 4].try_into().ok()?) as usize;
        pos += 4;
        if pos + len > data.len() {
            return None;
        }
        result.push(&data[pos..pos + len]);
        pos += len;
    }
    Some((result, pos))
}

/// Read the trampoline header from the end of an ELF file's data.
///
/// Returns `Some((file_offset, trampoline_size))` if valid, `None` otherwise.
#[allow(clippy::cast_possible_truncation)]
fn read_trampoline_header(file_data: &[u8]) -> Option<(u64, usize)> {
    const LITEBOX0_MAGIC: u64 = u64::from_le_bytes(*b"LITEBOX0");
    const HEADER_SIZE: usize = 32;

    if file_data.len() < HEADER_SIZE {
        return None;
    }
    let header_offset = file_data.len() - HEADER_SIZE;
    let magic = u64::from_le_bytes(
        file_data[header_offset..header_offset + 8]
            .try_into()
            .ok()?,
    );
    if magic != LITEBOX0_MAGIC {
        return None;
    }
    let file_offset = u64::from_le_bytes(
        file_data[header_offset + 8..header_offset + 16]
            .try_into()
            .ok()?,
    );
    let tramp_size = u64::from_le_bytes(
        file_data[header_offset + 24..header_offset + 32]
            .try_into()
            .ok()?,
    ) as usize;
    if tramp_size == 0 {
        return None;
    }
    Some((file_offset, tramp_size))
}
