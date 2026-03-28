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

use litebox_ipc::cq::{cq_notify_thread, cq_push};
use litebox_ipc::messages::{
    self, MSG_CHILD_READY, MSG_FORK_RESULT, MSG_LOCAL_RESULT, MSG_THREAD_DEREGISTER,
    MSG_THREAD_REGISTER,
};
use litebox_ipc::ring::{cq_flags, CqEntry, SqEntry, RING_MASK};
use litebox_ipc::sq::{sq_advance_head, sq_head_index, sq_try_consume};
use litebox_ipc::wait::spin_then_wait;
use litebox_shim_linux::ShimFS;

use crate::shmem::SharedRegion;

/// Pending fork that has been prepared but the child hasn't connected yet.
#[allow(dead_code, clippy::struct_field_names)] // child_ prefix is natural here
struct PendingFork<FS: ShimFS> {
    child_region: SharedRegion,
    child_pid: i32,
    child_task: litebox_shim_linux::LinuxShimTask<FS>,
}

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
    /// Pending forks awaiting MSG_CHILD_READY from the child.
    pending_forks: RefCell<Vec<PendingFork<FS>>>,
    /// Next child PID to assign (starts at 2 since the main process is 1).
    next_child_pid: Cell<i32>,
    /// Reference to the shim for creating child tasks.
    shim: Arc<litebox_shim_linux::LinuxShim<FS>>,
    /// Filesystem for creating child tasks.
    fs: Arc<FS>,
}

impl<FS: ShimFS> ProcessServer<FS> {
    /// Create a new `ProcessServer` backed by the given shared memory region.
    #[must_use]
    pub fn new(
        region: SharedRegion,
        task: litebox_shim_linux::LinuxShimTask<FS>,
        shim: Arc<litebox_shim_linux::LinuxShim<FS>>,
        fs: Arc<FS>,
    ) -> Self {
        Self {
            region,
            primary_task: task,
            thread_tasks: RefCell::new(HashMap::new()),
            pending_tasks: RefCell::new(Vec::new()),
            next_thread_slot: Cell::new(1),
            pending_forks: RefCell::new(Vec::new()),
            next_child_pid: Cell::new(2),
            shim,
            fs,
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
    pub fn run(&self) -> anyhow::Result<()> {
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

        // Exit syscalls: dispatch through the shim (to set the exiting flag)
        // AND tell micro to execute locally (to actually terminate the guest).
        #[allow(clippy::cast_possible_truncation)]
        if nr == libc::SYS_exit_group as u32 || nr == libc::SYS_exit as u32 {
            let mut regs = crate::dispatch::sq_entry_to_ptregs(entry);
            cq.result = self.dispatch_to_task(entry.thread_slot, &mut regs);
            cq.flags = cq_flags::EXEC_LOCAL;
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
                        cq.flags = cq_flags::EXEC_LOCAL;
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

        if Self::needs_local_exec(nr) {
            cq.flags = cq_flags::EXEC_LOCAL;
            return cq;
        }

        // TODO: set_initial_brk in PageManager before serving brk() syscalls.
        // Currently, the headless task has brk=0 which will panic on brk().
        // This is OK for nolibc test binaries that don't call brk.
        let mut regs = crate::dispatch::sq_entry_to_ptregs(entry);
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

        // 1. Create new shmem for child.
        let Ok((child_region, child_ring_fd)) = SharedRegion::create_child_ring() else {
            cq.result = -i64::from(libc::ENOMEM);
            return cq;
        };

        // 2. Assign child PID.
        let child_pid = self.next_child_pid.get();
        self.next_child_pid.set(child_pid + 1);

        // 3. Create child task via the shim.
        let params = litebox_common_linux::TaskParams {
            pid: child_pid,
            ppid: 1, // parent is the main process
            uid: 0,
            euid: 0,
            gid: 0,
            egid: 0,
        };
        let child_task = self.shim.create_task(self.fs.clone(), params);

        // 4. Store pending fork (consumed when child server is spawned).
        self.pending_forks.borrow_mut().push(PendingFork {
            child_region,
            child_pid,
            child_task,
        });

        // 5. Return info to micro.
        let central_pid = std::process::id();
        cq.result = i64::from(central_pid);
        cq.flags = cq_flags::EXEC_LOCAL;
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

    /// Returns `true` for syscalls that involve guest memory pointers.
    ///
    /// Central cannot dereference guest pointers (separate address space),
    /// so these must be executed locally by micro-LiteBox.
    fn needs_local_exec(nr: u32) -> bool {
        matches!(
            i64::from(nr),
            libc::SYS_read
                | libc::SYS_write
                | libc::SYS_readv
                | libc::SYS_writev
                | libc::SYS_pread64
                | libc::SYS_pwrite64
                | libc::SYS_preadv
                | libc::SYS_pwritev
                | libc::SYS_preadv2
                | libc::SYS_pwritev2
                | libc::SYS_recvfrom
                | libc::SYS_sendto
                | libc::SYS_recvmsg
                | libc::SYS_sendmsg
        )
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
                // A child process has finished post-fork initialization and is
                // ready to receive syscalls on its new ring.  Spawn a server
                // thread for it.
                self.spawn_child_server();
                0
            }
            // MSG_FORK_RESULT is a no-op acknowledgement.
            MSG_FORK_RESULT => 0,
            _ => -i64::from(libc::ENOSYS),
        };
        cq.result = result;
        cq
    }

    /// Spawn a new server thread for a pending forked child.
    ///
    /// Takes the most recent `PendingFork`, moves it to a new `ProcessServer`,
    /// and spawns a thread to run the child's server loop.
    fn spawn_child_server(&self) {
        let pending = self.pending_forks.borrow_mut().pop();
        if let Some(fork_info) = pending {
            let shim = self.shim.clone();
            let fs = self.fs.clone();

            let child_server =
                ProcessServer::new(fork_info.child_region, fork_info.child_task, shim, fs);
            // Inherit the next_child_pid counter so child-of-child PIDs
            // don't collide.  In a production system this would be a shared
            // atomic, but for now each server keeps its own counter.
            child_server.next_child_pid.set(self.next_child_pid.get());

            std::thread::spawn(move || {
                if let Err(e) = child_server.run() {
                    eprintln!("litebox_central: child server error: {e}");
                }
            });
        }
    }
}
