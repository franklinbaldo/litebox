// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Single-process server loop for central LiteBox.
//!
//! Consumes submission queue entries, dispatches them to either syscall
//! handlers or control message handlers, and writes completion queue results.

use std::ptr::null;
use std::sync::atomic::Ordering::Relaxed;

use litebox::fs::in_mem::FileSystem as InMemFs;
use litebox_ipc::cq::{cq_notify_thread, cq_push};
use litebox_ipc::messages::{
    self, MSG_CHILD_READY, MSG_FORK_RESULT, MSG_LOCAL_RESULT, MSG_THREAD_DEREGISTER,
    MSG_THREAD_REGISTER,
};
use litebox_ipc::ring::{CqEntry, SqEntry, RING_MASK};
use litebox_ipc::sq::{sq_advance_head, sq_head_index, sq_try_consume};
use litebox_ipc::wait::spin_then_wait;
use litebox_platform_multiplex::Platform;

use crate::shmem::SharedRegion;

/// The central server that processes SQ entries and produces CQ completions.
pub struct ProcessServer {
    region: SharedRegion,
    task: litebox_shim_linux::LinuxShimTask<InMemFs<Platform>>,
}

impl ProcessServer {
    /// Create a new `ProcessServer` backed by the given shared memory region.
    #[must_use]
    pub fn new(
        region: SharedRegion,
        task: litebox_shim_linux::LinuxShimTask<InMemFs<Platform>>,
    ) -> Self {
        Self { region, task }
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

            // Entry is ready — extract fields and dispatch.
            let seq = entry.seq;
            let thread_slot = entry.thread_slot;
            let syscall_nr = entry.syscall_nr;

            let result = if messages::is_control_message(syscall_nr) {
                self.handle_control_message(entry)
            } else {
                self.handle_syscall(entry)
            };

            let cq_entry = CqEntry {
                seq,
                result,
                flags: 0,
                thread_slot,
                _pad: [0; 4],
                data_offset: 0,
                data_len: 0,
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
            let notify_slot = cq_notify_thread(header, thread_slot);

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

            // Check if the guest process is exiting.
            if self.task.is_exiting() {
                eprintln!("litebox_central: guest exiting");
                break;
            }
        }

        Ok(())
    }

    /// Dispatch a regular syscall from an SQ entry.
    ///
    /// Builds a synthetic [`PtRegs`](litebox_common_linux::PtRegs) from the
    /// SQ entry's arguments and routes it through the shim's
    /// [`LinuxShimTask::dispatch_syscall`].
    fn handle_syscall(&self, entry: &SqEntry) -> i64 {
        // TODO: set_initial_brk in PageManager before serving brk() syscalls.
        // Currently, the headless task has brk=0 which will panic on brk().
        // This is OK for nolibc test binaries that don't call brk.
        let mut regs = crate::dispatch::sq_entry_to_ptregs(entry);
        self.task.dispatch_syscall(&mut regs)
    }

    /// Dispatch a control message from an SQ entry.
    ///
    /// Handles known `MSG_*` control messages by logging them and returning
    /// success (0). Unknown control messages return `-ENOSYS`.
    #[allow(clippy::unused_self)] // will use self once control messages are fully handled
    fn handle_control_message(&self, entry: &SqEntry) -> i64 {
        match entry.syscall_nr {
            MSG_THREAD_REGISTER => {
                eprintln!("litebox_central: MSG_THREAD_REGISTER (seq={})", entry.seq);
                0
            }
            MSG_THREAD_DEREGISTER => {
                eprintln!("litebox_central: MSG_THREAD_DEREGISTER (seq={})", entry.seq);
                0
            }
            MSG_FORK_RESULT => {
                eprintln!("litebox_central: MSG_FORK_RESULT (seq={})", entry.seq);
                0
            }
            MSG_CHILD_READY => {
                eprintln!("litebox_central: MSG_CHILD_READY (seq={})", entry.seq);
                0
            }
            MSG_LOCAL_RESULT => {
                eprintln!("litebox_central: MSG_LOCAL_RESULT (seq={})", entry.seq);
                0
            }
            _ => {
                eprintln!(
                    "litebox_central: unknown control message 0x{:08x} (seq={})",
                    entry.syscall_nr, entry.seq
                );
                -i64::from(libc::ENOSYS)
            }
        }
    }
}
