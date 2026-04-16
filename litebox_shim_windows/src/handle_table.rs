// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! NT object handle table.
//!
//! Maps Windows HANDLEs (opaque `usize` values) to typed kernel objects.
//! Handles are allocated as small integers starting from 4 (Windows skips 0,
//! and uses multiples of 4 for compatibility with tagged pointers).
//!
//! The handle table is not internally synchronized. The shim wraps it in a
//! `Mutex` for multi-threaded access (Phase 3+).

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

use litebox::fd::RawDescriptorStorage;
use litebox::LiteBox;
use litebox_common_windows::ntstatus::NtStatus;
use litebox_platform_multiplex::Platform;

/// The fd-subsystem type for NT kernel objects.
///
/// All NT handles (events, mutants, stubs, sections, processes, etc.) that are
/// not backed by a dedicated litebox core subsystem (like NtFS for files or
/// Network for sockets) are stored as entries of this subsystem in the shared
/// [`litebox::fd::Descriptors`] table.
pub struct NtObjectSubsystem<FS: crate::NtShimFS>(core::marker::PhantomData<FS>);

impl<FS: crate::NtShimFS> litebox::fd::FdEnabledSubsystem for NtObjectSubsystem<FS> {
    type Entry = NtObjectEntry<FS>;
}

/// A descriptor-table entry wrapping an [`NtObject`].
///
/// Implements [`FdEnabledSubsystemEntry`] with custom `on_dup`/`on_close`
/// hooks for reference-counted objects (pipes, etc.).
pub struct NtObjectEntry<FS: crate::NtShimFS> {
    pub object: NtObject<FS>,
}

impl<FS: crate::NtShimFS> litebox::fd::FdEnabledSubsystemEntry for NtObjectEntry<FS> {
    fn on_dup(&self) {
        // Not used — HandleTable::duplicate() uses clone_nt_object() + insert()
        // instead of Descriptors::duplicate(), so this hook is never called.
        // Pipe refcount increment is handled in clone_nt_object().
    }

    fn on_close(&self) {
        // Only lock-free operations here — this fires INSIDE the Descriptors
        // write lock. Anything that re-acquires the lock (fs.close, net.close)
        // goes in cleanup_after_close() instead.
        match &self.object {
            NtObject::Pipe {
                buffer, is_server, ..
            } => {
                let was_last = buffer.decrement(*is_server);
                if was_last {
                    buffer.wake_readers();
                    buffer.wake_writers();
                    if !*is_server {
                        buffer
                            .writer_gone
                            .store(true, core::sync::atomic::Ordering::Release);
                        buffer.break_pending_reads();
                    }
                }
            }
            _ => {}
        }
    }
}

impl<FS: crate::NtShimFS> From<NtObject<FS>> for NtObjectEntry<FS> {
    fn from(object: NtObject<FS>) -> Self {
        Self { object }
    }
}

impl<FS: crate::NtShimFS> NtObjectEntry<FS> {
    /// Post-close cleanup that runs AFTER the `Descriptors` write lock is
    /// released (i.e., after `Descriptors::remove()` returns).
    ///
    /// This is where cleanup operations that would re-acquire the Descriptors
    /// lock live — `fs.close()`, `fs.unlink()`, `net.close()` — which cannot
    /// run inside `on_close()` because that fires while the write lock is held
    /// and re-acquiring it would deadlock.
    ///
    /// `on_close()` remains for lock-free operations (pipe refcount atomics,
    /// wake signals).
    pub fn cleanup_after_close(self) {
        match self.object {
            NtObject::File {
                vfs_fd,
                vfs_path,
                delete_on_close,
                fs,
                ..
            } => {
                // Try to unwrap the Arc — succeeds only if this was the last
                // handle sharing this VFS fd.
                match alloc::sync::Arc::try_unwrap(vfs_fd) {
                    Ok(typed_fd) => {
                        // Last reference — close the fd on the filesystem.
                        use litebox::fs::FileSystem as _;
                        let _ = fs.close(&typed_fd);
                        // If marked for deletion, unlink the file from VFS now.
                        let should_delete =
                            delete_on_close.load(core::sync::atomic::Ordering::Acquire);
                        #[cfg(any(debug_assertions, feature = "trace_debug"))]
                        {
                            use litebox::platform::DebugLogProvider as _;
                            litebox_platform_multiplex::platform().debug_log_print(
                                &alloc::format!(
                                    "NT shim: cleanup_after_close last-close delete_on_close={should_delete} vfs_path={vfs_path:?}\n",
                                ),
                            );
                        }
                        if should_delete {
                            if let Some(ref vfs_p) = vfs_path {
                                let result = fs.unlink(vfs_p.as_str());
                                #[cfg(any(debug_assertions, feature = "trace_debug"))]
                                {
                                    use litebox::platform::DebugLogProvider as _;
                                    litebox_platform_multiplex::platform().debug_log_print(
                                        &alloc::format!(
                                            "NT shim: cleanup_after_close unlink({vfs_p:?}) result={result:?}\n",
                                        ),
                                    );
                                }
                            }
                        }
                    }
                    Err(_arc) => {
                        // Other handles still share this VFS fd. The Arc is
                        // dropped here, decrementing the refcount by one.
                    }
                }
            }
            NtObject::Socket { socket_fd, net, .. } => {
                // Close the socket in the core network stack, releasing the
                // smoltcp socket slot and associated ring buffers.
                let _ = net
                    .lock()
                    .close(&socket_fd, litebox::net::CloseBehavior::Immediate);
            }
            // Pipe cleanup is handled entirely by on_close() (atomic refcount
            // decrement + wake signals), which is safe inside the lock.
            // Registry, console, directory, etc. need no cleanup.
            _ => {}
        }
    }
}

/// Type alias for the typed fd handle to an NT object in the descriptor table.
pub type NtObjectFd<FS: crate::NtShimFS> = litebox::fd::TypedFd<NtObjectSubsystem<FS>>;

/// Type alias for thread wakers used by sync object waiters.
type SyncWaker = litebox::event::wait::Waker<Platform>;

/// The first allocatable handle value. Windows handles start at 4.
const FIRST_HANDLE: u32 = 4;
/// Handle increment (Windows allocates handles in steps of 4).
const HANDLE_STEP: u32 = 4;

/// Shared file position. Duplicated handles share the same host file object
/// and therefore the same file pointer; this `Arc<AtomicU64>` ensures both
/// handles see the same cached position (thread-safe for Phase 3+).
pub type SharedFilePosition = Arc<core::sync::atomic::AtomicU64>;

/// An NT kernel object.
pub enum NtObject<FS: crate::NtShimFS> {
    /// Console input stream (stdin).
    ConsoleInput,
    /// Console output stream (stdout or stderr).
    ConsoleOutput {
        /// True for stderr, false for stdout.
        is_stderr: bool,
    },
    /// A file opened via NtCreateFile.
    File {
        /// Guest-visible NT path.
        path: String,
        /// VFS path (e.g. `/c/test.txt`) for unlink on delete-on-close.
        /// `None` for files not backed by VFS.
        vfs_path: Option<String>,
        /// Shared file position (byte offset). Cloned on DuplicateHandle so
        /// both handles track the same underlying file pointer.
        position: SharedFilePosition,
        /// VFS file descriptor from the litebox core's Descriptors table.
        /// Shared via `Arc` across duplicated handles — only the last close
        /// actually calls `fs.close()` (detected via `Arc::try_unwrap()`).
        vfs_fd: alloc::sync::Arc<litebox::fd::TypedFd<FS>>,
        /// When true, the file is deleted from the VFS when the last handle
        /// is closed (Windows `FILE_DELETE_ON_CLOSE` / `FileDispositionInformation`).
        delete_on_close: Arc<core::sync::atomic::AtomicBool>,
        /// Reference to the filesystem for close/unlink in `cleanup_after_close()`.
        fs: alloc::sync::Arc<FS>,
    },
    /// A directory opened via NtCreateFile.
    Directory {
        /// Guest-visible NT path.
        path: String,
        /// Cached directory entries for NtQueryDirectoryFile enumeration.
        /// Populated lazily on the first query. Subsequent calls advance
        /// `enum_index` to provide forward progress.
        enum_entries: Vec<DirEnumEntry>,
        /// Current enumeration index into `enum_entries`.
        enum_index: usize,
    },
    /// A Win32 file search handle (FindFirstFileExW / FindNextFileW).
    FindSearch {
        /// All matching entries from the host search.
        entries: Vec<DirEnumEntry>,
        /// Index of the next entry to return from FindNextFileW.
        next_index: usize,
    },
    /// A placeholder for objects we don't fully implement yet.
    Stub {
        /// Description for debugging.
        kind: String,
        /// Optional I/O completion port binding (set by NtSetInformationFile FileCompletionInformation).
        io_completion: Option<(Arc<IoCompletionObject>, usize)>,
    },
    /// An NT event object (NtCreateEvent).
    Event(Arc<EventObject>),
    /// An NT semaphore object (NtCreateSemaphore).
    Semaphore(Arc<SemaphoreObject>),
    /// An NT mutant object (NtCreateMutant).
    Mutant(Arc<MutantObject>),
    /// An NT keyed event object (NtCreateKeyedEvent).
    KeyedEvent(Arc<KeyedEventObject>),
    /// An NT thread object (NtCreateThreadEx).
    Thread(Arc<ThreadObject>),
    /// An NT I/O completion port object.
    IoCompletion(Arc<IoCompletionObject>),
    /// A WinSock socket backed by the litebox core network stack.
    ///
    /// The `SocketFd` is the core's typed handle for this socket.
    /// The `NetworkProxy` provides lock-free access to the TX/RX ring buffers
    /// and IO event polling, without holding the `Network` lock.
    Socket {
        /// Core socket handle for bind/connect/close operations.
        socket_fd: litebox::net::SocketFd<Platform>,
        /// Lock-free proxy for send/recv/poll operations.
        proxy: alloc::sync::Arc<litebox::net::socket_channel::NetworkProxy<Platform>>,
        /// Reference to the network stack for close in `cleanup_after_close()`.
        net: alloc::sync::Arc<spin::Mutex<litebox::net::Network<Platform>>>,
        /// I/O completion port association (set via
        /// `NtSetInformationFile(FileCompletionInformation)`).
        /// Tuple of (port, completion_key).
        io_completion: Option<(Arc<IoCompletionObject>, usize)>,
        /// Pending async observers registered on the socket's pollee.
        ///
        /// These keep the `Arc<SocketIocpObserver>` alive so the `Weak`
        /// reference in the pollee doesn't expire prematurely. Observers
        /// are auto-pruned once they fire (the `Weak` upgrades fail after
        /// the socket is closed and these Arcs are dropped).
        pending_observers: Vec<Arc<SocketIocpObserver>>,
        /// Pending async RECV observers (non-zero-byte) registered on the
        /// socket's pollee.  Same lifetime semantics as `pending_observers`.
        pending_recv_observers: Vec<Arc<SocketRecvIocpObserver>>,
        /// Pending async datagram RECV observers (event-based, no IOCP).
        /// Same lifetime semantics as `pending_observers`.
        pending_dgram_event_observers: Vec<Arc<SocketRecvDatagramEventObserver>>,
        /// Pending async AFD_SELECT observers.
        /// Same lifetime semantics as `pending_observers`.
        pending_select_observers: Vec<Arc<SocketSelectIocpObserver>>,
        /// When `true`, synchronous I/O completions (status != STATUS_PENDING)
        /// do NOT post an IOCP completion entry.  Set by
        /// `NtSetInformationFile(FileIoCompletionNotificationInformation)`
        /// with `FILE_SKIP_COMPLETION_PORT_ON_SUCCESS (0x1)`.
        skip_completion_on_success: bool,
    },
    /// An NT section object (NtCreateSection).
    Section {
        /// The raw PE data (for SEC_IMAGE sections).
        pe_data: Arc<Vec<u8>>,
        /// Best-effort Win32-style module path for module lookup APIs.
        module_path: Option<String>,
        /// Best-effort module basename (for example, `kernel32.dll`).
        module_name: Option<String>,
        /// Parsed PE metadata.
        image_size: u32,
        image_base: u64,
        entry_point: u32,
        section_alignment: u32,
        is_dll: bool,
    },
    /// An anonymous data section (NtCreateSection without SEC_IMAGE).
    DataSection {
        /// Maximum size of the section (in bytes).
        max_size: u64,
    },
    /// Current process handle (from duplicating pseudo-handle -1).
    CurrentProcess,
    /// Current thread handle (from duplicating pseudo-handle -2).
    CurrentThread,
    /// A registry key handle.
    RegistryKey {
        /// Canonical NT path for this key, used to resolve RootDirectory-relative opens.
        path: String,
    },
    /// A named pipe endpoint.
    Pipe {
        /// Shared pipe buffer connecting the two endpoints.
        buffer: Arc<PipeBuffer>,
        /// True for the server (read) end, false for the client (write) end.
        is_server: bool,
        /// I/O completion port association (set via
        /// `NtSetInformationFile(FileCompletionInformation)`).
        /// Tuple of (port, completion_key).
        io_completion: Option<(Arc<IoCompletionObject>, usize)>,
    },
    /// A virtual process handle (for subprocess emulation).
    Process {
        /// Shared process state.
        state: Arc<ProcessObject>,
    },
    /// The NamedPipe root device handle (`\Device\NamedPipe\`).
    ///
    /// Returned when a caller opens the root pipe directory. This handle is
    /// used as `RootDirectory` in subsequent `NtCreateNamedPipeFile` or
    /// `NtOpenFile` calls so relative pipe names can be resolved.
    PipeRootDevice,
    /// A virtual thread handle for subprocess emulation.
    ///
    /// Returned by `NtCreateUserProcess` as the child's initial thread handle.
    /// The "thread" has already finished by the time the syscall returns (since
    /// subprocess commands are executed inline). `NtResumeThread` on this handle
    /// returns SUCCESS with previous suspend count = 1 (simulating a suspended
    /// thread that becomes resumed). `NtWaitForSingleObject` returns immediately
    /// because the process is already exited.
    VirtualThread {
        /// Shared process state (same as the `Process` variant's state).
        process: Arc<ProcessObject>,
    },
    /// A phantom executable file handle.
    ///
    /// Returned when `NtCreateFile`/`NtOpenFile` opens an `.exe` (or similar)
    /// that doesn't exist in the VFS. `CreateProcessW` pre-flight opens the
    /// target executable before calling `NtCreateUserProcess`; this phantom
    /// handle satisfies those checks and allows `NtCreateSection(SEC_IMAGE)`
    /// to succeed with a minimal stub section.
    PhantomExe {
        /// The NT path that was opened (e.g. `\??\C:\Windows\System32\cmd.exe`).
        path: String,
    },
    /// An NT job object (NtCreateJobObject).
    ///
    /// Job objects group processes for resource management and lifecycle control.
    /// In the sandbox we track the object for handle validity but do not enforce
    /// any job limits — all `NtSetInformationJobObject` and
    /// `NtAssignProcessToJobObject` calls succeed as no-ops.
    JobObject,
    /// An NT Timer2 object (NtCreateTimer2).
    ///
    /// Timer2 objects are the kernel timers used by the Windows thread pool for
    /// delayed work items.  Armed via `NtSetTimer2`, cancelled via
    /// `NtCancelTimer2`.  When the due time expires, the timer fires by posting
    /// a completion entry to its associated IOCP.
    Timer2(Arc<Timer2Object>),
    /// An NT worker factory object (NtCreateWorkerFactory).
    ///
    /// Worker factories are the kernel-side backing for the Windows thread pool.
    /// Each factory is associated with an I/O completion port; worker threads
    /// call `NtReleaseWorkerFactoryWorker` to block on the IOCP, and the kernel
    /// spawns new threads (via `StartRoutine`) when minimum thread counts are
    /// configured via `NtSetInformationWorkerFactory`.
    WorkerFactory(Arc<WorkerFactoryObject>),
}

/// Internal state for an NT event object.
///
/// Events have two modes:
/// - **Manual-reset**: stays signaled until explicitly reset. NtSetEvent wakes
///   all waiters.
/// - **Auto-reset**: automatically resets after waking one waiter.
pub struct EventObject {
    /// Mutex-protected signaled state.
    pub state: Mutex<bool>,
    /// True = manual-reset, false = auto-reset.
    pub manual_reset: bool,
    /// Wakers for threads blocked in wait_event. Signaling paths wake
    /// all registered wakers so that `wait_until` re-evaluates.
    pub waiters: Mutex<Vec<SyncWaker>>,
}

/// A pending asynchronous read on a pipe, waiting for data to arrive.
///
/// When `NtReadFile` is called on a pipe handle that has been associated with
/// an I/O completion port (via `NtSetInformationFile(FileCompletionInformation)`),
/// the read returns `STATUS_PENDING` immediately and a `PendingPipeRead` is
/// queued.  When data arrives (via `NtWriteFile`) or the pipe breaks, the
/// pending read is fulfilled and an IOCP completion packet is posted.
pub struct PendingPipeRead {
    /// Guest memory address where read data should be written.
    pub buffer_ptr: usize,
    /// Maximum number of bytes to read.
    pub buffer_len: usize,
    /// Guest address of the `IO_STATUS_BLOCK` to write completion status into.
    pub iosb_ptr: usize,
    /// APC context value (from `NtReadFile` arg3).  Passed through to the IOCP
    /// completion packet so the caller can correlate completions with requests.
    pub apc_context: usize,
    /// The I/O completion port to post the result to.
    pub port: Arc<IoCompletionObject>,
    /// The completion key associated with this file handle's IOCP binding.
    pub key: usize,
    /// Optional event object to signal when the read completes (from
    /// `NtReadFile`'s Event parameter, arg1/rdx).
    pub event: Option<Arc<EventObject>>,
}

/// Shared buffer for a named pipe.  Both endpoints (server/client) hold
/// `Arc<PipeBuffer>` so reads and writes go through the same backing store.
pub struct PipeBuffer {
    /// Pipe data ring. Writers append, readers consume from the front.
    pub data: Mutex<VecDeque<u8>>,
    /// Maximum buffer capacity (from InboundQuota / OutboundQuota).
    pub capacity: usize,
    /// Number of open server (read) endpoint handles.  The server side is
    /// considered closed when this reaches 0 after having been > 0.
    pub server_count: core::sync::atomic::AtomicU32,
    /// Number of open client (write) endpoint handles.  The client side is
    /// considered closed when this reaches 0 after having been > 0.
    pub client_count: core::sync::atomic::AtomicU32,
    /// The NT-style pipe name (e.g. `\Device\NamedPipe\Win32.Pipes.123.1`).
    pub name: Mutex<String>,
    /// Wakers for threads blocked on pipe read (waiting for data).
    pub read_waiters: Mutex<Vec<SyncWaker>>,
    /// Wakers for threads blocked on pipe write (waiting for space).
    pub write_waiters: Mutex<Vec<SyncWaker>>,
    /// Queue of pending asynchronous reads (IOCP-associated pipe handles).
    pub pending_reads: Mutex<Vec<PendingPipeRead>>,
    /// IOCP binding for the server (reader) side of the pipe.
    ///
    /// Set when `NtSetInformationFile(FileCompletionInformation)` is called on a
    /// server-side pipe handle.  Stored here (on the shared buffer) so that
    /// `break_pending_reads()` can post a `STATUS_PIPE_BROKEN` completion even
    /// when there are zero pending reads queued — the parent's event loop needs
    /// the notification to unblock.
    pub server_iocp: Mutex<Option<(Arc<IoCompletionObject>, usize)>>,
    /// True once the last client (writer) handle has been closed.
    ///
    /// Checked by `nt_read_file_pipe_async` so it can immediately complete new
    /// reads with `STATUS_PIPE_BROKEN` rather than queuing them as pending
    /// (the pipe will never receive more data).
    pub writer_gone: core::sync::atomic::AtomicBool,
}

impl PipeBuffer {
    /// Create a new pipe buffer with the given capacity and name.
    pub fn new(capacity: usize, name: String) -> Self {
        Self {
            data: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
            server_count: core::sync::atomic::AtomicU32::new(0),
            client_count: core::sync::atomic::AtomicU32::new(0),
            name: Mutex::new(name),
            read_waiters: Mutex::new(Vec::new()),
            write_waiters: Mutex::new(Vec::new()),
            pending_reads: Mutex::new(Vec::new()),
            server_iocp: Mutex::new(None),
            writer_gone: core::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Increment the handle count for a server (read) or client (write) endpoint.
    pub fn increment(&self, is_server: bool) {
        if is_server {
            self.server_count
                .fetch_add(1, core::sync::atomic::Ordering::Release);
        } else {
            self.client_count
                .fetch_add(1, core::sync::atomic::Ordering::Release);
        }
    }

    /// Decrement the handle count for a server (read) or client (write) endpoint.
    /// Returns true if this was the last handle of that type (count reached 0).
    pub fn decrement(&self, is_server: bool) -> bool {
        if is_server {
            self.server_count
                .fetch_sub(1, core::sync::atomic::Ordering::Release)
                == 1
        } else {
            self.client_count
                .fetch_sub(1, core::sync::atomic::Ordering::Release)
                == 1
        }
    }

    /// Check if all server (read) handles have been closed.
    pub fn server_closed(&self) -> bool {
        // A server_count of 0 with no handles ever opened should NOT be treated
        // as "closed" — but in practice, the server is always created first
        // with count >= 1, so 0 means all are closed.
        self.server_count
            .load(core::sync::atomic::Ordering::Acquire)
            == 0
    }

    /// Check if all client (write) handles have been closed.
    pub fn client_closed(&self) -> bool {
        self.client_count
            .load(core::sync::atomic::Ordering::Acquire)
            == 0
    }

    /// Wake all threads waiting to read from this pipe.
    pub fn wake_readers(&self) {
        for w in self.read_waiters.lock().iter() {
            w.wake();
        }
    }

    /// Wake all threads waiting to write to this pipe.
    pub fn wake_writers(&self) {
        for w in self.write_waiters.lock().iter() {
            w.wake();
        }
    }

    /// Drain any pending asynchronous reads that can be fulfilled.
    ///
    /// Called after new data has been written to the pipe (or after the writer
    /// has closed).  For each pending read, copies available data into the
    /// caller's guest buffer and posts an IOCP completion packet.
    ///
    /// Returns the number of pending reads that were fulfilled.
    pub fn drain_pending_reads(&self) -> usize {
        let mut pending = self.pending_reads.lock();
        let mut data = self.data.lock();
        let writer_gone = self.client_closed();

        #[cfg(feature = "trace_debug")]
        {
            use litebox::platform::DebugLogProvider as _;
            let self_ptr = self as *const Self as usize;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: drain_pending_reads PipeBuffer={self_ptr:#X} pending={} data_len={} writer_gone={writer_gone}\n",
                pending.len(), data.len(),
            ));
        }

        let mut fulfilled = 0usize;
        let mut remaining = Vec::new();

        for pr in pending.drain(..) {
            if !data.is_empty() {
                // Fulfill this read with available data.
                let to_copy = core::cmp::min(pr.buffer_len, data.len());
                let dst = pr.buffer_ptr as *mut u8;
                // Copy data from the ring buffer to the guest buffer.
                let (front, back) = data.as_slices();
                if to_copy <= front.len() {
                    unsafe {
                        core::ptr::copy_nonoverlapping(front.as_ptr(), dst, to_copy);
                    }
                } else {
                    let front_bytes = front.len();
                    unsafe {
                        core::ptr::copy_nonoverlapping(front.as_ptr(), dst, front_bytes);
                        core::ptr::copy_nonoverlapping(
                            back.as_ptr(),
                            dst.add(front_bytes),
                            to_copy - front_bytes,
                        );
                    }
                }
                // Consume the bytes from the ring buffer.
                data.drain(..to_copy);

                // Write IoStatusBlock: success + bytes transferred.
                if pr.iosb_ptr != 0 {
                    crate::try_write_guest_value_unaligned(pr.iosb_ptr, 0i32); // STATUS_SUCCESS
                    crate::try_write_guest_value_unaligned(pr.iosb_ptr + 8, to_copy);
                }

                // Post IOCP completion.
                pr.port.push(IoCompletionEntry {
                    key_context: pr.key,
                    apc_context: pr.apc_context,
                    status: NtStatus::STATUS_SUCCESS,
                    information: to_copy,
                });

                // Signal the Event handle if one was provided.
                if let Some(ref ev) = pr.event {
                    *ev.state.lock() = true;
                    ev.wake_waiters();
                }

                fulfilled += 1;
            } else if writer_gone {
                // No data and writer is gone — pipe broken.
                if pr.iosb_ptr != 0 {
                    crate::try_write_guest_value_unaligned(
                        pr.iosb_ptr,
                        NtStatus::STATUS_PIPE_BROKEN.raw() as i32,
                    );
                    crate::try_write_guest_value_unaligned(pr.iosb_ptr + 8, 0usize);
                }
                pr.port.push(IoCompletionEntry {
                    key_context: pr.key,
                    apc_context: pr.apc_context,
                    status: NtStatus::STATUS_PIPE_BROKEN,
                    information: 0,
                });

                // Signal the Event handle if one was provided.
                if let Some(ref ev) = pr.event {
                    *ev.state.lock() = true;
                    ev.wake_waiters();
                }

                fulfilled += 1;
            } else {
                // No data yet and writer still alive — keep pending.
                remaining.push(pr);
            }
        }

        *pending = remaining;
        fulfilled
    }

    /// Complete all pending reads with `STATUS_PIPE_BROKEN`.
    ///
    /// Called when the last writer (client) handle is closed, signaling EOF
    /// to any outstanding asynchronous reads.  Each pending read gets its
    /// IOCP completion posted and its Event signaled so the caller can
    /// synchronize on either mechanism.
    ///
    /// If there are **zero** pending reads but the server side of the pipe
    /// was associated with an IOCP (via `FileCompletionInformation`), a
    /// synthetic `STATUS_PIPE_BROKEN` completion is posted.  This matches
    /// real Windows kernel behavior: when a pipe breaks, the kernel posts a
    /// notification to the IOCP even if no I/O was outstanding.  Without
    /// this, event loops (e.g. libuv's `spawnSync`) that wait for pipe-
    /// broken notifications on *all* associated pipes (stdin, stdout,
    /// stderr) will hang indefinitely on pipes where no reads were ever
    /// issued (typically stdin, which the parent writes to but never reads).
    pub fn break_pending_reads(&self) {
        let mut pending = self.pending_reads.lock();
        let had_pending = !pending.is_empty();
        for pr in pending.drain(..) {
            if pr.iosb_ptr != 0 {
                crate::try_write_guest_value_unaligned(
                    pr.iosb_ptr,
                    NtStatus::STATUS_PIPE_BROKEN.raw() as i32,
                );
                crate::try_write_guest_value_unaligned(pr.iosb_ptr + 8, 0usize);
            }
            pr.port.push(IoCompletionEntry {
                key_context: pr.key,
                apc_context: pr.apc_context,
                status: NtStatus::STATUS_PIPE_BROKEN,
                information: 0,
            });

            // Signal the Event handle if one was provided.
            if let Some(ref ev) = pr.event {
                *ev.state.lock() = true;
                ev.wake_waiters();
            }
        }
        drop(pending);

        // If there were no pending reads but the server side is IOCP-bound,
        // post a synthetic PIPE_BROKEN completion so the event loop unblocks.
        if !had_pending {
            let server_iocp = self.server_iocp.lock();
            if let Some((ref port, key)) = *server_iocp {
                port.push(IoCompletionEntry {
                    key_context: key,
                    apc_context: 0,
                    status: NtStatus::STATUS_PIPE_BROKEN,
                    information: 0,
                });
            }
        }
    }
}

/// Virtual process state for subprocess emulation.
pub struct ProcessObject {
    /// Exit code set when the process finishes.
    pub exit_code: core::sync::atomic::AtomicI32,
    /// True when the process has exited.
    pub exited: core::sync::atomic::AtomicBool,
    /// Wakers for threads blocked in NtWaitForSingleObject on this process.
    pub waiters: Mutex<Vec<SyncWaker>>,
    /// IOCP waiters registered via `NtAssociateWaitCompletionPacket`.
    ///
    /// When the process exits (becomes signaled), each entry is posted to
    /// the corresponding I/O completion port. This enables libuv's
    /// `uv_process_close` flow which uses `NtAssociateWaitCompletionPacket`
    /// to receive process-exit notifications through an IOCP.
    pub iocp_waiters: Mutex<Vec<(Arc<IoCompletionObject>, IoCompletionEntry)>>,
    /// Stdout pipe buffer (if any) — the parent reads from this.
    pub stdout_pipe: Option<Arc<PipeBuffer>>,
    /// Stderr pipe buffer (if any) — the parent reads from this.
    pub stderr_pipe: Option<Arc<PipeBuffer>>,
    /// Guest-visible process ID (for real child processes).
    pub pid: u32,
    /// Shared exit code with the child process's shim (for real child processes).
    pub exit_code_shared: Option<Arc<core::sync::atomic::AtomicI32>>,
    /// Shared exit-requested flag with the child process (for real child processes).
    pub exit_requested_shared: Option<Arc<core::sync::atomic::AtomicBool>>,
    /// Address space ID for the child process (for real child processes).
    pub address_space_id: u32,
}

impl ProcessObject {
    /// Create a new process object for inline (virtual) subprocess emulation (not yet exited).
    pub fn new(stdout_pipe: Option<Arc<PipeBuffer>>, stderr_pipe: Option<Arc<PipeBuffer>>) -> Self {
        Self {
            exit_code: core::sync::atomic::AtomicI32::new(0),
            exited: core::sync::atomic::AtomicBool::new(false),
            waiters: Mutex::new(Vec::new()),
            iocp_waiters: Mutex::new(Vec::new()),
            stdout_pipe,
            stderr_pipe,
            pid: 0,
            exit_code_shared: None,
            exit_requested_shared: None,
            address_space_id: 0,
        }
    }

    /// Create a new process object for a real child process with its own address space.
    pub fn new_real(
        pid: u32,
        exit_code_shared: Arc<core::sync::atomic::AtomicI32>,
        exit_requested_shared: Arc<core::sync::atomic::AtomicBool>,
        address_space_id: u32,
    ) -> Self {
        Self {
            exit_code: core::sync::atomic::AtomicI32::new(259), // STILL_ACTIVE
            exited: core::sync::atomic::AtomicBool::new(false),
            waiters: Mutex::new(Vec::new()),
            iocp_waiters: Mutex::new(Vec::new()),
            stdout_pipe: None,
            stderr_pipe: None,
            pid,
            exit_code_shared: Some(exit_code_shared),
            exit_requested_shared: Some(exit_requested_shared),
            address_space_id,
        }
    }

    /// Set the exit code without marking the process as exited.
    ///
    /// Used by the child-process runner thread to store the exit code;
    /// the parent can later observe it via `NtQueryInformationProcess`.
    pub fn set_exit_code(&self, code: i32) {
        self.exit_code
            .store(code, core::sync::atomic::Ordering::Release);
        // Also propagate to the shared exit code if present.
        if let Some(ref shared) = self.exit_code_shared {
            shared.store(code, core::sync::atomic::Ordering::Release);
        }
        // Mark as exited and wake waiters.
        self.exited
            .store(true, core::sync::atomic::Ordering::Release);
        for w in self.waiters.lock().iter() {
            w.wake();
        }
        // Post IOCP completions registered via NtAssociateWaitCompletionPacket.
        self.fire_iocp_waiters();
    }

    /// Mark process as exited and wake all waiters.
    pub fn set_exited(&self, code: i32) {
        self.exit_code
            .store(code, core::sync::atomic::Ordering::Release);
        self.exited
            .store(true, core::sync::atomic::Ordering::Release);
        for w in self.waiters.lock().iter() {
            w.wake();
        }
        // Post IOCP completions registered via NtAssociateWaitCompletionPacket.
        self.fire_iocp_waiters();
    }

    /// Drain all registered IOCP wait completion packets and post them.
    ///
    /// Called when the process becomes signaled (exits). Each registered
    /// `(IoCompletionObject, IoCompletionEntry)` pair is consumed and the
    /// entry is pushed to the corresponding IOCP, waking any threads
    /// blocked in `NtRemoveIoCompletionEx`.
    fn fire_iocp_waiters(&self) {
        let waiters: Vec<_> = {
            let mut guard = self.iocp_waiters.lock();
            guard.drain(..).collect()
        };
        #[cfg(feature = "trace_debug")]
        if !waiters.is_empty() {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: ProcessObject::fire_iocp_waiters() posting {} IOCP completions\n",
                waiters.len(),
            ));
        }
        for (port, entry) in waiters {
            port.push(entry);
        }
    }
}

impl EventObject {
    /// Create a new event.
    pub fn new(manual_reset: bool, initial_state: bool) -> Self {
        Self {
            state: Mutex::new(initial_state),
            manual_reset,
            waiters: Mutex::new(Vec::new()),
        }
    }

    /// Wake all threads waiting on this event.
    pub fn wake_waiters(&self) {
        for w in self.waiters.lock().iter() {
            w.wake();
        }
    }
}

/// Internal state for a condition variable.
pub struct ConditionVariableObject {
    /// Wake state and waiter accounting.
    pub state: Mutex<ConditionVariableState>,
    /// Wakers for threads blocked on the condition variable.
    pub waiters: Mutex<Vec<SyncWaker>>,
}

/// Mutable state protected by a condition variable's mutex.
pub struct ConditionVariableState {
    pub waiter_count: u32,
    pub next_wait_ticket: u64,
    pub pending_single_wakes: u32,
    pub broadcast_generation: u64,
    pub wait_queue: VecDeque<u64>,
}

impl ConditionVariableObject {
    /// Create a new condition variable with no waiters or pending wakes.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(ConditionVariableState {
                waiter_count: 0,
                next_wait_ticket: 0,
                pending_single_wakes: 0,
                broadcast_generation: 0,
                wait_queue: VecDeque::new(),
            }),
            waiters: Mutex::new(Vec::new()),
        }
    }

    /// Wake blocked waiters so they can re-check the condition state.
    pub fn wake_waiters(&self) {
        for w in self.waiters.lock().iter() {
            w.wake();
        }
    }
}

/// Internal state for a slim reader/writer lock.
pub struct SrwLockObject {
    /// Exclusive owner and shared-reader count.
    pub state: Mutex<SrwLockState>,
    /// Wakers for threads blocked acquiring the lock.
    pub waiters: Mutex<Vec<SyncWaker>>,
}

/// Mutable state protected by an SRW lock object's mutex.
pub struct SrwLockState {
    pub exclusive_owner: Option<u32>,
    pub shared_count: u32,
}

impl SrwLockObject {
    /// Create a new unlocked SRW lock object.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(SrwLockState {
                exclusive_owner: None,
                shared_count: 0,
            }),
            waiters: Mutex::new(Vec::new()),
        }
    }

    /// Wake all blocked acquirers so they can re-evaluate the lock state.
    pub fn wake_waiters(&self) {
        for w in self.waiters.lock().iter() {
            w.wake();
        }
    }
}

/// A queued user-mode APC awaiting delivery on the target thread.
///
/// Queued via `NtQueueApcThread` / `NtQueueApcThreadEx`.  Delivered when
/// the target thread enters an alertable wait or calls `NtTestAlert`.
#[derive(Clone, Copy, Debug)]
pub struct PendingUserApc {
    /// Guest VA of the APC routine (`PKNORMAL_ROUTINE`).
    pub routine: usize,
    /// `NormalContext` argument passed to the routine.
    pub context: usize,
    /// `SystemArgument1` argument passed to the routine.
    pub system_arg1: usize,
    /// `SystemArgument2` argument passed to the routine.
    pub system_arg2: usize,
}

/// Internal state for an NT thread object.
///
/// Tracks thread exit status. Waiters block via WaitContext and are woken
/// when the thread exits.
pub struct ThreadObject {
    /// Thread exit code, set when the thread terminates.
    /// None = still running, Some(code) = exited.
    pub exit_status: Mutex<Option<i32>>,
    /// Guest-visible thread ID (TEB.ClientId.UniqueThread / GetCurrentThreadId).
    pub thread_id: u32,
    /// Guest VA of this thread's TEB.
    pub teb_va: Mutex<usize>,
    /// Wakers for threads blocked in wait_thread.
    pub waiters: Mutex<Vec<SyncWaker>>,
    /// Current suspend count. New threads created with CREATE_SUSPENDED start at 1.
    pub suspend_count: Mutex<u32>,
    /// Wakers for child threads blocked waiting to be resumed.
    pub resume_waiters: Mutex<Vec<SyncWaker>>,
    /// Pending thread-alert state.
    pub alert_by_id_pending: Mutex<AlertByIdState>,
    /// Wakers for generic alertable waits.
    pub alert_waiters: Mutex<Vec<SyncWaker>>,
    /// Pending user-mode APCs queued via `NtQueueApcThread`.
    pub pending_user_apcs: Mutex<alloc::vec::Vec<PendingUserApc>>,
    /// IOCP waiters registered via `NtAssociateWaitCompletionPacket`.
    ///
    /// When the thread exits (becomes signaled), each entry is posted to
    /// the corresponding I/O completion port.
    pub iocp_waiters: Mutex<Vec<(Arc<IoCompletionObject>, IoCompletionEntry)>>,
    /// Wakers for threads blocked in NtWaitForAlertByThreadId.
    pub alert_by_id_waiters: Mutex<Vec<SyncWaker>>,
    /// Most recent raw syscall number observed for this thread.
    pub last_syscall: core::sync::atomic::AtomicU32,
    /// Last guest RIP/RSP observed at a shim boundary for diagnostics.
    pub last_guest_rip: core::sync::atomic::AtomicUsize,
    pub last_guest_rsp: core::sync::atomic::AtomicUsize,
    /// Return address at the top of the guest stack on the last syscall entry.
    pub last_caller_ret: core::sync::atomic::AtomicUsize,
    /// Last address passed to NtWaitForAlertByThreadId by this thread.
    pub last_wait_alert_addr: core::sync::atomic::AtomicUsize,
    /// Last lock/address associated with an incoming by-thread-id alert.
    pub last_incoming_alert_lock: core::sync::atomic::AtomicUsize,
    /// Last target thread ID for an outgoing by-thread-id alert.
    pub last_outgoing_alert_target_tid: core::sync::atomic::AtomicU32,
    /// Last lock/address for an outgoing by-thread-id alert.
    pub last_outgoing_alert_lock: core::sync::atomic::AtomicUsize,
    /// Diagnostic counters for by-thread-id alert posts and consumptions.
    pub alert_by_id_posts: core::sync::atomic::AtomicU32,
    pub alert_by_id_consumes: core::sync::atomic::AtomicU32,
    /// Last implicit TLS array pointer observed during post-NtContinue repair.
    pub last_tls_array_ptr: core::sync::atomic::AtomicUsize,
    /// Last TLS repair counters: recopied slots, null slots, skipped slots.
    pub last_tls_slots_recopied: core::sync::atomic::AtomicU32,
    pub last_tls_null_slots: core::sync::atomic::AtomicU32,
    pub last_tls_skipped_slots: core::sync::atomic::AtomicU32,
    /// Progress marker for thread-exit bookkeeping diagnostics.
    pub exit_stage: core::sync::atomic::AtomicU32,
    /// Generic per-thread debug stage used by targeted investigations.
    pub debug_stage: core::sync::atomic::AtomicU32,
    /// Recent alert/wait history for watchdog diagnostics.
    alert_history: Mutex<VecDeque<AlertHistoryEntry>>,
}

pub struct AlertByIdState {
    /// Set by `NtAlertThread` — consumed by alertable waits
    /// (`take_pending_alert`).
    pub pending_any: bool,
    /// Set by `NtAlertThreadByThreadId` / `NtAlertThreadByThreadIdEx` —
    /// consumed by `NtWaitForAlertByThreadId` (`take_pending_alert_by_id`).
    /// On real Windows these are a separate per-thread mechanism from
    /// alertable waits; the address parameter in the Ex variant is purely
    /// informational (ETW) and the kernel does NOT match it.
    pub pending_by_thread_id: bool,
}

#[derive(Clone, Copy)]
enum AlertHistoryKind {
    WaitPending,
    WaitBlock,
    WaitOk,
    WaitTimeout,
    WaitConsume,
    PostIncoming,
    PostOutgoing,
}

#[derive(Clone, Copy)]
struct AlertHistoryEntry {
    kind: AlertHistoryKind,
    arg0: usize,
    arg1: usize,
}

impl ThreadObject {
    /// Create a new thread object with the given initial suspend count.
    pub fn new(thread_id: u32, initial_suspend_count: u32, teb_va: usize) -> Self {
        Self {
            exit_status: Mutex::new(None),
            thread_id,
            teb_va: Mutex::new(teb_va),
            waiters: Mutex::new(Vec::new()),
            suspend_count: Mutex::new(initial_suspend_count),
            resume_waiters: Mutex::new(Vec::new()),
            alert_by_id_pending: Mutex::new(AlertByIdState {
                pending_any: false,
                pending_by_thread_id: false,
            }),
            alert_waiters: Mutex::new(Vec::new()),
            pending_user_apcs: Mutex::new(alloc::vec::Vec::new()),
            iocp_waiters: Mutex::new(Vec::new()),
            alert_by_id_waiters: Mutex::new(Vec::new()),
            last_syscall: core::sync::atomic::AtomicU32::new(0),
            last_guest_rip: core::sync::atomic::AtomicUsize::new(0),
            last_guest_rsp: core::sync::atomic::AtomicUsize::new(0),
            last_caller_ret: core::sync::atomic::AtomicUsize::new(0),
            last_wait_alert_addr: core::sync::atomic::AtomicUsize::new(0),
            last_incoming_alert_lock: core::sync::atomic::AtomicUsize::new(0),
            last_outgoing_alert_target_tid: core::sync::atomic::AtomicU32::new(0),
            last_outgoing_alert_lock: core::sync::atomic::AtomicUsize::new(0),
            alert_by_id_posts: core::sync::atomic::AtomicU32::new(0),
            alert_by_id_consumes: core::sync::atomic::AtomicU32::new(0),
            last_tls_array_ptr: core::sync::atomic::AtomicUsize::new(0),
            last_tls_slots_recopied: core::sync::atomic::AtomicU32::new(0),
            last_tls_null_slots: core::sync::atomic::AtomicU32::new(0),
            last_tls_skipped_slots: core::sync::atomic::AtomicU32::new(0),
            exit_stage: core::sync::atomic::AtomicU32::new(0),
            debug_stage: core::sync::atomic::AtomicU32::new(0),
            alert_history: Mutex::new(VecDeque::new()),
        }
    }

    /// Mark the thread as exited with the given exit code and wake all waiters.
    pub fn set_exited(&self, code: i32) {
        *self.exit_status.lock() = Some(code);
        for w in self.waiters.lock().iter() {
            w.wake();
        }
        // Fire IOCP waiters registered via NtAssociateWaitCompletionPacket.
        let waiters: Vec<(Arc<IoCompletionObject>, IoCompletionEntry)> =
            core::mem::take(&mut *self.iocp_waiters.lock());
        for (iocp, entry) in waiters {
            iocp.push(entry);
        }
    }

    pub fn set_exit_stage(&self, stage: u32) {
        self.exit_stage
            .store(stage, core::sync::atomic::Ordering::Relaxed);
    }

    pub fn set_last_syscall(&self, nr: u32) {
        self.last_syscall
            .store(nr, core::sync::atomic::Ordering::Relaxed);
    }

    pub fn last_syscall(&self) -> u32 {
        self.last_syscall
            .load(core::sync::atomic::Ordering::Relaxed)
    }

    pub fn set_last_guest_context(&self, rip: usize, rsp: usize) {
        self.last_guest_rip
            .store(rip, core::sync::atomic::Ordering::Relaxed);
        self.last_guest_rsp
            .store(rsp, core::sync::atomic::Ordering::Relaxed);
    }

    pub fn last_guest_context(&self) -> (usize, usize) {
        (
            self.last_guest_rip
                .load(core::sync::atomic::Ordering::Relaxed),
            self.last_guest_rsp
                .load(core::sync::atomic::Ordering::Relaxed),
        )
    }

    pub fn set_last_caller_ret(&self, ret: usize) {
        self.last_caller_ret
            .store(ret, core::sync::atomic::Ordering::Relaxed);
    }

    pub fn last_caller_ret(&self) -> usize {
        self.last_caller_ret
            .load(core::sync::atomic::Ordering::Relaxed)
    }

    pub fn set_last_wait_alert_addr(&self, addr: usize) {
        self.last_wait_alert_addr
            .store(addr, core::sync::atomic::Ordering::Relaxed);
    }

    pub fn last_wait_alert_addr(&self) -> usize {
        self.last_wait_alert_addr
            .load(core::sync::atomic::Ordering::Relaxed)
    }

    pub fn set_last_outgoing_alert(&self, target_tid: u32, lock: usize) {
        self.last_outgoing_alert_target_tid
            .store(target_tid, core::sync::atomic::Ordering::Relaxed);
        self.last_outgoing_alert_lock
            .store(lock, core::sync::atomic::Ordering::Relaxed);
        self.record_alert_history(AlertHistoryKind::PostOutgoing, target_tid as usize, lock);
    }

    pub fn last_outgoing_alert(&self) -> (u32, usize) {
        (
            self.last_outgoing_alert_target_tid
                .load(core::sync::atomic::Ordering::Relaxed),
            self.last_outgoing_alert_lock
                .load(core::sync::atomic::Ordering::Relaxed),
        )
    }

    pub fn note_alert_by_id_post(&self, lock: usize) {
        self.last_incoming_alert_lock
            .store(lock, core::sync::atomic::Ordering::Relaxed);
        self.alert_by_id_posts
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        self.record_alert_history(AlertHistoryKind::PostIncoming, lock, 0);
    }

    pub fn note_alert_by_id_consume(&self) {
        self.alert_by_id_consumes
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }

    pub fn alert_by_id_counters(&self) -> (u32, u32) {
        (
            self.alert_by_id_posts
                .load(core::sync::atomic::Ordering::Relaxed),
            self.alert_by_id_consumes
                .load(core::sync::atomic::Ordering::Relaxed),
        )
    }

    pub fn last_incoming_alert_lock(&self) -> usize {
        self.last_incoming_alert_lock
            .load(core::sync::atomic::Ordering::Relaxed)
    }

    pub fn alert_by_id_snapshot(&self) -> (bool, bool, usize, usize) {
        let pending = self.alert_by_id_pending.lock();
        let pending_any = pending.pending_any;
        let pending_by_thread_id = pending.pending_by_thread_id;
        drop(pending);
        let alert_waiters = self.alert_waiters.lock().len();
        let alert_by_id_waiters = self.alert_by_id_waiters.lock().len();
        (
            pending_any,
            pending_by_thread_id,
            alert_waiters,
            alert_by_id_waiters,
        )
    }

    fn record_alert_history(&self, kind: AlertHistoryKind, arg0: usize, arg1: usize) {
        let mut history = self.alert_history.lock();
        if history.len() >= 8 {
            history.pop_front();
        }
        history.push_back(AlertHistoryEntry { kind, arg0, arg1 });
    }

    pub fn note_wait_alert_pending(&self, address: usize) {
        self.record_alert_history(AlertHistoryKind::WaitPending, address, 0);
    }

    pub fn note_wait_alert_consume(&self, address: usize) {
        self.record_alert_history(AlertHistoryKind::WaitConsume, address, 0);
    }

    pub fn note_wait_alert_block(&self, address: usize) {
        self.record_alert_history(AlertHistoryKind::WaitBlock, address, 0);
    }

    pub fn note_wait_alert_result(&self, address: usize, alerted: bool) {
        self.record_alert_history(
            if alerted {
                AlertHistoryKind::WaitOk
            } else {
                AlertHistoryKind::WaitTimeout
            },
            address,
            0,
        );
    }

    pub fn format_alert_history(&self) -> String {
        let history = self.alert_history.lock();
        if history.is_empty() {
            return String::new();
        }
        let mut out = String::new();
        for (idx, entry) in history.iter().enumerate() {
            if idx != 0 {
                out.push('|');
            }
            let piece = match entry.kind {
                AlertHistoryKind::WaitPending => alloc::format!("wp@0x{:X}", entry.arg0),
                AlertHistoryKind::WaitBlock => alloc::format!("wb@0x{:X}", entry.arg0),
                AlertHistoryKind::WaitOk => alloc::format!("wo@0x{:X}", entry.arg0),
                AlertHistoryKind::WaitTimeout => alloc::format!("wt@0x{:X}", entry.arg0),
                AlertHistoryKind::WaitConsume => alloc::format!("wc@0x{:X}", entry.arg0),
                AlertHistoryKind::PostIncoming => alloc::format!("pi@0x{:X}", entry.arg0),
                AlertHistoryKind::PostOutgoing => {
                    alloc::format!("po:{}@0x{:X}", entry.arg0, entry.arg1)
                }
            };
            out.push_str(&piece);
        }
        out
    }

    pub fn exit_stage(&self) -> u32 {
        self.exit_stage.load(core::sync::atomic::Ordering::Relaxed)
    }

    pub fn set_tls_repair_stats(
        &self,
        tls_array_ptr: usize,
        recopied: u32,
        null_slots: u32,
        skipped: u32,
    ) {
        self.last_tls_array_ptr
            .store(tls_array_ptr, core::sync::atomic::Ordering::Relaxed);
        self.last_tls_slots_recopied
            .store(recopied, core::sync::atomic::Ordering::Relaxed);
        self.last_tls_null_slots
            .store(null_slots, core::sync::atomic::Ordering::Relaxed);
        self.last_tls_skipped_slots
            .store(skipped, core::sync::atomic::Ordering::Relaxed);
    }

    pub fn tls_repair_stats(&self) -> (usize, u32, u32, u32) {
        (
            self.last_tls_array_ptr
                .load(core::sync::atomic::Ordering::Relaxed),
            self.last_tls_slots_recopied
                .load(core::sync::atomic::Ordering::Relaxed),
            self.last_tls_null_slots
                .load(core::sync::atomic::Ordering::Relaxed),
            self.last_tls_skipped_slots
                .load(core::sync::atomic::Ordering::Relaxed),
        )
    }

    pub fn set_debug_stage(&self, stage: u32) {
        self.debug_stage
            .store(stage, core::sync::atomic::Ordering::Relaxed);
    }

    pub fn debug_stage(&self) -> u32 {
        self.debug_stage.load(core::sync::atomic::Ordering::Relaxed)
    }

    /// Returns true if the thread has exited.
    pub fn has_exited(&self) -> bool {
        self.exit_status.lock().is_some()
    }

    /// Return the thread's current guest TEB VA.
    pub fn teb_va(&self) -> usize {
        *self.teb_va.lock()
    }

    /// Update the thread's guest TEB VA once it becomes known.
    pub fn set_teb_va(&self, teb_va: usize) {
        *self.teb_va.lock() = teb_va;
    }

    /// Block the host thread until the guest thread is resumed.
    pub fn wait_until_resumed(&self, cx: &litebox::event::wait::WaitContext<'_, Platform>) {
        self.resume_waiters.lock().push(cx.waker().clone());
        let _ = cx.wait_until(|| *self.suspend_count.lock() == 0);
        self.resume_waiters.lock().retain(|w| !w.ptr_eq(cx.waker()));
    }

    /// Resume the thread once and return the previous suspend count.
    pub fn resume(&self) -> u32 {
        let mut suspend_count = self.suspend_count.lock();
        let previous = *suspend_count;
        if *suspend_count != 0 {
            *suspend_count -= 1;
            if *suspend_count == 0 {
                let mut waiters = self.resume_waiters.lock();
                for w in waiters.drain(..) {
                    w.wake();
                }
            }
        }
        previous
    }

    /// Consume a pending plain thread alert, if one exists.
    pub(crate) fn take_pending_alert(&self) -> bool {
        let mut pending = self.alert_by_id_pending.lock();
        if pending.pending_any {
            pending.pending_any = false;
            true
        } else {
            false
        }
    }

    /// Consume a pending alert-by-thread-id wake, if one exists.
    ///
    /// The `_address` parameter is accepted for API compatibility but is not
    /// used for matching — all `NtAlertThreadByThreadId`/Ex alerts are
    /// unconditional per-thread wakes.  Plain `NtAlertThread` alerts
    /// (`pending_any`) do NOT satisfy this — they are a separate mechanism
    /// on real Windows.
    pub(crate) fn take_pending_alert_by_id(&self, address: usize) -> bool {
        let mut pending = self.alert_by_id_pending.lock();
        if pending.pending_by_thread_id {
            pending.pending_by_thread_id = false;
            self.note_alert_by_id_consume();
            drop(pending);
            true
        } else {
            false
        }
    }

    /// Post a plain thread alert and notify alertable waiters only.
    ///
    /// This is the correct mechanism for `NtAlertThread` and
    /// `NtAlertResumeThread`. It sets `pending_any` and wakes
    /// `alert_waiters` but does NOT wake `alert_by_id_waiters` —
    /// `NtWaitForAlertByThreadId` uses a separate mechanism.
    pub(crate) fn post_plain_alert(&self) {
        {
            let mut pending = self.alert_by_id_pending.lock();
            pending.pending_any = true;
        }
        for w in self.alert_waiters.lock().iter() {
            w.wake();
        }
    }

    /// Queue a user-mode APC and wake alertable waiters.
    ///
    /// The APC will be drained when the thread enters an alertable wait
    /// or calls `NtTestAlert`.
    pub(crate) fn queue_user_apc(&self, apc: PendingUserApc) {
        self.pending_user_apcs.lock().push(apc);
        // Wake alertable waiters so they can detect the pending APC.
        for w in self.alert_waiters.lock().iter() {
            w.wake();
        }
    }

    /// Drain all pending user-mode APCs, returning them.
    ///
    /// Returns an empty Vec if no APCs are pending.
    pub(crate) fn drain_pending_user_apcs(&self) -> alloc::vec::Vec<PendingUserApc> {
        let mut apcs = self.pending_user_apcs.lock();
        if apcs.is_empty() {
            return alloc::vec::Vec::new();
        }
        core::mem::take(&mut *apcs)
    }

    /// Check whether there are any pending user-mode APCs without draining.
    pub(crate) fn has_pending_user_apcs(&self) -> bool {
        !self.pending_user_apcs.lock().is_empty()
    }

    /// Post an alert-by-thread-id wake and notify any blocked waiters.
    ///
    /// `is_by_thread_id` distinguishes the two Windows alert mechanisms:
    /// - `true` — `NtAlertThreadByThreadId` / `NtAlertThreadByThreadIdEx`:
    ///   sets `pending_by_thread_id` and only wakes `alert_by_id_waiters`.
    ///   The address parameter in the Ex variant is purely informational
    ///   (used for ETW tracing); the kernel does NOT match it.
    /// - `false` — process-exit: sets both `pending_any` and
    ///   `pending_by_thread_id`, wakes both alertable and by-id waiters.
    pub(crate) fn alert_by_id(&self, is_by_thread_id: bool, lock: usize) {
        {
            let mut pending = self.alert_by_id_pending.lock();
            if is_by_thread_id {
                pending.pending_by_thread_id = true;
            } else {
                pending.pending_any = true;
                pending.pending_by_thread_id = true;
            }
        }
        self.note_alert_by_id_post(lock);

        if is_by_thread_id {
            // NtAlertThreadByThreadId/Ex only wakes NtWaitForAlertByThreadId.
            for w in self.alert_by_id_waiters.lock().iter() {
                w.wake();
            }
        } else {
            // Process-exit wakes everything.
            for w in self.alert_waiters.lock().iter() {
                w.wake();
            }
            for w in self.alert_by_id_waiters.lock().iter() {
                w.wake();
            }
        }
    }
}

/// A queued completion packet delivered through an I/O completion port.
#[derive(Clone, Copy, Debug)]
pub struct IoCompletionEntry {
    pub key_context: usize,
    pub apc_context: usize,
    pub status: NtStatus,
    pub information: usize,
}

/// Internal state for an NT I/O completion port.
pub struct IoCompletionObject {
    /// FIFO queue of pending completion packets.
    pub queue: Mutex<VecDeque<IoCompletionEntry>>,
    /// Wakers for threads blocked in NtRemoveIoCompletion[Ex].
    pub waiters: Mutex<Vec<SyncWaker>>,
}

impl IoCompletionObject {
    /// Create an empty completion port.
    pub fn new() -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            waiters: Mutex::new(Vec::new()),
        }
    }

    /// Queue a completion packet and wake any waiting threads.
    pub fn push(&self, entry: IoCompletionEntry) {
        #[cfg(feature = "trace_debug")]
        {
            use litebox::platform::DebugLogProvider as _;
            let waiter_count = self.waiters.lock().len();
            let self_ptr = self as *const Self as usize;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: IoCompletionObject::push() IOCP={self_ptr:#X} status={:?} info={} waiters={waiter_count}\n",
                entry.status, entry.information,
            ));
        }
        self.queue.lock().push_back(entry);
        self.wake_waiters();
    }

    /// Wake all threads waiting on this completion port.
    pub fn wake_waiters(&self) {
        for w in self.waiters.lock().iter() {
            w.wake();
        }
    }
}

/// Observer that posts an IOCP completion when a socket becomes readable,
/// reaches half-close, or enters an error state.
///
/// Registered on the socket's `NetworkProxy` pollee via `register_observer`.
/// The observer fires **at most once**: the first matching event atomically
/// sets the `fired` flag and posts a completion packet.  The `Arc` held by
/// the caller should be dropped after the completion fires so the `Weak`
/// reference in the pollee auto-prunes.
pub struct SocketIocpObserver {
    /// The I/O completion port to post to.
    iocp: Arc<IoCompletionObject>,
    /// Per-socket completion key (set by `FileCompletionInformation`).
    key_context: usize,
    /// The `OVERLAPPED*` value that libuv uses to correlate the completion.
    apc_context: usize,
    /// Ensures we only post one completion per observer.
    fired: core::sync::atomic::AtomicBool,
    /// The IO_STATUS_BLOCK address in guest memory to write on completion.
    io_status_block: usize,
    /// The event handle to signal on completion (0 = no event).
    event_handle: u32,
}

impl SocketIocpObserver {
    /// Create a new observer for a pending 0-byte async RECV.
    pub fn new(
        iocp: Arc<IoCompletionObject>,
        key_context: usize,
        apc_context: usize,
        io_status_block: usize,
        event_handle: u32,
    ) -> Self {
        Self {
            iocp,
            key_context,
            apc_context,
            fired: core::sync::atomic::AtomicBool::new(false),
            io_status_block,
            event_handle,
        }
    }

    /// Returns `true` if this observer has already fired its IOCP completion.
    pub fn is_fired(&self) -> bool {
        self.fired.load(core::sync::atomic::Ordering::Acquire)
    }
}

impl litebox::event::observer::Observer<litebox::event::Events> for SocketIocpObserver {
    fn on_events(&self, events: &litebox::event::Events) {
        // Only fire once.
        if self.fired.swap(true, core::sync::atomic::Ordering::AcqRel) {
            return;
        }

        let status = if events.contains(litebox::event::Events::ERR) {
            NtStatus::STATUS_CONNECTION_RESET
        } else {
            // IN or HUP — both mean the 0-byte recv notification succeeded.
            NtStatus::STATUS_SUCCESS
        };

        // Write IO_STATUS_BLOCK to guest memory.
        // Layout on x64: Status/Pointer union (8 bytes at +0), Information (usize at +8).
        if self.io_status_block != 0 {
            super::try_write_guest_value_unaligned::<u64>(
                self.io_status_block,
                (status.0 as u32) as u64,
            );
            super::try_write_guest_value_unaligned::<usize>(self.io_status_block + 8, 0);
        }

        // Signal the event if one was specified.
        if self.event_handle != 0 {
            // We cannot acquire the handle table lock here (called from
            // inside `Subject::notify_observers` which already holds a lock).
            // Instead we use the EventObject's methods directly via a stored
            // reference in the future.  For now, skip — libuv's 0-byte RECV
            // uses IOCP not events (event_handle == 0).
        }

        #[cfg(feature = "trace_debug")]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: SocketIocpObserver fired events={events:?} status=0x{:X} key=0x{:X} apc=0x{:X}\n",
                status.0, self.key_context, self.apc_context,
            ));
        }

        self.iocp.push(IoCompletionEntry {
            key_context: self.key_context,
            apc_context: self.apc_context,
            status,
            information: 0,
        });
    }
}

/// Observer that completes an async AFD_SELECT (poll) when events fire on the
/// watched socket.
///
/// When none of the requested events are immediately available, the AFD_SELECT
/// returns STATUS_PENDING.  This observer is registered on the *polled*
/// socket's proxy.  When matching events arrive, it writes the AFD_SELECT
/// output buffer and posts an IOCP completion to unblock the event loop.
pub struct SocketSelectIocpObserver {
    /// The I/O completion port to post to.
    iocp: Arc<IoCompletionObject>,
    /// Per-socket completion key (set by `FileCompletionInformation`).
    key_context: usize,
    /// The `OVERLAPPED*` / APC context value.
    apc_context: usize,
    /// Ensures we only fire once.
    fired: core::sync::atomic::AtomicBool,
    /// IO_STATUS_BLOCK address in guest memory.
    io_status_block: usize,
    /// Output buffer address (same as input for METHOD_BUFFERED).
    output_buf: usize,
    /// Total output buffer length.
    output_buf_len: usize,
    /// The polled socket handle value (written into the output entry).
    polled_handle: u64,
    /// Requested event mask (AFD_POLL_* bits).
    requested_events: u32,
}

impl SocketSelectIocpObserver {
    pub fn new(
        iocp: Arc<IoCompletionObject>,
        key_context: usize,
        apc_context: usize,
        io_status_block: usize,
        output_buf: usize,
        output_buf_len: usize,
        polled_handle: u64,
        requested_events: u32,
    ) -> Self {
        Self {
            iocp,
            key_context,
            apc_context,
            fired: core::sync::atomic::AtomicBool::new(false),
            io_status_block,
            output_buf,
            output_buf_len,
            polled_handle,
            requested_events,
        }
    }

    pub fn is_fired(&self) -> bool {
        self.fired.load(core::sync::atomic::Ordering::Acquire)
    }
}

impl litebox::event::observer::Observer<litebox::event::Events> for SocketSelectIocpObserver {
    fn on_events(&self, events: &litebox::event::Events) {
        // Only fire once.
        if self.fired.swap(true, core::sync::atomic::Ordering::AcqRel) {
            return;
        }

        // AFD_POLL event constants (from libuv's src/win/winsock.h).
        const AFD_POLL_RECEIVE: u32 = 0x0001;
        const AFD_POLL_SEND: u32 = 0x0004;
        const AFD_POLL_DISCONNECT: u32 = 0x0008;
        const AFD_POLL_ABORT: u32 = 0x0010;
        const AFD_POLL_CONNECT_FAIL: u32 = 0x0100;

        let mut signaled: u32 = 0;
        if events.contains(litebox::event::Events::IN)
            && (self.requested_events & AFD_POLL_RECEIVE) != 0
        {
            signaled |= AFD_POLL_RECEIVE;
        }
        if events.contains(litebox::event::Events::OUT)
            && (self.requested_events & AFD_POLL_SEND) != 0
        {
            signaled |= AFD_POLL_SEND;
        }
        if events.contains(litebox::event::Events::HUP)
            && (self.requested_events & AFD_POLL_DISCONNECT) != 0
        {
            signaled |= AFD_POLL_DISCONNECT;
        }
        if events.contains(litebox::event::Events::ERR) {
            if (self.requested_events & AFD_POLL_ABORT) != 0 {
                signaled |= AFD_POLL_ABORT;
            }
            if (self.requested_events & AFD_POLL_CONNECT_FAIL) != 0 {
                signaled |= AFD_POLL_CONNECT_FAIL;
            }
        }

        if signaled == 0 {
            // Events fired but nothing we care about — re-arm.
            self.fired
                .store(false, core::sync::atomic::Ordering::Release);
            return;
        }

        // Write AFD_SELECT output buffer:
        //   +0x08: NumberOfHandles = 1
        //   +0x10: Entry[0].Handle = polled_handle
        //   +0x18: Entry[0].Events = signaled
        //   +0x1C: Entry[0].Status = 0
        let buf = self.output_buf;
        if buf != 0 && self.output_buf_len >= 0x20 {
            super::try_write_guest_value_unaligned::<u32>(buf + 0x08, 1u32); // 1 handle
            super::try_write_guest_value_unaligned::<u64>(buf + 0x10, self.polled_handle);
            super::try_write_guest_value_unaligned::<u32>(buf + 0x18, signaled);
            super::try_write_guest_value_unaligned::<u32>(buf + 0x1C, 0u32); // STATUS_SUCCESS
        }

        // Write IO_STATUS_BLOCK.
        let info_size = 0x20usize; // header + 1 entry
        if self.io_status_block != 0 {
            super::try_write_guest_value_unaligned::<u64>(self.io_status_block, 0u64); // STATUS_SUCCESS (full 8-byte union)
            super::try_write_guest_value_unaligned::<usize>(self.io_status_block + 8, info_size);
        }

        #[cfg(feature = "trace_debug")]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: SocketSelectIocpObserver fired events={events:?} signaled=0x{signaled:X} handle=0x{:X}\n",
                self.polled_handle,
            ));

            // Readback the AFD_POLL output buffer to verify
            if buf != 0 && self.output_buf_len >= 0x20 {
                let mut poll_bytes = [0u8; 32];
                for i in 0..32 {
                    poll_bytes[i] =
                        super::try_read_guest_value_unaligned::<u8>(buf + i).unwrap_or(0xFF);
                }
                let hex: alloc::string::String = poll_bytes
                    .iter()
                    .map(|b| alloc::format!("{:02X} ", b))
                    .collect();
                litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                    "NT shim: AFD_POLL output readback at 0x{buf:X}: [{hex}]\n"
                ));
            }
        }

        self.iocp.push(IoCompletionEntry {
            key_context: self.key_context,
            apc_context: self.apc_context,
            status: NtStatus::STATUS_SUCCESS,
            information: info_size,
        });
    }
}

/// Observer that completes an async non-zero-byte RECV when data arrives.
///
/// Unlike `SocketIocpObserver` (which is a lightweight notification for 0-byte
/// RECV), this observer performs the actual read, scatters data into guest
/// WSABUF buffers, and posts the IOCP completion with the byte count.
///
/// The `fired` flag ensures at most one completion.  If `try_read` returns no
/// data (spurious wake or race), the flag is reset so the observer can be
/// re-triggered on the next event.
pub struct SocketRecvIocpObserver {
    /// Lock-free proxy for reading from the socket's RX ring buffer.
    proxy: alloc::sync::Arc<litebox::net::socket_channel::NetworkProxy<Platform>>,
    /// Temporary buffer for `try_read` output (sized to total WSABUF length).
    recv_buf: spin::Mutex<alloc::vec::Vec<u8>>,
    /// Guest WSABUF entries: (guest_ptr, len) pairs for scattering received data.
    wsabuf_entries: alloc::vec::Vec<(usize, usize)>,
    /// Receive flags (e.g. PEEK).
    recv_flags: litebox::net::ReceiveFlags,
    /// The I/O completion port to post to.
    iocp: Arc<IoCompletionObject>,
    /// Per-socket completion key.
    key_context: usize,
    /// The `OVERLAPPED*` value for IOCP correlation.
    apc_context: usize,
    /// Ensures at most one successful completion.
    fired: core::sync::atomic::AtomicBool,
    /// IO_STATUS_BLOCK address in guest memory.
    io_status_block: usize,
    /// Event handle to signal (0 = none).
    event_handle: u32,
}

impl SocketRecvIocpObserver {
    /// Create a new observer for a pending async non-zero-byte RECV.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proxy: alloc::sync::Arc<litebox::net::socket_channel::NetworkProxy<Platform>>,
        total_len: usize,
        wsabuf_entries: alloc::vec::Vec<(usize, usize)>,
        recv_flags: litebox::net::ReceiveFlags,
        iocp: Arc<IoCompletionObject>,
        key_context: usize,
        apc_context: usize,
        io_status_block: usize,
        event_handle: u32,
    ) -> Self {
        Self {
            proxy,
            recv_buf: spin::Mutex::new(alloc::vec![0u8; total_len]),
            wsabuf_entries,
            recv_flags,
            iocp,
            key_context,
            apc_context,
            fired: core::sync::atomic::AtomicBool::new(false),
            io_status_block,
            event_handle,
        }
    }

    /// Returns `true` if this observer has already completed.
    pub fn is_fired(&self) -> bool {
        self.fired.load(core::sync::atomic::Ordering::Acquire)
    }

    /// Attempt to complete the pending RECV right now (inline retry after
    /// observer registration).  Returns `true` if completed, `false` if no
    /// data was available.
    pub fn try_complete_now(&self) -> bool {
        self.do_try_read_and_complete()
    }

    /// Core logic shared by `on_events` and `try_complete_now`.
    ///
    /// Atomically claims the completion slot via `fired`, performs `try_read`,
    /// scatters data into guest buffers, and posts the IOCP completion.
    /// Returns `true` if a completion was posted (or a terminal error handled).
    fn do_try_read_and_complete(&self) -> bool {
        // Atomically claim — only one caller proceeds.
        if self.fired.swap(true, core::sync::atomic::Ordering::AcqRel) {
            return true; // already completed by another path
        }

        let mut buf = self.recv_buf.lock();
        match self.proxy.try_read(&mut buf, self.recv_flags, None) {
            Ok(n) if n > 0 => {
                // Scatter received data into guest WSABUF array.
                let mut offset = 0usize;
                for &(buf_ptr, len) in &self.wsabuf_entries {
                    if offset >= n {
                        break;
                    }
                    let chunk = core::cmp::min(len, n - offset);
                    for j in 0..chunk {
                        super::try_write_guest_value_unaligned(buf_ptr + j, buf[offset + j]);
                    }
                    offset += chunk;
                }
                drop(buf); // release lock before IOCP post

                self.post_completion(NtStatus::STATUS_SUCCESS, n);
                true
            }
            Ok(_) => {
                // No data yet — re-arm so the next event re-triggers us.
                drop(buf);
                self.fired
                    .store(false, core::sync::atomic::Ordering::Release);
                false
            }
            Err(litebox::net::errors::ReceiveError::SocketInInvalidState) => {
                drop(buf);
                // Check for graceful close or error.
                use litebox::event::IOPollable as _;
                let events = self.proxy.check_io_events();
                if events.contains(litebox::event::Events::HUP) {
                    self.post_completion(NtStatus::STATUS_SUCCESS, 0);
                    true
                } else if events.contains(litebox::event::Events::ERR) {
                    self.post_completion(NtStatus::STATUS_CONNECTION_RESET, 0);
                    true
                } else {
                    // Not yet ready — re-arm.
                    self.fired
                        .store(false, core::sync::atomic::Ordering::Release);
                    false
                }
            }
            Err(litebox::net::errors::ReceiveError::OperationFinished) => {
                drop(buf);
                self.post_completion(NtStatus::STATUS_SUCCESS, 0);
                true
            }
            Err(litebox::net::errors::ReceiveError::InvalidFd) => {
                drop(buf);
                self.post_completion(NtStatus::STATUS_INVALID_HANDLE, 0);
                true
            }
            Err(_) => {
                drop(buf);
                self.post_completion(NtStatus::STATUS_CONNECTION_RESET, 0);
                true
            }
        }
    }

    /// Write IO_STATUS_BLOCK and post IOCP completion.
    fn post_completion(&self, status: NtStatus, information: usize) {
        if self.io_status_block != 0 {
            super::try_write_guest_value_unaligned::<u64>(
                self.io_status_block,
                (status.0 as u32) as u64,
            );
            super::try_write_guest_value_unaligned::<usize>(self.io_status_block + 8, information);
        }

        #[cfg(feature = "trace_debug")]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: SocketRecvIocpObserver completed status=0x{:X} bytes={} key=0x{:X} apc=0x{:X}\n",
                status.0, information, self.key_context, self.apc_context,
            ));
        }

        self.iocp.push(IoCompletionEntry {
            key_context: self.key_context,
            apc_context: self.apc_context,
            status,
            information,
        });
    }
}

impl litebox::event::observer::Observer<litebox::event::Events> for SocketRecvIocpObserver {
    fn on_events(&self, _events: &litebox::event::Events) {
        self.do_try_read_and_complete();
    }
}

/// Observer that completes an async event-based datagram RECV when data arrives.
///
/// Used by `AFD_RECV_DATAGRAM` when the caller provides an event handle but no
/// IOCP (apc_context == 0).  On data arrival, scatters data into guest WSABUF
/// buffers, writes the source address into the TDI output structure, updates the
/// IO_STATUS_BLOCK, and signals the event.
pub struct SocketRecvDatagramEventObserver {
    /// Lock-free proxy for reading from the socket's RX ring buffer.
    proxy: alloc::sync::Arc<litebox::net::socket_channel::NetworkProxy<Platform>>,
    /// Temporary buffer for `try_read` output.
    recv_buf: spin::Mutex<alloc::vec::Vec<u8>>,
    /// Guest WSABUF entries: (guest_ptr, len) pairs.
    wsabuf_entries: alloc::vec::Vec<(usize, usize)>,
    /// Receive flags (e.g. PEEK).
    recv_flags: litebox::net::ReceiveFlags,
    /// SOCKADDR output address pointer (0 = none).
    address_ptr: u64,
    /// AddressLength output pointer (0 = none).
    address_len_ptr: u64,
    /// IO_STATUS_BLOCK address in guest memory.
    io_status_block: usize,
    /// The event object to signal on completion.
    event: Arc<EventObject>,
    /// Ensures at most one successful completion.
    fired: core::sync::atomic::AtomicBool,
}

impl SocketRecvDatagramEventObserver {
    /// Create a new observer for a pending async event-based datagram RECV.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proxy: alloc::sync::Arc<litebox::net::socket_channel::NetworkProxy<Platform>>,
        total_len: usize,
        wsabuf_entries: alloc::vec::Vec<(usize, usize)>,
        recv_flags: litebox::net::ReceiveFlags,
        address_ptr: u64,
        address_len_ptr: u64,
        io_status_block: usize,
        event: Arc<EventObject>,
    ) -> Self {
        Self {
            proxy,
            recv_buf: spin::Mutex::new(alloc::vec![0u8; total_len]),
            wsabuf_entries,
            recv_flags,
            address_ptr,
            address_len_ptr,
            io_status_block,
            event,
            fired: core::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Returns `true` if this observer has already completed.
    pub fn is_fired(&self) -> bool {
        self.fired.load(core::sync::atomic::Ordering::Acquire)
    }

    /// Attempt to complete the pending RECV right now (inline retry after
    /// observer registration).
    pub fn try_complete_now(&self) -> bool {
        self.do_try_read_and_complete()
    }

    /// Core logic: try to read a datagram, scatter to guest buffers, write
    /// source address, update IO_STATUS_BLOCK, and signal event.
    fn do_try_read_and_complete(&self) -> bool {
        if self.fired.swap(true, core::sync::atomic::Ordering::AcqRel) {
            return true;
        }

        let mut buf = self.recv_buf.lock();
        let mut source_addr: Option<core::net::SocketAddr> = None;
        match self
            .proxy
            .try_read(&mut buf, self.recv_flags, Some(&mut source_addr))
        {
            Ok(n) if n > 0 => {
                // Scatter received data into guest WSABUF array.
                let mut offset = 0usize;
                for &(buf_ptr, len) in &self.wsabuf_entries {
                    if offset >= n {
                        break;
                    }
                    let chunk = core::cmp::min(len, n - offset);
                    for j in 0..chunk {
                        super::try_write_guest_value_unaligned(buf_ptr + j, buf[offset + j]);
                    }
                    offset += chunk;
                }
                drop(buf);

                // Write source address back as SOCKADDR_IN.
                if self.address_ptr != 0 {
                    if let Some(core::net::SocketAddr::V4(v4)) = source_addr {
                        let addr = self.address_ptr as usize;
                        super::try_write_guest_value_unaligned::<u16>(addr, 2u16); // AF_INET
                        super::try_write_guest_value_unaligned::<u16>(addr + 2, v4.port().to_be());
                        super::try_write_guest_value_unaligned(addr + 4, v4.ip().octets());
                        // Zero out sin_zero
                        super::try_write_guest_value_unaligned::<u64>(addr + 8, 0u64);
                        // Update AddressLength if the pointer is provided.
                        if self.address_len_ptr != 0 {
                            super::try_write_guest_value_unaligned::<i32>(
                                self.address_len_ptr as usize,
                                16i32, // sizeof(SOCKADDR_IN)
                            );
                        }
                    }
                }

                // Write IO_STATUS_BLOCK.
                if self.io_status_block != 0 {
                    super::try_write_guest_value_unaligned::<u64>(
                        self.io_status_block,
                        (NtStatus::STATUS_SUCCESS.0 as u32) as u64,
                    );
                    super::try_write_guest_value_unaligned::<usize>(self.io_status_block + 8, n);
                }

                #[cfg(feature = "trace_debug")]
                {
                    use litebox::platform::DebugLogProvider as _;
                    litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                        "NT shim: SocketRecvDatagramEventObserver completed bytes={n} from={source_addr:?}\n"
                    ));
                }

                // Signal the event.
                let mut signaled = self.event.state.lock();
                *signaled = true;
                drop(signaled);
                self.event.wake_waiters();

                true
            }
            Ok(_) => {
                // No data yet — re-arm.
                self.fired
                    .store(false, core::sync::atomic::Ordering::Release);
                false
            }
            Err(litebox::net::errors::ReceiveError::InvalidFd) => {
                drop(buf);
                if self.io_status_block != 0 {
                    super::try_write_guest_value_unaligned::<u64>(
                        self.io_status_block,
                        (NtStatus::STATUS_INVALID_HANDLE.0 as u32) as u64,
                    );
                    super::try_write_guest_value_unaligned::<usize>(self.io_status_block + 8, 0);
                }
                let mut signaled = self.event.state.lock();
                *signaled = true;
                drop(signaled);
                self.event.wake_waiters();
                true
            }
            Err(_) => {
                // Re-arm for transient errors.
                drop(buf);
                self.fired
                    .store(false, core::sync::atomic::Ordering::Release);
                false
            }
        }
    }
}

impl litebox::event::observer::Observer<litebox::event::Events>
    for SocketRecvDatagramEventObserver
{
    fn on_events(&self, _events: &litebox::event::Events) {
        self.do_try_read_and_complete();
    }
}

/// Internal state for an NT worker factory object.
///
/// Stores the I/O completion port that worker threads block on, plus the
/// start routine and parameter used when the kernel needs to spawn new worker
/// threads (triggered by `NtSetInformationWorkerFactory(ThreadMinimum)`).
pub struct WorkerFactoryObject {
    /// The I/O completion port associated with this worker factory.
    /// Worker threads block here via `NtReleaseWorkerFactoryWorker`.
    pub iocp: Arc<IoCompletionObject>,
    /// Guest-code entry point for new worker threads (e.g. `TppWorkerThread`).
    pub start_routine: usize,
    /// Opaque parameter passed to `start_routine` (e.g. pointer to `TP_POOL`).
    pub start_parameter: usize,
    /// Number of worker threads already spawned for this factory.
    pub threads_spawned: core::sync::atomic::AtomicU32,
}

/// Internal state for an NT Timer2 object.
///
/// Timer2 objects are the kernel-level timers used by the Windows thread pool
/// (`TppTimerpSet` / `TppTimerpCancel`).  They are armed with a due time
/// (absolute FILETIME) and an optional period.  When the due time expires, the
/// timer fires by posting a completion entry to its associated IOCP (registered
/// via `NtAssociateWaitCompletionPacket`).
pub struct Timer2Object {
    /// Armed state and expiry information.
    ///
    /// `None` means the timer is disarmed (created but `NtSetTimer2` not yet
    /// called, or `NtCancelTimer2` was called).
    ///
    /// When `Some`, the timer fires once `windows_filetime_now() >= due_time`.
    pub armed: Mutex<Option<Timer2Armed>>,
    /// IOCP association registered via `NtAssociateWaitCompletionPacket`.
    ///
    /// When the timer fires, it posts this entry to the IOCP and clears the
    /// armed state (or re-arms with the period if non-zero).
    pub iocp_waiter: Mutex<Option<(Arc<IoCompletionObject>, IoCompletionEntry)>>,
}

/// Armed state of a Timer2 object.
#[derive(Clone, Copy, Debug)]
pub struct Timer2Armed {
    /// Absolute expiry time in Windows FILETIME units (100 ns intervals since
    /// 1601-01-01 00:00:00 UTC).
    pub due_time: i64,
    /// Repeat period in 100 ns intervals.  0 means one-shot.
    pub period: i64,
}

impl Timer2Object {
    /// Create a new disarmed Timer2 object.
    pub fn new() -> Self {
        Self {
            armed: Mutex::new(None),
            iocp_waiter: Mutex::new(None),
        }
    }
}

/// Internal state for an NT semaphore object.
pub struct SemaphoreObject {
    /// Mutex-protected current count.
    pub state: Mutex<i32>,
    /// Maximum count.
    pub max_count: i32,
    /// Wakers for threads blocked in wait_semaphore.
    pub waiters: Mutex<Vec<SyncWaker>>,
}

impl SemaphoreObject {
    /// Create a new semaphore.
    pub fn new(initial_count: i32, max_count: i32) -> Self {
        Self {
            state: Mutex::new(initial_count),
            max_count,
            waiters: Mutex::new(Vec::new()),
        }
    }

    /// Wake all threads waiting on this semaphore.
    pub fn wake_waiters(&self) {
        for w in self.waiters.lock().iter() {
            w.wake();
        }
    }
}

/// Internal state for an NT mutant object.
pub struct MutantObject {
    /// Mutex-protected owner / recursion / abandoned state.
    pub state: Mutex<MutantState>,
    /// Wakers for threads blocked waiting on this mutant.
    pub waiters: Mutex<Vec<SyncWaker>>,
}

/// Mutable state inside a mutant object.
#[derive(Clone, Copy, Debug, Default)]
pub struct MutantState {
    /// Owning thread, if any.
    pub owner_thread_id: Option<u32>,
    /// Recursive acquisition count for the owner.
    pub recursion_count: u32,
    /// Whether the previous owner exited without releasing.
    pub abandoned: bool,
}

impl MutantObject {
    /// Create a new mutant.
    pub fn new(initial_owner: bool, owner_thread_id: u32) -> Self {
        Self {
            state: Mutex::new(MutantState {
                owner_thread_id: initial_owner.then_some(owner_thread_id),
                recursion_count: u32::from(initial_owner),
                abandoned: false,
            }),
            waiters: Mutex::new(Vec::new()),
        }
    }

    /// Wake all threads waiting on this mutant.
    pub fn wake_waiters(&self) {
        for w in self.waiters.lock().iter() {
            w.wake();
        }
    }
}

/// Internal state for an NT keyed event object.
///
/// Keyed events are a low-level futex-like primitive used internally by
/// SRW locks and condition variables. Each wait/release pair is matched 1:1:
/// one NtReleaseKeyedEvent wakes exactly one NtWaitForKeyedEvent on the same
/// key, and vice versa.
pub struct KeyedEventObject {
    /// Per-key queue state with per-caller release tokens for 1:1 matching.
    pub state: Mutex<BTreeMap<usize, KeyedWaiterQueue>>,
    /// Monotonic counter for unique release token IDs.
    next_release_id: Mutex<u64>,
    /// Wakers for threads blocked in wait/release on this keyed event.
    pub waiters: Mutex<Vec<SyncWaker>>,
}

/// Per-key queue state inside a keyed event.
///
/// Uses explicit FIFO queues for both waiters and releasers so that each
/// release is paired with exactly the oldest blocked waiter.
#[derive(Debug, Default)]
pub struct KeyedWaiterQueue {
    /// FIFO queue of waiter IDs. Each blocked waiter pushes its ID to the
    /// back. A releaser marks the oldest unserved waiter as ready.
    pub waiter_ids: alloc::collections::VecDeque<u64>,
    /// Set of waiter IDs that have been matched to a release and can proceed.
    pub ready_ids: alloc::collections::BTreeSet<u64>,
    /// FIFO queue of pending release tokens. Each releaser that posts before
    /// a waiter exists pushes a token and blocks until `consumed` is set.
    /// Waiters pop from the front to pair 1:1 with releasers in FIFO order.
    pub pending_releases: alloc::collections::VecDeque<ReleaseToken>,
}

/// A per-releaser token in the pending release queue.
#[derive(Debug)]
pub struct ReleaseToken {
    /// Unique ID for this release, used by the releaser to detect when
    /// *its specific* release has been consumed.
    pub id: u64,
    /// Set to true by the waiter that consumes this release.
    pub consumed: bool,
}

impl KeyedWaiterQueue {
    /// Returns true if the queue is empty and can be removed.
    pub fn is_empty(&self) -> bool {
        self.waiter_ids.is_empty() && self.ready_ids.is_empty() && self.pending_releases.is_empty()
    }
}

impl KeyedEventObject {
    /// Create a new keyed event.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(BTreeMap::new()),
            next_release_id: Mutex::new(0),
            waiters: Mutex::new(Vec::new()),
        }
    }

    /// Allocate a unique release token ID.
    pub fn alloc_release_id(&self) -> u64 {
        let mut id = self.next_release_id.lock();
        let val = *id;
        *id = val.wrapping_add(1);
        val
    }

    /// Wake all threads waiting on this keyed event.
    pub fn wake_waiters(&self) {
        for w in self.waiters.lock().iter() {
            w.wake();
        }
    }
}

/// A cached directory/search entry.
#[derive(Debug, Clone)]
pub struct DirEnumEntry {
    pub name: String,
    pub attributes: u32,
    pub file_size: i64,
    pub creation_time: i64,
    pub last_access_time: i64,
    pub last_write_time: i64,
}

/// The NT handle table.
///
/// Backed by the litebox core's `Descriptors` table (via `LiteBox`) for actual
/// object storage, and `RawDescriptorStorage` for mapping Windows handle values
/// (multiples of 4) to typed fd indices.
///
/// Thread-safety: The handle table itself is not internally synchronized.
/// The shim wraps it in a `Mutex` for multi-threaded access (Phase 3+).
/// The underlying `Descriptors` table uses interior `RwLock`s.
pub struct HandleTable<FS: crate::NtShimFS> {
    /// Maps raw NT handle values (as `usize`) to typed fds in the Descriptors table.
    raw_store: RawDescriptorStorage,
    /// Next handle value to allocate.
    next_handle: u32,
    /// Shared LiteBox instance providing access to the `Descriptors` table.
    litebox: LiteBox<Platform>,
    _fs: core::marker::PhantomData<FS>,
}

/// Clone an `NtObject` for handle duplication.
///
/// Returns `None` for variants that cannot be trivially duplicated (e.g.
/// `Socket`, whose core `SocketFd` is not `Clone`).
pub fn clone_nt_object<FS: crate::NtShimFS>(obj: &NtObject<FS>) -> Option<NtObject<FS>> {
    Some(match obj {
        NtObject::ConsoleInput => NtObject::ConsoleInput,
        NtObject::ConsoleOutput { is_stderr } => NtObject::ConsoleOutput {
            is_stderr: *is_stderr,
        },
        NtObject::File {
            path,
            vfs_path,
            position,
            vfs_fd,
            delete_on_close,
            fs,
        } => {
            // VFS-backed file: share the same TypedFd via Arc clone.
            NtObject::File {
                path: path.clone(),
                vfs_path: vfs_path.clone(),
                position: Arc::clone(position),
                vfs_fd: alloc::sync::Arc::clone(vfs_fd),
                delete_on_close: Arc::clone(delete_on_close),
                fs: alloc::sync::Arc::clone(fs),
            }
        }
        NtObject::Directory { path, .. } => NtObject::Directory {
            path: path.clone(),
            enum_entries: Vec::new(),
            enum_index: 0,
        },
        NtObject::FindSearch { entries, .. } => NtObject::FindSearch {
            entries: entries.clone(),
            next_index: 0,
        },
        NtObject::Stub {
            kind,
            io_completion,
        } => NtObject::Stub {
            kind: kind.clone(),
            io_completion: io_completion.clone(),
        },
        NtObject::Event(e) => NtObject::Event(Arc::clone(e)),
        NtObject::Semaphore(s) => NtObject::Semaphore(Arc::clone(s)),
        NtObject::Mutant(m) => NtObject::Mutant(Arc::clone(m)),
        NtObject::KeyedEvent(k) => NtObject::KeyedEvent(Arc::clone(k)),
        NtObject::Thread(t) => NtObject::Thread(Arc::clone(t)),
        NtObject::IoCompletion(port) => NtObject::IoCompletion(Arc::clone(port)),
        NtObject::Socket { .. } => {
            // Socket handles cannot be trivially duplicated — the core's
            // SocketFd is not Clone. Proper socket dup would require
            // Descriptors::duplicate() on the core's SocketFd.
            return None;
        }
        NtObject::Section {
            pe_data,
            module_path,
            module_name,
            image_size,
            image_base,
            entry_point,
            section_alignment,
            is_dll,
        } => NtObject::Section {
            pe_data: Arc::clone(pe_data),
            module_path: module_path.clone(),
            module_name: module_name.clone(),
            image_size: *image_size,
            image_base: *image_base,
            entry_point: *entry_point,
            section_alignment: *section_alignment,
            is_dll: *is_dll,
        },
        NtObject::DataSection { max_size } => NtObject::DataSection {
            max_size: *max_size,
        },
        NtObject::CurrentProcess => NtObject::CurrentProcess,
        NtObject::CurrentThread => NtObject::CurrentThread,
        NtObject::RegistryKey { path } => NtObject::RegistryKey { path: path.clone() },
        NtObject::Pipe {
            buffer,
            is_server,
            io_completion,
        } => {
            buffer.increment(*is_server); // bump reference count for duplicated handle
            NtObject::Pipe {
                buffer: Arc::clone(buffer),
                is_server: *is_server,
                io_completion: io_completion.clone(),
            }
        }
        NtObject::Process { state } => NtObject::Process {
            state: Arc::clone(state),
        },
        NtObject::VirtualThread { process } => NtObject::VirtualThread {
            process: Arc::clone(process),
        },
        NtObject::PipeRootDevice => NtObject::PipeRootDevice,
        NtObject::PhantomExe { path } => NtObject::PhantomExe { path: path.clone() },
        NtObject::JobObject => NtObject::JobObject,
        NtObject::Timer2(t) => NtObject::Timer2(Arc::clone(t)),
        NtObject::WorkerFactory(f) => NtObject::WorkerFactory(Arc::clone(f)),
    })
}

impl<FS: crate::NtShimFS> HandleTable<FS> {
    /// Create a new empty handle table backed by the given `LiteBox`.
    pub fn new(litebox: LiteBox<Platform>) -> Self {
        Self {
            raw_store: RawDescriptorStorage::new(),
            next_handle: FIRST_HANDLE,
            litebox,
            _fs: core::marker::PhantomData,
        }
    }

    /// Create a handle table pre-populated with standard console handles.
    ///
    /// Returns (table, stdin_handle, stdout_handle, stderr_handle).
    pub fn with_stdio(litebox: LiteBox<Platform>) -> (Self, u32, u32, u32) {
        let mut table = Self::new(litebox);
        let stdin = table.insert(NtObject::ConsoleInput);
        let stdout = table.insert(NtObject::ConsoleOutput { is_stderr: false });
        let stderr = table.insert(NtObject::ConsoleOutput { is_stderr: true });
        (table, stdin, stdout, stderr)
    }

    /// Allocate a new handle for the given object.
    ///
    /// Inserts the object into the shared `Descriptors` table and maps the
    /// new handle value in the local `RawDescriptorStorage`.
    pub fn insert(&mut self, object: NtObject<FS>) -> u32 {
        let handle = self.next_handle;
        self.next_handle += HANDLE_STEP;

        // Insert into the shared descriptor table.
        let entry = NtObjectEntry { object };
        let typed_fd = self
            .litebox
            .descriptor_table_mut()
            .insert::<NtObjectSubsystem<FS>>(entry);

        // Map the handle value to the typed fd.
        let ok = self
            .raw_store
            .fd_into_specific_raw_integer(typed_fd, handle as usize);
        assert!(ok, "handle slot {handle} should be free");

        handle
    }

    /// Get the typed fd for a handle value.
    ///
    /// Returns `None` if the handle doesn't exist. Masks off the low 2 flag
    /// bits (protect-from-close / inherit) before lookup.
    pub fn get_fd(&self, handle: u32) -> Option<Arc<NtObjectFd<FS>>> {
        let slot = (handle & !3u32) as usize;
        self.raw_store
            .fd_from_raw_integer::<NtObjectSubsystem<FS>>(slot)
            .ok()
    }

    /// Access an object by handle (read-only).
    ///
    /// The closure receives `&NtObjectEntry` (which contains `&NtObject`).
    /// Returns `None` if the handle doesn't exist.
    pub fn with<F, R>(&self, handle: u32, f: F) -> Option<R>
    where
        F: FnOnce(&NtObjectEntry<FS>) -> R,
    {
        let fd = self.get_fd(handle)?;
        self.litebox
            .descriptor_table()
            .with_entry::<NtObjectSubsystem<FS>, _, _>(&fd, f)
    }

    /// Access an object by handle (mutable).
    ///
    /// The closure receives `&mut NtObjectEntry` (which contains `&mut NtObject`).
    /// Returns `None` if the handle doesn't exist.
    pub fn with_mut<F, R>(&self, handle: u32, f: F) -> Option<R>
    where
        F: FnOnce(&mut NtObjectEntry<FS>) -> R,
    {
        let fd = self.get_fd(handle)?;
        self.litebox
            .descriptor_table()
            .with_entry_mut::<NtObjectSubsystem<FS>, _, _>(&fd, f)
    }

    /// Close a handle, removing the object from the descriptor table.
    ///
    /// Calls `on_close()` (inside `Descriptors::remove()` while the write lock
    /// is held) for lock-free cleanup (pipe refcounts), then calls
    /// `cleanup_after_close()` after the lock is released for operations that
    /// need to re-acquire the lock (fs.close, net.close).
    ///
    /// Returns `true` if the handle existed and was closed, `false` otherwise.
    pub fn close(&mut self, handle: u32) -> bool {
        let slot = (handle & !3u32) as usize;
        let fd = match self
            .raw_store
            .fd_consume_raw_integer::<NtObjectSubsystem<FS>>(slot)
        {
            Ok(fd) => fd,
            Err(_) => return false,
        };
        // remove() fires on_close() inside the write lock (pipe atomics + wakes).
        let entry = self
            .litebox
            .descriptor_table_mut()
            .remove::<NtObjectSubsystem<FS>>(&fd);
        // cleanup_after_close() runs outside the lock (fs.close, net.close).
        if let Some(entry) = entry {
            entry.cleanup_after_close();
        }
        true
    }

    /// Returns true if the handle exists in the table.
    pub fn contains(&self, handle: u32) -> bool {
        self.raw_store.is_alive(handle as usize)
    }

    /// Duplicate a handle, creating a new handle table entry pointing to
    /// the same underlying object. For VFS File objects, the `Arc` position
    /// and refcount are shared so both handles see the same file state.
    /// Returns the new handle, or `None` if the source doesn't exist or
    /// the object cannot be duplicated.
    pub fn duplicate(&mut self, source: u32) -> Option<u32> {
        // Extract a clone of the NtObject via with().
        let new_obj = self.with(source, |entry| clone_nt_object(&entry.object))??;
        Some(self.insert(new_obj))
    }

    /// Returns all active handles (for debugging).
    pub fn handles(&self) -> Vec<u32> {
        self.raw_store
            .iter_alive()
            .map(|slot| slot as u32)
            .collect()
    }

    /// Iterate all live handles, calling `f` for each.
    pub fn for_each<F>(&self, mut f: F)
    where
        F: FnMut(u32, &NtObjectEntry<FS>),
    {
        for slot in self.raw_store.iter_alive() {
            let handle = slot as u32;
            let fd = self.get_fd(handle);
            if let Some(fd) = fd {
                self.litebox
                    .descriptor_table()
                    .with_entry::<NtObjectSubsystem<FS>, _, _>(&fd, |entry| {
                        f(handle, entry);
                    });
            }
        }
    }

    /// Close all handles in the table.
    ///
    /// Called during process cleanup (child exit). Closes every handle via
    /// `close()`, which fires `on_close()` (pipe refcount atomics + wake
    /// signals) and `cleanup_after_close()` (fs.close, net.close) for each.
    ///
    /// This matches real Windows behavior: on process exit, all handles are
    /// closed — not just pipes but also files, sockets, events, etc.
    pub fn close_all(&mut self) {
        let all_handles: Vec<u32> = self
            .raw_store
            .iter_alive()
            .map(|slot| slot as u32)
            .collect();
        for handle in all_handles {
            self.close(handle);
        }
    }
}

// No Default impl — HandleTable requires a LiteBox instance.

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    fn init_platform() {
        static PLATFORM_INIT: std::sync::Once = std::sync::Once::new();
        PLATFORM_INIT.call_once(|| {
            litebox_platform_multiplex::set_platform(Platform::new(None));
        });
    }

    fn make_litebox() -> LiteBox<Platform> {
        init_platform();
        LiteBox::new(litebox_platform_multiplex::platform())
    }

    #[test]
    fn basic_handle_operations() {
        let mut table = HandleTable::new(make_litebox());

        let h1 = table.insert(NtObject::ConsoleInput);
        let h2 = table.insert(NtObject::ConsoleOutput { is_stderr: false });

        assert_eq!(h1, 4);
        assert_eq!(h2, 8);

        assert!(table.with(h1, |_| ()).is_some());
        assert!(table.with(h2, |_| ()).is_some());
        assert!(table.with(99, |_| ()).is_none());

        let removed = table.close(h1);
        assert!(removed.is_some());
        assert!(table.with(h1, |_| ()).is_none());
    }

    #[test]
    fn stdio_handles() {
        let (table, stdin, stdout, stderr) = HandleTable::with_stdio(make_litebox());

        assert!(table
            .with(stdin, |e| matches!(e.object, NtObject::ConsoleInput))
            .unwrap_or(false));
        assert!(table
            .with(stdout, |e| matches!(
                e.object,
                NtObject::ConsoleOutput { is_stderr: false }
            ))
            .unwrap_or(false));
        assert!(table
            .with(stderr, |e| matches!(
                e.object,
                NtObject::ConsoleOutput { is_stderr: true }
            ))
            .unwrap_or(false));
    }

    #[test]
    fn alert_by_thread_id_wakes_wait_for_alert() {
        let thread = ThreadObject::new(100, 0, 0);

        // NtAlertThreadByThreadId sets pending_by_thread_id.
        thread.alert_by_id(true, 0);

        assert!(thread.take_pending_alert_by_id(0x1234));
        assert!(!thread.take_pending_alert_by_id(0x1234));
    }

    #[test]
    fn alert_by_thread_id_does_not_wake_alertable_wait() {
        // NtAlertThreadByThreadId/Ex is a separate mechanism from NtAlertThread.
        // It should NOT interrupt alertable waits.
        let thread = ThreadObject::new(100, 0, 0);

        thread.alert_by_id(true, 0);

        assert!(!thread.take_pending_alert());
        // But it does satisfy NtWaitForAlertByThreadId.
        assert!(thread.take_pending_alert_by_id(0));
    }

    #[test]
    fn plain_alert_wakes_both_mechanisms() {
        // Process-exit alert_by_id(false) sets both pending_any and
        // pending_by_thread_id. Both mechanisms are independently satisfied.
        let thread = ThreadObject::new(100, 0, 0);

        thread.alert_by_id(false, 0);

        // pending_by_thread_id satisfies NtWaitForAlertByThreadId.
        assert!(thread.take_pending_alert_by_id(0x1234));
        // pending_any satisfies alertable waits.
        assert!(thread.take_pending_alert());
    }

    #[test]
    fn plain_alert_consumed_by_alertable_wait() {
        let thread = ThreadObject::new(100, 0, 0);

        thread.alert_by_id(false, 0);

        // Consume pending_any first via alertable wait.
        assert!(thread.take_pending_alert());
        // pending_by_thread_id still available for NtWaitForAlertByThreadId.
        assert!(thread.take_pending_alert_by_id(0));
    }

    #[test]
    fn both_alert_types_pending_independently() {
        let thread = ThreadObject::new(100, 0, 0);

        thread.alert_by_id(true, 0); // pending_by_thread_id
        thread.alert_by_id(false, 0); // pending_any + pending_by_thread_id (already set)

        // Consume pending_by_thread_id first.
        assert!(thread.take_pending_alert_by_id(0x1234));
        // pending_any still available for alertable wait.
        assert!(thread.take_pending_alert());
        // Both consumed.
        assert!(!thread.take_pending_alert_by_id(0));
        assert!(!thread.take_pending_alert());
    }

    #[test]
    fn post_plain_alert_does_not_wake_wait_for_alert_by_id() {
        // NtAlertResumeThread uses post_plain_alert(), which should only
        // satisfy alertable waits, NOT NtWaitForAlertByThreadId.
        let thread = ThreadObject::new(100, 0, 0);

        thread.post_plain_alert();

        // pending_any does NOT satisfy NtWaitForAlertByThreadId.
        assert!(!thread.take_pending_alert_by_id(0));
        // But it does satisfy alertable waits.
        assert!(thread.take_pending_alert());
    }

    #[test]
    fn alert_by_thread_id_address_is_not_matched() {
        // The address parameter is informational; any address satisfies the wait.
        let thread = ThreadObject::new(100, 0, 0);

        thread.alert_by_id(true, 0);

        // Different address still matches.
        assert!(thread.take_pending_alert_by_id(0xDEAD));
    }
}
