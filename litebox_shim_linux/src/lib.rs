// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A shim that provides a Linux-compatible ABI via LiteBox.
//!
//! This shim is parametric in the choice of [LiteBox platform](../litebox/platform/index.html),
//! chosen by the [platform multiplex](../litebox_platform_multiplex/index.html).

#![no_std]
#![expect(
    clippy::unused_self,
    reason = "by convention, syscalls and related methods take &self even if unused"
)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use alloc::sync::Arc;
use core::cell::{Cell, RefCell};
use litebox::{
    fd::TypedFd,
    mm::{PageManager, linux::PAGE_SIZE},
    net::Network,
    pipes::Pipes,
    platform::{RawConstPointer as _, RawMutPointer as _, TimeProvider},
    shim::ContinueOperation,
    sync::futex::FutexManager,
    utils::{ReinterpretSignedExt as _, ReinterpretUnsignedExt as _},
};
use litebox_common_linux::{SyscallRequest, errno::Errno};
use litebox_platform_multiplex::Platform;

/// On debug builds, logs that the user attempted to use an unsupported feature.
// DEVNOTE: this is before the `mod` declarations so that it can be used within them.
macro_rules! log_unsupported {
    ($($arg:tt)*) => {
        $crate::log_unsupported_fmt(core::format_args!($($arg)*));
    };
}

pub(crate) mod channel;
pub mod loader;
pub(crate) mod stdio;
pub mod syscalls;
pub mod transport;
mod wait;

use crate::syscalls::file::get_file_descriptor_flags;

pub type DefaultFS = LinuxFS;

pub(crate) type LinuxFS = litebox::fs::layered::FileSystem<
    Platform,
    litebox::fs::in_mem::FileSystem<Platform>,
    litebox::fs::layered::FileSystem<
        Platform,
        litebox::fs::devices::FileSystem<Platform>,
        litebox::fs::tar_ro::FileSystem<Platform>,
    >,
>;

pub(crate) type FileFd<FS> = litebox::fd::TypedFd<FS>;

/// A trait required for file systems to be used in the shim.
pub trait ShimFS: litebox::fs::FileSystem<Platform = Platform> + Send + Sync + 'static {}
impl<T: litebox::fs::FileSystem<Platform = Platform> + Send + Sync + 'static> ShimFS for T {}

/// On debug builds, logs that the user attempted to use an unsupported feature.
fn log_unsupported_fmt(args: core::fmt::Arguments<'_>) {
    use litebox::platform::DebugLogProvider as _;

    if cfg!(debug_assertions) {
        let msg = alloc::format!("WARNING: unsupported: {args}\n");
        litebox_platform_multiplex::platform().debug_log_print(&msg);
    }
}

pub struct LinuxShimEntrypoints<FS: ShimFS> {
    task: Task<FS>,
    // The task should not be moved once it's bound to a platform thread so that
    // we preserve the ability to use TLS in the future.
    _not_send: core::marker::PhantomData<*const ()>,
}

impl<FS: ShimFS> litebox::shim::EnterShim for LinuxShimEntrypoints<FS> {
    type ExecutionContext = litebox_common_linux::PtRegs;

    fn init(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.enter_shim(true, ctx, Task::handle_init_request)
    }

    fn syscall(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.enter_shim(false, ctx, Task::handle_syscall_request)
    }

    fn exception(
        &self,
        ctx: &mut Self::ExecutionContext,
        info: &litebox::shim::ExceptionInfo,
    ) -> ContinueOperation {
        if info.kernel_mode && info.exception == litebox::shim::Exception::PAGE_FAULT {
            if unsafe {
                self.task
                    .pm
                    .handle_page_fault(info.cr2, info.error_code.into())
            }
            .is_ok()
            {
                return ContinueOperation::Resume;
            } else {
                return ContinueOperation::Terminate;
            }
        }
        self.enter_shim(false, ctx, |task, _ctx| task.handle_exception_request(info))
    }

    fn interrupt(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.enter_shim(false, ctx, |_, _| {})
    }
}

impl<FS: ShimFS> LinuxShimEntrypoints<FS> {
    fn enter_shim(
        &self,
        is_init: bool,
        ctx: &mut litebox_common_linux::PtRegs,
        f: impl FnOnce(&Task<FS>, &mut litebox_common_linux::PtRegs),
    ) -> ContinueOperation {
        if !is_init {
            self.task.enter_from_guest();
        }
        f(&self.task, ctx);
        if self.task.prepare_to_run_guest(ctx) {
            ContinueOperation::Resume
        } else {
            ContinueOperation::Terminate
        }
    }
}

/// The shim entry point structure.
pub struct LinuxShimBuilder {
    platform: &'static Platform,
    load_filter: Option<LoadFilter>,
}

impl Default for LinuxShimBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxShimBuilder {
    /// Returns a new shim builder.
    pub fn new() -> Self {
        let platform = litebox_platform_multiplex::platform();
        Self {
            platform,
            load_filter: None,
        }
    }


    /// Returns the platform instance.
    pub fn platform(&self) -> &'static Platform {
        self.platform
    }

    /// Create a default layered file system with the given in-memory and tar read-only layers.
    pub fn default_fs(
        &self,
        dt: &litebox::fd::DescriptorTable<Platform>,
        in_mem_fs: litebox::fs::in_mem::FileSystem<Platform>,
        tar_ro_fs: litebox::fs::tar_ro::FileSystem<Platform>,
    ) -> DefaultFS {
        default_fs(dt, self.platform, in_mem_fs, tar_ro_fs)
    }

    /// Set the load filter, which can augment envp or auxv when starting a new program.
    pub fn set_load_filter(&mut self, callback: LoadFilter) {
        self.load_filter = Some(callback);
    }

    /// Build the shim.
    pub fn build<FS: ShimFS>(self) -> LinuxShim<FS> {
        let root_dt = litebox::fd::new_descriptor_table();
        let mut net = Network::new(self.platform, &root_dt);
        net.set_platform_interaction(litebox::net::PlatformInteraction::Manual);
        let root_net = Arc::new(litebox::sync::Mutex::new(net));
        let global = Arc::new(GlobalState {
            platform: self.platform,
            futex_manager: FutexManager::new(),
            pipes: Pipes::new(),
            boot_time: self.platform.now(),
            load_filter: self.load_filter,
            next_thread_id: 2.into(), // start from 2, as 1 is used by the main thread
            unix_addr_table: litebox::sync::RwLock::new(syscalls::unix::UnixAddrTable::new()),
        });
        LinuxShim { global, root_dt, root_net }
    }
}

pub struct LinuxShim<FS: ShimFS> {
    global: Arc<GlobalState<FS>>,
    /// The root process's descriptor table.
    root_dt: litebox::fd::DescriptorTable<Platform>,
    /// The root process's Network. The single net-worker in main.rs drives
    /// this via [`Self::perform_network_interaction`].
    root_net: Arc<litebox::sync::Mutex<Platform, Network<Platform>>>,
}
impl<FS: ShimFS> Clone for LinuxShim<FS> {
    fn clone(&self) -> Self {
        Self {
            global: self.global.clone(),
            root_dt: self.root_dt.clone(),
            root_net: self.root_net.clone(),
        }
    }
}

impl<FS: ShimFS> LinuxShim<FS> {
    /// Loads the program at `path` as the shim's initial task, returning the
    /// initial register state.
    pub fn load_program(
        &self,
        fs: alloc::sync::Arc<FS>,
        task: litebox_common_linux::TaskParams,
        path: &str,
        argv: Vec<alloc::ffi::CString>,
        envp: Vec<alloc::ffi::CString>,
    ) -> Result<LoadedProgram<FS>, loader::elf::ElfLoaderError> {
        let litebox_common_linux::TaskParams {
            pid,
            ppid,
            uid,
            euid,
            gid,
            egid,
        } = task;

        let files = syscalls::file::FilesState::new(litebox::fd::new_descriptor_table(), fs);
        files.set_max_fd(syscalls::process::RLIMIT_NOFILE_CUR - 1);
        let files = Arc::new(files);
        files.initialize_stdio_in_shared_descriptors_table(&self.global);

        let entrypoints = crate::LinuxShimEntrypoints {
            _not_send: core::marker::PhantomData,
            task: Task {
                global: self.global.clone(),
                pm: alloc::sync::Arc::new(PageManager::new(self.global.platform)),
                net: self.root_net.clone(),
                thread: syscalls::process::ThreadState::new_process(pid),
                wait_state: wait::WaitState::new(self.global.platform),
                pid,
                ppid,
                tid: pid,
                credentials: syscalls::process::Credentials {
                    uid,
                    euid,
                    gid,
                    egid,
                }
                .into(),
                comm: [0; litebox_common_linux::TASK_COMM_LEN].into(), // set at load time
                fs: Arc::new(syscalls::file::FsState::new()).into(),
                files: files.into(),
                signals: syscalls::signal::SignalState::new_process(),
            },
        };
        entrypoints.task.load_program(
            loader::elf::ElfLoader::new(&entrypoints.task, path)?,
            argv,
            envp,
        )?;
        let process = LinuxShimProcess(entrypoints.task.process().clone());
        Ok(LoadedProgram {
            entrypoints,
            process,
        })
    }

    // page_manager() moved to LinuxShimTask





    /// Perform queued network interactions with the outside world.
    ///
    /// Drives the root process's Network. This function should be invoked in
    /// a loop, based on the returned advice.
    pub fn perform_network_interaction(
        &self,
    ) -> litebox::net::PlatformInteractionReinvocationAdvice {
        self.root_net.lock().perform_platform_interaction()
    }

    /// Establish a TCP connection to the given address.
    ///
    /// Returns a [`transport::ShimTransport`] that can be used as a
    /// byte-stream transport (e.g., for a 9P filesystem client).
    pub fn tcp_connection(
        &self,
        addr: core::net::SocketAddr,
    ) -> Result<transport::ShimTransport, Errno> {
        transport::ShimTransport::connect(self.global.clone(), &self.root_dt, self.root_net.clone(), addr)
    }

    /// Returns the platform instance.
    pub fn platform(&self) -> &'static Platform {
        self.global.platform
    }
}

pub struct LoadedProgram<FS: ShimFS> {
    pub entrypoints: LinuxShimEntrypoints<FS>,
    pub process: LinuxShimProcess,
}

/// A handle to a process loaded via [`LinuxShim::load_program`].
///
/// This can be used to wait for the process to exit.
pub struct LinuxShimProcess(Arc<syscalls::process::Process>);

impl LinuxShimProcess {
    /// Wait for the process to exit, returning its exit code.
    pub fn wait(&self) -> i32 {
        match self.0.wait_for_exit() {
            syscalls::process::ExitStatus::Exit(v) => v.into(),
            // TODO: return the enum instead of just a code?
            syscalls::process::ExitStatus::Signal(signal) => signal.as_i32() + 256,
        }
    }
}

/// A headless task handle for dispatching syscalls without loading an ELF
/// binary. Used by `litebox_central` to process syscall requests received
/// over IPC.
pub struct LinuxShimTask<FS: ShimFS> {
    task: Task<FS>,
}

impl<FS: ShimFS> LinuxShimTask<FS> {
    /// Dispatch a single syscall described by the given register context.
    ///
    /// Returns the raw syscall result: non-negative on success, negative
    /// `-errno` on failure.
    #[allow(clippy::cast_possible_wrap)] // syscall return values fit in i64
    pub fn dispatch_syscall(&self, ctx: &mut litebox_common_linux::PtRegs) -> i64 {
        match self.task.do_syscall(ctx) {
            Ok(v) => v as i64,
            Err(e) => i64::from(e.as_neg()),
        }
    }

    /// Returns true if the task's process has started exiting
    /// (e.g. after exit_group was called).
    pub fn is_exiting(&self) -> bool {
        self.task.is_exiting()
    }

    /// Create a new task handle for a child thread.
    ///
    /// Performs the same bookkeeping as `do_clone` (allocate TID, create
    /// `ThreadState`, attach to `Process`) but does **not** spawn a platform
    /// thread.  Returns `(child_tid, child_task)` on success.
    pub fn create_thread_task(&self) -> Result<(i32, Self), litebox_common_linux::errno::Errno> {
        let child_tid = self
            .task
            .global
            .next_thread_id
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        let thread = self
            .task
            .thread
            .new_thread(child_tid)
            .ok_or(litebox_common_linux::errno::Errno::EBUSY)?;

        let child_task = LinuxShimTask {
            task: Task {
                global: self.task.global.clone(),
                pm: self.task.pm.clone(), // Arc clone: threads share the same address space
                net: self.task.net.clone(),
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

    /// Set the initial program break address in the PageManager.
    ///
    /// Must be called once before the first `brk()` syscall. Panics if
    /// called after brk is already initialized.
    pub fn set_initial_brk(&self, brk: usize) {
        self.task.pm.set_initial_brk(brk);
    }

    /// Get the per-process page manager.
    pub fn page_manager(&self) -> &PageManager<Platform, PAGE_SIZE> {
        &self.task.pm
    }

    /// Return the process ID of this task.
    pub fn pid(&self) -> i32 {
        self.task.pid
    }

    /// Perform queued network interactions for this task's process Network.
    ///
    /// This function should be invoked in a loop, based on the returned advice.
    pub fn perform_network_interaction(
        &self,
    ) -> litebox::net::PlatformInteractionReinvocationAdvice {
        self.task.net.lock().perform_platform_interaction()
    }

    /// Return a clone of this task's per-process `Network` Arc.
    ///
    /// Used by `litebox_central`'s per-process net-worker thread, which needs
    /// to call `perform_platform_interaction()` without borrowing the task.
    pub fn net_mutex(&self) -> Arc<litebox::sync::Mutex<Platform, Network<Platform>>> {
        self.task.net.clone()
    }
}

impl<FS: ShimFS> LinuxShim<FS> {
    /// Create a headless task that can process syscalls without loading a
    /// guest ELF binary.
    ///
    /// This is the entry point for `litebox_central`: it creates a [`Task`]
    /// backed by the shim's [`GlobalState`] and the given filesystem, ready
    /// to receive [`dispatch_syscall`](LinuxShimTask::dispatch_syscall) calls.
    ///
    /// When `init_stdio` is `true`, fd 0/1/2 are mapped to `/dev/stdin`,
    /// `/dev/stdout`, `/dev/stderr` in the shared descriptor table. Set this
    /// to `false` for fork children whose stdio fds are real OS pipes — the
    /// shim will return EBADF for unknown fds, and central will fall back to
    /// `EXEC_LOCAL` so micro reads/writes the pipe directly.
    pub fn create_task(
        &self,
        fs: alloc::sync::Arc<FS>,
        params: litebox_common_linux::TaskParams,
        init_stdio: bool,
    ) -> LinuxShimTask<FS> {
        let files = Arc::new(syscalls::file::FilesState::new(litebox::fd::new_descriptor_table(), fs));
        files.set_max_fd(syscalls::process::RLIMIT_NOFILE_CUR - 1);
        if init_stdio {
            files.initialize_stdio_in_shared_descriptors_table(&self.global);
        } else {
            // For fork children, reserve fd 0/1/2 so the shim allocates new
            // descriptors starting at fd 3. Reads/writes on 0/1/2 will return
            // EBADF (not in shim's table), triggering EXEC_LOCAL fallback in
            // central so micro handles the real OS pipes.
            files.set_min_alloc_fd(3);
        }

        LinuxShimTask {
            task: Task {
                global: self.global.clone(),
                pm: alloc::sync::Arc::new(PageManager::new(self.global.platform)),
                net: self.root_net.clone(),
                thread: syscalls::process::ThreadState::new_process(params.pid),
                wait_state: wait::WaitState::new(self.global.platform),
                pid: params.pid,
                ppid: params.ppid,
                tid: params.pid,
                credentials: syscalls::process::Credentials {
                    uid: params.uid,
                    euid: params.euid,
                    gid: params.gid,
                    egid: params.egid,
                }
                .into(),
                comm: Cell::new([0; litebox_common_linux::TASK_COMM_LEN]),
                fs: Arc::new(syscalls::file::FsState::new()).into(),
                files: files.into(),
                signals: syscalls::signal::SignalState::new_process(),
            },
        }
    }

    /// Create a child task for a fork, inheriting the parent's file
    /// descriptors and current working directory.
    ///
    /// Unlike [`Self::create_task`], this duplicates every open fd from
    /// `parent_task` into the child's descriptor table, so that the child
    /// sees the same virtual fd numbers (including redirected stdin/stdout).
    ///
    /// # Panics
    ///
    /// Panics if listening socket re-creation or fd remapping fails during
    /// fork (these indicate internal bugs in the fork logic).
    pub fn fork_task(
        &self,
        _fs: alloc::sync::Arc<FS>,
        params: litebox_common_linux::TaskParams,
        parent_task: &LinuxShimTask<FS>,
    ) -> LinuxShimTask<FS> {
        let parent_files = parent_task.task.files.borrow();
        let files = parent_files.fork_files_state(&self.global);
        files.set_max_fd(syscalls::process::RLIMIT_NOFILE_CUR - 1);

        // Inherit the parent's current working directory and umask.
        let parent_fs = parent_task.task.fs.borrow();
        let child_fs_state: Arc<syscalls::file::FsState> = Arc::new((*parent_fs).as_ref().clone());

        // Each forked process gets its own fresh Network instance.
        let mut child_net = Network::new(self.global.platform, &files.dt);
        child_net.set_platform_interaction(litebox::net::PlatformInteraction::Manual);

        // Re-create listening sockets from the parent's Network into the child's
        // fresh Network, so that inherited listening fds actually work.
        {
            // Step 1: Export listening socket state from the parent's Network.
            // `listening_tcp_sockets()` filters by network_id, so it only
            // returns sockets owned by the parent (not other children).
            let parent_net_guard = parent_task.task.net.lock();
            let listeners = parent_net_guard.listening_tcp_sockets();

            // Step 2: Walk the child's raw fd table to find network fds that
            // correspond to listening sockets. We use the parent's Network
            // to check since both share the same descriptor table entries.
            let mut listening_raw_fds: Vec<(usize, u16)> = Vec::new();
            if !listeners.is_empty() {
                let alive_fds: Vec<usize> =
                    files.raw_descriptor_store.read().iter_alive().collect();
                let rds = files.raw_descriptor_store.read();
                for raw_fd in &alive_fds {
                    let Ok(net_fd) = rds.fd_from_raw_integer::<Network<Platform>>(*raw_fd) else {
                        continue;
                    };
                    if let Some(port) = parent_net_guard.listening_port(&net_fd) {
                        listening_raw_fds.push((*raw_fd, port));
                    }
                }
            }

            // Release the parent lock before mutating the child.
            drop(parent_net_guard);

            if !listening_raw_fds.is_empty() {
                // Step 3: Import listeners into the child's Network (creates new
                // smoltcp sockets, binds, and listens).
                let imported = child_net.import_listening_sockets(&listeners);

                // Step 4: Remap each listening raw fd to point to the new
                // child-owned descriptor table entry.
                for (raw_fd, port) in &listening_raw_fds {
                    // Find the matching imported fd by port.
                    let Some((_port, new_fd)) = imported.iter().find(|(p, _)| p == port) else {
                        continue;
                    };

                    // Read parent's metadata from the old fd BEFORE consuming it.
                    let (parent_sock_opts, parent_sock_type, parent_oflags, parent_cloexec) = {
                        let rds = files.raw_descriptor_store.read();
                        let old_net_fd = rds
                            .fd_from_raw_integer::<Network<Platform>>(*raw_fd)
                            .expect("raw fd should still be alive");
                        let dt = files.dt.read();
                        let sock_opts = dt
                            .with_metadata(
                                old_net_fd.as_ref(),
                                |o: &syscalls::net::SocketOptions| o.clone(),
                            )
                            .unwrap_or_default();
                        let sock_type = dt
                            .with_metadata(
                                old_net_fd.as_ref(),
                                |t: &litebox_common_linux::SockType| *t,
                            )
                            .unwrap_or(litebox_common_linux::SockType::Stream);
                        let oflags = dt
                            .with_metadata(
                                old_net_fd.as_ref(),
                                |f: &syscalls::net::SocketOFlags| *f,
                            )
                            .unwrap_or(syscalls::net::SocketOFlags(litebox::fs::OFlags::RDWR));
                        let cloexec = dt
                            .with_metadata(
                                old_net_fd.as_ref(),
                                |flags: &litebox_common_linux::FileDescriptorFlags| *flags,
                            )
                            .unwrap_or(litebox_common_linux::FileDescriptorFlags::empty());
                        (sock_opts, sock_type, oflags, cloexec)
                    };

                    // Set up metadata on the new fd (using parent's values).
                    {
                        let dt = files.dt.read();
                        let _old = dt.set_entry_metadata(new_fd, parent_sock_opts);
                        let _old = dt.set_entry_metadata(new_fd, parent_sock_type);
                        let _old = dt.set_entry_metadata(new_fd, parent_oflags);
                    }

                    // Create and set a new proxy for the child's socket.
                    let proxy = Arc::new(litebox::net::socket_channel::NetworkProxy::Stream(
                        litebox::net::socket_channel::StreamSocketChannel::new(),
                    ));
                    {
                        let dt = files.dt.read();
                        let _old = dt
                            .set_entry_metadata(new_fd, syscalls::net::SocketProxy(proxy.clone()));
                    }
                    let proxy_set = child_net.set_socket_proxy(new_fd, proxy.clone());
                    assert!(proxy_set, "failed to set proxy on imported socket");

                    // The proxy was created with default state (Closed), but the
                    // socket is already listening.  Without this, check_io_events()
                    // returns HUP (always-polled), causing epoll_wait to return
                    // immediately in an infinite spin loop.
                    proxy.set_state(litebox::net::socket_channel::SocketState::Listening);

                    // Replace the child's raw fd entry: consume the old
                    // (parent-shared) fd and insert the new (child-owned) one.
                    // Duplicate first (needs descriptor_table_mut), then swap
                    // in the raw descriptor store.
                    let dup_fd = files.dt.write()
                        .duplicate(new_fd)
                        .expect("new fd should be valid");

                    // Set FD_CLOEXEC on the dup_fd (not new_fd), since
                    // duplicate() creates entries with empty metadata.
                    if parent_cloexec
                        .contains(litebox_common_linux::FileDescriptorFlags::FD_CLOEXEC)
                    {
                        let dt = files.dt.read();
                        let _old = dt.set_fd_metadata(
                            &dup_fd,
                            litebox_common_linux::FileDescriptorFlags::FD_CLOEXEC,
                        );
                    }

                    let mut rds = files.raw_descriptor_store.write();
                    let _old_fd = rds
                        .fd_consume_raw_integer::<Network<Platform>>(*raw_fd)
                        .expect("raw fd should still be alive");
                    let success = rds.fd_into_specific_raw_integer(dup_fd, *raw_fd);
                    assert!(
                        success,
                        "child raw fd {raw_fd} should be free after consume"
                    );
                    drop(rds);
                }

                // Step 5: Clean up the original fds from import_listening_sockets().
                // They have been duplicated into the raw fd table, so we remove them
                // from the descriptor table to avoid leaking OwnedFds.
                {
                    let mut dt = files.dt.write();
                    for (_port, fd) in &imported {
                        let _ = dt.remove::<Network<Platform>>(fd);
                    }
                }
            }
        }

        let child_net = Arc::new(litebox::sync::Mutex::new(child_net));

        // Clone the parent's PageManager so the child gets an independent copy
        // of the virtual memory area map — just like Linux's fork() copies
        // the mm_struct. This prevents the child's execve (which calls
        // release_memory) from destroying the parent's mapping metadata.
        let child_pm = alloc::sync::Arc::new(parent_task.task.pm.clone_for_fork());

        LinuxShimTask {
            task: Task {
                global: self.global.clone(),
                pm: child_pm,
                net: child_net,
                thread: syscalls::process::ThreadState::new_process(params.pid),
                wait_state: wait::WaitState::new(self.global.platform),
                pid: params.pid,
                ppid: params.ppid,
                tid: params.pid,
                credentials: syscalls::process::Credentials {
                    uid: params.uid,
                    euid: params.euid,
                    gid: params.gid,
                    egid: params.egid,
                }
                .into(),
                comm: Cell::new([0; litebox_common_linux::TASK_COMM_LEN]),
                fs: child_fs_state.into(),
                files: files.into(),
                signals: parent_task.task.signals.clone_for_fork(),
            },
        }
    }
}

/// Create a default layered file system with the given in-memory and tar read-only layers.
fn default_fs(
    _dt: &litebox::fd::DescriptorTable<Platform>,
    platform: &'static Platform,
    in_mem_fs: litebox::fs::in_mem::FileSystem<Platform>,
    tar_ro_fs: litebox::fs::tar_ro::FileSystem<Platform>,
) -> LinuxFS {
    let dev_stdio = litebox::fs::devices::FileSystem::new(platform);
    litebox::fs::layered::FileSystem::new(
        in_mem_fs,
        litebox::fs::layered::FileSystem::new(
            dev_stdio,
            tar_ro_fs,
            litebox::fs::layered::LayeringSemantics::LowerLayerReadOnly,
        ),
        litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
    )
}

// Special override so that `GETFL` can return stdio-specific flags
pub(crate) struct StdioStatusFlags(litebox::fs::OFlags);

/// Status flags for pipes
pub(crate) struct PipeStatusFlags(pub litebox::fs::OFlags);

impl<FS: ShimFS> syscalls::file::FilesState<FS> {
    fn initialize_stdio_in_shared_descriptors_table(&self, _global: &GlobalState<FS>) {
        use litebox::fs::{Mode, OFlags};
        let stdin = self
            .fs
            .open(&self.dt, "/dev/stdin", OFlags::RDONLY, Mode::empty())
            .unwrap();
        let stdout = self
            .fs
            .open(&self.dt, "/dev/stdout", OFlags::WRONLY, Mode::empty())
            .unwrap();
        let stderr = self
            .fs
            .open(&self.dt, "/dev/stderr", OFlags::WRONLY, Mode::empty())
            .unwrap();
        let dt = self.dt.read();
        let mut rds = self.raw_descriptor_store.write();
        for (raw_fd, fd) in [(0, stdin), (1, stdout), (2, stderr)] {
            let status_flags = OFlags::APPEND | OFlags::RDWR;
            debug_assert_eq!(OFlags::STATUS_FLAGS_MASK & status_flags, status_flags);
            let old = dt.set_entry_metadata(&fd, StdioStatusFlags(status_flags));
            assert!(old.is_none());
            let success = rds.fd_into_specific_raw_integer(fd, raw_fd);
            assert!(success);
        }
    }
}

// Convenience type aliases
type ConstPtr<T> = <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<T>;
type MutPtr<T> = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<T>;

impl<FS: ShimFS> Task<FS> {
    fn close_on_exec(&self) {
        let files = self.files.borrow();
        let alive_fds: Vec<usize> = files.raw_descriptor_store.read().iter_alive().collect();
        for raw_fd in alive_fds {
            if let Ok(flags) = get_file_descriptor_flags(raw_fd, &self.global, &files)
                && flags.contains(litebox_common_linux::FileDescriptorFlags::FD_CLOEXEC)
            {
                let _ = self.do_close(raw_fd);
            }
        }
    }
}

impl<FS: ShimFS> syscalls::file::FilesState<FS> {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn run_on_raw_fd<R>(
        &self,
        fd: usize,
        fs: impl FnOnce(&TypedFd<FS>) -> R,
        net: impl FnOnce(&TypedFd<Network<Platform>>) -> R,
        pipes: impl FnOnce(&TypedFd<Pipes<Platform>>) -> R,
        eventfd: impl FnOnce(&TypedFd<syscalls::eventfd::EventfdSubsystem>) -> R,
        epoll: impl FnOnce(&TypedFd<syscalls::epoll::EpollSubsystem<FS>>) -> R,
        unix: impl FnOnce(&TypedFd<syscalls::unix::UnixSocketSubsystem<FS>>) -> R,
    ) -> Result<R, Errno> {
        let rds = self.raw_descriptor_store.read();
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(fs(&fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(net(&fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(pipes(&fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(eventfd(&fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(epoll(&fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(unix(&fd));
        }
        Err(Errno::EBADF)
    }

    /// Create a new `FilesState` for a fork child, inheriting all open file
    /// descriptors from this (parent) state.
    ///
    /// Each fd is duplicated in the descriptor table (sharing the underlying
    /// entry/offset) and placed at the same raw fd number in the child's
    /// `RawDescriptorStorage`. Per-fd metadata (e.g., `FD_CLOEXEC`) is also
    /// copied.
    pub(crate) fn fork_files_state(
        &self,
        _global: &GlobalState<FS>,
    ) -> Arc<syscalls::file::FilesState<FS>> {
        use litebox::fd::FdEnabledSubsystem;
        use litebox_common_linux::FileDescriptorFlags;

        // Helper: duplicate one fd from parent dt to child dt, preserving
        // per-fd metadata (e.g. FD_CLOEXEC). The underlying entry Arc is
        // shared between parent and child (same as dup within a single table).
        fn dup_one<S: FdEnabledSubsystem>(
            parent_dt: &litebox::fd::DescriptorTable<Platform>,
            child_dt: &litebox::fd::DescriptorTable<Platform>,
            child: &syscalls::file::FilesState<impl ShimFS>,
            parent_fd: &TypedFd<S>,
            raw_fd: usize,
        ) {
            let parent_guard = parent_dt.read();
            let Some(entry_arc) = parent_guard.entry_arc(parent_fd) else {
                return; // fd was closed concurrently
            };
            // Copy FD_CLOEXEC if set on the parent fd.
            let cloexec = parent_guard
                .with_metadata(parent_fd, |flags: &FileDescriptorFlags| *flags)
                .unwrap_or(FileDescriptorFlags::empty());
            drop(parent_guard);

            let mut child_guard = child_dt.write();
            let new_fd: TypedFd<S> = child_guard.insert_shared(entry_arc);
            if cloexec.contains(FileDescriptorFlags::FD_CLOEXEC) {
                let _old = child_guard.set_fd_metadata(&new_fd, FileDescriptorFlags::FD_CLOEXEC);
            }
            drop(child_guard);

            let mut rds = child.raw_descriptor_store.write();
            let success = rds.fd_into_specific_raw_integer(new_fd, raw_fd);
            assert!(success, "child raw fd {raw_fd} already occupied");
        }

        let parent_dt = &self.dt;
        let child = Arc::new(syscalls::file::FilesState::new(litebox::fd::new_descriptor_table(), Arc::clone(&self.fs)));
        let child_dt = &child.dt;

        // Collect alive fds while holding the parent's RDS lock briefly.
        let alive_fds: Vec<usize> = self.raw_descriptor_store.read().iter_alive().collect();

        for raw_fd in alive_fds {
            // Use run_on_raw_fd to dispatch by subsystem type.
            // The FS closure uses reopen_in_fork to create fresh inner fds
            // in the child's descriptor table, avoiding the bug where the
            // layered FS's inner TypedFd<Upper>/TypedFd<Lower> would index
            // into the parent's table after an insert_shared.
            let _ = self.run_on_raw_fd(
                raw_fd,
                |fd| {
                    // Try FS-level reopen first (layered FS needs this).
                    if let Some(new_fd) = self.fs.reopen_in_fork(parent_dt, child_dt, fd) {
                        // Copy FD_CLOEXEC metadata.
                        let cloexec = parent_dt
                            .read()
                            .with_metadata(fd, |flags: &FileDescriptorFlags| *flags)
                            .unwrap_or(FileDescriptorFlags::empty());
                        if cloexec.contains(FileDescriptorFlags::FD_CLOEXEC) {
                            let _old = child_dt.write().set_fd_metadata(&new_fd, FileDescriptorFlags::FD_CLOEXEC);
                        }
                        let mut rds = child.raw_descriptor_store.write();
                        let success = rds.fd_into_specific_raw_integer(new_fd, raw_fd);
                        assert!(success, "child raw fd {raw_fd} already occupied");
                    } else {
                        dup_one(parent_dt, child_dt, &child, fd, raw_fd);
                    }
                },
                |fd| dup_one(parent_dt, child_dt, &child, fd, raw_fd),
                |fd| dup_one(parent_dt, child_dt, &child, fd, raw_fd),
                |fd| dup_one(parent_dt, child_dt, &child, fd, raw_fd),
                |fd| dup_one(parent_dt, child_dt, &child, fd, raw_fd),
                |fd| dup_one(parent_dt, child_dt, &child, fd, raw_fd),
            );
        }

        // Don't set min_alloc_fd to 3 — the child inherits real virtual fds
        // at 0/1/2 from the parent. New allocations should start above the
        // highest inherited fd.
        child
    }
}

// This places size limits on maximum read/write sizes that might occur; it exists primarily to
// prevent OOM due to the user asking for a _massive_ read or such at once. Keeping this too small
// has the downside of requiring too many syscalls, while having it be too large allows for massive
// allocations to be triggered by the userland program. For now, this is set to a
// hopefully-reasonable middle ground.
const MAX_KERNEL_BUF_SIZE: usize = 0x80_000;

trait ToSyscallResult {
    fn to_syscall_result(self) -> Result<usize, Errno>;
}
impl ToSyscallResult for Result<(), Errno> {
    fn to_syscall_result(self) -> Result<usize, Errno> {
        self.map(|()| 0)
    }
}
impl ToSyscallResult for Result<usize, Errno> {
    fn to_syscall_result(self) -> Result<usize, Errno> {
        self
    }
}
impl ToSyscallResult for Result<u32, Errno> {
    fn to_syscall_result(self) -> Result<usize, Errno> {
        self.map(|v| v as usize)
    }
}

impl<FS: ShimFS> Task<FS> {
    /// A wrapper function around `sys_pread64` that copies data in chunks to avoid OOMing.
    fn pread_with_user_buf(
        &self,
        fd: i32,
        buf: MutPtr<u8>,
        count: usize,
        offset: i64,
    ) -> Result<usize, Errno> {
        #[cfg(feature = "platform_central")]
        {
            let addr = buf.as_usize();
            if addr == 0 {
                return Err(Errno::EFAULT);
            }
            // SAFETY: In central mode, buf points to the shmem data region
            // (central rewrites the pointer). The memory is valid and writable
            // for `count` bytes.
            let slice = unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, count) };
            let mut read_total = 0;
            while read_total < count {
                let cur_offset = offset + (read_total.reinterpret_as_signed() as i64);
                match self.sys_pread64(fd, &mut slice[read_total..], cur_offset) {
                    Ok(0) => break, // EOF
                    Ok(size) => read_total += size,
                    Err(e) => return Err(e),
                }
            }
            assert!(read_total <= count);
            Ok(read_total)
        }
        #[cfg(not(feature = "platform_central"))]
        {
            let mut kernel_buf = vec![0u8; count.min(MAX_KERNEL_BUF_SIZE)];
            let mut read_total = 0;
            while read_total < count {
                let to_read = (count - read_total).min(kernel_buf.len());
                match self.sys_pread64(
                    fd,
                    &mut kernel_buf[..to_read],
                    offset + (read_total.reinterpret_as_signed() as i64),
                ) {
                    Ok(0) => break, // EOF
                    Ok(size) => {
                        buf.copy_from_slice(read_total, &kernel_buf[..size])
                            .ok_or(Errno::EFAULT)?;
                        read_total += size;
                    }
                    Err(e) => return Err(e),
                }
            }
            assert!(read_total <= count);
            Ok(read_total)
        }
    }

    /// Handle Linux syscalls and dispatch them to LiteBox implementations.
    ///
    /// # Panics
    ///
    /// Unsupported syscalls or arguments would trigger a panic for development purposes.
    fn handle_syscall_request(&self, ctx: &mut litebox_common_linux::PtRegs) {
        let return_value = match self.do_syscall(ctx) {
            Ok(v) => v,
            Err(err) => (err.as_neg() as isize).reinterpret_as_unsigned(),
        };
        #[cfg(target_arch = "x86")]
        {
            ctx.eax = return_value;
        }
        #[cfg(target_arch = "x86_64")]
        {
            ctx.rax = return_value;
        }
    }

    fn do_syscall(&self, ctx: &mut litebox_common_linux::PtRegs) -> Result<usize, Errno> {
        // Helper macro to unify the return value from `sys_*`.
        macro_rules! syscall {
            ($func:ident($($args:expr),*)) => {
                self.$func($($args),*).to_syscall_result()
            };
        }

        #[cfg(target_arch = "x86")]
        let syscall_number = ctx.orig_eax;
        #[cfg(target_arch = "x86_64")]
        let syscall_number = ctx.orig_rax;
        let request =
            SyscallRequest::<Platform>::try_from_raw(syscall_number, ctx, log_unsupported_fmt)?;

        match request {
            SyscallRequest::Exit { status } => {
                self.sys_exit(status);
                Ok(0)
            }
            SyscallRequest::ExitGroup { status } => {
                self.sys_exit_group(status);
                Ok(0)
            }
            SyscallRequest::Execve {
                pathname,
                argv,
                envp,
            } => self.sys_execve(pathname, argv, envp, ctx),
            SyscallRequest::Read { fd, buf, count } => {
                // Note some applications (e.g., `node`) seem to assume that getting fewer bytes than
                // requested indicates EOF.
                if count <= MAX_KERNEL_BUF_SIZE {
                    #[cfg(feature = "platform_central")]
                    {
                        let addr = buf.as_usize();
                        if addr == 0 {
                            Err(Errno::EFAULT)
                        } else {
                            // SAFETY: In central mode, buf points to the shmem
                            // data region (central rewrites rsi). The memory is
                            // valid and writable for `count` bytes.
                            let slice =
                                unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, count) };
                            self.sys_read(fd, slice, None)
                        }
                    }
                    #[cfg(not(feature = "platform_central"))]
                    {
                        let mut kernel_buf = vec![0u8; count.min(MAX_KERNEL_BUF_SIZE)];
                        self.sys_read(fd, &mut kernel_buf, None).and_then(|size| {
                            buf.copy_from_slice(0, &kernel_buf[..size])
                                .map(|()| size)
                                .ok_or(Errno::EFAULT)
                        })
                    }
                } else {
                    // If the read size is too large, we need to do some extra work to avoid OOMing.
                    // We read data in chunks and update the file offset ourselves only if the read succeeds.
                    self.sys_lseek(fd, 0, litebox::fs::SeekWhence::RelativeToCurrentOffset)
                    .inspect_err(|e| {
                        match *e {
                            Errno::EBADF => (), // safe errors to return
                            Errno::ESPIPE => {
                                unimplemented!("read on non-seekable fds with large buffers");
                            }
                            Errno::EINVAL => {
                                unreachable!("seekable file should not return EINVAL when getting current offset");
                            }
                            _ => {
                                unimplemented!("unexpected error from lseek: {}", e);
                            }
                        }
                    })
                    .and_then(|cur_loc| {
                        self.pread_with_user_buf(fd, buf, count, i64::try_from(cur_loc).unwrap())
                            .inspect(|read_total| {
                                // Update the file offset to reflect the read we just did.
                                self.sys_lseek(
                                    fd,
                                    (cur_loc + read_total).reinterpret_as_signed(),
                                    litebox::fs::SeekWhence::RelativeToBeginning,
                                )
                                // Given that previous lseek and pread succeeded, this lseek should also succeed.
                                .expect("lseek failed");
                            })
                    })
                }
            }
            SyscallRequest::Write { fd, buf, count } => {
                #[cfg(feature = "platform_central")]
                {
                    let addr = buf.as_usize();
                    if addr == 0 {
                        Err(Errno::EFAULT)
                    } else {
                        // SAFETY: In central mode, buf points to valid, stable
                        // host memory (shmem or central's own heap) for the
                        // duration of this synchronous dispatch.
                        let slice =
                            unsafe { core::slice::from_raw_parts(addr as *const u8, count) };
                        self.sys_write(fd, slice, None)
                    }
                }
                #[cfg(not(feature = "platform_central"))]
                match buf.to_owned_slice(count) {
                    Some(buf) => self.sys_write(fd, &buf, None),
                    None => Err(Errno::EFAULT),
                }
            }
            SyscallRequest::Close { fd } => syscall!(sys_close(fd)),
            SyscallRequest::Lseek { fd, offset, whence } => {
                use litebox::utils::TruncateExt as _;
                syscalls::file::try_into_whence(whence.truncate())
                    .map_err(|_| Errno::EINVAL)
                    .and_then(|seekwhence| self.sys_lseek(fd, offset, seekwhence))
            }
            SyscallRequest::Mkdir { pathname, mode } => pathname
                .to_cstring()
                .map_or(Err(Errno::EINVAL), |path| syscall!(sys_mkdir(path, mode))),
            SyscallRequest::Chdir { pathname } => pathname
                .to_cstring()
                .map_or(Err(Errno::EINVAL), |path| syscall!(sys_chdir(path))),
            SyscallRequest::RtSigprocmask {
                how,
                set,
                oldset,
                sigsetsize,
            } => self.sys_rt_sigprocmask(how, set, oldset, sigsetsize),
            SyscallRequest::RtSigaction {
                signum,
                act,
                oldact,
                sigsetsize,
            } => self.sys_rt_sigaction(signum, act, oldact, sigsetsize),
            SyscallRequest::RtSigreturn => self.sys_rt_sigreturn(ctx),
            #[cfg(target_arch = "x86")]
            SyscallRequest::Sigreturn => self.sys_sigreturn(ctx),
            SyscallRequest::Ioctl { fd, arg } => syscall!(sys_ioctl(fd, arg)),
            SyscallRequest::Pread64 {
                fd,
                buf,
                count,
                offset,
            } => self.pread_with_user_buf(fd, buf, count, offset),
            SyscallRequest::Pwrite64 {
                fd,
                buf,
                count,
                offset,
            } => {
                #[cfg(feature = "platform_central")]
                {
                    let addr = buf.as_usize();
                    if addr == 0 {
                        Err(Errno::EFAULT)
                    } else {
                        // SAFETY: same reasoning as SyscallRequest::Write above.
                        let slice =
                            unsafe { core::slice::from_raw_parts(addr as *const u8, count) };
                        self.sys_pwrite64(fd, slice, offset)
                    }
                }
                #[cfg(not(feature = "platform_central"))]
                match buf.to_owned_slice(count) {
                    Some(buf) => self.sys_pwrite64(fd, &buf, offset),
                    None => Err(Errno::EFAULT),
                }
            }
            SyscallRequest::Mmap {
                addr,
                length,
                prot,
                flags,
                fd,
                offset,
            } => self
                .sys_mmap(addr, length, prot, flags, fd, offset)
                .map(|ptr| ptr.as_usize()),
            SyscallRequest::Mprotect { addr, length, prot } => {
                syscall!(sys_mprotect(addr, length, prot))
            }
            SyscallRequest::Mremap {
                old_addr,
                old_size,
                new_size,
                flags,
                new_addr,
            } => self
                .sys_mremap(old_addr, old_size, new_size, flags, new_addr)
                .map(|ptr| ptr.as_usize()),
            SyscallRequest::Munmap { addr, length } => syscall!(sys_munmap(addr, length)),
            SyscallRequest::Brk { addr } => self.sys_brk(addr),
            SyscallRequest::Readv { fd, iovec, iovcnt } => self.sys_readv(fd, iovec, iovcnt),
            SyscallRequest::Writev { fd, iovec, iovcnt } => self.sys_writev(fd, iovec, iovcnt),
            SyscallRequest::Access { pathname, mode } => pathname
                .to_cstring()
                .map_or(Err(Errno::EFAULT), |path| syscall!(sys_access(path, mode))),
            SyscallRequest::Madvise {
                addr,
                length,
                behavior,
            } => syscall!(sys_madvise(addr, length, behavior)),
            SyscallRequest::Dup {
                oldfd,
                newfd,
                flags,
            } => syscall!(sys_dup(oldfd, newfd, flags)),
            SyscallRequest::Socket {
                domain,
                type_and_flags,
                protocol,
            } => syscall!(sys_socket(domain, type_and_flags, protocol)),
            #[cfg(target_arch = "x86")]
            SyscallRequest::Socketcall { call, args } => self.sys_socketcall(call, args),
            SyscallRequest::Socketpair {
                domain,
                type_and_flags,
                protocol,
                sockvec,
            } => syscall!(sys_socketpair(domain, type_and_flags, protocol, sockvec)),
            SyscallRequest::Connect {
                sockfd,
                sockaddr,
                addrlen,
            } => syscall!(sys_connect(sockfd, sockaddr, addrlen)),
            SyscallRequest::Accept {
                sockfd,
                addr,
                addrlen,
                flags,
            } => syscall!(sys_accept(sockfd, addr, addrlen, flags)),
            SyscallRequest::Sendto {
                sockfd,
                buf,
                len,
                flags,
                addr,
                addrlen,
            } => self.sys_sendto(sockfd, buf, len, flags, addr, addrlen),
            SyscallRequest::Sendmsg { sockfd, msg, flags } => self.sys_sendmsg(sockfd, msg, flags),
            SyscallRequest::Recvfrom {
                sockfd,
                buf,
                len,
                flags,
                addr,
                addrlen,
            } => self.sys_recvfrom(sockfd, buf, len, flags, addr, addrlen),
            SyscallRequest::Bind {
                sockfd,
                sockaddr,
                addrlen,
            } => syscall!(sys_bind(sockfd, sockaddr, addrlen)),
            SyscallRequest::Listen { sockfd, backlog } => {
                syscall!(sys_listen(sockfd, backlog))
            }
            SyscallRequest::Setsockopt {
                sockfd,
                level,
                optname,
                optval,
                optlen,
            } => syscall!(sys_setsockopt(sockfd, level, optname, optval, optlen)),
            SyscallRequest::Getsockopt {
                sockfd,
                level,
                optname,
                optval,
                optlen,
            } => syscall!(sys_getsockopt(sockfd, level, optname, optval, optlen)),
            SyscallRequest::Getsockname {
                sockfd,
                addr,
                addrlen,
            } => syscall!(sys_getsockname(sockfd, addr, addrlen)),
            SyscallRequest::Getpeername {
                sockfd,
                addr,
                addrlen,
            } => syscall!(sys_getpeername(sockfd, addr, addrlen)),
            SyscallRequest::Shutdown { sockfd, how } => syscall!(sys_shutdown(sockfd, how)),
            SyscallRequest::Uname { buf } => syscall!(sys_uname(buf)),
            SyscallRequest::Fcntl { fd, arg } => syscall!(sys_fcntl(fd, arg)),
            SyscallRequest::Getcwd { buf, size: count } => {
                let mut kernel_buf = vec![0u8; count.min(MAX_KERNEL_BUF_SIZE)];
                self.sys_getcwd(&mut kernel_buf).and_then(|size| {
                    buf.copy_from_slice(0, &kernel_buf[..size])
                        .map(|()| size)
                        .ok_or(Errno::EFAULT)
                })
            }
            SyscallRequest::EpollCtl {
                epfd,
                op,
                fd,
                event,
            } => syscall!(sys_epoll_ctl(epfd, op, fd, event)),
            SyscallRequest::EpollCreate { size, flags } => {
                // the `size` argument is ignored, but must be greater than zero;
                if size > 0 {
                    syscall!(sys_epoll_create(flags))
                } else {
                    Err(Errno::EINVAL)
                }
            }
            SyscallRequest::EpollPwait {
                epfd,
                events,
                maxevents,
                timeout,
                sigmask,
                sigsetsize,
            } => self.sys_epoll_pwait(epfd, events, maxevents, timeout, sigmask, sigsetsize),
            SyscallRequest::Prctl { args } => self.sys_prctl(args),
            SyscallRequest::ArchPrctl { arg } => syscall!(sys_arch_prctl(arg)),
            SyscallRequest::Readlink {
                pathname,
                buf,
                bufsiz,
            } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                let mut kernel_buf = vec![0u8; bufsiz.min(MAX_KERNEL_BUF_SIZE)];
                self.sys_readlink(path, &mut kernel_buf).and_then(|size| {
                    buf.copy_from_slice(0, &kernel_buf[..size])
                        .map(|()| size)
                        .ok_or(Errno::EFAULT)
                })
            }),
            SyscallRequest::Ppoll {
                fds,
                nfds,
                timeout,
                sigmask,
                sigsetsize,
            } => self.sys_ppoll(fds, nfds, timeout, sigmask, sigsetsize),
            SyscallRequest::Pselect {
                nfds,
                readfds,
                writefds,
                exceptfds,
                timeout,
                sigsetpack,
            } => self.sys_pselect(nfds, readfds, writefds, exceptfds, timeout, sigsetpack),
            SyscallRequest::Readlinkat {
                dirfd,
                pathname,
                buf,
                bufsiz,
            } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                let mut kernel_buf = vec![0u8; bufsiz.min(MAX_KERNEL_BUF_SIZE)];
                self.sys_readlinkat(dirfd, path, &mut kernel_buf)
                    .and_then(|size| {
                        buf.copy_from_slice(0, &kernel_buf[..size])
                            .map(|()| size)
                            .ok_or(Errno::EFAULT)
                    })
            }),
            SyscallRequest::Gettimeofday { tv, tz } => syscall!(sys_gettimeofday(tv, tz)),
            SyscallRequest::ClockGettime { clockid, tp } => {
                litebox_common_linux::ClockId::try_from(clockid)
                    .map_err(|_| {
                        log_unsupported!("clock_gettime(clockid = {clockid})");
                        Errno::EINVAL
                    })
                    .and_then(|clock_id| syscall!(sys_clock_gettime(clock_id, tp)))
            }
            SyscallRequest::ClockGetres { clockid, res } => {
                litebox_common_linux::ClockId::try_from(clockid)
                    .map_err(|_| {
                        log_unsupported!("clock_getres(clockid = {clockid})");
                        Errno::EINVAL
                    })
                    .and_then(|clock_id| syscall!(sys_clock_getres(clock_id, res)))
            }
            SyscallRequest::ClockNanosleep {
                clockid,
                flags,
                request,
                remain,
            } => litebox_common_linux::ClockId::try_from(clockid)
                .map_err(|_| {
                    log_unsupported!("clock_nanosleep(clockid = {clockid})");
                    Errno::EINVAL
                })
                .and_then(|clock_id| {
                    syscall!(sys_clock_nanosleep(clock_id, flags, request, remain))
                }),
            SyscallRequest::Time { tloc } => self
                .sys_time(tloc)
                .and_then(|second| usize::try_from(second).or(Err(Errno::EOVERFLOW))),
            SyscallRequest::Openat {
                dirfd,
                pathname,
                flags,
                mode,
            } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                syscall!(sys_openat(dirfd, path, flags, mode))
            }),
            SyscallRequest::Ftruncate { fd, length } => syscall!(sys_ftruncate(fd, length)),
            SyscallRequest::Unlinkat {
                dirfd,
                pathname,
                flags,
            } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                syscall!(sys_unlinkat(dirfd, path, flags))
            }),
            SyscallRequest::Stat { pathname, buf } => {
                pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                    self.sys_stat(path).and_then(|stat| {
                        buf.write_at_offset(0, stat)
                            .ok_or(Errno::EFAULT)
                            .map(|()| 0)
                    })
                })
            }
            SyscallRequest::Lstat { pathname, buf } => {
                pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                    self.sys_lstat(path).and_then(|stat| {
                        buf.write_at_offset(0, stat)
                            .ok_or(Errno::EFAULT)
                            .map(|()| 0)
                    })
                })
            }
            SyscallRequest::Fstat { fd, buf } => self.sys_fstat(fd).and_then(|stat| {
                buf.write_at_offset(0, stat)
                    .ok_or(Errno::EFAULT)
                    .map(|()| 0)
            }),
            #[cfg(target_arch = "x86_64")]
            SyscallRequest::Newfstatat {
                dirfd,
                pathname,
                buf,
                flags,
            } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                self.sys_newfstatat(dirfd, path, flags).and_then(|stat| {
                    buf.write_at_offset(0, stat)
                        .ok_or(Errno::EFAULT)
                        .map(|()| 0)
                })
            }),
            #[cfg(target_arch = "x86")]
            SyscallRequest::Fstatat64 {
                dirfd,
                pathname,
                buf,
                flags,
            } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                self.sys_newfstatat(dirfd, path, flags).and_then(|stat| {
                    buf.write_at_offset(0, stat.into())
                        .ok_or(Errno::EFAULT)
                        .map(|()| 0)
                })
            }),
            SyscallRequest::Eventfd2 { initval, flags } => {
                syscall!(sys_eventfd2(initval, flags))
            }
            SyscallRequest::Pipe2 { pipefd, flags } => {
                self.sys_pipe2(flags).and_then(|(read_fd, write_fd)| {
                    pipefd.write_at_offset(0, read_fd).ok_or(Errno::EFAULT)?;
                    pipefd.write_at_offset(1, write_fd).ok_or(Errno::EFAULT)?;
                    Ok(0)
                })
            }
            SyscallRequest::Clone { args } => self.sys_clone(ctx, &args),
            SyscallRequest::Clone3 { args } => self.sys_clone3(ctx, args),
            SyscallRequest::SetThreadArea { user_desc } => {
                #[cfg(target_arch = "x86_64")]
                {
                    let _ = user_desc;
                    Err(Errno::ENOSYS) // x86_64 does not support set_thread_area
                }
                #[cfg(target_arch = "x86")]
                {
                    user_desc
                        .read_at_offset(0)
                        .ok_or(Errno::EFAULT)
                        .and_then(|mut desc| {
                            let idx = desc.entry_number;
                            self.set_thread_area(&mut desc)?;
                            if idx == u32::MAX {
                                // index -1 means the kernel should try to find and
                                // allocate an empty descriptor.
                                // return the allocated entry number
                                user_desc.write_at_offset(0, desc).ok_or(Errno::EFAULT)?;
                            }
                            Ok(0)
                        })
                }
            }
            SyscallRequest::SetTidAddress { tidptr } => {
                Ok(self.sys_set_tid_address(tidptr).reinterpret_as_unsigned() as usize)
            }
            SyscallRequest::Gettid => Ok(self.sys_gettid().reinterpret_as_unsigned() as usize),
            SyscallRequest::Getrlimit { resource, rlim } => {
                syscall!(sys_getrlimit(resource, rlim))
            }
            SyscallRequest::Setrlimit { resource, rlim } => {
                syscall!(sys_setrlimit(resource, rlim))
            }
            SyscallRequest::Prlimit {
                pid,
                resource,
                new_limit,
                old_limit,
            } => syscall!(sys_prlimit(pid, resource, new_limit, old_limit)),
            SyscallRequest::SetRobustList { head } => {
                self.sys_set_robust_list(head);
                Ok(0)
            }
            SyscallRequest::GetRobustList { pid, head, len } => self
                .sys_get_robust_list(pid, head)
                .and_then(|()| {
                    len.write_at_offset(0, size_of::<litebox_common_linux::RobustListHead>())
                        .ok_or(Errno::EFAULT)
                })
                .map(|()| 0),
            SyscallRequest::GetRandom { buf, count, flags } => {
                self.sys_getrandom(buf, count, flags)
            }
            SyscallRequest::Getpid => Ok(self.sys_getpid().reinterpret_as_unsigned() as usize),
            SyscallRequest::Getppid => Ok(self.sys_getppid().reinterpret_as_unsigned() as usize),
            SyscallRequest::Getuid => Ok(self.sys_getuid() as usize),
            SyscallRequest::Getgid => Ok(self.sys_getgid() as usize),
            SyscallRequest::Geteuid => Ok(self.sys_geteuid() as usize),
            SyscallRequest::Getegid => Ok(self.sys_getegid() as usize),
            SyscallRequest::Sysinfo { buf } => {
                let sysinfo = self.sys_sysinfo();
                buf.write_at_offset(0, sysinfo)
                    .ok_or(Errno::EFAULT)
                    .map(|()| 0)
            }
            SyscallRequest::CapGet { header, data } => syscall!(sys_capget(header, data)),
            SyscallRequest::GetDirent64 { fd, dirp, count } => {
                self.sys_getdirent64(fd, dirp, count)
            }
            SyscallRequest::SchedGetAffinity { pid, len, mask } => {
                const BITS_PER_BYTE: usize = 8;
                let cpuset = self.sys_sched_getaffinity(pid);
                if len * BITS_PER_BYTE < cpuset.len()
                    || len & (core::mem::size_of::<usize>() - 1) != 0
                {
                    Err(Errno::EINVAL)
                } else {
                    let raw_bytes = cpuset.as_bytes();
                    mask.copy_from_slice(0, raw_bytes)
                        .map(|()| raw_bytes.len())
                        .ok_or(Errno::EFAULT)
                }
            }
            SyscallRequest::SchedYield => {
                // Do nothing until we have more scheduler integration with the
                // platform.
                Ok(0)
            }
            SyscallRequest::Futex { args } => self.sys_futex(args),
            SyscallRequest::Umask { mask } => {
                let old_mask = self.sys_umask(mask);
                Ok(old_mask.bits() as usize)
            }
            // chmod/chown family: virtual root identity, always succeed as no-ops.
            SyscallRequest::Chmod { .. }
            | SyscallRequest::Fchmod { .. }
            | SyscallRequest::Fchmodat { .. }
            | SyscallRequest::Chown { .. }
            | SyscallRequest::Fchown { .. }
            | SyscallRequest::Lchown { .. }
            | SyscallRequest::Fchownat { .. } => Ok(0),
            SyscallRequest::Kill { pid, sig } => self.sys_kill(pid, sig),
            SyscallRequest::Tkill { tid, sig } => self.sys_tkill(tid, sig),
            SyscallRequest::Tgkill { tgid, tid, sig } => self.sys_tgkill(tgid, tid, sig),
            SyscallRequest::Sigaltstack { ss, old_ss } => self.sys_sigaltstack(ss, old_ss, ctx),
            SyscallRequest::Alarm { seconds } => syscall!(sys_alarm(seconds)),
            _ => {
                log_unsupported!("{request:?}");
                Err(Errno::ENOSYS)
            }
        }
    }
}

/// Global shim state, shared across all tasks.
struct GlobalState<FS: ShimFS> {
    /// The platform instance used throughout the shim.
    platform: &'static Platform,
    /// The futex manager for handling futex operations.
    futex_manager: FutexManager<Platform>,
    /// The anonymous pipe implementation.
    pipes: Pipes<Platform>,
    /// The time when the shim was started.
    boot_time: <Platform as TimeProvider>::Instant,
    /// Optional load filter function to modify environment variables during program loading.
    load_filter: Option<LoadFilter>,
    /// Next thread ID to assign.
    // TODO: better management of thread IDs
    next_thread_id: core::sync::atomic::AtomicI32,
    /// UNIX domain socket address table
    unix_addr_table: litebox::sync::RwLock<Platform, syscalls::unix::UnixAddrTable<FS>>,
}

struct Task<FS: ShimFS> {
    global: Arc<GlobalState<FS>>,
    /// Per-process page manager. Threads within the same process share this
    /// via `Arc` (like Linux's `mm_struct` with `CLONE_VM`), but each forked
    /// child gets its own independent clone (like Linux's `fork()` copying
    /// `mm_struct`).
    pm: alloc::sync::Arc<litebox::mm::PageManager<Platform, { PAGE_SIZE }>>,
    /// Per-process network state. Shared among threads in the same process
    /// via Arc, but each forked process gets its own instance.
    net: Arc<litebox::sync::Mutex<Platform, Network<Platform>>>,
    wait_state: wait::WaitState,
    thread: syscalls::process::ThreadState,
    /// Process ID
    pid: i32,
    /// Parent Process ID
    ppid: i32,
    /// Thread ID
    tid: i32,
    /// Task credentials. These are set per task but are Arc'd to save space
    /// since most tasks never change their credentials.
    credentials: Arc<syscalls::process::Credentials>,
    /// Command name (usually the executable name, excluding the path)
    comm: Cell<[u8; litebox_common_linux::TASK_COMM_LEN]>,
    /// Filesystem state. `RefCell` to support `unshare` in the future.
    fs: RefCell<Arc<syscalls::file::FsState>>,
    /// File descriptors. `RefCell` to support `unshare` in the future.
    files: RefCell<Arc<syscalls::file::FilesState<FS>>>,
    /// Signal state
    signals: syscalls::signal::SignalState,
}

impl<FS: ShimFS> Drop for Task<FS> {
    fn drop(&mut self) {
        self.prepare_for_exit();
    }
}

pub type LoadFilter = fn(envp: &mut alloc::vec::Vec<alloc::ffi::CString>);

#[cfg(test)]
mod test_utils {
    extern crate std;
    use super::*;

    impl<FS: ShimFS> GlobalState<FS> {
        /// Make a new task with default values for testing.
        pub(crate) fn new_test_task(self: Arc<Self>, fs: alloc::sync::Arc<FS>) -> Task<FS> {
            let pid = self
                .next_thread_id
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            let files = Arc::new(syscalls::file::FilesState::new(litebox::fd::new_descriptor_table(), fs));
            files.initialize_stdio_in_shared_descriptors_table(&self);
            let mut net = Network::new(self.platform, &files.dt);
            net.set_platform_interaction(litebox::net::PlatformInteraction::Manual);
            Task {
                wait_state: wait::WaitState::new(self.platform),
                net: Arc::new(litebox::sync::Mutex::new(net)),
                thread: syscalls::process::ThreadState::new_process(pid),
                pid,
                ppid: 0,
                tid: pid,
                credentials: Arc::new(syscalls::process::Credentials {
                    uid: 0,
                    euid: 0,
                    gid: 0,
                    egid: 0,
                }),
                comm: Cell::new(*b"test\0\0\0\0\0\0\0\0\0\0\0\0"),
                fs: Arc::new(syscalls::file::FsState::new()).into(),
                files: files.into(),
                signals: syscalls::signal::SignalState::new_process(),
                pm: alloc::sync::Arc::new(PageManager::new(self.platform)),
                global: self,
            }
        }
    }

    impl<FS: ShimFS> Task<FS> {
        /// Returns a clone of this task with a new TID for testing.
        pub(crate) fn clone_for_test(&self) -> Option<Self> {
            let tid = self
                .global
                .next_thread_id
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            let task = Task {
                wait_state: wait::WaitState::new(self.global.platform),
                global: self.global.clone(),
                pm: self.pm.clone(),
                net: self.net.clone(),
                thread: self.thread.new_thread(tid)?,
                pid: self.pid,
                ppid: self.ppid,
                tid,
                credentials: self.credentials.clone(),
                comm: self.comm.clone(),
                fs: self.fs.clone(),
                files: self.files.clone(),
                signals: self.signals.clone_for_new_task(),
            };
            Some(task)
        }

        /// Spawns a thread that runs with a clone of this task and a new TID.
        ///
        /// # Panics
        /// Panics if the test process is already terminating.
        pub(crate) fn spawn_clone_for_test<R>(
            &self,
            f: impl 'static + Send + FnOnce(Task<FS>) -> R,
        ) -> std::thread::JoinHandle<R>
        where
            R: 'static + Send,
        {
            let task = self.clone_for_test().unwrap();
            std::thread::spawn(move || f(task))
        }
    }
}
