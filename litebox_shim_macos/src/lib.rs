// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A shim that provides a macOS-compatible ABI via LiteBox.

#![no_std]
#![cfg(target_arch = "aarch64")]
#![expect(
    clippy::unused_self,
    reason = "by convention, syscalls and related methods take &self even if unused"
)]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::Cell;
use core::sync::atomic::{AtomicI32, Ordering};
use litebox::{
    fd::RawDescriptorStorage,
    mm::{linux::PAGE_SIZE, PageManager},
    net::Network,
    pipes::Pipes,
    platform::TimeProvider,
    shim::ContinueOperation,
    sync::futex::FutexManager,
    LiteBox,
};
use litebox_common_macos::PtRegs;
use litebox_platform_multiplex::Platform;

/// A trait required for file systems to be used in the shim.
pub trait ShimFS: litebox::fs::FileSystem + Send + Sync + 'static {}
impl<T: litebox::fs::FileSystem + Send + Sync + 'static> ShimFS for T {}

/// On debug builds, logs that the user attempted to use an unsupported feature.
// DEVNOTE: this is before the `mod` declarations so that it can be used within them.
macro_rules! log_unsupported {
    ($($arg:tt)*) => {
        $crate::log_unsupported_fmt(core::format_args!($($arg)*));
    };
}

pub(crate) fn log_unsupported_fmt(args: core::fmt::Arguments<'_>) {
    use litebox::platform::DebugLogProvider as _;

    if cfg!(debug_assertions) {
        let msg = alloc::format!("WARNING: unsupported: {args}\n");
        litebox_platform_multiplex::platform().debug_log_print(&msg);
    }
}

pub mod loader;
pub mod syscalls;

pub type DefaultFS = MacosFS;
pub(crate) type MacosFS = litebox::fs::layered::FileSystem<
    Platform,
    litebox::fs::in_mem::FileSystem<Platform>,
    litebox::fs::layered::FileSystem<
        Platform,
        litebox::fs::devices::FileSystem<Platform>,
        litebox::fs::tar_ro::FileSystem<Platform>,
    >,
>;

// Convenience type aliases
type ConstPtr<T> = <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<T>;
type MutPtr<T> = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<T>;

/// Builder for the macOS shim.
pub struct MacosShimBuilder<FS: ShimFS> {
    platform: &'static Platform,
    litebox: LiteBox<Platform>,
    fs: Option<FS>,
    sysroot: Option<String>,
}

impl<FS: ShimFS> Default for MacosShimBuilder<FS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<FS: ShimFS> MacosShimBuilder<FS> {
    /// Returns a new shim builder.
    pub fn new() -> Self {
        let platform = litebox_platform_multiplex::platform();
        Self {
            platform,
            litebox: LiteBox::new(platform),
            fs: None,
            sysroot: None,
        }
    }

    /// Set the sysroot path for file system path rewriting.
    ///
    /// When set, paths starting with `/usr/lib/` or `/System/Library/` will
    /// be redirected under this sysroot prefix in `sys_open`.
    pub fn set_sysroot(&mut self, path: String) {
        self.sysroot = Some(path);
    }

    /// Returns the litebox object for the shim.
    pub fn litebox(&self) -> &LiteBox<Platform> {
        &self.litebox
    }

    /// Set the global file system.
    pub fn set_fs(&mut self, fs: FS) {
        self.fs = Some(fs);
    }

    /// Create a default layered file system with the given in-memory and tar read-only layers.
    pub fn default_fs(
        &self,
        in_mem_fs: litebox::fs::in_mem::FileSystem<Platform>,
        tar_ro_fs: litebox::fs::tar_ro::FileSystem<Platform>,
    ) -> DefaultFS {
        let dev_stdio = litebox::fs::devices::FileSystem::new(&self.litebox);
        litebox::fs::layered::FileSystem::new(
            &self.litebox,
            in_mem_fs,
            litebox::fs::layered::FileSystem::new(
                &self.litebox,
                dev_stdio,
                tar_ro_fs,
                litebox::fs::layered::LayeringSemantics::LowerLayerReadOnly,
            ),
            litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
        )
    }

    /// Build the shim.
    ///
    /// # Panics
    /// Panics if the file system has not been set with [`set_fs`](Self::set_fs)
    /// before calling this method.
    pub fn build(self) -> MacosShim<FS> {
        let mut net = Network::new(&self.litebox);
        net.set_platform_interaction(litebox::net::PlatformInteraction::Manual);
        let global = Arc::new(GlobalState {
            platform: self.platform,
            pm: PageManager::new(&self.litebox),
            fs: self
                .fs
                .expect("File system must be set before calling build"),
            futex_manager: FutexManager::new(),
            pipes: Pipes::new(&self.litebox),
            net: litebox::sync::Mutex::new(net),
            boot_time: self.platform.now(),
            litebox: self.litebox,
            raw_descriptors: litebox::sync::RwLock::new(RawDescriptorStorage::new()),
            sysroot: self.sysroot,
        });
        MacosShim(global)
    }
}

/// The built macOS shim, holding shared global state.
pub struct MacosShim<FS: ShimFS>(Arc<GlobalState<FS>>);

impl<FS: ShimFS> Clone for MacosShim<FS> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<FS: ShimFS> MacosShim<FS> {
    /// Loads a program as the shim's initial task, returning the initial
    /// register state and process handle.
    pub fn load_program(
        &self,
        program_bytes: &[u8],
        argv: Vec<alloc::ffi::CString>,
        envp: Vec<alloc::ffi::CString>,
        dyld_bytes: Option<&[u8]>,
    ) -> Result<LoadedProgram<FS>, loader::MachoLoaderError> {
        let exit_code = Arc::new(AtomicI32::new(0));

        self.initialize_stdio();

        let entrypoints = MacosShimEntrypoints {
            task: Task {
                global: self.0.clone(),
                terminated: Cell::new(false),
                exit_code: exit_code.clone(),
                patch_cache: core::cell::RefCell::new(BTreeMap::new()),
            },
            _not_send: core::marker::PhantomData,
        };

        let arg_count = argv.len();
        let env_count = envp.len();
        let load_info =
            loader::load_macho(&entrypoints.task, program_bytes, argv, envp, dyld_bytes)?;

        let mut initial_ctx = PtRegs {
            pc: load_info.entry_point,
            sp: load_info.user_stack_top,
            ..PtRegs::default()
        };

        if load_info.is_lc_main {
            // LC_MAIN: entry is called as a C function:
            //   main(argc, argv, envp, apple)
            // The stack has: [argc, argv[0..n], NULL, envp[0..m], NULL, apple[0..], NULL]
            // We pass argc in x0, argv pointer in x1, envp pointer in x2, apple in x3.
            let sp = load_info.user_stack_top;
            initial_ctx.regs[0] = arg_count; // x0 = argc
            initial_ctx.regs[1] = sp + size_of::<usize>(); // x1 = &argv[0]
                                                           // x2 = envp: skip past argc + argv pointers + NULL terminator
            let envp_offset = size_of::<usize>() + (arg_count + 1) * size_of::<usize>();
            initial_ctx.regs[2] = sp + envp_offset; // x2 = &envp[0]
                                                    // x3 = apple: skip past envp pointers + NULL terminator
            let apple_offset = envp_offset + (env_count + 1) * size_of::<usize>();
            initial_ctx.regs[3] = sp + apple_offset; // x3 = &apple[0]
        }

        Ok(LoadedProgram {
            entrypoints,
            process: MacosShimProcess(exit_code),
            initial_ctx,
        })
    }

    /// Get the global page manager.
    pub fn page_manager(&self) -> &PageManager<Platform, PAGE_SIZE> {
        &self.0.pm
    }

    /// Initialize stdio file descriptors (0=stdin, 1=stdout, 2=stderr).
    fn initialize_stdio(&self) {
        use litebox::fs::{Mode, OFlags};

        let stdin = self
            .0
            .fs
            .open("/dev/stdin", OFlags::RDONLY, Mode::empty())
            .unwrap();
        let stdout = self
            .0
            .fs
            .open("/dev/stdout", OFlags::WRONLY, Mode::empty())
            .unwrap();
        let stderr = self
            .0
            .fs
            .open("/dev/stderr", OFlags::WRONLY, Mode::empty())
            .unwrap();

        let mut dt = self.0.litebox.descriptor_table_mut();
        let mut rds = self.0.raw_descriptors.write();
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

/// Metadata tag for stdio status flags, parallel to the Linux shim's usage.
#[expect(
    dead_code,
    reason = "stored as entry metadata for future GETFL support"
)]
struct StdioStatusFlags(litebox::fs::OFlags);

/// A loaded macOS program, ready to be executed on a platform.
pub struct LoadedProgram<FS: ShimFS> {
    /// The shim entrypoints for the platform to call.
    pub entrypoints: MacosShimEntrypoints<FS>,
    /// A handle to the running process.
    pub process: MacosShimProcess,
    /// The initial register state.
    pub initial_ctx: PtRegs,
}

/// A handle to a process loaded via [`MacosShim::load_program`].
///
/// Can be used to retrieve the exit code after the process terminates.
pub struct MacosShimProcess(Arc<AtomicI32>);

impl MacosShimProcess {
    /// Returns the exit code set by the process.
    pub fn exit_code(&self) -> i32 {
        self.0.load(Ordering::Acquire)
    }

    /// Wait for the process to exit, returning its exit code.
    ///
    /// In phase 1 (single-threaded), this is a simple synchronous read since
    /// `run_thread` has already returned by the time the runner calls this.
    pub fn wait(&self) -> i32 {
        self.0.load(Ordering::Acquire)
    }
}

/// The shim entrypoints, implementing `EnterShim` for the macOS platform.
pub struct MacosShimEntrypoints<FS: ShimFS> {
    task: Task<FS>,
    _not_send: core::marker::PhantomData<*const ()>,
}

impl<FS: ShimFS> litebox::shim::EnterShim for MacosShimEntrypoints<FS> {
    type ExecutionContext = PtRegs;

    fn init(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.enter_shim(true, ctx, Task::handle_init_request)
    }

    fn syscall(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.enter_shim(false, ctx, Task::handle_syscall_request)
    }

    fn exception(
        &self,
        _ctx: &mut Self::ExecutionContext,
        _info: &litebox::shim::ExceptionInfo,
    ) -> ContinueOperation {
        // Phase 1: no exception handling, just terminate.
        ContinueOperation::Terminate
    }

    fn interrupt(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.enter_shim(false, ctx, |_, _| {})
    }
}

impl<FS: ShimFS> MacosShimEntrypoints<FS> {
    fn enter_shim(
        &self,
        _is_init: bool,
        ctx: &mut PtRegs,
        f: impl FnOnce(&Task<FS>, &mut PtRegs),
    ) -> ContinueOperation {
        f(&self.task, ctx);
        if self.task.should_terminate() {
            ContinueOperation::Terminate
        } else {
            ContinueOperation::Resume
        }
    }
}

/// Global shim state, shared across all tasks.
struct GlobalState<FS: ShimFS> {
    /// The platform instance (used for diagnostics and time queries).
    #[expect(dead_code, reason = "will be used for clock_gettime and diagnostics")]
    platform: &'static Platform,
    /// The LiteBox instance.
    litebox: LiteBox<Platform>,
    /// The page manager for virtual memory.
    pm: PageManager<Platform, PAGE_SIZE>,
    /// The filesystem implementation.
    fs: FS,
    /// The futex manager for handling futex operations.
    #[expect(dead_code, reason = "will be used when futex syscalls are added")]
    futex_manager: FutexManager<Platform>,
    /// The anonymous pipe implementation.
    #[expect(dead_code, reason = "will be used when pipe syscalls are added")]
    pipes: Pipes<Platform>,
    /// The network subsystem.
    #[expect(dead_code, reason = "will be used when network syscalls are added")]
    net: litebox::sync::Mutex<Platform, Network<Platform>>,
    /// The time when the shim was started.
    #[expect(dead_code, reason = "will be used for clock_gettime and similar")]
    boot_time: <Platform as TimeProvider>::Instant,
    /// Raw file descriptor mapping (integer fd -> TypedFd).
    raw_descriptors: litebox::sync::RwLock<Platform, RawDescriptorStorage>,
    /// Optional sysroot prefix for path rewriting in sys_open.
    sysroot: Option<alloc::string::String>,
}

/// Per-fd state for tracking mmap-hook code patching.
pub(crate) struct MachoPatchState {
    /// VA of the allocated trampoline region.
    pub(crate) trampoline_addr: usize,
    /// Next write offset in the trampoline buffer.
    pub(crate) trampoline_cursor: usize,
}

/// Size of the per-fd trampoline region allocated by the mmap-hook (16 KB).
pub(crate) const MMAP_HOOK_TRAMPOLINE_SIZE: usize = 16 * 1024;

/// A single task (single-threaded for macOS phase 1).
struct Task<FS: ShimFS> {
    global: Arc<GlobalState<FS>>,
    /// Whether this task has been terminated (e.g., via sys_exit).
    terminated: Cell<bool>,
    /// The exit code, shared with `MacosShimProcess`.
    exit_code: Arc<AtomicI32>,
    /// Per-fd patch state for the mmap-hook. Tracks trampoline allocation
    /// and cursor for each fd that has had executable segments mapped.
    patch_cache: core::cell::RefCell<BTreeMap<i32, MachoPatchState>>,
}

impl<FS: ShimFS> Task<FS> {
    /// Returns whether this task should terminate.
    fn should_terminate(&self) -> bool {
        self.terminated.get()
    }

    /// Handle the init request — nothing to do in phase 1.
    fn handle_init_request(&self, ctx: &mut PtRegs) {
        let _ = ctx;
    }

    /// Handle a macOS syscall and write the result back to the register context.
    fn handle_syscall_request(&self, ctx: &mut PtRegs) {
        let request = litebox_common_macos::syscall::MacosSyscallRequest::try_from_raw(ctx);
        let result = self.do_syscall(request, ctx);
        litebox_common_macos::syscall::set_syscall_return(ctx, result);
    }
}
