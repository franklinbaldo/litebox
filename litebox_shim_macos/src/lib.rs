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
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};
use litebox::{
    LiteBox,
    fd::RawDescriptorStorage,
    mm::{PageManager, linux::PAGE_SIZE},
    net::Network,
    pipes::Pipes,
    platform::{PunchthroughProvider as _, PunchthroughToken as _, TimeProvider},
    shim::ContinueOperation,
    sync::futex::FutexManager,
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

/// Per-thread initialization state, set before the thread is resumed.
#[derive(Default)]
#[allow(
    dead_code,
    reason = "BsdThread variant used by bsdthread_create in a future task"
)]
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

/// Per-signal handler registration (matches macOS kernel-facing struct __sigaction layout).
#[derive(Clone, Copy, Default)]
struct SignalHandler {
    /// Signal handler address, or SIG_DFL(0)/SIG_IGN(1).
    handler: u64,
    /// Address of `_sigtramp` from libsystem_platform (passed via sa_tramp).
    tramp: u64,
    /// Signal mask to apply during handler execution (macOS 32-bit sigset_t).
    mask: u32,
    /// SA_* flags (SA_SIGINFO, SA_NODEFER, etc.).
    flags: u32,
}

/// Shared process state, accessible from all threads via `Arc`.
#[allow(
    dead_code,
    reason = "fields used by bsdthread syscalls in future tasks"
)]
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
    /// Next thread ID to allocate (starts at 2; main thread is 1).
    next_tid: AtomicI32,
    /// Next Mach thread port to allocate.
    next_mach_port: AtomicU32,
    /// Per-signal handler table. Indexed by signal number (1-31; index 0 unused).
    signal_handlers: litebox::sync::Mutex<Platform, [SignalHandler; 32]>,
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
            next_tid: AtomicI32::new(2),
            next_mach_port: AtomicU32::new(0x0403),
            signal_handlers: litebox::sync::Mutex::new([SignalHandler::default(); 32]),
        }
    }
}

/// Arguments for spawning a new macOS thread.
struct NewThreadArgs<FS: ShimFS> {
    task: Task<FS>,
}

impl<FS: ShimFS> litebox::shim::InitThread for NewThreadArgs<FS> {
    type ExecutionContext = litebox_common_linux::PtRegs;

    fn init(
        self: alloc::boxed::Box<Self>,
    ) -> alloc::boxed::Box<dyn litebox::shim::EnterShim<ExecutionContext = Self::ExecutionContext>>
    {
        let Self { task } = *self;
        alloc::boxed::Box::new(MacosShimEntrypoints { task })
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
            fd_paths: litebox::sync::RwLock::new(BTreeMap::new()),
            shared_cache_base: AtomicU64::new(0),
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
        let process = Arc::new(Process::new());

        self.initialize_stdio();

        let entrypoints = MacosShimEntrypoints {
            task: Task {
                global: self.0.clone(),
                process: process.clone(),
                tid: 1,
                terminated: AtomicBool::new(false),
                patch_cache: litebox::sync::Mutex::new(BTreeMap::new()),
                init_state: litebox::sync::Mutex::new(ThreadInitState::None),
                blocked_signals: AtomicU32::new(0),
            },
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
            process: MacosShimProcess(process),
            initial_ctx,
        })
    }

    /// Get the global page manager.
    pub fn page_manager(&self) -> &PageManager<Platform, PAGE_SIZE> {
        &self.0.pm
    }

    /// Install shared cache regions into the guest address space.
    ///
    /// Each region is mapped at `guest_addr` with the given data and protection.
    /// RX (executable) regions are patched for SVC rewriting before being made
    /// executable. The cache base address is recorded for `shared_region_check_np`.
    ///
    /// `cache_base` is typically `0x180000000`.
    /// `regions` is a slice of `(guest_addr, data, is_executable)` tuples.
    #[allow(clippy::missing_panics_doc, clippy::cast_possible_truncation)]
    pub fn install_shared_cache(
        &self,
        cache_base: u64,
        regions: &[(u64, &[u8], bool)],
        reserved_extents: &[(u64, u64)],
    ) {
        use litebox::mm::linux::PAGE_SIZE;
        use litebox::platform::{
            RawConstPointer as _, RawMutPointer as _, SystemInfoProvider as _,
        };
        use litebox_common_linux::MapFlags;
        use litebox_common_linux::ProtFlags;

        let syscall_entry = litebox_platform_multiplex::platform().get_syscall_entry_point();

        // Build a sorted list of all region page-aligned extents so we can find
        // gaps for trampoline placement.  Each entry is (aligned_start, aligned_end).
        // Include both the regions we're mapping AND any reserved extents (e.g.
        // the host's shared cache global mappings) so that trampolines never
        // overlap with existing memory.
        let mut all_extents: Vec<(u64, u64)> = reserved_extents.to_vec();
        all_extents.extend(regions.iter().map(|&(guest_addr, data, _)| {
            let aligned_start = guest_addr & !(PAGE_SIZE as u64 - 1);
            let aligned_end =
                (guest_addr + data.len() as u64 + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);
            (aligned_start, aligned_end)
        }));
        all_extents.sort_unstable();

        // Pass 1: map ALL regions as RW at their fixed addresses.
        // For regions on macOS-on-macOS, the host process may already have
        // these regions mapped from its own shared cache.  Mapping failures
        // are silently ignored — the host data is the same as what we would
        // write.  We track which regions mapped successfully so Pass 2 only
        // patches regions we own.
        let mut mapped_ok: Vec<bool> = Vec::with_capacity(regions.len());
        for &(guest_addr, data, is_executable) in regions {
            let aligned_start = guest_addr & !(PAGE_SIZE as u64 - 1);
            let aligned_end =
                (guest_addr + data.len() as u64 + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);
            let aligned_len = (aligned_end - aligned_start) as usize;
            let offset_in_page = (guest_addr - aligned_start) as usize;

            let rw_flags = MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED;
            let map_result: Result<MutPtr<u8>, _> = litebox_common_linux::mm::do_mmap(
                &self.0.pm,
                Some(aligned_start as usize),
                aligned_len,
                ProtFlags::PROT_READ_WRITE,
                rw_flags,
                false,
                |_| Ok(0),
            );

            match map_result {
                Ok(mapped_ptr) => {
                    mapped_ptr
                        .copy_from_slice(offset_in_page, data)
                        .expect("install_shared_cache: copy_from_slice failed");
                    mapped_ok.push(true);
                }
                Err(_) if !is_executable => {
                    // Non-executable region mapping failed — the host likely
                    // already has this data mapped from the shared cache.
                    log_unsupported!(
                        "install_shared_cache: skipping non-exec region at {:#x} (len {:#x}): \
                         host already maps this address",
                        aligned_start,
                        aligned_len
                    );
                    mapped_ok.push(false);
                }
                Err(_) => {
                    // Executable region mapping failed — the host may already
                    // occupy this address (e.g. small global metadata regions
                    // like slide info stubs).  Log and skip — the host data is
                    // identical to what we would write.
                    log_unsupported!(
                        "install_shared_cache: skipping exec region at {:#x} (len {:#x}): \
                         host already maps this address",
                        aligned_start,
                        aligned_len
                    );
                    mapped_ok.push(false);
                }
            }
        }

        // Pass 2: for each executable region that was successfully mapped,
        // find a nearby gap for the trampoline, patch SVC sites, and set R-X
        // permissions.
        for (idx, &(guest_addr, data, is_executable)) in regions.iter().enumerate() {
            if !is_executable || !mapped_ok[idx] {
                continue;
            }

            let aligned_start = guest_addr & !(PAGE_SIZE as u64 - 1);
            let aligned_end =
                (guest_addr + data.len() as u64 + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);
            let aligned_len = (aligned_end - aligned_start) as usize;
            let offset_in_page = (guest_addr - aligned_start) as usize;

            let tramp_size = ((data.len() / (1024 * 1024)) + 1) * 4 * PAGE_SIZE;

            // Find the best gap for the trampoline: scan the sorted extents
            // for a gap within ±128MB of the code region's midpoint.
            let code_mid = aligned_start + aligned_len as u64 / 2;
            let branch_range: u64 = 128 * 1024 * 1024; // ±128MB
            let tramp_addr = Self::find_trampoline_gap(
                &all_extents,
                code_mid,
                branch_range,
                tramp_size as u64,
                PAGE_SIZE as u64,
            )
            .unwrap_or_else(|| {
                panic!(
                    "install_shared_cache: no gap for trampoline near code at {:#x} (size {:#x})",
                    aligned_start, aligned_len
                )
            });

            // Record the trampoline extent so future gap searches don't overlap.
            let tramp_extent = (tramp_addr, tramp_addr + tramp_size as u64);
            let insert_pos = all_extents
                .binary_search_by_key(&tramp_addr, |e| e.0)
                .unwrap_or_else(|i| i);
            all_extents.insert(insert_pos, tramp_extent);

            // Allocate the trampoline with MAP_FIXED at the computed address.
            let tramp_flags = MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED;
            let tramp_ptr: MutPtr<u8> = litebox_common_linux::mm::do_mmap(
                &self.0.pm,
                Some(tramp_addr as usize),
                tramp_size,
                ProtFlags::PROT_READ_WRITE,
                tramp_flags,
                false,
                |_| Ok(0),
            )
            .expect("install_shared_cache: trampoline do_mmap failed");
            let tramp_addr_usize = tramp_ptr.as_usize();

            // Get mutable slices for patching.
            // SAFETY: We just allocated these RW regions and no other code is
            // accessing them yet (called during setup before guest runs).
            let code_slice = unsafe {
                core::slice::from_raw_parts_mut(aligned_start as usize as *mut u8, aligned_len)
            };
            let code_to_patch = &mut code_slice[offset_in_page..offset_in_page + data.len()];

            let tramp_slice =
                unsafe { core::slice::from_raw_parts_mut(tramp_addr_usize as *mut u8, tramp_size) };

            let mut tramp_cursor = 0usize;
            tramp_cursor = litebox_syscall_rewriter_macho::patch_code_segment(
                code_to_patch,
                guest_addr,
                tramp_slice,
                tramp_addr,
                tramp_cursor,
                syscall_entry as u64,
            )
            .expect("install_shared_cache: patch_code_segment failed");
            let _ = tramp_cursor;

            // mprotect trampoline to R-X.
            litebox_common_linux::mm::sys_mprotect(
                &self.0.pm,
                MutPtr::from_usize(tramp_addr_usize),
                tramp_size,
                ProtFlags::PROT_READ_EXEC,
            )
            .expect("install_shared_cache: trampoline mprotect failed");

            // mprotect code region to R-X.
            litebox_common_linux::mm::sys_mprotect(
                &self.0.pm,
                MutPtr::from_usize(aligned_start as usize),
                aligned_len,
                ProtFlags::PROT_READ_EXEC,
            )
            .expect("install_shared_cache: code mprotect failed");
        }

        // Record the cache base address.
        self.0
            .shared_cache_base
            .store(cache_base, Ordering::Release);
    }

    /// Find a page-aligned gap within `±branch_range` of `code_mid` that can
    /// hold `tramp_size` bytes without overlapping any extent in `extents`.
    ///
    /// `extents` must be sorted by start address.  Returns the gap start
    /// address, or `None` if no suitable gap exists.
    fn find_trampoline_gap(
        extents: &[(u64, u64)],
        code_mid: u64,
        branch_range: u64,
        tramp_size: u64,
        page_size: u64,
    ) -> Option<u64> {
        let range_lo = code_mid.saturating_sub(branch_range);
        let range_hi = code_mid.saturating_add(branch_range);

        // Candidate gaps: before the first extent, between consecutive extents,
        // and after the last extent — all clipped to [range_lo, range_hi].
        // Pick the gap whose midpoint is closest to `code_mid`.
        let mut best: Option<(u64, u64)> = None; // (distance_to_code, gap_start)

        // Helper to consider a candidate gap [gap_lo, gap_hi) clipped to the
        // branch range.
        let mut consider = |gap_lo: u64, gap_hi: u64| {
            let lo = gap_lo.max(range_lo);
            let hi = gap_hi.min(range_hi);
            if hi <= lo || hi - lo < tramp_size {
                return;
            }
            // Page-align the candidate.
            let aligned_lo = (lo + page_size - 1) & !(page_size - 1);
            if aligned_lo + tramp_size > hi {
                return;
            }
            // Pick the page-aligned start closest to code_mid.
            let candidate = if code_mid >= aligned_lo && code_mid <= hi - tramp_size {
                code_mid & !(page_size - 1)
            } else if code_mid < aligned_lo {
                aligned_lo
            } else {
                ((hi - tramp_size) & !(page_size - 1)).max(aligned_lo)
            };
            if candidate + tramp_size > hi {
                return;
            }
            let dist = code_mid.abs_diff(candidate + tramp_size / 2);
            if best.is_none_or(|(d, _)| dist < d) {
                best = Some((dist, candidate));
            }
        };

        // Gap before the first extent.
        if let Some(&(first_start, _)) = extents.first() {
            consider(0, first_start);
        }
        // Gaps between consecutive extents.
        for w in extents.windows(2) {
            consider(w[0].1, w[1].0);
        }
        // Gap after the last extent.
        if let Some(&(_, last_end)) = extents.last() {
            consider(last_end, u64::MAX - page_size);
        }

        best.map(|(_, addr)| addr)
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
pub struct MacosShimProcess(Arc<Process>);

impl MacosShimProcess {
    /// Returns the exit code set by the process.
    pub fn exit_code(&self) -> i32 {
        self.0.exit_code.load(Ordering::Acquire)
    }

    /// Wait for the process to exit, returning its exit code.
    ///
    /// Spins until `group_exit` is set or `nr_threads` reaches 0.
    pub fn wait(&self) -> i32 {
        loop {
            if self.0.group_exit.load(Ordering::Acquire) {
                return self.0.exit_code.load(Ordering::Acquire);
            }
            if self.0.nr_threads.load(Ordering::Acquire) <= 0 {
                return self.0.exit_code.load(Ordering::Acquire);
            }
            core::hint::spin_loop();
        }
    }
}

/// The shim entrypoints, implementing `EnterShim` for the macOS platform.
pub struct MacosShimEntrypoints<FS: ShimFS> {
    task: Task<FS>,
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
        ctx: &mut Self::ExecutionContext,
        info: &litebox::shim::ExceptionInfo,
    ) -> ContinueOperation {
        // The platform passes the Linux signal number in info.esr.
        // Convert to macOS signal number for the guest.
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        let macos_signum = syscalls::signal::linux_to_macos_signal(info.esr as i32);

        // Look up the handler for this signal.
        let handler = {
            let handlers = self.task.process.signal_handlers.lock();
            #[allow(clippy::cast_sign_loss)]
            handlers[macos_signum as usize]
        };

        match handler.handler {
            0 => {
                // SIG_DFL: terminate (default behavior for SIGSEGV, SIGBUS, etc.)
                log_unsupported!(
                    "EXCEPTION at pc={:#x} sp={:#x} signal={} (SIG_DFL → terminate)",
                    ctx.pc,
                    ctx.sp,
                    macos_signum
                );
                log_unsupported!(
                    "  x0={:#x} x1={:#x} x2={:#x} x3={:#x} x16={:#x} fault_addr={:#x}",
                    ctx.regs[0],
                    ctx.regs[1],
                    ctx.regs[2],
                    ctx.regs[3],
                    ctx.regs[16],
                    info.fault_address
                );
                self.task.process.group_exit.store(true, Ordering::Release);
                self.task.terminated.store(true, Ordering::Release);
                ContinueOperation::Terminate
            }
            1 => {
                // SIG_IGN: ignore and resume.
                log_unsupported!(
                    "EXCEPTION at pc={:#x} signal={} (SIG_IGN → ignore)",
                    ctx.pc,
                    macos_signum
                );
                ContinueOperation::Resume
            }
            _ => {
                // User handler: deliver signal via XNU signal frame.
                self.task
                    .deliver_signal(ctx, macos_signum, info.fault_address, &handler);
                ContinueOperation::Resume
            }
        }
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
    /// The platform instance (used for diagnostics, time queries, and punchthrough).
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
    /// Maps raw fd numbers to their open paths (for `F_GETPATH` support).
    fd_paths: litebox::sync::RwLock<Platform, BTreeMap<usize, String>>,
    /// Base address of the installed shared cache (0 if not installed).
    pub(crate) shared_cache_base: AtomicU64,
    /// Optional sysroot prefix for path rewriting in sys_open.
    #[expect(
        dead_code,
        reason = "will be used when sys_open path rewriting is implemented"
    )]
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

/// Per-thread task state.
struct Task<FS: ShimFS> {
    global: Arc<GlobalState<FS>>,
    /// Shared process state.
    process: Arc<Process>,
    /// Thread ID for this thread.
    tid: i32,
    /// Whether this thread has been terminated.
    terminated: AtomicBool,
    /// Per-fd patch state for the mmap-hook. Tracks trampoline allocation
    /// and cursor for each fd that has had executable segments mapped.
    patch_cache: litebox::sync::Mutex<Platform, BTreeMap<i32, MachoPatchState>>,
    /// Initialization state for this thread (set before first entry).
    init_state: litebox::sync::Mutex<Platform, ThreadInitState>,
    /// Per-thread blocked signal mask (macOS 32-bit sigset_t).
    blocked_signals: AtomicU32,
}

impl<FS: ShimFS> Task<FS> {
    /// Returns whether this task should terminate.
    fn should_terminate(&self) -> bool {
        self.terminated.load(Ordering::Acquire) || self.process.group_exit.load(Ordering::Acquire)
    }

    /// Handle the init request — set up registers for new threads.
    fn handle_init_request(&self, ctx: &mut PtRegs) {
        let state = {
            let mut guard = self.init_state.lock();
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

    /// Handle a macOS syscall and write the result back to the register context.
    #[allow(
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation
    )]
    fn handle_syscall_request(&self, ctx: &mut PtRegs) {
        // Debug: trace all syscall numbers
        if cfg!(debug_assertions) {
            let nr = ctx.regs[16];
            if (nr as i64) < 0 {
                let trap = (-(nr as i64)) as usize;
                log_unsupported!(
                    "TRACE: mach_trap({trap}) x0={:#x} x1={:#x} x2={:#x} x3={:#x}",
                    ctx.regs[0],
                    ctx.regs[1],
                    ctx.regs[2],
                    ctx.regs[3]
                );
            } else {
                log_unsupported!(
                    "TRACE: syscall({nr}) x0={:#x} x1={:#x} x2={:#x} x3={:#x} x4={:#x} x5={:#x}",
                    ctx.regs[0],
                    ctx.regs[1],
                    ctx.regs[2],
                    ctx.regs[3],
                    ctx.regs[4],
                    ctx.regs[5]
                );
            }
        }
        let request = litebox_common_macos::syscall::MacosSyscallRequest::try_from_raw(ctx);

        // Sigreturn restores the full register set (including pstate) and must
        // NOT be followed by set_syscall_return, which would overwrite x0 and
        // the carry flag.
        if let litebox_common_macos::syscall::MacosSyscallRequest::Sigreturn { uctx, .. } = &request
        {
            self.sys_sigreturn(ctx, *uctx);
            return;
        }

        let result = self.do_syscall(request, ctx);
        litebox_common_macos::syscall::set_syscall_return(ctx, result);
    }
}
