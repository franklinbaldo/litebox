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
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use litebox::{
    LiteBox,
    fd::{RawDescriptorStorage, TypedFd},
    mm::{PageManager, linux::PAGE_SIZE},
    net::Network,
    pipes::Pipes,
    platform::{PunchthroughProvider as _, PunchthroughToken as _, TimeProvider},
    shim::ContinueOperation,
    sync::futex::FutexManager,
};
use litebox_common_macos::PtRegs;
use litebox_common_macos::errno::Errno;
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
mod semaphore;
pub mod syscalls;
mod wait;

// Mach VM API and POSIX I/O for demand-paging shared cache pages on SIGBUS.
#[allow(dead_code)]
unsafe extern "C" {
    fn mach_task_self() -> u32;
    fn mach_vm_allocate(target_task: u32, address: *mut u64, size: u64, flags: i32) -> i32;
    fn mach_vm_deallocate(target_task: u32, address: u64, size: u64) -> i32;
    fn mach_vm_protect(
        target_task: u32,
        address: u64,
        size: u64,
        set_maximum: i32,
        new_protection: i32,
    ) -> i32;
    fn pread(fd: i32, buf: *mut u8, count: usize, offset: i64) -> isize;
    fn write(fd: i32, buf: *const u8, count: usize) -> isize;
}
/// `VM_FLAGS_FIXED`: Use the specified address exactly.
const VM_FLAGS_FIXED: i32 = 0;
/// `VM_FLAGS_OVERWRITE`: Allow overwriting existing mappings (including
/// kernel-managed shared region mappings).
const VM_FLAGS_OVERWRITE: i32 = 0x4000;
/// `VM_FLAGS_ANYWHERE`: Let the kernel pick any available address.
#[allow(dead_code)]
const VM_FLAGS_ANYWHERE: i32 = 1;
/// `VM_PROT_COPY`: Tell `mach_vm_protect` to create a COW copy of the page
/// (required for shared region pages that don't allow direct protection change).
#[allow(dead_code)]
const VM_PROT_COPY: i32 = 0x10;
/// macOS signal number for SIGBUS (differs from Linux SIGBUS=7).
const MACOS_SIGBUS: i32 = 10;
/// Hardware page size on macOS arm64 (16 KB).
const HW_PAGE_SIZE: u64 = 16384;

/// Debug-print to stderr (for `#![no_std]` crate).
/// Uses the POSIX `write` syscall on fd 2.
macro_rules! debug_eprintln {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        struct StderrWriter;
        impl Write for StderrWriter {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                unsafe { write(2, s.as_ptr(), s.len()) };
                Ok(())
            }
        }
        let _ = writeln!(StderrWriter, $($arg)*);
    }};
}

/// A file-backed source for demand-paging shared cache pages.
///
/// When a SIGBUS occurs at a faulting address within `[vm_start, vm_end)`,
/// the exception handler allocates a fresh 16 KB page and fills it with
/// data from the subcache file at the corresponding file offset.
///
/// The raw file descriptor must remain open for the lifetime of the guest.
/// Ownership of the FD is managed by the caller (the test harness holds
/// the `File` objects alive in `CollectedCache`).
#[derive(Debug, Clone, Copy)]
pub struct DemandPageSource {
    /// Start of the VM address range (page-aligned).
    pub vm_start: u64,
    /// End of the VM address range (page-aligned).
    pub vm_end: u64,
    /// Raw file descriptor for the subcache file (host-side, not guest).
    pub fd: i32,
    /// File offset that corresponds to `vm_start`.
    pub file_offset: u64,
}

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
            semaphore_manager: semaphore::MachSemaphoreManager::new(),
            pipes: Pipes::new(&self.litebox),
            net: litebox::sync::Mutex::new(net),
            boot_time: self.platform.now(),
            litebox: self.litebox,
            raw_descriptors: litebox::sync::RwLock::new(RawDescriptorStorage::new()),
            fd_paths: litebox::sync::RwLock::new(BTreeMap::new()),
            unix_sockets: litebox::sync::RwLock::new(BTreeMap::new()),
            unix_addr_table: litebox::sync::RwLock::new(BTreeMap::new()),
            unix_fd_counter: AtomicUsize::new(0x1_0000),
            kqueues: litebox::sync::RwLock::new(BTreeMap::new()),
            kqueue_fd_counter: AtomicUsize::new(0x2_0000),
            net_proxies: litebox::sync::RwLock::new(BTreeMap::new()),
            shared_cache_base: AtomicU64::new(0),
            shared_cache_end: AtomicU64::new(0),
            demand_page_ranges: litebox::sync::RwLock::new(Vec::new()),
            demand_page_sources: litebox::sync::RwLock::new(Vec::new()),
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
                wait_state: wait::WaitState::new(self.0.platform),
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
    /// `cache_base` is typically the host's ASLR-slid base (e.g. `0x181AC0000`).
    /// `regions` is a slice of `(guest_addr, data, is_executable)` tuples.
    /// `patch_in_place_text` lists `(addr, len)` of __TEXT segments already mapped
    /// by the host's shared cache — these are SVC-patched in place via
    /// `mprotect(RW)` → patch → `mprotect(RX)` without re-mapping.
    /// `demand_page_sources` provides file-backed data for SIGBUS demand-paging
    /// of shared cache pages that the host's shared region doesn't serve.
    #[allow(clippy::missing_panics_doc, clippy::cast_possible_truncation)]
    pub fn install_shared_cache(
        &self,
        cache_base: u64,
        regions: &[(u64, &[u8], bool)],
        reserved_extents: &[(u64, u64)],
        patch_in_place_text: &[(u64, usize)],
        reset_in_place_data: &[(u64, Vec<u8>)],
        demand_page_sources: &[DemandPageSource],
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
        all_extents.extend(patch_in_place_text.iter().map(|&(addr, len)| {
            let aligned_start = addr & !(PAGE_SIZE as u64 - 1);
            let aligned_end =
                (addr + len as u64 + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);
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

        // Pass 1.5: register VMAs for reserved extents (overlapping host cache
        // pages) so that the VMA system knows about them.  Without this,
        // mach_vm_protect / mprotect calls on these addresses fail with
        // "no mapping at this address" (InvalidRange → EACCES).
        //
        // We use `register_existing_mapping` which only inserts VMA entries
        // without touching the actual memory — the host's shared cache pages
        // remain in place.
        {
            use litebox::mm::linux::PageRange;
            use litebox::platform::page_mgmt::MemoryRegionPermissions;

            for &(start, end) in reserved_extents {
                let start_usize = start as usize;
                let end_usize = end as usize;
                // Ensure alignment to PAGE_SIZE (should already be aligned).
                let aligned_start = start_usize & !(PAGE_SIZE - 1);
                let aligned_end = (end_usize + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
                if let Some(page_range) = PageRange::<PAGE_SIZE>::new(aligned_start, aligned_end) {
                    // SAFETY: These pages are already mapped by the host's
                    // shared cache (readable).  We register them as READ-only
                    // so the VMA system can find them for future mprotect calls.
                    // SAFETY: These pages are already mapped by the host's
                    // shared cache (readable).  We register them as READ-only
                    // so the VMA system can find them for future mprotect calls.
                    let registered = unsafe {
                        self.0.pm.register_existing_mapping(
                            page_range,
                            MemoryRegionPermissions::READ,
                            /* is_file_backed */ false,
                            /* replace */ true,
                            /* shared */ false,
                        )
                    };
                    if registered.is_none() {
                        log_unsupported!(
                            "install_shared_cache: failed to register VMA for \
                             reserved extent {:#x}..{:#x}",
                            aligned_start,
                            aligned_end
                        );
                    }
                }
            }
        }

        // Store the reserved extents as demand-page ranges so the exception
        // handler can serve correct file data on SIGBUS instead of terminating.
        {
            let mut ranges = self.0.demand_page_ranges.write();
            ranges.extend_from_slice(reserved_extents);
        }

        // Store file-backed demand-page sources (sorted by vm_start) so the
        // exception handler can look up the correct subcache file and offset
        // for any faulting address.
        {
            let mut sources = self.0.demand_page_sources.write();
            sources.extend_from_slice(demand_page_sources);
            sources.sort_unstable_by_key(|s| s.vm_start);
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
            let candidates = Self::find_trampoline_gap_candidates(
                &all_extents,
                code_mid,
                branch_range,
                tramp_size as u64,
                PAGE_SIZE as u64,
            );
            let tramp_addr = *candidates.first().unwrap_or_else(|| {
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

        // Pass 3: patch-in-place text segments — SKIPPED.
        //
        // On macOS-on-macOS, the shared cache code uses real macOS SVCs that
        // execute correctly on the host kernel.  We skip SVC patching for these
        // segments because:
        //  1. The macOS kernel deadlocks on any attempt to modify shared region
        //     pages (mach_vm_protect, mach_vm_allocate OVERWRITE, mach_vm_deallocate
        //     all hang on shared cache __TEXT pages).
        //  2. The shared cache SVCs are legitimate macOS syscalls that should
        //     pass through to the host kernel (we only need to intercept
        //     guest binary SVCs, which are patched in Pass 2).
        let _ = &patch_in_place_text;
        debug_eprintln!(
            "  Pass 3: skipping {} patch-in-place segments (shared cache SVCs pass through to host)",
            patch_in_place_text.len(),
        );

        // Pass 4: reset in-place __DATA segments to pristine state.
        //
        // On macOS-on-macOS, the host process's dyld has already COW-ed shared
        // cache __DATA pages (e.g. setting sMemoryManagerInitialized = true).
        // The guest's dyld will see this stale state and hit assertions.
        // We fix this by overwriting the host-dirty __DATA pages with pristine
        // data read from the subcache files.  Since these pages are RW, the
        // kernel will COW them automatically on write — no mprotect needed.
        debug_eprintln!(
            "  Pass 4: resetting {} __DATA segments to pristine state",
            reset_in_place_data.len(),
        );
        for &(addr, ref data) in reset_in_place_data {
            debug_eprintln!(
                "    reset __DATA: {:#x}..{:#x} ({} bytes)",
                addr,
                addr + data.len() as u64,
                data.len(),
            );
            // SAFETY: addr points to a RW shared cache __DATA page that is
            // already mapped in our address space.  We are overwriting it with
            // pristine content of the same size.  The kernel will COW the page.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    data.as_ptr(),
                    addr as *mut u8,
                    data.len(),
                );
            }
        }
        debug_eprintln!("  Pass 4: done");

        // Record the cache base address.
        self.0
            .shared_cache_base
            .store(cache_base, Ordering::Release);
        // Record the cache end address from reserved_extents.
        if let Some(max_end) = reserved_extents.iter().map(|&(_, end)| end).max() {
            self.0
                .shared_cache_end
                .store(max_end, Ordering::Release);
        }
    }

    /// Find page-aligned gap candidates within `±branch_range` of `code_mid`
    /// that can hold `tramp_size` bytes without overlapping any extent in
    /// `extents`.
    ///
    /// `extents` must be sorted by start address.  Returns candidates sorted
    /// by distance from `code_mid` (closest first).
    fn find_trampoline_gap_candidates(
        extents: &[(u64, u64)],
        code_mid: u64,
        branch_range: u64,
        tramp_size: u64,
        page_size: u64,
    ) -> alloc::vec::Vec<u64> {
        let range_lo = code_mid.saturating_sub(branch_range);
        let range_hi = code_mid.saturating_add(branch_range);

        // Collect all candidates from gaps, sorted by distance to code_mid.
        let mut candidates: alloc::vec::Vec<(u64, u64)> = alloc::vec::Vec::new(); // (distance, addr)

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
            candidates.push((dist, candidate));
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

        // Sort by distance (closest first).
        candidates.sort_by_key(|&(d, _)| d);
        candidates.into_iter().map(|(_, addr)| addr).collect()
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

        // Demand-paging for shared cache overlap regions.
        //
        // On macOS-on-macOS, the host's shared cache occupies addresses that
        // overlap with the guest's unslid shared cache.  The host only
        // serves pages for its own ASLR slide, so some guest addresses have
        // no physical backing and cause SIGBUS.  When a SIGBUS occurs at an
        // address within a registered demand-page range, we allocate a fresh
        // 16 KB page and fill it with correct data from the subcache file.
        if macos_signum == MACOS_SIGBUS {
            let fault_addr = info.fault_address as u64;
            let in_demand_range = {
                let ranges = self.task.global.demand_page_ranges.read();
                ranges.iter().any(|&(start, end)| fault_addr >= start && fault_addr < end)
            };
            if in_demand_range {
                let hw_page_mask = HW_PAGE_SIZE - 1;
                let page_addr = fault_addr & !hw_page_mask;

                // Allocate a fresh page at the faulting address.
                let mut alloc_addr = page_addr;
                let kr = unsafe {
                    mach_vm_allocate(
                        mach_task_self(),
                        &raw mut alloc_addr,
                        HW_PAGE_SIZE,
                        VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                    )
                };
                if kr != 0 {
                    log_unsupported!(
                        "SIGBUS demand-page: mach_vm_allocate at {:#x} failed: kern_return {}",
                        page_addr,
                        kr
                    );
                    // Fall through to normal exception handling.
                } else {
                    // Try to fill the page with correct data from a subcache file.
                    let filled = {
                        let sources = self.task.global.demand_page_sources.read();
                        // Binary search for the source containing page_addr.
                        let idx = sources.partition_point(|s| s.vm_start <= page_addr);
                        if idx > 0 {
                            let src = &sources[idx - 1];
                            if page_addr >= src.vm_start && page_addr < src.vm_end {
                                let offset_in_source = page_addr - src.vm_start;
                                let file_offset = src.file_offset + offset_in_source;
                                // Clamp read length to not exceed the source range.
                                let remaining = src.vm_end - page_addr;
                                #[allow(clippy::cast_possible_truncation)]
                                let read_len = HW_PAGE_SIZE.min(remaining) as usize;

                                #[allow(clippy::cast_possible_wrap)]
                                let n = unsafe {
                                    pread(
                                        src.fd,
                                        alloc_addr as *mut u8,
                                        read_len,
                                        file_offset as i64,
                                    )
                                };
                                if n > 0 {
                                    log_unsupported!(
                                        "SIGBUS demand-page: mapped file-backed page at {:#x} \
                                         (fault_addr={:#x}, pc={:#x}, fd={}, offset={:#x}, read={})",
                                        page_addr,
                                        fault_addr,
                                        ctx.pc,
                                        src.fd,
                                        file_offset,
                                        n
                                    );
                                    true
                                } else {
                                    log_unsupported!(
                                        "SIGBUS demand-page: pread failed at {:#x} \
                                         (fd={}, offset={:#x}, n={}), using zero page",
                                        page_addr,
                                        src.fd,
                                        file_offset,
                                        n
                                    );
                                    false
                                }
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    };
                    if !filled {
                        log_unsupported!(
                            "SIGBUS demand-page: mapped zero page at {:#x} \
                             (fault_addr={:#x}, pc={:#x}, no file source)",
                            page_addr,
                            fault_addr,
                            ctx.pc
                        );
                    }
                    return ContinueOperation::Resume;
                }
            }
        }

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
                // Set exit code to 128+signal (Unix convention for signal death).
                self.task
                    .process
                    .exit_code
                    .store(128 + macos_signum, Ordering::Release);
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
    /// The Mach semaphore manager for semaphore trap emulation.
    semaphore_manager: semaphore::MachSemaphoreManager,
    /// The anonymous pipe implementation.
    pipes: Pipes<Platform>,
    /// The network subsystem (AF_INET sockets via smoltcp).
    net: litebox::sync::Mutex<Platform, Network<Platform>>,
    /// The time when the shim was started.
    boot_time: <Platform as TimeProvider>::Instant,
    /// Raw file descriptor mapping (integer fd -> TypedFd).
    raw_descriptors: litebox::sync::RwLock<Platform, RawDescriptorStorage>,
    /// Maps raw fd numbers to their open paths (for `F_GETPATH` support).
    fd_paths: litebox::sync::RwLock<Platform, BTreeMap<usize, String>>,
    /// Maps virtual fd numbers to Unix socket objects.
    unix_sockets: litebox::sync::RwLock<
        Platform,
        BTreeMap<usize, Arc<crate::syscalls::unix::UnixSocket<FS>>>,
    >,
    /// Maps Unix socket paths to their bound entries.
    unix_addr_table: litebox::sync::RwLock<
        Platform,
        BTreeMap<alloc::string::String, crate::syscalls::unix::UnixAddrEntry<FS>>,
    >,
    /// Counter for allocating virtual fd numbers for Unix sockets.
    unix_fd_counter: AtomicUsize,
    /// Maps virtual fd numbers to kqueue objects.
    pub(crate) kqueues:
        litebox::sync::RwLock<Platform, BTreeMap<usize, Arc<syscalls::kqueue::KqueueFile<FS>>>>,
    /// Counter for allocating virtual fd numbers for kqueues (starts at 0x2_0000).
    pub(crate) kqueue_fd_counter: AtomicUsize,
    /// Maps raw fd numbers to their NetworkProxy, for polling support.
    pub(crate) net_proxies: litebox::sync::RwLock<
        Platform,
        BTreeMap<usize, Arc<litebox::net::socket_channel::NetworkProxy<Platform>>>,
    >,
    /// Base address of the installed shared cache (0 if not installed).
    pub(crate) shared_cache_base: AtomicU64,
    /// End address (exclusive) of the installed shared cache (0 if not installed).
    pub(crate) shared_cache_end: AtomicU64,
    /// Address ranges for demand-paging shared cache pages on SIGBUS.
    ///
    /// These are the overlapping regions between the guest's unslid shared cache
    /// and the host's ASLR-slid shared cache.  The host's shared region only
    /// serves pages for its own slide, so some addresses within these ranges
    /// have no physical backing and cause SIGBUS when accessed.  When a SIGBUS
    /// occurs at an address within one of these ranges, the exception handler
    /// maps a page filled with correct file data and resumes execution.
    demand_page_ranges: litebox::sync::RwLock<Platform, Vec<(u64, u64)>>,
    /// File-backed sources for demand-paging.
    ///
    /// Sorted by `vm_start`.  When a SIGBUS fault address falls within a
    /// source's `[vm_start, vm_end)`, the handler reads the correct page data
    /// from the subcache file at the computed offset.
    demand_page_sources: litebox::sync::RwLock<Platform, Vec<DemandPageSource>>,
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

/// A strongly-typed FD that can represent any subsystem's file descriptor.
///
/// Used by read/write/close to dispatch to the correct subsystem.
enum StrongFd<FS: ShimFS> {
    FileSystem(Arc<TypedFd<FS>>),
    Pipes(Arc<TypedFd<Pipes<Platform>>>),
    Network(Arc<TypedFd<Network<Platform>>>),
}

impl<FS: ShimFS> StrongFd<FS> {
    /// Resolve a raw integer FD to a strongly-typed FD, trying each subsystem.
    fn from_raw(rds: &RawDescriptorStorage, fd: usize) -> Result<Self, Errno> {
        if let Ok(fd) = rds.fd_from_raw_integer::<FS>(fd) {
            return Ok(StrongFd::FileSystem(fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer::<Pipes<Platform>>(fd) {
            return Ok(StrongFd::Pipes(fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer::<Network<Platform>>(fd) {
            return Ok(StrongFd::Network(fd));
        }
        Err(Errno::EBADF)
    }
}

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
    /// Per-thread wait state for interruptible waits (pipes, futexes, etc.).
    wait_state: wait::WaitState,
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

    /// Handle `pipe()` — create an anonymous pipe.
    ///
    /// Returns `(read_fd, write_fd)` as raw integer FDs.
    #[allow(clippy::unnecessary_wraps)]
    fn sys_pipe(&self) -> Result<(usize, usize), Errno> {
        use core::num::NonZeroUsize;

        let (sender, receiver) = self.global.pipes.create_pipe(
            65536,                          // capacity (standard pipe buffer)
            litebox::pipes::Flags::empty(), // blocking mode
            NonZeroUsize::new(4096),        // PIPE_BUF atomic guarantee
        );

        let mut rds = self.global.raw_descriptors.write();
        let read_fd = rds.fd_into_raw_integer(receiver);
        let write_fd = rds.fd_into_raw_integer(sender);

        log_unsupported!("pipe() → read_fd={read_fd}, write_fd={write_fd}");
        Ok((read_fd, write_fd))
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

        // Pipe returns two values (read_fd in x0, write_fd in x1) via the macOS
        // dual-register return convention. set_syscall_return only sets x0, so
        // we handle pipe specially.
        if let litebox_common_macos::syscall::MacosSyscallRequest::Pipe = &request {
            match self.sys_pipe() {
                Ok((read_fd, write_fd)) => {
                    ctx.regs[0] = read_fd;
                    ctx.regs[1] = write_fd;
                    ctx.pstate &= !litebox_common_macos::syscall::CARRY_BIT;
                }
                Err(errno) => {
                    litebox_common_macos::syscall::set_syscall_return(ctx, Err(errno));
                }
            }
            return;
        }

        let result = self.do_syscall(request, ctx);
        litebox_common_macos::syscall::set_syscall_return(ctx, result);
    }
}
