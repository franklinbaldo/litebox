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
        // Use a fixed-size stack buffer to avoid heap allocation via
        // alloc::format!.  After install_shared_cache patches all SVC sites,
        // malloc/free go through the patched gate and could cause re-entrant
        // syscall_handler calls.
        struct StackWriter {
            buf: [u8; 512],
            pos: usize,
        }
        impl core::fmt::Write for StackWriter {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let bytes = s.as_bytes();
                let remaining = self.buf.len() - self.pos;
                let to_copy = bytes.len().min(remaining);
                self.buf[self.pos..self.pos + to_copy].copy_from_slice(&bytes[..to_copy]);
                self.pos += to_copy;
                Ok(())
            }
        }
        let mut w = StackWriter {
            buf: [0u8; 512],
            pos: 0,
        };
        let _ = core::fmt::Write::write_str(&mut w, "WARNING: unsupported: ");
        let _ = core::fmt::Write::write_fmt(&mut w, args);
        let _ = core::fmt::Write::write_str(&mut w, "\n");
        litebox_platform_multiplex::platform().debug_log_print(
            // SAFETY: the buffer is UTF-8 because we only wrote valid UTF-8 slices.
            unsafe { core::str::from_utf8_unchecked(&w.buf[..w.pos]) },
        );
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
    /// File creation mask (umask). Default 0o022.
    umask: AtomicU32,
    /// Next thread ID to allocate (starts at 2; main thread is 1).
    next_tid: AtomicI32,
    /// Next Mach thread port to allocate.
    next_mach_port: AtomicU32,
    /// Per-signal handler table. Indexed by signal number (1-31; index 0 unused).
    signal_handlers: litebox::sync::Mutex<Platform, [SignalHandler; 32]>,
    /// Resource limits (RLIMIT_*). Indexed by RlimitResource as usize.
    rlimits: [litebox::sync::Mutex<Platform, litebox_common_macos::Rlimit>;
        litebox_common_macos::RlimitResource::COUNT],
    /// Active thread pthread addresses.  Used to suppress premature
    /// `mach_vm_deallocate` on thread stacks before `pthread_join` reads them.
    /// Contains (pthread_addr) for each live spawned thread.
    thread_pthreads: litebox::sync::Mutex<Platform, alloc::collections::BTreeSet<usize>>,
    /// Current working directory.
    cwd: litebox::sync::RwLock<Platform, alloc::string::String>,
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
            umask: AtomicU32::new(0o022),
            next_tid: AtomicI32::new(2),
            next_mach_port: AtomicU32::new(0x0403),
            signal_handlers: litebox::sync::Mutex::new([SignalHandler::default(); 32]),
            rlimits: core::array::from_fn(|i| {
                use litebox_common_macos::{Rlimit, RlimitResource};
                #[allow(clippy::cast_possible_truncation)]
                let lim = match RlimitResource::from_raw(i as u32) {
                    Some(RlimitResource::Nofile) => Rlimit {
                        rlim_cur: 256,
                        rlim_max: u64::MAX,
                    },
                    Some(RlimitResource::Stack) => Rlimit {
                        rlim_cur: 8 * 1024 * 1024,
                        rlim_max: 64 * 1024 * 1024,
                    },
                    Some(RlimitResource::Nproc) => Rlimit {
                        rlim_cur: 2048,
                        rlim_max: 2048,
                    },
                    Some(RlimitResource::Core) => Rlimit {
                        rlim_cur: 0,
                        rlim_max: u64::MAX,
                    },
                    _ => Rlimit {
                        rlim_cur: u64::MAX,
                        rlim_max: u64::MAX,
                    },
                };
                litebox::sync::Mutex::new(lim)
            }),
            thread_pthreads: litebox::sync::Mutex::new(alloc::collections::BTreeSet::new()),
            cwd: litebox::sync::RwLock::new(alloc::string::String::from("/")),
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
mod mig;
mod semaphore;
pub mod syscalls;
mod wait;

// Mach VM API and POSIX I/O for demand-paging shared cache pages on SIGBUS.
#[allow(dead_code)]
unsafe extern "C" {
    fn mach_task_self() -> u32;
    fn mach_thread_self() -> u32;
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

// ── Global demand-page handler state (async-signal-safe) ─────────────────
//
// These statics mirror the demand-page data from GlobalState but are
// accessible from a plain `fn(usize) -> bool` signal handler without
// any instance reference.  They are populated once during
// `install_shared_cache` and persist across execve (the shared cache
// and its demand-page sources are preserved).

/// Maximum number of demand-page ranges we can track.
const MAX_DEMAND_PAGE_RANGES: usize = 128;
/// Maximum number of demand-page sources we can track.
const MAX_DEMAND_PAGE_SOURCES: usize = 256;

/// Demand-page range entries: (start, end) pairs stored as two separate
/// arrays of AtomicU64 for async-signal-safe access.
#[allow(clippy::declare_interior_mutable_const)]
static DEMAND_RANGE_STARTS: [AtomicU64; MAX_DEMAND_PAGE_RANGES] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_DEMAND_PAGE_RANGES]
};
#[allow(clippy::declare_interior_mutable_const)]
static DEMAND_RANGE_ENDS: [AtomicU64; MAX_DEMAND_PAGE_RANGES] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_DEMAND_PAGE_RANGES]
};
/// Number of valid demand-page range entries.
static DEMAND_RANGE_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Demand-page source entries stored as parallel arrays of atomics.
#[allow(clippy::declare_interior_mutable_const)]
static DEMAND_SRC_VM_STARTS: [AtomicU64; MAX_DEMAND_PAGE_SOURCES] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_DEMAND_PAGE_SOURCES]
};
#[allow(clippy::declare_interior_mutable_const)]
static DEMAND_SRC_VM_ENDS: [AtomicU64; MAX_DEMAND_PAGE_SOURCES] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_DEMAND_PAGE_SOURCES]
};
#[allow(clippy::declare_interior_mutable_const)]
static DEMAND_SRC_FDS: [AtomicI32; MAX_DEMAND_PAGE_SOURCES] = {
    const INIT: AtomicI32 = AtomicI32::new(-1);
    [INIT; MAX_DEMAND_PAGE_SOURCES]
};
#[allow(clippy::declare_interior_mutable_const)]
static DEMAND_SRC_FILE_OFFSETS: [AtomicU64; MAX_DEMAND_PAGE_SOURCES] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_DEMAND_PAGE_SOURCES]
};
/// Number of valid demand-page source entries.
static DEMAND_SRC_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Populate the global demand-page statics from the given ranges and sources.
///
/// This must be called exactly once (during `install_shared_cache`).
/// After this call, `demand_page_handler_fn` can serve faults.
fn populate_demand_page_globals(ranges: &[(u64, u64)], sources: &[DemandPageSource]) {
    let range_count = ranges.len().min(MAX_DEMAND_PAGE_RANGES);
    for (i, &(start, end)) in ranges[..range_count].iter().enumerate() {
        DEMAND_RANGE_STARTS[i].store(start, Ordering::Relaxed);
        DEMAND_RANGE_ENDS[i].store(end, Ordering::Relaxed);
    }
    // Release fence so the handler sees all stores above.
    core::sync::atomic::fence(Ordering::Release);
    DEMAND_RANGE_COUNT.store(range_count, Ordering::Release);

    // Sources must be sorted by vm_start (caller ensures this).
    let src_count = sources.len().min(MAX_DEMAND_PAGE_SOURCES);
    for (i, src) in sources[..src_count].iter().enumerate() {
        DEMAND_SRC_VM_STARTS[i].store(src.vm_start, Ordering::Relaxed);
        DEMAND_SRC_VM_ENDS[i].store(src.vm_end, Ordering::Relaxed);
        DEMAND_SRC_FDS[i].store(src.fd, Ordering::Relaxed);
        DEMAND_SRC_FILE_OFFSETS[i].store(src.file_offset, Ordering::Relaxed);
    }
    core::sync::atomic::fence(Ordering::Release);
    DEMAND_SRC_COUNT.store(src_count, Ordering::Release);
}

/// Async-signal-safe demand-page handler called from the platform's
/// `exception_signal_handler` via `DEMAND_PAGE_HANDLER`.
///
/// Returns `true` if the fault was handled (page allocated and filled),
/// `false` if the address is not in a demand-page range.
///
/// # Safety
///
/// Must only be called from signal handler context.  Uses only raw Mach
/// VM calls and `pread` (both async-signal-safe on macOS).
unsafe fn demand_page_handler_fn(fault_addr: usize) -> bool {
    let fault_addr64 = fault_addr as u64;

    // Check if fault address is in any demand-page range.
    let range_count = DEMAND_RANGE_COUNT.load(Ordering::Acquire);
    let mut in_range = false;
    for i in 0..range_count {
        let start = DEMAND_RANGE_STARTS[i].load(Ordering::Relaxed);
        let end = DEMAND_RANGE_ENDS[i].load(Ordering::Relaxed);
        if fault_addr64 >= start && fault_addr64 < end {
            in_range = true;
            break;
        }
    }
    if !in_range {
        return false;
    }

    let hw_page_mask = HW_PAGE_SIZE - 1;
    let page_addr = fault_addr64 & !hw_page_mask;

    // Allocate a fresh page at the faulting address using Mach VM.
    // We must use raw SVC inline assembly to avoid going through the
    // patched shared cache — the C wrapper for mach_vm_allocate is in
    // the shared cache and may touch demand-paged DATA pages itself,
    // causing infinite recursive SIGBUS.
    let mut alloc_addr = page_addr;
    let kr: i32;
    // SAFETY: raw Mach trap — async-signal-safe, no shared cache dependency.
    // mach_task_self_ is a global port number (always the same value, the
    // kernel caches it at known address).  We use the mach_task_self()
    // trap (trap number -28) to get it, then mach_vm_allocate (trap -10).
    unsafe {
        let task_self: u64;
        // mach_task_self() → Mach trap -28
        core::arch::asm!(
            "movn x16, #27",   // x16 = !27 = -28
            "svc #0x80",
            lateout("x0") task_self,
            out("x16") _,
            options(nomem, nostack),
        );
        // mach_vm_allocate(target, &mut addr, size, flags) → Mach trap -10
        let ret: u64;
        let addr_ptr = &raw mut alloc_addr as usize as u64;
        core::arch::asm!(
            "movn x16, #9",    // x16 = !9 = -10
            "svc #0x80",
            in("x0") task_self,
            in("x1") addr_ptr,
            in("x2") HW_PAGE_SIZE,
            in("x3") (VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE) as u64,
            lateout("x0") ret,
            out("x16") _,
        );
        #[allow(clippy::cast_possible_truncation)]
        {
            kr = ret as i32;
        }
    }
    if kr != 0 {
        return false;
    }

    // Try to fill the page with correct data from a subcache file.
    // Binary search for the source containing page_addr.
    let src_count = DEMAND_SRC_COUNT.load(Ordering::Acquire);
    if src_count > 0 {
        // Manual binary search (partition_point equivalent).
        let mut lo = 0usize;
        let mut hi = src_count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if DEMAND_SRC_VM_STARTS[mid].load(Ordering::Relaxed) <= page_addr {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        // lo is now the partition_point: first index where vm_start > page_addr.
        // The candidate source is at lo - 1 (if it exists).
        if lo > 0 {
            let idx = lo - 1;
            let src_start = DEMAND_SRC_VM_STARTS[idx].load(Ordering::Relaxed);
            let src_end = DEMAND_SRC_VM_ENDS[idx].load(Ordering::Relaxed);
            let src_fd = DEMAND_SRC_FDS[idx].load(Ordering::Relaxed);
            let src_offset = DEMAND_SRC_FILE_OFFSETS[idx].load(Ordering::Relaxed);

            if page_addr >= src_start && page_addr < src_end {
                let offset_in_source = page_addr - src_start;
                let file_offset = src_offset + offset_in_source;
                let remaining = src_end - page_addr;
                #[allow(clippy::cast_possible_truncation)]
                let read_len = HW_PAGE_SIZE.min(remaining) as usize;

                // Use raw SVC for pread to avoid shared cache dependency.
                // pread is Unix syscall 153 (SYS_pread) on macOS.
                // SAFETY: alloc_addr points to a freshly allocated page.
                #[allow(clippy::cast_possible_wrap)]
                let _n: i64 = unsafe {
                    let ret: u64;
                    #[allow(clippy::cast_sign_loss)]
                    let fd_u64 = src_fd as u64;
                    core::arch::asm!(
                        "mov x16, {nr}",
                        "svc #0x80",
                        nr = in(reg) (0x200_0000u64 | 0x19eu64), // SYS_pread_nocancel=414 + BSD flag
                        in("x0") fd_u64,
                        in("x1") alloc_addr,
                        in("x2") read_len as u64,
                        in("x3") file_offset,
                        lateout("x0") ret,
                        out("x16") _,
                        options(nostack),
                    );
                    ret as i64
                };
            }
        }
    }

    true
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
            cloexec_fds: litebox::sync::RwLock::new(alloc::collections::BTreeSet::new()),
            unix_sockets: litebox::sync::RwLock::new(BTreeMap::new()),
            unix_addr_table: litebox::sync::RwLock::new(BTreeMap::new()),
            unix_fd_counter: AtomicUsize::new(0x1_0000),
            kqueues: litebox::sync::RwLock::new(BTreeMap::new()),
            kqueue_fd_counter: AtomicUsize::new(0x2_0000),
            net_proxies: litebox::sync::RwLock::new(BTreeMap::new()),
            shared_cache_base: AtomicU64::new(0),
            shared_cache_end: AtomicU64::new(0),
            dyld_entry_point: AtomicUsize::new(0),
            dyld_base: AtomicUsize::new(0),
            dyld_end: AtomicUsize::new(0),
            dyld_bytes: litebox::sync::RwLock::new(None),
            shared_cache_trampoline_addrs: litebox::sync::RwLock::new(Vec::new()),
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
                altstack: litebox::sync::Mutex::new(litebox_common_macos::SigAltStack::DISABLED),
                wait_state: wait::WaitState::new(self.0.platform),
                dir_positions: litebox::sync::Mutex::new(BTreeMap::new()),
                real_mach_port: AtomicU32::new(unsafe { mach_thread_self() }),
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
            reserved_base: load_info.reserved_base,
            slide: load_info.slide,
        })
    }

    /// Get the global page manager.
    pub fn page_manager(&self) -> &PageManager<Platform, PAGE_SIZE> {
        &self.0.pm
    }

    /// Perform queued network interactions with the outside world.
    ///
    /// This function should be invoked in a loop, based on the returned advice.
    pub fn perform_network_interaction(
        &self,
    ) -> litebox::net::PlatformInteractionReinvocationAdvice {
        self.0.net.lock().perform_platform_interaction()
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
    #[allow(
        clippy::missing_panics_doc,
        clippy::cast_possible_truncation,
        clippy::too_many_arguments
    )]
    pub fn install_shared_cache(
        &self,
        cache_base: u64,
        regions: &[(u64, &[u8], bool)],
        reserved_extents: &[(u64, u64)],
        patch_in_place_text: &[(u64, usize)],
        reset_in_place_data: &[(u64, Vec<u8>)],
        demand_page_sources: &[DemandPageSource],
        sigtramp_addr: u64,
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
            let aligned_end = (addr + len as u64 + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);
            (aligned_start, aligned_end)
        }));
        all_extents.sort_unstable();

        // Merge overlapping/adjacent extents.  Without this, nested
        // sub-extents (e.g. patch_in_place_text segments inside a larger
        // preinstalled extent) create false gaps that the trampoline gap
        // finder would use, overwriting valid shared cache code.
        {
            let mut merged_ext: Vec<(u64, u64)> = Vec::with_capacity(all_extents.len());
            for &(s, e) in &all_extents {
                if let Some(last) = merged_ext.last_mut()
                    && s <= last.1
                {
                    // Overlapping or adjacent -- extend.
                    if e > last.1 {
                        last.1 = e;
                    }
                    continue;
                }
                merged_ext.push((s, e));
            }
            all_extents = merged_ext;
        }

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
            let sites = litebox_syscall_rewriter_macho::scan_svc_sites(code_to_patch, guest_addr);
            tramp_cursor = litebox_syscall_rewriter_macho::patch_code_segment_prescan(
                code_to_patch,
                tramp_slice,
                tramp_addr,
                tramp_cursor,
                syscall_entry as u64,
                &sites,
            )
            .expect("install_shared_cache: patch_code_segment_prescan failed");

            // Write the TLS table address into the trampoline header at offset 8.
            // patch_code_segment_prescan writes the syscall entry callback at offset 0
            // but leaves offset 8 (TLS table ptr) as zero for the caller to fill.
            if tramp_cursor > 0 {
                let tls_addr = litebox_common_linux::HOST_TLS_TABLE_ADDR
                    .load(core::sync::atomic::Ordering::Acquire);
                tramp_slice[8..16].copy_from_slice(&tls_addr.to_le_bytes());
            }
            // Record the trampoline address so we can update its TLS table
            // pointer after execve.
            if tramp_cursor > 0 {
                self.0
                    .shared_cache_trampoline_addrs
                    .write()
                    .push((tramp_addr, tramp_size));
            }
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

        // Pass 3: patch-in-place text segments.
        //
        // These are host-resident shared cache __TEXT segments.  The macOS
        // kernel maps them into a shared region whose pages cannot be modified
        // in the parent process (mach_vm_protect / mach_vm_allocate OVERWRITE /
        // mach_vm_deallocate all deadlock).  However, inside a forked child
        // process the COW semantics allow us to replace them with private
        // anonymous pages via mmap(MAP_FIXED).  We copy the original code
        // content into our private pages, then patch SVCs exactly as Pass 2
        // does for heap-backed executable regions.
        //
        // CRITICAL: We use raw syscalls (inline assembly) instead of litebox's
        // do_mmap / sys_mprotect for page replacement in this pass.  The
        // litebox MM layer's VMA tracking uses a BTree that allocates via the
        // global allocator (malloc).  Between the mmap(MAP_FIXED) call (which
        // zeroes the old shared cache pages) and copying the saved content back,
        // any malloc call would try to execute code on the now-zeroed pages,
        // causing a SIGBUS → panic → format → malloc → SIGBUS infinite loop.
        // Raw syscalls avoid this by returning control directly to our code
        // with no intermediate allocations.
        //
        // ALSO CRITICAL: Once libsystem_kernel's __TEXT is patched, ALL libc
        // calls (malloc, free, write, mmap, etc.) are intercepted by the
        // litebox gate.  The gate requires a TLS table entry for the current
        // thread, which doesn't exist during install_shared_cache.  Therefore
        // we split Pass 3 into two phases:
        //   Phase A: pre-compute all allocations (saved buffers, SVC sites,
        //            trampoline addresses) while libc still works.
        //   Phase B: patch all segments using only raw syscalls and pre-allocated
        //            data, with ZERO malloc/free calls.
        //
        // This ensures ALL guest SVCs — including those in shared cache
        // library code — are intercepted by the litebox shim.

        // Phase A: pre-compute everything while libc/malloc still works.
        #[allow(clippy::items_after_statements)]
        struct SegmentPlan {
            aligned_start: u64,
            aligned_len: usize,
            saved: alloc::vec::Vec<u8>,
            svc_sites: alloc::vec::Vec<litebox_syscall_rewriter_macho::PatchSite>,
            tramp_addr: u64,
            tramp_size: usize,
        }

        let tls_table_addr =
            litebox_common_linux::HOST_TLS_TABLE_ADDR.load(core::sync::atomic::Ordering::Acquire);

        // `_sigtramp` is the kernel's re-entry point for signal delivery; it
        // uses `sigreturn` (SVC #0x80) to return from the handler.  If we patch
        // that SVC, every signal delivery would go through the gate → TLS lookup
        // → sentinel → BRK → infinite loop.  Even during guest execution,
        // `sigreturn` must pass through to the host kernel.
        //
        // The caller resolves `_sigtramp` before the shared cache is patched
        // (via Mach-O symbol table walk) and passes it as `sigtramp_addr`.
        // A value of 0 means the caller could not resolve it; in that case
        // we skip segment exclusion (all SVC sites get patched).

        // Step 1: Compute aligned ranges for all segments, tracking which
        // original segments belong to each aligned range.  Shared cache
        // __TEXT segments are densely packed, so adjacent segments separated
        // by less than 16KB will produce overlapping 16KB-aligned ranges.
        // We MUST merge these to avoid a later MAP_FIXED destroying pages
        // that an earlier iteration already patched and mprotected.
        #[allow(clippy::items_after_statements)]
        struct AlignedEntry {
            aligned_start: u64,
            aligned_end: u64,
            /// Original segments (guest_addr, len) within this aligned range.
            /// Segments containing `_sigtramp` are excluded from SVC scanning
            /// but their pages are still included in the MAP_FIXED range.
            segments: alloc::vec::Vec<(u64, usize)>,
        }

        // Compute aligned range for each original segment and sort.
        let mut entries: alloc::vec::Vec<AlignedEntry> =
            alloc::vec::Vec::with_capacity(patch_in_place_text.len());
        for &(guest_addr, len) in patch_in_place_text {
            let a_start = guest_addr & !(HW_PAGE_SIZE - 1);
            let a_end = (guest_addr + len as u64 + HW_PAGE_SIZE - 1) & !(HW_PAGE_SIZE - 1);
            entries.push(AlignedEntry {
                aligned_start: a_start,
                aligned_end: a_end,
                segments: alloc::vec![(guest_addr, len)],
            });
        }
        entries.sort_by_key(|e| e.aligned_start);

        // Step 2: Merge overlapping / adjacent aligned ranges.
        let mut merged: alloc::vec::Vec<AlignedEntry> =
            alloc::vec::Vec::with_capacity(entries.len());
        for entry in entries {
            if let Some(last) = merged.last_mut()
                && entry.aligned_start <= last.aligned_end
            {
                // Overlapping or adjacent — extend.
                if entry.aligned_end > last.aligned_end {
                    last.aligned_end = entry.aligned_end;
                }
                last.segments.extend_from_slice(&entry.segments);
                continue;
            }
            merged.push(entry);
        }

        // Step 3: Build plans from merged ranges.
        let mut plans: alloc::vec::Vec<SegmentPlan> = alloc::vec::Vec::with_capacity(merged.len());

        for me in &merged {
            let aligned_start = me.aligned_start;
            let aligned_len = (me.aligned_end - me.aligned_start) as usize;

            // Save the original code content before replacing the pages.
            let mut saved = alloc::vec![0u8; aligned_len];
            unsafe {
                core::ptr::copy_nonoverlapping(
                    aligned_start as *const u8,
                    saved.as_mut_ptr(),
                    aligned_len,
                );
            }

            // Pre-scan for SVC sites in each constituent segment.
            // Skip scanning in segments that contain `_sigtramp` — their
            // SVCs must NOT be patched.  We still include their pages in
            // the MAP_FIXED range so that overlapping segments work.
            let mut svc_sites: alloc::vec::Vec<litebox_syscall_rewriter_macho::PatchSite> =
                alloc::vec::Vec::new();
            let mut total_code_len: usize = 0;
            for &(guest_addr, len) in &me.segments {
                // Skip SVC scanning for segments containing `_sigtramp`.
                if sigtramp_addr >= guest_addr && sigtramp_addr < guest_addr + len as u64 {
                    continue;
                }
                total_code_len += len;
                let offset_in_merged = (guest_addr - aligned_start) as usize;
                let mut sites = litebox_syscall_rewriter_macho::scan_svc_sites(
                    &saved[offset_in_merged..offset_in_merged + len],
                    guest_addr,
                );
                // Adjust file_offset to be relative to the full aligned
                // region (instead of relative to this sub-segment).
                for site in &mut sites {
                    site.file_offset += offset_in_merged;
                }
                svc_sites.extend(sites);
            }

            // If there are no SVC sites, we still need the plan for
            // B.1 (MAP_FIXED + copy) and B.2 (mprotect RX), but we do
            // NOT need a trampoline.  Allocating a trampoline for empty
            // plans wastes address space and can cause problems when the
            // trampoline page is never actually mapped by B.3.
            if svc_sites.is_empty() {
                plans.push(SegmentPlan {
                    aligned_start,
                    aligned_len,
                    saved,
                    svc_sites,
                    tramp_addr: 0,
                    tramp_size: 0,
                });
                continue;
            }

            let code_len_for_tramp = if total_code_len == 0 {
                aligned_len
            } else {
                total_code_len
            };

            // Find trampoline gap while malloc still works.
            let tramp_size = ((code_len_for_tramp / (1024 * 1024)) + 1) * 4 * HW_PAGE_SIZE as usize;
            let code_mid = aligned_start + aligned_len as u64 / 2;
            let branch_range: u64 = 128 * 1024 * 1024;
            let candidates = Self::find_trampoline_gap_candidates(
                &all_extents,
                code_mid,
                branch_range,
                tramp_size as u64,
                HW_PAGE_SIZE,
            );
            let Some(&tramp_addr) = candidates.first() else {
                continue;
            };

            // Record trampoline extent so future iterations avoid it.
            let tramp_extent = (tramp_addr, tramp_addr + tramp_size as u64);
            let insert_pos = all_extents
                .binary_search_by_key(&tramp_addr, |e| e.0)
                .unwrap_or_else(|i| i);
            all_extents.insert(insert_pos, tramp_extent);

            plans.push(SegmentPlan {
                aligned_start,
                aligned_len,
                saved,
                svc_sites,
                tramp_addr,
                tramp_size,
            });
        }

        // Record Pass 3 trampoline addresses for future TLS table updates.
        // Skip plans with no trampoline (svc_sites was empty).
        {
            let mut addrs = self.0.shared_cache_trampoline_addrs.write();
            for plan in &plans {
                if plan.tramp_size > 0 {
                    addrs.push((plan.tramp_addr, plan.tramp_size));
                }
            }
        }

        // Reset SIGBUS, SIGSEGV, SIGTRAP to SIG_DFL before Phase B,
        // saving the old handlers so we can restore them afterward.
        //
        // The platform's exception_signal_handler calls libc::sigaltstack()
        // internally. Once Phase B patches libsystem_kernel's SVC stubs,
        // that sigaltstack call would go through the litebox gate (no TLS
        // entry for the install thread) → BRK #1 → SIGTRAP → recursive
        // signal delivery → infinite CPU loop.
        //
        // By resetting to SIG_DFL, any signal during Phase B will crash
        // the forked child with a visible signal number (parent sees it
        // via waitpid). This replaces an infinite hang with a diagnosable
        // crash.
        let dfl_sa = [0u8; 24];
        let mut saved_sigbus = [0u8; 24];
        let mut saved_sigsegv = [0u8; 24];
        let mut saved_sigtrap = [0u8; 24];
        unsafe {
            raw_sigaction_set(10, &dfl_sa, &mut saved_sigbus); // SIGBUS
            raw_sigaction_set(11, &dfl_sa, &mut saved_sigsegv); // SIGSEGV
            raw_sigaction_set(5, &dfl_sa, &mut saved_sigtrap); // SIGTRAP
        }

        // Phase B: replace shared cache __TEXT pages with private copies.
        //
        // This is split into three sub-phases to avoid calling `memcpy`
        // (which lives in the shared cache) from non-executable pages:
        //
        //   B.1: For ALL plans: MAP_FIXED(RW) + volatile copy-back.
        //        After this, all shared cache code is on RW pages with
        //        correct content but NOT executable (W^X).
        //
        //   B.2: For ALL plans: mprotect code pages to R-X.
        //        After this, all shared cache code is executable again.
        //        `memcpy` and other libc functions work normally (their
        //        code is on R-X pages with correct bytes).
        //
        //   B.3: For each plan with SVC sites:
        //        - MAP_FIXED trampoline (RW)
        //        - mprotect code to RW
        //        - patch SVCs (can call memcpy — other plans' code is R-X)
        //        - mprotect code + trampoline to R-X
        //
        // This avoids the chicken-and-egg problem: patching code requires
        // writing to code pages (RW), but the patching code itself calls
        // `memcpy` which must be on executable pages (R-X).

        // B.1: MAP_FIXED + volatile copy-back for ALL plans.
        for plan in &plans {
            let map_result = unsafe {
                raw_mmap(
                    plan.aligned_start as usize,
                    plan.aligned_len,
                    RAW_PROT_READ | RAW_PROT_WRITE,
                    RAW_MAP_ANON | RAW_MAP_PRIVATE | RAW_MAP_FIXED,
                )
            };
            match map_result {
                Err(_) | Ok(0) => {
                    continue;
                }
                Ok(returned_addr) => {
                    if returned_addr != plan.aligned_start as usize {
                        continue;
                    }
                }
            }

            // Copy saved content back using volatile byte-by-byte loop.
            // Cannot use `copy_nonoverlapping` (calls `memcpy` which is
            // in the shared cache — those pages may already be RW/zeroed
            // from a prior iteration's MAP_FIXED).
            unsafe {
                let src = plan.saved.as_ptr();
                let dst = plan.aligned_start as usize as *mut u8;
                let len = plan.aligned_len;
                let mut i = 0usize;
                while i < len {
                    core::ptr::write_volatile(dst.add(i), core::ptr::read_volatile(src.add(i)));
                    i += 1;
                }
            }
        }

        // B.2: mprotect ALL code pages to R-X.
        // After this, `memcpy` and other shared cache functions are
        // executable again (correct code on R-X pages).
        for plan in &plans {
            let _ = unsafe {
                raw_mprotect(
                    plan.aligned_start as usize,
                    plan.aligned_len,
                    RAW_PROT_READ | RAW_PROT_EXEC,
                )
            };
        }

        // B.3: Patch SVCs and set up trampolines.
        // At this point, all shared cache code is R-X.  For each plan
        // that has SVC sites, we temporarily make its pages RW, patch,
        // then restore R-X.  `memcpy` calls during patching are safe
        // because other plans' code pages (including the one containing
        // `memcpy`) remain R-X.
        for plan in &plans {
            if plan.svc_sites.is_empty() {
                continue;
            }

            // Patch SVC sites for this plan.

            // Allocate trampoline pages (RW).
            let tramp_result = unsafe {
                raw_mmap(
                    plan.tramp_addr as usize,
                    plan.tramp_size,
                    RAW_PROT_READ | RAW_PROT_WRITE,
                    RAW_MAP_ANON | RAW_MAP_PRIVATE | RAW_MAP_FIXED,
                )
            };
            let Ok(tramp_addr_usize) = tramp_result else {
                continue;
            };

            // Make code pages RW for patching.
            let _ = unsafe {
                raw_mprotect(
                    plan.aligned_start as usize,
                    plan.aligned_len,
                    RAW_PROT_READ | RAW_PROT_WRITE,
                )
            };

            // Patch SVCs.  The full aligned region is passed as code;
            // SVC site file_offsets are relative to its start.
            let code_slice = unsafe {
                core::slice::from_raw_parts_mut(
                    plan.aligned_start as usize as *mut u8,
                    plan.aligned_len,
                )
            };
            let tramp_slice = unsafe {
                core::slice::from_raw_parts_mut(tramp_addr_usize as *mut u8, plan.tramp_size)
            };

            let patch_result = litebox_syscall_rewriter_macho::patch_code_segment_prescan(
                code_slice,
                tramp_slice,
                plan.tramp_addr,
                0,
                syscall_entry as u64,
                &plan.svc_sites,
            );
            let Ok(tramp_cursor) = patch_result else {
                // Restore R-X even on error.
                let _ = unsafe {
                    raw_mprotect(
                        plan.aligned_start as usize,
                        plan.aligned_len,
                        RAW_PROT_READ | RAW_PROT_EXEC,
                    )
                };
                continue;
            };

            // Write TLS table address into trampoline header at offset 8.
            // Use byte-by-byte volatile writes (u64 write was silently failing).
            if tramp_cursor > 0 {
                unsafe {
                    let tls_bytes = (tls_table_addr as u64).to_le_bytes();
                    let base = tramp_slice.as_mut_ptr();
                    let mut j = 0usize;
                    while j < 8 {
                        core::ptr::write_volatile(base.add(8 + j), tls_bytes[j]);
                        j += 1;
                    }
                }
            }

            // Restore code and trampoline to R-X.
            let _ = unsafe {
                raw_mprotect(
                    plan.aligned_start as usize,
                    plan.aligned_len,
                    RAW_PROT_READ | RAW_PROT_EXEC,
                )
            };
            let _ = unsafe {
                raw_mprotect(
                    tramp_addr_usize,
                    plan.tramp_size,
                    RAW_PROT_READ | RAW_PROT_EXEC,
                )
            };
        }

        // NOTE: Signal handlers remain SIG_DFL here.  They cannot be
        // restored yet because the install thread has no TLS entry —
        // if the platform's exception handler ran, its libc calls would
        // go through the gate → BRK #1 → infinite loop.  The handlers
        // are re-registered by the platform's run_thread after the TLS
        // entry is populated.

        // Drop all saved buffers.  This calls free() which may go through
        // patched libsystem_kernel.  We cannot avoid this, but free()
        // typically just marks memory as available without calling munmap
        // for small allocations.  For large allocations (>= ~64KB), the
        // allocator may call munmap.  Since libsystem_kernel is now patched,
        // munmap would go through the gate → BRK #1.
        //
        // To avoid this, we intentionally leak the saved buffers.  The
        // process will exit shortly after (via _exit in the forked child),
        // so the kernel will reclaim all memory.
        core::mem::forget(plans);

        // Pass 4: reset in-place __DATA segments to pristine state.
        //
        // On macOS-on-macOS, the host process's dyld has already COW-ed shared
        // cache __DATA pages (e.g. setting sMemoryManagerInitialized = true).
        // The guest's dyld will see this stale state and hit assertions.
        // We fix this by overwriting the host-dirty __DATA pages with pristine
        // data read from the subcache files.  Since these pages are RW, the
        // kernel will COW them automatically on write — no mprotect needed.
        //
        // NOTE: No debug_eprintln! here — libsystem_kernel's SVCs are patched
        // by Pass 3, so libc write() would go through the litebox gate (which
        // has no TLS entry for this thread).
        for &(addr, ref data) in reset_in_place_data {
            // SAFETY: addr points to a RW shared cache __DATA page that is
            // already mapped in our address space.  We are overwriting it with
            // pristine content of the same size.  The kernel will COW the page.
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr(), addr as *mut u8, data.len());
            }
        }

        // Pass 5b: Patch `_tlv_bootstrap` to bypass the error handler.
        //
        // On macOS, the shared cache builder patches the first instruction of
        // `_tlv_bootstrap` (the TLS variable resolver) to `B _tlv_bootstrap_error`.
        // Normally, dyld's initializer for `libdyld.dylib` patches this back
        // to NOP after TLS infrastructure is set up.  Since we skip shared cache
        // library initializers (`patch_skip_initializers`), this never happens.
        //
        // The fix: patch the first instruction of `_tlv_bootstrap` from
        // `B _tlv_bootstrap_error` to NOP, allowing the fast-path TLS lookup
        // to execute.
        #[cfg(feature = "platform_macos_userland")]
        {
            unsafe extern "C" {
                fn dlsym(
                    handle: *const core::ffi::c_void,
                    symbol: *const u8,
                ) -> *const core::ffi::c_void;
            }
            const RTLD_DEFAULT: *const core::ffi::c_void = -2_isize as *const core::ffi::c_void;

            let addr = unsafe { dlsym(RTLD_DEFAULT, c"_tlv_bootstrap".as_ptr().cast()) };
            if !addr.is_null() {
                let addr_usize = addr as usize;
                let insn = unsafe { core::ptr::read_volatile(addr_usize as *const u32) };
                // Verify it is an unconditional branch (B) instruction.
                // Encoding: bits [31:26] == 0b000101 => top byte & 0xFC == 0x14.
                let is_branch = (insn & 0xFC00_0000) == 0x1400_0000;
                if is_branch {
                    let page_start = addr_usize & !(HW_PAGE_SIZE as usize - 1);
                    let page_len = HW_PAGE_SIZE as usize;

                    // Make the page writable.
                    let mp = unsafe {
                        raw_mprotect(page_start, page_len, RAW_PROT_READ | RAW_PROT_WRITE)
                    };
                    if mp.is_ok() {
                        // Write NOP (0xD503201F).
                        const AARCH64_NOP: u32 = 0xD503_201F;
                        unsafe {
                            core::ptr::write_volatile(addr_usize as *mut u32, AARCH64_NOP);
                        }
                        // Restore R-X.
                        let _ = unsafe {
                            raw_mprotect(page_start, page_len, RAW_PROT_READ | RAW_PROT_EXEC)
                        };
                    }
                }
            }
        }

        // ----- Pass 5c: Manually call libc++ and libc++abi initializers -----
        //
        // `patch_skip_initializers` (Pass 4) NOPs the call to
        // `findAndRunAllInitializers` inside `PrebuiltLoader::runInitializers`,
        // which means shared-cache library initializers never run.  This is
        // intentional — most initializers (e.g. libSystem's `__pthread_init`)
        // are destructive in the host process.
        //
        // However, libc++ and libc++abi have idempotent initializers that are
        // required for typed `operator new` support (TMO — Typed Memory
        // Operations).  Without them, any binary compiled with
        // `-ftyped-cxx-new-delete` (e.g. clang) will abort.
        //
        // We iterate loaded dyld images at runtime to find these two libraries,
        // parse their Mach-O headers to locate the `__TEXT,__init_offsets`
        // section (shared-cache format: array of 32-bit offsets from __TEXT
        // start), compute function addresses, and call them directly.
        //
        // Dependency order: libc++abi first, then libc++.
        #[cfg(feature = "platform_macos_userland")]
        {
            unsafe extern "C" {
                fn _dyld_image_count() -> u32;
                fn _dyld_get_image_name(image_index: u32) -> *const u8;
                fn _dyld_get_image_header(image_index: u32) -> *const u8;
                fn _dyld_get_image_vmaddr_slide(image_index: u32) -> isize;
            }

            const MH_MAGIC_64: u32 = 0xFEED_FACF;
            const LC_SEGMENT_64: u32 = 0x19;

            /// Search a Mach-O image for the `__TEXT,__init_offsets` section
            /// and return the init function addresses (header + each 32-bit
            /// offset).
            ///
            /// # Safety
            /// `header` must point to a valid Mach-O 64-bit header in mapped
            /// memory.  The `__init_offsets` section addresses (after slide)
            /// must also be readable.
            #[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
            unsafe fn collect_init_addrs(
                header: *const u8,
                slide: isize,
            ) -> alloc::vec::Vec<usize> {
                unsafe {
                    let mut result = alloc::vec::Vec::new();
                    let magic = core::ptr::read_unaligned(header.cast::<u32>());
                    if magic != MH_MAGIC_64 {
                        return result;
                    }
                    // mach_header_64: 32 bytes total.
                    // ncmds is at offset 16.
                    let ncmds = core::ptr::read_unaligned(header.add(16).cast::<u32>());
                    let mut cmd_ptr = header.add(32);

                    for _ in 0..ncmds {
                        let cmd = core::ptr::read_unaligned(cmd_ptr.cast::<u32>());
                        let cmdsize = core::ptr::read_unaligned(cmd_ptr.add(4).cast::<u32>());

                        if cmd == LC_SEGMENT_64 {
                            // nsects at offset 64 in segment_command_64
                            let nsects = core::ptr::read_unaligned(cmd_ptr.add(64).cast::<u32>());

                            let mut sect_ptr = cmd_ptr.add(72);
                            for _ in 0..nsects {
                                // sectname is 16 bytes at offset 0
                                let expected = b"__init_offsets\0\0";
                                let sect_name_ptr = sect_ptr;
                                let mut name_match = true;
                                for (k, &ch) in expected.iter().enumerate() {
                                    if *sect_name_ptr.add(k) != ch {
                                        name_match = false;
                                        break;
                                    }
                                }
                                if name_match {
                                    let sect_addr =
                                        core::ptr::read_unaligned(sect_ptr.add(32).cast::<u64>());
                                    let sect_size =
                                        core::ptr::read_unaligned(sect_ptr.add(40).cast::<u64>());
                                    // sect_addr is unslid; add slide.
                                    let actual_addr =
                                        (sect_addr as isize).wrapping_add(slide) as usize;
                                    let n_offsets = sect_size as usize / 4;
                                    for j in 0..n_offsets {
                                        let off = core::ptr::read_unaligned(
                                            (actual_addr + j * 4) as *const u32,
                                        );
                                        let func_addr = header as usize + off as usize;
                                        result.push(func_addr);
                                    }
                                }

                                sect_ptr = sect_ptr.add(80);
                            }
                        }

                        cmd_ptr = cmd_ptr.add(cmdsize as usize);
                    }

                    result
                }
            }

            /// Check if a C string ends with the given suffix.
            ///
            /// # Safety
            /// `name_ptr` must point to a valid NUL-terminated string.
            unsafe fn cstr_ends_with(name_ptr: *const u8, suffix: &[u8]) -> bool {
                unsafe {
                    let mut len = 0usize;
                    while *name_ptr.add(len) != 0 {
                        len += 1;
                    }
                    if len < suffix.len() {
                        return false;
                    }
                    let start = len - suffix.len();
                    for (k, &ch) in suffix.iter().enumerate() {
                        if *name_ptr.add(start + k) != ch {
                            return false;
                        }
                    }
                    true
                }
            }

            /// Find a dyld image by suffix, collect its init offsets, and
            /// call each init function.
            ///
            /// # Safety
            /// Init functions must be safe to call (idempotent).
            unsafe fn run_inits_for_image(image_count: u32, suffix: &[u8]) {
                for i in 0..image_count {
                    let name_ptr = unsafe { _dyld_get_image_name(i) };
                    if name_ptr.is_null() {
                        continue;
                    }
                    if unsafe { cstr_ends_with(name_ptr, suffix) } {
                        let header = unsafe { _dyld_get_image_header(i) };
                        let slide = unsafe { _dyld_get_image_vmaddr_slide(i) };
                        let addrs = unsafe { collect_init_addrs(header, slide) };
                        for addr in addrs {
                            let func: unsafe extern "C" fn() =
                                unsafe { core::mem::transmute(addr) };
                            unsafe { func() };
                        }
                        break;
                    }
                }
            }

            let image_count = unsafe { _dyld_image_count() };
            // libc++abi first (dependency of libc++).
            unsafe {
                run_inits_for_image(image_count, b"libc++abi.dylib");
            }
            // Then libc++.
            unsafe {
                run_inits_for_image(image_count, b"libc++.1.dylib");
            }
        }

        // Record the cache base address.
        self.0
            .shared_cache_base
            .store(cache_base, Ordering::Release);
        // Record the cache end address from reserved_extents.
        if let Some(max_end) = reserved_extents.iter().map(|&(_, end)| end).max() {
            self.0.shared_cache_end.store(max_end, Ordering::Release);
        }

        // Populate the global demand-page statics and register the handler
        // with the platform's signal handler.  This allows HOST-side SIGBUS
        // faults (e.g. libc wrappers accessing shared cache DATA pages
        // during the second exec after execve) to be resolved without going
        // through the shim's exception() method.
        populate_demand_page_globals(reserved_extents, demand_page_sources);
        #[cfg(feature = "platform_macos_userland")]
        unsafe {
            litebox_platform_macos_userland::register_demand_page_handler(demand_page_handler_fn);
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
    /// The base address of the reserved memory region (for diagnostics).
    pub reserved_base: usize,
    /// The slide applied to the binary segments (for diagnostics).
    pub slide: usize,
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
    /// Spins until all threads have exited (`nr_threads` reaches 0).
    ///
    /// When `group_exit` is set (the guest called `exit()`), we still
    /// wait for `nr_threads` to reach 0.  Spawned threads will
    /// eventually terminate: either they call a shim-handled syscall
    /// (which checks `should_terminate` and returns `Terminate`), or
    /// they call `bsdthread_terminate` (which decrements `nr_threads`).
    /// If we returned immediately on `group_exit`, the child process
    /// would call `_exit(0)` while host POSIX threads are still running,
    /// causing SIGKILL.
    pub fn wait(&self) -> i32 {
        let mut iter = 0u64;
        loop {
            let exiting = self.0.group_exit.load(Ordering::Acquire);
            let threads = self.0.nr_threads.load(Ordering::Acquire);
            iter += 1;
            if threads <= 0 {
                return self.0.exit_code.load(Ordering::Acquire);
            }
            if exiting && threads <= 1 {
                // group_exit set and only the main thread remains
                // (main thread doesn't decrement nr_threads via
                // bsdthread_terminate, so it stays at 1).
                return self.0.exit_code.load(Ordering::Acquire);
            }
            // If group_exit is set and we've been waiting a while, force
            // return.  Spawned threads may be blocked in real kernel
            // syscalls (e.g. psynch_mutexwait) that cannot be interrupted
            // from userspace.  The forked child's _exit() will clean them
            // up via the kernel.
            if exiting && iter > 10_000_000 {
                return self.0.exit_code.load(Ordering::Acquire);
            }
            core::hint::spin_loop();
        }
    }

    /// Synthetically register pthread thread-start addresses.
    ///
    /// When library initializers are skipped (to avoid double-init SIGKILL),
    /// `bsdthread_register` is never called by the guest.  This method
    /// provides the same information so that `bsdthread_create` works.
    ///
    /// Call this after `load_program` but before `run_thread`.
    pub fn register_pthread_info(
        &self,
        threadstart: u64,
        wqthread: u64,
        pthsize: u32,
        tsd_offset: u32,
    ) {
        self.0.threadstart.store(threadstart, Ordering::Release);
        self.0.wqthread.store(wqthread, Ordering::Release);
        self.0.pthsize.store(pthsize, Ordering::Release);
        self.0.tsd_offset.store(tsd_offset, Ordering::Release);
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
                ranges
                    .iter()
                    .any(|&(start, end)| fault_addr >= start && fault_addr < end)
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
                log_unsupported!(
                    "  lr={:#x} x4={:#x} x5={:#x} x6={:#x} x7={:#x} x8={:#x}",
                    ctx.regs[30],
                    ctx.regs[4],
                    ctx.regs[5],
                    ctx.regs[6],
                    ctx.regs[7],
                    ctx.regs[8]
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
            // When a spawned thread is force-terminated because the main
            // thread called exit() (group_exit), it never reaches
            // bsdthread_terminate and therefore never decrements
            // nr_threads.  Do it here so that process.wait() can finish.
            if self.task.tid != 1 && !self.task.terminated.load(Ordering::Acquire) {
                self.task.terminated.store(true, Ordering::Release);
                self.task.process.nr_threads.fetch_sub(1, Ordering::Release);
            }
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
    /// The futex manager for handling futex operations (used by ulock syscalls).
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
    /// Tracks which file descriptors have FD_CLOEXEC set.
    cloexec_fds: litebox::sync::RwLock<Platform, alloc::collections::BTreeSet<usize>>,
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
    /// dyld's entry point address, stored after each load_dyld call.
    pub(crate) dyld_entry_point: AtomicUsize,
    /// Base address of the currently-loaded dyld binary (0 if not loaded).
    pub(crate) dyld_base: AtomicUsize,
    /// End address (exclusive) of the currently-loaded dyld binary (0 if not loaded).
    pub(crate) dyld_end: AtomicUsize,
    /// Raw bytes of /usr/lib/dyld, stored so execve can re-load dyld fresh
    /// (with pristine __DATA segments) on every exec, matching real macOS
    /// kernel behavior.
    pub(crate) dyld_bytes: litebox::sync::RwLock<Platform, Option<Vec<u8>>>,
    /// Addresses and sizes of shared cache trampoline regions.
    ///
    /// Each entry is `(trampoline_addr, trampoline_size)`.  These are populated
    /// during `install_shared_cache` and used by `update_shared_cache_tls_addrs`
    /// to patch the TLS table pointer (at offset 8) in each trampoline after
    /// execve allocates a new TLS table.
    pub(crate) shared_cache_trampoline_addrs: litebox::sync::RwLock<Platform, Vec<(u64, usize)>>,
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

impl<FS: ShimFS> GlobalState<FS> {
    /// Update the TLS table pointer in all shared cache trampoline headers.
    ///
    /// Each trampoline's first 16 bytes are: `[callback_addr (8 bytes), tls_table_addr (8 bytes)]`.
    /// After execve, the old TLS table is unmapped and a new one is allocated at a
    /// potentially different address.  This method patches offset 8 in every shared cache
    /// trampoline to point to the new TLS table.
    ///
    /// IMPORTANT: This uses raw `mprotect` syscalls (inline assembly) instead of
    /// `libc::mprotect`, because the libc call would go through the very trampolines
    /// we are trying to fix — their stale TLS pointer would cause a SIGSEGV.
    ///
    /// # Safety
    ///
    /// The caller must ensure `new_tls_addr` points to a valid, mapped TLS table.
    #[allow(clippy::cast_possible_truncation, clippy::similar_names)]
    pub(crate) unsafe fn update_shared_cache_tls_addrs(&self, new_tls_addr: usize) {
        let trampoline_list = self.shared_cache_trampoline_addrs.read();
        let tls_bytes = (new_tls_addr as u64).to_le_bytes();
        let mut updated = 0usize;
        for &(tramp_addr, tramp_size) in trampoline_list.iter() {
            let tramp_addr_usize = tramp_addr as usize;

            // Try mprotect(RW) first — works for non-shared-cache trampolines.
            let rw_ok = unsafe {
                raw_mprotect(tramp_addr_usize, tramp_size, RAW_PROT_READ | RAW_PROT_WRITE)
            }
            .is_ok();

            if !rw_ok {
                // mprotect failed (EACCES on shared cache region pages).
                // Replace the page with a fresh anonymous mapping via
                // raw_mmap(MAP_FIXED), which atomically replaces the old
                // mapping with a new private anonymous page.
                //
                // CRITICAL: We must NOT use any heap allocation (alloc::vec!,
                // Box, etc.) here because malloc goes through the shared cache
                // SVCs whose trampolines still have the STALE TLS address —
                // causing SIGSEGV. All memory must come from raw_mmap (inline
                // asm syscall that bypasses the patched SVCs entirely).
                //
                // Steps:
                // 1. Allocate a temporary buffer via raw_mmap (NOT heap)
                // 2. Read the existing R-X trampoline data into the buffer
                // 3. raw_mmap(MAP_FIXED) to replace the trampoline page
                // 4. Copy the saved data back with the updated TLS address
                // 5. raw_mprotect to R-X (succeeds on private anonymous pages)
                // 6. Free the temporary buffer via raw_munmap

                // Step 1: Allocate temporary save buffer via raw_mmap.
                let save_buf = unsafe {
                    raw_mmap(
                        0,
                        tramp_size,
                        RAW_PROT_READ | RAW_PROT_WRITE,
                        RAW_MAP_ANON | RAW_MAP_PRIVATE,
                    )
                };
                let save_buf = match save_buf {
                    Ok(addr) => addr,
                    Err(errno) => {
                        log_unsupported!(
                            "update_shared_cache_tls_addrs: raw_mmap for temp buffer failed (errno={errno})"
                        );
                        continue;
                    }
                };

                // Step 2: Copy existing trampoline data (page is R-X = readable).
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        tramp_addr_usize as *const u8,
                        save_buf as *mut u8,
                        tramp_size,
                    );
                }

                // Step 3: Replace trampoline with fresh anonymous RW page.
                let mmap_result = unsafe {
                    raw_mmap(
                        tramp_addr_usize,
                        tramp_size,
                        RAW_PROT_READ | RAW_PROT_WRITE,
                        RAW_MAP_ANON | RAW_MAP_PRIVATE | RAW_MAP_FIXED,
                    )
                };
                if mmap_result.is_err() {
                    // Clean up temp buffer and skip this trampoline.
                    unsafe {
                        let _ = raw_munmap(save_buf, tramp_size);
                    }
                    log_unsupported!(
                        "update_shared_cache_tls_addrs: raw_mmap MAP_FIXED failed for tramp at {tramp_addr_usize:#x}"
                    );
                    continue;
                }

                // Step 4: Copy saved data back to the (now-writable) trampoline.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        save_buf as *const u8,
                        tramp_addr_usize as *mut u8,
                        tramp_size,
                    );
                }

                // Step 5 (below): write new TLS + mprotect RX.

                // Step 6: Free temporary buffer.
                unsafe {
                    let _ = raw_munmap(save_buf, tramp_size);
                }
            }

            // Write the new TLS table address at offset 8 using volatile writes
            // (same technique as install_shared_cache Pass 3).
            unsafe {
                let base = tramp_addr_usize as *mut u8;
                let mut j = 0usize;
                while j < 8 {
                    core::ptr::write_volatile(base.add(8 + j), tls_bytes[j]);
                    j += 1;
                }
            }

            // Restore the trampoline to R-X using raw mprotect.
            // For mmap-replaced pages, this works because they are private anonymous.
            let rx_result = unsafe {
                raw_mprotect(tramp_addr_usize, tramp_size, RAW_PROT_READ | RAW_PROT_EXEC)
            };
            if let Err(errno) = rx_result {
                log_unsupported!(
                    "update_shared_cache_tls_addrs: raw_mprotect RX failed for tramp at {tramp_addr_usize:#x} (errno={errno})"
                );
            }
            updated += 1;
        }
        if updated > 0 {
            log_unsupported!(
                "update_shared_cache_tls_addrs: updated {updated}/{} trampolines to TLS addr {new_tls_addr:#x}",
                trampoline_list.len()
            );
        }
    }
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
    /// Per-thread alternate signal stack (set by sigaltstack).
    altstack: litebox::sync::Mutex<Platform, litebox_common_macos::SigAltStack>,
    /// Per-thread wait state for interruptible waits (pipes, futexes, etc.).
    wait_state: wait::WaitState,
    /// Directory enumeration positions for getattrlistbulk.
    /// Maps raw fd number -> number of entries already returned.
    dir_positions: litebox::sync::Mutex<Platform, BTreeMap<usize, usize>>,
    /// Real kernel mach port for this thread (from mach_thread_self()).
    /// Used by THREAD_SELF_TRAP to return a value consistent with tl_thport.
    real_mach_port: AtomicU32,
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

                // Populate the kernel thread mach port in the pthread struct.
                //
                // `_pthread_start` validates `pthread->tl_thport` (offset 248)
                // and aborts with BRK #0xB001 ("Unable to allocate thread port")
                // if the field is zero or MACH_PORT_DEAD.  On real macOS, the
                // kernel writes this field before starting the thread.  Since we
                // create host POSIX threads, we fill it with the real kernel
                // mach port of the current (spawned) thread.
                let real_mach_port = unsafe { mach_thread_self() };
                // Store the real port so THREAD_SELF_TRAP returns a consistent value.
                self.real_mach_port.store(real_mach_port, Ordering::Release);
                // Also pass the real port in x1 so _pthread_start has a
                // consistent view.
                ctx.regs[1] = real_mach_port as usize;
                // Write to pthread + 248 (tl_thport, uint32_t).
                let thport_ptr = (pthread + 248) as *mut u32;
                unsafe { core::ptr::write_volatile(thport_ptr, real_mach_port) };
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
        let request = litebox_common_macos::syscall::MacosSyscallRequest::try_from_raw(ctx);

        // Sigreturn restores the full register set (including pstate) and must
        // NOT be followed by set_syscall_return, which would overwrite x0 and
        // the carry flag.
        if let litebox_common_macos::syscall::MacosSyscallRequest::Sigreturn { uctx, .. } = &request
        {
            self.sys_sigreturn(ctx, *uctx);
            return;
        }

        // Kill and __pthread_kill may build a signal frame (rewriting ctx) for
        // user handlers.  When that happens, set_syscall_return must be skipped
        // because deliver_signal has already set up the register context.
        if let litebox_common_macos::syscall::MacosSyscallRequest::Kill { pid, sig } = &request {
            match self.sys_kill(*pid, *sig, ctx) {
                Ok(crate::syscalls::signal::KillResult::Delivered { frame_set: true }) => {
                    // Signal frame already set up — ctx points to _sigtramp.
                    // The saved context inside the frame has x0 from before the
                    // syscall; we need to patch it so that when sigreturn restores
                    // the context, the kill() caller sees return value 0.
                    // However, deliver_signal saved the pre-syscall ctx which
                    // already had x0 = the syscall's first argument.  The user
                    // handler doesn't observe x0 directly (it gets signal number
                    // via _sigtramp args), and sigreturn will restore the saved
                    // context.  We just need to make sure the saved x0 in the
                    // mcontext is 0 and carry is clear for the kill() return.
                    //
                    // For now, we accept that the saved x0 in the mcontext is
                    // the pre-syscall value.  After sigreturn, execution resumes
                    // at the instruction after the kill syscall, and the kernel
                    // convention is that x0 is already set by set_syscall_return.
                    // Since we can't easily patch the mcontext, and real macOS
                    // kernel handles this internally, we skip set_syscall_return
                    // here and trust that the signal frame mechanism is correct.
                    return;
                }
                Ok(crate::syscalls::signal::KillResult::Delivered { frame_set: false }) => {
                    litebox_common_macos::syscall::set_syscall_return(ctx, Ok(0));
                    return;
                }
                Err(errno) => {
                    litebox_common_macos::syscall::set_syscall_return(ctx, Err(errno));
                    return;
                }
            }
        }
        if let litebox_common_macos::syscall::MacosSyscallRequest::PthreadKill { port, sig } =
            &request
        {
            match self.sys_pthread_kill(*port, *sig, ctx) {
                Ok(crate::syscalls::signal::KillResult::Delivered { frame_set: true }) => {
                    return;
                }
                Ok(crate::syscalls::signal::KillResult::Delivered { frame_set: false }) => {
                    litebox_common_macos::syscall::set_syscall_return(ctx, Ok(0));
                    return;
                }
                Err(errno) => {
                    litebox_common_macos::syscall::set_syscall_return(ctx, Err(errno));
                    return;
                }
            }
        }

        // execve replaces the entire process image.  On success, ctx is
        // rewritten to the new entry point and set_syscall_return must be
        // skipped.  On failure, return the error normally.
        if let litebox_common_macos::syscall::MacosSyscallRequest::Execve { path, argv, envp } =
            &request
        {
            match self.sys_execve(*path, *argv, *envp, ctx) {
                Ok(()) => {
                    // ctx now points to the new program's entry point.
                    return;
                }
                Err(errno) => {
                    litebox_common_macos::syscall::set_syscall_return(ctx, Err(errno));
                    return;
                }
            }
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

        // Handle psynch synchronization syscalls (296-309).
        //
        // These are used by libpthread for internal mutex/condvar operations.
        // Guest threads are real host threads and guest memory is host memory,
        // so we pass them through to the real kernel.
        //
        // The kernel psynch calls are blocking; a thread stuck in the kernel
        // cannot check `should_terminate()`.  To avoid hangs on process exit,
        // we pass them through but accept that forked-child cleanup will
        // `_exit()` and the kernel will clean up any leftover blocked threads.
        if let litebox_common_macos::syscall::MacosSyscallRequest::Unknown { number } = &request
            && matches!(*number, 296..=309)
        {
            let result = unsafe {
                raw_bsd_syscall6(
                    *number as u64,
                    ctx.regs[0] as u64,
                    ctx.regs[1] as u64,
                    ctx.regs[2] as u64,
                    ctx.regs[3] as u64,
                    ctx.regs[4] as u64,
                    ctx.regs[5] as u64,
                )
            };
            match result {
                Ok(val) => {
                    ctx.regs[0] = val as usize;
                    ctx.pstate &= !litebox_common_macos::syscall::CARRY_BIT;
                }
                Err(errno) => {
                    ctx.regs[0] = errno as usize;
                    ctx.pstate |= litebox_common_macos::syscall::CARRY_BIT;
                }
            }
            return;
        }

        let result = self.do_syscall(request, ctx);
        litebox_common_macos::syscall::set_syscall_return(ctx, result);
    }
}

// ---------------------------------------------------------------------------
// Raw macOS aarch64 syscall helpers.
// ---------------------------------------------------------------------------

/// Execute a raw BSD syscall with up to 6 arguments via inline assembly.
///
/// Returns `Ok(return_value)` on success or `Err(errno)` on failure.
///
/// # Safety
///
/// Caller must ensure the syscall number and arguments are valid.
#[allow(clippy::cast_possible_truncation)]
unsafe fn raw_bsd_syscall6(
    nr: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
) -> Result<u64, i32> {
    let ret: u64;
    let err_flag: u64;
    unsafe {
        core::arch::asm!(
            "mov x16, x8",
            "svc #0x80",
            "cset x8, cs",
            in("x8") nr,
            inlateout("x0") a0 => ret,
            in("x1") a1,
            in("x2") a2,
            in("x3") a3,
            in("x4") a4,
            in("x5") a5,
            lateout("x8") err_flag,
            lateout("x16") _,
            lateout("x1") _,
            lateout("x2") _,
            lateout("x3") _,
            lateout("x4") _,
            lateout("x5") _,
            options(nostack),
        );
    }
    if err_flag != 0 {
        Err(ret as i32)
    } else {
        Ok(ret)
    }
}

// ---------------------------------------------------------------------------
// Raw macOS aarch64 syscall helpers for Pass 3.
//
// These bypass the litebox MM layer (and its VMA-tracking BTree allocations)
// to avoid triggering malloc on shared cache pages that may be temporarily
// zeroed during the copy-and-patch replacement.
// ---------------------------------------------------------------------------

/// macOS BSD mmap protection flags (from <sys/mman.h>).
const RAW_PROT_READ: i32 = 0x01;
const RAW_PROT_WRITE: i32 = 0x02;
const RAW_PROT_EXEC: i32 = 0x04;

/// macOS BSD mmap flags (from <sys/mman.h>).
const RAW_MAP_ANON: i32 = 0x1000;
const RAW_MAP_PRIVATE: i32 = 0x0002;
const RAW_MAP_FIXED: i32 = 0x0010;

/// macOS BSD syscall numbers (from <sys/syscall.h>).
const SYS_MMAP: u64 = 197;
const SYS_MPROTECT: u64 = 74;
const SYS_MUNMAP: u64 = 73;

/// Raw `mmap(addr, len, prot, flags, fd=-1, offset=0)` via inline assembly.
///
/// Returns `Ok(mapped_address)` or `Err(errno)`.
///
/// # Safety
///
/// Caller must ensure arguments are valid for the mmap syscall.
#[allow(clippy::cast_sign_loss)] // Intentional: kernel ABI uses unsigned registers for signed args.
#[allow(clippy::cast_possible_truncation)] // aarch64-only: usize == u64, errno fits i32.
unsafe fn raw_mmap(addr: usize, len: usize, prot: i32, flags: i32) -> Result<usize, i32> {
    let ret: u64;
    let err_flag: u64;
    unsafe {
        core::arch::asm!(
            "mov x16, {syscall_nr}",
            "svc #0x80",
            // After svc: x0 = return value, carry flag set on error.
            // Use cset to capture the carry flag (C = bit 29 of NZCV).
            "cset {err}, cs",
            syscall_nr = in(reg) SYS_MMAP,
            // x0 = addr, x1 = len, x2 = prot, x3 = flags, x4 = fd, x5 = offset
            in("x0") addr as u64,
            in("x1") len as u64,
            in("x2") prot as u64,
            in("x3") flags as u64,
            in("x4") u64::MAX,         // fd = -1 (MAP_ANON)
            in("x5") 0u64,             // offset = 0
            err = out(reg) err_flag,
            lateout("x0") ret,
            // x16 is clobbered by the syscall number.
            out("x16") _,
        );
    }
    if err_flag != 0 {
        Err(ret as i32)
    } else {
        Ok(ret as usize)
    }
}

/// Raw `mprotect(addr, len, prot)` via inline assembly.
///
/// Returns `Ok(())` or `Err(errno)`.
///
/// # Safety
///
/// Caller must ensure arguments are valid for the mprotect syscall.
#[allow(clippy::cast_sign_loss)] // Intentional: kernel ABI uses unsigned registers for signed args.
#[allow(clippy::cast_possible_truncation)] // aarch64-only: errno fits i32.
unsafe fn raw_mprotect(addr: usize, len: usize, prot: i32) -> Result<(), i32> {
    let ret: u64;
    let err_flag: u64;
    unsafe {
        core::arch::asm!(
            "mov x16, {syscall_nr}",
            "svc #0x80",
            "cset {err}, cs",
            syscall_nr = in(reg) SYS_MPROTECT,
            in("x0") addr as u64,
            in("x1") len as u64,
            in("x2") prot as u64,
            err = out(reg) err_flag,
            lateout("x0") ret,
            out("x16") _,
        );
    }
    if err_flag != 0 {
        Err(ret as i32)
    } else {
        Ok(())
    }
}

/// Raw `munmap(addr, len)` via inline assembly.
///
/// Returns `Ok(())` or `Err(errno)`.
///
/// # Safety
///
/// Caller must ensure arguments are valid for the munmap syscall.
#[allow(clippy::cast_possible_truncation)]
unsafe fn raw_munmap(addr: usize, len: usize) -> Result<(), i32> {
    let ret: u64;
    let err_flag: u64;
    unsafe {
        core::arch::asm!(
            "mov x16, {syscall_nr}",
            "svc #0x80",
            "cset {err}, cs",
            syscall_nr = in(reg) SYS_MUNMAP,
            in("x0") addr as u64,
            in("x1") len as u64,
            err = out(reg) err_flag,
            lateout("x0") ret,
            out("x16") _,
        );
    }
    if err_flag != 0 {
        Err(ret as i32)
    } else {
        Ok(())
    }
}

/// macOS BSD syscall number for `sigaction`.
const SYS_SIGACTION: u64 = 46;

/// Reset signal `signum` to `SIG_DFL` via raw `sigaction` syscall.
///
/// Uses a zeroed `struct __sigaction` (24 bytes) on the stack, which sets
/// `sa_handler = SIG_DFL (0)`, `sa_tramp = NULL`, `sa_mask = 0`, `sa_flags = 0`.
///
/// # Safety
///
/// Caller must ensure `signum` is a valid signal number (1..31).
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#[allow(dead_code)]
unsafe fn raw_sigaction_dfl(signum: i32) {
    let mut old_sa: [u8; 24] = [0; 24];
    unsafe {
        raw_sigaction_set(signum, &[0u8; 24], &mut old_sa);
    }
}

/// Set a signal action via raw `SVC #0x80`, saving the old action.
///
/// `new_sa` and `old_sa` must both point to valid 24-byte `__sigaction`
/// structs.
#[allow(clippy::cast_sign_loss)]
unsafe fn raw_sigaction_set(signum: i32, new_sa: &[u8; 24], old_sa: &mut [u8; 24]) {
    // struct __sigaction layout (aarch64 macOS):
    //   [0..8]  sa_handler  (SIG_DFL = 0)
    //   [8..16] sa_tramp    (NULL)
    //   [16..20] sa_mask    (0)
    //   [20..24] sa_flags   (0)
    let ret: u64;
    let err_flag: u64;
    unsafe {
        core::arch::asm!(
            "mov x16, {syscall_nr}",
            "svc #0x80",
            "cset {err}, cs",
            syscall_nr = in(reg) SYS_SIGACTION,
            in("x0") signum as u64,
            in("x1") new_sa.as_ptr() as u64,
            in("x2") old_sa.as_mut_ptr() as u64,
            err = out(reg) err_flag,
            lateout("x0") ret,
            out("x16") _,
        );
    }
    let _ = (err_flag, ret);
}
