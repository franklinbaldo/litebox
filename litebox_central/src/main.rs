// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Central LiteBox — host process serving syscalls for guest processes
//! via shared-memory ring buffer IPC.

mod dispatch;
mod inmem_alloc;
mod notification_state;
mod server;
mod shmem;

use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::sync::Mutex;

use clap::Parser;
use litebox::fs::FileSystem as _;
use litebox_ipc::ring::SharedRingLayout;
use litebox_platform_central::CentralPlatform;
use litebox_platform_multiplex::Platform;

/// Newtype wrapper so we can store raw ring-header pointers in a `Mutex`
/// across threads (required for `static` items to implement `Sync`).
struct RingPtr(*const litebox_ipc::ring::RingHeader);

// SAFETY: Ring header pointers come from mmap'd shared memory that outlives
// the process. The Mutex serialises all access.
unsafe impl Send for RingPtr {}

/// Global registry of active ring header pointers so that the panic hook
/// (and normal exit path) can set `is_exiting` on ALL rings, ensuring every
/// micro process detects central's death.
static ACTIVE_RINGS: Mutex<Vec<RingPtr>> = Mutex::new(Vec::new());

/// Register a ring header pointer so it will be signalled on exit/panic.
fn register_active_ring(header: &litebox_ipc::ring::RingHeader) {
    let ptr: *const litebox_ipc::ring::RingHeader = header;
    if let Ok(mut rings) = ACTIVE_RINGS.lock() {
        rings.push(RingPtr(ptr));
    }
}

/// Signal all active rings that central is exiting.
fn signal_all_rings_exiting() {
    if let Ok(rings) = ACTIVE_RINGS.lock() {
        for ring in &*rings {
            // SAFETY: The ring header lives in mmap'd shared memory that
            // remains valid for the lifetime of the process.
            unsafe {
                (*ring.0)
                    .is_exiting
                    .store(1, core::sync::atomic::Ordering::Release);
            }
        }
    }
}

/// Filesystem type for central: in-memory over (devices over tar_ro).
///
/// The tar_ro layer provides shared libraries from a rootfs tar.
/// The devices layer provides /dev/stdin, /dev/stdout, /dev/stderr.
/// The in-memory layer is the writable top layer.
type CentralFs = litebox::fs::layered::FileSystem<
    Platform,
    litebox::fs::in_mem::FileSystem<Platform>,
    litebox::fs::layered::FileSystem<
        Platform,
        litebox::fs::devices::FileSystem<Platform>,
        litebox::fs::tar_ro::FileSystem<Platform>,
    >,
>;

#[derive(Parser)]
struct Args {
    /// Shared memory file descriptor (inherited from launcher).
    /// If not provided, central creates its own shmem.
    #[arg(long)]
    shmem_fd: Option<i32>,

    /// Initial program break address from the ELF loader.
    #[arg(long, default_value = "0")]
    initial_brk: usize,

    /// Tar shmem file descriptor (inherited from launcher).
    /// If not provided, an empty tar is used.
    #[arg(long)]
    tar_fd: Option<i32>,

    /// Size in bytes of the tar shmem region.
    #[arg(long, default_value = "0")]
    tar_size: usize,

    /// Aligned memfd file descriptor (inherited from launcher).
    /// Contains page-aligned copies of tar file data for direct mmap by micro.
    #[arg(long)]
    aligned_fd: Option<i32>,

    /// Size in bytes of the aligned memfd region.
    #[arg(long, default_value = "0")]
    aligned_size: usize,

    /// In-memory filesystem shmem file descriptor (inherited from launcher).
    #[arg(long)]
    inmem_fd: Option<i32>,

    /// Size in bytes of the inmem shmem region.
    #[arg(long, default_value = "0")]
    inmem_size: usize,

    /// Name of the TUN device to open for raw IP networking (e.g. "tun0").
    /// If not provided, IP networking is disabled.
    #[arg(long)]
    tun_device: Option<String>,
}

fn main() -> anyhow::Result<()> {
    // Install a panic hook that signals all micro processes before aborting.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        signal_all_rings_exiting();
        default_hook(info);
    }));

    // Raise the file descriptor limit.  Each child process gets its own
    // ring buffer backed by a memfd.  Under heavy fork workloads (e.g.
    // shell benchmarks), hundreds of child server threads may be alive
    // simultaneously, each holding an open memfd.  The default 1024 soft
    // limit is quickly exhausted.
    {
        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut rlim) };
        if rlim.rlim_cur < rlim.rlim_max {
            rlim.rlim_cur = rlim.rlim_max;
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const rlim) };
        }
    }

    // Parse CLI args early — we need them for platform and FS construction.
    let args = Args::parse();

    // Initialize the platform — must happen before any other litebox usage.
    let platform: &'static Platform =
        Box::leak(Box::new(CentralPlatform::new(args.tun_device.as_deref())));
    litebox_platform_multiplex::set_platform(platform);

    // Build the LiteBox shim with a 3-layer filesystem:
    //   in_mem (writable top) over (devices over tar_ro)
    //
    // - tar_ro provides shared libraries from the rootfs tar
    // - devices provides /dev/stdin, /dev/stdout, /dev/stderr
    // - in_mem is the writable top layer for runtime state
    let shim_builder = litebox_shim_linux::LinuxShimBuilder::new();
    let dt = litebox::fd::new_descriptor_table();
    let platform = shim_builder.platform();

    let tar_data: std::borrow::Cow<'static, [u8]> = if let Some(tar_fd) = args.tar_fd {
        let size = args.tar_size;
        if size == 0 {
            eprintln!("litebox_central: --tar-fd provided but --tar-size is 0");
            std::borrow::Cow::Borrowed(litebox::fs::tar_ro::EMPTY_TAR_FILE)
        } else {
            let ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    size,
                    libc::PROT_READ,
                    libc::MAP_SHARED,
                    tar_fd,
                    0,
                )
            };
            if ptr == libc::MAP_FAILED {
                eprintln!(
                    "litebox_central: mmap tar shmem failed: {}",
                    std::io::Error::last_os_error()
                );
                std::borrow::Cow::Borrowed(litebox::fs::tar_ro::EMPTY_TAR_FILE)
            } else {
                // SAFETY: mmap succeeded, ptr valid for `size` bytes. The mapping
                // lives for the process lifetime (never munmap'd). We cast to
                // 'static because the data outlives all references.
                let slice: &'static [u8] =
                    unsafe { core::slice::from_raw_parts(ptr.cast::<u8>(), size) };
                std::borrow::Cow::Borrowed(slice)
            }
        }
    } else {
        std::borrow::Cow::Borrowed(litebox::fs::tar_ro::EMPTY_TAR_FILE)
    };

    let tar_shmem_base: *const u8 = tar_data.as_ptr();
    let tar_shmem_size: usize = tar_data.len();

    // Map the in-memory filesystem shmem region if provided by the launcher.
    // Central maps it read-write so it can manage file data allocations.
    let (inmem_base, inmem_size) = if let Some(inmem_fd) = args.inmem_fd {
        let size = args.inmem_size;
        if size == 0 {
            eprintln!("litebox_central: --inmem-fd provided but --inmem-size is 0");
            (std::ptr::null_mut(), 0)
        } else {
            let ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    inmem_fd,
                    0,
                )
            };
            if ptr == libc::MAP_FAILED {
                eprintln!(
                    "litebox_central: mmap inmem shmem failed: {}",
                    std::io::Error::last_os_error()
                );
                (std::ptr::null_mut(), 0)
            } else {
                (ptr.cast::<u8>(), size)
            }
        }
    } else {
        (std::ptr::null_mut(), 0)
    };

    let devices = litebox::fs::devices::FileSystem::new(platform);
    let mut in_mem = litebox::fs::in_mem::FileSystem::new();

    // Create /tmp on the in-memory layer so guest programs can write
    // temporary files (e.g. fstime benchmark's creat("/tmp/dummy0-...")).
    // This mirrors what litebox_runner_linux_userland does.
    //
    // Also make the root directory world-writable so that guest processes
    // (which run as uid 1000 in the in-mem FS) can create files in the
    // current working directory (which starts at /).
    in_mem.with_root_privileges(|fs| {
        let mode = litebox::fs::Mode::RWXU | litebox::fs::Mode::RWXG | litebox::fs::Mode::RWXO;
        if let Err(err) = fs.chmod(&dt, "/", mode) {
            eprintln!("litebox_central: failed to chmod /: {err:?}");
        }
        if let Err(err) = fs.mkdir(&dt, "/tmp", mode)
            && !matches!(err, litebox::fs::errors::MkdirError::AlreadyExists)
        {
            eprintln!("litebox_central: failed to create /tmp: {err:?}");
        }
    });

    let tar_ro = litebox::fs::tar_ro::FileSystem::new(tar_data);

    // Build a lookup table mapping tar paths to their byte ranges before
    // the tar_ro filesystem is moved into the layered FS.  This map is
    // shared (via Arc) with every ProcessServer so it can populate
    // OpenResponse tar fields without traversing the layered FS.
    let tar_file_map: std::collections::HashMap<String, std::ops::Range<usize>> = tar_ro
        .all_file_data_ranges()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
    let tar_file_map = std::sync::Arc::new(tar_file_map);

    // Build the aligned offset map from the ordered tar entries.
    // The launcher writes file data into the aligned memfd in tar-entry order,
    // each file starting at a page-aligned offset. We reconstruct the same
    // layout here so central can tell micro where each file lives in the
    // aligned memfd for direct mmap.
    let aligned_file_map: std::collections::HashMap<String, (usize, usize)> = {
        let mut map = std::collections::HashMap::new();
        if args.aligned_size > 0 {
            let page_size: usize = 4096;
            let mut offset: usize = 0;
            for (path, range) in tar_ro.all_file_data_ranges_ordered() {
                let file_size = range.end - range.start;
                // Skip zero-length entries — the launcher's
                // `compute_aligned_offsets()` skips them too, so we must
                // match to keep the offset maps consistent.
                if file_size == 0 {
                    continue;
                }
                offset = (offset + page_size - 1) & !(page_size - 1);
                map.insert(path.to_string(), (offset, file_size));
                offset += file_size;
            }
        }
        map
    };
    let aligned_file_map = std::sync::Arc::new(aligned_file_map);

    let inner = litebox::fs::layered::FileSystem::new(
        devices,
        tar_ro,
        litebox::fs::layered::LayeringSemantics::LowerLayerReadOnly,
    );
    let fs = std::sync::Arc::new(litebox::fs::layered::FileSystem::new(
        in_mem,
        inner,
        litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
    ));
    let shim = shim_builder.build::<CentralFs>();

    // Wrap the shim in an Arc so it can be shared with child ProcessServers.
    let shim = std::sync::Arc::new(shim);

    // Create a headless task for syscall dispatch.
    // TODO: receive real TaskParams from the launcher via the ring buffer
    // or command-line arguments.
    let params = litebox_common_linux::TaskParams {
        pid: 1,
        ppid: 0,
        uid: 0,
        euid: 0,
        gid: 0,
        egid: 0,
    };
    let task = shim.create_task(fs.clone(), params, true);

    if args.initial_brk != 0 {
        task.set_initial_brk(args.initial_brk);
    }

    let region = if let Some(fd) = args.shmem_fd {
        use std::os::unix::io::FromRawFd;
        let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let layout = SharedRingLayout::default_layout();
        shmem::SharedRegion::from_fd(owned_fd, layout)?
    } else {
        shmem::SharedRegion::new()?
    };

    let ring_pool = Arc::new(shmem::RingPool::new(8));

    // Register the initial ring so it gets signalled on exit/panic.
    register_active_ring(region.header());

    // Create the in-memory shmem allocator (shared across parent/child
    // ProcessServers via Arc).
    let inmem_alloc = Arc::new(Mutex::new(inmem_alloc::InMemAllocator::new(
        inmem_base, inmem_size,
    )));

    // Map from canonical file path to inmem shmem slot index, shared
    // across parent/child ProcessServers so that a file written by one
    // process can be served from shmem by another's openat.
    let inmem_file_map: Arc<Mutex<std::collections::HashMap<String, u32>>> =
        Arc::new(Mutex::new(std::collections::HashMap::new()));

    // Master starts with TUN queue 0 (works for single-process programs).
    // If the process forks workers, handle_fork detaches queue 0 from the
    // master and hands it to the first child, preventing the master from
    // black-holing connections it never accepts.  Subsequent children get
    // new queues via open_new_queue().
    let tun_enabled = args.tun_device.is_some();
    let master_tun_queue: Option<usize> = if tun_enabled { Some(0) } else { None };
    let server = server::ProcessServer::new(
        region,
        task,
        shim,
        fs,
        ring_pool,
        -1,
        master_tun_queue,
        tun_enabled,
        tar_shmem_base,
        tar_shmem_size,
        tar_file_map,
        aligned_file_map,
        args.aligned_size,
        inmem_base,
        inmem_size,
        inmem_alloc,
        inmem_file_map,
    );
    let result = server.run();

    // Signal all micro processes that central is shutting down.
    signal_all_rings_exiting();

    result
}
