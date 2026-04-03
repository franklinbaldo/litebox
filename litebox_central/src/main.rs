// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Central LiteBox — host process serving syscalls for guest processes
//! via shared-memory ring buffer IPC.

#[allow(dead_code)]
mod dispatch;
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

    /// Path to a .tar file containing the root filesystem (shared libraries, etc.).
    #[arg(long)]
    rootfs_tar: Option<String>,

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
    let lb = shim_builder.litebox();

    let tar_data: std::borrow::Cow<'static, [u8]> = if let Some(ref tar_path) = args.rootfs_tar {
        let data = std::fs::read(tar_path)
            .map_err(|e| anyhow::anyhow!("failed to read rootfs tar {tar_path}: {e}"))?;
        std::borrow::Cow::Owned(data)
    } else {
        std::borrow::Cow::Borrowed(litebox::fs::tar_ro::EMPTY_TAR_FILE)
    };

    let devices = litebox::fs::devices::FileSystem::new(lb);
    let mut in_mem = litebox::fs::in_mem::FileSystem::new(lb);

    // Create /tmp on the in-memory layer so guest programs can write
    // temporary files (e.g. fstime benchmark's creat("/tmp/dummy0-...")).
    // This mirrors what litebox_runner_linux_userland does.
    //
    // Also make the root directory world-writable so that guest processes
    // (which run as uid 1000 in the in-mem FS) can create files in the
    // current working directory (which starts at /).
    in_mem.with_root_privileges(|fs| {
        let mode = litebox::fs::Mode::RWXU | litebox::fs::Mode::RWXG | litebox::fs::Mode::RWXO;
        if let Err(err) = fs.chmod("/", mode) {
            eprintln!("litebox_central: failed to chmod /: {err:?}");
        }
        if let Err(err) = fs.mkdir("/tmp", mode)
            && !matches!(err, litebox::fs::errors::MkdirError::AlreadyExists)
        {
            eprintln!("litebox_central: failed to create /tmp: {err:?}");
        }
    });

    let tar_ro = litebox::fs::tar_ro::FileSystem::new(lb, tar_data);
    let inner = litebox::fs::layered::FileSystem::new(
        lb,
        devices,
        tar_ro,
        litebox::fs::layered::LayeringSemantics::LowerLayerReadOnly,
    );
    let fs = std::sync::Arc::new(litebox::fs::layered::FileSystem::new(
        lb,
        in_mem,
        inner,
        litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
    ));
    let shim = shim_builder.build::<CentralFs>();

    // Wrap the shim in an Arc so it can be shared with child ProcessServers.
    let shim = std::sync::Arc::new(shim);

    // Spawn a network worker thread to drive smoltcp ↔ TUN packet flow.
    let net_shutdown = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
    let net_worker = if args.tun_device.is_some() {
        let shim = shim.clone();
        let shutdown = net_shutdown.clone();
        Some(
            std::thread::Builder::new()
                .name("net-worker".into())
                .spawn(move || {
                    const DEFAULT_TIMEOUT: core::time::Duration =
                        core::time::Duration::from_micros(100);
                    const MAX_TIMEOUT: core::time::Duration =
                        core::time::Duration::from_millis(1);

                    while !shutdown.load(core::sync::atomic::Ordering::Relaxed) {
                        // Limit consecutive immediate re-polls to prevent the
                        // net-worker from starving server threads when smoltcp
                        // continuously reports SocketStateChanged (e.g. many
                        // sockets in half-closed / TIME_WAIT states).
                        const MAX_IMMEDIATE_POLLS: u32 = 64;
                        let mut polls = 0u32;
                        let timeout = loop {
                            match shim.perform_network_interaction() {
                                litebox::net::PlatformInteractionReinvocationAdvice::CallAgainImmediately => {
                                    polls += 1;
                                    if polls >= MAX_IMMEDIATE_POLLS {
                                        // Yield to let server threads acquire
                                        // the network lock, then try again
                                        // with a real blocking wait.
                                        break Some(MAX_TIMEOUT);
                                    }
                                }
                                litebox::net::PlatformInteractionReinvocationAdvice::WaitOnDeviceOrSocketInteraction { timeout } => {
                                    break timeout;
                                }
                            }
                        };
                        platform.wait_on_tun(
                            Some(timeout.unwrap_or(DEFAULT_TIMEOUT).min(MAX_TIMEOUT)),
                        );
                    }
                    // Final flush
                    while shim
                        .perform_network_interaction()
                        .call_again_immediately()
                    {}
                })
                .expect("failed to spawn network worker thread"),
        )
    } else {
        None
    };

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

    let server = server::ProcessServer::new(region, task, shim, fs, ring_pool, -1);
    let result = server.run();

    // Signal all micro processes that central is shutting down.
    signal_all_rings_exiting();

    net_shutdown.store(true, core::sync::atomic::Ordering::Relaxed);
    if let Some(handle) = net_worker {
        let _ = handle.join();
    }
    result
}
