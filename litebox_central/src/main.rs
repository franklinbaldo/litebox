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

use clap::Parser;
use litebox::fs::FileSystem as _;
use litebox_ipc::ring::SharedRingLayout;
use litebox_platform_central::CentralPlatform;
use litebox_platform_multiplex::Platform;

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
}

fn main() -> anyhow::Result<()> {
    // Initialize the platform — must happen before any other litebox usage.
    let platform: &'static Platform = Box::leak(Box::new(CentralPlatform));
    litebox_platform_multiplex::set_platform(platform);

    // Parse CLI args early — we need rootfs_tar for FS construction.
    let args = Args::parse();

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

    let server = server::ProcessServer::new(region, task, shim, fs);
    server.run()
}
