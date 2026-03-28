// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Central LiteBox — host process serving syscalls for guest processes
//! via shared-memory ring buffer IPC.

#[allow(dead_code)]
mod dispatch;
mod server;
mod shmem;

use std::os::fd::OwnedFd;

use clap::Parser;
use litebox_ipc::ring::SharedRingLayout;
use litebox_platform_central::CentralPlatform;
use litebox_platform_multiplex::Platform;

/// Filesystem type for central: device nodes (/dev/stdin, /dev/stdout, /dev/stderr)
/// layered on top of an in-memory FS.
type CentralFs = litebox::fs::layered::FileSystem<
    Platform,
    litebox::fs::devices::FileSystem<Platform>,
    litebox::fs::in_mem::FileSystem<Platform>,
>;

#[derive(Parser)]
struct Args {
    /// Shared memory file descriptor (inherited from launcher).
    /// If not provided, central creates its own shmem.
    #[arg(long)]
    shmem_fd: Option<i32>,
}

fn main() -> anyhow::Result<()> {
    // Initialize the platform — must happen before any other litebox usage.
    let platform: &'static Platform = Box::leak(Box::new(CentralPlatform));
    litebox_platform_multiplex::set_platform(platform);

    // Build the LiteBox shim with a layered filesystem (device nodes + in-mem).
    // The devices layer (upper) provides /dev/stdin, /dev/stdout, /dev/stderr
    // which are required for stdio initialization during task creation.
    // Devices must be the UPPER layer so that open() receives the original flags
    // (the layered FS rewrites lower-layer flags to RDONLY with LowerLayerReadOnly).
    let shim_builder = litebox_shim_linux::LinuxShimBuilder::new();
    let lb = shim_builder.litebox();
    let devices = litebox::fs::devices::FileSystem::new(lb);
    let in_mem = litebox::fs::in_mem::FileSystem::new(lb);
    let fs = std::sync::Arc::new(litebox::fs::layered::FileSystem::new(
        lb,
        devices,
        in_mem,
        litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
    ));
    let shim = shim_builder.build::<CentralFs>();

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
    let task = shim.create_task(fs, params);

    let args = Args::parse();

    let region = if let Some(fd) = args.shmem_fd {
        use std::os::unix::io::FromRawFd;
        let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let layout = SharedRingLayout::default_layout();
        shmem::SharedRegion::from_fd(owned_fd, layout)?
    } else {
        shmem::SharedRegion::new()?
    };

    let server = server::ProcessServer::new(region, task);
    server.run()
}
