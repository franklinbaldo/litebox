// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Central LiteBox — host process serving syscalls for guest processes
//! via shared-memory ring buffer IPC.

#[allow(dead_code)]
mod dispatch;
mod server;
#[allow(dead_code)]
mod shmem;

use litebox::fs::in_mem::FileSystem as InMemFs;
use litebox_platform_central::CentralPlatform;
use litebox_platform_multiplex::Platform;

fn main() -> anyhow::Result<()> {
    // Initialize the platform — must happen before any other litebox usage.
    let platform: &'static Platform = Box::leak(Box::new(CentralPlatform));
    litebox_platform_multiplex::set_platform(platform);
    eprintln!("litebox_central: platform initialized");

    // Build the LiteBox shim with an in-memory filesystem.
    let shim_builder = litebox_shim_linux::LinuxShimBuilder::new();
    let fs = InMemFs::new(shim_builder.litebox());
    let _shim = shim_builder.build::<InMemFs<Platform>>();
    let _fs = fs;
    eprintln!("litebox_central: shim initialized");

    eprintln!("litebox_central: creating shared memory region");
    let region = shmem::SharedRegion::new()?;
    eprintln!(
        "litebox_central: shared region created, {} bytes",
        region.layout().total_size
    );

    let server = server::ProcessServer::new(region);
    eprintln!("litebox_central: starting server loop");
    server.run()
}
