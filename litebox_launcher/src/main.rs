// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

mod central;
mod entry;
mod load_elf;
mod loader;
mod shmem;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    // Extract --rootfs-tar=<path> before processing guest args.
    let rootfs_tar = args
        .iter()
        .find(|a| a.starts_with("--rootfs-tar="))
        .map(|a| a.strip_prefix("--rootfs-tar=").unwrap().to_string());

    // Extract --rootfs-prefix=<dir> for interpreter resolution.
    let rootfs_prefix = args
        .iter()
        .find(|a| a.starts_with("--rootfs-prefix="))
        .map(|a| a.strip_prefix("--rootfs-prefix=").unwrap().to_string());

    // Filter out launcher-only flags from guest argv.
    let guest_argv: Vec<&str> = args[1..]
        .iter()
        .filter(|a| !a.starts_with("--rootfs-tar=") && !a.starts_with("--rootfs-prefix="))
        .map(String::as_str)
        .collect();

    if guest_argv.is_empty() {
        anyhow::bail!(
            "Usage: litebox_launcher [--rootfs-tar=<path>] [--rootfs-prefix=<dir>] <elf-path> [args...]"
        );
    }
    let elf_path = guest_argv[0];

    // 1. Create shared memory region for IPC ring buffer.
    let shmem = shmem::LauncherSharedRegion::new()?;

    // 2. Load the guest ELF binary (need brk for central initialization).
    let syscall_entry = litebox_micro::get_syscall_entry_point();
    // Pass the host environment through to the guest.  Benchmarks such as
    // `execl` rely on `UB_BINDIR` and other environment variables.
    let host_env: Vec<String> = std::env::vars()
        .filter(|(k, _)| {
            // Filter out launcher-internal vars that should not leak.
            k != "LITEBOX_CENTRAL_PATH"
        })
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    let guest_envp: Vec<&str> = host_env.iter().map(String::as_str).collect();
    let loaded = load_elf::load_elf(
        elf_path,
        &guest_argv,
        &guest_envp,
        syscall_entry,
        rootfs_prefix.as_deref(),
    )?;

    // 3. Spawn central process (child inherits the shmem fd + initial brk + rootfs tar).
    let central =
        central::CentralProcess::spawn(shmem.fd_raw(), loaded.brk, rootfs_tar.as_deref())?;

    // Give central time to initialize (platform, shim, server loop).
    // TODO: Replace with proper readiness signaling via ring header.
    std::thread::sleep(std::time::Duration::from_millis(200));

    // 4. Initialize micro-LiteBox global state and thread-local storage.
    // SAFETY: Called exactly once, before any guest code runs, while the
    // process is still single-threaded (central was forked, not a thread).
    unsafe {
        litebox_micro::micro_init(
            shmem.fd_raw(),
            shmem.base_ptr(),
            shmem.layout().total_size,
            1,                              // pid — the guest is process 1
            0,                              // ppid — no parent
            central.pid().cast_unsigned(),   // central_pid — for /proc fd passing
            syscall_entry,                   // syscall_entry_point
        );
    }

    // Initialize the stack pool for vfork children, after micro_init.
    litebox_micro::state::init_stack_pool();

    // SAFETY: Called exactly once on the main thread, after `micro_init`,
    // before any guest code runs.
    unsafe {
        litebox_micro::micro_init_thread(0);
    }

    // 5. Jump to guest entry point — this never returns.
    // SAFETY: `entry_point` was produced by `load_elf` from a valid ELF, and
    // `stack_pointer` points to a properly initialised user stack with
    // argc/argv/envp/auxv.
    unsafe { entry::jump_to_guest(loaded.entry_point, loaded.stack_pointer) }
}
