// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

mod central;
mod entry;
mod load_elf;
mod loader;
mod shmem;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        anyhow::bail!("Usage: litebox_launcher <elf-path> [args...]");
    }
    let elf_path = &args[1];

    // 1. Create shared memory region for IPC ring buffer.
    let shmem = shmem::LauncherSharedRegion::new()?;

    // 2. Spawn central process (child inherits the shmem fd).
    let central = central::CentralProcess::spawn(shmem.fd_raw())?;

    // Give central time to initialize (platform, shim, server loop).
    // TODO: Replace with proper readiness signaling via ring header.
    std::thread::sleep(std::time::Duration::from_millis(200));

    // 3. Initialize micro-LiteBox global state and thread-local storage.
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
        );
    }

    // SAFETY: Called exactly once on the main thread, after `micro_init`,
    // before any guest code runs.
    unsafe {
        litebox_micro::micro_init_thread(0);
    }

    // 4. Load the guest ELF binary.
    let syscall_entry = litebox_micro::get_syscall_entry_point();
    let guest_argv: Vec<&str> = args[1..].iter().map(String::as_str).collect();
    let guest_envp: Vec<&str> = Vec::new(); // empty environment for now
    let loaded = load_elf::load_elf(elf_path, &guest_argv, &guest_envp, syscall_entry)?;

    // 5. Jump to guest entry point — this never returns.
    // SAFETY: `entry_point` was produced by `load_elf` from a valid ELF, and
    // `stack_pointer` points to a properly initialised user stack with
    // argc/argv/envp/auxv.
    unsafe { entry::jump_to_guest(loaded.entry_point, loaded.stack_pointer) }
}
