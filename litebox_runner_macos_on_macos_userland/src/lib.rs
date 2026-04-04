// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use anyhow::{Result, anyhow};
use clap::Parser;
use litebox::fs::{FileSystem as _, Mode};
use litebox_platform_multiplex::Platform;
use memmap2::Mmap;
use std::path::Path;

/// Run macOS Mach-O programs with LiteBox on Apple Silicon
#[derive(Parser, Debug)]
pub struct CliArgs {
    /// The program and arguments passed to it
    #[arg(required = true, trailing_var_arg = true, value_hint = clap::ValueHint::CommandWithArguments)]
    pub program_and_arguments: Vec<String>,
    /// Environment variables passed to the program (`K=V` pairs)
    #[arg(long = "env")]
    pub environment_variables: Vec<String>,
    /// Apply Mach-O syscall rewriter before running
    #[arg(long = "rewrite-syscalls", default_value = "true")]
    pub rewrite_syscalls: bool,
}

/// Run macOS Mach-O programs with LiteBox on Apple Silicon.
///
/// # Panics
///
/// Panics if any program argument or environment variable contains a null byte.
pub fn run(cli_args: CliArgs) -> Result<()> {
    let prog_path = Path::new(&cli_args.program_and_arguments[0]);
    let file = std::fs::File::open(prog_path)?;
    let mmap = unsafe { Mmap::map(&file) }
        .map_err(|e| anyhow!("Could not mmap {}: {}", prog_path.display(), e))?;
    let prog_data: &[u8] = &mmap;

    // Rewrite syscalls if requested
    let rewritten: Vec<u8>;
    let binary_data: &[u8] = if cli_args.rewrite_syscalls {
        rewritten = litebox_syscall_rewriter_macho::hook_syscalls_in_macho(prog_data)
            .map_err(|e| anyhow!("Mach-O rewriter failed: {e}"))?;
        &rewritten
    } else {
        prog_data
    };

    // Initialize platform
    let platform = Platform::new(None);
    litebox_platform_multiplex::set_platform(platform);

    // Build shim
    let mut shim_builder =
        litebox_shim_macos::MacosShimBuilder::<litebox_shim_macos::DefaultFS>::new();
    let litebox = shim_builder.litebox();
    let in_mem_fs = {
        let mut fs = litebox::fs::in_mem::FileSystem::new(litebox);
        fs.with_root_privileges(|fs| {
            let mode = Mode::RWXU | Mode::RWXG | Mode::RWXO;
            let _ = fs.mkdir("/tmp", mode);
        });
        fs
    };
    let tar_ro_fs =
        litebox::fs::tar_ro::FileSystem::new(litebox, litebox::fs::tar_ro::EMPTY_TAR_FILE.into());
    let fs = shim_builder.default_fs(in_mem_fs, tar_ro_fs);
    shim_builder.set_fs(fs);
    let shim = shim_builder.build();

    // Load program
    let argv = cli_args
        .program_and_arguments
        .iter()
        .map(|x| std::ffi::CString::new(x.bytes().collect::<Vec<u8>>()).unwrap())
        .collect();
    let envp: Vec<_> = cli_args
        .environment_variables
        .iter()
        .map(|x| std::ffi::CString::new(x.bytes().collect::<Vec<u8>>()).unwrap())
        .collect();

    let program = shim
        .load_program(binary_data, argv, envp, None)
        .map_err(|e| anyhow!("Failed to load Mach-O: {e}"))?;

    let litebox_shim_macos::LoadedProgram {
        entrypoints,
        process,
        mut initial_ctx,
    } = program;

    // Run thread
    unsafe {
        litebox_platform_macos_userland::run_thread(entrypoints, &mut initial_ctx);
    }

    std::process::exit(process.wait())
}
