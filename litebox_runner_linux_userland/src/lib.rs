// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use anyhow::{Result, anyhow};
use clap::Parser;
use litebox::fs::{FileSystem as _, Mode};
use litebox_platform_multiplex::Platform;
use memmap2::Mmap;
use std::os::linux::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

extern crate alloc;

/// Run Linux programs with LiteBox on unmodified Linux
#[derive(Parser, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct CliArgs {
    /// The program and arguments passed to it (e.g., `python3 --version`).
    ///
    /// By default this is a path on the host filesystem. When --program-from-tar
    /// is set, it refers to a path inside the tar archive instead.
    #[arg(required = true, trailing_var_arg = true, value_hint = clap::ValueHint::CommandWithArguments)]
    pub program_and_arguments: Vec<String>,
    /// Environment variables passed to the program (`K=V` pairs; can be invoked multiple times)
    #[arg(long = "env")]
    pub environment_variables: Vec<String>,
    /// Forward the existing environment variables
    #[arg(long = "forward-env")]
    pub forward_environment_variables: bool,
    /// Allow using unstable options
    #[arg(short = 'Z', long = "unstable")]
    pub unstable: bool,
    /// Pre-fill files into the initial file system state
    // TODO: Might want to extend this to support full directories at some point?
    #[arg(long = "insert-file", value_hint = clap::ValueHint::FilePath,
          requires = "unstable", help_heading = "Unstable Options")]
    pub insert_files: Vec<PathBuf>,
    /// Pre-fill the files in this tar file into the initial file system state
    #[arg(long = "initial-files", value_name = "PATH_TO_TAR", value_hint = clap::ValueHint::FilePath,
          requires = "unstable", help_heading = "Unstable Options")]
    pub initial_files: Option<PathBuf>,
    /// Apply syscall-rewriter to the ELF file before running it
    ///
    /// This is meant as a convenience feature; real deployments would likely prefer ahead-of-time
    /// rewrite things to amortize costs.
    #[arg(
        long = "rewrite-syscalls",
        requires = "unstable",
        help_heading = "Unstable Options"
    )]
    pub rewrite_syscalls: bool,
    /// Choice of interception backend
    #[arg(
        value_enum,
        long = "interception-backend",
        requires = "unstable",
        help_heading = "Unstable Options",
        default_value = "rewriter"
    )]
    pub interception_backend: InterceptionBackend,
    /// Connect to a TUN device with this name
    #[arg(
        long = "tun-device-name",
        requires = "unstable",
        help_heading = "Unstable Options"
    )]
    pub tun_device_name: Option<String>,
    /// Load the program binary from the tar file instead of from the host filesystem.
    ///
    /// When set, the program path refers to a path inside the tar filesystem.
    /// The binary must already be rewritten (incompatible with --rewrite-syscalls).
    /// This is used by `litebox-packager` to create fully self-contained tar bundles.
    #[arg(
        long = "program-from-tar",
        requires_all = ["unstable", "initial_files"],
        conflicts_with = "rewrite_syscalls",
        help_heading = "Unstable Options"
    )]
    pub program_from_tar: bool,
    /// Connect to a 9P file broker at the given address (e.g., 10.0.0.1:5640).
    ///
    /// Requires --tun-device-name. The broker must be a 9P2000.L server listening
    /// on the TUN gateway. All file I/O flows through the shim's network stack,
    /// making it suspension-aware for multi-process support.
    #[arg(
        long = "nine-p-broker",
        requires_all = ["unstable", "tun_device_name"],
        help_heading = "Unstable Options"
    )]
    pub nine_p_broker: Option<String>,

    /// Set the initial working directory for the sandboxed process.
    /// Defaults to "/".
    #[arg(long = "cwd", requires = "unstable", help_heading = "Unstable Options")]
    pub working_directory: Option<String>,
}

/// Backends supported for intercepting syscalls
#[non_exhaustive]
#[derive(Debug, Clone, clap::ValueEnum)]
pub enum InterceptionBackend {
    /// Use seccomp-based syscall interception
    Seccomp,
    /// Depend purely on rewriten syscalls to intercept them
    Rewriter,
}

struct MmappedFile {
    data: &'static [u8],
    abs_path: PathBuf,
}

fn mmapped_file(path: impl AsRef<Path>) -> Result<MmappedFile> {
    let path = path.as_ref();
    let abs_path = std::path::absolute(path)
        .map_err(|e| anyhow!("Could not get absolute path for {}: {}", path.display(), e))?;
    let file = std::fs::File::open(&abs_path)?;
    let data = {
        // SAFETY: We assume that the file given to us is not going to change _externally_ while in
        // the middle of execution. Since we are mapping it as read-only and mapping it only once,
        // we are not planning to change it either. With both these in mind, this call is safe.
        //
        // We need to leak the `Mmap` object, so that it stays alive until the end of the program,
        // rather than being unmapped at function finish (i.e., to get the `'static` lifetime).
        Box::leak(Box::new(unsafe { Mmap::map(&file) }.map_err(|e| {
            anyhow!("Could not read tar file at {}: {}", path.display(), e)
        })?))
    };
    Ok(MmappedFile { data, abs_path })
}

/// Run Linux programs with LiteBox on unmodified Linux
///
/// # Panics
///
/// Can panic if any particulars of the environment are not set up as expected. Ideally, would not
/// panic. If it does actually panic, then ping the authors of LiteBox, and likely a better error
/// message could be thrown instead.
pub fn run(cli_args: CliArgs) -> Result<()> {
    if !cli_args.insert_files.is_empty() {
        unimplemented!(
            "this should (hopefully soon) have a nicer interface to support loading in files"
        )
    }

    // When loading from tar, the program path is a guest-internal path and must
    // be absolute — LiteBox does not resolve programs via PATH.
    if cli_args.program_from_tar && !cli_args.program_and_arguments[0].starts_with('/') {
        anyhow::bail!(
            "--program-from-tar requires an absolute path (e.g., /usr/bin/ls), \
             got: {}",
            cli_args.program_and_arguments[0]
        );
    }

    let mut cow_eligible_regions: Vec<MmappedFile> = Vec::new();

    // When --program-from-tar is set, the program binary is already in the tar file,
    // so we skip reading it from the host filesystem and skip extracting ancestor modes.
    #[allow(clippy::type_complexity)]
    let (ancestor_modes_and_users, prog_data): (
        Vec<(litebox::fs::Mode, u32)>,
        Option<alloc::borrow::Cow<'static, [u8]>>,
    ) = if cli_args.program_from_tar {
        (Vec::new(), None)
    } else {
        let prog = std::path::absolute(Path::new(&cli_args.program_and_arguments[0])).unwrap();
        if !prog.exists() {
            let mut msg = format!("program not found on host filesystem: {}", prog.display());
            if cli_args.initial_files.is_some() {
                msg.push_str(
                    "\nhint: if the program is inside the tar archive, \
                     add --program-from-tar",
                );
            }
            anyhow::bail!(msg);
        }
        let ancestors: Vec<_> = prog.ancestors().collect();
        let modes: Vec<_> = ancestors
            .into_iter()
            .rev()
            .skip(1)
            .map(|path| {
                let metadata = path.metadata().unwrap();
                (
                    litebox::fs::Mode::from_bits(metadata.st_mode()).unwrap(),
                    metadata.st_uid(),
                )
            })
            .collect();
        let file = mmapped_file(&prog)?;
        let data = if cli_args.rewrite_syscalls {
            litebox_syscall_rewriter::hook_syscalls_in_elf(file.data, None)
                .unwrap()
                .into()
        } else {
            let data = file.data.into();
            cow_eligible_regions.push(file);
            data
        };
        (modes, Some(data))
    };
    let tar_data: &'static [u8] = if let Some(tar_file) = cli_args.initial_files.as_ref() {
        if tar_file.extension().and_then(|x| x.to_str()) != Some("tar") {
            anyhow::bail!("Expected a .tar file, found {}", tar_file.display());
        }
        mmapped_file(tar_file)?.data
    } else {
        litebox::fs::tar_ro::EMPTY_TAR_FILE
    };

    // TODO(jb): Clean up platform initialization once we have https://github.com/MSRSSP/litebox/issues/24
    //
    // TODO: We also need to pick the type of syscall interception based on whether we want
    // systrap/sigsys interception, or binary rewriting interception. Currently
    // `litebox_platform_linux_userland` does not provide a way to pick between the two.
    let platform = Platform::new(cli_args.tun_device_name.as_deref());

    for file in cow_eligible_regions {
        platform.register_cow_region(file.data, file.abs_path);
    }

    litebox_platform_multiplex::set_platform(platform);

    let shim_builder = litebox_shim_linux::LinuxShimBuilder::new();
    let litebox = shim_builder.litebox();
    let (in_mem, tar_ro) = build_initial_fs(
        litebox,
        &cli_args,
        &ancestor_modes_and_users,
        prog_data,
        tar_data,
    )?;
    let default_fs = shim_builder.default_fs(in_mem, tar_ro);
    finish_run(shim_builder, default_fs, &cli_args)
}

/// Build the in-memory and tar read-only file systems, including program data and /tmp.
///
/// This is extracted so that both the default and 9P-broker-enabled code paths can share it.
#[allow(clippy::type_complexity)]
fn build_initial_fs(
    litebox: &litebox::LiteBox<Platform>,
    cli_args: &CliArgs,
    ancestor_modes_and_users: &[(litebox::fs::Mode, u32)],
    prog_data: Option<alloc::borrow::Cow<'static, [u8]>>,
    tar_data: &'static [u8],
) -> Result<(
    litebox::fs::in_mem::FileSystem<Platform>,
    litebox::fs::tar_ro::FileSystem<Platform>,
)> {
    let mut in_mem = litebox::fs::in_mem::FileSystem::new(litebox);

    // When loading the program from the tar, we don't need to create ancestor
    // directories or write the program binary into the in-memory FS -- the program
    // is already in the tar layer.
    if let Some(prog_data) = prog_data {
        let prog = std::path::absolute(Path::new(&cli_args.program_and_arguments[0])).unwrap();
        let ancestors: Vec<_> = prog.ancestors().collect();
        let mut prev_user = 0;
        for (path, &mode_and_user) in ancestors
            .into_iter()
            .skip(1)
            .rev()
            .skip(1)
            .zip(ancestor_modes_and_users)
        {
            if prev_user == 0 {
                in_mem.with_root_privileges(|fs| {
                    fs.mkdir(path.to_str().unwrap(), mode_and_user.0).unwrap();
                    if mode_and_user.1 != 0 {
                        fs.chown(path.to_str().unwrap(), Some(1000), Some(1000))
                            .unwrap();
                    }
                });
            } else {
                in_mem
                    .mkdir(path.to_str().unwrap(), mode_and_user.0)
                    .unwrap();
            }
            prev_user = mode_and_user.1;
        }

        let open_file =
            |fs: &mut litebox::fs::in_mem::FileSystem<litebox_platform_multiplex::Platform>,
             path,
             mode| {
                let fd = fs
                    .open(
                        path,
                        litebox::fs::OFlags::WRONLY | litebox::fs::OFlags::CREAT,
                        mode,
                    )
                    .unwrap();
                fs.initialize_primarily_read_heavy_file(&fd, prog_data);
                fs.close(&fd).unwrap();
            };
        let last = ancestor_modes_and_users.last().ok_or_else(|| {
            anyhow!("program path has no ancestor directories (is it the root path?)")
        })?;
        if prev_user == 0 {
            in_mem.with_root_privileges(|fs| {
                open_file(fs, prog.to_str().unwrap(), last.0);
                if last.1 != 0 {
                    fs.chown(prog.to_str().unwrap(), Some(1000), Some(1000))
                        .unwrap();
                }
            });
        } else {
            open_file(&mut in_mem, prog.to_str().unwrap(), last.0);
        }
    }
    in_mem.with_root_privileges(|fs| {
        let mode = Mode::RWXU | Mode::RWXG | Mode::RWXO;
        if let Err(err) = fs.mkdir("/tmp", mode) {
            match err {
                litebox::fs::errors::MkdirError::AlreadyExists => {
                    fs.chmod("/tmp", mode).expect("Failed to call chmod");
                }
                _ => panic!(),
            }
        }
    });

    // When using the rewriter backend, the shim's mmap hook handles
    // syscall patching at runtime — no audit library needed.

    let tar_ro = litebox::fs::tar_ro::FileSystem::new(litebox, tar_data.into());
    Ok((in_mem, tar_ro))
}

/// Complete the run after the file system has been composed and the shim builder is ready.
///
/// This is generic over the file system type so it can handle both the default and
/// broker-enabled FS compositions.
fn finish_run<FS: litebox_shim_linux::ShimFS>(
    mut shim_builder: litebox_shim_linux::LinuxShimBuilder,
    fs: FS,
    cli_args: &CliArgs,
) -> Result<()> {
    let platform = litebox_platform_multiplex::platform();

    let prog = if cli_args.program_from_tar {
        PathBuf::from(&cli_args.program_and_arguments[0])
    } else {
        std::path::absolute(Path::new(&cli_args.program_and_arguments[0])).unwrap()
    };
    let prog_path = prog.to_str().ok_or_else(|| {
        anyhow!(
            "Could not convert program path {:?} to a string",
            cli_args.program_and_arguments[0]
        )
    })?;

    shim_builder.set_load_filter(fixup_env);

    match cli_args.interception_backend {
        InterceptionBackend::Seccomp => platform.enable_seccomp_based_syscall_interception(),
        InterceptionBackend::Rewriter => {}
    }

    let argv = build_argv(cli_args);
    let envp = build_envp(cli_args);

    // If a 9P broker is requested, build shim → start network → connect 9P → layer FS.
    // The FS type differs between branches, so each must build its own shim and run.
    if cli_args.nine_p_broker.is_some() {
        finish_run_with_nine_p(shim_builder, fs, cli_args, platform, prog_path, argv, envp)
    } else {
        let initial_file_system = std::sync::Arc::new(fs);
        let shim = shim_builder.build();

        let shutdown = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
        let net_worker = start_network_worker(&shim, &shutdown, cli_args);

        let program = shim.load_program(
            initial_file_system,
            platform.init_task(),
            prog_path,
            argv,
            envp,
            cli_args.working_directory.clone(),
        )?;

        run_program(program, shutdown, net_worker);
    }
}

/// Finish running with a 9P broker providing the lower file system layer.
///
/// Builds the shim, starts the network worker, connects to the 9P broker,
/// layers the resulting FS on top of the base FS, and runs the program.
fn finish_run_with_nine_p<FS: litebox_shim_linux::ShimFS>(
    shim_builder: litebox_shim_linux::LinuxShimBuilder,
    base_fs: FS,
    cli_args: &CliArgs,
    platform: &litebox_platform_multiplex::Platform,
    prog_path: &str,
    argv: Vec<alloc::ffi::CString>,
    envp: Vec<alloc::ffi::CString>,
) -> Result<()> {
    let broker_addr = cli_args.nine_p_broker.as_deref().unwrap();
    let addr: core::net::SocketAddr = broker_addr
        .parse()
        .map_err(|e| anyhow!("Invalid 9P broker address '{broker_addr}': {e}"))?;

    // Build shim — the FS type is determined by the combined layered FS below.
    let shim = shim_builder.build();

    let shutdown = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
    let net_worker = start_network_worker(&shim, &shutdown, cli_args);

    eprintln!("Connecting to 9P broker at {broker_addr}...");

    // Retry connection with backoff (broker might not be listening yet)
    let transport = {
        let mut attempts = 0;
        loop {
            match shim.tcp_connection(addr) {
                Ok(t) => break t,
                Err(e) => {
                    attempts += 1;
                    if attempts >= 50 {
                        return Err(anyhow!(
                            "Failed to connect to 9P broker at {broker_addr} after {attempts} attempts: {e:?}"
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }
    };

    let litebox = shim.litebox();
    let nine_p_fs = litebox::fs::nine_p::FileSystem::new(litebox, transport, 65536, "root", "/")
        .map_err(|e| anyhow!("9P attach failed: {e:?}"))?;

    eprintln!("9P broker connected.");

    let combined = litebox::fs::layered::FileSystem::new(
        litebox,
        base_fs,
        nine_p_fs,
        litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
    );
    let combined_fs = std::sync::Arc::new(combined);

    let program = shim.load_program(
        combined_fs,
        platform.init_task(),
        prog_path,
        argv,
        envp,
        cli_args.working_directory.clone(),
    )?;

    run_program(program, shutdown, net_worker);
}

/// Run the loaded program and exit with its return code.
///
/// This function never returns — it calls `std::process::exit()`.
fn run_program<FS: litebox_shim_linux::ShimFS>(
    program: litebox_shim_linux::LoadedProgram<FS>,
    shutdown: std::sync::Arc<core::sync::atomic::AtomicBool>,
    net_worker: Option<std::thread::JoinHandle<()>>,
) -> ! {
    #[cfg(feature = "lock_tracing")]
    litebox::sync::start_recording();

    unsafe {
        litebox_platform_linux_userland::run_thread(
            program.entrypoints,
            &mut litebox_common_linux::PtRegs::default(),
        );
    }

    #[cfg(feature = "lock_tracing")]
    {
        litebox::sync::stop_recording();
        let events = litebox::sync::flush_to_jsonl();
        if !events.is_empty() {
            use std::io::Write;
            if let Ok(mut file) = std::fs::File::create("/tmp/locks.jsonl") {
                for line in &events {
                    let _ = writeln!(file, "{line}");
                }
            }
        }
    }

    if let Some(net_worker) = net_worker {
        shutdown.store(true, core::sync::atomic::Ordering::Relaxed);
        net_worker.join().unwrap();
    }
    std::process::exit(program.process.wait())
}

/// Pin the current thread to a specific CPU core
fn pin_thread_to_cpu(cpu: usize) {
    unsafe {
        let mut set = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);

        if libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &raw const set) != 0 {
            eprintln!("Warning: Failed to pin thread to CPU core {cpu}");
        }
    }
}

/// Start the network worker thread if a TUN device is configured.
fn start_network_worker<FS: litebox_shim_linux::ShimFS>(
    shim: &litebox_shim_linux::LinuxShim<FS>,
    shutdown: &std::sync::Arc<core::sync::atomic::AtomicBool>,
    cli_args: &CliArgs,
) -> Option<std::thread::JoinHandle<()>> {
    cli_args.tun_device_name.as_ref()?;
    let shim = shim.clone();
    let shutdown_clone = shutdown.clone();
    let child = litebox_platform_linux_userland::spawn_host_thread(move || {
        const DEFAULT_TIMEOUT: core::time::Duration = core::time::Duration::from_millis(5);
        pin_thread_to_cpu(0);

        while !shutdown_clone.load(core::sync::atomic::Ordering::Relaxed) {
            let timeout = loop {
                match shim.perform_network_interaction() {
                    litebox::net::PlatformInteractionReinvocationAdvice::CallAgainImmediately => {}
                    litebox::net::PlatformInteractionReinvocationAdvice::WaitOnDeviceOrSocketInteraction { timeout } => {
                        break timeout;
                    }
                }
            };
            let wait = match timeout {
                Some(t) if t < DEFAULT_TIMEOUT => t,
                _ => DEFAULT_TIMEOUT,
            };
            litebox_platform_multiplex::platform().wait_on_tun(Some(wait));
        }
        while shim.perform_network_interaction().call_again_immediately() {}
    });
    Some(child)
}

/// Build argv from CLI args.
fn build_argv(cli_args: &CliArgs) -> Vec<std::ffi::CString> {
    cli_args
        .program_and_arguments
        .iter()
        .map(|x| std::ffi::CString::new(x.bytes().collect::<Vec<u8>>()).unwrap())
        .collect()
}

/// Build envp from CLI args, optionally forwarding host environment.
fn build_envp(cli_args: &CliArgs) -> Vec<std::ffi::CString> {
    let envp: Vec<_> = cli_args
        .environment_variables
        .iter()
        .map(|x| std::ffi::CString::new(x.bytes().collect::<Vec<u8>>()).unwrap())
        .collect();
    if cli_args.forward_environment_variables {
        envp.into_iter()
            .chain(std::env::vars().map(|(k, v)| {
                std::ffi::CString::new(
                    k.bytes()
                        .chain([b'='])
                        .chain(v.bytes())
                        .collect::<Vec<u8>>(),
                )
                .unwrap()
            }))
            .collect()
    } else {
        envp
    }
}

fn fixup_env(_envp: &mut Vec<alloc::ffi::CString>) {
    // No environment fixups needed — the shim's mmap hook handles
    // syscall patching at runtime without LD_AUDIT.
}
