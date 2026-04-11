// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! OCI-compliant container runtime CLI using LiteBox sandbox.
//!
//! Implements OCI runtime specification commands for running
//! containers through LiteBox's userspace syscall emulation.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use litebox_runner_oci::lifecycle::Lifecycle;
use litebox_runner_oci::state::StateManager;

#[derive(Parser, Debug)]
#[clap(
    name = "litebox-oci",
    about = "OCI container runtime powered by LiteBox"
)]
#[command(version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    /// Root directory for container state
    #[clap(long)]
    root: Option<PathBuf>,

    /// Log file path (runtime logs are written here when provided)
    #[clap(long)]
    log: Option<PathBuf>,

    /// Log format: "text" (default) or "json"
    #[clap(long, default_value = "text")]
    log_format: String,

    /// Systemd cgroup mode (accepted for Podman compatibility, ignored)
    #[clap(long)]
    systemd_cgroup: bool,

    /// TUN device name for container networking (e.g., "tun99").
    /// Requires a pre-configured TUN device on the host.
    #[clap(long, value_name = "DEVICE")]
    tun_device: Option<String>,

    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create a container (OCI lifecycle)
    Create {
        /// Path to the OCI bundle directory
        #[clap(short = 'b', long)]
        bundle: PathBuf,

        /// Unique identifier for the container
        container_id: String,

        /// File to write the container PID to
        #[clap(long)]
        pid_file: Option<PathBuf>,

        /// Console socket path for TTY support.
        /// A PTY is created and the master fd is sent via SCM_RIGHTS.
        #[clap(long)]
        console_socket: Option<PathBuf>,

        /// Don't use pivot_root (accepted, we never pivot anyway)
        #[clap(long)]
        no_pivot: bool,

        /// Don't create new namespaces (accepted, we don't use namespaces)
        #[clap(long)]
        no_new_keyring: bool,

        /// TUN device name for container networking (e.g., "tun99").
        /// Requires a pre-configured TUN device on the host.
        #[clap(long, value_name = "DEVICE")]
        tun_device: Option<String>,
    },

    /// Start a created container (OCI lifecycle)
    Start {
        /// Container ID
        container_id: String,
    },

    /// Query container state (OCI lifecycle)
    State {
        /// Container ID
        container_id: String,
    },

    /// Send a signal to a container (OCI lifecycle)
    Kill {
        /// Container ID
        container_id: String,

        /// Signal to send (default: SIGTERM)
        #[clap(default_value = "SIGTERM")]
        signal: String,

        /// Send signal to all processes (accepted but ignored)
        #[clap(short, long)]
        all: bool,
    },

    /// Delete a container (OCI lifecycle)
    Delete {
        /// Container ID
        container_id: String,

        /// Force deletion even if container is running
        #[clap(short, long)]
        force: bool,
    },

    /// List all containers
    List,

    /// Pause a running container
    Pause {
        /// Container ID
        container_id: String,
    },

    /// Resume a paused container
    Resume {
        /// Container ID
        container_id: String,
    },

    /// Display container events and statistics
    Events {
        /// Container ID
        container_id: String,

        /// Display stats once and exit
        #[clap(long)]
        stats: bool,

        /// Stats collection interval (ignored, stats are emulated)
        #[clap(long, default_value = "5s")]
        interval: String,
    },

    /// Create and immediately run a container (convenience command)
    Run {
        /// Path to the OCI bundle directory
        #[clap(short, long)]
        bundle: PathBuf,

        /// Container ID
        container_id: String,

        /// Set environment variables (can be specified multiple times)
        #[clap(short, long, value_name = "KEY=VALUE")]
        env: Vec<String>,

        /// Read environment variables from a file (one KEY=VALUE per line)
        #[clap(long, value_name = "FILE")]
        env_file: Option<PathBuf>,

        /// TUN device name for container networking (e.g., "tun99").
        /// Requires a pre-configured TUN device on the host.
        #[clap(long, value_name = "DEVICE")]
        tun_device: Option<String>,
    },

    /// Execute a command in a container's rootfs (simplified exec)
    ///
    /// Note: This creates a new sandbox with the same rootfs, it does not
    /// share process state with the running container.
    Exec {
        /// Container ID
        container_id: String,

        /// Path to OCI process.json with args/env/cwd/user
        #[clap(short = 'p', long, value_name = "FILE")]
        process: Option<PathBuf>,

        /// Console socket path for PTY support.
        /// A PTY is created and the master fd is sent via SCM_RIGHTS.
        #[clap(long)]
        console_socket: Option<PathBuf>,

        /// File to write the exec process PID to
        #[clap(long)]
        pid_file: Option<PathBuf>,

        /// Fork and have the parent exit immediately (conmon expects this)
        #[clap(long)]
        detach: bool,

        /// Allocate a TTY (accepted for compat; actual PTY driven by --console-socket)
        #[clap(long)]
        tty: bool,

        /// Set environment variables (can be specified multiple times)
        #[clap(short, long, value_name = "KEY=VALUE")]
        env: Vec<String>,

        /// Read environment variables from a file (one KEY=VALUE per line)
        #[clap(long, value_name = "FILE")]
        env_file: Option<PathBuf>,

        /// TUN device name for container networking (e.g., "tun99").
        /// Requires a pre-configured TUN device on the host.
        #[clap(long, value_name = "DEVICE")]
        tun_device: Option<String>,

        /// Command and arguments to execute
        #[clap(num_args = 0..)]
        command: Vec<String>,
    },

    /// Show runtime version and features
    Info,

    /// Checkpoint a running container (CRIU-style)
    Checkpoint {
        /// Container ID
        container_id: String,

        /// Directory to write the checkpoint image to
        #[clap(long = "image-path")]
        image_path: PathBuf,

        /// Leave the container running after checkpoint (ignored — always stops)
        #[clap(long)]
        leave_running: bool,

        /// Path to a CRIU binary (accepted for compat, ignored)
        #[clap(long)]
        work_path: Option<PathBuf>,
    },

    /// Restore a container from a checkpoint image
    Restore {
        /// Path to the OCI bundle directory
        #[clap(short = 'b', long)]
        bundle: PathBuf,

        /// Container ID
        container_id: String,

        /// Directory containing the checkpoint image
        #[clap(long = "image-path")]
        image_path: PathBuf,

        /// File to write the container PID to
        #[clap(long)]
        pid_file: Option<PathBuf>,

        /// Console socket path for TTY support
        #[clap(long)]
        console_socket: Option<PathBuf>,

        /// Don't use pivot_root (accepted, we never pivot anyway)
        #[clap(long)]
        no_pivot: bool,

        /// Don't create new namespaces (accepted, ignored)
        #[clap(long)]
        no_new_keyring: bool,

        /// Detach from the container's process (run in background)
        #[clap(long, short)]
        detach: bool,

        /// TUN device name for container networking
        #[clap(long, value_name = "DEVICE")]
        tun_device: Option<String>,
    },
}

/// Parse a signal name or number into a signal number.
fn parse_signal(s: &str) -> Result<i32> {
    // Try parsing as number first
    if let Ok(num) = s.parse::<i32>() {
        return Ok(num);
    }

    // Parse signal name
    let s = s.to_uppercase();
    let s = s.strip_prefix("SIG").unwrap_or(&s);

    match s {
        "TERM" => Ok(libc::SIGTERM),
        "KILL" => Ok(libc::SIGKILL),
        "INT" => Ok(libc::SIGINT),
        "HUP" => Ok(libc::SIGHUP),
        "QUIT" => Ok(libc::SIGQUIT),
        "USR1" => Ok(libc::SIGUSR1),
        "USR2" => Ok(libc::SIGUSR2),
        "STOP" => Ok(libc::SIGSTOP),
        "CONT" => Ok(libc::SIGCONT),
        _ => anyhow::bail!("unknown signal: {s}"),
    }
}

/// Parse environment variables from command line and optional env file.
fn parse_extra_env(env: &[String], env_file: Option<&PathBuf>) -> Result<Vec<String>> {
    let mut extra_env = Vec::new();

    // Parse env file if provided
    if let Some(path) = env_file {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read env file: {}", path.display()))?;

        for line in content.lines() {
            let line = line.trim();
            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Validate KEY=VALUE format
            if !line.contains('=') {
                anyhow::bail!("invalid env file line (expected KEY=VALUE): {line}");
            }
            extra_env.push(line.to_string());
        }
    }

    // Add command-line env vars (these override file vars)
    for var in env {
        if !var.contains('=') {
            anyhow::bail!("invalid env var (expected KEY=VALUE): {var}");
        }
        extra_env.push(var.clone());
    }

    Ok(extra_env)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Set up tracing: --log writes to file, RUST_LOG writes to stderr
    if let Some(ref log_path) = cli.log {
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .with_context(|| format!("failed to open log file: {}", log_path.display()))?;
        let filter = tracing_subscriber::EnvFilter::from_default_env()
            .add_directive("tar_no_std=off".parse().unwrap())
            .add_directive(tracing::Level::DEBUG.into());
        if cli.log_format == "json" {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .json()
                .with_writer(log_file)
                .init();
        } else {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(log_file)
                .init();
        }
    } else if std::env::var("RUST_LOG").is_ok() {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive("tar_no_std=off".parse().unwrap()),
            )
            .init();
    }
    let root = cli.root.unwrap_or_else(|| {
        // Try XDG_RUNTIME_DIR first (works in rootless Podman and user sessions),
        // then /run for real root, then /tmp as last resort
        if let Ok(xrd) = std::env::var("XDG_RUNTIME_DIR") {
            PathBuf::from(xrd).join("litebox-oci")
        } else if unsafe { libc::geteuid() } == 0 {
            PathBuf::from("/run/litebox-oci")
        } else {
            PathBuf::from("/tmp/litebox-oci")
        }
    });
    let state_manager = StateManager::new(root.clone());
    let lifecycle = Lifecycle::new(state_manager);

    match cli.command {
        Command::Create {
            bundle,
            container_id,
            pid_file,
            console_socket,
            no_pivot: _,       // Accepted, we never pivot anyway
            no_new_keyring: _, // Accepted, we don't use keyrings
            tun_device,
        } => {
            // Merge global and subcommand-level flags (Podman passes via global)
            let tun_device = cli.tun_device.or(tun_device);

            tracing::info!(
                container_id = %container_id,
                bundle = %bundle.display(),
                tun_device = ?tun_device,
                "creating container"
            );

            // Collect extra run args to forward to the child process
            let mut extra_run_args = Vec::new();
            if let Some(ref dev) = tun_device {
                extra_run_args.push("--tun-device".to_string());
                extra_run_args.push(dev.clone());
            }

            let state = lifecycle.create(
                &container_id,
                &bundle,
                console_socket.as_deref(),
                &extra_run_args,
            )?;

            // Write PID file if requested
            if let Some(pid_file) = pid_file
                && let Some(pid) = state.pid
            {
                std::fs::write(&pid_file, format!("{pid}"))
                    .with_context(|| format!("failed to write pid file: {}", pid_file.display()))?;
            }

            Ok(())
        }

        Command::Start { container_id } => {
            tracing::info!(container_id = %container_id, "starting container");

            let _state = lifecycle.start(&container_id)?;
            Ok(())
        }

        Command::State { container_id } => {
            let state = lifecycle.state(&container_id)?;
            println!("{}", serde_json::to_string_pretty(&state)?);
            Ok(())
        }

        Command::Kill {
            container_id,
            signal,
            all: _, // Accepted but ignored - we only have one process
        } => {
            let sig = parse_signal(&signal)?;
            tracing::info!(container_id = %container_id, signal = sig, "killing container");

            lifecycle.kill(&container_id, sig)?;
            Ok(())
        }

        Command::Delete {
            container_id,
            force,
        } => {
            tracing::info!(container_id = %container_id, force = force, "deleting container");

            lifecycle.delete(&container_id, force)?;
            Ok(())
        }

        Command::List => {
            let states = lifecycle.list()?;
            if states.is_empty() {
                println!("No containers");
            } else {
                println!("{:<20} {:<10} {:<10} BUNDLE", "ID", "STATUS", "PID");
                for state in states {
                    println!(
                        "{:<20} {:<10} {:<10} {}",
                        state.id,
                        state.status,
                        state.pid.map(|p| p.to_string()).unwrap_or_default(),
                        state.bundle.display()
                    );
                }
            }
            Ok(())
        }

        Command::Pause { container_id } => {
            lifecycle.pause(&container_id)?;
            Ok(())
        }

        Command::Resume { container_id } => {
            lifecycle.resume(&container_id)?;
            Ok(())
        }

        Command::Events {
            container_id,
            stats,
            interval: _,
        } => {
            // Verify container exists
            let state = lifecycle.state(&container_id)?;

            // Read resource limits from the OCI spec in the bundle
            let (memory_limit, swap_limit, pids_limit) = {
                let config_path = state.bundle.join("config.json");
                std::fs::File::open(&config_path)
                    .ok()
                    .and_then(|f| serde_json::from_reader::<_, oci_spec::runtime::Spec>(f).ok())
                    .map_or((0, 0, 0), |spec| {
                        let (mem, swap, pids) = spec
                            .linux()
                            .as_ref()
                            .and_then(|l| l.resources().as_ref())
                            .map_or((0, 0, 0), |res| {
                                let mem = res
                                    .memory()
                                    .as_ref()
                                    .and_then(oci_spec::runtime::LinuxMemory::limit)
                                    .map_or(0_u64, |v| u64::try_from(v).unwrap_or(0));
                                let swap = res
                                    .memory()
                                    .as_ref()
                                    .and_then(oci_spec::runtime::LinuxMemory::swap)
                                    .map_or(0_u64, |v| u64::try_from(v).unwrap_or(0));
                                let pids = res
                                    .pids()
                                    .as_ref()
                                    .map_or(0_i64, oci_spec::runtime::LinuxPids::limit);
                                (mem, swap, pids)
                            });
                        (mem, swap, pids)
                    })
            };

            // Try to get real stats from /proc if PID is available
            #[allow(clippy::similar_names)]
            let (memory_usage, cpu_user_ns, cpu_sys_ns) = if let Some(pid) = state.pid {
                // Read memory from /proc/[pid]/statm (pages)
                let mem = std::fs::read_to_string(format!("/proc/{pid}/statm"))
                    .ok()
                    .and_then(|s| {
                        s.split_whitespace()
                            .next()
                            .and_then(|v| v.parse::<u64>().ok())
                    })
                    .map_or(0, |pages| pages * 4096); // Convert pages to bytes

                // Read CPU time from /proc/[pid]/stat
                let (utime, stime) = std::fs::read_to_string(format!("/proc/{pid}/stat"))
                    .ok()
                    .and_then(|s| {
                        let parts: Vec<&str> = s.split_whitespace().collect();
                        if parts.len() > 14 {
                            let utime = parts[13].parse::<u64>().unwrap_or(0);
                            let stime = parts[14].parse::<u64>().unwrap_or(0);
                            // Convert jiffies to nanoseconds (assuming 100 Hz)
                            Some((utime * 10_000_000, stime * 10_000_000))
                        } else {
                            None
                        }
                    })
                    .unwrap_or((0, 0));

                (mem, utime, stime)
            } else {
                (0, 0, 0)
            };

            // Generate stats JSON matching runc format
            let stats_json = serde_json::json!({
                "type": "stats",
                "id": container_id,
                "data": {
                    "cpu": {
                        "usage": {
                            "total": cpu_user_ns + cpu_sys_ns,
                            "kernel": cpu_sys_ns,
                            "user": cpu_user_ns
                        },
                        "throttling": {}
                    },
                    "memory": {
                        "usage": {
                            "limit": memory_limit,
                            "usage": memory_usage,
                            "max": memory_usage,
                            "failcnt": 0
                        },
                        "swap": {
                            "limit": swap_limit,
                            "usage": 0,
                            "failcnt": 0
                        }
                    },
                    "pids": {
                        "current": i32::from(state.pid.is_some()),
                        "limit": pids_limit
                    },
                    "blkio": {},
                    "hugetlb": {},
                    "intel_rdt": {}
                }
            });

            println!("{stats_json}");

            // If not --stats, we would loop. For now, just exit after one output.
            // Real implementation would loop with interval.
            if !stats {
                // In streaming mode, runc loops forever. We just output once.
                // Container orchestrators typically use --stats for one-shot.
            }

            Ok(())
        }

        Command::Run {
            bundle,
            container_id,
            env,
            env_file,
            tun_device,
        } => {
            tracing::info!(
                container_id = %container_id,
                bundle = %bundle.display(),
                tun_device = ?tun_device,
                "running container"
            );

            let bundle = bundle
                .canonicalize()
                .with_context(|| format!("bundle path not found: {}", bundle.display()))?;

            // Set up network configuration
            let network = litebox_runner_oci::NetworkConfig {
                tun_device: tun_device.clone(),
                cni: None,
            };

            let extra_env = parse_extra_env(&env, env_file.as_ref())?;

            // Compute state directory for checkpoint support.
            // The state dir exists when the container was created via
            // lifecycle create → start → (exec's "litebox-oci run").
            let state_dir = {
                let sd = root.join("containers").join(&container_id);
                if sd.exists() { Some(sd) } else { None }
            };

            let exit_code = litebox_runner_oci::run_container(
                &bundle, None, &extra_env, &network, None, None, state_dir,
            )?;

            // Save exit code to state (if this was a create+start lifecycle container)
            let sm = StateManager::new(root);
            if sm.exists(&container_id) {
                let _ = sm.update(&container_id, |s| {
                    s.status = litebox_runner_oci::state::Status::Stopped;
                    s.exit_code = Some(exit_code);
                });
            }

            std::process::exit(exit_code);
        }

        Command::Exec {
            container_id,
            process,
            console_socket,
            pid_file,
            detach,
            tty: _,
            env,
            env_file,
            tun_device,
            command,
        } => {
            tracing::info!(
                container_id = %container_id,
                process_json = ?process,
                console_socket = ?console_socket,
                pid_file = ?pid_file,
                detach = detach,
                command = ?command,
                tun_device = ?tun_device,
                "exec in container"
            );

            // Load container state to get bundle path
            let state = lifecycle.state(&container_id)?;

            // Container must exist (any status is fine for exec)
            let bundle = state.bundle;

            // Set up network configuration
            let network = litebox_runner_oci::NetworkConfig {
                tun_device: tun_device.clone(),
                cni: None,
            };

            // Parse process.json if provided
            let (proc_args, proc_env, proc_cwd, proc_user) = if let Some(ref p) = process {
                let (args, penv, cwd, user) = litebox_runner_oci::parse_process_spec(p)?;
                (Some(args), penv, cwd, user)
            } else {
                (None, vec![], None, None)
            };

            // Determine final args: --process overrides, then CLI command
            let override_args = if let Some(ref args) = proc_args {
                Some(args.as_slice())
            } else if !command.is_empty() {
                Some(command.as_slice())
            } else {
                None
            };

            // Merge env: process.json env first, then env-file, then CLI --env
            let mut extra_env = proc_env;
            extra_env.extend(parse_extra_env(&env, env_file.as_ref())?);

            let exit_code = litebox_runner_oci::exec_container(
                &bundle,
                override_args,
                &extra_env,
                &network,
                console_socket.as_deref(),
                pid_file.as_deref(),
                detach,
                proc_cwd.as_deref(),
                proc_user.as_ref(),
            )?;
            std::process::exit(exit_code);
        }

        Command::Checkpoint {
            container_id,
            image_path,
            leave_running: _,
            work_path: _,
        } => {
            tracing::info!(
                container_id = %container_id,
                image_path = %image_path.display(),
                "checkpointing container"
            );

            // Load container state to get PID
            let state = lifecycle.state(&container_id)?;
            let pid = state.pid.context("container has no PID (not running?)")?;

            if state.status != litebox_runner_oci::state::Status::Running
                && state.status != litebox_runner_oci::state::Status::Created
            {
                anyhow::bail!(
                    "cannot checkpoint container {}: status is {} (expected running)",
                    container_id,
                    state.status
                );
            }

            // Ensure image directory exists
            std::fs::create_dir_all(&image_path).with_context(|| {
                format!(
                    "failed to create checkpoint image directory: {}",
                    image_path.display()
                )
            })?;

            // Write the checkpoint request file.
            // The sandbox monitors this file when it receives SIGUSR1.
            let state_dir = root.join("containers").join(&container_id);
            let request_file = state_dir.join("checkpoint-request");
            let checkpoint_image_file = image_path.join("checkpoint.img");
            std::fs::write(
                &request_file,
                checkpoint_image_file.to_string_lossy().as_ref(),
            )
            .with_context(|| {
                format!(
                    "failed to write checkpoint request: {}",
                    request_file.display()
                )
            })?;

            // Send SIGUSR1 to the sandbox process to trigger checkpoint.
            // SAFETY: kill() is a standard POSIX syscall and pid is a valid PID.
            #[allow(clippy::cast_possible_wrap)]
            let ret = unsafe { libc::kill(pid as i32, libc::SIGUSR1) };
            if ret != 0 {
                // Clean up request file
                let _ = std::fs::remove_file(&request_file);
                anyhow::bail!(
                    "failed to send SIGUSR1 to container process {pid}: {}",
                    std::io::Error::last_os_error()
                );
            }

            tracing::info!(pid = pid, "sent SIGUSR1, waiting for process to exit");

            // Wait for the sandbox process to exit (it exits after writing checkpoint).
            // Use waitpid with WNOHANG in a poll loop — the process is our child
            // only if we are the original create parent. Otherwise, just poll
            // /proc/<pid>/stat until it disappears.
            let start = std::time::Instant::now();
            let timeout = std::time::Duration::from_secs(60);
            loop {
                // Check if process is still alive
                #[allow(clippy::cast_possible_wrap)]
                let alive = unsafe { libc::kill(pid as i32, 0) } == 0;
                if !alive {
                    break;
                }
                if start.elapsed() > timeout {
                    let _ = std::fs::remove_file(&request_file);
                    anyhow::bail!(
                        "timeout waiting for container {container_id} to checkpoint (PID {pid})"
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }

            // Clean up
            let _ = std::fs::remove_file(&request_file);

            // Update container state to stopped
            let _ = lifecycle.state_manager().update(&container_id, |s| {
                s.status = litebox_runner_oci::state::Status::Stopped;
                s.exit_code = Some(0);
            });

            // Verify checkpoint file was written
            if checkpoint_image_file.exists() {
                let metadata = std::fs::metadata(&checkpoint_image_file)?;
                tracing::info!(
                    path = %checkpoint_image_file.display(),
                    size = metadata.len(),
                    "checkpoint image written"
                );
                eprintln!(
                    "checkpoint: {} ({} bytes)",
                    checkpoint_image_file.display(),
                    metadata.len()
                );
            } else {
                anyhow::bail!(
                    "checkpoint image not found at {} — sandbox may have failed to write it",
                    checkpoint_image_file.display()
                );
            }

            Ok(())
        }

        Command::Restore {
            bundle,
            container_id,
            image_path,
            pid_file,
            console_socket: _, // TODO: PTY restore
            no_pivot: _,
            no_new_keyring: _,
            detach: _, // TODO: detach support
            tun_device,
        } => {
            tracing::info!(
                container_id = %container_id,
                bundle = %bundle.display(),
                image_path = %image_path.display(),
                "restoring container from checkpoint"
            );

            let bundle = bundle
                .canonicalize()
                .with_context(|| format!("bundle path not found: {}", bundle.display()))?;

            let checkpoint_image_file = image_path.join("checkpoint.img");
            if !checkpoint_image_file.exists() {
                anyhow::bail!(
                    "checkpoint image not found: {}",
                    checkpoint_image_file.display()
                );
            }

            // Create the container state directory
            let state_dir = root.join("containers").join(&container_id);
            std::fs::create_dir_all(&state_dir)?;

            // Fork: child does the restore, parent saves state and exits
            match unsafe { nix::unistd::fork() } {
                Ok(nix::unistd::ForkResult::Parent { child }) => {
                    let pid = child.as_raw().cast_unsigned();

                    // Write PID file if requested
                    if let Some(ref pf) = pid_file {
                        std::fs::write(pf, format!("{pid}")).with_context(|| {
                            format!("failed to write pid file: {}", pf.display())
                        })?;
                    }

                    // Save container state
                    let mut state = litebox_runner_oci::state::ContainerState::new(
                        container_id.clone(),
                        bundle.clone(),
                    );
                    state.status = litebox_runner_oci::state::Status::Running;
                    state.pid = Some(pid);
                    lifecycle.state_manager().save(&state)?;

                    Ok(())
                }
                Ok(nix::unistd::ForkResult::Child) => {
                    // Open checkpoint image and get fd
                    use std::os::fd::AsRawFd;
                    let file = std::fs::File::open(&checkpoint_image_file).with_context(|| {
                        format!(
                            "failed to open checkpoint image: {}",
                            checkpoint_image_file.display()
                        )
                    })?;
                    let fd = file.as_raw_fd();

                    // Exec litebox-oci run with fork-restore flags.
                    // The runner's fork-restore path reads the snapshot from the
                    // given fd and restores the full sandbox state.
                    let exe =
                        std::env::current_exe().context("failed to get current executable")?;

                    // We need the 9P broker for rootfs. Parse OCI spec for rootfs path.
                    let spec_path = bundle.join("config.json");
                    let spec: oci_spec::runtime::Spec = serde_json::from_reader(
                        std::fs::File::open(&spec_path).context("failed to open config.json")?,
                    )
                    .context("failed to parse config.json")?;

                    let rootfs_path = bundle.join(
                        spec.root()
                            .as_ref()
                            .map_or(std::path::Path::new("rootfs"), |r| r.path().as_path()),
                    );

                    // For restore, we launch the runner directly with fork-restore
                    // args. The runner's CliArgs::fork_restore path handles everything.
                    let mut cmd = exec::Command::new(&exe);
                    cmd.arg("run").arg("--bundle").arg(&bundle);
                    if let Some(ref dev) = tun_device {
                        cmd.arg("--tun-device").arg(dev);
                    }
                    cmd.arg(&container_id);

                    // TODO: The fork-restore path in litebox_runner_linux_userland
                    // requires --fork-restore and --fork-restore-fd flags on the
                    // inner runner binary, but we go through the OCI run path here.
                    // For now, we pass the checkpoint path via environment and let
                    // run_container handle it (to be completed in a follow-up).
                    //
                    // For this initial implementation, we can directly invoke the
                    // litebox runner binary with the fork-restore flags.

                    // Set the checkpoint fd as an env var for the restore path
                    // SAFETY: we are in a freshly-forked child with a single
                    // thread — no concurrent readers of the environment.
                    unsafe {
                        std::env::set_var("LITEBOX_RESTORE_FD", format!("{fd}"));
                        std::env::set_var(
                            "LITEBOX_RESTORE_ROOTFS",
                            rootfs_path.to_string_lossy().as_ref(),
                        );
                    }

                    let err = cmd.exec();
                    eprintln!("restore: exec failed: {err}");
                    std::process::exit(1);
                }
                Err(e) => {
                    anyhow::bail!("fork failed: {e}");
                }
            }
        }

        Command::Info => {
            println!("litebox-oci - OCI container runtime powered by LiteBox");
            println!("Version: {}", env!("CARGO_PKG_VERSION"));
            println!();
            println!("Features:");
            println!("  - Userspace syscall emulation via LiteBox");
            println!("  - In-memory filesystem isolation");
            println!("  - Syscall rewriting for interception");
            println!("  - TUN-based networking (--tun-device)");
            println!();
            println!("OCI Lifecycle Commands:");
            println!("  create  - Create a container");
            println!("  start   - Start a created container");
            println!("  state   - Query container state");
            println!("  kill    - Send signal to container");
            println!("  delete  - Delete a container");
            println!("  list    - List all containers");
            println!();
            println!("Convenience Commands:");
            println!("  run     - Create and run a container directly");
            println!("  exec    - Run a command in a container's rootfs");
            println!("  info    - Show this information");
            Ok(())
        }
    }
}
