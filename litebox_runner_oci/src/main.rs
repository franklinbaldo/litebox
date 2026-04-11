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
                    .map(|spec| {
                        let (mem, swap, pids) = spec
                            .linux()
                            .as_ref()
                            .and_then(|l| l.resources().as_ref())
                            .map(|res| {
                                let mem = res
                                    .memory()
                                    .as_ref()
                                    .and_then(|m| m.limit())
                                    .map_or(0_u64, |v| u64::try_from(v).unwrap_or(0));
                                let swap = res
                                    .memory()
                                    .as_ref()
                                    .and_then(|m| m.swap())
                                    .map_or(0_u64, |v| u64::try_from(v).unwrap_or(0));
                                let pids = res
                                    .pids()
                                    .as_ref()
                                    .map_or(0_i64, |p| p.limit());
                                (mem, swap, pids)
                            })
                            .unwrap_or((0, 0, 0));
                        (mem, swap, pids)
                    })
                    .unwrap_or((0, 0, 0))
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

            let exit_code =
                litebox_runner_oci::run_container(&bundle, None, &extra_env, &network, None, None)?;

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
