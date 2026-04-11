// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! LiteBox-native OCI container execution.
//!
//! This module runs OCI containers through LiteBox's sandbox by spawning a
//! `litebox_broker` child process for rootfs access (9P with on-the-fly ELF
//! rewriting), optionally detecting CNI networking from the OCI spec, and
//! delegating to `litebox_runner_linux_userland::run()`.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use anyhow::{Context, Result};
use oci_spec::runtime::Spec;

use litebox_runner_linux_userland::{CliArgs, InterceptionBackend};

/// Network configuration for container.
#[derive(Debug, Clone, Default)]
pub struct NetworkConfig {
    /// TUN device name for networking.
    pub tun_device: Option<String>,
    /// CNI-detected network configuration.
    pub cni: Option<CniNetworkConfig>,
}

/// CNI-detected network configuration.
#[derive(Debug, Clone)]
pub struct CniNetworkConfig {
    /// Path to the network namespace.
    pub netns_path: Option<PathBuf>,
    /// Container interface IP address.
    pub ip_addr: std::net::Ipv4Addr,
    /// Network prefix length.
    pub prefix_len: u8,
    /// Gateway IP address.
    pub gateway: std::net::Ipv4Addr,
    /// Interface MTU.
    pub mtu: u16,
}

// ---------------------------------------------------------------------------
// CNI detection helpers
// ---------------------------------------------------------------------------

/// Detect CNI network configuration from the OCI spec's network namespace.
///
/// Two detection strategies:
/// 1. If the spec defines a network namespace with a path (Podman), enters that namespace
///    and reads the interface configuration.
/// 2. If no netns path is available (e.g., `ctr --cni`), checks whether we're already
///    inside a netns with a non-loopback interface and reads config directly.
pub fn detect_cni_network(spec: &Spec) -> Option<CniNetworkConfig> {
    use oci_spec::runtime::LinuxNamespaceType;

    let linux = spec.linux().as_ref()?;
    let namespaces = linux.namespaces().as_ref()?;

    // Find network namespace entry
    let net_ns = namespaces
        .iter()
        .find(|ns| ns.typ() == LinuxNamespaceType::Network)?;

    if let Some(netns_path) = net_ns.path().as_ref() {
        // Strategy 1: explicit netns path (Podman) — enter it and read config
        use std::os::unix::io::AsRawFd;

        let netns_file = std::fs::File::open(netns_path).ok()?;
        let orig_netns = std::fs::File::open("/proc/self/ns/net").ok()?;

        let clone_newnet: libc::c_int = 0x40000000; // CLONE_NEWNET
                                                    // SAFETY: setns is a standard Linux syscall. We pass a valid fd and flag.
        let ret = unsafe { libc::setns(netns_file.as_raw_fd(), clone_newnet) };
        if ret != 0 {
            return None;
        }

        let result = read_netns_config(Some(netns_path));

        // Restore original netns
        // SAFETY: restoring the original network namespace with a valid fd.
        unsafe {
            libc::setns(orig_netns.as_raw_fd(), clone_newnet);
        }

        result
    } else {
        // Strategy 2: no netns path (ctr --cni) — we may already be inside the netns.
        if !is_in_non_default_netns() {
            return None;
        }
        read_netns_config(None)
    }
}

/// Check if the current process is in a different network namespace than PID 1.
fn is_in_non_default_netns() -> bool {
    let self_ns = std::fs::read_link("/proc/self/ns/net").ok();
    let init_ns = std::fs::read_link("/proc/1/ns/net").ok();
    match (self_ns, init_ns) {
        (Some(s), Some(i)) => s != i,
        _ => false,
    }
}

/// Read network configuration from inside a network namespace.
fn read_netns_config(netns_path: Option<&PathBuf>) -> Option<CniNetworkConfig> {
    let link_output = Command::new("ip")
        .args(["-o", "link", "show"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let link_text = String::from_utf8_lossy(&link_output.stdout);

    // Find the first non-loopback interface (typically "eth0")
    let mut iface_name = None;
    for line in link_text.lines() {
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() >= 2 {
            let name = parts[1]
                .trim_end_matches(':')
                .split('@')
                .next()
                .unwrap_or("");
            if !name.is_empty() && name != "lo" {
                iface_name = Some(name.to_string());
                break;
            }
        }
    }
    let iface_name = iface_name?;

    // Read MTU from ip link output
    let mtu: u16 = link_text
        .lines()
        .find(|l| l.contains(&iface_name))
        .and_then(|l| {
            let mtu_pos = l.find("mtu ")?;
            let after_mtu = &l[mtu_pos + 4..];
            let end = after_mtu.find(' ').unwrap_or(after_mtu.len());
            after_mtu[..end].parse().ok()
        })
        .unwrap_or(1500);

    // Read IP address and prefix
    let ip_output = Command::new("ip")
        .args(["-4", "-o", "addr", "show", &iface_name])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let ip_line = String::from_utf8_lossy(&ip_output.stdout);
    let (ip_addr, prefix_len) = parse_ip_addr_line(&ip_line)?;

    // Read default gateway
    let route_output = Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let route_line = String::from_utf8_lossy(&route_output.stdout);
    let gateway = parse_default_gateway(&route_line)?;

    Some(CniNetworkConfig {
        netns_path: netns_path.cloned(),
        ip_addr,
        prefix_len,
        gateway,
        mtu,
    })
}

/// Parse IP address and prefix length from `ip -4 -o addr show` output.
fn parse_ip_addr_line(line: &str) -> Option<(std::net::Ipv4Addr, u8)> {
    let inet_pos = line.find("inet ")?;
    let after_inet = &line[inet_pos + 5..];
    let cidr_end = after_inet.find(' ').unwrap_or(after_inet.len());
    let cidr = &after_inet[..cidr_end];
    let mut parts = cidr.split('/');
    let ip: std::net::Ipv4Addr = parts.next()?.parse().ok()?;
    let prefix: u8 = parts.next()?.parse().ok()?;
    Some((ip, prefix))
}

/// Parse default gateway from `ip -4 route show default` output.
fn parse_default_gateway(line: &str) -> Option<std::net::Ipv4Addr> {
    let via_pos = line.find("via ")?;
    let after_via = &line[via_pos + 4..];
    let gw_end = after_via.find(' ').unwrap_or(after_via.len());
    let gw = &after_via[..gw_end];
    gw.parse().ok()
}

/// Set up a TUN device inside the container's CNI network namespace.
///
/// Creates a TUN device, configures IP forwarding and NAT so that smoltcp
/// traffic is routed through the container's veth to the host network.
fn setup_cni_tun(cni: &CniNetworkConfig) -> Result<String> {
    let tun_name = "litebox0";
    let tun_ip = "10.0.0.1";
    let tun_subnet = "10.0.0.0/24";

    // Enter the container's network namespace if a path is provided
    if let Some(netns_path) = &cni.netns_path {
        use std::os::unix::io::AsRawFd;
        let netns_file = std::fs::File::open(netns_path)
            .with_context(|| format!("failed to open netns {}", netns_path.display()))?;

        let clone_newnet: libc::c_int = 0x40000000;
        // SAFETY: setns is a standard Linux syscall with a valid fd.
        let ret = unsafe { libc::setns(netns_file.as_raw_fd(), clone_newnet) };
        if ret != 0 {
            anyhow::bail!("setns failed: {}", std::io::Error::last_os_error());
        }
    }

    // Create TUN device inside the netns
    let status = Command::new("ip")
        .args(["tuntap", "add", "dev", tun_name, "mode", "tun"])
        .status()
        .context("failed to create TUN device")?;
    if !status.success() {
        anyhow::bail!("ip tuntap add failed with {status}");
    }

    // Configure TUN device
    let _ = Command::new("ip")
        .args(["addr", "add", &format!("{tun_ip}/24"), "dev", tun_name])
        .status();
    let _ = Command::new("ip")
        .args(["link", "set", tun_name, "up"])
        .status();

    // Enable IP forwarding inside the netns
    let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", "1");

    // Set up NAT: masquerade TUN subnet traffic going out via the real interface
    let _ = Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            tun_subnet,
            "!",
            "-o",
            tun_name,
            "-j",
            "MASQUERADE",
        ])
        .status();

    Ok(tun_name.to_string())
}

// ---------------------------------------------------------------------------
// Broker spawn helpers
// ---------------------------------------------------------------------------

/// Locate the `litebox_broker` binary.
///
/// Search order:
/// 1. Same directory as the current executable
/// 2. `$PATH`
fn find_broker_exe() -> Result<PathBuf> {
    // 1. Adjacent to self
    if let Ok(self_exe) = std::env::current_exe() {
        if let Some(dir) = self_exe.parent() {
            let candidate = dir.join("litebox_broker");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    // 2. Search $PATH
    if let Ok(output) = Command::new("which")
        .arg("litebox_broker")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
    {
        if output.status.success() {
            let path_str = String::from_utf8_lossy(&output.stdout);
            let path = PathBuf::from(path_str.trim());
            if path.is_file() {
                return Ok(path);
            }
        }
    }

    anyhow::bail!(
        "litebox_broker binary not found. \
         Place it next to the OCI runner or ensure it is in $PATH."
    )
}

/// Wait for a Unix socket to appear on the filesystem, polling up to `timeout`.
fn wait_for_socket(path: &Path, timeout: std::time::Duration) -> Result<()> {
    let start = std::time::Instant::now();
    let poll_interval = std::time::Duration::from_millis(50);

    while start.elapsed() < timeout {
        if path.exists() {
            return Ok(());
        }
        std::thread::sleep(poll_interval);
    }

    anyhow::bail!(
        "broker socket {} did not appear within {:.1}s",
        path.display(),
        timeout.as_secs_f64()
    )
}

/// Spawn a `litebox_broker` child process.
///
/// Returns the child process handle. The broker will listen on `socket_path`
/// for both LB9P (9P filesystem) and LBNP (network proxy) connections.
fn spawn_broker(socket_path: &Path, rootfs: &Path) -> Result<Child> {
    let broker_exe = find_broker_exe()?;

    tracing::info!(
        broker = %broker_exe.display(),
        socket = %socket_path.display(),
        rootfs = %rootfs.display(),
        "spawning litebox_broker"
    );

    let child = Command::new(&broker_exe)
        .arg("--network-proxy-listen")
        .arg(socket_path)
        .arg("--root-dir")
        .arg(rootfs)
        .arg("--rewrite-syscalls")
        .arg("--read-only")
        .arg("--writable-path")
        .arg("/tmp")
        .arg("--writable-path")
        .arg("/var")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn litebox_broker at {}", broker_exe.display()))?;

    Ok(child)
}

// ---------------------------------------------------------------------------
// CliArgs construction
// ---------------------------------------------------------------------------

/// Build `CliArgs` from the OCI spec and runtime options.
fn build_cli_args(
    spec: &Spec,
    override_args: Option<&[String]>,
    extra_env: &[String],
    broker_socket: &str,
    tun_device: Option<String>,
) -> Result<CliArgs> {
    let process = spec
        .process()
        .as_ref()
        .context("OCI spec missing 'process' section")?;

    // Program and arguments
    let program_and_arguments = if let Some(args) = override_args {
        args.to_vec()
    } else {
        let spec_args = process
            .args()
            .as_ref()
            .context("OCI spec missing 'process.args'")?;
        if spec_args.is_empty() {
            anyhow::bail!("process.args cannot be empty");
        }
        spec_args.clone()
    };

    // Environment variables: from spec + extra
    let mut environment_variables: Vec<String> =
        process.env().as_ref().map_or_else(Vec::new, |e| e.clone());
    environment_variables.extend_from_slice(extra_env);

    // Working directory
    let working_directory = process
        .cwd()
        .to_str()
        .map(|s| {
            if s.is_empty() {
                None
            } else {
                Some(s.to_string())
            }
        })
        .unwrap_or(None);

    // Networking: TUN device vs broker-based networking
    let (tun_device_name, network_broker) = if let Some(tun) = tun_device {
        // TUN available: smoltcp reads directly from the TUN fd
        (Some(tun), None)
    } else {
        // No TUN: use broker socket for IPC-based networking
        (None, Some(broker_socket.to_string()))
    };

    Ok(CliArgs {
        program_and_arguments,
        environment_variables,
        forward_environment_variables: false,
        unstable: true,
        insert_files: vec![],
        initial_files: None,
        rewrite_syscalls: false,
        interception_backend: InterceptionBackend::Rewriter,
        tun_device_name,
        network_broker,
        program_from_tar: false,
        nine_p_broker: Some(broker_socket.to_string()),
        working_directory,
        // Internal worker flags — all default/inactive
        worker_exec: false,
        worker_exec_fd: None,
        worker_result_fd: None,
        worker_interp_fd: None,
        worker_interp_path: None,
        guest_pid: None,
        guest_ppid: None,
        guest_uid: None,
        guest_euid: None,
        guest_gid: None,
        guest_egid: None,
        fork_restore: false,
        fork_restore_fd: None,
        fork_restore_ack_fd: None,
        pipe_bridge: vec![],
        mux_fd: None,
        mux_stream: vec![],
        local_pipe: vec![],
    })
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/// Run an OCI container.
///
/// Spawns a `litebox_broker` for rootfs access, detects CNI networking from
/// the OCI spec, constructs `CliArgs`, and delegates to
/// `litebox_runner_linux_userland::run()`.
///
/// # Errors
/// Returns an error if the bundle is invalid, the broker cannot be spawned,
/// or execution fails.
pub fn run_container(
    bundle_path: &Path,
    override_args: Option<&[String]>,
    extra_env: &[String],
    network: &NetworkConfig,
) -> Result<i32> {
    // 1. Parse config.json from bundle
    let spec_path = bundle_path.join("config.json");
    let spec: Spec = {
        let file = std::fs::File::open(&spec_path).with_context(|| {
            format!(
                "failed to open {}. Ensure the bundle directory contains a valid config.json",
                spec_path.display()
            )
        })?;
        serde_json::from_reader(file).with_context(|| {
            "failed to parse config.json. Ensure it is valid OCI runtime spec JSON."
        })?
    };

    // 2. Determine rootfs path
    let rootfs_path = bundle_path.join(
        spec.root()
            .as_ref()
            .map_or(Path::new("rootfs"), |r| r.path().as_path()),
    );
    if !rootfs_path.exists() {
        anyhow::bail!("rootfs not found at {}", rootfs_path.display());
    }

    // 3. Detect CNI network from OCI spec (if no explicit tun_device)
    let tun_device = if network.tun_device.is_some() {
        network.tun_device.clone()
    } else {
        match detect_cni_network(&spec) {
            Some(cni) => match setup_cni_tun(&cni) {
                Ok(tun_name) => {
                    tracing::info!(tun = %tun_name, "CNI TUN device created");
                    Some(tun_name)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "CNI TUN setup failed, falling back to broker networking");
                    None
                }
            },
            None => None,
        }
    };

    // 4. Generate broker socket path
    let broker_socket_path = PathBuf::from(format!(
        "/tmp/litebox-oci-broker-{}.sock",
        std::process::id()
    ));
    let broker_socket_str = broker_socket_path
        .to_str()
        .context("broker socket path is not valid UTF-8")?
        .to_string();

    // 5. Spawn broker
    let mut broker_child = spawn_broker(&broker_socket_path, &rootfs_path)?;

    // 6. Wait for broker socket to appear (up to 5 seconds)
    if let Err(e) = wait_for_socket(&broker_socket_path, std::time::Duration::from_secs(5)) {
        // Clean up broker process on timeout
        let _ = broker_child.kill();
        let _ = broker_child.wait();
        let _ = std::fs::remove_file(&broker_socket_path);
        return Err(e).context("broker failed to start");
    }

    // 7. Build CliArgs
    let cli_args = match build_cli_args(
        &spec,
        override_args,
        extra_env,
        &broker_socket_str,
        tun_device,
    ) {
        Ok(args) => args,
        Err(e) => {
            let _ = broker_child.kill();
            let _ = broker_child.wait();
            let _ = std::fs::remove_file(&broker_socket_path);
            return Err(e);
        }
    };

    tracing::info!(
        program = ?cli_args.program_and_arguments,
        nine_p = ?cli_args.nine_p_broker,
        network_broker = ?cli_args.network_broker,
        tun = ?cli_args.tun_device_name,
        cwd = ?cli_args.working_directory,
        "launching sandboxed process"
    );

    // 8. Call litebox_runner_linux_userland::run() — diverges on success
    let result = litebox_runner_linux_userland::run(cli_args);

    // 9. On error (or if run returns), clean up broker process and socket
    let _ = broker_child.kill();
    let _ = broker_child.wait();
    let _ = std::fs::remove_file(&broker_socket_path);

    match result {
        Ok(()) => Ok(0),
        Err(e) => Err(e).context("litebox runner failed"),
    }
}
