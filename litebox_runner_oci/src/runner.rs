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

use anyhow::{Context, Result, bail};
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
    /// Name of the CNI network interface (e.g., "eth0").
    pub iface_name: String,
    /// Interface MAC address.
    pub mac: [u8; 6],
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

    // Read MTU and MAC from ip link output
    let iface_line = link_text.lines().find(|l| l.contains(&iface_name))?;

    let mtu: u16 = iface_line
        .find("mtu ")
        .and_then(|pos| {
            let after_mtu = &iface_line[pos + 4..];
            let end = after_mtu.find(' ').unwrap_or(after_mtu.len());
            after_mtu[..end].parse().ok()
        })
        .unwrap_or(1500);

    let mac = parse_link_mac(iface_line)?;

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
        iface_name,
        mac,
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

/// Parse MAC address from `ip -o link show` output line.
///
/// The line contains `link/ether xx:xx:xx:xx:xx:xx` — extract the MAC.
fn parse_link_mac(line: &str) -> Option<[u8; 6]> {
    let marker = "link/ether ";
    let pos = line.find(marker)?;
    let after = &line[pos + marker.len()..];
    let end = after.find(' ').unwrap_or(after.len());
    let mac_str = &after[..end];
    let bytes: Vec<u8> = mac_str
        .split(':')
        .map(|b| u8::from_str_radix(b, 16).ok())
        .collect::<Option<Vec<u8>>>()?;
    if bytes.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&bytes);
    Some(mac)
}

/// Read the MAC address of a network interface from sysfs.
#[cfg(test)]
fn read_interface_mac(iface: &str) -> Result<[u8; 6]> {
    let path = format!("/sys/class/net/{iface}/address");
    let mac_str = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read MAC from {path}"))?;
    let mac_str = mac_str.trim();
    let bytes: Vec<u8> = mac_str
        .split(':')
        .map(|b| u8::from_str_radix(b, 16))
        .collect::<Result<Vec<u8>, _>>()
        .with_context(|| format!("invalid MAC address: {mac_str}"))?;
    if bytes.len() != 6 {
        anyhow::bail!(
            "MAC address has {} bytes, expected 6: {mac_str}",
            bytes.len()
        );
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&bytes);
    Ok(mac)
}

/// Open an AF_PACKET raw socket on the CNI veth interface.
///
/// Returns the socket fd and a [`litebox::net::NetworkConfig`] for smoltcp
/// (Ethernet mode with the veth's MAC, IP, prefix, and gateway).
///
/// If the CNI config has a `netns_path`, this function enters that network
/// namespace via `setns` **and stays there** — the AF_PACKET socket must
/// remain in the CNI netns, and the runner process should execute inside it.
fn setup_cni_af_packet(
    cni: &CniNetworkConfig,
) -> Result<(std::os::fd::OwnedFd, litebox::net::NetworkConfig)> {
    use std::os::fd::{AsRawFd, FromRawFd};

    // Enter the CNI network namespace if we have an explicit path.
    // We intentionally do NOT restore the original netns — the runner
    // process needs to stay in this namespace for the AF_PACKET socket
    // (and any other network operations) to work.
    if let Some(netns_path) = &cni.netns_path {
        let netns_file = std::fs::File::open(netns_path)
            .with_context(|| format!("failed to open netns {}", netns_path.display()))?;
        let ret = unsafe { libc::setns(netns_file.as_raw_fd(), libc::CLONE_NEWNET) };
        if ret != 0 {
            anyhow::bail!(
                "setns({}) failed: {}",
                netns_path.display(),
                std::io::Error::last_os_error()
            );
        }
        tracing::debug!(netns = %netns_path.display(), "entered CNI network namespace");
    }

    // Use the MAC address already parsed during CNI detection (from `ip link`
    // output inside the netns). Reading from sysfs doesn't work after setns
    // because /sys is bound to the mount namespace, not the network namespace.
    let mac = cni.mac;

    // Open AF_PACKET raw socket
    #[allow(clippy::cast_possible_truncation)] // ETH_P_ALL (0x0003) fits in u16
    let protocol = i32::from((libc::ETH_P_ALL as u16).to_be());
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, protocol) };
    if fd < 0 {
        anyhow::bail!(
            "socket(AF_PACKET) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };

    // Bind to the specific interface
    let iface_cstr = std::ffi::CString::new(cni.iface_name.as_str())
        .context("interface name contains null byte")?;
    let ifindex = unsafe { libc::if_nametoindex(iface_cstr.as_ptr()) };
    if ifindex == 0 {
        anyhow::bail!(
            "if_nametoindex({}) failed: {}",
            cni.iface_name,
            std::io::Error::last_os_error()
        );
    }

    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    #[allow(clippy::cast_possible_truncation)]
    {
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    }
    addr.sll_ifindex = ifindex.cast_signed();

    let ret = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&raw const addr).cast::<libc::sockaddr>(),
            #[allow(clippy::cast_possible_truncation)]
            {
                std::mem::size_of::<libc::sockaddr_ll>() as u32
            },
        )
    };
    if ret < 0 {
        anyhow::bail!(
            "bind(AF_PACKET, ifindex={ifindex}) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    // Set non-blocking for the network worker poll loop
    unsafe {
        let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL);
        libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    let net_config =
        litebox::net::NetworkConfig::ethernet(mac, cni.ip_addr, cni.prefix_len, cni.gateway);

    Ok((fd, net_config))
}

// ---------------------------------------------------------------------------
// Broker spawn helpers
// ---------------------------------------------------------------------------

/// Locate the `litebox_broker` binary.
///
/// Search order:
/// 1. Same directory as the current executable
/// 2. `$PATH`
///
/// Tries both `litebox_broker` (cargo default) and `litebox-broker` (installed)
/// name variants.
fn find_broker_exe() -> Result<PathBuf> {
    let names = ["litebox_broker", "litebox-broker"];

    // 1. Adjacent to self
    if let Ok(self_exe) = std::env::current_exe()
        && let Some(dir) = self_exe.parent()
    {
        for name in &names {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    // 2. Search $PATH
    for name in &names {
        if let Ok(output) = Command::new("which")
            .arg(name)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            && output.status.success()
        {
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
fn spawn_broker(
    socket_path: &Path,
    rootfs: &Path,
    bind_mounts: &[(String, String)],
    writable_paths: &[String],
    read_only: bool,
) -> Result<Child> {
    let broker_exe = find_broker_exe()?;

    tracing::info!(
        broker = %broker_exe.display(),
        socket = %socket_path.display(),
        rootfs = %rootfs.display(),
        bind_mounts = ?bind_mounts,
        "spawning litebox_broker"
    );

    let mut cmd = Command::new(&broker_exe);
    cmd.arg("--network-proxy-listen")
        .arg(socket_path)
        .arg("--root-dir")
        .arg(rootfs)
        .arg("--rewrite-syscalls");

    if read_only {
        cmd.arg("--read-only");
    }

    for writable_path in writable_paths {
        cmd.arg("--writable-path");
        cmd.arg(writable_path);
    }

    for (guest_path, host_path) in bind_mounts {
        cmd.arg("--bind");
        cmd.arg(format!("{guest_path}:{host_path}"));
    }

    let child = cmd
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn litebox_broker at {}", broker_exe.display()))?;

    Ok(child)
}

// ---------------------------------------------------------------------------
// Program path resolution
// ---------------------------------------------------------------------------

/// Resolve a bare program name against the rootfs using `$PATH`.
///
/// Searches each directory in `$PATH` (from the OCI environment) under the
/// rootfs for an executable file matching `program`. Returns the absolute
/// guest path (e.g., `/bin/echo`) or `None` if not found.
fn resolve_program_in_rootfs(
    rootfs: &Path,
    program: &str,
    environment: &[String],
) -> Option<String> {
    let path_env = environment.iter().find(|e| e.starts_with("PATH=")).map_or(
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        |e| &e[5..],
    );

    for dir in path_env.split(':') {
        let dir = dir.strip_prefix('/').unwrap_or(dir);
        let host_path = rootfs.join(dir).join(program);
        if host_path.is_file() {
            // Return the guest-absolute path
            let guest_path = format!(
                "{}/{}",
                if dir.is_empty() {
                    String::new()
                } else {
                    format!("/{dir}")
                },
                program
            );
            return Some(guest_path);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// CliArgs construction
// ---------------------------------------------------------------------------

/// Build `CliArgs` from the OCI spec and runtime options.
#[allow(clippy::too_many_arguments)]
fn build_cli_args(
    spec: &Spec,
    override_args: Option<&[String]>,
    extra_env: &[String],
    broker_socket: &str,
    tun_device: Option<String>,
    af_packet_fd: Option<std::os::fd::OwnedFd>,
    network_config: Option<litebox::net::NetworkConfig>,
    override_cwd: Option<&str>,
    override_user: Option<&(u32, u32)>,
    state_dir: Option<std::path::PathBuf>,
    restore_image: Option<std::path::PathBuf>,
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
        process.env().as_ref().map_or_else(Vec::new, Clone::clone);
    environment_variables.extend_from_slice(extra_env);

    // Working directory
    let working_directory = if let Some(cwd) = override_cwd {
        if cwd.is_empty() {
            None
        } else {
            Some(cwd.to_string())
        }
    } else {
        process.cwd().to_str().and_then(|s| {
            if s.is_empty() {
                None
            } else {
                Some(s.to_string())
            }
        })
    };

    // Networking: AF_PACKET fd vs TUN device vs broker-based networking
    let (tun_device_name, network_broker) = if af_packet_fd.is_some() {
        // AF_PACKET provides networking — no TUN or broker needed for network
        (None, None)
    } else if let Some(tun) = tun_device {
        // TUN available: smoltcp reads directly from the TUN fd
        (Some(tun), None)
    } else {
        // No TUN: use broker socket for IPC-based networking
        (None, Some(broker_socket.to_string()))
    };

    // Detect proc mount in OCI spec
    let has_proc_mount = spec
        .mounts()
        .as_ref()
        .is_some_and(|mounts| mounts.iter().any(|m| m.typ().as_deref() == Some("proc")));

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
        proc_mount: has_proc_mount,
        af_packet_fd,
        network_config,
        state_dir,
        restore_image,
        // Internal worker flags — all default/inactive
        worker_exec: false,
        worker_exec_fd: None,
        worker_result_fd: None,
        worker_interp_fd: None,
        worker_interp_path: None,
        guest_pid: None,
        guest_ppid: None,
        guest_uid: Some(override_user.map_or_else(|| process.user().uid(), |u| u.0)),
        guest_euid: Some(override_user.map_or_else(|| process.user().uid(), |u| u.0)),
        guest_gid: Some(override_user.map_or_else(|| process.user().gid(), |u| u.1)),
        guest_egid: Some(override_user.map_or_else(|| process.user().gid(), |u| u.1)),
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
#[allow(clippy::too_many_arguments)]
pub fn run_container(
    bundle_path: &Path,
    override_args: Option<&[String]>,
    extra_env: &[String],
    network: &NetworkConfig,
    override_cwd: Option<&str>,
    override_user: Option<&(u32, u32)>,
    state_dir: Option<std::path::PathBuf>,
    restore_image: Option<std::path::PathBuf>,
    extra_bind_mounts: &[(String, String)],
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
        serde_json::from_reader(file).with_context(
            || "failed to parse config.json. Ensure it is valid OCI runtime spec JSON.",
        )?
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

    // 3. Detect CNI network from OCI spec — use AF_PACKET if available
    let (af_packet_fd, af_packet_net_config) = if network.tun_device.is_some() {
        (None, None) // explicit TUN overrides CNI detection
    } else {
        match detect_cni_network(&spec) {
            Some(cni) => match setup_cni_af_packet(&cni) {
                Ok((fd, config)) => {
                    tracing::info!(
                        iface = %cni.iface_name,
                        ip = %cni.ip_addr,
                        "CNI AF_PACKET socket opened"
                    );
                    (Some(fd), Some(config))
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "CNI AF_PACKET setup failed, falling back to broker networking"
                    );
                    (None, None)
                }
            },
            None => (None, None),
        }
    };
    // If AF_PACKET is active, don't use TUN
    let tun_device: Option<String> = if af_packet_fd.is_some() {
        None
    } else {
        network.tun_device.clone()
    };

    // 4. Extract bind mounts from OCI spec
    let mut bind_mounts: Vec<(String, String)> = spec
        .mounts()
        .as_ref()
        .map(|mounts| {
            mounts
                .iter()
                .filter(|m| {
                    // Include bind mounts and mounts with a real source path
                    let typ = m.typ().as_deref().unwrap_or("bind");
                    typ == "bind" || typ == "none"
                })
                .filter_map(|m| {
                    let source = m.source().as_ref()?.to_str()?;
                    let dest = m.destination().to_str()?;
                    // Strip leading / from dest for guest-relative path
                    let guest_path = dest.strip_prefix('/').unwrap_or(dest);
                    Some((guest_path.to_string(), source.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();

    // 4b. Merge extra bind mounts from CLI -v/--volume flags.
    // extra_bind_mounts are (host_path, guest_path) pairs; convert to
    // (guest_path_no_slash, host_path) to match the broker's --bind format.
    for (host_path, guest_path) in extra_bind_mounts {
        let guest_rel = guest_path.strip_prefix('/').unwrap_or(guest_path);
        bind_mounts.push((guest_rel.to_string(), host_path.clone()));
    }

    // 5. Extract writable paths from tmpfs mounts in OCI spec
    let writable_paths: Vec<String> = spec
        .mounts()
        .as_ref()
        .map(|mounts| {
            mounts
                .iter()
                .filter(|m| m.typ().as_deref() == Some("tmpfs"))
                .filter_map(|m| m.destination().to_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // Honour the OCI spec's root.readonly field.  When false (e.g. bundles
    // produced by `--image`), the broker serves the rootfs fully writable
    // and no writable-path overrides are needed.
    let root_readonly = spec
        .root()
        .as_ref()
        .is_some_and(|r| r.readonly().unwrap_or(false));

    let writable_paths = if root_readonly {
        if writable_paths.is_empty() {
            vec!["/tmp".to_string(), "/var".to_string()]
        } else {
            writable_paths
        }
    } else {
        vec![] // entire rootfs is writable
    };

    // 6. Generate broker socket path
    let broker_socket_path = PathBuf::from(format!(
        "/tmp/litebox-oci-broker-{}.sock",
        std::process::id()
    ));
    let broker_socket_str = broker_socket_path
        .to_str()
        .context("broker socket path is not valid UTF-8")?
        .to_string();

    // 7. Spawn broker
    let mut broker_child = spawn_broker(
        &broker_socket_path,
        &rootfs_path,
        &bind_mounts,
        &writable_paths,
        root_readonly,
    )?;

    // 8. Wait for broker socket to appear (up to 5 seconds)
    if let Err(e) = wait_for_socket(&broker_socket_path, std::time::Duration::from_secs(5)) {
        // Clean up broker process on timeout
        let _ = broker_child.kill();
        let _ = broker_child.wait();
        let _ = std::fs::remove_file(&broker_socket_path);
        return Err(e).context("broker failed to start");
    }

    // 9. Build CliArgs
    let mut cli_args = match build_cli_args(
        &spec,
        override_args,
        extra_env,
        &broker_socket_str,
        tun_device,
        af_packet_fd,
        af_packet_net_config,
        override_cwd,
        override_user,
        state_dir,
        restore_image,
    ) {
        Ok(args) => args,
        Err(e) => {
            let _ = broker_child.kill();
            let _ = broker_child.wait();
            let _ = std::fs::remove_file(&broker_socket_path);
            return Err(e);
        }
    };

    // 9b. Resolve non-absolute program path against rootfs via $PATH.
    // OCI specs often pass bare command names (e.g., "echo"), which must
    // be resolved to an absolute path (e.g., "/bin/echo") in the container
    // rootfs for the 9P-backed filesystem to find the binary.
    if !cli_args.program_and_arguments.is_empty()
        && !cli_args.program_and_arguments[0].starts_with('/')
        && let Some(resolved) = resolve_program_in_rootfs(
            &rootfs_path,
            &cli_args.program_and_arguments[0],
            &cli_args.environment_variables,
        )
    {
        tracing::debug!(
            original = %cli_args.program_and_arguments[0],
            resolved = %resolved,
            "resolved program path via PATH"
        );
        cli_args.program_and_arguments[0] = resolved;
    }

    tracing::info!(
        program = ?cli_args.program_and_arguments,
        nine_p = ?cli_args.nine_p_broker,
        network_broker = ?cli_args.network_broker,
        tun = ?cli_args.tun_device_name,
        cwd = ?cli_args.working_directory,
        "launching sandboxed process"
    );

    // 9c. Apply OCI rlimits to the host process before starting the sandbox.
    // This bounds the litebox runner process itself (fd limits, etc.).
    if let Some(process) = spec.process().as_ref()
        && let Some(rlimits) = process.rlimits()
    {
        apply_rlimits(rlimits);
    }

    // 10. Call litebox_runner_linux_userland::run() — returns exit code on success
    let result = litebox_runner_linux_userland::run(cli_args);

    // 11. On error (or if run returns), clean up broker process and socket
    let _ = broker_child.kill();
    let _ = broker_child.wait();
    // Capture broker stderr for diagnostic info on failure
    if result.is_err()
        && let Some(mut stderr) = broker_child.stderr.take()
    {
        use std::io::Read;
        let mut buf = String::new();
        let _ = stderr.read_to_string(&mut buf);
        if !buf.is_empty() {
            tracing::error!(broker_stderr = %buf, "broker stderr output");
        }
    }
    let _ = std::fs::remove_file(&broker_socket_path);

    match result {
        Ok(exit_code) => Ok(exit_code),
        Err(e) => Err(e).context("litebox runner failed"),
    }
}

// ---------------------------------------------------------------------------
// Process spec parsing (for `exec --process <file>`)
// ---------------------------------------------------------------------------

/// Parse an OCI process.json file into (args, env, cwd, user).
///
/// The file format matches the `process` section of the OCI runtime spec.
/// Returns:
/// - `args`: the command and its arguments
/// - `env`: environment variables as `KEY=VALUE` strings
/// - `cwd`: working directory (None if empty/unset)
/// - `user`: (uid, gid) tuple if present
#[allow(clippy::type_complexity)]
pub fn parse_process_spec(
    path: &Path,
) -> Result<(Vec<String>, Vec<String>, Option<String>, Option<(u32, u32)>)> {
    use oci_spec::runtime::Process;

    let file = std::fs::File::open(path)
        .with_context(|| format!("failed to open process spec: {}", path.display()))?;
    let process: Process = serde_json::from_reader(file)
        .with_context(|| format!("failed to parse process spec: {}", path.display()))?;

    let args = process
        .args()
        .as_ref()
        .context("process spec missing 'args'")?
        .clone();

    let env = process.env().as_ref().map_or_else(Vec::new, Clone::clone);

    let cwd = process.cwd().to_str().and_then(|s| {
        if s.is_empty() {
            None
        } else {
            Some(s.to_string())
        }
    });

    let user = {
        let u = process.user();
        let uid = u.uid();
        let gid = u.gid();
        // Only return Some if at least one is non-zero, or if there's
        // explicit user info (uid=0, gid=0 is valid for root)
        Some((uid, gid))
    };

    Ok((args, env, cwd, user))
}

// ---------------------------------------------------------------------------
// Exec container (fork/detach/PTY + run)
// ---------------------------------------------------------------------------

/// Execute a command in an existing container's rootfs.
///
/// Handles forking (for `--detach`), PTY setup (for `--console-socket`),
/// PID file writing, and then delegates to [`run_container`].
#[allow(clippy::too_many_arguments)]
pub fn exec_container(
    bundle_path: &Path,
    override_args: Option<&[String]>,
    extra_env: &[String],
    network: &NetworkConfig,
    console_socket: Option<&Path>,
    pid_file: Option<&Path>,
    detach: bool,
    override_cwd: Option<&str>,
    override_user: Option<&(u32, u32)>,
) -> Result<i32> {
    if detach {
        // Fork: parent writes child PID and exits, child continues
        // SAFETY: fork() is a standard POSIX syscall. We immediately diverge
        // parent/child paths and avoid async-signal-unsafe calls before exec.
        let pid = unsafe { libc::fork() };
        match pid.cmp(&0) {
            std::cmp::Ordering::Less => {
                anyhow::bail!("fork() failed: {}", std::io::Error::last_os_error());
            }
            std::cmp::Ordering::Greater => {
                // Parent: write child PID and return success
                if let Some(pf) = pid_file {
                    std::fs::write(pf, format!("{pid}"))
                        .with_context(|| format!("failed to write pid-file: {}", pf.display()))?;
                }
                return Ok(0);
            }
            std::cmp::Ordering::Equal => {
                // Child: create new session and continue
                // SAFETY: setsid is a standard POSIX syscall, safe after fork.
                unsafe {
                    libc::setsid();
                }
            }
        }
    } else if let Some(pf) = pid_file {
        // Non-detach but pid_file requested: write own PID
        let pid = std::process::id();
        std::fs::write(pf, format!("{pid}"))
            .with_context(|| format!("failed to write pid-file: {}", pf.display()))?;
    }

    // Set up PTY if console-socket is provided
    if let Some(cs_path) = console_socket {
        use std::os::fd::AsRawFd;
        let slave_fd = crate::lifecycle::setup_console_socket(cs_path)?;
        let raw = slave_fd.as_raw_fd();
        // SAFETY: dup2, setsid, ioctl are standard POSIX/Linux syscalls.
        // The slave_fd is valid (just returned from setup_console_socket).
        unsafe {
            libc::setsid();
            libc::dup2(raw, 0); // stdin
            libc::dup2(raw, 1); // stdout
            libc::dup2(raw, 2); // stderr
            libc::ioctl(raw, libc::TIOCSCTTY, 0);
        }
        drop(slave_fd);
    }

    run_container(
        bundle_path,
        override_args,
        extra_env,
        network,
        override_cwd,
        override_user,
        None, // exec doesn't support checkpoint
        None, // exec doesn't support restore
        &[], // exec doesn't support volume mounts (yet)
    )
}

// ---------------------------------------------------------------------------
// OCI rlimits
// ---------------------------------------------------------------------------

/// Apply OCI rlimits to the current process via `setrlimit(2)`.
///
/// Each rlimit is applied best-effort: failures are logged but do not abort
/// container startup (some limits like `RLIMIT_NPROC` may fail in rootless
/// mode or when the requested value exceeds the hard limit).
fn apply_rlimits(rlimits: &[oci_spec::runtime::PosixRlimit]) {
    use oci_spec::runtime::PosixRlimitType;

    for rl in rlimits {
        let resource = match rl.typ() {
            PosixRlimitType::RlimitCpu => libc::RLIMIT_CPU,
            PosixRlimitType::RlimitFsize => libc::RLIMIT_FSIZE,
            PosixRlimitType::RlimitData => libc::RLIMIT_DATA,
            PosixRlimitType::RlimitStack => libc::RLIMIT_STACK,
            PosixRlimitType::RlimitCore => libc::RLIMIT_CORE,
            PosixRlimitType::RlimitRss => libc::RLIMIT_RSS,
            PosixRlimitType::RlimitNproc => libc::RLIMIT_NPROC,
            PosixRlimitType::RlimitNofile => libc::RLIMIT_NOFILE,
            PosixRlimitType::RlimitMemlock => libc::RLIMIT_MEMLOCK,
            PosixRlimitType::RlimitAs => libc::RLIMIT_AS,
            PosixRlimitType::RlimitLocks => libc::RLIMIT_LOCKS,
            PosixRlimitType::RlimitSigpending => libc::RLIMIT_SIGPENDING,
            PosixRlimitType::RlimitMsgqueue => libc::RLIMIT_MSGQUEUE,
            PosixRlimitType::RlimitNice => libc::RLIMIT_NICE,
            PosixRlimitType::RlimitRtprio => libc::RLIMIT_RTPRIO,
            PosixRlimitType::RlimitRttime => libc::RLIMIT_RTTIME,
        };

        let lim = libc::rlimit {
            rlim_cur: rl.soft(),
            rlim_max: rl.hard(),
        };

        // SAFETY: setrlimit is a standard POSIX call; we provide a valid
        // resource constant and a properly initialised rlimit struct.
        let rc = unsafe { libc::setrlimit(resource, &raw const lim) };
        if rc == 0 {
            tracing::debug!(
                typ = ?rl.typ(),
                soft = rl.soft(),
                hard = rl.hard(),
                "applied rlimit"
            );
        } else {
            let err = std::io::Error::last_os_error();
            tracing::warn!(
                typ = ?rl.typ(),
                soft = rl.soft(),
                hard = rl.hard(),
                error = %err,
                "failed to apply rlimit (continuing)"
            );
        }
    }
}

/// Run a single command inside the sandbox with a writable rootfs.
///
/// Used by `litebox-oci build` for executing Dockerfile RUN instructions.
/// The broker serves the rootfs directory with full write access, so guest
/// mutations (package installs, file creation, etc.) land on disk directly.
pub fn run_build_step(
    rootfs: &Path,
    command: &[String],
    env: &[String],
    working_dir: Option<&str>,
) -> Result<i32> {
    // 1. Generate unique broker socket path
    let broker_socket_path = PathBuf::from(format!(
        "/tmp/litebox-oci-build-{}-{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let broker_socket_str = broker_socket_path
        .to_str()
        .context("broker socket path not valid UTF-8")?
        .to_string();

    // 2. Spawn broker with writable rootfs (read_only = false)
    let mut broker_child = spawn_broker(
        &broker_socket_path,
        rootfs,
        &[],   // no bind mounts
        &[],   // no writable_paths needed when not read-only
        false, // read_only = false — entire rootfs writable
    )?;

    // 3. Wait for broker socket
    if let Err(e) = wait_for_socket(&broker_socket_path, std::time::Duration::from_secs(5)) {
        let _ = broker_child.kill();
        let _ = broker_child.wait();
        let _ = std::fs::remove_file(&broker_socket_path);
        return Err(e).context("broker failed to start for build step");
    }

    // 4. Build minimal CliArgs
    let cli_args = CliArgs {
        program_and_arguments: command.to_vec(),
        environment_variables: env.to_vec(),
        forward_environment_variables: false,
        unstable: true,
        insert_files: vec![],
        initial_files: None,
        rewrite_syscalls: false,
        interception_backend: InterceptionBackend::Rewriter,
        tun_device_name: None,
        network_broker: Some(broker_socket_str.clone()),
        program_from_tar: false,
        nine_p_broker: Some(broker_socket_str),
        working_directory: working_dir.map(String::from),
        proc_mount: true,
        af_packet_fd: None,
        network_config: None,
        state_dir: None,
        restore_image: None,
        worker_exec: false,
        worker_exec_fd: None,
        worker_result_fd: None,
        worker_interp_fd: None,
        worker_interp_path: None,
        guest_pid: None,
        guest_ppid: None,
        guest_uid: Some(0),
        guest_euid: Some(0),
        guest_gid: Some(0),
        guest_egid: Some(0),
        fork_restore: false,
        fork_restore_fd: None,
        fork_restore_ack_fd: None,
        pipe_bridge: vec![],
        mux_fd: None,
        mux_stream: vec![],
        local_pipe: vec![],
    };

    // 5. Run the sandbox in a child process.
    //
    // litebox_runner_linux_userland::run() initialises a global platform
    // singleton that cannot be re-initialised.  By forking, each RUN step
    // gets its own address space with a fresh singleton.
    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        let _ = broker_child.kill();
        let _ = broker_child.wait();
        let _ = std::fs::remove_file(&broker_socket_path);
        bail!("fork failed for build step");
    }

    if child_pid == 0 {
        // Child: run the sandbox, then _exit with the guest exit code.
        match litebox_runner_linux_userland::run(cli_args) {
            Ok(code) => std::process::exit(code),
            Err(_) => std::process::exit(125),
        }
    }

    // Parent: wait for child.
    let mut status: libc::c_int = 0;
    let rc = unsafe { libc::waitpid(child_pid, &raw mut status, 0) };

    // 6. Cleanup
    let _ = broker_child.kill();
    let _ = broker_child.wait();
    let _ = std::fs::remove_file(&broker_socket_path);

    if rc < 0 {
        bail!("waitpid failed for build step child");
    }

    if libc::WIFEXITED(status) {
        Ok(libc::WEXITSTATUS(status))
    } else {
        bail!("build step child terminated abnormally (status: {status})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oci_spec::runtime::{ProcessBuilder, SpecBuilder, UserBuilder};

    /// Helper: build a minimal OCI spec with a given UID/GID in process.user.
    fn spec_with_user(uid: u32, gid: u32) -> Spec {
        let user = UserBuilder::default().uid(uid).gid(gid).build().unwrap();
        let process = ProcessBuilder::default()
            .args(vec!["echo".to_string(), "hello".to_string()])
            .user(user)
            .cwd("/".to_string())
            .build()
            .unwrap();
        SpecBuilder::default().process(process).build().unwrap()
    }

    #[test]
    fn build_cli_args_sets_uid_gid_from_spec() {
        let spec = spec_with_user(1000, 1000);
        let args = build_cli_args(
            &spec,
            None,
            &[],
            "/tmp/test.sock",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(args.guest_uid, Some(1000));
        assert_eq!(args.guest_euid, Some(1000));
        assert_eq!(args.guest_gid, Some(1000));
        assert_eq!(args.guest_egid, Some(1000));
    }

    #[test]
    fn build_cli_args_sets_root_uid_gid_when_zero() {
        let spec = spec_with_user(0, 0);
        let args = build_cli_args(
            &spec,
            None,
            &[],
            "/tmp/test.sock",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(args.guest_uid, Some(0));
        assert_eq!(args.guest_euid, Some(0));
        assert_eq!(args.guest_gid, Some(0));
        assert_eq!(args.guest_egid, Some(0));
    }

    #[test]
    fn build_cli_args_detects_proc_mount() {
        use oci_spec::runtime::MountBuilder;
        let user = UserBuilder::default().build().unwrap();
        let proc_mount = MountBuilder::default()
            .typ("proc".to_string())
            .destination("/proc".to_string())
            .build()
            .unwrap();
        let process = ProcessBuilder::default()
            .args(vec!["sh".to_string()])
            .user(user)
            .cwd("/".to_string())
            .build()
            .unwrap();
        let spec = SpecBuilder::default()
            .process(process)
            .mounts(vec![proc_mount])
            .build()
            .unwrap();
        let args = build_cli_args(
            &spec,
            None,
            &[],
            "/tmp/test.sock",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert!(args.proc_mount);
    }

    #[test]
    fn build_cli_args_no_proc_mount_by_default() {
        use oci_spec::runtime::MountBuilder;
        // Build a spec with an explicit non-proc mount only (no default mounts).
        let user = UserBuilder::default().build().unwrap();
        let bind_mount = MountBuilder::default()
            .typ("bind".to_string())
            .destination("/data".to_string())
            .build()
            .unwrap();
        let process = ProcessBuilder::default()
            .args(vec!["sh".to_string()])
            .user(user)
            .cwd("/".to_string())
            .build()
            .unwrap();
        let spec = SpecBuilder::default()
            .process(process)
            .mounts(vec![bind_mount])
            .build()
            .unwrap();
        let args = build_cli_args(
            &spec,
            None,
            &[],
            "/tmp/test.sock",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert!(!args.proc_mount);
    }

    #[test]
    fn read_interface_mac_parses_loopback() {
        // lo always exists and typically has MAC 00:00:00:00:00:00
        let mac = read_interface_mac("lo");
        assert!(mac.is_ok(), "failed to read lo MAC: {:?}", mac.err());
        assert_eq!(mac.unwrap(), [0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn read_interface_mac_fails_for_nonexistent() {
        let mac = read_interface_mac("nonexistent_iface_xyz");
        assert!(mac.is_err());
    }

    #[test]
    fn parse_link_mac_extracts_ethernet_address() {
        let line = "2: tap0: <BROADCAST,UP,LOWER_UP> mtu 65520 qdisc fq_codel state UNKNOWN qlen 1000\\    link/ether 9a:db:90:ad:d2:33 brd ff:ff:ff:ff:ff:ff";
        let mac = parse_link_mac(line);
        assert_eq!(mac, Some([0x9a, 0xdb, 0x90, 0xad, 0xd2, 0x33]));
    }

    #[test]
    fn parse_link_mac_returns_none_for_loopback() {
        let line = "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000\\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00";
        // No link/ether marker in loopback
        let mac = parse_link_mac(line);
        assert_eq!(mac, None);
    }

    #[test]
    fn resolve_program_in_rootfs_finds_binary() {
        // Use /usr as a fake rootfs — /usr/bin/echo should exist on most systems
        let rootfs = Path::new("/usr");
        let env = vec!["PATH=/bin".to_string()];
        let result = resolve_program_in_rootfs(rootfs, "echo", &env);
        // Should find /usr/bin/echo -> returns guest path /bin/echo
        assert_eq!(result, Some("/bin/echo".to_string()));
    }

    #[test]
    fn resolve_program_in_rootfs_returns_none_for_missing() {
        let rootfs = Path::new("/usr");
        let env = vec!["PATH=/bin".to_string()];
        let result = resolve_program_in_rootfs(rootfs, "nonexistent_binary_xyz", &env);
        assert_eq!(result, None);
    }

    #[test]
    fn parse_process_spec_extracts_args_and_env() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("process.json");
        std::fs::write(
            &path,
            r#"{
                "user": {"uid": 1000, "gid": 1000},
                "args": ["echo", "hello"],
                "env": ["PATH=/usr/bin", "HOME=/home/user"],
                "cwd": "/home/user",
                "capabilities": {}
            }"#,
        )
        .unwrap();

        let (args, env, cwd, user) = parse_process_spec(&path).unwrap();
        assert_eq!(args, vec!["echo", "hello"]);
        assert_eq!(env, vec!["PATH=/usr/bin", "HOME=/home/user"]);
        assert_eq!(cwd, Some("/home/user".to_string()));
        assert_eq!(user, Some((1000, 1000)));
    }

    #[test]
    fn parse_process_spec_handles_minimal_spec() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("process.json");
        std::fs::write(
            &path,
            r#"{"args": ["sh"], "user": {"uid": 0, "gid": 0}, "cwd": "/"}"#,
        )
        .unwrap();

        let (args, env, _cwd, user) = parse_process_spec(&path).unwrap();
        assert_eq!(args, vec!["sh"]);
        assert!(env.is_empty());
        assert_eq!(user, Some((0, 0)));
    }

    #[test]
    fn parse_process_spec_fails_on_missing_file() {
        let result = parse_process_spec(Path::new("/nonexistent/process.json"));
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("failed to open process spec"),
            "unexpected error: {err}"
        );
    }
}
