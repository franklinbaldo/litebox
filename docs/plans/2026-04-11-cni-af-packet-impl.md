# CNI AF_PACKET Networking Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the TUN+iptables CNI networking path with direct AF_PACKET on the CNI veth, eliminating TUN device creation, iptables, ip_forward, and the `ip` command for device setup.

**Architecture:** Open an `AF_PACKET` raw socket bound to the CNI veth. Switch smoltcp to Ethernet mode for this transport so it emits complete Ethernet frames. Frames go directly from smoltcp → AF_PACKET write → kernel veth routing → host network. The platform, phy device, Network struct, and shim builder all gain awareness of the medium (IP vs Ethernet). The OCI runner's CNI setup is replaced.

**Tech Stack:** Rust, smoltcp (Ethernet mode), AF_PACKET sockets, litebox platform/net/shim layers

**Design doc:** `docs/plans/2026-04-11-cni-af-packet-design.md`

---

### Task 1: Add `medium()` to `IPInterfaceProvider` trait

**Files:**
- Modify: `litebox/src/platform/mod.rs:377-389` (IPInterfaceProvider trait)
- Modify: `litebox/src/platform/mock.rs` (MockPlatform impl — add medium() override or use default)

**Step 1: Add the `medium()` method with default to the trait**

In `litebox/src/platform/mod.rs`, add to the `IPInterfaceProvider` trait after the existing methods:

```rust
    /// The network medium for packet framing.
    ///
    /// Returns `Medium::Ip` (no link-layer framing) by default. Platforms using
    /// AF_PACKET on an Ethernet interface override this to `Medium::Ethernet`.
    fn medium(&self) -> smoltcp::phy::Medium {
        smoltcp::phy::Medium::Ip
    }
```

**Step 2: Verify compilation**

Run: `cargo check -p litebox`
Expected: Compiles (default method, no impl changes needed).

**Step 3: Commit**

```bash
git add litebox/src/platform/mod.rs
git commit -m "feat(platform): add medium() method to IPInterfaceProvider trait"
```

---

### Task 2: Make `phy::Device` use platform medium instead of hardcoding

**Files:**
- Modify: `litebox/src/net/phy.rs:70-75` (Device::capabilities)

**Step 1: Change capabilities() to query platform**

Replace the hardcoded `Medium::Ip` at line 72:

```rust
    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = smoltcp::phy::DeviceCapabilities::default();
        caps.medium = smoltcp::phy::Medium::Ip;
        caps.max_transmission_unit = DEVICE_MTU;
        caps
    }
```

With:

```rust
    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = smoltcp::phy::DeviceCapabilities::default();
        caps.medium = self.platform.medium();
        caps.max_transmission_unit = DEVICE_MTU;
        caps
    }
```

This requires the `Platform` bound to include `IPInterfaceProvider`. Check the existing bound on `Device<Platform>` — it already requires `platform::IPInterfaceProvider` (line 14 and line 20 show `Platform: platform::IPInterfaceProvider`).

**Step 2: Verify compilation and tests**

Run: `cargo test -p litebox --lib`
Expected: Compiles, existing tests pass (they use MockPlatform which gets `Medium::Ip` default).

**Step 3: Commit**

```bash
git add litebox/src/net/phy.rs
git commit -m "refactor(net): use platform medium() instead of hardcoded Medium::Ip"
```

---

### Task 3: Add `NetworkConfig` and `Network::with_config()`

**Files:**
- Modify: `litebox/src/net/mod.rs:36-132` (constants, Network::new)

**Step 1: Add `NetworkConfig` struct**

Near the top of `mod.rs` (after the existing constants at lines 36-44), add:

```rust
/// Configuration for the guest network stack.
///
/// Controls the smoltcp interface address, gateway, and link-layer mode.
pub struct NetworkConfig {
    /// Hardware address: `HardwareAddress::Ip` for TUN/IPC, `Ethernet(mac)` for AF_PACKET.
    pub hardware_addr: smoltcp::wire::HardwareAddress,
    /// Guest IP address on the virtual interface.
    pub ip_addr: smoltcp::wire::Ipv4Address,
    /// Network prefix length (e.g. 24 for /24).
    pub prefix_len: u8,
    /// Default gateway IP.
    pub gateway: smoltcp::wire::Ipv4Address,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            hardware_addr: smoltcp::wire::HardwareAddress::Ip,
            ip_addr: INTERFACE_IP_ADDR,
            prefix_len: 24,
            gateway: GATEWAY_IP_ADDR,
        }
    }
}
```

Make sure to add `pub use net::NetworkConfig;` in the appropriate re-export if `Network` is publicly accessible. Check how `Network` is imported.

**Step 2: Add `Network::with_config()`**

Add a new constructor alongside the existing `new()`:

```rust
    /// Construct a new `Network` with custom configuration.
    ///
    /// Use this for CNI AF_PACKET networking where the IP address, gateway,
    /// and link-layer mode differ from the defaults.
    pub fn with_config(litebox: &LiteBox<Platform>, config: NetworkConfig) -> Self {
        let mut device = phy::Device::new(litebox.x.platform);
        let smoltcp_config = smoltcp::iface::Config::new(config.hardware_addr);
        let mut interface = smoltcp::iface::Interface::new(
            smoltcp_config,
            &mut device,
            smoltcp::time::Instant::ZERO,
        );
        interface.update_ip_addrs(|ip_addrs| {
            match ip_addrs.push(smoltcp::wire::IpCidr::new(
                smoltcp::wire::IpAddress::Ipv4(config.ip_addr),
                config.prefix_len,
            )) {
                Ok(()) => {}
                Err(_) => unreachable!(),
            }
        });
        match interface
            .routes_mut()
            .add_default_ipv4_route(config.gateway)
        {
            Ok(None) => {}
            _ => unreachable!(),
        }
        Self {
            litebox: litebox.clone(),
            socket_set: smoltcp::iface::SocketSet::new(vec![]),
            device,
            interface,
            zero_time: litebox.x.platform.now(),
            local_port_allocator: LocalPortAllocator::new(),
            platform_interaction: PlatformInteraction::Automatic,
            closing_in_background: vec![],
        }
    }
```

**Step 3: Refactor `new()` to use `with_config()`**

Replace the existing `new()` body:

```rust
    pub fn new(litebox: &LiteBox<Platform>) -> Self {
        Self::with_config(litebox, NetworkConfig::default())
    }
```

**Step 4: Verify compilation and tests**

Run: `cargo test -p litebox --lib`
Expected: All tests pass. `new()` behavior unchanged (uses default config).

**Step 5: Commit**

```bash
git add litebox/src/net/mod.rs
git commit -m "feat(net): add NetworkConfig and Network::with_config()"
```

---

### Task 4: Wire NetworkConfig through LinuxShimBuilder

**Files:**
- Modify: `litebox_shim_linux/src/lib.rs:287-338` (LinuxShimBuilder struct and build())

**Step 1: Add `network_config` field to `LinuxShimBuilder`**

```rust
pub struct LinuxShimBuilder {
    platform: &'static Platform,
    litebox: LiteBox<Platform>,
    load_filter: Option<LoadFilter>,
    network_config: Option<litebox::net::NetworkConfig>,
}
```

Update `new()` to initialize `network_config: None`.

**Step 2: Add setter method**

```rust
    /// Set the network configuration for the guest network stack.
    ///
    /// When not set, the default configuration is used (IP mode, 10.0.0.2/24,
    /// gateway 10.0.0.1).
    pub fn set_network_config(&mut self, config: litebox::net::NetworkConfig) {
        self.network_config = Some(config);
    }
```

**Step 3: Use config in build()**

Change line 337 from:
```rust
        let mut net = Network::new(&self.litebox);
```
To:
```rust
        let mut net = if let Some(config) = self.network_config {
            Network::with_config(&self.litebox, config)
        } else {
            Network::new(&self.litebox)
        };
```

**Step 4: Verify compilation and tests**

Run: `cargo test -p litebox_shim_linux --lib`
Expected: Compiles, tests pass.

**Step 5: Commit**

```bash
git add litebox_shim_linux/src/lib.rs
git commit -m "feat(shim): wire NetworkConfig through LinuxShimBuilder"
```

---

### Task 5: Add `AfPacket` transport variant to platform

**Files:**
- Modify: `litebox_platform_linux_userland/src/lib.rs:120-130` (NetworkTransport enum)
- Modify: `litebox_platform_linux_userland/src/lib.rs:4141-4280` (IPInterfaceProvider impl)

**Step 1: Add `AfPacket` variant**

```rust
pub enum NetworkTransport {
    /// Traditional TUN device — requires root/admin to set up.
    Tun(std::os::fd::OwnedFd),
    /// IPC pipe to a network broker — no privileges needed.
    Ipc(std::os::fd::OwnedFd),
    /// AF_PACKET raw socket on an Ethernet interface (e.g. CNI veth).
    /// Sends/receives complete Ethernet frames.
    AfPacket(std::os::fd::OwnedFd),
}
```

**Step 2: Add `medium()` implementation**

In the `IPInterfaceProvider` impl for `LinuxUserland`, add:

```rust
    fn medium(&self) -> smoltcp::phy::Medium {
        let transport = self.network_transport.read().unwrap();
        match transport.as_ref() {
            Some(NetworkTransport::AfPacket(_)) => smoltcp::phy::Medium::Ethernet,
            _ => smoltcp::phy::Medium::Ip,
        }
    }
```

**Step 3: Add `send_ip_packet` and `receive_ip_packet` branches for AfPacket**

In `send_ip_packet`, add an `AfPacket` match arm after the `Ipc` arm:

```rust
            NetworkTransport::AfPacket(fd) => {
                // AF_PACKET: data is already a complete Ethernet frame from smoltcp.
                // Plain send() — no length framing needed.
                let ret = unsafe {
                    libc::send(
                        fd.as_raw_fd(),
                        packet.as_ptr().cast::<libc::c_void>(),
                        packet.len(),
                        libc::MSG_NOSIGNAL,
                    )
                };
                if ret < 0 {
                    Err(litebox::platform::SendError::Io(
                        unsafe { *libc::__errno_location() },
                    ))
                } else {
                    Ok(())
                }
            }
```

In `receive_ip_packet`, add:

```rust
            NetworkTransport::AfPacket(fd) => {
                // AF_PACKET: receive a complete Ethernet frame.
                let ret = unsafe {
                    libc::recv(
                        fd.as_raw_fd(),
                        packet.as_mut_ptr().cast::<libc::c_void>(),
                        packet.len(),
                        libc::MSG_DONTWAIT,
                    )
                };
                if ret < 0 {
                    let errno = unsafe { *libc::__errno_location() };
                    if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                        Err(litebox::platform::ReceiveError::WouldBlock)
                    } else {
                        Err(litebox::platform::ReceiveError::Eof)
                    }
                } else {
                    Ok(ret as usize)
                }
            }
```

**Step 4: Handle AfPacket in `wait_on_network` / `has_network`**

Check the `wait_on_network` and `has_network` implementations — they should match on all NetworkTransport variants. `AfPacket` behaves like `Tun` (direct fd polling).

**Step 5: Verify compilation and tests**

Run: `cargo test -p litebox_platform_linux_userland --lib`
Expected: All 40 tests pass. No behavioral change for existing code paths.

**Step 6: Commit**

```bash
git add litebox_platform_linux_userland/src/lib.rs
git commit -m "feat(platform): add AfPacket transport variant with Ethernet medium"
```

---

### Task 6: Add CliArgs fields and wire through run()

**Files:**
- Modify: `litebox_runner_linux_userland/src/lib.rs:29-226` (CliArgs struct)
- Modify: `litebox_runner_linux_userland/src/lib.rs:461-510` (run() platform construction)
- Modify: `litebox_runner_linux_userland/src/lib.rs:505-511` (shim builder setup)

**Step 1: Add skip fields to CliArgs**

After the `network_config` / `proc_mount` fields, add:

```rust
    /// Pre-opened AF_PACKET socket fd for CNI veth networking.
    /// When set, the platform uses `NetworkTransport::AfPacket` and smoltcp
    /// runs in Ethernet mode.
    #[arg(skip)]
    pub af_packet_fd: Option<std::os::fd::OwnedFd>,

    /// Network configuration for the guest smoltcp stack (IP, prefix, gateway, MAC).
    /// Used with AF_PACKET CNI networking to configure smoltcp with the real
    /// CNI network parameters instead of the default 10.0.0.x subnet.
    #[arg(skip)]
    pub network_config: Option<litebox::net::NetworkConfig>,
```

Update ALL other CliArgs construction sites (search for `CliArgs {`) to include:
- `af_packet_fd: None,`
- `network_config: None,`

There should be at least 3 sites: `build_cli_args()` in runner.rs, `build_cli_args_from_exec_params()` in lib.rs, and `test_cli_args()` in lib.rs.

**Step 2: Wire af_packet_fd into platform construction in run()**

In `run()` at lines 466-474, add a new branch before the existing `tun_device_name` check:

```rust
    let platform = if let Some(af_packet_fd) = cli_args.af_packet_fd.take() {
        use litebox_platform_linux_userland::NetworkTransport;
        Platform::with_network(Some(NetworkTransport::AfPacket(af_packet_fd)))
    } else if cli_args.tun_device_name.is_some() {
        Platform::new(cli_args.tun_device_name.as_deref())
    } else if let Some(broker_path) = &cli_args.network_broker {
        use litebox_platform_linux_userland::NetworkTransport;
        let fd = connect_to_broker_ipc(broker_path)?;
        Platform::with_network(Some(NetworkTransport::Ipc(fd)))
    } else {
        Platform::new(None)
    };
```

Note: `cli_args.af_packet_fd.take()` moves the `OwnedFd` out, leaving `None`. This requires `cli_args` to be `mut` — check if it already is, or add `mut`.

**Step 3: Wire network_config into shim builder**

After `let shim_builder = litebox_shim_linux::LinuxShimBuilder::new();` (line 505), add:

```rust
    if let Some(net_config) = cli_args.network_config.take() {
        shim_builder.set_network_config(net_config);
    }
```

This requires `shim_builder` to be `mut` — it should already be since `set_load_filter` is called on it later. Check.

Actually, looking at line 633: `shim_builder.set_load_filter(fixup_env);` — `shim_builder` is used mutably. But at line 505 it's `let shim_builder = ...` without `mut`. Check if `set_load_filter` is called on it (yes, at line 633 in `finish_run`). Wait — `finish_run` receives `mut shim_builder` as parameter. So we need to add `mut` to the let binding in `run()`, or set the config inside `finish_run`.

Actually, looking more carefully: `run()` creates `shim_builder` at line 505 and passes it by value to `finish_run` at line 510. Inside `finish_run`, the parameter is `mut shim_builder` (line 611). So we should set the network config in `finish_run`, not in `run()`, OR make the binding in `run()` mutable.

Simplest approach: pass network_config through to `finish_run` as a parameter, or set it on shim_builder in `run()` before passing it. Let's set it in `run()`:

Change line 505 from:
```rust
    let shim_builder = litebox_shim_linux::LinuxShimBuilder::new();
```
To:
```rust
    let mut shim_builder = litebox_shim_linux::LinuxShimBuilder::new();
    if let Some(net_config) = cli_args.network_config.take() {
        shim_builder.set_network_config(net_config);
    }
```

**Step 4: Verify compilation and tests**

Run: `cargo test -p litebox_runner_linux_userland --lib`
Run: `cargo test -p litebox_runner_oci --lib`
Expected: All tests pass.

**Step 5: Commit**

```bash
git add litebox_runner_linux_userland/src/lib.rs
git commit -m "feat(runner): add af_packet_fd and network_config CliArgs fields"
```

---

### Task 7: Implement `setup_cni_af_packet()` in OCI runner

**Files:**
- Modify: `litebox_runner_oci/src/runner.rs:197-258` (replace setup_cni_tun with setup_cni_af_packet)
- Modify: `litebox_runner_oci/src/runner.rs:513-530` (run_container CNI detection)

**Step 1: Add MAC reading helper**

Add a function to read the MAC address from sysfs:

```rust
/// Read the MAC address of a network interface from sysfs.
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
        anyhow::bail!("MAC address has {} bytes, expected 6: {mac_str}", bytes.len());
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&bytes);
    Ok(mac)
}
```

**Step 2: Add `CniNetworkConfig.iface_name` field**

The `CniNetworkConfig` struct at line 30 doesn't store the interface name. Add it:

```rust
pub struct CniNetworkConfig {
    pub netns_path: Option<PathBuf>,
    pub iface_name: String,  // NEW
    pub ip_addr: std::net::Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: std::net::Ipv4Addr,
    pub mtu: u16,
}
```

Update `read_netns_config()` at line 167 to include `iface_name: iface_name.clone(),` (or `iface_name,` if moved).

**Step 3: Replace `setup_cni_tun()` with `setup_cni_af_packet()`**

Delete `setup_cni_tun()` (lines 197-258). Replace with:

```rust
/// Open an AF_PACKET raw socket on the CNI veth interface.
///
/// Returns the socket fd and a `NetworkConfig` for smoltcp (Ethernet mode
/// with the veth's MAC, IP, prefix, and gateway from CNI detection).
///
/// The caller must already be in the CNI network namespace (via setns).
fn setup_cni_af_packet(
    cni: &CniNetworkConfig,
) -> Result<(std::os::fd::OwnedFd, litebox::net::NetworkConfig)> {
    use std::os::fd::FromRawFd;

    // Read the veth MAC address
    let mac = read_interface_mac(&cni.iface_name)?;

    // Open AF_PACKET raw socket
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        )
    };
    if fd < 0 {
        anyhow::bail!(
            "socket(AF_PACKET) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };

    // Bind to the specific interface
    let ifindex = unsafe { libc::if_nametoindex(
        std::ffi::CString::new(cni.iface_name.as_str())?.as_ptr()
    ) };
    if ifindex == 0 {
        anyhow::bail!(
            "if_nametoindex({}) failed: {}",
            cni.iface_name,
            std::io::Error::last_os_error()
        );
    }

    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    addr.sll_ifindex = ifindex as i32;

    let ret = unsafe {
        libc::bind(
            std::os::fd::AsRawFd::as_raw_fd(&fd),
            (&addr as *const libc::sockaddr_ll).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_ll>() as u32,
        )
    };
    if ret < 0 {
        anyhow::bail!(
            "bind(AF_PACKET, ifindex={ifindex}) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    // Set socket non-blocking for the network worker poll loop
    unsafe {
        let flags = libc::fcntl(std::os::fd::AsRawFd::as_raw_fd(&fd), libc::F_GETFL);
        libc::fcntl(std::os::fd::AsRawFd::as_raw_fd(&fd), libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    let net_config = litebox::net::NetworkConfig {
        hardware_addr: smoltcp::wire::HardwareAddress::Ethernet(
            smoltcp::wire::EthernetAddress(mac),
        ),
        ip_addr: smoltcp::wire::Ipv4Address::from(cni.ip_addr),
        prefix_len: cni.prefix_len,
        gateway: smoltcp::wire::Ipv4Address::from(cni.gateway),
    };

    Ok((fd, net_config))
}
```

**Step 4: Update `run_container()` to use AF_PACKET**

Replace the current CNI handling at lines 513-530:

```rust
    // 3. Detect CNI network from OCI spec — use AF_PACKET if available
    let (af_packet_fd, network_config) = if network.tun_device.is_some() {
        (None, None)  // explicit TUN overrides CNI detection
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
    let tun_device = if af_packet_fd.is_some() {
        None  // AF_PACKET replaces TUN
    } else {
        network.tun_device.clone()
    };
```

**Step 5: Pass AF_PACKET fd and config to CliArgs**

In `build_cli_args()`, add parameters for the AF_PACKET fd and network config. Change the function signature:

```rust
fn build_cli_args(
    spec: &Spec,
    override_args: Option<&[String]>,
    extra_env: &[String],
    broker_socket: &str,
    tun_device: Option<String>,
    af_packet_fd: Option<std::os::fd::OwnedFd>,
    network_config: Option<litebox::net::NetworkConfig>,
) -> Result<CliArgs> {
```

And in the CliArgs struct literal, replace the current `tun_device_name` and `network_broker` handling:

```rust
        af_packet_fd,
        network_config,
```

Update the caller in `run_container()` to pass the new parameters.

**Step 6: Add smoltcp dependency to litebox_runner_oci Cargo.toml**

The `NetworkConfig` struct references `smoltcp::wire::HardwareAddress` etc. Check if `smoltcp` is already a dependency of `litebox_runner_oci`. If not, add it to `Cargo.toml`, or use re-exports from `litebox::net`.

Actually, `NetworkConfig` is defined in `litebox::net` which is part of the `litebox` crate. If `litebox_runner_oci` depends on `litebox` (check Cargo.toml), then `litebox::net::NetworkConfig` is accessible. But the smoltcp types used in the constructor (`HardwareAddress::Ethernet`, `EthernetAddress`, `Ipv4Address`) need to be accessible too.

Best approach: Add constructor methods to `NetworkConfig` that accept plain types:

```rust
impl NetworkConfig {
    /// Create a config for Ethernet mode (AF_PACKET on a veth).
    pub fn ethernet(mac: [u8; 6], ip: std::net::Ipv4Addr, prefix_len: u8, gateway: std::net::Ipv4Addr) -> Self {
        Self {
            hardware_addr: smoltcp::wire::HardwareAddress::Ethernet(
                smoltcp::wire::EthernetAddress(mac),
            ),
            ip_addr: smoltcp::wire::Ipv4Address::from(ip),
            prefix_len,
            gateway: smoltcp::wire::Ipv4Address::from(gateway),
        }
    }
}
```

Then the OCI runner just calls:
```rust
litebox::net::NetworkConfig::ethernet(mac, cni.ip_addr, cni.prefix_len, cni.gateway)
```

No smoltcp dependency needed in the OCI runner crate.

**Step 7: Write tests**

Add to the test module in `runner.rs`:

```rust
    #[test]
    fn read_interface_mac_parses_valid_mac() {
        // This test requires a network interface. Use "lo" which always exists.
        // lo's MAC is typically 00:00:00:00:00:00.
        let mac = read_interface_mac("lo");
        assert!(mac.is_ok(), "failed to read lo MAC: {:?}", mac.err());
        assert_eq!(mac.unwrap(), [0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn read_interface_mac_fails_for_nonexistent() {
        let mac = read_interface_mac("nonexistent_iface_xyz");
        assert!(mac.is_err());
    }
```

**Step 8: Verify compilation and tests**

Run: `cargo test -p litebox_runner_oci --lib`
Run: `cargo test -p litebox_runner_linux_userland --lib`
Expected: All tests pass.

**Step 9: Commit**

```bash
git add litebox_runner_oci/src/runner.rs litebox/src/net/mod.rs
git commit -m "feat(oci): replace TUN+iptables CNI with AF_PACKET on veth"
```

---

### Task 8: Full test suite verification

**Step 1: Run all test suites**

```bash
cargo test -p litebox --lib
cargo test -p litebox_shim_linux --lib
cargo test -p litebox_runner_oci --lib
cargo test -p litebox_runner_linux_userland --lib
cargo test -p litebox_platform_linux_userland --lib
cargo test -p litebox_broker --lib
```

Expected: All tests pass.

**Step 2: Build OCI runner**

```bash
cargo build -p litebox_runner_oci
```

Expected: Clean build.
