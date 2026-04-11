# CNI AF_PACKET Networking Design

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:writing-plans to create the implementation plan after this design is approved.

**Goal:** Replace the TUN+iptables CNI networking path with direct AF_PACKET on the veth, eliminating TUN device creation, iptables MASQUERADE, ip_forward, and the `ip` command dependency.

## Problem

The current CNI networking path has too many hops and too many privilege/tool dependencies:

```text
Guest connect() → smoltcp (IP mode) → TUN fd write → kernel routing
    → iptables MASQUERADE → CNI veth → host network
```

This requires:
- `ip tuntap add` (creates TUN device)
- `ip addr add` + `ip link set up` (configures TUN)
- `echo 1 > /proc/sys/net/ipv4/ip_forward` (enables forwarding)
- `iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -j MASQUERADE` (NAT)

Each of these can fail, requires specific tools in the netns, and adds latency.

## Solution

Open an `AF_PACKET` raw socket directly on the CNI veth interface. Switch smoltcp to Ethernet mode so it emits complete Ethernet frames. Frames go straight to the kernel via the veth.

```text
Guest connect() → smoltcp (Ethernet mode) → AF_PACKET(veth) → kernel → host network
```

Eliminated: TUN, iptables, MASQUERADE, ip_forward, `ip` command.

## Architecture

### Packet flow (new)

```
┌─────────────────────────────────────────────┐
│  Guest process                              │
│  connect("1.2.3.4:80")                      │
│      ↓ (intercepted syscall)                │
│  smoltcp (Ethernet mode)                    │
│      ↓ (Ethernet frame: MAC + IP + TCP)     │
│  AF_PACKET socket on veth (e.g. eth0)       │
└──────────────┬──────────────────────────────┘
               ↓ (single write syscall)
┌──────────────┴──────────────────────────────┐
│  Kernel (CNI netns)                         │
│  Routes via veth peer → host network        │
└─────────────────────────────────────────────┘
```

### Component changes

**1. Platform layer** (`litebox_platform_linux_userland/src/lib.rs`)

New transport variant:
```rust
pub enum NetworkTransport {
    Tun(OwnedFd),       // existing: raw IP packets, Medium::Ip
    Ipc(OwnedFd),       // existing: length-framed IP packets, Medium::Ip
    AfPacket(OwnedFd),  // NEW: raw Ethernet frames, Medium::Ethernet
}
```

`send_ip_packet` / `receive_ip_packet` for `AfPacket`: plain `send()`/`recv()` on the raw socket — the data is already a complete Ethernet frame produced by smoltcp.

**2. IPInterfaceProvider trait** (`litebox/src/platform/mod.rs`)

Add a method to query the medium:
```rust
pub trait IPInterfaceProvider {
    fn send_ip_packet(&self, packet: &[u8]) -> Result<(), SendError>;
    fn receive_ip_packet(&self, packet: &mut [u8]) -> Result<usize, ReceiveError>;

    /// The network medium. Defaults to IP (no link-layer framing).
    fn medium(&self) -> smoltcp::phy::Medium { smoltcp::phy::Medium::Ip }
}
```

Platform returns `Medium::Ethernet` when transport is `AfPacket`.

**3. PHY device** (`litebox/src/net/phy.rs`)

`Device::capabilities()` uses `self.platform.medium()` instead of hardcoding `Medium::Ip`.

**4. Network** (`litebox/src/net/mod.rs`)

New config struct:
```rust
pub struct NetworkConfig {
    pub hardware_addr: smoltcp::wire::HardwareAddress,
    pub ip_addr: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Ipv4Addr,
}
```

`Network::new()` keeps existing behavior (IP mode, 10.0.0.2/24, gateway 10.0.0.1).
`Network::with_config(litebox, config)` uses the provided config. For CNI, this means:
- `HardwareAddress::Ethernet(mac)` with the veth's MAC
- IP/prefix/gateway from CNI detection

**5. OCI runner** (`litebox_runner_oci/src/runner.rs`)

Replace `setup_cni_tun()` with `setup_cni_af_packet()`:

1. Enter CNI netns via `setns()` (same as now)
2. Find non-loopback interface name (already done in `read_netns_config()`)
3. Read MAC from `/sys/class/net/<iface>/address`
4. Open AF_PACKET socket:
   ```rust
   let fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
   let mut addr = sockaddr_ll {
       sll_family: AF_PACKET,
       sll_protocol: htons(ETH_P_ALL),
       sll_ifindex: if_nametoindex(iface),
       ..zeroed()
   };
   bind(fd, &addr, size_of::<sockaddr_ll>());
   ```
5. Return `(OwnedFd, NetworkConfig)` — the fd + CNI network parameters

**6. CliArgs** (`litebox_runner_linux_userland/src/lib.rs`)

Two new `#[arg(skip)]` fields:
```rust
#[arg(skip)]
pub af_packet_fd: Option<std::os::fd::OwnedFd>,

#[arg(skip)]
pub network_config: Option<NetworkConfig>,
```

**7. run()** (`litebox_runner_linux_userland/src/lib.rs`)

When `af_packet_fd` is `Some`, create platform with `NetworkTransport::AfPacket(fd)` and use `network_config` for `Network::with_config()`. Existing TUN and IPC paths unchanged.

### What stays unchanged

- **IPC broker networking** — used when TUN/AF_PACKET aren't available (no CNI). The double-smoltcp path is the fallback.
- **TUN transport** — `NetworkTransport::Tun` stays for standalone (non-OCI) TUN usage.
- **9P filesystem** — unaffected. Uses shared-memory ring buffers, not the network stack.
- **Guest-side smoltcp** — same stack, just configured for Ethernet mode instead of IP mode when using AF_PACKET.

### What gets deleted

- `setup_cni_tun()` function
- TUN device creation commands (`ip tuntap add dev litebox0 mode tun`)
- TUN IP configuration (`ip addr add`, `ip link set up`)
- iptables MASQUERADE rule
- ip_forward sysctl write
- The `tun_device` branch in `run_container()` (replaced by `af_packet_fd` branch)

### Testing

- Unit tests for AF_PACKET socket creation (mock the syscalls or test in a netns)
- Integration test: run Alpine via OCI with CNI netns, verify `wget` works
- Verify IPC broker fallback still works when AF_PACKET setup fails
- Verify standalone TUN mode still works (non-OCI path)

### Risks

1. **AF_PACKET requires CAP_NET_RAW** — CNI netns should have this since Podman/containerd set it up, but needs verification.
2. **Promiscuous mode** — AF_PACKET with `ETH_P_ALL` receives ALL frames on the interface. May need filtering or `PACKET_AUXDATA` to avoid processing frames not meant for us. Alternatively, use `setsockopt(PACKET_ADD_MEMBERSHIP)` or BPF filter.
3. **ARP handling** — smoltcp in Ethernet mode handles ARP natively, but we need the correct MAC address for the veth. If the veth's MAC changes (unlikely in CNI), this breaks.
