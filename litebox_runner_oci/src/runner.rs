// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! LiteBox-native OCI container execution.

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
    pub netns_path: Option<std::path::PathBuf>,
    /// Container interface IP address.
    pub ip_addr: std::net::Ipv4Addr,
    /// Network prefix length.
    pub prefix_len: u8,
    /// Gateway IP address.
    pub gateway: std::net::Ipv4Addr,
    /// Interface MTU.
    pub mtu: u16,
}

/// Run an OCI container.
pub fn run_container(
    _bundle_path: &std::path::Path,
    _override_args: Option<&[String]>,
    _extra_env: &[String],
    _network: &NetworkConfig,
) -> anyhow::Result<i32> {
    anyhow::bail!("not yet implemented")
}
