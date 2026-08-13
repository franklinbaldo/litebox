//! Hardware capability discovery and broker registry for Windows userland.

use anyhow::Result;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityKind {
    Inherent,
    Brokered,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HardwareCapability {
    Hostinfo,
    Power,
}

#[derive(Clone, Copy, Debug)]
pub struct CapabilityInfo {
    pub name: &'static str,
    pub kind: CapabilityKind,
    pub backend: &'static str,
    pub available: bool,
    pub safe: bool,
    pub description: &'static str,
}

pub const CAPABILITIES: &[CapabilityInfo] = &[
    CapabilityInfo {
        name: "cpu",
        kind: CapabilityKind::Inherent,
        backend: "direct",
        available: true,
        safe: true,
        description: "Host CPU instructions",
    },
    CapabilityInfo {
        name: "simd",
        kind: CapabilityKind::Inherent,
        backend: "direct",
        available: true,
        safe: true,
        description: "Host SIMD instruction sets",
    },
    CapabilityInfo {
        name: "memory",
        kind: CapabilityKind::Inherent,
        backend: "windows-process",
        available: true,
        safe: true,
        description: "Process virtual memory",
    },
    CapabilityInfo {
        name: "clock",
        kind: CapabilityKind::Inherent,
        backend: "translated",
        available: true,
        safe: true,
        description: "Monotonic time and CPU counter",
    },
    CapabilityInfo {
        name: "threads",
        kind: CapabilityKind::Inherent,
        backend: "translated",
        available: true,
        safe: true,
        description: "Host thread execution",
    },
    CapabilityInfo {
        name: "hostinfo",
        kind: CapabilityKind::Brokered,
        backend: "windows-userland",
        available: true,
        safe: true,
        description: "Read-only host architecture and CPU-count snapshot",
    },
    CapabilityInfo {
        name: "power",
        kind: CapabilityKind::Brokered,
        backend: "windows-power-stack",
        available: true,
        safe: true,
        description: "Read-only AC and battery status",
    },
    CapabilityInfo {
        name: "network",
        kind: CapabilityKind::Brokered,
        backend: "not-implemented",
        available: false,
        safe: false,
        description: "Windows network broker",
    },
    CapabilityInfo {
        name: "audio",
        kind: CapabilityKind::Brokered,
        backend: "not-implemented",
        available: false,
        safe: false,
        description: "Windows audio broker",
    },
    CapabilityInfo {
        name: "camera",
        kind: CapabilityKind::Brokered,
        backend: "not-implemented",
        available: false,
        safe: false,
        description: "Windows camera broker",
    },
    CapabilityInfo {
        name: "gpu",
        kind: CapabilityKind::Brokered,
        backend: "not-implemented",
        available: false,
        safe: false,
        description: "Windows GPU broker",
    },
    CapabilityInfo {
        name: "usb",
        kind: CapabilityKind::Brokered,
        backend: "not-implemented",
        available: false,
        safe: false,
        description: "Windows USB broker",
    },
];

pub fn capability_by_name(name: &str) -> Option<&'static CapabilityInfo> {
    CAPABILITIES
        .iter()
        .find(|capability| capability.name == name)
}

pub fn brokered_by_name(name: &str) -> Option<HardwareCapability> {
    match name {
        "hostinfo" => Some(HardwareCapability::Hostinfo),
        "power" => Some(HardwareCapability::Power),
        _ => None,
    }
}

pub fn safe_capabilities() -> Vec<HardwareCapability> {
    vec![HardwareCapability::Hostinfo, HardwareCapability::Power]
}

pub fn host_capabilities() -> Vec<HardwareCapability> {
    CAPABILITIES
        .iter()
        .filter(|capability| capability.kind == CapabilityKind::Brokered && capability.available)
        .filter_map(|capability| brokered_by_name(capability.name))
        .collect()
}

pub fn snapshot(capability: HardwareCapability) -> Result<(&'static str, Vec<u8>)> {
    match capability {
        HardwareCapability::Hostinfo => {
            let logical_processors =
                std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
            Ok((
                "/run/litebox/hostinfo.json",
                format!(
                    "{{\"schema\":1,\"source\":\"windows-userland\",\"architecture\":\"{}\",\"logical_processors\":{logical_processors}}}\n",
                    std::env::consts::ARCH
                )
                .into_bytes(),
            ))
        }
        HardwareCapability::Power => Ok((
            "/run/litebox/power.json",
            windows_power_snapshot()?.into_bytes(),
        )),
    }
}

fn windows_power_snapshot() -> Result<String> {
    use windows_sys::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};

    let mut status = SYSTEM_POWER_STATUS {
        ACLineStatus: 0,
        BatteryFlag: 0,
        BatteryLifePercent: 0,
        SystemStatusFlag: 0,
        BatteryLifeTime: 0,
        BatteryFullLifeTime: 0,
    };
    if unsafe { GetSystemPowerStatus(&raw mut status) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(format!(
        "{{\"schema\":1,\"source\":\"windows-power-stack\",\"ac_line_status\":{},\"battery_flag\":{},\"battery_percent\":{},\"battery_lifetime_seconds\":{}}}\n",
        status.ACLineStatus, status.BatteryFlag, status.BatteryLifePercent, status.BatteryLifeTime
    ))
}
