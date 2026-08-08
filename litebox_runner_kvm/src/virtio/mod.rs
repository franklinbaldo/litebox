// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Discovery of a modern (virtio 1.0) PCI device's configuration structures.
//!
//! A virtio 1.0 device does not put its registers at fixed offsets. It
//! describes them, instead, through a chain of vendor-specific PCI
//! capabilities, each naming a BAR, an offset within it and a length. This
//! module walks that chain and records what it finds.
//!
//! Nothing here maps or touches device memory: every read is a PCI
//! configuration cycle over `0xCF8`/`0xCFC`. The BAR contents themselves are
//! only reported, not sized and not mapped -- that is deliberately left to the
//! next step, since sizing a BAR requires writing to it.

use crate::pci::{self, Bar, DeviceHeader};

/// The `cfg_type` byte of a virtio PCI capability.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CfgType {
    /// Common configuration: the device/driver feature bits, status, and the
    /// per-queue registers.
    Common,
    /// The notification region a queue kick is written to.
    Notify,
    /// ISR status. Read by a polling driver to acknowledge the device, even
    /// with no interrupt wired up.
    Isr,
    /// Device-specific configuration; for virtio-console, the port count and
    /// geometry.
    Device,
    /// An alternative access path to the above through configuration space
    /// alone. Not needed once the BARs are mapped.
    PciConfigAccess,
    /// Something this driver does not know about. Recorded rather than
    /// dropped, so an unexpected structure shows up in the log instead of
    /// vanishing.
    Unknown(u8),
}

impl CfgType {
    fn from_raw(raw: u8) -> Self {
        match raw {
            1 => Self::Common,
            2 => Self::Notify,
            3 => Self::Isr,
            4 => Self::Device,
            5 => Self::PciConfigAccess,
            other => Self::Unknown(other),
        }
    }
}

impl core::fmt::Display for CfgType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Common => f.write_str("common"),
            Self::Notify => f.write_str("notify"),
            Self::Isr => f.write_str("isr"),
            Self::Device => f.write_str("device"),
            Self::PciConfigAccess => f.write_str("pci-cfg"),
            Self::Unknown(raw) => write!(f, "unknown({raw:#04X})"),
        }
    }
}

/// Field offsets within a `virtio_pci_cap`, relative to the capability's own
/// offset in configuration space.
mod cap {
    // +0 is `cap_vndr` and +1 is `cap_next`; both are generic PCI capability
    // fields and are read by `pci::for_each_capability`, not here.
    /// `cap_len`: the whole capability's length in bytes.
    pub const LEN: u8 = 2;
    /// `cfg_type`.
    pub const CFG_TYPE: u8 = 3;
    /// `bar`: which BAR the structure lives in.
    pub const BAR: u8 = 4;
    /// `id`: distinguishes multiple structures of the same type.
    pub const ID: u8 = 5;
    // 6..8 is padding.
    /// `offset` (u32): byte offset of the structure within the BAR.
    pub const OFFSET: u8 = 8;
    /// `length` (u32): length of the structure.
    pub const LENGTH: u8 = 12;
    /// `notify_off_multiplier` (u32), present only on the notify capability.
    pub const NOTIFY_OFF_MULTIPLIER: u8 = 16;

    /// Length of a `virtio_pci_cap` without any type-specific tail.
    pub const BASE_LEN: u8 = 16;
    /// Length of a `virtio_pci_notify_cap`, which appends
    /// `notify_off_multiplier`.
    pub const NOTIFY_LEN: u8 = 20;
    /// Length of a `virtio_pci_cfg_cap`, which appends a `pci_cfg_data`
    /// window of the same width.
    pub const PCI_CFG_LEN: u8 = 20;
}

/// One virtio structure, as described by its capability.
#[derive(Clone, Copy)]
pub struct VirtioCap {
    /// Offset of the capability itself in configuration space, kept so the
    /// log can be checked against a raw dump.
    pub cap_offset: u8,
    pub cfg_type: CfgType,
    /// Which BAR the structure lives in.
    pub bar: u8,
    /// Distinguishes multiple structures of the same `cfg_type`.
    pub id: u8,
    /// Byte offset of the structure within that BAR.
    pub offset: u32,
    /// Length of the structure in bytes.
    pub length: u32,
    /// Present only on the notify capability: the stride between the
    /// notification addresses of consecutive queues.
    pub notify_off_multiplier: Option<u32>,
    /// The declared `cap_len`, retained because a value that disagrees with
    /// the `cfg_type` is the clearest sign the layout is not what we assume.
    pub cap_len: u8,
}

/// Upper bound on the number of virtio capabilities recorded for one device.
///
/// A modern virtio device needs four (common, notify, ISR, device-specific)
/// plus the PCI-config access one; QEMU emits five. Eight leaves room without
/// making the structure large enough to matter on a kernel stack.
const MAX_CAPS: usize = 8;

/// Everything discovery found out about one virtio device.
pub struct VirtioDevice {
    pub header: DeviceHeader,
    caps: [Option<VirtioCap>; MAX_CAPS],
    cap_count: usize,
    /// Set if the device declared more virtio capabilities than [`MAX_CAPS`],
    /// so a truncated table is never mistaken for a complete one.
    truncated: bool,
    pub bars: [Bar; pci::BAR_COUNT as usize],
}

impl VirtioDevice {
    /// Parses the capability list and BARs of `header`.
    pub fn discover(header: DeviceHeader) -> Self {
        let mut device = Self {
            header,
            caps: [None; MAX_CAPS],
            cap_count: 0,
            truncated: false,
            bars: header.bars(),
        };

        header.for_each_capability(|cap_offset, cap_id| {
            if cap_id != pci::CAP_ID_VENDOR_SPECIFIC {
                return;
            }

            let cap_len = pci::read_u8(header.address, cap_offset + cap::LEN);
            let cfg_type =
                CfgType::from_raw(pci::read_u8(header.address, cap_offset + cap::CFG_TYPE));

            // Read only for the notify capability, and only if it declared
            // itself long enough to have the field.
            //
            // Both halves matter. `virtio_pci_cfg_cap` is the same 20 bytes
            // but its trailing dword is `pci_cfg_data`, a live access window
            // -- reading that as a multiplier would report nonsense and
            // perform a stray device access besides. And a notify capability
            // that declared itself short has no such field at all, so reading
            // it would take four bytes belonging to the next capability.
            let notify_off_multiplier = (cfg_type == CfgType::Notify && cap_len >= cap::NOTIFY_LEN)
                .then(|| pci::read_u32(header.address, cap_offset + cap::NOTIFY_OFF_MULTIPLIER));

            let parsed = VirtioCap {
                cap_offset,
                cfg_type,
                bar: pci::read_u8(header.address, cap_offset + cap::BAR),
                id: pci::read_u8(header.address, cap_offset + cap::ID),
                offset: pci::read_u32(header.address, cap_offset + cap::OFFSET),
                length: pci::read_u32(header.address, cap_offset + cap::LENGTH),
                notify_off_multiplier,
                cap_len,
            };

            if device.cap_count < MAX_CAPS {
                device.caps[device.cap_count] = Some(parsed);
                device.cap_count += 1;
            } else {
                device.truncated = true;
            }
        });

        device
    }

    /// The virtio capabilities found, in list order.
    pub fn caps(&self) -> impl Iterator<Item = &VirtioCap> {
        self.caps[..self.cap_count].iter().flatten()
    }

    /// The first capability of the given type, if any.
    pub fn cap(&self, cfg_type: CfgType) -> Option<&VirtioCap> {
        self.caps().find(|cap| cap.cfg_type == cfg_type)
    }

    /// Whether the device exposes the three structures a modern virtio driver
    /// cannot work without.
    ///
    /// Device-specific configuration is deliberately not required: it is
    /// optional in the specification, and a driver that ignores the console's
    /// geometry does not need it.
    pub fn is_modern(&self) -> bool {
        self.cap(CfgType::Common).is_some()
            && self.cap(CfgType::Notify).is_some()
            && self.cap(CfgType::Isr).is_some()
    }
}

/// Logs the parsed capability table and BARs of every virtio device on bus 0.
///
/// Pure discovery. Returns the number of devices that expose a complete modern
/// capability set, so a caller can distinguish "no virtio device" from "a
/// virtio device we cannot drive this way".
pub fn log_virtio_devices() -> usize {
    let mut modern = 0;
    let mut total = 0;

    pci::for_each_device_with_vendor(pci::VENDOR_VIRTIO, |header| {
        total += 1;
        let device = VirtioDevice::discover(*header);
        let header = &device.header;
        let address = header.address;

        let (base, sub, prog_if) = header.class;
        log::info!(
            "virtio     {address} vendor {:#06X} device {:#06X} subsys {:#06X}:{:#06X} \
             rev {:#04X} class {base:#04X}/{sub:#04X}/{prog_if:#04X}",
            header.vendor_id,
            header.device_id,
            header.subsystem_vendor_id,
            header.subsystem_id,
            header.revision_id,
        );
        // The device ID says which interface generation to expect. 0x1040 +
        // type is modern-only; 0x1000..0x1040 is the legacy ID, which a
        // transitional device keeps while still offering the modern
        // structures alongside. Only the capability list settles it, which is
        // why this is reported rather than acted on.
        log::info!(
            "virtio     {address}   device id is {} ({})",
            if header.device_id >= 0x1040 {
                "modern-range"
            } else {
                "legacy-range"
            },
            if header.device_id >= 0x1040 {
                "0x1040 + device type"
            } else {
                "transitional or legacy"
            },
        );

        log::info!(
            "virtio     {address}   header {:#04X} (layout {}, {}) command {:#06X} \
             status {:#06X} caps at {}",
            header.header_type,
            header.layout(),
            if header.is_multifunction() {
                "multi-function"
            } else {
                "single-function"
            },
            header.command,
            header.status,
            CapPtr(header.capabilities_ptr),
        );

        for (index, bar) in device.bars.iter().enumerate() {
            log::info!("virtio     {address}   bar{index} {bar}");
        }

        for cap in device.caps() {
            log::info!(
                "virtio     {address}   cap@{:#04X} len {:2} type {:<8} bar {} id {} \
                 offset {:#010X} length {:#010X}{}",
                cap.cap_offset,
                cap.cap_len,
                cap.cfg_type,
                cap.bar,
                cap.id,
                cap.offset,
                cap.length,
                NotifyMultiplier(cap.notify_off_multiplier),
            );

            // A notify capability that is only `BASE_LEN` long has no
            // multiplier to read, which would make queue notification
            // addresses unknowable. Say so now rather than computing garbage
            // addresses later.
            if cap.cfg_type == CfgType::Notify && cap.cap_len < cap::NOTIFY_LEN {
                log::warn!(
                    "virtio     {address}   notify capability is {} bytes, expected {}; \
                     notify_off_multiplier is absent",
                    cap.cap_len,
                    cap::NOTIFY_LEN,
                );
            }
            // Two capability types are longer than the base structure:
            // notify appends `notify_off_multiplier`, and the PCI-config
            // access one appends its `pci_cfg_data` window. Anything else
            // that is not exactly `BASE_LEN` is unexpected.
            let expected_len = match cap.cfg_type {
                CfgType::Notify => cap::NOTIFY_LEN,
                CfgType::PciConfigAccess => cap::PCI_CFG_LEN,
                _ => cap::BASE_LEN,
            };
            if cap.cfg_type != CfgType::Notify && cap.cap_len != expected_len {
                log::warn!(
                    "virtio     {address}   {} capability is {} bytes, expected {expected_len}",
                    cap.cfg_type,
                    cap.cap_len,
                );
            }
            if cap.bar >= pci::BAR_COUNT {
                log::warn!(
                    "virtio     {address}   {} capability names bar {}, which does not exist",
                    cap.cfg_type,
                    cap.bar,
                );
            }
        }

        if device.truncated {
            log::warn!(
                "virtio     {address}   more than {MAX_CAPS} virtio capabilities; table truncated"
            );
        }

        if device.is_modern() {
            modern += 1;
            log::info!(
                "virtio     {address}   modern: common, notify and isr structures are all present"
            );
        } else {
            // Not a panic. This is discovery, and the runner's existing
            // behaviour must not depend on it; a legacy-only device is a fact
            // to report, not a reason to refuse to boot.
            log::warn!(
                "virtio     {address}   NOT usable as a modern device: missing{}{}{}",
                if device.cap(CfgType::Common).is_none() {
                    " common"
                } else {
                    ""
                },
                if device.cap(CfgType::Notify).is_none() {
                    " notify"
                } else {
                    ""
                },
                if device.cap(CfgType::Isr).is_none() {
                    " isr"
                } else {
                    ""
                },
            );
        }
    });

    if total == 0 {
        log::warn!("virtio     no virtio devices found on bus 0");
    }
    modern
}

/// Renders the capability list pointer, or says there is no list.
struct CapPtr(Option<u8>);

impl core::fmt::Display for CapPtr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            // A pointer of zero terminates the list before it starts, which
            // is indistinguishable from having no list at all.
            None | Some(0) => f.write_str("none"),
            Some(ptr) => write!(f, "{ptr:#04X}"),
        }
    }
}

/// Renders an optional `notify_off_multiplier` as a trailing log fragment.
///
/// A newtype rather than a formatted string because there is no allocator-free
/// way to build one inline, and the alternative -- two nearly identical
/// `log::info!` calls -- duplicates the whole format string.
struct NotifyMultiplier(Option<u32>);

impl core::fmt::Display for NotifyMultiplier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            Some(m) => write!(f, " notify_off_multiplier {m:#X}"),
            None => Ok(()),
        }
    }
}
