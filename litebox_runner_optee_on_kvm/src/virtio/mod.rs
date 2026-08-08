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

pub mod mmio;
pub mod queue;

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

// ---------------------------------------------------------------------------
// The mapped transport.
// ---------------------------------------------------------------------------

/// Field offsets within `virtio_pci_common_cfg`.
///
/// Fixed by the specification, not discovered: the capability says where the
/// structure is, and this says what is in it.
pub mod common {
    /// Selects which 32-bit word of the device's feature bits [`DEVICE_FEATURE`]
    /// reads (u32).
    ///
    /// [`DEVICE_FEATURE`]: self::DEVICE_FEATURE
    pub const DEVICE_FEATURE_SELECT: u64 = 0x00;
    /// The selected word of the device's feature bits (u32, read-only).
    pub const DEVICE_FEATURE: u64 = 0x04;
    /// Selects which word [`DRIVER_FEATURE`] writes (u32).
    ///
    /// [`DRIVER_FEATURE`]: self::DRIVER_FEATURE
    pub const DRIVER_FEATURE_SELECT: u64 = 0x08;
    /// The selected word of the features the driver accepts (u32).
    pub const DRIVER_FEATURE: u64 = 0x0C;
    /// The number of virtqueues the device implements (u16, read-only).
    pub const NUM_QUEUES: u64 = 0x12;
    /// Device status (u8).
    pub const DEVICE_STATUS: u64 = 0x14;
    /// Selects the queue the registers below refer to (u16).
    pub const QUEUE_SELECT: u64 = 0x16;
    /// The selected queue's size in descriptors (u16). Writable, to request a
    /// smaller queue than the device's maximum.
    pub const QUEUE_SIZE: u64 = 0x18;
    /// Whether the selected queue is live (u16).
    pub const QUEUE_ENABLE: u64 = 0x1C;
    /// The selected queue's index into the notification region (u16,
    /// read-only).
    pub const QUEUE_NOTIFY_OFF: u64 = 0x1E;
    /// Physical address of the selected queue's descriptor table (u64).
    pub const QUEUE_DESC: u64 = 0x20;
    /// Physical address of the selected queue's available ring (u64).
    pub const QUEUE_DRIVER: u64 = 0x28;
    /// Physical address of the selected queue's used ring (u64).
    pub const QUEUE_DEVICE: u64 = 0x30;
}

/// `device_status` bits.
pub mod status {
    /// The driver has noticed the device.
    pub const ACKNOWLEDGE: u8 = 1;
    /// The driver knows how to drive it.
    pub const DRIVER: u8 = 2;
    /// The driver is ready; the device may start using the queues.
    pub const DRIVER_OK: u8 = 4;
    /// Feature negotiation is complete. The device clears this bit if it
    /// cannot live with what the driver chose, which is the only way it has to
    /// say so.
    pub const FEATURES_OK: u8 = 8;
    /// The driver has given up. Set on every bring-up failure path so the
    /// device is left knowing it is not being driven, rather than half
    /// initialised.
    pub const FAILED: u8 = 128;
}

/// Feature bit 32: the device follows the virtio 1.0 specification rather than
/// the legacy layout. A device that does not offer this is not one this driver
/// can talk to at all.
pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;

/// A virtio device whose configuration structures have been mapped.
pub struct Transport {
    pub header: DeviceHeader,
    pub common: mmio::Region,
    pub notify: mmio::Region,
    pub isr: mmio::Region,
    /// Device-specific configuration, if the device declared any.
    pub device_cfg: Option<mmio::Region>,
    /// The stride between consecutive queues' notification addresses.
    pub notify_off_multiplier: u32,
}

impl Transport {
    /// Reads the 64 bits of features the device offers.
    ///
    /// Two selected reads rather than one, because the register is 32 bits
    /// wide and the low word must be selected explicitly -- the selector's
    /// value after reset is not something the specification promises.
    pub fn device_features(&self) -> u64 {
        let mut features = 0_u64;
        for word in 0..2_u32 {
            // SAFETY: `device_feature_select` is a selector with no effect
            // beyond choosing which word the next read returns.
            unsafe {
                self.common.write_u32(common::DEVICE_FEATURE_SELECT, word);
            }
            features |= u64::from(self.common.read_u32(common::DEVICE_FEATURE)) << (word * 32);
        }
        features
    }

    /// The number of virtqueues the device implements.
    pub fn num_queues(&self) -> u16 {
        self.common.read_u16(common::NUM_QUEUES)
    }

    /// The current device status byte.
    pub fn device_status(&self) -> u8 {
        self.common.read_u8(common::DEVICE_STATUS)
    }
}

/// Finds the first virtio device on bus 0 that exposes a complete modern
/// capability set, sizes its BARs, and maps its configuration structures.
///
/// Returns `None` if there is no such device -- which is the normal case for
/// `scripts/run.sh`, whose QEMU line has no virtio device at all. Absence is
/// logged and returned, never panicked on: nothing else in the runner depends
/// on this, and a runner that refused to boot without a device would be a
/// worse runner.
pub fn map_transport() -> Option<Transport> {
    let mut found: Option<VirtioDevice> = None;
    pci::for_each_device_with_vendor(pci::VENDOR_VIRTIO, |header| {
        if found.is_none() {
            let device = VirtioDevice::discover(*header);
            if device.is_modern() {
                found = Some(device);
            }
        }
    });
    let device = found?;
    let address = device.header.address;

    // Every structure this driver needs lives in some BAR; each has to be
    // sized and mapped before it can be read. QEMU puts all four in BAR4, but
    // that is an observation about QEMU and not a rule, so the BAR is taken
    // from each capability rather than assumed.
    //
    // Sizing is done once per distinct BAR. Doing it per capability would
    // reprogram the same register four times, and each reprogramming is a
    // window in which the BAR decodes somewhere else.
    let mut mapped: [Option<mmio::Region>; pci::BAR_COUNT as usize] = [None; _];
    let mut region_for = |bar: u8| -> Option<mmio::Region> {
        let slot = mapped.get_mut(bar as usize)?;
        if let Some(region) = *slot {
            return Some(region);
        }
        // SAFETY: nothing has mapped or accessed this BAR yet -- this is the
        // code that is about to do so -- and no other agent in this guest
        // touches PCI.
        let (base, size) = unsafe { device.header.size_memory_bar(bar) }?;
        log::info!("virtio     {address}   bar{bar} pa {base:#014X} size {size:#X}");
        let region = mmio::Region::map(base, size);
        log::info!(
            "virtio     {address}   bar{bar} mapped at va {:#018X} (uncacheable)",
            region.va()
        );
        *slot = Some(region);
        Some(region)
    };

    // Each structure is narrowed to the sub-range its capability describes,
    // so an offset mistake is caught by the region's own bounds check rather
    // than landing in a neighbouring structure in the same BAR.
    let mut structure = |cfg_type: CfgType| -> Option<mmio::Region> {
        let cap = device.cap(cfg_type)?;
        let bar = region_for(cap.bar)?;
        Some(mmio::Region::sub(
            bar,
            u64::from(cap.offset),
            u64::from(cap.length),
        ))
    };

    let common = structure(CfgType::Common)?;
    let notify_cap = *device.cap(CfgType::Notify)?;
    let notify = structure(CfgType::Notify)?;
    let isr = structure(CfgType::Isr)?;
    let device_cfg = structure(CfgType::Device);

    // Without this the memory BARs decode nothing and every read below would
    // return all-ones. QEMU boots this guest with `-kernel` and no firmware,
    // so nothing has enabled the decoders on our behalf.
    let command = pci::read_u16(address, pci::offset::COMMAND);
    // SAFETY: enabling memory-space decoding on a device whose BARs QEMU has
    // already assigned, and bus mastering so its virtqueue DMA works. Neither
    // moves anything; the BARs were restored by `size_memory_bar`.
    unsafe {
        pci::write_u16(
            address,
            pci::offset::COMMAND,
            command | pci::COMMAND_MEMORY_SPACE | pci::COMMAND_BUS_MASTER,
        );
    }
    log::info!(
        "virtio     {address}   command {command:#06X} -> {:#06X} (memory space, bus master)",
        pci::read_u16(address, pci::offset::COMMAND),
    );

    let notify_off_multiplier = notify_cap.notify_off_multiplier.unwrap_or_else(|| {
        // Reaching here means the notify capability declared itself too short
        // to have the field, which `log_virtio_devices` already warned about.
        // Queue notification addresses would be unknowable, so refuse rather
        // than pick a number.
        panic!("virtio {address}: notify capability has no notify_off_multiplier")
    });

    Some(Transport {
        header: device.header,
        common,
        notify,
        isr,
        device_cfg,
        notify_off_multiplier,
    })
}

/// Maps the first modern virtio device and reads back enough of its common
/// configuration to prove the mapping and the capability offsets are both
/// right.
///
/// This is the evidence step, not a driver: all-ones would mean the BAR is not
/// decoding, all-zeroes that the offsets are wrong, and either is far cheaper
/// to diagnose here than three layers into queue setup.
pub fn probe() -> Option<Transport> {
    let transport = map_transport()?;
    let address = transport.header.address;

    let features = transport.device_features();
    log::info!(
        "virtio     {address}   device_feature[0] {:#010X} [1] {:#010X} (= {features:#018X})",
        features & 0xFFFF_FFFF,
        features >> 32,
    );
    log::info!(
        "virtio     {address}   num_queues {} device_status {:#04X}",
        transport.num_queues(),
        transport.device_status(),
    );

    // The rest of the mapped structures, reported rather than used: their
    // addresses are the other half of the evidence that the capability
    // offsets were parsed correctly, and the notify multiplier is what makes
    // a queue's notification address computable at all.
    log::info!(
        "virtio     {address}   notify va {:#018X} multiplier {} isr va {:#018X}{}",
        transport.notify.va(),
        transport.notify_off_multiplier,
        transport.isr.va(),
        DeviceCfgVa(transport.device_cfg),
    );

    assert_ne!(
        features,
        u64::MAX,
        "virtio {address}: device_feature reads all-ones; the BAR is not decoding"
    );
    assert_ne!(
        features, 0,
        "virtio {address}: device_feature reads zero; the mapping or the capability offsets are wrong"
    );
    assert!(
        features & VIRTIO_F_VERSION_1 != 0,
        "virtio {address}: VIRTIO_F_VERSION_1 is not offered ({features:#018X}); \
         this is not a modern device"
    );
    log::info!("virtio     {address}   VIRTIO_F_VERSION_1 offered; mapping confirmed");

    Some(transport)
}

/// Renders the device-specific configuration structure's address, or says
/// there is none.
///
/// A newtype for the same reason [`NotifyMultiplier`] is one: an optional
/// trailing fragment cannot be built inline without an allocator.
struct DeviceCfgVa(Option<mmio::Region>);

impl core::fmt::Display for DeviceCfgVa {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            Some(region) => write!(f, " device-cfg va {:#018X}", region.va()),
            None => f.write_str(" (no device-specific configuration)"),
        }
    }
}

// ---------------------------------------------------------------------------
// Device initialisation.
// ---------------------------------------------------------------------------

/// `VIRTIO_CONSOLE_F_MULTIPORT` (feature bit 1): the device is a multiport
/// console controller, with a control queue pair and two queues per port.
///
/// Deliberately *not* negotiated. See [`bring_up`] for what was measured.
pub const VIRTIO_CONSOLE_F_MULTIPORT: u64 = 1 << 1;

/// The queue carrying bytes from the device to the driver, with
/// `F_MULTIPORT` declined.
pub const QUEUE_RECEIVE: u16 = 0;
/// The queue carrying bytes from the driver to the device.
pub const QUEUE_TRANSMIT: u16 = 1;

/// Why a bring-up attempt stopped.
///
/// Every variant carries the values that produced it. A bring-up failure with
/// no numbers in it is nearly impossible to act on: the difference between "the
/// device rejected the features" and "the mapping is wrong" is entirely in what
/// the registers read back as.
#[derive(Clone, Copy)]
pub enum Error {
    /// `device_status` did not return to zero after a reset was requested.
    ResetTimedOut { status: u8 },
    /// The device does not offer `VIRTIO_F_VERSION_1`.
    NotModern { device_features: u64 },
    /// The device cleared `FEATURES_OK`, rejecting what the driver accepted.
    FeaturesRejected { accepted: u64, status: u8 },
    /// The device implements fewer queues than the driver needs.
    TooFewQueues { num_queues: u16, needed: u16 },
    /// A queue reported a size of zero, i.e. it does not exist.
    QueueUnavailable { queue: u16 },
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::ResetTimedOut { status } => {
                write!(f, "reset timed out, device_status is still {status:#04X}")
            }
            Self::NotModern { device_features } => write!(
                f,
                "VIRTIO_F_VERSION_1 is not offered (features {device_features:#018X})"
            ),
            Self::FeaturesRejected { accepted, status } => write!(
                f,
                "device rejected features {accepted:#018X}; device_status read back {status:#04X} \
                 with FEATURES_OK clear"
            ),
            Self::TooFewQueues { num_queues, needed } => write!(
                f,
                "device implements {num_queues} queues, {needed} are needed"
            ),
            Self::QueueUnavailable { queue } => {
                write!(f, "queue {queue} reports size zero")
            }
        }
    }
}

impl Transport {
    /// Sets `device_status` to `value`.
    fn set_status(&self, value: u8) {
        // SAFETY: `device_status` is the register the driver drives the
        // initialisation handshake with; writing it is the entire mechanism.
        unsafe { self.common.write_u8(common::DEVICE_STATUS, value) }
    }

    /// Adds `bits` to `device_status`.
    ///
    /// Read-modify-write rather than a bare store because the specification
    /// requires the bits to accumulate: the device sees the whole progression,
    /// and clearing an earlier bit would tell it the driver had gone backwards.
    fn add_status(&self, bits: u8) {
        let status = self.device_status();
        self.set_status(status | bits);
    }

    /// Writes the 64 bits of features the driver accepts.
    fn set_driver_features(&self, features: u64) {
        for word in 0..2_u32 {
            // SAFETY: a selector followed by the word it selects. Neither has
            // an effect until `FEATURES_OK` is set.
            unsafe {
                self.common.write_u32(common::DRIVER_FEATURE_SELECT, word);
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "the shift-and-truncate is the register's 32-bit window on a 64-bit value"
                )]
                self.common
                    .write_u32(common::DRIVER_FEATURE, (features >> (word * 32)) as u32);
            }
        }
    }

    /// Resets the device and waits for it to say so.
    ///
    /// The specification is explicit that writing zero is a *request*, and
    /// that the driver must read the register back until it returns zero. The
    /// wait is bounded so that a device that never resets is a reported error
    /// rather than a hang with no output -- which, with no interrupts and no
    /// watchdog, is indistinguishable from any other hang.
    fn reset(&self) -> Result<(), Error> {
        self.set_status(0);
        for _ in 0..RESET_POLL_LIMIT {
            let status = self.device_status();
            if status == 0 {
                return Ok(());
            }
        }
        Err(Error::ResetTimedOut {
            status: self.device_status(),
        })
    }

    /// Selects `queue` and returns its maximum size, or `None` if the device
    /// does not implement it.
    fn queue_size(&self, queue: u16) -> Option<u16> {
        // SAFETY: `queue_select` only chooses which queue the neighbouring
        // registers refer to.
        unsafe { self.common.write_u16(common::QUEUE_SELECT, queue) };
        match self.common.read_u16(common::QUEUE_SIZE) {
            0 => None,
            size => Some(size),
        }
    }

    /// Registers `queue` with the device and enables it.
    ///
    /// The queue must already be selected -- which [`Self::queue_size`] does,
    /// and which is why the two are always called in that order.
    fn configure_queue(&self, queue: &mut queue::Queue) {
        // SAFETY: these registers take the physical addresses of the three
        // rings, which is what `Queue` allocated and recorded. The queue is
        // fully initialised -- descriptors threaded, rings zeroed -- before
        // `queue_enable` makes the device look at any of it, which is the
        // ordering that matters.
        unsafe {
            self.common.write_u16(common::QUEUE_SELECT, queue.index());
            self.common.write_u16(common::QUEUE_SIZE, queue.size());
            self.common.write_u64(common::QUEUE_DESC, queue.desc_pa());
            self.common
                .write_u64(common::QUEUE_DRIVER, queue.driver_pa());
            self.common
                .write_u64(common::QUEUE_DEVICE, queue.device_pa());
        }
        queue.set_notify_off(self.common.read_u16(common::QUEUE_NOTIFY_OFF));
        // SAFETY: everything the device will read is now in place.
        unsafe { self.common.write_u16(common::QUEUE_ENABLE, 1) };
    }

    /// Tells the device to look at `queue`'s available ring.
    ///
    /// The address is `notify_off * notify_off_multiplier` into the
    /// notification structure, and the value written is the queue's index.
    /// With `notify_off_multiplier` zero every queue would share one address
    /// and the value would be the only thing distinguishing them; QEMU reports
    /// 4, so each queue has its own dword and the write is really a doorbell
    /// per queue.
    pub fn notify(&self, queue: &queue::Queue) {
        let offset = u64::from(queue.notify_off()) * u64::from(self.notify_off_multiplier);
        // SAFETY: `Region` bounds-checks the offset against the notification
        // structure's declared length. The write is a doorbell: its only
        // effect is to make the device scan the queue named by the value.
        unsafe { self.notify.write_u16(offset, queue.index()) };
    }
}

/// How many times [`Transport::reset`] reads `device_status` before giving up.
///
/// QEMU resets synchronously, so the first read is expected to return zero.
/// The bound exists for the case where it does not.
const RESET_POLL_LIMIT: u32 = 1_000_000;

/// A device that has completed the initialisation handshake, with its receive
/// and transmit queues live.
pub struct Console {
    pub transport: Transport,
    pub receive: queue::Queue,
    pub transmit: queue::Queue,
    /// The features actually negotiated.
    pub features: u64,
}

/// Runs the virtio 1.0 initialisation handshake and sets up the console's two
/// queues.
///
/// # Which queues, and why `F_MULTIPORT` is declined
///
/// `virtio-serial-pci` is the multiport console controller, and QEMU offers it
/// with 31 ports, hence the 64 queues `num_queues` reports. With
/// `VIRTIO_CONSOLE_F_MULTIPORT` negotiated the driver would owe the device a
/// control-queue conversation -- `DEVICE_READY`, then a `PORT_OPEN` for each
/// port the device announces -- before the device will move a byte, and the
/// port a `virtconsole` lands on is not fixed.
///
/// Declining the feature avoids all of it. The device then presents as a plain
/// single-port console: queue 0 is receive, queue 1 is transmit, and QEMU's
/// `virtio-serial` treats port 0 -- which is reserved for `virtconsole` and is
/// where a lone one lands -- as that single port. It is opened implicitly,
/// with no control traffic at all. This was checked rather than assumed; see
/// the commit message for the measured result.
///
/// The queues past 1 still exist and are simply left disabled.
///
/// # Errors
///
/// Returns [`Error`] with the register values that produced it, and leaves
/// `FAILED` set in `device_status` so the device knows the driver gave up.
pub fn bring_up(transport: Transport) -> Result<Console, Error> {
    let address = transport.header.address;

    // 1. Reset, and wait for it.
    transport.reset()?;
    log::info!(
        "virtio     {address}   reset; device_status {:#04X}",
        transport.device_status()
    );

    // 2 and 3. Acknowledge the device, then claim to know how to drive it.
    transport.add_status(status::ACKNOWLEDGE);
    transport.add_status(status::DRIVER);

    // 4. Negotiate. As little as possible: VIRTIO_F_VERSION_1 is the only
    //    feature this driver needs and the only one it understands. Every
    //    other bit QEMU offers -- MULTIPORT, EMERG_WRITE, INDIRECT_DESC,
    //    EVENT_IDX, RING_RESET -- is declined, because accepting a feature
    //    means implementing it, and each of those changes either the ring
    //    layout or the protocol.
    let device_features = transport.device_features();
    if device_features & VIRTIO_F_VERSION_1 == 0 {
        transport.set_status(status::FAILED);
        return Err(Error::NotModern { device_features });
    }
    let accepted = device_features & VIRTIO_F_VERSION_1;
    transport.set_driver_features(accepted);
    log::info!(
        "virtio     {address}   features offered {device_features:#018X}, accepted {accepted:#018X} \
         (VIRTIO_F_VERSION_1 only; MULTIPORT {})",
        if device_features & VIRTIO_CONSOLE_F_MULTIPORT == 0 {
            "not offered"
        } else {
            "offered and declined"
        }
    );

    // 5. FEATURES_OK, then read it back. This is the device's one chance to
    //    veto, and skipping the read-back turns a rejected feature set into a
    //    device that silently never does anything.
    transport.add_status(status::FEATURES_OK);
    let status = transport.device_status();
    if status & status::FEATURES_OK == 0 {
        transport.set_status(status::FAILED);
        return Err(Error::FeaturesRejected { accepted, status });
    }
    log::info!("virtio     {address}   FEATURES_OK stuck; device_status {status:#04X}");

    // 6. The queues.
    let num_queues = transport.num_queues();
    if num_queues <= QUEUE_TRANSMIT {
        transport.set_status(status::FAILED);
        return Err(Error::TooFewQueues {
            num_queues,
            needed: QUEUE_TRANSMIT + 1,
        });
    }

    let mut queues = [QUEUE_RECEIVE, QUEUE_TRANSMIT].map(|index| {
        transport.queue_size(index).map(|max_size| {
            // The device's maximum is used as-is. It is a power of two by
            // specification, and there is no reason to want a smaller ring:
            // the rings cost three pages between them at QEMU's size.
            let mut q = queue::Queue::new(index, max_size);
            transport.configure_queue(&mut q);
            log::info!(
                "virtio     {address}   queue {index} size {max_size} notify_off {} \
                 desc {:#014X} driver {:#014X} device {:#014X}",
                q.notify_off(),
                q.desc_pa(),
                q.driver_pa(),
                q.device_pa(),
            );
            q
        })
    });
    let transmit = queues[1].take().ok_or_else(|| {
        transport.set_status(status::FAILED);
        Error::QueueUnavailable {
            queue: QUEUE_TRANSMIT,
        }
    })?;
    let receive = queues[0].take().ok_or_else(|| {
        transport.set_status(status::FAILED);
        Error::QueueUnavailable {
            queue: QUEUE_RECEIVE,
        }
    })?;

    // 7. DRIVER_OK. Last, because it is the point at which the device may
    //    start reading the rings, and everything they name must already be in
    //    place.
    transport.add_status(status::DRIVER_OK);
    log::info!(
        "virtio     {address}   DRIVER_OK; device_status {:#04X}, {num_queues} queues exposed, \
         0 and 1 enabled",
        transport.device_status()
    );

    Ok(Console {
        transport,
        receive,
        transmit,
        features: accepted,
    })
}

/// How many times a completion poll reads the used ring before giving up.
///
/// The device is QEMU, which consumes a transmit buffer as soon as it is
/// notified, so the first read is usually enough. A bound rather than an
/// unbounded spin because there is no interrupt to break a wait that will
/// never end.
const USED_POLL_LIMIT: u32 = 100_000_000;

impl Console {
    /// Submits `bytes` on the transmit queue and waits for the device to hand
    /// the descriptor back.
    ///
    /// Returns `false` if the completion never arrived.
    ///
    /// # Panics
    ///
    /// Panics if the transmit queue has no free descriptor, which with a
    /// synchronous single-buffer caller cannot happen.
    pub fn send_blocking(&mut self, buffer: &queue::Dma, len: u32) -> bool {
        // SAFETY: the buffer outlives the call -- it is borrowed for the whole
        // of it, and the call does not return until the device has handed the
        // descriptor back -- and it is submitted device-readable, so the
        // device only reads it while this function refrains from writing it.
        let head = unsafe { self.transmit.submit(buffer.pa(), len, false) }
            .expect("transmit queue has no free descriptor");
        self.transport.notify(&self.transmit);

        for _ in 0..USED_POLL_LIMIT {
            if let Some((completed, written)) = self.transmit.take_used() {
                if completed == head {
                    log::info!(
                        "virtio     tx completed: used ring returned descriptor {completed}, \
                         len {written}"
                    );
                    return true;
                }
                log::warn!(
                    "virtio     tx completion is for descriptor {completed}, expected {head}"
                );
            }
            core::hint::spin_loop();
        }
        false
    }

    /// Posts a receive buffer and waits up to `timeout_nanos` for the device
    /// to fill it.
    ///
    /// Returns the number of bytes received, or `None` if the deadline passed
    /// with nothing arriving.
    ///
    /// Exactly one descriptor is posted per call and waited on. The obvious
    /// alternative -- post a buffer, poll for a while, return, and let the
    /// caller try again -- loses bytes: the abandoned descriptors stay in the
    /// available ring, the device fills the *oldest* of them, and the
    /// completion is then discarded by a caller watching for a newer head.
    /// That was observed, not reasoned about; see [`init`].
    ///
    /// The bound is a deadline rather than a spin count because a spin count
    /// is not a duration: it means whatever the surrounding loop happens to
    /// cost, which changes with every edit and differs by orders of magnitude
    /// between TCG and KVM. A wall-clock deadline is checkable against the
    /// client's own patience.
    ///
    /// # Panics
    ///
    /// Panics if the receive queue has no free descriptor.
    pub fn receive_deadline(
        &mut self,
        buffer: &mut queue::Dma,
        capacity: u32,
        timeout_nanos: u64,
    ) -> Option<u32> {
        use litebox::platform::Instant as _;
        use litebox_platform_lvbs::Instant;

        // SAFETY: as `receive_polling` -- the buffer is borrowed mutably for
        // the whole call, submitted device-writable, and not read until the
        // completion says the device has finished with it.
        let head = unsafe { self.receive.submit(buffer.pa(), capacity, true) }
            .expect("receive queue has no free descriptor");
        self.transport.notify(&self.receive);

        let start = Instant::now();
        loop {
            if let Some((completed, written)) = self.receive.take_used()
                && completed == head
            {
                return Some(written);
            }
            let elapsed = Instant::now()
                .checked_duration_since(&start)
                .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
            if elapsed >= timeout_nanos {
                return None;
            }
            core::hint::spin_loop();
        }
    }
}

/// Brings the console up, ready to carry framed messages.
///
/// Returns the live console, or `None` if there is no virtio device -- which
/// is the normal case for `scripts/run.sh`.
///
/// # No loopback proof any more
///
/// This function used to transmit a `hello from the guest` banner and then
/// post a receive buffer and poll it briefly, as Task 4's evidence that both
/// directions worked. Both had to go once the channel became real, and for
/// the same reason: the console is now a framed byte stream with an owner.
///
/// - The banner is not a frame. A client reading the socket takes its first
///   four bytes as a length prefix and gets `1702127980`, which is `"litd"`.
/// - The receive probe posts a descriptor and abandons it when nothing
///   arrives within its spin bound. The device fills the *oldest* posted
///   descriptor, so the abandoned one swallows the client's first request and
///   the completion is then discarded by a caller watching for a newer head.
///
/// Both were observed, in that order, on the first end-to-end attempt. The
/// channel working at all is strictly better evidence than either was.
///
/// # Panics
///
/// Panics if a device is present but cannot be brought up. A half-working
/// device is worth failing on: it means the driver's model of it is wrong,
/// and every later step would be built on that.
pub fn init() -> Option<Console> {
    let transport = probe()?;
    let address = transport.header.address;

    let console = match bring_up(transport) {
        Ok(console) => console,
        Err(error) => panic!("virtio {address}: bring-up failed: {error}"),
    };
    log::info!(
        "virtio     {address}   negotiated features {:#018X}",
        console.features
    );

    Some(console)
}
