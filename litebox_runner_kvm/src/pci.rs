// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! PCI configuration access over the legacy `0xCF8`/`0xCFC` port pair.
//!
//! This is deliberately the *legacy* mechanism rather than ECAM. Both reach
//! the same configuration space, but ECAM is memory-mapped, and its window on
//! q35 sits at `0xB000_0000` -- far above the 1 GiB the platform's page tables
//! cover. Using it would mean mapping a 256 MiB MMIO window before we know
//! whether there is anything worth talking to. Port I/O needs no mapping at
//! all, so discovery costs nothing; only the device's own BAR has to be mapped
//! later, and that is a single small region.
//!
//! # What is assumed
//!
//! Only bus 0 is scanned, and only function 0 of each device. QEMU's q35
//! machine puts `virtio-*-pci` devices on the root bus as single-function
//! devices, so this is sufficient for the runner's purposes. It would miss a
//! device behind a bridge, or a multi-function device's higher functions;
//! [`Address::function`] exists so that reading them is a matter of passing a
//! different address, not of changing this code.

use litebox_platform_lvbs::arch::ioport::{inl, outl};

/// Configuration address port. A dword written here selects the register that
/// the next access to [`CONFIG_DATA`] reads or writes.
const CONFIG_ADDRESS: u16 = 0xCF8;
/// Configuration data port.
const CONFIG_DATA: u16 = 0xCFC;

/// Bit 31 of [`CONFIG_ADDRESS`]: perform a configuration cycle at all.
const CONFIG_ENABLE: u32 = 1 << 31;

/// Vendor ID returned when no device is present at an address.
///
/// The host bridge drives the data port to all-ones for an unclaimed
/// configuration cycle, so this is "absent", not a real vendor.
pub const VENDOR_INVALID: u16 = 0xFFFF;

/// Red Hat, Inc. -- the vendor ID all virtio devices use.
pub const VENDOR_VIRTIO: u16 = 0x1AF4;

/// Configuration-space offsets used here.
pub mod offset {
    /// Vendor ID (u16).
    pub const VENDOR_ID: u8 = 0x00;
    /// Device ID (u16).
    pub const DEVICE_ID: u8 = 0x02;
    /// Command register (u16).
    pub const COMMAND: u8 = 0x04;
    /// Status register (u16); bit 4 reports a capability list.
    pub const STATUS: u8 = 0x06;
    /// Revision ID (u8).
    pub const REVISION_ID: u8 = 0x08;
    /// Class code, subclass and programming interface (three u8s at 0x09).
    pub const CLASS_CODE: u8 = 0x09;
    /// Header type (u8); bit 7 marks a multi-function device.
    pub const HEADER_TYPE: u8 = 0x0E;
    /// Subsystem vendor ID (u16).
    pub const SUBSYSTEM_VENDOR_ID: u8 = 0x2C;
    /// Subsystem ID (u16).
    pub const SUBSYSTEM_ID: u8 = 0x2E;
    /// Capability list pointer (u8), valid only when `STATUS` bit 4 is set.
    pub const CAPABILITIES_PTR: u8 = 0x34;
}

/// `STATUS` bit 4: the device implements a capability list.
pub const STATUS_CAPABILITIES_LIST: u16 = 1 << 4;

/// `HEADER_TYPE` bit 7: the device is multi-function.
pub const HEADER_TYPE_MULTIFUNCTION: u8 = 0x80;

/// A bus/device/function triple identifying one PCI function.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Address {
    bus: u8,
    device: u8,
    function: u8,
}

impl Address {
    /// Builds an address.
    ///
    /// # Panics
    ///
    /// Panics if `device` is not in `0..32` or `function` is not in `0..8`,
    /// since either would silently alias a different device once truncated
    /// into the address word.
    pub fn new(bus: u8, device: u8, function: u8) -> Self {
        assert!(device < 32, "PCI device number {device} is out of range");
        assert!(
            function < 8,
            "PCI function number {function} is out of range"
        );
        Self {
            bus,
            device,
            function,
        }
    }

    /// The dword written to [`CONFIG_ADDRESS`] to select `offset`.
    ///
    /// ```text
    ///   31       30..24    23..16   15..11   10..8      7..2       1..0
    ///   enable   reserved  bus      device   function   register   00
    /// ```
    ///
    /// The low two bits are always zero: the hardware transfers a whole
    /// aligned dword, and sub-dword accesses are made by selecting a byte lane
    /// out of it. See [`read_u8`] and [`read_u16`].
    fn config_address(self, offset: u8) -> u32 {
        CONFIG_ENABLE
            | (u32::from(self.bus) << 16)
            | (u32::from(self.device) << 11)
            | (u32::from(self.function) << 8)
            | u32::from(offset & 0xFC)
    }
}

impl core::fmt::Display for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:02x}:{:02x}.{}", self.bus, self.device, self.function)
    }
}

/// Reads the aligned dword containing `offset` from configuration space.
pub fn read_u32(address: Address, offset: u8) -> u32 {
    // SAFETY: 0xCF8/0xCFC are the architectural PCI configuration ports. The
    // address written has bit 31 set and the low two bits clear, which is the
    // only form the host bridge accepts; the subsequent read is a pure
    // configuration read, which has no side effects on any device this runner
    // touches. Reading an absent function yields all-ones rather than
    // faulting.
    unsafe {
        outl(CONFIG_ADDRESS, address.config_address(offset));
        inl(CONFIG_DATA)
    }
}

/// Reads a 16-bit register.
///
/// Configuration cycles move a whole dword, so this selects the half the
/// offset names. Bit 1 of the offset picks the half; bit 0 is ignored, as an
/// unaligned 16-bit configuration register does not exist.
pub fn read_u16(address: Address, offset: u8) -> u16 {
    let dword = read_u32(address, offset);
    #[expect(clippy::cast_possible_truncation)]
    {
        (dword >> ((u32::from(offset) & 2) * 8)) as u16
    }
}

/// Reads an 8-bit register by selecting the appropriate byte lane.
pub fn read_u8(address: Address, offset: u8) -> u8 {
    let dword = read_u32(address, offset);
    #[expect(clippy::cast_possible_truncation)]
    {
        (dword >> ((u32::from(offset) & 3) * 8)) as u8
    }
}

/// Everything the type-0 header says about one function, gathered in one go.
///
/// Held by value because reading it costs eight configuration cycles and the
/// values do not change underneath us: nothing else in this guest touches PCI.
#[derive(Clone, Copy)]
pub struct DeviceHeader {
    pub address: Address,
    pub vendor_id: u16,
    pub device_id: u16,
    pub subsystem_vendor_id: u16,
    pub subsystem_id: u16,
    pub revision_id: u8,
    /// Base class, subclass, programming interface.
    pub class: (u8, u8, u8),
    /// Raw header type byte, multi-function bit included.
    pub header_type: u8,
    pub command: u16,
    pub status: u16,
    /// Offset of the first capability, or `None` if the device has no
    /// capability list.
    pub capabilities_ptr: Option<u8>,
}

impl DeviceHeader {
    /// Reads the header of the function at `address`, or `None` if nothing is
    /// there.
    pub fn read(address: Address) -> Option<Self> {
        let vendor_id = read_u16(address, offset::VENDOR_ID);
        if vendor_id == VENDOR_INVALID {
            return None;
        }

        let command = read_u16(address, offset::COMMAND);
        let status = read_u16(address, offset::STATUS);
        // The capability pointer is only meaningful when the status register
        // says a list exists. Devices are permitted to leave the byte as
        // whatever they like otherwise, so reading it unconditionally would
        // invent a list out of stale bits.
        let capabilities_ptr = (status & STATUS_CAPABILITIES_LIST != 0)
            .then(|| read_u8(address, offset::CAPABILITIES_PTR));

        Some(Self {
            address,
            vendor_id,
            device_id: read_u16(address, offset::DEVICE_ID),
            subsystem_vendor_id: read_u16(address, offset::SUBSYSTEM_VENDOR_ID),
            subsystem_id: read_u16(address, offset::SUBSYSTEM_ID),
            revision_id: read_u8(address, offset::REVISION_ID),
            class: (
                read_u8(address, offset::CLASS_CODE + 2),
                read_u8(address, offset::CLASS_CODE + 1),
                read_u8(address, offset::CLASS_CODE),
            ),
            header_type: read_u8(address, offset::HEADER_TYPE),
            command,
            status,
            capabilities_ptr,
        })
    }

    /// Whether bit 7 of the header type marks this as a multi-function device.
    pub fn is_multifunction(self) -> bool {
        self.header_type & HEADER_TYPE_MULTIFUNCTION != 0
    }

    /// The header layout: 0 for an endpoint, 1 for a PCI-to-PCI bridge.
    pub fn layout(self) -> u8 {
        self.header_type & 0x7F
    }
}

/// Calls `visit` for every function on bus 0 whose vendor ID is `vendor`.
///
/// Function 0 of each of the 32 device slots is probed; higher functions are
/// probed only when function 0 sets the multi-function bit, which is the
/// standard rule and costs nothing when -- as under QEMU -- no virtio device
/// uses it.
pub fn for_each_device_with_vendor(vendor: u16, mut visit: impl FnMut(&DeviceHeader)) {
    for device in 0..32 {
        let zero = Address::new(0, device, 0);
        let Some(header) = DeviceHeader::read(zero) else {
            continue;
        };
        if header.vendor_id == vendor {
            visit(&header);
        }

        if !header.is_multifunction() {
            continue;
        }
        for function in 1..8 {
            let address = Address::new(0, device, function);
            if let Some(header) = DeviceHeader::read(address)
                && header.vendor_id == vendor
            {
                visit(&header);
            }
        }
    }
}

/// Logs every virtio device on bus 0.
///
/// Pure discovery: nothing is written to configuration space and no BAR is
/// mapped. Returns the number of devices found so the caller can say something
/// useful when there are none.
pub fn log_virtio_devices() -> usize {
    let mut found = 0;
    for_each_device_with_vendor(VENDOR_VIRTIO, |header| {
        found += 1;
        let (base, sub, prog_if) = header.class;
        log::info!(
            "pci        {} vendor {:#06X} device {:#06X} subsys {:#06X}:{:#06X} rev {:#04X}",
            header.address,
            header.vendor_id,
            header.device_id,
            header.subsystem_vendor_id,
            header.subsystem_id,
            header.revision_id,
        );
        log::info!(
            "pci        {}   class {base:#04X}/{sub:#04X}/{prog_if:#04X} header {:#04X} \
             (layout {}, {}) command {:#06X} status {:#06X}",
            header.address,
            header.header_type,
            header.layout(),
            if header.is_multifunction() {
                "multi-function"
            } else {
                "single-function"
            },
            header.command,
            header.status,
        );
        match header.capabilities_ptr {
            // A capability pointer of zero terminates the list before it
            // starts, which for a virtio device means it is legacy-only.
            Some(0) | None => log::info!("pci        {}   no capability list", header.address),
            Some(ptr) => log::info!(
                "pci        {}   capability list at {ptr:#04X}",
                header.address
            ),
        }
    });

    if found == 0 {
        log::warn!("pci        no virtio devices found on bus 0");
    }
    found
}
