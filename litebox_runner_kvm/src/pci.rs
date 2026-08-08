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
    /// First base address register. Six follow, at 4-byte intervals, ending
    /// one past `0x24`.
    pub const BAR0: u8 = 0x10;
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

/// The number of base address registers in a type-0 header.
pub const BAR_COUNT: u8 = 6;

/// Capability ID `0x09`: vendor-specific. Virtio puts all of its structure
/// descriptors here.
pub const CAP_ID_VENDOR_SPECIFIC: u8 = 0x09;

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

/// Writes the aligned dword containing `offset` to configuration space.
///
/// # Safety
///
/// A configuration write is not a pure operation: it can move a BAR, disable
/// a device's decoders, or reset it. The caller must know what the register
/// does and must restore anything it perturbs.
pub unsafe fn write_u32(address: Address, offset: u8, value: u32) {
    // SAFETY: as `read_u32` for the address cycle; the data write is the
    // caller's responsibility, which the function's own contract passes on.
    unsafe {
        outl(CONFIG_ADDRESS, address.config_address(offset));
        outl(CONFIG_DATA, value);
    }
}

/// Writes a 16-bit register by read-modify-writing the dword containing it.
///
/// # Safety
///
/// As [`write_u32`]. The read-modify-write also rewrites the *other* half of
/// the dword with the value just read, which is harmless for the command and
/// status pair used here but would not be for a register with write-1-to-clear
/// bits in the untouched half.
pub unsafe fn write_u16(address: Address, offset: u8, value: u16) {
    let shift = (u32::from(offset) & 2) * 8;
    let dword = read_u32(address, offset);
    let merged = (dword & !(0xFFFF << shift)) | (u32::from(value) << shift);
    // SAFETY: the caller's contract.
    unsafe { write_u32(address, offset, merged) }
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

    /// Reads base address register `index` raw, exactly as the device
    /// presents it.
    ///
    /// Deliberately *not* sized: sizing requires writing all-ones and reading
    /// back, which momentarily decodes the BAR somewhere else entirely. That
    /// belongs with the mapping work, not with discovery.
    ///
    /// # Panics
    ///
    /// Panics if `index` is not a type-0 BAR index.
    pub fn raw_bar(self, index: u8) -> u32 {
        assert!(index < BAR_COUNT, "BAR index {index} is out of range");
        read_u32(self.address, offset::BAR0 + index * 4)
    }

    /// Decodes all six BARs, pairing the two halves of any 64-bit one.
    pub fn bars(self) -> [Bar; BAR_COUNT as usize] {
        let mut bars = [Bar::Unused; BAR_COUNT as usize];
        let mut index = 0_u8;
        while index < BAR_COUNT {
            let raw = self.raw_bar(index);
            let (bar, consumed) = if raw & BAR_SPACE_IO != 0 {
                (
                    Bar::Io {
                        raw,
                        port: raw & BAR_IO_ADDR_MASK,
                    },
                    1,
                )
            } else if raw & BAR_MEM_TYPE_MASK == BAR_MEM_TYPE_64 {
                // The upper half lives in the next register, which is why
                // this loop steps by a variable amount. A 64-bit BAR in slot
                // 5 has nowhere to put its upper half and is malformed;
                // treat the missing half as zero rather than reading past the
                // end of the header.
                let high = if index + 1 < BAR_COUNT {
                    self.raw_bar(index + 1)
                } else {
                    0
                };
                (
                    Bar::Memory {
                        raw_low: raw,
                        raw_high: Some(high),
                        base: (u64::from(high) << 32) | u64::from(raw & BAR_MEM_ADDR_MASK),
                        is_64bit: true,
                        prefetchable: raw & BAR_MEM_PREFETCHABLE != 0,
                    },
                    2,
                )
            } else {
                (
                    Bar::Memory {
                        raw_low: raw,
                        raw_high: None,
                        base: u64::from(raw & BAR_MEM_ADDR_MASK),
                        is_64bit: false,
                        prefetchable: raw & BAR_MEM_PREFETCHABLE != 0,
                    },
                    1,
                )
            };
            // An all-zero BAR is one the device does not implement. Reported
            // as unused rather than as a memory BAR at address zero, which is
            // what the raw decode would otherwise claim.
            bars[index as usize] = if raw == 0 { Bar::Unused } else { bar };
            index += consumed;
        }
        bars
    }

    /// Determines the size of memory BAR `index` and returns
    /// `(base, size_in_bytes)`.
    ///
    /// The only way to learn a BAR's size is to write all-ones into it and
    /// read back: the device leaves the bits it does not decode clear, so the
    /// lowest set address bit of the result is the region's size. That means
    /// the BAR momentarily decodes at a completely different address, which is
    /// why memory decoding is disabled around the probe and the original value
    /// is written back before it is re-enabled.
    ///
    /// A 64-bit BAR is probed as a pair. Writing ones to only the low dword
    /// and restoring only the low dword would leave the upper half holding
    /// whatever the probe put there -- which is why this takes the whole BAR,
    /// not one register, as its unit.
    ///
    /// Returns `None` if `index` is not an implemented memory BAR.
    ///
    /// # Safety
    ///
    /// Reprogramming a BAR, even transiently, is only safe while nothing is
    /// accessing the region. The caller must not have mapped it yet, and no
    /// other agent in this guest may be talking to the device.
    pub unsafe fn size_memory_bar(self, index: u8) -> Option<(u64, u64)> {
        let (base, is_64bit) = match self.bars().get(index as usize)? {
            Bar::Memory { base, is_64bit, .. } => (*base, *is_64bit),
            Bar::Unused | Bar::Io { .. } => return None,
        };

        let low_offset = offset::BAR0 + index * 4;
        let high_offset = low_offset + 4;
        let saved_low = read_u32(self.address, low_offset);
        let saved_high = is_64bit.then(|| read_u32(self.address, high_offset));

        let command = read_u16(self.address, offset::COMMAND);

        // SAFETY: the caller has promised nothing is using the region. Memory
        // decoding is switched off first so that the aliased address the probe
        // creates is never live, and every register touched is written back
        // below before decoding is restored.
        let (probe_low, probe_high) = unsafe {
            write_u16(
                self.address,
                offset::COMMAND,
                command & !COMMAND_MEMORY_SPACE,
            );

            write_u32(self.address, low_offset, u32::MAX);
            if is_64bit {
                write_u32(self.address, high_offset, u32::MAX);
            }
            let probe_low = read_u32(self.address, low_offset);
            let probe_high = if is_64bit {
                read_u32(self.address, high_offset)
            } else {
                0
            };

            write_u32(self.address, low_offset, saved_low);
            if let Some(high) = saved_high {
                write_u32(self.address, high_offset, high);
            }
            write_u16(self.address, offset::COMMAND, command);

            (probe_low, probe_high)
        };

        // Mask off the low bits, which are the type field rather than address
        // bits and read back as they were written -- counting them would
        // report a size 16 bytes too small on every BAR.
        let mask = (u64::from(probe_high) << 32) | u64::from(probe_low & BAR_MEM_ADDR_MASK);
        // A BAR that decodes nothing reads back as all-zero here; `!mask + 1`
        // would be 1, which is not a plausible size. Report it as absent.
        if mask == 0 {
            return None;
        }
        Some((base, (!mask).wrapping_add(1)))
    }

    /// Iterates the capability list, calling `visit` with the offset and ID of
    /// each entry.
    ///
    /// The walk is bounded. A capability list is a linked list living in
    /// device-controlled memory, so a malformed or hostile one can contain a
    /// cycle; without a bound this would hang the guest with no output. The
    /// bound is the number of dword-aligned offsets that fit in the 192 bytes
    /// of configuration space a capability may occupy, so no well-formed list
    /// can reach it.
    pub fn for_each_capability(self, mut visit: impl FnMut(u8, u8)) {
        let Some(mut offset) = self.capabilities_ptr else {
            return;
        };
        for _ in 0..(256 - 0x40) / 4 {
            // Zero terminates the list. Offsets below 0x40 would alias the
            // standard header, which no capability may do, so treat them as
            // termination too rather than reading a header field as a
            // capability.
            if offset < 0x40 {
                return;
            }
            let id = read_u8(self.address, offset);
            let next = read_u8(self.address, offset + 1);
            visit(offset, id);
            // Capabilities must be dword aligned; a `next` that is not is
            // malformed, and following it would misread the list.
            if next & 0x3 != 0 {
                log::warn!(
                    "pci        {} capability at {offset:#04X} has misaligned next {next:#04X}",
                    self.address
                );
                return;
            }
            offset = next;
        }
        log::warn!(
            "pci        {} capability list did not terminate; walk abandoned",
            self.address
        );
    }
}

/// BAR bit 0: the region lives in I/O space rather than memory space.
pub const BAR_SPACE_IO: u32 = 1 << 0;
/// Memory BAR bits 2:1, the type field.
pub const BAR_MEM_TYPE_MASK: u32 = 0b110;
/// Memory BAR type 2: the register is the low half of a 64-bit address.
pub const BAR_MEM_TYPE_64: u32 = 0b100;
/// Memory BAR bit 3: prefetchable.
pub const BAR_MEM_PREFETCHABLE: u32 = 1 << 3;
/// Address bits of a memory BAR (31:4).
pub const BAR_MEM_ADDR_MASK: u32 = 0xFFFF_FFF0;
/// Address bits of an I/O BAR (31:2).
pub const BAR_IO_ADDR_MASK: u32 = 0xFFFF_FFFC;

/// `COMMAND` bit 1: respond to memory space cycles. A memory BAR decodes
/// nothing at all with this clear, and reads of it return all-ones.
pub const COMMAND_MEMORY_SPACE: u16 = 1 << 1;
/// `COMMAND` bit 2: the device may act as a bus master, i.e. may DMA. A
/// virtqueue is DMA, so nothing works without it.
pub const COMMAND_BUS_MASTER: u16 = 1 << 2;

/// A decoded base address register.
#[derive(Clone, Copy)]
pub enum Bar {
    /// The device does not implement this register, or it is the upper half
    /// of the 64-bit BAR in the preceding slot.
    Unused,
    /// A memory-space region.
    Memory {
        raw_low: u32,
        /// The upper dword, present only for a 64-bit BAR.
        raw_high: Option<u32>,
        base: u64,
        is_64bit: bool,
        prefetchable: bool,
    },
    /// An I/O-space region.
    Io { raw: u32, port: u32 },
}

impl core::fmt::Display for Bar {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Unused => write!(f, "unused"),
            Self::Memory {
                raw_low,
                raw_high,
                base,
                is_64bit,
                prefetchable,
            } => {
                write!(
                    f,
                    "mem {}-bit{} base {base:#014X} raw {raw_low:#010X}",
                    if is_64bit { 64 } else { 32 },
                    if prefetchable {
                        " prefetchable"
                    } else {
                        " non-prefetchable"
                    },
                )?;
                if let Some(high) = raw_high {
                    write!(f, ":{high:#010X}")?;
                }
                Ok(())
            }
            Self::Io { raw, port } => write!(f, "io  port {port:#06X} raw {raw:#010X}"),
        }
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
