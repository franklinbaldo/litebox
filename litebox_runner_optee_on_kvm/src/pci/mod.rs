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

#[cfg(test)]
use fake_bus::{inl, outl};
#[cfg(not(test))]
use litebox_platform_lvbs::arch::ioport::{inl, outl};

#[cfg(test)]
mod fake_bus;

mod bar;

pub use bar::BAR_MEM_ADDR_MASK;

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

/// Writes the `COMMAND` register without disturbing `STATUS`.
///
/// `COMMAND` (0x04) and `STATUS` (0x06) share one dword, and configuration
/// cycles move whole dwords, so writing one means writing the other. The
/// obvious implementation -- read the dword, replace the low half, write it
/// back -- writes `STATUS` back with whatever bits were set in it, and half of
/// `STATUS` is write-1-to-clear: received master abort, signalled target abort,
/// detected parity error, master data parity error, signalled system error.
/// Reading a device with an error latched and then enabling its decoders would
/// silently clear that latch, so the error is gone before anything can report
/// it -- and gone at the hands of code whose stated purpose is to set two bits
/// in a different register.
///
/// Writing zero to the `STATUS` half instead is not a compromise, it is what
/// the specification says to do: a zero in a write-1-to-clear bit leaves it
/// alone, and every other `STATUS` bit is read-only. So the dword is simply
/// `value` zero-extended.
///
/// # Safety
///
/// As [`write_u32`]. `COMMAND` controls the device's decoders and its ability
/// to master the bus; the caller must know what it is turning on or off.
pub unsafe fn write_command(address: Address, value: u16) {
    // SAFETY: the caller's contract.
    unsafe { write_u32(address, offset::COMMAND, u32::from(value)) }
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
                // 5 has nowhere to put its upper half and is malformed: the
                // register after BAR5 is the Cardbus CIS pointer, not an
                // address. Treat the missing half as zero rather than reading
                // it. `size_memory_bar` refuses to probe such a BAR at all,
                // because probing would also *write* to that register.
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

        // A 64-bit BAR needs two registers, and slot 5 is the last one. The
        // register after it is 0x28, the Cardbus CIS pointer -- so probing such
        // a BAR would read the Cardbus pointer as the high dword of a size and,
        // far worse, *write* 0xFFFFFFFF into it and then write back what it
        // read. `bars()` already refuses to believe the high half of a slot-5
        // 64-bit BAR; this refuses to touch the register at all. The BAR is
        // malformed either way, and reporting it as unsizeable is the honest
        // answer.
        if is_64bit && index + 1 >= BAR_COUNT {
            log::warn!(
                "pci        {} BAR {index} claims to be 64-bit but is the last register, so \
                 its upper half would be the Cardbus CIS pointer; not sized",
                self.address
            );
            return None;
        }

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
            write_command(self.address, command & !COMMAND_MEMORY_SPACE);

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
            write_command(self.address, command);

            (probe_low, probe_high)
        };

        // The complement is taken at the BAR's own width -- see
        // [`bar::size_from_probe`]. Doing it in 64 bits for a 32-bit BAR, which
        // has no upper dword, sets all 32 upper bits and reports an absurd
        // size. A BAR that decodes nothing reads back as all-zero and is
        // reported as absent rather than as a size of 1.
        let size = bar::size_from_probe(probe_low, probe_high, is_64bit)?;
        Some((base, size))
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
            // `next` is the byte after the id. An `offset` of 0xFF has no byte
            // after it, and wrapping to 0x00 would read the vendor id as a
            // capability pointer. Configuration space is device-controlled, so
            // this is checked rather than assumed.
            let Some(next_offset) = offset.checked_add(1) else {
                log::warn!(
                    "pci        {} capability at {offset:#04X} has no room for a next pointer",
                    self.address
                );
                return;
            };
            let next = read_u8(self.address, next_offset);
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

// ---------------------------------------------------------------------------
// Tests.
//
// `dev_tests/tests/kvm_pci.rs` compiles this file for the host with
// `fake_bus` underneath it, so everything below drives the guest's own
// configuration-space code against a device that answers the way hardware
// does. See that file and `fake_bus`'s own comment.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::fake_bus::{self, Device, Register};
    use super::{
        Address, BAR_COUNT, Bar, COMMAND_BUS_MASTER, COMMAND_MEMORY_SPACE, DeviceHeader,
        STATUS_CAPABILITIES_LIST, offset, read_u8, read_u16, read_u32, write_command, write_u32,
    };
    use alloc::vec::Vec;

    /// The index of the dword containing byte `offset` of configuration
    /// space. Spelling the byte offset out is what makes these tables
    /// readable against the specification.
    fn dword(offset: usize) -> usize {
        offset / 4
    }

    /// `STATUS` write-1-to-clear bits: master data parity error (8), signalled
    /// target abort (11), received target abort (12), received master abort
    /// (13), signalled system error (14), detected parity error (15).
    const STATUS_RW1C: u16 = 0xF900;

    /// The two errors this device has latched before the driver ever touches
    /// it: detected parity error and signalled target abort. Both are RW1C,
    /// so both are destroyed by a read-modify-write of the dword they share
    /// with `COMMAND`.
    const LATCHED: u16 = 0x8000 | 0x2000;

    /// The `COMMAND` value QEMU leaves on a virtio device: I/O space, memory
    /// space disabled, and the reserved-but-set bit 8 (SERR# enable).
    const COMMAND_INITIAL: u16 = 0x0103;

    /// A virtio-console-shaped function: a 4 KiB 32-bit BAR at index 1 and a
    /// 16 KiB 64-bit BAR at index 4, which are the two the runner actually
    /// enumerates, plus a capability list.
    fn console() -> Device {
        let mut regs = [Register::default(); 64];
        let ro = Register::ro;

        regs[dword(0x00)] = ro(0x1043_1AF4); // device 0x1043, vendor 0x1AF4.
        regs[dword(0x04)] = Register {
            value: (u32::from(LATCHED | STATUS_CAPABILITIES_LIST) << 16)
                | u32::from(COMMAND_INITIAL),
            // Only `COMMAND` is writable. `STATUS`'s other bits are read-only
            // and its RW1C bits are handled separately, which is the whole
            // distinction the fix turns on.
            writable: 0x0000_FFFF,
            rw1c: u32::from(STATUS_RW1C) << 16,
        };
        regs[dword(0x08)] = ro(0x0780_0001); // class 07, subclass 80, rev 1.
        regs[dword(0x0C)] = ro(0x0000_0000); // header type 0, single function.

        // BAR1: 4 KiB, 32-bit, non-prefetchable, at 0xFEB0_0000.
        regs[dword(0x14)] = Register {
            value: 0xFEB0_0000,
            writable: 0xFFFF_F000,
            rw1c: 0,
        };
        // BAR4/BAR5: 16 KiB, 64-bit, at 0x0000_0000_FE00_0000. The type field
        // (bits 2:1 = 0b10) is read-only, as it is on real hardware, so the
        // probe cannot corrupt it.
        regs[dword(0x20)] = Register {
            value: 0xFE00_0004,
            writable: 0xFFFF_C000,
            rw1c: 0,
        };
        regs[dword(0x24)] = Register {
            value: 0x0000_0000,
            writable: 0xFFFF_FFFF,
            rw1c: 0,
        };
        // The Cardbus CIS pointer. Writable, so that a probe which strays into
        // it leaves evidence rather than being silently absorbed.
        regs[dword(0x28)] = Register {
            value: 0xCA5C_0DE5,
            writable: 0xFFFF_FFFF,
            rw1c: 0,
        };
        regs[dword(0x2C)] = ro(0x0003_1AF4); // subsystem.
        regs[dword(0x34)] = ro(0x0000_0040); // capabilities pointer.

        Device {
            regs,
            writes: Vec::new(),
        }
    }

    /// The same function, but with BAR4 unimplemented and BAR5 declaring
    /// itself the low half of a 64-bit BAR.
    ///
    /// BAR5 can only be 64-bit on a device whose BAR4 is not, because the
    /// register a 64-bit BAR4 claims for its upper half *is* BAR5. That is the
    /// whole malformation: BAR5's own upper half would have to be `0x28`, the
    /// Cardbus CIS pointer.
    fn console_with_64bit_bar5() -> Device {
        let mut device = console();
        device.regs[dword(0x20)] = Register::default(); // BAR4 unimplemented.
        device.regs[dword(0x24)] = Register {
            value: 0xFD00_0004,
            writable: 0xFFFF_0000,
            rw1c: 0,
        };
        device
    }

    fn header() -> DeviceHeader {
        DeviceHeader::read(fake_bus::present()).expect("the fake device is present")
    }

    // -----------------------------------------------------------------------
    // `cdd66696`: the COMMAND write must not clear STATUS.
    // -----------------------------------------------------------------------

    /// The value put on the bus, which is what the fix is about: a dword whose
    /// upper half -- `STATUS` -- is all zeros, so that every write-1-to-clear
    /// bit is written zero and therefore left alone.
    #[test]
    fn write_command_puts_zeros_in_every_write_1_to_clear_position() {
        fake_bus::install(console());
        let address = fake_bus::present();

        let command = read_u16(address, offset::COMMAND);
        assert_eq!(command, COMMAND_INITIAL);
        let before = fake_bus::writes().len();

        // SAFETY: the fake device has no decoders to disturb.
        unsafe { write_command(address, command | COMMAND_MEMORY_SPACE | COMMAND_BUS_MASTER) };

        let new: Vec<(u8, u32)> = fake_bus::writes().split_off(before);
        assert_eq!(
            new,
            [(offset::COMMAND & 0xFC, 0x0000_0107)],
            "the COMMAND write should be exactly one dword, {:#010X}, with zeros in the \
             STATUS half",
            0x0000_0107_u32
        );
        for (_, value) in &new {
            assert_eq!(
                value >> 16 & u32::from(STATUS_RW1C),
                0,
                "a write-1-to-clear STATUS bit was written as 1"
            );
        }
    }

    /// The consequence: the two errors the device had latched are still
    /// latched afterwards, and `COMMAND` did change.
    #[test]
    fn write_command_leaves_a_latched_status_bit_alone() {
        fake_bus::install(console());
        let address = fake_bus::present();
        assert_eq!(read_u16(address, offset::STATUS) & LATCHED, LATCHED);

        let command = read_u16(address, offset::COMMAND);
        // SAFETY: as above.
        unsafe { write_command(address, command | COMMAND_MEMORY_SPACE | COMMAND_BUS_MASTER) };

        assert_eq!(
            read_u16(address, offset::STATUS) & LATCHED,
            LATCHED,
            "enabling the decoders cleared an error the device had latched"
        );
        assert_eq!(
            read_u16(address, offset::COMMAND),
            COMMAND_INITIAL | COMMAND_MEMORY_SPACE | COMMAND_BUS_MASTER
        );
    }

    /// What the read-modify-write `write_u16` did, spelled out against the
    /// same device, so the regression is pinned rather than merely absent.
    /// This is not a call into the driver -- `write_u16` no longer exists --
    /// it is its two lines.
    #[test]
    fn the_read_modify_write_this_replaced_would_have_wiped_the_status() {
        fake_bus::install(console());
        let address = fake_bus::present();
        assert_eq!(read_u16(address, offset::STATUS) & LATCHED, LATCHED);

        let command =
            read_u16(address, offset::COMMAND) | COMMAND_MEMORY_SPACE | COMMAND_BUS_MASTER;
        let dword = read_u32(address, offset::COMMAND);
        let rebuilt = (dword & 0xFFFF_0000) | u32::from(command);
        // SAFETY: the fake device has no decoders to disturb.
        unsafe { write_u32(address, offset::COMMAND, rebuilt) };

        assert_eq!(
            read_u16(address, offset::STATUS) & LATCHED,
            0,
            "the device's latched errors survived a write-back of the STATUS half, so this \
             test is no longer demonstrating anything"
        );
    }

    // -----------------------------------------------------------------------
    // `cdd66696`: a 64-bit BAR in slot 5 must not be probed.
    // -----------------------------------------------------------------------

    /// Sizing must still work for the BARs the runner actually uses -- the
    /// guard is not allowed to cost that -- and must restore every register it
    /// touched, including `COMMAND`, without clearing `STATUS` on the way.
    #[test]
    fn the_bars_in_use_still_size_and_are_restored() {
        fake_bus::install(console());
        let header = header();

        // SAFETY: nothing is mapped and nothing else is talking to the fake
        // device.
        let bar1 = unsafe { header.size_memory_bar(1) };
        assert_eq!(bar1, Some((0xFEB0_0000, 0x1000)), "the 32-bit BAR");

        // SAFETY: as above.
        let bar4 = unsafe { header.size_memory_bar(4) };
        assert_eq!(bar4, Some((0xFE00_0000, 0x4000)), "the 64-bit BAR");

        assert_eq!(read_u32(header.address, offset::BAR0 + 4), 0xFEB0_0000);
        assert_eq!(read_u32(header.address, offset::BAR0 + 16), 0xFE00_0004);
        assert_eq!(read_u32(header.address, offset::BAR0 + 20), 0x0000_0000);
        assert_eq!(read_u16(header.address, offset::COMMAND), COMMAND_INITIAL);
        assert_eq!(
            read_u16(header.address, offset::STATUS) & LATCHED,
            LATCHED,
            "the two write_command calls inside the probe cleared a latched error"
        );
    }

    #[test]
    fn the_bars_decode_as_a_32_bit_one_and_a_64_bit_one() {
        fake_bus::install(console());
        let bars = header().bars();
        assert!(matches!(bars[0], Bar::Unused));
        assert!(
            matches!(
                bars[1],
                Bar::Memory {
                    base: 0xFEB0_0000,
                    is_64bit: false,
                    ..
                }
            ),
            "BAR1 decoded as {}",
            bars[1]
        );
        assert!(matches!(bars[2], Bar::Unused));
        assert!(matches!(bars[3], Bar::Unused));
        assert!(
            matches!(
                bars[4],
                Bar::Memory {
                    base: 0xFE00_0000,
                    is_64bit: true,
                    ..
                }
            ),
            "BAR4 decoded as {}",
            bars[4]
        );
        // The upper half of BAR4, not a BAR of its own.
        assert!(matches!(bars[5], Bar::Unused));
    }

    /// A 64-bit BAR in the last slot has nowhere to put its upper half. The
    /// register after it is the Cardbus CIS pointer, and probing would write
    /// `0xFFFFFFFF` into it and then write back whatever it read.
    #[test]
    fn a_64_bit_bar5_is_unsizeable_and_the_cardbus_pointer_is_never_touched() {
        fake_bus::install(console_with_64bit_bar5());
        let header = header();
        let cardbus_before = read_u32(header.address, 0x28);

        // SAFETY: nothing is mapped and nothing else is talking to the fake
        // device.
        let sized = unsafe { header.size_memory_bar(5) };
        assert_eq!(sized, None, "a malformed BAR was reported as sizeable");

        assert!(
            !fake_bus::writes().iter().any(|(o, _)| *o == 0x28),
            "the probe wrote to the Cardbus CIS pointer: {:#010X?}",
            fake_bus::writes()
        );
        assert_eq!(
            read_u32(header.address, 0x28),
            cardbus_before,
            "the Cardbus CIS pointer changed"
        );
    }

    /// The guard applies to the *last* slot, not to 64-bit BARs generally, and
    /// not to the other BARs on the same device.
    #[test]
    fn the_bar5_guard_does_not_catch_the_other_bars() {
        fake_bus::install(console_with_64bit_bar5());
        // SAFETY: nothing is mapped and nothing else is talking to the fake
        // device.
        let sized = unsafe { header().size_memory_bar(1) };
        assert_eq!(sized, Some((0xFEB0_0000, 0x1000)));
        assert!(
            !fake_bus::writes().iter().any(|(o, _)| *o == 0x28),
            "sizing BAR1 reached the Cardbus CIS pointer"
        );
    }

    // -----------------------------------------------------------------------
    // `759a187f`: `for_each_capability` reads `next` at `offset + 1`.
    // -----------------------------------------------------------------------

    /// Places a capability list, and points the header at its first entry.
    fn with_capabilities(device: &mut Device, first: u8, entries: &[(u8, u8, u8)]) {
        device.regs[dword(0x34)] = Register::ro(u32::from(first));
        for (at, id, next) in entries {
            let reg = &mut device.regs[dword(usize::from(*at))];
            let lane = u32::from(at & 3) * 8;
            reg.value &= !(0xFFFF << lane);
            reg.value |= (u32::from(*id) | (u32::from(*next) << 8)) << lane;
        }
    }

    fn walk(header: DeviceHeader) -> Vec<(u8, u8)> {
        let mut seen = Vec::new();
        header.for_each_capability(|offset, id| seen.push((offset, id)));
        seen
    }

    #[test]
    fn an_ordinary_capability_list_is_walked_in_order() {
        let mut device = console();
        with_capabilities(&mut device, 0x40, &[(0x40, 0x09, 0x50), (0x50, 0x09, 0x00)]);
        fake_bus::install(device);
        assert_eq!(walk(header()), [(0x40, 0x09), (0x50, 0x09)]);
    }

    /// A capability that declares itself at `0xFF` has no byte after it, so
    /// there is nowhere for a `next` pointer to be, and the walk ends without
    /// parsing it.
    ///
    /// The old code read `offset + 1`. In a release build that wraps to `0x00`
    /// and takes the low byte of the vendor id -- `0xF4` here -- as the next
    /// capability pointer, which is above `0x40` and so is followed into the
    /// middle of nowhere. In a debug build, which is what this project builds,
    /// it panics on the overflow instead. **Neither is what this asserts.**
    /// The assertion is that `for_each_capability` *returns*, having read
    /// nothing past the end of configuration space, which only the checked add
    /// produces: a panic fails this test, and a visit to `0xF4` fails it too.
    ///
    /// `0xFF` can only be reached through the capabilities pointer itself.
    /// A `next` of `0xFF` is not dword aligned, and that check fires first.
    #[test]
    fn a_capability_at_the_last_byte_is_not_parsed_and_does_not_wrap() {
        let mut device = console();
        // The low byte of the vendor id, which is what a wrapped read of
        // `next` would find, and which is a plausible-looking pointer.
        assert_eq!(device.regs[0].value & 0xFF, 0xF4);
        with_capabilities(&mut device, 0xFF, &[]);
        // A capability id at 0xFF, so the walk has something to read there.
        device.regs[dword(0xFC)].value =
            (device.regs[dword(0xFC)].value & 0x00FF_FFFF) | (0x09 << 24);
        // And one at 0xF4, so that following a wrapped pointer would be
        // visible rather than silent.
        device.regs[dword(0xF4)].value = 0x0000_0909;
        fake_bus::install(device);

        assert_eq!(
            walk(header()),
            [],
            "the capability at 0xFF has no next pointer, so it is refused rather than \
             parsed; a visit to 0xF4 means `offset + 1` wrapped into the standard header"
        );
    }

    /// A `next` that is not dword aligned is malformed; following it would
    /// misread the list.
    #[test]
    fn a_misaligned_next_pointer_ends_the_walk() {
        let mut device = console();
        with_capabilities(&mut device, 0x40, &[(0x40, 0x09, 0x51), (0x50, 0x09, 0x00)]);
        fake_bus::install(device);
        assert_eq!(walk(header()), [(0x40, 0x09)]);
    }

    /// A cycle is bounded rather than hanging the guest.
    #[test]
    fn a_cyclic_capability_list_terminates() {
        let mut device = console();
        with_capabilities(&mut device, 0x40, &[(0x40, 0x09, 0x50), (0x50, 0x09, 0x40)]);
        fake_bus::install(device);
        let seen = walk(header());
        assert_eq!(seen.len(), (256 - 0x40) / 4, "the walk was not bounded");
    }

    /// An offset below `0x40` would alias the standard header, so it
    /// terminates the list rather than being read as a capability.
    #[test]
    fn a_next_pointer_into_the_standard_header_ends_the_walk() {
        let mut device = console();
        with_capabilities(&mut device, 0x40, &[(0x40, 0x09, 0x04)]);
        fake_bus::install(device);
        assert_eq!(walk(header()), [(0x40, 0x09)]);
    }

    /// No capability list at all: the pointer byte is not even read, because
    /// devices are permitted to leave it as anything when `STATUS` bit 4 is
    /// clear.
    #[test]
    fn a_device_without_a_capability_list_is_not_walked() {
        let mut device = console();
        device.regs[dword(0x04)].value &= !(u32::from(STATUS_CAPABILITIES_LIST) << 16);
        device.regs[dword(0x34)] = Register::ro(0x0000_0040);
        fake_bus::install(device);
        assert!(header().capabilities_ptr.is_none());
        assert_eq!(walk(header()), []);
    }

    #[test]
    fn an_absent_function_reads_as_absent() {
        fake_bus::install(console());
        assert!(DeviceHeader::read(Address::new(0, 4, 0)).is_none());
        assert_eq!(BAR_COUNT, 6);
        assert_eq!(read_u8(fake_bus::present(), offset::REVISION_ID), 0x01);
    }
}
