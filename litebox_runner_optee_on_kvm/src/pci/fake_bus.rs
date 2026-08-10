// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A PCI host bridge, for host tests only.
//!
//! [`super`] reaches configuration space through exactly two functions, `inl`
//! and `outl` on the `0xCF8`/`0xCFC` port pair. Those are the whole of its
//! dependency on the platform, and they are the whole of what this module
//! replaces: everything else in `pci.rs` -- the address encoding, the byte-lane
//! selection, the BAR decode, the sizing probe, the capability walk -- is the
//! guest's code, running here unchanged against a device that answers.
//!
//! It answers *like hardware*, which is the point. A configuration register is
//! not a byte of RAM:
//!
//! - most bits are read-only, so a driver that writes them back has no effect
//!   and a test of such a driver would notice nothing;
//! - the write-1-to-clear bits of `STATUS` are cleared by writing a one and
//!   **left alone** by writing a zero, which is the entire subject of
//!   `cdd66696`;
//! - a BAR reads back the complement of its size in the bits it decodes, and
//!   its low type bits are read-only.
//!
//! So each dword has a writable mask and an optional write-1-to-clear mask,
//! and every dword write is recorded, because "what did the driver put on the
//! bus" is a question some of these tests ask directly.
//!
//! One function is present, at `Address::new(0, 3, 0)`; every other address
//! reads all-ones, as an unclaimed configuration cycle does.

use std::cell::RefCell;
use std::vec::Vec;

/// Configuration address port, mirroring [`super::CONFIG_ADDRESS`].
const CONFIG_ADDRESS: u16 = 0xCF8;
/// Configuration data port, mirroring [`super::CONFIG_DATA`].
const CONFIG_DATA: u16 = 0xCFC;

/// One dword of configuration space.
#[derive(Clone, Copy, Default)]
pub struct Register {
    /// What a read returns.
    pub value: u32,
    /// Bits a write may change. Everything outside it is read-only, which is
    /// what most of configuration space is.
    pub writable: u32,
    /// Bits a write of `1` *clears* and a write of `0` leaves alone.
    ///
    /// Deliberately separate from `writable`: an RW1C bit is not writable in
    /// the ordinary sense, and treating it as such is precisely the bug.
    pub rw1c: u32,
}

impl Register {
    /// A read-only register.
    pub fn ro(value: u32) -> Self {
        Self {
            value,
            writable: 0,
            rw1c: 0,
        }
    }
}

/// The 256 bytes of one function's configuration space, as 64 dwords, plus
/// what the driver has written.
pub struct Device {
    pub regs: [Register; 64],
    /// `(byte offset, value)` of every dword write, in order.
    pub writes: Vec<(u8, u32)>,
}

impl Device {
    fn read(&self, offset: u8) -> u32 {
        self.regs[usize::from(offset >> 2)].value
    }

    fn write(&mut self, offset: u8, value: u32) {
        self.writes.push((offset & 0xFC, value));
        let reg = &mut self.regs[usize::from(offset >> 2)];
        reg.value = (reg.value & !reg.writable) | (value & reg.writable);
        // A one clears; a zero has no effect. Applied after the ordinary
        // writable bits so that the two masks cannot be confused for each
        // other.
        reg.value &= !(value & reg.rw1c);
    }
}

/// The bus, and the address cycle in progress.
struct Bus {
    device: Device,
    /// The last dword written to [`CONFIG_ADDRESS`], which selects what the
    /// next data-port access reaches.
    selected: u32,
}

thread_local! {
    /// Per-test, because the tests run concurrently and each wants its own
    /// device. Reset by [`install`].
    static BUS: RefCell<Bus> = RefCell::new(Bus {
        device: Device {
            regs: [Register::default(); 64],
            writes: Vec::new(),
        },
        selected: 0,
    });
}

/// Puts `device` on the bus for the current test, discarding whatever was
/// there.
pub fn install(device: Device) {
    BUS.with_borrow_mut(|bus| {
        bus.device = device;
        bus.selected = 0;
    });
}

/// Runs `f` against the device currently on the bus.
pub fn with_device<R>(f: impl FnOnce(&mut Device) -> R) -> R {
    BUS.with_borrow_mut(|bus| f(&mut bus.device))
}

/// The dword writes the driver has performed since [`install`], as
/// `(offset, value)`.
pub fn writes() -> Vec<(u8, u32)> {
    with_device(|device| device.writes.clone())
}

/// The address of the one function this bridge presents.
pub fn present() -> super::Address {
    super::Address::new(0, 3, 0)
}

/// Decodes an address cycle into a byte offset, if it names the present
/// function.
fn selected_offset(selected: u32) -> Option<u8> {
    // Bit 31 enables the cycle; 23:16 is the bus, 15:11 the device, 10:8 the
    // function, 7:2 the register.
    if selected & (1 << 31) == 0 {
        return None;
    }
    let bus = (selected >> 16) & 0xFF;
    let device = (selected >> 11) & 0x1F;
    let function = (selected >> 8) & 0x7;
    if (bus, device, function) != (0, 3, 0) {
        return None;
    }
    Some(u8::try_from(selected & 0xFC).expect("masked to six bits"))
}

/// The `inl` [`super`] is built on.
///
/// # Safety
///
/// None required here; the signature matches the real one so that the guest's
/// call sites are unchanged.
pub unsafe fn inl(port: u16) -> u32 {
    assert_eq!(port, CONFIG_DATA, "read of an unexpected port");
    BUS.with_borrow(|bus| match selected_offset(bus.selected) {
        // An unclaimed configuration cycle: the host bridge drives all-ones.
        None => u32::MAX,
        Some(offset) => bus.device.read(offset),
    })
}

/// The `outl` [`super`] is built on.
///
/// # Safety
///
/// As [`inl`].
pub unsafe fn outl(port: u16, value: u32) {
    match port {
        CONFIG_ADDRESS => BUS.with_borrow_mut(|bus| bus.selected = value),
        CONFIG_DATA => BUS.with_borrow_mut(|bus| {
            let Some(offset) = selected_offset(bus.selected) else {
                return;
            };
            bus.device.write(offset, value);
        }),
        other => panic!("write to an unexpected port {other:#06X}"),
    }
}
