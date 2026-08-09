// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Pure decoding arithmetic for PCI base address registers.
//!
//! This module is deliberately free of dependencies: it names nothing outside
//! `core`, and in particular does not touch the I/O ports that the rest of
//! [`super`] is built on. That is what makes it host-testable. The enclosing
//! crate builds only for the bare-metal `x86_64_kvm.json` target and has no
//! test harness, so the sizing arithmetic below is exercised from
//! `dev_tests/tests/kvm_pci_bar.rs`, which includes this file with `#[path]`
//! exactly as `dev_tests/tests/kvm_proto.rs` does for `proto.rs`. There is one
//! copy of the code, so the guest and the test cannot drift.

/// Address bits of a memory BAR (31:4).
///
/// Bits 3:0 are the type field rather than address bits, and read back as they
/// were written; counting them would report a size 16 bytes too small on every
/// BAR.
pub const BAR_MEM_ADDR_MASK: u32 = 0xFFFF_FFF0;

/// Computes a memory BAR's size from the values read back after writing
/// all-ones to it.
///
/// `probe_high` is meaningful only when `is_64bit`; callers pass 0 otherwise.
/// Returns `None` for a BAR that decodes nothing, which reads back as all-zero
/// in the address bits.
///
/// # Width
///
/// The complement must be taken at the BAR's *actual* width. A 32-bit BAR has
/// no upper dword, so widening its mask to 64 bits before complementing sets
/// all 32 upper bits and yields a nonsensical size:
///
/// ```text
/// 4 KiB 32-bit BAR:  mask  = 0x00000000_FFFFF000
///                    !mask = 0xFFFFFFFF_00000FFF
///                    +1    = 0xFFFFFFFF_00001000   -- want 0x1000
/// ```
///
/// So the 32-bit case complements in `u32` and widens afterwards, and only the
/// 64-bit case complements in `u64`.
pub const fn size_from_probe(probe_low: u32, probe_high: u32, is_64bit: bool) -> Option<u64> {
    if is_64bit {
        let mask = ((probe_high as u64) << 32) | (probe_low & BAR_MEM_ADDR_MASK) as u64;
        if mask == 0 {
            return None;
        }
        Some((!mask).wrapping_add(1))
    } else {
        let mask = probe_low & BAR_MEM_ADDR_MASK;
        if mask == 0 {
            return None;
        }
        Some((!mask).wrapping_add(1) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::{BAR_MEM_ADDR_MASK, size_from_probe};

    /// A 4 KiB 32-bit BAR. This is the case the 64-bit complement got wrong:
    /// it reported `0xFFFFFFFF_00001000` instead of `0x1000`.
    #[test]
    fn sizes_4kib_32bit_bar() {
        // Writing all-ones leaves the low type bits as they were -- here a
        // 32-bit non-prefetchable memory BAR, type field zero.
        assert_eq!(size_from_probe(0xFFFF_F000, 0, false), Some(0x1000));
    }

    /// The type bits are not address bits and must not be counted. A device
    /// that reports them set must still size as 4 KiB.
    #[test]
    fn ignores_type_bits_when_sizing() {
        // Bit 3 (prefetchable) and bit 0 read back set; neither is a size bit.
        assert_eq!(size_from_probe(0xFFFF_F009, 0, false), Some(0x1000));
    }

    /// A 16 KiB 64-bit BAR. The upper dword is all-ones because none of its
    /// bits participate in a region this small.
    #[test]
    fn sizes_16kib_64bit_bar() {
        assert_eq!(
            size_from_probe(0xFFFF_C000, 0xFFFF_FFFF, true),
            Some(0x4000)
        );
    }

    /// A BAR that decodes nothing reads back all-zero. `!0 + 1` would be 1,
    /// which is not a plausible size, so it is reported as absent instead.
    #[test]
    fn absent_bar_is_none() {
        assert_eq!(size_from_probe(0, 0, false), None);
        assert_eq!(size_from_probe(0, 0, true), None);
    }

    /// A 32-bit BAR whose upper dword happens to be nonzero garbage must not
    /// influence the result: there is no upper dword to read.
    #[test]
    fn ignores_high_dword_for_32bit_bar() {
        assert_eq!(
            size_from_probe(0xFFFF_F000, 0xDEAD_BEEF, false),
            Some(0x1000)
        );
    }

    /// A 4 GiB 64-bit BAR -- the smallest size that cannot be represented in
    /// 32 bits, and so the case that justifies the 64-bit path existing.
    #[test]
    fn sizes_4gib_64bit_bar() {
        assert_eq!(
            size_from_probe(0x0000_0000, 0xFFFF_FFFF, true),
            Some(0x1_0000_0000)
        );
    }

    #[test]
    fn addr_mask_covers_bits_31_through_4() {
        assert_eq!(BAR_MEM_ADDR_MASK, !0xF_u32);
    }
}
