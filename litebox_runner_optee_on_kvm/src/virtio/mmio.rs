// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Mapping device MMIO into the kernel address space, and accessing it.
//!
//! # Why this is not done through the platform
//!
//! `Platform::new` maps exactly one thing: the guest's RAM, once, at
//! `PA + KERNEL_OFFSET`. Its mapping entry points (`map_phys_frame_range` and
//! friends) are `pub(crate)` to `litebox_platform_lvbs`, and widening them
//! would change that crate's public surface -- which is shared with the LVBS
//! runner and gated on byte-for-byte. A device BAR is a runner concern, so the
//! handful of page-table entries it needs are installed here instead, directly
//! into the page table the platform has already loaded.
//!
//! # Why a separate virtual window
//!
//! The obvious address for a BAR at PA `0xFE00_0000` would be
//! `0xFE00_0000 + KERNEL_OFFSET`, matching the RAM alias. That is a trap. The
//! platform's alias is a *statement about RAM*: `Platform::va_to_pa` subtracts
//! `KERNEL_OFFSET` from any address in it, `walk`-based checks assert that
//! anything in it is backed by RAM, and future code that reclaims or refills
//! heap pages reasons about that window as a whole. Putting device registers
//! inside it makes an MMIO address indistinguishable from a RAM address.
//!
//! So MMIO gets its own PML4 slot. [`WINDOW_BASE`] is the base of PML4 entry
//! 454; the RAM alias starts at entry 452 and, at 512 GiB per entry, cannot
//! reach 454 for any guest this runner will ever see. The two windows
//! therefore cannot overlap by construction rather than by arithmetic.

use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(not(test))]
use litebox_platform_lvbs::mm::MemoryProvider as _;
#[cfg(not(test))]
use litebox_platform_multiplex::Platform;

/// Base of the device-MMIO virtual window: the first address covered by PML4
/// entry 454.
///
/// See the module comment for why this is not the `KERNEL_OFFSET` alias.
pub const WINDOW_BASE: u64 = 0xFFFF_E300_0000_0000;

/// Size of the window. One PML4 entry is 512 GiB; this bound is far smaller
/// and exists only so a runaway mapping request is rejected rather than
/// silently spilling into the next entry.
const WINDOW_SIZE: u64 = 1 << 30;

/// Next free virtual address in the window.
static NEXT_VA: AtomicU64 = AtomicU64::new(WINDOW_BASE);

const PAGE_SIZE: u64 = 4096;

/// Page-table entry bits.
const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITABLE: u64 = 1 << 1;
/// Page-level write-through.
const PTE_PWT: u64 = 1 << 3;
/// Page-level cache disable.
const PTE_PCD: u64 = 1 << 4;
const PTE_NO_EXECUTE: u64 = 1 << 63;
/// Physical-address field of an entry (bits 51:12).
const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Reads CR3.
#[cfg(not(test))]
fn read_cr3() -> u64 {
    let cr3: u64;
    // SAFETY: reading CR3 into a register has no side effects.
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }
    cr3
}

/// There is no CR3 on the host, and no test reaches this.
///
/// The three functions below are the whole of what the page-table walk needs
/// from the machine, and the walk itself is not hosted: it edits the page
/// tables the CPU is *currently using*, which cannot be modelled and cannot be
/// faked, and which the QEMU boot test exercises on every run. What is hosted
/// is everything that happens before the walk -- the span arithmetic and the
/// window bound -- which is what `759a187f` is about, and which rejects the
/// request without ever getting here.
#[cfg(test)]
fn read_cr3() -> u64 {
    unreachable!("the page-table walk is not hosted; see this function's documentation")
}

/// Allocates a zeroed 4 KiB frame for use as a page table, returning its
/// physical address.
///
/// # Panics
///
/// Panics if the heap cannot satisfy the request. There is no useful recovery:
/// the caller is in the middle of installing a mapping and has no way to undo
/// the levels already written.
#[cfg(not(test))]
fn allocate_table_frame() -> u64 {
    let va = Platform::mem_allocate_pages(0).expect("out of memory allocating a page table frame");
    // SAFETY: `mem_allocate_pages(0)` returns a live, exclusively owned,
    // page-aligned 4 KiB allocation in the kernel alias.
    unsafe { core::ptr::write_bytes(va, 0, usize::try_from(PAGE_SIZE).expect("64-bit target")) };
    Platform::va_to_pa(x86_64::VirtAddr::new(va as u64)).as_u64()
}

/// Not hosted; see [`read_cr3`].
#[cfg(test)]
fn allocate_table_frame() -> u64 {
    unreachable!("the page-table walk is not hosted; see `read_cr3`")
}

/// Reads one entry of the page-table frame at `table_pa`.
///
/// # Safety
///
/// `table_pa` must be a page-table frame inside guest RAM, and `index` must be
/// less than 512.
unsafe fn read_entry(table_pa: u64, index: u64) -> u64 {
    #[cfg(test)]
    {
        let _ = (table_pa, index);
        unreachable!("the page-table walk is not hosted; see `read_cr3`")
    }
    #[cfg(not(test))]
    {
        let va = table_pa + crate::boot::KERNEL_OFFSET + index * 8;
        // SAFETY: the caller's contract puts the address inside a real frame,
        // which the RAM alias maps read/write.
        unsafe { (va as *const u64).read_volatile() }
    }
}

/// Writes one entry of the page-table frame at `table_pa`.
///
/// # Safety
///
/// As [`read_entry`], and the value must be a well-formed entry for the level:
/// installing a bad one is a page-table corruption the CPU will act on.
unsafe fn write_entry(table_pa: u64, index: u64, value: u64) {
    #[cfg(test)]
    {
        let _ = (table_pa, index, value);
        unreachable!("the page-table walk is not hosted; see `read_cr3`")
    }
    #[cfg(not(test))]
    {
        let va = table_pa + crate::boot::KERNEL_OFFSET + index * 8;
        // SAFETY: the caller's contract.
        unsafe { (va as *mut u64).write_volatile(value) }
    }
}

/// Discards any translation cached for `va`.
///
/// The address was unmapped a moment ago, so any TLB entry for it is a
/// negative one -- which x86-64 does not cache. Invalidating anyway costs one
/// instruction and removes the need to have been right about that.
fn flush_tlb(va: u64) {
    #[cfg(test)]
    {
        let _ = va;
        unreachable!("the page-table walk is not hosted; see `read_cr3`")
    }
    #[cfg(not(test))]
    // SAFETY: `invlpg` only discards a translation.
    unsafe {
        core::arch::asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags));
    }
}

/// Maps `len` bytes of physical memory at `pa` as uncacheable device memory,
/// returning the virtual address it now answers to.
///
/// `pa` and `len` are rounded outwards to whole pages, so a BAR that is not
/// page-aligned still gets all of its bytes.
///
/// The mapping is `PRESENT | WRITABLE | NO_EXECUTE | PCD | PWT`.
/// `PCD`/`PWT` are the load-bearing pair: with the default PAT, that
/// combination selects uncacheable. Mapping device registers write-back would
/// let the CPU satisfy a "read" from a cache line filled minutes ago and
/// coalesce or reorder writes the device is meant to see individually, which
/// presents as the device malfunctioning rather than as a mapping bug.
///
/// # Panics
///
/// Panics if the request does not fit in the window, or if a level of the walk
/// is already occupied by a huge page -- both mean the window is not the
/// exclusively owned region this assumes.
///
/// `pa` and `len` are the device's: they come from a BAR and from a virtio
/// capability's `length` field. So the span arithmetic is checked rather than
/// wrapping. A `len` near `u64::MAX` used to make `offset_in_page + len`
/// overflow to a small number, and a `span` large enough to wrap the window
/// bound made `va_start + span <= WINDOW_BASE + WINDOW_SIZE` compare two
/// wrapped values and pass. Either way a device could have had a handful of
/// pages mapped at an address the caller then treated as covering its whole
/// declared length.
pub fn map_device_memory(pa: u64, len: u64) -> u64 {
    let page_pa = pa & !(PAGE_SIZE - 1);
    let offset_in_page = pa - page_pa;
    let span = offset_in_page
        .checked_add(len)
        .map(|bytes| bytes.div_ceil(PAGE_SIZE))
        .and_then(|pages| pages.checked_mul(PAGE_SIZE))
        .unwrap_or_else(|| {
            panic!("device MMIO request of {len:#X} bytes at pa {pa:#X} does not fit in 64 bits")
        });
    assert!(
        span <= WINDOW_SIZE,
        "device MMIO request of {span:#X} bytes at pa {pa:#X} is larger than the \
         {WINDOW_SIZE:#X}-byte window"
    );

    // Reserved before the bound is checked, so a rejected request still cannot
    // hand a second caller a range that overlaps a live one. `span` is bounded
    // by `WINDOW_SIZE` above and `NEXT_VA` never exceeds
    // `WINDOW_BASE + WINDOW_SIZE` while requests are accepted, so this add
    // cannot wrap for any request that gets past the assertion below.
    let va_start = NEXT_VA.fetch_add(span, Ordering::SeqCst);
    assert!(
        va_start
            .checked_add(span)
            .is_some_and(|end| end <= WINDOW_BASE + WINDOW_SIZE),
        "device MMIO window exhausted mapping {span:#X} bytes at pa {pa:#X}"
    );
    let pages = span / PAGE_SIZE;

    let cr3 = read_cr3() & PTE_ADDR_MASK;
    for page in 0..pages {
        let va = va_start + page * PAGE_SIZE;
        let frame = page_pa + page * PAGE_SIZE;

        // Descend, creating any missing level. Intermediate entries are
        // deliberately *not* marked NO_EXECUTE: on x86-64 the NX bit of a
        // non-leaf entry applies to everything beneath it, and this window is
        // not the only thing that could ever live under these tables.
        let mut table = cr3;
        for level in (2..=4_u32).rev() {
            let index = (va >> (12 + 9 * (level - 1))) & 0x1FF;
            // SAFETY: `table` is CR3 or a physical address taken from a
            // present non-leaf entry, so it is a real frame in RAM; `index` is
            // masked into range.
            let entry = unsafe { read_entry(table, index) };
            table = if entry & PTE_PRESENT == 0 {
                let new = allocate_table_frame();
                // SAFETY: as above; the value is a well-formed non-leaf entry
                // pointing at a freshly zeroed frame.
                unsafe {
                    write_entry(table, index, new | PTE_PRESENT | PTE_WRITABLE);
                }
                new
            } else {
                assert!(
                    entry & (1 << 7) == 0,
                    "MMIO window va {va:#018X} is covered by a huge page at level {level}"
                );
                entry & PTE_ADDR_MASK
            };
        }

        let index = (va >> 12) & 0x1FF;
        // SAFETY: `table` is the level-1 frame reached above, and the value is
        // a well-formed leaf entry naming the caller's device frame.
        unsafe {
            write_entry(
                table,
                index,
                frame | PTE_PRESENT | PTE_WRITABLE | PTE_NO_EXECUTE | PTE_PCD | PTE_PWT,
            );
        }
        flush_tlb(va);
    }

    va_start + offset_in_page
}

/// A mapped device register region.
///
/// Bounds-checks every access against the length the capability declared, so
/// a wrong offset is a panic naming the region rather than a read of whatever
/// the next structure happens to be.
#[derive(Clone, Copy)]
pub struct Region {
    va: u64,
    pa: u64,
    len: u64,
}

impl Region {
    /// Maps `len` bytes at `pa`.
    pub fn map(pa: u64, len: u64) -> Self {
        Self {
            va: map_device_memory(pa, len),
            pa,
            len,
        }
    }

    /// Narrows this region to `len` bytes at `offset` within it.
    ///
    /// No new mapping is made: the sub-region is a tighter bound on the same
    /// pages. That tighter bound is the point -- a virtio structure knows its
    /// own length, and an access past the end of it should name the structure
    /// rather than silently reach the next one along in the same BAR.
    ///
    /// # Panics
    ///
    /// Panics if the sub-range is not contained in this one.
    pub fn sub(self, offset: u64, len: u64) -> Self {
        assert!(
            offset.checked_add(len).is_some_and(|end| end <= self.len),
            "sub-region of {len:#X} bytes at {offset:#X} does not fit in the \
             {:#X}-byte region at pa {:#X}",
            self.len,
            self.pa,
        );
        Self {
            va: self.va + offset,
            pa: self.pa + offset,
            len,
        }
    }

    /// The virtual address the region is mapped at.
    pub fn va(self) -> u64 {
        self.va
    }

    /// Checks that `size` bytes at `offset` lie inside the region and returns
    /// the address of the first.
    ///
    /// # Panics
    ///
    /// Panics if the access is out of bounds or misaligned. Both are driver
    /// bugs, and an unaligned MMIO access in particular may be split by the
    /// CPU into two bus transactions, which a device register is not obliged
    /// to tolerate.
    fn addr(self, offset: u64, size: u64) -> u64 {
        assert!(
            offset.checked_add(size).is_some_and(|end| end <= self.len),
            "MMIO access of {size} bytes at offset {offset:#X} is outside the \
             {:#X}-byte region at pa {:#X}",
            self.len,
            self.pa,
        );
        assert!(
            offset.is_multiple_of(size),
            "MMIO access of {size} bytes at offset {offset:#X} is misaligned"
        );
        self.va + offset
    }
}

/// Generates the volatile read for one register width.
macro_rules! read_accessor {
    ($ty:ty, $read:ident) => {
        impl Region {
            #[doc = concat!("Reads a `", stringify!($ty), "` at `offset`.")]
            ///
            /// # Panics
            ///
            /// Panics if the access is out of bounds or misaligned.
            pub fn $read(self, offset: u64) -> $ty {
                let addr = self.addr(offset, size_of::<$ty>() as u64);
                // SAFETY: `addr` bounds-checked the access into a region this
                // driver mapped read/write and uncacheable, and nothing else
                // in the guest touches it. `read_volatile` keeps the load from
                // being elided or duplicated, which for a register whose value
                // the device changes underneath us is the whole point.
                unsafe { (addr as *const $ty).read_volatile() }
            }
        }
    };
}

/// Generates the volatile write for one register width.
macro_rules! write_accessor {
    ($ty:ty, $write:ident) => {
        impl Region {
            #[doc = concat!("Writes a `", stringify!($ty), "` at `offset`.")]
            ///
            /// # Panics
            ///
            /// Panics if the access is out of bounds or misaligned.
            ///
            /// # Safety
            ///
            /// A register write is a command to the device. The caller must
            /// know what the register does.
            pub unsafe fn $write(self, offset: u64, value: $ty) {
                let addr = self.addr(offset, size_of::<$ty>() as u64);
                // SAFETY: the bounds check above puts the store inside a
                // region this driver mapped read/write and uncacheable, and
                // the caller's contract covers what the value means to the
                // device. `write_volatile` keeps it from being merged with or
                // reordered against neighbouring register accesses.
                unsafe { (addr as *mut $ty).write_volatile(value) }
            }
        }
    };
}

read_accessor!(u8, read_u8);
read_accessor!(u16, read_u16);
read_accessor!(u32, read_u32);

write_accessor!(u8, write_u8);
write_accessor!(u16, write_u16);
write_accessor!(u32, write_u32);
write_accessor!(u64, write_u64);

// ---------------------------------------------------------------------------
// Tests.
//
// `pa` and `len` here are the *device's*: a BAR base and size, or a virtio
// capability's declared `offset` and `length`. So these are about what happens
// when the device chooses absurd ones. See `dev_tests/tests/kvm_virtio_mmio.rs`
// for how this file is compiled for the host, and `read_cr3` for what is
// deliberately not hosted.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{Region, WINDOW_SIZE, map_device_memory};

    /// The BAR size from the finding. In a release build the old
    /// `(offset_in_page + len).div_ceil(PAGE_SIZE)` wrapped to a handful of
    /// pages and the caller was handed a virtual address for a region it
    /// believed was 2^64 bytes.
    ///
    /// The `expected` string matters. This project builds debug, where the old
    /// arithmetic panics on the overflow all by itself -- so a bare
    /// `should_panic` would pass against the unfixed code and prove nothing.
    /// "does not fit in 64 bits" is the explicit rejection; an overflow panic
    /// says "attempt to add with overflow" and does not match it.
    #[test]
    #[should_panic(expected = "does not fit in 64 bits")]
    fn a_bar_size_near_the_top_of_the_address_space_is_rejected() {
        map_device_memory(0xFE00_0000, 0xFFFF_FFFF_FFFF_FFF0);
    }

    #[test]
    #[should_panic(expected = "does not fit in 64 bits")]
    fn a_length_of_u64_max_is_rejected() {
        map_device_memory(0xFE00_0000, u64::MAX);
    }

    /// The page *rounding* is the other place it can wrap: the byte count
    /// itself fits, but rounding it up to whole pages does not.
    ///
    /// `0xFFFF_FFFF_FFFF_F001` is the smallest such length: everything
    /// below it rounds up to `0xFFFF_FFFF_FFFF_F000` or less, and is caught by
    /// the window bound instead -- which is the neighbouring test, and which
    /// is why both messages are asserted rather than just "it panicked".
    #[test]
    #[should_panic(expected = "does not fit in 64 bits")]
    fn a_length_whose_page_rounding_wraps_is_rejected() {
        map_device_memory(0, 0xFFFF_FFFF_FFFF_F001);
    }

    /// One byte less, and the rounding fits -- so the window bound is what
    /// catches it, with a different message. The pair is what shows the two
    /// checks are distinct and that neither is doing the other's work.
    #[test]
    #[should_panic(expected = "is larger than the")]
    fn the_largest_length_that_rounds_without_wrapping_hits_the_window_bound() {
        map_device_memory(0, 0xFFFF_FFFF_FFFF_F000);
    }

    /// The offset within the page is part of the span, so a length that only
    /// just fits on its own does not once the offset is added.
    #[test]
    #[should_panic(expected = "does not fit in 64 bits")]
    fn an_unaligned_base_pushes_a_borderline_length_over() {
        // `pa` is 16 bytes into its page, and `len` is everything above it.
        map_device_memory(0x10, u64::MAX);
    }

    /// A span that is representable but larger than the window is rejected on
    /// its own terms, *before* `NEXT_VA` is advanced by it -- which is also
    /// what makes the reservation add provably non-wrapping.
    #[test]
    #[should_panic(expected = "is larger than the")]
    fn a_span_larger_than_the_window_is_rejected() {
        map_device_memory(0xFE00_0000, WINDOW_SIZE + 1);
    }

    /// A terabyte: no arithmetic difficulty at all, simply far too much. The
    /// distinct message is the evidence that the window bound caught it rather
    /// than the overflow check.
    #[test]
    #[should_panic(expected = "is larger than the")]
    fn a_terabyte_bar_is_rejected_by_the_window_bound() {
        map_device_memory(0xFE00_0000, 1 << 40);
    }

    /// The two rejections are distinguishable, and neither reaches the walk.
    /// If either had, the stubbed `read_cr3` would panic with its own message
    /// instead, and none of the `should_panic` expectations above would match.
    #[test]
    fn the_window_is_a_gigabyte() {
        assert_eq!(WINDOW_SIZE, 1 << 30);
    }

    // -----------------------------------------------------------------------
    // `Region`'s own bounds, which are the same arithmetic one level up: a
    // capability's `offset` and `length` are device-supplied too.
    // -----------------------------------------------------------------------

    /// A region built by hand, so that `sub` can be tested without mapping
    /// anything.
    fn region(len: u64) -> Region {
        Region {
            va: 0xFFFF_E300_0000_0000,
            pa: 0xFE00_0000,
            len,
        }
    }

    #[test]
    fn a_sub_region_inside_the_region_is_allowed() {
        let sub = region(0x1000).sub(0x100, 0x200);
        assert_eq!(sub.va(), 0xFFFF_E300_0000_0100);
    }

    #[test]
    fn a_sub_region_may_reach_exactly_the_end() {
        let sub = region(0x1000).sub(0xF00, 0x100);
        assert_eq!(sub.va(), 0xFFFF_E300_0000_0F00);
    }

    #[test]
    #[should_panic(expected = "does not fit in the")]
    fn a_sub_region_past_the_end_is_rejected() {
        region(0x1000).sub(0xF00, 0x101);
    }

    /// `offset + len` wrapping is the interesting case: without the checked
    /// add, `0xFFFF_FFFF_FFFF_FF00 + 0x200` is `0x100`, which is comfortably
    /// inside a 4 KiB region, and the sub-region would be accepted.
    #[test]
    #[should_panic(expected = "does not fit in the")]
    fn a_sub_region_whose_end_wraps_is_rejected() {
        region(0x1000).sub(0xFFFF_FFFF_FFFF_FF00, 0x200);
    }

    #[test]
    #[should_panic(expected = "does not fit in the")]
    fn a_sub_region_of_u64_max_bytes_is_rejected() {
        region(0x1000).sub(0, u64::MAX);
    }
}
