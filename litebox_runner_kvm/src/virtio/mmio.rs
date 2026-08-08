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

use litebox_platform_lvbs::mm::MemoryProvider as _;
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
fn read_cr3() -> u64 {
    let cr3: u64;
    // SAFETY: reading CR3 into a register has no side effects.
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }
    cr3
}

/// Allocates a zeroed 4 KiB frame for use as a page table, returning its
/// physical address.
///
/// # Panics
///
/// Panics if the heap cannot satisfy the request. There is no useful recovery:
/// the caller is in the middle of installing a mapping and has no way to undo
/// the levels already written.
fn allocate_table_frame() -> u64 {
    let va = Platform::mem_allocate_pages(0).expect("out of memory allocating a page table frame");
    // SAFETY: `mem_allocate_pages(0)` returns a live, exclusively owned,
    // page-aligned 4 KiB allocation in the kernel alias.
    unsafe { core::ptr::write_bytes(va, 0, usize::try_from(PAGE_SIZE).expect("64-bit target")) };
    Platform::va_to_pa(x86_64::VirtAddr::new(va as u64)).as_u64()
}

/// Reads one entry of the page-table frame at `table_pa`.
///
/// # Safety
///
/// `table_pa` must be a page-table frame inside guest RAM, and `index` must be
/// less than 512.
unsafe fn read_entry(table_pa: u64, index: u64) -> u64 {
    let va = table_pa + crate::boot::KERNEL_OFFSET + index * 8;
    // SAFETY: the caller's contract puts the address inside a real frame,
    // which the RAM alias maps read/write.
    unsafe { (va as *const u64).read_volatile() }
}

/// Writes one entry of the page-table frame at `table_pa`.
///
/// # Safety
///
/// As [`read_entry`], and the value must be a well-formed entry for the level:
/// installing a bad one is a page-table corruption the CPU will act on.
unsafe fn write_entry(table_pa: u64, index: u64, value: u64) {
    let va = table_pa + crate::boot::KERNEL_OFFSET + index * 8;
    // SAFETY: the caller's contract.
    unsafe { (va as *mut u64).write_volatile(value) }
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
pub fn map_device_memory(pa: u64, len: u64) -> u64 {
    let page_pa = pa & !(PAGE_SIZE - 1);
    let offset_in_page = pa - page_pa;
    let pages = (offset_in_page + len).div_ceil(PAGE_SIZE);
    let span = pages * PAGE_SIZE;

    let va_start = NEXT_VA.fetch_add(span, Ordering::SeqCst);
    assert!(
        va_start + span <= WINDOW_BASE + WINDOW_SIZE,
        "device MMIO window exhausted mapping {span:#X} bytes at pa {pa:#X}"
    );

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
        // The address was unmapped a moment ago, so any TLB entry for it is a
        // negative one -- which x86-64 does not cache. Invalidating anyway
        // costs one instruction and removes the need to have been right about
        // that.
        //
        // SAFETY: `invlpg` only discards a translation.
        unsafe {
            core::arch::asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags));
        }
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
