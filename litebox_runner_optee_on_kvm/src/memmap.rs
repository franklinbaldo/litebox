// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deciding which of guest RAM becomes the heap.
//!
//! Firmware-neutral by construction: this consumes a [`BootInfo`], which the
//! active boot backend produced, and never learns how the firmware described
//! memory. PVH's `hvm_start_info`, BIOS's e820 and UEFI's `GetMemoryMap()` all
//! arrive here as the same two lists -- usable RAM, and ranges to withhold.
//!
//! What this module adds to the backend's list of withheld ranges is only what
//! is true regardless of firmware: the first megabyte of an x86 PC, and the
//! image we ourselves were linked as.
//!
//! Everything here reads physical addresses through the high-canonical alias
//! (`VA = PA + KERNEL_OFFSET`), which the backend installs and which covers
//! physical memory up to [`BootInfo::mapped_limit`].
//!
//! # Why this is the dangerous part
//!
//! Whatever this module accepts is handed to the heap, which will write free
//! list nodes into it immediately and hand it to arbitrary callers thereafter.
//! Accepting a range we are executing from, or whose page tables we are
//! walking, does not fail cleanly -- and with no IDT yet it does not fail
//! *audibly* either. So the rule here is to exclude conservatively and to
//! print everything, accepted and rejected alike, so the decision can be
//! checked from outside rather than trusted.

use crate::boot::{BootInfo, KERNEL_OFFSET, MAX_FIRMWARE_RESERVED, Range};

/// Bytes below which memory is never accepted: the real-mode IVT, the BIOS
/// data area, the EBDA and whatever else firmware left in the first megabyte.
/// Some of it is genuinely reported as usable and is still not ours to use.
///
/// Firmware-neutral: this is a fact about an x86 PC, not about who booted us,
/// and it is conservative in either direction.
const LOW_MEMORY_FLOOR: u64 = 0x0010_0000;

/// Page granularity. Region bounds are rounded inwards to this.
const PAGE_SIZE: u64 = 4096;

/// Number of ranges that may be withheld from the heap: everything the backend
/// asked for, plus the two this module adds.
const MAX_RESERVED: usize = MAX_FIRMWARE_RESERVED + 2;

/// Translates a physical address into the high-canonical alias the kernel runs
/// in.
const fn pa_to_va(pa: u64) -> u64 {
    pa.wrapping_add(KERNEL_OFFSET)
}

/// Physical address of `_heap_start`: one page past the end of everything the
/// linker script places, which is the image followed by the boot scratch
/// region.
///
/// Nothing below this is ever offered to the heap. The single bound covers
/// `.text`, `.data`, `.bss`, `.rela.dyn`, the early page tables, the GDT, the
/// saved firmware pointer and the boot stack, because the linker script puts
/// `_heap_start` above all of them.
///
/// The symbol's address is taken with a RIP-relative `lea` rather than by
/// reading a static, for the same reason [`crate::boot::apply_relocations`]
/// does: it must not depend on an absolute address. The result is the
/// high-canonical VA, so subtracting [`KERNEL_OFFSET`] recovers the PA. That
/// subtraction is exact because the image's load bias *is* `KERNEL_OFFSET` --
/// the linker script starts at `. = 0x0`, so link-time addresses are physical
/// addresses.
pub fn heap_start_pa() -> u64 {
    unsafe extern "C" {
        static _heap_start: u8;
    }

    let va: u64;
    // SAFETY: `lea` with a RIP-relative operand only computes an address into
    // a register; it reads no memory and touches no flags.
    unsafe {
        core::arch::asm!(
            "lea {}, [rip + _heap_start]",
            out(reg) va,
            options(nostack, nomem, preserves_flags)
        );
    }
    va - KERNEL_OFFSET
}

/// Accumulates accepted ranges and reports what it did with each one.
struct Regions {
    /// Ranges withheld from the heap, **sorted by `start`**. [`Regions::add`]
    /// depends on that order; it is established once at construction.
    reserved: arrayvec::ArrayVec<Range, MAX_RESERVED>,
    accepted_bytes: u64,
    accepted_count: u32,
    /// One past the highest physical address of any *usable RAM* region,
    /// clamped to `mapped_limit`.
    ///
    /// Tracked from the raw type-1 entries rather than from the accepted
    /// ranges because it describes how much physical memory the platform must
    /// map, not how much of it the heap owns. The reserved ranges -- the
    /// image, the boot scratch region, the boot structures -- sit *inside*
    /// RAM and must stay mapped even though they are withheld from the heap.
    ram_end: u64,
    /// One past the highest physical address the backend mapped; see
    /// [`BootInfo::mapped_limit`].
    mapped_limit: u64,
}

impl Regions {
    /// Offers `[start, end)` to the heap, minus every reserved range that
    /// overlaps it.
    ///
    /// The subtraction is a linear sweep over the reserved list, which is
    /// sorted by start at construction: carry a cursor through the candidate
    /// range and emit the gaps.
    /// The reserved ranges may overlap each other, which the `max` on the
    /// cursor handles.
    fn add(&mut self, start: u64, end: u64) {
        // Clamp to what the backend actually mapped. Clamping rather than
        // extending is deliberate: with `-m 512M` all RAM is below PVH's
        // 1 GiB limit, so nothing is lost, and the alternative -- building
        // finer page tables to cover more -- is real page-table work that
        // belongs with the memory management phase rather than being smuggled
        // in here. If the guest is ever given more than the backend mapped,
        // this will visibly drop the excess rather than fault on first touch.
        let end = end.min(self.mapped_limit);
        if start >= end {
            return;
        }
        self.ram_end = self.ram_end.max(end);

        // Indexed rather than iterated: `emit` takes `&mut self`, so a
        // borrow of `self.reserved` cannot be held across the loop body.
        let mut cursor = start;
        for i in 0..self.reserved.len() {
            let r = self.reserved[i];
            if r.start >= end {
                break;
            }
            if r.end <= cursor {
                continue;
            }
            if r.start > cursor {
                self.emit(cursor, r.start.min(end));
            }
            cursor = cursor.max(r.end);
            if cursor >= end {
                return;
            }
        }
        self.emit(cursor, end);
    }

    /// Rounds `[start, end)` inwards to whole pages and, if anything is left,
    /// gives it to the heap.
    fn emit(&mut self, start: u64, end: u64) {
        let start = start.next_multiple_of(PAGE_SIZE);
        let end = end - end % PAGE_SIZE;
        if start >= end {
            return;
        }
        let size = end - start;

        self.accepted_bytes += size;
        self.accepted_count += 1;
        log::info!(
            "  accept  pa {start:#014X}..{end:#014X}  {:>7} KiB  (total {} KiB)",
            size / 1024,
            self.accepted_bytes / 1024
        );

        // SAFETY: `[start, end)` is usable RAM per the firmware, page
        // aligned, below `mapped_limit` and therefore mapped read/write
        // through `KERNEL_OFFSET`, and disjoint from every range in
        // `reserved` -- which covers the first megabyte, the image and the
        // boot scratch region behind it (page tables, GDT and the live
        // stack), and every structure the backend asked to have withheld.
        // Nothing else has been handed this memory: this is the only caller
        // of `heap_add_region` and each range is emitted once.
        unsafe {
            litebox_platform_lvbs::host::kvm::heap_add_region(
                usize::try_from(pa_to_va(start)).expect("64-bit target"),
                usize::try_from(size).expect("64-bit target"),
            );
        }
    }
}

/// What [`init_heap`] learned about guest RAM.
#[derive(Clone, Copy)]
pub struct RamInfo {
    /// Total bytes handed to the heap.
    pub usable_bytes: u64,
    /// One past the highest usable-RAM physical address, clamped to
    /// `mapped_limit`.
    ///
    /// This is the upper bound of the physical range the platform owns, and
    /// is what the runner passes to `Platform::new` as `phys_end`.
    pub ram_end_pa: u64,
    /// One past the highest physical address the backend mapped, carried
    /// through from [`BootInfo::mapped_limit`] so that the runner's heap
    /// checks can bound a heap pointer without knowing which backend ran.
    pub mapped_limit: u64,
}

/// Panics unless the firmware's usable-RAM regions are mutually disjoint.
///
/// [`Regions::add`] subtracts the *reserved* list from each usable region, but
/// it treats the usable regions themselves as independent and has no memory of
/// what earlier calls emitted. Two overlapping usable entries would therefore
/// each emit the shared span, and `heap_add_region` would be handed the same
/// physical pages twice -- after which the allocator can satisfy two different
/// callers with the same address. That is precisely the failure this module's
/// header calls "the worst available bug here", and it is silent: the accepted
/// byte total would simply look larger than RAM.
///
/// QEMU's PVH map does not produce overlaps, so this is defensive. It is a
/// panic rather than a merge because an overlap means the firmware described
/// memory in a way nobody here has reasoned about, and quietly repairing it
/// would be guessing about which description is true. Consistent with the
/// module's rule of excluding conservatively and failing audibly.
///
/// O(n^2) over at most [`crate::boot::MAX_RAM_REGIONS`] entries -- nine in
/// practice -- which
/// needs no sorted copy of a list that arrives in firmware order.
///
/// # Panics
///
/// Panics naming both ranges if any two usable regions overlap.
fn assert_usable_regions_disjoint(usable: &[Range]) {
    for (i, a) in usable.iter().enumerate() {
        // Empty entries cover nothing and cannot overlap anything.
        if a.start >= a.end {
            continue;
        }
        for b in &usable[i + 1..] {
            if b.start >= b.end {
                continue;
            }
            // Half-open ranges overlap iff each starts before the other ends.
            assert!(
                a.start >= b.end || b.start >= a.end,
                "firmware reported overlapping usable RAM: \
                 pa {:#014X}..{:#014X} and pa {:#014X}..{:#014X}. \
                 Accepting both would hand the shared pages to the heap twice",
                a.start,
                a.end,
                b.start,
                b.end
            );
        }
    }
}

/// Gives every usable region the firmware reported to the heap, minus
/// everything that must be withheld.
///
/// # Panics
///
/// Panics if no usable memory is found at all -- because continuing would only
/// defer the failure to the first allocation, where the cause would be much
/// less obvious.
pub fn init_heap(info: &BootInfo) -> RamInfo {
    let mut reserved: arrayvec::ArrayVec<Range, MAX_RESERVED> = arrayvec::ArrayVec::new();

    // 1. The first megabyte: IVT, BDA, EBDA, VGA and option ROM windows.
    //    Parts of it are reported as usable and are still not ours.
    reserved.push(Range {
        start: 0,
        end: LOW_MEMORY_FLOOR,
    });

    // 2. The loaded image, and the boot scratch region behind it. The linker
    //    places `_heap_start` above both (`x86_64_kvm.ld`), so one range
    //    covers `.text`, `.data`, `.bss`, `.rela.dyn`, the early page tables,
    //    the GDT, the saved firmware pointer, and the stack this function is
    //    currently executing on. Handing any of that out would not fail
    //    cleanly.
    reserved.push(Range {
        start: 0,
        end: heap_start_pa(),
    });

    // 3. Whatever the backend asked for: its own boot structures, which are
    //    firmware-specific and deliberately opaque here.
    reserved
        .try_extend_from_slice(&info.reserved)
        .expect("MAX_RESERVED is MAX_FIRMWARE_RESERVED plus the two ranges above");

    for r in &reserved {
        log::info!("  reserve pa {:#014X}..{:#014X}", r.start, r.end);
    }

    // `Regions::add` sweeps this list in address order, once per usable
    // region. The set is fixed from here on, so sort it once rather than on
    // every call. Logged above in declaration order first, because the reason
    // each range is withheld is what makes that log readable.
    reserved.sort_unstable_by_key(|r| r.start);

    let mut regions = Regions {
        reserved,
        accepted_bytes: 0,
        accepted_count: 0,
        ram_end: 0,
        mapped_limit: info.mapped_limit,
    };

    assert_usable_regions_disjoint(&info.usable);

    for r in &info.usable {
        regions.add(r.start, r.end);
    }

    log::info!(
        "heap       {} regions, {} KiB ({} MiB) usable",
        regions.accepted_count,
        regions.accepted_bytes / 1024,
        regions.accepted_bytes / (1024 * 1024)
    );
    log::info!("ram        pa {:#014X}..{:#014X}", 0, regions.ram_end);
    assert!(
        regions.accepted_bytes > 0,
        "the firmware memory map yielded no usable memory"
    );
    RamInfo {
        usable_bytes: regions.accepted_bytes,
        ram_end_pa: regions.ram_end,
        mapped_limit: info.mapped_limit,
    }
}
