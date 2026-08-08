// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The PVH memory map, and the decision about which of it becomes the heap.
//!
//! QEMU enters [`crate::_start`] with `%ebx` pointing at an `hvm_start_info`
//! structure; the entry stub squirrels that pointer away (see
//! [`crate::hvm_start_info_addr`]). From version 1 onwards that structure
//! carries a table of `hvm_memmap_table_entry`, which is the only description
//! of guest RAM we get.
//!
//! Everything here reads physical addresses through the high-canonical alias
//! (`VA = PA + KERNEL_OFFSET`) installed by the boot stub, which covers the
//! low 1 GiB and nothing else.
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

use crate::KERNEL_OFFSET;

/// `hvm_start_info.magic`: "xEn3" little-endian.
const HVM_START_MAGIC_VALUE: u32 = 0x336e_c578;

/// `hvm_memmap_table_entry.type_` for usable RAM. Mirrors the E820 encoding.
const HVM_MEMMAP_TYPE_RAM: u32 = 1;

/// The `memmap_paddr`/`memmap_entries` fields exist from version 1.
const HVM_START_INFO_MEMMAP_VERSION: u32 = 1;

/// Bytes below which memory is never accepted: the real-mode IVT, the BIOS
/// data area, the EBDA and whatever else firmware left in the first megabyte.
/// Some of it is genuinely reported as type 1 and is still not ours to use.
const LOW_MEMORY_FLOOR: u64 = 0x0010_0000;

/// One past the highest physical address the early page tables map.
///
/// The boot stub builds a single PD of 512 2 MiB leaves, so exactly the low
/// 1 GiB is addressable through the high-canonical alias. Regions are clamped
/// to this rather than the mapping being extended -- see [`Regions::add`].
pub const MAPPED_LIMIT: u64 = 1 << 30;

/// Page granularity. Region bounds are rounded inwards to this.
const PAGE_SIZE: u64 = 4096;

/// The PVH boot information structure, version 1.
///
/// Field order and offsets are fixed by the PVH boot specification
/// (`xen/include/public/arch-x86/hvm/start_info.h`); this is a wire format, so
/// it is `#[repr(C)]` and must not be reordered.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct HvmStartInfo {
    pub magic: u32,
    pub version: u32,
    pub flags: u32,
    pub nr_modules: u32,
    pub modlist_paddr: u64,
    pub cmdline_paddr: u64,
    pub rsdp_paddr: u64,
    /// Present only when `version >= 1`.
    pub memmap_paddr: u64,
    /// Present only when `version >= 1`.
    pub memmap_entries: u32,
    pub reserved: u32,
}

/// One entry of the PVH memory map.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct HvmMemmapTableEntry {
    pub addr: u64,
    pub size: u64,
    pub type_: u32,
    pub reserved: u32,
}

/// Translates a physical address into the high-canonical alias the kernel runs
/// in.
const fn pa_to_va(pa: u64) -> u64 {
    pa.wrapping_add(KERNEL_OFFSET)
}

/// Reads a `T` from physical address `pa` through the high-canonical alias.
///
/// # Panics
///
/// Panics if the object does not lie wholly within the mapped low 1 GiB.
/// Faulting instead would be a silent triple fault, since there is no IDT.
///
/// # Safety
///
/// `pa` must name a `T` that the firmware actually placed there, correctly
/// aligned. `read_unaligned` is used regardless, so only the "is it really a
/// `T`" half of that is on the caller.
unsafe fn read_phys<T>(pa: u64) -> T {
    let end = pa
        .checked_add(size_of::<T>() as u64)
        .expect("physical address overflows");
    assert!(
        end <= MAPPED_LIMIT,
        "physical read at {pa:#X}..{end:#X} is outside the mapped low 1 GiB; \
         extend the early page tables before reading it"
    );
    // SAFETY: The range was just checked to lie inside the low 1 GiB, which
    // the early page tables map read/write through `KERNEL_OFFSET`.
    // `read_unaligned` imposes no alignment requirement of its own.
    unsafe { (pa_to_va(pa) as *const T).read_unaligned() }
}

/// Reads and validates the `hvm_start_info` handed to us at boot.
///
/// # Panics
///
/// Panics if the magic does not match. A wrong pointer here would have us
/// treat arbitrary memory as a memory map and then feed the results to the
/// heap, so this must be fatal rather than best-effort.
pub fn read_start_info(pa: u64) -> HvmStartInfo {
    assert!(pa != 0, "PVH passed a null hvm_start_info pointer in %ebx");

    // SAFETY: The address comes from `%ebx` as the PVH boot protocol defines
    // it, saved by the entry stub before anything could clobber it.
    // `read_phys` bounds-checks it against the mapping, and the magic check
    // below rejects a structure that is not really one.
    let info: HvmStartInfo = unsafe { read_phys(pa) };

    assert!(
        info.magic == HVM_START_MAGIC_VALUE,
        "hvm_start_info at {:#X} has magic {:#010X}, expected {:#010X}",
        pa,
        info.magic,
        HVM_START_MAGIC_VALUE
    );
    info
}

/// Reads memory map entry `index`.
///
/// # Safety
///
/// `info` must have been validated by [`read_start_info`], `info.version` must
/// be at least [`HVM_START_INFO_MEMMAP_VERSION`], and `index` must be less
/// than `info.memmap_entries`.
unsafe fn read_memmap_entry(info: &HvmStartInfo, index: u32) -> HvmMemmapTableEntry {
    let offset = u64::from(index) * size_of::<HvmMemmapTableEntry>() as u64;
    // SAFETY: The table pointer is from a magic-validated `hvm_start_info`,
    // and the caller guarantees `index` is in range. `read_phys` bounds-checks
    // the resulting address against the mapping.
    unsafe { read_phys(info.memmap_paddr + offset) }
}

/// A half-open physical range `[start, end)`.
#[derive(Clone, Copy)]
struct Range {
    start: u64,
    end: u64,
}

/// Number of ranges that may be withheld from the heap.
///
/// Four are fixed (see [`reserved_ranges`]); the slack is there so that adding
/// one more does not require thinking about this number.
const MAX_RESERVED: usize = 8;

/// The physical ranges that must never reach the heap.
///
/// Named individually rather than merged, because the reason each one is here
/// is the interesting part and a merged list cannot be reviewed.
fn reserved_ranges(
    info: &HvmStartInfo,
    start_info_pa: u64,
) -> arrayvec::ArrayVec<Range, MAX_RESERVED> {
    let mut out = arrayvec::ArrayVec::new();

    // 1. The first megabyte: IVT, BDA, EBDA, VGA and option ROM windows.
    //    Parts of it are reported as type 1 and are still not ours.
    out.push(Range {
        start: 0,
        end: LOW_MEMORY_FLOOR,
    });

    // 2. The loaded image, and the boot scratch region behind it. The linker
    //    places `_heap_start` above both (`x86_64_kvm.ld`), so one range
    //    covers `.text`, `.data`, `.bss`, `.rela.dyn`, the early page tables,
    //    the GDT, the saved start_info pointer, and the stack this function is
    //    currently executing on. Handing any of that out would not fail
    //    cleanly.
    out.push(Range {
        start: 0,
        end: crate::heap_start_pa(),
    });

    // 3. The `hvm_start_info` structure itself. Nothing reads it after boot,
    //    but it costs one page to keep it intact and makes a post-mortem
    //    possible.
    out.push(Range {
        start: start_info_pa,
        end: start_info_pa + size_of::<HvmStartInfo>() as u64,
    });

    // 4. The memory map table. Same reasoning; also, we are iterating over it
    //    while deciding what to accept, so it must survive the walk.
    if info.version >= HVM_START_INFO_MEMMAP_VERSION {
        let bytes = u64::from(info.memmap_entries) * size_of::<HvmMemmapTableEntry>() as u64;
        out.push(Range {
            start: info.memmap_paddr,
            end: info.memmap_paddr.saturating_add(bytes),
        });
    }

    out
}

/// Accumulates accepted ranges and reports what it did with each one.
struct Regions {
    reserved: arrayvec::ArrayVec<Range, MAX_RESERVED>,
    accepted_bytes: u64,
    accepted_count: u32,
    /// Highest physical address one past the end of any *usable RAM* entry,
    /// clamped to [`MAPPED_LIMIT`].
    ///
    /// Tracked from the raw type-1 entries rather than from the accepted
    /// ranges because it describes how much physical memory the platform must
    /// map, not how much of it the heap owns. The reserved ranges -- the
    /// image, the boot scratch region, the boot structures -- sit *inside*
    /// RAM and must stay mapped even though they are withheld from the heap.
    ram_end: u64,
}

impl Regions {
    /// Offers `[start, end)` to the heap, minus every reserved range that
    /// overlaps it.
    ///
    /// The subtraction is a linear sweep over the reserved list sorted by
    /// start: carry a cursor through the candidate range and emit the gaps.
    /// The reserved ranges may overlap each other, which the `max` on the
    /// cursor handles.
    fn add(&mut self, start: u64, end: u64) {
        // Clamp to what the early page tables map. Clamping rather than
        // extending is deliberate: with `-m 512M` all RAM is below 1 GiB, so
        // nothing is lost, and the alternative -- building finer page tables
        // to cover more -- is real page-table work that belongs with the
        // memory management phase rather than being smuggled in here. If the
        // guest is ever given more than 1 GiB this will visibly drop the
        // excess rather than fault on first touch.
        let end = end.min(MAPPED_LIMIT);
        if start >= end {
            return;
        }
        self.ram_end = self.ram_end.max(end);

        let mut reserved = self.reserved.clone();
        reserved.sort_unstable_by_key(|r| r.start);

        let mut cursor = start;
        for r in &reserved {
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

        // SAFETY: `[start, end)` is type-1 RAM per the PVH memory map, page
        // aligned, below `MAPPED_LIMIT` and therefore mapped read/write
        // through `KERNEL_OFFSET`, and disjoint from every range in
        // `reserved` -- which covers the image, the boot scratch region
        // (page tables, GDT and the live stack), the first megabyte, and the
        // boot structures. Nothing else has been handed this memory: this is
        // the only caller of `heap_add_region` and each range is emitted once.
        unsafe {
            litebox_platform_lvbs::host::kvm_impl::heap_add_region(
                usize::try_from(pa_to_va(start)).expect("64-bit target"),
                usize::try_from(size).expect("64-bit target"),
            );
        }
    }
}

/// What [`init_heap_from_pvh`] learned about guest RAM.
#[derive(Clone, Copy)]
pub struct RamInfo {
    /// Total bytes handed to the heap.
    pub usable_bytes: u64,
    /// One past the highest usable-RAM physical address, clamped to
    /// [`MAPPED_LIMIT`].
    ///
    /// This is the upper bound of the physical range the platform owns, and
    /// is what the runner passes to `Platform::new` as `phys_end`.
    pub ram_end_pa: u64,
}

/// Parses the PVH memory map and gives every usable region to the heap.
///
/// # Panics
///
/// Panics if the `hvm_start_info` magic is wrong, or if no usable memory is
/// found at all -- the latter because continuing would only defer the failure
/// to the first allocation, where the cause would be much less obvious.
pub fn init_heap_from_pvh(start_info_pa: u64) -> RamInfo {
    let info = read_start_info(start_info_pa);

    log::info!(
        "start_info magic {:#010X} version {} flags {:#010X} nr_modules {}",
        info.magic,
        info.version,
        info.flags,
        info.nr_modules
    );
    log::info!(
        "start_info cmdline {:#X} rsdp {:#X} modlist {:#X}",
        info.cmdline_paddr,
        info.rsdp_paddr,
        info.modlist_paddr
    );

    assert!(
        info.version >= HVM_START_INFO_MEMMAP_VERSION,
        "hvm_start_info version {} predates the memory map table; there is no \
         other description of guest RAM to fall back on",
        info.version
    );
    log::info!(
        "memmap     {} entries at pa {:#X}",
        info.memmap_entries,
        info.memmap_paddr
    );

    let reserved = reserved_ranges(&info, start_info_pa);
    for r in &reserved {
        log::info!("  reserve pa {:#014X}..{:#014X}", r.start, r.end);
    }

    let mut regions = Regions {
        reserved,
        accepted_bytes: 0,
        accepted_count: 0,
        ram_end: 0,
    };

    for index in 0..info.memmap_entries {
        // SAFETY: `info` passed the magic check, its version carries a memory
        // map, and `index < info.memmap_entries`.
        let entry = unsafe { read_memmap_entry(&info, index) };
        let end = entry.addr.saturating_add(entry.size);
        log::info!(
            "  entry   pa {:#014X}..{:#014X}  type {}",
            entry.addr,
            end,
            entry.type_
        );
        if entry.type_ == HVM_MEMMAP_TYPE_RAM {
            regions.add(entry.addr, end);
        }
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
        "PVH memory map yielded no usable memory"
    );
    RamInfo {
        usable_bytes: regions.accepted_bytes,
        ram_end_pa: regions.ram_end,
    }
}
