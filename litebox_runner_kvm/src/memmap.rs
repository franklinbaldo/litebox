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

use crate::boot::KERNEL_OFFSET;

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

/// One entry of the PVH module list, pointed at by
/// [`HvmStartInfo::modlist_paddr`].
///
/// Same wire format caveat as [`HvmStartInfo`]: fixed by the PVH boot
/// specification, so `#[repr(C)]` and not to be reordered.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct HvmModlistEntry {
    pub paddr: u64,
    pub size: u64,
    pub cmdline_paddr: u64,
    pub reserved: u64,
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
    unsafe { read_phys(info.memmap_paddr.saturating_add(offset)) }
}

/// A half-open physical range `[start, end)`.
#[derive(Clone, Copy)]
struct Range {
    start: u64,
    end: u64,
}

/// Number of ranges that may be withheld from the heap.
///
/// Four are unconditional, plus the command line, the module list, and up to
/// [`MAX_MODULES`] module images (see [`reserved_ranges`]); the slack is there
/// so that adding one more does not require thinking about this number.
const MAX_RESERVED: usize = 16;

/// Largest module count this will reason about.
///
/// Nothing we boot uses modules at all; the cap exists so that a bogus
/// `nr_modules` becomes a loud assertion rather than an overrun of
/// [`MAX_RESERVED`].
const MAX_MODULES: u32 = 8;

/// Longest command line this will scan for a terminator.
///
/// `cmdline_paddr` names a NUL-terminated string with no length field, so the
/// only way to know how much to withhold is to find the NUL. A missing one
/// must not turn into an unbounded walk over guest memory.
const MAX_CMDLINE: u64 = 4096;

/// Length in bytes of the NUL-terminated string at `pa`, including the NUL.
///
/// # Panics
///
/// Panics if no terminator appears within [`MAX_CMDLINE`] bytes: the string
/// is then not one, and guessing how much memory to withhold on its behalf is
/// exactly the kind of silent assumption this module exists to avoid.
fn cstr_len(pa: u64) -> u64 {
    for i in 0..MAX_CMDLINE {
        // SAFETY: A `u8` is valid at any address, and `read_phys` bounds
        // -checks each one against the mapped low 1 GiB before dereferencing.
        let byte: u8 = unsafe { read_phys(pa.saturating_add(i)) };
        if byte == 0 {
            return i + 1;
        }
    }
    panic!("string at {pa:#X} has no NUL in {MAX_CMDLINE} bytes; refusing to guess its extent");
}

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
        end: start_info_pa.saturating_add(size_of::<HvmStartInfo>() as u64),
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

    // 5. The kernel command line. QEMU happens to place it at 0x11C0, below
    //    `_heap_start`, so range 2 already covers it today -- but nothing in
    //    the boot protocol promises that, and the day it moves above the heap
    //    floor the heap would start writing free-list nodes over it. Withhold
    //    it explicitly, measured to its terminator rather than assumed.
    if info.cmdline_paddr != 0 {
        let len = cstr_len(info.cmdline_paddr);
        out.push(Range {
            start: info.cmdline_paddr,
            end: info.cmdline_paddr.saturating_add(len),
        });
    }

    // 6. The module list and every module image it names. QEMU's PVH loader
    //    places an `-initrd` payload in RAM and reports it as *type 1*, so
    //    without this the heap is handed the module image and writes into it
    //    immediately. `nr_modules` was previously read, logged, and then
    //    ignored, which is the whole bug.
    assert!(
        info.nr_modules <= MAX_MODULES,
        "hvm_start_info reports {} modules, more than the {} this can withhold \
         from the heap; raise MAX_MODULES and MAX_RESERVED together",
        info.nr_modules,
        MAX_MODULES
    );
    if info.nr_modules != 0 {
        assert!(
            info.modlist_paddr != 0,
            "hvm_start_info reports {} modules but a null modlist_paddr; there \
             is no way to find them and therefore no way to withhold them",
            info.nr_modules
        );

        let entry_size = size_of::<HvmModlistEntry>() as u64;
        let bytes = u64::from(info.nr_modules) * entry_size;

        // The array itself, for the same reason as the memmap table: it is
        // read during the walk that decides what the heap gets.
        out.push(Range {
            start: info.modlist_paddr,
            end: info.modlist_paddr.saturating_add(bytes),
        });

        for i in 0..info.nr_modules {
            let at = info.modlist_paddr.saturating_add(u64::from(i) * entry_size);
            // SAFETY: `at` is the `i`th element of an `nr_modules`-long array
            // of `HvmModlistEntry` named by a magic-validated
            // `hvm_start_info`, and `read_phys` bounds-checks it against the
            // mapping before dereferencing.
            let module: HvmModlistEntry = unsafe { read_phys(at) };

            log::info!(
                "module {i}  pa {:#X}..{:#X}  cmdline {:#X}",
                module.paddr,
                module.paddr.saturating_add(module.size),
                module.cmdline_paddr
            );

            out.push(Range {
                start: module.paddr,
                end: module.paddr.saturating_add(module.size),
            });
        }
    }

    out
}

/// Accumulates accepted ranges and reports what it did with each one.
struct Regions {
    /// Ranges withheld from the heap, **sorted by `start`**. [`Regions::add`]
    /// depends on that order; it is established once at construction.
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
    /// The subtraction is a linear sweep over the reserved list, which is
    /// sorted by start at construction: carry a cursor through the candidate
    /// range and emit the gaps.
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

        // SAFETY: `[start, end)` is type-1 RAM per the PVH memory map, page
        // aligned, below `MAPPED_LIMIT` and therefore mapped read/write
        // through `KERNEL_OFFSET`, and disjoint from every range in
        // `reserved` -- which covers the image, the boot scratch region
        // (page tables, GDT and the live stack), the first megabyte, the
        // boot structures, the command line, and every module image the
        // module list names. Nothing else has been handed this memory: this
        // is the only caller of `heap_add_region` and each range is emitted
        // once.
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

    // `Regions::add` sweeps this list in address order, once per memory map
    // entry. The set is fixed from here on, so sort it once rather than on
    // every call. Logged above in declaration order first, because the reason
    // each range is withheld is what makes that log readable.
    let mut reserved = reserved;
    reserved.sort_unstable_by_key(|r| r.start);

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
