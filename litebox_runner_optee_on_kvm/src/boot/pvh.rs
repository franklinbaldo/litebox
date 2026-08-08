// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The PVH boot backend.
//!
//! QEMU's `-kernel` finds the `XEN_ELFNOTE_PHYS32_ENTRY` note below in this
//! ELF and enters [`_start`] in 32-bit protected mode with paging off, A20 on,
//! a flat GDT, interrupts disabled, and `%ebx` pointing at an `hvm_start_info`
//! structure.
//!
//! This module is everything that is specific to that: the note, the fixed
//! entry address, the 32-bit stub, the early 2 MiB page tables, the 32-to-64
//! trampoline, and the parsing of `hvm_start_info` into a firmware-neutral
//! [`BootInfo`].
//!
//! None of it is universal. BIOS would need its own stub and its own e820
//! parsing; UEFI hands over 64-bit long mode with paging already enabled and
//! reports memory through `GetMemoryMap()`, so it would need no stub at all.
//! See [`super`] for the contract all three have to meet.
//!
//! Everything here that reads guest memory does so through the high-canonical
//! alias (`VA = PA + KERNEL_OFFSET`) that the stub installs, which covers the
//! low 1 GiB and nothing else -- see [`MAPPED_LIMIT`].

use core::arch::global_asm;

use super::{BootInfo, KERNEL_OFFSET, MAX_FIRMWARE_RESERVED, MAX_RAM_REGIONS, Range};

/// Physical address of [`_start`].
///
/// The linker script places `.text` at `0x200000` and `KEEP`s `.text._start`
/// as its first input section, so `_start` is guaranteed to sit exactly here.
/// The build is verified against `nm` rather than trusting this by inspection.
const PVH_ENTRY_ADDR: u32 = 0x0020_0000;

/// `XEN_ELFNOTE_PHYS32_ENTRY`: the note type QEMU looks for to select PVH.
const XEN_ELFNOTE_PHYS32_ENTRY: u32 = 18;

/// PML4 index covering [`KERNEL_OFFSET`]: `(KERNEL_OFFSET >> 39) & 0x1FF`.
///
/// This is 452, *not* 0. `KERNEL_OFFSET`'s PDPT and PD indices are both 0,
/// which is why the identity map and the high-canonical map can share a single
/// PDPT and PD: only the PML4 entry differs.
const KERNEL_PML4_INDEX: u32 = ((KERNEL_OFFSET >> 39) & 0x1FF) as u32;

/// Number of 2 MiB leaves built in the PD: 512 * 2 MiB = 1 GiB.
const PD_ENTRIES: u32 = 512;

// ---------------------------------------------------------------------------
// Early boot scratch region.
//
// The 32-bit entry stub needs the page tables, the GDT, its pseudo-descriptor
// and the boot stack at *physical* addresses it can name. It cannot name Rust
// statics: the target links `--pie`, and a 32-bit absolute relocation against
// an ordinary symbol would need a dynamic relocation that nothing in a
// freshly-entered guest applies. (`rust-lld` rejects such relocations
// outright.) 32-bit mode also has no RIP-relative addressing to fall back on.
//
// So the region lives at a fixed physical address, reserved by the linker
// script, and every reference to it is a plain immediate: no relocations, no
// load-address assumptions beyond the one PVH already forces on us.
//
// `BOOT_SCRATCH_BASE` is duplicated in `x86_64_kvm.ld`, which `ASSERT`s that
// the image does not grow into it.
// ---------------------------------------------------------------------------

/// Physical base of the early boot scratch region. Must match
/// `_boot_scratch_base` in `x86_64_kvm.ld`.
const BOOT_SCRATCH_BASE: u32 = 0x0100_0000;

/// Offset of the PML4 within the scratch region.
const OFF_PML4: u32 = 0x0000;
/// Offset of the PDPT within the scratch region.
const OFF_PDPT: u32 = 0x1000;
/// Offset of the PD within the scratch region.
const OFF_PD: u32 = 0x2000;
/// Offset of the boot GDT (three 8-byte descriptors).
const OFF_GDT: u32 = 0x3000;
/// Offset of the boot GDT pseudo-descriptor (2-byte limit + 4-byte base).
const OFF_GDTR: u32 = 0x3020;
/// Offset of the saved `hvm_start_info` physical address.
const OFF_HVM_START_INFO: u32 = 0x3030;
/// Offset one past the end of the boot stack. The stack grows down, so this is
/// the initial `%rsp`.
///
/// This leaves roughly 500 KiB between the top of the page tables (`OFF_GDTR`
/// and below) and the initial `%rsp`. The original 32 KiB region gave the
/// stack only about 20 KiB, which a debug build of the ChaCha20 CRNG
/// exhausted: `%rsp` ran down past `BOOT_SCRATCH_BASE`, overwrote the PML4,
/// PDPT and PD sitting at the bottom of this very region, and triple-faulted
/// on the next instruction fetch.
///
/// Note what makes that failure mode nasty: the stack grows *towards* the page
/// tables, so an overflow corrupts the mapping that would be needed to report
/// it. This headroom is not a fix.
///
/// TODO: give the boot stack a real guard page. Nothing on this path has one:
/// neither this stack nor the per-CPU kernel stack switched to later, whose
/// `_guard_page_0`/`_guard_page_1` fields in `PerCpuVariables` are padding
/// that keeps neighbouring per-CPU data out of an overflow's way, not
/// unmapped pages. A guard page needs 4 KiB-granular tables, which the 2 MiB
/// early tables here cannot express, plus a way to punch a hole in the real
/// tables built later -- `unmap_pages` and `mprotect_pages` in the platform
/// crate's paging module are `pub(crate)` and would have to be exposed.
const OFF_STACK_TOP: u32 = 0x80000;

/// An ELF note with a 4-byte name and a 4-byte descriptor.
#[repr(C, align(4))]
struct PvhNote {
    namesz: u32,
    descsz: u32,
    ntype: u32,
    name: [u8; 4],
    desc: u32,
}

#[used]
#[unsafe(link_section = ".note.Xen")]
static PVH_NOTE: PvhNote = PvhNote {
    namesz: 4,
    descsz: 4,
    ntype: XEN_ELFNOTE_PHYS32_ENTRY,
    name: *b"Xen\0",
    desc: PVH_ENTRY_ADDR,
};

/// Physical address of the `hvm_start_info` structure supplied at boot.
///
/// `%ebx` is the only pointer to that structure and is trivially clobbered, so
/// the entry stub stores it in the scratch region before touching any other
/// register. [`boot_info`] consumes this.
///
/// Returns zero if the hypervisor passed a null `%ebx`.
fn hvm_start_info_addr() -> u64 {
    let slot = u64::from(BOOT_SCRATCH_BASE + OFF_HVM_START_INFO) + KERNEL_OFFSET;
    // SAFETY: The slot is inside the linker-reserved boot scratch region, so
    // nothing else owns it. It is naturally aligned, is written exactly once
    // by the entry stub strictly before any Rust code runs, and is read-only
    // thereafter; no other CPU has been started, so there is no concurrency.
    // The high-canonical alias used here is mapped by the early page tables.
    unsafe { (slot as *const u64).read() }
}

// ---------------------------------------------------------------------------
// The boot stub.
//
// Written in `global_asm!` rather than as Rust because the first half runs in
// 32-bit protected mode, where Rust's ABI and codegen (which assume long mode)
// cannot be used at all.
//
// COM1's transmit-holding register needs no initialisation: QEMU's emulated
// 16550 accepts writes to it immediately.
// ---------------------------------------------------------------------------
global_asm!(
    r#"
    .section .text._start,"ax",@progbits
    .globl _start
    .code32
_start:
    /* Step 1: %ebx is the only pointer to hvm_start_info. Save it before
       anything else can clobber it. The upper half is zeroed because PVH
       hands us a 32-bit physical address. */
    mov dword ptr [{scratch} + {off_sinfo}], ebx
    mov dword ptr [{scratch} + {off_sinfo} + 4], 0

    /* Liveness marker: proof the hypervisor reached this entry point at all,
       emitted before anything that could plausibly fail. */
    mov dx, 0x3F8
    mov al, 'P'
    out dx, al
    mov al, 'V'
    out dx, al
    mov al, 'H'
    out dx, al
    mov al, 0x0A
    out dx, al

    /* Step 2: build the early page tables.

       Zero all three tables first. The scratch region is NOLOAD, so its
       contents on entry are whatever the firmware left behind. */
    cld
    mov edi, {scratch} + {off_pml4}
    xor eax, eax
    mov ecx, (3 * 4096) / 4
    rep stosd

    /* PML4[0] -> PDPT: identity map of the low 1 GiB. Required, not optional:
       we are executing at ~0x200000 and would fault the instant CR0.PG goes
       on without it. */
    mov eax, {scratch} + {off_pdpt}
    or eax, 0x03                      /* PRESENT | WRITABLE */
    mov dword ptr [{scratch} + {off_pml4}], eax

    /* PML4[452] -> the same PDPT: the high-canonical alias at KERNEL_OFFSET.
       Sharing one PDPT is sound because KERNEL_OFFSET's PDPT and PD indices
       are both 0. */
    mov dword ptr [{scratch} + {off_pml4} + {kernel_pml4_index} * 8], eax

    /* PDPT[0] -> PD. */
    mov eax, {scratch} + {off_pd}
    or eax, 0x03                      /* PRESENT | WRITABLE */
    mov dword ptr [{scratch} + {off_pdpt}], eax

    /* PD[i] = (i * 2 MiB) | PRESENT | WRITABLE | HUGE. The last address is
       1 GiB - 2 MiB = 0x3FE00000, so the whole loop stays inside 32 bits. */
    xor ecx, ecx
    mov eax, 0x83
2:
    mov dword ptr [{scratch} + {off_pd} + ecx * 8], eax
    add eax, 0x200000
    inc ecx
    cmp ecx, {pd_entries}
    jb 2b

    /* Build the 64-bit GDT in place. Writing it at runtime rather than
       emitting it into .rodata keeps its address an immediate here, and keeps
       its pseudo-descriptor free of an absolute relocation. */
    mov dword ptr [{scratch} + {off_gdt} + 0x00], 0x00000000   /* null  */
    mov dword ptr [{scratch} + {off_gdt} + 0x04], 0x00000000
    mov dword ptr [{scratch} + {off_gdt} + 0x08], 0x0000FFFF   /* code64 */
    mov dword ptr [{scratch} + {off_gdt} + 0x0C], 0x00AF9A00   /* L=1, DPL=0 */
    mov dword ptr [{scratch} + {off_gdt} + 0x10], 0x0000FFFF   /* data  */
    mov dword ptr [{scratch} + {off_gdt} + 0x14], 0x00CF9200

    /* Pseudo-descriptor: 2-byte limit then 4-byte base. `lgdt` executes in
       32-bit mode here, so the base is 4 bytes, which the scratch region's
       address fits in. */
    mov word ptr  [{scratch} + {off_gdtr}], 3 * 8 - 1
    mov dword ptr [{scratch} + {off_gdtr} + 2], {scratch} + {off_gdt}

    /* Step 3: the transition, in the one order the CPU accepts. */
    mov eax, cr4
    or eax, 1 << 5                    /* CR4.PAE */
    mov cr4, eax

    mov eax, {scratch} + {off_pml4}
    mov cr3, eax

    mov ecx, 0xC0000080               /* IA32_EFER */
    rdmsr
    or eax, 1 << 8                    /* EFER.LME */
    wrmsr

    mov eax, cr0
    or eax, 1 << 31                   /* CR0.PG -- paging is live from here */
    mov cr0, eax

    /* Long mode is now *active*, but we are in compatibility mode: the flat
       GDT QEMU left us has CS.L clear. Load our own GDT and far-return
       through a CS with L set to actually reach 64-bit.

       Both the pseudo-descriptor and the GDT it points at are reachable with
       paging on only because of the identity map built above. */
    lgdt [{scratch} + {off_gdtr}]

    /* A far return rather than `ljmp`: same effect, no far-pointer syntax to
       get wrong. Pushes CS then EIP; in 32-bit mode both are 4 bytes. */
    mov eax, offset .Lpa_compat
    push 0x08
    push eax
    retf

    .code64
.Lcompat_to_long:
    /* Step 4: 64-bit at last, though still executing out of the identity
       map. */
    mov ax, 0x10
    mov ss, ax
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax

    /* Relocate execution into the high-canonical alias. This doubles as the
       strongest proof available that we really are in 64-bit long mode: the
       destination has bits set far above bit 31 and simply cannot be
       expressed, let alone jumped to, in 32-bit mode. It also exercises the
       KERNEL_OFFSET window the platform crate depends on. */
    mov rax, offset .Lpa_high
    mov rcx, {kernel_offset}
    add rax, rcx
    jmp rax

.Lhigh_half:
    /* Stack, in the high alias too, so %rsp and %rip agree about which window
       we are running in. It grows down, hence the top of the region. */
    mov rsp, {scratch} + {off_stack_top}
    add rsp, rcx

    /* Enable SSE before any Rust runs.

       SSE2 is part of the x86-64 ABI baseline, so the compiler may emit xmm
       instructions in *any* function without asking. On reset CR0.EM is set
       and CR4.OSFXSR is clear, which makes every one of them #UD. Nothing
       caught this earlier only because the boot path so far happened to be
       plain integer code; the first library that vectorises anything (here
       rand_chacha, via `xorps %xmm0,%xmm0`) triple-faults instead, with no
       output, because there is no IDT to report the #UD.

       CR0.EM off / CR0.MP on selects FPU rather than emulation; CR4.OSFXSR
       tells the CPU the OS will manage xmm state via FXSAVE, and
       CR4.OSXMMEXCPT routes SIMD FP exceptions to vector 19 instead of #UD.

       AVX is deliberately not enabled: the target sets `-avx,-avx2,-avx512f`,
       so nothing needs XCR0 and this can stay a two-register change. */
    mov rax, cr0
    and rax, ~(1 << 2)                /* CR0.EM  = 0 */
    or  rax, 1 << 1                   /* CR0.MP  = 1 */
    mov cr0, rax

    mov rax, cr4
    or  rax, (1 << 9) | (1 << 10)     /* CR4.OSFXSR | CR4.OSXMMEXCPT */
    mov cr4, rax

    /* Terminate the frame chain so any future unwinder or backtrace stops
       here rather than walking into garbage. */
    xor rbp, rbp

    call {rust_entry}

    /* {rust_entry} is `-> !`; if it ever returns, stop dead rather than
       execute whatever happens to follow. */
3:
    cli
    hlt
    jmp 3b

    /* `_start`'s physical address is fixed by the linker script, so a label's
       physical address is {entry} plus its offset from `_start`. Each such
       address is folded into an absolute symbol by `.set`, whose
       expression parser handles symbol arithmetic that the Intel-syntax
       *operand* parser does not: written inline, `a - b + c` is rejected
       outright and `offset a + c` silently drops the addend. Uses then name a
       single absolute symbol, which also keeps them relocation-free. */
    .set .Lpa_compat, .Lcompat_to_long - _start + {entry}
    .set .Lpa_high,   .Lhigh_half - _start + {entry}
"#,
    entry = const PVH_ENTRY_ADDR,
    kernel_offset = const KERNEL_OFFSET,
    kernel_pml4_index = const KERNEL_PML4_INDEX,
    pd_entries = const PD_ENTRIES,
    scratch = const BOOT_SCRATCH_BASE,
    off_pml4 = const OFF_PML4,
    off_pdpt = const OFF_PDPT,
    off_pd = const OFF_PD,
    off_gdt = const OFF_GDT,
    off_gdtr = const OFF_GDTR,
    off_sinfo = const OFF_HVM_START_INFO,
    off_stack_top = const OFF_STACK_TOP,
    rust_entry = sym crate::kvm_long_mode_entry,
);

/// The boot stack, as physical addresses `[floor, top)`.
///
/// `floor` is [`BOOT_SCRATCH_BASE`] rather than anything tighter because the
/// stack grows down *towards* the page tables at the bottom of the scratch
/// region -- see [`OFF_STACK_TOP`] for what happens when it gets there.
///
/// Reported through [`super::former_stack_range`].
pub(super) fn boot_stack_range() -> (u64, u64) {
    (
        u64::from(BOOT_SCRATCH_BASE),
        u64::from(BOOT_SCRATCH_BASE + OFF_STACK_TOP),
    )
}

/// One past the highest physical address the image may occupy: the base of the
/// scratch region, which `x86_64_kvm.ld` `ASSERT`s the image does not reach.
///
/// Reported through [`super::image_limit_pa`].
pub(super) fn image_limit_pa() -> u64 {
    u64::from(BOOT_SCRATCH_BASE)
}

// ---------------------------------------------------------------------------
// The `hvm_start_info` wire format, and reading it.
//
// Field order and offsets are fixed by the PVH boot specification
// (`xen/include/public/arch-x86/hvm/start_info.h`). These are wire formats, so
// they are `#[repr(C)]` and must not be reordered.
// ---------------------------------------------------------------------------

/// `hvm_start_info.magic`: "xEn3" little-endian.
const HVM_START_MAGIC_VALUE: u32 = 0x336e_c578;

/// `hvm_memmap_table_entry.type_` for usable RAM. Mirrors the E820 encoding.
const HVM_MEMMAP_TYPE_RAM: u32 = 1;

/// The `memmap_paddr`/`memmap_entries` fields exist from version 1.
const HVM_START_INFO_MEMMAP_VERSION: u32 = 1;

/// One past the highest physical address the early page tables map.
///
/// The stub above builds a single PD of [`PD_ENTRIES`] 2 MiB leaves, so
/// exactly the low 1 GiB is addressable through the high-canonical alias.
///
/// This is the PVH backend's own value, used by [`read_phys`] while parsing --
/// which happens before a [`BootInfo`](super::BootInfo) exists to carry it.
/// It is also what this backend reports as
/// [`BootInfo::mapped_limit`](super::BootInfo::mapped_limit), so consumers
/// downstream never name it.
pub const MAPPED_LIMIT: u64 = 1 << 30;

/// The PVH boot information structure, version 1.
#[repr(C)]
#[derive(Clone, Copy)]
struct HvmStartInfo {
    magic: u32,
    version: u32,
    flags: u32,
    nr_modules: u32,
    modlist_paddr: u64,
    cmdline_paddr: u64,
    rsdp_paddr: u64,
    /// Present only when `version >= 1`.
    memmap_paddr: u64,
    /// Present only when `version >= 1`.
    memmap_entries: u32,
    reserved: u32,
}

/// One entry of the PVH memory map.
#[repr(C)]
#[derive(Clone, Copy)]
struct HvmMemmapTableEntry {
    addr: u64,
    size: u64,
    type_: u32,
    reserved: u32,
}

/// One entry of the PVH module list, pointed at by
/// `HvmStartInfo::modlist_paddr`.
#[repr(C)]
#[derive(Clone, Copy)]
struct HvmModlistEntry {
    paddr: u64,
    size: u64,
    cmdline_paddr: u64,
    reserved: u64,
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
fn read_start_info(pa: u64) -> HvmStartInfo {
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

/// Largest module count this will reason about.
///
/// Nothing we boot uses modules at all; the cap exists so that a bogus
/// `nr_modules` becomes a loud assertion rather than an overrun of
/// [`MAX_FIRMWARE_RESERVED`].
const MAX_MODULES: u32 = 8;

/// Parses the `hvm_start_info` handed to us at boot into a [`BootInfo`].
///
/// # What is withheld, and why
///
/// The reserved ranges reported here are the *firmware's own* structures, and
/// nothing else. `crate::memmap` adds the firmware-neutral exclusions -- the
/// first megabyte and the loaded image -- because those are facts about an x86
/// PC and about our own link, not about PVH.
///
/// Each is named individually rather than merged, because the reason each one
/// is here is the interesting part and a merged list cannot be reviewed.
///
/// # Panics
///
/// Panics if the `hvm_start_info` magic is wrong, if its version predates the
/// memory map table, if it reports more modules than [`MAX_MODULES`], or if it
/// reports more usable-RAM regions than [`MAX_RAM_REGIONS`]. Every one of these
/// would otherwise end in the heap being handed memory that is not free.
pub(super) fn boot_info() -> BootInfo {
    let start_info_pa = hvm_start_info_addr();
    log::info!("start_info {start_info_pa:#018X}");
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

    let mut reserved: arrayvec::ArrayVec<Range, MAX_FIRMWARE_RESERVED> = arrayvec::ArrayVec::new();

    // 1. The `hvm_start_info` structure itself. Nothing reads it after boot,
    //    but it costs one page to keep it intact and makes a post-mortem
    //    possible.
    reserved.push(Range {
        start: start_info_pa,
        end: start_info_pa.saturating_add(size_of::<HvmStartInfo>() as u64),
    });

    // 2. The memory map table. Same reasoning; also, it is read while deciding
    //    what to accept, so it must survive the walk.
    let bytes = u64::from(info.memmap_entries) * size_of::<HvmMemmapTableEntry>() as u64;
    reserved.push(Range {
        start: info.memmap_paddr,
        end: info.memmap_paddr.saturating_add(bytes),
    });

    // 3. The kernel command line. QEMU happens to place it at 0x11C0, below
    //    `_heap_start`, so the image range already covers it today -- but
    //    nothing in the boot protocol promises that, and the day it moves above
    //    the heap floor the heap would start writing free-list nodes over it.
    //    Withhold it explicitly, measured to its terminator rather than
    //    assumed.
    if info.cmdline_paddr != 0 {
        let len = cstr_len(info.cmdline_paddr);
        reserved.push(Range {
            start: info.cmdline_paddr,
            end: info.cmdline_paddr.saturating_add(len),
        });
    }

    // 4. The module list and every module image it names. QEMU's PVH loader
    //    places an `-initrd` payload in RAM and reports it as *type 1*, so
    //    without this the heap is handed the module image and writes into it
    //    immediately.
    assert!(
        info.nr_modules <= MAX_MODULES,
        "hvm_start_info reports {} modules, more than the {} this can withhold \
         from the heap; raise MAX_MODULES and MAX_FIRMWARE_RESERVED together",
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
        reserved.push(Range {
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

            reserved.push(Range {
                start: module.paddr,
                end: module.paddr.saturating_add(module.size),
            });
        }
    }

    // The memory map itself. Every entry is logged, accepted or not, so the
    // decision can be checked from outside rather than trusted -- which is why
    // this loop reports entries it does not collect.
    let mut usable: arrayvec::ArrayVec<Range, MAX_RAM_REGIONS> = arrayvec::ArrayVec::new();
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
            assert!(
                !usable.is_full(),
                "hvm_start_info reports more than {MAX_RAM_REGIONS} usable-RAM \
                 regions; raise MAX_RAM_REGIONS rather than silently dropping \
                 memory the heap would then never see"
            );
            usable.push(Range {
                start: entry.addr,
                end,
            });
        }
    }

    BootInfo {
        usable,
        reserved,
        mapped_limit: MAPPED_LIMIT,
    }
}
