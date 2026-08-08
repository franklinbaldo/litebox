//! LiteBox runner for a KVM/QEMU guest.
//!
//! Booted via the PVH boot protocol: QEMU's `-kernel` finds an
//! `XEN_ELFNOTE_PHYS32_ENTRY` note in this ELF and enters [`_start`] in 32-bit
//! protected mode with paging off, A20 on, a flat GDT, and `%ebx` pointing at
//! an `hvm_start_info` structure.
//!
//! The entry stub saves `%ebx`, builds early 2 MiB page tables, enters long
//! mode, relocates execution into the high-canonical alias of the image, and
//! calls into 64-bit Rust, which applies `.rela.dyn` before touching any
//! pointer-bearing static and then brings up serial logging.

#![no_std]
#![no_main]

use core::arch::global_asm;
use core::panic::PanicInfo;

use litebox_platform_lvbs::{Instant, serial_println};

/// Physical address of [`_start`].
///
/// The linker script places `.text` at `0x200000` and `KEEP`s `.text._start`
/// as its first input section, so `_start` is guaranteed to sit exactly here.
/// The build is verified against `nm` rather than trusting this by inspection.
const PVH_ENTRY_ADDR: u32 = 0x0020_0000;

/// `XEN_ELFNOTE_PHYS32_ENTRY`: the note type QEMU looks for to select PVH.
const XEN_ELFNOTE_PHYS32_ENTRY: u32 = 18;

/// Base of the high-canonical kernel window: `VA = PA + KERNEL_OFFSET`.
///
/// This must match `litebox_platform_lvbs::KERNEL_OFFSET` (lib.rs:160), which
/// is what that crate's `MemoryProvider::pa_to_va` assumes. The early page
/// tables built below install that window, so the platform crate's assumption
/// already holds by the time Rust runs.
const KERNEL_OFFSET: u64 = 0xFFFF_E200_0000_0000;

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
/// it. A real guard page needs 4 KiB granularity, which the 2 MiB early tables
/// cannot express; Task 6 owns proper memory setup and should add one. Until
/// then this is headroom, not a fix.
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
/// register. Task 6 consumes this to read the memory map.
///
/// Returns zero if the hypervisor passed a null `%ebx`.
pub fn hvm_start_info_addr() -> u64 {
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

    /* Liveness marker, matching the Task 1 behaviour. */
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
       physical address is {entry} plus its offset from `_start`. Folding each
       Each address is folded into an absolute symbol by `.set`, whose
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
    rust_entry = sym kvm_long_mode_entry,
);

// ---------------------------------------------------------------------------
// Global allocator placeholder.
//
// Depending on `litebox_platform_lvbs` pulls in `alloc`, and rustc then
// demands a `#[global_allocator]` at link time. Under `host_lvbs` the platform
// crate supplies one (`host/lvbs_impl.rs`); under `host_kvm` it deliberately
// does not, because the KVM heap needs the PVH memory map, which Task 6 parses.
//
// So this is a placeholder that cannot silently paper over the gap: every
// entry point panics. Nothing on the Task 3 path allocates, so it is never
// reached. TASK 6 MUST REPLACE THIS with the real `SafeZoneAllocator` wired to
// the PVH memory map.
// ---------------------------------------------------------------------------

/// Placeholder allocator: panics on any use. See the module comment above.
struct NoAllocatorYet;

// SAFETY: Every method diverges, so the trait's contract about returned
// pointers is vacuously upheld -- nothing is ever returned.
unsafe impl core::alloc::GlobalAlloc for NoAllocatorYet {
    unsafe fn alloc(&self, _layout: core::alloc::Layout) -> *mut u8 {
        panic!("heap allocation before the KVM allocator exists (Task 6)")
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {
        panic!("heap deallocation before the KVM allocator exists (Task 6)")
    }
}

#[global_allocator]
static ALLOCATOR: NoAllocatorYet = NoAllocatorYet;

// ---------------------------------------------------------------------------
// Relocation.
//
// The target links `--pie` (`relocation-model: "pie"` in x86_64_kvm.json), so
// every absolute address the compiler needed to store in memory -- vtables,
// `&'static str` data pointers, `&OTHER_STATIC` -- was emitted as a link-time
// value plus an `R_X86_64_RELATIVE` entry in `.rela.dyn`. Nothing applies
// those entries for us: PVH drops us straight into the raw image. Until the
// loop below runs, any pointer-bearing static is wrong, and anything that
// appears to work does so by accident.
// ---------------------------------------------------------------------------

/// An ELF64 relocation entry with an explicit addend (`Elf64_Rela`).
#[repr(C)]
struct Elf64Rela {
    /// Link-time address of the word to patch.
    offset: u64,
    /// Symbol index in the high 32 bits, relocation type in the low 32.
    info: u64,
    /// Link-time value to which the load bias is added.
    addend: i64,
}

/// `R_X86_64_RELATIVE`: `*offset = load_bias + addend`. The only relocation
/// type a `--static --pie` image with no dynamic symbols can contain, and the
/// only one handled here; anything else means the link went wrong.
const R_X86_64_RELATIVE: u64 = 8;

/// Applies every `R_X86_64_RELATIVE` entry in `.rela.dyn`, returning the load
/// bias used.
///
/// # Load bias
///
/// The linker script starts at `. = 0x0` and puts `_memory_base` there, so
/// link-time addresses are image offsets and the link-time base is exactly
/// zero. The bias is therefore just the runtime address of `_memory_base`.
///
/// We are already executing in the high-canonical alias installed by the boot
/// stub, so the RIP-relative `lea` below yields `0 + KERNEL_OFFSET`, and every
/// relocated pointer comes out high-canonical -- which is what the rest of the
/// kernel, and `litebox_platform_lvbs`'s `pa_to_va`, expect. Doing this before
/// the jump into the alias would instead produce low physical pointers that
/// would all have to be fixed up a second time.
///
/// # Position independence
///
/// This function must not itself depend on an absolute address, so the three
/// linker symbols it needs are taken via RIP-relative `lea` rather than by
/// reading a static.
///
/// # Safety
///
/// - Must run before anything reads a pointer-bearing static.
/// - Must run exactly once.
/// - The `.rela.dyn` table and every address it names must be mapped writable
///   at `link-time address + load_bias`.
#[inline(never)]
unsafe fn apply_relocations() -> u64 {
    unsafe extern "C" {
        static _memory_base: u8;
        static _rela_start: u8;
        static _rela_end: u8;
    }

    let load_bias: u64;
    let rela_start: u64;
    let rela_end: u64;
    // SAFETY: `lea` with RIP-relative operands only computes addresses into
    // registers; it reads no memory and touches no flags.
    unsafe {
        core::arch::asm!(
            "lea {base}, [rip + _memory_base]",
            "lea {start}, [rip + _rela_start]",
            "lea {end}, [rip + _rela_end]",
            base = out(reg) load_bias,
            start = out(reg) rela_start,
            end = out(reg) rela_end,
            options(nostack, nomem, preserves_flags)
        );
    }

    // Already at the link-time base: nothing to adjust. Cannot happen here
    // (we run in the high alias), but applying a zero bias would be a no-op
    // anyway, and skipping keeps the invariant explicit.
    if load_bias == 0 {
        return 0;
    }

    let mut rela = rela_start as *const Elf64Rela;
    let rela_end_ptr = rela_end as *const Elf64Rela;

    while rela < rela_end_ptr {
        // SAFETY: `rela` is within `[_rela_start, _rela_end)`, a linker-
        // emitted array of `Elf64_Rela` (checked by the loop condition), and
        // the section is 8-byte aligned by construction.
        let entry = unsafe { &*rela };

        if entry.info & 0xFFFF_FFFF == R_X86_64_RELATIVE {
            let target = load_bias.wrapping_add(entry.offset) as *mut u64;
            // The ELF ABI defines the addend as signed and the result as an
            // unsigned address; wrapping through both is the intended
            // arithmetic, not an overflow bug.
            #[expect(
                clippy::cast_possible_wrap,
                clippy::cast_sign_loss,
                reason = "ELF relocation arithmetic is defined modulo 2^64"
            )]
            let value = entry.addend.wrapping_add(load_bias as i64) as u64;
            // SAFETY: `target` is a link-time address from the linker's own
            // relocation table, biased into the mapping we execute in, so it
            // lies inside the image and is 8-byte aligned. `write_volatile`
            // keeps the store from being reordered against the reads that the
            // relocated statics will shortly perform.
            unsafe { target.write_volatile(value) };
        }

        // SAFETY: Still inside the table; the loop condition rechecks before
        // the next dereference.
        rela = unsafe { rela.add(1) };
    }

    load_bias
}

// ---------------------------------------------------------------------------
// Relocation probe.
//
// A `&'static str` inside a static array is the cheapest thing that forces the
// linker to emit an `R_X86_64_RELATIVE` entry: the array slot holds the
// absolute address of the string data. Reading the slot's raw bits before and
// after `apply_relocations` shows the bias being applied, and successfully
// dereferencing it afterwards shows the result is a real, mapped pointer.
// ---------------------------------------------------------------------------

/// Static whose stored data pointer is patched by `.rela.dyn`.
static RELOC_PROBE: [&str; 1] = ["relocation probe string"];

/// Reads the raw bits of [`RELOC_PROBE`]'s data pointer without dereferencing
/// it, so it is safe to call before relocations have been applied.
fn read_reloc_probe_slot() -> u64 {
    // The first word of a `&str` is its data pointer, which is what the
    // relocation patches.
    let slot = (&raw const RELOC_PROBE).cast::<u64>();
    // SAFETY: `slot` points at the first eight bytes of a live, naturally
    // aligned static. `read_volatile` forces an actual load of the stored
    // value rather than letting the compiler rematerialise the address
    // RIP-relatively, which would hide the very thing being measured.
    unsafe { slot.read_volatile() }
}

// ---------------------------------------------------------------------------
// Logging.
// ---------------------------------------------------------------------------

/// `log` backend that forwards formatted records to COM1.
///
/// Mirrors `litebox_runner_lvbs`'s logger. Phase 1 routed the platform crate's
/// `print()` to COM1 under `host_kvm`, so this needs no extra plumbing.
struct HostLogger;

impl log::Log for HostLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        // Stack-allocated: there is no allocator until Task 6. Records longer
        // than the buffer are truncated rather than dropped.
        let mut buf: arrayvec::ArrayString<1024> = arrayvec::ArrayString::new();
        let _ = litebox_util_log::format_record(&mut buf, record);
        litebox_platform_lvbs::arch::ioport::serial_print_string(&buf);
    }

    fn flush(&self) {}
}

static HOST_LOGGER: HostLogger = HostLogger;

/// The first 64-bit Rust code to run.
///
/// Entered from the boot stub through the high-canonical alias, so `%rip` and
/// `%rsp` are both at `PA + KERNEL_OFFSET` on arrival.
///
/// Nothing here may touch a pointer-bearing static until [`apply_relocations`]
/// has run: the image is linked `--pie`, so every such pointer still holds its
/// link-time value until then.
extern "C" fn kvm_long_mode_entry() -> ! {
    // Sample the relocation probe *before* relocating, while its stored
    // pointer is still the link-time address. Only the raw bits are read, so
    // this does not dereference anything.
    let probe_before = read_reloc_probe_slot();

    // SAFETY: This is the first thing 64-bit Rust does, so nothing has yet
    // relied on an unrelocated absolute address, and it therefore runs exactly
    // once. The `.rela.dyn` bounds come from the linker script, and both the
    // table and every target it names lie in the low 1 GiB, which the early
    // page tables map writably through the high-canonical alias we run in.
    let load_bias = unsafe { apply_relocations() };

    let probe_after = read_reloc_probe_slot();

    // Statics are now trustworthy, so the logger -- itself reached through a
    // `&'static` -- can be installed.
    let _ = log::set_logger(&HOST_LOGGER);
    log::set_max_level(log::LevelFilter::Trace);

    log::info!("litebox_runner_kvm: long mode, relocations applied");
    log::info!("load bias  {load_bias:#018X}");

    // Evidence of 64-bit execution: %rip is a high-canonical address with bits
    // set far above bit 31, which no 32-bit mode could produce or reach.
    let rip: u64;
    // SAFETY: `lea` with a RIP-relative operand only reads the instruction
    // pointer into a register.
    unsafe {
        core::arch::asm!("lea {}, [rip + 0]", out(reg) rip, options(nomem, nostack));
    }
    log::info!("rip        {rip:#018X}");
    log::info!("start_info {:#018X}", hvm_start_info_addr());

    // Relocation proof. `probe_before` is the raw word as the linker left it
    // in the image; `probe_after` is the same slot once `.rela.dyn` has been
    // applied, and must be the high-canonical address of the string data.
    //
    // Note that `probe_before` is *zero*, not the link-time address: in RELA
    // form the value lives entirely in the entry's addend and the in-place
    // field is left empty. That makes the point more sharply than a low
    // address would -- dereferencing this static before relocation would have
    // been a null-pointer read.
    //
    // Dereferencing it afterwards and getting the expected text back is the
    // real check: a wrong load bias would fault or print rubbish.
    serial_println!("probe ptr  {probe_before:#018X} -> {probe_after:#018X}");
    serial_println!("probe str  {}", RELOC_PROBE[0]);
    assert_eq!(probe_before, 0, "RELA entries should leave the field empty");
    assert!(
        probe_after.wrapping_sub(load_bias) < u64::from(BOOT_SCRATCH_BASE),
        "relocated probe pointer does not land inside the image"
    );

    check_clock();
    check_crng();

    halt();
}

// ---------------------------------------------------------------------------
// Clock and CRNG checks.
//
// These exist because "it did not panic" is not evidence that a clock works: a
// wrong TSC frequency produces a clock that runs happily at the wrong rate.
// ---------------------------------------------------------------------------

/// Iterations of the short spin used to show the clock advancing over a small,
/// bounded interval. Large enough to dwarf the two `rdtsc` reads, small enough
/// to stay well under a second even under TCG.
const SPIN_ITERS: u32 = 10_000_000;

/// Busy-waits until this many nanoseconds have elapsed *by our own clock*.
///
/// One second is convenient because it is directly checkable from outside the
/// guest: the two log lines bracketing the wait are timestamped by the host as
/// they arrive on the serial port, so a wrong TSC frequency shows up as a
/// host-observed gap that is not one second.
const CALIBRATED_WAIT_NANOS: u64 = 1_000_000_000;

/// Nanoseconds between two [`Instant`]s.
fn elapsed_nanos(start: &Instant, end: &Instant) -> u64 {
    use litebox::platform::Instant as _;
    end.checked_duration_since(start)
        .expect("clock went backwards")
        .as_nanos()
        .try_into()
        .expect("interval does not fit in u64 nanoseconds")
}

/// Exercises the TSC clock and reports enough numbers to tell a working clock
/// from a plausible-looking broken one.
fn check_clock() {
    log::info!(
        "tsc freq   {} Hz via {}",
        litebox_platform_lvbs::arch::clock::tsc_hz(),
        litebox_platform_lvbs::arch::clock::tsc_source()
    );

    // A short spin. Checks the clock advances, and by an amount whose order of
    // magnitude is credible for this many iterations.
    let start = Instant::now();
    for _ in 0..SPIN_ITERS {
        core::hint::spin_loop();
    }
    let end = Instant::now();
    let spin_nanos = elapsed_nanos(&start, &end);
    log::info!("spin       {SPIN_ITERS} iters -> {spin_nanos} ns");
    assert!(
        spin_nanos > 0,
        "clock did not advance across {SPIN_ITERS} iterations"
    );

    // A wait of one second by our own clock. The host timestamps the two lines
    // below as they arrive, so this is checked against a clock we do not own.
    log::info!("wait 1s    start");
    let start = Instant::now();
    let mut end = Instant::now();
    while elapsed_nanos(&start, &end) < CALIBRATED_WAIT_NANOS {
        core::hint::spin_loop();
        end = Instant::now();
    }
    log::info!(
        "wait 1s    done, measured {} ns",
        elapsed_nanos(&start, &end)
    );

    // Cross-check against the PIT. This is the part that actually proves the
    // TSC scaling is right rather than merely self-consistent: the PIT is a
    // separate counter with an independently fixed rate, so bracketing one of
    // its gated intervals with two `Instant`s compares two clocks that share
    // nothing. A TSC frequency wrong by a factor of N shows up here as an
    // error of N, whereas the spin above would look perfectly healthy.
    let start = Instant::now();
    let pit_nanos = litebox_platform_lvbs::arch::clock::pit_reference_interval_nanos();
    let end = Instant::now();
    match pit_nanos {
        Some(pit_nanos) => {
            let tsc_nanos = elapsed_nanos(&start, &end);
            // Integer permille error, avoiding floating point.
            let error_permille =
                (tsc_nanos.abs_diff(pit_nanos)).saturating_mul(1000) / pit_nanos.max(1);
            log::info!(
                "pit check  pit {pit_nanos} ns vs tsc {tsc_nanos} ns, error {error_permille} permille"
            );
        }
        None => log::warn!("pit check  PIT unavailable, cross-check skipped"),
    }
}

/// Draws from the CRNG twice and shows that it produces bytes, and different
/// ones each time.
fn check_crng() {
    // QEMU's default `qemu64` CPU model does not implement RDRAND, and the
    // CRNG rightly refuses to run without it rather than substituting
    // something weaker. Skip the self-check loudly in that case: provoking a
    // deliberate panic would tell us nothing we did not already know from
    // CPUID, and would stop the rest of boot.
    if !litebox_platform_lvbs::host::kvm_impl::rdrand_supported() {
        log::warn!("crng       RDRAND absent (CPUID.1:ECX bit 30 clear), check skipped");
        return;
    }

    let mut first = [0u8; 32];
    let mut second = [0u8; 32];
    litebox_platform_lvbs::host::kvm_impl::fill_bytes_crng(&mut first);
    litebox_platform_lvbs::host::kvm_impl::fill_bytes_crng(&mut second);

    log::info!("crng #1    {}", HexBytes(&first));
    log::info!("crng #2    {}", HexBytes(&second));

    assert_ne!(first, second, "CRNG returned the same block twice");
    assert!(first != [0u8; 32], "CRNG returned all zeroes");
}

/// Formats a byte slice as lower-case hex without allocating.
struct HexBytes<'a>(&'a [u8]);

impl core::fmt::Display for HexBytes<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Disables interrupts and halts this CPU forever.
fn halt() -> ! {
    loop {
        // SAFETY: `cli`/`hlt` only disable interrupts and halt this CPU.
        unsafe {
            core::arch::asm!("cli; hlt", options(nomem, nostack));
        }
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("PANIC: {info}");
    halt()
}
