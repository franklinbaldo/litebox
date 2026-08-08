//! LiteBox runner for a KVM/QEMU guest.
//!
//! Booted via the PVH boot protocol: QEMU's `-kernel` finds an
//! `XEN_ELFNOTE_PHYS32_ENTRY` note in this ELF and enters [`_start`] in 32-bit
//! protected mode with paging off, A20 on, a flat GDT, and `%ebx` pointing at
//! an `hvm_start_info` structure.
//!
//! The entry stub saves `%ebx`, builds early 2 MiB page tables, enters long
//! mode, relocates execution into the high-canonical alias of the image, and
//! calls into 64-bit Rust.

#![no_std]
#![no_main]

use core::arch::global_asm;
use core::panic::PanicInfo;

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
const OFF_STACK_TOP: u32 = 0x8000;

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

/// The first 64-bit Rust code to run.
///
/// Entered from the boot stub through the high-canonical alias, so `%rip` and
/// `%rsp` are both at `PA + KERNEL_OFFSET` on arrival.
///
/// This writes to COM1 by hand rather than through the platform crate's serial
/// helpers, which are not wired up until Task 3.
extern "C" fn kvm_long_mode_entry() -> ! {
    serial_str("LONG MODE\n");

    // Evidence of 64-bit execution: %rip is a high-canonical address with bits
    // set far above bit 31, which no 32-bit mode could produce or reach.
    let rip: u64;
    // SAFETY: `lea` with a RIP-relative operand only reads the instruction
    // pointer into a register.
    unsafe {
        core::arch::asm!("lea {}, [rip + 0]", out(reg) rip, options(nomem, nostack));
    }
    serial_str("RIP   ");
    serial_hex64(rip);
    serial_str("\n");

    serial_str("SINFO ");
    serial_hex64(hvm_start_info_addr());
    serial_str("\n");

    halt();
}

/// COM1's transmit-holding register.
const COM1: u16 = 0x3F8;

/// Writes one byte to COM1.
fn serial_byte(byte: u8) {
    // SAFETY: `out` to COM1's transmit-holding register. QEMU's emulated 16550
    // accepts writes with no initialisation, and port I/O touches no memory.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") COM1, in("al") byte, options(nomem, nostack));
    }
}

/// Writes an ASCII string to COM1.
fn serial_str(text: &str) {
    for byte in text.as_bytes() {
        serial_byte(*byte);
    }
}

/// Writes a 64-bit value to COM1 as `0x`-prefixed, zero-padded hex.
fn serial_hex64(value: u64) {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    serial_str("0x");
    for shift in (0..64).step_by(4).rev() {
        serial_byte(DIGITS[((value >> shift) & 0xF) as usize]);
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
fn panic(_info: &PanicInfo) -> ! {
    halt()
}
