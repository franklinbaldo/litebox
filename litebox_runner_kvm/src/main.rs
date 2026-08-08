//! LiteBox runner for a KVM/QEMU guest.
//!
//! Booted via the PVH boot protocol: QEMU's `-kernel` finds an
//! `XEN_ELFNOTE_PHYS32_ENTRY` note in this ELF and enters [`_start`] in 32-bit
//! protected mode with paging off, A20 on, a flat GDT, and `%ebx` pointing at
//! an `hvm_start_info` structure.
//!
//! At this stage the runner does nothing but prove the entry point is reached:
//! it writes `PVH\n` to COM1 and halts.

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

// The 32-bit PVH entry point.
//
// Written in `global_asm!` rather than as a naked Rust function because this
// code runs in 32-bit protected mode: nothing here may touch Rust, whose ABI
// and codegen assume long mode.
//
// COM1's transmit-holding register needs no initialisation — QEMU's emulated
// 16550 accepts writes to it immediately.
global_asm!(
    r#"
    .section .text._start,"ax",@progbits
    .globl _start
    .code32
_start:
    mov dx, 0x3F8
    mov al, 'P'
    out dx, al
    mov al, 'V'
    out dx, al
    mov al, 'H'
    out dx, al
    mov al, 0x0A
    out dx, al
2:
    cli
    hlt
    jmp 2b
    .code64
"#
);

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        // SAFETY: `cli`/`hlt` only disable interrupts and halt this CPU.
        unsafe {
            core::arch::asm!("cli; hlt", options(nomem, nostack));
        }
    }
}
