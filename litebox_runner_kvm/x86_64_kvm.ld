OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

SECTIONS
{
    . = 0x0;
    _memory_base = .;

    /*  CONFIG_PHYSICAL_START=0x200000 */
    . = 0x200000;

    /* CONFIG_PHYSICAL_ALIGN=0x200000 */

    /* `_start` is KEEPt first so that it lands at exactly 0x200000. The PVH
       note's XEN_ELFNOTE_PHYS32_ENTRY descriptor hardcodes that address
       (PVH_ENTRY_ADDR in src/main.rs); the two must stay in sync. */
    .text : ALIGN(0x200000) {
        _text_start = .;
        KEEP(*(.text._start))
        *(.text .text.*)
        *(.got)
        _text_end = .;
    }

    /* The PVH boot note. This must NOT be discarded: QEMU reads
       XEN_ELFNOTE_PHYS32_ENTRY out of it to decide to use the PVH boot
       protocol, and needs it exposed via a PT_NOTE program header. Kept
       adjacent to .text so the surrounding PT_LOAD stays a single run. */
    .note : ALIGN(4) {
        KEEP(*(.note.Xen))
        KEEP(*(.note .note.*))
    }

    .data : ALIGN(0x200000) { 
        _data_start = .;
        *(.rodata .rodata.*)
        *(.data .data.*)

        /* Exception table for fallible memory operations (memcpy_fallible, etc.) */
        . = ALIGN(4);
        __start_ex_table = .;
        KEEP(*(ex_table))
        __stop_ex_table = .;

        _data_end = .;

        . = ALIGN(0x1000);
        _bss_start = .;
        *(.bss .bss.*)
        _bss_end = .;
    }

    /* Relocation section for position-independent execution */
    .rela.dyn : ALIGN(0x200000) {
        _rela_start = .;
        *(.rela.text .rela.text*)
        *(.rela.data .rela.data*)
        *(.rela.rodata .rela.rodata*)
        *(.rela.got .rela.got*)
        *(.rela.bss .rela.bss*)
        *(.rela.dyn)
        _rela_end = .;
    }

    . = ALIGN(0x1000);
    _image_end = .;

    /* Early boot scratch: PML4/PDPT/PD, the 64-bit GDT and its pseudo-
       descriptor, the saved hvm_start_info pointer, and the boot stack.

       This sits at a *fixed* physical address because the 32-bit entry stub
       has to name it, and 32-bit code has no RIP-relative addressing. The
       target links --pie, where a 32-bit absolute relocation against an
       ordinary symbol needs a dynamic relocation that nothing applies this
       early (rust-lld rejects them outright). A hardcoded address lets the
       stub use plain immediates instead. Keep in sync with
       BOOT_SCRATCH_BASE and the OFF_* constants in src/main.rs.

       NOLOAD: the stub initialises every field it uses at runtime, so there
       is nothing to put in the file. */
    ASSERT(_image_end <= 0x1000000,
           "image has grown into the boot scratch region at 0x1000000")
    . = 0x1000000;
    _boot_scratch_base = .;
    .boot_scratch (NOLOAD) : {
        . = . + 0x80000;
    }
    _boot_scratch_end = .;

    /* The heap starts above the scratch region so the two cannot collide. */
    . = ALIGN(0x1000);
    _heap_start = .;
    
    /DISCARD/ :
    {
        *(.rela.debug .rela.debug*)
        *(.dynamic) *(.dynsym) *(.dynstr) *(.dynbss)
        *(.eh_frame .eh_frame*)
        *(.comment*)
        *(.gnu.hash*)
        *(.hash)
    }
    .debug :
    {
        *(.debug .debug* )
    }
}
