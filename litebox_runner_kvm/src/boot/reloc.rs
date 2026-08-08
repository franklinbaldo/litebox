// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Applying `.rela.dyn`.
//!
//! The target links `--pie` (`relocation-model: "pie"` in x86_64_kvm.json), so
//! every absolute address the compiler needed to store in memory -- vtables,
//! `&'static str` data pointers, `&OTHER_STATIC` -- was emitted as a link-time
//! value plus an `R_X86_64_RELATIVE` entry in `.rela.dyn`. Nothing applies
//! those entries for us: the firmware drops us straight into the raw image.
//! Until the loop below runs, any pointer-bearing static is wrong, and
//! anything that appears to work does so by accident.
//!
//! This is firmware-neutral: it is a property of how the image is *linked*,
//! not of how it is *entered*, so every backend needs it and none of them
//! needs a different version of it.

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
/// The caller is expected to be executing in the high-canonical alias already,
/// so the RIP-relative `lea` below yields `0 + KERNEL_OFFSET`, and every
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
pub unsafe fn apply_relocations() -> u64 {
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
        } else {
            // Silently skipping would leave the target at zero -- the RELA
            // convention noted above -- and turn the link error into a null
            // dereference at an arbitrary later moment, with nothing left to
            // connect it back to here.
            panic!(
                "unsupported relocation type {:#X} at offset {:#X}; this image \
                 is linked -pie with only R_X86_64_RELATIVE, so anything else \
                 means the link went wrong",
                entry.info & 0xFFFF_FFFF,
                entry.offset
            );
        }

        // SAFETY: Still inside the table; the loop condition rechecks before
        // the next dereference.
        rela = unsafe { rela.add(1) };
    }

    load_bias
}
