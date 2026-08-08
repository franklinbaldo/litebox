// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! LiteBox runner for a KVM/QEMU guest.
//!
//! This file is everything that happens *after* bootloading: the first 64-bit
//! Rust entry point, the bring-up self-checks, platform initialisation and the
//! panic handler. It is firmware-neutral throughout, and deliberately so --
//! most runners in this repo begin here, and this one should differ only in
//! having a boot path at all.
//!
//! The boot path itself lives in [`boot`]. [`boot`] documents precisely what
//! state the machine is in by the time [`kvm_long_mode_entry`] is entered;
//! [`boot::pvh`] is the one backend that implements it today, and BIOS and
//! UEFI backends are meant to be additive to it rather than changes to this
//! file.

#![no_std]
#![no_main]

extern crate alloc;

mod boot;
mod memmap;
mod pci;
mod ta;

use core::panic::PanicInfo;

use litebox_platform_lvbs::host::per_cpu_variables::{
    KERNEL_STACK_SIZE, PerCpuVariablesAsm, allocate_per_cpu_variables, init_per_cpu_variables,
};
use litebox_platform_lvbs::mm::MemoryProvider as _;
use litebox_platform_lvbs::{Instant, serial_println};
use litebox_platform_multiplex::Platform;

use crate::boot::KERNEL_OFFSET;

// ---------------------------------------------------------------------------
// Relocation probe.
//
// A `&'static str` inside a static array is the cheapest thing that forces the
// linker to emit an `R_X86_64_RELATIVE` entry: the array slot holds the
// absolute address of the string data. Reading the slot's raw bits before and
// after `boot::apply_relocations` shows the bias being applied, and successfully
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
        // Stack-allocated: logging must work before the heap exists, and this
        // logger is installed long before it does. Records longer
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
/// Nothing here may touch a pointer-bearing static until [`boot::apply_relocations`]
/// has run: the image is linked `--pie`, so every such pointer still holds its
/// link-time value until then.
pub(crate) extern "C" fn kvm_long_mode_entry() -> ! {
    // Sample the relocation probe *before* relocating, while its stored
    // pointer is still the link-time address. Only the raw bits are read, so
    // this does not dereference anything.
    let probe_before = read_reloc_probe_slot();

    // SAFETY: This is the first thing 64-bit Rust does, so nothing has yet
    // relied on an unrelocated absolute address, and it therefore runs exactly
    // once. The `.rela.dyn` bounds come from the linker script, and both the
    // table and every target it names lie in the low 1 GiB, which the early
    // page tables map writably through the high-canonical alias we run in.
    let load_bias = unsafe { boot::apply_relocations() };

    let probe_after = read_reloc_probe_slot();

    // Statics are now trustworthy, so the logger -- itself reached through a
    // `&'static` -- can be installed.
    let _ = log::set_logger(&HOST_LOGGER);
    // Debug rather than Trace: slabmalloc logs every single slab allocation
    // and deallocation at Trace, which buries the boot log once the heap is
    // up. Raise this to Trace when debugging the allocator itself.
    log::set_max_level(log::LevelFilter::Debug);

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
        probe_after.wrapping_sub(load_bias) < boot::image_limit_pa(),
        "relocated probe pointer does not land inside the image"
    );

    check_clock();

    // ---------------------------------------------------------------------
    // Per-CPU bring-up. The order below is the LVBS runner's `common_start`
    // (litebox_runner_lvbs/src/main.rs), and it is load-bearing:
    //
    //   1. FSGSBASE, because `allocate_per_cpu_variables` sets GSBASE with
    //      `wrgsbase`, which #UDs without CR4.FSGSBASE.
    //   2. Extended states, because the XSAVE-area allocation below queries
    //      CPUID and needs CR4.OSXSAVE set to read XCR0.
    //   3. The heap, because per-CPU variables are heap-allocated.
    //   4. `allocate_per_cpu_variables` / `init_per_cpu_variables`.
    //   5. The stack switch.
    //
    // `check_crng` has moved from before the heap to after the stack switch.
    // It was the single largest stack consumer on this path (a debug build of
    // the ChaCha20 CRNG is what once exhausted the boot stack), and
    // there is no reason to spend it on the boot stack now that a 128 KiB
    // per-CPU kernel stack exists a few instructions later. This shrinks the
    // window in which a boot-stack overflow is possible, which is the best
    // available mitigation while neither stack has a guard page (see
    // `OFF_STACK_TOP`).
    // ---------------------------------------------------------------------
    litebox_platform_lvbs::arch::enable_fsgsbase();
    litebox_platform_lvbs::arch::enable_extended_states();

    // Ask the active boot backend what the firmware said about memory. This
    // is the last thing on the boot path that is firmware-specific; from here
    // down, nothing in this file knows how we were booted.
    let boot_info = boot::boot_info();

    // The heap. Everything after this point may allocate; nothing before it
    // may.
    let ram = memmap::init_heap(&boot_info);

    allocate_per_cpu_variables();
    init_per_cpu_variables();

    // Switch to this core's per-CPU kernel stack and tail-call `kernel_main`.
    //
    // `kernel_stack_ptr` is the first field of `PerCpuVariablesAsm`, which is
    // the first field of `PerCpuVariables`, so GSBASE + this offset addresses
    // it directly -- the layout the platform's own assembly assumes.
    //
    // `init_per_cpu_variables` already aligned the stored value to 16, so the
    // `call` below leaves RSP ≡ 8 (mod 16) on entry to `kernel_main`, which is
    // what the SysV ABI requires. RBP is zeroed to terminate the frame chain,
    // since the new stack has no caller.
    //
    // The offset is a `const` operand, not symbol arithmetic, so the
    // `.set`-only hazard from the boot stub does not apply here -- but the
    // emitted code was disassembled and checked regardless.
    //
    // SAFETY: GSBASE points at this core's `PerCpuVariables` (just set by
    // `allocate_per_cpu_variables`), and `kernel_stack_ptr` points one past
    // the top of the 128 KiB `kernel_stack` field inside it (just set by
    // `init_per_cpu_variables`). Nothing on the boot stack is live across
    // this point: `kernel_main` diverges and never returns here.
    unsafe {
        core::arch::asm!(
            "mov rsp, gs:[{kernel_sp_off}]",
            "and rsp, -16",
            "xor ebp, ebp",
            "call {kernel_main}",
            kernel_sp_off = const { PerCpuVariablesAsm::kernel_stack_ptr_offset() },
            kernel_main = sym kernel_main,
            in("rdi") ram.usable_bytes,
            in("rsi") ram.ram_end_pa,
            in("rdx") ram.mapped_limit,
            options(noreturn),
        );
    }
}

/// Everything that runs on the per-CPU kernel stack.
///
/// Reached only via the stack switch at the end of [`kvm_long_mode_entry`],
/// with `%rsp` inside this core's `PerCpuVariables::kernel_stack`.
extern "C" fn kernel_main(usable: u64, ram_end_pa: u64, mapped_limit: u64) -> ! {
    // The XSAVE areas are allocated here rather than beside
    // `allocate_per_cpu_variables` for the reason the platform's own doc
    // comment gives: the CPUID queries and `avec!` allocations use more stack
    // than the boot stack has. LVBS likewise defers this into `init()`.
    litebox_platform_lvbs::host::per_cpu_variables::allocate_xsave_area();

    // GDT and TSS first: `syscall_entry::init` reads the segment selectors
    // back out of per-CPU state to program STAR, and the IDT's double-fault
    // gate refers to TSS.IST1.
    litebox_platform_lvbs::arch::gdt::init();

    // The IDT. From here on a fault is a reportable event rather than a
    // silent triple fault.
    litebox_platform_lvbs::arch::interrupts::init_idt();

    // Mask the legacy 8259 PICs. Ring 0 runs with interrupts off, but ring 3
    // does not: `PtRegs::sanitize_for_user_return` forces EFLAGS.IF on before
    // every user entry, and rightly so -- a user thread that could not be
    // interrupted would be unkillable by design rather than by omission.
    //
    // The PICs come out of QEMU's firmware with IRQ0 (the PIT) unmasked and
    // the master's vector base still at its power-on default of 0x08, which
    // collides with the architectural exception vectors. So the first timer
    // tick after entering ring 3 is delivered as vector 8 -- through the
    // *double-fault* gate. That is exactly what happened on the first attempt
    // to run ldelf: `-d int` showed `Servicing hardware INT=0x08 ... cpl=3` at
    // ldelf's entry point, and the shim dutifully killed the thread for taking
    // a #DF before it executed a single instruction.
    //
    // Masking is the correct fix rather than remapping: nothing here services
    // 8259 interrupts, there is no LAPIC bring-up, and running a TA needs
    // none.
    // Remapping would only move the collision somewhere quieter while leaving
    // unhandled interrupts arriving.
    //
    // The PIT itself is left running -- it is not a source of IRQs once the
    // PIC is masked, and `pit_reference_interval_nanos` uses channel 2, which
    // is gated by port 0x61 and raises no IRQ at all.
    mask_legacy_pics();

    // LSTAR / SFMASK / STAR. Requires the GDT, hence the ordering.
    litebox_platform_lvbs::Platform::enable_syscall_support();

    // SMEP and SMAP. Not a nicety: Phase 1 made VSM page protection a no-op
    // under `host_kvm` on the grounds that the real boundary is ring 0 vs
    // ring 3, "enforced by page tables, SMEP/SMAP and the syscall gate".
    // Until this call existed that claim was false on this path.
    litebox_platform_lvbs::arch::enable_smep_smap();

    check_crng();
    check_heap(usable, mapped_limit);
    check_cpu_state();
    check_interrupts();

    // The real page tables. Everything above ran on the early 2 MiB boot
    // mapping; everything below runs on 4 KiB tables with DEP.
    init_platform(ram_end_pa);

    check_address_space();
    check_data_access();
    check_text_is_read_only();

    // Discovery only: enumerate the PCI bus and report any virtio devices.
    // Nothing is written to configuration space and no BAR is mapped, so this
    // cannot change the behaviour of anything below it.
    pci::log_virtio_devices();

    // The point of the whole phase: load and execute an OP-TEE TA in ring 3.
    // Everything above is the platform this needs.
    ta::run();

    // Last, because it is not recoverable: an instruction-fetch fault leaves
    // RIP on the data page, which no exception-table entry can name. See
    // `check_nx_is_enforced`, which ends the guest through the panic handler.
    check_nx_is_enforced();
}

// ---------------------------------------------------------------------------
// Bring-up verification.
//
// Each check below is written to fail loudly and visibly rather than to pass
// quietly. An IDT that is silently wrong presents during TA execution as an
// inexplicable triple fault during TA execution, with no indication of which
// layer to suspect; the point of these is to remove that ambiguity now, while
// exactly one thing has just changed.
// ---------------------------------------------------------------------------

/// Data port of the master 8259 PIC; with ICW initialisation complete this is
/// the interrupt mask register.
const PIC1_DATA_PORT: u16 = 0x21;
/// Data port of the slave 8259 PIC.
const PIC2_DATA_PORT: u16 = 0xA1;

/// Masks every IRQ line on both 8259 PICs.
///
/// See the call site in [`kernel_main`] for why this is necessary.
fn mask_legacy_pics() {
    // SAFETY: writes 0xFF to the two PIC interrupt-mask registers. Masking
    // every line is always a legal state for the device and cannot fault; no
    // memory is touched.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") PIC1_DATA_PORT,
            in("al") 0xFF_u8,
            options(nomem, nostack, preserves_flags),
        );
        core::arch::asm!(
            "out dx, al",
            in("dx") PIC2_DATA_PORT,
            in("al") 0xFF_u8,
            options(nomem, nostack, preserves_flags),
        );
    }
    log::info!("pic        legacy 8259 IRQs masked");
}

/// CR4.SMEP.
const CR4_SMEP: u64 = 1 << 20;
/// CR4.SMAP.
const CR4_SMAP: u64 = 1 << 21;
/// CR4.FSGSBASE.
const CR4_FSGSBASE: u64 = 1 << 16;

/// Reads CR4.
fn read_cr4() -> u64 {
    let cr4: u64;
    // SAFETY: reading CR4 into a register has no side effects.
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
    }
    cr4
}

/// Reads GSBASE with `rdgsbase`.
fn read_gsbase() -> u64 {
    let gsbase: u64;
    // SAFETY: `rdgsbase` is enabled (CR4.FSGSBASE was set by
    // `enable_fsgsbase` before any per-CPU state was allocated, and is
    // asserted below); it only reads a register.
    unsafe {
        core::arch::asm!("rdgsbase {}", out(reg) gsbase, options(nomem, nostack, preserves_flags));
    }
    gsbase
}

/// Reads `kernel_stack_ptr` through `%gs`, exactly as the platform's own
/// assembly does.
///
/// Read this way rather than through an accessor so that the check exercises
/// the same addressing mode the syscall and exception entry paths use: a
/// getter would prove the field's value, but not that `gs:[offset]` reaches
/// it.
fn read_gs_kernel_stack_ptr() -> u64 {
    let sp: u64;
    // SAFETY: GSBASE points at this core's `PerCpuVariables`, whose first
    // field is `PerCpuVariablesAsm`, whose `kernel_stack_ptr` sits at this
    // offset. The load is 8 bytes from a naturally aligned `Cell<usize>`.
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[{off}]",
            out(reg) sp,
            off = const { PerCpuVariablesAsm::kernel_stack_ptr_offset() },
            options(nostack, preserves_flags, readonly),
        );
    }
    sp
}

/// Checks GSBASE, the kernel stack switch, and CR4's protection bits.
fn check_cpu_state() {
    use litebox_platform_lvbs::host::per_cpu_variables::with_per_cpu_variables;

    // 1. GSBASE. `rdgsbase` must return this core's `PerCpuVariables`, which
    //    is a `#[repr(C, align(4096))]` heap allocation in the high-canonical
    //    kernel alias. A zero or low value means `wrgsbase` never took, and
    //    every `gs:`-relative access the platform's assembly makes -- syscall
    //    entry included -- would be reading whatever sits at that address.
    let gsbase = read_gsbase();
    let via_helper = with_per_cpu_variables(|pcv| (&raw const *pcv) as u64);
    log::info!("gsbase     {gsbase:#018X} (per-CPU variables)");
    assert_ne!(gsbase, 0, "GSBASE is zero: wrgsbase did not take");
    assert_eq!(
        gsbase, via_helper,
        "GSBASE disagrees with with_per_cpu_variables"
    );
    assert!(
        gsbase >= KERNEL_OFFSET,
        "GSBASE {gsbase:#018X} is not in the high-canonical kernel alias"
    );
    assert_eq!(gsbase % 4096, 0, "PerCpuVariables is not page-aligned");

    // 2. The stack switch. RSP must lie inside the per-CPU kernel stack, i.e.
    //    below the stored `kernel_stack_ptr` and within one stack's length of
    //    it -- and, critically, *nowhere near* the boot stack in the scratch
    //    region, which is what we just stopped using.
    let rsp: u64;
    // SAFETY: reading RSP into a register has no side effects.
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags));
    }
    let stack_top = read_gs_kernel_stack_ptr();
    log::info!(
        "kstack     rsp {rsp:#018X}, top {stack_top:#018X}, used {} B",
        stack_top.saturating_sub(rsp)
    );
    assert!(
        rsp <= stack_top && stack_top - rsp < KERNEL_STACK_SIZE as u64,
        "RSP {rsp:#018X} is not inside the per-CPU kernel stack (top {stack_top:#018X})"
    );
    let boot_stack_top = boot::former_stack_range().1 + KERNEL_OFFSET;
    assert!(
        rsp > boot_stack_top || boot_stack_top - rsp > (1 << 20),
        "RSP {rsp:#018X} is still on the boot stack"
    );

    // 3. CR4. SMEP and SMAP are the load-bearing bits: with them clear, the
    //    ring-0/ring-3 boundary Phase 1 leans on is not actually enforced by
    //    anything. `enable_smep_smap` asserts CPUID support before setting
    //    them, so reaching here with them clear would mean the write itself
    //    was dropped.
    let cr4 = read_cr4();
    log::info!(
        "cr4        {cr4:#018X} (SMEP {}, SMAP {}, FSGSBASE {})",
        if cr4 & CR4_SMEP != 0 { "set" } else { "CLEAR" },
        if cr4 & CR4_SMAP != 0 { "set" } else { "CLEAR" },
        if cr4 & CR4_FSGSBASE != 0 {
            "set"
        } else {
            "CLEAR"
        },
    );
    assert!(
        cr4 & CR4_SMEP != 0,
        "CR4.SMEP is clear: the kernel can execute ring-3 pages"
    );
    assert!(
        cr4 & CR4_SMAP != 0,
        "CR4.SMAP is clear: the kernel can read ring-3 pages"
    );
    assert!(cr4 & CR4_FSGSBASE != 0, "CR4.FSGSBASE is clear");

    // 4. SMAP enforcement is *not* tested here, deliberately. Proving it
    //    requires a page with the USER bit set, and there is none: the early
    //    2 MiB tables built by the boot stub use flags 0x83
    //    (PRESENT|WRITABLE|HUGE) throughout, with USER clear on every entry.
    //    `ta::check_smap` confirms enforcement later, once ldelf has created
    //    a real user mapping: a kernel read of it faults with CR4.SMAP set
    //    and succeeds between `stac`/`clac`. Inventing a user mapping here to
    //    test against would prove only that the test's own mapping works.
    log::warn!(
        "smap       enforcement untested here: no USER-accessible page exists yet (see ta::check_smap)"
    );
}

/// A magic value carried across the `int3` to show the ISR stub's register
/// restore is correct, not merely that the handler ran.
const BP_WITNESS: u64 = 0x5EED_1234_ABCD_F00D;

/// Triggers a breakpoint and a page fault and confirms both are reported.
fn check_interrupts() {
    // 1. `int3`. The handler logs and returns, so this exercises the whole
    //    round trip: IDT gate -> `isr_breakpoint` -> `push_regs` -> Rust
    //    handler -> `pop_regs` -> `iretq` -> here. A callee-clobbered
    //    register is loaded with a witness value across the trap: if
    //    `pop_regs` restored the wrong slots, or the stub's `add rsp, 8`
    //    error-code fixup were wrong, this comes back corrupted (or we never
    //    come back at all). That return path is exactly what the TA's
    //    ring-3 exception handling depends on.
    log::info!("int3       triggering breakpoint...");
    let witness: u64;
    // SAFETY: vector 3 is present in the IDT loaded above, and under
    // `host_kvm` its handler logs and returns rather than panicking. `int3`
    // itself has no effect beyond the trap.
    //
    // Deliberately *not* `options(nostack)`. Vector 3 is a same-privilege trap
    // gate, so the CPU pushes five words (SS, RSP, RFLAGS, CS, RIP) onto the
    // current `%rsp` rather than switching stacks, and the handler runs on top
    // of them. `nostack` promises the asm neither writes below `%rsp` nor
    // pushes, and this does both, so the annotation was simply untrue. Nothing
    // is corrupted today only because the KVM target spec sets
    // `"disable-redzone": true` and so leaves nothing below `%rsp` to clobber
    // -- a property no comment here referenced and which the annotation should
    // not be silently relying on. Dropping it costs nothing.
    unsafe {
        core::arch::asm!("int3", inlateout("r12") BP_WITNESS => witness);
    }
    log::info!("int3       returned, witness {witness:#018X}");
    assert_eq!(
        witness, BP_WITNESS,
        "register state was corrupted across the breakpoint"
    );

    // 2. A deliberate fault at an unmapped address.
    //
    //    Note this is *not* a null read, despite the task asking for one: a
    //    null read does not fault here. PML4[0] identity-maps the low 1 GiB
    //    (the boot stub cannot survive enabling paging without it), so VA 0 is
    //    a perfectly good mapping and reading it would prove nothing. Reading
    //    through the high-canonical alias of PA 0x8000_0000 -- beyond the 1
    //    GiB the PD covers -- is genuinely unmapped, so the fault is
    //    unambiguous and CR2 is checkable against a value we chose.
    //
    //    `read_u64_fallible` registers the load in `.ex_table`, so
    //    `kernel_exception_handler_no_ctx` finds a fixup and, under
    //    `host_kvm`, logs CR2, the error code and the faulting RIP before
    //    patching the saved RIP and `iretq`-ing. That proves the #PF gate,
    //    `kernel_exception_callback`, the exception table and the resume
    //    path, and it leaves the kernel running so the boot log completes.
    let unmapped = (KERNEL_OFFSET + UNMAPPED_PROBE_PA) as *const u64;
    log::info!("pf         reading unmapped {:#018X}...", unmapped as u64);
    // SAFETY: this is precisely what `read_u64_fallible` exists for -- the
    // pointer is expected to fault, and the fault is recovered through the
    // exception table rather than propagating.
    let result = unsafe { litebox::mm::exception_table::read_u64_fallible(unmapped) };
    match result {
        Ok(v) => panic!(
            "read of unmapped {:#018X} succeeded, returned {v:#X}",
            unmapped as u64
        ),
        Err(_) => log::info!("pf         faulted and recovered as expected"),
    }

    // 3. A null read is deliberately *not* attempted here. PA 0 is still
    //    mapped at this point (PML4[0] identity-maps the low 1 GiB, and the
    //    boot stub needs that to survive enabling paging), so it would not
    //    fault and would prove nothing. `check_address_space` retries it
    //    after the real page tables are loaded, where PML4[0] is empty.
    log::info!(
        "pf         VA 0 still mapped by the early identity map; retried after the CR3 switch"
    );
}

/// A physical address beyond the 1 GiB the early PD covers, used to provoke a
/// page fault at an address that cannot be mapped by accident.
const UNMAPPED_PROBE_PA: u64 = 0x8000_0000;

// ---------------------------------------------------------------------------
// The real page tables.
//
// Everything above this point ran on the early 2 MiB tables the boot stub
// built: an identity map of the low 1 GiB plus the same 1 GiB again at
// `KERNEL_OFFSET`, every leaf `PRESENT | WRITABLE | HUGE`. That mapping has no
// DEP, no read-only text, and maps VA 0.
//
// `Platform::new` replaces it with 4 KiB tables covering the guest's physical
// memory once, at `PA + KERNEL_OFFSET` only, with `.text` mapped
// read-only-executable and every other page `NO_EXECUTE`. The identity map
// disappears with it, which is what finally unmaps VA 0.
// ---------------------------------------------------------------------------

/// Page-table entry bits, named so the walk below reads as prose.
const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITABLE: u64 = 1 << 1;
const PTE_USER: u64 = 1 << 2;
const PTE_HUGE: u64 = 1 << 7;
const PTE_NO_EXECUTE: u64 = 1 << 63;
/// The physical-address field of a page-table entry (bits 51:12).
const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// CR0.WP: honour the read-only bit for supervisor writes.
const CR0_WP: u64 = 1 << 16;

/// The result of a software page-table walk.
#[derive(Clone, Copy)]
struct Translation {
    /// Physical address the virtual address maps to.
    pa: u64,
    /// The leaf entry, for its flag bits.
    pte: u64,
    /// Level the walk terminated at: 1 for a 4 KiB page, 2 for 2 MiB, 3 for
    /// 1 GiB.
    level: u32,
}

impl core::fmt::Display for Translation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "pa {:#014X} {} [{}{}{}]",
            self.pa,
            match self.level {
                1 => "4K",
                2 => "2M",
                _ => "1G",
            },
            if self.pte & PTE_WRITABLE != 0 {
                "W"
            } else {
                "r"
            },
            if self.pte & PTE_NO_EXECUTE != 0 {
                "N"
            } else {
                "X"
            },
            if self.pte & PTE_USER != 0 { "U" } else { "s" },
        )
    }
}

/// Reads CR3.
fn read_cr3() -> u64 {
    let cr3: u64;
    // SAFETY: reading CR3 into a register has no side effects.
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }
    cr3
}

/// Reads CR0.
fn read_cr0() -> u64 {
    let cr0: u64;
    // SAFETY: reading CR0 into a register has no side effects.
    unsafe {
        core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
    }
    cr0
}

/// Walks the page tables currently in CR3 in software and reports what `va`
/// translates to, or `None` if it is unmapped at some level.
///
/// This exists because "we did not triple-fault" is the only other evidence
/// available that a mapping is what it was meant to be, and it arrives too
/// late to be useful. Reading the tables directly turns a claim about page
/// permissions into a printed number.
///
/// Table frames are reached through the `KERNEL_OFFSET` alias, which both the
/// early tables (for the low 1 GiB) and the new tables (for all of RAM) map.
fn walk(va: u64) -> Option<Translation> {
    let mut table = read_cr3() & PTE_ADDR_MASK;
    let mut level = 4_u32;

    loop {
        let shift = 12 + 9 * (level - 1);
        let index = (va >> shift) & 0x1FF;
        let entry_va = table + KERNEL_OFFSET + index * 8;
        // SAFETY: `table` is a page-table frame physical address, taken from
        // CR3 or from a present entry of the level above, so it is a real
        // 4 KiB-aligned frame inside guest RAM and is mapped read/write
        // through `KERNEL_OFFSET`. `index` is masked to 0..512, so the read
        // stays inside that frame. `read_volatile` keeps the compiler from
        // caching entries across the CR3 switch.
        let entry = unsafe { (entry_va as *const u64).read_volatile() };

        if entry & PTE_PRESENT == 0 {
            return None;
        }

        // Level 1 entries are always leaves; above that, PS/HUGE marks one.
        if level == 1 || entry & PTE_HUGE != 0 {
            let page_mask = (1_u64 << shift) - 1;
            return Some(Translation {
                pa: (entry & PTE_ADDR_MASK & !page_mask) | (va & page_mask),
                pte: entry,
                level,
            });
        }

        table = entry & PTE_ADDR_MASK;
        level -= 1;
    }
}

/// Scans the page tables for the first mapped page whose leaf entry has the
/// USER bit set, and returns its virtual address.
///
/// The whole table is scanned, kernel entries included, and the result is
/// asserted to be in the lower half. Restricting the scan instead would hide
/// exactly the bug worth catching: a kernel page that had USER set would be
/// skipped silently rather than tripping the assertion.
///
/// The USER bit must be set at *every* level for the hardware to grant user
/// access, so the walk requires it all the way down rather than only at the
/// leaf. Reporting a leaf whose parent withheld USER would be reporting a page
/// the CPU does not in fact consider user-accessible.
fn first_user_page() -> Option<u64> {
    /// Recursive descent through one table. `base_va` is the virtual address
    /// the first entry of this table covers, sign-extended by the caller at
    /// the top level.
    fn descend(table_pa: u64, level: u32, base_va: u64) -> Option<u64> {
        let shift = 12 + 9 * (level - 1);
        for index in 0..512_u64 {
            let entry_va = table_pa + KERNEL_OFFSET + index * 8;
            // SAFETY: `table_pa` is a page-table frame physical address taken
            // from CR3 or from a present non-leaf entry, so it is a real 4 KiB
            // frame inside guest RAM, mapped read/write through
            // `KERNEL_OFFSET`. `index` stays inside the frame.
            let entry = unsafe { (entry_va as *const u64).read_volatile() };
            if entry & PTE_PRESENT == 0 || entry & PTE_USER == 0 {
                continue;
            }
            let va = base_va + (index << shift);
            if level == 1 || entry & PTE_HUGE != 0 {
                return Some(va);
            }
            if let Some(found) = descend(entry & PTE_ADDR_MASK, level - 1, va) {
                return Some(found);
            }
        }
        None
    }

    descend(read_cr3() & PTE_ADDR_MASK, 4, 0).inspect(|&va| {
        // Lower half only, so no sign extension is needed; assert that rather
        // than assume it.
        assert!(
            va < (1 << 47),
            "user page {va:#018X} is not in the lower half"
        );
    })
}

/// The `.text` section's bounds, as virtual addresses.
///
/// Taken with RIP-relative `lea`s for the same reason [`heap_start_pa`] does:
/// this must not depend on an absolute address. The platform's own
/// `get_text_start_address` is unavailable here -- it lives in the `mshv`
/// module, which Phase 1 gated out entirely under `host_kvm` -- but the linker
/// symbols themselves are defined identically by `x86_64_kvm.ld`.
fn text_va_range() -> (u64, u64) {
    unsafe extern "C" {
        static _text_start: u8;
        static _text_end: u8;
    }

    let start: u64;
    let end: u64;
    // SAFETY: `lea` with RIP-relative operands only computes addresses into
    // registers; it reads no memory and touches no flags.
    unsafe {
        core::arch::asm!(
            "lea {s}, [rip + _text_start]",
            "lea {e}, [rip + _text_end]",
            s = out(reg) start,
            e = out(reg) end,
            options(nostack, nomem, preserves_flags)
        );
    }
    (start, end)
}

/// The `.rela.dyn` section's bounds, as virtual addresses.
fn rela_va_range() -> (u64, u64) {
    unsafe extern "C" {
        static _rela_start: u8;
        static _rela_end: u8;
    }

    let start: u64;
    let end: u64;
    // SAFETY: as `text_va_range`.
    unsafe {
        core::arch::asm!(
            "lea {s}, [rip + _rela_start]",
            "lea {e}, [rip + _rela_end]",
            s = out(reg) start,
            e = out(reg) end,
            options(nostack, nomem, preserves_flags)
        );
    }
    (start, end)
}

/// Reads the GDTR with `sgdt`.
fn read_gdtr_base() -> u64 {
    /// The 10-byte pseudo-descriptor `sgdt`/`sidt` store.
    #[repr(C, packed)]
    struct Pseudo {
        limit: u16,
        base: u64,
    }

    let mut p = Pseudo { limit: 0, base: 0 };
    // SAFETY: `sgdt` writes exactly ten bytes to the given address, which is a
    // live, correctly sized local.
    unsafe {
        core::arch::asm!("sgdt [{}]", in(reg) &raw mut p, options(nostack, preserves_flags));
    }
    p.base
}

/// Reads the IDTR with `sidt`.
fn read_idtr_base() -> u64 {
    #[repr(C, packed)]
    struct Pseudo {
        limit: u16,
        base: u64,
    }

    let mut p = Pseudo { limit: 0, base: 0 };
    // SAFETY: as `read_gdtr_base`.
    unsafe {
        core::arch::asm!("sidt [{}]", in(reg) &raw mut p, options(nostack, preserves_flags));
    }
    p.base
}

/// A `.data` object written by [`check_data_access`], so that the data path is
/// exercised on a page that is neither the heap nor the stack.
static DATA_PROBE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Constructs the real platform and switches to its page tables.
///
/// # The ranges
///
/// `phys_start` is 0 and `phys_end` is one past the highest usable-RAM address
/// the PVH memory map described (clamped to the 1 GiB the early tables reach,
/// which with `-m 512M` loses nothing). The range therefore covers, in one
/// span, every physical page anything currently in use lives on: the loaded
/// image, the boot scratch region, and all of the heap. Starting at 0 rather
/// than at the image costs 2 MiB of mappings and removes an entire class of
/// "that PA was just outside the range" failure.
///
/// Nothing is mapped at VA 0 as a result: the new tables map physical memory
/// exactly once, at `PA + KERNEL_OFFSET`, so PML4[0] is left empty and the
/// early identity map ceases to exist the moment CR3 changes.
///
/// # The CR3 switch
///
/// `Platform::new` builds the tables *and* loads them; there is no window in
/// which the caller can inspect the new PML4 before it becomes live. So the
/// verification below is done the other way round: for each address that must
/// survive the switch, walk the *current* tables, confirm they translate it to
/// `VA - KERNEL_OFFSET`, and confirm that physical address lies inside
/// `[phys_start, phys_end)`. Since the new tables map that whole range at
/// exactly `PA + KERNEL_OFFSET`, coverage of the range is coverage of the
/// address.
///
/// # Panics
///
/// Panics if any address that must survive the switch is not covered, rather
/// than letting the switch triple-fault.
fn init_platform(ram_end_pa: u64) -> &'static Platform {
    let (text_va_start, text_va_end) = text_va_range();
    let text_phys_start = Platform::va_to_pa(x86_64::VirtAddr::new(text_va_start));
    let text_phys_end = Platform::va_to_pa(x86_64::VirtAddr::new(text_va_end));

    let phys_start = x86_64::PhysAddr::new(0);
    let phys_end = x86_64::PhysAddr::new(ram_end_pa);

    log::info!(
        "pt         phys {:#014X}..{:#014X} ({} MiB)",
        phys_start.as_u64(),
        phys_end.as_u64(),
        (phys_end.as_u64() - phys_start.as_u64()) / (1024 * 1024)
    );
    log::info!(
        "pt         text va {text_va_start:#018X}..{text_va_end:#018X} -> pa {:#014X}..{:#014X}",
        text_phys_start.as_u64(),
        text_phys_end.as_u64()
    );

    // Everything that must remain addressable across the CR3 switch. Named
    // individually because a merged list cannot be reviewed, and because a
    // missing entry here is a triple fault with no output.
    let rsp: u64;
    let rip: u64;
    // SAFETY: both only copy a register (or a RIP-relative address) into
    // another register.
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags));
        core::arch::asm!("lea {}, [rip + 0]", out(reg) rip, options(nomem, nostack, preserves_flags));
    }
    let heap_probe = alloc::boxed::Box::new(0_u64);
    let must_stay_mapped = [
        ("rip (.text)", rip),
        (".text start", text_va_start),
        (".text end-1", text_va_end - 1),
        (".data probe", (&raw const DATA_PROBE) as u64),
        (".bss (per-cpu ptr)", read_gsbase()),
        ("rsp (kernel stack)", rsp),
        ("gdt", read_gdtr_base()),
        ("idt", read_idtr_base()),
        ("heap", (&raw const *heap_probe) as u64),
        ("page tables (cr3)", read_cr3() & PTE_ADDR_MASK),
    ];

    for (name, va) in must_stay_mapped {
        // CR3 is a physical address, not a virtual one; normalise it into the
        // alias so one loop covers both kinds.
        let va = if va < KERNEL_OFFSET {
            va + KERNEL_OFFSET
        } else {
            va
        };
        let translation = walk(va).unwrap_or_else(|| {
            panic!("{name} at {va:#018X} is not mapped even by the early tables")
        });
        log::info!("pt keep    {name:<20} va {va:#018X} -> {translation}");
        assert_eq!(
            translation.pa,
            va - KERNEL_OFFSET,
            "{name} at {va:#018X} is not in the KERNEL_OFFSET alias, so the new \
             tables will not map it"
        );
        assert!(
            translation.pa >= phys_start.as_u64() && translation.pa < phys_end.as_u64(),
            "{name} at pa {:#014X} is outside the range the new tables will map",
            translation.pa
        );
    }
    drop(heap_probe);

    // CR0.WP. Without it, the read-only `.text` mapping `Platform::new` is
    // about to install is advisory: a supervisor write to a read-only page
    // succeeds silently when WP is clear, which is how the CPU comes out of
    // reset and how PVH leaves us. LVBS never sets this bit because the
    // hypervisor hands VTL1 a CR0 that already has it; on KVM nobody does.
    //
    // Set before the switch, so there is no interval in which text is nominally
    // read-only and actually writable.
    let cr0 = read_cr0();
    log::info!(
        "cr0        {cr0:#018X} (WP {})",
        if cr0 & CR0_WP != 0 { "set" } else { "CLEAR" }
    );
    if cr0 & CR0_WP == 0 {
        // SAFETY: setting CR0.WP only makes supervisor writes honour the
        // read-only bit. Nothing on this path writes to a read-only mapping;
        // the early tables mark every page writable, so no existing access
        // can start faulting.
        unsafe {
            core::arch::asm!(
                "mov cr0, {}",
                in(reg) cr0 | CR0_WP,
                options(nomem, nostack, preserves_flags)
            );
        }
        log::info!("cr0        {:#018X} (WP set)", read_cr0());
    }

    // The switch. `Platform::new` maps the range with DEP, enables EFER.NXE
    // and loads CR3 before returning.
    let platform = Platform::new(phys_start, phys_end, text_phys_start, text_phys_end);
    log::info!("pt         new tables live, cr3 {:#014X}", read_cr3());

    // Reclaim `.rela.dyn`. The relocations were applied by
    // `boot::apply_relocations` before any static was read, and nothing consults the
    // table afterwards. The bounds are rounded inwards to whole pages: the
    // section starts 2 MiB aligned but its end is not aligned to anything.
    let (rela_va_start, rela_va_end) = rela_va_range();
    let rela_start = rela_va_start.next_multiple_of(4096);
    let rela_end = rela_va_end - rela_va_end % 4096;
    if rela_end > rela_start {
        let size = rela_end - rela_start;
        // SAFETY: `.rela.dyn` is dead once relocations are applied, so nothing
        // references these pages. They lie inside the physical range just
        // mapped read/write, and the memory map withheld them from the heap
        // (they are below `_heap_start`), so this is the only claim on them.
        unsafe {
            Platform::mem_fill_pages(
                usize::try_from(rela_start).expect("64-bit target"),
                usize::try_from(size).expect("64-bit target"),
            );
        }
        log::info!("heap       reclaim .rela.dyn va {rela_start:#018X}, size {size:#X}");
    }

    litebox_platform_multiplex::set_platform(platform);
    litebox_platform_lvbs::set_platform_low(platform);
    log::info!("platform   registered with the multiplexer");

    platform
}

/// Walks the *new* tables for the same addresses [`init_platform`] checked,
/// and confirms VA 0 has gone away.
fn check_address_space() {
    let (text_va_start, text_va_end) = text_va_range();
    let rsp: u64;
    // SAFETY: reading RSP into a register has no side effects.
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags));
    }

    // 1. `.text` must be present, executable and *not* writable. The W^X rule
    //    lives in `map_phys_frame_range`, which clears WRITABLE for any frame
    //    inside an exec range; this is the check that it actually did.
    for (name, va) in [
        ("text start", text_va_start),
        ("text end-1", text_va_end - 1),
    ] {
        let t = walk(va).unwrap_or_else(|| panic!("{name} {va:#018X} is unmapped"));
        log::info!("pt now     {name:<16} va {va:#018X} -> {t}");
        assert_eq!(t.level, 1, "{name} is not mapped with 4 KiB pages");
        assert!(
            t.pte & PTE_NO_EXECUTE == 0,
            "{name} is NO_EXECUTE: the kernel cannot run"
        );
        assert!(
            t.pte & PTE_WRITABLE == 0,
            "{name} is writable: W^X is not being applied to .text"
        );
    }

    // 2. Everything that is not `.text` must be NO_EXECUTE. This is the DEP
    //    guarantee stated as a page-table fact rather than as an intention.
    let heap_probe = alloc::boxed::Box::new(0_u64);
    for (name, va) in [
        (".data", (&raw const DATA_PROBE) as u64),
        ("per-cpu / stack", rsp),
        ("heap", (&raw const *heap_probe) as u64),
    ] {
        let t = walk(va).unwrap_or_else(|| panic!("{name} {va:#018X} is unmapped"));
        log::info!("pt now     {name:<16} va {va:#018X} -> {t}");
        assert!(
            t.pte & PTE_NO_EXECUTE != 0,
            "{name} is executable: DEP is not being applied"
        );
        assert!(t.pte & PTE_WRITABLE != 0, "{name} is not writable");
        assert!(
            t.pte & PTE_USER == 0,
            "{name} is user-accessible: SMAP/SMEP would be bypassable"
        );
    }
    drop(heap_probe);

    // 3. VA 0. The early identity map is gone, so PML4[0] is empty and a null
    //    dereference finally faults. This needed no work of its own: it is a
    //    consequence of mapping physical memory only at `PA + KERNEL_OFFSET`.
    assert!(walk(0).is_none(), "VA 0 is still mapped");
    log::info!("pt now     VA 0 is unmapped");

    log::info!("null       reading VA 0...");
    // SAFETY: this is exactly what `read_u64_fallible` exists for: the pointer
    // is expected to fault and the fault is recovered through the exception
    // table rather than propagating.
    let result = unsafe { litebox::mm::exception_table::read_u64_fallible(core::ptr::null()) };
    assert!(
        result.is_err(),
        "a read of VA 0 succeeded: page zero is still mapped"
    );
    log::info!("null       faulted and recovered as expected");
}

/// Confirms the new tables did not break ordinary data access.
///
/// A DEP change that also broke normal reads and writes would show up as
/// something far more confusing later, so each of the three kinds of writable
/// memory is written and read back here.
fn check_data_access() {
    use core::sync::atomic::Ordering;

    // 1. `.data`.
    DATA_PROBE.store(0x0123_4567_89AB_CDEF, Ordering::SeqCst);
    let data = DATA_PROBE.load(Ordering::SeqCst);
    assert_eq!(data, 0x0123_4567_89AB_CDEF, ".data write did not stick");

    // 2. The stack. `black_box` keeps the round trip from being folded away.
    let mut on_stack = [0_u64; 16];
    for (i, slot) in on_stack.iter_mut().enumerate() {
        *slot = (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }
    let stack_sum = core::hint::black_box(&on_stack)
        .iter()
        .fold(0_u64, |a, x| a.wrapping_add(*x));

    // 3. The heap, through a fresh allocation large enough to come from the
    //    buddy allocator rather than a slab that was already warm.
    let mut heap: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(256 * 1024);
    heap.resize(256 * 1024, 0x5A);
    heap[0] = 0x11;
    heap[256 * 1024 - 1] = 0x22;
    assert!(
        heap[1..256 * 1024 - 1].iter().all(|&b| b == 0x5A),
        "heap write did not survive the CR3 switch"
    );

    log::info!(
        "data ok    .data {data:#018X}, stack sum {stack_sum:#018X}, heap {:#018X} ends {:#04X}/{:#04X}",
        heap.as_ptr() as u64,
        heap[0],
        heap[256 * 1024 - 1]
    );
}

/// Proves `.text` is read-only: a supervisor write to it faults.
///
/// Recovered through the exception table so boot continues. The handler under
/// `host_kvm` prints CR2, the error code and the faulting RIP on the recovery
/// path, which is the actual evidence.
fn check_text_is_read_only() {
    let (text_va_start, _) = text_va_range();
    // Aim at the middle of the first text page rather than at byte zero, so a
    // "wrote to the wrong thing entirely" bug cannot look like a pass.
    let target = (text_va_start + 0x40) as *mut u8;

    log::info!("wx         writing to .text at {:#018X}...", target as u64);
    // SAFETY: the write is expected to fault, and `write_u8_fallible`
    // registers it in `.ex_table` so the fault is recovered rather than
    // propagating. If it does *not* fault the assertion below fires; the byte
    // written is the one already there, so even that case leaves `.text`
    // unchanged.
    let existing = unsafe { core::ptr::read_volatile(target) };
    let result = unsafe { litebox::mm::exception_table::write_u8_fallible(target, existing) };
    assert!(
        result.is_err(),
        "a write to .text at {:#018X} succeeded: W^X is not enforced",
        target as u64
    );
    log::info!("wx         .text write faulted and recovered as expected");
}

/// Address of the [`check_nx_is_enforced`] probe page, or 0 before it is
/// armed.
///
/// Read by [`panic`] to tell the run's expected ending from a real failure.
static NX_PROBE_ADDR: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Reads CR2, the address of the most recent page fault.
fn read_cr2() -> u64 {
    let cr2: u64;
    // SAFETY: reading CR2 into a register has no side effects.
    unsafe {
        core::arch::asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack, preserves_flags));
    }
    cr2
}

/// Proves NX is enforced: executing from a data page faults with the
/// instruction-fetch bit set in the error code.
///
/// This is the more important half of the DEP guarantee and the one that
/// cannot be recovered from. The exception table is keyed on the faulting RIP,
/// and on an instruction-fetch fault the faulting RIP *is* the data page --
/// an address no `.ex_table` entry can name, since entries store link-time
/// relative offsets. So there is no fixup to find and the handler panics,
/// after printing CR2, the error code and the RIP.
///
/// It is therefore the last thing the boot path does, and it is how a
/// successful run *ends*: [`panic`] recognises this specific fault -- by
/// comparing CR2, which is still the faulting address at that point, against
/// [`NX_PROBE_ADDR`] -- and exits with the success status rather than the
/// failure one. Any other panic, before or after, still fails.
///
/// The alternative -- skipping the check so the boot could end with a plain
/// `exit()` -- would leave DEP, the central guarantee of the page-table
/// rebuild, untested, and the
/// alternative to *that* -- hand-rolling a `longjmp` out of the panic handler
/// -- would add a page of register-restore assembly to save one log line.
fn check_nx_is_enforced() -> ! {
    // 0xC3 is `ret`. If NX were not enforced this would execute and return
    // cleanly, which is precisely the failure the assertion below reports.
    let mut code: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(4096);
    code.resize(4096, 0xC3);
    let entry = code.as_ptr() as u64;

    let t = walk(entry).expect("the code buffer is unmapped");
    log::info!("nx         heap buffer va {entry:#018X} -> {t}");
    assert!(
        t.pte & PTE_NO_EXECUTE != 0,
        "the heap page is not NO_EXECUTE; the probe would prove nothing"
    );

    log::info!("nx         calling into the heap buffer (expected: #PF, error code bit 4 set)");
    log::info!("nx         this is the last check; the fault ends the run");

    // Armed as late as possible: `panic` treats a fault at exactly this
    // address as the successful end of the run, so the window in which an
    // unrelated panic could be misreported is the two instructions below.
    NX_PROBE_ADDR.store(entry, core::sync::atomic::Ordering::SeqCst);

    // SAFETY: nothing about this is sound, and that is the point -- the call
    // is expected never to reach its target. The buffer is 4 KiB of `ret`, so
    // in the failure case (NX not enforced) the callee is a valid, ABI-correct
    // no-op function and control returns here to report it.
    let f: extern "C" fn() = unsafe { core::mem::transmute::<u64, extern "C" fn()>(entry) };
    f();

    panic!(
        "execution from the heap page at {entry:#018X} SUCCEEDED: NX is not enforced, \
         DEP is a fiction"
    );
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

/// Largest TSC-versus-PIT disagreement `check_clock` tolerates, in permille.
///
/// 10%, which is deliberately loose. Two things set the floor and the ceiling:
///
/// - Observed error is 1-2 permille (measured over repeated TCG runs), all of
///   it in one direction: `tsc_nanos` brackets the PIT interval and so also
///   contains the port-I/O polling around it, while `pit_nanos` is the
///   interval's exact *nominal* length and cannot move. So the check has
///   roughly 50x headroom over the noise it actually sees.
/// - The error is one-sided and, under TCG on a loaded machine, unbounded:
///   nothing stops the host descheduling the QEMU thread mid-interval, which
///   inflates `tsc_nanos` alone. A tight bound would turn that into a CI flake
///   while proving nothing extra.
///
/// 10% is still far below anything the assertion is meant to catch. The
/// smallest interesting failure is a frequency or conversion wrong by a factor
/// of two, which is 1000 permille -- ten times the limit.
const MAX_PIT_ERROR_PERMILLE: u64 = 100;

/// Nanoseconds between two [`Instant`]s.
fn elapsed_nanos(start: Instant, end: Instant) -> u64 {
    use litebox::platform::Instant as _;
    end.checked_duration_since(&start)
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
    let spin_nanos = elapsed_nanos(start, end);
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
    while elapsed_nanos(start, end) < CALIBRATED_WAIT_NANOS {
        core::hint::spin_loop();
        end = Instant::now();
    }
    log::info!("wait 1s    done, measured {} ns", elapsed_nanos(start, end));

    // Cross-check against the PIT: bracket one of its gated intervals with two
    // `Instant`s and compare what each clock says the interval was.
    //
    // How much this proves depends on which source won discovery, and the
    // honest answer is "less than it looks like under TCG":
    //
    // - If `tsc_source()` is *not* the PIT -- CPUID leaf 0x15/0x16, the KVM
    //   paravirt leaf, or pvclock -- then this is genuine independent
    //   evidence. The TSC scale came from one authority and the interval
    //   length from a different counter whose rate is fixed by the i8254's
    //   hardware definition, so a TSC frequency wrong by a factor of N shows
    //   up here as an error of N.
    // - If `tsc_source()` *is* "i8254 PIT calibration", which is the case
    //   under TCG and therefore in CI, the check is circular: the TSC scale
    //   was derived from this same PIT, so the comparison degenerates into an
    //   arithmetic self-check. It cannot detect a wrong frequency, because
    //   both sides move together.
    //
    // The bound below is asserted either way. Even in the degenerate case it
    // is worth having: it still catches a broken fixed-point tick-to-nanosecond
    // conversion (a wrong `SCALE_SHIFT`, a lost widening to u128, an overflow),
    // which is arithmetic downstream of the frequency and so does *not* cancel.
    let start = Instant::now();
    let pit_nanos = litebox_platform_lvbs::arch::clock::pit_reference_interval_nanos();
    let end = Instant::now();
    match pit_nanos {
        Some(pit_nanos) => {
            let tsc_nanos = elapsed_nanos(start, end);
            // Integer permille error, avoiding floating point.
            let error_permille =
                (tsc_nanos.abs_diff(pit_nanos)).saturating_mul(1000) / pit_nanos.max(1);
            log::info!(
                "pit check  pit {pit_nanos} ns vs tsc {tsc_nanos} ns, error {error_permille} permille"
            );
            assert!(
                error_permille <= MAX_PIT_ERROR_PERMILLE,
                "TSC and PIT disagree by {error_permille} permille (limit \
                 {MAX_PIT_ERROR_PERMILLE}): pit {pit_nanos} ns vs tsc {tsc_nanos} ns. \
                 The TSC scale (source: {}) is wrong, or the tick-to-nanosecond \
                 conversion is",
                litebox_platform_lvbs::arch::clock::tsc_source()
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

// ---------------------------------------------------------------------------
// Heap checks.
//
// "It did not panic" is not evidence that an allocator works. An allocator
// that hands out the same block twice, or memory it does not own, or that
// leaks every block, all survive a single `Box::new`. So each check below is
// chosen to fail loudly on a specific way of being wrong.
// ---------------------------------------------------------------------------

/// Elements pushed into the growth-test `Vec`. `Vec` doubles from a capacity
/// of 4, so this forces ten reallocations, crossing from the slab into the
/// buddy allocator on the way.
const HEAP_VEC_ELEMS: u64 = 4096;

/// Size of the oversized allocation. Larger than the slab's 2 MiB backing
/// page, so it cannot be served from a slab at all and must come straight
/// from the buddy allocator.
const HEAP_BIG_BYTES: usize = 3 * 1024 * 1024;

/// Size of the large-object allocation. `ZoneAllocator::MAX_BASE_ALLOC_SIZE`
/// is 256 bytes and `MAX_ALLOC_SIZE` is 128 KiB, so 64 KiB lands in the
/// large-object slab, whose refill path allocates a 2 MiB `LargeObjectPage`
/// from the buddy allocator.
const HEAP_LARGE_BYTES: usize = 64 * 1024;

/// Exercises the heap and prints enough to tell a working allocator from a
/// plausible-looking broken one.
fn check_heap(usable_bytes: u64, mapped_limit: u64) {
    use alloc::boxed::Box;
    use alloc::vec::Vec;

    // 1. Growth. Repeated reallocation is what shakes out an allocator that
    //    mishandles copy-and-free, and the checksum catches one that returns
    //    overlapping blocks: a `Vec` whose backing store was aliased would
    //    come back with the wrong sum, not merely the wrong length.
    let mut v: Vec<u64> = Vec::new();
    let mut caps = 0_u32;
    let mut last_cap = 0;
    for i in 0..HEAP_VEC_ELEMS {
        v.push(i.wrapping_mul(2_654_435_761));
        if v.capacity() != last_cap {
            last_cap = v.capacity();
            caps += 1;
        }
    }
    let checksum = v.iter().fold(0_u64, |a, x| a.rotate_left(7) ^ x);
    let expected = (0..HEAP_VEC_ELEMS).fold(0_u64, |a, i| {
        a.rotate_left(7) ^ i.wrapping_mul(2_654_435_761)
    });
    log::info!(
        "heap vec   len {} cap {} after {caps} reallocations, checksum {checksum:#018X}",
        v.len(),
        v.capacity()
    );
    assert_eq!(v.len() as u64, HEAP_VEC_ELEMS, "Vec lost elements");
    assert_eq!(checksum, expected, "Vec contents were corrupted");
    assert!(caps > 1, "Vec never reallocated; the test proved nothing");
    drop(v);

    // 2. The page path, both ways in.
    //
    //    A 64 KiB block exceeds the slab's 256-byte base class, so the zone
    //    allocator refills from a 2 MiB `LargeObjectPage` taken from the
    //    buddy allocator -- the case the LVBS comment warns needs >= 2 MB of
    //    backing. A 3 MiB block exceeds the slab's maximum outright and comes
    //    from the buddy allocator directly.
    //
    //    Both are written end to end and read back, because an allocator that
    //    returns a pointer to memory it does not actually own will happily
    //    return the pointer and only misbehave when the bytes are touched.
    let mut large: Vec<u8> = Vec::with_capacity(HEAP_LARGE_BYTES);
    large.resize(HEAP_LARGE_BYTES, 0xA5);
    large[0] = 0x11;
    large[HEAP_LARGE_BYTES - 1] = 0x22;
    log::info!(
        "heap large {HEAP_LARGE_BYTES} B at {:#018X}, ends {:#04X}/{:#04X}",
        large.as_ptr() as u64,
        large[0],
        large[HEAP_LARGE_BYTES - 1]
    );
    assert!(
        large[1..HEAP_LARGE_BYTES - 1].iter().all(|&b| b == 0xA5),
        "large-object slab allocation did not survive being written"
    );
    drop(large);

    let mut big: Vec<u8> = Vec::with_capacity(HEAP_BIG_BYTES);
    big.resize(HEAP_BIG_BYTES, 0x5A);
    big[0] = 0x33;
    big[HEAP_BIG_BYTES - 1] = 0x44;
    let big_ptr = big.as_ptr() as u64;
    log::info!(
        "heap big   {HEAP_BIG_BYTES} B at {big_ptr:#018X}, ends {:#04X}/{:#04X}",
        big[0],
        big[HEAP_BIG_BYTES - 1]
    );
    assert!(
        big[1..HEAP_BIG_BYTES - 1].iter().all(|&b| b == 0x5A),
        "buddy allocation did not survive being written"
    );

    // 3. Reuse. Free the 3 MiB block and allocate the same size again, over
    //    and over, enough times that the total *exceeds the whole heap*. If
    //    freed memory does not come back -- if the allocator is merely
    //    bumping a pointer and leaking -- the loop cannot complete: it runs
    //    out and the allocation error handler ends the guest. Completing it
    //    is direct evidence the free path works.
    //
    //    This is deliberately phrased as "the memory came back" rather than
    //    "the same address came back". Asserting address equality would test
    //    `SafeZoneAllocator`'s current placement strategy, not the property
    //    that matters, and would turn any future change of strategy into a
    //    boot panic misreported as a leak. The address is still logged, and
    //    is still the fastest hint when this does go wrong -- but only as an
    //    observation.
    drop(big);
    let rounds = (usable_bytes / HEAP_BIG_BYTES as u64).saturating_add(2);
    // Guards the check against passing vacuously: if `usable_bytes` were ever
    // reported as (near) zero, a handful of rounds would prove nothing.
    assert!(
        rounds.saturating_mul(HEAP_BIG_BYTES as u64) > usable_bytes,
        "the churn total does not exceed the heap; this would prove nothing"
    );
    assert!(
        rounds >= 16,
        "only {rounds} rounds: heap reported too small"
    );
    let mut first_reuse_ptr = 0_u64;
    for i in 0..rounds {
        let mut again: Vec<u8> = Vec::with_capacity(HEAP_BIG_BYTES);
        // Touch both ends -- but only the ends. Filling all 3 MiB every round
        // would mean memset-ing more than the whole heap in a debug build,
        // which costs minutes under QEMU and proves nothing the ends do not:
        // step 2 above already wrote and verified a whole block.
        let p = again.as_mut_ptr();
        // SAFETY: `p` owns `HEAP_BIG_BYTES` bytes of freshly allocated,
        // uninitialised capacity; writing byte 0 and byte `len - 1` is in
        // bounds. The length is left at 0, so nothing reads them as
        // initialised and the `Vec` still drops correctly.
        unsafe {
            p.write(0x77);
            p.add(HEAP_BIG_BYTES - 1).write(0x88);
            assert_eq!(p.read(), 0x77, "the reused block did not hold a write");
            assert_eq!(
                p.add(HEAP_BIG_BYTES - 1).read(),
                0x88,
                "the reused block did not hold a write"
            );
        }
        if i == 0 {
            first_reuse_ptr = p as u64;
        }
    }
    log::info!(
        "heap reuse {rounds} x {HEAP_BIG_BYTES} B churned ({} B total) against a {usable_bytes} B heap; \
         freed {big_ptr:#018X}, first reallocation {first_reuse_ptr:#018X} -- {}",
        rounds.saturating_mul(HEAP_BIG_BYTES as u64),
        if first_reuse_ptr == big_ptr {
            "same block"
        } else {
            "different block (fine: placement is the allocator's business)"
        }
    );

    // 4. Provenance. A `Box` is the smallest allocation there is, so it comes
    //    from the slab -- a different path from everything above. Its address
    //    must be high-canonical (we run in the `KERNEL_OFFSET` alias, so a low
    //    or non-canonical pointer means the region was added with a physical
    //    address by mistake) and must lie above `_heap_start` and below the
    //    backend's mapping limit, which is the tightest bound the exclusion
    //    set guarantees.
    let boxed = Box::new(0xDEAD_BEEF_u64);
    let addr = (&raw const *boxed) as u64;
    let pa = addr.wrapping_sub(KERNEL_OFFSET);
    log::info!(
        "heap box   va {addr:#018X} -> pa {pa:#014X}, value {:#X}",
        *boxed
    );
    assert!(
        addr >= KERNEL_OFFSET,
        "heap pointer {addr:#018X} is not in the high-canonical kernel alias"
    );
    assert!(
        pa >= memmap::heap_start_pa(),
        "heap pointer pa {pa:#014X} is below _heap_start ({:#014X}): the \
         allocator is handing out the image or the boot scratch region",
        memmap::heap_start_pa()
    );
    assert!(
        pa < mapped_limit,
        "heap pointer pa {pa:#014X} is outside the {mapped_limit:#014X} bytes \
         of physical memory the boot backend mapped"
    );
    assert_eq!(*boxed, 0xDEAD_BEEF, "Box contents were corrupted");
    drop(boxed);

    log::info!(
        "heap ok    all four checks passed against {} MiB usable",
        usable_bytes / (1024 * 1024)
    );
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

/// A panicking guest ends the machine with the failure code, rather than
/// halting.
///
/// Halting was right while nothing could stop QEMU: it at least left the log
/// readable. Now that `isa-debug-exit` works, halting is actively harmful --
/// the run only ends when the 60-second `timeout` kills it, so a panic is
/// reported to the shell as 124 ("timed out"), indistinguishable from a hang,
/// and it costs a minute of CI time per failure. Exiting makes a panic fail
/// fast and fail distinguishably (status 65).
///
/// `debug_exit` falls through to a halt loop if the device is absent, so the
/// old behaviour is still what happens when there is nothing to exit through.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("PANIC: {info}");

    // The one expected panic: the unrecoverable instruction-fetch fault that
    // `check_nx_is_enforced` provokes as the last act of a successful run.
    //
    // It is identified by CR2 rather than by a bare "expected panic" flag.
    // CR2 still holds the faulting address here -- nothing has faulted since
    // -- so this asserts that the panic we are handling is *that* fault at
    // *that* address, not merely some panic that happened after the flag was
    // set. Anything else, including a second fault at a different address, is
    // reported as a failure.
    let probe = NX_PROBE_ADDR.load(core::sync::atomic::Ordering::SeqCst);
    if probe != 0 && read_cr2() == probe {
        serial_println!(
            "nx         instruction fetch from {probe:#018X} faulted as expected; \
             DEP is enforced and the run is complete"
        );
        litebox_platform_lvbs::host::kvm_impl::debug_exit(
            litebox_platform_lvbs::host::kvm_impl::DEBUG_EXIT_SUCCESS,
        )
    }

    litebox_platform_lvbs::host::kvm_impl::debug_exit(
        litebox_platform_lvbs::host::kvm_impl::DEBUG_EXIT_FAILURE,
    )
}
