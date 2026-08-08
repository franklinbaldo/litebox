# LiteBox on KVM/QEMU — Design

Date: 2026-08-08
Branch: `sanghle/kvm`
Supersedes: `sanghle/hypervisor/bootloader_v2`

## Goal

Run LiteBox as a guest kernel under KVM/QEMU on x86_64, booting directly via
`qemu-system-x86_64 -kernel`, loading a static OP-TEE TA, executing it in ring 3,
and exiting cleanly.

This is a redo of `sanghle/hypervisor/bootloader_v2` against the current code base.
That branch forked `litebox_platform_lvbs` into `litebox_platform_hypervisor` and
then rotted against upstream, which is why it needs redoing. This design avoids
repeating that mistake.

## Decisions

| Decision | Choice |
|---|---|
| Substrate | Extend `litebox_platform_lvbs` with a KVM host — **not** a fork |
| Shim | OP-TEE first; Linux runner later against the same platform |
| Boot | QEMU `-kernel` with a **PVH** ELF note (not the Linux bzImage protocol) |
| Milestone 1 | Boot → run one OP-TEE TA → clean exit. Single CPU, no SMP, no preemption |

### Why not fork

`litebox_platform_lvbs` is ~10k lines, of which `src/mshv/` is ~3.5k. The coupling
from the remaining 6.5k lines into `mshv` is **nine localized seams**, not pervasive
entanglement. Forking would duplicate 6.5k lines that immediately begin drifting from
upstream — the exact failure mode that killed `bootloader_v2`.

### Why not ostd

`jayb/experimental/ostd` (`ostd-test/{platform,runner}`) boots under QEMU today and
would be less bring-up work, but it introduces a heavyweight external kernel
dependency and diverges from the LVBS lineage we want to keep shared.

## 1. Architecture and crate layout

No new platform crate. `litebox_platform_lvbs` gains a second host alongside
`LvbsLinuxKernel`.

```
litebox_platform_lvbs/
  src/host/kvm_impl.rs   NEW   KvmGuest = LinuxKernel<HostKvmInterface>
  src/host/mod.rs              mod kvm_impl (cfg-gated)
  src/mm/layout.rs       NEW   PAGE_SIZE etc. hoisted out of mshv::vtl1_mem_layout
  src/mshv/                    unchanged, gated behind feature = "host_lvbs"
litebox_runner_kvm/      NEW   no_std/no_main PVH runner, OP-TEE shim
litebox_platform_multiplex/    feature platform_kvm
litebox_shim_optee/            feature platform_kvm
```

Two mutually exclusive platform features: `host_lvbs` (default, current behaviour)
and `host_kvm`. The shared 6.5k lines compile identically for both.

### The host seam is *not* `HostInterface`

`HostInterface` (`src/lib.rs:924`) looks like the abstraction point but is vestigial.
In `HostLvbsInterface` (`src/host/lvbs_impl.rs:261-320`) **every method is
`unimplemented!()` or `panic!` except `log`** — including `switch`, because
`mshv::vtl_switch` is called directly rather than through the trait. And `log` calls
`serial_print_string`, which writes straight to COM1; the mshv ringbuffer is only on
the `print()` / `serial_println!` path (`arch/x86/ioport.rs:161`).

The impls that actually carry per-host behaviour are the provider traits implemented
directly on `LvbsLinuxKernel`:

| Real seam | LVBS today | KVM needs |
|---|---|---|
| `crate::mm::MemoryProvider` | `GVA_OFFSET`, `PRIVATE_PTE_MASK = 0`, pages from `SafeZoneAllocator` | same shape; heap sized from the PVH memmap |
| `litebox::mm::allocator::MemoryProvider` | forwards to `HostLvbsInterface::alloc` → `panic!` | must actually work — back the allocator with usable RAM |
| `ThreadLocalStorageProvider` | per-CPU variables | reusable verbatim |
| `CrngProvider` | PRK + RDRAND | RDRAND-only seed, no PRK |
| `DerivedKeyProvider` | PRK | `UnsupportedRebootPersistentKey` |
| `HostInterface::log` | `serial_print_string` (COM1) | works verbatim under QEMU |

`HostKvmInterface` is therefore a near-copy of the existing placeholder. We keep the
parametric `Host` only because `LinuxKernel<Host>` is already spelled that way. We do
**not** invest in fleshing the trait out (YAGNI).

The real content of this work is: (a) the nine mshv seams, (b) a working page
allocator over the firmware memory map — the one thing LVBS never needed because
VTL0 hands it fixed memory, and (c) boot plus runner.

## 2. Boot and memory bring-up

### PVH direct boot

QEMU's `-kernel` accepts a plain ELF carrying an `XEN_ELFNOTE_PHYS32_ENTRY` note. It
enters at that address in 32-bit protected mode, paging off, A20 on, flat GDT, with
`%ebx` pointing at an `hvm_start_info` struct (memory map, cmdline, RSDP).

Compared to the Linux bzImage boot protocol this drops the setup header and the
16-bit real-mode stub while keeping the "no disk image, just `-kernel`" property. We
still write the 32→64 trampoline and early page tables.

Caveat: `litebox_runner_lvbs/x86_64_vtl1.ld` `/DISCARD/`s `*(.note.*)`. The KVM
linker script must `KEEP` it or the PVH note is stripped and QEMU falls back to
multiboot/linux probing.

### Memory

LVBS is handed 16 MiB pre-populated and pre-identity-mapped, with GDT/TSS/PML4/PDPT/
PDE/PTE at fixed frames (`mshv/vtl1_mem_layout.rs`). Under KVM none of that exists.

1. Early 32-bit stub builds a temporary 2 MiB-page identity map plus a higher-half
   map at `KERNEL_OFFSET`, enables PAE/LME/PG, far-jumps to 64-bit.
2. Rust entry relocates via `.rela.dyn` — reuse the `R_X86_64_RELATIVE` loop from
   `litebox_runner_lvbs/src/main.rs` verbatim.
3. Walk the `hvm_start_info` memmap; feed every usable region not covered by the
   kernel image into `SafeZoneAllocator::fill_pages`.
4. `GVA_OFFSET` (`0xFFFF_8000_0000_0000`) and `KERNEL_OFFSET`
   (`0xFFFF_E200_0000_0000`) carry over unchanged, as does `PRIVATE_PTE_MASK = 0`.
   They are plain higher-half offsets with nothing VSM-specific about them.
5. `src/mm/mod.rs:64` hardcodes `PageTable<ALIGN> = X64PageTable<LvbsLinuxKernel,
   ALIGN>` and needs a cfg arm for `KvmGuest`.

## 3. The nine mshv seams

Feature `host_kvm` compiles out `mod mshv`. Each seam gets the minimum treatment that
leaves LVBS behaviour unchanged and its `.text` identical apart from 11 additional
upstream generic instantiations (`base16ct` copies of `core` generics, +1024 bytes)
that `-Z share-generics` selects differently once a cargo feature is added to the
crate. No LiteBox symbol is added, removed, or resized. See the Gate A/A' discussion
in the Phase 1 plan for how this is measured.

| # | Seam | Treatment |
|---|---|---|
| 1 | `mm/pgtable.rs:4`, `mm/vmap.rs:19` — `PAGE_SIZE` | Hoist `PAGE_SIZE`/`PAGE_SHIFT`/`PTES_PER_PAGE` into `mm/layout.rs`; `vtl1_mem_layout` re-exports. Pure move. |
| 2 | `host/mod.rs:32`, `lib.rs:586` — hvcall page address | cfg-out `HVCALL_PAGE_ANCHOR` and the `.hvcall_page` section. KVM has no hypercall page. |
| 3 | `lib.rs:54,1132` — `ProtectedFrameAccessGuard` | `LvbsPhysPageMapInfo.protected_frame_access` becomes `Option<()>`; `acquire_access_guard` → `Some(())`. |
| 4 | `lib.rs:1298-1313` — `HvPageProtFlags`, `protect_physical_memory_range` | `validate_unowned` / page-protect path becomes `Ok(())`. See security note below. |
| 5 | `arch/x86/interrupts.rs:20,91` — `HYPERVISOR_CALLBACK_VECTOR` | cfg-out that IDT entry and the `isr_hyperv_sint` stub in `interrupts.S`. |
| 6 | `arch/x86/ioport.rs:6,161` — ringbuffer in `print()` | Route `print()` to `serial_print_string` so `serial_println!` works under QEMU. |
| 7 | `arch/x86/timer.rs:30` — Hyper-V STIMER | cfg-out the module; milestone 1 has no preemption. The x2APIC half is architectural and salvageable later. |
| 8 | `arch/x86/mm/paging.rs:64` — `flush_tlb_range` via hypercall | Unconditionally take the existing `!is_hvcall_ready()` fallback: local `invlpg` / `flush_all`. Correct for single CPU; needs IPI shootdown when SMP lands. |
| 9 | `mm/mod.rs:64` — `PageTable<ALIGN>` bound to `LvbsLinuxKernel` | Add a cfg arm for `KvmGuest`. |

### Security note on seam 4

Dropping VSM page protection does not leave `litebox_runner_kvm` without a boundary;
it relocates the boundary. LiteBox on KVM is a conventional OS kernel, so the
security boundary is **ring 0 vs ring 3**, enforced by page tables, SMEP/SMAP and the
syscall gate. All of that is in the shared code and stays live: `enable_smep_smap`,
`LvbsValidateAccess::with_user_memory_access` (`stac`/`clac`), and `SFMask` clearing
AC/IF on `syscall`.

What is lost is only the VTL1-protects-against-VTL0 layer, which presumes a hostile
peer kernel that does not exist in this configuration.

Consequently this is a testing vehicle first, but also a legitimate standalone-OS
deployment model — LiteBox as the kernel, TAs and Linux binaries as userspace, under
a normal OS threat model rather than a VBS one. SMP, APIC-timer preemption and
virtio-net are therefore real roadmap features, not test scaffolding.

## 4. Runner

```
litebox_runner_kvm/
  src/main.rs       #![no_std] #![no_main], PVH entry, boot → shim → TA
  x86_64_kvm.json   target spec, copied from x86_64_vtl1.json
  x86_64_kvm.ld     as x86_64_vtl1.ld, minus .hvcall_page, with KEEP(.note.*)
  run-qemu.sh
```

Boot-to-TA sequence:

1. PVH 32-bit stub → early page tables → long mode → `.rela.dyn` relocation.
2. `allocate_per_cpu_variables` / `init_per_cpu_variables`, GDT + TSS, IDT,
   `enable_fsgsbase`, `enable_extended_states`, `enable_smep_smap`,
   `syscall_entry::init` — all reused unchanged from the LVBS runner.
3. Fill `SafeZoneAllocator` from the `hvm_start_info` memmap; install `HostLogger`
   over COM1.
4. `set_platform(KvmGuest)`, `set_platform_low`, OP-TEE shim init, load a static TA
   embedded via `include_bytes!`, enter ring 3.
5. TA returns → `HostKvmInterface::exit()` writes the `isa-debug-exit` port (`0xf4`)
   so QEMU exits with a distinguishable code.

## 5. Verification

- Existing `litebox_platform_lvbs` unit tests pass unchanged under default features.
  This is the gate for landing the seam extraction before any KVM code is written.
- The same tests under `host_kvm`, excluding those that depend on mshv.
- An integration test running `qemu-system-x86_64 -kernel … -device isa-debug-exit`
  that asserts on the exit code and expected serial output. Runs under plain TCG in
  CI so it does not require `/dev/kvm`, and under `-enable-kvm` locally.

## 6. Sequencing

1. No-op seam extraction on `litebox_platform_lvbs`; existing tests green.
2. `KvmGuest` host impl plus a working page allocator over the firmware memmap.
3. PVH boot to a serial "hello" in long mode.
4. OP-TEE TA load and ring-3 execution; clean exit.
5. CI wiring.

Deferred beyond milestone 1: SMP / AP bring-up, APIC-timer preemption, virtio-net,
and a Linux-shim runner on the same platform.
