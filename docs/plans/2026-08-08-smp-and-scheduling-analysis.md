# SMP on LiteBox/KVM: prerequisites and sequencing

> **Path note (later restructure).** After this document was written,
> `litebox_platform_lvbs` was reorganised so that all host-specific code lives
> under `src/host/<name>/`. Paths named below are the ones that were current at
> the time and are kept as written, because they are part of the record of what
> was decided. The mapping to today's tree is:
>
> | then | now |
> |---|---|
> | `src/mshv/` | `src/host/lvbs/mshv/` |
> | `src/arch/x86/timer.rs` | `src/host/lvbs/timer.rs` |
> | `src/arch/x86/clock.rs` | `src/host/kvm/clock.rs` |
> | `src/host/lvbs_impl.rs` | `src/host/lvbs/mod.rs` |
> | `src/host/kvm_impl.rs` | `src/host/kvm/mod.rs` |
> | `src/host/bootparam.rs` | `src/host/lvbs/bootparam.rs` |
> | `host::linux::CpuMask` | `host::lvbs::cpu_mask::CpuMask` |
>
> Public paths moved correspondingly: `litebox_platform_lvbs::mshv` is now
> `litebox_platform_lvbs::host::lvbs::mshv`.

Date: 2026-08-08
Status: analysis, no implementation proposed yet

## The question

Is multi-core support meaningful without a scheduler?

## Short answer

It depends entirely on which shim, and the two answers are opposite.

| Path | Scheduler needed? | Why |
|---|---|---|
| OP-TEE, two-VM | **No** | Normal-world Linux schedules; LiteBox runs requests to completion |
| Linux shim, self-contained | **Yes** | The value of a second core *is* threads, which forces clone + futex + multiplexing |

So "multi-core needs a scheduler" is false in general but true for the Linux
shim. Getting this backwards would mean building a scheduler for a workload
that never needed one, or shipping SMP that cannot be used.

## Why the OP-TEE path needs no scheduler

`litebox_runner_lvbs/src/lib.rs:231-236` is the entire VTL1 main loop:

```rust
loop {
    let params = vtl_switch(return_value);      // block until VTL0 calls in
    return_value = Some(vtlcall_dispatch(&params));
}
```

That is a run-to-completion request/response server, one instance per VP, with
**no scheduler in LiteBox at all**. LVBS already has meaningful SMP — `_ap_start`,
`MAX_CORES = 128`, per-CPU state — and gets real parallelism because Linux in
VTL0 is the scheduler. It decides which CPU calls in and when. LiteBox answers.

The equivalent on KVM is the **two-VM model**: a normal-world VM and a secure
VM, which is what Intel used to run OP-TEE on x86-64. It is a direct VTL0/VTL1
analogue rather than a novel arrangement:

- the normal-world VM runs the *real* OP-TEE stack — driver, `tee-supplicant`,
  `libteec` — reused rather than reimplemented
- LiteBox is the secure VM
- the hypervisor mediates shared memory (ivshmem, vhost-user, vsock)
- **normal-world Linux is the scheduler**, exactly as VTL0 is today

The shim is already ready for this. `litebox_shim_optee::msg_handler` is
transport-agnostic: `handle_optee_smc_args()` and `handle_optee_msg_args()` take
decoded structs and know nothing about where a request came from. LVBS just
happens to fill them from VTL0 shared memory.

So the work on this path is a **transport and shared-memory port**, not protocol
invention. N cores means N independent workers. Nothing multiplexes, preempts or
migrates.

## Why the Linux-shim path does need one

Here a second core is only worth having because a process has threads. That
forces `clone`, threads block so it forces futex
(`HostInterface::wake_many` / `block_or_maybe_timeout`, both `unimplemented!()`),
and threads outnumber cores so it forces multiplexing.

**LiteBox does not define a scheduler today.** There is no run queue, no context
switch, no thread abstraction beyond the OP-TEE shim's per-invocation
`ThreadState`. `litebox_shim_linux` has a `sched_getaffinity` stub and nothing
else. This is greenfield work, not an extension.

If the program is single-threaded, a second core does nothing whatsoever.

## AP bring-up is not the easy part on KVM

An earlier version of this analysis claimed AP bring-up was the cheap half of
SMP. That was wrong, and it was wrong because it generalised from LVBS without
reading why LVBS's version is short.

`litebox_runner_lvbs/src/main.rs:362` says it plainly:

> Entered directly by Hyper-V via `hvcall_enable_vp_vtl` (the VP context's RIP
> is set to this symbol). APs inherit the BSP's CR3, so they already run at
> high-canonical VAs and need no remap.

LVBS APs arrive **in 64-bit long mode with paging already established**. Hyper-V
does everything hard, which is why `_ap_start` is twenty lines of spinlock.

KVM offers no equivalent. Decoding what this guest is actually told —
`CPUID 0x4000_0001 EAX = 0x0100_7afb`:

```
bit  0  CLOCKSOURCE          bit  9  PV_TLB_FLUSH
bit  1  NOP_IO_DELAY         bit 11  PV_SEND_IPI
bit  3  CLOCKSOURCE2         bit 12  POLL_CONTROL
bit  4  ASYNC_PF             bit 13  PV_SCHED_YIELD
bit  5  STEAL_TIME           bit 14  ASYNC_PF_INT
bit  6  PV_EOI               bit 24  CLOCKSOURCE_STABLE
bit  7  PV_UNHALT
```

The asymmetry is specific and worth naming: **KVM helps with steady-state SMP
and not at all with bring-up.** `PV_TLB_FLUSH` and `PV_SEND_IPI` address two of
the recurring costs. There is no "start this vCPU at this RIP with this context"
hypercall. Hyper-V provides both halves; KVM provides only the second.

What AP bring-up therefore costs here:

| Step | Note |
|---|---|
| INIT–SIPI–SIPI | the SIPI vector is a page number below 1 MiB, so APs start in **16-bit real mode** |
| Trampoline | a *third* mode path, 16→32→64. The existing 32→64 stub was bitten twice by LLVM's Intel-syntax immediate-arithmetic hazard |
| Low memory | the trampoline must live below 1 MiB — excluded from the heap by `LOW_MEMORY_FLOOR`, and no longer mapped at all since the CR3 switch unmapped VA 0 and dropped the identity map |
| CPU enumeration | ACPI MADT. `rsdp_paddr` is parsed in `boot/pvh.rs` but deliberately not carried in `BootInfo`; restoring it is additive, but the ACPI parsing is new |
| IPI | x2APIC send exists but is `host_lvbs`-gated inside `arch/x86/timer.rs` |
| Per-AP state | stack, per-CPU area, GDT/IDT/TSS, syscall MSRs, boot-stack handoff |

That is comparable in size to the whole of Phase 2's boot work.

## Correctness blockers, independent of any scheduler

These are required for SMP whatever the model, and they land first:

- **TLB shootdown.** `flush_tlb_range` under `host_kvm` flushes locally only
  (`TODO(SMP)`, `arch/x86/mm/paging.rs`). Today that is a note; with a second
  core it is a silent stale-TLB corruption bug. `PV_TLB_FLUSH` above is the
  cheap way out.
- **Page-table mutation** while another core walks them.
- **`_guard_page_0` / `_guard_page_1`** in `PerCpuVariables` are padding, not
  unmapped pages. Per-CPU, so SMP multiplies the exposure rather than creating
  it. This is an LVBS bug too.

## Recommendation: preemption timer next, not SMP

Both SMP paths are expensive for architectural reasons. The preemption timer is
the one thing both want, and it is cheap:

- **Useful today, single-core.** A ring-3 loop currently wedges the guest
  permanently, with no way to recover. Nothing has closed this.
- **A hard prerequisite for any scheduler**, so it is not speculative for the
  Linux path.
- **Robustness for the OP-TEE path** — killing a runaway TA is exactly what
  LVBS's STIMER exists for, and it is the only scheduler-adjacent thing that
  path needs at all.
- **Half-written.** `arch/x86/timer.rs` already contains the architectural
  x2APIC bring-up (`IA32_APIC_BASE`, `X2APIC_SVR`, `X2APIC_EOI`); its own doc
  flags this as worth lifting. Only the Hyper-V STIMER backend needs replacing —
  with TSC-deadline if the guest exposes it (the TSC is already calibrated), or
  an APIC LVT one-shot calibrated the same way the TSC already is.
- **Zero SMP correctness risk**, so it does not drag in TLB shootdown.
- **Commits to neither model**, which matters while OP-TEE-vs-Linux is open.

## Open questions

1. Which shim is the target? The answer determines whether a scheduler is on
   the roadmap at all.
2. For the OP-TEE two-VM shape: which transport, and what stands in for
   OP-TEE's physically-shared buffers between worlds?
3. Does the normal-world OP-TEE driver need modification, as it did for LVBS,
   or can a stock driver be pointed at a different transport?
