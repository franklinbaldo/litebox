# LiteBox on KVM — Phase 1: mshv Seam Extraction

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make the `mshv` boundary inside `litebox_platform_lvbs` explicit and feature-gated, so a second host (KVM) can compile against the shared 6.5k lines — without changing LVBS behaviour by a single byte.

**Architecture:** Add two mutually-exclusive cargo features to `litebox_platform_lvbs`: `host_lvbs` (default, today's behaviour) and `host_kvm`. Hoist the genuinely-generic constants out of `mshv::vtl1_mem_layout`, then gate each of the nine `mshv` seams. No KVM logic is written in this phase — only the boundary.

**Tech Stack:** Rust (stable 1.97 for host tests, `nightly-2025-12-31` + `-Z build-std` for the bare-metal target `x86_64_vtl1.json`).

**Design doc:** `docs/plans/2026-08-08-litebox-on-kvm-design.md`

---

## Background you need

`litebox_platform_lvbs` is a `no_std` platform crate for running LiteBox in Hyper-V VTL1
(Virtual Trust Level 1 — a higher-privilege peer to the normal "VTL0" Linux kernel).
Everything Hyper-V-specific lives in `src/mshv/`. The other ~6.5k lines are a generic
x86_64 kernel: GDT, IDT, paging, per-CPU variables, syscall entry.

We want to reuse those 6.5k lines for a plain KVM guest. Only nine places reach into
`mshv`. This plan severs them.

**Do not** "improve" code you touch. Every task in this plan is behaviour-preserving.
Resist refactoring urges — they defeat the verification gates below.

## Verification gates

Two gates. Learn both; every task names which one applies.

**Gate A — `.text` byte-identity (for pure code moves).**
The bare-metal build is reproducible. If a task is a pure move, the emitted
instructions must not change.

Compare **`.text` only, never the whole ELF.** Debug builds embed
`#[track_caller]` `core::panic::Location` records in `.data`, so changing the
line *count* of any file shifts those `u32` line numbers without altering a
single instruction. Whole-ELF hashing therefore reports false failures on
essentially every edit. (Measured: Task 1 shifts exactly 4 bytes in `.data` —
`47→48`, `54→55`, and `77→75` twice — with `.text` bit-identical.)

```bash
BIN=target/x86_64_vtl1/debug/litebox_runner_lvbs
objcopy -O binary --only-section=.text "$BIN" /tmp/check.text
sha256sum /tmp/check.text
```

Baseline `.text` hash (recorded at `655833c8`):
```
293dc2d00ea51d892d5e31d07fe22f5a2a101ef8aa2ec2ef1b191bae173b64ad
```

**Gate A' — LiteBox symbol names and sizes (for feature-gating tasks).**
Gate A is only valid for pure code moves within an *unchanged feature set*.
Enabling a cargo feature changes `litebox_platform_lvbs`'s `-C metadata` hash,
which changes every downstream mangled symbol, which changes which crate's copy
of a shared generic `-Z share-generics` selects — linking extra upstream CGUs.
(Measured on Task 2: 11 added `base16ct` copies of `core` generics, +1024 bytes
of `.text`, with zero LiteBox code changed and no symbol removed or resized.)

Gate A' sidesteps that by comparing only *our* symbols, by name and size:

```bash
nm -S --defined-only "$BIN" | awk 'NF>=4{print $2, $4}' \
  | grep -E 'litebox|_start|syscall|isr_' \
  | sed -E 's/(17h|C[sS])[0-9a-zA-Z]{10,}_?//g' | sort | sha256sum
```

Baseline (12599 symbols, recorded at `76b176f6`):
```
de61da6739bc88fe6239f820ac42f334f6e59056e06cf09c8be040bb484c61c2
```

Use Gate A' for Tasks 2-9. It stays stable across feature flips but still catches
any real change to LiteBox code.

**Gate B — builds and tests pass (for restructuring tasks).**
The bare-metal build must succeed, plus:

```bash
cargo test -p litebox_platform_lvbs
```
Expected: `15 passed; 0 failed; 4 ignored`.

Note the host test suite is a *weak* gate — much mshv-coupled code is `#[cfg(not(test))]`
and never compiled during `cargo test`. The bare-metal build is the load-bearing check.

Gate A applies to Task 1 only. Tasks 2-9 use Gate A' plus Gate B.

Save yourself typing:

```bash
cat > /tmp/lvbs-check.sh <<'EOF'
#!/bin/sh
set -e
cd /workspace/litebox-kvm/.worktrees/kvm-seams
BIN=target/x86_64_vtl1/debug/litebox_runner_lvbs
cargo +nightly-2025-12-31 build -Z build-std-features=compiler-builtins-mem \
  -Z build-std=core,alloc --manifest-path=litebox_runner_lvbs/Cargo.toml \
  --target litebox_runner_lvbs/x86_64_vtl1.json 2>&1 | tail -2
objcopy -O binary --only-section=.text "$BIN" /tmp/check.text
printf '.text  '; sha256sum /tmp/check.text | cut -d' ' -f1
cargo test -p litebox_platform_lvbs 2>&1 | grep "^test result" | head -1
EOF
chmod +x /tmp/lvbs-check.sh
```

---

### Task 1: Hoist generic page constants into `mm/layout.rs`

Seam 1. `PAGE_SIZE`, `PAGE_SHIFT` and `PTES_PER_PAGE` are architectural x86_64 facts
that happen to live in a Hyper-V-specific module. Move them; leave a re-export so
nothing else changes.

**Files:**
- Create: `litebox_platform_lvbs/src/mm/layout.rs`
- Modify: `litebox_platform_lvbs/src/mm/mod.rs`
- Modify: `litebox_platform_lvbs/src/mshv/vtl1_mem_layout.rs:6-8`
- Modify: `litebox_platform_lvbs/src/mm/pgtable.rs:4`
- Modify: `litebox_platform_lvbs/src/mm/vmap.rs:19`

**Step 1: Create the new module**

`litebox_platform_lvbs/src/mm/layout.rs`:

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Architectural x86_64 paging constants.
//!
//! These are properties of the CPU, not of any particular hypervisor, so they
//! are shared by every host implementation.

/// Size of a 4 KiB page in bytes.
pub const PAGE_SIZE: usize = 4096;

/// `log2(PAGE_SIZE)`.
pub const PAGE_SHIFT: usize = 12;

/// Number of page table entries in one 4 KiB page table.
pub const PTES_PER_PAGE: usize = 512;
```

**Step 2: Register the module**

In `litebox_platform_lvbs/src/mm/mod.rs`, next to the existing `pub(crate) mod pgtable;`:

```rust
pub mod layout;
```

**Step 3: Re-export from the old location**

In `litebox_platform_lvbs/src/mshv/vtl1_mem_layout.rs`, replace lines 6-8:

```rust
pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SHIFT: usize = 12;
pub const PTES_PER_PAGE: usize = 512;
```

with:

```rust
pub use crate::mm::layout::{PAGE_SHIFT, PAGE_SIZE, PTES_PER_PAGE};
```

**Step 4: Repoint the two non-mshv consumers**

`litebox_platform_lvbs/src/mm/pgtable.rs:4` — change:
```rust
use crate::mshv::vtl1_mem_layout::PAGE_SIZE;
```
to:
```rust
use crate::mm::layout::PAGE_SIZE;
```

`litebox_platform_lvbs/src/mm/vmap.rs:19` — same substitution.

**Step 5: Verify with Gate A**

Run `/tmp/lvbs-check.sh`.

Expected `.text` hash: `293dc2d00ea51d892d5e31d07fe22f5a2a101ef8aa2ec2ef1b191bae173b64ad`
Expected tests: `15 passed; 0 failed; 4 ignored`

If the hash differs, you changed behaviour. Stop and find out why before continuing.

**Step 6: Commit**

```bash
git add litebox_platform_lvbs/src/mm/layout.rs litebox_platform_lvbs/src/mm/mod.rs \
        litebox_platform_lvbs/src/mshv/vtl1_mem_layout.rs \
        litebox_platform_lvbs/src/mm/pgtable.rs litebox_platform_lvbs/src/mm/vmap.rs
git commit -m "Hoist architectural page constants out of mshv into mm::layout"
```

---

### Task 2: Add mutually-exclusive `host_lvbs` / `host_kvm` features

No code is gated yet. This task only establishes the switch and its guard rail, so
later tasks have something to gate against.

**Files:**
- Modify: `litebox_platform_lvbs/Cargo.toml` (the `[features]` block)
- Modify: `litebox_platform_lvbs/src/lib.rs` (top of file, after the crate attrs)

**Step 1: Declare the features**

In `litebox_platform_lvbs/Cargo.toml`, change:

```toml
[features]
default = []
```

to:

```toml
[features]
default = ["host_lvbs"]
# Hyper-V VTL1 host. Enables the `mshv` module and VSM-based page protection.
host_lvbs = []
# Plain KVM/QEMU guest. LiteBox is the whole kernel; there is no hypervisor
# to call and no VTL0 peer to protect against.
host_kvm = []
```

Leave the other features (`linux_syscall`, `devbox`, `preemption_test_quantum`) alone.

**Step 2: Add the guard rail**

In `litebox_platform_lvbs/src/lib.rs`, immediately after the module declarations
(around line 47, after `pub mod syscall_entry;`):

```rust
#[cfg(all(feature = "host_lvbs", feature = "host_kvm"))]
compile_error!("features `host_lvbs` and `host_kvm` are mutually exclusive");

#[cfg(not(any(feature = "host_lvbs", feature = "host_kvm")))]
compile_error!(
    "exactly one host must be selected: enable `host_lvbs` or `host_kvm`. \
     Hint: you may have set `default-features = false` without picking a host."
);
```

**Step 3: Verify with Gate A'**

Run `/tmp/lvbs-check.sh`. Use **Gate A'** here, not Gate A: enabling a feature
perturbs upstream codegen. The symbol hash must still be
`de61da6739bc88fe6239f820ac42f334f6e59056e06cf09c8be040bb484c61c2` (12599 symbols).

**Step 4: Verify the guard rail actually fires**

```bash
cargo check -p litebox_platform_lvbs --no-default-features 2>&1 | grep "exactly one host"
```
Expected: the `compile_error!` message appears.

```bash
cargo check -p litebox_platform_lvbs --features host_kvm 2>&1 | grep "mutually exclusive"
```
Expected: the mutual-exclusion message appears (because `default` still pulls in `host_lvbs`).

**Step 5: Commit**

```bash
git add litebox_platform_lvbs/Cargo.toml litebox_platform_lvbs/src/lib.rs
git commit -m "Add mutually exclusive host_lvbs/host_kvm features"
```

---

### Task 3: Add a skeleton `KvmGuest` host

Seam 9 needs a concrete type to name. This is a stub: every method panics. Real
implementations land in Phase 2.

**Files:**
- Create: `litebox_platform_lvbs/src/host/kvm_impl.rs`
- Modify: `litebox_platform_lvbs/src/host/mod.rs:5-11`

**Step 1: Gate the existing LVBS host**

In `litebox_platform_lvbs/src/host/mod.rs`, wrap the LVBS host exports:

```rust
pub mod bootparam;
pub mod linux;
#[cfg(feature = "host_kvm")]
pub mod kvm_impl;
#[cfg(feature = "host_lvbs")]
pub mod lvbs_impl;
pub mod per_cpu_variables;

#[cfg(feature = "host_kvm")]
pub use kvm_impl::KvmGuest;
#[cfg(feature = "host_lvbs")]
pub use lvbs_impl::LvbsLinuxKernel;
#[cfg(feature = "host_lvbs")]
pub(crate) use lvbs_impl::set_platform_root_key;
```

**Step 2: Write the stub host**

`litebox_platform_lvbs/src/host/kvm_impl.rs`:

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! An implementation of [`HostInterface`] for a plain KVM/QEMU guest.
//!
//! Unlike LVBS, LiteBox here *is* the kernel: there is no VTL0 peer to delegate
//! to. The security boundary is ring 0 vs ring 3, enforced by page tables,
//! SMEP/SMAP and the syscall gate — a conventional OS threat model rather than
//! a VBS one.
//!
//! Phase 1 note: every method below is still a stub. Real implementations land
//! with the boot path in Phase 2.

use crate::{Errno, HostInterface, arch::ioport::serial_print_string};

pub type KvmGuest = crate::LinuxKernel<HostKvmInterface>;

pub struct HostKvmInterface;

impl HostInterface for HostKvmInterface {
    fn log(msg: &str) {
        serial_print_string(msg);
    }

    fn alloc(_layout: &core::alloc::Layout) -> Option<(usize, usize)> {
        unimplemented!("KVM host allocator lands in Phase 2")
    }

    unsafe fn free(_addr: usize) {
        unimplemented!("KVM host allocator lands in Phase 2")
    }

    fn exit() -> ! {
        unimplemented!("isa-debug-exit lands in Phase 2")
    }

    fn terminate(_reason_set: u64, _reason_code: u64) -> ! {
        unimplemented!("isa-debug-exit lands in Phase 2")
    }

    fn wake_many(_mutex: &core::sync::atomic::AtomicU32, _n: usize) -> Result<usize, Errno> {
        unimplemented!()
    }

    fn block_or_maybe_timeout(
        _mutex: &core::sync::atomic::AtomicU32,
        _val: u32,
        _timeout: Option<core::time::Duration>,
    ) -> Result<(), Errno> {
        unimplemented!()
    }

    fn send_ip_packet(_packet: &[u8]) -> Result<usize, Errno> {
        unimplemented!("virtio-net is post-milestone-1")
    }

    fn receive_ip_packet(_packet: &mut [u8]) -> Result<usize, Errno> {
        unimplemented!("virtio-net is post-milestone-1")
    }

    /// Unreachable on KVM: there is no lower VTL to switch back to.
    fn switch(_result: u64) -> ! {
        unreachable!("no VTL0 peer exists in a plain KVM guest")
    }
}
```

**Step 3: Verify with Gate A**

Run `/tmp/lvbs-check.sh`. `host_kvm` is off by default, so the Gate A' symbol hash
must be unchanged.

**Step 4: Commit**

```bash
git add litebox_platform_lvbs/src/host/kvm_impl.rs litebox_platform_lvbs/src/host/mod.rs
git commit -m "Add skeleton KvmGuest host behind host_kvm feature"
```

---

### Task 4: Gate `mod mshv` and the hypercall page (seams 2 and 5)

**Files:**
- Modify: `litebox_platform_lvbs/src/lib.rs:45` (`pub mod mshv;`)
- Modify: `litebox_platform_lvbs/src/lib.rs:586`
- Modify: `litebox_platform_lvbs/src/host/mod.rs:15-33` (anchor + `hv_hypercall_page_address`)
- Modify: `litebox_platform_lvbs/src/arch/x86/interrupts.rs:20,91-92`
- Modify: `litebox_platform_lvbs/src/arch/x86/interrupts.S` (the `isr_hyperv_sint` stub)

**Step 1** — `lib.rs:45`: `#[cfg(feature = "host_lvbs")] pub mod mshv;`

**Step 2** — `host/mod.rs`: put `#[cfg(feature = "host_lvbs")]` on both
`HVCALL_PAGE_ANCHOR` and `hv_hypercall_page_address`. A KVM guest has no
hypercall page, so the `.hvcall_page` linker section is not needed.

**Step 3** — `lib.rs:586`: this is inside `get_syscall_entry_point`'s neighbourhood.
Read the surrounding function first, then gate only the hypercall-page arm. If the
function returns a value derived from the hvcall page, the `host_kvm` arm should
return the plain `syscall_entry` address instead. Record what you did in the commit
message.

**Step 4** — `interrupts.rs`: gate the `use crate::mshv::HYPERVISOR_CALLBACK_VECTOR;`
import and the `idt.index_mut(HYPERVISOR_CALLBACK_VECTOR)` registration at lines 91-92.
In `interrupts.S`, the `isr_hyperv_sint` stub becomes dead under `host_kvm`; leave the
assembly in place (it is harmless and unreferenced) rather than trying to `cfg` inside
`global_asm!`.

**Step 5: Verify with Gate B**

Run `/tmp/lvbs-check.sh`. This task changes cfg structure, so the `.text` hash *may* shift —
that is acceptable here, but the build must succeed and tests must stay at
`15 passed; 0 failed`. If `.text` is unchanged, better still.

**Step 6: Commit**

```bash
git commit -am "Gate mshv module, hypercall page and Hyper-V SINT vector behind host_lvbs"
```

---

### Task 5: Neutralise VSM page protection (seams 3 and 4)

Under KVM there is no VTL0 peer, so there is nothing to protect pages *from*. These
paths become no-ops.

**Files:**
- Modify: `litebox_platform_lvbs/src/lib.rs:51-57` (`LvbsPhysPageMapInfo`)
- Modify: `litebox_platform_lvbs/src/lib.rs:1132`
- Modify: `litebox_platform_lvbs/src/lib.rs:1298-1313`

**Step 1** — the struct field. Today:
```rust
protected_frame_access: Option<crate::mshv::vsm::ProtectedFrameAccessGuard<'static>>,
```
Introduce a type alias near the top of `lib.rs` so the struct body stays single-form:
```rust
#[cfg(feature = "host_lvbs")]
type ProtectedFrameAccess = crate::mshv::vsm::ProtectedFrameAccessGuard<'static>;
#[cfg(feature = "host_kvm")]
type ProtectedFrameAccess = ();
```
and change the field to `protected_frame_access: Option<ProtectedFrameAccess>`.

**Step 2** — `lib.rs:1132`: gate the acquisition.
```rust
#[cfg(feature = "host_lvbs")]
let protected_frame_access =
    Some(crate::mshv::vsm::protected_frame_registry().acquire_access_guard(pages)?);
#[cfg(feature = "host_kvm")]
let protected_frame_access = Some(());
```
Adapt to the exact expression shape at that line; read it before editing.

**Step 3** — `lib.rs:1298-1313` (`validate_unowned` and its `HvPageProtFlags` mapping):
gate the whole LVBS body, and give `host_kvm` a body that returns `Ok(())` with a
comment explaining *why* it is sound here (no hostile peer kernel; the ring 0/3
boundary is the real boundary).

**Step 4: Verify with Gate B**, then also confirm the LVBS path is untouched by
reading `git diff` and checking every LVBS-side line is identical modulo the `cfg`
attribute.

**Step 5: Commit**

```bash
git commit -am "Make VSM page protection a no-op under host_kvm"
```

---

### Task 6: Route serial output off the mshv ringbuffer (seam 6)

**Files:**
- Modify: `litebox_platform_lvbs/src/arch/x86/ioport.rs:6,159-164`

`print()` currently writes into the mshv ringbuffer. Under `host_kvm` it must go
straight to COM1, which QEMU exposes on `-nographic`.

**Step 1** — gate the `use crate::mshv::ringbuffer::ringbuffer;` import.

**Step 2** — give `print()` two bodies:

```rust
#[cfg(feature = "host_lvbs")]
pub fn print(args: fmt::Arguments<'_>) {
    if let Some(rb) = ringbuffer() {
        let _ = rb.lock().write_fmt(args);
    }
}

#[cfg(feature = "host_kvm")]
pub fn print(args: fmt::Arguments<'_>) {
    let _ = com().lock().write_fmt(args);
}
```

Check the real signature at line 159 before pasting; match it exactly.

**Step 3: Verify with Gate B. Step 4: Commit**

```bash
git commit -am "Send serial_println! to COM1 directly under host_kvm"
```

---

### Task 7: Local-only TLB shootdown (seam 8)

**Files:**
- Modify: `litebox_platform_lvbs/src/arch/x86/mm/paging.rs:60-94`

`flush_tlb_range` uses Hyper-V hypercalls so remote cores sharing the page table see
the invalidation. Under `host_kvm` (single CPU in milestone 1) the existing
`!is_hvcall_ready()` fallback branch is exactly right.

**Step 1** — extract that fallback branch into a helper, so both hosts call it:

```rust
fn flush_tlb_range_local(start: Page<Size4KiB>, count: usize) {
    if count <= TLB_SINGLE_PAGE_FLUSH_CEILING {
        let base = start.start_address().as_u64();
        for i in 0..count {
            x86_64::instructions::tlb::flush(VirtAddr::new(base + (i as u64) * Size4KiB::SIZE));
        }
    } else {
        x86_64::instructions::tlb::flush_all();
    }
}
```

**Step 2** — have the LVBS `flush_tlb_range` call it in its early-return path (pure
refactor, same behaviour), and add:

```rust
// TODO(SMP): needs IPI-based shootdown once AP bring-up lands.
#[cfg(all(not(test), feature = "host_kvm"))]
fn flush_tlb_range(start: Page<Size4KiB>, count: usize) {
    if count == 0 {
        return;
    }
    flush_tlb_range_local(start, count);
}
```

Put `#[cfg(all(not(test), feature = "host_lvbs"))]` on the existing one.

**Step 3: Verify with Gate B. Step 4: Commit**

```bash
git commit -am "Use local TLB flush under host_kvm; extract shared local-flush helper"
```

---

### Task 8: Gate the Hyper-V synthetic timer (seam 7)

**Files:**
- Modify: `litebox_platform_lvbs/src/arch/mod.rs` or `arch/x86/mod.rs` (wherever `mod timer;` is declared)
- Modify: callers of `timer::` under `host_kvm`

Milestone 1 has no preemption, so the whole module is `host_lvbs`-only. The x2APIC
half is architectural and worth salvaging later — leave a note saying so.

**Step 1** — `#[cfg(feature = "host_lvbs")] mod timer;`

**Step 2** — find every caller and gate it:
```bash
grep -rn "timer::" litebox_platform_lvbs/src --include=*.rs | grep -v "arch/x86/timer.rs"
```
`interrupts.rs` imports `STIMER_VECTOR` and `SPURIOUS_VECTOR` from it. `SPURIOUS_VECTOR`
is architectural; if only that is needed under `host_kvm`, move it to `arch/x86/mod.rs`
rather than duplicating the constant.

**Step 3: Verify with Gate B. Step 4: Commit**

```bash
git commit -am "Gate Hyper-V synthetic timer behind host_lvbs"
```

---

### Task 9: Bind `PageTable<ALIGN>` per host (seam 9)

**Files:**
- Modify: `litebox_platform_lvbs/src/mm/mod.rs:63-68`

**Step 1** — add the `host_kvm` arm:

```rust
#[cfg(all(target_arch = "x86_64", not(test), feature = "host_lvbs"))]
pub type PageTable<const ALIGN: usize> =
    crate::arch::mm::paging::X64PageTable<'static, crate::host::LvbsLinuxKernel, ALIGN>;
#[cfg(all(target_arch = "x86_64", not(test), feature = "host_kvm"))]
pub type PageTable<const ALIGN: usize> =
    crate::arch::mm::paging::X64PageTable<'static, crate::host::KvmGuest, ALIGN>;
#[cfg(all(target_arch = "x86_64", test))]
pub type PageTable<const ALIGN: usize> =
    crate::arch::mm::paging::X64PageTable<'static, crate::host::mock::MockKernel, ALIGN>;
```

This requires `KvmGuest` to implement `crate::mm::MemoryProvider`. Add a stub impl in
`host/kvm_impl.rs` mirroring the `#[cfg(test)]` one in `lvbs_impl.rs:61-77`
(`GVA_OFFSET`, `PRIVATE_PTE_MASK = 0`, three `unimplemented!()` methods). Real bodies
land in Phase 2.

**Step 2: Verify with Gate B. Step 3: Commit**

```bash
git commit -am "Bind PageTable to the selected host"
```

---

### Task 10: Prove `host_kvm` compiles

The payoff task. Until now `host_kvm` has never been built.

**Step 1: Try it**

```bash
cargo check -p litebox_platform_lvbs --no-default-features --features host_kvm
```

**Step 2: Fix what falls out**

Expect leftovers: gate any remaining `mshv` reference the same way. Re-run until clean.
If a fix is anything more than a `cfg` attribute or a no-op body, stop and flag it —
that means the seam analysis missed something and the design doc needs updating.

**Step 3: Confirm LVBS is still pristine**

```bash
/tmp/lvbs-check.sh
```
Tests `15 passed; 0 failed; 4 ignored`, and the bare-metal build succeeds.

**Step 4: Add both configurations to CI**

In `.github/workflows/ci.yml`, the clippy invocation at line 61 uses `--all-features`,
which now trips the mutual-exclusion `compile_error!`. Change `litebox_platform_lvbs`
to be checked twice explicitly instead — once per host feature — and exclude it from
the `--all-features` sweep.

**Step 5: Commit**

```bash
git commit -am "Verify host_kvm compiles; check both hosts in CI"
```

---

## Definition of done

- `cargo check -p litebox_platform_lvbs --no-default-features --features host_kvm` succeeds.
- `/tmp/lvbs-check.sh` shows the bare-metal LVBS build succeeding and `15 passed; 0 failed`.
- `git diff main -- litebox_platform_lvbs/src` contains no LVBS-side logic change —
  only `cfg` attributes, the `mm::layout` move, and new `host_kvm` arms.
- CI checks both host configurations.

## Out of scope for this phase

PVH boot, the page allocator over the firmware memmap, `litebox_runner_kvm`, the
OP-TEE TA, and the QEMU integration test. Those are Phase 2 onward — see
`docs/plans/2026-08-08-litebox-on-kvm-design.md` section 6.
