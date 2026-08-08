# LiteBox on KVM — Phase 2: Boot and Run a TA

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Boot `litebox_runner_optee_on_kvm` under `qemu-system-x86_64 -kernel`, load a static OP-TEE TA, execute it in ring 3, and exit with a distinguishable code.

**Architecture:** A new `no_std`/`no_main` runner crate targeting `litebox_platform_lvbs` with `host_kvm`. QEMU enters a PVH ELF entry point in 32-bit protected mode; we build early page tables, reach long mode, relocate, seed a heap from the firmware memory map, bring up per-CPU state, then drive the OP-TEE shim directly the way `litebox_runner_optee_on_linux_userland` does.

**Tech Stack:** Rust `nightly-2025-12-31` + `-Z build-std`, custom target `x86_64_kvm.json`, QEMU 8.2.2, `/dev/kvm` available locally.

**Prerequisites:** Phase 1 (branch `sanghle/kvm-seams`) must be merged or based on. `cargo check -p litebox_platform_lvbs --no-default-features --features host_kvm` succeeds today.

**Design doc:** `docs/plans/2026-08-08-litebox-on-kvm-design.md`
**Phase 1 debt list:** end of `docs/plans/2026-08-08-kvm-phase1-seam-extraction.md`

---

## Deviation from the design doc's sequencing

The design doc (§6) orders this as allocator → boot. **This plan boots first.**

PVH entry is the phase's only real unknown — everything else is code we can read from `litebox_runner_lvbs`. An allocator we cannot boot is unverifiable, whereas a boot with no allocator is provable in one QEMU run. If PVH turns out not to work as expected, we want to discover that in Task 2, not Task 6.

## Background you need

**VTL vocabulary.** `litebox_platform_lvbs` was written for Hyper-V VTL1, a higher-privilege peer to the normal Linux kernel (VTL0). Phase 1 gated all of that behind a `host_lvbs` feature. Under `host_kvm` LiteBox is simply the kernel. You will still see VTL names in shared code — Phase 1 deliberately did not rename them.

**What already exists and should be reused, not rewritten:**
- `litebox_runner_lvbs/src/main.rs` — `.rela.dyn` relocation loop, `common_start` boot ordering, `HostLogger`. Read this before writing any boot code.
- `litebox_runner_lvbs/src/lib.rs:94` `init()` — the `Platform::new()` call with text ranges and heap seeding.
- `litebox_runner_optee_on_linux_userland/src/lib.rs:105-149` — how to drive the OP-TEE shim *without* a VTL0 caller. **This is the model for our TA execution**, not the LVBS runner, which is driven by VTL0 requests that will never arrive on KVM.
- `litebox_runner_optee_on_linux_userland/tests/` — `ldelf.elf` and `hello-ta.elf` are already in-tree. Use them; do not build new ones.

**What must NOT be reused:** anything under `litebox_platform_lvbs::mshv` — it does not compile under `host_kvm`.

## Hazard discovered in Task 2: LLVM mis-assembles symbol arithmetic in immediates

**Read this before writing any 32-bit or boot assembly.** LLVM's Intel-syntax operand
parser silently mis-assembles address arithmetic. Task 2 triple-faulted on it:

| Written | Result |
|---|---|
| `a - b + c` inline | hard error, "cannot use more than one symbol in memory operand" |
| `(a + c)` | **silently** parsed as a memory dereference — `push (X)` became `push DWORD PTR [X]` |
| `offset a + c` | **silently** drops the addend, and emitted a 16-bit `pushw` |

The middle case is what bit: a far-return target assembled to a *load of the code bytes at
that label*, which then served as its own bogus jump address.

Only the `.set` directive's expression parser handles this arithmetic correctly. The
working pattern:

```asm
.set SYM_ABS, (label - _start + 0x200000)
mov eax, offset SYM_ABS      // stage through a register to avoid operand-size guessing
push eax
```

**Disassembly review is mandatory, not optional, for boot asm on this toolchain.** Verify
with `objdump -d` that what you wrote is what was emitted, before running it. A
`-d int,cpu_reset` dump that shows the mode switch *succeeded* (correct `CS64`, `EFER.LMA`,
`CR3`, `CR4.PAE`) but faults at an address outside the image is the signature of this bug.

Related constraint: the target links `--pie`, and `rust-lld` rejects every 32-bit absolute
relocation against an ordinary symbol (`R_X86_64_32 cannot be used against symbol ...`).
32-bit mode has no RIP-relative fallback, so boot structures live in a linker-reserved
`NOLOAD` region at fixed PA `0x1000000`, referenced as plain immediates. `_heap_start`
begins above that region.

## QEMU CPU model matters (found in Task 5)

**TCG runs must use `-cpu max`.** The default `qemu64` model lacks RDRAND, so
`CrngProvider` panics the moment anything asks for randomness. Task 10's TA almost
certainly will. `-cpu max` also exposes RDRAND under TCG, verified producing distinct
values.

**Do not trust CPUID frequency leaves.** The dev host is an AMD EPYC 7763; leaves
`0x15`/`0x16` are Intel-only and QEMU here reports max hypervisor leaf `0x40000001`, so
`0x40000010` is absent too. Worse, at the default `level=0xd`, `-cpu max` returns
*leaf-0xd contents* for leaf `0x15` — `eax=0x21f ebx=0x240 ecx=0xa88`, which parses as a
plausible crystal ratio. CPUID returns the highest supported leaf's data for out-of-range
input. **The max-leaf guards in `arch/x86/clock.rs` are load-bearing; do not remove them.**

Working frequency sources, in the order the clock tries them:
| Source | Where it wins |
|---|---|
| CPUID `0x15`/`0x16`/`0x40000010` | Intel hardware; never on this dev host |
| KVM pvclock, MSR `0x4b564d01` | `--kvm` (2445432000 Hz observed) |
| i8254 PIT calibration | TCG, always (~2.4457 GHz observed, agrees with pvclock to 0.02%) |

## Two boot hazards found in Task 5

- **SSE must be enabled before any non-trivial Rust runs.** `CR0.EM` is set and
  `CR4.OSFXSR` clear at reset. SSE2 is x86-64 ABI baseline, so *any* Rust function may
  emit xmm instructions. The boot path survived early tasks only because it was all
  integer code; `rand_chacha` `#UD`'d immediately. With no IDT that is a silent triple
  fault — `qemu exit: 0` and no output. Fixed in `595451a4`.
- **The boot stack grows towards the early page tables.** Both live in the `NOLOAD`
  scratch region at PA `0x1000000`, with the tables at its base. A stack overflow
  destroys the mapping needed to report it. Enlarged to 512 KiB in `595451a4`, but a
  real guard page needs 4 KiB granularity the 2 MiB early tables cannot express.
  **Task 6 should address this** when it builds proper page tables.

## Phase 1 gating errors surface only when code is actually called

Two `host_kvm` breakages were invisible throughout Phase 1 and only appeared in Task 7,
when `init_idt()` was first called. **`--gc-sections` hides link errors until something
references the object.** Expect more of these as Tasks 8 and 10 light up `mm` and the shim.

- **`interrupts.S` undefined symbol.** Phase 1 gated the STIMER *IDT entry* and the
  `stimer_handler_impl` *Rust function*, but `interrupts.S` is pulled in by `global_asm!`
  unconditionally and its `isr_stimer` stub still contains `call stimer_handler_impl`.
  Result under `host_kvm`: `rust-lld: error: undefined symbol: stimer_handler_impl`.
  Fixed with a `host_kvm`-only panicking definition — chosen over splitting the `.S`,
  which would have reordered LVBS's emitted assembly.
- **`enable_extended_states()` asserted a VTL0 premise.** It ends with
  `assert!(xcr0.contains(SSE), "XCR0 must have SSE enabled by VTL0")`. Under PVH we boot
  from reset, where XCR0 is architecturally `0x1` (x87 only) — there is no VTL0 to have
  set it. `host_kvm` now sets `XCR0.X87|SSE` itself, which it is entitled to do as sole
  owner of the register. Needed by `allocate_xsave_area` (`VTL1_XSAVE_MASK = 0b11`).

## Deferred to Task 8 (real page tables)

- **`_guard_page_0` / `_guard_page_1` in `PerCpuVariables` are padding, not guard pages.**
  They are plain `[u8; PAGE_SIZE]` fields and nothing anywhere marks them non-present.
  A kernel stack overflow runs straight into `exception_stack` with no fault. **This is an
  LVBS bug too**, not just a KVM gap — worth reporting to that crate's owners.
- **VA 0 is mapped.** The early identity map covers the low 1 GiB, so a null dereference
  does not fault. Real page tables should unmap page zero.
- **SMAP enforcement is unverified.** No USER-accessible page exists yet. Task 10 should
  confirm a kernel read of a user page faults, and succeeds between `stac`/`clac`.

## CR0.WP was clear — found in Task 8, and it mattered

**PVH leaves `CR0.WP` clear** (`CR0 = 0x8000_0013` at entry). With WP clear, a *supervisor*
write to a read-only page **succeeds silently**. The read-only `.text` mapping would have
been decorative: the W^X test would have passed by not faulting, and we would have reported
a guarantee that did not exist.

LVBS never sets WP because Hyper-V hands VTL1 a CR0 that already has it. Nothing in the
shared code sets it. The runner now sets WP **before** the CR3 switch, so there is no
interval where `.text` is nominally read-only and actually writable.

This is exactly the class of bug that only testing a claim can find — the code looked
correct, the mapping was correct, and the guarantee was absent.

Verified DEP state after the switch (4 KiB granularity, no USER bit anywhere):

| Region | Flags | Probe | CR2 | Error code |
|---|---|---|---|---|
| `.text` | `[rXs]` read-only, executable | write to `.text+0x40` | `0xffffe20000200040` | `0x3` present+write |
| heap / `.data` / stack | `[WNs]` writable, NX | call into a heap page | `0xffffe20000608000` | `0x11` present+**instruction fetch** |
| VA 0 | unmapped | null read | `0x0` | `0x0` not-present |

The NX probe's faulting RIP *equals* the data page address, which is what makes it a real
instruction-fetch fault rather than a data fault that happened to be nearby.

## Verification gates

**Gate P1 — Phase 1 invariant.** Every task must leave the LVBS build untouched:
```bash
/tmp/lvbs-check.sh
```
Expected: `Gate A' symbols de61da6739bc88fe6239f820ac42f334f6e59056e06cf09c8be040bb484c61c2`, `12599`, `fmt CLEAN`, `15 passed; 0 failed`.

If you change shared code in `litebox_platform_lvbs`, this hash WILL move. That is allowed in Phase 2 — but only deliberately. Diff the symbol tables, confirm the delta is what you intended, and rebaseline in your commit message. Never rebaseline silently.

**Gate P2 — the KVM build:**
```bash
cargo +nightly-2025-12-31 build -Z build-std-features=compiler-builtins-mem \
  -Z build-std=core,alloc --manifest-path=litebox_runner_optee_on_kvm/Cargo.toml \
  --target litebox_runner_optee_on_kvm/x86_64_kvm.json
```

**Gate P3 — it actually boots.** From Task 2 onward every task ends with a QEMU run. A task that compiles but does not boot is not done.

Helper (create in Task 1):
```bash
cat > /tmp/kvm-run.sh <<'EOF'
#!/bin/sh
# Boot the KVM runner. Pass --kvm to use hardware acceleration.
cd /workspace/litebox-kvm/.worktrees/kvm-seams
BIN=target/x86_64_kvm/debug/litebox_runner_optee_on_kvm
ACCEL=""
[ "$1" = "--kvm" ] && ACCEL="-enable-kvm -cpu host"
timeout 30 qemu-system-x86_64 -machine q35 $ACCEL -m 512M \
  -kernel "$BIN" -nographic -no-reboot \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04
echo "qemu exit: $?"
EOF
chmod +x /tmp/kvm-run.sh
```

Note on `isa-debug-exit`: QEMU exits with `(value << 1) | 1`. So writing `0` gives exit 1, writing `1` gives exit 3. Pick a success value and document it; do not expect exit 0.

**Always test under TCG first** (no `--kvm`). It is slower but deterministic and does not need `/dev/kvm`. Confirm with `--kvm` before committing, since CI may or may not have KVM.

---

### Task 1: Crate skeleton, PVH note, linker script

**Files:**
- Create: `litebox_runner_optee_on_kvm/Cargo.toml`
- Create: `litebox_runner_optee_on_kvm/x86_64_kvm.json`
- Create: `litebox_runner_optee_on_kvm/x86_64_kvm.ld`
- Create: `litebox_runner_optee_on_kvm/rust-toolchain.toml`
- Create: `litebox_runner_optee_on_kvm/src/main.rs`
- Modify: `Cargo.toml` (workspace `members`; do **not** add to `default-members` — it needs a custom target, like `litebox_runner_lvbs`)

**Step 1: `rust-toolchain.toml`** — copy `litebox_runner_lvbs/rust-toolchain.toml` verbatim (`nightly-2025-12-31`).

**Step 2: `x86_64_kvm.json`** — copy `litebox_runner_lvbs/x86_64_vtl1.json`, changing only the linker script paths to `litebox_runner_optee_on_kvm/x86_64_kvm.ld`.

**Step 3: `x86_64_kvm.ld`** — start from `litebox_runner_lvbs/x86_64_vtl1.ld` with three changes:

1. **Delete the `.hvcall_page` section.** There is no hypervisor to write code into it.
2. **Do NOT discard `.note.*`.** The `/DISCARD/` block currently lists `*(.note.*)`; removing that line is what makes PVH possible at all. Add an explicit `.note` output section so it lands in a `PT_NOTE` program header:
   ```
   .note : ALIGN(4) { KEEP(*(.note.Xen)) KEEP(*(.note .note.*)) }
   ```
3. Keep `_memory_base`, `_heap_start`, `_text_start`/`_text_end`, `_rela_start`/`_rela_end` — Phase 1 left the platform depending on all of them.

**Step 4: The PVH note.** QEMU reads `XEN_ELFNOTE_PHYS32_ENTRY` (type 18) from a note with name `"Xen"`. In `src/main.rs`:

```rust
#[repr(C, align(4))]
struct Note {
    namesz: u32,
    descsz: u32,
    ntype: u32,
    name: [u8; 4],   // "Xen\0"
    desc: u32,       // 32-bit entry point address
}

#[used]
#[unsafe(link_section = ".note.Xen")]
static PVH_NOTE: Note = Note {
    namesz: 4,
    descsz: 4,
    ntype: 18, // XEN_ELFNOTE_PHYS32_ENTRY
    name: *b"Xen\0",
    desc: PVH_ENTRY_ADDR,
};
```

`PVH_ENTRY_ADDR` must be the *physical* address of your 32-bit entry symbol. Because the image is PIE-linked at `0x200000`, this is a link-time constant — but verify it rather than assuming. If a `static` cannot reference a symbol address as a `u32` const, define the entry address as a linker-script symbol or a fixed constant and place the entry stub there explicitly.

**Step 5: minimal `main.rs`.** `#![no_std] #![no_main]`, a panic handler that halts, and a `#[unsafe(naked)] extern "C"` 32-bit entry that does nothing but write bytes to COM1:

```rust
// 32-bit protected mode, paging off, %ebx -> hvm_start_info.
// Write 'P','V','H' to COM1 (0x3F8) and halt. No UART init needed:
// QEMU's 16550 accepts writes to THR immediately.
```
Use raw `out dx, al` in the naked asm. Do not call into Rust yet — you are not in long mode.

**Step 6: verify the note is actually in the binary**

```bash
readelf -n target/x86_64_kvm/debug/litebox_runner_optee_on_kvm
readelf -l target/x86_64_kvm/debug/litebox_runner_optee_on_kvm | grep NOTE
```
You must see a `PT_NOTE` segment and a `Xen` note of type `0x12`. **If `PT_NOTE` is absent, QEMU will silently fall back to another boot protocol and nothing will work** — do not proceed past this check.

**Step 7: boot it**

```bash
/tmp/kvm-run.sh
```
Expected: `PVH` on the console. Then `/tmp/kvm-run.sh --kvm` — same output.

If nothing appears, debug with `-d int,cpu_reset` and check whether QEMU took the PVH path at all.

**Step 8: commit** — `Add litebox_runner_optee_on_kvm skeleton with PVH entry point`

---

### Task 2: 32-to-64-bit trampoline

**Files:** Modify `litebox_runner_optee_on_kvm/src/main.rs`

Build early page tables in `.bss`, enter long mode, reach Rust.

**Step 1** — reserve three static page tables (PML4, PDPT, PD), 4 KiB-aligned, in a `static mut` or a `#[repr(align(4096))]` static.

**Step 2** — in the 32-bit stub, before touching anything else, **save `%ebx`** (the `hvm_start_info` pointer). It is the only way to find the memory map and it is easily clobbered. Stash it somewhere that survives the transition.

**Step 3** — map with 2 MiB pages:
- identity map the low 1 GiB (so we keep executing after enabling paging)
- map the same 1 GiB at `KERNEL_OFFSET` (`0xFFFF_E200_0000_0000`) — this is what `MemoryProvider::pa_to_va` assumes

**Step 4** — the standard sequence: set `CR4.PAE`, load `CR3`, set `EFER.LME` via `wrmsr(0xC0000080)`, set `CR0.PG`, `lgdt` a flat 64-bit GDT, then `ljmp` to a 64-bit code segment.

**Step 5** — in 64-bit code set up a stack (a `static` array in `.bss` is fine) and `call` a Rust `extern "C" fn`. That function prints via COM1 and halts.

**Step 6** — verify: `/tmp/kvm-run.sh` prints from Rust in long mode. Confirm under both TCG and KVM.

**Common failure:** a triple-fault reboot loop. `-no-reboot` turns it into an exit; add `-d int,cpu_reset` to see the faulting state. Nearly always a bad page table or a GDT that is not reachable at its physical address.

**Step 7: commit** — `Enter long mode from the PVH 32-bit entry point`

---

### Task 3: Relocation and the serial logger

**Files:** Modify `litebox_runner_optee_on_kvm/src/main.rs`

**Step 1** — port the `.rela.dyn` `R_X86_64_RELATIVE` loop from `litebox_runner_lvbs/src/main.rs` (search `Elf64Rela`). The image is PIE; until this runs, no absolute address in a static is valid. Read the LVBS "two-phase relocation" comments carefully — they explain why linker symbols return high-canonical VAs afterwards.

**Step 2** — install the `HostLogger` from `litebox_runner_lvbs/src/main.rs` (it forwards `log` records to `serial_print_string`). Phase 1 already routed `print()` to COM1 under `host_kvm`, so `serial_println!` works.

**Step 3** — verify: `serial_println!` output appears, including a formatted value that requires a relocated static.

**Step 4: commit** — `Apply .rela.dyn relocations and install the serial logger`

---

### Task 4: Fix the `Instant` tick-unit trap BEFORE writing the clock

**This is Phase 1 debt and it must be paid before Task 5.** See the debt list: `REF_COUNTER_TICK_NANOS` is a Hyper-V constant (100 ns per *partition reference counter* tick) that Phase 1 hoisted into the shared `arch::x86` module. Under `host_kvm`, `Instant::checked_duration_since` and `checked_add` already compile against it. If you implement a TSC-based `now()` without fixing this first, you get a type that compiles, never warns, and returns durations wrong by the TSC-to-100ns ratio.

**Files:** Modify `litebox_platform_lvbs/src/arch/x86/mod.rs`, `litebox_platform_lvbs/src/lib.rs`

**Step 1** — make the tick unit per-host. Under `host_lvbs` keep 100 ns with its existing doc. Under `host_kvm` define the unit that your Task 5 clock will actually produce.

**Step 2** — fix the stale docs the review flagged: `Instant`'s own doc ("Backed by the Hyper-V partition reference counter") and `REF_COUNTER_TICK_NANOS`'s ("partition reference counter").

**Step 3** — Gate P1. This touches shared code, so expect the LVBS symbol hash to move only if you changed LVBS-side codegen; if the `host_lvbs` value is genuinely unchanged the hash must NOT move. Verify and report.

**Step 4: commit** — `Make the Instant tick unit per-host`

---

### Task 5: TSC clock for `host_kvm`

**Files:** Modify `litebox_platform_lvbs/src/host/kvm_impl.rs` (or a new `arch/x86/clock.rs`), `litebox_platform_lvbs/src/lib.rs`

`Instant::now()` currently panics under `host_kvm`.

**Step 1** — read the TSC frequency from CPUID leaf `0x15` (TSC/core crystal ratio) and `0x16` if needed. **If the leaf is absent or reports zero, panic with a clear message rather than guessing a frequency.** A loud failure is correct here; a fabricated calibration is the thing Phase 1 deliberately refused to write.

**Step 2** — implement `now()` as `rdtsc` scaled to your Task 4 tick unit.

**Step 3** — the design doc's §1 seam table also lists `CrngProvider` and `DerivedKeyProvider` as unimplemented for `KvmGuest`. Implement `CrngProvider` with `RDRAND` seeding (mirror `lvbs_impl.rs`'s `rdrand_seed`, minus the PRK). Leave `DerivedKeyProvider` returning `UnsupportedRebootPersistentKey` — there is no platform root key on KVM, and inventing one would be worse than admitting it.

**Step 4** — verify by printing two `Instant`s around a busy loop and checking the delta is plausible. Gate P1 + P3.

**Step 5: commit** — `Add a TSC-based clock and RDRAND CRNG for host_kvm`

---

### Task 6: Heap from the PVH memory map

**Files:** Create `litebox_runner_optee_on_kvm/src/memmap.rs`; modify `litebox_platform_lvbs/src/host/kvm_impl.rs`

> **Mandatory first step: delete `NoAllocatorYet`.** Task 3 had to link
> `litebox_platform_lvbs`, which fails to *compile* without a `#[global_allocator]`
> (`host_kvm` deliberately provides none, since the heap needs the PVH memmap). Task 3
> therefore added a placeholder in the runner whose every method `panic!`s. It is
> scaffolding, not an implementation. This task must remove it entirely and replace it
> with the real `SafeZoneAllocator` wiring. **If it survives this task, the phase has a
> latent panic in it.**

This is the piece LVBS never needed — VTL0 hands it fixed memory, so `HostLvbsInterface::alloc` is a `panic!`.

**Step 1** — define `hvm_start_info` and `hvm_memmap_table_entry` per the PVH boot spec. Fields you need: `magic` (`0x336ec578`), `version`, `memmap_paddr`, `memmap_entries`. Each entry is `{ addr: u64, size: u64, type: u32, reserved: u32 }`; type 1 is usable RAM.

**Step 2** — **validate the magic before trusting anything.** If it does not match, panic with the observed value. A wrong pointer here corrupts memory silently.

**Step 3** — implement `crate::mm::MemoryProvider` and `litebox::mm::allocator::MemoryProvider` for `KvmGuest`, backed by `SafeZoneAllocator`, mirroring the `#[cfg(not(test))] mod alloc` block in `lvbs_impl.rs:20-58`. Register the `#[global_allocator]`.

**Step 4** — walk the memmap and `mem_fill_pages` every type-1 region, **excluding**:
- everything below 1 MiB (legacy)
- the kernel image itself (`_memory_base` .. `_heap_start`)
- the `hvm_start_info` structure and the memmap table
- your early page tables and boot stack, if they are inside the image

Getting this wrong gives an allocator that hands out memory you are executing from. Print each accepted region and its size; eyeball the total against `-m 512M`.

**Step 5** — verify: allocate a `Vec`, push enough to force several growths, print it. Then allocate something larger than a slab (>2 MiB) to exercise the page path. Gate P3.

**Step 6: commit** — `Seed the KVM heap from the PVH memory map`

---

### Task 7: Per-CPU state, GDT, IDT, syscall entry

**Files:** Modify `litebox_runner_optee_on_kvm/src/main.rs`

Follow `common_start` in `litebox_runner_lvbs/src/main.rs:396-430` — the ordering there is load-bearing.

**Step 1** — in order: `enable_fsgsbase()`, `enable_extended_states()`, seed heap (Task 6), `allocate_per_cpu_variables()`, `init_per_cpu_variables()`, switch `rsp` to the per-CPU kernel stack.

Phase 1 gated the Hyper-V fields out of `PerCpuVariables`, so this should work unmodified. If it does not, that is a Phase 1 gating error — report it rather than patching around it.

**Step 1b (folded in from Task 6)** — **add a stack guard page.** Task 5 found the boot
stack grows towards the early page tables in the same `NOLOAD` scratch region; an overflow
destroys the mapping needed to report it. Task 6 deliberately deferred the guard page to
here, and the reasoning is worth preserving: a guard page needs 4 KiB-granular tables, and
armed *before* the IDT exists it converts silent corruption into a silent triple fault —
no improvement. Once this task installs a `#PF` handler that can report `CR2`, the guard
becomes genuinely diagnostic. Build it after the IDT is live, not before.

**Step 2** — **`enable_smep_smap()`.** Phase 1's security argument for dropping VSM protection explicitly depends on this being called (see the debt list, MIN-5). It is not optional; it is the boundary.

**Step 3** — `interrupts::init()` for the IDT, `gdt` setup with TSS, `syscall_entry::init()`.

**Step 4** — verify each layer deliberately:
- trigger `int3` and confirm the handler prints and returns
- read a null pointer and confirm the page-fault handler reports it
- confirm `rdgsbase` returns the per-CPU pointer

Do not skip this. An IDT that is silently wrong will present later as an inexplicable triple fault during TA execution.

**Step 5: commit** — `Bring up per-CPU state, GDT, IDT and syscall entry`

---

### Task 8: Platform construction and DEP page tables

**Files:** Modify `litebox_runner_optee_on_kvm/src/main.rs`

**Step 1** — mirror `litebox_runner_lvbs/src/lib.rs:94` `init()`: compute `text_phys_start`/`text_phys_end` from the linker symbols, call `Platform::new(phys_start, phys_end, text_phys_start, text_phys_end)`.

Under `host_kvm`, Phase 1 gated out the hvcall page from `exec_ranges`, so only `.text` stays executable. That is correct and is the DEP guarantee.

**Step 2** — reclaim `.rela.dyn` into the allocator, as the LVBS runner does.

**Step 3** — `litebox_platform_multiplex::set_platform()` and `litebox_platform_lvbs::set_platform_low()`.

Use the `platform_kvm` feature added at the end of Phase 1 — that is exactly what it is for. Do **not** pin `host_kvm` on the dependency directly; that was the bug Phase 1 fixed.

**Step 4** — verify the new page tables are live: confirm a write to a `.text` address faults, and that normal data access still works. A DEP claim you have not tested is not a DEP guarantee.

**Step 5: commit** — `Construct the KVM platform with DEP-enforcing page tables`

---

### Task 9: Clean exit via isa-debug-exit

**Files:** Modify `litebox_platform_lvbs/src/host/kvm_impl.rs`

**Step 1** — implement `exit()` and `terminate()` to write to port `0xf4`. Choose distinct values for success and failure, and document the `(value << 1) | 1` transformation in a comment so nobody later wonders why success is exit code 3.

**Step 2** — fall through to `hlt_loop()` after the write, so the signature stays `-> !` and behaviour is defined if the device is absent.

**Step 3** — also route the panic handler through `terminate()` with a failure code, so a panicking guest fails the test rather than hanging until `timeout` kills it.

**Step 4** — verify both paths: a successful exit and a deliberate panic, checking the shell exit code each time.

**Step 5: commit** — `Exit the guest through isa-debug-exit`

---

### Task 10: Load and run an OP-TEE TA

**Files:** Modify `litebox_runner_optee_on_kvm/src/main.rs`; add `litebox_shim_optee` to `litebox_runner_optee_on_kvm/Cargo.toml`

**Model this on `litebox_runner_optee_on_linux_userland/src/lib.rs:105-149`, not on the LVBS runner.** The LVBS runner waits for VTL0 to make requests; on KVM nobody will.

**Step 1** — embed the binaries:
```rust
static LDELF: &[u8] = include_bytes!("../../litebox_runner_optee_on_linux_userland/tests/ldelf.elf");
static TA: &[u8] = include_bytes!("../../litebox_runner_optee_on_linux_userland/tests/hello-ta.elf");
```
`hello-ta.elf` is the simplest; save `aes-ta` and `kmpp-ta` for later.

**Step 2a** — `litebox_shim_optee` has no `platform_kvm` feature yet. It currently offers
only `platform_linux_userland` and `platform_lvbs`, with `platform_lvbs` as default, each
forwarding to the matching `litebox_platform_multiplex` feature. Add:

```toml
platform_kvm = ["litebox_platform_multiplex/platform_kvm"]
```

and depend on it with `default-features = false, features = ["platform_kvm"]`. This mirrors
exactly what Phase 1 did for `litebox_platform_multiplex` — the host choice belongs in a
feature, not pinned on a dependency.

**Step 2b** — build the shim: `OpteeShimBuilder::new()`, then `.build()`.

**Step 3** — reproduce the open-session flow:
```
session_manager().try_acquire_open_session_token()
shim.load_ldelf(LDELF, TeeUuid::default(), Some(TA))
run_thread_ref(entrypoints, &mut PtRegs::default())      // ldelf runs, loads the TA
entrypoints.load_ta_context(&params, session_id, UteeEntryFunc::OpenSession as u32, None)
reenter_thread_ref(entrypoints, &mut PtRegs::default())  // TA's OpenSession runs
```
Use `litebox_platform_lvbs::{run_thread_ref, reenter_thread_ref}` (lib.rs:1406, 1421) in place of the userland runner's platform-specific calls.

**Step 4** — then `CloseSession`, then `exit()` with the success code.

**Step 5** — verify: the console shows ldelf loading the TA and the TA's own output, and QEMU exits with the success code. Under both TCG and KVM.

**Expect trouble here**, and expect it to be informative. Likely failure modes:
- a syscall the shim makes that `host_kvm` stubs with `unimplemented!()` — implement it properly; do not stub it further
- a missing trait impl on `KvmGuest` from the Phase 1 debt list (`ThreadLocalStorageProvider` is the likely one, and it is not LVBS-specific — it just reads `pcv.tls`)
- ring-3 entry faulting, which usually means the TSS or `syscall_entry::init()` from Task 7 is wrong

For each failure, fix the cause. **If you find yourself adding a stub to make the TA appear to work, stop and report instead** — a TA that "runs" against faked syscalls proves nothing.

**Step 6: commit** — `Load and execute an OP-TEE TA under KVM`

---

### Task 11: Integration test

**Files:** Create `litebox_runner_optee_on_kvm/tests/boot.rs` (or a `dev_tests` entry, matching repo convention — check where `litebox_runner_lvbs`-adjacent tests live first)

**Step 1** — a test that shells out to QEMU with the same arguments as `/tmp/kvm-run.sh`, captures stdout, and asserts:
- the process exit code equals the Task 9 success value
- the TA's expected output appears on the console

**Step 2** — **assert on the failure path too.** A test that only checks the happy path will pass against a guest that exits successfully without running anything. Add a case that forces a panic and asserts the failure exit code.

**Step 3** — run under TCG, with no `-enable-kvm`, so it works without `/dev/kvm`. Gate the KVM-accelerated variant behind an env var or `#[ignore]`.

**Step 4** — put a generous `timeout` on the QEMU invocation. A hung guest must fail the test, not hang CI.

**Step 5: commit** — `Add a QEMU boot-and-run integration test`

---

### Task 12: CI

**Files:** Modify `.github/workflows/ci.yml`

**Step 1** — add a `litebox_runner_optee_on_kvm` build using the nightly toolchain and `-Z build-std`, modelled on the existing `build_and_test_lvbs` job (around line 156).

**Step 2** — add the Task 11 integration test, with `qemu-system-x86_64` installed via apt in the job. TCG only — do not assume runners expose `/dev/kvm`.

**Step 3** — `litebox_runner_optee_on_kvm` needs the same exclusions `litebox_runner_lvbs` has from the workspace-wide sweeps (custom target, `no_std`). Check every place `litebox_runner_lvbs` is excluded and add the new crate alongside it. Phase 1 touched four such sites; expect the same four.

**Step 4** — verify the whole CI file locally: run every command you added, and re-check `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"`.

**Step 5: commit** — `Build and test the KVM runner in CI`

---

### Task 13: Pay down the remaining Phase 1 debt

Only after the TA runs. See the debt list at the end of the Phase 1 plan.

**Step 1** — fix the `SAFETY:` comment at `lib.rs:1179-1181` that asserts a check which does not happen under `host_kvm` (split it per host; the conclusion holds, the justification does not).

**Step 2** — update the `host_kvm` security comment to state that the runner *does* call `enable_smep_smap()` — by Task 7 this is true, so the comment can finally be a fact rather than an obligation.

**Step 3** — give `kvm_impl.rs`'s module doc an accurate inventory of what is and is not implemented.

**Step 4** — gate `host/bootparam.rs` and `host/linux.rs::CpuMask` behind `host_lvbs` (dead under `host_kvm`; `pub` so `dead_code` never fires).

**Step 5** — make the LVBS-only dependencies optional in `litebox_platform_lvbs/Cargo.toml` (`litebox_common_lvbs`, `rand_chacha`, `rand_core`, `sha2`, `digest`, `zeroize`, `modular-bitfield`) — but check first whether Task 5's CRNG now needs `rand_chacha`/`rand_core` under `host_kvm`.

**Step 6** — add `nextest -p litebox_platform_lvbs --no-default-features --features host_kvm` to CI.

**Step 7** — Gate P1 + P2 + P3, then commit each item separately.

---

## Definition of done

- `/tmp/kvm-run.sh` boots, runs `hello-ta`, and exits with the success code, under both TCG and KVM.
- The integration test passes, including its failure case.
- Gate P1 holds, or any movement is deliberate, diffed and documented.
- CI builds the KVM runner and runs the integration test.
- No stub added to make the TA appear to work.

## Out of scope

SMP / AP bring-up, APIC-timer preemption (the `host_kvm` gap Phase 1 marked), virtio-net, a Linux-shim runner on the same platform, and UEFI boot. All are post-milestone-1 — see the design doc §3 and §6.
