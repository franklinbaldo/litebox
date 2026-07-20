# LVBS Platform Refactoring Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Move OP-TEE/HEKI/HVCI policy code out of `litebox_platform_lvbs` into `litebox_runner_lvbs`, leaving the platform with only VTL1 resource management and Hyper-V/VTL0 interaction primitives — mechanically, with no semantics change.

**Architecture:** Introduce a `litebox_common_lvbs` crate for the pure shared type/const surface. Split `mshv/vsm.rs` into a platform-resident VSM core (bootstrap, AP boot, lock_regs, protected-frame registry) and runner-resident policy (module/kexec validation, patching, mem_integrity, ringbuffer). The runner's existing `vtlcall_dispatch` becomes the sole dispatcher.

**Tech Stack:** Rust `no_std`, `-Z build-std` against `x86_64_vtl1.json`, custom Hyper-V VSM/VTL1 kernel.

**Design reference:** `docs/plans/2026-07-20-lvbs-platform-refactoring-design.md`

---

## Conventions

### Verification command (`VERIFY`)

Run after every change set. All must pass with zero warnings/errors:

```bash
TOOLCHAIN=$(awk -F'"' '/channel/{print $2}' litebox_runner_lvbs/rust-toolchain.toml)
# Workspace-level clippy on the new common crate (CI runs --workspace -Dwarnings)
cargo +$TOOLCHAIN clippy -p litebox_common_lvbs --all-targets --all-features
# Platform host-target unit tests
cargo +$TOOLCHAIN test --manifest-path=litebox_platform_lvbs/Cargo.toml
# build-std clippy + build for platform and runner
for M in litebox_platform_lvbs litebox_runner_lvbs; do
  cargo +$TOOLCHAIN clippy --lib --bins --examples --no-deps --all-features \
    -Z build-std-features=compiler-builtins-mem -Z build-std=core,alloc \
    --manifest-path=$M/Cargo.toml --target litebox_runner_lvbs/x86_64_vtl1.json
  cargo +$TOOLCHAIN build \
    -Z build-std-features=compiler-builtins-mem -Z build-std=core,alloc \
    --manifest-path=$M/Cargo.toml --target litebox_runner_lvbs/x86_64_vtl1.json
done
```

### Principles

- **Mechanical only.** Copy code verbatim; adjust `use`/visibility paths. No logic edits.
- **Preserve semantics.** If a behavior would change, stop and flag it.
- **Commit per task**, only after `VERIFY` is clean.
- When a moved item needs to be reachable across a crate boundary, prefer
  making it `pub` in its new home over adding a re-export shim; add temporary
  re-exports only if needed to keep an intermediate step building.

---

## Task 1: Create `litebox_common_lvbs` crate with the shared surface

**Files:**
- Create: `litebox_common_lvbs/Cargo.toml`
- Create: `litebox_common_lvbs/src/lib.rs`
- Modify: `Cargo.toml` (workspace `members` + `default-members`)
- Modify: `litebox_platform_lvbs/Cargo.toml` (add dep)
- Modify: `litebox_runner_lvbs/Cargo.toml` (add dep)
- Modify: `litebox_platform_lvbs/src/mshv/mod.rs`, `mshv/heki.rs`, `mshv/error.rs`

**Step 1:** Create `litebox_common_lvbs/Cargo.toml` (`no_std` lib). Include only deps the moved types need: `bitflags`, `num_enum`, `zerocopy`, `modular-bitfield`, `x86_64` (for the `x86_64` target), `litebox` (for `TruncateExt`), `litebox_common_linux`. Add `[lints] workspace = true`.

**Step 2:** Add `litebox_common_lvbs` to workspace `members` and `default-members` in root `Cargo.toml`.

**Step 3:** Create `litebox_common_lvbs/src/lib.rs` (`#![no_std]`, `extern crate alloc` if needed). Move **verbatim** into it:
- From `mshv/mod.rs`: `VsmFunction` + every `VSM_VTL_CALL_FUNC_ID_*` const, `NUM_VTLCALL_PARAMS`.
- From `mshv/error.rs`: `VsmError` (entire file).
- From `mshv/heki.rs`: `MemAttr`, `HekiRange`, `HekiPage`, `HekiPatch`, `HekiPatchType`, `HekiPatchInfo`, `HekiKernelSymbol`, `HekiKernelInfo`, `ModMemType`, `HekiKdataType`, `HekiKexecType`, `HEKI_MAX_RANGES`, `POKE_MAX_OPCODE_SIZE` (entire file).
- `PAGE_SIZE` / `PAGE_SHIFT` (define here; `mshv/vtl1_mem_layout.rs` currently owns these — re-export from common there instead of duplicating).

**Step 4:** In `litebox_platform_lvbs/Cargo.toml` and `litebox_runner_lvbs/Cargo.toml`, add `litebox_common_lvbs = { path = "...", version = "0.1.0" }`.

**Step 5:** Delete `mshv/error.rs` and the moved items from `mshv/heki.rs` / `mshv/mod.rs`. Replace in-crate references with `use litebox_common_lvbs::...`. To minimize churn, in `mshv/mod.rs` add `pub use litebox_common_lvbs::{VsmFunction, VsmError, ...};` re-exports so existing `crate::mshv::VsmFunction` paths keep working. Keep `mshv/heki.rs` as a module that re-exports the common types if other platform code imports `mshv::heki::*`.

**Step 6:** Run `VERIFY`. Fix path/visibility fallout only.

**Step 7:** Commit: `git commit -m "Add litebox_common_lvbs crate with shared VSM/HEKI types"`

---

## Task 2: (REMOVED) Ringbuffer stays in the platform

**Decision (2026-07-20):** `ringbuffer.rs` is consumed by the platform's own
print path (`arch/x86/ioport.rs::print` calls `ringbuffer()`). Moving it to the
runner would force a platform→runner function-pointer callback hook — an
architectural/indirection change, not a mechanical move, and it changes
semantics. Ringbuffer is normal-world debug-log infrastructure, not
OP-TEE/HEKI/HVCI policy, so it **stays in the platform**.

The only policy piece — the `AllocateRingbufferMemory` VSM dispatch arm
(`mshv_vsm_allocate_ringbuffer_memory`, which calls `set_ringbuffer`) — moves to
the runner as part of Task 3. To support that, `set_ringbuffer` becomes a `pub`
platform primitive (folded into Task 3, Step 4). No file move, no separate
commit.

---

## Task 3: Split `vsm.rs` — policy to runner, core stays in platform

**Files:**
- Create: `litebox_runner_lvbs/src/vsm.rs` (policy)
- Modify: `litebox_platform_lvbs/src/mshv/vsm.rs` (retain core, make primitives `pub`)
- Modify: `litebox_platform_lvbs/src/lib.rs` (remove `vtl0_kernel_info` field + `Vtl0KernelInfo` import)
- Modify: `litebox_platform_lvbs/src/host/per_cpu_variables.rs` (keep `ControlRegMap` import from platform)
- Modify: `litebox_runner_lvbs/src/lib.rs` (own the full `vtlcall_dispatch`; add `Vtl0KernelInfo` global)

**Step 1 — classify.** In platform `mshv/vsm.rs` KEEP: `init`, `mshv_vsm_enable_aps`, `mshv_vsm_boot_aps`, `mshv_vsm_secure_config_vtl0`, `mshv_vsm_configure_partition`, `mshv_vsm_get_code_page_offsets`, `mshv_vsm_lock_regs`, `save_vtl0_locked_regs`, `ControlRegMap`, `NUM_CONTROL_REGS`, `ProtectedFrameRegistry` + guards, `protected_frame_registry`, `protect_physical_memory_range`, `unprotect_physical_memory_range`, `protect_vtl1_physical_memory_range`.

**Step 2 — move policy.** Move to runner `src/vsm.rs`: `mshv_vsm_end_of_boot`, `mshv_vsm_protect_memory`, `mshv_vsm_load_kdata`, `parse_certs`, `mshv_vsm_validate_guest_module`, `mshv_vsm_free_guest_module_init`, `mshv_vsm_unload_guest_module`, `mshv_vsm_copy_secondary_key`, `mshv_vsm_kexec_validate`, `mshv_vsm_patch_text`, `copy_heki_patch_from_vtl0`, `apply_vtl0_text_patch`, `mshv_vsm_allocate_ringbuffer_memory`, `mshv_vsm_set_platform_root_key`, `copy_heki_pages_from_vtl0`, and all policy data structures: `Vtl0KernelInfo`, `ModuleMemoryMetadataMap`/`Metadata`/`Range`/`Iters`, `ModuleMemory`, `MemoryContainer`, `MemoryContainerError`, `KexecMemoryMetadata*`/`Range`, `PatchDataMap`.

**Step 3 — Vtl0KernelInfo global.** In the runner, add `static VTL0_KERNEL_INFO: spin::Once<Vtl0KernelInfo>` + `fn vtl0_kernel_info() -> &'static Vtl0KernelInfo` (init on first use). Replace every `crate::platform_low().vtl0_kernel_info` with `vtl0_kernel_info()`. Remove the `vtl0_kernel_info` field from `LinuxKernel` (`lib.rs:392,625`) and the `use ...vsm::Vtl0KernelInfo` at `lib.rs:9`.

**Step 4 — expose platform primitives `pub`.** Make `pub` (crate-external): `protect_physical_memory_range`, `unprotect_physical_memory_range`, `protected_frame_registry`/needed guard types, and a `pub` privileged-vmap entry the runner's patch code needs (currently `PrivilegedVmap`/`vmap_privileged` in `mshv/mod.rs`). Also expose `mshv::ringbuffer::set_ringbuffer` as `pub` so the runner's moved `mshv_vsm_allocate_ringbuffer_memory` can install the ring buffer (ringbuffer.rs itself stays in the platform — see Task 2 decision). Expose the smallest surface that lets runner policy call these. `ControlRegMap` stays `pub` in platform (used by `per_cpu_variables`).

**Step 5 — dispatch.** Delete platform `vsm_dispatch`. In runner `lib.rs`, extend `vtlcall_dispatch` (already routes `OpteeMessage`): route `EnableAPsVtl`/`BootAPs`/`LockRegs`/`SignalEndOfBoot` to the appropriate handlers (platform `pub` fns for AP/lock; runner `end_of_boot`), and all policy IDs to runner `vsm::` handlers. Preserve exact error mapping (`Errno::from(VsmError)`).

**Step 6 — init wiring.** `vsm::init` stays in platform and is still called from `mshv/hvcall.rs:163`. Confirm it no longer references moved policy. `mem_integrity::parse_modinfo` reference inside moved code now resolves within the runner (Task 4).

**Step 7:** `VERIFY`. Fold in Task 2 if ordering requires.

**Step 8:** Commit: `git commit -m "Split vsm.rs: move VSM/HEKI policy to runner, keep VSM core in platform"`

---

## Task 4: Move `mem_integrity.rs` to the runner

**Files:**
- Create: `litebox_runner_lvbs/src/mem_integrity.rs`
- Delete: `litebox_platform_lvbs/src/mshv/mem_integrity.rs`
- Modify: `mshv/mod.rs` (drop `mod mem_integrity;`), runner `lib.rs` (add `mod mem_integrity;`)

**Step 1:** Copy `mem_integrity.rs` to the runner verbatim. Fix imports: `crate::debug_serial_println`/`serial_println` → the runner's logging macros; `vsm::ModuleMemory` → `crate::vsm::ModuleMemory` (now runner-local); shared types → `litebox_common_lvbs`.

**Step 2:** Remove `mod mem_integrity;` from `mshv/mod.rs`; delete the platform file. Ensure `parse_modinfo` (used by runner `vsm`) is reachable.

**Step 3:** `VERIFY`.

**Step 4:** Commit: `git commit -m "Move mem_integrity from platform to runner"`

---

## Task 5: Cleanup and dependency migration

**Files:**
- Modify: `litebox_platform_lvbs/Cargo.toml`, `litebox_runner_lvbs/Cargo.toml`
- Modify: `litebox_platform_lvbs/src/mshv/mod.rs`, `mshv/heki.rs`, `lib.rs`

**Step 1 — deps.** Move crypto/ELF deps now used only by runner policy from `litebox_platform_lvbs/Cargo.toml` to `litebox_runner_lvbs/Cargo.toml`: `elf`, `cms`, `rsa`, `sha2`, `x509-cert`, `const-oid`, `authenticode`, `object`, `digest`, `aligned-vec`, `zeroize`, and any `rand_*` only used by moved code. Verify each is unused in the platform via grep before removing.

**Step 2 — dead code.** Remove now-unused platform re-exports/shims (`mshv/heki.rs` if empty, dead `use`s, `PrivilegedVmap` if fully moved), and any `platform_low` machinery no longer needed. If `mshv/heki.rs` is now just re-exports and nothing in the platform uses it, delete it and its `mod` line.

**Step 3 — docs.** Update `litebox_platform_lvbs/README.md` and any module docs that describe the platform as owning module verification / HEKI / OP-TEE.

**Step 4:** `VERIFY` (including `cargo test`).

**Step 5:** Commit: `git commit -m "Migrate policy-only dependencies to runner and remove dead platform code"`

---

## Final verification

- Run full `VERIFY`; zero warnings.
- `git log --oneline` shows 5 focused commits.
- Confirm platform `mshv/` no longer contains: `mem_integrity.rs`, `ringbuffer.rs`, module/kexec/patch policy, `Vtl0KernelInfo`.
- Confirm platform still contains: hvcall/hvcall_mm/hvcall_vp, vtl_switch, vsm_intercept, vtl1_mem_layout, VSM core (init, AP boot, lock_regs, protected-frame registry, `protect_physical_memory_range`).
- Use superpowers:requesting-code-review before finishing.
