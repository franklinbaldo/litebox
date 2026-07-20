# LVBS Kernel Platform Refactoring — Design

Date: 2026-07-20

## Goal

Strip OP-TEE / HEKI / HVCI **policy** out of the LVBS kernel platform
(`litebox_platform_lvbs`) so the platform only concerns itself with:

- its own VTL1 resource management (page tables, memory, per-CPU state), and
- primitives for interacting with the normal world (VTL0) and Hyper-V
  (hypercalls, VTL switch, interrupts).

All *policy over those primitives* — what to verify, what to patch, what a
"module"/"certificate"/"kexec image" is — moves to the runner
(`litebox_runner_lvbs`).

This refactoring is **mechanical**: no behavior/semantics changes. Only code
location, crate boundaries, and visibility change.

> Note: This supersedes the earlier attempt on `sanghle/lvbs/refactoring`.
> We do **not** follow it verbatim because the tree has since gained the
> protected-frame registry (concurrent VTL0 mappings, commit 210db69c), which
> changes how `vsm.rs` must be split. OP-TEE SMC/session handling is already
> runner-side in the current tree, so it is out of scope here.

## Boundary Principle

The platform keeps anything that is (a) VTL1 resource management, or (b) a
*primitive* for talking to Hyper-V / VTL0. The runner gets anything that is
*policy* over those primitives.

## Target Crate Structure

Three crates:

- **`litebox_common_lvbs`** (new, `no_std`): pure, logic-free shared data
  types + constants depended on by both platform and runner.
- **`litebox_platform_lvbs`** (slimmed): `arch`, `mm`, page tables, `host`,
  and under `mshv/`: `hvcall`, `hvcall_mm`, `hvcall_vp`, `vtl_switch`,
  `vsm_intercept`, `vtl1_mem_layout`, plus a **platform-resident VSM core**.
- **`litebox_runner_lvbs`** (grows): the policy modules — `mem_integrity`,
  HEKI/HVCI verification, module/kexec validation, `patch_text`,
  `Vtl0KernelInfo`, `ringbuffer`, and the policy half of VSM dispatch.

### `litebox_common_lvbs` contents (surgical — shared surface only)

- `VsmFunction` enum + all `VSM_VTL_CALL_FUNC_ID_*` constants
- `MemAttr`, `VsmError` (needed by the platform's retained
  `protect_physical_memory_range`)
- All HEKI **data** types from `heki.rs` (`HekiRange`, `HekiPage`,
  `HekiPatch`, `HekiPatchInfo`/`HekiPatchType`, `HekiKernelSymbol`,
  `HekiKernelInfo`, and the `ModMemType` / `HekiKdataType` / `HekiKexecType`
  enums)
- `PAGE_SIZE` / `PAGE_SHIFT`

The platform keeps its bulky Hyper-V hypercall structs/constants in
`mshv/mod.rs`; the runner never references them directly, so they stay put to
avoid needless churn.

## Splitting `vsm.rs`

`vsm.rs` (~2423 lines) mixes platform bootstrap/resource management with
policy. It must be **split**, not moved wholesale.

### Stays in platform (VSM core; primitives become `pub`)

- `init` (VSM bootstrap: partition config + VTL1 memory protection)
- `mshv_vsm_enable_aps`, `mshv_vsm_boot_aps` (AP startup)
- `mshv_vsm_secure_config_vtl0`, `mshv_vsm_configure_partition`,
  code-page-offsets
- `mshv_vsm_lock_regs` + `save_vtl0_locked_regs` + `ControlRegMap`
  (per-CPU, used by `host/per_cpu_variables.rs`)
- `ProtectedFrameRegistry` + guards, `protected_frame_registry`,
  `protect_physical_memory_range`, `unprotect_physical_memory_range`,
  `protect_vtl1_physical_memory_range` — the platform's own `vmap` depends on
  these; they are exposed as `pub` platform primitives.

### Moves to runner (policy)

- `mshv_vsm_end_of_boot`, `mshv_vsm_protect_memory`, `mshv_vsm_load_kdata`,
  `parse_certs`, `mshv_vsm_validate_guest_module`,
  `mshv_vsm_free_guest_module_init`, `mshv_vsm_unload_guest_module`,
  `mshv_vsm_copy_secondary_key`, `mshv_vsm_kexec_validate`,
  `mshv_vsm_patch_text`, `copy_heki_patch_from_vtl0`, `apply_vtl0_text_patch`,
  `mshv_vsm_allocate_ringbuffer_memory`, `mshv_vsm_set_platform_root_key`
- Policy data structures: `Vtl0KernelInfo`, `ModuleMemory*`,
  `MemoryContainer`, `Kexec*`, `PatchDataMap`, `HekiPatch` builders
- These call `protect_physical_memory_range` (etc.) via the platform's now-`pub`
  primitives.

### Dispatch & globals

- The runner already owns `vtlcall_dispatch`. It becomes the single dispatcher:
  platform-subset IDs (`EnableAPsVtl`, `BootAPs`, `LockRegs`) call the newly
  `pub` platform fns; policy IDs call runner-local handlers. The platform's
  `vsm_dispatch` is deleted.
- `Vtl0KernelInfo` moves out of the `LinuxKernel` struct into a runner
  `spin::Once` global (as the old attempt did), removing the
  `vtl0_kernel_info` field and its coupling from `platform_low()`.

## Sequencing (incremental, per-module commits)

Each step builds + commits independently so the work is reviewable/bisectable.

1. Create `litebox_common_lvbs`; move the shared surface; update platform
   imports/re-exports. Verify.
2. Move `ringbuffer.rs` → runner. Verify.
3. Split `vsm.rs`: policy fns + `Vtl0KernelInfo` (→ runner global) + dispatch →
   runner; platform retains VSM-core with `pub` `protect_physical_memory_range`,
   AP boot, `lock_regs`, `ProtectedFrameRegistry`. Runner's `vtlcall_dispatch`
   becomes sole dispatcher. Verify.
4. Move `mem_integrity.rs` → runner (its `ModuleMemory` dep now lives there).
   Verify.
5. Cleanup: drop dead platform re-exports, the `vtl0_kernel_info` field, fix
   docs. Verify.

## Verification (per step)

From `bacon.toml`:

- clippy + `build-std` build of **both** `litebox_platform_lvbs` and
  `litebox_runner_lvbs` against `x86_64_vtl1.json`:
  ```
  cargo +$TOOLCHAIN clippy --lib --bins --examples --no-deps --all-features \
    -Z build-std-features=compiler-builtins-mem -Z build-std=core,alloc \
    --manifest-path=litebox_runner_lvbs/Cargo.toml --target litebox_runner_lvbs/x86_64_vtl1.json
  cargo +$TOOLCHAIN build ... --manifest-path=litebox_platform_lvbs/Cargo.toml --target litebox_runner_lvbs/x86_64_vtl1.json
  ```
- `cargo test` for the platform's host-target unit tests (`mshv/mod.rs`
  bitfield tests, `mm/tests.rs`).

## Non-Goals

- No behavior/semantics changes.
- No move of OP-TEE SMC/session handling (already runner-side).
- No move of the platform's Hyper-V hypercall struct/constant definitions.
- No KPTI or other security hardening.
