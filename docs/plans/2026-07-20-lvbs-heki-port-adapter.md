# LVBS HEKI/HVCI Port–Adapter Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: superpowers:executing-plans / subagent-driven-development.

**Goal:** Re-architect so HEKI/HVCI algorithms live in a host-testable `litebox_heki` library, generic over a `HekiEnforcer` port; the platform provides the adapter; the runner is the composition root. Realizes "test HEKI/HVCI without a real LVBS platform" and closes the exposed-security-surface findings.

**Design:** `docs/plans/2026-07-20-lvbs-heki-port-adapter-design.md`.

**Mechanical where possible:** algorithm bodies move verbatim; the only substantive change is replacing direct platform calls with `enforcer.*` calls and threading `HekiState`. Preserve all validation/enforcement semantics.

---

## VERIFY (per task)

```bash
TOOLCHAIN=$(awk -F'"' '/channel/{print $2}' litebox_runner_lvbs/rust-toolchain.toml)
cargo +$TOOLCHAIN clippy -p litebox_common_lvbs --all-targets --all-features
cargo +$TOOLCHAIN clippy -p litebox_heki --all-targets --all-features       # host build + tests
cargo +$TOOLCHAIN test  -p litebox_heki --all-features
cargo +$TOOLCHAIN test  --manifest-path=litebox_platform_lvbs/Cargo.toml
for M in litebox_platform_lvbs litebox_runner_lvbs; do
  cargo +$TOOLCHAIN clippy --lib --bins --examples --no-deps --all-features \
    -Z build-std-features=compiler-builtins-mem -Z build-std=core,alloc \
    --manifest-path=$M/Cargo.toml --target litebox_runner_lvbs/x86_64_vtl1.json
  cargo +$TOOLCHAIN build \
    -Z build-std-features=compiler-builtins-mem -Z build-std=core,alloc \
    --manifest-path=$M/Cargo.toml --target litebox_runner_lvbs/x86_64_vtl1.json
done
```

---

## Task A: Create `litebox_heki` crate with the `HekiEnforcer` port

- Create `litebox_heki/{Cargo.toml,src/lib.rs}` (`no_std`, host-buildable; `extern crate alloc`). Deps: `litebox_common_lvbs`, `litebox_common_linux`, `x86_64`, and (for later tasks) the crypto/ELF crates. Add to workspace members + default-members. `[lints] workspace = true`.
- Define in `litebox_heki`: `EnforceError`; `trait FrameTxn { reserve, protect }`; `trait HekiEnforcer { read_vtl0*, protect_frames_transactionally, apply_text_patch, install_ringbuffer, set_platform_root_key }` exactly as in the design (generic read methods; closure-based transaction; `&mut dyn FrameTxn`).
- No consumers yet. `VERIFY` (litebox_heki builds host + target).
- Commit: `Add litebox_heki crate with HekiEnforcer port`.

## Task B: Platform implements `HekiEnforcer` (adapter)

- Add a platform type (e.g. `PlatformHekiEnforcer` or impl on the existing `LinuxKernel`) implementing `litebox_heki::HekiEnforcer`:
  - reads → existing `Vmap`-backed `Vtl0PhysConstPtr`.
  - `protect_frames_transactionally` → wraps `FrameReservation` (reserve initial, build a private `FrameTxn` adapter over the reservation + `protect_physical_memory_range`, run closure, `commit()` on Ok / drop-rollback on Err).
  - `apply_text_patch` → the page-span logic + `PrivilegedVtl0PhysMutPtr` writes (moved from the runner's `apply_vtl0_text_patch`).
  - `install_ringbuffer`/`set_platform_root_key` → existing installers, returning `AlreadyInitialized` on second call.
- Keep primitives `pub` for now (removed in Task D). `VERIFY`. Commit: `Implement HekiEnforcer adapter in platform`.

## Task C: Move algorithms into `litebox_heki`, generic over the port

- Move from `litebox_runner_lvbs/src/{vsm.rs,mem_integrity.rs}` into `litebox_heki`: `mshv_vsm_validate_guest_module`, `mshv_vsm_kexec_validate`, `mshv_vsm_load_kdata`, `mshv_vsm_protect_memory`, `mshv_vsm_patch_text`, `mshv_vsm_end_of_boot`, cert parsing, all `mem_integrity` functions, and the metadata/patch-map data structures + `Vtl0KernelInfo` (renamed to `HekiState`, passed explicitly).
- Rewrite each to take `enforcer: &impl HekiEnforcer` and `state: &HekiState`, replacing every direct platform call:
  - VTL0 reads (`Vtl0PhysConstPtr…`) → `enforcer.read_vtl0*`.
  - `FrameReservation`/`protect`/`unprotect` sequences → `enforcer.protect_frames_transactionally(initial, |txn| { … txn.reserve/protect … })`.
  - `apply_vtl0_text_patch` write → `enforcer.apply_text_patch`.
  - `set_ringbuffer`/`set_platform_root_key` → `enforcer.*`.
  - logging macros → `log` crate facade (so tests link without platform).
- Runner: dispatcher (`vtlcall_dispatch`) constructs/holds the platform enforcer + the single `HekiState`, and calls `litebox_heki::*` for policy IDs; VSM-core arms (EnableAPs/BootAPs/LockRegs) still call the platform directly. Remove the moved code from the runner.
- `VERIFY`. Commit: `Move HEKI/HVCI algorithms into litebox_heki generic over HekiEnforcer`.

## Task D: Make platform enforcement primitives private

- Now the only consumer is the platform's own adapter. Revert to private: `FrameReservation`, `ReservationStatus`, `protect_physical_memory_range`, `unprotect_physical_memory_range`, `PrivilegedVmap`, `PrivilegedVtl0PhysMutPtr`, `set_ringbuffer`, PRK installer, and delete the `write_validated_vtl0_patch_*` pub fns (their body now lives in `apply_text_patch`).
- `VERIFY`. Commit: `Make platform enforcement primitives private behind the enforcer adapter`.

## Task E: `MockEnforcer` + host unit tests

- In `litebox_heki` (under `#[cfg(test)]` or a `mock` feature): `MockEnforcer` backed by an in-memory map of PA→bytes for VTL0 reads, an in-memory frame-protection set for the transaction, and capture buffers for `apply_text_patch`/ringbuffer/PRK.
- Unit tests driving `validate_guest_module`, `kexec_validate`, and `apply_text_patch` with crafted inputs (happy path + a rejection path each), asserting protections/writes recorded by the mock. Reuse the migrated `mem_integrity` tests (now host-runnable).
- `VERIFY` (tests execute on host). Commit: `Add MockEnforcer and host-run HEKI/HVCI unit tests`.

## Task F: Cleanup + docs

- Remove dead re-exports/deps; move pure data types (`Kimage`, `KEXEC_SEGMENT_MAX`, `ModuleSignature`) to `litebox_common_lvbs` if that removes the last runner→platform data coupling in the algorithms.
- Update platform/runner READMEs to describe the port–adapter split.
- `VERIFY` + full workspace `cargo build`. Commit: `Clean up after HEKI port–adapter migration`.

## Final
- Full `VERIFY`; confirm `cargo test -p litebox_heki` runs real HEKI/HVCI tests on the host with no platform.
- superpowers:requesting-code-review, then finishing-a-development-branch.
