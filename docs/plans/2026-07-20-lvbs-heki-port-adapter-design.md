# LVBS HEKI/HVCI Port–Adapter Refactoring — Design

Date: 2026-07-20 (addendum to `2026-07-20-lvbs-platform-refactoring-design.md`)

## Vision

**Algorithms live in the runner-side library; enforcement/implementation lives
in the platform — connected by a trait (port).** The HEKI/HVCI *algorithms*
(what to validate, crypto, ELF parsing, which frames to protect, which patches
to apply) must not touch VTL1/Hyper-V directly. They reach the platform only
through a `HekiEnforcer` trait. Because the algorithms are generic over that
trait, a **mock enforcer** allows unit-testing HEKI/HVCI logic on the host with
plain byte buffers — no real LVBS platform, no Hyper-V.

This is hexagonal architecture: `HekiEnforcer` is the **port** (defined with the
algorithms, in `litebox_heki`); the platform provides the **adapter** (the real
implementation); the runner is the **composition root** that wires them together.

## Crate topology

```
litebox_common_lvbs      pure data types/consts (HekiPatch, MemAttr, VsmError, ...)
        ▲
litebox_heki             HEKI/HVCI algorithms + `trait HekiEnforcer` (port)
   ▲        ▲            + MockEnforcer + host unit tests. no_std, host-buildable.
   │        │            deps: common_lvbs, crypto/ELF crates. NO platform dep.
   │        │ implements HekiEnforcer (adapter)
   │   litebox_platform_lvbs   real enforcement; FrameReservation, protect/unprotect,
   │        ▲                   PrivilegedVmap, ringbuffer/PRK install all PRIVATE.
   └─── litebox_runner_lvbs     composition root: constructs platform enforcer,
                                dispatches VSM calls to litebox_heki algorithms.
```

No cycles: `litebox_heki` depends only on `litebox_common_lvbs`; the platform
depends on `litebox_heki` (to implement the port) and `common`; the runner
depends on both.

## The `HekiEnforcer` port

Captures exactly the platform operations the algorithms need. Consumed by
generics (`&impl HekiEnforcer`), not `dyn` (zero-cost, allows generic methods).

```rust
pub trait HekiEnforcer {
    // --- VTL0 foreign physical-memory reads (guarded) ---
    fn read_vtl0<T: FromBytes>(&self, pa: usize) -> Result<T, EnforceError>;
    fn read_vtl0_pages<T: FromBytes>(
        &self, pages: &[PhysPageAddr<PAGE_SIZE>], offset: usize,
    ) -> Result<T, EnforceError>;
    fn read_vtl0_bytes(&self, pa: usize, out: &mut [u8]) -> Result<(), EnforceError>;
    fn read_vtl0_bytes_pages(
        &self, pages: &[PhysPageAddr<PAGE_SIZE>], offset: usize, out: &mut [u8],
    ) -> Result<(), EnforceError>;

    // --- TOCTOU-safe protected-frame transaction ---
    // Platform reserves `initial`, runs `f`, commits on Ok / rolls back on Err.
    fn protect_frames_transactionally(
        &self,
        initial: &[PhysFrameRange],
        f: &mut dyn FnMut(&mut dyn FrameTxn) -> Result<(), VsmError>,
    ) -> Result<(), VsmError>;

    // --- validated privileged text write ---
    fn apply_text_patch(&self, patch: &HekiPatch) -> Result<(), VsmError>;

    // --- one-time security state (return error if already set) ---
    fn install_ringbuffer(&self, pa: u64, size: usize) -> Result<(), VsmError>;
    fn set_platform_root_key(&self, key: &[u8]) -> Result<(), VsmError>;
}

/// Restricted handle handed to the transaction closure — the only way to
/// reserve/protect frames, scoped to the transaction. Not constructible by
/// callers; the guard type stays private in the platform.
pub trait FrameTxn {
    fn reserve(&mut self, ranges: &[PhysFrameRange]) -> Result<Vec<ReservationStatus>, VsmError>;
    fn protect(&mut self, range: PhysFrameRange, attr: MemAttr) -> Result<(), VsmError>;
}
```

### Security properties regained
- `FrameReservation`, `ReservationStatus` (concrete), `protect/unprotect`,
  `PrivilegedVmap`, `set_ringbuffer`, PRK-init are **all private** to the
  platform. They are only reachable through the trait impl.
- The privileged write is only `apply_text_patch`, which the platform adapter
  performs after the algorithm has validated the patch; no free-floating
  "write arbitrary VTL0" fn (finding 1).
- One-time inits return `AlreadyInitialized` errors instead of silently
  ignoring a second caller (finding 2).
- The frame-protection lifecycle is platform-owned; the runner cannot hold or
  leak a reservation guard across the boundary.

## Algorithm state

`Vtl0KernelInfo` (precomputed patches, system certificates, module/kexec
metadata) is algorithm state and moves into `litebox_heki`. To keep tests
hermetic it is passed to the algorithms as an explicit context
(`&HekiState` / `&mut HekiState`) rather than a hidden global; the runner owns
the single long-lived instance.

## What stays where
- `litebox_heki`: `mshv_vsm_validate_guest_module`, `mshv_vsm_kexec_validate`,
  `mshv_vsm_load_kdata`, `mshv_vsm_protect_memory`, `mshv_vsm_patch_text`,
  `mshv_vsm_end_of_boot`, cert parsing, `mem_integrity` (signature/ELF/reloc),
  the module/kexec metadata + patch-map data structures, `HekiEnforcer` port,
  `MockEnforcer`, tests.
- Platform: the `HekiEnforcer` adapter impl; VSM-core (init, AP boot, lock_regs,
  ControlRegMap, ProtectedFrameRegistry, protect/unprotect, PrivilegedVmap,
  ringbuffer, PRK) — now all private except the trait impl; hvcall/vtl_switch/etc.
- Runner: composition root — builds the platform enforcer + `HekiState`,
  dispatches VSM function IDs to `litebox_heki` algorithms, VSM-core dispatch
  arms (EnableAPs/BootAPs/LockRegs) call the platform directly.

## Testability deliverable
`litebox_heki` builds for the host and ships a `MockEnforcer` (byte-buffer
backed VTL0 memory, in-memory frame-protection set) plus unit tests that drive
`validate_guest_module` / `kexec_validate` / `apply_text_patch` end-to-end with
crafted inputs — proving HEKI/HVCI logic is testable without an LVBS platform.

## Non-goals
- No change to the actual validation/enforcement semantics.
- Data types (`Kimage`, `KEXEC_SEGMENT_MAX`, `ModuleSignature`) that are pure
  move to `litebox_common_lvbs` as needed; no behavioral change.
