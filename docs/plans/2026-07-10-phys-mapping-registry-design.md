# Design: Separate Mapping from Physical Pointer Descriptors

Date: 2026-07-10

## Problem

The OP-TEE driver packs multiple requests into sub-page slots of a single
physical frame. Multiple cores on the base (kernel) page table therefore attempt
to map the *same* frame concurrently. LiteBox's vmap layer maintains a strict 1:1
PA→VA registry (`litebox_platform_lvbs/src/mm/vmap.rs`, `pa_to_va_map`) and
rejects any second mapping of an already-mapped frame with
`VmapAllocError::DuplicateMapping` / `PhysPointerError::AlreadyMapped`
(`litebox_shim_optee/src/ptr.rs:426`). The concurrent access is thus rejected and
the kernel crashes.

PR #979 ("Fix: Serialize packed-`OpteeMsgArgs` access") mitigates this with a
single global `SpinMutex` (`packed_msg_args_lock`) taken around three reads and
one write. This is correct but blunt:

- It over-serializes. The root cause is not a read/write **data** hazard — it is
  the mapping registry's inability to share a frame. Concurrent *read-only*
  access to the same frame is inherently safe and should not need serialization.
- It serializes reads against unrelated reads and does nothing structural about
  the 1:1 mapping limitation the TODO in `msg_handler.rs` already flags.

## Root Cause

`map_info: Option<PhysPageMapInfo<ALIGN>>` lives *inside* `PhysMutPtr`
(`ptr.rs:111`). Each pointer instance exclusively owns its mapping, so two
pointers over the same frame produce two independent map attempts. The mapping
lifetime is coupled to the pointer, and the registry has no concept of sharing or
reference counting.

## Approach

Separate the mapping from the pointer struct. The pointer becomes a **pure,
immutable descriptor**; the mapping lives in a shared, reference-counted registry
that enforces reader/writer semantics per frame.

### Decisions

- **Pure descriptor.** `PhysMutPtr` / `PhysConstPtr` keep their names but drop
  `map_info`. All access methods take `&self` (no more `&mut`). The `Mut`/`Const`
  distinction now expresses **access capability** (write-capable vs read-only),
  not mapping ownership.
- **RwLock-style per-frame semantics.** Multiple concurrent read guards share one
  RO mapping; a write guard is exclusive and waits for readers to drain.
- **Deadlock-free multi-frame acquisition** via a global ascending-physical-
  address lock ordering.
- **Eager unmap on last release** (refcount → 0), preserving the existing
  "no persistent normal-world mapping" security posture (`ptr.rs:14-25`).

## Component Split

1. **`PhysMutPtr` / `PhysConstPtr` (descriptors).** Pure, immutable, `Clone`.
   Fields: `pages`, `offset`, `count`, `_type`. No mapping state. Constructed and
   validated exactly as today (`new`, `with_contiguous_pages`, `with_usize`).
   `PhysConstPtr` may request read guards only; `PhysMutPtr` may request read or
   write guards.

2. **`FrameMapRegistry` (global).** The only caller of `platform().vmap/vunmap`.
   Owns VA mappings and per-frame reader/writer state. Lives near `VmapManager`
   (`litebox_common_linux::vmap` or a sibling module).

3. **Access guards** — `FrameReadGuard` / `FrameWriteGuard`, plus a composite
   guard for multi-frame descriptors. A descriptor's `read()` / `write()` asks the
   registry to acquire the needed frames; the guard exposes the mapped base VA and,
   on drop, releases its refcount so the registry can eager-unmap.

## Registry State

Replace the 1:1 `pa_to_va_map` with a per-frame entry:

```text
FrameEntry {
    va:      VirtAddr,      // the single mapping's base VA
    perms:   RO | RW,       // current mapping permission
    readers: usize,         // active read guards
    writer:  bool,          // an active write guard
}
registry: SpinMutex<HashMap<PhysFrame, FrameEntry>>
```

The outer `SpinMutex` guards only the bookkeeping (lookup, refcount inc/dec,
map/unmap decisions) in tiny critical sections. It is **not** held while callers
read/write frame data. Reader/writer exclusion is enforced by the `readers` /
`writer` fields.

- **Acquire read (frame):** lock → absent: `vmap` RO, insert `readers=1`. Present,
  RO, no writer: `readers += 1`. Present with writer/RW: wait. Unlock, return guard.
- **Acquire write (frame):** lock → require `readers==0 && !writer`. Absent: `vmap`
  RW. Present as RO: remap RW (unmap+map or PTE perm flip). Set `writer=true`.
  Otherwise wait.
- **Release:** lock → decrement `readers` or clear `writer`; if both zero, `vunmap`
  and remove the entry (eager).

Because the registry is 1:1 PA→VA, a frame has exactly one VA at a time. "Shared
RO" and "exclusive RW" are two **states** of that single mapping, not two
coexisting mappings.

## Waiting & Deadlock-Free Acquisition

- **Waiting:** spin-with-backoff on the bookkeeping mutex — release the registry
  `SpinMutex`, pause, re-lock, re-check. No condvars. Critical sections are tiny
  and OP-TEE traffic is low-volume, so contention is negligible. A per-frame ticket
  for fairness is deferred (YAGNI).

- **Multi-frame acquisition (ascending PA order):**
  1. Collect the descriptor's distinct frames, sort ascending by physical address.
  2. Acquire each frame's read/write state in that order, spinning per-frame.
  3. Waiting on frame *k* while holding *0..k* cannot cycle because every core
     acquires in the same global PA order → deadlock-free.
  4. Return a composite guard owning all N acquisitions; drop releases them.

  The composite guard computes base VA + `offset` to hand back the region, exactly
  as `MappedGuard` does today (`ptr.rs:391`). Convoy stalls under heavy contention
  are acceptable for this workload; liveness holds because the core holding the
  lowest contended frame always progresses.

## Access API

```text
impl PhysConstPtr<T, ALIGN> {
    fn read_at(&self, idx: usize) -> Result<T, PhysPointerError>;
    fn read_slice_at_offset(&self, off: usize, buf: &mut [u8]) -> Result<..>;
    // registry.acquire_read(sorted_frames)? -> guard -> copy out
}
impl PhysMutPtr<T, ALIGN> {
    // all read methods, plus:
    fn write_at(&self, idx: usize, val: &T) -> Result<..>;
    fn write_slice_at_offset(&self, off: usize, data: &[u8]) -> Result<..>;
    // registry.acquire_write(sorted_frames)? -> guard -> copy in
}
```

Each call is self-contained: acquire → copy to/from the LiteBox-owned buffer →
drop guard (eager unmap). Preserves the "copy before use, never hold a persistent
mapping" invariant.

## Call-Site Migration

Files: `litebox_shim_optee/src/msg_handler.rs`,
`litebox_runner_lvbs/src/lib.rs`, `litebox_shim_optee/src/ptr.rs`,
`dev_tests/src/ratchet.rs`.

- Delete `packed_msg_args_lock()` and all four PR #979 guards. The registry now
  enforces correct concurrency intrinsically.
- `write_non_ta_msg_args_to_normal_world`: `ptr.write_slice_at_offset(0, &blob)`
  needs no external lock; the write guard serializes against concurrent same-frame
  reads automatically.
- The three read sites (`CallWithArg`, `CallWithRpcArg`, RPC `read_at`) call the
  `read_*` methods. Reads of different frames run fully parallel; reads of the same
  frame share one RO mapping.
- `PhysMutPtr` values no longer need `mut` bindings — remove the `mut` plumbing.
- Revert the `ratchet.rs` global-count bump (the static lock disappears).

## Net Effect

- The crash is fixed at the mapping layer (the true root cause), not papered over
  with a coarse lock.
- Reads become lock-free-concurrent (across frames) or RO-shared (same frame).
- Writes are exclusive per frame.
- PR #979's global mutex is fully removed.
- The security posture (no persistent normal-world mapping) is preserved via eager
  unmap.

## Out of Scope / Future Work

- Fairness (per-frame ticketing) if spin convoys ever become measurable.
- Lazy/cached mappings (rejected here: reintroduces persistent-mapping windows).
- Broader use of the registry beyond OP-TEE (the descriptor types are not
  OP-TEE-specific; see the TODO at `ptr.rs:61`).
