# Multi-segment TA loading fails under LiteBox's VMA allocator

Date: 2026-08-08
Status: diagnosed, not fixed. Affects `litebox_runner_lvbs` and `litebox_runner_kvm`.
Not a KVM-specific issue; recorded here because that is where it surfaced.

## Summary

Any TA with **three or more `PT_LOAD` segments** fails to load with
`TEE_ERROR_ACCESS_CONFLICT` (`0xffff0003`) from `ldelf`. Two-segment TAs are
unaffected, which is why nothing has noticed: `hello`, `aes`, `random` and
`kmpp` all have exactly two.

The cause is that **LiteBox allocates top-down while `ldelf`'s protocol assumes
bottom-up**. It is in core `litebox` memory management, shared by every
platform that uses `Vmem` — so it affects LVBS as well as KVM. The userland
runner is immune only because it uses the host's `mmap` rather than `Vmem`.

## Mechanism

`ldelf` loads a TA in several `sys_map_bin` calls:

| # | call | placement |
|---|---|---|
| 1 | `addr=0, num_bytes=4096, pad=0/0` | one-page ELF header map, kernel-chosen |
| 2 | `addr=0, num_bytes=<seg0>, pad_begin=<ASLR>, pad_end=<rest of image>` | the image, kernel-chosen |
| 3+ | `addr=<fixed>, pad_end=<rest of image>` | later segments, `MAP_FIXED_NOREPLACE` |

Only step 3 exists for a 3+-segment TA, and only step 3 takes the
`MAP_FIXED_NOREPLACE` branch that calls `ensure_pads_are_unmapped`.

`pad_end` grows **upward** from each segment, covering the remainder of the
image. So step 3's padding extends toward the top of the image span — into
whatever sits immediately above it.

- **OP-TEE allocates bottom-up, first-fit.** The header page from step 1 lands
  *below* the image from step 2, and the address space above the image is free.
  Step 3's upward padding lands in nothing.
- **LiteBox allocates top-down and packs flush** (`get_unmmaped_area`,
  `litebox/src/mm/linux.rs:886`). The header page, allocated *first*, gets the
  *highest* address; the image is packed immediately beneath it. The image
  span's upper edge is pinned against the header page with zero slack, and
  step 3's padding has nowhere to go.

Measured with `hello3seg-ta`:

```
2nd call: pad_begin=0x50000  num_bytes=0xefec  pad_end=0xE000
  padded span   0x7fffffc8d000 .. 0x7fffffcfa000
  usable        0x7fffffcdd000 .. 0x7fffffcec000
1st call (header page)
                0x7fffffcfa000 .. 0x7fffffcfb000   <- exactly the span's upper edge
3rd call: addr=0x7fffffcec000  num_bytes=0x1860  pad_end=0xD000
  padding       0x7fffffcee000 .. 0x7fffffcfb000   <- one page into the header page
```

`ldelf`'s `pad_end` also overshoots the image span by one page, because it
rounds the pad up from the *unrounded* segment end while the mapping size is
rounded separately. Under bottom-up allocation that overshoot is harmless; it
only matters because top-down packing leaves no slack.

Note this is invariant under `ldelf`'s ASLR: top-down pins the span's *upper*
edge, so `header_page − load_addr` is `0x1D000` for every value of `pad_begin`.
A randomised failure would have looked like flakiness; the determinism is what
made it diagnosable.

## Things that are *not* the cause

Recorded because each was proposed and disproved, and each is a plausible
wrong turn:

- **Not the stack.** The TA stack *is* flagged `VM_GROWSDOWN`, the
  `STACK_GUARD_GAP << 1` logic does engage, and it works — there is 2 MiB of
  free space below the stack. The conflict is with the ELF header page, 2 MiB
  lower.
- **Not a missing reservation.** OP-TEE does not reserve the pad area either;
  `select_va_in_range` checks the range is free at allocation time, exactly as
  `ensure_pads_are_unmapped` does.
- **Not our padding check being too strict.** `optee_os/core/mm/vm.c`
  (`select_va_in_range`, lines 81-105) enforces `pad_end` for a caller-named
  `va` too. Relaxing our check would *diverge* from OP-TEE.
- **Not the KVM port.** `TASK_ADDR_MIN`/`TASK_ADDR_MAX` are set once with no
  `cfg`, so LVBS uses the same allocator, shim and `ldelf`. LVBS has simply
  never loaded a 3+-segment TA.

## Direction for a fix

Make the TA load's kernel-chosen mappings allocate **bottom-up**, so allocation
order and address order agree with what `ldelf` assumes. That matches OP-TEE's
semantics rather than working around them, and does not depend on choosing an
arbitrary slack size.

The cost: `get_unmmaped_area` is core LiteBox shared with LVBS, so this changes
LVBS's address-space layout. Given LVBS is latently broken for the same input,
that is a fix rather than a regression — but it is a deliberate change to
shared behaviour and should be decided as one.

Rejected alternatives: leaving unconditional slack below kernel-chosen
mappings (fixes this case, but the size is unprincipled and a larger rounding
discrepancy would still fail), and exempting the TA's own mappings from the pad
check (diverges from OP-TEE, which would also conflict were the neighbour
adjacent).

## Reproducing

`hello3seg-ta` is the only TA in the tree with three segments. It is
deliberately **not** covered by the KVM test suite: it exists to exercise
syscall trampolines, which only the userland runners use — `get_syscall_entry_point()`
returns 0 on this platform and `UnpatchedBinary` is tolerated — so it tests
nothing relevant here and its failure is unrelated to what it was written for.

```sh
T=litebox_runner_optee_on_linux_userland/tests
./litebox_runner_kvm/scripts/run.sh -l $T/ldelf.elf -a $T/hello3seg-ta.elf -c $T/hello3seg-ta-cmds.json
```
