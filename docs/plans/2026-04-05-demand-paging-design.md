# Demand Paging via Aligned Data Memfd

**Date:** 2026-04-05
**Status:** Approved
**Scope:** mmap-based ELF segment loading during exec (file read path unchanged)

## Problem

During exec, `map_segments` in micro takes ~283us (67% of measured exec time).
It performs 11 memcpy operations totaling ~260KB (24KB binary + 237KB
ld-linux) from tar shmem into anonymous pages. Native Linux does zero copies
— it uses demand paging from the page cache. The memcpy dominates exec
overhead and is the primary reason execl runs at 1,576 lps vs native's
16,687 lps.

## Solution

Replace the anonymous mmap + memcpy pattern with `mmap(MAP_PRIVATE,
aligned_fd, offset)` using `MAP_FIXED` to place ELF segments at their
required virtual addresses. This requires file data to be at page-aligned
offsets within the memfd, so we create a second memfd with page-aligned file
data alongside the existing tar memfd.

**Benefits:**
- **Zero-copy on map**: kernel sets up PTEs, no data movement
- **Demand paging**: pages fault in only when accessed
- **Copy-on-write**: `MAP_PRIVATE` gives private pages on write (BSS,
  relocations, trampolines)

## Architecture Overview

Two memfds coexist:

1. **Tar memfd** (existing) — standard tar format, used by central for
   `TarIndex` and by micro's file-read fast path (`read`/`pread64`/`lseek`).
   Unchanged.

2. **Aligned data memfd** (new, `litebox-aligned-data`) — contains file data
   at page-aligned (4096-byte) offsets. Used by micro for mmap-based ELF
   segment loading during exec.

## Aligned Data Memfd Layout

The launcher creates the aligned data memfd by iterating tar entries in
order and copying each file's data to the next page-aligned position:

```
Offset 0x0000:  [file1 data, padded to file1_size]
                [zero padding to next 4096 boundary]
Offset 0x1000:  [file2 data, padded to file2_size]
                [zero padding to next 4096 boundary]
Offset 0x3000:  [file3 data, ...]
...
```

The algorithm is deterministic: iterate files in tar-entry order, assign
each to `next_offset = (current_offset + 4095) & !4095`. Both launcher and
central can independently reconstruct the `path -> aligned_offset` mapping
from the tar index using this algorithm.

The space between files (zero-fill from `ftruncate`) ensures that partial
pages beyond each file's data contain zeros, which is important for BSS
segments.

## Exec Path Changes

### Micro segment mapping (new flow)

For each tar-backed segment where `tar_data_offset % 4096 == 0`:

1. **mmap**: `mmap(vaddr, map_len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED,
   aligned_fd, tar_data_offset)` — replaces anonymous pages with file-backed
   pages from the aligned memfd. No data copy.
2. **BSS zeroing**: if `data_len < map_len`, explicitly zero the region from
   `data_len` to `map_len`. This triggers COW for BSS pages.
3. **Trampoline patching**: unchanged — writes to trampolines trigger COW,
   creating private pages automatically.
4. **mprotect**: unchanged — set final segment permissions.

For segments where `tar_data_offset % 4096 != 0` (fallback):
- Use existing memcpy path, reading from `aligned_base + tar_data_offset`.

### ExecveSegment wire format

No structural change. The `tar_data_offset` field now points into the
aligned data memfd instead of the tar memfd. The sentinel `u64::MAX` still
means "use ring data region" (non-tar binary).

### Central exec handler changes

- `compute_tar_offset()` uses the aligned offset map instead of tar pointer
  subtraction: `aligned_file_start + segment.file_data_offset`
- `aligned_file_start` comes from the deterministically-reconstructed
  `aligned_file_map: HashMap<String, usize>`

## File Read Path

**Unchanged.** File reads (`read`/`pread64`/`lseek`) continue using
`tar_base` + tar offsets via the existing fast path. The aligned memfd is
only for exec segment mapping.

## Component Changes

### Launcher (`litebox_launcher/src/shmem.rs`)

New struct `AlignedDataRegion`:

```rust
pub struct AlignedDataRegion {
    fd: OwnedFd,
    ptr: NonNull<u8>,
    size: usize,
}
```

Created from tar data by iterating entries and copying file data to
page-aligned positions. Exposes `fd_raw()`, `base_ptr()`, `size()`.

### Launcher (`litebox_launcher/src/main.rs`)

- Create `AlignedDataRegion` from tar data
- Pass aligned fd + size to central: `--aligned-fd=N --aligned-size=N`
- Pass aligned fd + base_ptr + size to micro via `micro_init()`

### Central (`litebox_central/src/main.rs`)

- Parse `--aligned-fd` and `--aligned-size` CLI args
- Reconstruct `aligned_file_map` from tar index using deterministic algorithm
- Store in `ProcessServer`

### Central (`litebox_central/src/server.rs`)

- `compute_tar_offset()` uses `aligned_file_map` to look up the file's
  page-aligned start offset, then adds the segment's `p_offset`
- No need to mmap the aligned memfd — central only needs the offset map

### Micro (`litebox_micro/src/state.rs`)

- Add `aligned_fd: i32`, `aligned_base: *const u8`, `aligned_size: usize`
  to `MicroState`
- Update `micro_init()` signature with new parameters

### Micro (`litebox_micro/src/execve.rs`)

- In segment data loop, for tar-backed segments:
  - If `tar_data_offset % 4096 == 0`: use mmap path
  - Else: use memcpy fallback from `aligned_base + tar_data_offset`
- After mmap: zero BSS region if `data_len < map_len`
- Trampoline and mprotect: unchanged

## Error Handling and Edge Cases

### No tar provided

`aligned_fd = -1`, `aligned_base = null`, `aligned_size = 0`. All segments
use the ring data region path. No behavior change.

### Non-tar binaries

`tar_data_offset == u64::MAX`: existing ring data path. No change.

### Non-page-aligned segments

Fallback to memcpy from `aligned_base`. This handles any ELF with unusual
segment alignment. In practice, standard ELF LOAD segments have page-aligned
`p_offset` for segments with `p_align >= PAGE_SIZE`, so the mmap path should
cover the common case.

### Fork semantics

`aligned_fd`, `aligned_base`, `aligned_size` are inherited by fork child.
`MAP_PRIVATE` file-backed mappings survive fork with COW semantics —
parent and child share read-only pages until either writes.

### Deterministic offset map

Both launcher and central MUST iterate tar entries in the same order and use
the same alignment algorithm. The algorithm is:
```
offset = 0
for each file in tar_entry_order:
    offset = (offset + 4095) & !4095   // page-align
    map[file.path] = offset
    offset += file.size
```

### mmap failure

If the `mmap(MAP_FIXED)` call fails (returns MAP_FAILED), fall back to the
memcpy path. This makes the optimization best-effort.

## Performance Impact

### Expected improvements

- **map_segments**: from ~283us to near-zero for the mmap portion. The
  kernel only sets up PTEs. Actual page faults happen lazily.
- **Per-exec savings**: ~260KB of memcpy eliminated
- **execl benchmark**: potentially 2-5x improvement (from ~1,576 lps toward
  native's 16,687 lps), depending on remaining bottlenecks

### Costs

- **One-time launch cost**: extra memcpy of all file data into aligned memfd
  (~a few MB). Negligible for long-running workloads.
- **Memory overhead**: aligned memfd wastes ~2KB average per file for
  page-alignment padding. Negligible.
- **BSS zeroing**: explicit memset of BSS regions triggers COW. Same as
  native behavior.

## Scope Boundaries

**In scope:** mmap-based ELF segment loading during exec using page-aligned
data memfd.

**Out of scope:** file read path changes, writable shmem, ELF caching,
changes to tar format or tar_no_std parser.
