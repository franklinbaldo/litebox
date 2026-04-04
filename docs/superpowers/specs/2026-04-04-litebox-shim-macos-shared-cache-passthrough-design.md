# Shared Cache Passthrough for macOS Dynamic Linking

**Date:** 2026-04-04
**Status:** Approved
**Supersedes:** Portions of `2026-04-03-litebox-shim-macos-phase2-dynamic-linking-design.md` (specifically the extracted-dylib approach)

## Problem

The Phase 2 dynamic linking implementation originally extracted individual dylibs from the dyld shared cache using `dsc_extractor.bundle`. This approach hit three structural issues:

1. Empty exports tries (rebuilt with ~300-line trie rebuilder)
2. Missing `SG_READ_ONLY` flags on `__DATA_CONST` segments
3. Non-monotonic segment vmaddrs (dyld rejects with "segment '__DATA' vm address out of order")

Each fix revealed a new problem in a different place. The extracted dylibs retain the shared cache's interleaved layout where all dylibs' `__TEXT` segments are packed together, all `__DATA_CONST` together, etc. Individual dylib segments have vmaddrs scattered across the entire cache address space. Fixing this would require a full Mach-O rebaser handling relocations, fixups, bind opcodes, and pointer authentication — hundreds of lines of fragile code.

## Solution: Map Real Shared Cache Data

Instead of extracting and fixing individual dylibs, map the actual shared cache data directly into the guest address space at the original virtual addresses. This is how macOS actually works — dyld expects the cache to be pre-mapped by the kernel.

### Approach: Selective Mapping via .map File

The shared cache on macOS 15 is ~5.5GB virtual across 13 sub-cache files. A simple `hello world` uses ~10 dylibs with ~1MB total `__TEXT`. We parse the `.map` file to identify which dylibs are needed and map only their regions.

## Architecture

### Data Flow

```
Host FS: /System/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e*
                    |
                    v
Test Harness: parse .map file, resolve dependency graph, read selective regions
                    |
                    v
SharedCacheRegions: Vec<{ guest_addr: u64, data: Vec<u8>, prot: Protection }>
                    |
                    v
Shim: install regions into PageManager, patch RX regions for SVC, set shared_region base
                    |
                    v
dyld: shared_region_check_np returns success, finds cache at 0x180000000
```

### Cache File Structure (macOS 15)

The shared cache is split across 13 files:
- `dyld_shared_cache_arm64e` — 573KB header + first RX mapping (0.5MB)
- `.01` — main TEXT region (1621MB RX)
- `.02.dylddata` — DATA_CONST, DATA, AUTH, DATA_DIRTY (224MB mixed)
- `.03.dyldreadonly` — read-only data (121MB R)
- `.04.dyldlinkedit` — LINKEDIT (572MB R)
- `.05` — second TEXT region (1737MB RX)
- `.06-.12` — additional data/linkedit/text for additional cache content

Each sub-cache has a `dyld_v1  arm64e` header with its own `mappingOffset`/`mappingCount` describing where its data maps in virtual memory.

### .map File Format

```
mapping  EX  544KB 0x180000000 -> 0x180088000
mapping  EX 1620MB 0x180088000 -> 0x1E5534000
...

/usr/lib/libSystem.B.dylib
              __TEXT 0x190312000 -> 0x190313CE4
        __DATA_CONST 0x1E605F3A8 -> 0x1E605F3B8
        __AUTH_CONST 0x1EE865F50 -> 0x1EE866230
              __DATA 0x1E9B4C808 -> 0x1E9B4C810
        __DATA_DIRTY 0x1EC3F7980 -> 0x1EC3F7988
          __LINKEDIT 0x1FEC7C000 -> 0x2228D8000
```

### Component 1: Cache Map Parser (test harness)

**Input:** Path to `.map` file
**Output:** Map of dylib install name to list of `(segment_name, vmaddr_start, vmaddr_end)`

Parsing rules:
- Lines starting with `/` are dylib paths
- Indented lines following a dylib path are segment entries: `segment_name vmaddr_start -> vmaddr_end`
- Lines starting with `mapping` are global mapping regions
- The parser also extracts the global mapping list for address-to-subcache-file resolution

### Component 2: Dependency Resolver (test harness)

For a given main binary, determine which dylibs it needs:
- Parse the main binary's `LC_LOAD_DYLIB` commands to find direct dependencies
- For `libSystem.B.dylib`, also include its `LC_REEXPORT_DYLIB` targets (the `/usr/lib/system/*.dylib` sub-dylibs)
- Recursive resolution is not needed for the initial implementation — libSystem.B re-exports everything a typical program needs

For the initial implementation, hard-code the dependency set:
- `/usr/lib/libSystem.B.dylib` (umbrella)
- All dylibs in `/usr/lib/system/` that appear in the .map file

### Component 3: Region Collector (test harness)

Given the needed dylibs and their segment ranges from the .map file:

1. Determine which sub-cache file contains each segment's data by matching the segment's vmaddr against the global mapping entries
2. Compute the file offset within that sub-cache: `file_offset = segment_vmaddr - mapping.vmaddr + mapping.fileOffset`
3. Read the bytes from the sub-cache file
4. Package as `SharedCacheRegion { guest_addr, data, prot }`

**Handling `__LINKEDIT`:** All dylibs share a single large `__LINKEDIT` region. There are three LINKEDIT regions across the sub-caches: 572MB, 586MB, and 238MB (total ~1.4GB). All dylibs in the first cache reference `0x1FEC7C000 -> 0x2228D8000` (572MB). Since libSystem and all its sub-dylibs are in the first cache, we map the first LINKEDIT region (572MB) in full. The other two LINKEDIT regions are mapped only if needed (i.e., if dyld accesses dylibs from sub-caches .05-.12).

LINKEDIT is RO (read-only), so no SVC patching is needed. It's a single large read.

### Component 4: Cache Installation (shim)

New API on `MacosShimBuilder` or `MacosShim`:

```rust
pub fn install_shared_cache_regions(&self, regions: &[SharedCacheRegion]) {
    for region in regions {
        // 1. Allocate pages in PageManager at region.guest_addr
        // 2. Write region.data into those pages
        // 3. If prot includes EXEC, run SVC patcher on the data
        // 4. Set page protection to region.prot
    }
    // Record cache base address for shared_region_check_np
}
```

The SVC patcher is the existing `patch_code_segment` from `litebox_syscall_rewriter_macho`.

### Component 5: Syscall Changes

**`shared_region_check_np`:** Currently returns `Err(Errno::EINVAL)`. Change to:
- If cache is installed: write `0x180000000` (cache base) to the output pointer and return `Ok(0)`
- If not installed: return `Err(Errno::EINVAL)` (current behavior)

**`shared_region_map_and_slide_2_np`:** Currently stubbed. Change to:
- Return `Ok(0)` (no-op — cache is already mapped by the shim)

**File I/O:** dyld may still `open()` dylib paths for header validation. The dylibs are in the shared cache, not in the in-mem FS. Options:
- Return `ENOENT` for cached dylib paths — dyld should fall back to the cache
- OR populate minimal Mach-O headers in in-mem FS (complex, likely unnecessary)

Start with `ENOENT` and see if dyld handles it.

### What Gets Removed

1. `litebox_runner_macos_on_macos_userland/tests/common/trie_rebuilder.rs` — no longer needed
2. `litebox_runner_macos_on_macos_userland/extract_sysroot.sh` — no longer needed
3. `litebox_runner_macos_on_macos_userland/test-sysroot/` — no longer needed (host data, not in git)
4. `populate_inmem_from_sysroot()` in `common/mod.rs` — replaced by cache region loading

### What Stays

All the Phase 2 work that isn't related to dylib extraction:
- All syscall implementations (fd_paths, F_GETPATH, stat64, openat, fstatat64, statfs64, etc.)
- Mach trap implementations (vm_allocate, vm_deallocate, vm_protect, vm_map, port_construct)
- dyld loading (init_for_dyld, KernelArgs, executable_mh)
- mmap-hook/SVC patching infrastructure
- Ignition sequence handling

## Testing

The existing `test_hello_dynamic` test continues to be the primary test. Changes:
1. Test harness reads cache map file from `/System/Cryptexes/OS/System/Library/dyld/`
2. Collects regions for needed dylibs
3. Passes regions to shim before running
4. Validates hello world output as before

## Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| LINKEDIT is too large to map eagerly | Start with first LINKEDIT only (572MB). Add others if needed. Consider lazy mapping later. |
| dyld validates individual dylib files via open/read | Return ENOENT; dyld should use cached version. If not, add minimal headers to in-mem FS. |
| Page-aligned mapping boundaries | Round all regions to page boundaries (4KB). The cache data IS page-aligned in the sub-cache files. |
| SVC patching in cache TEXT | Same existing patcher. Cache TEXT is valid Mach-O code with standard SVC encoding. |
| Host cache version differs from what dyld expects | For now, host macOS version = guest macOS version. Cross-version is future work. |
