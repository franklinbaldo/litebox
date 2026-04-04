# Shared Cache Passthrough — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the broken extracted-dylib approach with direct selective mapping of the real dyld shared cache, enabling dynamically linked macOS binaries to run through litebox.

**Architecture:** The test harness parses the dyld shared cache `.map` file to find address ranges of needed dylibs, reads the corresponding bytes from sub-cache files, and provides them to the shim as pre-built regions. The shim installs these regions into PageManager at the original cache virtual addresses, patches SVC instructions in executable regions, and responds to `shared_region_check_np` with success.

**Tech Stack:** Rust (edition 2024), aarch64, macOS dyld shared cache format.

**Prerequisites:** All existing Phase 2 work (Tasks 1-7 + Task 8 syscall/mach-trap additions) is committed and working. This plan replaces the dylib-loading portion of Task 8.

---

### Task 1: Add cache map parser to test harness

Parse the `.map` file from `/System/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e.map` to extract per-dylib segment address ranges and the global mapping regions.

**Files:**
- Create: `litebox_runner_macos_on_macos_userland/tests/common/shared_cache.rs`
- Modify: `litebox_runner_macos_on_macos_userland/tests/common/mod.rs` (add `mod shared_cache;`)

- [ ] **Step 1: Create the shared_cache module with types**

Create `litebox_runner_macos_on_macos_userland/tests/common/shared_cache.rs`:

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Parses the dyld shared cache `.map` file and reads selective regions
//! from sub-cache files for installation into the litebox guest.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// A global mapping region from the cache map header.
/// Example: `mapping  EX 1620MB 0x180088000 -> 0x1E5534000`
#[derive(Debug, Clone)]
pub struct CacheMapping {
    pub vm_start: u64,
    pub vm_end: u64,
    pub prot: Protection,
}

/// Protection flags for a cache region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    ReadExecute,
    ReadWrite,
    ReadOnly,
}

/// A single segment of a dylib as listed in the .map file.
#[derive(Debug, Clone)]
pub struct DylibSegment {
    pub name: String,
    pub vm_start: u64,
    pub vm_end: u64,
}

/// All segments for a single dylib.
#[derive(Debug, Clone)]
pub struct DylibEntry {
    pub path: String,
    pub segments: Vec<DylibSegment>,
}

/// A region of shared cache data ready for installation into the guest.
#[derive(Debug)]
pub struct SharedCacheRegion {
    pub guest_addr: u64,
    pub data: Vec<u8>,
    pub prot: Protection,
}

/// Parsed contents of a `.map` file.
#[derive(Debug)]
pub struct CacheMap {
    pub mappings: Vec<CacheMapping>,
    pub dylibs: BTreeMap<String, DylibEntry>,
}
```

- [ ] **Step 2: Implement the map file parser**

Add to `shared_cache.rs`:

```rust
impl CacheMap {
    /// Parse a dyld shared cache `.map` file.
    pub fn parse(map_text: &str) -> CacheMap {
        let mut mappings = Vec::new();
        let mut dylibs = BTreeMap::new();
        let mut current_dylib: Option<String> = None;
        let mut current_segments: Vec<DylibSegment> = Vec::new();

        for line in map_text.lines() {
            if line.starts_with("mapping") {
                // Example: "mapping  EX 1620MB 0x180088000 -> 0x1E5534000"
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    let prot = match parts[1] {
                        "EX" => Protection::ReadExecute,
                        "RW" => Protection::ReadWrite,
                        "RO" | "R" => Protection::ReadOnly,
                        _ => Protection::ReadOnly,
                    };
                    if let (Some(start), Some(end)) = (
                        parse_hex(parts[3]),
                        parse_hex(parts[parts.len() - 1]),
                    ) {
                        mappings.push(CacheMapping {
                            vm_start: start,
                            vm_end: end,
                            prot,
                        });
                    }
                }
            } else if line.starts_with('/') {
                // New dylib path — flush previous
                if let Some(path) = current_dylib.take() {
                    let segments = std::mem::take(&mut current_segments);
                    dylibs.insert(
                        path.clone(),
                        DylibEntry { path, segments },
                    );
                }
                current_dylib = Some(line.trim().to_string());
            } else if line.starts_with('\t') || line.starts_with("    ") {
                // Segment line: "          __TEXT 0x190312000 -> 0x190313CE4"
                let trimmed = line.trim();
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 4 && parts[2] == "->" {
                    if let (Some(start), Some(end)) =
                        (parse_hex(parts[1]), parse_hex(parts[3]))
                    {
                        current_segments.push(DylibSegment {
                            name: parts[0].to_string(),
                            vm_start: start,
                            vm_end: end,
                        });
                    }
                }
            }
        }
        // Flush last dylib
        if let Some(path) = current_dylib.take() {
            let segments = std::mem::take(&mut current_segments);
            dylibs.insert(path.clone(), DylibEntry { path, segments });
        }

        CacheMap { mappings, dylibs }
    }
}

fn parse_hex(s: &str) -> Option<u64> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(s, 16).ok()
}
```

- [ ] **Step 3: Add unit test for map parser**

Add to bottom of `shared_cache.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_map_snippet() {
        let map_text = "\
mapping  EX  544KB 0x180000000 -> 0x180088000
mapping  EX 1620MB 0x180088000 -> 0x1E5534000
mapping  RW   35MB 0x1E5538000 -> 0x1E7858000

/usr/lib/libSystem.B.dylib
\t          __TEXT 0x190312000 -> 0x190313CE4
\t    __DATA_CONST 0x1E605F3A8 -> 0x1E605F3B8
\t      __LINKEDIT 0x1FEC7C000 -> 0x2228D8000

/usr/lib/system/libsystem_c.dylib
\t          __TEXT 0x18037E000 -> 0x1803FEEF8
\t    __DATA_CONST 0x1E55C7A10 -> 0x1E55C9280
";
        let cache_map = CacheMap::parse(map_text);

        assert_eq!(cache_map.mappings.len(), 3);
        assert_eq!(cache_map.mappings[0].vm_start, 0x180000000);
        assert_eq!(cache_map.mappings[0].vm_end, 0x180088000);
        assert!(matches!(cache_map.mappings[0].prot, Protection::ReadExecute));
        assert!(matches!(cache_map.mappings[2].prot, Protection::ReadWrite));

        assert_eq!(cache_map.dylibs.len(), 2);
        let lib_sys = &cache_map.dylibs["/usr/lib/libSystem.B.dylib"];
        assert_eq!(lib_sys.segments.len(), 3);
        assert_eq!(lib_sys.segments[0].name, "__TEXT");
        assert_eq!(lib_sys.segments[0].vm_start, 0x190312000);

        let lib_c = &cache_map.dylibs["/usr/lib/system/libsystem_c.dylib"];
        assert_eq!(lib_c.segments.len(), 2);
    }
}
```

- [ ] **Step 4: Run the unit test**

Run: `cargo test -p litebox_runner_macos_on_macos_userland test_parse_map_snippet -- --nocapture`
Expected: PASS

- [ ] **Step 5: Wire up the module**

In `litebox_runner_macos_on_macos_userland/tests/common/mod.rs`, add after the existing `mod trie_rebuilder;` line:

```rust
pub mod shared_cache;
```

- [ ] **Step 6: Commit**

```bash
git add litebox_runner_macos_on_macos_userland/tests/common/shared_cache.rs \
       litebox_runner_macos_on_macos_userland/tests/common/mod.rs
git commit -m "Add shared cache map file parser for selective region loading"
```

---

### Task 2: Add sub-cache region reader

Read the sub-cache file headers to build a vmaddr-to-file mapping, then use that to read selective bytes for needed dylib segments.

**Files:**
- Modify: `litebox_runner_macos_on_macos_userland/tests/common/shared_cache.rs`

- [ ] **Step 1: Add sub-cache header parser**

Add to `shared_cache.rs`:

```rust
/// A mapping region within a sub-cache file.
#[derive(Debug, Clone)]
struct SubCacheFileMapping {
    pub vm_addr: u64,
    pub vm_size: u64,
    pub file_offset: u64,
    pub init_prot: u32,
}

/// A parsed sub-cache file with its mappings.
#[derive(Debug)]
struct SubCacheFile {
    pub path: PathBuf,
    pub mappings: Vec<SubCacheFileMapping>,
}

impl SubCacheFile {
    /// Parse the header of a sub-cache file to extract its mapping table.
    fn parse(path: &Path) -> Option<SubCacheFile> {
        let data = std::fs::read(path).ok()?;
        if data.len() < 24 {
            return None;
        }
        // Magic: "dyld_v1  arm64e\0" (16 bytes)
        let magic = std::str::from_utf8(&data[..15]).ok()?;
        if !magic.starts_with("dyld_v1") {
            return None;
        }
        let mapping_offset = u32::from_le_bytes(data[16..20].try_into().ok()?) as usize;
        let mapping_count = u32::from_le_bytes(data[20..24].try_into().ok()?) as usize;

        let mut mappings = Vec::new();
        for i in 0..mapping_count {
            let off = mapping_offset + i * 32;
            if off + 32 > data.len() {
                break;
            }
            let vm_addr = u64::from_le_bytes(data[off..off + 8].try_into().ok()?);
            let vm_size = u64::from_le_bytes(data[off + 8..off + 16].try_into().ok()?);
            let file_offset = u64::from_le_bytes(data[off + 16..off + 24].try_into().ok()?);
            let _max_prot = u32::from_le_bytes(data[off + 24..off + 28].try_into().ok()?);
            let init_prot = u32::from_le_bytes(data[off + 28..off + 32].try_into().ok()?);
            mappings.push(SubCacheFileMapping {
                vm_addr,
                vm_size,
                file_offset,
                init_prot,
            });
        }

        Some(SubCacheFile {
            path: path.to_path_buf(),
            mappings,
        })
    }

    /// Check if this sub-cache contains data at the given vm address.
    fn contains_vmaddr(&self, addr: u64) -> bool {
        self.mappings
            .iter()
            .any(|m| addr >= m.vm_addr && addr < m.vm_addr + m.vm_size)
    }

    /// Read bytes from this sub-cache for a given vm address range.
    fn read_region(&self, vm_start: u64, vm_end: u64) -> Option<Vec<u8>> {
        use std::io::{Read, Seek, SeekFrom};

        for m in &self.mappings {
            let m_end = m.vm_addr + m.vm_size;
            if vm_start >= m.vm_addr && vm_start < m_end {
                let offset_in_mapping = vm_start - m.vm_addr;
                let file_pos = m.file_offset + offset_in_mapping;
                // Clamp read length to the mapping boundary
                let avail = m_end.saturating_sub(vm_start);
                let want = vm_end.saturating_sub(vm_start);
                let read_len = want.min(avail) as usize;

                let mut file = std::fs::File::open(&self.path).ok()?;
                file.seek(SeekFrom::Start(file_pos)).ok()?;
                let mut buf = vec![0u8; read_len];
                file.read_exact(&mut buf).ok()?;
                return Some(buf);
            }
        }
        None
    }
}
```

- [ ] **Step 2: Add the top-level region collector**

Add to `shared_cache.rs`:

```rust
/// Discover all sub-cache files in the cache directory.
fn discover_subcache_files(cache_dir: &Path) -> Vec<SubCacheFile> {
    let base = cache_dir.join("dyld_shared_cache_arm64e");
    let mut files = Vec::new();

    // Main header file
    if let Some(sc) = SubCacheFile::parse(&base) {
        files.push(sc);
    }

    // Numbered sub-caches: .01, .02.dylddata, .03.dyldreadonly, etc.
    for entry in std::fs::read_dir(cache_dir).into_iter().flatten() {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with("dyld_shared_cache_arm64e.")
            && !name_str.ends_with(".map")
            && !name_str.ends_with(".atlas")
        {
            if let Some(sc) = SubCacheFile::parse(&entry.path()) {
                files.push(sc);
            }
        }
    }

    files
}

/// Determine the protection of a segment based on its name and the global
/// mapping regions.
fn segment_protection(seg_name: &str, vm_start: u64, mappings: &[CacheMapping]) -> Protection {
    // First check if the segment name implies a specific protection
    match seg_name {
        "__TEXT" => return Protection::ReadExecute,
        "__DATA" | "__DATA_DIRTY" | "__AUTH" => return Protection::ReadWrite,
        "__DATA_CONST" | "__AUTH_CONST" | "__TPRO_CONST" => return Protection::ReadOnly,
        "__LINKEDIT" => return Protection::ReadOnly,
        _ => {}
    }
    // Fall back to the global mapping protection
    for m in mappings {
        if vm_start >= m.vm_start && vm_start < m.vm_end {
            return m.prot;
        }
    }
    Protection::ReadOnly
}

/// Collect shared cache regions for a set of dylib paths.
///
/// `cache_dir` should be `/System/Cryptexes/OS/System/Library/dyld/`.
/// `needed_dylibs` is a list of install names like `/usr/lib/libSystem.B.dylib`.
///
/// Returns regions ready for installation into the guest, plus the LINKEDIT
/// region (mapped separately since all dylibs share it).
pub fn collect_regions(
    cache_dir: &Path,
    needed_dylibs: &[&str],
) -> Vec<SharedCacheRegion> {
    let map_path = cache_dir.join("dyld_shared_cache_arm64e.map");
    let map_text = std::fs::read_to_string(&map_path)
        .unwrap_or_else(|e| panic!("Failed to read cache map at {}: {}", map_path.display(), e));
    let cache_map = CacheMap::parse(&map_text);
    let subcaches = discover_subcache_files(cache_dir);

    let mut regions: Vec<SharedCacheRegion> = Vec::new();
    let mut seen_ranges: std::collections::HashSet<(u64, u64)> = std::collections::HashSet::new();

    for &dylib_path in needed_dylibs {
        let entry = match cache_map.dylibs.get(dylib_path) {
            Some(e) => e,
            None => {
                eprintln!("Warning: dylib not found in cache map: {}", dylib_path);
                continue;
            }
        };

        for seg in &entry.segments {
            // Skip __LINKEDIT — handled separately below
            if seg.name == "__LINKEDIT" {
                continue;
            }

            let range_key = (seg.vm_start, seg.vm_end);
            if !seen_ranges.insert(range_key) {
                continue; // Already collected this range
            }

            let prot = segment_protection(&seg.name, seg.vm_start, &cache_map.mappings);

            // Find the sub-cache containing this address
            let data = subcaches
                .iter()
                .find_map(|sc| sc.read_region(seg.vm_start, seg.vm_end));

            match data {
                Some(data) => {
                    regions.push(SharedCacheRegion {
                        guest_addr: seg.vm_start,
                        data,
                        prot,
                    });
                }
                None => {
                    eprintln!(
                        "Warning: could not find cache data for {} {} at 0x{:x}-0x{:x}",
                        dylib_path, seg.name, seg.vm_start, seg.vm_end
                    );
                }
            }
        }
    }

    // Collect the shared LINKEDIT region(s).
    // All dylibs in the first cache reference __LINKEDIT at 0x1FEC7C000.
    // Find the unique LINKEDIT ranges across all needed dylibs.
    let mut linkedit_ranges: std::collections::HashSet<(u64, u64)> = std::collections::HashSet::new();
    for &dylib_path in needed_dylibs {
        if let Some(entry) = cache_map.dylibs.get(dylib_path) {
            for seg in &entry.segments {
                if seg.name == "__LINKEDIT" {
                    linkedit_ranges.insert((seg.vm_start, seg.vm_end));
                }
            }
        }
    }

    for (le_start, le_end) in &linkedit_ranges {
        if !seen_ranges.insert((*le_start, *le_end)) {
            continue;
        }
        let data = subcaches
            .iter()
            .find_map(|sc| sc.read_region(*le_start, *le_end));

        match data {
            Some(data) => {
                eprintln!(
                    "Loaded LINKEDIT region: 0x{:x}-0x{:x} ({:.1} MB)",
                    le_start,
                    le_end,
                    data.len() as f64 / (1024.0 * 1024.0)
                );
                regions.push(SharedCacheRegion {
                    guest_addr: *le_start,
                    data,
                    prot: Protection::ReadOnly,
                });
            }
            None => {
                eprintln!(
                    "Warning: could not find LINKEDIT data at 0x{:x}-0x{:x}",
                    le_start, le_end
                );
            }
        }
    }

    regions
}
```

- [ ] **Step 3: Add a helper to list needed dylibs from the map file**

Add to `shared_cache.rs`:

```rust
impl CacheMap {
    /// Return the install names of all `/usr/lib/system/*.dylib` entries,
    /// plus `/usr/lib/libSystem.B.dylib` itself.
    pub fn system_dylib_paths(&self) -> Vec<String> {
        let mut paths: Vec<String> = self
            .dylibs
            .keys()
            .filter(|p| {
                *p == "/usr/lib/libSystem.B.dylib"
                    || p.starts_with("/usr/lib/system/")
            })
            .cloned()
            .collect();
        paths.sort();
        paths
    }
}
```

- [ ] **Step 4: Add integration test that reads the real cache**

Add to the `tests` module in `shared_cache.rs`:

```rust
    #[test]
    #[ignore = "requires access to /System/Cryptexes/OS/System/Library/dyld/"]
    fn test_read_real_cache_regions() {
        let cache_dir = Path::new("/System/Cryptexes/OS/System/Library/dyld");
        if !cache_dir.exists() {
            eprintln!("Skipping: cache dir not found");
            return;
        }

        let map_path = cache_dir.join("dyld_shared_cache_arm64e.map");
        let map_text = std::fs::read_to_string(&map_path).unwrap();
        let cache_map = CacheMap::parse(&map_text);

        let system_dylibs = cache_map.system_dylib_paths();
        eprintln!("Found {} system dylibs in cache map", system_dylibs.len());
        assert!(system_dylibs.contains(&"/usr/lib/libSystem.B.dylib".to_string()));

        let dylib_refs: Vec<&str> = system_dylibs.iter().map(|s| s.as_str()).collect();
        let regions = collect_regions(cache_dir, &dylib_refs);

        eprintln!("Collected {} regions", regions.len());
        assert!(!regions.is_empty());

        let total_rx: usize = regions
            .iter()
            .filter(|r| matches!(r.prot, Protection::ReadExecute))
            .map(|r| r.data.len())
            .sum();
        let total_ro: usize = regions
            .iter()
            .filter(|r| matches!(r.prot, Protection::ReadOnly))
            .map(|r| r.data.len())
            .sum();
        let total_rw: usize = regions
            .iter()
            .filter(|r| matches!(r.prot, Protection::ReadWrite))
            .map(|r| r.data.len())
            .sum();

        eprintln!(
            "RX: {:.1} MB, RO: {:.1} MB, RW: {:.1} MB",
            total_rx as f64 / (1024.0 * 1024.0),
            total_ro as f64 / (1024.0 * 1024.0),
            total_rw as f64 / (1024.0 * 1024.0),
        );

        // Sanity: the RX regions for system dylibs should be small (< 10MB),
        // not the full 3.5GB cache TEXT
        assert!(total_rx < 20 * 1024 * 1024, "RX too large: {}", total_rx);
    }
```

- [ ] **Step 5: Run the integration test**

Run: `cargo test -p litebox_runner_macos_on_macos_userland test_read_real_cache_regions -- --ignored --nocapture`
Expected: PASS, with output showing the number of regions and size breakdown

- [ ] **Step 6: Commit**

```bash
git add litebox_runner_macos_on_macos_userland/tests/common/shared_cache.rs
git commit -m "Add sub-cache region reader for selective dylib loading

Discovers sub-cache files, parses their headers to build vm-to-file
mappings, and reads selective byte ranges for needed dylib segments."
```

---

### Task 3: Add shared cache installation API to the shim

Add a method to install pre-read cache regions into the guest's PageManager. This allocates pages at the correct guest addresses, writes data, patches SVC instructions in RX regions, and records the cache base address.

**Files:**
- Modify: `litebox_shim_macos/src/lib.rs` (add `shared_cache_base` to GlobalState, add install method)
- Modify: `litebox_shim_macos/src/syscalls/mm.rs` (extract SVC patching into a reusable helper)

- [ ] **Step 1: Add `shared_cache_base` field to GlobalState**

In `litebox_shim_macos/src/lib.rs`, add to the `GlobalState` struct (around line 396, before `sysroot`):

```rust
    /// Base address of the installed shared cache (0x180000000 if installed).
    pub(crate) shared_cache_base: Option<u64>,
```

Update the `GlobalState` construction in `MacosShimBuilder::build()` (around line 155) to initialize it:

```rust
            shared_cache_base: None,
```

- [ ] **Step 2: Add region installation method to MacosShim**

In `litebox_shim_macos/src/lib.rs`, add a new method to `impl<FS: ...> MacosShim<FS>` (after `load_program`):

```rust
    /// Install shared cache regions into the guest address space.
    ///
    /// Each region is mapped at `guest_addr` with the given data and protection.
    /// RX (executable) regions are patched for SVC rewriting before being made
    /// executable. The cache base address is recorded for `shared_region_check_np`.
    ///
    /// `cache_base` is typically `0x180000000`.
    pub fn install_shared_cache(
        &self,
        cache_base: u64,
        regions: &[(u64, &[u8], bool)], // (guest_addr, data, is_executable)
    ) {
        use litebox::mm::linux::{MmapFlags, MmapProt};
        use litebox_common_linux::mm::do_mmap;

        let global = &self.0;
        let page_size = PAGE_SIZE;

        for &(guest_addr, data, is_exec) in regions {
            if data.is_empty() {
                continue;
            }

            // Page-align the start address down and compute the aligned length
            let aligned_start = guest_addr & !(page_size as u64 - 1);
            let end = guest_addr + data.len() as u64;
            let aligned_end = (end + page_size as u64 - 1) & !(page_size as u64 - 1);
            let aligned_len = (aligned_end - aligned_start) as usize;

            // Allocate RW pages at the target address
            let flags = MmapFlags::MAP_PRIVATE
                | MmapFlags::MAP_ANONYMOUS
                | MmapFlags::MAP_FIXED;
            let result = do_mmap(
                &global.pm,
                aligned_start as usize,
                aligned_len,
                MmapProt::PROT_READ | MmapProt::PROT_WRITE,
                flags,
                None,
            );

            let mapped_addr = match result {
                Ok(addr) => addr,
                Err(e) => {
                    log::error!(
                        "Failed to map cache region at 0x{:x} (len 0x{:x}): {:?}",
                        aligned_start, aligned_len, e
                    );
                    continue;
                }
            };

            // Write data into the mapping at the correct offset
            let offset_in_page = (guest_addr - aligned_start) as usize;
            let dest = (mapped_addr + offset_in_page) as *mut u8;
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr(), dest, data.len());
            }

            if is_exec {
                // Patch SVC sites in the code before making it executable.
                // We use a single large trampoline allocation for the entire cache.
                let code_slice = unsafe {
                    core::slice::from_raw_parts_mut(dest, data.len())
                };

                // Allocate a trampoline region for this chunk (16KB per 1MB of code)
                let trampoline_pages = ((data.len() / (1024 * 1024)) + 1) * 4;
                let trampoline_size = trampoline_pages * page_size;
                let tramp_result = do_mmap(
                    &global.pm,
                    0,
                    trampoline_size,
                    MmapProt::PROT_READ | MmapProt::PROT_WRITE,
                    MmapFlags::MAP_PRIVATE | MmapFlags::MAP_ANONYMOUS,
                    None,
                );

                if let Ok(tramp_addr) = tramp_result {
                    let tramp_slice = unsafe {
                        core::slice::from_raw_parts_mut(
                            tramp_addr as *mut u8,
                            trampoline_size,
                        )
                    };

                    let mut tramp_cursor = 0usize;
                    litebox_syscall_rewriter_macho::patch_code_segment(
                        code_slice,
                        guest_addr as usize,
                        tramp_slice,
                        tramp_addr,
                        &mut tramp_cursor,
                    );

                    // Make trampoline R-X
                    let _ = litebox_common_linux::mm::do_mprotect(
                        &global.pm,
                        tramp_addr,
                        trampoline_size,
                        MmapProt::PROT_READ | MmapProt::PROT_EXEC,
                    );
                } else {
                    log::error!(
                        "Failed to allocate trampoline for cache region at 0x{:x}",
                        guest_addr,
                    );
                }

                // Make code R-X
                let _ = litebox_common_linux::mm::do_mprotect(
                    &global.pm,
                    mapped_addr,
                    aligned_len,
                    MmapProt::PROT_READ | MmapProt::PROT_EXEC,
                );
            }
        }

        // Record the cache base
        // Safety: this is called before any guest code runs
        let global_mut = unsafe {
            &mut *(core::ptr::from_ref(global) as *mut GlobalState<FS>)
        };
        global_mut.shared_cache_base = Some(cache_base);

        log::info!(
            "Installed {} shared cache regions, base=0x{:x}",
            regions.len(),
            cache_base,
        );
    }
```

**Important:** The above uses `patch_code_segment` from `litebox_syscall_rewriter_macho`. Verify this function's signature matches what's already used in `sys_mmap_exec_hook` in `mm.rs`. The existing code at `mm.rs:253-276` calls it with `(code_buf, base_addr, trampoline_slice, trampoline_base, &mut cursor)`.

- [ ] **Step 3: Verify it compiles**

Run: `cargo check -p litebox_shim_macos`
Expected: Compiles (possibly with unused warnings for `shared_cache_base` — that's fine, we'll use it in Task 4)

- [ ] **Step 4: Commit**

```bash
git add litebox_shim_macos/src/lib.rs
git commit -m "Add install_shared_cache API for mapping cache regions into guest

Allocates pages at correct guest addresses, writes cache data, patches
SVC instructions in executable regions, and records the cache base
address for shared_region_check_np."
```

---

### Task 4: Update shared_region_check_np to return success when cache is installed

Change `sys_shared_region_check_np` from always returning `EINVAL` to returning the cache base address when the shared cache has been installed.

**Files:**
- Modify: `litebox_shim_macos/src/syscalls/stubs.rs`

- [ ] **Step 1: Update sys_shared_region_check_np**

In `litebox_shim_macos/src/syscalls/stubs.rs`, replace the `sys_shared_region_check_np` function (lines 59-61):

Old:
```rust
    pub(crate) fn sys_shared_region_check_np(&self, _start_address: usize) -> Result<usize, Errno> {
        Err(Errno::EINVAL)
    }
```

New:
```rust
    pub(crate) fn sys_shared_region_check_np(&self, start_address: usize) -> Result<usize, Errno> {
        match self.global.shared_cache_base {
            Some(base) => {
                // Write the cache base address to the user-provided pointer
                let ptr = start_address as *mut u64;
                unsafe { core::ptr::write(ptr, base) };
                log::debug!(
                    "shared_region_check_np: cache installed at 0x{:x}",
                    base
                );
                Ok(0)
            }
            None => {
                log::debug!("shared_region_check_np: no cache installed, returning EINVAL");
                Err(Errno::EINVAL)
            }
        }
    }
```

- [ ] **Step 2: Also update shared_region_map_and_slide_2_np dispatch**

In `litebox_shim_macos/src/syscalls/mod.rs`, find the dispatch arm for `SharedRegionMapAndSlide2Np` and ensure it returns `Ok(0)` (no-op since cache is pre-mapped). It may currently return `Err(Errno::ENOSYS)` or similar. Change it to:

```rust
MacosSyscallRequest::SharedRegionMapAndSlide2Np { .. } => {
    log::debug!("shared_region_map_and_slide_2_np: no-op (cache pre-mapped)");
    Ok(0)
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check -p litebox_shim_macos`
Expected: Compiles

- [ ] **Step 4: Commit**

```bash
git add litebox_shim_macos/src/syscalls/stubs.rs litebox_shim_macos/src/syscalls/mod.rs
git commit -m "Return success from shared_region_check_np when cache is installed

When the shared cache has been pre-mapped via install_shared_cache(),
shared_region_check_np now writes the base address (0x180000000) to
the caller's pointer and returns success. shared_region_map_and_slide_2_np
returns success as a no-op."
```

---

### Task 5: Update test harness to use shared cache passthrough

Replace the `populate_inmem_from_sysroot` approach with the new shared cache region loading. Update `run_macho_dynamic` and `test_hello_dynamic`.

**Files:**
- Modify: `litebox_runner_macos_on_macos_userland/tests/common/mod.rs`
- Modify: `litebox_runner_macos_on_macos_userland/tests/loader.rs`

- [ ] **Step 1: Update run_macho_dynamic to accept and install cache regions**

In `litebox_runner_macos_on_macos_userland/tests/common/mod.rs`, modify `run_macho_dynamic` to:
1. Accept cache regions instead of a sysroot path
2. Call `shim.install_shared_cache()` instead of `populate_inmem_from_sysroot()`

Replace the entire `run_macho_dynamic` function with:

```rust
pub fn run_macho_dynamic(
    binary_data: &[u8],
    argv: &[&str],
    cache_regions: &[shared_cache::SharedCacheRegion],
) -> (i32, Vec<u8>) {
    let _lock = TEST_LOCK.lock().unwrap();
    let platform = ensure_platform();
    litebox_shim_macos::reset_tls_table();

    let mut builder = litebox_shim_macos::MacosShimBuilder::<
        litebox_shim_macos::DefaultFS,
    >::new();

    // Build in-mem FS with main binary
    let in_mem_fs = {
        let in_mem_fs =
            litebox::fs::in_mem::FileSystem::new(platform);
        let mode = litebox::fs::Mode::from_bits(0o755);
        in_mem_fs.with_root_privileges(|fs| {
            fs.mkdir(
                "/tmp",
                mode,
            )
            .unwrap();
            fs.mkdir(
                "/usr",
                mode,
            )
            .unwrap();
            fs.mkdir(
                "/usr/bin",
                mode,
            )
            .unwrap();
            fs.mkdir(
                "/usr/lib",
                mode,
            )
            .unwrap();

            // Write the main binary into the in-mem FS
            let fd = fs
                .open(
                    "/usr/bin/hello_dynamic",
                    litebox::fs::OFlags::from_bits(
                        0o100 | 0o1, // O_CREAT | O_WRONLY (Linux values)
                    ),
                    mode,
                )
                .unwrap();
            fs.write(&fd, binary_data, None).unwrap();
            fs.close(&fd);
        });
        in_mem_fs
    };

    let tar_ro_fs = litebox::fs::tar_ro::FileSystem::empty(platform);
    let default_fs = builder.default_fs(in_mem_fs, tar_ro_fs);
    builder.set_fs(default_fs);

    let shim = builder.build();

    // Install shared cache regions
    let regions_for_shim: Vec<(u64, &[u8], bool)> = cache_regions
        .iter()
        .map(|r| {
            let is_exec = matches!(r.prot, shared_cache::Protection::ReadExecute);
            (r.guest_addr, r.data.as_slice(), is_exec)
        })
        .collect();
    shim.install_shared_cache(0x180000000, &regions_for_shim);

    // Initialize stdio
    shim.initialize_stdio();

    // Load dyld from the host
    let dyld_path = "/usr/lib/dyld";
    let dyld_bytes = std::fs::read(dyld_path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", dyld_path, e));

    let argv_cstrings: Vec<_> = argv
        .iter()
        .map(|s| alloc::ffi::CString::new(*s).unwrap())
        .collect();
    let envp_cstrings: Vec<alloc::ffi::CString> = Vec::new();

    let loaded = shim
        .load_program(
            binary_data,
            argv_cstrings,
            envp_cstrings,
            Some(&dyld_bytes),
        )
        .unwrap();

    let output = shim.run_thread(loaded);
    let exit_code = output.exit_code.load(core::sync::atomic::Ordering::SeqCst);
    (exit_code, Vec::new())
}
```

- [ ] **Step 2: Update test_hello_dynamic in loader.rs**

In `litebox_runner_macos_on_macos_userland/tests/loader.rs`, replace the `test_hello_dynamic` function:

```rust
#[test]
#[ignore = "requires access to /System/Cryptexes/OS/System/Library/dyld/"]
fn test_hello_dynamic() {
    let cache_dir =
        std::path::Path::new("/System/Cryptexes/OS/System/Library/dyld");
    if !cache_dir.exists() {
        panic!(
            "Shared cache not found at {}. This test requires macOS with dyld shared cache.",
            cache_dir.display()
        );
    }

    // Parse cache map and collect regions for system dylibs
    let map_path = cache_dir.join("dyld_shared_cache_arm64e.map");
    let map_text = std::fs::read_to_string(&map_path).unwrap();
    let cache_map = common::shared_cache::CacheMap::parse(&map_text);
    let system_dylibs = cache_map.system_dylib_paths();
    let dylib_refs: Vec<&str> = system_dylibs.iter().map(|s| s.as_str()).collect();
    let cache_regions = common::shared_cache::collect_regions(cache_dir, &dylib_refs);

    eprintln!(
        "Loaded {} cache regions ({:.1} MB total)",
        cache_regions.len(),
        cache_regions.iter().map(|r| r.data.len()).sum::<usize>() as f64 / (1024.0 * 1024.0),
    );

    let binary = common::compile_macho_dynamic(HELLO_DYNAMIC_C);
    // Don't rewrite the main binary — it has no SVC instructions
    let (exit_code, _) = common::run_macho_dynamic(
        &binary,
        &["/usr/bin/hello_dynamic", "arg1", "arg2"],
        &cache_regions,
    );
    assert_eq!(exit_code, 0, "Dynamic hello world should exit with code 0");
}
```

- [ ] **Step 3: Remove populate_inmem_from_sysroot and trie_rebuilder references**

In `litebox_runner_macos_on_macos_userland/tests/common/mod.rs`:
1. Remove the `mod trie_rebuilder;` line
2. Remove the entire `populate_inmem_from_sysroot` function
3. Remove unused `use` statements that were only needed by that function

- [ ] **Step 4: Verify it compiles**

Run: `cargo check -p litebox_runner_macos_on_macos_userland --tests`
Expected: Compiles (may have warnings for unused trie_rebuilder.rs file — that's expected)

- [ ] **Step 5: Run the test**

Run: `cargo test -p litebox_runner_macos_on_macos_userland test_hello_dynamic -- --ignored --nocapture`
Expected: May not pass yet (we may need additional syscall fixes), but it should at least get past the "segment vm address out of order" error

- [ ] **Step 6: Commit**

```bash
git add litebox_runner_macos_on_macos_userland/tests/common/mod.rs \
       litebox_runner_macos_on_macos_userland/tests/loader.rs
git commit -m "Switch test harness from extracted dylibs to shared cache passthrough

Replace populate_inmem_from_sysroot with shared cache region loading.
The test now reads selective regions from the real dyld shared cache
and installs them into the guest address space at the correct virtual
addresses."
```

---

### Task 6: Remove extracted-dylib infrastructure

Clean up files that are no longer needed.

**Files:**
- Delete: `litebox_runner_macos_on_macos_userland/tests/common/trie_rebuilder.rs`
- Delete: `litebox_runner_macos_on_macos_userland/extract_sysroot.sh`

- [ ] **Step 1: Delete trie_rebuilder.rs**

```bash
rm litebox_runner_macos_on_macos_userland/tests/common/trie_rebuilder.rs
```

- [ ] **Step 2: Delete extract_sysroot.sh**

```bash
rm litebox_runner_macos_on_macos_userland/extract_sysroot.sh
```

- [ ] **Step 3: Verify compilation still works**

Run: `cargo check -p litebox_runner_macos_on_macos_userland --tests`
Expected: Compiles cleanly

- [ ] **Step 4: Commit**

```bash
git add -u
git commit -m "Remove extracted-dylib infrastructure (trie rebuilder, extract script)

These files are no longer needed now that we load dylibs from the real
shared cache instead of extracting and patching individual dylibs."
```

---

### Task 7: Debug and iterate on dynamic linking test

Run the integration test and fix any new issues that arise from the shared cache passthrough approach. This task is iterative — run the test, read the error output, fix the issue, repeat.

**Files:**
- Modify: Various files in `litebox_shim_macos/src/syscalls/` as needed
- Modify: `litebox_runner_macos_on_macos_userland/tests/common/shared_cache.rs` as needed

- [ ] **Step 1: Run the test and capture output**

Run: `cargo test -p litebox_runner_macos_on_macos_userland test_hello_dynamic -- --ignored --nocapture 2>&1`
Expected: Some progress past the previous "segment vm address out of order" error. Capture the full output for analysis.

- [ ] **Step 2: Analyze failures and fix iteratively**

Common issues to expect:
1. **shared_region_check_np pointer write** — dyld may expect the base address at a specific location; verify the pointer write is correct
2. **Missing syscalls** — dyld may call new syscalls we haven't seen before when using the shared cache path instead of the fallback path
3. **mprotect on cache regions** — dyld may try to change permissions on cache regions
4. **Trampoline sizing** — large RX regions may need larger trampoline allocations

For each failure:
- Read the error/panic message
- Identify the syscall or operation that failed
- Implement the minimal fix
- Re-run the test
- Commit when a meaningful fix is made

- [ ] **Step 3: Commit fixes as they're made**

Each significant fix should be committed with a descriptive message explaining what was wrong and how it was fixed.

---

### Task 8: Final verification and cleanup

Ensure all tests pass, code compiles cleanly, and there are no dead code warnings.

**Files:**
- Modify: Various files for cleanup

- [ ] **Step 1: Run full test suite for the macOS runner**

Run: `cargo test -p litebox_runner_macos_on_macos_userland -- --nocapture`
Expected: All non-ignored tests pass

- [ ] **Step 2: Run the dynamic linking test**

Run: `cargo test -p litebox_runner_macos_on_macos_userland test_hello_dynamic -- --ignored --nocapture`
Expected: PASS — hello world prints output and exits with code 0

- [ ] **Step 3: Run clippy**

Run: `cargo clippy -p litebox_shim_macos -p litebox_runner_macos_on_macos_userland -- -D warnings`
Expected: No warnings

- [ ] **Step 4: Clean up dead code warnings**

Remove any `#[allow(dead_code)]` annotations that are no longer needed, remove unused fields (like `sysroot` on `GlobalState` if it's fully unused now), etc.

- [ ] **Step 5: Commit final cleanup**

```bash
git add -A
git commit -m "Final cleanup: remove dead code, fix warnings after shared cache switch"
```
