// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Memory protection for a shared cache mapping or region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    ReadExecute,
    ReadWrite,
    ReadOnly,
}

/// A global mapping region from the cache map header.
#[derive(Debug, Clone)]
pub struct CacheMapping {
    pub vm_start: u64,
    pub vm_end: u64,
    pub prot: Protection,
}

/// A single named segment within a dylib.
#[derive(Debug, Clone)]
pub struct DylibSegment {
    pub name: String,
    pub vm_start: u64,
    pub vm_end: u64,
}

/// A dylib entry: install path + its segments.
#[derive(Debug, Clone)]
pub struct DylibEntry {
    pub path: String,
    pub segments: Vec<DylibSegment>,
}

/// A region of shared cache data ready to be mapped into guest memory.
#[derive(Debug, Clone)]
pub struct SharedCacheRegion {
    pub guest_addr: u64,
    pub data: Vec<u8>,
    pub prot: Protection,
}

/// Parsed representation of a dyld shared cache `.map` file.
#[derive(Debug)]
pub struct CacheMap {
    pub mappings: Vec<CacheMapping>,
    pub dylibs: BTreeMap<String, DylibEntry>,
}

/// Parse a hex string like `0x180088000` into a u64.
fn parse_hex(s: &str) -> Option<u64> {
    let s = s.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))?;
    u64::from_str_radix(s, 16).ok()
}

impl CacheMap {
    /// Parse the text content of a `.map` file.
    ///
    /// The format consists of:
    /// - `mapping` lines at the top describing global regions
    /// - Dylib paths starting with `/` followed by indented segment lines
    pub fn parse(map_text: &str) -> CacheMap {
        let mut mappings = Vec::new();
        let mut dylibs = BTreeMap::new();
        let mut current_dylib: Option<DylibEntry> = None;

        for line in map_text.lines() {
            if line.starts_with("mapping") {
                // Format: mapping  EX 1620MB 0x180088000 -> 0x1E5534000
                let parts: Vec<&str> = line.split_whitespace().collect();
                // parts: ["mapping", prot, size, vm_start, "->", vm_end]
                if parts.len() >= 6 {
                    let prot = match parts[1] {
                        "EX" => Protection::ReadExecute,
                        "RW" => Protection::ReadWrite,
                        "RO" | "R" => Protection::ReadOnly,
                        _ => continue,
                    };
                    if let (Some(vm_start), Some(vm_end)) =
                        (parse_hex(parts[3]), parse_hex(parts[5]))
                    {
                        mappings.push(CacheMapping {
                            vm_start,
                            vm_end,
                            prot,
                        });
                    }
                }
            } else if line.starts_with('/') {
                // Flush previous dylib entry.
                if let Some(entry) = current_dylib.take() {
                    dylibs.insert(entry.path.clone(), entry);
                }
                let path = line.trim().to_string();
                current_dylib = Some(DylibEntry {
                    path,
                    segments: Vec::new(),
                });
            } else if line.starts_with('\t') || line.starts_with(' ') {
                // Segment line: \t          __TEXT 0x190312000 -> 0x190313CE4
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                // parts: ["__TEXT", "0x190312000", "->", "0x190313CE4"]
                if parts.len() >= 4 && parts[2] == "->" {
                    if let (Some(vm_start), Some(vm_end)) =
                        (parse_hex(parts[1]), parse_hex(parts[3]))
                    {
                        if let Some(ref mut entry) = current_dylib {
                            entry.segments.push(DylibSegment {
                                name: parts[0].to_string(),
                                vm_start,
                                vm_end,
                            });
                        }
                    }
                }
            }
            // Empty lines are ignored.
        }

        // Flush last dylib.
        if let Some(entry) = current_dylib.take() {
            dylibs.insert(entry.path.clone(), entry);
        }

        CacheMap { mappings, dylibs }
    }

    /// Return paths of all system dylibs needed for a basic C program:
    /// `/usr/lib/libSystem.B.dylib` and `/usr/lib/system/*.dylib`.
    pub fn system_dylib_paths(&self) -> Vec<String> {
        self.dylibs
            .keys()
            .filter(|p| *p == "/usr/lib/libSystem.B.dylib" || p.starts_with("/usr/lib/system/"))
            .cloned()
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Sub-cache file reader
// ---------------------------------------------------------------------------

/// A single VM mapping entry from a sub-cache file header.
struct SubCacheFileMapping {
    pub vm_addr: u64,
    pub vm_size: u64,
    pub file_offset: u64,
    pub _init_prot: u32,
}

/// Represents a single sub-cache file with its parsed mapping table.
struct SubCacheFile {
    pub path: PathBuf,
    pub mappings: Vec<SubCacheFileMapping>,
}

impl SubCacheFile {
    /// Parse a sub-cache file by reading its header (~4KB).
    /// Returns `None` if the file cannot be read or lacks the `dyld_v1` magic.
    fn parse(path: &Path) -> Option<SubCacheFile> {
        let mut f = fs::File::open(path).ok()?;
        let mut header = vec![0u8; 4096];
        let n = f.read(&mut header).ok()?;
        if n < 24 {
            return None;
        }

        // Validate magic: first 7 bytes must be "dyld_v1"
        if &header[..7] != b"dyld_v1" {
            return None;
        }

        // mapping_offset at offset 16 (u32 LE)
        let mapping_offset = u32::from_le_bytes(header[16..20].try_into().ok()?) as usize;
        // mapping_count at offset 20 (u32 LE)
        let mapping_count = u32::from_le_bytes(header[20..24].try_into().ok()?) as usize;

        if mapping_count == 0 {
            return Some(SubCacheFile {
                path: path.to_path_buf(),
                mappings: Vec::new(),
            });
        }

        // Each mapping entry is 32 bytes.
        let end = mapping_offset + mapping_count * 32;
        if end > n {
            // Need to read more data.
            header.resize(end, 0);
            f.seek(SeekFrom::Start(n as u64)).ok()?;
            f.read_exact(&mut header[n..end]).ok()?;
        }

        let mut mappings = Vec::with_capacity(mapping_count);
        for i in 0..mapping_count {
            let base = mapping_offset + i * 32;
            let vm_addr = u64::from_le_bytes(header[base..base + 8].try_into().ok()?);
            let vm_size = u64::from_le_bytes(header[base + 8..base + 16].try_into().ok()?);
            let file_offset = u64::from_le_bytes(header[base + 16..base + 24].try_into().ok()?);
            // max_prot at base+24..base+28 — skip
            let _init_prot = u32::from_le_bytes(header[base + 28..base + 32].try_into().ok()?);
            mappings.push(SubCacheFileMapping {
                vm_addr,
                vm_size,
                file_offset,
                _init_prot,
            });
        }

        Some(SubCacheFile {
            path: path.to_path_buf(),
            mappings,
        })
    }

    /// Returns `true` if any mapping in this sub-cache file contains `addr`.
    fn contains_vmaddr(&self, addr: u64) -> bool {
        self.mappings
            .iter()
            .any(|m| addr >= m.vm_addr && addr < m.vm_addr + m.vm_size)
    }

    /// Read bytes from `[vm_start, vm_end)` out of this sub-cache file.
    ///
    /// Finds the mapping that contains `vm_start`, computes the file offset,
    /// and reads the bytes.  The read length is clamped to the mapping boundary.
    fn read_region(&self, vm_start: u64, vm_end: u64) -> Option<Vec<u8>> {
        let mapping = self
            .mappings
            .iter()
            .find(|m| vm_start >= m.vm_addr && vm_start < m.vm_addr + m.vm_size)?;

        let offset_in_mapping = vm_start - mapping.vm_addr;
        let file_pos = mapping.file_offset + offset_in_mapping;

        // Clamp to mapping boundary.
        let mapping_remaining = mapping.vm_size - offset_in_mapping;
        let requested = vm_end - vm_start;
        let len = requested.min(mapping_remaining) as usize;

        let mut f = fs::File::open(&self.path).ok()?;
        f.seek(SeekFrom::Start(file_pos)).ok()?;
        let mut buf = vec![0u8; len];
        f.read_exact(&mut buf).ok()?;
        Some(buf)
    }
}

/// Discover all sub-cache files in `cache_dir` matching `dyld_shared_cache_arm64e*`,
/// excluding `.map` and `.atlas` files.
fn discover_subcache_files(cache_dir: &Path) -> Vec<SubCacheFile> {
    let mut files = Vec::new();
    let entries = match fs::read_dir(cache_dir) {
        Ok(e) => e,
        Err(_) => return files,
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.starts_with("dyld_shared_cache_arm64e") {
            continue;
        }
        if name_str.ends_with(".map") || name_str.ends_with(".atlas") {
            continue;
        }
        if let Some(sc) = SubCacheFile::parse(&entry.path()) {
            files.push(sc);
        }
    }
    files
}

/// Determine the memory protection for a segment based on its name.
///
/// Falls back to the global cache mapping that contains `vm_start` for unknown
/// segment names.
fn segment_protection(seg_name: &str, vm_start: u64, mappings: &[CacheMapping]) -> Protection {
    match seg_name {
        "__TEXT" => Protection::ReadExecute,
        "__DATA" | "__DATA_DIRTY" | "__AUTH" => Protection::ReadWrite,
        "__DATA_CONST" | "__AUTH_CONST" | "__TPRO_CONST" | "__LINKEDIT" => Protection::ReadOnly,
        _ => {
            // Fall back to global mapping protection.
            mappings
                .iter()
                .find(|m| vm_start >= m.vm_start && vm_start < m.vm_end)
                .map(|m| m.prot)
                .unwrap_or(Protection::ReadOnly)
        }
    }
}

/// Result of collecting shared cache regions.
pub struct CollectedCache {
    /// Regions to be mapped via `install_shared_cache`.
    pub regions: Vec<SharedCacheRegion>,
}

/// Collect shared-cache regions for the given set of dylibs.
///
/// Maps a complete, independent copy of the cache at UNSLID addresses.
/// The host's shared cache is at SLID addresses (ASLR), so mapping at
/// unslid addresses does not interfere with the host process.
///
/// Includes:
/// - The cache header (first global mapping, typically 544KB)
/// - All segments (__TEXT, __DATA_CONST, __DATA, __AUTH, etc.) of needed dylibs
/// - Deduplicated __LINKEDIT ranges
///
/// The dynamic config data region is returned separately in `CollectedCache`
/// because it may overlap with the host's slid cache and needs special handling.
pub fn collect_regions(
    cache_dir: &Path,
    cache_map: &CacheMap,
    needed_dylibs: &[&str],
) -> CollectedCache {
    let subcaches = discover_subcache_files(cache_dir);

    // Deduplicate regions by (vm_start, vm_end).
    let mut seen: std::collections::HashSet<(u64, u64)> = std::collections::HashSet::new();
    let mut regions: Vec<SharedCacheRegion> = Vec::new();

    // Map the cache header — dyld reads magic, dynamicDataOffset, slide info,
    // and other metadata from the first global mapping.
    if let Some(first_mapping) = cache_map.mappings.first() {
        let header_start = first_mapping.vm_start;
        let header_end = first_mapping.vm_end;
        if let Some(sc) = subcaches.iter().find(|s| s.contains_vmaddr(header_start)) {
            if let Some(mut data) = sc.read_region(header_start, header_end) {
                seen.insert((header_start, header_end));

                // Parse dynamicDataOffset and dynamicDataMaxSize from the cache
                // header. The original offset points to an address that overlaps
                // with the host's slid shared cache (kernel-protected), so we
                // relocate the dynamic config data to the end of the first
                // mapping (which is the header itself) and patch our copy.
                // dyld validates that dynamicDataOffset falls within one of the
                // cache's global mapping ranges, so we must place it INSIDE
                // an existing mapping — not adjacent to one.
                if data.len() >= 0x200 {
                    let orig_off = u64::from_le_bytes(data[0x1F0..0x1F8].try_into().unwrap());
                    let max_size = u64::from_le_bytes(data[0x1F8..0x200].try_into().unwrap());
                    if orig_off != 0 && max_size != 0 {
                        let size = max_size as usize;
                        let header_size = data.len();

                        // Place the dynamic config data at the end of the
                        // header mapping. The mapping covers `header_start..
                        // header_end` and we own all the data, so we can write
                        // the synthesized struct at the tail.
                        let new_offset = (header_size - size) as u64;
                        // Ensure page alignment (16KB pages).
                        let new_offset = new_offset & !0x3FFF;
                        let dyn_guest_addr = header_start + new_offset;

                        eprintln!(
                            "Relocating dyld dynamic config data: orig VM {:#X} → new VM {:#X} \
                             (offset {:#X} → {:#X}, size {:#X})",
                            header_start + orig_off,
                            dyn_guest_addr,
                            orig_off,
                            new_offset,
                            max_size
                        );

                        // Patch dynamicDataOffset in our copy of the header.
                        data[0x1F0..0x1F8].copy_from_slice(&new_offset.to_le_bytes());

                        // Write the synthesized dynamic config data struct
                        // into our header data buffer.
                        //
                        // DynamicRegion layout (from dyld open source):
                        //   char     _magic[16]             — "dyld_data    v3\0"
                        //   fsid_t   _dyldCache.fsid        — { int32_t val[2] } = 8 bytes
                        //   fsobj_id _dyldCache.fsobjid     — { u32 fid_objno; u32 fid_generation } = 8 bytes
                        //   uint32_t _osCryptexPathOffset   — 4 bytes (v1)
                        //   uint32_t _cachePathOffset       — 4 bytes (v2)
                        //   ...more v3 fields...
                        let write_start = new_offset as usize;
                        let magic = b"dyld_data    v3\0";
                        // Zero-fill the region first.
                        data[write_start..write_start + size].fill(0);
                        data[write_start..write_start + 16].copy_from_slice(magic);
                        // FileIdTuple at bytes 16..32: must be non-zero so
                        // FileIdTuple::operator bool() returns true and dyld
                        // doesn't halt.  Write fake but non-zero values.
                        // fsid.val[0] (i32 LE) at offset 16
                        data[write_start + 16..write_start + 20]
                            .copy_from_slice(&1_i32.to_le_bytes());
                        // fsid.val[1] (i32 LE) at offset 20
                        data[write_start + 20..write_start + 24]
                            .copy_from_slice(&0_i32.to_le_bytes());
                        // fsobjid.fid_objno (u32 LE) at offset 24
                        data[write_start + 24..write_start + 28]
                            .copy_from_slice(&1_u32.to_le_bytes());
                        // fsobjid.fid_generation (u32 LE) at offset 28
                        data[write_start + 28..write_start + 32]
                            .copy_from_slice(&0_u32.to_le_bytes());
                    }
                }

                regions.push(SharedCacheRegion {
                    guest_addr: header_start,
                    data,
                    prot: first_mapping.prot,
                });
            }
        }
    }

    // Collect LINKEDIT ranges separately so we can deduplicate them across dylibs.
    let mut linkedit_ranges: Vec<(u64, u64)> = Vec::new();

    for &dylib_path in needed_dylibs {
        let entry = match cache_map.dylibs.get(dylib_path) {
            Some(e) => e,
            None => continue,
        };

        for seg in &entry.segments {
            if seg.name == "__LINKEDIT" {
                linkedit_ranges.push((seg.vm_start, seg.vm_end));
                continue;
            }

            let key = (seg.vm_start, seg.vm_end);
            if !seen.insert(key) {
                continue;
            }

            let prot = segment_protection(&seg.name, seg.vm_start, &cache_map.mappings);

            // Find the sub-cache file that contains this VM address.
            let sc = match subcaches.iter().find(|s| s.contains_vmaddr(seg.vm_start)) {
                Some(s) => s,
                None => continue,
            };

            if let Some(data) = sc.read_region(seg.vm_start, seg.vm_end) {
                regions.push(SharedCacheRegion {
                    guest_addr: seg.vm_start,
                    data,
                    prot,
                });
            }
        }
    }

    // Deduplicate and read LINKEDIT ranges.
    linkedit_ranges.sort();
    linkedit_ranges.dedup();
    for (vm_start, vm_end) in &linkedit_ranges {
        let key = (*vm_start, *vm_end);
        if !seen.insert(key) {
            continue;
        }
        let sc = match subcaches.iter().find(|s| s.contains_vmaddr(*vm_start)) {
            Some(s) => s,
            None => continue,
        };
        if let Some(data) = sc.read_region(*vm_start, *vm_end) {
            regions.push(SharedCacheRegion {
                guest_addr: *vm_start,
                data,
                prot: Protection::ReadOnly,
            });
        }
    }

    CollectedCache { regions }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_map_snippet() {
        let snippet = "\
mapping  EX  544KB 0x180000000 -> 0x180088000
mapping  RW   35MB 0x1E5538000 -> 0x1E7858000
mapping  RO  120MB 0x1F73F0000 -> 0x1FEC78000

/usr/lib/libobjc.A.dylib
\t          __TEXT 0x18008C000 -> 0x1800DEB4C
\t    __DATA_CONST 0x1E55BF000 -> 0x1E55BFB80
\t          __DATA 0x1E9858000 -> 0x1E98586F8
\t      __LINKEDIT 0x1FEC7C000 -> 0x2228D8000

/usr/lib/system/libdyld.dylib
\t          __TEXT 0x1800DF000 -> 0x180113B35
\t    __DATA_CONST 0x1ED950FC8 -> 0x1ED951980
";

        let map = CacheMap::parse(snippet);

        // -- Verify mappings --
        assert_eq!(map.mappings.len(), 3, "expected 3 mappings");

        assert_eq!(map.mappings[0].vm_start, 0x180000000);
        assert_eq!(map.mappings[0].vm_end, 0x180088000);
        assert_eq!(map.mappings[0].prot, Protection::ReadExecute);

        assert_eq!(map.mappings[1].vm_start, 0x1E5538000);
        assert_eq!(map.mappings[1].vm_end, 0x1E7858000);
        assert_eq!(map.mappings[1].prot, Protection::ReadWrite);

        assert_eq!(map.mappings[2].vm_start, 0x1F73F0000);
        assert_eq!(map.mappings[2].vm_end, 0x1FEC78000);
        assert_eq!(map.mappings[2].prot, Protection::ReadOnly);

        // -- Verify dylibs --
        assert_eq!(map.dylibs.len(), 2, "expected 2 dylibs");

        let objc = map
            .dylibs
            .get("/usr/lib/libobjc.A.dylib")
            .expect("missing libobjc");
        assert_eq!(objc.path, "/usr/lib/libobjc.A.dylib");
        assert_eq!(objc.segments.len(), 4);
        assert_eq!(objc.segments[0].name, "__TEXT");
        assert_eq!(objc.segments[0].vm_start, 0x18008C000);
        assert_eq!(objc.segments[0].vm_end, 0x1800DEB4C);
        assert_eq!(objc.segments[3].name, "__LINKEDIT");
        assert_eq!(objc.segments[3].vm_start, 0x1FEC7C000);

        let dyld = map
            .dylibs
            .get("/usr/lib/system/libdyld.dylib")
            .expect("missing libdyld");
        assert_eq!(dyld.segments.len(), 2);
        assert_eq!(dyld.segments[0].name, "__TEXT");
        assert_eq!(dyld.segments[0].vm_start, 0x1800DF000);
        assert_eq!(dyld.segments[0].vm_end, 0x180113B35);

        // -- Verify system_dylib_paths --
        let sys_paths = map.system_dylib_paths();
        assert!(
            sys_paths.contains(&"/usr/lib/system/libdyld.dylib".to_string()),
            "system_dylib_paths should include libdyld"
        );
        // libobjc is NOT under /usr/lib/system/ nor is it libSystem.B.dylib
        assert!(
            !sys_paths.contains(&"/usr/lib/libobjc.A.dylib".to_string()),
            "system_dylib_paths should not include libobjc"
        );
    }

    #[test]
    #[ignore = "requires access to /System/Cryptexes/OS/System/Library/dyld/"]
    fn test_read_real_cache_regions() {
        let cache_dir = std::path::Path::new("/System/Cryptexes/OS/System/Library/dyld/");
        if !cache_dir.exists() {
            eprintln!("Skipping: cache dir does not exist");
            return;
        }

        let map_path = cache_dir.join("dyld_shared_cache_arm64e.map");
        let map_text = std::fs::read_to_string(&map_path).expect("failed to read map file");
        let cache_map = CacheMap::parse(&map_text);
        let sys_paths = cache_map.system_dylib_paths();
        let needed: Vec<&str> = sys_paths.iter().map(|s| s.as_str()).collect();

        eprintln!("Collecting regions for {} dylibs...", needed.len());
        let result = collect_regions(cache_dir, &cache_map, &needed);

        assert!(
            !result.regions.is_empty(),
            "expected at least one region from system dylibs"
        );

        let total_rx: usize = result
            .regions
            .iter()
            .filter(|r| r.prot == Protection::ReadExecute)
            .map(|r| r.data.len())
            .sum();

        eprintln!(
            "Collected {} regions, total RX = {:.2} MB",
            result.regions.len(),
            total_rx as f64 / (1024.0 * 1024.0)
        );

        // System dylibs should be well under 20 MB of RX data.
        assert!(
            total_rx < 20 * 1024 * 1024,
            "total RX {total_rx} bytes exceeds 20 MB — are we loading too much?"
        );
    }
}
