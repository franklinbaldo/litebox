// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::collections::BTreeMap;

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
}
