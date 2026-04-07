// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

// Mach VM API for fallback allocation over host shared cache pages.
unsafe extern "C" {
    fn mach_task_self() -> u32;
    fn mach_vm_allocate(target_task: u32, address: *mut u64, size: u64, flags: i32) -> i32;
    fn mach_vm_deallocate(target_task: u32, address: u64, size: u64) -> i32;
}

/// `VM_FLAGS_FIXED`: Use the specified address exactly.
const VM_FLAGS_FIXED: i32 = 0;
/// `VM_FLAGS_OVERWRITE`: Allow overwriting existing mappings (including
/// kernel-managed shared region mappings like the dyld shared cache).
const VM_FLAGS_OVERWRITE: i32 = 0x4000;

/// Memory protection for a shared cache mapping or region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
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
///
/// Data may be heap-allocated (`Vec<u8>`) or file-backed (`MmappedRegion`).
/// The `data()` method returns a `&[u8]` regardless of backing.
#[derive(Debug)]
pub struct SharedCacheRegion {
    pub guest_addr: u64,
    pub prot: Protection,
    backing: RegionBacking,
}

#[derive(Debug)]
#[allow(dead_code)]
enum RegionBacking {
    Heap(Vec<u8>),
    Mmap(MmappedRegion),
}

/// A file-backed mmap region.  Dropped automatically via `munmap`.
///
/// When pages overlap the host shared cache, `mach_vm_allocate` is used
/// instead of `mmap(MAP_FIXED)`.  The `vm_allocated` flag tracks this so
/// `Drop` uses the correct deallocation API.
struct MmappedRegion {
    ptr: *mut u8,
    len: usize,
    /// `true` when the region was allocated via `mach_vm_allocate` (must use
    /// `mach_vm_deallocate` to free); `false` for normal `mmap` regions
    /// (freed via `munmap`).
    vm_allocated: bool,
}

// SAFETY: The mmap'd data is read-only file content, safe to share.
unsafe impl Send for MmappedRegion {}
unsafe impl Sync for MmappedRegion {}

impl std::fmt::Debug for MmappedRegion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MmappedRegion")
            .field("ptr", &self.ptr)
            .field("len", &self.len)
            .field("vm_allocated", &self.vm_allocated)
            .finish()
    }
}

impl Drop for MmappedRegion {
    fn drop(&mut self) {
        if !self.ptr.is_null() && self.len > 0 {
            unsafe {
                if self.vm_allocated {
                    mach_vm_deallocate(mach_task_self(), self.ptr as u64, self.len as u64);
                } else {
                    libc::munmap(self.ptr.cast::<libc::c_void>(), self.len);
                }
            }
        }
    }
}

impl MmappedRegion {
    /// mmap a region from a file.  Returns `None` on failure.
    #[allow(dead_code)]
    fn from_file(file: &fs::File, offset: u64, len: usize) -> Option<MmappedRegion> {
        Self::from_file_at(file, offset, len, None)
    }

    /// mmap a region from a file, optionally at a fixed address.
    ///
    /// If `fixed_addr` is `Some(addr)`, uses `MAP_FIXED` to place the mapping
    /// at exactly `addr`.  This is used for macOS-on-macOS where the guest
    /// address space IS the host process address space.
    ///
    /// When `MAP_FIXED` fails (EACCES/EPERM — typically because the target
    /// address overlaps the host's kernel-managed shared cache), falls back to
    /// `mach_vm_allocate(VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE)` which CAN
    /// replace shared region pages.  The file data is then `pread` into the
    /// allocated anonymous pages and the pages are set to PROT_READ.
    #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
    fn from_file_at(
        file: &fs::File,
        offset: u64,
        len: usize,
        fixed_addr: Option<u64>,
    ) -> Option<MmappedRegion> {
        use std::os::unix::io::AsRawFd;
        if len == 0 {
            return None;
        }
        let (hint, flags) = match fixed_addr {
            Some(addr) => (
                addr as usize as *mut libc::c_void,
                libc::MAP_PRIVATE | libc::MAP_FIXED,
            ),
            None => (std::ptr::null_mut(), libc::MAP_PRIVATE),
        };
        let ptr = unsafe {
            libc::mmap(
                hint,
                len,
                libc::PROT_READ,
                flags,
                file.as_raw_fd(),
                offset as libc::off_t,
            )
        };
        if ptr != libc::MAP_FAILED {
            return Some(MmappedRegion {
                ptr: ptr.cast::<u8>(),
                len,
                vm_allocated: false,
            });
        }

        // mmap failed.  If this was a MAP_FIXED request, the address may
        // overlap the host's shared cache (kernel returns EACCES).  Try
        // the Mach VM API which can overwrite shared region pages.
        let fixed_addr = fixed_addr?;
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno != libc::EACCES && errno != libc::EPERM {
            return None;
        }

        // Phase 1: Allocate anonymous RW pages at the exact address.
        let mut addr = fixed_addr;
        let kr = unsafe {
            mach_vm_allocate(
                mach_task_self(),
                &raw mut addr,
                len as u64,
                VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
            )
        };
        if kr != 0 {
            eprintln!(
                "MmappedRegion: mach_vm_allocate at {fixed_addr:#x} len {len:#x} failed: kern_return {kr}",
            );
            return None;
        }

        // Phase 2: Read the file data into the allocated pages.
        // Use pread to avoid seeking the shared file descriptor.
        let buf_ptr = addr as *mut libc::c_void;
        let mut remaining = len;
        let mut buf_off: usize = 0;
        let mut file_off = offset as libc::off_t;
        while remaining > 0 {
            let n = unsafe {
                libc::pread(
                    file.as_raw_fd(),
                    (buf_ptr as usize + buf_off) as *mut libc::c_void,
                    remaining,
                    file_off,
                )
            };
            if n <= 0 {
                // Read error or EOF.  Zero-fill the rest (already zero from
                // mach_vm_allocate) and break.
                break;
            }
            let n = n.cast_unsigned();
            remaining -= n;
            buf_off += n;
            file_off += n as libc::off_t;
        }

        // Phase 3: Set pages to read-only (matching file-backed mmap behavior).
        let r = unsafe { libc::mprotect(buf_ptr, len, libc::PROT_READ) };
        if r != 0 {
            eprintln!(
                "MmappedRegion: mprotect PROT_READ at {addr:#x} len {len:#x} failed: {}",
                std::io::Error::last_os_error(),
            );
            // Pages are still RW — usable but not ideal.  Continue anyway.
        }

        eprintln!(
            "MmappedRegion: mach_vm_allocate fallback at {addr:#x} len {len:#x} OK \
             (read {buf_off:#x} bytes from file offset {offset:#x})",
        );

        Some(MmappedRegion {
            ptr: addr as *mut u8,
            len,
            vm_allocated: true,
        })
    }

    /// Allocate zero-filled pages at a fixed address via `mach_vm_allocate`.
    ///
    /// Used for regions that overlap the host shared cache where file-backed
    /// mmap is rejected by the kernel.  The pages are anonymous and read-only
    /// (zero-filled).  Dylib-specific segments will be overlaid later by the
    /// heap-based region loader (`install_shared_cache`).
    #[allow(clippy::cast_possible_truncation, dead_code)]
    fn zero_filled_at(addr: u64, len: usize) -> Option<MmappedRegion> {
        if len == 0 {
            return None;
        }
        let mut alloc_addr = addr;
        let kr = unsafe {
            mach_vm_allocate(
                mach_task_self(),
                &raw mut alloc_addr,
                len as u64,
                VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
            )
        };
        if kr != 0 {
            eprintln!(
                "MmappedRegion::zero_filled_at: mach_vm_allocate at {addr:#x} len {len:#x} \
                 failed: kern_return {kr}",
            );
            return None;
        }

        // Set pages to read-only.  They're zero-filled which is enough to
        // prevent SIGBUS.  Dyld may read metadata from these pages and get
        // zeros, but the critical dylib segments are installed separately.
        let r = unsafe { libc::mprotect(alloc_addr as *mut libc::c_void, len, libc::PROT_READ) };
        if r != 0 {
            eprintln!(
                "MmappedRegion::zero_filled_at: mprotect PROT_READ at {alloc_addr:#x} \
                 len {len:#x} failed: {}",
                std::io::Error::last_os_error(),
            );
        }

        Some(MmappedRegion {
            ptr: alloc_addr as *mut u8,
            len,
            vm_allocated: true,
        })
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl SharedCacheRegion {
    /// Get the region data as a byte slice.
    pub fn data(&self) -> &[u8] {
        match &self.backing {
            RegionBacking::Heap(v) => v,
            RegionBacking::Mmap(m) => m.as_slice(),
        }
    }
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
                if parts.len() >= 4
                    && parts[2] == "->"
                    && let (Some(vm_start), Some(vm_end)) =
                        (parse_hex(parts[1]), parse_hex(parts[3]))
                    && let Some(ref mut entry) = current_dylib
                {
                    entry.segments.push(DylibSegment {
                        name: parts[0].to_string(),
                        vm_start,
                        vm_end,
                    });
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
    #[allow(clippy::used_underscore_binding)]
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
    #[allow(clippy::cast_possible_truncation)]
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

    /// Memory-map a region from `[vm_start, vm_end)` using file-backed mmap.
    ///
    /// This is more efficient than `read_region` for large ranges because the
    /// OS only pages in data that's actually accessed.
    #[allow(dead_code)]
    #[allow(clippy::cast_possible_truncation)]
    fn mmap_region(&self, vm_start: u64, vm_end: u64) -> Option<MmappedRegion> {
        self.mmap_region_inner(vm_start, vm_end, None)
    }

    /// Memory-map a region at a fixed guest address using `MAP_FIXED`.
    ///
    /// Used for macOS-on-macOS where the guest address space is the host
    /// process. Maps the file content directly at `vm_start` so data is
    /// lazily paged in by the OS — no copy required.
    #[allow(clippy::cast_possible_truncation, dead_code)]
    fn mmap_region_fixed(&self, vm_start: u64, vm_end: u64) -> Option<MmappedRegion> {
        self.mmap_region_inner(vm_start, vm_end, Some(vm_start))
    }

    /// Memory-map file data for unslid `[vm_start, vm_end)` but place it at
    /// `target_addr` (which may be slid).  The file offset is computed from
    /// the unslid addresses (matching the on-disk subcache mappings), but the
    /// `MAP_FIXED` address is `target_addr`.
    #[allow(clippy::cast_possible_truncation)]
    fn mmap_region_fixed_at(
        &self,
        vm_start: u64,
        vm_end: u64,
        target_addr: u64,
    ) -> Option<MmappedRegion> {
        self.mmap_region_inner(vm_start, vm_end, Some(target_addr))
    }

    #[allow(clippy::cast_possible_truncation)]
    fn mmap_region_inner(
        &self,
        vm_start: u64,
        vm_end: u64,
        fixed_addr: Option<u64>,
    ) -> Option<MmappedRegion> {
        let mapping = self
            .mappings
            .iter()
            .find(|m| vm_start >= m.vm_addr && vm_start < m.vm_addr + m.vm_size)?;

        let offset_in_mapping = vm_start - mapping.vm_addr;
        let file_pos = mapping.file_offset + offset_in_mapping;

        let mapping_remaining = mapping.vm_size - offset_in_mapping;
        let requested = vm_end - vm_start;
        let len = requested.min(mapping_remaining) as usize;

        let f = fs::File::open(&self.path).ok()?;
        MmappedRegion::from_file_at(&f, file_pos, len, fixed_addr)
    }
}

/// Discover all sub-cache files in `cache_dir` matching `dyld_shared_cache_arm64e*`,
/// excluding `.map` and `.atlas` files.
fn discover_subcache_files(cache_dir: &Path) -> Vec<SubCacheFile> {
    let mut files = Vec::new();
    let Ok(entries) = fs::read_dir(cache_dir) else {
        return files;
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
                .map_or(Protection::ReadOnly, |m| m.prot)
        }
    }
}

/// Query the host process's shared cache range using `_dyld_get_shared_cache_range`.
///
/// Returns `(base_address, length)` or `None` if the function is unavailable.
fn host_shared_cache_range() -> Option<(u64, u64)> {
    // Link to the dyld SPI
    unsafe extern "C" {
        fn _dyld_get_shared_cache_range(length: *mut u64) -> u64;
    }
    let mut length: u64 = 0;
    let base = unsafe { _dyld_get_shared_cache_range(&raw mut length) };
    if base == 0 || length == 0 {
        return None;
    }
    Some((base, length))
}

/// Result of collecting shared cache regions.
pub struct CollectedCache {
    /// Regions to be mapped via `install_shared_cache`.
    pub regions: Vec<SharedCacheRegion>,
    /// Extents that were directly mmap'd at guest addresses (MAP_FIXED).
    /// These are already installed and should NOT be passed through
    /// `install_shared_cache`. They should be passed as `reserved_extents`
    /// so the trampoline allocator avoids them.
    /// Each entry is `(start_addr, end_addr)`.
    pub preinstalled_extents: Vec<(u64, u64)>,
    /// __TEXT segments that are already mapped by the host's shared cache
    /// and only need SVC patching in place (no re-mapping).
    ///
    /// Each entry is `(guest_addr, length)`.  The `install_shared_cache`
    /// function will `mprotect(RW)` → SVC-patch → `mprotect(RX)` these
    /// in place, letting the kernel COW-fault the pages on first write.
    pub patch_in_place_text: Vec<(u64, usize)>,
    /// __DATA segments that are host-resident but need resetting to pristine
    /// (uninitialised) state.  The host process's dyld has already written
    /// to these COW-ed pages (e.g. `sMemoryManagerInitialized`), so the
    /// guest sees stale state.  We overwrite them with pristine data read
    /// from the subcache files.
    ///
    /// Each entry is `(slid_guest_addr, pristine_data)`.
    pub reset_in_place_data: Vec<(u64, Vec<u8>)>,
    /// File-backed sources for demand-paging shared cache pages on SIGBUS.
    ///
    /// Each source maps a VM address range to a subcache file + offset so
    /// the shim's exception handler can fill pages with correct data instead
    /// of zeros.
    pub demand_page_sources: Vec<litebox_shim_macos::DemandPageSource>,
    /// The host's ASLR-slid shared cache base address.
    ///
    /// On macOS-on-macOS, we accept the host's slide: the guest uses the
    /// host's already-rebased shared cache data at slid addresses instead
    /// of trying to map its own copy at unslid addresses.  This value is
    /// passed to `install_shared_cache` as `cache_base` so that
    /// `shared_region_check_np` returns the correct (slid) address to dyld.
    pub host_cache_base: u64,
    /// MmappedRegions that must be kept alive for the duration of the guest
    /// process.  Dropping them would unmap the guest memory.
    #[allow(dead_code)]
    preinstalled_mmaps: Vec<MmappedRegion>,
    /// Open file handles for subcache files referenced by `demand_page_sources`.
    /// Must be kept alive for the duration of the guest process so the FDs
    /// remain valid.
    #[allow(dead_code)]
    demand_page_files: Vec<fs::File>,
}

/// Map a sub-region of a global mapping via file-backed mmap at a fixed address.
///
/// `sub_start`/`sub_end` are the *slid* (guest) addresses where data will be
/// placed.  `slide` is subtracted to compute the *unslid* addresses used for
/// subcache file lookup (the on-disk files use unslid addresses).
#[allow(clippy::cast_possible_truncation, clippy::too_many_arguments)]
fn phase0_mmap_subregion(
    sub_start: u64,
    sub_end: u64,
    slide: u64,
    subcaches: &[SubCacheFile],
    preinstalled_extents: &mut Vec<(u64, u64)>,
    preinstalled_mmaps: &mut Vec<MmappedRegion>,
    seen: &mut std::collections::HashSet<(u64, u64)>,
    label: &str,
) {
    // Unslid addresses for subcache lookup.
    let unslid_start = sub_start - slide;
    let unslid_end = sub_end - slide;
    let Some(sc) = subcaches.iter().find(|s| s.contains_vmaddr(unslid_start)) else {
        #[allow(clippy::cast_precision_loss)]
        let sub_size = (sub_end - sub_start) as f64 / (1024.0 * 1024.0);
        eprintln!(
            "    → {label} {sub_start:#x}..{sub_end:#x} ({sub_size:.1} MB): no subcache \
             (unslid {unslid_start:#x})",
        );
        return;
    };
    // Look up file data via unslid addresses, but map at the slid target.
    if let Some(mmap) = sc.mmap_region_fixed_at(unslid_start, unslid_end, sub_start) {
        let actual_len = mmap.len as u64;
        let actual_end = sub_start + actual_len;
        #[allow(clippy::cast_precision_loss)]
        let actual_mb = actual_len as f64 / (1024.0 * 1024.0);
        eprintln!("    → {label} {sub_start:#x}..{actual_end:#x} ({actual_mb:.1} MB): mapped OK",);
        preinstalled_extents.push((sub_start, actual_end));
        seen.insert((sub_start, actual_end));
        preinstalled_mmaps.push(mmap);
    } else {
        #[allow(clippy::cast_precision_loss)]
        let sub_size = (sub_end - sub_start) as f64 / (1024.0 * 1024.0);
        eprintln!("    → {label} {sub_start:#x}..{sub_end:#x} ({sub_size:.1} MB): mmap failed",);
    }
}

/// Collect shared-cache regions for the given set of dylibs.
///
/// Uses the "accept host's slide" strategy: the host process's shared cache
/// (at ASLR-slid addresses) is left in place and registered as preinstalled.
/// Dylib segments are read from subcache files at unslid addresses but placed
/// at slid guest addresses so the guest sees a consistent address space.
///
/// Includes:
/// - ALL global mapping regions registered as preinstalled (host data in place)
/// - After-host portions of global mappings via file-backed mmap at slid addresses
/// - All segments (__TEXT, __DATA_CONST, __DATA, __AUTH, etc.) of needed dylibs
///   at slid addresses
/// - Deduplicated __LINKEDIT ranges at slid addresses
/// - Demand-page sources for gaps in the slid address space
///
/// Global mapping regions are left as-is (host's data). Only the __TEXT segments
/// of explicitly needed dylibs are marked executable and SVC-patched.
#[allow(clippy::cast_possible_truncation)]
pub fn collect_regions(
    cache_dir: &Path,
    cache_map: &CacheMap,
    needed_dylibs: &[&str],
) -> CollectedCache {
    let subcaches = discover_subcache_files(cache_dir);
    eprintln!(
        "collect_regions: discovered {} subcache files",
        subcaches.len()
    );

    // Query the host's shared cache address range so we can split global
    // mappings around it.  All portions (overlapping and non-overlapping)
    // get file-backed mmap — overlapping portions use MAP_FIXED|MAP_PRIVATE
    // which gives the process a COW view without affecting the shared region.
    let host_range = host_shared_cache_range();
    let (host_start, host_end) = if let Some((base, len)) = host_range {
        let end = base + len;
        #[allow(clippy::cast_precision_loss)]
        let size_mb = len as f64 / (1024.0 * 1024.0);
        eprintln!("collect_regions: host shared cache at {base:#x}..{end:#x} ({size_mb:.0} MB)",);
        (base, end)
    } else {
        eprintln!("collect_regions: could not query host shared cache range");
        (0, 0)
    };

    // Deduplicate regions by (vm_start, vm_end).
    let mut seen: std::collections::HashSet<(u64, u64)> = std::collections::HashSet::new();
    let mut regions: Vec<SharedCacheRegion> = Vec::new();
    let mut patch_in_place_text: Vec<(u64, usize)> = Vec::new();
    let reset_in_place_data: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut preinstalled_extents: Vec<(u64, u64)> = Vec::new();
    let mut preinstalled_mmaps: Vec<MmappedRegion> = Vec::new();

    // Compute the host's ASLR slide.  With the "accept host's slide"
    // strategy, we tell the guest dyld that the cache starts at the host's
    // slid base instead of the unslid base (0x180000000).  The host's
    // already-rebased data is then correct — no need to replace overlap pages.
    let unslid_base = cache_map
        .mappings
        .first()
        .map_or(0x180000000, |m| m.vm_start);
    let host_slide = if host_start > 0 {
        host_start - unslid_base
    } else {
        0
    };
    eprintln!(
        "collect_regions: accepting host slide {host_slide:#x} \
         (unslid base {unslid_base:#x}, slid base {host_start:#x})",
    );

    // Phase 0: Register the host's shared cache as preinstalled.
    //
    // With the "accept host's slide" strategy, the host's shared cache at
    // [host_start, host_end) already contains correctly-rebased data.  We
    // do NOT mmap anything over it — we simply register the entire range as
    // preinstalled so the trampoline allocator avoids it.
    //
    // For portions of global mappings that fall OUTSIDE the host cache
    // (after-host sub-regions), we still need file-backed mmap at slid
    // addresses.
    for (i, mapping) in cache_map.mappings.iter().enumerate() {
        let vm_start = mapping.vm_start;
        let vm_end = mapping.vm_end;
        // Slid addresses: where the host has this mapping's data.
        let slid_start = vm_start + host_slide;
        let slid_end = vm_end + host_slide;
        #[allow(clippy::cast_precision_loss)]
        let size_mb = (vm_end - vm_start) as f64 / (1024.0 * 1024.0);
        let prot = mapping.prot;
        eprintln!(
            "  Phase 0: mapping {i} slid {slid_start:#x}..{slid_end:#x} \
             ({size_mb:.1} MB, {prot:?})",
        );
        // Use slid addresses as the dedup key.
        let key = (slid_start, slid_end);
        if !seen.insert(key) {
            eprintln!("    → skipped (duplicate)");
            continue;
        }

        if host_start > 0 && host_end > host_start {
            // The portion within [host_start, host_end) is already mapped
            // by the host — just register as preinstalled.
            let overlap_start = slid_start.max(host_start);
            let overlap_end = slid_end.min(host_end);
            if overlap_end > overlap_start {
                #[allow(clippy::cast_precision_loss)]
                let overlap_mb = (overlap_end - overlap_start) as f64 / (1024.0 * 1024.0);
                eprintln!(
                    "    → overlap {overlap_start:#x}..{overlap_end:#x} ({overlap_mb:.1} MB): \
                     host data in place (accepted slide)",
                );
                preinstalled_extents.push((overlap_start, overlap_end));
            }

            // Portion after the host cache: file-backed mmap at slid address.
            let after_start = slid_start.max(host_end);
            let after_end = slid_end;
            if after_end > after_start {
                phase0_mmap_subregion(
                    after_start,
                    after_end,
                    host_slide,
                    &subcaches,
                    &mut preinstalled_extents,
                    &mut preinstalled_mmaps,
                    &mut seen,
                    "after-host",
                );
            }
        } else {
            // No host cache info — map the whole thing via file-backed mmap.
            phase0_mmap_subregion(
                slid_start,
                slid_end,
                host_slide,
                &subcaches,
                &mut preinstalled_extents,
                &mut preinstalled_mmaps,
                &mut seen,
                "full",
            );
        }
    }

    eprintln!(
        "collect_regions: Phase 0 done — {} preinstalled extents",
        preinstalled_extents.len()
    );

    // Phase 1: Cache header.
    //
    // With the "accept host's slide" strategy, the host's cache header at
    // `host_start` is already in place and correct — the kernel set up the
    // dynamic config data and applied the ASLR slide.  We don't need to map
    // or patch a separate header copy.  The preinstalled extent from Phase 0
    // already covers the header region.
    eprintln!(
        "collect_regions: Phase 1 (header) — skipped (using host's header at {host_start:#x})"
    );

    // Collect LINKEDIT ranges separately so we can deduplicate them across dylibs.
    // Store as (unslid_start, unslid_end) — slide is applied when creating regions.
    let mut linkedit_ranges: Vec<(u64, u64)> = Vec::new();

    // With the "accept host's slide" strategy, the host's shared cache already
    // contains correctly-rebased data at slid addresses.  Non-executable
    // segments (DATA, DATA_CONST, AUTH, etc.) don't need to be overwritten —
    // the host's copy is identical.  Only __TEXT segments need heap regions
    // because they must be SVC-patched by install_shared_cache.
    //
    // Segments that fall entirely within a preinstalled extent are considered
    // "host-resident" and are skipped for non-executable segments.
    let is_host_resident = |slid_start: u64, slid_end: u64| -> bool {
        preinstalled_extents
            .iter()
            .any(|&(ext_start, ext_end)| slid_start >= ext_start && slid_end <= ext_end)
    };

    for &dylib_path in needed_dylibs {
        let Some(entry) = cache_map.dylibs.get(dylib_path) else {
            continue;
        };

        for seg in &entry.segments {
            if seg.name == "__LINKEDIT" {
                linkedit_ranges.push((seg.vm_start, seg.vm_end));
                continue;
            }

            // Use slid addresses for dedup (consistent with Phase 0).
            let slid_start = seg.vm_start + host_slide;
            let slid_end = seg.vm_end + host_slide;
            let key = (slid_start, slid_end);
            if !seen.insert(key) {
                continue;
            }

            let prot = segment_protection(&seg.name, seg.vm_start, &cache_map.mappings);
            let host_resident = is_host_resident(slid_start, slid_end);

            // Host-resident __TPRO_CONST segments — skip for now.
            // The loaded dyld uses PC-relative (ADRP) addressing to reference
            // its own __TPRO_CONST copy which is fresh from disk (all zeros).
            // The shared cache libdyld's __TPRO_CONST is hardware write-
            // protected (TPRO/SPRR) and cannot be reset without hanging.
            // Since the loaded dyld doesn't reference the shared cache copy,
            // we don't need to reset it.
            if seg.name == "__TPRO_CONST" && host_resident {
                continue;
            }

            // Host-resident ReadOnly segments — host data is identical, skip.
            if prot == Protection::ReadOnly && host_resident {
                continue;
            }

            // Host-resident ReadWrite segments — the host may have written to
            // these COW pages.  We skip resetting regular __DATA/__DATA_DIRTY
            // because overwriting them corrupts the host process's runtime
            // (malloc, threading, etc.).  Only __TPRO_CONST is reset (above).
            if prot == Protection::ReadWrite && host_resident {
                continue;
            }

            // Host-resident __TEXT: don't re-map, just record for in-place
            // SVC patching (mprotect RW → patch → mprotect RX).
            if prot == Protection::ReadExecute && host_resident {
                // Page-align the length for mprotect.
                let len = (slid_end - slid_start) as usize;
                patch_in_place_text.push((slid_start, len));
                continue;
            }

            // Non-host-resident segment: read from subcache and emit as a
            // heap-backed region for install_shared_cache to map.
            let Some(sc) = subcaches.iter().find(|s| s.contains_vmaddr(seg.vm_start)) else {
                continue;
            };

            if let Some(data) = sc.read_region(seg.vm_start, seg.vm_end) {
                regions.push(SharedCacheRegion {
                    guest_addr: slid_start,
                    prot,
                    backing: RegionBacking::Heap(data),
                });
            }
        }
    }

    // Deduplicate and read LINKEDIT ranges.
    // With the slid approach, LINKEDIT is read-only and host-resident.
    // Skip LINKEDIT ranges that are entirely within the host's preinstalled
    // extents — the host data is identical.
    linkedit_ranges.sort_unstable();
    linkedit_ranges.dedup();
    for (vm_start, vm_end) in &linkedit_ranges {
        // Use slid addresses for dedup and guest placement.
        let slid_start = vm_start + host_slide;
        let slid_end = vm_end + host_slide;
        let key = (slid_start, slid_end);
        if !seen.insert(key) {
            continue;
        }
        // Skip host-resident LINKEDIT ranges.
        if is_host_resident(slid_start, slid_end) {
            continue;
        }
        // Subcache lookup uses unslid addresses.
        let Some(sc) = subcaches.iter().find(|s| s.contains_vmaddr(*vm_start)) else {
            continue;
        };
        if let Some(data) = sc.read_region(*vm_start, *vm_end) {
            regions.push(SharedCacheRegion {
                guest_addr: slid_start,
                prot: Protection::ReadOnly,
                backing: RegionBacking::Heap(data),
            });
        }
    }

    eprintln!(
        "collect_regions: done — {} heap regions, {} patch-in-place text, {} reset-in-place data, {} preinstalled extents",
        regions.len(),
        patch_in_place_text.len(),
        reset_in_place_data.len(),
        preinstalled_extents.len()
    );

    // Build demand-page sources for gaps in the guest address space.
    //
    // The host's shared cache is left in place, but there may be gaps between
    // subcache file mappings where no physical page exists.  When the guest
    // (dyld) touches such a page, it gets SIGBUS.  We create DemandPageSource
    // entries at *slid* addresses so the shim's exception handler can pread
    // the correct file data into the faulting page.
    //
    // We cover the full range of each subcache file mapping (translated to
    // slid addresses) — not just the host overlap region — because after-host
    // regions also benefit from demand-paging for unmapped gaps.
    let mut demand_page_sources: Vec<litebox_shim_macos::DemandPageSource> = Vec::new();
    let mut demand_page_files: Vec<fs::File> = Vec::new();

    {
        // Open each subcache file once and create sources for all mappings.
        for sc in &subcaches {
            let mut file_opened = false;
            let mut fd: i32 = -1;

            for mapping in &sc.mappings {
                // Subcache mappings are at unslid addresses.  Translate to slid.
                let slid_m_start = mapping.vm_addr + host_slide;
                let slid_m_end = mapping.vm_addr + mapping.vm_size + host_slide;

                // Open the file lazily (only if we have mappings to register).
                if !file_opened {
                    if let Ok(f) = fs::File::open(&sc.path) {
                        use std::os::unix::io::AsRawFd;
                        fd = f.as_raw_fd();
                        demand_page_files.push(f);
                        file_opened = true;
                    } else {
                        eprintln!(
                            "collect_regions: WARNING: cannot open {} for demand-paging",
                            sc.path.display()
                        );
                        break;
                    }
                }

                demand_page_sources.push(litebox_shim_macos::DemandPageSource {
                    vm_start: slid_m_start,
                    vm_end: slid_m_end,
                    fd,
                    file_offset: mapping.file_offset,
                });
            }
        }

        demand_page_sources.sort_unstable_by_key(|s| s.vm_start);
        eprintln!(
            "collect_regions: {} demand-page sources covering slid address space",
            demand_page_sources.len()
        );
    }

    CollectedCache {
        regions,
        preinstalled_extents,
        patch_in_place_text,
        reset_in_place_data,
        demand_page_sources,
        host_cache_base: host_start,
        preinstalled_mmaps,
        demand_page_files,
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

    #[test]
    #[allow(clippy::cast_precision_loss)]
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
        let needed: Vec<&str> = sys_paths.iter().map(std::string::String::as_str).collect();

        eprintln!("Collecting regions for {} dylibs...", needed.len());
        let result = collect_regions(cache_dir, &cache_map, &needed);

        // With the "accept host's slide" strategy, all segments are host-resident,
        // so `regions` (heap-backed copies) may be empty.  Verify that the
        // collector found *something* — either heap-backed regions, host-resident
        // TEXT needing SVC patching, or preinstalled extents.
        assert!(
            !result.regions.is_empty()
                || !result.patch_in_place_text.is_empty()
                || !result.preinstalled_extents.is_empty(),
            "expected at least one region, patch-in-place text, or preinstalled extent \
             from system dylibs (regions={}, patch_in_place={}, preinstalled={})",
            result.regions.len(),
            result.patch_in_place_text.len(),
            result.preinstalled_extents.len(),
        );

        let total_rx: usize = result
            .regions
            .iter()
            .filter(|r| r.prot == Protection::ReadExecute)
            .map(|r| r.data().len())
            .sum();

        eprintln!(
            "Collected {} regions (total RX = {:.2} MB), {} patch-in-place TEXT, {} preinstalled",
            result.regions.len(),
            total_rx as f64 / (1024.0 * 1024.0),
            result.patch_in_place_text.len(),
            result.preinstalled_extents.len(),
        );

        // System dylibs should be well under 20 MB of RX data in heap-backed regions.
        assert!(
            total_rx < 20 * 1024 * 1024,
            "total RX {total_rx} bytes exceeds 20 MB — are we loading too much?"
        );
    }
}
