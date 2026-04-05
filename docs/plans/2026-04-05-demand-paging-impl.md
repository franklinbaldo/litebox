# Demand Paging Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace memcpy-based ELF segment loading during exec with mmap of a page-aligned data memfd, enabling demand paging and eliminating ~260KB of memcpy per exec cycle.

**Architecture:** Launcher creates a second memfd (`litebox-aligned-data`) containing file data at page-aligned offsets. Central reconstructs the offset map from the tar index using the same deterministic algorithm. Micro uses `mmap(MAP_PRIVATE|MAP_FIXED, aligned_fd, offset)` for page-aligned segments, falling back to memcpy for non-aligned ones. BSS is explicitly zeroed after mmap.

**Tech Stack:** Rust (edition 2024), `#![no_std]` for micro/IPC crates, memfd_create, mmap, MAP_PRIVATE, MAP_FIXED.

**Design doc:** `docs/plans/2026-04-05-demand-paging-design.md`

---

### Task 1: AlignedDataRegion in launcher

Create a memfd with file data placed at page-aligned offsets.

**Files:**
- Modify: `litebox_launcher/src/shmem.rs` (after `TarSharedRegion` impl)

**Step 1: Add AlignedDataRegion struct**

Add after `TarSharedRegion`:

```rust
/// A shared memory region containing file data at page-aligned offsets,
/// enabling demand paging via `mmap(MAP_PRIVATE|MAP_FIXED)`.
///
/// Created from a tar blob by iterating entries in order and copying each
/// file's data to the next page-aligned (4096-byte) position. Both launcher
/// and central can independently reconstruct the `path -> aligned_offset`
/// mapping using the same deterministic algorithm.
pub struct AlignedDataRegion {
    fd: OwnedFd,
    ptr: NonNull<u8>,
    size: usize,
}

unsafe impl Send for AlignedDataRegion {}
```

**Step 2: Implement the page-alignment algorithm**

```rust
const PAGE_SIZE: usize = 4096;

impl AlignedDataRegion {
    /// Build a page-aligned data region from raw tar bytes.
    ///
    /// Iterates tar entries in order, copies each file's data to the next
    /// page-aligned offset. The deterministic algorithm is:
    /// ```text
    /// offset = 0
    /// for each file in tar_entry_order:
    ///     offset = (offset + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
    ///     copy file data to [offset..offset+file_size]
    ///     offset += file_size
    /// total_size = (offset + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
    /// ```
    pub fn from_tar_bytes(tar_data: &[u8]) -> anyhow::Result<Self> {
        // Phase 1: compute total aligned size and collect entries
        let archive = tar_no_std::TarArchiveRef::new(tar_data)
            .map_err(|_| anyhow::anyhow!("invalid tar data for alignment"))?;

        let mut entries: Vec<(&[u8], usize)> = Vec::new(); // (data, aligned_offset)
        let mut offset: usize = 0;
        for entry in archive.entries() {
            offset = (offset + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
            let data = entry.data();
            entries.push((data, offset));
            offset += data.len();
        }
        let total_size = if offset == 0 {
            PAGE_SIZE // minimum one page
        } else {
            (offset + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
        };

        // Phase 2: create memfd and copy data
        let name = c"litebox-aligned-data";
        let raw_fd = unsafe { libc::memfd_create(name.as_ptr(), 0) };
        if raw_fd < 0 {
            return Err(anyhow::anyhow!(
                "memfd_create failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        let ret = unsafe {
            libc::ftruncate(fd.as_raw_fd(), i64::try_from(total_size).expect("size fits"))
        };
        if ret != 0 {
            return Err(anyhow::anyhow!(
                "ftruncate failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                total_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(anyhow::anyhow!(
                "mmap failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Copy each file's data to its page-aligned offset
        for (data, aligned_offset) in &entries {
            if !data.is_empty() {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        data.as_ptr(),
                        (ptr as *mut u8).add(*aligned_offset),
                        data.len(),
                    );
                }
            }
        }

        // Downgrade to read-only
        let ret = unsafe { libc::mprotect(ptr, total_size, libc::PROT_READ) };
        if ret != 0 {
            eprintln!(
                "litebox_launcher: mprotect on aligned data failed: {}",
                std::io::Error::last_os_error()
            );
        }

        Ok(Self {
            fd,
            ptr: NonNull::new(ptr.cast::<u8>()).expect("mmap succeeded but null"),
            size: total_size,
        })
    }

    pub fn fd_raw(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    pub fn base_ptr(&self) -> *const u8 {
        self.ptr.as_ptr()
    }

    pub fn size(&self) -> usize {
        self.size
    }
}

impl Drop for AlignedDataRegion {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr.as_ptr().cast(), self.size);
        }
    }
}
```

**Step 3: Add the `compute_aligned_offsets` standalone function**

This function is the deterministic algorithm that both launcher and central use. Extract it so it can be shared (or duplicated in central since they're different crates):

```rust
/// Compute page-aligned offsets for all files in a tar archive.
///
/// Returns a Vec of (filename, aligned_offset, file_size) tuples.
/// The algorithm is deterministic: iterate tar entries in order,
/// assign each to the next page-aligned offset.
pub fn compute_aligned_offsets(tar_data: &[u8]) -> Vec<(String, usize, usize)> {
    let archive = tar_no_std::TarArchiveRef::new(tar_data).expect("invalid tar");
    let mut result = Vec::new();
    let mut offset: usize = 0;
    for entry in archive.entries() {
        offset = (offset + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let name = entry.filename().as_str().unwrap_or("").to_string();
        let size = entry.data().len();
        result.push((name, offset, size));
        offset += size;
    }
    result
}
```

Actually, this function needs to live somewhere accessible to both launcher and central. The launcher has `std` and can use `tar_no_std`. Central also has `std`. But they're separate crates. Options:
- Duplicate the algorithm (it's ~10 lines, simple enough)
- Put it in a shared crate (overkill)

Duplicate it. Central will reconstruct the map in Task 4.

**Step 4: Add unit tests**

```rust
#[test]
fn aligned_data_region_from_tar() {
    // Create a minimal valid tar with the standard `tar` crate
    let mut builder = tar::Builder::new(Vec::new());
    let data1 = b"hello world";
    let mut header1 = tar::Header::new_gnu();
    header1.set_size(data1.len() as u64);
    header1.set_mode(0o644);
    header1.set_entry_type(tar::EntryType::Regular);
    header1.set_cksum();
    builder.append_data(&mut header1, "file1.txt", &data1[..]).unwrap();

    let data2 = b"second file with more content for testing";
    let mut header2 = tar::Header::new_gnu();
    header2.set_size(data2.len() as u64);
    header2.set_mode(0o644);
    header2.set_entry_type(tar::EntryType::Regular);
    header2.set_cksum();
    builder.append_data(&mut header2, "file2.txt", &data2[..]).unwrap();
    builder.finish().unwrap();
    let tar_bytes = builder.into_inner().unwrap();

    let region = AlignedDataRegion::from_tar_bytes(&tar_bytes).expect("failed");
    assert!(region.size() > 0);
    assert!(region.size() % 4096 == 0);
    assert!(region.fd_raw() >= 0);

    // Verify data is at page-aligned offsets
    let base = region.base_ptr();
    // File 1 should be at offset 0 (page-aligned)
    let slice1 = unsafe { core::slice::from_raw_parts(base, data1.len()) };
    assert_eq!(slice1, data1);
    // File 2 should be at the next page boundary
    let offset2 = 4096; // first file is 11 bytes, next page is at 4096
    let slice2 = unsafe { core::slice::from_raw_parts(base.add(offset2), data2.len()) };
    assert_eq!(slice2, data2);
}
```

**Step 5: Add tar-no-std dependency to launcher if not already present**

Check `litebox_launcher/Cargo.toml` — add `tar-no-std` dependency if needed.

**Step 6: Build and test**

```bash
cargo build -p litebox_launcher
cargo nextest run -p litebox_launcher
```

**Step 7: Commit**

```bash
git add litebox_launcher/src/shmem.rs litebox_launcher/Cargo.toml
git commit -m "feat(launcher): add AlignedDataRegion for page-aligned ELF data memfd"
```

---

### Task 2: Wire aligned data memfd through launcher

Pass the aligned memfd to central and micro.

**Files:**
- Modify: `litebox_launcher/src/main.rs` (lines 49-106)
- Modify: `litebox_launcher/src/central.rs` (lines 53-137)
- Modify: `litebox_micro/src/state.rs` (MicroState, micro_init)
- Modify: `litebox_micro/src/lib.rs` (re-export)

**Step 1: Add aligned fields to MicroState**

In `litebox_micro/src/state.rs`, add to `MicroState` after `tar_size`:

```rust
    /// File descriptor for the aligned data memfd (for mmap during exec).
    pub aligned_fd: i32,
    /// Base pointer of the aligned data memfd mapping.
    pub aligned_base: *const u8,
    /// Size of the aligned data memfd in bytes.
    pub aligned_size: usize,
```

**Step 2: Extend micro_init**

Add `aligned_fd: i32`, `aligned_base: *const u8`, `aligned_size: usize` parameters. Store them in `MICRO_STATE`.

**Step 3: Update CentralProcess::spawn**

Add `aligned_fd: Option<i32>` and `aligned_size: Option<usize>` parameters. In the child arg construction:

```rust
if let Some(afd) = aligned_fd {
    c_args.push(CString::new(format!("--aligned-fd={afd}")).unwrap());
}
if let Some(asz) = aligned_size {
    c_args.push(CString::new(format!("--aligned-size={asz}")).unwrap());
}
```

**Step 4: Update launcher main.rs**

After creating `tar_shmem`, create the aligned data region:

```rust
let aligned_data = tar_shmem.as_ref()
    .map(|ts| {
        let tar_bytes = unsafe {
            core::slice::from_raw_parts(ts.base_ptr(), ts.size())
        };
        shmem::AlignedDataRegion::from_tar_bytes(tar_bytes)
    })
    .transpose()?;
```

Pass to central:
```rust
let central = central::CentralProcess::spawn(
    shmem.fd_raw(),
    loaded.brk,
    tar_shmem.as_ref().map(shmem::TarSharedRegion::fd_raw),
    tar_shmem.as_ref().map(shmem::TarSharedRegion::size),
    aligned_data.as_ref().map(shmem::AlignedDataRegion::fd_raw),
    aligned_data.as_ref().map(shmem::AlignedDataRegion::size),
    tun_device.as_deref(),
);
```

Pass to micro_init:
```rust
litebox_micro::micro_init(
    // ... existing params ...
    tar_shmem.as_ref().map_or(core::ptr::null(), shmem::TarSharedRegion::base_ptr),
    tar_shmem.as_ref().map_or(0, shmem::TarSharedRegion::size),
    aligned_data.as_ref().map_or(-1, shmem::AlignedDataRegion::fd_raw),
    aligned_data.as_ref().map_or(core::ptr::null(), shmem::AlignedDataRegion::base_ptr),
    aligned_data.as_ref().map_or(0, shmem::AlignedDataRegion::size),
);
```

**Step 5: Build**

```bash
cargo build -p litebox_launcher
cargo build -p litebox_micro
```

**Step 6: Commit**

```bash
git add litebox_launcher/src/main.rs litebox_launcher/src/central.rs \
       litebox_micro/src/state.rs litebox_micro/src/lib.rs
git commit -m "feat(launcher): wire aligned data memfd through to central and micro"
```

---

### Task 3: Central receives aligned memfd and builds offset map

Central parses the aligned memfd CLI args and reconstructs the page-aligned offset map.

**Files:**
- Modify: `litebox_central/src/main.rs` (Args, tar loading section)
- Modify: `litebox_central/src/server.rs` (ProcessServer fields)

**Step 1: Add CLI args to central's Args struct**

```rust
    #[arg(long)]
    aligned_fd: Option<i32>,

    #[arg(long, default_value = "0")]
    aligned_size: usize,
```

**Step 2: Build aligned offset map in central**

After building `tar_file_map` (line ~195), reconstruct the aligned offset map using the same deterministic algorithm. Central has the tar data (from the tar shmem) and can iterate it:

```rust
let aligned_file_map: HashMap<String, (usize, usize)> = {
    let mut map = HashMap::new();
    if args.aligned_size > 0 {
        let mut offset: usize = 0;
        let page_size: usize = 4096;
        for (path, range) in tar_ro.all_file_data_ranges() {
            offset = (offset + page_size - 1) & !(page_size - 1);
            let file_size = range.end - range.start;
            map.insert(path.to_string(), (offset, file_size));
            offset += file_size;
        }
    }
    map
};
```

**IMPORTANT**: The iteration order of `all_file_data_ranges()` must match the tar entry order used in the launcher's `AlignedDataRegion::from_tar_bytes()`. Both iterate using `tar_no_std::TarArchiveRef::entries()` over the same tar data, so the order is deterministic and identical. However, `all_file_data_ranges()` iterates `files_by_path` (a HashMap), which does NOT have deterministic order. This is a bug — we need to iterate in tar entry order instead.

**Fix**: Use `tar_ro.files` (the Vec in TarIndex) which preserves tar entry order, OR expose a method that returns files in tar entry order.

Actually, looking at the TarIndex construction: `files` is a `Vec<IndexedFile>` populated in tar entry order, and `files_by_path` is a `HashMap<String, usize>` mapping path → index. The `all_file_data_ranges()` method iterates `files_by_path` which has random order.

**Solution**: Add a new method `all_file_data_ranges_ordered()` that iterates `files` (the Vec) in order:

```rust
pub fn all_file_data_ranges_ordered(&self) -> impl Iterator<Item = (&str, Range<usize>)> + '_ {
    self.files.iter().map(|f| (f.path.as_str(), f.data_range.clone()))
}
```

Wait — need to check if `IndexedFile` has a `path` field. Let me note this as a requirement: ensure the method exists or create it. Central's deterministic map reconstruction MUST iterate in tar entry order.

**Step 3: Store in ProcessServer**

Add `aligned_file_map: HashMap<String, (usize, usize)>` to `ProcessServer`. Thread it from main.

**Step 4: Build**

```bash
cargo build --release -p litebox_central
```

**Step 5: Commit**

```bash
git add litebox_central/src/main.rs litebox_central/src/server.rs litebox/src/fs/tar_ro.rs
git commit -m "feat(central): receive aligned memfd and build page-aligned offset map"
```

---

### Task 4: Central exec handler — use aligned offsets

Central computes `tar_data_offset` using the aligned offset map instead of tar pointer subtraction.

**Files:**
- Modify: `litebox_central/src/server.rs` (`compute_tar_offset` function, ~lines 3695-3712)

**Step 1: Modify compute_tar_offset**

Replace the pointer-subtraction approach with an aligned offset map lookup. The function needs access to the aligned_file_map and the file path. Rename and restructure:

```rust
fn compute_aligned_offset(
    aligned_file_map: &HashMap<String, (usize, usize)>,
    file_path: &str,
    file_data_offset: u64,  // ELF segment's p_offset
    aligned_size: usize,    // total aligned memfd size, for bounds check
) -> u64 {
    if aligned_size == 0 {
        return u64::MAX;
    }
    if let Some(&(aligned_start, _file_size)) = aligned_file_map.get(file_path) {
        let result = (aligned_start as u64) + file_data_offset;
        if (result as usize) < aligned_size {
            result
        } else {
            u64::MAX
        }
    } else {
        u64::MAX
    }
}
```

**Step 2: Update all call sites of compute_tar_offset**

The exec handler needs the file path to look up the aligned offset. Currently `compute_tar_offset` uses pointer arithmetic. Update the calling code to pass the file path and use the new function.

The file path is available in the exec handler — it's the `path` or `interp_path` that was resolved earlier.

**Step 3: Build**

```bash
cargo build --release -p litebox_central
cargo clippy -p litebox_central
```

**Step 4: Commit**

```bash
git add litebox_central/src/server.rs
git commit -m "feat(central): use aligned offset map for exec segment offsets"
```

---

### Task 5: Micro exec handler — mmap from aligned fd

Replace memcpy with mmap(MAP_PRIVATE|MAP_FIXED) for page-aligned segments.

**Files:**
- Modify: `litebox_micro/src/execve.rs` (lines 823-854, segment data copy loop)

**Step 1: Modify segment data copy loop**

In the pass-1 loop (Phase 2) where segment data is copied, replace the memcpy with an mmap attempt for tar-backed segments:

```rust
for i in 0..num_segments {
    let seg = unsafe { /* read ExecveSegment */ };
    let vaddr = seg.vaddr as usize;
    let data_len = seg.data_len as usize;
    let map_len = seg.map_len as usize;

    if data_len > 0 && seg.tar_data_offset != u64::MAX {
        let tar_off = seg.tar_data_offset as usize;

        // Try mmap path if offset is page-aligned
        if tar_off % 4096 == 0 && map_len > 0 {
            // mmap the segment from the aligned data memfd
            let mmap_len = if data_len < map_len { map_len } else { data_len };
            // Round mmap_len up to page boundary
            let mmap_len_rounded = (mmap_len + 4095) & !4095;

            let result = unsafe {
                libc::mmap(
                    vaddr as *mut libc::c_void,
                    mmap_len_rounded,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_FIXED,
                    micro.aligned_fd,
                    tar_off as libc::off_t,
                )
            };

            if result != libc::MAP_FAILED {
                // mmap succeeded — zero BSS if needed
                if data_len < map_len {
                    unsafe {
                        core::ptr::write_bytes(
                            (vaddr + data_len) as *mut u8,
                            0,
                            map_len - data_len,
                        );
                    }
                }
                continue; // skip memcpy path
            }
            // mmap failed — fall through to memcpy
        }

        // Memcpy fallback (non-aligned or mmap failed)
        if tar_off + data_len > micro.aligned_size {
            unsafe { crate::raw_syscall::syscall1(libc::SYS_exit_group, 127) };
        }
        unsafe {
            core::ptr::copy_nonoverlapping(
                micro.aligned_base.add(tar_off),
                vaddr as *mut u8,
                data_len,
            );
        }
    } else if data_len > 0 {
        // Ring data region path (non-tar binary)
        unsafe {
            core::ptr::copy_nonoverlapping(
                data_base.add(seg.data_offset as usize),
                vaddr as *mut u8,
                data_len,
            );
        }
    }
}
```

**Important considerations:**
- The bulk anonymous mmap still happens first (reserves the full VA range). The `MAP_FIXED` mmap replaces specific pages within that range.
- `MAP_PRIVATE` ensures writes (BSS zeroing, trampoline patching, relocations) create COW pages.
- If the aligned memfd doesn't have enough data at the offset (file is shorter than the segment), the kernel maps what's available and fills the rest. But we explicitly zero BSS regardless.

**Step 2: Verify trampoline handling is compatible**

Trampolines write to segment pages. With `MAP_PRIVATE`, writes trigger COW — this should work identically. Verify the trampoline code path doesn't assume anonymous backing.

**Step 3: Build and clippy**

```bash
cargo build --release -p litebox_micro -p litebox_launcher
cargo clippy -p litebox -p litebox_shim_linux -p litebox_micro -p litebox_launcher
```

**Step 4: Smoke test — execl benchmark**

```bash
pkill -9 litebox_central; pkill -9 litebox; pkill -9 litebox_launcher
cargo build --release -p litebox_central
sudo sh -c 'sync; echo 3 > /proc/sys/vm/drop_caches'
sudo -E python3 dev_bench/unixbench/run_unixbench.py \
  --mode micro --release --no-build --duration 3 --iterations 1 --benchmarks execl
```

**Step 5: Commit**

```bash
git add litebox_micro/src/execve.rs
git commit -m "feat(micro): mmap ELF segments from aligned data memfd instead of memcpy"
```

---

### Task 6: Ordered tar iteration for deterministic offset map

Ensure both launcher and central iterate tar entries in the same order.

**Files:**
- Modify: `litebox/src/fs/tar_ro.rs` (add `all_file_data_ranges_ordered` method)

**Step 1: Check TarIndex internals**

Verify that `TarIndex` stores files in a `Vec` that preserves tar entry order. Check `IndexedFile` struct for path field.

**Step 2: Add ordered iteration method**

If `files_by_path` iteration (used by `all_file_data_ranges()`) is not ordered, add:

```rust
/// Returns file data ranges in tar entry order (deterministic).
/// This is required for the aligned data memfd offset reconstruction.
pub fn all_file_data_ranges_ordered(&self) -> impl Iterator<Item = (&str, Range<usize>)> + '_ {
    self.files.iter().map(|f| {
        // Need to get path — check how IndexedFile stores it
        // ...
    })
}
```

Alternatively, if `files_by_path` is iterated via `iter()` on a `HashMap` (non-deterministic), central MUST use a different approach. The simplest fix: central iterates the raw tar data using `tar_no_std::TarArchiveRef::entries()` directly (same as launcher), not via `TarIndex`.

**Step 3: Update central's offset map construction (from Task 3)**

Ensure it uses the same iteration method as the launcher.

**Step 4: Build and test**

```bash
cargo build --release -p litebox_central
cargo build -p litebox
cargo nextest run -p litebox
```

**Step 5: Commit**

```bash
git add litebox/src/fs/tar_ro.rs
git commit -m "feat(tar_ro): add ordered iteration for deterministic offset map"
```

---

### Task 7: Full integration test and benchmarks

Run the full UnixBench suite and verify correctness + performance.

**Files:** None (testing only)

**Step 1: Build everything**

```bash
cargo build --release -p litebox_central
cargo build --release -p litebox_micro -p litebox_launcher
```

**Step 2: Clippy everything**

```bash
cargo clippy -p litebox -p litebox_shim_linux -p litebox_micro -p litebox_launcher
cargo clippy -p litebox_central
```

**Step 3: Run unit tests**

```bash
cargo nextest run -p litebox_launcher
cargo nextest run -p litebox_ipc
cargo nextest run -p litebox
```

**Step 4: Run execl benchmark (primary target)**

```bash
pkill -9 litebox_central; pkill -9 litebox; pkill -9 litebox_launcher
sudo sh -c 'sync; echo 3 > /proc/sys/vm/drop_caches'
sudo -E python3 dev_bench/unixbench/run_unixbench.py \
  --mode micro --release --no-build --duration 10 --iterations 1 --benchmarks execl
```

Compare with baseline (~1,576 lps). Expected improvement: 2-5x.

**Step 5: Run native comparison**

```bash
sudo sh -c 'sync; echo 3 > /proc/sys/vm/drop_caches'
sudo -E python3 dev_bench/unixbench/run_unixbench.py \
  --mode native --release --no-build --duration 10 --iterations 1 --benchmarks execl
```

**Step 6: Run full UnixBench suite**

```bash
pkill -9 litebox_central; pkill -9 litebox; pkill -9 litebox_launcher
sudo sh -c 'sync; echo 3 > /proc/sys/vm/drop_caches'
sudo -E python3 dev_bench/unixbench/run_unixbench.py \
  --mode micro --release --no-build --duration 10 --iterations 1
```

Verify: all benchmarks pass, no regressions on CPU-bound benchmarks.

**Step 7: Record results and commit any final adjustments**

---

## Task Dependency Graph

```
Task 1 (AlignedDataRegion) ──┐
                              ├── Task 2 (Wire through launcher) ──┐
                              │                                     │
Task 6 (Ordered iteration) ──┤                                     │
                              │                                     │
                              ├── Task 3 (Central offset map) ─── Task 4 (Central exec aligned offsets)
                              │                                     │
                              └─────────────────────────────────── Task 5 (Micro mmap exec) ──┐
                                                                                               │
                                                                    Task 7 (Integration test) ◄┘
```

**Critical path:** Tasks 1 → 2 → 3 → 4 → 5 → 7
**Parallel track:** Task 6 can proceed in parallel with Tasks 1-2 (needed by Task 3)
