// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared memory region for the launcher's ring buffer IPC.
//!
//! Unlike `litebox_central`'s `SharedRegion`, this version intentionally omits
//! `MFD_CLOEXEC` so that the file descriptor is inherited by forked child
//! processes (central). It also exposes the raw fd number for passing to
//! central and micro.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::ptr::NonNull;

use anyhow::bail;
use litebox_ipc::ring::SharedRingLayout;

/// An owned, memory-mapped shared memory region for the launcher.
///
/// The memfd is created **without** `MFD_CLOEXEC` so that it remains
/// inheritable across `fork`/`exec` to the central child process.
///
/// # Safety
///
/// `LauncherSharedRegion` owns both the file descriptor and the mapping. It is
/// `Send` but deliberately not `Sync` — a single owner should manage the
/// region.
pub struct LauncherSharedRegion {
    fd: OwnedFd,
    ptr: NonNull<u8>,
    layout: SharedRingLayout,
}

// SAFETY: The raw pointer is derived from an owned mmap region. Only one
// `LauncherSharedRegion` instance owns the mapping, so moving it to another
// thread is safe. We intentionally do NOT implement `Sync`.
unsafe impl Send for LauncherSharedRegion {}

impl LauncherSharedRegion {
    /// Create a new shared memory region with the default layout.
    ///
    /// The memfd is created **without** `MFD_CLOEXEC` so that the fd is
    /// inherited by forked child processes.
    ///
    /// # Errors
    ///
    /// Returns an error if `memfd_create`, `ftruncate`, or `mmap` fails.
    pub fn new() -> anyhow::Result<Self> {
        let layout = SharedRingLayout::default_layout();
        let name = c"litebox-ring";

        // SAFETY: `memfd_create` creates an anonymous file backed by memory.
        // The name is a valid C string. We pass 0 for flags (no MFD_CLOEXEC)
        // so the fd is inheritable by child processes.
        let raw_fd = unsafe { libc::memfd_create(name.as_ptr(), 0) };
        if raw_fd < 0 {
            return Err(anyhow::anyhow!(
                "memfd_create failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // SAFETY: `raw_fd` is a valid, newly created file descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        let total_size = layout.total_size;

        // SAFETY: `ftruncate` sets the size of the memfd. The fd is valid and
        // we own it exclusively at this point.
        let ret = unsafe {
            libc::ftruncate(
                fd.as_raw_fd(),
                i64::try_from(total_size).expect("total_size fits in i64"),
            )
        };
        if ret != 0 {
            return Err(anyhow::anyhow!(
                "ftruncate failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // SAFETY: We map the entire region as shared, read-write. The fd is
        // valid and has been sized to `total_size`. `MAP_SHARED` ensures
        // changes are visible to other mappings of the same fd.
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

        // SAFETY: `mmap` succeeded, so `ptr` is non-null and points to
        // `total_size` bytes of mapped memory. We zero-initialize the entire
        // region to ensure all atomic fields start at zero.
        unsafe {
            std::ptr::write_bytes(ptr.cast::<u8>(), 0, total_size);
        }

        let non_null = NonNull::new(ptr.cast::<u8>()).expect("mmap succeeded but returned null");

        Ok(Self {
            fd,
            ptr: non_null,
            layout,
        })
    }

    /// Returns the raw file descriptor number for passing to central/micro.
    pub fn fd_raw(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    /// Returns a pointer to the raw mapped region.
    pub fn base_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    /// Returns the layout describing this region's offsets and sizes.
    pub fn layout(&self) -> &SharedRingLayout {
        &self.layout
    }
}

impl Drop for LauncherSharedRegion {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` was obtained from a successful `mmap` call with
        // size `self.layout.total_size`. We unmap the entire region. After
        // this, the pointer is invalid — but since we're in `drop`, no further
        // access is possible.
        unsafe {
            let ret = libc::munmap(self.ptr.as_ptr().cast(), self.layout.total_size);
            debug_assert_eq!(ret, 0, "munmap failed during drop");
        }
    }
}

/// An owned, memory-mapped shared memory region holding a tar archive.
///
/// The tar data is loaded into a memfd **without** `MFD_CLOEXEC` so that the
/// file descriptor is inheritable across `fork`/`exec`. After the initial
/// write the mapping is downgraded to read-only via `mprotect`.
///
/// # Safety
///
/// `TarSharedRegion` owns both the file descriptor and the mapping. It is
/// `Send` but deliberately not `Sync`.
pub struct TarSharedRegion {
    fd: OwnedFd,
    ptr: NonNull<u8>,
    size: usize,
}

// SAFETY: The raw pointer is derived from an owned mmap region. Only one
// `TarSharedRegion` instance owns the mapping, so moving it to another
// thread is safe. We intentionally do NOT implement `Sync`.
unsafe impl Send for TarSharedRegion {}

impl TarSharedRegion {
    /// Create a `TarSharedRegion` by reading a tar file from disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or shared-memory setup fails.
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let data = std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("failed to read tar file '{path}': {e}"))?;
        Self::from_bytes(&data)
    }

    /// Create a `TarSharedRegion` from an in-memory byte slice.
    ///
    /// The data is copied into a memfd (no `MFD_CLOEXEC`), mapped read-write
    /// for the initial copy, then downgraded to read-only via `mprotect`.
    ///
    /// # Errors
    ///
    /// Returns an error if `data` is empty or any syscall fails.
    pub fn from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        if data.is_empty() {
            bail!("cannot create TarSharedRegion from empty data");
        }

        let name = c"litebox-tar";

        // SAFETY: `memfd_create` creates an anonymous file backed by memory.
        // The name is a valid C string. We pass 0 for flags (no MFD_CLOEXEC)
        // so the fd is inheritable by child processes.
        let raw_fd = unsafe { libc::memfd_create(name.as_ptr(), 0) };
        if raw_fd < 0 {
            return Err(anyhow::anyhow!(
                "memfd_create failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // SAFETY: `raw_fd` is a valid, newly created file descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        let size = data.len();

        // SAFETY: `ftruncate` sets the size of the memfd. The fd is valid and
        // we own it exclusively at this point.
        let ret = unsafe {
            libc::ftruncate(
                fd.as_raw_fd(),
                i64::try_from(size).expect("size fits in i64"),
            )
        };
        if ret != 0 {
            return Err(anyhow::anyhow!(
                "ftruncate failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // SAFETY: We map the entire region as shared, read-write for the
        // initial copy. The fd is valid and has been sized to `size`.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
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

        // SAFETY: `mmap` succeeded, so `ptr` is non-null and points to `size`
        // bytes of mapped memory. We copy the tar data into the region.
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), ptr.cast::<u8>(), size);
        }

        // SAFETY: Downgrade the mapping to read-only now that the data has
        // been written. `ptr` is page-aligned (from mmap) and `size` covers
        // the entire mapping.
        let ret = unsafe { libc::mprotect(ptr, size, libc::PROT_READ) };
        if ret != 0 {
            // Clean up the mapping before returning the error.
            unsafe {
                libc::munmap(ptr, size);
            }
            return Err(anyhow::anyhow!(
                "mprotect failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        let non_null = NonNull::new(ptr.cast::<u8>()).expect("mmap succeeded but returned null");

        Ok(Self {
            fd,
            ptr: non_null,
            size,
        })
    }

    /// Returns the raw file descriptor number for passing to child processes.
    pub fn fd_raw(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    /// Returns a pointer to the start of the mapped tar data (read-only).
    pub fn base_ptr(&self) -> *const u8 {
        self.ptr.as_ptr()
    }

    /// Returns the size of the tar data in bytes.
    pub fn size(&self) -> usize {
        self.size
    }
}

impl Drop for TarSharedRegion {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` was obtained from a successful `mmap` call with
        // size `self.size`. We unmap the entire region. After this, the pointer
        // is invalid — but since we're in `drop`, no further access is possible.
        unsafe {
            let ret = libc::munmap(self.ptr.as_ptr().cast(), self.size);
            debug_assert_eq!(ret, 0, "munmap failed during drop");
        }
    }
}

/// An owned, memory-mapped shared memory region for the in-memory filesystem
/// upper layer.
///
/// The memfd is created **without** `MFD_CLOEXEC` so that it remains
/// inheritable across `fork`/`exec` to the central child process. The region
/// is initialized with a [`litebox_ipc::inmem_shmem::RegionHeader`] at offset
/// 0 and zero-filled slot + data areas.
///
/// # Safety
///
/// `InMemSharedRegion` owns both the file descriptor and the mapping. It is
/// `Send` but deliberately not `Sync`.
pub struct InMemSharedRegion {
    fd: OwnedFd,
    ptr: NonNull<u8>,
    size: usize,
}

// SAFETY: The raw pointer is derived from an owned mmap region. Only one
// `InMemSharedRegion` instance owns the mapping, so moving it to another
// thread is safe. We intentionally do NOT implement `Sync`.
unsafe impl Send for InMemSharedRegion {}

impl InMemSharedRegion {
    /// Create a new in-memory filesystem shmem region of the given `size`.
    ///
    /// The region is zero-initialized and a [`litebox_ipc::inmem_shmem::RegionHeader`]
    /// is written at offset 0. The memfd is created **without** `MFD_CLOEXEC`
    /// so the fd survives `fork`/`exec`.
    ///
    /// # Errors
    ///
    /// Returns an error if `memfd_create`, `ftruncate`, or `mmap` fails, or
    /// if the region is too small for the header and slot array.
    pub fn new(size: usize) -> anyhow::Result<Self> {
        use litebox_ipc::inmem_shmem::{
            self, DEFAULT_MAX_SLOTS, INMEM_MAGIC, INMEM_VERSION, RegionHeader,
        };

        let dro = inmem_shmem::data_region_offset(DEFAULT_MAX_SLOTS);
        if size < dro {
            return Err(anyhow::anyhow!(
                "inmem region size ({size}) is smaller than minimum ({dro})"
            ));
        }

        let name = c"litebox-inmem";

        // SAFETY: `memfd_create` creates an anonymous file backed by memory.
        // The name is a valid C string. We pass 0 for flags (no MFD_CLOEXEC)
        // so the fd is inheritable by child processes.
        let raw_fd = unsafe { libc::memfd_create(name.as_ptr(), 0) };
        if raw_fd < 0 {
            return Err(anyhow::anyhow!(
                "memfd_create failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // SAFETY: `raw_fd` is a valid, newly created file descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        // SAFETY: `ftruncate` sets the size of the memfd. The fd is valid and
        // we own it exclusively at this point.
        let ret = unsafe {
            libc::ftruncate(
                fd.as_raw_fd(),
                i64::try_from(size).expect("size fits in i64"),
            )
        };
        if ret != 0 {
            return Err(anyhow::anyhow!(
                "ftruncate failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // SAFETY: We map the entire region as shared, read-write. The fd is
        // valid and has been sized to `size`. `MAP_SHARED` ensures changes
        // are visible to other mappings of the same fd.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
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

        // SAFETY: `mmap` succeeded, so `ptr` is non-null and points to
        // `size` bytes of mapped memory. We zero-initialize the entire
        // region.
        unsafe {
            std::ptr::write_bytes(ptr.cast::<u8>(), 0, size);
        }

        // Write the region header at offset 0.
        let header = RegionHeader {
            magic: INMEM_MAGIC,
            version: INMEM_VERSION,
            max_slots: DEFAULT_MAX_SLOTS,
            _pad0: 0,
            data_region_offset: dro as u64,
            data_region_size: (size - dro) as u64,
            _reserved: [0; 32],
        };

        // SAFETY: `ptr` points to a valid, writable mapping of at least
        // `REGION_HEADER_SIZE` bytes. We write the header struct at the
        // start of the region.
        unsafe {
            std::ptr::write(ptr.cast::<RegionHeader>(), header);
        }

        // Downgrade the launcher/micro mapping to read-only.  Central runs
        // in a separate process and creates its own PROT_READ|PROT_WRITE
        // mapping of the same memfd, so it can still write.  This ensures
        // that guest code running in micro cannot corrupt the inmem region
        // at the hardware/MMU level.
        //
        // SAFETY: `ptr` is page-aligned (from mmap) and `size` covers the
        // entire mapping.
        let ret = unsafe { libc::mprotect(ptr, size, libc::PROT_READ) };
        if ret != 0 {
            unsafe {
                libc::munmap(ptr, size);
            }
            return Err(anyhow::anyhow!(
                "mprotect failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        let non_null = NonNull::new(ptr.cast::<u8>()).expect("mmap succeeded but returned null");

        Ok(Self {
            fd,
            ptr: non_null,
            size,
        })
    }

    /// Returns the raw file descriptor number for passing to central/micro.
    pub fn fd_raw(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    /// Returns a pointer to the raw mapped region (read-only after
    /// construction; the underlying pages are `PROT_READ`).
    pub fn base_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    /// Returns the total size of the region in bytes.
    pub fn size(&self) -> usize {
        self.size
    }
}

impl Drop for InMemSharedRegion {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` was obtained from a successful `mmap` call with
        // size `self.size`. We unmap the entire region. After this, the pointer
        // is invalid — but since we're in `drop`, no further access is possible.
        unsafe {
            let ret = libc::munmap(self.ptr.as_ptr().cast(), self.size);
            debug_assert_eq!(ret, 0, "munmap failed during drop");
        }
    }
}

const PAGE_SIZE: usize = 4096;

/// Compute page-aligned offsets for each file in a tar archive.
///
/// Returns a vector of `(filename, aligned_offset, file_size)` tuples using
/// the deterministic alignment algorithm. Files with zero-length data are
/// skipped.
///
/// This function is intentionally duplicated from `litebox_central` so that
/// both sides can reconstruct the offset map independently from the same tar.
pub fn compute_aligned_offsets(tar_data: &[u8]) -> Vec<(String, usize, usize)> {
    let archive = tar_no_std::TarArchiveRef::new(tar_data)
        .expect("invalid tar data in compute_aligned_offsets");
    let mut result = Vec::new();
    let mut offset: usize = 0;

    for entry in archive.entries() {
        let filename = entry.filename();
        let Ok(name) = filename.as_str() else {
            continue;
        };
        let data = entry.data();
        if data.is_empty() {
            continue;
        }

        // Page-align the offset (first file starts at 0, which is already aligned).
        offset = (offset + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        result.push((name.to_string(), offset, data.len()));
        offset += data.len();
    }

    result
}

/// An owned, memory-mapped shared memory region holding file data at
/// page-aligned offsets.
///
/// Each file from a tar archive is placed at a page-aligned offset within
/// a memfd, enabling `mmap`-based ELF segment loading during exec. The memfd
/// is created **without** `MFD_CLOEXEC` so that the file descriptor is
/// inheritable across `fork`/`exec`.
///
/// # Safety
///
/// `AlignedDataRegion` owns both the file descriptor and the mapping. It is
/// `Send` but deliberately not `Sync`.
pub struct AlignedDataRegion {
    fd: OwnedFd,
    ptr: NonNull<u8>,
    size: usize,
}

// SAFETY: The raw pointer is derived from an owned mmap region. Only one
// `AlignedDataRegion` instance owns the mapping, so moving it to another
// thread is safe. We intentionally do NOT implement `Sync`.
unsafe impl Send for AlignedDataRegion {}

impl AlignedDataRegion {
    /// Create an `AlignedDataRegion` from raw tar bytes.
    ///
    /// Parses the tar, computes page-aligned offsets for each file, creates a
    /// memfd, and copies each file's data to its aligned offset. The mapping
    /// is downgraded to read-only after the data is written.
    ///
    /// # Errors
    ///
    /// Returns an error if the tar contains no files with data, or if any
    /// syscall fails.
    pub fn from_tar_bytes(tar_data: &[u8]) -> anyhow::Result<Self> {
        // Phase 1: Parse tar and compute page-aligned offsets.
        let entries = compute_aligned_offsets(tar_data);
        if entries.is_empty() {
            bail!("cannot create AlignedDataRegion: tar contains no files with data");
        }

        // Compute total size (round up to page boundary).
        let last = entries.last().unwrap();
        let raw_end = last.1 + last.2;
        let total_size = (raw_end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

        // We also need to collect the actual data bytes for Phase 2.
        let archive = tar_no_std::TarArchiveRef::new(tar_data)
            .map_err(|e| anyhow::anyhow!("invalid tar data: {e:?}"))?;
        let mut file_data: Vec<(&[u8], usize)> = Vec::new();
        let mut entry_idx = 0;

        for entry in archive.entries() {
            let filename = entry.filename();
            let Ok(_name) = filename.as_str() else {
                continue;
            };
            let data = entry.data();
            if data.is_empty() {
                continue;
            }

            if entry_idx < entries.len() {
                file_data.push((data, entries[entry_idx].1));
                entry_idx += 1;
            }
        }

        // Phase 2: Create memfd, ftruncate, mmap, copy data, mprotect.
        let name = c"litebox-aligned-data";

        // SAFETY: `memfd_create` creates an anonymous file backed by memory.
        // The name is a valid C string. We pass 0 for flags (no MFD_CLOEXEC)
        // so the fd is inheritable by child processes.
        let raw_fd = unsafe { libc::memfd_create(name.as_ptr(), 0) };
        if raw_fd < 0 {
            return Err(anyhow::anyhow!(
                "memfd_create failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // SAFETY: `raw_fd` is a valid, newly created file descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        // SAFETY: `ftruncate` sets the size of the memfd. The fd is valid and
        // we own it exclusively at this point.
        let ret = unsafe {
            libc::ftruncate(
                fd.as_raw_fd(),
                i64::try_from(total_size).expect("total_size fits in i64"),
            )
        };
        if ret != 0 {
            return Err(anyhow::anyhow!(
                "ftruncate failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // SAFETY: We map the entire region as shared, read-write for the
        // initial data copy. The fd is valid and has been sized to `total_size`.
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

        // Copy each file's data to its page-aligned offset.
        for (data, offset) in &file_data {
            // SAFETY: `ptr` points to a valid mapping of `total_size` bytes.
            // Each `offset + data.len()` is within `total_size` (guaranteed by
            // the alignment algorithm).
            unsafe {
                let dst = ptr.cast::<u8>().add(*offset);
                std::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len());
            }
        }

        // SAFETY: Downgrade the mapping to read-only now that the data has
        // been written. `ptr` is page-aligned (from mmap) and `total_size`
        // covers the entire mapping.
        let ret = unsafe { libc::mprotect(ptr, total_size, libc::PROT_READ) };
        if ret != 0 {
            // Clean up the mapping before returning the error.
            unsafe {
                libc::munmap(ptr, total_size);
            }
            return Err(anyhow::anyhow!(
                "mprotect failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        let non_null = NonNull::new(ptr.cast::<u8>()).expect("mmap succeeded but returned null");

        Ok(Self {
            fd,
            ptr: non_null,
            size: total_size,
        })
    }

    /// Returns the raw file descriptor number for passing to child processes.
    pub fn fd_raw(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    /// Returns a pointer to the start of the mapped region (read-only).
    pub fn base_ptr(&self) -> *const u8 {
        self.ptr.as_ptr()
    }

    /// Returns the total size of the mapped region in bytes.
    pub fn size(&self) -> usize {
        self.size
    }
}

impl Drop for AlignedDataRegion {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` was obtained from a successful `mmap` call with
        // size `self.size`. We unmap the entire region. After this, the pointer
        // is invalid — but since we're in `drop`, no further access is possible.
        unsafe {
            let ret = libc::munmap(self.ptr.as_ptr().cast(), self.size);
            debug_assert_eq!(ret, 0, "munmap failed during drop");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;

    #[test]
    fn create_launcher_shared_region() {
        let region = LauncherSharedRegion::new().expect("failed to create launcher shared region");

        assert!(!region.base_ptr().is_null());
        assert!(region.layout().total_size > 0);
        assert!(region.fd_raw() >= 0);
    }

    #[test]
    fn header_is_zeroed() {
        let region = LauncherSharedRegion::new().expect("failed to create launcher shared region");

        // SAFETY: Region was just created and we have exclusive access. The
        // header lives at offset 0, and the mapping is page-aligned which
        // satisfies `RingHeader`'s 64-byte alignment requirement.
        let header = unsafe { &*region.base_ptr().cast::<litebox_ipc::ring::RingHeader>() };

        assert_eq!(header.sq_head.load(Ordering::Relaxed), 0);
        assert_eq!(header.sq_tail.load(Ordering::Relaxed), 0);
        assert_eq!(header.cq_head.load(Ordering::Relaxed), 0);
        assert_eq!(header.cq_tail.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn fd_is_valid_and_inheritable() {
        let region = LauncherSharedRegion::new().expect("failed to create launcher shared region");

        let raw_fd = region.fd_raw();

        // Verify the fd is valid by checking its flags.
        let flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFD) };
        assert!(flags >= 0, "fd should be valid");

        // Verify CLOEXEC is NOT set (fd is inheritable).
        assert_eq!(
            flags & libc::FD_CLOEXEC,
            0,
            "fd should NOT have CLOEXEC set so children inherit it"
        );
    }

    #[test]
    fn create_tar_shared_region() {
        let data = b"fake tar data for testing";
        let region = TarSharedRegion::from_bytes(data).expect("failed to create tar shared region");

        assert!(!region.base_ptr().is_null());
        assert_eq!(region.size(), data.len());
        assert!(region.fd_raw() >= 0);
    }

    #[test]
    fn tar_shmem_data_is_readable() {
        let data = b"hello from tar shmem";
        let region = TarSharedRegion::from_bytes(data).expect("failed to create tar shared region");

        // SAFETY: The mapping is valid and readable for `region.size()` bytes.
        let mapped = unsafe { std::slice::from_raw_parts(region.base_ptr(), region.size()) };
        assert_eq!(mapped, data);
    }

    #[test]
    fn tar_shmem_fd_is_inheritable() {
        let data = b"inheritable check";
        let region = TarSharedRegion::from_bytes(data).expect("failed to create tar shared region");

        let raw_fd = region.fd_raw();

        // Verify the fd is valid by checking its flags.
        let flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFD) };
        assert!(flags >= 0, "fd should be valid");

        // Verify CLOEXEC is NOT set (fd is inheritable).
        assert_eq!(
            flags & libc::FD_CLOEXEC,
            0,
            "fd should NOT have CLOEXEC set so children inherit it"
        );
    }

    #[test]
    fn tar_shmem_visible_from_second_mmap() {
        let data = b"visible across mappings";
        let region = TarSharedRegion::from_bytes(data).expect("failed to create tar shared region");

        // Create a second mapping of the same fd.
        let ptr2 = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                region.size(),
                libc::PROT_READ,
                libc::MAP_SHARED,
                region.fd_raw(),
                0,
            )
        };
        assert_ne!(ptr2, libc::MAP_FAILED, "second mmap should succeed");

        // SAFETY: Both mappings are valid and backed by the same fd.
        let mapped2 = unsafe { std::slice::from_raw_parts(ptr2.cast::<u8>(), region.size()) };
        assert_eq!(mapped2, data);

        // Clean up the second mapping.
        unsafe {
            libc::munmap(ptr2, region.size());
        }
    }

    /// Helper: build a tar archive in memory with the given files.
    fn build_test_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, data) in files {
            let mut header = tar::Header::new_gnu();
            header.set_path(name).unwrap();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, &data[..]).unwrap();
        }
        builder.into_inner().unwrap()
    }

    #[test]
    fn aligned_data_region_from_tar() {
        let file_a = b"Hello, world!";
        let file_b = b"Second file with more data inside it.";
        let tar_data = build_test_tar(&[("a.txt", file_a), ("b.txt", file_b)]);

        let region = AlignedDataRegion::from_tar_bytes(&tar_data)
            .expect("failed to create AlignedDataRegion");

        // Size must be page-aligned.
        assert_eq!(
            region.size() % PAGE_SIZE,
            0,
            "region size should be page-aligned"
        );
        assert!(region.size() > 0);

        // Verify data is at correct offsets using compute_aligned_offsets.
        let offsets = compute_aligned_offsets(&tar_data);
        assert_eq!(offsets.len(), 2);

        for (name, offset, size) in &offsets {
            // SAFETY: The mapping is valid and readable for `region.size()` bytes.
            let mapped =
                unsafe { std::slice::from_raw_parts(region.base_ptr().add(*offset), *size) };
            let expected: &[u8] = if name == "a.txt" { file_a } else { file_b };
            assert_eq!(mapped, expected, "data mismatch for {name}");
        }
    }

    #[test]
    fn aligned_data_page_alignment() {
        let file_a = b"short";
        let file_b = b"another file";
        let file_c = b"third file with longer content that spans more bytes";
        let tar_data = build_test_tar(&[
            ("alpha.bin", file_a),
            ("beta.bin", file_b),
            ("gamma.bin", file_c),
        ]);

        let offsets = compute_aligned_offsets(&tar_data);
        assert_eq!(offsets.len(), 3);

        for (name, offset, _size) in &offsets {
            assert_eq!(
                offset % PAGE_SIZE,
                0,
                "offset for {name} ({offset}) should be a multiple of {PAGE_SIZE}"
            );
        }
    }

    #[test]
    fn aligned_data_fd_inheritable() {
        let tar_data = build_test_tar(&[("test.bin", b"data")]);
        let region = AlignedDataRegion::from_tar_bytes(&tar_data)
            .expect("failed to create AlignedDataRegion");

        let raw_fd = region.fd_raw();

        // Verify the fd is valid by checking its flags.
        let flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFD) };
        assert!(flags >= 0, "fd should be valid");

        // Verify CLOEXEC is NOT set (fd is inheritable).
        assert_eq!(
            flags & libc::FD_CLOEXEC,
            0,
            "fd should NOT have CLOEXEC set so children inherit it"
        );
    }
}
