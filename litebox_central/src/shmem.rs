// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared memory region for ring buffer IPC.
//!
//! Creates an anonymous shared memory region via `memfd_create`, maps it into
//! the process address space, and provides typed accessors for the ring header,
//! submission queue, completion queue, and data region.

use std::mem::align_of;
use std::os::unix::io::OwnedFd;
use std::ptr::NonNull;
use std::sync::Mutex;

use litebox_ipc::ring::{CqEntry, RING_SIZE, RingHeader, SharedRingLayout, SqEntry};

/// An owned, memory-mapped shared memory region laid out for ring buffer IPC.
///
/// The region is backed by an anonymous `memfd` file descriptor that can be
/// shared with child processes. The mapping is zero-initialized on creation.
///
/// # Safety
///
/// `SharedRegion` owns both the file descriptor and the mapping. It is `Send`
/// but deliberately not `Sync` — a single owner should manage the region and
/// share the fd with exactly one guest process.
#[allow(dead_code)] // fd/as_ptr/data_region will be used by the launcher in Phase B
pub struct SharedRegion {
    /// The anonymous shared memory file descriptor.
    fd: OwnedFd,
    /// Pointer to the start of the mapped region.
    ptr: NonNull<u8>,
    /// Layout describing offsets within the region.
    layout: SharedRingLayout,
}

// SAFETY: The raw pointer is derived from an owned mmap region. Only one
// `SharedRegion` instance owns the mapping, so moving it to another thread is
// safe. We intentionally do NOT implement `Sync`.
unsafe impl Send for SharedRegion {}

#[allow(dead_code)] // fd/as_ptr/data_region will be used by the launcher
impl SharedRegion {
    /// Create a new shared memory region with the default layout.
    ///
    /// # Errors
    ///
    /// Returns an error if `memfd_create`, `ftruncate`, or `mmap` fails.
    pub fn new() -> anyhow::Result<Self> {
        Self::with_layout(SharedRingLayout::default_layout())
    }

    /// Create a new shared memory region with the given layout.
    ///
    /// # Errors
    ///
    /// Returns an error if `memfd_create`, `ftruncate`, or `mmap` fails.
    pub fn with_layout(layout: SharedRingLayout) -> anyhow::Result<Self> {
        use std::os::unix::io::FromRawFd;

        let name = c"litebox-ring";

        // SAFETY: `memfd_create` creates an anonymous file backed by memory.
        // The name is a valid C string. We take ownership of the returned fd.
        let raw_fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
        if raw_fd < 0 {
            return Err(anyhow::anyhow!(
                "memfd_create failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // SAFETY: `raw_fd` is a valid, newly created file descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        Self::from_fd(fd, layout)
    }

    /// Create a new shared memory region for a child process after fork.
    ///
    /// The memfd is created **without** `MFD_CLOEXEC` so that the fd remains
    /// accessible via `/proc/<pid>/fd/<N>` from the micro process.
    ///
    /// Returns `(region, raw_fd)` where `raw_fd` is the fd number in this
    /// process's fd table that micro will use to construct the `/proc` path.
    ///
    /// # Errors
    ///
    /// Returns an error if `memfd_create`, `ftruncate`, or `mmap` fails.
    pub fn create_child_ring() -> anyhow::Result<(Self, i32)> {
        use std::os::fd::AsRawFd;
        use std::os::unix::io::FromRawFd;

        let name = c"litebox-child-ring";
        // Note: NO MFD_CLOEXEC — fd must be accessible from micro via /proc.
        let raw_fd = unsafe { libc::memfd_create(name.as_ptr(), 0) };
        if raw_fd < 0 {
            return Err(anyhow::anyhow!(
                "memfd_create failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        let layout = SharedRingLayout::default_layout();
        let region = Self::from_fd(fd, layout)?;
        let result_fd = region.fd().as_raw_fd();
        Ok((region, result_fd))
    }

    /// Initialize a shared memory region from an existing file descriptor.
    ///
    /// Sets the fd to the required size, maps it, and zero-initializes the
    /// region.
    ///
    /// # Errors
    ///
    /// Returns an error if `ftruncate` or `mmap` fails.
    pub fn from_fd(fd: OwnedFd, layout: SharedRingLayout) -> anyhow::Result<Self> {
        use std::os::unix::io::AsRawFd;

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

        // Note: No explicit zero-initialization needed. The memfd was just
        // created (empty) and ftruncated to `total_size`, so the kernel
        // guarantees that all mapped pages are zero-filled. This avoids
        // touching every page eagerly, which would cause ~2048 page faults
        // and has been observed to hang under heavy fork workloads.

        let non_null = NonNull::new(ptr.cast::<u8>()).expect("mmap succeeded but returned null");

        Ok(Self {
            fd,
            ptr: non_null,
            layout,
        })
    }

    /// Returns a reference to the underlying file descriptor.
    pub fn fd(&self) -> &OwnedFd {
        &self.fd
    }

    /// Returns the layout describing this region's offsets and sizes.
    pub fn layout(&self) -> &SharedRingLayout {
        &self.layout
    }

    /// Returns a pointer to the raw mapped region.
    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    /// Returns a reference to the [`RingHeader`] at the start of the region.
    ///
    /// # Safety
    ///
    /// The caller must ensure no mutable references to the header exist
    /// simultaneously, and that the region has not been unmapped.
    #[allow(clippy::cast_ptr_alignment)] // alignment verified by debug_assert
    pub fn header(&self) -> &RingHeader {
        // SAFETY: The header lives at offset 0 of the mapped region. The
        // region is at least `total_size` bytes (which is >= size_of::<RingHeader>()).
        // The mapping is page-aligned, satisfying RingHeader's 64-byte alignment.
        // The region was zero-initialized, so all fields are valid.
        unsafe {
            let ptr = self.ptr.as_ptr();
            debug_assert_eq!(ptr as usize % align_of::<RingHeader>(), 0);
            &*ptr.cast::<RingHeader>()
        }
    }

    /// Returns the submission queue entries as a slice.
    ///
    /// # Safety
    ///
    /// The caller must ensure no mutable references to these entries exist
    /// simultaneously.
    #[allow(clippy::cast_ptr_alignment)] // alignment verified by debug_assert
    pub fn sq_entries(&self) -> &[SqEntry] {
        // SAFETY: SQ entries start at `sq_entries_offset`, which is 64-byte
        // aligned (matching SqEntry's alignment). The layout guarantees
        // RING_SIZE entries fit before the CQ region begins. The region is
        // zero-initialized.
        unsafe {
            let base = self.ptr.as_ptr().add(self.layout.sq_entries_offset);
            debug_assert_eq!(base as usize % align_of::<SqEntry>(), 0);
            std::slice::from_raw_parts(base.cast::<SqEntry>(), RING_SIZE)
        }
    }

    /// Returns the completion queue entries as a slice.
    ///
    /// # Safety
    ///
    /// The caller must ensure no mutable references to these entries exist
    /// simultaneously.
    #[allow(clippy::cast_ptr_alignment)] // alignment verified by debug_assert
    pub fn cq_entries(&self) -> &[CqEntry] {
        // SAFETY: CQ entries start at `cq_entries_offset`, which follows the
        // SQ entries. CqEntry requires no special alignment beyond its 32-byte
        // size. The layout guarantees RING_SIZE entries fit before the data
        // region. The region is zero-initialized.
        unsafe {
            let base = self.ptr.as_ptr().add(self.layout.cq_entries_offset);
            debug_assert_eq!(base as usize % align_of::<CqEntry>(), 0);
            std::slice::from_raw_parts(base.cast::<CqEntry>(), RING_SIZE)
        }
    }

    /// Returns the data region as a byte slice.
    pub fn data_region(&self) -> &[u8] {
        // SAFETY: The data region starts at `data_region_offset` and extends
        // for `data_region_size` bytes, all within the mapped region. The
        // region is zero-initialized.
        unsafe {
            let base = self.ptr.as_ptr().add(self.layout.data_region_offset);
            std::slice::from_raw_parts(base, self.layout.data_region_size)
        }
    }

    /// Returns the data region as a mutable byte slice.
    ///
    /// # Safety
    ///
    /// The caller must ensure no other references to the data region exist
    /// simultaneously. In practice, the server is single-threaded and only
    /// accesses the data region during syscall handling (between CQ writes).
    #[allow(clippy::mut_from_ref)] // shared-memory region with single-threaded access
    pub fn data_region_mut(&self) -> &mut [u8] {
        unsafe {
            let base = self.ptr.as_ptr().add(self.layout.data_region_offset);
            std::slice::from_raw_parts_mut(base, self.layout.data_region_size)
        }
    }
}

/// Pre-allocated pool of shared memory rings for child processes.
///
/// Rings are created eagerly at startup and recycled when child servers exit.
/// If the pool is empty, `acquire()` falls back to fresh allocation.
/// Thread-safe: the main server thread acquires, child server threads release.
pub struct RingPool {
    rings: Mutex<Vec<(SharedRegion, i32)>>,
}

impl RingPool {
    /// Create a new pool, eagerly pre-allocating `initial_count` rings.
    pub fn new(initial_count: usize) -> Self {
        let mut rings = Vec::with_capacity(initial_count);
        for _ in 0..initial_count {
            match SharedRegion::create_child_ring() {
                Ok(entry) => rings.push(entry),
                Err(e) => {
                    eprintln!("ring pool: failed to pre-allocate ring: {e}");
                    break;
                }
            }
        }
        Self {
            rings: Mutex::new(rings),
        }
    }

    /// Take a ring from the pool, or allocate a fresh one if empty.
    pub fn acquire(&self) -> anyhow::Result<(SharedRegion, i32)> {
        if let Some(entry) = self.rings.lock().unwrap().pop() {
            Ok(entry)
        } else {
            SharedRegion::create_child_ring()
        }
    }

    /// Return a ring to the pool after resetting its header and SQ flags.
    pub fn release(&self, region: SharedRegion, fd: i32) {
        use std::sync::atomic::Ordering::Relaxed;

        // Reset ring header to initial state
        let header = region.header();
        header.sq_head.store(0, Relaxed);
        header.sq_tail.store(0, Relaxed);
        header.sq_notify.store(0, Relaxed);
        header.is_exiting.store(0, Relaxed);
        header.cq_head.store(0, Relaxed);
        header.cq_tail.store(0, Relaxed);
        for slot in &header.cq_notify_slots {
            slot.store(0, Relaxed);
        }
        // Reset all SQ entry ready flags
        let sq = region.sq_entries();
        for entry in sq {
            entry.ready.store(0, Relaxed);
        }
        self.rings.lock().unwrap().push((region, fd));
    }
}

impl Drop for SharedRegion {
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;

    #[test]
    fn create_shared_region() {
        let region = SharedRegion::new().expect("failed to create shared region");

        assert!(!region.as_ptr().is_null());
        assert!(region.layout().total_size > 0);
    }

    #[test]
    fn shared_region_header_is_zeroed() {
        let region = SharedRegion::new().expect("failed to create shared region");
        let header = region.header();

        assert_eq!(header.sq_head.load(Ordering::Relaxed), 0);
        assert_eq!(header.sq_tail.load(Ordering::Relaxed), 0);
        assert_eq!(header.cq_head.load(Ordering::Relaxed), 0);
        assert_eq!(header.cq_tail.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn data_region_mut_is_writable() {
        let region = SharedRegion::new().expect("failed to create shared region");
        let data = region.data_region_mut();
        assert!(!data.is_empty());
        data[0] = 0xAB;
        assert_eq!(region.data_region()[0], 0xAB);
    }
}
