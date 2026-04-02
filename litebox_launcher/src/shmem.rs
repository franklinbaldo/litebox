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
#[allow(dead_code)] // Used by launcher orchestration in later phases
pub struct LauncherSharedRegion {
    fd: OwnedFd,
    ptr: NonNull<u8>,
    layout: SharedRingLayout,
}

// SAFETY: The raw pointer is derived from an owned mmap region. Only one
// `LauncherSharedRegion` instance owns the mapping, so moving it to another
// thread is safe. We intentionally do NOT implement `Sync`.
unsafe impl Send for LauncherSharedRegion {}

#[allow(dead_code)] // Methods used by launcher orchestration in later phases
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
}
