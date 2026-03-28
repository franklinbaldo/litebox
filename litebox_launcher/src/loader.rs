// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Real-file implementations of the ELF loader traits from
//! `litebox_common_linux::loader`.
//!
//! These are used inside the launcher (guest) process where the mapped memory
//! lives in our own address space, so [`AccessMemory`] can use plain pointer
//! operations.

use litebox_common_linux::loader::{AccessMemory, Fault, MapMemory, Protection, ReadAt};

// Used by loader orchestration in later phases; suppress dead-code warnings
// until the caller code lands.
#[allow(dead_code)]
const PAGE_SIZE: usize = 4096;

// ---------------------------------------------------------------------------
// ReadAt: RealFile
// ---------------------------------------------------------------------------

/// A read-only file descriptor used for ELF loading.
pub struct RealFile {
    fd: i32,
    size: u64,
}

impl RealFile {
    /// Open `path` as read-only with `O_CLOEXEC`.
    ///
    /// # Errors
    ///
    /// Returns the `errno` value (as `i32`) on failure.
    pub fn open(path: &str) -> Result<Self, i32> {
        let c_path = std::ffi::CString::new(path).map_err(|_| libc::EINVAL)?;
        // SAFETY: `c_path` is a valid NUL-terminated C string.
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(unsafe { *libc::__errno_location() });
        }

        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `fd` is a valid open file descriptor.
        let ret = unsafe { libc::fstat(fd, &raw mut stat) };
        if ret != 0 {
            let err = unsafe { *libc::__errno_location() };
            unsafe { libc::close(fd) };
            return Err(err);
        }

        Ok(Self {
            fd,
            size: stat.st_size.cast_unsigned(),
        })
    }
}

impl Drop for RealFile {
    fn drop(&mut self) {
        // SAFETY: `self.fd` was obtained from a successful `open` call.
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// Implement `ReadAt` on `&RealFile` so that callers can pass `&mut &file`
/// to APIs that take `&mut F where F: ReadAt` (e.g. `ElfParsedFile::parse`).
impl ReadAt for &RealFile {
    type Error = i32;

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), Self::Error> {
        let mut total = 0usize;
        while total < buf.len() {
            // SAFETY: `self.fd` is a valid open file descriptor and `buf` is a
            // valid mutable byte slice.
            let n = unsafe {
                libc::pread(
                    self.fd,
                    buf[total..].as_mut_ptr().cast(),
                    buf.len() - total,
                    offset
                        .checked_add(total as u64)
                        .ok_or(libc::EINVAL)?
                        .cast_signed(),
                )
            };
            if n < 0 {
                return Err(unsafe { *libc::__errno_location() });
            }
            if n == 0 {
                // Unexpected EOF — treat as an I/O error.
                return Err(libc::EIO);
            }
            total += n.cast_unsigned();
        }
        Ok(())
    }

    fn size(&mut self) -> Result<u64, Self::Error> {
        Ok(self.size)
    }
}

// ---------------------------------------------------------------------------
// MapMemory: RealMapper
// ---------------------------------------------------------------------------

/// Maps ELF segments into the current process via real `mmap`/`mprotect` calls.
#[allow(dead_code)]
pub struct RealMapper {
    fd: i32,
}

impl RealMapper {
    /// Create a new mapper that will use `fd` for file-backed mappings.
    #[allow(dead_code)]
    pub fn new(fd: i32) -> Self {
        Self { fd }
    }
}

/// Convert [`Protection`] flags to the `libc` `PROT_*` bitmask.
#[allow(dead_code)]
fn prot_to_libc(prot: Protection) -> i32 {
    prot.flags().bits()
}

impl MapMemory for RealMapper {
    type Error = i32;

    fn reserve(&mut self, len: usize, align: usize) -> Result<usize, Self::Error> {
        debug_assert!(align.is_power_of_two(), "align must be a power of two");
        let extra = align.saturating_sub(PAGE_SIZE);
        let total = len.checked_add(extra).ok_or(libc::ENOMEM)?;
        // SAFETY: We request an anonymous, private, inaccessible reservation.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                total,
                libc::PROT_NONE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(unsafe { *libc::__errno_location() });
        }

        let base_addr = base as usize;
        let aligned = (base_addr + align - 1) & !(align - 1);

        // Unmap prefix.
        let prefix = aligned - base_addr;
        if prefix > 0 {
            // SAFETY: The prefix region was part of the successful `mmap` above.
            let ret = unsafe { libc::munmap(base, prefix) };
            debug_assert_eq!(ret, 0, "munmap of prefix failed");
        }

        // Unmap suffix.
        let suffix = total - prefix - len;
        if suffix > 0 {
            // SAFETY: The suffix region was part of the successful `mmap` above.
            let ret = unsafe { libc::munmap((aligned + len) as *mut libc::c_void, suffix) };
            debug_assert_eq!(ret, 0, "munmap of suffix failed");
        }

        Ok(aligned)
    }

    fn map_file(
        &mut self,
        address: usize,
        len: usize,
        offset: u64,
        prot: &Protection,
    ) -> Result<(), Self::Error> {
        // SAFETY: Caller guarantees `address`, `len`, and `offset` are
        // page-aligned. `self.fd` is a valid file descriptor.
        let ret = unsafe {
            libc::mmap(
                address as *mut libc::c_void,
                len,
                prot_to_libc(*prot),
                libc::MAP_PRIVATE | libc::MAP_FIXED,
                self.fd,
                offset.cast_signed(),
            )
        };
        if ret == libc::MAP_FAILED {
            return Err(unsafe { *libc::__errno_location() });
        }
        Ok(())
    }

    fn map_zero(
        &mut self,
        address: usize,
        len: usize,
        prot: &Protection,
    ) -> Result<(), Self::Error> {
        // SAFETY: Caller guarantees `address` and `len` are page-aligned.
        let ret = unsafe {
            libc::mmap(
                address as *mut libc::c_void,
                len,
                prot_to_libc(*prot),
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        if ret == libc::MAP_FAILED {
            return Err(unsafe { *libc::__errno_location() });
        }
        Ok(())
    }

    fn protect(
        &mut self,
        address: usize,
        len: usize,
        prot: &Protection,
    ) -> Result<(), Self::Error> {
        // SAFETY: Caller guarantees `address` and `len` are page-aligned and
        // the region is currently mapped.
        let ret = unsafe { libc::mprotect(address as *mut libc::c_void, len, prot_to_libc(*prot)) };
        if ret != 0 {
            return Err(unsafe { *libc::__errno_location() });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// AccessMemory: RealMemory
// ---------------------------------------------------------------------------

/// Direct in-process memory access (the launcher IS the guest process).
#[allow(dead_code)]
pub struct RealMemory;

impl AccessMemory for RealMemory {
    fn read(&mut self, address: usize, buf: &mut [u8]) -> Result<usize, Fault> {
        // SAFETY: The caller guarantees that the address range is mapped and
        // readable.
        unsafe {
            std::ptr::copy_nonoverlapping(address as *const u8, buf.as_mut_ptr(), buf.len());
        }
        Ok(buf.len())
    }

    fn write(&mut self, address: usize, data: &[u8]) -> Result<(), Fault> {
        // SAFETY: The caller guarantees that the address range is mapped and
        // writable.
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), address as *mut u8, data.len());
        }
        Ok(())
    }

    fn zero(&mut self, address: usize, len: usize) -> Result<(), Fault> {
        // SAFETY: The caller guarantees that the address range is mapped and
        // writable.
        unsafe {
            std::ptr::write_bytes(address as *mut u8, 0, len);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_file_open_proc_self_exe() {
        let file = RealFile::open("/proc/self/exe").expect("should open /proc/self/exe");
        assert!(file.size > 0, "file size should be > 0");
    }

    #[test]
    fn real_file_read_at_elf_magic() {
        let file = RealFile::open("/proc/self/exe").expect("should open /proc/self/exe");
        let mut file_ref = &file;
        let mut buf = [0u8; 4];
        file_ref
            .read_at(0, &mut buf)
            .expect("should read at offset 0");
        assert_eq!(&buf, b"\x7fELF", "first 4 bytes should be ELF magic");
    }

    #[test]
    fn real_mapper_reserve_and_map_zero() {
        let mut mapper = RealMapper::new(-1);

        // Reserve 2 pages.
        let addr = mapper
            .reserve(2 * PAGE_SIZE, PAGE_SIZE)
            .expect("reserve should succeed");
        assert_ne!(addr, 0);
        assert_eq!(addr % PAGE_SIZE, 0, "address should be page-aligned");

        // Map zero-filled writable memory at that address.
        let prot = Protection {
            read: true,
            write: true,
            execute: false,
        };
        mapper
            .map_zero(addr, 2 * PAGE_SIZE, &prot)
            .expect("map_zero should succeed");

        // Write to it and read back via raw pointers.
        let ptr = addr as *mut u8;
        unsafe {
            std::ptr::write(ptr, 0xAB);
            assert_eq!(std::ptr::read(ptr), 0xAB);
        }

        // Clean up.
        unsafe {
            libc::munmap(addr as *mut libc::c_void, 2 * PAGE_SIZE);
        }
    }

    #[test]
    fn real_memory_write_read_zero() {
        // Map a writable page to exercise RealMemory.
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        assert_ne!(addr, libc::MAP_FAILED);
        let addr = addr as usize;

        let mut mem = RealMemory;

        // Write a pattern.
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        mem.write(addr, &data).expect("write should succeed");

        // Read it back.
        let mut buf = [0u8; 4];
        let n = mem.read(addr, &mut buf).expect("read should succeed");
        assert_eq!(n, 4);
        assert_eq!(buf, data);

        // Zero it out.
        mem.zero(addr, 4).expect("zero should succeed");
        mem.read(addr, &mut buf).expect("read should succeed");
        assert_eq!(buf, [0, 0, 0, 0]);

        // Clean up.
        unsafe {
            libc::munmap(addr as *mut libc::c_void, PAGE_SIZE);
        }
    }
}
