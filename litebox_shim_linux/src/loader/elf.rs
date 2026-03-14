// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! ELF loader for LiteBox

use alloc::{ffi::CString, vec::Vec};
use litebox::{
    fs::{Mode, OFlags},
    mm::linux::{CreatePagesFlags, MappingError, PAGE_SIZE},
    platform::{RawConstPointer as _, SystemInfoProvider as _},
    utils::{ReinterpretSignedExt, TruncateExt},
};
use litebox_common_linux::{errno::Errno, loader::ElfParsedFile, MapFlags};
use thiserror::Error;

use crate::{
    loader::auxv::{AuxKey, AuxVec},
    MutPtr,
};

use super::stack::UserStack;
use crate::{ShimFS, Task};

// An opened elf file
struct ElfFile<'a, FS: ShimFS> {
    task: &'a Task<FS>,
    fd: i32,
    /// Hint address passed to mmap when reserving address space for the ELF.
    /// Defaults to `DEFAULT_LOW_ADDR`. Can be raised to avoid placing the
    /// interpreter in the brk growth region of the main binary.
    mmap_hint: usize,
}

impl<'a, FS: ShimFS> ElfFile<'a, FS> {
    fn new(task: &'a Task<FS>, path: impl litebox::path::Arg) -> Result<Self, Errno> {
        let fd = task
            .sys_open(path, OFlags::RDONLY, Mode::empty())?
            .reinterpret_as_signed();
        Ok(ElfFile {
            task,
            fd,
            mmap_hint: super::DEFAULT_LOW_ADDR,
        })
    }
}

impl<FS: ShimFS> Drop for ElfFile<'_, FS> {
    fn drop(&mut self) {
        self.task.sys_close(self.fd).expect("failed to close fd");
    }
}

impl<FS: ShimFS> litebox_common_linux::loader::ReadAt for &'_ ElfFile<'_, FS> {
    type Error = Errno;

    fn read_at(&mut self, mut offset: u64, mut buf: &mut [u8]) -> Result<(), Self::Error> {
        loop {
            if buf.is_empty() {
                return Ok(());
            }
            // Try to read the remaining bytes
            let bytes_read = self.task.sys_read(self.fd, buf, Some(offset.truncate()))?;
            if bytes_read == 0 {
                // reached the end of the file
                return Err(Errno::ENODATA);
            } else {
                // Successfully read some bytes
                buf = &mut buf[bytes_read..];
                offset += bytes_read as u64;
            }
        }
    }

    fn size(&mut self) -> Result<u64, Self::Error> {
        Ok(u64::try_from(self.task.sys_fstat(self.fd)?.st_size)
            .expect("file size must be non-negative"))
    }
}

impl<FS: ShimFS> litebox_common_linux::loader::MapMemory for ElfFile<'_, FS> {
    type Error = Errno;

    fn reserve(&mut self, len: usize, align: usize) -> Result<usize, Self::Error> {
        // Allocate a mapping large enough that even if it's maximally misaligned we can
        // still fit `len` bytes.
        let mapping_len = len + (align.max(PAGE_SIZE) - PAGE_SIZE);
        let mapping_ptr = self
            .task
            .sys_mmap(
                self.mmap_hint,
                mapping_len,
                litebox_common_linux::ProtFlags::PROT_NONE,
                litebox_common_linux::MapFlags::MAP_ANONYMOUS
                    | litebox_common_linux::MapFlags::MAP_PRIVATE,
                -1,
                0,
            )?
            .as_usize();

        let ptr = mapping_ptr.next_multiple_of(align);
        let end = ptr + len;
        let mapping_end = mapping_ptr + mapping_len;
        if ptr != mapping_ptr {
            self.task
                .sys_munmap(MutPtr::from_usize(mapping_ptr), ptr - mapping_ptr)?;
        }
        if end != mapping_end {
            self.task
                .sys_munmap(MutPtr::from_usize(end), mapping_end - end)?;
        }
        Ok(ptr)
    }

    fn map_file(
        &mut self,
        address: usize,
        len: usize,
        offset: u64,
        prot: &litebox_common_linux::loader::Protection,
    ) -> Result<(), Self::Error> {
        self.task.sys_mmap(
            address,
            len,
            prot.flags(),
            MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
            self.fd,
            offset.truncate(),
        )?;
        Ok(())
    }

    fn map_zero(
        &mut self,
        address: usize,
        len: usize,
        prot: &litebox_common_linux::loader::Protection,
    ) -> Result<(), Self::Error> {
        self.task.sys_mmap(
            address,
            len,
            prot.flags(),
            MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
            -1,
            0,
        )?;
        Ok(())
    }

    fn protect(
        &mut self,
        address: usize,
        len: usize,
        prot: &litebox_common_linux::loader::Protection,
    ) -> Result<(), Self::Error> {
        let addr = crate::MutPtr::<u8>::from_usize(address);
        self.task.sys_mprotect(addr, len, prot.flags())
    }
}

/// Struct to hold the information needed to start the program
/// (entry point and user stack top).
pub struct ElfLoadInfo {
    pub entry_point: usize,
    pub user_stack_top: usize,
}

/// Loader for ELF files
pub(crate) struct ElfLoader<'a, FS: ShimFS> {
    path: &'a str,
    main: FileAndParsed<'a, FS>,
    interp: Option<FileAndParsed<'a, FS>>,
}

struct FileAndParsed<'a, FS: ShimFS> {
    file: ElfFile<'a, FS>,
    parsed: ElfParsedFile,
}

impl<'a, FS: ShimFS> FileAndParsed<'a, FS> {
    fn new(task: &'a Task<FS>, path: impl litebox::path::Arg) -> Result<Self, ElfLoaderError> {
        let file = ElfFile::new(task, path).map_err(ElfLoaderError::OpenError)?;
        let mut parsed = litebox_common_linux::loader::ElfParsedFile::parse(&mut &file)
            .map_err(ElfLoaderError::ParseError)?;
        parsed.parse_trampoline(&mut &file, task.global.platform.get_syscall_entry_point())?;
        Ok(Self { file, parsed })
    }
}

impl<'a, FS: ShimFS> ElfLoader<'a, FS> {
    /// Parses an ELF file from the given path.
    pub fn new(task: &'a Task<FS>, path: &'a str) -> Result<Self, ElfLoaderError> {
        // Parse the main ELF file.
        let main = FileAndParsed::new(task, path)?;

        // Parse the interpreter ELF file, if any.
        let interp = if let Some(interp_name) = main.parsed.interp(&mut &main.file)? {
            // e.g., /lib64/ld-linux-x86-64.so.2
            Some(FileAndParsed::new(task, interp_name)?)
        } else {
            None
        };

        Ok(Self { path, main, interp })
    }

    /// Load an ELF file and prepare the stack for the new process.
    pub fn load(
        &mut self,
        argv: Vec<CString>,
        envp: Vec<CString>,
        mut aux: AuxVec,
    ) -> Result<ElfLoadInfo, ElfLoaderError> {
        let global = &self.main.file.task.global;

        // Load the main ELF file first so that it gets privileged addresses.
        let info = self
            .main
            .parsed
            .load(&mut self.main.file, &mut &*global.platform)?;

        // Load the interpreter ELF file, if any.
        let interp = if let Some(interp) = &mut self.interp {
            // On macOS ARM64, the default top-down address allocator tends to
            // place the interpreter immediately after the main binary, leaving
            // almost no room for brk to grow.  When glibc's malloc later tries
            // to extend the heap via brk(), it collides with the interpreter
            // mapping and gets ENOMEM → "malloc(): corrupted top size".
            //
            // Additionally, the vmem VMA tree includes macOS reserved regions
            // (dyld, shared cache, etc.) discovered at startup.  A blind
            // brk+offset hint may land inside one of those regions, causing
            // get_unmmaped_area to reject it and fall back to a top-down
            // address near TASK_ADDR_MAX that macOS ignores — placing the
            // interpreter right next to the main binary anyway.
            //
            // Fix: query the vmem layer for a genuinely free gap above the brk
            // reservation zone.  This produces a hint that both the vmem
            // allocator and the macOS kernel will accept.
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            {
                use litebox::mm::PageManager;
                type PM = PageManager<crate::Platform, { PAGE_SIZE }>;
                // 4 MiB is generous for any interpreter (ld-linux is ~300 KiB).
                const INTERP_SIZE_ESTIMATE: usize = 4 * 1024 * 1024;

                let brk_aligned = info.brk.next_multiple_of(PAGE_SIZE);
                let min_addr = brk_aligned + PM::BRK_RESERVE_SIZE;
                if let Some(hint) = global
                    .pm
                    .find_free_hint_above(min_addr, INTERP_SIZE_ESTIMATE)
                {
                    litebox::log_println!(
                        global.platform,
                        "[diag] interp hint: brk={:#x} min_search={:#x} found_free={:#x}",
                        info.brk,
                        min_addr,
                        hint
                    );
                    interp.file.mmap_hint = hint;
                } else {
                    litebox::log_println!(
                        global.platform,
                        "[diag] interp hint: no free region above {:#x}, using default",
                        min_addr
                    );
                }
            }

            Some(
                interp
                    .parsed
                    .load(&mut interp.file, &mut &*global.platform)?,
            )
        } else {
            None
        };

        // Log the key addresses for brk/interpreter collision debugging
        #[cfg(target_arch = "aarch64")]
        if let Some(interp_info) = &interp {
            litebox::log_println!(
                global.platform,
                "[diag] layout: main base={:#x} brk={:#x} | interp base={:#x} brk={:#x} | gap={:#x}",
                info.base_addr,
                info.brk,
                interp_info.base_addr,
                interp_info.brk,
                interp_info.base_addr.saturating_sub(info.brk)
            );
        }

        global.pm.set_initial_brk(info.brk);
        aux.insert(AuxKey::AT_PAGESZ, PAGE_SIZE);
        aux.insert(AuxKey::AT_PHDR, info.phdrs_addr);
        aux.insert(AuxKey::AT_PHENT, info.phent_size());
        aux.insert(AuxKey::AT_PHNUM, info.num_phdrs);
        aux.insert(AuxKey::AT_ENTRY, info.entry_point);
        let entry = if let Some(interp) = &interp {
            aux.insert(AuxKey::AT_BASE, interp.base_addr);
            interp.entry_point
        } else {
            info.entry_point
        };

        let sp = unsafe {
            let length = litebox::mm::linux::NonZeroPageSize::new(super::DEFAULT_STACK_SIZE)
                .expect("DEFAULT_STACK_SIZE is not page-aligned");
            global
                .pm
                .create_stack_pages(None, length, CreatePagesFlags::empty())
                .map_err(ElfLoaderError::MappingError)?
        };
        let mut stack = UserStack::new(sp, super::DEFAULT_STACK_SIZE)
            .ok_or(ElfLoaderError::InvalidStackAddr)?;
        stack
            .init(argv, envp, aux)
            .ok_or(ElfLoaderError::InvalidStackAddr)?;

        Ok(ElfLoadInfo {
            entry_point: entry,
            user_stack_top: stack.get_cur_stack_top(),
        })
    }

    /// Returns the command name from the ELF path.
    pub fn comm(&self) -> &[u8] {
        self.path.rsplit('/').next().unwrap_or("unknown").as_bytes()
    }
}

#[derive(Error, Debug)]
pub enum ElfLoaderError {
    #[error("failed to open the ELF file")]
    OpenError(#[from] Errno),
    #[error("failed to parse the ELF file")]
    ParseError(#[from] litebox_common_linux::loader::ElfParseError<Errno>),
    #[error("failed to load the ELF file")]
    LoadError(#[from] litebox_common_linux::loader::ElfLoadError<Errno>),
    #[error("invalid stack")]
    InvalidStackAddr,
    #[error("failed to mmap")]
    MappingError(#[from] MappingError),
}

impl From<ElfLoaderError> for litebox_common_linux::errno::Errno {
    fn from(value: ElfLoaderError) -> Self {
        match value {
            ElfLoaderError::OpenError(e) => e,
            ElfLoaderError::ParseError(e) => e.into(),
            ElfLoaderError::InvalidStackAddr | ElfLoaderError::MappingError(_) => {
                litebox_common_linux::errno::Errno::ENOMEM
            }
            ElfLoaderError::LoadError(e) => e.into(),
        }
    }
}
