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
use litebox_common_linux::{MapFlags, errno::Errno, loader::ElfParsedFile};
use thiserror::Error;

use crate::{
    MutPtr,
    loader::auxv::{AuxKey, AuxVec},
};

use super::stack::UserStack;
use crate::{ShimFS, Task};

// An opened elf file
struct ElfFile<'a, FS: ShimFS> {
    task: &'a Task<FS>,
    fd: i32,
}

impl<'a, FS: ShimFS> ElfFile<'a, FS> {
    fn new(task: &'a Task<FS>, path: impl litebox::path::Arg) -> Result<Self, Errno> {
        let fd = task
            .sys_open(path, OFlags::RDONLY, Mode::empty())?
            .reinterpret_as_signed();
        Ok(ElfFile { task, fd })
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
                super::DEFAULT_LOW_ADDR,
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
            Some(
                interp
                    .parsed
                    .load(&mut interp.file, &mut &*global.platform)?,
            )
        } else {
            None
        };

        // == Diagnostic: simulate rtld_audit's parse_object scan on the main binary ==
        // This runs on the host side to verify what the guest-side parse_object would see.
        // rtld_audit's debug prints are invisible when syscall_entry==0, so we need
        // host-side visibility into the trampoline state.
        #[cfg(target_arch = "aarch64")]
        #[allow(clippy::cast_possible_truncation)]
        {
            use litebox_common_linux::loader::AccessMemory;
            let base = info.base_addr;
            litebox::log_println!(
                global.platform,
                "[diag] parse_object sim: main base_addr={:#x} brk={:#x} phdrs_addr={:#x} num_phdrs={} tls_table={:#x}",
                base,
                info.brk,
                info.phdrs_addr,
                info.num_phdrs,
                info.tls_table_addr
            );

            // Read in-memory ELF header to get e_phoff and e_phnum
            let mut ehdr = [0u8; 64]; // Elf64_Ehdr is 64 bytes
            if (&*global.platform).read(base, &mut ehdr).is_ok() {
                let e_phoff = u64::from_le_bytes(ehdr[32..40].try_into().unwrap()) as usize;
                let e_phentsize = u16::from_le_bytes(ehdr[54..56].try_into().unwrap()) as usize;
                let e_phnum = u16::from_le_bytes(ehdr[56..58].try_into().unwrap()) as usize;
                litebox::log_println!(
                    global.platform,
                    "[diag] parse_object sim: e_phoff={:#x} e_phentsize={} e_phnum={}",
                    e_phoff,
                    e_phentsize,
                    e_phnum
                );

                // Walk program headers like parse_object does
                let mut max_filesz_end: usize = 0;
                let mut max_memsz_end: usize = 0;
                for i in 0..e_phnum {
                    let ph_addr = base + e_phoff + i * e_phentsize;
                    let mut phdr = [0u8; 56]; // Elf64_Phdr is 56 bytes
                    if (&*global.platform).read(ph_addr, &mut phdr).is_ok() {
                        let p_type = u32::from_le_bytes(phdr[0..4].try_into().unwrap());
                        let p_vaddr = u64::from_le_bytes(phdr[16..24].try_into().unwrap()) as usize;
                        let p_filesz =
                            u64::from_le_bytes(phdr[32..40].try_into().unwrap()) as usize;
                        let p_memsz = u64::from_le_bytes(phdr[40..48].try_into().unwrap()) as usize;
                        if p_type == 1 {
                            // PT_LOAD
                            litebox::log_println!(
                                global.platform,
                                "[diag] parse_object sim: PT_LOAD[{}] p_vaddr={:#x} p_filesz={:#x} p_memsz={:#x}",
                                i,
                                p_vaddr,
                                p_filesz,
                                p_memsz
                            );
                            let filesz_end = p_vaddr + p_filesz;
                            let memsz_end = p_vaddr + p_memsz;
                            if filesz_end > max_filesz_end {
                                max_filesz_end = filesz_end;
                            }
                            if memsz_end > max_memsz_end {
                                max_memsz_end = memsz_end;
                            }
                        }
                    }
                }

                // Simulate the scan: align_up(max_filesz_end, 0x1000) .. align_up(max_memsz_end, 0x1000)
                let scan_start = (max_filesz_end + 0xFFF) & !0xFFF;
                let scan_end = (max_memsz_end + 0xFFF) & !0xFFF;
                litebox::log_println!(
                    global.platform,
                    "[diag] parse_object sim: max_filesz_end={:#x} max_memsz_end={:#x} scan_start={:#x} scan_end={:#x}",
                    max_filesz_end,
                    max_memsz_end,
                    scan_start,
                    scan_end
                );

                // Scan each 4KB page in the range, read first 8 bytes
                let mut found_trampoline = false;
                let mut offset = scan_start;
                while offset < scan_end {
                    let addr = base + offset;
                    let mut buf = [0u8; 8];
                    match (&*global.platform).read(addr, &mut buf) {
                        Ok(_) => {
                            let val = u64::from_le_bytes(buf);
                            litebox::log_println!(
                                global.platform,
                                "[diag] parse_object sim: scan addr={:#x} (offset={:#x}) val={:#x}",
                                addr,
                                offset,
                                val
                            );
                            if val != 0 && !found_trampoline {
                                found_trampoline = true;
                                // Also read the next 8 bytes (tls_table_ptr)
                                let mut buf2 = [0u8; 8];
                                if (&*global.platform).read(addr + 8, &mut buf2).is_ok() {
                                    let tls_ptr = u64::from_le_bytes(buf2);
                                    litebox::log_println!(
                                        global.platform,
                                        "[diag] parse_object sim: FOUND trampoline at {:#x}: syscall_entry={:#x} tls_table_ptr={:#x}",
                                        addr,
                                        val,
                                        tls_ptr
                                    );
                                }
                            }
                        }
                        Err(_) => {
                            litebox::log_println!(
                                global.platform,
                                "[diag] parse_object sim: scan addr={:#x} (offset={:#x}) READ FAILED",
                                addr,
                                offset
                            );
                        }
                    }
                    offset += 0x1000;
                }
                if !found_trampoline {
                    litebox::log_println!(
                        global.platform,
                        "[diag] parse_object sim: NO trampoline found in scan range!"
                    );
                }
            } else {
                litebox::log_println!(
                    global.platform,
                    "[diag] parse_object sim: failed to read ELF header at {:#x}",
                    base
                );
            }
        }

        // Also dump interpreter trampoline info
        #[cfg(target_arch = "aarch64")]
        #[allow(clippy::cast_possible_truncation)]
        if let Some(interp_info) = &interp {
            use litebox_common_linux::loader::AccessMemory;
            let ibase = interp_info.base_addr;
            litebox::log_println!(
                global.platform,
                "[diag] parse_object sim: interp base_addr={:#x} brk={:#x} tls_table={:#x}",
                ibase,
                interp_info.brk,
                interp_info.tls_table_addr
            );
            // Read trampoline from interpreter using same scan
            let mut ehdr = [0u8; 64];
            if (&*global.platform).read(ibase, &mut ehdr).is_ok() {
                let e_phoff = u64::from_le_bytes(ehdr[32..40].try_into().unwrap()) as usize;
                let e_phentsize = u16::from_le_bytes(ehdr[54..56].try_into().unwrap()) as usize;
                let e_phnum = u16::from_le_bytes(ehdr[56..58].try_into().unwrap()) as usize;
                let mut max_filesz_end: usize = 0;
                let mut max_memsz_end: usize = 0;
                for i in 0..e_phnum {
                    let ph_addr = ibase + e_phoff + i * e_phentsize;
                    let mut phdr = [0u8; 56];
                    if (&*global.platform).read(ph_addr, &mut phdr).is_ok() {
                        let p_type = u32::from_le_bytes(phdr[0..4].try_into().unwrap());
                        let p_vaddr = u64::from_le_bytes(phdr[16..24].try_into().unwrap()) as usize;
                        let p_filesz =
                            u64::from_le_bytes(phdr[32..40].try_into().unwrap()) as usize;
                        let p_memsz = u64::from_le_bytes(phdr[40..48].try_into().unwrap()) as usize;
                        if p_type == 1 {
                            // PT_LOAD
                            let filesz_end = p_vaddr + p_filesz;
                            let memsz_end = p_vaddr + p_memsz;
                            if filesz_end > max_filesz_end {
                                max_filesz_end = filesz_end;
                            }
                            if memsz_end > max_memsz_end {
                                max_memsz_end = memsz_end;
                            }
                        }
                    }
                }
                let scan_start = (max_filesz_end + 0xFFF) & !0xFFF;
                let scan_end = (max_memsz_end + 0xFFF) & !0xFFF;
                litebox::log_println!(
                    global.platform,
                    "[diag] parse_object sim interp: scan_start={:#x} scan_end={:#x}",
                    scan_start,
                    scan_end
                );
                let mut offset = scan_start;
                while offset < scan_end {
                    let addr = ibase + offset;
                    let mut buf = [0u8; 8];
                    if (&*global.platform).read(addr, &mut buf).is_ok() {
                        let val = u64::from_le_bytes(buf);
                        if val != 0 {
                            let mut buf2 = [0u8; 8];
                            let tls_ptr = if (&*global.platform).read(addr + 8, &mut buf2).is_ok() {
                                u64::from_le_bytes(buf2)
                            } else {
                                0
                            };
                            litebox::log_println!(
                                global.platform,
                                "[diag] parse_object sim interp: FOUND at {:#x} (offset={:#x}): entry={:#x} tls={:#x}",
                                addr,
                                offset,
                                val,
                                tls_ptr
                            );
                            break; // Only need to find the first one
                        }
                    }
                    offset += 0x1000;
                }
            }
        }
        // == End diagnostic ==

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
