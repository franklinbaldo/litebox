// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::{vec, vec::Vec};

use litebox::fd::TypedFd;
use litebox::fs::{Mode, OFlags};
use litebox::mm::linux::{
    CreatePagesFlags, MappingError, NonZeroAddress, NonZeroPageSize, VmemProtectError,
};
use litebox::platform::RawPointerProvider;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _, SystemInfoProvider as _};
use litebox_common_windows::loader::{
    AccessMemory, Fault, MapMemory, MappingInfo, PeDataDirectory, PeExport, PeLoadError,
    PeParseError, PeParsedFile, Protection, ReadAt,
};
use litebox_platform_multiplex::Platform;
use thiserror::Error;
use zerocopy::FromZeros;

use crate::nt_types::{
    KiUserInvertedFunctionTableEntry, KiUserInvertedFunctionTableHeader,
    MAXIMUM_INVERTED_FUNCTION_TABLE_SIZE, ProcessEnvironmentBlock, RtlUserProcFlags,
    RtlUserProcessParameters, ThreadEnvironmentBlock, UnicodeString,
};
use crate::{NtShimFS, WindowsPageManager, WindowsVirtualAllocation, write_slice, write_value};

const PAGE_SIZE: usize = litebox_common_windows::loader::PAGE_SIZE;
const INITIAL_STACK_SIZE: usize = 1024 * 1024;
const NTDLL_PATHS: &[&str] = &["/Windows/System32/ntdll.dll", "/windows/system32/ntdll.dll"];
const NTDLL_WRITABLE_SECTIONS: &[&[u8]] = &[b".mrdata"];
const NTDLL_LOADER_ENTRYPOINT: &[u8] = b"LdrInitializeThunk";
const KI_USER_INVERTED_FUNCTION_TABLE: &[u8] = b"KiUserInvertedFunctionTable";
const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
const PROCESS_ENVIRONMENT_ALLOCATION_PROTECT: u32 = 0x04;

/// Struct to hold the information needed to start the program.
pub(crate) struct PeLoadInfo {
    pub(crate) entry_point: usize,
    pub(crate) stack_top: usize,
    pub(crate) environment: WindowsProcessEnvironment,
    pub(crate) application_mapping: MappingInfo,
    pub(crate) ntdll_mapping: Option<MappingInfo>,
}

/// Loader for Windows PE files.
pub(crate) struct PeLoader<'a, FS: NtShimFS> {
    fs: Arc<FS>,
    page_manager: &'a WindowsPageManager,
}

impl<'a, FS: NtShimFS> PeLoader<'a, FS> {
    pub(crate) fn new(fs: Arc<FS>, page_manager: &'a WindowsPageManager) -> Self {
        Self { fs, page_manager }
    }

    pub(crate) fn load(&self, path: &str) -> Result<PeLoadInfo, WindowsLoadError> {
        let image = load_image(self.fs.clone(), path, self.page_manager)?;
        let application_entry_point = image.mapping.entry_point;
        let image_base_address = image.mapping.base_addr;
        let ntdll = load_ntdll(self.fs.clone(), self.page_manager, NTDLL_PATHS)?;

        let entry_point = if let Some(ntdll) = &ntdll {
            if !ntdll.has_trampoline {
                return Err(WindowsLoadError::UnrewrittenNtDll);
            }
            Self::initialize_ki_user_inverted_function_table(ntdll)?;
            let loader_entry_point = ntdll
                .export_address(NTDLL_LOADER_ENTRYPOINT)?
                .ok_or(WindowsLoadError::MissingNtDllLoaderEntrypoint)?;
            litebox_util_log::debug!(
                entry_point:% = format_args!("{loader_entry_point:#x}"),
                application_entry_point:% = format_args!("{application_entry_point:#x}");
                "Starting Windows guest through ntdll!LdrInitializeThunk"
            );
            loader_entry_point
        } else {
            application_entry_point
        };

        let length =
            NonZeroPageSize::new(INITIAL_STACK_SIZE).ok_or(PeImageAccessError::AddressOverflow)?;
        let stack_base = unsafe {
            self.page_manager
                .create_stack_pages(None, length, CreatePagesFlags::empty())
                .map_err(PeImageAccessError::Mapping)?
        };
        let stack_top = stack_base
            .as_usize()
            .checked_add(INITIAL_STACK_SIZE)
            .ok_or(PeImageAccessError::AddressOverflow)?;

        Ok(PeLoadInfo {
            entry_point,
            stack_top,
            application_mapping: image.mapping,
            ntdll_mapping: ntdll.map(|image| image.mapping),
            environment: self.create_process_environment(image_base_address, path)?,
        })
    }

    fn create_process_environment(
        &self,
        image_base_address: usize,
        image_path: &str,
    ) -> Result<WindowsProcessEnvironment, WindowsLoadError> {
        let mut virtual_allocations = Vec::new();
        let mut create_pages = |size: usize| -> Result<usize, PeImageAccessError> {
            let aligned_length = size.next_multiple_of(PAGE_SIZE);
            let length =
                NonZeroPageSize::new(aligned_length).ok_or(PeImageAccessError::AddressOverflow)?;
            let ptr = unsafe {
                self.page_manager.create_writable_pages(
                    None,
                    length,
                    CreatePagesFlags::empty(),
                    |_| Ok(0),
                )
            }?;
            let base = ptr.as_usize();
            virtual_allocations.push(WindowsVirtualAllocation {
                base,
                size: aligned_length,
                allocation_protect: PROCESS_ENVIRONMENT_ALLOCATION_PROTECT,
            });
            Ok(base)
        };
        let teb_ptr = create_pages(core::mem::size_of::<ThreadEnvironmentBlock>())?;
        let peb_ptr = create_pages(core::mem::size_of::<ProcessEnvironmentBlock>())?;

        let dos_image_path = dos_image_path(image_path);
        let current_directory_path = Utf16StringBuffer::new(r"C:\")?;
        let dll_path = Utf16StringBuffer::new(r"C:\Windows\System32;C:\")?;
        let image_path_name = Utf16StringBuffer::new(&dos_image_path)?;
        let command_line = Utf16StringBuffer::new(&dos_image_path)?;
        let window_title = Utf16StringBuffer::new(&dos_image_path)?;
        let desktop_info = Utf16StringBuffer::new("")?;
        let shell_info = Utf16StringBuffer::new("")?;
        let runtime_data = Utf16StringBuffer::new("")?;
        let redirection_dll_name = Utf16StringBuffer::new("")?;
        let process_parameter_strings = [
            &current_directory_path,
            &dll_path,
            &image_path_name,
            &command_line,
            &window_title,
            &desktop_info,
            &shell_info,
            &runtime_data,
            &redirection_dll_name,
        ];
        let process_parameters_length = process_parameter_strings.iter().try_fold(
            core::mem::size_of::<RtlUserProcessParameters>(),
            |length, string| {
                length
                    .checked_add(usize::from(string.maximum_length))
                    .ok_or(PeImageAccessError::AddressOverflow)
            },
        )?;
        let process_parameters_allocation_length =
            process_parameters_length.next_multiple_of(PAGE_SIZE);
        let process_parameters_ptr = create_pages(process_parameters_length)?;

        let mut process_parameters = RtlUserProcessParameters::new_zeroed();
        process_parameters.maximum_length = u32::try_from(process_parameters_allocation_length)
            .map_err(|_| PeImageAccessError::AddressOverflow)?;
        process_parameters.length = u32::try_from(process_parameters_length)
            .map_err(|_| PeImageAccessError::AddressOverflow)?;
        process_parameters.flags = RtlUserProcFlags::NORMALIZED;
        let mut process_parameter_tail = process_parameters_ptr
            .checked_add(core::mem::size_of::<RtlUserProcessParameters>())
            .ok_or(PeImageAccessError::AddressOverflow)?;
        let mut write_parameter_string =
            |string: &Utf16StringBuffer| -> Result<UnicodeString, PeImageAccessError> {
                let buffer = process_parameter_tail;
                write_slice(buffer, &string.units).ok_or(PeImageAccessError::MemoryAccess)?;
                process_parameter_tail = process_parameter_tail
                    .checked_add(usize::from(string.maximum_length))
                    .ok_or(PeImageAccessError::AddressOverflow)?;
                Ok(UnicodeString {
                    length: string.length,
                    maximum_length: string.maximum_length,
                    padding_0: [0; 4],
                    buffer,
                })
            };
        process_parameters.current_directory.dos_path =
            write_parameter_string(&current_directory_path)?;
        process_parameters.dll_path = write_parameter_string(&dll_path)?;
        process_parameters.image_path_name = write_parameter_string(&image_path_name)?;
        process_parameters.command_line = write_parameter_string(&command_line)?;
        process_parameters.window_title = write_parameter_string(&window_title)?;
        process_parameters.desktop_info = write_parameter_string(&desktop_info)?;
        process_parameters.shell_info = write_parameter_string(&shell_info)?;
        process_parameters.runtime_data = write_parameter_string(&runtime_data)?;
        process_parameters.redirection_dll_name = write_parameter_string(&redirection_dll_name)?;
        write_value(process_parameters_ptr, process_parameters)
            .ok_or(PeImageAccessError::MemoryAccess)?;

        let mut peb = ProcessEnvironmentBlock::new_zeroed();
        peb.image_base_address = image_base_address;
        peb.process_parameters = process_parameters_ptr;
        write_value(peb_ptr, peb).ok_or(PeImageAccessError::MemoryAccess)?;

        let mut teb = ThreadEnvironmentBlock::new_zeroed();
        teb.nt_tib.self_pointer = teb_ptr;
        teb.process_environment_block = peb_ptr;
        write_value(teb_ptr, teb).ok_or(PeImageAccessError::MemoryAccess)?;
        Ok(WindowsProcessEnvironment {
            peb: peb_ptr,
            _process_parameters: process_parameters_ptr,
            teb: teb_ptr,
            virtual_allocations,
        })
    }

    fn initialize_ki_user_inverted_function_table(
        ntdll: &LoadedImage,
    ) -> Result<(), WindowsLoadError> {
        let Some(table_address) = ntdll.export_address(KI_USER_INVERTED_FUNCTION_TABLE)? else {
            litebox_util_log::debug!("Guest ntdll.dll does not export KiUserInvertedFunctionTable");
            return Ok(());
        };

        let mut entries = Vec::new();
        if let Some(entry) = ntdll.inverted_function_table_entry()? {
            entries.push(entry);
        }
        entries.sort_by_key(|entry| entry.image_base);

        let current_size =
            u32::try_from(entries.len()).map_err(|_| PeImageAccessError::AddressOverflow)?;
        let header = KiUserInvertedFunctionTableHeader {
            current_size,
            maximum_size: MAXIMUM_INVERTED_FUNCTION_TABLE_SIZE,
            epoch: 0,
            overflow: 0,
            padding_0: [0; 3],
        };

        // `KI_USER_INVERTED_FUNCTION_TABLE` lives in ntdll's writable `.mrdata` section.
        write_value(table_address, header).ok_or(PeImageAccessError::MemoryAccess)?;

        let entries_address = table_address
            .checked_add(core::mem::size_of::<KiUserInvertedFunctionTableHeader>())
            .ok_or(PeImageAccessError::AddressOverflow)?;
        write_slice(entries_address, &entries).ok_or(PeImageAccessError::MemoryAccess)?;

        litebox_util_log::debug!(
            table:% = format_args!("{table_address:#x}"),
            current_size = current_size;
            "Initialized ntdll!KiUserInvertedFunctionTable"
        );

        Ok(())
    }
}

struct Utf16StringBuffer {
    units: Vec<u16>,
    length: u16,
    maximum_length: u16,
}

impl Utf16StringBuffer {
    fn new(value: &str) -> Result<Self, PeImageAccessError> {
        let mut units: Vec<u16> = value.encode_utf16().collect();
        let length = units
            .len()
            .checked_mul(size_of::<u16>())
            .ok_or(PeImageAccessError::AddressOverflow)?;
        units.push(0);
        let maximum_length = units
            .len()
            .checked_mul(size_of::<u16>())
            .ok_or(PeImageAccessError::AddressOverflow)?;
        Ok(Self {
            units,
            length: u16::try_from(length).map_err(|_| PeImageAccessError::AddressOverflow)?,
            maximum_length: u16::try_from(maximum_length)
                .map_err(|_| PeImageAccessError::AddressOverflow)?,
        })
    }
}

fn dos_image_path(path: &str) -> String {
    let mut dos_path = String::from(r"\??\C:");
    if !path.starts_with('/') && !path.starts_with('\\') {
        dos_path.push('\\');
    }
    for ch in path.chars() {
        dos_path.push(if ch == '/' { '\\' } else { ch });
    }
    dos_path
}

pub(crate) struct WindowsProcessEnvironment {
    pub(crate) peb: usize,
    pub(crate) _process_parameters: usize,
    pub(crate) teb: usize,
    pub(crate) virtual_allocations: Vec<WindowsVirtualAllocation>,
}

pub(crate) struct LoadedImage {
    pub(crate) mapping: MappingInfo,
    image_size: usize,
    data_directories: Vec<PeDataDirectory>,
    exports: Vec<PeExport>,
    pub(crate) has_trampoline: bool,
}

impl LoadedImage {
    pub(crate) fn export_address(&self, name: &[u8]) -> Result<Option<usize>, PeImageAccessError> {
        let Some(export) = self.exports.iter().find(|export| export.name == name) else {
            return Ok(None);
        };
        let rva = usize::try_from(export.rva).map_err(|_| PeImageAccessError::AddressOverflow)?;
        self.mapping
            .base_addr
            .checked_add(rva)
            .ok_or(PeImageAccessError::AddressOverflow)
            .map(Some)
    }

    fn inverted_function_table_entry(
        &self,
    ) -> Result<Option<KiUserInvertedFunctionTableEntry>, PeImageAccessError> {
        let Some(exception_directory) = self.data_directories.get(IMAGE_DIRECTORY_ENTRY_EXCEPTION)
        else {
            return Ok(None);
        };
        if exception_directory.size == 0 {
            return Ok(None);
        }

        let size_of_table = exception_directory.size;
        let exception_directory_rva = exception_directory.virtual_address as usize;
        let exception_directory = self
            .mapping
            .base_addr
            .checked_add(exception_directory_rva)
            .ok_or(PeImageAccessError::AddressOverflow)?;
        let image_size =
            u32::try_from(self.image_size).map_err(|_| PeImageAccessError::AddressOverflow)?;

        Ok(Some(KiUserInvertedFunctionTableEntry {
            exception_directory,
            image_base: self.mapping.base_addr,
            image_size,
            size_of_table,
        }))
    }
}

pub(crate) fn load_ntdll<FS: NtShimFS>(
    fs: Arc<FS>,
    page_manager: &WindowsPageManager,
    ntdll_paths: &[&str],
) -> Result<Option<LoadedImage>, WindowsLoadError> {
    for path in ntdll_paths {
        match load_image_with_writable_sections(
            fs.clone(),
            path,
            page_manager,
            NTDLL_WRITABLE_SECTIONS,
        ) {
            Ok(image) => {
                litebox_util_log::debug!(path:% = path; "Loaded guest ntdll.dll");
                return Ok(Some(image));
            }
            Err(error) if is_missing_file_error(&error) => {}
            Err(error) => return Err(error),
        }
    }

    litebox_util_log::debug!("Guest ntdll.dll was not found in the initial filesystem");
    Ok(None)
}

pub(crate) fn load_image<FS: NtShimFS>(
    fs: Arc<FS>,
    path: &str,
    page_manager: &WindowsPageManager,
) -> Result<LoadedImage, WindowsLoadError> {
    load_image_with_writable_sections(fs, path, page_manager, &[])
}

fn load_image_with_writable_sections<FS: NtShimFS>(
    fs: Arc<FS>,
    path: &str,
    page_manager: &WindowsPageManager,
    writable_section_names: &[&[u8]],
) -> Result<LoadedImage, WindowsLoadError> {
    let file = PeImageFile::open(fs, path)?;
    let mut parsed = PeParsedFile::parse(&mut &file).map_err(WindowsLoadError::Parse)?;
    let image_size = parsed.image.size_of_image;
    let data_directories = parsed.data_directories.clone();
    let exports = parsed.exports.clone();
    parsed
        .parse_trampoline(
            &mut &file,
            litebox_platform_multiplex::platform().get_syscall_entry_point(),
        )
        .map_err(WindowsLoadError::Parse)?;
    let has_trampoline = parsed.has_trampoline();
    let mut mapper = PeImageMapper {
        file: &file,
        page_manager,
    };
    let mut memory = PeImageMemory;
    let mapping = parsed
        .load_with_writable_sections(&mut mapper, &mut memory, writable_section_names)
        .map_err(WindowsLoadError::Load)?;
    Ok(LoadedImage {
        mapping,
        image_size,
        data_directories,
        exports,
        has_trampoline,
    })
}

/// Errors that can occur while opening, parsing, and mapping a Windows PE image.
#[derive(Debug, Error)]
pub enum WindowsLoadError {
    /// PE parsing failed.
    #[error("failed to parse PE image")]
    Parse(#[source] PeParseError<PeImageAccessError>),
    /// PE image mapping failed.
    #[error("failed to load PE image")]
    Load(#[source] PeLoadError<PeImageAccessError>),
    /// Opening the PE image failed.
    #[error(transparent)]
    Access(#[from] PeImageAccessError),
    /// Guest ntdll.dll does not export LdrInitializeThunk.
    #[error("guest ntdll.dll does not export LdrInitializeThunk")]
    MissingNtDllLoaderEntrypoint,
    /// Guest ntdll.dll has not been rewritten for LiteBox syscall/GS handling.
    #[error("guest ntdll.dll must be rewritten for LiteBox before entering its loader")]
    UnrewrittenNtDll,
}

/// Errors from the shim-side PE image backing file and memory mapper.
#[derive(Debug, Error)]
pub enum PeImageAccessError {
    /// Opening the executable failed.
    #[error("failed to open PE image")]
    Open(#[from] litebox::fs::errors::OpenError),
    /// Reading the executable failed.
    #[error("failed to read PE image")]
    Read(#[from] litebox::fs::errors::ReadError),
    /// Reading file metadata failed.
    #[error("failed to read PE image metadata")]
    FileStatus(#[from] litebox::fs::errors::FileStatusError),
    /// The backing file ended before the requested range was read.
    #[error("short read from PE image")]
    ShortRead,
    /// A PE file offset or image address overflowed this host representation.
    #[error("PE image address overflow")]
    AddressOverflow,
    /// A memory mapping operation failed.
    #[error(transparent)]
    Mapping(#[from] MappingError),
    /// A memory protection operation failed.
    #[error(transparent)]
    Protect(#[from] VmemProtectError),
    /// A mapped memory access failed.
    #[error("mapped PE image memory access failed")]
    MemoryAccess,
}

fn is_missing_file_error(error: &WindowsLoadError) -> bool {
    let WindowsLoadError::Access(PeImageAccessError::Open(error)) = error else {
        return false;
    };

    matches!(
        error,
        litebox::fs::errors::OpenError::PathError(
            litebox::fs::errors::PathError::NoSuchFileOrDirectory
                | litebox::fs::errors::PathError::MissingComponent
        )
    )
}

struct PeImageFile<FS: NtShimFS> {
    fs: Arc<FS>,
    fd: TypedFd<FS>,
}

impl<FS: NtShimFS> PeImageFile<FS> {
    fn open(fs: Arc<FS>, path: &str) -> Result<Self, PeImageAccessError> {
        let fd = fs.open(path, OFlags::RDONLY, Mode::empty())?;
        Ok(Self { fs, fd })
    }

    fn read_exact_at(
        &self,
        mut offset: usize,
        mut buf: &mut [u8],
    ) -> Result<(), PeImageAccessError> {
        while !buf.is_empty() {
            let bytes_read = self.fs.read(&self.fd, buf, Some(offset))?;
            if bytes_read == 0 {
                return Err(PeImageAccessError::ShortRead);
            }
            offset = offset
                .checked_add(bytes_read)
                .ok_or(PeImageAccessError::AddressOverflow)?;
            buf = &mut buf[bytes_read..];
        }
        Ok(())
    }
}

impl<FS: NtShimFS> Drop for PeImageFile<FS> {
    fn drop(&mut self) {
        let _ = self.fs.close(&self.fd);
    }
}

impl<FS: NtShimFS> ReadAt for &'_ PeImageFile<FS> {
    type Error = PeImageAccessError;

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), Self::Error> {
        self.read_exact_at(
            offset
                .try_into()
                .map_err(|_| PeImageAccessError::AddressOverflow)?,
            buf,
        )
    }

    fn size(&mut self) -> Result<u64, Self::Error> {
        self.fs
            .fd_file_status(&self.fd)?
            .size
            .try_into()
            .map_err(|_| PeImageAccessError::AddressOverflow)
    }
}

struct PeImageMapper<'a, FS: NtShimFS> {
    file: &'a PeImageFile<FS>,
    page_manager: &'a WindowsPageManager,
}

impl<FS: NtShimFS> MapMemory for PeImageMapper<'_, FS> {
    type Error = PeImageAccessError;

    fn reserve(
        &mut self,
        preferred_base: usize,
        len: usize,
        _align: usize,
    ) -> Result<usize, Self::Error> {
        let length = NonZeroPageSize::new(len).ok_or(PeImageAccessError::AddressOverflow)?;
        let suggested_address = if preferred_base == 0 {
            None
        } else {
            Some(NonZeroAddress::new(preferred_base).ok_or(PeImageAccessError::AddressOverflow)?)
        };

        // SAFETY: The PE loader owns this reserved image range and maps concrete
        // headers/sections into it before any guest execution is allowed.
        let ptr = unsafe {
            self.page_manager.create_inaccessible_pages(
                suggested_address,
                length,
                CreatePagesFlags::empty(),
                |_| Ok(0),
            )?
        };
        Ok(ptr.as_usize())
    }

    fn map_zero(
        &mut self,
        address: usize,
        len: usize,
        prot: &Protection,
    ) -> Result<(), Self::Error> {
        make_pages_writable(self.page_manager, address, len)?;
        let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(address);
        for index in 0..len {
            ptr.write_at_offset(
                index
                    .try_into()
                    .map_err(|_| PeImageAccessError::AddressOverflow)?,
                0,
            )
            .ok_or(PeImageAccessError::MemoryAccess)?;
        }
        protect_pages(self.page_manager, address, len, *prot)
    }

    fn map_file(
        &mut self,
        address: usize,
        len: usize,
        offset: u64,
        prot: &Protection,
    ) -> Result<(), Self::Error> {
        make_pages_writable(self.page_manager, address, len)?;
        let mut data = vec![0; len];
        self.file.read_exact_at(
            offset
                .try_into()
                .map_err(|_| PeImageAccessError::AddressOverflow)?,
            &mut data,
        )?;
        let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(address);
        ptr.copy_from_slice(0, &data)
            .ok_or(PeImageAccessError::MemoryAccess)?;
        protect_pages(self.page_manager, address, len, *prot)
    }

    fn protect(
        &mut self,
        address: usize,
        len: usize,
        prot: &Protection,
    ) -> Result<(), Self::Error> {
        protect_pages(self.page_manager, address, len, *prot)
    }
}

struct PeImageMemory;

impl AccessMemory for PeImageMemory {
    fn read(&mut self, address: usize, buf: &mut [u8]) -> Result<(), Fault> {
        let ptr = <Platform as RawPointerProvider>::RawConstPointer::<u8>::from_usize(address);
        buf.copy_from_slice(&ptr.to_owned_slice(buf.len()).ok_or(Fault)?);
        Ok(())
    }

    fn write(&mut self, address: usize, data: &[u8]) -> Result<(), Fault> {
        let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(address);
        ptr.copy_from_slice(0, data).ok_or(Fault)
    }
}

fn make_pages_writable(
    page_manager: &WindowsPageManager,
    address: usize,
    len: usize,
) -> Result<(), PeImageAccessError> {
    let (start, len) = page_range(address, len)?;
    if len == 0 {
        return Ok(());
    }
    let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(start);
    // SAFETY: Loading happens before the initial guest thread is allowed to execute.
    unsafe { page_manager.make_pages_writable(ptr, len)? };
    Ok(())
}

fn protect_pages(
    page_manager: &WindowsPageManager,
    address: usize,
    len: usize,
    prot: Protection,
) -> Result<(), PeImageAccessError> {
    let (start, len) = page_range(address, len)?;
    if len == 0 {
        return Ok(());
    }
    let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(start);
    // SAFETY: Loading and final image protection happen before guest execution.
    unsafe {
        match (prot.read, prot.write, prot.execute) {
            (_, true, true) => page_manager.make_pages_rwx(ptr, len)?,
            (_, true, false) => page_manager.make_pages_writable(ptr, len)?,
            (_, false, true) => page_manager.make_pages_executable(ptr, len)?,
            (true, false, false) => page_manager.make_pages_readable(ptr, len)?,
            (false, false, false) => page_manager.make_pages_inaccessible(ptr, len)?,
        }
    }
    Ok(())
}

fn page_range(address: usize, len: usize) -> Result<(usize, usize), PeImageAccessError> {
    if len == 0 {
        return Ok((address, 0));
    }
    let start = page_align_down(address);
    let end = page_align_up(
        address
            .checked_add(len)
            .ok_or(PeImageAccessError::AddressOverflow)?,
    )
    .ok_or(PeImageAccessError::AddressOverflow)?;
    Ok((start, end - start))
}

fn page_align_down(address: usize) -> usize {
    address & !(PAGE_SIZE - 1)
}

fn page_align_up(address: usize) -> Option<usize> {
    address.checked_add(PAGE_SIZE - 1).map(page_align_down)
}
