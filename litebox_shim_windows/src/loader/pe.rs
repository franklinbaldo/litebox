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
    AccessMemory, Fault, MapMemory, MappingInfo, PeDataDirectory, PeExport, PeImageInfo,
    PeLoadError, PeParseError, PeParsedFile, Protection, ReadAt,
};
use litebox_platform_multiplex::Platform;
use thiserror::Error;
use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT, CONTEXT_CONTROL_AMD64, CONTEXT_INTEGER_AMD64,
};
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes};

use crate::nt_types::{
    ClientId, KiUserInvertedFunctionTableEntry, KiUserInvertedFunctionTableHeader,
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
const INITIAL_PROCESS_ID: usize = 1;
const INITIAL_THREAD_ID: usize = 1;
const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
const PROCESS_ENVIRONMENT_ALLOCATION_PROTECT: u32 = 0x04;
const API_SET_NAMESPACE_VERSION: u32 = 6;
const API_SET_NAMESPACE_ENTRY_FLAGS: u32 = 1;
const API_SET_NAMESPACE_HASH_FACTOR: u32 = 31;
const MAX_API_SET_NAMESPACE_SIZE: usize = 16 * 1024 * 1024;
const WINDOWS_OS_MAJOR_VERSION: u32 = 10;
const WINDOWS_OS_MINOR_VERSION: u32 = 0;
const WINDOWS_OS_BUILD_NUMBER: u16 = 19041;
const WINDOWS_OS_PLATFORM_WIN32_NT: u32 = 2;
const USER_MODE_CODE_SELECTOR: u16 = 0x33;
const USER_MODE_DATA_SELECTOR: u16 = 0x2b;

/// Struct to hold the information needed to start the program.
pub(crate) struct PeLoadInfo {
    pub(crate) entry_point: usize,
    pub(crate) stack_top: usize,
    pub(crate) initial_context: Option<usize>,
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
        let initial_context_stack_top = initial_stack_top(stack_top);
        let environment = self.create_process_environment(
            &image.image,
            image_base_address,
            path,
            ntdll
                .as_ref()
                .map(|_| (application_entry_point, initial_context_stack_top)),
        )?;
        let initial_context = environment.initial_context;

        Ok(PeLoadInfo {
            entry_point,
            stack_top,
            initial_context,
            application_mapping: image.mapping,
            ntdll_mapping: ntdll.map(|image| image.mapping),
            environment,
        })
    }

    fn create_process_environment(
        &self,
        image: &PeImageInfo,
        image_base_address: usize,
        image_path: &str,
        initial_context: Option<(usize, usize)>,
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
        let api_set_map = build_api_set_namespace()?;
        let api_set_map_ptr = create_pages(api_set_map.len())?;
        write_slice(api_set_map_ptr, &api_set_map).ok_or(PeImageAccessError::MemoryAccess)?;
        let initial_context = initial_context
            .map(|(entry_point, stack_top)| {
                let context_ptr = create_pages(size_of::<CONTEXT>())?;
                let context = initial_thread_context(entry_point, stack_top);
                let context_bytes = context_as_bytes(&context);
                write_slice(context_ptr, context_bytes).ok_or(PeImageAccessError::MemoryAccess)?;
                Ok::<usize, PeImageAccessError>(context_ptr)
            })
            .transpose()?;

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
        peb.api_set_map = api_set_map_ptr;
        peb.number_of_processors = 1;
        peb.heap_segment_reserve = image.size_of_heap_reserve as u64;
        peb.heap_segment_commit = image.size_of_heap_commit as u64;
        peb.active_process_affinity_mask = 1;
        peb.os_major_version = WINDOWS_OS_MAJOR_VERSION;
        peb.os_minor_version = WINDOWS_OS_MINOR_VERSION;
        peb.os_build_number = WINDOWS_OS_BUILD_NUMBER;
        peb.os_platform_id = WINDOWS_OS_PLATFORM_WIN32_NT;
        peb.image_subsystem = u32::from(image.subsystem);
        peb.image_subsystem_major_version = u32::from(image.major_subsystem_version);
        peb.image_subsystem_minor_version = u32::from(image.minor_subsystem_version);
        write_value(peb_ptr, peb).ok_or(PeImageAccessError::MemoryAccess)?;

        let mut teb = ThreadEnvironmentBlock::new_zeroed();
        teb.nt_tib.self_pointer = teb_ptr;
        teb.client_id = ClientId {
            unique_process: INITIAL_PROCESS_ID,
            unique_thread: INITIAL_THREAD_ID,
        };
        teb.process_environment_block = peb_ptr;
        teb.real_client_id = teb.client_id;
        write_value(teb_ptr, teb).ok_or(PeImageAccessError::MemoryAccess)?;
        Ok(WindowsProcessEnvironment {
            peb: peb_ptr,
            _process_parameters: process_parameters_ptr,
            teb: teb_ptr,
            initial_context,
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
    pub(crate) initial_context: Option<usize>,
    pub(crate) virtual_allocations: Vec<WindowsVirtualAllocation>,
}

fn initial_stack_top(stack_top: usize) -> usize {
    if stack_top.is_multiple_of(16) {
        stack_top - core::mem::size_of::<usize>()
    } else {
        stack_top
    }
}

fn initial_thread_context(entry_point: usize, stack_top: usize) -> CONTEXT {
    CONTEXT {
        ContextFlags: CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64,
        SegCs: USER_MODE_CODE_SELECTOR,
        SegDs: USER_MODE_DATA_SELECTOR,
        SegEs: USER_MODE_DATA_SELECTOR,
        SegFs: USER_MODE_DATA_SELECTOR,
        SegGs: USER_MODE_DATA_SELECTOR,
        SegSs: USER_MODE_DATA_SELECTOR,
        EFlags: 0x202,
        Rsp: stack_top as u64,
        Rip: entry_point as u64,
        ..CONTEXT::default()
    }
}

fn context_as_bytes(context: &CONTEXT) -> &[u8] {
    // SAFETY: `CONTEXT` is a `repr(C)` Windows ABI struct from `windows-sys`.
    // The loader only copies its initialized bytes into guest memory.
    unsafe {
        core::slice::from_raw_parts(
            core::ptr::from_ref(context).cast::<u8>(),
            size_of::<CONTEXT>(),
        )
    }
}

pub(crate) struct LoadedImage {
    pub(crate) mapping: MappingInfo,
    image: PeImageInfo,
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

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, FromBytes, Immutable, IntoBytes)]
struct ApiSetNamespace {
    version: u32,
    size: u32,
    flags: u32,
    count: u32,
    entry_offset: u32,
    hash_offset: u32,
    hash_factor: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, FromBytes, Immutable, IntoBytes)]
struct ApiSetNamespaceEntry {
    flags: u32,
    name_offset: u32,
    name_length: u32,
    hashed_length: u32,
    value_offset: u32,
    value_count: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, FromBytes, Immutable, IntoBytes)]
struct ApiSetValueEntry {
    flags: u32,
    name_offset: u32,
    name_length: u32,
    value_offset: u32,
    value_length: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, FromBytes, Immutable, IntoBytes)]
struct ApiSetHashEntry {
    hash: u32,
    index: u32,
}

const API_SET_MAPPINGS: &[(&str, &str)] = &[
    ("api-ms-win-core-apiquery-l1-1-0", "ntdll.dll"),
    ("api-ms-win-core-apiquery-l1-1-2", "ntdll.dll"),
    ("api-ms-win-core-apiquery-l2-1-1", "kernelbase.dll"),
    ("api-ms-win-core-appcompat-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-appcompat-l1-1-1", "kernelbase.dll"),
    ("api-ms-win-core-appinit-l1-1-0", "kernel32.dll"),
    ("api-ms-win-core-atoms-l1-1-0", "kernel32.dll"),
    ("api-ms-win-core-backgroundtask-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-calendar-l1-1-0", "kernel32.dll"),
    ("api-ms-win-core-comm-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-comm-l1-1-2", "kernelbase.dll"),
    ("api-ms-win-core-commandlinetoargv-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-console-ansi-l2-1-0", "kernel32.dll"),
    ("api-ms-win-core-console-internal-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-console-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-console-l1-2-0", "kernelbase.dll"),
    ("api-ms-win-core-console-l1-2-1", "kernelbase.dll"),
    ("api-ms-win-core-console-l1-2-2", "kernelbase.dll"),
    ("api-ms-win-core-console-l2-1-0", "kernelbase.dll"),
    ("api-ms-win-core-console-l2-2-0", "kernelbase.dll"),
    ("api-ms-win-core-console-l3-1-0", "kernelbase.dll"),
    ("api-ms-win-core-console-l3-2-0", "kernelbase.dll"),
    ("api-ms-win-core-crt-l1-1-0", "ntdll.dll"),
    ("api-ms-win-core-crt-l2-1-0", "kernelbase.dll"),
    ("api-ms-win-core-datetime-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-datetime-l1-1-1", "kernelbase.dll"),
    ("api-ms-win-core-datetime-l1-1-2", "kernelbase.dll"),
    ("api-ms-win-core-debug-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-debug-l1-1-1", "kernelbase.dll"),
    ("api-ms-win-core-debug-l1-1-2", "kernelbase.dll"),
    ("api-ms-win-core-delayload-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-delayload-l1-1-1", "kernelbase.dll"),
    ("api-ms-win-downlevel-shlwapi-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-errorhandling-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-errorhandling-l1-1-2", "kernelbase.dll"),
    ("api-ms-win-core-errorhandling-l1-1-3", "kernelbase.dll"),
    ("api-ms-win-core-fibers-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-fibers-l1-1-2", "kernelbase.dll"),
    ("api-ms-win-core-fibers-l2-1-0", "kernelbase.dll"),
    ("api-ms-win-core-fibers-l2-1-1", "kernelbase.dll"),
    ("api-ms-win-core-file-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-file-l1-1-1", "kernelbase.dll"),
    ("api-ms-win-core-file-l1-2-0", "kernelbase.dll"),
    ("api-ms-win-core-file-l1-2-1", "kernelbase.dll"),
    ("api-ms-win-core-file-l1-2-2", "kernelbase.dll"),
    ("api-ms-win-core-file-l1-2-3", "kernelbase.dll"),
    ("api-ms-win-core-file-l1-2-5", "kernelbase.dll"),
    ("api-ms-win-core-file-l2-1-0", "kernelbase.dll"),
    ("api-ms-win-core-file-l2-1-1", "kernelbase.dll"),
    ("api-ms-win-core-file-l2-1-2", "kernelbase.dll"),
    ("api-ms-win-core-file-l2-1-3", "kernelbase.dll"),
    ("api-ms-win-core-file-l2-1-4", "kernelbase.dll"),
    ("api-ms-win-core-handle-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-heap-obsolete-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-heap-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-heap-l2-1-0", "kernelbase.dll"),
    ("api-ms-win-core-heap-l1-2-0", "kernelbase.dll"),
    ("api-ms-win-core-interlocked-l1-1-1", "kernelbase.dll"),
    ("api-ms-win-core-io-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-io-l1-1-1", "kernelbase.dll"),
    ("api-ms-win-core-job-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-largeinteger-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-libraryloader-l1-1-1", "kernelbase.dll"),
    ("api-ms-win-core-libraryloader-l1-2-0", "kernelbase.dll"),
    ("api-ms-win-core-libraryloader-l1-2-1", "kernelbase.dll"),
    ("api-ms-win-core-libraryloader-l1-2-2", "kernelbase.dll"),
    ("api-ms-win-core-libraryloader-l1-2-3", "kernelbase.dll"),
    ("api-ms-win-core-libraryloader-l2-1-0", "kernelbase.dll"),
    ("api-ms-win-core-localization-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-localization-l1-2-0", "kernelbase.dll"),
    ("api-ms-win-core-localization-l1-2-4", "kernelbase.dll"),
    ("api-ms-win-core-localization-l2-1-0", "kernelbase.dll"),
    (
        "api-ms-win-core-localization-private-l1-1-0",
        "kernelbase.dll",
    ),
    ("api-ms-win-core-localregistry-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-memory-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-memory-l1-1-1", "kernelbase.dll"),
    ("api-ms-win-core-memory-l1-1-2", "kernelbase.dll"),
    ("api-ms-win-core-memory-l1-1-9", "kernelbase.dll"),
    ("api-ms-win-core-misc-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-namedpipe-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-namedpipe-l1-2-1", "kernelbase.dll"),
    ("api-ms-win-core-namedpipe-l1-2-2", "kernelbase.dll"),
    ("api-ms-win-core-namespace-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-normalization-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-path-l1-1-0", "kernelbase.dll"),
    (
        "api-ms-win-core-processenvironment-l1-1-0",
        "kernelbase.dll",
    ),
    (
        "api-ms-win-core-processenvironment-l1-1-1",
        "kernelbase.dll",
    ),
    (
        "api-ms-win-core-processenvironment-l1-2-0",
        "kernelbase.dll",
    ),
    ("api-ms-win-core-processsnapshot-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-processthreads-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-processthreads-l1-1-1", "kernelbase.dll"),
    ("api-ms-win-core-processthreads-l1-1-2", "kernelbase.dll"),
    ("api-ms-win-core-processthreads-l1-1-3", "kernelbase.dll"),
    ("api-ms-win-core-processthreads-l1-1-8", "kernel32.dll"),
    ("api-ms-win-core-processtopology-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-profile-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-pcw-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-psapi-ansi-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-psapi-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-realtime-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-registry-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-rtlsupport-l1-1-0", "ntdll.dll"),
    ("api-ms-win-core-rtlsupport-l1-1-1", "ntdll.dll"),
    ("api-ms-win-core-rtlsupport-l1-2-2", "ntdll.dll"),
    ("api-ms-win-core-sidebyside-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-string-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-string-l2-1-1", "kernelbase.dll"),
    ("api-ms-win-core-synch-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-synch-l1-1-1", "kernelbase.dll"),
    ("api-ms-win-core-synch-l1-2-0", "kernelbase.dll"),
    ("api-ms-win-core-synch-l1-2-1", "kernelbase.dll"),
    ("api-ms-win-core-sysinfo-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-sysinfo-l1-1-1", "kernelbase.dll"),
    ("api-ms-win-core-sysinfo-l1-2-0", "kernelbase.dll"),
    ("api-ms-win-core-sysinfo-l1-2-1", "kernelbase.dll"),
    ("api-ms-win-core-sysinfo-l1-2-3", "kernelbase.dll"),
    ("api-ms-win-core-sysinfo-l1-2-8", "kernelbase.dll"),
    ("api-ms-win-core-systemtopology-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-systemtopology-l1-1-1", "kernelbase.dll"),
    ("api-ms-win-core-threadpool-legacy-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-threadpool-l1-2-0", "kernelbase.dll"),
    (
        "api-ms-win-core-threadpool-private-l1-1-0",
        "kernelbase.dll",
    ),
    ("api-ms-win-core-timezone-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-util-l1-1-0", "kernelbase.dll"),
    (
        "api-ms-win-core-windowserrorreporting-l1-1-0",
        "kernelbase.dll",
    ),
    (
        "api-ms-win-core-windowserrorreporting-l1-1-1",
        "kernelbase.dll",
    ),
    (
        "api-ms-win-core-windowserrorreporting-l1-1-2",
        "kernelbase.dll",
    ),
    (
        "api-ms-win-core-windowserrorreporting-l1-1-3",
        "kernelbase.dll",
    ),
    ("api-ms-win-core-wow64-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-wow64-l1-1-1", "kernelbase.dll"),
    ("api-ms-win-core-wow64-l1-1-3", "kernelbase.dll"),
    ("api-ms-win-core-xstate-l2-1-0", "kernelbase.dll"),
    ("api-ms-win-core-xstate-l2-1-1", "kernelbase.dll"),
    ("api-ms-win-core-xstate-l2-1-2", "kernelbase.dll"),
    ("api-ms-win-eventing-consumer-l1-1-0", "sechost.dll"),
    ("api-ms-win-eventing-consumer-l1-1-1", "sechost.dll"),
    ("api-ms-win-eventing-controller-l1-1-0", "sechost.dll"),
    ("api-ms-win-eventing-provider-l1-1-0", "advapi32.dll"),
    ("api-ms-win-security-audit-l1-1-0", "sechost.dll"),
    ("api-ms-win-security-audit-l1-1-1", "sechost.dll"),
    ("api-ms-win-security-appcontainer-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-security-base-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-security-base-l1-2-0", "kernelbase.dll"),
    ("api-ms-win-security-base-private-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-security-lsalookup-l1-1-0", "sechost.dll"),
    ("api-ms-win-security-sddl-l1-1-0", "sechost.dll"),
    ("api-ms-win-service-core-l1-1-0", "sechost.dll"),
    ("api-ms-win-service-core-l1-1-1", "sechost.dll"),
    ("api-ms-win-service-core-l1-1-2", "sechost.dll"),
    ("api-ms-win-service-management-l1-1-0", "sechost.dll"),
    ("api-ms-win-service-management-l2-1-0", "sechost.dll"),
    ("api-ms-win-service-private-l1-1-0", "sechost.dll"),
    ("api-ms-win-service-private-l1-1-2", "sechost.dll"),
    ("api-ms-win-service-private-l1-1-3", "sechost.dll"),
    ("api-ms-win-service-winsvc-l1-1-0", "sechost.dll"),
    ("ext-ms-win-appcompat-apphelp-l1-1-2", "apphelp.dll"),
    ("ext-ms-win-authz-context-l1-1-0", "authz.dll"),
    ("ext-ms-win-core-winrt-remote-l1-1-0", "rpcrtremote.dll"),
    ("ext-ms-win-oobe-query-l1-1-0", "kernelbase.dll"),
    (
        "ext-ms-win-packagevirtualizationcontext-l1-1-0",
        "kernelbase.dll",
    ),
    ("ext-ms-win-rpc-ssl-l1-1-0", "rpcrtremote.dll"),
];

fn build_api_set_namespace() -> Result<Vec<u8>, PeImageAccessError> {
    let mut mappings = API_SET_MAPPINGS.to_vec();
    mappings.sort_by_key(|mapping| mapping.0);

    let count = mappings.len();
    let entry_offset = size_of::<ApiSetNamespace>();
    let value_offset = checked_add(
        entry_offset,
        checked_mul(count, size_of::<ApiSetNamespaceEntry>())?,
    )?;
    let strings_offset = checked_add(
        value_offset,
        checked_mul(count, size_of::<ApiSetValueEntry>())?,
    )?;
    let mut string_data = Vec::new();
    let mut entries = Vec::with_capacity(count);
    let mut values = Vec::with_capacity(count);
    let mut hashes = Vec::with_capacity(count);

    for (index, mapping) in mappings.iter().enumerate() {
        let name = utf16_bytes(mapping.0)?;
        let host = utf16_bytes(mapping.1)?;
        let name_offset = checked_add(strings_offset, string_data.len())?;
        string_data.extend_from_slice(&name);
        let host_offset = checked_add(strings_offset, string_data.len())?;
        string_data.extend_from_slice(&host);
        let value_entry_offset = checked_add(
            value_offset,
            checked_mul(index, size_of::<ApiSetValueEntry>())?,
        )?;
        entries.push(ApiSetNamespaceEntry {
            flags: API_SET_NAMESPACE_ENTRY_FLAGS,
            name_offset: to_u32(name_offset)?,
            name_length: to_u32(name.len())?,
            hashed_length: to_u32(
                api_set_hashed_name_len(mapping.0)
                    .checked_mul(size_of::<u16>())
                    .ok_or(PeImageAccessError::AddressOverflow)?,
            )?,
            value_offset: to_u32(value_entry_offset)?,
            value_count: 1,
        });
        values.push(ApiSetValueEntry {
            flags: 0,
            name_offset: 0,
            name_length: 0,
            value_offset: to_u32(host_offset)?,
            value_length: to_u32(host.len())?,
        });
        hashes.push(ApiSetHashEntry {
            hash: api_set_hash(mapping.0),
            index: to_u32(index)?,
        });
    }

    let hash_offset =
        checked_add(strings_offset, string_data.len())?.next_multiple_of(size_of::<u32>());
    let size = checked_add(
        hash_offset,
        checked_mul(count, size_of::<ApiSetHashEntry>())?,
    )?;
    if size > MAX_API_SET_NAMESPACE_SIZE {
        return Err(PeImageAccessError::AddressOverflow);
    }
    hashes.sort_by_key(|entry| (entry.hash, entry.index));

    let namespace = ApiSetNamespace {
        version: API_SET_NAMESPACE_VERSION,
        size: to_u32(size)?,
        flags: 0,
        count: to_u32(count)?,
        entry_offset: to_u32(entry_offset)?,
        hash_offset: to_u32(hash_offset)?,
        hash_factor: API_SET_NAMESPACE_HASH_FACTOR,
    };

    let mut bytes = Vec::with_capacity(size);
    append_struct(&mut bytes, &namespace);
    for entry in &entries {
        append_struct(&mut bytes, entry);
    }
    for value in &values {
        append_struct(&mut bytes, value);
    }
    bytes.extend_from_slice(&string_data);
    bytes.resize(hash_offset, 0);
    for hash in &hashes {
        append_struct(&mut bytes, hash);
    }
    debug_assert_eq!(bytes.len(), size);
    Ok(bytes)
}

fn append_struct<T: IntoBytes + Immutable>(bytes: &mut Vec<u8>, value: &T) {
    bytes.extend_from_slice(value.as_bytes());
}

fn utf16_bytes(value: &str) -> Result<Vec<u8>, PeImageAccessError> {
    let mut bytes = Vec::with_capacity(
        value
            .len()
            .checked_mul(size_of::<u16>())
            .ok_or(PeImageAccessError::AddressOverflow)?,
    );
    for unit in value.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    Ok(bytes)
}

fn api_set_hashed_name_len(name: &str) -> usize {
    name.rfind('-').unwrap_or(name.len())
}

fn api_set_hash(name: &str) -> u32 {
    name[..api_set_hashed_name_len(name)]
        .bytes()
        .fold(0, |hash, byte| {
            hash.wrapping_mul(API_SET_NAMESPACE_HASH_FACTOR)
                .wrapping_add(u32::from(byte.to_ascii_lowercase()))
        })
}

fn checked_add(left: usize, right: usize) -> Result<usize, PeImageAccessError> {
    left.checked_add(right)
        .ok_or(PeImageAccessError::AddressOverflow)
}

fn checked_mul(left: usize, right: usize) -> Result<usize, PeImageAccessError> {
    left.checked_mul(right)
        .ok_or(PeImageAccessError::AddressOverflow)
}

fn to_u32(value: usize) -> Result<u32, PeImageAccessError> {
    u32::try_from(value).map_err(|_| PeImageAccessError::AddressOverflow)
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
    let image = parsed.image;
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
        image,
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

#[cfg(test)]
mod tests {
    use super::*;

    extern crate std;

    #[cfg(windows)]
    unsafe extern "system" {
        fn RtlGetCurrentPeb() -> *const ProcessEnvironmentBlock;
    }

    impl ApiSetNamespace {
        fn parse(bytes: &[u8]) -> Option<Self> {
            let namespace = Self::read_from_prefix(bytes).ok()?.0;
            let size = namespace.size as usize;
            if size != bytes.len()
                || !(size_of::<Self>()..=MAX_API_SET_NAMESPACE_SIZE).contains(&size)
            {
                return None;
            }
            if checked_table_end(
                namespace.entry_offset,
                namespace.count,
                size_of::<ApiSetNamespaceEntry>(),
            )? > size
            {
                return None;
            }
            if checked_table_end(
                namespace.hash_offset,
                namespace.count,
                size_of::<ApiSetHashEntry>(),
            )? > size
            {
                return None;
            }
            Some(namespace)
        }

        fn entry(self, bytes: &[u8], index: u32) -> Option<ApiSetNamespaceEntry> {
            if index >= self.count {
                return None;
            }
            ApiSetNamespaceEntry::parse(
                bytes,
                table_offset(self.entry_offset, index, size_of::<ApiSetNamespaceEntry>())?,
            )
        }

        fn hash_entry(self, bytes: &[u8], index: u32) -> Option<ApiSetHashEntry> {
            if index >= self.count {
                return None;
            }
            ApiSetHashEntry::parse(
                bytes,
                table_offset(self.hash_offset, index, size_of::<ApiSetHashEntry>())?,
            )
        }
    }

    impl ApiSetNamespaceEntry {
        fn parse(bytes: &[u8], offset: usize) -> Option<Self> {
            Some(Self::read_from_prefix(bytes.get(offset..)?).ok()?.0)
        }

        fn name(self, bytes: &[u8]) -> Option<String> {
            read_utf16_string(bytes, self.name_offset, self.name_length)
        }

        fn value(self, bytes: &[u8], index: u32) -> Option<ApiSetValueEntry> {
            if index >= self.value_count {
                return None;
            }
            ApiSetValueEntry::parse(
                bytes,
                table_offset(self.value_offset, index, size_of::<ApiSetValueEntry>())?,
            )
        }
    }

    impl ApiSetValueEntry {
        fn parse(bytes: &[u8], offset: usize) -> Option<Self> {
            Some(Self::read_from_prefix(bytes.get(offset..)?).ok()?.0)
        }

        fn name(self, bytes: &[u8]) -> Option<String> {
            read_utf16_string(bytes, self.name_offset, self.name_length)
        }

        fn value(self, bytes: &[u8]) -> Option<String> {
            read_utf16_string(bytes, self.value_offset, self.value_length)
        }
    }

    impl ApiSetHashEntry {
        fn parse(bytes: &[u8], offset: usize) -> Option<Self> {
            Some(Self::read_from_prefix(bytes.get(offset..)?).ok()?.0)
        }
    }

    fn table_offset(base: u32, index: u32, entry_size: usize) -> Option<usize> {
        (base as usize).checked_add((index as usize).checked_mul(entry_size)?)
    }

    fn checked_table_end(base: u32, count: u32, entry_size: usize) -> Option<usize> {
        table_offset(base, count, entry_size)
    }

    fn read_utf16_string(bytes: &[u8], offset: u32, len: u32) -> Option<String> {
        let offset = offset as usize;
        let len = len as usize;
        let end = offset.checked_add(len)?;
        let bytes = bytes.get(offset..end)?;
        let mut chunks = bytes.chunks_exact(size_of::<u16>());
        if !chunks.remainder().is_empty() {
            return None;
        }
        let units = chunks
            .by_ref()
            .map(|chunk| u16::from_le_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<_>>();
        Some(String::from_utf16_lossy(&units))
    }

    #[test]
    fn api_set_namespace_maps_apphelp_contract() {
        let namespace = build_api_set_namespace().expect("LiteBox API_SET_NAMESPACE builds");
        let api_set_map = ApiSetNamespace::parse(&namespace).expect("valid API_SET_NAMESPACE");

        for index in 0..api_set_map.count {
            let entry = api_set_map
                .entry(&namespace, index)
                .expect("namespace entry");
            if entry.name(&namespace).as_deref() == Some("ext-ms-win-appcompat-apphelp-l1-1-2") {
                let value = entry.value(&namespace, 0).expect("namespace value");
                assert_eq!(value.value(&namespace).as_deref(), Some("apphelp.dll"));
                return;
            }
        }

        panic!("apphelp API-set contract is missing");
    }

    #[test]
    #[ignore = "debug dump of LiteBox and host API_SET_NAMESPACE"]
    fn dump_host_api_set_namespace() {
        dump_host_api_set_namespace_impl();

        let namespace = build_api_set_namespace().expect("LiteBox API_SET_NAMESPACE builds");
        dump_api_set_namespace(
            "LiteBox synthetic API_SET_NAMESPACE",
            namespace.as_ptr() as usize,
            &namespace,
        );
    }

    fn dump_api_set_namespace(label: &str, ptr: usize, bytes: &[u8]) {
        let api_set_map = ApiSetNamespace::parse(bytes).expect("valid API_SET_NAMESPACE");
        std::println!("{label}");
        std::println!(
            "API_SET_NAMESPACE ptr={:#x} len={:#x} ({})",
            ptr,
            bytes.len(),
            bytes.len()
        );
        std::println!("     version: {:#010x}", api_set_map.version);
        std::println!("        size: {:#010x}", api_set_map.size);
        std::println!("       flags: {:#010x}", api_set_map.flags);
        std::println!("       count: {:#010x}", api_set_map.count);
        std::println!("entry_offset: {:#010x}", api_set_map.entry_offset);
        std::println!(" hash_offset: {:#010x}", api_set_map.hash_offset);
        std::println!(" hash_factor: {:#010x}", api_set_map.hash_factor);
        std::println!();
        dump_api_set_entries(bytes, api_set_map);
        std::println!();
        dump_api_set_hash_entries(bytes, api_set_map);
        std::println!();
        dump_hex(bytes);
        std::println!();
    }

    #[cfg(windows)]
    fn dump_host_api_set_namespace_impl() {
        let peb = unsafe {
            // SAFETY: `RtlGetCurrentPeb` returns the current process PEB pointer on Windows.
            RtlGetCurrentPeb().as_ref()
        }
        .expect("host PEB");
        let namespace_ptr = peb.api_set_map as *const ApiSetNamespace;
        let namespace = unsafe {
            // SAFETY: `ApiSetMap` points at the host process API_SET_NAMESPACE while the
            // process is alive; we read only the fixed header first to learn its size.
            namespace_ptr.as_ref()
        }
        .expect("host API_SET_NAMESPACE header");
        let size = namespace.size as usize;
        assert!(
            (size_of::<ApiSetNamespace>()..=MAX_API_SET_NAMESPACE_SIZE).contains(&size),
            "host API_SET_NAMESPACE has unexpected size {size:#x}"
        );
        let bytes = unsafe {
            // SAFETY: The size was read from the validated namespace header above, and the
            // host API-set namespace is immutable process-wide data owned by ntdll.
            core::slice::from_raw_parts(peb.api_set_map as *const u8, size)
        };
        dump_api_set_namespace("Host API_SET_NAMESPACE", peb.api_set_map, bytes);
    }

    #[cfg(not(windows))]
    fn dump_host_api_set_namespace_impl() {
        std::println!("Host API_SET_NAMESPACE unavailable on non-Windows hosts");
    }

    fn dump_api_set_entries(bytes: &[u8], namespace: ApiSetNamespace) {
        std::println!("entries:");
        for index in 0..namespace.count {
            let entry = namespace.entry(bytes, index).expect("namespace entry");
            std::println!(
                "  {index:04} name={} flags={:#x} hashed_len={} values={}",
                entry
                    .name(bytes)
                    .unwrap_or_else(|| String::from("<invalid>")),
                entry.flags,
                entry.hashed_length,
                entry.value_count
            );
            for value_index in 0..entry.value_count {
                let value = entry.value(bytes, value_index).expect("namespace value");
                let name = value.name(bytes).unwrap_or_default();
                let value_name = value
                    .value(bytes)
                    .unwrap_or_else(|| String::from("<invalid>"));
                std::println!(
                    "       [{value_index}] name={} value={} flags={:#x}",
                    if name.is_empty() { "<default>" } else { &name },
                    value_name,
                    value.flags
                );
            }
        }
    }

    fn dump_api_set_hash_entries(bytes: &[u8], namespace: ApiSetNamespace) {
        std::println!("hash entries:");
        for index in 0..namespace.count {
            let entry = namespace.hash_entry(bytes, index).expect("hash entry");
            std::println!(
                "  {index:04} hash={:#010x} index={}",
                entry.hash,
                entry.index
            );
        }
    }

    fn dump_hex(bytes: &[u8]) {
        for (base, chunk) in bytes.chunks(16).enumerate() {
            std::print!("{:#08x}  ", base * 16);
            for byte in chunk {
                std::print!("{byte:02x} ");
            }
            for _ in chunk.len()..16 {
                std::print!("   ");
            }
            std::print!(" |");
            for byte in chunk {
                let ch = if byte.is_ascii_graphic() || *byte == b' ' {
                    char::from(*byte)
                } else {
                    '.'
                };
                std::print!("{ch}");
            }
            std::println!("|");
        }
    }
}
