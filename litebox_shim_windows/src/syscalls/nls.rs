// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::format;
use alloc::string::String;
use litebox::fd::TypedFd;
use litebox::fs::errors::{FileStatusError, OpenError, PathError, ReadError};
use litebox::fs::{FileType, Mode, OFlags};
use litebox::mm::linux::{CreatePagesFlags, MappingError, NonZeroPageSize};
use litebox::platform::page_mgmt::MemoryRegionPermissions;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_windows::nt_status::NtStatus;
use litebox_platform_multiplex::Platform;

use super::mm;
use crate::loader::nt_types::ProcessEnvironmentBlock;
use crate::{NtShimFS, PAGE_SIZE, Task};

type GuestMutPointer<T> = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<T>;

const ANSI_CODE_PAGE: u32 = 1252;
const OEM_CODE_PAGE: u32 = 437;
const UNICODE_CASE_TABLE: u32 = 10000;
const CODE_PAGE_SECTION_TYPE: u32 = 11;

#[derive(Clone, Copy)]
struct NlsSectionRequest {
    section_type: u32,
    section_data: u32,
    context_data: usize,
    section_pointer: GuestMutPointer<usize>,
    section_size: Option<GuestMutPointer<u32>>,
}

#[derive(Clone, Copy)]
struct MappedNlsSection {
    address: usize,
    len: usize,
}

struct NlsSectionFile<FS: NtShimFS> {
    fd: TypedFd<FS>,
    len: usize,
}

impl<FS: NtShimFS> Task<FS> {
    pub(crate) fn handle_nt_get_nls_section_ptr(
        &self,
        section_type: u32,
        section_data: u32,
        context_data: usize,
        section_pointer: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<usize>,
        section_size: Option<
            <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u32>,
        >,
    ) -> NtStatus {
        let request = NlsSectionRequest {
            section_type,
            section_data,
            context_data,
            section_pointer,
            section_size,
        };

        if request.section_pointer.as_usize() == 0 {
            return NtStatus::INVALID_PARAMETER;
        }
        let cache_key = (request.section_type, request.section_data);

        if let Some((mapped_address, section_len)) = self
            .process
            .nls_section_mappings
            .lock()
            .get(&cache_key)
            .copied()
        {
            return self.write_nls_section_result(
                request,
                MappedNlsSection {
                    address: mapped_address,
                    len: section_len,
                },
                true,
            );
        }

        let section_file = match self.open_nls_section_file(request) {
            Ok(section_file) => section_file,
            Err(status) => {
                litebox_util_log::debug!(
                    section_type = request.section_type,
                    section_data = request.section_data,
                    status:? = status;
                    "NtGetNlsSectionPtr section is not available"
                );
                return status;
            }
        };
        let section_len = section_file.len;
        let alloc_len = section_len.next_multiple_of(PAGE_SIZE);
        let Some(page_len) = NonZeroPageSize::<PAGE_SIZE>::new(alloc_len) else {
            return NtStatus::INVALID_PARAMETER;
        };

        let mut copy_status = None;
        let mapping = mm::create_pages(
            &self.global.page_manager,
            None,
            page_len,
            CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
            MemoryRegionPermissions::READ,
            |ptr| match self.copy_nls_section_file(&section_file.fd, section_len, ptr) {
                Ok(copied) => Ok(copied),
                Err(status) => {
                    copy_status = Some(status);
                    Err(MappingError::OutOfMemory)
                }
            },
        );
        let _ = self.fs.close(&section_file.fd);
        let Ok(mapping) = mapping else {
            return copy_status.unwrap_or(NtStatus::NO_MEMORY);
        };
        let mapped_address = mapping.as_usize();

        self.process
            .nls_section_mappings
            .lock()
            .insert(cache_key, (mapped_address, alloc_len));

        self.write_nls_section_result(
            request,
            MappedNlsSection {
                address: mapped_address,
                len: alloc_len,
            },
            false,
        )
    }

    fn open_nls_section_file(
        &self,
        request: NlsSectionRequest,
    ) -> Result<NlsSectionFile<FS>, NtStatus> {
        let Some(path) = nls_section_file_path(request.section_type, request.section_data) else {
            return Err(NtStatus::OBJECT_NAME_NOT_FOUND);
        };

        let fd = self
            .fs
            .open(path.as_str(), OFlags::RDONLY, Mode::empty())
            .map_err(map_nls_open_error)?;

        let status = match self.fs.fd_file_status(&fd) {
            Ok(status) => status,
            Err(error) => {
                let _ = self.fs.close(&fd);
                return Err(map_nls_file_status_error(error));
            }
        };
        if status.file_type != FileType::RegularFile {
            let _ = self.fs.close(&fd);
            return Err(NtStatus::OBJECT_TYPE_MISMATCH);
        }
        let section_len = status.size;
        if section_len == 0 {
            let _ = self.fs.close(&fd);
            litebox_util_log::debug!(
                path = path.as_str();
                "NtGetNlsSectionPtr NLS file is empty"
            );
            return Err(NtStatus::OBJECT_NAME_NOT_FOUND);
        }

        Ok(NlsSectionFile {
            fd,
            len: section_len,
        })
    }

    fn copy_nls_section_file(
        &self,
        fd: &TypedFd<FS>,
        section_len: usize,
        output: GuestMutPointer<u8>,
    ) -> Result<usize, NtStatus> {
        let mut offset = 0;
        while offset < section_len {
            let mut chunk = [0; PAGE_SIZE];
            let remaining = section_len - offset;
            let chunk_len = remaining.min(PAGE_SIZE);
            let read = match self.fs.read(fd, &mut chunk[..chunk_len], Some(offset)) {
                Ok(read) => read,
                Err(error) => return Err(map_nls_read_error(error)),
            };
            if read == 0 {
                return Err(NtStatus::END_OF_FILE);
            }
            if output
                .write_slice_at_offset(
                    isize::try_from(offset).expect("u32 section offset fits in isize"),
                    &chunk[..read],
                )
                .is_none()
            {
                return Err(NtStatus::ACCESS_VIOLATION);
            }
            offset += read;
        }
        Ok(offset)
    }

    fn write_nls_section_result(
        &self,
        request: NlsSectionRequest,
        mapped_section: MappedNlsSection,
        cached: bool,
    ) -> NtStatus {
        if request
            .section_pointer
            .write_at_offset(0, mapped_section.address)
            .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        let len = u32::try_from(mapped_section.len).unwrap_or(u32::MAX);
        if let Some(section_size) = request.section_size
            && section_size.write_at_offset(0, len).is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        self.set_peb_nls_pointer(request.section_data, mapped_section.address);

        litebox_util_log::debug!(
            section_type = request.section_type,
            section_data = request.section_data,
            context_data:% = format_args!("{:#x}", request.context_data),
            mapped_address:% = format_args!("{:#x}", mapped_section.address),
            section_len = mapped_section.len,
            cached = cached;
            "Handled NtGetNlsSectionPtr syscall"
        );

        NtStatus::SUCCESS
    }

    fn set_peb_nls_pointer(&self, section_data: u32, mapped_address: usize) {
        if self.process.peb_address == 0 {
            return;
        }

        let Some(field_offset) = (match section_data {
            ANSI_CODE_PAGE => Some(core::mem::offset_of!(
                ProcessEnvironmentBlock,
                ansi_code_page_data
            )),
            OEM_CODE_PAGE => Some(core::mem::offset_of!(
                ProcessEnvironmentBlock,
                oem_code_page_data
            )),
            UNICODE_CASE_TABLE => Some(core::mem::offset_of!(
                ProcessEnvironmentBlock,
                unicode_case_table_data
            )),
            _ => None,
        }) else {
            return;
        };

        let peb_field =
            <Platform as litebox::platform::RawPointerProvider>::RawMutPointer::<usize>::from_usize(
                self.process.peb_address + field_offset,
            );
        let _ = peb_field.write_at_offset(0, mapped_address);
    }
}

fn nls_section_file_path(section_type: u32, section_data: u32) -> Option<String> {
    if section_type == CODE_PAGE_SECTION_TYPE {
        Some(format!("/Windows/System32/c_{section_data}.nls"))
    } else {
        None
    }
}

fn map_nls_open_error(error: OpenError) -> NtStatus {
    match error {
        OpenError::PathError(
            PathError::NoSuchFileOrDirectory
            | PathError::MissingComponent
            | PathError::ComponentNotADirectory,
        ) => NtStatus::OBJECT_NAME_NOT_FOUND,
        OpenError::PathError(PathError::NoSearchPerms { .. }) | OpenError::AccessNotAllowed => {
            NtStatus::ACCESS_DENIED
        }
        _ => NtStatus::UNSUCCESSFUL,
    }
}

fn map_nls_file_status_error(error: FileStatusError) -> NtStatus {
    match error {
        FileStatusError::PathError(
            PathError::NoSuchFileOrDirectory
            | PathError::MissingComponent
            | PathError::ComponentNotADirectory,
        ) => NtStatus::OBJECT_NAME_NOT_FOUND,
        FileStatusError::PathError(PathError::NoSearchPerms { .. }) => NtStatus::ACCESS_DENIED,
        _ => NtStatus::UNSUCCESSFUL,
    }
}

fn map_nls_read_error(error: ReadError) -> NtStatus {
    match error {
        ReadError::NotForReading => NtStatus::ACCESS_DENIED,
        _ => NtStatus::UNSUCCESSFUL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use litebox::platform::RawPointerProvider;
    use zerocopy::{FromBytes, IntoBytes};

    extern crate std;

    type MutPtr<T> = <Platform as RawPointerProvider>::RawMutPointer<T>;

    #[cfg(target_os = "windows")]
    unsafe extern "system" {
        fn NtGetNlsSectionPtr(
            section_type: u32,
            section_data: u32,
            context_data: *mut core::ffi::c_void,
            section_pointer: *mut *const u8,
            section_size: *mut u32,
        ) -> i32;
    }

    fn mut_ptr<T: FromBytes + IntoBytes>(value: &mut T) -> MutPtr<T> {
        MutPtr::from_usize(core::ptr::from_mut(value).cast::<u8>() as usize)
    }

    #[test]
    fn nt_get_nls_section_ptr_maps_file_backed_section() {
        let section_bytes = vec![1, 2, 3, 4, 5];
        let task = crate::tests::test_task_with_nls_files(&[(
            "/Windows/System32/c_1252.nls",
            section_bytes.as_slice(),
        )]);
        let mut section_pointer = 0usize;
        let mut section_size = 0u32;

        assert_eq!(
            task.handle_nt_get_nls_section_ptr(
                11,
                1252,
                0,
                mut_ptr(&mut section_pointer),
                Some(mut_ptr(&mut section_size)),
            ),
            NtStatus::SUCCESS
        );

        assert_ne!(section_pointer, 0);
        assert_eq!(section_size, u32::try_from(PAGE_SIZE).unwrap());
        let mapped =
            <Platform as RawPointerProvider>::RawConstPointer::<u8>::from_usize(section_pointer);
        assert_eq!(
            mapped.to_owned_slice(section_bytes.len()).unwrap().as_ref(),
            section_bytes.as_slice()
        );

        let mut second_section_pointer = 0usize;
        assert_eq!(
            task.handle_nt_get_nls_section_ptr(
                11,
                1252,
                0,
                mut_ptr(&mut second_section_pointer),
                None,
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(second_section_pointer, section_pointer);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn nt_get_nls_section_ptr_matches_host_section_content() {
        let host_file_bytes = std::fs::read(
            std::path::PathBuf::from(
                std::env::var_os("SystemRoot")
                    .unwrap_or_else(|| std::ffi::OsString::from(r"C:\Windows")),
            )
            .join("System32")
            .join("c_1252.nls"),
        )
        .unwrap();
        let task = crate::tests::test_task_with_nls_files(&[(
            "/Windows/System32/c_1252.nls",
            host_file_bytes.as_slice(),
        )]);

        let mut host_section_pointer = core::ptr::null::<u8>();
        let mut host_section_size = 0u32;
        // SAFETY: The pointers reference local output variables, and the section type/data pair is
        // the same supported codepage section requested by normal Windows process startup.
        let host_status = unsafe {
            NtGetNlsSectionPtr(
                CODE_PAGE_SECTION_TYPE,
                ANSI_CODE_PAGE,
                core::ptr::null_mut(),
                core::ptr::addr_of_mut!(host_section_pointer),
                core::ptr::addr_of_mut!(host_section_size),
            )
        };
        assert_eq!(
            NtStatus::from_raw(u32::from_ne_bytes(host_status.to_ne_bytes())),
            NtStatus::SUCCESS
        );
        assert!(!host_section_pointer.is_null());

        let mut section_pointer = 0usize;
        let mut section_size = 0u32;
        assert_eq!(
            task.handle_nt_get_nls_section_ptr(
                CODE_PAGE_SECTION_TYPE,
                ANSI_CODE_PAGE,
                0,
                mut_ptr(&mut section_pointer),
                Some(mut_ptr(&mut section_size)),
            ),
            NtStatus::SUCCESS
        );

        let host_section_len = usize::try_from(host_section_size).unwrap();
        assert_eq!(section_size, host_section_size);
        let mapped =
            <Platform as RawPointerProvider>::RawConstPointer::<u8>::from_usize(section_pointer);
        // SAFETY: A successful host NtGetNlsSectionPtr returned a non-null pointer and size for a
        // process-lifetime read-only NLS mapping.
        let host_section =
            unsafe { core::slice::from_raw_parts(host_section_pointer, host_section_len) };
        assert_eq!(
            mapped.to_owned_slice(host_section_len).unwrap().as_ref(),
            host_section
        );
    }

    #[test]
    fn nt_get_nls_section_ptr_rejects_invalid_arguments() {
        let bytes = [0xaa];
        let task = crate::tests::test_task_with_nls_files(&[(
            "/Windows/System32/c_437.nls",
            bytes.as_slice(),
        )]);
        let mut section_pointer = 0usize;

        assert_eq!(
            task.handle_nt_get_nls_section_ptr(11, 437, 0, MutPtr::from_usize(0), None),
            NtStatus::INVALID_PARAMETER
        );
        assert_eq!(
            task.handle_nt_get_nls_section_ptr(11, 1252, 0, mut_ptr(&mut section_pointer), None,),
            NtStatus::OBJECT_NAME_NOT_FOUND
        );
        assert_eq!(section_pointer, 0);
    }
}
