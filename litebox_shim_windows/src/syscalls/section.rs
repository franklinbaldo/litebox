// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::string::String;

use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::fs::{Mode, OFlags};
use litebox::mm::linux::NonZeroPageSize;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _, RawPointerProvider};
use litebox_common_windows::nt_status::NtStatus;

use crate::loader::WindowsLoadError;
use crate::loader::pe;
use crate::syscalls::object::{ObjectAttributes, read_object_attributes, read_unicode_string};
use crate::{
    Handle, NtShimFS, Platform, Task, WindowsSectionView, insert_raw_handle, remove_raw_handle,
};
use crate::{PAGE_SIZE, ProcessHandle};

type GuestMutPointer<T> = <Platform as RawPointerProvider>::RawMutPointer<T>;

const VIEW_SHARE: u32 = 1;
const VIEW_UNMAP: u32 = 2;
const MEM_TOP_DOWN: u32 = 0x100000;
const MEM_DIFFERENT_IMAGE_BASE_OK: u32 = 0x800000;
const SUPPORTED_MAP_ALLOCATION_TYPES: u32 = MEM_TOP_DOWN | MEM_DIFFERENT_IMAGE_BASE_OK;
const IMAGE_EXTENSION_SIZE: usize = PAGE_SIZE;

pub(crate) struct SectionSubsystem;

impl FdEnabledSubsystem for SectionSubsystem {
    type Entry = SectionObject;
}

impl FdEnabledSubsystemEntry for SectionObject {}

pub(crate) struct SectionObject {
    object_path: String,
    fs_path: String,
}

pub(crate) struct MapViewOfSectionRequest {
    pub(crate) section_handle: Handle,
    pub(crate) process_handle: ProcessHandle,
    pub(crate) base_address: GuestMutPointer<usize>,
    pub(crate) zero_bits: usize,
    pub(crate) commit_size: usize,
    pub(crate) section_offset: Option<GuestMutPointer<i64>>,
    pub(crate) view_size: GuestMutPointer<usize>,
    pub(crate) inherit_disposition: u32,
    pub(crate) allocation_type: u32,
    pub(crate) page_protection: u32,
}

impl SectionObject {
    fn object_path(&self) -> &str {
        &self.object_path
    }

    fn fs_path(&self) -> &str {
        &self.fs_path
    }
}

impl<FS: NtShimFS> Task<FS> {
    pub(crate) fn handle_nt_open_section(
        &self,
        section_handle: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<Handle>,
        desired_access: u32,
        object_attributes: Option<
            <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<ObjectAttributes>,
        >,
    ) -> NtStatus {
        if section_handle
            .write_at_offset(0, Handle::default())
            .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }

        let Some(object_attributes) = object_attributes else {
            return NtStatus::INVALID_PARAMETER;
        };
        let object_attributes = match read_object_attributes(object_attributes) {
            Ok(object_attributes) => object_attributes,
            Err(status) => return status,
        };
        if object_attributes.object_name == 0 {
            return NtStatus::INVALID_PARAMETER;
        }

        let name = match read_unicode_string(object_attributes.object_name) {
            Ok(name) => name,
            Err(status) => return status,
        };
        let object_path = match self.resolve_object_path(object_attributes.root_directory, &name) {
            Ok(path) => path,
            Err(status) => return status,
        };
        let Some(fs_path) = known_dll_section_fs_path(&object_path) else {
            litebox_util_log::debug!(
                desired_access:% = format_args!("{desired_access:#x}"),
                root_directory:% = format_args!("{:#x}", object_attributes.root_directory.as_raw()),
                object_path:% = object_path,
                status:% = NtStatus::OBJECT_NAME_NOT_FOUND;
                "Handled NtOpenSection syscall"
            );
            return NtStatus::OBJECT_NAME_NOT_FOUND;
        };
        let Ok(fd) = self.fs.open(&fs_path, OFlags::RDONLY, Mode::empty()) else {
            litebox_util_log::debug!(
                desired_access:% = format_args!("{desired_access:#x}"),
                root_directory:% = format_args!("{:#x}", object_attributes.root_directory.as_raw()),
                object_path:% = object_path,
                fs_path:% = fs_path,
                status:% = NtStatus::OBJECT_NAME_NOT_FOUND;
                "Handled NtOpenSection syscall"
            );
            return NtStatus::OBJECT_NAME_NOT_FOUND;
        };
        let _ = self.fs.close(&fd);

        let section = SectionObject {
            object_path: object_path.clone(),
            fs_path: fs_path.clone(),
        };
        let log_object_path = String::from(section.object_path());
        let log_fs_path = String::from(section.fs_path());
        let mut descriptor_table = self.global.litebox.descriptor_table_mut();
        let typed = descriptor_table.insert::<SectionSubsystem>(section);
        drop(descriptor_table);
        let handle = match insert_raw_handle(&self.global.litebox, &self.process.handles, typed) {
            Ok(handle) => handle,
            Err(status) => return status,
        };

        if section_handle.write_at_offset(0, handle).is_none() {
            remove_raw_handle::<SectionSubsystem>(
                &self.global.litebox,
                &self.process.handles,
                handle,
            );
            return NtStatus::ACCESS_VIOLATION;
        }

        litebox_util_log::debug!(
            handle:% = format_args!("{:#x}", handle.as_raw()),
            desired_access:% = format_args!("{desired_access:#x}"),
            root_directory:% = format_args!("{:#x}", object_attributes.root_directory.as_raw()),
            object_path:% = log_object_path,
            fs_path:% = log_fs_path;
            "Handled NtOpenSection syscall"
        );

        NtStatus::SUCCESS
    }

    pub(crate) fn handle_nt_map_view_of_section(
        &self,
        request: MapViewOfSectionRequest,
    ) -> NtStatus {
        if !request.process_handle.is_current() {
            return NtStatus::INVALID_HANDLE;
        }

        let Some(requested_base) = request.base_address.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        let Some(requested_view_size) = request.view_size.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        let requested_section_offset = if let Some(section_offset) = request.section_offset {
            let Some(offset) = section_offset.read_at_offset(0) else {
                return NtStatus::ACCESS_VIOLATION;
            };
            offset
        } else {
            0
        };

        if requested_base != 0
            || request.zero_bits != 0
            || request.commit_size != 0
            || requested_view_size != 0
            || requested_section_offset != 0
            || !matches!(request.inherit_disposition, VIEW_SHARE | VIEW_UNMAP)
            || request.allocation_type & !SUPPORTED_MAP_ALLOCATION_TYPES != 0
        {
            return NtStatus::INVALID_PARAMETER;
        }

        let Some(section) = crate::raw_handle_entry::<SectionSubsystem>(
            &self.global.litebox,
            &self.process.handles,
            request.section_handle,
        ) else {
            return NtStatus::INVALID_HANDLE;
        };
        let (object_path, fs_path) = section.with_entry(|section| {
            (
                String::from(section.object_path()),
                String::from(section.fs_path()),
            )
        });

        let image = match pe::load_image(self.fs.clone(), &fs_path, &self.global.page_manager) {
            Ok(image) => image,
            Err(error) => return map_section_load_error(&error),
        };

        let mapped_size = match section_view_mapped_size(image.mapping.mapped_size) {
            Some(mapped_size) => mapped_size,
            None => {
                let _ = remove_section_view_pages(
                    &self.global.page_manager,
                    image.mapping.base_addr,
                    image.mapping.mapped_size,
                );
                return NtStatus::NO_MEMORY;
            }
        };
        if request
            .base_address
            .write_at_offset(0, image.mapping.base_addr)
            .is_none()
            || request
                .view_size
                .write_at_offset(0, image.mapping.image_size)
                .is_none()
        {
            let _ = remove_section_view_pages(
                &self.global.page_manager,
                image.mapping.base_addr,
                mapped_size,
            );
            return NtStatus::ACCESS_VIOLATION;
        }

        self.process.section_views.lock().insert(
            image.mapping.base_addr,
            WindowsSectionView {
                image_size: image.mapping.image_size,
                mapped_size: image.mapping.mapped_size,
            },
        );

        litebox_util_log::debug!(
            section_handle:% = format_args!("{:#x}", request.section_handle.as_raw()),
            process_handle:% = format_args!("{:#x}", request.process_handle.as_raw()),
            base:% = format_args!("{:#x}", image.mapping.base_addr),
            view_size = image.mapping.image_size,
            inherit_disposition = request.inherit_disposition,
            allocation_type:% = format_args!("{:#x}", request.allocation_type),
            page_protection:% = format_args!("{:#x}", request.page_protection),
            object_path:% = object_path,
            fs_path:% = fs_path;
            "Handled NtMapViewOfSection syscall"
        );

        NtStatus::SUCCESS
    }

    pub(crate) fn handle_nt_unmap_view_of_section(
        &self,
        process_handle: ProcessHandle,
        base_address: usize,
    ) -> NtStatus {
        if !process_handle.is_current() {
            return NtStatus::INVALID_HANDLE;
        }

        let Some((view_base, view)) =
            remove_section_view_for_address(&self.process.section_views, base_address)
        else {
            return NtStatus::NOT_MAPPED_VIEW;
        };

        let Some(mapped_size) = section_view_mapped_size(view.mapped_size) else {
            self.process.section_views.lock().insert(view_base, view);
            return NtStatus::UNABLE_TO_FREE_VM;
        };

        if remove_section_view_pages(&self.global.page_manager, view_base, mapped_size).is_err() {
            self.process.section_views.lock().insert(view_base, view);
            return NtStatus::UNABLE_TO_FREE_VM;
        }

        litebox_util_log::debug!(
            process_handle:% = format_args!("{:#x}", process_handle.as_raw()),
            base_address:% = format_args!("{base_address:#x}"),
            view_base:% = format_args!("{view_base:#x}"),
            view_size = view.image_size;
            "Handled NtUnmapViewOfSection syscall"
        );

        NtStatus::SUCCESS
    }
}

fn section_view_mapped_size(mapped_size: usize) -> Option<usize> {
    mapped_size.checked_add(IMAGE_EXTENSION_SIZE)
}

fn remove_section_view_for_address(
    section_views: &crate::WindowsSectionViews,
    base_address: usize,
) -> Option<(usize, WindowsSectionView)> {
    let mut views = section_views.lock();
    let (&view_base, &view) = views.range(..=base_address).next_back()?;
    let view_end = view_base.checked_add(view.image_size)?;
    if base_address < view_end {
        views.remove(&view_base);
        Some((view_base, view))
    } else {
        None
    }
}

fn remove_section_view_pages(
    page_manager: &crate::WindowsPageManager,
    view_base: usize,
    view_size: usize,
) -> Result<(), ()> {
    if view_base == 0 || NonZeroPageSize::<PAGE_SIZE>::new(view_size).is_none() {
        return Err(());
    }

    let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(view_base);
    // SAFETY: Section views are ranges previously created by this shim's section mapper and
    // tracked in `section_views`; removing them implements the guest's explicit unmap request.
    unsafe { page_manager.remove_pages(ptr, view_size) }.map_err(|_| ())
}

fn map_section_load_error(error: &WindowsLoadError) -> NtStatus {
    match error {
        WindowsLoadError::Access(_) => NtStatus::OBJECT_NAME_NOT_FOUND,
        WindowsLoadError::Load(_) => NtStatus::NO_MEMORY,
        WindowsLoadError::Parse(_)
        | WindowsLoadError::MissingNtDllLoaderEntrypoint
        | WindowsLoadError::MissingNtDllThreadEntrypoint
        | WindowsLoadError::UnrewrittenNtDll => NtStatus::INVALID_FILE_FOR_SECTION,
    }
}

fn known_dll_section_fs_path(object_path: &str) -> Option<String> {
    let dll_name = strip_case_insensitive_prefix(object_path, r"\KnownDlls\")
        .or_else(|| strip_case_insensitive_prefix(object_path, r"\KnownDlls32\"))?;
    if dll_name.contains(['\\', '/']) || !ends_with_ignore_ascii_case(dll_name, ".dll") {
        return None;
    }

    let mut fs_path = String::from("/Windows/System32/");
    fs_path.push_str(&dll_name.to_ascii_lowercase());
    Some(fs_path)
}

fn strip_case_insensitive_prefix<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    value
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
        .then(|| &value[prefix.len()..])
}

fn ends_with_ignore_ascii_case(value: &str, suffix: &str) -> bool {
    value
        .get(value.len().saturating_sub(suffix.len())..)
        .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use litebox::mm::linux::CreatePagesFlags;
    use litebox::platform::RawConstPointer as _;
    use litebox::platform::page_mgmt::MemoryRegionPermissions;
    use litebox_common_windows::nt_status::NtStatus;
    use zerocopy::{FromBytes, IntoBytes};

    use super::*;
    use crate::loader::nt_types::UnicodeString;

    type MutPtr<T> = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<T>;
    type ConstPtr<T> = <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<T>;

    fn mut_handle_ptr(value: &mut Handle) -> MutPtr<Handle> {
        MutPtr::from_usize(core::ptr::from_mut(value) as usize)
    }

    fn mut_ptr<T: FromBytes + IntoBytes>(value: &mut T) -> MutPtr<T> {
        MutPtr::from_usize(core::ptr::from_mut(value).cast::<u8>() as usize)
    }

    fn const_ptr<T: FromBytes>(value: &T) -> ConstPtr<T> {
        ConstPtr::from_usize(core::ptr::from_ref(value).cast::<u8>() as usize)
    }

    fn wide(value: &str) -> alloc::vec::Vec<u16> {
        value.encode_utf16().collect()
    }

    fn object_attributes_for_name(
        root_directory: Handle,
        object_name: &UnicodeString,
    ) -> ObjectAttributes {
        ObjectAttributes {
            length: u32::try_from(size_of::<ObjectAttributes>()).unwrap(),
            root_directory,
            object_name: core::ptr::from_ref(object_name) as usize,
            attributes: 0,
            security_descriptor: 0,
            security_quality_of_service: 0,
        }
    }

    fn map_view_request(
        section_handle: Handle,
        base_address: &mut usize,
        view_size: &mut usize,
    ) -> MapViewOfSectionRequest {
        MapViewOfSectionRequest {
            section_handle,
            process_handle: ProcessHandle::CURRENT,
            base_address: mut_ptr(base_address),
            zero_bits: 0,
            commit_size: 0,
            section_offset: None,
            view_size: mut_ptr(view_size),
            inherit_disposition: VIEW_UNMAP,
            allocation_type: 0,
            page_protection: 0x02,
        }
    }

    #[test]
    fn nt_open_section_opens_known_dll_section() {
        let task =
            crate::tests::test_task_with_nls_files(&[("/Windows/System32/kernel32.dll", b"dll")]);
        let mut section_handle = Handle::from_raw(usize::MAX);
        let path = wide(r"\KnownDlls\kernel32.dll");
        let object_name = UnicodeString {
            length: u16::try_from(path.len() * size_of::<u16>()).unwrap(),
            maximum_length: u16::try_from(path.len() * size_of::<u16>()).unwrap(),
            padding_0: [0; 4],
            buffer: path.as_ptr() as usize,
        };
        let object_attributes = object_attributes_for_name(Handle::default(), &object_name);

        assert_eq!(
            task.handle_nt_open_section(
                mut_handle_ptr(&mut section_handle),
                0xf001f,
                Some(const_ptr(&object_attributes)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(section_handle, Handle::from_raw_fd(0).unwrap());

        let section = crate::raw_handle_entry::<SectionSubsystem>(
            &task.global.litebox,
            &task.process.handles,
            section_handle,
        )
        .unwrap();
        section.with_entry(|section| {
            assert_eq!(section.object_path(), r"\KnownDlls\kernel32.dll");
            assert_eq!(section.fs_path(), "/Windows/System32/kernel32.dll");
        });
    }

    #[test]
    fn nt_open_section_resolves_relative_known_dll_name() {
        let task =
            crate::tests::test_task_with_nls_files(&[("/Windows/System32/kernel32.dll", b"dll")]);
        let mut directory_handle = Handle::from_raw(0);
        let directory_path = wide(r"\KnownDlls");
        let directory_name = UnicodeString {
            length: u16::try_from(directory_path.len() * size_of::<u16>()).unwrap(),
            maximum_length: u16::try_from(directory_path.len() * size_of::<u16>()).unwrap(),
            padding_0: [0; 4],
            buffer: directory_path.as_ptr() as usize,
        };
        let directory_attributes = object_attributes_for_name(Handle::default(), &directory_name);
        assert_eq!(
            task.handle_nt_open_directory_object(
                mut_handle_ptr(&mut directory_handle),
                0x3,
                Some(const_ptr(&directory_attributes)),
            ),
            NtStatus::SUCCESS
        );

        let mut section_handle = Handle::from_raw(usize::MAX);
        let path = wide("kernel32.dll");
        let object_name = UnicodeString {
            length: u16::try_from(path.len() * size_of::<u16>()).unwrap(),
            maximum_length: u16::try_from(path.len() * size_of::<u16>()).unwrap(),
            padding_0: [0; 4],
            buffer: path.as_ptr() as usize,
        };
        let object_attributes = object_attributes_for_name(directory_handle, &object_name);

        assert_eq!(
            task.handle_nt_open_section(
                mut_handle_ptr(&mut section_handle),
                0xf001f,
                Some(const_ptr(&object_attributes)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(section_handle, Handle::from_raw_fd(1).unwrap());
    }

    #[test]
    fn nt_open_section_reports_missing_known_dll() {
        let task = crate::tests::test_task();
        let mut section_handle = Handle::from_raw(usize::MAX);
        let path = wide(r"\KnownDlls\missing.dll");
        let object_name = UnicodeString {
            length: u16::try_from(path.len() * size_of::<u16>()).unwrap(),
            maximum_length: u16::try_from(path.len() * size_of::<u16>()).unwrap(),
            padding_0: [0; 4],
            buffer: path.as_ptr() as usize,
        };
        let object_attributes = object_attributes_for_name(Handle::default(), &object_name);

        assert_eq!(
            task.handle_nt_open_section(
                mut_handle_ptr(&mut section_handle),
                0,
                Some(const_ptr(&object_attributes)),
            ),
            NtStatus::OBJECT_NAME_NOT_FOUND
        );
        assert_eq!(section_handle, Handle::default());
    }

    #[test]
    fn nt_close_removes_section_handle() {
        let task =
            crate::tests::test_task_with_nls_files(&[("/Windows/System32/kernel32.dll", b"dll")]);
        let mut section_handle = Handle::from_raw(0);
        let path = wide(r"\KnownDlls\kernel32.dll");
        let object_name = UnicodeString {
            length: u16::try_from(path.len() * size_of::<u16>()).unwrap(),
            maximum_length: u16::try_from(path.len() * size_of::<u16>()).unwrap(),
            padding_0: [0; 4],
            buffer: path.as_ptr() as usize,
        };
        let object_attributes = object_attributes_for_name(Handle::default(), &object_name);

        assert_eq!(
            task.handle_nt_open_section(
                mut_handle_ptr(&mut section_handle),
                0,
                Some(const_ptr(&object_attributes)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(task.handle_nt_close(section_handle), NtStatus::SUCCESS);
        assert_eq!(
            task.handle_nt_close(section_handle),
            NtStatus::INVALID_HANDLE
        );
    }

    #[test]
    fn nt_map_view_of_section_rejects_unknown_section_handle() {
        let task = crate::tests::test_task();
        let mut base_address = 0usize;
        let mut view_size = 0usize;

        assert_eq!(
            task.handle_nt_map_view_of_section(map_view_request(
                Handle::from_raw_fd(0).unwrap(),
                &mut base_address,
                &mut view_size,
            )),
            NtStatus::INVALID_HANDLE
        );
    }

    #[test]
    fn nt_map_view_of_section_rejects_invalid_image_file() {
        let task =
            crate::tests::test_task_with_nls_files(&[("/Windows/System32/kernel32.dll", b"dll")]);
        let mut section_handle = Handle::from_raw(0);
        let path = wide(r"\KnownDlls\kernel32.dll");
        let object_name = UnicodeString {
            length: u16::try_from(path.len() * size_of::<u16>()).unwrap(),
            maximum_length: u16::try_from(path.len() * size_of::<u16>()).unwrap(),
            padding_0: [0; 4],
            buffer: path.as_ptr() as usize,
        };
        let object_attributes = object_attributes_for_name(Handle::default(), &object_name);
        assert_eq!(
            task.handle_nt_open_section(
                mut_handle_ptr(&mut section_handle),
                0,
                Some(const_ptr(&object_attributes)),
            ),
            NtStatus::SUCCESS
        );

        let mut base_address = 0usize;
        let mut view_size = 0usize;
        assert_eq!(
            task.handle_nt_map_view_of_section(map_view_request(
                section_handle,
                &mut base_address,
                &mut view_size,
            )),
            NtStatus::INVALID_FILE_FOR_SECTION
        );
        assert_eq!(base_address, 0);
        assert_eq!(view_size, 0);
    }

    #[test]
    fn nt_unmap_view_of_section_removes_tracked_view() {
        let task = crate::tests::test_task();
        let mapping = crate::syscalls::mm::create_pages(
            &task.global.page_manager,
            None,
            NonZeroPageSize::new(PAGE_SIZE).unwrap(),
            CreatePagesFlags::empty(),
            MemoryRegionPermissions::READ,
            |_| Ok(0),
        )
        .unwrap();
        let view_base = mapping.as_usize();
        task.process.section_views.lock().insert(
            view_base,
            WindowsSectionView {
                image_size: PAGE_SIZE,
                mapped_size: PAGE_SIZE,
            },
        );

        assert_eq!(
            task.handle_nt_unmap_view_of_section(ProcessHandle::CURRENT, view_base + 0x20),
            NtStatus::SUCCESS
        );
        assert_eq!(
            task.handle_nt_unmap_view_of_section(ProcessHandle::CURRENT, view_base),
            NtStatus::NOT_MAPPED_VIEW
        );
    }

    #[test]
    fn nt_unmap_view_of_section_rejects_unknown_view() {
        let task = crate::tests::test_task();

        assert_eq!(
            task.handle_nt_unmap_view_of_section(ProcessHandle::CURRENT, 0x1234_5000),
            NtStatus::NOT_MAPPED_VIEW
        );
    }
}
