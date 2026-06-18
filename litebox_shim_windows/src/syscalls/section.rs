use alloc::string::String;
use alloc::sync::Arc;
use core::marker::PhantomData;
use core::mem::size_of;

use int_enum::IntEnum;
use litebox::fd::{ErrRawIntFd, FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::mm::linux::{CreatePagesFlags, NonZeroPageSize};
use litebox::platform::page_mgmt::MemoryRegionPermissions;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_windows::nt_status::NtStatus;
use rangemap::RangeMap;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use super::Handle;
use super::ProcessHandle;
use super::directory_object::directory_key;
use super::mm::{MemoryType, PageProtection, create_pages, parse_page_protection};
use crate::nt_types::{
    AccessMask, ObjectAttributes, ProcessEnvironmentBlock, UnicodeString, read_object_attributes,
};
use crate::{
    ConstPtr, MutPtr, PAGE_SIZE, ShimFS, ShimPlatform, Task, WindowsSectionView, insert_raw_handle,
    probe_guest_output_preserving_value, read_value, remove_raw_handle,
};

const SEC_RESERVE: u32 = 0x0400_0000;
const SEC_COMMIT: u32 = 0x0800_0000;
const SEC_IMAGE: u32 = 0x0100_0000;
const SEC_FILE: u32 = 0x0080_0000;
const SUPPORTED_CREATE_ATTRIBUTES: u32 = SEC_RESERVE | SEC_COMMIT;

const VIEW_SHARE: u32 = 1;
const VIEW_UNMAP: u32 = 2;
const MEM_TOP_DOWN: u32 = 0x0010_0000;
const MEM_PHYSICAL: u32 = 0x0040_0000;
const MEM_DIFFERENT_IMAGE_BASE_OK: u32 = 0x0080_0000;
const SUPPORTED_MAP_ALLOCATION_TYPES: u32 = MEM_TOP_DOWN | MEM_DIFFERENT_IMAGE_BASE_OK;

const WINDOWS_SHARED_SECTION_OBJECT: &str = r"\Windows\SharedSection";
const WINDOWS_SHARED_SECTION_SIZE: usize = 0x1_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SectionBacking {
    Pagefile,
    CsrSharedSection,
    ImageFile,
}

pub(crate) struct SectionSubsystem(PhantomData<fn()>);

impl FdEnabledSubsystem for SectionSubsystem {
    type Entry = SectionHandleObject;
}

impl FdEnabledSubsystemEntry for SectionHandleObject {}

pub(crate) struct SectionHandleObject {
    section: Arc<SectionObject>,
    granted_access: SectionAccess,
}

pub(crate) struct SectionObject {
    fs_path: Option<String>,
    size: usize,
    attributes: u32,
    protection: PageProtection,
    backing: SectionBacking,
}

pub(crate) struct MapViewOfSectionParameters<Platform: ShimPlatform> {
    pub(crate) section_handle: Handle,
    pub(crate) process_handle: ProcessHandle,
    pub(crate) base_address: MutPtr<Platform, usize>,
    pub(crate) zero_bits: usize,
    pub(crate) commit_size: usize,
    pub(crate) section_offset: Option<ConstPtr<Platform, i64>>,
    pub(crate) view_size: MutPtr<Platform, usize>,
    pub(crate) inherit_disposition: u32,
    pub(crate) allocation_type: u32,
    pub(crate) page_protection: u32,
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct SectionAccess: u32 {
        const QUERY = 0x0001;
        const MAP_WRITE = 0x0002;
        const MAP_READ = 0x0004;
        const MAP_EXECUTE = 0x0008;
        const EXTEND_SIZE = 0x0010;
        const MAP_EXECUTE_EXPLICIT = 0x0020;

        const GENERIC_READ_EXPANSION = AccessMask::STANDARD_RIGHTS_READ.bits()
            | Self::QUERY.bits()
            | Self::MAP_READ.bits();
        const GENERIC_WRITE_EXPANSION = AccessMask::STANDARD_RIGHTS_WRITE.bits()
            | Self::MAP_WRITE.bits()
            | Self::EXTEND_SIZE.bits();
        const GENERIC_EXECUTE_EXPANSION = AccessMask::STANDARD_RIGHTS_EXECUTE.bits()
            | Self::MAP_EXECUTE.bits();
        const ALL_ACCESS = AccessMask::STANDARD_RIGHTS_ALL.bits()
            | Self::QUERY.bits()
            | Self::MAP_WRITE.bits()
            | Self::MAP_READ.bits()
            | Self::MAP_EXECUTE.bits()
            | Self::EXTEND_SIZE.bits();
        const GENERIC_ALL = AccessMask::GENERIC_ALL.bits();
        const GENERIC_EXECUTE = AccessMask::GENERIC_EXECUTE.bits();
        const GENERIC_WRITE = AccessMask::GENERIC_WRITE.bits();
        const GENERIC_READ = AccessMask::GENERIC_READ.bits();

        const _ = !0;
    }
}

impl SectionAccess {
    fn from_desired_access(desired_access: u32) -> Self {
        let mut access = Self::from_bits_retain(desired_access);
        if access.contains(Self::GENERIC_READ) {
            access.remove(Self::GENERIC_READ);
            access.insert(Self::GENERIC_READ_EXPANSION);
        }
        if access.contains(Self::GENERIC_WRITE) {
            access.remove(Self::GENERIC_WRITE);
            access.insert(Self::GENERIC_WRITE_EXPANSION);
        }
        if access.contains(Self::GENERIC_EXECUTE) {
            access.remove(Self::GENERIC_EXECUTE);
            access.insert(Self::GENERIC_EXECUTE_EXPANSION);
        }
        if access.contains(Self::GENERIC_ALL) {
            access.remove(Self::GENERIC_ALL);
            access.insert(Self::ALL_ACCESS);
        }
        access
    }

    fn require(self, required: Self) -> Result<(), NtStatus> {
        if self.contains(required) {
            Ok(())
        } else {
            Err(NtStatus::ACCESS_DENIED)
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
enum SectionInformationClass {
    Basic = 0,
    Image = 1,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct SectionBasicInformation {
    base_address: usize,
    attributes: u32,
    _padding: u32,
    size: i64,
}

const _: () = assert!(size_of::<SectionBasicInformation>() == 24);

const SECTION_IMAGE_INFORMATION_SIZE: usize = 72;

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    fn section_entry(
        &self,
        handle: Handle,
    ) -> Result<litebox::fd::EntryHandle<Platform, SectionSubsystem>, NtStatus> {
        let Some(raw_fd) = handle.raw_fd() else {
            return Err(NtStatus::INVALID_HANDLE);
        };
        let typed = {
            let handles = self.process.handles.read();
            match handles.fd_from_raw_integer::<SectionSubsystem>(raw_fd) {
                Ok(typed) => typed,
                Err(ErrRawIntFd::NotFound) => return Err(NtStatus::INVALID_HANDLE),
                Err(ErrRawIntFd::InvalidSubsystem) => return Err(NtStatus::OBJECT_TYPE_MISMATCH),
            }
        };
        self.global
            .litebox
            .descriptor_table()
            .entry_handle(&typed)
            .ok_or(NtStatus::INVALID_HANDLE)
    }

    fn insert_section_handle(
        &self,
        section: Arc<SectionObject>,
        granted_access: SectionAccess,
    ) -> Result<Handle, NtStatus> {
        let typed = self
            .global
            .litebox
            .descriptor_table_mut()
            .insert::<SectionSubsystem>(SectionHandleObject {
                section,
                granted_access,
            });
        insert_raw_handle::<Platform, SectionSubsystem>(
            &self.global.litebox,
            &self.process.handles,
            typed,
            drop,
        )
    }

    pub(crate) fn close_section_handle(&self, handle: Handle) {
        remove_raw_handle::<Platform, SectionSubsystem>(
            &self.global.litebox,
            &self.process.handles,
            handle,
            drop,
        );
    }

    pub(crate) fn close_section(section: SectionHandleObject) {
        drop(section);
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "NtCreateSection has seven ABI parameters; keeping them explicit avoids call-site reshuffling"
    )]
    pub(crate) fn sys_nt_create_section(
        &self,
        section_handle: MutPtr<Platform, Handle>,
        desired_access: u32,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
        maximum_size: Option<ConstPtr<Platform, i64>>,
        section_page_protection: u32,
        allocation_attributes: u32,
        file_handle: Handle,
    ) -> NtStatus {
        if let Err(status) = probe_guest_output_preserving_value::<Platform, _>(section_handle) {
            return status;
        }
        let granted_access = SectionAccess::from_desired_access(desired_access);
        if granted_access.is_empty() {
            return NtStatus::ACCESS_DENIED;
        }
        let Some((protection, _)) = parse_page_protection(section_page_protection) else {
            return NtStatus::INVALID_PAGE_PROTECTION;
        };
        if !file_handle.is_null() {
            return NtStatus::INVALID_HANDLE;
        }
        if allocation_attributes & !SUPPORTED_CREATE_ATTRIBUTES != 0 {
            return NtStatus::INVALID_PARAMETER;
        }
        if allocation_attributes & (SEC_COMMIT | SEC_RESERVE) == 0 {
            return NtStatus::INVALID_PARAMETER;
        }

        let Some(maximum_size) = maximum_size else {
            return NtStatus::INVALID_PARAMETER;
        };
        let maximum_size = match maximum_size.read_at_offset(0) {
            Some(value) if value > 0 => value,
            Some(_) => return NtStatus::INVALID_PARAMETER,
            None => return NtStatus::ACCESS_VIOLATION,
        };
        let Ok(size) = usize::try_from(maximum_size) else {
            return NtStatus::SECTION_TOO_BIG;
        };
        let Some(size) = size.checked_next_multiple_of(PAGE_SIZE) else {
            return NtStatus::SECTION_TOO_BIG;
        };
        if NonZeroPageSize::<PAGE_SIZE>::new(size).is_none() {
            return NtStatus::INVALID_PARAMETER;
        }

        let name = match self.read_section_name(object_attributes) {
            Ok(name) => name,
            Err(status) => return status,
        };
        let attributes = if allocation_attributes & SEC_RESERVE != 0 {
            SEC_RESERVE
        } else {
            SEC_COMMIT
        };
        let section = Arc::new(SectionObject {
            fs_path: None,
            size,
            attributes,
            protection,
            backing: SectionBacking::Pagefile,
        });
        if let Some(name) = &name {
            let status = self.insert_named_section(name, &section);
            if status != NtStatus::SUCCESS {
                return status;
            }
        }
        self.publish_section_handle(section_handle, section, granted_access)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "NtCreateSectionEx extends NtCreateSection with two ABI parameters"
    )]
    pub(crate) fn sys_nt_create_section_ex(
        &self,
        section_handle: MutPtr<Platform, Handle>,
        desired_access: u32,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
        maximum_size: Option<ConstPtr<Platform, i64>>,
        section_page_protection: u32,
        allocation_attributes: u32,
        file_handle: Handle,
        extended_parameters: Option<ConstPtr<Platform, u8>>,
        extended_parameter_count: u32,
    ) -> NtStatus {
        if extended_parameters.is_some() || extended_parameter_count != 0 {
            return NtStatus::INVALID_PARAMETER;
        }
        self.sys_nt_create_section(
            section_handle,
            desired_access,
            object_attributes,
            maximum_size,
            section_page_protection,
            allocation_attributes,
            file_handle,
        )
    }

    pub(crate) fn sys_nt_open_section(
        &self,
        section_handle: MutPtr<Platform, Handle>,
        desired_access: u32,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
    ) -> NtStatus {
        if let Err(status) = probe_guest_output_preserving_value::<Platform, _>(section_handle) {
            return status;
        }
        let granted_access = SectionAccess::from_desired_access(desired_access);
        if granted_access.is_empty() {
            return NtStatus::ACCESS_DENIED;
        }
        let name = match self.read_required_section_name(object_attributes) {
            Ok(name) => name,
            Err(status) => return status,
        };
        if self.directory_object_exists(&name) || self.symbolic_link_object_exists(&name) {
            return NtStatus::OBJECT_TYPE_MISMATCH;
        }
        if let Some(section) = self.named_section(&name) {
            return self.publish_section_handle(section_handle, section, granted_access);
        }
        if name.eq_ignore_ascii_case(WINDOWS_SHARED_SECTION_OBJECT) {
            let section = Arc::new(SectionObject {
                fs_path: None,
                size: WINDOWS_SHARED_SECTION_SIZE,
                attributes: SEC_COMMIT,
                protection: PageProtection::PAGE_READWRITE,
                backing: SectionBacking::CsrSharedSection,
            });
            return self.publish_section_handle(section_handle, section, granted_access);
        }
        let Some(fs_path) = known_dll_section_fs_path(&name) else {
            return section_missing_status(self.directory_parent_exists(&name));
        };
        let Ok(file_status) = self.fs.file_status(&fs_path) else {
            return NtStatus::OBJECT_NAME_NOT_FOUND;
        };
        let section = Arc::new(SectionObject {
            fs_path: Some(fs_path),
            size: file_status.size,
            attributes: SEC_FILE | SEC_IMAGE,
            protection: PageProtection::PAGE_EXECUTE_WRITECOPY,
            backing: SectionBacking::ImageFile,
        });
        self.publish_section_handle(section_handle, section, granted_access)
    }

    pub(crate) fn sys_nt_query_section(
        &self,
        section_handle: Handle,
        section_information_class: u32,
        section_information: MutPtr<Platform, u8>,
        section_information_length: usize,
        return_length: Option<MutPtr<Platform, usize>>,
    ) -> NtStatus {
        let Ok(information_class) = SectionInformationClass::try_from(section_information_class)
        else {
            return NtStatus::INVALID_INFO_CLASS;
        };
        let entry = match self.section_entry(section_handle) {
            Ok(entry) => entry,
            Err(status) => return status,
        };
        let result = entry.with_entry(|entry| {
            entry
                .granted_access
                .require(SectionAccess::QUERY)
                .map(|()| entry.section.clone())
        });
        let section = match result {
            Ok(section) => section,
            Err(status) => return status,
        };
        match information_class {
            SectionInformationClass::Basic => write_section_basic_information::<Platform>(
                &section,
                section_information,
                section_information_length,
                return_length,
            ),
            SectionInformationClass::Image => write_section_image_information::<Platform>(
                &section,
                section_information,
                section_information_length,
                return_length,
            ),
        }
    }

    pub(crate) fn sys_nt_map_view_of_section(
        &self,
        request: MapViewOfSectionParameters<Platform>,
    ) -> NtStatus {
        if !request.process_handle.is_current() {
            return NtStatus::INVALID_HANDLE;
        }
        let Some(base) = request.base_address.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        let Some(requested_view_size) = request.view_size.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        let section_offset = match request.section_offset {
            Some(section_offset) => match section_offset.read_at_offset(0) {
                Some(value) if value >= 0 => usize::try_from(value).unwrap_or(usize::MAX),
                Some(_) => return NtStatus::INVALID_PARAMETER,
                None => return NtStatus::ACCESS_VIOLATION,
            },
            None => 0,
        };
        if base != 0
            || request.zero_bits != 0
            || request.commit_size != 0
            || !section_offset.is_multiple_of(PAGE_SIZE)
            || !matches!(request.inherit_disposition, VIEW_SHARE | VIEW_UNMAP)
            || request.allocation_type & !(SUPPORTED_MAP_ALLOCATION_TYPES | MEM_PHYSICAL) != 0
        {
            return NtStatus::INVALID_PARAMETER;
        }
        let Some((page_protection, permissions)) = parse_page_protection(request.page_protection)
        else {
            return NtStatus::INVALID_PAGE_PROTECTION;
        };
        let entry = match self.section_entry(request.section_handle) {
            Ok(entry) => entry,
            Err(status) => return status,
        };
        let result = entry.with_entry(|entry| {
            required_map_access(page_protection)
                .and_then(|required| entry.granted_access.require(required))
                .map(|()| entry.section.clone())
        });
        let section = match result {
            Ok(section) => section,
            Err(status) => return status,
        };
        if section.backing != SectionBacking::CsrSharedSection
            && request.allocation_type & MEM_PHYSICAL != 0
        {
            return NtStatus::INVALID_PARAMETER;
        }
        match section.backing {
            SectionBacking::Pagefile => self.map_pagefile_section(
                request,
                &section,
                requested_view_size,
                section_offset,
                page_protection,
                permissions,
            ),
            SectionBacking::CsrSharedSection => self.map_csr_shared_section(
                request,
                &section,
                requested_view_size,
                section_offset,
                page_protection,
                permissions,
            ),
            SectionBacking::ImageFile => self.map_image_section(request, &section),
        }
    }

    pub(crate) fn sys_nt_map_view_of_section_ex(
        &self,
        request: MapViewOfSectionParameters<Platform>,
        extended_parameters: Option<ConstPtr<Platform, u8>>,
        extended_parameter_count: u32,
    ) -> NtStatus {
        if extended_parameters.is_some() || extended_parameter_count != 0 {
            return NtStatus::INVALID_PARAMETER;
        }
        self.sys_nt_map_view_of_section(request)
    }

    pub(crate) fn sys_nt_unmap_view_of_section(
        &self,
        process_handle: ProcessHandle,
        base_address: usize,
    ) -> NtStatus {
        if !process_handle.is_current() {
            return NtStatus::INVALID_HANDLE;
        }
        let Some((view_base, view)) = self.remove_section_view_for_address(base_address) else {
            return NtStatus::NOT_MAPPED_VIEW;
        };
        let ptr = MutPtr::<Platform, u8>::from_usize(view_base);
        // SAFETY: Section views are tracked only after this shim successfully creates the pages;
        // unmapping consumes the tracked view and removes the exact owned range.
        if unsafe { self.global.page_manager.remove_pages(ptr, view.size) }.is_err() {
            self.process.section_views.write().insert(view_base, view);
            return NtStatus::UNABLE_TO_FREE_VM;
        }
        self.process.virtual_allocations.write().remove(&view_base);
        self.process.image_mappings.write().remove(&view_base);
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_unmap_view_of_section_ex(
        &self,
        process_handle: ProcessHandle,
        base_address: usize,
        flags: u32,
    ) -> NtStatus {
        if flags != 0 {
            return NtStatus::INVALID_PARAMETER;
        }
        self.sys_nt_unmap_view_of_section(process_handle, base_address)
    }

    fn publish_section_handle(
        &self,
        section_handle: MutPtr<Platform, Handle>,
        section: Arc<SectionObject>,
        granted_access: SectionAccess,
    ) -> NtStatus {
        let handle = match self.insert_section_handle(section, granted_access) {
            Ok(handle) => handle,
            Err(status) => return status,
        };
        if section_handle.write_at_offset(0, handle).is_none() {
            self.close_section_handle(handle);
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    fn insert_named_section(&self, name: &str, section: &Arc<SectionObject>) -> NtStatus {
        if self.directory_object_exists(name) || self.symbolic_link_object_exists(name) {
            return NtStatus::OBJECT_NAME_COLLISION;
        }
        if !self.directory_parent_exists(name) {
            return NtStatus::OBJECT_PATH_NOT_FOUND;
        }
        let key = directory_key(name);
        let mut namespace = self.process.section_namespace.write();
        if let Some(existing) = namespace.get(&key)
            && existing.upgrade().is_some()
        {
            return NtStatus::OBJECT_NAME_EXISTS;
        }
        namespace.insert(key, Arc::downgrade(section));
        NtStatus::SUCCESS
    }

    fn named_section(&self, name: &str) -> Option<Arc<SectionObject>> {
        let key = directory_key(name);
        let mut namespace = self.process.section_namespace.write();
        let section = namespace.get(&key).and_then(alloc::sync::Weak::upgrade);
        if section.is_none() {
            namespace.remove(&key);
        }
        section
    }

    fn map_pagefile_section(
        &self,
        request: MapViewOfSectionParameters<Platform>,
        section: &SectionObject,
        requested_view_size: usize,
        section_offset: usize,
        page_protection: PageProtection,
        permissions: MemoryRegionPermissions,
    ) -> NtStatus {
        if section_offset > section.size {
            return NtStatus::INVALID_VIEW_SIZE;
        }
        let remaining = section.size - section_offset;
        let view_size = if requested_view_size == 0 {
            remaining
        } else {
            requested_view_size
        };
        if view_size == 0 || view_size > remaining {
            return NtStatus::INVALID_VIEW_SIZE;
        }
        let Some(mapped_size) = view_size.checked_next_multiple_of(PAGE_SIZE) else {
            return NtStatus::INVALID_VIEW_SIZE;
        };
        let Some(length) = NonZeroPageSize::<PAGE_SIZE>::new(mapped_size) else {
            return NtStatus::INVALID_VIEW_SIZE;
        };
        let Ok(mapping) = create_pages(
            &self.global.page_manager,
            None,
            length,
            CreatePagesFlags::empty(),
            permissions,
            |_| Ok(0),
        ) else {
            return NtStatus::NO_MEMORY;
        };
        let base = mapping.as_usize();
        if request.base_address.write_at_offset(0, base).is_none()
            || request.view_size.write_at_offset(0, view_size).is_none()
        {
            let _ = remove_view_pages::<Platform>(&self.global.page_manager, base, mapped_size);
            return NtStatus::ACCESS_VIOLATION;
        }
        self.process
            .section_views
            .write()
            .insert(base, WindowsSectionView { size: mapped_size });
        self.process.virtual_allocations.write().insert(
            base,
            crate::WindowsVirtualAllocation {
                base,
                size: mapped_size,
                allocation_protect: section.protection,
                type_: MemoryType::MEM_MAPPED,
                pages: committed_pages(base, mapped_size, page_protection),
            },
        );
        NtStatus::SUCCESS
    }

    fn map_csr_shared_section(
        &self,
        request: MapViewOfSectionParameters<Platform>,
        section: &SectionObject,
        requested_view_size: usize,
        section_offset: usize,
        page_protection: PageProtection,
        permissions: MemoryRegionPermissions,
    ) -> NtStatus {
        if section_offset != 0 {
            return NtStatus::INVALID_VIEW_SIZE;
        }
        let view_size = if requested_view_size == 0 {
            section.size
        } else {
            requested_view_size
        };
        if view_size == 0 || view_size > section.size {
            return NtStatus::INVALID_VIEW_SIZE;
        }
        let Some(mapped_size) = view_size.checked_next_multiple_of(PAGE_SIZE) else {
            return NtStatus::INVALID_VIEW_SIZE;
        };
        let Some(length) = NonZeroPageSize::<PAGE_SIZE>::new(mapped_size) else {
            return NtStatus::INVALID_VIEW_SIZE;
        };
        let csr_server_read_only_shared_memory_base = read_value::<Platform, u64>(
            self.process.peb_address
                + core::mem::offset_of!(
                    ProcessEnvironmentBlock,
                    csr_server_read_only_shared_memory_base
                ),
        )
        .and_then(|base| usize::try_from(base).ok())
        .unwrap_or(0);
        if csr_server_read_only_shared_memory_base != 0 {
            if request
                .base_address
                .write_at_offset(0, csr_server_read_only_shared_memory_base)
                .is_none()
                || request.view_size.write_at_offset(0, view_size).is_none()
            {
                return NtStatus::ACCESS_VIOLATION;
            }
            return NtStatus::SUCCESS;
        }
        let Ok(mapping) = create_pages(
            &self.global.page_manager,
            None,
            length,
            CreatePagesFlags::empty(),
            permissions,
            |base| {
                let server_base = if csr_server_read_only_shared_memory_base == 0 {
                    base.as_usize()
                } else {
                    csr_server_read_only_shared_memory_base
                };
                let _ = server_base;
                Ok(0)
            },
        ) else {
            return NtStatus::NO_MEMORY;
        };
        let base = mapping.as_usize();
        if request.base_address.write_at_offset(0, base).is_none()
            || request.view_size.write_at_offset(0, view_size).is_none()
        {
            let _ = remove_view_pages::<Platform>(&self.global.page_manager, base, mapped_size);
            return NtStatus::ACCESS_VIOLATION;
        }
        self.process
            .section_views
            .write()
            .insert(base, WindowsSectionView { size: mapped_size });
        self.process.virtual_allocations.write().insert(
            base,
            crate::WindowsVirtualAllocation {
                base,
                size: mapped_size,
                allocation_protect: section.protection,
                type_: MemoryType::MEM_MAPPED,
                pages: committed_pages(base, mapped_size, page_protection),
            },
        );
        NtStatus::SUCCESS
    }

    fn map_image_section(
        &self,
        request: MapViewOfSectionParameters<Platform>,
        section: &SectionObject,
    ) -> NtStatus {
        let Some(fs_path) = &section.fs_path else {
            return NtStatus::INVALID_FILE_FOR_SECTION;
        };
        let mapping = match crate::loader::load_image_section(
            self.global.platform,
            self.fs.clone(),
            fs_path,
            &self.global.page_manager,
            &self.process.virtual_allocations,
        ) {
            Ok(mapping) => mapping,
            Err(error) => {
                litebox_util_log::debug!(
                    path:% = fs_path,
                    error:? = error;
                    "NtMapViewOfSection image load failed"
                );
                return match error {
                    crate::loader::WindowsLoadError::Access(_) => NtStatus::OBJECT_NAME_NOT_FOUND,
                    crate::loader::WindowsLoadError::Load(_) => NtStatus::NO_MEMORY,
                    _ => NtStatus::INVALID_FILE_FOR_SECTION,
                };
            }
        };
        if request
            .base_address
            .write_at_offset(0, mapping.base_addr)
            .is_none()
            || request
                .view_size
                .write_at_offset(0, mapping.image_size)
                .is_none()
        {
            let _ = remove_view_pages::<Platform>(
                &self.global.page_manager,
                mapping.base_addr,
                mapping.mapping_size,
            );
            self.process
                .virtual_allocations
                .write()
                .remove(&mapping.base_addr);
            self.process
                .image_mappings
                .write()
                .remove(&mapping.base_addr);
            return NtStatus::ACCESS_VIOLATION;
        }
        self.process.section_views.write().insert(
            mapping.base_addr,
            WindowsSectionView {
                size: mapping.mapping_size,
            },
        );
        self.process.image_mappings.write().insert(
            mapping.base_addr,
            crate::WindowsImageMapping {
                name: fs_path.clone(),
                size: mapping.image_size,
                entry_point: mapping.entry_point,
            },
        );
        NtStatus::SUCCESS
    }

    fn remove_section_view_for_address(
        &self,
        base_address: usize,
    ) -> Option<(usize, WindowsSectionView)> {
        let mut views = self.process.section_views.write();
        let (&view_base, &view) = views.range(..=base_address).next_back()?;
        let view_end = view_base.checked_add(view.size)?;
        if base_address < view_end {
            views.remove(&view_base);
            Some((view_base, view))
        } else {
            None
        }
    }

    fn read_section_name(
        &self,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
    ) -> Result<Option<String>, NtStatus> {
        let Some(object_attributes_ptr) = object_attributes else {
            return Ok(None);
        };
        let object_attributes = read_object_attributes::<Platform>(object_attributes_ptr)?;
        if object_attributes.object_name == 0 {
            return Ok(None);
        }
        let name = read_object_name::<Platform>(object_attributes.object_name)?;
        Ok(Some(
            self.resolve_object_name_path(&object_attributes, &name)?,
        ))
    }

    fn read_required_section_name(
        &self,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
    ) -> Result<String, NtStatus> {
        let Some(object_attributes_ptr) = object_attributes else {
            return Err(NtStatus::INVALID_PARAMETER);
        };
        let object_attributes = read_object_attributes::<Platform>(object_attributes_ptr)?;
        if object_attributes.object_name == 0 {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let name = read_object_name::<Platform>(object_attributes.object_name)?;
        self.resolve_object_name_path(&object_attributes, &name)
    }
}

fn read_object_name<Platform: ShimPlatform>(object_name: usize) -> Result<String, NtStatus> {
    let unicode = ConstPtr::<Platform, UnicodeString>::from_usize(object_name)
        .read_at_offset(0)
        .ok_or(NtStatus::ACCESS_VIOLATION)?;
    let name = unicode.read_string::<Platform>()?;
    if name.is_empty() {
        return Err(NtStatus::OBJECT_NAME_INVALID);
    }
    Ok(name)
}

fn section_missing_status(parent_exists: bool) -> NtStatus {
    if parent_exists {
        NtStatus::OBJECT_NAME_NOT_FOUND
    } else {
        NtStatus::OBJECT_PATH_NOT_FOUND
    }
}

fn known_dll_section_fs_path(object_path: &str) -> Option<String> {
    let (prefix, fs_directory) =
        if let Some(rest) = strip_case_insensitive_prefix(object_path, r"\KnownDlls\") {
            (rest, "/Windows/System32/")
        } else if let Some(rest) = strip_case_insensitive_prefix(object_path, r"\KnownDlls32\") {
            (rest, "/Windows/SysWOW64/")
        } else {
            return None;
        };
    if prefix.contains(['\\', '/']) || !ends_with_ignore_ascii_case(prefix, ".dll") {
        return None;
    }
    let mut fs_path = String::from(fs_directory);
    fs_path.push_str(&prefix.to_ascii_lowercase());
    Some(fs_path)
}

fn strip_case_insensitive_prefix<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    value
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
        .then_some(&value[prefix.len()..])
}

fn ends_with_ignore_ascii_case(value: &str, suffix: &str) -> bool {
    value
        .get(value.len().saturating_sub(suffix.len())..)
        .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
}

fn required_map_access(protection: PageProtection) -> Result<SectionAccess, NtStatus> {
    let base = protection.base();
    let required = if base == PageProtection::PAGE_EXECUTE_READWRITE.bits() {
        SectionAccess::MAP_WRITE | SectionAccess::MAP_EXECUTE
    } else if base == PageProtection::PAGE_READWRITE.bits() {
        SectionAccess::MAP_WRITE
    } else if matches!(
        base,
        value if value == PageProtection::PAGE_EXECUTE.bits()
            || value == PageProtection::PAGE_EXECUTE_READ.bits()
            || value == PageProtection::PAGE_EXECUTE_WRITECOPY.bits()
    ) {
        SectionAccess::MAP_EXECUTE
    } else if base == PageProtection::PAGE_NOACCESS.bits() {
        return Err(NtStatus::SECTION_PROTECTION);
    } else {
        SectionAccess::MAP_READ
    };
    Ok(required)
}

fn write_section_basic_information<Platform: ShimPlatform>(
    section: &SectionObject,
    section_information: MutPtr<Platform, u8>,
    section_information_length: usize,
    return_length: Option<MutPtr<Platform, usize>>,
) -> NtStatus {
    let required_len = size_of::<SectionBasicInformation>();
    if let Some(return_length) = return_length
        && return_length.write_at_offset(0, required_len).is_none()
    {
        return NtStatus::ACCESS_VIOLATION;
    }
    if section_information_length < required_len {
        return NtStatus::INFO_LENGTH_MISMATCH;
    }
    let Ok(size) = i64::try_from(section.size) else {
        return NtStatus::SECTION_TOO_BIG;
    };
    let info = SectionBasicInformation {
        base_address: 0,
        attributes: section.attributes,
        _padding: 0,
        size,
    };
    let output =
        MutPtr::<Platform, SectionBasicInformation>::from_usize(section_information.as_usize());
    if output.write_at_offset(0, info).is_none() {
        return NtStatus::ACCESS_VIOLATION;
    }
    NtStatus::SUCCESS
}

fn write_section_image_information<Platform: ShimPlatform>(
    section: &SectionObject,
    section_information: MutPtr<Platform, u8>,
    section_information_length: usize,
    return_length: Option<MutPtr<Platform, usize>>,
) -> NtStatus {
    if section.backing != SectionBacking::ImageFile {
        return NtStatus::SECTION_NOT_IMAGE;
    }
    let required_len = SECTION_IMAGE_INFORMATION_SIZE;
    if let Some(return_length) = return_length
        && return_length.write_at_offset(0, required_len).is_none()
    {
        return NtStatus::ACCESS_VIOLATION;
    }
    if section_information_length < required_len {
        return NtStatus::INFO_LENGTH_MISMATCH;
    }
    for offset in 0..required_len {
        let Ok(offset) = isize::try_from(offset) else {
            return NtStatus::INVALID_PARAMETER;
        };
        if section_information.write_at_offset(offset, 0).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }
    }
    NtStatus::SUCCESS
}

fn committed_pages(
    base: usize,
    size: usize,
    protect: PageProtection,
) -> RangeMap<usize, PageProtection> {
    let mut pages = RangeMap::new();
    if let Some(end) = base.checked_add(size) {
        pages.insert(base..end, protect);
    }
    pages
}

fn remove_view_pages<Platform: ShimPlatform>(
    page_manager: &crate::WindowsPageManager<Platform>,
    base: usize,
    size: usize,
) -> Result<(), ()> {
    let ptr = MutPtr::<Platform, u8>::from_usize(base);
    // SAFETY: The caller passes a view range created by this syscall path and not yet exposed, or
    // a tracked view being rolled back after output write failure.
    unsafe { page_manager.remove_pages(ptr, size) }.map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use core::mem::{size_of, size_of_val};

    use litebox_common_windows::nt_status::NtStatus;
    use zerocopy::FromZeros as _;

    use super::*;
    use crate::nt_types::{ObjectAttributes, ProcessEnvironmentBlock, UnicodeString};
    use crate::tests::{TestFS, TestPlatform, const_ptr, mut_byte_ptr, mut_ptr};

    fn wide(value: &str) -> alloc::vec::Vec<u16> {
        value.encode_utf16().collect()
    }

    fn unicode(value: &[u16]) -> UnicodeString {
        UnicodeString {
            length: u16::try_from(size_of_val(value)).unwrap(),
            maximum_length: u16::try_from(size_of_val(value)).unwrap(),
            padding_0: [0; 4],
            buffer: value.as_ptr() as usize,
        }
    }

    fn object_attributes(name: &UnicodeString) -> ObjectAttributes {
        ObjectAttributes {
            length: u32::try_from(size_of::<ObjectAttributes>()).unwrap(),
            root_directory: Handle::from_raw(0),
            object_name: core::ptr::from_ref(name) as usize,
            attributes: 0,
            security_descriptor: 0,
            security_quality_of_service: 0,
        }
    }

    fn create_pagefile_section(
        task: &Task<TestPlatform, TestFS>,
        access: u32,
        size: i64,
    ) -> Handle {
        let mut handle = Handle::from_raw(usize::MAX);
        assert_eq!(
            task.sys_nt_create_section(
                mut_ptr(&mut handle),
                access,
                None,
                Some(const_ptr(&size)),
                PageProtection::PAGE_READWRITE.bits(),
                SEC_COMMIT,
                Handle::from_raw(0),
            ),
            NtStatus::SUCCESS
        );
        handle
    }

    #[test]
    fn nt_create_section_creates_queryable_pagefile_section() {
        let task = crate::tests::test_task();
        let handle = create_pagefile_section(&task, SectionAccess::ALL_ACCESS.bits(), 0x2345);
        let mut info = SectionBasicInformation {
            base_address: usize::MAX,
            attributes: u32::MAX,
            _padding: u32::MAX,
            size: -1,
        };
        let mut return_length = 0usize;

        assert_eq!(
            task.sys_nt_query_section(
                handle,
                SectionInformationClass::Basic as u32,
                mut_byte_ptr(&mut info),
                size_of::<SectionBasicInformation>(),
                Some(mut_ptr(&mut return_length)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(return_length, size_of::<SectionBasicInformation>());
        assert_eq!(info.base_address, 0);
        assert_eq!(info.attributes, SEC_COMMIT);
        assert_eq!(info.size, 0x3000);
    }

    #[test]
    fn nt_query_section_enforces_query_access() {
        let task = crate::tests::test_task();
        let handle = create_pagefile_section(&task, SectionAccess::MAP_READ.bits(), 0x1000);
        let mut info = [0u8; 24];

        assert_eq!(
            task.sys_nt_query_section(
                handle,
                SectionInformationClass::Basic as u32,
                mut_byte_ptr(&mut info),
                info.len(),
                None,
            ),
            NtStatus::ACCESS_DENIED
        );
    }

    #[test]
    fn nt_map_view_of_section_maps_and_unmaps_pagefile_section() {
        let task = crate::tests::test_task();
        let handle = create_pagefile_section(&task, SectionAccess::ALL_ACCESS.bits(), 0x2000);
        let mut base = 0usize;
        let mut view_size = 0usize;

        assert_eq!(
            task.sys_nt_map_view_of_section(MapViewOfSectionParameters {
                section_handle: handle,
                process_handle: ProcessHandle::CURRENT,
                base_address: mut_ptr(&mut base),
                zero_bits: 0,
                commit_size: 0,
                section_offset: None,
                view_size: mut_ptr(&mut view_size),
                inherit_disposition: VIEW_SHARE,
                allocation_type: 0,
                page_protection: PageProtection::PAGE_READWRITE.bits(),
            }),
            NtStatus::SUCCESS
        );
        assert_ne!(base, 0);
        assert_eq!(view_size, 0x2000);
        assert_eq!(
            task.sys_nt_unmap_view_of_section(ProcessHandle::CURRENT, base + 0x100),
            NtStatus::SUCCESS
        );
        assert_eq!(
            task.sys_nt_unmap_view_of_section(ProcessHandle::CURRENT, base),
            NtStatus::NOT_MAPPED_VIEW
        );
    }

    #[test]
    fn nt_map_view_of_section_allows_execute_writecopy_without_map_write() {
        let task = crate::tests::test_task();
        let handle = create_pagefile_section(
            &task,
            (SectionAccess::QUERY | SectionAccess::MAP_READ | SectionAccess::MAP_EXECUTE).bits(),
            0x2000,
        );
        let mut base = 0usize;
        let mut view_size = 0usize;

        assert_eq!(
            task.sys_nt_map_view_of_section(MapViewOfSectionParameters {
                section_handle: handle,
                process_handle: ProcessHandle::CURRENT,
                base_address: mut_ptr(&mut base),
                zero_bits: 0,
                commit_size: 0,
                section_offset: None,
                view_size: mut_ptr(&mut view_size),
                inherit_disposition: VIEW_SHARE,
                allocation_type: 0,
                page_protection: PageProtection::PAGE_EXECUTE_WRITECOPY.bits(),
            }),
            NtStatus::SUCCESS
        );
        assert_eq!(view_size, 0x2000);
        assert_eq!(
            task.sys_nt_unmap_view_of_section(ProcessHandle::CURRENT, base),
            NtStatus::SUCCESS
        );
    }

    #[test]
    fn nt_map_view_of_section_requires_execute_access_for_execute_readwrite() {
        let task = crate::tests::test_task();
        let write_only_handle = create_pagefile_section(
            &task,
            (SectionAccess::QUERY | SectionAccess::MAP_WRITE).bits(),
            0x2000,
        );
        let mut base = 0usize;
        let mut view_size = 0usize;

        assert_eq!(
            task.sys_nt_map_view_of_section(MapViewOfSectionParameters {
                section_handle: write_only_handle,
                process_handle: ProcessHandle::CURRENT,
                base_address: mut_ptr(&mut base),
                zero_bits: 0,
                commit_size: 0,
                section_offset: None,
                view_size: mut_ptr(&mut view_size),
                inherit_disposition: VIEW_SHARE,
                allocation_type: 0,
                page_protection: PageProtection::PAGE_EXECUTE_READWRITE.bits(),
            }),
            NtStatus::ACCESS_DENIED
        );

        let execute_write_handle = create_pagefile_section(
            &task,
            (SectionAccess::QUERY | SectionAccess::MAP_WRITE | SectionAccess::MAP_EXECUTE).bits(),
            0x2000,
        );
        assert_eq!(
            task.sys_nt_map_view_of_section(MapViewOfSectionParameters {
                section_handle: execute_write_handle,
                process_handle: ProcessHandle::CURRENT,
                base_address: mut_ptr(&mut base),
                zero_bits: 0,
                commit_size: 0,
                section_offset: None,
                view_size: mut_ptr(&mut view_size),
                inherit_disposition: VIEW_SHARE,
                allocation_type: 0,
                page_protection: PageProtection::PAGE_EXECUTE_READWRITE.bits(),
            }),
            NtStatus::SUCCESS
        );
        assert_eq!(
            task.sys_nt_unmap_view_of_section(ProcessHandle::CURRENT, base),
            NtStatus::SUCCESS
        );
    }

    #[test]
    fn nt_map_view_of_pagefile_section_rejects_mem_physical() {
        let task = crate::tests::test_task();
        let handle = create_pagefile_section(&task, SectionAccess::ALL_ACCESS.bits(), 0x2000);
        let mut base = 0usize;
        let mut view_size = 0usize;

        assert_eq!(
            task.sys_nt_map_view_of_section(MapViewOfSectionParameters {
                section_handle: handle,
                process_handle: ProcessHandle::CURRENT,
                base_address: mut_ptr(&mut base),
                zero_bits: 0,
                commit_size: 0,
                section_offset: None,
                view_size: mut_ptr(&mut view_size),
                inherit_disposition: VIEW_SHARE,
                allocation_type: MEM_PHYSICAL,
                page_protection: PageProtection::PAGE_READWRITE.bits(),
            }),
            NtStatus::INVALID_PARAMETER
        );
    }

    #[test]
    fn nt_map_view_of_csr_shared_section_reuses_loader_shared_base() {
        let mut task = crate::tests::test_task();
        let mut peb = ProcessEnvironmentBlock::new_zeroed();
        let shared_base = 0x7000_0000usize;
        peb.csr_server_read_only_shared_memory_base = shared_base as u64;
        alloc::sync::Arc::get_mut(&mut task.process)
            .expect("test task has a unique process reference")
            .peb_address = core::ptr::from_mut(&mut peb) as usize;
        let name = wide(WINDOWS_SHARED_SECTION_OBJECT);
        let unicode = unicode(&name);
        let object_attributes = object_attributes(&unicode);
        let mut handle = Handle::from_raw(0);
        assert_eq!(
            task.sys_nt_open_section(
                mut_ptr(&mut handle),
                SectionAccess::ALL_ACCESS.bits(),
                Some(const_ptr(&object_attributes)),
            ),
            NtStatus::SUCCESS
        );

        let mut base = 0usize;
        let mut view_size = 0usize;
        assert_eq!(
            task.sys_nt_map_view_of_section(MapViewOfSectionParameters {
                section_handle: handle,
                process_handle: ProcessHandle::CURRENT,
                base_address: mut_ptr(&mut base),
                zero_bits: 0,
                commit_size: 0,
                section_offset: None,
                view_size: mut_ptr(&mut view_size),
                inherit_disposition: VIEW_UNMAP,
                allocation_type: MEM_TOP_DOWN | MEM_PHYSICAL,
                page_protection: PageProtection::PAGE_READONLY.bits(),
            }),
            NtStatus::SUCCESS
        );
        assert_eq!(base, shared_base);
        assert_eq!(view_size, WINDOWS_SHARED_SECTION_SIZE);
    }

    #[test]
    fn nt_open_section_opens_existing_named_section() {
        let task = crate::tests::test_task();
        let name = wide(r"\BaseNamedObjects\LiteBoxNamedSection");
        let unicode = unicode(&name);
        let object_attributes = object_attributes(&unicode);
        let size = 0x1000i64;
        let mut created = Handle::from_raw(0);
        assert_eq!(
            task.sys_nt_create_section(
                mut_ptr(&mut created),
                SectionAccess::ALL_ACCESS.bits(),
                Some(const_ptr(&object_attributes)),
                Some(const_ptr(&size)),
                PageProtection::PAGE_READWRITE.bits(),
                SEC_COMMIT,
                Handle::from_raw(0),
            ),
            NtStatus::SUCCESS
        );
        let mut opened = Handle::from_raw(0);
        assert_eq!(
            task.sys_nt_open_section(
                mut_ptr(&mut opened),
                SectionAccess::QUERY.bits(),
                Some(const_ptr(&object_attributes)),
            ),
            NtStatus::SUCCESS
        );
        assert_ne!(created, opened);
    }

    #[test]
    fn nt_open_section_reports_wrong_object_type_for_directory() {
        let task = crate::tests::test_task();
        let name = wide(r"\KnownDlls");
        let unicode = unicode(&name);
        let object_attributes = object_attributes(&unicode);
        let mut opened = Handle::from_raw(usize::MAX);

        assert_eq!(
            task.sys_nt_open_section(
                mut_ptr(&mut opened),
                SectionAccess::QUERY.bits(),
                Some(const_ptr(&object_attributes)),
            ),
            NtStatus::OBJECT_TYPE_MISMATCH
        );
    }
}
