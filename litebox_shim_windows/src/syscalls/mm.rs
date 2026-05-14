// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::mem::size_of;

use litebox::mm::linux::{CreatePagesFlags, MappingError, NonZeroAddress, NonZeroPageSize};
use litebox::platform::page_mgmt::MemoryRegionPermissions;
use litebox::platform::{PageManagementProvider, RawConstPointer as _, RawMutPointer as _};
use litebox_common_windows::nt_status::NtStatus;
use litebox_platform_multiplex::Platform;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::{PAGE_SIZE, ProcessHandle, WindowsPageManager};

type GuestMutPointer<T> = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<T>;
type GuestConstPointer<T> = <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<T>;

const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_WRITECOPY: u32 = 0x08;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
const PAGE_NOCACHE: u32 = 0x200;
const PAGE_WRITECOMBINE: u32 = 0x400;
const PAGE_BASE_MASK: u32 = 0xff;
const SUPPORTED_PAGE_MODIFIERS: u32 = PAGE_NOCACHE | PAGE_WRITECOMBINE;

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_DECOMMIT: u32 = 0x4000;
const MEM_RELEASE: u32 = 0x8000;
const MEM_FREE: u32 = 0x10000;
const MEM_PRIVATE: u32 = 0x20000;
const MEM_TOP_DOWN: u32 = 0x100000;
const SUPPORTED_ALLOCATION_TYPES: u32 = MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN;

const MEMORY_BASIC_INFORMATION_CLASS: u32 = 0;
const MEM_EXTENDED_PARAMETER_TYPE_MASK: u64 = 0xff;
const MEM_EXTENDED_PARAMETER_ADDRESS_REQUIREMENTS: u64 = 1;
const MEM_EXTENDED_PARAMETER_NUMA_NODE: u64 = 2;
const MEM_EXTENDED_PARAMETER_ATTRIBUTE_FLAGS: u64 = 5;
const MEM_EXTENDED_PARAMETER_NONPAGED: usize = 0x02;
const MEM_EXTENDED_PARAMETER_NONPAGED_LARGE: usize = 0x08;
const MEM_EXTENDED_PARAMETER_NONPAGED_HUGE: usize = 0x10;
const MEM_EXTENDED_PARAMETER_EC_CODE: usize = 0x40;
const SUPPORTED_MEM_EXTENDED_PARAMETER_ATTRIBUTE_FLAGS: usize = MEM_EXTENDED_PARAMETER_NONPAGED
    | MEM_EXTENDED_PARAMETER_NONPAGED_LARGE
    | MEM_EXTENDED_PARAMETER_NONPAGED_HUGE
    | MEM_EXTENDED_PARAMETER_EC_CODE;

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct MemoryBasicInformation {
    base_address: usize,
    allocation_base: usize,
    allocation_protect: u32,
    partition_id: u16,
    _padding0: u16,
    region_size: usize,
    state: u32,
    protect: u32,
    type_: u32,
    _padding1: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
pub(crate) struct MemoryExtendedParameter {
    type_: u64,
    value: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct MemoryAddressRequirements {
    lowest_starting_address: usize,
    highest_ending_address: usize,
    alignment: usize,
}

pub(crate) struct MemoryExtendedParameters {
    pub(crate) parameters: Option<GuestConstPointer<MemoryExtendedParameter>>,
    pub(crate) count: u32,
}

struct VirtualMemoryAllocationRequest {
    process_handle: ProcessHandle,
    base_address: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<usize>,
    zero_bits: usize,
    region_size: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<usize>,
    allocation_type: u32,
    protect: u32,
}

pub(crate) fn handle_nt_allocate_virtual_memory(
    page_manager: &WindowsPageManager,
    process_handle: ProcessHandle,
    base_address: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<usize>,
    zero_bits: usize,
    region_size: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<usize>,
    allocation_type: u32,
    protect: u32,
) -> NtStatus {
    allocate_virtual_memory(
        page_manager,
        VirtualMemoryAllocationRequest {
            process_handle,
            base_address,
            zero_bits,
            region_size,
            allocation_type,
            protect,
        },
    )
}

pub(crate) fn handle_nt_allocate_virtual_memory_ex(
    page_manager: &WindowsPageManager,
    process_handle: ProcessHandle,
    base_address: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<usize>,
    region_size: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<usize>,
    allocation_type: u32,
    protect: u32,
    extended_parameters: MemoryExtendedParameters,
) -> NtStatus {
    if !process_handle.is_current() {
        return NtStatus::INVALID_HANDLE;
    }

    if let Err(status) = validate_memory_extended_parameters(extended_parameters) {
        return status;
    }

    allocate_virtual_memory(
        page_manager,
        VirtualMemoryAllocationRequest {
            process_handle,
            base_address,
            zero_bits: 0,
            region_size,
            allocation_type,
            protect,
        },
    )
}

fn allocate_virtual_memory(
    page_manager: &WindowsPageManager,
    request: VirtualMemoryAllocationRequest,
) -> NtStatus {
    let VirtualMemoryAllocationRequest {
        process_handle,
        base_address,
        zero_bits,
        region_size,
        allocation_type,
        protect,
    } = request;

    if !process_handle.is_current() {
        return NtStatus::INVALID_HANDLE;
    }

    let Some(base) = base_address.read_at_offset(0) else {
        return NtStatus::ACCESS_VIOLATION;
    };
    let Some(size) = region_size.read_at_offset(0) else {
        return NtStatus::ACCESS_VIOLATION;
    };
    if zero_bits != 0 || size == 0 || allocation_type & !SUPPORTED_ALLOCATION_TYPES != 0 {
        return NtStatus::INVALID_PARAMETER;
    }
    if allocation_type & (MEM_COMMIT | MEM_RESERVE) == 0 {
        return NtStatus::INVALID_PARAMETER;
    }

    let Some((aligned_base, aligned_len)) = allocation_region(base, size) else {
        return NtStatus::INVALID_PARAMETER;
    };
    let Some(permissions) = page_protect_to_permissions(protect) else {
        return NtStatus::INVALID_PAGE_PROTECTION;
    };

    if allocation_type & MEM_RESERVE == 0 {
        if base == 0 {
            return NtStatus::INVALID_PARAMETER;
        }
        if update_permissions(page_manager, aligned_base, aligned_len, permissions).is_err() {
            return NtStatus::INVALID_PARAMETER;
        }
        if base_address.write_at_offset(0, aligned_base).is_none()
            || region_size.write_at_offset(0, aligned_len).is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }

        litebox_util_log::debug!(
            process_handle:% = format_args!("{:#x}", process_handle.as_raw()),
            base:% = format_args!("{:#x}", base),
            aligned_base:% = format_args!("{:#x}", aligned_base),
            aligned_len = aligned_len,
            allocation_type:% = format_args!("{:#x}", allocation_type),
            protect:% = format_args!("{:#x}", protect);
            "Handled virtual memory commit syscall"
        );

        return NtStatus::SUCCESS;
    }

    let suggested_address = NonZeroAddress::new(aligned_base);
    let Some(length) = NonZeroPageSize::new(aligned_len) else {
        return NtStatus::INVALID_PARAMETER;
    };
    let flags = if suggested_address.is_some() {
        CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE
    } else {
        CreatePagesFlags::empty()
    };

    let allocation = create_pages(
        page_manager,
        suggested_address,
        length,
        flags,
        permissions,
        |_| Ok(0),
    );
    let ptr = match allocation {
        Ok(ptr) => ptr,
        Err(status) => return status,
    };
    if base_address.write_at_offset(0, ptr.as_usize()).is_none()
        || region_size.write_at_offset(0, aligned_len).is_none()
    {
        return NtStatus::ACCESS_VIOLATION;
    }

    litebox_util_log::debug!(
        process_handle:% = format_args!("{:#x}", process_handle.as_raw()),
        base:% = format_args!("{:#x}", base),
        aligned_base:% = format_args!("{:#x}", ptr.as_usize()),
        aligned_len = aligned_len,
        allocation_type:% = format_args!("{:#x}", allocation_type),
        protect:% = format_args!("{:#x}", protect);
        "Handled virtual memory allocation syscall"
    );

    NtStatus::SUCCESS
}

fn validate_memory_extended_parameters(
    extended_parameters: MemoryExtendedParameters,
) -> Result<(), NtStatus> {
    if extended_parameters.count == 0 {
        return Ok(());
    }

    let Some(parameters) = extended_parameters.parameters else {
        return Err(NtStatus::ACCESS_VIOLATION);
    };
    let count =
        usize::try_from(extended_parameters.count).map_err(|_| NtStatus::INVALID_PARAMETER)?;
    for index in 0..count {
        let index = isize::try_from(index).map_err(|_| NtStatus::INVALID_PARAMETER)?;
        let parameter = parameters
            .read_at_offset(index)
            .ok_or(NtStatus::ACCESS_VIOLATION)?;
        validate_memory_extended_parameter(parameter)?;
    }

    Ok(())
}

fn validate_memory_extended_parameter(parameter: MemoryExtendedParameter) -> Result<(), NtStatus> {
    if parameter.type_ & !MEM_EXTENDED_PARAMETER_TYPE_MASK != 0 {
        return Err(NtStatus::INVALID_PARAMETER);
    }

    match parameter.type_ & MEM_EXTENDED_PARAMETER_TYPE_MASK {
        MEM_EXTENDED_PARAMETER_ADDRESS_REQUIREMENTS => {
            let address_requirements =
                GuestConstPointer::<MemoryAddressRequirements>::from_usize(parameter.value)
                    .read_at_offset(0)
                    .ok_or(NtStatus::ACCESS_VIOLATION)?;
            if address_requirements.lowest_starting_address != 0
                || address_requirements.highest_ending_address != 0
                || address_requirements.alignment != 0
            {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            Ok(())
        }
        MEM_EXTENDED_PARAMETER_NUMA_NODE => Ok(()),
        MEM_EXTENDED_PARAMETER_ATTRIBUTE_FLAGS => {
            if parameter.value & !SUPPORTED_MEM_EXTENDED_PARAMETER_ATTRIBUTE_FLAGS != 0 {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            Ok(())
        }
        _ => Err(NtStatus::INVALID_PARAMETER),
    }
}

pub(crate) fn handle_nt_free_virtual_memory(
    page_manager: &WindowsPageManager,
    process_handle: ProcessHandle,
    base_address: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<usize>,
    region_size: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<usize>,
    free_type: u32,
) -> NtStatus {
    if !process_handle.is_current() {
        return NtStatus::INVALID_HANDLE;
    }

    let Some(base) = base_address.read_at_offset(0) else {
        return NtStatus::ACCESS_VIOLATION;
    };
    let Some(size) = region_size.read_at_offset(0) else {
        return NtStatus::ACCESS_VIOLATION;
    };
    if base == 0 || !matches!(free_type, MEM_DECOMMIT | MEM_RELEASE) {
        return NtStatus::INVALID_PARAMETER;
    }

    let Some((aligned_base, aligned_len)) = free_region(page_manager, base, size, free_type) else {
        return NtStatus::INVALID_PARAMETER;
    };

    let ptr = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer::<u8>::from_usize(
        aligned_base,
    );
    // SAFETY: This implements the guest's explicit NtFreeVirtualMemory request for a page-aligned
    // range tracked by the LiteBox page manager. The caller is responsible for not using the region
    // after the syscall succeeds.
    if unsafe { page_manager.remove_pages(ptr, aligned_len) }.is_err() {
        return NtStatus::UNABLE_TO_FREE_VM;
    }
    if base_address.write_at_offset(0, aligned_base).is_none()
        || region_size.write_at_offset(0, aligned_len).is_none()
    {
        return NtStatus::ACCESS_VIOLATION;
    }

    litebox_util_log::debug!(
        process_handle:% = format_args!("{:#x}", process_handle.as_raw()),
        base:% = format_args!("{:#x}", base),
        size = size,
        aligned_base:% = format_args!("{:#x}", aligned_base),
        aligned_len = aligned_len,
        free_type:% = format_args!("{:#x}", free_type);
        "Handled NtFreeVirtualMemory syscall"
    );

    NtStatus::SUCCESS
}

pub(crate) fn handle_nt_protect_virtual_memory(
    page_manager: &WindowsPageManager,
    process_handle: ProcessHandle,
    base_address: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<usize>,
    region_size: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<usize>,
    new_protect: u32,
    old_protect: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u32>,
) -> NtStatus {
    if !process_handle.is_current() {
        return NtStatus::INVALID_HANDLE;
    }

    let Some(base) = base_address.read_at_offset(0) else {
        return NtStatus::ACCESS_VIOLATION;
    };
    let Some(size) = region_size.read_at_offset(0) else {
        return NtStatus::ACCESS_VIOLATION;
    };
    if base == 0 || size == 0 {
        return NtStatus::INVALID_PARAMETER;
    }

    let Some((aligned_base, aligned_len)) = page_aligned_region(base, size) else {
        return NtStatus::INVALID_PARAMETER;
    };
    let Some(new_permissions) = page_protect_to_permissions(new_protect) else {
        return NtStatus::INVALID_PAGE_PROTECTION;
    };

    let Some(old_permissions) = page_manager.get_memory_permissions(
        NonZeroAddress::new(aligned_base).expect("aligned_base is non-zero"),
        NonZeroPageSize::new(PAGE_SIZE).expect("PAGE_SIZE is non-zero and aligned"),
    ) else {
        return NtStatus::ACCESS_VIOLATION;
    };
    let old_protect_value = permissions_to_page_protect(old_permissions);

    if update_permissions(page_manager, aligned_base, aligned_len, new_permissions).is_err() {
        return NtStatus::ACCESS_VIOLATION;
    }

    let output_ok = old_protect.write_at_offset(0, old_protect_value).is_some()
        && base_address.write_at_offset(0, aligned_base).is_some()
        && region_size.write_at_offset(0, aligned_len).is_some();

    litebox_util_log::debug!(
        process_handle:% = format_args!("{:#x}", process_handle.as_raw()),
        base:% = format_args!("{:#x}", base),
        size = size,
        aligned_base:% = format_args!("{:#x}", aligned_base),
        aligned_len = aligned_len,
        new_protect:% = format_args!("{:#x}", new_protect),
        old_protect:% = format_args!("{:#x}", old_protect_value),
        output_ok = output_ok;
        "Handled NtProtectVirtualMemory syscall"
    );

    if output_ok {
        NtStatus::SUCCESS
    } else {
        NtStatus::ACCESS_VIOLATION
    }
}

pub(crate) fn handle_nt_query_virtual_memory(
    page_manager: &WindowsPageManager,
    process_handle: ProcessHandle,
    base_address: usize,
    memory_information_class: u32,
    memory_information: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u8>,
    memory_information_length: usize,
    return_length: Option<
        <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<usize>,
    >,
) -> NtStatus {
    if !process_handle.is_current() {
        return NtStatus::INVALID_HANDLE;
    }

    if memory_information_class != MEMORY_BASIC_INFORMATION_CLASS {
        return NtStatus::INVALID_INFO_CLASS;
    }

    let required_len = size_of::<MemoryBasicInformation>();
    if let Some(return_length) = return_length
        && return_length.write_at_offset(0, required_len).is_none()
    {
        return NtStatus::ACCESS_VIOLATION;
    }
    if memory_information_length < required_len {
        return NtStatus::INFO_LENGTH_MISMATCH;
    }

    let Some(info) = query_memory_basic_information(page_manager, base_address) else {
        return NtStatus::INVALID_PARAMETER;
    };

    let output = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer::<
        MemoryBasicInformation,
    >::from_usize(memory_information.as_usize());
    if output.write_at_offset(0, info).is_none() {
        return NtStatus::ACCESS_VIOLATION;
    }

    litebox_util_log::debug!(
        process_handle:% = format_args!("{:#x}", process_handle.as_raw()),
        base:% = format_args!("{:#x}", base_address),
        result_base:% = format_args!("{:#x}", info.base_address),
        region_size = info.region_size,
        state:% = format_args!("{:#x}", info.state),
        protect:% = format_args!("{:#x}", info.protect);
        "Handled NtQueryVirtualMemory syscall"
    );

    NtStatus::SUCCESS
}

fn page_aligned_region(base: usize, size: usize) -> Option<(usize, usize)> {
    let aligned_base = base & !(PAGE_SIZE - 1);
    let end = base.checked_add(size)?;
    let aligned_end = end.checked_add(PAGE_SIZE - 1)? & !(PAGE_SIZE - 1);
    let aligned_len = aligned_end.checked_sub(aligned_base)?;
    if aligned_base == 0 || aligned_len == 0 {
        return None;
    }
    Some((aligned_base, aligned_len))
}

fn allocation_region(base: usize, size: usize) -> Option<(usize, usize)> {
    let aligned_base = base & !(PAGE_SIZE - 1);
    let end = base.checked_add(size)?;
    let aligned_end = end.checked_add(PAGE_SIZE - 1)? & !(PAGE_SIZE - 1);
    let aligned_len = aligned_end.checked_sub(aligned_base)?;
    if aligned_len == 0 {
        return None;
    }
    Some((aligned_base, aligned_len))
}

fn free_region(
    page_manager: &WindowsPageManager,
    base: usize,
    size: usize,
    free_type: u32,
) -> Option<(usize, usize)> {
    if free_type == MEM_RELEASE {
        if size != 0 {
            return None;
        }
        return page_manager
            .mappings()
            .into_iter()
            .find(|(range, _)| range.contains(&base))
            .map(|(range, _)| (range.start, range.end - range.start));
    }

    page_aligned_region(base, size)
}

fn page_protect_to_permissions(protect: u32) -> Option<MemoryRegionPermissions> {
    if protect & !(PAGE_BASE_MASK | SUPPORTED_PAGE_MODIFIERS) != 0 {
        return None;
    }

    match protect & PAGE_BASE_MASK {
        PAGE_NOACCESS => Some(MemoryRegionPermissions::empty()),
        PAGE_READONLY => Some(MemoryRegionPermissions::READ),
        PAGE_READWRITE | PAGE_WRITECOPY => {
            Some(MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE)
        }
        PAGE_EXECUTE | PAGE_EXECUTE_READ => {
            Some(MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC)
        }
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY => Some(
            MemoryRegionPermissions::READ
                | MemoryRegionPermissions::WRITE
                | MemoryRegionPermissions::EXEC,
        ),
        _ => None,
    }
}

pub(crate) fn create_pages(
    page_manager: &WindowsPageManager,
    suggested_address: Option<NonZeroAddress<PAGE_SIZE>>,
    length: NonZeroPageSize<PAGE_SIZE>,
    flags: CreatePagesFlags,
    permissions: MemoryRegionPermissions,
    op: impl FnOnce(GuestMutPointer<u8>) -> Result<usize, MappingError>,
) -> Result<GuestMutPointer<u8>, NtStatus> {
    // SAFETY: This creates page-aligned guest mappings through the LiteBox page manager. The
    // caller chooses fixed-address behavior via `flags`, and the initializer only writes to the
    // newly-created mapping before it is exposed with the requested final permissions.
    unsafe {
        match permissions {
            permissions if permissions.is_empty() => page_manager
                .create_inaccessible_pages(suggested_address, length, flags, op)
                .map_err(|_| NtStatus::NO_MEMORY),
            MemoryRegionPermissions::READ => page_manager
                .create_readable_pages(suggested_address, length, flags, op)
                .map_err(|_| NtStatus::NO_MEMORY),
            permissions
                if permissions
                    == MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE =>
            {
                page_manager
                    .create_writable_pages(suggested_address, length, flags, op)
                    .map_err(|_| NtStatus::NO_MEMORY)
            }
            permissions
                if permissions == MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC =>
            {
                page_manager
                    .create_executable_pages(suggested_address, length, flags, op)
                    .map_err(|_| NtStatus::NO_MEMORY)
            }
            permissions
                if permissions
                    == MemoryRegionPermissions::READ
                        | MemoryRegionPermissions::WRITE
                        | MemoryRegionPermissions::EXEC =>
            {
                let ptr = page_manager
                    .create_writable_pages(suggested_address, length, flags, op)
                    .map_err(|_| NtStatus::NO_MEMORY)?;
                page_manager
                    .make_pages_rwx(ptr, length.as_usize())
                    .map_err(|_| NtStatus::NO_MEMORY)?;
                Ok(ptr)
            }
            _ => Err(NtStatus::INVALID_PAGE_PROTECTION),
        }
    }
}

fn permissions_to_page_protect(permissions: MemoryRegionPermissions) -> u32 {
    match (
        permissions.contains(MemoryRegionPermissions::READ),
        permissions.contains(MemoryRegionPermissions::WRITE),
        permissions.contains(MemoryRegionPermissions::EXEC),
    ) {
        (false, false, false) => PAGE_NOACCESS,
        (true, false, false) => PAGE_READONLY,
        (false | true, true, false) => PAGE_READWRITE,
        (false, false, true) => PAGE_EXECUTE,
        (true, false, true) => PAGE_EXECUTE_READ,
        (false | true, true, true) => PAGE_EXECUTE_READWRITE,
    }
}

fn update_permissions(
    page_manager: &WindowsPageManager,
    aligned_base: usize,
    aligned_len: usize,
    permissions: MemoryRegionPermissions,
) -> Result<(), ()> {
    let ptr = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer::<u8>::from_usize(
        aligned_base,
    );

    // SAFETY: This implements the guest's explicit NtProtectVirtualMemory request for a
    // page-aligned range tracked by the LiteBox page manager. The page manager serializes the VMA
    // update; callers must still avoid racing guest execution against permission changes.
    let result = unsafe {
        match permissions {
            permissions if permissions.is_empty() => {
                page_manager.make_pages_inaccessible(ptr, aligned_len)
            }
            MemoryRegionPermissions::READ => page_manager.make_pages_readable(ptr, aligned_len),
            permissions
                if permissions
                    == MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE =>
            {
                page_manager.make_pages_writable(ptr, aligned_len)
            }
            permissions
                if permissions == MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC =>
            {
                page_manager.make_pages_executable(ptr, aligned_len)
            }
            permissions
                if permissions
                    == MemoryRegionPermissions::READ
                        | MemoryRegionPermissions::WRITE
                        | MemoryRegionPermissions::EXEC =>
            {
                page_manager.make_pages_rwx(ptr, aligned_len)
            }
            _ => return Err(()),
        }
    };

    result.map_err(|_| ())
}

fn query_memory_basic_information(
    page_manager: &WindowsPageManager,
    base_address: usize,
) -> Option<MemoryBasicInformation> {
    let query_base = base_address & !(PAGE_SIZE - 1);
    if query_base >= <Platform as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX {
        return None;
    }

    let mut mappings = page_manager.mappings();
    mappings.sort_by_key(|(range, _)| range.start);

    if let Some((range, flags)) = mappings
        .iter()
        .find(|(range, _)| range.contains(&base_address))
    {
        let protect = permissions_to_page_protect(MemoryRegionPermissions::from(*flags));
        return Some(MemoryBasicInformation {
            base_address: range.start,
            allocation_base: range.start,
            allocation_protect: protect,
            partition_id: 0,
            _padding0: 0,
            region_size: range.end - range.start,
            state: MEM_COMMIT,
            protect,
            type_: MEM_PRIVATE,
            _padding1: 0,
        });
    }

    let next_mapping_start = mappings
        .iter()
        .find(|(range, _)| range.start > query_base)
        .map_or(
            <Platform as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX,
            |(range, _)| range.start,
        );

    Some(MemoryBasicInformation {
        base_address: query_base,
        allocation_base: 0,
        allocation_protect: 0,
        partition_id: 0,
        _padding0: 0,
        region_size: next_mapping_start.saturating_sub(query_base),
        state: MEM_FREE,
        protect: 0,
        type_: 0,
        _padding1: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox::{LiteBox, platform::RawPointerProvider};

    extern crate std;

    type MutPtr<T> = <Platform as RawPointerProvider>::RawMutPointer<T>;

    const ALLOC_TEST_BASE: usize = 0x1000_0000;
    const FIXED_TEST_BASE: usize = 0x1100_0000;
    const PROTECT_TEST_BASE: usize = 0x1200_0000;
    const QUERY_TEST_BASE: usize = 0x1300_0000;
    const FREE_TEST_BASE: usize = 0x1400_0000;
    const COMMIT_TEST_BASE: usize = 0x1500_0000;
    const OTHER_PROCESS_HANDLE: ProcessHandle = ProcessHandle::from_raw(0x1234);

    fn init_platform() {
        crate::tests::init_platform();
    }

    fn page_manager() -> WindowsPageManager {
        init_platform();
        let litebox = LiteBox::new(litebox_platform_multiplex::platform());
        WindowsPageManager::new(&litebox)
    }

    fn mut_ptr<T: FromBytes + IntoBytes>(value: &mut T) -> MutPtr<T> {
        MutPtr::from_usize(core::ptr::from_mut(value).cast::<u8>() as usize)
    }

    fn mut_byte_ptr<T>(value: &mut T) -> MutPtr<u8> {
        MutPtr::from_usize(core::ptr::from_mut(value).cast::<u8>() as usize)
    }

    fn empty_memory_basic_information() -> MemoryBasicInformation {
        MemoryBasicInformation {
            base_address: 0,
            allocation_base: 0,
            allocation_protect: 0,
            partition_id: 0,
            _padding0: 0,
            region_size: 0,
            state: 0,
            protect: 0,
            type_: 0,
            _padding1: 0,
        }
    }

    fn release_mapping(page_manager: &WindowsPageManager, base: usize) {
        let mut base = base;
        let mut size = 0usize;
        assert_eq!(
            handle_nt_free_virtual_memory(
                page_manager,
                ProcessHandle::CURRENT,
                mut_ptr(&mut base),
                mut_ptr(&mut size),
                MEM_RELEASE,
            ),
            NtStatus::SUCCESS
        );
    }

    #[test]
    fn memory_basic_information_matches_windows_x64_layout() {
        assert_eq!(size_of::<MemoryBasicInformation>(), 48);
        assert_eq!(align_of::<MemoryBasicInformation>(), 8);
    }

    #[test]
    fn memory_extended_parameter_matches_windows_x64_layout() {
        assert_eq!(size_of::<MemoryExtendedParameter>(), 16);
        assert_eq!(align_of::<MemoryExtendedParameter>(), 8);
        assert_eq!(size_of::<MemoryAddressRequirements>(), 24);
        assert_eq!(align_of::<MemoryAddressRequirements>(), 8);
    }

    #[test]
    fn nt_allocate_virtual_memory_allocates_writable_pages() {
        let page_manager = page_manager();
        let mut base = ALLOC_TEST_BASE;
        let mut size = PAGE_SIZE + 1;

        assert_eq!(
            handle_nt_allocate_virtual_memory(
                &page_manager,
                ProcessHandle::CURRENT,
                mut_ptr(&mut base),
                0,
                mut_ptr(&mut size),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(base, ALLOC_TEST_BASE);
        assert_eq!(size, PAGE_SIZE * 2);

        let data = MutPtr::<u8>::from_usize(base);
        data.write_slice_at_offset(0, &[0xab; PAGE_SIZE * 2])
            .unwrap();
        assert_eq!(
            data.read_at_offset(PAGE_SIZE.try_into().unwrap()),
            Some(0xab)
        );
        assert_eq!(
            page_manager.get_memory_permissions(
                NonZeroAddress::new(base).unwrap(),
                NonZeroPageSize::new(size).unwrap(),
            ),
            Some(MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE)
        );

        release_mapping(&page_manager, base);
    }

    #[test]
    fn nt_allocate_virtual_memory_ex_allocates_writable_pages() {
        let page_manager = page_manager();
        let mut base = ALLOC_TEST_BASE + 0x10_0000;
        let mut size = PAGE_SIZE + 1;

        assert_eq!(
            handle_nt_allocate_virtual_memory_ex(
                &page_manager,
                ProcessHandle::CURRENT,
                mut_ptr(&mut base),
                mut_ptr(&mut size),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
                MemoryExtendedParameters {
                    parameters: None,
                    count: 0,
                },
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(base, ALLOC_TEST_BASE + 0x10_0000);
        assert_eq!(size, PAGE_SIZE * 2);

        let data = MutPtr::<u8>::from_usize(base);
        data.write_slice_at_offset(0, &[0xcd; PAGE_SIZE * 2])
            .unwrap();
        assert_eq!(
            data.read_at_offset(PAGE_SIZE.try_into().unwrap()),
            Some(0xcd)
        );

        release_mapping(&page_manager, base);
    }

    #[test]
    fn nt_allocate_virtual_memory_ex_accepts_supported_extended_parameter_hints() {
        let page_manager = page_manager();
        let mut base = ALLOC_TEST_BASE + 0x20_0000;
        let mut size = PAGE_SIZE;
        let address_requirements = MemoryAddressRequirements {
            lowest_starting_address: 0,
            highest_ending_address: 0,
            alignment: 0,
        };
        let extended_parameters = [
            MemoryExtendedParameter {
                type_: MEM_EXTENDED_PARAMETER_ADDRESS_REQUIREMENTS,
                value: core::ptr::from_ref(&address_requirements) as usize,
            },
            MemoryExtendedParameter {
                type_: MEM_EXTENDED_PARAMETER_NUMA_NODE,
                value: 0,
            },
            MemoryExtendedParameter {
                type_: MEM_EXTENDED_PARAMETER_ATTRIBUTE_FLAGS,
                value: MEM_EXTENDED_PARAMETER_EC_CODE,
            },
        ];

        assert_eq!(
            handle_nt_allocate_virtual_memory_ex(
                &page_manager,
                ProcessHandle::CURRENT,
                mut_ptr(&mut base),
                mut_ptr(&mut size),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
                MemoryExtendedParameters {
                    parameters: Some(GuestConstPointer::<MemoryExtendedParameter>::from_usize(
                        extended_parameters.as_ptr() as usize,
                    )),
                    count: u32::try_from(extended_parameters.len()).unwrap(),
                },
            ),
            NtStatus::SUCCESS
        );

        release_mapping(&page_manager, base);
    }

    #[test]
    fn nt_allocate_virtual_memory_ex_rejects_unsupported_address_requirements() {
        let page_manager = page_manager();
        let mut base = ALLOC_TEST_BASE + 0x30_0000;
        let mut size = PAGE_SIZE;
        let address_requirements = MemoryAddressRequirements {
            lowest_starting_address: 0,
            highest_ending_address: 0x7fff_ffff,
            alignment: 0,
        };
        let extended_parameters = [MemoryExtendedParameter {
            type_: MEM_EXTENDED_PARAMETER_ADDRESS_REQUIREMENTS,
            value: core::ptr::from_ref(&address_requirements) as usize,
        }];

        assert_eq!(
            handle_nt_allocate_virtual_memory_ex(
                &page_manager,
                ProcessHandle::CURRENT,
                mut_ptr(&mut base),
                mut_ptr(&mut size),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
                MemoryExtendedParameters {
                    parameters: Some(GuestConstPointer::<MemoryExtendedParameter>::from_usize(
                        extended_parameters.as_ptr() as usize,
                    )),
                    count: u32::try_from(extended_parameters.len()).unwrap(),
                },
            ),
            NtStatus::INVALID_PARAMETER
        );
    }

    #[test]
    fn nt_allocate_virtual_memory_commits_existing_range() {
        let page_manager = page_manager();
        let mut base = COMMIT_TEST_BASE;
        let mut size = PAGE_SIZE;

        assert_eq!(
            handle_nt_allocate_virtual_memory(
                &page_manager,
                ProcessHandle::CURRENT,
                mut_ptr(&mut base),
                0,
                mut_ptr(&mut size),
                MEM_RESERVE,
                PAGE_READONLY,
            ),
            NtStatus::SUCCESS
        );

        let mut commit_base = COMMIT_TEST_BASE;
        let mut commit_size = 1usize;
        assert_eq!(
            handle_nt_allocate_virtual_memory(
                &page_manager,
                ProcessHandle::CURRENT,
                mut_ptr(&mut commit_base),
                0,
                mut_ptr(&mut commit_size),
                MEM_COMMIT,
                PAGE_READWRITE,
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(commit_base, COMMIT_TEST_BASE);
        assert_eq!(commit_size, PAGE_SIZE);

        let info = query_memory_basic_information(&page_manager, COMMIT_TEST_BASE).unwrap();
        assert_eq!(info.protect, PAGE_READWRITE);

        release_mapping(&page_manager, base);
    }

    #[test]
    fn nt_allocate_virtual_memory_fixed_address_does_not_replace_existing_mapping() {
        let page_manager = page_manager();
        let mut base = FIXED_TEST_BASE;
        let mut size = PAGE_SIZE;
        assert_eq!(
            handle_nt_allocate_virtual_memory(
                &page_manager,
                ProcessHandle::CURRENT,
                mut_ptr(&mut base),
                0,
                mut_ptr(&mut size),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READONLY,
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(base, FIXED_TEST_BASE);

        let mut overlapping_base = base;
        let mut overlapping_size = PAGE_SIZE;
        assert_eq!(
            handle_nt_allocate_virtual_memory(
                &page_manager,
                ProcessHandle::CURRENT,
                mut_ptr(&mut overlapping_base),
                0,
                mut_ptr(&mut overlapping_size),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            ),
            NtStatus::NO_MEMORY
        );

        release_mapping(&page_manager, base);
    }

    #[test]
    fn nt_protect_virtual_memory_updates_permissions_and_old_protect() {
        let page_manager = page_manager();
        let mut base = PROTECT_TEST_BASE;
        let mut size = PAGE_SIZE * 2;
        assert_eq!(
            handle_nt_allocate_virtual_memory(
                &page_manager,
                ProcessHandle::CURRENT,
                mut_ptr(&mut base),
                0,
                mut_ptr(&mut size),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            ),
            NtStatus::SUCCESS
        );

        let mut protect_base = base + 1;
        let mut protect_size = 1usize;
        let mut old_protect = 0u32;
        assert_eq!(
            handle_nt_protect_virtual_memory(
                &page_manager,
                ProcessHandle::CURRENT,
                mut_ptr(&mut protect_base),
                mut_ptr(&mut protect_size),
                PAGE_READONLY,
                mut_ptr(&mut old_protect),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(protect_base, base);
        assert_eq!(protect_size, PAGE_SIZE);
        assert_eq!(old_protect, PAGE_READWRITE);
        assert_eq!(
            page_manager.get_memory_permissions(
                NonZeroAddress::new(base).unwrap(),
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
            ),
            Some(MemoryRegionPermissions::READ)
        );

        old_protect = 0;
        assert_eq!(
            handle_nt_protect_virtual_memory(
                &page_manager,
                ProcessHandle::CURRENT,
                mut_ptr(&mut protect_base),
                mut_ptr(&mut protect_size),
                PAGE_EXECUTE_READ,
                mut_ptr(&mut old_protect),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(old_protect, PAGE_READONLY);
        assert_eq!(
            page_manager.get_memory_permissions(
                NonZeroAddress::new(base).unwrap(),
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
            ),
            Some(MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC)
        );

        release_mapping(&page_manager, base);
    }

    #[test]
    fn nt_query_virtual_memory_reports_committed_and_free_regions() {
        let page_manager = page_manager();
        let mut base = QUERY_TEST_BASE;
        let mut size = PAGE_SIZE * 2;
        assert_eq!(
            handle_nt_allocate_virtual_memory(
                &page_manager,
                ProcessHandle::CURRENT,
                mut_ptr(&mut base),
                0,
                mut_ptr(&mut size),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            ),
            NtStatus::SUCCESS
        );

        let mut info = empty_memory_basic_information();
        let mut return_length = 0usize;
        assert_eq!(
            handle_nt_query_virtual_memory(
                &page_manager,
                ProcessHandle::CURRENT,
                base + 0x10,
                MEMORY_BASIC_INFORMATION_CLASS,
                mut_byte_ptr(&mut info),
                size_of::<MemoryBasicInformation>(),
                Some(mut_ptr(&mut return_length)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(return_length, size_of::<MemoryBasicInformation>());
        assert_eq!(info.base_address, base);
        assert_eq!(info.allocation_base, base);
        assert_eq!(info.allocation_protect, PAGE_READWRITE);
        assert_eq!(info.region_size, PAGE_SIZE * 2);
        assert_eq!(info.state, MEM_COMMIT);
        assert_eq!(info.protect, PAGE_READWRITE);
        assert_eq!(info.type_, MEM_PRIVATE);

        release_mapping(&page_manager, base);

        let mut free_info = empty_memory_basic_information();
        assert_eq!(
            handle_nt_query_virtual_memory(
                &page_manager,
                ProcessHandle::CURRENT,
                base,
                MEMORY_BASIC_INFORMATION_CLASS,
                mut_byte_ptr(&mut free_info),
                size_of::<MemoryBasicInformation>(),
                None,
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(free_info.base_address, base);
        assert_eq!(free_info.state, MEM_FREE);
        assert_eq!(free_info.protect, 0);
        assert_eq!(free_info.type_, 0);
    }

    #[test]
    fn nt_free_virtual_memory_decommits_requested_pages() {
        let page_manager = page_manager();
        let mut base = FREE_TEST_BASE;
        let mut size = PAGE_SIZE;
        assert_eq!(
            handle_nt_allocate_virtual_memory(
                &page_manager,
                ProcessHandle::CURRENT,
                mut_ptr(&mut base),
                0,
                mut_ptr(&mut size),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            ),
            NtStatus::SUCCESS
        );

        let mut free_base = base;
        let mut free_size = PAGE_SIZE;
        assert_eq!(
            handle_nt_free_virtual_memory(
                &page_manager,
                ProcessHandle::CURRENT,
                mut_ptr(&mut free_base),
                mut_ptr(&mut free_size),
                MEM_DECOMMIT,
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(free_base, base);
        assert_eq!(free_size, PAGE_SIZE);
        assert_eq!(
            page_manager.get_memory_permissions(
                NonZeroAddress::new(base).unwrap(),
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
            ),
            None
        );
    }

    #[test]
    fn memory_syscalls_reject_invalid_arguments() {
        let page_manager = page_manager();
        let mut base = 0usize;
        let mut size = PAGE_SIZE;
        let mut old_protect = 0u32;
        let mut info = empty_memory_basic_information();

        assert_eq!(
            handle_nt_allocate_virtual_memory(
                &page_manager,
                ProcessHandle::CURRENT,
                mut_ptr(&mut base),
                1,
                mut_ptr(&mut size),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            ),
            NtStatus::INVALID_PARAMETER
        );
        assert_eq!(
            handle_nt_allocate_virtual_memory(
                &page_manager,
                ProcessHandle::CURRENT,
                mut_ptr(&mut base),
                0,
                mut_ptr(&mut size),
                MEM_COMMIT | MEM_RESERVE,
                0,
            ),
            NtStatus::INVALID_PAGE_PROTECTION
        );
        assert_eq!(
            handle_nt_protect_virtual_memory(
                &page_manager,
                ProcessHandle::CURRENT,
                mut_ptr(&mut base),
                mut_ptr(&mut size),
                PAGE_READONLY,
                mut_ptr(&mut old_protect),
            ),
            NtStatus::INVALID_PARAMETER
        );
        assert_eq!(
            handle_nt_query_virtual_memory(
                &page_manager,
                ProcessHandle::CURRENT,
                base,
                1,
                mut_byte_ptr(&mut info),
                size_of::<MemoryBasicInformation>(),
                None,
            ),
            NtStatus::INVALID_INFO_CLASS
        );
    }

    #[test]
    fn memory_syscalls_reject_non_current_process_handles() {
        let page_manager = page_manager();
        let mut base = ALLOC_TEST_BASE;
        let mut size = PAGE_SIZE;
        let mut old_protect = 0u32;
        let mut info = empty_memory_basic_information();

        assert_eq!(
            handle_nt_allocate_virtual_memory(
                &page_manager,
                OTHER_PROCESS_HANDLE,
                mut_ptr(&mut base),
                0,
                mut_ptr(&mut size),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            ),
            NtStatus::INVALID_HANDLE
        );
        assert_eq!(
            handle_nt_allocate_virtual_memory_ex(
                &page_manager,
                OTHER_PROCESS_HANDLE,
                mut_ptr(&mut base),
                mut_ptr(&mut size),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
                MemoryExtendedParameters {
                    parameters: None,
                    count: 0,
                },
            ),
            NtStatus::INVALID_HANDLE
        );
        assert_eq!(
            handle_nt_free_virtual_memory(
                &page_manager,
                OTHER_PROCESS_HANDLE,
                mut_ptr(&mut base),
                mut_ptr(&mut size),
                MEM_DECOMMIT,
            ),
            NtStatus::INVALID_HANDLE
        );
        assert_eq!(
            handle_nt_protect_virtual_memory(
                &page_manager,
                OTHER_PROCESS_HANDLE,
                mut_ptr(&mut base),
                mut_ptr(&mut size),
                PAGE_READONLY,
                mut_ptr(&mut old_protect),
            ),
            NtStatus::INVALID_HANDLE
        );
        assert_eq!(
            handle_nt_query_virtual_memory(
                &page_manager,
                OTHER_PROCESS_HANDLE,
                base,
                MEMORY_BASIC_INFORMATION_CLASS,
                mut_byte_ptr(&mut info),
                size_of::<MemoryBasicInformation>(),
                None,
            ),
            NtStatus::INVALID_HANDLE
        );
    }
}
