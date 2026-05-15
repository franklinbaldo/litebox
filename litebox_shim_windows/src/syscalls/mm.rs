// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::mem::size_of;

use int_enum::IntEnum;
use litebox::mm::linux::{CreatePagesFlags, MappingError, NonZeroAddress, NonZeroPageSize};
use litebox::platform::page_mgmt::MemoryRegionPermissions;
use litebox::platform::{PageManagementProvider, RawConstPointer as _, RawMutPointer as _};
use litebox_common_windows::{loader::MappingInfo, nt_status::NtStatus};
use litebox_platform_multiplex::Platform;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::{
    NtShimFS, PAGE_SIZE, ProcessHandle, Task, WindowsPageManager, WindowsVirtualAllocation,
    WindowsVirtualAllocations,
};

type GuestMutPointer<T> = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<T>;
type GuestConstPointer<T> = <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<T>;

const ALLOCATION_GRANULARITY: usize = 0x1_0000;

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

const MEMORY_IMAGE_EXTENSION_INFORMATION_SIZE: usize = 24;
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

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, IntEnum)]
enum MemoryInformationClass {
    Basic = 0,
    Image = 6,
    ImageExtension = 14,
}

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
struct MemoryImageInformation {
    image_base: usize,
    size_of_image: usize,
    image_flags: u32,
    _padding: u32,
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

impl<FS: NtShimFS> Task<FS> {
    pub(crate) fn handle_nt_allocate_virtual_memory_ex(
        &self,
        process_handle: ProcessHandle,
        base_address: GuestMutPointer<usize>,
        region_size: GuestMutPointer<usize>,
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

        self.handle_nt_allocate_virtual_memory(
            process_handle,
            base_address,
            0,
            region_size,
            allocation_type,
            protect,
        )
    }

    pub(crate) fn handle_nt_allocate_virtual_memory(
        &self,
        process_handle: ProcessHandle,
        base_address: GuestMutPointer<usize>,
        zero_bits: usize,
        region_size: GuestMutPointer<usize>,
        allocation_type: u32,
        protect: u32,
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
        if zero_bits != 0 || size == 0 || allocation_type & !SUPPORTED_ALLOCATION_TYPES != 0 {
            return NtStatus::INVALID_PARAMETER;
        }
        if allocation_type & (MEM_COMMIT | MEM_RESERVE) == 0 {
            return NtStatus::INVALID_PARAMETER;
        }

        let reserve_allocation = allocation_type & MEM_RESERVE != 0;
        let Some((aligned_base, aligned_len)) = (if reserve_allocation {
            reserve_allocation_region(base, size)
        } else {
            page_aligned_region(base, size)
        }) else {
            return NtStatus::INVALID_PARAMETER;
        };
        let Some(permissions) = page_protect_to_permissions(protect) else {
            return NtStatus::INVALID_PAGE_PROTECTION;
        };

        if allocation_type & MEM_RESERVE == 0 {
            if base == 0 {
                return NtStatus::INVALID_PARAMETER;
            }
            if find_virtual_allocation(&self.process.virtual_allocations, aligned_base, aligned_len)
                .is_none()
            {
                return NtStatus::INVALID_PARAMETER;
            }
            if update_permissions(
                &self.global.page_manager,
                aligned_base,
                aligned_len,
                permissions,
            )
            .is_err()
            {
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

        let Some(length) = NonZeroPageSize::new(aligned_len) else {
            return NtStatus::INVALID_PARAMETER;
        };

        let initial_permissions = if allocation_type & MEM_COMMIT != 0 {
            permissions
        } else {
            MemoryRegionPermissions::empty()
        };

        let allocation = if reserve_allocation && base == 0 {
            create_allocation_granularity_aligned_pages(
                &self.global.page_manager,
                length,
                initial_permissions,
            )
        } else {
            let suggested_address = NonZeroAddress::new(aligned_base);
            let flags = if suggested_address.is_some() {
                CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE
            } else {
                CreatePagesFlags::empty()
            };
            create_pages(
                &self.global.page_manager,
                suggested_address,
                length,
                flags,
                initial_permissions,
                |_| Ok(0),
            )
        };
        let ptr = match allocation {
            Ok(ptr) => ptr,
            Err(status) => return status,
        };
        if base_address.write_at_offset(0, ptr.as_usize()).is_none()
            || region_size.write_at_offset(0, aligned_len).is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }

        insert_virtual_allocation(
            &self.process.virtual_allocations,
            WindowsVirtualAllocation {
                base: ptr.as_usize(),
                size: aligned_len,
                allocation_protect: protect,
            },
        );

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

impl<FS: NtShimFS> Task<FS> {
    pub(crate) fn handle_nt_free_virtual_memory(
        &self,
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

        let Some((aligned_base, aligned_len)) =
            free_region(&self.process.virtual_allocations, base, size, free_type)
        else {
            return NtStatus::INVALID_PARAMETER;
        };

        let ptr =
            <Platform as litebox::platform::RawPointerProvider>::RawMutPointer::<u8>::from_usize(
                aligned_base,
            );
        if free_type == MEM_DECOMMIT {
            if update_permissions(
                &self.global.page_manager,
                aligned_base,
                aligned_len,
                MemoryRegionPermissions::empty(),
            )
            .is_err()
            {
                return NtStatus::UNABLE_TO_FREE_VM;
            }
        } else {
            // SAFETY: This implements the guest's explicit NtFreeVirtualMemory request for a
            // page-aligned range tracked by the LiteBox page manager. The caller is responsible for not
            // using the region after the syscall succeeds.
            if unsafe { self.global.page_manager.remove_pages(ptr, aligned_len) }.is_err() {
                return NtStatus::UNABLE_TO_FREE_VM;
            }
            remove_virtual_allocation(&self.process.virtual_allocations, aligned_base);
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
        &self,
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

        let Some(old_permissions) = self.global.page_manager.get_memory_permissions(
            NonZeroAddress::new(aligned_base).expect("aligned_base is non-zero"),
            NonZeroPageSize::new(PAGE_SIZE).expect("PAGE_SIZE is non-zero and aligned"),
        ) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        let old_protect_value = permissions_to_page_protect(old_permissions);

        if update_permissions(
            &self.global.page_manager,
            aligned_base,
            aligned_len,
            new_permissions,
        )
        .is_err()
        {
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
        &self,
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

        let Ok(memory_information_class) =
            MemoryInformationClass::try_from(memory_information_class)
        else {
            return NtStatus::INVALID_INFO_CLASS;
        };

        match memory_information_class {
            MemoryInformationClass::Image => {
                return self.handle_nt_query_virtual_memory_image_information(
                    process_handle,
                    base_address,
                    memory_information,
                    memory_information_length,
                    return_length,
                );
            }
            MemoryInformationClass::ImageExtension => {
                return handle_nt_query_virtual_memory_image_extension_information(
                    process_handle,
                    base_address,
                    memory_information,
                    memory_information_length,
                    return_length,
                );
            }
            MemoryInformationClass::Basic => {}
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

        let Some(info) = query_memory_basic_information(
            &self.global.page_manager,
            &self.process.virtual_allocations,
            base_address,
        ) else {
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

    fn handle_nt_query_virtual_memory_image_information(
        &self,
        process_handle: ProcessHandle,
        base_address: usize,
        memory_information: GuestMutPointer<u8>,
        memory_information_length: usize,
        return_length: Option<GuestMutPointer<usize>>,
    ) -> NtStatus {
        let required_len = size_of::<MemoryImageInformation>();
        if let Some(return_length) = return_length
            && return_length.write_at_offset(0, required_len).is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        if memory_information_length < required_len {
            return NtStatus::INFO_LENGTH_MISMATCH;
        }

        let Some(mapping) = image_mapping_for_address(
            &self.process.mapping,
            self.process.ntdll_mapping.as_ref(),
            base_address,
        ) else {
            return NtStatus::INVALID_PARAMETER;
        };

        let info = MemoryImageInformation {
            image_base: mapping.base_addr,
            size_of_image: mapping.image_size,
            image_flags: 0,
            _padding: 0,
        };
        let output = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer::<
            MemoryImageInformation,
        >::from_usize(memory_information.as_usize());
        if output.write_at_offset(0, info).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }

        litebox_util_log::debug!(
            process_handle:% = format_args!("{:#x}", process_handle.as_raw()),
            base:% = format_args!("{:#x}", base_address),
            image_base:% = format_args!("{:#x}", mapping.base_addr),
            image_size = mapping.image_size;
            "Handled NtQueryVirtualMemory MemoryImageInformation syscall"
        );

        NtStatus::SUCCESS
    }
}

fn image_mapping_for_address<'a>(
    application_mapping: &'a MappingInfo,
    ntdll_mapping: Option<&'a MappingInfo>,
    address: usize,
) -> Option<&'a MappingInfo> {
    [Some(application_mapping), ntdll_mapping]
        .into_iter()
        .flatten()
        .find(|mapping| {
            mapping.image_size != 0
                && address >= mapping.base_addr
                && address < mapping.base_addr.saturating_add(mapping.image_size)
        })
}

fn handle_nt_query_virtual_memory_image_extension_information(
    process_handle: ProcessHandle,
    base_address: usize,
    memory_information: GuestMutPointer<u8>,
    memory_information_length: usize,
    return_length: Option<GuestMutPointer<usize>>,
) -> NtStatus {
    if let Some(return_length) = return_length
        && return_length
            .write_at_offset(0, MEMORY_IMAGE_EXTENSION_INFORMATION_SIZE)
            .is_none()
    {
        return NtStatus::ACCESS_VIOLATION;
    }
    if memory_information_length < MEMORY_IMAGE_EXTENSION_INFORMATION_SIZE {
        return NtStatus::INFO_LENGTH_MISMATCH;
    }
    let output = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer::<
        [u8; MEMORY_IMAGE_EXTENSION_INFORMATION_SIZE],
    >::from_usize(memory_information.as_usize());
    if output
        .write_at_offset(0, [0; MEMORY_IMAGE_EXTENSION_INFORMATION_SIZE])
        .is_none()
    {
        return NtStatus::ACCESS_VIOLATION;
    }

    litebox_util_log::debug!(
        process_handle:% = format_args!("{:#x}", process_handle.as_raw()),
        base:% = format_args!("{:#x}", base_address),
        required_len = MEMORY_IMAGE_EXTENSION_INFORMATION_SIZE;
        "Handled NtQueryVirtualMemory MemoryImageExtensionInformation syscall"
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

fn reserve_allocation_region(base: usize, size: usize) -> Option<(usize, usize)> {
    let aligned_base = if base == 0 {
        0
    } else {
        base & !(ALLOCATION_GRANULARITY - 1)
    };
    if base != 0 && aligned_base == 0 {
        return None;
    }
    let end = base.checked_add(size)?;
    let aligned_end = end.checked_add(PAGE_SIZE - 1)? & !(PAGE_SIZE - 1);
    let aligned_len = aligned_end.checked_sub(aligned_base)?;
    if aligned_len == 0 {
        return None;
    }
    Some((aligned_base, aligned_len))
}

fn free_region(
    virtual_allocations: &WindowsVirtualAllocations,
    base: usize,
    size: usize,
    free_type: u32,
) -> Option<(usize, usize)> {
    if free_type == MEM_RELEASE {
        if size != 0 {
            return None;
        }
        let allocation = virtual_allocations.lock().get(&base).copied()?;
        return Some((allocation.base, allocation.size));
    }

    let (aligned_base, aligned_len) = page_aligned_region(base, size)?;
    find_virtual_allocation(virtual_allocations, aligned_base, aligned_len)?;
    Some((aligned_base, aligned_len))
}

fn insert_virtual_allocation(
    virtual_allocations: &WindowsVirtualAllocations,
    allocation: WindowsVirtualAllocation,
) {
    virtual_allocations
        .lock()
        .insert(allocation.base, allocation);
}

fn remove_virtual_allocation(virtual_allocations: &WindowsVirtualAllocations, base: usize) {
    virtual_allocations.lock().remove(&base);
}

fn find_virtual_allocation(
    virtual_allocations: &WindowsVirtualAllocations,
    base: usize,
    size: usize,
) -> Option<WindowsVirtualAllocation> {
    let end = base.checked_add(size)?;
    virtual_allocations
        .lock()
        .range(..=base)
        .next_back()
        .map(|(_, allocation)| *allocation)
        .filter(|allocation| {
            allocation
                .base
                .checked_add(allocation.size)
                .is_some_and(|allocation_end| end <= allocation_end)
        })
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

fn create_allocation_granularity_aligned_pages(
    page_manager: &WindowsPageManager,
    length: NonZeroPageSize<PAGE_SIZE>,
    permissions: MemoryRegionPermissions,
) -> Result<GuestMutPointer<u8>, NtStatus> {
    let max_start = <Platform as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX
        .checked_sub(length.as_usize())
        .ok_or(NtStatus::NO_MEMORY)?;
    let min_start = <Platform as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN
        .next_multiple_of(ALLOCATION_GRANULARITY);
    let mut candidate = max_start & !(ALLOCATION_GRANULARITY - 1);
    let mut mappings = page_manager.mappings();
    mappings.sort_by_key(|(range, _)| range.start);

    while candidate >= min_start {
        let Some(candidate_end) = candidate.checked_add(length.as_usize()) else {
            break;
        };
        let overlaps = mappings
            .iter()
            .any(|(range, _)| range.start < candidate_end && candidate < range.end);
        if !overlaps {
            let ptr = create_pages(
                page_manager,
                NonZeroAddress::new(candidate),
                length,
                CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
                permissions,
                |_| Ok(0),
            );
            if ptr.is_ok() {
                return ptr;
            }
        }

        let Some(next_candidate) = candidate.checked_sub(ALLOCATION_GRANULARITY) else {
            break;
        };
        candidate = next_candidate;
    }

    Err(NtStatus::NO_MEMORY)
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
    virtual_allocations: &WindowsVirtualAllocations,
    base_address: usize,
) -> Option<MemoryBasicInformation> {
    let query_base = base_address & !(PAGE_SIZE - 1);
    if query_base >= <Platform as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX {
        return None;
    }

    let mut mappings = page_manager.mappings();
    mappings.sort_by_key(|(range, _)| range.start);

    let allocation = find_virtual_allocation(virtual_allocations, query_base, 1);

    if let Some((range, flags)) = mappings
        .iter()
        .find(|(range, _)| range.contains(&base_address))
    {
        let protect = permissions_to_page_protect(MemoryRegionPermissions::from(*flags));
        let state = if allocation.is_some() && protect == PAGE_NOACCESS {
            MEM_RESERVE
        } else {
            MEM_COMMIT
        };
        let allocation_end =
            allocation.and_then(|allocation| allocation.base.checked_add(allocation.size));
        let result_base =
            allocation.map_or(range.start, |allocation| range.start.max(allocation.base));
        let result_end =
            allocation_end.map_or(range.end, |allocation_end| range.end.min(allocation_end));
        return Some(MemoryBasicInformation {
            base_address: result_base,
            allocation_base: allocation.map_or(range.start, |allocation| allocation.base),
            allocation_protect: allocation
                .map_or(protect, |allocation| allocation.allocation_protect),
            partition_id: 0,
            _padding0: 0,
            region_size: result_end - result_base,
            state,
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
    use litebox::platform::RawPointerProvider;

    extern crate std;

    type MutPtr<T> = <Platform as RawPointerProvider>::RawMutPointer<T>;

    const ALLOC_TEST_BASE: usize = 0x1000_0000;
    const FIXED_TEST_BASE: usize = 0x1100_0000;
    const PROTECT_TEST_BASE: usize = 0x1200_0000;
    const QUERY_TEST_BASE: usize = 0x1300_0000;
    const FREE_TEST_BASE: usize = 0x1400_0000;
    const COMMIT_TEST_BASE: usize = 0x1500_0000;
    const IMAGE_EXTENSION_TEST_BASE: usize = 0x1600_0000;
    const OTHER_PROCESS_HANDLE: ProcessHandle = ProcessHandle::from_raw(0x1234);

    fn mut_ptr<T: FromBytes + IntoBytes>(value: &mut T) -> MutPtr<T> {
        MutPtr::from_usize(core::ptr::from_mut(value).cast::<u8>() as usize)
    }

    fn mut_byte_ptr<T>(value: &mut T) -> MutPtr<u8> {
        MutPtr::from_usize(core::ptr::from_mut(value).cast::<u8>() as usize)
    }

    fn class_value(class: MemoryInformationClass) -> u32 {
        class as u32
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

    fn release_mapping<FS: NtShimFS>(task: &Task<FS>, base: usize) {
        let mut base = base;
        let mut size = 0usize;
        assert_eq!(
            task.handle_nt_free_virtual_memory(
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
    fn memory_image_information_matches_windows_x64_layout() {
        assert_eq!(size_of::<MemoryImageInformation>(), 24);
        assert_eq!(align_of::<MemoryImageInformation>(), 8);
    }

    #[test]
    fn memory_extended_parameter_matches_windows_x64_layout() {
        assert_eq!(size_of::<MemoryExtendedParameter>(), 16);
        assert_eq!(align_of::<MemoryExtendedParameter>(), 8);
        assert_eq!(size_of::<MemoryAddressRequirements>(), 24);
        assert_eq!(align_of::<MemoryAddressRequirements>(), 8);
    }

    #[test]
    fn nt_query_virtual_memory_image_extension_information_returns_zeroed_info() {
        let task = crate::tests::test_task();
        let mut output_base = IMAGE_EXTENSION_TEST_BASE;
        let mut output_size = PAGE_SIZE;
        assert_eq!(
            task.handle_nt_allocate_virtual_memory(
                ProcessHandle::CURRENT,
                mut_ptr(&mut output_base),
                0,
                mut_ptr(&mut output_size),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            ),
            NtStatus::SUCCESS
        );

        let output = MutPtr::<u8>::from_usize(output_base);
        output
            .write_slice_at_offset(0, &[0xff; MEMORY_IMAGE_EXTENSION_INFORMATION_SIZE])
            .unwrap();
        let mut return_length = 0usize;

        assert_eq!(
            task.handle_nt_query_virtual_memory(
                ProcessHandle::CURRENT,
                QUERY_TEST_BASE,
                class_value(MemoryInformationClass::ImageExtension),
                output,
                MEMORY_IMAGE_EXTENSION_INFORMATION_SIZE,
                Some(mut_ptr(&mut return_length)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(return_length, MEMORY_IMAGE_EXTENSION_INFORMATION_SIZE);
        let information = core::array::from_fn(|index| {
            output
                .read_at_offset(index.try_into().unwrap())
                .expect("test output byte is readable")
        });
        assert_eq!(information, [0; MEMORY_IMAGE_EXTENSION_INFORMATION_SIZE]);

        release_mapping(&task, output_base);
    }

    #[test]
    fn nt_query_virtual_memory_image_extension_information_rejects_short_buffer() {
        let task = crate::tests::test_task();
        let mut information = [0xff; MEMORY_IMAGE_EXTENSION_INFORMATION_SIZE - 1];
        let mut return_length = 0usize;
        let information_len = information.len();

        assert_eq!(
            task.handle_nt_query_virtual_memory(
                ProcessHandle::CURRENT,
                QUERY_TEST_BASE,
                class_value(MemoryInformationClass::ImageExtension),
                mut_byte_ptr(&mut information),
                information_len,
                Some(mut_ptr(&mut return_length)),
            ),
            NtStatus::INFO_LENGTH_MISMATCH
        );
        assert_eq!(return_length, MEMORY_IMAGE_EXTENSION_INFORMATION_SIZE);
        assert_eq!(
            information,
            [0xff; MEMORY_IMAGE_EXTENSION_INFORMATION_SIZE - 1]
        );
    }

    #[test]
    fn nt_query_virtual_memory_image_information_rejects_unknown_image_address() {
        let task = crate::tests::test_task();
        let mut information = MemoryImageInformation {
            image_base: usize::MAX,
            size_of_image: usize::MAX,
            image_flags: u32::MAX,
            _padding: u32::MAX,
        };
        let mut return_length = 0usize;

        assert_eq!(
            task.handle_nt_query_virtual_memory(
                ProcessHandle::CURRENT,
                QUERY_TEST_BASE,
                class_value(MemoryInformationClass::Image),
                mut_byte_ptr(&mut information),
                size_of::<MemoryImageInformation>(),
                Some(mut_ptr(&mut return_length)),
            ),
            NtStatus::INVALID_PARAMETER
        );
        assert_eq!(return_length, size_of::<MemoryImageInformation>());
        assert_eq!(information.image_base, usize::MAX);
    }

    #[test]
    fn nt_allocate_virtual_memory_allocates_writable_pages() {
        let task = crate::tests::test_task();
        let mut base = ALLOC_TEST_BASE;
        let mut size = PAGE_SIZE + 1;

        assert_eq!(
            task.handle_nt_allocate_virtual_memory(
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
            task.global.page_manager.get_memory_permissions(
                NonZeroAddress::new(base).unwrap(),
                NonZeroPageSize::new(size).unwrap(),
            ),
            Some(MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE)
        );

        release_mapping(&task, base);
    }

    #[test]
    fn nt_allocate_virtual_memory_null_reservation_is_allocation_granularity_aligned() {
        let task = crate::tests::test_task();
        let mut base = 0usize;
        let mut size = PAGE_SIZE;

        assert_eq!(
            task.handle_nt_allocate_virtual_memory(
                ProcessHandle::CURRENT,
                mut_ptr(&mut base),
                0,
                mut_ptr(&mut size),
                MEM_RESERVE,
                PAGE_READWRITE,
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(base % ALLOCATION_GRANULARITY, 0);
        assert_eq!(size, PAGE_SIZE);

        release_mapping(&task, base);
    }

    #[test]
    fn nt_allocate_virtual_memory_reservation_rounds_fixed_base_to_allocation_granularity() {
        let task = crate::tests::test_task();
        let mut base = FIXED_TEST_BASE + 0x1234;
        let mut size = 1usize;

        assert_eq!(
            task.handle_nt_allocate_virtual_memory(
                ProcessHandle::CURRENT,
                mut_ptr(&mut base),
                0,
                mut_ptr(&mut size),
                MEM_RESERVE,
                PAGE_READWRITE,
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(base, FIXED_TEST_BASE);
        assert_eq!(size, 0x2000);

        release_mapping(&task, base);
    }

    #[test]
    fn nt_allocate_virtual_memory_ex_allocates_writable_pages() {
        let task = crate::tests::test_task();
        let mut base = ALLOC_TEST_BASE + 0x10_0000;
        let mut size = PAGE_SIZE + 1;

        assert_eq!(
            task.handle_nt_allocate_virtual_memory_ex(
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

        release_mapping(&task, base);
    }

    #[test]
    fn nt_allocate_virtual_memory_ex_accepts_supported_extended_parameter_hints() {
        let task = crate::tests::test_task();
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
            task.handle_nt_allocate_virtual_memory_ex(
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

        release_mapping(&task, base);
    }

    #[test]
    fn nt_allocate_virtual_memory_ex_rejects_unsupported_address_requirements() {
        let task = crate::tests::test_task();
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
            task.handle_nt_allocate_virtual_memory_ex(
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
        let task = crate::tests::test_task();
        let mut base = COMMIT_TEST_BASE;
        let mut size = PAGE_SIZE;

        assert_eq!(
            task.handle_nt_allocate_virtual_memory(
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
            task.handle_nt_allocate_virtual_memory(
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

        let info = query_memory_basic_information(
            &task.global.page_manager,
            &task.process.virtual_allocations,
            COMMIT_TEST_BASE,
        )
        .unwrap();
        assert_eq!(info.protect, PAGE_READWRITE);

        release_mapping(&task, base);
    }

    #[test]
    fn nt_allocate_virtual_memory_fixed_address_does_not_replace_existing_mapping() {
        let task = crate::tests::test_task();
        let mut base = FIXED_TEST_BASE;
        let mut size = PAGE_SIZE;
        assert_eq!(
            task.handle_nt_allocate_virtual_memory(
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
            task.handle_nt_allocate_virtual_memory(
                ProcessHandle::CURRENT,
                mut_ptr(&mut overlapping_base),
                0,
                mut_ptr(&mut overlapping_size),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            ),
            NtStatus::NO_MEMORY
        );

        release_mapping(&task, base);
    }

    #[test]
    fn nt_protect_virtual_memory_updates_permissions_and_old_protect() {
        let task = crate::tests::test_task();
        let mut base = PROTECT_TEST_BASE;
        let mut size = PAGE_SIZE * 2;
        assert_eq!(
            task.handle_nt_allocate_virtual_memory(
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
            task.handle_nt_protect_virtual_memory(
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
            task.global.page_manager.get_memory_permissions(
                NonZeroAddress::new(base).unwrap(),
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
            ),
            Some(MemoryRegionPermissions::READ)
        );

        old_protect = 0;
        assert_eq!(
            task.handle_nt_protect_virtual_memory(
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
            task.global.page_manager.get_memory_permissions(
                NonZeroAddress::new(base).unwrap(),
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
            ),
            Some(MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC)
        );

        release_mapping(&task, base);
    }

    #[test]
    fn nt_query_virtual_memory_keeps_allocation_protect_after_protect() {
        let task = crate::tests::test_task();
        let mut base = PROTECT_TEST_BASE + 0x10_0000;
        let mut size = PAGE_SIZE;
        assert_eq!(
            task.handle_nt_allocate_virtual_memory(
                ProcessHandle::CURRENT,
                mut_ptr(&mut base),
                0,
                mut_ptr(&mut size),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            ),
            NtStatus::SUCCESS
        );

        let mut protect_base = base;
        let mut protect_size = PAGE_SIZE;
        let mut old_protect = 0u32;
        assert_eq!(
            task.handle_nt_protect_virtual_memory(
                ProcessHandle::CURRENT,
                mut_ptr(&mut protect_base),
                mut_ptr(&mut protect_size),
                PAGE_READONLY,
                mut_ptr(&mut old_protect),
            ),
            NtStatus::SUCCESS
        );

        let mut info = empty_memory_basic_information();
        assert_eq!(
            task.handle_nt_query_virtual_memory(
                ProcessHandle::CURRENT,
                base,
                class_value(MemoryInformationClass::Basic),
                mut_byte_ptr(&mut info),
                size_of::<MemoryBasicInformation>(),
                None,
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(info.allocation_base, base);
        assert_eq!(info.allocation_protect, PAGE_READWRITE);
        assert_eq!(info.protect, PAGE_READONLY);

        release_mapping(&task, base);
    }

    #[test]
    fn nt_query_virtual_memory_reports_committed_and_free_regions() {
        let task = crate::tests::test_task();
        let mut base = QUERY_TEST_BASE;
        let mut size = PAGE_SIZE * 2;
        assert_eq!(
            task.handle_nt_allocate_virtual_memory(
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
            task.handle_nt_query_virtual_memory(
                ProcessHandle::CURRENT,
                base + 0x10,
                class_value(MemoryInformationClass::Basic),
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

        release_mapping(&task, base);

        let mut free_info = empty_memory_basic_information();
        assert_eq!(
            task.handle_nt_query_virtual_memory(
                ProcessHandle::CURRENT,
                base,
                class_value(MemoryInformationClass::Basic),
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
        let task = crate::tests::test_task();
        let mut base = FREE_TEST_BASE;
        let mut size = PAGE_SIZE;
        assert_eq!(
            task.handle_nt_allocate_virtual_memory(
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
            task.handle_nt_free_virtual_memory(
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
            task.global.page_manager.get_memory_permissions(
                NonZeroAddress::new(base).unwrap(),
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
            ),
            Some(MemoryRegionPermissions::empty())
        );

        let mut reserve_base = base;
        let mut reserve_size = PAGE_SIZE;
        assert_ne!(
            task.handle_nt_allocate_virtual_memory(
                ProcessHandle::CURRENT,
                mut_ptr(&mut reserve_base),
                0,
                mut_ptr(&mut reserve_size),
                MEM_RESERVE,
                PAGE_READWRITE,
            ),
            NtStatus::SUCCESS
        );
    }

    #[test]
    fn nt_free_virtual_memory_release_requires_allocation_base() {
        let task = crate::tests::test_task();
        let mut base = FREE_TEST_BASE + 0x10_0000;
        let mut size = PAGE_SIZE * 2;
        assert_eq!(
            task.handle_nt_allocate_virtual_memory(
                ProcessHandle::CURRENT,
                mut_ptr(&mut base),
                0,
                mut_ptr(&mut size),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            ),
            NtStatus::SUCCESS
        );

        let mut free_base = base + PAGE_SIZE;
        let mut free_size = 0usize;
        assert_eq!(
            task.handle_nt_free_virtual_memory(
                ProcessHandle::CURRENT,
                mut_ptr(&mut free_base),
                mut_ptr(&mut free_size),
                MEM_RELEASE,
            ),
            NtStatus::INVALID_PARAMETER
        );

        release_mapping(&task, base);
    }

    #[test]
    fn nt_free_virtual_memory_release_preserves_adjacent_allocation() {
        let task = crate::tests::test_task();
        let mut first_base = FREE_TEST_BASE + 0x20_0000;
        let mut first_size = ALLOCATION_GRANULARITY;
        assert_eq!(
            task.handle_nt_allocate_virtual_memory(
                ProcessHandle::CURRENT,
                mut_ptr(&mut first_base),
                0,
                mut_ptr(&mut first_size),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            ),
            NtStatus::SUCCESS
        );

        let mut second_base = first_base + ALLOCATION_GRANULARITY;
        let mut second_size = PAGE_SIZE;
        assert_eq!(
            task.handle_nt_allocate_virtual_memory(
                ProcessHandle::CURRENT,
                mut_ptr(&mut second_base),
                0,
                mut_ptr(&mut second_size),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            ),
            NtStatus::SUCCESS
        );

        let mut second_info = empty_memory_basic_information();
        assert_eq!(
            task.handle_nt_query_virtual_memory(
                ProcessHandle::CURRENT,
                second_base,
                class_value(MemoryInformationClass::Basic),
                mut_byte_ptr(&mut second_info),
                size_of::<MemoryBasicInformation>(),
                None,
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(second_info.base_address, second_base);
        assert_eq!(second_info.allocation_base, second_base);
        assert_eq!(second_info.region_size, PAGE_SIZE);

        release_mapping(&task, second_base);
        assert_eq!(
            task.global.page_manager.get_memory_permissions(
                NonZeroAddress::new(first_base).unwrap(),
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
            ),
            Some(MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE)
        );
        assert_eq!(
            task.global.page_manager.get_memory_permissions(
                NonZeroAddress::new(second_base).unwrap(),
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
            ),
            None
        );

        release_mapping(&task, first_base);
    }

    #[test]
    fn memory_syscalls_reject_invalid_arguments() {
        let task = crate::tests::test_task();
        let mut base = 0usize;
        let mut size = PAGE_SIZE;
        let mut old_protect = 0u32;
        let mut info = empty_memory_basic_information();

        assert_eq!(
            task.handle_nt_allocate_virtual_memory(
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
            task.handle_nt_allocate_virtual_memory(
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
            task.handle_nt_protect_virtual_memory(
                ProcessHandle::CURRENT,
                mut_ptr(&mut base),
                mut_ptr(&mut size),
                PAGE_READONLY,
                mut_ptr(&mut old_protect),
            ),
            NtStatus::INVALID_PARAMETER
        );
        assert_eq!(
            task.handle_nt_query_virtual_memory(
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
        let task = crate::tests::test_task();
        let mut base = ALLOC_TEST_BASE;
        let mut size = PAGE_SIZE;
        let mut old_protect = 0u32;
        let mut info = empty_memory_basic_information();

        assert_eq!(
            task.handle_nt_allocate_virtual_memory(
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
            task.handle_nt_allocate_virtual_memory_ex(
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
            task.handle_nt_free_virtual_memory(
                OTHER_PROCESS_HANDLE,
                mut_ptr(&mut base),
                mut_ptr(&mut size),
                MEM_DECOMMIT,
            ),
            NtStatus::INVALID_HANDLE
        );
        assert_eq!(
            task.handle_nt_protect_virtual_memory(
                OTHER_PROCESS_HANDLE,
                mut_ptr(&mut base),
                mut_ptr(&mut size),
                PAGE_READONLY,
                mut_ptr(&mut old_protect),
            ),
            NtStatus::INVALID_HANDLE
        );
        assert_eq!(
            task.handle_nt_query_virtual_memory(
                OTHER_PROCESS_HANDLE,
                base,
                class_value(MemoryInformationClass::Basic),
                mut_byte_ptr(&mut info),
                size_of::<MemoryBasicInformation>(),
                None,
            ),
            NtStatus::INVALID_HANDLE
        );
    }
}
