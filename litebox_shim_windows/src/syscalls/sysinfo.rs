// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::mem::size_of;

use int_enum::IntEnum;
use litebox::platform::Instant as _;
use litebox::platform::{
    PageManagementProvider, RawConstPointer as _, RawMutPointer as _, TimeProvider as _,
};
use litebox_common_windows::nt_status::NtStatus;
use litebox_platform_multiplex::Platform;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::{PAGE_SIZE, loader::nt_types::GroupAffinity};

const QPC_FREQUENCY_HZ: i64 = 1_000_000_000;
const SYSTEM_FEATURE_CONFIGURATION_SECTION_TYPE_COUNT: usize = 4;
const MAXIMUM_NODE_COUNT: usize = 0x40;
const RELATION_PROCESSOR_CORE: u32 = 0;
const RELATION_NUMA_NODE: u32 = 1;
const RELATION_PROCESSOR_PACKAGE: u32 = 3;
const RELATION_GROUP: u32 = 4;
const RELATION_ALL: u32 = 0xffff;
const TIMER_RESOLUTION_100NS: u32 = 156_250;
const ALLOCATION_GRANULARITY: u32 = 0x1_0000;
const DEFAULT_PHYSICAL_PAGES: u32 = 1024 * 1024;
const NUMBER_OF_PROCESSORS: u8 = 1;
const SUPPORTED_FLUSH_METHODS: u32 = 0x7;
const SUPPORTED_FLUSH_PROCESSOR_FEATURES: u32 = 0x40;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, IntEnum)]
enum SystemInformationClass {
    Basic = 0,
    Verifier = 50,
    NumaProcessorMap = 55,
    EmulationBasic = 62,
    LogicalProcessorAndGroup = 107,
    Flush = 192,
    HypervisorSharedPage = 197,
    FeatureConfigurationSection = 211,
    ProcessorFeaturesBitMap = 250,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct SystemBasicInformation {
    reserved: u32,
    timer_resolution: u32,
    page_size: u32,
    number_of_physical_pages: u32,
    lowest_physical_page_number: u32,
    highest_physical_page_number: u32,
    allocation_granularity: u32,
    _padding0: u32,
    minimum_user_mode_address: usize,
    maximum_user_mode_address: usize,
    active_processors_affinity_mask: usize,
    number_of_processors: u8,
    _padding1: [u8; 7],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct SystemNumaInformation {
    highest_node_number: u32,
    reserved: u32,
    active_processors_group_affinity: [GroupAffinity; MAXIMUM_NODE_COUNT],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct SystemFlushInformation {
    supported_flush_methods: u32,
    processor_features: u32,
    reserved: [u32; 6],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct SystemHypervisorSharedPageInformation {
    hypervisor_shared_user_va: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct SystemProcessorFeaturesBitMapInformation {
    feature_bits: [u64; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct SystemVerifierInformation {
    flags: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct ProcessorRelationship {
    flags: u8,
    efficiency_class: u8,
    reserved: [u8; 20],
    group_count: u16,
    group_mask: [GroupAffinity; 1],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct NumaNodeRelationship {
    node_number: u32,
    reserved: [u8; 18],
    group_count: u16,
    group_masks: [GroupAffinity; 1],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct ProcessorGroupInfo {
    maximum_processor_count: u8,
    active_processor_count: u8,
    reserved: [u8; 38],
    active_processor_mask: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct GroupRelationship {
    maximum_group_count: u16,
    active_group_count: u16,
    reserved: [u8; 20],
    group_info: [ProcessorGroupInfo; 1],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct SystemLogicalProcessorInformationExProcessor {
    relationship: u32,
    size: u32,
    processor: ProcessorRelationship,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct SystemLogicalProcessorInformationExNumaNode {
    relationship: u32,
    size: u32,
    numa_node: NumaNodeRelationship,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct SystemLogicalProcessorInformationExGroup {
    relationship: u32,
    size: u32,
    group: GroupRelationship,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct SystemFeatureConfigurationSectionsRequest {
    previous_change_stamps: [u64; SYSTEM_FEATURE_CONFIGURATION_SECTION_TYPE_COUNT],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct SystemFeatureConfigurationSectionsInformationEntry {
    change_stamp: u64,
    section_handle: usize,
    size: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct SystemFeatureConfigurationSectionsInformation {
    overall_change_stamp: u64,
    descriptors: [SystemFeatureConfigurationSectionsInformationEntry;
        SYSTEM_FEATURE_CONFIGURATION_SECTION_TYPE_COUNT],
}

pub(crate) fn handle_nt_query_performance_counter(
    performance_counter: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<i64>,
    performance_frequency: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<i64>,
    qpc_boot_instant: <Platform as litebox::platform::TimeProvider>::Instant,
) -> NtStatus {
    let elapsed = litebox_platform_multiplex::platform()
        .now()
        .duration_since(&qpc_boot_instant);
    let ticks =
        i64::try_from(core::cmp::min(elapsed.as_nanos(), i64::MAX as u128)).unwrap_or(i64::MAX);

    if performance_counter.write_at_offset(0, ticks).is_none() {
        return NtStatus::ACCESS_VIOLATION;
    }
    if performance_frequency.as_usize() != 0
        && performance_frequency
            .write_at_offset(0, QPC_FREQUENCY_HZ)
            .is_none()
    {
        return NtStatus::ACCESS_VIOLATION;
    }

    NtStatus::SUCCESS
}

pub(crate) fn handle_nt_query_system_information(
    system_information_class: u32,
    system_information: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u8>,
    system_information_length: u32,
    return_length: Option<<Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u32>>,
) -> NtStatus {
    let Ok(system_information_class) = SystemInformationClass::try_from(system_information_class)
    else {
        litebox_util_log::debug!(
            system_information_class = system_information_class;
            "Unsupported NtQuerySystemInformation class"
        );
        return NtStatus::INVALID_INFO_CLASS;
    };

    let status = match system_information_class {
        SystemInformationClass::Basic | SystemInformationClass::EmulationBasic => {
            write_system_information(
                system_information,
                system_information_length,
                return_length,
                &system_basic_information(),
            )
        }
        SystemInformationClass::NumaProcessorMap => write_system_information(
            system_information,
            system_information_length,
            return_length,
            &system_numa_information(),
        ),
        SystemInformationClass::Flush => write_system_information(
            system_information,
            system_information_length,
            return_length,
            &system_flush_information(),
        ),
        SystemInformationClass::HypervisorSharedPage => write_system_information(
            system_information,
            system_information_length,
            return_length,
            &system_hypervisor_shared_page_information(),
        ),
        SystemInformationClass::ProcessorFeaturesBitMap => write_system_information(
            system_information,
            system_information_length,
            return_length,
            &system_processor_features_bitmap_information(),
        ),
        SystemInformationClass::Verifier => write_system_information(
            system_information,
            system_information_length,
            return_length,
            &SystemVerifierInformation { flags: 0 },
        ),
        _ => {
            litebox_util_log::debug!(
                system_information_class:? = system_information_class;
                "Unsupported NtQuerySystemInformation class"
            );
            NtStatus::INVALID_INFO_CLASS
        }
    };

    if status == NtStatus::SUCCESS {
        litebox_util_log::debug!(
            system_information_class:? = system_information_class,
            system_information_length = system_information_length;
            "Handled NtQuerySystemInformation syscall"
        );
    }

    status
}

pub(crate) fn handle_nt_query_system_information_ex(
    system_information_class: u32,
    input_buffer: Option<<Platform as litebox::platform::RawPointerProvider>::RawConstPointer<u8>>,
    input_buffer_length: u32,
    system_information: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u8>,
    system_information_length: u32,
    return_length: Option<<Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u32>>,
) -> NtStatus {
    let Ok(system_information_class) = SystemInformationClass::try_from(system_information_class)
    else {
        litebox_util_log::debug!(
            system_information_class = system_information_class;
            "Unsupported NtQuerySystemInformationEx class"
        );
        return NtStatus::INVALID_INFO_CLASS;
    };

    let status = match system_information_class {
        SystemInformationClass::LogicalProcessorAndGroup => {
            write_system_logical_processor_and_group_information(
                input_buffer,
                input_buffer_length,
                system_information,
                system_information_length,
                return_length,
            )
        }
        SystemInformationClass::FeatureConfigurationSection => {
            write_system_feature_configuration_sections_information(
                input_buffer,
                input_buffer_length,
                system_information,
                system_information_length,
                return_length,
            )
        }
        _ => {
            litebox_util_log::debug!(
                system_information_class:? = system_information_class;
                "Unsupported NtQuerySystemInformationEx class"
            );
            NtStatus::INVALID_INFO_CLASS
        }
    };

    if status == NtStatus::SUCCESS {
        litebox_util_log::debug!(
            system_information_class:? = system_information_class,
            input_buffer_length = input_buffer_length,
            system_information_length = system_information_length;
            "Handled NtQuerySystemInformationEx syscall"
        );
    }

    status
}

fn write_system_information<T: Immutable + IntoBytes>(
    system_information: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u8>,
    system_information_length: u32,
    return_length: Option<<Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u32>>,
    information: &T,
) -> NtStatus {
    let required_len =
        u32::try_from(size_of::<T>()).expect("system information length fits in ULONG");
    if let Some(return_length) = return_length
        && return_length.write_at_offset(0, required_len).is_none()
    {
        return NtStatus::ACCESS_VIOLATION;
    }
    if system_information_length < required_len {
        return NtStatus::INFO_LENGTH_MISMATCH;
    }

    if system_information
        .write_slice_at_offset(0, information.as_bytes())
        .is_none()
    {
        return NtStatus::ACCESS_VIOLATION;
    }

    NtStatus::SUCCESS
}

fn write_system_information_records(
    system_information: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u8>,
    system_information_length: u32,
    return_length: Option<<Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u32>>,
    records: &[&[u8]],
) -> NtStatus {
    let required_len = records
        .iter()
        .try_fold(0u32, |total, record| {
            let record_len = u32::try_from(record.len()).ok()?;
            total.checked_add(record_len)
        })
        .expect("system information length fits in ULONG");
    if let Some(return_length) = return_length
        && return_length.write_at_offset(0, required_len).is_none()
    {
        return NtStatus::ACCESS_VIOLATION;
    }
    if system_information_length < required_len {
        return NtStatus::INFO_LENGTH_MISMATCH;
    }

    let mut offset = 0isize;
    for record in records {
        if system_information
            .write_slice_at_offset(offset, record)
            .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        offset += isize::try_from(record.len()).expect("record length fits in isize");
    }

    NtStatus::SUCCESS
}

fn write_system_logical_processor_and_group_information(
    input_buffer: Option<<Platform as litebox::platform::RawPointerProvider>::RawConstPointer<u8>>,
    input_buffer_length: u32,
    system_information: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u8>,
    system_information_length: u32,
    return_length: Option<<Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u32>>,
) -> NtStatus {
    let Some(input_buffer) = input_buffer else {
        return NtStatus::INVALID_PARAMETER;
    };
    if input_buffer_length < u32::try_from(size_of::<u32>()).expect("ULONG length fits in ULONG") {
        return NtStatus::INVALID_PARAMETER;
    }

    let input_buffer =
        <Platform as litebox::platform::RawPointerProvider>::RawConstPointer::<u32>::from_usize(
            input_buffer.as_usize(),
        );
    let Some(relationship) = input_buffer.read_at_offset(0) else {
        return NtStatus::ACCESS_VIOLATION;
    };

    match relationship {
        RELATION_PROCESSOR_CORE | RELATION_PROCESSOR_PACKAGE => {
            let processor = logical_processor_information_ex_processor(relationship);
            write_system_information_records(
                system_information,
                system_information_length,
                return_length,
                &[processor.as_bytes()],
            )
        }
        RELATION_NUMA_NODE => {
            let numa_node = logical_processor_information_ex_numa_node();
            write_system_information_records(
                system_information,
                system_information_length,
                return_length,
                &[numa_node.as_bytes()],
            )
        }
        RELATION_GROUP => {
            let group = logical_processor_information_ex_group();
            write_system_information_records(
                system_information,
                system_information_length,
                return_length,
                &[group.as_bytes()],
            )
        }
        RELATION_ALL => {
            let processor = logical_processor_information_ex_processor(RELATION_PROCESSOR_CORE);
            let numa_node = logical_processor_information_ex_numa_node();
            let group = logical_processor_information_ex_group();
            write_system_information_records(
                system_information,
                system_information_length,
                return_length,
                &[processor.as_bytes(), numa_node.as_bytes(), group.as_bytes()],
            )
        }
        _ => NtStatus::INVALID_PARAMETER,
    }
}

fn write_system_feature_configuration_sections_information(
    input_buffer: Option<<Platform as litebox::platform::RawPointerProvider>::RawConstPointer<u8>>,
    input_buffer_length: u32,
    system_information: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u8>,
    system_information_length: u32,
    return_length: Option<<Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u32>>,
) -> NtStatus {
    let Some(input_buffer) = input_buffer else {
        return NtStatus::INVALID_PARAMETER;
    };
    if input_buffer_length
        < u32::try_from(size_of::<SystemFeatureConfigurationSectionsRequest>())
            .expect("feature configuration sections request length fits in ULONG")
    {
        return NtStatus::INVALID_PARAMETER;
    }

    let input_buffer = <Platform as litebox::platform::RawPointerProvider>::RawConstPointer::<
        SystemFeatureConfigurationSectionsRequest,
    >::from_usize(input_buffer.as_usize());
    let Some(_request) = input_buffer.read_at_offset(0) else {
        return NtStatus::ACCESS_VIOLATION;
    };

    write_system_information(
        system_information,
        system_information_length,
        return_length,
        &system_feature_configuration_sections_information(),
    )
}

fn system_basic_information() -> SystemBasicInformation {
    let maximum_user_mode_address =
        <Platform as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX.saturating_sub(1);
    SystemBasicInformation {
        reserved: 0,
        timer_resolution: TIMER_RESOLUTION_100NS,
        page_size: u32::try_from(PAGE_SIZE).expect("PAGE_SIZE fits in ULONG"),
        number_of_physical_pages: DEFAULT_PHYSICAL_PAGES,
        lowest_physical_page_number: 0,
        highest_physical_page_number: DEFAULT_PHYSICAL_PAGES.saturating_sub(1),
        allocation_granularity: ALLOCATION_GRANULARITY,
        _padding0: 0,
        minimum_user_mode_address: <Platform as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN,
        maximum_user_mode_address,
        active_processors_affinity_mask: usize::from(NUMBER_OF_PROCESSORS),
        number_of_processors: NUMBER_OF_PROCESSORS,
        _padding1: [0; 7],
    }
}

fn system_numa_information() -> SystemNumaInformation {
    let mut active_processors_group_affinity = [GroupAffinity {
        mask: 0,
        group: 0,
        reserved: [0; 3],
    }; MAXIMUM_NODE_COUNT];
    active_processors_group_affinity[0].mask = usize::from(NUMBER_OF_PROCESSORS);

    SystemNumaInformation {
        highest_node_number: 0,
        reserved: 0,
        active_processors_group_affinity,
    }
}

fn system_flush_information() -> SystemFlushInformation {
    SystemFlushInformation {
        supported_flush_methods: SUPPORTED_FLUSH_METHODS,
        processor_features: SUPPORTED_FLUSH_PROCESSOR_FEATURES,
        reserved: [0; 6],
    }
}

fn system_hypervisor_shared_page_information() -> SystemHypervisorSharedPageInformation {
    SystemHypervisorSharedPageInformation {
        hypervisor_shared_user_va: 0,
    }
}

fn system_processor_features_bitmap_information() -> SystemProcessorFeaturesBitMapInformation {
    SystemProcessorFeaturesBitMapInformation {
        feature_bits: [0; 2],
    }
}

fn active_processors_group_affinity() -> GroupAffinity {
    GroupAffinity {
        mask: usize::from(NUMBER_OF_PROCESSORS),
        group: 0,
        reserved: [0; 3],
    }
}

fn logical_processor_information_ex_processor(
    relationship: u32,
) -> SystemLogicalProcessorInformationExProcessor {
    SystemLogicalProcessorInformationExProcessor {
        relationship,
        size: u32::try_from(size_of::<SystemLogicalProcessorInformationExProcessor>())
            .expect("logical processor information length fits in ULONG"),
        processor: ProcessorRelationship {
            flags: 0,
            efficiency_class: 0,
            reserved: [0; 20],
            group_count: 1,
            group_mask: [active_processors_group_affinity()],
        },
    }
}

fn logical_processor_information_ex_numa_node() -> SystemLogicalProcessorInformationExNumaNode {
    SystemLogicalProcessorInformationExNumaNode {
        relationship: RELATION_NUMA_NODE,
        size: u32::try_from(size_of::<SystemLogicalProcessorInformationExNumaNode>())
            .expect("logical processor information length fits in ULONG"),
        numa_node: NumaNodeRelationship {
            node_number: 0,
            reserved: [0; 18],
            group_count: 1,
            group_masks: [active_processors_group_affinity()],
        },
    }
}

fn logical_processor_information_ex_group() -> SystemLogicalProcessorInformationExGroup {
    SystemLogicalProcessorInformationExGroup {
        relationship: RELATION_GROUP,
        size: u32::try_from(size_of::<SystemLogicalProcessorInformationExGroup>())
            .expect("logical processor information length fits in ULONG"),
        group: GroupRelationship {
            maximum_group_count: 1,
            active_group_count: 1,
            reserved: [0; 20],
            group_info: [ProcessorGroupInfo {
                maximum_processor_count: NUMBER_OF_PROCESSORS,
                active_processor_count: NUMBER_OF_PROCESSORS,
                reserved: [0; 38],
                active_processor_mask: usize::from(NUMBER_OF_PROCESSORS),
            }],
        },
    }
}

fn system_feature_configuration_sections_information()
-> SystemFeatureConfigurationSectionsInformation {
    SystemFeatureConfigurationSectionsInformation {
        overall_change_stamp: 0,
        descriptors: [SystemFeatureConfigurationSectionsInformationEntry {
            change_stamp: 0,
            section_handle: 0,
            size: 0,
        }; SYSTEM_FEATURE_CONFIGURATION_SECTION_TYPE_COUNT],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox::platform::RawPointerProvider;

    extern crate std;

    type ConstPtr<T> = <Platform as RawPointerProvider>::RawConstPointer<T>;
    type MutPtr<T> = <Platform as RawPointerProvider>::RawMutPointer<T>;

    fn init_platform() {
        crate::tests::init_platform();
    }

    fn mut_ptr<T: FromBytes + IntoBytes>(value: &mut T) -> MutPtr<T> {
        MutPtr::from_usize(core::ptr::from_mut(value).cast::<u8>() as usize)
    }

    fn mut_byte_ptr<T>(value: &mut T) -> MutPtr<u8> {
        MutPtr::from_usize(core::ptr::from_mut(value).cast::<u8>() as usize)
    }

    fn const_byte_ptr<T>(value: &T) -> ConstPtr<u8> {
        ConstPtr::from_usize(core::ptr::from_ref(value).cast::<u8>() as usize)
    }

    fn class_value(class: SystemInformationClass) -> u32 {
        class as u32
    }

    #[test]
    fn system_information_class_matches_windows_values() {
        assert_eq!(class_value(SystemInformationClass::Basic), 0);
        assert_eq!(class_value(SystemInformationClass::NumaProcessorMap), 55);
        assert_eq!(class_value(SystemInformationClass::EmulationBasic), 62);
        assert_eq!(
            class_value(SystemInformationClass::LogicalProcessorAndGroup),
            107
        );
        assert_eq!(class_value(SystemInformationClass::Flush), 192);
        assert_eq!(
            class_value(SystemInformationClass::HypervisorSharedPage),
            197
        );
        assert_eq!(
            class_value(SystemInformationClass::FeatureConfigurationSection),
            211
        );
        assert_eq!(
            class_value(SystemInformationClass::ProcessorFeaturesBitMap),
            250
        );
    }

    #[test]
    fn system_basic_information_matches_windows_x64_layout() {
        assert_eq!(size_of::<SystemBasicInformation>(), 64);
        assert_eq!(align_of::<SystemBasicInformation>(), 8);
    }

    #[test]
    fn system_flush_information_matches_windows_x64_layout() {
        assert_eq!(size_of::<SystemFlushInformation>(), 32);
        assert_eq!(align_of::<SystemFlushInformation>(), 4);
    }

    #[test]
    fn system_numa_information_matches_windows_x64_layout() {
        assert_eq!(size_of::<GroupAffinity>(), 16);
        assert_eq!(align_of::<GroupAffinity>(), 8);
        assert_eq!(size_of::<SystemNumaInformation>(), 1032);
        assert_eq!(align_of::<SystemNumaInformation>(), 8);
    }

    #[test]
    fn system_hypervisor_shared_page_information_matches_windows_x64_layout() {
        assert_eq!(size_of::<SystemHypervisorSharedPageInformation>(), 8);
        assert_eq!(align_of::<SystemHypervisorSharedPageInformation>(), 8);
    }

    #[test]
    fn system_processor_features_bitmap_information_matches_windows_x64_layout() {
        assert_eq!(size_of::<SystemProcessorFeaturesBitMapInformation>(), 16);
        assert_eq!(align_of::<SystemProcessorFeaturesBitMapInformation>(), 8);
    }

    #[test]
    fn system_logical_processor_information_ex_matches_windows_x64_layout() {
        assert_eq!(size_of::<ProcessorRelationship>(), 40);
        assert_eq!(align_of::<ProcessorRelationship>(), 8);
        assert_eq!(size_of::<NumaNodeRelationship>(), 40);
        assert_eq!(align_of::<NumaNodeRelationship>(), 8);
        assert_eq!(size_of::<ProcessorGroupInfo>(), 48);
        assert_eq!(align_of::<ProcessorGroupInfo>(), 8);
        assert_eq!(size_of::<GroupRelationship>(), 72);
        assert_eq!(align_of::<GroupRelationship>(), 8);
        assert_eq!(
            size_of::<SystemLogicalProcessorInformationExProcessor>(),
            48
        );
        assert_eq!(
            align_of::<SystemLogicalProcessorInformationExProcessor>(),
            8
        );
        assert_eq!(size_of::<SystemLogicalProcessorInformationExNumaNode>(), 48);
        assert_eq!(align_of::<SystemLogicalProcessorInformationExNumaNode>(), 8);
        assert_eq!(size_of::<SystemLogicalProcessorInformationExGroup>(), 80);
        assert_eq!(align_of::<SystemLogicalProcessorInformationExGroup>(), 8);
    }

    #[test]
    fn system_feature_configuration_sections_layout_matches_windows_x64() {
        assert_eq!(size_of::<SystemFeatureConfigurationSectionsRequest>(), 32);
        assert_eq!(align_of::<SystemFeatureConfigurationSectionsRequest>(), 8);
        assert_eq!(
            size_of::<SystemFeatureConfigurationSectionsInformationEntry>(),
            24
        );
        assert_eq!(
            align_of::<SystemFeatureConfigurationSectionsInformationEntry>(),
            8
        );
        assert_eq!(
            size_of::<SystemFeatureConfigurationSectionsInformation>(),
            104
        );
        assert_eq!(
            align_of::<SystemFeatureConfigurationSectionsInformation>(),
            8
        );
    }

    #[test]
    fn nt_query_system_information_reports_basic_information() {
        init_platform();
        let mut info = SystemBasicInformation {
            reserved: u32::MAX,
            timer_resolution: 0,
            page_size: 0,
            number_of_physical_pages: 0,
            lowest_physical_page_number: 0,
            highest_physical_page_number: 0,
            allocation_granularity: 0,
            _padding0: 0,
            minimum_user_mode_address: 0,
            maximum_user_mode_address: 0,
            active_processors_affinity_mask: 0,
            number_of_processors: 0,
            _padding1: [0; 7],
        };
        let mut return_length = 0;

        assert_eq!(
            handle_nt_query_system_information(
                class_value(SystemInformationClass::Basic),
                mut_byte_ptr(&mut info),
                u32::try_from(size_of::<SystemBasicInformation>()).unwrap(),
                Some(mut_ptr(&mut return_length)),
            ),
            NtStatus::SUCCESS
        );

        assert_eq!(
            return_length,
            u32::try_from(size_of::<SystemBasicInformation>()).unwrap()
        );
        assert_eq!(info.page_size, u32::try_from(PAGE_SIZE).unwrap());
        assert_eq!(info.allocation_granularity, ALLOCATION_GRANULARITY);
        assert_eq!(info.number_of_processors, NUMBER_OF_PROCESSORS);
        assert_eq!(
            info.minimum_user_mode_address,
            <Platform as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN
        );
        assert_eq!(
            info.maximum_user_mode_address,
            <Platform as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX - 1
        );
    }

    #[test]
    fn nt_query_system_information_reports_emulation_basic_information() {
        init_platform();
        let mut info = SystemBasicInformation {
            reserved: u32::MAX,
            timer_resolution: 0,
            page_size: 0,
            number_of_physical_pages: 0,
            lowest_physical_page_number: 0,
            highest_physical_page_number: 0,
            allocation_granularity: 0,
            _padding0: 0,
            minimum_user_mode_address: 0,
            maximum_user_mode_address: 0,
            active_processors_affinity_mask: 0,
            number_of_processors: 0,
            _padding1: [0; 7],
        };
        let mut return_length = 0;

        assert_eq!(
            handle_nt_query_system_information(
                class_value(SystemInformationClass::EmulationBasic),
                mut_byte_ptr(&mut info),
                u32::try_from(size_of::<SystemBasicInformation>()).unwrap(),
                Some(mut_ptr(&mut return_length)),
            ),
            NtStatus::SUCCESS
        );

        assert_eq!(
            return_length,
            u32::try_from(size_of::<SystemBasicInformation>()).unwrap()
        );
        assert_eq!(info.page_size, u32::try_from(PAGE_SIZE).unwrap());
        assert_eq!(info.allocation_granularity, ALLOCATION_GRANULARITY);
        assert_eq!(info.number_of_processors, NUMBER_OF_PROCESSORS);
    }

    #[test]
    fn nt_query_system_information_reports_numa_processor_map() {
        init_platform();
        let mut info = SystemNumaInformation {
            highest_node_number: u32::MAX,
            reserved: u32::MAX,
            active_processors_group_affinity: [GroupAffinity {
                mask: usize::MAX,
                group: u16::MAX,
                reserved: [u16::MAX; 3],
            }; MAXIMUM_NODE_COUNT],
        };
        let mut return_length = 0;

        assert_eq!(
            handle_nt_query_system_information(
                class_value(SystemInformationClass::NumaProcessorMap),
                mut_byte_ptr(&mut info),
                u32::try_from(size_of::<SystemNumaInformation>()).unwrap(),
                Some(mut_ptr(&mut return_length)),
            ),
            NtStatus::SUCCESS
        );

        assert_eq!(
            return_length,
            u32::try_from(size_of::<SystemNumaInformation>()).unwrap()
        );
        assert_eq!(info.highest_node_number, 0);
        assert_eq!(info.reserved, 0);
        assert_eq!(
            info.active_processors_group_affinity[0].mask,
            usize::from(NUMBER_OF_PROCESSORS)
        );
        assert_eq!(info.active_processors_group_affinity[0].group, 0);
        assert!(
            info.active_processors_group_affinity[1..]
                .iter()
                .all(|affinity| affinity.mask == 0 && affinity.group == 0)
        );
    }

    #[test]
    fn nt_query_system_information_reports_no_hypervisor_shared_page() {
        init_platform();
        let mut info = SystemHypervisorSharedPageInformation {
            hypervisor_shared_user_va: usize::MAX,
        };
        let mut return_length = 0;

        assert_eq!(
            handle_nt_query_system_information(
                class_value(SystemInformationClass::HypervisorSharedPage),
                mut_byte_ptr(&mut info),
                u32::try_from(size_of::<SystemHypervisorSharedPageInformation>()).unwrap(),
                Some(mut_ptr(&mut return_length)),
            ),
            NtStatus::SUCCESS
        );

        assert_eq!(
            return_length,
            u32::try_from(size_of::<SystemHypervisorSharedPageInformation>()).unwrap()
        );
        assert_eq!(info.hypervisor_shared_user_va, 0);
    }

    #[test]
    fn nt_query_system_information_reports_processor_features_bitmap() {
        init_platform();
        let mut info = SystemProcessorFeaturesBitMapInformation {
            feature_bits: [u64::MAX; 2],
        };
        let mut return_length = 0;

        assert_eq!(
            handle_nt_query_system_information(
                class_value(SystemInformationClass::ProcessorFeaturesBitMap),
                mut_byte_ptr(&mut info),
                u32::try_from(size_of::<SystemProcessorFeaturesBitMapInformation>()).unwrap(),
                Some(mut_ptr(&mut return_length)),
            ),
            NtStatus::SUCCESS
        );

        assert_eq!(
            return_length,
            u32::try_from(size_of::<SystemProcessorFeaturesBitMapInformation>()).unwrap()
        );
        assert_eq!(info.feature_bits, [0; 2]);
    }

    #[test]
    fn nt_query_system_information_rejects_invalid_arguments() {
        init_platform();
        let mut info = [0u8; size_of::<SystemBasicInformation>()];
        let mut return_length = 0;

        assert_eq!(
            handle_nt_query_system_information(
                class_value(SystemInformationClass::Basic),
                mut_byte_ptr(&mut info),
                u32::try_from(size_of::<SystemBasicInformation>() - 1).unwrap(),
                Some(mut_ptr(&mut return_length)),
            ),
            NtStatus::INFO_LENGTH_MISMATCH
        );
        assert_eq!(
            return_length,
            u32::try_from(size_of::<SystemBasicInformation>()).unwrap()
        );

        assert_eq!(
            handle_nt_query_system_information(
                1,
                mut_byte_ptr(&mut info),
                u32::try_from(info.len()).unwrap(),
                None,
            ),
            NtStatus::INVALID_INFO_CLASS
        );
    }

    #[test]
    fn nt_query_system_information_reports_flush_information() {
        init_platform();
        let mut info = SystemFlushInformation {
            supported_flush_methods: 0,
            processor_features: 0,
            reserved: [u32::MAX; 6],
        };
        let mut return_length = 0;

        assert_eq!(
            handle_nt_query_system_information(
                class_value(SystemInformationClass::Flush),
                mut_byte_ptr(&mut info),
                u32::try_from(size_of::<SystemFlushInformation>()).unwrap(),
                Some(mut_ptr(&mut return_length)),
            ),
            NtStatus::SUCCESS
        );

        assert_eq!(
            return_length,
            u32::try_from(size_of::<SystemFlushInformation>()).unwrap()
        );
        assert_eq!(info.supported_flush_methods, SUPPORTED_FLUSH_METHODS);
        assert_eq!(info.processor_features, SUPPORTED_FLUSH_PROCESSOR_FEATURES);
        assert_eq!(info.reserved, [0; 6]);
    }

    #[test]
    fn nt_query_system_information_rejects_short_flush_information_buffer() {
        init_platform();
        let mut info = [0u8; size_of::<SystemFlushInformation>() - 1];
        let mut return_length = 0;

        assert_eq!(
            handle_nt_query_system_information(
                class_value(SystemInformationClass::Flush),
                mut_byte_ptr(&mut info),
                u32::try_from(info.len()).unwrap(),
                Some(mut_ptr(&mut return_length)),
            ),
            NtStatus::INFO_LENGTH_MISMATCH
        );
        assert_eq!(
            return_length,
            u32::try_from(size_of::<SystemFlushInformation>()).unwrap()
        );
    }

    #[test]
    fn nt_query_system_information_ex_reports_feature_configuration_sections() {
        init_platform();
        let request = SystemFeatureConfigurationSectionsRequest {
            previous_change_stamps: [1, 2, 3, 4],
        };
        let mut info = SystemFeatureConfigurationSectionsInformation {
            overall_change_stamp: u64::MAX,
            descriptors: [SystemFeatureConfigurationSectionsInformationEntry {
                change_stamp: u64::MAX,
                section_handle: usize::MAX,
                size: usize::MAX,
            }; SYSTEM_FEATURE_CONFIGURATION_SECTION_TYPE_COUNT],
        };
        let mut return_length = 0;

        assert_eq!(
            handle_nt_query_system_information_ex(
                class_value(SystemInformationClass::FeatureConfigurationSection),
                Some(const_byte_ptr(&request)),
                u32::try_from(size_of::<SystemFeatureConfigurationSectionsRequest>()).unwrap(),
                mut_byte_ptr(&mut info),
                u32::try_from(size_of::<SystemFeatureConfigurationSectionsInformation>()).unwrap(),
                Some(mut_ptr(&mut return_length)),
            ),
            NtStatus::SUCCESS
        );

        assert_eq!(
            return_length,
            u32::try_from(size_of::<SystemFeatureConfigurationSectionsInformation>()).unwrap()
        );
        assert_eq!(info.overall_change_stamp, 0);
        for descriptor in info.descriptors {
            assert_eq!(descriptor.change_stamp, 0);
            assert_eq!(descriptor.section_handle, 0);
            assert_eq!(descriptor.size, 0);
        }
    }

    #[test]
    fn nt_query_system_information_ex_reports_logical_processor_group_information() {
        init_platform();
        let relationship = RELATION_GROUP;
        let mut info = SystemLogicalProcessorInformationExGroup {
            relationship: u32::MAX,
            size: u32::MAX,
            group: GroupRelationship {
                maximum_group_count: u16::MAX,
                active_group_count: u16::MAX,
                reserved: [u8::MAX; 20],
                group_info: [ProcessorGroupInfo {
                    maximum_processor_count: u8::MAX,
                    active_processor_count: u8::MAX,
                    reserved: [u8::MAX; 38],
                    active_processor_mask: usize::MAX,
                }],
            },
        };
        let mut return_length = 0;

        assert_eq!(
            handle_nt_query_system_information_ex(
                class_value(SystemInformationClass::LogicalProcessorAndGroup),
                Some(const_byte_ptr(&relationship)),
                u32::try_from(size_of::<u32>()).unwrap(),
                mut_byte_ptr(&mut info),
                u32::try_from(size_of::<SystemLogicalProcessorInformationExGroup>()).unwrap(),
                Some(mut_ptr(&mut return_length)),
            ),
            NtStatus::SUCCESS
        );

        assert_eq!(
            return_length,
            u32::try_from(size_of::<SystemLogicalProcessorInformationExGroup>()).unwrap()
        );
        assert_eq!(info.relationship, RELATION_GROUP);
        assert_eq!(
            info.size,
            u32::try_from(size_of::<SystemLogicalProcessorInformationExGroup>()).unwrap()
        );
        assert_eq!(info.group.maximum_group_count, 1);
        assert_eq!(info.group.active_group_count, 1);
        assert_eq!(
            info.group.group_info[0].active_processor_count,
            NUMBER_OF_PROCESSORS
        );
        assert_eq!(
            info.group.group_info[0].active_processor_mask,
            usize::from(NUMBER_OF_PROCESSORS)
        );
    }

    #[test]
    fn nt_query_system_information_ex_reports_logical_processor_required_length() {
        init_platform();
        let relationship = RELATION_ALL;
        let mut info = [0u8; 1];
        let mut return_length = 0;

        assert_eq!(
            handle_nt_query_system_information_ex(
                class_value(SystemInformationClass::LogicalProcessorAndGroup),
                Some(const_byte_ptr(&relationship)),
                u32::try_from(size_of::<u32>()).unwrap(),
                mut_byte_ptr(&mut info),
                u32::try_from(info.len()).unwrap(),
                Some(mut_ptr(&mut return_length)),
            ),
            NtStatus::INFO_LENGTH_MISMATCH
        );

        assert_eq!(
            return_length,
            u32::try_from(
                size_of::<SystemLogicalProcessorInformationExProcessor>()
                    + size_of::<SystemLogicalProcessorInformationExNumaNode>()
                    + size_of::<SystemLogicalProcessorInformationExGroup>()
            )
            .unwrap()
        );
    }

    #[test]
    fn nt_query_system_information_ex_rejects_invalid_feature_configuration_input() {
        init_platform();
        let request = SystemFeatureConfigurationSectionsRequest {
            previous_change_stamps: [0; SYSTEM_FEATURE_CONFIGURATION_SECTION_TYPE_COUNT],
        };
        let mut info = [0u8; size_of::<SystemFeatureConfigurationSectionsInformation>()];

        assert_eq!(
            handle_nt_query_system_information_ex(
                class_value(SystemInformationClass::FeatureConfigurationSection),
                None,
                u32::try_from(size_of::<SystemFeatureConfigurationSectionsRequest>()).unwrap(),
                mut_byte_ptr(&mut info),
                u32::try_from(info.len()).unwrap(),
                None,
            ),
            NtStatus::INVALID_PARAMETER
        );

        assert_eq!(
            handle_nt_query_system_information_ex(
                class_value(SystemInformationClass::FeatureConfigurationSection),
                Some(const_byte_ptr(&request)),
                u32::try_from(size_of::<SystemFeatureConfigurationSectionsRequest>() - 1).unwrap(),
                mut_byte_ptr(&mut info),
                u32::try_from(info.len()).unwrap(),
                None,
            ),
            NtStatus::INVALID_PARAMETER
        );
    }

    #[test]
    fn nt_query_system_information_ex_rejects_short_feature_configuration_output() {
        init_platform();
        let request = SystemFeatureConfigurationSectionsRequest {
            previous_change_stamps: [0; SYSTEM_FEATURE_CONFIGURATION_SECTION_TYPE_COUNT],
        };
        let mut info = [0u8; size_of::<SystemFeatureConfigurationSectionsInformation>() - 1];
        let mut return_length = 0;

        assert_eq!(
            handle_nt_query_system_information_ex(
                class_value(SystemInformationClass::FeatureConfigurationSection),
                Some(const_byte_ptr(&request)),
                u32::try_from(size_of::<SystemFeatureConfigurationSectionsRequest>()).unwrap(),
                mut_byte_ptr(&mut info),
                u32::try_from(info.len()).unwrap(),
                Some(mut_ptr(&mut return_length)),
            ),
            NtStatus::INFO_LENGTH_MISMATCH
        );
        assert_eq!(
            return_length,
            u32::try_from(size_of::<SystemFeatureConfigurationSectionsInformation>()).unwrap()
        );
    }

    #[test]
    fn nt_query_system_information_ex_rejects_unknown_class() {
        init_platform();
        let mut info = [0u8; size_of::<SystemFeatureConfigurationSectionsInformation>()];

        assert_eq!(
            handle_nt_query_system_information_ex(
                class_value(SystemInformationClass::FeatureConfigurationSection) + 1,
                None,
                0,
                mut_byte_ptr(&mut info),
                u32::try_from(info.len()).unwrap(),
                None,
            ),
            NtStatus::INVALID_INFO_CLASS
        );
    }
}
