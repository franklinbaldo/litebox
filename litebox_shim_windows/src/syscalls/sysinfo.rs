// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::mem::size_of;

use litebox::platform::Instant as _;
use litebox::platform::{
    PageManagementProvider, RawConstPointer as _, RawMutPointer as _, TimeProvider as _,
};
use litebox_common_windows::nt_status::NtStatus;
use litebox_platform_multiplex::Platform;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::PAGE_SIZE;

const QPC_FREQUENCY_HZ: i64 = 1_000_000_000;
const SYSTEM_BASIC_INFORMATION_CLASS: u32 = 0;
const SYSTEM_EMULATION_BASIC_INFORMATION_CLASS: u32 = 62;
const SYSTEM_FLUSH_INFORMATION_CLASS: u32 = 192;
const TIMER_RESOLUTION_100NS: u32 = 156_250;
const ALLOCATION_GRANULARITY: u32 = 0x1_0000;
const DEFAULT_PHYSICAL_PAGES: u32 = 1024 * 1024;
const NUMBER_OF_PROCESSORS: u8 = 1;
const SUPPORTED_FLUSH_METHODS: u32 = 0x7;
const SUPPORTED_FLUSH_PROCESSOR_FEATURES: u32 = 0x40;

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
struct SystemFlushInformation {
    supported_flush_methods: u32,
    processor_features: u32,
    reserved: [u32; 6],
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
    let status = match system_information_class {
        SYSTEM_BASIC_INFORMATION_CLASS | SYSTEM_EMULATION_BASIC_INFORMATION_CLASS => {
            write_system_information(
                system_information,
                system_information_length,
                return_length,
                &system_basic_information(),
            )
        }
        SYSTEM_FLUSH_INFORMATION_CLASS => write_system_information(
            system_information,
            system_information_length,
            return_length,
            &system_flush_information(),
        ),
        _ => {
            litebox_util_log::debug!(
                system_information_class = system_information_class;
                "Unsupported NtQuerySystemInformation class"
            );
            NtStatus::INVALID_INFO_CLASS
        }
    };

    if status == NtStatus::SUCCESS {
        litebox_util_log::debug!(
            system_information_class = system_information_class,
            system_information_length = system_information_length;
            "Handled NtQuerySystemInformation syscall"
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

fn system_flush_information() -> SystemFlushInformation {
    SystemFlushInformation {
        supported_flush_methods: SUPPORTED_FLUSH_METHODS,
        processor_features: SUPPORTED_FLUSH_PROCESSOR_FEATURES,
        reserved: [0; 6],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox::platform::RawPointerProvider;

    extern crate std;

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
                SYSTEM_BASIC_INFORMATION_CLASS,
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
                SYSTEM_EMULATION_BASIC_INFORMATION_CLASS,
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
    fn nt_query_system_information_rejects_invalid_arguments() {
        init_platform();
        let mut info = [0u8; size_of::<SystemBasicInformation>()];
        let mut return_length = 0;

        assert_eq!(
            handle_nt_query_system_information(
                SYSTEM_BASIC_INFORMATION_CLASS,
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
                SYSTEM_FLUSH_INFORMATION_CLASS,
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
                SYSTEM_FLUSH_INFORMATION_CLASS,
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
}
