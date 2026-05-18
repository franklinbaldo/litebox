// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::mem::size_of;
use core::sync::atomic::Ordering;

use int_enum::IntEnum;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_windows::nt_status::NtStatus;
use litebox_platform_multiplex::Platform;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::{NtShimFS, ProcessHandle, Task};

const ACTIVE_PROCESS_EXIT_STATUS: i32 = 0x0000_0103;
const NORMAL_PROCESS_BASE_PRIORITY: i32 = 8;
const GUEST_PROCESS_ID: usize = 1;
const GUEST_PARENT_PROCESS_ID: usize = 0;
const GUEST_PROCESS_AFFINITY_MASK: usize = 1;
const PROCESS_DEBUG_FLAGS_NO_DEBUGGER: u32 = 1;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, IntEnum)]
enum ProcessInformationClass {
    BasicInformation = 0,
    DebugPort = 7,
    DefaultHardErrorMode = 12,
    Wow64Information = 26,
    DebugFlags = 31,
    Cookie = 36,
    ImageInformation = 53,
    SchedulerSharedData = 112,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct ProcessBasicInformation {
    exit_status: i32,
    _padding0: u32,
    peb_base_address: usize,
    affinity_mask: usize,
    base_priority: i32,
    _padding1: u32,
    unique_process_id: usize,
    inherited_from_unique_process_id: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct ProcessDefaultHardErrorMode {
    default_hard_error_mode: u32,
}

impl<FS: NtShimFS> Task<FS> {
    pub(crate) fn handle_nt_query_information_process(
        &self,
        process_handle: ProcessHandle,
        process_information_class: u32,
        process_information: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u8>,
        process_information_length: u32,
        return_length: Option<
            <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u32>,
        >,
    ) -> NtStatus {
        if !process_handle.is_current() {
            return NtStatus::INVALID_HANDLE;
        }

        let Ok(process_information_class) =
            ProcessInformationClass::try_from(process_information_class)
        else {
            litebox_util_log::debug!(
                process_information_class = process_information_class;
                "Unsupported NtQueryInformationProcess class"
            );
            return NtStatus::INVALID_INFO_CLASS;
        };

        match process_information_class {
            ProcessInformationClass::BasicInformation => write_fixed_information(
                process_information,
                process_information_length,
                return_length,
                process_basic_information(self.process.peb_address),
            ),
            ProcessInformationClass::DebugPort | ProcessInformationClass::Wow64Information => {
                write_fixed_information(
                    process_information,
                    process_information_length,
                    return_length,
                    0usize,
                )
            }
            ProcessInformationClass::DebugFlags => write_fixed_information(
                process_information,
                process_information_length,
                return_length,
                PROCESS_DEBUG_FLAGS_NO_DEBUGGER,
            ),
            ProcessInformationClass::DefaultHardErrorMode => write_fixed_information(
                process_information,
                process_information_length,
                return_length,
                ProcessDefaultHardErrorMode {
                    default_hard_error_mode: self
                        .process
                        .default_hard_error_mode
                        .load(Ordering::Acquire),
                },
            ),
            ProcessInformationClass::Cookie => write_fixed_information(
                process_information,
                process_information_length,
                return_length,
                self.process.cookie,
            ),
            ProcessInformationClass::ImageInformation
            | ProcessInformationClass::SchedulerSharedData => {
                litebox_util_log::debug!(
                    process_information_class:? = process_information_class;
                    "Unsupported NtQueryInformationProcess class"
                );
                NtStatus::INVALID_INFO_CLASS
            }
        }
    }

    pub(crate) fn handle_nt_set_information_process(
        &self,
        process_handle: ProcessHandle,
        process_information_class: u32,
        process_information: <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<
            u8,
        >,
        process_information_length: u32,
    ) -> NtStatus {
        if !process_handle.is_current() {
            return NtStatus::INVALID_HANDLE;
        }

        let Ok(process_information_class) =
            ProcessInformationClass::try_from(process_information_class)
        else {
            litebox_util_log::debug!(
                process_information_class = process_information_class;
                "Unsupported NtSetInformationProcess class"
            );
            return NtStatus::INVALID_INFO_CLASS;
        };

        let status = match process_information_class {
            ProcessInformationClass::DefaultHardErrorMode => {
                let mode = match read_fixed_information::<ProcessDefaultHardErrorMode>(
                    process_information,
                    process_information_length,
                ) {
                    Ok(mode) => mode,
                    Err(status) => return status,
                };
                self.process
                    .default_hard_error_mode
                    .store(mode.default_hard_error_mode, Ordering::Release);
                NtStatus::SUCCESS
            }
            ProcessInformationClass::ImageInformation
            | ProcessInformationClass::SchedulerSharedData => NtStatus::SUCCESS,
            _ => {
                litebox_util_log::debug!(
                    process_information_class:? = process_information_class;
                    "Unsupported NtSetInformationProcess class"
                );
                NtStatus::INVALID_INFO_CLASS
            }
        };

        if status == NtStatus::SUCCESS {
            litebox_util_log::debug!(
                process_information_class:? = process_information_class,
                process_information_length;
                "Handled NtSetInformationProcess syscall"
            );
        }

        status
    }
}

fn read_fixed_information<T: FromBytes + IntoBytes>(
    process_information: <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<u8>,
    process_information_length: u32,
) -> Result<T, NtStatus> {
    let required_len =
        u32::try_from(size_of::<T>()).expect("process information length fits in ULONG");
    if process_information_length < required_len {
        return Err(NtStatus::INFO_LENGTH_MISMATCH);
    }

    let input =
        <Platform as litebox::platform::RawPointerProvider>::RawConstPointer::<T>::from_usize(
            process_information.as_usize(),
        );
    input.read_at_offset(0).ok_or(NtStatus::ACCESS_VIOLATION)
}

fn write_fixed_information<T: FromBytes + IntoBytes>(
    process_information: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u8>,
    process_information_length: u32,
    return_length: Option<<Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u32>>,
    value: T,
) -> NtStatus {
    let required_len =
        u32::try_from(size_of::<T>()).expect("process information length fits in ULONG");
    if let Some(return_length) = return_length
        && return_length.write_at_offset(0, required_len).is_none()
    {
        return NtStatus::ACCESS_VIOLATION;
    }
    if process_information_length < required_len {
        return NtStatus::INFO_LENGTH_MISMATCH;
    }

    let output =
        <Platform as litebox::platform::RawPointerProvider>::RawMutPointer::<T>::from_usize(
            process_information.as_usize(),
        );
    if output.write_at_offset(0, value).is_none() {
        return NtStatus::ACCESS_VIOLATION;
    }

    NtStatus::SUCCESS
}

fn process_basic_information(peb_address: usize) -> ProcessBasicInformation {
    ProcessBasicInformation {
        exit_status: ACTIVE_PROCESS_EXIT_STATUS,
        _padding0: 0,
        peb_base_address: peb_address,
        affinity_mask: GUEST_PROCESS_AFFINITY_MASK,
        base_priority: NORMAL_PROCESS_BASE_PRIORITY,
        _padding1: 0,
        unique_process_id: GUEST_PROCESS_ID,
        inherited_from_unique_process_id: GUEST_PARENT_PROCESS_ID,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox::platform::RawPointerProvider;

    extern crate std;

    type MutPtr<T> = <Platform as RawPointerProvider>::RawMutPointer<T>;
    type ConstPtr<T> = <Platform as RawPointerProvider>::RawConstPointer<T>;

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

    fn class_value(class: ProcessInformationClass) -> u32 {
        class as u32
    }

    #[test]
    fn process_basic_information_matches_windows_x64_layout() {
        assert_eq!(size_of::<ProcessBasicInformation>(), 48);
        assert_eq!(align_of::<ProcessBasicInformation>(), 8);
    }

    #[test]
    fn process_default_hard_error_mode_matches_windows_x64_layout() {
        assert_eq!(size_of::<ProcessDefaultHardErrorMode>(), 4);
        assert_eq!(align_of::<ProcessDefaultHardErrorMode>(), 4);
    }

    #[test]
    fn nt_query_information_process_reports_basic_information() {
        init_platform();
        let peb_address = 0x1234_5000;
        let mut info = ProcessBasicInformation {
            exit_status: 0,
            _padding0: 0,
            peb_base_address: 0,
            affinity_mask: 0,
            base_priority: 0,
            _padding1: 0,
            unique_process_id: 0,
            inherited_from_unique_process_id: usize::MAX,
        };
        let mut return_length = 0;
        let task = crate::tests::test_task_with_process(peb_address, 0);

        assert_eq!(
            task.handle_nt_query_information_process(
                ProcessHandle::CURRENT,
                class_value(ProcessInformationClass::BasicInformation),
                mut_byte_ptr(&mut info),
                u32::try_from(size_of::<ProcessBasicInformation>()).unwrap(),
                Some(mut_ptr(&mut return_length)),
            ),
            NtStatus::SUCCESS
        );

        assert_eq!(
            return_length,
            u32::try_from(size_of::<ProcessBasicInformation>()).unwrap()
        );
        assert_eq!(info.exit_status, ACTIVE_PROCESS_EXIT_STATUS);
        assert_eq!(info.peb_base_address, peb_address);
        assert_eq!(info.affinity_mask, GUEST_PROCESS_AFFINITY_MASK);
        assert_eq!(info.base_priority, NORMAL_PROCESS_BASE_PRIORITY);
        assert_eq!(info.unique_process_id, GUEST_PROCESS_ID);
        assert_eq!(
            info.inherited_from_unique_process_id,
            GUEST_PARENT_PROCESS_ID
        );
    }

    #[test]
    fn nt_query_information_process_reports_debug_and_wow64_state() {
        init_platform();
        let process_cookie = 0x4455_6677;
        let mut debug_port = usize::MAX;
        let mut wow64_information = usize::MAX;
        let mut debug_flags = 0;
        let mut cookie = 0;
        let task = crate::tests::test_task_with_process(0, process_cookie);

        assert_eq!(
            task.handle_nt_query_information_process(
                ProcessHandle::CURRENT,
                class_value(ProcessInformationClass::DebugPort),
                mut_byte_ptr(&mut debug_port),
                u32::try_from(size_of::<usize>()).unwrap(),
                None,
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(debug_port, 0);

        assert_eq!(
            task.handle_nt_query_information_process(
                ProcessHandle::CURRENT,
                class_value(ProcessInformationClass::Wow64Information),
                mut_byte_ptr(&mut wow64_information),
                u32::try_from(size_of::<usize>()).unwrap(),
                None,
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(wow64_information, 0);

        assert_eq!(
            task.handle_nt_query_information_process(
                ProcessHandle::CURRENT,
                class_value(ProcessInformationClass::DebugFlags),
                mut_byte_ptr(&mut debug_flags),
                u32::try_from(size_of::<u32>()).unwrap(),
                None,
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(debug_flags, PROCESS_DEBUG_FLAGS_NO_DEBUGGER);

        assert_eq!(
            task.handle_nt_query_information_process(
                ProcessHandle::CURRENT,
                class_value(ProcessInformationClass::Cookie),
                mut_byte_ptr(&mut cookie),
                u32::try_from(size_of::<u32>()).unwrap(),
                None,
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(cookie, process_cookie);
    }

    #[test]
    fn nt_query_and_set_information_process_default_hard_error_mode() {
        init_platform();
        let task = crate::tests::test_task_with_process(0, 0);
        let new_mode = ProcessDefaultHardErrorMode {
            default_hard_error_mode: 0x8000,
        };
        let mut queried_mode = ProcessDefaultHardErrorMode {
            default_hard_error_mode: u32::MAX,
        };
        let mut return_length = 0;

        assert_eq!(
            task.handle_nt_set_information_process(
                ProcessHandle::CURRENT,
                class_value(ProcessInformationClass::DefaultHardErrorMode),
                const_byte_ptr(&new_mode),
                u32::try_from(size_of::<ProcessDefaultHardErrorMode>()).unwrap(),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(
            task.handle_nt_query_information_process(
                ProcessHandle::CURRENT,
                class_value(ProcessInformationClass::DefaultHardErrorMode),
                mut_byte_ptr(&mut queried_mode),
                u32::try_from(size_of::<ProcessDefaultHardErrorMode>()).unwrap(),
                Some(mut_ptr(&mut return_length)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(
            queried_mode.default_hard_error_mode,
            new_mode.default_hard_error_mode
        );
        assert_eq!(
            return_length,
            u32::try_from(size_of::<ProcessDefaultHardErrorMode>()).unwrap()
        );
    }

    #[test]
    fn nt_set_information_process_accepts_scheduler_shared_data() {
        init_platform();
        let task = crate::tests::test_task_with_process(0, 0);
        let scheduler_slot = 0usize;

        assert_eq!(
            task.handle_nt_set_information_process(
                ProcessHandle::CURRENT,
                class_value(ProcessInformationClass::SchedulerSharedData),
                const_byte_ptr(&scheduler_slot),
                u32::try_from(size_of::<usize>()).unwrap(),
            ),
            NtStatus::SUCCESS
        );
    }

    #[test]
    fn nt_set_information_process_rejects_invalid_arguments() {
        init_platform();
        let task = crate::tests::test_task_with_process(0, 0);
        let mode = ProcessDefaultHardErrorMode {
            default_hard_error_mode: 1,
        };

        assert_eq!(
            task.handle_nt_set_information_process(
                ProcessHandle::from_raw(0x1234),
                class_value(ProcessInformationClass::DefaultHardErrorMode),
                const_byte_ptr(&mode),
                u32::try_from(size_of::<ProcessDefaultHardErrorMode>()).unwrap(),
            ),
            NtStatus::INVALID_HANDLE
        );
        assert_eq!(
            task.handle_nt_set_information_process(
                ProcessHandle::CURRENT,
                class_value(ProcessInformationClass::DefaultHardErrorMode),
                const_byte_ptr(&mode),
                u32::try_from(size_of::<ProcessDefaultHardErrorMode>() - 1).unwrap(),
            ),
            NtStatus::INFO_LENGTH_MISMATCH
        );
        assert_eq!(
            task.handle_nt_set_information_process(
                ProcessHandle::CURRENT,
                class_value(ProcessInformationClass::BasicInformation),
                const_byte_ptr(&mode),
                u32::try_from(size_of::<ProcessDefaultHardErrorMode>()).unwrap(),
            ),
            NtStatus::INVALID_INFO_CLASS
        );
    }

    #[test]
    fn nt_query_information_process_rejects_invalid_arguments() {
        init_platform();
        let mut info = [0u8; size_of::<ProcessBasicInformation>()];
        let mut return_length = 0;
        let task = crate::tests::test_task_with_process(0, 0);

        assert_eq!(
            task.handle_nt_query_information_process(
                ProcessHandle::CURRENT,
                class_value(ProcessInformationClass::BasicInformation),
                mut_byte_ptr(&mut info),
                u32::try_from(size_of::<ProcessBasicInformation>() - 1).unwrap(),
                Some(mut_ptr(&mut return_length)),
            ),
            NtStatus::INFO_LENGTH_MISMATCH
        );
        assert_eq!(
            return_length,
            u32::try_from(size_of::<ProcessBasicInformation>()).unwrap()
        );

        assert_eq!(
            task.handle_nt_query_information_process(
                ProcessHandle::from_raw(0x1234),
                class_value(ProcessInformationClass::BasicInformation),
                mut_byte_ptr(&mut info),
                u32::try_from(info.len()).unwrap(),
                None,
            ),
            NtStatus::INVALID_HANDLE
        );

        assert_eq!(
            task.handle_nt_query_information_process(
                ProcessHandle::CURRENT,
                0xffff,
                mut_byte_ptr(&mut info),
                u32::try_from(info.len()).unwrap(),
                None,
            ),
            NtStatus::INVALID_INFO_CLASS
        );
    }
}
