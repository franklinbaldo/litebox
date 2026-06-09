// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::mem::size_of;
use core::sync::atomic::Ordering;

use int_enum::IntEnum;
use litebox::mm::linux::{CreatePagesFlags, NonZeroPageSize};
use litebox::platform::page_mgmt::MemoryRegionPermissions;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::PAGE_SIZE;
use crate::nt_types::UnicodeString;
use crate::syscalls::ProcessHandle;
use crate::syscalls::mm::create_pages;
use crate::{ConstPtr, MutPtr, ShimFS, ShimPlatform, Task, probe_guest_output_preserving_value};

const ACTIVE_PROCESS_EXIT_STATUS: i32 = 0x0000_0103;
const NORMAL_PROCESS_BASE_PRIORITY: i32 = 8;
const GUEST_PROCESS_ID: usize = 1;
const GUEST_PARENT_PROCESS_ID: usize = 0;
const GUEST_PROCESS_AFFINITY_MASK: usize = 1;
const PROCESS_DEBUG_FLAGS_NO_DEBUGGER: u32 = 1;
const PROCESS_COOKIE: u32 = 0xdead_beef;
const MAXIMUM_HARDERROR_PARAMETERS: u32 = 5;
const HARDERROR_OPTION_SHUTDOWN_SYSTEM: u32 = 6;
const HARDERROR_OPTION_CANCEL_TRY_CONTINUE: u32 = 8;
const HARDERROR_RESPONSE_RETURN_TO_CALLER: u32 = 0;
const HARDERROR_RESPONSE_NOT_HANDLED: u32 = 1;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, IntEnum)]
enum ProcessInformationClass {
    BasicInformation = 0,
    DebugPort = 7,
    DefaultHardErrorMode = 12,
    Wow64Information = 26,
    DebugFlags = 31,
    Cookie = 36,
    ConsoleHostProcess = 49,
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

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    pub(crate) fn sys_nt_query_information_process(
        &self,
        process_handle: ProcessHandle,
        process_information_class: u32,
        process_information: MutPtr<Platform, u8>,
        process_information_length: u32,
        return_length: Option<MutPtr<Platform, u32>>,
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

        let status = match process_information_class {
            ProcessInformationClass::BasicInformation => Self::write_process_information(
                process_information,
                process_information_length,
                return_length,
                &self.process_basic_information(),
            ),
            ProcessInformationClass::DebugPort | ProcessInformationClass::Wow64Information => {
                Self::write_process_information(
                    process_information,
                    process_information_length,
                    return_length,
                    &0usize,
                )
            }
            ProcessInformationClass::DebugFlags => Self::write_process_information(
                process_information,
                process_information_length,
                return_length,
                &PROCESS_DEBUG_FLAGS_NO_DEBUGGER,
            ),
            ProcessInformationClass::DefaultHardErrorMode => Self::write_process_information(
                process_information,
                process_information_length,
                return_length,
                &ProcessDefaultHardErrorMode {
                    default_hard_error_mode: self
                        .process
                        .default_hard_error_mode
                        .load(Ordering::Acquire),
                },
            ),
            ProcessInformationClass::Cookie => Self::write_process_information(
                process_information,
                process_information_length,
                return_length,
                &self.process.cookie,
            ),
            ProcessInformationClass::ConsoleHostProcess
            | ProcessInformationClass::ImageInformation
            | ProcessInformationClass::SchedulerSharedData => {
                litebox_util_log::debug!(
                    process_information_class:? = process_information_class;
                    "Unsupported NtQueryInformationProcess class"
                );
                NtStatus::INVALID_INFO_CLASS
            }
        };

        if status == NtStatus::SUCCESS {
            litebox_util_log::debug!(
                process_information_class:? = process_information_class,
                process_information_length = process_information_length;
                "Handled NtQueryInformationProcess syscall"
            );
        }

        status
    }

    pub(crate) fn sys_nt_set_information_process(
        &self,
        process_handle: ProcessHandle,
        process_information_class: u32,
        process_information: ConstPtr<Platform, u8>,
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
                let mode = match Self::read_exact_process_information::<ProcessDefaultHardErrorMode>(
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
            ProcessInformationClass::ConsoleHostProcess => {
                if let Err(status) = Self::read_exact_process_information::<usize>(
                    process_information,
                    process_information_length,
                ) {
                    return status;
                }
                NtStatus::INVALID_PARAMETER
            }
            ProcessInformationClass::ImageInformation => NtStatus::INFO_LENGTH_MISMATCH,
            ProcessInformationClass::SchedulerSharedData => {
                self.write_scheduler_shared_data(process_information, process_information_length)
            }
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
                process_information_length = process_information_length;
                "Handled NtSetInformationProcess syscall"
            );
        }

        status
    }

    pub(crate) fn sys_nt_raise_hard_error(
        error_status: NtStatus,
        number_of_parameters: u32,
        unicode_string_parameter_mask: u32,
        parameters: Option<ConstPtr<Platform, usize>>,
        valid_response_options: u32,
        response: MutPtr<Platform, u32>,
    ) -> NtStatus {
        if number_of_parameters > MAXIMUM_HARDERROR_PARAMETERS
            || parameters.is_some() != (number_of_parameters != 0)
        {
            return NtStatus::INVALID_PARAMETER_2;
        }
        if valid_response_options > HARDERROR_OPTION_CANCEL_TRY_CONTINUE {
            return NtStatus::INVALID_PARAMETER_4;
        }
        if let Err(status) = probe_guest_output_preserving_value::<Platform, u32>(response) {
            return status;
        }
        if let Some(parameters) = parameters
            && let Err(status) = Self::probe_hard_error_parameters(
                parameters,
                number_of_parameters,
                unicode_string_parameter_mask,
            )
        {
            return status;
        }

        litebox_util_log::debug!(
            error_status:? = error_status,
            number_of_parameters,
            unicode_string_parameter_mask:% = format_args!("{unicode_string_parameter_mask:#x}"),
            valid_response_options;
            "Handled NtRaiseHardError as a local hard-error sink"
        );

        let response_value = if valid_response_options == HARDERROR_OPTION_SHUTDOWN_SYSTEM {
            HARDERROR_RESPONSE_NOT_HANDLED
        } else {
            HARDERROR_RESPONSE_RETURN_TO_CALLER
        };
        if response.write_at_offset(0, response_value).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }
        if valid_response_options == HARDERROR_OPTION_SHUTDOWN_SYSTEM {
            return NtStatus::PRIVILEGE_NOT_HELD;
        }

        NtStatus::SUCCESS
    }

    fn probe_hard_error_parameters(
        parameters: ConstPtr<Platform, usize>,
        number_of_parameters: u32,
        unicode_string_parameter_mask: u32,
    ) -> Result<(), NtStatus> {
        for index in 0..number_of_parameters {
            let index_offset =
                isize::try_from(index).expect("hard-error parameter index fits isize");
            let parameter = parameters
                .read_at_offset(index_offset)
                .ok_or(NtStatus::ACCESS_VIOLATION)?;
            if unicode_string_parameter_mask & (1u32 << index) == 0 {
                continue;
            }

            let string = ConstPtr::<Platform, UnicodeString>::from_usize(parameter)
                .read_at_offset(0)
                .ok_or(NtStatus::ACCESS_VIOLATION)?;
            if string.maximum_length == 0 {
                continue;
            }

            let buffer = ConstPtr::<Platform, u8>::from_usize(string.buffer);
            let last_byte_offset = isize::try_from(string.maximum_length - 1)
                .expect("UNICODE_STRING maximum length fits isize");
            if buffer.read_at_offset(0).is_none()
                || buffer.read_at_offset(last_byte_offset).is_none()
            {
                return Err(NtStatus::ACCESS_VIOLATION);
            }
        }
        Ok(())
    }

    fn write_process_information<T: Immutable + IntoBytes>(
        process_information: MutPtr<Platform, u8>,
        process_information_length: u32,
        return_length: Option<MutPtr<Platform, u32>>,
        information: &T,
    ) -> NtStatus {
        let required_len = process_information_len::<T>();
        if process_information_length < required_len {
            return NtStatus::INFO_LENGTH_MISMATCH;
        }
        if let Some(return_length) = return_length
            && return_length.write_at_offset(0, required_len).is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        if process_information
            .write_slice_at_offset(0, information.as_bytes())
            .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }

        NtStatus::SUCCESS
    }

    fn write_scheduler_shared_data(
        &self,
        process_information: ConstPtr<Platform, u8>,
        process_information_length: u32,
    ) -> NtStatus {
        if process_information_length != process_information_len::<usize>() {
            return NtStatus::INFO_LENGTH_MISMATCH;
        }

        let Some(shared_data) = self.scheduler_shared_data() else {
            return NtStatus::NO_MEMORY;
        };
        let output = MutPtr::<Platform, usize>::from_usize(process_information.as_usize());
        if output.write_at_offset(0, shared_data).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }

        NtStatus::SUCCESS
    }

    pub(crate) fn scheduler_shared_data(&self) -> Option<usize> {
        let existing = self.process.scheduler_shared_data.load(Ordering::Acquire);
        if existing != 0 {
            return Some(existing);
        }

        let length = NonZeroPageSize::new(PAGE_SIZE)?;
        let shared_data_ptr = create_pages(
            &self.global.page_manager,
            None,
            length,
            CreatePagesFlags::empty(),
            MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
            |_| Ok(0),
        )
        .ok()?;
        let shared_data = shared_data_ptr.as_usize();

        match self.process.scheduler_shared_data.compare_exchange(
            0,
            shared_data,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => Some(shared_data),
            Err(existing) => {
                // SAFETY: This mapping was just created by this thread and was not published
                // because another thread installed the process-wide scheduler shared-data page.
                let _ = unsafe {
                    self.global
                        .page_manager
                        .remove_pages(shared_data_ptr, PAGE_SIZE)
                };
                Some(existing)
            }
        }
    }

    fn read_exact_process_information<T: FromBytes>(
        process_information: ConstPtr<Platform, u8>,
        process_information_length: u32,
    ) -> Result<T, NtStatus> {
        if process_information_length != process_information_len::<T>() {
            return Err(NtStatus::INFO_LENGTH_MISMATCH);
        }

        Self::read_process_information(process_information, process_information_length)
    }

    fn read_process_information<T: FromBytes>(
        process_information: ConstPtr<Platform, u8>,
        process_information_length: u32,
    ) -> Result<T, NtStatus> {
        let required_len = process_information_len::<T>();
        if process_information_length < required_len {
            return Err(NtStatus::INFO_LENGTH_MISMATCH);
        }

        let input = ConstPtr::<Platform, T>::from_usize(process_information.as_usize());
        input.read_at_offset(0).ok_or(NtStatus::ACCESS_VIOLATION)
    }

    fn process_basic_information(&self) -> ProcessBasicInformation {
        ProcessBasicInformation {
            exit_status: ACTIVE_PROCESS_EXIT_STATUS,
            _padding0: 0,
            peb_base_address: self.process.peb_address,
            affinity_mask: GUEST_PROCESS_AFFINITY_MASK,
            base_priority: NORMAL_PROCESS_BASE_PRIORITY,
            _padding1: 0,
            unique_process_id: GUEST_PROCESS_ID,
            inherited_from_unique_process_id: GUEST_PARENT_PROCESS_ID,
        }
    }
}

pub(crate) const fn default_process_cookie() -> u32 {
    // TODO: use CrngProvider to generate a random cookie
    PROCESS_COOKIE
}

fn process_information_len<T>() -> u32 {
    u32::try_from(size_of::<T>()).expect("process information fits in ULONG")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{const_ptr, mut_byte_ptr, mut_ptr, null_const_ptr, null_mut_ptr};
    use litebox::platform::ThreadProvider;

    type TestPlatform = crate::tests::TestPlatform;

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    unsafe extern "system" {
        fn NtQueryInformationProcess(
            process_handle: *mut core::ffi::c_void,
            process_information_class: u32,
            process_information: *mut core::ffi::c_void,
            process_information_length: u32,
            return_length: *mut u32,
        ) -> i32;

        fn NtRaiseHardError(
            error_status: i32,
            number_of_parameters: u32,
            unicode_string_parameter_mask: u32,
            parameters: *const usize,
            valid_response_options: u32,
            response: *mut u32,
        ) -> i32;
    }

    fn run_with_test_platform_pointers<R>(f: impl FnOnce() -> R) -> R {
        let _ = crate::tests::test_platform();
        <TestPlatform as ThreadProvider>::run_test_thread(f)
    }

    fn class_value(class: ProcessInformationClass) -> u32 {
        class as u32
    }

    fn const_byte_ptr<T>(value: &T) -> ConstPtr<TestPlatform, u8> {
        ConstPtr::<TestPlatform, u8>::from_usize(core::ptr::from_ref(value).cast::<u8>() as usize)
    }

    fn const_byte_mut_ptr<T>(value: &mut T) -> ConstPtr<TestPlatform, u8> {
        ConstPtr::<TestPlatform, u8>::from_usize(core::ptr::from_mut(value).cast::<u8>() as usize)
    }

    fn sys_nt_query_information_process(
        task: &Task<TestPlatform, crate::tests::TestFS>,
        process_information_class: u32,
        process_information: MutPtr<TestPlatform, u8>,
        process_information_length: u32,
        return_length: Option<MutPtr<TestPlatform, u32>>,
    ) -> NtStatus {
        task.sys_nt_query_information_process(
            ProcessHandle::CURRENT,
            process_information_class,
            process_information,
            process_information_length,
            return_length,
        )
    }

    fn sys_nt_set_information_process(
        task: &Task<TestPlatform, crate::tests::TestFS>,
        process_information_class: u32,
        process_information: ConstPtr<TestPlatform, u8>,
        process_information_length: u32,
    ) -> NtStatus {
        task.sys_nt_set_information_process(
            ProcessHandle::CURRENT,
            process_information_class,
            process_information,
            process_information_length,
        )
    }

    fn sys_nt_raise_hard_error(
        number_of_parameters: u32,
        parameters: Option<ConstPtr<TestPlatform, usize>>,
        valid_response_options: u32,
        response: MutPtr<TestPlatform, u32>,
    ) -> NtStatus {
        Task::<TestPlatform, crate::tests::TestFS>::sys_nt_raise_hard_error(
            NtStatus::SUCCESS,
            number_of_parameters,
            0,
            parameters,
            valid_response_options,
            response,
        )
    }

    fn empty_basic_information() -> ProcessBasicInformation {
        ProcessBasicInformation {
            exit_status: 0,
            _padding0: 0,
            peb_base_address: 0,
            affinity_mask: 0,
            base_priority: 0,
            _padding1: 0,
            unique_process_id: 0,
            inherited_from_unique_process_id: usize::MAX,
        }
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn host_status(status: i32) -> NtStatus {
        NtStatus::from_raw(u32::from_ne_bytes(status.to_ne_bytes()))
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn nt_current_process() -> *mut core::ffi::c_void {
        usize::MAX as *mut core::ffi::c_void
    }

    #[test]
    fn nt_query_and_set_information_process_default_hard_error_mode() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let new_mode = ProcessDefaultHardErrorMode {
                default_hard_error_mode: 0x8000,
            };
            let mut queried_mode = ProcessDefaultHardErrorMode {
                default_hard_error_mode: u32::MAX,
            };
            let mut return_length = 0;

            assert_eq!(
                sys_nt_set_information_process(
                    &task,
                    class_value(ProcessInformationClass::DefaultHardErrorMode),
                    const_byte_ptr(&new_mode),
                    process_information_len::<ProcessDefaultHardErrorMode>(),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(
                sys_nt_query_information_process(
                    &task,
                    class_value(ProcessInformationClass::DefaultHardErrorMode),
                    mut_byte_ptr(&mut queried_mode),
                    process_information_len::<ProcessDefaultHardErrorMode>(),
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
                process_information_len::<ProcessDefaultHardErrorMode>()
            );
        });
    }

    #[test]
    fn nt_set_information_process_accepts_startup_related_classes() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut scheduler_shared_data = 0usize;

            assert_eq!(
                sys_nt_set_information_process(
                    &task,
                    class_value(ProcessInformationClass::SchedulerSharedData),
                    const_byte_mut_ptr(&mut scheduler_shared_data),
                    process_information_len::<usize>(),
                ),
                NtStatus::SUCCESS
            );
            assert_ne!(scheduler_shared_data, 0);
        });
    }

    #[test]
    fn nt_query_information_process_validates_arguments() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut info = [0u8; size_of::<ProcessBasicInformation>()];
            let mut return_length = 0;

            assert_eq!(
                sys_nt_query_information_process(
                    &task,
                    class_value(ProcessInformationClass::BasicInformation),
                    mut_byte_ptr(&mut info),
                    process_information_len::<ProcessBasicInformation>() - 1,
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::INFO_LENGTH_MISMATCH
            );
            assert_eq!(
                return_length, 0,
                "NtQueryInformationProcess leaves ReturnLength untouched on length mismatch"
            );

            assert_eq!(
                task.sys_nt_query_information_process(
                    ProcessHandle::from_raw(0x1234),
                    class_value(ProcessInformationClass::BasicInformation),
                    mut_byte_ptr(&mut info),
                    process_information_len::<ProcessBasicInformation>(),
                    None,
                ),
                NtStatus::INVALID_HANDLE
            );

            assert_eq!(
                sys_nt_query_information_process(
                    &task,
                    0xffff,
                    mut_byte_ptr(&mut info),
                    process_information_len::<ProcessBasicInformation>(),
                    None,
                ),
                NtStatus::INVALID_INFO_CLASS
            );
        });
    }

    #[test]
    fn nt_set_information_process_validates_arguments() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mode = ProcessDefaultHardErrorMode {
                default_hard_error_mode: 1,
            };

            assert_eq!(
                task.sys_nt_set_information_process(
                    ProcessHandle::from_raw(0x1234),
                    class_value(ProcessInformationClass::DefaultHardErrorMode),
                    const_byte_ptr(&mode),
                    process_information_len::<ProcessDefaultHardErrorMode>(),
                ),
                NtStatus::INVALID_HANDLE
            );
            assert_eq!(
                sys_nt_set_information_process(
                    &task,
                    class_value(ProcessInformationClass::DefaultHardErrorMode),
                    const_byte_ptr(&mode),
                    process_information_len::<ProcessDefaultHardErrorMode>() - 1,
                ),
                NtStatus::INFO_LENGTH_MISMATCH
            );
            assert_eq!(
                sys_nt_set_information_process(
                    &task,
                    class_value(ProcessInformationClass::DefaultHardErrorMode),
                    const_byte_ptr(&mode),
                    process_information_len::<ProcessDefaultHardErrorMode>() + 1,
                ),
                NtStatus::INFO_LENGTH_MISMATCH
            );
            assert_eq!(
                sys_nt_set_information_process(
                    &task,
                    class_value(ProcessInformationClass::BasicInformation),
                    const_byte_ptr(&mode),
                    process_information_len::<ProcessDefaultHardErrorMode>(),
                ),
                NtStatus::INVALID_INFO_CLASS
            );
            assert_eq!(
                sys_nt_set_information_process(
                    &task,
                    class_value(ProcessInformationClass::DefaultHardErrorMode),
                    null_const_ptr::<u8>(),
                    process_information_len::<ProcessDefaultHardErrorMode>(),
                ),
                NtStatus::ACCESS_VIOLATION
            );

            let mut scheduler_shared_data = 0usize;
            assert_eq!(
                sys_nt_set_information_process(
                    &task,
                    class_value(ProcessInformationClass::SchedulerSharedData),
                    const_byte_mut_ptr(&mut scheduler_shared_data),
                    process_information_len::<usize>() - 1,
                ),
                NtStatus::INFO_LENGTH_MISMATCH
            );
            assert_eq!(
                sys_nt_set_information_process(
                    &task,
                    class_value(ProcessInformationClass::SchedulerSharedData),
                    null_const_ptr::<u8>(),
                    process_information_len::<usize>(),
                ),
                NtStatus::ACCESS_VIOLATION
            );

            assert_eq!(
                sys_nt_set_information_process(
                    &task,
                    class_value(ProcessInformationClass::ConsoleHostProcess),
                    const_byte_ptr(&scheduler_shared_data),
                    process_information_len::<usize>() - 1,
                ),
                NtStatus::INFO_LENGTH_MISMATCH
            );
            assert_eq!(
                sys_nt_set_information_process(
                    &task,
                    class_value(ProcessInformationClass::ConsoleHostProcess),
                    null_const_ptr::<u8>(),
                    process_information_len::<usize>(),
                ),
                NtStatus::ACCESS_VIOLATION
            );
            assert_eq!(
                sys_nt_set_information_process(
                    &task,
                    class_value(ProcessInformationClass::ConsoleHostProcess),
                    const_byte_ptr(&scheduler_shared_data),
                    process_information_len::<usize>(),
                ),
                NtStatus::INVALID_PARAMETER
            );

            assert_eq!(
                sys_nt_set_information_process(
                    &task,
                    class_value(ProcessInformationClass::ImageInformation),
                    const_byte_ptr(&scheduler_shared_data),
                    process_information_len::<usize>(),
                ),
                NtStatus::INFO_LENGTH_MISMATCH
            );
        });
    }

    #[test]
    fn nt_raise_hard_error_returns_to_caller_without_hard_error_port() {
        run_with_test_platform_pointers(|| {
            let mut response = u32::MAX;

            assert_eq!(
                sys_nt_raise_hard_error(0, None, 1, mut_ptr(&mut response),),
                NtStatus::SUCCESS
            );
            assert_eq!(response, HARDERROR_RESPONSE_RETURN_TO_CALLER);
        });
    }

    #[test]
    fn nt_raise_hard_error_validates_shallow_arguments() {
        run_with_test_platform_pointers(|| {
            let parameters = [0usize; 1];
            let mut response = 0xcccc_cccc;

            assert_eq!(
                sys_nt_raise_hard_error(
                    MAXIMUM_HARDERROR_PARAMETERS + 1,
                    None,
                    1,
                    mut_ptr(&mut response),
                ),
                NtStatus::INVALID_PARAMETER_2
            );
            assert_eq!(response, 0xcccc_cccc);

            assert_eq!(
                sys_nt_raise_hard_error(1, None, 1, mut_ptr(&mut response)),
                NtStatus::INVALID_PARAMETER_2
            );

            assert_eq!(
                sys_nt_raise_hard_error(
                    0,
                    Some(const_ptr(&parameters[0])),
                    1,
                    mut_ptr(&mut response),
                ),
                NtStatus::INVALID_PARAMETER_2
            );

            assert_eq!(
                sys_nt_raise_hard_error(
                    0,
                    None,
                    HARDERROR_OPTION_CANCEL_TRY_CONTINUE + 1,
                    mut_ptr(&mut response),
                ),
                NtStatus::INVALID_PARAMETER_4
            );

            assert_eq!(
                sys_nt_raise_hard_error(0, None, 1, null_mut_ptr()),
                NtStatus::ACCESS_VIOLATION
            );
        });
    }

    #[test]
    fn nt_raise_hard_error_probes_unicode_string_parameters() {
        run_with_test_platform_pointers(|| {
            let text = [b'O', 0, b'K', 0];
            let string = UnicodeString {
                length: 4,
                maximum_length: 4,
                padding_0: [0; 4],
                buffer: text.as_ptr() as usize,
            };
            let parameters = [core::ptr::from_ref(&string) as usize];
            let mut response = u32::MAX;

            assert_eq!(
                Task::<TestPlatform, crate::tests::TestFS>::sys_nt_raise_hard_error(
                    NtStatus::SUCCESS,
                    1,
                    1,
                    Some(const_ptr(&parameters[0])),
                    1,
                    mut_ptr(&mut response),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(response, HARDERROR_RESPONSE_RETURN_TO_CALLER);

            let bad_string = UnicodeString {
                buffer: 0,
                ..string
            };
            let bad_parameters = [core::ptr::from_ref(&bad_string) as usize];

            assert_eq!(
                Task::<TestPlatform, crate::tests::TestFS>::sys_nt_raise_hard_error(
                    NtStatus::SUCCESS,
                    1,
                    1,
                    Some(const_ptr(&bad_parameters[0])),
                    1,
                    mut_ptr(&mut response),
                ),
                NtStatus::ACCESS_VIOLATION
            );
        });
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn nt_query_information_process_status_matches_host_ntdll() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut host_basic = [0u8; size_of::<ProcessBasicInformation>()];
            let mut guest_basic = empty_basic_information();
            let mut host_return_length = 0;
            let mut guest_return_length = 0;
            let information_length = process_information_len::<ProcessBasicInformation>();

            // SAFETY: The handle is the current-process pseudo handle and both output pointers are
            // valid locals that ntdll does not retain.
            let host_basic_status = unsafe {
                host_status(NtQueryInformationProcess(
                    nt_current_process(),
                    class_value(ProcessInformationClass::BasicInformation),
                    host_basic.as_mut_ptr().cast(),
                    information_length,
                    &raw mut host_return_length,
                ))
            };
            let guest_basic_status = sys_nt_query_information_process(
                &task,
                class_value(ProcessInformationClass::BasicInformation),
                mut_byte_ptr(&mut guest_basic),
                information_length,
                Some(mut_ptr(&mut guest_return_length)),
            );
            assert_eq!(guest_basic_status, host_basic_status);
            assert_eq!(guest_return_length, host_return_length);

            let mut host_short_return_length = 0;
            let mut guest_short_return_length = 0;
            // SAFETY: This intentionally probes host length handling with valid local pointers and
            // a one-byte-short output buffer.
            let host_short_status = unsafe {
                host_status(NtQueryInformationProcess(
                    nt_current_process(),
                    class_value(ProcessInformationClass::BasicInformation),
                    host_basic.as_mut_ptr().cast(),
                    information_length - 1,
                    &raw mut host_short_return_length,
                ))
            };
            let guest_short_status = sys_nt_query_information_process(
                &task,
                class_value(ProcessInformationClass::BasicInformation),
                mut_byte_ptr(&mut guest_basic),
                information_length - 1,
                Some(mut_ptr(&mut guest_short_return_length)),
            );
            assert_eq!(guest_short_status, host_short_status);
            assert_eq!(guest_short_return_length, host_short_return_length);
        });
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn nt_raise_hard_error_shallow_statuses_match_host_ntdll() {
        run_with_test_platform_pointers(|| {
            let parameters = [0usize; 1];
            let mut host_response = 0xcccc_cccc;
            let mut guest_response = 0xcccc_cccc;

            // SAFETY: This uses STATUS_SUCCESS and no parameters, which host probes show returns
            // through the no-port path without displaying a hard-error UI; response is a local.
            let host_nt_status = unsafe {
                host_status(NtRaiseHardError(
                    NtStatus::SUCCESS.as_raw(),
                    0,
                    0,
                    core::ptr::null(),
                    1,
                    &raw mut host_response,
                ))
            };
            let guest_status = sys_nt_raise_hard_error(0, None, 1, mut_ptr(&mut guest_response));
            assert_eq!(guest_status, host_nt_status);
            assert_eq!(guest_response, host_response);

            host_response = 0xcccc_cccc;
            guest_response = 0xcccc_cccc;
            // SAFETY: Invalid response option is rejected before any hard-error port interaction.
            let host_nt_status = unsafe {
                host_status(NtRaiseHardError(
                    NtStatus::SUCCESS.as_raw(),
                    0,
                    0,
                    core::ptr::null(),
                    HARDERROR_OPTION_CANCEL_TRY_CONTINUE + 1,
                    &raw mut host_response,
                ))
            };
            let guest_status = sys_nt_raise_hard_error(
                0,
                None,
                HARDERROR_OPTION_CANCEL_TRY_CONTINUE + 1,
                mut_ptr(&mut guest_response),
            );
            assert_eq!(guest_status, host_nt_status);
            assert_eq!(guest_response, host_response);

            host_response = 0xcccc_cccc;
            guest_response = 0xcccc_cccc;
            // SAFETY: Excess parameter count is rejected before dereferencing pointers.
            let host_nt_status = unsafe {
                host_status(NtRaiseHardError(
                    NtStatus::SUCCESS.as_raw(),
                    MAXIMUM_HARDERROR_PARAMETERS + 1,
                    0,
                    core::ptr::null(),
                    1,
                    &raw mut host_response,
                ))
            };
            let guest_status = sys_nt_raise_hard_error(
                MAXIMUM_HARDERROR_PARAMETERS + 1,
                None,
                1,
                mut_ptr(&mut guest_response),
            );
            assert_eq!(guest_status, host_nt_status);
            assert_eq!(guest_response, host_response);

            host_response = 0xcccc_cccc;
            guest_response = 0xcccc_cccc;
            // SAFETY: A non-null parameter array with zero parameters is rejected before the
            // parameter array is dereferenced.
            let host_nt_status = unsafe {
                host_status(NtRaiseHardError(
                    NtStatus::SUCCESS.as_raw(),
                    0,
                    0,
                    parameters.as_ptr(),
                    1,
                    &raw mut host_response,
                ))
            };
            let guest_status = sys_nt_raise_hard_error(
                0,
                Some(const_ptr(&parameters[0])),
                1,
                mut_ptr(&mut guest_response),
            );
            assert_eq!(guest_status, host_nt_status);
            assert_eq!(guest_response, host_response);

            // SAFETY: Null response is rejected by ntdll probing; no hard-error UI is involved.
            let host_nt_status = unsafe {
                host_status(NtRaiseHardError(
                    NtStatus::SUCCESS.as_raw(),
                    0,
                    0,
                    core::ptr::null(),
                    1,
                    core::ptr::null_mut(),
                ))
            };
            let guest_status = sys_nt_raise_hard_error(0, None, 1, null_mut_ptr());
            assert_eq!(guest_status, host_nt_status);
        });
    }
}
