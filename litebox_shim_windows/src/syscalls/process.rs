// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::sync::atomic::Ordering;
use int_enum::IntEnum;
use litebox::mm::linux::{CreatePagesFlags, NonZeroPageSize};
use litebox::platform::page_mgmt::MemoryRegionPermissions;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox::utils::TruncateExt;
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::PAGE_SIZE;
use crate::syscalls::ProcessHandle;
use crate::syscalls::mm::create_pages;
use crate::{ConstPtr, MutPtr, ShimFS, ShimPlatform, Task};

const ACTIVE_PROCESS_EXIT_STATUS: i32 = 0x0000_0103;
const NORMAL_PROCESS_BASE_PRIORITY: i32 = 8;
pub(crate) const INITIAL_PROCESS_ID: usize = 1;
pub(crate) const INITIAL_THREAD_ID: usize = 1;
const GUEST_PARENT_PROCESS_ID: usize = 0;
const GUEST_PROCESS_AFFINITY_MASK: usize = 1;
const PROCESS_DEBUG_FLAGS_NO_DEBUGGER: u32 = 1;
const PROCESS_COOKIE: u32 = 0xdead_beef;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, IntEnum)]
enum ProcessInformationClass {
    BasicInformation = 0,
    DebugPort = 7,
    DefaultHardErrorMode = 12,
    Wow64Information = 26,
    DebugFlags = 31,
    TlsInformation = 35,
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
            | ProcessInformationClass::TlsInformation
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

    fn read_exact_process_information<T: FromBytes>(
        process_information: ConstPtr<Platform, u8>,
        process_information_length: u32,
    ) -> Result<T, NtStatus> {
        if process_information_length as usize != size_of::<T>() {
            return Err(NtStatus::INFO_LENGTH_MISMATCH);
        }
        let Some(bytes) = process_information.to_owned_slice(size_of::<T>()) else {
            return Err(NtStatus::ACCESS_VIOLATION);
        };
        T::read_from_bytes(bytes.as_ref()).map_err(|_| NtStatus::ACCESS_VIOLATION)
    }

    fn write_scheduler_shared_data(
        &self,
        process_information: ConstPtr<Platform, u8>,
        process_information_length: u32,
    ) -> NtStatus {
        if process_information_length as usize != size_of::<usize>() {
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

    fn write_process_information<T: Immutable + IntoBytes>(
        process_information: MutPtr<Platform, u8>,
        process_information_length: u32,
        return_length: Option<MutPtr<Platform, u32>>,
        information: &T,
    ) -> NtStatus {
        let required_len = size_of::<T>().trunc();
        if process_information_length < required_len {
            return NtStatus::INFO_LENGTH_MISMATCH;
        }
        if process_information
            .write_slice_at_offset(0, information.as_bytes())
            .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        if let Some(return_length) = return_length
            && return_length.write_at_offset(0, required_len).is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }

        NtStatus::SUCCESS
    }

    fn process_basic_information(&self) -> ProcessBasicInformation {
        ProcessBasicInformation {
            exit_status: ACTIVE_PROCESS_EXIT_STATUS,
            _padding0: 0,
            peb_base_address: self.process.peb_address,
            affinity_mask: GUEST_PROCESS_AFFINITY_MASK,
            base_priority: NORMAL_PROCESS_BASE_PRIORITY,
            _padding1: 0,
            unique_process_id: INITIAL_PROCESS_ID,
            inherited_from_unique_process_id: GUEST_PARENT_PROCESS_ID,
        }
    }
}

pub(crate) const fn default_process_cookie() -> u32 {
    // TODO: use CrngProvider to generate a random cookie
    PROCESS_COOKIE
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{mut_byte_ptr, mut_ptr, null_const_ptr, null_mut_ptr};
    use litebox::platform::ThreadProvider;

    const RETURN_LENGTH_SENTINEL: u32 = 0xaaaa_aaaa;

    type TestPlatform = crate::tests::TestPlatform;

    fn run_with_test_platform_pointers<R>(f: impl FnOnce() -> R) -> R {
        let _ = crate::tests::test_platform();
        <TestPlatform as ThreadProvider>::run_test_thread(f)
    }

    #[test]
    fn nt_query_information_process_validates_arguments() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut info = [0u8; size_of::<ProcessBasicInformation>()];
            let mut return_length = 0;
            let basic_information_len: u32 = size_of::<ProcessBasicInformation>().trunc();

            assert_eq!(
                task.sys_nt_query_information_process(
                    ProcessHandle::CURRENT,
                    ProcessInformationClass::BasicInformation as u32,
                    mut_byte_ptr(&mut info),
                    basic_information_len - 1,
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::INFO_LENGTH_MISMATCH
            );
            assert_eq!(
                return_length, 0,
                "ReactOS sets ReturnLength only after the exact-size check for this class; a host Windows probe shows the same result"
            );

            assert_eq!(
                task.sys_nt_query_information_process(
                    ProcessHandle::from_raw(0x1234),
                    ProcessInformationClass::BasicInformation as u32,
                    mut_byte_ptr(&mut info),
                    basic_information_len,
                    None,
                ),
                NtStatus::INVALID_HANDLE
            );

            assert_eq!(
                task.sys_nt_query_information_process(
                    ProcessHandle::CURRENT,
                    0xffff,
                    mut_byte_ptr(&mut info),
                    basic_information_len,
                    None,
                ),
                NtStatus::INVALID_INFO_CLASS
            );

            assert_eq!(
                task.sys_nt_query_information_process(
                    ProcessHandle::CURRENT,
                    ProcessInformationClass::BasicInformation as u32,
                    null_mut_ptr::<u8>(),
                    basic_information_len,
                    None,
                ),
                NtStatus::ACCESS_VIOLATION
            );

            return_length = RETURN_LENGTH_SENTINEL;
            assert_eq!(
                task.sys_nt_query_information_process(
                    ProcessHandle::CURRENT,
                    ProcessInformationClass::BasicInformation as u32,
                    null_mut_ptr::<u8>(),
                    basic_information_len,
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::ACCESS_VIOLATION
            );
            assert_eq!(
                return_length, RETURN_LENGTH_SENTINEL,
                "a host Windows probe leaves ReturnLength unchanged when ProcessInformation faults"
            );
        });
    }

    #[test]
    fn nt_set_information_process_updates_default_hard_error_mode() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let new_mode = ProcessDefaultHardErrorMode {
                default_hard_error_mode: 0x8000,
            };
            let mut queried_mode = ProcessDefaultHardErrorMode {
                default_hard_error_mode: u32::MAX,
            };
            let mut return_length = 0;
            let mode_len: u32 = size_of::<ProcessDefaultHardErrorMode>().trunc();

            assert_eq!(
                task.sys_nt_set_information_process(
                    ProcessHandle::CURRENT,
                    ProcessInformationClass::DefaultHardErrorMode as u32,
                    ConstPtr::<TestPlatform, u8>::from_usize(
                        core::ptr::from_ref(&new_mode).cast::<u8>() as usize,
                    ),
                    mode_len,
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(
                task.sys_nt_query_information_process(
                    ProcessHandle::CURRENT,
                    ProcessInformationClass::DefaultHardErrorMode as u32,
                    mut_byte_ptr(&mut queried_mode),
                    mode_len,
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(
                queried_mode.default_hard_error_mode,
                new_mode.default_hard_error_mode
            );
            assert_eq!(return_length, mode_len);
        });
    }

    #[test]
    fn nt_set_information_process_writes_scheduler_shared_data_once() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut first_shared_data = 0usize;
            let mut second_shared_data = 0usize;
            let first_ptr = ConstPtr::<TestPlatform, u8>::from_usize(
                core::ptr::from_mut(&mut first_shared_data).cast::<u8>() as usize,
            );
            let second_ptr = ConstPtr::<TestPlatform, u8>::from_usize(
                core::ptr::from_mut(&mut second_shared_data).cast::<u8>() as usize,
            );
            let scheduler_len: u32 = size_of::<usize>().trunc();

            assert_eq!(
                task.sys_nt_set_information_process(
                    ProcessHandle::CURRENT,
                    ProcessInformationClass::SchedulerSharedData as u32,
                    first_ptr,
                    scheduler_len,
                ),
                NtStatus::SUCCESS
            );
            assert_ne!(first_shared_data, 0);
            assert_eq!(
                task.sys_nt_set_information_process(
                    ProcessHandle::CURRENT,
                    ProcessInformationClass::SchedulerSharedData as u32,
                    second_ptr,
                    scheduler_len,
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(second_shared_data, first_shared_data);
        });
    }

    #[test]
    fn nt_set_information_process_validates_arguments() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mode = ProcessDefaultHardErrorMode {
                default_hard_error_mode: 1,
            };
            let mode_ptr = ConstPtr::<TestPlatform, u8>::from_usize(
                core::ptr::from_ref(&mode).cast::<u8>() as usize,
            );
            let mode_len: u32 = size_of::<ProcessDefaultHardErrorMode>().trunc();

            assert_eq!(
                task.sys_nt_set_information_process(
                    ProcessHandle::from_raw(0x1234),
                    ProcessInformationClass::DefaultHardErrorMode as u32,
                    mode_ptr,
                    mode_len,
                ),
                NtStatus::INVALID_HANDLE
            );
            assert_eq!(
                task.sys_nt_set_information_process(
                    ProcessHandle::CURRENT,
                    ProcessInformationClass::DefaultHardErrorMode as u32,
                    mode_ptr,
                    mode_len - 1,
                ),
                NtStatus::INFO_LENGTH_MISMATCH
            );
            assert_eq!(
                task.sys_nt_set_information_process(
                    ProcessHandle::CURRENT,
                    ProcessInformationClass::DefaultHardErrorMode as u32,
                    mode_ptr,
                    mode_len + 1,
                ),
                NtStatus::INFO_LENGTH_MISMATCH
            );
            assert_eq!(
                task.sys_nt_set_information_process(
                    ProcessHandle::CURRENT,
                    ProcessInformationClass::BasicInformation as u32,
                    mode_ptr,
                    mode_len,
                ),
                NtStatus::INVALID_INFO_CLASS
            );
            assert_eq!(
                task.sys_nt_set_information_process(
                    ProcessHandle::CURRENT,
                    ProcessInformationClass::DefaultHardErrorMode as u32,
                    null_const_ptr::<u8>(),
                    mode_len,
                ),
                NtStatus::ACCESS_VIOLATION
            );

            let mut scheduler_shared_data = 0usize;
            let scheduler_ptr = ConstPtr::<TestPlatform, u8>::from_usize(
                core::ptr::from_mut(&mut scheduler_shared_data).cast::<u8>() as usize,
            );
            let scheduler_len: u32 = size_of::<usize>().trunc();
            assert_eq!(
                task.sys_nt_set_information_process(
                    ProcessHandle::CURRENT,
                    ProcessInformationClass::SchedulerSharedData as u32,
                    scheduler_ptr,
                    scheduler_len - 1,
                ),
                NtStatus::INFO_LENGTH_MISMATCH
            );
            assert_eq!(
                task.sys_nt_set_information_process(
                    ProcessHandle::CURRENT,
                    ProcessInformationClass::SchedulerSharedData as u32,
                    null_const_ptr::<u8>(),
                    scheduler_len,
                ),
                NtStatus::ACCESS_VIOLATION
            );
        });
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    mod host_fidelity {
        use core::ffi::c_void;

        use super::*;

        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtQueryInformationProcess(
                process_handle: *mut c_void,
                process_information_class: u32,
                process_information: *mut c_void,
                process_information_length: u32,
                return_length: *mut u32,
            ) -> i32;
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

        fn host_nt_query_information_process(
            process_information_class: ProcessInformationClass,
            process_information: *mut c_void,
            process_information_length: u32,
            return_length: *mut u32,
        ) -> NtStatus {
            // SAFETY: The host ntdll call treats these as user-mode output pointers, probes them,
            // and does not retain them. Tests pass either valid locals or null to observe NTSTATUS
            // and output side effects.
            let status = unsafe {
                NtQueryInformationProcess(
                    usize::MAX as *mut c_void,
                    process_information_class as u32,
                    process_information,
                    process_information_length,
                    return_length,
                )
            };
            NtStatus::from_raw(u32::from_ne_bytes(status.to_ne_bytes()))
        }

        #[test]
        fn nt_query_information_process_basic_length_mismatch_matches_host() {
            run_with_test_platform_pointers(|| {
                let task = crate::tests::test_task();
                let mut host_info = empty_basic_information();
                let mut shim_info = empty_basic_information();
                let mut host_return_length = RETURN_LENGTH_SENTINEL;
                let mut shim_return_length = RETURN_LENGTH_SENTINEL;
                let basic_information_len: u32 = size_of::<ProcessBasicInformation>().trunc();
                let short_length = basic_information_len - 1;

                let host = host_nt_query_information_process(
                    ProcessInformationClass::BasicInformation,
                    core::ptr::addr_of_mut!(host_info).cast::<c_void>(),
                    short_length,
                    core::ptr::addr_of_mut!(host_return_length),
                );
                let shim = task.sys_nt_query_information_process(
                    ProcessHandle::CURRENT,
                    ProcessInformationClass::BasicInformation as u32,
                    mut_byte_ptr(&mut shim_info),
                    short_length,
                    Some(mut_ptr(&mut shim_return_length)),
                );

                assert_eq!(shim, host);
                assert_eq!(shim_return_length, host_return_length);
                assert_eq!(shim_info.peb_base_address, 0);
            });
        }

        #[test]
        fn nt_query_information_process_invalid_output_leaves_return_length_unchanged() {
            run_with_test_platform_pointers(|| {
                let task = crate::tests::test_task();
                let mut host_return_length = RETURN_LENGTH_SENTINEL;
                let mut shim_return_length = RETURN_LENGTH_SENTINEL;
                let basic_information_len: u32 = size_of::<ProcessBasicInformation>().trunc();

                let host = host_nt_query_information_process(
                    ProcessInformationClass::BasicInformation,
                    core::ptr::null_mut(),
                    basic_information_len,
                    core::ptr::addr_of_mut!(host_return_length),
                );
                let shim = task.sys_nt_query_information_process(
                    ProcessHandle::CURRENT,
                    ProcessInformationClass::BasicInformation as u32,
                    null_mut_ptr::<u8>(),
                    basic_information_len,
                    Some(mut_ptr(&mut shim_return_length)),
                );

                assert_eq!(shim, host);
                assert_eq!(shim_return_length, host_return_length);
            });
        }
    }
}
