// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::mem::size_of;
use core::sync::atomic::Ordering;

use int_enum::IntEnum;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::nt_types::{ClientId, ThreadEnvironmentBlock};
use crate::syscalls::ThreadHandle;
use crate::{ConstPtr, MutPtr, ShimFS, ShimPlatform, Task, probe_guest_output_preserving_value};

const ACTIVE_THREAD_EXIT_STATUS: i32 = 0x0000_0103;
const NORMAL_THREAD_PRIORITY: i32 = 8;
const GUEST_THREAD_AFFINITY_MASK: usize = 1;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, IntEnum)]
enum ThreadInformationClass {
    BasicInformation = 0,
    QuerySetWin32StartAddress = 9,
    IsIoPending = 16,
    HideFromDebugger = 17,
    IsTerminated = 20,
    SchedulerSharedDataSlot = 57,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, IntEnum)]
enum SchedulerSharedDataSlotAction {
    Assign = 0,
    Free = 1,
    Query = 2,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct SchedulerSharedDataSlotInformation {
    action: u32,
    _padding: u32,
    scheduler_shared_data_handle: usize,
    slot: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct ThreadBasicInformation {
    exit_status: i32,
    _padding: u32,
    teb_base_address: usize,
    client_id: ClientId,
    affinity_mask: usize,
    priority: i32,
    base_priority: i32,
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    pub(crate) fn sys_nt_query_information_thread(
        &self,
        thread_handle: ThreadHandle,
        thread_information_class: u32,
        thread_information: MutPtr<Platform, u8>,
        thread_information_length: u32,
        return_length: Option<MutPtr<Platform, u32>>,
    ) -> NtStatus {
        let Ok(thread_information_class) =
            ThreadInformationClass::try_from(thread_information_class)
        else {
            litebox_util_log::debug!(
                thread_information_class = thread_information_class;
                "Unsupported NtQueryInformationThread class"
            );
            return NtStatus::INVALID_INFO_CLASS;
        };

        let status = match thread_information_class {
            ThreadInformationClass::BasicInformation => self.write_thread_basic_information(
                thread_handle,
                thread_information,
                thread_information_length,
                return_length,
            ),
            ThreadInformationClass::QuerySetWin32StartAddress => Self::write_thread_information(
                thread_handle,
                thread_information,
                thread_information_length,
                return_length,
                &self.entry_point,
            ),
            ThreadInformationClass::IsIoPending | ThreadInformationClass::IsTerminated => {
                Self::write_thread_information(
                    thread_handle,
                    thread_information,
                    thread_information_length,
                    return_length,
                    &0u32,
                )
            }
            ThreadInformationClass::HideFromDebugger => self.query_thread_hide_from_debugger(
                thread_handle,
                thread_information,
                thread_information_length,
                return_length,
            ),
            ThreadInformationClass::SchedulerSharedDataSlot => NtStatus::INVALID_INFO_CLASS,
        };

        if status == NtStatus::SUCCESS {
            litebox_util_log::debug!(
                thread_handle:% = format_args!("{:#x}", thread_handle.as_raw()),
                thread_information_class:? = thread_information_class,
                thread_information_length = thread_information_length;
                "Handled NtQueryInformationThread syscall"
            );
        }

        status
    }

    pub(crate) fn sys_nt_set_information_thread(
        &self,
        thread_handle: ThreadHandle,
        thread_information_class: u32,
        thread_information: ConstPtr<Platform, u8>,
        thread_information_length: u32,
    ) -> NtStatus {
        let Ok(thread_information_class) =
            ThreadInformationClass::try_from(thread_information_class)
        else {
            litebox_util_log::debug!(
                thread_information_class = thread_information_class;
                "Unsupported NtSetInformationThread class"
            );
            return NtStatus::INVALID_INFO_CLASS;
        };

        let status = match thread_information_class {
            ThreadInformationClass::HideFromDebugger => {
                self.set_thread_hide_from_debugger(thread_handle, thread_information_length)
            }
            ThreadInformationClass::SchedulerSharedDataSlot => self.set_scheduler_shared_data_slot(
                thread_handle,
                thread_information,
                thread_information_length,
            ),
            ThreadInformationClass::BasicInformation
            | ThreadInformationClass::QuerySetWin32StartAddress
            | ThreadInformationClass::IsIoPending
            | ThreadInformationClass::IsTerminated => NtStatus::INVALID_INFO_CLASS,
        };

        if status == NtStatus::SUCCESS {
            litebox_util_log::debug!(
                thread_handle:% = format_args!("{:#x}", thread_handle.as_raw()),
                thread_information_class:? = thread_information_class,
                thread_information_length = thread_information_length;
                "Handled NtSetInformationThread syscall"
            );
        }

        status
    }

    fn write_thread_basic_information(
        &self,
        thread_handle: ThreadHandle,
        thread_information: MutPtr<Platform, u8>,
        thread_information_length: u32,
        return_length: Option<MutPtr<Platform, u32>>,
    ) -> NtStatus {
        if thread_information_length != thread_information_len::<ThreadBasicInformation>() {
            return NtStatus::INFO_LENGTH_MISMATCH;
        }
        if !thread_handle.is_current() {
            return NtStatus::INVALID_HANDLE;
        }

        Self::write_thread_information(
            thread_handle,
            thread_information,
            thread_information_length,
            return_length,
            &self.thread_basic_information(),
        )
    }

    fn write_thread_information<T: Immutable + IntoBytes>(
        thread_handle: ThreadHandle,
        thread_information: MutPtr<Platform, u8>,
        thread_information_length: u32,
        return_length: Option<MutPtr<Platform, u32>>,
        information: &T,
    ) -> NtStatus {
        let required_len = thread_information_len::<T>();
        if thread_information_length != required_len {
            return NtStatus::INFO_LENGTH_MISMATCH;
        }
        if !thread_handle.is_current() {
            return NtStatus::INVALID_HANDLE;
        }
        if thread_information
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

    fn query_thread_hide_from_debugger(
        &self,
        thread_handle: ThreadHandle,
        thread_information: MutPtr<Platform, u8>,
        thread_information_length: u32,
        return_length: Option<MutPtr<Platform, u32>>,
    ) -> NtStatus {
        if let Some(return_length) = return_length
            && let Err(status) = probe_guest_output_preserving_value::<Platform, u32>(return_length)
        {
            return status;
        }
        if thread_information_length != thread_information_len::<u8>() {
            return NtStatus::INFO_LENGTH_MISMATCH;
        }
        if !thread_handle.is_current() {
            return NtStatus::INVALID_HANDLE;
        }

        let hidden = u8::from(
            self.process
                .thread_hidden_from_debugger
                .load(Ordering::Acquire),
        );
        if thread_information.write_at_offset(0, hidden).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }
        if let Some(return_length) = return_length
            && return_length
                .write_at_offset(0, thread_information_len::<u8>())
                .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }

        NtStatus::SUCCESS
    }

    fn set_thread_hide_from_debugger(
        &self,
        thread_handle: ThreadHandle,
        thread_information_length: u32,
    ) -> NtStatus {
        if thread_information_length != 0 {
            return NtStatus::INFO_LENGTH_MISMATCH;
        }
        if !thread_handle.is_current() {
            return NtStatus::INVALID_HANDLE;
        }

        self.process
            .thread_hidden_from_debugger
            .store(true, Ordering::Release);
        NtStatus::SUCCESS
    }

    fn set_scheduler_shared_data_slot(
        &self,
        thread_handle: ThreadHandle,
        thread_information: ConstPtr<Platform, u8>,
        thread_information_length: u32,
    ) -> NtStatus {
        let slot_information = match read_thread_information::<
            Platform,
            SchedulerSharedDataSlotInformation,
        >(thread_information, thread_information_length)
        {
            Ok(slot_information) => slot_information,
            Err(status) => return status,
        };
        if !thread_handle.is_current() {
            return NtStatus::INVALID_HANDLE;
        }
        let Ok(action) = SchedulerSharedDataSlotAction::try_from(slot_information.action) else {
            litebox_util_log::debug!(
                action = slot_information.action;
                "Unsupported NtSetInformationThread scheduler shared-data slot action"
            );
            return NtStatus::INVALID_PARAMETER;
        };

        let slot = match action {
            SchedulerSharedDataSlotAction::Assign => {
                let Some(shared_data) = self.scheduler_shared_data() else {
                    return NtStatus::NO_MEMORY;
                };
                if slot_information.scheduler_shared_data_handle != shared_data {
                    return NtStatus::INVALID_HANDLE;
                }
                shared_data
            }
            SchedulerSharedDataSlotAction::Free => 0,
            SchedulerSharedDataSlotAction::Query => self.teb_scheduler_shared_data_slot(),
        };

        if self.write_teb_scheduler_shared_data_slot(slot).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }
        if write_scheduler_shared_data_slot::<Platform>(thread_information, slot).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }

        NtStatus::SUCCESS
    }

    fn thread_basic_information(&self) -> ThreadBasicInformation {
        ThreadBasicInformation {
            exit_status: ACTIVE_THREAD_EXIT_STATUS,
            _padding: 0,
            teb_base_address: self.teb_address,
            client_id: self.teb_client_id(),
            affinity_mask: GUEST_THREAD_AFFINITY_MASK,
            priority: NORMAL_THREAD_PRIORITY,
            base_priority: NORMAL_THREAD_PRIORITY,
        }
    }

    fn teb_client_id(&self) -> ClientId {
        let client_id_address = self
            .teb_address
            .checked_add(core::mem::offset_of!(ThreadEnvironmentBlock, client_id));
        client_id_address
            .and_then(|address| {
                ConstPtr::<Platform, ClientId>::from_usize(address).read_at_offset(0)
            })
            .unwrap_or(ClientId {
                unique_process: 1,
                unique_thread: 1,
            })
    }

    fn teb_scheduler_shared_data_slot(&self) -> usize {
        let slot_address = self.teb_address.checked_add(core::mem::offset_of!(
            ThreadEnvironmentBlock,
            scheduler_shared_data_slot
        ));
        slot_address
            .and_then(|address| ConstPtr::<Platform, usize>::from_usize(address).read_at_offset(0))
            .unwrap_or(0)
    }

    fn write_teb_scheduler_shared_data_slot(&self, slot: usize) -> Option<()> {
        let slot_address = self.teb_address.checked_add(core::mem::offset_of!(
            ThreadEnvironmentBlock,
            scheduler_shared_data_slot
        ))?;
        MutPtr::<Platform, usize>::from_usize(slot_address).write_at_offset(0, slot)
    }
}

fn read_thread_information<Platform: ShimPlatform, T: FromBytes>(
    thread_information: ConstPtr<Platform, u8>,
    thread_information_length: u32,
) -> Result<T, NtStatus> {
    if thread_information_length != thread_information_len::<T>() {
        return Err(NtStatus::INFO_LENGTH_MISMATCH);
    }

    ConstPtr::<Platform, T>::from_usize(thread_information.as_usize())
        .read_at_offset(0)
        .ok_or(NtStatus::ACCESS_VIOLATION)
}

fn write_scheduler_shared_data_slot<Platform: ShimPlatform>(
    thread_information: ConstPtr<Platform, u8>,
    slot: usize,
) -> Option<()> {
    let slot_address = thread_information
        .as_usize()
        .checked_add(core::mem::offset_of!(
            SchedulerSharedDataSlotInformation,
            slot
        ))?;
    MutPtr::<Platform, usize>::from_usize(slot_address).write_at_offset(0, slot)
}

fn thread_information_len<T>() -> u32 {
    u32::try_from(size_of::<T>()).expect("thread information fits in ULONG")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{mut_byte_ptr, mut_ptr, null_const_ptr, null_mut_ptr};
    use litebox::platform::ThreadProvider;
    use zerocopy::FromZeros;

    type TestPlatform = crate::tests::TestPlatform;

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    unsafe extern "system" {
        fn NtQueryInformationThread(
            thread_handle: *mut core::ffi::c_void,
            thread_information_class: u32,
            thread_information: *mut core::ffi::c_void,
            thread_information_length: u32,
            return_length: *mut u32,
        ) -> i32;

        fn NtSetInformationThread(
            thread_handle: *mut core::ffi::c_void,
            thread_information_class: u32,
            thread_information: *const core::ffi::c_void,
            thread_information_length: u32,
        ) -> i32;
    }

    fn run_with_test_platform_pointers<R>(f: impl FnOnce() -> R) -> R {
        let _ = crate::tests::test_platform();
        <TestPlatform as ThreadProvider>::run_test_thread(f)
    }

    fn class_value(class: ThreadInformationClass) -> u32 {
        class as u32
    }

    fn action_value(action: SchedulerSharedDataSlotAction) -> u32 {
        action as u32
    }

    fn const_byte_ptr<T: FromBytes>(value: &T) -> ConstPtr<TestPlatform, u8> {
        ConstPtr::<TestPlatform, u8>::from_usize(core::ptr::from_ref(value).cast::<u8>() as usize)
    }

    fn scheduler_slot(action: SchedulerSharedDataSlotAction) -> SchedulerSharedDataSlotInformation {
        SchedulerSharedDataSlotInformation {
            action: action_value(action),
            _padding: 0,
            scheduler_shared_data_handle: 0,
            slot: usize::MAX,
        }
    }

    fn task_with_teb(teb: &mut ThreadEnvironmentBlock) -> Task<TestPlatform, crate::tests::TestFS> {
        let mut task = crate::tests::test_task();
        task.teb_address = core::ptr::from_mut(teb) as usize;
        task.entry_point = 0x1234_5678;
        task
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn host_status(status: i32) -> NtStatus {
        NtStatus::from_raw(u32::from_ne_bytes(status.to_ne_bytes()))
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn nt_current_thread() -> *mut core::ffi::c_void {
        (usize::MAX - 1) as *mut core::ffi::c_void
    }

    #[test]
    fn nt_query_information_thread_reports_basic_information() {
        run_with_test_platform_pointers(|| {
            let mut teb = ThreadEnvironmentBlock::new_zeroed();
            teb.client_id = ClientId {
                unique_process: 42,
                unique_thread: 43,
            };
            let task = task_with_teb(&mut teb);
            let mut information = ThreadBasicInformation {
                exit_status: 0,
                _padding: 0,
                teb_base_address: 0,
                client_id: ClientId {
                    unique_process: 0,
                    unique_thread: 0,
                },
                affinity_mask: 0,
                priority: 0,
                base_priority: 0,
            };
            let mut return_length = 0;

            assert_eq!(
                task.sys_nt_query_information_thread(
                    ThreadHandle::CURRENT,
                    class_value(ThreadInformationClass::BasicInformation),
                    mut_byte_ptr(&mut information),
                    thread_information_len::<ThreadBasicInformation>(),
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(information.exit_status, ACTIVE_THREAD_EXIT_STATUS);
            assert_eq!(information.teb_base_address, task.teb_address);
            assert_eq!(information.client_id, teb.client_id);
            assert_eq!(information.affinity_mask, GUEST_THREAD_AFFINITY_MASK);
            assert_eq!(information.priority, NORMAL_THREAD_PRIORITY);
            assert_eq!(information.base_priority, NORMAL_THREAD_PRIORITY);
            assert_eq!(
                return_length,
                thread_information_len::<ThreadBasicInformation>()
            );
        });
    }

    #[test]
    fn nt_query_information_thread_reports_start_address_and_boolean_classes() {
        run_with_test_platform_pointers(|| {
            let mut teb = ThreadEnvironmentBlock::new_zeroed();
            let task = task_with_teb(&mut teb);
            let mut start_address = 0usize;
            let mut is_io_pending = u32::MAX;
            let mut is_terminated = u32::MAX;

            assert_eq!(
                task.sys_nt_query_information_thread(
                    ThreadHandle::CURRENT,
                    class_value(ThreadInformationClass::QuerySetWin32StartAddress),
                    mut_byte_ptr(&mut start_address),
                    thread_information_len::<usize>(),
                    None,
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(start_address, task.entry_point);

            assert_eq!(
                task.sys_nt_query_information_thread(
                    ThreadHandle::CURRENT,
                    class_value(ThreadInformationClass::IsIoPending),
                    mut_byte_ptr(&mut is_io_pending),
                    thread_information_len::<u32>(),
                    None,
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(is_io_pending, 0);

            assert_eq!(
                task.sys_nt_query_information_thread(
                    ThreadHandle::CURRENT,
                    class_value(ThreadInformationClass::IsTerminated),
                    mut_byte_ptr(&mut is_terminated),
                    thread_information_len::<u32>(),
                    None,
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(is_terminated, 0);
        });
    }

    #[test]
    fn nt_set_information_thread_hide_from_debugger_updates_query_state() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut hidden = u8::MAX;

            assert_eq!(
                task.sys_nt_query_information_thread(
                    ThreadHandle::CURRENT,
                    class_value(ThreadInformationClass::HideFromDebugger),
                    mut_byte_ptr(&mut hidden),
                    thread_information_len::<u8>(),
                    None,
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(hidden, 0);

            assert_eq!(
                task.sys_nt_set_information_thread(
                    ThreadHandle::CURRENT,
                    class_value(ThreadInformationClass::HideFromDebugger),
                    null_const_ptr::<u8>(),
                    0,
                ),
                NtStatus::SUCCESS
            );

            assert_eq!(
                task.sys_nt_query_information_thread(
                    ThreadHandle::CURRENT,
                    class_value(ThreadInformationClass::HideFromDebugger),
                    mut_byte_ptr(&mut hidden),
                    thread_information_len::<u8>(),
                    None,
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(hidden, 1);
        });
    }

    #[test]
    fn nt_set_information_thread_scheduler_shared_data_slot_updates_teb() {
        run_with_test_platform_pointers(|| {
            let mut teb = ThreadEnvironmentBlock::new_zeroed();
            let task = task_with_teb(&mut teb);
            let shared_data = task.scheduler_shared_data().expect("shared-data page");
            let mut information = scheduler_slot(SchedulerSharedDataSlotAction::Assign);
            information.scheduler_shared_data_handle = shared_data;

            assert_eq!(
                task.sys_nt_set_information_thread(
                    ThreadHandle::CURRENT,
                    class_value(ThreadInformationClass::SchedulerSharedDataSlot),
                    const_byte_ptr(&information),
                    thread_information_len::<SchedulerSharedDataSlotInformation>(),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(teb.scheduler_shared_data_slot, shared_data);
            assert_eq!(information.slot, shared_data);

            information = scheduler_slot(SchedulerSharedDataSlotAction::Free);
            assert_eq!(
                task.sys_nt_set_information_thread(
                    ThreadHandle::CURRENT,
                    class_value(ThreadInformationClass::SchedulerSharedDataSlot),
                    const_byte_ptr(&information),
                    thread_information_len::<SchedulerSharedDataSlotInformation>(),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(teb.scheduler_shared_data_slot, 0);
            assert_eq!(information.slot, 0);
        });
    }

    #[test]
    fn nt_query_information_thread_validates_arguments() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut information = [0u8; size_of::<ThreadBasicInformation>()];
            let mut hidden = 0u8;
            let mut return_length = u32::MAX;

            assert_eq!(
                task.sys_nt_query_information_thread(
                    ThreadHandle::CURRENT,
                    class_value(ThreadInformationClass::BasicInformation),
                    mut_byte_ptr(&mut information),
                    thread_information_len::<ThreadBasicInformation>() - 1,
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::INFO_LENGTH_MISMATCH
            );
            assert_eq!(return_length, u32::MAX);

            assert_eq!(
                task.sys_nt_query_information_thread(
                    ThreadHandle::from_raw(0x1234),
                    class_value(ThreadInformationClass::BasicInformation),
                    mut_byte_ptr(&mut information),
                    thread_information_len::<ThreadBasicInformation>(),
                    None,
                ),
                NtStatus::INVALID_HANDLE
            );

            assert_eq!(
                task.sys_nt_query_information_thread(
                    ThreadHandle::CURRENT,
                    u32::MAX,
                    mut_byte_ptr(&mut information),
                    thread_information_len::<ThreadBasicInformation>(),
                    None,
                ),
                NtStatus::INVALID_INFO_CLASS
            );

            assert_eq!(
                task.sys_nt_query_information_thread(
                    ThreadHandle::CURRENT,
                    class_value(ThreadInformationClass::HideFromDebugger),
                    mut_byte_ptr(&mut hidden),
                    0,
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::INFO_LENGTH_MISMATCH
            );
            assert_eq!(return_length, u32::MAX);

            assert_eq!(
                task.sys_nt_query_information_thread(
                    ThreadHandle::CURRENT,
                    class_value(ThreadInformationClass::HideFromDebugger),
                    mut_byte_ptr(&mut hidden),
                    thread_information_len::<u8>(),
                    Some(null_mut_ptr::<u32>()),
                ),
                NtStatus::ACCESS_VIOLATION
            );
        });
    }

    #[test]
    fn nt_set_information_thread_validates_arguments() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let information = scheduler_slot(SchedulerSharedDataSlotAction::Assign);
            let invalid_action = SchedulerSharedDataSlotInformation {
                action: u32::MAX,
                ..information
            };

            assert_eq!(
                task.sys_nt_set_information_thread(
                    ThreadHandle::from_raw(0x1234),
                    class_value(ThreadInformationClass::HideFromDebugger),
                    null_const_ptr::<u8>(),
                    0,
                ),
                NtStatus::INVALID_HANDLE
            );
            assert_eq!(
                task.sys_nt_set_information_thread(
                    ThreadHandle::CURRENT,
                    class_value(ThreadInformationClass::HideFromDebugger),
                    null_const_ptr::<u8>(),
                    1,
                ),
                NtStatus::INFO_LENGTH_MISMATCH
            );
            assert_eq!(
                task.sys_nt_set_information_thread(
                    ThreadHandle::CURRENT,
                    u32::MAX,
                    null_const_ptr::<u8>(),
                    0,
                ),
                NtStatus::INVALID_INFO_CLASS
            );
            assert_eq!(
                task.sys_nt_set_information_thread(
                    ThreadHandle::CURRENT,
                    class_value(ThreadInformationClass::SchedulerSharedDataSlot),
                    const_byte_ptr(&information),
                    thread_information_len::<SchedulerSharedDataSlotInformation>() - 1,
                ),
                NtStatus::INFO_LENGTH_MISMATCH
            );
            assert_eq!(
                task.sys_nt_set_information_thread(
                    ThreadHandle::CURRENT,
                    class_value(ThreadInformationClass::SchedulerSharedDataSlot),
                    null_const_ptr::<u8>(),
                    thread_information_len::<SchedulerSharedDataSlotInformation>(),
                ),
                NtStatus::ACCESS_VIOLATION
            );
            assert_eq!(
                task.sys_nt_set_information_thread(
                    ThreadHandle::CURRENT,
                    class_value(ThreadInformationClass::SchedulerSharedDataSlot),
                    const_byte_ptr(&invalid_action),
                    thread_information_len::<SchedulerSharedDataSlotInformation>(),
                ),
                NtStatus::INVALID_PARAMETER
            );
            assert_eq!(
                task.sys_nt_set_information_thread(
                    ThreadHandle::CURRENT,
                    class_value(ThreadInformationClass::SchedulerSharedDataSlot),
                    const_byte_ptr(&information),
                    thread_information_len::<SchedulerSharedDataSlotInformation>(),
                ),
                NtStatus::INVALID_HANDLE
            );
        });
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn nt_query_information_thread_basic_length_matches_host() {
        let mut information = ThreadBasicInformation {
            exit_status: 0,
            _padding: 0,
            teb_base_address: 0,
            client_id: ClientId {
                unique_process: 0,
                unique_thread: 0,
            },
            affinity_mask: 0,
            priority: 0,
            base_priority: 0,
        };
        let mut return_length = u32::MAX;

        let host = unsafe {
            NtQueryInformationThread(
                nt_current_thread(),
                class_value(ThreadInformationClass::BasicInformation),
                core::ptr::from_mut(&mut information).cast::<core::ffi::c_void>(),
                thread_information_len::<ThreadBasicInformation>() + 8,
                core::ptr::from_mut(&mut return_length),
            )
        };
        assert_eq!(host_status(host), NtStatus::INFO_LENGTH_MISMATCH);
        assert_eq!(return_length, u32::MAX);
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn nt_set_information_thread_hide_from_debugger_shape_matches_host() {
        let mut dummy = 0u32;
        let host_mismatch = unsafe {
            NtSetInformationThread(
                nt_current_thread(),
                class_value(ThreadInformationClass::HideFromDebugger),
                core::ptr::from_mut(&mut dummy).cast::<core::ffi::c_void>(),
                thread_information_len::<u32>(),
            )
        };
        assert_eq!(host_status(host_mismatch), NtStatus::INFO_LENGTH_MISMATCH);

        let host_success = unsafe {
            NtSetInformationThread(
                nt_current_thread(),
                class_value(ThreadInformationClass::HideFromDebugger),
                core::ptr::null(),
                0,
            )
        };
        assert_eq!(host_status(host_success), NtStatus::SUCCESS);
    }
}
