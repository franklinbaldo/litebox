// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::mem::size_of;
use core::sync::atomic::Ordering;

use int_enum::IntEnum;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::nt_types::ThreadEnvironmentBlock;
use crate::syscalls::ThreadHandle;
use crate::{ConstPtr, MutPtr, ShimFS, ShimPlatform, Task};

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

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
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

    fn teb_scheduler_shared_data_slot(&self) -> usize {
        self.teb_usize(core::mem::offset_of!(
            ThreadEnvironmentBlock,
            scheduler_shared_data_slot
        ))
        .unwrap_or(0)
    }

    fn teb_usize(&self, offset: usize) -> Option<usize> {
        let address = self.teb_address.checked_add(offset)?;
        ConstPtr::<Platform, usize>::from_usize(address).read_at_offset(0)
    }

    fn write_teb_scheduler_shared_data_slot(&self, value: usize) -> Option<()> {
        self.write_teb_usize(
            core::mem::offset_of!(ThreadEnvironmentBlock, scheduler_shared_data_slot),
            value,
        )
    }

    fn write_teb_usize(&self, offset: usize, value: usize) -> Option<()> {
        let address = self.teb_address.checked_add(offset)?;
        MutPtr::<Platform, usize>::from_usize(address).write_at_offset(0, value)
    }
}

fn read_thread_information<Platform: ShimPlatform, T: FromBytes>(
    thread_information: ConstPtr<Platform, u8>,
    thread_information_length: u32,
) -> Result<T, NtStatus> {
    if thread_information_length as usize != size_of::<T>() {
        return Err(NtStatus::INFO_LENGTH_MISMATCH);
    }
    let Some(bytes) = thread_information.to_owned_slice(size_of::<T>()) else {
        return Err(NtStatus::ACCESS_VIOLATION);
    };
    T::read_from_bytes(bytes.as_ref()).map_err(|_| NtStatus::ACCESS_VIOLATION)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nt_types::ThreadEnvironmentBlock;
    use crate::tests::null_const_ptr;
    use litebox::platform::ThreadProvider;
    use zerocopy::FromZeros as _;

    type TestPlatform = crate::tests::TestPlatform;

    fn run_with_test_platform_pointers<R>(f: impl FnOnce() -> R) -> R {
        let _ = crate::tests::test_platform();
        <TestPlatform as ThreadProvider>::run_test_thread(f)
    }

    fn thread_information_len<T>() -> u32 {
        u32::try_from(size_of::<T>()).expect("thread information fits in ULONG")
    }

    fn scheduler_slot(action: SchedulerSharedDataSlotAction) -> SchedulerSharedDataSlotInformation {
        SchedulerSharedDataSlotInformation {
            action: action as u32,
            _padding: 0,
            scheduler_shared_data_handle: 0,
            slot: usize::MAX,
        }
    }

    fn const_byte_ptr<T: FromBytes>(value: &T) -> ConstPtr<TestPlatform, u8> {
        ConstPtr::<TestPlatform, u8>::from_usize(core::ptr::from_ref(value).cast::<u8>() as usize)
    }

    fn task_with_teb(teb: &mut ThreadEnvironmentBlock) -> Task<TestPlatform, crate::tests::TestFS> {
        let mut task = crate::tests::test_task();
        task.teb_address = core::ptr::from_mut(teb) as usize;
        task
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
                    ThreadInformationClass::SchedulerSharedDataSlot as u32,
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
                    ThreadInformationClass::SchedulerSharedDataSlot as u32,
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
                    ThreadInformationClass::HideFromDebugger as u32,
                    null_const_ptr::<u8>(),
                    0,
                ),
                NtStatus::INVALID_HANDLE
            );
            assert_eq!(
                task.sys_nt_set_information_thread(
                    ThreadHandle::CURRENT,
                    ThreadInformationClass::HideFromDebugger as u32,
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
                    ThreadInformationClass::SchedulerSharedDataSlot as u32,
                    const_byte_ptr(&information),
                    thread_information_len::<SchedulerSharedDataSlotInformation>() - 1,
                ),
                NtStatus::INFO_LENGTH_MISMATCH
            );
            assert_eq!(
                task.sys_nt_set_information_thread(
                    ThreadHandle::CURRENT,
                    ThreadInformationClass::SchedulerSharedDataSlot as u32,
                    null_const_ptr::<u8>(),
                    thread_information_len::<SchedulerSharedDataSlotInformation>(),
                ),
                NtStatus::ACCESS_VIOLATION
            );
            assert_eq!(
                task.sys_nt_set_information_thread(
                    ThreadHandle::CURRENT,
                    ThreadInformationClass::SchedulerSharedDataSlot as u32,
                    const_byte_ptr(&invalid_action),
                    thread_information_len::<SchedulerSharedDataSlotInformation>(),
                ),
                NtStatus::INVALID_PARAMETER
            );
            assert_eq!(
                task.sys_nt_set_information_thread(
                    ThreadHandle::CURRENT,
                    ThreadInformationClass::SchedulerSharedDataSlot as u32,
                    const_byte_ptr(&information),
                    thread_information_len::<SchedulerSharedDataSlotInformation>(),
                ),
                NtStatus::INVALID_HANDLE
            );
        });
    }
}
