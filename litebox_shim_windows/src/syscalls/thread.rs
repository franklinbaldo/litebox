// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::mem::size_of;

use int_enum::IntEnum;
use litebox::platform::RawConstPointer as _;
use litebox_common_windows::nt_status::NtStatus;
use litebox_platform_multiplex::Platform;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::ThreadHandle;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, IntEnum)]
enum ThreadInformationClass {
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

pub(crate) fn handle_nt_set_information_thread(
    thread_handle: ThreadHandle,
    thread_information_class: u32,
    thread_information: <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<u8>,
    thread_information_length: u32,
) -> NtStatus {
    if !thread_handle.is_current() {
        return NtStatus::INVALID_HANDLE;
    }

    let Ok(thread_information_class) = ThreadInformationClass::try_from(thread_information_class)
    else {
        litebox_util_log::debug!(
            thread_information_class = thread_information_class;
            "Unsupported NtSetInformationThread class"
        );
        return NtStatus::INVALID_INFO_CLASS;
    };

    let status = match thread_information_class {
        ThreadInformationClass::SchedulerSharedDataSlot => {
            let slot_information = match read_scheduler_shared_data_slot_information(
                thread_information,
                thread_information_length,
            ) {
                Ok(slot_information) => slot_information,
                Err(status) => return status,
            };
            let Ok(action) = SchedulerSharedDataSlotAction::try_from(slot_information.action)
            else {
                litebox_util_log::debug!(
                    action = slot_information.action;
                    "Unsupported NtSetInformationThread scheduler shared-data slot action"
                );
                return NtStatus::INVALID_PARAMETER;
            };

            litebox_util_log::debug!(
                action:? = action,
                scheduler_shared_data_handle:% = format_args!(
                    "{:#x}",
                    slot_information.scheduler_shared_data_handle
                ),
                slot:% = format_args!("{:#x}", slot_information.slot);
                "Handled scheduler shared-data slot action as a local no-op"
            );

            NtStatus::SUCCESS
        }
    };

    if status == NtStatus::SUCCESS {
        litebox_util_log::debug!(
            thread_handle:% = format_args!("{:#x}", thread_handle.as_raw()),
            thread_information_class:? = thread_information_class,
            thread_information_length;
            "Handled NtSetInformationThread syscall"
        );
    }

    status
}

fn read_scheduler_shared_data_slot_information(
    thread_information: <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<u8>,
    thread_information_length: u32,
) -> Result<SchedulerSharedDataSlotInformation, NtStatus> {
    let required_len = u32::try_from(size_of::<SchedulerSharedDataSlotInformation>())
        .expect("thread information length fits in ULONG");
    if thread_information_length < required_len {
        return Err(NtStatus::INFO_LENGTH_MISMATCH);
    }

    let input = <Platform as litebox::platform::RawPointerProvider>::RawConstPointer::<
        SchedulerSharedDataSlotInformation,
    >::from_usize(thread_information.as_usize());
    input.read_at_offset(0).ok_or(NtStatus::ACCESS_VIOLATION)
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox::platform::RawPointerProvider;

    type ConstPtr<T> = <Platform as RawPointerProvider>::RawConstPointer<T>;

    fn init_platform() {
        crate::tests::init_platform();
    }

    fn const_byte_ptr<T>(value: &T) -> ConstPtr<u8> {
        ConstPtr::from_usize(core::ptr::from_ref(value).cast::<u8>() as usize)
    }

    fn class_value(class: ThreadInformationClass) -> u32 {
        class as u32
    }

    fn action_value(action: SchedulerSharedDataSlotAction) -> u32 {
        action as u32
    }

    fn scheduler_slot(action: SchedulerSharedDataSlotAction) -> SchedulerSharedDataSlotInformation {
        SchedulerSharedDataSlotInformation {
            action: action_value(action),
            _padding: 0,
            scheduler_shared_data_handle: 0,
            slot: 0,
        }
    }

    #[test]
    fn scheduler_shared_data_slot_information_matches_windows_x64_layout() {
        assert_eq!(size_of::<SchedulerSharedDataSlotInformation>(), 24);
        assert_eq!(
            core::mem::align_of::<SchedulerSharedDataSlotInformation>(),
            8
        );
    }

    #[test]
    fn nt_set_information_thread_accepts_scheduler_shared_data_slot() {
        init_platform();
        let scheduler_slot = scheduler_slot(SchedulerSharedDataSlotAction::Assign);

        assert_eq!(
            handle_nt_set_information_thread(
                ThreadHandle::CURRENT,
                class_value(ThreadInformationClass::SchedulerSharedDataSlot),
                const_byte_ptr(&scheduler_slot),
                u32::try_from(size_of::<SchedulerSharedDataSlotInformation>()).unwrap(),
            ),
            NtStatus::SUCCESS
        );
    }

    #[test]
    fn nt_set_information_thread_rejects_invalid_arguments() {
        init_platform();
        let scheduler_slot = scheduler_slot(SchedulerSharedDataSlotAction::Assign);

        assert_eq!(
            handle_nt_set_information_thread(
                ThreadHandle::from_raw(0x1234),
                class_value(ThreadInformationClass::SchedulerSharedDataSlot),
                const_byte_ptr(&scheduler_slot),
                u32::try_from(size_of::<SchedulerSharedDataSlotInformation>()).unwrap(),
            ),
            NtStatus::INVALID_HANDLE
        );
        assert_eq!(
            handle_nt_set_information_thread(
                ThreadHandle::CURRENT,
                class_value(ThreadInformationClass::SchedulerSharedDataSlot),
                const_byte_ptr(&scheduler_slot),
                u32::try_from(size_of::<SchedulerSharedDataSlotInformation>() - 1).unwrap(),
            ),
            NtStatus::INFO_LENGTH_MISMATCH
        );
        assert_eq!(
            handle_nt_set_information_thread(
                ThreadHandle::CURRENT,
                0xffff,
                const_byte_ptr(&scheduler_slot),
                u32::try_from(size_of::<SchedulerSharedDataSlotInformation>()).unwrap(),
            ),
            NtStatus::INVALID_INFO_CLASS
        );

        let invalid_action = SchedulerSharedDataSlotInformation {
            action: u32::MAX,
            ..scheduler_slot
        };
        assert_eq!(
            handle_nt_set_information_thread(
                ThreadHandle::CURRENT,
                class_value(ThreadInformationClass::SchedulerSharedDataSlot),
                const_byte_ptr(&invalid_action),
                u32::try_from(size_of::<SchedulerSharedDataSlotInformation>()).unwrap(),
            ),
            NtStatus::INVALID_PARAMETER
        );
    }
}
