// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::mem::size_of;

use int_enum::IntEnum;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _, RawPointerProvider};
use litebox_common_windows::nt_status::NtStatus;
use litebox_platform_multiplex::Platform;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::ThreadHandle;
use crate::nt_types::{
    AMD64_CONTEXT_CONTROL, AMD64_CONTEXT_INTEGER, Amd64Context, ThreadEnvironmentBlock,
};
use crate::{NtShimFS, Task};

const SCHEDULER_SHARED_DATA_SLOT_OFFSET: usize = 16;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, IntEnum)]
enum ThreadInformationClass {
    Basic = 0,
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
struct ClientId {
    unique_process: usize,
    unique_thread: usize,
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

impl<FS: NtShimFS> Task<FS> {
    pub(crate) fn handle_nt_wait_for_alert_by_thread_id(
        &self,
        address: usize,
        timeout: Option<<Platform as litebox::platform::RawPointerProvider>::RawConstPointer<i64>>,
    ) -> NtStatus {
        let timeout_value = timeout.and_then(|timeout| timeout.read_at_offset(0));

        litebox_util_log::debug!(
            address:% = format_args!("{:#x}", address),
            timeout:? = timeout_value;
            "Handled NtWaitForAlertByThreadId syscall as a local wait sink"
        );

        NtStatus::TIMEOUT
    }

    pub(crate) fn handle_nt_query_information_thread(
        &self,
        thread_handle: ThreadHandle,
        thread_information_class: u32,
        thread_information: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u8>,
        thread_information_length: u32,
        return_length: Option<
            <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u32>,
        >,
    ) -> NtStatus {
        if !thread_handle.is_current() {
            return NtStatus::INVALID_HANDLE;
        }

        let Ok(thread_information_class) =
            ThreadInformationClass::try_from(thread_information_class)
        else {
            litebox_util_log::debug!(
                thread_information_class;
                "Unsupported NtQueryInformationThread class"
            );
            return NtStatus::INVALID_INFO_CLASS;
        };

        let status = match thread_information_class {
            ThreadInformationClass::Basic => self.write_thread_basic_information(
                thread_information,
                thread_information_length,
                return_length,
            ),
            ThreadInformationClass::SchedulerSharedDataSlot => NtStatus::INVALID_INFO_CLASS,
        };

        litebox_util_log::debug!(
            thread_handle:% = format_args!("{:#x}", thread_handle.as_raw()),
            thread_information_class:? = thread_information_class,
            thread_information_length,
            status:? = status;
            "Handled NtQueryInformationThread syscall"
        );

        status
    }

    pub(crate) fn handle_nt_set_information_thread(
        &self,
        thread_handle: ThreadHandle,
        thread_information_class: u32,
        thread_information: <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<
            u8,
        >,
        thread_information_length: u32,
    ) -> NtStatus {
        if !thread_handle.is_current() {
            return NtStatus::INVALID_HANDLE;
        }

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
            ThreadInformationClass::Basic => NtStatus::INVALID_INFO_CLASS,
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

                self.handle_scheduler_shared_data_slot_information(
                    thread_information,
                    thread_information_length,
                    action,
                    slot_information.scheduler_shared_data_handle,
                )
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

    fn write_thread_basic_information(
        &self,
        thread_information: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u8>,
        thread_information_length: u32,
        return_length: Option<
            <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u32>,
        >,
    ) -> NtStatus {
        let required_len = u32::try_from(size_of::<ThreadBasicInformation>())
            .expect("thread basic information length fits in ULONG");
        if let Some(return_length) = return_length {
            if return_length.write_at_offset(0, required_len).is_none() {
                return NtStatus::ACCESS_VIOLATION;
            }
        }
        if thread_information_length < required_len {
            return NtStatus::INFO_LENGTH_MISMATCH;
        }

        let information = ThreadBasicInformation {
            exit_status: NtStatus::SUCCESS.as_raw(),
            _padding: 0,
            teb_base_address: self.teb_address,
            client_id: ClientId {
                unique_process: 1000,
                unique_thread: 1000,
            },
            affinity_mask: 1,
            priority: 8,
            base_priority: 8,
        };
        let output = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer::<
            ThreadBasicInformation,
        >::from_usize(thread_information.as_usize());
        if output.write_at_offset(0, information).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }

        NtStatus::SUCCESS
    }

    fn handle_scheduler_shared_data_slot_information(
        &self,
        thread_information: <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<
            u8,
        >,
        thread_information_length: u32,
        action: SchedulerSharedDataSlotAction,
        scheduler_shared_data_handle: usize,
    ) -> NtStatus {
        let slot = match action {
            SchedulerSharedDataSlotAction::Assign => {
                let Some(shared_data) = self.scheduler_shared_data() else {
                    return NtStatus::NO_MEMORY;
                };
                if scheduler_shared_data_handle != shared_data {
                    return NtStatus::INVALID_HANDLE;
                }
                shared_data
            }
            SchedulerSharedDataSlotAction::Query => read_teb_usize(
                self.teb_address,
                core::mem::offset_of!(ThreadEnvironmentBlock, scheduler_shared_data_slot),
            )
            .unwrap_or(0),
            SchedulerSharedDataSlotAction::Free => 0,
        };

        if write_teb_usize(
            self.teb_address,
            core::mem::offset_of!(ThreadEnvironmentBlock, scheduler_shared_data_slot),
            slot,
        )
        .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }

        if write_scheduler_shared_data_slot(thread_information, thread_information_length, slot)
            .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }

        litebox_util_log::debug!(
            action:? = action,
            scheduler_shared_data_handle:% = format_args!("{:#x}", scheduler_shared_data_handle),
            slot:% = format_args!("{:#x}", slot);
            "Handled scheduler shared-data slot action"
        );

        NtStatus::SUCCESS
    }
}

fn read_teb_usize(teb_address: usize, offset: usize) -> Option<usize> {
    <Platform as litebox::platform::RawPointerProvider>::RawConstPointer::<usize>::from_usize(
        teb_address.checked_add(offset)?,
    )
    .read_at_offset(0)
}

fn write_teb_usize(teb_address: usize, offset: usize, value: usize) -> Option<()> {
    <Platform as litebox::platform::RawPointerProvider>::RawMutPointer::<usize>::from_usize(
        teb_address.checked_add(offset)?,
    )
    .write_at_offset(0, value)
}

pub(crate) fn handle_nt_continue(
    context: <Platform as RawPointerProvider>::RawConstPointer<Amd64Context>,
    test_alert: u8,
    pt_regs: &mut litebox_common_linux::PtRegs,
) -> NtStatus {
    let Some(guest_context) = context.read_at_offset(0) else {
        return NtStatus::ACCESS_VIOLATION;
    };
    if let Err(status) = apply_amd64_context(&guest_context, pt_regs) {
        return status;
    }

    litebox_util_log::debug!(
        context:% = format_args!("{:#x}", context.as_usize()),
        test_alert;
        "Handled NtContinue syscall"
    );

    NtStatus::SUCCESS
}

fn apply_amd64_context(
    guest_context: &Amd64Context,
    pt_regs: &mut litebox_common_linux::PtRegs,
) -> Result<(), NtStatus> {
    let flags = guest_context.context_flags;

    if flags & AMD64_CONTEXT_INTEGER == AMD64_CONTEXT_INTEGER {
        pt_regs.rax = context_usize(guest_context.rax)?;
        pt_regs.rcx = context_usize(guest_context.rcx)?;
        pt_regs.rdx = context_usize(guest_context.rdx)?;
        pt_regs.rbx = context_usize(guest_context.rbx)?;
        pt_regs.rbp = context_usize(guest_context.rbp)?;
        pt_regs.rsi = context_usize(guest_context.rsi)?;
        pt_regs.rdi = context_usize(guest_context.rdi)?;
        pt_regs.r8 = context_usize(guest_context.r8)?;
        pt_regs.r9 = context_usize(guest_context.r9)?;
        pt_regs.r10 = context_usize(guest_context.r10)?;
        pt_regs.r11 = context_usize(guest_context.r11)?;
        pt_regs.r12 = context_usize(guest_context.r12)?;
        pt_regs.r13 = context_usize(guest_context.r13)?;
        pt_regs.r14 = context_usize(guest_context.r14)?;
        pt_regs.r15 = context_usize(guest_context.r15)?;
    }

    if flags & AMD64_CONTEXT_CONTROL == AMD64_CONTEXT_CONTROL {
        pt_regs.rip = context_usize(guest_context.rip)?;
        pt_regs.rsp = context_usize(guest_context.rsp)?;
        pt_regs.eflags = guest_context.e_flags as usize;
        if guest_context.seg_cs != 0 {
            pt_regs.cs = usize::from(guest_context.seg_cs);
        }
        if guest_context.seg_ss != 0 {
            pt_regs.ss = usize::from(guest_context.seg_ss);
        }
    }

    Ok(())
}

fn context_usize(value: u64) -> Result<usize, NtStatus> {
    usize::try_from(value).map_err(|_| NtStatus::INVALID_PARAMETER)
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

fn write_scheduler_shared_data_slot(
    thread_information: <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<u8>,
    thread_information_length: u32,
    slot: usize,
) -> Option<()> {
    if usize::try_from(thread_information_length).ok()?
        < SCHEDULER_SHARED_DATA_SLOT_OFFSET.checked_add(size_of::<usize>())?
    {
        return None;
    }

    <Platform as litebox::platform::RawPointerProvider>::RawMutPointer::<usize>::from_usize(
        thread_information
            .as_usize()
            .checked_add(SCHEDULER_SHARED_DATA_SLOT_OFFSET)?,
    )
    .write_at_offset(0, slot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox::platform::RawPointerProvider;

    type ConstPtr<T> = <Platform as RawPointerProvider>::RawConstPointer<T>;

    #[repr(align(8))]
    struct AlignedTebBytes([u8; size_of::<ThreadEnvironmentBlock>()]);

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
        let mut teb = AlignedTebBytes([0; size_of::<ThreadEnvironmentBlock>()]);
        let task = crate::tests::test_task_with_teb_address(teb.0.as_mut_ptr() as usize);
        let mut scheduler_slot = scheduler_slot(SchedulerSharedDataSlotAction::Assign);
        scheduler_slot.scheduler_shared_data_handle = task.scheduler_shared_data().unwrap();

        assert_eq!(
            task.handle_nt_set_information_thread(
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
        let task = crate::tests::test_task();
        let scheduler_slot = scheduler_slot(SchedulerSharedDataSlotAction::Assign);

        assert_eq!(
            task.handle_nt_set_information_thread(
                ThreadHandle::from_raw(0x1234),
                class_value(ThreadInformationClass::SchedulerSharedDataSlot),
                const_byte_ptr(&scheduler_slot),
                u32::try_from(size_of::<SchedulerSharedDataSlotInformation>()).unwrap(),
            ),
            NtStatus::INVALID_HANDLE
        );
        assert_eq!(
            task.handle_nt_set_information_thread(
                ThreadHandle::CURRENT,
                class_value(ThreadInformationClass::SchedulerSharedDataSlot),
                const_byte_ptr(&scheduler_slot),
                u32::try_from(size_of::<SchedulerSharedDataSlotInformation>() - 1).unwrap(),
            ),
            NtStatus::INFO_LENGTH_MISMATCH
        );
        assert_eq!(
            task.handle_nt_set_information_thread(
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
            task.handle_nt_set_information_thread(
                ThreadHandle::CURRENT,
                class_value(ThreadInformationClass::SchedulerSharedDataSlot),
                const_byte_ptr(&invalid_action),
                u32::try_from(size_of::<SchedulerSharedDataSlotInformation>()).unwrap(),
            ),
            NtStatus::INVALID_PARAMETER
        );
    }
}
