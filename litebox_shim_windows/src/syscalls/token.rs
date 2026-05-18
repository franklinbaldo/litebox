// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::platform::{RawMutPointer as _, RawPointerProvider};
use litebox_common_windows::nt_status::NtStatus;

use crate::{
    Handle, NtShimFS, Platform, ProcessHandle, Task, ThreadHandle, insert_raw_handle,
    remove_raw_handle,
};

pub(crate) struct TokenSubsystem;

impl FdEnabledSubsystem for TokenSubsystem {
    type Entry = TokenObject;
}

impl FdEnabledSubsystemEntry for TokenObject {}

pub(crate) struct TokenObject;

impl<FS: NtShimFS> Task<FS> {
    fn insert_token_handle(
        &self,
        token_handle: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<Handle>,
    ) -> Result<Handle, NtStatus> {
        let mut descriptor_table = self.global.litebox.descriptor_table_mut();
        let typed = descriptor_table.insert::<TokenSubsystem>(TokenObject);
        drop(descriptor_table);
        let handle = insert_raw_handle(&self.global.litebox, &self.process.handles, typed)?;

        if token_handle.write_at_offset(0, handle).is_none() {
            remove_raw_handle::<TokenSubsystem>(
                &self.global.litebox,
                &self.process.handles,
                handle,
            );
            return Err(NtStatus::ACCESS_VIOLATION);
        }

        Ok(handle)
    }

    pub(crate) fn handle_nt_open_thread_token(
        &self,
        thread_handle: ThreadHandle,
        desired_access: u32,
        open_as_self: u8,
        token_handle: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<Handle>,
    ) -> NtStatus {
        if !thread_handle.is_current() {
            return NtStatus::INVALID_HANDLE;
        }

        let handle = match self.insert_token_handle(token_handle) {
            Ok(handle) => handle,
            Err(status) => return status,
        };

        litebox_util_log::debug!(
            handle:% = format_args!("{:#x}", handle.as_raw()),
            thread_handle:% = format_args!("{:#x}", thread_handle.as_raw()),
            desired_access,
            open_as_self = open_as_self != 0;
            "Handled NtOpenThreadToken syscall"
        );

        NtStatus::SUCCESS
    }

    pub(crate) fn handle_nt_open_process_token(
        &self,
        process_handle: ProcessHandle,
        desired_access: u32,
        token_handle: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<Handle>,
    ) -> NtStatus {
        if !process_handle.is_current() {
            return NtStatus::INVALID_HANDLE;
        }

        let handle = match self.insert_token_handle(token_handle) {
            Ok(handle) => handle,
            Err(status) => return status,
        };

        litebox_util_log::debug!(
            handle:% = format_args!("{:#x}", handle.as_raw()),
            process_handle:% = format_args!("{:#x}", process_handle.as_raw()),
            desired_access;
            "Handled NtOpenProcessToken syscall"
        );

        NtStatus::SUCCESS
    }

    pub(crate) fn handle_nt_query_information_token(
        &self,
        token_handle: Handle,
        token_information_class: u32,
        token_information: <Platform as RawPointerProvider>::RawMutPointer<u8>,
        token_information_length: u32,
        return_length: Option<<Platform as RawPointerProvider>::RawMutPointer<u32>>,
    ) -> NtStatus {
        if token_handle != Handle::from_raw(usize::MAX - 3)
            && token_handle.raw_fd().is_some()
            && crate::raw_handle_entry::<TokenSubsystem>(
                &self.global.litebox,
                &self.process.handles,
                token_handle,
            )
            .is_none()
        {
            return NtStatus::INVALID_HANDLE;
        }

        for offset in 0..token_information_length as usize {
            let Ok(offset) = isize::try_from(offset) else {
                return NtStatus::ACCESS_VIOLATION;
            };
            if token_information.write_at_offset(offset, 0).is_none() {
                return NtStatus::ACCESS_VIOLATION;
            }
        }
        if let Some(return_length) = return_length {
            if return_length
                .write_at_offset(0, token_information_length)
                .is_none()
            {
                return NtStatus::ACCESS_VIOLATION;
            }
        }

        litebox_util_log::debug!(
            token_handle:% = format_args!("{:#x}", token_handle.as_raw()),
            token_information_class = token_information_class,
            token_information_length = token_information_length;
            "Handled NtQueryInformationToken syscall"
        );

        NtStatus::SUCCESS
    }

    pub(crate) fn handle_nt_query_security_attributes_token(
        &self,
        token_handle: Handle,
        has_attributes: bool,
        number_of_attributes: u32,
        buffer: Option<<Platform as RawPointerProvider>::RawMutPointer<u8>>,
        length: u32,
        return_length: Option<<Platform as RawPointerProvider>::RawMutPointer<u32>>,
    ) -> NtStatus {
        if token_handle != Handle::from_raw(usize::MAX - 5)
            && token_handle != Handle::from_raw(usize::MAX - 3)
            && token_handle.raw_fd().is_some()
            && crate::raw_handle_entry::<TokenSubsystem>(
                &self.global.litebox,
                &self.process.handles,
                token_handle,
            )
            .is_none()
        {
            return NtStatus::INVALID_HANDLE;
        }

        if let Some(buffer) = buffer {
            for offset in 0..length as usize {
                let Ok(offset) = isize::try_from(offset) else {
                    return NtStatus::ACCESS_VIOLATION;
                };
                if buffer.write_at_offset(offset, 0).is_none() {
                    return NtStatus::ACCESS_VIOLATION;
                }
            }
        }
        if let Some(return_length) = return_length {
            if return_length.write_at_offset(0, 0).is_none() {
                return NtStatus::ACCESS_VIOLATION;
            }
        }

        litebox_util_log::debug!(
            token_handle:% = format_args!("{:#x}", token_handle.as_raw()),
            has_attributes = has_attributes,
            number_of_attributes = number_of_attributes,
            length = length;
            "Handled NtQuerySecurityAttributesToken syscall as empty attributes"
        );

        NtStatus::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use litebox::platform::{RawConstPointer as _, RawPointerProvider};
    use litebox_common_windows::nt_status::NtStatus;

    use super::*;

    type MutPtr<T> = <Platform as RawPointerProvider>::RawMutPointer<T>;

    fn init_platform() {
        crate::tests::init_platform();
    }

    fn mut_handle_ptr(value: &mut Handle) -> MutPtr<Handle> {
        MutPtr::from_usize(core::ptr::from_mut(value) as usize)
    }

    #[test]
    fn nt_open_thread_token_returns_token_handle() {
        init_platform();
        let task = crate::tests::test_task();
        let mut token_handle = Handle::from_raw(usize::MAX);

        assert_eq!(
            task.handle_nt_open_thread_token(
                ThreadHandle::CURRENT,
                0x0008,
                1,
                mut_handle_ptr(&mut token_handle),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(token_handle, Handle::from_raw_fd(0).unwrap());
        assert_ne!(token_handle.as_raw(), 0);
        assert!(
            task.process
                .handles
                .read()
                .fd_from_raw_integer::<TokenSubsystem>(token_handle.raw_fd().unwrap())
                .is_ok()
        );
    }

    #[test]
    fn nt_close_removes_token_handle() {
        init_platform();
        let task = crate::tests::test_task();
        let mut token_handle = Handle::from_raw(0);

        assert_eq!(
            task.handle_nt_open_thread_token(
                ThreadHandle::CURRENT,
                0x0008,
                1,
                mut_handle_ptr(&mut token_handle),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(task.handle_nt_close(token_handle), NtStatus::SUCCESS);
        assert_eq!(task.handle_nt_close(token_handle), NtStatus::INVALID_HANDLE);
    }

    #[test]
    fn nt_open_thread_token_rejects_unknown_thread_handle() {
        init_platform();
        let task = crate::tests::test_task();
        let mut token_handle = Handle::from_raw(0);

        assert_eq!(
            task.handle_nt_open_thread_token(
                ThreadHandle::from_raw(0x1234),
                0x0008,
                0,
                mut_handle_ptr(&mut token_handle),
            ),
            NtStatus::INVALID_HANDLE
        );
    }
}
