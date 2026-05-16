// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::platform::RawMutPointer as _;
use litebox_common_windows::nt_status::NtStatus;

use crate::{Handle, NtShimFS, Platform, Task, ThreadHandle, insert_raw_handle, remove_raw_handle};

pub(crate) struct TokenSubsystem;

impl FdEnabledSubsystem for TokenSubsystem {
    type Entry = TokenObject;
}

impl FdEnabledSubsystemEntry for TokenObject {}

pub(crate) struct TokenObject;

impl<FS: NtShimFS> Task<FS> {
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

        let mut descriptor_table = self.global.litebox.descriptor_table_mut();
        let typed = descriptor_table.insert::<TokenSubsystem>(TokenObject);
        drop(descriptor_table);
        let handle = match insert_raw_handle(&self.global.litebox, &self.process.handles, typed) {
            Ok(handle) => handle,
            Err(status) => return status,
        };

        if token_handle.write_at_offset(0, handle).is_none() {
            remove_raw_handle::<TokenSubsystem>(
                &self.global.litebox,
                &self.process.handles,
                handle,
            );
            return NtStatus::ACCESS_VIOLATION;
        }

        litebox_util_log::debug!(
            handle:% = format_args!("{:#x}", handle.as_raw()),
            thread_handle:% = format_args!("{:#x}", thread_handle.as_raw()),
            desired_access,
            open_as_self = open_as_self != 0;
            "Handled NtOpenThreadToken syscall"
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
