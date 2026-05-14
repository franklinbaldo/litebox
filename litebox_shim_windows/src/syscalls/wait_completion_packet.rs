// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::platform::RawMutPointer as _;
use litebox_common_windows::nt_status::NtStatus;
use litebox_platform_multiplex::Platform;

use crate::{Handle, NtShimFS, Task, insert_raw_handle, remove_raw_handle};

use super::object::{ObjectAttributes, read_object_attributes};

pub(crate) struct WaitCompletionPacketSubsystem;

impl FdEnabledSubsystem for WaitCompletionPacketSubsystem {
    type Entry = WaitCompletionPacketObject;
}

impl FdEnabledSubsystemEntry for WaitCompletionPacketObject {}

pub(crate) struct WaitCompletionPacketObject;

impl<FS: NtShimFS> Task<FS> {
    pub(crate) fn handle_nt_create_wait_completion_packet(
        &self,
        wait_completion_packet_handle: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<
            Handle,
        >,
        desired_access: u32,
        object_attributes: Option<
            <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<ObjectAttributes>,
        >,
    ) -> NtStatus {
        if let Some(object_attributes) = object_attributes {
            let object_attributes = match read_object_attributes(object_attributes) {
                Ok(object_attributes) => object_attributes,
                Err(status) => return status,
            };
            if !object_attributes.root_directory.is_null() || object_attributes.object_name != 0 {
                litebox_util_log::warn!(
                    root_directory = object_attributes.root_directory.as_raw(),
                    object_name = object_attributes.object_name;
                    "NtCreateWaitCompletionPacket: root_directory and object_name are not supported"
                );
                return NtStatus::NOT_IMPLEMENTED;
            }
        }

        let mut descriptor_table = self.global.litebox.descriptor_table_mut();
        let typed =
            descriptor_table.insert::<WaitCompletionPacketSubsystem>(WaitCompletionPacketObject);
        drop(descriptor_table);
        let handle = match insert_raw_handle(&self.global.litebox, &self.process.handles, typed) {
            Ok(handle) => handle,
            Err(status) => return status,
        };

        if wait_completion_packet_handle
            .write_at_offset(0, handle)
            .is_none()
        {
            remove_raw_handle::<WaitCompletionPacketSubsystem>(
                &self.global.litebox,
                &self.process.handles,
                handle,
            );
            return NtStatus::ACCESS_VIOLATION;
        }

        litebox_util_log::debug!(
            handle:% = format_args!("{:#x}", handle.as_raw()),
            desired_access:% = format_args!("{desired_access:#x}");
            "Handled NtCreateWaitCompletionPacket syscall"
        );

        NtStatus::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscalls::object::ObjectAttributes;
    use litebox::platform::{RawConstPointer as _, RawPointerProvider};
    use zerocopy::{FromBytes, IntoBytes};

    extern crate std;

    type MutPtr<T> = <Platform as RawPointerProvider>::RawMutPointer<T>;
    type ConstPtr<T> = <Platform as RawPointerProvider>::RawConstPointer<T>;

    fn init_platform() {
        crate::tests::init_platform();
    }

    fn mut_ptr<T: FromBytes + IntoBytes>(value: &mut T) -> MutPtr<T> {
        MutPtr::from_usize(core::ptr::from_mut(value).cast::<u8>() as usize)
    }

    fn const_ptr<T: FromBytes>(value: &T) -> ConstPtr<T> {
        ConstPtr::from_usize(core::ptr::from_ref(value).cast::<u8>() as usize)
    }

    #[test]
    fn nt_create_wait_completion_packet_returns_non_null_encoded_handle() {
        init_platform();
        let task = crate::tests::test_task();
        let mut handle = Handle::from_raw(usize::MAX);

        assert_eq!(
            task.handle_nt_create_wait_completion_packet(mut_ptr(&mut handle), 0x1f0003, None,),
            NtStatus::SUCCESS
        );
        assert_eq!(handle, Handle::from_raw_fd(0).unwrap());
        assert_ne!(handle.as_raw(), 0);
        assert!(
            task.process
                .handles
                .read()
                .fd_from_raw_integer::<WaitCompletionPacketSubsystem>(handle.raw_fd().unwrap())
                .is_ok()
        );
    }

    #[test]
    fn nt_create_wait_completion_packet_accepts_unnamed_object_attributes() {
        init_platform();
        let task = crate::tests::test_task();
        let mut handle = Handle::from_raw(usize::MAX);
        let object_attributes = ObjectAttributes {
            length: u32::try_from(core::mem::size_of::<ObjectAttributes>()).unwrap(),
            root_directory: Handle::default(),
            object_name: 0,
            attributes: 0,
            security_descriptor: 0,
            security_quality_of_service: 0,
        };

        assert_eq!(
            task.handle_nt_create_wait_completion_packet(
                mut_ptr(&mut handle),
                0,
                Some(const_ptr(&object_attributes)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(handle, Handle::from_raw_fd(0).unwrap());
    }

    #[test]
    fn nt_close_removes_wait_completion_packet_handle() {
        let task = crate::tests::test_task();
        let mut handle = Handle::from_raw(0);

        assert_eq!(
            task.handle_nt_create_wait_completion_packet(mut_ptr(&mut handle), 0, None,),
            NtStatus::SUCCESS
        );
        assert_eq!(task.handle_nt_close(handle), NtStatus::SUCCESS);
        assert_eq!(task.handle_nt_close(handle), NtStatus::INVALID_HANDLE);
    }
}
