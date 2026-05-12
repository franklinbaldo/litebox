// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use int_enum::IntEnum;
use litebox::LiteBox;
use litebox::event::{Events, IOPollable, observer::Observer, polling::Pollee};
use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _, TimeProvider};
use litebox::sync::RawSyncPrimitivesProvider;
use litebox_common_windows::nt_status::NtStatus;
use litebox_platform_multiplex::Platform;
use zerocopy::{FromBytes, Immutable};

use crate::{Handle, WindowsHandleStore, insert_raw_handle, remove_raw_handle};

// See <https://ntdoc.m417z.com/object_attributes> for more details
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable)]
pub(crate) struct ObjectAttributes {
    length: u32,
    root_directory: usize,
    object_name: usize,
    attributes: u32,
    security_descriptor: usize,
    security_quality_of_service: usize,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, IntEnum)]
enum EventType {
    Notification = 0,
    Synchronization = 1,
}

pub(crate) struct EventSubsystem;

impl FdEnabledSubsystem for EventSubsystem {
    type Entry = EventObject<Platform>;
}

impl FdEnabledSubsystemEntry for EventObject<Platform> {}

pub(crate) struct EventObject<P: RawSyncPrimitivesProvider + TimeProvider> {
    event_type: EventType,
    signaled: litebox::sync::Mutex<P, bool>,
    pollee: Pollee<P>,
}

impl<P: RawSyncPrimitivesProvider + TimeProvider> EventObject<P> {
    fn new(event_type: EventType, initial_state: bool) -> Self {
        Self {
            event_type,
            signaled: litebox::sync::Mutex::new(initial_state),
            pollee: Pollee::new(),
        }
    }
}

impl<P: RawSyncPrimitivesProvider + TimeProvider> IOPollable for EventObject<P> {
    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.pollee.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        let signaled = *self.signaled.lock();
        if !signaled {
            return Events::empty();
        }

        Events::IN
    }
}

pub(crate) fn handle_nt_create_event(
    litebox: &LiteBox<Platform>,
    handles: &WindowsHandleStore,
    event_handle: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<Handle>,
    desired_access: u32,
    object_attributes: Option<
        <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<ObjectAttributes>,
    >,
    event_type: u32,
    initial_state: u8,
) -> NtStatus {
    let Ok(event_type) = EventType::try_from(event_type) else {
        return NtStatus::INVALID_PARAMETER;
    };

    if let Some(object_attributes) = object_attributes {
        let Some(object_attributes) = object_attributes.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        if object_attributes.length as usize != core::mem::size_of::<ObjectAttributes>() {
            return NtStatus::INVALID_PARAMETER;
        }
        if object_attributes.root_directory != 0 || object_attributes.object_name != 0 {
            litebox_util_log::warn!(
                root_directory = object_attributes.root_directory,
                object_name = object_attributes.object_name;
                "NtCreateEvent: root_directory and object_name are not supported"
            );
            return NtStatus::NOT_IMPLEMENTED;
        }
    }

    let event = EventObject::new(event_type, initial_state != 0);
    let mut descriptor_table = litebox.descriptor_table_mut();
    let typed = descriptor_table.insert::<EventSubsystem>(event);
    drop(descriptor_table);
    let handle = match insert_raw_handle(litebox, handles, typed) {
        Ok(handle) => handle,
        Err(status) => return status,
    };

    if event_handle.write_at_offset(0, handle).is_none() {
        remove_raw_handle::<EventSubsystem>(litebox, handles, handle);
        return NtStatus::ACCESS_VIOLATION;
    }

    litebox_util_log::debug!(
        handle:% = format_args!("{:#x}", handle.as_raw()),
        desired_access:% = format_args!("{desired_access:#x}"),
        event_type:? = event_type,
        initial_state = initial_state != 0;
        "Handled NtCreateEvent syscall"
    );

    NtStatus::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox::fd::RawDescriptorStorage;
    use litebox::platform::RawPointerProvider;
    use zerocopy::IntoBytes;

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

    fn test_context() -> (LiteBox<Platform>, WindowsHandleStore) {
        init_platform();
        (
            LiteBox::new(litebox_platform_multiplex::platform()),
            WindowsHandleStore::new(RawDescriptorStorage::new()),
        )
    }

    #[test]
    fn nt_create_event_returns_non_null_encoded_handle() {
        let (litebox, handles) = test_context();
        let mut handle = Handle::from_raw(usize::MAX);

        assert_eq!(
            handle_nt_create_event(
                &litebox,
                &handles,
                mut_ptr(&mut handle),
                0x1f0003,
                None,
                EventType::Notification.into(),
                1,
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(handle, Handle::from_raw_fd(0).unwrap());
        assert_ne!(handle.as_raw(), 0);
        assert!(
            handles
                .read()
                .fd_from_raw_integer::<EventSubsystem>(handle.raw_fd().unwrap())
                .is_ok()
        );
    }

    #[test]
    fn nt_create_event_accepts_unnamed_object_attributes() {
        let (litebox, handles) = test_context();
        let mut handle = Handle::from_raw(usize::MAX);
        let object_attributes = ObjectAttributes {
            length: u32::try_from(core::mem::size_of::<ObjectAttributes>()).unwrap(),
            root_directory: 0,
            object_name: 0,
            attributes: 0,
            security_descriptor: 0,
            security_quality_of_service: 0,
        };

        assert_eq!(
            handle_nt_create_event(
                &litebox,
                &handles,
                mut_ptr(&mut handle),
                0,
                Some(const_ptr(&object_attributes)),
                EventType::Synchronization.into(),
                0,
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(handle, Handle::from_raw_fd(0).unwrap());
    }

    #[test]
    fn nt_create_event_rejects_invalid_event_type() {
        let (litebox, handles) = test_context();
        let mut handle = Handle::from_raw(usize::MAX);

        assert_eq!(
            handle_nt_create_event(&litebox, &handles, mut_ptr(&mut handle), 0, None, 2, 0),
            NtStatus::INVALID_PARAMETER
        );
        assert_eq!(handle, Handle::from_raw(usize::MAX));
        assert!(handles.read().iter_alive().next().is_none());
    }
}
