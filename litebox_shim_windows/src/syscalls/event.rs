// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use int_enum::IntEnum;
use litebox::LiteBox;
use litebox::event::{Events, IOPollable, observer::Observer, polling::Pollee};
use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::platform::{RawMutPointer as _, TimeProvider};
use litebox::sync::RawSyncPrimitivesProvider;
use litebox_common_windows::nt_status::NtStatus;
use litebox_platform_multiplex::Platform;

use crate::{Handle, WindowsHandleStore, insert_raw_handle, raw_handle_entry, remove_raw_handle};

use super::object::{ObjectAttributes, read_object_attributes};

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
    #[expect(dead_code)]
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

    fn clear(&self) -> bool {
        let mut signaled = self.signaled.lock();
        let previous = *signaled;
        *signaled = false;
        previous
    }

    fn set(&self) -> bool {
        let mut signaled = self.signaled.lock();
        let previous = *signaled;
        *signaled = true;
        drop(signaled);
        if !previous {
            self.pollee.notify_observers(Events::IN);
        }
        previous
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
    _loader_tls_initialized: bool,
) -> NtStatus {
    let Ok(event_type) = EventType::try_from(event_type) else {
        return NtStatus::INVALID_PARAMETER;
    };

    if let Some(object_attributes) = object_attributes {
        let object_attributes = match read_object_attributes(object_attributes) {
            Ok(object_attributes) => object_attributes,
            Err(status) => return status,
        };
        if !object_attributes.root_directory.is_null() || object_attributes.object_name != 0 {
            litebox_util_log::warn!(
                root_directory = object_attributes.root_directory.as_raw(),
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

pub(crate) fn handle_nt_clear_event(
    litebox: &LiteBox<Platform>,
    handles: &WindowsHandleStore,
    event_handle: Handle,
) -> NtStatus {
    let Some(event) = raw_handle_entry::<EventSubsystem>(litebox, handles, event_handle) else {
        return NtStatus::INVALID_HANDLE;
    };
    event.with_entry(EventObject::clear);

    litebox_util_log::debug!(
        handle:% = format_args!("{:#x}", event_handle.as_raw());
        "Handled NtClearEvent syscall"
    );

    NtStatus::SUCCESS
}

pub(crate) fn handle_nt_reset_event(
    litebox: &LiteBox<Platform>,
    handles: &WindowsHandleStore,
    event_handle: Handle,
    previous_state: Option<<Platform as litebox::platform::RawPointerProvider>::RawMutPointer<i32>>,
) -> NtStatus {
    let Some(event) = raw_handle_entry::<EventSubsystem>(litebox, handles, event_handle) else {
        return NtStatus::INVALID_HANDLE;
    };
    let was_signaled = event.with_entry(EventObject::clear);
    if let Some(previous_state) = previous_state
        && previous_state
            .write_at_offset(0, i32::from(was_signaled))
            .is_none()
    {
        return NtStatus::ACCESS_VIOLATION;
    }

    litebox_util_log::debug!(
        handle:% = format_args!("{:#x}", event_handle.as_raw()),
        previous_state = was_signaled;
        "Handled NtResetEvent syscall"
    );

    NtStatus::SUCCESS
}

pub(crate) fn handle_nt_set_event(
    litebox: &LiteBox<Platform>,
    handles: &WindowsHandleStore,
    event_handle: Handle,
    previous_state: Option<<Platform as litebox::platform::RawPointerProvider>::RawMutPointer<i32>>,
) -> NtStatus {
    let Some(event) = raw_handle_entry::<EventSubsystem>(litebox, handles, event_handle) else {
        return NtStatus::INVALID_HANDLE;
    };
    let was_signaled = event.with_entry(EventObject::set);
    if let Some(previous_state) = previous_state
        && previous_state
            .write_at_offset(0, i32::from(was_signaled))
            .is_none()
    {
        return NtStatus::ACCESS_VIOLATION;
    }

    litebox_util_log::debug!(
        handle:% = format_args!("{:#x}", event_handle.as_raw()),
        previous_state = was_signaled;
        "Handled NtSetEvent syscall"
    );

    NtStatus::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscalls::object::ObjectAttributes;
    use litebox::fd::RawDescriptorStorage;
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

    fn test_context() -> (LiteBox<Platform>, WindowsHandleStore) {
        init_platform();
        (
            LiteBox::new(litebox_platform_multiplex::platform()),
            WindowsHandleStore::new(RawDescriptorStorage::new()),
        )
    }

    fn create_test_event(
        litebox: &LiteBox<Platform>,
        handles: &WindowsHandleStore,
        initial_state: bool,
    ) -> Handle {
        let mut handle = Handle::from_raw(0);
        assert_eq!(
            handle_nt_create_event(
                litebox,
                handles,
                mut_ptr(&mut handle),
                0,
                None,
                EventType::Notification.into(),
                u8::from(initial_state),
                false,
            ),
            NtStatus::SUCCESS
        );
        handle
    }

    fn events_for_handle(
        litebox: &LiteBox<Platform>,
        handles: &WindowsHandleStore,
        handle: Handle,
    ) -> Events {
        raw_handle_entry::<EventSubsystem>(litebox, handles, handle)
            .unwrap()
            .with_entry(IOPollable::check_io_events)
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
                false,
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
            root_directory: Handle::default(),
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
                false,
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
            handle_nt_create_event(
                &litebox,
                &handles,
                mut_ptr(&mut handle),
                0,
                None,
                2,
                0,
                false
            ),
            NtStatus::INVALID_PARAMETER
        );
        assert_eq!(handle, Handle::from_raw(usize::MAX));
        assert!(handles.read().iter_alive().next().is_none());
    }

    #[test]
    fn nt_clear_event_clears_signaled_event() {
        let (litebox, handles) = test_context();
        let handle = create_test_event(&litebox, &handles, true);
        assert_eq!(events_for_handle(&litebox, &handles, handle), Events::IN);

        assert_eq!(
            handle_nt_clear_event(&litebox, &handles, handle),
            NtStatus::SUCCESS
        );
        assert!(events_for_handle(&litebox, &handles, handle).is_empty());
    }

    #[test]
    fn nt_reset_event_clears_and_returns_previous_state() {
        let (litebox, handles) = test_context();
        let handle = create_test_event(&litebox, &handles, true);
        let mut previous_state = -1;

        assert_eq!(
            handle_nt_reset_event(
                &litebox,
                &handles,
                handle,
                Some(mut_ptr(&mut previous_state)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(previous_state, 1);
        assert!(events_for_handle(&litebox, &handles, handle).is_empty());

        previous_state = -1;
        assert_eq!(
            handle_nt_reset_event(
                &litebox,
                &handles,
                handle,
                Some(mut_ptr(&mut previous_state)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(previous_state, 0);
    }

    #[test]
    fn nt_set_event_signals_and_returns_previous_state() {
        let (litebox, handles) = test_context();
        let handle = create_test_event(&litebox, &handles, false);
        let mut previous_state = -1;

        assert_eq!(
            handle_nt_set_event(
                &litebox,
                &handles,
                handle,
                Some(mut_ptr(&mut previous_state)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(previous_state, 0);
        assert_eq!(events_for_handle(&litebox, &handles, handle), Events::IN);

        previous_state = -1;
        assert_eq!(
            handle_nt_set_event(
                &litebox,
                &handles,
                handle,
                Some(mut_ptr(&mut previous_state)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(previous_state, 1);
    }

    #[test]
    fn nt_close_removes_event_handle() {
        let task = crate::tests::test_task();
        let handle = create_test_event(&task.global.litebox, &task.process.handles, false);

        assert_eq!(task.handle_nt_close(handle), NtStatus::SUCCESS);
        assert_eq!(
            handle_nt_set_event(&task.global.litebox, &task.process.handles, handle, None),
            NtStatus::INVALID_HANDLE
        );
        assert_eq!(task.handle_nt_close(handle), NtStatus::INVALID_HANDLE);
    }

    #[test]
    fn event_state_syscalls_reject_invalid_handles() {
        let (litebox, handles) = test_context();
        let invalid_handle = Handle::from_raw_fd(0).unwrap();
        let mut previous_state = -1;

        assert_eq!(
            handle_nt_clear_event(&litebox, &handles, invalid_handle),
            NtStatus::INVALID_HANDLE
        );
        assert_eq!(
            handle_nt_reset_event(
                &litebox,
                &handles,
                invalid_handle,
                Some(mut_ptr(&mut previous_state)),
            ),
            NtStatus::INVALID_HANDLE
        );
        assert_eq!(
            handle_nt_set_event(
                &litebox,
                &handles,
                invalid_handle,
                Some(mut_ptr(&mut previous_state)),
            ),
            NtStatus::INVALID_HANDLE
        );
        assert_eq!(previous_state, -1);
    }
}
