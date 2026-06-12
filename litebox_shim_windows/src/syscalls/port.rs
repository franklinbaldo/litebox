//! Windows NT LPC/ALPC port syscalls.

use core::marker::PhantomData;
use core::mem::size_of;

use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::nt_types::{
    PortMessage, PortView, ProcessEnvironmentBlock, RemotePortView, UnicodeString,
};
use crate::syscalls::Handle;
use crate::{
    ConstPtr, MutPtr, ShimFS, ShimPlatform, Task, insert_raw_handle, raw_handle_entry,
    remove_raw_handle,
};

const CSR_CONNECT_MAX_MESSAGE_LENGTH: u32 = 0x3b8;
const CSR_API_MESSAGE_STATUS_OFFSET: usize = 0x34;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PortKind {
    CsrApi,
}

pub(crate) struct PortSubsystem<Platform>(PhantomData<fn(Platform)>);

impl<Platform: ShimPlatform> FdEnabledSubsystem for PortSubsystem<Platform> {
    type Entry = PortHandleObject;
}

impl FdEnabledSubsystemEntry for PortHandleObject {}

pub(crate) struct PortHandleObject {
    _kind: PortKind,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable)]
pub(crate) struct CsrApiConnectInfoX64 {
    shared_section_base: u64,
    shared_static_server_data: u64,
    server_process_id: u64,
    reserved: u64,
    server_id: u32,
    server_to_server_call: u32,
    connection_info: u64,
}

pub(crate) struct ConnectPortParameters<Platform: ShimPlatform> {
    pub(crate) port_handle: MutPtr<Platform, Handle>,
    pub(crate) port_name: ConstPtr<Platform, UnicodeString>,
    pub(crate) security_quality_of_service: Option<ConstPtr<Platform, u8>>,
    pub(crate) client_view: Option<MutPtr<Platform, PortView>>,
    pub(crate) server_view: Option<MutPtr<Platform, RemotePortView>>,
    pub(crate) max_message_length: Option<MutPtr<Platform, u32>>,
    pub(crate) connection_information: Option<MutPtr<Platform, CsrApiConnectInfoX64>>,
    pub(crate) connection_information_length: Option<MutPtr<Platform, u32>>,
}

pub(crate) struct AlpcSendWaitReceivePortParameters<Platform: ShimPlatform> {
    pub(crate) port_handle: Handle,
    pub(crate) flags: u32,
    pub(crate) send_message: Option<ConstPtr<Platform, PortMessage>>,
    pub(crate) send_message_attributes: Option<ConstPtr<Platform, u8>>,
    pub(crate) receive_message: Option<MutPtr<Platform, PortMessage>>,
    pub(crate) buffer_length: Option<MutPtr<Platform, u32>>,
    pub(crate) receive_message_attributes: Option<MutPtr<Platform, u8>>,
    pub(crate) timeout: Option<ConstPtr<Platform, i64>>,
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    fn port_entry(
        &self,
        handle: Handle,
    ) -> Result<litebox::fd::EntryHandle<Platform, PortSubsystem<Platform>>, NtStatus> {
        raw_handle_entry::<Platform, PortSubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            handle,
        )
        .ok_or(NtStatus::INVALID_HANDLE)
    }

    fn insert_port_handle(&self, kind: PortKind) -> Result<Handle, NtStatus> {
        let typed = self
            .global
            .litebox
            .descriptor_table_mut()
            .insert::<PortSubsystem<Platform>>(PortHandleObject { _kind: kind });
        insert_raw_handle::<Platform, PortSubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            typed,
            drop,
        )
    }

    pub(crate) fn close_port_handle(&self, handle: Handle) {
        remove_raw_handle::<Platform, PortSubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            handle,
            drop,
        );
    }

    pub(crate) fn close_port(port: PortHandleObject) {
        drop(port);
    }

    pub(crate) fn sys_nt_connect_port(&self, params: ConnectPortParameters<Platform>) -> NtStatus {
        if params.port_handle.as_usize() == 0 || params.port_name.as_usize() == 0 {
            return NtStatus::INVALID_PARAMETER;
        }
        let _ = params.security_quality_of_service;

        let port_name = match params
            .port_name
            .read_at_offset(0)
            .ok_or(NtStatus::ACCESS_VIOLATION)
            .and_then(UnicodeString::read_string::<Platform>)
        {
            Ok(port_name) => port_name,
            Err(status) => return status,
        };
        if !port_name.ends_with("ApiPort") {
            return NtStatus::OBJECT_NAME_NOT_FOUND;
        }

        if let Some(client_view) = params.client_view
            && let Err(status) = self.populate_client_view(client_view, params.server_view)
        {
            return status;
        }

        if let Some(max_message_length) = params.max_message_length
            && max_message_length
                .write_at_offset(0, CSR_CONNECT_MAX_MESSAGE_LENGTH)
                .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }

        if params.connection_information.is_some() || params.connection_information_length.is_some()
        {
            match (
                params.connection_information,
                params.connection_information_length,
            ) {
                (Some(connection_information), Some(connection_information_length)) => {
                    if let Err(status) = self
                        .write_connect_info(connection_information, connection_information_length)
                    {
                        return status;
                    }
                }
                _ => return NtStatus::INVALID_PARAMETER,
            }
        }

        let handle = match self.insert_port_handle(PortKind::CsrApi) {
            Ok(handle) => handle,
            Err(status) => return status,
        };
        if params.port_handle.write_at_offset(0, handle).is_none() {
            self.close_port_handle(handle);
            return NtStatus::ACCESS_VIOLATION;
        }

        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_alpc_send_wait_receive_port(
        &self,
        params: AlpcSendWaitReceivePortParameters<Platform>,
    ) -> NtStatus {
        if self.port_entry(params.port_handle).is_err() {
            return NtStatus::INVALID_HANDLE;
        }

        let _ = params.send_message_attributes;
        let _ = params.receive_message_attributes;
        let _ = params.timeout;
        let _ = params.flags;

        let send_message = match params.send_message {
            Some(send_message) => match send_message.read_at_offset(0) {
                Some(message) => Some(message),
                None => return NtStatus::ACCESS_VIOLATION,
            },
            None => None,
        };

        if let Some(receive_message) = params.receive_message {
            let reply = send_message.unwrap_or_default();
            let required_length = u32::from(reply.total_length);
            if let Some(buffer_length) = params.buffer_length {
                let available_length = match buffer_length.read_at_offset(0) {
                    Some(length) => length,
                    None => return NtStatus::ACCESS_VIOLATION,
                };
                if buffer_length.write_at_offset(0, required_length).is_none() {
                    return NtStatus::ACCESS_VIOLATION;
                }
                if available_length < required_length {
                    return NtStatus::BUFFER_TOO_SMALL;
                }
            }

            let status = MutPtr::<Platform, u32>::from_usize(
                receive_message.as_usize() + CSR_API_MESSAGE_STATUS_OFFSET,
            );
            if receive_message.write_at_offset(0, reply).is_none()
                || status
                    .write_at_offset(0, NtStatus::SUCCESS.as_raw().cast_unsigned())
                    .is_none()
            {
                return NtStatus::ACCESS_VIOLATION;
            }
        }

        NtStatus::SUCCESS
    }

    fn populate_client_view(
        &self,
        client_view: MutPtr<Platform, PortView>,
        server_view: Option<MutPtr<Platform, RemotePortView>>,
    ) -> Result<(), NtStatus> {
        let mut view = client_view
            .read_at_offset(0)
            .ok_or(NtStatus::ACCESS_VIOLATION)?;
        let section_handle = Handle::from_raw(view.section_handle as usize);
        let requested_size = view.view_size.try_into().unwrap_or(usize::MAX);
        let (mapped_base, mapped_size) =
            self.map_port_section_view(section_handle, requested_size)?;

        view.view_base = mapped_base as u64;
        view.view_remote_base = mapped_base as u64;
        view.view_size = mapped_size as u64;
        if client_view.write_at_offset(0, view).is_none() {
            return Err(NtStatus::ACCESS_VIOLATION);
        }

        if let Some(server_view) = server_view {
            let view = RemotePortView {
                length: size_of::<RemotePortView>() as u32,
                view_size: mapped_size as u64,
                view_base: mapped_base as u64,
                ..RemotePortView::default()
            };
            if server_view.write_at_offset(0, view).is_none() {
                return Err(NtStatus::ACCESS_VIOLATION);
            }
        }
        Ok(())
    }

    fn write_connect_info(
        &self,
        connection_information: MutPtr<Platform, CsrApiConnectInfoX64>,
        connection_information_length: MutPtr<Platform, u32>,
    ) -> Result<(), NtStatus> {
        let info_len = connection_information_length
            .read_at_offset(0)
            .ok_or(NtStatus::ACCESS_VIOLATION)? as usize;
        if info_len < size_of::<CsrApiConnectInfoX64>() {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let prior_connection_info = connection_information
            .read_at_offset(0)
            .map_or(0, |info| info.connection_info);
        let peb =
            ConstPtr::<Platform, ProcessEnvironmentBlock>::from_usize(self.process.peb_address)
                .read_at_offset(0)
                .ok_or(NtStatus::ACCESS_VIOLATION)?;
        let connect_info = CsrApiConnectInfoX64 {
            shared_section_base: peb.csr_server_read_only_shared_memory_base,
            shared_static_server_data: peb.read_only_static_server_data as u64,
            server_process_id: 4,
            reserved: 0,
            server_id: 1,
            server_to_server_call: 0,
            connection_info: prior_connection_info,
        };
        if connection_information
            .write_at_offset(0, connect_info)
            .is_none()
            || connection_information_length
                .write_at_offset(0, size_of::<CsrApiConnectInfoX64>() as u32)
                .is_none()
        {
            return Err(NtStatus::ACCESS_VIOLATION);
        }
        Ok(())
    }
}
