// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! NT LPC/ALPC syscall handlers.

use litebox_common_windows::nt_types::{PortMessage, PortView, RemotePortView, UnicodeString};
use litebox_common_windows::ntstatus::NtStatus;

use crate::handle_table::{HandleTable, NtObject};
use crate::{
    NtSharedState, is_addr_range_committed, is_addr_range_writable, try_read_guest_value_unaligned,
    try_write_guest_value_unaligned,
};

use super::NtSyscallArgs;

const CSR_API_NUMBER_OFFSET: usize = 0x30;
const CSR_API_STATUS_OFFSET: usize = 0x34;
const CSR_CLIENT_CONNECT_SERVER_ID_OFFSET: usize = 0x40;
const CSR_CLIENT_CONNECT_INFO_PTR_OFFSET: usize = 0x48;
const CSR_CLIENT_CONNECT_INFO_LEN_OFFSET: usize = 0x50;
const CSRSRV_SERVER_DLL_INDEX: u32 = 0;
const USER_SERVER_DLL_INDEX: u32 = 3;
const CSR_CONNECT_MAX_MESSAGE_LENGTH: u32 = 0x3B8;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CsrApiConnectInfoX64 {
    shared_section_base: u64,
    shared_static_server_data: u64,
    server_process_id: u64,
    reserved: u64,
    server_id: u32,
    server_to_server_call: u32,
    connection_info: u64,
}

pub(crate) fn nt_connect_port(
    ctx: &mut crate::ExecutionContext,
    handles: &mut HandleTable,
    shared: &NtSharedState,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let port_handle_out_ptr = args.arg0;
    let port_name_ptr = args.arg1;
    let client_view_ptr = args.arg3;
    let server_view_ptr = NtSyscallArgs::arg4(ctx);
    let max_message_length_ptr = NtSyscallArgs::arg5(ctx);
    let connection_information_ptr = NtSyscallArgs::arg6(ctx);
    let connection_information_length_ptr = NtSyscallArgs::arg7(ctx);

    if port_handle_out_ptr == 0 || port_name_ptr == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    let Some(port_name) = read_guest_unicode_string_lossy(port_name_ptr) else {
        return NtStatus::STATUS_INVALID_PARAMETER;
    };
    if !port_name.ends_with("ApiPort") {
        return NtStatus::STATUS_OBJECT_NAME_NOT_FOUND;
    }

    #[cfg(debug_assertions)]
    let mut mapped_view = None;
    if client_view_ptr != 0 {
        let mut client_view = match try_read_guest_value_unaligned::<PortView>(client_view_ptr) {
            Some(view) => view,
            None => return NtStatus::STATUS_INVALID_PARAMETER,
        };
        let section_handle = client_view.section_handle as u32;
        let max_size = match handles.with(section_handle, |entry| match &entry.object {
            NtObject::DataSection { max_size } => Some(*max_size as usize),
            _ => None,
        }).flatten() {
            Some(v) => v,
            None => return NtStatus::STATUS_INVALID_HANDLE,
        };
        let requested_size = if client_view.view_size == 0 {
            max_size
        } else {
            core::cmp::min(client_view.view_size as usize, max_size)
        };
        let (mapped_base, mapped_size) = match super::section::map_data_section_pages(
            &shared.process_state,
            client_view.view_base as usize,
            requested_size,
        ) {
            Ok(mapped) => mapped,
            Err(status) => return status,
        };
        client_view.view_base = mapped_base as u64;
        client_view.view_remote_base = mapped_base as u64;
        client_view.view_size = mapped_size as u64;
        if !try_write_guest_value_unaligned(client_view_ptr, client_view) {
            return NtStatus::STATUS_INVALID_PARAMETER;
        }

        if server_view_ptr != 0 {
            let mut server_view = try_read_guest_value_unaligned::<RemotePortView>(server_view_ptr)
                .unwrap_or_default();
            server_view.length = core::mem::size_of::<RemotePortView>() as u32;
            server_view.view_size = mapped_size as u64;
            server_view.view_base = mapped_base as u64;
            if !try_write_guest_value_unaligned(server_view_ptr, server_view) {
                return NtStatus::STATUS_INVALID_PARAMETER;
            }
        }

        #[cfg(debug_assertions)]
        {
            mapped_view = Some((mapped_base, mapped_size));
        }
    }

    if max_message_length_ptr != 0
        && !try_write_guest_value_unaligned(max_message_length_ptr, CSR_CONNECT_MAX_MESSAGE_LENGTH)
    {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    if connection_information_ptr != 0 || connection_information_length_ptr != 0 {
        if let Err(status) = write_connect_info(
            shared,
            connection_information_ptr,
            connection_information_length_ptr,
        ) {
            return status;
        }
    }

    let port_handle = handles.insert(NtObject::Stub {
        kind: alloc::string::String::from("CsrApiPort"),
        io_completion: None,
    });
    if !try_write_guest_value_unaligned(port_handle_out_ptr, port_handle as u64) {
        let _ = handles.close(port_handle);
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        let view_desc = mapped_view.map_or_else(
            || alloc::string::String::from("none"),
            |(base, size)| alloc::format!("0x{base:X}+0x{size:X}"),
        );
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: NtConnectPort name=\"{port_name}\" -> handle=0x{port_handle:X} view={view_desc}\n",
        ));
    }

    NtStatus::STATUS_SUCCESS
}

pub(crate) fn nt_alpc_send_wait_receive_port(
    ctx: &mut crate::ExecutionContext,
    handles: &HandleTable,
    shared: &NtSharedState,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let is_csr_port = handles.with(args.arg0 as u32, |entry| {
        matches!(&entry.object, NtObject::Stub { kind, .. } if kind == "CsrApiPort")
    }).unwrap_or(false);
    if !is_csr_port {
        return NtStatus::STATUS_INVALID_HANDLE;
    }

    let send_message_ptr = args.arg2;
    let receive_message_ptr = NtSyscallArgs::arg4(ctx);
    let reply_ptr = if receive_message_ptr != 0 {
        receive_message_ptr
    } else {
        send_message_ptr
    };

    let api_number =
        try_read_guest_value_unaligned::<u32>(send_message_ptr + CSR_API_NUMBER_OFFSET)
            .unwrap_or(0);
    let server_id = api_number >> 16;
    let api_id = api_number & 0xFFFF;
    let api_status = if server_id == CSRSRV_SERVER_DLL_INDEX {
        NtStatus::STATUS_SUCCESS
    } else {
        // BASESRV (server_id=1) api_id=29 is BaseSrvCreateProcess, called by
        // CreateProcessInternalW after NtCreateUserProcess.  Return SUCCESS
        // for this specific call so the process creation completes.
        // All other non-CSRSRV APIs continue to get STATUS_NOT_IMPLEMENTED
        // which the callers typically handle gracefully (e.g. loader DLL
        // notification calls like api_id=30 BaseSrvNotifyDllLoad).
        if server_id == 1 && api_id == 29 {
            NtStatus::STATUS_SUCCESS
        } else {
            NtStatus::STATUS_NOT_IMPLEMENTED
        }
    };

    if send_message_ptr != 0
        && reply_ptr != 0
        && reply_ptr != send_message_ptr
        && let Some(message) = try_read_guest_value_unaligned::<PortMessage>(send_message_ptr)
    {
        let total_length = usize::from(message.total_length);
        let receive_length_ptr = NtSyscallArgs::arg5(ctx);
        let receive_capacity = if receive_length_ptr != 0 {
            try_read_guest_value_unaligned::<usize>(receive_length_ptr).unwrap_or(total_length)
        } else {
            total_length
        };
        let copy_len = core::cmp::min(total_length, receive_capacity);
        if copy_len != 0
            && is_addr_range_committed(send_message_ptr, copy_len)
            && is_addr_range_committed(reply_ptr, copy_len)
        {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    send_message_ptr as *const u8,
                    reply_ptr as *mut u8,
                    copy_len,
                );
            }
        }
    }

    if !try_write_guest_value_unaligned(reply_ptr + CSR_API_STATUS_OFFSET, api_status.0) {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }
    if api_status.is_success()
        && server_id == CSRSRV_SERVER_DLL_INDEX
        && api_id == 0
        && let Err(status) = populate_client_connect_reply(shared, reply_ptr)
    {
        return status;
    }

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        let total_length = try_read_guest_value_unaligned::<u16>(send_message_ptr + 2).unwrap_or(0);
        let data_length = try_read_guest_value_unaligned::<u16>(send_message_ptr).unwrap_or(0);
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: NtAlpcSendWaitReceivePort api=0x{api_number:X} server={} api_id={} total=0x{total_length:X} data=0x{data_length:X} -> status=0x{:X}\n",
            server_id,
            api_id,
            api_status.0 as u32,
        ));
    }
    #[cfg(feature = "trace_debug")]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: NtAlpcSendWaitReceivePort api=0x{api_number:X} server={server_id} api_id={api_id} -> csr_status=0x{:X}\n",
            api_status.0 as u32,
        ));
    }

    NtStatus::STATUS_SUCCESS
}

fn populate_client_connect_reply(shared: &NtSharedState, reply_ptr: usize) -> Result<(), NtStatus> {
    let server_dll_index =
        try_read_guest_value_unaligned::<u32>(reply_ptr + CSR_CLIENT_CONNECT_SERVER_ID_OFFSET)
            .unwrap_or(0);
    let conn_info_ptr =
        try_read_guest_value_unaligned::<u64>(reply_ptr + CSR_CLIENT_CONNECT_INFO_PTR_OFFSET)
            .unwrap_or(0) as usize;
    let conn_info_len =
        try_read_guest_value_unaligned::<u32>(reply_ptr + CSR_CLIENT_CONNECT_INFO_LEN_OFFSET)
            .unwrap_or(0) as usize;
    if conn_info_ptr == 0 || conn_info_len == 0 {
        return Ok(());
    }

    let buf_size = core::cmp::min(conn_info_len, 0x1000);
    if !is_addr_range_writable(conn_info_ptr, buf_size) {
        return Err(NtStatus::STATUS_INVALID_PARAMETER);
    }
    unsafe {
        core::ptr::write_bytes(conn_info_ptr as *mut u8, 0, buf_size);
    }

    if server_dll_index == USER_SERVER_DLL_INDEX && buf_size >= 0x10 {
        let server_info_va = shared.process_state.alloc_rw_bytes(crate::PAGE_SIZE);
        if server_info_va == 0 {
            return Err(NtStatus::STATUS_NO_MEMORY);
        }

        if !try_write_guest_value_unaligned::<u32>(server_info_va, 0x0D10)
            || !try_write_guest_value_unaligned::<u64>(conn_info_ptr + 0x08, server_info_va as u64)
        {
            return Err(NtStatus::STATUS_ACCESS_VIOLATION);
        }

        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: CsrpClientConnect(USER) -> SERVERINFO at 0x{server_info_va:X}, buf=0x{conn_info_ptr:X}, len=0x{buf_size:X}\n",
            ));
        }
    }

    Ok(())
}

fn write_connect_info(
    shared: &NtSharedState,
    connection_information_ptr: usize,
    connection_information_length_ptr: usize,
) -> Result<(), NtStatus> {
    const CONNECT_INFO_SIZE: usize = core::mem::size_of::<CsrApiConnectInfoX64>();

    let info_len = if connection_information_length_ptr != 0 {
        try_read_guest_value_unaligned::<u32>(connection_information_length_ptr).unwrap_or(0)
            as usize
    } else {
        0
    };
    if connection_information_ptr == 0
        || connection_information_length_ptr == 0
        || info_len < CONNECT_INFO_SIZE
    {
        return Err(NtStatus::STATUS_INVALID_PARAMETER);
    }

    let prior_connection_info =
        try_read_guest_value_unaligned::<u64>(connection_information_ptr + 0x28).unwrap_or(0);
    let csr = *shared.csr_state.lock();
    let connect_info = CsrApiConnectInfoX64 {
        shared_section_base: csr.shared_section_base as u64,
        shared_static_server_data: csr.shared_static_server_data as u64,
        server_process_id: csr.server_process_id as u64,
        reserved: 0,
        server_id: 1,
        server_to_server_call: 0,
        connection_info: prior_connection_info,
    };

    if !try_write_guest_value_unaligned(connection_information_ptr, connect_info)
        || !try_write_guest_value_unaligned(
            connection_information_length_ptr,
            CONNECT_INFO_SIZE as u32,
        )
    {
        return Err(NtStatus::STATUS_INVALID_PARAMETER);
    }
    Ok(())
}

fn read_guest_unicode_string_lossy(ptr: usize) -> Option<alloc::string::String> {
    let unicode = try_read_guest_value_unaligned::<UnicodeString>(ptr)?;
    let len = usize::from(unicode.length);
    let buf = unicode.buffer as usize;
    if buf == 0 || len == 0 || len % 2 != 0 || !is_addr_range_committed(buf, len) {
        return None;
    }
    let chars = unsafe { core::slice::from_raw_parts(buf as *const u16, len / 2) };
    Some(alloc::string::String::from_utf16_lossy(chars))
}
