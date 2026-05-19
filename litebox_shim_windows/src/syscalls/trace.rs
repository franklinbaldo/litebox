// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox::platform::RawMutPointer as _;
use litebox_common_windows::nt_status::NtStatus;
use litebox_platform_multiplex::Platform;

use crate::Handle;

pub(crate) fn handle_nt_trace_event(
    trace_handle: Handle,
    flags: u32,
    field_size: u32,
    fields: Option<<Platform as litebox::platform::RawPointerProvider>::RawConstPointer<u8>>,
) -> NtStatus {
    litebox_util_log::debug!(
        trace_handle:% = format_args!("{:#x}", trace_handle.as_raw()),
        flags:% = format_args!("{flags:#x}"),
        field_size = field_size,
        has_fields = fields.is_some();
        "Handled NtTraceEvent syscall as a local trace sink"
    );

    NtStatus::SUCCESS
}

pub(crate) fn handle_nt_trace_control(
    control_code: u32,
    input_buffer: Option<<Platform as litebox::platform::RawPointerProvider>::RawConstPointer<u8>>,
    input_buffer_size: u32,
    output_buffer: Option<<Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u8>>,
    output_buffer_size: u32,
    return_length: Option<<Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u32>>,
) -> NtStatus {
    if let Some(return_length) = return_length {
        if return_length.write_at_offset(0, 0).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }
    }

    litebox_util_log::debug!(
        control_code:% = format_args!("{control_code:#x}"),
        input_buffer_size = input_buffer_size,
        output_buffer_size = output_buffer_size,
        has_input_buffer = input_buffer.is_some(),
        has_output_buffer = output_buffer.is_some(),
        has_return_length = return_length.is_some();
        "Handled NtTraceControl syscall as a local trace control sink"
    );

    NtStatus::SUCCESS
}

pub(crate) fn handle_nt_query_debug_filter_state(component_id: u32, level: u32) -> NtStatus {
    litebox_util_log::debug!(
        component_id,
        level;
        "Handled NtQueryDebugFilterState syscall as disabled debug filtering"
    );

    NtStatus::NOT_IMPLEMENTED
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox::platform::RawConstPointer as _;

    #[test]
    fn nt_trace_event_accepts_trace_payload_without_reading_it() {
        crate::tests::init_platform();
        let fields =
            <Platform as litebox::platform::RawPointerProvider>::RawConstPointer::<u8>::from_usize(
                usize::MAX,
            );

        assert_eq!(
            handle_nt_trace_event(Handle::from_raw(0), 0, 1, Some(fields)),
            NtStatus::SUCCESS
        );
    }

    #[test]
    fn nt_trace_control_reports_zero_output_length() {
        crate::tests::init_platform();
        let mut return_length = u32::MAX;

        assert_eq!(
            handle_nt_trace_control(
                0,
                None,
                0,
                None,
                0,
                Some(<Platform as litebox::platform::RawPointerProvider>::RawMutPointer::<
                    u32,
                >::from_ptr(core::ptr::from_mut(&mut return_length))),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(return_length, 0);
    }
}
