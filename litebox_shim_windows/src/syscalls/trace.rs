// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

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
}
