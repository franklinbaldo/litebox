// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox::platform::{RawMutPointer as _, RawPointerProvider};
use litebox_common_windows::nt_status::NtStatus;
use litebox_platform_multiplex::Platform;

const RESPONSE_RETURN_TO_CALLER: u32 = 0;

pub(crate) fn handle_nt_raise_hard_error(
    error_status: NtStatus,
    number_of_parameters: u32,
    unicode_string_parameter_mask: u32,
    parameters: Option<<Platform as RawPointerProvider>::RawConstPointer<usize>>,
    valid_response_options: u32,
    response: <Platform as RawPointerProvider>::RawMutPointer<u32>,
) -> NtStatus {
    litebox_util_log::debug!(
        error_status:% = format_args!("{:#x}", error_status.as_raw().cast_unsigned()),
        number_of_parameters = number_of_parameters,
        unicode_string_parameter_mask:% = format_args!("{unicode_string_parameter_mask:#x}"),
        has_parameters = parameters.is_some(),
        valid_response_options = valid_response_options;
        "Handled NtRaiseHardError syscall as a local hard-error sink"
    );

    response
        .write_at_offset(0, RESPONSE_RETURN_TO_CALLER)
        .map_or(NtStatus::ACCESS_VIOLATION, |()| NtStatus::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox::platform::RawConstPointer as _;
    use zerocopy::{FromBytes, IntoBytes};

    type MutPtr<T> = <Platform as RawPointerProvider>::RawMutPointer<T>;

    fn mut_ptr<T: FromBytes + IntoBytes>(value: &mut T) -> MutPtr<T> {
        MutPtr::from_usize(core::ptr::from_mut(value).cast::<u8>() as usize)
    }

    #[test]
    fn nt_raise_hard_error_returns_to_caller() {
        crate::tests::init_platform();
        let mut response = u32::MAX;

        assert_eq!(
            handle_nt_raise_hard_error(
                NtStatus::ACCESS_VIOLATION,
                0,
                0,
                None,
                1,
                mut_ptr(&mut response),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(response, RESPONSE_RETURN_TO_CALLER);
    }

    #[test]
    fn nt_raise_hard_error_does_not_read_parameters() {
        crate::tests::init_platform();
        let mut response = u32::MAX;
        let parameters =
            <Platform as RawPointerProvider>::RawConstPointer::<usize>::from_usize(usize::MAX);

        assert_eq!(
            handle_nt_raise_hard_error(
                NtStatus::INVALID_PARAMETER,
                1,
                0,
                Some(parameters),
                1,
                mut_ptr(&mut response),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(response, RESPONSE_RETURN_TO_CALLER);
    }
}
