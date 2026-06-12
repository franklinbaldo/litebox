// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows Notification Facility syscalls.

use litebox::platform::{RawConstPointer as _, RawMutPointer as _, RawPointerProvider};
use litebox_common_windows::nt_status::NtStatus;

const WNF_BOOLEAN_INFORMATION_SIZE: u32 = size_of::<u32>() as u32;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WnfStateNameInformationClass {
    StateNameExist = 0,
    SubscribersPresent = 1,
    IsQuiescent = 2,
}

impl WnfStateNameInformationClass {
    fn from_raw(raw: u32) -> Result<Self, NtStatus> {
        match raw {
            0 => Ok(Self::StateNameExist),
            1 => Ok(Self::SubscribersPresent),
            2 => Ok(Self::IsQuiescent),
            _ => Err(NtStatus::INVALID_INFO_CLASS),
        }
    }
}

pub(crate) fn sys_nt_set_wnf_process_notification_event() -> NtStatus {
    NtStatus::SUCCESS
}

pub(crate) fn sys_nt_subscribe_wnf_state_change() -> NtStatus {
    NtStatus::SUCCESS
}

pub(crate) fn sys_nt_unsubscribe_wnf_state_change() -> NtStatus {
    NtStatus::SUCCESS
}

pub(crate) fn sys_nt_query_wnf_state_name_information<Platform: RawPointerProvider>(
    state_name: Option<Platform::RawConstPointer<u64>>,
    name_information_class: u32,
    _explicit_scope: Option<Platform::RawConstPointer<u8>>,
    buffer: Option<Platform::RawMutPointer<u32>>,
    buffer_length: u32,
) -> NtStatus {
    let Some(state_name) = state_name else {
        return NtStatus::INVALID_PARAMETER;
    };
    if state_name.read_at_offset(0).is_none() {
        return NtStatus::ACCESS_VIOLATION;
    }

    let Ok(information_class) = WnfStateNameInformationClass::from_raw(name_information_class)
    else {
        return NtStatus::INVALID_INFO_CLASS;
    };
    if buffer_length < WNF_BOOLEAN_INFORMATION_SIZE {
        return NtStatus::BUFFER_TOO_SMALL;
    }
    let Some(buffer) = buffer else {
        return NtStatus::ACCESS_VIOLATION;
    };

    let value = match information_class {
        WnfStateNameInformationClass::StateNameExist
        | WnfStateNameInformationClass::SubscribersPresent => 0u32,
        WnfStateNameInformationClass::IsQuiescent => 1u32,
    };
    buffer
        .write_at_offset(0, value)
        .map_or(NtStatus::ACCESS_VIOLATION, |()| NtStatus::SUCCESS)
}

pub(crate) fn sys_nt_query_wnf_state_data<Platform: RawPointerProvider>(
    state_name: Option<Platform::RawConstPointer<u64>>,
    _type_id: Option<Platform::RawConstPointer<u8>>,
    _explicit_scope: Option<Platform::RawConstPointer<u8>>,
    change_stamp: Option<Platform::RawMutPointer<u32>>,
    _buffer: Option<Platform::RawMutPointer<u8>>,
    buffer_length: Option<Platform::RawMutPointer<u32>>,
) -> NtStatus {
    let Some(state_name) = state_name else {
        return NtStatus::INVALID_PARAMETER;
    };
    if state_name.read_at_offset(0).is_none() {
        return NtStatus::ACCESS_VIOLATION;
    }
    let Some(buffer_length) = buffer_length else {
        return NtStatus::INVALID_PARAMETER;
    };
    if buffer_length.read_at_offset(0).is_none() {
        return NtStatus::ACCESS_VIOLATION;
    }
    if let Some(change_stamp) = change_stamp
        && change_stamp.write_at_offset(0, 0).is_none()
    {
        return NtStatus::ACCESS_VIOLATION;
    }

    NtStatus::UNSUCCESSFUL
}

pub(crate) fn sys_nt_update_wnf_state_data<Platform: RawPointerProvider>(
    state_name: Option<Platform::RawConstPointer<u64>>,
    buffer: Option<Platform::RawConstPointer<u8>>,
    length: u32,
    _type_id: Option<Platform::RawConstPointer<u8>>,
    _explicit_scope: Option<Platform::RawConstPointer<u8>>,
    _matching_change_stamp: u32,
    _check_stamp: u32,
) -> NtStatus {
    let Some(state_name) = state_name else {
        return NtStatus::INVALID_PARAMETER;
    };
    if state_name.read_at_offset(0).is_none() {
        return NtStatus::ACCESS_VIOLATION;
    }
    if length != 0 {
        let Some(buffer) = buffer else {
            return NtStatus::INVALID_PARAMETER;
        };
        if buffer.read_at_offset(0).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }
    }

    NtStatus::SUCCESS
}
