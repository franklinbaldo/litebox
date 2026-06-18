// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows NT token object syscalls.

use core::mem::size_of;

use int_enum::IntEnum;
use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::nt_types::AccessMask;
use crate::syscalls::{Handle, ProcessHandle, ThreadHandle};
use crate::{
    MutPtr, ShimFS, ShimPlatform, Task, insert_raw_handle, probe_guest_output_preserving_value,
    raw_handle_entry, remove_raw_handle,
};

const CURRENT_PROCESS_TOKEN: Handle = Handle::from_raw(usize::MAX - 3);
const CURRENT_THREAD_TOKEN: Handle = Handle::from_raw(usize::MAX - 4);
const CURRENT_THREAD_EFFECTIVE_TOKEN: Handle = Handle::from_raw(usize::MAX - 5);

const TOKEN_TYPE_PRIMARY: u32 = 1;
const TOKEN_ELEVATION_TYPE_DEFAULT: u32 = 1;
const TOKEN_MANDATORY_LABEL_ATTRIBUTES: u32 = 0x0000_0020;
const MEDIUM_INTEGRITY_SID: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 16, 0, 0x20, 0, 0];
const LOCAL_SYSTEM_SID: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];

bitflags::bitflags! {
    /// Token generic-right mapping follows Wine's object-manager tests.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct TokenAccess: u32 {
        const ASSIGN_PRIMARY = 0x0001;
        const DUPLICATE = 0x0002;
        const IMPERSONATE = 0x0004;
        const QUERY = 0x0008;
        const QUERY_SOURCE = 0x0010;
        const ADJUST_PRIVILEGES = 0x0020;
        const ADJUST_GROUPS = 0x0040;
        const ADJUST_DEFAULT = 0x0080;
        const ADJUST_SESSIONID = 0x0100;

        const GENERIC_READ = AccessMask::GENERIC_READ.bits();
        const GENERIC_WRITE = AccessMask::GENERIC_WRITE.bits();
        const GENERIC_EXECUTE = AccessMask::GENERIC_EXECUTE.bits();
        const GENERIC_ALL = AccessMask::GENERIC_ALL.bits();

        const GENERIC_READ_EXPANSION = AccessMask::STANDARD_RIGHTS_READ.bits()
            | Self::QUERY_SOURCE.bits()
            | Self::QUERY.bits()
            | Self::DUPLICATE.bits();
        const GENERIC_WRITE_EXPANSION = AccessMask::STANDARD_RIGHTS_WRITE.bits()
            | Self::ADJUST_SESSIONID.bits()
            | Self::ADJUST_DEFAULT.bits()
            | Self::ADJUST_GROUPS.bits()
            | Self::ADJUST_PRIVILEGES.bits();
        const GENERIC_EXECUTE_EXPANSION = AccessMask::STANDARD_RIGHTS_EXECUTE.bits()
            | Self::IMPERSONATE.bits()
            | Self::ASSIGN_PRIMARY.bits();
        const ALL_ACCESS = AccessMask::STANDARD_RIGHTS_ALL.bits()
            | Self::ASSIGN_PRIMARY.bits()
            | Self::DUPLICATE.bits()
            | Self::IMPERSONATE.bits()
            | Self::QUERY.bits()
            | Self::QUERY_SOURCE.bits()
            | Self::ADJUST_PRIVILEGES.bits()
            | Self::ADJUST_GROUPS.bits()
            | Self::ADJUST_DEFAULT.bits()
            | Self::ADJUST_SESSIONID.bits();

        const _ = !0;
    }
}

impl TokenAccess {
    fn from_desired_access(desired_access: u32) -> Self {
        let mut access = Self::from_bits_retain(desired_access);
        if access.contains(Self::GENERIC_READ) {
            access.remove(Self::GENERIC_READ);
            access.insert(Self::GENERIC_READ_EXPANSION);
        }
        if access.contains(Self::GENERIC_WRITE) {
            access.remove(Self::GENERIC_WRITE);
            access.insert(Self::GENERIC_WRITE_EXPANSION);
        }
        if access.contains(Self::GENERIC_EXECUTE) {
            access.remove(Self::GENERIC_EXECUTE);
            access.insert(Self::GENERIC_EXECUTE_EXPANSION);
        }
        if access.contains(Self::GENERIC_ALL) {
            access.remove(Self::GENERIC_ALL);
            access.insert(Self::ALL_ACCESS);
        }
        access
    }

    fn require(self, required: Self) -> Result<(), NtStatus> {
        if self.contains(required) {
            Ok(())
        } else {
            Err(NtStatus::ACCESS_DENIED)
        }
    }
}

pub(crate) struct TokenSubsystem;

impl FdEnabledSubsystem for TokenSubsystem {
    type Entry = TokenHandleObject;
}

impl FdEnabledSubsystemEntry for TokenHandleObject {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TokenHandleObject {
    granted_access: TokenAccess,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
enum TokenInformationClass {
    User = 1,
    Groups = 2,
    Privileges = 3,
    Owner = 4,
    PrimaryGroup = 5,
    DefaultDacl = 6,
    Source = 7,
    Type = 8,
    ImpersonationLevel = 9,
    Statistics = 10,
    RestrictedSids = 11,
    SessionId = 12,
    GroupsAndPrivileges = 13,
    SessionReference = 14,
    SandBoxInert = 15,
    AuditPolicy = 16,
    Origin = 17,
    ElevationType = 18,
    LinkedToken = 19,
    Elevation = 20,
    HasRestrictions = 21,
    AccessInformation = 22,
    VirtualizationAllowed = 23,
    VirtualizationEnabled = 24,
    IntegrityLevel = 25,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, Immutable, IntoBytes)]
struct Luid {
    low_part: u32,
    high_part: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct TokenStatistics {
    token_id: Luid,
    authentication_id: Luid,
    expiration_time: i64,
    token_type: u32,
    impersonation_level: u32,
    dynamic_charged: u32,
    dynamic_available: u32,
    group_count: u32,
    privilege_count: u32,
    modified_id: Luid,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct SidAndAttributesHeader {
    sid: usize,
    attributes: u32,
    _padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct CountHeader {
    count: u32,
    _padding: u32,
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    pub(crate) fn sys_nt_open_thread_token(
        &self,
        thread_handle: ThreadHandle,
        desired_access: u32,
        open_as_self: u8,
        token_handle: MutPtr<Platform, Handle>,
    ) -> NtStatus {
        if let Err(status) = probe_guest_output_preserving_value::<Platform, Handle>(token_handle) {
            return status;
        }
        if !thread_handle.is_current() {
            return NtStatus::INVALID_HANDLE;
        }

        let access = TokenAccess::from_desired_access(desired_access);
        let handle = match self.insert_token_handle(access, token_handle) {
            Ok(handle) => handle,
            Err(status) => return status,
        };

        litebox_util_log::debug!(
            handle:% = format_args!("{:#x}", handle.as_raw()),
            thread_handle:% = format_args!("{:#x}", thread_handle.as_raw()),
            desired_access,
            open_as_self = open_as_self != 0;
            "Handled NtOpenThreadToken syscall"
        );

        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_open_thread_token_ex(
        &self,
        thread_handle: ThreadHandle,
        desired_access: u32,
        open_as_self: u8,
        _handle_attributes: u32,
        token_handle: MutPtr<Platform, Handle>,
    ) -> NtStatus {
        self.sys_nt_open_thread_token(thread_handle, desired_access, open_as_self, token_handle)
    }

    pub(crate) fn sys_nt_open_process_token(
        &self,
        process_handle: ProcessHandle,
        desired_access: u32,
        token_handle: MutPtr<Platform, Handle>,
    ) -> NtStatus {
        self.open_process_token(process_handle, desired_access, token_handle)
    }

    pub(crate) fn sys_nt_open_process_token_ex(
        &self,
        process_handle: ProcessHandle,
        desired_access: u32,
        _handle_attributes: u32,
        token_handle: MutPtr<Platform, Handle>,
    ) -> NtStatus {
        self.open_process_token(process_handle, desired_access, token_handle)
    }

    pub(crate) fn sys_nt_query_information_token(
        &self,
        token_handle: Handle,
        token_information_class: u32,
        token_information: MutPtr<Platform, u8>,
        token_information_length: u32,
        return_length: Option<MutPtr<Platform, u32>>,
    ) -> NtStatus {
        let Some(return_length) = return_length else {
            return NtStatus::ACCESS_VIOLATION;
        };
        if let Err(status) = probe_guest_output_preserving_value::<Platform, u32>(return_length) {
            return status;
        }

        let token = match self.token_handle(token_handle) {
            Ok(token) => token,
            Err(status) => return status,
        };
        let Ok(token_information_class) = TokenInformationClass::try_from(token_information_class)
        else {
            litebox_util_log::debug!(
                token_information_class = token_information_class;
                "Unsupported NtQueryInformationToken class"
            );
            return NtStatus::INVALID_INFO_CLASS;
        };

        let status = match token_information_class {
            TokenInformationClass::User => token.write_sid_and_attributes::<Platform>(
                token_information,
                token_information_length,
                return_length,
                &LOCAL_SYSTEM_SID,
                0,
            ),
            TokenInformationClass::Groups
            | TokenInformationClass::RestrictedSids
            | TokenInformationClass::GroupsAndPrivileges
            | TokenInformationClass::AccessInformation => token.write_count_header::<Platform>(
                token_information,
                token_information_length,
                return_length,
            ),
            TokenInformationClass::Privileges
            | TokenInformationClass::SessionId
            | TokenInformationClass::SandBoxInert
            | TokenInformationClass::VirtualizationAllowed
            | TokenInformationClass::VirtualizationEnabled
            | TokenInformationClass::HasRestrictions => token.write_u32::<Platform>(
                token_information,
                token_information_length,
                return_length,
                0,
                LengthRule::AtLeast,
            ),
            TokenInformationClass::Owner | TokenInformationClass::PrimaryGroup => token
                .write_sid::<Platform>(
                    token_information,
                    token_information_length,
                    return_length,
                    &LOCAL_SYSTEM_SID,
                ),
            TokenInformationClass::DefaultDacl => token.write_usize::<Platform>(
                token_information,
                token_information_length,
                return_length,
                0,
                LengthRule::AtLeast,
            ),
            TokenInformationClass::Source => token.write_source::<Platform>(
                token_information,
                token_information_length,
                return_length,
            ),
            TokenInformationClass::Type => token.write_u32::<Platform>(
                token_information,
                token_information_length,
                return_length,
                TOKEN_TYPE_PRIMARY,
                LengthRule::AtLeast,
            ),
            TokenInformationClass::ImpersonationLevel | TokenInformationClass::SessionReference => {
                NtStatus::INVALID_INFO_CLASS
            }
            TokenInformationClass::Statistics => token.write_statistics::<Platform>(
                token_information,
                token_information_length,
                return_length,
            ),
            TokenInformationClass::AuditPolicy => NtStatus::PRIVILEGE_NOT_HELD,
            TokenInformationClass::Origin => token.write_luid::<Platform>(
                token_information,
                token_information_length,
                return_length,
                Luid::default(),
            ),
            TokenInformationClass::ElevationType => token.write_u32::<Platform>(
                token_information,
                token_information_length,
                return_length,
                TOKEN_ELEVATION_TYPE_DEFAULT,
                LengthRule::AtLeast,
            ),
            TokenInformationClass::LinkedToken => token.write_handle::<Platform>(
                token_information,
                token_information_length,
                return_length,
                CURRENT_PROCESS_TOKEN,
                LengthRule::Exact,
            ),
            TokenInformationClass::Elevation => token.write_u32::<Platform>(
                token_information,
                token_information_length,
                return_length,
                0,
                LengthRule::Exact,
            ),
            TokenInformationClass::IntegrityLevel => token.write_sid_and_attributes::<Platform>(
                token_information,
                token_information_length,
                return_length,
                &MEDIUM_INTEGRITY_SID,
                TOKEN_MANDATORY_LABEL_ATTRIBUTES,
            ),
        };

        if status == NtStatus::SUCCESS {
            litebox_util_log::debug!(
                token_handle:% = format_args!("{:#x}", token_handle.as_raw()),
                token_information_class:? = token_information_class,
                token_information_length = token_information_length;
                "Handled NtQueryInformationToken syscall"
            );
        }

        status
    }

    pub(crate) fn sys_nt_query_security_attributes_token(
        &self,
        token_handle: Handle,
        _attributes: Option<crate::ConstPtr<Platform, u8>>,
        _number_of_attributes: u32,
        buffer: Option<MutPtr<Platform, u8>>,
        length: u32,
        return_length: Option<MutPtr<Platform, u32>>,
    ) -> NtStatus {
        let Some(return_length) = return_length else {
            return NtStatus::ACCESS_VIOLATION;
        };
        if let Err(status) = probe_guest_output_preserving_value::<Platform, u32>(return_length) {
            return status;
        }
        let token = match self.token_handle(token_handle) {
            Ok(token) => token,
            Err(status) => return status,
        };
        if let Err(status) = token.ensure_query_access() {
            return status;
        }
        if let Some(buffer) = buffer
            && length != 0
            && buffer.write_at_offset(0, 0).is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        if return_length.write_at_offset(0, 0).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }

        NtStatus::SUCCESS
    }

    pub(crate) fn close_token(_token: TokenHandleObject) {}

    fn open_process_token(
        &self,
        process_handle: ProcessHandle,
        desired_access: u32,
        token_handle: MutPtr<Platform, Handle>,
    ) -> NtStatus {
        if let Err(status) = probe_guest_output_preserving_value::<Platform, Handle>(token_handle) {
            return status;
        }
        if !process_handle.is_current() {
            return NtStatus::INVALID_HANDLE;
        }

        let handle = match self.insert_token_handle(
            TokenAccess::from_desired_access(desired_access),
            token_handle,
        ) {
            Ok(handle) => handle,
            Err(status) => return status,
        };

        litebox_util_log::debug!(
            handle:% = format_args!("{:#x}", handle.as_raw()),
            process_handle:% = format_args!("{:#x}", process_handle.as_handle().as_raw()),
            desired_access;
            "Handled NtOpenProcessToken syscall"
        );

        NtStatus::SUCCESS
    }

    fn insert_token_handle(
        &self,
        granted_access: TokenAccess,
        token_handle: MutPtr<Platform, Handle>,
    ) -> Result<Handle, NtStatus> {
        let mut descriptor_table = self.global.litebox.descriptor_table_mut();
        let typed = descriptor_table.insert::<TokenSubsystem>(TokenHandleObject { granted_access });
        drop(descriptor_table);

        let handle = insert_raw_handle(
            &self.global.litebox,
            &self.process.handles,
            typed,
            Self::close_token,
        )?;

        if token_handle.write_at_offset(0, handle).is_none() {
            remove_raw_handle::<Platform, TokenSubsystem>(
                &self.global.litebox,
                &self.process.handles,
                handle,
                Self::close_token,
            );
            return Err(NtStatus::ACCESS_VIOLATION);
        }

        Ok(handle)
    }

    fn token_handle(&self, token_handle: Handle) -> Result<TokenHandleObject, NtStatus> {
        match token_handle {
            CURRENT_PROCESS_TOKEN | CURRENT_THREAD_EFFECTIVE_TOKEN => Ok(TokenHandleObject {
                granted_access: TokenAccess::ALL_ACCESS,
            }),
            CURRENT_THREAD_TOKEN => Err(NtStatus::NO_TOKEN),
            _ => raw_handle_entry::<Platform, TokenSubsystem>(
                &self.global.litebox,
                &self.process.handles,
                token_handle,
            )
            .map(|entry| entry.with_entry(|token| *token))
            .ok_or(NtStatus::INVALID_HANDLE),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LengthRule {
    AtLeast,
    Exact,
}

impl TokenHandleObject {
    fn ensure_query_access(self) -> Result<(), NtStatus> {
        self.granted_access.require(TokenAccess::QUERY)
    }

    fn ensure_query_source_access(self) -> Result<(), NtStatus> {
        self.granted_access.require(TokenAccess::QUERY_SOURCE)
    }

    fn check_length<Platform: ShimPlatform>(
        length: u32,
        required_length: u32,
        return_length: MutPtr<Platform, u32>,
        rule: LengthRule,
    ) -> Result<(), NtStatus> {
        if return_length.write_at_offset(0, required_length).is_none() {
            return Err(NtStatus::ACCESS_VIOLATION);
        }
        match rule {
            LengthRule::AtLeast if length < required_length => Err(NtStatus::BUFFER_TOO_SMALL),
            LengthRule::Exact if length != required_length => Err(NtStatus::INFO_LENGTH_MISMATCH),
            _ => Ok(()),
        }
    }

    fn write_value<Platform: ShimPlatform, T: Immutable + IntoBytes>(
        self,
        token_information: MutPtr<Platform, u8>,
        token_information_length: u32,
        return_length: MutPtr<Platform, u32>,
        value: &T,
        rule: LengthRule,
    ) -> NtStatus {
        if let Err(status) = self.ensure_query_access() {
            return status;
        }
        let required_length = information_len::<T>();
        if let Err(status) = Self::check_length::<Platform>(
            token_information_length,
            required_length,
            return_length,
            rule,
        ) {
            return status;
        }
        if token_information
            .write_slice_at_offset(0, value.as_bytes())
            .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    fn write_u32<Platform: ShimPlatform>(
        self,
        token_information: MutPtr<Platform, u8>,
        token_information_length: u32,
        return_length: MutPtr<Platform, u32>,
        value: u32,
        rule: LengthRule,
    ) -> NtStatus {
        self.write_value::<Platform, u32>(
            token_information,
            token_information_length,
            return_length,
            &value,
            rule,
        )
    }

    fn write_usize<Platform: ShimPlatform>(
        self,
        token_information: MutPtr<Platform, u8>,
        token_information_length: u32,
        return_length: MutPtr<Platform, u32>,
        value: usize,
        rule: LengthRule,
    ) -> NtStatus {
        self.write_value::<Platform, usize>(
            token_information,
            token_information_length,
            return_length,
            &value,
            rule,
        )
    }

    fn write_handle<Platform: ShimPlatform>(
        self,
        token_information: MutPtr<Platform, u8>,
        token_information_length: u32,
        return_length: MutPtr<Platform, u32>,
        value: Handle,
        rule: LengthRule,
    ) -> NtStatus {
        self.write_value::<Platform, Handle>(
            token_information,
            token_information_length,
            return_length,
            &value,
            rule,
        )
    }

    fn write_luid<Platform: ShimPlatform>(
        self,
        token_information: MutPtr<Platform, u8>,
        token_information_length: u32,
        return_length: MutPtr<Platform, u32>,
        value: Luid,
    ) -> NtStatus {
        self.write_value::<Platform, Luid>(
            token_information,
            token_information_length,
            return_length,
            &value,
            LengthRule::AtLeast,
        )
    }

    fn write_count_header<Platform: ShimPlatform>(
        self,
        token_information: MutPtr<Platform, u8>,
        token_information_length: u32,
        return_length: MutPtr<Platform, u32>,
    ) -> NtStatus {
        self.write_value::<Platform, CountHeader>(
            token_information,
            token_information_length,
            return_length,
            &CountHeader {
                count: 0,
                _padding: 0,
            },
            LengthRule::AtLeast,
        )
    }

    fn write_statistics<Platform: ShimPlatform>(
        self,
        token_information: MutPtr<Platform, u8>,
        token_information_length: u32,
        return_length: MutPtr<Platform, u32>,
    ) -> NtStatus {
        self.write_value::<Platform, TokenStatistics>(
            token_information,
            token_information_length,
            return_length,
            &TokenStatistics {
                token_id: Luid {
                    low_part: 1,
                    high_part: 0,
                },
                authentication_id: Luid::default(),
                expiration_time: i64::MAX,
                token_type: TOKEN_TYPE_PRIMARY,
                impersonation_level: 0,
                dynamic_charged: 0,
                dynamic_available: 0,
                group_count: 0,
                privilege_count: 0,
                modified_id: Luid {
                    low_part: 1,
                    high_part: 0,
                },
            },
            LengthRule::AtLeast,
        )
    }

    fn write_source<Platform: ShimPlatform>(
        self,
        token_information: MutPtr<Platform, u8>,
        token_information_length: u32,
        return_length: MutPtr<Platform, u32>,
    ) -> NtStatus {
        if let Err(status) = self.ensure_query_source_access() {
            return status;
        }
        let source = [
            b'L', b'i', b't', b'e', b'B', b'x', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let required_length = information_len::<[u8; 16]>();
        if let Err(status) = Self::check_length::<Platform>(
            token_information_length,
            required_length,
            return_length,
            LengthRule::AtLeast,
        ) {
            return status;
        }
        if token_information
            .write_slice_at_offset(0, source.as_bytes())
            .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    fn write_sid<Platform: ShimPlatform>(
        self,
        token_information: MutPtr<Platform, u8>,
        token_information_length: u32,
        return_length: MutPtr<Platform, u32>,
        sid: &[u8],
    ) -> NtStatus {
        if let Err(status) = self.ensure_query_access() {
            return status;
        }
        let Ok(required_length) = u32::try_from(size_of::<usize>() + sid.len()) else {
            return NtStatus::NO_MEMORY;
        };
        if let Err(status) = Self::check_length::<Platform>(
            token_information_length,
            required_length,
            return_length,
            LengthRule::AtLeast,
        ) {
            return status;
        }
        let Some(sid_address) = token_information.as_usize().checked_add(size_of::<usize>()) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        if token_information
            .write_slice_at_offset(0, sid_address.as_bytes())
            .is_none()
            || token_information
                .write_slice_at_offset(
                    size_of::<usize>()
                        .try_into()
                        .expect("usize size fits isize"),
                    sid,
                )
                .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    fn write_sid_and_attributes<Platform: ShimPlatform>(
        self,
        token_information: MutPtr<Platform, u8>,
        token_information_length: u32,
        return_length: MutPtr<Platform, u32>,
        sid: &[u8],
        attributes: u32,
    ) -> NtStatus {
        if let Err(status) = self.ensure_query_access() {
            return status;
        }
        let Ok(required_length) = u32::try_from(size_of::<SidAndAttributesHeader>() + sid.len())
        else {
            return NtStatus::NO_MEMORY;
        };
        if let Err(status) = Self::check_length::<Platform>(
            token_information_length,
            required_length,
            return_length,
            LengthRule::AtLeast,
        ) {
            return status;
        }
        let Some(sid_address) = token_information
            .as_usize()
            .checked_add(size_of::<SidAndAttributesHeader>())
        else {
            return NtStatus::ACCESS_VIOLATION;
        };
        let header = SidAndAttributesHeader {
            sid: sid_address,
            attributes,
            _padding: 0,
        };
        if token_information
            .write_slice_at_offset(0, header.as_bytes())
            .is_none()
            || token_information
                .write_slice_at_offset(
                    size_of::<SidAndAttributesHeader>()
                        .try_into()
                        .expect("header size fits isize"),
                    sid,
                )
                .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }
}

fn information_len<T>() -> u32 {
    u32::try_from(size_of::<T>()).expect("token information fits in ULONG")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{mut_byte_ptr, mut_ptr, null_mut_ptr};
    use litebox::platform::ThreadProvider;

    type TestPlatform = crate::tests::TestPlatform;

    const TOKEN_QUERY: u32 = TokenAccess::QUERY.bits();
    const TOKEN_QUERY_SOURCE: u32 = TokenAccess::QUERY_SOURCE.bits();

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    unsafe extern "system" {
        fn NtOpenProcessToken(
            process_handle: *mut core::ffi::c_void,
            desired_access: u32,
            token_handle: *mut *mut core::ffi::c_void,
        ) -> i32;

        fn NtQueryInformationToken(
            token_handle: *mut core::ffi::c_void,
            token_information_class: u32,
            token_information: *mut core::ffi::c_void,
            token_information_length: u32,
            return_length: *mut u32,
        ) -> i32;

        fn NtClose(handle: *mut core::ffi::c_void) -> i32;
    }

    fn run_with_test_platform_pointers<R>(f: impl FnOnce() -> R) -> R {
        let _ = crate::tests::test_platform();
        <TestPlatform as ThreadProvider>::run_test_thread(f)
    }

    fn class_value(class: TokenInformationClass) -> u32 {
        class as u32
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn host_status(status: i32) -> NtStatus {
        NtStatus::from_raw(u32::from_ne_bytes(status.to_ne_bytes()))
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn nt_current_process() -> *mut core::ffi::c_void {
        usize::MAX as *mut core::ffi::c_void
    }

    #[test]
    fn nt_open_thread_token_returns_queryable_handle() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut token_handle = Handle::from_raw(0);

            assert_eq!(
                task.sys_nt_open_thread_token(
                    ThreadHandle::CURRENT,
                    TOKEN_QUERY | TOKEN_QUERY_SOURCE,
                    1,
                    mut_ptr(&mut token_handle),
                ),
                NtStatus::SUCCESS
            );
            assert!(!token_handle.is_null());

            let mut token_type = 0u32;
            let mut return_length = 0u32;
            assert_eq!(
                task.sys_nt_query_information_token(
                    token_handle,
                    class_value(TokenInformationClass::Type),
                    mut_byte_ptr(&mut token_type),
                    information_len::<u32>(),
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(token_type, TOKEN_TYPE_PRIMARY);
            assert_eq!(return_length, information_len::<u32>());
            assert_eq!(task.sys_nt_close(token_handle), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn nt_open_thread_token_probes_output_before_opening_handle() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            assert_eq!(
                task.sys_nt_open_thread_token(
                    ThreadHandle::CURRENT,
                    TOKEN_QUERY,
                    1,
                    null_mut_ptr(),
                ),
                NtStatus::ACCESS_VIOLATION
            );
        });
    }

    #[test]
    fn nt_open_process_token_returns_queryable_handle() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut token_handle = Handle::from_raw(0);

            assert_eq!(
                task.sys_nt_open_process_token(
                    ProcessHandle::CURRENT,
                    TOKEN_QUERY | TOKEN_QUERY_SOURCE,
                    mut_ptr(&mut token_handle),
                ),
                NtStatus::SUCCESS
            );
            assert!(!token_handle.is_null());

            let mut token_type = 0u32;
            let mut return_length = 0u32;
            assert_eq!(
                task.sys_nt_query_information_token(
                    token_handle,
                    class_value(TokenInformationClass::Type),
                    mut_byte_ptr(&mut token_type),
                    information_len::<u32>(),
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(token_type, TOKEN_TYPE_PRIMARY);
            assert_eq!(return_length, information_len::<u32>());
            assert_eq!(task.sys_nt_close(token_handle), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn nt_query_information_token_supports_pseudo_tokens() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut token_type = 0u32;
            let mut return_length = 0u32;

            assert_eq!(
                task.sys_nt_query_information_token(
                    CURRENT_PROCESS_TOKEN,
                    class_value(TokenInformationClass::Type),
                    mut_byte_ptr(&mut token_type),
                    information_len::<u32>(),
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(token_type, TOKEN_TYPE_PRIMARY);
            assert_eq!(
                task.sys_nt_query_information_token(
                    CURRENT_THREAD_EFFECTIVE_TOKEN,
                    class_value(TokenInformationClass::Type),
                    mut_byte_ptr(&mut token_type),
                    information_len::<u32>(),
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(
                task.sys_nt_query_information_token(
                    CURRENT_THREAD_TOKEN,
                    class_value(TokenInformationClass::Type),
                    mut_byte_ptr(&mut token_type),
                    information_len::<u32>(),
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::NO_TOKEN
            );
        });
    }

    #[test]
    fn nt_query_information_token_has_restrictions_is_ulong() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut has_restrictions = u32::MAX;
            let mut return_length = 0;

            assert_eq!(
                task.sys_nt_query_information_token(
                    CURRENT_PROCESS_TOKEN,
                    class_value(TokenInformationClass::HasRestrictions),
                    mut_byte_ptr(&mut has_restrictions),
                    information_len::<u32>(),
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(has_restrictions, 0);
            assert_eq!(return_length, information_len::<u32>());
        });
    }

    #[test]
    fn nt_query_information_token_source_only_requires_query_source() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut token_handle = Handle::default();
            assert_eq!(
                task.sys_nt_open_thread_token(
                    ThreadHandle::CURRENT,
                    TOKEN_QUERY_SOURCE,
                    1,
                    mut_ptr(&mut token_handle),
                ),
                NtStatus::SUCCESS
            );

            let mut source = [0u8; 16];
            let mut return_length = 0;
            assert_eq!(
                task.sys_nt_query_information_token(
                    token_handle,
                    class_value(TokenInformationClass::Source),
                    mut_byte_ptr(&mut source[0]),
                    u32::try_from(source.len()).expect("source length fits ULONG"),
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(&source[..6], b"LiteBx");
            assert_eq!(return_length, information_len::<[u8; 16]>());

            let mut token_type = 0u32;
            assert_eq!(
                task.sys_nt_query_information_token(
                    token_handle,
                    class_value(TokenInformationClass::Type),
                    mut_byte_ptr(&mut token_type),
                    information_len::<u32>(),
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::ACCESS_DENIED
            );
            assert_eq!(task.sys_nt_close(token_handle), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn nt_query_security_attributes_token_requires_query_access() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut token_handle = Handle::default();
            assert_eq!(
                task.sys_nt_open_thread_token(
                    ThreadHandle::CURRENT,
                    TokenAccess::ASSIGN_PRIMARY.bits(),
                    1,
                    mut_ptr(&mut token_handle),
                ),
                NtStatus::SUCCESS
            );

            let mut buffer = 0u8;
            let mut return_length = u32::MAX;
            assert_eq!(
                task.sys_nt_query_security_attributes_token(
                    token_handle,
                    None,
                    0,
                    Some(mut_byte_ptr(&mut buffer)),
                    1,
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::ACCESS_DENIED
            );
            assert_eq!(return_length, u32::MAX);
            assert_eq!(task.sys_nt_close(token_handle), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn nt_query_information_token_requires_return_length_pointer() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut token_type = 0u32;

            assert_eq!(
                task.sys_nt_query_information_token(
                    CURRENT_PROCESS_TOKEN,
                    0,
                    mut_byte_ptr(&mut token_type),
                    information_len::<u32>(),
                    None,
                ),
                NtStatus::ACCESS_VIOLATION
            );
        });
    }

    #[test]
    fn nt_query_information_token_matches_host_length_rules_for_core_classes() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut token_type = 0u32;
            let mut return_length = 0u32;
            assert_eq!(
                task.sys_nt_query_information_token(
                    CURRENT_PROCESS_TOKEN,
                    class_value(TokenInformationClass::Type),
                    mut_byte_ptr(&mut token_type),
                    0,
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::BUFFER_TOO_SMALL
            );
            assert_eq!(return_length, information_len::<u32>());

            let mut token_elevation = 0u32;
            assert_eq!(
                task.sys_nt_query_information_token(
                    CURRENT_PROCESS_TOKEN,
                    class_value(TokenInformationClass::Elevation),
                    mut_byte_ptr(&mut token_elevation),
                    8,
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::INFO_LENGTH_MISMATCH
            );
            assert_eq!(return_length, information_len::<u32>());
        });
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn nt_query_information_token_length_rules_match_windows() {
        let mut host_token = core::ptr::null_mut();
        let open_status = unsafe {
            host_status(NtOpenProcessToken(
                nt_current_process(),
                TOKEN_QUERY,
                &raw mut host_token,
            ))
        };
        assert_eq!(open_status, NtStatus::SUCCESS);

        let mut host_return_length = 0;
        let mut host_token_elevation = 0u32;
        let host_type_status = unsafe {
            host_status(NtQueryInformationToken(
                host_token,
                class_value(TokenInformationClass::Type),
                core::ptr::null_mut(),
                0,
                &raw mut host_return_length,
            ))
        };
        let mut host_elevation_return_length = 0;
        let host_elevation_status = unsafe {
            host_status(NtQueryInformationToken(
                host_token,
                class_value(TokenInformationClass::Elevation),
                core::ptr::from_mut(&mut host_token_elevation).cast(),
                8,
                &raw mut host_elevation_return_length,
            ))
        };
        unsafe {
            NtClose(host_token);
        }

        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut token_type = 0u32;
            let mut return_length = 0u32;
            assert_eq!(
                task.sys_nt_query_information_token(
                    CURRENT_PROCESS_TOKEN,
                    class_value(TokenInformationClass::Type),
                    mut_byte_ptr(&mut token_type),
                    0,
                    Some(mut_ptr(&mut return_length)),
                ),
                host_type_status
            );
            assert_eq!(return_length, host_return_length);

            let mut token_elevation = 0u32;
            assert_eq!(
                task.sys_nt_query_information_token(
                    CURRENT_PROCESS_TOKEN,
                    class_value(TokenInformationClass::Elevation),
                    mut_byte_ptr(&mut token_elevation),
                    8,
                    Some(mut_ptr(&mut return_length)),
                ),
                host_elevation_status
            );
            assert_eq!(return_length, host_elevation_return_length);
        });
    }
}
