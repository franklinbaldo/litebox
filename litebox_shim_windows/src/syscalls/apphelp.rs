// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use int_enum::IntEnum;
use litebox_common_windows::nt_status::NtStatus;

use crate::{MutPtr, ShimPlatform};

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, IntEnum)]
enum ApphelpCacheServiceClass {
    Lookup = 0,
    Remove = 1,
    Update = 2,
    Flush = 3,
    Dump = 4,
    DumpCache = 5,
    LookupCdb = 6,
}

pub(crate) fn sys_nt_apphelp_cache_control<Platform: ShimPlatform>(
    service_class: u32,
    service_data: Option<MutPtr<Platform, u8>>,
) -> NtStatus {
    let Ok(service_class) = ApphelpCacheServiceClass::try_from(service_class) else {
        litebox_util_log::debug!(
            service_class = service_class;
            "Unsupported NtApphelpCacheControl service class"
        );
        return NtStatus::INVALID_PARAMETER;
    };

    let status = match service_class {
        ApphelpCacheServiceClass::Lookup
        | ApphelpCacheServiceClass::Remove
        | ApphelpCacheServiceClass::Update
        | ApphelpCacheServiceClass::LookupCdb => {
            if service_data.is_some() {
                NtStatus::SUCCESS
            } else {
                NtStatus::INVALID_PARAMETER
            }
        }
        ApphelpCacheServiceClass::Flush
        | ApphelpCacheServiceClass::Dump
        | ApphelpCacheServiceClass::DumpCache => NtStatus::SUCCESS,
    };

    litebox_util_log::debug!(
        service_class:? = service_class,
        has_service_data = service_data.is_some(),
        status:? = status;
        "Handled NtApphelpCacheControl syscall as an empty apphelp cache"
    );

    status
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::tests::TestPlatform;

    fn service_value(service_class: ApphelpCacheServiceClass) -> u32 {
        service_class as u32
    }

    fn service_data_ptr(service_data: &mut u8) -> MutPtr<TestPlatform, u8> {
        MutPtr::<TestPlatform, u8>::from_ptr(core::ptr::from_mut(service_data))
    }

    #[test]
    fn nt_apphelp_cache_control_accepts_empty_cache_lookups() {
        let mut service_data = 0;
        assert_eq!(
            sys_nt_apphelp_cache_control::<TestPlatform>(
                service_value(ApphelpCacheServiceClass::Lookup),
                Some(service_data_ptr(&mut service_data)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(
            sys_nt_apphelp_cache_control::<TestPlatform>(
                service_value(ApphelpCacheServiceClass::LookupCdb),
                Some(service_data_ptr(&mut service_data)),
            ),
            NtStatus::SUCCESS
        );
    }

    #[test]
    fn nt_apphelp_cache_control_accepts_cache_mutations_as_noops() {
        let mut service_data = 0;
        assert_eq!(
            sys_nt_apphelp_cache_control::<TestPlatform>(
                service_value(ApphelpCacheServiceClass::Update),
                Some(service_data_ptr(&mut service_data)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(
            sys_nt_apphelp_cache_control::<TestPlatform>(
                service_value(ApphelpCacheServiceClass::Flush),
                None,
            ),
            NtStatus::SUCCESS
        );
    }

    #[test]
    fn nt_apphelp_cache_control_rejects_invalid_arguments() {
        assert_eq!(
            sys_nt_apphelp_cache_control::<TestPlatform>(
                service_value(ApphelpCacheServiceClass::Lookup),
                None,
            ),
            NtStatus::INVALID_PARAMETER
        );

        let mut service_data = 0;
        assert_eq!(
            sys_nt_apphelp_cache_control::<TestPlatform>(
                u32::MAX,
                Some(service_data_ptr(&mut service_data)),
            ),
            NtStatus::INVALID_PARAMETER
        );
    }
}
