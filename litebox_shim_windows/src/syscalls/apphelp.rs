// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use int_enum::IntEnum;
use litebox_common_windows::nt_status::NtStatus;

use crate::{MutPtr, ShimPlatform};

const STATUS_NOT_FOUND: NtStatus = NtStatus::from_raw(0xC000_0225);

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
        | ApphelpCacheServiceClass::LookupCdb
        | ApphelpCacheServiceClass::Remove
        | ApphelpCacheServiceClass::Update => {
            service_data.map_or(NtStatus::INVALID_PARAMETER, |_| STATUS_NOT_FOUND)
        }
        ApphelpCacheServiceClass::Flush
        | ApphelpCacheServiceClass::Dump
        | ApphelpCacheServiceClass::DumpCache => NtStatus::SUCCESS,
    };

    litebox_util_log::debug!(
        service_class:? = service_class,
        has_service_data = service_data.is_some(),
        status:? = status;
        "Handled NtApphelpCacheControl syscall as an apphelp cache miss"
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

    fn service_data_ptr() -> MutPtr<TestPlatform, u8> {
        MutPtr::<TestPlatform, u8>::from_ptr(core::ptr::NonNull::dangling().as_ptr())
    }

    #[test]
    fn nt_apphelp_cache_control_reports_cache_miss_for_lookups() {
        assert_eq!(
            sys_nt_apphelp_cache_control::<TestPlatform>(
                service_value(ApphelpCacheServiceClass::Lookup),
                Some(service_data_ptr()),
            ),
            STATUS_NOT_FOUND
        );

        assert_eq!(
            sys_nt_apphelp_cache_control::<TestPlatform>(
                service_value(ApphelpCacheServiceClass::LookupCdb),
                Some(service_data_ptr()),
            ),
            STATUS_NOT_FOUND
        );
    }

    #[test]
    fn nt_apphelp_cache_control_accepts_cache_mutations_as_noops() {
        assert_eq!(
            sys_nt_apphelp_cache_control::<TestPlatform>(
                service_value(ApphelpCacheServiceClass::Update),
                Some(service_data_ptr()),
            ),
            STATUS_NOT_FOUND
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

        assert_eq!(
            sys_nt_apphelp_cache_control::<TestPlatform>(u32::MAX, Some(service_data_ptr()),),
            NtStatus::INVALID_PARAMETER
        );
    }
}
