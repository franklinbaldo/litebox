use int_enum::IntEnum;
use litebox_common_windows::nt_status::NtStatus;
use litebox_platform_multiplex::Platform;

type GuestMutPointer<T> = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<T>;

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

pub(crate) fn handle_nt_apphelp_cache_control(
    service_class: u32,
    service_data: Option<GuestMutPointer<u8>>,
) -> NtStatus {
    let Ok(service_class) = ApphelpCacheServiceClass::try_from(service_class) else {
        litebox_util_log::debug!(
            service_class = service_class;
            "Unsupported NtApphelpCacheControl service class"
        );
        return NtStatus::INVALID_PARAMETER;
    };

    let status = match service_class {
        ApphelpCacheServiceClass::Lookup => {
            if service_data.is_none() {
                NtStatus::INVALID_PARAMETER
            } else {
                NtStatus::SUCCESS
            }
        }
        ApphelpCacheServiceClass::LookupCdb => {
            if service_data.is_none() {
                NtStatus::INVALID_PARAMETER
            } else {
                NtStatus::SUCCESS
            }
        }
        ApphelpCacheServiceClass::Remove | ApphelpCacheServiceClass::Update => {
            if service_data.is_none() {
                NtStatus::INVALID_PARAMETER
            } else {
                NtStatus::SUCCESS
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
    use litebox::platform::RawConstPointer as _;

    fn service_value(service_class: ApphelpCacheServiceClass) -> u32 {
        service_class as u32
    }

    fn service_data_ptr() -> GuestMutPointer<u8> {
        GuestMutPointer::<u8>::from_usize(0x1000)
    }

    #[test]
    fn nt_apphelp_cache_control_reports_empty_lookup_cache() {
        assert_eq!(
            handle_nt_apphelp_cache_control(
                service_value(ApphelpCacheServiceClass::Lookup),
                Some(service_data_ptr()),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(
            handle_nt_apphelp_cache_control(
                service_value(ApphelpCacheServiceClass::LookupCdb),
                Some(service_data_ptr()),
            ),
            NtStatus::SUCCESS
        );
    }

    #[test]
    fn nt_apphelp_cache_control_accepts_cache_mutations_as_noops() {
        assert_eq!(
            handle_nt_apphelp_cache_control(
                service_value(ApphelpCacheServiceClass::Update),
                Some(service_data_ptr()),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(
            handle_nt_apphelp_cache_control(service_value(ApphelpCacheServiceClass::Flush), None),
            NtStatus::SUCCESS
        );
    }

    #[test]
    fn nt_apphelp_cache_control_rejects_invalid_arguments() {
        assert_eq!(
            handle_nt_apphelp_cache_control(service_value(ApphelpCacheServiceClass::Lookup), None),
            NtStatus::INVALID_PARAMETER
        );
        assert_eq!(
            handle_nt_apphelp_cache_control(u32::MAX, Some(service_data_ptr())),
            NtStatus::INVALID_PARAMETER
        );
    }
}
