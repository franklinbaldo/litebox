#[derive(Debug, PartialEq)]
pub enum ResolverError {
    TrappedUnsupported,
    TrappedHostEffect,
    Unknown,
}

pub fn resolve_import(import_name: &str) -> Result<(), ResolverError> {
    let allowlist = ["DbgPrint", "ExAllocatePool", "ExFreePool"];
    let host_effect_apis = ["ZwWriteFile", "ZwCreateFile"];

    if host_effect_apis.contains(&import_name) {
        // Even if somehow we wanted to allow it, host effects are trapped
        return Err(ResolverError::TrappedHostEffect);
    }

    if !allowlist.contains(&import_name) {
        return Err(ResolverError::TrappedUnsupported);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sploit_import_outside_allowlist_trapped() {
        // import outside the allowlist -> UNSUPPORTED/TRAPPED
        assert_eq!(
            resolve_import("KeBugCheckEx"),
            Err(ResolverError::TrappedUnsupported)
        );
    }

    #[test]
    fn test_clean_allowlisted_import() {
        // only allowlisted imports -> resolves
        assert_eq!(resolve_import("DbgPrint"), Ok(()));
        assert_eq!(resolve_import("ExAllocatePool"), Ok(()));
    }

    #[test]
    fn test_fail_closed_unresolved() {
        // host-effect API -> trapped, never executed
        assert_eq!(
            resolve_import("ZwWriteFile"),
            Err(ResolverError::TrappedHostEffect)
        );

        // unknown -> trapped
        assert_eq!(
            resolve_import("RtlUnknownRandom"),
            Err(ResolverError::TrappedUnsupported)
        );
    }
}
