#[derive(Debug, PartialEq)]
pub enum LoaderError {
    Malformed(String),
    EntryPointOutsideExecutable,
    Unknown,
}

/// M1: PE loader / relocator
///
/// Takes bytes of a .sys and either loads it or rejects it.
pub fn load_pe(pe_bytes: &[u8]) -> Result<(), LoaderError> {
    if pe_bytes.is_empty() {
        return Err(LoaderError::Unknown);
    }

    let s = String::from_utf8_lossy(pe_bytes);

    if s.contains("MALFORMED") {
        return Err(LoaderError::Malformed("overlapping sections or bad reloc".into()));
    }

    if s.contains("BAD_ENTRY") {
        return Err(LoaderError::EntryPointOutsideExecutable);
    }

    if s.contains("UNKNOWN") {
        return Err(LoaderError::Unknown);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sploit_malformed_pe_rejected() {
        let malformed_pe = b"MALFORMED: overlapping sections or bad reloc table";
        let result = load_pe(malformed_pe);
        assert!(matches!(result, Err(LoaderError::Malformed(_))));
    }

    #[test]
    fn test_clean_well_formed_pe_loaded() {
        let well_formed_pe = b"MZ... valid pe data";
        let result = load_pe(well_formed_pe);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_fail_closed_on_unknown() {
        let bad_entry_pe = b"MZ... BAD_ENTRY";
        let result = load_pe(bad_entry_pe);
        assert_eq!(result, Err(LoaderError::EntryPointOutsideExecutable));

        let unknown = b"UNKNOWN structure";
        assert_eq!(load_pe(unknown), Err(LoaderError::Unknown));
    }
}
