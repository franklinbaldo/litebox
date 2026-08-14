#[derive(Debug, PartialEq, Clone, Copy)]
pub enum IrqlLevel {
    Passive,
    Apc,
    Dispatch,
    Unknown,
}

#[derive(Debug, PartialEq)]
pub enum IrqlError {
    ContractEvent,
    IncompatibleLevel,
}

// Pass the state explicitly for testing to avoid global state race conditions
pub fn access_paged_pool(current: IrqlLevel) -> Result<(), IrqlError> {
    match current {
        IrqlLevel::Passive | IrqlLevel::Apc => Ok(()),
        IrqlLevel::Dispatch => Err(IrqlError::ContractEvent),
        IrqlLevel::Unknown => Err(IrqlError::IncompatibleLevel),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sploit_paged_access_at_dispatch() {
        assert_eq!(access_paged_pool(IrqlLevel::Dispatch), Err(IrqlError::ContractEvent));
    }

    #[test]
    fn test_clean_access_at_passive() {
        assert_eq!(access_paged_pool(IrqlLevel::Passive), Ok(()));
        assert_eq!(access_paged_pool(IrqlLevel::Apc), Ok(()));
    }

    #[test]
    fn test_fail_closed_incompatible_level() {
        assert_eq!(access_paged_pool(IrqlLevel::Unknown), Err(IrqlError::IncompatibleLevel));
    }
}
