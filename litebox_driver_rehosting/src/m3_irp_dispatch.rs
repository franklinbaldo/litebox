#[derive(Debug, PartialEq)]
pub enum DispatchError {
    TrappedOperation,
}

pub fn dispatch_irp(operation: &str) -> Result<String, DispatchError> {
    match operation {
        "IOCTL_TOY_TRANSFORM" => Ok("DETERMINISTIC_OUTPUT".to_string()),
        "DriverEntry" => Ok("ENTRY_SUCCESS".to_string()),
        _ => Err(DispatchError::TrappedOperation),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_deterministic_output() {
        // DriverEntry + 1 IOCTL (transform, not sensor) -> deterministic reproducible output
        assert_eq!(dispatch_irp("DriverEntry"), Ok("ENTRY_SUCCESS".to_string()));
        assert_eq!(dispatch_irp("IOCTL_TOY_TRANSFORM"), Ok("DETERMINISTIC_OUTPUT".to_string()));
    }

    #[test]
    fn test_sploit_unknown_behavior_trapped() {
        // unknown behavior -> TRAPPED_OPERATION
        assert_eq!(dispatch_irp("IOCTL_MALICIOUS"), Err(DispatchError::TrappedOperation));
    }

    #[test]
    fn test_fail_closed_unhandled_irp() {
        // any unhandled IRP falls back to TRAPPED_OPERATION
        assert_eq!(dispatch_irp("IRP_MJ_CREATE"), Err(DispatchError::TrappedOperation));
    }
}
