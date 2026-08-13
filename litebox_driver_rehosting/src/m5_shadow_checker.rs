#[derive(Debug, PartialEq)]
pub enum ShadowError {
    UnboundedWrite,
    DistinctEvent,
    InvalidLengths,
}

pub fn check_write(in_len: usize, out_len: usize, write_offset: usize) -> Result<(), ShadowError> {
    // If output is somehow larger than input (just for sanity in this specific problem domain)
    // or if the test defines an invalid setup
    if in_len == 0 {
        return Err(ShadowError::InvalidLengths);
    }

    // write > InLen -> distinct physical event
    if write_offset >= in_len {
        return Err(ShadowError::DistinctEvent);
    }

    // write >= OutLen -> UNBOUNDED_WRITE (OOB within N)
    if write_offset >= out_len {
        return Err(ShadowError::UnboundedWrite);
    }

    // write < OutLen -> silent
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sploit_unbounded_write() {
        // InLen=64, OutLen=8, write=32 -> UNBOUNDED_WRITE (OOB within N)
        assert_eq!(check_write(64, 8, 32), Err(ShadowError::UnboundedWrite));
        // High-water mark > OutputBufferLength
        assert_eq!(check_write(64, 8, 8), Err(ShadowError::UnboundedWrite));
    }

    #[test]
    fn test_clean_silent_write() {
        // write=8 (assuming offset is 0-7, which is < 8) -> silent
        assert_eq!(check_write(64, 8, 7), Ok(()));
        assert_eq!(check_write(64, 8, 0), Ok(()));
    }

    #[test]
    fn test_clean_distinct_event() {
        // write=128 -> distinct physical event
        assert_eq!(check_write(64, 8, 128), Err(ShadowError::DistinctEvent));
    }

    #[test]
    fn test_fail_closed() {
        assert_eq!(check_write(0, 0, 0), Err(ShadowError::InvalidLengths));
    }
}
