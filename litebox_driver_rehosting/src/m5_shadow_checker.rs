#[derive(Debug, PartialEq)]
pub enum ShadowError {
    UnboundedWrite,
    DistinctEvent,
    InvalidLengths,
}

pub fn check_write(in_len: usize, out_len: usize, writes: &[(usize, usize)]) -> Result<(), ShadowError> {
    if in_len == 0 {
        return Err(ShadowError::InvalidLengths);
    }

    let mut high_water_mark = 0;

    for &(offset, length) in writes {
        let end = offset + length;

        // write > InLen -> distinct physical event
        if end > in_len {
            return Err(ShadowError::DistinctEvent);
        }

        if end > high_water_mark {
            high_water_mark = end;
        }
    }

    // write > OutLen -> UNBOUNDED_WRITE (OOB within N)
    if high_water_mark > out_len {
        return Err(ShadowError::UnboundedWrite);
    }

    // write <= OutLen -> silent
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sploit_unbounded_write() {
        // InLen=64, OutLen=8, write=32 -> UNBOUNDED_WRITE (OOB within N)
        // A single write of length 32 at offset 0 ends at 32 > 8
        assert_eq!(check_write(64, 8, &[(0, 32)]), Err(ShadowError::UnboundedWrite));

        // High-water mark > OutputBufferLength
        assert_eq!(check_write(64, 8, &[(0, 4), (4, 5)]), Err(ShadowError::UnboundedWrite)); // Ends at 9 > 8
    }

    #[test]
    fn test_clean_silent_write() {
        // write=8 -> silent (high-water mark == OutputBufferLength)
        assert_eq!(check_write(64, 8, &[(0, 8)]), Ok(()));

        // write=7 -> silent
        assert_eq!(check_write(64, 8, &[(0, 7)]), Ok(()));

        // Multiple small writes within bounds
        assert_eq!(check_write(64, 8, &[(0, 4), (4, 4)]), Ok(()));
    }

    #[test]
    fn test_clean_distinct_event() {
        // write=128 (when in_len=64) -> distinct physical event
        assert_eq!(check_write(64, 8, &[(0, 128)]), Err(ShadowError::DistinctEvent));

        // Offset beyond in_len
        assert_eq!(check_write(64, 8, &[(65, 1)]), Err(ShadowError::DistinctEvent));
    }

    #[test]
    fn test_fail_closed() {
        assert_eq!(check_write(0, 0, &[]), Err(ShadowError::InvalidLengths));
    }
}
