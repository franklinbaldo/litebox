use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::LazyLock;

#[derive(Debug, PartialEq)]
pub enum AllocError {
    UseAfterFree,
    DoubleFree,
    OutOfBounds,
    InvalidPointer,
}

#[derive(Clone, Copy)]
enum BlockState {
    Allocated(usize), // holds size
    Freed,
}

struct AllocatorState {
    blocks: HashMap<usize, BlockState>,
    next_ptr: usize,
}

static STATE: LazyLock<Mutex<AllocatorState>> = LazyLock::new(|| {
    Mutex::new(AllocatorState {
        blocks: HashMap::new(),
        next_ptr: 0x1000,
    })
});

pub fn alloc(size: usize) -> *mut u8 {
    let mut state = STATE.lock().unwrap();
    let ptr = state.next_ptr;
    state.blocks.insert(ptr, BlockState::Allocated(size));
    state.next_ptr += 0x1000; // Keep pointers distinct
    ptr as *mut u8
}

pub fn free(ptr: *mut u8) -> Result<(), AllocError> {
    let ptr_val = ptr as usize;
    let mut state = STATE.lock().unwrap();

    if let Some(block) = state.blocks.get_mut(&ptr_val) {
        match *block {
            BlockState::Allocated(_) => {
                *block = BlockState::Freed;
                Ok(())
            }
            BlockState::Freed => Err(AllocError::DoubleFree),
        }
    } else {
        Err(AllocError::InvalidPointer)
    }
}

pub fn check_access(ptr: *mut u8, offset: usize) -> Result<(), AllocError> {
    let ptr_val = ptr as usize;
    let state = STATE.lock().unwrap();
    match state.blocks.get(&ptr_val) {
        Some(BlockState::Allocated(size)) => {
            if offset >= *size {
                Err(AllocError::OutOfBounds)
            } else {
                Ok(())
            }
        }
        Some(BlockState::Freed) => Err(AllocError::UseAfterFree),
        None => Err(AllocError::InvalidPointer),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sploit_uaf() {
        let ptr = alloc(100);
        assert_eq!(free(ptr), Ok(()));
        assert_eq!(check_access(ptr, 10), Err(AllocError::UseAfterFree));
    }

    #[test]
    fn test_sploit_double_free() {
        let ptr = alloc(100);
        assert_eq!(free(ptr), Ok(()));
        assert_eq!(free(ptr), Err(AllocError::DoubleFree));
    }

    #[test]
    fn test_sploit_oob() {
        let ptr = alloc(100);
        assert_eq!(check_access(ptr, 99), Ok(()));
        assert_eq!(check_access(ptr, 100), Err(AllocError::OutOfBounds));
        assert_eq!(free(ptr), Ok(()));
    }

    #[test]
    fn test_clean_sequence() {
        let ptr = alloc(50);
        assert_eq!(check_access(ptr, 0), Ok(()));
        assert_eq!(check_access(ptr, 49), Ok(()));
        assert_eq!(free(ptr), Ok(()));

        // clean sequence -> silent poison on freed memory
        assert_eq!(check_access(ptr, 0), Err(AllocError::UseAfterFree));
    }

    #[test]
    fn test_fail_closed() {
        // Any unknown pointer fails closed
        assert_eq!(free(0x1234 as *mut u8), Err(AllocError::InvalidPointer));
        assert_eq!(check_access(0x1234 as *mut u8, 0), Err(AllocError::InvalidPointer));
    }
}
