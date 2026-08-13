use std::thread;
use std::time::Duration;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Debug, PartialEq)]
pub enum IsolationError {
    CrashContained,
    TimeBoundExceeded,
    MemoryBoundExceeded,
    UnknownFailure,
}

pub fn run_isolated<F>(payload: F) -> Result<(), IsolationError>
where
    F: FnOnce() + Send + 'static,
{
    // A primitive mock isolation wrapper. In reality, this would use job objects,
    // seccomp, namespaces, etc. Here we just use a thread with a timeout and panic catcher.
    let timeout = Duration::from_millis(100);

    let finished = Arc::new(AtomicBool::new(false));
    let finished_clone = finished.clone();

    let handle = thread::spawn(move || {
        let result = panic::catch_unwind(AssertUnwindSafe(payload));
        finished_clone.store(true, Ordering::SeqCst);
        result
    });

    let mut elapsed = Duration::from_millis(0);
    let step = Duration::from_millis(10);
    while !finished.load(Ordering::SeqCst) {
        if elapsed >= timeout {
            // In a real implementation we would kill the thread/process here
            return Err(IsolationError::TimeBoundExceeded);
        }
        thread::sleep(step);
        elapsed += step;
    }

    match handle.join() {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(_)) => Err(IsolationError::CrashContained), // Panicked inside
        Err(_) => Err(IsolationError::CrashContained), // Thread panicked
    }
}

// Memory boundary is mocked via a global check for the test
static MEMORY_LIMIT_EXCEEDED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn trigger_memory_exceeded() {
    MEMORY_LIMIT_EXCEEDED.store(true, Ordering::SeqCst);
}

pub fn run_isolated_with_mem_check<F>(payload: F) -> Result<(), IsolationError>
where
    F: FnOnce() + Send + 'static,
{
    MEMORY_LIMIT_EXCEEDED.store(false, Ordering::SeqCst);
    let result = run_isolated(payload);
    if MEMORY_LIMIT_EXCEEDED.load(Ordering::SeqCst) {
        return Err(IsolationError::MemoryBoundExceeded);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_sploit_contain_crash() {
        let result = run_isolated(|| {
            panic!("Mock crash!");
        });
        assert_eq!(result, Err(IsolationError::CrashContained));
    }

    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    #[test]
    fn test_sploit_contain_loop() {
        // Use a flag so the thread can eventually terminate after test finishes
        // to avoid leaking the thread.
        let run_flag = Arc::new(AtomicBool::new(true));
        let run_flag_clone = run_flag.clone();

        let result = run_isolated(move || {
            while run_flag_clone.load(std::sync::atomic::Ordering::SeqCst) {
                // mock infinite loop, thread will sleep to simulate work
                std::thread::sleep(Duration::from_millis(10));
            }
        });

        assert_eq!(result, Err(IsolationError::TimeBoundExceeded));
        run_flag.store(false, std::sync::atomic::Ordering::SeqCst);
    }

    #[test]
    fn test_clean_payload_exits() {
        let result = run_isolated(|| {
            // clean payload, does nothing and exits
        });
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_fail_closed() {
        let result = run_isolated_with_mem_check(|| {
            // Simulate OOM kill from outer layer
            trigger_memory_exceeded();
        });
        assert_eq!(result, Err(IsolationError::MemoryBoundExceeded));
    }
}
