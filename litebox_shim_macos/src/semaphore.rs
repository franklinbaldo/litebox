// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Mach semaphore emulation.
//!
//! Implements counting semaphores using the litebox `Waker` / `WaitContext`
//! API.  Semaphores are created via the `semaphore_create` MIG handler
//! and manipulated via the Mach trap interfaces.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
use litebox::event::wait::{WaitError, Waker};

use crate::{Platform, ShimFS, Task};

/// A blocked waiter: the waker to wake plus a shared flag to signal readiness.
struct BlockedWaiter {
    waker: Waker<Platform>,
    /// Set to `true` by the signaler before calling `waker.wake()`.
    /// The waiter's `wait_until` predicate polls this flag.
    signaled: Arc<AtomicBool>,
}

/// Per-semaphore state.
struct SemaphoreState {
    /// Signed count — negative means that many waiters are blocked.
    count: i32,
    /// Queue of blocked waiters (FIFO).
    waiters: VecDeque<BlockedWaiter>,
}

/// Manager for all Mach semaphores in the process.
pub(crate) struct MachSemaphoreManager {
    semaphores: litebox::sync::Mutex<Platform, BTreeMap<u32, SemaphoreState>>,
}

/// Mach kernel return values.
const KERN_SUCCESS: usize = 0;
const KERN_ABORTED: usize = 14;
const KERN_OPERATION_TIMED_OUT: usize = 49;

impl MachSemaphoreManager {
    /// Create a new, empty manager.
    pub(crate) fn new() -> Self {
        Self {
            semaphores: litebox::sync::Mutex::new(BTreeMap::new()),
        }
    }

    /// Get or lazily create a semaphore for the given port name.
    fn get_or_create(guard: &mut BTreeMap<u32, SemaphoreState>, port: u32) -> &mut SemaphoreState {
        guard.entry(port).or_insert_with(|| SemaphoreState {
            count: 0,
            waiters: VecDeque::new(),
        })
    }

    /// `semaphore_signal_trap(mach_port_name_t signal_name)`
    ///
    /// Increment count. If count was < 0, pop one waiter and wake it.
    pub(crate) fn signal(&self, port: u32) -> usize {
        let mut guard = self.semaphores.lock();
        let sem = Self::get_or_create(&mut guard, port);
        sem.count += 1;
        if sem.count <= 0
            && let Some(waiter) = sem.waiters.pop_front()
        {
            waiter.signaled.store(true, Ordering::Release);
            waiter.waker.wake();
        }
        KERN_SUCCESS
    }

    /// `semaphore_signal_all_trap(mach_port_name_t signal_name)`
    ///
    /// Wake all waiters. Set count to max(count, 0).
    pub(crate) fn signal_all(&self, port: u32) -> usize {
        let mut guard = self.semaphores.lock();
        let sem = Self::get_or_create(&mut guard, port);
        for waiter in sem.waiters.drain(..) {
            waiter.signaled.store(true, Ordering::Release);
            waiter.waker.wake();
        }
        if sem.count < 0 {
            sem.count = 0;
        }
        KERN_SUCCESS
    }

    /// Register a newly created semaphore with the given port name and
    /// initial value.  Called by the `semaphore_create` MIG handler.
    pub(crate) fn create(&self, port: u32, initial_value: i32) {
        let mut guard = self.semaphores.lock();
        guard.insert(
            port,
            SemaphoreState {
                count: initial_value,
                waiters: VecDeque::new(),
            },
        );
    }

    /// Destroy a semaphore, waking any blocked waiters.  Called by the
    /// `semaphore_destroy` MIG handler.  Returns `true` if the semaphore
    /// existed.
    pub(crate) fn destroy(&self, port: u32) -> bool {
        let mut guard = self.semaphores.lock();
        if let Some(mut sem) = guard.remove(&port) {
            // Wake all blocked waiters so they don't hang forever.
            for waiter in sem.waiters.drain(..) {
                waiter.signaled.store(true, Ordering::Release);
                waiter.waker.wake();
            }
            true
        } else {
            false
        }
    }
}

impl<FS: ShimFS> Task<FS> {
    /// `semaphore_wait_trap(mach_port_name_t wait_name)`
    ///
    /// Decrement count. If count < 0, push waker and block until woken.
    pub(crate) fn sys_semaphore_wait(&self, port: u32) -> usize {
        let signaled = Arc::new(AtomicBool::new(false));

        // Decrement and check under lock.
        {
            let mut guard = self.global.semaphore_manager.semaphores.lock();
            let sem = MachSemaphoreManager::get_or_create(&mut guard, port);
            sem.count -= 1;
            if sem.count >= 0 {
                return KERN_SUCCESS;
            }
            // Need to block — register waker while holding lock.
            let cx = self.wait_cx();
            sem.waiters.push_back(BlockedWaiter {
                waker: cx.waker().clone(),
                signaled: Arc::clone(&signaled),
            });
            // Drop lock before blocking.
        }
        // Block until signaled.
        let cx = self.wait_cx();
        match cx.wait_until(|| signaled.load(Ordering::Acquire)) {
            Ok(()) => KERN_SUCCESS,
            Err(WaitError::Interrupted) => {
                self.cancel_wait(port, &signaled);
                KERN_ABORTED
            }
            Err(WaitError::TimedOut) => {
                // Untimed wait shouldn't time out, but handle defensively.
                self.cancel_wait(port, &signaled);
                KERN_OPERATION_TIMED_OUT
            }
        }
    }

    /// `semaphore_timedwait_trap(mach_port_name_t wait_name, unsigned int sec,
    ///     clock_res_t nsec)`
    ///
    /// Same as wait but with timeout.
    pub(crate) fn sys_semaphore_timedwait(&self, port: u32, sec: u32, nsec: u32) -> usize {
        let signaled = Arc::new(AtomicBool::new(false));

        // Decrement and check under lock.
        {
            let mut guard = self.global.semaphore_manager.semaphores.lock();
            let sem = MachSemaphoreManager::get_or_create(&mut guard, port);
            sem.count -= 1;
            if sem.count >= 0 {
                return KERN_SUCCESS;
            }
            // Need to block — register waker while holding lock.
            let cx = self.wait_cx();
            sem.waiters.push_back(BlockedWaiter {
                waker: cx.waker().clone(),
                signaled: Arc::clone(&signaled),
            });
            // Drop lock before blocking.
        }
        // Block with timeout.
        let timeout = core::time::Duration::new(u64::from(sec), nsec);
        let cx = self.wait_cx().with_timeout(timeout);
        match cx.wait_until(|| signaled.load(Ordering::Acquire)) {
            Ok(()) => KERN_SUCCESS,
            Err(WaitError::TimedOut) => {
                self.cancel_wait(port, &signaled);
                KERN_OPERATION_TIMED_OUT
            }
            Err(WaitError::Interrupted) => {
                self.cancel_wait(port, &signaled);
                KERN_ABORTED
            }
        }
    }

    /// Cancel a wait that timed out or was interrupted.
    ///
    /// Removes our waiter from the queue (if still present) and restores
    /// the count.  If the signaler already consumed our waiter (signaled
    /// flag is true), the count was already adjusted by the signaler, so
    /// we don't need to undo anything.
    fn cancel_wait(&self, port: u32, signaled: &Arc<AtomicBool>) {
        let mut guard = self.global.semaphore_manager.semaphores.lock();
        if let Some(sem) = guard.get_mut(&port) {
            // Check if we were signaled between the wait_until return and
            // acquiring the lock.  If so, the signal already consumed our
            // slot — don't double-undo.
            if signaled.load(Ordering::Acquire) {
                return;
            }
            // Remove our waiter from the queue and undo the count decrement.
            sem.waiters.retain(|w| !Arc::ptr_eq(&w.signaled, signaled));
            sem.count += 1;
        }
    }
}
