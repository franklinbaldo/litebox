// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Mach semaphore emulation.
//!
//! Implements counting semaphores using the litebox `Waker` / `WaitContext`
//! API.  Semaphores are lazily created on first use (since `semaphore_create`
//! is a MIG call we don't fully emulate).

use alloc::collections::{BTreeMap, VecDeque};
use litebox::event::wait::{WaitError, Waker};

use crate::{Platform, ShimFS, Task};

/// Per-semaphore state.
struct SemaphoreState {
    /// Signed count — negative means that many waiters are blocked.
    count: i32,
    /// Queue of blocked waiters (FIFO).
    waiters: VecDeque<Waker<Platform>>,
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
            && let Some(waker) = sem.waiters.pop_front()
        {
            waker.wake();
        }
        KERN_SUCCESS
    }

    /// `semaphore_signal_all_trap(mach_port_name_t signal_name)`
    ///
    /// Wake all waiters. Set count to max(count, 0).
    pub(crate) fn signal_all(&self, port: u32) -> usize {
        let mut guard = self.semaphores.lock();
        let sem = Self::get_or_create(&mut guard, port);
        for waker in sem.waiters.drain(..) {
            waker.wake();
        }
        if sem.count < 0 {
            sem.count = 0;
        }
        KERN_SUCCESS
    }
}

impl<FS: ShimFS> Task<FS> {
    /// `semaphore_wait_trap(mach_port_name_t wait_name)`
    ///
    /// Decrement count. If count < 0, push waker and block until woken.
    pub(crate) fn sys_semaphore_wait(&self, port: u32) -> usize {
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
            sem.waiters.push_back(cx.waker().clone());
            // Drop lock before blocking.
        }
        // Block until woken.
        let cx = self.wait_cx();
        match cx.wait_until(|| {
            // We've been woken by signal/signal_all — check is trivially true.
            // The waker was already consumed from the queue by the signaler.
            true
        }) {
            Ok(()) => KERN_SUCCESS,
            Err(WaitError::Interrupted) => KERN_ABORTED,
            Err(WaitError::TimedOut) => KERN_OPERATION_TIMED_OUT,
        }
    }

    /// `semaphore_timedwait_trap(mach_port_name_t wait_name, unsigned int sec,
    ///     clock_res_t nsec)`
    ///
    /// Same as wait but with timeout.
    pub(crate) fn sys_semaphore_timedwait(&self, port: u32, sec: u32, nsec: u32) -> usize {
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
            sem.waiters.push_back(cx.waker().clone());
            // Drop lock before blocking.
        }
        // Block with timeout.
        let timeout = core::time::Duration::new(u64::from(sec), nsec);
        let cx = self.wait_cx().with_timeout(timeout);
        match cx.wait_until(|| true) {
            Ok(()) => KERN_SUCCESS,
            Err(WaitError::TimedOut) => KERN_OPERATION_TIMED_OUT,
            Err(WaitError::Interrupted) => KERN_ABORTED,
        }
    }
}
