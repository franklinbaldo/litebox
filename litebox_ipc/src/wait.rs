// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Adaptive spin-then-wait primitives for IPC synchronisation.
//!
//! These functions are platform-agnostic — the actual futex syscall (or
//! equivalent) is supplied by the caller as a callback.

use core::hint::spin_loop;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering::Acquire;

/// Number of busy-spin iterations in phase 1.
pub const SPIN_ITERS: u32 = 200;

/// Number of exponential back-off rounds in phase 2.
pub const BACKOFF_ROUNDS: u32 = 8;

/// Three-phase adaptive wait on an atomic address.
///
/// Returns as soon as `addr.load(Acquire) != expected`.
///
/// 1. **Phase 1 — busy spin**: up to [`SPIN_ITERS`] iterations with
///    `spin_loop()` hints.
/// 2. **Phase 2 — exponential back-off**: [`BACKOFF_ROUNDS`] rounds of
///    `1 << round.min(6)` `spin_loop()` iterations each.
/// 3. **Phase 3 — wait callback**: repeatedly calls `wait_fn(addr, expected)`
///    until the value changes. The callback should block the thread (e.g. via
///    `futex_wait`) when `*addr == expected`.
pub fn spin_then_wait(addr: &AtomicU32, expected: u32, wait_fn: impl Fn(&AtomicU32, u32)) {
    // Phase 1: busy spin.
    for _ in 0..SPIN_ITERS {
        if addr.load(Acquire) != expected {
            return;
        }
        spin_loop();
    }

    // Phase 2: exponential back-off.
    for round in 0..BACKOFF_ROUNDS {
        let iters = 1u32 << round.min(6);
        for _ in 0..iters {
            if addr.load(Acquire) != expected {
                return;
            }
            spin_loop();
        }
    }

    // Phase 3: wait callback.
    loop {
        if addr.load(Acquire) != expected {
            return;
        }
        wait_fn(addr, expected);
    }
}

/// Busy-wait until `addr` no longer equals `expected`.
///
/// # Warning
///
/// This function will spin **indefinitely** if the value never changes. Only
/// use it when you are certain the value will be updated promptly (e.g. during
/// very short critical sections).
pub fn spin_only(addr: &AtomicU32, expected: u32) {
    loop {
        if addr.load(Acquire) != expected {
            return;
        }
        spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::Ordering::Relaxed;

    #[test]
    fn spin_only_returns_when_value_changes() {
        let addr = AtomicU32::new(1);
        // expected is 0, but the value is 1, so it should return immediately.
        spin_only(&addr, 0);
        // If we get here, the function returned as expected.
        assert_eq!(addr.load(Relaxed), 1);
    }

    #[test]
    fn spin_then_wait_returns_immediately_when_not_equal() {
        let addr = AtomicU32::new(1);
        // expected is 0, value is 1 — should return in phase 1 without
        // ever reaching the wait callback.
        spin_then_wait(&addr, 0, |_, _| {
            panic!("wait_fn should never be called when value != expected");
        });
        assert_eq!(addr.load(Relaxed), 1);
    }
}
