// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Adaptive spin-then-wait primitives for IPC synchronisation.
//!
//! These functions are platform-agnostic — the actual futex syscall (or
//! equivalent) is supplied by the caller as a callback.

use core::hint::spin_loop;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering::Acquire;

/// Number of busy-spin iterations before falling to futex.
///
/// On an AMD EPYC 7763 VM, each PAUSE iteration takes ~10 ns.
/// 10,000 iterations ≈ 100 µs spin window — long enough to catch
/// the vast majority of IPC round-trips without kernel overhead,
/// while still yielding CPU for multi-process workloads.
pub const SPIN_ITERS: u32 = 10_000;

/// Three-phase adaptive wait on an `AtomicU32` address.
///
/// Returns as soon as `addr.load(Acquire) != expected`.
///
/// 1. **Phase 1 — busy spin**: up to [`SPIN_ITERS`] iterations with
///    `spin_loop()` hints.
/// 2. **Phase 2 — wait callback**: repeatedly calls `wait_fn(addr, expected)`
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

    // Phase 2: wait callback (typically futex).
    loop {
        if addr.load(Acquire) != expected {
            return;
        }
        wait_fn(addr, expected);
    }
}

/// Spin on an `AtomicU8` with futex fallback on an `AtomicU32`.
///
/// Spins on `spin_addr` (e.g. an SQ entry's `ready` flag) for up to
/// [`SPIN_ITERS`] iterations. If the value hasn't changed, falls back
/// to a futex wait on `futex_addr` (e.g. `sq_notify`).
///
/// This is used when the fast-path check is on a `u8` field but the
/// futex fallback must target a `u32` (Linux futex requires 4-byte
/// aligned `u32`).
pub fn spin_u8_then_wait_u32(
    spin_addr: &AtomicU8,
    spin_expected: u8,
    futex_addr: &AtomicU32,
    wait_fn: impl Fn(&AtomicU32, u32),
) {
    // Phase 1: busy spin on the u8 address.
    for _ in 0..SPIN_ITERS {
        if spin_addr.load(Acquire) != spin_expected {
            return;
        }
        spin_loop();
    }

    // Phase 2: futex wait on the u32 address.
    loop {
        if spin_addr.load(Acquire) != spin_expected {
            return;
        }
        // Re-read the futex address — it may have advanced since our
        // earlier read. If it differs from the expected value, the
        // futex_wait will return immediately (spurious wake).
        let current = futex_addr.load(Acquire);
        if spin_addr.load(Acquire) != spin_expected {
            return;
        }
        wait_fn(futex_addr, current);
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

/// Like [`spin_only`] but for `AtomicU8` (e.g. SQ entry `ready` flags).
pub fn spin_only_u8(addr: &AtomicU8, expected: u8) {
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
