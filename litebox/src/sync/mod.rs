// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Higher-level synchronization primitives
//!
//! The implementation for some of the components in this module (specifically, [`Mutex`] and
//! [`RwLock`]) is derived from related source files in Rust's `std`. See `./cgmanifest.json` for a
//! declaration of the specific commit hashes. The files have been modified significantly to support
//! invoking through the [`platform`], rather than through regular system interfaces. Additionally,
//! support is added tracing locks through the `lock_tracing` conditional-compilation feature that
//! can aid in debugging.

use crate::platform;

mod condvar;
pub mod futex;
mod mutex;
mod rwlock;

#[cfg(feature = "lock_tracing")]
pub(crate) mod lock_tracing;

#[cfg(feature = "lock_tracing")]
pub use lock_tracing::{RecordingSummary, flush_to_jsonl, start_recording, stop_recording};

pub use condvar::Condvar;
pub use mutex::{Mutex, MutexGuard};
pub use rwlock::{
    MappedRwLockReadGuard, MappedRwLockWriteGuard, RwLock, RwLockReadGuard, RwLockWriteGuard,
};

#[cfg(not(any(feature = "lock_tracing", feature = "trace_fs")))]
/// A convenience name for specific requirements from the platform
pub trait RawSyncPrimitivesProvider: platform::RawMutexProvider + Sync + 'static {}
#[cfg(not(any(feature = "lock_tracing", feature = "trace_fs")))]
impl<Platform> RawSyncPrimitivesProvider for Platform where
    Platform: platform::RawMutexProvider + Sync + 'static
{
}

// When `trace_fs` is enabled, filesystem tracing code logs through
// `DebugLogProvider`. Since the platform type is threaded through
// `RawSyncPrimitivesProvider` in fs-related contexts, the bound is added here
// so it is available wherever the platform is used. `lock_tracing` already
// includes `DebugLogProvider`, so this branch only applies when `trace_fs` is
// enabled without `lock_tracing`.
#[cfg(all(feature = "trace_fs", not(feature = "lock_tracing")))]
/// A convenience name for specific requirements from the platform
pub trait RawSyncPrimitivesProvider:
    platform::RawMutexProvider + platform::DebugLogProvider + Sync + 'static
{
}
#[cfg(all(feature = "trace_fs", not(feature = "lock_tracing")))]
impl<Platform> RawSyncPrimitivesProvider for Platform where
    Platform: platform::RawMutexProvider + platform::DebugLogProvider + Sync + 'static
{
}

#[cfg(feature = "lock_tracing")]
/// A convenience name for specific requirements from the platform
pub trait RawSyncPrimitivesProvider:
    platform::RawMutexProvider + platform::TimeProvider + platform::DebugLogProvider + Sync + 'static
{
}
#[cfg(feature = "lock_tracing")]
impl<Platform> RawSyncPrimitivesProvider for Platform where
    Platform: platform::RawMutexProvider
        + platform::TimeProvider
        + platform::DebugLogProvider
        + Sync
        + 'static
{
}
