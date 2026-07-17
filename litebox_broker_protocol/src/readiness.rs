// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Object-neutral readiness values shared by broker notifications.

/// Object-neutral readiness flags carried by broker notifications.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadinessFlags(pub u32);

impl ReadinessFlags {
    /// Reading can complete without blocking.
    pub const READ: Self = Self(1 << 0);
    /// Writing can complete without blocking.
    pub const WRITE: Self = Self(1 << 1);
    /// A stream or pipe write peer has closed.
    pub const HANGUP: Self = Self(1 << 2);
    /// An object has an error condition.
    pub const ERROR: Self = Self(1 << 3);
}

impl core::ops::BitOr for ReadinessFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}
