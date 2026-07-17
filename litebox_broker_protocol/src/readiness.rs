// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Object-neutral readiness values shared by broker notifications.

/// Object-neutral readiness flags carried by broker notifications.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadinessFlags(u32);

impl ReadinessFlags {
    /// Reading can complete without blocking.
    pub const READ: Self = Self(1 << 0);
    /// Writing can complete without blocking.
    pub const WRITE: Self = Self(1 << 1);
    /// A stream or pipe write peer has closed.
    pub const HANGUP: Self = Self(1 << 2);
    /// An object has an error condition.
    pub const ERROR: Self = Self(1 << 3);

    /// Constructs readiness flags while retaining unknown future bits.
    pub const fn from_bits_retain(bits: u32) -> Self {
        Self(bits)
    }

    /// Returns the raw readiness bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Returns whether all bits in `other` are present.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl core::ops::BitOr for ReadinessFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}
