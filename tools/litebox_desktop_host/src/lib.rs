// Copyright (c) franklinbaldo.
// Licensed under the MIT license.

//! LiteBox Desktop Host library.
//!
//! Provides reusable host components such as WinMM audio and desktop protocol.

pub mod audio;
pub mod protocol;

pub use audio::{AudioMetrics, WinMMAudio};
