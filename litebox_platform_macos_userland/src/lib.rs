// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox on userland macOS (Apple Silicon).

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

extern crate alloc;

/// The userland macOS platform.
pub struct MacosUserland;
