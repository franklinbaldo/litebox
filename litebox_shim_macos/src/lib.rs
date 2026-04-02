// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A shim that provides a macOS-compatible ABI via LiteBox.

#![no_std]
#![cfg(target_arch = "aarch64")]

extern crate alloc;
