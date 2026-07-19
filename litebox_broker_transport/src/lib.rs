// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg_attr(not(all(feature = "unix", target_os = "linux")), no_std)]

//! Broker transport implementations.
//!
//! Transports own hosted or platform-specific framing and I/O. Portable broker
//! protocol messages, local-side adapters, host-side request handling, and core
//! authority state live in separate crates.

#[cfg(all(feature = "unix", target_os = "linux"))]
pub mod unix_socket;
