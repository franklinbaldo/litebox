// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg_attr(not(feature = "unix"), no_std)]

//! Broker transport implementations.
//!
//! Transports own hosted or platform-specific framing and I/O. Portable broker
//! protocol messages, local-side adapters, host-side request handling, and core
//! authority state live in separate crates.

#[cfg(feature = "unix")]
pub mod unix_socket;
