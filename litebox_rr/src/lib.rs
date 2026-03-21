// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Core data types and binary serialization for the LiteBox record-and-replay
//! trace format.

#![no_std]
extern crate alloc;

pub mod recorder;
pub mod replayer;
pub mod trace;
