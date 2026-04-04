// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared-memory ring buffer IPC types for communication between micro-LiteBox
//! (in-process guest agent) and central LiteBox (host process).

#![no_std]

extern crate alloc;

pub mod cq;
pub mod messages;
pub mod pipe;
pub mod ring;
pub mod socket_ring;
pub mod sq;
pub mod wait;
