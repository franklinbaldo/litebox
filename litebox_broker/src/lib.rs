// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Litebox File Broker — policy-enforced external file access for sandboxed
//! processes.
//!
//! This crate provides both a library (proto types + client re-exports) and a
//! standalone broker binary.

pub mod policy;
pub mod server;

/// Auto-generated protobuf / gRPC types for the `FileBroker` service.
pub mod proto {
    tonic::include_proto!("litebox.broker");
}
