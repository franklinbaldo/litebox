// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile_protos(&["proto/broker.proto"], &["proto"])?;
    Ok(())
}
