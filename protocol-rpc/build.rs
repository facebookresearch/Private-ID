//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let grpc_path = "proto";
    let proto_files = &[
        "common.proto",
        "privateid.proto",
        "privateidmultikey.proto",
        "crosspsi.proto",
        "crosspsixor.proto",
        "pjc.proto",
        "suidcreate.proto",
    ];

    tonic_build::configure()
        .out_dir(std::env::var("OUT").unwrap())
        .compile(
            proto_files,
            // HACK: we need '.' directory for build with Buck
            &[".", grpc_path],
        )
        .unwrap();

    Ok(())
}
