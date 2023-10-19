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
        "dpmccompany.proto",
        "dpmcpartner.proto",
        "dspmccompany.proto",
        "dspmchelper.proto",
        "dspmcpartner.proto",
    ];
    let out_env = if cfg!(fbcode_build) { "OUT" } else { "OUT_DIR" };
    let out_dir = std::env::var_os(out_env).unwrap_or_else(|| panic!("env `{out_env}` is not set"));

    tonic_build::configure()
        .out_dir(out_dir)
        .compile(
            proto_files,
            // HACK: we need '.' directory for build with Buck
            &[".", grpc_path],
        )
        .unwrap();

    Ok(())
}
