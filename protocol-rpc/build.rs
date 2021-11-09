//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("proto/common.proto")
        .unwrap_or_else(|e| panic!("Failed to compile protos {:?}", e));
    tonic_build::compile_protos("proto/privateid.proto")
        .unwrap_or_else(|e| panic!("Failed to compile protos {:?}", e));
    tonic_build::compile_protos("proto/privateidmultikey.proto")
        .unwrap_or_else(|e| panic!("Failed to compile protos {:?}", e));
    tonic_build::compile_protos("proto/crosspsi.proto")
        .unwrap_or_else(|e| panic!("Failed to compile protos {:?}", e));
    tonic_build::compile_protos("proto/crosspsixor.proto")
        .unwrap_or_else(|e| panic!("Failed to compile protos {:?}", e));
    tonic_build::compile_protos("proto/pjc.proto")
        .unwrap_or_else(|e| panic!("Failed to compile protos {:?}", e));
    tonic_build::compile_protos("proto/suidcreate.proto")
        .unwrap_or_else(|e| panic!("Failed to compile protos {:?}", e));
    Ok(())
}
