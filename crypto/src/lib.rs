//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
#![crate_name = "crypto"]

pub mod eccipher;
#[cfg(not(target_arch = "wasm32"))]
pub mod he;
pub mod prelude;
pub mod spoint;
