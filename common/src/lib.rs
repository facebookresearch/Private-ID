//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
#![crate_name = "common"]

#[macro_use]
extern crate log;
extern crate rayon;

/// Simple timer
pub mod timer;

/// Simple file io
pub mod files;

/// Collections utils
pub mod vectors;

/// Permutation utils
pub mod permutations;
