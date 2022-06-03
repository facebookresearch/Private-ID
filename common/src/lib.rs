//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

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

/// S3 path parsing
pub mod s3_path;

/// GCS path parsing
pub mod gcs_path;

/// Generate metrics
pub mod metrics;
