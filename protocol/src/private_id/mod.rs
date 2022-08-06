//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::sync::RwLock;

use common::permutations::gen_permute_pattern;
use common::timer;

#[derive(Debug)]
pub enum ProtocolError {
    ErrorDeserialization(String),
    ErrorSerialization(String),
    ErrorEncryption(String),
    ErrorCalcSetDiff(String),
    ErrorReencryption(String),
    ErrorIO(String),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "protocol error {}", self)
    }
}

impl Error for ProtocolError {}

fn fill_permute(permutation: Arc<RwLock<Vec<usize>>>, text_len: usize) {
    let _ = timer::Builder::new()
        .label("gen_permutation")
        .size(text_len)
        .build();
    let t = timer::Timer::new_silent("fill permute");
    if let Ok(mut wguard) = permutation.write() {
        if wguard.is_empty() {
            let mut pm = gen_permute_pattern(text_len);
            wguard.append(&mut pm);
            t.qps("gen permutation", pm.len())
        }
    }
}

pub mod company;
pub mod partner;
pub mod traits;
