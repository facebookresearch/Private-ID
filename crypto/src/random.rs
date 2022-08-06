//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

// Web-capable implementation of RngCore to replace the one in rand_core::OsRng

use std::io::Write;

use rand_core::CryptoRng;
use rand_core::RngCore;

use self::rand::prelude::ThreadRng;
use self::rand::Rng;
use self::rand_core::Error;

pub struct CsRng {
    rng: ThreadRng,
}

impl CsRng {
    pub fn new() -> CsRng {
        CsRng {
            rng: rand::thread_rng(),
        }
    }
}

impl CryptoRng for CsRng {}

impl RngCore for CsRng {
    fn next_u32(&mut self) -> u32 {
        self.rng.gen()
    }

    fn next_u64(&mut self) -> u64 {
        self.rng.gen()
    }

    fn fill_bytes(&mut self, mut dest: &mut [u8]) {
        let l = dest.len();
        for _ in 0..l {
            let d = [self.rng.gen()];
            dest.write(&d).unwrap();
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
