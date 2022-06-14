//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Error, Formatter};

#[derive(Hash, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct ByteBuffer {
    pub buffer: Vec<u8>,
}

impl ByteBuffer {
    pub fn from_slice(v: &[u8]) -> ByteBuffer {
        ByteBuffer { buffer: v.to_vec() }
    }
}

impl Display for ByteBuffer {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        //todo : fix me with proper formatting
        for b in self.buffer.iter() {
            write!(f, "{:X}", b)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_bytebuffer_display() {
        let b = ByteBuffer {
            buffer: 0x12345678u32.to_le_bytes().to_vec(),
        };
        assert_eq!(
            format!("The ByteBuffer is: {}", b),
            "The ByteBuffer is: 78563412"
        );
    }
}
