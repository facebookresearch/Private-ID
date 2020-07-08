//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

pub use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar,
    scalar::Scalar,
};

pub use paillier::EncryptionKey;

pub use crate::spoint::ByteBuffer;
pub use paillier::BigInt;

pub type TPayload = Vec<ByteBuffer>;
pub type TPoint = RistrettoPoint;
pub type TScalar = Scalar;
pub type TypeHeEncKey = EncryptionKey;

pub const PAILLIER_PUBLIC_KEY_SIZE: usize = 2048;

pub use crate::he::domain::*;
