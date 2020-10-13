//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

pub use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar,
    scalar::Scalar,
};

pub use crate::spoint::ByteBuffer;

pub type Bytes = Vec<ByteBuffer>;
pub type TPayload = Bytes;
pub type TPoint = RistrettoPoint;
pub type TScalar = Scalar;

// Paillier is not supported in wasm32 nor does Private-ID use it.
#[cfg(not(target_arch = "wasm32"))]  pub use paillier::EncryptionKey;
#[cfg(not(target_arch = "wasm32"))]  pub use paillier::BigInt;

#[cfg(not(target_arch = "wasm32"))]  pub use crate::he::domain::*;

#[cfg(not(target_arch = "wasm32"))]  pub type TypeHeEncKey = EncryptionKey;

#[cfg(not(target_arch = "wasm32"))]  pub const PAILLIER_PUBLIC_KEY_SIZE: usize = 2048;