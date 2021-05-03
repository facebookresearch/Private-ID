//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

pub use curve25519_dalek::{
    constants::{BASEPOINT_ORDER, RISTRETTO_BASEPOINT_TABLE},
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar,
    scalar::Scalar,
    traits::Identity,
};

pub use crate::spoint::ByteBuffer;
pub use paillier::BigInt;

pub type TPayload = Vec<ByteBuffer>;
pub type TPoint = RistrettoPoint;
pub type TScalar = Scalar;

#[cfg(not(target_arch = "wasm32"))]
pub use paillier::EncryptionKey;

#[cfg(not(target_arch = "wasm32"))]
pub type TypeHeEncKey = EncryptionKey;

#[cfg(not(target_arch = "wasm32"))]
pub const PAILLIER_PUBLIC_KEY_SIZE: usize = 2048;

#[cfg(not(target_arch = "wasm32"))]
pub use crate::he::domain::*;
