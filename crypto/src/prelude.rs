//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

pub use curve25519_dalek::constants::BASEPOINT_ORDER;
pub use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
pub use curve25519_dalek::ristretto::CompressedRistretto;
pub use curve25519_dalek::ristretto::RistrettoPoint;
pub use curve25519_dalek::scalar;
pub use curve25519_dalek::scalar::Scalar;
pub use curve25519_dalek::traits::Identity;
pub use curve25519_dalek::traits::IsIdentity;

pub use crate::spoint::ByteBuffer;

pub type TPayload = Vec<ByteBuffer>;
pub type TPoint = RistrettoPoint;
pub type TScalar = Scalar;

#[cfg(not(target_arch = "wasm32"))]
pub use crate::paillier::EncryptionKey;

#[cfg(not(target_arch = "wasm32"))]
pub type TypeHeEncKey = EncryptionKey;

#[cfg(not(target_arch = "wasm32"))]
pub const PAILLIER_PUBLIC_KEY_SIZE: usize = 2048;
