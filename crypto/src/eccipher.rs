//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate curve25519_dalek;
extern crate rand_core;
extern crate rayon;
extern crate sha2;

use crate::random::CsRng;  // web-capable abstraction replacing rand_core::OsRng
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use sha2::Sha512;
use std::fmt::{Debug, Error, Formatter};

use crate::prelude::{ByteBuffer, CompressedRistretto, RistrettoPoint, Scalar};

/// Two base crypt-operations that we need to have Private-Id happen
///
/// The trait aims to interface sequential and parallel implementations
///
/// Actual EC curve operations are driven by [Dalek](https://doc.dalek.rs/x25519_dalek/index.html)
pub trait ECCipher {
    type Item;

    /// Given the point on a curve, exponentiates it to the power `pow`
    fn encrypt(&self, points: &[Self::Item], pow: &Scalar) -> Vec<Self::Item>;

    /// Mapping plain text to EC Curve using Sha512
    /// and exponentiating the point to `key` power
    fn hash_encrypt(&self, plaintext: &[String], key: &Scalar) -> Vec<Self::Item>;

    /// Serializes the points to bytes representation
    fn to_bytes(&self, points: &[Self::Item]) -> Vec<ByteBuffer>;

    /// exponentiates and serializes the point
    fn encrypt_to_bytes(&self, points: &[Self::Item], pow: &Scalar) -> Vec<ByteBuffer>;

    /// Combining encryption and serialization for better resource utilisation
    fn hash_encrypt_to_bytes(&self, plaintext: &[String], key: &Scalar) -> Vec<ByteBuffer>;

    /// Deserializes the points
    fn to_points(&self, payload: &[ByteBuffer]) -> Vec<Self::Item>;

    /// Deserializes the point and makes exponentiation after that
    fn to_points_encrypt(&self, payload: &[ByteBuffer], pow: &Scalar) -> Vec<Self::Item>;
}

/// Sequential impl of `ECCipher`
///
/// All transformations are single-threaded
pub struct ECRistrettoSequential {}

impl ECRistrettoSequential {
    pub fn new() -> ECRistrettoSequential {
        ECRistrettoSequential {}
    }
    pub fn default() -> ECRistrettoSequential {
        ECRistrettoSequential::new()
    }
}

impl ECCipher for ECRistrettoSequential {
    type Item = RistrettoPoint;

    fn hash_encrypt(&self, plaintext: &[String], key: &Scalar) -> Vec<Self::Item> {
        plaintext
            .iter()
            .map(|text| {
                let p: RistrettoPoint = RistrettoPoint::hash_from_bytes::<Sha512>(text.as_bytes());
                p * key
            })
            .collect::<Vec<Self::Item>>()
    }

    fn hash_encrypt_to_bytes(&self, plaintext: &[String], key: &Scalar) -> Vec<ByteBuffer> {
        plaintext
            .iter()
            .map(|text| {
                let p = RistrettoPoint::hash_from_bytes::<Sha512>(text.as_bytes()) * key;
                ByteBuffer::from_slice(&p.compress().to_bytes())
            })
            .collect::<Vec<ByteBuffer>>()
    }

    fn encrypt(&self, points: &[Self::Item], pow: &Scalar) -> Vec<Self::Item> {
        points.iter().map(|p| p * pow).collect::<Vec<Self::Item>>()
    }

    fn encrypt_to_bytes(&self, points: &[Self::Item], pow: &Scalar) -> Vec<ByteBuffer> {
        points
            .iter()
            .map(|p| {
                let z: RistrettoPoint = p * pow;
                ByteBuffer::from_slice(&z.compress().to_bytes())
            })
            .collect::<Vec<_>>()
    }

    fn to_bytes(&self, points: &[Self::Item]) -> Vec<ByteBuffer> {
        points
            .iter()
            .map(|p| ByteBuffer::from_slice(&p.compress().to_bytes()))
            .collect::<Vec<_>>()
    }

    fn to_points(&self, payload: &[ByteBuffer]) -> Vec<Self::Item> {
        payload
            .iter()
            .map(|b| {
                CompressedRistretto::from_slice(&b.buffer)
                    .decompress()
                    .unwrap()
            })
            .collect::<Vec<_>>()
    }

    fn to_points_encrypt(&self, payload: &[ByteBuffer], pow: &Scalar) -> Vec<Self::Item> {
        payload
            .iter()
            .map(|b| {
                let p = CompressedRistretto::from_slice(&b.buffer)
                    .decompress()
                    .unwrap();
                p * pow
            })
            .collect::<Vec<_>>()
    }
}

impl Default for ECRistrettoSequential {
    fn default() -> Self {
        Self::new()
    }
}

/// Parallel impl of `ECCipher`
///
/// Multithreaded component happens via `rayon` crate.
///
/// A high-level api aims to spawn as many threads as "it makes sense" for the job
///
/// # Parameters
///
/// chunk_size - The input vectors will be chunked first before sending it to vectors
///
/// Encryption based on parallel iterator from rayon
///
/// # Example
///
/// ```
/// extern crate curve25519_dalek;
/// use rand_core::OsRng;
/// use curve25519_dalek::scalar::Scalar;
/// use crypto::eccipher;
/// let mut rng = OsRng;
/// let (key, power) = (Scalar::random(&mut rng), Scalar::random(&mut rng));
/// let eccipher = eccipher::ECRistrettoParallel::default();
///
/// let text = vec!["a", "b", "c"].iter().map(|x| String::from(*x)).collect::<Vec<_>>();
/// ```
pub struct ECRistrettoParallel {}

impl ECRistrettoParallel {
    pub fn new() -> ECRistrettoParallel {
        ECRistrettoParallel {}
    }

    // TODO: switch to Default trait instead
    // https://doc.rust-lang.org/std/default/trait.Default.html
    pub fn default() -> ECRistrettoParallel {
        ECRistrettoParallel::new()
    }
}

impl ECCipher for ECRistrettoParallel {
    type Item = RistrettoPoint;

    // TODO: parametrise type of scalar

    /// Encryption is a two-step operation
    ///
    /// - Step1: Each string maps to curve (Sha512 is used)
    ///
    /// - Step2: Curve point exponentiates to `key` power
    fn hash_encrypt(&self, plaintext: &[String], key: &Scalar) -> Vec<Self::Item> {
        // TODO: Explore batching options, quick tests showed batching
        // gives +10-20% speedup batching in this context means
        // `par_chunks` iteration
        plaintext
            .into_par_iter()
            .map_with(key, |ctx, item| {
                let p: RistrettoPoint = RistrettoPoint::hash_from_bytes::<Sha512>(item.as_bytes());
                p * (*ctx)
            })
            .collect::<Vec<Self::Item>>()
    }

    fn encrypt(&self, points: &[Self::Item], pow: &Scalar) -> Vec<Self::Item> {
        points
            .into_par_iter()
            .map_with(pow, |ctx, item| item * (*ctx))
            .collect::<Vec<_>>()
    }

    fn to_bytes(&self, points: &[Self::Item]) -> Vec<ByteBuffer> {
        points
            .into_par_iter()
            .map(|item| ByteBuffer::from_slice(&item.compress().to_bytes()))
            .collect::<Vec<_>>()
    }

    fn to_points(&self, payload: &[ByteBuffer]) -> Vec<Self::Item> {
        payload
            .into_par_iter()
            .map(|item| {
                CompressedRistretto::from_slice(&item.buffer)
                    .decompress()
                    .unwrap()
            })
            .collect::<Vec<_>>()
    }

    fn hash_encrypt_to_bytes(&self, plaintext: &[String], key: &Scalar) -> Vec<ByteBuffer> {
        // TODO: Explore batching options, quick tests showed batching gives +10-20% speedup
        // batching in this context means `par_chunks` iteration
        plaintext
            .into_par_iter()
            .map_with(key, |ctx, item| {
                let p = RistrettoPoint::hash_from_bytes::<Sha512>(item.as_bytes()) * (*ctx);
                ByteBuffer::from_slice(&p.compress().to_bytes())
            })
            .collect::<Vec<ByteBuffer>>()
    }

    fn encrypt_to_bytes(&self, points: &[Self::Item], pow: &Scalar) -> Vec<ByteBuffer> {
        points
            .into_par_iter()
            .map_with(pow, |ctx, item| {
                let p: RistrettoPoint = item * (*ctx);
                ByteBuffer::from_slice(&p.compress().to_bytes())
            })
            .collect::<Vec<_>>()
    }

    fn to_points_encrypt(&self, payload: &[ByteBuffer], pow: &Scalar) -> Vec<Self::Item> {
        payload
            .into_par_iter()
            .map(|item| {
                let p = CompressedRistretto::from_slice(&item.buffer)
                    .decompress()
                    .unwrap();
                p * pow
            })
            .collect::<Vec<_>>()
    }
}

impl Default for ECRistrettoParallel {
    fn default() -> Self {
        Self::new()
    }
}

impl Debug for ECRistrettoSequential {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(
            f,
            "{}",
            "Ristretto EC ops sequential implementation".to_string()
        )
    }
}

impl Debug for ECRistrettoParallel {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(
            f,
            "{}",
            "Ristretto EC ops parallel implementation".to_string()
        )
    }
}

/// Generates random Scalar
///
/// the method would be used to get private keys & masking powers
///
/// the method uses
/// [CSPRNG](https://rust-num.github.io/num/rand/index.html#cryptographic-security)
/// random generator.
pub fn gen_scalar() -> Scalar {
    let mut rng = CsRng::new();
    Scalar::random(&mut rng)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vec_compare<T: PartialEq>(va: &[T], vb: &[T]) -> bool {
        (va.len() == vb.len()) &&  // zip stops at the shortest
            va.iter()
                .zip(vb)
                .all(|(a, b)| a.eq(b))
    }

    fn random_string(size: usize) -> String {
        thread_rng()
            .sample_iter(&distributions::Alphanumeric)
            .take(size)
            .collect()
    }

    fn gen_points(n: usize) -> Vec<RistrettoPoint> {
        let mut rng = CsRng::new();
        (0..n)
            .map(|_| RistrettoPoint::random(&mut rng))
            .collect::<Vec<RistrettoPoint>>()
    }

    #[test]
    fn compress_decompress_works() {
        let n = 100;
        let mut rng = CsRng::new();
        let key = Scalar::random(&mut rng);
        for _ in 0..3 {
            let items = gen_points(n);
            let seq = ECRistrettoSequential::new();
            let parr = ECRistrettoParallel::new();

            // Try API that encrypts and converts to bytes
            {
                let srlz_items_seq = seq.encrypt_to_bytes(&items, &key);
                let srlz_items_parr = parr.encrypt_to_bytes(&items, &key);

                let dcmp_seq = seq.to_points(&srlz_items_seq);
                let dcmp_parr = parr.to_points(&srlz_items_parr);

                assert_eq!(vec_compare(&srlz_items_seq, &srlz_items_parr), true);
                assert_eq!(vec_compare(&dcmp_seq, &dcmp_parr), true);
            }

            // Try APIs that encrypts and converts to bytes separately
            {
                let srlz_items_seq = seq.to_bytes(&seq.encrypt(&items, &key));
                let srlz_items_parr = parr.to_bytes(&parr.encrypt(&items, &key));

                let dcmp_seq = seq.to_points(&srlz_items_seq);
                let dcmp_parr = parr.to_points(&srlz_items_parr);

                assert_eq!(vec_compare(&srlz_items_seq, &srlz_items_parr), true);
                assert_eq!(vec_compare(&dcmp_seq, &dcmp_parr), true);
            }
        }
    }

    #[test]
    fn exp_op_is_identical_for_serial_and_parr() {
        let mut rng = CsRng::new();
        let n = 100;
        // let chunk_size = 3;
        // its important to keep the chunk size smaller
        // we need to test that the order is preserved
        // assert!(chunk_size < n);
        for _ in 0..3 {
            let key = Scalar::random(&mut rng);
            let points = gen_points(n);
            let seq = ECRistrettoSequential::new();
            let parr = ECRistrettoParallel::new();
            let res_parr = parr.encrypt(&points, &key);
            let res_seq = seq.encrypt(&points, &key);
            assert_eq!(vec_compare(&res_parr, &res_seq), true);
        }
    }

    #[test]
    fn enc_op_is_identical_for_serial_and_parr() {
        let mut rng = CsRng::new();
        let n = 100;
        // let chunk_size = 3;
        for _ in 0..10 {
            let key = Scalar::random(&mut rng);
            let text = (0..n).map(|_| random_string(16)).collect::<Vec<String>>();

            let seq = ECRistrettoSequential::default();
            let parr = ECRistrettoParallel::new();
            let res_parr = parr.hash_encrypt(&text, &key);
            let res_seq = seq.hash_encrypt(&text, &key);
            assert_eq!(vec_compare(&res_parr, &res_seq), true);
        }
    }
}
