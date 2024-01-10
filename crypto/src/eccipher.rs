//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::fmt::Error;
use std::fmt::Formatter;

use rand::rngs::OsRng;
use rand::RngCore;
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;
use sha2::Sha512;

use crate::prelude::ByteBuffer;
use crate::prelude::CompressedRistretto;
use crate::prelude::RistrettoPoint;
use crate::prelude::Scalar;

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
    fn hash(&self, plaintext: &[String]) -> Vec<Self::Item>;

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

    fn hash(&self, plaintext: &[String]) -> Vec<Self::Item> {
        plaintext
            .iter()
            .map(|text| RistrettoPoint::hash_from_bytes::<Sha512>(text.as_bytes()))
            .collect::<Vec<Self::Item>>()
    }

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
                    .expect("Failed to construct compressed point")
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
                    .expect("Failed to construct compressed point")
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
/// use crypto::eccipher;
/// use curve25519_dalek::scalar::Scalar;
/// use rand_core::OsRng;
/// let mut rng = OsRng;
/// let (key, power) = (Scalar::random(&mut rng), Scalar::random(&mut rng));
/// let eccipher = eccipher::ECRistrettoParallel::default();
///
/// let text = vec!["a", "b", "c"]
///     .iter()
///     .map(|x| String::from(*x))
///     .collect::<Vec<_>>();
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

    /// Each string maps to curve (Sha512 is used)
    fn hash(&self, plaintext: &[String]) -> Vec<Self::Item> {
        plaintext
            .into_par_iter()
            .map(|item| RistrettoPoint::hash_from_bytes::<Sha512>(item.as_bytes()))
            .collect::<Vec<Self::Item>>()
    }

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
                    .expect("Failed to construct compressed point")
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
                    .expect("Failed to construct compressed point")
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
    let mut rng = OsRng;
    let mut scalar_bytes = [0u8; 64];
    rng.fill_bytes(&mut scalar_bytes);
    Scalar::from_bytes_mod_order_wide(&scalar_bytes)
}

#[cfg(test)]
mod tests {
    use rand::distributions;
    use rand::thread_rng;
    use rand::Rng;

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
            .map(char::from)
            .collect()
    }

    fn gen_points(n: usize) -> Vec<RistrettoPoint> {
        let mut rng = OsRng;
        (0..n)
            .map(|_| {
                let mut uniform_bytes = [0u8; 64];
                rng.fill_bytes(&mut uniform_bytes);
                RistrettoPoint::from_uniform_bytes(&uniform_bytes)
            })
            .collect::<Vec<RistrettoPoint>>()
    }

    #[test]
    fn compress_decompress_works() {
        let n = 100;
        let mut rng = OsRng;
        let key = {
            let mut scalar_bytes = [0u8; 64];
            rng.fill_bytes(&mut scalar_bytes);
            Scalar::from_bytes_mod_order_wide(&scalar_bytes)
        };
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
    fn exp_op_is_identical_for_serial_and_parallel() {
        let mut rng = OsRng;
        let n = 100;
        // let chunk_size = 3;
        // its important to keep the chunk size smaller
        // we need to test that the order is preserved
        // assert!(chunk_size < n);
        for _ in 0..3 {
            let key = {
                let mut scalar_bytes = [0u8; 64];
                rng.fill_bytes(&mut scalar_bytes);
                Scalar::from_bytes_mod_order_wide(&scalar_bytes)
            };
            let points = gen_points(n);
            let seq = ECRistrettoSequential::new();
            let parr = ECRistrettoParallel::new();
            let res_parr = parr.encrypt(&points, &key);
            let res_seq = seq.encrypt(&points, &key);
            assert_eq!(vec_compare(&res_parr, &res_seq), true);
        }
    }

    #[test]
    fn enc_op_is_identical_for_serial_and_parallel() {
        let mut rng = OsRng;
        let n = 100;
        // let chunk_size = 3;
        for _ in 0..10 {
            let key = {
                let mut scalar_bytes = [0u8; 64];
                rng.fill_bytes(&mut scalar_bytes);
                Scalar::from_bytes_mod_order_wide(&scalar_bytes)
            };
            let text = (0..n).map(|_| random_string(16)).collect::<Vec<String>>();

            let seq = ECRistrettoSequential::default();
            let parr = ECRistrettoParallel::new();
            let res_parr = parr.hash_encrypt(&text, &key);
            let res_seq = seq.hash_encrypt(&text, &key);
            assert_eq!(vec_compare(&res_parr, &res_seq), true);
        }
    }

    #[test]
    fn test_ecristrettoparallel_debug() {
        let parr = ECRistrettoParallel::new();
        assert_eq!(
            format!("The ECRistrettoParallel is: {:?}", parr),
            "The ECRistrettoParallel is: Ristretto EC ops parallel implementation"
        );
    }

    #[test]
    fn test_ecristrettosequential_debug() {
        let parr = ECRistrettoSequential::new();
        assert_eq!(
            format!("The ECRistrettoSequential is: {:?}", parr),
            "The ECRistrettoSequential is: Ristretto EC ops sequential implementation"
        );
    }

    #[test]
    fn test_ecristrettosequential_hash() {
        let parr = ECRistrettoSequential::default();
        let input = &mut [String::from("3"), String::from("2")];

        let res = parr.hash(input);
        assert_eq!(res.len(), 2);
    }

    #[test]
    fn test_ecristrettosequential_hash_encrypt_to_bytes() {
        let mut rng = OsRng;
        let parr = ECRistrettoSequential::default();
        let input = &mut [String::from("3"), String::from("2")];
        let key = {
            let mut scalar_bytes = [0u8; 64];
            rng.fill_bytes(&mut scalar_bytes);
            Scalar::from_bytes_mod_order_wide(&scalar_bytes)
        };
        let res = parr.hash_encrypt_to_bytes(input, &key);
        assert_eq!(res.len(), 2);
    }

    #[test]
    fn test_ecristrettosequential_to_points_encrypt() {
        let mut rng = OsRng;
        let parr = ECRistrettoSequential::default();
        let input = &mut [
            ByteBuffer {
                buffer: vec![
                    58, 238, 93, 247, 63, 124, 81, 222, 215, 243, 95, 187, 205, 5, 208, 227, 101,
                    148, 128, 240, 157, 22, 38, 218, 110, 130, 240, 13, 75, 104, 73, 97,
                ],
            },
            ByteBuffer {
                buffer: vec![
                    214, 21, 219, 73, 112, 150, 130, 90, 224, 145, 41, 23, 251, 237, 166, 76, 231,
                    200, 59, 116, 68, 223, 226, 162, 97, 48, 191, 15, 49, 103, 144, 82,
                ],
            },
        ];
        let key = {
            let mut scalar_bytes = [0u8; 64];
            rng.fill_bytes(&mut scalar_bytes);
            Scalar::from_bytes_mod_order_wide(&scalar_bytes)
        };
        let res = parr.to_points_encrypt(input, &key);
        assert_eq!(res.len(), 2);
    }

    #[test]
    fn test_ecristrettoparallel_hash() {
        let parr = ECRistrettoParallel::default();
        let input = &mut [String::from("3"), String::from("2")];
        let res = parr.hash(input);
        assert_eq!(res.len(), 2);
    }
}
