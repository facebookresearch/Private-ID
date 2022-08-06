//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::fmt::Error;
use std::fmt::Formatter;
use std::ops::Neg;
use std::sync::Arc;

use paillier::Add;
use paillier::Decrypt;
use paillier::DecryptionKey;
use paillier::Encrypt;
use paillier::KeyGeneration;
use paillier::Paillier;
use paillier::RawCiphertext;
use paillier::RawPlaintext;
use paillier::Rerandomize;
use rayon::iter::IndexedParallelIterator;
use rayon::iter::IntoParallelIterator;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;
use serde::Deserialize;
use serde::Serialize;

use crate::prelude::BigInt;
use crate::prelude::ByteBuffer;
use crate::prelude::EncryptionKey;
use crate::prelude::PAILLIER_PUBLIC_KEY_SIZE;

/// A wrapper struct to be used to convert bigints into byte arrays
/// Serde Serialiser: paillier::serialize::bigint
/// bincode lib is used to convert to the bytes
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BigIntWrapper {
    #[serde(with = "paillier::serialize::bigint")]
    pub raw: BigInt,
}

/// Auxilary methods
/// Mostly copy-pasted if there is no available public API
pub mod domain {
    extern crate rand;

    use crate::prelude::BigInt;

    pub fn sample(bit_size: usize) -> BigInt {
        const BYTE: usize = 8;
        const MAX_BITS: usize = 1024;
        const NUM_ELEMENTS: usize = MAX_BITS / BYTE;

        assert!(bit_size <= MAX_BITS);
        let nun_bytes = (bit_size - 1) / BYTE + 1;
        let buf: Vec<u8> = (0..NUM_ELEMENTS).map(|_| rand::random::<u8>()).collect();
        BigInt::from(&*buf) >> (nun_bytes * BYTE - bit_size)
    }

    pub fn mod_add(a: &BigInt, b: &BigInt, modulus: &BigInt) -> BigInt {
        (a.mod_floor(modulus) + b.mod_floor(modulus)).mod_floor(modulus)
    }

    pub fn mod_sub(a: &BigInt, b: &BigInt, modulus: &BigInt) -> BigInt {
        let sub_op = a.mod_floor(modulus) - b.mod_floor(modulus) + modulus;
        sub_op.mod_floor(modulus)
    }

    pub fn rand_bigints(n: usize) -> Vec<BigInt> {
        (0..n).map(|_| sample(1024)).collect::<Vec<BigInt>>()
    }
}

/// The main trait for the HE cipher vector operations
/// D - represents domain of the text: BigInt or u64 etc
/// Self::Item - is the ciphertext representation
pub trait HECipher<'a, D>
where
    D: Sized + Sync,
{
    type Item;

    fn enc(&self, values: &[D]) -> Vec<Self::Item>;

    fn dec(&self, ciphers: &[Self::Item]) -> Vec<D>;

    // TODO: borrow ciphers
    fn add(&self, ciphers: Vec<Self::Item>, values: &[D]) -> Vec<Self::Item>;
}

/// Reduce operations to perform on vector values
pub trait HEReducer<'a> {
    type Item;
    /// Homomorphically summs the values, using encryption key
    fn reduce_sum_with_key(&self, key: &EncryptionKey, ciphers: &[Self::Item]) -> Self::Item;
}

/// Cipher serialisation - deserialisation
pub trait HeDeSer<'a> {
    type Item;

    fn serialise(&self, ciphers: &[Self::Item]) -> Vec<ByteBuffer>;
    fn deserialise(&self, payload: &[ByteBuffer]) -> Vec<Self::Item>;
}

/// The main struct for multithreaded Paillier lib wrapper
pub struct PaillierParallel {
    pub enc_key: Arc<EncryptionKey>,
    dec_key: Arc<DecryptionKey>,
}

impl PaillierParallel {
    /// Constructor initiates encryption and decryption keys
    pub fn new() -> PaillierParallel {
        let (ek, dk) = Paillier::keypair_with_modulus_size(PAILLIER_PUBLIC_KEY_SIZE).keys();
        PaillierParallel {
            enc_key: Arc::new(ek),
            dec_key: Arc::new(dk),
        }
    }
}

impl Default for PaillierParallel {
    fn default() -> Self {
        Self::new()
    }
}

impl Debug for PaillierParallel {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(
            f,
            "{}",
            "HE Paillier Cipher parallel implementation".to_string()
        )
    }
}

/// Implementation of HE specification for PaillierParralel
/// for BigInt domain
impl<'a> HECipher<'a, BigInt> for PaillierParallel {
    type Item = RawCiphertext<'a>;

    fn enc(&self, values: &[BigInt]) -> Vec<Self::Item> {
        values
            .into_par_iter()
            .map_with(self.enc_key.clone(), |k, item| {
                let t = RawPlaintext::from(item);
                Paillier::encrypt(k.as_ref(), t)
            })
            .collect::<Vec<Self::Item>>()
    }

    fn dec(&self, ciphers: &[Self::Item]) -> Vec<BigInt> {
        let max_val = BigInt::one() << (PAILLIER_PUBLIC_KEY_SIZE / 2);
        ciphers
            .into_par_iter()
            .map_with(self.dec_key.clone(), |k, cipher| {
                let raw_ptext: RawPlaintext = Paillier::decrypt(k.as_ref(), cipher);
                raw_ptext.0.as_ref().mod_floor(&max_val)
            })
            .collect::<Vec<BigInt>>()
    }

    fn add(&self, ciphers: Vec<Self::Item>, values: &[BigInt]) -> Vec<Self::Item> {
        let max_val = BigInt::one() << (PAILLIER_PUBLIC_KEY_SIZE / 2);
        let k = self.enc_key.clone();
        let it_a = ciphers.into_par_iter();
        let it_b = values.into_par_iter();
        it_a.zip_eq(it_b)
            .map(|kv| {
                let val = RawPlaintext::from(kv.1.mod_floor(&max_val));
                Paillier::add(k.as_ref(), kv.0, val)
            })
            .collect::<Vec<RawCiphertext>>()
    }
}

impl PaillierParallel {
    pub fn enc_serialise_u64(&self, raw_text: &[u64]) -> Vec<ByteBuffer> {
        let key = self.enc_key.clone();
        let zero_enc = Paillier::encrypt(key.as_ref(), RawPlaintext::from(BigInt::from(0)));
        raw_text
            .into_par_iter()
            .map_with(zero_enc, |zero_enc_local, item| {
                let enc_text = if *item != 0 {
                    Paillier::encrypt(key.as_ref(), RawPlaintext::from(BigInt::from(*item)))
                } else {
                    Paillier::rerandomize(key.as_ref(), zero_enc_local.clone())
                };
                ByteBuffer {
                    buffer: bincode::serialize(&BigIntWrapper {
                        raw: BigInt::from(enc_text),
                    })
                    .unwrap(),
                }
            })
            .collect::<Vec<ByteBuffer>>()
    }

    pub fn enc_serialise(&self, raw_text: &[BigInt]) -> Vec<ByteBuffer> {
        let key = self.enc_key.clone();
        // let zero_enc = Paillier::encrypt(key.as_ref(), RawPlaintext::from(BigInt::from(0)));
        raw_text
            .into_par_iter()
            //.map_with(zero_enc, |zero_enc_local, item| {
            .map(|item| {
                let enc_text = Paillier::encrypt(key.as_ref(), RawPlaintext::from(item.clone()));
                ByteBuffer {
                    buffer: bincode::serialize(&BigIntWrapper {
                        raw: BigInt::from(enc_text),
                    })
                    .unwrap(),
                }
            })
            .collect::<Vec<ByteBuffer>>()
    }

    pub fn subtract_plaintext(
        &self,
        key: &EncryptionKey,
        lhs: Vec<ByteBuffer>,
        rhs: &[BigInt],
    ) -> Vec<ByteBuffer> {
        let it_lhs = lhs.into_par_iter();
        let it_rhs = rhs.into_par_iter();
        it_lhs
            .zip_eq(it_rhs)
            .map(|(lhs_bytes, rhs)| {
                let max_val = BigInt::one() << (PAILLIER_PUBLIC_KEY_SIZE / 2);
                let neg_rhs = RawPlaintext::from(rhs.neg().mod_floor(&max_val));
                let lhs = RawCiphertext::from(
                    (bincode::deserialize::<BigIntWrapper>(&lhs_bytes.buffer).unwrap()).raw,
                );
                let w = BigIntWrapper {
                    raw: BigInt::from(Paillier::add(key, lhs, neg_rhs)),
                };
                ByteBuffer {
                    buffer: bincode::serialize(&w).unwrap(),
                }
            })
            .collect::<Vec<ByteBuffer>>()
    }

    pub fn add_plaintext(
        &self,
        key: &EncryptionKey,
        lhs: Vec<ByteBuffer>,
        rhs: &[BigInt],
    ) -> Vec<ByteBuffer> {
        let it_lhs = lhs.into_par_iter();
        let it_rhs = rhs.into_par_iter();
        it_lhs
            .zip_eq(it_rhs)
            .map(|(lhs_bytes, rhs)| {
                let lhs = RawCiphertext::from(
                    (bincode::deserialize::<BigIntWrapper>(&lhs_bytes.buffer).unwrap()).raw,
                );
                let w = BigIntWrapper {
                    raw: BigInt::from(Paillier::add(key, lhs, RawPlaintext::from(rhs))),
                };
                ByteBuffer {
                    buffer: bincode::serialize(&w).unwrap(),
                }
            })
            .collect::<Vec<ByteBuffer>>()
    }

    pub fn decrypt(&self, payload: Vec<ByteBuffer>) -> Vec<BigInt> {
        let dkey = self.dec_key.clone();
        payload
            .into_par_iter()
            .map(|pl| {
                let enc_text = RawCiphertext::from(
                    (bincode::deserialize::<BigIntWrapper>(&pl.buffer).unwrap()).raw,
                );
                (BigInt::from(Paillier::decrypt(dkey.as_ref(), &enc_text)))
                    .mod_floor(&(BigInt::one() << (PAILLIER_PUBLIC_KEY_SIZE / 2)))
            })
            .collect::<Vec<BigInt>>()
    }
}

/// Implementation of serialisation - deserialisation
/// multithreaded
impl<'a> HeDeSer<'a> for PaillierParallel {
    type Item = RawCiphertext<'a>;

    fn serialise(&self, ciphers: &[Self::Item]) -> Vec<ByteBuffer> {
        ciphers
            .into_par_iter()
            .map(|cipher: &RawCiphertext| {
                let z = cipher.0.as_ref().to_owned();
                let w: BigIntWrapper = BigIntWrapper { raw: z };
                ByteBuffer {
                    buffer: bincode::serialize(&w).unwrap(),
                }
            })
            .collect::<Vec<ByteBuffer>>()
    }

    fn deserialise(&self, payload: &[ByteBuffer]) -> Vec<Self::Item> {
        payload
            .into_par_iter()
            .map(|pl| {
                Self::Item::from((bincode::deserialize::<BigIntWrapper>(&pl.buffer).unwrap()).raw)
            })
            .collect::<Vec<Self::Item>>()
    }
}

impl<'a> HEReducer<'a> for PaillierParallel {
    type Item = RawCiphertext<'a>;

    fn reduce_sum_with_key(&self, key: &EncryptionKey, ciphers: &[Self::Item]) -> Self::Item {
        let reduce_op = move |a: Self::Item, b: Self::Item| Paillier::add(key, a, b);
        ciphers.par_iter().cloned().reduce_with(reduce_op).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;

    use super::*;

    pub mod aux {
        use super::*;

        pub fn vec_compare<T: PartialEq>(va: &[T], vb: &[T]) -> bool {
            (va.len() == vb.len()) &&  // zip stops at the shortest
                va.iter().zip(vb).all(|(a, b)| a.eq(b))
        }

        pub fn rand_vec_u64(n: usize) -> Vec<u64> {
            let mut g = rand::thread_rng();
            let mut v: Vec<u64> = Vec::with_capacity(n);
            for _ in 0..n {
                v.push(g.gen::<u32>() as u64)
            }
            v
        }
    }

    #[test]
    fn test_reduce_sum() {
        let enc_cipher = PaillierParallel::new();
        let processing_cipher = PaillierParallel::new();

        let v = aux::rand_vec_u64(5);
        let v_bigint: Vec<BigInt> = v.iter().map(|x| BigInt::from(*x)).collect();
        let target_sum: u64 = v.iter().sum();
        let ciphertexts = enc_cipher.enc(&v_bigint);

        let res: Vec<RawCiphertext> =
            vec![processing_cipher.reduce_sum_with_key(enc_cipher.enc_key.as_ref(), &ciphertexts)];
        let res_plain: Vec<BigInt> = enc_cipher.dec(&res);
        let res_sum = (Option::<u64>::from(&res_plain[0])).unwrap();
        assert_eq!(target_sum, res_sum)
    }

    // Test both subtract_plaintext and add_plaintext
    #[test]
    fn test_additive_shares_first() {
        let cipher = PaillierParallel::new();

        // random values generation
        let data: Vec<u64> = aux::rand_vec_u64(1000);
        let data_bigint: Vec<BigInt> = data.iter().map(|x| BigInt::from(*x)).collect();

        // Generating masking variables from 1024 bit domain
        let v_rand = domain::rand_bigints(data.len());

        // Raw text HE encrypted
        let data_enc = cipher.enc_serialise_u64(data.as_slice());

        // HE subtract
        let v_share1_enc = cipher.subtract_plaintext(cipher.enc_key.as_ref(), data_enc, &v_rand);
        // HE add the same - this shouuld get us back to where we started
        let v_raw_enc = cipher.add_plaintext(cipher.enc_key.as_ref(), v_share1_enc, &v_rand);

        let v_raw = cipher.decrypt(v_raw_enc);
        assert!(aux::vec_compare(&data_bigint, &v_raw));
    }

    /// The test checks that additive shares actually work
    /// it can fail with the prob ~ 2^-960
    /// if it happens, you must be lucky!
    #[test]
    fn test_additive_shares_second() {
        let cipher = PaillierParallel::new();

        // that is 2^l
        let output_domain: u64 = 1 << 32 as u64;

        // Same as output domain, in BigInt type
        let output_domain_bigint: BigInt = BigInt::from(output_domain);

        // random values generation
        let raw_text: Vec<u64> = aux::rand_vec_u64(1000)
            .iter()
            .map(|x| x % output_domain)
            .collect();

        // moving raw text to raw_text
        let v_bigint: Vec<BigInt> = raw_text.iter().map(|x| BigInt::from(*x)).collect();

        // Generating masking variables from 1024 bit domain
        let masking_variables = domain::rand_bigints(raw_text.len());

        // Raw text HE encrypted
        let raw_text_enc = cipher.enc_serialise_u64(raw_text.as_slice());

        // Encrypted one - side shares of the domain
        let v_share1_enc =
            cipher.subtract_plaintext(cipher.enc_key.as_ref(), raw_text_enc, &masking_variables);

        // the Party1 will have shares
        let share_1: Vec<BigInt> = cipher.decrypt(v_share1_enc);

        // the party2 will have shares
        let share_2: Vec<BigInt> = masking_variables.clone();

        // Checking that the shares are actually work
        let v_restored_bigint = share_1
            .iter()
            .zip(share_2.iter())
            .zip(raw_text.iter())
            .map(|(a, b)| {
                // a.0 - party A shares
                // a.1 - party B shares
                // b - expected values

                // DEC( ... ) - N mod 2^l
                let z = domain::mod_sub(
                    a.0,
                    &(BigInt::one() << (PAILLIER_PUBLIC_KEY_SIZE / 2)),
                    &output_domain_bigint,
                );
                // party A will output as u64
                let party_a_output = (Option::<u64>::from(&z)).unwrap();

                // part B will output as u64
                let party_b_output =
                    (Option::<u64>::from(&a.1.mod_floor(&output_domain_bigint))).unwrap();

                // that how the downstream MPC reconstructs the value
                let reconstructed_output =
                    (party_a_output.wrapping_add(party_b_output)) % output_domain;

                // checking that reconstructed value actually would work in MPC
                assert_eq!(reconstructed_output, *b);

                //outputting for vector comparison as bigint
                domain::mod_add(a.0, a.1, &output_domain_bigint)
            })
            .collect::<Vec<BigInt>>();

        assert!(aux::vec_compare(&v_restored_bigint, &v_bigint));
    }

    #[test]
    fn test_bigint_understand() {
        // let cipher = PaillierParallel::new();
        let max_val = BigInt::one() << (PAILLIER_PUBLIC_KEY_SIZE / 2);
        let v_u64 = vec![3u64];
        let v: Vec<BigInt> = v_u64.iter().map(|x| BigInt::from(*x)).collect();
        let s = vec![BigInt::from(2)];

        {
            // checking that + and - are reversable
            // a = v - s
            let a: BigInt = &v[0] - &s[0];
            // b = a + s = v
            let b: BigInt = &a + &s[0];
            let a_mod = domain::mod_sub(&v[0], &s[0], &max_val);
            let b_mod = domain::mod_add(&a_mod, &s[0], &max_val);
            assert_eq!(b, v[0], "first_0");
            assert_eq!(b_mod, v[0], "first_1");
        }
        {
            let a: BigInt = &v[0] - &s[0];
            let c = a + &s[0];
            assert_eq!(c, v[0], "a+b=c");
        }
    }

    #[test]
    fn test_enc_dec_bigint() {
        let v = domain::rand_bigints(100);
        let ciphers: Vec<Box<dyn HECipher<BigInt, Item = RawCiphertext>>> =
            vec![Box::new(PaillierParallel::new())];
        for cipher in ciphers {
            let v_enc = cipher.enc(&v);
            let v_dec = cipher.dec(&v_enc);
            assert!(aux::vec_compare(&v, &v_dec));
        }

        // Now test encrypting and decrypting as arrays
        {
            let cipher = PaillierParallel::new();
            let enc_v = cipher.enc_serialise(v.as_slice());
            let dec_v = cipher.decrypt(enc_v);
            assert!(aux::vec_compare(&v, &dec_v));
        }
    }

    #[test]
    fn test_serialise_deserialise_parallel() {
        let v = domain::rand_bigints(50);
        assert_eq!(50, v.len());

        let cipher = PaillierParallel::new();
        let v_enc = &cipher.enc(&v);
        let v_ser = &cipher.serialise(&v_enc);
        let v_dsr = &cipher.deserialise(&v_ser);
        assert!(aux::vec_compare(v_enc, &v_dsr));
    }

    #[test]
    fn paillier_parallel_dry_run_bigint() {
        let v = domain::rand_bigints(100);
        let he = PaillierParallel::new();
        let v_enc: Vec<RawCiphertext> = he.enc(&v);
        let v_enc_ser = he.serialise(&v_enc);
        let v_enc_ser_des = he.deserialise(&v_enc_ser);
        let v_dec: Vec<BigInt> = he.dec(&v_enc);
        let v_dec_sd: Vec<BigInt> = he.dec(&v_enc_ser_des);
        assert!(aux::vec_compare(&v, &v_dec));
        assert!(aux::vec_compare(&v, &v_dec_sd));
    }
}
