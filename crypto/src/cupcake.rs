//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

use std::fmt::{Debug, Error, Formatter};

use cupcake::{
    integer_arith::scalar::Scalar,
    traits::{AddAndSubtract, KeyGeneration, PKEncryption, SKEncryption, Serializable},
    DefaultSchemeType, FVCiphertext, SecretKey,
};

use crate::prelude::ByteBuffer;

fn u64_to_vec_scalar(v: &u64) -> Vec<Scalar> {
    let u64_len: usize = 64;

    (0..u64_len)
        .collect::<Vec<usize>>()
        .iter()
        .map(|pos| {
            let x = (v >> pos) & 1;
            Scalar::from(x as u32)
        })
        .collect::<Vec<Scalar>>()
}

fn vec_scalar_to_u64(v: &[Scalar]) -> u64 {
    let u64_len: usize = 64;

    (0..u64_len)
        .collect::<Vec<usize>>()
        .iter()
        .map(|pos| u64::from(v[*pos].clone()) * (1 << pos))
        .sum()
}

pub struct CupcakeParallel {
    pub scheme: DefaultSchemeType,
    pub pk: FVCiphertext<Scalar>,
    sk: SecretKey<Scalar>,
}

impl CupcakeParallel {
    pub fn new() -> CupcakeParallel {
        // Only support mod 2 for XOR
        let scheme_ = cupcake::default_with_plaintext_mod(2);
        let (pk_, sk_) = scheme_.generate_keypair();
        CupcakeParallel {
            scheme: scheme_,
            pk: pk_,
            sk: sk_,
        }
    }

    pub fn enc_serialise_u64(&self, raw_text: &[u64]) -> Vec<ByteBuffer> {
        raw_text
            .into_par_iter()
            .map(|item| {
                let x = u64_to_vec_scalar(item);
                let t = &self.scheme.encrypt(&x, &self.pk);
                ByteBuffer {
                    buffer: t.to_bytes(),
                }
            })
            .collect::<Vec<ByteBuffer>>()
    }

    pub fn decrypt_vec_u64(&self, payload: Vec<ByteBuffer>) -> Vec<u64> {
        payload
            .into_par_iter()
            .map(|item| {
                let t: Vec<Scalar> = self
                    .scheme
                    .decrypt(&(self.scheme.from_bytes(&(item.buffer))), &self.sk);
                vec_scalar_to_u64(&t)
            })
            .collect::<Vec<u64>>()
    }

    pub fn xor_plaintext(&self, lhs: Vec<ByteBuffer>, rhs: &[u64]) -> Vec<ByteBuffer> {
        let it_lhs = lhs.into_par_iter();
        let it_rhs = rhs.into_par_iter();

        it_lhs
            .zip_eq(it_rhs)
            .map(|(lhs_bytes, rhs)| {
                let mut ct = self.scheme.from_bytes(&lhs_bytes.buffer);
                let t = u64_to_vec_scalar(rhs);
                self.scheme.add_plain_inplace(&mut ct, &t);
                ByteBuffer {
                    buffer: ct.to_bytes(),
                }
            })
            .collect::<Vec<ByteBuffer>>()
    }
}

impl Debug for CupcakeParallel {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "{}", "Cupcake Cipher".to_string())
    }
}

impl Default for CupcakeParallel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {

    use cupcake::{
        integer_arith::scalar::Scalar,
        traits::{
            AddAndSubtract, AdditiveHomomorphicScheme, KeyGeneration, PKEncryption, SKEncryption,
        },
    };
    use rand::{distributions::Uniform, Rng};
    use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

    use crate::cupcake::{u64_to_vec_scalar, vec_scalar_to_u64, CupcakeParallel};

    #[test]
    fn check_enc_dec() {
        let mut rng = rand::thread_rng();
        let scheme = cupcake::default_with_plaintext_mod(2);
        let (e_key, d_key) = scheme.generate_keypair();

        let range = Uniform::new(0_u64, u64::MAX);

        for _ in 0..1000 {
            let msg: u64 = rng.sample(&range);
            let ct = scheme.encrypt(&(u64_to_vec_scalar(&msg)), &e_key);
            let t: Vec<Scalar> = scheme.decrypt(&ct, &d_key);
            assert_eq!(msg == vec_scalar_to_u64(&t), true);
        }
    }

    #[test]
    fn check_enc_rerand_dec() {
        let mut rng = rand::thread_rng();
        let scheme = cupcake::default_with_plaintext_mod(2);
        let (e_key, d_key) = scheme.generate_keypair();

        let range = Uniform::new(0_u64, u64::MAX);

        for _ in 0..1000 {
            // encrypt
            let msg: u64 = rng.sample(&range);
            let ct = scheme.encrypt(&(u64_to_vec_scalar(&msg)), &e_key);
            let mut ct_r = ct.clone();

            // rerandomize
            scheme.rerandomize(&mut ct_r, &e_key);

            let t1: Vec<Scalar> = scheme.decrypt(&ct, &d_key);
            assert_eq!(msg == vec_scalar_to_u64(&t1), true);
            let t2: Vec<Scalar> = scheme.decrypt(&ct_r, &d_key);
            assert_eq!(msg == vec_scalar_to_u64(&t2), true);
        }
    }

    #[test]
    fn check_enc_enc_xor() {
        let mut rng = rand::thread_rng();

        let scheme = cupcake::default_with_plaintext_mod(2);
        let (e_key, d_key) = scheme.generate_keypair();

        let range = Uniform::new(0_u64, u64::MAX);

        for _ in 0..1000 {
            let msg1: u64 = rng.sample(&range);
            let msg2: u64 = rng.sample(&range);
            let ct1 = scheme.encrypt(&(u64_to_vec_scalar(&msg1)), &e_key);
            let mut ct2 = scheme.encrypt(&(u64_to_vec_scalar(&msg2)), &e_key);
            scheme.add_inplace(&mut ct2, &ct1);
            let t: Vec<Scalar> = scheme.decrypt(&ct2, &d_key);
            assert_eq!((msg1 ^ msg2) == vec_scalar_to_u64(&t), true);
        }
    }

    #[test]
    fn check_enc_clear_xor() {
        let mut rng = rand::thread_rng();

        let scheme = cupcake::default_with_plaintext_mod(2);
        let (e_key, d_key) = scheme.generate_keypair();

        let range = Uniform::new(0_u64, u64::MAX);

        for _ in 0..1000 {
            let msg1: u64 = rng.sample(&range);
            let msg2: u64 = rng.sample(&range);
            let mut ct1 = scheme.encrypt(&(u64_to_vec_scalar(&msg1)), &e_key);
            scheme.add_plain_inplace(&mut ct1, &(u64_to_vec_scalar(&msg2)));
            let t: Vec<Scalar> = scheme.decrypt(&ct1, &d_key);
            assert_eq!((msg1 ^ msg2) == vec_scalar_to_u64(&t), true);
        }
    }

    #[test]
    fn check_enc_u64() {
        let mut rng = rand::thread_rng();

        let range = Uniform::new(0_u64, u64::MAX);
        let vals: Vec<u64> = (0..1000).map(|_| rng.sample(&range)).collect();

        let cipher = CupcakeParallel::new();

        let x = cipher.enc_serialise_u64(vals.as_ref());
        let x_dec_u64 = cipher.decrypt_vec_u64(x);

        let matching = vals
            .iter()
            .zip(x_dec_u64.iter())
            .filter(|&(a, b)| a == b)
            .count();
        assert_eq!(matching, vals.len());
    }

    #[test]
    fn check_enc_xor_enc_dec_u64() {
        let mut rng = rand::thread_rng();

        let range = Uniform::new(0_u64, u64::MAX);
        let vals_x: Vec<u64> = (0..1000).map(|_| rng.sample(&range)).collect();
        let vals_y: Vec<u64> = (0..1000).map(|_| rng.sample(&range)).collect();

        let cipher = CupcakeParallel::new();

        let x = cipher.enc_serialise_u64(vals_x.as_ref());

        let z = cipher.xor_plaintext(x, &vals_y);

        let vals_z = vals_x
            .clone()
            .into_par_iter()
            .zip_eq(vals_y.clone().into_par_iter())
            .map(|(lhs, rhs)| lhs ^ rhs)
            .collect::<Vec<u64>>();

        let z_dec_u64 = cipher.decrypt_vec_u64(z.clone());

        let mut matching = vals_z
            .iter()
            .zip(z_dec_u64.iter())
            .filter(|&(a, b)| a == b)
            .count();
        assert_eq!(matching, vals_z.len());

        let z_p = cipher.xor_plaintext(z, &vals_y);
        let z_p_dec_u64 = cipher.decrypt_vec_u64(z_p);

        matching = vals_x
            .iter()
            .zip(z_p_dec_u64.iter())
            .filter(|&(a, b)| a == b)
            .count();
        assert_eq!(matching, vals_x.len());
    }

    #[test]
    fn check_gen_xor_shares_u64() {
        let mut rng = rand::thread_rng();

        let range = Uniform::new(0_u64, u64::MAX);
        let features: Vec<u64> = (0..1000).map(|_| rng.sample(&range)).collect();

        let cipher = CupcakeParallel::new();

        let enc_x = cipher.enc_serialise_u64(features.as_ref());

        // mask is share1
        let mask: Vec<u64> = (0..features.len()).map(|_| rng.sample(&range)).collect();
        let z = cipher.xor_plaintext(enc_x, &mask);

        let share2 = cipher.decrypt_vec_u64(z.clone());

        let rec_x = share2
            .clone()
            .into_par_iter()
            .zip_eq(mask.clone().into_par_iter())
            .map(|(lhs, rhs)| lhs ^ rhs)
            .collect::<Vec<u64>>();

        let matching = features
            .iter()
            .zip(rec_x.iter())
            .filter(|&(a, b)| a == b)
            .count();
        assert_eq!(matching, features.len());
    }
}
