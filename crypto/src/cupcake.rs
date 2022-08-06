//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use std::cmp;
use std::fmt::Debug;
use std::fmt::Error;
use std::fmt::Formatter;

use cupcake::integer_arith::scalar::Scalar;
use cupcake::traits::AddAndSubtract;
use cupcake::traits::KeyGeneration;
use cupcake::traits::PKEncryption;
use cupcake::traits::SKEncryption;
use cupcake::traits::Serializable;
use cupcake::DefaultSchemeType;
use cupcake::FVCiphertext;
use cupcake::SecretKey;
use rayon::iter::IndexedParallelIterator;
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;

use crate::prelude::ByteBuffer;

const U64_LEN: usize = 64;

fn u64_to_vec_scalar(v: &u64) -> Vec<Scalar> {
    (0..U64_LEN)
        .collect::<Vec<usize>>()
        .iter()
        .map(|pos| {
            let x = (v >> pos) & 1;
            Scalar::from(x as u32)
        })
        .collect::<Vec<Scalar>>()
}

fn vec_scalar_to_u64(v: &[Scalar]) -> u64 {
    assert!(v.len() >= U64_LEN);

    (0..U64_LEN)
        .collect::<Vec<usize>>()
        .iter()
        .map(|pos| u64::from(v[*pos].clone()) * (1 << pos))
        .sum()
}

fn vec_scalar_to_vec_u64(v: &[Scalar], n: usize) -> Vec<u64> {
    assert!(v.len() >= U64_LEN);

    assert!(n > 0);

    // Must be a multiple of plaintext size in bits
    assert!(((v.len() as f32) / U64_LEN as f32).fract() <= f32::EPSILON);
    let n_u64 = v.len() / U64_LEN;
    assert!(n_u64 >= n);

    let mut output = vec![0_u64; n];
    for i in 0..n {
        output[i] = vec_scalar_to_u64(&v[i * U64_LEN..(i + 1) * U64_LEN]);
    }
    return output;
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
        assert!(scheme_.n >= U64_LEN);
        assert!(((scheme_.n as f32) / U64_LEN as f32).fract() <= f32::EPSILON);

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

    // Vector of features (vector of u64). All features are of same length
    // raw_text[0] is first feature
    // raw_text[1] is second feature etc
    pub fn enc_serialise_u64_vec(&self, raw_text: &Vec<Vec<u64>>) -> (usize, Vec<Vec<ByteBuffer>>) {
        assert!(raw_text.len() > 0);
        assert!(raw_text[0].len() > 0);
        let num_features = raw_text.len();

        // Check if all features have the same number of elements
        {
            let l = raw_text.iter().map(|x| x.len()).collect::<Vec<_>>();
            assert_eq!(l.iter().min(), l.iter().max());
        }

        // Calculate number of Cupcake ciphertexts needed
        let n_cipher =
            ((U64_LEN as f32) * (num_features as f32) / (self.scheme.n as f32)).ceil() as usize;
        assert!(n_cipher >= 1);
        assert!(n_cipher * self.scheme.n >= U64_LEN * num_features);

        let stride = self.scheme.n / U64_LEN;
        let f_len = raw_text[0].len();
        let indices = (0..f_len).map(|x| x).collect::<Vec<_>>();

        let mut v: Vec<Vec<ByteBuffer>> = Vec::new();
        for i in 0..n_cipher {
            let t = indices
                .clone()
                .into_par_iter()
                .map(|idx| {
                    let mut x: Vec<Scalar> = Vec::new();
                    let start = i * stride;
                    let end = cmp::min(num_features, (i + 1) * stride);
                    for j in start..end {
                        let mut t = u64_to_vec_scalar(&(raw_text[j][idx]));
                        x.append(&mut t);
                    }
                    let t = &self.scheme.encrypt(&x, &self.pk);
                    ByteBuffer {
                        buffer: t.to_bytes(),
                    }
                })
                .collect::<Vec<ByteBuffer>>();
            v.push(t);
        }

        (num_features, v)
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

    // Vector of ciphertexts. All ciphertexts are of same length
    // payload[0] is first vector of ciphertexts
    // payload[1] is second vector of ciphertexts
    pub fn decrypt_vec_u64_vec(
        &self,
        payload: Vec<Vec<ByteBuffer>>,
        num_features: usize,
    ) -> Vec<Vec<u64>> {
        assert!(payload.len() > 0);
        assert!(payload[0].len() > 0);
        assert!(num_features > 0);

        // Check if all ciphertexts have the same number of elements
        {
            let l = payload.iter().map(|x| x.len()).collect::<Vec<_>>();
            assert_eq!(l.iter().min(), l.iter().max());
        }

        // Calculate number of Cupcake ciphertexts needed
        let n_cipher =
            ((U64_LEN as f32) * (num_features as f32) / (self.scheme.n as f32)).ceil() as usize;
        assert!(payload.len() >= n_cipher);

        let stride = self.scheme.n / U64_LEN;
        let f_len = payload[0].len();
        let indices = (0..f_len).map(|x| x).collect::<Vec<_>>();

        let mut output: Vec<Vec<u64>> = Vec::new();

        for i in 0..std::cmp::min(n_cipher, payload.len()) {
            let start = i * stride;
            let end = std::cmp::min(num_features, (i + 1) * stride);

            let t = indices
                .clone()
                .into_par_iter()
                .map(|idx| {
                    let t: Vec<Scalar> = self.scheme.decrypt(
                        &(self.scheme.from_bytes(&(payload[i][idx].buffer))),
                        &self.sk,
                    );

                    vec_scalar_to_vec_u64(&t, end - start)
                })
                .collect::<Vec<_>>();

            assert!(t.len() >= 1);
            assert_eq!(t[0].len(), end - start);

            for j in 0..t[0].len() {
                let x = indices
                    .clone()
                    .into_par_iter()
                    .map(|idx| t[idx][j])
                    .collect::<Vec<_>>();
                output.push(x);
            }
        }
        assert_eq!(output.len(), num_features);

        output
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

    pub fn xor_plaintext_vec(
        &self,
        lhs: Vec<Vec<ByteBuffer>>,
        rhs: &Vec<Vec<u64>>,
    ) -> Vec<Vec<ByteBuffer>> {
        assert!(rhs.len() > 0);
        assert!(rhs[0].len() > 0);
        let num_features = rhs.len();

        // Check if all features have the same number of elements
        {
            let l = rhs.iter().map(|x| x.len()).collect::<Vec<_>>();
            assert_eq!(l.iter().min(), l.iter().max());
        }

        // Calculate number of Cupcake ciphertexts needed
        let n_cipher =
            ((U64_LEN as f32) * (num_features as f32) / (self.scheme.n as f32)).ceil() as usize;
        assert!(n_cipher > 0);
        assert!(n_cipher * self.scheme.n >= U64_LEN * num_features);

        let stride = self.scheme.n / U64_LEN;
        let f_len = rhs[0].len();
        let indices = (0..f_len).map(|x| x).collect::<Vec<_>>();

        assert!(lhs.len() > 0);
        assert!(lhs[0].len() > 0);

        // Check if all ciphertext have the same number of elements
        {
            let l = lhs.iter().map(|x| x.len()).collect::<Vec<_>>();
            assert_eq!(l.iter().min(), l.iter().max());
        }

        assert!(lhs.len() >= n_cipher);
        assert_eq!(lhs[0].len(), rhs[0].len());

        let mut v: Vec<Vec<ByteBuffer>> = Vec::new();
        for i in 0..n_cipher {
            let t = indices
                .clone()
                .into_par_iter()
                .map(|idx| {
                    let mut x: Vec<Scalar> = Vec::new();
                    let start = i * stride;
                    let end = cmp::min(num_features, (i + 1) * stride);
                    for j in start..end {
                        let mut t = u64_to_vec_scalar(&(rhs[j][idx]));
                        x.append(&mut t);
                    }
                    let mut ct = self.scheme.from_bytes(&lhs[i][idx].buffer);
                    self.scheme.add_plain_inplace(&mut ct, &x);
                    ByteBuffer {
                        buffer: ct.to_bytes(),
                    }
                })
                .collect::<Vec<ByteBuffer>>();
            v.push(t);
        }

        v
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

    use cupcake::integer_arith::scalar::Scalar;
    use cupcake::traits::AddAndSubtract;
    use cupcake::traits::AdditiveHomomorphicScheme;
    use cupcake::traits::KeyGeneration;
    use cupcake::traits::PKEncryption;
    use cupcake::traits::SKEncryption;
    use rand::distributions::Uniform;
    use rand::Rng;
    use rayon::iter::IndexedParallelIterator;
    use rayon::iter::IntoParallelIterator;
    use rayon::iter::ParallelIterator;

    use crate::cupcake::u64_to_vec_scalar;
    use crate::cupcake::vec_scalar_to_u64;
    use crate::cupcake::CupcakeParallel;

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

        let (n_f, y) = cipher.enc_serialise_u64_vec((vec![vals.clone()]).as_ref());
        assert_eq!(n_f, 1);

        let y_dec_u64 = &cipher.decrypt_vec_u64_vec(y, 1)[0];

        let mut matching = vals
            .iter()
            .zip(x_dec_u64.iter())
            .filter(|&(a, b)| a == b)
            .count();
        assert_eq!(matching, vals.len());

        matching = vals
            .iter()
            .zip(y_dec_u64.iter())
            .filter(|&(a, b)| a == b)
            .count();
        assert_eq!(matching, vals.len());
    }

    #[test]
    fn check_enc_u64_vec() {
        let mut rng = rand::thread_rng();
        let range = Uniform::new(0_u64, u64::MAX);
        let n_features = vec![1, 2, 64, 97, 200];

        for n_feature in n_features {
            let indices = (0..n_feature).map(|x| x).collect::<Vec<_>>();
            let vals: Vec<Vec<u64>> = indices
                .iter()
                .map(|_| (0..1000).map(|_| rng.sample(&range)).collect())
                .collect();

            let cipher = CupcakeParallel::new();

            let (n_f, y) = cipher.enc_serialise_u64_vec(vals.as_ref());
            assert_eq!(n_f, n_feature);

            let y_dec_u64 = cipher.decrypt_vec_u64_vec(y, n_f);
            assert_eq!(y_dec_u64.len(), n_f);
            assert_eq!(y_dec_u64.len(), vals.len());

            for i in 0..n_f {
                let matching = vals[i]
                    .iter()
                    .zip(y_dec_u64[i].iter())
                    .filter(|&(a, b)| a == b)
                    .count();
                assert_eq!(matching, vals[i].len());
            }
        }
    }

    #[test]
    fn check_enc_xor_enc_dec_u64() {
        let mut rng = rand::thread_rng();

        let range = Uniform::new(0_u64, u64::MAX);
        let vals_x: Vec<u64> = (0..1000).map(|_| rng.sample(&range)).collect();
        let vals_y: Vec<u64> = (0..1000).map(|_| rng.sample(&range)).collect();

        let cipher = CupcakeParallel::new();

        let x = cipher.enc_serialise_u64(vals_x.as_ref());
        let (n_f, x_v) = cipher.enc_serialise_u64_vec(vec![vals_x.clone()].as_ref());

        assert_eq!(n_f, 1);

        let z = cipher.xor_plaintext(x, vals_y.as_ref());
        let z_v = cipher.xor_plaintext_vec(x_v, vec![vals_y.clone()].as_ref());

        let vals_z = vals_x
            .clone()
            .into_par_iter()
            .zip_eq(vals_y.clone().into_par_iter())
            .map(|(lhs, rhs)| lhs ^ rhs)
            .collect::<Vec<u64>>();

        let z_dec_u64 = cipher.decrypt_vec_u64(z.clone());
        let z_dec_u64_v = cipher.decrypt_vec_u64_vec(z_v.clone(), 1);

        let mut matching = vals_z
            .iter()
            .zip(z_dec_u64.iter())
            .filter(|&(a, b)| a == b)
            .count();
        assert_eq!(matching, vals_z.len());

        matching = vals_z
            .iter()
            .zip(z_dec_u64_v[0].iter())
            .filter(|&(a, b)| a == b)
            .count();
        assert_eq!(matching, vals_z.len());

        let z_p = cipher.xor_plaintext(z, &vals_y);
        let z_p_dec_u64 = cipher.decrypt_vec_u64(z_p);

        let z_p_v = cipher.xor_plaintext_vec(z_v, vec![vals_y.clone()].as_ref());
        let z_p_dec_u64_v = cipher.decrypt_vec_u64_vec(z_p_v, 1);

        matching = vals_x
            .iter()
            .zip(z_p_dec_u64.iter())
            .filter(|&(a, b)| a == b)
            .count();
        assert_eq!(matching, vals_x.len());

        matching = vals_x
            .iter()
            .zip(z_p_dec_u64_v[0].iter())
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

    #[test]
    fn check_gen_xor_shares_u64_vec() {
        let mut rng = rand::thread_rng();
        let range = Uniform::new(0_u64, u64::MAX);
        let n_features = vec![1, 2, 4, 64, 97, 225];

        for n_feature in n_features {
            let num_entries = 1000;
            let indices = (0..n_feature).map(|x| x).collect::<Vec<_>>();
            let features: Vec<Vec<u64>> = indices
                .iter()
                .map(|_| (0..num_entries).map(|_| rng.sample(&range)).collect())
                .collect();

            let cipher = CupcakeParallel::new();

            let (n_f, enc_x) = cipher.enc_serialise_u64_vec(features.as_ref());

            // mask is share1
            let mask: Vec<Vec<u64>> = indices
                .iter()
                .map(|_| (0..num_entries).map(|_| rng.sample(&range)).collect())
                .collect();

            let z = cipher.xor_plaintext_vec(enc_x, &mask);

            let share2 = cipher.decrypt_vec_u64_vec(z.clone(), n_f);

            assert_eq!(share2.len(), n_f);
            assert_eq!(mask.len(), n_f);

            let rec_x = {
                let mut v: Vec<Vec<u64>> = Vec::new();
                for i in 0..n_f {
                    let t = share2[i]
                        .clone()
                        .into_par_iter()
                        .zip_eq(mask[i].clone().into_par_iter())
                        .map(|(lhs, rhs)| lhs ^ rhs)
                        .collect::<Vec<u64>>();
                    v.push(t);
                }
                v
            };

            assert_eq!(rec_x.len(), n_f);
            assert_eq!(features.len(), n_f);

            for i in 0..n_f {
                let matching = features[i]
                    .iter()
                    .zip(rec_x[i].iter())
                    .filter(|&(a, b)| a == b)
                    .count();
                assert_eq!(matching, features[i].len());
            }
        }
    }
}
