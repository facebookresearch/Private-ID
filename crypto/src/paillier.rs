//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::fmt::Error;
use std::fmt::Formatter;

use num_bigint::BigUint;
use num_bigint::RandBigInt;
use num_bigint::ToBigInt;
use num_traits::identities::Zero;
use num_traits::One;
use num_traits::Signed;
use rayon::iter::IndexedParallelIterator;
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;

use crate::gcd::mod_inverse;
use crate::prelude::ByteBuffer;
use crate::prime::sample_prime;

struct MinimalEncryptionKey {
    pub n: BigUint,
}

#[derive(Clone, Debug)]
pub struct EncryptionKey {
    pub n: BigUint,
    pub nn: BigUint,
}

struct MinimalDecryptionKey {
    pub p: BigUint,
    pub q: BigUint,
}

struct DecryptionKey {
    pub p: BigUint,
    pub q: BigUint,
    pub p_1: BigUint,
    pub q_1: BigUint,
    pub p_inv: BigUint,
    pub n: BigUint,
    pub pp: BigUint,
    pub qq: BigUint,
    pub nn: BigUint,
    pub h_p: BigUint,
    pub h_q: BigUint,
    // lambda is psi(n)
    pub lambda: BigUint,
    // mu is psi(n) inv
    pub mu: BigUint,
}

fn gen_keypair(key_size: u64) -> (MinimalEncryptionKey, MinimalDecryptionKey) {
    // Check if even
    assert_eq!(key_size % 2, 0);

    let l_p = sample_prime(key_size / 2);
    let l_q = sample_prime(key_size / 2);
    let l_n = &l_p * &l_q;

    (
        MinimalEncryptionKey { n: l_n },
        MinimalDecryptionKey { p: l_p, q: l_q },
    )
}

fn l(x: &BigUint, n: &BigUint) -> BigUint {
    assert!(x > &BigUint::zero());
    (x - BigUint::one()) / n
}

fn gen_encryption_key(key: MinimalEncryptionKey) -> EncryptionKey {
    let t = &key.n * &key.n;
    EncryptionKey { n: key.n, nn: t }
}

fn gen_decryption_key(key: MinimalDecryptionKey) -> DecryptionKey {
    assert!(key.p > BigUint::one());
    assert!(key.q > BigUint::one());

    let l_n = &key.p * &key.q;
    let l_pp = &key.p * &key.p;
    let l_qq = &key.q * &key.q;
    let l_nn = &l_n * &l_n;

    let l_p_1 = &key.p - BigUint::one();
    let l_q_1 = &key.q - BigUint::one();
    let l_p_inv = mod_inverse(&key.p, &key.q).unwrap().to_biguint().unwrap();
    let g = &l_n + BigUint::one();

    let l_p = l(&(g.modpow(&l_p_1, &l_pp)), &key.p);
    let l_q = l(&(g.modpow(&l_q_1, &l_qq)), &key.q);
    let l_h_p = mod_inverse(&l_p, &key.p).unwrap().to_biguint().unwrap();
    let l_h_q = mod_inverse(&l_q, &key.q).unwrap().to_biguint().unwrap();

    // let l = (&key.p - BigUint::one()) * (&key.q - BigUint::one());
    let l = &l_p_1 * &l_q_1;
    let m = mod_inverse(&l, &l_n).unwrap().to_biguint().unwrap();

    assert!(((&l * &m) % &l_n) == BigUint::one());

    DecryptionKey {
        p: key.p,
        q: key.q,
        p_1: l_p_1,
        q_1: l_q_1,
        p_inv: l_p_inv,
        n: l_n,
        pp: l_pp,
        qq: l_qq,
        nn: l_nn,
        h_p: l_h_p,
        h_q: l_h_q,
        lambda: l,
        mu: m,
    }
}

fn encrypt(msg: BigUint, key: &EncryptionKey) -> BigUint {
    assert!(msg < key.n);
    let mut rng = rand::thread_rng();
    // Random sample from (0, n) or [1, n-1)
    let r = rng.gen_biguint_range(&BigUint::one(), &key.n);

    // For us g = key.n + 1. Hence g^m is (n + 1)^m mod n^2 which is (1 + m * n)
    let g_m = BigUint::one() + &msg * &key.n;

    let r_n = r.modpow(&key.n, &key.nn);
    let e = (&g_m * &r_n) % &key.nn;

    assert!(g_m < key.nn);

    e
}

fn decrypt(msg: BigUint, key: &DecryptionKey) -> BigUint {
    let t = msg.modpow(&key.lambda, &key.nn);
    (l(&t, &key.n) * &key.mu) % &key.n
}

// Algorithm from section 7 of
// http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.112.4035&rep=rep1&type=pdf
fn decrypt_fast(msg: BigUint, key: &DecryptionKey) -> BigUint {
    let m_p = (l(&(msg.modpow(&key.p_1, &key.pp)), &key.p) * &key.h_p) % &key.p;
    let m_q = (l(&(msg.modpow(&key.q_1, &key.qq)), &key.q) * &key.h_q) % &key.q;

    // Combine via Chinese Remainder Theorem
    let m = {
        let mut diff = m_q.to_bigint().unwrap() - m_p.to_bigint().unwrap();
        let to_add = key.q.to_bigint().unwrap();
        while diff.is_negative() {
            diff += &to_add;
        }
        let t = (diff.to_biguint().unwrap() * &key.p_inv) % &key.q;
        m_p + (t * &key.p)
    };

    assert!(m < key.n);
    m
}

pub fn sum_reduce_with_key(enc_key: &EncryptionKey, enc_data: &[ByteBuffer]) -> ByteBuffer {
    let mut acc = encrypt(BigUint::zero(), enc_key);

    for item in enc_data {
        let t = BigUint::from_bytes_le(&(item.buffer));
        acc = (acc * t) % &enc_key.nn;
    }

    ByteBuffer {
        buffer: acc.to_bytes_le(),
    }
}

pub fn add_plaintext(
    enc_key: &EncryptionKey,
    lhs: Vec<ByteBuffer>,
    rhs: &[BigUint],
) -> Vec<ByteBuffer> {
    let it_lhs = lhs.into_par_iter();
    let it_rhs = rhs.into_par_iter();
    it_lhs
        .zip_eq(it_rhs)
        .map(|(lhs_bytes, rhs)| {
            let cipher1 = BigUint::from_bytes_le(&(lhs_bytes.buffer));
            let g_m = BigUint::one() + rhs * &enc_key.n;
            let cipher = (cipher1 * g_m) % &enc_key.nn;
            ByteBuffer {
                buffer: cipher.to_bytes_le(),
            }
        })
        .collect::<Vec<ByteBuffer>>()
}

pub fn subtract_plaintext(
    enc_key: &EncryptionKey,
    lhs: Vec<ByteBuffer>,
    rhs: &[BigUint],
) -> Vec<ByteBuffer> {
    let it_lhs = lhs.into_par_iter();
    let it_rhs = rhs.into_par_iter();
    it_lhs
        .zip_eq(it_rhs)
        .map(|(lhs_bytes, rhs)| {
            // Negate
            let rhs_n = &enc_key.n - rhs;

            let cipher1 = BigUint::from_bytes_le(&(lhs_bytes.buffer));
            let g_m = BigUint::one() + &rhs_n * &enc_key.n;
            let cipher = (cipher1 * g_m) % &enc_key.nn;
            ByteBuffer {
                buffer: cipher.to_bytes_le(),
            }
        })
        .collect::<Vec<ByteBuffer>>()
}

pub struct PaillierParallel {
    pub enc_key: EncryptionKey,
    dec_key: DecryptionKey,
}

impl PaillierParallel {
    pub fn new() -> PaillierParallel {
        let (m_e, m_d) = gen_keypair(2048_u64);
        PaillierParallel {
            enc_key: gen_encryption_key(m_e),
            dec_key: gen_decryption_key(m_d),
        }
    }

    pub fn enc_serialise_u64(&self, raw_text: &[u64]) -> Vec<ByteBuffer> {
        raw_text
            .into_par_iter()
            .map(|item| {
                let t = encrypt(BigUint::from(*item), &self.enc_key);
                ByteBuffer {
                    buffer: t.to_bytes_le(),
                }
            })
            .collect::<Vec<ByteBuffer>>()
    }

    pub fn enc_serialise(&self, raw_text: &[BigUint]) -> Vec<ByteBuffer> {
        raw_text
            .into_par_iter()
            .map(|item| {
                let t = encrypt((*item).clone(), &self.enc_key);
                ByteBuffer {
                    buffer: t.to_bytes_le(),
                }
            })
            .collect::<Vec<ByteBuffer>>()
    }

    pub fn decrypt_vec(&self, payload: Vec<ByteBuffer>) -> Vec<BigUint> {
        payload
            .into_par_iter()
            .map(|item| decrypt_fast(BigUint::from_bytes_le(&(item.buffer)), &self.dec_key))
            .collect::<Vec<BigUint>>()
    }

    pub fn add_plaintext(&self, lhs: Vec<ByteBuffer>, rhs: &[BigUint]) -> Vec<ByteBuffer> {
        add_plaintext(&self.enc_key, lhs, rhs)
    }

    pub fn subtract_plaintext(&self, lhs: Vec<ByteBuffer>, rhs: &[BigUint]) -> Vec<ByteBuffer> {
        subtract_plaintext(&self.enc_key, lhs, rhs)
    }
}

impl Debug for PaillierParallel {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "{}", "Paillier Cipher".to_string())
    }
}

impl Default for PaillierParallel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {

    use std::num::Wrapping;

    use num_bigint::BigUint;
    use num_bigint::RandBigInt;
    use num_bigint::ToBigInt;
    use num_traits::One;
    use num_traits::Signed;
    use num_traits::Zero;
    use rand::distributions::Uniform;
    use rand::Rng;
    use rayon::iter::IndexedParallelIterator;
    use rayon::iter::IntoParallelIterator;
    use rayon::iter::ParallelIterator;

    use crate::paillier::decrypt_fast;
    use crate::paillier::encrypt;
    use crate::paillier::gen_decryption_key;
    use crate::paillier::gen_encryption_key;
    use crate::paillier::gen_keypair;
    use crate::paillier::sum_reduce_with_key;
    use crate::paillier::PaillierParallel;

    #[test]
    fn check_enc_dec() {
        let mut rng = rand::thread_rng();

        let (m_e, m_d) = gen_keypair(2048_u64);
        let e_key = gen_encryption_key(m_e);
        let d_key = gen_decryption_key(m_d);

        for _ in 0..1000 {
            let msg = rng.gen_biguint_range(&BigUint::zero(), &e_key.n);
            let cipher = encrypt(msg.clone(), &e_key);
            assert_eq!(msg == decrypt_fast(cipher, &d_key), true);
        }
    }

    #[test]
    fn check_enc_rerand_dec() {
        let mut rng = rand::thread_rng();

        let (m_e, m_d) = gen_keypair(2048_u64);
        let e_key = gen_encryption_key(m_e);
        let d_key = gen_decryption_key(m_d);

        for _ in 0..1000 {
            // encrypt
            let msg = rng.gen_biguint_range(&BigUint::one(), &e_key.n);
            let cipher = encrypt(msg.clone(), &e_key);

            // rerandomize
            let r = rng.gen_biguint_range(&BigUint::zero(), &e_key.n);
            let r_n = r.modpow(&e_key.n, &e_key.nn);
            let cipher_r = (&cipher * &r_n) % &e_key.nn;

            assert_eq!(msg == decrypt_fast(cipher, &d_key), true);
            assert_eq!(msg == decrypt_fast(cipher_r, &d_key), true);
        }
    }

    #[test]
    fn check_enc_enc_add() {
        let mut rng = rand::thread_rng();

        let (m_e, m_d) = gen_keypair(2048_u64);
        let e_key = gen_encryption_key(m_e);
        let d_key = gen_decryption_key(m_d);

        for _ in 0..1000 {
            let msg1 = rng.gen_biguint_range(&BigUint::zero(), &e_key.n);
            let msg2 = rng.gen_biguint_range(&BigUint::zero(), &e_key.n);
            let cipher1 = encrypt(msg1.clone(), &e_key);
            let cipher2 = encrypt(msg2.clone(), &e_key);
            let cipher = (cipher1 * cipher2) % &e_key.nn;
            assert_eq!(
                ((msg1 + msg2) % &e_key.n) == decrypt_fast(cipher, &d_key),
                true
            );
        }
    }

    #[test]
    fn check_enc_clear_add() {
        let mut rng = rand::thread_rng();

        let (m_e, m_d) = gen_keypair(2048_u64);
        let e_key = gen_encryption_key(m_e);
        let d_key = gen_decryption_key(m_d);

        for _ in 0..1000 {
            let msg1 = rng.gen_biguint_range(&BigUint::zero(), &e_key.n);
            let msg2 = rng.gen_biguint_range(&BigUint::zero(), &e_key.n);
            let cipher1 = encrypt(msg1.clone(), &e_key);
            let g_m = BigUint::one() + &msg2 * &e_key.n;
            let cipher = (cipher1 * g_m) % &e_key.nn;
            assert_eq!(
                ((msg1 + msg2) % &e_key.n) == decrypt_fast(cipher, &d_key),
                true
            );
        }
    }

    #[test]
    fn check_enc_clear_sub() {
        let mut rng = rand::thread_rng();

        let (m_e, m_d) = gen_keypair(2048_u64);
        let e_key = gen_encryption_key(m_e);
        let d_key = gen_decryption_key(m_d);

        for _ in 0..1000 {
            let msg1 = rng.gen_biguint_range(&BigUint::zero(), &e_key.n);
            let msg2 = rng.gen_biguint_range(&BigUint::zero(), &e_key.n);

            // Negate
            let msg2_n = &e_key.n - &msg2;

            let cipher1 = encrypt(msg1.clone(), &e_key);
            let g_m = BigUint::one() + &msg2_n * &e_key.n;
            let cipher = (cipher1 * g_m) % &e_key.nn;
            let result = decrypt_fast(cipher, &d_key);

            // Correct difference
            let to_compare = (msg1.to_bigint().unwrap() - msg2.to_bigint().unwrap()
                + e_key.n.to_bigint().unwrap())
            .to_biguint()
            .unwrap()
                % &e_key.n;
            assert_eq!(to_compare == result, true);
        }
    }

    #[test]
    fn check_reduce() {
        let mut rng = rand::thread_rng();

        let range = Uniform::new(0_u64, 1 << 62);
        let vals_x: Vec<u64> = (0..1000).map(|_| rng.sample(&range)).collect();

        let cipher = PaillierParallel::new();

        let x = cipher.enc_serialise_u64(vals_x.as_ref());

        let mut sum = BigUint::zero();

        for i in 0..vals_x.len() {
            sum = sum + BigUint::from(vals_x[i]);
        }

        let sum_cipher = {
            let t = vec![sum_reduce_with_key(&cipher.enc_key, &x)];
            cipher.decrypt_vec(t)[0].clone()
        };

        assert_eq!(sum == sum_cipher, true);
    }

    #[test]
    fn check_enc_u64() {
        let mut rng = rand::thread_rng();

        let range = Uniform::new(0_u64, 1 << 62);
        let vals: Vec<u64> = (0..1000).map(|_| rng.sample(&range)).collect();

        let cipher = PaillierParallel::new();

        let x = cipher.enc_serialise_u64(vals.as_ref());
        let x_dec = cipher.decrypt_vec(x);
        let x_dec_u64 = x_dec
            .into_par_iter()
            .map(|item| {
                let t = item.to_u64_digits();
                assert_eq!(t.len(), 1);
                t[0]
            })
            .collect::<Vec<u64>>();

        let matching = vals
            .iter()
            .zip(x_dec_u64.iter())
            .filter(|&(a, b)| a == b)
            .count();
        assert_eq!(matching, vals.len());
    }

    #[test]
    fn check_enc_add_enc_dec_u64() {
        let mut rng = rand::thread_rng();

        let range = Uniform::new(0_u64, 1 << 62);
        let vals_x: Vec<u64> = (0..1000).map(|_| rng.sample(&range)).collect();
        let vals_y: Vec<u64> = (0..1000).map(|_| rng.sample(&range)).collect();

        let cipher = PaillierParallel::new();

        let x = cipher.enc_serialise_u64(vals_x.as_ref());

        let y = vals_y
            .clone()
            .into_par_iter()
            .map(|item| BigUint::from(item))
            .collect::<Vec<BigUint>>();
        let z = cipher.add_plaintext(x, &y);

        let vals_z = vals_x
            .clone()
            .into_par_iter()
            .zip_eq(vals_y.into_par_iter())
            .map(|(lhs, rhs)| lhs + rhs)
            .collect::<Vec<u64>>();

        let z_dec_u64 = cipher
            .decrypt_vec(z.clone())
            .into_par_iter()
            .map(|item| {
                let t = item.to_u64_digits();
                assert_eq!(t.len(), 1);
                t[0]
            })
            .collect::<Vec<u64>>();

        let mut matching = vals_z
            .iter()
            .zip(z_dec_u64.iter())
            .filter(|&(a, b)| a == b)
            .count();
        assert_eq!(matching, vals_z.len());

        let z_p = cipher.subtract_plaintext(z, &y);
        let z_p_dec_u64 = cipher
            .decrypt_vec(z_p)
            .into_par_iter()
            .map(|item| {
                let t = item.to_u64_digits();
                assert_eq!(t.len(), 1);
                t[0]
            })
            .collect::<Vec<u64>>();

        matching = vals_x
            .iter()
            .zip(z_p_dec_u64.iter())
            .filter(|&(a, b)| a == b)
            .count();
        assert_eq!(matching, vals_x.len());
    }

    #[test]
    fn check_enc_dec_u64() {
        let mut rng = rand::thread_rng();

        let range = Uniform::new(0_u64, 1 << 62);
        let vals_x: Vec<u64> = (0..1000).map(|_| rng.sample(&range)).collect();
        let vals_y: Vec<u64> = (0..1000).map(|_| rng.sample(&range)).collect();

        let cipher = PaillierParallel::new();

        let x = cipher.enc_serialise_u64(vals_x.as_ref());

        let y = vals_y
            .clone()
            .into_par_iter()
            .map(|item| BigUint::from(item))
            .collect::<Vec<BigUint>>();
        let z = cipher.subtract_plaintext(x, &y);

        let vals_z = vals_x
            .into_par_iter()
            .zip_eq(vals_y.into_par_iter())
            .map(|(lhs, rhs)| {
                if lhs < rhs {
                    (true, rhs - lhs)
                } else {
                    (false, lhs - rhs)
                }
            })
            .collect::<Vec<(bool, u64)>>();

        let z_dec_u64 = cipher
            .decrypt_vec(z.clone())
            .into_par_iter()
            .map(|item| {
                let t = item.to_u64_digits();
                let ret = if t.len() > 1 {
                    let x = item.to_bigint().unwrap() - cipher.enc_key.n.to_bigint().unwrap();
                    assert_eq!(x.is_negative(), true);
                    let (_, v) = x.to_u64_digits();
                    assert_eq!(v.len(), 1);
                    (true, v[0])
                } else {
                    (false, t[0])
                };
                ret
            })
            .collect::<Vec<(bool, u64)>>();

        let matching = vals_z
            .iter()
            .zip(z_dec_u64.iter())
            .filter(|&(a, b)| (a.0 == b.0) && (a.1 == b.1))
            .count();
        assert_eq!(matching, vals_z.len());
    }

    #[test]
    fn check_gen_additive_shares_u64() {
        let mut rng = rand::thread_rng();

        let range = Uniform::new(0_u64, 1 << 62);
        let features: Vec<u64> = (0..1000).map(|_| rng.sample(&range)).collect();
        let x = features
            .clone()
            .into_par_iter()
            .map(|item| BigUint::from(item))
            .collect::<Vec<BigUint>>();

        let cipher = PaillierParallel::new();

        let enc_x = cipher.enc_serialise_u64(features.as_ref());

        let mask: Vec<BigUint> = (0..features.len())
            .map(|_| rng.gen_biguint_range(&BigUint::zero(), &cipher.enc_key.n))
            .collect();
        let z = cipher.subtract_plaintext(enc_x, &mask);

        let share2 = cipher.decrypt_vec(z.clone());

        let rec_x = share2
            .clone()
            .into_par_iter()
            .zip_eq(mask.clone().into_par_iter())
            .map(|(lhs, rhs)| (lhs + rhs) % &cipher.enc_key.n)
            .collect::<Vec<BigUint>>();

        // Changing mod to 64 bit
        let output_mod: BigUint = BigUint::one() << 64;
        let share1_p = mask
            .clone()
            .into_par_iter()
            .map(|item| {
                let t = (item % &output_mod).to_u64_digits();
                assert_eq!(t.len(), 1);
                t[0]
            })
            .collect::<Vec<u64>>();

        let share2_p = share2
            .into_par_iter()
            .map(|item| {
                let o_mod = output_mod.to_bigint().unwrap();
                let t1 = item.to_bigint().unwrap() % &o_mod;
                let t2 = cipher.enc_key.n.to_bigint().unwrap() % &o_mod;
                let s = (t1 - t2 + &o_mod) % o_mod;

                assert_eq!(s.is_negative(), false);
                let (_, v) = s.to_u64_digits();
                assert_eq!(v.len(), 1);
                v[0]
            })
            .collect::<Vec<u64>>();

        let rec_x_u64 = share1_p
            .into_par_iter()
            .zip_eq(share2_p.into_par_iter())
            .map(|(lhs, rhs)| {
                // Ignore overflow since we need low 64 bits anyway
                // lhs + rhs
                (Wrapping(lhs) + Wrapping(rhs)).0
            })
            .collect::<Vec<u64>>();

        let mut matching = x.iter().zip(rec_x.iter()).filter(|&(a, b)| a == b).count();
        assert_eq!(matching, x.len());
        matching = features
            .iter()
            .zip(rec_x_u64.iter())
            .filter(|&(a, b)| a == b)
            .count();
        assert_eq!(matching, x.len());
    }

    #[test]
    fn check_decrypt() {
        use crate::paillier::decrypt;
        let mut rng = rand::thread_rng();
        let (m_e, m_d) = gen_keypair(2048_u64);
        let e_key = gen_encryption_key(m_e);
        let d_key = gen_decryption_key(m_d);

        for _ in 0..1000 {
            let msg = rng.gen_biguint_range(&BigUint::zero(), &e_key.n);
            let cipher = encrypt(msg.clone(), &e_key);
            assert!(msg == decrypt(cipher, &d_key));
        }
    }

    #[test]
    fn check_enc_serialise() {
        let vals: Vec<BigUint> = vec![
            BigUint::parse_bytes(b"1234", 10).unwrap(),
            BigUint::parse_bytes(b"1234", 10).unwrap(),
        ];
        let cipher = PaillierParallel::default();

        let x = cipher.enc_serialise(vals.as_ref());
        assert_eq!(x.len(), 2);
    }
}
