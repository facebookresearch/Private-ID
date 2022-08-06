//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use std::num::Wrapping;

use criterion::*;
use crypto::paillier::sum_reduce_with_key;
use crypto::paillier::PaillierParallel;
use num_bigint::BigUint;
use num_bigint::RandBigInt;
use num_bigint::ToBigInt;
use num_traits::identities::One;
use num_traits::Signed;
use rand::distributions::Uniform;
use rand::Rng;
use rayon::iter::IndexedParallelIterator;
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;

fn parallel_enc(n: usize, c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let cipher = PaillierParallel::new();
    let data = (0..n)
        .map(|_| rng.gen_biguint_range(&BigUint::one(), &cipher.enc_key.n))
        .collect::<Vec<BigUint>>();
    c.bench_function(
        format!("paillier parallel enc, size: {}", n).as_str(),
        move |b| {
            b.iter_batched(
                || data.clone(),
                |ctx| cipher.enc_serialise(&ctx),
                BatchSize::SmallInput,
            )
        },
    );
}

fn parallel_he_sum_reduction(n: usize, c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let cipher = PaillierParallel::new();
    let data = (0..n)
        .map(|_| rng.gen_biguint_range(&BigUint::one(), &cipher.enc_key.n))
        .collect::<Vec<BigUint>>();
    let enc_data = cipher.enc_serialise(&data);
    c.bench_function(
        format!("paillier parallel HE sum, size: {}", n).as_str(),
        move |b| {
            b.iter_batched(
                || enc_data.clone(),
                |ctx| sum_reduce_with_key(&cipher.enc_key, &ctx),
                BatchSize::SmallInput,
            )
        },
    );
}

fn parallel_enc_add_dec(n: usize, c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let cipher = PaillierParallel::new();
    let data_a = (0..n)
        .map(|_| rng.gen_biguint_range(&BigUint::one(), &cipher.enc_key.n))
        .collect::<Vec<BigUint>>();
    let data_b = (0..n)
        .map(|_| rng.gen_biguint_range(&BigUint::one(), &cipher.enc_key.n))
        .collect::<Vec<BigUint>>();
    c.bench_function(
        format!("paillier parallel enc + add + dec, size: {}", n).as_str(),
        move |b| {
            b.iter_batched(
                || (data_a.clone(), data_b.clone()),
                |ctx| {
                    let a = cipher.enc_serialise(&ctx.0);
                    let b = cipher.add_plaintext(a, &ctx.1);
                    let _ = cipher.decrypt_vec(b);
                },
                BatchSize::SmallInput,
            )
        },
    );
}

fn parallel_additive_shares(n: usize, c: &mut Criterion) {
    c.bench_function(
        format!("paillier parallel ser+des, size: {}", n).as_str(),
        move |b| {
            b.iter(|| {
                let mut rng = rand::thread_rng();

                let output_domain: BigUint = BigUint::one() << 64;
                let range = Uniform::new(0_u64, 1 << 62);
                let raw_text: Vec<u64> = (0..n).map(|_| rng.sample(&range)).collect();

                let cipher = PaillierParallel::new();

                let raw_text_enc = cipher.enc_serialise_u64(raw_text.as_ref());

                let mask: Vec<BigUint> = (0..raw_text.len())
                    .map(|_| rng.gen_biguint_range(&BigUint::one(), &cipher.enc_key.n))
                    .collect();
                let v_share1_enc = cipher.subtract_plaintext(raw_text_enc, &mask);

                let share1 = cipher.decrypt_vec(v_share1_enc.clone());
                let share2 = mask.clone();

                share1
                    .into_par_iter()
                    .zip_eq(share2.into_par_iter())
                    .zip_eq(raw_text.into_par_iter())
                    .for_each(|(a, b)| {
                        // a.0 - party A shares
                        // a.1 - party B shares
                        // b - expected values
                        // DEC( ... ) - N mod 2^l
                        let party_a = {
                            let o_mod = output_domain.to_bigint().unwrap();
                            let t1 = a.0.to_bigint().unwrap() % &o_mod;
                            let t2 = cipher.enc_key.n.to_bigint().unwrap() % &o_mod;
                            let s = (t1 - t2 + &o_mod) % o_mod;

                            assert_eq!(s.is_negative(), false);
                            let (_, v) = s.to_u64_digits();
                            assert_eq!(v.len(), 1);
                            v[0]
                        };

                        let party_b = {
                            let t = (a.1 % &output_domain).to_u64_digits();
                            assert_eq!(t.len(), 1);
                            t[0]
                        };

                        let rec_output = (Wrapping(party_a) + Wrapping(party_b)).0;
                        assert_eq!(rec_output, b);
                    });
                ()
            })
        },
    );
}

fn parallel_bench_x1(c: &mut Criterion) {
    parallel_enc(1, c);
}

fn parallel_bench_x10(c: &mut Criterion) {
    parallel_enc(10, c);
}

fn parallel_enc_add_dec_x10(c: &mut Criterion) {
    parallel_enc_add_dec(10, c);
}

fn parallel_enc_add_dec_x100(c: &mut Criterion) {
    parallel_enc_add_dec(100, c);
}

fn parallel_additive_shares_x100(c: &mut Criterion) {
    parallel_additive_shares(100, c);
}

fn parallel_he_sum_x100(c: &mut Criterion) {
    parallel_he_sum_reduction(100, c);
}

criterion_group!(
name = parallel_paillier;
config = Criterion::default()
        .sample_size(10)
        .nresamples(10);
targets = parallel_bench_x1, parallel_bench_x10, parallel_enc_add_dec_x10, parallel_enc_add_dec_x100
);

criterion_group!(
name = paillier_additive_shares;
config = Criterion::default()
        .sample_size(10)
        .nresamples(10);
targets = parallel_additive_shares_x100
);

criterion_group!(
name = paillier_he_sum;
config = Criterion::default()
        .sample_size(10)
        .nresamples(10);
targets = parallel_he_sum_x100
);

criterion_main!(paillier_additive_shares, parallel_paillier, paillier_he_sum);
