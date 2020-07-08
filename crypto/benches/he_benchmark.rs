//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate criterion;
extern crate crypto;
extern crate rand;

use criterion::*;
use crypto::he::{domain, HECipher, HEReducer, HeDeSer, PaillierParallel};
use paillier::{BigInt, RawCiphertext};

mod bench_aux {
    use super::*;
    use rand::Rng;

    pub fn rand_vec_u64(n: usize) -> Vec<u64> {
        let mut g = rand::thread_rng();
        let mut v: Vec<u64> = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(g.gen::<u64>())
        }
        v
    }
}

fn parallel_enc(n: usize, c: &mut Criterion) {
    let data = domain::rand_bigints(n);
    let cipher = PaillierParallel::new();
    c.bench_function(
        format!("paillier parallel enc, size: {}", n).as_str(),
        move |b| {
            b.iter_batched(
                || data.clone(),
                |ctx| cipher.enc(&ctx),
                BatchSize::SmallInput,
            )
        },
    );
}

fn parallel_he_summ_reduction(n: usize, c: &mut Criterion) {
    let data = domain::rand_bigints(n);
    let cipher = PaillierParallel::new();
    let enc_data = cipher.enc(&data);
    c.bench_function(
        format!("paillier parallel HE summ, size: {}", n).as_str(),
        move |b| {
            b.iter_batched(
                || enc_data.clone(),
                |ctx| cipher.reduce_sum_with_key(cipher.enc_key.as_ref(), &ctx),
                BatchSize::SmallInput,
            )
        },
    );
}

fn parallel_enc_add_dec(n: usize, c: &mut Criterion) {
    let data_a = domain::rand_bigints(n);
    let data_b = domain::rand_bigints(n);
    let cipher = PaillierParallel::new();
    c.bench_function(
        format!("paillier parallel enc + add + dec, size: {}", n).as_str(),
        move |b| {
            b.iter_batched(
                || (data_a.clone(), data_b.clone()),
                |ctx| {
                    let a = cipher.enc(&ctx.0);
                    let b = cipher.add(a, &ctx.1);
                    let _: Vec<BigInt> = cipher.dec(&b);
                },
                BatchSize::SmallInput,
            )
        },
    );
}

fn parallel_ser_des(n: usize, c: &mut Criterion) {
    let data_a = domain::rand_bigints(n);
    let cipher = PaillierParallel::new();
    let enc: Vec<RawCiphertext> = cipher.enc(&data_a);
    c.bench_function(
        format!("paillier parallel ser+des, size: {}", n).as_str(),
        move |b| {
            b.iter_batched(
                || (enc.clone()),
                |ctx| {
                    let a = cipher.serialise(&ctx);
                    let _: Vec<RawCiphertext> = cipher.deserialise(&a);
                },
                BatchSize::SmallInput,
            )
        },
    );
}

fn parrallel_additive_shares(n: usize, c: &mut Criterion) {
    c.bench_function(
        format!("paillier parallel ser+des, size: {}", n).as_str(),
        move |b| {
            b.iter(|| {
                let cipher = PaillierParallel::new();
                let output_domain: u64 = 1 << 62 as u64;
                let output_domain_bigint: BigInt = BigInt::from(output_domain);
                let raw_text: Vec<u64> = bench_aux::rand_vec_u64(n)
                    .iter()
                    .map(|x| x % output_domain)
                    .collect();
                // let v_bigint: Vec<BigInt> = raw_text.iter().map(|x| BigInt::from(*x)).collect();
                let masking_variables = domain::rand_bigints(raw_text.len());
                // let raw_text_enc = cipher.enc(&v_bigint);
                let raw_text_enc = cipher.enc_serialise_u64(raw_text.as_slice());
                // let v_share1_enc = cipher.subtract(raw_text_enc, &masking_variables);
                let v_share1_enc = cipher.subtract_plaintext(
                    cipher.enc_key.as_ref(),
                    raw_text_enc,
                    &masking_variables,
                );
                // let share_1: Vec<BigInt> = cipher.dec(&v_share1_enc);
                let share_1: Vec<BigInt> = cipher.decrypt(v_share1_enc);
                let share_2: Vec<BigInt> = masking_variables.clone();

                share_1
                    .iter()
                    .zip(share_2.iter())
                    .zip(raw_text.iter())
                    .for_each(|(a, b)| {
                        // a.0 - party A shares
                        // a.1 - party B shares
                        // b - expected values
                        // DEC( ... ) - N mod 2^l
                        let z =
                            domain::mod_sub(a.0, &(BigInt::one() << 1024), &output_domain_bigint);
                        // party A will output as u64
                        let party_a_output = (Option::<u64>::from(&z)).unwrap();
                        let party_b_output =
                            (Option::<u64>::from(&a.1.mod_floor(&output_domain_bigint))).unwrap();
                        let reconstructed_output =
                            (party_a_output.wrapping_add(party_b_output)) % output_domain;
                        assert_eq!(reconstructed_output, *b);
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

fn parallel_ser_des_x100(c: &mut Criterion) {
    parallel_ser_des(100, c);
}

fn parallel_additive_shares_x100(c: &mut Criterion) {
    parrallel_additive_shares(100, c);
}

fn parallel_he_summ_x100(c: &mut Criterion) {
    parallel_he_summ_reduction(100, c);
}

criterion_group!(
name = parallel_paillier;
config = Criterion::default()
        .sample_size(10)
        .nresamples(10);
targets = parallel_bench_x1, parallel_bench_x10, parallel_enc_add_dec_x10, parallel_enc_add_dec_x100, parallel_ser_des_x100
);

criterion_group!(
name = paillier_additive_shares;
config = Criterion::default()
        .sample_size(10)
        .nresamples(10);
targets = parallel_additive_shares_x100
);

criterion_group!(
name = paillier_he_summ;
config = Criterion::default()
        .sample_size(10)
        .nresamples(10);
targets = parallel_he_summ_x100
);

criterion_main!(
    paillier_additive_shares,
    parallel_paillier,
    paillier_he_summ
);
