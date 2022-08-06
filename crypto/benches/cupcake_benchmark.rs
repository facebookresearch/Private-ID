//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use criterion::*;
use crypto::cupcake::CupcakeParallel;
use rand::distributions::Uniform;
use rand::Rng;
use rayon::iter::IndexedParallelIterator;
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;

fn parallel_enc(n: usize, c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let range = Uniform::new(0_u64, 1 << 62);

    let cipher = CupcakeParallel::new();
    let data: Vec<u64> = (0..n).map(|_| rng.sample(&range)).collect();

    c.bench_function(
        format!("cupcake parallel enc, size: {}", n).as_str(),
        move |b| {
            b.iter_batched(
                || data.clone(),
                |ctx| cipher.enc_serialise_u64(&ctx),
                BatchSize::SmallInput,
            )
        },
    );
}

fn parallel_enc_xor_dec(n: usize, c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let range = Uniform::new(0_u64, 1 << 62);

    let cipher = CupcakeParallel::new();
    let data_a: Vec<u64> = (0..n).map(|_| rng.sample(&range)).collect();
    let data_b: Vec<u64> = (0..n).map(|_| rng.sample(&range)).collect();

    c.bench_function(
        format!("cupcake parallel enc + add + dec, size: {}", n).as_str(),
        move |b| {
            b.iter_batched(
                || (data_a.clone(), data_b.clone()),
                |ctx| {
                    let a = cipher.enc_serialise_u64(&ctx.0);
                    let b = cipher.xor_plaintext(a, &ctx.1);
                    let _ = cipher.decrypt_vec_u64(b);
                },
                BatchSize::SmallInput,
            )
        },
    );
}

fn parallel_xor_shares(n: usize, c: &mut Criterion) {
    c.bench_function(
        format!("cupcake parallel ser+des, size: {}", n).as_str(),
        move |b| {
            b.iter(|| {
                let mut rng = rand::thread_rng();

                let range = Uniform::new(0_u64, 1 << 62);
                let raw_text: Vec<u64> = (0..n).map(|_| rng.sample(&range)).collect();

                let cipher = CupcakeParallel::new();

                let raw_text_enc = cipher.enc_serialise_u64(raw_text.as_ref());

                let mask: Vec<u64> = (0..raw_text.len()).map(|_| rng.sample(&range)).collect();
                let v_share1_enc = cipher.xor_plaintext(raw_text_enc, &mask);

                let share1 = cipher.decrypt_vec_u64(v_share1_enc.clone());
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
                        assert_eq!(a.0 ^ a.1, b);
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

fn parallel_enc_xor_dec_x10(c: &mut Criterion) {
    parallel_enc_xor_dec(10, c);
}

fn parallel_enc_xor_dec_x100(c: &mut Criterion) {
    parallel_enc_xor_dec(100, c);
}

fn parallel_xor_shares_x100(c: &mut Criterion) {
    parallel_xor_shares(100, c);
}

criterion_group!(
name = parallel_cupcake;
config = Criterion::default()
        .sample_size(10)
        .nresamples(10);
targets = parallel_bench_x1, parallel_bench_x10, parallel_enc_xor_dec_x10, parallel_enc_xor_dec_x100
);

criterion_group!(
name = cupcake_xor_shares;
config = Criterion::default()
        .sample_size(10)
        .nresamples(10);
targets = parallel_xor_shares_x100
);

criterion_main!(cupcake_xor_shares, parallel_cupcake);
