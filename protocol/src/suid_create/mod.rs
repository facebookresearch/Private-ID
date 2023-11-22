//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::error::Error;
use std::fmt;

use common::files;
use common::timer;
use crypto::eccipher::gen_scalar;
use crypto::prelude::*;
use itertools::Itertools;
use rand_core::OsRng;

#[derive(Debug)]
pub enum ProtocolError {
    ErrorDataRead(String),
    ErrorDataWrite(String),
    ErrorShuffle(String),
    ErrorEncryption(String),
    ErrorCalculateSUID(String),
    ErrorIO(String),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "protocol error {}", self)
    }
}

impl Error for ProtocolError {}

fn load_data(path: &str, input_with_headers: bool) -> Vec<Vec<String>> {
    let t = timer::Timer::new_silent("load data");

    let mut lines = files::read_csv_as_strings(path, true);
    let text_len = lines.len();

    let mut data = Vec::<Vec<String>>::new();

    let mut line_it = lines.drain(..);
    // Strip the header for now
    if input_with_headers && line_it.next().is_some() {}

    let mut x = HashSet::<Vec<String>>::new();
    // Filter out zero length strings - these will come from ragged
    // arrays since they are padded out to the longest array
    // Also deduplicate all input
    for line in line_it {
        let v = line
            .iter()
            .map(String::from)
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        if !x.contains(&v) {
            data.push(v.clone());
            x.insert(v);
        }
    }
    info!("Read {} lines from {}", text_len, path,);

    t.qps("text read", text_len);
    data
}

fn writer_helper(suids: &[(String, String)], data: &[Vec<String>], path: Option<String>) {
    let mut device = match path {
        Some(path) => {
            let wr = csv::WriterBuilder::new()
                .flexible(true)
                .buffer_capacity(1024)
                .from_path(path)
                .unwrap();
            Some(wr)
        }
        None => None,
    };

    for ((c1, c2), d) in suids.iter().zip_eq(data.iter()) {
        let mut v = vec![c1.clone(), c2.clone()];
        v.extend(d.clone());

        match device {
            Some(ref mut wr) => {
                wr.write_record(v.as_slice()).unwrap();
            }
            None => {
                println!("{}", v.join(","));
            }
        }
    }
}

fn compute_prefix_sum(input: &[usize]) -> Vec<usize> {
    let prefix_sum = input
        .iter()
        .scan(0, |sum, i| {
            *sum += i;
            Some(*sum)
        })
        .collect::<Vec<_>>();

    // offset is now a combined exclusive and inclusive prefix sum
    // that will help us convert to a flattened vector and back to a
    // vector of vectors
    let mut output = Vec::<usize>::with_capacity(prefix_sum.len() + 1);
    output.push(0);
    output.extend(prefix_sum);
    output
}

fn serialize_helper<T>(data: Vec<Vec<T>>) -> (Vec<T>, TPayload, TPayload) {
    let offset = {
        let lengths = data.iter().map(|v| v.len()).collect::<Vec<usize>>();
        compute_prefix_sum(&lengths)
            .iter()
            .map(|&o| ByteBuffer {
                buffer: (o as u64).to_le_bytes().to_vec(),
            })
            .collect::<Vec<_>>()
    };

    let d_flat = data.into_iter().flatten().collect::<Vec<_>>();

    let metadata = vec![
        ByteBuffer {
            buffer: (d_flat.len() as u64).to_le_bytes().to_vec(),
        },
        ByteBuffer {
            buffer: (offset.len() as u64).to_le_bytes().to_vec(),
        },
    ];

    (d_flat, offset, metadata)
}

fn gen_elgamal_keypair() -> (Scalar, TPoint) {
    let private_key = gen_scalar();
    let public_key = &private_key * RISTRETTO_BASEPOINT_TABLE;

    (private_key, public_key)
}

fn unflatten_vec<T: Clone>(data: &[T], psum_offsets: &[usize]) -> Vec<Vec<T>> {
    if psum_offsets.len() < 2 {
        panic!("Offset is a inclusive and exclusive sum, hence needs at least 2 elements");
    }

    let num_output = psum_offsets.len() - 1;

    psum_offsets
        .get(0..num_output)
        .unwrap()
        .iter()
        .zip_eq(psum_offsets.get(1..num_output + 1).unwrap().iter())
        .map(|(&x1, &x2)| data.get(x1..x2).unwrap().to_vec())
        .collect::<Vec<Vec<_>>>()
}

fn elgamal_decrypt(c1: Vec<TPoint>, c2: Vec<TPoint>, private_key: Scalar) -> Vec<TPoint> {
    c1.iter()
        .zip_eq(c2.iter())
        .map(|(&x1, &x2)| x2 + (x1 * (BASEPOINT_ORDER - private_key)))
        .collect::<Vec<_>>()
}

fn elgamal_encrypt(data: Vec<TPoint>, public_key: &TPoint) -> (Vec<TPoint>, Vec<TPoint>) {
    let r = (0..data.len())
        .collect::<Vec<_>>()
        .iter()
        .map(|_| Scalar::random(&mut OsRng))
        .collect::<Vec<_>>();

    let c1 = r
        .iter()
        .map(|x| x * RISTRETTO_BASEPOINT_TABLE)
        .collect::<Vec<_>>();

    let c2 = data
        .iter()
        .zip_eq(r.iter())
        .map(|(x, y)| x + (y * public_key))
        .collect::<Vec<_>>();

    (c1, c2)
}

pub mod merger;
pub mod sharer;
pub mod traits;
