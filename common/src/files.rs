//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate csv;

use rayon::prelude::ParallelSliceMut;
use std::{error::Error, path::Path, str::FromStr};

pub struct KeyedNums<T> {
    pub key: String,
    pub ints: Vec<T>,
}

// TODO get generic implementation for i64 etc
impl KeyedNums<u64> {
    pub fn new(vals: &[String]) -> KeyedNums<u64> {
        assert!(vals.len() >= 2, "Need at least one key and one value");
        KeyedNums {
            key: String::from(vals.first().unwrap()),
            ints: KeyedNums::string_to_u64(&vals[1..]),
        }
    }

    fn string_to_u64(vals: &[String]) -> Vec<u64> {
        vals.iter()
            .map(|x| {
                u64::from_str(x.trim()).unwrap_or_else(|_| panic!("Cannot format {} as u64", x))
            })
            .collect::<Vec<u64>>()
    }
}

/// Input: A vector of rows - each row is a vector with a string key and a vector of ints
/// a 1 10
/// b 2 20
/// c 3 30
///
/// Output: A vector of strings for the first row, followed by a vector of vectors
///         one per row of ints
/// a  b  c
/// 1  2  3
/// 10 20 30
pub fn transpose_keyed_nums(mut data: Vec<KeyedNums<u64>>) -> (Vec<String>, Vec<Vec<u64>>) {
    if data.is_empty() {
        panic!("Got empty data to transpose, fail fast");
    }
    let n_rows = data.len();
    let n_cols: usize = data[0].ints.len();
    let mut keys: Vec<String> = Vec::with_capacity(n_rows);
    let mut features: Vec<Vec<u64>> = vec![vec![0; n_rows]; n_cols];
    for (i, mut e) in data.drain(..).enumerate() {
        keys.push(e.key);
        let e_len = e.ints.len();
        if e_len != n_cols {
            panic!(
                "Column {} has different number of values {}, expected {}",
                i, e_len, n_cols
            );
        }
        for (j, v) in e.ints.drain(..).enumerate() {
            features[j][i] = v
        }
    }
    (keys, features)
}

/// Reads CSV file into vector of rows,
/// where each row is represented as a vector of strings
pub fn read_csv_as_strings<T>(filename: T) -> Vec<Vec<String>>
where
    T: AsRef<Path>,
{
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(b',')
        .flexible(false)
        .has_headers(false)
        .from_path(filename)
        .expect("");
    let it = reader.records();
    it.map(|x| {
        x.unwrap()
            .iter()
            .map(|z| String::from(z.trim()))
            .collect::<Vec<String>>()
    })
    .collect::<Vec<Vec<String>>>()
}

/// Reads CSV file into vector of rows,
/// where each row is a first as key, and then as interger-like values
pub fn read_csv_as_keyed_nums<T>(filename: T, has_headers: bool) -> Vec<KeyedNums<u64>>
where
    T: AsRef<Path>,
{
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(b',')
        .has_headers(has_headers)
        .flexible(false)
        .from_path(filename)
        .expect("");
    let _ = reader.records();
    //TODO: change to iter
    let mut res: Vec<KeyedNums<u64>> = Vec::new();
    for (_, row) in reader.records().enumerate() {
        let v: Vec<String> = row.unwrap().iter().map(String::from).collect();
        res.push(KeyedNums::new(&v))
    }
    res
}

/// Function to save a vector of vector of strings to the CSV file
/// WARN: the function takes ownership of the hashmap and and drains it to the file
// TODO: add parallel sorting of the outputs by key or by value
pub fn write_vec_to_csv<T>(
    view_map: &mut Vec<Vec<String>>,
    path: T,
    output_with_headers: bool,
    use_row_numbers: bool,
) -> Result<(), Box<dyn Error>>
where
    T: AsRef<Path>,
{
    if view_map.is_empty() || view_map.iter().any(|vec| vec.is_empty()) {
        panic!("Got empty rows to write to CSV");
    }
    let mut wr = csv::WriterBuilder::new()
        .buffer_capacity(1024)
        .from_path(path)
        .unwrap();
    let mut start_index = 0;
    if output_with_headers {
        start_index = 1
    }
    view_map[start_index..].par_sort_unstable_by(|a, b| a[0].cmp(&b[0]));

    for (i, line) in view_map.drain(..).enumerate() {
        let mut record = line.to_vec();
        if use_row_numbers && i >= start_index {
            record[0] = i.to_string();
        }
        wr.write_record(record.as_slice())?;
    }
    Ok(())
}

pub fn write_u64cols_to_file<T>(shares: &mut Vec<Vec<u64>>, path: T) -> Result<(), Box<dyn Error>>
where
    T: AsRef<Path>,
{
    let mut wr = csv::WriterBuilder::new()
        .buffer_capacity(1024)
        .from_path(path)
        .unwrap();

    let l = shares[0].len();
    let z = shares.len();
    for i in 0..l {
        let mut line: Vec<String> = Vec::with_capacity(z);
        for share in shares.iter() {
            let s: String = format!("{}", share[i]);
            line.push(s);
        }
        wr.write_record(line.as_slice())?;
    }
    Ok(())
}

pub fn write_vec_to_stdout(
    view_map: &[Vec<String>],
    limit: usize,
    output_with_headers: bool,
    use_row_numbers: bool,
) -> Result<(), String> {
    if view_map.len() > limit {
        warn!(
            "View size {} is bigger than stdout limit {} view will be truncated",
            view_map.len(),
            limit
        );
    }

    let mut start_index = 0;
    if output_with_headers {
        start_index = 1
    }
    let mut slice = view_map.iter().take(limit).collect::<Vec<_>>();
    if slice.len() < start_index || slice.iter().any(|vec| vec.is_empty()) {
        panic!("Got empty rows to print out");
    }
    slice[start_index..].sort_by(|a, b| a[0].cmp(&b[0]));

    println!("-----BEGIN FULL VIEW-----");
    for (i, line) in slice.iter().enumerate() {
        let mut record = line.to_vec();
        if use_row_numbers && i >= start_index {
            record[0] = i.to_string();
        }
        println!("{}", record.join(","));
    }
    println!("-----END FULL VIEW-----");
    Ok(())
}
