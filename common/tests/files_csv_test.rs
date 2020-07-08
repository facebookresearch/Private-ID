//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate common;

use common::files::{read_csv_as_keyed_nums, transpose_keyed_nums, KeyedNums};

#[test]
fn test_read_csv_as_keyed_ints() {
    let r: Vec<KeyedNums<u64>> = read_csv_as_keyed_nums("./tests/keyed_ints.csv", false);
    assert_eq!(r.len(), 4);
    let s = r
        .iter()
        .map(|x| String::from(x.key.clone()))
        .collect::<Vec<String>>();
    assert_eq!(s, vec!["a", "b", "c", "d"]);
    assert_eq!(r[0].ints, vec![1, 10]);
    assert_eq!(r[r.len() - 1].ints, vec![4, 40]);
}

#[test]
fn test_transpose_keyed_ints() {
    let r: Vec<KeyedNums<u64>> = read_csv_as_keyed_nums("./tests/keyed_ints.csv", false);
    assert_eq!(r.len(), 4);
    let (keys, rows) = transpose_keyed_nums(r);
    assert_eq!(keys.len(), 4);
    assert_eq!(keys, vec!["a", "b", "c", "d"]);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].len(), 4);
    assert_eq!(rows[0], [1, 2, 3, 4]);
    assert_eq!(rows[1].len(), 4);
    assert_eq!(rows[1], [10, 20, 30, 40]);
}
