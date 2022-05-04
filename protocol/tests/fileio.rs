//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate protocol;
use protocol::fileio::*;
use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, RwLock},
};

#[test]
fn test_load_data() {
    let t = KeyedCSV {
        headers : vec![],
        records : HashMap::from([
            (String::from("a"), vec![String::from("1"), String::from("10")]),
            (String::from("b"), vec![String::from("2"), String::from("20")]),
            (String::from("c"), vec![String::from("3"), String::from("30")]),
            (String::from("d"), vec![String::from("4"), String::from("40")]),
        ]),
    };


    let plain_data = Arc::new(RwLock::new(KeyedCSV::default()));
    let c = Arc::clone(&plain_data);
    load_data(plain_data, "./tests/keyed_ints.csv", false);

    let r1 = c.read().unwrap();
    assert_eq!(*r1.headers, t.headers);

    let mut k1: Vec<String>= (*r1.records.keys().map(|s| s.clone()).collect::<Vec<String>>()).to_vec().clone();
    let mut k2: Vec<String> = t.records.keys().cloned().collect();
    k1.sort();
    k2.sort();
    assert_eq!(k1, k2);
    for k in k1 {
        let mut v1: Vec<String> =  (*r1).records.get(&k).unwrap().to_vec().clone();
        v1.sort();
        let mut v2 = t.records.get(&k).unwrap().clone();
        v2.sort();
        assert_eq!( v1, v2);
    }
}
