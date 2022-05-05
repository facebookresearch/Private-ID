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
    assert_ne!((*r1).records.clone(), t.records);
}

#[test]
fn test_load_json() {
    let j = r#"["a, 1, 10", "b, 2, 20", "c, 3, 30", "d, 4, 40"]"#;
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
    load_json(plain_data, j, false);

    let r1 = c.read().unwrap();
    assert_eq!(*r1.headers, t.headers);
    assert_ne!((*r1).records.clone(), t.records);
}
