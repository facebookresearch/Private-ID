//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use protocol::fileio::*;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::RwLock;

#[test]
fn test_load_data() {
    let t = KeyedCSV {
        headers: vec![],
        records: HashMap::from([
            (
                String::from("a"),
                vec![String::from("1"), String::from("10")],
            ),
            (
                String::from("b"),
                vec![String::from("2"), String::from("20")],
            ),
            (
                String::from("c"),
                vec![String::from("3"), String::from("30")],
            ),
            (
                String::from("d"),
                vec![String::from("4"), String::from("40")],
            ),
        ]),
    };

    let plain_data = Arc::new(RwLock::new(KeyedCSV::default()));
    load_data(plain_data.clone(), "./tests/keyed_ints.csv", false);

    let r1 = plain_data.read().unwrap();
    assert_eq!(*r1.headers, t.headers);
    assert_eq!((*r1).records.clone(), t.records);
}
