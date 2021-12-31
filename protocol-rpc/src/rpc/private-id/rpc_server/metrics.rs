//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs::File;

#[derive(Serialize, Deserialize)]
pub struct Metrics {
    protocol_name: String,
    partner_input_size: Option<usize>,
    publisher_input_size: Option<usize>,
    union_file_size: Option<usize>,
}

impl Metrics {
    pub fn new(
        protocol_name: String,
        partner_input_size: Option<usize>,
        publisher_input_size: Option<usize>,
        union_file_size: Option<usize>,
    ) -> Metrics {
        Metrics {
            protocol_name,
            partner_input_size,
            publisher_input_size,
            union_file_size,
        }
    }

    pub fn set_partner_input_size(&mut self, partner_input_size: usize) {
        self.partner_input_size = Some(partner_input_size);
    }

    pub fn set_publisher_input_size(&mut self, publisher_input_size: usize) {
        self.publisher_input_size = Some(publisher_input_size);
    }

    pub fn set_union_file_size(&mut self, union_file_size: usize) {
        self.union_file_size = Some(union_file_size);
    }

    pub fn save_metrics(&self, path: &str) ->  Result<(), serde_json::Error> {
        let f = &File::create(path).unwrap();
        serde_json::to_writer(f, &self)
    }

    pub fn print_metrics(&self) {
        println!("-----BEGIN METRIC VIEW-----");
        println!("{}", serde_json::to_string(&self).unwrap());
        println!("-----END METRIC VIEW-----");
    }
}
