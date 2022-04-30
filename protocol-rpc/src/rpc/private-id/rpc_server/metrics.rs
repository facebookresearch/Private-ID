//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use serde_json;
use std::fs::File;

#[derive(Serialize, Deserialize)]
struct RawMetrics {
    protocol_name: String,
    partner_input_size: Option<usize>,
    publisher_input_size: Option<usize>,
    union_file_size: Option<usize>,
}

impl RawMetrics {
    fn new(
        protocol_name: String,
        partner_input_size: Option<usize>,
        publisher_input_size: Option<usize>,
        union_file_size: Option<usize>,
    ) -> RawMetrics {
        RawMetrics {
            protocol_name,
            partner_input_size,
            publisher_input_size,
            union_file_size,
        }
    }

    fn save_metrics(&self, path: &str) ->  Result<(), serde_json::Error> {
        let f = &File::create(path).unwrap();
        serde_json::to_writer(f, &self)
    }

    fn print_metrics(&self) {
        println!("-----BEGIN METRIC VIEW-----");
        println!("{}", serde_json::to_string(&self).unwrap());
        println!("-----END METRIC VIEW-----");
    }
}

pub struct Metrics {
    protocol_name: String,
    partner_input_size: Arc<RwLock<Option<usize>>>,
    publisher_input_size: Arc<RwLock<Option<usize>>>,
    union_file_size: Arc<RwLock<Option<usize>>>,
}

impl Metrics {
    pub fn new(protocol_name: String) -> Metrics {
        Metrics {
            protocol_name,
            partner_input_size: Arc::new(RwLock::default()),
            publisher_input_size: Arc::new(RwLock::default()),
            union_file_size: Arc::new(RwLock::default()),
        }
    }

    fn cp_to_raw(&self) -> RawMetrics{
        RawMetrics::new(
            self.protocol_name.clone(),
            *self.partner_input_size.read().unwrap(),
            *self.publisher_input_size.read().unwrap(),
            *self.union_file_size.read().unwrap(),
        )
    }
    pub fn set_partner_input_size(&self, partner_input_size: usize) {
        let mut d = self.partner_input_size
            .write()
            .unwrap();
        *d = Some(partner_input_size);
    }

    pub fn set_publisher_input_size(&self, publisher_input_size: usize) {
        let mut d = self.publisher_input_size
            .write()
            .unwrap();
        *d = Some(publisher_input_size);
    }

    pub fn set_union_file_size(&self, union_file_size: usize) {
        let mut d = self.union_file_size
            .write()
            .unwrap();
        *d = Some(union_file_size);
    }

    pub fn save_metrics(&self, path: &str) ->  Result<(), serde_json::Error> {
        let raw = self.cp_to_raw();
        raw.save_metrics(path)
    }

    pub fn print_metrics(&self) {
        let raw = self.cp_to_raw();
        raw.print_metrics();
    }
}
