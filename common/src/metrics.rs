//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0
use std::fs::File;
use std::sync::Arc;
use std::sync::RwLock;

use serde::Deserialize;
use serde::Serialize;

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

    fn save_metrics(&self, path: &str) -> Result<(), serde_json::Error> {
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

    fn cp_to_raw(&self) -> RawMetrics {
        RawMetrics::new(
            self.protocol_name.clone(),
            *self.partner_input_size.read().unwrap(),
            *self.publisher_input_size.read().unwrap(),
            *self.union_file_size.read().unwrap(),
        )
    }
    pub fn set_partner_input_size(&self, partner_input_size: usize) {
        let mut d = self.partner_input_size.write().unwrap();
        *d = Some(partner_input_size);
    }

    pub fn set_publisher_input_size(&self, publisher_input_size: usize) {
        let mut d = self.publisher_input_size.write().unwrap();
        *d = Some(publisher_input_size);
    }

    pub fn set_union_file_size(&self, union_file_size: usize) {
        let mut d = self.union_file_size.write().unwrap();
        *d = Some(union_file_size);
    }

    pub fn save_metrics(&self, path: &str) -> Result<(), serde_json::Error> {
        let raw = self.cp_to_raw();
        raw.save_metrics(path)
    }

    pub fn print_metrics(&self) {
        let raw = self.cp_to_raw();
        raw.print_metrics();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_metrics_set_parameters() {
        let partner_sz = Some(4);
        let publisher_sz = Some(5);
        let union_sz = Some(6);
        let partner_new_sz = 14;
        let publisher_new_sz = 15;
        let union_new_sz = 16;
        let m = Metrics {
            protocol_name: "private-id".to_string(),
            partner_input_size: Arc::new(RwLock::new(partner_sz)),
            publisher_input_size: Arc::new(RwLock::new(publisher_sz)),
            union_file_size: Arc::new(RwLock::new(union_sz)),
        };

        assert_eq!(
            m.partner_input_size.read().unwrap().unwrap(),
            partner_sz.unwrap()
        );
        m.set_partner_input_size(partner_new_sz);
        assert_eq!(
            m.partner_input_size.read().unwrap().unwrap(),
            partner_new_sz
        );

        assert_eq!(
            m.publisher_input_size.read().unwrap().unwrap(),
            publisher_sz.unwrap()
        );
        m.set_publisher_input_size(publisher_new_sz);
        assert_eq!(
            m.publisher_input_size.read().unwrap().unwrap(),
            publisher_new_sz
        );

        assert_eq!(
            m.union_file_size.read().unwrap().unwrap(),
            union_sz.unwrap()
        );
        m.set_union_file_size(union_new_sz);
        assert_eq!(m.union_file_size.read().unwrap().unwrap(), union_new_sz);
    }

    #[test]
    fn test_metrics_cp_to_raw() {
        let partner_sz = Some(4);
        let publisher_sz = Some(5);
        let union_sz = Some(6);
        let m = Metrics {
            protocol_name: "private-id".to_string(),
            partner_input_size: Arc::new(RwLock::new(partner_sz)),
            publisher_input_size: Arc::new(RwLock::new(publisher_sz)),
            union_file_size: Arc::new(RwLock::new(union_sz)),
        };

        let r = m.cp_to_raw();
        let t = RawMetrics {
            protocol_name: "private-id".to_string(),
            partner_input_size: partner_sz,
            publisher_input_size: publisher_sz,
            union_file_size: union_sz,
        };
        assert_eq!(r.protocol_name, t.protocol_name);
        assert_eq!(r.partner_input_size, t.partner_input_size);
        assert_eq!(r.publisher_input_size, t.publisher_input_size);
        assert_eq!(r.union_file_size, t.union_file_size);
    }

    #[test]
    fn test_metrics_save() {
        use std::io::Read;

        use tempfile::NamedTempFile;

        let partner_sz = Some(4);
        let publisher_sz = Some(5);
        let union_sz = Some(6);
        let m = Metrics {
            protocol_name: "private-id".to_string(),
            partner_input_size: Arc::new(RwLock::new(partner_sz)),
            publisher_input_size: Arc::new(RwLock::new(publisher_sz)),
            union_file_size: Arc::new(RwLock::new(union_sz)),
        };

        let mut file = NamedTempFile::new().unwrap();
        m.save_metrics(file.path().to_str().unwrap()).unwrap();
        m.print_metrics();
        let mut buf = String::new();
        file.read_to_string(&mut buf).unwrap();
        assert_eq!(
            buf,
            "{\"protocol_name\":\"private-id\",\"partner_input_size\":4,\"publisher_input_size\":5,\"union_file_size\":6}"
        );
        drop(file);
    }
}
