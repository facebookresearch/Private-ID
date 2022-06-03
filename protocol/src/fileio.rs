//  Copyright (c) Facebook, Inc. and its affiliates.
//   SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, RwLock},
};

use crate::shared::TFeatures;
use common::{files, timer};
use serde_json::Value;

/// load text and update the protocol
pub fn load_data_with_features<T>(
    input_path: T,
    keys: Arc<RwLock<Vec<String>>>,
    features: Arc<RwLock<TFeatures>>,
    num_features: Arc<RwLock<usize>>,
    num_records: Arc<RwLock<usize>>,
) where
    T: AsRef<Path>,
{
    if let (
        Ok(mut input_keys),
        Ok(mut input_features),
        Ok(mut input_num_features),
        Ok(mut input_num_records),
    ) = (
        keys.write(),
        features.write(),
        num_features.write(),
        num_records.write(),
    ) {
        if !input_keys.is_empty() || !input_features.is_empty() {
            info!("Data is not empty, skipping reading the data again")
        } else {
            let (mut keys, mut features) = common::files::transpose_keyed_nums(
                common::files::read_csv_as_keyed_nums(input_path, false),
            );
            assert!(!features.is_empty(), "Empty data features, fail fast, bye!");
            input_keys.extend(keys.drain(..));
            input_features.extend(features.drain(..));

            *input_num_features = input_features.len();
            *input_num_records = input_features[0].len();

            info!(
                "Data initialised with dimensions: cols: {}, rows: {}, keys len: {}",
                input_num_features,
                input_num_records,
                input_keys.len()
            );
        }
    }
}

#[derive(Default, Debug)]
pub struct KeyedCSV {
    pub headers: Vec<String>,
    pub records: HashMap<String, Vec<String>>,
}

impl KeyedCSV {
    /// Returns the keys(first column of the CSV) read from the CSV Input
    pub fn get_plain_keys(&self) -> Vec<String> {
        self.records
            .keys()
            .map(|k| k.to_string())
            .collect::<Vec<String>>()
    }
    /// Returns a writable CSV record padded with empty values for every other column except the key
    /// If there is no other column but key, it adds an empty string instead of the the plain key
    /// for debugging purposes
    pub fn get_empty_record_with_key(
        &self,
        key: String,
        empty_val: Option<&String>,
    ) -> Vec<String> {
        let mut record = vec![key];

        let mut until = self.headers.len();
        if self.headers.is_empty() {
            until = 2;
        }

        for _ in 1..until {
            record.push(empty_val.unwrap_or(&String::new()).to_string());
        }
        record
    }
    /// Returns a writable CSV record extended with non-key values from the input CSV
    /// If there is no other column but key, it adds the plain key for debugging purposes
    pub fn get_record_with_keys(&self, enc_key: String, raw_key: &str) -> Vec<String> {
        let mut record = vec![enc_key];
        if let Some(extra_columns) = self.records.get(raw_key) {
            if extra_columns.is_empty() {
                record.push(String::from(raw_key));
            } else {
                record.extend(extra_columns.iter().cloned());
            }
        }
        record
    }
}

pub fn load_data(data: Arc<RwLock<KeyedCSV>>, path: &str, has_headers: bool) {
    let t = timer::Timer::new_silent("load");

    let mut lines = files::read_csv_as_strings(path, false);
    let text_len = lines.len();

    if let Ok(mut wguard) = data.write() {
        if wguard.records.is_empty() {
            let mut line_it = lines.drain(..);
            if has_headers {
                if let Some(headers) = line_it.next() {
                    wguard.headers = headers;
                }
            }
            for line in line_it {
                if let Some((key, rest)) = line.split_first() {
                    wguard.records.insert(key.to_string(), rest.to_vec());
                }
            }
            let keys_len = wguard.records.len();
            info!(
                "Read {} lines from {} (dedup: {} lines)",
                text_len,
                path,
                text_len - keys_len
            );
        } else {
            warn!("Attempted to run the protocol after the text was already initaialised")
        }
        t.qps("text read", text_len);
    }
}

pub fn load_json(data: Arc<RwLock<KeyedCSV>>, json_table: &str, has_headers: bool) -> bool {
    // Read json object from dynamic str into the expected Vec<Vec> form (previously from a CSV)
    let table: Value = serde_json::from_str(json_table).unwrap();
    let table: &Vec<Value> = table.as_array().unwrap();
    let table_len = table.len();

    let mut lines: Vec<Vec<String>> = vec![vec!["".to_string()]; table.len()]; // -OR- files::read_csv_as_strings(path)
    for (row_num, row) in table.iter().enumerate() {
        lines[row_num] = vec![row.as_str().unwrap().to_string()];
    }

    let mut ret = false;
    if let Ok(mut wguard) = data.write() {
        if wguard.records.is_empty() {
            let mut line_it = lines.drain(..);
            if has_headers {
                if let Some(headers) = line_it.next() {
                    wguard.headers = headers;
                }
            }
            for line in line_it {
                if let Some((key, rest)) = line.split_first() {
                    wguard.records.insert(key.to_string(), rest.to_vec());
                }
            }
            let keys_len = wguard.records.len();
            info!(
                "Read {} lines from json (dedup: {} lines)",
                table_len,
                table_len - keys_len
            );
            ret = true
        }
    }
    ret
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_keyedcsv_get_plain_keys() {
        let t = KeyedCSV {
            headers : vec![String::from("ID"),String::from("NAME")],
            records : HashMap::from([
                (String::from("25"), vec![String::from("Norway"), String::from("Sunnyvale")]),
                (String::from("24"), vec![String::from("Denmark")]),
                (String::from("12"), vec![String::from("Iceland")]),
            ]),
        };
        let mut v = t.get_plain_keys();
        v.sort();
        assert_eq!(v, vec![String::from("12"),String::from("24"),String::from("25")]);
    }

    #[test]
    fn test_keyedcsv_get_empty_record_with_key_emptyval_none() {
        let t = KeyedCSV {
            headers : vec![String::from("ID"), String::from("NAME")],
            records : HashMap::from([
                (String::from("25"), vec![String::from("Norway"), String::from("Sunnyvale")]),
                (String::from("24"), vec![String::from("Denmark")]),
                (String::from("12"), vec![String::from("Iceland")]),
            ]),
        };
        let v = t.get_empty_record_with_key(String::from("pid"), None);

        assert_eq!(v, vec![String::from("pid"), String::from("")]);
    }

    #[test]
    fn test_keyedcsv_get_empty_record_with_key() {
        let t = KeyedCSV {
            headers : vec![String::from("ID"),String::from("NAME")],
            records : HashMap::from([
                (String::from("25"), vec![String::from("Norway"), String::from("Sunnyvale")]),
                (String::from("24"), vec![String::from("Denmark")]),
                (String::from("12"), vec![String::from("Iceland")]),
            ]),
        };
        let v = t.get_empty_record_with_key(String::from("pid"), Some(&String::from("fb")));

        assert_eq!(v, vec![String::from("pid"), String::from("fb")]);
    }

    #[test]
    fn test_keyedcsv_get_record_with_keys() {
        let t = KeyedCSV {
            headers : vec![String::from("ID"), String::from("NAME")],
            records : HashMap::from([
                (String::from("25"), vec![String::from("Norway"), String::from("Sunnyvale")]),
                (String::from("24"), vec![String::from("Denmark")]),
                (String::from("12"), vec![String::from("Iceland")]),
            ]),
        };
        let v_has_cols = t.get_record_with_keys(String::from("e"), "25");
        let v_empty_cols = t.get_record_with_keys(String::from("e"), "26");
        assert_eq!(v_has_cols, vec![String::from("e"), String::from("Norway"), String::from("Sunnyvale")]);
        assert_eq!(v_empty_cols, vec![String::from("e")]);
    }
}
