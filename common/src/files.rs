//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::path::Path;
use std::str::FromStr;

use rayon::prelude::ParallelSliceMut;

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
/// All zero length fields are removed
pub fn read_csv_as_strings<T>(filename: T, is_flexible: bool) -> Vec<Vec<String>>
where
    T: AsRef<Path>,
{
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(b',')
        .flexible(is_flexible)
        .has_headers(false)
        .from_path(filename)
        .expect("Failure reading CSV file");
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
/// where each row is represented as a vector of u64
/// All zero length fields are removed
pub fn read_csv_as_u64<T>(filename: T) -> Vec<Vec<u64>>
where
    T: AsRef<Path>,
{
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(b',')
        .flexible(false)
        .has_headers(false)
        .from_path(filename)
        .expect("Failure reading CSV file");

    let it = reader.records();
    it.map(|x| {
        x.unwrap()
            .iter()
            .map(|z| {
                u64::from_str(z.trim()).unwrap_or_else(|_| panic!("Cannot format {} as u64", z))
            })
            .collect::<Vec<u64>>()
    })
    .collect::<Vec<Vec<u64>>>()
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

pub fn sort_stringify_id_map(id_map: &[Vec<String>], use_row_numbers: bool) -> String {
    let mut output = "".to_owned();

    let mut sorted_id_map = id_map.iter().collect::<Vec<_>>();
    if sorted_id_map.iter().any(|vec| vec.is_empty()) {
        panic!("Got empty rows to print out");
    }
    sorted_id_map[0..].sort_by(|a, b| a[0].cmp(&b[0]));

    output.push_str("-----BEGIN FULL VIEW-----");
    output.push_str("\n");
    for (i, line) in sorted_id_map.iter().enumerate() {
        let mut record = line.to_vec();
        if use_row_numbers {
            record[0] = i.to_string();
        }
        output.push_str(&format!("{}", record.join("\t")));
        output.push_str("\n");
    }
    output.push_str("-----END FULL VIEW-----");
    output.push_str("\n");
    output
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_sort_stringify_id_map_use_row_number() {
        let s1 = vec![String::from("3"), String::from("a")];
        let s2 = vec![String::from("2"), String::from("a")];
        let s3 = vec![String::from("1"), String::from("a")];
        let id_map = vec![s1, s2, s3];
        let res = sort_stringify_id_map(&id_map, false);
        assert_eq!(
            res,
            "-----BEGIN FULL VIEW-----\n1\ta\n2\ta\n3\ta\n-----END FULL VIEW-----\n"
        );
    }

    #[test]
    fn test_sort_stringify_id_map_no_row_number() {
        let s1 = vec![String::from("3"), String::from("a")];
        let s2 = vec![String::from("2"), String::from("a")];
        let s3 = vec![String::from("1"), String::from("a")];
        let id_map = vec![s1, s2, s3];
        let res = sort_stringify_id_map(&id_map, true);
        assert_eq!(
            res,
            "-----BEGIN FULL VIEW-----\n0\ta\n1\ta\n2\ta\n-----END FULL VIEW-----\n"
        );
    }

    #[test]
    #[should_panic]
    fn test_sort_stringify_id_map_empty_row() {
        let s1 = vec![String::from("3"), String::from("a")];
        let s2 = vec![];
        let s3 = vec![String::from("1"), String::from("a")];
        let id_map = vec![s1, s2, s3];
        sort_stringify_id_map(&id_map, true);
    }

    #[test]
    fn test_write_vec_to_csv() {
        use std::io::Read;

        use tempfile::NamedTempFile;
        let s1 = vec![String::from("3"), String::from("a")];
        let s2 = vec![String::from("2"), String::from("a")];
        let s3 = vec![String::from("1"), String::from("a")];

        let mut id_map = vec![s1, s2, s3];
        let file = NamedTempFile::new().unwrap();
        let mut file1 = file.reopen().unwrap();
        let _ = write_vec_to_csv(&mut id_map, file, false, false);
        let mut buf = String::new();
        file1.read_to_string(&mut buf).unwrap();
        drop(file1);
        assert_eq!(buf, "1,a\n2,a\n3,a\n");
    }

    #[test]
    fn test_write_vec_to_csv_with_header() {
        use std::io::Read;

        use tempfile::NamedTempFile;
        let s0 = vec![String::from("ID"), String::from("NAME")];
        let s1 = vec![String::from("3"), String::from("a")];
        let s2 = vec![String::from("2"), String::from("a")];
        let s3 = vec![String::from("1"), String::from("a")];

        let mut id_map = vec![s0, s1, s2, s3];
        let file = NamedTempFile::new().unwrap();
        let mut file1 = file.reopen().unwrap();
        let _ = write_vec_to_csv(&mut id_map, file, true, false);
        let mut buf = String::new();
        file1.read_to_string(&mut buf).unwrap();
        drop(file1);
        assert_eq!(buf, "ID,NAME\n1,a\n2,a\n3,a\n");
    }

    #[test]
    fn test_write_vec_to_csv_rownumber() {
        use std::io::Read;

        use tempfile::NamedTempFile;
        let s1 = vec![String::from("3"), String::from("a")];
        let s2 = vec![String::from("2"), String::from("a")];
        let s3 = vec![String::from("1"), String::from("a")];

        let mut id_map = vec![s1, s2, s3];
        let file = NamedTempFile::new().unwrap();
        let mut file1 = file.reopen().unwrap();
        let _ = write_vec_to_csv(&mut id_map, file, false, true);
        let mut buf = String::new();
        file1.read_to_string(&mut buf).unwrap();
        drop(file1);
        assert_eq!(buf, "0,a\n1,a\n2,a\n");
    }

    #[test]
    fn test_write_u64cols_to_file() {
        use std::io::Read;

        use tempfile::NamedTempFile;
        let s1 = vec![11, 21];
        let s2 = vec![12, 22];
        let s3 = vec![13, 23];

        let mut id_map = vec![s1, s2, s3];
        let file = NamedTempFile::new().unwrap();
        let mut file1 = file.reopen().unwrap();
        let _ = write_u64cols_to_file(&mut id_map, file);
        let mut buf = String::new();
        file1.read_to_string(&mut buf).unwrap();
        drop(file1);
        assert_eq!(buf, "11,12,13\n21,22,23\n");
    }

    #[test]
    fn test_write_vec_to_stdout() {
        let s1 = vec![String::from("3"), String::from("a")];
        let s2 = vec![String::from("2"), String::from("a")];
        let s3 = vec![String::from("1"), String::from("a")];
        let id_map = vec![s1, s2, s3];
        let res = write_vec_to_stdout(&id_map, 4, false, false);

        assert!(res.is_ok());
    }

    #[test]
    fn test_read_csv_as_keyed_ints() {
        let data = "a,1,10\n
b,2,20\n
c,3,30\n
d,4,40";

        use std::io::Write;

        use tempfile::NamedTempFile;
        // Create a file inside of `std::env::temp_dir()`.
        let mut file1 = NamedTempFile::new().unwrap();

        // Write some test data to the first handle.
        file1.write_all(data.as_bytes()).unwrap();
        let p = file1.path().to_str().unwrap();
        let r: Vec<KeyedNums<u64>> = read_csv_as_keyed_nums(p, false);
        assert_eq!(r.len(), 4);
        let s = r.iter().map(|x| x.key.clone()).collect::<Vec<String>>();
        assert_eq!(s, vec!["a", "b", "c", "d"]);
        assert_eq!(r[0].ints, vec![1, 10]);
        assert_eq!(r[r.len() - 1].ints, vec![4, 40]);
    }

    #[test]
    fn test_transpose_keyed_ints() {
        let data = "a,1,10 \n
b,2,20 \n
c,3,30 \n
d,4,40";

        use std::io::Write;

        use tempfile::NamedTempFile;
        // Create a file inside of `std::env::temp_dir()`.
        let mut file1 = NamedTempFile::new().unwrap();

        // Write some test data to the first handle.
        file1.write_all(data.as_bytes()).unwrap();
        let p = file1.path().to_str().unwrap();
        let r: Vec<KeyedNums<u64>> = read_csv_as_keyed_nums(p, false);
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

    #[test]
    fn test_read_csv_as_strings() {
        let data = "a,1,10\n
b,2,20\n
c,3,30\n
d,4,40";

        use std::io::Write;

        use tempfile::NamedTempFile;
        // Create a file inside of `std::env::temp_dir()`.
        let mut file1 = NamedTempFile::new().unwrap();

        // Write some test data to the first handle.
        file1.write_all(data.as_bytes()).unwrap();
        let p = file1.path().to_str().unwrap();
        let r: Vec<Vec<String>> = read_csv_as_strings(p, false);
        assert_eq!(r.len(), 4);
        assert_eq!(r[0], ["a", "1", "10"]);
        assert_eq!(r[1], ["b", "2", "20"]);
        assert_eq!(r[2], ["c", "3", "30"]);
        assert_eq!(r[3], ["d", "4", "40"]);
    }
}
