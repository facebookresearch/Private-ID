//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use clap::App;
use clap::Arg;
use log::info;
use rand::distributions;
use rand::thread_rng;
use rand::Rng;

pub mod gen {
    use rand::prelude::SliceRandom;
    use rayon::iter::IntoParallelRefIterator;
    use rayon::iter::ParallelIterator;

    use super::*;

    pub struct Data {
        pub player_a: Vec<String>,
        pub player_a_values: Option<Vec<u32>>,
        pub player_b: Vec<String>,
        pub player_b_values: Option<Vec<String>>,
    }

    pub fn random_data(
        player_a_size: usize,
        player_b_size: usize,
        intersection_size: usize,
    ) -> Data {
        let string_len = 16;
        let intersection = par_random_string(intersection_size, string_len);
        let s = intersection[0].as_bytes();
        info!("{}", s.len());
        let mut player_a = par_random_string(player_a_size, string_len);
        player_a.extend_from_slice(&intersection);
        let mut rng = rand::thread_rng();
        player_a.shuffle(&mut rng);

        let mut player_b = par_random_string(player_b_size, string_len);
        player_b.extend_from_slice(&intersection);
        player_b.shuffle(&mut rng);

        let player_b_features = (0..(player_a_size + intersection_size))
            .map(|_| random_u8().to_string())
            .collect::<Vec<String>>();

        Data {
            player_a,
            player_b,
            player_a_values: None,
            player_b_values: Some(player_b_features),
        }
    }

    pub fn par_random_string(size: usize, string_len: usize) -> Vec<String> {
        (0..size)
            .collect::<Vec<usize>>()
            .par_iter()
            .map(|_| random_string(string_len))
            .collect::<Vec<String>>()
    }

    /// Method to use to generate dummy random string for inputs
    ///
    /// to be used only for dummy string generation
    ///
    /// Uses instance of ThreadRng which has CryptoRng  marker on it.
    /// It makes underlying gen CSPRNG.
    fn random_string(size: usize) -> String {
        thread_rng()
            .sample_iter(&distributions::Alphanumeric)
            .take(size)
            .map(char::from)
            .collect()
    }

    fn random_u32() -> u32 {
        let mut r = thread_rng();
        let s: u32 = r.gen();
        s
    }

    fn random_u8() -> u8 {
        let mut r = thread_rng();
        let s: u8 = r.gen();
        s
    }

    pub fn write_slice_to_file(source: &[String], cols: usize, path: &str) -> Result<(), String> {
        use indicatif::ProgressBar;

        let mut wr = csv::WriterBuilder::new()
            .buffer_capacity(1024)
            .from_path(path)
            .unwrap();
        let progress_bar = ProgressBar::new(source.len() as u64);
        for (i, line) in source.iter().enumerate() {
            let mut buf: Vec<String> = Vec::with_capacity(1 + cols);
            buf.push(line.to_string());
            for _ in 0..cols {
                buf.push(format!("{}", random_u32()));
            }
            wr.write_record(&buf).unwrap();
            if i % 100 == 0 {
                progress_bar.inc(100);
            }
        }
        Ok(())
    }
}

fn main() {
    env_logger::init();

    let matches = App::new("Protocol testing")
        .version("0.1")
        .about("Permutations testing")
        .arg(
            Arg::with_name("dir")
                .short("d")
                .long("dir")
                .value_name("DIR")
                .help("output dir")
                .takes_value(true)
                .default_value("./"),
        )
        .arg(
            Arg::with_name("size")
                .short("n")
                .long("size")
                .value_name("SIZE")
                .help("size_of_dataset")
                .takes_value(true)
                .default_value("10"),
        )
        .arg(
            Arg::with_name("cols")
                .short("c")
                .long("cols")
                .value_name("COLS")
                .help("extra columns")
                .takes_value(true)
                .default_value("0"),
        )
        .arg(
            Arg::with_name("features")
                .short("f")
                .long("features")
                .value_name("FEATURES")
                .help("number of features")
                .takes_value(false),
        )
        .get_matches();

    let size = matches
        .value_of("size")
        .unwrap()
        .parse::<usize>()
        .expect("size param");

    let cols = matches
        .value_of("cols")
        .unwrap()
        .parse::<usize>()
        .expect("size param");

    let gen_features = matches.is_present("features");
    let dir = matches.value_of("dir").unwrap_or("./");

    let fn_a = format!("{}/input_{}_size_{}_cols_{}.csv", dir, "a", size, cols);
    let fn_b = format!("{}/input_{}_size_{}_cols_{}.csv", dir, "b", size, cols);
    let fn_b_features = format!(
        "{}/input_{}_size_{}_cols_{}_features.csv",
        dir, "b", size, cols
    );

    info!("Generating output of size {}", size);
    info!("Player a output: {}", fn_a);
    info!("Player b output: {}", fn_b);
    info!("Player b features: {}", fn_b_features);

    let intrsct = size / 2_usize;
    let size_player = size - intrsct;
    let data = gen::random_data(size_player, size_player, intrsct);
    info!("Data generation done, writing to files");
    gen::write_slice_to_file(&data.player_a, cols, &fn_a).unwrap();
    info!("File {} finished", fn_a);

    gen::write_slice_to_file(&data.player_b, cols, &fn_b).unwrap();
    info!("File {} finished", fn_b);

    if gen_features {
        gen::write_slice_to_file(&data.player_b_values.unwrap(), 0, &fn_b_features).unwrap();
        info!("File {} finished", fn_b_features);
    }

    info!("Bye!");
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_par_random_string() {
        let res = gen::par_random_string(8, 8);
        assert_eq!(res.len(), 8);
    }

    #[test]
    fn test_write_slice_to_file() {
        use tempfile::NamedTempFile;
        let file = NamedTempFile::new().unwrap();
        let input = &mut [String::from("3"), String::from("2")];
        let p = file.path().to_str().unwrap();
        let res = gen::write_slice_to_file(input, 1, p);
        assert!(res.is_ok());
    }

    #[test]
    fn test_random_data() {
        let size = 10;
        let intrsct = size / 2;
        let size_player = size - intrsct;

        let data = gen::random_data(size_player, size_player, intrsct);

        assert_eq!(data.player_a.len(), 10);
    }
}
