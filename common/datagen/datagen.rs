//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use clap::App;
use clap::Arg;
use log::info;
use rand::distributions;
use rand::thread_rng;
use rand::Rng;

pub mod gen {
    use super::*;
    use rand::prelude::SliceRandom;
    use rayon::iter::IntoParallelRefIterator;
    use rayon::iter::ParallelIterator;

    pub struct Data {
        pub player_a: Vec<String>,
        pub player_a_values: Option<Vec<u32>>,
        pub player_b: Vec<String>,
        pub player_b_values: Option<Vec<u32>>,
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

        Data {
            player_a,
            player_b,
            player_a_values: None,
            player_b_values: None,
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
    let dir = matches.value_of("dir").unwrap_or("./");

    let fn_a = format!("{}/input_{}_size_{}_cols_{}.csv", dir, "a", size, cols);
    let fn_b = format!("{}/input_{}_size_{}_cols_{}.csv", dir, "b", size, cols);

    info!("Generating output of size {}", size);
    info!("Player a output: {}", fn_a);
    info!("Player b output: {}", fn_b);

    let intrsct = size / 2 as usize;
    let size_player = size - intrsct;
    let data = gen::random_data(size_player, size_player, intrsct);
    info!("Data generation done, writing to files");
    gen::write_slice_to_file(&data.player_a, cols, &fn_a).unwrap();
    info!("File {} finished", fn_a);

    gen::write_slice_to_file(&data.player_b, cols, &fn_b).unwrap();
    info!("File {} finished", fn_b);

    info!("Bye!");
}
