#![forbid(unsafe_code)]
#![crate_name = "protocol"]

#[macro_use]
extern crate log;

pub mod fileio;
pub mod private_id;

pub mod shared {
    extern crate crypto;

    use std::path::Path;

    pub type TDomain = u64;  /// Type of the input expected right now

    pub type TFeatures = Vec<Vec<TDomain>>;  /// Feature matrix type

    pub trait LoadData {
        fn load_data<T>(&self, input_path: T)
        where
            T: AsRef<Path>;
    }

    pub trait Reveal {
        fn reveal<T: AsRef<Path>>(&self, path: T);
    }
}
