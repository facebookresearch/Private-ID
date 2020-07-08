//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate common;
extern crate crypto;

use log::info;
use std::{
    collections::HashMap,
    ops::Deref,
    path::Path,
    sync::{Arc, RwLock},
};

use crate::{
    cross_psi::traits::*,
    fileio::load_data_with_features,
    shared::{LoadData, Reveal, ShareableEncKey, TFeatures},
};
use common::timer;

use crypto::{
    eccipher,
    eccipher::{gen_scalar, ECCipher},
    he,
    prelude::{mod_sub, rand_bigints, BigInt, EncryptionKey, Scalar, TPayload},
};

#[derive(Debug)]
pub struct PartnerCrossPsi {
    ec_cipher: eccipher::ECRistrettoParallel,
    he_cipher: he::PaillierParallel,
    ec_key: Scalar,
    company_he_public_key: Arc<RwLock<EncryptionKey>>,
    self_num_records: Arc<RwLock<usize>>,
    self_num_features: Arc<RwLock<usize>>,
    company_num_records: Arc<RwLock<usize>>,
    company_num_features: Arc<RwLock<usize>>,
    plaintext_keys: Arc<RwLock<Vec<String>>>,
    plaintext_features: Arc<RwLock<TFeatures>>,
    company_permutation: Arc<RwLock<Vec<usize>>>,
    self_permutation: Arc<RwLock<Vec<usize>>>,
    additive_mask: Arc<RwLock<Vec<BigInt>>>,
    self_shares: Arc<RwLock<HashMap<usize, Vec<BigInt>>>>,
    company_intersection_indices: Arc<RwLock<Vec<usize>>>,
}

impl PartnerCrossPsi {
    pub fn new() -> PartnerCrossPsi {
        PartnerCrossPsi {
            ec_cipher: eccipher::ECRistrettoParallel::new(),
            he_cipher: he::PaillierParallel::new(),
            ec_key: gen_scalar(),
            company_he_public_key: Arc::new(RwLock::new(EncryptionKey {
                n: BigInt::zero(),
                nn: BigInt::zero(),
            })),
            self_num_records: Arc::new(RwLock::default()),
            self_num_features: Arc::new(RwLock::default()),
            company_num_records: Arc::new(RwLock::default()),
            company_num_features: Arc::new(RwLock::default()),
            plaintext_keys: Arc::new(RwLock::default()),
            plaintext_features: Arc::new(RwLock::default()),
            company_permutation: Arc::new(RwLock::default()),
            self_permutation: Arc::new(RwLock::default()),
            additive_mask: Arc::new(RwLock::default()),
            self_shares: Arc::new(RwLock::default()),
            company_intersection_indices: Arc::new(RwLock::default()),
        }
    }

    pub fn set_company_intersection_indices(&self, mut indices: Vec<usize>) {
        if let Ok(mut company_indices) = self.company_intersection_indices.clone().write() {
            company_indices.clear();
            company_indices.extend(indices.drain(..));
        } else {
            panic!("Cannot set indices");
        }
    }

    pub fn get_self_num_features(&self) -> usize {
        *self.self_num_features.clone().read().unwrap()
    }

    pub fn get_self_num_records(&self) -> usize {
        *self.self_num_records.clone().read().unwrap()
    }

    pub fn get_company_num_features(&self) -> usize {
        *self.company_num_features.clone().read().unwrap()
    }

    pub fn get_company_num_records(&self) -> usize {
        *self.company_num_records.clone().read().unwrap()
    }

    pub fn set_company_num_records(&self, company_num_records: usize) {
        *self.company_num_records.clone().write().unwrap() = company_num_records;
    }

    pub fn set_company_num_features(&self, company_num_features: usize) {
        *self.company_num_features.clone().write().unwrap() = company_num_features;
    }

    pub fn set_company_he_public_key(&self, company_he_public_key: EncryptionKey) {
        *self.company_he_public_key.clone().write().unwrap() = company_he_public_key;
    }

    pub fn fill_permute_company(&self, length: usize) {
        if let Ok(mut permute) = self.company_permutation.clone().write() {
            permute.clear();
            permute.append(&mut common::permutations::gen_permute_pattern(length));
        }
    }

    pub fn fill_permute_self(&self) {
        if let Ok(mut permute) = self.self_permutation.clone().write() {
            permute.clear();
            permute.append(&mut common::permutations::gen_permute_pattern(
                self.get_self_num_records(),
            ));
        }
    }

    pub fn permute<T: Sized>(&self, values: &mut Vec<T>) {
        common::permutations::permute(
            self.company_permutation.clone().read().unwrap().as_slice(),
            values,
        );
    }
}

impl Default for PartnerCrossPsi {
    fn default() -> Self {
        Self::new()
    }
}

impl LoadData for PartnerCrossPsi {
    fn load_data<T>(&self, input_path: T)
    where
        T: AsRef<Path>,
    {
        load_data_with_features(
            input_path,
            self.plaintext_keys.clone(),
            self.plaintext_features.clone(),
            self.self_num_features.clone(),
            self.self_num_records.clone(),
        )
    }
}

impl ShareableEncKey for PartnerCrossPsi {
    fn get_he_public_key(&self) -> EncryptionKey {
        (*self.he_cipher.enc_key.clone()).clone()
    }
}

impl PartnerCrossPsiProtocol for PartnerCrossPsi {
    fn get_permuted_keys(&self) -> TPayload {
        timer::Builder::new()
            .label("u_partner")
            .extra_label("keys EC enc")
            .size(self.get_self_num_records())
            .build();

        if let (Ok(perm), Ok(mut text)) = (
            self.self_permutation.clone().read(),
            self.plaintext_keys.clone().write(),
        ) {
            common::permutations::permute(perm.as_slice(), &mut text);
            self.ec_cipher
                .hash_encrypt_to_bytes(text.as_slice(), &self.ec_key)
        } else {
            panic!("Could not permute and encrypt keys");
        }
    }

    fn get_permuted_features(&self, feature_index: usize) -> TPayload {
        let t = timer::Builder::new()
            .silent(true)
            .label("u_partner")
            .size(self.get_self_num_records())
            .build();

        if let (Ok(perm), Ok(mut features)) = (
            self.self_permutation.clone().read(),
            self.plaintext_features.clone().write(),
        ) {
            let feature_column = &mut features[feature_index];
            common::permutations::permute(perm.as_slice(), feature_column);
            let res = self.he_cipher.enc_serialise_u64(&feature_column);
            t.qps(
                format!("column {} HE enc", feature_index).as_str(),
                res.len(),
            );
            res
        } else {
            panic!("Cannot HE encrypt column {} ", feature_index);
        }
    }

    fn encrypt(&self, keys: TPayload) -> TPayload {
        timer::Builder::new()
            .label("e_company")
            .extra_label("keys EC enc + srlz")
            .size(keys.len())
            .build();

        self.ec_cipher.to_bytes(
            self.ec_cipher
                .to_points_encrypt(keys.as_slice(), &self.ec_key)
                .as_slice(),
        )
    }

    fn generate_additive_shares(&self, _: usize, values: TPayload) -> TPayload {
        {
            *self.additive_mask.clone().write().unwrap() = rand_bigints(values.len());
        }

        if let (Ok(key), Ok(mask)) = (
            self.company_he_public_key.clone().read(),
            self.additive_mask.clone().read(),
        ) {
            self.he_cipher
                .subtract_plaintext(key.deref(), values, &mask)
        } else {
            panic!("Cannot mask with additive shares")
        }
    }

    fn set_self_shares(&self, feature_index: usize, data: TPayload) {
        if let Ok(mut shares) = self.self_shares.clone().write() {
            info!("Saving self-shares for feature {}", feature_index);
            shares.insert(feature_index, self.he_cipher.decrypt(data));
        } else {
            panic!("Unable to write shares");
        }
    }
}

impl Reveal for PartnerCrossPsi {
    fn reveal<T: AsRef<Path>>(&self, path: T) {
        if let (Ok(indices), Ok(mut self_shares), Ok(mut additive_mask)) = (
            self.company_intersection_indices.clone().read(),
            self.self_shares.clone().write(),
            self.additive_mask.clone().write(),
        ) {
            let output_mod = BigInt::one() << 64;
            let n = BigInt::one() << 1024;

            let mut filtered_shares: Vec<BigInt> = Vec::with_capacity(indices.len());

            for index in indices.iter() {
                filtered_shares.push(additive_mask[*index].clone());
            }
            additive_mask.clear();

            let company_shares = filtered_shares
                .iter()
                .map(|e| (Option::<u64>::from(&mod_sub(e, &n, &output_mod))).unwrap())
                .collect::<Vec<u64>>();

            let partner_shares = self_shares
                .remove(&0)
                .unwrap()
                .iter()
                .map(|e| (Option::<u64>::from(&mod_sub(e, &n, &output_mod))).unwrap())
                .collect::<Vec<u64>>();

            let mut out: Vec<Vec<u64>> =
                Vec::with_capacity(self.get_self_num_features() + self.get_company_num_features());
            out.push(partner_shares);
            out.push(company_shares);
            info!("revealing columns to output file");
            common::files::write_u64cols_to_file(&mut out, path).unwrap();
        }
    }
}
