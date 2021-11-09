//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate common;
extern crate crypto;

use log::info;
use rand::{distributions::Uniform, Rng};
use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, RwLock},
};

use crate::{
    cross_psi_xor::traits::*,
    fileio::load_data_with_features,
    shared::{LoadData, Reveal, TFeatures},
};
use common::timer;

use crypto::{
    cupcake::CupcakeParallel,
    eccipher,
    eccipher::{gen_scalar, ECCipher, ECRistrettoParallel},
    prelude::{ByteBuffer, Scalar, TPayload},
};

#[derive(Debug)]
pub struct CompanyCrossPsiXOR {
    ec_cipher: eccipher::ECRistrettoParallel,
    he_cipher: CupcakeParallel,

    ec_key: Scalar,

    self_num_records: Arc<RwLock<usize>>,
    self_num_features: Arc<RwLock<usize>>,
    partner_num_records: Arc<RwLock<usize>>,
    partner_num_features: Arc<RwLock<usize>>,

    plaintext_keys: Arc<RwLock<Vec<String>>>,
    plaintext_features: Arc<RwLock<TFeatures>>,

    self_permutation: Arc<RwLock<Vec<usize>>>,
    // These are double encrypted - once by partner
    // and once by company
    encrypted_company_keys: Arc<RwLock<TPayload>>,

    partner_intersection_mask: Arc<RwLock<Vec<bool>>>,
    self_intersection_indices: Arc<RwLock<Vec<usize>>>,

    //TODO: WARN: this is single column only (yet)
    additive_mask: Arc<RwLock<Vec<u64>>>,
    partner_shares: Arc<RwLock<HashMap<usize, TPayload>>>,
    self_shares: Arc<RwLock<HashMap<usize, Vec<u64>>>>,
}

impl CompanyCrossPsiXOR {
    pub fn new() -> CompanyCrossPsiXOR {
        CompanyCrossPsiXOR {
            ec_cipher: ECRistrettoParallel::new(),
            he_cipher: CupcakeParallel::new(),

            ec_key: gen_scalar(),

            self_num_records: Arc::new(RwLock::default()),
            self_num_features: Arc::new(RwLock::default()),
            partner_num_records: Arc::new(RwLock::default()),
            partner_num_features: Arc::new(RwLock::default()),

            plaintext_features: Arc::new(RwLock::default()),
            plaintext_keys: Arc::new(RwLock::default()),

            self_permutation: Arc::new(RwLock::default()),

            encrypted_company_keys: Arc::new(RwLock::default()),

            partner_intersection_mask: Arc::new(RwLock::default()),
            self_intersection_indices: Arc::new(RwLock::default()),

            additive_mask: Arc::new(RwLock::default()),
            partner_shares: Arc::new(RwLock::default()),
            self_shares: Arc::new(RwLock::default()),
        }
    }

    pub fn get_self_num_features(&self) -> usize {
        *self.self_num_features.clone().read().unwrap()
    }

    pub fn get_self_num_records(&self) -> usize {
        *self.self_num_records.clone().read().unwrap()
    }

    pub fn get_partner_num_features(&self) -> usize {
        *self.partner_num_features.clone().read().unwrap()
    }

    pub fn get_partner_num_records(&self) -> usize {
        *self.partner_num_records.clone().read().unwrap()
    }

    pub fn set_partner_num_features(&self, partner_num_features: usize) {
        *self.partner_num_features.clone().write().unwrap() = partner_num_features;
    }

    pub fn set_partner_num_records(&self, partner_num_records: usize) {
        *self.partner_num_records.clone().write().unwrap() = partner_num_records;
    }

    pub fn fill_permute_self(&self) {
        if let Ok(mut permute) = self.self_permutation.clone().write() {
            permute.clear();
            permute.append(&mut common::permutations::gen_permute_pattern(
                self.get_self_num_records(),
            ));
        }
    }
}

impl Default for CompanyCrossPsiXOR {
    fn default() -> Self {
        Self::new()
    }
}

impl LoadData for CompanyCrossPsiXOR {
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

impl CompanyCrossPsiXORProtocol for CompanyCrossPsiXOR {
    fn get_permuted_keys(&self) -> TPayload {
        let t = timer::Builder::new()
            .label("u_company")
            .size(self.get_self_num_records())
            .build();

        if let (Ok(perm), Ok(mut text)) = (
            self.self_permutation.clone().read(),
            self.plaintext_keys.clone().write(),
        ) {
            common::permutations::permute(perm.as_slice(), &mut text);
            let res = self
                .ec_cipher
                .hash_encrypt_to_bytes(text.as_slice(), &self.ec_key);
            t.qps("keys EC enc", res.len());
            res
        } else {
            panic!("Unable to make u_company keys happen")
        }
    }

    fn get_permuted_features(&self, feature_id: usize) -> TPayload {
        let t = timer::Builder::new()
            .silent(true)
            .label("u_company")
            .size(self.get_self_num_records())
            .build();

        if let (Ok(perm), Ok(mut features)) = (
            self.self_permutation.clone().read(),
            self.plaintext_features.clone().write(),
        ) {
            let feature = &mut features[feature_id];
            common::permutations::permute(perm.as_slice(), feature);

            let res = self.he_cipher.enc_serialise_u64(feature);
            t.qps(format!("feature {} HE enc", feature_id).as_str(), res.len());
            res
        } else {
            panic!("Cannot HE encrypt column {} ", feature_id);
        }
    }

    fn set_encrypted_company_keys(&self, mut data: TPayload) {
        if let Ok(mut keys) = self.encrypted_company_keys.clone().write() {
            keys.clear();
            keys.extend(data.drain(..))
        } else {
            panic!("Cannot upload e_company keys");
        }
    }

    fn generate_additive_shares(&self, feature_id: usize, values: TPayload) {
        let t = timer::Builder::new()
            .label("server")
            .silent(true)
            .extra_label("additive shares mask")
            .build();
        let filtered_values: TPayload =
            if let Ok(mask) = self.partner_intersection_mask.clone().read() {
                values
                    .iter()
                    .zip(mask.iter())
                    .filter(|(_, &b)| b)
                    .map(|(a, _)| a.clone())
                    .collect::<TPayload>()
            } else {
                panic!("unable to get masked vals")
            };

        if let (Ok(mut mask), Ok(mut partner_shares)) = (
            self.additive_mask.clone().write(),
            self.partner_shares.clone().write(),
        ) {
            let mut rng = rand::thread_rng();
            let range = Uniform::new(0_u64, u64::MAX);
            *mask = (0..filtered_values.len())
                .map(|_| rng.sample(&range))
                .collect();

            let res = self.he_cipher.xor_plaintext(filtered_values, &mask);
            t.qps("masking values in the intersection", res.len());
            partner_shares.insert(feature_id, res);
        } else {
            panic!("Unable to add additive shares with the intersection")
        }
    }

    fn get_shares(&self, feature_index: usize) -> TPayload {
        if let Ok(mut shares) = self.partner_shares.clone().write() {
            assert!(shares.contains_key(&feature_index),
                "No feature_index {} for shares", feature_index);
            shares.remove(&feature_index).unwrap()
        } else {
            panic!("Unable to read shares");
        }
    }

    fn set_self_shares(&self, feature_index: usize, data: TPayload) {
        if let Ok(mut shares) = self.self_shares.clone().write() {
            info!(
                "Saving self-shares for feature index {} len {}",
                feature_index,
                data.len()
            );
            shares.insert(feature_index, self.he_cipher.decrypt_vec_u64(data));
        } else {
            panic!("Unable to write shares");
        }
    }

    fn calculate_intersection(&self, keys: TPayload) {
        let partner_keys = self.ec_cipher.to_bytes(
            &self
                .ec_cipher
                .to_points_encrypt(keys.as_slice(), &self.ec_key),
        );

        // find the index of the intersection

        if let (Ok(company_keys), Ok(mut partner_mask), Ok(mut company_indices)) = (
            self.encrypted_company_keys.clone().read(),
            self.partner_intersection_mask.clone().write(),
            self.self_intersection_indices.clone().write(),
        ) {
            assert!(!company_keys.is_empty(),
                "e_partner keys should be uploaded after e_company keys are uploaded");

            partner_mask.clear();

            partner_mask.extend(common::vectors::vec_intersection_mask(
                partner_keys.as_slice(),
                company_keys.as_slice(),
            ));

            // TODO: can this be a parallel forall
            for (flag, partner_key) in partner_mask.iter().zip(&partner_keys) {
                if *flag {
                    let index = company_keys
                        .iter()
                        .position(|x| *x == *partner_key)
                        .unwrap();
                    company_indices.push(index);
                }
            }

            info!(
                "Company-Partner Intersection size: {}",
                company_indices.len()
            );
        } else {
            panic!("Unable to find interesection");
        }
    }

    fn get_company_indices(&self) -> TPayload {
        if let Ok(indices) = self.self_intersection_indices.clone().read() {
            let mut index_buffer: TPayload = Vec::with_capacity(indices.len());
            for index in indices.iter() {
                index_buffer.push(ByteBuffer {
                    buffer: (*index as u64).to_le_bytes().to_vec(),
                });
            }
            index_buffer
        } else {
            panic!("Unable to fetch company indices");
        }
    }
}

impl Reveal for CompanyCrossPsiXOR {
    fn reveal<T: AsRef<Path>>(&self, path: T) {
        if let (Ok(indices), Ok(additive_mask), Ok(mut self_shares)) = (
            self.self_intersection_indices.clone().read(),
            self.additive_mask.clone().read(),
            self.self_shares.clone().write(),
        ) {
            let mut company_shares: Vec<u64> = Vec::with_capacity(indices.len());

            for index in indices.iter() {
                company_shares.push(self_shares[&0][*index]);
            }
            self_shares.remove(&0);

            let partner_shares = additive_mask.clone();

            let mut out: Vec<Vec<u64>> =
                Vec::with_capacity(self.get_self_num_features() + self.get_partner_num_features());
            out.push(partner_shares);
            out.push(company_shares);
            info!("revealing columns to output file");
            common::files::write_u64cols_to_file(&mut out, path).unwrap();
        } else {
            panic!("Unable to reveal");
        }
    }
}
