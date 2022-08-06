//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use std::path::Path;
use std::sync::Arc;
use std::sync::RwLock;

use common::timer;
use crypto::eccipher;
use crypto::eccipher::gen_scalar;
use crypto::eccipher::ECCipher;
use crypto::eccipher::ECRistrettoParallel;
use crypto::paillier::sum_reduce_with_key;
use crypto::prelude::EncryptionKey;
use crypto::prelude::Scalar;
use crypto::prelude::TPayload;
use crypto::prelude::TypeHeEncKey;
use num_bigint::BigUint;
use num_traits::Zero;
use zeroize::Zeroizing;

use crate::fileio::load_data_with_features;
use crate::pjc::traits::CompanyPJCProtocol;
use crate::shared::LoadData;
use crate::shared::TFeatures;

#[derive(Debug)]
pub struct CompanyPjc {
    ec_cipher: eccipher::ECRistrettoParallel,
    ec_key: Zeroizing<Scalar>,
    partner_he_public_key: Arc<RwLock<TypeHeEncKey>>,
    self_num_features: Arc<RwLock<usize>>,
    self_num_records: Arc<RwLock<usize>>,
    plaintext_keys: Arc<RwLock<Vec<String>>>,
    // TODO: These are unused in this protocl and should be removed
    plaintext_features: Arc<RwLock<TFeatures>>,
    encrypted_company_keys: Arc<RwLock<TPayload>>,
    partner_intersection_mask: Arc<RwLock<Vec<bool>>>,
    encrypted_stats: Arc<RwLock<Vec<TPayload>>>,
}

impl CompanyPjc {
    pub fn new() -> CompanyPjc {
        CompanyPjc {
            ec_cipher: ECRistrettoParallel::new(),
            ec_key: Zeroizing::new(gen_scalar()),
            partner_he_public_key: Arc::new(RwLock::new(EncryptionKey {
                n: BigUint::zero(),
                nn: BigUint::zero(),
            })),
            self_num_features: Arc::new(RwLock::default()),
            self_num_records: Arc::new(RwLock::default()),
            plaintext_keys: Arc::new(RwLock::default()),
            plaintext_features: Arc::new(RwLock::default()),
            encrypted_company_keys: Arc::new(RwLock::default()),
            partner_intersection_mask: Arc::new(RwLock::default()),
            encrypted_stats: Arc::new(RwLock::default()),
        }
    }

    pub fn set_partner_he_public_key(&self, partner_he_pub_key: EncryptionKey) {
        *self.partner_he_public_key.clone().write().unwrap() = partner_he_pub_key;
    }

    pub fn get_self_num_records(&self) -> usize {
        *self.self_num_records.clone().read().unwrap()
    }
}

impl Default for CompanyPjc {
    fn default() -> Self {
        Self::new()
    }
}

impl LoadData for CompanyPjc {
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

impl CompanyPJCProtocol for CompanyPjc {
    fn get_keys(&self) -> TPayload {
        timer::Builder::new()
            .label("u_company")
            .extra_label("keys EC enc and permutation")
            .size(self.get_self_num_records())
            .build();

        if let Ok(text) = self.plaintext_keys.clone().read() {
            self.ec_cipher
                .hash_encrypt_to_bytes(text.as_slice(), &self.ec_key)
        } else {
            panic!("Unable to make u_company keys happen")
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

    fn calculate_intersection(&self, keys: TPayload) {
        let partner_keys = self.ec_cipher.to_bytes(
            &self
                .ec_cipher
                .to_points_encrypt(keys.as_slice(), &self.ec_key),
        );

        // find the index of the intersection
        if let (Ok(company_keys), Ok(mut partner_mask)) = (
            self.encrypted_company_keys.clone().read(),
            self.partner_intersection_mask.clone().write(),
        ) {
            //it's important to have partner keys first
            let mut mask = common::vectors::vec_intersection_mask(
                partner_keys.as_slice(),
                company_keys.as_slice(),
            );

            info!(
                "e-partner Intersection size: {}",
                mask.iter().fold(0, |a, &b| a + b as i32)
            );
            partner_mask.clear();
            partner_mask.extend(mask.drain(..));
        } else {
            panic!("Unable to find interesection");
        }
    }

    fn sum_common_values(&self, feature_index: usize, values: TPayload) {
        let _ = timer::Builder::new()
            .label("company")
            .silent(true)
            .extra_label(format!("u_partner feature index {} he-sum", feature_index).as_str())
            .build();
        let masked_values: TPayload =
            if let Ok(partner_mask) = self.partner_intersection_mask.clone().read() {
                if partner_mask.is_empty() {
                    panic!("Partner mask is empty, send keys beforehand")
                }
                common::vectors::apply_mask(partner_mask.as_slice(), &values)
            } else {
                panic!("unable to get masked vals")
            };

        if let (Ok(public_key), Ok(mut enc_stats)) = (
            self.partner_he_public_key.clone().read(),
            self.encrypted_stats.clone().write(),
        ) {
            let res = sum_reduce_with_key(&public_key, &masked_values);
            enc_stats.push(vec![res]);
        } else {
            panic!("Unable to add additive shares with the intersection")
        }
    }

    fn get_stats(&self) -> Vec<TPayload> {
        if let Ok(stats) = self.encrypted_stats.clone().read() {
            stats.clone()
        } else {
            panic!("Cannot get company stats")
        }
    }
}
