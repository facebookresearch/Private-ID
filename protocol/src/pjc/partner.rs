//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate common;
extern crate crypto;

use std::path::Path;
use std::sync::Arc;
use std::sync::RwLock;

use common::timer;
use crypto::eccipher;
use crypto::eccipher::gen_scalar;
use crypto::eccipher::ECCipher;
use crypto::paillier::PaillierParallel;
use crypto::prelude::EncryptionKey;
use crypto::prelude::Scalar;
use crypto::prelude::TPayload;
use num_bigint::BigUint;
use num_traits::One;
use zeroize::Zeroizing;

use crate::fileio::load_data_with_features;
use crate::pjc::traits::PartnerPJCProtocol;
use crate::shared::LoadData;
use crate::shared::ShareableEncKey;
use crate::shared::TFeatures;

#[derive(Debug)]
pub struct PartnerPjc {
    ec_cipher: eccipher::ECRistrettoParallel,
    he_cipher: PaillierParallel,
    ec_key: Zeroizing<Scalar>,
    self_num_features: Arc<RwLock<usize>>,
    self_num_records: Arc<RwLock<usize>>,
    plaintext_keys: Arc<RwLock<Vec<String>>>,
    plaintext_features: Arc<RwLock<TFeatures>>,
    self_permutation: Arc<RwLock<Vec<usize>>>,
    decrypted_stats: Arc<RwLock<Vec<u64>>>,
}

impl PartnerPjc {
    pub fn new() -> PartnerPjc {
        PartnerPjc {
            ec_cipher: eccipher::ECRistrettoParallel::new(),
            he_cipher: PaillierParallel::new(),
            ec_key: Zeroizing::new(gen_scalar()),
            self_num_features: Arc::new(RwLock::default()),
            self_num_records: Arc::new(RwLock::default()),
            plaintext_features: Arc::new(RwLock::default()),
            plaintext_keys: Arc::new(RwLock::default()),
            self_permutation: Arc::new(RwLock::default()),
            decrypted_stats: Arc::new(RwLock::default()),
        }
    }

    pub fn get_self_num_features(&self) -> usize {
        *self.self_num_features.clone().read().unwrap()
    }

    pub fn get_self_num_records(&self) -> usize {
        *self.self_num_records.clone().read().unwrap()
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

impl Default for PartnerPjc {
    fn default() -> Self {
        Self::new()
    }
}

impl LoadData for PartnerPjc {
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

impl ShareableEncKey for PartnerPjc {
    fn get_he_public_key(&self) -> EncryptionKey {
        self.he_cipher.enc_key.clone()
    }
}

impl PartnerPJCProtocol for PartnerPjc {
    fn get_permuted_keys(&self) -> TPayload {
        let t = timer::Builder::new()
            .silent(true)
            .label("u_partner")
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

    fn get_permuted_features(&self, feature_index: usize) -> TPayload {
        let t = timer::Builder::new()
            .label("u_partner")
            .size(self.get_self_num_records())
            .build();

        if let (Ok(perm), Ok(features)) = (
            self.self_permutation.clone().read(),
            self.plaintext_features.clone().write(),
        ) {
            let mut feature = features[feature_index].clone();
            common::permutations::permute(perm.as_slice(), &mut feature);
            let res = self.he_cipher.enc_serialise_u64(&feature);
            t.qps(
                format!("column {} HE enc", feature_index).as_str(),
                res.len(),
            );
            res
        } else {
            panic!("Cannot HE encrypt column {} ", feature_index);
        }
    }

    fn encrypt_permute(&self, keys: TPayload) -> TPayload {
        let t = timer::Builder::new()
            .silent(true)
            .label("e_company")
            .size(keys.len())
            .build();

        let mut reencrypted = self
            .ec_cipher
            .to_points_encrypt(keys.as_slice(), &self.ec_key);
        let permutation = common::permutations::gen_permute_pattern(reencrypted.len());
        common::permutations::permute(permutation.as_slice(), &mut reencrypted);
        let res = self.ec_cipher.to_bytes(reencrypted.as_slice());
        t.qps("keys EC enc, permutation, srlz", res.len());
        res
    }

    fn decrypt_stats(&self, encrypted_sums: Vec<TPayload>) {
        let max_val: BigUint = BigUint::one() << 64;

        if let Ok(mut partner_stats) = self.decrypted_stats.clone().write() {
            partner_stats.clear();

            for (feature_index, encrypted_sum) in encrypted_sums.into_iter().enumerate() {
                assert_eq!(encrypted_sum.len(), 1);
                let z = ((self.he_cipher.decrypt_vec(encrypted_sum))[0]).clone();
                let sum = {
                    let v = (z % &max_val).to_u64_digits();
                    assert_eq!(v.len(), 1);
                    v[0]
                };
                info!("Feature: {},  Sum {}", feature_index, sum);

                partner_stats.push(sum);
            }
        }
    }
}
