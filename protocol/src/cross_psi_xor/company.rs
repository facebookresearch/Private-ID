//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use std::path::Path;
use std::sync::Arc;
use std::sync::RwLock;

use common::timer;
use crypto::cupcake::CupcakeParallel;
use crypto::eccipher;
use crypto::eccipher::gen_scalar;
use crypto::eccipher::ECCipher;
use crypto::eccipher::ECRistrettoParallel;
use crypto::prelude::ByteBuffer;
use crypto::prelude::Scalar;
use crypto::prelude::TPayload;
use log::info;
use rand::distributions::Uniform;
use rand::Rng;
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;
use zeroize::Zeroizing;

use crate::cross_psi_xor::traits::*;
use crate::fileio::load_data_with_features;
use crate::shared::LoadData;
use crate::shared::Reveal;
use crate::shared::TFeatures;

#[derive(Debug)]
pub struct CompanyCrossPsiXOR {
    ec_cipher: eccipher::ECRistrettoParallel,
    he_cipher: CupcakeParallel,

    ec_key: Zeroizing<Scalar>,

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

    additive_mask: Arc<RwLock<Vec<Vec<u64>>>>,
    partner_shares: (Arc<RwLock<usize>>, Arc<RwLock<Vec<TPayload>>>),
    self_shares: Arc<RwLock<Vec<Vec<u64>>>>,
}

impl CompanyCrossPsiXOR {
    pub fn new() -> CompanyCrossPsiXOR {
        CompanyCrossPsiXOR {
            ec_cipher: ECRistrettoParallel::new(),
            he_cipher: CupcakeParallel::new(),

            ec_key: Zeroizing::new(gen_scalar()),

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
            partner_shares: (Arc::new(RwLock::default()), Arc::new(RwLock::default())),
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

    fn get_permuted_features(&self) -> TPayload {
        let t = timer::Builder::new()
            .silent(true)
            .label("u_company")
            .size(self.get_self_num_records())
            .build();

        if let (Ok(perm), Ok(mut features)) = (
            self.self_permutation.clone().read(),
            self.plaintext_features.clone().write(),
        ) {
            for i in 0..features.len() {
                assert_eq!(perm.len(), features[i].len());
                common::permutations::permute(perm.as_slice(), &mut features[i]);
            }

            let (num_features, res) = self.he_cipher.enc_serialise_u64_vec(features.as_ref());
            let num_ciphers = res.len();
            assert_eq!(num_features, features.len());
            let num_entries = res[0].len();

            let mut r_flat = res.into_iter().flatten().collect::<Vec<_>>();
            r_flat.push(ByteBuffer {
                buffer: (num_entries as u64).to_le_bytes().to_vec(),
            });
            r_flat.push(ByteBuffer {
                buffer: (num_ciphers as u64).to_le_bytes().to_vec(),
            });
            r_flat.push(ByteBuffer {
                buffer: (num_features as u64).to_le_bytes().to_vec(),
            });
            t.qps(format!("feature length HE enc").as_str(), num_entries);
            r_flat
        } else {
            panic!("Cannot HE encrypt features");
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

    fn generate_additive_shares(&self, features: Vec<TPayload>, num_features: usize) {
        let t = timer::Builder::new()
            .label("server")
            .silent(true)
            .extra_label("additive shares mask")
            .build();
        assert!(features.len() > 0);
        assert!(num_features > 0);
        // Check if all features have the same number of elements
        {
            let l = features.iter().map(|x| x.len()).collect::<Vec<_>>();
            assert_eq!(l.iter().min(), l.iter().max());
        }

        let mut filtered_features = Vec::<TPayload>::new();

        for feature in features.iter() {
            if let Ok(mask) = self.partner_intersection_mask.clone().read() {
                assert_eq!(feature.len(), mask.len());
                let t = feature
                    .iter()
                    .zip(mask.iter())
                    .filter(|(_, &b)| b)
                    .map(|(a, _)| a.clone())
                    .collect::<Vec<_>>();
                filtered_features.push(t);
            } else {
                panic!("unable to get masked vals")
            };
        }

        let num_entries = filtered_features[0].len();

        if let (Ok(mut mask), Ok(mut num_features_partner_shares), Ok(mut partner_shares)) = (
            self.additive_mask.clone().write(),
            self.partner_shares.0.clone().write(),
            self.partner_shares.1.clone().write(),
        ) {
            let mut rng = rand::thread_rng();
            let range = Uniform::new(0_u64, u64::MAX);

            let mut r = {
                let mut r_l = Vec::<Vec<u64>>::new();
                for _ in 0..num_features {
                    let x = (0..num_entries).map(|_| rng.sample(&range)).collect();
                    r_l.push(x);
                }
                r_l
            };

            mask.clear();
            mask.extend(r.drain(..));

            *num_features_partner_shares = num_features;
            partner_shares.clear();
            partner_shares.append(&mut self.he_cipher.xor_plaintext_vec(filtered_features, &mask));
            t.qps(
                "masking values in the intersection",
                partner_shares[0].len(),
            );
        } else {
            panic!("Unable to add additive shares with the intersection")
        }
    }

    fn get_shares(&self) -> TPayload {
        if let (Ok(num_features), Ok(shares)) = (
            self.partner_shares.0.clone().read(),
            self.partner_shares.1.clone().read(),
        ) {
            let mut s_flat = shares.clone().into_iter().flatten().collect::<Vec<_>>();
            let num_ciphers = shares.len();
            let num_entries = shares[0].len();
            s_flat.push(ByteBuffer {
                buffer: (num_entries as u64).to_le_bytes().to_vec(),
            });
            s_flat.push(ByteBuffer {
                buffer: (num_ciphers as u64).to_le_bytes().to_vec(),
            });
            s_flat.push(ByteBuffer {
                buffer: (*num_features as u64).to_le_bytes().to_vec(),
            });
            s_flat
        } else {
            panic!("Unable to read shares");
        }
    }

    fn set_self_shares(&self, data: Vec<TPayload>, num_features: usize) {
        if let Ok(mut shares) = self.self_shares.clone().write() {
            // Check if all features have the same number of elements
            {
                let l = data.iter().map(|x| x.len()).collect::<Vec<_>>();
                assert_eq!(l.iter().min(), l.iter().max());
            }
            info!(
                "Saving self-shares for len {} num_features {}",
                data[0].len(),
                num_features,
            );
            shares.clear();
            shares.append(&mut self.he_cipher.decrypt_vec_u64_vec(data, num_features));
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
            assert!(
                !company_keys.is_empty(),
                "e_partner keys should be uploaded after e_company keys are uploaded"
            );

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
        if let (Ok(indices), Ok(mut additive_mask), Ok(mut self_shares)) = (
            self.self_intersection_indices.clone().read(),
            self.additive_mask.clone().write(),
            self.self_shares.clone().write(),
        ) {
            let mut company_shares = Vec::<Vec<u64>>::new();

            for i in 0..self_shares.len() {
                /*
                let mut t: Vec<u64> = Vec::with_capacity(indices.len());

                for index in indices.iter() {
                    t.push(self_shares[i][*index]);
                }*/

                let t = indices
                    .clone()
                    .into_par_iter()
                    .map(|idx| self_shares[i][idx])
                    .collect();
                company_shares.push(t);
            }
            self_shares.clear();

            let c_filename = format!("{}{}", path.as_ref().display(), "_company_feature.csv");
            info!("revealing company features to output file");
            common::files::write_u64cols_to_file(&mut company_shares, Path::new(&c_filename))
                .unwrap();

            // additive_mask are partner_shares
            let p_filename = format!("{}{}", path.as_ref().display(), "_partner_feature.csv");
            info!("revealing partner features to output file");
            common::files::write_u64cols_to_file(&mut additive_mask, Path::new(&p_filename))
                .unwrap();

            additive_mask.clear();
        } else {
            panic!("Unable to reveal");
        }
    }
}
