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
pub struct PartnerCrossPsiXOR {
    ec_cipher: eccipher::ECRistrettoParallel,
    he_cipher: CupcakeParallel,
    ec_key: Zeroizing<Scalar>,
    self_num_records: Arc<RwLock<usize>>,
    self_num_features: Arc<RwLock<usize>>,
    company_num_records: Arc<RwLock<usize>>,
    company_num_features: Arc<RwLock<usize>>,
    plaintext_keys: Arc<RwLock<Vec<String>>>,
    plaintext_features: Arc<RwLock<TFeatures>>,
    company_permutation: Arc<RwLock<Vec<usize>>>,
    self_permutation: Arc<RwLock<Vec<usize>>>,
    additive_mask: Arc<RwLock<Vec<Vec<u64>>>>,
    self_shares: Arc<RwLock<Vec<Vec<u64>>>>,
    company_intersection_indices: Arc<RwLock<Vec<usize>>>,
}

impl PartnerCrossPsiXOR {
    pub fn new() -> PartnerCrossPsiXOR {
        PartnerCrossPsiXOR {
            ec_cipher: eccipher::ECRistrettoParallel::new(),
            he_cipher: CupcakeParallel::new(),
            ec_key: Zeroizing::new(gen_scalar()),
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

    pub fn permute<T: Sized + Clone>(&self, values: &mut Vec<T>) {
        if let Ok(permute) = self.company_permutation.clone().read() {
            assert_eq!(permute.len(), values.len());
            common::permutations::permute(permute.as_slice(), values);
        }
    }
}

impl Default for PartnerCrossPsiXOR {
    fn default() -> Self {
        Self::new()
    }
}

impl LoadData for PartnerCrossPsiXOR {
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

impl PartnerCrossPsiXORProtocol for PartnerCrossPsiXOR {
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

    fn get_permuted_features(&self) -> TPayload {
        let t = timer::Builder::new()
            .silent(true)
            .label("u_partner")
            .size(self.get_self_num_records())
            .build();

        if let (Ok(perm), Ok(mut features)) = (
            self.self_permutation.clone().read(),
            self.plaintext_features.clone().write(),
        ) {
            for i in 0..features.len() {
                common::permutations::permute(perm.as_slice(), &mut features[i]);
            }

            let (num_features, res) = self.he_cipher.enc_serialise_u64_vec(features.as_ref());
            assert_eq!(num_features, features.len());
            assert!(res.len() > 0);
            let num_entries = res[0].len();
            let num_ciphers = res.len();

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

            t.qps(format!("features HE enc").as_str(), num_entries);
            r_flat
        } else {
            panic!("Cannot HE encrypt features");
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

    fn get_additive_shares(&self, features: Vec<TPayload>, num_features: usize) -> TPayload {
        let t = timer::Builder::new()
            .label("e_company_features")
            .size(num_features)
            .build();

        if let Ok(mut mask) = self.additive_mask.clone().write() {
            let mut rng = rand::thread_rng();
            let range = Uniform::new(0_u64, u64::MAX);

            assert!(features.len() > 0);
            // Check if all features have the same number of elements
            {
                let l = features.iter().map(|x| x.len()).collect::<Vec<_>>();
                assert_eq!(l.iter().min(), l.iter().max());
            }
            let num_entries = features[0].len();

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

            let res = self.he_cipher.xor_plaintext_vec(features, &mask);
            let num_ciphers = res.len();
            assert_eq!(num_entries, res[0].len());

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
            t.qps(
                format!(
                    "num_features {}, num_records {}, num_ciphers {}",
                    num_features, num_entries, num_ciphers
                )
                .as_str(),
                num_entries,
            );
            r_flat
        } else {
            panic!("Cannot mask with additive shares")
        }
    }

    fn set_self_shares(&self, data: Vec<TPayload>, num_features: usize) {
        if let Ok(mut shares) = self.self_shares.clone().write() {
            info!("Saving self-shares for {} features", num_features);
            let mut res = self.he_cipher.decrypt_vec_u64_vec(data, num_features);
            assert_eq!(res.len(), num_features);

            shares.clear();
            shares.extend(res.drain(..));
        } else {
            panic!("Unable to write shares");
        }
    }
}

impl Reveal for PartnerCrossPsiXOR {
    fn reveal<T: AsRef<Path>>(&self, path: T) {
        if let (Ok(indices), Ok(mut self_shares), Ok(mut additive_mask)) = (
            self.company_intersection_indices.clone().read(),
            self.self_shares.clone().write(),
            self.additive_mask.clone().write(),
        ) {
            let mut company_shares = Vec::<Vec<u64>>::new();

            for i in 0..additive_mask.len() {
                /*
                let mut t: Vec<u64> = Vec::with_capacity(indices.len());

                for index in indices.iter() {
                    t.push(additive_mask[i][*index]);
                }*/

                let t = indices
                    .clone()
                    .into_par_iter()
                    .map(|idx| additive_mask[i][idx])
                    .collect();
                company_shares.push(t);
            }
            additive_mask.clear();

            let c_filename = format!("{}{}", path.as_ref().display(), "_company_feature.csv");
            info!("revealing company features to output file");
            common::files::write_u64cols_to_file(&mut company_shares, Path::new(&c_filename))
                .unwrap();

            let p_filename = format!("{}{}", path.as_ref().display(), "_partner_feature.csv");
            info!("revealing partner features to output file");
            common::files::write_u64cols_to_file(&mut self_shares, Path::new(&p_filename)).unwrap();

            self_shares.clear();
        }
    }
}
