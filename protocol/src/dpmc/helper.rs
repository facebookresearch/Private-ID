//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate csv;

use std::collections::HashMap;
use std::collections::HashSet;
use std::convert::TryInto;
use std::path::Path;
use std::sync::Arc;
use std::sync::RwLock;

use base64::engine::general_purpose::URL_SAFE;
use base64::Engine;
use common::permutations::gen_permute_pattern;
use common::permutations::permute;
use common::permutations::undo_permute;
use common::timer;
use crypto::eccipher::gen_scalar;
use crypto::eccipher::ECCipher;
use crypto::eccipher::ECRistrettoParallel;
use crypto::prelude::*;
use fernet::Fernet;
use itertools::Itertools;
use rand::distributions::Uniform;
use rand::Rng;
use rayon::iter::ParallelDrainRange;
use rayon::iter::ParallelIterator;

use super::writer_helper_dpmc;
use super::ProtocolError;
use crate::dpmc::traits::HelperDpmcProtocol;
use crate::shared::TFeatures;

#[derive(Debug)]
struct PartnerData {
    h_b_partner: Vec<Vec<TPoint>>,
    features: TFeatures,
    g_zi: Vec<ByteBuffer>,
}

struct SetDiff {
    s_company: HashSet<String>,
    s_partner: HashSet<String>,
}

pub struct HelperDpmc {
    keypair_sk: Scalar,
    keypair_pk: TPoint,
    company_public_key: Arc<RwLock<TPoint>>,
    ec_cipher: ECRistrettoParallel,
    self_permutation: Arc<RwLock<Vec<usize>>>,
    partners_data: Arc<RwLock<Vec<PartnerData>>>,
    set_diffs: Arc<RwLock<Vec<SetDiff>>>,
    h_company_beta: Arc<RwLock<Vec<Vec<TPoint>>>>,
    partner_shares: Arc<RwLock<HashMap<usize, Vec<u64>>>>,
    id_map: Arc<RwLock<Vec<(String, usize, bool, usize)>>>,
}

impl HelperDpmc {
    pub fn new() -> HelperDpmc {
        let x = gen_scalar();
        HelperDpmc {
            keypair_sk: x,
            keypair_pk: &x * RISTRETTO_BASEPOINT_TABLE,
            company_public_key: Arc::new(RwLock::default()),
            ec_cipher: ECRistrettoParallel::default(),
            self_permutation: Arc::new(RwLock::default()),
            partners_data: Arc::new(RwLock::default()),
            set_diffs: Arc::new(RwLock::default()),
            h_company_beta: Arc::new(RwLock::default()),
            partner_shares: Arc::new(RwLock::default()),
            id_map: Arc::new(RwLock::default()),
        }
    }

    pub fn set_company_public_key(
        &self,
        company_public_key: TPayload,
    ) -> Result<(), ProtocolError> {
        let pk = self.ec_cipher.to_points(&company_public_key);
        // Check that one key is sent
        assert_eq!(pk.len(), 1);

        match self.company_public_key.clone().write() {
            Ok(mut company_pk) => {
                *company_pk = pk[0];
                assert!(!(*company_pk).is_identity());
                Ok(())
            }
            _ => {
                error!("Unable to set company public key");
                Err(ProtocolError::ErrorEncryption(
                    "unable to set company public key".to_string(),
                ))
            }
        }
    }

    pub fn get_helper_public_key(&self) -> Result<TPayload, ProtocolError> {
        Ok(self.ec_cipher.to_bytes(&[self.keypair_pk]))
    }
}

impl Default for HelperDpmc {
    fn default() -> Self {
        Self::new()
    }
}

fn decrypt_shares(mut enc_t: TPayload, aes_key: String) -> (TFeatures, TPayload) {
    let mut t = {
        let fernet = Fernet::new(&aes_key).unwrap();
        enc_t
            .par_drain(..)
            .map(|x| {
                let ctxt_str = String::from_utf8(x.buffer).unwrap();
                ByteBuffer {
                    buffer: fernet.decrypt(&ctxt_str).unwrap().to_vec(),
                }
            })
            .collect::<Vec<_>>()
    };

    let num_features =
        u64::from_le_bytes(t.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;
    let num_rows =
        u64::from_le_bytes(t.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;
    let g_zi = t.drain(num_features * num_rows..).collect::<Vec<_>>();

    let mut features = TFeatures::new();
    for i in (0..num_features).rev() {
        let x = t
            .drain(i * num_rows..)
            .map(|x| u64::from_le_bytes(x.buffer.as_slice().try_into().unwrap()))
            .collect::<Vec<_>>();
        features.push(x);
    }

    (features, g_zi)
}

impl HelperDpmcProtocol for HelperDpmc {
    fn remove_partner_scalar_from_p_and_set_shares(
        &self,
        data: TPayload,
        psum: Vec<usize>,
        enc_alpha_t: Vec<u8>,
        p_scalar_g: TPayload,
        xor_shares: TPayload,
    ) -> Result<(), ProtocolError> {
        match (
            self.partners_data.clone().write(),
            self.set_diffs.clone().write(),
        ) {
            (Ok(mut partners_data), Ok(mut set_diffs)) => {
                let t = timer::Timer::new_silent("load_h_b_partner");

                let aes_key = {
                    let aes_key_bytes = {
                        let x = self
                            .ec_cipher
                            .to_points_encrypt(&p_scalar_g, &self.keypair_sk);
                        let y = self.ec_cipher.to_bytes(&x);
                        y[0].buffer.clone()
                    };
                    URL_SAFE.encode(aes_key_bytes)
                };

                let alpha_t = {
                    let ctxt_str: String = String::from_utf8(enc_alpha_t.clone()).unwrap();

                    Scalar::from_bytes_mod_order(
                        Fernet::new(&aes_key)
                            .unwrap()
                            .decrypt(&ctxt_str)
                            .unwrap()
                            .to_vec()[0..32]
                            .try_into()
                            .unwrap(),
                    )
                };

                // This is an array of exclusive-inclusive prefix sum - hence
                // number of keys is one less than length
                let num_keys = psum.len() - 1;

                // Unflatten
                let pdata = {
                    let t = self.ec_cipher.to_points_encrypt(&data, &alpha_t.invert());

                    psum.get(0..num_keys)
                        .unwrap()
                        .iter()
                        .zip_eq(psum.get(1..num_keys + 1).unwrap().iter())
                        .map(|(&x1, &x2)| t.get(x1..x2).unwrap().to_vec())
                        .collect::<Vec<Vec<_>>>()
                };

                t.qps("deserialize_exp", pdata.len());

                let (features, g_zi) = decrypt_shares(xor_shares, aes_key);

                partners_data.push(PartnerData {
                    h_b_partner: pdata,
                    features,
                    g_zi,
                });

                set_diffs.push(SetDiff {
                    s_company: HashSet::<String>::new(),
                    s_partner: HashSet::<String>::new(),
                });

                Ok(())
            }
            _ => {
                error!("Cannot load e_company");
                Err(ProtocolError::ErrorDeserialization(
                    "cannot load h_b_partner".to_string(),
                ))
            }
        }
    }

    fn set_encrypted_company(
        &self,
        company: TPayload,
        company_psum: Vec<usize>,
    ) -> Result<(), ProtocolError> {
        match (self.h_company_beta.clone().write(),) {
            (Ok(mut h_company_beta),) => {
                // To ragged array
                let num_keys = company_psum.len() - 1;
                h_company_beta.clear();
                let e_company = {
                    let t = self.ec_cipher.to_points(&company);
                    company_psum
                        .get(0..num_keys)
                        .unwrap()
                        .iter()
                        .zip_eq(company_psum.get(1..num_keys + 1).unwrap().iter())
                        .map(|(&x1, &x2)| t.get(x1..x2).unwrap().to_vec())
                        .collect::<Vec<Vec<_>>>()
                };
                h_company_beta.extend(e_company);

                Ok(())
            }
            _ => {
                error!("Unable to obtain locks to buffers for set_encrypted_company");
                Err(ProtocolError::ErrorEncryption(
                    "unable to encrypt data".to_string(),
                ))
            }
        }
    }

    fn calculate_set_diff(&self, partner_idx: usize) -> Result<(), ProtocolError> {
        match (
            self.h_company_beta.clone().read(),
            self.partners_data.clone().read(),
            self.set_diffs.clone().write(),
        ) {
            (Ok(e_company), Ok(partners_data), Ok(mut set_diffs)) => {
                let e_partner = &partners_data[partner_idx].h_b_partner;

                let set_diff = &mut set_diffs[partner_idx];
                let s_company = &mut set_diff.s_company;
                let s_partner = &mut set_diff.s_partner;

                let s_c = e_company.iter().map(|e| e[0]).collect::<Vec<_>>();
                let s_p = e_partner.iter().map(|e| e[0]).collect::<Vec<_>>();

                let max_len = e_company.iter().map(|e| e.len()).max().unwrap();

                // Start with both vectors as all valid
                let mut e_c_valid = vec![true; e_company.len()];
                let mut e_p_valid = vec![true; e_partner.len()];

                for idx in 0..max_len {
                    // TODO: This should be a ByteBuffer instead of a vec<u8>
                    let mut e_c_map = HashMap::<Vec<u8>, usize>::new();

                    // Strip the idx-th key (viewed as a column)
                    for (e, i) in e_company
                        .iter()
                        .enumerate()
                        .filter(|(_, e)| e.len() > idx)
                        .map(|(i, e)| (e[idx], i))
                    {
                        // Ristretto points are not hashable by themselves
                        e_c_map.insert(e.compress().to_bytes().to_vec(), i);
                    }

                    // Vector of indices of e_p that match. These will be set to false
                    let mut e_p_match_idx = Vec::<usize>::new();
                    for ((i, e), _) in e_partner
                        .iter()
                        .enumerate()
                        .zip_eq(e_p_valid.iter())
                        .filter(|((_, _), &f)| f)
                    {
                        // Find the minimum index where match happens
                        let match_idx = e
                            .iter()
                            .map(|key|
                                // TODO: Replace with match
                                if e_c_map.contains_key(&key.compress().to_bytes().to_vec()) {
                                    let &m_idx = e_c_map.get(&key.compress().to_bytes().to_vec()).unwrap();
                                    (m_idx, e_c_valid[m_idx])
                                } else {
                                    // Using length of vector as a sentinel value. Will get
                                    // filtered out because of false
                                    (e_c_valid.len(), false)
                                })
                            .filter(|(_, f)| *f)
                            .map(|(e, _)| e)
                            .min();

                        // For those indices that have matched - set them to false
                        // Also assign the correct keys
                        if let Some(m_idx) = match_idx {
                            e_c_valid[m_idx] = false;
                            e_p_match_idx.push(i);
                        }
                    }

                    // Set all e_p that matched to false - so they aren't matched in the next
                    // iteration
                    e_p_match_idx.iter().for_each(|&idx| e_p_valid[idx] = false);
                }

                // Create S_p by filtering out values that matched
                s_partner.clear();
                {
                    // Only keep s_p that have not been matched
                    let mut inp = s_p
                        .iter()
                        .zip_eq(e_p_valid.iter())
                        .filter(|(_, &f)| f)
                        .map(|(&e, _)| e)
                        .collect::<Vec<_>>();

                    if !inp.is_empty() {
                        // Permute s_p
                        permute(gen_permute_pattern(inp.len()).as_slice(), &mut inp);

                        // save output
                        let x = self.ec_cipher.to_bytes(inp.as_slice());
                        let y = x.iter().map(|t| t.to_string()).collect::<HashSet<String>>();
                        s_partner.extend(y);
                    }
                }

                // Create S_c by filtering out values that matched
                let t = s_c
                    .iter()
                    .zip_eq(e_c_valid.iter())
                    .filter(|(_, &f)| f)
                    .map(|(&e, _)| e)
                    .collect::<Vec<_>>();
                s_company.clear();

                if !t.is_empty() {
                    let x = self.ec_cipher.to_bytes(t.as_slice());
                    let y = x.iter().map(|t| t.to_string()).collect::<HashSet<String>>();
                    s_company.extend(y);
                }

                Ok(())
            }
            _ => {
                error!("Unable to obtain locks to buffers for set diff operation");
                Err(ProtocolError::ErrorEncryption(
                    "unable to encrypt data".to_string(),
                ))
            }
        }
    }

    /// s_partner_i has all the data that are in Partner_i but did not get matched.
    /// s_company_i has all the data that are in Company but not in partner i.
    ///
    /// 1. Add all elements from P_i that are not in SP_i in the id_map.
    /// Essentially, these are the items on the intersection.
    /// 2. Add intersection of all SC_i elements. These are the items that company
    /// has, but none of the partners had.
    ///
    /// Example:
    /// C:  a b c d e f
    /// P1: a b c g f
    /// P2: a b d h
    ///
    /// SC1: d e
    /// SP1: g
    /// SC2: c e f
    /// SP2: h
    ///
    /// 1) P1 \ SP1: a b c f
    /// LJ result: a b c f
    ///
    /// 2) P2 \ SP2: a b d
    /// LJ result: a b c d f
    ///
    /// 3) SC1 intersection SC2: e
    /// LJ result: a b c d e f
    fn calculate_id_map(&self, num_of_matches: usize) {
        match (
            self.partners_data.clone().read(),
            self.set_diffs.clone().read(),
            self.self_permutation.clone().read(),
            self.id_map.clone().write(),
        ) {
            (Ok(partners_data), Ok(set_diffs), Ok(permutation), Ok(mut id_map)) => {
                assert_eq!(partners_data.len(), set_diffs.len());

                // Compute the intersection of all SC_i
                let sc_intersection = {
                    let mut x: HashSet<_> = set_diffs[0].s_company.clone();

                    for p in 1..set_diffs.len() {
                        x.retain(|e| set_diffs[p].s_company.contains(e));
                    }
                    x
                };

                // Create a hashmap for all unique partner keys that are not in S_Partner
                let mut unique_partner_ids: HashMap<String, Vec<(usize, usize)>> = HashMap::new();
                for p in 0..set_diffs.len() {
                    // Get the first column.
                    let partner_keys = {
                        let tmp = {
                            let mut h_b_partner = partners_data[p].h_b_partner.clone();
                            undo_permute(permutation.as_slice(), &mut h_b_partner);

                            h_b_partner.iter().map(|s| s[0]).collect::<Vec<_>>()
                        };
                        self.ec_cipher.to_bytes(tmp.as_slice())
                    };

                    for (idx, key) in partner_keys.iter().enumerate() {
                        // if not in S_Partner
                        if !set_diffs[p].s_partner.contains(&key.to_string()) {
                            // if not already in the id map
                            if let std::collections::hash_map::Entry::Vacant(e) =
                                unique_partner_ids.entry(key.to_string())
                            {
                                e.insert(vec![(idx, p)]);
                            } else {
                                let v = unique_partner_ids.get_mut(&key.to_string()).unwrap();
                                if v.len() < num_of_matches {
                                    v.push((idx, p));
                                }
                            }
                        }
                    }
                }
                // Add each item of unique_partner_ids into id_map.
                id_map.clear();
                id_map.extend({
                    let x = unique_partner_ids
                        .iter_mut()
                        .map(|(key, v)| {
                            v.resize(num_of_matches, (usize::MAX, usize::MAX));
                            v.iter()
                                .map(|(idx, from_p)| {
                                    if *idx < usize::MAX {
                                        (key.to_string(), *idx, true, *from_p)
                                    } else {
                                        (key.to_string(), 0, false, 0)
                                    }
                                })
                                .collect::<Vec<_>>()
                        })
                        .collect::<Vec<_>>();
                    x.into_iter().flatten().collect::<Vec<_>>()
                });
                // Add all the remaining keys that company has but the partners don't.
                id_map.extend({
                    let x = sc_intersection
                        .clone()
                        .iter()
                        .map(|key| {
                            (0..num_of_matches)
                                .map(|_| (key.to_string(), 0, false, 0))
                                .collect::<Vec<_>>()
                        })
                        .collect::<Vec<_>>();
                    x.into_iter().flatten().collect::<Vec<_>>()
                });

                // Sort the id_map by the spine
                id_map.sort_by(|(a, _, _, _), (b, _, _, _)| a.cmp(b));
            }
            _ => panic!("Cannot make v"),
        }
    }

    fn calculate_features_xor_shares(&self) -> Result<TPayload, ProtocolError> {
        match (
            self.partners_data.clone().read(),
            self.id_map.clone().read(),
            self.company_public_key.clone().read(),
            self.partner_shares.clone().write(),
        ) {
            (Ok(partners_data), Ok(id_map), Ok(company_public_key), Ok(mut shares)) => {
                let mut rng = rand::thread_rng();
                let range = Uniform::new(0_u64, u64::MAX);
                let t = timer::Timer::new_silent("calculate_features_xor_shares");

                // Find maximum number of features across all partners.
                let n_features = partners_data
                    .iter()
                    .map(|p| p.features.len())
                    .max()
                    .unwrap();

                let (t_i, mut g_zi) = {
                    let z_i = (0..id_map.len()).map(|_| gen_scalar()).collect::<Vec<_>>();
                    let x = z_i
                        .iter()
                        .map(|a| {
                            let x = self.ec_cipher.to_bytes(&[a * *company_public_key]);
                            x[0].clone()
                        })
                        .collect::<Vec<_>>();
                    let y = z_i
                        .iter()
                        .map(|a| a * RISTRETTO_BASEPOINT_TABLE)
                        .collect::<Vec<_>>();
                    (x, y)
                };

                let mut d_flat = {
                    let p_mask_v = partners_data
                        .iter()
                        .map(|p_data| self.ec_cipher.to_points(&p_data.g_zi))
                        .collect::<Vec<_>>();

                    let mut v_p = Vec::<TPayload>::new();
                    for f_idx in (0..n_features).rev() {
                        let mask = (0..id_map.len())
                            .map(|_| rng.sample(range))
                            .collect::<Vec<u64>>();
                        let t = id_map
                            .iter()
                            .enumerate()
                            .map(|(i, (_, idx, exists, from_partner))| {
                                let y = if *exists {
                                    if f_idx == 0 {
                                        g_zi[i] = p_mask_v[*from_partner][*idx];
                                    }
                                    let partner_features = &partners_data[*from_partner].features;
                                    if f_idx < partner_features.len() {
                                        partner_features[f_idx][*idx] ^ mask[i]
                                    } else {
                                        // In case the data are not padded correctly,
                                        // return secret shares of the first feature.
                                        partner_features[0][*idx] ^ mask[i]
                                    }
                                } else {
                                    let y = u64::from_le_bytes(
                                        (t_i[i].buffer[0..8]).try_into().unwrap(),
                                    );
                                    y ^ mask[i]
                                };
                                ByteBuffer {
                                    buffer: y.to_le_bytes().to_vec(),
                                }
                            })
                            .collect::<Vec<_>>();

                        v_p.push(t);
                        shares.insert(f_idx, mask);
                    }

                    v_p.into_iter().flatten().collect::<Vec<_>>()
                };

                d_flat.extend(self.ec_cipher.to_bytes(&g_zi));

                let metadata = vec![
                    ByteBuffer {
                        buffer: (id_map.len() as u64).to_le_bytes().to_vec(),
                    },
                    ByteBuffer {
                        buffer: (n_features as u64).to_le_bytes().to_vec(),
                    },
                ];

                d_flat.extend(metadata);
                t.qps("d_flat", d_flat.len());
                Ok(d_flat)
            }
            _ => {
                error!("Cannot read id_map");
                Err(ProtocolError::ErrorEncryption(
                    "unable to read id_map".to_string(),
                ))
            }
        }
    }

    fn print_id_map(&self) {
        match self.id_map.clone().read() {
            Ok(id_map) => {
                // Create fake data since we only have encrypted partner keys
                let m_idx = id_map
                    .iter()
                    .filter(|(_, _, flag, _)| *flag)
                    .map(|(_, idx, _, _)| idx)
                    .max()
                    .unwrap();

                let mut data: Vec<Vec<String>> = vec![vec!["NA".to_string()]; m_idx + 1];

                for i in 0..id_map.len() {
                    let (_, idx, flag, _) = id_map[i];
                    if flag {
                        data[idx] = vec![format!(" Partner enc key at pos {}", idx)];
                    }
                }

                writer_helper_dpmc(&data, &id_map, None);
            }
            _ => panic!("Cannot print id_map"),
        }
    }

    fn save_id_map(&self, path: &str) -> Result<(), ProtocolError> {
        match self.id_map.clone().read() {
            Ok(id_map) => {
                // Create fake data since we only have encrypted partner keys
                let m_idx = id_map
                    .iter()
                    .filter(|(_, _, flag, _)| *flag)
                    .map(|(_, idx, _, _)| idx)
                    .max()
                    .unwrap();

                let mut data: Vec<Vec<String>> = vec![vec!["NA".to_string()]; m_idx + 1];

                for i in 0..id_map.len() {
                    let (_, idx, flag, _) = id_map[i];
                    if flag {
                        data[idx] = vec![format!(" Partner enc key at pos {}", idx)];
                    }
                }

                writer_helper_dpmc(&data, &id_map, Some(path.to_string()));
                Ok(())
            }
            _ => Err(ProtocolError::ErrorIO(
                "Unable to write company view to file".to_string(),
            )),
        }
    }

    fn save_features_shares(&self, path_prefix: &str) -> Result<(), ProtocolError> {
        match self.partner_shares.clone().read() {
            Ok(shares) => {
                assert!(shares.len() > 0);

                let mut out: Vec<Vec<u64>> = Vec::new();

                for key in shares.keys().sorted() {
                    out.push(shares.get(key).unwrap().clone());
                }

                let p_filename = format!("{}{}", path_prefix, "_partner_features.csv");
                info!("revealing partner features to output file");
                common::files::write_u64cols_to_file(&mut out, Path::new(&p_filename)).unwrap();

                Ok(())
            }
            _ => Err(ProtocolError::ErrorIO(
                "Unable to write company shares of partner features to file".to_string(),
            )),
        }
    }
}
