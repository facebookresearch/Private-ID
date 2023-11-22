//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate csv;

use std::collections::HashMap;
use std::convert::TryInto;
use std::path::Path;
use std::sync::Arc;
use std::sync::RwLock;

use common::permutations::gen_permute_pattern;
use common::permutations::permute;
use common::timer;
use crypto::eccipher::gen_scalar;
use crypto::eccipher::ECCipher;
use crypto::eccipher::ECRistrettoParallel;
use crypto::prelude::*;
use itertools::Itertools;
use rand::distributions::Uniform;
use rand::prelude::*;
use rand::Rng;

use super::writer_helper;
use super::ProtocolError;
use crate::dspmc::traits::HelperDspmcProtocol;
use crate::shared::TFeatures;

#[derive(Debug)]
pub struct HelperDspmc {
    keypair_sk: Scalar,
    keypair_pk: TPoint,
    ec_cipher: ECRistrettoParallel,
    company_public_key: Arc<RwLock<(TPoint, TPoint)>>,
    xor_shares_v2: Arc<RwLock<TFeatures>>, // v2 = v xor v1 -- The shuffler has v1
    enc_company: Arc<RwLock<Vec<Vec<TPoint>>>>, // H(C)^c
    enc_partners: Arc<RwLock<Vec<Vec<TPoint>>>>, // H(P)^c
    features: Arc<RwLock<TFeatures>>,      // v''' from shuffler
    p_cd: Arc<RwLock<Vec<usize>>>,
    v_cd: Arc<RwLock<Vec<u64>>>,
    p_sd: Arc<RwLock<Vec<usize>>>,
    v_sd: Arc<RwLock<Vec<u64>>>,
    shuffler_gz: Arc<RwLock<Vec<ByteBuffer>>>, // h = g^z from shuffler
    s_company: Arc<RwLock<Vec<ByteBuffer>>>,
    s_partner: Arc<RwLock<Vec<ByteBuffer>>>,
    id_map: Arc<RwLock<Vec<(String, usize, bool)>>>,
    helper_shares: Arc<RwLock<HashMap<usize, Vec<u64>>>>,
}

impl HelperDspmc {
    pub fn new() -> HelperDspmc {
        let x = gen_scalar();
        HelperDspmc {
            keypair_sk: x,
            keypair_pk: &x * RISTRETTO_BASEPOINT_TABLE,
            ec_cipher: ECRistrettoParallel::default(),
            company_public_key: Arc::new(RwLock::default()),
            xor_shares_v2: Arc::new(RwLock::default()),
            enc_company: Arc::new(RwLock::default()),
            enc_partners: Arc::new(RwLock::default()),
            features: Arc::new(RwLock::default()),
            p_cd: Arc::new(RwLock::default()),
            v_cd: Arc::new(RwLock::default()),
            p_sd: Arc::new(RwLock::default()),
            v_sd: Arc::new(RwLock::default()),
            shuffler_gz: Arc::new(RwLock::default()),
            s_company: Arc::new(RwLock::default()),
            s_partner: Arc::new(RwLock::default()),
            id_map: Arc::new(RwLock::default()),
            helper_shares: Arc::new(RwLock::default()),
        }
    }

    pub fn get_helper_public_key(&self) -> Result<TPayload, ProtocolError> {
        Ok(self.ec_cipher.to_bytes(&[self.keypair_pk]))
    }

    pub fn set_company_public_key(
        &self,
        company_public_key: TPayload,
    ) -> Result<(), ProtocolError> {
        let pk = self.ec_cipher.to_points(&company_public_key);
        // Check that two keys are sent
        assert_eq!(pk.len(), 2);

        match self.company_public_key.clone().write() {
            Ok(mut company_pk) => {
                company_pk.0 = pk[0];
                company_pk.1 = pk[1];
                assert!(!(company_pk.0).is_identity());
                assert!(!(company_pk.1).is_identity());
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
}

impl Default for HelperDspmc {
    fn default() -> Self {
        Self::new()
    }
}

impl HelperDspmcProtocol for HelperDspmc {
    fn set_ct3p_cd_v_cd(
        &self,
        mut data: TPayload,
        num_partners: usize,
        v_cd_bytes: TPayload,
        p_cd_bytes: TPayload,
    ) -> Result<(), ProtocolError> {
        match (
            self.xor_shares_v2.clone().write(),
            self.p_cd.clone().write(),
            self.v_cd.clone().write(),
        ) {
            (Ok(mut xor_shares_v2), Ok(mut p_cd), Ok(mut v_cd)) => {
                let t = timer::Timer::new_silent("set v''");
                for _ in 0..num_partners {
                    // Data in form [(ct3, metadata), (ct3, metadata), ... ]
                    let n_features = u64::from_le_bytes(
                        data.pop().unwrap().buffer.as_slice().try_into().unwrap(),
                    ) as usize;
                    let n_rows = u64::from_le_bytes(
                        data.pop().unwrap().buffer.as_slice().try_into().unwrap(),
                    ) as usize;

                    let ct3 = data.drain((data.len() - 1)..).collect::<Vec<_>>();

                    // PRG seed = scalar * PK_helper
                    let seed = {
                        let x = self.ec_cipher.to_points_encrypt(&ct3, &self.keypair_sk);
                        &self.ec_cipher.to_bytes(&x)[0].buffer
                    };
                    let seed_array: [u8; 32] =
                        seed.as_slice().try_into().expect("incorrect length");
                    let mut rng = StdRng::from_seed(seed_array);

                    // Merge features from all partners together. Example:
                    // features from P1:
                    //   10, 11, 12
                    //   20, 21, 22
                    // --> [[10, 20], [11, 21], [12, 22]]
                    //
                    // features from P2:
                    //   30, 31, 32
                    //   40, 41, 42
                    // --> [[30, 40], [31, 41], [32, 42]]
                    //
                    // Merged: [[10, 20, 30, 40], [11, 21, 31, 41], [12, 22, 32, 42]]
                    for f_idx in 0..n_features {
                        let t = (0..n_rows)
                            .collect::<Vec<_>>()
                            .iter()
                            .map(|_| rng.gen::<u64>())
                            .collect::<Vec<_>>();
                        if xor_shares_v2.len() != n_features {
                            xor_shares_v2.push(t);
                        } else {
                            xor_shares_v2[f_idx].extend(t);
                        }
                    }
                }

                *v_cd = v_cd_bytes
                    .iter()
                    .map(|x| u64::from_le_bytes((x.buffer[0..8]).try_into().unwrap()))
                    .collect::<Vec<_>>();

                *p_cd = p_cd_bytes
                    .iter()
                    .map(|x| u64::from_le_bytes((x.buffer[0..8]).try_into().unwrap()) as usize)
                    .collect::<Vec<_>>();

                t.qps("deserialize_exp", xor_shares_v2.len());

                Ok(())
            }
            _ => {
                error!("Cannot load xor_shares_v2");
                Err(ProtocolError::ErrorDeserialization(
                    "cannot load xor_shares_v2".to_string(),
                ))
            }
        }
    }

    fn set_encrypted_vprime(
        &self,
        blinded_features: TFeatures,
        g_zi: TPayload,
    ) -> Result<(), ProtocolError> {
        match (
            self.features.clone().write(),
            self.shuffler_gz.clone().write(),
        ) {
            (Ok(mut features), Ok(mut shuffler_gz)) => {
                let t = timer::Timer::new_silent("set_encrypted_vprime");

                features.clear();
                features.extend(blinded_features);

                shuffler_gz.clear();
                shuffler_gz.extend(g_zi);

                t.qps("deserialize_exp", shuffler_gz.len());

                Ok(())
            }
            _ => {
                error!("Cannot load encrypted_vprime");
                Err(ProtocolError::ErrorDeserialization(
                    "cannot load encrypted_vprime".to_string(),
                ))
            }
        }
    }

    fn set_p_sd_v_sd(
        &self,
        v_sd_bytes: TPayload,
        p_sd_bytes: TPayload,
    ) -> Result<(), ProtocolError> {
        match (self.p_sd.clone().write(), self.v_sd.clone().write()) {
            (Ok(mut p_sd), Ok(mut v_sd)) => {
                let t = timer::Timer::new_silent("set set_p_sd_v_sd");

                *v_sd = v_sd_bytes
                    .iter()
                    .map(|x| u64::from_le_bytes((x.buffer[0..8]).try_into().unwrap()))
                    .collect::<Vec<_>>();

                *p_sd = p_sd_bytes
                    .iter()
                    .map(|x| u64::from_le_bytes((x.buffer[0..8]).try_into().unwrap()) as usize)
                    .collect::<Vec<_>>();

                t.qps("deserialize_exp", (*p_sd).len());

                Ok(())
            }
            _ => {
                error!("Cannot load set_p_sd_v_sd");
                Err(ProtocolError::ErrorDeserialization(
                    "cannot load set_p_sd_v_sd".to_string(),
                ))
            }
        }
    }

    fn set_u1(&self, mut u1: TFeatures) -> Result<(), ProtocolError> {
        match (
            self.p_sd.clone().read(),
            self.v_sd.clone().read(),
            self.xor_shares_v2.clone().write(),
        ) {
            (Ok(p_sd), Ok(v_sd), Ok(mut xor_shares_v2)) => {
                let t = timer::Timer::new_silent("set set_u1");

                let n_features = u1.len();

                xor_shares_v2.clear();
                for f_idx in 0..n_features {
                    permute(p_sd.as_slice(), &mut u1[f_idx]); // p_sc
                    let t = u1[f_idx]
                        .iter()
                        .zip_eq(v_sd.iter())
                        .map(|(s, t)| *s ^ *t)
                        .collect::<Vec<_>>();
                    xor_shares_v2.push(t);
                }

                t.qps("deserialize_exp", xor_shares_v2.len());
                Ok(())
            }
            _ => {
                error!("Cannot load set_u1");
                Err(ProtocolError::ErrorDeserialization(
                    "cannot load set_u1".to_string(),
                ))
            }
        }
    }

    // Gets H(C)^c and ct1, ct2.
    // Stores H(C)^c as enc_company
    // Computes H(P)^c = ct2 / ct1^d
    // Stores H(P)^c as enc_partners
    fn set_encrypted_keys(
        &self,
        enc_keys: TPayload,
        psum: Vec<usize>,
        ct1_flat: TPayload,
        ct2_flat: TPayload,
        ct_psum: Vec<usize>,
    ) -> Result<(), ProtocolError> {
        match (
            self.enc_company.clone().write(),
            self.enc_partners.clone().write(),
        ) {
            (Ok(mut enc_company), Ok(mut enc_partners)) => {
                let t = timer::Timer::new_silent("set set_encrypted_keys");

                // Unflatten and convert to points
                let num_ct_keys = ct_psum.len() - 1;
                *enc_partners = {
                    let t1 = self.ec_cipher.to_points(&ct1_flat);
                    let t2 = self.ec_cipher.to_points(&ct2_flat);

                    let ct1_d = t1
                        .iter()
                        .map(|x| *x * (&self.keypair_sk))
                        .collect::<Vec<_>>();

                    let y = t2
                        .iter()
                        .zip_eq(ct1_d.iter())
                        .map(|(s2, s1)| *s2 - *s1)
                        .collect::<Vec<_>>();

                    ct_psum
                        .get(0..num_ct_keys)
                        .unwrap()
                        .iter()
                        .zip_eq(ct_psum.get(1..num_ct_keys + 1).unwrap().iter())
                        .map(|(&x1, &x2)| y.get(x1..x2).unwrap().to_vec())
                        .collect::<Vec<Vec<_>>>()
                };

                // Unflatten and convert to points
                let num_company_keys = psum.len() - 1;
                *enc_company = {
                    let t = self.ec_cipher.to_points(&enc_keys);

                    psum.get(0..num_company_keys)
                        .unwrap()
                        .iter()
                        .zip_eq(psum.get(1..num_company_keys + 1).unwrap().iter())
                        .map(|(&x1, &x2)| t.get(x1..x2).unwrap().to_vec())
                        .collect::<Vec<Vec<_>>>()
                };

                t.qps("deserialize_exp", (*enc_company).len());
                Ok(())
            }
            _ => {
                error!("Cannot load set_encrypted_keys");
                Err(ProtocolError::ErrorDeserialization(
                    "cannot load set_encrypted_keys".to_string(),
                ))
            }
        }
    }

    // s_partner has all the data that are in Partner but did not get matched
    // s_company has all the data that are in Company but did not get matched
    //
    // 1. For each item of the partners ID-MAP:
    //    * If it is already in the ID-MAP continue.
    //    * If it is a company key OR if it is not in s_partner (which means
    //      that this item is in the intersection), save it to ID-MAP and set
    //      "partner index" to the correct index and "found" to true.
    // 2. For all the keys from s_company add them to ID-MAP and se "found" to
    //    false.
    fn calculate_id_map(&self) {
        match (
            self.enc_partners.clone().read(),
            self.enc_company.clone().read(),
            self.s_partner.clone().read(),
            self.s_company.clone().read(),
            self.id_map.clone().write(),
        ) {
            (Ok(enc_partners), Ok(enc_company), Ok(s_partner), Ok(s_company), Ok(mut id_map)) => {
                // Get the first column.
                let partner_keys = {
                    let tmp = enc_partners.iter().map(|s| s[0]).collect::<Vec<_>>();
                    self.ec_cipher.to_bytes(tmp.as_slice())
                };

                // Get the first column.
                let company_keys = {
                    let tmp = enc_company.iter().map(|s| s[0]).collect::<Vec<_>>();
                    self.ec_cipher.to_bytes(tmp.as_slice())
                };

                // Put all the company keys into a map to access them quickly.
                let mut company_keys_map = HashMap::new();
                for key in company_keys.iter() {
                    company_keys_map.insert(key.to_string(), false);
                }

                // Put all the items of s_partner into a map to access them quickly.
                let mut s_partner_map = HashMap::new();
                for key in s_partner.iter() {
                    s_partner_map.insert(key.to_string(), true);
                }

                // Add the index of each item of partner_keys into company_keys_map
                // if it's already there (i.e., if it's in the intersection).
                let mut id_hashmap = HashMap::new();
                for (idx, key) in partner_keys.iter().enumerate() {
                    if id_hashmap.contains_key(&key.to_string()) {
                        continue;
                    }
                    if company_keys_map.contains_key(&key.to_string())
                        || !s_partner_map.contains_key(&key.to_string())
                    {
                        id_hashmap.insert(key.to_string(), (idx, true));
                    }
                }

                // Add all the remaining keys that company has but the partner doesn't.
                for (idx, key) in s_company.iter().enumerate() {
                    id_hashmap.insert(key.to_string(), (idx, false));
                }

                id_map.clear();
                *id_map = id_hashmap
                    .into_iter()
                    .map(|(key, (idx, score))| (key, idx, score))
                    .collect::<Vec<(String, usize, bool)>>();

                // Sort the id_map by the spine
                id_map.sort_by(|(a, _, _), (b, _, _)| a.cmp(b));
            }
            _ => panic!("Cannot create id-map"),
        }
    }

    fn calculate_set_diff(&self) -> Result<(), ProtocolError> {
        match (
            self.enc_company.clone().read(),
            self.enc_partners.clone().write(),
            self.s_company.clone().write(),
            self.s_partner.clone().write(),
        ) {
            (Ok(e_company), Ok(mut e_partner), Ok(mut s_company), Ok(mut s_partner)) => {
                // let t = timer::Timer::new_silent("helper calculate_set_diff");

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
                        .iter_mut()
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
                            // if the match occurred not in the first column,
                            // make sure the spine keys will be the same.
                            if idx > 0 {
                                e[0] = e_company[m_idx][0];
                            }
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
                        s_partner.extend(self.ec_cipher.to_bytes(inp.as_slice()));
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
                    s_company.extend(self.ec_cipher.to_bytes(t.as_slice()));
                }
                // t.qps("s_company", s_company.len());

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

    // Compute u2 = p_cd(v_2) xor v_cd
    fn get_u2(&self) -> Result<TPayload, ProtocolError> {
        match (
            self.xor_shares_v2.clone().write(),
            self.p_cd.clone().read(),
            self.v_cd.clone().read(),
        ) {
            (Ok(mut xor_shares_v2), Ok(p_cd), Ok(v_cd)) => {
                let t = timer::Timer::new_silent("helper get_u2");

                let n_rows = xor_shares_v2[0].len();
                let n_features = xor_shares_v2.len();
                let mut u2 = Vec::<TPayload>::new();
                // for f_idx in (0..n_features).rev() {
                for f_idx in 0..n_features {
                    permute(p_cd.as_slice(), &mut xor_shares_v2[f_idx]);
                    let t = xor_shares_v2[f_idx]
                        .iter()
                        .zip_eq(v_cd.iter())
                        .map(|(s, t)| {
                            let y = *s ^ *t;
                            ByteBuffer {
                                buffer: y.to_le_bytes().to_vec(),
                            }
                        })
                        .collect::<Vec<_>>();
                    u2.push(t);
                }

                let mut d_flat = u2.into_iter().flatten().collect::<Vec<_>>();
                let metadata = vec![
                    ByteBuffer {
                        buffer: (n_rows as u64).to_le_bytes().to_vec(),
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
                error!("Cannot read get_u2");
                Err(ProtocolError::ErrorEncryption(
                    "unable to read get_u2".to_string(),
                ))
            }
        }
    }

    fn calculate_features_xor_shares(&self) -> Result<TPayload, ProtocolError> {
        match (
            self.features.clone().read(),
            self.xor_shares_v2.clone().read(),
            self.shuffler_gz.clone().read(),
            self.id_map.clone().read(),
            self.company_public_key.clone().read(),
            self.helper_shares.clone().write(),
        ) {
            (
                Ok(partner_features),
                Ok(xor_shares_v2),
                Ok(shuffler_gz),
                Ok(id_map),
                Ok(company_pk),
                Ok(mut shares),
            ) => {
                let t = timer::Timer::new_silent("helper calculate_features_xor_shares");
                let mut rng = rand::thread_rng();
                let range = Uniform::new(0_u64, u64::MAX);

                let n_features = partner_features.len();

                let (t_i, mut g_zi) = {
                    let z_i = (0..id_map.len()).map(|_| gen_scalar()).collect::<Vec<_>>();
                    let x = z_i
                        .iter()
                        .map(|a| {
                            let x = self.ec_cipher.to_bytes(&[a * company_pk.0]);
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
                    let mut v_p = Vec::<TPayload>::new();

                    let shuffler_gz_points = self.ec_cipher.to_points(&shuffler_gz);

                    for f_idx in (0..n_features).rev() {
                        let mask = (0..id_map.len())
                            .map(|_| rng.sample(range))
                            .collect::<Vec<u64>>();
                        let t = id_map
                            .iter()
                            .enumerate()
                            .map(|(i, (_, idx, exists))| {
                                let y = if *exists {
                                    if f_idx == 0 {
                                        // If exists, overwrite g_z' with g_z from shuffler.
                                        g_zi[i] = shuffler_gz_points[*idx];
                                    }
                                    // v'' xor v''' xor mask = v'' xor v' xor r xor mask =
                                    // v xor r xor mask
                                    xor_shares_v2[f_idx][*idx]
                                        ^ partner_features[f_idx][*idx]
                                        ^ mask[i]
                                } else {
                                    // If it doesn't exist, r xor mask
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
                    .filter(|(_, _, flag)| *flag)
                    .map(|(_, idx, _)| idx)
                    .max()
                    .unwrap();

                let mut data: Vec<Vec<String>> = vec![vec!["NA".to_string()]; m_idx + 1];

                for i in 0..id_map.len() {
                    let (_, idx, flag) = id_map[i];
                    if flag {
                        data[idx] = vec![format!(" Partner enc key at pos {}", idx)];
                    }
                }

                writer_helper(&data, &id_map, None);
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
                    .filter(|(_, _, flag)| *flag)
                    .map(|(_, idx, _)| idx)
                    .max()
                    .unwrap();

                let mut data: Vec<Vec<String>> = vec![vec!["NA".to_string()]; m_idx + 1];

                for i in 0..id_map.len() {
                    let (_, idx, flag) = id_map[i];
                    if flag {
                        data[idx] = vec![format!(" Partner enc key at pos {}", idx)];
                    }
                }

                writer_helper(&data, &id_map, Some(path.to_string()));
                Ok(())
            }
            _ => Err(ProtocolError::ErrorIO(
                "Unable to write company view to file".to_string(),
            )),
        }
    }

    fn save_features_shares(&self, path_prefix: &str) -> Result<(), ProtocolError> {
        match self.helper_shares.clone().read() {
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
