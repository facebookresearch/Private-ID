//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate csv;

use std::collections::HashMap;
use std::collections::VecDeque;
use std::convert::TryInto;
use std::path::Path;
use std::sync::Arc;
use std::sync::RwLock;

use common::permutations::gen_permute_pattern;
use common::permutations::permute;
use common::permutations::undo_permute;
use common::timer;
use crypto::eccipher::gen_scalar;
use crypto::eccipher::ECCipher;
use crypto::eccipher::ECRistrettoParallel;
use crypto::prelude::*;
use itertools::Itertools;
use rand::distributions::Uniform;
use rand::Rng;

use super::load_data_keys;
use super::serialize_helper;
use super::writer_helper;
use super::ProtocolError;
use crate::dspmc::traits::CompanyDspmcProtocol;
use crate::shared::TFeatures;

#[derive(Debug)]
struct PartnerData {
    scalar_g: Vec<u8>,
    n_rows: usize,
    n_features: usize,
}

#[derive(Debug)]
pub struct CompanyDspmc {
    keypair_sk: (Scalar, Scalar),
    keypair_pk: (TPoint, TPoint),
    helper_public_key: Arc<RwLock<TPoint>>,
    ec_cipher: ECRistrettoParallel,
    ct1: Arc<RwLock<Vec<Vec<TPoint>>>>, // initially holds ct1 and later ct1''
    ct2: Arc<RwLock<Vec<Vec<TPoint>>>>, // initially holds ct2 and later ct2''
    v1: Arc<RwLock<TFeatures>>,
    u1: Arc<RwLock<Vec<TPayload>>>,
    plaintext: Arc<RwLock<Vec<Vec<String>>>>,
    permutation: Arc<RwLock<Vec<usize>>>,
    perms: Arc<RwLock<(Vec<usize>, Vec<usize>)>>, // (p_3, p_4)
    blinds: Arc<RwLock<(Vec<u64>, Vec<u64>)>>,    // (v_cd, v_cs)
    enc_company: Arc<RwLock<Vec<Vec<TPoint>>>>,
    partners_queue: Arc<RwLock<VecDeque<PartnerData>>>,
    id_map: Arc<RwLock<Vec<(String, usize, bool)>>>,
    partner_shares: Arc<RwLock<HashMap<usize, Vec<u64>>>>,
}

impl CompanyDspmc {
    pub fn new() -> CompanyDspmc {
        let x1 = gen_scalar();
        let x2 = gen_scalar();
        CompanyDspmc {
            keypair_sk: (x1, x2),
            keypair_pk: (
                &x1 * RISTRETTO_BASEPOINT_TABLE,
                &x2 * RISTRETTO_BASEPOINT_TABLE,
            ),
            helper_public_key: Arc::new(RwLock::default()),
            ec_cipher: ECRistrettoParallel::default(),
            ct1: Arc::new(RwLock::default()),
            ct2: Arc::new(RwLock::default()),
            v1: Arc::new(RwLock::default()),
            u1: Arc::new(RwLock::default()),
            plaintext: Arc::new(RwLock::default()),
            permutation: Arc::new(RwLock::default()),
            perms: Arc::new(RwLock::default()),
            blinds: Arc::new(RwLock::default()),
            enc_company: Arc::new(RwLock::default()),
            partners_queue: Arc::new(RwLock::default()),
            id_map: Arc::new(RwLock::default()),
            partner_shares: Arc::new(RwLock::default()),
        }
    }

    pub fn get_company_public_key(&self) -> Result<TPayload, ProtocolError> {
        Ok(self
            .ec_cipher
            .to_bytes(&vec![self.keypair_pk.0, self.keypair_pk.1]))
    }

    pub fn load_data(&self, path: &str, input_with_headers: bool) {
        load_data_keys(self.plaintext.clone(), path, input_with_headers);
    }

    pub fn gen_permutations(&self) {
        match (
            self.perms.clone().write(),
            self.blinds.clone().write(),
            self.ct1.clone().read(),
        ) {
            (Ok(mut perms), Ok(mut blinds), Ok(ct1_data)) => {
                let mut rng = rand::thread_rng();
                let range = Uniform::new(0_u64, u64::MAX);

                let data_len = ct1_data.len();
                assert!(data_len > 0);
                perms.0.clear();
                perms.1.clear();
                perms.0.extend(gen_permute_pattern(data_len));
                perms.1.extend(gen_permute_pattern(data_len));

                blinds.0 = (0..data_len)
                    .map(|_| rng.sample(range))
                    .collect::<Vec<u64>>();
                blinds.1 = (0..data_len)
                    .map(|_| rng.sample(range))
                    .collect::<Vec<u64>>();
            }
            _ => {}
        }
    }

    pub fn set_helper_public_key(&self, helper_public_key: TPayload) -> Result<(), ProtocolError> {
        let pk = self.ec_cipher.to_points(&helper_public_key);
        // Check that one key is sent
        assert_eq!(pk.len(), 1);
        match self.helper_public_key.clone().write() {
            Ok(mut helper_pk) => {
                *helper_pk = pk[0];
                Ok(())
            }
            _ => {
                error!("Unable to set helper public key");
                Err(ProtocolError::ErrorEncryption(
                    "unable to set helper public key".to_string(),
                ))
            }
        }
    }
}

impl Default for CompanyDspmc {
    fn default() -> Self {
        Self::new()
    }
}

impl CompanyDspmcProtocol for CompanyDspmc {
    fn set_encrypted_partner_keys_and_shares(
        &self,
        ct1: TPayload,
        ct2: TPayload,
        psum: Vec<usize>,
        ct3: Vec<u8>,
        xor_features: TFeatures,
    ) -> Result<(), ProtocolError> {
        match (
            self.partners_queue.clone().write(),
            self.ct1.clone().write(),
            self.ct2.clone().write(),
            self.v1.clone().write(),
        ) {
            (Ok(mut partners_queue), Ok(mut all_ct1), Ok(mut all_ct2), Ok(mut all_v1)) => {
                let t = timer::Timer::new_silent("load_ct2");
                // This is an array of exclusive-inclusive prefix sum - hence
                // number of keys is one less than length
                let num_keys = psum.len() - 1;

                // Unflatten
                let ct1_points = {
                    let t = self.ec_cipher.to_points(&ct1);

                    psum.get(0..num_keys)
                        .unwrap()
                        .iter()
                        .zip_eq(psum.get(1..num_keys + 1).unwrap().iter())
                        .map(|(&x1, &x2)| t.get(x1..x2).unwrap().to_vec())
                        .collect::<Vec<Vec<_>>>()
                };
                let ct2_points = {
                    let t = self.ec_cipher.to_points(&ct2);

                    psum.get(0..num_keys)
                        .unwrap()
                        .iter()
                        .zip_eq(psum.get(1..num_keys + 1).unwrap().iter())
                        .map(|(&x1, &x2)| t.get(x1..x2).unwrap().to_vec())
                        .collect::<Vec<Vec<_>>>()
                };
                assert_eq!(ct1_points.len(), ct2_points.len());
                let data_size = ct1_points.len();
                t.qps("deserialize_exp", data_size);

                all_ct1.extend(ct1_points);
                all_ct2.extend(ct2_points);

                let n_rows = xor_features[0].len();
                let n_features = xor_features.len();
                assert_eq!(n_rows, data_size);

                for f_idx in 0..n_features {
                    if all_v1.len() != n_features {
                        all_v1.push(xor_features[f_idx].clone());
                    } else {
                        all_v1[f_idx].extend(xor_features[f_idx].clone());
                    }
                }

                partners_queue.push_back(PartnerData {
                    scalar_g: ct3,
                    n_rows,
                    n_features,
                });
                Ok(())
            }
            _ => {
                error!("Cannot load ct2");
                Err(ProtocolError::ErrorDeserialization(
                    "cannot load ct2".to_string(),
                ))
            }
        }
    }

    // Get dataset C with company keys and encrypt them to H(C)^c
    //  With Elliptic curves: H(C)*c
    fn get_company_keys(&self) -> Result<TPayload, ProtocolError> {
        match (
            self.plaintext.clone().read(),
            self.enc_company.clone().write(),
        ) {
            (Ok(pdata), Ok(mut enc_company)) => {
                let t = timer::Timer::new_silent("x_company");

                // Flatten
                let (mut d_flat, mut offset, metadata) = {
                    let (d_flat, offset, metadata) = serialize_helper(pdata.to_vec());

                    // Hash Encrypt - H(C)^c
                    let enc = self
                        .ec_cipher
                        .hash_encrypt(d_flat.as_slice(), &self.keypair_sk.0);

                    (enc, offset, metadata)
                };

                // Unflatten and set encrypted keys
                {
                    let psum = offset
                        .iter()
                        .map(|b| {
                            u64::from_le_bytes(b.buffer.as_slice().try_into().unwrap()) as usize
                        })
                        .collect::<Vec<_>>();

                    let num_keys = psum.len() - 1;
                    let mut x = psum
                        .get(0..num_keys)
                        .unwrap()
                        .iter()
                        .zip_eq(psum.get(1..num_keys + 1).unwrap().iter())
                        .map(|(&x1, &x2)| d_flat.get(x1..x2).unwrap().to_vec())
                        .collect::<Vec<Vec<_>>>();

                    enc_company.clear();
                    enc_company.extend(x.drain(..));
                }

                t.qps("encryption H(C)^c", d_flat.len());

                // Serialize
                let buf = {
                    let mut x = self.ec_cipher.to_bytes(d_flat.as_slice());

                    d_flat.clear();
                    d_flat.shrink_to_fit();

                    offset.extend(metadata);
                    // Append offsets array
                    x.extend(offset);
                    x
                };

                Ok(buf)
            }
            _ => {
                error!("Unable to encrypt H(C)^c:");
                Err(ProtocolError::ErrorEncryption(
                    "cannot encrypt H(C)^c".to_string(),
                ))
            }
        }
    }

    // Get dataset ct1 and ct2'
    fn get_ct1_ct2(&self) -> Result<TPayload, ProtocolError> {
        match (self.ct1.clone().read(), self.ct2.clone().read()) {
            (Ok(ct1), Ok(ct2)) => {
                let t = timer::Timer::new_silent("x_company");

                // Re-randomize ct1'' and ct2'' and flatten
                let (mut ct1_dprime_flat, ct2_dprime_flat, ct_offset) = {
                    // flatten
                    let (ct1_dprime_flat, _ct1_offset) = {
                        let (d_flat, mut offset, metadata) = serialize_helper(ct1.clone());
                        offset.extend(metadata);

                        (self.ec_cipher.to_bytes(d_flat.as_slice()), offset)
                    };

                    let (ctd2_dprime_flat, ct2_offset) = {
                        let (d_flat, mut offset, metadata) = serialize_helper(ct2.clone());
                        offset.extend(metadata);

                        let d_flat_c = d_flat
                            .iter()
                            .map(|x| *x * (self.keypair_sk.0))
                            .collect::<Vec<_>>();

                        (self.ec_cipher.to_bytes(d_flat_c.as_slice()), offset)
                    };
                    (ct1_dprime_flat, ctd2_dprime_flat, ct2_offset)
                };

                ct1_dprime_flat.extend(ct2_dprime_flat);
                ct1_dprime_flat.extend(ct_offset);

                t.qps("encryption H(C)^c", ct1_dprime_flat.len());

                // ct1_dprime_flat, ct2_dprime_flat, ct_offset
                Ok(ct1_dprime_flat)
            }
            _ => {
                error!("Unable to encrypt H(C)^c:");
                Err(ProtocolError::ErrorEncryption(
                    "cannot encrypt H(C)^c".to_string(),
                ))
            }
        }
    }

    // Send <ct3>, v_cd, p_cd to D
    fn get_all_ct3_p_cd_v_cd(&self) -> Result<TPayload, ProtocolError> {
        match (
            self.partners_queue.clone().write(),
            self.perms.clone().read(),
            self.blinds.clone().read(),
        ) {
            (Ok(mut partners_data_q), Ok(perms), Ok(blinds)) => {
                let mut res = vec![];
                let num_partners = partners_data_q.len();
                for _ in 0..num_partners {
                    let partner_data: PartnerData = partners_data_q.pop_back().unwrap();
                    let ct3 = partner_data.scalar_g;
                    let n_rows = partner_data.n_rows;
                    let n_features = partner_data.n_features;

                    res.push(ByteBuffer { buffer: ct3 });
                    let metadata = vec![
                        ByteBuffer {
                            buffer: (n_rows as u64).to_le_bytes().to_vec(),
                        },
                        ByteBuffer {
                            buffer: (n_features as u64).to_le_bytes().to_vec(),
                        },
                    ];
                    res.extend(metadata);
                }
                res.push(ByteBuffer {
                    buffer: (num_partners as u64).to_le_bytes().to_vec(),
                });

                let p_cd_bytes = perms
                    .0
                    .iter()
                    .map(|e| ByteBuffer {
                        buffer: (*e).to_le_bytes().to_vec(),
                    })
                    .collect::<Vec<ByteBuffer>>();
                let v_cd_bytes = blinds
                    .0
                    .iter()
                    .map(|e| ByteBuffer {
                        buffer: (*e).to_le_bytes().to_vec(),
                    })
                    .collect::<Vec<ByteBuffer>>();
                let data_len = p_cd_bytes.len();
                res.extend(p_cd_bytes);
                res.extend(v_cd_bytes);
                res.push(ByteBuffer {
                    buffer: (data_len as u64).to_le_bytes().to_vec(),
                });

                Ok(res)
            }
            _ => {
                error!("Unable to flatten ct3:");
                Err(ProtocolError::ErrorEncryption(
                    "cannot flatten ct3".to_string(),
                ))
            }
        }
    }

    fn get_p_cs_v_cs(&self) -> Result<TPayload, ProtocolError> {
        match (
            self.perms.clone().read(),
            self.blinds.clone().read(),
            self.ct1.clone().write(),
            self.ct2.clone().write(),
            self.helper_public_key.clone().read(),
        ) {
            (Ok(perms), Ok(blinds), Ok(mut ct1), Ok(mut ct2), Ok(helper_pk)) => {
                let mut res = vec![];

                let p_cs_bytes = perms
                    .1
                    .iter()
                    .map(|e| ByteBuffer {
                        buffer: (*e as u64).to_le_bytes().to_vec(),
                    })
                    .collect::<Vec<ByteBuffer>>();
                let v_cs_bytes = blinds
                    .1
                    .iter()
                    .map(|e| ByteBuffer {
                        buffer: (*e as u64).to_le_bytes().to_vec(),
                    })
                    .collect::<Vec<ByteBuffer>>();
                let data_len = ct1.len();
                res.extend(p_cs_bytes);
                res.extend(v_cs_bytes);

                // Re-randomize ct1 and ct2 to ct1' and ct2'
                let (ct1_prime_flat, ct2_prime_flat, ct_offset) = {
                    let r_i = (0..data_len)
                        .collect::<Vec<_>>()
                        .iter()
                        .map(|_| gen_scalar())
                        .collect::<Vec<_>>();
                    // company_pk^r
                    // with EC: company_pk * r
                    let pkc_r = r_i
                        .iter()
                        .map(|x| *x * (self.keypair_pk.0))
                        .collect::<Vec<_>>();
                    // helper_pk^r
                    // with EC: helper_pk * r
                    let pkd_r = r_i.iter().map(|x| *x * (*helper_pk)).collect::<Vec<_>>();

                    permute(perms.0.as_slice(), &mut ct1); // p_cd
                    permute(perms.0.as_slice(), &mut ct2); // p_cd
                    permute(perms.1.as_slice(), &mut ct1); // p_cs
                    permute(perms.1.as_slice(), &mut ct2); // p_cs

                    // ct1' = p_4(p_3(ct1)) * company_pk^r
                    // with EC: ct1' = p_4(p_3(ct1)) + company_pk*r
                    let ct1_prime = ct1
                        .iter()
                        .zip_eq(pkc_r.iter())
                        .map(|(s, t)| (*s).iter().map(|si| *si + *t).collect::<Vec<_>>())
                        .collect::<Vec<_>>();
                    // ct2' = p_4(p_3(ct2)) * helper_pk^r
                    // with EC: ct2' = p_4(p_3(ct2)) + helper_pk*r
                    let ct2_prime = ct2
                        .iter()
                        .zip_eq(pkd_r.iter())
                        .map(|(s, t)| (*s).iter().map(|si| *si + *t).collect::<Vec<_>>())
                        .collect::<Vec<_>>();

                    let (ct1_prime_flat, _ct1_offset) = {
                        let (d_flat, mut offset, metadata) = serialize_helper(ct1_prime.clone());
                        offset.extend(metadata);

                        (self.ec_cipher.to_bytes(d_flat.as_slice()), offset)
                    };
                    let (ct2_prime_flat, ct2_offset) = {
                        let (d_flat, mut offset, metadata) = serialize_helper(ct2_prime.clone());
                        offset.extend(metadata);

                        (self.ec_cipher.to_bytes(d_flat.as_slice()), offset)
                    };
                    (ct1_prime_flat, ct2_prime_flat, ct2_offset)
                };

                assert_eq!(ct1_prime_flat.len(), ct2_prime_flat.len());

                res.extend(ct1_prime_flat);
                res.extend(ct2_prime_flat);
                res.extend(ct_offset);

                // p_cs, v_cs, ct1_prime_flat, ct2_prime_flat, ct_offset
                Ok(res)
            }
            _ => {
                error!("Unable to flatten ct3:");
                Err(ProtocolError::ErrorEncryption(
                    "cannot flatten ct3".to_string(),
                ))
            }
        }
    }

    fn set_p_sc_v_sc_ct1ct2dprime(
        &self,
        v_sc_bytes: TPayload,
        p_sc_bytes: TPayload,
        ct1_dprime_flat: TPayload,
        ct2_dprime_flat: TPayload,
        psum: Vec<usize>,
    ) -> Result<(), ProtocolError> {
        match (
            self.ct1.clone().write(),
            self.ct2.clone().write(),
            self.perms.clone().read(),
            self.blinds.clone().read(),
            self.v1.clone().write(),
            self.u1.clone().write(),
        ) {
            (Ok(mut ct1), Ok(mut ct2), Ok(perms), Ok(blinds), Ok(mut v1), Ok(mut u1)) => {
                let t = timer::Timer::new_silent("set set_p_sc_v_sc_ct1ct2dprime");
                let num_keys = v_sc_bytes.len();
                // Remove the previous data and replace them with the (doubly) re-randomized
                ct1.clear();
                ct2.clear();
                // Unflatten and convert to points
                *ct1 = {
                    // ct1'' (doubly re-randomized ct1)
                    let t = self.ec_cipher.to_points(&ct1_dprime_flat);

                    psum.get(0..num_keys)
                        .unwrap()
                        .iter()
                        .zip_eq(psum.get(1..num_keys + 1).unwrap().iter())
                        .map(|(&x1, &x2)| t.get(x1..x2).unwrap().to_vec())
                        .collect::<Vec<Vec<_>>>()
                };
                // Unflatten and convert to points
                *ct2 = {
                    // ct2'' (doubly re-randomized ct2)
                    let t = self.ec_cipher.to_points(&ct2_dprime_flat);

                    psum.get(0..num_keys)
                        .unwrap()
                        .iter()
                        .zip_eq(psum.get(1..num_keys + 1).unwrap().iter())
                        .map(|(&x1, &x2)| t.get(x1..x2).unwrap().to_vec())
                        .collect::<Vec<Vec<_>>>()
                };

                let p_sc = p_sc_bytes
                    .iter()
                    .map(|x| u64::from_le_bytes((x.buffer[0..8]).try_into().unwrap()) as usize)
                    .collect::<Vec<_>>();
                let v_sc = v_sc_bytes
                    .iter()
                    .map(|x| u64::from_le_bytes((x.buffer[0..8]).try_into().unwrap()))
                    .collect::<Vec<_>>();

                let n_features = v1.len();
                // Compute u1 = p_sc( p_cs( p_cd(v_1) xor v_cd) xor v_cs) xor v_sc
                (*u1).clear();
                for f_idx in (0..n_features).rev() {
                    permute(perms.0.as_slice(), &mut v1[f_idx]); // p_cd
                    let mut u2 = v1[f_idx]
                        .iter()
                        .zip_eq(blinds.0.iter()) // v_cd
                        .map(|(s, v_cd)| *s ^ *v_cd)
                        .collect::<Vec<_>>();

                    permute(perms.1.as_slice(), &mut u2); // p_cs
                    let mut t1 = u2
                        .iter()
                        .zip_eq(blinds.1.iter()) // v_cs
                        .map(|(s, v_cs)| *s ^ *v_cs)
                        .collect::<Vec<_>>();

                    permute(p_sc.as_slice(), &mut t1); // p_sc
                    (*u1).push(
                        t1.iter()
                            .zip_eq(v_sc.iter())
                            .map(|(s, v_sc)| {
                                // v_sc
                                let y = *s ^ *v_sc;
                                ByteBuffer {
                                    buffer: y.to_le_bytes().to_vec(),
                                }
                            })
                            .collect::<Vec<_>>(),
                    );
                }

                t.qps("ct1'' and ct2''", ct1.len());
                Ok(())
            }
            _ => {
                error!("Cannot flatten ct1'' and ct2''");
                Err(ProtocolError::ErrorDeserialization(
                    "cannot flatten ct1'' and ct2''".to_string(),
                ))
            }
        }
    }

    // Send u1 to D
    fn get_u1(&self) -> Result<TPayload, ProtocolError> {
        match self.u1.clone().read() {
            Ok(u1) => {
                let t = timer::Timer::new_silent("company get_u1");
                t.qps("u1", u1.len());

                let mut d_flat = (*u1).clone().into_iter().flatten().collect::<Vec<_>>();
                let n_rows = u1[0].len();
                let n_features = u1.len();
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
                error!("Unable to flatten u1:");
                Err(ProtocolError::ErrorEncryption(
                    "cannot flatten u1".to_string(),
                ))
            }
        }
    }

    fn calculate_features_xor_shares(
        &self,
        partner_features: TFeatures,
        g_zi: TPayload,
    ) -> Result<(), ProtocolError> {
        match self.partner_shares.clone().write() {
            Ok(mut shares) => {
                let n_features = partner_features.len();

                let g_zi_pt = self.ec_cipher.to_points(&g_zi);
                let r = g_zi_pt
                    .iter()
                    .map(|x| {
                        let t = self.ec_cipher.to_bytes(&[x * self.keypair_sk.0]);
                        u64::from_le_bytes((t[0].buffer[0..8]).try_into().unwrap())
                    })
                    .collect::<Vec<_>>();

                for f_idx in 0..n_features {
                    let s = partner_features[f_idx]
                        .iter()
                        .zip_eq(r.iter())
                        .map(|(x1, x2)| *x1 ^ *x2)
                        .collect::<Vec<_>>();
                    shares.insert(f_idx, s);
                }

                Ok(())
            }
            _ => {
                error!("Unable to calculate XOR shares");
                Err(ProtocolError::ErrorEncryption(
                    "unable to calculate XOR shares".to_string(),
                ))
            }
        }
    }

    fn write_company_to_id_map(&self) -> Result<(), ProtocolError> {
        match (
            self.enc_company.clone().read(),
            self.permutation.clone().read(),
            self.id_map.clone().write(),
        ) {
            (Ok(pdata), Ok(permutation), Ok(mut id_map)) => {
                let mut company_ragged = pdata.clone();
                undo_permute(permutation.as_slice(), &mut company_ragged);

                // Get the first column.
                let company_keys = {
                    let tmp = company_ragged.iter().map(|s| s[0]).collect::<Vec<_>>();
                    self.ec_cipher.to_bytes(tmp.as_slice())
                };

                id_map.clear();
                for (idx, k) in company_keys.iter().enumerate() {
                    id_map.push((k.to_string(), idx, true));
                }

                // Sort the id_map by the spine
                id_map.sort_by(|(a, _, _), (b, _, _)| a.cmp(b));

                Ok(())
            }
            _ => {
                error!("Cannot create id_map");
                Err(ProtocolError::ErrorDeserialization(
                    "cannot create id_map".to_string(),
                ))
            }
        }
    }

    fn print_id_map(&self) {
        match (self.plaintext.clone().read(), self.id_map.clone().read()) {
            (Ok(data), Ok(id_map)) => {
                writer_helper(&data, &id_map, None);
            }
            _ => panic!("Cannot print id_map"),
        }
    }

    fn save_id_map(&self, path: &str) -> Result<(), ProtocolError> {
        match (self.plaintext.clone().read(), self.id_map.clone().read()) {
            (Ok(data), Ok(id_map)) => {
                writer_helper(&data, &id_map, Some(path.to_string()));
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
