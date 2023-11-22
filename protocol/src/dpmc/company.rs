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

use super::load_data_keys;
use super::serialize_helper;
use super::writer_helper;
use super::ProtocolError;
use crate::dpmc::traits::CompanyDpmcProtocol;
use crate::shared::TFeatures;

#[derive(Debug)]
struct PartnerData {
    enc_alpha_t: Vec<u8>,
    scalar_g: Vec<u8>,
    partner_enc_shares: Vec<ByteBuffer>,
    e_partner: Vec<Vec<TPoint>>,
}

#[derive(Debug)]
pub struct CompanyDpmc {
    keypair_sk: Scalar,
    keypair_pk: TPoint,
    private_beta: Scalar,
    ec_cipher: ECRistrettoParallel,
    // TODO: consider using dyn pid::crypto::ECCipher trait?
    plaintext: Arc<RwLock<Vec<Vec<String>>>>,
    permutation: Arc<RwLock<Vec<usize>>>,
    h_k_beta_company: Arc<RwLock<Vec<Vec<TPoint>>>>,
    partners_queue: Arc<RwLock<VecDeque<PartnerData>>>,
    id_map: Arc<RwLock<Vec<(String, usize, bool)>>>,
    partner_shares: Arc<RwLock<HashMap<usize, Vec<u64>>>>,
}

impl CompanyDpmc {
    pub fn new() -> CompanyDpmc {
        let x = gen_scalar();
        CompanyDpmc {
            keypair_sk: x,
            keypair_pk: &x * RISTRETTO_BASEPOINT_TABLE,
            private_beta: gen_scalar(),
            ec_cipher: ECRistrettoParallel::default(),
            plaintext: Arc::new(RwLock::default()),
            permutation: Arc::new(RwLock::default()),
            h_k_beta_company: Arc::new(RwLock::default()),
            partners_queue: Arc::new(RwLock::default()),
            id_map: Arc::new(RwLock::default()),
            partner_shares: Arc::new(RwLock::default()),
        }
    }

    pub fn get_company_public_key(&self) -> Result<TPayload, ProtocolError> {
        Ok(self.ec_cipher.to_bytes(&[self.keypair_pk]))
    }

    pub fn load_data(&self, path: &str, input_with_headers: bool) {
        load_data_keys(self.plaintext.clone(), path, input_with_headers);
    }
}

impl Default for CompanyDpmc {
    fn default() -> Self {
        Self::new()
    }
}

impl CompanyDpmcProtocol for CompanyDpmc {
    fn set_encrypted_partner_keys_and_shares(
        &self,
        data: TPayload,
        psum: Vec<usize>,
        enc_alpha_t: Vec<u8>,
        scalar_g: Vec<u8>,
        xor_shares: TPayload,
    ) -> Result<(), ProtocolError> {
        match (self.partners_queue.clone().write(),) {
            (Ok(mut partners_queue),) => {
                let t = timer::Timer::new_silent("load_e_partner");
                // This is an array of exclusive-inclusive prefix sum - hence
                // number of keys is one less than length
                let num_keys = psum.len() - 1;

                // Unflatten
                let pdata = {
                    let t = self.ec_cipher.to_points_encrypt(&data, &self.private_beta);

                    psum.get(0..num_keys)
                        .unwrap()
                        .iter()
                        .zip_eq(psum.get(1..num_keys + 1).unwrap().iter())
                        .map(|(&x1, &x2)| t.get(x1..x2).unwrap().to_vec())
                        .collect::<Vec<Vec<_>>>()
                };

                t.qps("deserialize_exp", pdata.len());

                partners_queue.push_back(PartnerData {
                    enc_alpha_t,
                    scalar_g,
                    partner_enc_shares: xor_shares,
                    e_partner: pdata,
                });

                Ok(())
            }
            _ => {
                error!("Cannot load e_partner");
                Err(ProtocolError::ErrorDeserialization(
                    "cannot load e_partner".to_string(),
                ))
            }
        }
    }

    fn get_permuted_keys(&self) -> Result<TPayload, ProtocolError> {
        match (
            self.plaintext.clone().read(),
            self.h_k_beta_company.clone().write(),
            self.permutation.clone().write(),
        ) {
            (Ok(pdata), Ok(mut edata), Ok(mut permutation)) => {
                let t = timer::Timer::new_silent("u_company");

                permutation.clear();
                permutation.extend(gen_permute_pattern(pdata.len()));

                // Permute, flatten, encrypt
                let (mut d_flat, mut offset, metadata) = {
                    let mut d = pdata.clone();
                    permute(permutation.as_slice(), &mut d);

                    let (d_flat, offset, metadata) = serialize_helper(d);

                    // Encrypt
                    let x = self
                        .ec_cipher
                        .hash_encrypt(d_flat.as_slice(), &self.private_beta);

                    (x, offset, metadata)
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

                    edata.clear();
                    edata.extend(x.drain(..));
                }

                t.qps("encryption", d_flat.len());

                // Serialize
                let buf = {
                    let mut x = self.ec_cipher.to_bytes(d_flat.as_slice());

                    d_flat.clear();
                    d_flat.shrink_to_fit();

                    offset.extend(metadata);
                    x.extend(offset);
                    x
                };

                Ok(buf)
            }
            _ => {
                error!("Unable to encrypt UCompany:");
                Err(ProtocolError::ErrorEncryption(
                    "cannot encrypt UCompany".to_string(),
                ))
            }
        }
    }

    fn serialize_encrypted_keys_and_features(&self) -> Result<TPayload, ProtocolError> {
        match (self.partners_queue.clone().write(),) {
            (Ok(mut partners_data_q),) => {
                let t = timer::Timer::new_silent("e_partner");

                let partner_data: PartnerData = partners_data_q.pop_front().unwrap();
                let pdata = partner_data.e_partner;
                let enc_a_t = partner_data.enc_alpha_t;
                let scalar_g = partner_data.scalar_g;
                let enc_shares = partner_data.partner_enc_shares;

                let (mut d_flat, offset) = {
                    let (d_flat, mut offset, metadata) = serialize_helper(pdata.to_vec());
                    offset.extend(metadata);

                    // Serialize
                    (self.ec_cipher.to_bytes(&d_flat), offset)
                };

                t.qps("encryption", d_flat.len());

                // Append offsets array
                d_flat.extend(offset);

                // Append encrypted key alpha
                d_flat.push(ByteBuffer {
                    buffer: enc_a_t.to_vec(),
                });

                d_flat.push(ByteBuffer {
                    buffer: scalar_g.to_vec(),
                });

                // Append offsets array
                d_flat.extend(enc_shares.clone());
                d_flat.push(ByteBuffer {
                    buffer: (enc_shares.len() as u64).to_le_bytes().to_vec(),
                });

                Ok(d_flat)
            }
            _ => {
                error!("Unable to flatten e_partner:");
                Err(ProtocolError::ErrorEncryption(
                    "cannot flatten e_partner".to_string(),
                ))
            }
        }
    }

    fn calculate_features_xor_shares(
        &self,
        partner_features: TFeatures,
        p_mask_d: TPayload,
    ) -> Result<(), ProtocolError> {
        match self.partner_shares.clone().write() {
            Ok(mut shares) => {
                let n_features = partner_features.len();
                let p_mask = self.ec_cipher.to_points(&p_mask_d);

                let mask = p_mask
                    .iter()
                    .map(|x| {
                        let t = self.ec_cipher.to_bytes(&[x * self.keypair_sk]);
                        u64::from_le_bytes((t[0].buffer[0..8]).try_into().unwrap())
                    })
                    .collect::<Vec<_>>();

                for f_idx in 0..n_features {
                    let s = partner_features[f_idx]
                        .iter()
                        .zip_eq(mask.iter())
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
            self.h_k_beta_company.clone().read(),
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
