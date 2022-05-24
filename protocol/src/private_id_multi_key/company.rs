//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate csv;

use itertools::Itertools;
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use crypto::{
    eccipher::{gen_scalar, ECCipher, ECRistrettoParallel},
    prelude::*,
};

use common::{
    files,
    permutations::{gen_permute_pattern, permute, undo_permute},
    timer,
};

use zeroize::Zeroizing;

use crate::private_id_multi_key::traits::CompanyPrivateIdMultiKeyProtocol;

use super::{load_data, serialize_helper, writer_helper, ProtocolError};

#[derive(Debug)]
pub struct CompanyPrivateIdMultiKey {
    private_keys: Zeroizing<(Scalar, Scalar, Scalar)>,
    ec_cipher: ECRistrettoParallel,
    // TODO: consider using dyn pid::crypto::ECCipher trait?
    plaintext: Arc<RwLock<Vec<Vec<String>>>>,
    permutation: Arc<RwLock<Vec<usize>>>,

    e_company: Arc<RwLock<Vec<Vec<TPoint>>>>,
    e_partner: Arc<RwLock<Vec<Vec<TPoint>>>>,

    v_company: Arc<RwLock<Vec<ByteBuffer>>>,
    v_partner: Arc<RwLock<Vec<ByteBuffer>>>,

    s_prime_company: Arc<RwLock<Vec<ByteBuffer>>>,
    s_partner: Arc<RwLock<Vec<ByteBuffer>>>,

    w_company: Arc<RwLock<Vec<ByteBuffer>>>,
    s_prime_partner: Arc<RwLock<Vec<ByteBuffer>>>,

    id_map: Arc<RwLock<Vec<(String, usize, bool)>>>,
}

impl CompanyPrivateIdMultiKey {
    pub fn new() -> CompanyPrivateIdMultiKey {
        CompanyPrivateIdMultiKey {
            private_keys: Zeroizing::new((gen_scalar(), gen_scalar(), gen_scalar())),
            ec_cipher: ECRistrettoParallel::default(),
            plaintext: Arc::new(RwLock::default()),
            permutation: Arc::new(RwLock::default()),
            v_company: Arc::new(RwLock::default()),
            v_partner: Arc::new(RwLock::default()),
            e_company: Arc::new(RwLock::default()),
            e_partner: Arc::new(RwLock::default()),
            s_prime_company: Arc::new(RwLock::default()),
            s_partner: Arc::new(RwLock::default()),
            w_company: Arc::new(RwLock::default()),
            s_prime_partner: Arc::new(RwLock::default()),
            id_map: Arc::new(RwLock::default()),
        }
    }

    pub fn load_data(&self, path: &str, input_with_headers: bool) {
        load_data(self.plaintext.clone(), path, input_with_headers);
    }

    pub fn get_e_company_size(&self) -> usize {
        self.e_company.read().unwrap().len()
    }

    pub fn get_e_partner_size(&self) -> usize {
        self.e_partner.read().unwrap().len()
    }

    pub fn get_id_map_size(&self) -> usize {
        self.id_map.read().unwrap().len()
    }
}

impl Default for CompanyPrivateIdMultiKey {
    fn default() -> Self {
        Self::new()
    }
}

impl CompanyPrivateIdMultiKeyProtocol for CompanyPrivateIdMultiKey {
    fn set_encrypted_company(
        &self,
        name: String,
        data: TPayload,
        psum: Vec<usize>,
    ) -> Result<(), ProtocolError> {
        // This is an array of exclusive-inclusive prefix sum - hence number of keys
        // is one less than length
        let num_keys = psum.len() - 1;

        // Unflatten
        let mut x = {
            let t = self.ec_cipher.to_points(&data);

            psum.get(0..num_keys)
                .unwrap()
                .iter()
                .zip_eq(psum.get(1..num_keys + 1).unwrap().iter())
                .map(|(&x1, &x2)| t.get(x1..x2).unwrap().to_vec())
                .collect::<Vec<Vec<_>>>()
        };

        assert_eq!(x.len(), num_keys);

        match name.as_str() {
            "e_company" => self
                .e_company
                .clone()
                .write()
                .map(|mut d| {
                    let t = timer::Timer::new_silent("Load e_company");
                    d.clear();
                    d.extend(x.drain(..));
                    t.qps("deserialize", data.len());
                })
                .map_err(|_| {
                    ProtocolError::ErrorDeserialization("Cannot load e_company".to_string())
                }),
            _ => panic!("wrong name"),
        }
    }

    fn set_encrypted_partner_keys(
        &self,
        data: TPayload,
        psum: Vec<usize>,
    ) -> Result<(), ProtocolError> {
        // This is an array of exclusive-inclusive prefix sum - hence number of keys
        // is one less than length
        let num_keys = psum.len() - 1;

        // Unflatten
        let mut x = {
            let t = self
                .ec_cipher
                .to_points_encrypt(&data, &self.private_keys.0);

            psum.get(0..num_keys)
                .unwrap()
                .iter()
                .zip_eq(psum.get(1..num_keys + 1).unwrap().iter())
                .map(|(&x1, &x2)| t.get(x1..x2).unwrap().to_vec())
                .collect::<Vec<Vec<_>>>()
        };

        self.e_partner
            .clone()
            .write()
            .map(|mut data| {
                let t = timer::Timer::new_silent("load_u_partner");
                data.clear();
                data.extend(x.drain(..));
                t.qps("deserialize_exp", data.len());
            })
            .map_err(|err| {
                error!("Cannot load e_company {}", err);
                ProtocolError::ErrorDeserialization("cannot load u_partner".to_string())
            })
    }

    fn get_permuted_keys(&self) -> Result<TPayload, ProtocolError> {
        match (
            self.plaintext.clone().read(),
            self.permutation.clone().write(),
        ) {
            (Ok(pdata), Ok(mut permutation)) => {
                let t = timer::Timer::new_silent("u_company");

                permutation.clear();
                permutation.extend(gen_permute_pattern(pdata.len()));

                let mut d = pdata.clone();
                permute(permutation.as_slice(), &mut d);

                // Permute and flatten
                let (mut d_flat, offset) = {
                    let (d_flat, mut offset, metadata) = serialize_helper(d);
                    offset.extend(metadata);

                    // Encrypt
                    (
                        self.ec_cipher
                            .hash_encrypt_to_bytes(d_flat.as_slice(), &self.private_keys.0),
                        offset,
                    )
                };

                t.qps("encryption", d_flat.len());

                // Append offsets array
                d_flat.extend(offset);

                Ok(d_flat)
            }
            _ => {
                error!("Unable to encrypt UCompany:");
                Err(ProtocolError::ErrorEncryption(
                    "cannot encrypt UCompany".to_string(),
                ))
            }
        }
    }

    fn calculate_set_diff(&self) -> Result<(), ProtocolError> {
        match (
            self.e_partner.clone().read(),
            self.e_company.clone().read(),
            self.v_partner.clone().write(),
            self.v_company.clone().write(),
            self.s_partner.clone().write(),
            self.s_prime_company.clone().write(),
        ) {
            (
                Ok(e_partner),
                Ok(e_company),
                Ok(mut v_partner),
                Ok(mut v_company),
                Ok(mut s_partner),
                Ok(mut s_prime_company),
            ) => {
                let s_c = e_company.iter().map(|e| e[0]).collect::<Vec<_>>();
                let s_p = e_partner.iter().map(|e| e[0]).collect::<Vec<_>>();

                let mut v_c = self.ec_cipher.encrypt(
                    &self.ec_cipher.encrypt(s_c.as_slice(), &self.private_keys.1),
                    &self.private_keys.2,
                );

                let mut v_p = self.ec_cipher.encrypt(s_p.as_slice(), &self.private_keys.1);

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
                            // Create a single element vector since that is what encrypt
                            // expects
                            let matched = vec![e_company[m_idx][idx]];
                            let p = self
                                .ec_cipher
                                .encrypt(matched.as_slice(), &self.private_keys.1);
                            let c = self.ec_cipher.encrypt(
                                p.as_slice(),
                                &self.private_keys.2,
                            );

                            e_c_valid[m_idx] = false;
                            v_c[m_idx] = c[0];

                            e_p_match_idx.push(i);
                            v_p[i] = p[0];
                        }
                    }

                    // Set all e_p that matched to false - so they aren't matched in the next
                    // iteration
                    e_p_match_idx.iter().for_each(|&idx| e_p_valid[idx] = false);
                }

                // Create V_c and V_p
                v_company.clear();
                v_company.extend(self.ec_cipher.to_bytes(v_c.as_slice()));

                v_partner.clear();
                v_partner.extend(self.ec_cipher.to_bytes(v_p.as_slice()));

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
                s_prime_company.clear();

                if !t.is_empty() {
                    s_prime_company.extend(
                        self.ec_cipher
                            .encrypt_to_bytes(t.as_slice(), &self.private_keys.1),
                    );
                }

                Ok(())
            }
            _ => {
                error!("Unable to obtain locks to buffers for set diff operation");
                Err(ProtocolError::ErrorCalcSetDiff(
                    "cannot calculate set difference".to_string(),
                ))
            }
        }
    }

    fn get_set_diff_output(&self, name: String) -> Result<TPayload, ProtocolError> {
        match name.as_str() {
            "s_partner" => self
                .s_partner
                .clone()
                .read()
                .map(|data| data.to_vec())
                .map_err(|err| {
                    error!("Unable to get s_prime_partner: {}", err);
                    ProtocolError::ErrorDeserialization("cannot obtain s_partner".to_string())
                }),
            "s_prime_company" => self
                .s_prime_company
                .clone()
                .read()
                .map(|data| data.to_vec())
                .map_err(|err| {
                    error!("Unable to get s_prime_company: {}", err);
                    ProtocolError::ErrorDeserialization("cannot obtain s_prime_company".to_string())
                }),
            "v_partner" => self
                .v_partner
                .clone()
                .read()
                .map(|data| data.to_vec())
                .map_err(|err| {
                    error!("Unable to get v_partner: {}", err);
                    ProtocolError::ErrorDeserialization("cannot obtain v_partner".to_string())
                }),
            "v_company" => self
                .v_company
                .clone()
                .read()
                .map(|data| data.to_vec())
                .map_err(|err| {
                    error!("Unable to get v_company: {}", err);
                    ProtocolError::ErrorDeserialization("cannot obtain v_company".to_string())
                }),
            _ => panic!("wrong name"),
        }
    }

    // Even though set diff is computed by company, it has to do a round-trip
    // through the client to be encrypted and unshuffled
    fn set_set_diff_output(&self, name: String, data: TPayload) -> Result<(), ProtocolError> {
        match name.as_str() {
            "s_prime_partner" => self
                .s_prime_partner
                .clone()
                .write()
                .map(|mut input| {
                    input.clear();
                    input.extend(data);
                })
                .map_err(|err| {
                    error!("Unable to write s_prime_partner: {}", err);
                    ProtocolError::ErrorDeserialization("cannot write s_prime_partner".to_string())
                }),
            "w_company" => self
                .w_company
                .clone()
                .write()
                .map(|mut input| {
                    input.clear();
                    input.extend(data);
                })
                .map_err(|err| {
                    error!("Unable to write w_company: {}", err);
                    ProtocolError::ErrorDeserialization("cannot write w_company".to_string())
                }),
            _ => panic!("wrong name"),
        }
    }

    fn write_company_to_id_map(&self) {
        match (
            self.permutation.clone().read(),
            self.w_company.clone().read(),
            self.s_prime_partner.clone().read(),
            self.id_map.clone().write(),
        ) {
            (Ok(permutation), Ok(company), Ok(partner), Ok(mut id_map)) => {
                let company_encrypt = {
                    let mut out = company.clone();
                    undo_permute(permutation.as_slice(), &mut out);

                    self.ec_cipher
                        .to_points_encrypt(out.as_slice(), &self.private_keys.2.invert())
                };

                id_map.clear();
                for (idx, k) in self.ec_cipher.to_bytes(&company_encrypt).iter().enumerate() {
                    id_map.push((k.to_string(), idx, true));
                }

                for (idx, k) in self
                    .ec_cipher
                    .to_bytes(
                        &self
                            .ec_cipher
                            .to_points_encrypt(&partner, &self.private_keys.1),
                    )
                    .iter()
                    .enumerate()
                {
                    id_map.push((k.to_string(), idx, false));
                }

                // Sort the id_map by the spine
                id_map.sort_by(|(a, _, _), (b, _, _)| a.cmp(b));
            }
            _ => panic!("Cannot create id_map"),
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
                "Unable to write partner view to file".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_get_e_company_size() {
        let b = CompanyPrivateIdMultiKey::new();
        assert_eq!(b.get_e_company_size(), 0);
    }

    #[test]
    fn test_get_e_partner_size() {
        let b = CompanyPrivateIdMultiKey::new();
        assert_eq!(b.get_e_partner_size(), 0);
    }

    #[test]
    fn test_get_id_map_size() {
        let b = CompanyPrivateIdMultiKey::new();
        assert_eq!(b.get_id_map_size(), 0);
    }
}
