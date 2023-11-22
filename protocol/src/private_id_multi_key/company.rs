//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
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
use zeroize::Zeroizing;

use super::load_data;
use super::serialize_helper;
use super::writer_helper;
use super::ProtocolError;
use crate::private_id_multi_key::traits::CompanyPrivateIdMultiKeyProtocol;

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
                            let c = self.ec_cipher.encrypt(p.as_slice(), &self.private_keys.2);

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
    use std::io::{self};

    use tempfile::NamedTempFile;

    use super::*;
    fn create_data_file() -> Result<NamedTempFile, io::Error> {
        let data = "email1,phone1 \n
        phone2, \n
        email3,";

        use std::io::Write;
        // Create a file inside of `std::env::temp_dir()`.
        let mut file1 = NamedTempFile::new().unwrap();

        // Write some test data to the first handle.
        file1.write_all(data.as_bytes()).unwrap();
        Ok(file1)
    }

    fn create_key() -> Scalar {
        let l_plus_two_bytes: [u8; 32] = [
            0xef, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ];
        Scalar::from_bytes_mod_order(l_plus_two_bytes)
    }

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

    #[test]
    fn check_load_data() {
        let f = create_data_file().unwrap();

        let company = CompanyPrivateIdMultiKey::new();
        let p = f.path().to_str().unwrap();
        company.load_data(p, false);
        let v = company.plaintext.read().unwrap().clone();

        assert_eq!(v[0], vec![String::from("email1"), String::from("phone1")]);
        assert_eq!(v[1], vec![String::from("phone2")]);
        assert_eq!(v[2], vec![String::from("email3")]);
    }

    #[test]
    fn check_write_company_to_id_map() {
        let f = create_data_file().unwrap();

        let mut company = CompanyPrivateIdMultiKey::new();
        let p = f.path().to_str().unwrap();
        company.load_data(p, false);
        company.permutation = Arc::new(RwLock::new(vec![2, 0, 1]));

        company.w_company = Arc::new(RwLock::new(vec![
            ByteBuffer {
                buffer: vec![
                    58, 238, 93, 247, 63, 124, 81, 222, 215, 243, 95, 187, 205, 5, 208, 227, 101,
                    148, 128, 240, 157, 22, 38, 218, 110, 130, 240, 13, 75, 104, 73, 97,
                ],
            },
            ByteBuffer {
                buffer: vec![
                    214, 21, 219, 73, 112, 150, 130, 90, 224, 145, 41, 23, 251, 237, 166, 76, 231,
                    200, 59, 116, 68, 223, 226, 162, 97, 48, 191, 15, 49, 103, 144, 82,
                ],
            },
            ByteBuffer {
                buffer: vec![
                    236, 161, 226, 204, 138, 177, 182, 83, 166, 68, 126, 141, 217, 34, 99, 150,
                    239, 116, 79, 75, 27, 10, 91, 83, 192, 15, 83, 146, 140, 178, 237, 109,
                ],
            },
        ]));

        company.s_prime_partner = Arc::new(RwLock::new(vec![ByteBuffer {
            buffer: vec![
                0, 119, 48, 179, 225, 233, 92, 97, 158, 42, 97, 60, 16, 8, 240, 134, 84, 32, 209,
                173, 230, 87, 191, 5, 44, 184, 1, 155, 194, 46, 95, 8,
            ],
        }]));
        company.private_keys.1 = create_key();
        company.private_keys.2 = create_key();

        company.write_company_to_id_map();
        company.print_id_map();

        let mut res = company.id_map.read().unwrap().clone();
        res.sort();
        let mut expected = vec![
            (
                String::from("2CA6934AAEB83F429276A2A431FBD05A3E90CF8CAD72DF5327CE93A37CC79"),
                0,
                true,
            ),
            (
                String::from("46FC0D94F2B89C4CCAF4BE054E79ED5BFF8A43E8D8FFD3B74E9496F7FEE882E"),
                2,
                true,
            ),
            (
                String::from("888B5EDF9AD79141C841E9ED6CE34BC582669E4FEF516920101687CB6CE2F85A"),
                1,
                true,
            ),
            (
                String::from("B891BC079AD554CB3D73A2392F588E4BEA97F33F98718B1F4520C51EDCDC"),
                0,
                false,
            ),
        ];
        expected.sort();
        assert_eq!(res, expected);
    }

    #[test]
    fn check_save_id_map() {
        //save_id_map() will use company.private_keys.1, private_keys.2, permutation, s_prime_partner and w_company TPayload for encryption.
        //if private_keys.1, private_keys.2, s_prime_partner and permutation are fixed, the result is always same.
        use std::io::Read;
        let f = create_data_file().unwrap();

        let mut company = CompanyPrivateIdMultiKey::new();
        let p = f.path().to_str().unwrap();
        company.load_data(p, false);
        company.permutation = Arc::new(RwLock::new(vec![2, 0, 1]));

        company.w_company = Arc::new(RwLock::new(vec![
            ByteBuffer {
                buffer: vec![
                    58, 238, 93, 247, 63, 124, 81, 222, 215, 243, 95, 187, 205, 5, 208, 227, 101,
                    148, 128, 240, 157, 22, 38, 218, 110, 130, 240, 13, 75, 104, 73, 97,
                ],
            },
            ByteBuffer {
                buffer: vec![
                    214, 21, 219, 73, 112, 150, 130, 90, 224, 145, 41, 23, 251, 237, 166, 76, 231,
                    200, 59, 116, 68, 223, 226, 162, 97, 48, 191, 15, 49, 103, 144, 82,
                ],
            },
            ByteBuffer {
                buffer: vec![
                    236, 161, 226, 204, 138, 177, 182, 83, 166, 68, 126, 141, 217, 34, 99, 150,
                    239, 116, 79, 75, 27, 10, 91, 83, 192, 15, 83, 146, 140, 178, 237, 109,
                ],
            },
        ]));

        company.s_prime_partner = Arc::new(RwLock::new(vec![ByteBuffer {
            buffer: vec![
                0, 119, 48, 179, 225, 233, 92, 97, 158, 42, 97, 60, 16, 8, 240, 134, 84, 32, 209,
                173, 230, 87, 191, 5, 44, 184, 1, 155, 194, 46, 95, 8,
            ],
        }]));
        company.private_keys.1 = create_key();
        company.private_keys.2 = create_key();

        company.write_company_to_id_map();
        // Create a file inside of `std::env::temp_dir()`.
        let mut file1 = NamedTempFile::new().unwrap();
        let p = file1.path().to_str().unwrap();
        company.save_id_map(p).unwrap();
        let mut actual_result = String::new();
        file1.read_to_string(&mut actual_result).unwrap();
        let expected_result = "2CA6934AAEB83F429276A2A431FBD05A3E90CF8CAD72DF5327CE93A37CC79,email1,phone1\n46FC0D94F2B89C4CCAF4BE054E79ED5BFF8A43E8D8FFD3B74E9496F7FEE882E,email3\n888B5EDF9AD79141C841E9ED6CE34BC582669E4FEF516920101687CB6CE2F85A,phone2\nB891BC079AD554CB3D73A2392F588E4BEA97F33F98718B1F4520C51EDCDC,NA\n";
        assert_eq!(actual_result, expected_result);
    }

    #[test]
    fn check_set_set_diff_output() {
        let f = create_data_file().unwrap();
        let company = CompanyPrivateIdMultiKey::default();
        let p = f.path().to_str().unwrap();
        company.load_data(p, false);

        let data = vec![
            ByteBuffer {
                buffer: vec![
                    170, 206, 33, 27, 149, 177, 31, 116, 89, 46, 96, 98, 116, 115, 143, 239, 208,
                    136, 101, 118, 101, 28, 222, 176, 134, 209, 195, 132, 222, 148, 61, 74,
                ],
            },
            ByteBuffer {
                buffer: vec![
                    126, 159, 62, 144, 16, 33, 230, 162, 97, 55, 213, 11, 52, 45, 222, 188, 202,
                    142, 50, 71, 228, 111, 224, 45, 177, 175, 241, 142, 247, 14, 215, 126,
                ],
            },
            ByteBuffer {
                buffer: vec![
                    20, 250, 150, 75, 227, 186, 198, 234, 129, 171, 43, 37, 17, 97, 177, 86, 118,
                    209, 51, 215, 43, 71, 187, 80, 17, 225, 204, 175, 216, 85, 37, 29,
                ],
            },
        ];
        company
            .set_set_diff_output(String::from("w_company"), data.clone())
            .unwrap();

        let res = company
            .w_company
            .read()
            .map(|data| data.to_vec())
            .ok()
            .unwrap();
        assert_eq!(res, data);

        company
            .set_set_diff_output(String::from("s_prime_partner"), data.clone())
            .unwrap();
        let res = company
            .s_prime_partner
            .read()
            .map(|data| data.to_vec())
            .ok()
            .unwrap();
        assert_eq!(res, data);
    }

    #[test]
    fn check_get_set_diff_output() {
        let f = create_data_file().unwrap();
        let mut company = CompanyPrivateIdMultiKey::new();
        let p = f.path().to_str().unwrap();
        company.load_data(p, false);
        company.permutation = Arc::new(RwLock::new(vec![2, 0, 1]));
        let data = vec![
            ByteBuffer {
                buffer: vec![
                    58, 238, 93, 247, 63, 124, 81, 222, 215, 243, 95, 187, 205, 5, 208, 227, 101,
                    148, 128, 240, 157, 22, 38, 218, 110, 130, 240, 13, 75, 104, 73, 97,
                ],
            },
            ByteBuffer {
                buffer: vec![
                    214, 21, 219, 73, 112, 150, 130, 90, 224, 145, 41, 23, 251, 237, 166, 76, 231,
                    200, 59, 116, 68, 223, 226, 162, 97, 48, 191, 15, 49, 103, 144, 82,
                ],
            },
            ByteBuffer {
                buffer: vec![
                    236, 161, 226, 204, 138, 177, 182, 83, 166, 68, 126, 141, 217, 34, 99, 150,
                    239, 116, 79, 75, 27, 10, 91, 83, 192, 15, 83, 146, 140, 178, 237, 109,
                ],
            },
        ];

        company.v_partner = Arc::new(RwLock::new(data.clone()));
        let v_partner_res = company
            .get_set_diff_output(String::from("v_partner"))
            .unwrap();

        company.v_company = Arc::new(RwLock::new(data.clone()));
        let v_company_res = company
            .get_set_diff_output(String::from("v_company"))
            .unwrap();

        company.s_partner = Arc::new(RwLock::new(data.clone()));
        let s_partner_res = company
            .get_set_diff_output(String::from("s_partner"))
            .unwrap();

        company.s_prime_company = Arc::new(RwLock::new(data.clone()));
        let s_prime_company_res = company
            .get_set_diff_output(String::from("s_prime_company"))
            .unwrap();

        assert_eq!(v_partner_res, data);
        assert_eq!(v_company_res, data);
        assert_eq!(s_partner_res, data);
        assert_eq!(s_prime_company_res, data);
    }

    #[test]
    fn check_get_permuted_keys() {
        use std::io::Write;
        let data = "email1,phone1";
        // Create a file inside of `std::env::temp_dir()`.
        let mut f = NamedTempFile::new().unwrap();

        // Write some test data to the first handle.
        f.write_all(data.as_bytes()).unwrap();

        let mut company = CompanyPrivateIdMultiKey::new();
        let p = f.path().to_str().unwrap();
        company.load_data(p, false);
        company.private_keys.0 = create_key();

        let actural_res = company.get_permuted_keys().unwrap();
        let expected_res = vec![
            ByteBuffer {
                buffer: vec![
                    56, 197, 96, 89, 53, 196, 33, 112, 252, 240, 13, 203, 205, 213, 229, 14, 40,
                    27, 147, 68, 58, 201, 22, 220, 97, 221, 221, 214, 107, 68, 69, 71,
                ],
            },
            ByteBuffer {
                buffer: vec![
                    164, 174, 70, 150, 206, 226, 174, 2, 30, 223, 217, 72, 100, 37, 12, 173, 165,
                    85, 58, 201, 213, 74, 238, 97, 8, 93, 143, 87, 178, 122, 176, 12,
                ],
            },
            ByteBuffer {
                buffer: vec![0, 0, 0, 0, 0, 0, 0, 0],
            },
            ByteBuffer {
                buffer: vec![2, 0, 0, 0, 0, 0, 0, 0],
            },
            ByteBuffer {
                buffer: vec![2, 0, 0, 0, 0, 0, 0, 0],
            },
            ByteBuffer {
                buffer: vec![2, 0, 0, 0, 0, 0, 0, 0],
            },
        ];
        assert_eq!(expected_res, actural_res);
    }

    #[test]
    fn check_calculate_set_diff() {
        let f = create_data_file().unwrap();
        let mut company = CompanyPrivateIdMultiKey::new();
        let p = f.path().to_str().unwrap();
        company.load_data(p, false);
        company.permutation = Arc::new(RwLock::new(vec![2, 0, 1]));

        let data = vec![
            ByteBuffer {
                buffer: vec![
                    200, 135, 56, 19, 5, 207, 16, 147, 198, 229, 224, 111, 97, 119, 247, 238, 48,
                    209, 55, 188, 30, 178, 53, 4, 110, 27, 182, 220, 156, 57, 53, 63,
                ],
            },
            ByteBuffer {
                buffer: vec![
                    102, 237, 233, 208, 207, 235, 165, 5, 177, 27, 168, 233, 239, 69, 163, 80, 155,
                    2, 85, 192, 182, 25, 20, 189, 118, 5, 225, 153, 13, 254, 201, 40,
                ],
            },
            ByteBuffer {
                buffer: vec![
                    48, 54, 39, 197, 69, 34, 214, 167, 225, 117, 64, 223, 51, 164, 33, 208, 18,
                    108, 38, 248, 215, 189, 94, 180, 82, 105, 196, 43, 189, 2, 220, 6,
                ],
            },
            ByteBuffer {
                buffer: vec![
                    228, 188, 46, 30, 21, 100, 156, 96, 162, 185, 103, 149, 89, 159, 81, 67, 119,
                    112, 0, 174, 99, 188, 74, 7, 13, 236, 98, 48, 50, 145, 156, 50,
                ],
            },
        ];

        let psum = vec![0, 2, 3, 4];
        company.private_keys.0 = create_key();
        company
            .set_encrypted_partner_keys(data.clone(), psum.clone())
            .unwrap();
        company
            .set_encrypted_company(String::from("e_company"), data, psum)
            .unwrap();

        company.calculate_set_diff().unwrap();

        let v_partner_res = company
            .get_set_diff_output(String::from("v_partner"))
            .unwrap();

        let v_company_res = company
            .get_set_diff_output(String::from("v_company"))
            .unwrap();

        let s_partner_res = company
            .get_set_diff_output(String::from("s_partner"))
            .unwrap();

        let s_prime_company_res = company
            .get_set_diff_output(String::from("s_prime_company"))
            .unwrap();

        assert_eq!(v_partner_res.len(), 3);
        assert_eq!(v_company_res.len(), 3);
        assert_eq!(s_partner_res.len(), 3);
        assert_eq!(s_prime_company_res.len(), 3);
    }
}
