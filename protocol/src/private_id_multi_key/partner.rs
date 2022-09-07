//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

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
use crate::private_id_multi_key::traits::PartnerPrivateIdMultiKeyProtocol;

pub struct PartnerPrivateIdMultiKey {
    private_keys: Zeroizing<(Scalar, Scalar)>,
    ec_cipher: ECRistrettoParallel,
    plaintext: Arc<RwLock<Vec<Vec<String>>>>,
    self_permutation: Arc<RwLock<Vec<usize>>>,
    company_permutation: Arc<RwLock<Vec<usize>>>,
    id_map: Arc<RwLock<Vec<(String, usize, bool)>>>,
}

impl PartnerPrivateIdMultiKey {
    pub fn new() -> PartnerPrivateIdMultiKey {
        PartnerPrivateIdMultiKey {
            private_keys: Zeroizing::new((gen_scalar(), gen_scalar())),
            ec_cipher: ECRistrettoParallel::default(),
            plaintext: Arc::new(RwLock::default()),
            self_permutation: Arc::new(RwLock::default()),
            company_permutation: Arc::new(RwLock::default()),
            id_map: Arc::new(RwLock::default()),
        }
    }

    // TODO: Fix header processing
    pub fn load_data(&self, path: &str, input_with_headers: bool) -> Result<(), ProtocolError> {
        load_data(self.plaintext.clone(), path, input_with_headers);
        Ok(())
    }

    pub fn get_size(&self) -> usize {
        self.plaintext.clone().read().unwrap().len()
    }
}

impl Default for PartnerPrivateIdMultiKey {
    fn default() -> Self {
        Self::new()
    }
}

impl PartnerPrivateIdMultiKeyProtocol for PartnerPrivateIdMultiKey {
    fn permute_hash_to_bytes(&self) -> Result<TPayload, ProtocolError> {
        match (
            self.plaintext.clone().read(),
            self.self_permutation.clone().write(),
        ) {
            (Ok(pdata), Ok(mut permutation)) => {
                let t = timer::Timer::new_silent("u_partner");

                permutation.clear();
                permutation.extend(gen_permute_pattern(pdata.len()));

                // Outer permute
                let mut d = pdata.clone();
                permute(permutation.as_slice(), &mut d);

                // Inner permute each record
                d.iter_mut()
                    .for_each(|v| permute(gen_permute_pattern(v.len()).as_slice(), v));

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
                error!("Unable to encrypt data");
                Err(ProtocolError::ErrorEncryption(
                    "unable to encrypt data".to_string(),
                ))
            }
        }
    }

    //TODO: return result
    fn encrypt_permute(
        &self,
        company: TPayload,
        psum: Vec<usize>,
    ) -> Result<TPayload, ProtocolError> {
        match self.company_permutation.clone().write() {
            Ok(mut permutation) => {
                let t = timer::Timer::new_silent("encrypt_permute_company");
                // This is an array of exclusive-inclusive prefix sum - hence number of keys
                // is one less than length
                let num_keys = psum.len() - 1;

                // Encrypt and unflatten
                let mut d = {
                    let e_c = self
                        .ec_cipher
                        .to_points_encrypt(&company, &self.private_keys.0);
                    t.qps("ecompany", e_c.len());

                    psum.get(0..num_keys)
                        .unwrap()
                        .iter()
                        .zip_eq(psum.get(1..num_keys + 1).unwrap().iter())
                        .map(|(&x1, &x2)| e_c.get(x1..x2).unwrap().to_vec())
                        .collect::<Vec<Vec<_>>>()
                };

                assert_eq!(d.len(), num_keys);

                permutation.clear();
                permutation.extend(gen_permute_pattern(d.len()));

                // Permute each record - outer
                permute(permutation.as_slice(), &mut d);

                // Create prefix-postfix array before flatten. This encodes the
                // ragged array structure
                let (mut d_flat, offset) = {
                    let (d_flat, mut offset, metadata) = serialize_helper(d);
                    offset.extend(metadata);

                    // Serialize to bytes
                    (self.ec_cipher.to_bytes(&d_flat), offset)
                };

                // Append offsets array
                d_flat.extend(offset);
                Ok(d_flat)
            }

            Err(e) => {
                error!("Unable to encrypt data : {}", e);
                Err(ProtocolError::ErrorEncryption(
                    "unable to encrypt data".to_string(),
                ))
            }
        }
    }

    fn encrypt(&self, data: TPayload) -> Result<TPayload, ProtocolError> {
        let ep = self
            .ec_cipher
            .to_points_encrypt(&data, &self.private_keys.1);
        Ok(self.ec_cipher.to_bytes(&ep))
    }

    fn unshuffle_encrypt(&self, data: TPayload) -> Result<TPayload, ProtocolError> {
        match self.company_permutation.clone().read() {
            Ok(permutation) => {
                let ep = {
                    let mut out = data;
                    undo_permute(permutation.as_slice(), &mut out);
                    self.ec_cipher.to_points_encrypt(&out, &self.private_keys.1)
                };
                Ok(self.ec_cipher.to_bytes(&ep))
            }

            Err(e) => {
                error!("Unable to encrypt data : {}", e);
                Err(ProtocolError::ErrorEncryption(
                    "unable to encrypt data".to_string(),
                ))
            }
        }
    }

    fn create_id_map(&self, partner: TPayload, company: TPayload) {
        match (
            self.self_permutation.clone().read(),
            self.id_map.clone().write(),
        ) {
            (Ok(permutation), Ok(mut id_map)) => {
                let partner_encrypt = {
                    let mut out = partner;
                    undo_permute(permutation.as_slice(), &mut out);

                    // Encrypt
                    self.ec_cipher.to_points_encrypt(&out, &self.private_keys.1)
                };

                id_map.clear();
                for (idx, k) in self.ec_cipher.to_bytes(&partner_encrypt).iter().enumerate() {
                    id_map.push((k.to_string(), idx, true));
                }

                for (idx, k) in self
                    .ec_cipher
                    .to_bytes(
                        &self
                            .ec_cipher
                            .to_points_encrypt(&company, &self.private_keys.1),
                    )
                    .iter()
                    .enumerate()
                {
                    id_map.push((k.to_string(), idx, false));
                }

                // Sort the id_map by the spine
                id_map.sort_by(|(a, _, _), (b, _, _)| a.cmp(b));
            }
            _ => panic!("Cannot make v"),
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
        Scalar::from_bits(l_plus_two_bytes)
    }

    #[test]
    fn check_load_data() {
        let f = create_data_file().unwrap();

        let partner = PartnerPrivateIdMultiKey::new();
        let p = f.path().to_str().unwrap();
        partner.load_data(p, false).unwrap();

        let v = partner.plaintext.read().unwrap().clone();
        assert_eq!(v[0], vec![String::from("email1"), String::from("phone1")]);
        assert_eq!(v[1], vec![String::from("phone2")]);
        assert_eq!(v[2], vec![String::from("email3")]);
        assert_eq!(partner.get_size(), 3);
    }

    #[test]
    fn check_permute_hash_to_bytes() {
        let f = create_data_file().unwrap();

        let partner = PartnerPrivateIdMultiKey::new();
        let p = f.path().to_str().unwrap();
        partner.load_data(p, false).unwrap();
        partner.permute_hash_to_bytes().unwrap();
        let mut v = partner.self_permutation.read().unwrap().clone();
        v.sort();
        assert_eq!(v, vec![0, 1, 2]);
    }

    #[test]
    fn check_encrypt() {
        let f = create_data_file().unwrap();

        let mut partner = PartnerPrivateIdMultiKey::new();
        let p = f.path().to_str().unwrap();
        partner.load_data(p, false).unwrap();
        partner.permute_hash_to_bytes().unwrap();

        let data = vec![ByteBuffer {
            buffer: vec![
                62, 18, 201, 254, 28, 155, 30, 218, 108, 118, 81, 64, 32, 200, 123, 153, 164, 39,
                197, 222, 181, 193, 86, 185, 54, 23, 127, 203, 61, 232, 30, 34,
            ],
        }];

        let expected_result = vec![ByteBuffer {
            buffer: vec![
                68, 53, 160, 155, 8, 186, 3, 37, 64, 232, 81, 44, 69, 213, 20, 243, 106, 45, 90,
                245, 216, 85, 109, 207, 70, 130, 15, 119, 105, 14, 159, 99,
            ],
        }];

        partner.private_keys.1 = create_key();
        let ret = partner.encrypt(data).unwrap();

        assert_eq!(ret, expected_result);
    }

    #[test]
    fn check_create_id_map() {
        let f = create_data_file().unwrap();

        let mut partner = PartnerPrivateIdMultiKey::new();
        let p = f.path().to_str().unwrap();
        partner.load_data(p, false).unwrap();
        partner.permute_hash_to_bytes().unwrap();
        partner.self_permutation = Arc::new(RwLock::new(vec![2, 0, 1]));

        let v_partner = vec![
            ByteBuffer {
                buffer: vec![
                    184, 37, 136, 74, 91, 89, 249, 229, 149, 35, 102, 42, 232, 146, 17, 246, 76,
                    220, 123, 255, 26, 158, 35, 211, 76, 0, 12, 77, 138, 141, 88, 55,
                ],
            },
            ByteBuffer {
                buffer: vec![
                    100, 97, 144, 135, 147, 68, 216, 225, 242, 22, 79, 71, 68, 234, 128, 43, 10,
                    77, 232, 44, 231, 186, 118, 248, 170, 72, 69, 235, 244, 14, 89, 39,
                ],
            },
            ByteBuffer {
                buffer: vec![
                    80, 11, 202, 56, 183, 53, 94, 71, 140, 170, 181, 22, 207, 222, 150, 81, 80,
                    180, 174, 79, 191, 137, 150, 58, 5, 76, 147, 129, 97, 101, 254, 78,
                ],
            },
        ];

        let s_prime_company = vec![ByteBuffer {
            buffer: vec![
                150, 101, 24, 58, 27, 195, 133, 170, 204, 58, 112, 209, 217, 143, 84, 106, 228,
                249, 130, 71, 190, 173, 65, 47, 162, 8, 216, 116, 205, 239, 8, 17,
            ],
        }];
        partner.private_keys.1 = create_key();

        partner.create_id_map(v_partner, s_prime_company);
        partner.print_id_map();

        let mut res = partner.id_map.read().unwrap().clone();
        res.sort();
        let mut expected = vec![
            (
                String::from("08FCF66A09440EFCB475BBCFA5915648A9A7DD0F2D0B75E965EDBAEC249D7D"),
                0,
                false,
            ),
            (
                String::from("30A397CD5C79AB7D6FBD59BF191326BAC43983497C81E1E2F109B3252EACE5F"),
                0,
                true,
            ),
            (
                String::from("7E105B924F454CF6E0BB4DC7158003A5647DC64A08FDC58BFCC03BDFF85718"),
                2,
                true,
            ),
            (
                String::from("D69F32E652AED8427DAACF74D57B807714160D7454310BF3515DD5AA5F98F4F"),
                1,
                true,
            ),
        ];
        expected.sort();
        assert_eq!(res, expected);
    }
}
