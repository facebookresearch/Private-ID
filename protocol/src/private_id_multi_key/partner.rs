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

    fn get_id_map_size(&self) -> usize {
        match self.id_map.clone().read() {
            Ok(id_map) => id_map.len(),
            _ => panic!("Cannot get id_map size"),
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

    #[test]
    fn check_save_id_map() {
        use std::io::Read;
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

        // Create a file inside of `std::env::temp_dir()`.
        let mut file1 = NamedTempFile::new().unwrap();
        let p = file1.path().to_str().unwrap();
        partner.save_id_map(p).unwrap();
        let mut actual_result = String::new();
        file1.read_to_string(&mut actual_result).unwrap();
        let expected_result = "08FCF66A09440EFCB475BBCFA5915648A9A7DD0F2D0B75E965EDBAEC249D7D,NA\n30A397CD5C79AB7D6FBD59BF191326BAC43983497C81E1E2F109B3252EACE5F,email1,phone1\n7E105B924F454CF6E0BB4DC7158003A5647DC64A08FDC58BFCC03BDFF85718,email3\nD69F32E652AED8427DAACF74D57B807714160D7454310BF3515DD5AA5F98F4F,phone2\n";

        assert_eq!(actual_result, expected_result);
    }

    #[test]
    fn check_unshuffle_encrypt() {
        //unshuffle_encrypt() will use partner.private_keys.1, company_permutation and company TPayload for encryption.
        //if private_keys.1 and company_permutation are fixed, the result is always same.
        let f = create_data_file().unwrap();

        let mut partner = PartnerPrivateIdMultiKey::new();
        let p = f.path().to_str().unwrap();
        partner.load_data(p, false).unwrap();
        let company = vec![
            ByteBuffer {
                buffer: vec![
                    36, 244, 207, 223, 128, 173, 31, 181, 186, 89, 61, 91, 219, 83, 150, 163, 56,
                    181, 116, 224, 145, 141, 18, 242, 129, 233, 88, 17, 110, 49, 49, 113,
                ],
            },
            ByteBuffer {
                buffer: vec![
                    206, 39, 208, 50, 231, 84, 72, 52, 135, 144, 245, 104, 135, 123, 216, 160, 250,
                    156, 243, 96, 68, 64, 103, 112, 164, 31, 215, 241, 135, 231, 229, 51,
                ],
            },
            ByteBuffer {
                buffer: vec![
                    144, 162, 198, 54, 153, 9, 60, 84, 104, 61, 151, 133, 153, 255, 136, 35, 177,
                    232, 237, 86, 120, 242, 246, 122, 108, 43, 120, 114, 122, 164, 232, 51,
                ],
            },
            ByteBuffer {
                buffer: vec![
                    120, 158, 173, 88, 177, 146, 46, 30, 111, 2, 68, 17, 136, 215, 136, 104, 90,
                    99, 11, 75, 109, 8, 51, 118, 132, 25, 188, 220, 104, 111, 176, 2,
                ],
            },
        ];

        partner.company_permutation = Arc::new(RwLock::new(vec![2, 0, 1]));
        partner.private_keys.1 = create_key();

        let actual_result = partner.unshuffle_encrypt(company).unwrap();
        let expected_result = vec![
            ByteBuffer {
                buffer: vec![
                    202, 241, 242, 47, 249, 131, 246, 166, 85, 138, 218, 82, 84, 153, 30, 46, 133,
                    64, 162, 113, 123, 163, 114, 137, 37, 175, 188, 211, 29, 31, 140, 1,
                ],
            },
            ByteBuffer {
                buffer: vec![
                    94, 224, 94, 242, 165, 118, 221, 50, 246, 154, 226, 214, 153, 9, 99, 197, 204,
                    62, 30, 150, 243, 209, 123, 42, 94, 157, 3, 206, 7, 225, 230, 123,
                ],
            },
            ByteBuffer {
                buffer: vec![
                    176, 194, 85, 162, 206, 222, 179, 118, 53, 252, 105, 204, 185, 60, 160, 145,
                    164, 6, 89, 69, 170, 120, 63, 6, 15, 198, 94, 114, 76, 140, 65, 8,
                ],
            },
            ByteBuffer {
                buffer: vec![
                    54, 143, 63, 196, 218, 246, 85, 75, 171, 239, 105, 248, 133, 85, 150, 20, 1,
                    236, 251, 228, 106, 88, 96, 240, 68, 236, 174, 68, 237, 25, 49, 43,
                ],
            },
        ];
        assert_eq!(actual_result, expected_result);
    }
    #[test]
    fn check_encrypt_permute() {
        let f = create_data_file().unwrap();
        let mut patner = PartnerPrivateIdMultiKey::new();
        let p = f.path().to_str().unwrap();
        patner.load_data(p, false).unwrap();
        patner.self_permutation = Arc::new(RwLock::new(vec![2, 0, 1]));

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
        patner.private_keys.0 = create_key();
        let res = patner.encrypt_permute(data, psum).unwrap();
        assert_eq!(res.len(), 10);
    }
}
