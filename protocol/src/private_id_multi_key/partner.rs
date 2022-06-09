//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use crypto::{
    eccipher::{gen_scalar, ECCipher, ECRistrettoParallel},
    prelude::*,
};
use itertools::Itertools;
use zeroize::Zeroizing;

use crate::private_id_multi_key::traits::PartnerPrivateIdMultiKeyProtocol;

use common::{
    permutations::{gen_permute_pattern, permute, undo_permute},
    timer,
};

use std::sync::{Arc, RwLock};

use super::{load_data, serialize_helper, writer_helper, ProtocolError};

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
