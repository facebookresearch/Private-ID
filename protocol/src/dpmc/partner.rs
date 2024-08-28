//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use std::convert::TryInto;
use std::sync::Arc;
use std::sync::RwLock;

use base64::engine::general_purpose::URL_SAFE;
use base64::Engine;
use common::permutations::gen_permute_pattern;
use common::permutations::permute;
use common::timer;
use crypto::eccipher::gen_scalar;
use crypto::eccipher::ECCipher;
use crypto::eccipher::ECRistrettoParallel;
use crypto::prelude::*;
use fernet::Fernet;
use rayon::iter::ParallelDrainRange;
use rayon::iter::ParallelIterator;

use super::load_data_features;
use super::load_data_keys;
use super::serialize_helper;
use super::ProtocolError;
use crate::dpmc::traits::PartnerDpmcProtocol;
use crate::shared::TFeatures;

pub struct PartnerDpmc {
    keypair_sk: Scalar,
    keypair_pk: TPoint,
    partner_scalar: Scalar,
    company_public_key: Arc<RwLock<TPoint>>,
    helper_public_key: Arc<RwLock<TPoint>>,
    ec_cipher: ECRistrettoParallel,
    permutation: Arc<RwLock<Vec<usize>>>,
    plaintext_keys: Arc<RwLock<Vec<Vec<String>>>>,
    plaintext_features: Arc<RwLock<TFeatures>>,
    aes_key: Arc<RwLock<String>>,
}

impl PartnerDpmc {
    pub fn new() -> PartnerDpmc {
        let x = gen_scalar();
        PartnerDpmc {
            keypair_sk: x,
            keypair_pk: &x * RISTRETTO_BASEPOINT_TABLE,
            partner_scalar: gen_scalar(),
            company_public_key: Arc::new(RwLock::default()),
            helper_public_key: Arc::new(RwLock::default()),
            ec_cipher: ECRistrettoParallel::default(),
            permutation: Arc::new(RwLock::default()),
            plaintext_keys: Arc::new(RwLock::default()),
            plaintext_features: Arc::new(RwLock::default()),
            aes_key: Arc::new(RwLock::default()),
        }
    }

    // TODO: Fix header processing
    pub fn load_data(&self, path_keys: &str, path_features: &str, input_with_headers: bool) {
        load_data_keys(self.plaintext_keys.clone(), path_keys, input_with_headers);
        load_data_features(self.plaintext_features.clone(), path_features);

        match (
            self.plaintext_keys.clone().read(),
            self.plaintext_features.clone().read(),
        ) {
            (Ok(keys), Ok(features)) => {
                assert!(features.len() > 0);
                assert_eq!(keys.len(), features[0].len());
            }
            _ => {
                error!("Unable to read keys and features");
            }
        }
    }

    pub fn get_size(&self) -> usize {
        self.plaintext_keys.clone().read().unwrap().len()
    }

    pub fn get_partner_public_key(&self) -> Result<TPayload, ProtocolError> {
        Ok(self.ec_cipher.to_bytes(&[self.keypair_pk]))
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

    pub fn set_helper_public_key(&self, helper_public_key: TPayload) -> Result<(), ProtocolError> {
        let pk = self.ec_cipher.to_points(&helper_public_key);
        // Check that one key is sent
        assert_eq!(pk.len(), 1);
        match (
            self.helper_public_key.clone().write(),
            self.aes_key.clone().write(),
        ) {
            (Ok(mut helper_pk), Ok(mut aes_key)) => {
                *helper_pk = pk[0];
                assert!(!(*helper_pk).is_identity());

                *aes_key = {
                    let x = self
                        .ec_cipher
                        .to_bytes(&[self.partner_scalar * (*helper_pk)]);
                    let aes_key_bytes = x[0].buffer.clone();
                    URL_SAFE.encode(aes_key_bytes)
                };
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

impl Default for PartnerDpmc {
    fn default() -> Self {
        Self::new()
    }
}

impl PartnerDpmcProtocol for PartnerDpmc {
    fn get_encrypted_keys(&self) -> Result<TPayload, ProtocolError> {
        match (
            self.plaintext_keys.clone().read(),
            self.aes_key.clone().read(),
            self.permutation.clone().write(),
        ) {
            (Ok(pdata), Ok(aes_key), Ok(mut permutation)) => {
                let t = timer::Timer::new_silent("partner data");

                // Generate random permutation.
                permutation.clear();
                permutation.extend(gen_permute_pattern(pdata.len()));

                // Permute, flatten, encrypt
                let (mut d_flat, offset) = {
                    let mut d = pdata.clone();
                    permute(permutation.as_slice(), &mut d);

                    let (d_flat, mut offset, metadata) = serialize_helper(d);
                    offset.extend(metadata);

                    // Encrypt
                    (
                        // Blind the keys by encrypting
                        self.ec_cipher
                            .hash_encrypt_to_bytes(d_flat.as_slice(), &self.keypair_sk),
                        offset,
                    )
                };

                t.qps("encryption", d_flat.len());

                // Append offsets array
                d_flat.extend(offset);

                let fernet = Fernet::new(&aes_key).unwrap();
                let ctxt = fernet.encrypt(self.keypair_sk.to_bytes().clone().as_slice());
                // Append encrypted key alpha
                d_flat.push(ByteBuffer {
                    buffer: ctxt.as_bytes().to_vec(),
                });

                let p_scalar_times_g = self
                    .ec_cipher
                    .to_bytes(&[&self.partner_scalar * RISTRETTO_BASEPOINT_TABLE]);
                d_flat.extend(p_scalar_times_g);

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

    fn get_features_xor_shares(&self) -> Result<TPayload, ProtocolError> {
        match (
            self.plaintext_features.clone().read(),
            self.company_public_key.clone().read(),
            self.aes_key.clone().read(),
            self.permutation.clone().read(),
        ) {
            (Ok(pdata), Ok(company_public_key), Ok(aes_key), Ok(permutation)) => {
                let t = timer::Timer::new_silent("get_features_xor_shares");
                let n_rows = pdata[0].len();
                let n_features = pdata.len();

                // Apply the same permutation as in keys.
                let mut permuted_pdata = pdata.clone();
                for i in 0..n_features {
                    permute(permutation.as_slice(), &mut permuted_pdata[i]);
                }

                let z_i = (0..n_rows)
                    .collect::<Vec<_>>()
                    .iter()
                    .map(|_| gen_scalar())
                    .collect::<Vec<_>>();

                let mut d_flat = {
                    let r_i = {
                        let y_zi = {
                            let t = z_i
                                .iter()
                                .map(|x| *x * *company_public_key)
                                .collect::<Vec<_>>();
                            self.ec_cipher.to_bytes(&t)
                        };
                        y_zi.iter()
                            .map(|x| u64::from_le_bytes((x.buffer[0..8]).try_into().unwrap()))
                            .collect::<Vec<u64>>()
                    };

                    let mut v_p = Vec::<TPayload>::new();

                    for f_idx in (0..n_features).rev() {
                        let t = (0..n_rows)
                            .map(|x| x)
                            .collect::<Vec<_>>()
                            .iter()
                            .map(|i| {
                                let z: u64 = permuted_pdata[f_idx][*i] ^ r_i[*i];
                                ByteBuffer {
                                    buffer: z.to_le_bytes().to_vec(),
                                }
                            })
                            .collect::<Vec<_>>();
                        v_p.push(t);
                    }

                    v_p.into_iter().flatten().collect::<Vec<_>>()
                };

                {
                    let g_zi = {
                        let t = z_i
                            .iter()
                            .map(|x| x * RISTRETTO_BASEPOINT_TABLE)
                            .collect::<Vec<_>>();
                        self.ec_cipher.to_bytes(&t)
                    };
                    d_flat.extend(g_zi);
                }

                let metadata = vec![
                    ByteBuffer {
                        buffer: (n_rows as u64).to_le_bytes().to_vec(),
                    },
                    ByteBuffer {
                        buffer: (n_features as u64).to_le_bytes().to_vec(),
                    },
                ];
                d_flat.extend(metadata);

                let e_d_flat = {
                    let fernet = Fernet::new(&aes_key.clone()).unwrap();
                    d_flat
                        .par_drain(..)
                        .map(|x| {
                            let ctxt = fernet.encrypt(x.buffer.as_slice());
                            ByteBuffer {
                                buffer: ctxt.as_bytes().to_vec(),
                            }
                        })
                        .collect::<Vec<_>>()
                };
                t.qps("e_d_flat", e_d_flat.len());

                Ok(e_d_flat)
            }
            _ => {
                error!("Unable to encrypt data");
                Err(ProtocolError::ErrorEncryption(
                    "unable to encrypt data".to_string(),
                ))
            }
        }
    }
}
