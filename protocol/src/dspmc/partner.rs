//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate csv;

use std::convert::TryInto;
use std::sync::Arc;
use std::sync::RwLock;

use common::timer;
use crypto::eccipher::gen_scalar;
use crypto::eccipher::ECCipher;
use crypto::eccipher::ECRistrettoParallel;
use crypto::prelude::*;
use itertools::Itertools;
use rand::prelude::*;

use super::load_data_features;
use super::load_data_keys;
use super::serialize_helper;
use super::ProtocolError;
use crate::dspmc::traits::PartnerDspmcProtocol;
use crate::shared::TFeatures;

pub struct PartnerDspmc {
    company_public_key: Arc<RwLock<(TPoint, TPoint)>>,
    helper_public_key: Arc<RwLock<TPoint>>,
    ec_cipher: ECRistrettoParallel,
    plaintext_keys: Arc<RwLock<Vec<Vec<String>>>>,
    plaintext_features: Arc<RwLock<TFeatures>>,
}

impl PartnerDspmc {
    pub fn new() -> PartnerDspmc {
        PartnerDspmc {
            company_public_key: Arc::new(RwLock::default()),
            helper_public_key: Arc::new(RwLock::default()),
            ec_cipher: ECRistrettoParallel::default(),
            plaintext_keys: Arc::new(RwLock::default()),
            plaintext_features: Arc::new(RwLock::default()),
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

    pub fn set_helper_public_key(&self, helper_public_key: TPayload) -> Result<(), ProtocolError> {
        let pk = self.ec_cipher.to_points(&helper_public_key);
        // Check that one key is sent
        assert_eq!(pk.len(), 1);
        match self.helper_public_key.clone().write() {
            Ok(mut helper_pk) => {
                *helper_pk = pk[0];
                assert_eq!((*helper_pk).is_identity(), false);
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

impl Default for PartnerDspmc {
    fn default() -> Self {
        Self::new()
    }
}

impl PartnerDspmcProtocol for PartnerDspmc {
    fn get_encrypted_keys(&self) -> Result<TPayload, ProtocolError> {
        match (
            self.plaintext_keys.clone().read(),
            self.company_public_key.clone().read(),
            self.helper_public_key.clone().read(),
        ) {
            (Ok(pdata), Ok(company_pk), Ok(helper_pk)) => {
                let t = timer::Timer::new_silent("partner data");

                // let n_rows = pdata.len();

                // ct2 = helper_pk^r * H(P_i)
                // with EC: helper_pk*r + H(P_i)
                let (mut d_flat, ct1_flat, offset) = {
                    let (d_flat, mut offset, metadata) = serialize_helper(pdata.clone());
                    offset.extend(metadata);
                    let hash_p = self.ec_cipher.hash(d_flat.as_slice());

                    // ct1 = company_pk^r
                    // with EC: company_pk * r
                    let (ct1, pkd_r) = {
                        let r_i = (0..d_flat.len())
                            .collect::<Vec<_>>()
                            .iter()
                            .map(|_| gen_scalar())
                            .collect::<Vec<_>>();
                        let ct1_bytes = {
                            let t1 = r_i.iter().map(|x| *x * company_pk.0).collect::<Vec<_>>();
                            self.ec_cipher.to_bytes(&t1)
                        };
                        let pkd_r = r_i.iter().map(|x| *x * (*helper_pk)).collect::<Vec<_>>();
                        (ct1_bytes, pkd_r)
                    };

                    let ct2 = pkd_r
                        .iter()
                        .zip_eq(hash_p.iter())
                        .map(|(s, t)| *s + *t)
                        .collect::<Vec<_>>();

                    (self.ec_cipher.to_bytes(ct2.as_slice()), ct1, offset)
                };

                // Append ct1
                d_flat.extend(ct1_flat);
                // Append offsets array
                d_flat.extend(offset);

                t.qps("encryption", d_flat.len());

                // d_flat = ct2, ct1, offset
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
            self.helper_public_key.clone().read(),
        ) {
            (Ok(pdata), Ok(helper_pk)) => {
                let t = timer::Timer::new_silent("get_features_xor_shares");
                let n_rows = pdata[0].len();
                let n_features = pdata.len();

                // ct3 = scalar * g
                // PRG seed = scalar * PK_helper
                let (seed, ct3) = {
                    let x = gen_scalar();
                    let ct3 = self.ec_cipher.to_bytes(&[&x * RISTRETTO_BASEPOINT_TABLE]);
                    let seed: [u8; 32] = {
                        let t = self.ec_cipher.to_bytes(&[x * (*helper_pk)]);
                        t[0].buffer.as_slice().try_into().expect("incorrect length")
                    };
                    (seed, ct3)
                };

                let mut rng = StdRng::from_seed(seed);
                let mut v2 = TFeatures::new();
                for _ in 0..n_features {
                    let t = (0..n_rows)
                        .collect::<Vec<_>>()
                        .iter()
                        .map(|_| rng.gen::<u64>())
                        .collect::<Vec<_>>();
                    v2.push(t);
                }

                let mut d_flat = {
                    let mut v_p = Vec::<TPayload>::new();

                    for f_idx in (0..n_features).rev() {
                        let t = (0..n_rows)
                            .map(|x| x)
                            .collect::<Vec<_>>()
                            .iter()
                            .map(|i| {
                                let z: u64 = pdata[f_idx][*i] ^ v2[f_idx][*i];
                                ByteBuffer {
                                    buffer: z.to_le_bytes().to_vec(),
                                }
                            })
                            .collect::<Vec<_>>();
                        v_p.push(t);
                    }

                    v_p.into_iter().flatten().collect::<Vec<_>>()
                };

                let metadata = vec![
                    ByteBuffer {
                        buffer: (n_rows as u64).to_le_bytes().to_vec(),
                    },
                    ByteBuffer {
                        buffer: (n_features as u64).to_le_bytes().to_vec(),
                    },
                ];
                d_flat.extend(metadata);
                d_flat.extend(ct3);

                t.qps("d_flat", d_flat.len());

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
}
