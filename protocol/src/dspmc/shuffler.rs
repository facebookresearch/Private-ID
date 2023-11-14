//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate csv;

use std::convert::TryInto;
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
use rand::Rng;

use super::serialize_helper;
use super::ProtocolError;
use crate::dspmc::traits::ShufflerDspmcProtocol;
use crate::shared::TFeatures;

pub struct ShufflerDspmc {
    company_public_key: Arc<RwLock<(TPoint, TPoint)>>,
    helper_public_key: Arc<RwLock<TPoint>>,
    ec_cipher: ECRistrettoParallel,
    p_cs: Arc<RwLock<Vec<usize>>>,
    v_cs: Arc<RwLock<Vec<u64>>>,
    perms: Arc<RwLock<(Vec<usize>, Vec<usize>)>>, // (p_sc, p_sd)
    blinds: Arc<RwLock<(Vec<u64>, Vec<u64>)>>,    // (v_sc, v_sd)
    xor_shares_v1: Arc<RwLock<TFeatures>>,        // v'
    ct1_dprime: Arc<RwLock<Vec<Vec<TPoint>>>>,
    ct2_dprime: Arc<RwLock<Vec<Vec<TPoint>>>>,
}

impl ShufflerDspmc {
    pub fn new() -> ShufflerDspmc {
        ShufflerDspmc {
            company_public_key: Arc::new(RwLock::default()),
            helper_public_key: Arc::new(RwLock::default()),
            ec_cipher: ECRistrettoParallel::default(),
            p_cs: Arc::new(RwLock::default()),
            v_cs: Arc::new(RwLock::default()),
            perms: Arc::new(RwLock::default()),
            blinds: Arc::new(RwLock::default()),
            xor_shares_v1: Arc::new(RwLock::default()),
            ct1_dprime: Arc::new(RwLock::default()),
            ct2_dprime: Arc::new(RwLock::default()),
        }
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

impl Default for ShufflerDspmc {
    fn default() -> Self {
        Self::new()
    }
}

impl ShufflerDspmcProtocol for ShufflerDspmc {
    fn set_p_cs_v_cs(
        &self,
        v_cs_bytes: TPayload,
        p_cs_bytes: TPayload,
    ) -> Result<(), ProtocolError> {
        match (self.p_cs.clone().write(), self.v_cs.clone().write()) {
            (Ok(mut p_cs), Ok(mut v_cs)) => {
                let t = timer::Timer::new_silent("set p_cs, v_cs");
                *v_cs = v_cs_bytes
                    .iter()
                    .map(|x| u64::from_le_bytes((x.buffer[0..8]).try_into().unwrap()))
                    .collect::<Vec<_>>();

                *p_cs = p_cs_bytes
                    .iter()
                    .map(|x| u64::from_le_bytes((x.buffer[0..8]).try_into().unwrap()) as usize)
                    .collect::<Vec<_>>();

                t.qps("deserialize_exp", p_cs_bytes.len());
                Ok(())
            }
            _ => {
                error!("Cannot load p_cs, v_cs");
                Err(ProtocolError::ErrorDeserialization(
                    "cannot load p_cs, v_cs".to_string(),
                ))
            }
        }
    }

    fn gen_permutations(&self) -> Result<(TPayload, TPayload), ProtocolError> {
        match (
            self.p_cs.clone().read(),
            self.perms.clone().write(),
            self.blinds.clone().write(),
        ) {
            (Ok(p_cs), Ok(mut perms), Ok(mut blinds)) => {
                let mut rng = rand::thread_rng();
                let range = Uniform::new(0_u64, u64::MAX);

                let data_len = p_cs.len();
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

                let mut p_sc_v_sc = perms
                    .0
                    .iter()
                    .map(|e| ByteBuffer {
                        buffer: (*e).to_le_bytes().to_vec(),
                    })
                    .collect::<Vec<ByteBuffer>>();
                let v_sc_bytes = blinds
                    .0
                    .iter()
                    .map(|e| ByteBuffer {
                        buffer: (*e).to_le_bytes().to_vec(),
                    })
                    .collect::<Vec<ByteBuffer>>();
                p_sc_v_sc.extend(v_sc_bytes);

                let mut p_sd_v_sd = perms
                    .1
                    .iter()
                    .map(|e| ByteBuffer {
                        buffer: (*e as u64).to_le_bytes().to_vec(),
                    })
                    .collect::<Vec<ByteBuffer>>();
                let v_sd_bytes = blinds
                    .1
                    .iter()
                    .map(|e| ByteBuffer {
                        buffer: (*e as u64).to_le_bytes().to_vec(),
                    })
                    .collect::<Vec<ByteBuffer>>();
                p_sd_v_sd.extend(v_sd_bytes);
                p_sd_v_sd.push(ByteBuffer {
                    buffer: (data_len as u64).to_le_bytes().to_vec(),
                });

                Ok((p_sc_v_sc, p_sd_v_sd))
            }
            _ => {
                error!("Unable to generate p_sc, v_sc, p_sd, v_sd:");
                Err(ProtocolError::ErrorEncryption(
                    "cannot generate p_sc, v_sc, p_sd, v_sd".to_string(),
                ))
            }
        }
    }

    fn compute_v2prime_ct1ct2(
        &self,
        mut u2: TFeatures,
        ct1_prime_bytes: TPayload,
        ct2_prime_bytes: TPayload,
        psum: Vec<usize>,
    ) -> Result<TPayload, ProtocolError> {
        match (
            self.p_cs.clone().read(),
            self.v_cs.clone().read(),
            self.perms.clone().read(),
            self.blinds.clone().read(),
            self.company_public_key.clone().read(),
            self.helper_public_key.clone().read(),
            self.xor_shares_v1.clone().write(),
            self.ct1_dprime.clone().write(),
            self.ct2_dprime.clone().write(),
        ) {
            (
                Ok(p_cs),
                Ok(v_cs),
                Ok(perms),
                Ok(blinds),
                Ok(company_pk),
                Ok(helper_pk),
                Ok(mut v_p),
                Ok(mut ct1_dprime),
                Ok(mut ct2_dprime),
            ) => {
                // This is an array of exclusive-inclusive prefix sum - hence
                // number of keys is one less than length
                let num_keys = psum.len() - 1;

                // Unflatten and convert to points
                let mut ct1_prime = {
                    let t = self.ec_cipher.to_points(&ct1_prime_bytes);

                    psum.get(0..num_keys)
                        .unwrap()
                        .iter()
                        .zip_eq(psum.get(1..num_keys + 1).unwrap().iter())
                        .map(|(&x1, &x2)| t.get(x1..x2).unwrap().to_vec())
                        .collect::<Vec<Vec<_>>>()
                };
                let mut ct2_prime = {
                    let t = self.ec_cipher.to_points(&ct2_prime_bytes);

                    psum.get(0..num_keys)
                        .unwrap()
                        .iter()
                        .zip_eq(psum.get(1..num_keys + 1).unwrap().iter())
                        .map(|(&x1, &x2)| t.get(x1..x2).unwrap().to_vec())
                        .collect::<Vec<Vec<_>>>()
                };

                let n_rows = u2[0].len();
                let n_features = u2.len();

                // Compute p_sd(p_sc(p_cs( u2 ) xor v_cs) xor v_sc) xor v_sd
                (*v_p).clear();
                for f_idx in (0..n_features).rev() {
                    permute(p_cs.as_slice(), &mut u2[f_idx]); // p_cs
                    let mut x_2 = u2[f_idx]
                        .iter()
                        .zip_eq(v_cs.iter())
                        .map(|(s, v_cs)| *s ^ *v_cs)
                        .collect::<Vec<_>>();

                    permute(perms.0.as_slice(), &mut x_2); // p_sc
                    let mut t_1 = x_2
                        .iter()
                        .zip_eq(blinds.0.iter())
                        .map(|(s, v_sc)| *s ^ *v_sc)
                        .collect::<Vec<_>>();

                    permute(perms.1.as_slice(), &mut t_1); // p_sd
                    (*v_p).push(
                        t_1.iter()
                            .zip_eq(blinds.1.iter())
                            .map(|(s, v_sd)| *s ^ *v_sd)
                            .collect::<Vec<_>>(),
                    );
                }

                // Re-randomize ct1'' and ct2'' and flatten
                let (mut ct1_dprime_flat, ct2_dprime_flat, ct_offset) = {
                    let r_i = (0..n_rows)
                        .collect::<Vec<_>>()
                        .iter()
                        .map(|_| gen_scalar())
                        .collect::<Vec<_>>();
                    // company_pk^r
                    // with EC: company_pk * r
                    let pkc_r = r_i.iter().map(|x| *x * (company_pk.0)).collect::<Vec<_>>();
                    // helper_pk^r
                    // with EC: helper_pk * r
                    let pkd_r = r_i.iter().map(|x| *x * (*helper_pk)).collect::<Vec<_>>();

                    permute(perms.0.as_slice(), &mut ct1_prime); // p_sc
                    permute(perms.0.as_slice(), &mut ct2_prime); // p_sc
                    permute(perms.1.as_slice(), &mut ct1_prime); // p_sd
                    permute(perms.1.as_slice(), &mut ct2_prime); // p_sd

                    // ct1' = ct1'' * company_pk^r
                    // with EC: ct1' = ct1'' + company_pk*r
                    *ct1_dprime = ct1_prime
                        .iter()
                        .zip_eq(pkc_r.iter())
                        .map(|(s, t)| (*s).iter().map(|si| *si + *t).collect::<Vec<_>>())
                        .collect::<Vec<_>>();
                    // ct2' = ct2'' * helper_pk^r
                    // with EC: ct2' = ct2'' + helper_pk*r
                    *ct2_dprime = ct2_prime
                        .iter()
                        .zip_eq(pkd_r.iter())
                        .map(|(s, t)| (*s).iter().map(|si| *si + *t).collect::<Vec<_>>())
                        .collect::<Vec<_>>();
                    let (ct1_dprime_flat, _ct1_offset) = {
                        let (d_flat, mut offset, metadata) = serialize_helper(ct1_dprime.clone());
                        offset.extend(metadata);

                        (self.ec_cipher.to_bytes(d_flat.as_slice()), offset)
                    };
                    let (ctd2_dprime_flat, ct2_offset) = {
                        let (d_flat, mut offset, metadata) = serialize_helper(ct2_dprime.clone());
                        offset.extend(metadata);

                        (self.ec_cipher.to_bytes(d_flat.as_slice()), offset)
                    };
                    (ct1_dprime_flat, ctd2_dprime_flat, ct2_offset)
                };
                ct1_dprime_flat.extend(ct2_dprime_flat);
                ct1_dprime_flat.extend(ct_offset);

                // ct1_dprime_flat, ct2_dprime_flat, ct_offset
                Ok(ct1_dprime_flat)
            }
            _ => {
                error!("Unable to flatten ct1'' and ct2'':");
                Err(ProtocolError::ErrorEncryption(
                    "cannot flatten ct1'' and ct2''".to_string(),
                ))
            }
        }
    }

    fn get_blinded_vprime(&self) -> Result<TPayload, ProtocolError> {
        match (
            self.company_public_key.clone().read(),
            self.xor_shares_v1.clone().read(),
        ) {
            (Ok(company_pk), Ok(v_p)) => {
                let t = timer::Timer::new_silent("get_blinded_vprime");

                let n_rows = v_p[0].len();
                let n_features = v_p.len();

                let z_i = (0..n_rows).map(|_| gen_scalar()).collect::<Vec<_>>();

                let mut d_flat = {
                    let r_i = {
                        let y_zi = {
                            let t = z_i.iter().map(|x| *x * company_pk.0).collect::<Vec<_>>();
                            self.ec_cipher.to_bytes(&t)
                        };
                        y_zi.iter()
                            .map(|x| u64::from_le_bytes((x.buffer[0..8]).try_into().unwrap()))
                            .collect::<Vec<u64>>()
                    };

                    let mut blinded_vprime = Vec::<TPayload>::new();

                    for f_idx in (0..n_features).rev() {
                        let t = (0..n_rows)
                            .collect::<Vec<_>>()
                            .iter()
                            .map(|i| {
                                let z: u64 = v_p[f_idx][*i] ^ r_i[*i];
                                ByteBuffer {
                                    buffer: z.to_le_bytes().to_vec(),
                                }
                            })
                            .collect::<Vec<_>>();
                        blinded_vprime.push(t);
                    }

                    blinded_vprime.into_iter().flatten().collect::<Vec<_>>()
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

                t.qps("get_blinded_vprime", d_flat.len());
                Ok(d_flat)
            }
            _ => {
                error!("Unable to serialize v1':");
                Err(ProtocolError::ErrorEncryption(
                    "cannot serialize v1'".to_string(),
                ))
            }
        }
    }
}
