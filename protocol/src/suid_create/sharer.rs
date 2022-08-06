//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate csv;

use std::sync::Arc;
use std::sync::RwLock;

use common::permutations::gen_permute_pattern;
use common::permutations::permute;
use common::permutations::undo_permute;
use crypto::eccipher::gen_scalar;
use crypto::eccipher::ECCipher;
use crypto::eccipher::ECRistrettoParallel;
use crypto::prelude::*;
use itertools::Itertools;

use super::compute_prefix_sum;
use super::elgamal_encrypt;
use super::gen_elgamal_keypair;
use super::load_data;
use super::serialize_helper;
use super::unflatten_vec;
use super::writer_helper;
use super::ProtocolError;
use crate::suid_create::traits::SUIDCreateSharerProtocol;

pub struct SUIDCreateSharer {
    private_key: Scalar,
    keypair_reuse: (Scalar, TPoint),
    ec_cipher: ECRistrettoParallel,
    pub_key_m: Arc<RwLock<TPoint>>,
    plaintext: Arc<RwLock<Vec<Vec<Vec<String>>>>>,
    permutation: Arc<RwLock<Vec<usize>>>,
    num_entries: Arc<RwLock<Vec<usize>>>,
    suids_for_parties: Arc<RwLock<Vec<(TPayload, TPayload)>>>,
}

impl SUIDCreateSharer {
    pub fn new() -> SUIDCreateSharer {
        SUIDCreateSharer {
            private_key: gen_scalar(),
            keypair_reuse: gen_elgamal_keypair(),
            ec_cipher: ECRistrettoParallel::default(),
            pub_key_m: Arc::new(RwLock::default()),
            plaintext: Arc::new(RwLock::default()),
            permutation: Arc::new(RwLock::default()),
            num_entries: Arc::new(RwLock::default()),
            suids_for_parties: Arc::new(RwLock::default()),
        }
    }

    // TODO: Fix header processing
    pub fn load_encrypt_data(
        &self,
        paths: Vec<&str>,
        input_with_headers: bool,
    ) -> Result<Vec<(Vec<Vec<TPoint>>, Vec<Vec<TPoint>>)>, ProtocolError> {
        match (
            self.plaintext.clone().write(),
            self.pub_key_m.clone().read(),
        ) {
            (Ok(mut p_data), Ok(p_key)) => {
                p_data.clear();

                let mut c_data = Vec::<(Vec<Vec<TPoint>>, Vec<Vec<TPoint>>)>::new();

                for path in paths.iter() {
                    // Read data
                    let d = load_data(path, input_with_headers);

                    // Hash and ElGamal encrypt
                    let (c1, c2) = {
                        // Record offsets to unflatten
                        let offsets = {
                            let l = d.iter().map(|v| v.len()).collect::<Vec<usize>>();
                            compute_prefix_sum(&l)
                        };

                        // Flatten and Encrypt
                        let (c1_flat, c2_flat) = {
                            let x = d.clone().into_iter().flatten().collect::<Vec<_>>();

                            elgamal_encrypt(self.ec_cipher.hash(x.as_slice()), &p_key)
                        };

                        // Unflatten
                        (
                            unflatten_vec(&c1_flat, &offsets),
                            unflatten_vec(&c2_flat, &offsets),
                        )
                    };

                    p_data.push(d);
                    c_data.push((c1, c2));
                }
                Ok(c_data)
            }
            _ => {
                error!("Unable to load data");
                Err(ProtocolError::ErrorIO("unable to load data".to_string()))
            }
        }
    }

    pub fn deserialize_elgamal(
        &self,
        mut data: TPayload,
        psum: Vec<usize>,
    ) -> (Vec<Vec<TPoint>>, Vec<Vec<TPoint>>) {
        let data_len = data.len();
        assert_eq!((data_len % 2), 0);

        let d_m_flat_c2 = self
            .ec_cipher
            .to_points(&(data.drain((data_len / 2)..).collect::<Vec<_>>()));
        let d_m_flat_c1 = self
            .ec_cipher
            .to_points(&(data.drain(..).collect::<Vec<_>>()));

        assert_eq!(d_m_flat_c1.len(), d_m_flat_c2.len());

        (
            unflatten_vec(&d_m_flat_c1, &psum),
            unflatten_vec(&d_m_flat_c2, &psum),
        )
    }
}

impl Default for SUIDCreateSharer {
    fn default() -> Self {
        Self::new()
    }
}

impl SUIDCreateSharerProtocol for SUIDCreateSharer {
    fn get_public_key_reuse(&self) -> TPayload {
        let x = vec![self.keypair_reuse.1];
        self.ec_cipher.to_bytes(&x)
    }

    fn set_public_key_m(&self, p_key: TPayload) -> Result<(), ProtocolError> {
        match self.pub_key_m.clone().write() {
            Ok(mut pub_key_m) => {
                assert_eq!(p_key.len(), 1);
                *pub_key_m = (self.ec_cipher.to_points(&p_key))[0];
                Ok(())
            }
            _ => Err(ProtocolError::ErrorDataWrite(
                "unable to write public key".to_string(),
            )),
        }
    }

    // ElGamal Exponentiate
    fn elgamal_exponentiate(
        &self,
        data: Vec<(Vec<Vec<TPoint>>, Vec<Vec<TPoint>>)>,
    ) -> Result<Vec<(Vec<Vec<TPoint>>, Vec<Vec<TPoint>>)>, ProtocolError> {
        let mut data_r = Vec::<(Vec<Vec<TPoint>>, Vec<Vec<TPoint>>)>::new();

        for (c1, c2) in data.iter() {
            // Assume both ragged arrays have the same shape
            let offsets = {
                let l = c1.iter().map(|v| v.len()).collect::<Vec<usize>>();
                compute_prefix_sum(&l)
            };

            // El Gamal exponentiate - do it on the flattened array
            // for more parallelism
            let (c1_flat_r, c2_flat_r) = {
                let c1_flat = c1.iter().flatten().collect::<Vec<_>>();
                let c2_flat = c2.iter().flatten().collect::<Vec<_>>();

                (
                    c1_flat
                        .iter()
                        .map(|&x| x * self.private_key)
                        .collect::<Vec<_>>(),
                    c2_flat
                        .iter()
                        .map(|&x| x * self.private_key)
                        .collect::<Vec<_>>(),
                )
            };

            // Unflatten the ciphertext
            data_r.push((
                unflatten_vec(&c1_flat_r, &offsets),
                unflatten_vec(&c2_flat_r, &offsets),
            ));
        }

        Ok(data_r)
    }

    fn shuffle_flatten(
        &self,
        mut data: Vec<(Vec<Vec<TPoint>>, Vec<Vec<TPoint>>)>,
    ) -> Result<TPayload, ProtocolError> {
        match (
            self.permutation.clone().write(),
            self.num_entries.clone().write(),
        ) {
            (Ok(mut permutation), Ok(mut num_entries)) => {
                num_entries.clear();
                num_entries.extend(data.iter().map(|(x, _)| x.len()).collect::<Vec<_>>());

                let total_entries = num_entries.iter().sum();

                permutation.clear();
                permutation.extend(gen_permute_pattern(total_entries));

                let (c1_buf, c2_buf, offset) = {
                    let mut c1 = Vec::<Vec<TPoint>>::new();
                    for x in data.iter_mut() {
                        c1.append(&mut x.0);
                    }

                    let mut c2 = Vec::<Vec<TPoint>>::new();
                    for x in data.iter_mut() {
                        c2.append(&mut x.1);
                    }

                    assert_eq!(c1.len(), c2.len());
                    assert_eq!(c1.len(), permutation.len());

                    // Free up memory
                    data.clear();
                    data.shrink_to_fit();

                    // Global permute
                    permute(permutation.as_slice(), &mut c1);
                    permute(permutation.as_slice(), &mut c2);

                    // Flatten and calculate offsets for unflattening
                    let (c1_f, offset_c1, _) = serialize_helper(c1);
                    let (c2_f, offset_c2, _) = serialize_helper(c2);

                    assert_eq!(c1_f.len(), c2_f.len());
                    assert_eq!(offset_c1.len(), offset_c2.len());

                    // Check if the vectors are identical
                    assert_eq!(
                        offset_c1
                            .iter()
                            .zip_eq(offset_c2.iter())
                            .filter(|&(a, b)| a != b)
                            .count(),
                        0
                    );

                    (
                        self.ec_cipher.to_bytes(&c1_f),
                        self.ec_cipher.to_bytes(&c2_f),
                        offset_c1,
                    )
                };

                let offset_len = offset.len();

                let mut buf = c1_buf;
                buf.extend(c2_buf);

                let data_len = buf.len();

                // Push only one offset for two data since both should
                // have same shape
                buf.extend(offset);

                buf.push(ByteBuffer {
                    buffer: (data_len as u64).to_le_bytes().to_vec(),
                });
                buf.push(ByteBuffer {
                    buffer: (offset_len as u64).to_le_bytes().to_vec(),
                });

                Ok(buf)
            }
            _ => {
                error!("Unable to shuffle data");
                Err(ProtocolError::ErrorShuffle(
                    "unable to shuffle data".to_string(),
                ))
            }
        }
    }

    fn unshuffle_suids(
        &self,
        mut data: TPayload,
    ) -> Result<Vec<(TPayload, TPayload)>, ProtocolError> {
        // Since ElGamal cyphertexts have two parts, this should be even numbered
        assert_eq!(data.len() % 2, 0);
        let data_len = data.len();

        match (
            self.permutation.clone().read(),
            self.num_entries.clone().read(),
        ) {
            (Ok(permutation), Ok(num_entries)) => {
                let (c1, c2) = {
                    let mut c2_buf = data.drain((data_len / 2)..).collect::<Vec<_>>();
                    let mut c1_buf = data;

                    undo_permute(permutation.as_slice(), &mut c1_buf);
                    undo_permute(permutation.as_slice(), &mut c2_buf);

                    let offsets = compute_prefix_sum(&num_entries);

                    (
                        unflatten_vec(&c1_buf, &offsets),
                        unflatten_vec(&c2_buf, &offsets),
                    )
                };

                assert_eq!(c1.len(), c2.len());

                let x = c1
                    .iter()
                    .zip_eq(c2.iter())
                    .map(|(x, y)| (x.clone(), y.clone()))
                    .collect::<Vec<_>>();
                Ok(x)
            }
            _ => {
                error!("Unable to un-shuffle data");
                Err(ProtocolError::ErrorShuffle(
                    "unable to un-shuffle data".to_string(),
                ))
            }
        }
    }

    fn set_suids_for_parties(
        &self,
        mut data: Vec<(TPayload, TPayload)>,
    ) -> Result<(), ProtocolError> {
        match self.suids_for_parties.write() {
            Ok(mut suids_for_parties) => {
                suids_for_parties.clear();
                suids_for_parties.extend(data.drain(..));
                Ok(())
            }
            _ => {
                error!("Unable to un-shuffle data");
                Err(ProtocolError::ErrorDataWrite(
                    "Unable to write SUIDs".to_string(),
                ))
            }
        }
    }

    fn print_suids_data(&self) {
        match (
            self.plaintext.clone().read(),
            self.suids_for_parties.clone().read(),
        ) {
            (Ok(data), Ok(suids_for_parties)) => {
                for (suids_for_party, d) in suids_for_parties.iter().zip_eq(data.iter()) {
                    println!(
                        "=========================================================================================="
                    );
                    let s = suids_for_party
                        .0
                        .iter()
                        .zip_eq(suids_for_party.1.iter())
                        .map(|(x1, x2)| (x1.clone().to_string(), x2.clone().to_string()))
                        .collect::<Vec<_>>();
                    writer_helper(&s, d, None);
                }
            }
            _ => panic!("Cannot print SUIDs"),
        }
    }

    fn save_suids_data(&self, path: &str) -> Result<(), ProtocolError> {
        match (
            self.plaintext.clone().read(),
            self.suids_for_parties.clone().read(),
        ) {
            (Ok(data), Ok(suids_for_parties)) => {
                for (idx, suids_for_party) in suids_for_parties.iter().enumerate() {
                    let s = suids_for_party
                        .0
                        .iter()
                        .zip_eq(suids_for_party.1.iter())
                        .map(|(x1, x2)| (x1.clone().to_string(), x2.clone().to_string()))
                        .collect::<Vec<_>>();
                    let fname = format!("{}_{}.csv", path, idx);
                    writer_helper(&s, &data[idx], Some(fname));
                }
                Ok(())
            }
            _ => {
                error!("Unable to write SUIDs to file");
                Err(ProtocolError::ErrorIO(
                    "Unable to write SUIDsl to file".to_string(),
                ))
            }
        }
    }
}
