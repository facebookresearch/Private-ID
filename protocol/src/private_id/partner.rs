//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::sync::RwLock;

use common::files;
use common::permutations::gen_permute_pattern;
use common::permutations::permute;
use common::permutations::undo_permute;
use common::timer;
use crypto::eccipher::gen_scalar;
use crypto::eccipher::ECCipher;
#[cfg(not(target_arch = "wasm32"))]
use crypto::eccipher::ECRistrettoParallel as ECRistretto;
#[cfg(target_arch = "wasm32")]
use crypto::eccipher::ECRistrettoSequential as ECRistretto;
use crypto::prelude::*;
use zeroize::Zeroizing;

use super::fill_permute;
use super::ProtocolError;
use crate::fileio::load_data;
use crate::fileio::KeyedCSV;
use crate::private_id::traits::PartnerPrivateIdProtocol;

pub struct PartnerPrivateId {
    private_keys: Zeroizing<(Scalar, Scalar)>,
    ec_cipher: ECRistretto,
    plain_data: Arc<RwLock<KeyedCSV>>,
    permutation: Arc<RwLock<Vec<usize>>>,
    id_map: Arc<RwLock<Vec<Vec<String>>>>,
}

impl PartnerPrivateId {
    pub fn new() -> PartnerPrivateId {
        PartnerPrivateId {
            private_keys: Zeroizing::new((gen_scalar(), gen_scalar())),
            ec_cipher: ECRistretto::default(),
            plain_data: Arc::new(RwLock::default()),
            permutation: Arc::new(RwLock::default()),
            id_map: Arc::new(RwLock::default()),
        }
    }

    pub fn load_data(&self, path: &str, input_with_headers: bool) -> Result<(), ProtocolError> {
        load_data(self.plain_data.clone(), path, input_with_headers);
        Ok(())
    }

    pub fn get_size(&self) -> usize {
        self.plain_data.clone().read().unwrap().records.len()
    }
}

impl Default for PartnerPrivateId {
    fn default() -> Self {
        Self::new()
    }
}

impl PartnerPrivateIdProtocol for PartnerPrivateId {
    fn gen_permute_pattern(&self) -> Result<(), ProtocolError> {
        fill_permute(
            self.permutation.clone(),
            (*self.plain_data.clone().read().unwrap()).records.len(),
        );
        Ok(())
    }

    fn permute_hash_to_bytes(&self) -> Result<TPayload, ProtocolError> {
        match self.plain_data.clone().read() {
            Ok(pdata) => {
                let t = timer::Timer::new_silent("u_partner");
                let plain_keys = pdata.get_plain_keys();
                let mut u = self
                    .ec_cipher
                    .hash_encrypt_to_bytes(plain_keys.as_slice(), &self.private_keys.0);
                t.qps("encryption", u.len());

                self.permutation
                    .clone()
                    .read()
                    .map(|pm| {
                        permute(&pm, &mut u);
                        t.qps("permutation", pm.len());
                        u
                    })
                    .map_err(|err| {
                        error!("error in permute {}", err);
                        ProtocolError::ErrorEncryption("unable to encrypt data".to_string())
                    })
            }

            Err(e) => {
                error!("Unable to encrypt plain_data: {}", e);
                Err(ProtocolError::ErrorEncryption(
                    "unable to encrypt data".to_string(),
                ))
            }
        }
    }

    //TODO: return result
    fn encrypt_permute(&self, company: TPayload) -> (TPayload, TPayload) {
        let t = timer::Timer::new_silent("encrypt_permute_company");
        let mut encrypt_company = self
            .ec_cipher
            .to_points_encrypt(&company, &self.private_keys.0);
        t.qps("encrypt_company", encrypt_company.len());
        let v_company = self
            .ec_cipher
            .encrypt_to_bytes(&encrypt_company, &self.private_keys.1);
        t.qps("v_company", v_company.len());
        {
            let rand_permutation = gen_permute_pattern(encrypt_company.len());
            // TODO: BUG why is this undo_permute
            // undo_permute(&rand_permutation, &mut e_company_dsrlz);
            permute(&rand_permutation, &mut encrypt_company);
        }
        (self.ec_cipher.to_bytes(&encrypt_company), v_company)
    }

    fn encrypt(&self, partner: TPayload) -> Result<TPayload, ProtocolError> {
        let ep = self
            .ec_cipher
            .to_points_encrypt(&partner, &self.private_keys.1);
        Ok(self.ec_cipher.to_bytes(&ep))
    }

    fn create_id_map(&self, partner: TPayload, company: TPayload, na_val: Option<&str>) {
        match (
            self.permutation.clone().read(),
            self.plain_data.clone().read(),
            self.id_map.clone().write(),
        ) {
            (Ok(pm), Ok(plain_data), Ok(mut id_map)) => {
                let mut partner_encrypt = self
                    .ec_cipher
                    .to_points_encrypt(&partner, &self.private_keys.1);
                undo_permute(&pm, &mut partner_encrypt);

                for (k, v) in self
                    .ec_cipher
                    .to_bytes(&partner_encrypt)
                    .iter()
                    .zip(plain_data.get_plain_keys().iter())
                {
                    let record = plain_data.get_record_with_keys(k.to_string(), v);
                    id_map.push(record);
                }

                for k in self
                    .ec_cipher
                    .to_bytes(
                        &self
                            .ec_cipher
                            .to_points_encrypt(&company, &self.private_keys.1),
                    )
                    .iter()
                {
                    let record = plain_data.get_empty_record_with_key(
                        k.to_string(),
                        na_val.map(String::from).as_ref(),
                    );
                    id_map.push(record);
                }

                if !plain_data.headers.is_empty() {
                    id_map.insert(0, plain_data.headers.clone());
                }
            }
            _ => panic!("Cannot make v"),
        }
    }

    fn print_id_map(&self, limit: usize, input_with_headers: bool, use_row_numbers: bool) {
        let _ = self
            .id_map
            .clone()
            .read()
            .map(|data| {
                files::write_vec_to_stdout(&data, limit, input_with_headers, use_row_numbers)
                    .unwrap()
            })
            .map_err(|_| {});
    }

    fn save_id_map(
        &self,
        path: &str,
        input_with_headers: bool,
        use_row_numbers: bool,
    ) -> Result<(), ProtocolError> {
        self.id_map
            .clone()
            .write()
            .map(|mut data| {
                files::write_vec_to_csv(&mut data, path, input_with_headers, use_row_numbers)
                    .unwrap();
            })
            .map_err(|_| ProtocolError::ErrorIO("Unable to write partner view to file".to_string()))
    }

    fn stringify_id_map(&self, use_row_numbers: bool) -> String {
        let id_map_str = self
            .id_map
            .clone()
            .read()
            .map(|data| files::sort_stringify_id_map(&data, use_row_numbers))
            .map_err(|_| {});
        id_map_str.unwrap()
    }

    fn get_id_map_size(&self) -> usize {
        self.id_map.read().unwrap().len()
    }
}
