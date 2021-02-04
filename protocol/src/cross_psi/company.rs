//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate csv;

use std::sync::{Arc, RwLock};

use crypto::{
    eccipher::{gen_scalar, ECCipher},
    prelude::*,
};
#[cfg(target_arch = "wasm32")]
use crypto::eccipher::ECRistrettoSequential as ECRistretto;
#[cfg(not(target_arch = "wasm32"))]
use crypto::eccipher::ECRistrettoParallel as ECRistretto;

use common::{
    files,
    permutations::{permute, undo_permute},
    timer,
};

use crate::{
    fileio::{load_data, load_json, KeyedCSV},
    private_id::traits::CompanyPrivateIdProtocol,
};

use super::{fill_permute, ProtocolError};

#[derive(Debug)]
pub struct CompanyPrivateId {
    private_keys: (Scalar, Scalar),
    ec_cipher: ECRistretto,
    // TODO: consider using dyn pid::crypto::ECCipher trait?
    plain_data: Arc<RwLock<KeyedCSV>>,
    permutation: Arc<RwLock<Vec<usize>>>,

    v_company: Arc<RwLock<Vec<TPoint>>>,
    e_company: Arc<RwLock<Vec<TPoint>>>,
    e_partner: Arc<RwLock<Vec<TPoint>>>,

    s_prime_company: Arc<RwLock<Vec<ByteBuffer>>>,
    s_prime_partner: Arc<RwLock<Vec<ByteBuffer>>>,

    id_map: Arc<RwLock<Vec<Vec<String>>>>,
}

impl CompanyPrivateId {
    pub fn new() -> CompanyPrivateId {
        CompanyPrivateId {
            private_keys: (gen_scalar(), gen_scalar()),
            ec_cipher: ECRistretto::default(),
            plain_data: Arc::new(RwLock::default()),
            permutation: Arc::new(RwLock::default()),
            v_company: Arc::new(RwLock::default()),
            e_company: Arc::new(RwLock::default()),
            e_partner: Arc::new(RwLock::default()),
            s_prime_company: Arc::new(RwLock::default()),
            s_prime_partner: Arc::new(RwLock::default()),
            id_map: Arc::new(RwLock::default()),
        }
    }

    pub fn load_data(&self, path: &str, input_with_headers: bool) {
        load_data(self.plain_data.clone(), path, input_with_headers);
        fill_permute(
            self.permutation.clone(),
            (*self.plain_data.clone().read().unwrap()).records.len(),
        );
    }

    pub fn load_json(&self, json: &str, input_with_headers: bool) -> bool {
        let success = load_json(self.plain_data.clone(), json, input_with_headers);
        if success {
            fill_permute(
                self.permutation.clone(),
                (*self.plain_data.clone().read().unwrap()).records.len(),
            );
        }
        success
    }
}

impl Default for CompanyPrivateId {
    fn default() -> Self {
        Self::new()
    }
}

impl CompanyPrivateIdProtocol for CompanyPrivateId {
    fn set_encrypted_company(&self, name: String, data: TPayload) -> Result<(), ProtocolError> {
        match name.as_str() {
            "e_company" => self
                .e_company
                .clone()
                .write()
                .map(|mut d| {
                    let t = timer::Timer::new_silent("Load e_company");
                    d.append(&mut self.ec_cipher.to_points(&data));
                    t.qps("deserialize", data.len());
                })
                .map_err(|_| {
                    ProtocolError::ErrorDeserialization("Cannot load e_company".to_string())
                }),
            "v_company" => self
                .v_company
                .clone()
                .write()
                .map(|mut d| {
                    let t = timer::Timer::new_silent("Load v_company");
                    d.append(&mut self.ec_cipher.to_points(&data));
                    t.qps("deserialize", data.len());
                })
                .map_err(|_| {
                    ProtocolError::ErrorDeserialization("Cannot load v_company".to_string())
                }),
            _ => panic!("wrong name"),
        }
    }

    fn set_encrypted_partner_keys(&self, u_partner_payload: TPayload) -> Result<(), ProtocolError> {
        self.e_partner
            .clone()
            .write()
            .map(|mut data| {
                let t = timer::Timer::new_silent("load_u_partner");
                if data.is_empty() {
                    data.extend(
                        &self
                            .ec_cipher
                            .to_points_encrypt(&u_partner_payload, &self.private_keys.0),
                    );
                    t.qps("deserialize_exp", u_partner_payload.len());
                }
            })
            .map_err(|err| {
                error!("Cannot load e_company {}", err);
                ProtocolError::ErrorDeserialization("cannot load u_partner".to_string())
            })
    }

    fn write_partner_to_id_map(
        &self,
        s_prime_partner_payload: TPayload,
        na_val: Option<&String>,
    ) -> Result<(), ProtocolError> {
        self.id_map
            .clone()
            .write()
            .map(|mut data| {
                let t = timer::Timer::new_silent("load_s_prime_partner");
                if data.is_empty() {
                    for k in &s_prime_partner_payload {
                        let record = (*self.plain_data.clone().read().unwrap())
                            .get_empty_record_with_key(k.to_string(), na_val);
                        data.push(record);
                    }
                    t.qps("deserialize_exp", s_prime_partner_payload.len());
                }
            })
            .map_err(|err| {
                error!("Cannot load s_double_prime_partner {}", err);
                ProtocolError::ErrorDeserialization(
                    "cannot load s_double_prime_partner".to_string(),
                )
            })
    }

    fn get_permuted_keys(&self) -> Result<TPayload, ProtocolError> {
        match self.plain_data.clone().read() {
            Ok(pdata) => {
                let t = timer::Timer::new_silent("u_company");
                let plain_keys = pdata.get_plain_keys();
                let mut u = self
                    .ec_cipher
                    .hash_encrypt_to_bytes(&plain_keys.as_slice(), &self.private_keys.0);
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
                        error!("Cannot permute {}", err);
                        ProtocolError::ErrorEncryption("cannot permute u_company".to_string())
                    })
            }
            Err(e) => {
                error!("Unable to encrypt UCompany: {}", e);
                Err(ProtocolError::ErrorEncryption(
                    "cannot encrypt UCompany".to_string(),
                ))
            }
        }
    }

    fn get_encrypted_partner_keys(&self) -> Result<TPayload, ProtocolError> {
        self.e_partner
            .clone()
            .read()
            .map(|data| {
                let t = timer::Timer::new_silent("v_partner");
                let u = self.ec_cipher.encrypt_to_bytes(&data, &self.private_keys.1);
                t.qps("exp_serialize", u.len());
                u
            })
            .map_err(|err| {
                error!("Unable to encrypt VPartner: {}", err);
                ProtocolError::ErrorDeserialization("cannot encrypt VPartner".to_string())
            })
    }

    fn calculate_set_diff(&self) -> Result<(), ProtocolError> {
        match (
            self.e_partner.clone().read(),
            self.e_company.clone().read(),
            self.s_prime_company.clone().write(),
            self.s_prime_partner.clone().write(),
        ) {
            (Ok(e_partner), Ok(e_company), Ok(mut s_prime_company), Ok(mut s_prime_partner)) => {
                let e_company_bytes = self
                    .ec_cipher
                    .encrypt_to_bytes(&e_company, &self.private_keys.1);
                let e_partner_bytes = self
                    .ec_cipher
                    .encrypt_to_bytes(&e_partner, &self.private_keys.1);

                s_prime_partner.clear();
                s_prime_partner.extend(common::vectors::subtract_set(
                    &e_partner_bytes,
                    &e_company_bytes,
                ));

                s_prime_company.clear();
                s_prime_company.extend(common::vectors::subtract_set(
                    &e_company_bytes,
                    &e_partner_bytes,
                ));
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
            "s_prime_partner" => self
                .s_prime_partner
                .clone()
                .read()
                .map(|data| data.to_vec())
                .map_err(|err| {
                    error!("Unable to get s_prime_partner: {}", err);
                    ProtocolError::ErrorDeserialization("cannot obtain s_prime_partner".to_string())
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
            _ => panic!("wrong name"),
        }
    }

    fn write_company_to_id_map(&self) {
        match (
            self.permutation.clone().read(),
            self.plain_data.clone().read(),
            self.v_company.clone().read(),
            self.id_map.clone().write(),
        ) {
            (Ok(pm), Ok(plain_data), Ok(v_company), Ok(mut id_map)) => {
                let mut company_encrypt = self.ec_cipher.encrypt(&v_company, &self.private_keys.1);
                undo_permute(&pm, &mut company_encrypt);
                for (k, v) in self
                    .ec_cipher
                    .to_bytes(&company_encrypt)
                    .iter()
                    .zip(plain_data.get_plain_keys().iter())
                {
                    let record = plain_data.get_record_with_keys(k.to_string(), &v);
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
            .map_err(|_| ProtocolError::ErrorIO("Unable to write company view to file".to_string()))
    }

    fn stringify_id_map(&self, use_row_numbers: bool) -> String {
        files::stringify_id_map(self.id_map.clone(), use_row_numbers)
    }
}
