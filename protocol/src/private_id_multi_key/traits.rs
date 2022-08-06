//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use crypto::prelude::TPayload;

use crate::private_id_multi_key::ProtocolError;

pub trait PartnerPrivateIdMultiKeyProtocol {
    fn permute_hash_to_bytes(&self) -> Result<TPayload, ProtocolError>;
    fn encrypt_permute(&self, data: TPayload, psum: Vec<usize>) -> Result<TPayload, ProtocolError>;
    fn encrypt(&self, data: TPayload) -> Result<TPayload, ProtocolError>;
    fn unshuffle_encrypt(&self, data: TPayload) -> Result<TPayload, ProtocolError>;

    fn create_id_map(&self, partner: TPayload, company: TPayload);
    fn print_id_map(&self);
    fn save_id_map(&self, path: &str) -> Result<(), ProtocolError>;
}

pub trait CompanyPrivateIdMultiKeyProtocol {
    fn set_encrypted_company(
        &self,
        name: String,
        data: TPayload,
        psum: Vec<usize>,
    ) -> Result<(), ProtocolError>;
    fn set_encrypted_partner_keys(
        &self,
        data: TPayload,
        psum: Vec<usize>,
    ) -> Result<(), ProtocolError>;

    fn get_permuted_keys(&self) -> Result<TPayload, ProtocolError>;

    fn calculate_set_diff(&self) -> Result<(), ProtocolError>;
    fn get_set_diff_output(&self, name: String) -> Result<TPayload, ProtocolError>;
    fn set_set_diff_output(&self, name: String, data: TPayload) -> Result<(), ProtocolError>;

    fn write_company_to_id_map(&self);

    fn print_id_map(&self);
    fn save_id_map(&self, path: &str) -> Result<(), ProtocolError>;
}
