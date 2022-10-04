//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use crypto::prelude::TPayload;

use crate::private_id::ProtocolError;

pub trait PartnerPrivateIdProtocol {
    fn gen_permute_pattern(&self) -> Result<(), ProtocolError>;

    fn permute_hash_to_bytes(&self) -> Result<TPayload, ProtocolError>;
    fn encrypt_permute(&self, company: TPayload) -> (TPayload, TPayload);
    fn encrypt(&self, partner: TPayload) -> Result<TPayload, ProtocolError>;

    fn create_id_map(&self, partner: TPayload, company: TPayload, na_val: Option<&str>);
    fn print_id_map(&self, limit: usize, input_with_headers: bool, use_row_numbers: bool);
    fn save_id_map(
        &self,
        path: &str,
        input_with_headers: bool,
        use_row_numbers: bool,
    ) -> Result<(), ProtocolError>;
    fn stringify_id_map(&self, use_row_numbers: bool) -> String;
    fn get_id_map_size(&self) -> usize;
}

pub trait CompanyPrivateIdProtocol {
    fn set_encrypted_company(&self, name: String, data: TPayload) -> Result<(), ProtocolError>;
    fn set_encrypted_partner_keys(&self, u_partner_payload: TPayload) -> Result<(), ProtocolError>;

    fn get_permuted_keys(&self) -> Result<TPayload, ProtocolError>;
    fn get_encrypted_partner_keys(&self) -> Result<TPayload, ProtocolError>;

    fn calculate_set_diff(&self) -> Result<(), ProtocolError>;
    fn get_set_diff_output(&self, name: String) -> Result<TPayload, ProtocolError>;

    fn write_company_to_id_map(&self);
    fn write_partner_to_id_map(
        &self,
        s_prime_partner_payload: TPayload,
        na_val: Option<&String>,
    ) -> Result<(), ProtocolError>;

    fn print_id_map(&self, limit: usize, input_with_headers: bool, use_row_numbers: bool);
    fn save_id_map(
        &self,
        path: &str,
        input_with_headers: bool,
        use_row_numbers: bool,
    ) -> Result<(), ProtocolError>;
    fn stringify_id_map(&self, use_row_numbers: bool) -> String;
}
