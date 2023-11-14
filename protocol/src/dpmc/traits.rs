//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate crypto;

use crypto::prelude::TPayload;

use crate::dpmc::ProtocolError;
use crate::shared::TFeatures;

pub trait PartnerDpmcProtocol {
    fn get_encrypted_keys(&self) -> Result<TPayload, ProtocolError>;
    fn get_features_xor_shares(&self) -> Result<TPayload, ProtocolError>;
}

pub trait HelperDpmcProtocol {
    fn remove_partner_scalar_from_p_and_set_shares(
        &self,
        data: TPayload,
        psum: Vec<usize>,
        enc_alpha_t: Vec<u8>,
        p_scalar_g: TPayload,
        xor_shares: TPayload,
    ) -> Result<(), ProtocolError>;
    fn calculate_set_diff(&self, partner_num: usize) -> Result<(), ProtocolError>;
    fn calculate_id_map(&self, calculate_id_map: usize);
    fn set_encrypted_company(
        &self,
        company: TPayload,
        company_psum: Vec<usize>,
    ) -> Result<(), ProtocolError>;
    fn calculate_features_xor_shares(&self) -> Result<TPayload, ProtocolError>;
    fn print_id_map(&self);
    fn save_id_map(&self, path: &str) -> Result<(), ProtocolError>;
    fn save_features_shares(&self, path_prefix: &str) -> Result<(), ProtocolError>;
}

pub trait CompanyDpmcProtocol {
    fn set_encrypted_partner_keys_and_shares(
        &self,
        keys_data: TPayload,
        keys_psum: Vec<usize>,
        enc_alpha_t: Vec<u8>,
        p_scalar_g: Vec<u8>,
        shares_data: TPayload,
    ) -> Result<(), ProtocolError>;
    fn get_permuted_keys(&self) -> Result<TPayload, ProtocolError>;
    fn serialize_encrypted_keys_and_features(&self) -> Result<TPayload, ProtocolError>;
    fn calculate_features_xor_shares(
        &self,
        features: TFeatures,
        data: TPayload,
    ) -> Result<(), ProtocolError>;
    fn write_company_to_id_map(&self) -> Result<(), ProtocolError>;
    fn print_id_map(&self);
    fn save_id_map(&self, path: &str) -> Result<(), ProtocolError>;
    fn save_features_shares(&self, path_prefix: &str) -> Result<(), ProtocolError>;
}
