//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate crypto;

use crypto::prelude::TPayload;

use crate::dspmc::ProtocolError;
use crate::shared::TFeatures;

pub trait PartnerDspmcProtocol {
    fn get_encrypted_keys(&self) -> Result<TPayload, ProtocolError>;
    fn get_features_xor_shares(&self) -> Result<TPayload, ProtocolError>;
}

pub trait ShufflerDspmcProtocol {
    fn set_p_cs_v_cs(
        &self,
        v_cs_bytes: TPayload,
        p_cs_bytes: TPayload,
    ) -> Result<(), ProtocolError>;
    fn gen_permutations(&self) -> Result<(TPayload, TPayload), ProtocolError>;
    fn get_blinded_vprime(&self) -> Result<TPayload, ProtocolError>;
    fn compute_v2prime_ct1ct2(
        &self,
        u2_bytes: TFeatures,
        ct1_prime_bytes: TPayload,
        ct2_prime_bytes: TPayload,
        psum: Vec<usize>,
    ) -> Result<TPayload, ProtocolError>;
}

pub trait CompanyDspmcProtocol {
    fn set_encrypted_partner_keys_and_shares(
        &self,
        ct1: TPayload,
        ct2: TPayload,
        keys_psum: Vec<usize>,
        ct3: Vec<u8>,
        xor_features: TFeatures,
    ) -> Result<(), ProtocolError>;
    fn get_all_ct3_p_cd_v_cd(&self) -> Result<TPayload, ProtocolError>;
    fn get_company_keys(&self) -> Result<TPayload, ProtocolError>;
    fn get_ct1_ct2(&self) -> Result<TPayload, ProtocolError>;
    fn get_p_cs_v_cs(&self) -> Result<TPayload, ProtocolError>;
    fn get_u1(&self) -> Result<TPayload, ProtocolError>;
    fn calculate_features_xor_shares(
        &self,
        features: TFeatures,
        g_zi: TPayload,
    ) -> Result<(), ProtocolError>;
    fn write_company_to_id_map(&self) -> Result<(), ProtocolError>;
    fn print_id_map(&self);
    fn save_id_map(&self, path: &str) -> Result<(), ProtocolError>;
    fn save_features_shares(&self, path_prefix: &str) -> Result<(), ProtocolError>;
    fn set_p_sc_v_sc_ct1ct2dprime(
        &self,
        v_sc_bytes: TPayload,
        p_sc_bytes: TPayload,
        ct1_dprime_flat: TPayload,
        ct2_dprime_flat: TPayload,
        psum: Vec<usize>,
    ) -> Result<(), ProtocolError>;
}

pub trait HelperDspmcProtocol {
    fn set_ct3p_cd_v_cd(
        &self,
        ct3: TPayload,
        num_partners: usize,
        v_cd_bytes: TPayload,
        p_cd_bytes: TPayload,
    ) -> Result<(), ProtocolError>;
    fn set_encrypted_vprime(
        &self,
        blinded_features: TFeatures,
        g_zi: TPayload,
    ) -> Result<(), ProtocolError>;
    fn set_encrypted_keys(
        &self,
        enc_keys: TPayload,
        psum: Vec<usize>,
        ct1: TPayload,
        ct2: TPayload,
        ct_psum: Vec<usize>,
    ) -> Result<(), ProtocolError>;
    fn set_p_sd_v_sd(
        &self,
        v_sd_bytes: TPayload,
        p_sd_bytes: TPayload,
    ) -> Result<(), ProtocolError>;
    fn set_u1(&self, u1_bytes: TFeatures) -> Result<(), ProtocolError>;
    fn calculate_set_diff(&self) -> Result<(), ProtocolError>;
    fn calculate_features_xor_shares(&self) -> Result<TPayload, ProtocolError>;
    fn get_u2(&self) -> Result<TPayload, ProtocolError>;
    fn calculate_id_map(&self);
    fn print_id_map(&self);
    fn save_id_map(&self, path: &str) -> Result<(), ProtocolError>;
    fn save_features_shares(&self, path_prefix: &str) -> Result<(), ProtocolError>;
}
