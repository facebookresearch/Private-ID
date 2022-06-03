//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use crypto::prelude::TPayload;

pub trait CompanyCrossPsiProtocol {
    fn get_permuted_keys(&self) -> TPayload;
    fn get_permuted_features(&self, feature_index: usize) -> TPayload;
    fn get_company_indices(&self) -> TPayload;
    fn get_shares(&self, feature_index: usize) -> TPayload;

    fn set_encrypted_company_keys(&self, data: TPayload);
    fn set_self_shares(&self, feature_index: usize, data: TPayload);

    fn calculate_intersection(&self, keys: TPayload);
    fn generate_additive_shares(&self, feature_index: usize, data: TPayload);
}

pub trait PartnerCrossPsiProtocol {
    fn get_permuted_keys(&self) -> TPayload;
    fn get_permuted_features(&self, feature_index: usize) -> TPayload;

    fn set_self_shares(&self, feature_index: usize, data: TPayload);

    fn encrypt(&self, u_company_keys: TPayload) -> TPayload;
    fn generate_additive_shares(&self, feature_index: usize, data: TPayload) -> TPayload;
}
