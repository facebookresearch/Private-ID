//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use crypto::prelude::TPayload;

pub trait CompanyCrossPsiXORProtocol {
    fn get_permuted_keys(&self) -> TPayload;
    fn get_permuted_features(&self) -> TPayload;
    fn get_company_indices(&self) -> TPayload;
    fn get_shares(&self) -> TPayload;

    fn set_encrypted_company_keys(&self, data: TPayload);
    fn set_self_shares(&self, data: Vec<TPayload>, num_features: usize);

    fn calculate_intersection(&self, keys: TPayload);
    fn generate_additive_shares(&self, data: Vec<TPayload>, num_features: usize);
}

pub trait PartnerCrossPsiXORProtocol {
    fn get_permuted_keys(&self) -> TPayload;
    fn get_permuted_features(&self) -> TPayload;

    fn set_self_shares(&self, data: Vec<TPayload>, num_features: usize);

    fn encrypt(&self, u_company_keys: TPayload) -> TPayload;
    fn get_additive_shares(&self, data: Vec<TPayload>, num_features: usize) -> TPayload;
}
