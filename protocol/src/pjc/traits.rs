//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use crypto::prelude::TPayload;

pub trait PartnerPJCProtocol {
    fn get_permuted_keys(&self) -> TPayload;
    fn get_permuted_features(&self, feature_index: usize) -> TPayload;

    fn encrypt_permute(&self, keys: TPayload) -> TPayload;
    fn decrypt_stats(&self, encrypted_stats: Vec<TPayload>);
}

pub trait CompanyPJCProtocol {
    fn get_keys(&self) -> TPayload;
    fn get_stats(&self) -> Vec<TPayload>;

    fn set_encrypted_company_keys(&self, data: TPayload);

    fn calculate_intersection(&self, keys: TPayload);
    fn sum_common_values(&self, feature_index: usize, values: TPayload);
}
