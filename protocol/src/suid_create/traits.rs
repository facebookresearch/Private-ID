//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use crypto::prelude::TPayload;
use crypto::prelude::TPoint;

use crate::suid_create::ProtocolError;

pub trait SUIDCreateSharerProtocol {
    fn get_public_key_reuse(&self) -> TPayload;
    fn set_public_key_m(&self, p_key: TPayload) -> Result<(), ProtocolError>;

    fn elgamal_exponentiate(
        &self,
        data: Vec<(Vec<Vec<TPoint>>, Vec<Vec<TPoint>>)>,
    ) -> Result<Vec<(Vec<Vec<TPoint>>, Vec<Vec<TPoint>>)>, ProtocolError>;
    fn shuffle_flatten(
        &self,
        data: Vec<(Vec<Vec<TPoint>>, Vec<Vec<TPoint>>)>,
    ) -> Result<TPayload, ProtocolError>;
    fn unshuffle_suids(&self, data: TPayload) -> Result<Vec<(TPayload, TPayload)>, ProtocolError>;

    fn set_suids_for_parties(&self, data: Vec<(TPayload, TPayload)>) -> Result<(), ProtocolError>;

    fn print_suids_data(&self);
    fn save_suids_data(&self, path: &str) -> Result<(), ProtocolError>;
}

pub trait SUIDCreateMergerProtocol {
    fn get_public_key_m(&self) -> TPayload;
    fn set_sharer_public_key_reuse(&self, p_key: TPayload) -> Result<(), ProtocolError>;
    fn set_encrypted_keys_to_merge(
        &self,
        c1_buf: TPayload,
        c2_buf: TPayload,
        psum: Vec<usize>,
    ) -> Result<(), ProtocolError>;
    fn get_party_merger_keys(&self) -> Result<TPayload, ProtocolError>;

    fn calculate_suids(&self) -> Result<(), ProtocolError>;

    fn get_suids(&self) -> Result<TPayload, ProtocolError>;
    fn set_suids_for_party_merger(&self, data: TPayload) -> Result<(), ProtocolError>;

    fn print_suids_data(&self);
    fn save_suids_data(&self, path: &str) -> Result<(), ProtocolError>;
}
