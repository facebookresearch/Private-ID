//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use crypto::prelude::TPayload;
use mockall::automock;

use crate::private_id_multi_key::ProtocolError;

#[automock]
pub trait PartnerPrivateIdMultiKeyProtocol {
    fn permute_hash_to_bytes(&self) -> Result<TPayload, ProtocolError>;
    fn encrypt_permute(&self, data: TPayload, psum: Vec<usize>) -> Result<TPayload, ProtocolError>;
    fn encrypt(&self, data: TPayload) -> Result<TPayload, ProtocolError>;
    fn unshuffle_encrypt(&self, data: TPayload) -> Result<TPayload, ProtocolError>;

    fn create_id_map(&self, partner: TPayload, company: TPayload);
    fn print_id_map(&self);
    fn save_id_map(&self, path: &str) -> Result<(), ProtocolError>;
    fn get_id_map_size(&self) -> usize;
}

#[cfg_attr(test, automock)]
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_calculate_set_diff() {
        let mut mock = MockCompanyPrivateIdMultiKeyProtocol::new();
        mock.expect_calculate_set_diff().return_once(move || Ok(()));
        mock.calculate_set_diff().unwrap();
    }

    #[test]
    fn test_set_encrypted_company() {
        use crypto::prelude::*;
        let mut mock = MockCompanyPrivateIdMultiKeyProtocol::new();

        let data = vec![
            ByteBuffer {
                buffer: vec![
                    222, 241, 181, 82, 110, 1, 31, 200, 211, 43, 28, 242, 161, 246, 45, 150, 189,
                    231, 60, 151, 206, 157, 220, 189, 164, 218, 9, 206, 149, 216, 83, 8,
                ],
            },
            ByteBuffer {
                buffer: vec![
                    252, 70, 29, 162, 246, 4, 17, 183, 10, 161, 16, 235, 255, 70, 126, 143, 124,
                    168, 50, 231, 171, 4, 23, 107, 182, 200, 192, 171, 217, 205, 103, 21,
                ],
            },
            ByteBuffer {
                buffer: vec![
                    14, 171, 203, 48, 135, 252, 78, 6, 47, 148, 85, 63, 35, 232, 109, 127, 95, 17,
                    39, 248, 164, 153, 44, 124, 217, 144, 42, 35, 181, 125, 65, 4,
                ],
            },
            ByteBuffer {
                buffer: vec![
                    148, 206, 109, 52, 210, 222, 221, 117, 79, 160, 249, 40, 80, 146, 29, 46, 210,
                    247, 42, 75, 166, 131, 96, 101, 75, 250, 93, 121, 210, 206, 228, 65,
                ],
            },
        ];

        let psum = vec![0, 2, 3, 4];
        mock.expect_set_encrypted_company()
            .return_once(move |_, _, _| Ok(()));
        mock.set_encrypted_company(String::from("e_company"), data, psum)
            .unwrap();
    }
}
