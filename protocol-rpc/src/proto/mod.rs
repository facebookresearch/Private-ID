//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

pub mod common {
    tonic::include_proto!("common");
}

pub mod gen_private_id {
    tonic::include_proto!("privateid");
}

pub mod gen_private_id_multi_key {
    tonic::include_proto!("privateidmultikey");
}

pub mod gen_crosspsi {
    tonic::include_proto!("crosspsi");
}

pub mod gen_crosspsi_xor {
    tonic::include_proto!("crosspsixor");
}

pub mod gen_pjc {
    tonic::include_proto!("pjc");
}

pub mod gen_suid_create {
    tonic::include_proto!("suidcreate");
}

pub mod gen_dpmc_company {
    tonic::include_proto!("dpmccompany");
}

pub mod gen_dpmc_partner {
    tonic::include_proto!("dpmcpartner");
}

pub mod gen_dspmc_company {
    tonic::include_proto!("dspmccompany");
}

pub mod gen_dspmc_helper {
    tonic::include_proto!("dspmchelper");
}

pub mod gen_dspmc_partner {
    tonic::include_proto!("dspmcpartner");
}

pub mod streaming;

use gen_crosspsi::cross_psi_client::CrossPsiClient;
use gen_crosspsi_xor::cross_psi_xor_client::CrossPsiXorClient;
use gen_dpmc_company::dpmc_company_client::DpmcCompanyClient;
use gen_dpmc_partner::dpmc_partner_client::DpmcPartnerClient;
use gen_dspmc_company::dspmc_company_client::DspmcCompanyClient;
use gen_dspmc_helper::dspmc_helper_client::DspmcHelperClient;
use gen_dspmc_partner::dspmc_partner_client::DspmcPartnerClient;
use gen_pjc::pjc_client::PjcClient;
use gen_private_id::private_id_client::PrivateIdClient;
use gen_private_id_multi_key::private_id_multi_key_client::PrivateIdMultiKeyClient;
use gen_suid_create::suid_create_client::SuidCreateClient;
use tonic::transport::Channel;
pub enum RpcClient {
    PrivateId(PrivateIdClient<Channel>),
    PrivateIdMultiKey(PrivateIdMultiKeyClient<Channel>),
    CrossPsi(CrossPsiClient<Channel>),
    CrossPsiXor(CrossPsiXorClient<Channel>),
    Pjc(PjcClient<Channel>),
    SuidCreate(SuidCreateClient<Channel>),
    DpmcCompany(DpmcCompanyClient<Channel>),
    DpmcPartner(DpmcPartnerClient<Channel>),
    DspmcCompany(DspmcCompanyClient<Channel>),
    DspmcHelper(DspmcHelperClient<Channel>),
    DspmcPartner(DspmcPartnerClient<Channel>),
}

use crypto::prelude::*;

pub mod from {
    use num_bigint::BigUint;

    use super::common::*;
    use super::*;

    impl From<&EncryptionKey> for common::Payload {
        fn from(key: &EncryptionKey) -> Self {
            common::Payload {
                payload: vec![key.n.to_bytes_le(), key.nn.to_bytes_le()],
            }
        }
    }

    impl From<&Payload> for EncryptionKey {
        fn from(pld: &Payload) -> Self {
            assert_eq!(pld.payload.len(), 2);
            EncryptionKey {
                n: BigUint::from_bytes_le(&pld.payload[0]),
                nn: BigUint::from_bytes_le(&pld.payload[1]),
            }
        }
    }

    impl From<&TPayload> for common::Payload {
        fn from(payload: &TPayload) -> Self {
            let z = payload
                .iter()
                .map(|c| c.buffer.clone())
                .collect::<Vec<Vec<u8>>>();
            common::Payload { payload: z }
        }
    }

    impl From<&Payload> for TPayload {
        fn from(pld: &Payload) -> Self {
            pld.payload
                .iter()
                .map(|x| ByteBuffer { buffer: x.to_vec() })
                .collect::<TPayload>()
        }
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use num_traits::identities::Zero;

    use super::common::*;
    use super::*;

    #[test]
    fn test_ser_dsr_he_enc_key() {
        for _ in 1..10 {
            let k1 = EncryptionKey {
                n: BigUint::zero(),
                nn: BigUint::zero(),
            };
            let k2 = EncryptionKey::from(&Payload::from(&k1));
            assert_eq!(k1.n, k2.n);
            assert_eq!(k1.nn, k2.nn);
        }
    }

    #[test]
    fn test_tpayload_to_payload() {
        let data = vec![
            ByteBuffer {
                buffer: vec![
                    200, 135, 56, 19, 5, 207, 16, 147, 198, 229, 224, 111, 97, 119, 247, 238, 48,
                    209, 55, 188, 30, 178, 53, 4, 110, 27, 182, 220, 156, 57, 53, 63,
                ],
            },
            ByteBuffer {
                buffer: vec![
                    102, 237, 233, 208, 207, 235, 165, 5, 177, 27, 168, 233, 239, 69, 163, 80, 155,
                    2, 85, 192, 182, 25, 20, 189, 118, 5, 225, 153, 13, 254, 201, 40,
                ],
            },
            ByteBuffer {
                buffer: vec![
                    48, 54, 39, 197, 69, 34, 214, 167, 225, 117, 64, 223, 51, 164, 33, 208, 18,
                    108, 38, 248, 215, 189, 94, 180, 82, 105, 196, 43, 189, 2, 220, 6,
                ],
            },
            ByteBuffer {
                buffer: vec![
                    228, 188, 46, 30, 21, 100, 156, 96, 162, 185, 103, 149, 89, 159, 81, 67, 119,
                    112, 0, 174, 99, 188, 74, 7, 13, 236, 98, 48, 50, 145, 156, 50,
                ],
            },
        ];

        let p = Payload::from(&data);
        let tp = TPayload::from(&p);
        assert_eq!(tp, data);
    }
}
