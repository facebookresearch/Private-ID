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

pub mod streaming;

use gen_crosspsi::cross_psi_client::CrossPsiClient;
use gen_crosspsi_xor::cross_psi_xor_client::CrossPsiXorClient;
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
}
