//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

pub mod common {
    tonic::include_proto!("common");
}

pub mod gen_private_id {
    tonic::include_proto!("privateid");
}

pub mod gen_crosspsi {
    tonic::include_proto!("crosspsi");
}

pub mod gen_pjc {
    tonic::include_proto!("pjc");
}

pub mod streaming;

use gen_crosspsi::cross_psi_client::CrossPsiClient;
use gen_pjc::pjc_client::PjcClient;
use gen_private_id::private_id_client::PrivateIdClient;
use tonic::transport::Channel;
pub enum RpcClient {
    PrivateId(PrivateIdClient<Channel>),
    CrossPsi(CrossPsiClient<Channel>),
    Pjc(PjcClient<Channel>),
}

use crypto::{he::BigIntWrapper, prelude::*};

pub mod from {
    use super::{common::*, *};

    impl From<&EncryptionKey> for common::Payload {
        fn from(key: &EncryptionKey) -> Self {
            common::Payload {
                payload: vec![
                    bincode::serialize(&BigIntWrapper { raw: key.n.clone() }).unwrap(),
                    bincode::serialize(&BigIntWrapper {
                        raw: key.nn.clone(),
                    })
                    .unwrap(),
                ],
            }
        }
    }

    impl From<&Payload> for EncryptionKey {
        fn from(pld: &Payload) -> Self {
            assert_eq!(pld.payload.len(), 2);
            EncryptionKey {
                n: (bincode::deserialize::<BigIntWrapper>(&pld.payload[0]).unwrap()).raw,
                nn: (bincode::deserialize::<BigIntWrapper>(&pld.payload[1]).unwrap()).raw,
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
    use super::{common::*, *};

    #[test]
    fn test_ser_dsr_he_enc_key() {
        for _ in 1..10 {
            let k1 = EncryptionKey {
                n: BigInt::zero(),
                nn: BigInt::zero(),
            };
            let k2 = EncryptionKey::from(&Payload::from(&k1));
            assert_eq!(k1, k2);
        }
    }
}
