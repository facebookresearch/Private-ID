//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate common;
extern crate crypto;
extern crate protocol;
extern crate rpc;
extern crate tokio;
extern crate tonic;

use log::info;
use std::{
    convert::TryInto,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tonic::{Request, Response, Status, Streaming};

use common::timer;
use crypto::prelude::TypeHeEncKey;
use protocol::{
    pjc::{company::CompanyPjc, traits::*},
    shared::LoadData,
};
use rpc::proto::{
    common::Payload,
    gen_pjc::{
        pjc_server::Pjc, service_response::*, Commitment, EncryptedSum, FeatureAck, FeatureQuery,
        Init, InitAck, KeysAck, ServiceResponse, Stats,
    },
    streaming::{read_from_stream, write_to_stream},
};

pub struct PJCService {
    pub killswitch: Arc<AtomicBool>,
    protocol: CompanyPjc,
}

impl PJCService {
    pub fn new(input_path: &str) -> PJCService {
        let protocol = CompanyPjc::new();
        info!(
            "Starting the service, loading from the path: {}",
            input_path
        );
        protocol.load_data(input_path);
        PJCService {
            killswitch: Arc::new(AtomicBool::new(false)),
            protocol,
        }
    }
}

#[tonic::async_trait]
impl Pjc for PJCService {
    type RecvUCompanyKeysStream = rpc::proto::streaming::TPayloadStream;

    async fn recv_u_company_keys(
        &self,
        _: Request<ServiceResponse>,
    ) -> Result<Response<Self::RecvUCompanyKeysStream>, Status> {
        Ok(write_to_stream(self.protocol.get_keys()))
    }

    async fn send_u_partner_keys(
        &self,
        request: Request<Streaming<Payload>>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let t = timer::Builder::new().label("server").build();
        let mut strm = request.into_inner();
        let data = read_from_stream(&mut strm).await?;
        t.qps("send u_partner_keys", data.len());
        self.protocol.calculate_intersection(data);

        Ok(Response::new(ServiceResponse {
            ack: Some(Ack::KeysAck(KeysAck {})),
        }))
    }

    async fn send_u_partner_feature(
        &self,
        request: Request<Streaming<Payload>>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let t = timer::Builder::new().label("server").build();

        let mut strm = request.into_inner();
        let mut data = read_from_stream(&mut strm).await?;
        let feature_index =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;
        let num_elements = data.len();
        self.protocol.sum_common_values(feature_index, data);
        t.qps(
            format!("he sum u_partner_column {}", feature_index).as_str(),
            num_elements,
        );
        Ok(Response::new(ServiceResponse {
            ack: Some(Ack::FeatureAck(FeatureAck {
                query_ack: Some(FeatureQuery {
                    feature_index: feature_index as u64,
                }),
            })),
        }))
    }

    async fn send_e_company_keys(
        &self,
        request: Request<Streaming<Payload>>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let t = timer::Builder::new().label("server").build();
        let mut strm = request.into_inner();
        let data = read_from_stream(&mut strm).await?;
        let data_len = data.len();
        self.protocol.set_encrypted_company_keys(data);
        t.qps("send_e_company_keys", data_len);
        Ok(Response::new(ServiceResponse {
            ack: Some(Ack::KeysAck(KeysAck {})),
        }))
    }

    async fn key_exchange(&self, request: Request<Init>) -> Result<Response<InitAck>, Status> {
        let _ = timer::Builder::new()
            .label("company")
            .extra_label("init")
            .build();

        let init = request.into_inner();
        let partner_he_public_key = TypeHeEncKey::from(
            &init
                .public_key
                .expect("public key for HE encryption must be present"),
        );
        self.protocol
            .set_partner_he_public_key(partner_he_public_key);

        Ok(Response::new(InitAck {}))
    }

    async fn recv_stats(&self, request: Request<Commitment>) -> Result<Response<Stats>, Status> {
        let _t = timer::Builder::new()
            .label("company")
            .extra_label("recv_stats")
            .build();

        let _ = request;

        let enc_sums = self
            .protocol
            .get_stats()
            .iter()
            .map(|he_sum| EncryptedSum {
                payload: Some(Payload::from(he_sum)),
            })
            .collect::<Vec<EncryptedSum>>();
        {
            debug!("Setting up flag for graceful down");
            self.killswitch.store(true, Ordering::SeqCst);
        }

        Ok(Response::new(Stats {
            encrypted_sums: enc_sums,
        }))
    }
}
