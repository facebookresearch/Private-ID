//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use std::borrow::BorrowMut;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use common::timer;
use crypto::prelude::TypeHeEncKey;
use log::info;
use protocol::cross_psi::company::CompanyCrossPsi;
use protocol::cross_psi::traits::CompanyCrossPsiProtocol;
use protocol::shared::LoadData;
use protocol::shared::Reveal;
use protocol::shared::ShareableEncKey;
use rpc::proto::common::Payload;
use rpc::proto::gen_crosspsi::cross_psi_server::CrossPsi;
use rpc::proto::gen_crosspsi::service_response::*;
use rpc::proto::gen_crosspsi::Commitment;
use rpc::proto::gen_crosspsi::CommitmentAck;
use rpc::proto::gen_crosspsi::FeatureAck;
use rpc::proto::gen_crosspsi::FeatureQuery;
use rpc::proto::gen_crosspsi::Init;
use rpc::proto::gen_crosspsi::InitAck;
use rpc::proto::gen_crosspsi::KeysAck;
use rpc::proto::gen_crosspsi::ServiceResponse;
use rpc::proto::streaming::read_from_stream;
use rpc::proto::streaming::write_to_stream;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::Streaming;

pub struct CrossPsiService {
    pub killswitch: Arc<AtomicBool>,
    output_path: Option<String>,
    protocol: CompanyCrossPsi,
}

impl CrossPsiService {
    pub fn new(input_path: &str, output_path: Option<&str>) -> CrossPsiService {
        let protocol = CompanyCrossPsi::new();
        info!(
            "Starting the service, loading from the path: {}",
            input_path
        );
        protocol.load_data(input_path);
        protocol.fill_permute_self();
        CrossPsiService {
            killswitch: Arc::new(AtomicBool::new(false)),
            output_path: output_path.map(String::from),
            protocol,
        }
    }
}

#[tonic::async_trait]
impl CrossPsi for CrossPsiService {
    async fn key_exchange(&self, request: Request<Init>) -> Result<Response<InitAck>, Status> {
        let _t = timer::Builder::new()
            .label("server")
            .extra_label("init")
            .build();
        info!("a client requesting public key, loading data");

        let init = request.into_inner();
        let partner_he_public_key = TypeHeEncKey::from(
            &init
                .partner_public_key
                .expect("public key for HE encryption must be present"),
        );
        self.protocol
            .set_partner_num_features(init.partner_num_features as usize);
        self.protocol
            .set_partner_num_records(init.partner_num_records as usize);
        self.protocol
            .set_partner_he_public_key(partner_he_public_key);

        Ok(Response::new(InitAck {
            company_public_key: Some(Payload::from(&self.protocol.get_he_public_key())),
            company_num_features: self.protocol.get_self_num_features() as u64,
            company_num_records: self.protocol.get_self_num_records() as u64,
        }))
    }

    type RecvUCompanyKeysStream = rpc::proto::streaming::TPayloadStream;

    async fn recv_u_company_keys(
        &self,
        _: Request<ServiceResponse>,
    ) -> Result<Response<Self::RecvUCompanyKeysStream>, Status> {
        Ok(write_to_stream(self.protocol.get_permuted_keys()))
    }

    type RecvUCompanyFeatureStream = rpc::proto::streaming::TPayloadStream;

    async fn recv_u_company_feature(
        &self,
        request: Request<ServiceResponse>,
    ) -> Result<Response<Self::RecvUCompanyFeatureStream>, Status> {
        let feature_index = match request.into_inner().ack.unwrap() {
            Ack::FeatureQuery(x) => x.feature_index as usize,
            _ => panic!("wrong ack"),
        };
        let res = self.protocol.get_permuted_features(feature_index);
        Ok(write_to_stream(res))
    }

    async fn send_u_partner_keys(
        &self,
        request: Request<Streaming<Payload>>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let t = timer::Builder::new().label("server").build();
        let mut strm = request.into_inner();
        let data = read_from_stream(&mut strm).await?;
        t.qps("push u_partner_keys", data.len());
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

        let mut data = read_from_stream(request.into_inner().borrow_mut()).await?;

        // The feature index is sent as the last element of the payload
        let feature_index =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;
        let num_elements = data.len();
        let _ = self.protocol.generate_additive_shares(feature_index, data);

        t.qps(
            format!("push e_partner_feature {}", feature_index).as_str(),
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
        t.qps("push_e_company_keys", data_len);
        Ok(Response::new(ServiceResponse {
            ack: Some(Ack::KeysAck(KeysAck {})),
        }))
    }

    async fn send_e_company_feature(
        &self,
        request: Request<Streaming<Payload>>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let t = timer::Builder::new().label("server").build();

        let mut data = read_from_stream(request.into_inner().borrow_mut()).await?;
        let feature_index =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;
        let num_elements = data.len();

        self.protocol.set_self_shares(feature_index, data);
        t.qps(
            format!("push_e_company_feature {}", feature_index).as_str(),
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

    type RecvSharesFeatureStream = rpc::proto::streaming::TPayloadStream;

    async fn recv_shares_feature(
        &self,
        request: Request<ServiceResponse>,
    ) -> Result<Response<Self::RecvSharesFeatureStream>, Status> {
        let feature_index = match request.into_inner().ack.unwrap() {
            Ack::SharesQuery(x) => x.query.unwrap().feature_index as usize,
            _ => panic!("wrong ack"),
        };
        let res = self.protocol.get_shares(feature_index);
        Ok(write_to_stream(res))
    }

    async fn reveal(&self, _: Request<Commitment>) -> Result<Response<CommitmentAck>, Status> {
        println!("Reveal the shares");
        let _t = timer::Builder::new()
            .label("server")
            .extra_label("reveal")
            .build();

        self.protocol.reveal(self.output_path.clone().unwrap());

        {
            debug!("Setting up flag for graceful down");
            self.killswitch.store(true, Ordering::SeqCst);
        }
        Ok(Response::new(CommitmentAck {}))
    }

    type RecvSharesCompanyIndicesStream = rpc::proto::streaming::TPayloadStream;

    async fn recv_shares_company_indices(
        &self,
        _: Request<ServiceResponse>,
    ) -> Result<Response<Self::RecvSharesCompanyIndicesStream>, Status> {
        let payload = self.protocol.get_company_indices();

        Ok(write_to_stream(payload))
    }
}
