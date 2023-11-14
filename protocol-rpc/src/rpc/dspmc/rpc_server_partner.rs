//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate common;
extern crate crypto;
extern crate futures;
extern crate protocol;
extern crate tokio;
extern crate tonic;

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use common::timer;
use protocol::dspmc::partner::PartnerDspmc;
use protocol::dspmc::traits::PartnerDspmcProtocol;
use rpc::proto::common::Payload;
use rpc::proto::gen_dspmc_company::dspmc_company_client::DspmcCompanyClient;
use rpc::proto::gen_dspmc_partner::dspmc_partner_server::DspmcPartner;
use rpc::proto::gen_dspmc_partner::service_response::*;
use rpc::proto::gen_dspmc_partner::Commitment;
use rpc::proto::gen_dspmc_partner::CommitmentAck;
use rpc::proto::gen_dspmc_partner::CompanyPublicKeyAck;
use rpc::proto::gen_dspmc_partner::HelperPublicKeyAck;
use rpc::proto::gen_dspmc_partner::Init;
use rpc::proto::gen_dspmc_partner::InitAck;
use rpc::proto::gen_dspmc_partner::SendData;
use rpc::proto::gen_dspmc_partner::SendDataAck;
use rpc::proto::gen_dspmc_partner::ServiceResponse;
use rpc::proto::streaming::read_from_stream;
use rpc::proto::streaming::send_data;
use tonic::transport::Channel;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::Streaming;

pub struct DspmcPartnerService {
    protocol: PartnerDspmc,
    input_keys_path: String,
    input_features_path: String,
    input_with_headers: bool,
    company_client_context: DspmcCompanyClient<Channel>,
    pub killswitch: Arc<AtomicBool>,
}

impl DspmcPartnerService {
    pub fn new(
        input_keys_path: &str,
        input_features_path: &str,
        input_with_headers: bool,
        company_client_context: DspmcCompanyClient<Channel>,
    ) -> DspmcPartnerService {
        DspmcPartnerService {
            protocol: PartnerDspmc::new(),
            input_keys_path: String::from(input_keys_path),
            input_features_path: String::from(input_features_path),
            input_with_headers,
            company_client_context,
            killswitch: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[tonic::async_trait]
impl DspmcPartner for DspmcPartnerService {
    async fn initialize(&self, _: Request<Init>) -> Result<Response<ServiceResponse>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("init")
            .build();
        self.protocol.load_data(
            &self.input_keys_path,
            &self.input_features_path,
            self.input_with_headers,
        );
        Ok(Response::new(ServiceResponse {
            ack: Some(Ack::InitAck(InitAck {})),
        }))
    }

    async fn send_data_to_company(
        &self,
        _: Request<SendData>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("init")
            .build();

        // Send partner data to company. - Partner acts as a client to company.
        let mut ct1_ct2 = self.protocol.get_encrypted_keys().unwrap();
        let mut company_client_contxt = self.company_client_context.clone();

        // XOR shares + metadata + ct3
        let xor_shares = self.protocol.get_features_xor_shares().unwrap();

        ct1_ct2.extend(xor_shares);

        // ct2 + ct1 + offset + XOR shares + metadata + ct3
        _ = company_client_contxt
            .send_u_partner(send_data(ct1_ct2))
            .await;

        Ok(Response::new(ServiceResponse {
            ack: Some(Ack::SendDataAck(SendDataAck {})),
        }))
    }

    async fn send_company_public_key(
        &self,
        request: Request<Streaming<Payload>>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("send_company_public_key")
            .build();
        let mut strm = request.into_inner();
        self.protocol
            .set_company_public_key(read_from_stream(&mut strm).await?)
            .map(|_| {
                Response::new(ServiceResponse {
                    ack: Some(Ack::CompanyPublicKeyAck(CompanyPublicKeyAck {})),
                })
            })
            .map_err(|_| Status::internal("error writing"))
    }

    async fn send_helper_public_key(
        &self,
        request: Request<Streaming<Payload>>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("send_helper_public_key")
            .build();
        let mut strm = request.into_inner();
        self.protocol
            .set_helper_public_key(read_from_stream(&mut strm).await?)
            .map(|_| {
                Response::new(ServiceResponse {
                    ack: Some(Ack::HelperPublicKeyAck(HelperPublicKeyAck {})),
                })
            })
            .map_err(|_| Status::internal("error writing"))
    }

    async fn stop_service(
        &self,
        _: Request<Commitment>,
    ) -> Result<Response<CommitmentAck>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("stop")
            .build();
        {
            debug!("Setting up flag for graceful down");
            self.killswitch.store(true, Ordering::SeqCst);
        }

        Ok(Response::new(CommitmentAck {}))
    }
}
