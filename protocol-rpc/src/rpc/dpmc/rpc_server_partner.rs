//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use common::timer;
use crypto::spoint::ByteBuffer;
use protocol::dpmc::partner::PartnerDpmc;
use protocol::dpmc::traits::PartnerDpmcProtocol;
use rpc::proto::common::Payload;
use rpc::proto::gen_dpmc_company::dpmc_company_client::DpmcCompanyClient;
use rpc::proto::gen_dpmc_partner::dpmc_partner_server::DpmcPartner;
use rpc::proto::gen_dpmc_partner::service_response::*;
use rpc::proto::gen_dpmc_partner::Commitment;
use rpc::proto::gen_dpmc_partner::CommitmentAck;
use rpc::proto::gen_dpmc_partner::CompanyPublicKeyAck;
use rpc::proto::gen_dpmc_partner::HelperPublicKeyAck;
use rpc::proto::gen_dpmc_partner::Init;
use rpc::proto::gen_dpmc_partner::InitAck;
use rpc::proto::gen_dpmc_partner::SendData;
use rpc::proto::gen_dpmc_partner::SendDataAck;
use rpc::proto::gen_dpmc_partner::ServiceResponse;
use rpc::proto::streaming::read_from_stream;
use rpc::proto::streaming::send_data;
use rpc::proto::streaming::write_to_stream;
use rpc::proto::streaming::TPayloadStream;
use tonic::transport::Channel;
use tonic::Code;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::Streaming;

pub struct DpmcPartnerService {
    protocol: PartnerDpmc,
    input_keys_path: String,
    input_features_path: String,
    input_with_headers: bool,
    company_client_context: DpmcCompanyClient<Channel>,
    pub killswitch: Arc<AtomicBool>,
}

impl DpmcPartnerService {
    pub fn new(
        input_keys_path: &str,
        input_features_path: &str,
        input_with_headers: bool,
        company_client_context: DpmcCompanyClient<Channel>,
    ) -> DpmcPartnerService {
        DpmcPartnerService {
            protocol: PartnerDpmc::new(),
            input_keys_path: String::from(input_keys_path),
            input_features_path: String::from(input_features_path),
            input_with_headers,
            company_client_context,
            killswitch: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[tonic::async_trait]
impl DpmcPartner for DpmcPartnerService {
    type RecvPartnerPublicKeyStream = TPayloadStream;

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
        let mut h_partner_alpha = self.protocol.get_encrypted_keys().unwrap();
        let mut company_client_contxt = self.company_client_context.clone();

        let xor_shares = self.protocol.get_features_xor_shares().unwrap();
        let xor_shares_len = xor_shares.len();
        h_partner_alpha.extend(xor_shares);
        h_partner_alpha.push(ByteBuffer {
            buffer: (xor_shares_len as u64).to_le_bytes().to_vec(),
        });

        _ = company_client_contxt
            .send_u_partner(send_data(h_partner_alpha))
            .await;

        Ok(Response::new(ServiceResponse {
            ack: Some(Ack::SendDataAck(SendDataAck {})),
        }))
    }

    async fn recv_partner_public_key(
        &self,
        _: Request<ServiceResponse>,
    ) -> Result<Response<Self::RecvPartnerPublicKeyStream>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("recv_partner_public_key")
            .build();
        self.protocol
            .get_partner_public_key()
            .map(write_to_stream)
            .map_err(|_| Status::new(Code::Aborted, "cannot send partner_public_key"))
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
