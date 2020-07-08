//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate common;
extern crate crypto;
extern crate futures;
extern crate protocol;
extern crate tokio;
extern crate tonic;

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tonic::{Code, Request, Response, Status, Streaming};

use common::timer;
use protocol::private_id::{company::CompanyPrivateId, traits::CompanyPrivateIdProtocol};
use rpc::proto::{
    common::Payload,
    gen_private_id::{
        private_id_server::PrivateId, service_response::*, CalculateSetDiffAck, Commitment,
        CommitmentAck, ECompanyAck, Init, InitAck, SDoublePrimePartnerAck, ServiceResponse,
        Step1Barrier, UPartnerAck, VCompanyAck,
    },
    streaming::{read_from_stream, write_to_stream, TPayloadStream},
};

pub struct PrivateIdService {
    protocol: CompanyPrivateId,
    input_path: String,
    output_path: Option<String>,
    input_with_headers: bool,
    na_val: Option<String>,
    use_row_numbers: bool,
    pub killswitch: Arc<AtomicBool>,
}

impl PrivateIdService {
    pub fn new(
        input_path: &str,
        output_path: Option<&str>,
        input_with_headers: bool,
        na_val: Option<&str>,
        use_row_numbers: bool,
    ) -> PrivateIdService {
        PrivateIdService {
            protocol: CompanyPrivateId::new(),
            input_path: String::from(input_path),
            output_path: output_path.map(String::from),
            input_with_headers,
            na_val: na_val.map(String::from),
            use_row_numbers,
            killswitch: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[tonic::async_trait]
impl PrivateId for PrivateIdService {
    type RecvUCompanyStream = TPayloadStream;
    type RecvVPartnerStream = TPayloadStream;
    type RecvSPrimeCompanyStream = TPayloadStream;
    type RecvSPrimePartnerStream = TPayloadStream;

    async fn initialize(&self, _: Request<Init>) -> Result<Response<ServiceResponse>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("init")
            .build();
        self.protocol
            .load_data(&self.input_path, self.input_with_headers);
        Ok(Response::new(ServiceResponse {
            ack: Some(Ack::InitAck(InitAck {})),
        }))
    }

    async fn calculate_set_diff(
        &self,
        _: Request<Step1Barrier>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("calculate_set_diff")
            .build();
        self.protocol
            .calculate_set_diff()
            .map(|_| {
                Response::new(ServiceResponse {
                    ack: Some(Ack::CalculateSetDiffAck(CalculateSetDiffAck {})),
                })
            })
            .map_err(|_| Status::new(Code::Aborted, "cannot init the protocol for partner"))
    }

    async fn recv_u_company(
        &self,
        _: Request<ServiceResponse>,
    ) -> Result<Response<Self::RecvUCompanyStream>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("recv_u_company")
            .build();
        self.protocol
            .get_permuted_keys()
            .map(write_to_stream)
            .map_err(|_| Status::new(Code::Aborted, "cannot init the protocol for partner"))
    }

    async fn recv_s_prime_company(
        &self,
        _: Request<ServiceResponse>,
    ) -> Result<Response<Self::RecvSPrimeCompanyStream>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("recv_prime_company")
            .build();
        self.protocol
            .get_set_diff_output("s_prime_company".to_string())
            .map(write_to_stream)
            .map_err(|_| Status::new(Code::Aborted, "cannot init the protocol for partner"))
    }

    async fn recv_s_prime_partner(
        &self,
        _: Request<ServiceResponse>,
    ) -> Result<Response<Self::RecvSPrimePartnerStream>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("recv_s_partner")
            .build();
        self.protocol
            .get_set_diff_output("s_prime_partner".to_string())
            .map(write_to_stream)
            .map_err(|_| Status::new(Code::Aborted, "cannot init the protocol for partner"))
    }

    async fn send_e_company(
        &self,
        request: Request<Streaming<Payload>>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("send_e_company")
            .build();
        let mut strm = request.into_inner();
        self.protocol
            .set_encrypted_company("e_company".to_string(), read_from_stream(&mut strm).await?)
            .map(|_| {
                Response::new(ServiceResponse {
                    ack: Some(Ack::ECompanyAck(ECompanyAck {})),
                })
            })
            .map_err(|_| Status::internal("error loading"))
    }

    async fn send_v_company(
        &self,
        request: Request<Streaming<Payload>>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("send_v_company")
            .build();
        let mut strm = request.into_inner();
        self.protocol
            .set_encrypted_company("v_company".to_string(), read_from_stream(&mut strm).await?)
            .map(|_| {
                Response::new(ServiceResponse {
                    ack: Some(Ack::VCompanyAck(VCompanyAck {})),
                })
            })
            .map_err(|_| Status::internal("error loading"))
    }

    async fn send_u_partner(
        &self,
        request: Request<Streaming<Payload>>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("send_u_partner")
            .build();
        let mut strm = request.into_inner();
        self.protocol
            .set_encrypted_partner_keys(read_from_stream(&mut strm).await?)
            .map(|_| {
                Response::new(ServiceResponse {
                    ack: Some(Ack::UPartnerAck(UPartnerAck {})),
                })
            })
            .map_err(|_| Status::internal("error loading"))
    }

    async fn recv_v_partner(
        &self,
        _: Request<ServiceResponse>,
    ) -> Result<Response<Self::RecvVPartnerStream>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("recv_v_partner")
            .build();
        self.protocol
            .get_encrypted_partner_keys()
            .map(write_to_stream)
            .map_err(|_| Status::internal("unable to recv_company"))
    }

    async fn send_s_double_prime_partner(
        &self,
        request: Request<Streaming<Payload>>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("send_s_prime_partner")
            .build();
        let mut strm = request.into_inner();
        self.protocol
            .write_partner_to_id_map(read_from_stream(&mut strm).await?, self.na_val.as_ref())
            .map(|_| {
                Response::new(ServiceResponse {
                    ack: Some(Ack::SDoublePrimePartnerAck(SDoublePrimePartnerAck {})),
                })
            })
            .map_err(|_| Status::internal("error loading"))
    }

    async fn reveal(&self, _: Request<Commitment>) -> Result<Response<CommitmentAck>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("reveal")
            .build();
        self.protocol.write_company_to_id_map();
        match &self.output_path {
            Some(p) => self
                .protocol
                .save_id_map(&p, self.input_with_headers, self.use_row_numbers)
                .unwrap(),
            None => self
                .protocol
                .print_id_map(10, self.input_with_headers, self.use_row_numbers),
        }
        {
            debug!("Setting up flag for graceful down");
            self.killswitch.store(true, Ordering::SeqCst);
        }
        Ok(Response::new(CommitmentAck {}))
    }
}
