//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use std::borrow::BorrowMut;
use std::convert::TryInto;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use common::timer;
use protocol::dpmc::company::CompanyDpmc;
use protocol::dpmc::traits::CompanyDpmcProtocol;
use protocol::shared::TFeatures;
use rpc::proto::common::Payload;
use rpc::proto::gen_dpmc_company::dpmc_company_server::DpmcCompany;
use rpc::proto::gen_dpmc_company::service_response::*;
use rpc::proto::gen_dpmc_company::CalculateFeaturesXorSharesAck;
use rpc::proto::gen_dpmc_company::Commitment;
use rpc::proto::gen_dpmc_company::CommitmentAck;
use rpc::proto::gen_dpmc_company::Init;
use rpc::proto::gen_dpmc_company::InitAck;
use rpc::proto::gen_dpmc_company::ServiceResponse;
use rpc::proto::gen_dpmc_company::UPartnerAck;
use rpc::proto::streaming::read_from_stream;
use rpc::proto::streaming::write_to_stream;
use rpc::proto::streaming::TPayloadStream;
use tonic::Code;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::Streaming;

pub struct DpmcCompanyService {
    protocol: CompanyDpmc,
    input_path: String,
    output_keys_path: Option<String>,
    output_shares_path: Option<String>,
    input_with_headers: bool,
    pub killswitch: Arc<AtomicBool>,
}

impl DpmcCompanyService {
    pub fn new(
        input_path: &str,
        output_keys_path: Option<&str>,
        output_shares_path: Option<&str>,
        input_with_headers: bool,
    ) -> DpmcCompanyService {
        DpmcCompanyService {
            protocol: CompanyDpmc::new(),
            input_path: String::from(input_path),
            output_keys_path: output_keys_path.map(String::from),
            output_shares_path: output_shares_path.map(String::from),
            input_with_headers,
            killswitch: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[tonic::async_trait]
impl DpmcCompany for DpmcCompanyService {
    type RecvUCompanyStream = TPayloadStream;
    type RecvVPartnerStream = TPayloadStream;
    type RecvCompanyPublicKeyStream = TPayloadStream;

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

    async fn calculate_id_map(
        &self,
        _: Request<Commitment>,
    ) -> Result<Response<CommitmentAck>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("calculate_id_map")
            .build();
        self.protocol
            .write_company_to_id_map()
            .map(|_| Response::new(CommitmentAck {}))
            .map_err(|_| Status::new(Code::Aborted, "cannot init the protocol for partner"))
    }

    async fn calculate_features_xor_shares(
        &self,
        request: Request<Streaming<Payload>>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("calculate_features_xor_shares")
            .build();
        let mut data = read_from_stream(request.into_inner().borrow_mut()).await?;

        let num_features =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;
        let num_rows =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;
        let mask = data
            .drain(num_features * num_rows..)
            .map(|x| x)
            .collect::<Vec<_>>();
        let mut t = TFeatures::new();

        for i in (0..num_features).rev() {
            let x = data
                .drain(i * num_rows..)
                .map(|x| u64::from_le_bytes(x.buffer.as_slice().try_into().unwrap()))
                .collect::<Vec<_>>();
            t.push(x);
        }

        self.protocol
            .calculate_features_xor_shares(t, mask)
            .map(|_| {
                Response::new(ServiceResponse {
                    ack: Some(Ack::CalculateFeaturesXorSharesAck(
                        CalculateFeaturesXorSharesAck {},
                    )),
                })
            })
            .map_err(|_| Status::internal("error calculating XOR shares"))
    }

    async fn recv_company_public_key(
        &self,
        _: Request<ServiceResponse>,
    ) -> Result<Response<Self::RecvCompanyPublicKeyStream>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("recv_company_public_key")
            .build();
        self.protocol
            .get_company_public_key()
            .map(write_to_stream)
            .map_err(|_| Status::new(Code::Aborted, "cannot send company_public_key"))
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
            .map_err(|_| Status::new(Code::Aborted, "cannot send u_company"))
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
            .serialize_encrypted_keys_and_features()
            .map(write_to_stream)
            .map_err(|_| Status::new(Code::Aborted, "cannot init the protocol for partner"))
    }

    async fn send_u_partner(
        &self,
        request: Request<Streaming<Payload>>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("send_u_partner")
            .build();
        let mut data = read_from_stream(request.into_inner().borrow_mut()).await?;

        let xor_shares_len =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;

        let xor_shares = data
            .drain((data.len() - xor_shares_len)..)
            .collect::<Vec<_>>();

        let p_scalar_g = data.pop().unwrap();

        let enc_alpha_t = data.pop().unwrap();

        let offset_len =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;
        let data_len =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;

        let offset = data
            .drain(data_len..)
            .map(|b| u64::from_le_bytes(b.buffer.as_slice().try_into().unwrap()) as usize)
            .collect::<Vec<_>>();
        data.shrink_to_fit();

        assert_eq!(offset_len, offset.len());

        self.protocol
            .set_encrypted_partner_keys_and_shares(
                data,
                offset,
                enc_alpha_t.buffer,
                p_scalar_g.buffer,
                xor_shares,
            )
            .map(|_| {
                Response::new(ServiceResponse {
                    ack: Some(Ack::UPartnerAck(UPartnerAck {})),
                })
            })
            .map_err(|_| Status::internal("error loading"))
    }

    async fn reveal(&self, _: Request<Commitment>) -> Result<Response<CommitmentAck>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("reveal")
            .build();
        match &self.output_keys_path {
            Some(p) => self.protocol.save_id_map(p).unwrap(),
            None => self.protocol.print_id_map(),
        }

        let resp = self
            .protocol
            .save_features_shares(&self.output_shares_path.clone().unwrap())
            .map(|_| Response::new(CommitmentAck {}))
            .map_err(|_| Status::internal("error saving feature shares"));
        {
            debug!("Setting up flag for graceful down");
            self.killswitch.store(true, Ordering::SeqCst);
        }

        resp
    }
}
