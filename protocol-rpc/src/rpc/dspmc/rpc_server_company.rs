//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate common;
extern crate crypto;
extern crate futures;
extern crate protocol;
extern crate tokio;
extern crate tonic;

use std::borrow::BorrowMut;
use std::convert::TryInto;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use common::timer;
use protocol::dspmc::company::CompanyDspmc;
use protocol::dspmc::traits::CompanyDspmcProtocol;
use protocol::shared::TFeatures;
use rpc::proto::common::Payload;
use rpc::proto::gen_dspmc_company::dspmc_company_server::DspmcCompany;
use rpc::proto::gen_dspmc_company::service_response::*;
use rpc::proto::gen_dspmc_company::Commitment;
use rpc::proto::gen_dspmc_company::CommitmentAck;
use rpc::proto::gen_dspmc_company::HelperPublicKeyAck;
use rpc::proto::gen_dspmc_company::Init;
use rpc::proto::gen_dspmc_company::InitAck;
use rpc::proto::gen_dspmc_company::RecvShares;
use rpc::proto::gen_dspmc_company::RecvSharesAck;
use rpc::proto::gen_dspmc_company::SendData;
use rpc::proto::gen_dspmc_company::SendDataAck;
use rpc::proto::gen_dspmc_company::ServiceResponse;
use rpc::proto::gen_dspmc_company::UPartnerAck;
use rpc::proto::gen_dspmc_helper::dspmc_helper_client::DspmcHelperClient;
use rpc::proto::gen_dspmc_helper::ServiceResponse as HelperServiceResponse;
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

pub struct DspmcCompanyService {
    protocol: CompanyDspmc,
    input_path: String,
    output_keys_path: Option<String>,
    output_shares_path: Option<String>,
    input_with_headers: bool,
    helper_client_context: DspmcHelperClient<Channel>,
    pub killswitch: Arc<AtomicBool>,
}

impl DspmcCompanyService {
    pub fn new(
        input_path: &str,
        output_keys_path: Option<&str>,
        output_shares_path: Option<&str>,
        input_with_headers: bool,
        helper_client_context: DspmcHelperClient<Channel>,
    ) -> DspmcCompanyService {
        DspmcCompanyService {
            protocol: CompanyDspmc::new(),
            input_path: String::from(input_path),
            output_keys_path: output_keys_path.map(String::from),
            output_shares_path: output_shares_path.map(String::from),
            input_with_headers,
            helper_client_context,
            killswitch: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[tonic::async_trait]
impl DspmcCompany for DspmcCompanyService {
    type RecvUCompanyStream = TPayloadStream;
    type RecvPCsVCsStream = TPayloadStream;
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

    async fn send_ct3_p_cd_v_cd_to_helper(
        &self,
        _: Request<SendData>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("send_ct3_p_cd_v_cd_to_helper")
            .build();

        self.protocol.gen_permutations();

        // Send ct3 from all partners to helper. - company acts as a client to helper.
        let partners_ct3 = self.protocol.get_all_ct3_p_cd_v_cd().unwrap();
        let mut helper_client_contxt = self.helper_client_context.clone();
        _ = helper_client_contxt
            .send_ct3_p_cd_v_cd(send_data(partners_ct3))
            .await;

        Ok(Response::new(ServiceResponse {
            ack: Some(Ack::SendDataAck(SendDataAck {})),
        }))
    }

    async fn send_u1_to_helper(
        &self,
        _: Request<SendData>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("send_u1_to_helper")
            .build();

        // Send u1 to helper. - company acts as a client to helper.
        let u1 = self.protocol.get_u1().unwrap();
        let mut helper_client_contxt = self.helper_client_context.clone();
        _ = helper_client_contxt.send_u1(send_data(u1)).await;

        Ok(Response::new(ServiceResponse {
            ack: Some(Ack::SendDataAck(SendDataAck {})),
        }))
    }

    async fn send_encrypted_keys_to_helper(
        &self,
        _: Request<SendData>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("send_encrypted_keys_to_helper")
            .build();

        // Send ct1, ct2', and X to helper. - company acts as a client to helper.
        // H(C)^c
        let mut enc_keys = self.protocol.get_company_keys().unwrap();
        let ct1_ct2 = self.protocol.get_ct1_ct2().unwrap();
        enc_keys.extend(ct1_ct2);

        let mut helper_client_contxt = self.helper_client_context.clone();
        // X, offset, metadata, ct1, ct2, offset, metadata
        _ = helper_client_contxt
            .send_encrypted_keys(send_data(enc_keys))
            .await;

        Ok(Response::new(ServiceResponse {
            ack: Some(Ack::SendDataAck(SendDataAck {})),
        }))
    }

    async fn recv_shares_from_helper(
        &self,
        _: Request<RecvShares>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("recv_shares_from_helper")
            .build();

        let mut helper_client_contxt = self.helper_client_context.clone();
        let request = Request::new(HelperServiceResponse {
            ack: Some(
                rpc::proto::gen_dspmc_helper::service_response::Ack::UPartnerAck(
                    rpc::proto::gen_dspmc_helper::UPartnerAck {},
                ),
            ),
        });
        let mut strm = helper_client_contxt
            .recv_xor_shares(request)
            .await?
            .into_inner();
        let mut data = read_from_stream(&mut strm).await?;

        let num_features =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;
        let num_rows =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;
        let g_zi = data
            .drain(num_features * num_rows..)
            .map(|x| x)
            .collect::<Vec<_>>();

        let mut features = TFeatures::new();
        for i in (0..num_features).rev() {
            let x = data
                .drain(i * num_rows..)
                .map(|x| u64::from_le_bytes(x.buffer.as_slice().try_into().unwrap()))
                .collect::<Vec<_>>();
            features.push(x);
        }

        _ = self.protocol.calculate_features_xor_shares(features, g_zi);

        // Print Company's ID spine and save partners shares
        match &self.output_keys_path {
            Some(p) => self.protocol.save_id_map(p).unwrap(),
            None => self.protocol.print_id_map(),
        }

        let resp = self
            .protocol
            .save_features_shares(&self.output_shares_path.clone().unwrap())
            .map(|_| {
                Response::new(ServiceResponse {
                    ack: Some(Ack::RecvSharesAck(RecvSharesAck {})),
                })
            })
            .map_err(|_| Status::internal("error saving feature shares"));
        {
            debug!("Setting up flag for graceful down");
            self.killswitch.store(true, Ordering::SeqCst);
        }

        resp
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

    async fn recv_p_cs_v_cs(
        &self,
        _: Request<ServiceResponse>,
    ) -> Result<Response<Self::RecvUCompanyStream>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("recv_p_cs_v_cs")
            .build();
        self.protocol
            .get_p_cs_v_cs()
            .map(write_to_stream)
            .map_err(|_| Status::new(Code::Aborted, "cannot send p_cs_v_cs"))
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
            .get_company_keys()
            .map(write_to_stream)
            .map_err(|_| Status::new(Code::Aborted, "cannot send u_company"))
    }

    async fn send_p_sc_v_sc_ct1ct2dprime(
        &self,
        request: Request<Streaming<Payload>>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("send_p_sc_v_sc_ct1ct2dprime")
            .build();
        let mut data = read_from_stream(request.into_inner().borrow_mut()).await?;

        let offset_len =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;
        // flattened len
        let data_len =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;
        let num_keys = offset_len - 1;

        let offset = data
            .drain((num_keys * 2 + data_len * 2)..)
            .map(|b| u64::from_le_bytes(b.buffer.as_slice().try_into().unwrap()) as usize)
            .collect::<Vec<_>>();
        assert_eq!(offset_len, offset.len());

        let ct2_dprime_flat = data.drain((data.len() - data_len)..).collect::<Vec<_>>();
        let ct1_dprime_flat = data.drain((data.len() - data_len)..).collect::<Vec<_>>();

        let v_sc_bytes = data.drain((data.len() - num_keys)..).collect::<Vec<_>>();
        data.shrink_to_fit(); // p_sc

        self.protocol
            .set_p_sc_v_sc_ct1ct2dprime(v_sc_bytes, data, ct1_dprime_flat, ct2_dprime_flat, offset)
            .map(|_| {
                Response::new(ServiceResponse {
                    ack: Some(Ack::UPartnerAck(UPartnerAck {})),
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
        let mut data = read_from_stream(request.into_inner().borrow_mut()).await?;

        let ct3 = data.pop().unwrap();

        let num_features =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;
        let num_rows =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;

        let mut v_prime = data
            .drain((data.len() - (num_features * num_rows))..)
            .collect::<Vec<_>>();

        let mut xor_features = TFeatures::new();
        for i in (0..num_features).rev() {
            let x = v_prime
                .drain(i * num_rows..)
                .map(|x| u64::from_le_bytes(x.buffer.as_slice().try_into().unwrap()))
                .collect::<Vec<_>>();
            xor_features.push(x);
        }

        let offset_len =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;
        let data_len =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;

        let offset = data
            .drain((data_len * 2)..)
            .map(|b| u64::from_le_bytes(b.buffer.as_slice().try_into().unwrap()) as usize)
            .collect::<Vec<_>>();

        // ct2 = pkd^r * H(P)
        // ct1 = pkc^r
        data.shrink_to_fit();
        let (ct2, ct1) = data.split_at(data_len);

        assert_eq!(offset_len, offset.len());

        self.protocol
            .set_encrypted_partner_keys_and_shares(
                ct1.to_vec(),
                ct2.to_vec(),
                offset,
                ct3.buffer,
                xor_features,
            )
            .map(|_| {
                Response::new(ServiceResponse {
                    ack: Some(Ack::UPartnerAck(UPartnerAck {})),
                })
            })
            .map_err(|_| Status::internal("error loading"))
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
}
