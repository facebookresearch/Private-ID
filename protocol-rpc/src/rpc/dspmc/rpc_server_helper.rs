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
use protocol::dspmc::helper::HelperDspmc;
use protocol::dspmc::traits::HelperDspmcProtocol;
use protocol::shared::TFeatures;
use rpc::proto::common::Payload;
use rpc::proto::gen_dspmc_helper::dspmc_helper_server::DspmcHelper;
use rpc::proto::gen_dspmc_helper::service_response::*;
use rpc::proto::gen_dspmc_helper::Commitment;
use rpc::proto::gen_dspmc_helper::CommitmentAck;
use rpc::proto::gen_dspmc_helper::CompanyPublicKeyAck;
use rpc::proto::gen_dspmc_helper::EHelperAck;
use rpc::proto::gen_dspmc_helper::ServiceResponse;
use rpc::proto::gen_dspmc_helper::UPartnerAck;
use rpc::proto::streaming::read_from_stream;
use rpc::proto::streaming::write_to_stream;
use rpc::proto::streaming::TPayloadStream;
use tonic::Code;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::Streaming;

pub struct DspmcHelperService {
    protocol: HelperDspmc,
    output_keys_path: Option<String>,
    output_shares_path: Option<String>,
    pub killswitch: Arc<AtomicBool>,
}

impl DspmcHelperService {
    pub fn new(
        output_keys_path: Option<&str>,
        output_shares_path: Option<&str>,
    ) -> DspmcHelperService {
        DspmcHelperService {
            protocol: HelperDspmc::new(),
            output_keys_path: output_keys_path.map(String::from),
            output_shares_path: output_shares_path.map(String::from),
            killswitch: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[tonic::async_trait]
impl DspmcHelper for DspmcHelperService {
    type RecvHelperPublicKeyStream = TPayloadStream;
    type RecvXorSharesStream = TPayloadStream;
    type RecvU2Stream = TPayloadStream;

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

    async fn calculate_id_map(
        &self,
        _: Request<Commitment>,
    ) -> Result<Response<CommitmentAck>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("calculate_id_map")
            .build();
        _ = self.protocol.calculate_set_diff();
        self.protocol.calculate_id_map();
        Ok(Response::new(CommitmentAck {}))
    }

    async fn recv_helper_public_key(
        &self,
        _: Request<ServiceResponse>,
    ) -> Result<Response<Self::RecvHelperPublicKeyStream>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("recv_helper_public_key")
            .build();
        self.protocol
            .get_helper_public_key()
            .map(write_to_stream)
            .map_err(|_| Status::new(Code::Aborted, "cannot send helper_public_key"))
    }

    async fn recv_xor_shares(
        &self,
        _: Request<ServiceResponse>,
    ) -> Result<Response<Self::RecvXorSharesStream>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("calculate_features_xor_shares")
            .build();
        self.protocol
            .calculate_features_xor_shares() // returns v_d_prime
            .map(write_to_stream)
            .map_err(|_| Status::new(Code::Aborted, "cannot send xor shares"))
    }

    async fn recv_u2(
        &self,
        _: Request<ServiceResponse>,
    ) -> Result<Response<Self::RecvXorSharesStream>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("recv_u2")
            .build();
        self.protocol
            .get_u2()
            .map(write_to_stream)
            .map_err(|_| Status::new(Code::Aborted, "cannot send u2"))
    }

    // Gets ct3s from all partners as well as permutation p_cd and blinding v_cd.
    async fn send_ct3_p_cd_v_cd(
        &self,
        request: Request<Streaming<Payload>>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("send_ct3_p_cd_v_cd")
            .build();
        let mut data = read_from_stream(request.into_inner().borrow_mut()).await?;

        let data_len =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;

        let v_cd_bytes = data.drain((data.len() - data_len)..).collect::<Vec<_>>();
        let p_cd_bytes = data.drain((data.len() - data_len)..).collect::<Vec<_>>();

        let num_partners =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;

        self.protocol
            .set_ct3p_cd_v_cd(data, num_partners, v_cd_bytes, p_cd_bytes)
            .map(|_| {
                Response::new(ServiceResponse {
                    ack: Some(Ack::EHelperAck(EHelperAck {})),
                })
            })
            .map_err(|_| Status::internal("error loading"))
    }

    async fn send_p_sd_v_sd(
        &self,
        request: Request<Streaming<Payload>>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("send_p_sd_v_sd")
            .build();
        let mut data = read_from_stream(request.into_inner().borrow_mut()).await?;

        let data_len =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;

        let v_sd_bytes = data.drain((data.len() - data_len)..).collect::<Vec<_>>();
        data.shrink_to_fit();

        self.protocol
            .set_p_sd_v_sd(v_sd_bytes, data)
            .map(|_| {
                Response::new(ServiceResponse {
                    ack: Some(Ack::UPartnerAck(UPartnerAck {})),
                })
            })
            .map_err(|_| Status::internal("error loading"))
    }

    async fn send_encrypted_vprime(
        &self,
        request: Request<Streaming<Payload>>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("send_encrypted_vprime")
            .build();
        let mut data = read_from_stream(request.into_inner().borrow_mut()).await?;

        let num_features =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;
        let num_rows =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;
        let g_zi = data
            .drain(num_features * num_rows..)
            .map(|x| x)
            .collect::<Vec<_>>();

        let mut blinded_features = TFeatures::new();
        for i in (0..num_features).rev() {
            let x = data
                .drain(i * num_rows..)
                .map(|x| u64::from_le_bytes(x.buffer.as_slice().try_into().unwrap()))
                .collect::<Vec<_>>();
            blinded_features.push(x);
        }

        self.protocol
            .set_encrypted_vprime(blinded_features, g_zi)
            .map(|_| {
                Response::new(ServiceResponse {
                    ack: Some(Ack::UPartnerAck(UPartnerAck {})),
                })
            })
            .map_err(|_| Status::internal("error loading"))
    }

    async fn send_u1(
        &self,
        request: Request<Streaming<Payload>>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("send_u1")
            .build();
        let mut data = read_from_stream(request.into_inner().borrow_mut()).await?;

        let num_features =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;
        let num_rows =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;
        data.shrink_to_fit();

        let mut u1 = TFeatures::new();
        for i in (0..num_features).rev() {
            let x = data
                .drain(i * num_rows..)
                .map(|x| u64::from_le_bytes(x.buffer.as_slice().try_into().unwrap()))
                .collect::<Vec<_>>();
            u1.push(x);
        }

        self.protocol
            .set_u1(u1)
            .map(|_| {
                Response::new(ServiceResponse {
                    ack: Some(Ack::UPartnerAck(UPartnerAck {})),
                })
            })
            .map_err(|_| Status::internal("error loading"))
    }

    async fn send_encrypted_keys(
        &self,
        request: Request<Streaming<Payload>>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("send_encrypted_keys")
            .build();

        // X, offset, metadata, ct1, ct2, offset, metadata
        let mut data = read_from_stream(request.into_inner().borrow_mut()).await?;

        let ct_offset_len =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;
        // flattened len
        let ct_data_len =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;
        // let num_keys = ct_offset_len - 1;

        let ct_offset = data
            .drain((data.len() - ct_offset_len)..)
            .map(|b| u64::from_le_bytes(b.buffer.as_slice().try_into().unwrap()) as usize)
            .collect::<Vec<_>>();
        assert_eq!(ct_offset_len, ct_offset.len());

        let ct2_flat = data.drain((data.len() - ct_data_len)..).collect::<Vec<_>>();
        let ct1_flat = data.drain((data.len() - ct_data_len)..).collect::<Vec<_>>();

        // H(C)*c
        let offset_len =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;
        // flattened len
        let data_len =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;
        // let num_keys = offset_len - 1;

        let offset = data
            .drain(data_len..)
            .map(|b| u64::from_le_bytes(b.buffer.as_slice().try_into().unwrap()) as usize)
            .collect::<Vec<_>>();
        assert_eq!(offset_len, offset.len());
        data.shrink_to_fit();

        self.protocol
            .set_encrypted_keys(data, offset, ct1_flat, ct2_flat, ct_offset)
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
            Some(p) => self.protocol.save_id_map(&String::from(p)).unwrap(),
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
