//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use std::borrow::BorrowMut;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use common::timer;
use protocol::suid_create::merger::SUIDCreateMerger;
use protocol::suid_create::traits::SUIDCreateMergerProtocol;
use rpc::proto::common::Payload;
use rpc::proto::gen_suid_create::service_response::*;
use rpc::proto::gen_suid_create::suid_create_server::SuidCreate;
use rpc::proto::gen_suid_create::CalculateSuidsAck;
use rpc::proto::gen_suid_create::Commitment;
use rpc::proto::gen_suid_create::CommitmentAck;
use rpc::proto::gen_suid_create::EncryptedKeysToMergeAck;
use rpc::proto::gen_suid_create::Init;
use rpc::proto::gen_suid_create::InitAck;
use rpc::proto::gen_suid_create::ServiceResponse;
use rpc::proto::gen_suid_create::SharerPublicKeyReuseAck;
use rpc::proto::gen_suid_create::Step1Barrier;
use rpc::proto::gen_suid_create::SuidsPartyMergerAck;
use rpc::proto::streaming::read_from_stream;
use rpc::proto::streaming::write_to_stream;
use rpc::proto::streaming::TPayloadStream;
use tonic::Code;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::Streaming;

pub struct SUIDCreateService {
    protocol: SUIDCreateMerger,
    input_path: String,
    output_path: Option<String>,
    input_with_headers: bool,
    pub killswitch: Arc<AtomicBool>,
}

impl SUIDCreateService {
    pub fn new(
        input_path: &str,
        output_path: Option<&str>,
        input_with_headers: bool,
    ) -> SUIDCreateService {
        SUIDCreateService {
            protocol: SUIDCreateMerger::new(),
            input_path: String::from(input_path),
            output_path: output_path.map(String::from),
            input_with_headers,
            killswitch: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[tonic::async_trait]
impl SuidCreate for SUIDCreateService {
    type RecvPublicKeyMStream = TPayloadStream;
    type RecvPartyMergerStream = TPayloadStream;
    type RecvSuidsStream = TPayloadStream;

    async fn initialize(&self, _: Request<Init>) -> Result<Response<ServiceResponse>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("init")
            .build();
        self.protocol
            .load_data(&self.input_path, self.input_with_headers)
            .map(|_| {
                Response::new(ServiceResponse {
                    ack: Some(Ack::InitAck(InitAck {})),
                })
            })
            .map_err(|_| Status::new(Code::Aborted, "cannot load data for party with merger"))
    }

    async fn recv_public_key_m(
        &self,
        _: Request<ServiceResponse>,
    ) -> Result<Response<Self::RecvPublicKeyMStream>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("public_key_m")
            .build();
        Ok(write_to_stream(self.protocol.get_public_key_m()))
    }

    async fn send_sharer_public_key_reuse(
        &self,
        request: Request<Streaming<Payload>>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("sharer_public_key_reuse")
            .build();
        let mut strm = request.into_inner();
        self.protocol
            .set_sharer_public_key_reuse(read_from_stream(&mut strm).await?)
            .map(|_| {
                Response::new(ServiceResponse {
                    ack: Some(Ack::SharerPublicKeyReuseAck(SharerPublicKeyReuseAck {})),
                })
            })
            .map_err(|_| Status::internal("error writing sharer public key_reuse to merger"))
    }

    async fn calculate_suids(
        &self,
        _: Request<Step1Barrier>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("calculate_suids")
            .build();
        self.protocol
            .calculate_suids()
            .map(|_| {
                Response::new(ServiceResponse {
                    ack: Some(Ack::CalculateSuidsAck(CalculateSuidsAck {})),
                })
            })
            .map_err(|_| Status::new(Code::Aborted, "cannot calculate SUIDs"))
    }

    async fn recv_party_merger(
        &self,
        _: Request<ServiceResponse>,
    ) -> Result<Response<Self::RecvPartyMergerStream>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("recv_party_merger")
            .build();
        self.protocol
            .get_party_merger_keys()
            .map(write_to_stream)
            .map_err(|_| {
                Status::new(
                    Code::Aborted,
                    "cannot keys for party associated with merger",
                )
            })
    }

    async fn recv_suids(
        &self,
        _: Request<ServiceResponse>,
    ) -> Result<Response<Self::RecvSuidsStream>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("recv_suids")
            .build();
        self.protocol
            .get_suids()
            .map(write_to_stream)
            .map_err(|_| Status::new(Code::Aborted, "cannot init the protocol for partner"))
    }

    async fn send_encrypted_keys_to_merge(
        &self,
        request: Request<Streaming<Payload>>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("send_encrypted_keys_to_merge")
            .build();
        let mut data = read_from_stream(request.into_inner().borrow_mut()).await?;

        let offsets_len =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;
        let data_len =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;

        let offsets = data
            .drain(data_len..)
            .map(|b| u64::from_le_bytes(b.buffer.as_slice().try_into().unwrap()) as usize)
            .collect::<Vec<_>>();
        data.shrink_to_fit();

        assert_eq!(offsets_len, offsets.len());
        assert_eq!(data_len, data.len());
        assert_eq!(data_len % 2, 0);

        let data2 = data.drain((data_len / 2)..).collect::<Vec<_>>();
        let data1 = data;

        assert_eq!(data1.len(), data2.len());

        self.protocol
            .set_encrypted_keys_to_merge(data1, data2, offsets)
            .map(|_| {
                Response::new(ServiceResponse {
                    ack: Some(Ack::EncryptedKeysToMergeAck(EncryptedKeysToMergeAck {})),
                })
            })
            .map_err(|_| Status::internal("error loading"))
    }

    async fn send_suids_party_merger(
        &self,
        request: Request<Streaming<Payload>>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("suids_party_merger")
            .build();
        let mut strm = request.into_inner();
        self.protocol
            .set_suids_for_party_merger(read_from_stream(&mut strm).await?)
            .map(|_| {
                Response::new(ServiceResponse {
                    ack: Some(Ack::SuidsPartyMergerAck(SuidsPartyMergerAck {})),
                })
            })
            .map_err(|_| Status::internal("error writing"))
    }

    async fn reveal(&self, _: Request<Commitment>) -> Result<Response<CommitmentAck>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("reveal")
            .build();
        match &self.output_path {
            Some(p) => self.protocol.save_suids_data(p).unwrap(),
            None => self.protocol.print_suids_data(),
        }
        {
            debug!("Setting up flag for graceful down");
            self.killswitch.store(true, Ordering::SeqCst);
        }
        Ok(Response::new(CommitmentAck {}))
    }
}
