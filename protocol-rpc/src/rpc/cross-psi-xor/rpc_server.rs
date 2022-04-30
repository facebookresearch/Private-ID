//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate common;
extern crate crypto;
extern crate protocol;
extern crate rpc;
extern crate tokio;
extern crate tonic;

use itertools::Itertools;
use std::{
    str::FromStr,
    borrow::BorrowMut,
    convert::TryInto,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tonic::{Request, Response, Status, Streaming};

use common::{gcs_path::GCSPath, s3_path::S3Path, timer};
use crypto::prelude::TPayload;
use log::info;
use protocol::{
    cross_psi_xor::{company::CompanyCrossPsiXOR, traits::CompanyCrossPsiXORProtocol},
    shared::{LoadData, Reveal},
};
use rpc::proto::{
    common::Payload,
    gen_crosspsi_xor::{
        cross_psi_xor_server::CrossPsiXor, service_response::*, Commitment, CommitmentAck,
        FeatureAck, FeatureQuery, Init, InitAck, KeysAck, ServiceResponse,
    },
    streaming::{read_from_stream, write_to_stream},
};

pub struct CrossPsiXorService {
    pub killswitch: Arc<AtomicBool>,
    output_path: Option<String>,
    protocol: CompanyCrossPsiXOR,
}

impl CrossPsiXorService {
    pub fn new(input_path: &str, output_path: Option<&str>) -> CrossPsiXorService {
        let protocol = CompanyCrossPsiXOR::new();
        info!(
            "Starting the service, loading from the path: {}",
            input_path
        );
        protocol.load_data(input_path);
        protocol.fill_permute_self();
        CrossPsiXorService {
            killswitch: Arc::new(AtomicBool::new(false)),
            output_path: output_path.map(String::from),
            protocol,
        }
    }
}

#[tonic::async_trait]
impl CrossPsiXor for CrossPsiXorService {
    async fn key_exchange(&self, request: Request<Init>) -> Result<Response<InitAck>, Status> {
        let _t = timer::Builder::new()
            .label("server")
            .extra_label("init")
            .build();
        info!("a client requesting public key, loading data");

        let init = request.into_inner();
        self.protocol
            .set_partner_num_features(init.partner_num_features as usize);
        self.protocol
            .set_partner_num_records(init.partner_num_records as usize);

        Ok(Response::new(InitAck {
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

    type RecvUCompanyFeaturesStream = rpc::proto::streaming::TPayloadStream;

    async fn recv_u_company_features(
        &self,
        _: Request<ServiceResponse>,
    ) -> Result<Response<Self::RecvUCompanyFeaturesStream>, Status> {
        let res = self.protocol.get_permuted_features();
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

    async fn send_u_partner_features(
        &self,
        request: Request<Streaming<Payload>>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let t = timer::Builder::new().label("server").build();

        let mut data = read_from_stream(request.into_inner().borrow_mut()).await?;

        // The feature index is sent as the last element of the payload
        let num_features =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;
        let num_ciphers =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;
        let num_entries =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;

        assert_eq!(num_ciphers * num_entries, data.len());
        let features : Vec<TPayload> = data.into_iter().chunks(num_entries).into_iter().map(|x| x.collect_vec()).collect_vec();
        assert_eq!(features.len(), num_ciphers);

        let _ = self.protocol.generate_additive_shares(features, num_features);

        t.qps(
            format!("push e_partner_feature").as_str(),
            num_entries,
        );
        Ok(Response::new(ServiceResponse {
            ack: Some(Ack::FeatureAck(FeatureAck {
                query_ack: Some(FeatureQuery {}),
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

    async fn send_e_company_features(
        &self,
        request: Request<Streaming<Payload>>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let t = timer::Builder::new().label("server").build();

        let mut data = read_from_stream(request.into_inner().borrow_mut()).await?;
        let num_features =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;
        let num_ciphers =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;
        let num_entries =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;

        assert_eq!(num_ciphers * num_entries, data.len());
        let features : Vec<TPayload> = data.into_iter().chunks(num_entries).into_iter().map(|x| x.collect_vec()).collect_vec();
        assert_eq!(features.len(), num_ciphers);

        self.protocol.set_self_shares(features, num_features);
        t.qps(
            format!("push_e_company_feature ").as_str(),
            num_entries,
        );
        Ok(Response::new(ServiceResponse {
            ack: Some(Ack::FeatureAck(FeatureAck {
                query_ack: Some(FeatureQuery {}),
            })),
        }))
    }

    type RecvSharesFeaturesStream = rpc::proto::streaming::TPayloadStream;

    async fn recv_shares_features(
        &self,
        _: Request<ServiceResponse>,
    ) -> Result<Response<Self::RecvSharesFeaturesStream>, Status> {
        let res = self.protocol.get_shares();
        Ok(write_to_stream(res))
    }

    async fn reveal(&self, _: Request<Commitment>) -> Result<Response<CommitmentAck>, Status> {
        println!("Reveal the shares");
        let _t = timer::Builder::new()
            .label("server")
            .extra_label("reveal")
            .build();

        match &self.output_path {
            Some(p) => {
                if let Ok(output_path_s3) = S3Path::from_str(p) {
                    let s3_tempfile = tempfile::NamedTempFile::new().unwrap();
                    let (_file, tmp_path) = s3_tempfile.keep().unwrap();
                    let tmp_path = tmp_path.to_str().expect("Failed to convert path to str");
                    self.protocol.reveal(tmp_path);
                    output_path_s3
                        .copy_from_local(&tmp_path)
                        .await
                        .expect("Failed to write to S3");
                } else if let Ok(output_path_gcp) = GCSPath::from_str(p) {
                    let gcs_tempfile = tempfile::NamedTempFile::new().unwrap();
                    let (_file, tmp_path) = gcs_tempfile.keep().unwrap();
                    let tmp_path = tmp_path.to_str().expect("Failed to convert path to str");
                    self.protocol.reveal(tmp_path);
                    output_path_gcp
                        .copy_from_local(&tmp_path)
                        .await
                        .expect("Failed to write to GCS");

                } else {
                    self.protocol.reveal(p);
                }
            }
            None => self.protocol.reveal(self.output_path.clone().unwrap()),
        }
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
