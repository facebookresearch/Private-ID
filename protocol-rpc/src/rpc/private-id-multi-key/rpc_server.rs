//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use common::{gcs_path::GCSPath, metrics, s3_path::S3Path, timer};
use protocol::private_id_multi_key::{
    company::CompanyPrivateIdMultiKey, traits::CompanyPrivateIdMultiKeyProtocol,
};
use rpc::proto::{
    common::Payload,
    gen_private_id_multi_key::{
        private_id_multi_key_server::PrivateIdMultiKey, service_response::*, CalculateSetDiffAck,
        Commitment, CommitmentAck, ECompanyAck, Init, InitAck, SPrimePartnerAck, ServiceResponse,
        Step1Barrier, UPartnerAck, WCompanyAck,
    },
    streaming::{read_from_stream, write_to_stream, TPayloadStream},
};
use std::{
    borrow::BorrowMut,
    convert::TryInto,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tonic::{Code, Request, Response, Status, Streaming};

pub struct PrivateIdMultiKeyService {
    protocol: CompanyPrivateIdMultiKey,
    input_path: String,
    output_path: Option<String>,
    input_with_headers: bool,
    metrics_path: Option<String>,
    metrics_obj: metrics::Metrics,
    pub killswitch: Arc<AtomicBool>,
}

impl PrivateIdMultiKeyService {
    pub fn new(
        input_path: &str,
        output_path: Option<&str>,
        input_with_headers: bool,
        metrics_path: Option<String>,
    ) -> PrivateIdMultiKeyService {
        PrivateIdMultiKeyService {
            protocol: CompanyPrivateIdMultiKey::new(),
            input_path: String::from(input_path),
            output_path: output_path.map(String::from),
            input_with_headers,
            metrics_path,
            metrics_obj: metrics::Metrics::new("private-id-multi-key".to_string()),
            killswitch: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[tonic::async_trait]
impl PrivateIdMultiKey for PrivateIdMultiKeyService {
    type RecvUCompanyStream = TPayloadStream;
    type RecvVPartnerStream = TPayloadStream;
    type RecvVCompanyStream = TPayloadStream;
    type RecvSPartnerStream = TPayloadStream;
    type RecvSPrimeCompanyStream = TPayloadStream;

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
            .extra_label("recv_s_prime_company")
            .build();
        self.protocol
            .get_set_diff_output("s_prime_company".to_string())
            .map(write_to_stream)
            .map_err(|_| Status::new(Code::Aborted, "cannot init the protocol for partner"))
    }

    async fn recv_s_partner(
        &self,
        _: Request<ServiceResponse>,
    ) -> Result<Response<Self::RecvSPartnerStream>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("recv_s_partner")
            .build();
        self.protocol
            .get_set_diff_output("s_partner".to_string())
            .map(write_to_stream)
            .map_err(|_| Status::new(Code::Aborted, "cannot init the protocol for partner"))
    }

    async fn recv_v_company(
        &self,
        _: Request<ServiceResponse>,
    ) -> Result<Response<Self::RecvVCompanyStream>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("recv_v_company")
            .build();
        self.protocol
            .get_set_diff_output("v_company".to_string())
            .map(write_to_stream)
            .map_err(|_| Status::new(Code::Aborted, "cannot init the protocol for partner"))
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
            .get_set_diff_output("v_partner".to_string())
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
        let mut data = read_from_stream(request.into_inner().borrow_mut()).await?;

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
            .set_encrypted_company("e_company".to_string(), data, offset)
            .map(|_| {
                Response::new(ServiceResponse {
                    ack: Some(Ack::ECompanyAck(ECompanyAck {})),
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
            .set_encrypted_partner_keys(data, offset)
            .map(|_| {
                Response::new(ServiceResponse {
                    ack: Some(Ack::UPartnerAck(UPartnerAck {})),
                })
            })
            .map_err(|_| Status::internal("error loading"))
    }

    async fn send_s_prime_partner(
        &self,
        request: Request<Streaming<Payload>>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("send_u_partner")
            .build();
        let mut strm = request.into_inner();
        self.protocol
            .set_set_diff_output(
                "s_prime_partner".to_string(),
                read_from_stream(&mut strm).await?,
            )
            .map(|_| {
                Response::new(ServiceResponse {
                    ack: Some(Ack::SPrimePartnerAck(SPrimePartnerAck {})),
                })
            })
            .map_err(|_| Status::internal("error writing"))
    }

    async fn send_w_company(
        &self,
        request: Request<Streaming<Payload>>,
    ) -> Result<Response<ServiceResponse>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("send_w_company")
            .build();
        let mut strm = request.into_inner();
        self.protocol
            .set_set_diff_output("w_company".to_string(), read_from_stream(&mut strm).await?)
            .map(|_| {
                Response::new(ServiceResponse {
                    ack: Some(Ack::WCompanyAck(WCompanyAck {})),
                })
            })
            .map_err(|_| Status::internal("error writing"))
    }

    async fn reveal(&self, _: Request<Commitment>) -> Result<Response<CommitmentAck>, Status> {
        let _ = timer::Builder::new()
            .label("server")
            .extra_label("reveal")
            .build();
        self.protocol.write_company_to_id_map();
        self.metrics_obj
            .set_partner_input_size(self.protocol.get_e_partner_size());
        self.metrics_obj
            .set_publisher_input_size(self.protocol.get_e_company_size());
        self.metrics_obj
            .set_union_file_size(self.protocol.get_id_map_size());
        match &self.output_path {
            Some(p) => {
                if let Ok(output_path_s3) = S3Path::from_str(p) {
                    let s3_tempfile = tempfile::NamedTempFile::new().unwrap();
                    let (_file, path) = s3_tempfile.keep().unwrap();
                    let path = path.to_str().expect("Failed to convert path to str");
                    self.protocol
                        .save_id_map(&String::from(path))
                        .expect("Failed to save id map to tempfile");
                    output_path_s3
                        .copy_from_local(&path)
                        .await
                        .expect("Failed to write to S3");
                } else if let Ok(output_path_gcp) = GCSPath::from_str(p) {
                    let gcs_tempfile = tempfile::NamedTempFile::new().unwrap();
                    let (_file, path) = gcs_tempfile.keep().unwrap();
                    let path = path.to_str().expect("Failed to convert path to str");
                    self.protocol
                        .save_id_map(&String::from(path))
                        .expect("Failed to save id map to tempfile");
                    output_path_gcp
                        .copy_from_local(&path)
                        .await
                        .expect("Failed to write to GCS");
                } else {
                    self.protocol.save_id_map(p).unwrap();
                }
            }
            None => self.protocol.print_id_map(),
        }
        match &self.metrics_path {
            Some(p) => {
                if let Ok(metrics_path_s3) = S3Path::from_str(p) {
                    let s3_tempfile = tempfile::NamedTempFile::new().unwrap();
                    let (_file, path) = s3_tempfile.keep().unwrap();
                    let path = path.to_str().expect("Failed to convert path to str");
                    self.metrics_obj
                        .save_metrics(&String::from(path))
                        .expect("Failed to metrics to tempfile");
                    metrics_path_s3
                        .copy_from_local(&path)
                        .await
                        .expect("Failed to write to S3");
                } else {
                    self.metrics_obj
                        .save_metrics(p)
                        .expect("Failed to write to metrics path");
                }
            }
            None => {
                self.metrics_obj.print_metrics();
            }
        }
        {
            debug!("Setting up flag for graceful down");
            self.killswitch.store(true, Ordering::SeqCst);
        }
        Ok(Response::new(CommitmentAck {}))
    }
}
