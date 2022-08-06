//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate common;
extern crate crypto;
extern crate futures;
extern crate protocol;
extern crate tokio;
extern crate tonic;

use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use common::gcs_path::GCSPath;
use common::metrics;
use common::s3_path::S3Path;
use common::timer;
use protocol::private_id::company::CompanyPrivateId;
use protocol::private_id::traits::CompanyPrivateIdProtocol;
use rpc::proto::common::Payload;
use rpc::proto::gen_private_id::private_id_server::PrivateId;
use rpc::proto::gen_private_id::service_response::*;
use rpc::proto::gen_private_id::CalculateSetDiffAck;
use rpc::proto::gen_private_id::Commitment;
use rpc::proto::gen_private_id::CommitmentAck;
use rpc::proto::gen_private_id::ECompanyAck;
use rpc::proto::gen_private_id::Init;
use rpc::proto::gen_private_id::InitAck;
use rpc::proto::gen_private_id::SPrimePartnerAck;
use rpc::proto::gen_private_id::ServiceResponse;
use rpc::proto::gen_private_id::Step1Barrier;
use rpc::proto::gen_private_id::UPartnerAck;
use rpc::proto::gen_private_id::VCompanyAck;
use rpc::proto::streaming::read_from_stream;
use rpc::proto::streaming::write_to_stream;
use rpc::proto::streaming::TPayloadStream;
use tonic::Code;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::Streaming;

pub struct PrivateIdService {
    protocol: CompanyPrivateId,
    input_path: String,
    output_path: Option<String>,
    input_with_headers: bool,
    na_val: Option<String>,
    use_row_numbers: bool,
    metrics_path: Option<String>,
    metrics_obj: metrics::Metrics,
    pub killswitch: Arc<AtomicBool>,
}

impl PrivateIdService {
    pub fn new(
        input_path: &str,
        output_path: Option<&str>,
        input_with_headers: bool,
        na_val: Option<&str>,
        use_row_numbers: bool,
        metrics_path: Option<String>,
    ) -> PrivateIdService {
        PrivateIdService {
            protocol: CompanyPrivateId::new(),
            input_path: String::from(input_path),
            output_path: output_path.map(String::from),
            input_with_headers,
            na_val: na_val.map(String::from),
            use_row_numbers,
            metrics_path,
            metrics_obj: metrics::Metrics::new("private-id".to_string()),
            killswitch: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[tonic::async_trait]
impl PrivateId for PrivateIdService {
    type RecvUCompanyStream = TPayloadStream;
    type RecvVPartnerStream = TPayloadStream;
    type RecvSPrimeCompanyStream = TPayloadStream;
    type RecvSPartnerStream = TPayloadStream;

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

    async fn send_s_prime_partner(
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
                    ack: Some(Ack::SPrimePartnerAck(SPrimePartnerAck {})),
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
                        .save_id_map(
                            &String::from(path),
                            self.input_with_headers,
                            self.use_row_numbers,
                        )
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
                        .save_id_map(
                            &String::from(path),
                            self.input_with_headers,
                            self.use_row_numbers,
                        )
                        .expect("Failed to save id map to tempfile");
                    output_path_gcp
                        .copy_from_local(&path)
                        .await
                        .expect("Failed to write to GCS");
                } else {
                    self.protocol
                        .save_id_map(p, self.input_with_headers, self.use_row_numbers)
                        .unwrap();
                }
            }
            None => self
                .protocol
                .print_id_map(10, self.input_with_headers, self.use_row_numbers),
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
