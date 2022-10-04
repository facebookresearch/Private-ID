//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use std::borrow::BorrowMut;
use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use common::gcs_path::GCSPath;
use common::metrics;
use common::s3_path::S3Path;
use common::timer;
use protocol::private_id_multi_key::company::CompanyPrivateIdMultiKey;
use protocol::private_id_multi_key::traits::CompanyPrivateIdMultiKeyProtocol;
use rpc::proto::common::Payload;
use rpc::proto::gen_private_id_multi_key::private_id_multi_key_server::PrivateIdMultiKey;
use rpc::proto::gen_private_id_multi_key::service_response::*;
use rpc::proto::gen_private_id_multi_key::CalculateSetDiffAck;
use rpc::proto::gen_private_id_multi_key::Commitment;
use rpc::proto::gen_private_id_multi_key::CommitmentAck;
use rpc::proto::gen_private_id_multi_key::ECompanyAck;
use rpc::proto::gen_private_id_multi_key::Init;
use rpc::proto::gen_private_id_multi_key::InitAck;
use rpc::proto::gen_private_id_multi_key::SPrimePartnerAck;
use rpc::proto::gen_private_id_multi_key::ServiceResponse;
use rpc::proto::gen_private_id_multi_key::Step1Barrier;
use rpc::proto::gen_private_id_multi_key::UPartnerAck;
use rpc::proto::gen_private_id_multi_key::WCompanyAck;
use rpc::proto::streaming::read_from_stream;
use rpc::proto::streaming::write_to_stream;
use rpc::proto::streaming::TPayloadStream;
use tonic::Code;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::Streaming;

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

#[cfg(test)]
mod tests {
    use std::io::{self};

    use crypto::prelude::*;
    use tempfile::NamedTempFile;

    use super::*;
    fn create_data_file() -> Result<NamedTempFile, io::Error> {
        let data = "email1,phone1 \n
        phone2, \n
        email3,";

        use std::io::Write;
        // Create a file inside of `std::env::temp_dir()`.
        let mut file1 = NamedTempFile::new().unwrap();

        // Write some test data to the first handle.
        file1.write_all(data.as_bytes()).unwrap();
        Ok(file1)
    }

    #[tokio::test]
    async fn test_recv_parameters() {
        let f = create_data_file().unwrap();
        let p = f.path().to_str().unwrap();
        let svc = PrivateIdMultiKeyService::new(p, None, false, None);
        let r1 = Request::new(Init {});
        let response_initialize = svc.initialize(r1).await;

        let response_recv_s_partner = svc
            .recv_s_partner(Request::new(ServiceResponse {
                ack: Some(Ack::ECompanyAck(ECompanyAck {})),
            }))
            .await;
        let response_recv_s_prime_company = svc
            .recv_s_prime_company(Request::new(ServiceResponse {
                ack: Some(Ack::ECompanyAck(ECompanyAck {})),
            }))
            .await;
        let response_recv_v_company = svc
            .recv_v_company(Request::new(ServiceResponse {
                ack: Some(Ack::ECompanyAck(ECompanyAck {})),
            }))
            .await;
        let response_recv_v_partner = svc
            .recv_v_partner(Request::new(ServiceResponse {
                ack: Some(Ack::ECompanyAck(ECompanyAck {})),
            }))
            .await;
        let response_recv_u_company = svc
            .recv_u_company(Request::new(ServiceResponse {
                ack: Some(Ack::ECompanyAck(ECompanyAck {})),
            }))
            .await;

        assert!(response_initialize.is_ok());
        assert!(response_recv_s_partner.is_ok());
        assert!(response_recv_s_prime_company.is_ok());
        assert!(response_recv_v_company.is_ok());
        assert!(response_recv_v_partner.is_ok());
        assert!(response_recv_u_company.is_ok());
    }
    #[tokio::test]
    async fn test_reveal() {
        let f = create_data_file().unwrap();
        let p = f.path().to_str().unwrap();
        let svc = PrivateIdMultiKeyService::new(p, None, false, None);
        let response = svc.reveal(Request::new(Commitment {})).await;

        assert!(response.is_ok());
    }

    #[tokio::test]
    async fn test_calculate_set_diff() {
        let f = create_data_file().unwrap();
        let p = f.path().to_str().unwrap();
        let svc = PrivateIdMultiKeyService::new(p, None, false, None);

        let data = vec![
            ByteBuffer {
                buffer: vec![
                    200, 135, 56, 19, 5, 207, 16, 147, 198, 229, 224, 111, 97, 119, 247, 238, 48,
                    209, 55, 188, 30, 178, 53, 4, 110, 27, 182, 220, 156, 57, 53, 63,
                ],
            },
            ByteBuffer {
                buffer: vec![
                    102, 237, 233, 208, 207, 235, 165, 5, 177, 27, 168, 233, 239, 69, 163, 80, 155,
                    2, 85, 192, 182, 25, 20, 189, 118, 5, 225, 153, 13, 254, 201, 40,
                ],
            },
            ByteBuffer {
                buffer: vec![
                    48, 54, 39, 197, 69, 34, 214, 167, 225, 117, 64, 223, 51, 164, 33, 208, 18,
                    108, 38, 248, 215, 189, 94, 180, 82, 105, 196, 43, 189, 2, 220, 6,
                ],
            },
            ByteBuffer {
                buffer: vec![
                    228, 188, 46, 30, 21, 100, 156, 96, 162, 185, 103, 149, 89, 159, 81, 67, 119,
                    112, 0, 174, 99, 188, 74, 7, 13, 236, 98, 48, 50, 145, 156, 50,
                ],
            },
        ];

        let psum = vec![0, 2, 3, 4];
        // company.private_keys.0 = create_key();
        svc.protocol
            .set_encrypted_partner_keys(data.clone(), psum.clone())
            .unwrap();
        svc.protocol
            .set_encrypted_company(String::from("e_company"), data, psum)
            .unwrap();

        let response = svc
            .calculate_set_diff(Request::new(Step1Barrier {
                e_company_ack: Some(ECompanyAck {}),
                u_partner_ack: Some(UPartnerAck {}),
            }))
            .await;

        assert!(response.is_ok());
    }
}
