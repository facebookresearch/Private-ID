//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate common;
extern crate crypto;
extern crate protocol;

use crypto::prelude::TPayload;
use rpc::proto::gen_dpmc_partner::dpmc_partner_client::DpmcPartnerClient;
use rpc::proto::gen_dpmc_partner::Commitment;
use rpc::proto::gen_dpmc_partner::ServiceResponse;
use rpc::proto::streaming::send_data;
use tonic::transport::Channel;
use tonic::Request;
use tonic::Response;
use tonic::Status;

pub async fn send(
    data: TPayload,
    name: String,
    rpc: &mut DpmcPartnerClient<Channel>,
) -> Result<Response<ServiceResponse>, Status> {
    match name.as_str() {
        "company_public_key" => rpc.send_company_public_key(send_data(data)).await,
        "helper_public_key" => rpc.send_helper_public_key(send_data(data)).await,
        _ => panic!("wrong data type"),
    }
}

pub async fn stop_service(rpc: &mut DpmcPartnerClient<Channel>) -> Result<(), Status> {
    let _r = rpc
        .stop_service(Request::new(Commitment {}))
        .await?
        .into_inner();
    Ok(())
}
