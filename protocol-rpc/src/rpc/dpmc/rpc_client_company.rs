//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate common;
extern crate crypto;
extern crate protocol;

use common::timer;
use crypto::prelude::TPayload;
use rpc::proto::gen_dpmc_company::dpmc_company_client::DpmcCompanyClient;
use rpc::proto::gen_dpmc_company::Commitment;
use rpc::proto::gen_dpmc_company::ServiceResponse;
use rpc::proto::streaming::read_from_stream;
use rpc::proto::streaming::send_data;
use tonic::transport::Channel;
use tonic::Request;
use tonic::Response;
use tonic::Status;

pub async fn recv(
    response: ServiceResponse,
    name: String,
    data: &mut TPayload,
    rpc: &mut DpmcCompanyClient<Channel>,
) -> Result<(), Status> {
    let t = timer::Builder::new().label(name.as_str()).build();

    let request = Request::new(response);
    let mut strm = match name.as_str() {
        "company_public_key" => rpc.recv_company_public_key(request).await?.into_inner(),
        "u_company" => rpc.recv_u_company(request).await?.into_inner(),
        "v_partner" => rpc.recv_v_partner(request).await?.into_inner(),
        _ => panic!("wrong data type"),
    };

    let res = read_from_stream(&mut strm).await?;
    t.qps(format!("received {}", name.as_str()).as_str(), res.len());
    data.clear();
    data.extend(res);
    Ok(())
}

pub async fn calculate_features_xor_shares(
    data: TPayload,
    rpc: &mut DpmcCompanyClient<Channel>,
) -> Result<Response<ServiceResponse>, Status> {
    rpc.calculate_features_xor_shares(send_data(data)).await
}

pub async fn calculate_id_map(rpc: &mut DpmcCompanyClient<Channel>) -> Result<(), Status> {
    let _r = rpc
        .calculate_id_map(Request::new(Commitment {}))
        .await?
        .into_inner();
    Ok(())
}

pub async fn reveal(rpc: &mut DpmcCompanyClient<Channel>) -> Result<(), Status> {
    let _r = rpc.reveal(Request::new(Commitment {})).await?.into_inner();
    Ok(())
}
