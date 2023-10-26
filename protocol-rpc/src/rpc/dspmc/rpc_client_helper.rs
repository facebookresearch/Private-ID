//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate common;
extern crate crypto;
extern crate protocol;

use common::timer;
use crypto::prelude::TPayload;
use rpc::proto::gen_dspmc_helper::dspmc_helper_client::DspmcHelperClient;
use rpc::proto::gen_dspmc_helper::Commitment;
use rpc::proto::gen_dspmc_helper::ServiceResponse;
use rpc::proto::streaming::read_from_stream;
use rpc::proto::streaming::send_data;
use tonic::transport::Channel;
use tonic::Request;
use tonic::Response;
use tonic::Status;

pub async fn send(
    data: TPayload,
    name: String,
    rpc: &mut DspmcHelperClient<Channel>,
) -> Result<Response<ServiceResponse>, Status> {
    match name.as_str() {
        "company_public_key" => rpc.send_company_public_key(send_data(data)).await,
        "p_sd_v_sd" => rpc.send_p_sd_v_sd(send_data(data)).await,
        "encrypted_vprime" => rpc.send_encrypted_vprime(send_data(data)).await,
        _ => panic!("wrong data type"),
    }
}

pub async fn recv(
    response: ServiceResponse,
    name: String,
    data: &mut TPayload,
    rpc: &mut DspmcHelperClient<Channel>,
) -> Result<(), Status> {
    let t = timer::Builder::new().label(name.as_str()).build();

    let request = Request::new(response);
    let mut strm = match name.as_str() {
        "helper_public_key" => rpc.recv_helper_public_key(request).await?.into_inner(),
        "u2" => rpc.recv_u2(request).await?.into_inner(),
        _ => panic!("wrong data type"),
    };

    let res = read_from_stream(&mut strm).await?;
    t.qps(format!("received {}", name.as_str()).as_str(), res.len());
    data.clear();
    data.extend(res);
    Ok(())
}

pub async fn calculate_id_map(rpc: &mut DspmcHelperClient<Channel>) -> Result<(), Status> {
    let _r = rpc
        .calculate_id_map(Request::new(Commitment {}))
        .await?
        .into_inner();
    Ok(())
}

pub async fn reveal(rpc: &mut DspmcHelperClient<Channel>) -> Result<(), Status> {
    let _r = rpc.reveal(Request::new(Commitment {})).await?.into_inner();
    Ok(())
}

pub async fn stop_service(rpc: &mut DspmcHelperClient<Channel>) -> Result<(), Status> {
    let _r = rpc
        .stop_service(Request::new(Commitment {}))
        .await?
        .into_inner();
    Ok(())
}
