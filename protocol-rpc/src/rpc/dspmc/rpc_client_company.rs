//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate common;
extern crate crypto;
extern crate protocol;

use common::timer;
use crypto::prelude::TPayload;
use rpc::proto::gen_dspmc_company::dspmc_company_client::DspmcCompanyClient;
use rpc::proto::gen_dspmc_company::Commitment;
use rpc::proto::gen_dspmc_company::ServiceResponse;
use rpc::proto::streaming::read_from_stream;
use rpc::proto::streaming::send_data;
use tonic::transport::Channel;
use tonic::Request;
use tonic::Response;
use tonic::Status;

pub async fn send(
    data: TPayload,
    name: String,
    rpc: &mut DspmcCompanyClient<Channel>,
) -> Result<Response<ServiceResponse>, Status> {
    match name.as_str() {
        "helper_public_key" => rpc.send_helper_public_key(send_data(data)).await,
        "p_sc_v_sc_ct1_ct2_dprime" => rpc.send_p_sc_v_sc_ct1ct2dprime(send_data(data)).await,
        _ => panic!("wrong data type"),
    }
}

pub async fn recv(
    response: ServiceResponse,
    name: String,
    data: &mut TPayload,
    rpc: &mut DspmcCompanyClient<Channel>,
) -> Result<(), Status> {
    let t = timer::Builder::new().label(name.as_str()).build();

    let request = Request::new(response);
    let mut strm = match name.as_str() {
        "company_public_key" => rpc.recv_company_public_key(request).await?.into_inner(),
        "p_cs_v_cs" => rpc.recv_p_cs_v_cs(request).await?.into_inner(),
        "u_company" => rpc.recv_u_company(request).await?.into_inner(),
        _ => panic!("wrong data type"),
    };

    let res = read_from_stream(&mut strm).await?;
    t.qps(format!("received {}", name.as_str()).as_str(), res.len());
    data.clear();
    data.extend(res);
    Ok(())
}

pub async fn calculate_id_map(rpc: &mut DspmcCompanyClient<Channel>) -> Result<(), Status> {
    let _r = rpc
        .calculate_id_map(Request::new(Commitment {}))
        .await?
        .into_inner();
    Ok(())
}
