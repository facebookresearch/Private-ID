//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate common;
extern crate crypto;
extern crate protocol;
extern crate rpc;

use common::timer;
use crypto::prelude::TPayload;
use rpc::proto::gen_pjc::pjc_client::PjcClient;
use rpc::proto::gen_pjc::Commitment;
use rpc::proto::gen_pjc::ServiceResponse;
use rpc::proto::gen_pjc::Stats;
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
    rpc: &mut PjcClient<Channel>,
) -> Result<(), Status> {
    let t = timer::Builder::new().label(name.as_str()).build();

    let request = Request::new(response);
    let mut strm = match name.as_str() {
        "u_company_keys" => rpc.recv_u_company_keys(request).await?.into_inner(),
        _ => panic!("wrong data type"),
    };

    let res = read_from_stream(&mut strm).await?;
    t.qps(format!("received {}", name.as_str()).as_str(), res.len());
    data.clear();
    data.extend(res);
    Ok(())
}

pub async fn send(
    data: TPayload,
    name: String,
    rpc: &mut PjcClient<Channel>,
) -> Result<Response<ServiceResponse>, Status> {
    match name.as_str() {
        "e_company_keys" => rpc.send_e_company_keys(send_data(data)).await,
        "u_partner_keys" => rpc.send_u_partner_keys(send_data(data)).await,
        "u_partner_feature" => rpc.send_u_partner_feature(send_data(data)).await,
        _ => panic!("wrong data type"),
    }
}

pub async fn recv_stats(rpc: &mut PjcClient<Channel>) -> Result<Response<Stats>, Status> {
    let _t = timer::Builder::new().label("recv_stats").build();
    rpc.recv_stats(Commitment {}).await
}
