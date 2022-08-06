//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use common::timer;
use crypto::prelude::TPayload;
use rpc::proto::gen_private_id::private_id_client::PrivateIdClient;
use rpc::proto::gen_private_id::Commitment;
use rpc::proto::gen_private_id::ServiceResponse;
use rpc::proto::gen_private_id::Step1Barrier;
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
    rpc: &mut PrivateIdClient<Channel>,
) -> Result<(), Status> {
    let t = timer::Builder::new().label(name.as_str()).build();

    let request = Request::new(response);
    let mut strm = match name.as_str() {
        "u_company" => rpc.recv_u_company(request).await?.into_inner(),
        "v_partner" => rpc.recv_v_partner(request).await?.into_inner(),
        "s_partner" => rpc.recv_s_partner(request).await?.into_inner(),
        "s_prime_company" => rpc.recv_s_prime_company(request).await?.into_inner(),
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
    rpc: &mut PrivateIdClient<Channel>,
) -> Result<Response<ServiceResponse>, Status> {
    match name.as_str() {
        "u_partner" => rpc.send_u_partner(send_data(data)).await,
        "e_company" => rpc.send_e_company(send_data(data)).await,
        "v_company" => rpc.send_v_company(send_data(data)).await,
        "s_prime_partner" => rpc.send_s_prime_partner(send_data(data)).await,
        _ => panic!("wrong data type"),
    }
}

pub async fn calculate_set_diff(
    barrier: Step1Barrier,
    rpc: &mut PrivateIdClient<Channel>,
) -> Result<Response<ServiceResponse>, Status> {
    rpc.calculate_set_diff(Request::new(barrier)).await
}

pub async fn reveal(rpc: &mut PrivateIdClient<Channel>) -> Result<(), Status> {
    let _r = rpc.reveal(Request::new(Commitment {})).await?.into_inner();
    Ok(())
}
