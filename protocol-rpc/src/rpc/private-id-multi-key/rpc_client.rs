//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate common;
extern crate crypto;
extern crate protocol;

use tonic::{transport::Channel, Request, Response, Status};

use common::timer;
use crypto::prelude::TPayload;
use rpc::proto::{
    gen_private_id_multi_key::{
        private_id_multi_key_client::PrivateIdMultiKeyClient, Commitment, ServiceResponse,
        Step1Barrier,
    },
    streaming::{read_from_stream, send_data},
};

pub async fn recv(
    response: ServiceResponse,
    name: String,
    data: &mut TPayload,
    rpc: &mut PrivateIdMultiKeyClient<Channel>,
) -> Result<(), Status> {
    let t = timer::Builder::new().label(name.as_str()).build();

    let request = Request::new(response);
    let mut strm = match name.as_str() {
        "u_company" => rpc.recv_u_company(request).await?.into_inner(),
        "v_company" => rpc.recv_v_company(request).await?.into_inner(),
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
    rpc: &mut PrivateIdMultiKeyClient<Channel>,
) -> Result<Response<ServiceResponse>, Status> {
    match name.as_str() {
        "u_partner" => rpc.send_u_partner(send_data(data)).await,
        "e_company" => rpc.send_e_company(send_data(data)).await,
        "s_prime_partner" => rpc.send_s_prime_partner(send_data(data)).await,
        "w_company" => rpc.send_w_company(send_data(data)).await,
        _ => panic!("wrong data type"),
    }
}

pub async fn calculate_set_diff(
    barrier: Step1Barrier,
    rpc: &mut PrivateIdMultiKeyClient<Channel>,
) -> Result<Response<ServiceResponse>, Status> {
    rpc.calculate_set_diff(Request::new(barrier)).await
}

pub async fn reveal(rpc: &mut PrivateIdMultiKeyClient<Channel>) -> Result<(), Status> {
    let _r = rpc.reveal(Request::new(Commitment {})).await?.into_inner();
    Ok(())
}
