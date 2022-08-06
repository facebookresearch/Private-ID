//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate common;
extern crate crypto;
extern crate protocol;

use common::timer;
use crypto::prelude::TPayload;
use rpc::proto::gen_suid_create::suid_create_client::SuidCreateClient;
use rpc::proto::gen_suid_create::Commitment;
use rpc::proto::gen_suid_create::ServiceResponse;
use rpc::proto::gen_suid_create::Step1Barrier;
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
    rpc: &mut SuidCreateClient<Channel>,
) -> Result<(), Status> {
    let t = timer::Builder::new().label(name.as_str()).build();

    let request = Request::new(response);
    let mut strm = match name.as_str() {
        "public_key_m" => rpc.recv_public_key_m(request).await?.into_inner(),
        "party_merger" => rpc.recv_party_merger(request).await?.into_inner(),
        "suids" => rpc.recv_suids(request).await?.into_inner(),
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
    rpc: &mut SuidCreateClient<Channel>,
) -> Result<Response<ServiceResponse>, Status> {
    match name.as_str() {
        "sharer_public_key_reuse" => rpc.send_sharer_public_key_reuse(send_data(data)).await,
        "encrypted_keys_to_merge" => rpc.send_encrypted_keys_to_merge(send_data(data)).await,
        "suids_party_merger" => rpc.send_suids_party_merger(send_data(data)).await,
        _ => panic!("wrong data type"),
    }
}

pub async fn calculate_suids(
    barrier: Step1Barrier,
    rpc: &mut SuidCreateClient<Channel>,
) -> Result<Response<ServiceResponse>, Status> {
    rpc.calculate_suids(Request::new(barrier)).await
}

pub async fn reveal(rpc: &mut SuidCreateClient<Channel>) -> Result<(), Status> {
    let _r = rpc.reveal(Request::new(Commitment {})).await?.into_inner();
    Ok(())
}
