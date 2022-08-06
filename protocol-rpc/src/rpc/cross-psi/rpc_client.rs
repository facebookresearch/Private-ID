//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use common::timer;
use crypto::prelude::TPayload;
use rpc::proto::gen_crosspsi::cross_psi_client::CrossPsiClient;
use rpc::proto::gen_crosspsi::Commitment;
use rpc::proto::gen_crosspsi::CommitmentAck;
use rpc::proto::gen_crosspsi::ServiceResponse;
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
    rpc: &mut CrossPsiClient<Channel>,
) -> Result<(), Status> {
    let t = timer::Builder::new().label(name.as_str()).build();

    let request = Request::new(response);
    let mut strm = match name.as_str() {
        "u_company_keys" => rpc.recv_u_company_keys(request).await?.into_inner(),
        "u_company_feature" => rpc.recv_u_company_feature(request).await?.into_inner(),
        "shares_company_indices" => rpc.recv_shares_company_indices(request).await?.into_inner(),
        "shares_feature" => rpc.recv_shares_feature(request).await?.into_inner(),
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
    rpc: &mut CrossPsiClient<Channel>,
) -> Result<Response<ServiceResponse>, Status> {
    match name.as_str() {
        "e_company_keys" => rpc.send_e_company_keys(send_data(data)).await,
        "e_company_feature" => rpc.send_e_company_feature(send_data(data)).await,
        "u_partner_keys" => rpc.send_u_partner_keys(send_data(data)).await,
        "u_partner_feature" => rpc.send_u_partner_feature(send_data(data)).await,
        _ => panic!("wrong data type"),
    }
}

/// Reveals outputs
pub async fn reveal(rpc: &mut CrossPsiClient<Channel>) -> Result<CommitmentAck, Status> {
    let r: CommitmentAck = rpc.reveal(Request::new(Commitment {})).await?.into_inner();
    Ok(r)
}
