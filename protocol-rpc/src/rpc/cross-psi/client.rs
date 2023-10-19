//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use clap::App;
use clap::Arg;
use clap::ArgGroup;
use common::timer;
use crypto::prelude::ByteBuffer;
use crypto::prelude::TPayload;
use crypto::prelude::TypeHeEncKey;
use log::info;
use tonic::Request;
mod rpc_client;
use protocol::cross_psi::partner::PartnerCrossPsi;
use protocol::cross_psi::traits::*;
use protocol::shared::*;
use rpc::connect::create_client::create_client;
use rpc::proto::common::Payload;
use rpc::proto::gen_crosspsi::service_response::*;
use rpc::proto::gen_crosspsi::FeatureQuery;
use rpc::proto::gen_crosspsi::Init;
use rpc::proto::gen_crosspsi::ServiceResponse;
use rpc::proto::gen_crosspsi::SharesQuery;
use rpc::proto::gen_crosspsi::Step1Barrier;
use rpc::proto::RpcClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // todo: move matches outside, or move to build.rs
    let matches = App::new("Cross PSI Client")
        .version("0.1")
        .about("Cross PSI Protocol")
        .args(&[
            Arg::with_name("company")
                .long("company")
                .short("c")
                .takes_value(true)
                .required(true)
                .help("Host path to connect to, ex: 0.0.0.0:10009"),
            Arg::with_name("input")
                .long("input")
                .short("i")
                .default_value("input.csv")
                .help("Path to input file with keys"),
            Arg::with_name("output")
                .long("output")
                .short("o")
                .takes_value(true)
                .help("Path to output file, output format: private-id, option(key)"),
            Arg::with_name("stdout")
                .long("stdout")
                .short("u")
                .takes_value(false)
                .help("Prints the output to stdout rather than file"),
            Arg::with_name("no-tls")
                .long("no-tls")
                .takes_value(false)
                .help("Turns tls off"),
            Arg::with_name("tls-dir")
                .long("tls-dir")
                .takes_value(true)
                .help(
                    "Path to directory with files with key, cert and ca.pem file\n
                    client: client.key, client.pem, ca.pem \n
                    server: server.key, server.pem, ca.pem \n
                ",
                ),
            Arg::with_name("tls-key")
                .long("tls-key")
                .takes_value(true)
                .requires("tls-cert")
                .requires("tls-ca")
                .help("Path to tls key (non-encrypted)"),
            Arg::with_name("tls-cert")
                .long("tls-cert")
                .takes_value(true)
                .requires("tls-key")
                .requires("tls-ca")
                .help(
                    "Path to tls certificate (pem format), SINGLE cert, \
                     NO CHAINING, required by client as well",
                ),
            Arg::with_name("tls-ca")
                .long("tls-ca")
                .takes_value(true)
                .help("Path to root CA certificate issued cert and keys"),
            Arg::with_name("tls-domain")
                .long("tls-domain")
                .takes_value(true)
                .help("Override TLS domain for SSL cert (if host is IP)"),
        ])
        .groups(&[
            ArgGroup::with_name("tls")
                .args(&["no-tls", "tls-dir", "tls-ca"])
                .required(true),
            ArgGroup::with_name("out")
                .args(&["output", "stdout"])
                .required(true),
        ])
        .get_matches();

    let global_timer = timer::Timer::new_silent("global");
    let input_path = matches.value_of("input").unwrap_or("input.csv");
    let output_path = matches.value_of("output");

    let mut client_context = {
        let no_tls = matches.is_present("no-tls");
        let host_pre = matches.value_of("company");
        let tls_dir = matches.value_of("tls-dir");
        let tls_key = matches.value_of("tls-key");
        let tls_cert = matches.value_of("tls-cert");
        let tls_ca = matches.value_of("tls-ca");
        let tls_domain = matches.value_of("tls-domain");

        match create_client(
            no_tls,
            host_pre,
            tls_dir,
            tls_key,
            tls_cert,
            tls_ca,
            tls_domain,
            "cross-psi".to_string(),
        ) {
            RpcClient::CrossPsi(x) => x,
            _ => panic!("wrong client"),
        }
    };

    // 1. Create partner protocol instance
    let partner_protocol = PartnerCrossPsi::new();

    // 2. Load partner's data
    partner_protocol.load_data(input_path);

    // 3a. Key exchange for Paillier public keys
    // 3b. Exchange number of features and number of records
    let init_ack = {
        let req = Request::new(Init {
            partner_public_key: Some(Payload::from(&partner_protocol.get_he_public_key())),
            partner_num_features: partner_protocol.get_self_num_features() as u64,
            partner_num_records: partner_protocol.get_self_num_records() as u64,
        });

        let ack = client_context.key_exchange(req).await?.into_inner();
        let res = ack.clone();

        let company_he_public_key = TypeHeEncKey::from(&ack.company_public_key.unwrap());
        partner_protocol.set_company_num_features(ack.company_num_features as usize);
        partner_protocol.set_company_num_records(ack.company_num_records as usize);
        // TODO: Remove clone and consume
        partner_protocol.set_company_he_public_key(company_he_public_key);

        info!(
            "Number of company features {}",
            partner_protocol.get_company_num_features()
        );

        res
    };

    // 4. Get keys from company. These are the keys on which intersection
    //    will happen
    let mut u_company_keys = TPayload::new();
    let _ = rpc_client::recv(
        ServiceResponse {
            ack: Some(Ack::InitAck(init_ack)),
        },
        "u_company_keys".to_string(),
        &mut u_company_keys,
        &mut client_context,
    )
    .await?;

    // 5. Generate permutation pattern
    partner_protocol.fill_permute_company(u_company_keys.len());

    // 6. Permute the keys with the permutation pattern generated
    partner_protocol.permute(u_company_keys.as_mut());

    // 7. Encrypt (Elliptic curve) company's keys with partner's key
    //    Send them to company
    let e_company_keys = partner_protocol.encrypt(u_company_keys);
    let _ = rpc_client::send(
        e_company_keys,
        "e_company_keys".to_string(),
        &mut client_context,
    )
    .await?
    .into_inner()
    .ack
    .unwrap();

    // 8. Generate additive shares of company features
    for feature_index in 0..partner_protocol.get_company_num_features() {
        // 8a. Get feature from company
        let mut u_company_feature = TPayload::new();
        let _ = rpc_client::recv(
            ServiceResponse {
                ack: Some(Ack::FeatureQuery(FeatureQuery {
                    feature_index: feature_index as u64,
                })),
            },
            "u_company_feature".to_string(),
            &mut u_company_feature,
            &mut client_context,
        )
        .await?;

        // 8b. Permute with the same permutation as keys
        partner_protocol.permute(u_company_feature.as_mut());

        // 8c. Generate additive shares of feature through additive
        //     Homomorphic Encryption scheme - Paillier in this case
        let mut feature_additive_share =
            partner_protocol.generate_additive_shares(feature_index, u_company_feature);
        feature_additive_share.push(ByteBuffer {
            buffer: (feature_index as u64).to_le_bytes().to_vec(),
        });

        // 8d. Send additive share to company
        let ack = match rpc_client::send(
            feature_additive_share,
            "e_company_feature".to_string(),
            &mut client_context,
        )
        .await?
        .into_inner()
        .ack
        .unwrap()
        {
            Ack::FeatureAck(x) => x,
            _ => panic!("wrong ack"),
        };

        info!(
            "e_company_ack feature index {}",
            ack.query_ack.unwrap().feature_index
        );
    }

    // 9. Send partner's keys to company
    // 9a. Generate permutation pattern to permute keys
    partner_protocol.fill_permute_self();
    let u_partner_keys = partner_protocol.get_permuted_keys();
    let _ = rpc_client::send(
        u_partner_keys,
        "u_partner_keys".to_string(),
        &mut client_context,
    )
    .await?
    .into_inner()
    .ack
    .unwrap();

    // 10. Send partner's feature to company
    for feature_index in 0..partner_protocol.get_self_num_features() {
        // 10a. Get partner's feature
        let mut u_partner_feature = partner_protocol.get_permuted_features(feature_index);

        // 10b. Append feature index
        u_partner_feature.push(ByteBuffer {
            buffer: (feature_index as u64).to_le_bytes().to_vec(),
        });

        // 10c. Send partner's feature to company
        let ack = match rpc_client::send(
            u_partner_feature,
            "u_partner_feature".to_string(),
            &mut client_context,
        )
        .await?
        .into_inner()
        .ack
        .unwrap()
        {
            Ack::FeatureAck(x) => x,
            _ => panic!("wrong ack"),
        };

        info!(
            "e_company_ack feature_index {}",
            ack.query_ack.unwrap().feature_index
        );
    }

    // TODO: Decide if we need the dummy barrier
    let dummy_barrier = Step1Barrier {
        u_partner_keys_ack: None,
        u_partner_ack: None,
        e_partner_ack: None,
    };
    let t = timer::Builder::new().label("indices").silent(true).build();

    // 11. Receive boolean flag for elements that are common to both partner
    //     and company
    let company_indices = {
        let mut payload = TPayload::new();
        let _ = rpc_client::recv(
            ServiceResponse {
                ack: Some(Ack::Step1Barrier(dummy_barrier.clone())),
            },
            "shares_company_indices".to_string(),
            &mut payload,
            &mut client_context,
        )
        .await?;

        payload
            .iter()
            .map(|x| u64::from_le_bytes(x.buffer.as_slice().try_into().unwrap()) as usize)
            .collect::<Vec<usize>>()
    };
    t.qps("recv company intersection indices", company_indices.len());

    info!("company intersection size: {}", company_indices.len());

    // 12. Save indices to compute intersection
    partner_protocol.set_company_intersection_indices(company_indices);

    // 13. Receive and save additive shares for partner's features
    for feature_index in 0..partner_protocol.get_self_num_features() {
        let query = SharesQuery {
            query: Some(FeatureQuery {
                feature_index: feature_index as u64,
            }),
            barrier: Some(dummy_barrier.clone()),
        };
        // 13a. Receive additive shares for partner's features
        let mut feature = TPayload::new();
        let _ = rpc_client::recv(
            ServiceResponse {
                ack: Some(Ack::SharesQuery(query)),
            },
            "shares_feature".to_string(),
            &mut feature,
            &mut client_context,
        )
        .await?;
        let feature_len = feature.len();

        // 13a. Save additive shares for
        partner_protocol.set_self_shares(feature_index, feature);

        t.qps(
            format!("recv shares for feature {}", feature_index).as_str(),
            feature_len,
        )
    }

    // 14. Request company to output shares to file
    let _ = rpc_client::reveal(&mut client_context).await?;

    // 15. Request partner to output shares to file
    partner_protocol.reveal(output_path.unwrap());

    global_timer.qps(
        "total time",
        partner_protocol.get_self_num_features() * partner_protocol.get_self_num_records(),
    );
    Ok(())
}
