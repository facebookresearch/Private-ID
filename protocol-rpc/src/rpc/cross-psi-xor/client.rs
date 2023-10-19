//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate clap;
extern crate common;
extern crate ctrlc;
extern crate protocol;
extern crate retry;
extern crate rpc;
extern crate tonic;

use std::str::FromStr;

use clap::App;
use clap::Arg;
use clap::ArgGroup;
use common::gcs_path::GCSPath;
use common::s3_path::S3Path;
use common::timer;
use crypto::prelude::TPayload;
use itertools::Itertools;
use log::info;
use tonic::Request;
mod rpc_client;
use protocol::cross_psi_xor::partner::PartnerCrossPsiXOR;
use protocol::cross_psi_xor::traits::*;
use protocol::shared::*;
use rpc::connect::create_client::create_client;
use rpc::proto::gen_crosspsi_xor::service_response::*;
use rpc::proto::gen_crosspsi_xor::FeatureQuery;
use rpc::proto::gen_crosspsi_xor::Init;
use rpc::proto::gen_crosspsi_xor::ServiceResponse;
use rpc::proto::gen_crosspsi_xor::SharesQuery;
use rpc::proto::gen_crosspsi_xor::Step1Barrier;
use rpc::proto::RpcClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // todo: move matches outside, or move to build.rs
    let matches = App::new("Cross PSI XOR Client")
        .version("0.1")
        .about("Cross PSI XOR Protocol")
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
    let input_path_str = matches.value_of("input").unwrap_or("input.csv");
    let mut input_path = input_path_str.to_string();
    if let Ok(s3_path) = S3Path::from_str(input_path_str) {
        info!(
            "Reading {} from S3 and copying to local path",
            input_path_str
        );
        let local_path = s3_path
            .copy_to_local()
            .await
            .expect("Failed to copy s3 path to local tempfile");
        info!("Wrote {} to tempfile {}", input_path_str, local_path);
        input_path = local_path;
    } else if let Ok(gcs_path) = GCSPath::from_str(input_path_str) {
        info!(
            "Reading {} from GCS and copying to local path",
            input_path_str
        );
        let local_path = gcs_path
            .copy_to_local()
            .await
            .expect("Failed to copy GCS path to local tempfile");
        info!("Wrote {} to tempfile {}", input_path_str, local_path);
        input_path = local_path;
    }
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
            "cross-psi-xor".to_string(),
        ) {
            RpcClient::CrossPsiXor(x) => x,
            _ => panic!("wrong client"),
        }
    };

    // 1. Create partner protocol instance
    let partner_protocol = PartnerCrossPsiXOR::new();

    // 2. Load partner's data
    partner_protocol.load_data(input_path);

    // 3a. Key exchange for Paillier public keys
    // 3b. Exchange number of features and number of records
    let init_ack = {
        let req = Request::new(Init {
            partner_num_features: partner_protocol.get_self_num_features() as u64,
            partner_num_records: partner_protocol.get_self_num_records() as u64,
        });

        let ack = client_context.key_exchange(req).await?.into_inner();
        let res = ack.clone();

        partner_protocol.set_company_num_features(ack.company_num_features as usize);
        partner_protocol.set_company_num_records(ack.company_num_records as usize);

        info!(
            "Number of company features {} and records {}",
            partner_protocol.get_company_num_features(),
            partner_protocol.get_company_num_records(),
        );

        info!(
            "Number of partner features {} and records {}",
            partner_protocol.get_self_num_features(),
            partner_protocol.get_self_num_records(),
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
    let (u_company_features, num_features_company) = {
        // 8a. Get feature from company
        let (mut features, num_features) = {
            let mut data = TPayload::new();
            let _ = rpc_client::recv(
                ServiceResponse {
                    ack: Some(Ack::FeatureQuery(FeatureQuery {})),
                },
                "u_company_features".to_string(),
                &mut data,
                &mut client_context,
            )
            .await?;

            let num_features =
                u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap())
                    as usize;
            let num_ciphers =
                u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap())
                    as usize;
            let num_entries =
                u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap())
                    as usize;

            assert_eq!(num_ciphers * num_entries, data.len());
            let features: Vec<TPayload> = data
                .into_iter()
                .chunks(num_entries)
                .into_iter()
                .map(|x| x.collect_vec())
                .collect_vec();
            assert_eq!(features.len(), num_ciphers);

            (features, num_features)
        };

        //8b. Permute with same permutation as company keys
        for i in 0..features.len() {
            partner_protocol.permute(features[i].as_mut());
        }

        (features, num_features)
    };

    // 8c. Generate and send additive share to company
    let _ = match rpc_client::send(
        partner_protocol.get_additive_shares(u_company_features, num_features_company),
        "e_company_features".to_string(),
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

    // 10. Send partner's features to company
    let _ = match rpc_client::send(
        partner_protocol.get_permuted_features(),
        "u_partner_features".to_string(),
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
    {
        let query = SharesQuery {
            query: Some(FeatureQuery {}),
            barrier: Some(dummy_barrier.clone()),
        };

        // 13a. Receive additive shares for partner's features
        let mut data = TPayload::new();
        let _ = rpc_client::recv(
            ServiceResponse {
                ack: Some(Ack::SharesQuery(query)),
            },
            "shares_features".to_string(),
            &mut data,
            &mut client_context,
        )
        .await?;

        let num_features =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;
        let num_ciphers =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;
        let num_entries =
            u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;

        assert_eq!(num_ciphers * num_entries, data.len());
        let features: Vec<TPayload> = data
            .into_iter()
            .chunks(num_entries)
            .into_iter()
            .map(|x| x.collect_vec())
            .collect_vec();
        assert_eq!(features.len(), num_ciphers);

        // 13a. Save additive shares for
        partner_protocol.set_self_shares(features, num_features);

        t.qps(format!("recv shares for features").as_str(), num_entries)
    }

    // 14. Request company to output shares to file
    let _ = rpc_client::reveal(&mut client_context).await?;

    // 15. Request partner to output shares to file
    match output_path {
        Some(p) => {
            if let Ok(output_path_s3) = S3Path::from_str(p) {
                let s3_tempfile = tempfile::NamedTempFile::new().unwrap();
                let (_file, tmp_path) = s3_tempfile.keep().unwrap();
                let tmp_path = tmp_path.to_str().expect("Failed to convert path to str");
                partner_protocol.reveal(tmp_path);
                output_path_s3
                    .copy_from_local(&tmp_path)
                    .await
                    .expect("Failed to write to S3");
            } else if let Ok(output_path_gcp) = GCSPath::from_str(p) {
                let gcs_tempfile = tempfile::NamedTempFile::new().unwrap();
                let (_file, tmp_path) = gcs_tempfile.keep().unwrap();
                let tmp_path = tmp_path.to_str().expect("Failed to convert path to str");
                partner_protocol.reveal(tmp_path);
                output_path_gcp
                    .copy_from_local(&tmp_path)
                    .await
                    .expect("Failed to write to GCS");
            } else {
                partner_protocol.reveal(p);
            }
        }
        None => partner_protocol.reveal(output_path.unwrap()),
    }

    global_timer.qps(
        "total time",
        partner_protocol.get_self_num_features() * partner_protocol.get_self_num_records(),
    );
    Ok(())
}
