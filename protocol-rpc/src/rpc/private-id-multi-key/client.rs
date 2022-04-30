//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate clap;
extern crate common;
extern crate crypto;
extern crate ctrlc;
extern crate protocol;
extern crate retry;
extern crate rpc;
extern crate tonic;

use clap::{App, Arg, ArgGroup};
use log::info;
use std::convert::TryInto;
use tonic::Request;

use common::{gcs_path::GCSPath, s3_path::S3Path, timer};
use crypto::prelude::TPayload;
use protocol::private_id_multi_key::{partner::PartnerPrivateIdMultiKey, traits::*};
use rpc::{
    connect::create_client::create_client,
    proto::{
        gen_private_id_multi_key::{service_response::*, Init, ServiceResponse, Step1Barrier},
        RpcClient,
    },
};
use std::str::FromStr;

mod rpc_client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // todo: move matches outside, or move to build.rs
    let matches = App::new("Private Id MultiKey Client")
        .version("0.1")
        .about("Private Id Multi Key Protocol")
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
            Arg::with_name("input-with-headers")
                .long("input-with-headers")
                .takes_value(false)
                .help("Indicates if the input CSV contains headers"),
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
                .requires("tls-key")
                .requires("tls-cert")
                .help("Path to root CA certificate issued cert and keys"),
            Arg::with_name("tls-domain")
                .long("tls-domain")
                .takes_value(true)
                .help("Override TLS domain for SSL cert (if host is IP)"),
        ])
        .groups(&[
            ArgGroup::with_name("tls")
                .args(&["no-tls", "tls-dir", "tls-key"])
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
    let input_with_headers = matches.is_present("input-with-headers");
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
            "private-id-multi-key".to_string(),
        ) {
            RpcClient::PrivateIdMultiKey(x) => x,
            _ => panic!("wrong client"),
        }
    };

    info!("Input path: {}", input_path);
    if output_path.is_some() {
        info!("Output path: {}", output_path.unwrap());
    } else {
        info!("Output view to stdout (first 10 items)");
    }

    // 1. Create partner protocol instance
    let partner_protocol = PartnerPrivateIdMultiKey::new();

    // 2. Load partner's data
    // 3. Generate permute pattern
    // 4. Permute data and hash
    partner_protocol
        .load_data(&input_path.to_string(), input_with_headers)
        .unwrap();
    let u_partner = partner_protocol.permute_hash_to_bytes().unwrap();

    // 5. Initialize company - this loads company's data and generates its permutation pattern
    let init_ack = match client_context
        .initialize(Request::new(Init {}))
        .await?
        .into_inner()
        .ack
        .unwrap()
    {
        Ack::InitAck(x) => x,
        _ => panic!("wrong ack"),
    };

    // 6. Get data from company
    let mut u_company = TPayload::new();
    let _ = rpc_client::recv(
        ServiceResponse {
            ack: Some(Ack::InitAck(init_ack.clone())),
        },
        "u_company".to_string(),
        &mut u_company,
        &mut client_context,
    )
    .await?;

    // 7. Permute and encrypt data from company with own keys
    let e_company = {
        let offset_len = u64::from_le_bytes(
            u_company
                .pop()
                .unwrap()
                .buffer
                .as_slice()
                .try_into()
                .unwrap(),
        ) as usize;
        let data_len = u64::from_le_bytes(
            u_company
                .pop()
                .unwrap()
                .buffer
                .as_slice()
                .try_into()
                .unwrap(),
        ) as usize;

        let offset = u_company
            .drain(data_len..)
            .map(|b| u64::from_le_bytes(b.buffer.as_slice().try_into().unwrap()) as usize)
            .collect::<Vec<_>>();
        u_company.shrink_to_fit();

        assert_eq!(offset_len, offset.len());
        partner_protocol.encrypt_permute(u_company, offset).unwrap()
    };

    // 8. Send partner's data to company
    let ack_u_partner =
        match rpc_client::send(u_partner, "u_partner".to_string(), &mut client_context)
            .await?
            .into_inner()
            .ack
            .unwrap()
        {
            Ack::UPartnerAck(x) => x,
            _ => panic!("wrong ack"),
        };

    // 9a. Send company's data back to company
    let ack_e_company =
        match rpc_client::send(e_company, "e_company".to_string(), &mut client_context)
            .await?
            .into_inner()
            .ack
            .unwrap()
        {
            Ack::ECompanyAck(x) => x,
            _ => panic!("wrong ack"),
        };

    let step1_barrier = Step1Barrier {
        u_partner_ack: Some(ack_u_partner),
        e_company_ack: Some(ack_e_company),
    };

    // 10. Calculate symmetric set difference between company and partners data
    let calculate_set_diff_ack =
        match rpc_client::calculate_set_diff(step1_barrier.clone(), &mut client_context)
            .await?
            .into_inner()
            .ack
            .unwrap()
        {
            Ack::CalculateSetDiffAck(x) => x,
            _ => panic!("wrong ack"),
        };

    // 11. Receive company's keys back from company
    let mut v_company = TPayload::new();
    let _ = rpc_client::recv(
        ServiceResponse {
            ack: Some(Ack::Step1Barrier(step1_barrier.clone())),
        },
        "v_company".to_string(),
        &mut v_company,
        &mut client_context,
    )
    .await?;

    // 11. Receive partner's keys back from company
    let mut v_partner = TPayload::new();
    let _ = rpc_client::recv(
        ServiceResponse {
            ack: Some(Ack::Step1Barrier(step1_barrier.clone())),
        },
        "v_partner".to_string(),
        &mut v_partner,
        &mut client_context,
    )
    .await?;

    // 12. Get data that partner has but company doesn't
    let mut s_partner = TPayload::new();
    let _ = rpc_client::recv(
        ServiceResponse {
            ack: Some(Ack::CalculateSetDiffAck(calculate_set_diff_ack.clone())),
        },
        "s_partner".to_string(),
        &mut s_partner,
        &mut client_context,
    )
    .await?;

    // 13. Get data that company has but partner doesn't
    let mut s_prime_company = TPayload::new();
    let _ = rpc_client::recv(
        ServiceResponse {
            ack: Some(Ack::CalculateSetDiffAck(calculate_set_diff_ack.clone())),
        },
        "s_prime_company".to_string(),
        &mut s_prime_company,
        &mut client_context,
    )
    .await?;

    // 14. Encrypt and send back data that partner has company doesn't
    //     Generates s_prime_partner in-place
    let _ = rpc_client::send(
        partner_protocol.encrypt(s_partner)?,
        "s_prime_partner".to_string(),
        &mut client_context,
    )
    .await?
    .into_inner()
    .ack
    .unwrap();

    // 15. Unshuffle, encrypt and send back company
    //     Generates w_company in-place
    let _ = rpc_client::send(
        partner_protocol.unshuffle_encrypt(v_company)?,
        "w_company".to_string(),
        &mut client_context,
    )
    .await?
    .into_inner()
    .ack
    .unwrap();

    // 16. Create partner's ID spine and print
    partner_protocol.create_id_map(v_partner, s_prime_company);
    match output_path {
        Some(p) => {
            if let Ok(output_path_s3) = S3Path::from_str(p) {
                let s3_tempfile = tempfile::NamedTempFile::new().unwrap();
                let (_file, path) = s3_tempfile.keep().unwrap();
                let path = path.to_str().expect("Failed to convert path to str");
                partner_protocol
                    .save_id_map(&String::from(path))
                    .expect("Failed to save id map to tempfile");
                output_path_s3
                    .copy_from_local(&path)
                    .await
                    .expect("Failed to write to S3");
            } else if let Ok(output_path_gcp) = GCSPath::from_str(p) {
                let gcs_tempfile = tempfile::NamedTempFile::new().unwrap();
                let (_file, path) = gcs_tempfile.keep().unwrap();
                let path = path.to_str().expect("Failed to convert path to str");
                partner_protocol
                    .save_id_map(&String::from(path))
                    .expect("Failed to save id map to tempfile");
                output_path_gcp
                    .copy_from_local(&path)
                    .await
                    .expect("Failed to write to GCS");
            } else {
                partner_protocol
                    .save_id_map(&String::from(p))
                    .expect("Failed to save id map to output file");
            }
        }
        None => partner_protocol.print_id_map(),
    }

    // 17. Create company's ID spine and print
    rpc_client::reveal(&mut client_context).await?;
    global_timer.qps("total time", partner_protocol.get_size());
    info!("Bye!");
    Ok(())
}
