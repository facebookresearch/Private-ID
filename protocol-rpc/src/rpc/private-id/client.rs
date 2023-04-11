//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use clap::App;
use clap::Arg;
use clap::ArgGroup;
use common::gcs_path::GCSPath;
use common::metrics;
use common::s3_path::S3Path;
use common::timer;
use crypto::prelude::TPayload;
use log::info;
use protocol::private_id::partner::PartnerPrivateId;
use protocol::private_id::traits::*;
use rpc::connect::create_client::create_client;
use rpc::proto::gen_private_id::service_response::*;
use rpc::proto::gen_private_id::Init;
use rpc::proto::gen_private_id::ServiceResponse;
use rpc::proto::gen_private_id::Step1Barrier;
use rpc::proto::RpcClient;
use tonic::Request;

mod rpc_client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // todo: move matches outside, or move to build.rs
    let matches = App::new("Private Id Client")
        .version("0.1")
        .about("Private Id Protocol")
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
            Arg::with_name("metric-path")
                .long("metric-path")
                .takes_value(true)
                .help("Path to metric output file"),
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
            Arg::with_name("not-matched-value")
                .long("not-matched-value")
                .takes_value(true)
                .help("Override the default placeholder value for non-matched records"),
            Arg::with_name("run_id")
                .takes_value(true)
                .long("run_id")
                .default_value("")
                .help("A run_id used to identify all the logs in a PL/PA run."),
            Arg::with_name("use-row-numbers")
                .long("use-row-numbers")
                .takes_value(false)
                .help("Indicates if the output would consist row numbers instead of encrypted IDs"),
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
    let input_with_headers = matches.is_present("input-with-headers");
    let output_path = matches.value_of("output");
    let na_val = matches.value_of("not-matched-value");
    let use_row_numbers = matches.is_present("use-row-numbers");

    let metric_path = matches.value_of("metric-path");
    let metrics = metrics::Metrics::new("private-id-multi-key".to_string());
    let mut metrics_output_path: Option<String> = None;
    if let Some(val) = metric_path {
        metrics_output_path = Some(val.to_string());
    }

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
            "private-id".to_string(),
        ) {
            RpcClient::PrivateId(x) => x,
            _ => panic!("wrong client"),
        }
    };

    info!("Input path: {}", input_path);
    if output_path.is_some() {
        info!("Output path: {}", output_path.unwrap());
        if metrics_output_path.is_none() {
            metrics_output_path = Some(format!("{}_metrics", output_path.unwrap()));
        }
    } else {
        info!("Output view to stdout (first 10 items)");
    }

    // 1. Create partner protocol instance
    let partner_protocol = PartnerPrivateId::new();

    // 2. Load partner's data
    // 3. Generate permute pattern
    // 4. Permute data and hash
    partner_protocol
        .load_data(&input_path.to_string(), input_with_headers)
        .unwrap();
    partner_protocol.gen_permute_pattern().unwrap();
    let u_partner = partner_protocol.permute_hash_to_bytes().unwrap();
    metrics.set_partner_input_size(partner_protocol.get_size());

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
    let (e_company, v_company) = partner_protocol.encrypt_permute(u_company);
    metrics.set_publisher_input_size(e_company.len());

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

    // 9b. Send company's data back to company
    let ack_v_company =
        match rpc_client::send(v_company, "v_company".to_string(), &mut client_context)
            .await?
            .into_inner()
            .ack
            .unwrap()
        {
            Ack::VCompanyAck(x) => x,
            _ => panic!("wrong ack"),
        };

    let step1_barrier = Step1Barrier {
        u_partner_ack: Some(ack_u_partner),
        e_company_ack: Some(ack_e_company),
        v_company_ack: Some(ack_v_company),
    };

    // 10. Receive partner's back from company
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

    // 11. Calculate symmetric set difference between company and partners data
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

    // 12. Get data that partner has but company doesn't (send Sp to P)
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

    // 15. Create partner's ID spine and print
    partner_protocol.create_id_map(v_partner, s_prime_company, na_val);
    metrics.set_union_file_size(partner_protocol.get_id_map_size());
    match output_path {
        Some(p) => {
            if let Ok(output_path_s3) = S3Path::from_str(p) {
                let s3_tempfile = tempfile::NamedTempFile::new().unwrap();
                let (_file, path) = s3_tempfile.keep().unwrap();
                let path = path.to_str().expect("Failed to convert path to str");
                partner_protocol
                    .save_id_map(&String::from(path), input_with_headers, use_row_numbers)
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
                    .save_id_map(&String::from(path), input_with_headers, use_row_numbers)
                    .expect("Failed to save id map to tempfile");
                output_path_gcp
                    .copy_from_local(&path)
                    .await
                    .expect("Failed to write to GCS");
            } else {
                partner_protocol
                    .save_id_map(&String::from(p), input_with_headers, use_row_numbers)
                    .expect("Failed to save id map to output file");
            }
        }
        None => partner_protocol.print_id_map(10, input_with_headers, use_row_numbers),
    }
    match &metrics_output_path {
        Some(p) => {
            if let Ok(metrics_path_s3) = S3Path::from_str(p) {
                let s3_tempfile = tempfile::NamedTempFile::new().unwrap();
                let (_file, path) = s3_tempfile.keep().unwrap();
                let path = path.to_str().expect("Failed to convert path to str");
                metrics
                    .save_metrics(&String::from(path))
                    .expect("Failed to write metrics to tempfile");
                metrics_path_s3
                    .copy_from_local(&path)
                    .await
                    .expect("Failed to write to S3");
            } else {
                metrics
                    .save_metrics(p)
                    .expect("Failed to write to metrics path");
            }
        }
        None => {
            metrics.print_metrics();
        }
    }

    // 16. Create company's ID spine and print
    rpc_client::reveal(&mut client_context).await?;
    global_timer.qps("total time", partner_protocol.get_size());
    info!("Bye!");
    Ok(())
}
