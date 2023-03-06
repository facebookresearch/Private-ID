//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use clap::App;
use clap::Arg;
use clap::ArgGroup;
use common::timer;
use crypto::prelude::TPayload;
use log::info;
use protocol::suid_create::sharer::SUIDCreateSharer;
use protocol::suid_create::traits::*;
use rpc::connect::create_client::create_client;
use rpc::proto::gen_suid_create::service_response::*;
use rpc::proto::gen_suid_create::Init;
use rpc::proto::gen_suid_create::ServiceResponse;
use rpc::proto::gen_suid_create::Step1Barrier;
use rpc::proto::RpcClient;
use tonic::Request;

mod rpc_client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // todo: move matches outside, or move to build.rs
    let matches = App::new("SUID Create Sharer (Client)")
        .version("0.1")
        .about("SUID Create Protocol")
        .args(&[
            Arg::with_name("merger")
                .long("merger")
                .short("c")
                .takes_value(true)
                .required(true)
                .help("Host path to connect to, ex: 0.0.0.0:10009"),
            Arg::with_name("input")
                .long("input")
                .short("i")
                .required(true)
                .multiple(true)
                .number_of_values(1)
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
    let input_paths: Vec<_> = matches.values_of("input").unwrap().collect();
    let input_with_headers = matches.is_present("input-with-headers");
    let output_path = matches.value_of("output");

    let mut client_context = {
        let no_tls = matches.is_present("no-tls");
        let host_pre = matches.value_of("merger");
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
            "suid-create".to_string(),
        ) {
            RpcClient::SuidCreate(x) => x,
            _ => panic!("wrong client"),
        }
    };

    for input_path in input_paths.iter() {
        info!("Input path: {}", input_path);
    }

    if output_path.is_some() {
        info!("Output path: {}", output_path.unwrap());
    } else {
        info!("Output view to stdout (first 10 items)");
    }

    // 1. Create sharer instance
    let sharer = SUIDCreateSharer::new();

    // 2. Initialize merger - this loads merger's data and generates its permutation pattern
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

    // 3. Get public key from merger
    let mut public_key = TPayload::new();
    let _ = rpc_client::recv(
        ServiceResponse {
            ack: Some(Ack::InitAck(init_ack.clone())),
        },
        "public_key_m".to_string(),
        &mut public_key,
        &mut client_context,
    )
    .await?;
    sharer.set_public_key_m(public_key).unwrap();

    // 4. Send 2-out-of-2 El Gamal public key sharer to merger
    let pub_key_r = sharer.get_public_key_reuse();
    let key_reuse_ack = match rpc_client::send(
        pub_key_r,
        "sharer_public_key_reuse".to_string(),
        &mut client_context,
    )
    .await?
    .into_inner()
    .ack
    .unwrap()
    {
        Ack::SharerPublicKeyReuseAck(x) => x,
        _ => panic!("wrong ack"),
    };

    // 4. Load sharer's data - we assume that sharer loads data for
    //    N-1 parties and merger loads data for 1 party
    let mut d_e_sharer = sharer
        .load_encrypt_data(input_paths, input_with_headers)
        .unwrap();

    // 5. Get data from merger. This is the 1 party that merger loads
    let mut d_merger = TPayload::new();
    let _ = rpc_client::recv(
        ServiceResponse {
            ack: Some(Ack::SharerPublicKeyReuseAck(key_reuse_ack.clone())),
        },
        "party_merger".to_string(),
        &mut d_merger,
        &mut client_context,
    )
    .await?;

    // 6. Deserialize data from merger and El Gamal encrypt
    let (d_merger_c1, d_merger_c2) = {
        let offset_len = u64::from_le_bytes(
            d_merger
                .pop()
                .unwrap()
                .buffer
                .as_slice()
                .try_into()
                .unwrap(),
        ) as usize;
        let data_len = u64::from_le_bytes(
            d_merger
                .pop()
                .unwrap()
                .buffer
                .as_slice()
                .try_into()
                .unwrap(),
        ) as usize;

        let offsets = d_merger
            .drain(data_len..)
            .map(|b| u64::from_le_bytes(b.buffer.as_slice().try_into().unwrap()) as usize)
            .collect::<Vec<_>>();

        assert_eq!(data_len % 2, 0);
        assert_eq!(offset_len, offsets.len());

        d_merger.shrink_to_fit();

        sharer.deserialize_elgamal(d_merger, offsets)
    };

    // 7. Gather data from all parties
    // TODO: This push is likely unneccessary
    d_e_sharer.push((d_merger_c1, d_merger_c2));

    // 8. El Gamal exponentiate and global shuffle
    let data_exp = sharer.elgamal_exponentiate(d_e_sharer).unwrap();
    let total_keys: usize = data_exp
        .iter()
        .map(|x| x.0.len())
        .collect::<Vec<_>>()
        .iter()
        .sum();

    let data_to_send = sharer.shuffle_flatten(data_exp).unwrap();

    // 9. Send keys to merge
    let keys_to_merge_ack = match rpc_client::send(
        data_to_send,
        "encrypted_keys_to_merge".to_string(),
        &mut client_context,
    )
    .await?
    .into_inner()
    .ack
    .unwrap()
    {
        Ack::EncryptedKeysToMergeAck(x) => x,
        _ => panic!("wrong ack"),
    };

    let step1_barrier = Step1Barrier {
        sharer_public_key_reuse_ack: Some(key_reuse_ack),
        encrypted_keys_to_merge_ack: Some(keys_to_merge_ack),
    };

    // 10. Calculate SUIDs
    let calculate_suids_ack =
        match rpc_client::calculate_suids(step1_barrier.clone(), &mut client_context)
            .await?
            .into_inner()
            .ack
            .unwrap()
        {
            Ack::CalculateSuidsAck(x) => x,
            _ => panic!("wrong ack"),
        };

    // 11. Receive SUIDs back from merger
    let mut suids = TPayload::new();
    let _ = rpc_client::recv(
        ServiceResponse {
            ack: Some(Ack::CalculateSuidsAck(calculate_suids_ack.clone())),
        },
        "suids".to_string(),
        &mut suids,
        &mut client_context,
    )
    .await?;

    // 12. Unshuffle received SUIDs
    let mut suids_for_parties = sharer.unshuffle_suids(suids).unwrap();

    // 13. Pop off SUIDS for party that merger sent
    let suids_party_merger = {
        let mut x = suids_for_parties.pop().unwrap();
        x.0.append(&mut x.1);
        x.0
    };

    // 14. Set SUIDs for rest of parties that sharer is responsible for
    let _ = sharer.set_suids_for_parties(suids_for_parties).unwrap();

    // 15. Send back merger's suids
    let _ = rpc_client::send(
        suids_party_merger,
        "suids_party_merger".to_string(),
        &mut client_context,
    )
    .await?
    .into_inner()
    .ack
    .unwrap();

    // 16. Output El Gamal encrypted SUIDs for parties associated with sharer
    match output_path {
        Some(p) => sharer.save_suids_data(&String::from(p)).unwrap(),
        None => sharer.print_suids_data(),
    }

    // 17. Output El Gamal encrypted SUIDs for party associated with merger
    rpc_client::reveal(&mut client_context).await?;

    global_timer.qps("total time", total_keys);
    info!("Bye!");
    Ok(())
}
