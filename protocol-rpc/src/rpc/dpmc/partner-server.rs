//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

#[macro_use]
extern crate log;
extern crate clap;
extern crate ctrlc;
extern crate tonic;

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time;

use clap::App;
use clap::Arg;
use clap::ArgGroup;
use log::info;

mod rpc_client_company;
mod rpc_server_partner;
use rpc::connect::create_client::create_client;
use rpc::connect::create_server::create_server;
use rpc::proto::gen_dpmc_partner::dpmc_partner_server;
use rpc::proto::RpcClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let matches = App::new("Delegated Private Id MultiKey Partner")
        .version("0.1")
        .about("Delegated Private Id MultiKey Protocol")
        .args(&[
            Arg::with_name("host")
                .long("host")
                .takes_value(true)
                .required(true)
                .help("Host path to connect to, ex: 0.0.0.0:10009"),
            Arg::with_name("company")
                .long("company")
                .short("c")
                .takes_value(true)
                .required(true)
                .help("Company host path to connect to, ex: 0.0.0.0:10009"),
            Arg::with_name("input-keys")
                .long("input-keys")
                .default_value("input_keys.csv")
                .help("Path to input file with keys"),
            Arg::with_name("input-features")
                .long("input-features")
                .default_value("input_features.csv")
                .help("Path to input file with keys"),
            Arg::with_name("input-with-headers")
                .long("input-with-headers")
                .takes_value(false)
                .help("Indicates if the input CSV contains headers"),
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
                    server: server.key, server.pem, ca.pem \n",
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
        .groups(&[ArgGroup::with_name("tls")
            .args(&["no-tls", "tls-dir", "tls-key"])
            .required(true)])
        .get_matches();

    let input_keys_path = matches.value_of("input-keys").unwrap_or("input_keys.csv");
    let input_features_path = matches
        .value_of("input-features")
        .unwrap_or("input_features.csv");
    let input_with_headers = matches.is_present("input-with-headers");

    let no_tls = matches.is_present("no-tls");
    let host = matches.value_of("host");
    let company_host = matches.value_of("company");
    let tls_dir = matches.value_of("tls-dir");
    let tls_key = matches.value_of("tls-key");
    let tls_cert = matches.value_of("tls-cert");
    let tls_ca = matches.value_of("tls-ca");
    let tls_domain = matches.value_of("tls-domain");

    let company_client_context = {
        match create_client(
            no_tls,
            company_host,
            tls_dir,
            tls_key,
            tls_cert,
            tls_ca,
            tls_domain,
            "dpmc-company".to_string(),
        ) {
            RpcClient::DpmcCompany(x) => x,
            _ => panic!("wrong client"),
        }
    };

    let (mut server, tx, rx) = create_server(no_tls, tls_dir, tls_key, tls_cert, tls_ca);

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    info!("Input path for keys: {}", input_keys_path);
    info!("Input path for features: {}", input_features_path);

    let service = rpc_server_partner::DpmcPartnerService::new(
        input_keys_path,
        input_features_path,
        input_with_headers,
        company_client_context,
    );

    let ks = service.killswitch.clone();
    let recv_thread = thread::spawn(move || {
        let sleep_dur = time::Duration::from_millis(1000);
        while !(ks.load(Ordering::Relaxed)) && running.load(Ordering::Relaxed) {
            thread::sleep(sleep_dur);
        }

        info!("Shutting down server ...");
        tx.send(()).unwrap();
    });

    info!("Server starting at {}", host.unwrap());

    let addr = host.unwrap().parse()?;

    server
        .add_service(dpmc_partner_server::DpmcPartnerServer::new(service))
        .serve_with_shutdown(addr, async {
            rx.await.ok();
        })
        .await?;

    recv_thread.join().unwrap();

    info!("Bye!");
    Ok(())
}
