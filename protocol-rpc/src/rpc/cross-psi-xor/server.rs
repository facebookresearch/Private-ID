//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

#[macro_use]
extern crate log;
extern crate clap;
extern crate ctrlc;
extern crate protocol;
extern crate rpc;
extern crate tonic;

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time;

use clap::App;
use clap::Arg;
use clap::ArgGroup;
use common::gcs_path::GCSPath;
use common::s3_path::S3Path;
use log::info;

mod rpc_server;
use rpc::connect::create_server::create_server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let matches = App::new("Cross PSI XOR Company")
        .version("0.1")
        .about("Cross PSI XOR Protocol")
        .args(&[
            Arg::with_name("host")
                .long("host")
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
                .help("Path to tls key (non-encrypted)"),
            Arg::with_name("tls-cert")
                .long("tls-cert")
                .takes_value(true)
                .requires("tls-key")
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

    let host = matches.value_of("host");
    let no_tls = matches.is_present("no-tls");
    let tls_dir = matches.value_of("tls-dir");
    let tls_key = matches.value_of("tls-key");
    let tls_cert = matches.value_of("tls-cert");
    let tls_ca = matches.value_of("tls-ca");

    let (mut server, tx, rx) = create_server(no_tls, tls_dir, tls_key, tls_cert, tls_ca);

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    info!("Input path: {}", input_path);

    if output_path.is_some() {
        info!("Output path: {}", output_path.unwrap());
    } else {
        info!("Output view to stdout (first 10 items)");
    }

    let service = rpc_server::CrossPsiXorService::new(&input_path, output_path);

    let ks = service.killswitch.clone();
    let pull_thread = thread::spawn(move || {
        let sleep_dur = time::Duration::from_millis(1000);
        while !(ks.load(Ordering::Relaxed)) && running.load(Ordering::Relaxed) {
            thread::sleep(sleep_dur);
        }

        info!("Shutting down server ...");
        tx.send(()).unwrap();
    });

    info!("Cross-Psi XOR server starting at {}", host.unwrap());

    let addr: SocketAddr = host.unwrap().parse()?;

    server
        .add_service(
            rpc::proto::gen_crosspsi_xor::cross_psi_xor_server::CrossPsiXorServer::new(service),
        )
        .serve_with_shutdown(addr, async {
            rx.await.ok();
        })
        .await?;

    pull_thread.join().unwrap();
    info!("Bye!");

    Ok(())
}
