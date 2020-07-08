//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

#[macro_use]
extern crate log;
extern crate clap;
extern crate ctrlc;
extern crate tonic;

use clap::{App, Arg, ArgGroup};
use log::info;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread, time,
};

mod rpc_server;
use rpc::{connect::create_server::create_server, proto::gen_private_id::private_id_server};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let matches = App::new("Private Id Company")
        .version("0.1")
        .about("Private Id Protocol")
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
            Arg::with_name("not-matched-value")
                .long("not-matched-value")
                .takes_value(true)
                .help("Override the default placeholder value for non-matched records"),
            Arg::with_name("use-row-numbers")
                .long("use-row-numbers")
                .takes_value(false)
                .help("Indicates if the output would consist row numbers instead of encrypted IDs"),
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

    let input_path = matches.value_of("input").unwrap_or("input.csv");
    let input_with_headers = matches.is_present("input-with-headers");
    let output_path = matches.value_of("output");
    let na_val = matches.value_of("not-matched-value");
    let use_row_numbers = matches.is_present("use-row-numbers");

    let no_tls = matches.is_present("no-tls");
    let host = matches.value_of("host");
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

    let service = rpc_server::PrivateIdService::new(
        input_path,
        output_path,
        input_with_headers,
        na_val,
        use_row_numbers,
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
        .add_service(private_id_server::PrivateIdServer::new(service))
        .serve_with_shutdown(addr, async {
            rx.await.ok();
        })
        .await?;

    recv_thread.join().unwrap();
    info!("Bye!");
    Ok(())
}
