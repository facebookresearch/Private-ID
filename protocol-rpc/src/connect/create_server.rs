//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate clap;
extern crate ctrlc;
extern crate tonic;

use log::{info, warn};
use tonic::transport::{Server, ServerTlsConfig};

use crate::connect::tls;

pub fn create_server(
    no_tls: bool,
    tls_dir: Option<&str>,
    tls_key: Option<&str>,
    tls_cert: Option<&str>,
    tls_ca: Option<&str>,
) -> (
    tonic::transport::Server,
    tokio::sync::oneshot::Sender<()>,
    tokio::sync::oneshot::Receiver<()>,
) {
    let tls_context = if no_tls {
        warn!("Starting server without TLS");
        None
    } else {
        match (tls_dir, tls_key, tls_cert, tls_ca) {
            (Some(d), None, None, None) => {
                info!("using dir for tls files {}", d);
                Some(tls::TlsContext::from_dir(d, true))
            }
            (None, Some(key), Some(cert), Some(ca)) => {
                debug!("using paths diretcly to read the files");
                Some(tls::TlsContext::from_paths(key, cert, ca))
            }
            _ => {
                let msg = "Supporting --tls-dir together with direct paths is not supported yet";
                error!("{}", msg);
                panic!("{}", msg)
            }
        }
    };

    // oneshot channel impl from tokio is necessary
    // standard channel does not support futures yet
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();

    let mut server = Server::builder();

    server = match tls_context {
        Some(ctx) => {
            info!("Starting server with TLS support");
            server
                .tls_config(
                    ServerTlsConfig::new()
                        .identity(ctx.identity)
                        .client_ca_root(ctx.ca),
                )
                .unwrap()
        }
        None => server,
    };
    (server, tx, rx)
}
