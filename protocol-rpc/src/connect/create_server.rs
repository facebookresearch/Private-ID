//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use std::env;

use log::info;
use log::warn;
use tonic::transport::Server;
use tonic::transport::ServerTlsConfig;

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
                info!("using dir for TLS files {}", d);
                Some(tls::TlsContext::from_dir(d, true))
            }
            // Two-way TLS
            (None, Some(key), Some(cert), Some(ca)) => {
                debug!("using paths directly to read the files");
                Some(tls::TlsContext::from_paths(key, cert, ca))
            }
            // One-way TLS
            (None, Some(key), Some(cert), None) => {
                let full_key_path = if env::var("HOME").is_ok() {
                    env::var("HOME").unwrap() + "/" + key
                } else {
                    "/".to_owned() + key
                };
                let full_cert_path = if env::var("HOME").is_ok() {
                    env::var("HOME").unwrap() + "/" + cert
                } else {
                    "/".to_owned() + cert
                };
                info!("full key path: {}", full_key_path);
                info!("full cert path: {}", full_cert_path);
                Some(tls::TlsContext::from_paths_server(
                    full_key_path.as_str(),
                    full_cert_path.as_str(),
                ))
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
            if ctx.ca.is_some() {
                // Two-way TLS
                server
                    .tls_config(
                        ServerTlsConfig::new()
                            .identity(ctx.identity.unwrap())
                            .client_ca_root(ctx.ca.unwrap()),
                    )
                    .unwrap()
            } else {
                // One-way TLS
                server
                    .tls_config(ServerTlsConfig::new().identity(ctx.identity.unwrap()))
                    .unwrap()
            }
        }
        None => server,
    };
    (server, tx, rx)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_create_server_no_tls() {
        let _ = create_server(true, None, None, None, None);
    }

    #[test]
    #[should_panic]
    fn test_create_server_tls_panic() {
        let _ = create_server(false, None, None, None, None);
    }

    #[test]
    #[should_panic(expected = "private.key not found")]
    fn test_create_server_with_oneway_tls() {
        use std::fs::File;
        use std::io::Write;

        use tempfile::tempdir;

        // Create a directory inside of `std::env::temp_dir()`.
        let dir = tempdir().unwrap();
        use rcgen::*;
        let subject_alt_names: &[_] = &["hello.world.example".to_string(), "localhost".to_string()];

        let server_cert = generate_simple_self_signed(subject_alt_names).unwrap();
        let server_pem = server_cert.serialize_pem().unwrap();
        let private_key = server_cert.serialize_private_key_pem();

        let file_path_server_pem = dir.path().join("server.pem");
        let mut file_server_pem = File::create(file_path_server_pem).unwrap();
        file_server_pem.write_all(server_pem.as_bytes()).unwrap();

        let file_path_private_key = dir.path().join("private.key");
        let mut file_private_key = File::create(file_path_private_key).unwrap();
        file_private_key.write_all(private_key.as_bytes()).unwrap();

        // create_server will use HOME env as the prefix of path, not temp dir, it will throw key not found error
        let _ = create_server(false, None, Some("private.key"), Some("server.pem"), None);

        drop(file_server_pem);
        drop(file_private_key);
        dir.close().unwrap();
    }
}
