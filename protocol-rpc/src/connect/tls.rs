//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use futures::executor::block_on;
use http::Uri;
use log::debug;
use log::error;
use log::info;
use tonic::transport::Certificate;
use tonic::transport::Identity;
use url::Url;

#[derive(Clone, Debug)]
pub struct TlsContext {
    pub identity: Option<tonic::transport::Identity>,
    pub ca: Option<tonic::transport::Certificate>,
}

impl TlsContext {
    /// Construct TlsContext from corresponding files in the system
    /// panics if file not found
    pub fn from_paths<T>(key_path: T, cert_path: T, ca_path: T) -> TlsContext
    where
        T: AsRef<Path> + Copy,
    {
        info!(
            "Reading tls files, key: {}, cert: {}, ca: {}",
            key_path.as_ref().display(),
            cert_path.as_ref().display(),
            ca_path.as_ref().display()
        );
        [key_path, cert_path, ca_path].iter().for_each(|p| {
            if !Path::new(p.as_ref()).exists() {
                panic!("File {} not found", p.as_ref().display())
            }
        });

        let z = async {
            let cert = tokio::fs::read(cert_path).await.expect("Cannot read cert");
            let key = tokio::fs::read(key_path).await.unwrap();
            let ca = tokio::fs::read(ca_path).await.unwrap();
            (key, cert, ca)
        };
        let (key, cert, ca) = block_on(z);
        debug!("Successfully read key, cert and CA cert");

        TlsContext {
            identity: Some(Identity::from_pem(cert, key)),
            ca: Some(Certificate::from_pem(ca)),
        }
    }

    /// Tries to find the necessary files in the directory
    /// if is server is set to true, the filenames are:
    /// server.key, server.pem, ca.pem
    /// otherwise the filenames will be:
    /// lient.key, client.pem, ca.pem
    pub fn from_dir<T>(tls_dir_path: T, is_server: bool) -> TlsContext
    where
        T: AsRef<Path> + Copy,
    {
        if !Path::new(tls_dir_path.as_ref()).is_dir() {
            error!(
                "Path {} is not a directory",
                tls_dir_path.as_ref().display()
            );
            panic!(
                "{}",
                format!(
                    "Path {} is not a directory",
                    tls_dir_path.as_ref().display()
                )
            );
        }
        let prefix = if is_server {
            "server".to_string()
        } else {
            "client".to_string()
        };

        let key_path = tls_dir_path
            .as_ref()
            .join(Path::new(format!("{}.key", prefix).as_str()));

        let cert_path = tls_dir_path
            .as_ref()
            .join(Path::new(format!("{}.pem", prefix).as_str()));

        let ca_path = tls_dir_path.as_ref().join(Path::new("ca.pem"));

        TlsContext::from_paths(key_path.as_path(), cert_path.as_path(), ca_path.as_path())
    }

    /// Construct TlsContext for Client from corresponding file in the system
    /// panics if file not found
    pub fn from_path_client<T>(ca_path: T) -> TlsContext
    where
        T: AsRef<Path> + Copy,
    {
        info!("Reading TLS file, ca: {}", ca_path.as_ref().display());
        [ca_path].iter().for_each(|p| {
            if !Path::new(p.as_ref()).exists() {
                panic!("File {} not found", p.as_ref().display())
            }
        });

        let z = async {
            let ca = tokio::fs::read(ca_path).await.unwrap();
            ca
        };
        let ca = block_on(z);
        info!("Successfully read CA cert");

        TlsContext {
            identity: None,
            ca: Some(Certificate::from_pem(ca)),
        }
    }

    /// Construct TlsContext for Serever from corresponding files in the system
    /// panics if file not found
    pub fn from_paths_server<T>(key_path: T, cert_path: T) -> TlsContext
    where
        T: AsRef<Path> + Copy,
    {
        info!(
            "Reading TLS files, key: {}, cert: {}",
            key_path.as_ref().display(),
            cert_path.as_ref().display(),
        );
        [key_path, cert_path].iter().for_each(|p| {
            if !Path::new(p.as_ref()).exists() {
                panic!("File {} not found", p.as_ref().display())
            }
        });

        let z = async {
            let key = tokio::fs::read(key_path).await.unwrap();
            let cert = tokio::fs::read(cert_path).await.unwrap();
            (key, cert)
        };
        let (key, cert) = block_on(z);
        debug!("Successfully read key and cert");

        TlsContext {
            identity: Some(Identity::from_pem(cert, key)),
            ca: None,
        }
    }
}

/// Converts host string into URI object
/// The host should contain connection string
pub fn host_into_uri(host: &str, no_tls: bool) -> Uri {
    let url_str = host_into_url(host, no_tls).to_string();
    url_str
        .parse()
        .unwrap_or_else(|_| panic!("Unable to convert {} to URI", host))
}

/// Converts host string into URI object
/// The host should contain connection string
pub fn host_into_url(host: &str, no_tls: bool) -> Url {
    let pre = Url::parse(host).unwrap_or_else(|_| panic!("Unable to convert {} to URL", host));
    if !vec!["http", "https", "tcp"].contains(&pre.scheme()) {
        let z = if no_tls {
            format!("http://{}", host)
        } else {
            format!("https://{}", host)
        };
        debug!("Scheme overriden to: {} (from: {})", z, host);
        Url::parse(&z).unwrap_or_else(|_| panic!("Unable to convert {} to URL", z))
    } else {
        pre
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_input_to_url() {
        let r = host_into_url("http://foo.bar:10009/path?1234", true);
        assert_eq!(r.domain().unwrap(), "foo.bar");

        let r2 = host_into_url("http://20.00.10.10:10009/path?1234", true);
        assert!(r2.domain().is_none());
        assert_eq!(r2.host().unwrap().to_string(), "20.0.10.10");
    }

    #[test]
    fn test_noscheme_to_url() {
        let r = host_into_url("foo.bar:10009/path?1234", false);
        assert_eq!(r.scheme(), "https");
        assert_eq!(
            host_into_url("http://foo.bar:10009/path?1234", true).scheme(),
            "http"
        );
        assert_eq!(
            host_into_url("https://foo.bar:10009/path?1234", false).scheme(),
            "https"
        );
    }

    #[test]
    fn test_host_into_uri() {
        let _ = host_into_uri("foo.bar:10009/path?1234", false);
    }

    #[tokio::test]
    async fn test_from_dir() {
        use std::fs::File;
        use std::io::Write;

        use tempfile::tempdir;

        // Create a directory inside of `std::env::temp_dir()`.
        let dir = tempdir().unwrap();
        use rcgen::*;
        let subject_alt_names: &[_] = &["hello.world.example".to_string(), "localhost".to_string()];
        let ca_subject_alt_names: &[_] = &["ca.world.example".to_string(), "localhost".to_string()];

        let client_cert = generate_simple_self_signed(subject_alt_names).unwrap();
        let ca_cert = generate_simple_self_signed(ca_subject_alt_names).unwrap();
        let client_pem = client_cert.serialize_pem().unwrap();
        let client_key = client_cert.serialize_private_key_pem();
        let ca_pem = ca_cert.serialize_pem().unwrap();

        let file_path_ca_pem = dir.path().join("ca.pem");
        let mut file_ca_pem = File::create(file_path_ca_pem).unwrap();
        file_ca_pem.write_all(ca_pem.as_bytes()).unwrap();

        let file_path_client_pem = dir.path().join("client.pem");
        let mut file_client_pem = File::create(file_path_client_pem).unwrap();
        file_client_pem.write_all(client_pem.as_bytes()).unwrap();

        let file_path_client_key = dir.path().join("client.key");
        let mut file_client_key = File::create(file_path_client_key).unwrap();
        file_client_key.write_all(client_key.as_bytes()).unwrap();

        let _ = TlsContext::from_dir(dir.path(), false);

        drop(file_ca_pem);
        drop(file_client_pem);
        drop(file_client_key);
        dir.close().unwrap();
    }

    #[tokio::test]
    async fn test_from_path_client() {
        use std::fs::File;
        use std::io::Write;

        use tempfile::tempdir;

        // Create a directory inside of `std::env::temp_dir()`.
        let dir = tempdir().unwrap();
        use rcgen::*;
        let ca_subject_alt_names: &[_] = &["ca.world.example".to_string(), "localhost".to_string()];

        let ca_cert = generate_simple_self_signed(ca_subject_alt_names).unwrap();
        let ca_pem = ca_cert.serialize_pem().unwrap();

        let file_path_ca_pem = dir.path().join("ca.pem");
        let mut file_ca_pem = File::create(file_path_ca_pem).unwrap();
        file_ca_pem.write_all(ca_pem.as_bytes()).unwrap();

        let _ = TlsContext::from_path_client(dir.path().join(Path::new("ca.pem")).as_path());

        drop(file_ca_pem);
        dir.close().unwrap();
    }

    #[tokio::test]
    async fn test_from_path_server() {
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

        let _ = TlsContext::from_paths_server(
            dir.path().join(Path::new("private.key")).as_path(),
            dir.path().join(Path::new("server.pem")).as_path(),
        );

        drop(file_server_pem);
        drop(file_private_key);
        dir.close().unwrap();
    }
}
