//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use log::{debug, error, info};

use futures::executor::block_on;
use http::Uri;
use std::path::Path;
use tonic::transport::{Certificate, Identity};
use url::Url;

#[derive(Clone, Debug)]
pub struct TlsContext {
    pub identity: tonic::transport::Identity,
    pub ca: tonic::transport::Certificate,
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
            identity: Identity::from_pem(cert, key),
            ca: Certificate::from_pem(ca),
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
}
