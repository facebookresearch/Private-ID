//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use futures::executor::block_on;
use log::error;
use log::info;
use log::warn;
use tonic::transport::ClientTlsConfig;
use tonic::transport::Endpoint;

use crate::connect::tls;
use crate::proto::gen_crosspsi::cross_psi_client::CrossPsiClient;
use crate::proto::gen_crosspsi_xor::cross_psi_xor_client::CrossPsiXorClient;
use crate::proto::gen_pjc::pjc_client::PjcClient;
use crate::proto::gen_private_id::private_id_client::PrivateIdClient;
use crate::proto::gen_private_id_multi_key::private_id_multi_key_client::PrivateIdMultiKeyClient;
use crate::proto::gen_suid_create::suid_create_client::SuidCreateClient;
use crate::proto::gen_dpmc_company::dpmc_company_client::DpmcCompanyClient;
use crate::proto::gen_dpmc_partner::dpmc_partner_client::DpmcPartnerClient;
use crate::proto::gen_dspmc_company::dspmc_company_client::DspmcCompanyClient;
use crate::proto::gen_dspmc_helper::dspmc_helper_client::DspmcHelperClient;
use crate::proto::gen_dspmc_partner::dspmc_partner_client::DspmcPartnerClient;
use crate::proto::RpcClient;

pub fn create_client(
    no_tls: bool,
    host_pre: Option<&str>,
    tls_dir: Option<&str>,
    tls_key: Option<&str>,
    tls_cert: Option<&str>,
    tls_ca: Option<&str>,
    tls_domain: Option<&str>,
    client_name: String,
) -> RpcClient {
    let tls_context = if no_tls {
        warn!("Connecting to company without TLS, avoid in production");
        None
    } else {
        match (tls_dir, tls_key, tls_cert, tls_ca) {
            (Some(d), None, None, None) => {
                info!("using dir for tls files {}", d);
                Some(tls::TlsContext::from_dir(d, false))
            }
            (None, Some(key), Some(cert), Some(ca)) => {
                debug!("using paths directly to read the files");
                Some(tls::TlsContext::from_paths(key, cert, ca))
            }
            _ => {
                let msg = "Supporting --tls-dir together with direct paths is not supported yet";
                error!("{}", msg);
                panic!("{}", msg)
            }
        }
    };

    let host = tls::host_into_url(&host_pre.unwrap(), no_tls).to_string();

    let maybe_tls = match tls_context {
        Some(ctx) => {
            let domain_name = match tls_domain {
                Some(domain) => String::from(domain),
                None => tls::host_into_url(&host, no_tls)
                    .domain()
                    .unwrap_or_else(|| {
                        panic!(
                            "Cannot extract domain neither from host {}\
                         nor --tls-domain arg was specified",
                            host
                        )
                    })
                    .to_owned(),
            };

            info!(
                "tls domain name: {} (--tls-domain can can override)",
                domain_name
            );

            Some(
                ClientTlsConfig::new()
                    .domain_name(domain_name)
                    .identity(ctx.identity)
                    .ca_certificate(ctx.ca),
            )
        }
        None => None,
    };
    let has_tls = maybe_tls.is_some();
    let running = Arc::new(AtomicBool::new(true));
    let _r = running.clone();
    // ctrlc::set_handler(move || {
    //     r.store(false, Ordering::SeqCst);
    // })
    // .expect("Error setting Ctrl-C handler");

    let mut retry_count: u32 = 0;

    let context = retry::retry(retry::delay::Fixed::from_millis(3000), move || {
        if retry_count == 0 {
            info!("Connecting to host: {}", host);
        } else {
            info!("Connecting to host: {} [retry: {}]", host, retry_count)
        }
        let __uri = tls::host_into_uri(&host, no_tls);
        retry_count += 1;
        let z = async {
            if has_tls {
                Endpoint::new(__uri)?
                    .tls_config(maybe_tls.clone().unwrap())
                    .unwrap()
                    .connect()
                    .await
                    .map(|conn| match client_name.as_str() {
                        "private-id" => RpcClient::PrivateId(PrivateIdClient::new(conn)),
                        "private-id-multi-key" => {
                            RpcClient::PrivateIdMultiKey(PrivateIdMultiKeyClient::new(conn))
                        }
                        "cross-psi" => RpcClient::CrossPsi(CrossPsiClient::new(conn)),
                        "cross-psi-xor" => RpcClient::CrossPsiXor(CrossPsiXorClient::new(conn)),
                        "pjc" => RpcClient::Pjc(PjcClient::new(conn)),
                        "suid-create" => RpcClient::SuidCreate(SuidCreateClient::new(conn)),
                        "dpmc-company" => RpcClient::DpmcCompany(
                            DpmcCompanyClient::new(conn),
                        ),
                        "dpmc-partner" => RpcClient::DpmcPartner(
                            DpmcPartnerClient::new(conn),
                        ),
                        "dspmc-company" => RpcClient::DspmcCompany(
                            DspmcCompanyClient::new(conn),
                        ),
                        "dspmc-helper" => RpcClient::DspmcHelper(
                            DspmcHelperClient::new(conn),
                        ),
                        "dspmc-partner" => RpcClient::DspmcPartner(
                            DspmcPartnerClient::new(conn),
                        ),
                        _ => panic!("wrong client"),
                    })
            } else {
                match client_name.as_str() {
                    "private-id" => Ok(RpcClient::PrivateId(
                        PrivateIdClient::connect(__uri).await.unwrap(),
                    )),
                    "private-id-multi-key" => Ok(RpcClient::PrivateIdMultiKey(
                        PrivateIdMultiKeyClient::connect(__uri).await.unwrap(),
                    )),
                    "cross-psi" => Ok(RpcClient::CrossPsi(
                        CrossPsiClient::connect(__uri).await.unwrap(),
                    )),
                    "cross-psi-xor" => Ok(RpcClient::CrossPsiXor(
                        CrossPsiXorClient::connect(__uri).await.unwrap(),
                    )),
                    "pjc" => Ok(RpcClient::Pjc(PjcClient::connect(__uri).await.unwrap())),
                    "suid-create" => Ok(RpcClient::SuidCreate(
                        SuidCreateClient::connect(__uri).await.unwrap(),
                    )),
                    "dpmc-company" => Ok(RpcClient::DpmcCompany(
                        DpmcCompanyClient::connect(__uri).await.unwrap(),
                    )),
                    "dpmc-partner" => Ok(RpcClient::DpmcPartner(
                        DpmcPartnerClient::connect(__uri).await.unwrap(),
                    )),
                    "dspmc-company" => Ok(RpcClient::DspmcCompany(
                        DspmcCompanyClient::connect(__uri)
                            .await
                            .unwrap(),
                    )),
                    "dspmc-helper" => Ok(RpcClient::DspmcHelper(
                        DspmcHelperClient::connect(__uri)
                            .await
                            .unwrap(),
                    )),
                    "dspmc-partner" => Ok(RpcClient::DspmcPartner(
                        DspmcPartnerClient::connect(__uri)
                            .await
                            .unwrap(),
                    )),
                    _ => panic!("wrong client"),
                }
            }
        };
        if running.load(Ordering::SeqCst) {
            block_on(z)
        } else {
            panic!("Caught SIGTERM, quit via panic, Bye!")
        }
    })
    .unwrap();
    info!("Client connected!");

    context
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[should_panic]
    fn test_create_client_tls_panic() {
        let no_tls = false;

        let host_pre: Option<&str> = Some("localhost:10009");
        let tls_dir = None;
        let tls_key = None;
        let tls_cert = None;
        let tls_ca = None;
        let tls_domain = None;

        let _ = create_client(
            no_tls,
            host_pre,
            tls_dir,
            tls_key,
            tls_cert,
            tls_ca,
            tls_domain,
            "private-id-multi-key".to_string(),
        );
    }
}
