//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use std::convert::TryInto;

use clap::App;
use clap::Arg;
use clap::ArgGroup;
use common::timer;
use crypto::prelude::TPayload;
use log::error;
use log::info;
use protocol::dpmc::helper::HelperDpmc;
use protocol::dpmc::traits::*;
use rpc::connect::create_client::create_client;
use rpc::proto::gen_dpmc_company::service_response::Ack as CompanyAck;
use rpc::proto::gen_dpmc_company::Init as CompanyInit;
use rpc::proto::gen_dpmc_company::ServiceResponse as CompanyServiceResponse;
use rpc::proto::gen_dpmc_partner::service_response::Ack as PartnerAck;
use rpc::proto::gen_dpmc_partner::Init as PartnerInit;
use rpc::proto::gen_dpmc_partner::SendData as PartnerSendData;
use rpc::proto::RpcClient;
use tonic::Request;

mod rpc_client_company;
mod rpc_client_partner;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // todo: move matches outside, or move to build.rs
    let matches = App::new("Delegated Private Id MultiKey Helper")
        .version("0.1")
        .about("Delegated Private Id Multi Key Protocol")
        .args(&[
            Arg::with_name("company")
                .long("company")
                .short("c")
                .takes_value(true)
                .required(true)
                .help("Company host path to connect to, ex: 0.0.0.0:10009"),
            Arg::with_name("partners")
                .long("partners")
                .short("p")
                .takes_value(true)
                .required(true)
                .help("Partner host path to connect to, ex: 0.0.0.0:10010"),
            Arg::with_name("output")
                .long("output")
                .short("o")
                .takes_value(true)
                .help("Path to output file for spine, output format: private-id, option(key)"),
            Arg::with_name("stdout")
                .long("stdout")
                .short("u")
                .takes_value(false)
                .help("Prints the output to stdout rather than file"),
            Arg::with_name("output-shares-path")
                .long("output-shares-path")
                .takes_value(true)
                .help(
                    "path to write shares of features.\n
                      Feature will be written as {path}_partner_features.csv",
                ),
            Arg::with_name("one-to-many")
                .long("one-to-many")
                .takes_value(true)
                .required(false)
                .help(
                    "By default, DPMC generates one-to-one matches. Use this\n
                       flag to generate one(C)-to-many(P) matches.",
                ),
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
        .groups(&[
            ArgGroup::with_name("tls")
                .args(&["no-tls", "tls-dir", "tls-key"])
                .required(true),
            ArgGroup::with_name("out")
                .args(&["output", "stdout"])
                .required(true),
        ])
        .get_matches();

    let global_timer = timer::Timer::new_silent("global");

    let no_tls = matches.is_present("no-tls");
    let host_pre = matches.value_of("company");
    let tls_dir = matches.value_of("tls-dir");
    let tls_key = matches.value_of("tls-key");
    let tls_cert = matches.value_of("tls-cert");
    let tls_ca = matches.value_of("tls-ca");
    let tls_domain = matches.value_of("tls-domain");
    let one_to_many = {
        match matches.value_of("one-to-many") {
            Some(many) => many.parse::<usize>().unwrap(),
            _ => 1,
        }
    };

    let mut company_client_context = {
        match create_client(
            no_tls,
            host_pre,
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

    let mut partner_client_context = vec![];
    let partner_host_pre = matches.value_of("partners").unwrap().split(",");
    for host_pre_i in partner_host_pre {
        let partner_client_context_i = {
            match create_client(
                no_tls,
                Some(host_pre_i),
                tls_dir,
                tls_key,
                tls_cert,
                tls_ca,
                tls_domain,
                "dpmc-partner".to_string(),
            ) {
                RpcClient::DpmcPartner(x) => x,
                _ => panic!("wrong client"),
            }
        };
        partner_client_context.push(partner_client_context_i);
    }

    let output_keys_path = matches.value_of("output");
    let output_shares_path = matches.value_of("output-shares-path");

    // 1. Create helper protocol instance
    let helper_protocol = HelperDpmc::new();

    // 2. Initialize company - this loads company's data
    let company_init_ack = match company_client_context
        .initialize(Request::new(CompanyInit {}))
        .await?
        .into_inner()
        .ack
        .unwrap()
    {
        CompanyAck::InitAck(x) => x,
        _ => panic!("wrong ack"),
    };

    // 3. Initialize partners - this loads partner's data
    let mut partner_init_acks = vec![];
    for i in 0..partner_client_context.len() {
        let partner_init_ack = match partner_client_context[i]
            .initialize(Request::new(PartnerInit {}))
            .await?
            .into_inner()
            .ack
            .unwrap()
        {
            PartnerAck::InitAck(x) => x,
            _ => panic!("wrong ack"),
        };
        partner_init_acks.push(partner_init_ack);
    }

    // 4. Get public key from company and send it to partners
    // Send helper's public key to partners
    {
        let helper_public_key = helper_protocol.get_helper_public_key().unwrap();

        let mut company_public_key = TPayload::new();
        let _ = rpc_client_company::recv(
            CompanyServiceResponse {
                ack: Some(CompanyAck::InitAck(company_init_ack.clone())),
            },
            "company_public_key".to_string(),
            &mut company_public_key,
            &mut company_client_context,
        )
        .await?;

        helper_protocol.set_company_public_key(company_public_key.clone())?;

        for i in 0..partner_client_context.len() {
            // Send company public key
            let _ = match rpc_client_partner::send(
                company_public_key.clone(),
                "company_public_key".to_string(),
                &mut partner_client_context[i],
            )
            .await?
            .into_inner()
            .ack
            .unwrap()
            {
                PartnerAck::CompanyPublicKeyAck(x) => x,
                _ => panic!("wrong ack"),
            };

            // Send helper public key
            let _ = match rpc_client_partner::send(
                helper_public_key.clone(),
                "helper_public_key".to_string(),
                &mut partner_client_context[i],
            )
            .await?
            .into_inner()
            .ack
            .unwrap()
            {
                PartnerAck::HelperPublicKeyAck(x) => x,
                _ => panic!("wrong ack"),
            };
        }
    }

    // 5. Get company's data from company
    //    h_company_beta = H(C)^beta
    //      beta = company.private_key
    {
        let mut h_company_beta = TPayload::new();
        let _ = rpc_client_company::recv(
            CompanyServiceResponse {
                ack: Some(CompanyAck::InitAck(company_init_ack.clone())),
            },
            "u_company".to_string(),
            &mut h_company_beta,
            &mut company_client_context,
        )
        .await?;

        let offset_len = u64::from_le_bytes(
            h_company_beta
                .pop()
                .unwrap()
                .buffer
                .as_slice()
                .try_into()
                .unwrap(),
        ) as usize;
        // flattened len
        let data_len = u64::from_le_bytes(
            h_company_beta
                .pop()
                .unwrap()
                .buffer
                .as_slice()
                .try_into()
                .unwrap(),
        ) as usize;

        let offset = h_company_beta
            .drain(data_len..)
            .map(|b| u64::from_le_bytes(b.buffer.as_slice().try_into().unwrap()) as usize)
            .collect::<Vec<_>>();
        h_company_beta.shrink_to_fit();

        assert_eq!(offset_len, offset.len());

        // set H(C)^beta
        helper_protocol.set_encrypted_company(h_company_beta, offset)?;
    }

    // 6. Send requests to partners to send their data and shares to company
    let mut partner_sent_data_acks = vec![];
    for i in 0..partner_client_context.len() {
        let partner_sent_data_ack = match partner_client_context[i]
            .send_data_to_company(Request::new(PartnerSendData {}))
            .await?
            .into_inner()
            .ack
            .unwrap()
        {
            PartnerAck::SendDataAck(x) => x,
            _ => panic!("wrong ack"),
        };
        partner_sent_data_acks.push(partner_sent_data_ack);
    }

    // 7. Stop Partner service
    for i in 0..partner_client_context.len() {
        rpc_client_partner::stop_service(&mut partner_client_context[i]).await?;
    }

    // 8. Receive partner's data from company, deserialize, and remove
    //    private exponent alpha. Also decrypt the XOR shares.
    //  input: h_partner_alpha_beta = H(P)^alpha^beta
    //  output: h_partner_beta = H(P)^beta
    for _ in 0..partner_client_context.len() {
        let mut h_partner_alpha_beta = TPayload::new();

        let _ = rpc_client_company::recv(
            CompanyServiceResponse {
                ack: Some(CompanyAck::InitAck(company_init_ack.clone())),
            },
            "v_partner".to_string(),
            &mut h_partner_alpha_beta,
            &mut company_client_context,
        )
        .await?;

        let xor_shares_len = u64::from_le_bytes(
            h_partner_alpha_beta
                .pop()
                .unwrap()
                .buffer
                .as_slice()
                .try_into()
                .unwrap(),
        ) as usize;

        let xor_shares = h_partner_alpha_beta
            .drain((h_partner_alpha_beta.len() - xor_shares_len)..)
            .collect::<Vec<_>>();

        // Last element is the p_scalar_times_g
        let p_scalar_times_g = h_partner_alpha_beta.pop().unwrap();

        // Last element is the encrypted_alpha_t
        let enc_alpha_t = h_partner_alpha_beta.pop().unwrap();

        // deserialize ragged array
        let num_partner_keys = u64::from_le_bytes(
            h_partner_alpha_beta
                .pop()
                .unwrap()
                .buffer
                .as_slice()
                .try_into()
                .unwrap(),
        ) as usize;
        // flattened len
        let data_len = u64::from_le_bytes(
            h_partner_alpha_beta
                .pop()
                .unwrap()
                .buffer
                .as_slice()
                .try_into()
                .unwrap(),
        ) as usize;

        let offset = h_partner_alpha_beta
            .drain(data_len..)
            .map(|b| u64::from_le_bytes(b.buffer.as_slice().try_into().unwrap()) as usize)
            .collect::<Vec<_>>();
        h_partner_alpha_beta.shrink_to_fit();

        assert_eq!(num_partner_keys, offset.len());

        // Perform 1/alpha, where alpha = partner.alpha.
        // Then decrypt XOR secret shares and compute features and mask.
        helper_protocol.remove_partner_scalar_from_p_and_set_shares(
            h_partner_alpha_beta,
            offset,
            enc_alpha_t.buffer,
            vec![p_scalar_times_g],
            xor_shares,
        )?;
    }

    // 9. Calculate set diffs
    for i in 0..partner_client_context.len() {
        // Compute multi-key matches
        helper_protocol.calculate_set_diff(i)?;
    }

    // 10. Create helper's ID spine
    // Compute ID map for LJ
    helper_protocol.calculate_id_map(one_to_many);

    // 11. Create company's ID spine
    rpc_client_company::calculate_id_map(&mut company_client_context).await?;

    // 12. Get XOR share of value from partner. Depends on Id-map
    let v_d_prime = helper_protocol.calculate_features_xor_shares()?;

    // 13. Set XOR share of features for company
    let _ =
        rpc_client_company::calculate_features_xor_shares(v_d_prime, &mut company_client_context)
            .await?
            .into_inner()
            .ack
            .unwrap();

    // 14. Print Company's ID spine and save partners shares
    rpc_client_company::reveal(&mut company_client_context).await?;

    // 15. Print Helper's ID spine (same as Partners without the keys)
    match output_keys_path {
        Some(p) => helper_protocol.save_id_map(&String::from(p)).unwrap(),
        None => helper_protocol.print_id_map(),
    };

    // 16. Print Helper's feature shares
    match output_shares_path {
        Some(p) => helper_protocol
            .save_features_shares(&String::from(p))
            .unwrap(),
        None => error!("Output features path not set. Can't output shares"),
    };

    global_timer.qps("total time", partner_client_context.len());
    info!("Bye!");
    Ok(())
}
