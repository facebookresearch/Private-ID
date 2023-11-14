//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use std::convert::TryInto;

use clap::App;
use clap::Arg;
use clap::ArgGroup;
use common::timer;
use crypto::prelude::TPayload;
use log::info;
use protocol::dspmc::shuffler::ShufflerDspmc;
use protocol::dspmc::traits::*;
use protocol::shared::TFeatures;
use rpc::connect::create_client::create_client;
use rpc::proto::gen_dspmc_company::service_response::Ack as CompanyAck;
use rpc::proto::gen_dspmc_company::Init as CompanyInit;
use rpc::proto::gen_dspmc_company::RecvShares as CompanyRecvShares;
use rpc::proto::gen_dspmc_company::SendData as CompanySendData;
use rpc::proto::gen_dspmc_company::ServiceResponse as CompanyServiceResponse;
use rpc::proto::gen_dspmc_helper::service_response::Ack as HelperAck;
use rpc::proto::gen_dspmc_helper::SendDataAck;
use rpc::proto::gen_dspmc_helper::ServiceResponse as HelperServiceResponse;
use rpc::proto::gen_dspmc_partner::service_response::Ack as PartnerAck;
use rpc::proto::gen_dspmc_partner::Init as PartnerInit;
use rpc::proto::gen_dspmc_partner::SendData as PartnerSendData;
use rpc::proto::RpcClient;
use tonic::Request;

mod rpc_client_company;
mod rpc_client_helper;
mod rpc_client_partner;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // todo: move matches outside, or move to build.rs
    let matches = App::new("Delegated Private Id MultiKey Shuffler")
        .version("0.1")
        .about("Delegated Private Id Multi Key Protocol")
        .args(&[
            Arg::with_name("company")
                .long("company")
                .short("c")
                .takes_value(true)
                .required(true)
                .help("Company host path to connect to, ex: 0.0.0.0:10009"),
            Arg::with_name("helper")
                .long("helper")
                .short("helper")
                .takes_value(true)
                .required(true)
                .help("Helper host path to connect to, ex: 0.0.0.0:10011"),
            Arg::with_name("partners")
                .long("partners")
                .short("p")
                .takes_value(true)
                .required(true)
                .help("Partner host path to connect to, ex: 0.0.0.0:10010"),
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
            ArgGroup::with_name("out").args(&["stdout"]).required(true),
        ])
        .get_matches();

    let global_timer = timer::Timer::new_silent("global");

    let no_tls = matches.is_present("no-tls");
    let company_host = matches.value_of("company");
    let helper_host = matches.value_of("helper");
    let tls_dir = matches.value_of("tls-dir");
    let tls_key = matches.value_of("tls-key");
    let tls_cert = matches.value_of("tls-cert");
    let tls_ca = matches.value_of("tls-ca");
    let tls_domain = matches.value_of("tls-domain");

    let mut company_client_context = {
        match create_client(
            no_tls,
            company_host,
            tls_dir,
            tls_key,
            tls_cert,
            tls_ca,
            tls_domain,
            "dspmc-company".to_string(),
        ) {
            RpcClient::DspmcCompany(x) => x,
            _ => panic!("wrong client"),
        }
    };

    let mut helper_client_context = {
        match create_client(
            no_tls,
            helper_host,
            tls_dir,
            tls_key,
            tls_cert,
            tls_ca,
            tls_domain,
            "dspmc-helper".to_string(),
        ) {
            RpcClient::DspmcHelper(x) => x,
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
                "dspmc-partner".to_string(),
            ) {
                RpcClient::DspmcPartner(x) => x,
                _ => panic!("wrong client"),
            }
        };
        partner_client_context.push(partner_client_context_i);
    }

    // 1. Create shuffler protocol instance
    let shuffler_protocol = ShufflerDspmc::new();

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

    // 4. Get public key from company and send it to partners and to helper
    // Send helper's public key to partners
    {
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
        shuffler_protocol.set_company_public_key(company_public_key.clone())?;

        let helper_public_key_ack = match rpc_client_helper::send(
            company_public_key.clone(),
            "company_public_key".to_string(),
            &mut helper_client_context,
        )
        .await?
        .into_inner()
        .ack
        .unwrap()
        {
            HelperAck::CompanyPublicKeyAck(x) => x,
            _ => panic!("wrong ack"),
        };

        let mut helper_public_key = TPayload::new();
        let _ = rpc_client_helper::recv(
            HelperServiceResponse {
                ack: Some(HelperAck::CompanyPublicKeyAck(
                    helper_public_key_ack.clone(),
                )),
            },
            "helper_public_key".to_string(),
            &mut helper_public_key,
            &mut helper_client_context,
        )
        .await?;
        shuffler_protocol.set_helper_public_key(helper_public_key.clone())?;

        // Send helper public key to Company
        let _ = match rpc_client_company::send(
            helper_public_key.clone(),
            "helper_public_key".to_string(),
            &mut company_client_context,
        )
        .await?
        .into_inner()
        .ack
        .unwrap()
        {
            CompanyAck::HelperPublicKeyAck(x) => x,
            _ => panic!("wrong ack"),
        };

        for i in 0..partner_client_context.len() {
            // Send company public key to partners
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

            // Send helper public key to partners
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

    // 5. Send requests to partners to send their data and shares to company
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

    // 6. Stop Partner service
    for i in 0..partner_client_context.len() {
        rpc_client_partner::stop_service(&mut partner_client_context[i]).await?;
    }

    // Secure shuffling starts here

    // 7. Send request to company to send ct3 from all partners to Helper along
    // with p_cd and v_cd
    let company_sent_ct3_v3_p3_ack = match company_client_context
        .send_ct3_p_cd_v_cd_to_helper(Request::new(CompanySendData {}))
        .await?
        .into_inner()
        .ack
        .unwrap()
    {
        CompanyAck::SendDataAck(x) => x,
        _ => panic!("wrong ack"),
    };

    // 8. Receive p_cs and v_cs from company
    let mut v4_p4 = TPayload::new();
    let _ = rpc_client_company::recv(
        CompanyServiceResponse {
            ack: Some(CompanyAck::SendDataAck(company_sent_ct3_v3_p3_ack.clone())),
        },
        "p_cs_v_cs".to_string(),
        &mut v4_p4,
        &mut company_client_context,
    )
    .await?;

    let offset_len =
        u64::from_le_bytes(v4_p4.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;
    // flattened len
    let data_len =
        u64::from_le_bytes(v4_p4.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;
    let num_keys = offset_len - 1;
    let offset = v4_p4
        .drain((num_keys * 2 + data_len * 2)..)
        .map(|b| u64::from_le_bytes(b.buffer.as_slice().try_into().unwrap()) as usize)
        .collect::<Vec<_>>();
    assert_eq!(offset_len, offset.len());

    let ct2_prime_flat = v4_p4.drain((v4_p4.len() - data_len)..).collect::<Vec<_>>();
    let ct1_prime_flat = v4_p4.drain((v4_p4.len() - data_len)..).collect::<Vec<_>>();

    let v_cs_bytes = v4_p4.drain((v4_p4.len() - num_keys)..).collect::<Vec<_>>();
    v4_p4.shrink_to_fit();

    shuffler_protocol.set_p_cs_v_cs(v_cs_bytes, v4_p4)?;

    // 9. Receive u_2 = p_cd(v'') xor v_cd from helper
    let mut data = TPayload::new();
    let _ = rpc_client_helper::recv(
        HelperServiceResponse {
            ack: Some(HelperAck::SendDataAck(SendDataAck {})),
        },
        "u2".to_string(),
        &mut data,
        &mut helper_client_context,
    )
    .await?;
    let num_features =
        u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;
    let num_rows =
        u64::from_le_bytes(data.pop().unwrap().buffer.as_slice().try_into().unwrap()) as usize;
    data.shrink_to_fit();

    let mut u2 = TFeatures::new();
    for i in (0..num_features).rev() {
        let x = data
            .drain(i * num_rows..)
            .map(|x| u64::from_le_bytes(x.buffer.as_slice().try_into().unwrap()))
            .collect::<Vec<_>>();
        u2.push(x);
    }

    // 10. Generete shuffler permutations
    // Generate p_sc, v_sc and p_sd, v_sd
    let (p_sc_v_sc, p_sd_v_sd) = shuffler_protocol.gen_permutations().unwrap();

    // 11. Compute x_2 = p_cs(u2) xor v_cs
    // Compute v_2' = p_sd(p_sc(x_2) xor v_sd) xor v_sd
    // Return rerandomized ct1' and ct2' as ct1'' and ct2''
    let ct1_ct2_dprime = shuffler_protocol
        .compute_v2prime_ct1ct2(u2, ct1_prime_flat, ct2_prime_flat, offset)
        .unwrap();

    // v_sc, p_sc, ct1_dprime_flat, ct2_dprime_flat, ct_offset
    let mut p_sc_v_sc_ct1_ct2_dprime = p_sc_v_sc;
    p_sc_v_sc_ct1_ct2_dprime.extend(ct1_ct2_dprime);

    // 12. Send v_sc, p_sc, ct1'', ct2'' to C
    let _company_p_sc_v_sc_ack = match rpc_client_company::send(
        p_sc_v_sc_ct1_ct2_dprime,
        "p_sc_v_sc_ct1_ct2_dprime".to_string(),
        &mut company_client_context,
    )
    .await?
    .into_inner()
    .ack
    .unwrap()
    {
        CompanyAck::UPartnerAck(x) => x,
        _ => panic!("wrong ack"),
    };

    // 13. Send p_sd, v_sd to helper (D)
    let _ = match rpc_client_helper::send(
        p_sd_v_sd,
        "p_sd_v_sd".to_string(),
        &mut helper_client_context,
    )
    .await?
    .into_inner()
    .ack
    .unwrap()
    {
        HelperAck::UPartnerAck(x) => x,
        _ => panic!("wrong ack"),
    };

    // 14. Send request to company to send u1 to Helper
    // u1 = p_sc( p_cs( p_cd(v_1) xor v_cd) xor v_cs) xor v_sc
    let _company_sent_u1_ack = match company_client_context
        .send_u1_to_helper(Request::new(CompanySendData {}))
        .await?
        .into_inner()
        .ack
        .unwrap()
    {
        CompanyAck::SendDataAck(x) => x,
        _ => panic!("wrong ack"),
    };

    // Secure shuffling ends here

    // Blind v' with hashed Elgamal.
    // Send blinded v' and h = g^z.
    let blinded_vprime = shuffler_protocol.get_blinded_vprime().unwrap();

    // 15. Send blinded v' and g^z to helper (D)
    let _helper_vprime_ack = match rpc_client_helper::send(
        blinded_vprime,
        "encrypted_vprime".to_string(),
        &mut helper_client_context,
    )
    .await?
    .into_inner()
    .ack
    .unwrap()
    {
        HelperAck::UPartnerAck(x) => x,
        _ => panic!("wrong ack"),
    };

    // 16. Send request to company to send ct1, ct2', and X to Helper
    //  ct2' = ct2^c
    //  X = H(C)^c
    let _company_keys_ack = match company_client_context
        .send_encrypted_keys_to_helper(Request::new(CompanySendData {}))
        .await?
        .into_inner()
        .ack
        .unwrap()
    {
        CompanyAck::SendDataAck(x) => x,
        _ => panic!("wrong ack"),
    };

    // Identity Match Stage is done.

    // 17. Create company's ID spine
    rpc_client_company::calculate_id_map(&mut company_client_context).await?;

    // 18. Signal the helper to run the rest of the protocol
    //      1. Compute multi-key matches -- calculate_set_diff
    //      2. Compute ID map for LJ -- calculate_id_map
    rpc_client_helper::calculate_id_map(&mut helper_client_context).await?;

    // 19. Send request to company to receive shares from helper
    // calculate_features_xor_shares
    // Set XOR share of features for company
    // Print Company's ID spine and save partners shares
    let _company_sent_data_ack = match company_client_context
        .recv_shares_from_helper(Request::new(CompanyRecvShares {}))
        .await?
        .into_inner()
        .ack
        .unwrap()
    {
        CompanyAck::RecvSharesAck(x) => x,
        _ => panic!("wrong ack"),
    };

    // 20. Print Helper's ID spine and save partners shares
    rpc_client_helper::reveal(&mut helper_client_context).await?;

    // Stop Helper service
    rpc_client_helper::stop_service(&mut helper_client_context).await?;

    global_timer.qps("total time", partner_client_context.len());
    info!("Bye!");
    Ok(())
}
