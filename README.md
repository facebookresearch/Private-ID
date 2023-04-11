# Private-ID

Private-ID is a collection of algorithms to match records between two parties, while preserving the privacy of these records. We present two algorithms to do this---one of which does an outer join between parties and another does a inner join and then generates additive shares that can then be input to a Multi Party Compute system like [CrypTen](https://github.com/facebookresearch/CrypTen). Please refer to our [paper](https://eprint.iacr.org/2020/599.pdf) for more details.

## Build

Private-ID is implemented in Rust to take advantage of the languages security features and to leverage the encryption libraries that we depend on. It should compile with the nightly Rust toolchain.

The following should build and run the unit tests for the building blocks used by the protocols

- `cargo build`, `cargo test`

Each protocol involves two parties and they have to be run in its own shell environment. We call one party Company and another party Partner.

Run the script at etc/example/generate_cert.sh to generate dummy_certs directroy if you want to test protocol with tls on local.

## Private-ID

This protocol maps the email addresses from both parties to a single ID spine, so that same e-mail addresses map to the same key.

To run Company

```bash
env RUST_LOG=info cargo run --bin private-id-server -- \
  --host 0.0.0.0:10009 \
  --input etc/example/email_company.csv \
  --stdout \
  --tls-dir etc/example/dummy_certs
```

To run Partner

```bash
env RUST_LOG=info cargo run --bin private-id-client -- \
  --company localhost:10009 \
  --input etc/example/email_partner.csv \
  --stdout \
  --tls-dir etc/example/dummy_certs
```

## Private-ID MultiKey

We extend the Private-ID protocol to match multiple identifiers. Please refer to our [paper](https://eprint.iacr.org/2021/770) for more details.

To run Company

```bash
env RUST_LOG=info cargo run --bin private-id-multi-key-server -- \
  --host 0.0.0.0:10009 \
  --input etc/example/private_id_multi_key/Ex1_company.csv \
  --stdout \
  --tls-dir etc/example/dummy_certs
```

To run Partner

```bash
env RUST_LOG=info cargo run --bin private-id-multi-key-client -- \
  --company localhost:10009 \
  --input etc/example/private_id_multi_key/Ex1_partner.csv \
  --stdout \
  --tls-dir etc/example/dummy_certs
```

## PS3I

This protocol does an inner join based on email addresses as keys and then generates additive share of a feature associated with that email address. The shares are generated in the designated output files as 64 bit numbers

To run Company

```bash
env RUST_LOG=info cargo run --bin cross-psi-server -- \
  --host 0.0.0.0:10010 \
  --input etc/example/input_company.csv \
  --output etc/example/output_company.csv \
  --no-tls
```

To run Partner

```bash
env RUST_LOG=info cargo run --bin cross-psi-client -- \
  --company localhost:10010 \
  --input etc/example/input_partner.csv \
  --output etc/example/output_partner.csv \
  --no-tls
```

## PS3I XOR

This protocol does an inner join based on email addresses as keys and then generates XOR share of a feature associated with that email address. The shares are generated in the designated output files as 64 bit numbers

To run Company

```bash
env RUST_LOG=info cargo run --bin cross-psi-xor-server -- \
  --host 0.0.0.0:10010 \
  --input etc/example/cross_psi_xor/input_company.csv \
  --output etc/example/cross_psi_xor/output_company \
  --no-tls
```

To run Partner

```bash
env RUST_LOG=info cargo run --bin cross-psi-xor-client -- \
  --company localhost:10010 \
  --input etc/example/cross_psi_xor/input_partner.csv \
  --output etc/example/cross_psi_xor/output_partner \
  --no-tls
```

The `--output` option provides prefix for the output files that contain the shares. In this case, Company generates two files; `output_company_company_feature.csv` and `output_company_partner_feature.csv`. They contain Company's share of company and parter features respectively. Similarly Partner generates two files; `output_partner_company_feature.csv` and `output_partner_partner_feature.csv`. They contain Partner's share of company and partner features respectively.

Thus `output_company_company_feature.csv` and `output_partner_company_feature.csv` are XOR shares of Company's features. Similarly `output_partner_company_feature.csv` and `output_partner_partner_feature.csv` are XOR shares of Partner's features.

### Private Join and Compute
This is an implementation of Google's [Private Join and Compute](https://github.com/google/private-join-and-compute) protocol, that does a inner join based on email addresses and computes a sum of the corresponding feature for the Partner.

```bash
env RUST_LOG=info cargo run --bin pjc-client -- \
  --company localhost:10011 \
  --input etc/example/pjc_partner.csv \
  --stdout \
  --tls-dir etc/example/dummy_certs
```

```bash
env RUST_LOG=info cargo run --bin pjc-server -- \
  --host 0.0.0.0:10011 \
  --input etc/example/pjc_company.csv \
  --stdout \
  --tls-dir etc/example/dummy_certs
```

## SUMID
This is an implmentation of 2-party version of Secure Universal ID protocol. This can work on multiple keys. In the current implementation, the merger party also assumes the role of one data party and the sharer party assumes the role of all the other data parties. The data parties are the `.csv` files show below

To run merger
```bash
env RUST_LOG=info cargo run --bin suid-create-server -- \
  --host 0.0.0.0:10010 \
  --input etc/example/suid/Example1/DataParty2_input.csv \
  --stdout \
  --tls-dir etc/example/dummy_certs
```

To run merger
```bash
env RUST_LOG=info cargo run --bin suid-create-client -- \
  --merger localhost:10010 \
  --input etc/example/suid/Example1/DataParty1_input.csv \
  --input etc/example/suid/Example1/DataParty3_input.csv \
  --stdout \
  --tls-dir etc/example/dummy_certs
```

The output will be ElGamal encrypted Universal IDs assigned to each entry in the `.csv` file.

## Delegated Private Matching for Compute (DPMC)

We extend the Multi-key Private-ID protocol to multiple partners. Please refer to our [paper](TODO) for more details.

To run Company
```bash
env RUST_LOG=info cargo run --bin dpmc-company-server -- \
  --host 0.0.0.0:10010 \
  --input etc/example/dpmc/Ex0_company.csv \
  --stdout \
  --output-shares-path etc/example/dpmc/output_company \
  --no-tls
```

To multiple partners (servers)
```bash
env RUST_LOG=info cargo run --bin dpmc-partner-server -- \
  --host 0.0.0.0:10020 \
  --company localhost:10010 \
  --input-keys etc/example/dpmc/Ex0_partner_1.csv \
  --input-features etc/example/dpmc/Ex0_partner_1_features.csv \
  --no-tls
```

```bash
env RUST_LOG=info cargo run --bin dpmc-partner-server -- \
  --host 0.0.0.0:10021 \
  --company localhost:10010 \
  --input-keys etc/example/dpmc/Ex0_partner_2.csv \
  --input-features etc/example/dpmc/Ex0_partner_2_features.csv \
  --no-tls
```

Start helper (client)
```bash
env RUST_LOG=info cargo run --bin dpmc-helper -- \
  --company localhost:10010 \
  --partners localhost:10020,localhost:10021 \
  --stdout \
  --output-shares-path etc/example/dpmc/output_partner \
  --no-tls
```

The above will generate one-to-one matches. To enable one-to-many matches (one
record from C will match to `M` P records), use the flag `--one-to-many M` in the
`dpmc-helper` binary, where `M` is the number of matches.

For example, using the same scripts as above for company and partners, to run
`1-2` matching, start the helper as follows:

```bash
env RUST_LOG=info cargo run --bin dpmc-helper -- \
  --company localhost:10010 \
  --partners localhost:10020,localhost:10021 \
  --one-to-many 2 \
  --stdout \
  --output-shares-path etc/example/dpmc/output_partner \
  --tls-dir etc/example/dummy_certs
```

## Delegated Private Matching for Compute with Secure Shuffling (DSPMC)

Start helper (server)

```bash
env RUST_LOG=info cargo run --bin dspmc-helper-server -- \
  --host 0.0.0.0:10030 \
  --stdout \
  --output-shares-path etc/example/dspmc/output_helper \
  --no-tls
```

Start company (server)

```bash
env RUST_LOG=info cargo run --bin dspmc-company-server -- \
  --host 0.0.0.0:10010 \
  --helper localhost:10030 \
  --input etc/example/dspmc/Ex0_company.csv \
  --stdout \
  --output-shares-path etc/example/dspmc/output_company \
  --no-tls
```

Start multiple partners (servers)

```bash
env RUST_LOG=info cargo run --bin dspmc-partner-server -- \
  --host 0.0.0.0:10020 \
  --company localhost:10010 \
  --input-keys etc/example/dspmc/Ex0_partner_1.csv \
  --input-features etc/example/dspmc/Ex0_partner_1_features.csv \
  --no-tls
```

```bash
env RUST_LOG=info cargo run --bin dspmc-partner-server -- \
  --host 0.0.0.0:10021 \
  --company localhost:10010 \
  --input-keys etc/example/dspmc/Ex0_partner_2.csv \
  --input-features etc/example/dspmc/Ex0_partner_2_features.csv \
  --no-tls
```

Start Shuffler (client)

```bash
env RUST_LOG=info cargo run --bin dspmc-shuffler -- \
  --company localhost:10010 \
  --helper localhost:10030 \
  --partners localhost:10020,localhost:10021 \
  --stdout \
  --no-tls
```

# Citing Private-ID

To cite Private-ID in academic papers, please use the following BibTeX entries.

## Delegated Private-ID
```
@Misc{EPRINT:MMTSBC23,
  author = "Dimitris Mouris and
    Daniel Masny and
    Ni Trieu and
    Shubho Sengupta and
    Prasad Buddhavarapu and
    Benjamin M Case",
  title = "Delegated Private Matching for Compute",
  year = 2023,
  howpublished = "Cryptology ePrint Archive, Report 2023/012",
  note = "\url{https://eprint.iacr.org/2023/012}",
}
```

## Multi-Key Private-ID
```
@Misc{EPRINT:BCGKMSTX21,
  author = "Prasad Buddhavarapu and
    Benjamin M Case and
    Logan Gore and
    Andrew Knox and
    Payman Mohassel and
    Shubho Sengupta and
    Erik Taubeneck and
    Min Xue",
  title = "Multi-key Private Matching for Compute",
  year = 2021,
  howpublished = "Cryptology ePrint Archive, Report 2021/770",
  note = "\url{https://eprint.iacr.org/2021/770}",
}
```

## Private-ID
```
@Misc{EPRINT:BKMSTV20,
  author = "Prasad Buddhavarapu and
    Andrew Knox and
    Payman Mohassel and
    Shubho Sengupta and
    Erik Taubeneck and
    Vlad Vlaskin",
  title = "Private Matching for Compute",
  year = 2020,
  howpublished = "Cryptology ePrint Archive, Report 2020/599",
  note = "\url{https://eprint.iacr.org/2020/599}",
}
```

## License
Private-ID is Apache 2.0 licensed, as found in the [LICENSE](/LICENSE) file.

## Additional Resources on Private Computation at Meta
* [Delegated Multi-key Private Matching for Compute: Improving match rates and enabling adoption](https://research.facebook.com/blog/2023/1/delegated-multi-key-private-matching-for-compute-improving-match-rates-and-enabling-adoption/)
* [Private matching for compute](https://engineering.fb.com/2020/07/10/open-source/private-matching/)
* [The Value of Secure Multi-Party Computation](https://privacytech.fb.com/multi-party-computation/)
* [Building the Next Era of Personalized Experiences](https://www.facebook.com/business/news/building-the-next-era-of-personalized-experiences)
* [Privacy-Enhancing Technologies and Building for the Future](https://www.facebook.com/business/news/building-for-the-future)
