# Private-ID

Private-ID is a collection of algorithms to match records between two or more parties, while preserving the privacy of these records. We present multiple algorithms to do this---one of which does an outer join between parties, and others do inner or left join and then generate additive shares that can then be input to a Multi Party Compute system like [CrypTen](https://github.com/facebookresearch/CrypTen). Please refer to our [paper](https://eprint.iacr.org/2020/599.pdf) for more details. The MultiKey Private-ID [paper](https://eprint.iacr.org/2021/770.pdf) and the Delegated Private-ID [paper](https://eprint.iacr.org/2023/012.pdf) extend Private-ID.

## Build

Private-ID is implemented in Rust to take advantage of the language's security features and to leverage the encryption libraries that we depend on. It should compile with the nightly Rust toolchain.

The following should build and run the unit tests for the building blocks used by the protocols

```bash
cargo build --release
cargo test --release
```

Each protocol involves two (or more) parties and they have to be run in their own shell environment. We call one party Company and another party Partner. Some protocols also involve additional parties such as the Helper and the Shuffler.

Run the script at etc/example/generate_cert.sh to generate dummy_certs directory if you want to test protocol with TLS on local.

### Build & Run With Docker Compose
The following, run each party in a different container:
* Private-ID: `docker compose --profile private-id up`
* Delegated Private Matching for Compute (DPMC): `docker compose --profile dpmc up`
* Delegated Private Matching for Compute with Secure Shuffling (DSPMC): `docker compose --profile dspmc up`

By default, this will create datasets of 10 items each. To run with bigger datasets set the `ENV_VARIABLE_FOR_SIZE` environment variable. For example: `ENV_VARIABLE_FOR_SIZE=100 docker compose --profile dpmc up` will run DPMC with datasets of 100 items each.

Note, to run on an ARM machine modify the Dockerfile and add `--platform=linux/amd64` to the two `FROM` lines (e.g., `FROM --platform=linux/amd64 rust:latest AS build`, `FROM --platform=linux/amd64 debian:stable-slim AS privateid`).

## Private-ID

This protocol maps the email addresses from both parties to a single ID spine, so that same e-mail addresses map to the same key.

To run Company:
```bash
env RUST_LOG=info cargo run --release --bin private-id-server -- \
  --host 0.0.0.0:10009 \
  --input etc/example/email_company.csv \
  --stdout \
  --no-tls
```

To run Partner:
```bash
env RUST_LOG=info cargo run --release --bin private-id-client -- \
  --company localhost:10009 \
  --input etc/example/email_partner.csv \
  --stdout \
  --no-tls
```

## Private-ID MultiKey

We extend the Private-ID protocol to match multiple identifiers. Please refer to our [paper](https://eprint.iacr.org/2021/770) for more details.

To run Company:
```bash
env RUST_LOG=info cargo run --release --bin private-id-multi-key-server -- \
  --host 0.0.0.0:10009 \
  --input etc/example/private_id_multi_key/Ex1_company.csv \
  --stdout \
  --no-tls
```

To run Partner:
```bash
env RUST_LOG=info cargo run --release --bin private-id-multi-key-client -- \
  --company localhost:10009 \
  --input etc/example/private_id_multi_key/Ex1_partner.csv \
  --stdout \
  --no-tls
```

## PS3I

This protocol does an inner join based on email addresses as keys and then generates additive share of a feature associated with that email address. The shares are generated in the designated output files as 64-bit numbers

To run Company:
```bash
env RUST_LOG=info cargo run --release --bin cross-psi-server -- \
  --host 0.0.0.0:10010 \
  --input etc/example/input_company.csv \
  --output etc/example/output_company.csv \
  --no-tls
```

To run Partner:
```bash
env RUST_LOG=info cargo run --release --bin cross-psi-client -- \
  --company localhost:10010 \
  --input etc/example/input_partner.csv \
  --output etc/example/output_partner.csv \
  --no-tls
```

## PS3I XOR

This protocol does an inner join based on email addresses as keys and then generates XOR share of a feature associated with that email address. The shares are generated in the designated output files as 64-bit numbers

To run Company:
```bash
env RUST_LOG=info cargo run --release --bin cross-psi-xor-server -- \
  --host 0.0.0.0:10010 \
  --input etc/example/cross_psi_xor/input_company.csv \
  --output etc/example/cross_psi_xor/output_company \
  --no-tls
```

To run Partner:
```bash
env RUST_LOG=info cargo run --release --bin cross-psi-xor-client -- \
  --company localhost:10010 \
  --input etc/example/cross_psi_xor/input_partner.csv \
  --output etc/example/cross_psi_xor/output_partner \
  --no-tls
```

The `--output` option provides prefix for the output files that contain the shares. In this case, Company generates two files; `output_company_company_feature.csv` and `output_company_partner_feature.csv`. They contain Company's share of company and partner features respectively. Similarly, Partner generates two files; `output_partner_company_feature.csv` and `output_partner_partner_feature.csv`. They contain Partner's share of company and partner features respectively.

Thus `output_company_company_feature.csv` and `output_partner_company_feature.csv` are XOR shares of Company's features. Similarly, `output_partner_company_feature.csv` and `output_partner_partner_feature.csv` are XOR shares of Partner's features.

### Private Join and Compute
This is an implementation of Google's [Private Join and Compute](https://github.com/google/private-join-and-compute) protocol, that does a inner join based on email addresses and computes a sum of the corresponding feature for the Partner.

To run Company:
```bash
env RUST_LOG=info cargo run --release --bin pjc-server -- \
  --host 0.0.0.0:10011 \
  --input etc/example/pjc_company.csv \
  --stdout \
  --no-tls
```

To run Partner:
```bash
env RUST_LOG=info cargo run --release --bin pjc-client -- \
  --company localhost:10011 \
  --input etc/example/pjc_partner.csv \
  --stdout \
  --no-tls
```

## SUMID
This is an implementation of 2-party version of Secure Universal ID protocol. This can work on multiple keys. In the current implementation, the merger party also assumes the role of one data party and the sharer party assumes the role of all the other data parties. The data parties are the `.csv` files show below

To run merger:
```bash
env RUST_LOG=info cargo run --release --bin suid-create-server -- \
  --host 0.0.0.0:10010 \
  --input etc/example/suid/Example1/DataParty2_input.csv \
  --stdout \
  --no-tls
```

To run client:
```bash
env RUST_LOG=info cargo run --release --bin suid-create-client -- \
  --merger localhost:10010 \
  --input etc/example/suid/Example1/DataParty1_input.csv \
  --input etc/example/suid/Example1/DataParty3_input.csv \
  --stdout \
  --no-tls
```

The output will be ElGamal encrypted Universal IDs assigned to each entry in the `.csv` file.

## Delegated Private Matching for Compute (DPMC)

We extend the Multi-key Private-ID protocol to multiple partners. Please refer to our [paper](https://eprint.iacr.org/2023/012) for more details.

To run Company:
```bash
env RUST_LOG=info cargo run --release --bin dpmc-company-server -- \
  --host 0.0.0.0:10010 \
  --input etc/example/dpmc/Ex0_company.csv \
  --stdout \
  --output-shares-path etc/example/dpmc/output_company \
  --no-tls
```

To run multiple partners (servers):
```bash
env RUST_LOG=info cargo run --release --bin dpmc-partner-server -- \
  --host 0.0.0.0:10020 \
  --company localhost:10010 \
  --input-keys etc/example/dpmc/Ex0_partner_1.csv \
  --input-features etc/example/dpmc/Ex0_partner_1_features.csv \
  --no-tls
```

```bash
env RUST_LOG=info cargo run --release --bin dpmc-partner-server -- \
  --host 0.0.0.0:10021 \
  --company localhost:10010 \
  --input-keys etc/example/dpmc/Ex0_partner_2.csv \
  --input-features etc/example/dpmc/Ex0_partner_2_features.csv \
  --no-tls
```

Start helper (client):
```bash
env RUST_LOG=info cargo run --release --bin dpmc-helper -- \
  --company localhost:10010 \
  --partners localhost:10020,localhost:10021 \
  --stdout \
  --output-shares-path etc/example/dpmc/output_partner \
  --no-tls
```

The above will generate one-to-one matches.

To explain the results, we need to look at the inputs first:

### Inputs

Company Input:
```bash
email1
email2
email3
email4
```

Partner 1 Input (IDs):
```bash
email1
email7
```

Partner 1 Input (Associated Data):
```bash
10, 0
50, 50
```

Partner 2 Input:
```bash
email1
email4
```

Partner 2 Input (Associated Data):
```bash
20, 21
30, 31
```

### Outputs

Company:
```bash
2C124C57A040C6FEB396F101F84C3B8C6A466FA53C0FDED94E8F725F2E9704B,email4
6695895CB82E629598547D93FA67403D4249B83A9944A21E53BBE3F9854F7140,email3
CEE0A32A239B802558ABFD57EE87587B5FD15D64E73FD805D13A1303CDD5429,email2
FEC9F87838BEEFFD3B689D13A538FB05767B2F9CDEE53903D22E67B91F,email1
```

Output Secret shares at `etc/example/dpmc/output_company_partner_features.csv`:
```bash
2123763108355018584,7917888405770470969
7553524091763063603,12192982022453250030
12025288841580037526,5628706741631442660
12193188557740602958,3696238821401023600
```

Helper:
```bash
2C124C57A040C6FEB396F101F84C3B8C6A466FA53C0FDED94E8F725F2E9704B, Partner enc key at pos 0
6695895CB82E629598547D93FA67403D4249B83A9944A21E53BBE3F9854F7140,NA
CEE0A32A239B802558ABFD57EE87587B5FD15D64E73FD805D13A1303CDD5429,NA
FEC9F87838BEEFFD3B689D13A538FB05767B2F9CDEE53903D22E67B91F, Partner enc key at pos 0
```

Output Secret shares at `etc/example/dpmc/output_partner_partner_features.csv`:
```bash
2123763108355018566,7917888405770470950
7553524091763063603,12192982022453250030
12025288841580037526,5628706741631442660
12193188557740602948,3696238821401023600
```

Since DPMC focuses on left-join, wherever was a match in Company's dataset, we have secret shares
of the partner's associated data, while wherever there was no match, we have secret shares of zero.

Indeed, since `email1` and `email4` matched:
```bash
2123763108355018584 ^ 2123763108355018566 = 30,   7917888405770470969 ^ 7917888405770470950 = 31
7553524091763063603 ^ 7553524091763063603 = 0,    12192982022453250030 ^ 12192982022453250030 = 0
12025288841580037526 ^ 12025288841580037526 = 0,  5628706741631442660 ^ 5628706741631442660 = 0
12193188557740602958 ^ 12193188557740602948 = 10, 3696238821401023600 ^ 3696238821401023600 = 0
```
Observe that `email1` matched with both partners but since this is one-to-one matching then the
first match was only considered.

### One-to-many matches

To enable one-to-many matches (one record from C will match to `M` P records), use the flag
`--one-to-many M` in the `dpmc-helper` binary, where `M` is the number of matches.

For example, using the same scripts as above for company and partners, to run
`1-2` matching, start the helper as follows:

```bash
env RUST_LOG=info cargo run --release --bin dpmc-helper -- \
  --company localhost:10010 \
  --partners localhost:10020,localhost:10021 \
  --one-to-many 2 \
  --stdout \
  --output-shares-path etc/example/dpmc/output_partner \
  --no-tls
```

### Outputs

Company:
```bash
267549DEDFC9898B9ADB99278E86162155119ADBDCC1589F44E12EC66AD723,email2
40C1E76B6F2CF94B1B86D31FD9FB5C62B9114C85FC2AAAB59A6A1379044323,email1
44469BA5EBF28547491442BA88A996C91D2E5C1874BD56131FDE6FC2C19F95B,email4
725FAAA4E9862E5983979C85E58AA59347FF2C5C1AE0CC89201B34711588E957,email3
```

Output Secret shares at `etc/example/dpmc/output_company_partner_features.csv`:
```bash
15639158529780438101,10355320774873656494
13789343269605551875,7497287768912087672
1103603035954233860,16491667106643692030
16818785984424715268,17987764095998628258
5216582505071635321,17033543400689351118
9296137075950449950,6917021766104166842
1775928733629157667,2173601871347247126
10727446575062113091,6625868366339267723
```

Helper:
```bash
267549DEDFC9898B9ADB99278E86162155119ADBDCC1589F44E12EC66AD723, NA
267549DEDFC9898B9ADB99278E86162155119ADBDCC1589F44E12EC66AD723, NA
40C1E76B6F2CF94B1B86D31FD9FB5C62B9114C85FC2AAAB59A6A1379044323, Partner enc key at pos 0
40C1E76B6F2CF94B1B86D31FD9FB5C62B9114C85FC2AAAB59A6A1379044323, Partner enc key at pos 1
44469BA5EBF28547491442BA88A996C91D2E5C1874BD56131FDE6FC2C19F95B, Partner enc key at pos 0
44469BA5EBF28547491442BA88A996C91D2E5C1874BD56131FDE6FC2C19F95B, NA
725FAAA4E9862E5983979C85E58AA59347FF2C5C1AE0CC89201B34711588E957, NA
725FAAA4E9862E5983979C85E58AA59347FF2C5C1AE0CC89201B34711588E957, NA
```

Output Secret shares at `etc/example/dpmc/output_partner_partner_features.csv`:
```bash
15639158529780438101,10355320774873656494
13789343269605551875,7497287768912087672
1103603035954233870,16491667106643692030
16818785984424715280,17987764095998628279
5216582505071635303,17033543400689351121
9296137075950449940,6917021766104166842
1775928733629157667,2173601871347247126
10727446575062113091,6625868366339267723
```

Since DPMC focuses on left-join, wherever was a match in Company's dataset, we have secret shares
of the partner's associated data, while wherever there was no match, we have secret shares of zero.

Indeed, since `email1` and `email4` matched:
```bash
15639158529780438101 ^ 15639158529780438101 = 0,  10355320774873656494 ^ 10355320774873656494 = 0
13789343269605551875 ^ 13789343269605551875 = 0,  7497287768912087672 ^ 7497287768912087672 = 0
1103603035954233860 ^ 1103603035954233870 = 10,   16491667106643692030 ^ 16491667106643692030 = 0
16818785984424715268 ^ 16818785984424715280 = 20, 17987764095998628258 ^ 17987764095998628279 = 21
5216582505071635321 ^ 5216582505071635303 = 30,   17033543400689351118 ^ 17033543400689351121 = 31
9296137075950449950 ^ 9296137075950449940 = 0,   6917021766104166842 ^ 6917021766104166842 = 0
1775928733629157667 ^ 1775928733629157667 = 0,    2173601871347247126 ^ 2173601871347247126 = 0
10727446575062113091 ^ 10727446575062113091 = 0,  6625868366339267723 ^ 6625868366339267723 = 0

```
Observe that `email1` matched with both partners and here we have secret shares for both.


## Delegated Private Matching for Compute with Secure Shuffling (DsPMC)

Start helper (server):
```bash
env RUST_LOG=info cargo run --release --bin dspmc-helper-server -- \
  --host 0.0.0.0:10030 \
  --stdout \
  --output-shares-path etc/example/dspmc/output_helper \
  --no-tls
```

Start company (server):
```bash
env RUST_LOG=info cargo run --release --bin dspmc-company-server -- \
  --host 0.0.0.0:10010 \
  --helper localhost:10030 \
  --input etc/example/dspmc/Ex0_company.csv \
  --stdout \
  --output-shares-path etc/example/dspmc/output_company \
  --no-tls
```

Start multiple partners (servers):
```bash
env RUST_LOG=info cargo run --release --bin dspmc-partner-server -- \
  --host 0.0.0.0:10020 \
  --company localhost:10010 \
  --input-keys etc/example/dspmc/Ex0_partner_1.csv \
  --input-features etc/example/dspmc/Ex0_partner_1_features.csv \
  --no-tls
```

```bash
env RUST_LOG=info cargo run --release --bin dspmc-partner-server -- \
  --host 0.0.0.0:10021 \
  --company localhost:10010 \
  --input-keys etc/example/dspmc/Ex0_partner_2.csv \
  --input-features etc/example/dspmc/Ex0_partner_2_features.csv \
  --no-tls
```

Start Shuffler (client):
```bash
env RUST_LOG=info cargo run --release --bin dspmc-shuffler -- \
  --company localhost:10010 \
  --helper localhost:10030 \
  --partners localhost:10020,localhost:10021 \
  --stdout \
  --no-tls
```

### Note: Running over the network
To run over the network instead of localhost prepend the IP address with `http://` or `https://`. For example:

To run Company (in IP `1.23.34.45`):
```bash
env RUST_LOG=info cargo run --release --bin dpmc-company-server -- \
  --host 0.0.0.0:10010 \
  --input etc/example/dpmc/Ex0_company.csv \
  --stdout \
  --output-shares-path etc/example/dpmc/output_company \
  --no-tls
```

To run multiple partners (servers) (in IPs `76.65.54.43` and `76.65.54.44`):
```bash
env RUST_LOG=info cargo run --release --bin dpmc-partner-server -- \
  --host 0.0.0.0:10020 \
  --company http://1.23.34.45:10010 \
  --input-keys etc/example/dpmc/Ex0_partner_1.csv \
  --input-features etc/example/dpmc/Ex0_partner_1_features.csv \
  --no-tls
```

```bash
env RUST_LOG=info cargo run --release --bin dpmc-partner-server -- \
  --host 0.0.0.0:10021 \
  --company http://1.23.34.45:10010 \
  --input-keys etc/example/dpmc/Ex0_partner_2.csv \
  --input-features etc/example/dpmc/Ex0_partner_2_features.csv \
  --no-tls
```

Start helper (client):
```bash
env RUST_LOG=info cargo run --release --bin dpmc-helper -- \
  --company http://1.23.34.45:10010 \
  --partners http://76.65.54.43:10020,http://76.65.54.44:10021 \
  --stdout \
  --output-shares-path etc/example/dpmc/output_partner \
  --no-tls
```

# Citing Private-ID

To cite Private-ID in academic papers, please use the following BibTeX entries.

## Delegated Private-ID
```
@Article{PoPETS:MMTSBC23,
  author = "Dimitris Mouris and
    Daniel Masny and
    Ni Trieu and
    Shubho Sengupta and
    Prasad Buddhavarapu and
    Benjamin M Case",
  title =   "{Delegated Private Matching for Compute}",
  volume =  2024,
  month =   Jul,
  year =    2024,
  journal = "{Proceedings on Privacy Enhancing Technologies}",
  number =  2,
  pages =   "1--24",
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
