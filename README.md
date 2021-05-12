# Private-ID

Private-ID is a collection of algorithms to match records between two parties, while preserving the privacy of these records. We present two algorithms to do this---one of which does an outer join between parties and another does a inner join and then generates additive shares that can then be input to a Multi Party Compute system like [CrypTen](https://github.com/facebookresearch/CrypTen). Please refer to our [paper](https://eprint.iacr.org/2020/599.pdf) for more details.

### Build

Private-ID is implemented in Rust to take advantage of the languages security features and to leverage the encryption libraries that we depend on. It should compile with the nightly Rust toolchain.

The following should build and run the unit tests for the building blocks used by the protocols

- `cargo build`, `cargo test`

Each protocol involves two parties and they have to be run in its own shell environment. We call one party Company and another party Partner.

### Private-ID 

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

### PS3I 

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
### SUMID
This is an implmentation of 2-party version of Secure Universal ID protocol. This can work on multiple keys. In the current implementation, the merger party also assumes the role of one data party and the sharer party assumes the role of all the other data parties. The data parties are the `.csv` files show below

To run merger
```bash
env RUST_LOG=info cargo run --bin suid-create-server -- \
        --host 0.0.0.0:10010 \
        --input etc/docker/suid/Example1/DataParty2_input.csv \
        --stdout \
        --tls-dir etc/docker/dummy_certs
```

To run merger
```bash
env RUST_LOG=info cargo run --bin suid-create-client -- \
     --merger localhost:10010 \
     --input etc/docker/suid/Example1/DataParty1_input.csv \
     --input etc/docker/suid/Example1/DataParty3_input.csv \
     --stdout \
     --tls-dir etc/docker/dummy_certs
```

The output will be ElGamal encrypted Universal IDs assigned to each entry in the `.csv` file

## License
Private-ID is Apache 2.0 licensed, as found in the LICENSE file
