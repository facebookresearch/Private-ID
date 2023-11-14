FROM rust:latest AS build
LABEL maintainer="Vlad Vlaskin <vladvlaskin@fb.com>"

ENV BASE /usr/local
RUN apt-get update && \
    apt-get install -y cmake
RUN rustup install stable && \
rustup component add rustfmt --toolchain stable-x86_64-unknown-linux-gnu

ADD . /opt/private-id
WORKDIR /opt/private-id
RUN cargo +stable build \
    --release \
    --workspace \
    --target-dir /opt/private-id/bin


#cleanup everything except binaries
RUN mkdir -p /opt/private-id/exec && \
cp bin/release/private-id-server exec  && \
cp bin/release/private-id-client exec  && \
cp bin/release/cross-psi-server exec && \
cp bin/release/cross-psi-client exec && \
cp bin/release/cross-psi-xor-server exec && \
cp bin/release/cross-psi-xor-client exec && \
cp bin/release/pjc-client exec && \
cp bin/release/pjc-server exec && \
cp bin/release/datagen exec && \
cp bin/release/private-id-multi-key-server exec && \
cp bin/release/private-id-multi-key-client exec && \
cp bin/release/dpmc-company-server exec && \
cp bin/release/dpmc-helper exec && \
cp bin/release/dpmc-partner-server exec && \
cp bin/release/dspmc-company-server exec && \
cp bin/release/dspmc-helper-server exec && \
cp bin/release/dspmc-partner-server exec && \
cp bin/release/dspmc-shuffler exec

# thin container with binaries
# base image is taken from here https://hub.docker.com/_/debian/
FROM debian:stable-slim AS privateid
RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/private-id/exec /opt/private-id/bin
WORKDIR /opt/private-id
