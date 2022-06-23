#!/bin/bash

set -e

directory="$( dirname -- "$0";)/dummy_certs";
mkdir "$directory" || exit
cd "$directory" || exit

# Create cnf file. DNS name is VERY important
tee ssl-extensions-x509.cnf << EOF
[v3_ca]
authorityKeyIdentifier = keyid,issuer
basicConstraints = CA:FALSE
keyUsage = Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
EOF

#Generate a private key for the CA:
openssl genrsa 2048 > ca.key
#Generate the X509 certificate for the CA:
openssl req -new -x509 -nodes -days 365000 \
   -key ca.key \
   -out ca.pem \
   -subj "/C=US/ST=CA State/L=Menlo Park City/O=Meta Inc./CN=example.com"

#Generate the private key and certificate request of server:
openssl req -newkey rsa:2048 -nodes -days 365 \
   -keyout server.key \
   -out server_requst.pem \
   -subj "/C=US/ST=CA State/L=Menlo Park City/O=Meta Inc./CN=server.example.com"
#Generate the X509 certificate for the server:
openssl x509 -req -days 365 \
   -in server_requst.pem \
   -out server.pem \
   -CA ca.pem \
   -CAkey ca.key \
   -CAcreateserial \
   -extensions v3_ca \
   -extfile ./ssl-extensions-x509.cnf

#Generate the private key and certificate request of client:
openssl req -newkey rsa:2048 -nodes -days 365 \
   -keyout client.key \
   -out client_request.pem \
   -subj "/C=US/ST=CA State/L=Menlo Park City/O=Meta Inc./CN=server.example.com"
#Generate the X509 certificate for the client:
openssl x509 -req -days 365 \
   -in client_request.pem \
   -out client.pem \
   -CA ca.pem \
   -CAkey ca.key \
   -CAcreateserial \
   -extensions v3_ca \
   -extfile ./ssl-extensions-x509.cnf
