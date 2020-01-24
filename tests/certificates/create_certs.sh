#!/bin/bash

# RSA root certificate
openssl genrsa -out rsa_ca_key.pem 2048
openssl req -x509 -new -nodes -key rsa_ca_key.pem -out rsa_ca_cert.pem -days 365 -sha256 \
  -subj "/C=TE/ST=TEST/L=TEST/O=TEST/CN=test.dev.intranet"

# ECDSA root certificate
openssl ecparam -out ecdsa_ca_key.pem -name prime256v1 -genkey
openssl req -x509 -new -nodes -key ecdsa_ca_key.pem -out ecdsa_ca_cert.pem -days 365 -sha256 \
  -subj "/C=TE/ST=TEST/L=TEST/O=TEST/CN=test.dev.intranet"

# Certificate for the modern server
openssl ecparam -out modern_key.pem -name prime256v1 -genkey
openssl req -new -key modern_key.pem -out modern_cert.csr -sha512 \
  -subj "/C=TE/ST=TEST/L=TEST/O=TEST/CN=modern.dev.intranet"
openssl x509 -req -in modern_cert.csr -CA ecdsa_ca_cert.pem -CAkey ecdsa_ca_key.pem \
  -CAcreateserial -out modern_cert.pem -days 90 -sha512

# Certificate for the intermediate server
openssl genrsa -out intermediate_key.pem 2048
openssl req -new -key intermediate_key.pem -out intermediate_cert.csr -sha256 \
  -subj "/C=TE/ST=TEST/L=TEST/O=TEST/CN=intermediate.dev.intranet"
openssl x509 -req -in intermediate_cert.csr -CA ecdsa_ca_cert.pem -CAkey ecdsa_ca_key.pem \
  -CAcreateserial -out intermediate_cert.pem -days 13 -sha256

# Certificate for the old server
openssl genrsa -out old_key.pem 2048
openssl req -new -key old_key.pem -out old_cert.csr -sha256 \
  -subj "/C=TE/ST=TEST/L=TEST/O=TEST/CN=old.dev.intranet"
openssl x509 -req -in old_cert.csr -CA rsa_ca_cert.pem -CAkey rsa_ca_key.pem \
  -CAcreateserial -out old_cert.pem -days 730 -sha256

# Certificate for the none server
openssl ecparam -out none_key.pem -name secp521r1 -genkey
openssl req -new -key none_key.pem -out none_cert.csr -sha384 \
  -subj "/C=TE/ST=TEST/L=TEST/O=TEST/CN=none.dev.intranet"
openssl x509 -req -in none_cert.csr -CA ecdsa_ca_cert.pem -CAkey ecdsa_ca_key.pem \
  -CAcreateserial -out none_cert.pem -days 1000 -sha384
