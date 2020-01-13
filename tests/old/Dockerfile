FROM nginx:1.17.7

RUN apt update && apt install -y openssl

COPY old/default.conf /etc/nginx/conf.d/default.conf

COPY old/dhparams1024.pem /etc/ssl/dhparams1024.pem

COPY certificates/rsa_ca_key.pem /etc/ssl/rsa_ca_key.pem
COPY certificates/rsa_ca_cert.pem /etc/ssl/rsa_ca_cert.pem

WORKDIR /etc/ssl/

RUN openssl genrsa -out tls_key.pem 2048
RUN openssl req -new -key tls_key.pem -out tls_cert.csr -sha256 \
    -subj "/C=TE/ST=TEST/L=TEST/O=TEST/CN=old.dev.intranet"
RUN openssl x509 -req -in tls_cert.csr -CA rsa_ca_cert.pem -CAkey rsa_ca_key.pem \
    -CAcreateserial -out tls_cert.pem -days 730 -sha256


RUN apt purge -y openssl