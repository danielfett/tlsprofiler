FROM httpd:2.4

RUN apt update && apt install -y openssl

COPY intermediate/httpd.conf /usr/local/apache2/conf/httpd.conf
COPY intermediate/httpd-ssl.conf /usr/local/apache2/conf/extra/httpd-ssl.conf

COPY intermediate/dhparams2048.pem /usr/local/apache2/conf/dhparams2048.pem

COPY certificates/ecdsa_ca_key.pem /usr/local/apache2/conf/ecdsa_ca_key.pem
COPY certificates/ecdsa_ca_cert.pem /usr/local/apache2/conf/ecdsa_ca_cert.pem

WORKDIR /usr/local/apache2/conf/

RUN openssl genrsa -out tls_key.pem 2048
RUN openssl req -new -key tls_key.pem -out tls_cert.csr -sha256 \
    -subj "/C=TE/ST=TEST/L=TEST/O=TEST/CN=intermediate.dev.intranet"
RUN openssl x509 -req -in tls_cert.csr -CA ecdsa_ca_cert.pem -CAkey ecdsa_ca_key.pem \
    -CAcreateserial -out tls_cert.pem -days 730 -sha256

RUN cat dhparams2048.pem >> tls_cert.pem

RUN apt purge -y openssl
