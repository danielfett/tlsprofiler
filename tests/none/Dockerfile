FROM httpd:2.4

RUN apt update && apt install -y openssl

COPY none/httpd.conf /usr/local/apache2/conf/httpd.conf
COPY none/httpd-ssl.conf /usr/local/apache2/conf/extra/httpd-ssl.conf

COPY none/dhparams4096.pem /usr/local/apache2/conf/dhparams4096.pem

COPY certificates/ecdsa_ca_key.pem /usr/local/apache2/conf/ecdsa_ca_key.pem
COPY certificates/ecdsa_ca_cert.pem /usr/local/apache2/conf/ecdsa_ca_cert.pem

WORKDIR /usr/local/apache2/conf/

RUN openssl ecparam -out tls_key.pem -name secp521r1 -genkey
RUN openssl req -new -key tls_key.pem -out tls_cert.csr -sha384 \
    -subj "/C=TE/ST=TEST/L=TEST/O=TEST/CN=none.dev.intranet"
RUN openssl x509 -req -in tls_cert.csr -CA ecdsa_ca_cert.pem -CAkey ecdsa_ca_key.pem \
    -CAcreateserial -out tls_cert.pem -days 1000 -sha384

RUN cat dhparams4096.pem >> tls_cert.pem
