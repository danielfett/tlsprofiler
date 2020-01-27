FROM nginx:1.17.7

COPY old/dhparams1024.pem /etc/ssl/dhparams1024.pem

COPY certificates/rsa_ca_cert.pem /etc/ssl/rsa_ca_cert.pem

COPY certificates/old_key.pem /etc/ssl/tls_key.pem
COPY certificates/old_cert.pem /etc/ssl/tls_cert.pem

COPY old/default.conf /etc/nginx/conf.d/default.conf
