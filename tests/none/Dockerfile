FROM httpd:2.4.41

WORKDIR /usr/local/apache2/conf/

COPY none/dhparams4096.pem dhparams4096.pem

COPY certificates/none_key.pem tls_key.pem
COPY certificates/none_cert.pem tls_cert.pem

RUN cat dhparams4096.pem >> tls_cert.pem

COPY none/httpd.conf /usr/local/apache2/conf/httpd.conf
COPY none/httpd-ssl.conf /usr/local/apache2/conf/extra/httpd-ssl.conf
