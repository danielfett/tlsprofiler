FROM httpd:2.4.41

COPY intermediate/dhparams2048.pem /usr/local/apache2/conf/dhparams2048.pem

COPY certificates/intermediate_key.pem /usr/local/apache2/conf/tls_key.pem
COPY certificates/intermediate_cert.pem /usr/local/apache2/conf/tls_cert.pem

COPY intermediate/httpd.conf /usr/local/apache2/conf/httpd.conf
COPY intermediate/httpd-ssl.conf /usr/local/apache2/conf/extra/httpd-ssl.conf
