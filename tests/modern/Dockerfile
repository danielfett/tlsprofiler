FROM httpd:2.4.41

COPY certificates/modern_key.pem /usr/local/apache2/conf/tls_key.pem
COPY certificates/modern_cert.pem /usr/local/apache2/conf/tls_cert.pem

COPY modern/httpd.conf /usr/local/apache2/conf/httpd.conf
COPY modern/httpd-ssl.conf /usr/local/apache2/conf/extra/httpd-ssl.conf
