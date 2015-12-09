service nginx stop
mkdir /root/backup
rm /root/backup/nginx -r
mkdir /root/backup/nginx
cp -R /etc/nginx/* /root/backup/nginx

NGINX_VERSION="1.9.7"
OPENSSL_VERSION="1.0.2e"
OPENSSH_VERSION="7.1"
NPS_VERSION="1.9.32.10"
NAXSI_VERSION="0.54"

cd ~/sources
echo "${info} Downloading Nginx Pagespeed..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
wget https://github.com/pagespeed/ngx_pagespeed/archive/release-${NPS_VERSION}-beta.zip >/dev/null 2>&1
unzip -qq release-${NPS_VERSION}-beta.zip
cd ngx_pagespeed-release-${NPS_VERSION}-beta/
wget https://dl.google.com/dl/page-speed/psol/${NPS_VERSION}.tar.gz >/dev/null 2>&1
tar -xzf ${NPS_VERSION}.tar.gz
cd ~/sources
echo "${info} Downloading Naxsi..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
wget --no-check-certificate https://github.com/nbs-system/naxsi/archive/${NAXSI_VERSION}.tar.gz >/dev/null 2>&1
tar -xzf ${NAXSI_VERSION}.tar.gz
echo "${info} Downloading Nginx..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
wget http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz >/dev/null 2>&1
tar -xzf nginx-${NGINX_VERSION}.tar.gz
cd nginx-${NGINX_VERSION}

sed -i '49s/.*/static char ngx_http_server_string[] = "";/' src/http/ngx_http_header_filter_module.c
sed -i '50s/.*/static char ngx_http_server_full_string[] = "";/' src/http/ngx_http_header_filter_module.c
sed -i '281s/.*/        len += clcf->server_tokens ? sizeof(ngx_http_server_full_string) - 0:/' src/http/ngx_http_header_filter_module.c
sed -i '282s/.*/                                     sizeof(ngx_http_server_string) - 0;/' src/http/ngx_http_header_filter_module.c
sed -i '217s/.*/\/*    if (r->headers_out.server == NULL) {/' src/http/v2/ngx_http_v2_filter_module.c
sed -i '220s/.*/    } *\//' src/http/v2/ngx_http_v2_filter_module.c
sed -i '407s/.*/\/*    if (r->headers_out.server == NULL) {/' src/http/v2/ngx_http_v2_filter_module.c
sed -i '418s/.*/    } *\//' src/http/v2/ngx_http_v2_filter_module.c

sed -i '20,298d' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_507_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_504_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_503_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_502_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_501_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_500_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_497_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_496_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_495_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_494_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_416_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_415_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_414_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_413_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_412_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_411_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_410_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_409_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_408_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_406_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_405_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_404_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_403_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_402_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_401_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_400_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_307_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_303_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_302_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_301_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static u_char ngx_http_msie_refresh_tail[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static u_char ngx_http_msie_refresh_head[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static u_char ngx_http_msie_padding[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static u_char ngx_http_error_tail[] =""CRLF;\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static u_char ngx_http_error_full_tail[] =""CRLF;\n&/' src/http/ngx_http_special_response.c

sed -i '121s/.*/#define NGX_SSL_BUFSIZE  1400/' src/event/ngx_event_openssl.h
sed -i '732s/.*/                (void) BIO_set_write_buffer_size(wbio, 16384);/' src/event/ngx_event_openssl.c

./configure --prefix=/etc/nginx \
--sbin-path=/usr/sbin/nginx \
--conf-path=/etc/nginx/nginx.conf \
--error-log-path=/var/log/nginx/error.log \
--http-log-path=/var/log/nginx/access.log \
--pid-path=/var/run/nginx.pid \
--lock-path=/var/run/nginx.lock \
--http-client-body-temp-path=/var/lib/nginx/body \
--http-proxy-temp-path=/var/lib/nginx/proxy \
--http-fastcgi-temp-path=/var/lib/nginx/fastcgi \
--http-uwsgi-temp-path=/var/lib/nginx/uwsgi \
--http-scgi-temp-path=/var/lib/nginx/scgi \
--user=www-data \
--group=www-data \
--without-http_autoindex_module \
--without-http_browser_module \
--without-http_empty_gif_module \
--without-http_map_module \
--without-http_userid_module \
--without-http_split_clients_module \
--with-http_ssl_module \
--with-http_v2_module \
--with-http_realip_module \
--with-http_addition_module \
--with-http_sub_module \
--with-http_dav_module \
--with-http_flv_module \
--with-http_mp4_module \
--with-http_gunzip_module \
--with-http_gzip_static_module \
--with-http_random_index_module \
--with-http_secure_link_module \
--with-http_stub_status_module \
--with-http_auth_request_module \
--with-mail \
--with-mail_ssl_module \
--with-file-aio \
--with-ipv6 \
--with-debug \
--with-cc-opt='-O2 -g -pipe -Wall -Wformat -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector --param=ssp-buffer-size=4 -m64 -mtune=generic' \
--with-openssl=$HOME/sources/openssl-${OPENSSL_VERSION} \
--add-module=$HOME/sources/ngx_pagespeed-release-${NPS_VERSION}-beta \
--add-module=$HOME/sources/naxsi-${NAXSI_VERSION}/naxsi_src >/dev/null 2>&1

make

checkinstall --install=no -y

dpkg -i nginx_${NGINX_VERSION}-1_amd64.deb

mv nginx_${NGINX_VERSION}-1_amd64.deb ../
cp -R /root/backup/nginx/* /etc/nginx/

service nginx start
