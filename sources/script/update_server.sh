source ~/updateconfig.cfg

IPADR=$(ifconfig eth0 | awk -F ' *|:' '/inet /{print $4}')

# Some nice colors
red() { echo "$(tput setaf 1)$*$(tput setaf 9)"; }
green() { echo "$(tput setaf 2)$*$(tput setaf 9)"; }
yellow() { echo "$(tput setaf 3)$*$(tput setaf 9)"; }
magenta() { echo "$(tput setaf 5)$*$(tput setaf 9)"; }
cyan() { echo "$(tput setaf 6)$*$(tput setaf 9)"; }
textb() { echo $(tput bold)${1}$(tput sgr0); }
greenb() { echo $(tput bold)$(tput setaf 2)${1}$(tput sgr0); }
redb() { echo $(tput bold)$(tput setaf 1)${1}$(tput sgr0); }
yellowb() { echo $(tput bold)$(tput setaf 3)${1}$(tput sgr0); }
pinkb() { echo $(tput bold)$(tput setaf 5)${1}$(tput sgr0); }

# Some nice variables
info="$(textb [INFO] -)"
warn="$(yellowb [WARN] -)"
error="$(redb [ERROR] -)"
fyi="$(pinkb [INFO] -)"
ok="$(greenb [OKAY] -)"

echo
echo "$(yellowb +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+)"
echo " $(textb Perfect) $(textb Rootserver) $(textb Update) $(textb by)" "$(cyan MXIIII)"
echo "$(yellowb +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+)"
echo
if [ "$CONFIG_COMPLETED" != '1' ]; then
echo "${error} Please check the userconfig and set a valid value for the variable \"$(textb CONFIG_COMPLETED)\" to continue." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
exit 1
fi
echo "${info} Backup..."

rm /root/backup/ -r >/dev/null 2>&1
mkdir -p /root/backup/fuglu >/dev/null 2>&1
mkdir /root/backup/nginx >/dev/null 2>&1

cp /var/www/mail/inc/footer.inc.php /root/backup/
cp /var/www/mail/inc/header.inc.php /root/backup/
cp /var/www/mail/inc/triggers.inc.php /root/backup/
cp /var/www/mail/inc/functions.inc.php /root/backup/
cp /var/www/mail/add.php /root/backup/
cp /var/www/mail/mailbox.php /root/backup/
cp /var/www/mail/delete.php /root//backup/
cp /var/www/mail/edit.php /root/backup/
cp /var/www/mail/admin.php /root/backup/
cp /etc/dovecot/dovecot.conf /root/backup/
cp /etc/spamassassin/local.cf /root/backup/
cp /etc/postfix/main.cf  /root/backup/
cp /etc/postfix/sql/mysql_virtual_sender_acl.cf /root/backup/ >/dev/null 2>&1
cp /etc/postfix/sql/mysql_virtual_alias_maps.cf /root/backup/
cp /etc/php5/fpm/pool.d/mail.conf /root/backup/
cp -R /etc/fuglu/* /root/backup/fuglu
cp -R /etc/nginx/* /root/backup/nginx
cp /usr/local/sbin/mc_pflog_renew /root/backup/
cp /var/www/mail/inc/vars.inc.php /root/backup/

echo "${info} Install..."

sed -i "s/myhostname =.*/myhostname = ${MYHOSTNAME}/g" ~/sources/update/main.cf 
sed -i "s/user =.*/user = ${MYSQLUSER}/g" ~/sources/update/mysql_virtual_sender_acl.cf
sed -i "s/hosts =.*/hosts = ${MYSQLHOST}/g" ~/sources/update/mysql_virtual_sender_acl.cf
sed -i "s/dbname =.*/dbname = ${MYSQLDB}/g" ~/sources/update/mysql_virtual_sender_acl.cf
sed -i "s/password =.*/password = ${MYSQLMAILCOW}/g" ~/sources/update/mysql_virtual_sender_acl.cf
sed -i "s/user =.*/user = ${MYSQLUSER}/g" ~/sources/update/mysql_virtual_alias_maps.cf
sed -i "s/hosts =.*/hosts = ${MYSQLHOST}/g" ~/sources/update/mysql_virtual_alias_maps.cf
sed -i "s/dbname =.*/dbname = ${MYSQLDB}/g" ~/sources/update/mysql_virtual_alias_maps.cf
sed -i "s/password =.*/password = ${MYSQLMAILCOW}/g" ~/sources/update/mysql_virtual_alias_maps.cf
sed -i 's/$database_user =.*/$database_user = "'${MYSQLUSER}'"/g' ~/sources/update/vars.inc.php
sed -i 's/$database_host =.*/$database_host = "'${MYSQLHOST}'"/g' ~/sources/update/vars.inc.php
sed -i 's/$database_name.*/$database_name = "'${MYSQLDB}'"/g' ~/sources/update/vars.inc.php
sed -i 's/$database_pass.*/$database_pass = "'${MYSQLMAILCOW}'"/g' ~/sources/update/vars.inc.php
sed -i "s/login_greeting =.*/login_greeting = ${MYHOSTNAME}/g" ~/sources/update/dovecot.conf
sed -i 's/.*cgi.fix_pathinfo=.*/cgi.fix_pathinfo=1/' /etc/php5/fpm/php.ini

cp ~/sources/update/footer.inc.php /var/www/mail/inc/ 
cp ~/sources/update/header.inc.php /var/www/mail/inc/ 
cp ~/sources/update/triggers.inc.php /var/www/mail/inc/
cp ~/sources/update/functions.inc.php /var/www/mail/inc/ 
cp ~/sources/update/add.php /var/www/mail/
cp ~/sources/update/mailbox.php /var/www/mail/
cp ~/sources/update/delete.php /var/www/mail/
cp ~/sources/update/edit.php /var/www/mail/
cp ~/sources/update/admin.php /var/www/mail/
install -m 644 ~/sources/update/dovecot.conf /etc/dovecot/ 
install -m 755 ~/sources/update/local.cf /etc/spamassassin/ 
install -m 755 ~/sources/update/main.cf /etc/postfix/ 
install -m 640 ~/sources/update/mysql_virtual_sender_acl.cf /etc/postfix/sql/ 
install -m 640 ~/sources/update/mysql_virtual_alias_maps.cf /etc/postfix/sql/ 
install -m 755 ~/sources/update/mail.conf /etc/php5/fpm/pool.d/
install -m 755 ~/sources/update/mc_pflog_renew /usr/local/sbin/
install -m 755 ~/sources/update/mc_setup_relayhost /usr/local/sbin/
install -m 755 ~/sources/update/mc_msg_size /usr/local/sbin/
cp ~/sources/update/vars.inc.php /var/www/mail/inc/

mysql --host localhost -u root -p${MYSQLROOT} mailcow -e "CREATE TABLE IF NOT EXISTS alias (address varchar(255) NOT NULL, goto text NOT NULL, domain varchar(255) NOT NULL, created datetime NOT NULL DEFAULT '0000-00-00 00:00:00', modified datetime NOT NULL DEFAULT '0000-00-00 00:00:00', active tinyint(1) NOT NULL DEFAULT '1', PRIMARY KEY (address), KEY domain (domain) ) ENGINE=InnoDB DEFAULT CHARSET=latin1;"
mysql --host localhost -u root -p${MYSQLROOT} mailcow -e "CREATE TABLE IF NOT EXISTS sender_acl (logged_in_as varchar(255) NOT NULL, send_as varchar(255) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=latin1;"
if [[ -z $(mysql --host localhost -u root -p${MYSQLROOT} mailcow -e "SHOW COLUMNS FROM domain LIKE 'relay_all_recipients';" -N -B) ]]; then 
		mysql --host localhost -u root -p${MYSQLROOT} mailcow -e "ALTER TABLE domain ADD relay_all_recipients tinyint(1) NOT NULL DEFAULT '0';" -N -B
fi
mysql --host localhost -u root -p${MYSQLROOT} mailcow -e "ALTER TABLE domain MODIFY COLUMN relay_all_recipients tinyint(1) NOT NULL DEFAULT '0';"

apt-get update >/dev/null 2>&1
apt-get install rrdtool -y >/dev/null 2>&1
apt-get install spawn-fcgi -y >/dev/null 2>&1
apt-get install mailgraph -y >/dev/null 2>&1
apt-get install memcached -y >/dev/null 2>&1
apt-get install spawn-fcgi -y >/dev/null 2>&1
apt-get install dovecot-solr -y >/dev/null 2>&1
apt-get install solr-jetty -y >/dev/null 2>&1

chown root:postfix "/etc/postfix/sql/mysql_virtual_sender_acl.cf"
chown -R www-data: /var/lib/php5/sessions
chown -R www-data: /var/www/{.,mail,dav} /var/lib/php5/sessions
chown -R www-data: /var/www/mail/rc

[[ -f /etc/cron.daily/doverecalcq ]] && rm /etc/cron.daily/doverecalcq
install -m 755 ~/sources/update/dovemaint /etc/cron.daily/
install -m 644 ~/sources/update/solrmaint /etc/cron.d/

echo "${info} Mailcow Update..."
			
mkdir -p /var/mailcow/log
mkdir -p /var/mailcow/tmp
touch /var/mailcow/mailbox_backup_env
echo none > /var/mailcow/log/pflogsumm.log
chown -R www-data: /var/www/{.,mail,dav} /var/lib/php5/sessions /var/mailcow/mailbox_backup_env
mv /var/www/MAILBOX_BACKUP /var/mailcow/mailbox_backup_env 2> /dev/null
mv /var/www/PFLOG /var/mailcow/log/pflogsumm.log 2> /dev/null

cat > /etc/nginx/sites-custom/mailcow.conf <<END
 location /admin {
     alias /var/www/mail;
     index index.php;
 
     location ~ ^/admin/(.+\.php)$ {
         alias /var/www/mail/\$1;
         fastcgi_split_path_info ^(.+\.php)(/.+)$;
         include fastcgi_params;
         fastcgi_index index.php;
         fastcgi_param SCRIPT_FILENAME /var/www/mail/\$1;
         fastcgi_pass unix:/var/run/php5-fpm-mail.sock;
     }
 
     location ~* ^/admin/(.+\.(jpg|jpeg|gif|css|png|js|ico|html|xml|txt))$ {
         alias /var/www/mail/\$1;
     }
 }
 
 location ~ ^/(admin/rc)/ {
     deny all;
     return 301 /admin;
 }

location ~ \.cgi\$ {
	allow 127.0.0.1;
	deny all;
	alias /usr/lib/cgi-bin;
	include fastcgi_params;
	fastcgi_param SCRIPT_FILENAME /usr/lib/cgi-bin/\$1;
	fastcgi_pass unix:/var/run/fcgiwrap.socket;
}
END

echo "${info} Blacklist Fix..."
sed -i 's/.*BLOCK_HOSTS_FILE=.*/BLOCK_HOSTS_FILE="\/etc\/arno-iptables-firewall\/blocked-hosts"/' /etc/arno-iptables-firewall/firewall.conf
cat > /etc/cron.daily/blocked-hosts <<END
#!/bin/bash
BLACKLIST_DIR="/root/sources/blacklist"
BLACKLIST="/etc/arno-iptables-firewall/blocked-hosts"
BLACKLIST_TEMP="\$BLACKLIST_DIR/blacklist"
LIST=(
"http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1"
"http://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1"
"http://www.maxmind.com/en/anonymous_proxies"
"http://danger.rulez.sk/projects/bruteforceblocker/blist.php"
"http://rules.emergingthreats.net/blockrules/compromised-ips.txt"
"http://www.spamhaus.org/drop/drop.lasso"
"http://cinsscore.com/list/ci-badguys.txt"
"http://www.openbl.org/lists/base.txt"
"http://www.autoshun.org/files/shunlist.csv"
"http://lists.blocklist.de/lists/all.txt"
)
for i in "\${LIST[@]}"
do
    wget -T 10 -t 2 -O - \$i | grep -Po '(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?' >> \$BLACKLIST_TEMP
done
sort \$BLACKLIST_TEMP -n | uniq > \$BLACKLIST
cp \$BLACKLIST_TEMP \${BLACKLIST_DIR}/blacklist\_\$(date '+%d.%m.%Y_%T' | tr -d :) && rm \$BLACKLIST_TEMP
systemctl force-reload arno-iptables-firewall.service
END
chmod +x /etc/cron.daily/blocked-hosts

echo "${info} ZPush Update..."

mkdir /var/www/zpush/mail >/dev/null 2>&1
cat > /var/www/zpush/mail/config-v1.1.xml <<END
<?xml version="1.0" encoding="UTF-8"?>

<clientConfig version="1.1">
  <emailProvider id="${MYDOMAIN}">
    <domain>${MYDOMAIN}</domain>
    <displayName>${MYDOMAIN} Mail</displayName>
    <displayShortName>${MYDOMAIN}</displayShortName>
    <incomingServer type="imap">
      <hostname>mail.${MYDOMAIN}</hostname>
      <port>993</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <incomingServer type="imap">
      <hostname>mail.${MYDOMAIN}</hostname>
      <port>143</port>
      <socketType>STARTTLS</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <incomingServer type="pop3">
      <hostname>mail.${MYDOMAIN}</hostname>
      <port>995</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <incomingServer type="pop3">
      <hostname>mail.${MYDOMAIN}</hostname>
      <port>110</port>
      <socketType>STARTTLS</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>mail.${MYDOMAIN}</hostname>
      <port>587</port>
      <socketType>STARTTLS</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </outgoingServer>
    <documentation url="https://${MYDOMAIN}/admin">
      <descr lang="de">Allgemeine Beschreibung der Einstellungen</descr>
      <descr lang="en">Generic settings page</descr>
    </documentation>
    <documentation url="https://${MYDOMAIN}/admin">
      <descr lang="de">TB 2.0 IMAP-Einstellungen</descr>
      <descr lang="en">TB 2.0 IMAP settings</descr>
    </documentation>
  </emailProvider>
</clientConfig>
END
	chown -R www-data: /var/www/zpush/mail/

echo "${info} Mailgraph Update..."

cat > /etc/nginx/sites-available/mailgraph.conf <<END
server {
	listen 127.0.0.1:81;
		location ~ \.cgi\$ {
		    alias /usr/lib/cgi-bin/\$1;
		    include /etc/nginx/fastcgi_params;
		    fastcgi_pass unix:/var/run/fcgiwrap.socket;
		}
}
END

ln -s /etc/nginx/sites-available/mailgraph.conf /etc/nginx/sites-enabled/mailgraph.conf >/dev/null 2>&1


service dovecot restart
service spamassassin restart
service postfix restart
service php5-fpm restart
service mailgraph restart
echo "${info} Fuglu Update..."
service fuglu stop
cd ~
wget https://github.com/gryphius/fuglu/tarball/master -O fuglu-latest.tar.gz >/dev/null 2>&1
tar -xvzf fuglu-latest.tar.gz
cd gryphius-fuglu-*
cd fuglu
python setup.py install
echo
echo starte Fuglu 
cp -R /root/backup/fuglu/* /etc/fuglu/
service fuglu restart

clear
echo
echo "$(yellowb +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+)"
echo " $(textb Perfect) $(textb Rootserver) $(textb Update) $(textb by)" "$(cyan MXIIII)"
echo "$(yellowb +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+)"
echo
echo "${info} Backup..."
echo "${info} Install..."
echo "${info} Mailcow Update..."
echo "${info} Blacklist Fix..."
echo "${info} ZPush Update..."
echo "${info} Mailgraph Update..."
echo "${info} Fuglu Update..."
echo "${info} NGINX Update..."
echo "${warn} Some of the tasks could take a long time, please be patient!"
service nginx stop

cd ~/sources
wget -nc http://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz >/dev/null 2>&1
tar -xzf openssl-${OPENSSL_VERSION}.tar.gz >/dev/null 2>&1
echo "${info} Downloading OpenSSH..."
wget -nc http://ftp.hostserver.de/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_VERSION}p1.tar.gz >/dev/null 2>&1
tar -xzf openssh-${OPENSSH_VERSION}p1.tar.gz >/dev/null 2>&1
cd openssh-${OPENSSH_VERSION}p1
echo "${info} Compiling OpenSSH..."
./configure --prefix=/usr --with-pam --with-zlib --with-ssl-engine --with-ssl-dir=/etc/ssl --sysconfdir=/etc/ssh >/dev/null 2>&1
make >/dev/null 2>&1 && mv /etc/ssh{,.bak} >/dev/null 2>&1 && make install >/dev/null 2>&1
systemctl -q restart ssh.service
echo "${info} Downloading Nginx Pagespeed..."
wget -nc https://github.com/pagespeed/ngx_pagespeed/archive/release-${NPS_VERSION}-beta.zip >/dev/null 2>&1
unzip -qq release-${NPS_VERSION}-beta.zip 
cd ngx_pagespeed-release-${NPS_VERSION}-beta/
wget -nc https://dl.google.com/dl/page-speed/psol/${NPS_VERSION}.tar.gz >/dev/null 2>&1
tar -xzf ${NPS_VERSION}.tar.gz
cd ~/sources
echo "${info} Downloading Naxsi..."
wget --no-check-certificate -nc https://github.com/nbs-system/naxsi/archive/${NAXSI_VERSION}.tar.gz >/dev/null 2>&1
tar -xzf ${NAXSI_VERSION}.tar.gz
echo "${info} Downloading Nginx..."
wget -nc http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz >/dev/null 2>&1
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

echo "${info} NGINX Install..."
make >/dev/null 2>&1

checkinstall --install=no -y >/dev/null 2>&1

dpkg -i nginx_${NGINX_VERSION}-1_amd64.deb >/dev/null 2>&1

mv nginx_${NGINX_VERSION}-1_amd64.deb ../
cp -R /root/backup/nginx/* /etc/nginx/

cat > /etc/nginx/sites-available/autodiscover.${MYDOMAIN}.conf <<END
 server {
 			listen 80;
 			server_name autodiscover.${MYDOMAIN} autoconfig.${MYDOMAIN};
 			return 301 https://autodiscover.${MYDOMAIN}\$request_uri;
 }
 
 server {
 			listen 443 ssl http2;
 			server_name autodiscover.${MYDOMAIN} autoconfig.${MYDOMAIN};
 
 			root /var/www/zpush;
 			index index.php;
 			charset utf-8;
 
 			error_page 404 /index.php;
 
 			ssl_certificate 	ssl/${MYDOMAIN}.pem;
 			ssl_certificate_key ssl/${MYDOMAIN}.key;
 			#ssl_trusted_certificate ssl/${MYDOMAIN}.pem;
 			ssl_dhparam	     	ssl/dh.pem;
 			#ssl_ecdh_curve		secp384r1;
 			ssl_session_cache   shared:SSL:10m;
 			ssl_session_timeout 10m;
 			ssl_session_tickets off;
 			ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;
 			ssl_prefer_server_ciphers on;
 			ssl_buffer_size 	1400;
 
 			#ssl_stapling 		on;
 			#ssl_stapling_verify on;
 			#resolver 			8.8.8.8 8.8.4.4 208.67.222.222 208.67.220.220 valid=60s;
 			#resolver_timeout 	2s;
 
 			ssl_ciphers 		"ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK";
 
 			#add_header 		Strict-Transport-Security "max-age=63072000; includeSubdomains; preload";
 			#add_header 		Public-Key-Pins 'pin-sha256="${HPKP1}"; pin-sha256="${HPKP2}"; max-age=5184000; includeSubDomains';
 			add_header 			Cache-Control "public";
 			add_header 			X-Frame-Options SAMEORIGIN;
 			add_header 			Alternate-Protocol  443:npn-http/2;
 			add_header 			X-Content-Type-Options nosniff;
 			add_header 			X-XSS-Protection "1; mode=block";
 			add_header 			X-Permitted-Cross-Domain-Policies "master-only";
 			add_header 			"X-UA-Compatible" "IE=Edge";
 			add_header 			"Access-Control-Allow-Origin" "*";
 			add_header 			Content-Security-Policy "script-src 'self' 'unsafe-inline' 'unsafe-eval' *.youtube.com maps.gstatic.com *.googleapis.com *.google-analytics.com cdnjs.cloudflare.com assets.zendesk.com connect.facebook.net; frame-src 'self' *.youtube.com assets.zendesk.com *.facebook.com s-static.ak.facebook.com tautt.zendesk.com; object-src 'self'";
 
 			auth_basic_user_file htpasswd/.htpasswd;
 
 			location ~ ^(.+\.php)(.*)\$ {
 				fastcgi_split_path_info ^(.+\.php)(/.+)\$;
 				try_files \$fastcgi_script_name =404;
 				set \$path_info \$fastcgi_path_info;
 				fastcgi_param PATH_INFO \$path_info;
 				fastcgi_param APP_ENV production;
 				fastcgi_pass unix:/var/run/php5-fpm.sock;
 				fastcgi_index index.php;
 				include fastcgi.conf;
 				fastcgi_intercept_errors on;
 				fastcgi_ignore_client_abort off;
 				fastcgi_buffers 256 16k;
 				fastcgi_buffer_size 128k;
 				fastcgi_connect_timeout 3s;
 				fastcgi_send_timeout 120s;
 				fastcgi_read_timeout 120s;
 				fastcgi_busy_buffers_size 256k;
 				fastcgi_temp_file_write_size 256k;
 			}
 
 			rewrite (?i)^/autodiscover/autodiscover\.xml\$ /autodiscover/autodiscover.php;
 
 			location / {
 				try_files \$uri \$uri/ /index.php;
 			}
 
 			location /Microsoft-Server-ActiveSync {
             	rewrite ^(.*)\$  /index.php last;
         	}
 
 			location ~ /(\.ht|Core|Specific) {
                 deny all;
                 return 404;
         	}
 
 			location = /favicon.ico {
 				access_log off;
 				log_not_found off;
 			}
 				
 			location = /robots.txt {
 				allow all;
 				access_log off;
 				log_not_found off;
 			}
 
 			location ~* ^.+\.(css|js)\$ {
 				rewrite ^(.+)\.(\d+)\.(css|js)\$ \$1.\$3 last;
 				expires 30d;
 				access_log off;
 				log_not_found off;
 				add_header Pragma public;
 				add_header Cache-Control "max-age=2592000, public";
 			}
 
 			location ~* \.(asf|asx|wax|wmv|wmx|avi|bmp|class|divx|doc|docx|eot|exe|gif|gz|gzip|ico|jpg|jpeg|jpe|mdb|mid|midi|mov|qt|mp3|m4a|mp4|m4v|mpeg|mpg|mpe|mpp|odb|odc|odf|odg|odp|ods|odt|ogg|ogv|otf|pdf|png|pot|pps|ppt|pptx|ra|ram|svg|svgz|swf|tar|t?gz|tif|tiff|ttf|wav|webm|wma|woff|wri|xla|xls|xlsx|xlt|xlw|zip)\$ {
 				expires 30d;
 				access_log off;
 				log_not_found off;
 				add_header Pragma public;
 				add_header Cache-Control "max-age=2592000, public";
 			}
 
			if (\$http_user_agent ~* "FeedDemon|JikeSpider|Indy Library|Alexa Toolbar|AskTbFXTV|AhrefsBot|CrawlDaddy|CoolpadWebkit|Java|Feedly|UniversalFeedParser|ApacheBench|Microsoft URL Control|Swiftbot|ZmEu|oBot|jaunty|Python-urllib|lightDeckReports Bot|YYSpider|DigExt|YisouSpider|HttpClient|MJ12bot|heritrix|EasouSpider|Ezooms|Scrapy") {
             	return 403;
             }
 
 }
END

cat > /etc/nginx/sites-available/dav.${MYDOMAIN}.conf <<END
 server {
 			listen 80;
 			server_name dav.${MYDOMAIN};
 			return 301 https://dav.${MYDOMAIN}\$request_uri;
 }
 
 server {
 			listen 443 ssl http2;
 			server_name dav.${MYDOMAIN};
 
 			root /var/www/dav;
 			index server.php;
 			charset utf-8;
 
 			error_page 404 /index.php;
 
 			ssl_certificate 	ssl/${MYDOMAIN}.pem;
 			ssl_certificate_key ssl/${MYDOMAIN}.key;
 			#ssl_trusted_certificate ssl/${MYDOMAIN}.pem;
 			ssl_dhparam	     	ssl/dh.pem;
 			#ssl_ecdh_curve		secp384r1;
 			ssl_session_cache   shared:SSL:10m;
 			ssl_session_timeout 10m;
 			ssl_session_tickets off;
 			ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;
 			ssl_prefer_server_ciphers on;
 			ssl_buffer_size 	1400;
 
 			#ssl_stapling 		on;
 			#ssl_stapling_verify on;
 			#resolver 			8.8.8.8 8.8.4.4 208.67.222.222 208.67.220.220 valid=60s;
 			#resolver_timeout 	2s;
 
 			ssl_ciphers 		"ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK";
 
 			#add_header 		Strict-Transport-Security "max-age=63072000; includeSubdomains; preload";
 			#add_header 		Public-Key-Pins 'pin-sha256="${HPKP1}"; pin-sha256="${HPKP2}"; max-age=5184000; includeSubDomains';
 			add_header 			Cache-Control "public";
 			add_header 			X-Frame-Options SAMEORIGIN;
 			add_header 			Alternate-Protocol  443:npn-http/2;
 			add_header 			X-Content-Type-Options nosniff;
 			add_header 			X-XSS-Protection "1; mode=block";
 			add_header 			X-Permitted-Cross-Domain-Policies "master-only";
 			add_header 			"X-UA-Compatible" "IE=Edge";
 			add_header 			"Access-Control-Allow-Origin" "*";
 			add_header 			Content-Security-Policy "script-src 'self' 'unsafe-inline' 'unsafe-eval' *.youtube.com maps.gstatic.com *.googleapis.com *.google-analytics.com cdnjs.cloudflare.com assets.zendesk.com connect.facebook.net; frame-src 'self' *.youtube.com assets.zendesk.com *.facebook.com s-static.ak.facebook.com tautt.zendesk.com; object-src 'self'";
 			
 			auth_basic_user_file htpasswd/.htpasswd;
 
 			location ~ ^(.+\.php)(.*)\$ {
 				fastcgi_split_path_info ^(.+\.php)(/.+)\$;
 				try_files \$fastcgi_script_name =404;
 				set \$path_info \$fastcgi_path_info;
 				fastcgi_param PATH_INFO \$path_info;
 				fastcgi_param APP_ENV production;
 				fastcgi_pass unix:/var/run/php5-fpm.sock;
 				fastcgi_index index.php;
 				include fastcgi.conf;
 				fastcgi_intercept_errors on;
 				fastcgi_ignore_client_abort off;
 				fastcgi_buffers 256 16k;
 				fastcgi_buffer_size 128k;
 				fastcgi_connect_timeout 3s;
 				fastcgi_send_timeout 120s;
 				fastcgi_read_timeout 120s;
 				fastcgi_busy_buffers_size 256k;
 				fastcgi_temp_file_write_size 256k;
 			}
 
 			rewrite ^/.well-known/caldav /server.php redirect;
 			rewrite ^/.well-known/carddav /server.php redirect;
 
 			location / {
 				try_files \$uri \$uri/ /server.php?\$args;
 			}
 
 			location ~ /(\.ht|Core|Specific) {
                 deny all;
                 return 404;
         	}
 
 			location = /favicon.ico {
 				access_log off;
 				log_not_found off;
 			}
 				
 			location = /robots.txt {
 				allow all;
 				access_log off;
 				log_not_found off;
 			}
 
 			location ~* ^.+\.(css|js)\$ {
 				rewrite ^(.+)\.(\d+)\.(css|js)\$ \$1.\$3 last;
 				expires 30d;
 				access_log off;
 				log_not_found off;
 				add_header Pragma public;
 				add_header Cache-Control "max-age=2592000, public";
 			}
 
 			location ~* \.(asf|asx|wax|wmv|wmx|avi|bmp|class|divx|doc|docx|eot|exe|gif|gz|gzip|ico|jpg|jpeg|jpe|mdb|mid|midi|mov|qt|mp3|m4a|mp4|m4v|mpeg|mpg|mpe|mpp|odb|odc|odf|odg|odp|ods|odt|ogg|ogv|otf|pdf|png|pot|pps|ppt|pptx|ra|ram|svg|svgz|swf|tar|t?gz|tif|tiff|ttf|wav|webm|wma|woff|wri|xla|xls|xlsx|xlt|xlw|zip)\$ {
 				expires 30d;
 				access_log off;
 				log_not_found off;
 				add_header Pragma public;
 				add_header Cache-Control "max-age=2592000, public";
 			}
 
			if (\$http_user_agent ~* "FeedDemon|JikeSpider|Indy Library|Alexa Toolbar|AskTbFXTV|AhrefsBot|CrawlDaddy|CoolpadWebkit|Java|Feedly|UniversalFeedParser|ApacheBench|Microsoft URL Control|Swiftbot|ZmEu|oBot|jaunty|Python-urllib|lightDeckReports Bot|YYSpider|DigExt|YisouSpider|HttpClient|MJ12bot|heritrix|EasouSpider|Ezooms|Scrapy") {
             	return 403;
             }
 }
END

cat > /etc/nginx/sites-available/${MYDOMAIN}.conf <<END
 server {
 			listen 				80 default_server;
 			server_name 		${IPADR} ${MYDOMAIN};
 			return 301 			https://${MYDOMAIN}\$request_uri;
 }
 
 server {
 			listen 				443;
 			server_name 		${IPADR} www.${MYDOMAIN} mail.${MYDOMAIN};
 			return 301 			https://${MYDOMAIN}\$request_uri;
 }
 
 server {
 			listen 				443 ssl http2 default deferred;
 			server_name 		${MYDOMAIN};
 
 			root 				/etc/nginx/html;
 			index 				index.php index.html index.htm;
 
 			charset 			utf-8;
 
 			error_page 404 		/index.php;
 
 			ssl_certificate 	ssl/${MYDOMAIN}.pem;
 			ssl_certificate_key ssl/${MYDOMAIN}.key;
 			#ssl_trusted_certificate ssl/${MYDOMAIN}.pem;
 			ssl_dhparam	     	ssl/dh.pem;
 			#ssl_ecdh_curve		secp384r1;
 			ssl_session_cache   shared:SSL:10m;
 			ssl_session_timeout 10m;
 			ssl_session_tickets off;
 			ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;
 			ssl_prefer_server_ciphers on;
 			ssl_buffer_size 	1400;
 
 			#ssl_stapling 		on;
 			#ssl_stapling_verify on;
 			#resolver 			8.8.8.8 8.8.4.4 208.67.222.222 208.67.220.220 valid=60s;
 			#resolver_timeout 	2s;
 
 			ssl_ciphers 		"ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK";
 
 			#add_header 		Strict-Transport-Security "max-age=63072000; includeSubdomains; preload";
 			#add_header 		Public-Key-Pins 'pin-sha256="${HPKP1}"; pin-sha256="${HPKP2}"; max-age=5184000; includeSubDomains';
 			add_header 			Cache-Control "public";
 			add_header 			X-Frame-Options SAMEORIGIN;
 			add_header 			Alternate-Protocol  443:npn-http/2;
 			add_header 			X-Content-Type-Options nosniff;
 			add_header 			X-XSS-Protection "1; mode=block";
 			add_header 			X-Permitted-Cross-Domain-Policies "master-only";
 			add_header 			"X-UA-Compatible" "IE=Edge";
 			add_header 			"Access-Control-Allow-Origin" "*";
 			add_header 			Content-Security-Policy "script-src 'self' 'unsafe-inline' 'unsafe-eval' *.youtube.com maps.gstatic.com *.googleapis.com *.google-analytics.com cdnjs.cloudflare.com assets.zendesk.com connect.facebook.net; frame-src 'self' *.youtube.com assets.zendesk.com *.facebook.com s-static.ak.facebook.com tautt.zendesk.com; object-src 'self'";
 
 			pagespeed 			on;
 			pagespeed 			EnableFilters collapse_whitespace;
 			pagespeed 			EnableFilters canonicalize_javascript_libraries;
 			pagespeed 			EnableFilters combine_css;
 			pagespeed 			EnableFilters combine_javascript;
 			pagespeed 			EnableFilters elide_attributes;
 			pagespeed 			EnableFilters extend_cache;
 			pagespeed 			EnableFilters flatten_css_imports;
 			pagespeed 			EnableFilters lazyload_images;
 			pagespeed 			EnableFilters rewrite_javascript;
 			pagespeed 			EnableFilters rewrite_images;
 			pagespeed 			EnableFilters insert_dns_prefetch;
 			pagespeed 			EnableFilters prioritize_critical_css;
 
 			pagespeed 			FetchHttps enable,allow_self_signed;
 			pagespeed 			FileCachePath /var/lib/nginx/nps_cache;
 			pagespeed 			RewriteLevel CoreFilters;
 			pagespeed 			CssFlattenMaxBytes 5120;
 			pagespeed 			LogDir /var/log/pagespeed;
 			pagespeed 			EnableCachePurge on;
 			pagespeed 			PurgeMethod PURGE;
 			pagespeed 			DownstreamCachePurgeMethod PURGE;
 			pagespeed 			DownstreamCachePurgeLocationPrefix http://127.0.0.1:80/;
 			pagespeed 			DownstreamCacheRewrittenPercentageThreshold 95;
 			pagespeed 			LazyloadImagesAfterOnload on;
 			pagespeed 			LazyloadImagesBlankUrl "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7";
 
 			pagespeed 			MemcachedThreads 1;
 			pagespeed 			MemcachedServers "localhost:11211";
 			pagespeed 			MemcachedTimeoutUs 100000;
 			pagespeed 			RespectVary on;
 
 			pagespeed 			Disallow "*/pma/*";
 
 			# This will correctly rewrite your subresources with https:// URLs and thus avoid mixed content warnings.
 			# Note, that you should only enable this option if you are behind a load-balancer that will set this header,
 			# otherwise your users will be able to set the protocol PageSpeed uses to interpret the request.
 			#
 			#pagespeed 			RespectXForwardedProto on;
 
 			auth_basic_user_file htpasswd/.htpasswd;
 
 			location ~ \.php\$ {
 				fastcgi_split_path_info ^(.+\.php)(/.+)\$;
 				try_files \$fastcgi_script_name =404;
 				fastcgi_param PATH_INFO \$fastcgi_path_info;
				fastcgi_param PATH_TRANSLATED \$document_root\$fastcgi_path_info;
 				fastcgi_param APP_ENV production;
 				fastcgi_pass unix:/var/run/php5-fpm.sock;
 				fastcgi_index index.php;
 				include fastcgi.conf;
 				fastcgi_intercept_errors off;
 				fastcgi_ignore_client_abort off;
 				fastcgi_buffers 256 16k;
 				fastcgi_buffer_size 128k;
 				fastcgi_connect_timeout 3s;
 				fastcgi_send_timeout 120s;
 				fastcgi_read_timeout 120s;
 				fastcgi_busy_buffers_size 256k;
 				fastcgi_temp_file_write_size 256k;
 			}
 
 			include /etc/nginx/sites-custom/*.conf;
 
 			location / {
 			   	include /etc/nginx/naxsi.rules;
 
 			   	# Uncomment, if you need to remove index.php from the
 				# URL. Usefull if you use Codeigniter, Zendframework, etc.
 				# or just need to remove the index.php
 				#
 			   	#try_files \$uri \$uri/ /index.php?\$args;
 			}
 
 			location ~* /\.(?!well-known\/) {
 			    deny all;
 			    access_log off;
 				log_not_found off;
 			}
 
 			location ~* (?:\.(?:bak|conf|dist|fla|in[ci]|log|psd|sh|sql|sw[op])|~)$ {
 			    deny all;
 			    access_log off;
 				log_not_found off;
 			}
 
 			location = /favicon.ico {
 				access_log off;
 				log_not_found off;
 			}
 				
 			location = /robots.txt {
 				allow all;
 				access_log off;
 				log_not_found off;
 			}
 
 			location ~* ^.+\.(css|js)\$ {
 				rewrite ^(.+)\.(\d+)\.(css|js)\$ \$1.\$3 last;
 				expires 30d;
 				access_log off;
 				log_not_found off;
 				add_header Pragma public;
 				add_header Cache-Control "max-age=2592000, public";
 			}
 
 			location ~* \.(asf|asx|wax|wmv|wmx|avi|bmp|class|divx|doc|docx|eot|exe|gif|gz|gzip|ico|jpg|jpeg|jpe|mdb|mid|midi|mov|qt|mp3|m4a|mp4|m4v|mpeg|mpg|mpe|mpp|odb|odc|odf|odg|odp|ods|odt|ogg|ogv|otf|pdf|png|pot|pps|ppt|pptx|ra|ram|svg|svgz|swf|tar|t?gz|tif|tiff|ttf|wav|webm|wma|woff|wri|xla|xls|xlsx|xlt|xlw|zip)\$ {
 				expires 30d;
 				access_log off;
 				log_not_found off;
 				add_header Pragma public;
 				add_header Cache-Control "max-age=2592000, public";
 			}
 
			if (\$http_user_agent ~* "FeedDemon|JikeSpider|Indy Library|Alexa Toolbar|AskTbFXTV|AhrefsBot|CrawlDaddy|CoolpadWebkit|Java|Feedly|UniversalFeedParser|ApacheBench|Microsoft URL Control|Swiftbot|ZmEu|oBot|jaunty|Python-urllib|lightDeckReports Bot|YYSpider|DigExt|YisouSpider|HttpClient|MJ12bot|heritrix|EasouSpider|Ezooms|Scrapy") {
             	return 403;
             }
 }
END
service nginx start
echo
echo
echo "${info} In the next step you have to set one DNS TXT records for your domain."
echo
echo
echo " NAME       TYPE          VALUE"
echo "-----------------------------------"
echo "  @         TXT         \"mailconf=https://autoconfig.${MYDOMAIN}/mail/config-v1.1.xml\""
echo
echo
