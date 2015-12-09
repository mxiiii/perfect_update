MYDOMAIN="domainname"
mkdir -p /root/backup/nginx/sites-available
cp -R /etc/nginx/sites-available/dav.* /root/backup/nginx/sites-available

rm -rf /etc/nginx/sites-available/dav.${MYDOMAIN}.conf
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
 			ssl_certificate_key ssl/${MYDOMAIN}.key.pem;
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

service nginx restart