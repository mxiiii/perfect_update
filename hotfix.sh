#!/bin/bash
# The perfect rootserver UPDATE
# by mxiiii
# https://github.com/mxiiii/perfect_update
# Thanks to https://github.com/zypr/perfectrootserver
# and https://github.com/andryyy/mailcow
# Compatible with Debian 8.x (jessie)
#
# Hotfix v1.1
#
install -m 755 ~/sources/update/mc_setup_relayhost /usr/local/sbin/
install -m 755 ~/sources/update/mc_msg_size /usr/local/sbin/
cp ~/sources/update/functions.inc.php /var/www/mail/inc/ 
