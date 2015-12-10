## perfect_update ##

[Get the latest release](https://github.com/mxiiii/perfect_update/releases/latest "Latest Release"): 

Update_Patch für [https://github.com/zypr/perfectrootserver/](https://github.com/zypr/perfectrootserver/)

Das Patch_File ist nur für die Version vom Perfect Root Server v0.3.5 (Nov 07, 2015) und beinhaltet die aktuellen Äderungen von Mailcow Version 13.1 bis zum Dez. 8, 2015

Bis auf Lets Encrypt ist es ein Update vom PerfecRootServer v0.3.5 auf v0.3.8 

Wer schon das v0.3.5 auf v0.3.8 update durchgefüht hat oder direkt eine neuinstallation von v0.3.8 hat, benötigt nur das Hotfix für die aktuellen Änderungen.

----------

### Update von v0.3.5 auf v0.3.8 : ###

1. `wget -O ~/perfectupdate.tar.gz https://github.com/mxiiii/perfect_update/archive/v0.x.x.tar.gz`
2. `tar -xzf ~/perfectupdate.tar.gz -C ~/ --strip-components=1`
3. `nano ~/updateconfig.cfg`
5. Dateien manuell anpassen siehe unten
4. `bash ~/update.sh`

### Hotfix für v0.3.8 ###

1. `wget -O ~/perfectupdate.tar.gz https://github.com/mxiiii/perfect_update/archive/v0.x.x.tar.gz`
2. `tar -xzf ~/perfectupdate.tar.gz -C ~/ --strip-components=1`
4. `bash ~/hotfix.sh`

----------

### Hotfix changelog ###

1. fix Message size 
2. add Setup Relayhost
3. fix Alias


----------

#### Wichtig !!! ###

Bitte alle selbstmodifizierten Dateien vorher sichern und ggf. zurückspielen. Das Update geht von einer unveränderten instalation des v0.3.5 PerfectRootserver aus !!!

Vor dem Update müssen folgende Dateien noch per Hand angepasst werden:

    ~/sources/update/main.cf # Zeile 96 myhostname=

    ~/sources/update/mysql_virtual_sender_acl.cf # Zeile 2-5 user = / password = / hosts = / dbname

    ~/sources/update/mysql_virtual_alias_maps.cf # Zeile 2-5 user = / password = / hosts = / dbname

    ~/sources/update/dovecot.conf # Zeile 5 login_greeting = FQDN des Mailservers hinzufügen
    
    ~/sources/update/vars.inc.php # Zeile 3-6 / Login usw. für MYSQL

Neuen DNS TXT Record setzen auf: mailconf=https://autoconfig.DOMAIN/mail/config-v1.1.xml 
