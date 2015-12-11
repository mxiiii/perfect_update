## perfect_update ##

[Get the latest release](https://github.com/mxiiii/perfect_update/releases/latest "Latest Release"): 

Update_Patch für [https://github.com/zypr/perfectrootserver/](https://github.com/zypr/perfectrootserver/)

Das Patch_File ist nur für die Version vom Perfect Root Server v0.3.5 (Nov 07, 2015) und beinhaltet die aktuellen Änderungen von Mailcow Version 13.1 bis zum Dez. 8, 2015

Bis auf Lets Encrypt ist es ein Update vom PerfecRootServer v0.3.5 auf v0.3.8 

Wer schon das v0.3.5 auf v0.3.8 Update durchgefüht hat oder direkt eine neuinstallation von v0.3.8 hat, benötigt nur das Hotfix für die aktuellen Änderungen.

----------

### Update von v0.3.5 auf v0.3.8 : ###

1. `wget -O ~/perfectupdate.tar.gz https://github.com/mxiiii/perfect_update/archive/v0.x.x.tar.gz`
2. `tar -xzf ~/perfectupdate.tar.gz -C ~/ --strip-components=1`
3. `nano ~/updateconfig.cfg`
4. `bash ~/update.sh`

### Hotfix für v0.3.8 ###

1. `wget -O ~/perfectupdate.tar.gz https://github.com/mxiiii/perfect_update/archive/v0.x.x.tar.gz`
2. `tar -xzf ~/perfectupdate.tar.gz -C ~/ --strip-components=1`
3. `nano ~/updateconfig.cfg`
4. `bash ~/hotfix.sh`

----------

### Hotfix v1.2 changelog ###

1. fixed Message size 
2. add Setup Relayhost
3. fixed Alias
4. fixed fastcgi_params
5. fixed fastcgi_path_info

----------

#### Wichtig !!! ###

Bitte alle selbstmodifizierten Dateien vorher sichern und ggf. zurückspielen. Das Update geht von einer unveränderten instalation des v0.3.5 PerfectRootserver aus !!!

Nach dem Update muss ein neuer DNS TXT Record gesetzt werden:

`mailconf=https://autoconfig.${MYDOMAIN}/mail/config-v1.1.xml`
