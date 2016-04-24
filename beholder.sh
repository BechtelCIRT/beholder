#!/bin/bash
############################################
#Beholder V1.07.000 - ELK/BRO/Libtrace
#Created By: Jason Azzarella and Chris Pavan
#Problems or Feature Requests?
#E-mail Us: jmazzare@bechtel.com
############################################
clear
dt() {
date -u '+%m/%d/%Y %H:%M:%S'
}
rootcheck() {
	if [ $(id -u) != "0" ]; then
		echo -e "$(dt) Elevating your privileges..."
		sudo "sh" "$0" "$@"
		exit $?
	fi
}
rootcheck
#####################
#Check Ubuntu Version
#####################
echo "[+] Ubuntu Version Check."
apt-get update
apt-get install -y lsb-core
version=$(lsb_release -a | grep Release | awk '{print $2}' | sed 's/\..*//')
versioncheck() {
	if [ $version = "15" ]; then
		echo "You are on Ubuntu:" $version
		echo "Your Ubuntu version is supported. Installing init support."
		apt-get install -y upstart-sysv openjdk-8-jre
		update-initramfs -u
	elif [ $version = "14" ]; then
		sudo add-apt-repository ppa:webupd8team/java -y
		sudo apt-get update
		echo oracle-java8-installer shared/accepted-oracle-license-v1-1 select true | /usr/bin/debconf-set-selections
		sudo apt-get install oracle-java8-installer -y
		echo "You are on Ubuntu:" $version
		echo "Your Ubuntu version is supported."
	else
		echo "Beholder does not support version" $version
		echo "Exiting Beholder."
		exit
	fi
}
versioncheck
clear
#######################
#Creating Beholder User
#######################
echo "[+] Creating beholder user."
useradd beholder -m -d /home/beholder
echo 'beholder:beholder' | chpasswd
#####################
#Build File Structure
#####################
echo "[+] Setting up the file system."
mkdir /logs
mkdir /logs/bro
mkdir /logs/elasticsearch
mkdir /logs/index
mkdir /logs/bro/spool
mkdir /logs/logstash
mkdir /pcaps/
mkdir /home/beholder
chown beholder:beholder /home/beholder
#####################################
#Installing Updates and Dependencies.
#####################################
echo "[+] Starting download and install. This WILL take a while. Be cool!"
wget -qO - https://packages.elasticsearch.org/GPG-KEY-elasticsearch | sudo apt-key add -
cd /etc/apt/sources.list.d/
cat <<EOF > curator.list
deb http://packages.elasticsearch.org/curator/3/debian stable main
EOF
apt-get update
apt-get install -y apache2 apache2-utils unzip bless lsb-core cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev git dh-autoreconf python-elasticsearch-curator
#####################
#Installing ELK Stack
#####################
echo "[+] Installing ELK Stack"
cd /opt/
wget https://www.dropbox.com/s/r27jwgo13d0hnga/elasticsearch-2.2.1.tar.gz
tar -zxvf *.tar.gz
rm -rf *.tar.gz
mv elastic* elasticsearch
wget https://www.dropbox.com/s/gz4txuatpcl5sbh/logstash-2.2.2.tar.gz
tar -zxvf *.tar.gz
rm -rf *.tar.gz
mv logstash* logstash
wget https://www.dropbox.com/s/pv9xj6dl2sa8mk8/kibana-4.4.2-linux-x64.tar.gz
tar -zxvf *.tar.gz
rm -rf *.tar.gz
mv kibana-* kibana
###############
#Installing Bro
###############
echo "[+] Installing Bro"
cd /opt/
mkdir /opt/broinstall
mkdir /opt/bro
cd /opt/broinstall
wget https://www.bro.org/downloads/release/bro-2.4.1.tar.gz
tar -zxvf bro*
cd /opt/broinstall/bro-2.4.1
./configure --prefix=/opt/bro
make
make install
rm -rf /opt/broinst*
####################
#Installing Libtrace
####################
echo "[+] Installing Libtrace"
cd /opt/
wget http://research.wand.net.nz/software/libtrace/libtrace-latest.tar.bz2
tar jxf libtrace-latest.tar.bz2
rm -rf libtrace-latest.tar.bz2
mv libtrace-* libtrace
cd /opt/libtrace
./configure
make
make install
###############
#Configurations
###############
echo "[+] Beginning Configurations"
###############################
#Configuration - Bro Node Setup
###############################
clear
echo "Bro is used to monitor traffic on an interface."
echo "We have identified the following interfaces on your system;"
echo "-----------------------------------------------------------"
for line in $(awk 'NR>2 {print $1}' /proc/net/dev | sed 's/://g'); do
        echo "$line"
done
echo "-----------------------------------------------------------"
read -p "Which interface above would you like to monitor: " broinput
sed -i "s/interface=.*/interface=$broinput/" /opt/bro/etc/node.cfg
##############################
#Configuration - Bro Logs Path
##############################
sed -i 's/LogDir\s=.*/LogDir = \/logs\/bro/' /opt/bro/etc/broctl.cfg
sed -i 's/SpoolDir\s=.*/SpoolDir = \/logs\/bro\/spool/' /opt/bro/etc/broctl.cfg
############################
#Configuration - Bro Install
############################
/opt/bro/bin/broctl install
/opt/bro/bin/broctl deploy
##############################
#Configuration - Elasticsearch
##############################
cd /opt/elasticsearch/config
cat <<EOF > elasticsearch.yml
cluster.name: beholder
node.name: beholder
path.data: /logs/index
path.logs: /logs/elasticsearch
EOF
################################
#Configuration - Logstash Inputs
################################
mkdir /opt/logstash/config
cd /opt/logstash/config
#####################################
#Configuration - Logstash ES Template
#####################################
cat <<EOF > /opt/logstash/config/bro.json
{
    "template": "bro*",
    "settings": {
        "index.refresh_interval": "5s"
    },
    "mappings": {
        "_default_": {
            "_all": {
                "enabled": true
            },
            "dynamic_templates": [
                {
                    "string_fields": {
                        "match": "*",
                        "match_mapping_type": "string",
                        "mapping": {
                            "type": "string",
                            "index": "analyzed",
                            "omit_norms": true,
                            "fields": {
                                "raw": {
                                    "type": "string",
                                    "index": "not_analyzed",
                                    "ignore_above": 1024
                                }
                            }
                        }
                    }
                }
            ],
            "properties": {
                "@version": {
                    "type": "string",
                    "index": "not_analyzed"
                },
                "dest_ip_bytes": {
                    "type": "integer",
                    "ignore_malformed": true,
                    "index": "analyzed"
                },
                "dest_bytes": {
                    "type": "integer",
                    "ignore_malformed": true,
                    "index": "analyzed"
                },
                "dest_pkts": {
                    "type": "integer",
                    "ignore_malformed": true,
                    "index": "analyzed"
                },
                "duration": {
                    "type": "float",
                    "ignore_malformed": true,
                    "index": "analyzed"
                },
                "missed_bytes": {
                    "type": "integer",
                    "ignore_malformed": true,
                    "index": "analyzed"
                },
                "missing_bytes": {
                    "type": "integer",
                    "ignore_malformed": true,
                    "index": "analyzed"
                },
                "seen_bytes": {
                    "type": "integer",
                    "ignore_malformed": true,
                    "index": "analyzed"
                },
                "src_bytes": {
                    "type": "integer",
                    "ignore_malformed": true,
                    "index": "analyzed"
                },
                "src_ip_bytes": {
                    "type": "integer",
                    "ignore_malformed": true,
                    "index": "analyzed"
                },
                "src_pkts": {
                    "type": "integer",
                    "ignore_malformed": true,
                    "index": "analyzed"
                },
                "total_bytes": {
                    "type": "integer",
                    "ignore_malformed": true,
                    "index": "analyzed"
                }
            }
        }
    }
}
EOF
####################################
#Configuration - Logstash Bro Parser
####################################
cat <<EOF > /opt/logstash/config/bro.conf
input {
        file {
                path => "/logs/bro/spool/bro/files.log"
                type => "bro_files"
                sincedb_path => "/logs/logstash/brofiles"
        }
        file {
                path => "/logs/bro/spool/bro/dhcp.log"
                type => "bro_dhcp"
                sincedb_path => "/logs/logstash/brodhcp"
        }
        file {
                path => "/logs/bro/spool/bro/http.log"
                type => "bro_http"
                sincedb_path => "/logs/logstash/brohttp"
        }
        file {
                path => "/logs/bro/spool/bro/ssl.log"
                type => "bro_ssl"
                sincedb_path => "/logs/logstash/brossl"
        }
        file {
                path => "/logs/bro/spool/bro/dns.log"
                type => "bro_dns"
                sincedb_path => "/logs/logstash/brodns"
        }
        file {
                path => "/logs/bro/spool/bro/conn.log"
                type => "bro_conn"
                sincedb_path => "/logs/logstash/broconn"
        }
        file {
                path => "/logs/bro/spool/bro/smtp.log"
                type => "bro_smtp"
                sincedb_path => "/logs/logstash/brosmtp"
        }
}
filter {
		if ([message] =~ /^#/) {
        	drop{}
    	}
        else if [type] == "bro_files" {
                grok {
                        match => [ "message", "(?<time>(.*?))\t(?<bro_id>(.*?))\t(?<source_ip>(.*?))\t(?<dest_ip>(.*?))\t(?<conn_uids>(.*?))\t(?<source>(.*?))\t(?<depth>(.*?))\t(?<analyzers>(.*?))\t(?<mime_type>(.*?))\t(?<filename>(.*?))\t(?<duration>(.*?))\t(?<local_orig>(.*?))\t(?<is_orig>(.*?))\t(?<seen_bytes>(.*?))\t(?<total_bytes>(.*?))\t(?<missing_bytes>(.*?))\t(?<overflow_bytes>(.*?))\t(?<timedout>(.*?))\t(?<parent_fuid>(.*?))\t(?<md5>(.*?))\t(?<sha1>(.*?))\t(?<sha256>(.*?))\t(?<extracted>(.*?))" ]
                        }
        }
        else if [type] == "bro_dhcp" {
                grok {
                        match => [ "message", "(?<time>(.*?))\t(?<bro_id>(.*?))\t(?<source_ip>(.*?))\t(?<source_port>(.*?))\t(?<dest_ip>(.*?))\t(?<dest_port>(.*?))\t(?<mac>(.*?))\t(?<assigned_ip>(.*?))\t(?<lease_time>(.*?))\t(?<trans_id>(.*?))" ]
                        }
        }
        else if [type] == "bro_http" {
                grok {
                        match => [ "message", "(?<time>(.*?))\t(?<bro_id>(.*?))\t(?<source_ip>(.*?))\t(?<source_port>(.*?))\t(?<dest_ip>(.*?))\t(?<dest_port>(.*?))\t(?<depth>(.*?))\t(?<method>(.*?))\t(?<domain>(.*?))\t(?<uri>(.*?))\t(?<referrer>(.*?))\t(?<user_agent>(.*?))\t(?<request_length>(.*?))\t(?<response_length>(.*?))\t(?<status_code>(.*?))\t(?<status_msg>(.*?))\t(?<info_code>(.*?))\t(?<info_msg>(.*?))\t(?<filename>(.*?))\t(?<tags>(.*?))\t(?<username>(.*?))\t(?<password>(.*?))\t(?<proxied>(.*?))\t(?<orig_fuids>(.*?))\t(?<orig_mime_types>(.*?))\t(?<resp_fuids>(.*?))\t(?<resp_mime_types>(.*?))" ]
                        }
        }
        else if [type] == "bro_ssl" {
                grok {
                        match => [ "message", "(?<time>(.*?))\t(?<bro_id>(.*?))\t(?<source_ip>(.*?))\t(?<source_port>(.*?))\t(?<dest_ip>(.*?))\t(?<dest_port>(.*?))\t(?<version>(.*?))\t(?<cypher>(.*?))\t(?<curve>(.*?))\t(?<server_name>(.*?))\t(?<resumed>(.*?))\t(?<last_alert>(.*?))\t(?<next_protocol>(.*?))\t(?<established>(.*?))\t(?<cert_chain_fuids>(.*?))\t(?<client_cert_chain_fuids>(.*?))\t(?<subject>(.*?))\t(?<issuer>(.*?))\t(?<client_subject>(.*?))\t(?<client_issuer>(.*?))\t(?<validation_status>(.*?))" ]
                        }
        }
        else if [type] == "bro_dns" {
                grok {
                        match => [ "message", "(?<time>(.*?))\t(?<bro_id>(.*?))\t(?<source_ip>(.*?))\t(?<source_port>(.*?))\t(?<dest_ip>(.*?))\t(?<dest_port>(.*?))\t(?<proto>(.*?))\t(?<trans_id>(.*?))\t(?<query>(.*?))\t(?<qclass>(.*?))\t(?<qclass_name>(.*?))\t(?<qtype>(.*?))\t(?<qtype_name>(.*?))\t(?<rcode>(.*?))\t(?<rcode_name>(.*?))\t(?<AA>(.*?))\t(?<TC>(.*?))\t(?<RD>(.*?))\t(?<RA>(.*?))\t(?<Z>(.*?))\t(?<answers>(.*?))\t(?<ttls>(.*?))\t(?<rejected>(.*?))" ]
                        }
        }
        else if [type] == "bro_conn" {
                grok {
                        match => [ "message", "(?<time>(.*?))\t(?<bro_id>(.*?))\t(?<source_ip>(.*?))\t(?<source_port>(.*?))\t(?<dest_ip>(.*?))\t(?<dest_port>(.*?))\t(?<proto>(.*?))\t(?<service>(.*?))\t(?<duration>(.*?))\t(?<src_bytes>(.*?))\t(?<dest_bytes>(.*?))\t(?<state>(.*?))\t(?<local_orig>(.*?))\t(?<local_resp>(.*?))\t(?<missed_bytes>(.*?))\t(?<history>(.*?))\t(?<src_pkts>(.*?))\t(?<src_ip_bytes>(.*?))\t(?<dest_pkts>(.*?))\t(?<dest_ip_bytes>(.*?))\t(?<tunnel_parents>(.*?))" ]
                        }
        }
        else if [type] == "bro_smtp" {
                grok {
                        match => [ "message", "(?<time>(.*?))\t(?<bro_id>(.*?))\t(?<id.orig_h>(.*?))\t(?<id.resp_h>(.*?))\t(?<id.resp_p>(.*?))\t(?<trans_depth>(.*?))\t(?<helo>(.*?))\t(?<mailfrom>(.*?))\t(?<rcptto>(.*?))\t(?<date>(.*?))\t(?<from>(.*?))\t(?<to>(.*?))\t(?<reply_to>(.*?))\t(?<msg_id>(.*?))\t(?<in_reply_to>(.*?))\t(?<subject>(.*?))\t(?<x_originating_ip>(.*?))\t(?<first_received>(.*?))\t(?<second_received>(.*?))\t(?<last_reply>(.*?))\t(?<path>(.*?))\t(?<user_agent>(.*?))" ]
                		}
        }
}
output {
        elasticsearch {
                hosts => ["localhost:9200"]
                index => "bro-%{+YYYY.MM.dd}"
                template => "/opt/logstash/config/bro.json"
                template_name => "bro*"
        }
        stdout {
                codec => rubydebug
        }
}
EOF
#########################
#Setup Initialize Scripts
#########################
echo "[+] Setting up Init Scripts"
##############
#Logstash Init
##############
cd /etc/init.d
cat <<'EOF' > logstash
. /lib/lsb/init-functions
name="logstash"
logstash_bin="-- /opt/logstash/bin/logstash"
logstash_conf="/opt/logstash/config/bro.conf"
logstash_log="/logs/logstash/$name.log"
pid_file="/var/run/$name.pid"
NICE_LEVEL="-n 19"
HOME=/home/beholder
start () {
    command="/usr/bin/nice ${NICE_LEVEL} ${logstash_bin} agent -f $logstash_conf --log ${logstash_log} -- web"

    log_daemon_msg "Starting $name"
    if start-stop-daemon --start --chuid "beholder" --quiet --oknodo --pidfile "$pid_file" -b -m --exec $command; then
        log_end_msg 0
    else
        log_end_msg 1
    fi
}
stop () {
    echo "Stopping $name"
    start-stop-daemon --stop --quiet --oknodo --pidfile "$pid_file"
    echo "$name stopped"
}

status () {
    status_of_proc -p $pid_file "" "$name"
}
case $1 in
    start)
        if status; then exit 0; fi
        start
        ;;
    stop)
        stop
        ;;
    reload)
        stop
        start
        ;;
    restart)
        stop
        start
        ;;
    status)
        status && exit 0 || exit $?
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|reload|status}"
        exit 1
        ;;
esac
exit 0
EOF
chmod +x logstash
update-rc.d logstash defaults
###################
#Elasticsearch Init
###################
cd /etc/init.d
cat <<'EOF' > elasticsearch
. /lib/lsb/init-functions
name="elasticsearch"
elastic="-- /opt/elasticsearch/bin/elasticsearch"
pid_file="/var/run/$name.pid"
NICE_LEVEL="-n 19"
start () {
    command="/usr/bin/nice ${NICE_LEVEL} ${elastic}"

    log_daemon_msg "Starting $mode" "$name"
    if start-stop-daemon --start --chuid "beholder" --quiet --oknodo --pidfile "$pid_file" -b -m --exec $command; then
        log_end_msg 0
    else
        log_end_msg 1
    fi
}
stop () {
    echo "Stopping $name"
    start-stop-daemon --stop --quiet --oknodo --pidfile "$pid_file"
    echo "$name stopped"
}

status () {
    status_of_proc -p $pid_file "" "$name"
}
case $1 in
    start)
        if status; then exit 0; fi
        start
        ;;
    stop)
        stop
        ;;
    reload)
        stop
        start
        ;;
    restart)
        stop
        start
        ;;
    status)
        status && exit 0 || exit $?
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|reload|status}"
        exit 1
        ;;
esac
exit 0
EOF
chmod +x elasticsearch
update-rc.d elasticsearch defaults
############
#Kibana Init
############
cd /etc/init.d
cat <<'EOF' > kibana
. /lib/lsb/init-functions
name="kibana"
kibana="-- /opt/kibana/bin/kibana"
pid_file="/var/run/$name.pid"
NICE_LEVEL="-n 19"
start () {
    command="/usr/bin/nice ${NICE_LEVEL} ${kibana}"

    log_daemon_msg "Starting $mode" "$name"
    if start-stop-daemon --start --chuid "beholder" --quiet --oknodo --pidfile "$pid_file" -b -m --exec $command; then
        log_end_msg 0
    else
        log_end_msg 1
    fi
}
stop () {
    echo "Stopping $name"
    start-stop-daemon --stop --quiet --oknodo --pidfile "$pid_file"
    echo "$name stopped"
}

status () {
    status_of_proc -p $pid_file "" "$name"
}
case $1 in
    start)
        if status; then exit 0; fi
        start
        ;;
    stop)
        stop
        ;;
    reload)
        stop
        start
        ;;
    restart)
        stop
        start
        ;;
    status)
        status && exit 0 || exit $?
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|reload|status}"
        exit 1
        ;;
esac
exit 0
EOF
chmod +x kibana
update-rc.d kibana defaults
#################
#Fixing the Crons
#################
echo "[+] Fixin your crons!"
cd /opt/
cat <<EOF > cron
0-59/5 * * * * /opt/bro/bin/broctl cron
0 0 * * * /usr/local/bin/curator --host localhost --port 9200 close indices --older-than 30 --time-unit days --timestring '%Y.%m.%d' --prefix bro
EOF
crontab cron
rm -rf cron
######################
#CHOWNing your system!
######################
chown -R beholder:beholder /logs
chown -R beholder:beholder /opt
######################
#Clearing Certificates
######################
update-ca-certificates -f
###################
#Apache - a2e Setup
###################
echo "[+] Setting up Apache."
a2enmod proxy proxy_http ssl
##################################
#Apache - Creating Basic Auth User
##################################
htpasswd -cbm /etc/apache2/.htpasswd beholder beholder
###################################
#Apache - Creating self-signed cert
###################################
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -subj "/C=DD/ST=Guarding/L=Caverns/O=beholder/CN=beholder" -keyout /etc/ssl/certs/beholder.key -out /etc/ssl/certs/beholder.crt
################################
#Apache - A2E Enable and Disable
################################
a2ensite default-ssl
a2dissite 000-default
########################
#Apache - Port Listening
########################
cat <<EOF > /etc/apache2/ports.conf
Listen 443
EOF
#########################
#Apache - Sites-Available
#########################
cat <<EOF > /etc/apache2/sites-available/default-ssl.conf
<IfModule mod_ssl.c>
        <VirtualHost *:443>
                ServerAdmin webmaster@localhost
                <Proxy *>
                Order deny,allow
                Allow from all
                AuthType Basic
                AuthName "Access Kibana"
                AuthUserFile /etc/apache2/.htpasswd
                Require valid-user
                </Proxy>
                ProxyPass / http://localhost:5601/
                ProxyPassReverse / http://localhost:5601/
                SSLEngine on
                SSLCertificateFile      /etc/ssl/certs/beholder.crt
                SSLCertificateKeyFile   /etc/ssl/certs/beholder.key
                <FilesMatch "\.(cgi|shtml|phtml|php)$">
                                SSLOptions +StdEnvVars
                </FilesMatch>
                <Directory /usr/lib/cgi-bin>
                                SSLOptions +StdEnvVars
                </Directory>
                BrowserMatch "MSIE [2-6]" \
                                nokeepalive ssl-unclean-shutdown \
                                downgrade-1.0 force-response-1.0
                # MSIE 7 and newer should be able to use keepalive
                BrowserMatch "MSIE [17-9]" ssl-unclean-shutdown
        </VirtualHost>
</IfModule>
EOF
#############
#Firewall Fix
#############
echo "[+] Configuring the firewall."
ufw deny 5601
ufw default allow
ufw enable
#########
#Finished
#########
clear
echo 'Your installation has finished. We are rebooting your system.'
seconds=10
while [ $seconds -gt 0 ];
        do
                echo "$seconds"
                sleep 1s
                seconds=$(($seconds - 1))
        done
echo 'VGhhbmsgeW91IGZvciB0cnlpbmcgdGhlIEJlaG9sZGVyIHNjcmlwdCEgVGhlIHBhbmNha2VzIGFyZSBub3QgYSBsaWUu'
shutdown -r now