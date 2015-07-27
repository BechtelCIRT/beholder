#!/bin/bash
############################################
#Beholder v1.01.000 - ELK/BRO/Libtrace
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
apt-get install -y unzip bless cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev git default-jdk dh-autoreconf python-elasticsearch-curator
#####################
#Installing ELK Stack
#####################
echo "[+] Installing ELK Stack"
cd /opt/
wget https://download.elastic.co/elasticsearch/elasticsearch/elasticsearch-1.7.0.tar.gz
tar -zxvf *.tar.gz
rm -rf *.tar.gz
mv elastic* elasticsearch
wget https://download.elastic.co/logstash/logstash/logstash-1.5.3.tar.gz
tar -zxvf *.tar.gz
rm -rf *.tar.gz
mv logstash* logstash
wget https://download.elastic.co/kibana/kibana/kibana-4.1.1-linux-x64.tar.gz
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
wget https://www.bro.org/downloads/release/bro-2.4.tar.gz
tar -zxvf bro*
cd /opt/broinstall/bro-2.4
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
#######################################
#Configuration - Elasticsearch Template
#######################################
mkdir /opt/elasticsearch/config/templates
cd /opt/elasticsearch/config/templates
cat <<'EOF' > /opt/elasticsearch/config/templates/bro.json
{
  "template" : "bro*",
  "settings" : {
    "index.refresh_interval" : "5s"
  },
  "mappings" : {
    "_default_" : {
       "_all" : {"enabled" : true},
       "dynamic_templates" : [ {
         "string_fields" : {
           "match" : "*",
           "match_mapping_type" : "string",
           "mapping" : {
             "type" : "string", "index" : "analyzed", "omit_norms" : true,
               "fields" : {
                 "raw" : {"type": "string", "index" : "not_analyzed", "ignore_above" : 1024}
               }
           }
         }
       } ],
       "properties" : {
         "@version": { "type": "string", "index": "not_analyzed" },
		 "dest_ip_bytes" : { "index_name": "dest_ip_bytes", "type": "integer", "ignore_malformed": true, "index": "analyzed" },
		 "dest_bytes" : { "index_name": "dest_bytes ", "type": "integer", "ignore_malformed": true, "index": "analyzed" },
		 "dest_ip_bytes" : { "index_name": "dest_ip_bytes", "type": "integer", "ignore_malformed": true, "index": "analyzed" },
		 "dest_pkts" : { "index_name": "dest_pkts", "type": "integer", "ignore_malformed": true, "index": "analyzed" },
		 "duration" : { "index_name": "duration", "type": "float", "ignore_malformed": true, "index": "analyzed" },
		 "missed_bytes" : { "index_name": "missed_bytes", "type": "integer", "ignore_malformed": true, "index": "analyzed" },
		 "missing_bytes" : { "index_name": "missing_bytes", "type": "integer", "ignore_malformed": true, "index": "analyzed" },
		 "seen_bytes" : { "index_name": "seen_bytes", "type": "integer", "ignore_malformed": true, "index": "analyzed" },
		 "src_bytes" : { "index_name": "src_bytes", "type": "integer", "ignore_malformed": true, "index": "analyzed" },
		 "src_ip_bytes" : { "index_name": "src_ip_bytes", "type": "integer", "ignore_malformed": true, "index": "analyzed" },
		 "src_pkts" : { "index_name": "src_pkts", "type": "integer", "ignore_malformed": true, "index": "analyzed" },
		 "total_bytes" : { "index_name": "total_bytes", "type": "integer", "ignore_malformed": true, "index": "analyzed" }
         }
       }
    }
  }
}
EOF
################################
#Configuration - Logstash Inputs
################################
mkdir /opt/logstash/config
cd /opt/logstash/config
####################################
#Configuration - Logstash Bro Parser
####################################
cat <<'EOF' > /opt/logstash/config/bro.conf
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
        elasticsearch_http {
                host => localhost
                index => "bro-%{+YYYY.MM.dd}"
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
cat <<'EOF' > logstash-reader
. /lib/lsb/init-functions
mode="reader"
name="logstash-$mode"
logstash_bin="-- /opt/logstash/bin/logstash"
logstash_conf="/opt/logstash/config/bro.conf"
logstash_log="/logs/logstash/$name.log"
pid_file="/var/run/$name.pid"
NICE_LEVEL="-n 19"
start () {
    command="/usr/bin/nice ${NICE_LEVEL} ${logstash_bin} agent -f $logstash_conf --log ${logstash_log} -- web"

    log_daemon_msg "Starting $mode" "$name"
    if start-stop-daemon --start --quiet --oknodo --pidfile "$pid_file" -b -m --exec $command; then
        log_end_msg 0
    else
        log_end_msg 1
    fi
}
stop () {
    echo "Stoping $name"
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
chmod +x logstash-reader
update-rc.d logstash-reader defaults
#########
#Bro Init
#########
cd /etc/init.d
cat <<'EOF' > bro
. /lib/lsb/init-functions
name="bro"
bro="-- /opt/bro/bin/broctl"
pid_file="/var/run/$name.pid"
NICE_LEVEL="-n 19"
start () {
    command="/usr/bin/nice ${NICE_LEVEL} ${bro}"

    log_daemon_msg "Starting $mode" "$name"
    if start-stop-daemon --start --quiet --oknodo --pidfile "$pid_file" -b -m --exec $command; then
        log_end_msg 0
    else
        log_end_msg 1
    fi
}
stop () {
    echo "Stoping $name"
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
chmod +x bro
update-rc.d bro defaults
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
    if start-stop-daemon --start --quiet --oknodo --pidfile "$pid_file" -b -m --exec $command; then
        log_end_msg 0
    else
        log_end_msg 1
    fi
}
stop () {
    echo "Stoping $name"
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
    if start-stop-daemon --start --quiet --oknodo --pidfile "$pid_file" -b -m --exec $command; then
        log_end_msg 0
    else
        log_end_msg 1
    fi
}
stop () {
    echo "Stoping $name"
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
0 0 * * * curator --host localhost --port 9200 close indices --older-than 30 --time-unit days --timestring '%Y.%m.%d' --prefix bro
EOF
crontab cron
rm -rf cron
#########
#Finished
#########
clear
echo 'Your installation has finished. We recommend rebooting your system.'