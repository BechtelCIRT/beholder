#!/bin/bash
############################################
#Beholder V1.08.000 - ELK/BRO/Libtrace
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
wget https://www.dropbox.com/s/jikilywdcz3sryt/elasticsearch-2.3.2.tar.gz
tar -zxvf *.tar.gz
rm -rf *.tar.gz
mv elastic* elasticsearch
wget https://www.dropbox.com/s/c3ww7odx8dsnl9z/logstash-2.3.2.tar.gz
tar -zxvf *.tar.gz
rm -rf *.tar.gz
mv logstash* logstash
wget https://www.dropbox.com/s/h0bvni3nnpawdcg/kibana-4.5.0-linux-x64.tar.gz
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
                "bytes_seen": {
                    "type": "integer",
                    "ignore_malformed": true,
                    "index": "analyzed"
                },
                "bytes_total": {
                    "type": "integer",
                    "ignore_malformed": true,
                    "index": "analyzed"
                },
                "bytes_missing": {
                    "type": "integer",
                    "ignore_malformed": true,
                    "index": "analyzed"
                },
                "bytes_overflow": {
                    "type": "integer",
                    "ignore_malformed": true,
                    "index": "analyzed"
                },
                "bytes_origin": {
                    "type": "integer",
                    "ignore_malformed": true,
                    "index": "analyzed"
                },
                "bytes_response": {
                    "type": "integer",
                    "ignore_malformed": true,
                    "index": "analyzed"
                },
                "bytes_source_ip": {
                    "type": "integer",
                    "ignore_malformed": true,
                    "index": "analyzed"
                },
                "bytes_response_ip": {
                    "type": "integer",
                    "ignore_malformed": true,
                    "index": "analyzed"
                },
                "bytes_source": {
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
        file {
                path => "/logs/bro/spool/bro/known_modbus.log"
                type => "bro_known_modbus"
                sincedb_path => "/logs/logstash/knownmodbus"
        }
        file {
                path => "/logs/bro/spool/bro/software.log"
                type => "bro_software"
                sincedb_path => "/logs/logstash/software"
        }
        file {
                path => "/logs/bro/spool/bro/known_certs.log"
                type => "bro_known_certs"
                sincedb_path => "/logs/logstash/knowncerts"
        }
        file {
                path => "/logs/bro/spool/bro/known_services.log"
                type => "bro_known_services"
                sincedb_path => "/logs/logstash/knownservices"
        }
        file {
                path => "/logs/bro/spool/bro/known_hosts.log"
                type => "bro_known_hosts"
                sincedb_path => "/logs/logstash/knownhosts"
        }
        file {
                path => "/logs/bro/spool/bro/x509.log"
                type => "bro_x509"
                sincedb_path => "/logs/logstash/x509"
        }
        file {
                path => "/logs/bro/spool/bro/pe.log"
                type => "bro_pe"
                sincedb_path => "/logs/logstash/pe"
        }
        file {
                path => "/logs/bro/spool/bro/known_devices.log"
                type => "bro_known_devices"
                sincedb_path => "/logs/logstash/knowndevices"
        }
        file {
                path => "/logs/bro/spool/bro/communication.log"
                type => "bro_communication"
                sincedb_path => "/logs/logstash/communication"
        }
        file {
                path => "/logs/bro/spool/bro/traceroute.log"
                type => "bro_traceroute"
                sincedb_path => "/logs/logstash/traceroute"
        }
        file {
                path => "/logs/bro/spool/bro/app_stats.log"
                type => "bro_app_stats"
                sincedb_path => "/logs/logstash/appstats"
        }
        file {
                path => "/logs/bro/spool/bro/dnp3.log"
                type => "bro_dnp3"
                sincedb_path => "/logs/logstash/dnp3"
        }
        file {
                path => "/logs/bro/spool/bro/intel.log"
                type => "bro_intel"
                sincedb_path => "/logs/logstash/intel"
        }
        file {
                path => "/logs/bro/spool/bro/modbus.log"
                type => "bro_modbus"
                sincedb_path => "/logs/logstash/modbus"
        }
        file {
                path => "/logs/bro/spool/bro/modbus_register_change.log"
                type => "bro_modbus_register_change"
                sincedb_path => "/logs/logstash/modbusregisterchange"
        }
        file {
                path => "/logs/bro/spool/bro/modbus_register_change.log"
                type => "bro_modbus_register_change"
                sincedb_path => "/logs/logstash/modbusregisterchange"
        }
        file {
                path => "/logs/bro/spool/bro/ftp.log"
                type => "bro_ftp"
                sincedb_path => "/logs/logstash/ftp"
        }
        file {
                path => "/logs/bro/spool/bro/irc.log"
                type => "bro_irc"
                sincedb_path => "/logs/logstash/irc"
        }
        file {
                path => "/logs/bro/spool/bro/kerberos.log"
                type => "bro_kerberos"
                sincedb_path => "/logs/logstash/kerberos"
        }
        file {
                path => "/logs/bro/spool/bro/mysql.log"
                type => "bro_mysql"
                sincedb_path => "/logs/logstash/mysql"
        }
        file {
                path => "/logs/bro/spool/bro/notice.log"
                type => "bro_notice"
                sincedb_path => "/logs/logstash/notice"
        }
        file {
                path => "/logs/bro/spool/bro/radius.log"
                type => "bro_radius"
                sincedb_path => "/logs/logstash/radius"
        }
        file {
                path => "/logs/bro/spool/bro/rdp.log"
                type => "bro_rdp"
                sincedb_path => "/logs/logstash/rdp"
        }
        file {
                path => "/logs/bro/spool/bro/sip.log"
                type => "bro_sip"
                sincedb_path => "/logs/logstash/sip"
        }
        file {
                path => "/logs/bro/spool/bro/snmp.log"
                type => "bro_snmp"
                sincedb_path => "/logs/logstash/snmp"
        }
        file {
                path => "/logs/bro/spool/bro/socks.log"
                type => "bro_socks"
                sincedb_path => "/logs/logstash/socks"
        }
        file {
                path => "/logs/bro/spool/bro/ssh.log"
                type => "bro_ssh"
                sincedb_path => "/logs/logstash/ssh"
        }
        file {
                path => "/logs/bro/spool/bro/syslog.log"
                type => "bro_syslog"
                sincedb_path => "/logs/logstash/syslog"
        }
        file {
                path => "/logs/bro/spool/bro/tunnel.log"
                type => "bro_tunnel"
                sincedb_path => "/logs/logstash/tunnel"
        }
        file {
                path => "/logs/bro/spool/bro/weird.log"
                type => "bro_weird"
                sincedb_path => "/logs/logstash/weird"
        }
        file {
                path => "/logs/bro/spool/bro/signatures.log"
                type => "bro_signatures"
                sincedb_path => "/logs/logstash/signatures"
        }
}
filter {
		if ([message] =~ /^#/) {
        	drop{}
    	}
        else if [type] == "bro_files" {
                csv {
                        columns => ["time","fuid","transmit","receive","conn_uids","bro_type","depth","analyzers","mime_type","filename","duration","local_orig","is_orig","bytes_seen","bytes_total","bytes_missing","bytes_overflow","timedout","parent_fuid","md5","sha1","sha256","extracted"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_dhcp" {
                csv {
                        columns => ["time","bro_id","source","source_port","destination","destination_port","mac","assigned_ip","lease_time","trans_id"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_http" {
                csv {
                        columns => ["time","bro_id","source","source_port","destination","destination_port","trans_depth","method","host","uri","referrer","user_agent","request_body_len","response_body_len","status_code","status_msg","info_code","info_msg","filename","tags","username","password","proxied","orig_fuids","orig_mime_types","resp_fuids","resp_mime_types"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_ssl" {
                csv {
                        columns => ["time","bro_id","source","source_port","destination","destination_port","version","cipher","curve","server_name","resumed","last_alert","next_protocol","established","cert_chain_fuids","client_cert_chain_fuids","subject","issuer","client_subject","client_issuer","validation_status"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_dns" {
                csv {
                        columns => ["time","bro_id","source","source_port","destination","destination_port","proto","trans_id","query","qclass","qclass_name","qtype","qtype_name","rcode","rcode_name","AA","TC","RD","RA","Z","answers","TTLs","rejected"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_conn" {
                csv {
                        columns => ["time","bro_id","source","source_port","destination","destination_port","proto","service","duration","bytes_origin","bytes_response","conn_state","local_orig","local_resp","bytes_missing","history","orig_pkts","bytes_source_ip","resp_pkts","bytes_response_ip","tunnel_parents"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_smtp" {
                csv {
                        columns => ["time","bro_id","source","source_port","destination","destination_port","trans_depth","helo","mailfrom","rcptto","date","from","to","reply_to","msg_id","in_reply_to","subject","x_originating_ip","first_received","second_received","last_reply","path","user_agent","tls","fuids","is_webmail"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_known_modbus" {
                csv {
                        columns => ["time","source","device_type"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_software" {
                csv {
                        columns => ["time","source","source_port","software_type","name","version.major","version.minor","version.minor2","version.minor3","version.addl","unparsed_version"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_known_certs" {
                csv {
                        columns => ["time","source","source_port","subject","issuer_subject","serial"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_known_services" {
                csv {
                        columns => ["time","source","source_port","port_proto","service"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_known_hosts" {
                csv {
                        columns => ["time","source"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_x509" {
                csv {
                        columns => ["time","source","certificate.version","certificate.serial","certificate.subject","certificate.issuer","certificate.not_valid_before","certificate.not_valid_after","certificate.key_alg","certificate.sig_alg","certificate.key_type","certificate.key_length","certificate.exponent","certificate.curve","san.dns","san.uri","san.email","san.ip","basic_constraints.ca","basic_constraints.path_len"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_pe" {
                csv {
                        columns => ["time","source","machine","compile_ts","os","subsystem","is_exe","is_64bit","uses_aslr","uses_dep","uses_code_integrity","uses_seh","has_import_table","has_export_table","has_cert_table","has_debug_data","section_names"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_known_devices" {
                csv {
                        columns => ["time","mac","dhcp_host_name"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_communication" {
                csv {
                        columns => ["time","peer","source","connected_peer_desc","connected_peer_addr","connected_peer_port","level","bromessage"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_traceroute" {
                csv {
                        columns => ["time","src","dst","proto"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_app_stats" {
                csv {
                        columns => ["time","ts_delta","app","uniq_hosts","hits","bytes_source"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_dnp3" {
                csv {
                        columns => ["time","bro_id","source","fc_request","fc_reply","iin"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_intel" {
                csv {
                        columns => ["time","bro_id","source","fuid","file_mime_type","file_desc","seen","sources"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_modbus" {
                csv {
                        columns => ["time","bro_id","source","func","exception","track_address"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_modbus_register_change" {
                csv {
                        columns => ["time","bro_id","source","register","old_val","new_val","delta"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_ftp" {
                csv {
                        columns => ["time","bro_id","source","source_port","destination","destination_port","user","password","command","arg","mime_type","file_size","reply_code","reply_msg","data_channel","cwd","cmdarg","pending_commands","passive","capture_password","fuid","File","unique","ID","last_auth_requested"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_irc" {
                csv {
                        columns => ["time","bro_id","source","source_port","destination","destination_port","nick","user","command","value","addl","dcc_file_name","dcc_file_size","dcc_mime_type","fuid"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_kerberos" {
                csv {
                        columns => ["time","bro_id","source","source_port","destination","destination_port","request_type","client","service","success","error_code","error_msg","from","till","cipher","forwardable","renewable","logged","client_cert","client_cert_subject","client_cert_fuid","server_cert","server_cert_subject","server_cert_fuid"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_mysql" {
                csv {
                        columns => ["time","bro_id","source","source_port","destination","destination_port","cmd","arg","success","rows","response"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_notice" {
                csv {
                        columns => ["time","bro_id","source","source_port","destination","destination_port","fuid","file_mime_type","file_desc","proto","note","msg","sub","src","dst","p","n","peer_descr","actions","suppress_for","dropped","remote_location.country_code","remote_location.region","remote_location.city","remote_location.latitude","remote_location.longitude"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_radius" {
                csv {
                        columns => ["time","bro_id","source","source_port","destination","destination_port","username","mac","remote_ip","connect_info","result","logged"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_rdp" {
                csv {
                        columns => ["time","bro_id","source","source_port","destination","destination_port","cookie","result","security_protocol","keyboard_layout","client_build","client_name","client_dig_product_id","desktop_width","desktop_height","requested_color_depth","cert_type","cert_count","cert_permanent","encryption_level","encryption_method","analyzer_id","done","ssl"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_sip" {
                csv {
                        columns => ["time","bro_id","source","source_port","destination","destination_port","trans_depth","method","uri","date","request_from","request_to","response_from","response_to","reply_to","call_id","seq","subject","request_path","response_path","user_agent","status_code","status_msg","warning","request_body_len","response_body_len","content_type"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_snmp" {
                csv {
                        columns => ["time","bro_id","source","source_port","destination","destination_port","duration","version","community","get_requests","get_bulk_requests","get_responses","set_requests","display_string","up_since"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_socks" {
                csv {
                        columns => ["time","bro_id","source","source_port","destination","destination_port","version","user","password","status","request","request_p","bound","bound_p"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_ssh" {
                csv {
                        columns => ["time","bro_id","source","source_port","destination","destination_port","version","auth_success","direction","client","server","cipher_alg","mac_alg","compression_alg","kex_alg","host_key_alg","host_key","logged","num_failures","capabilities","remote_location"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_syslog" {
                csv {
                        columns => ["time","bro_id","source","source_port","destination","destination_port","proto","facility","severity","bromessage"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_tunnel" {
                csv {
                        columns => ["time","bro_id","source","source_port","destination","destination_port","tunnel_type","action"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_weird" {
                csv {
                        columns => ["time","bro_id","source","source_port","destination","destination_port","name","addl","notice","peer"]
                        separator => "	"
                        }
        }
        else if [type] == "bro_signatures" {
                csv {
                        columns => ["time","bro_id","source","source_port","destination","destination_port","note","sig_id","event_msg","sub_msg","sig_count","host_count"]
                        separator => "	"
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