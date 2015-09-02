############################################
#Beholder v1.02.000 - ELK/BRO/Libtrace
#Created By: Jason Azzarella and Chris Pavan
#Problems or Feature Requests?
#E-mail Us: jmazzare@bechtel.com
############################################

Beholder is a shell script which installs and configures essentials to peer into your network activity. Monitor your network traffic with Bro IDS, build dashboards with Kibana to get a visual representation of your activity and obtain packet captures of the identified events with Tracesplit.

'''Under the Hood'''

* ELK Stack (https://www.elastic.co)
	* Elasticsearch
		* Curator (pre-set to close out indexes older than 30 days)
	* Logstash
	* Kibana
* Bro IDS (https://www.bro.org/)
* Libtrace (http://research.wand.net.nz/software/libtrace.php)

'''Software Requirements'''

* Ubuntu 14.04 x64

'''Hardware Minimum Requirements’’’

* 64 Bit Processor
* 3 GB RAM
* 40 GB HDD

'''Installation'''

* Run the beholder script. Don't forget to sudo!
* When prompted, enter the interface that you would like to monitor.
* At completion, reboot the system.

'''Details'''

* Kibana Interface - http://localhost:5601
	* Use a web browser to access your Kibana instance.
	* On your first load, you will be required to insert the elasticsearch index.
		* Input bro* and select the @timestamp field from the timestamp dropdown.
		* You will be presented with the index fields that have been identified. Use the yellow refresh button in order to update the listed fields. You may need to hit this a few times on first setup.
			* You should get about 187 fields after all have been populated at least once.

* Tracesplit Example
	* Capture data from interface eth0 - sudo /opt/libtrace/tools/tracesplit/tracesplit -z 6 -Z gzip int:eth0 erf:/pcaps/capture.gz
	
'''What's in a Version Name?'''

Version numbers get confusing so I'm adding an explanation as to what matters for versions of this script.

EX 1.00.001

The first set of digits (1) represents major tool additions and new functionality.
The second set of digits (00) represents upgraded versions of tools such as Bro, Elasticsearch, Logstash.
The third set of digits (001) represents tweaks to the scripts, changes to the templates or all around fixes to the code.