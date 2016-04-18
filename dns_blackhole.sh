#!/bin/bash

## WARNING: This script is destructive and will remove any firewall rules you have in place.

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

config_path="/var/run/shm/dnsmasq.d"

if [ ! -d $config_path ]; then
    echo "Creating directory for config files"
    mkdir -p -m 755 $config_path
fi

ip_address="$(hostname -I | awk '{ print $1 }')"
echo "Using ${ip_address} for DNS black hole"

echo "Removing and unlinking previous configs"
rm ${config_path}/gen.*
find /etc/dnsmasq.d/ -type l -exec unlink {} \;

echo "Downloading bad/advertising domain lists"

curl -s "http://pgl.yoyo.org/adservers/serverlist.php?showintro=0;hostformat=hosts" |\
	grep -v '#' | grep -v 'localhost' |\
	awk '/127.0.0.1/ { gsub("127.0.0.1 ","address=/"); print $0 "/'$ip_address'"}' |\
	split -C 50K - ${config_path}/gen.yoyo.

curl -s "https://adaway.org/hosts.txt" |\
	grep -v '#' | grep -v 'localhost' |\
        awk '/127.0.0.1/ { gsub("127.0.0.1 ","address=/"); print $0 "/'$ip_address'"}' |\
        split -C 50K - ${config_path}/gen.adaway.

curl -s "http://adblock.gjtech.net/?format=unix-hosts" |\
	grep -v '#' | grep -v 'localhost' |\
        awk '/127.0.0.1/ { gsub("127.0.0.1 ","address=/"); print $0 "/'$ip_address'"}' |\
        split -C 50K - ${config_path}/gen.gjtech.

curl -s http://someonewhocares.org/hosts/hosts |\
	grep -v '#' | grep -v 'localhost' | grep -v 'broadcasthost' |\
        awk '/127.0.0.1 / { gsub("127.0.0.1 ","address=/"); print $0 "/'$ip_address'"}' |\
        split -C 50K - ${config_path}/gen.someonewhocares.

#curl -s -A 'Mozilla/5.0 (X11; Linux x86_64; rv:30.0) Gecko/20100101 Firefox/30.0' -e http://forum.xda-developers.com/ http://adblock.mahakala.is/ |\
#	grep -v '#' | grep -v 'localhost' |\
#	awk '/127.0.0.1/ { gsub("127.0.0.1\t","address=/"); print $0 "/'$ip_address'"}' |\
#	split -C 50K - ${config_path}/gen.mahakala.

curl -s --compressed "https://isc.sans.edu/feeds/suspiciousdomains_High.txt" |\
	awk 'NR > 1 && !/#/ && !/Site/ { gsub("\t",""); print "address=/" $0 "/'$ip_address'" }' |\
	split -C 50K - ${config_path}/gen.susp.high.

curl -s --compressed "https://isc.sans.edu/feeds/suspiciousdomains_Medium.txt" |\
        awk 'NR > 1 && !/#/ && !/Site/ { gsub("\t",""); print "address=/" $0 "/'$ip_address'" }' |\
        split -C 50K - ${config_path}/gen.susp.med.

curl -s http://mirror1.malwaredomains.com/files/BOOT |\
	awk 'NR > 11 { gsub("PRIMARY ","address=/"); gsub(" blockeddomain.hosts","/'$ip_address'"); print ;}' |\
	split -C 50K - ${config_path}/gen.malw.

echo "Re-linking config files:"
find $config_path -type f -exec ln -fvs {} /etc/dnsmasq.d/ \;

echo "Configuring firewall"
iptables -F
iptables -A INPUT -p tcp -i eth0 --dport 80 -j REJECT
iptables -A INPUT -p tcp -i eth0 --dport 443 -j REJECT

echo "Configuring permissions"
chmod 644 $config_path/*
chmod 755 $config_path
chown -R root $config_path

echo "Making sure that dnsmasq is started"
if [ -n "$(ps -e | grep dnsmasq)" ]; then
    service dnsmasq restart
else
    while [ -z "$(ps -e | grep dnsmasq)" ]; do
        service dnsmasq stop
        service dnsmasq start
        sleep 2m
    done
fi
