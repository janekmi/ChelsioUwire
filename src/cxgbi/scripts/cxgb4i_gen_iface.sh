#!/bin/bash

ethlist=();
iplist=();
nport=0

#
# generate cxgb4 iface file
# only the one which has ip address provisioned will be generated
#
rm -rf /etc/iscsi/ifaces/cxgb4i.*
rm -rf /var/lib/iscsi/ifaces/cxgb4i.*

list=`ls /sys/class/net`
cnt=1
for eth in $list; do
	if [ $eth == "lo" ]; then
		continue;
	fi

	vl=`ethtool -i $eth | grep VLAN`
	if [ -z "$vl" ]; then
		vlan=0
	else
		vlan=1
	fi

	v=`ethtool -i ${eth%.*} | grep cxgb4`
	if [ -z "$v" ]; then
		echo "$eth is NOT cxgb4"
		continue
	fi

#	echo "$eth:"
	v=`ifconfig $eth | grep HWaddr`
#	echo "HWaddr: $v."
	mac=`echo $v | cut -d':' -f2-7 | cut -d' ' -f3`
#	echo "mac=$mac."
	mac=`echo $mac | awk '{print tolower($0)}'`

	ip=`ifconfig $eth | grep "inet addr" | cut -f2 -d":" | cut -f1 -d" "`
	if [ -z "$ip" ]; then
		echo "$eth ipv4 address NOT configured, skip" 
		continue
	fi

	tmpfn="cxgb4i.p"${cnt}
	if [ $vlan -eq 1 ]; then
		tmpfn=${tmpfn}".vlan"
	fi
	echo "cxgb4 port $cnt: $eth, $mac, $ip -> $tmpfn."
	ethlist=("${ethlist[@]}" "$eth")
	iplist=("${iplist[@]}" "$ip")

	fn=/tmp/$tmpfn
	echo "# BEGIN RECORD 2.0-872" > $fn
	echo "iface.iscsi_ifacename = $tmpfn" >> $fn
	echo "iface.hwaddress = $mac" >> $fn
	echo "iface.transport_name = cxgb4i" >> $fn
	echo "iface.ipaddress = $ip" >> $fn
	if [ $vlan -eq 1 ]; then
		echo "iface.net_ifacename = $eth" >> $fn
	fi

	if [ -d /var/lib/iscsi/ifaces ]; then
		cp $fn /var/lib/iscsi/ifaces
	fi
	mv $fn /etc/iscsi/ifaces

	let cnt=$cnt+1
done;

nport=$cnt

