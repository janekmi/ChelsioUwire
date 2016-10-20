#! /bin/bash

################################################################################
# Function definition
################################################################################

function removemod {
	module=$1

	if [[ -n $(lsmod | grep $module) ]]; then
		echo -e "Removing $module\n"
		modprobe -r $module
	fi
}

function setup_smp_affinity {
	maxcpu=$(( $(grep processor /proc/cpuinfo|wc -l) - 1))
	cpu=$((1))

	for e in $(ifconfig -a|grep 00:07:43|awk '{print $1}'); do
	        for i in $(egrep "${e}" /proc/interrupts | grep queue | awk '{printf "%d\n",$1}' ) ; do
	                echo "${e} cpu $(printf "%x" ${cpu}) irq ${i}"
	                echo $(printf "%x" ${cpu}) > /proc/irq/${i}/smp_affinity

	                cpu=$((${cpu}<<1))
	                temp=$(( 1 << ${maxcpu} ))

	                if [[ ${cpu} -gt $temp ]]; then
	                        cpu=$(( 1 ))
	                fi
	        done
	done
}

################################################################################
# Main
################################################################################
ETH0=$1
ETH1=$2
qsets=$3

ETH0_IP="10.10.10.1"
ETH1_IP="20.10.10.1"

if [[ "$ETH1" == "" ]]; then

	echo "Usage: $0 <interface 0> <interface 1> [<qsets>]"
	exit -1

fi

if [[ "$qsets" == "" ]]; then
	qsets=$(( $(cat /proc/cpuinfo | grep processor | wc -l) ))
	if (( $qsets > 16 )); then
		qsets=$(( qsets / 2 ))
	fi 
fi

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1

# Set number of qsets
cxgbtool $ETH0 qsets $qsets
cxgbtool $ETH1 qsets $qsets

# Bringup interfaces
ifconfig $ETH0 $ETH0_IP/24 up
ifconfig $ETH1 $ETH1_IP/24 up

# Setup SMP affinity
setup_smp_affinity

sleep 5

################################################################################
# Things that are just good to disable when doing latency testing...
################################################################################
# Disable GRO
ethtool -K $ETH0 gro off
ethtool -K $ETH1 gro off

# Disable rp_filter
sysctl -n net.ipv4.conf.$ETH0.rp_filter=0
sysctl -n net.ipv4.conf.$ETH1.rp_filter=0

# Disable pause frames
ethtool -A $ETH0 autoneg off rx off tx off
ethtool -A $ETH1 autoneg off rx off tx off

################################################################################
# Disable services that have been known to reduce performance
################################################################################
# cpuspeed had a huge affect on performance. Enabled: -3Mpps per port
chkconfig --level 12345 cpuspeed off
service cpuspeed stop

# All the rest of these services that we are disabling did not have that much
# of an impact on performance...
chkconfig --level 12345 iptables off
chkconfig --level 12345 ip6tables off
chkconfig --level 12345 NetworkManager off
chkconfig --level 12345 openibd off
chkconfig --level 12345 irqbalance off
chkconfig --level 12345 avahi-daemon off

# Stop services which have been disabled above
tmp=$(ps -ea | grep iptables)
if [[ $tmp != "" ]]; then service iptables stop; fi
tmp=$(ps -ea | grep ip6tables)
if [[ $tmp != "" ]]; then service ip6tables stop; fi
tmp=$(ps -ea | grep NetworkManager)
if [[ $tmp != "" ]]; then service NetworkManager stop; fi
tmp=$(ps -ea | grep openibd)
if [[ $tmp != "" ]]; then service openibd stop; fi
tmp=$(ps -ea | grep irqbalance)
if [[ $tmp != "" ]]; then service irqbalance stop; fi

# Disable some iptables stuff in order to remove iptable* modules.
if [[ -n $(lsmod | grep ip_tables) ]] ; then
	iptables -t filter -F
	iptables -t filter -X
	iptables -t nat -F
	iptables -t nat -X
	iptables -t mangle -F
	iptables -t mangle -X
	iptables -t raw -F
	iptables -t raw -X
fi

removemod "iptable_mangle"
removemod "iptable_filter"
removemod "ip_MASQUERADE"
removemod "iptable_nat"
removemod "ip_conntrack"
removemod "iptable_raw"
removemod "ip_tables"
removemod "i7core_edac"
removemod "ip6table_filter"
removemod "ip6_tables"
removemod "ipt_REJECT"
removemod "xt_CHECKSUM"
removemod "xt_state"
removemod "nf_conntrack"

# rmmod xt_state and nf_conntrack may fail.
# So need to add two lines to /etc/modprobe.d/blacklist.conf
# blacklist xt_state
# blacklist nf_conntrack

removemod "sit"
removemod "tunnel4"
removemod "ebtable_nat"
removemod "ebtables"
removemod "kvm_intel"
removemod "kvm"
removemod "iTCO_wdt"
removemod "iTCO_vendor_support"

#cd /lib/modules/$(uname -a | awk '{print $3}')/kernel/drivers/dma/ioat
#if [[ $(ls | grep ioatdma.ko) == "ioatdma.ko" ]] ; then mv ioatdma.ko orig.ioatdma.ko.orig; fi
cd ~
