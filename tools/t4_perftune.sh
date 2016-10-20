#!/bin/bash

# Find Chelsio devices

# commands path
MODPROBE=`which modprobe`
ETHTOOL=`which ethtool 2> /dev/null`
IFUP=/sbin/ifup
CXGBTOOL=`which cxgbtool 2> /dev/null`
KILLALL="`which killall` -q"
SYSCTL="`which sysctl` -q -w" 

usage()
{
        echo "Usage: $0 [options]"
		echo "options:"
		echo " -C    Disable binding IRQs to CPUs (smp_affinity)."
		echo " -D    Do not disable IRQ balance daemon." 
		echo " -t    Write tx_coal=2 to modprobe.d/conf."
		echo " -T    Remove tx_coal=2 from modprobe.d/conf."
		echo
        exit

}

# Look for cxgb4 devices
list_chelsio_dev()
{
        list_dev=`/sbin/ip link show | grep mtu | cut -d':' -f2`
        for dev in $list_dev
        do
                desc_dev=`$ETHTOOL -i $dev 2>&1 | grep cxgb4`
                if [ $? -eq 0 ]; then
                        echo $dev
                fi
        done
}

bringup()
{
	# Privilege ifup as it will apply the interfaces'settings.
	# If it fails, presumably due to the lack of config file,
	# just bring the link up. IP settings can be applied later.
        $IFUP $1 2>/dev/null
        if [ $? -ne 0 ];
        then
                /sbin/ip link set dev $1 up
        fi
}

# cpumask is used in msi_x_perftune function to evenly spread interrupts around
# all the ports/CPUs
# It is declared external to the function as we want a stateful cpumask rotor
# which spreads interrupts as evenly as possible around all the ports/CPUs
cpumask=1

# grep /proc/interrupts to figure out cxgb4's interfaces msi interrupts.
# On recent kernels, typical lines look like:
# 81: 0  0   0   0   PCI-MSI-edge      eth25-Rx1
# 89: 0  0   0   0   PCI-MSI-edge      0000:08:00.4-ofld3
# 90: 0  0   0   0   PCI-MSI-edge      0000:08:00.4-rdma0
# hence the grep on $1 and 'edge'
msi_x_perftune()
{
        ETH=$1
	
	# MSI-X interrupts allocated by driver are recognised by different
	# terminology by different Linux distros.
	# In RHEL 5.X, RHEL 6.X and SLES 11 SP1 distros MSI-X interrupts are
	# recognised as PCI-MSI-edge.
	# In SLES 10 SPX distros  MSI-X interrupts are recognised as
	# PCI-MSI-X.
	# Following switch case statements handles these cases.
	irqs=($(cat /proc/interrupts | grep $ETH | \
	grep "PCI-MSI-" | awk '{ split($0,a,":"); print a[1] }'))
	echo "IRQ table length ${#irqs[@]}"

	maxcpu=$(( $(grep processor /proc/cpuinfo|wc -l) - 1))
	numa_nodes_no=($(ls /sys/devices/system/node/ | grep -c node))

	if [[ ${numa_nodes_no} -gt 1 ]]; then
			numa_node=$(cat /sys/class/net/$dev/device/numa_node)
			node_str="node$numa_node"
			numa_cpus=($(ls /sys/devices/system/node/$node_str/ | grep cpu | sed -n 's/^cpu\([0-9]\)/\1/p' | sort -n))
	fi

	for (( c=0, k=0; c < ${#irqs[@]}; c++ ));
	do
		if [[ ${numa_nodes_no} -gt 1 ]]; then
				cpuid="${numa_cpus[$k]}"
				cpumask=$((1<<cpuid))
				if [[ $cpumask -le $((1<<31)) ]]; then
					echo "Writing $(printf "%x" $cpumask) in /proc/irq/${irqs[$c]}/smp_affinity"
					echo $(printf "%x" $cpumask) > /proc/irq/${irqs[$c]}/smp_affinity
				else
					echo "Writing $(printf "%x,%s" $(($cpumask>>32)) "0")in /proc/irq/${irqs[$c]}/smp_affinity"
					echo $(printf "%x,%s"$(($cpumask>>32)) "0") > /proc/irq/${irqs[$c]}/smp_affinity
				fi
				k=$((k + 1))
				if [[ ${cpumask} -gt $((1<<${maxcpu})) ]] || [[ ${k} -ge  ${#numa_cpus[@]} ]]; then
					k=0
				fi

		else
			if [[ $cpumask -le $((1<<31)) ]]; then
				echo "Writing $(printf "%x" $cpumask) in /proc/irq/${irqs[$c]}/smp_affinity"
				echo $(printf "%x" $cpumask) > /proc/irq/${irqs[$c]}/smp_affinity
			else
				echo "Writing $(printf "%x,%s" $(($cpumask>>32)) "0") in /proc/irq/${irqs[$c]}/smp_affinity"
				echo $(printf "%x,%s" $(($cpumask>>32)) "0") > /proc/irq/${irqs[$c]}/smp_affinity
			fi
			cpumask=`expr $cpumask \* 2`
			if [[ ${cpumask} -gt $((1<<${maxcpu})) ]] ; then
				cpumask=1
			fi
		fi
        done
}

dev_perftune()
{
	ETH=$1
	if ! (( disable_smp_affinity )); then
		echo "Tuning $ETH"
		msi_x_perftune $ETH
	fi
	# For offload and RDMA devices no need to set coalesce settings
	if [[ $ETH != "ofld" && $ETH != "rdma" ]]; then
		$ETHTOOL -C $ETH rx-frames 4
	fi
}

Options="CDTth"
while getopts $Options option; do
	case $option in
		C ) disable_smp_affinity=1;;
		D ) dont_disable_irqbalance=1;;
		t ) tx_coal=2;;
		T ) tx_coal=1;;
		* ) usage;;
	esac
done
shift $(($OPTIND - 1))

if [ $# -ne 0 ]; 
then
        usage
fi

if [ -z $CXGBTOOL ];
then
        echo "Error: please install cxgbtool utility"
        exit 1
fi

if [ -z $ETHTOOL ];
then
	echo "Error: please install ethtool utility"
	exit 1
fi

# start fresh

# If iw_cxgb4 and cxgb4 modules are not loaded then trying to
# remove them will result into FATAL error. This can lead user
# to wrong direction. Hence removing errors getting displyed to
# user evenif modules are not loaded.

if ! (( dont_disable_irqbalance )); then
	$KILLALL irqbalance
fi


if [ -e /etc/modprobe.conf ]; then
	modprobe_config=/etc/modprobe.conf
elif [ -e /etc/modules.conf ]; then
	modprobe_config=/etc/modules.conf
elif [ -d /etc/modprobe.d/ ]; then
	modprobe_config=/etc/modprobe.d
fi

# Option for ipforwarding mode.
if [ "$tx_coal" == "2" ]; then
	if [ -d "$modprobe_config" ]; then
		# modprobe_config is a directory, need to scan all files.
		cf=$(grep -r -l 'options\s*cxgb4\s*.*tx_coal=.*' $modprobe_config/* \
			 2>/dev/null | awk 'BEGIN{FS=":"}{print $1}')
	else
		cf=$(grep -l 'options\s*cxgb4\s*.*tx_coal=.*' $modprobe_config \
			 2>/dev/null)
		[ -n "$cf" ] && cf=$modprobe_config
	fi

	if [ -z "$cf" ]; then
		if [ -d "$modprobe_config" ]; then
			cf=/etc/modprobe.d/chelsio.conf
		else
			cf=$modprobe_config
		fi
		echo "options cxgb4 tx_coal=2" >> $cf
		logger -s "cxgb4 added tx_coal=2 to $cf"
	else
		# The tx_coal option is already set. Dump an error to syslog and continue.
		logger -s "cxgb4 tx_coal value already set. Please check your $cf file."
	fi
# Back to default mode.
elif [ "$tx_coal" == "1" ]; then
	if [ -d "$modprobe_config" ]; then
		cf=$(grep -r -l 'options\s*cxgb4\s*.*tx_coal=.*' $modprobe_config/* \
			 2>/dev/null)
	else
		cf=$modprobe_config
	fi

	if [[ ! -z "$cf" ]]; then
		# If tx_coal is the only option on the line, then remove the
		#  line, otherwise, remove just the tx_coal option.
		sed -i 's/\(\s\)*/\1/g' $cf # get rid of multiple spaces
		t=$(grep "^options\s*cxgb4\s*.*tx_coal=2" $cf)
		t=$(echo $t | sed 's/options\s*cxgb4\s*.*tx_coal=.//')
		if [ -z "$t" ]; then
			logger -s "cxgb4 tx_coal=2 removed from $cf"
			sed -i 's/^options\s*cxgb4\s*tx_coal=.//' $cf
		else
			logger -s "cxgb4 tx_coal=2 removed from $cf"
			sed -i 's/^\(options\s*cxgb4\s*.*\)tx_coal=./\1/' $cf
		fi
	fi
fi

echo "Discovering Chelsio T4/T5/T6 devices ..."


# Allow the dust to settle. Sometimes the OS will rename the network interfaces,
# so if we bringup an interface before it finishes renaming them
# /proc/interrupts will associate irqs with stale interface names.
sleep 2;


# Get cxgb4 devices, bring them up
chelsio_devs=`list_chelsio_dev`
for dev in $chelsio_devs
do
        bringup $dev
done

echo "Configuring Chelsio T4/T5/T6 devices ..."

# get devices again, after potential renaming
# Complete the performance tuning on interfaces now up
chelsio_devs=`list_chelsio_dev`
numa_nodes_no=($(ls /sys/devices/system/node/ | grep -c node))

if [[ ${numa_nodes_no} -gt 1 ]]; then
	echo "Machine contains NUMA nodes..CPU's will be assigned accordingly"	
fi

for dev in $chelsio_devs
do
        dev_perftune $dev
        echo "$dev now up and tuned"
done

# Assign CPUs for offload queues
dev_perftune ofld

# Assign CPUs for rdma queues
dev_perftune rdma

# kill netserver
# killall -v netserver 2>&1 > /dev/null
# start netserver
# taskset -c 4-7 netserver 2>&1 > /dev/null
