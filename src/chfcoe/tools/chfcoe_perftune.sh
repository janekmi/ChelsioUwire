#!/bin/bash

node_id=0
num_cpu_id=0

declare -a cpu_id

usage()
{
        echo "Usage: $0 [options]"
		echo "options:"
		echo " -i    Bind IRQs to CPUs (smp_affinity)."
		echo " -w    Bind Workers to CPUs." 
		echo " -n    Numa node id."
		echo " -c    CPU IDs."
		echo
        exit 1
}

check_command_exist()
{
	cmd=`which $1`
	if [ -z $cmd ]; then
		echo "$1 not available"
		exit 1
	fi
}

tune_irq()
{
	irqs=($(cat /proc/interrupts |grep fcoe | \
	grep "PCI-MSI-" | awk '{ split($0,a,":"); print a[1] }' ))

	echo "IRQ table length ${#irqs[@]}"
	
	maxcpu_id=$(($(grep processor /proc/cpuinfo | wc -l) -1))
	if [ $maxcpu_id -gt 31 ]; then
		let max_cpu_id=31
	fi
	
	index=0
	for (( c=0; c<${#irqs[@]}; c++ ))
	do
		let index=$index%$num_cpu_id
		let cpu_num=${cpu_id[$index]}
		let index=$index+1
		
		if [ $cpu_num -gt $maxcpu_id ]; then
			if [ $cpu_num -gt 31 ]; then
				echo -n "cpu id ($cpu_num) greater than 31 not supported by script, "
				echo "please set IRQ smp_affinity manually"
			else
				echo "Invalid cpu id $cpu_num"
			fi
			exit 1
		fi

		let "cpumask=(1<<$cpu_num)"
		echo "Writing $(printf "%x" $cpumask) in /proc/irq/${irqs[$c]}/smp_affinity"
		echo $(printf "%x" $cpumask) >/proc/irq/${irqs[$c]}/smp_affinity
		
	done

}

tune_worker()
{
	check_command_exist taskset
	check_command_exist pgrep

	worker_num=`pgrep chfcoe_$node_id | wc -l`
	maxcpu_id=$(($(grep processor /proc/cpuinfo | wc -l) -1))
	
	index=0
	for (( c=0; c<$worker_num; c++ ))
	do
		let index=$index%$num_cpu_id
		let cpu_num=${cpu_id[$index]}
		let index=$index+1
		
		if [ $cpu_num -gt $maxcpu_id ]; then
			echo "Invalid cpu id $cpu_num"
			exit 1
		fi
		worker_name=$(printf "chfcoe_%u_%u" "$node_id" "$c")
		pgrep -x $worker_name >/dev/null 2>&1
		if [ $? -ne 0 ]; then
			exit 1
		fi
		
		worker_pid=`pgrep -x $worker_name`
		new_cpu_id=`taskset -p -c $cpu_num $worker_pid | grep new`
		echo "$worker_name: $new_cpu_id"

	done	
}

cmd="0"
Options="iwn:c:"
while getopts $Options option; do
	case $option in
		i ) cmd="irq";;
		w ) cmd="worker";;
		n ) node_id=$OPTARG;;
		c ) cpu_id=($OPTARG);;
		* ) usage;;
	esac
done

num_cpu_id=${#cpu_id[@]}
if [ $num_cpu_id -le 0 ]; then
	usage
fi

case $cmd in
	irq)	tune_irq;;
	worker)	tune_worker;;
	*)	usage;;
esac
exit 0 
