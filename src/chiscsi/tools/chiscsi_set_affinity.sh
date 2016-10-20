#!/bin/bash

function check_cmd_exist
{
	path=`which $1`
	if [ -z "$path" ]; then
		echo "$1 NOT available, bail out."
		exit 0
	fi
}

check_cmd_exist pgrep 
check_cmd_exist taskset

cpu=`cat /proc/cpuinfo | grep processor | wc -l`

cnt=0
mask=1
while [ $cnt -lt $cpu ]; do
	proc=`pgrep -x ch_tworker_$cnt`
	hex=`echo $mask | awk '{printf "0x%x",$0}'`
	v=`taskset -p $hex $proc | grep new`
	echo "ch_tworker_$cnt: $v."
	let cnt=$cnt+1
	let mask*=2
done

cnt=0
mask=1
while [ $cnt -lt $cpu ]; do
	proc=`pgrep -x ch_tlu_$cnt`
	hex=`echo $mask | awk '{printf "0x%x",$0}'`
	v=`taskset -p $hex $proc | grep new`
	echo "ch_tlu_$cnt: $v."
	let cnt=$cnt+1
	let mask*=2
done
