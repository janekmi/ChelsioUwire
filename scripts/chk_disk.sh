#!/bin/bash
k=$(df --block-size=1K . | awk 'NR==2' | awk '{print $4}' | head -1 | awk '{print $1}') ;
dev_name=$(df . | awk 'NR==2' | awk '{print $1}')  
chk=1
r=512000
if [ $k ] ; then 
	p=$k
else
	k=$(df --block-size=1K . | awk 'NR==3' | awk '{print $3}' | head -1 | awk '{print $1}') ;
	dev_name=$(df . | awk 'NR==2' | awk '{print $1}')
	p=$k 
fi;

if [ $p -lt $r ]
then
    o=` expr $r - $p ` ;
    if [ $o -lt 1024 ] ; then
        op=1
    else
        op=` expr $o / 1024 ` ;
    fi;
    echo "$op $dev_name" ;
    exit -1 ;
else
    chk=0 ;
fi;

k=$(df --block-size=1K /lib/modules/`uname -r` | awk 'NR==2' | awk '{print $4}' | head -1 | awk '{print $1}')
dev_name=$(df  /lib/modules/`uname -r` | awk 'NR==2' | awk '{print $1}')

if [ $k ] ; then 
	p=$k
else 
	k=$(df --block-size=1K /lib/modules/`uname -r` | awk 'NR==3' | awk '{print $3}' | head -1 | awk '{print $1}')
	dev_name=$(df  /lib/modules/`uname -r` | awk 'NR==2' | awk '{print $1}')
	p=$k
fi;

r=102400
if [ $p -lt $r ] ; then
    o=` expr $r - $p `
    if [ $o -lt 1024 ] ; then
        op=1
    else
        op=` expr $o / 1024 ` ;
    fi;
    echo "$op $dev_name"
    exit -1 ;
else
    chk=0
fi ;

if [ $chk -eq 0 ] ; then 
echo "0"
fi ;
