#!/bin/bash
machineName=$1
pkgPath=$2
pkgName=$3
self=`hostname`
logfile="$4/deployment.log"
logDir=$4
echo -e "Getting Logs from $machineName...\n" >> $logfile 
for file in install.log uninstall.log ; do
     echo "$machineName:/var/tmp/$pkgName/$file $logDir/." >> /root/asdf 
     scp $machineName:/var/tmp/$pkgName/$file $logDir/. 2>&1 > /dev/null
done
scp $machineName:/var/tmp/$pkgName/scripts/deps.log $logDir/. &> /dev/null
echo -e "Getting Logs from $machineName...DONE\n" >> $logfile 
