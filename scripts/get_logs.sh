#!/bin/bash
machineName=$1
pkgPath=$2
pkgName=$3
self=`hostname`
logfile="$4/deployment.log"
logDir=$4
echo -e "Getting Logs from $machineName...\n" >> $logfile 
for file in Summary install.log ; do 
     scp $machineName:/var/tmp/$pkgName/$file $logDir/. &> /dev/null
done
scp $machineName:/var/tmp/$pkgName/scripts/deps.log $logDir/. &> /dev/null
echo -e "Getting Logs from $machineName...DONE\n" >> $logfile 
