#!/bin/bash
machineName=$1
isInstallSet=$2
pkgPath=$3
pkgName=$4
logfile="$5/deployment.log"
errfile="$5/deployerror.log"
confTune=$6
installOfed=$7
if [[ $confTune == "memfree-config" ]] ; then
instTargs="iwarp:toe"
else 
instTargs="iwarp:toe:rdma_block_device"
fi 

echo -e "Copying Chelsio Cluster Deployment Installer on $machineName.\n" > $logfile 
scp $pkgPath.tar.gz root@$machineName:/var/tmp/.
if [ $? -ne 0 ]; then
      echo -e "\nError: while copying Chelsio Cluster Deployment Installer on $machineName.\n"  > $errfile 
      exit -1
fi
echo -e "Copying Chelsio Cluster Deployment Installer on $machineName...DONE\n" >> $logfile 

ssh root@$machineName rm -rf /var/tmp/$pkgName > /dev/null
echo -e "Untarring Chelsio Cluster Deployment Installer on $machineName.\n" >> $logfile 
ssh root@$machineName tar xzf /var/tmp/$pkgName.tar.gz -C /var/tmp
if [ $? -ne 0  ]; then
      echo -e "\nError: while untaring Chelsio Cluster Deployment Installer on $machineName.\n" >> $errfile 
      exit -1
fi
echo -e "Untarring Chelsio Cluster Deployment Installer on $machineName...DONE\n" >> $logfile 

if [ "$isInstallSet" == "yes" ]; then
	echo -e "Installing Chelsio Cluster Deployment Installer on $machineName.\n"
	if [ "$installOfed" == "yes" ]; then
		ssh root@$machineName "cd /var/tmp/$pkgName && python install.py -s -O -c $instTargs -x $confTune "
	else 
		ssh root@$machineName "cd /var/tmp/$pkgName && python install.py -s -c $instTargs -x $confTune "
	fi
	if [ $? -ne 0 ]; then
      		echo -e "\nError: while installing package on $machineName.\n" >> $errfile 
		exit -1
	fi
	echo -e "Installing Chelsio Cluster Deployment Installer on $machineName...DONE\n"  >> $logfile 
else
	echo -e "Uninstalling Chelsio Cluster Deployment Installer on $machineName\n"
	ssh root@$machineName " cd /var/tmp/$pkgName && python install.py -s -u all "
	if [ $? -ne 0 ]; then
      		echo -e "\nError: while installing OFED package on $machineName.\n" >> $errfile 
      		exit -1
	fi
	echo -e "Uninstalling Chelsio Cluster Deployment Installer on $machineName...DONE\n" >> $logfile 
fi
