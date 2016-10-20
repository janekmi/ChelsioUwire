#!/bin/bash

if [ $# -ne 1 ]; then
        echo -e "\nUSAGE: $0 <interface name> \n"
        exit 1
fi

intfcPresent=$(ifconfig -a | grep -c $1)
if [ $intfcPresent -ne 1 ]; then
	echo -e "\nError: Interface $1 is not present.\n"
        exit 1
fi


status=0

echo -e "\nPlease do the following settings to get the good latency numbers on all the machines under test:\n\n1. Disable Hyper Threading in the system BIOS.\n2. Disable C State in the system BIOS.\n3. Add these kernel command line options, 'idle=poll maxcpus=1', to kernel command line and reboot the machine.\n"

echo "Press ENTER to continue..."
read -s

echo -e "\nNow the script will stop certain services to improve latency.\n"
sleep 4
echo -n -e "\nSetting TCP time stamp to 0..."
sysctl -w net.ipv4.tcp_timestamps=0 &> temp
echo DONE
irqBalanceProc=$(ps -ef | grep irqbalance | grep -c -v "grep")
if [ $irqBalanceProc -ne 0 ]; then  
	echo -n -e "\nKilling irqbalance process..."
	killall irqbalance &> temp
	if [ "$?" -ne "0" ]; then
		echo -e "\nCannot kill irqbalance process.\n"
		cat temp 
		status=1
	else 
		echo DONE
	fi
fi
if [ -e /etc/init.d/iptables ]; then
	srvStatus=$(service iptables status | grep -c "Firewall is stopped")
	if [ $srvStatus -ne 1 ]; then
		echo -n -e "\nStopping iptables service..."
		service iptables stop &> temp
		if [ "$?" -ne "0" ]; then
        		echo -e "\nCannot stop iptables service.\n"
		        cat temp
			status=1
		else 
			echo DONE
		fi
	fi
fi
if [ -e /etc/init.d/ip6tables ]; then
	srvStatus=$(service ip6tables status | grep -c "Firewall is stopped")
        if [ $srvStatus -ne 1 ]; then
		echo -n -e "\nStopping ip6tables service..."
		service ip6tables stop &> temp
		if [ "$?" -ne "0" ]; then
        		echo -e "\nCannot stop ip6tables service.\n"
	        	cat temp
			status=1
		else 
			echo DONE
		fi
	fi
fi
if [ -e /etc/init.d/NetworkManager ]; then
	echo -n -e "\nStopping NetworkManager service..."
	service NetworkManager stop &> temp
	if [ "$?" -ne "0" ]; then
        	echo -e "\nCannot stop NetworkManager service.\n"
	        cat temp
		status=1
	else 
		echo DONE
	fi
fi
if [ -e /etc/init.d/lvm2-monitor ]; then
	echo -n -e "\nStopping lvm2-monitor service..."
	service lvm2-monitor force-stop &> temp
	if [ "$?" -ne "0" ]; then
        	echo -e "\nCannot stop lvm2-monitor service.\n"
	        cat temp
		status=1
	else 
		echo DONE
	fi
fi
if [ -e /etc/init.d/cpuspeed ]; then
	echo -n -e "\nStopping cpuspeed service..."
	service cpuspeed stop &> temp
	if [ "$?" -ne "0" ]; then
        	echo -e "\nCannot stop cpuspeed service.\n"
	        cat temp
		status=1
	else
		echo DONE
	fi
fi
if [ -e /etc/init.d/irqbalance ]; then
	echo -n -e "\nStopping irqbalance service..."
	service irqbalance stop &> temp
	if [ "$?" -ne "0" ]; then
	        echo -e "\nCannot stop irqbalance service.\n"
        	cat temp
		status=1
	else 
		echo DONE
	fi
fi
if [ -e /etc/init.d/trace-cmd ]; then
	echo -n -e "\nStopping trace-cmd service..."
	service trace-cmd stop &> temp
	if [ "$?" -ne "0" ]; then
	        echo -e "\nCannot stop trace-cmd service.\n"
        	cat temp
		status=1
	else
		echo DONE
	fi
fi
if [ -e /etc/init.d/arptables_jf ]; then
	echo -n -e "\nStopping  arptables_jf service..."
	service arptables_jf stop &> temp
	if [ "$?" -ne "0" ]; then
        	echo -e "\nCannot stop arptables_jf service.\n"
	        cat temp
		status=1
	else
		echo DONE
	fi
fi
groPresent=$(ethtool -k $1 | egrep -c "generic-receive-offload|generic receive offload")
if [ $groPresent -ne 0 ]; then 
	echo -n -e "\nDisabling generic-receive-offload on $1..."
	ethtool -K $1 gro off &> temp
	if [ "$?" -ne "0" ]; then
        	echo -e "\nCannot disable generic-receive-offload on $1.\n"
	        cat temp
		status=1
	else
		echo DONE
	fi
fi
gsoPresent=$(ethtool -k $1 | egrep -c "generic segmentation offload|generic-segmentation-offload")
if [ $gsoPresent -ne 0 ]; then
	echo -n -e "\nDisabling generic segmentation offload on $1..."
	ethtool -K $1 gso off &> temp
	if [ "$?" -ne "0" ]; then
        	echo -e "\nCannot disable generic segmentation offload on $1.\n"
	        cat temp
		status=1
	else
		echo DONE
	fi
fi
tsoPresent=$(ethtool -k $1 | egrep -c "tcp segmentation offload|tcp-segmentation-offload")
if [ $tsoPresent -ne 0 ]; then
	echo -n -e "\nDisabling tcp segmentation offload on $1..."
	ethtool -K $1 tso off &> temp
	if [ "$?" -ne "0" ]; then
        	echo -e "\nCannot disable tcp segmentation offload on $1.\n"
	        cat temp
		status=1
	else
		echo DONE
	fi
fi

rm -f temp

if [ $status -ne 0 ]; then 
	echo -e "\nError: while tunning latency for Chelsio adapter.\n"
else
	echo -e "\nLatency tunning is completed successfully.\n"
fi
