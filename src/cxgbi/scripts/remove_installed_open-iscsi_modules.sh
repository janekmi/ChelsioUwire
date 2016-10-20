#!/bin/bash

mods="scsi_transport_iscsi libiscsi libiscsi_tcp"
# for RHEL >= 5.4
mods="$mods libiscsi2 scsi_transport_iscsi2"
mods="$mods cxgb3i"

for m in $mods; do
	location=`modinfo $m | grep filename | cut -d':' -f2`
	if [ -n "$location" ]; then
		echo "removing $location ..."
		rm -f $location
	fi
done

depmod -a
