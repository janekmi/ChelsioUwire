
#
# Copyright (c) 2015 Chelsio Communications, Inc. All rights reserved.
#
# This software is available to you under a choice of one of two
# licenses.  You may choose to be licensed under the terms of the GNU
# General Public License (GPL) Version 2, available from the file
# COPYING in the main directory of this source tree, or the
# OpenIB.org BSD license below:
#
#     Redistribution and use in source and binary forms, with or
#     without modification, are permitted provided that the following
#     conditions are met:
#
#      - Redistributions of source code must retain the above
#        copyright notice, this list of conditions and the following
#        disclaimer.
#
#      - Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials
#        provided with the distribution.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

		RDMA Block Device Driver

This package contains drivers and support commands that implement an RDMA
initiator and target for arbitrary block devices.  The initiator registers
as a blkdev driver locally.  The target opens the backend block device
submitting BIO operations on behalf of the initiator.  Data flows via
rdma into/out of fast registered memory regions with zero copying added.

Currently this has only been tested on a 3.18.x kernel.  I know there are 
backport issues that will need to be addressed going forward.


### Build/Install:

hg clone http://willow/hg/rdma_block_dev

cd rdma_block_dev

make && make install


### Setting up a RDMA block device to backend device /dev/ram0:

On the initiator and target, configure RDMA and make sure rping works.

On the initiator: modprobe rbdi

On the target: modprobe rbdt

On the initiator: rbdctl -n -a <target-ipaddr> -p 65000 -d /dev/ram0 

This will create a local device on the initiator called /dev/rbdi0
which you can access as a local block device.  Each successive 
target added will get a new /dev/rdbiX number where X is the next 
available number.


### To remove a device:

On the initiator: rbdctl -r -d /dev/rbdi0


### To list active devices:

Initiator: cat /sys/kernel/debug/rbdi/devices

Target: cat /sys/kernel/debug/rbdt/devices


### To show stats per device:

Initiator: cat /sys/kernel/debug/rbdi/rdbi0/stats

Target: cat /sys/kernel/debug/rbdt/ram0/stats

END
