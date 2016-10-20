                              Wire Sniffing/Tapping
                    ****************************************

================================================================================
0. CONTENTS
================================================================================

1.	Theory of Operation
2.	Package content
3.	Known working configuration
4.	Installation
5.	How to load drivers
6.	Examples

================================================================================
1. Theory of Operation
================================================================================

The objective is to provide sniffing capabilities via T4 from which will
become invaluable in debugging issue in lab.

             ----------                  ---------
            |  libapp  |                | libpcap |
            |(User app)|                |(tcpdump)|
             ----------\                /---------
                        |              |
                        |              |
             ---------------------------------------
            |               libcxgb4                |
             ---|-|---------|----------------|------
                | |         |                |
User Space      |K|         |                |
----------------|e|---------|----------------|----------------------------------
Kernel Space    |r|         |                |
                |n|         |                |
                |e|     ---------      ---------------------
                |l|    |  Iwarp  |    | Kernel TCP/IP Stack |
                | |    |         |    |                     |
                |B|    |         |    |                     |
                |y|    |         |    |                     |
                |p|     ---------      ---------------------
                |a|         |                |
                |s|         |                |
                |s|         |                |
                | |         |                |
             ---|-|---------------------------------
            |              T4 Adapter               |
            |                                       |
            |                                       |
-----PCI----|---------------------------------------|---------------------------
            |                                       |
            |                                       |
            |          Port0       Port1            |
             -----------|------------|--------------
                        |            |
                        |            |
   ------------         |            |         ------------
  |  Client A  |---------            ---------|  Client B  |
   ------------                                ------------

There are two modes of operation. Mode1 filter sniffing mode, involves
targeting specific multicast traffic and sending it directly to user space.
Mode2 wire tap mode, all tapped traffic is forwarded to user space and also
pushed back on the wire via the internal loop back mechanism. In either
mode the targeted traffic bypasses the kernel TCP/IP stack and is delivered
directly to user space via T4 filtering. Filtering does this by pushing the
packets through an RX queue which is defined by the register
MPS_TRC_RSS_CONTROL. Also to provide an accurate time we highjack some fields
in the ib_wc struct and use it to pass a HW timestamp up.

	Mode 1 (Filter Sniffing):
		A) Get a Queue (raw QP) idx
		B) Program a filter to redirect specfic traffic to the raw QP
		   queue.

	Mode 2 (wire tap):
		A) Get a Queue (raw QP) idx
		B) Set the T4 adatper in loop back
		C) connect Client A and B to ports 0 and 1
		D) Enable tracing.

================================================================================
2. Package content
================================================================================

doc:
	Where the documentation lives.

libcxgb4:
	Contains the modified code which provides the hooks to makes filter
	sniffing or wire tapping mode possible.

libpcap-1.1.1 (filtering):
	untested filtering capable libpcap-1.1.1 source code, so to be
	deprecated.

libpcap-1.1.1_trace (tracing):
	An example of how to use pcap(tcpdump) to capture packets which bypass
	the kernel stack. All we did was modify libpcap to listen on a
	predefined queue for packets.

sniffer_rdma_filter (filtering):
	An example of how to write a userspace application which will setup
	filtering and capture packets.

================================================================================
3. Known working configuration
================================================================================

Kernel: RHEL6.0
Driver: RHEL6.0 changeset 4941, but should work with anything >= 4941
OFED:	OFED-1.5.3

================================================================================
4. Installation
================================================================================

4.1 Installing basic support
---------------------------

i.	Build and install OFED-1.5.3 following its installation instructions.

ii.	Build and install cxgb4 make sure to use the makefile option OFA_DIR.
	# cd /pathto/driver/
	# ./buildall.sh OFA_DIR=/usr/src/ofa_kernel
	# cd linux_t4_build/
	# make clean
	# make OFA_DIR=/usr/src/ofa_kernel install

iii.	Getting the t4_sniffer source
	# hg clone http://willow/hg/t4_sniffer
	# cd t4_sniffer/

iv.	Build and install libcxgb4.
	# cd /pathto/t4_sniffer/libcxgb4/
	# ./autogen.sh
	# ./configure
	# make install

4.2 Installing tcpdump libpcap-1.1.1 (filtering)
-----------------------------------------------------

i.	Build and install libpcap-1.1.1
	# cd /pathto/t4_sniffer/libpcap-1.1.1/
	# ./configure LIBS=/usr/lib64/libibverbs.so.1 CFLAGS=-DCHELSIO_RDMA
	# make install

ii.	Locate libpcap.so.1 path
	# ldd /usr/sbin/tcpdump

iii.	Backup the original libpcap.so.1 file
	# mv /usr/lib64/libpcap.so.1 /usr/lib64/libpcap.so.1.bak

iv.	Add symlink libpcap.so.1 to the one you just rebuilt
	# ln -s /pathto/t4_sniffer/libpcap-1.1.1/libpcap.so.1.1.1 /usr/lib64/libpcap.so.1

4.3 Installing tcpdump libpcap-1.1.1_trace (tracing)
----------------------------------------------------------

i.	Build and install libpcap-1.1.1_trace
	# cd /pathto/t4_sniffer/libpcap-1.1.1_trace/
	# ./configure LIBS=/usr/lib64/libibverbs.so.1 CFLAGS=-DCHELSIO_RDMA
	# make install

ii.	Locate libpcap.so.1 path
	# ldd /usr/sbin/tcpdump

iii.	Backup the original libpcap.so.1 file
	# mv /usr/lib64/libpcap.so.1 /usr/lib64/libpcap.so.1.bak

iv.	Add symlink libpcap.so.1 to the one you just rebuilt
	# ln -s /pathto/t4_sniffer/libpcap-1.1.1_trace/libpcap.so.1.1.1 /usr/lib64/libpcap.so.1

4.3 Installing sample sniffer program (filtering)
------------------------------------------------------

i.	Build the sniffer.
	# cd /pathto/t4_sniffer/sniffer_rdma_filter/
	# make

================================================================================
5. How to load drivers
================================================================================

1) Load cxgb4. If installation process went fine cxgb4 should load on boot.
   # modprobe cxgb4
2) Load iw_cxgb4
   # modprobe iw_cxgb4
3) Load rdma_ucm
   # modprobe rdma_ucm

================================================================================
6. Examples
================================================================================

6.1 How to use mode 1 (filter sniffing) using sniffer_rdma_filter
-----------------------------------------------------------------

i.	Setup:
	Wire filter sniffing requires 2 PC's with one machine having a T4 card.
	The machines should be setup in the following manner:

                Machine A    <---------> Machine  B
                192.168.1.100            192.168.1.200

ii.	Procedure for setting up mode 1 (Sniff specific traffic):

	Please be sure you installed and loaded all required drivers, refer to
	the installation section of this doc.

	On the DUT start sniffer.
	# ./sniffer -T 20 -s 1000 -I <MAC address of interface to sniff>

	Start traffic on the PEER and watch the sniffer...

	sniffer gets all the packets as fast as possible, makes packet count,
	then discards data. Performance is a full 10Gbps for packet size 1000.

6.2 How to use mode 2 (wire tapping) libpcap-1.1.1_trace
--------------------------------------------------------

i.	Setup:
	Wire tapping requires 3 PC's with one machine having a T4 two ports or
	more card. The machnes should be setup in the following manner:

                            DUT: Machine  B
PEER: Machine A <-----> (port 0)        (port 1)    <-----> PEER: Machine C
192.168.1.100            IP-dont-care   IP-dont-care        192.168.1.200

ii.	Procedure for setting up mode 2 (wire tapping):

	Please be sure you installed the correct version of libpcap and load all
	required drivers, refer to the README.txt for instructions.

	Configure the DUT to loopback for port 0 to port 1 via indirect register
	the registers are TP_PIO_ADDR (0x7e40) to target the CHANNEL_MAP (0x27)
	and TP_PIO_DATA (0x7e44) to modify the mapping.

	# cxgbtool <interface> reg 0x7e40=0x27
	4 port card:
		# cxgbtool <interface> reg 0x7e44=0x3e100
	2 port card:
		# cxgbtool <interface> reg 0x7e44=0x5c500

	Turn on promiscuous for both ports

	# ifconfig <interface 0> promisc
	# ifconfig <interface 1> promisc

	Run tcpdump, it will display the Queue # it will monitor. Use that
	number to program the MPS_TRC_RSS_CONTROL[QueueNumber] which is the
	queue the tracer will be dumping packets too.

	# tcpdump -i <interface>
	interface: eth3, queue: 61

	On another xterm enable TrcEN[1:1] and TrcMultiFilter[0:0] of the
	register MPS_TRC_CFG(0x9800).

	# cxgbtool <interface> reg 0x9800=0x3

	Configure the MPS_TRC_RSS_CONTROL(0x9808) bits QueueNumber[15:0] to the
	channel# given by tcpdump "interface: <intf>, queue: <queue number>".

	# cxgbtool <interface> reg 0x9808=<queue number>

	Use the following commands to enable Tracing of the RX and TX paths.

	# echo rx0 snaplen=1000 > /sys/kernel/debug/cxgb4/<pci mapping>/trace0
	# echo tx0 snaplen=1000 > /sys/kernel/debug/cxgb4/<pci mapping>/trace1

	Try ping or ssh between machines A and B. The traffic should
	successfully make it from end to end and tcpdump on the DUT should show
	the tapped traffic.
