#############################################################
# Shell script for UDP/TCP/MPI communication tests          #
# Test communication throughputs between two nodes with     #
# different parameters such as buffer size                  #          
# Usage: "test.sh all host1 host2 [port]"                   #
# March 2004, by Ben Huang, huang@csd.uwo.ca                #
#############################################################

#!/bin/sh

# Check the arguments
if [ $# -lt 3 ]; then
	echo " UDP/TCP/MPI test script"
	echo " Usage: test.sh <protocol> host1 host2 [port-number]" 
	echo " Protocols: [udp] UDP communication tests"
	echo "            [tcp] TCP communication tests"
	echo "            [mpi] MPI communication tests"
	echo "            [all] Test all three protocols"
	echo " Example 1 : % test.sh udp gw38 gw39"
	echo " UDP communication test between \"gw38\" and \"gw39\" with default port nuumber"
	echo " Example 2 : % test.sh all gw38 gw39 2000" 
	echo " UDP/TCP/MPI Tests with port number 2000"
	exit
fi

if [ $1 != "all" ] && [ $1 != "udp" ] && [ $1 != "tcp" ] && [ $1 != "mpi" ]; then
	echo " Usage: test.sh protocol host1 host2 [port-number]" 
	echo " Porotocol must be one of the following: udp, tcp, mpi, all"
	exit
fi

###############  Customized setting  ########################

# Select the program for remotely execution
prog="ssh"
#prog="rsh"

# Set the ommunication port 
if [ -z "$4" ]; then 
	port=4000
else
	port="$4"
fi

# Define the working directory
dir=$HOME/hpcbench

# Define the executables directory
rundir=$dir/bin

# Define the data directory. 
# Results will be stored in $datadir/host1-host2
datadir=$dir/data

# Define the log directory. 
logdir=$dir/log

# Define the test time (second)
time=2

# Define the repetition of tests
repeat=10

# Process number 
proc=2

# Link to MPICH 
MPIRUN=/pkg/mpich-ge/bin/mpirun

# Link to MPI test executable
MPITEST=/home/huang/hpcbench/bin/mpitest

# Machine file name
hostfile="nodes_list"

# Define the pause time (second) for server's startup
pause=3

##############  Ending of customized setting  ###############

# Two nodes to be examined
host1="$2"
host2="$3"

# Create log directory if not existing 
# host2 might not have the same directory structure as host1
$prog $host1 "mkdir -p $datadir"
$prog $host1 "mkdir -p $datadir/$host1-$host2"
$prog $host2 "mkdir -p $datadir"
$prog $host2 "mkdir -p $datadir/$host1-$host2"

# Write the machine file
number=1
host=$hostfile
while [ -f $logdir/$host ]
    do
	host="$hostfile$number"
	number=`expr $number + 1`
done
hostfile=$host

echo "$host1" >> $logdir/$hostfile
echo "$host2" >> $logdir/$hostfile
echo "$host1 0 $MPITEST" >> $logdir/$hostfile-1
echo "$host1 1 $MPITEST" >> $logdir/$hostfile-1
echo "$host2 0 $MPITEST" >> $logdir/$hostfile-2
echo "$host2 1 $MPITEST" >> $logdir/$hostfile-2

# Clean up the machines
$prog $host1 "$rundir/killserver"
$prog $host2 "$rundir/killserver"
sleep $pause
sleep $pause

################################  UDP tests  ####################################

# Output format: 
# udp-gw10-dp10-b1m-l10k.txt : gw10 (client) --> dp10 (server), UPD fixed-size test,
# Buffer size 1 MBytes, datagram Length (packet size) 10 KBytes, data size of each sending equals the packet size.
# udp-gw10-dp10-exp-b1m-l10k.txt : gw10 (client) --> dp10 (server), UDP exponential test, 
# Data size of each sending increasing from 1 byte to the packet size.

if [ $1 = "all" ] || [ $1 = "udp" ]; then

# Start server process on both machines
$prog $host1 "$rundir/udpserver -p $port" &
$prog $host2 "$rundir/udpserver -p $port" &
sleep $pause

# Start UDP test
# Experiments = 8x3x4 = 96

for buffersize in 10k 100k 1m 10m
do
    for datagram in 1k 1460 10k
    do

	echo "Start UDP test with buffersize $buffersize and packet size $datagram"

# Inter-node fixed-size test (host2->host1)
        $prog $host2 "$rundir/udptest -ch $host1 -p $port -b $buffersize -l $datagram \
		-t $time -r $repeat -o $datadir/$host1-$host2/udp-$host2-$host1-b$buffersize-l$datagram.txt"

# Inter-node exponential test (host2->host1)
        $prog $host2 "$rundir/udptest -eP -ch $host1 -p $port -b $buffersize -l $datagram \
		-t $time -o $datadir/$host1-$host2/udp-$host2-$host1-exp-b$buffersize-l$datagram.txt"

# Intro-node fixed-size test (host1->host1)
	$prog $host1 "$rundir/udptest -ch $host1 -p $port -b $buffersize -l $datagram \
		 -t $time -r $repeat -o $datadir/$host1-$host2/udp-$host1-$host1-b$buffersize-l$datagram.txt"

# Intro-node exponential test (host1->host1)
	$prog $host1 "$rundir/udptest -eP -ch $host1 -p $port -b $buffersize -l $datagram \
		-t $time -o $datadir/$host1-$host2/udp-$host1-$host1-exp-b$buffersize-l$datagram.txt"
	
# Inter-node fixed-size test (host1->host2)
	$prog $host1 "$rundir/udptest -ch $host2 -p $port -b $buffersize -l $datagram \
		-t $time -r $repeat -o $datadir/$host1-$host2/udp-$host1-$host2-b$buffersize-l$datagram.txt"

# Inter-node exponential test (host1->host2)
	$prog $host1 "$rundir/udptest -eP -ch $host2 -p $port -b $buffersize -l $datagram \
		-t $time -o $datadir/$host1-$host2/udp-$host1-$host2-exp-b$buffersize-l$datagram.txt"

# Intro-node fixed-size test (host2->host2)
	$prog $host2 "$rundir/udptest -ch $host2 -p $port -b $buffersize -l $datagram \
		-t $time -r $repeat -o $datadir/$host1-$host2/udp-$host2-$host2-b$buffersize-l$datagram.txt"

# Intro-node exponential test (host2->host2)
	$prog $host2 "$rundir/udptest -eP -ch $host2 -p $port -b $buffersize -l $datagram \
		-t $time -o $datadir/$host1-$host2/udp-$host2-$host2-exp-b$buffersize-l$datagram.txt"
    done
done

# Kill server process
$prog $host1 "$rundir/killserver"
$prog $host2 "$rundir/killserver"
sleep $pause
sleep $pause

echo " UDP tests done!"

fi

######################################  TCP tests  #############################

# Output format: 
# tcp-gw10-dp10-sb-b10k-m100m.txt : gw10 (client) --> dp10 (server), fixed-size test,
# TCP communication, Stream and Blocking mode, Buffer size 10Kbytes, Message size 100 Mbytes.
# tcp-gw10-dp10-exp-sn-b10k.txt : gw10 (client) --> dp10 (server), exponential tests,
# Stream, non-blocking tests, buffer size 10K, message size increasing exponentially.

if [ $1 = "all" ] || [ $1 = "tcp" ]; then

# Start server process in both machines
$prog $host1 "$rundir/tcpserver -p $port" &
$prog $host2 "$rundir/tcpserver -p $port" &
sleep $pause  

########################### TCP blocking communication ##########################
########################### Stream and pingpong tests  ##########################
# Experiments: (5x8+8)x4=192

for buffersize in 10k 100k 1m 10m
do
    for msgsize in 10k 100k 1m 10m 100m
    do
	echo " Start blocking tests with buffer size: $buffersize  message size: $msgsize"

# Inter-node test (host2->host1) (Stream and pingpong tests)
       	$prog $host2 "$rundir/tcptest -ch $host1 -p $port -b $buffersize -m $msgsize \
		-t $time -r $repeat -o $datadir/$host1-$host2/tcp-$host2-$host1-sb-b$buffersize-m$msgsize.txt" 
       	$prog $host2 "$rundir/tcptest -ih $host1 -p $port -b $buffersize -m $msgsize \
		-t $time -r $repeat -o $datadir/$host1-$host2/tcp-$host2-$host1-pb-b$buffersize-m$msgsize.txt" 

# Inter-node test (host1->host2)
       	$prog $host1 "$rundir/tcptest -ch $host2 -p $port -b $buffersize -m $msgsize \
		-t $time -r $repeat -o $datadir/$host1-$host2/tcp-$host1-$host2-sb-b$buffersize-m$msgsize.txt"
       	$prog $host1 "$rundir/tcptest -ih $host2 -p $port -b $buffersize -m $msgsize \
		-t $time -r $repeat -o $datadir/$host1-$host2/tcp-$host1-$host2-pb-b$buffersize-m$msgsize.txt"

# Intra-node test (host1->host1)
	$prog $host1 "$rundir/tcptest -ch $host1 -p $port -b $buffersize -m $msgsize \
		-t $time -r $repeat -o $datadir/$host1-$host2/tcp-$host1-$host1-sb-b$buffersize-m$msgsize.txt"
	$prog $host1 "$rundir/tcptest -ih $host1 -p $port -b $buffersize -m $msgsize \
		-t $time -r $repeat -o $datadir/$host1-$host2/tcp-$host1-$host1-pb-b$buffersize-m$msgsize.txt"

# Intra-node test (host2->host2)
       	$prog $host2 "$rundir/tcptest --ch $host2 -p $port -b $buffersize -m $msgsize \
		-t $time -r $repeat -o $datadir/$host1-$host2/tcp-$host2-$host2-sb-b$buffersize-m$msgsize.txt" 
       	$prog $host2 "$rundir/tcptest -ih $host2 -p $port -b $buffersize -m $msgsize \
		-t $time -r $repeat -o $datadir/$host1-$host2/tcp-$host2-$host2-pb-b$buffersize-m$msgsize.txt" 

    done

# Exponential test with maximum size of 64M (2^26)	

	echo " Start blocking exponential test with buffer size: $buffersize"

# Intro-node test (host1->host1) (Stream and pingpong tests)
	$prog $host1 "$rundir/tcptest -e 26 -P -ch $host1 -p $port -b $buffersize -t $time \
		-o $datadir/$host1-$host2/tcp-$host1-$host1-exp-sb-b$buffersize.txt"
	$prog $host1 "$rundir/tcptest -e 26 -iP -ch $host1 -p $port -b $buffersize -t $time \
		-o $datadir/$host1-$host2/tcp-$host1-$host1-exp-pb-b$buffersize.txt"

# Intro-node test (host2->host2)
	$prog $host2 "$rundir/tcptest -e 26 -P -ch $host2 -p $port -b $buffersize -t $time \
		-o $datadir/$host1-$host2/tcp-$host2-$host2-exp-sb-b$buffersize.txt"
	$prog $host2 "$rundir/tcptest -e 26 -iP -ch $host2 -p $port -b $buffersize -t $time \
		-o $datadir/$host1-$host2/tcp-$host2-$host2-exp-pb-b$buffersize.txt"

# Inter-node test (host1->host2)
	$prog $host1 "$rundir/tcptest -e 26 -P -ch $host2 -p $port -b $buffersize -t $time \
		-o $datadir/$host1-$host2/tcp-$host1-$host2-exp-sb-b$buffersize.txt"
	$prog $host1 "$rundir/tcptest -e 26 -iP -ch $host2 -p $port -b $buffersize -t $time \
		-o $datadir/$host1-$host2/tcp-$host1-$host2-exp-pb-b$buffersize.txt"

# Inter-node test (host2->host1)
	$prog $host2 "$rundir/tcptest -e 26 -P -ch $host1 -p $port -b $buffersize -t $time \
		-o $datadir/$host1-$host2/tcp-$host2-$host1-exp-sb-b$buffersize.txt"
	$prog $host2 "$rundir/tcptest -e 26 -iP -ch $host1 -p $port -b $buffersize -t $time \
		-o $datadir/$host1-$host2/tcp-$host2-$host1-exp-pb-b$buffersize.txt"

done

######################## TCP non-blocking communication ########################
#################### Single and bidirectional stream test ######################
# Experiments: (5x8+8)x4=192

for buffersize in 10k 100k 1m 10m
do 
    for msgsize in 10k 100k 1m 10m 100m
do
	echo " Start non-blocking tests with buffer size: $buffersize  message size: $msgsize"

# Inter-node test (host2->host1)
       	$prog $host2 "$rundir/tcptest -n -ch $host1 -p $port -b $buffersize -m $msgsize \
		-t $time -r $repeat -o $datadir/$host1-$host2/tcp-$host2-$host1-sn-b$buffersize-m$msgsize.txt" 
       	$prog $host2 "$rundir/tcptest -in -ch $host1 -p $port -b $buffersize -m $msgsize \
		-t $time -r $repeat -o $datadir/$host1-$host2/tcp-$host2-$host1-pn-b$buffersize-m$msgsize.txt" 

# Inter-node test (host1->host2)
       	$prog $host1 "$rundir/tcptest -n -ch $host2 -p $port -b $buffersize -m $msgsize \
		-t $time -r $repeat -o $datadir/$host1-$host2/tcp-$host1-$host2-sn-b$buffersize-m$msgsize.txt"
       	$prog $host1 "$rundir/tcptest -in -ch $host2 -p $port -b $buffersize -m $msgsize \
		-t $time -r $repeat -o $datadir/$host1-$host2/tcp-$host1-$host2-pn-b$buffersize-m$msgsize.txt"

# Intra-node test (host1->host1)
       	$prog $host1 "$rundir/tcptest -n -ch $host1 -p $port -b $buffersize -m $msgsize \
		-t $time -r $repeat -o $datadir/$host1-$host2/tcp-$host1-$host1-sn-b$buffersize-m$msgsize.txt"
       	$prog $host1 "$rundir/tcptest -in -ch $host1 -p $port -b $buffersize -m $msgsize \
		-t $time -r $repeat -o $datadir/$host1-$host2/tcp-$host1-$host1-pn-b$buffersize-m$msgsize.txt"

# Intra-node test (host2->host2)
	$prog $host2 "$rundir/tcptest -n -ch $host2 -p $port -b $buffersize -m $msgsize \
		-t $time -r $repeat -o $datadir/$host1-$host2/tcp-$host2-$host2-sn-b$buffersize-m$msgsize.txt" 
	$prog $host2 "$rundir/tcptest -in -ch $host2 -p $port -b $buffersize -m $msgsize \
		-t $time -r $repeat -o $datadir/$host1-$host2/tcp-$host2-$host2-pn-b$buffersize-m$msgsize.txt" 
    done

# Exponential test (Maximum size 64MB)
	echo " Start non-blocking exponential test with buffer size: $buffersize"

	$prog $host1 "$rundir/tcptest -e 25 -nP -ch $host1 -p $port -b $buffersize -t $time \
		-o $datadir/$host1-$host2/tcp-$host1-$host1-exp-sn-b$buffersize.txt"
	$prog $host1 "$rundir/tcptest -e 25 -inP -ch $host1 -p $port -b $buffersize -t $time \
		-o $datadir/$host1-$host2/tcp-$host1-$host1-exp-pn-b$buffersize.txt"

	$prog $host1 "$rundir/tcptest -e 25 -nP -ch $host2 -p $port -b $buffersize -t $time \
		-o $datadir/$host1-$host2/tcp-$host1-$host2-exp-sn-b$buffersize.txt"
	$prog $host1 "$rundir/tcptest -e 25 -inP -ch $host2 -p $port -b $buffersize -t $time \
		-o $datadir/$host1-$host2/tcp-$host1-$host2-exp-pn-b$buffersize.txt"
    
	$prog $host2 "$rundir/tcptest -e 25 -nP -ch $host1 -p $port -b $buffersize -t $time \
		-o $datadir/$host1-$host2/tcp-$host2-$host1-exp-sn-b$buffersize.txt"
	$prog $host2 "$rundir/tcptest -e 25 -inP -ch $host1 -p $port -b $buffersize -t $time \
		-o $datadir/$host1-$host2/tcp-$host2-$host1-exp-pn-b$buffersize.txt"

	$prog $host2 "$rundir/tcptest -e 25 -nP -ch $host2 -p $port -b $buffersize -t $time \
		-o $datadir/$host1-$host2/tcp-$host2-$host2-exp-sn-b$buffersize.txt"
	$prog $host2 "$rundir/tcptest -e 25 -inP -ch $host2 -p $port -b $buffersize -t $time \
		-o $datadir/$host1-$host2/tcp-$host2-$host2-exp-pn-b$buffersize.txt"

done

# Kill the server processes
$prog $host1 "$rundir/killserver"
$prog $host2 "$rundir/killserver"
sleep $pause

echo " TCP tests done!"

fi

#################################  MPI tests  ###################################

if [ $1 = "all" ] || [ $1 = "mpi" ]; then

# Blocking communication test

for size in 10k 100k 1m 10m; do
# Two nodes cross two machines (stream and pingpong tests)
	$MPIRUN -np $proc -machinefile $logdir/$hostfile $MPITEST -c \
	    -r $repeat -t $time -m $size -o $datadir/$host1-$host2/mpi-$host1-$host2-sb-$size.txt
	wait
	$MPIRUN -np $proc -machinefile $logdir/$hostfile $MPITEST -i -c\
	    -r $repeat -t $time -m $size -o $datadir/$host1-$host2/mpi-$host1-$host2-pb-$size.txt
	wait
# Two nodes inside one machine
	echo "$MPIRUN -p4pg $logdir/$hostfile-1 $MPITEST -c \
	    -r $repeat -t $time -m $size -o $datadir/$host1-$host2/mpi-$host1-$host1-sb-$size.txt"
	$prog $host1 "$MPIRUN -p4pg $logdir/$hostfile-1 $MPITEST -c \
	    -r $repeat -t $time -m $size -o $datadir/$host1-$host2/mpi-$host1-$host1-sb-$size.txt"
	wait
	$prog $host1 "$MPIRUN -p4pg $logdir/$hostfile-1 $MPITEST -i -c \
	    -r $repeat -t $time -m $size -o $datadir/$host1-$host2/mpi-$host1-$host1-pb-$size.txt"
	wait
	$prog $host2 "$MPIRUN -p4pg $logdir/$hostfile-2 $MPITEST -c \
	    -r $repeat -t $time -m $size -o $datadir/$host1-$host2/mpi-$host2-$host2-sb-$size.txt"
	wait
	$prog $host2 "$MPIRUN -p4pg $logdir/$hostfile-2 $MPITEST -i -c \
	    -r $repeat -t $time -m $size -o $datadir/$host1-$host2/mpi-$host2-$host2-pb-$size.txt"
	wait
done

# Exponential test (blocking, Maximum size 128MB)
$MPIRUN -np $proc -machinefile $logdir/$hostfile $MPITEST -c \
	-P -e 26 -t $time -o $datadir/$host1-$host2/mpi-$host1-$host2-sb-exp.txt
wait 
$MPIRUN -np $proc -machinefile $logdir/$hostfile $MPITEST -c \
	-iP -e 26 -t $time -o $datadir/$host1-$host2/mpi-$host1-$host2-pb-exp.txt
wait
$prog $host1 "$MPIRUN -p4pg $logdir/$hostfile-1 $MPITEST -c \
	-P -e 26 -t $time -o $datadir/$host1-$host2/mpi-$host1-$host1-sb-exp.txt"
wait
$prog $host1 "$MPIRUN -p4pg $logdir/$hostfile-1 $MPITEST -c \
	-iP -e 26 -t $time -o $datadir/$host1-$host2/mpi-$host1-$host1-pb-exp.txt"
wait
$prog $host2 "$MPIRUN -p4pg $logdir/$hostfile-2 $MPITEST -c \
	-P -e 26 -t $time -o $datadir/$host1-$host2/mpi-$host2-$host2-sb-exp.txt"
wait
$prog $host2 "$MPIRUN -p4pg $logdir/$hostfile-2 $MPITEST -c \
	-iP -e 26 -t $time -o $datadir/$host1-$host2/mpi-$host2-$host2-pb-exp.txt"
wait

# Non-blocking communication tests

for size in 10k 100k 1m 10m; do
# Two nodes cross two machines (stream and pingpong tests)
	$MPIRUN -np $proc -machinefile $logdir/$hostfile $MPITEST -cn \
	    -r $repeat -t $time -m $size -o $datadir/$host1-$host2/mpi-$host1-$host2-sn-$size.txt
	wait
	$MPIRUN -np $proc -machinefile $logdir/$hostfile $MPITEST -i -cn\
	    -r $repeat -t $time -m $size -o $datadir/$host1-$host2/mpi-$host1-$host2-pn-$size.txt
	wait
# Two nodes inside one machine
	$prog $host1 "$MPIRUN -p4pg $logdir/$hostfile-1 $MPITEST -cn \
	    -r $repeat -t $time -m $size -o $datadir/$host1-$host2/mpi-$host1-$host1-sn-$size.txt"
	wait
	$prog $host1 "$MPIRUN -p4pg $logdir/$hostfile-1 $MPITEST -i -cn \
	    -r $repeat -t $time -m $size -o $datadir/$host1-$host2/mpi-$host1-$host1-pn-$size.txt"
	wait
	$prog $host2 "$MPIRUN  -p4pg $logdir/$hostfile-2 $MPITEST -cn \
	    -r $repeat -t $time -m $size -o $datadir/$host1-$host2/mpi-$host2-$host2-sn-$size.txt"
	wait
	$prog $host2 "$MPIRUN -p4pg $logdir/$hostfile-2 $MPITEST -i -cn \
	    -r $repeat -t $time -m $size -o $datadir/$host1-$host2/mpi-$host2-$host2-pn-$size.txt"
	wait
done

# Exponential test (non-blocking, Maximum size 128MB)
$MPIRUN -np $proc -machinefile $logdir/$hostfile $MPITEST -cn \
	-P -e 26 -t $time -o $datadir/$host1-$host2/mpi-$host1-$host2-sn-exp.txt
wait 
$MPIRUN -np $proc -machinefile $logdir/$hostfile $MPITEST -cn \
	-iP -e 26 -t $time -o $datadir/$host1-$host2/mpi-$host1-$host2-pn-exp.txt
wait
$prog $host1 "$MPIRUN -p4pg $logdir/$hostfile-1 $MPITEST -cn \
	-P -e 26 -t $time -o $datadir/$host1-$host2/mpi-$host1-$host1-sn-exp.txt"
wait
$prog $host1 "$MPIRUN -p4pg $logdir/$hostfile-1 $MPITEST -cn \
	-iP -e 26 -t $time -o $datadir/$host1-$host2/mpi-$host1-$host1-pn-exp.txt"
wait
$prog $host2 "$MPIRUN -p4pg $logdir/$hostfile-2 $MPITEST -cn \
	-P -e 26 -t $time -o $datadir/$host1-$host2/mpi-$host2-$host2-sn-exp.txt"
wait
$prog $host2 "$MPIRUN -p4pg $logdir/$hostfile-2 $MPITEST -cn \
	-iP -e 26 -t $time -o $datadir/$host1-$host2/mpi-$host2-$host2-pn-exp.txt"
wait

echo " MPI tests done!"

fi

# Clean up the machine file
rm -f $logdir/$hostfile
rm -f $logdir/$hostfile-1
rm -f $logdir/$hostfile-2

echo " Quit..."
