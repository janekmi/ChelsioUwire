#############################################################
# Shell script for MPI communication tests                  #
# Test MPI communication between two nodes                  #
# Use "test-mpi.sh host1 host2" to start the tests          #
# March 2004, by Ben Huang, huang@csd.uwo.ca                #
#############################################################

#!/bin/sh

# Check the arguments
if [ $# -lt 2 ]; then
	echo " Usage: test-mpi.sh host1 host2" 
	echo " Example 1 : % test-mpi.sh gw38 gw39"
	echo " MPI communication tests between \"gw38\" (Master node) and \"gw39\" (Secondary node)"
	exit
fi

# Process number
proc=2

# Working directory
rundir=$HOME/hpcbench

# Program for the tests
prog=mpitest

# Link to MPICH
mpirun=/pkg/mpich-ge/bin/mpirun

# Define the test time (Seconds)
time=1

# Define the repetition of tests
repeat=10

# Nodes name
host1=$1
host2=$2

# Define log directory
# Results will be stored in $logdir/host1-host2/
logdir=$rundir/data

# Create the log directory if not existing
mkdir -p $logdir
mkdir -p $logdir/$host1-$host2

# Machine file name
hostfile="nodes_list"

# Write the machine file
number=1
host=$hostfile
while [ -f $rundir/$host ]
    do
	host="$hostfile$number"
	number=`expr $number + 1`
done
hostfile=$host

echo "$host1" >> $rundir/$hostfile
echo "$host2" >> $rundir/$hostfile

####### Start to test  #######

# Fixed size test
for size in 10k 100k 100k 1m
do
	$mpirun -np $proc -machinefile $rundir/$hostfile $rundir/mpi/$prog \
	    -sp -r $repeat -t $time -m $size -o $logdir/$host1-$host2/mpi-$size.txt
	wait
done

# Exponential test
$mpirun -np $proc -machinefile $rundir/$hostfile $rundir/mpi/$prog \
	-sp -e 27 -t $time -o $logdir/$host1-$host2/mpi-exp.txt
wait

# Clean up the machine file
rm -f $rundir/$hostfile

echo " MPI tests done!"
