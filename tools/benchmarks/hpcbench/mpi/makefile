# A simple make file for MPI test
# mpitest tests the MPICH over Gigabit EtherNet interconnect
# qmpitest tests the MPICH over Quadrics interconnect 

# Compiler for MPICH based on Gigabit Ethernet interconnect
# CC = $(HOME)/mpich-1.2.5.2/bin/mpicc
# CC = /pkg/mpich-ge/bin/mpicc
CC = mpicc

# Compiler for MPICH based on Quadrics interconnect
# QCC = /usr/bin/mpicc 

all: mpitest 

mpitest: mpitest.c util.c
	$(CC) -O3 mpitest.c util.c -o mpitest 

qmpitest: mpitest.c util.c
	$(QCC) -O3 mpitest.c util.c -o qmpitest
	@rm -f ./*.o

clean: 
	rm -f *.o core 
cleanall:
	rm -f *.o *~ core mpitest qmpitest
