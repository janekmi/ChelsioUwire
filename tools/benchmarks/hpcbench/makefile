# A simple make file for hpcbench tool 
# Created on Jan. 23, 2004 by Ben Huang hben@users.sf.net

# Tested in Linux system. 
# For SunOS, uncomment the "LIB = -lsocket -lnsl" line in the 
# makefile in udp/tcp/mpi dirctories.

UDPDIR = udp
TCPDIR = tcp
MPIDIR = mpi
SYSDIR = sys
BINDIR = bin 

all:
	@echo; (cd $(SYSDIR); make); 
	@echo; (cd $(UDPDIR); make all); 
	@echo; (cd $(TCPDIR); make all); 
	@echo; (cd $(MPIDIR); make all); 
tcp:
	@echo; (cd $(TCPDIR); make all); 
udp:
	@echo; (cd $(UDPDIR); make all); 
mpi:
	@echo; (cd $(MPIDIR); make all); 
sysmon:
	@echo; (cd $(SYSDIR); make); 
debug:
	@echo; (cd $(UDPDIR); make debug); 
	@echo; (cd $(TCPDIR); make debug); 
udpdebug: 
	@echo; (cd $(UDPDIR); make debug); 
tcpdebug:
	@echo; (cd $(TCPDIR); make debug) 
clean: 
	cd $(UDPDIR); make clean
	cd $(TCPDIR); make clean
	cd $(MPIDIR); make clean
cleanall:
	cd $(UDPDIR); make cleanall
	cd $(TCPDIR); make cleanall
	cd $(MPIDIR); make cleanall
	cd $(SYSDIR); make cleanall
	cd $(BINDIR); rm -f *test sysmon tcpserver udpserver
