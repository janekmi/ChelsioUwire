LIBCXGB4_DIR := libcxgb4
T4_SNIFFER_DIR := sniffer_rdma_filter
LIBPCAP_FILTER_DIR := libpcap-1.1.1
LIBPCAP_TRACE_DIR := libpcap-1.1.1_trace
TCPDUMP_DIR := tcpdump-4.1.1
ARCH := $(shell uname -m)
LIBDIR :=

ifneq ($(wildcard /usr/bin/dpkg),)
 LIBDIR := /usr/lib
else
 ifeq ($(ARCH), x86_64)
  LIBDIR := /usr/lib64
 else
  LIBDIR := /usr/lib
 endif
endif

.PHONY: all
all: default

clean:
	@echo "***********************************************************************"
	@echo "Clean libpcap-1.1.1, libpcap-1.1.1_trace and tcpdump 4.1.1  directories"
	@echo "***********************************************************************\n"
	-cd $(shell pwd)/$(T4_SNIFFER_DIR); make clean;
	-cd $(shell pwd)/$(LIBPCAP_FILTER_DIR); make clean;
	-cd $(shell pwd)/$(LIBPCAP_TRACE_DIR); make clean;
	-cd $(shell pwd)/$(TCPDUMP_DIR); make clean;

default:
	@echo "\n******************************"
	@echo "Building libcxgb4"
	@echo "********************************\n"
	cd $(shell pwd)/$(LIBCXGB4_DIR); ./autogen.sh;\
		./configure --libdir=$(LIBDIR) --sysconfdir=/etc --prefix=/usr;\
		make install;
	@echo "\n********************************************"
	@echo "Building libcap-1.1.1 filtering and wd_tcpdump"
	@echo "**********************************************\n"
	cd $(shell pwd)/$(LIBPCAP_FILTER_DIR); ./configure LIBS=$(LIBDIR)/libibverbs.so.1 CFLAGS=-DCHELSIO_RDMA; make;
	cd $(shell pwd)/$(TCPDUMP_DIR); ./configure; make; mv tcpdump wd_tcpdump;
	@echo "\n**********************************************"
	@echo "Building libpap-1.1.1_trace and wd_tcpdump_trace"
	@echo "************************************************\n"
	cd $(shell pwd)/$(LIBPCAP_TRACE_DIR); ./configure LIBS=$(LIBDIR)/libibverbs.so.1 CFLAGS=-DCHELSIO_RDMA; make;
	cd $(shell pwd)/$(TCPDUMP_DIR); ./configure; make; mv tcpdump wd_tcpdump_trace;
	@echo "\n************************"
	@echo "Building T4 sniffer binary"
	@echo "**************************\n"
	cd $(shell pwd)/$(T4_SNIFFER_DIR); make;

install:
	cp ./tcpdump-4.1.1/wd_tcpdump_trace /usr/sbin
	cp ./tcpdump-4.1.1/wd_tcpdump /usr/sbin
	cp ./sniffer_rdma_filter/sniffer /usr/sbin

