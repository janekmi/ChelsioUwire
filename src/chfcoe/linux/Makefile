################################################################################
# Makefile for Chelsio Partial Offload FCoE linux drivers.                     #
#                                                                              #
# Copyright (C) 2015 Chelsio Communications.                                   #
#                                                                              #
################################################################################

#
# Usage:
# 	"make initiator=1" - builds initiator only
# 	"make target=1"    - builds target only
# 	"make"             - builds both target & initiator
# 	make KDIR=<path_to_source> - if source differs from current path.
#

SHELL = /bin/sh

CURRDIR = $(shell pwd)
KERNELRELEASE := $(shell uname -r)

ifeq ($(KDIR),)
	KDIR ?= /lib/modules/$(KERNELRELEASE)/build
else
	override KDIR := $(shell cd $(KDIR) && pwd)
endif

KERNEL_INC = $(KDIR)/include

ifeq ($(DEBUG),1)
 DBG := y
else
 DBG :=
endif

ifeq ($(initiator),1)
 INIT := y
 TGT :=
else
 override INIT := y
endif

ifeq ($(CXGB4_SRC_PATH),)
      $(error Please provide CXGB4_SRC_PATH)
endif

ifeq ($(CSIOSTOR_SRC_PATH),)
      $(error Please provide CSIOSTOR_SRC_PATH)
endif

ifeq ($(FIRMWARE_PATH),)
      $(error Please provide FIRMWARE_PATH)
endif

ifeq ($(target),1)
 INIT := y
 TGT := y
 SCST_INC ?= /usr/local/include/scst
 ifeq ($(wildcard $(SCST_INC)),)
      SCST_INC1 ?= /usr/include/scst
      ifeq ($(wildcard $(SCST_INC1)),)
          $(error Please install scst before compiling this driver.)
      endif
      SCST_INC = $(SCST_INC1)
 endif
 SCST_MOD_VERS := $(SCST_INC)/Module.symvers
 CXGB4_MOD_VERS := $(CXGB4_SRC_PATH)/Module.symvers
 ifeq ($(wildcard $(CXGB4_MOD_VERS)),)
      $(error Please compile cxgb4 before compiling this driver.)
 endif
endif

export KERNEL_INC
export SCST_INC
export INIT
export TGT
export DBG
export CXGB4_SRC_PATH
export CSIOSTOR_SRC_PATH
export FIRMWARE_PATH

obj-m := chfcoe.o

default: symver build

symver:
	@if [ "$(TGT)" = "y" ]; then \
	  rm -f Module.symvers; \
	  cat $(SCST_MOD_VERS) $(CXGB4_MOD_VERS) > ./Module.symvers; \
	fi;

build:
	make -f Makefile_private
	$(MAKE) -C $(KDIR) M=$(CURRDIR) modules

install:
	$(MAKE) -C $(KDIR) M=$(CURRDIR) modules_install
	@depmod -A
	@mkdir -p /etc/chelsio-fcoe/
	@echo "Chelsio POFCOE driver installed successfully"

uninstall:
	@rm -f /lib/modules/$(KERNELRELEASE)/extra/chfcoe.ko
	@depmod 
	@echo "Chelsio POFCOE driver uninstalled successfully"
	
clean:
	make -f Makefile_private clean
	$(MAKE) -C $(KDIR) M=$(CURRDIR) clean
	@rm -rf ../common/*.o ../target/*.o ../target/.*.o.cmd

help:
	@echo "Build Options:";\
	echo " KDIR=<path>       - Kernel build and source path.";\
	echo " DEBUG=1           - Enable debugging and tracing.";\
	echo " target=1          - Builds CHFCOE Target driver.";\
	echo " initiator=1       - Builds CHFCOE Initiator driver.";\
	echo " Just 'make'       - Builds both Target & Initiator driver.";\
	echo;
