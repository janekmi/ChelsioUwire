# Makefile for Chelsio T4 cxgb4 driver.
# Copyright (c) 2006-2009 Chelsio Communications, Inc.
SHELL = /bin/bash

# The top-level makefile defines required variables and flags.
ifneq ($(shell [[ $(MAKELEVEL) -ge 1 ]] && echo 1),1)
  $(error Please use the top-level Makefile to build this driver)
endif

# Includes.
EXTRA_CFLAGS += $(FLAGS)
EXTRA_CFLAGS += -I$(srcdir)/include
EXTRA_CFLAGS += -I$(KSRC)/drivers/net/bonding
EXTRA_CFLAGS += -I$(KSRC)/include
EXTRA_CFLAGS += -I.
EXTRA_CFLAGS += -I$(srcdir)/cxgb4
EXTRA_CFLAGS += -I$(srcdir)/cudbg_inc

CFILES  = cxgb4_main.c l2t.c clip_tbl.c cxgb4_ethtool.c cxgb4_cxgbtool.c cxgb4_filter.c cxgb4_debugfs.c t4_hw.c t4_linux_debugfs.c sge.c trace.c smt.c srq.c cxgb4_ptp.c

ifneq ($(disable_cudbg), 1)
  CFILES += cxgb4_cudbg.c fastlz_api.c fastlz.c cudbg_lib.c cudbg_wtp.c cudbg_flash_utils.c cudbg_common.c
endif

ifneq ($(disable_offload),1)
  CFILES += ocqp.c
endif

ifeq ($(enable_dcb),1)
  CFILES += cxgb4_dcb.c
endif

ifeq ($(enable_bypass),1)
  CFILES +=  t4_bypass.c bypass_sysfs.c
  EXTRA_CFLAGS += -DCONFIG_CHELSIO_BYPASS
endif

ifeq ($(po_fcoe),1)
  CFILES += cxgb4_fcoe.c
endif

ifneq ($(disable_mafo),1)
    CFILES += cxgb4_ma_failover.c
endif

ifeq ($(filter $(EXTRA_CFLAGS),-DGEN_ALLOC),)
  CFILES += cxgb4_genalloc.c
endif

TARGET  = cxgb4.o
CLEAN_FILES := $(wildcard *.c)
CLEAN_FILES := $(CLEAN_FILES:.c=.o)

lib_path     := $(PREFIX)/lib/modules/$(utsrelease)
module_path   = updates/drivers/net/cxgb4
install_path := $(lib_path)/$(module_path)
old_install_path := $(lib_path)/updates/kernel/drivers/net/cxgb4

driver := $(TARGET:.o=.ko)

ifneq ($(modulesymfile),)
  override symverfile = symverfile="$(topdir)/$(modulesymfile) \
                                    -o $(drvdir)/$(modulesymfile)"
else
  override symverfile =
endif

obj-m := $(TARGET)
$(TARGET:.o=)-objs := $(CFILES:.c=.o)

.SUFFIXES:
.SUFFIXES: .c .o

.PHONY: default
default: prep build

.PHONY: prep
prep:

.PHONY: build
build:
	@$(MAKE) $(symverfile) -C $(KOBJ) SUBDIRS=$(shell pwd) modules

.PHONY: install
install:
	@-if [ -e "$(old_install_path)/$(driver)" ]; then \
		echo "* Removing old driver at $(old_install_path)/$(driver)"; \
		/bin/rm -f "$(old_install_path)/$(driver)"; \
	fi;
	@install -D $(verbose) -m 644 $(driver) $(install_path)/$(driver)

.PHONY: uninstall
uninstall:
	@-if [ -n "$(verbose)" ]; then \
	    echo "Removing $(install_path)/$(driver)";\
		if [ -e "$(old_install_path)/$(driver)" ]; then \
		    echo "Removing $(old_install_path)/$(driver)";\
		fi; \
	  fi;\
	  /bin/rm -f "$(install_path)/$(driver)"; \
	  /bin/rm -f "$(old_install_path)/$(driver)";

.PHONY: clean
clean:
	-/bin/rm -rf $(driver) $(TARGET) $(TARGET:.o=.mod.c) \
	             $(TARGET:.o=.mod.o) $(CLEAN_FILES) \
		     .*cmd .tmp_versions *.symvers
