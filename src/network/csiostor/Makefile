# Makefile for Chelsio T4 Storage driver.
# Copyright (c) 2006-2009 Chelsio Communications, Inc.
SHELL = /bin/bash

# The top-level makefile defines required variables and flags.
ifneq ($(shell [[ $(MAKELEVEL) -ge 1 ]] && echo 1),1)
  $(error Please use the top-level Makefile to build this driver)
endif

# Includes.
EXTRA_CFLAGS += $(FLAGS)
#EXTRA_CFLAGS += -D__CSIO_DEBUG_VERBOSE__
ifeq ($(DEBUG),1)
EXTRA_CFLAGS += -D__CSIO_DEBUG__
EXTRA_CFLAGS += -D__CSIO_BRINGUP__
EXTRA_CFLAGS += -D__CSIO_TRACE_SUPPORT__
EXTRA_CFLAGS += -D__CSIO_SCSI_PERF__
#EXTRA_CFLAGS += -DCSIO_DATA_CAPTURE
#EXTRA_CFLAGS += -D__CSIO_DIE_NOTIFY__
endif

#Flag __CSIO_FOISCSI_ENABLED__ is added temporarily to
#enable FOiSCSI. It will be removed after one pass of QA
#has been done on csiostor tot.
EXTRA_CFLAGS += -D__CSIO_FOISCSI_ENABLED__
EXTRA_CFLAGS += -D__CSIO_DDP_SUPPORT__
# Unlike make storage, when no targets are defined, 
# we need to filter out MA to avoid load failure 
EXTRA_CFLAGS := $(filter-out -DCONFIG_T4_MA_FAILOVER,$(EXTRA_CFLAGS))
EXTRA_CFLAGS := $(filter-out -DT4_TRACE,$(EXTRA_CFLAGS))
EXTRA_CFLAGS += -I$(KSRC)/include
EXTRA_CFLAGS += -I$(srcdir)/csiostor/include

CFILES  = csio_os_dfs.c t4_linux_debugfs.c csio_oss.c csio_scsi.c csio_hw.c \
	  csio_mb.c csio_os_fcoe.c csio_os_scsi.c csio_rnf_cofld.c csio_wr.c \
	  csio_lnf_cofld.c csio_mb_helpers.c csio_os_init.c \
	  csio_rnode.c csio_lnode.c csio_mgmt.c csio_os_isr.c \
	  t4_hw.c
ifeq ($(filter -D__CSIO_FOISCSI_ENABLED__, $(EXTRA_CFLAGS)), -D__CSIO_FOISCSI_ENABLED__)
  CFILES += csio_trans_foiscsi.c csio_os_transch_foiscsi.c csio_ctrl_foiscsi.c \
            csio_os_foiscsi.c csio_foiscsi.c csio_lnode_foiscsi.c \
            csio_rnode_foiscsi.c csio_mb_foiscsi.c
  ifneq (,$(filter $(ARCH), x86_64 i386 i686))
    CFILES += csio_ibft.c csio_persistent.c
    EXTRA_CFLAGS += -DCSIO_FOISCSI_PERSISTENT_ENABLE
  endif
endif

BUILD_TARGET  = csiostor.o
CLEAN_FILES := $(wildcard *.c)
CLEAN_FILES := $(CLEAN_FILES:.c=.o)

lib_path     := $(PREFIX)/lib/modules/$(utsrelease)
module_path   = updates/drivers/scsi/csiostor
install_path := $(lib_path)/$(module_path)
old_install_path := $(lib_path)/updates/kernel/drivers/scsi/csiostor
udev_path := /lib/udev

ifeq ($(kseries),2.4)
  $(error Storage offload driver is not supported on 2.4 series kernel)
  driver := $(BUILD_TARGET)
  $(BUILD_TARGET): $(filter-out $(BUILD_TARGET),$(CFILES:.c=.o))
        $(LD) -r $^ -o $@
else
  driver := $(BUILD_TARGET:.o=.ko)
endif

ifneq ($(modulesymfile),)
  override symverfile = symverfile="$(topdir)/$(modulesymfile) \
                                    -o $(drvdir)/$(modulesymfile)"
else
  override symverfile =
endif

obj-m := $(BUILD_TARGET)
$(BUILD_TARGET:.o=)-objs := $(CFILES:.c=.o)

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
	@-if [ -d $(udev_path)/rules.d ] ; then \
	  install -m 744 udev/path_chelsio_id $(udev_path)/path_chelsio_id; \
	  install -m 644 udev/30-chelsio-storage.rules $(udev_path)/rules.d/30-chelsio-storage.rules; \
	fi;

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
	@-if [ -d $(udev_path)/rules.d ] ; then \
	  /bin/rm -f $(udev_path)/path_chelsio_id \
	  $(udev_path)/rules.d/30-chelsio-storage.rules  2>/dev/null ; \
	fi;

.PHONY: clean
clean:
	-/bin/rm -rf $(driver) $(BUILD_TARGET) $(BUILD_TARGET:.o=.mod.c) \
	             $(BUILD_TARGET:.o=.mod.o) $(CLEAN_FILES) \
		     .*cmd .tmp_versions *.symvers
