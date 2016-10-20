# Makefile for Chelsio T4 bonding driver.
# Copyright (c) 2009 Chelsio Communications, Inc.
SHELL = /bin/bash

# The top-level makefile defines required variables and flags.
ifneq ($(shell [[ $(MAKELEVEL) -ge 1 ]] && echo 1),1)
  $(error Please use the top-level Makefile to build this driver)
endif

# Includes.
EXTRA_CFLAGS += $(FLAGS)
EXTRA_CFLAGS += -I$(srcdir)/include
EXTRA_CFLAGS += -I$(KSRC)/include
EXTRA_CFLAGS += -I.

CFILES  = bond_3ad.c bond_alb.c bond_debugfs.c bond_procfs.c bond_main.c
CFILES += $(notdir $(wildcard $(drvdir)/BONDING_KDIR/bond_sysfs.c))
CFILES += $(notdir $(wildcard $(drvdir)/BONDING_KDIR/bond_sysfs_slave.c))
CFILES += $(notdir $(wildcard $(drvdir)/BONDING_KDIR/bond_netlink.c))
CFILES += $(notdir $(wildcard $(drvdir)/BONDING_KDIR/bond_options.c))
TARGET  = bonding.o
INC_FILES = bond_3ad.h bond_alb.h bonding.h bond_options.h
INC_FILES += $(notdir $(wildcard $(drvdir)/BONDING_KDIR/bond_options.h))
INC_FILES += $(notdir $(wildcard $(drvdir)/BONDING_KDIR/bonding_priv.h))
CLEAN_FILES := $(INC_FILES)
CLEAN_FILES += $(CFILES)
BOND_FILES := $(CLEAN_FILES)
CLEAN_FILES += $(CFILES:.c=.o)
CLEAN_FILES += bond_sysfs.o bond_netlink.o bond_options.o
CLEAN_FILES += BONDING_KDIR

lib_path     := $(PREFIX)/lib/modules/$(utsrelease)
module_path   = updates/drivers/net/bonding
install_path := $(lib_path)/$(module_path)
old_install_path := $(lib_path)/updates/kernel/drivers/net/bonding

ifeq ($(kseries),2.4)
  $(error offload driver is not supported on 2.4 series kernel)
  driver := $(TARGET)
  $(TARGET): $(filter-out $(TARGET),$(CFILES:.c=.o))
	$(LD) -r $^ -o $@
else
  driver := $(TARGET:.o=.ko)
endif

ifneq ($(modulesymfile),)
  override symverfile = symverfile="$(topdir)/$(modulesymfile) \
                                    -o $(drvdir)/$(modulesymfile)"
else
  override symverfile =
endif

ifeq ($(shell echo $(kseries) | cut -d. -f1), 3)
  kversions += $(kseries)
endif

ifeq ($(shell echo $(kseries) | cut -d. -f1), 4)
  kversions += $(kseries)
endif

obj-m := $(TARGET)
$(TARGET:.o=)-objs := $(CFILES:.c=.o)

.SUFFIXES:
.SUFFIXES: .c .o

.PHONY: default
default: prep build

.PHONY: prep
prep: symlink

# The Linux kernel bonding source files (with small TOE modifications) are
# symbolic links to BONDING_KDIR/{File}.  However, BONDING_KDIR itself will be
# a symbolic link pointing to the correct Linux Kernel Version director based
# on the Kernel Version that we're building.  These Linux-Version-specific
# directories are appropriately named sub-directories of BONDING_KDIRS.
#
# We itterate across the $(kversions) variable looking for a matching
# sub-directory under BONDING_KDIRS.  If we find a match, we create the
# symbolic link BONDING_KDIR pointing to BONDING_KDIRS/{Linux-Kernel-Version}.
# If not, we throw an error.
#
.PHONY: symlink
symlink:
	@[ -L BONDING_KDIR ] && /bin/rm -f BONDING_KDIR; true
	@BONDING_KDIR=""; \
	for ver in $(kversions); do \
	    if [[ -d BONDING_KDIRS/$$ver ]]; then \
		BONDING_KDIR=$$ver; \
		break; \
	    fi; \
	    if [[ -d BONDING_KDIRS/$$ver.0 ]]; then \
		BONDING_KDIR=$$ver.0; \
		break; \
	    fi; \
	done; \
	if [[ -z "$$BONDING_KDIR" ]]; then \
	    echo "*** ERROR: Kernel version not supported" >&2; \
	    exit 1; \
	fi; \
	ln -sf BONDING_KDIRS/$$BONDING_KDIR BONDING_KDIR; \
	for bond_file in $(BOND_FILES); do \
		ln -sf BONDING_KDIR/$$bond_file $$bond_file; \
	done; \
	mkdir -p $$srcdir/include/drivers/net/bonding; \
	for inc_file in $(INC_FILES); do \
		ln -sf $(shell pwd)/$$inc_file $$srcdir/include/drivers/net/bonding/$$inc_file; \
	done;


.PHONY: build
build:
	@$(MAKE) $(symverfile) -C $(KOBJ) SUBDIRS=$(shell pwd) modules

.PHONY:
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
		     .*cmd .tmp_versions *.symvers \
		     ../include/drivers/net/bonding/*.h
