# Makefile for Chelsio T4 iw_cxgb4 driver.
# Copyright (c) 2009-2010 Chelsio, Inc. All rights reserved.
SHELL = /bin/sh

# The top-level makefile defines required variables and flags.
ifneq ($(shell [ $(MAKELEVEL) -ge 1 ] && echo 1),1)
  $(error Please use the top-level Makefile to build this driver)
endif

# Includes.
EXTRA_CFLAGS += $(FLAGS)
EXTRA_CFLAGS += $(iwarp_include)
EXTRA_CFLAGS += -I$(srcdir)/include
EXTRA_CFLAGS += -I$(srcdir)/cxgb4
EXTRA_CFLAGS += -I$(srcdir)/iw_cxgb4
EXTRA_CFLAGS += -I$(KSRC)/include
EXTRA_CFLAGS += -I. -g -O1

ifneq ($(OFA_DIR),)

VERSION_H := $(KOBJ)/include/linux/version.h
ifeq ($(wildcard $(VERSION_H)),)
  VERSION_H := $(KOBJ)/include/generated/uapi/linux/version.h
endif

AUTOCONF_H := $(KOBJ)/include/linux/autoconf.h
ifeq ($(wildcard $(AUTOCONF_H)),)
  AUTOCONF_H := $(KOBJ)/include/generated/autoconf.h
endif

#
# If compat_autoconf.h exists then we're dealing with OFED-3.x.
# We must include this file, which also requires including
# the main autoconf.h and version.h prior to compat_autoconf.h
#
COMPAT_AUTOCONF_H := $(OFA_DIR)/include/linux/compat_autoconf.h
ifneq ($(wildcard $(COMPAT_AUTOCONF_H)),)
  AUTOCONFS := -include $(VERSION_H) -include $(AUTOCONF_H) -include $(COMPAT_AUTOCONF_H)
endif

EXTRA_CFLAGS += -DOFED_BUILD -D__OFED_BUILD__
FOO := $(AUTOCONFS) -I$(OFA_DIR)/include $(LINUXINCLUDE)
override LINUXINCLUDE=$(FOO)

endif

CFILES  = ev.c cm.c mem.c device.c resource.c provider.c cq.c qp.c id_table.c iw_cxgb4_compat.c
TARGET  = iw_cxgb4.o
CLEAN_FILES := $(wildcard *.c)
CLEAN_FILES := $(CLEAN_FILES:.c=.o)

lib_path     := $(PREFIX)/lib/modules/$(utsrelease)
module_path   = updates/drivers/infiniband/hw/cxgb4
install_path := $(lib_path)/$(module_path)
old_install_path := $(lib_path)/kernel/$(module_path)

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

obj-m := $(TARGET)
$(TARGET:.o=)-objs := $(CFILES:.c=.o)

.SUFFIXES:
.SUFFIXES: .c .o

.PHONY: default
default: prep build

.PHONY: prep
prep:

AUTOCONF_H := $(KOBJ)/include/generated/autoconf.h
ifeq ($(wildcard $(AUTOCONF_H)),)
  AUTOCONF_H := $(KOBJ)/include/linux/autoconf.h
endif

.PHONY: build
build:
	@$(MAKE) $(symverfile) -C $(KOBJ) SUBDIRS=$(shell pwd) \
		V=$(V) $(WITH_MAKE_PARAMS) \
		KBUILD_NOCMDDEP=1 \
		modules

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
