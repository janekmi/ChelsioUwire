# Makefile for Chelsio iSCSI Target T3/T4 Offload driver.
# Copyright (c) 2004-2012 Chelsio Communications, Inc.
SHELL = /bin/bash
 
#
# kernel parameters:
# - KDIR/KSRC/KOBJ=, optional
#
# offload parameters:
# - CXGB3TOE_SRC=	path to cxgb3toe-1.x.x.x/
# - CXGB4TOE_SRC=	path to linux_t4_build/
#
# compile option:
# - enable_dcb=<0|1>	enable DCBx support
# - enable_lld_debug=<0|1>	LLD/TOM DEBUG is enabled
# - enable_scst=<0|1>	enable SCST passthru mode support
# - enable_lm=<0|1>	enable lunmasking support
# - enable_bl=<0|1>	enable blanket license support
# - disable_vfs=<0|1>	disable FILE mode support
# - enable_notification=<0|1>	enable event notifications
# - libsrc=<0|1>	always recompile the library as the same time as
#   			the modules
# - test_premap=<0|1>	enable testing of premapped skb via blk interface
# - enable_dsgl=<0|1>	enable mem_write via dsgl
#

# Define grep error output to NULL, since -s is not portable.
grep = grep 2>/dev/null

# ALL subdirectories
ALLSUBDIRS := base t3 t4

# subdirectories to be build
SUBDIRS := $(ALLSUBDIRS)

# Honor the -s (silent) make option.
verbose := $(if $(filter s,$(MAKEFLAGS)),,-v)

# Define paths.
srcdir := $(shell pwd)
topdir := $(shell cd $(srcdir)/.. && pwd)

kernel_check = 1
distro_check = 1
ifeq ($(libsrc),)
  libsrc = 1
endif

ifeq ($(filter clean,$(MAKECMDGOALS)),clean)
  kernel_check = 0
  distro_check = 0
endif

ifeq ($(filter uninstall,$(MAKECMDGOALS)),uninstall)
  distro_check = 0
endif

ifeq ($(kernel_check),1)
  include kernel_check.mk

  ifeq ($(distro_check),1)
    include distro_check.mk

    include cxgb_check.mk
    ifeq ($(CXGB3TOE_SRC),)
      SUBDIRS := $(filter-out t3,$(SUBDIRS))
    endif
    ifeq ($(CXGB4TOE_SRC),)
      SUBDIRS := $(filter-out t4,$(SUBDIRS))
    endif
  endif
endif

ifneq ($(wildcard $(KINC)/linux/kconfig.h),)
  FLAGS += -DKERNEL_HAS_KCONFIG_H
endif
ifneq ($(wildcard $(KINC)/linux/export.h),)
  FLAGS += -DKERNEL_HAS_EXPORT_H
endif

ifneq ($(shell $(grep) -c 'skb_frag_page' $(KINC)/linux/skbuff.h),0)
  FLAGS += -DDEFINED_SKB_FRAG_PAGE
endif

# Debug flags.
ifeq ($(DEBUG),1)
  FLAGS += -g
#  ifeq ($(shell $(grep) -c '^\#define[[:space:]]\+CONFIG_DEBUG_FS[[:space:]]\+1' \
#                $(AUTOCONF_H)),1)
#    FLAGS += -DT4_TRACE
#  endif
endif

# Don't allow ARCH to overwrite the modified variable when passed to
# the sub-makes.
MAKEOVERRIDES := $(filter-out ARCH=%,$(MAKEOVERRIDES))
# Don't allow CFLAGS/EXTRA_CFLAGS to clobber definitions in sub-make.
MAKEOVERRIDES := $(filter-out CFLAGS=%,$(MAKEOVERRIDES))
MAKEOVERRIDES := $(filter-out EXTRA_CFLAGS=%,$(MAKEOVERRIDES))

# library check: if source exist, use the source instead
srcklib := 0
srculib := 0
ifeq ($(libsrc),1)
  ifneq ($(wildcard $(srcdir)/private/klib),)
    srcklib := 1
    $(shell rm -f base/klib; ln -fs $(srcdir)/private/klib base/klib;)
  else
    $(warning $(srcdir)/private/klib NOT exists.)
  endif

  ifneq ($(wildcard $(srcdir)/private/ulib),)
    srculib := 1
    $(shell rm -f user/ulib; ln -fs $(srcdir)/private/ulib user/ulib;)
  endif
endif

# Exports.
export grep
export srcdir
export topdir
export KERNELRELEASE
#export PREFIX
#export INSTALL_MOD_DIR
export KSRC
export KOBJ
export KINC
# arm64 specific fix to include <ksrc>/arch/<karch> folder properly.
# This hack is motivated by the RHEL7.X/CentOS7.X release where the 
# uname Architecture is indicated as "aarch64" but the 
# real Architecture source directory is "arm64"
ifeq ($(ARCH),aarch64)
  ifeq ($(wildcard $(KOBJ)/arch/$(ARCH)/Makefile),)
    override MAKECMDGOALS = $(MAKECMDGOALS) "ARCH=arm64"
  else
    export ARCH
  endif
else
  export ARCH
endif
export FLAGS
#export FLAGS += $(CFLAGS) $(EXTRA_CFLAGS) $(CPPFLAGS)
export verbose
export utsrelease
export kversions
export kseries
export modulesymfile
export srcklib
export srculib

export enable_dcb
export enable_lld_debug
export enable_scst
export enable_lm
export enable_bl
export disable_vfs
export enable_notification
export test_premap
export enable_dsgl

install_path := $(PREFIX)/lib/modules/$(utsrelease)/updates/kernel/drivers/scsi/chiscsi
conf_path := /etc/chelsio-iscsi

.PHONY: eval.mak

.PHONY: default
default: user subdirs post

.PHONY: install
install: install-mods install-user install-etc install-initd

.PHONY: uninstall
uninstall: uninstall-mod uninstall-user uninstall-initd

.PHONY: user
user:
	$(MAKE) -C user

.PHONY: subdirs $(SUBDIRS)
subdirs: $(SUBDIRS)
$(SUBDIRS):
	@if [ -n "$(verbose)" ]; then \
	   echo "#######################";\
	   printf "####  %-8s%5s####\n" $(@);\
	   echo "#######################";\
	 fi;
	@drvdir=$(shell pwd)/$(@) $(MAKE) -C $(@);

#	/bin/cp -f $(modulesymfile) $(@)/;
#	   /bin/cp -f $(@)/$(modulesymfile) .;\

.PHONY: post
post:
	@if [ -n "$(post_msg)" ]; then \
	   echo -e "\nWARNING:\n $(post_msg)";\
	 fi;

.PHONY: clean
clean:
	@echo "#######################";
	@echo "####  user         ####";
	@echo "#######################";
	$(MAKE) -C user clean;
	@for dir in $(ALLSUBDIRS); do \
	   echo "#######################";\
	   printf "####  %-8s%5s####\n" $$dir;\
	   echo "#######################";\
	  drvdir=$(shell pwd)/$$dir $(MAKE) -C $$dir clean;\
	done;
	@-/bin/rm -f *.symvers eval.mak 2>/dev/null;

.PHONY: install-mods
install-mods:
	@echo "installing kernel modules to $(install_path) ..."
	@mkdir -p -m 755 $(install_path)
	@-for m in $(ALLSUBDIRS); do \
		if [ -f "$$m/chiscsi_$$m.ko" ]; then \
			install -v -m 644 $$m/chiscsi_$$m.ko $(install_path); \
		fi; \
	done;
	@depmod -a || true

.PHONY: install-user
install-user:
	@echo "installing user tools to /sbin ..."
	@install -v -m 755 user/iscsictl /sbin
	@install -v -m 755 user/chisns /sbin
	@if [ -d /etc/bash_completion.d ]; then \
		echo "BASH COMPLETION:"; \
		install -v -m 644 user/bash/iscsictl /etc/bash_completion.d; \
		install -v -m 644 user/bash/chisns /etc/bash_completion.d; \
	fi;
	@echo "MAN PAGES:"
	@install -v -m 644 docs/iscsictl.8.gz /usr/share/man/man8

.PHONY: install-etc
install-etc:
	@echo "install Chelsio iSCSI config:"
	@mkdir -p -m 755 $(conf_path)
	@mkdir -p -m 755 $(conf_path)/prdb
	@mkdir -p -m 755 $(conf_path)/discovery
	@mkdir -p -m 755 $(conf_path)/discovery/log
	@if [ ! -f "$(conf_path)/chiscsi.conf" ]; then \
		install -v -m 644 example/chiscsi.conf $(conf_path); \
	fi;
	@if [ ! -f "$(conf_path)/chiscsi_perf.conf" ]; then \
		install -v -m 644 example/chiscsi_perf.conf $(conf_path); \
	fi;

.PHONY: install-initd
install-initd:
	@echo "install Chelsio iSCSI Service Script:"
	@if [ ! -f /etc/sysconfig/chiscsi ]; then \
		install -m 644 example/initd/chiscsi /etc/sysconfig; \
	fi;
	@if [ -f /etc/init.d/chelsio-target ]; then \
		install -vD -m 755 example/initd/chelsio-target.redhat /etc/init.d/chelsio-target; \
		chkconfig --add chelsio-target 2>/dev/null; \
	elif [ -f /etc/redhat-release ]; then \
		install -vD -m 755 example/initd/chelsio-target.redhat /etc/init.d/chelsio-target; \
		chkconfig --add chelsio-target 2>/dev/null; \
	elif [ -f /etc/SuSE-release ]; then \
		install -vD -m 755 example/initd/chelsio-target.suse /etc/init.d/chelsio-target; \
	elif [ -f /etc/debian_version ]; then \
		install -vD -m 755 example/initd/chelsio-target /etc/init.d/; \
		update-rc.d chelsio-target defaults 2>/dev/null; \
	else \
		install -vD -m 755 example/initd/chelsio-target /etc/init.d/; \
		chkconfig --add chelsio-target 2>/dev/null; \
        fi

.PHONY: uninstall-mod
uninstall-mod:
	@echo "Un-installing $(install_path) ..."
	@/bin/rm -rf $(install_path)*
	@depmod -a
	
.PHONY: uninstall-user
uninstall-user:
	@echo "Un-installing user tools under /sbin ..."
	@/bin/rm -f /sbin/iscsictl /sbin/chisns

.PHONY: uninstall-initd
uninstall-initd:
	@echo "Un-installing Chelsio iSCSI Service Script:"
	@/bin/rm -f /etc/sysconfig/chiscsi
	@/bin/rm -f /etc/init.d/chelsio-target

.PHONY: help
help:
	@echo "Build Targets:";\
	 echo " install             - Installs all compiled drivers.";\
	 echo " uninstall           - Uninstalls drivers.";\
	 echo " clean               - Removes all generated files.";\
	 echo;\
	 echo "Build Options:";\
	 echo " KOBJ=<path>         - Kernel build (object) path.";\
	 echo " KSRC=<path>         - Kernel source path.";\
	 echo "                     - Note: When using KSRC or KOBJ, both";\
	 echo "                             variables must be specified.";\
	 echo " KDIR=<path>         - Kernel build and source path. Shortcut";\
	 echo "                       for KOBJ=KSRC=<path>.";\
	 echo " CXGB3TOE_SRC=<path> - cxgb3 & toe driver source path.";\
	 echo " CXGB4TOE_SRC=<path> - cxgb4 & toe driver source path.";\
	 echo;\
	 echo " enable_ldd_debug=1  - LLD is compiled with DEBUG=1";\
	 echo;
