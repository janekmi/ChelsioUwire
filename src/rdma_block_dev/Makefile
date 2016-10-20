obj-m += rbdt.o rbdi.o
rbdt-y := target.o profile.o
rbdi-y := initiator.o profile.o rbdi_dev.o

#
# Do 'make OFA_KERNEL=/pathto/compat-rdma' if building
# on top of an OFED-3.x installation.
#

PWD  := $(shell pwd)
KVER := $(shell uname -r)
MODULES_DIR := /lib/modules/$(KVER)
KDIR := $(MODULES_DIR)/build
MODULE_DESTDIR := $(MODULES_DIR)/extra/
DEPMOD := depmod
grep = grep 2>/dev/null

EXTRA_CFLAGS += $(PROFILE) -D_KERNEL_

KERNEL_VER?=$(shell uname -r)

ifneq ($(OFA_KERNEL),)
  MODFILE := $(OFA_KERNEL)/Module.symvers

  VERSION_H := $(KDIR)/include/linux/version.h
  ifeq ($(wildcard $(VERSION_H)),)
    VERSION_H := $(KDIR)/include/generated/uapi/linux/version.h
  endif

  AUTOCONF_H := $(KDIR)/include/linux/autoconf.h
  ifeq ($(wildcard $(AUTOCONF_H)),)
    AUTOCONF_H := $(KDIR)/include/generated/autoconf.h
  endif

  #
  # If compat_autoconf.h exists then we're dealing with OFED-3.x.
  # We must include this file, which also requires including
  # the main autoconf.h and version.h prior to compat_autoconf.h
  #
  COMPAT_AUTOCONF_H := $(OFA_KERNEL)/include/linux/compat_autoconf.h
  ifneq ($(wildcard $(COMPAT_AUTOCONF_H)),)
    AUTOCONFS := -include $(VERSION_H) -include $(AUTOCONF_H) -include $(COMPAT_AUTOCONF_H)
  endif

  EXTRA_CFLAGS += -DOFED_BUILD -D__OFED_BUILD__
  FOO := $(AUTOCONFS) -I$(OFA_KERNEL)/include $(LINUXINCLUDE)
  override LINUXINCLUDE=$(FOO)

  RDMA_INC = $(OFA_KERNEL)/include/rdma
else
  MODFILE := $(KDIR)/Module.symvers
  RDMA_INC = $(KDIR)/include/rdma
endif

ifneq ($(wildcard $(RDMA_INC)/ib_verbs.h),)
  ifneq ($(shell $(grep) -c 'ib_cq_init_attr' $(RDMA_INC)/ib_verbs.h),0)
    EXTRA_CFLAGS += -DHAVE_IB_CQ_INIT_ATTR
  endif
endif

all:
	cp -rf $(MODFILE) Module.symvers
	make -C $(KDIR) M=$(PWD) NOSTDINC_FLAGS="$(EXTRA_CFLAGS)" modules
	make -C rbdctl

clean:
	make -C $(KDIR)  M=$(PWD) clean
	make -C rbdctl clean

install:
	mkdir -p $(MODULE_DESTDIR);
	cp -f $(PWD)/rbdt.ko $(MODULE_DESTDIR);
	cp -f $(PWD)/rbdi.ko $(MODULE_DESTDIR);
	cp -f $(PWD)/rbdctl/rbdctl /usr/bin;
	gzip -c rbdctl/rbdctl.8 > rbdctl.8.gz
	@if [ -d $(PREFIX)/usr/share/man ];\
		then install -m 444 rbdctl.8.gz $(PREFIX)/usr/share/man/man8;\
	elif [ -d $(PREFIX)/usr/man ];\
		then install -m 444 rbdctl.8.gz $(PREFIX)/usr/man/man8;\
	fi
	@/bin/rm -f rbdctl.8.gz
	$(DEPMOD) -r -ae $(KVER)

uninstall:
	/bin/rm -f $(MODULE_DESTDIR)/rbdt.ko
	/bin/rm -f $(MODULE_DESTDIR)/rbdi.ko
	$(DEPMOD) -r -ae $(KVER)
