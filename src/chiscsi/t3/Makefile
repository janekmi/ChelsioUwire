SHELL = /bin/bash

# The top-level makefile defines required variables and flags.
ifneq ($(shell [[ $(MAKELEVEL) -ge 1 ]] && echo 1),1)
  $(error Please use the top-level Makefile to build this driver)
endif

FLAGS += CHISCSI_T3_OFFLOAD_ENABLE

include $(drvdir)/t3_flags.mk
cxgb3_inc := -I$(CXGB3TOE_SRC)
cxgb3_inc += -I$(CXGB3TOE_SRC)/include
cxgb3_inc += -I$(CXGB3TOE_SRC)/cxgb3


FLAGS += -DCONFIG_CHELSIO_T3_CORE
FLAGS += -DCONFIG_CHELSIO_T3_OFFLOAD
FLAGS += -DCONFIG_TCP_OFFLOAD_MODULE
ifeq ($(shell [ -e $(CXGB3TOE_SRC)/cxgb3/sge_skb.h ] && echo 1), 1)
  FLAGS += -DCXGB_SGE_SKB_H
endif

EXTRA_CFLAGS += -DLINUX -D__KERNEL__ -DMODULE -O2 -pipe -Wall
EXTRA_CFLAGS += $(FLAGS) $(CPPFLAGS)
EXTRA_CFLAGS += -I$(srcdir)/includes
EXTRA_CFLAGS += -I$(KSRC)/include
EXTRA_CFLAGS += -I$(KSRC)/include/uapi
EXTRA_CFLAGS += -I$(KSRC)/include/generated/uapi
EXTRA_CFLAGS += -I$(KSRC)/arch/x86/include/generated/uapi
EXTRA_CFLAGS += -I.

ifneq ($(modulesymfile),)
  override symverfile = symverfile="$(topdir)/$(modulesymfile) \
					-o $(drvdir)/$(modulesymfile)"
else
  override symverfile =
endif

AUTOCONF_H := $(KOBJ)/include/generated/autoconf.h
ifeq ($(wildcard $(AUTOCONF_H)),)
  AUTOCONF_H := $(KOBJ)/include/linux/autoconf.h
endif

obj-m := chiscsi_t3.o
chiscsi_t3-objs := t3.o

.PHONY: default
default: prep build

.PHONY: prep
prep: $(modulesymfile)
$(modulesymfile):
	@echo "copying $(modulesymfile) ..."
	@rm -f $(modulesymfile)
	@cat $(CXGB3TOE_SRC)/$(modulesymfile) $(srcdir)/base/$(modulesymfile) > ./$(modulesymfile)

.PHONY: build
build:
	@$(MAKE) symverfile=$(symverfile) -C $(KOBJ) SUBDIRS=$(shell pwd) \
		V=$(V) $(WITH_MAKE_PARAMS) \
		KBUILD_NOCMDDEP=1 \
		LINUXINCLUDE='\
		-include $(AUTOCONF_H) \
		$(cxgb3_inc) \
		-Iinclude \
		$$(if $$(KBUILD_SRC),-Iinclude2 -I$$(srctree)/include) \
		-I$$(srctree)/arch/$$(SRCARCH)/include \
		-I. \
		' \
		modules

.PHONY: clean
clean:
	@-/bin/rm -rf *.ko* ?odule* .tmp_versions *.mod.* *.o .*.o.* .*.cmd \
			*/*.o */.*.o.* */.*.cmd $(modulesymfile)
