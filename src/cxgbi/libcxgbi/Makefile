SHELL = /bin/bash

# The top-level makefile defines required variables and flags.
ifneq ($(shell [[ $(MAKELEVEL) -ge 1 ]] && echo 1),1)
  $(error Please use the top-level Makefile to build this driver)
endif

EXTRA_CFLAGS += -DLINUX -D__KERNEL__ -DMODULE -O2 -pipe -Wall
EXTRA_CFLAGS += -D__LIBCXGBI__
EXTRA_CFLAGS += $(OFLAGS)
EXTRA_CFLAGS += $(FLAGS) $(CPPFLAGS)
EXTRA_CFLAGS += -I$(OISCSI_SRC)/include -I$(OISCSI_INC)
EXTRA_CFLAGS += -I$(KSRC)/include
EXTRA_CFLAGS += -I.

# virt_to_head_page >= 2.6.24
ifneq ($(shell $(grep) -c 'virt_to_head_page' $(KINC)/linux/mm.h),0)
  FLAGS += -DVIRT_TO_HEAD_PAGE
endif

ifneq ($(shell $(grep) -c 'skb_frag_page' $(KINC)/linux/skbuff.h),0)
  FLAGS += -DHAS_SKB_FRAG_PAGE
endif

ifneq ($(modulesymfile),)
  override symverfile = symverfile="$(topdir)/$(modulesymfile) \
					-o $(drvdir)/$(modulesymfile)"
else
  override symverfile =
endif

obj-m := libcxgbi.o

.PHONY: default
default: prep build

.PHONY: prep
prep: $(modulesymfile)
$(modulesymfile):
	@if [ -n "$(OISCSI_SRC)" ]; then \
	   echo "copying open-iscsi symvers: $(OISCSI_SRC) $(modulesymfile) ..."; \
	   rm -f $(modulesymfile); \
	   cp $(OISCSI_SRC)/kernel/$(modulesymfile) $(modulesymfile); \
	fi;

.PHONY: build
build:
	@$(MAKE) symverfile=$(symverfile) -C $(KOBJ) SUBDIRS=$(shell pwd) modules

.PHONY: clean
clean:
	-/bin/rm -rf *.ko* ?odule* .tmp_versions *.mod.* *.o .*.o.* .*.cmd
