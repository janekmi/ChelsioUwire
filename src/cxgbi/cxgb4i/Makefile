SHELL = /bin/bash

# The top-level makefile defines required variables and flags.
ifneq ($(shell [[ $(MAKELEVEL) -ge 1 ]] && echo 1),1)
  $(error Please use the top-level Makefile to build this driver)
endif

FLAGS += -D__CXGB4TOE__
FLAGS += -DCONFIG_CHELSIO_T4_CORE
FLAGS += -DCONFIG_CHELSIO_T4_OFFLOAD_MODULE
FLAGS += -DCONFIG_TCP_OFFLOAD_MODULE

ifneq ($(shell $(grep) 'cxgb4_port_idx' $(CXGB4TOE_SRC)/cxgb4/*.c | \
		$(grep) -c 'EXPORT_SYMBOL'),0)
  FLAGS += -DCXGB4_PORT_IDX
endif

# sw repo (4.X) uses napi_alloc_skb() but not the backport repos
# which also implies that lro_rx_handler() with parameter *napi
ifneq ($(shell $(grep) 'cxgb4_pktgl_to_skb' \
			$(CXGB4TOE_SRC)/cxgb4/cxgb4_ofld.h | \
                $(grep) -c 'napi'),0)
  FLAGS += -DCXGB4_NAPI_ALLOC_SKB
endif

# lro_rx_handler() with parameter napi_id
ifneq ($(shell $(grep) -c 'napi_id' $(CXGB4TOE_SRC)/cxgb4/cxgb4_ofld.h),0)
  FLAGS += -DCXGB4_LRO_HANDLER_NAPI_ID
endif

ifneq ($(shell $(grep) -c 't4_pktgl_to_skb' $(CXGB4TOE_SRC)/cxgb4/sge.c),0)
  FLAGS += -DCXGB4_T4_PKTGL_TO_SKB
  t4_pkt := 1
else
  t4_pkt := 0
endif

ifeq ($(dmajor),5)
  FLAGS += -DDEL_WORK
endif

ifneq ($(MAKECMDGOALS),clean)
  include $(drvdir)/t4_flags.mk
endif

EXTRA_CFLAGS += -DLINUX -D__KERNEL__ -DMODULE -O2 -pipe -Wall
EXTRA_CFLAGS += $(OFLAGS)
EXTRA_CFLAGS += $(FLAGS) $(CPPFLAGS)

ifeq ($(no_libcxgbi),1)
EXTRA_CFLAGS += -D__LIBCXGBI__
endif

EXTRA_CFLAGS += -I$(OISCSI_SRC)/include -I$(OISCSI_INC)
EXTRA_CFLAGS += -I$(CXGB4TOE_SRC)/include -I$(CXGB4TOE_SRC)/cxgb4
EXTRA_CFLAGS += -I$(KSRC)/include
EXTRA_CFLAGS += -I$(srcdir)/libcxgbi
EXTRA_CFLAGS += -I.

ifneq ($(modulesymfile),)
  override symverfile = symverfile="$(topdir)/$(modulesymfile) \
					-o $(drvdir)/$(modulesymfile)"
else
  override symverfile =
endif

obj-m := cxgb4i.o

.PHONY: default
default: prep build

.PHONY: prep
prep: $(modulesymfile)
$(modulesymfile):
	@rm -f $(modulesymfile)
	@if [ -z "$(no_libcxgbi)" ]; then \
	  cp $(srcdir)/libcxgbi/$(modulesymfile) $(modulesymfile);\
	fi;
	@echo "copying over cxgb4 $(modulesymfile) ..."
	@grep cxgb4_ $(CXGB4TOE_SRC)/$(modulesymfile) >> $(modulesymfile)
	@grep t4_l2t $(CXGB4TOE_SRC)/$(modulesymfile) >> $(modulesymfile)
	@if [ "$(t4_pkt)" -ne 0 ]; then \
	  grep t4_pkt $(CXGB4TOE_SRC)/$(modulesymfile) >> $(modulesymfile);\
	fi;

.PHONY: build
build:
	@$(MAKE) symverfile=$(symverfile) -C $(KOBJ) SUBDIRS=$(shell pwd) modules

.PHONY: clean
clean:
	-/bin/rm -rf *.ko* ?odule* .tmp_versions *.mod.* *.o .*.o.* .*.cmd
