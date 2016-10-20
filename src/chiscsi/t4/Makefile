SHELL = /bin/bash

# The top-level makefile defines required variables and flags.
ifneq ($(shell [[ $(MAKELEVEL) -ge 1 ]] && echo 1),1)
  $(error Please use the top-level Makefile to build this driver)
endif

FLAGS += -DCHISCSI_T4_OFFLOAD_ENABLE

ifeq ($(enable_dsgl),1)
  FLAGS += -D__ULP_MEM_WRITE_USE_DSGL__
  $(warning enable ulp mem_write dsgl.)
endif


include $(drvdir)/t4_flags.mk
cxgb4_inc := -I$(CXGB4TOE_SRC) -I$(CXGB4TOE_SRC)/include
cxgb4_inc += -I$(CXGB4TOE_SRC)/include/linux
cxgb4_inc += -I$(CXGB4TOE_SRC)/cxgb4 -I$(CXGB4TOE_SRC)/t4_tom

# for backward compatibility
ifneq ($(shell $(grep) 'fp_iscsi_lro_rcv' $(CXGB4TOE_SRC)/t4_tom/tom.c | grep -c 'napi'),0)
  FLAGS += -DUSE_NAPI_ALLOC_SKB
endif


# skb_frag_page is defined in cxgb4_compat.h
ifneq ($(shell $(grep) -c 'skb_frag_page' $(CXGB4TOE_SRC)/cxgb4/cxgb4_compat.h),0)
  FLAGS += -DDEFINED_SKB_FRAG_PAGE
endif

ifneq ($(shell $(grep) -c 'iscsi_tagmask' $(CXGB4TOE_SRC)/cxgb4/cxgb4_ofld.h),0)
  FLAGS += -DDEFINED_LLD_ISCSI_TAG_MASK
endif

# txplen_max in tom for flowc_wr
ifneq ($(shell $(grep) -c 'txplen_max' $(CXGB4TOE_SRC)/t4_tom/cpl_io_state.h),0)
  FLAGS += -DDEFINED_CPLIOS_TXPLEN_MAX
endif

# check if qset_idx changed to txq_idx
ifneq ($(shell $(grep) -c 'txq_idx' $(CXGB4TOE_SRC)/t4_tom/cpl_io_state.h),0)
  FLAGS += -DDEFINED_CPLIOS_TXQ_IDX
endif

# new version of offload_get_phys_egress()
ifneq ($(shell $(grep) -c 'init_toe_hash_params' $(CXGB4TOE_SRC)/toecore/toedev.h),0)
  FLAGS += -DOFFLOAD_GET_PHYS_EGRESS_PARAM2
endif

FLAGS += -DCONFIG_CHELSIO_T4_OFFLOAD_MODULE
FLAGS += -DCONFIG_TCP_OFFLOAD_MODULE
FLAGS += -DCONFIG_CHELSIO_IO_SPIN
ifeq ($(shell [ -e $(CXGB4TOE_SRC)/cxgb4/sge_skb.h ] && echo 1), 1)
  FLAGS += -DCXGB_SGE_SKB_H
endif

EXTRA_CFLAGS += -DLINUX -D__KERNEL__ -DMODULE -O2 -pipe -Wall
EXTRA_CFLAGS += $(FLAGS) $(CPPFLAGS)
EXTRA_CFLAGS += -I$(srcdir)/includes
EXTRA_CFLAGS += -I$(KSRC)/include
EXTRA_CFLAGS += -I$(KSRC)/include/uapi
EXTRA_CFLAGS += -I$(KSRC)/include/generated/uapi
EXTRA_CFLAGS += -I$(KSRC)/arch/x86/include/generated/uapi
EXTRA_CFLAGS += $(cxgb4_inc)
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

ifeq ($(enable_lld_debug),1)
  ifeq ($(shell $(grep) -c '^\#define[[:space:]]\+CONFIG_DEBUG_FS[[:space:]]\+1' \
		 $(AUTOCONF_H)),1)
    FLAGS += -DT4_TRACE
    FLAGS += -DT4_TRACE_TOM
  endif
endif

obj-m := chiscsi_t4.o
chiscsi_t4-objs := t4.o

.PHONY: default
default: prep build

.PHONY: prep
prep:
	@echo "copying $(modulesymfile) ..."
	@rm -f ./$(modulesymfile)
	@cat $(CXGB4TOE_SRC)/$(modulesymfile) $(srcdir)/base/$(modulesymfile) > ./$(modulesymfile)

.PHONY: build
build:
	$(MAKE) symverfile=$(symverfile) -C $(KOBJ) SUBDIRS=$(shell pwd) modules

.PHONY: clean
clean:
	@-/bin/rm -rf *.ko* ?odule* .tmp_versions *.mod.* *.o .*.o.* .*.cmd \
			*/*.o */.*.o.* */.*.cmd $(modulesymfile)
