#
# open-iscsi check
#

# if out-of-box, must be >= 2.0.872

OISCSI_VER_MIN := 872

ifneq ($(OISCSI_SRC),)
  oiscsi_ver := $(shell grep 'ISCSI_VERSION_STR' $(OISCSI_SRC)/usr/version.h | \
		 grep -E -o [0-9.-]+)
  oiscsi_vminor :=  $(shell echo $(oiscsi_ver) | cut -d'-' -f2)
  $(warning open-iscsi V $(oiscsi_ver).)

  ifeq ($(shell [ $(oiscsi_vminor) -lt $(OISCSI_VER_MIN) ] && echo 1),1)
    $(error ERROR! Unsupported open-iscsi V $(oiscsi_ver).)
  endif

  OISCSI_INC := $(OISCSI_SRC)/kernel

#  OISCSI_PATCH += 

else
  OISCSI_INC := $(KSRC)/include/scsi
  $(warning open-iscsi inbox $(OISCSI_INC).)
  ifneq ($(wildcard $(OISCSI_INC)/libiscsi2.h),)
    OFLAGS += -DOISCSI_LIBISCSI2
    HDR2 := 2
    $(warning open-iscsi inbox libiscsi2 present.)
  endif

  ifeq ($(wildcard $(OISCSI_INC)/libiscsi_tcp.h),)
    $(warning ERROR! $(KSRC) missing libiscsi_tcp.h, \
		     in-box open-iscsi source too old.)
    $(error Please download and install open-iscsi >= 2.0.$(OISCSI_VER_MIN))
  endif

  # make sure the in-box open-iscsi version has the proper hooks for us
  ifneq ($(shell $(grep) -c 'CAP_DIGEST_OFFLOAD' $(OISCSI_INC)/iscsi_if$(HDR2).h),1)
    $(warning ERROR! $(KSRC) in-box open-iscsi too old.)
    $(error Please download and install open-iscsi >= 2.0.$(OISCSI_VER_MIN))
  endif

endif

ifneq ($(shell $(grep) -c 'eh_target_reset_handler' $(KSRC)/include/scsi/scsi_host.h),0)
  OFLAGS += -DOISCSI_SCSI_TARGET_RESET_HANDLER
endif

ifneq ($(shell $(grep) -c 'eh_host_reset_handler' $(KSRC)/include/scsi/scsi_host.h),0)
  OFLAGS += -DOISCSI_SCSI_HOST_RESET_HANDLER
endif

ifneq ($(shell $(grep) -c '_eh_recover_target' $(OISCSI_INC)/libiscsi$(HDR2).h),0)
  OFLAGS += -DOISCSI_DEFINED_RECOVER_TARGET
endif

ifneq ($(shell $(grep) -c '_eh_target_reset' $(OISCSI_INC)/libiscsi$(HDR2).h),0)
  OFLAGS += -DOISCSI_DEFINED_RESET_TARGET
endif

ifneq ($(shell $(grep) -c '_target_alloc' $(OISCSI_INC)/libiscsi$(HDR2).h),0)
  OFLAGS += -DOISCSI_SCSI_TARGET_ALLOC_HANDLER
endif

ifneq ($(shell $(grep) -c 'portal_address' $(OISCSI_INC)/libiscsi$(HDR2).h),0)
  OFLAGS += -DOISCSI_CONN_HAS_PORTAL_ADDR
endif

ifneq ($(shell $(grep) -c 'param_mask' $(OISCSI_INC)/scsi_transport_iscsi$(HDR2).h),0)
  OFLAGS += -DOISCSI_TRANSPORT_HAS_PARAM_MASK
endif

ifneq ($(shell $(grep) -c 'get_ep_param' $(OISCSI_INC)/scsi_transport_iscsi$(HDR2).h),0)
  OFLAGS += -DOISCSI_TRANSPORT_HAS_GET_EP_PARAM
endif

ifneq ($(shell $(grep) -c 'portal_address' $(OISCSI_INC)/libiscsi$(HDR2).h),0)
  OFLAGS += -DOISCSI_CONN_HAS_PORTAL_ADDR
endif

ifneq ($(shell $(grep) -c 'ISCSI_ERR_TCP_CONN_CLOSE' $(OISCSI_INC)/iscsi_if$(HDR2).h),0)
  OFLAGS += -DOISCSI_ERR_TCP_CLOSE
endif

export OISCSI_SRC
export OISCSI_INC
export OISCSI_PATCH
export OFLAGS

EXTRA_CFLAGS += -I$(OISCSI_INC)
#$(warning oiscsi OFLAGS = $(OFLAGS).)

ifneq ($(shell $(grep) -c 'attr_is_visible' $(OISCSI_INC)/scsi_transport_iscsi$(HDR2).h),0)
  OFLAGS += -DOISCSI_TRANSPORT_HAS_ATTR_IS_VISIBLE
endif

ifneq ($(shell $(grep) -c 'umode_t' $(OISCSI_INC)/scsi_transport_iscsi$(HDR2).h),0)
  OFLAGS += -DOISCSI_TRANSPORT_UMODE_T
endif

ifneq ($(shell $(grep) -c 'portal_address' $(OISCSI_INC)/libiscsi$(HDR2).h),0)
  OFLAGS += -DOISCSI_CONN_HAS_PORTAL_ADDR
endif

ifneq ($(shell $(grep) -c 'ISCSI_ERR_TCP_CONN_CLOSE' $(OISCSI_INC)/iscsi_if$(HDR2).h),0)
  OFLAGS += -DOISCSI_ERR_TCP_CLOSE
endif

export OISCSI_SRC
export OISCSI_INC
export OISCSI_PATCH
export OFLAGS

EXTRA_CFLAGS += -I$(OISCSI_INC)
