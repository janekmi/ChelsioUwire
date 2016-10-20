#$(warning KINC=$(KINC).)

ifneq ($(shell $(grep) -c 'usecs_to_jiffies' $(KINC)/linux/jiffies.h),0)
  FLAGS += -DUSECS_TO_JIFFIES
endif

ifneq ($(shell $(grep) -c 'is_vmalloc_addr' $(KINC)/linux/mm.h),0)
  FLAGS += -DISVMALLOC
endif

ifneq ($(shell $(grep) -c 'NIPQUAD' $(KINC)/linux/kernel.h),0)
  FLAGS += -DIPV4QUAD
endif

ifneq ($(shell $(grep) -c 'pr_fmt' $(KINC)/linux/kernel.h),0)
  FLAGS += -DPRFMT
endif

ifneq ($(shell $(grep) -c 'vlan_dev_real_dev' $(KINC)/linux/if_vlan.h),0)
  FLAGS += -D_VLAN_DEV_API_
endif

ifneq ($(shell $(grep) -c 'sysfs_format_mac' $(KINC)/linux/if_ether.h),0)
  FLAGS += -DFORMAT_MAC
endif

ifneq ($(wildcard $(KINC)/linux/log2.h),)
  ifneq ($(shell $(grep) -c '__ilog2_u32' $(KINC)/linux/log2.h),0)
    FLAGS += -DLOG2_U32
  endif
endif

#ifneq ($(shell sed '/ip_route_output_flow/,/{/!d' 2>/dev/null \
#                 < $(KINC)/net/route.h | $(grep) -c 'net'),0)
ifneq ($(shell $(grep) 'ip_route_output_flow' $(KINC)/net/route.h | \
                $(grep) -c 'struct net'),0)
  FLAGS += -DIP_ROUTE_OUTPUT_NET
endif

ifneq ($(shell $(grep) 'ip_dev_find' $(KINC)/linux/inetdevice.h | \
                $(grep) -c 'struct net '),0)
  FLAGS += -DIP_DEV_FIND_NET
endif

ifneq ($(shell $(grep) 'pci_dma_mapping_error' $(KINC)/asm-generic/dma-mapping.h | \
                $(grep) -c 'pci_dev'),0)
  FLAGS += -DPDEV_MAPPING
endif
# Linux 2.6.30 moved the prototype declaration of pci_dma_mapping_error()
# to asm-generic/pci-dma-compat.h ...
ifneq ($(shell $(grep) 'pci_dma_mapping_error' $(KINC)/asm-generic/pci-dma-compat.h | \
                $(grep) -c 'pci_dev'),0)
  FLAGS += -DPDEV_MAPPING
endif

# This lets you read ip addr from in_ifaddr instead of cxgbi_hba.
# Kept it place so that it can be easily disabled/backporting.
ifeq (NULL,NULL)
  FLAGS += -DIFA_IPADDR
endif

# Enable ipv6 support in cxgbi if kernel enabled ipv6.
ifneq ($(shell $(grep) -c \
        '^\#define[[:space:]]\+CONFIG_\(IPV6\|IPV6_MODULE\)[[:space:]]\+1' \
        $(KINC)/generated/autoconf.h),0)
  FLAGS += -DCXGBI_IPV6_SUPPORT

  ifneq ($(shell $(grep) -c 'ip6_rt_put' $(KINC)/net/ip6_fib.h),0)
    FLAGS += -D_IP6_RT_API_
  endif

  ifneq ($(shell $(grep) -c 'VLAN_N_VID' $(KINC)/linux/if_vlan.h),0)
    FLAGS += -D_VLAN_N_VID_
  endif

  ifneq ($(shell $(grep) -c 'rt6i_prefsrc' $(KINC)/net/ip6_fib.h),0)
    FLAGS += -D_PREFSRC_ADDR_
  endif

endif

ifneq ($(shell $(grep) -c 'KMALLOC_MAX_SIZE' $(KINC)/linux/slab.h),0)
  FLAGS += -DHAS_KMALLOC_MAX_SIZE
endif

#$(warning FLAGS = $(FLAGS).)
