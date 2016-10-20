ifneq ($(shell $(grep) -c 'IRQF_SHARED' $(KINC)/linux/interrupt.h),0)
  FLAGS += -DIRQF
endif
ifneq ($(shell $(grep) -c 'atomic_add_return' $(KINC)/asm/atomic.h),0)
  FLAGS += -DATOMIC_ADD_RETURN
endif
ifneq ($(shell $(grep) -c 'spin_trylock_irqsave' $(KINC)/linux/spinlock.h),0)
  FLAGS += -DSPIN_TRYLOCK_IRQSAVE
endif
ifneq ($(shell $(grep) -c 'rtnl_trylock' $(KINC)/linux/rtnetlink.h),0)
  FLAGS += -DRTNL_TRYLOCK
endif
ifneq ($(shell $(grep) -c 'gso_size' $(KINC)/linux/skbuff.h),0)
  FLAGS += -DGSO_SIZE
endif
ifneq ($(shell $(grep) -c 'gso_type' $(KINC)/linux/skbuff.h),0)
  FLAGS += -DGSO_TYPE
endif
ifneq ($(shell $(grep) -c 'kzalloc' $(KINC)/linux/slab.h),0)
  FLAGS += -DKZALLOC
endif
ifneq ($(shell $(grep) -c 'pci_error_handlers' $(KINC)/linux/pci.h),0)
  FLAGS += -DHAS_EEH
endif
ifneq ($(shell $(grep) -c 'vlan_group_get_device' $(KINC)/linux/if_vlan.h),0)
  FLAGS += -DVLANGRP
endif
ifneq ($(shell $(grep) -c 'skb_copy_from_linear_data' \
               $(KINC)/linux/skbuff.h),0)
  FLAGS += -DNEW_SKB_COPY
endif
ifneq ($(shell $(grep) -c 'i_private' $(KINC)/linux/fs.h),0)
  FLAGS += -DI_PRIVATE
endif
ifneq ($(shell $(grep) -c 'skb_network_offset' $(KINC)/linux/skbuff.h),0)
  FLAGS += -DNEW_SKB_OFFSET
endif
ifneq ($(shell $(grep) -c 'arp_hdr' $(KINC)/linux/if_arp.h),0)
  FLAGS += -DARP_HDR
endif
ifneq ($(shell $(grep) 'transport_header' $(KINC)/linux/skbuff.h | \
		$(grep) -c 'sk_buff_data_t'),0)
  FLAGS += -DTRANSPORT_HEADER
endif
ifneq ($(wildcard $(KINC)/net/netdma.h),)
  FLAGS += -DNETDMA_IN_KERNEL
endif
ifneq ($(shell $(grep) -c 'ioat_sock' $(KINC)/net/netdma.h),0)
  FLAGS += -DIOAT_SOCK
endif
ifneq ($(shell sed '/ip_route_connect/,/{/!d' 2>/dev/null \
                 < $(KINC)/net/route.h | $(grep) -c 'flags'),0)
  FLAGS += -DIP_ROUTE_FLAGS
endif
ifneq ($(shell $(grep) -c 'security_inet_conn_request' \
               $(KINC)/linux/security.h),0)
  FLAGS += -DSEC_INET_CONN_REQUEST
endif
ifneq ($(shell $(grep) -c 'security_inet_conn_established' \
               $(KINC)/linux/security.h),0)
  FLAGS += -DSEC_INET_CONN_ESTABLISHED
endif
ifneq ($(wildcard $(KINC)/net/netevent.h),)
  FLAGS += -DNETEVENT
endif
ifneq ($(shell $(grep) -c 'kallsyms_lookup_name' $(KOBJ)/$(modulesymfile)),0)
  FLAGS += -DKALLSYMS_LOOKUP_NAME
endif
ifneq ($(shell $(grep) -c 'symbol_name' $(KINC)/linux/kprobes.h),0)
  FLAGS += -DKPROBES_SYMBOL_NAME
endif
kallsyms := $(shell $(grep) '[[:space:]]\+kallsyms_lookup_name$$' /proc/kallsyms |\
                    cut -d' ' -f1)
ifneq ($(kallsyms),)
  FLAGS += -DKALLSYMS_LOOKUP=0x$(kallsyms)
endif

ifneq ($(shell $(grep) -c 'skb_transport_offset' $(KINC)/linux/skbuff.h),0)
  FLAGS += -DT3_SKB_TRANSPORT_OFFSET
endif

ifneq ($(shell $(grep) -c 'ip_hdr' $(KINC)/linux/ip.h),0)
  FLAGS += -DT3_IP_HDR
endif

ifneq ($(shell $(grep) -c 'tcp_hdr' $(KINC)/linux/tcp.h),0)
  FLAGS += -DT3_TCP_HDR
endif

ifneq ($(shell $(grep) -c 'skb_reset_mac_header' $(KINC)/linux/skbuff.h),0)
  FLAGS += -DT3_RESET_MAC_HEADER
endif

ifneq ($(shell $(grep) -c 'netif_napi_add' $(KINC)/linux/netdevice.h),0)
  FLAGS += -DNAPI_UPDATE
endif

ifneq ($(shell $(grep) -c 'skb_mac_header' $(KINC)/linux/skbuff.h),0)
  FLAGS += -DT3_MAC_HEADER
endif

ifneq ($(shell $(grep) -c 'sk_filter_uncharge' $(KINC)/net/sock.h),0)
  FLAGS += -DSK_FILTER_UNCHARGE
endif

ifneq ($(shell $(grep) -c 'void inet_inherit_port' $(KINC)/net/inet_hashtables.h),0)
  FLAGS += -DINET_INHERIT_PORT
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

ifneq ($(shell $(grep) -c 'vlan_dev_real_dev' $(KINC)/linux/if_vlan.h),0)
  FLAGS += -DVLAN_DEV_API
endif

ifeq ($(shell [ -e  $(KINC)/linux/semaphore.h ] && echo 1), 1)
  FLAGS += -DLINUX_SEMAPHORE_H
endif

ifneq ($(shell $(grep) -c 'highest_sack' $(KINC)/linux/tcp.h),0)
  FLAGS += -DHIGHEST_SACK
endif

ifneq ($(shell $(grep) -c 'get_stats_count' $(KINC)/linux/ethtool.h),0)
  FLAGS += -DGET_STATS_COUNT
endif

ifeq ($(shell [ -e $(KINC)/net/inet_sock.h ] && echo 1),1)
  ifneq ($(shell $(grep) -c 'inet_daddr' $(KINC)/net/inet_sock.h),0)
    FLAGS += -DINET_PREFIX
  endif
endif

ifneq ($(shell $(grep) -c 'skb_dst_set' $(KINC)/linux/skbuff.h),0)
  FLAGS += -DSKB_DST_SET
endif

ifneq ($(shell $(grep) -c 'netdev_get_tx_queue' $(KINC)/linux/netdevice.h),0)
  FLAGS += -DMQ_TX
endif

ifneq ($(shell $(grep) -c 'alloc_etherdev_mq' $(KINC)/linux/etherdevice.h),0)
  FLAGS += -DALLOC_ETHERDEV_MQ_DEF
endif

ifneq ($(shell $(grep) -c 'skb_record_rx_queue' $(KINC)/linux/skbuff.h),0)
  FLAGS += -DSKB_RECORD_RX_QUEUE
endif

ifneq ($(shell $(grep) -c 'ctl_name' $(KINC)/linux/sysctl.h),0)
  FLAGS += -DSYSCTL_CTL_NAME
endif

ifneq ($(shell $(grep) -c 'NIPQUAD' $(KINC)/linux/kernel.h),0)
  FLAGS += -DCXGB3_NIPQUAD
endif

ifeq ($(shell $(grep) -c '__sk_add_backlog' $(KINC)/net/sock.h),0)
  FLAGS += -DCXGB3___SK_ADD_BACKLOG
endif

ifeq ($(shell $(grep) -c '_Bool' $(KINC)/linux/types.h),0)
  FLAGS += -DCXGB3_BOOL
endif

ifeq ($(shell [ -e  $(KINC)/linux/mutex.h ] && echo 1), 1)
  FLAGS += -DT3_LINUX_MUTEX_H
endif

ifneq ($(shell $(grep) -c 'usecs_to_jiffies' $(KINC)/linux/jiffies.h),0)
  FLAGS += -DUSECS_TO_JIFFIES
endif
