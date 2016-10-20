/*
 * This file is part of the Chelsio T4/T5/T6 Virtual Function (VF) Ethernet
 * driver for Linux.
 *
 * Copyright (C) 2003-2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __CXGB4VF_COMPAT_H__
#define __CXGB4VF_COMPAT_H__

#include <linux/version.h>
#include "distro_compat.h"

/*
 * Compute a default TX hash of an skb.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
static inline u16 skb_tx_hash(const struct net_device *dev,
			      const struct sk_buff *skb)
{
	return 0;
}
#endif

/*
 * Set a /proc node's module owner field.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
#define SET_PROC_NODE_OWNER(_p, _owner) \
	do { (_p)->owner = (_owner); } while (0)
#else
#define SET_PROC_NODE_OWNER(_p, _owner) \
	do { } while (0)
#endif


/*
 * Collect up to maxaddrs worth of a netdevice's unicast addresses, starting
 * at a specified offset within the list, into an array of addrss pointers and
 * return the number collected.
 */
static inline unsigned int collect_netdev_uc_list_addrs(const struct net_device *dev,
							const u8 **addr,
							unsigned int offset,
							unsigned int maxaddrs)
{
	unsigned int index = 0;
	unsigned int naddr = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
	const struct dev_addr_list *da;

	for (da = dev->uc_list; da && naddr < maxaddrs; da = da->next)
		if (index++ >= offset)
			addr[naddr++] = da->dmi_addr;
#else
	const struct netdev_hw_addr *ha;

	for_each_dev_addr(dev, ha)
		if (index++ >= offset) {
			addr[naddr++] = ha->addr;
			if (naddr >= maxaddrs)
				break;
		}
#endif
	return naddr;
}

/*
 * Collect up to maxaddrs worth of a netdevice's multicast addresses, starting
 * at a specified offset within the list, into an array of addrss pointers and
 * return the number collected.
 */
static inline unsigned int collect_netdev_mc_list_addrs(const struct net_device *dev,
							const u8 **addr,
							unsigned int offset,
							unsigned int maxaddrs)
{
	unsigned int index = 0;
	unsigned int naddr = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
	const struct dev_addr_list *da;

	for (da = dev->mc_list; da && naddr < maxaddrs; da = da->next)
		if (index++ >= offset)
			addr[naddr++] = da->dmi_addr;
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2,6,34)
	const struct dev_mc_list *mclist;

	netdev_for_each_mc_addr(mclist, dev)
		if (index++ >= offset) {
			addr[naddr++] = mclist->dmi_addr;
			if (naddr >= maxaddrs)
				break;
		}
#else
	const struct netdev_hw_addr *ha;

	netdev_for_each_mc_addr(ha, dev)
		if (index++ >= offset) {
			addr[naddr++] = ha->addr;
			if (naddr >= maxaddrs)
				break;
		}
#endif
	return naddr;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35) && !defined(RHEL_RELEASE_6_0)
static inline int netif_set_real_num_tx_queues(struct net_device *dev,
					       unsigned int txq)
{
	dev->real_num_tx_queues = txq;
	return 0;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)
static inline int netif_set_real_num_rx_queues(struct net_device *dev,
					       unsigned int rxq)
{
	return 0;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37) && !defined(RHEL_RELEASE_6_1)
static inline void skb_checksum_none_assert(struct sk_buff *skb)
{
#ifdef DEBUG
	BUG_ON(skb->ip_summed != CHECKSUM_NONE);
#endif
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33) && !defined(RHEL_RELEASE_6_0)
static inline long __must_check IS_ERR_OR_NULL(const void *ptr)
{
	return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}
#endif
/*
 * Use fragment API to access the sk fragment page pointer.
 * This API was introduced in kernel 3.2.0, hence for previous
 * kernels we need to define this function.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0) && !defined(RHEL_RELEASE_6_3)
static inline struct page *skb_frag_page(const skb_frag_t *frag)
{
	return frag->page;
}

static inline void skb_frag_set_page(struct sk_buff *skb, int f,
		struct page *page)
{
	skb_shinfo(skb)->frags[f].page = page;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
#define NETIF_F_HW_VLAN_CTAG_RX	NETIF_F_HW_VLAN_RX
#define NETIF_F_HW_VLAN_CTAG_TX	NETIF_F_HW_VLAN_TX
#endif

#include <linux/if_vlan.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
static inline struct sk_buff *__vlan_hwaccel_put_ctag(struct sk_buff *skb,
						      u16 vlan_tci)
{
	return __vlan_hwaccel_put_tag(skb, vlan_tci);
}

#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
static inline struct sk_buff *
__vlan_hwaccel_put_ctag(struct sk_buff *skb, u16 vlan_tci)
{
	return __vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), vlan_tci);
}

#else
static inline void __vlan_hwaccel_put_ctag(struct sk_buff *skb,
					   u16 vlan_tci)
{
	__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), vlan_tci);
}
#endif

/*
 * Prior to 2.6.24 the Write memory Barrier macro was incorrectly defined for
 * the x86-64 architecture when CONFIG_UNORDERED_IO wasn't defined.  In that
 * case it simply expanded out to <<asm volatile("" ::: "memory")>> and didn't
 * include an "sfence" instruction.  This was fixed in kernel.org git commit
 * "4071c71" by Nick Piggin on October 13, 2007.  Because we need the Write
 * memory Barrier to be correctly defined for writes to T5's Write Combined
 * mapping of BAR2, we "fix" the Write Memory Barrier macro here for these
 * older kernels ...
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24) && \
	defined(CONFIG_X86_64) && \
	!defined(CONFIG_UNORDERED_IO)
#undef wmb
#define wmb()	asm volatile("sfence" ::: "memory")
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
#include <linux/pci.h>

static inline int pci_enable_msix_range(struct pci_dev *dev,
					struct msix_entry *entries,
					int minvec, int maxvec)
{
	int nvec = maxvec;
	int rc;

	if (maxvec < minvec)
		return -ERANGE;

	do {
		rc = pci_enable_msix(dev, entries, nvec);
		if (rc < 0) {
			return rc;
		} else if (rc > 0) {
			if (rc < minvec) {
				pci_disable_msix(dev);
				return -ENOSPC;
			}
			nvec = rc;
		}
	} while (rc);

	return nvec;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
#define skb_vlan_tag_present(__skb)	vlan_tx_tag_present(__skb)
#define skb_vlan_tag_get(__skb)		vlan_tx_tag_get(__skb)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
static inline struct page *__dev_alloc_pages(gfp_t gfp_mask,
					     unsigned int order)
{
	gfp_mask |= __GFP_COLD | __GFP_COMP | __GFP_MEMALLOC;

	return alloc_pages_node(NUMA_NO_NODE, gfp_mask, order);
}

static inline struct page *__dev_alloc_page(gfp_t gfp_mask)
{
	return __dev_alloc_pages(gfp_mask, 0);
}
#endif

#ifndef smp_mb__after_atomic
#define smp_mb__after_atomic()  smp_mb()
#endif

#ifndef dma_rmb
#define dma_rmb()	rmb()
#endif
#endif /* __CXGB4VF_COMPAT_H__ */
