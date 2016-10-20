/*
 * This file is part of the Chelsio T4 Ethernet driver.
 *
 * Copyright (C) 2003-2009 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

/*
 * This file is used to allow the driver to be compiled under multiple
 * versions of Linux with as few obtrusive in-line #ifdef's as possible.
 */

#ifndef __CXGB4_COMPAT_H
#define __CXGB4_COMPAT_H

#include <linux/version.h>
#include <net/inet6_hashtables.h>
#include "common.h"
#include "distro_compat.h"
#include <linux/pci.h>
#if defined(CONFIG_NET_RX_BUSY_POLL)
#include <net/busy_poll.h>
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
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
	const struct netdev_hw_addr *ha;

	list_for_each_entry(ha, &dev->uc.list, list)
		if (index++ >= offset) {
			addr[naddr++] = ha->addr;
			if (naddr >= maxaddrs)
				break;
		}
#else
	const struct netdev_hw_addr *ha;

	netdev_for_each_uc_addr(ha, dev)
		if (index++ >= offset) {
			addr[naddr++] = ha->addr;
			if (naddr >= maxaddrs)
				break;
		}
#endif
	return naddr;
}

#ifndef mult_frac
#define mult_frac(x, numer, denom)(                     \
{                                                       \
        typeof(x) quot = (x) / (denom);                 \
        typeof(x) rem  = (x) % (denom);                 \
        (quot * (numer)) + ((rem * (numer)) / (denom)); \
}                                                       \
)
#endif

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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37) && !defined(RHEL_RELEASE_6_4)
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

#ifndef NIPQUAD
#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
#endif

#ifndef NIPQUAD_FMT
#define NIPQUAD_FMT "%u.%u.%u.%u"
#endif

#ifndef PORT_DA
#define PORT_DA 0x05
#endif
#ifndef PORT_OTHER
#define PORT_OTHER 0xff
#endif

#ifndef VLAN_PRIO_MASK
#define VLAN_PRIO_MASK		0xe000
#endif
#ifndef VLAN_PRIO_SHIFT
#define VLAN_PRIO_SHIFT		13
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
#include <net/ipv6.h>
#include <net/ndisc.h>

#define ND_DEBUG 1

#define ND_PRINTK(val, level, fmt, ...)				\
do {								\
	if (val <= ND_DEBUG)					\
		net_##level##_ratelimited(fmt, ##__VA_ARGS__);	\
} while (0)

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
/* got moved from net/ipv6/ndisc.c to include/net/ndisc.h in Linux 3.9 */
static inline int ndisc_opt_addr_space(struct net_device *dev)
{
	return NDISC_OPT_SPACE(dev->addr_len + ndisc_addr_option_pad(dev->type));
}
#endif

static u8 *ndisc_fill_addr_option(u8 *opt, int type, void *data, int data_len,
				  unsigned short addr_type)
{
	int pad   = ndisc_addr_option_pad(addr_type);
	int space = NDISC_OPT_SPACE(data_len + pad);

	opt[0] = type;
	opt[1] = space>>3;

	memset(opt + 2, 0, pad);
	opt   += pad;
	space -= pad;

	memcpy(opt+2, data, data_len);
	data_len += 2;
	opt += data_len;
	if ((space -= data_len) > 0)
		memset(opt, 0, space);
	return opt + space;
}

static inline int ip6_nd_hdr_inline(struct sock *sk, struct sk_buff *skb,
				    struct net_device *dev,
				    const struct in6_addr *saddr,
				    const struct in6_addr *daddr,
				    int proto, int len)
{
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct ipv6hdr *hdr;

	skb->protocol = htons(ETH_P_IPV6);
	skb->dev = dev;

	skb_reset_network_header(skb);
	skb_put(skb, sizeof(struct ipv6hdr));
	hdr = ipv6_hdr(skb);

	*(__be32*)hdr = htonl(0x60000000);

	hdr->payload_len = htons(len);
	hdr->nexthdr = proto;
	hdr->hop_limit = np->hop_limit;

	hdr->saddr = *saddr;
	hdr->daddr = *daddr;

	return 0;
}

static inline struct sk_buff *ndisc_build_skb(struct net_device *dev,
					      const struct in6_addr *daddr,
					      const struct in6_addr *saddr,
					      struct icmp6hdr *icmp6h,
					      const struct in6_addr *target,
					      int llinfo)
{
	struct net *net = dev_net(dev);
	struct sock *sk = net->ipv6.ndisc_sk;
	struct sk_buff *skb;
	struct icmp6hdr *hdr;
	int hlen = LL_RESERVED_SPACE(dev);
	int tlen = dev->needed_tailroom;
	int len;
	int err;
	u8 *opt;

	if (!dev->addr_len)
		llinfo = 0;

	len = sizeof(struct icmp6hdr) + (target ? sizeof(*target) : 0);
	if (llinfo)
		len += ndisc_opt_addr_space(dev);

	skb = sock_alloc_send_skb(sk,
				  (MAX_HEADER + sizeof(struct ipv6hdr) +
				   len + hlen + tlen),
				  1, &err);
	if (!skb) {
		ND_PRINTK(0, err, "ND: %s failed to allocate an skb, err=%d\n",
			  __func__, err);
		return NULL;
	}

	skb_reserve(skb, hlen);
	ip6_nd_hdr_inline(sk, skb, dev, saddr, daddr, IPPROTO_ICMPV6, len);

	skb_set_mac_header(skb, 0);
	skb_set_network_header(skb, skb->len);

	skb_put(skb, len);
	skb_set_transport_header(skb, skb->len);
	
	hdr = (struct icmp6hdr *)icmp6_hdr(skb);
	memcpy(hdr, icmp6h, sizeof(*hdr));

	opt = skb_transport_header(skb) + sizeof(struct icmp6hdr);
	if (target) {
		*(struct in6_addr *)opt = *target;
		opt += sizeof(*target);
	}

	if (llinfo)
		ndisc_fill_addr_option(opt, llinfo, dev->dev_addr,
				       dev->addr_len, dev->type);

	hdr->icmp6_cksum = csum_ipv6_magic(saddr, daddr, len,
					   IPPROTO_ICMPV6,
					   csum_partial(hdr,
							len, 0));

	return skb;
}
#endif
#endif /* LINUX_VERSION_CODE >= 3.8.0 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
static inline bool netif_is_bond_slave(struct net_device *dev)
{
        return dev->flags & IFF_SLAVE && dev->priv_flags & IFF_BONDING;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
#define kstrtoul strict_strtoul
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
static inline struct net_device *netdev_master_upper_dev_get(struct net_device *dev)
{
	return dev->master;
}

#define netdev_master_upper_dev_get_rcu netdev_master_upper_dev_get
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
#define NETIF_F_HW_VLAN_CTAG_RX	NETIF_F_HW_VLAN_RX
#define NETIF_F_HW_VLAN_CTAG_TX	NETIF_F_HW_VLAN_TX
#endif

#include <linux/if_vlan.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)

static inline struct sk_buff *
__vlan_hwaccel_put_ctag(struct sk_buff *skb, u16 vlan_tci)
{
	return __vlan_hwaccel_put_tag(skb, vlan_tci);
}

static inline struct net_device *
__vlan_find_dev_deep_ctag(struct net_device *real_dev, u16 vlan_id)
{
        return __vlan_find_dev_deep(real_dev, vlan_id);
}

#else

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
static inline struct sk_buff *
__vlan_hwaccel_put_ctag(struct sk_buff *skb, u16 vlan_tci)
{
	return __vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), vlan_tci);
}

#else
static inline void
__vlan_hwaccel_put_ctag(struct sk_buff *skb, u16 vlan_tci)
{
	__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), vlan_tci);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
static inline struct net_device *
__vlan_find_dev_deep_ctag(struct net_device *real_dev, u16 vlan_id)
{
        return __vlan_find_dev_deep(real_dev, htons(ETH_P_8021Q), vlan_id);
}
#else
static inline struct net_device *
__vlan_find_dev_deep_ctag(struct net_device *real_dev, u16 vlan_id)
{
	return __vlan_find_dev_deep_rcu(real_dev, htons(ETH_P_8021Q), vlan_id);
}
#endif

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)

typedef int bond_list_iter;

#define bond_for_each_slave_compat(__bond, __pos, __iter) \
	bond_for_each_slave(__bond, __pos, __iter)
#define bond_first_slave_compat(__bond) \
	(__bond)->first_slave
#define bond_is_last_slave(__bond, __pos) \
	((__pos)->next == bond_first_slave(__bond))
#define bond_next_slave(__bond, __pos) \
	(bond_is_last_slave(__bond, __pos) \
	 ? bond_first_slave(__bond) \
	 : (__pos)->next)

#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)

typedef int bond_list_iter __attribute__((unused));

#define bond_first_slave_compat(__bond) \
        bond_first_slave(__bond)

#define bond_for_each_slave_compat(__bond, __pos, __iter) \
	bond_for_each_slave(__bond, __pos)

#else

typedef struct list_head * bond_list_iter;
	

#define bond_for_each_slave_compat(__bond, __pos, __iter) \
	bond_for_each_slave(__bond, __pos, __iter)

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0)
#define bond_first_slave_compat(__bond) \
        bond_first_slave(__bond)
#else
#define bond_first_slave_compat(__bond) \
        bond_first_slave_rcu(__bond)
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0)
#define bond_for_each_slave_rcu_compat(__bond, __pos, __iter) \
        bond_for_each_slave_compat(__bond, __pos, __iter)
#else
#define bond_for_each_slave_rcu_compat(__bond, __pos, __iter) \
        bond_for_each_slave_rcu(__bond, __pos, __iter)
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0) && !defined(RHEL_RELEASE_7_0)
#define inet6_sk_saddr(__sk)	inet6_sk(__sk)->saddr
#define inet6_sk_rcv_saddr(__sk)	inet6_sk(__sk)->rcv_saddr
#define inet6_sk_daddr(__sk)	inet6_sk(__sk)->daddr
#else
#define inet6_sk_saddr(__sk)	inet6_sk(__sk)->saddr
#define inet6_sk_rcv_saddr(__sk)	(__sk)->sk_v6_rcv_saddr
#define inet6_sk_daddr(__sk)	(__sk)->sk_v6_daddr
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
#if !defined(NUMA_NO_NODE)
#include <asm/numa.h>
#endif
static inline int netdev_queue_numa_node_read(void)
{
	return NUMA_NO_NODE;
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38)
#if !defined(NUMA_NO_NODE)
#include <asm/numa.h>
#endif
static inline int netdev_queue_numa_node_read(const struct netdev_queue *q)
{
	return NUMA_NO_NODE;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
static inline void *kzalloc_node(size_t size, gfp_t flags, int node)
{
	return kzalloc(size, flags);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
/* PCI Express Capability access functions are not supported 
 * for kernel version <3.7.
 * Hence replacing it with original PCI accessors.
 */
#include <linux/pci.h>
static inline void pcie_capability_set_word(struct pci_dev *dev, int pos,
					    u16 val)
{
	u16 v;

	pos = pci_pcie_cap(dev);
	if (pos > 0) {
		pci_read_config_word(dev, pos + PCI_EXP_DEVCTL, &v);
		v |= PCI_EXP_DEVCTL_RELAX_EN;
		pci_write_config_word(dev, pos + PCI_EXP_DEVCTL, v);
	}
}

static inline void pcie_capability_read_word(struct pci_dev *dev, int pos,
					     u16 *val)
{
	if (pci_pcie_cap(dev) > 0)
		pci_read_config_word(dev, pos + pci_pcie_cap(dev), val);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
static inline unsigned int cxgb4_get_napi_id(struct napi_struct *napi)
{
	return 0;
}

static inline void cxgb4_skb_mark_napi_id(struct sk_buff *skb,
					  struct napi_struct *napi)
{
}

static inline void cxgb4_napi_hash_add(struct napi_struct *napi)
{
}

static inline void cxgb4_napi_hash_del(struct napi_struct *napi)
{
}
#else
static inline unsigned int cxgb4_get_napi_id(struct napi_struct *napi)
{
	return napi->napi_id;
}

static inline void cxgb4_skb_mark_napi_id(struct sk_buff *skb,
					  struct napi_struct *napi)
{
	skb_mark_napi_id(skb, napi);
}

static inline void cxgb4_napi_hash_add(struct napi_struct *napi)
{
	napi_hash_add(napi);
}

static inline void cxgb4_napi_hash_del(struct napi_struct *napi)
{
	napi_hash_del(napi);
}
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

#define  PCI_EXP_LNKSTA_CLS_8_0GB 0x0003 /* Current Link Speed 8.0GT/s */
#define  PCI_EXP_LNKSTA_NLW_X1 0x0010  /* Current Link Width x1 */
#define  PCI_EXP_LNKSTA_NLW_X2 0x0020  /* Current Link Width x2 */
#define  PCI_EXP_LNKSTA_NLW_X4 0x0040  /* Current Link Width x4 */
#define  PCI_EXP_LNKSTA_NLW_X8 0x0080  /* Current Link Width x8 */
#endif

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
static inline unsigned int t4_inet6_ehashfn(struct net *net,
					    const struct in6_addr *laddr,
					    const u16 lport,
					    const struct in6_addr *faddr,
					    const __be16 fport)
{
	static u32 inet6_ehash_secret __read_mostly;
	static u32 ipv6_hash_secret __read_mostly;

	u32 lhash, fhash;

	net_get_random_once(&inet6_ehash_secret, sizeof(inet6_ehash_secret));
	net_get_random_once(&ipv6_hash_secret, sizeof(ipv6_hash_secret));

	lhash = (__force u32)laddr->s6_addr32[3];
	fhash = __ipv6_addr_jhash(faddr, ipv6_hash_secret);

	return __inet6_ehashfn(lhash, lport, fhash, fport,
			       inet6_ehash_secret + net_hash_mix(net));
}
#else
static inline unsigned int t4_inet6_ehashfn(struct net *net,
					    const struct in6_addr *laddr,
					    const u16 lport,
					    const struct in6_addr *faddr,
					    const __be16 fport)
{
	return inet6_ehashfn(net, laddr, lport, faddr, fport);
}
#endif
#else
static inline unsigned int t4_inet6_ehashfn(struct net *net,
					    const struct in6_addr *laddr,
					    const u16 lport,
					    const struct in6_addr *faddr,
					    const __be16 fport)
{
	return 0;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0)
#define bond_read_lock_compat(__bond)	read_lock(&(__bond)->lock);
#define bond_read_unlock_compat(__bond)	read_unlock(&(__bond)->lock);

#else

#define bond_read_lock_compat(__bond)	rcu_read_lock();
#define bond_read_unlock_compat(__bond)	rcu_read_unlock();
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
#define skb_vlan_tag_present(__skb)	vlan_tx_tag_present(__skb)
#define skb_vlan_tag_get(__skb)		vlan_tx_tag_get(__skb)
#endif

#ifndef smp_mb__after_atomic
#define smp_mb__after_atomic()  smp_mb()
#endif

#ifndef smp_mb__before_atomic
#define smp_mb__before_atomic()  smp_mb()
#endif

#ifndef dma_rmb
#define dma_rmb()	rmb()
#endif
#endif  /* !__CXGB4_COMPAT_H */
