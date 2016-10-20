/*
 * Copyright (C) 2003-2006 Chelsio Communications.  All rights reserved.
 *
 * Written by Dimitris Michailidis (dm@chelsio.com),
 *	      Divy Le Ray (divy@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */
#ifndef __TOE_COMPAT_2_6_H
#define __TOE_COMPAT_2_6_H

/* semaphore.h is under include/linux for 2.6.27 */
#ifdef LINUX_SEMAPHORE_H
#include <linux/semaphore.h>
#else
#include <asm/semaphore.h>
#endif

#include <linux/version.h>
#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,9)
#define inet_sock inet_opt
#define SOCK_QUEUE_SHRUNK SOCK_TIMESTAMP
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,13)
#define DEFINE_MUTEX DECLARE_MUTEX
#define mutex_lock down
#define mutex_unlock up
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
#define T3_IP_INC_STATS_BH(net, field) IP_INC_STATS_BH(net, field)
#else
#define T3_IP_INC_STATS_BH(net, field) IP_INC_STATS_BH(field)
#endif

#if defined(KALLSYMS_LOOKUP_NAME)
#include <linux/kallsyms.h>
#endif /* KALLSYMS_LOOKUP_NAME */

#ifdef CONFIG_IA64
static inline int change_page_attr(struct page *page, int numpages,
				   pgprot_t prot)
{
	return 0;
}

static inline void global_flush_tlb(void)
{}

/* Unused dummy value */
#define PAGE_KERNEL_RO	__pgprot(0)
#endif

#ifdef LOOPBACK
static inline int ipv4_is_loopback(__be32 addr)
{
	return LOOPBACK(addr);
}
#endif

#if defined(CONFIG_XEN) && defined(CONFIG_XEN_TOE)
/* prevent collision with (struct mac_addr) definition in bond_3ad.h */
#define mac_addr __br_mac_addr
#include <net/bridge/br_private.h>
#undef mac_addr

#if defined(NETIF_F_TCPIP_OFFLOAD)
static inline void br_set_offload_mask(struct net_bridge *br)
{
	br->feature_mask |= NETIF_F_TCPIP_OFFLOAD;

}
#endif
#endif

/*
 * In Linux 3.1 dst->neighbour was removed and we now need to use the function
 * dst_neigh_lookup() which takes a reference on the neighbour.  These
 * compatibility routines encode that dependency.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)
static inline struct neighbour *t4_dst_neigh_lookup(const struct dst_entry *dst,
                                                    const void *daddr)
{
        return dst->neighbour;
}

static inline void t4_dst_neigh_release(struct neighbour *neigh)
{
}
#else
static inline struct neighbour *t4_dst_neigh_lookup(const struct dst_entry *dst,
                                                    const void *daddr)
{
        return dst_neigh_lookup(dst, daddr);
}

static inline void t4_dst_neigh_release(struct neighbour *neigh)
{
        neigh_release(neigh);
}
#endif

static inline int t4_get_sysctl_tcp_ecn(struct net *net)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
	extern int *sysctl_tcp_ecn_p;
	return *sysctl_tcp_ecn_p;
#else
	return net->ipv4.sysctl_tcp_ecn;
#endif
}
#endif
