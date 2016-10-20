/*
 * Copyright (C) 2003-2008 Chelsio Communications.  All rights reserved.
 *
 * Written by Dimitris Michailidis (dm@chelsio.com),
 *	      Divy Le Ray (divy@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */
#ifndef __TOE_COMPAT_H
#define __TOE_COMPAT_H

#include <linux/version.h>
#include "distro_compat.h"

/*
 * Pull in either Linux 2.6 or earlier compatibility definitions.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#include "toe_compat_2_6.h"
#else
#include "toe_compat_2_4.h"
#endif

#if !defined(for_each_netdev)
#define for_each_netdev(d) \
	for (d = dev_base; d; d = d->next)
#endif

#if !defined(NEW_SKB_OFFSET)
static inline void skb_reset_network_header(struct sk_buff *skb)
{
	skb->nh.raw = skb->data;
}
#endif

#if !defined(TRANSPORT_HEADER)
#define transport_header h.raw
#define network_header nh.raw
#endif

#if !defined(SEC_INET_CONN_ESTABLISHED)
static inline void security_inet_conn_established(struct sock *sk,
						  struct sk_buff *skb)
{}
#endif

#if defined(CONFIG_KPROBES) && defined(KPROBES_SYMBOL_NAME)
#define KPROBES_KALLSYMS
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
#define INET_PROC_DIR init_net.proc_net
#else
#define INET_PROC_DIR proc_net
#endif

#if !defined(VLAN_DEV_API)
#include <linux/if_vlan.h>
#if defined(VLAN_DEV_INFO)
static inline struct vlan_dev_info *vlan_dev_info(const struct net_device *dev)
{
	return VLAN_DEV_INFO(dev);
}
#endif

static inline u16 vlan_dev_vlan_id(const struct net_device *dev)
{
	return vlan_dev_info(dev)->vlan_id;
}

static inline struct net_device *vlan_dev_real_dev(const struct net_device *dev)
{
	return vlan_dev_info(dev)->real_dev;
}
#else /* VLAN_DEV_API */

#if defined(RHEL_RELEASE_5_7)
#include <linux/if_vlan.h>
static inline u16 vlan_dev_vlan_id(const struct net_device *dev)
{
	return VLAN_DEV_INFO(dev)->vlan_id;
}
#endif /* RHEL_RELEASE */
#endif /* VLAN_DEV_API */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
#define SET_PROC_NODE_OWNER(_p, _owner) \
	do { (_p)->owner = (_owner); } while (0)
#else
#define SET_PROC_NODE_OWNER(_p, _owner) \
	do { } while (0)
#endif

#if !defined(INET_PREFIX)
#define inet_daddr daddr
#define inet_rcv_saddr rcv_saddr
#define inet_dport dport
#define inet_saddr saddr
#define inet_sport sport
#define inet_id id
#endif

#if !defined(INIT_RCU_HEAD)
#define INIT_RCU_HEAD(ptr)
#endif

#if defined(RHEL_RELEASE_6_2)
#include <net/secure_seq.h>
#endif /* RHEL_RELEASE */

#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32)
#if !defined(GFP_MEMALLOC)
static inline gfp_t sk_allocation(struct sock *sk, gfp_t gfp_mask)
{
        return gfp_mask;
}
#endif /* GFP_MEMALLOC */
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
static inline void *PDE_DATA(const struct inode *inode)
{
	return PDE(inode)->data;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
#define netdev_notifier_info_to_dev(__data) ((struct net_device *)(__data))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)

typedef int bond_list_iter;

#define bond_for_each_slave_compat(__bond, __pos, __iter) \
	bond_for_each_slave(__bond, __pos, __iter)
#define bond_first_slave_compat(__bond) \
	(__bond)->first_slave
#define bond_is_last_slave(__bond, __pos) \
	((__pos)->next == bond_first_slave(__bond))

#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)

typedef int  __attribute__((unused)) bond_list_iter;

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

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0) && !defined(RHEL_RELEASE_7_0)
#define inet6_sk_saddr(__sk)	inet6_sk(__sk)->saddr
#define inet6_sk_rcv_saddr(__sk)	inet6_sk(__sk)->rcv_saddr
#define inet6_sk_daddr(__sk)	inet6_sk(__sk)->daddr
#else
#define inet6_sk_saddr(__sk)	inet6_sk(__sk)->saddr
#define inet6_sk_rcv_saddr(__sk)	(__sk)->sk_v6_rcv_saddr
#define inet6_sk_daddr(__sk)	(__sk)->sk_v6_daddr
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
#define net_random()		prandom_u32()
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
#define bond_slave_is_up(__slave) IS_UP((__slave)->dev)
#define bond_slave_can_tx(__slave) SLAVE_IS_OK(__slave)
#endif

/*
 * A little complicated here.  The Bond Slave AD Information used to be an
 * embedded structure within the (struct slave) and is now a pointer to
 * a separately allocated structure.  So SLAVE_AD_INFO() used to be a
 * reference to that embedded structure and we'd see uses of code like
 *
 *     SLAVE_AD_INFO(slave).port
 *
 * but these now need to be
 *
 *     SLAVE_AD_INFO(slave)->port
 *
 * So we give ourselves a compatibility definition which work more like the
 * new one.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
#define SLAVE_AD_INFO_COMPAT(__slave) \
	(&SLAVE_AD_INFO(__slave))
#else
#define SLAVE_AD_INFO_COMPAT(__slave) \
	SLAVE_AD_INFO(__slave)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0)
#define bond_read_lock_compat(__bond)	read_lock(&(__bond)->lock);
#define bond_read_unlock_compat(__bond)	read_unlock(&(__bond)->lock);
#else
#define bond_read_lock_compat(__bond)	rcu_read_lock();
#define bond_read_unlock_compat(__bond)	rcu_read_unlock();
#endif

#endif /* __TOE_COMPAT_H */
