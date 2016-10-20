/*
 * Network offload device definitions.
 *
 * Copyright (C) 2003-2008 Chelsio Communications.  All rights reserved.
 *
 * Written by Dimitris Michailidis (dm@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef _OFFLOAD_DEV_H_
#define _OFFLOAD_DEV_H_

#include <linux/version.h>

struct neighbour;

/* Parameter values for offload_get_phys_egress() */
enum {
	TOE_OPEN,
	TOE_FAILOVER,
};

/* Parameter values for toe_failover() */
enum {
	TOE_ACTIVE_SLAVE,
	TOE_LINK_DOWN,
	TOE_LINK_UP,
	TOE_RELEASE,
	TOE_RELEASE_ALL,
	TOE_BOND_DOWN,
	TOE_BOND_UP,
};

#if defined(CONFIG_TCP_OFFLOAD) || defined(CONFIG_TCP_OFFLOAD_MODULE)
#include <linux/list.h>
#include <linux/netdevice.h>

#define TOENAMSIZ 16

/*
 * These definitions of the (struct net_device *)->priv_flags bits
 * IFF_OFFLOAD_TCPIP and IFF_OFFLOAD_TCPIP6 belong in include/linux/if.h but
 * haven't made it in yet.  Unfortunately, this exposes us to potential
 * conflict with definitins which are in that header file.  Up to Linux 2.6.36
 * the priv_flags field was an (unsigned short), in 2.6.37 and later it was
 * changed to an (unsigned int) -- a 32-bit field in all extant 2.6.37+ Linux
 * kernels.  We use the top two bits of priv_flags for our "OFFLOAD" flags but
 * we're still left with the problem that 2.6.36 introduced IFF_MACVLAN_PORT
 * (0x4000) and IFF_BRIDGE_PORT (0x8000) which use those last two bits in the
 * (unsigned short).
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,37)

#define IFF_OFFLOAD_TCPIP  (1U << 30)
#define IFF_OFFLOAD_TCPIP6 (1U << 31)

#else /* Linux < 2.6.37 */

/*
 * Check for the conflicting bits in Linux 2.6.36.  We probably need to find a
 * safer place for these two bits -- say in the bottom two bits if (struct
 * net_device *)->ec_ptr which we're already using for the pointer to our
 * (struct toedev *) -- but for now we'll deal with it as a conflict.
 */
#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,36)

#if defined(CONFIG_MACVLAN) || defined(CONFIG_MACVLAN_MODULE)
#error Cannot Offload IPv4 and config MACVLAN in Linux 2.6.36
#endif

#if defined(CONFIG_TCPV6_OFFLOAD)
#if defined(CONFIG_BRIDGE) || defined(CONFIG_BRIDGE_MODULE)
#error Cannot Offload IPv6 and config BRIDGE in Linux 2.6.36
#endif
#endif

#endif /* Linux == 2.6.36 */

#define IFF_OFFLOAD_TCPIP  (1U << 14)
#define IFF_OFFLOAD_TCPIP6 (1U << 15)

#endif /* Linux < 2.6.37 */

/* Get the toedev associated with a net_device */
#define TOEDEV(netdev) (*(struct toedev **)&(netdev)->ax25_ptr)

/* offload type ids */
enum {
	TOE_ID_CHELSIO_T1 = 1,
	TOE_ID_CHELSIO_T1C,
	TOE_ID_CHELSIO_T2,
	TOE_ID_CHELSIO_T3,
	TOE_ID_CHELSIO_T3B,
	TOE_ID_CHELSIO_T3C,
	TOE_ID_CHELSIO_T4
};

struct offload_id {
	unsigned int id;
	unsigned long data;
};

struct net_device;
struct tom_info;
struct proc_dir_entry;
struct sock;
struct sk_buff;

struct toedev {
	char name[TOENAMSIZ];       /* TOE device name */
	struct list_head toe_list;  /* for list linking */
	unsigned int ttid;          /* TOE type id */
	unsigned long flags;        /* device flags */
	unsigned int mtu;           /* max size of TX offloaded data */
	unsigned int nconn;         /* max # of offloaded connections */
	unsigned int nlldev;        /* # of associated Ethernet devices */
	struct net_device **lldev;  /* associated LL devices */
	struct tom_info *offload_mod; /* attached TCP offload module */
	struct offload_policy *policy;
	struct proc_dir_entry *proc_dir;    /* root of proc dir for this TOE */
	int (*open)(struct toedev *dev);
	int (*close)(struct toedev *dev);
	int (*can_offload)(struct toedev *dev, struct sock *sk);
	int (*connect)(struct toedev *dev, struct sock *sk,
		       struct net_device *egress_dev);
	int (*send)(struct toedev *dev, struct sk_buff *skb);
	int (*recv)(struct toedev *dev, struct sk_buff **skb, int n);
	int (*ctl)(struct toedev  *tdev, unsigned int req, void *data);
	void (*neigh_update)(struct toedev *dev, struct neighbour *neigh);
	void (*failover)(struct toedev *dev, struct net_device *bond_dev,
			 struct net_device *ndev, int event, struct net_device *last);
	void *priv;                 /* driver private data */
	void *l2opt;                /* optional layer 2 data */
	void *l3opt;                /* optional layer 3 data */
	void *l4opt;                /* optional layer 4 data */
	void *ulp;                  /* ulp stuff */
	bool *in_shutdown;
	struct completion shutdown_completion;
};

struct tom_info {
	int (*attach)(struct toedev *dev, const struct offload_id *entry);
	int (*detach)(struct toedev *dev);
	const char *name;
	const struct offload_id *id_table;
	struct module *owner;
	atomic_t refcnt;
	struct list_head list_node;
};

struct toe_hash_params {
	struct net_device *dev;
	struct neighbour *neigh;
	bool is_ipv6;
	u16 l4_prot;
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__be32 *s;
	__be32 *d;
};

static inline void init_offload_dev(struct toedev *dev)
{
	INIT_LIST_HEAD(&dev->toe_list);
}

static inline int netdev_is_offload(const struct net_device *dev)
{
	return dev->priv_flags & IFF_OFFLOAD_TCPIP;
}

static inline void netdev_set_offload(struct net_device *dev)
{
	dev->priv_flags |= IFF_OFFLOAD_TCPIP;
}

static inline void netdev_clear_offload(struct net_device *dev)
{
	dev->priv_flags &= ~IFF_OFFLOAD_TCPIP;
}

extern int tcp_sack_enabled(void);
extern int tcp_timestamps_enabled(void);
extern int tcp_win_scaling_enabled(void);
extern int tcp_ecn_enabled(struct net *net);
extern int register_tom(struct tom_info *t);
extern int unregister_tom(struct tom_info *t);
extern int register_toedev(struct toedev *dev, const char *name);
extern int unregister_toedev(struct toedev *dev);
extern int activate_offload(struct toedev *dev);
extern int deactivate_offload(struct toedev *dev);
extern int toe_send(struct toedev *dev, struct sk_buff *skb);
extern struct net_device *offload_get_phys_egress(struct toe_hash_params *hash_params,
						  int context);
extern void init_toe_hash_params(struct toe_hash_params *hash_params,
				 struct net_device *dev, struct neighbour *neigh,
				 __u32 saddr, __u32 daddr, __u16 sport, __u16 dport,
				 __be32 *s, __be32 *d, bool is_ipv6, u16 l4_prot);
#endif

#if defined(CONFIG_TCP_OFFLOAD_MODULE)
static inline int toe_receive_skb(struct toedev *dev, struct sk_buff **skb,
				  int n)
{
	return dev->recv(dev, skb, n);
}

extern int  prepare_tcp_for_offload(void);
extern void restore_tcp_to_nonoffload(void);
#elif defined(CONFIG_TCP_OFFLOAD)
extern int toe_receive_skb(struct toedev *dev, struct sk_buff **skb, int n);
#endif

#if defined(CONFIG_TCP_OFFLOAD) || \
    (defined(CONFIG_TCP_OFFLOAD_MODULE) && defined(MODULE))
extern void toe_neigh_update(struct neighbour *neigh);
extern int toe_failover(struct net_device *bond_dev,
			 struct net_device *fail_dev, int event,
			 struct net_device *last_dev);
extern int toe_enslave(struct net_device *bond_dev,
		       struct net_device *slave_dev);
extern void register_toe_bond_rr_select_cb(struct net_device* (*fn)(int slave_no, struct net_device *bond_dev));
extern void register_toe_bond_acb_select_cb(struct net_device* (*fn)(struct net_device *bond_dev));
extern void register_toe_bond_8023AD_select_cb(struct net_device* (*fn)(int slave_agg_no, struct net_device *dev));
extern void register_toe_bond_xor_select_cb(struct net_device* (*fn)(int slave_no, struct net_device *dev));
extern int toe_bond_get_hash(struct toe_hash_params *hash_params, int xmit_policy, int count);
#else
static inline void toe_neigh_update(struct neighbour *neigh) {}
static inline void toe_failover(struct net_device *bond_dev,
				struct net_device *fail_dev, int event,
				struct net_device *last_dev)
{}
static inline int toe_enslave(struct net_device *bond_dev,
			      struct net_device *slave_dev)
{
	return 0;
}
static inline void register_toe_bond_rr_select_cb(struct net_device* (*fn)(int slave_no,
									   struct net_device *bond_dev))
{
}
static inline void register_toe_bond_acb_select_cb(struct net_device* (*fn)(struct net_device *bond_dev))
{
}
static inline void register_toe_bond_8023AD_select_cb(struct net_device* (*fn)(int slave_agg_no,
									       struct net_device *dev))
{
}
static inline void register_toe_bond_xor_select_cb(struct net_device* (*fn)(int slave_no,
									    struct net_device *dev))
{
}
extern int toe_bond_get_hash(struct toe_hash_params *hash_params,
			     int xmit_policy, int count)
{
	return 0;
}

#endif /* CONFIG_TCP_OFFLOAD */

#endif /* _OFFLOAD_DEV_H_ */
