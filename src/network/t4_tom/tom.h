/*
 * Copyright (C) 2003-2015 Chelsio Communications.  All rights reserved.
 *
 * Written by Dimitris Michailidis (dm@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef _CHELSIO_TOM_T4_H
#define _CHELSIO_TOM_T4_H

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/cache.h>
#include <linux/delay.h>
#include <linux/workqueue.h>
#include <linux/skbuff.h>
#include <linux/toedev.h>
#include <asm/atomic.h>
#include "t4_hw.h"

struct sock;
struct cxgb4_lld_info;

#define S_TP_VERSION_MAJOR              16
#define M_TP_VERSION_MAJOR              0xFF
#define V_TP_VERSION_MAJOR(x)           ((x) << S_TP_VERSION_MAJOR)
#define G_TP_VERSION_MAJOR(x)           \
            (((x) >> S_TP_VERSION_MAJOR) & M_TP_VERSION_MAJOR)

#define S_TP_VERSION_MINOR              8
#define M_TP_VERSION_MINOR              0xFF
#define V_TP_VERSION_MINOR(x)           ((x) << S_TP_VERSION_MINOR)
#define G_TP_VERSION_MINOR(x)           \
            (((x) >> S_TP_VERSION_MINOR) & M_TP_VERSION_MINOR)

#define S_TP_VERSION_MICRO              0
#define M_TP_VERSION_MICRO              0xFF
#define V_TP_VERSION_MICRO(x)           ((x) << S_TP_VERSION_MICRO)
#define G_TP_VERSION_MICRO(x)           \
            (((x) >> S_TP_VERSION_MICRO) & M_TP_VERSION_MICRO)

enum {
	TP_VERSION_MAJOR = 1,
	TP_VERSION_MINOR = 1,
	TP_VERSION_MICRO = 0
};

struct listen_info {
	struct listen_info *next;  /* Link to next entry */
	struct sock *sk;           /* The listening socket */
	unsigned int stid;         /* The server TID */
};

/*
 * TOM tunable parameters.  They can be manipulated through sysctl(2) or /proc.
 */
struct tom_tunables {
	int max_host_sndbuf;	// max host RAM consumed by a sndbuf
	int tx_hold_thres;	// push/pull threshold for non-full TX sk_buffs
	int max_wr_credits;     // max # of outstanding WR credits per connection
	int rx_credit_thres;	// min # of RX credits needed for RX_DATA_ACK
	int mss;		// max TX_DATA WR payload size
	int delack;		// delayed ACK control
	int max_conn;		// maximum number of offloaded connections
	int soft_backlog_limit;	// whether the listen backlog limit is soft
	int kseg_ddp;
	int ddp;		// whether to put new connections in DDP mode
	int ddp_thres;          // min recvmsg size before activating DDP (default)
	int ddp_xlthres;	// min recvmsg size before activating DDP (40Gbps)
	int ddp_maxpages;	// max pages for DDP buffer to limit pods/buffer
	int ddp_maxfail;	// max failures for DDP buffer allocation/post
	int ddp_copy_limit;     // capacity of kernel DDP buffer
	int ddp_push_wait;      // whether blocking DDP waits for PSH flag
	int ddp_rcvcoalesce;    // whether receive coalescing is enabled
#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
	int zcopy_sendmsg_partial_thres; // < is never zcopied
	int zcopy_sendmsg_partial_xlthres; // < is never zcopied for 40G
	int zcopy_sendmsg_partial_copy; // bytes copied in partial zcopy
	int zcopy_sendmsg_ret_pending_dma;// pot. return while pending DMA
#endif
	int activated;		// TOE engine activation state
	int cop_managed_offloading;// offloading decisions managed by a COP
#if defined(CONFIG_CHELSIO_IO_SPIN)
	int recvmsg_spin_us;	// time to spin in recvmsg() for input data
#endif
	int recvmsg_ddp_wait_us; // time to wait for ddp invalidate in recvmsg()
	int lro; /* LRO enabled/disabled */

	/*
	 * This code demonstrates how one would selectively Offload
	 * (TOE) certain incoming connections by using the extended
	 * "Filter Information" capabilities of Server Control Blocks
	 * (SCB).  (See "Classification and Filtering" in the T4 Data
	 * Book for a description of Ingress Packet pattern matching
	 * capabilities.  See also documentation on the
	 * TP_VLAN_PRI_MAP register.)  Because this selective
	 * Offloading is happening in the chip, this allows
	 * non-Offloading and Offloading drivers to coexist.  For
	 * example, an Offloading Driver might be running in a
	 * Hypervisor while non-Offloading vNIC Drivers might be
	 * running in Virtual Machines.
	 *
	 * This particular example code demonstrates how one would
	 * selectively Offload incoming connections based on VLANs.
	 * We allow one VLAN to be designated as the "Offloading
	 * VLAN".  Ingress SYNs on this Offload VLAN will match the
	 * filter which we put into the Listen SCB and will result in
	 * Offloaded Connections on that VLAN.  Incoming SYNs on other
	 * VLANs will not match and will go through normal NIC
	 * processing.
	 *
	 * This is not production code since one would want a lot more
	 * infrastructure to allow a variety of filter specifications
	 * on a per-server basis.  But this demonstrates the
	 * fundamental mechanisms one would use to build such an
	 * infrastructure.
	 */
	int offload_vlan;
};

#define FAILOVER_MAX_ATTEMPTS 5

struct tom_sysctl_table;
struct pci_dev;
struct tom_data;

#define LISTEN_INFO_HASH_SIZE 32
#define TOM_RSPQ_HASH_BITS 5

typedef int (*t4tom_cpl_handler_func)(struct tom_data *td,
                                      struct sk_buff *skb);

struct tom_data {
	struct list_head list_node;
	struct pci_dev *pdev;
	struct toedev tdev;
	struct cxgb4_lld_info *lldi;

	struct tom_tunables conf;
	struct tom_sysctl_table *sysctl;

	/*
	 * The next three locks listen_lock, deferq.lock, and tid_release_lock
	 * are used rarely so we let them potentially share a cacheline.
	 */

	struct listen_info *listen_hash_tab[LISTEN_INFO_HASH_SIZE];
	spinlock_t listen_lock;

	struct sk_buff_head deferq;
	struct work_struct deferq_task;

	struct sock **tid_release_list;
	spinlock_t tid_release_lock;
	struct work_struct tid_release_task;

#ifdef T4_TRACE_TOM
#define T4_TRACE_TOM_BUFFERS 8
	struct dentry *debugfs_root;
	struct trace_buf *tb[T4_TRACE_TOM_BUFFERS];
#endif

	unsigned int pfvf;
	unsigned int ddp_llimit;

	unsigned long *ppod_bmap;
	unsigned int nppods;
	unsigned int start_tag;
	spinlock_t ppod_map_lock;

	struct adap_ports *ports;
	const unsigned short *mtus;
	struct tid_info *tids;
	unsigned int rss_qid;
	unsigned int tx_max_chunk;
	unsigned int max_wr_credits;
	unsigned int send_page_order;
	unsigned int offload_vlan;
	struct net_device *egr_dev[NCHAN*2]; // Ports + Loopback

	/*
	 * Synchronizes access to the various SYN queues.  We assume that SYN
	 * queue accesses do not cause much contention so that one lock for all
	 * the queues suffices.  This is because the primary user of this lock
	 * is the TOE softirq, which runs on one CPU and so most accesses
	 * should be naturally contention-free.  The only contention can come
	 * from listening sockets processing backlogged messages, and that
	 * should not be high volume.
	 */
	spinlock_t synq_lock ____cacheline_aligned_in_smp;

	int round_robin_cnt;
#ifdef DEBUG
	atomic_t rspq_alloc_count;
	atomic_t rspq_reuse_count;
#endif
	struct sk_buff *rspq_skb_cache[1 << TOM_RSPQ_HASH_BITS];
	struct list_head rcu_node;
	struct list_head na_node;
};

enum {
	T4_LISTEN_START_PENDING,
	T4_LISTEN_STARTED
};

struct listen_ctx {
	struct sock *lsk;
	struct tom_data *tom_data;
	u32 state;
};

#include "cpl_io_state.h"

/*
 * toedev -> tom_data accessor
 */
#define TOM_DATA(dev) container_of(dev, struct tom_data, tdev)

#ifdef T4_TRACE_TOM
static inline struct trace_buf *TIDTB(struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct toedev *tdev = cplios->toedev;

	if (tdev == NULL)
		return NULL;
	return TOM_DATA(tdev)->tb[cplios->tid % T4_TRACE_TOM_BUFFERS];
}
#endif

#define RX_PULL_LEN 128
/*
 * Access a configurable parameter of a TOE device's TOM.
 */
#define TOM_TUNABLE(dev, param) (TOM_DATA(dev)->conf.param)

static inline int cxgb4_sk_l2t_send(struct net_device *dev, struct sk_buff *skb,
			     struct l2t_entry *e, struct sock *sk)
{
#if defined(CONFIG_TCPV6_OFFLOAD)
	return cxgb4_l2t_send(dev, skb, e, &inet6_sk_rcv_saddr(sk),__sk_dst_get(sk));
#else
	return cxgb4_l2t_send(dev, skb, e, NULL, NULL);
#endif
}

void t4_init_tunables(struct tom_data *t);
void t4_sysctl_unregister(struct tom_sysctl_table *t);
struct tom_sysctl_table *t4_sysctl_register(struct toedev *dev,
					    const struct tom_tunables *p);
#endif
