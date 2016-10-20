/*
 * This file is part of the Chelsio T4/T5/T6 Ethernet driver for Linux.
 *
 * Copyright (C) 2003-2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

/* This file should not be included directly.  Include common.h instead. */

#ifndef __T4_ADAPTER_H__
#define __T4_ADAPTER_H__

#include <linux/pci.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/timer.h>
#include <linux/cache.h>
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
#include <linux/toedev.h>
#endif
#include <linux/bitops.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/list_nulls.h>
#include <linux/netdevice.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
#include <linux/net_tstamp.h>
#endif
#include <asm/io.h>
#ifdef CONFIG_PO_FCOE
#include "cxgb4_fcoe.h"
#endif /* CONFIG_PO_FCOE */
#include "cxgb4_ofld.h"
#include "t4_regs_values.h"
#include "cxgb4_dcb.h"
#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
#include <linux/ptp_clock_kernel.h>
#include <linux/ptp_classify.h>
#include "cxgb4_ptp.h"
#endif

#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,12,0))
#include <net/vxlan.h>
#endif

#ifdef T4_TRACE
# include "trace.h"
# define NTRACEBUFS 8
#endif

#define CH_ERR(adap, fmt, ...)   dev_err(adap->pdev_dev, fmt, ## __VA_ARGS__)
#define CH_WARN(adap, fmt, ...)  dev_warn(adap->pdev_dev, fmt, ## __VA_ARGS__)
#define CH_ALERT(adap, fmt, ...) dev_alert(adap->pdev_dev, fmt, ## __VA_ARGS__)

#define CH_WARN_RATELIMIT(adap, fmt, ...)  do {\
	if (printk_ratelimit()) \
		dev_warn(adap->pdev_dev, fmt, ## __VA_ARGS__); \
} while (0)

/*
 * More powerful macro that selectively prints messages based on msg_enable.
 * For info and debugging messages.
 */
#define CH_MSG(adapter, level, category, fmt, ...) do { \
	if ((adapter)->msg_enable & NETIF_MSG_##category) \
		dev_printk(KERN_##level, adapter->pdev_dev, fmt, \
			   ## __VA_ARGS__); \
} while (0)

#ifdef DEBUG
# define CH_DBG(adapter, category, fmt, ...) \
	CH_MSG(adapter, DEBUG, category, fmt, ## __VA_ARGS__)
#else
# define CH_DBG(adapter, category, fmt, ...)
#endif

/*
 * XXX It's not clear that we need this anymore now
 * XXX that we have mailbox logging ...
 */
#define CH_DUMP_MBOX(adap, mbox, data_reg, size) \
	CH_MSG(adap, INFO, MBOX, \
	       "mbox %u: %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n", (mbox), \
	       (unsigned long long)t4_read_reg64(adap, data_reg), \
	       (unsigned long long)t4_read_reg64(adap, data_reg + 8), \
	       (unsigned long long)t4_read_reg64(adap, data_reg + 16), \
	       (unsigned long long)t4_read_reg64(adap, data_reg + 24), \
	       (unsigned long long)t4_read_reg64(adap, data_reg + 32), \
	       (unsigned long long)t4_read_reg64(adap, data_reg + 40), \
	       (unsigned long long)t4_read_reg64(adap, data_reg + 48), \
	       (unsigned long long)t4_read_reg64(adap, data_reg + 56));

/* Additional NETIF_MSG_* categories */
#define NETIF_MSG_DDRFILTER	0x2000000
#define NETIF_MSG_MBOX		0x4000000
#define NETIF_MSG_MMIO		0x8000000
#define NETIF_MSG_DCBX		0x1000000

enum {
	MAX_ETH_QSETS = 64,           /* # of Ethernet Tx/Rx queue sets */
	MAX_OFLD_QSETS = 64,          /* # of offload Tx/Rx queue sets */
	MAX_CTRL_QUEUES = NCHAN,      /* # of control Tx queues */
	MAX_RDMA_QUEUES = NCHAN,      /* # of streaming RDMA Rx queues */
	MAX_RDMA_CIQS = 32,           /* # of RDMA concentrator IQs */
	MAX_ISCSI_QUEUES = NCHAN*8,   /* # of streaming iSCSI Rx queues */
	MAX_TRACE_QUEUES = NCHAN,     /* # of Trace Rx queueus */
	MAX_HFILTER_QUEUES = NCHAN,   /* # of Hash Filter queues */
	MAX_FAILOVER_QUEUES = 1,      /* # of Failover queues */
	DEFAULT_OFLD_QSETS   = 32,    /* # of OFLD queues (default) */
	DEFAULT_RDMA_CIQS    = 32,    /* # of RDMA CIQs   (default) */
};

enum {
	MAX_TXQ_ENTRIES      = 16384,
	MAX_CTRL_TXQ_ENTRIES = 1024,
	MAX_RSPQ_ENTRIES     = 16384,
	MAX_RX_BUFFERS       = 16384,
	MIN_TXQ_ENTRIES      = 32,
	MIN_CTRL_TXQ_ENTRIES = 32,
	MIN_RSPQ_ENTRIES     = 128,
	MIN_FL_ENTRIES       = 16
};

/* Adapter flags for vxlan offload support for T5 */
enum {
	VXLAN_TX_OFFLOAD,
	VXLAN_RX_OFFLOAD              /* Set when promisc mode is enabled */
};

enum {
	VXLAN_TXQ_RUNNING             /* VxLAN lopback Tx queue lock */
};

/* PCI bus speeds */
enum terminator_bus_speed {
	terminator_bus_speed_unknown  = 0,
	terminator_bus_speed_33       = 33,
	terminator_bus_speed_66       = 66,
	terminator_bus_speed_100      = 100,
	terminator_bus_speed_120      = 120,
	terminator_bus_speed_133      = 133,
	terminator_bus_speed_2500     = 2500,
	terminator_bus_speed_5000     = 5000,
	terminator_bus_speed_8000     = 8000,
	terminator_bus_speed_reserved
};

/* PCI bus widths */
enum terminator_bus_width {
	terminator_bus_width_unknown  = 0,
	terminator_bus_width_pcie_x1  = 1,
	terminator_bus_width_pcie_x2  = 2,
	terminator_bus_width_pcie_x4  = 4,
	terminator_bus_width_pcie_x8  = 8,
	terminator_bus_width_32       = 32,
	terminator_bus_width_64       = 64,
	terminator_bus_width_reserved
};

#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0))
/* Maximum header size for an encapsulated packet */
#define MAX_ENCAP_HDR_SIZE (VXLAN6_HEADROOM + ETH_HLEN + VLAN_HLEN +\
			    MAX_IPOPTLEN + MAX_TCP_OPTION_SPACE)

/* vxlan_gro_receive expects all the headers to be in the same skb fragment
 * for better performance. Since after loopback we receive the inner packet
 * followed by outer header, we need to copy the outer header and inner header
 * into a separate fragment. For this we will allocate and use
 * below per RxQ page.
 */
struct vxlan_buf_for_hdr {
	struct page *pg;
	void *va;		/* Virtual address of first byte */
	pgoff_t offset;		/* Offset within the page to copy the header */
	pgoff_t size;		/* Total size of the page */
};
#endif

/*
 * We need to size various arrays and bitmaps to be able to use Ingress and
 * Egress Queue IDs (minus the base starting Ingress/Egress Queue IDs) to
 * index into those arrays/bitmaps.
 *
 * The maximum number of Egress Queue IDs is determined by the maximum number
 * of Ethernet "Queue Sets" which we support plus Control, Offload "Queue
 * Sets", RDMA and iSCSI RX Queues.  The maximum number of Ingress Queue IDs
 * is also determined by the maximum number of Ethernet "Queue Sets" plus
 * Offload RX Queues, the Asynchronous Firmware Event Queue and the Forwarded
 * Interrupt Queue.
 *
 * Each Ethernet "Queue Set" requires one Ingress Queue for RX Packet Ingress
 * Event notifications and two Egress Queues for a Free List and an Ethernet
 * TX list (remember that a Free List is really an Egress Queue since it
 * contains pointer to host side buffers which the host send to the hardware)
 * The same is true for the Offload "Queue Sets".  And the RDMA and iSCSI RX
 * Queues also have Free Lists, so we need to count those in the Egress Queue
 * count Each Offload "Queue Set" has one Ingress and one Egress Queue.
 */
enum {
	INGQ_EXTRAS = 2,	/* firmware event queue and */
				/*   forwarded interrupts */
	MAX_INGQ = MAX_ETH_QSETS + MAX_OFLD_QSETS
		   + MAX_RDMA_QUEUES + MAX_RDMA_CIQS + MAX_ISCSI_QUEUES
		   + MAX_HFILTER_QUEUES + MAX_FAILOVER_QUEUES
		   + INGQ_EXTRAS,
};

struct adapter;
struct vlan_group;
struct sge_eth_rxq;
struct sge_rspq;

#ifdef CONFIG_T4_MA_FAILOVER

enum {  /* ma failover flags */
       MA_FAILOVER_NONE,
       MA_FAILOVER,
       MA_FAILOVER_TRANS
};

struct ma_failover {
       int flags;
       struct net_device *this_dev;
       struct net_device *backup_dev;
       atomic_t conn_moved;
       int fidx;
       int fidx6;
};

#endif /* CONFIG_T4_MA_FAILOVER */

struct port_info {
	struct adapter *adapter;
	struct vlan_group *vlan_grp;
	struct sge_eth_rxq *qs;		/* first Rx queue for this port */
	u16    viid;
	s16    xact_addr_filt;		/* index of exact MAC address filter */
	u16    rss_size;		/* size of VI's RSS table slice */
	s8     mdio_addr;		/* address of the PHY */
	u8     port_type;		/* firmware port type */
	u8     mod_type;		/* firmware module type */
	u8     port_id;			/* physical port ID */
	u8     tx_chan;
	u8     lport;			/* associated offload logical port */
	u8     nqsets;			/* # of qsets */
	u8     first_qset;		/* index of first qset */
	u8     rss_mode;
	struct link_config link_cfg;
	u16    *rss;
	struct port_stats stats_base;
	struct lb_port_stats lb_port_stats_base;
	struct tp_fcoe_stats fcoe_stats_base;
#ifdef CONFIG_T4_MA_FAILOVER
	struct ma_failover ma_fail_data;
#endif

#ifdef CONFIG_CXGB4_DCB
	struct port_dcb_info dcb;     /* Data Center Bridging support */
#endif /* CONFIG_CXGB4_DCB */
#ifdef CONFIG_PO_FCOE
	struct cxgb_fcoe fcoe;
#endif /* CONFIG_PO_FCOE */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
	bool rxtstamp;	/* Enable TS */
	struct hwtstamp_config tstamp_config;
#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
	bool   ptp_enable;	/* Enable PTP*/
#endif
#endif
};

struct work_struct;
struct dentry;
struct proc_dir_entry;

enum {                                 /* adapter flags */
	FULL_INIT_DONE     = (1 << 0),
	DEV_ENABLED        = (1 << 1),
	USING_MSI          = (1 << 2),
	USING_MSIX         = (1 << 3),
	FW_OK              = (1 << 4),
	RSS_TNLALLLOOKUP   = (1 << 5),
	MASTER_PF          = (1 << 6),
	BYPASS_DROP        = (1 << 7),
	FW_OFLD_CONN       = (1 << 8),
	K_CRASH            = (1 << 9),
};

enum {
	ADAPTER_ERROR,
	ADAPTER_DEAD,
};

struct rx_sw_desc;

struct sge_fl {                     /* SGE free-buffer queue state */
	unsigned int avail;         /* # of available Rx buffers */
	unsigned int pend_cred;     /* new buffers since last FL DB ring */
	unsigned int cidx;          /* consumer index */
	unsigned int pidx;          /* producer index */
	unsigned long alloc_failed; /* # of times buffer allocation failed */
	unsigned long large_alloc_failed;
	unsigned long mapping_err;  /* # of RX Buffer DMA Mapping failures */
	unsigned long low;          /* # of times momentarily starving */
	unsigned long starving;     /* # of times starving longer term */
	/* RO fields */
	unsigned int cntxt_id;      /* SGE relative QID for the free list */
	unsigned int size;          /* capacity of free list */
	struct rx_sw_desc *sdesc;   /* address of SW Rx descriptor ring */
	__be64 *desc;               /* address of HW Rx descriptor ring */
	dma_addr_t addr;            /* bus address of HW ring start */
	void __iomem *bar2_addr;    /* address of BAR2 Queue registers */
	unsigned int bar2_qid;      /* Queue ID for BAR2 Queue registers */
};

/* A packet gather list */
struct pkt_gl {
	u64 sgetstamp;		/* SGE Time Stamp for Ingress Packet */
	union {
		struct page_frag frags[MAX_SKB_FRAGS];
		struct sk_buff *skbs[MAX_SKB_FRAGS];
	} /*UNNAMED*/;
	void *va;                         /* virtual address of first byte */
	unsigned int nfrags;              /* # of fragments */
	unsigned int tot_len;             /* total length of fragments */
};

typedef int (*rspq_handler_t)(struct sge_rspq *q, const __be64 *rsp,
			      const struct pkt_gl *gl);
typedef void (*rspq_flush_handler_t)(struct sge_rspq *q);

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
/* LRO related declarations for TOM */
struct t4_lro_mgr {
#define MAX_LRO_SESSIONS		64
	u8 lro_session_cnt;         /* # of sessions to aggregate */
	unsigned long lro_pkts;     /* # of LRO super packets */
	unsigned long lro_merged;   /* # of wire packets merged by LRO */
	struct sk_buff_head lroq; /* list of aggregated sessions */
};
#endif

struct sge_rspq {                   /* state for an SGE response queue */
	struct napi_struct napi;
	const __be64 *cur_desc;     /* current descriptor in queue */
	unsigned int cidx;          /* consumer index */
	u8 gen;                     /* current generation bit */
	u8 intr_params;             /* interrupt holdoff parameters */
	u8 next_intr_params;        /* holdoff params for next interrupt */
	u8 adaptive_rx;
	u8 pktcnt_idx;              /* interrupt packet threshold */
	u8 uld;                     /* ULD handling this queue */
	u8 idx;                     /* queue index within its group */
	int offset;                 /* offset into current Rx buffer */
	u16 cntxt_id;               /* SGE relative QID for the response Q */
	u16 abs_id;                 /* absolute SGE id for the response q */
	__be64 *desc;               /* address of HW response ring */
	dma_addr_t phys_addr;       /* physical address of the ring */
	void __iomem *bar2_addr;    /* address of BAR2 Queue registers */
	unsigned int bar2_qid;      /* Queue ID for BAR2 Queue registers */
	unsigned int iqe_len;       /* entry size */
	unsigned int size;          /* capacity of response queue */
	struct adapter *adap;
	struct net_device *netdev;  /* associated net device */
	rspq_handler_t handler;
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	rspq_flush_handler_t flush_handler;
	struct t4_lro_mgr lro_mgr;
#endif
#ifdef CONFIG_NET_RX_BUSY_POLL
#define CXGB_POLL_STATE_IDLE		0
#define CXGB_POLL_STATE_NAPI		(1 << 0) /* NAPI owns this poll */
#define CXGB_POLL_STATE_POLL		(1 << 1) /* poll owns this poll */
#define CXGB_POLL_STATE_NAPI_YIELD	(1 << 2) /* NAPI yielded this poll */
#define CXGB_POLL_STATE_POLL_YIELD	(1 << 3) /* poll yielded this poll */
#define CXGB_POLL_YIELD			(CXGB_POLL_STATE_NAPI_YIELD |   \
					 CXGB_POLL_STATE_POLL_YIELD)
#define CXGB_POLL_LOCKED		(CXGB_POLL_STATE_NAPI |         \
					 CXGB_POLL_STATE_POLL)
#define CXGB_POLL_USER_PEND		(CXGB_POLL_STATE_POLL |         \
					 CXGB_POLL_STATE_POLL_YIELD)
	unsigned int bpoll_state;
	spinlock_t bpoll_lock;
#endif /* CONFIG_NET_RX_BUSY_POLL */
};

struct sge_eth_stats {              /* Ethernet queue statistics */
	unsigned long pkts;         /* # of ethernet packets */
	unsigned long lro_pkts;     /* # of LRO super packets */
	unsigned long lro_merged;   /* # of wire packets merged by LRO */
	unsigned long rx_cso;       /* # of Rx checksum offloads */
	unsigned long vlan_ex;      /* # of Rx VLAN extractions */
	unsigned long rx_drops;     /* # of packets dropped due to no mem */
};

struct sge_eth_rxq {                /* a SW Ethernet Rx queue */
	struct sge_rspq rspq;
	struct sge_fl fl;
#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0))
	struct vxlan_buf_for_hdr hdr_buf;
#endif
	struct sge_eth_stats stats;
} ____cacheline_aligned_in_smp;

struct sge_ofld_stats {             /* offload queue statistics */
	unsigned long pkts;         /* # of packets */
	unsigned long imm;          /* # of immediate-data packets */
	unsigned long an;           /* # of asynchronous notifications */
	unsigned long nomem;        /* # of responses deferred due to no mem */
};

struct sge_ofld_rxq {               /* a SW offload Rx queue */
	struct sge_rspq rspq;
	struct sge_fl fl;
	struct sge_ofld_stats stats;
} ____cacheline_aligned_in_smp;

struct tx_desc {
	__be64 flit[8];
};

struct tx_sw_desc;

struct eth_coalesce {
	unsigned int idx;
	unsigned int len;
	unsigned int flits;
	unsigned int max;
	unsigned char *ptr;
	unsigned char type;
	bool ison;
	bool intr;
};

struct sge_txq {
	unsigned int  in_use;       /* # of in-use Tx descriptors */
	unsigned int  size;         /* # of descriptors */
	unsigned int  cidx;         /* SW consumer index */
	unsigned int  pidx;         /* producer index */
	unsigned long txp;          /* # of transmitted requests */
	unsigned long stops;        /* # of times q has been stopped */
	unsigned long restarts;     /* # of queue restarts */
	unsigned int  cntxt_id;     /* SGE relative QID for the Tx Q */
	struct tx_desc *desc;       /* address of HW Tx descriptor ring */
	struct tx_sw_desc *sdesc;   /* address of SW Tx descriptor ring */
	struct eth_coalesce coalesce;
	struct sge_qstat *stat;     /* queue status entry */
	dma_addr_t    phys_addr;    /* physical address of the ring */
	void __iomem *bar2_addr;    /* address of BAR2 Queue registers */
	unsigned int bar2_qid;      /* Queue ID for BAR2 Queue registers */
	spinlock_t db_lock;
	int db_disabled;
	unsigned short db_pidx;
	unsigned short db_pidx_inc;
	u8 is_vxlan_lb;             /* for looping back of vxlan packets */
#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0))
	unsigned long flags;        /* synchronize loopback tx queue */
#endif
};

struct sge_eth_txq {                /* state for an SGE Ethernet Tx queue */
	struct sge_txq q;
	struct netdev_queue *txq;   /* associated netdev TX queue */
#ifdef CONFIG_CXGB4_DCB
	u8 dcb_prio;                /* DCB Priority bound to queue */
#endif
	unsigned long tso;          /* # of TSO requests */
	unsigned long tx_cso;       /* # of Tx checksum offloads */
	unsigned long vlan_ins;     /* # of Tx VLAN insertions */
	unsigned long mapping_err;  /* # of I/O MMU packet mapping errors */
	unsigned long coal_wr;      /* # of coalesce WR */
	unsigned long coal_pkts;    /* # of coalesced packets */
} ____cacheline_aligned_in_smp;

struct sge_ofld_txq {               /* state for an SGE offload Tx queue */
	struct sge_txq q;
	struct adapter *adap;
	struct sk_buff_head sendq;  /* list of backpressured packets */
	struct tasklet_struct qresume_tsk; /* restarts the queue */
	u8 service_ofldq_running;   /* service_ofldq() is processing sendq */
	u8 full;                    /* the Tx ring is full */
	unsigned long mapping_err;  /* # of I/O MMU packet mapping errors */
} ____cacheline_aligned_in_smp;

struct sge_ctrl_txq {               /* state for an SGE control Tx queue */
	struct sge_txq q;
	struct adapter *adap;
	struct sk_buff_head sendq;  /* list of backpressured packets */
	struct tasklet_struct qresume_tsk; /* restarts the queue */
	u8 full;                    /* the Tx ring is full */
} ____cacheline_aligned_in_smp;

struct sge {
	/*
	 * Keep all the Tx queues before the Rx queues so we can tell easily
	 * what egr_map entries point at.
	 */
	struct sge_eth_txq ethtxq[MAX_ETH_QSETS];
#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0))
	/* Special transmit queues to loopback outer header removed
	 * vxlan packet for checksum verification.
	 * We create one corresponding to each ethernet receive queue.
	 */
	struct sge_eth_txq vxlantxq[MAX_ETH_QSETS];
#endif
#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
	struct sge_eth_txq ptptxq;
#endif
	struct sge_ofld_txq ofldtxq[MAX_OFLD_QSETS];
	struct sge_ctrl_txq ctrlq[MAX_CTRL_QUEUES];

	struct sge_eth_rxq ethrxq[MAX_ETH_QSETS];
	struct sge_eth_rxq traceq[MAX_TRACE_QUEUES];
	struct sge_ofld_rxq ofldrxq[MAX_OFLD_QSETS];
	struct sge_ofld_rxq rdmarxq[MAX_RDMA_QUEUES];
	struct sge_ofld_rxq rdmaciq[MAX_RDMA_CIQS];
	struct sge_ofld_rxq iscsirxq[MAX_ISCSI_QUEUES];
#ifdef CONFIG_T4_MA_FAILOVER
	struct sge_ofld_rxq failoverq;
#endif
	struct sge_rspq fw_evtq ____cacheline_aligned_in_smp;

	struct sge_rspq intrq ____cacheline_aligned_in_smp;
	spinlock_t intrq_lock;

	u16 max_ethqsets;           /* # of available Ethernet queue sets */
	u16 ethqsets;               /* # of active Ethernet queue sets */
	u16 ethtxq_rover;           /* Tx queue to clean up next */
	u16 ofldqsets;              /* # of active offload queue sets */
	u16 rdmaqs;                 /* # of available RDMA Rx queues */
	u16 rdmaciqs;               /* # of available RDMA concentrator IQs */
	u16 niscsiq;                /* # of available iSCSI Rx queues */
	u16 ntraceq;		    /* # of available trace Rx queues */
	u16 nfailoverq;		    /* # of available failover Rx queues */
	u16 nvxlanq;		    /* # of vxlan loopback Tx queues */
	u16 max_ofldqsets;		/* # of available offload queue sets*/
	u16 ofld_rxq[MAX_OFLD_QSETS];
	u16 rdma_rxq[MAX_RDMA_QUEUES];
	u16 rdma_ciq[MAX_RDMA_CIQS];
	u16 iscsi_rxq[MAX_ISCSI_QUEUES];
	u16 timer_val[SGE_NTIMERS];
	u8 counter_val[SGE_NCOUNTERS];
	u32 fl_pg_order;            /* large page allocation size */
        u32 stat_len;               /* length of status page at ring end */
        u32 pktshift;               /* padding between CPL & packet data */
        u32 fl_align;               /* response queue message alignment */
	u32 fl_starve_thres;        /* Free List starvation threshold */

	struct sge_idma_monitor_state idma_monitor;
	unsigned int egr_start;
	unsigned int egr_sz;
	unsigned int ingr_start;
	unsigned int ingr_sz;
	void **egr_map;    /* qid->queue egress queue map */
	struct sge_rspq **ingr_map; /* qid->queue ingress queue map */
	unsigned long *starving_fl;
	unsigned long *txq_maperr;
	unsigned long *blocked_fl;
	struct timer_list rx_timer; /* refills starving FLs */
	struct timer_list tx_timer; /* checks Tx queues */
};

#define for_each_ethrxq(sge, i) for (i = 0; i < (sge)->ethqsets; i++)
#define for_each_ofldrxq(sge, i) for (i = 0; i < (sge)->ofldqsets; i++)
#define for_each_rdmarxq(sge, i) for (i = 0; i < (sge)->rdmaqs; i++)
#define for_each_rdmaciq(sge, i) for (i = 0; i < (sge)->rdmaciqs; i++)
#define for_each_iscsirxq(sge, i) for (i = 0; i < (sge)->niscsiq; i++)
#define for_each_tracerxq(sge, i) for (i = 0; i < (sge)->ntraceq; i++)

#ifdef CONFIG_PCI_IOV
/*
 * T4 supports SRIOV on PF0-3 and T5 on PF0-7.  However, the Serial
 * Configuration initialization for T5 only has SR-IOV functionality enabled
 * on PF0-3 in order to simplify everything.
 */
#define NUM_OF_PF_WITH_SRIOV 4
#endif

struct l2t_data;
struct filter_info;

/*
 * The Linux driver needs locking around mailbox accesses ...
 */
#define T4_OS_NEEDS_MBOX_LOCKING 1

/*
 * OS Lock/List primitives for those interfaces in the Common Code which
 * need this.
 */
typedef spinlock_t t4_os_lock_t;
typedef struct t4_os_list {
	struct list_head list;
} t4_os_list_t;

/*
 * If Linux is configured with hard lockup detection, we'll need to call
 * touch_nmi_watchdog() in the middle of any non-sleeping busy spin-loops.
 */
#if defined(CONFIG_HAVE_NMI_WATCHDOG) || defined(CONFIG_HARDLOCKUP_DETECTOR)
#define T4_OS_NEEDS_TOUCH_NMI_WATCHDOG 1

#include <linux/nmi.h>

static inline void t4_os_touch_nmi_watchdog(void)
{
	touch_nmi_watchdog();
}
#endif

struct doorbell_stats {
	u32 db_drop;
	u32 db_empty;
	u32 db_full;
};

struct filter_ehash_bucket {
	struct hlist_nulls_head chain;
};

struct filter_hashinfo {
	struct filter_ehash_bucket *ehash;
	spinlock_t *ehash_filter_locks;
	unsigned int ehash_mask;
	unsigned int ehash_filter_locks_mask;
};

/*
 * Host shadow copy of ingress filter entry.  This is in host native format
 * and doesn't match the ordering or bit order, etc. of the hardware or the
 * firmware command.
 */
struct filter_entry {
	/*
	 * Administrative fields for filter.
	 */
	u32 valid:1;            /* filter allocated and valid */
	u32 locked:1;           /* filter is administratively locked */
	u32 pending:1;          /* filter action is pending firmware reply */
	u32 smtidx:8;           /* Source MAC Table index for smac */
	struct filter_ctx *ctx; /* caller's completion hook */
	struct l2t_entry *l2t;  /* Layer Two Table entry for dmac */
	struct smt_entry *smt;  /* Source Mac Table entry for smac */
	struct net_device *dev;
	/* This will store the actual tid */
	u32 tid;
	unsigned int filter_hash;
	struct hlist_nulls_node filter_nulls_node;
	unsigned long pkt_counter;

	/*
	 * The filter itself.  Most of this is a straight copy of information
	 * provided by the extended ioctl().  Some fields are translated to
	 * internal forms -- for instance the Ingress Queue ID passed in from
	 * the ioctl() is translated into the Absolute Ingress Queue ID.
	 */
	struct ch_filter_specification fs;
};

struct hash_mac_addr {
	struct list_head list;
	u8 addr[ETH_ALEN];
};

struct adapter {
	void __iomem *regs;
	void __iomem *bar2;
	u32 t4_bar0;
	struct pci_dev *pdev;
	struct device *pdev_dev;
	unsigned long registered_device_map;
	unsigned long flags;
	unsigned long adap_err_state; /* Fatal Error/AER/EEH recovery state */
	u32 use_bd;	/* Use SGE Back Door intfc for reading SGE Contexts */

	const char *name;
	unsigned int mbox;
	unsigned int pf;
	unsigned int vpd_busy;
	unsigned int vpd_flag;
	int msg_enable;
#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0))
	__be16 vxlan_port;
	u8 vxlan_port_cnt;
#endif

	struct adapter_params params;
	struct cxgb4_virt_res vres;
	unsigned int swintr;

	struct {
		unsigned short vec;
		char desc[IFNAMSIZ + 10];
	} msix_info[MAX_INGQ + 1];

#ifdef T4_TRACE
	struct trace_buf *tb[NTRACEBUFS];
#endif

	struct doorbell_stats db_stats;
	/* T4 modules */
	struct sge sge;

	struct tp_cpl_stats tp_cpl_stats_base;
	struct tp_err_stats tp_err_stats_base;

	struct net_device *port[MAX_NPORTS];
	u8 chan_map[NCHAN];                   /* channel -> port map */

	struct filter_info *filters;
	unsigned int l2t_start;
	unsigned int l2t_end;
	struct l2t_data *l2t;
	unsigned int clipt_start;
	unsigned int clipt_end;
	struct clip_tbl *clipt;
	unsigned int rawf_start;
	unsigned int rawf_cnt;
	struct smt_data *smt;
	struct srq_data *srq;
	struct list_head mac_hlist; /* list of MAC addresses in MPS Hash */

	void *uld_handle[CXGB4_ULD_MAX];
	struct list_head list_node;
	struct filter_hashinfo filter_tcphash;
	struct filter_hashinfo filter_udphash;

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	struct gen_pool *ocqp_pool;
	unsigned long oc_mw_pa;
	void __iomem *oc_mw_kva;
	void *iscsi_ppm;
#endif
	struct tid_info tids;
	void **tid_release_head;
	spinlock_t tid_release_lock;
	struct workqueue_struct *workq;
	struct workqueue_struct *eeh_workq;
	struct work_struct tid_release_task;
	struct work_struct db_full_task;
	struct work_struct db_drop_task;
	struct work_struct fatal_err_task;

#ifdef CONFIG_CHELSIO_BYPASS
	int bypass_watchdog_timeout;
	int bypass_failover_mode;
	int bypass_watchdog_lock;
#else
	struct delayed_work deadman_watchdog_task;
#endif

#ifdef CONFIG_PCI_IOV
	struct delayed_work vf_monitor_task;
	unsigned int vf_monitor_mask;
#endif

	struct dentry *debugfs_root;
	void *dma_virt;
	dma_addr_t dma_phys;

	spinlock_t mdio_lock;
	spinlock_t stats_lock;
	spinlock_t work_lock;

	/* support for single-threading access to adapter mailbox registers */
	t4_os_lock_t mbox_lock;
	t4_os_list_t mbox_list;

	/* support for mailbox command/reply logging */
	#define T4_OS_LOG_MBOX_CMDS 256
	struct mbox_cmd_log *mbox_log;

	struct mutex user_mutex;
	struct mutex uld_mutex;

	/*
	 * Copies of applicable Module Parameters so we can use them in
	 * various pieces of the driver code.
	 */
	int tx_coal;
	int tx_db_wc;

#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
	struct ptp_clock *ptp_clock;
	struct ptp_clock_info ptp_clock_info; /* PTP HW clock ops */
	struct sk_buff *ptp_tx_skb;     /* PTP Tx TS skb */
	spinlock_t ptp_lock; /* PTP lock for Tx */
#endif

	spinlock_t win0_lock ____cacheline_aligned_in_smp;

	/* Buffer and notifier necessary for debug collection using cudbg */
	u32 *dump_buf;
	struct notifier_block panic_nb;
};

#include "cxgb4_compat.h"

/**
 * t4_read_reg - read a HW register
 * @adapter: the adapter
 * @reg_addr: the register address
 *
 * Returns the 32-bit value of the given HW register.
 */
static inline u32 t4_read_reg(adapter_t *adapter, u32 reg_addr)
{
	u32 val = readl(adapter->regs + reg_addr);

	CH_DBG(adapter, MMIO, "read register 0x%x value 0x%x\n", reg_addr,
	       val);
	return val;
}

/**
 * t4_write_reg - write a HW register
 * @adapter: the adapter
 * @reg_addr: the register address
 * @val: the value to write
 *
 * Write a 32-bit value into the given HW register.
 */
static inline void t4_write_reg(adapter_t *adapter, u32 reg_addr, u32 val)
{
	CH_DBG(adapter, MMIO, "setting register 0x%x to 0x%x\n", reg_addr,
	       val);
	writel(val, adapter->regs + reg_addr);
}

#ifndef readq
static inline u64 readq(const volatile void __iomem *addr)
{
	return readl(addr) + ((u64)readl(addr + 4) << 32);
}

static inline void writeq(u64 val, volatile void __iomem *addr)
{
	writel(val, addr);
	writel(val >> 32, addr + 4);
}
#endif

/**
 * t4_read_reg64 - read a 64-bit HW register
 * @adapter: the adapter
 * @reg_addr: the register address
 *
 * Returns the 64-bit value of the given HW register.
 */
static inline u64 t4_read_reg64(adapter_t *adapter, u32 reg_addr)
{
	u64 val = readq(adapter->regs + reg_addr);

	CH_DBG(adapter, MMIO, "64-bit read register %#x value %#llx\n",
	       reg_addr, (unsigned long long)val);
	return val;
}

/**
 * t4_write_reg64 - write a 64-bit HW register
 * @adapter: the adapter
 * @reg_addr: the register address
 * @val: the value to write
 *
 * Write a 64-bit value into the given HW register.
 */
static inline void t4_write_reg64(adapter_t *adapter, u32 reg_addr, u64 val)
{
	CH_DBG(adapter, MMIO, "setting register %#x to %#llx\n", reg_addr,
	       (unsigned long long)val);
	writeq(val, adapter->regs + reg_addr);
}

/**
 * t4_os_pci_write_cfg4 - 32-bit write to PCI config space
 * @adapter: the adapter
 * @reg: the register address
 * @val: the value to write
 *
 * Write a 32-bit value into the given register in PCI config space.
 */
static inline void t4_os_pci_write_cfg4(adapter_t *adapter, int reg, u32 val)
{
	pci_write_config_dword(adapter->pdev, reg, val);
}

/**
 * t4_os_pci_read_cfg4 - read a 32-bit value from PCI config space
 * @adapter: the adapter
 * @reg: the register address
 * @val: where to store the value read
 *
 * Read a 32-bit value from the given register in PCI config space.
 */
static inline void t4_os_pci_read_cfg4(adapter_t *adapter, int reg, u32 *val)
{
	pci_read_config_dword(adapter->pdev, reg, val); 
}

/**
 * t4_os_pci_write_cfg2 - 16-bit write to PCI config space
 * @adapter: the adapter
 * @reg: the register address
 * @val: the value to write
 *
 * Write a 16-bit value into the given register in PCI config space.
 */
static inline void t4_os_pci_write_cfg2(adapter_t *adapter, int reg, u16 val)
{
	pci_write_config_word(adapter->pdev, reg, val);
}

/**
 * t4_os_pci_read_cfg2 - read a 16-bit value from PCI config space
 * @adapter: the adapter
 * @reg: the register address
 * @val: where to store the value read
 *
 * Read a 16-bit value from the given register in PCI config space.
 */
static inline void t4_os_pci_read_cfg2(adapter_t *adapter, int reg, u16 *val)
{
	pci_read_config_word(adapter->pdev, reg, val); 
}

/**
 * t4_os_find_pci_capability - lookup a capability in the PCI capability list
 * @adapter: the adapter
 * @cap: the capability
 *
 * Return the address of the given capability within the PCI capability list.
 */
static inline int t4_os_find_pci_capability(adapter_t *adapter, int cap)
{
	return pci_find_capability(adapter->pdev, cap);
}

/**
 * t4_os_pci_read_seeprom - read four bytes of SEEPROM/VPD contents
 * @adapter: the adapter
 * @addr: SEEPROM/VPD Address to read
 * @valp: where to store the value read
 *
 * Read a 32-bit value from the given address in the SEEPROM/VPD.  The address
 * must be four-byte aligned.  Returns 0 on success, a negative erro number
 * on failure.
 */
static inline int t4_os_pci_read_seeprom(adapter_t *adapter,
					 int addr, u32 *valp)
{
	ssize_t ret;

	/*
	 * For newer versions of Linux we use the OS APIs in order to
	 * serialize accesses to the PCI VPD Capability.  For older versions
	 * we just have to use our VPD Capability directly since Linux didn't
	 * export an interface in the past.
	 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
	int t4_seeprom_read(struct adapter *adapter, u32 addr, u32 *data);

	ret = t4_seeprom_read(adapter, addr, valp);
#else
	ret = pci_read_vpd(adapter->pdev, addr, sizeof(u32), valp);
#endif

	return ret >= 0 ? 0 : ret;
}

/**
 * t4_os_pci_write_seeprom - write four bytes of SEEPROM/VPD contents
 * @adapter: the adapter
 * @addr: SEEPROM/VPD Address to write
 * @val: the value write
 *
 * Write a 32-bit value to the given address in the SEEPROM/VPD.  The address
 * must be four-byte aligned.  Returns 0 on success, a negative erro number
 * on failure.
 */
static inline int t4_os_pci_write_seeprom(adapter_t *adapter,
					  int addr, u32 val)
{
	ssize_t ret;

	/*
	 * For newer versions of Linux we use the OS APIs in order to
	 * serialize accesses to the PCI VPD Capability.  For older versions
	 * we just have to use our VPD Capability directly since Linux didn't
	 * export an interface in the past.
	 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
	int t4_seeprom_write(struct adapter *adapter, u32 addr, u32 data);

	ret = t4_seeprom_write(adapter, addr, val);
#else
	ret = pci_write_vpd(adapter->pdev, addr, sizeof(u32), &val);
#endif

	return ret >= 0 ? 0 : ret;
}

/**
 *	t4_os_timestamp - return an opaque OS-dependent 64-bit timestamp
 *
 *	This is used by the Common Code to timestamp various things.
 *	It's up to OS-dependent code to use these later ...
 */
static inline u64 t4_os_timestamp(void)
{
	return jiffies;
}

/**
 * t4_os_set_hw_addr - store a port's MAC address in SW
 * @adapter: the adapter
 * @port_idx: the port index
 * @hw_addr: the Ethernet address
 *
 * Store the Ethernet address of the given port in SW.  Called by the common
 * code when it retrieves a port's Ethernet address from EEPROM.
 */
static inline void t4_os_set_hw_addr(adapter_t *adapter, int port_idx,
				     u8 hw_addr[])
{
	memcpy(adapter->port[port_idx]->dev_addr, hw_addr, ETH_ALEN);
}

/**
 * netdev2pinfo - return the port_info structure associated with a net_device
 * @dev: the netdev
 *
 * Return the struct port_info associated with a net_device
 */
static inline struct port_info *netdev2pinfo(const struct net_device *dev)
{
	return netdev_priv(dev);
}

/**
 * adap2pinfo - return the port_info of a port
 * @adap: the adapter
 * @idx: the port index
 *
 * Return the port_info structure for the port of the given index.
 */
static inline struct port_info *adap2pinfo(struct adapter *adap, int idx)
{
	return netdev_priv(adap->port[idx]);
}

/**
 * netdev2adap - return the adapter structure associated with a net_device
 * @dev: the netdev
 *
 * Return the struct adapter associated with a net_device
 */
static inline struct adapter *netdev2adap(const struct net_device *dev)
{
	return netdev2pinfo(dev)->adapter;
}

/**
 * t4_os_lock_init - initialize spinlock
 * @lock: the spinlock
 */
static inline void t4_os_lock_init(t4_os_lock_t *lock)
{
	spin_lock_init(lock);
}

/**
 * t4_os_trylock - try to acquire a spinlock
 * @lock: the spinlock
 *
 * Returns 1 if successful and 0 otherwise.
 */
static inline int t4_os_trylock(t4_os_lock_t *lock)
{
	return spin_trylock_bh(lock);
}

/**
 * t4_os_lock - spin until lock is acquired
 * @lock: the spinlock
 */
static inline void t4_os_lock(t4_os_lock_t *lock)
{
	spin_lock_bh(lock);
}

/**
 * t4_os_unlock - unlock a spinlock
 * @lock: the spinlock
 */
static inline void t4_os_unlock(t4_os_lock_t *lock)
{
	spin_unlock_bh(lock);
}

/**
 * t4_os_init_list_head - initialize 
 * @head: head of list to initialize [to empty]
 */
static inline void t4_os_init_list_head(t4_os_list_t *head)
{
	INIT_LIST_HEAD(&head->list);
}

static inline struct t4_os_list *t4_os_list_first_entry(t4_os_list_t *head)
{
	return list_first_entry(&head->list, t4_os_list_t, list);
}

/**
 * t4_os_atomic_add_tail - Enqueue list element atomically onto list
 * @new: the entry to be addded to the queue
 * @head: current head of the linked list
 * @lock: lock to use to guarantee atomicity
 */
static inline void t4_os_atomic_add_tail(t4_os_list_t *new,
					 t4_os_list_t *head,
					 t4_os_lock_t *lock)
{
	t4_os_lock(lock);
	list_add_tail(&new->list, &head->list);
	t4_os_unlock(lock);
}

/**
 * t4_os_atomic_list_del - Dequeue list element atomically from list
 * @entry: the entry to be remove/dequeued from the list.
 * @lock: the spinlock
 */
static inline void t4_os_atomic_list_del(t4_os_list_t *entry,
					 t4_os_lock_t *lock)
{
	t4_os_lock(lock);
	list_del(&entry->list);
	t4_os_unlock(lock);
}

#ifdef CONFIG_NET_RX_BUSY_POLL
static inline void cxgb_busy_poll_init_lock(struct sge_rspq *q)
{
	spin_lock_init(&q->bpoll_lock);
	q->bpoll_state = CXGB_POLL_STATE_IDLE;
}

static inline bool cxgb_poll_lock_napi(struct sge_rspq *q)
{
	bool rc = true;

	spin_lock(&q->bpoll_lock);
	if (q->bpoll_state & CXGB_POLL_LOCKED) {
		q->bpoll_state |= CXGB_POLL_STATE_NAPI_YIELD;
		rc = false;
	} else {
		q->bpoll_state = CXGB_POLL_STATE_NAPI;
	}
	spin_unlock(&q->bpoll_lock);
	return rc;
}

static inline bool cxgb_poll_unlock_napi(struct sge_rspq *q)
{
	bool rc = false;

	spin_lock(&q->bpoll_lock);
	if (q->bpoll_state & CXGB_POLL_STATE_POLL_YIELD)
		rc = true;
	q->bpoll_state = CXGB_POLL_STATE_IDLE;
	spin_unlock(&q->bpoll_lock);
	return rc;
}
static inline bool cxgb_poll_lock_poll(struct sge_rspq *q)
{
	bool rc = true;

	spin_lock_bh(&q->bpoll_lock);
	if (q->bpoll_state & CXGB_POLL_LOCKED) {
		q->bpoll_state |= CXGB_POLL_STATE_POLL_YIELD;
		rc = false;
	} else {
		q->bpoll_state |= CXGB_POLL_STATE_POLL;
	}
	spin_unlock_bh(&q->bpoll_lock);
	return rc;
}

static inline bool cxgb_poll_unlock_poll(struct sge_rspq *q)
{
	bool rc = false;

	spin_lock_bh(&q->bpoll_lock);
	if (q->bpoll_state & CXGB_POLL_STATE_POLL_YIELD)
		rc = true;
	q->bpoll_state = CXGB_POLL_STATE_IDLE;
	spin_unlock_bh(&q->bpoll_lock);
	return rc;
}

static inline bool cxgb_poll_busy_polling(struct sge_rspq *q)
{
	return q->bpoll_state & CXGB_POLL_USER_PEND;
}
#else
static inline void cxgb_busy_poll_init_lock(struct sge_rspq *q)
{
}

static inline bool cxgb_poll_lock_napi(struct sge_rspq *q)
{
	return true;
}

static inline bool cxgb_poll_unlock_napi(struct sge_rspq *q)
{
	return false;
}
static inline bool cxgb_poll_lock_poll(struct sge_rspq *q)
{
	return false;
}

static inline bool cxgb_poll_unlock_poll(struct sge_rspq *q)
{
	return false;
}

static inline bool cxgb_poll_busy_polling(struct sge_rspq *q)
{
	return false;
}
#endif /* CONFIG_NET_RX_BUSY_POLL */

/* Return a version number to identify the type of adapter.  The scheme is:
 * - bits 0..9: chip version
 * - bits 10..15: chip revision
 * - bits 16..23: register dump version
 */
static inline unsigned int mk_adap_vers(struct adapter *ap)
{
	return CHELSIO_CHIP_VERSION(ap->params.chip) |
		(CHELSIO_CHIP_RELEASE(ap->params.chip) << 10) | (1 << 16);
}

/* Return a queue's interrupt hold-off time in us.  0 means no timer.
 */
static inline unsigned int qtimer_val(const struct adapter *adap,
			       const struct sge_rspq *q)
{
	unsigned int idx = q->intr_params >> 1;

	return idx < SGE_NTIMERS ? adap->sge.timer_val[idx] : 0;
}

static inline unsigned int t4_use_ldst(struct adapter *adap)
{
	return (adap->flags & FW_OK) || (!adap->use_bd);
}

/* driver version & name used for ethtool_drvinfo */
extern char cxgb4_driver_name[];
extern const char cxgb4_driver_version[];

/* fw_attach module param is used in cxgb4_ethtool.c */
extern int fw_attach;

#ifndef CONFIG_CHELSIO_T4_OFFLOAD
static inline void t4_db_full(struct adapter *adap) {}
static inline void t4_db_dropped(struct adapter *adap) {}
#endif

#define OFFLOAD_DEVMAP_BIT 15

void t4_os_portmod_changed(const struct adapter *adap, int port_id);
void t4_os_link_changed(struct adapter *adap, int port_id, int link_stat);

void *t4_alloc_mem(size_t size);
void t4_free_mem(void *addr);
#define t4_os_alloc(_size)	t4_alloc_mem((_size))
#define t4_os_free(_ptr)	t4_free_mem((_ptr))

void t4_free_sge_resources(struct adapter *adap);
void t4_free_ofld_rxqs(struct adapter *adap, int n, struct sge_ofld_rxq *q);
irq_handler_t t4_intr_handler(struct adapter *adap);
int t4_eth_xmit(struct sk_buff *skb, struct net_device *dev);
int t4vf_eth_xmit(struct sk_buff *skb, struct net_device *dev);
int t4_ethrx_handler(struct sge_rspq *q, const __be64 *rsp,
		     const struct pkt_gl *gl);
int t4_trace_handler(struct sge_rspq *q, const __be64 *rsp,
		     const struct pkt_gl *gl);
int t4_mgmt_tx(adapter_t *adap, struct sk_buff *skb);
int t4_ofld_send(struct adapter *adap, struct sk_buff *skb);
int t4_sge_alloc_rxq(struct adapter *adap, struct sge_rspq *iq, bool fwevtq,
		     struct net_device *dev, int intr_idx,
		     struct sge_fl *fl, rspq_handler_t hnd,
		     rspq_flush_handler_t flush_hnd, int cong);
int t4_sge_alloc_eth_txq(struct adapter *adap, struct sge_eth_txq *txq,
			 struct net_device *dev, struct netdev_queue *netdevq,
			 unsigned int iqid);
int t4_sge_alloc_ctrl_txq(struct adapter *adap, struct sge_ctrl_txq *txq,
			  struct net_device *dev, unsigned int iqid,
			  unsigned int cmplqid);
int t4_sge_alloc_ofld_txq(struct adapter *adap, struct sge_ofld_txq *txq,
			  struct net_device *dev, unsigned int iqid);
irqreturn_t t4_sge_intr_msix(int irq, void *cookie);
int t4_sge_init(struct adapter *adap);
void t4_sge_init_tasklet(struct adapter *adap);
void t4_sge_start(struct adapter *adap);
void t4_sge_stop(struct adapter *adap);
int t4_sge_coalesce_handler(struct adapter *adap, struct sge_eth_txq *q);
int cxgb_busy_poll(struct napi_struct *napi);
int cxgb4_set_rspq_intr_params(struct sge_rspq *q, unsigned int us, unsigned int cnt);
void cxgb4_set_ethtool_ops(struct net_device *netdev);
int cxgb4_write_rss(const struct port_info *pi, const u16 *queues);
#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0))
void *refill_vxlan_hdr_buf(struct adapter *adap,
			   struct sge_eth_rxq *rxq, gfp_t gfp);
#endif
#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,4))
enum cpl_tx_tnl_lso_type cxgb_encap_offload_supported(struct sk_buff *skb);
#endif

void do_collect(struct adapter *adap, void *buf, unsigned long size);
extern int dbfifo_int_thresh;
#endif /* __T4_ADAPTER_H__ */
