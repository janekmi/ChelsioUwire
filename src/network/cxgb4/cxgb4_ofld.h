/*
 * This file is part of the Chelsio T4/T5/T6 Ethernet driver.
 *
 * Copyright (C) 2009-2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __CXGB4_OFLD_H
#define __CXGB4_OFLD_H

#include <linux/cache.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/inetdevice.h>
#include <linux/completion.h>
#include <linux/bitmap.h>
#include <net/sock.h>
#include "l2t.h"
#include <asm/atomic.h>

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
#include <net/offload.h>
#endif

#include "cxgbtool.h"

/* CPL message priority levels */
enum {
	CPL_PRIORITY_DATA     = 0,  /* data messages */
	CPL_PRIORITY_SETUP    = 1,  /* connection setup messages */
	CPL_PRIORITY_TEARDOWN = 0,  /* connection teardown messages */
	CPL_PRIORITY_LISTEN   = 1,  /* listen start/stop messages */
	CPL_PRIORITY_ACK      = 1,  /* RX ACK messages */
	CPL_PRIORITY_CONTROL  = 1   /* control messages */
};

/*
 * Max Tx descriptor space we allow for an Ethernet packet to be inlined
 * into a WR.
 */
#define MAX_IMM_TX_PKT_LEN 256

/*
 * Max WR length for FW_OFLD_TX_DATA_WR in immediate only case
 * Work request header + 8-bit immediate data length
 */
#define MAX_IMM_OFLD_TX_DATA_WR_LEN (0xff + sizeof(struct fw_ofld_tx_data_wr))

/* ulp_mem_io + ulptx_idata + payload + padding */
#define MAX_IMM_ULPTX_WR_LEN (32 + 8 + 256 + 8)

#define INIT_TP_WR(w, tid) do { \
	(w)->wr.wr_hi = htonl(V_FW_WR_OP(FW_TP_WR) | \
			      V_FW_WR_IMMDLEN(sizeof(*w) - sizeof(w->wr))); \
	(w)->wr.wr_mid = htonl(V_FW_WR_LEN16(DIV_ROUND_UP(sizeof(*w), 16)) | \
			       V_FW_WR_FLOWID(tid)); \
	(w)->wr.wr_lo = cpu_to_be64(0); \
} while (0)

#define INIT_TP_WR_MIT_CPL(w, cpl, tid) do { \
	INIT_TP_WR(w, tid); \
	OPCODE_TID(w) = htonl(MK_OPCODE_TID(cpl, tid)); \
} while (0)

#define INIT_ULPTX_WR(w, wrlen, atomic, tid) do { \
	(w)->wr.wr_hi = htonl(V_FW_WR_OP(FW_ULPTX_WR) | V_FW_WR_ATOMIC(atomic)); \
	(w)->wr.wr_mid = htonl(V_FW_WR_LEN16(DIV_ROUND_UP(wrlen, 16)) | \
			       V_FW_WR_FLOWID(tid)); \
	(w)->wr.wr_lo = cpu_to_be64(0); \
} while (0)

/* Special asynchronous notification message */
#define CXGB4_MSG_AN ((void *)1)

struct serv_entry {
	void *data;
};

struct uoconn_entry {
	void *data;
};

union aopen_entry {
	void *data;
	union aopen_entry *next;
};

/*
 * Holds the size, base address, free list start, etc of the TID, server TID,
 * and active-open TID tables.  The tables themselves are allocated dynamically.
 */
struct tid_info {
	void **tid_tab;
	unsigned int ntids;

	struct serv_entry *stid_tab;
	unsigned long *stid_bmap;
	unsigned int nstids;
	unsigned int stid_base;
	unsigned int hash_base;

	union aopen_entry *atid_tab;
	unsigned int natids;

	struct filter_entry *ftid_tab;	/* Normal + Hi prio filters */
	unsigned long *ftid_bmap;
	unsigned int nftids;
	unsigned int ftid_base;

	/* T6 has separate hi-prio filter region */
	unsigned int hpftid_base;
	unsigned long *hpftid_bmap;
	unsigned int nhpftids;

	unsigned int aftid_base;
	unsigned int aftid_end;
	/* Server filter region */
	unsigned int sftid_base;
	unsigned int nsftids;
	/* UO context range */
	unsigned int uotid_base;
	unsigned int nuotids;
	struct uoconn_entry *uotid_tab;
	unsigned long *uotid_bmap;

	/*
	 * The following members are accessed R/W so we put them in their own
	 * cache line.  STIDs are used sparingly, we let them share the line.
	 */
	spinlock_t atid_lock ____cacheline_aligned_in_smp;
	union aopen_entry *afree;
	unsigned int atids_in_use;

	spinlock_t stid_lock;
	unsigned int stids_in_use;
	unsigned int v6_stids_in_use;
	unsigned int sftids_in_use;

	spinlock_t uotid_lock;
	unsigned int uotids_in_use;

	/* TIDs in the TCAM */
	atomic_t tids_in_use;
	/* TIDs in the HASH */
	atomic_t hash_tids_in_use;
	atomic_t conns_in_use;
	spinlock_t ftid_lock;
};

static inline void *lookup_tid(const struct tid_info *t, unsigned int tid)
{
	return tid < t->ntids ? t->tid_tab[tid] : NULL;
}

static inline void *lookup_atid(const struct tid_info *t, unsigned int atid)
{
	return atid < t->natids ? t->atid_tab[atid].data : NULL;
}

static inline void *lookup_stid(const struct tid_info *t, unsigned int stid)
{
	/* Is it a server filter TID? */
	if (t->nsftids && (stid >= t->sftid_base)) {
		stid -= t->sftid_base;
		stid += t->nstids;
	} else
		stid -= t->stid_base;

	return stid < (t->nstids + t->nsftids) ? t->stid_tab[stid].data : NULL;
}

static inline void *lookup_uotid(const struct tid_info *t, unsigned int uotid)
{
	uotid -= t->uotid_base;
	return uotid <  t->nuotids ? t->uotid_tab[uotid].data : NULL;
}

static inline void cxgb4_insert_tid(struct tid_info *t, void *data,
				    unsigned int tid, unsigned short family)
{
	t->tid_tab[tid] = data;
	if (t->hash_base && (tid >= t->hash_base)) {
		if (family == AF_INET6)
			atomic_add(2, &t->hash_tids_in_use);
		else
			atomic_inc(&t->hash_tids_in_use);
	}

	else {
		if (family == AF_INET6)
			atomic_add(2, &t->tids_in_use);
		else
			atomic_inc(&t->tids_in_use);
	}

	atomic_inc(&t->conns_in_use);
}

int cxgb4_alloc_atid(struct tid_info *t, void *data);
int cxgb4_alloc_stid(struct tid_info *t, int family, void *data);
int cxgb4_alloc_sftid(struct tid_info *t, int family, void *data);
void cxgb4_free_atid(struct tid_info *t, unsigned int atid);
void cxgb4_free_stid(struct tid_info *t, unsigned int stid, int family);
int cxgb4_alloc_uotid(struct tid_info *t, void *data);
void cxgb4_free_uotid(struct tid_info *t, unsigned int uotid);

void *cxgb_alloc_mem(unsigned long size);
void cxgb4_remove_tid(struct tid_info *t, unsigned int qid, unsigned int tid,
		      unsigned short family);

struct in6_addr;

int cxgb4_create_server(const struct net_device *dev, unsigned int stid,
			__be32 sip, __be16 sport, __be16 vlan,
			unsigned int queue);
int cxgb4_create_server_restricted(const struct net_device *dev,
				   unsigned int stid,
				   __be32 sip, __be16 sport,
				   __u64 filter_value, __u64 filter_mask,
				   unsigned int queue);
int cxgb4_create_filter_info(const struct adapter *adapter,
			     u64 *filter_value, u64 *filter_mask,
			     int fcoe, int port, int vnic,
			     int vlan, int vlan_pcp, int vlan_dei,
			     int tos, int protocol, int ethertype,
			     int macmatch, int matchtype, int frag);
int cxgb4_create_server_filter(const struct net_device *dev, unsigned int stid,
			       __be32 sip, __be16 sport, __be16 vlan,
			       unsigned int queue, unsigned char port, unsigned char mask);
int cxgb4_create_server6(const struct net_device *dev, unsigned int stid,
			 const struct in6_addr *sip, __be16 sport,
			 unsigned int queue);
int cxgb4_create_server6_restricted(const struct net_device *dev,
				    unsigned int stid,
				    const struct in6_addr *sip, __be16 sport,
				    __u64 filter_value, __u64 filter_mask,
				    unsigned int queue);
int cxgb4_remove_server(const struct net_device *dev, unsigned int stid,
			unsigned int queue, bool ipv6);
int cxgb4_remove_server_filter(const struct net_device *dev, unsigned int stid,
			unsigned int queue, bool ipv6);
int cxgb4_filter_field_shift(const struct net_device *dev, int filter_sel);

/*
 * Filter operation context to allow callers of cxgb_set_filter() and
 * cxgb_del_filter() to wait for an asynchronous completion.
 */
struct filter_ctx {
	struct completion completion;	/* completion rendezvous */
	void *closure;			/* caller's opaque information */
	int result;			/* result of operation */
	u32 tid;			/* to store tid of hash filter */
};
int cxgb4_set_filter(struct net_device *dev, int filter_id,
		     struct ch_filter_specification *fs,
		     struct filter_ctx *ctx, gfp_t flags);
int cxgb4_del_filter(struct net_device *dev, int filter_id,
		     struct ch_filter_specification *fs,
		     struct filter_ctx *ctx, gfp_t flags);
void cxgb4_flush_all_filters(struct adapter *adapter, gfp_t flags);

int cxgb4_alloc_ftid(struct tid_info *t, int family);
int cxgb4_alloc_hpftid(struct tid_info *t, int family);
void cxgb4_clear_hpftid(struct tid_info *t, int fidx, int family);
void cxgb4_clear_ftid(struct tid_info *t, int fidx, int family);

static inline void set_wr_txq(struct sk_buff *skb, int prio, int queue)
{
	skb_set_queue_mapping(skb, (queue << 1) | prio);
}

#define ofld_skb_premapped_frags(skb)   ((skb)->peeked)

/*
 *      ofld_skb_get_premapped_frags - return if the skb contains pre-mapped dma
 *                      addresses
 *      @skb: the packet
 *      Returns true if the skb contains pre-mapped dma addresses
 */
static inline unsigned int
ofld_skb_get_premapped_frags(const struct sk_buff *skb)
{
	return skb->peeked;
}

/*
 *      ofld_skb_set_premapped_frags - skb contains pre-mapped dma addresses
 *                      addresses
 *      @skb: the packet
 *      @premapped: 0 or 1
 */
static inline void ofld_skb_set_premapped_frags(struct sk_buff *skb,
						int premapped)
{
	skb->peeked = premapped;
}

/*
 *      is_ofld_sg_reqd - check whether a packet requires an SG list
 *      @skb: the packet
 *
 *      Returns true if a packet cannot be sent as an offload WR entirely with
 *      immediate data.
 */
static inline int is_ofld_sg_reqd(const struct sk_buff *skb)
{
	return ofld_skb_get_premapped_frags(skb) ||
			(skb->len > MAX_IMM_ULPTX_WR_LEN);
}


enum cxgb4_uld {
	CXGB4_ULD_RDMA,
	CXGB4_ULD_ISCSI,
	CXGB4_ULD_TOE,
	CXGB4_ULD_MAX
};

enum cxgb4_state {
	CXGB4_STATE_UP,
	CXGB4_STATE_START_RECOVERY,
	CXGB4_STATE_DOWN,
	CXGB4_STATE_DETACH,
	CXGB4_STATE_SHUTDOWN
};

enum cxgb4_control {
	CXGB4_CONTROL_SET_OFFLOAD_POLICY,
	CXGB4_CONTROL_DB_FULL,
	CXGB4_CONTROL_DB_EMPTY,
	CXGB4_CONTROL_DB_DROP,
};

struct pci_dev;
struct l2t_data;
struct net_device;
struct pkt_gl;
struct t4_lro_mgr;

struct cxgb4_range {
	unsigned int start;
	unsigned int size;
};

struct cxgb4_virt_res {                      /* virtualized HW resources */
	struct cxgb4_range ddp;
	struct cxgb4_range iscsi;
	struct cxgb4_range stag;
	struct cxgb4_range rq;
	struct cxgb4_range srq;
	struct cxgb4_range pbl;
	struct cxgb4_range qp;
	struct cxgb4_range cq;
	struct cxgb4_range ocq;
#ifdef CONFIG_PO_FCOE
	u8 *ppod_map;
	u16 *tid2xid;
	unsigned int toe_nppods;
	unsigned int fcoe_nppods;
	spinlock_t ppod_map_lock;	/* page pod map lock */
#endif /* CONFIG_PO_FCOE */
};

#define OCQ_WIN_OFFSET(pdev, vres) \
	(pci_resource_len((pdev), 2) - roundup_pow_of_two((vres)->ocq.size))

/*
 * Block of information the LLD provides to ULDs attaching to a device.
 */
struct cxgb4_lld_info {
	struct pci_dev *pdev;                /* associated PCI device */
	struct l2t_data *l2t;                /* L2 table */
	struct tid_info *tids;               /* TID table */
	struct net_device **ports;           /* device ports */
	const struct cxgb4_virt_res *vr;     /* assorted HW resources */
	const unsigned short *mtus;          /* MTU table */
	const unsigned short *rxq_ids;       /* the ULD's Rx queue ids */
	const unsigned short *ciq_ids;       /* the ULD's concentrator IQ ids */
	unsigned short nrxq;                 /* # of Rx queues */
	unsigned short ntxq;                 /* # of Tx queues */
	unsigned short nciq;
	unsigned char nchan:4;               /* # of channels */
	unsigned char nports:4;              /* # of ports */
	unsigned char wr_cred;               /* WR 16-byte credits */
	unsigned char fw_api_ver;            /* FW API version */
	enum chip_type adapter_type;         /* type of adapter */
	unsigned int fw_vers;                /* FW version */
	unsigned int iscsi_iolen;            /* iSCSI max I/O length */
	unsigned short udb_density;          /* # of user DB/page */
	unsigned short ucq_density;          /* # of user CQs/page */
	unsigned short tx_db_wc;             /* use TX Doorbell Write Combining */
	unsigned short filt_mode;            /* filter optional components */
	unsigned short tx_modq[NCHAN]; 	     /* maps each tx channel to a scheduler queue */
	void __iomem *gts_reg;               /* address of GTS register */
	void __iomem *db_reg;                /* address of kernel doorbell */
	int dbfifo_int_thresh;		     /* doorbell fifo int threshold */
	unsigned int sge_ingpadboundary;     /* SGE ingress padding boundary */
	unsigned int sge_pktshift;   	     /* Padding between CPL and packet Data */
	unsigned int sge_egrstatuspagesize;  /* SGE egress status page size */
	unsigned int pf;                     /* Physical Function we're using */
	bool enable_fw_ofld_conn;	     /* Enable connection through fw WR */
	unsigned int nsched_cls;             /* number of traffic classes */
	unsigned int max_ordird_qp;	     /* Max ORD/IRD depth per RDMA QP */
	unsigned int max_ird_adapter;	     /* Max IRD memory per adapter */
	bool ulptx_memwrite_dsgl;            /* use of T5 DSGL allowed */
	unsigned int iscsi_tagmask;          /* iscsi ddp tag mask */
	unsigned int iscsi_pgsz_order;       /* iscsi ddp page size orders */
	unsigned int cclk_ps;		     /* Core clock period in picoseconds */
	unsigned int iscsi_llimit;	     /* chip's iscsi region llimit */
	void **iscsi_ppm;	             /* iscsi pagepod manager */
	int nodeid;			     /* device numa node id */
	unsigned char ulp_t10dif;            /* t10dif support in ulp */
};

struct cxgb4_uld_info {
	const char *name;
	void *(*add)(const struct cxgb4_lld_info *p);
	int (*rx_handler)(void *handle, const __be64 *rsp,
			  const struct pkt_gl *gl);
	int (*ma_failover_handler)(void *handle, const __be64 *rsp,
				   const struct pkt_gl *gl);
	int (*state_change)(void *handle, enum cxgb4_state new_state);
	int (*control)(void *handle, enum cxgb4_control control, ...);
	int (*lro_rx_handler)(void *handle, const __be64 *rsp,
			      const struct pkt_gl *gl,
			      struct t4_lro_mgr *lro_mgr,
			      struct napi_struct *napi);
	void (*lro_flush)(struct t4_lro_mgr *);
};

int cxgb4_register_uld(enum cxgb4_uld type, const struct cxgb4_uld_info *p);
int cxgb4_unregister_uld(enum cxgb4_uld type);
int cxgb4_ofld_send(struct net_device *dev, struct sk_buff *skb);
unsigned int cxgb4_dbfifo_count(const struct net_device *dev, int lpfifo);
unsigned int cxgb4_port_chan(const struct net_device *dev);
unsigned int cxgb4_port_viid(const struct net_device *dev);
unsigned int cxgb4_tp_smt_idx(enum chip_type chip, unsigned int viid);
unsigned int cxgb4_port_idx(const struct net_device *dev);
int cxgb4_dcb_enabled(const struct net_device *dev);
struct net_device *cxgb4_netdev_by_hwid(struct pci_dev *pdev, unsigned int id);
unsigned int cxgb4_best_mtu(const unsigned short *mtus, unsigned short mtu,
			    unsigned int *idx);
unsigned int cxgb4_best_aligned_mtu(const unsigned short *mtus,
				    unsigned short header_size,
				    unsigned short data_size_max,
				    unsigned short data_size_align,
				    unsigned int *mtu_idxp);
void cxgb4_get_tcp_stats(struct pci_dev *pdev, struct tp_tcp_stats *v4,
                        struct tp_tcp_stats *v6);
int cxgb4_wr_mbox(struct net_device *dev, const void *cmd, int size, void *rpl);
int cxgb4_sync_txq_pidx(struct net_device *dev, u16 qid, u16 pidx, u16 size);
int cxgb4_flush_eq_cache(struct net_device *dev);
int cxgb4_read_tpte(struct net_device *dev, u32 stag, __be32 *tpte);
int cxgb4_set_params(struct net_device *dev, unsigned int nparams,
		     const u32 *params, const u32 *val);
u64 cxgb4_read_sge_timestamp(struct net_device *dev);
struct sk_buff *cxgb4_pktgl_to_skb(struct napi_struct *napi,
				   const struct pkt_gl *gl,
				   unsigned int skb_len, unsigned int pull_len);

enum cxgb4_bar2_qtype { CXGB4_BAR2_QTYPE_EGRESS, CXGB4_BAR2_QTYPE_INGRESS };
int cxgb4_bar2_sge_qregs(struct net_device *dev,
			 unsigned int qid,
			 enum cxgb4_bar2_qtype qtype,
			 int user,
			 u64 *pbar2_qoffset,
			 unsigned int *pbar2_qid);
void cxgb4_fatal_err(struct net_device *dev);

/*
 * Allocate n page pods.  Returns -1 on failure or the page pod tag.
 */
static inline int cxgb4_alloc_ppods(unsigned long *bmap, unsigned int max_ppods,
				    unsigned int start, unsigned int n,
				    unsigned int align_mask)
{
	unsigned long tag;

	tag = bitmap_find_next_zero_area(bmap, max_ppods, start, n, align_mask);
	if (unlikely(tag >= max_ppods))
		return -1;

	bitmap_set(bmap, tag, n);
	return tag;
}

static inline void cxgb4_free_ppods(unsigned long *bmap,
				    unsigned int tag, unsigned int n)
{
	bitmap_clear(bmap, tag, n);
}

#endif  /* !__CXGB4_OFLD_H */
