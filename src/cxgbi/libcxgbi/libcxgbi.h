/*
 * libcxgbi.h: Chelsio common library for T3/T4 iSCSI driver.
 *
 * Copyright (c) 2012-2015 Chelsio Communications, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Written by: Karen Xie (kxie@chelsio.com)
	void *lldev;
 * Written by: Rakesh Ranjan (rranjan@chelsio.com)
 */

#ifndef	__LIBCXGBI_H__
#define	__LIBCXGBI_H__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/debugfs.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#ifdef IFA_IPADDR
#include <linux/inetdevice.h>
#endif
#include <linux/if_vlan.h>
#include <linux/scatterlist.h>
#include <linux/skbuff.h>
#include <linux/vmalloc.h>
#include <linux/kfifo.h>
#include <linux/sched.h>
#include <scsi/scsi_device.h>
#include <libiscsi_tcp.h>

#include "cxgbi_t10.h"
#include "cxgbi_ippm.h"
#include "libilro.h"

enum cxgbi_dbg_flag {
	CXGBI_DBG_ISCSI,
	CXGBI_DBG_DDP,
	CXGBI_DBG_TOE,
	CXGBI_DBG_SOCK,

	CXGBI_DBG_PDU_TX,
	CXGBI_DBG_PDU_RX,
	CXGBI_DBG_DEV,
};

#define log_debug(level, fmt, ...)	\
	do {	\
		if (dbg_level & (level)) \
			pr_info(fmt, ##__VA_ARGS__); \
	} while (0)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
#define pr_info_ipaddr(fmt_trail,					\
			addr1, addr2, args_trail...)			\
do {									\
	if (!((1 << CXGBI_DBG_SOCK) & dbg_level))			\
		break;							\
	pr_info("%pISpc - %pISpc, " fmt_trail,				\
		addr1, addr2, args_trail);				\
} while(0)

#else
#define pr_info_ipaddr(fmt_trail,					\
			addr1, addr2, args_trail...)			\
do {									\
	if (!((1 << CXGBI_DBG_SOCK) & dbg_level))			\
		break;							\
	if (addr1->sin_family == AF_INET)				\
		pr_info("[%pI4]:%u-[%pI4]:%u, " fmt_trail, 		\
			&addr1->sin_addr.s_addr, 			\
			ntohs(addr1->sin_port),				\
			&addr2->sin_addr.s_addr,			\
			ntohs(addr2->sin_port),				\
			args_trail);					\
	else {	/* ipv6 */						\
		struct sockaddr_in6 *_addr1 = (struct sockaddr_in6 *)addr1;	\
		struct sockaddr_in6 *_addr2 = (struct sockaddr_in6 *)addr2;	\
									\
		pr_info("[%pI6]:%u-[%pI6]:%u, " fmt_trail,		\
			&_addr1->sin6_addr,				\
			ntohs(_addr1->sin6_port),			\
			&_addr2->sin6_addr,				\
			ntohs(_addr2->sin6_port),			\
			args_trail);					\
	}								\
} while (0)
#endif

/* max. connections per adapter */
#define CXGBI_MAX_CONN		16384

/* always allocate rooms for AHS */
#define SKB_TX_ISCSI_PDU_HEADER_MAX	\
	(sizeof(struct iscsi_hdr) + ISCSI_MAX_AHS_SIZE)

#define	ISCSI_PDU_NONPAYLOAD_LEN	312 /* bhs(48) + ahs(256) + digest(8)*/

/*
 * align pdu size to multiple of 512 for better performance
 */
#define cxgbi_align_pdu_size(n) do { n = (n) & (~511); } while (0)

#define ULP2_MODE_ISCSI		2

#define ULP2_MAX_PKT_SIZE	16224
#define ULP2_MAX_PDU_PAYLOAD	\
	(ULP2_MAX_PKT_SIZE - ISCSI_PDU_NONPAYLOAD_LEN)

#define ULP2_MAX_ISO_PAYLOAD	65535

#define MAX_PROT_FRAGS	4

#define CXGBI_MAX_ISO_DATA_IN_SKB	\
	min_t(unsigned int, (MAX_SKB_FRAGS << PAGE_SHIFT), ULP2_MAX_ISO_PAYLOAD)
/* (63KB data +1008B pi bytes for 63K) < 65535) */
#define CXGBI_MAX_ISO_DATA_IN_SKB_WITH_PI	\
	min_t(unsigned int, \
	((MAX_SKB_FRAGS - MAX_PROT_FRAGS) << PAGE_SHIFT), 63*1024)

/* 
 * Threshold for disabling iso if we encounter
 * back to back tx credit crunch
 */
#define BB_TX_CR_THRESHOLD	(2)
/* hold off time for backing out iso*/
#define ISO_HOLD_TICKS		(1*HZ)
/* expanders */
#define is_iso_config(csk)	(csk->cdev->skb_iso_txhdr)
#define is_iso_disabled(csk)	(csk->disable_iso)

/*
 * For iscsi connections HW may inserts digest bytes into the pdu. Those digest
 * bytes are not sent by the host but are part of the TCP payload and therefore
 * consume TCP sequence space.
 */
static const unsigned int ulp2_extra_len[] = { 0, 4, 4, 8 };
static inline unsigned int cxgbi_ulp_extra_len(int submode)
{
	return ulp2_extra_len[submode & 3];
}

/*
 * sge_opaque_hdr -
 * Opaque version of structure the SGE stores at skb->head of TX_DATA packets
 * and for which we must reserve space.
 */
struct sge_opaque_hdr {
	void *dev;
	dma_addr_t addr[MAX_SKB_FRAGS + 1];
};

struct cxgbi_sock {
	struct cxgbi_device *cdev;

	int tid;
	int atid;
	unsigned long flags;
	unsigned int mtu;
	unsigned short rss_qid;
	unsigned short txq_idx;
	unsigned short advmss;
	unsigned int tx_chan;
	unsigned int rx_chan;
	unsigned int mss_idx;
	unsigned int smac_idx;
	unsigned char port_id;
	int wr_max_cred;
	int wr_cred;
	int wr_una_cred;
	u8 dcb_priority;
	unsigned char hcrc_len;
	unsigned char dcrc_len;
	unsigned char filler;

	void *l2t;
	struct sk_buff *wr_pending_head;
	struct sk_buff *wr_pending_tail;
	struct sk_buff *cpl_close;
	struct sk_buff *cpl_abort_req;
	struct sk_buff *cpl_abort_rpl;
	struct sk_buff *skb_ulp_lhdr;
	struct sk_buff *skb_lro;
	struct sk_buff *skb_lro_hold;

	spinlock_t lock;
	struct kref refcnt;
	unsigned int state;
	unsigned int csk_family;
	union {
		struct sockaddr_in saddr;
		struct sockaddr_in6 saddr6;
	};
	union {
		struct sockaddr_in daddr;
		struct sockaddr_in6 daddr6;
	};
	struct dst_entry *dst;
	struct sk_buff_head receive_queue;
	struct sk_buff_head write_queue;
	struct timer_list retry_timer;
	int err;
	rwlock_t callback_lock;
	void *user_data;

	u32 xmit_dlength_save;
	u32 pdu_tx_seq;
	u32 rcv_nxt;
	u32 copied_seq;
	u32 rcv_wup;
	u32 snd_nxt;
	u32 snd_una;
	u32 write_seq;
	u32 snd_win;
	u32 rcv_win;
	u32 snd_wscale;

	u32 disable_iso;
	u32 bb_tx_choke;
	unsigned long prev_iso_ts;
};

/*
 * connection states
 */
enum cxgbi_sock_states{
	CTP_CLOSED,
	CTP_CONNECTING,
	CTP_ACTIVE_OPEN,
	CTP_ESTABLISHED,
	CTP_ACTIVE_CLOSE,
	CTP_PASSIVE_CLOSE,
	CTP_CLOSE_WAIT_1,
	CTP_CLOSE_WAIT_2,
	CTP_ABORTING,
};

/*
 * Connection flags -- many to track some close related events.
 */
enum cxgbi_sock_flags {
	CTPF_ABORT_RPL_RCVD,	/*received one ABORT_RPL_RSS message */
	CTPF_ABORT_REQ_RCVD,	/*received one ABORT_REQ_RSS message */
	CTPF_ABORT_RPL_PENDING,	/* expecting an abort reply */
	CTPF_TX_DATA_SENT,	/* already sent a TX_DATA WR */

	CTPF_ACTIVE_CLOSE_NEEDED,/* need to be closed */
	CTPF_HAS_ATID,		/* reserved atid */
	CTPF_HAS_TID,		/* reserved hw tid */
	CTPF_OFFLOAD_DOWN,	/* offload function off */

	CTPF_TX_WAIT_IDLE,	/* suspend Tx until in-flight data is acked */
	CTPF_PEER_CHECKED,
	CTPF_PEER_ULP,
	CTPF_TX_LOGIN_ALIGNED,
};

struct sd_dif_tuple {
	__be16 guard_tag;    /* Checksum */
	__be16 app_tag;      /* Opaque storage */
	__be32 ref_tag;      /* Target LBA or indirect LBA */
};

struct cxgbi_skb_rx_cb {
	__u32 ddigest;
	__u32 pdulen;
#ifdef CXGBI_T10DIF_SUPPORT
	struct cxgbi_pdu_pi_info pi;
#endif
};

struct cxgbi_skb_tx_cb {
	__u16  iscsi_hdr_len;
#ifdef CXGBI_T10DIF_SUPPORT
	struct cxgbi_pdu_pi_info pi;
	void *pi_page;
#endif
	struct sk_buff *wr_next;
};

enum cxgbi_skcb_flags {
	SKCBF_TX_NEED_HDR,	/* packet needs a header */
	SKCBF_TX_PUSH,		/* tx push bit */
	SKCBF_TX_MEM_WRITE,	/* memory write */
	SKCBF_TX_FLAG_COMPL,	/* wr completion flag */

	SKCBF_RX_LRO,
	SKCBF_RX_COALESCED,	/* received whole pdu */
	SKCBF_RX_HDR,		/* recieved pdu header */
	SKCBF_RX_DATA,		/* recieved pdu payload */

	SKCBF_RX_STATUS,	/* recieved ddp status */
	SKCBF_RX_ISCSI_COMPL,	/* using iscsi completion feature */
	SKCBF_RX_DATA_DDPD,	/* pdu payload ddp'd */
	SKCBF_RX_HCRC_ERR,	/* header digest error */
	SKCBF_RX_DCRC_ERR,	/* data digest error */

	SKCBF_RX_PAD_ERR,	/* padding byte error */
#ifdef CXGBI_T10DIF_SUPPORT
	SKCBF_RX_PI,		/* PI cpl rcvd */
	SKCBF_RX_PI_DDPD,	/* pdu pi ddp'd */
	SKCBF_RX_PI_ERR,	/* PI verification error */

	SKCBF_TX_PI,		/* PI hdr in tx skb */
	/* Chelsio specific workaround for t10dif */
	 /* T10DIF_DDP_WORKAROUND */
	SKCBF_PI_OFFSET_UPDATED,	/* pi offset updated, used in Tx/Rx */
#endif
	SKCBF_TX_ISO,		/* iso cpl in tx skb */
};

struct cxgbi_skb_cb {
	unsigned long flags;
	unsigned int seq;
	unsigned char ulp_mode;
	union {
		struct cxgbi_skb_rx_cb rx;
		struct cxgbi_skb_tx_cb tx;
	};
};

#define CXGBI_SKB_CB(skb)	((struct cxgbi_skb_cb *)&((skb)->cb[0]))
#define cxgbi_skcb_flags(skb)		(CXGBI_SKB_CB(skb)->flags)
#define cxgbi_skcb_ulp_mode(skb)	(CXGBI_SKB_CB(skb)->ulp_mode)
#define cxgbi_skcb_tcp_seq(skb)		(CXGBI_SKB_CB(skb)->seq)
#define cxgbi_skcb_rx_ddigest(skb)	(CXGBI_SKB_CB(skb)->rx.ddigest)
#define cxgbi_skcb_rx_pdulen(skb)	(CXGBI_SKB_CB(skb)->rx.pdulen)
#define cxgbi_skcb_tx_wr_next(skb)	(CXGBI_SKB_CB(skb)->tx.wr_next)
#define cxgbi_skcb_tx_iscsi_hdrlen(skb)	\
					(CXGBI_SKB_CB(skb)->tx.iscsi_hdr_len)

#ifdef CXGBI_T10DIF_SUPPORT
#define cxgbi_skcb_rx_pi_len(skb)	(CXGBI_SKB_CB(skb)->rx.pi.pi_len)
#define cxgbi_skcb_tx_pi_page(skb)	(CXGBI_SKB_CB(skb)->tx.pi_page)
#define cxgbi_skcb_tx_prot_op(skb)	(CXGBI_SKB_CB(skb)->tx.pi.prot_op)
#define cxgbi_skcb_tx_guard_type(skb)	(CXGBI_SKB_CB(skb)->tx.pi.guard)
#define cxgbi_skcb_tx_pi_interval(skb)	(CXGBI_SKB_CB(skb)->tx.pi.interval)
#define cxgbi_skcb_tx_pi_offset_update(skb)	(CXGBI_SKB_CB(skb)->tx.pi.offset_update)
#define cxgbi_skcb_tx_dif_type(skb)	(CXGBI_SKB_CB(skb)->tx.pi.dif_type)
#define cxgbi_skcb_tx_pi_len(skb)	(CXGBI_SKB_CB(skb)->tx.pi.pi_len)
#define cxgbi_skcb_tx_pi_sgcnt(skb)	(CXGBI_SKB_CB(skb)->tx.pi.pi_sgcnt)
#define cxgbi_skcb_tx_pi_offset(skb)	(CXGBI_SKB_CB(skb)->tx.pi.pi_offset)
#define cxgbi_skcb_tx_pi_app_tag(skb)	(CXGBI_SKB_CB(skb)->tx.pi.app_tag)
#define cxgbi_skcb_tx_pi_ref_tag(skb)	(CXGBI_SKB_CB(skb)->tx.pi.ref_tag)

#endif

static inline void cxgbi_skcb_set_flag(struct sk_buff *skb,
					enum cxgbi_skcb_flags flag)
{
	__set_bit(flag, &(cxgbi_skcb_flags(skb)));
}

static inline void cxgbi_skcb_clear_flag(struct sk_buff *skb,
					enum cxgbi_skcb_flags flag)
{
	__clear_bit(flag, &(cxgbi_skcb_flags(skb)));
}

static inline int cxgbi_skcb_test_flag(const struct sk_buff *skb,
					enum cxgbi_skcb_flags flag)
{
	return test_bit(flag, &(cxgbi_skcb_flags(skb)));
}

static inline void cxgbi_sock_set_flag(struct cxgbi_sock *csk,
					enum cxgbi_sock_flags flag)
{
	__set_bit(flag, &csk->flags);
	log_debug(1 << CXGBI_DBG_SOCK,
		"csk 0x%p,%u,0x%lx, bit %d.\n",
		csk, csk->state, csk->flags, flag);
}

static inline void cxgbi_sock_clear_flag(struct cxgbi_sock *csk,
					enum cxgbi_sock_flags flag)
{
	__clear_bit(flag, &csk->flags);
	log_debug(1 << CXGBI_DBG_SOCK,
		"csk 0x%p,%u,0x%lx, bit %d.\n",
		csk, csk->state, csk->flags, flag);
}

static inline int cxgbi_sock_flag(struct cxgbi_sock *csk,
				enum cxgbi_sock_flags flag)
{
	if (csk == NULL)
		return 0;
	return test_bit(flag, &csk->flags);
}

static inline void cxgbi_sock_set_state(struct cxgbi_sock *csk, int state)
{
	log_debug(1 << CXGBI_DBG_SOCK,
		"csk 0x%p,%u,0x%lx, state -> %u.\n",
		csk, csk->state, csk->flags, state);
	csk->state = state;
}

static inline void cxgbi_sock_free(struct kref *kref)
{
	struct cxgbi_sock *csk = container_of(kref,
						struct cxgbi_sock,
						refcnt);
	if (csk) {
		log_debug(1 << CXGBI_DBG_SOCK,
			"free csk 0x%p, state %u, flags 0x%lx\n",
			csk, csk->state, csk->flags);
		kfree(csk);
	}
}

static inline void __cxgbi_sock_put(const char *fn, struct cxgbi_sock *csk)
{
	log_debug(1 << CXGBI_DBG_SOCK,
		"%s, put csk 0x%p, ref %u-1.\n",
		fn, csk, atomic_read(&csk->refcnt.refcount));
	kref_put(&csk->refcnt, cxgbi_sock_free);
}
#define cxgbi_sock_put(csk)	__cxgbi_sock_put(__func__, csk)

static inline void __cxgbi_sock_get(const char *fn, struct cxgbi_sock *csk)
{
	log_debug(1 << CXGBI_DBG_SOCK,
		"%s, get csk 0x%p, ref %u+1.\n",
		fn, csk, atomic_read(&csk->refcnt.refcount));
	kref_get(&csk->refcnt);
}
#define cxgbi_sock_get(csk)	__cxgbi_sock_get(__func__, csk)

static inline int cxgbi_sock_is_closing(struct cxgbi_sock *csk)
{
	return csk->state >= CTP_ACTIVE_CLOSE;
}

static inline int cxgbi_sock_is_established(struct cxgbi_sock *csk)
{
	return csk->state == CTP_ESTABLISHED;
}

static inline void cxgbi_sock_purge_write_queue(struct cxgbi_sock *csk)
{
	struct sk_buff *skb;

	while ((skb = __skb_dequeue(&csk->write_queue)))
		__kfree_skb(skb);
}

static inline unsigned int cxgbi_sock_compute_wscale(unsigned int win)
{
	unsigned int wscale = 0;

	while (wscale < 14 && (65535 << wscale) < win)
		wscale++;
	return wscale;
}

static inline struct sk_buff *alloc_wr(int wrlen, int dlen, gfp_t gfp)
{
	struct sk_buff *skb = alloc_skb(wrlen + dlen, gfp);

	if (skb) {
		__skb_put(skb, wrlen);
		memset(skb->head, 0, wrlen + dlen);
	} else
		pr_info("alloc cpl wr skb %u+%u, OOM.\n", wrlen, dlen);
	return skb;
}


/*
 * The number of WRs needed for an skb depends on the number of fragments
 * in the skb and whether it has any payload in its main body.  This maps the
 * length of the gather list represented by an skb into the # of necessary WRs.
 * The extra two fragments are for iscsi bhs and payload padding.
 */
#define SKB_WR_LIST_SIZE	 (MAX_SKB_FRAGS + 2)

static inline void cxgbi_sock_reset_wr_list(struct cxgbi_sock *csk)
{
	csk->wr_pending_head = csk->wr_pending_tail = NULL;
}

static inline void cxgbi_sock_enqueue_wr(struct cxgbi_sock *csk,
					  struct sk_buff *skb)
{
	cxgbi_skcb_tx_wr_next(skb) = NULL;
	/*
	 * We want to take an extra reference since both us and the driver
	 * need to free the packet before it's really freed. We know there's
	 * just one user currently so we use atomic_set rather than skb_get
	 * to avoid the atomic op.
	 */
	atomic_set(&skb->users, 2);

	if (!csk->wr_pending_head)
		csk->wr_pending_head = skb;
	else
		cxgbi_skcb_tx_wr_next(csk->wr_pending_tail) = skb;
	csk->wr_pending_tail = skb;
}

static inline int cxgbi_sock_count_pending_wrs(const struct cxgbi_sock *csk)
{
	int n = 0;
	const struct sk_buff *skb = csk->wr_pending_head;

	while (skb) {
		n += skb->csum;
		skb = cxgbi_skcb_tx_wr_next(skb);
	}
	return n;
}

static inline struct sk_buff *cxgbi_sock_peek_wr(const struct cxgbi_sock *csk)
{
	return csk->wr_pending_head;
}

static inline struct sk_buff *cxgbi_sock_dequeue_wr(struct cxgbi_sock *csk)
{
	struct sk_buff *skb = csk->wr_pending_head;

	if (likely(skb)) {
		csk->wr_pending_head = cxgbi_skcb_tx_wr_next(skb);
		cxgbi_skcb_tx_wr_next(skb) = NULL;
	}
	return skb;
}

void cxgbi_sock_check_wr_invariants(const struct cxgbi_sock *);
void cxgbi_sock_purge_wr_queue(struct cxgbi_sock *);
void cxgbi_sock_skb_entail(struct cxgbi_sock *, struct sk_buff *);
void cxgbi_sock_fail_act_open(struct cxgbi_sock *, int);
void cxgbi_sock_act_open_req_arp_failure(void *, struct sk_buff *);
void cxgbi_sock_closed(struct cxgbi_sock *);
void cxgbi_sock_established(struct cxgbi_sock *, unsigned int, unsigned int);
void cxgbi_sock_rcv_abort_rpl(struct cxgbi_sock *);
void cxgbi_sock_rcv_peer_close(struct cxgbi_sock *);
void cxgbi_sock_rcv_close_conn_rpl(struct cxgbi_sock *, u32);
void cxgbi_sock_rcv_wr_ack(struct cxgbi_sock *, unsigned int, unsigned int,
				int);
unsigned int cxgbi_sock_select_mss(struct cxgbi_sock *, unsigned int);
void cxgbi_sock_free_cpl_skbs(struct cxgbi_sock *);

struct cxgbi_hba {
	struct net_device *vdev;	/* vlan dev */
	struct net_device *ndev;	/* real dev */
	struct Scsi_Host *shost;
	struct cxgbi_device *cdev;
	__be32 ipv4addr;
	unsigned int cmds_max;
	unsigned int cmds_min;
	unsigned char port_id;
};

struct cxgbi_ports_map {
	unsigned int max_connect;
	unsigned int used;
	unsigned short sport_base;
	spinlock_t lock;
	unsigned int next;
	struct cxgbi_sock **port_csk;
};

struct cxgbi_pi_page_poolq {
	struct kfifo queue;
	void **pool;
	void **page_list;
	int max;
	spinlock_t lock;
};

#define CXGBI_FLAG_DEV_T3		0x1
#define CXGBI_FLAG_DEV_T4		0x2
#define CXGBI_FLAG_ADAPTER_RESET	0x4
#define CXGBI_FLAG_IPV4_SET		0x10
#define CXGBI_FLAG_ULPTX_DSGL		0x20
#define CXGBI_FLAG_USE_PPOD_OFLDQ	0x40 /* Use ofldq to write ppod */
#define CXGBI_FLAG_T10DIF_OFFSET_UPDATED	0x80

#define CXGBI_FLAG_DDP_OFF		0x100
struct cxgbi_device {
	struct list_head list_head;
	struct list_head rcu_node;
	unsigned int flags;
	unsigned int force;
	struct net_device **ports;
	void *lldev;
	struct cxgbi_hba **hbas;
	const unsigned short *mtus;
	unsigned char nmtus;
	unsigned char nports;
	struct pci_dev *pdev;
	struct dentry *debugfs_root;
	struct iscsi_transport *itp;

	unsigned int pfvf;
	unsigned int rx_credit_thres;
	unsigned int skb_tx_rsvd;
	unsigned int skb_rx_extra;	/* for msg coalesced mode */
	unsigned int tx_max_size;
#ifdef CXGBI_T10DIF_SUPPORT
	unsigned int skb_t10dif_txhdr;
#endif
	unsigned int skb_iso_txhdr;
	unsigned int rx_max_size;
	unsigned int round_robin_cnt;
	struct cxgbi_ports_map pmap;
#ifdef CXGBI_T10DIF_SUPPORT
	struct cxgbi_pi_page_poolq tx_pi_page_poolq;
#endif

	struct cxgbi_ppm* (*cdev2ppm)(struct cxgbi_device *);
	
	int (*csk_ddp_set_map)(struct cxgbi_ppm *, struct cxgbi_sock *,
			struct cxgbi_task_tag_info *);
	void (*csk_ddp_clear_map)(struct cxgbi_device *cdev,
			struct cxgbi_ppm *, struct cxgbi_task_tag_info *);
	int (*csk_ddp_setup_digest)(struct cxgbi_sock *,
				unsigned int, int, int, int);
	int (*csk_ddp_setup_pgidx)(struct cxgbi_sock *,
				unsigned int, int, bool);

	void (*csk_release_offload_resources)(struct cxgbi_sock *);
	int (*csk_rx_pdu_ready)(struct cxgbi_sock *, struct sk_buff *);
	u32 (*csk_send_rx_credits)(struct cxgbi_sock *, u32);
	int (*csk_push_tx_frames)(struct cxgbi_sock *, int);
	void (*csk_send_abort_req)(struct cxgbi_sock *);
	void (*csk_send_close_req)(struct cxgbi_sock *);
	int (*csk_alloc_cpls)(struct cxgbi_sock *);
	int (*csk_init_act_open)(struct cxgbi_sock *);

	void *dd_data;
};
#define cxgbi_cdev_priv(cdev)	((cdev)->dd_data)

struct cxgbi_conn {
	struct cxgbi_endpoint *cep;
	struct iscsi_conn *iconn;
	struct cxgbi_hba *chba;
	u32 task_idx_bits;
	unsigned int ddp_full;
	unsigned int ddp_tag_full;
};

struct cxgbi_endpoint {
	struct cxgbi_conn *cconn;
	struct cxgbi_hba *chba;
	struct cxgbi_sock *csk;
};

/* not using skb_frag_t because RHEL 6.x __skb_frag_set_page() 
 * take extra reference of the page than kernel.org
 */ 
struct cxgbi_frag {
	struct page *page;
	unsigned int offset;
	unsigned int size;
};

#define MAX_PDU_FRAGS	MAX_SKB_FRAGS
#define MAX_TX_PI_RSVD_PAGES	8
struct cxgbi_task_data {
	unsigned short flag;
#define TASK_SGL_CHECKED	0x1
#define TASK_SGL_COPY		0x2
#define TASK_USE_POOLPI_PAGE 0x4
	unsigned short nr_cfrags;
	struct cxgbi_frag cfrags[MAX_PDU_FRAGS];
	struct sk_buff *skb;
	struct page *pi_page;
	struct cxgbi_device *cdev;
	unsigned int dlen;
	unsigned int offset;
	unsigned int count;
	unsigned int sgoffset;
	unsigned int prot_nr_cfrags;
	unsigned int prot_offset;
	unsigned int pi_len;
	unsigned int prot_sgoffset;
	unsigned int tx_pi_offset;
	unsigned int total_count;
	unsigned int total_offset;
	unsigned int max_xmit_dlength;
	struct cxgbi_frag prot_cfrags[MAX_PROT_FRAGS];
	struct cxgbi_task_tag_info ttinfo;
#ifdef __VARIABLE_DDP_PAGE_SIZE__
	unsigned char pgsz_indx;
	unsigned char filler[3];
	struct scatterlist *sgl;
	unsigned int npages;
#endif
};
#define iscsi_task_cxgbi_data(task) \
	((task)->dd_data + sizeof(struct iscsi_tcp_task))

#define CXGBI_ISO_INFO_FSLICE 		0x01
#define CXGBI_ISO_INFO_LSLICE 		0x02
#define CXGBI_ISO_INFO_IMM_ENABLE	0x04
struct cxgbi_iso_info {
	unsigned char flags;
	unsigned char op;
	unsigned char ahs;
	unsigned char num_pdu;
	unsigned int mpdu;
	unsigned int burst_size;
	unsigned int len;
	unsigned int segment_offset;
	unsigned int datasn_offset;
	unsigned int buffer_offset;
};

static inline void *cxgbi_alloc_big_mem(unsigned int size,
					gfp_t gfp)
{
	void *p;

	if (size > (PAGE_SIZE << MAX_ORDER)
#ifdef HAS_KMALLOC_MAX_SIZE
		|| size > KMALLOC_MAX_SIZE
#endif
	   )
		p = vmalloc(size);
	else {
		p = kmalloc(size, gfp);
		if (!p)
			p = vmalloc(size);
	}
	if (p)
		memset(p, 0, size);
	return p;
}

static inline void cxgbi_free_big_mem(void *addr)
{
	if (is_vmalloc_addr(addr))
		vfree(addr);
	else
		kfree(addr);
}

static inline void cxgbi_set_iscsi_ipv4(struct cxgbi_hba *chba, __be32 ipaddr)
{
	if (chba->cdev->flags & CXGBI_FLAG_IPV4_SET)
		chba->ipv4addr = ipaddr;
	else
		pr_info("set iscsi ipv4 NOT supported, using %s ipv4.\n",
			chba->ndev->name);
}

struct cxgbi_device *cxgbi_device_register(unsigned int, unsigned int);
void cxgbi_device_unregister(struct cxgbi_device *);
void cxgbi_device_unregister_all(unsigned int flag);
struct cxgbi_device *cxgbi_device_find_by_lldev(void *);
struct cxgbi_device *cxgbi_device_find_by_netdev(struct net_device *, int *);
struct cxgbi_device *cxgbi_device_find_by_netdev_rcu(struct net_device *,
			int *);
int cxgbi_hbas_add(struct cxgbi_device *, unsigned int, unsigned int,
			unsigned int, unsigned int,
			struct scsi_host_template *,
			struct scsi_transport_template *);
void cxgbi_hbas_remove(struct cxgbi_device *);

int cxgbi_device_portmap_create(struct cxgbi_device *cdev, unsigned int base,
			unsigned int max_conn);
void cxgbi_device_portmap_cleanup(struct cxgbi_device *cdev);

#ifdef CXGBI_T10DIF_SUPPORT
int cxgbi_prot_register(struct cxgbi_device *, unsigned int dif_dix,
			unsigned int guard_type);
int cxgbi_tx_pi_page_pool_init(struct cxgbi_device *cdev,
			unsigned int order);
int cxgbi_tx_pi_page_pool_free(struct cxgbi_device *cdev);
#endif

void cxgbi_conn_tx_open(struct cxgbi_sock *);
void cxgbi_conn_pdu_ready(struct cxgbi_sock *);
int cxgbi_conn_alloc_pdu(struct iscsi_task *, u8);
int cxgbi_conn_init_pdu(struct iscsi_task *, unsigned int , unsigned int);
int cxgbi_conn_xmit_pdu(struct iscsi_task *);

void cxgbi_cleanup_task(struct iscsi_task *task);

#ifdef OISCSI_TRANSPORT_HAS_ATTR_IS_VISIBLE

#ifdef OISCSI_TRANSPORT_UMODE_T
umode_t
#else
mode_t
#endif
cxgbi_attr_is_visible(int param_type, int param);
#endif
void cxgbi_get_conn_stats(struct iscsi_cls_conn *, struct iscsi_stats *);
int cxgbi_set_conn_param(struct iscsi_cls_conn *,
			enum iscsi_param, char *, int);
#ifdef OISCSI_TRANSPORT_HAS_GET_EP_PARAM
int cxgbi_get_ep_param(struct iscsi_endpoint *ep, enum iscsi_param, char *);
#endif
int cxgbi_get_conn_param(struct iscsi_cls_conn *, enum iscsi_param, char *);
struct iscsi_cls_conn *cxgbi_create_conn(struct iscsi_cls_session *, u32);
int cxgbi_bind_conn(struct iscsi_cls_session *,
			struct iscsi_cls_conn *, u64, int);
void cxgbi_destroy_session(struct iscsi_cls_session *);
struct iscsi_cls_session *cxgbi_create_session(struct iscsi_endpoint *,
			u16, u16, u32);
int cxgbi_set_host_param(struct Scsi_Host *,
			enum iscsi_host_param, char *, int);
int cxgbi_get_host_param(struct Scsi_Host *, enum iscsi_host_param, char *);
struct iscsi_endpoint *cxgbi_ep_connect(struct Scsi_Host *,
			struct sockaddr *, int);
int cxgbi_ep_poll(struct iscsi_endpoint *, int);
void cxgbi_ep_disconnect(struct iscsi_endpoint *);

int cxgbi_slave_configure(struct scsi_device *sdev);

int cxgbi_iscsi_init(struct iscsi_transport *,
			struct scsi_transport_template **);
void cxgbi_iscsi_cleanup(struct iscsi_transport *,
			struct scsi_transport_template **);
void cxgbi_parse_pdu_itt(struct iscsi_conn *, itt_t, int *, int *);

void cxgbi_dump_bytes(char *, unsigned char *, int, int);
unsigned int cxgbi_select_delack(struct cxgbi_sock *,unsigned int);

/*
 * struct pagepod_hdr, pagepod - pagepod format
 */

#define CPL_RX_DDP_STATUS_DDP_SHIFT	16 /* ddp'able */
#define CPL_RX_DDP_STATUS_PAD_SHIFT	19 /* pad error */
#define CPL_RX_DDP_STATUS_HCRC_SHIFT	20 /* hcrc error */
#define CPL_RX_DDP_STATUS_DCRC_SHIFT	21 /* dcrc error */

void cxgbi_dump_sgl(const char *cap, struct scatterlist *sgl, int nents);
void cxgbi_ddp_set_one_ppod(struct cxgbi_pagepod *,
			struct cxgbi_task_tag_info *,
			struct scatterlist **sg_pp, unsigned int *sg_off);
void cxgbi_ddp_ppm_setup(void **ppm_pp, struct cxgbi_device *,
			struct cxgbi_tag_format *, unsigned int ppmax,
			unsigned int llimit, unsigned int start,
			unsigned int rsvd_factor);

void cxgbi_lro_skb_dump(struct sk_buff *);

#ifdef CXGBI_T10DIF_SUPPORT
int cxgbi_skb_tx_pi_len_correction(struct sk_buff *);
#endif

#endif	/*__LIBCXGBI_H__*/
