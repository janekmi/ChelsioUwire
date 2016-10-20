/*
 * This file contains declarations for the Chelsio CPL5 message processing.
 *
 * Copyright (C) 2003-2015 Chelsio Communications.  All rights reserved.
 *
 * Written by Dimitris Michailidis (dm@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef _CHELSIO_CPL_IO_STATE_H
#define _CHELSIO_CPL_IO_STATE_H

#include "t4_ddp_state.h"

/*
 * A map of the world.
 * -------------------
 */

/*
 *    ---           +----------------+
 *     |            |      sock      |
 *     |     Linux  | -------------- |
 *     |            |    tcp_sock    |
 *     |            +----------------+
 *     |                    | sk_protinfo
 * Connection               V
 *     |            +----------------+
 *     |            |                |
 *     |    t4_tom  |  cpl_io_state  |
 *     |            |                |
 *    ---           +----------------+
 *                     | toedev
 *                     |
 *    ---           +--|-------------+
 *     |            |  |             |
 *     |    t4_tom  |  |  tom_data   |
 *  Device          |  V             |
 *     |  /         |  +-tdev-----+  |    lldev     +----------------+
 *     |  |         |  |          |---------------->|                |
 *     |  | toecore |  |  toedev  |  |    ec_ptr    |   net_device   |  Linux
 *     |  |         |  |          |<----------------|                |
 *     |  \         |  +----------+  |              | -------------- |
 *     |            |                |          .-->| priv:port_info |  cxgb4
 *    ---           +----------------+          |   +----------------+
 *                                              |            | adapter
 *                                      port[i] |            V
 *                                              |   +----------------+
 *                                              `---|     adapter    |
 *                                                  +----------------+
 *
 * The net_device private area contains the "port_info" data structure which
 * contains a pointer to the adapter data structure and the adapter structure
 * contains pointers to its net_device's in "port[i]".
 */


/*
 * Per-connection state.
 * ---------------------
 */

#ifdef CONFIG_T4_MA_FAILOVER

/* MA-Failover CPL_SET_TCB_FIELD cookies */
enum {
	MA_FAILOVER_COOKIE_RCV_WND = 1,
	MA_FAILOVER_COOKIE_RX_HDR_OFFSET = 2,
	MA_FAILOVER_COOKIE_NEW_RCV_WND = 3,
	MA_FAILOVER_COOKIE_L2TIX = 4,
};

enum ma_fail_info_flags {
	MA_FAIL_NONE,
	MA_FAIL_OVER,
	MA_FAIL_DONE,
	MA_FAIL_ABORT
};

struct ma_failover_info {
       unsigned long flags;
       struct net_device *egress_dev;
       unsigned int tx_c_chan;         /* PCIe channel */
       unsigned int rx_c_chan;         /* Rx priority channel */
       unsigned int smac_idx;          /* Source MAC index */
       u8 port_id;                     /* egress netdev port id */
       unsigned short port_speed;      /* egress netdev link_cfg.speed */
       struct toedev *toedev;          /* TOE device */
       struct l2t_entry *l2t_e;        /* pointer to the L2T entry */
       struct l2t_entry *l2t_e_arpmiss;/* pointer to the dummy L2T entry */
       unsigned int txq_idx;  
       unsigned int rss_qid;           /* TOE RSS queue number */
       unsigned int tid;               /* TCP Control Block ID */
       struct hrtimer rx_drain_timer;  /* Timer to allow rx-drain */
       struct tasklet_struct get_tcb_task; /* tasklet to get tcb */
       u32 rcv_wnd;
       u32 rx_hdr_offset;
       u32 last_rcv_nxt;
       int rx_retry;
};     

#endif /* CONFIG_T4_MA_FAILOVER */

/*
 * This structure records all "non-standard" per-connection state for
 * offloaded TCP connections.  For "standard" state like packet/byte count
 * statistics and other data elements which are tracked by the Linux kernel
 * for software socket/TCP connections, we use the existing Linux data
 * structure fields.  This allows standard tools like netstat, etc. to work
 * well with offloaded connections and report reasonable results.
 */
struct cpl_io_state {
	struct sock *sk;
	unsigned long flags;		/* offload connection flags */

	unsigned int opt2;		/* CPL opt2 value for connection */
	unsigned int wr_max_credits;	/* max number of WR credits (16 byte units) */
	unsigned int wr_credits;	/* number of available WRs credits */
	unsigned int wr_unacked;	/* number of unacked WRs */

#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
	size_t zcopy_dma_unacked;	/* ZCOPY DMA bytes unacked */
#endif

	unsigned int delack_mode;	/* current delack mode */
	unsigned int delack_seq;	/* RX sequence of most recent delack */
					/*   mode change */
	unsigned int hw_rcv_nxt;	/* rcv_nxt from a GET_TCB_RPL */

	unsigned int mtu_idx;		/* MTU table index */
	unsigned int txq_idx;		/* HW queue associated with the TX path*/
	unsigned int rss_qid;		/* TOE RSS queue number */
	unsigned int tid;		/* TCP Control Block ID */
	unsigned int neg_adv_tid;	/* TID available in neg. advice message */
	unsigned int sched_cls;		/* scheduling class */
	unsigned int ulp_mode;		/* ULP mode */
	unsigned int tx_c_chan;		/* PCIe channel */
	unsigned int rx_c_chan;		/* Rx priority channel */
	unsigned int smac_idx;		/* Source MAC index */
	unsigned int sndbuf;		/* Send buffer size for allocating TX pages */
	u8 port_id;			/* egress netdev port id */
	unsigned short port_speed;	/* egress netdev link_cfg.speed */
	struct toedev *toedev;		/* TOE device */
	struct l2t_entry *l2t_entry;	/* pointer to the L2T entry */
	struct net_device *egress_dev;	/* TX_CHAN for act open retry */
	u8 lro;				/* LRO enabled or disabled */
	struct sk_buff *lro_skb;	/* The packet under aggregation */

	/*
	 * Transmit Data skbs are either on a Write Queue pending being sent
	 * to the hardware or are on the Work Request Queue heading towards
	 * the hardware.  The Work Request Queue is also used to send Control
	 * Messages to the hardware.
	 *
	 * Note that we don't use the Socket's sk->sk_write_queue for the
	 * Transmit Data Queue because there are cases where the Linux kernel
	 * TCP stack can attempt to process/clear that list.  A good example
	 * is when an intermediate router sends an ICMP Unreachable : Needs
	 * Fragmentation.  The Linux kernel will compute a new Path MTU and
	 * then call tcp_simple_retransmit() to process the Socket Write
	 * Queue.  (We rely of the hardware eventually sending us a Negative
	 * Advice "Abort" message to trigger looking at that new path MTU and
	 * applying it to the Offloaded Connection.)
	 *
	 * The Work Request Queue is currently implemented as a special
	 * singly-linked lists of skb Work Requests (Transmit Data and
	 * Control) linked via (struct wr_skb_cb *)->wr_next.  There's really
	 * no need for such a one-off set of list manipulation code and this
	 * would probably be more simply implemented as another (struct
	 * sk_buff_head) since an skb is never on both the TX and WR Queues at
	 * the same time ...
	 */
	struct sk_buff_head tx_queue;	/* queue of TX skbs not sent to HW */
	struct kref kref;		/* refcount for races between */
					/*   freeing atid and getting a tid */
	struct sk_buff *wr_skb_head;	/* head of WR queue */
	struct sk_buff *wr_skb_tail;	/* tail of WR queue */

	struct sk_buff *ctrl_skb_cache;	/* cached sk_buff for small control */
					/*   messages */
	struct sk_buff *txdata_skb_cache; /* abort path messages */
	struct sk_buff *skb_ulp_lhdr;	/* ulp iscsi with msg coalescing */
					/*   off: last cpl_iscsi_hdr (pdu */
					/*   header) rcv'ed */

	struct ddp_state ddp_state;	/* DDP state data */

	unsigned int txplen_max;	/* ulp max tx pdu length */
	unsigned int rtp_header_len;	/* RTP header len */
	void *passive_reap_next;	/* temp. placeholder for passive */
					/* connection handling */
#ifdef CONFIG_T4_MA_FAILOVER
	struct ma_failover_info ma_fail_info;
#endif
};

#define CPL_IO_STATE(sk)	(*(struct cpl_io_state **)&((sk)->sk_protinfo))
#define DDP_STATE(sk)		(&(CPL_IO_STATE(sk)->ddp_state))

/*
 * Offloaded connection state flags.
 */
enum cplios_flags {
	CPLIOS_CALLBACKS_CHKD,		/* socket callbacks have been sanitized */
	CPLIOS_ABORT_REQ_RCVD,		/* received one ABORT_REQ_RSS message */
	CPLIOS_TX_MORE_DATA,		/* still sending ULP data; don't set the SHOVE bit */
	CPLIOS_TX_WAIT_IDLE,		/* suspend Tx until in-flight data is ACKed */
	CPLIOS_ABORT_SHUTDOWN,		/* shouldn't send more abort requests */
	CPLIOS_ABORT_RPL_PENDING,	/* expecting an abort reply */
	CPLIOS_CLOSE_CON_REQUESTED,	/* we've sent a close_conn_req */
	CPLIOS_TX_DATA_SENT,		/* already sent a TX_DATA WR on this connection */
	CPLIOS_TX_FAILOVER,		/* Tx traffic failing over */
	CPLIOS_UPDATE_RCV_WND,		/* Need to update rcv window */
	CPLIOS_RST_ABORTED,		/* outgoing RST was aborted */
#ifdef CONFIG_T4_MA_FAILOVER
	CPLIOS_MA_FAILOVER,		/* Traffic failing over to new adap */
#endif
};

static inline void cplios_set_flag(struct sock *sk, enum cplios_flags flag)
{
	__set_bit(flag, &CPL_IO_STATE(sk)->flags);
}

static inline void cplios_reset_flag(struct sock *sk, enum cplios_flags flag)
{
	__clear_bit(flag, &CPL_IO_STATE(sk)->flags);
}

static inline int cplios_flag(struct sock *sk, enum cplios_flags flag)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);

	if (cplios == NULL)
		return 0;
	return test_bit(flag, &CPL_IO_STATE(sk)->flags);
}


/*
 * List of write requests hung off of connection.
 * ----------------------------------------------
 */

/*
 * This lives in skb->cb and is used to chain WRs in a linked list.
 */
struct wr_skb_cb {
	struct l2t_skb_cb l2t;		/* reserve space for l2t CB */
	struct sk_buff *next_wr;	/* next write request */
};

#define WR_SKB_CB(skb) ((struct wr_skb_cb *)(skb)->cb)

static inline void reset_wr_list(struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	cplios->wr_skb_head = cplios->wr_skb_tail = NULL;
}

static inline void __enqueue_wr_core(struct cpl_io_state *cplios, struct sk_buff *skb)
{
	WR_SKB_CB(skb)->next_wr = NULL;
	if (cplios->wr_skb_head == NULL)
		cplios->wr_skb_head = skb;
	else
		WR_SKB_CB(cplios->wr_skb_tail)->next_wr = skb;
	cplios->wr_skb_tail = skb;
}

/*
 * Add a WR to a socket's list of pending WRs.
 */
static inline void enqueue_wr(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);

	/*
 	 * We want to take an extra reference since both us and the driver
 	 * need to free the packet before it's really freed.  We know there's
 	 * just one user currently so we use atomic_set rather than skb_get
 	 * to avoid the atomic op.
 	 */
	atomic_set(&skb->users, 2);
	__enqueue_wr_core(cplios, skb);
}

static inline void enqueue_wr_shared(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);

	if (skb_shared(skb))
		skb_get(skb);
	else
		atomic_set(&skb->users, 2);
	__enqueue_wr_core(cplios, skb);
}

/*
 * Return the first pending WR without removing it from the list.
 */
static inline struct sk_buff *peek_wr(const struct sock *sk)
{
	return CPL_IO_STATE(sk)->wr_skb_head;
}

/*
 * Dequeue and return the first unacknowledged's WR on a socket's pending list.
 */
static inline struct sk_buff *dequeue_wr(struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct sk_buff *skb = cplios->wr_skb_head;

	if (likely(skb)) {
		/* Don't bother clearing the tail */
		cplios->wr_skb_head = WR_SKB_CB(skb)->next_wr;
		WR_SKB_CB(skb)->next_wr = NULL;
	}
	return skb;
}

#define wr_queue_walk(sk, skb) \
        for (skb = peek_wr(sk); skb; skb = WR_SKB_CB(skb)->next_wr)


/*
 * Upper Layer Protocol skb handling.
 * ----------------------------------
 */

/*
 * Similar to tcp_skb_cb but with ULP elements added to support DDP, iSCSI,
 * etc.
 */
struct ulp_skb_cb {
	struct wr_skb_cb wr;		/* reserve space for write request */
	u16 flags;			/* TCP-like flags */
	u8 rsvd;
	u8 ulp_mode;			/* ULP mode/submode of sk_buff */
	u32 seq;			/* TCP sequence number */
	union { /* ULP-specific fields */
		struct {
			u32 ddigest;	/* ULP rx_data_ddp selected field */
			u16 pdulen;	/* ULP rx_data_ddp selected field */
			u8 pi_len8;	/* Rx pi length, in mutliple of 8B */
			u8  pi_flags;	/* Rx pi related flags */
		} iscsi; /* iscsi rx */
		struct {
			u32 offset;	/* ULP DDP offset notification */
			u8 flags;	/* ULP DDP flags ... */
		} ddp;
		struct {
			short fix_txlen; /* ULP data len adjustment due to
					    pi tx */
		} iscsi_pi; /* iscsi tx fields */
	} ulp;
};

#define ULP_SKB_CB(skb) ((struct ulp_skb_cb *)&((skb)->cb[0]))

/*
 * Flags for ulp_skb_cb.flags.
 */
enum {
	ULPCB_FLAG_NEED_HDR  = 1 << 0,	/* packet needs a TX_DATA_WR header */
	ULPCB_FLAG_NO_APPEND = 1 << 1,	/* don't grow this skb */
	ULPCB_FLAG_BARRIER   = 1 << 2,	/* set TX_WAIT_IDLE after sending */
	ULPCB_FLAG_HOLD      = 1 << 3,	/* skb not ready for Tx yet */
	ULPCB_FLAG_COMPL     = 1 << 4,	/* request WR completion */
	ULPCB_FLAG_URG       = 1 << 5,	/* urgent data */
#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
	ULPCB_FLAG_ZCOPY     = 1 << 6,	/* direct reference to user pages */
	ULPCB_FLAG_ZCOPY_COW_SKIP = 1 << 7, /* zcopy done but VMA read-only */
	ULPCB_FLAG_ZCOPY_COW = 1 << 8,	/* copy on write for deferred writes */
#endif
	ULPCB_FLAG_ISCSI_WR  = 1 << 9,	/* Use FW_ISCSI_TX_DATA_WR in place of
					   FW_OFLD_TX_DATA_WR */
	ULPCB_FLAG_MEMWRITE  = 1 << 10,	/* memory write skb (Do not add WR hdr,
					   used to write ppod using ofldq */
	ULPCB_FLAG_ISCSI_FORCE = 1 << 11 /* Set force bit */

};

/* The ULP mode/submode of an skbuff */
#define skb_ulp_mode(skb)  (ULP_SKB_CB(skb)->ulp_mode)
enum {
	ULPCB_MODE_SUBMODE_ISCSI_HCRC = 1 << 0,	/* iscsi hdr crc enabled */
	ULPCB_MODE_SUBMODE_ISCSI_DCRC = 1 << 1	/* iscsi data crc enabled */
};

/* ULP: iSCSI rx_data_ddp selected field */
#define skb_ulp_iscsi_ddigest(skb)	(ULP_SKB_CB(skb)->ulp.iscsi.ddigest)
#define skb_ulp_iscsi_pdulen(skb)	(ULP_SKB_CB(skb)->ulp.iscsi.pdulen)

/*
 * ULP: For iscsi ULP connections HW may generate/drop/pass pi data bytes and
 * TCP sequence space must cosider these. There can be 4 cases:
 * 1. Generate pi: The message sent by host doesn't contain these bytes
 *                      but they are part of the TCP payload. In this case it
 *                      contain positive value.
 * 2. Drop pi: The message sent by host include these bytes but HW will
 *                  drop these after processing. In this case it will have 
 *                  negative value.
 * 2. Pass pi: The message sent by host includes these bytes and they are part
 *             of TCP payload also. Its value is 0 in this case.
 * 4. No pi:   No pi in message sent by host and no pi generation in HW. Its
 *             value is 0 (default).
 * 5. iscsi hdrs in iso: The message sent by host doesn't contain iscsi hdr
 * 			for all the pdus which will be created by HW to
 * 			send the data burst after segmentation.
 */
#define skb_ulp_len_adjust(skb)	(ULP_SKB_CB(skb)->ulp.iscsi_pi.fix_txlen)

/* XXX temporary compatibility for old code-base chisci */
#define skb_ulp_lhdr(sk)		(CPL_IO_STATE(sk)->skb_ulp_lhdr)
#define skb_ulp_ddigest(skb)		skb_ulp_iscsi_ddigest(skb)
#define skb_ulp_pdulen(skb)		skb_ulp_iscsi_pdulen(skb)

/* ULP: DDP */
#define skb_ulp_ddp_offset(skb)		(ULP_SKB_CB(skb)->ulp.ddp.offset)
#define skb_ulp_ddp_flags(skb)		(ULP_SKB_CB(skb)->ulp.ddp.flags)

/*
 * Set the ULP mode and submode for a Tx packet.
 */
static inline void skb_set_ulp_mode(struct sk_buff *skb, int mode, int submode)
{
	skb_ulp_mode(skb) = (mode << 4) | submode;
}

/*
 * Return the length of any HW additions that will be made to a Tx packet.
 * Such additions can happen for some types of ULP packets.
 */
static inline unsigned int ulp_extra_len(const struct sk_buff *skb)
{
	extern const unsigned int t4_ulp_extra_len[];
	return t4_ulp_extra_len[skb_ulp_mode(skb) & 3];
}

/*
 * skb Control Block Usage.
 * ------------------------
 *
 * This definition is used to make sure that we never exceed the size of
 * the skb Control Block.
 */
#ifndef BUILD_BUG_ON
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))
#endif

#define CPLIOS_SKB_CB_SIZE (sizeof (struct ulp_skb_cb))
#define CPLIOS_SKB_CB_MAX (sizeof (((struct sk_buff *)0)->cb))

#define CPLIOS_SKB_CB_CHECK \
	BUILD_BUG_ON(CPLIOS_SKB_CB_SIZE > CPLIOS_SKB_CB_MAX)


/*
 * Deferred skb processing.
 * ------------------------
 */

typedef void (*defer_handler_t)(struct toedev *dev, struct sk_buff *skb);

/*
 * Stores information used to send deferred CPL replies from process context.
 */
struct deferred_skb_cb {
	defer_handler_t handler;
	struct toedev *dev;
};

#define DEFERRED_SKB_CB(skb) ((struct deferred_skb_cb *)(skb)->cb)

void t4_defer_reply(struct sk_buff *skb, struct toedev *dev,
		    defer_handler_t handler);


/*
 * Backlog skb handling.
 * ---------------------
 */

/*
 * The definition of the backlog skb control buffer is provided by the
 * general TOE infrastructure.
 */
#include <net/offload.h>
#include "tom_compat.h"

/*
 * Top-level CPL message processing used by most CPL messages that
 * pertain to connections.
 */
static inline void process_cpl_msg(void (*fn)(struct sock *, struct sk_buff *),
				   struct sock *sk, struct sk_buff *skb)
{
        skb_reset_mac_header(skb);
        skb_reset_network_header(skb);
        skb_reset_transport_header(skb);

	bh_lock_sock(sk);
	if (unlikely(sock_owned_by_user(sk))) {
		BLOG_SKB_CB(skb)->backlog_rcv = fn;
		__sk_add_backlog(sk, skb);
	} else
		fn(sk, skb);
	bh_unlock_sock(sk);
}

#endif /* _CHELSIO_CPL_IO_STATE_H */
