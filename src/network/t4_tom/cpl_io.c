/*
 * This file implements the Chelsio CPL5 message processing.
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

#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/toedev.h>
#include <linux/if_vlan.h>
#include <linux/kref.h>
#include <net/ipv6.h>
#include <net/transp_v6.h>
#include <net/ip6_route.h>
#include <net/tcp.h>
#include <net/offload.h>
#include <net/route.h>
#include <net/secure_seq.h>
#include <asm/atomic.h>
#include "common.h"
#include "defs.h"
#include "tom.h"
#include "l2t.h"
#include "clip_tbl.h"
#include "cpl_io_state.h"
#include "t4_ddp.h"
#include "t4_tcb.h"
#include "t4_regs.h"
#include "cxgb4_ctl_defs.h"
#include "cxgb4_ofld.h"
#include "t4fw_interface.h"
#include "t4_ma_failover.h"
#include "trace.h"
#include "tom_compat.h"
#include "offload.h"
#ifdef WD_TOE
#include "ntuples.h"
#include "wd_qp.h"
#endif

#define DEBUG_WR 0
#define TCB_PAGE_PTR_NULL 0x1ffffU

/*
 * Min receive window.  We want it to be large enough to accommodate receive
 * coalescing, handle jumbo frames, and not trigger sender SWS avoidance.
 */
#define MIN_RCV_WND (24 * 1024U)

extern struct sk_ofld_proto t4_tcp_prot;
extern struct sk_ofld_proto t4_tcp_v6_prot;
extern struct request_sock_ops t4_rsk_ops;
extern struct request_sock_ops t4_rsk6_ops;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0)
extern struct tcp_congestion_ops *tcp_reno_p;
#endif
extern int do_pass_open_rpl(struct tom_data *td, struct sk_buff *skb);

#ifdef WD_TOE
/*
 * external variable for WD-TOE.
 *
 * "wdtoe_dev_table" is where all the WD-TOE device or stack stored;
 *
 * "conn_tuple" is the table hold information of all the actively opening 
 *    connections (sending out a SYN to remote peer). This table is to help 
 *    user land WD-TOE library to have the tid<->sockfd mapping. Once the 
 *    connections are established, the entry in this table is cleared;
 *
 * "passive_conn_tuple" is the table hold information of all the passively
 *    opening/listening server connections (SYN from remote peer). Again, 
 *    this table is to help user land WD-TOE library to have the passive 
 *    side tid<->sockfd mapping. Once the connections are established, the 
 *    entry in this table is cleared;
 *
 * "listen_table" is the table to hold all listening server's local port 
 *    number. When a SYN arrives from remote peer to a local port, we look
 *    it up in this table to figure out which WD-TOE device, i.e. which 
 *    stack this SYN corresponds;
 */
extern struct wdtoe_device_table *wdtoe_dev_table;
extern struct conn_tuple *conn_tuple;
extern struct passive_tuple *passive_conn_tuple;
extern struct wdtoe_listen_device *listen_table;
#endif

/*
 * For ULP connections HW may add headers, e.g., for digests, that aren't part
 * of the messages sent by the host but that are part of the TCP payload and
 * therefore consume TCP sequence space.  Tx connection parameters that
 * operate in TCP sequence space are affected by the HW additions and need to
 * compensate for them to accurately track TCP sequence numbers. This array
 * contains the compensating extra lengths for ULP packets.  It is indexed by
 * a packet's ULP submode.
 */
const unsigned int t4_ulp_extra_len[] = {0, 4, 4, 8};

/*
 * This sk_buff holds a fake header-only TCP segment that we use whenever we
 * need to exploit SW TCP functionality that expects TCP headers, such as
 * tcp_create_openreq_child().  It's a RO buffer that may be used by multiple
 * CPUs without locking.
 */
static struct sk_buff *tcphdr_skb __read_mostly;

/*
 * Socket filter that drops everything.  This is assigned to offloaded sockets
 * in order to make sure that any packets belonging to an offloaded socket
 * which may find their way into the Host Stack are dropped.  See
 * init_cpl_io() for the initialization.
 */
static struct sk_filter *drop_all;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
static struct sock_filter drop_insns[] = {
	{(BPF_RET | BPF_K), 0, 0, 0},
};

#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0)
static struct sock_filter drop_insns[] = {
	{BPF_S_RET_K, 0, 0, 0},
};

#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)

static struct sock_filter_int drop_insnsi[] = {
	{(BPF_JMP|BPF_EXIT), 0, 0, 0, 0},
};

#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0)

static struct sock_filter_int drop_insnsi[] = {
	BPF_EXIT_INSN(),
};

#else /* >= 3.17 */

static struct bpf_prog *drop_bpf;
static struct bpf_insn drop_insnsi[] = {
	BPF_EXIT_INSN(),
};

#endif /* >= 3.17 */

/*
 * TOE information returned through inet_diag for offloaded connections.
 */
struct t4_inet_diag_info {
	u32 toe_id;    /* determines how to interpret the rest of the fields */
	u32 tid;
	u8  wr_credits;
	u8  queue;
	u8  ulp_mode:4;
	u8  sched_class:4;
	u8  ddp_enabled;
	char dev_name[TOENAMSIZ];
};

/*
 * Similar to process_cpl_msg() but takes an extra socket reference around the
 * call to the handler.  Should be used if the handler may drop a socket
 * reference.
 */
static inline void process_cpl_msg_ref(void (*fn)(struct sock *,
						  struct sk_buff *),
				       struct sock *sk, struct sk_buff *skb)
{
	sock_hold(sk);
	process_cpl_msg(fn, sk, skb);
	sock_put(sk);
}

static inline int is_t4a(const struct toedev *dev)
{
	return dev->ttid == TOE_ID_CHELSIO_T4;
}

/*
 * Returns an sk_buff for a reply CPL message of size len.  If the input
 * sk_buff has no other users it is trimmed and reused, otherwise a new buffer
 * is allocated.  The input skb must be of size at least len.  Note that this
 * operation does not destroy the original skb data even if it decides to reuse
 * the buffer.
 */
static struct sk_buff *get_cpl_reply_skb(struct sk_buff *skb, size_t len,
					 gfp_t gfp)
{
	if (likely(!skb_is_nonlinear(skb) && !skb_cloned(skb))) {
		BUG_ON(skb->len < len);
		__skb_trim(skb, len);
		skb_get(skb);
	} else {
		skb = alloc_skb(len, gfp);
		if (skb)
			__skb_put(skb, len);
	}
	return skb;
}

/*
 * Like get_cpl_reply_skb() but the returned buffer starts out empty.
 */
static struct sk_buff *__get_cpl_reply_skb(struct sk_buff *skb, size_t len,
					   gfp_t gfp)
{
	if (likely(!skb_is_nonlinear(skb) && !skb_cloned(skb))) {
		__skb_trim(skb, 0);
		skb_get(skb);
	} else
		skb = alloc_skb(len, gfp);
	return skb;
}

/*
 * Determine whether to send a CPL message now or defer it.  A message is
 * deferred if the connection is in SYN_SENT since we don't know the TID yet.
 * For connections in other states the message is sent immediately.
 * If through_l2t is set the message is subject to ARP processing, otherwise
 * it is sent directly.
 */
inline void send_or_defer(struct sock *sk, struct tcp_sock *tp,
			  struct sk_buff *skb, int through_l2t)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);

	rcu_read_lock();
	if (rcu_access_pointer(cplios->toedev->in_shutdown)) {
		rcu_read_unlock();
		return;
	}
	rcu_read_unlock();

	if (unlikely(sk->sk_state == TCP_SYN_SENT))
		__skb_queue_tail(&tp->out_of_order_queue, skb);  // defer
	else if (through_l2t)
		cxgb4_sk_l2t_send(cplios->egress_dev, skb, cplios->l2t_entry, sk); // send through L2T
	else
		cxgb4_ofld_send(cplios->egress_dev, skb);          // send directly
}

/*
 * Populate a TID_RELEASE WR.  The skb must be already propely sized.
 */
static inline void mk_tid_release(struct sk_buff *skb, unsigned int chan, unsigned int tid)
{
	struct cpl_tid_release *req;
	unsigned int len = roundup(sizeof(struct cpl_tid_release), 16);

	req = (struct cpl_tid_release *)__skb_put(skb, len);
	memset(req, 0, len);
	set_wr_txq(skb, CPL_PRIORITY_SETUP, chan);
	INIT_TP_WR_MIT_CPL(req, CPL_TID_RELEASE, tid);
}

/*
 * Insert a socket to the TID table and take an extra reference.
 */
inline void sk_insert_tid(struct tom_data *d, struct sock *sk,
			  unsigned int tid)
{
	sock_hold(sk);
	cxgb4_insert_tid(d->tids, sk, tid, sk->sk_family);
}

static unsigned int select_mss(struct sock *sk, unsigned int pmtu, u16 peer_mss)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	unsigned int idx;
	struct tcp_sock *tp = tcp_sk(sk);
	struct dst_entry *dst = __sk_dst_get(sk);
	struct tom_data *d = TOM_DATA(cplios->toedev);
	unsigned int iphdrsize;
	unsigned int tcpopthdrsize = 0;

	/*
	 * Compute the size of the IP + TCP headers.
	 */
#if defined(CONFIG_TCPV6_OFFLOAD)
	if (sk->sk_family == AF_INET6)
		iphdrsize = sizeof(struct ipv6hdr) + sizeof(struct tcphdr);
	else
#endif
		iphdrsize = sizeof(struct iphdr) + sizeof(struct tcphdr);

	if (cplios->opt2 & F_TSTAMPS_EN)
		tcpopthdrsize += round_up(TCPOLEN_TIMESTAMP, 4);

	/*
	 * Compute the Maximum Segment Size based on all the constraints
	 * we've been given.
	 */
	tp->advmss = dst_metric_advmss(dst);
	if (USER_MSS(tp) && tp->advmss > USER_MSS(tp))
		tp->advmss = USER_MSS(tp);
	if (tp->advmss > pmtu - iphdrsize)
		tp->advmss = pmtu - iphdrsize;
	if (peer_mss && tp->advmss > peer_mss)
		tp->advmss = peer_mss;

	/*
	 * Now find a TP MTU Index which will give us an MSS not larger than
	 * our constrained size.  If we can get an MTU which will allow the
	 * MSS to be a multiple of 8 bytes we'll get better performance within
	 * the chip between TP and the memory controller.  Note that
	 * Advertised MSS includes both Data and TCP Option Headers but our
	 * goal is to get the Data Portion of a TCP Segment to be a multiple
	 * of 8 bytes so it'll slot into the chip memory nicely ...
	 */
	tp->advmss = (cxgb4_best_aligned_mtu(d->mtus,
					     iphdrsize + tcpopthdrsize,
					     tp->advmss - tcpopthdrsize,
					     8, &idx)
		      - iphdrsize);

	inet_csk(sk)->icsk_pmtu_cookie = pmtu;
	return idx;
}

void t4_select_window(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int wnd = tp->rcv_wnd;

	wnd = max_t(unsigned int, wnd, tcp_full_space(sk));

	wnd = max_t(unsigned int, MIN_RCV_WND, wnd);

        if (wnd > MAX_RCV_WND)
                wnd = MAX_RCV_WND;

/*
 * Check if we need to grow the receive window in response to an increase in
 * the socket's receive buffer size.  Some applications increase the buffer
 * size dynamically and rely on the window to grow accordingly.
 */

        if (wnd > tp->rcv_wnd) {
                tp->rcv_wup -= wnd - tp->rcv_wnd;
                tp->rcv_wnd = wnd;
		/* Mark the recieve window as updated */
		cplios_reset_flag(sk, CPLIOS_UPDATE_RCV_WND);
        }

}

unsigned int t4_select_delack(struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct toedev *dev = cplios->toedev;
	unsigned int dack_mode;
	
	dack_mode = TOM_TUNABLE(dev, delack);
	if (!dack_mode || !inet_csk(sk)->icsk_ack.pingpong)
		return 0;

	if ((dack_mode == 2) && (MSS_CLAMP(tp) > 1680))
		dack_mode = 3;

	if ((dack_mode == 3) && (tp->rcv_wnd < 2 * 26880))
		dack_mode = 1;

	if ((dack_mode == 2) && (tp->rcv_wnd < 2 * 16 * MSS_CLAMP(tp)))
		dack_mode = 1;
		
	if ((dev->ttid >= TOE_ID_CHELSIO_T4) && (cplios->delack_mode == 0) &&
		(tp->rcv_wnd > 2 * 2 * MSS_CLAMP(tp)))
		dack_mode = 1;

	return dack_mode;
}

#if VALIDATE_TID
#define VALIDATE_SOCK(sk) \
	do { \
		if (unlikely(!(sk))) \
			return CPL_RET_UNKNOWN_TID | CPL_RET_BUF_DONE; \
	} while (0)
#else
#define VALIDATE_SOCK(sk) do {} while (0)
#endif

/*
 * Called when we receive the last message from HW for a connection.  A
 * connection cannot transition to TCP_CLOSE prior to this event.
 * Resources related to the offload state of a connection (e.g., L2T entries)
 * must have been relinquished prior to calling this.
 */
void connection_done(struct sock *sk)
{
#if 0
	printk("connection_done: TID: %u, state: %d, dead %d, refs %d\n",
	       CPL_IO_STATE(sk)->tid, sk->sk_state, sock_flag(sk, SOCK_DEAD),
	       atomic_read(&sk->sk_refcnt));
//	dump_stack();
#endif

#ifdef T4_TRACE
	T4_TRACE1(TIDTB(sk),
		  "connection_done: GTS rpl pending %d, if pending wake",
		  cplios_flag(sk, CPLIOS_ABORT_RPL_PENDING));
#endif
	if (sock_flag(sk, SOCK_DEAD))
		t4_purge_receive_queue(sk);
	sk_wakeup_sleepers(sk, 0);
	tcp_done(sk);
}

/*
 * Determine the receive window scaling factor given a target max
 * receive window.
 */
static inline int select_rcv_wscale(int space, int wscale_ok, int window_clamp)
{
	int wscale = 0;

	if (space > MAX_RCV_WND)
		space = MAX_RCV_WND;
	if (window_clamp && window_clamp < space)
		space = window_clamp;

	if (wscale_ok)
		for (; space > 65535 && wscale < 14; space >>= 1, ++wscale) ;
	return wscale;
}


/* Returns bits 2:7 of a socket's TOS field */
#define SK_TOS(sk) ((inet_sk(sk)->tos >> 2) & M_DSCP)

/*
 * The next two functions calculate the option 0 value for a socket.
 */
inline unsigned long long calc_opt0(struct sock *sk)
{
	const struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	const struct tcp_sock *tp = tcp_sk(sk);

        return V_NAGLE((tp->nonagle & TCP_NAGLE_OFF) == 0) | F_TCAM_BYPASS |
		V_KEEP_ALIVE(sock_flag(sk, SOCK_KEEPOPEN) != 0) |
            	V_WND_SCALE(RCV_WSCALE(tp)) | V_MSS_IDX(cplios->mtu_idx) |
 		V_DSCP(SK_TOS(sk)) | V_ULP_MODE(cplios->ulp_mode) |
		V_RCV_BUFSIZ(min(tp->rcv_wnd >> 10, M_RCV_BUFSIZ));
}

unsigned int t4_calc_opt2(const struct sock *sk,
			 const struct offload_settings *s,
			 unsigned int iq_id)
{
	const struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct toedev *tdev = cplios->toedev;
	struct tom_data *td = TOM_DATA(tdev);
	struct cxgb4_lld_info *lldi = td->lldi;
	unsigned short chan = cxgb4_port_chan(tdev->lldev[cplios->port_id]);

	u32 opt2 = V_RX_CHANNEL(cplios->rx_c_chan) |
		V_TX_QUEUE(lldi->tx_modq[chan]) |
		F_RSS_QUEUE_VALID |
		V_RSS_QUEUE(iq_id);

	/*
	 * Absent a specified offload settings, the default is to enable RX
	 * Coalescing.  For T5 we also enable the ability to set the Initial
	 * Segment Sequence Number in CPL_ACT_OPEN_REQ{,_V6}.ISS fields.
	 */
	if (is_t4(lldi->adapter_type))
		opt2 |= F_RX_COALESCE_VALID;
	else {
		opt2 |= F_T5_OPT_2_VALID;
		opt2 |= F_T5_ISS;
	}
	opt2 |= V_RX_COALESCE(M_RX_COALESCE);

	if (cplios->ulp_mode == ULP_MODE_TCPDDP)
		opt2 |= F_RX_FC_VALID | F_RX_FC_DDP;

	if (tcp_win_scaling_enabled())
		opt2 |= F_WND_SCALE_EN;

	/*
	 * Other TCP options obey the sysctls in the absence of policies.
	 */
	if (s && s->tstamp >= 0)
		opt2 |= V_TSTAMPS_EN(s->tstamp);
	else if (tcp_timestamps_enabled())
		opt2 |= F_TSTAMPS_EN;

	if (s && s->sack >= 0)
		opt2 |= V_SACK_EN(s->sack);
	else if (tcp_sack_enabled())
		opt2 |= F_SACK_EN;

	if (unlikely(!s))
		return opt2;

	/*
	 * We have an ofload settings specification so it can specify behavior
	 * which is different from the default.  E.g. turning RX Coalescing.
	 */
	if (s->rx_coalesce >= 0) {
		opt2 &= ~V_RX_COALESCE(M_RX_COALESCE);
		opt2 |= V_RX_COALESCE(s->rx_coalesce ? M_RX_COALESCE : 0);
	}

	if (s->cong_algo >= 0) {
		if (is_t4(lldi->adapter_type))
			opt2 |= F_CONG_CNTRL_VALID;
		opt2 |= V_CONG_CNTRL(s->cong_algo);
	}

	if (tcp_sk(sk)->ecn_flags & TCP_ECN_OK)
		opt2 |= F_CCTRL_ECN;

	return opt2;
}

/*
 * This function is intended for allocations of small control messages.
 * Such messages go as immediate data and usually the pakets are freed
 * immediately.  We maintain a cache of one small sk_buff and use it whenever
 * it is available (has a user count of 1).  Otherwise we get a fresh buffer.
 */
struct sk_buff *alloc_ctrl_skb(struct sk_buff *skb, int len)
{
	if (likely(skb && !skb_shared(skb) && !skb_cloned(skb))) {
		__skb_trim(skb, 0);
		atomic_set(&skb->users, 2);
#ifdef DEBUG
		if (skb_tailroom(skb) < len) {
			printk(KERN_WARNING "Requested Length of sk_buff (%d) is larger "
				"than pre-allocated sk_buff cache (%d).\n",
			len, skb_tailroom(skb));
			BUG_ON(1);
		}
#endif

	} else if (likely(!in_atomic()))
		skb = alloc_skb_nofail(len);
	else
		skb = alloc_skb(len, GFP_ATOMIC);
	return skb;
}

static inline void free_wr_skb(struct sock *sk, struct sk_buff *skb)
{
#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
	if (skb->data[0] == FW_OFLD_TX_DATA_WR)
		t4_zcopy_cleanup_skb(sk, skb);
#endif
	kfree_skb(skb);
}

static void purge_wr_queue(struct sock *sk)
{
	struct sk_buff *skb;
	while ((skb = dequeue_wr(sk)) != NULL)
		free_wr_skb(sk, skb);
}

/*
 * Returns true if an sk_buff carries urgent data.
 */
static inline int skb_urgent(struct sk_buff *skb)
{
	return (ULP_SKB_CB(skb)->flags & ULPCB_FLAG_URG) != 0;
}

/*
 * Generic ARP failure handler that discards the buffer.
 */
static void arp_failure_discard(void *handle, struct sk_buff *skb)
{
	kfree_skb(skb);
}

/**
 *      sgl_len - calculates the size of an SGL of the given capacity
 *      @n: the number of SGL entries
 *
 *      Calculates the number of flits needed for a scatter/gather list that
 *      can hold the given number of entries.
 */
static inline unsigned int sgl_len(unsigned int n)
{
        /*
         * A Direct Scatter Gather List uses 32-bit lengths and 64-bit PCI DMA
         * addresses.  The DSGL Work Request starts off with a 32-bit DSGL
         * ULPTX header, then Length0, then Address0, then, for 1 <= i <= N,
         * repeated sequences of { Length[i], Length[i+1], Address[i],
         * Address[i+1] } (this ensures that all addresses are on 64-bit
         * boundaries).  If N is even, then Length[N+1] should be set to 0 and
         * Address[N+1] is omitted.
         *
         * The following calculation incorporates all of the above.  It's
         * somewhat hard to follow but, briefly: the "+2" accounts for the
         * first two flits which include the DSGL header, Length0 and
         * Address0; the "(3*(n-1))/2" covers the main body of list entries (3
         * flits for every pair of the remaining N) +1 if (n-1) is odd; and
         * finally the "+((n-1)&1)" adds the one remaining flit needed if
         * (n-1) is odd ...
         */
        n--;
        return (3 * n) / 2 + (n & 1) + 2;
}


/*
 *	is_ofld_imm - check whether a packet can be sent as immediate data
 *	@skb: the packet
 *
 *	Returns true if a packet can be sent as an offload WR with immediate
 *	data.
 *	FW_OFLD_TX_DATA_WR limits the payload to 255 bytes due to 8-bit field.
 *      However, FW_ULPTX_WR commands have a 256 byte immediate only
 *      payload limit.
 */
static inline int is_ofld_imm(const struct sk_buff *skb)
{	
	int length = skb->len;

	if (is_ofld_sg_reqd(skb))
		return 0;

	if (likely(ULP_SKB_CB(skb)->flags & ULPCB_FLAG_NEED_HDR)) {
		length += sizeof(struct fw_ofld_tx_data_wr);
		return length <= MAX_IMM_OFLD_TX_DATA_WR_LEN;
	}

	return 1;
}

/**
 *      calc_tx_flits_ofld - calculate # of flits for an offload packet
 *      @skb: the packet
 *
 *      Returns the number of flits needed for the SG offload packet.
 */
static inline unsigned int calc_tx_flits_ofld(const struct sk_buff *skb)
{
	unsigned int flits, cnt;

	flits = skb_transport_offset(skb) / 8;   /* headers */
	cnt = skb_shinfo(skb)->nr_frags;
	if (skb_tail_pointer(skb) != skb_transport_header(skb))
		cnt++;
	return flits + sgl_len(cnt);
}

u8 tcp_state_to_flowc_state(u8 state)
{
	u8 ret = FW_FLOWC_MNEM_TCPSTATE_ESTABLISHED;

	switch (state) {
	case TCP_ESTABLISHED:
		ret = FW_FLOWC_MNEM_TCPSTATE_ESTABLISHED;
		break;
	case TCP_CLOSE_WAIT:
		ret = FW_FLOWC_MNEM_TCPSTATE_CLOSEWAIT;
		break;
	case TCP_FIN_WAIT1:
		ret = FW_FLOWC_MNEM_TCPSTATE_FINWAIT1;
		break;
	case TCP_CLOSING:
		ret = FW_FLOWC_MNEM_TCPSTATE_CLOSING;
		break;
	case TCP_LAST_ACK:
		ret = FW_FLOWC_MNEM_TCPSTATE_LASTACK;
		break;
	case TCP_FIN_WAIT2:
		ret = FW_FLOWC_MNEM_TCPSTATE_FINWAIT2;
		break;
	};

	return ret;
}

/*
 * Return the number of 16-byte "credits" used by a FlowC Work Request sent by
 * send_tx_flowc_wr() (see below).  Normally this code would be inside
 * send_tx_flowc_wr() but there are some callers which need this information
 * for the purpose of credit accounting.  As such, this routine and
 * send_tx_flowc_wr() must always be changed together.
 */
int tx_flowc_wr_credits(struct sock *sk, int *nparamsp, int *flowclenp)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	int nparams, flowclen16, flowclen;

	/*
	 * Determine the number of parameters we're going to send and the
	 * consequent size of the Work Request.
	 */
	nparams = 9;
#ifdef CONFIG_CXGB4_DCB
	nparams++;
#endif
	if (cplios->sched_cls != SCHED_CLS_NONE)
		nparams++;
	if (cplios->txplen_max)
		nparams++;
	if (SND_WSCALE(tcp_sk(sk)))
		nparams++;

        flowclen = offsetof(struct fw_flowc_wr, mnemval[nparams]);
	flowclen16 = DIV_ROUND_UP(flowclen, 16);
	flowclen = flowclen16 * 16;

	/*
	 * Return the number of 16-byte credits used by the FlowC request.
	 * Pass back the nparams and actual FlowC length if requested.
	 */
	if (nparamsp)
		*nparamsp = nparams;
	if (flowclenp)
		*flowclenp = flowclen;
	return flowclen16;
}

void send_tx_flowc_wr(struct sock *sk, int compl, u32 snd_nxt, u32 rcv_nxt)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct tom_data *d = TOM_DATA(cplios->toedev);
	struct sk_buff *skb;
	struct fw_flowc_wr *flowc;
	int nparams, vparamidx, flowclen16, flowclen;
#ifdef CONFIG_CXGB4_DCB
	u16 vlan;
#endif

#ifdef WD_TOE
	struct wdtoe_device *wd_dev;
	int ret, iq_id, dev_idx, tbl_idx;
	/* find the associated wd_dev by the tid */
	ret = wdtoe_find_dev_by_tid(wdtoe_dev_table, &dev_idx, 
					&tbl_idx, cplios->tid);
	if (ret == 0) {
		/* 
		 * we find the tid in the wdtoe device table, 
		 * so we get "wd_dev" and figure out the iq_id 
		 * for this WDTOE connection.
		 */
		wd_dev = wdtoe_dev_table[dev_idx].wd_dev;
		iq_id = wd_dev->rxq_list[cplios->port_id]->iq.cntxt_id;
	} else {
		/*
		 * The tid is not in the wdtoe device table.
		 * This probably means we have WDTOE in place, 
		 * but we want this connection go through TOE instead.
		 */
		iq_id = cplios->rss_qid;
	}
#endif

	/*
	 * Determine the number of parameters we're going to send and the
	 * consequent size of the Work Request.
	 */
	flowclen16 = tx_flowc_wr_credits(sk, &nparams, &flowclen);

	/*
	 * Allocate the skb for the FlowC Work Request and clear it.
	 */
        skb = alloc_ctrl_skb(cplios->txdata_skb_cache, flowclen);
	BUG_ON(!skb);

        flowc = (struct fw_flowc_wr *)__skb_put(skb, flowclen);
	memset(flowc, 0, flowclen);

	/*
	 * Initialize the FlowC Work Request.
	 */
        flowc->op_to_nparams =
                htonl(V_FW_WR_OP(FW_FLOWC_WR) |
		      V_FW_WR_COMPL(compl) |
		      V_FW_FLOWC_WR_NPARAMS(nparams));
        flowc->flowid_len16 =
                htonl(V_FW_WR_LEN16(flowclen16) |
		      V_FW_WR_FLOWID(cplios->tid));

        flowc->mnemval[0].mnemonic = FW_FLOWC_MNEM_PFNVFN;
        flowc->mnemval[0].val = htonl(d->pfvf);
        flowc->mnemval[1].mnemonic = FW_FLOWC_MNEM_CH;
        flowc->mnemval[1].val = htonl(cplios->tx_c_chan);
        flowc->mnemval[2].mnemonic = FW_FLOWC_MNEM_PORT;
        flowc->mnemval[2].val = htonl(cplios->tx_c_chan);
        flowc->mnemval[3].mnemonic = FW_FLOWC_MNEM_IQID;
#ifdef WD_TOE
        flowc->mnemval[3].val = htonl(iq_id);
#else
        flowc->mnemval[3].val = htonl(cplios->rss_qid);
#endif
        flowc->mnemval[4].mnemonic = FW_FLOWC_MNEM_SNDNXT;
        flowc->mnemval[4].val = htonl(snd_nxt);
        flowc->mnemval[5].mnemonic = FW_FLOWC_MNEM_RCVNXT;
        flowc->mnemval[5].val = htonl(rcv_nxt);
        flowc->mnemval[6].mnemonic = FW_FLOWC_MNEM_SNDBUF;
        flowc->mnemval[6].val = htonl(cplios->sndbuf);
        flowc->mnemval[7].mnemonic = FW_FLOWC_MNEM_MSS;
        flowc->mnemval[7].val = htonl(tp->mss_cache);
        flowc->mnemval[8].mnemonic = FW_FLOWC_MNEM_TCPSTATE;
        flowc->mnemval[8].val = htonl(tcp_state_to_flowc_state(sk->sk_state));


	/*
	 * Variable parameters which are sometimes present ...
	 */
	vparamidx = 9;
#ifdef CONFIG_CXGB4_DCB
	flowc->mnemval[vparamidx].mnemonic = FW_FLOWC_MNEM_DCBPRIO;
	if (!cxgb4_dcb_enabled(cplios->egress_dev))
		flowc->mnemval[vparamidx].val = 0;
	else {
		vlan = cplios->l2t_entry->vlan;
		if (vlan == CPL_L2T_VLAN_NONE) {
			if (printk_ratelimit())
				printk(KERN_WARNING "Connection without VLAN "
			       "Tag on DCB Link\n");
			flowc->mnemval[vparamidx].val = 0;
		} else
			flowc->mnemval[vparamidx].val =
				htonl((vlan & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT);
	}
	vparamidx++;
#endif
	/*
	 * If the connection's Scheduling Class has been set, pass that in.
	 */
	if (cplios->sched_cls != SCHED_CLS_NONE) {
		flowc->mnemval[vparamidx].mnemonic = FW_FLOWC_MNEM_SCHEDCLASS;
		flowc->mnemval[vparamidx].val = htonl(cplios->sched_cls);
		vparamidx++;
	}

	if (cplios->txplen_max) {
		flowc->mnemval[vparamidx].mnemonic = FW_FLOWC_MNEM_TXDATAPLEN_MAX;
		flowc->mnemval[vparamidx].val = htonl(cplios->txplen_max);
		vparamidx++;
	}

	if (SND_WSCALE(tp)) {
		flowc->mnemval[vparamidx].mnemonic = FW_FLOWC_MNEM_RCV_SCALE;
		flowc->mnemval[vparamidx].val = cpu_to_be32(SND_WSCALE(tp));
		vparamidx++;
	}
	set_queue(skb, (cplios->txq_idx << 1) | CPL_PRIORITY_DATA, sk);
	send_or_defer(sk, tp, skb, 0);
}
EXPORT_SYMBOL(send_tx_flowc_wr);

static inline void make_tx_data_wr(struct sock *sk, struct sk_buff *skb,
				   unsigned int immdlen, int len,
				   u32 credits, u32 compl)
{
	const struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	const struct tom_data *d = TOM_DATA(cplios->toedev);
	const enum chip_type adapter_type = d->lldi->adapter_type;
	struct fw_ofld_tx_data_wr *req;
	unsigned int opcode = FW_OFLD_TX_DATA_WR;
	unsigned int wr_ulp_mode_force;

	if (ULP_SKB_CB(skb)->flags & ULPCB_FLAG_ISCSI_WR) {
		/* fw_ofld_tx_data_wr struct is used for this as well */
		opcode = FW_ISCSI_TX_DATA_WR;
	}

	req = (struct fw_ofld_tx_data_wr *)__skb_push(skb, sizeof(*req));
	req->op_to_immdlen = htonl(V_WR_OP(opcode) |
				V_FW_WR_COMPL(compl) |
				V_FW_WR_IMMDLEN(immdlen));
	req->flowid_len16 = htonl(V_FW_WR_FLOWID(cplios->tid) |
				V_FW_WR_LEN16(credits));

	/* for iscsi, the mode & submode setting is per-packet */
	if (cplios->ulp_mode == ULP_MODE_ISCSI)
		wr_ulp_mode_force =
		    V_TX_ULP_MODE(skb_ulp_mode(skb) >> 4) |
			V_TX_ULP_SUBMODE(skb_ulp_mode(skb) & 0xf);
	else {
		wr_ulp_mode_force = V_TX_ULP_MODE(cplios->ulp_mode);
		if (is_ofld_sg_reqd(skb))
			wr_ulp_mode_force |= F_FW_OFLD_TX_DATA_WR_ALIGNPLD |
				((tcp_sk(sk)->nonagle & TCP_NAGLE_OFF) ? 0 :
					F_FW_OFLD_TX_DATA_WR_ALIGNPLDSHOVE);
	}

	if (ULP_SKB_CB(skb)->flags & ULPCB_FLAG_ISCSI_FORCE)
			wr_ulp_mode_force |= is_t5(adapter_type) ?
				F_TX_FORCE : F_T6_TX_FORCE;

	req->lsodisable_to_flags = htonl(wr_ulp_mode_force |
			V_TX_URG(skb_urgent(skb)) |
			V_TX_SHOVE((!cplios_flag(sk, CPLIOS_TX_MORE_DATA)) &&
			skb_queue_empty(&cplios->tx_queue)));
	req->plen = htonl(len);
}

/*
 * Prepends TX_DATA_WR to buffers requesting a header using ULPCB_FLAG_NEED_HDR
 * waiting on a socket's send queue and sends them on to the TOE.
 * Must be called with the socket lock held. Returns the amount of send buffer 
 * space that was freed as a result of sending queued data to the TOE.
 * Buffers with headers should set ULPCB_FLAG_COMPL to request completion.
 */
int t4_push_frames(struct sock *sk, int req_completion)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	int total_size = 0;
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	struct tom_data *d;

	if (unlikely(sk_in_state(sk, TCPF_SYN_SENT | TCPF_CLOSE)))
		return 0;

	/*
	 * We shouldn't really be called at all after an abort but check just
	 * in case.
	 */
	if (unlikely(cplios_flag(sk, CPLIOS_ABORT_SHUTDOWN)))
		return 0;

	d = TOM_DATA(cplios->toedev);

	while (cplios->wr_credits && (skb = skb_peek(&cplios->tx_queue)) &&
	       !cplios_flag(sk, CPLIOS_TX_WAIT_IDLE) &&
	       (!(ULP_SKB_CB(skb)->flags & ULPCB_FLAG_HOLD) ||
		skb_queue_len(&cplios->tx_queue) > 1)) {

		unsigned int immdlen;
		int len;	/* length with ulp bytes inserted by h/w */
		unsigned int credits_needed, credit_len;
		unsigned int completion=0;
		int flowclen16=0;

		immdlen = len = credit_len = skb->len;
		if (!is_ofld_imm(skb)) {
			immdlen = skb_transport_offset(skb);
			credit_len = 8*calc_tx_flits_ofld(skb);
		}
		if (likely(ULP_SKB_CB(skb)->flags & ULPCB_FLAG_NEED_HDR))
			credit_len += sizeof(struct fw_ofld_tx_data_wr);
		credits_needed = DIV_ROUND_UP(credit_len, 16);
		/* Assumes the initial credits is large enough to support
                   fw_flowc_wr plus largest possible first payload */
		if (!cplios_flag(sk, CPLIOS_TX_DATA_SENT)) {
			flowclen16 = tx_flowc_wr_credits(sk, NULL, NULL);

			cplios->wr_credits -= flowclen16;
			cplios->wr_unacked += flowclen16;
			send_tx_flowc_wr(sk, 1, tp->snd_nxt, tp->rcv_nxt);
			cplios_set_flag(sk, CPLIOS_TX_DATA_SENT);
		}

		if (cplios->wr_credits < credits_needed)
			break;

		__skb_unlink(skb, &cplios->tx_queue);
		set_queue(skb, (cplios->txq_idx << 1) | CPL_PRIORITY_DATA, sk);
		skb->csum = credits_needed + flowclen16;    /* remember this until the WR_ACK */
		cplios->wr_credits -= credits_needed;
		cplios->wr_unacked += credits_needed;
		enqueue_wr(sk, skb);

		if (likely(ULP_SKB_CB(skb)->flags & ULPCB_FLAG_NEED_HDR)) {
			len += ulp_extra_len(skb) + skb_ulp_len_adjust(skb);
                        if ((req_completion && cplios->wr_unacked == credits_needed) ||
                            (ULP_SKB_CB(skb)->flags & ULPCB_FLAG_COMPL) ||
                            cplios->wr_unacked >= cplios->wr_max_credits / 2) {
                                completion = 1;
                                cplios->wr_unacked = 0;
                        }
			make_tx_data_wr(sk, skb, immdlen, len, credits_needed,
					completion);
			tp->snd_nxt += len;
			tp->lsndtime = tcp_time_stamp;
			if (completion)
				ULP_SKB_CB(skb)->flags &= ~ULPCB_FLAG_NEED_HDR;
		} else {
			struct cpl_close_con_req *req = cplhdr(skb);
			unsigned int cmd  = (G_CPL_OPCODE(ntohl(OPCODE_TID(req))));
			
			if (cmd == CPL_CLOSE_CON_REQ)
				cplios_set_flag(sk, CPLIOS_CLOSE_CON_REQUESTED);

			if ((ULP_SKB_CB(skb)->flags & ULPCB_FLAG_COMPL) &&
				(cplios->wr_unacked >= cplios->wr_max_credits / 2)) {
					req->wr.wr_hi |= htonl(F_FW_WR_COMPL);
					cplios->wr_unacked = 0;
			}
				
		}
		total_size += skb->truesize;
		if (ULP_SKB_CB(skb)->flags & ULPCB_FLAG_BARRIER)
			cplios_set_flag(sk, CPLIOS_TX_WAIT_IDLE);
		t4_set_arp_err_handler(skb, NULL, arp_failure_discard);
		cxgb4_sk_l2t_send(cplios->egress_dev, skb, cplios->l2t_entry, sk);
	}
	sk->sk_wmem_queued -= total_size;
	return total_size;
}
EXPORT_SYMBOL(t4_push_frames);

#ifndef TCP_CONGESTION_CONTROL
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0)
tcp_reno_p  = & struct tcp_congestion_ops {
        .name           = "",
        .owner          = THIS_MODULE,
};
#else
struct tcp_congestion_ops tcp_init_congestion_ops  = {
	.name		= "",
	.owner		= THIS_MODULE,
};
#endif
#endif

inline void free_atid(struct tid_info *tids, unsigned int atid)
{
	struct cpl_io_state *cplios;

	cplios = lookup_atid(tids, atid);
	cxgb4_free_atid(tids, atid);
	sock_put(cplios->sk);
	kref_put(&cplios->kref, t4_cplios_release);
}

/*
 * Release resources held by an offload connection (TID, L2T entry, etc.)
 */
void t4_release_offload_resources(struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct toedev *tdev = cplios->toedev;
	struct tid_info *tids;
	unsigned int tid = cplios->tid;

	if (!tdev)
		return;

	tids = TOM_DATA(tdev)->tids;
	cplios->rss_qid = cplios->txq_idx = 0;
	t4_release_ddp_resources(sk);

	kfree_skb(cplios->ctrl_skb_cache);
	cplios->ctrl_skb_cache = NULL;
	kfree_skb(cplios->txdata_skb_cache);
	cplios->txdata_skb_cache = NULL;

	if (cplios->wr_credits != cplios->wr_max_credits) {
		purge_wr_queue(sk);
		reset_wr_list(sk);
	}

	if (cplios->l2t_entry) {
		cxgb4_l2t_release(cplios->l2t_entry);
		cplios->l2t_entry = NULL;
	}
	if (sk->sk_family != AF_INET)
		cxgb4_clip_release(cplios->egress_dev,
			(const u32 *)((&inet6_sk_saddr(sk))->s6_addr), 1);

	if (sk->sk_state == TCP_SYN_SENT) {               // we have ATID
		free_atid(tids, tid);
		__skb_queue_purge(&tp->out_of_order_queue);
	} else {                                          // we have TID
		cxgb4_remove_tid(tids, cplios->port_id, tid, sk->sk_family);
		sock_put(sk);
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0)
	t4_set_ca_ops(sk, tcp_reno_p);
#else
	t4_set_ca_ops(sk, &tcp_init_congestion_ops);
#endif
	cplios->toedev = NULL;
}

/*
 * Returns whether a CPL message is not expected in the socket backlog of a
 * closed connection.  Most messages are illegal at that point except
 * ABORT_RPL_RSS and SET_TCB_RPL sent by DDP.
 */
static int bad_backlog_msg(unsigned int opcode)
{
	return opcode != CPL_ABORT_RPL_RSS && opcode != CPL_SET_TCB_RPL;
}

/*
 * Called for each sk_buff in a socket's receive backlog during
 * backlog processing.
 */
static int t4_backlog_rcv(struct sock *sk, struct sk_buff *skb)
{
#if VALIDATE_TID
	u8 opcode;
#endif

	/*
	 * NIC packets can sneak into the backlog once a sokcet is hashed and
	 * before the BPF drop filter is installed.  They'll have either IP or
	 * IPv6 protocol while TOE packets leave it at 0.  Look for them and
	 * drop them.
	 */
	if (skb->protocol) {
		kfree_skb(skb);
		return 0;
	}

#if VALIDATE_TID
	opcode = ((const struct rss_header *)cplhdr(skb))->opcode;
	if (unlikely(sk->sk_state == TCP_CLOSE && bad_backlog_msg(opcode))) {
		printk(KERN_ERR "unexpected CPL message with opcode %x for "
		       "closed TID %u\n", opcode, CPL_IO_STATE(sk)->tid);
		kfree_skb(skb);
		return 0;
	}
#endif

	BLOG_SKB_CB(skb)->backlog_rcv(sk, skb);
	return 0;
}

#ifdef CONFIG_TCP_OFFLOAD_MODULE
static void dummy_tcp_keepalive_timer(unsigned long data)
{
}
#endif

/*
 * Switch a socket to the offload protocol operations.  Note that the offload
 * operations do not contain the offload backlog handler, we install that
 * directly to the socket.
 */
static void install_offload_ops(struct sock *sk)
{
#if defined(CONFIG_TCPV6_OFFLOAD)
	if (sk->sk_family == AF_INET)
		sk->sk_prot = &t4_tcp_prot.proto;
	else
		sk->sk_prot = &t4_tcp_v6_prot.proto;
#else
	sk->sk_prot = &t4_tcp_prot.proto;
#endif
	sk->sk_backlog_rcv = t4_backlog_rcv;
	if (sk->sk_write_space == sk_stream_write_space)
		sk->sk_write_space = t4_write_space;

	if (sk->sk_filter)
		sk_filter_uncharge_compat(sk, sk->sk_filter);
	sk->sk_filter = drop_all;
	sk_filter_charge_compat(sk, sk->sk_filter);

#ifdef CONFIG_TCP_OFFLOAD_MODULE
	sk->sk_timer.function = dummy_tcp_keepalive_timer;
#endif
	sock_set_flag(sk, SOCK_OFFLOADED);
}

#if DEBUG_WR
static void dump_wrs(struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	u64 *d;
	struct sk_buff *p;

	printk("TID %u info:\n", cplios->tid);
	skb_queue_walk(&cplios->tx_queue, p) {
		d = cplhdr(p);
		printk("   len %u, frags %u, flags %x, data %llx\n",
		       p->len, skb_shinfo(p)->nr_frags, ULP_SKB_CB(p)->flags,
		       (unsigned long long)be64_to_cpu(*d));
	}
	printk("outstanding:\n");
	wr_queue_walk(sk, p) {
		d = cplhdr(p);
		printk("   len %u, frags %u, flags %x, data %llx,%llx,%llx\n",
		       p->len, skb_shinfo(p)->nr_frags, ULP_SKB_CB(p)->flags,
		       (unsigned long long)be64_to_cpu(*d),
		       (unsigned long long)be64_to_cpu(d[1]),
		       (unsigned long long)be64_to_cpu(d[2]));
	}
}

static int count_pending_wrs(const struct sock *sk)
{
	int n = 0;
	const struct sk_buff *p;

	wr_queue_walk(sk, p)
		n += p->csum;
	return n;
}

static void check_wr_invariants(const struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	int pending = count_pending_wrs(sk);

	if (unlikely(cplios->wr_avail + pending != cplios->wr_max))
		printk(KERN_ERR "TID %u: credit imbalance: avail %u, "
		       "pending %u, total should be %u\n", cplios->tid,
		       cplios->wr_avail, pending, cplios->wr_max);
}
#endif

#define T4_CONG_OPS(s) \
	{ .name = s, .owner = THIS_MODULE }

static struct tcp_congestion_ops t4_cong_ops[] = {
	T4_CONG_OPS("reno"),        T4_CONG_OPS("tahoe"),
	T4_CONG_OPS("newreno"),     T4_CONG_OPS("highspeed")
};

#ifdef WD_TOE
/**
 * wdtoe_remove_conn_tuple - sets a conn_tuple in c as not in use (free)
 * @c: array of connection tupes
 * @atid: atid of the tuple we want to make available
 *
 * returns: index of the successfully freed tuple, 0 otherwise
 */
static int wdtoe_remove_conn_tuple(struct conn_tuple *c, unsigned atid)
{
	int i;
	for (i = 0; i < NWDTOECONN; i++) {
		if (c[i].in_use && c[i].atid == atid) {
			c[i].in_use = 0;
			return i;
		}
	}

	return 0;
}
#endif

#ifdef WD_TOE
/*
 * Same logic as wdtoe_remove_conn_tuple(), but work on the passive 
 * connection table and mark one entry as free.
 */
static int wdtoe_remove_passive_conn_tuple(struct passive_tuple *c,
					unsigned stid, unsigned int tid)
{
	int i;
	for (i = 0; i < NWDTOECONN; i++) {
		if (c[i].in_use && c[i].stid == stid && c[i].tid == tid) {
			c[i].in_use = 0;
			return i;
		}
	}

	return 0;
}
#endif


static void mk_act_open_req(struct sock *sk, struct sk_buff *skb,
			    unsigned int qid_atid,
			    const struct l2t_entry *e,
			    const struct offload_settings *s)
{
	const struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tom_data *td = TOM_DATA(cplios->toedev);
#ifdef WD_TOE
	int ret;
#endif
	struct cpl_act_open_req *req = NULL;
	struct cpl_t5_act_open_req *t5req = NULL;
	struct cpl_t6_act_open_req *t6req = NULL;

	switch (CHELSIO_CHIP_VERSION(td->lldi->adapter_type)) {
	case CHELSIO_T4:
		req = (struct cpl_act_open_req *)__skb_put(skb, sizeof(*req));
		INIT_TP_WR(req, 0);
	break;
	case CHELSIO_T5:
		t5req = (struct cpl_t5_act_open_req *)__skb_put(skb,
								sizeof(*t5req));
		INIT_TP_WR(t5req, 0);
		req = (struct cpl_act_open_req *)t5req;
	break;
	case CHELSIO_T6:
	default:
		t6req = (struct cpl_t6_act_open_req *)__skb_put(skb,
								sizeof(*t6req));
		INIT_TP_WR(t6req, 0);
		req = (struct cpl_act_open_req *)t6req;
		t5req = (struct cpl_t5_act_open_req *)t6req;
	break;
	}

	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_ACT_OPEN_REQ,
					      qid_atid));
	set_wr_txq(skb, CPL_PRIORITY_SETUP, cplios->port_id);
	req->local_port = inet_sk(sk)->inet_sport;
	req->peer_port = inet_sk(sk)->inet_dport;
	req->local_ip = inet_sk(sk)->inet_saddr;
	req->peer_ip = inet_sk(sk)->inet_daddr;
	req->opt0 = cpu_to_be64(calc_opt0(sk) |
				V_L2T_IDX(e->idx) |
				V_SMAC_SEL(cplios->smac_idx) |
				V_TX_CHAN(cplios->tx_c_chan));

	if (is_t4(td->lldi->adapter_type)) {
		req->params = cpu_to_be32(cxgb4_select_ntuple(cplios->egress_dev, e));
#ifdef WD_TOE
		if (is_wdtoe(sk)) {
			ret = wdtoe_act_open_req(sk, G_TID_TID(qid_atid),
						 req->local_port, s,
						 &req->opt2);
			if (ret == -1)
				goto t4_toe;

			return;
		}
t4_toe:
#endif
		req->opt2 = htonl(cplios->opt2);
	} else if (is_t5(td->lldi->adapter_type)) {
		t5req->rsvd = cpu_to_be32(secure_tcp_sequence_number_offload(
				 inet_sk(sk)->inet_saddr,
				 inet_sk(sk)->inet_daddr,
				 inet_sk(sk)->inet_sport,
				 inet_sk(sk)->inet_dport) |
				 (sizeof(uint64_t) - 1));
		t5req->params = cpu_to_be64(V_FILTER_TUPLE(cxgb4_select_ntuple(cplios->egress_dev, e)));

#ifdef WD_TOE
		if (is_wdtoe(sk)) {
			ret = wdtoe_act_open_req(sk, G_TID_TID(qid_atid),
						 t5req->local_port, s,
						 &t5req->opt2);
			if (ret == -1)
				goto t5_toe;

			return;
		}
t5_toe:
#endif
		t5req->opt2 = htonl(cplios->opt2);
	} else {
		t6req->rsvd = cpu_to_be32(secure_tcp_sequence_number_offload(
				 inet_sk(sk)->inet_saddr,
				 inet_sk(sk)->inet_daddr,
				 inet_sk(sk)->inet_sport,
				 inet_sk(sk)->inet_dport) |
				 (sizeof(uint64_t) - 1));
		t6req->params = cpu_to_be64(V_FILTER_TUPLE(cxgb4_select_ntuple(cplios->egress_dev, e)));

#ifdef WD_TOE
		if (is_wdtoe(sk)) {
			ret = wdtoe_act_open_req(sk, G_TID_TID(qid_atid),
						 t6req->local_port, s,
						 &t6req->opt2);
			if (ret == -1)
				goto t6_toe;

			return;
		}
t6_toe:
#endif
		t6req->opt2 = htonl(cplios->opt2);
		/* TODO */
		//t6req->opt3 = htonl(cplios->opt3);
	}
}

static int mk_fw_act_open_req(struct sock *sk, unsigned int atid,
			    const struct l2t_entry *e)
{
	struct sk_buff *skb;
	struct fw_ofld_connection_wr *req;
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	u32 dack;

	if (ma_fail_mk_fw_act_open_req(sk, atid, e))
		return 0;

	dack = t4_select_delack(sk);

	skb = alloc_ctrl_skb(cplios->ctrl_skb_cache, sizeof(*req));
	if (!skb)
		return -ENOMEM;

	req = (struct fw_ofld_connection_wr *)__skb_put(skb, sizeof(*req));
	memset(req, 0, sizeof(*req));
	req->op_compl = htonl(V_WR_OP(FW_OFLD_CONNECTION_WR));
	req->len16_pkd = htonl(V_FW_WR_LEN16(DIV_ROUND_UP(sizeof(*req), 16)));
	req->le.filter = cpu_to_be32(cxgb4_select_ntuple(cplios->egress_dev, e));
	req->le.lport = inet_sk(sk)->inet_sport;
	req->le.pport = inet_sk(sk)->inet_dport;
	req->le.u.ipv4.lip = inet_sk(sk)->inet_saddr;
	req->le.u.ipv4.pip = inet_sk(sk)->inet_daddr;
	req->tcb.t_state_to_astid =
		htonl(V_FW_OFLD_CONNECTION_WR_T_STATE(TCP_SYN_SENT) |
				V_FW_OFLD_CONNECTION_WR_ASTID(atid));
	req->tcb.cplrxdataack_cplpassacceptrpl =
		htons(F_FW_OFLD_CONNECTION_WR_CPLRXDATAACK);
	req->tcb.tx_max = jiffies;
	req->tcb.rcv_adv = htons(1);
	req->tcb.opt0 = cpu_to_be64(calc_opt0(sk) |
				V_L2T_IDX(e->idx) |
				V_SMAC_SEL(cplios->smac_idx) |
				V_TX_CHAN(cplios->tx_c_chan));

	req->tcb.opt2 = htonl(cplios->opt2);

	set_wr_txq(skb, CPL_PRIORITY_CONTROL, cplios->port_id);
	t4_set_arp_err_handler(skb, NULL, NULL);
	cxgb4_sk_l2t_send(cplios->egress_dev, skb, cplios->l2t_entry, sk);

	return 0;
}

static int mk_fw_pass_open_req(struct tom_data *td, struct sk_buff *skb,
				 struct request_sock *oreq, u32 filter,
				 u16 window, struct l2t_entry *e,
				 struct cpl_io_state *cplios)
{
	struct sk_buff *req_skb;
	struct fw_ofld_connection_wr *req;
	struct cpl_pass_accept_req *cpl = cplhdr(skb);

	req_skb = alloc_skb(sizeof(struct fw_ofld_connection_wr), GFP_ATOMIC);
	if (!req_skb)
		return -ENOMEM;

	req = (struct fw_ofld_connection_wr *)__skb_put(req_skb, sizeof(*req));
	memset(req, 0, sizeof(*req));
	req->op_compl = htonl(V_WR_OP(FW_OFLD_CONNECTION_WR) | F_FW_WR_COMPL);
	req->len16_pkd = htonl(V_FW_WR_LEN16(DIV_ROUND_UP(sizeof(*req), 16)));
	req->le.version_cpl = htonl(F_FW_OFLD_CONNECTION_WR_CPL);
	req->le.filter = filter;
	req->le.lport = t4_get_req_lport(oreq);
	req->le.pport = inet_rsk(oreq)->ir_rmt_port;
	req->le.u.ipv4.lip = inet_rsk(oreq)->ir_loc_addr;
	req->le.u.ipv4.pip = inet_rsk(oreq)->ir_rmt_addr;
	req->tcb.rcv_nxt = htonl(tcp_rsk(oreq)->rcv_isn + 1);
	req->tcb.rcv_adv = htons(window);
	req->tcb.t_state_to_astid =
		 htonl(V_FW_OFLD_CONNECTION_WR_T_STATE(TCP_SYN_RECV) |
			V_FW_OFLD_CONNECTION_WR_RCV_SCALE(cpl->tcpopt.wsf) |
			V_FW_OFLD_CONNECTION_WR_ASTID(G_PASS_OPEN_TID(ntohl(cpl->tos_stid))));

	cplios->port_id = ((struct port_info *)netdev_priv(cplios->egress_dev))->port_id;
	cplios->rss_qid = td->lldi->rxq_ids[cplios->port_id*td->lldi->nrxq/td->lldi->nchan];
	cplios->l2t_entry = e;

	/* We store the qid in opt2 which will be used by firmware
	 * to send us the response to the work request
	 */
	req->tcb.opt2 = htonl(V_RSS_QUEUE(cplios->rss_qid));

	/* We initialize the MSS index in TCB to 0xF.
	 * So that when driver sends cpl_pass_accept_rpl
	 * TCB picks up the correct value. If this was 0
	 * TP will ignore any value > 0 for MSS index.
	 */
	req->tcb.opt0 = cpu_to_be64(V_MSS_IDX(0xF));
	req->cookie = cpu_to_be64((u64)(uintptr_t)skb);

	set_wr_txq(req_skb, CPL_PRIORITY_CONTROL, cplios->port_id);
	cxgb4_ofld_send(cplios->egress_dev, req_skb);
	return 0;
}

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
static void mk_act_open_req6(struct sock *sk, struct sk_buff *skb,
                            unsigned int qid_atid,
                            const struct l2t_entry *e,
                            const struct offload_settings *s,
			    const struct in6_addr *sip,
				const struct in6_addr *dip)
{
        const struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tom_data *td = TOM_DATA(cplios->toedev);
	struct cpl_act_open_req6 *req = NULL;
	struct cpl_t5_act_open_req6 *t5req = NULL;
	struct cpl_t6_act_open_req6 *t6req = NULL;

	switch (CHELSIO_CHIP_VERSION(td->lldi->adapter_type)) {
	case CHELSIO_T4:
		req = (struct cpl_act_open_req6 *)__skb_put(skb, sizeof(*req));
		INIT_TP_WR(req, 0);
	break;
	case CHELSIO_T5:
		t5req = (struct cpl_t5_act_open_req6 *)__skb_put(skb,
								 sizeof(*t5req));
		INIT_TP_WR(t5req, 0);
		req = (struct cpl_act_open_req6 *)t5req;
	break;
	case CHELSIO_T6:
	default:
		t6req = (struct cpl_t6_act_open_req6 *)__skb_put(skb,
								 sizeof(*t6req));
		INIT_TP_WR(t6req, 0);
		req = (struct cpl_act_open_req6 *)t6req;
		t5req = (struct cpl_t5_act_open_req6 *)t6req;
	break;
	}

	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_ACT_OPEN_REQ6, qid_atid));
	set_wr_txq(skb, CPL_PRIORITY_SETUP, cplios->port_id);
	req->local_port = inet_sk(sk)->inet_sport;
	req->peer_port = inet_sk(sk)->inet_dport;
	req->local_ip_hi = *(__be64 *)(sip->s6_addr);
	req->local_ip_lo = *(__be64 *)(sip->s6_addr + 8);
	req->peer_ip_hi = *(__be64 *)(dip->s6_addr);
	req->peer_ip_lo = *(__be64 *)(dip->s6_addr + 8);

	req->opt0 = cpu_to_be64(calc_opt0(sk) |
				V_L2T_IDX(e->idx) |
				V_SMAC_SEL(cplios->smac_idx) |
				V_TX_CHAN(cplios->tx_c_chan));

	if (is_t4(td->lldi->adapter_type)) {
		req->params = cpu_to_be32(cxgb4_select_ntuple(cplios->egress_dev, e));
		req->opt2 = htonl(cplios->opt2);
	} else {
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		t5req->rsvd = cpu_to_be32(secure_tcpv6_sequence_number(
					inet6_sk_saddr(sk).s6_addr32,
					inet6_sk_daddr(sk).s6_addr32,
					inet_sk(sk)->inet_sport,
					inet_sk(sk)->inet_dport) |
					(sizeof(uint64_t) - 1));
#endif
		t5req->params = cpu_to_be64(V_FILTER_TUPLE(cxgb4_select_ntuple(cplios->egress_dev, e)));
		t5req->opt2 = htonl(cplios->opt2);
		/* TODO */
		//if (is_t6(td->lldi->adapter_type))
		//	t6req->opt3 = htonl(cplios->opt3);
	}
}
#endif

/*
 * Convert an ACT_OPEN_RPL status to a Linux errno.
 */
static int act_open_rpl_status_to_errno(int status)
{
	switch (status) {
	case CPL_ERR_CONN_RESET:
		return ECONNREFUSED;
	case CPL_ERR_ARP_MISS:
		return EHOSTUNREACH;
	case CPL_ERR_CONN_TIMEDOUT:
		return ETIMEDOUT;
	case CPL_ERR_TCAM_FULL:
		return ENOMEM;
	case CPL_ERR_CONN_EXIST:
		return EADDRINUSE;
	default:
		return EIO;
	}
}

void act_open_req_arp_failure(void *handle, struct sk_buff *skb);

void t4_fail_act_open(struct sock *sk, int errno)
{
	sk->sk_err = errno;
	sk->sk_error_report(sk);
	t4_release_offload_resources(sk);
	connection_done(sk);
	T4_TCP_INC_STATS_BH(sock_net(sk), TCP_MIB_ATTEMPTFAILS);
}

static void act_open_retry_timer(unsigned long data)
{
	struct sk_buff *skb;
	struct sock *sk = (struct sock *)data;
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk))         /* try in a bit */
		sk_reset_timer(sk, &icsk->icsk_retransmit_timer,
			       jiffies + HZ / 20);
	else {
		/* no space is saved using hw specific cpl_act_open_req here
		 * no need to check sk_family either.
		 */
		skb = alloc_skb(
			   roundup(sizeof(struct cpl_t6_act_open_req6), 16),
				GFP_ATOMIC);
		if (!skb)
			t4_fail_act_open(sk, ENOMEM);
		else {
			unsigned int qid_atid = cplios->rss_qid << 14;

			qid_atid |= (unsigned int)cplios->tid;
			skb->sk = sk;
			t4_set_arp_err_handler(skb, NULL, act_open_req_arp_failure);
			if (sk->sk_family == AF_INET)
				mk_act_open_req(sk, skb, qid_atid,
					cplios->l2t_entry, NULL);
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
			else
				mk_act_open_req6(sk, skb, qid_atid,
					cplios->l2t_entry, NULL,
					&inet6_sk_rcv_saddr(sk),
					&inet6_sk_daddr(sk));
#endif

			cxgb4_sk_l2t_send(cplios->egress_dev, skb, cplios->l2t_entry, sk);
		}
	}
	bh_unlock_sock(sk);
	sock_put(sk);
}

static void deferred_tnl_connect(struct toedev *tdev, struct sk_buff *skb)
{
	struct sock *sk =  skb->sk;
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	int err;

	kfree_skb(skb);
	lock_sock(sk);
	if (sk->sk_state == TCP_SYN_SENT) {
		if (CPL_IO_STATE(sk)) {
			t4_release_offload_resources(sk);
			t4_install_standard_ops(sk);
		}
		if (!tp->write_seq) {
			if (sk->sk_family == AF_INET)
				tp->write_seq = secure_tcp_sequence_number_offload(inet->inet_saddr,
                                                             inet->inet_daddr,
                                                             inet->inet_sport,
                                                             inet->inet_dport);
#if defined(CONFIG_TCPV6_OFFLOAD)
			else
				tp->write_seq = secure_tcpv6_sequence_number(
								inet6_sk_saddr(sk).s6_addr32,
								inet6_sk_daddr(sk).s6_addr32,
								inet->inet_sport,
								inet->inet_dport);
#endif
		}
		inet->inet_id = tp->write_seq ^ jiffies;
		err = tcp_connect(sk);
		if (err)
			goto failure;
	}
	release_sock(sk);
	return;
failure:
	tcp_set_state(sk, TCP_CLOSE);
	sk->sk_route_caps = 0;
	inet->inet_dport = 0;
	sk->sk_err = err;
	sk->sk_error_report(sk);
	T4_TCP_INC_STATS_BH(sock_net(sk), TCP_MIB_ATTEMPTFAILS);
	release_sock(sk);
}

static void fixup_and_send_ofo(struct sock *sk, unsigned int tid);

/*
* Returns whether an ABORT_REQ_RSS/ACT_OPEN_RPL message is a negative advice.
*/
static inline int is_neg_adv(unsigned int status)
{
	return status == CPL_ERR_RTX_NEG_ADVICE ||
		status == CPL_ERR_KEEPALV_NEG_ADVICE ||
		status == CPL_ERR_PERSIST_NEG_ADVICE;
}

/*
 * Handle active open replies. Reply status is non-zero
 * except when ACT_OPEN_REQ has NON_OFFLOAD set.
 * Note miss in CLIP region is reported as CPL_ERR_TCAM_PARITY
 */
static void active_open_rpl(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_act_open_rpl *rpl = cplhdr(skb);
	struct inet_connection_sock *icsk = inet_csk(sk);
	unsigned int status  = G_AOPEN_STATUS(ntohl(rpl->atid_status));
	int err;

	if (is_neg_adv(status)) {
		struct cpl_io_state *cplios = CPL_IO_STATE(sk);
		struct tom_data *td = TOM_DATA(cplios->toedev);
		unsigned int tid = GET_TID(rpl);

		if (cplios_flag(sk, CPLIOS_ABORT_RPL_PENDING)) {
			if (!lookup_tid(td->tids, tid))
				sk_insert_tid(td, sk, tid);
		}
		cplios->neg_adv_tid = tid;
		fixup_and_send_ofo(sk, tid);
		kfree_skb(skb);
		return;
	}

	if (status) {
		if (status == CPL_ERR_CONN_EXIST &&
			icsk->icsk_retransmit_timer.function != act_open_retry_timer) {
			icsk->icsk_retransmit_timer.function = act_open_retry_timer;
			sk_reset_timer(sk, &icsk->icsk_retransmit_timer,
					jiffies + HZ / 2);
		} else if (status == CPL_ERR_TCAM_PARITY) {
			struct cpl_io_state *cplios = CPL_IO_STATE(sk);

			skb->sk = sk;
			t4_defer_reply(skb, cplios->toedev, deferred_tnl_connect);
			return;
		} else if (status == CPL_ERR_TCAM_FULL) {
			struct cpl_io_state *cplios = CPL_IO_STATE(sk);
			struct tom_data *d = TOM_DATA(cplios->toedev);
			if (sk->sk_family == AF_INET && d->lldi->enable_fw_ofld_conn) {
				err = mk_fw_act_open_req(sk, G_TID_TID(G_AOPEN_ATID(ntohl(rpl->atid_status))), cplios->l2t_entry);

				if (err < 0 ) {
					skb->sk = sk;
					t4_defer_reply(skb, cplios->toedev,
							deferred_tnl_connect);
					return;
				}
			} else {
				skb->sk = sk;
				t4_defer_reply(skb, cplios->toedev, deferred_tnl_connect);
				return;
			}
		} else {
			err = act_open_rpl_status_to_errno(status);
			if (err == EADDRINUSE) {
				unsigned short sport = ntohs(inet_sk(sk)->inet_sport);
				unsigned short dport = ntohs(inet_sk(sk)->inet_dport);

				printk(KERN_ERR "ACTIVE_OPEN_RPL: 4-tuple in use: ");
				if (sk->sk_family == AF_INET)
					printk("%pi4, %u, %pi4, %u\n",
					       &inet_sk(sk)->inet_saddr,
					       sport,
					       &inet_sk(sk)->inet_daddr,
					       dport);
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
				else
					printk("%pi6, %u, %pi6, %u\n",
					       &inet6_sk_rcv_saddr(sk),
					       sport,
					       &inet6_sk_daddr(sk),
					       dport);
#endif
			}
			t4_fail_act_open(sk, err);
		}
	} else
		ma_fail_active_open_rpl(sk, skb);
	kfree_skb(skb);
}

/*
 * Process an ACT_OPEN_RPL CPL message.
 */
static int do_act_open_rpl(struct tom_data *td, struct sk_buff *skb)
{
	struct cpl_act_open_rpl *rpl = cplhdr(skb);
	unsigned int atid = G_TID_TID(G_AOPEN_ATID(ntohl(rpl->atid_status)));
	unsigned int status  = G_AOPEN_STATUS(ntohl(rpl->atid_status));
	struct cpl_io_state *cplios;
	struct sock *sk;

	cplios = (struct cpl_io_state *)lookup_atid(td->tids, atid);
	VALIDATE_SOCK(cplios);

	sk = cplios->sk;

	if (status && !is_neg_adv(status) && act_open_has_tid(status))
		cxgb4_remove_tid(td->tids, cplios->port_id, GET_TID(rpl),
				 sk->sk_family);

	process_cpl_msg_ref(active_open_rpl, sk, skb);
	return 0;
}

/*
 * Handle an ARP failure for an active open.   XXX purge ofo queue
 *
 * XXX badly broken for crossed SYNs as the ATID is no longer valid.
 * XXX crossed SYN errors should be generated by PASS_ACCEPT_RPL which should
 * check SOCK_DEAD or sk->sk_sock.  Or maybe generate the error here but don't
 * free the atid.  Hmm.
 */
void act_open_req_arp_failure(void *handle, struct sk_buff *skb)
{
	struct sock *sk = skb->sk;

	sock_hold(sk);
	bh_lock_sock(sk);
	if (sk->sk_state == TCP_SYN_SENT || sk->sk_state == TCP_SYN_RECV) {
		if (!sock_owned_by_user(sk)) {
			t4_fail_act_open(sk, EHOSTUNREACH);
			__kfree_skb(skb);
		} else {
			/*
			 * Smart solution: Synthesize an ACTIVE_OPEN_RPL in the
			 * existing sk_buff and queue it to the backlog.  We
			 * are certain the sk_buff is not shared.  We also
			 * don't bother trimming the buffer.
			 */
			struct cpl_act_open_rpl *rpl = cplhdr(skb);

			rpl->ot.opcode = CPL_ACT_OPEN_RPL;
			rpl->atid_status = CPL_ERR_ARP_MISS;
			BLOG_SKB_CB(skb)->backlog_rcv = active_open_rpl;
			__sk_add_backlog(sk, skb);

			/*
			 * XXX Make sure a PASS_ACCEPT_RPL behind us doesn't
			 * destroy the socket.  Unfortunately we can't go into
			 * SYN_SENT because we don't have an atid.
			 * Needs more thought.
			 */
		}
	}
	bh_unlock_sock(sk);
	sock_put(sk);
}

/*
 * Determine the receive window size for a socket.
 */
static unsigned int select_rcv_wnd(struct sock *sk)
{
	unsigned int wnd = tcp_full_space(sk);
	unsigned int max_rcv_wnd;
	
	/*
	 * For receive coalescing to work effectively we need a receive window
	 * that can accomodate a coalesced segment.
	 */	
	if (wnd < MIN_RCV_WND)
		wnd = MIN_RCV_WND; 
	
	max_rcv_wnd = MAX_RCV_WND;

	cplios_set_flag(sk, CPLIOS_UPDATE_RCV_WND);
	
	return min(wnd, max_rcv_wnd);
}

#if defined(TCP_CONGESTION_CONTROL)
static void pivot_ca_ops(struct sock *sk, int cong)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (icsk->icsk_ca_ops->release)
		icsk->icsk_ca_ops->release(sk);
	module_put(icsk->icsk_ca_ops->owner);
	icsk->icsk_ca_ops = &t4_cong_ops[cong < 0 ? 2 : cong];
}
#endif

#define CTRL_SKB_LEN 304
#define TXDATA_SKB_LEN 128

/*
 * Assign offload parameters to some socket fields.  This code is used by
 * both active and passive opens.
 */
static void init_offload_sk(struct sock *sk, struct toedev *dev,
			    unsigned int tid, struct l2t_entry *e,
			    struct dst_entry *dst,
			    struct net_device *egress_dev,
			    const struct offload_settings *s,
			    u16 peer_mss)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct tom_data *td = TOM_DATA(dev);
	struct cxgb4_lld_info *lldi = td->lldi;
	int rxq_perchan, rxq_idx;

	cplios->toedev = dev;
	cplios->tid = tid;
	cplios->l2t_entry = e;
	cplios->wr_max_credits = cplios->wr_credits =
		min_t(unsigned int, td->max_wr_credits,
			TOM_TUNABLE(dev, max_wr_credits));
	cplios->wr_unacked = 0;
	cplios->delack_mode = 0;
	tp->rcv_wnd = select_rcv_wnd(sk);
        cplios->ulp_mode = ((TOM_TUNABLE(dev, ddp) &&
                  !sock_flag(sk, SOCK_NO_DDP) && s->ddp)
                 ? ULP_MODE_TCPDDP
                 : ULP_MODE_NONE);

	cplios->lro = TOM_TUNABLE(dev, lro);
	cplios->lro_skb = NULL;
	cplios->sched_cls =
		(s->sched_class >= 0 && s->sched_class < lldi->nsched_cls
		 ? s->sched_class
		 : SCHED_CLS_NONE);

	/*
	 * Save the socket send buffer size parameter for sending it to firmware for
	 * allocating TX pages.
	 */
	cplios->sndbuf = sk->sk_sndbuf;

	if (netdev_is_offload(egress_dev)) {
		cplios->port_id = ((struct port_info *)netdev_priv(egress_dev))->port_id;
		cplios->port_speed = ((struct port_info *)netdev_priv(egress_dev))->link_cfg.speed;
	}

	/*
	 * Note that select_mss() depends on cplios->opt2 being setup.  Thus
	 * the follwoing three lines need to be executed in exactly the order
	 * below: 1. rss_qid, 2. opt2, 3. mtu_idx.
	 */
	rxq_perchan = td->lldi->nrxq/td->lldi->nchan;
	rxq_idx = cplios->port_id*rxq_perchan;
	if (s->rssq >= 0 || s->rssq == QUEUE_CPU) {
		unsigned int id;

		if (s->rssq >= 0)
			id = s->rssq; 
		else
			id = smp_processor_id();
		rxq_idx += id % rxq_perchan;
        } else if (s->rssq == QUEUE_RANDOM) {
		rxq_idx += td->round_robin_cnt++;
		if (td->round_robin_cnt == rxq_perchan)
			td->round_robin_cnt = 0;
	}

	cplios->rss_qid = td->lldi->rxq_ids[rxq_idx];
	cplios->txq_idx = (rxq_idx < td->lldi->ntxq) ? rxq_idx :
		cplios->port_id*td->lldi->ntxq/td->lldi->nchan;
	cplios->opt2 = t4_calc_opt2(sk, s, cplios->rss_qid);
	cplios->mtu_idx = select_mss(sk, dst_mtu(dst), peer_mss);
	cplios->ctrl_skb_cache = __alloc_skb(CTRL_SKB_LEN, gfp_any(), 0, td->lldi->nodeid);
	cplios->txdata_skb_cache = alloc_skb(TXDATA_SKB_LEN, gfp_any());
	cplios->neg_adv_tid = INVALID_TID;
	cplios->passive_reap_next = NULL;
	skb_queue_head_init(&cplios->tx_queue);
	reset_wr_list(sk);

	if (!tp->window_clamp)
		tp->window_clamp = dst_metric(dst, RTAX_WINDOW);
	inet_csk(sk)->icsk_ack.pingpong = 1; /* TCP_QUICKACK disabled */

	/*
	 * Set sk_sndbuf so that t4_write_space and sk_stream_write_space
	 * calculate available socket space the same way.  This allows us to
	 * keep the original ->sk_write_space callback in cases of kernel
	 * sockets that provide their own version and expect
	 * sk_stream_write_space's method to be working.
	 *
	 * The only case we don't handle are sockets that have their own
	 * ->sk_write_space callback and set SOCK_SNDBUF_LOCK.
	 */
	if (!(sk->sk_userlocks & SOCK_SNDBUF_LOCK))
		sk->sk_sndbuf = TOM_TUNABLE(dev, max_host_sndbuf);

#if defined(TCP_CONGESTION_CONTROL)
	pivot_ca_ops(sk, s->cong_algo);
#endif
}

static inline void check_sk_callbacks(struct sock *sk)
{
	if (unlikely(sk->sk_user_data &&
		     !cplios_flag(sk, CPLIOS_CALLBACKS_CHKD))) {
		if (install_special_data_ready(sk) > 0)
			sock_set_flag(sk, SOCK_NO_DDP);
		cplios_set_flag(sk, CPLIOS_CALLBACKS_CHKD);
	}
}

/*
 * Send an active open request.
 */
int t4_connect(struct toedev *tdev, struct sock *sk,
	       struct net_device *egress_dev)
{
	int atid, ret;
	struct sk_buff *skb;
	struct l2t_entry *e;
	struct tom_data *d = TOM_DATA(tdev);
	struct tcp_sock *tp = tcp_sk(sk);
	struct dst_entry *dst = __sk_dst_get(sk);
	struct cpl_io_state *cplios = NULL;
	struct offload_req orq;
	struct offload_settings settings;
	unsigned int qid_atid;
	struct neighbour *neigh = NULL;
	struct net_device *master = NULL;
	bool use_ecn;

	offload_req_from_sk(&orq, sk, OPEN_TYPE_ACTIVE);
	settings = *lookup_ofld_policy(tdev, &orq, d->conf.cop_managed_offloading);
	if (!settings.offload) {
		rcu_read_unlock();
		goto out_err;
	}
	if (netif_is_bond_slave(egress_dev))
		master = netdev_master_upper_dev_get_rcu(egress_dev);

	if (rcu_access_pointer(tdev->in_shutdown)) {
		rcu_read_unlock();
		goto out_err;
	}
	rcu_read_unlock();

	if (master) {
		ret = toe_enslave(master, egress_dev);
		if (ret)
			goto out_err;
	}

	cplios = kzalloc(sizeof(*cplios), GFP_USER);
	if (!cplios)
		goto out_err;
	kref_init(&cplios->kref);
	atid = cxgb4_alloc_atid(d->tids, cplios);
	if (atid < 0)
		goto out_err;

	cplios->sk = sk;
	cplios->egress_dev = egress_dev;
	if (sk->sk_family == AF_INET)
		neigh = t4_dst_neigh_lookup(dst, &inet_sk(sk)->inet_daddr);
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else
		neigh = t4_dst_neigh_lookup(dst, &inet6_sk_daddr(sk));
#endif
	if (!neigh) {
		printk(KERN_INFO "%s: dst->_neighbour is NULL\n", __func__);
		goto free_tid;
	}

	e = cxgb4_l2t_get(d->lldi->l2t, neigh, egress_dev , sk->sk_priority);
	t4_dst_neigh_release(neigh);
	if (!e) {
		printk(KERN_ERR "cxgb4_l2t_get() returned zero\n");
		goto free_tid;
	}

	tp->ecn_flags = 0;
	use_ecn = (tcp_ecn_enabled(sock_net(sk)) == 1) || tcp_ca_needs_ecn(sk);

	if (!use_ecn) {
		if (dst && dst_feature(dst, RTAX_FEATURE_ECN))
			use_ecn = true;
	}

	if (use_ecn)
		tp->ecn_flags = TCP_ECN_OK;

	/* no space is saved using hw specific cpl_act_open_req here
	 * no need to check sk_family either.
	 */
	skb = alloc_skb(
		roundup(sizeof(struct cpl_t6_act_open_req6), 16), GFP_KERNEL);
	if (!skb)
		goto free_tid;

	if (sk->sk_family != AF_INET) {
		if (cxgb4_clip_get(egress_dev,
			(const u32 *)((&inet6_sk_saddr(sk))->s6_addr), 1))
			goto free_tid;
	}

	skb->sk = sk;
	t4_set_arp_err_handler(skb, NULL, act_open_req_arp_failure);

	kref_get(&cplios->kref);
	sock_hold(sk);
	CPL_IO_STATE(sk) = cplios;
	install_offload_ops(sk);
	check_sk_callbacks(sk);

	init_offload_sk(sk, tdev, atid, e, dst, egress_dev, &settings, 0);
	RCV_WSCALE(tp) = select_rcv_wscale(tcp_full_space(sk),
					   sysctl_tcp_window_scaling,
					   tp->window_clamp);
	sk->sk_err = 0;
	sock_reset_flag(sk, SOCK_DONE);
	T4_TCP_INC_STATS(sock_net(sk), TCP_MIB_ACTIVEOPENS);

	ma_fail_t4_connect(sk);
	cplios->toedev = tdev;
	cplios->tx_c_chan = cxgb4_port_chan(egress_dev);
	cplios->rx_c_chan = 0;
	cplios->smac_idx = cxgb4_tp_smt_idx(d->lldi->adapter_type,
					    cxgb4_port_viid(egress_dev));
	qid_atid = cplios->rss_qid << 14;
	qid_atid |= (unsigned int)atid;
	if (sk->sk_family == AF_INET)
		mk_act_open_req(sk, skb, qid_atid, e, &settings);
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else
		mk_act_open_req6(sk, skb, qid_atid, e, &settings,
				 &inet6_sk_rcv_saddr(sk),
				 &inet6_sk_daddr(sk));
#endif
	cxgb4_sk_l2t_send(cplios->egress_dev, skb, e, sk);
	return 0;

free_tid:
	cxgb4_free_atid(d->tids, atid);
out_err:
	if (cplios)
		kfree(cplios);
	return -1;
}

extern t4tom_cpl_handler_func tom_cpl_handlers[NUM_CPL_CMDS];

extern void (*tom_cpl_iscsi_callback)(struct tom_data *, struct sock *,
					struct sk_buff *, unsigned int);
extern void (*fp_iscsi_lro_proc_rx)(struct sock *sk, struct sk_buff *skb);

static int inline t4_cpl_iscsi_callback(struct tom_data *td,
					struct sock *sk, struct sk_buff *skb,
					unsigned int opcode)
{
	if (tom_cpl_iscsi_callback && sk) {
		struct cpl_io_state *cplios = CPL_IO_STATE(sk);

		if (cplios->ulp_mode == ULP_MODE_ISCSI) {
			tom_cpl_iscsi_callback(td, sk, skb, opcode);
			return 0;
		}
	}

	return 1;
}

/*
 * Handle an ARP failure for a CPL_ABORT_REQ.  Change it into a no RST variant
 * and send it along.
 */
static void abort_arp_failure(void *handle, struct sk_buff *skb)
{
	struct cpl_abort_req *req = cplhdr(skb);
	struct toedev *tdev = (struct toedev *)handle;

	req->cmd = CPL_ABORT_NO_RST;
	cxgb4_ofld_send(tdev->lldev[0], skb);
}

/* Helper function to send the CPL_ABORT_REQ
 */
static void t4_send_abort(struct sock *sk, int mode, struct sk_buff *skb)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	bool use_negadv_tid = false;
	struct cpl_abort_req *req;
	unsigned int tid;

	if ((sk->sk_state == TCP_SYN_SENT) &&
	    (cplios->neg_adv_tid != INVALID_TID)) {
		tid = cplios->neg_adv_tid;
		sk_insert_tid(TOM_DATA(cplios->toedev), sk, tid);
		use_negadv_tid = true;
	} else
		tid = cplios->tid;

	if (!skb)
		skb = alloc_ctrl_skb(cplios->txdata_skb_cache, sizeof(*req));

	req = (struct cpl_abort_req *)skb_put(skb, sizeof(*req));
	INIT_TP_WR_MIT_CPL(req, CPL_ABORT_REQ, tid);
	set_queue(skb, (cplios->txq_idx << 1) | CPL_PRIORITY_DATA, sk);
	req->rsvd0 = htonl(tp->snd_nxt);
	req->rsvd1 = !cplios_flag(sk, CPLIOS_TX_DATA_SENT);
	req->cmd = mode;

	if (unlikely(use_negadv_tid)) {
		/*
		 * need to queue it since flowc is already queued-up.
		 * So, can't send directly.
		 */
		__skb_queue_tail(&tp->out_of_order_queue, skb);
		fixup_and_send_ofo(sk, tid);
	} else {
		t4_set_arp_err_handler(skb, cplios->toedev, abort_arp_failure);
		send_or_defer(sk, tp, skb, mode == CPL_ABORT_SEND_RST);
	}
}

/*
 * Send an ABORT_REQ message.  Cannot fail.  This routine makes sure we do
 * not send multiple ABORT_REQs for the same connection and also that we do
 * not try to send a message after the connection has closed.  Returns 1 if
 * an ABORT_REQ wasn't generated after all, 0 otherwise.
 */
int t4_send_reset(struct sock *sk, int mode, struct sk_buff *skb)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tom_data *d = NULL;

	if (unlikely(cplios_flag(sk, CPLIOS_ABORT_SHUTDOWN) ||
		     !cplios->toedev)) {
		if (sk->sk_state == TCP_SYN_RECV)
			cplios_set_flag(sk, CPLIOS_RST_ABORTED);
		goto out;
	}

	if (ma_fail_t4_send_reset(sk))
		goto out;

	d = TOM_DATA(cplios->toedev);

	if (!cplios_flag(sk, CPLIOS_TX_DATA_SENT)) {
		struct tcp_sock *tp = tcp_sk(sk);
		send_tx_flowc_wr(sk, 0, tp->snd_nxt, tp->rcv_nxt);
		cplios_set_flag(sk, CPLIOS_TX_DATA_SENT);
	}

	cplios_set_flag(sk, CPLIOS_ABORT_RPL_PENDING);

	/* Purge the send queue so we don't send anything after an abort. */
	t4_purge_write_queue(sk);

	/* PR20010: Sending ABORT in SYN_RCV state.
	 * As a workaround to using the same queue for
	 * CPL_PASS_ACCEPT_RPL/CPL_ABORT_REQ, we read the DDP buffer offset
	 * so that ingress queue is set in the rss_info TCB field by the time
	 * CPL_SET_TCB_RPL comes back.
	 * We will send the CPL_ABORT_REQ in process_set_tcb_rpl.
	 * Without this CPL_ABORT_RPL_RSS might end up with receive queue as 0
	 * which can happen when CPL_ABORT_REQ reaches hardware before
	 * CPL_PASS_ACCEPT_RPL as they are sent on different queues.
	 */
	if (sk->sk_state == TCP_SYN_RECV) {
		t4_set_tcb_field_rpl(sk, W_TCB_RX_DDP_BUF0_OFFSET, 0, 0,
				     DDP_COOKIE_OFFSET);
		cplios_set_flag(sk, CPLIOS_ABORT_SHUTDOWN);
	} else {
		cplios_set_flag(sk, CPLIOS_ABORT_SHUTDOWN);
		t4_send_abort(sk, mode, skb);
	}

	return 0;
out:
	if (skb)
		kfree_skb(skb);
	return 1;
}
EXPORT_SYMBOL(t4_send_reset);

/*
 * Reset a connection that is on a listener's SYN queue or accept queue,
 * i.e., one that has not had a struct socket associated with it.
 * Must be called from process context.
 *
 * Modeled after code in inet_csk_listen_stop().
 */
static void reset_listen_child(struct sock *child)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(child);
	struct sk_buff *skb;

	skb = alloc_ctrl_skb(cplios->txdata_skb_cache, sizeof(struct cpl_abort_req));

	t4_send_reset(child, CPL_ABORT_SEND_RST, skb);
	sock_orphan(child);
	INC_ORPHAN_COUNT(child);
	if (child->sk_state == TCP_CLOSE)
		inet_csk_destroy_sock(child);
}

/*
 * The reap list is the list of passive open sockets that were orphaned when
 * their listening parent went away and wasn't able to nuke them for whatever
 * reason.  These sockets are terminated through a work request from process
 * context.
 */
static struct sock *reap_list;
static DEFINE_SPINLOCK(reap_list_lock);

/*
 * Process the reap list.
 */
DECLARE_TASK_FUNC(process_reap_list, task_param)
{
	spin_lock_bh(&reap_list_lock);
	while (reap_list) {
		struct sock *sk = reap_list;

		reap_list = CPL_IO_STATE(sk)->passive_reap_next;
		CPL_IO_STATE(sk)->passive_reap_next = NULL;
		spin_unlock(&reap_list_lock);
	        sock_hold(sk);      // need to survive past inet_csk_destroy_sock()
		bh_lock_sock(sk);
		reset_listen_child(sk);
		bh_unlock_sock(sk);
		sock_put(sk);
		spin_lock(&reap_list_lock);
	}
	spin_unlock_bh(&reap_list_lock);
}

static T4_DECLARE_WORK(reap_task, process_reap_list, NULL);

/*
 * Add a socket to the reap list and schedule a work request to process it.
 * We thread sockets through their sk_user_data pointers.  May be called
 * from softirq context and any associated open request must have already
 * been freed.
 */
static void add_to_reap_list(struct sock *sk)
{
	BUG_ON(CPL_IO_STATE(sk)->passive_reap_next);

	local_bh_disable();
	bh_lock_sock(sk);
	release_tcp_port(sk); // release the port immediately, it may be reused

	spin_lock(&reap_list_lock);
	CPL_IO_STATE(sk)->passive_reap_next = reap_list;
	reap_list = sk;
	if (!CPL_IO_STATE(sk)->passive_reap_next)
		schedule_work(&reap_task);
	spin_unlock(&reap_list_lock);
	bh_unlock_sock(sk);
	local_bh_enable();
}

void __set_tcb_field(struct sock *sk, struct sk_buff *skb, u16 word,
			    u64 mask, u64 val, u8 cookie, int no_reply)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct cpl_set_tcb_field *req;
	struct ulptx_idata *sc;
	unsigned int wrlen = roundup(sizeof(*req) + sizeof(*sc), 16);

	req = (struct cpl_set_tcb_field *)__skb_put(skb, wrlen);
	INIT_TP_WR_MIT_CPL(req, CPL_SET_TCB_FIELD, cplios->tid);
	req->reply_ctrl = htons(V_NO_REPLY(no_reply) |
				V_REPLY_CHAN(cplios->rx_c_chan) |
				V_QUEUENO(cplios->rss_qid));
	req->word_cookie = htons(V_WORD(word) | V_COOKIE(cookie));
	req->mask = cpu_to_be64(mask);
	req->val = cpu_to_be64(val);
	sc = (struct ulptx_idata *)(req + 1);
	sc->cmd_more = htonl(V_ULPTX_CMD(ULP_TX_SC_NOOP));
	sc->len = htonl(0);

	set_wr_txq(skb, CPL_PRIORITY_CONTROL, cplios->port_id);
}

void t4_set_tcb_field(struct sock *sk, u16 word, u64 mask, u64 val)
{
	struct sk_buff *skb;
	struct cpl_set_tcb_field *req;
	struct ulptx_idata *sc;
	unsigned int wrlen = roundup(sizeof(*req) + sizeof(*sc), 16);

	if (sk->sk_state == TCP_CLOSE || cplios_flag(sk, CPLIOS_ABORT_SHUTDOWN))
		return;

	skb = alloc_ctrl_skb(CPL_IO_STATE(sk)->ctrl_skb_cache, wrlen);
	BUG_ON(!skb);

	__set_tcb_field(sk, skb, word, mask, val, 0, 1);
	send_or_defer(sk, tcp_sk(sk), skb, 0);
}

void t4_set_tcb_field_rpl(struct sock *sk, u16 word, u64 mask, u64 val, u8 cookie)
{
	struct sk_buff *skb;
	struct cpl_set_tcb_field *req;
	struct ulptx_idata *sc;
	unsigned int wrlen = roundup(sizeof(*req) + sizeof(*sc), 16);

	if (sk->sk_state == TCP_CLOSE || cplios_flag(sk, CPLIOS_ABORT_SHUTDOWN))
		return;

	skb = alloc_ctrl_skb(CPL_IO_STATE(sk)->ctrl_skb_cache, wrlen);
	BUG_ON(!skb);

	__set_tcb_field(sk, skb, word, mask, val, cookie, 0);
	send_or_defer(sk, tcp_sk(sk), skb, 0);
}

/*
 * Set one of the t_flags bits in the TCB.
 */
void t4_set_tcb_tflag(struct sock *sk, unsigned int bit_pos, int val)
{
	t4_set_tcb_field(sk, W_TCB_T_FLAGS, 1ULL << bit_pos, val << bit_pos);
}

/*
 * Send a SET_TCB_FIELD CPL message to change a connection's Nagle setting.
 */
void t4_set_nagle(struct sock *sk)
{
	t4_set_tcb_tflag(sk, S_TF_NAGLE, !(tcp_sk(sk)->nonagle & TCP_NAGLE_OFF));
}

/*
 * Send a SET_TCB_FIELD CPL message to change a connection's keepalive setting.
 */
void t4_set_keepalive(struct sock *sk, int on_off)
{
	t4_set_tcb_tflag(sk, S_TF_KEEPALIVE, on_off);
}

void t4_set_rcv_coalesce_enable(struct sock *sk, int on_off)
{
	t4_set_tcb_tflag(sk, S_TF_RCV_COALESCE_ENABLE, on_off);
}

void t4_set_dack(struct sock *sk, int on_off)
{
        t4_set_tcb_tflag(sk, S_TF_DACK, on_off);
}

void t4_set_dack_mss(struct sock *sk, int on_off)
{
	t4_set_tcb_tflag(sk, S_TF_DACK_MSS, on_off);
}

void t4_set_migrating(struct sock *sk, int on_off)
{
        t4_set_tcb_tflag(sk, S_TF_MIGRATING, on_off);
}

void t4_set_non_offload(struct sock *sk, int on_off)
{
        t4_set_tcb_tflag(sk, S_TF_NON_OFFLOAD, on_off);
}

/*
 * Send a SET_TCB_FIELD CPL message to change a connection's TOS setting.
 */
void t4_set_tos(struct sock *sk)
{
	t4_set_tcb_field(sk, W_TCB_TOS, V_TCB_TOS(M_TCB_TOS),
			 V_TCB_TOS(SK_TOS(sk)));
}

/*
 * In DDP mode, TP fails to schedule a timer to push RX data to the host when
 * DDP is disabled (data is delivered to freelist). [Note that, the peer should
 * set the PSH bit in the last segment, which would trigger delivery.]
 * We work around the issue by setting a DDP buffer in a partial placed state,
 * which guarantees that TP will schedule a timer.
 */
#define TP_DDP_TIMER_WORKAROUND_MASK\
    (V_TF_DDP_BUF0_VALID(1) | V_TF_DDP_ACTIVE_BUF(1) |\
     ((V_TCB_RX_DDP_BUF0_OFFSET(M_TCB_RX_DDP_BUF0_OFFSET) |\
       V_TCB_RX_DDP_BUF0_LEN(3)) << 32))
#define TP_DDP_TIMER_WORKAROUND_VAL\
    (V_TF_DDP_BUF0_VALID(1) | V_TF_DDP_ACTIVE_BUF(0) |\
     ((V_TCB_RX_DDP_BUF0_OFFSET((u64)1) | V_TCB_RX_DDP_BUF0_LEN((u64)2)) <<\
      32))

void t4_enable_ddp(struct sock *sk, int on_off)
{
	t4_set_tcb_field(sk, W_TCB_RX_DDP_FLAGS, V_TF_DDP_OFF(1ULL),
				 V_TF_DDP_OFF((unsigned long long)!on_off));
}

void t4_disable_ddp(struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);

	t4_set_tcb_field(sk, W_TCB_RX_DDP_FLAGS, V_TF_DDP_OFF(1ULL),
		V_TF_DDP_OFF(1ULL));
	if (cplios && !TOM_TUNABLE(cplios->toedev, ddp_rcvcoalesce))
		t4_set_tcb_field(sk, W_TCB_T_FLAGS,
			V_TF_RCV_COALESCE_ENABLE(1ULL),
			V_TF_RCV_COALESCE_ENABLE(1ULL));
}

void t4_set_ddp_tag(struct sock *sk, int buf_idx, unsigned int tag_color)
{
	t4_set_tcb_field(sk, W_TCB_RX_DDP_BUF0_TAG + buf_idx,
			 V_TCB_RX_DDP_BUF0_TAG(M_TCB_RX_DDP_BUF0_TAG),
			 tag_color);
}

void t4_set_ddp_buf(struct sock *sk, int buf_idx, unsigned int offset,
		    unsigned int len)
{
	if (buf_idx == 0)
		t4_set_tcb_field(sk, W_TCB_RX_DDP_BUF0_OFFSET,
			 V_TCB_RX_DDP_BUF0_OFFSET(M_TCB_RX_DDP_BUF0_OFFSET) |
			 V_TCB_RX_DDP_BUF0_LEN(M_TCB_RX_DDP_BUF0_LEN),
			 V_TCB_RX_DDP_BUF0_OFFSET((u64)offset) |
			 V_TCB_RX_DDP_BUF0_LEN((u64)len));
	else
		t4_set_tcb_field(sk, W_TCB_RX_DDP_BUF1_OFFSET,
			 V_TCB_RX_DDP_BUF1_OFFSET(M_TCB_RX_DDP_BUF1_OFFSET) |
			 V_TCB_RX_DDP_BUF1_LEN(M_TCB_RX_DDP_BUF1_LEN << 32),
			 V_TCB_RX_DDP_BUF1_OFFSET((u64)offset) |
			 V_TCB_RX_DDP_BUF1_LEN(((u64)len) << 32));
}

void t4_set_ddp_indicate(struct sock *sk, int on)
{
	if (on)
		t4_set_tcb_field_rpl(sk, W_TCB_RX_DDP_FLAGS,
				V_TF_DDP_INDICATE_OUT(1ULL) |
				V_TF_DDP_BUF0_VALID(1ULL) | V_TF_DDP_BUF1_VALID(1ULL) |
				V_TF_DDP_BUF0_INDICATE(1ULL) | V_TF_DDP_BUF1_INDICATE(1ULL),
				V_TF_DDP_BUF0_INDICATE(1ULL), DDP_COOKIE_INDOUT);
	else
		t4_set_tcb_field_rpl(sk, W_TCB_RX_DDP_FLAGS, V_TF_DDP_INDICATE_OUT(1ULL),
				V_TF_DDP_INDICATE_OUT(1ULL), DDP_COOKIE_INDOUT);
}

int t4_set_cong_control(struct sock *sk, const char *name)
{
	int cong_algo;

	for (cong_algo = 0; cong_algo < ARRAY_SIZE(t4_cong_ops); cong_algo++)
		if (!strcmp(name, t4_cong_ops[cong_algo].name))
			break;

	if (cong_algo >= ARRAY_SIZE(t4_cong_ops))
		return -EINVAL;
	return 0;
}

/*
 * Send RX credits through an RX_DATA_ACK CPL message.  If nofail is 0 we are
 * permitted to return without sending the message in case we cannot allocate
 * an sk_buff.  Returns the number of credits sent.
 */
u32 t4_send_rx_credits(struct sock *sk, u32 credits, u32 dack, int nofail)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct sk_buff *skb;
	struct cpl_rx_data_ack *req;

	if (ma_fail_t4_send_rx_credits(sk))
		return 0;

	skb = nofail ? alloc_ctrl_skb(cplios->ctrl_skb_cache, sizeof(*req)) :
		       alloc_skb(sizeof(*req), GFP_ATOMIC);
	if (!skb)
		return 0;

	req = (struct cpl_rx_data_ack *)__skb_put(skb, sizeof(*req));
	INIT_TP_WR_MIT_CPL(req, CPL_RX_DATA_ACK, cplios->tid);
	req->credit_dack = htonl(dack | V_RX_CREDITS(credits));
	set_wr_txq(skb, CPL_PRIORITY_ACK, cplios->port_id);
	cxgb4_ofld_send(cplios->egress_dev, skb);
	return credits;
}

/*
 * Handle receipt of an urgent pointer.
 */
static void handle_urg_ptr(struct sock *sk, u32 urg_seq)
{
	struct tcp_sock *tp = tcp_sk(sk);

	urg_seq--;   /* initially points past the urgent data, per BSD */

	if (tp->urg_data && !after(urg_seq, tp->urg_seq))
		return;                                 /* duplicate pointer */

	sk_send_sigurg(sk);
	if (tp->urg_seq == tp->copied_seq && tp->urg_data &&
	    !sock_flag(sk, SOCK_URGINLINE) && tp->copied_seq != tp->rcv_nxt) {
		struct sk_buff *skb = skb_peek(&sk->sk_receive_queue);

		tp->copied_seq++;
		if (skb && tp->copied_seq - ULP_SKB_CB(skb)->seq >= skb->len)
			tom_eat_skb(sk, skb);
	}
	tp->urg_data = TCP_URG_NOTYET;
	tp->urg_seq = urg_seq;
}

/*
 * Process an urgent data notification.
 */
static void rx_urg_notify(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_rx_urg_notify *hdr = cplhdr(skb);

	if (!sk_no_receive(sk))
		handle_urg_ptr(sk, ntohl(hdr->seq));

	kfree_skb(skb);
}

/*
 * Handler for RX_URG_NOTIFY CPL messages.
 */
static int do_rx_urg_notify(struct tom_data *td, struct sk_buff *skb)
{
        struct sock *sk;
        struct cpl_rx_urg_notify *req = cplhdr(skb);
        unsigned int hwtid = GET_TID(req);

        sk = lookup_tid(td->tids, hwtid);

	VALIDATE_SOCK(sk);

	process_cpl_msg(rx_urg_notify, sk, skb);
	return 0;
}

/*
 * A helper function that aborts a connection and increments the given MIB
 * counter.  The supplied skb is used to generate the ABORT_REQ message if
 * possible.  Must be called with softirqs disabled.
 */
static inline void abort_conn(struct sock *sk, struct sk_buff *skb, int mib)
{
	struct sk_buff *abort_skb;

	abort_skb = __get_cpl_reply_skb(skb, sizeof(struct cpl_abort_req),
					GFP_ATOMIC);
	if (abort_skb) {
		T4_NET_INC_STATS_BH(sock_net(sk), mib);
		t4_send_reset(sk, CPL_ABORT_SEND_RST, abort_skb);
	}
}

/*
 * Returns true if we need to explicitly request RST when we receive new data
 * on an RX-closed connection.
 */
static inline int need_rst_on_excess_rx(const struct sock *sk)
{
	return 1;
}

/*
 * Handles Rx data that arrives in a state where the socket isn't accepting
 * new data.
 */
static void handle_excess_rx(struct sock *sk, struct sk_buff *skb)
{
	if (need_rst_on_excess_rx(sk) && !cplios_flag(sk, CPLIOS_ABORT_SHUTDOWN))
		abort_conn(sk, skb, LINUX_MIB_TCPABORTONDATA);

	kfree_skb(skb);  /* can't use __kfree_skb here */
}

/*
 * Build a CPL_SET_TCB_FIELD message as payload of a ULP_TX_PKT command.
 */
static inline void mk_set_tcb_field_ulp(struct cpl_io_state *cplios,
				struct cpl_set_tcb_field *req,
                                unsigned int word,
                                u64 mask, u64 val, u8 cookie, int no_reply)
{
        struct ulp_txpkt *txpkt = (struct ulp_txpkt *)req;
        struct ulptx_idata *sc = (struct ulptx_idata *)(txpkt + 1);

        txpkt->cmd_dest = htonl(V_ULPTX_CMD(ULP_TX_PKT) | V_ULP_TXPKT_DEST(0));
        txpkt->len = htonl(DIV_ROUND_UP(sizeof(*req), 16));
        sc->cmd_more = htonl(V_ULPTX_CMD(ULP_TX_SC_IMM));
        sc->len = htonl(sizeof(*req) - sizeof(struct work_request_hdr));
        OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_SET_TCB_FIELD, cplios->tid));
	req->reply_ctrl = htons(V_NO_REPLY(no_reply) | V_REPLY_CHAN(cplios->rx_c_chan) | V_QUEUENO(
cplios->rss_qid));
	req->word_cookie = htons(V_WORD(word) | V_COOKIE(cookie));
        req->mask = cpu_to_be64(mask);
        req->val = cpu_to_be64(val);
	sc = (struct ulptx_idata *)(req + 1);
	sc->cmd_more = htonl(V_ULPTX_CMD(ULP_TX_SC_NOOP));
	sc->len = htonl(0);
}

static void t4_set_maxseg(struct sock *sk, unsigned int mtu_idx)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct sk_buff *skb;
	struct work_request_hdr *wr;
	struct ulptx_idata *aligner;
	struct cpl_set_tcb_field *req;
	struct cpl_set_tcb_field *tstampreq;
	unsigned int wrlen;

	if (sk->sk_state == TCP_CLOSE || cplios_flag(sk, CPLIOS_ABORT_SHUTDOWN))
		return;

	wrlen = roundup(sizeof(*wr) + 2*(sizeof(*req) + sizeof(*aligner)), 16);

	skb = alloc_ctrl_skb(cplios->ctrl_skb_cache, wrlen);
	if (!skb)
		return;

	set_wr_txq(skb, CPL_PRIORITY_CONTROL, cplios->port_id);

	req = (struct cpl_set_tcb_field *)__skb_put(skb, wrlen);
	INIT_ULPTX_WR(req, wrlen, 0, 0);

	wr = (struct work_request_hdr *)req;
	wr++;
	req = (struct cpl_set_tcb_field *)wr;

	mk_set_tcb_field_ulp(cplios, req, W_TCB_T_MAXSEG,
					  V_TCB_T_MAXSEG(M_TCB_T_MAXSEG),
					  mtu_idx, 0, 1);

	aligner = (struct ulptx_idata *)(req + 1);
	tstampreq = (struct cpl_set_tcb_field *)(aligner + 1);

	/*
	 * Clear bits 29:11 of the TCB Time Stamp field to trigger an
	 * immediate retransmission with the new Maximum Segment Size.
	 */
	mk_set_tcb_field_ulp(cplios, tstampreq, W_TCB_TIMESTAMP,
					     V_TCB_TIMESTAMP(0x7FFFFULL << 11),
					     0, 0, 1);

	cxgb4_ofld_send(cplios->egress_dev, skb);
}

/*
 * Process a set_tcb_rpl as a DDP completion (similar to RX_DDP_COMPLETE)
 * by getting the DDP offset from the TCB.
 */
static void tcb_rpl_as_ddp_complete(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct ddp_state *q;
	struct ddp_buf_state *bsp;
	struct cpl_set_tcb_rpl *hdr;
	unsigned int ddp_offset;

	if (unlikely(!(tp = tcp_sk(sk)) || !CPL_IO_STATE(sk))) {
		kfree_skb(skb);
		return;
	}

        hdr = cplhdr(skb);

	/* It is a possible that a previous CPL already invalidated UBUF DDP
	 * and moved the cur_buf idx and hence no further processing of this
	 * skb is required. However, the app might be sleeping on
	 * !q->get_tcb_count and we need to wake it up.
	 */
	q = DDP_STATE(sk);
	if (q->cancel_ubuf && !t4_ddp_ubuf_pending(sk)) {
		kfree_skb(skb);
		q->get_tcb_count--;

		if (!sock_flag(sk, SOCK_DEAD))
			sk_data_ready_compat(sk, 0);

		return;
	}

	bsp = &q->buf_state[q->cur_buf];
	if (q->cur_buf == 0)
		ddp_offset = (be64_to_cpu(hdr->oldval) >> S_TCB_RX_DDP_BUF0_OFFSET) & M_TCB_RX_DDP_BUF0_OFFSET;
	else
		ddp_offset = (be64_to_cpu(hdr->oldval) >> (32+S_TCB_RX_DDP_BUF1_OFFSET)) & M_TCB_RX_DDP_BUF1_OFFSET;

	skb_ulp_ddp_offset(skb) = bsp->cur_offset;
	bsp->cur_offset = ddp_offset;
	skb->len = ddp_offset - skb_ulp_ddp_offset(skb);

	if (unlikely(sk_no_receive(sk) && skb->len)) {
		handle_excess_rx(sk, skb);
		q->get_tcb_count--;
		return;
	}

	if (bsp->flags & DDP_BF_NOCOPY) {
		skb_ulp_ddp_flags(skb) =
				DDP_BF_PSH | DDP_BF_NODATA | DDP_BF_NOCOPY | 1;
		bsp->flags &= ~(DDP_BF_NOCOPY|DDP_BF_NODATA);
		q->cur_buf ^= 1;
	} else {
		/* This reply is for a CPL_GET_TCB_RPL to cancel the UBUF DDP,
		 * but it got here way late and nobody cares anymore.
		 */
		kfree_skb(skb);
		q->get_tcb_count--;
		return;
	}

	skb_gl_set(skb, bsp->gl);
	ULP_SKB_CB(skb)->seq = tp->rcv_nxt;
	tp->rcv_nxt += skb->len;

	skb_reset_transport_header(skb);
	tcp_hdr(skb)->fin = 0;          /* changes original TCB */

	inet_csk(sk)->icsk_ack.lrcvtime = tcp_time_stamp;

	__skb_queue_tail(&sk->sk_receive_queue, skb);
	smp_wmb();
	q->get_tcb_count--;

	if (!sock_flag(sk, SOCK_DEAD))
		sk_data_ready_compat(sk, 0);
}

static void process_set_tcb_rpl(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_set_tcb_rpl *rpl = cplhdr(skb);
	struct ddp_state *q;

        if (rpl->status)
		printk(KERN_INFO "CPL_SET_TCB_RPL: status = 0x%u\n", rpl->status);
	q = DDP_STATE(sk);
	if (G_COOKIE(rpl->cookie) == DDP_COOKIE_ENABLE) {
		if (likely(!sk_no_receive(sk) && !q->ddp_setup)) {
			q->indicate = tcp_sk(sk)->rcv_nxt;
			t4_set_ddp_indicate(sk, 1);
			q->indout_count++;
			q->ddp_setup = 1;
		}
	}
	else if (G_COOKIE(rpl->cookie) == DDP_COOKIE_INDOUT) {
		if (likely(!sk_no_receive(sk) && q->ddp_setup))
			q->indout_count--;
	} else if ((G_COOKIE(rpl->cookie) == DDP_COOKIE_OFFSET) &&
		   !q->ddp_setup) {
		/* Sending ABORT in SYN_RCV state.
		 * We are reusing this DDP_COOKIE_OFFSET to handle the special
		 * case of sending ABORT in TCP_SYN_RECV state.
		 */

		/* Reusing the skb as size of cpl_set_tcb_field structure
		 * is greater than cpl_abort_req
		 */
		__skb_trim(skb, 0);
		skb_get(skb);
		t4_send_abort(sk, CPL_ABORT_SEND_RST, skb);
	} else if (G_COOKIE(rpl->cookie) == DDP_COOKIE_OFFSET) {
		tcb_rpl_as_ddp_complete(sk, skb);
		return;
	} else {
#ifdef CONFIG_T4_MA_FAILOVER
		if ((G_COOKIE(rpl->cookie) == MA_FAILOVER_COOKIE_RCV_WND) |
		    (G_COOKIE(rpl->cookie) == MA_FAILOVER_COOKIE_RX_HDR_OFFSET) |
		    (G_COOKIE(rpl->cookie) == MA_FAILOVER_COOKIE_NEW_RCV_WND) |
		    (G_COOKIE(rpl->cookie) == MA_FAILOVER_COOKIE_L2TIX))
			ma_fail_process_set_tcb_rpl(sk, skb);
#endif
	}
	kfree_skb(skb);
}

static int do_set_tcb_rpl(struct tom_data *td, struct sk_buff *skb)
{
        struct sock *sk;
        struct cpl_set_tcb_rpl *req = cplhdr(skb);
        unsigned int hwtid = GET_TID(req);

        sk = lookup_tid(td->tids, hwtid);

        /* OK if socket doesn't exist */
        if (!sk)
                return CPL_RET_BUF_DONE;

	if (!t4_cpl_iscsi_callback(td, sk, skb, CPL_SET_TCB_RPL))
		return 0;

        process_cpl_msg(process_set_tcb_rpl, sk, skb);
        return 0;
}

/*
 * We get called from the CPL_RX_DATA handler new_rx_data() when it gets
 * called and discovers that we thought the connection was in DDP mode.  Here
 * we'll examine the CPL_RX_DATA and use it to synthesize a DDP skb to cover
 * the sequence space between where we last expected to get DDP data and the
 * sequence number of the new CPL_RX_DATA.
 */ 
static void handle_ddp_data(struct sock *sk, struct sk_buff *origskb)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct ddp_state *q;
	struct ddp_buf_state *bsp;
	struct cpl_rx_data *hdr = cplhdr(origskb);
	unsigned int rcv_nxt = ntohl(hdr->seq);
	struct sk_buff *skb;

	/*
	 * If the sequence number received is less than expected then the
	 * assumptions that follow do not apply.
	 */
	if (before(rcv_nxt, tp->rcv_nxt))
		return;

	q = DDP_STATE(sk);
	if (!q->ddp_setup)
		return;

	bsp = &q->buf_state[q->cur_buf];

	if (after(rcv_nxt, tp->rcv_nxt)) {
		/*
		 * Create an skb to cover the range of data which was DDP'ed
		 * and append that to the socket's receive queue.
		 */
		skb = skb_clone(origskb, GFP_ATOMIC);
		if (!skb)
			return;

		/*
		 * Here we assume that data placed into host memory by DDP
		 * corresponds to the difference between the sequence number
		 * received in the RX_DATA header and the expected sequence
		 * number. And since we tested the sequence above, the
		 * computed skb->len is positive and we won't panic later on
		 * ...
		 */
		skb->len = rcv_nxt - tp->rcv_nxt;
		skb_gl_set(skb, bsp->gl);
		
		skb_ulp_ddp_offset(skb) = bsp->cur_offset;
		skb_ulp_ddp_flags(skb) =
			DDP_BF_PSH | (bsp->flags & DDP_BF_NOCOPY) | 1;
		if (bsp->flags & DDP_BF_NOCOPY)
			bsp->flags &= ~DDP_BF_NOCOPY;

		if (unlikely(hdr->dack_mode != cplios->delack_mode)) {
			cplios->delack_mode = hdr->dack_mode;
			cplios->delack_seq = tp->rcv_nxt;
		}
	
		ULP_SKB_CB(skb)->seq = tp->rcv_nxt;
		tp->rcv_nxt = rcv_nxt;
		bsp->cur_offset += skb->len;
		q->cur_buf ^= 1;
		inet_csk(sk)->icsk_ack.lrcvtime = tcp_time_stamp;
		__skb_queue_tail(&sk->sk_receive_queue, skb);

		/*
		 * Note that we've fallen out of DDP mode.
		 */
		q->ddp_off = 1;
		q->indicate = 0;
	} else {
		/*
		 * This could be an "indicate" from T4 telling us about more
		 * data available to DDP.  Or it could be a CPL_RX_DATA with
		 * ddp_off set meaning that we've fallen out of DDP mode ...
		 */
		unsigned int target, ind_size;

		q->ind_rcv_nxt = rcv_nxt;
		ind_size = origskb->len - sizeof(*hdr);
		if (hdr->ddp_off) {
			q->ddp_off = 1;
			q->indicate = 0;
		} else if (q->ddp_off)
			q->ddp_off = 0;
		target = sock_rcvlowat(sk, 0, (int)(~0U>>1));
		if (!q->ddp_off &&
		    ((tp->rcv_nxt + ind_size) - tp->copied_seq < target)) {
			t4_set_ddp_indicate(sk, 1);
			q->indicate = tp->rcv_nxt + ind_size;
                	q->indout_count++;
		}
	}
}

/*
 * Process new data received for a connection.
 */
static void new_rx_data(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct cpl_rx_data *hdr = cplhdr(skb);
	struct tcp_sock *tp = tcp_sk(sk);

	if (unlikely(sk_no_receive(sk))) {
		handle_excess_rx(sk, skb);
		return;
	}

	if (unlikely(hdr->status)) {
		u8 status = ACCESS_ONCE(hdr->status);

		/* iscsi connections can send cpl_rx_data
		 * with status CPL_ERR_IWARP_FLM
		 */
		if (cplios->ulp_mode == ULP_MODE_ISCSI) {
			handle_excess_rx(sk, skb);
			pr_err_ratelimited(
				"%s: TID %u: iSCSI unexpected CPL_RX_DATA status = %u\n",
				cplios->toedev->name, cplios->tid, status);
			return;
		}
	}

	tom_sk_set_napi_id(sk, tom_skb_get_napi_id(skb));

	if (cplios->ulp_mode == ULP_MODE_TCPDDP)
		handle_ddp_data(sk, skb);

	ULP_SKB_CB(skb)->seq = ntohl(hdr->seq);
	ULP_SKB_CB(skb)->flags = 0;
	skb_ulp_mode(skb) = ULP_MODE_NONE;	/* for iSCSI */
	skb_ulp_ddp_flags(skb) = 0;		/* for DDP */

#if VALIDATE_SEQ
	if (unlikely(ULP_SKB_CB(skb)->seq != tp->rcv_nxt)) {
		pr_err_ratelimited(
		       "%s: TID %u: Bad sequence number %u, expected %u\n",
		       cplios->toedev->name, cplios->tid, ULP_SKB_CB(skb)->seq,
		       tp->rcv_nxt);
		__kfree_skb(skb);
		return;
	}
#endif
	skb_reset_transport_header(skb);
	__skb_pull(skb, sizeof(*hdr));
	if (!skb->data_len)
		__skb_trim(skb, ntohs(hdr->len));

	if (unlikely(hdr->urg))
		handle_urg_ptr(sk, tp->rcv_nxt + ntohs(hdr->urg));
	if (unlikely(tp->urg_data == TCP_URG_NOTYET &&
		     tp->urg_seq - tp->rcv_nxt < skb->len))
		tp->urg_data = TCP_URG_VALID | skb->data[tp->urg_seq -
							 tp->rcv_nxt];

	if (unlikely(hdr->dack_mode != cplios->delack_mode)) {
		cplios->delack_mode = hdr->dack_mode;
		cplios->delack_seq = tp->rcv_nxt;
	}

	tcp_hdr(skb)->fin = 0;          /* modifies original hdr->urg */
	tp->rcv_nxt += skb->len;
	
	inet_csk(sk)->icsk_ack.lrcvtime = tcp_time_stamp;
	__skb_queue_tail(&sk->sk_receive_queue, skb);

	if (!sock_flag(sk, SOCK_DEAD)) {
		check_sk_callbacks(sk);
		sk_data_ready_compat(sk, 0);
	}
}

/*
 * Handler for RX_DATA CPL messages.
 */
static int do_rx_data(struct tom_data *td, struct sk_buff *skb)
{
        struct sock *sk;
        struct cpl_rx_data *req = cplhdr(skb);
        unsigned int hwtid = GET_TID(req);

        sk = lookup_tid(td->tids, hwtid);

	VALIDATE_SOCK(sk);

	skb_gl_set(skb, NULL);		/* indicates packet is RX_DATA */

	process_cpl_msg(new_rx_data, sk, skb);
	return 0;
}

static void new_rx_data_ddp(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tcp_sock *tp;
	struct ddp_state *q;
	struct ddp_buf_state *bsp;
	struct cpl_rx_data_ddp *hdr;
	unsigned int ddp_len, rcv_nxt, ddp_report, end_offset, buf_idx;
	unsigned int delack_mode;
	
	if (unlikely(sk_no_receive(sk))) {
		handle_excess_rx(sk, skb);
		return;
	}

	tp = tcp_sk(sk);
	q = DDP_STATE(sk);
	hdr = cplhdr(skb);
	ddp_report = ntohl(hdr->ddp_report);
	buf_idx = (ddp_report >> S_DDP_BUF_IDX) & 1;
	bsp = &q->buf_state[buf_idx];

	ddp_len = ntohs(hdr->len);
	rcv_nxt = ntohl(hdr->seq) + ddp_len;

	delack_mode = G_DDP_DACK_MODE(ddp_report);
	if (unlikely(G_DDP_DACK_MODE(ddp_report) != cplios->delack_mode)) {
		cplios->delack_mode = delack_mode;
		cplios->delack_seq = tp->rcv_nxt;
	}

	ULP_SKB_CB(skb)->seq = tp->rcv_nxt;
	tp->rcv_nxt = rcv_nxt;

	/*
	 * Store the length in skb->len.  We are changing the meaning of
	 * skb->len here, we need to be very careful that nothing from now on
	 * interprets ->len of this packet the usual way.
	 */
	skb->len = tp->rcv_nxt - ULP_SKB_CB(skb)->seq;

	/*
	 * Figure out where the new data was placed in the buffer and store it
	 * in when.  Assumes the buffer offset starts at 0, consumer needs to
	 * account for page pod's pg_offset.
	 */
	end_offset = G_DDP_OFFSET(ddp_report) + ddp_len;
	skb_ulp_ddp_offset(skb) = end_offset - skb->len;

	/*
	 * We store in mac.raw the address of the gather list where the
	 * placement happened.
	 */
	skb_gl_set(skb, bsp->gl);
	bsp->cur_offset = end_offset;

	/*
	 * Bit 0 of DDP flags stores whether the DDP buffer is completed.
	 * Note that other parts of the code depend on this being in bit 0.
	 */
	skb_ulp_ddp_flags(skb) = !!(ddp_report & F_DDP_INV);
	if (bsp->flags & DDP_BF_NOCOPY) {
		skb_ulp_ddp_flags(skb) |= (bsp->flags & DDP_BF_NOCOPY);
		if (ddp_report & F_DDP_INV)
			bsp->flags &= ~DDP_BF_NOCOPY;
	}

	if (ddp_report & F_DDP_PSH)
		skb_ulp_ddp_flags(skb) |= DDP_BF_PSH;

	if (!!(ddp_report & F_DDP_INV))
		skb_ulp_ddp_flags(skb) |= DDP_BF_NODATA;

	skb_reset_transport_header(skb);
	tcp_hdr(skb)->fin = 0;          /* changes original hdr->ddp_report */

	inet_csk(sk)->icsk_ack.lrcvtime = tcp_time_stamp;
	__skb_queue_tail(&sk->sk_receive_queue, skb);
	if (!sock_flag(sk, SOCK_DEAD))
		sk_data_ready_compat(sk, 0);
}

#define DDP_ERR (F_DDP_PPOD_MISMATCH | F_DDP_LLIMIT_ERR | F_DDP_ULIMIT_ERR |\
		 F_DDP_PPOD_PARITY_ERR | F_DDP_PADDING_ERR | F_DDP_OFFSET_ERR |\
		 F_DDP_INVALID_TAG | F_DDP_COLOR_ERR | F_DDP_TID_MISMATCH |\
		 F_DDP_INVALID_PPOD | F_DDP_HDRCRC_ERR | F_DDP_DATACRC_ERR)

/*
 * Handler for RX_DATA_DDP CPL messages.
 */
static int do_rx_data_ddp(struct tom_data *td, struct sk_buff *skb)
{
        struct sock *sk;
        struct cpl_rx_data_ddp *hdr = cplhdr(skb);
        unsigned int hwtid = GET_TID(hdr);

        sk = lookup_tid(td->tids, hwtid);

	VALIDATE_SOCK(sk);

	if (!t4_cpl_iscsi_callback(td, sk, skb, CPL_RX_DATA_DDP))
		return 0;

	if (unlikely(ntohl(hdr->ddpvld) & DDP_ERR)) {
		printk(KERN_ERR "RX_DATA_DDP for TID %u reported error 0x%x\n",
		       GET_TID(hdr), ntohl(hdr->ddpvld));
		return CPL_RET_BUF_DONE;
	}

	process_cpl_msg(new_rx_data_ddp, sk, skb);
	return 0;
}

static void process_ddp_complete(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct ddp_state *q;
	struct ddp_buf_state *bsp;
	struct cpl_rx_ddp_complete *hdr;
	unsigned int ddp_report, buf_idx;
	unsigned int delack_mode;

	if (unlikely(sk_no_receive(sk))) {
		handle_excess_rx(sk, skb);
		return;
	}

	tp = tcp_sk(sk);
	q = DDP_STATE(sk);
	hdr = cplhdr(skb);
	ddp_report = ntohl(hdr->ddp_report);
	buf_idx = (ddp_report >> S_DDP_BUF_IDX) & 1;
	bsp = &q->buf_state[buf_idx];

	skb_ulp_ddp_offset(skb) = bsp->cur_offset;
	skb->len = G_DDP_OFFSET(ddp_report) - skb_ulp_ddp_offset(skb);

	bsp->cur_offset += skb->len;

	q->cur_buf ^= 1;

	skb_gl_set(skb, bsp->gl);
	skb_ulp_ddp_flags(skb) = (bsp->flags & DDP_BF_NOCOPY) | 1;

	if (bsp->flags & DDP_BF_NOCOPY)
		bsp->flags &= ~DDP_BF_NOCOPY;
	skb_ulp_ddp_flags(skb) |= DDP_BF_NODATA;

	delack_mode = G_DDP_DACK_MODE(ddp_report);
	if (unlikely(G_DDP_DACK_MODE(ddp_report) != cplios->delack_mode)) {
		cplios->delack_mode = delack_mode;
		cplios->delack_seq = tp->rcv_nxt;
	}

	ULP_SKB_CB(skb)->seq = tp->rcv_nxt;

	tp->rcv_nxt = ntohl(hdr->rcv_nxt);

	skb_reset_transport_header(skb);
	tcp_hdr(skb)->fin = 0;          /* changes valid memory past CPL */

	inet_csk(sk)->icsk_ack.lrcvtime = tcp_time_stamp;
	__skb_queue_tail(&sk->sk_receive_queue, skb);
	if (!sock_flag(sk, SOCK_DEAD))
		sk_data_ready_compat(sk, 0);
}

/*
 * Handler for RX_DDP_COMPLETE CPL messages.
 */
static int do_rx_ddp_complete(struct tom_data *td, struct sk_buff *skb)
{
        struct sock *sk;
        struct cpl_rx_ddp_complete *req = cplhdr(skb);
        unsigned int hwtid = GET_TID(req);

        sk = lookup_tid(td->tids, hwtid);

	VALIDATE_SOCK(sk);

	process_cpl_msg(process_ddp_complete, sk, skb);
	return 0;
}

/*
 * Move a socket to TIME_WAIT state.  We need to make some adjustments to the
 * socket state before calling tcp_time_wait to comply with its expectations.
 */
static void enter_timewait(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/*
	 * Bump rcv_nxt for the peer FIN.  We don't do this at the time we
	 * process peer_close because we don't want to carry the peer FIN in
	 * the socket's receive queue and if we increment rcv_nxt without
	 * having the FIN in the receive queue we'll confuse facilities such
	 * as SIOCINQ.
	 */
	tp->rcv_nxt++;

	/*
	 * Fake a timestamp for the most recent time that ts_recent was set.
	 * We never actually set ts_recent in our code but without this, an
	 * attampt to use SO_REUSEADDR won't work on the client side and the
	 * client will have to wait for the zombie socket to time out in the
	 * kernel's Time Wait list.
	 */
	TS_RECENT_STAMP(tp) = get_seconds();

	tp->srtt_us = 0;                        /* defeat tcp_update_metrics */
	tcp_time_wait(sk, TCP_TIME_WAIT, 0); /* calls tcp_done */
}

/*
 * For TCP DDP a PEER_CLOSE may also be an implicit RX_DDP_COMPLETE.  This
 * function deals with the data that may be reported along with the FIN.
 * Returns -1 if no further processing of the PEER_CLOSE is needed, >= 0 to
 * perform normal FIN-related processing.  In the latter case 1 indicates that
 * there was an implicit RX_DDP_COMPLETE and the skb should not be freed, 0 the
 * skb can be freed.
 */
static int handle_peer_close_data(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct ddp_state *q;
	struct ddp_buf_state *bsp;
	struct cpl_peer_close *req = cplhdr(skb);
	unsigned int rcv_nxt = ntohl(req->rcv_nxt) - 1; /* exclude FIN */

	if (tp->rcv_nxt == rcv_nxt)			/* no data */
		return 0;

	if (unlikely(sk_no_receive(sk))) {
		handle_excess_rx(sk, skb);

		/*
		 * Although we discard the data we want to process the FIN so
		 * that PEER_CLOSE + data behaves the same as RX_DATA_DDP +
		 * PEER_CLOSE without data.  In particular this PEER_CLOSE
		 * may be what will close the connection.  We return 1 because
		 * handle_excess_rx() already freed the packet.
		 */
		return 1;
	}

	q = DDP_STATE(sk);
	if (!q->ddp_setup)
		return 0;

	bsp = &q->buf_state[q->cur_buf];
	skb->len = rcv_nxt - tp->rcv_nxt;
	skb_gl_set(skb, bsp->gl);
	skb_ulp_ddp_offset(skb) = bsp->cur_offset;
	skb_ulp_ddp_flags(skb) =
	    DDP_BF_PSH | (bsp->flags & DDP_BF_NOCOPY) | 1;

	ULP_SKB_CB(skb)->seq = tp->rcv_nxt;
	tp->rcv_nxt = rcv_nxt;
	bsp->cur_offset += skb->len;
	q->cur_buf ^= 1;

	skb_reset_transport_header(skb);
	tcp_hdr(skb)->fin = 0;          /* changes valid memory past CPL */

	inet_csk(sk)->icsk_ack.lrcvtime = tcp_time_stamp;
	__skb_queue_tail(&sk->sk_receive_queue, skb);
	if (!sock_flag(sk, SOCK_DEAD))
		sk_data_ready_compat(sk, 0);
	return 1;
}

/*
 * Handle a peer FIN.
 */
static void do_peer_fin(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	int keep = 0, dead = sock_flag(sk, SOCK_DEAD);

	if (cplios_flag(sk, CPLIOS_ABORT_RPL_PENDING))
		goto out;

	if (cplios->ulp_mode == ULP_MODE_TCPDDP) {
		keep = handle_peer_close_data(sk, skb);
		if (keep < 0)
			return;
	}

	sk->sk_shutdown |= RCV_SHUTDOWN;
	sock_set_flag(sk, SOCK_DONE);

	switch (sk->sk_state) {
	case TCP_SYN_RECV:
	case TCP_ESTABLISHED:
		tcp_set_state(sk, TCP_CLOSE_WAIT);
		break;
	case TCP_FIN_WAIT1:
		tcp_set_state(sk, TCP_CLOSING);
		break;
	case TCP_FIN_WAIT2:
		if (ma_fail_do_peer_fin(sk, TCP_FIN_WAIT2))
			break;

		/*
		 * If we've sent an abort_req we must have sent it too late,
		 * HW will send us a reply telling us so, and this peer_close
		 * is really the last message for this connection and needs to
		 * be treated as an abort_rpl, i.e., transition the connection
		 * to TCP_CLOSE (note that the host stack does this at the
		 * time of generating the RST but we must wait for HW).
		 * Otherwise we enter TIME_WAIT.
		 */
		t4_release_offload_resources(sk);
		if (cplios_flag(sk, CPLIOS_ABORT_RPL_PENDING))
			connection_done(sk);
		else
			enter_timewait(sk);
		break;
	default:
		printk(KERN_ERR
		       "%s: TID %u received PEER_CLOSE in bad state %d\n",
		       cplios->toedev->name, cplios->tid, sk->sk_state);
	}

	if (!dead) {
		sk->sk_state_change(sk);

		/* Do not send POLL_HUP for half duplex close. */
		if ((sk->sk_shutdown & SEND_SHUTDOWN) ||
		    sk->sk_state == TCP_CLOSE)
			sk_wake_async(sk, 1, POLL_HUP);
		else
			sk_wake_async(sk, 1, POLL_IN);
	}
out:	if (!keep)
		kfree_skb(skb);
}

/*
 * Handler for PEER_CLOSE CPL messages.
 */
static int do_peer_close(struct tom_data *td, struct sk_buff *skb)
{
	struct sock *sk;
	struct cpl_peer_close *req = cplhdr(skb);
	unsigned int hwtid = GET_TID(req);

	sk = lookup_tid(td->tids, hwtid);

	VALIDATE_SOCK(sk);

	process_cpl_msg_ref(do_peer_fin, sk, skb);
	return 0;
}

/*
 * Process a peer ACK to our FIN.
 */
static void process_close_con_rpl(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct cpl_close_con_rpl *rpl = cplhdr(skb);

	tp->snd_una = ntohl(rpl->snd_nxt) - 1;  /* exclude FIN */

	if (cplios_flag(sk, CPLIOS_ABORT_RPL_PENDING))
		goto out;

	switch (sk->sk_state) {
	case TCP_CLOSING:              /* see FIN_WAIT2 case in do_peer_fin */
		if (ma_fail_process_close_con_rpl(sk, TCP_CLOSING))
			break;

		t4_release_offload_resources(sk);
		if (cplios_flag(sk, CPLIOS_ABORT_RPL_PENDING))
			connection_done(sk);
		else
			enter_timewait(sk);
		break;
	case TCP_LAST_ACK:
		if (ma_fail_process_close_con_rpl(sk, TCP_LAST_ACK))
			break;

		/*
		 * In this state we don't care about pending abort_rpl.
		 * If we've sent abort_req it was post-close and was sent too
		 * late, this close_con_rpl is the actual last message.
		 */
		t4_release_offload_resources(sk);
		connection_done(sk);
		break;
	case TCP_FIN_WAIT1:
		tcp_set_state(sk, TCP_FIN_WAIT2);
		sk->sk_shutdown |= SEND_SHUTDOWN;
		dst_confirm(sk->sk_dst_cache);

		if (!sock_flag(sk, SOCK_DEAD))
			sk->sk_state_change(sk); // Wake up lingering close()
		else if (tcp_sk(sk)->linger2 < 0 &&
			 !cplios_flag(sk, CPLIOS_ABORT_SHUTDOWN))
			abort_conn(sk, skb, LINUX_MIB_TCPABORTONLINGER);
		break;
	default:
		printk(KERN_ERR
		       "%s: TID %u received CLOSE_CON_RPL in bad state %d\n",
		       cplios->toedev->name, cplios->tid, sk->sk_state);
	}
out:	kfree_skb(skb);  /* can't use __kfree_skb here */
}

/*
 * Handler for CLOSE_CON_RPL CPL messages.
 */
static int do_close_con_rpl(struct tom_data *td, struct sk_buff *skb)
{
        struct sock *sk;
        struct cpl_close_con_rpl *rpl = cplhdr(skb);
        unsigned int hwtid = GET_TID(rpl);

        sk = lookup_tid(td->tids, hwtid);

	VALIDATE_SOCK(sk);

	process_cpl_msg_ref(process_close_con_rpl, sk, skb);
	return 0;
}

/*
 * Process abort replies.  We only process these messages if we anticipate
 * them as the coordination between SW and HW in this area is somewhat lacking
 * and sometimes we get ABORT_RPLs after we are done with the connection that
 * originated the ABORT_REQ. A migrating connection will set MIGRATION_TOEDEV
 * and CPLIOS_TX_FAILOVER before issuing commands to the old T4.
 */
static void process_abort_rpl(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_abort_rpl_rss *rpl = cplhdr(skb);

	if (ma_fail_process_abort_rpl(sk))
		goto out;

	if (rpl->rss_hdr.channel != CPL_IO_STATE(sk)->tx_c_chan) {
		cplios_reset_flag(sk, CPLIOS_TX_WAIT_IDLE);
		cplios_reset_flag(sk, CPLIOS_TX_FAILOVER);
	}

	if (cplios_flag(sk, CPLIOS_ABORT_RPL_PENDING)) {
			cplios_reset_flag(sk, CPLIOS_ABORT_RPL_PENDING);
			if (!cplios_flag(sk, CPLIOS_ABORT_REQ_RCVD)) {
				BUG_ON(cplios_flag(sk, CPLIOS_ABORT_REQ_RCVD));

				if (sk->sk_state == TCP_SYN_SENT) {
					struct cpl_io_state *cplios = CPL_IO_STATE(sk);
					struct tid_info *tids = TOM_DATA(cplios->toedev)->tids;

					cxgb4_remove_tid(tids, cplios->port_id, GET_TID(rpl),
							 sk->sk_family);
					sock_put(sk);
				}

				t4_release_offload_resources(sk);
				connection_done(sk);
			}
	}
out:
	kfree_skb(skb);
}

/*
 * Handle an ABORT_RPL_RSS CPL message.
 */
static int do_abort_rpl(struct tom_data *td, struct sk_buff *skb)
{
	struct cpl_abort_rpl_rss *rpl = cplhdr(skb);
        struct sock *sk;
        unsigned int hwtid = GET_TID(rpl);

        sk = lookup_tid(td->tids, hwtid);

	/*
	 * Ignore replies to post-close aborts indicating that the abort was
	 * requested too late.  These connections are terminated when we get
	 * PEER_CLOSE or CLOSE_CON_RPL and by the time the abort_rpl_rss
	 * arrives the TID is either no longer used or it has been recycled.
	 */
	if (rpl->status == CPL_ERR_ABORT_FAILED) {
discard:
		kfree_skb(skb);
		return 0;
	}

	/*
	 * Sometimes we've already closed the socket, e.g., a post-close
	 * abort races with ABORT_REQ_RSS, the latter frees the socket
	 * expecting the ABORT_REQ will fail with CPL_ERR_ABORT_FAILED,
	 * but FW turns the ABORT_REQ into a regular one and so we get
	 * ABORT_RPL_RSS with status 0 and no socket.  
	 */
	if (!sk)
		goto discard;

	process_cpl_msg_ref(process_abort_rpl, sk, skb);
	return 0;
}

/*
 * Convert the status code of an ABORT_REQ into a Linux error code.  Also
 * indicate whether RST should be sent in response.
 */
static int abort_status_to_errno(struct sock *sk, int abort_reason,
				 int *need_rst)
{
	switch (abort_reason) {
	case CPL_ERR_BAD_SYN:
	case CPL_ERR_CONN_RESET:
		// XXX need to handle SYN_RECV due to crossed SYNs
		return sk->sk_state == TCP_CLOSE_WAIT ? EPIPE : ECONNRESET;
	case CPL_ERR_XMIT_TIMEDOUT:
	case CPL_ERR_PERSIST_TIMEDOUT:
	case CPL_ERR_FINWAIT2_TIMEDOUT:
	case CPL_ERR_KEEPALIVE_TIMEDOUT:
		T4_NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPABORTONTIMEOUT);
		return ETIMEDOUT;
	default:
		return EIO;
	}
}

static inline void set_abort_rpl_wr(struct sk_buff *skb, unsigned int tid,
				    int cmd)
{
	struct cpl_abort_rpl *rpl = cplhdr(skb);

	INIT_TP_WR_MIT_CPL(rpl, CPL_ABORT_RPL, tid);
	rpl->cmd = cmd;
}

static void send_deferred_abort_rpl(struct toedev *tdev, struct sk_buff *skb)
{
	struct sk_buff *reply_skb;
	struct cpl_abort_req_rss *req = cplhdr(skb);

	reply_skb = alloc_skb_nofail(sizeof(struct cpl_abort_rpl));
	__skb_put(reply_skb, sizeof(struct cpl_abort_rpl));
	set_abort_rpl_wr(reply_skb, GET_TID(req), (req->status & CPL_ABORT_NO_RST));
	set_wr_txq(reply_skb, CPL_PRIORITY_DATA, req->status >> 1);
	cxgb4_ofld_send(tdev->lldev[0], reply_skb);
	kfree_skb(skb);
}

static void send_deferred_tnl(struct toedev *tdev, struct sk_buff *skb)
{
	local_bh_disable();
	netif_receive_skb(skb);
	local_bh_enable();
}

static void send_abort_rpl(struct sock *sk, struct sk_buff *skb,
			   struct toedev *tdev, int rst_status, int queue)
{
	struct sk_buff *reply_skb;
	struct cpl_abort_req_rss *req = cplhdr(skb);
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);

	reply_skb = get_cpl_reply_skb(skb, sizeof(struct cpl_abort_rpl),
				      gfp_any());
	if (!reply_skb) {
		/* Defer the reply.  Stick rst_status into req->cmd. Supports 7-bit tx ofld index */
		req->status = (queue << 1) | rst_status;
		t4_defer_reply(skb, tdev, send_deferred_abort_rpl);
		return;
	}

	set_abort_rpl_wr(reply_skb, GET_TID(req), rst_status);
	kfree_skb(skb);	       /* can't use __kfree_skb here */
	/*
	 * XXX need to sync with ARP as for SYN_RECV connections we can send
	 * these messages while ARP is pending.  For other connection states
	 * it's not a problem.
	 */
	set_wr_txq(reply_skb, CPL_PRIORITY_DATA, queue);
	if (cplios && cplios->l2t_entry && (sk->sk_state != TCP_SYN_RECV))
		cxgb4_sk_l2t_send(cplios->egress_dev, reply_skb,
			       cplios->l2t_entry, sk);
	else
		cxgb4_ofld_send(tdev->lldev[0], reply_skb);
}

static void cleanup_syn_rcv_conn(struct sock *child, struct sock *parent)
{
	struct request_sock *req = CPL_IO_STATE(child)->passive_reap_next;

	reqsk_queue_removed(&inet_csk(parent)->icsk_accept_queue, req);
	synq_remove(child);
	t4_reqsk_free(req);
	CPL_IO_STATE(child)->passive_reap_next = NULL;
}

/*
 * Performs the actual work to abort a SYN_RECV connection.
 */
static void do_abort_syn_rcv(struct sock *child, struct sock *parent)
{
	/*
	 * If the server is still open we clean up the child connection,
	 * otherwise the server already did the clean up as it was purging
	 * its SYN queue and the skb was just sitting in its backlog.
	 */
	if (likely(parent->sk_state == TCP_LISTEN)) {
		cleanup_syn_rcv_conn(child, parent);
		/* Without the below call to sock_orphan,
		 * we leak the socket resource with syn_flood test
		 * as inet_csk_destroy_sock will not be called
		 * in tcp_done since SOCK_DEAD flag is not set.
		 * Kernel handles this differently where new socket is
		 * created only after 3 way handshake is done.
		 */
		sock_orphan(child);
		INC_ORPHAN_COUNT(child);
		t4_release_offload_resources(child);
		connection_done(child);
	} else {
		if (cplios_flag(child, CPLIOS_RST_ABORTED)) {
			t4_release_offload_resources(child);
			connection_done(child);
		}
	}
}

/*
 * This is run from a listener's backlog to abort a child connection in
 * SYN_RCV state (i.e., one on the listener's SYN queue).
 */
static void bl_abort_syn_rcv(struct sock *lsk, struct sk_buff *skb)
{
	struct sock *child = skb->sk;
	int queue = CPL_IO_STATE(child)->txq_idx;

	skb->sk = NULL;
	do_abort_syn_rcv(child, lsk);
	send_abort_rpl(child, skb, BLOG_SKB_CB(skb)->dev, CPL_ABORT_NO_RST,
		       queue);
}

/*
 * Handle abort requests for a SYN_RECV connection.  These need extra work
 * because the socket is on its parent's SYN queue.
 */
static int abort_syn_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct sock *parent;
	struct toedev *tdev = CPL_IO_STATE(sk)->toedev;
	struct tom_data *td = TOM_DATA(tdev);
	const struct request_sock *oreq = CPL_IO_STATE(sk)->passive_reap_next;
	void *data;
	struct listen_ctx *listen_ctx;

	if (!oreq) {
		printk(KERN_ERR "abort_syn_rcv: sk not on SYN Queue!\n");
		return -1;        /* somehow we are not on the SYN queue */
	}

	data = lookup_stid(td->tids, oreq->ts_recent);
	if (!data) {
		printk(KERN_INFO "abort_syn_rcv: lookup for stid=%u failed\n", oreq->ts_recent);
		return -1;
	}
	listen_ctx = (struct listen_ctx *)data;
	parent = listen_ctx->lsk;

	bh_lock_sock(parent);
	if (!sock_owned_by_user(parent)) {
		int queue = CPL_IO_STATE(sk)->txq_idx;

		do_abort_syn_rcv(sk, parent);
		send_abort_rpl(sk, skb, tdev, CPL_ABORT_NO_RST, queue);
	} else {
		skb->sk = sk;
		BLOG_SKB_CB(skb)->backlog_rcv = bl_abort_syn_rcv;
		__sk_add_backlog(parent, skb);
	}
	bh_unlock_sock(parent);
	return 0;
}

/*
 * Process abort requests.  If we are waiting for an ABORT_RPL we ignore this
 * request except that we need to reply to it.
 */
static void process_abort_req(struct sock *sk, struct sk_buff *skb)
{
	int rst_status = CPL_ABORT_NO_RST;
	const struct cpl_abort_req_rss *req = cplhdr(skb);
	int queue = CPL_IO_STATE(sk)->txq_idx;

	/*
	 * If the Abort is really a "Negative Advice" message from TP
	 * indicating that it's having problems with the connection (multiple
	 * retransmissions, etc.), then let's see if something has changed
	 * like the Path MTU (typically indicated via an ICMP_UNREACH
	 * ICMP_FRAG_NEEDED message from an intermediate router).
	 */
	if (is_neg_adv(req->status)) {
		struct dst_entry *dst = __sk_dst_get(sk);
		unsigned int mtu_idx = select_mss(sk, dst_mtu(dst), 0);
		struct cpl_io_state *cplios = CPL_IO_STATE(sk);

		if (mtu_idx < cplios->mtu_idx) {
			t4_set_maxseg(sk, mtu_idx);
			cplios->mtu_idx = mtu_idx;
		}

		if (sk->sk_state == TCP_SYN_RECV)
			t4_set_tcb_tflag(sk, S_TF_MIGRATING, 0);
	
		kfree_skb(skb);
		return;
	}

	cplios_reset_flag(sk, CPLIOS_ABORT_REQ_RCVD);

	if (req->rss_hdr.channel != CPL_IO_STATE(sk)->tx_c_chan) {
		cplios_reset_flag(sk, CPLIOS_TX_WAIT_IDLE);
		cplios_reset_flag(sk, CPLIOS_TX_FAILOVER);
	}
	/*
	 * Send a flowc if not already sent
	 */
	if (!cplios_flag(sk, CPLIOS_ABORT_SHUTDOWN) &&
	    !cplios_flag(sk, CPLIOS_TX_DATA_SENT)) {
		struct tcp_sock *tp = tcp_sk(sk);
		send_tx_flowc_wr(sk, 0, tp->snd_nxt, tp->rcv_nxt);
		cplios_set_flag(sk, CPLIOS_TX_DATA_SENT);
	}

	cplios_set_flag(sk, CPLIOS_ABORT_SHUTDOWN);

	if (ma_fail_process_abort_req(sk))
		goto out;

	/*
	 * Three cases to consider:
	 * a) We haven't sent an abort_req; close the connection.
	 * b) We have sent a post-close abort_req that will get to TP too late
	 *    and will generate a CPL_ERR_ABORT_FAILED reply.  The reply will
	 *    be ignored and the connection should be closed now.
	 * c) We have sent a regular abort_req that will get to TP too late.
	 *    That will generate an abort_rpl with status 0, wait for it.
	 */
	if (!cplios_flag(sk, CPLIOS_ABORT_RPL_PENDING)) {
		sk->sk_err = abort_status_to_errno(sk, req->status,
						   &rst_status);
		if (!sock_flag(sk, SOCK_DEAD))
			sk->sk_error_report(sk);

		/*
		 * SYN_RECV needs special processing.  If abort_syn_rcv()
		 * returns 0 is has taken care of the abort.
		 */
		if (sk->sk_state == TCP_SYN_RECV && !abort_syn_rcv(sk, skb))
			return;

		t4_release_offload_resources(sk);
		connection_done(sk);
	}
out:
	send_abort_rpl(sk, skb, BLOG_SKB_CB(skb)->dev, rst_status, queue);
}

/*
 * Handle an ABORT_REQ_RSS CPL message.
 */
static int do_abort_req(struct tom_data *td, struct sk_buff *skb)
{
	const struct cpl_abort_req_rss *req = cplhdr(skb);
        unsigned int hwtid = GET_TID(req);
	struct sock *sk;

        sk = lookup_tid(td->tids, hwtid);

	VALIDATE_SOCK(sk);

	/*
	 * Save the offload device in the skb, we may process this message
	 * after the socket has closed.
	 */
	BLOG_SKB_CB(skb)->dev = CPL_IO_STATE(sk)->toedev;

	process_cpl_msg_ref(process_abort_req, sk, skb);
	return 0;
}

static void pass_open_abort(struct sock *child, struct sock *parent,
			    struct sk_buff *skb)
{
	do_abort_syn_rcv(child, parent);
	kfree_skb(skb);
}

/*
 * Runs from a listener's backlog to abort a child connection that had an
 * ARP failure.
 */
static void bl_pass_open_abort(struct sock *lsk, struct sk_buff *skb)
{
	pass_open_abort(skb->sk, lsk, skb);
}

static void handle_pass_open_arp_failure(struct sock *sk, struct sk_buff *skb)
{
	struct sock *parent;
	const struct request_sock *oreq;
	void *data;
	const struct tom_data *d = TOM_DATA(CPL_IO_STATE(sk)->toedev);
	
	/*
	 * If the connection is being aborted due to the parent listening
	 * socket going away there's nothing to do, the ABORT_REQ will close
	 * the connection.
	 */
	if (cplios_flag(sk, CPLIOS_ABORT_RPL_PENDING)) {
		kfree_skb(skb);
		return;
	}

	oreq = CPL_IO_STATE(sk)->passive_reap_next;
	data = lookup_stid(d->tids, oreq->ts_recent);
	parent = ((struct listen_ctx *)data)->lsk;

	bh_lock_sock(parent);
	if (!sock_owned_by_user(parent))
		pass_open_abort(sk, parent, skb);
	else {
		BLOG_SKB_CB(skb)->backlog_rcv = bl_pass_open_abort;
		__sk_add_backlog(parent, skb);
	}
	bh_unlock_sock(parent);
}

/*
 * Handle an ARP failure for a CPL_PASS_ACCEPT_RPL.  This is treated similarly
 * to an ABORT_REQ_RSS in SYN_RECV as both events need to tear down a SYN_RECV
 * connection.
 */
static void pass_accept_rpl_arp_failure(void *handle, struct sk_buff *skb)
{
	T4_TCP_INC_STATS_BH(sock_net(skb->sk), TCP_MIB_ATTEMPTFAILS);
	BLOG_SKB_CB(skb)->dev = CPL_IO_STATE(skb->sk)->toedev;
	process_cpl_msg_ref(handle_pass_open_arp_failure, skb->sk, skb);
}

#if defined(ROUTE_REQ)
static struct dst_entry *route_req(struct sock *sk, struct open_request *req)
{
	struct rtable *rt;
	struct flowi fl = { .oif = sk->sk_bound_dev_if,
			    .nl_u = { .ip4_u =
				      { .daddr = req->af.v4_req.rmt_addr,
					.saddr = req->af.v4_req.loc_addr,
					.tos = RT_CONN_FLAGS(sk)}},
			    .proto = IPPROTO_TCP,
			    .uli_u = { .ports =
				       { .sport = inet_sk(sk)->inet_sport,
					 .dport = req->rmt_port}}
	};

	if (ip_route_output_flow(&rt, &fl, sk, 0)) {
		IP_INC_STATS_BH(IPSTATS_MIB_OUTNOROUTES);
		return NULL;
	}
	return &rt->u.dst;
}
#endif

/*
 * Create a new socket as a child of the listening socket 'lsk' and initialize
 * with the information in the supplied PASS_ACCEPT_REQ message.
 *
 * 'retry' indicates to the caller whether a failure is device-related and the
 * connection should be passed to the host stack, or connection-related and
 * the connection request should be rejected.
 */
static struct sock *mk_pass_sock(struct sock *lsk, struct toedev *tdev, struct net_device *edev, int tid,
				 const struct cpl_pass_accept_req *req,
				 void *network_hdr,
				 struct request_sock *oreq,
				 int *retry,
				 const struct offload_settings *s)
{
	struct sock *newsk;
	struct cpl_io_state *newcplios;
	struct l2t_entry *e;
	struct dst_entry *dst=NULL;
	struct tcp_sock *newtp;
	struct net_device *egress = NULL;
	struct tom_data *d = TOM_DATA(tdev);
	const struct iphdr *iph = (const struct iphdr *)network_hdr;
	struct tcphdr *tcph;
	struct inet_sock *newinet;
	struct neighbour *neigh = NULL;
	struct toe_hash_params hash_params;
#ifdef CONFIG_TCPV6_OFFLOAD
	struct tcp6_sock *newtcp6sk;
	struct ipv6_pinfo *newnp, *np = inet6_sk(lsk);
	inet6_request_sock_t *treq;
#endif

	*retry = 0;
	if (!oreq)
		goto out_err;

#ifdef CONFIG_SECURITY_NETWORK
	if (security_inet_conn_request(lsk, tcphdr_skb, oreq))
		goto free_or;
#endif
	newsk = tcp_create_openreq_child(lsk, oreq, tcphdr_skb);
	if (!newsk)
		goto free_or;
	if (lsk->sk_family == AF_INET) {
		dst = inet_csk_route_child_sock(lsk, newsk, oreq);
		if (!dst)
			goto free_sk;

		tcph = (struct tcphdr *)(iph + 1);
		neigh = t4_dst_neigh_lookup(dst, &iph->saddr);
		if (neigh) {
			init_toe_hash_params(&hash_params, neigh->dev, neigh,
					     iph->saddr, iph->daddr, tcph->source,
					     tcph->dest, NULL, NULL, false,
					     IPPROTO_TCP);
			egress = offload_get_phys_egress(&hash_params, TOE_OPEN);
			if (!egress || !netdev_is_offload(egress) ||
			    (TOEDEV(egress) != tdev)) {
				t4_dst_neigh_release(neigh);
				goto free_dst;
			}
		} else {
			printk(KERN_INFO "mk_pass_sock: dst->_neighbour is NULL\n");
			goto free_dst;
		}
	}
#if defined(CONFIG_TCPV6_OFFLOAD)
	else {
		struct flowi6 fl6;
		const struct ipv6hdr *ip6h = (const struct ipv6hdr *)network_hdr;
		tcph = (struct tcphdr *)(ip6h + 1);

		memset(&fl6, 0, sizeof(fl6));
		fl6.flowi6_proto = IPPROTO_TCP;
		fl6.saddr = ip6h->daddr;
		fl6.daddr = ip6h->saddr;
		fl6.fl6_dport = inet_rsk(oreq)->ir_rmt_port;
		fl6.fl6_sport = t4_get_req_lport(oreq);

		if (ipv6_addr_type(&fl6.daddr) & IPV6_ADDR_LINKLOCAL)
			fl6.flowi6_oif = edev->ifindex;
		inet6_rsk(oreq)->ir_iif = fl6.flowi6_oif;
		security_req_classify_flow(oreq,  flowi6_to_flowi(&fl6));

		dst = ip6_dst_lookup_flow_compat(lsk, &fl6, NULL, false);
		if (IS_ERR(dst))
			goto free_sk;

		neigh = t4_dst_neigh_lookup(dst, &ip6h->saddr);
		if (neigh) {
			init_toe_hash_params(&hash_params, neigh->dev, neigh,
					     0, 0, tcph->source, tcph->dest,
					     (__be32*)&ip6h->saddr,
					     (__be32*)&ip6h->daddr,
					     true, IPPROTO_TCP);
			egress = offload_get_phys_egress(&hash_params, TOE_OPEN);
			if (!egress || !netdev_is_offload(egress) ||
			    (TOEDEV(egress) != tdev)) {
				t4_dst_neigh_release(neigh);
				goto free_dst;
			}
		} else {
			printk(KERN_INFO "mk_pass_sock: dst->_neighbour is NULL\n");
			goto free_dst;
		}
	}
#endif
	e = cxgb4_l2t_get(d->lldi->l2t, neigh, egress , lsk->sk_priority);
	t4_dst_neigh_release(neigh);
	if (!e) {
		*retry = 1;                       /* out of HW resources */
		goto free_dst;
	}

	newcplios = kzalloc(sizeof *newcplios, GFP_ATOMIC);
	if (!newcplios)
		goto free_l2t;
	kref_init(&newcplios->kref);
	newcplios->sk = newsk;
	CPL_IO_STATE(newsk) = newcplios;
	if (sock_flag(newsk, SOCK_KEEPOPEN))
		inet_csk_delete_keepalive_timer(newsk);

	oreq->ts_recent = G_PASS_OPEN_TID(ntohl(req->tos_stid));
	newcplios->tx_c_chan = G_SYN_INTF(ntohs(req->l2info));
	sk_setup_caps(newsk, dst);

	newtp = tcp_sk(newsk);
	newinet = inet_sk(newsk);
	if (unlikely(newsk->sk_user_data && check_special_data_ready(newsk) > 0))
		sock_set_flag(newsk, SOCK_NO_DDP);
	init_offload_sk(newsk, tdev, tid, e, dst, egress, s, ntohs(req->tcpopt.mss));
	newcplios->passive_reap_next = oreq;
	newcplios->egress_dev = egress;
	newcplios->delack_seq = newtp->rcv_nxt;
	ma_fail_mk_pass_sock(newsk);
	RCV_WSCALE(newtp) = select_rcv_wscale(tcp_full_space(newsk),
					      WSCALE_OK(newtp),
					      newtp->window_clamp);

	if (iph->version == 0x4) {
		newinet->inet_daddr = iph->saddr;
		newinet->inet_rcv_saddr = iph->daddr;
		newinet->inet_saddr = iph->daddr;
	}
#ifdef CONFIG_TCPV6_OFFLOAD
	else if (iph->version == 0x6) {
		newtcp6sk = (struct tcp6_sock *)newsk;
		inet_sk(newsk)->pinet6 = &newtcp6sk->inet6;
		np  = inet6_sk(lsk);
		newnp = inet6_sk(newsk);
		treq = inet6_rsk(oreq);
		memcpy(newnp, np, sizeof(struct ipv6_pinfo));
		inet6_sk_daddr(newsk) = treq->ir_v6_rmt_addr;
		inet6_sk_saddr(newsk) = treq->ir_v6_loc_addr;
		inet6_sk_rcv_saddr(newsk) = treq->ir_v6_loc_addr;
		t4_set_inet_sock_opt(newinet, NULL);
		newnp->ipv6_fl_list = NULL;
		newnp->pktoptions = NULL;
        	newsk->sk_bound_dev_if = treq->ir_iif;
		newinet->inet_daddr = newinet->inet_saddr = LOOPBACK4_IPV6;
		newinet->inet_rcv_saddr = LOOPBACK4_IPV6;
	}
#endif
	lsk->sk_prot->hash(newsk);
	t4_inet_inherit_port(&tcp_hashinfo, lsk, newsk);
	install_offload_ops(newsk);
	bh_unlock_sock(newsk);     // counters tcp_create_openreq_child()
	if (lsk->sk_family != AF_INET)
		if (cxgb4_clip_get(newcplios->egress_dev,
			(const u32 *)((&inet6_sk_saddr(newsk))->s6_addr), 1))
			goto free_l2t;

	return newsk;

free_l2t:
	cxgb4_l2t_release(e);	
free_dst:
	dst_release(dst);
free_sk:
	inet_csk_prepare_forced_close(newsk);
	tcp_done(newsk);
free_or:
	t4_reqsk_free(oreq);
out_err:
	return NULL;
}

static void offload_req_from_pass_accept_req(struct offload_req *oreq,
				      const struct cpl_pass_accept_req *req,
					     const struct tcphdr *tcph,
					     const struct sk_buff *skb,
					     const struct sock *listen_sk)
{
	unsigned int ipvers;

	if (listen_sk->sk_family == PF_INET) {
		const struct iphdr *iph = (struct iphdr *)skb_network_header(skb);

		ipvers = 4;
		oreq->sip[0] = iph->saddr;
		oreq->dip[0] = iph->daddr;
		oreq->sip[1] = oreq->sip[2] = oreq->sip[3] = 0;
		oreq->dip[1] = oreq->dip[2] = oreq->dip[3] = 0;	
	} else {
		ipvers = 6;
		oreq->sip[0] = ipv6_hdr(skb)->saddr.s6_addr32[0];
		oreq->sip[1] = ipv6_hdr(skb)->saddr.s6_addr32[1];
		oreq->sip[2] = ipv6_hdr(skb)->saddr.s6_addr32[2];
		oreq->sip[3] = ipv6_hdr(skb)->saddr.s6_addr32[3];
		oreq->dip[0] = ipv6_hdr(skb)->daddr.s6_addr32[0];
		oreq->dip[1] = ipv6_hdr(skb)->daddr.s6_addr32[1];
		oreq->dip[2] = ipv6_hdr(skb)->daddr.s6_addr32[2];
		oreq->dip[3] = ipv6_hdr(skb)->daddr.s6_addr32[3];
	}
	oreq->dport = tcph->dest;
	oreq->sport = tcph->source;
	oreq->ipvers_opentype = (OPEN_TYPE_PASSIVE << 4) | ipvers;
	oreq->tos = G_PASS_OPEN_TOS(ntohl(req->tos_stid));
	oreq->vlan = req->vlan ? req->vlan & htons(VLAN_VID_MASK) :
				     htons(CPL_L2T_VLAN_NONE);
#ifdef SO_MARK
	oreq->mark = listen_sk->sk_mark;
#else
	oreq->mark = 0;
#endif
}

static u32 resolve_options(u32 my_opt2, const struct cpl_pass_accept_req *req)
{
	if (!req->tcpopt.tstamp)
		my_opt2 &= ~F_TSTAMPS_EN;
	if (!req->tcpopt.sack)
		my_opt2 &= ~F_SACK_EN;
	if (req->tcpopt.wsf > 14)
		my_opt2 &= ~F_WND_SCALE_EN;
	return my_opt2;
}

#ifdef WD_TOE
/*
 * This function is for a passive connection request (SYN) to find 
 * which "wdtoe_device" according to the listening port.
 */
static int wdtoe_find_listen_dev_new(struct wdtoe_listen_device *t,
					int *idx,
					int listen_port)
{
	int i;

	for (i = 0; i < NWDTOECONN; i++) {
		if (t[i].in_use == 1 && t[i].listen_port == listen_port) {
			*idx = t[i].idx_dev;
			return 0;
		}
	}

	return -1;
}
#endif

#ifdef WD_TOE
/*
 * Check if an entry is alredy in the table
 */
static int wdtoe_passive_tuple_exists(struct passive_tuple *c,
					unsigned int stid,
					__u32 pip, __u16 pport)
{
	int i;

	for (i = 0; i < NWDTOECONN; i++) {
		if (c[i].in_use && c[i].stid == stid 
			&& c[i].pip == pip
			&& c[i].pport == pport)
			return 1;
	}

	return 0;
}
#endif

#ifdef WD_TOE
static struct passive_tuple *wdtoe_get_free_passive_tuple_slot(
					struct passive_tuple *c,
					unsigned short *idx)
{
	int i;

	for (i = 0; i < NWDTOECONN; i++) {
		if (!c[i].in_use) {
			*idx = i;
			return &c[i];
		}
	}

	return NULL;
}
#endif

#ifdef WD_TOE
static int wdtoe_insert_passive_tuple(struct passive_tuple *c,
					unsigned int stid,
					__u32 pip,
					__u16 pport)
{
	int ret;
	unsigned short idx;
	struct passive_tuple *free_slot;

	ret = wdtoe_passive_tuple_exists(c, stid, pip, pport);

	if (ret)
		return -1;

	free_slot = wdtoe_get_free_passive_tuple_slot(c, &idx);

	if (!free_slot)
		return -1;

	free_slot->stid = stid;
	free_slot->pip = pip;
	free_slot->pport = pport;
	free_slot->in_use = 1;

	return idx;
}
#endif

#ifdef WD_TOE
/* insert tid into the existing entry in the passive tuple */
static int wdtoe_insert_passive_tuple_tid(struct passive_tuple *c,
					unsigned int tid,
					__u32 pip,
					__u16 pport)
{
	int i;

	for (i = 0; i < NWDTOECONN; i++) {
		if(c[i].pip == pip && 
			c[i].pport == pport && 
			c[i].in_use == 1) {
			/* we get the entry, now update the tid and exit */
			c[i].tid = tid;
			return 0;
		}
	}

	return -1;
}
#endif

/*
 * Process a CPL_PASS_ACCEPT_REQ message.  Does the part that needs the socket
 * lock held.  Note that the sock here is a listening socket that is not owned
 * by the TOE.
 */
static void process_pass_accept_req(struct sock *sk, struct sk_buff *skb)
{
	int rt_flags;
	int pass2host, ret;
	struct sock *newsk;
	struct cpl_io_state *cplios;
	struct l2t_entry *e;
	struct offload_req orq;
	struct offload_settings settings;
	struct sk_buff *reply_skb;
	struct cpl_pass_accept_rpl *rpl;
	struct cpl_pass_accept_req *req = cplhdr(skb);
#ifdef WD_TOE
        unsigned int stid = G_PASS_OPEN_TID(ntohl(req->tos_stid));
#endif
	unsigned int tid = GET_TID(req);
	struct toedev *tdev = BLOG_SKB_CB(skb)->dev;
	struct tom_data *d = TOM_DATA(tdev);
	struct ethhdr *eh;
	struct vlan_ethhdr *vlan_eh = NULL;
	struct iphdr *iph;
	struct ipv6hdr *ip6h;
	struct tcphdr *tcph;
	struct request_sock *oreq = NULL;
	struct net_device *egress_dev;
	void *network_hdr;
	u16 vlan_tag, vlan_id, eth_hdr_len;
	struct cpl_t5_pass_accept_rpl *rpl5 = NULL;
	struct net_device *master = NULL;
	struct net_device *vlan_dev = NULL;
	__u8 ip_dsfield; /* IPv4 tos or IPv6 dsfield */
	bool th_ecn, ect, ecn_ok;

	rcu_read_lock();
	/*
	 * Ignore new connection request (as of now) if we are in middle
	 * of shutdown
	 */
	if (rcu_access_pointer(tdev->in_shutdown)) {
		rcu_read_unlock();
		goto out;
	}
	rcu_read_unlock();

	newsk = lookup_tid(d->tids, tid);
	if (newsk) {
		printk(KERN_ERR "%s: tid (%d) already in use\n", __func__, tid);
		goto out;
	}

	if (is_t4(d->lldi->adapter_type))
		reply_skb = alloc_skb(sizeof(*rpl), GFP_ATOMIC);
	else
		reply_skb = alloc_skb(
			roundup(sizeof(*rpl5), 16), GFP_ATOMIC);

	if (unlikely(!reply_skb)) {
		cxgb4_remove_tid(d->tids, 0, tid, sk->sk_family);
		kfree_skb(skb);
		goto out;
	}

	if (sk->sk_state != TCP_LISTEN)
		goto reject;

	skb->dev = egress_dev = d->egr_dev[G_SYN_INTF(ntohs(req->l2info))];

	if (CHELSIO_CHIP_VERSION(d->lldi->adapter_type) <= CHELSIO_T5)
	       eth_hdr_len = G_ETH_HDR_LEN(ntohl(req->hdr_len));
	else /* T6 and later */
	       eth_hdr_len = G_T6_ETH_HDR_LEN(ntohl(req->hdr_len));

	if (eth_hdr_len == ETH_HLEN) {
        	eh = (struct ethhdr *)(req + 1);
	     	iph = (struct iphdr *)(eh + 1);
		ip6h = (struct ipv6hdr *)(eh + 1);
		network_hdr = (void *)(eh + 1);
	} else {
		vlan_eh = (struct vlan_ethhdr *)(req + 1);
        	iph = (struct iphdr *)(vlan_eh + 1);
		ip6h = (struct ipv6hdr *)(vlan_eh + 1);
		network_hdr = (void *)(vlan_eh + 1);
	}
	if (iph->version == 0x4) {
		tcph = (struct tcphdr *)(iph + 1);
		skb_set_network_header(skb, (void *)iph - (void *)req);
	} else {
		tcph = (struct tcphdr *)(ip6h + 1);
		skb_set_network_header(skb, (void *)ip6h - (void *)req);
	}

	/*
	 * See if we have a Connection Offload Policy -- user-specified or
	 * default -- which allows this connection to be offloaded.  If not,
	 * we'll defer to the Host Stack.
	 */
	offload_req_from_pass_accept_req(&orq, req, tcph, skb, sk);
	rcu_read_lock();
	settings = *lookup_ofld_policy(tdev, &orq, d->conf.cop_managed_offloading);
	if (!settings.offload) {
		rcu_read_unlock();
		goto defer;
	}

	if (netif_is_bond_slave(egress_dev))
		master = netdev_master_upper_dev_get_rcu(egress_dev);

	vlan_tag = ntohs(req->vlan);
	vlan_id = vlan_tag & VLAN_VID_MASK;
	if (vlan_id != CPL_L2T_VLAN_NONE) {
		if (master)
			vlan_dev = __vlan_find_dev_deep_ctag(master, vlan_id);
		else
			vlan_dev = __vlan_find_dev_deep_ctag(egress_dev, vlan_id);
		if (!vlan_dev) {
			/* Hmm.. we have a vlan id on packet, and we don't have
			 * corresponding vlan device on host! Reject.
			 */
			rcu_read_unlock();
			goto reject;
		}
		egress_dev = vlan_dev;
	}
	if (!rcu_access_pointer(tdev->can_offload) || !tdev->can_offload(tdev, sk)) {
		rcu_read_unlock();
		goto reject;
	}
	rcu_read_unlock();

	if (inet_csk_reqsk_queue_is_full(sk))
		goto reject;
	if (sk_acceptq_is_full(sk) && d->conf.soft_backlog_limit)
		goto reject;

	if (master && !vlan_dev)
		skb->dev = master;
	else
		skb->dev = egress_dev;

	/*
	 * If this isn't a SYN destined to us, let the Host Stack figure it
	 * out.
	 */
	if ((iph->version == 0x4) && ip_route_input(skb, iph->daddr, iph->saddr,
			   G_PASS_OPEN_TOS(ntohl(req->tos_stid)), skb->dev))
		goto defer;

#if defined(CONFIG_TCPPV6_OFFLOAD)
	if (iph->version == 0x6) {
		ip6_route_input(skb);
		if (skb_dst(skb)->error)
			goto defer;
		dst_release(skb_dst(skb));
		skb_dst_set(skb, NULL);
	}
#endif
	skb->dev = egress_dev;

	if ((iph->version == 0x4) && skb_rtable(skb)) {
		rt_flags = skb_rtable(skb)->rt_flags &
			(RTCF_BROADCAST | RTCF_MULTICAST | RTCF_LOCAL);
		dst_release(skb_dst(skb));	// done with the input route, release it
		skb_dst_set(skb, NULL);
		if (rt_flags != RTCF_LOCAL)
			goto reject;
	}

	if (master) {
		ret = toe_enslave(master, egress_dev);
		if (ret)
			goto defer;
	}

	if (iph->version == 0x4)
		oreq = inet_reqsk_alloc(&t4_rsk_ops, sk);
#if defined(CONFIG_TCPV6_OFFLOAD)
	else
		oreq = inet6_reqsk_alloc(&t4_rsk6_ops, sk);
#endif
	if (!oreq)
		goto reject;

	/*
	 * The newly allocated oreq returned from above is mostly
	 * uninitialized.  Most of this initialization echos the work done in
	 * tcp_openreq_init().  Note that it's important to get these zero'ed
	 * out since they're used in tcp_create_openreq_child() to initialize
	 * various TCP Socket fields which can lead to confusion later on in
	 * this code.  For instance, if oreq->window_clamp contains a non-zero
	 * (junk) value, that'll get assigned to the TCP Socket Window Clamp
	 * field and later we'll think that was the desired (random value)
	 * Window Clamp ...
	 */
	oreq->rcv_wnd = 0;
	oreq->cookie_ts = 0;
	oreq->mss = 0;
	oreq->window_clamp = 0;
	oreq->ts_recent = 0;

        tcp_rsk(oreq)->rcv_isn = ntohl(tcph->seq);
	t4_set_req_port(oreq, tcph->source, tcph->dest);
	inet_rsk(oreq)->ecn_ok = 0;
	if (iph->version == 0x4) {
        	t4_set_req_addr(oreq, iph->daddr, iph->saddr);
		ip_dsfield = ipv4_get_dsfield(iph);
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	} else {
		inet6_rsk(oreq)->ir_v6_rmt_addr = ipv6_hdr(skb)->saddr;
		inet6_rsk(oreq)->ir_v6_loc_addr = ipv6_hdr(skb)->daddr;
		ip_dsfield = ipv6_get_dsfield(ipv6_hdr(skb));
#endif
	}
	t4_set_req_opt(oreq, NULL);
       	if (req->tcpopt.wsf <= 14 && tcp_win_scaling_enabled()) {
               	inet_rsk(oreq)->wscale_ok = 1;
               	inet_rsk(oreq)->snd_wscale = req->tcpopt.wsf;
	}

	/* Note: tcp_v6_init_req() might override ir_iif for link
	   locals */
	inet_rsk(oreq)->ir_iif = sk->sk_bound_dev_if;

	th_ecn = tcph->ece && tcph->cwr;
	if (th_ecn) {
		ect = !INET_ECN_is_not_ect(ip_dsfield);
		ecn_ok = tcp_ecn_enabled(sock_net(sk));

		if ((!ect && ecn_ok) || tcp_ca_needs_ecn(sk))
			inet_rsk(oreq)->ecn_ok = 1;
	}

	newsk = mk_pass_sock(sk, tdev, egress_dev, tid, req, network_hdr, oreq, &pass2host, &settings);
	if (!newsk)
		goto reject;

	inet_csk_reqsk_queue_added(sk, TCP_TIMEOUT_INIT);

	synq_add(sk, newsk);

	/* Don't get a reference, newsk starts out with ref count 2 */
	cxgb4_insert_tid(d->tids, newsk, tid, newsk->sk_family);
	cplios = CPL_IO_STATE(newsk);

	reply_skb->sk = newsk;
	t4_set_arp_err_handler(reply_skb, NULL, pass_accept_rpl_arp_failure);

	e = cplios->l2t_entry;
	cplios->smac_idx = cxgb4_tp_smt_idx(d->lldi->adapter_type,
					    cxgb4_port_viid(cplios->egress_dev));
	cplios->rx_c_chan = 0;

	if (is_t4(d->lldi->adapter_type)) {
		rpl = (struct cpl_pass_accept_rpl *)__skb_put(reply_skb, sizeof(*rpl));
		INIT_TP_WR_MIT_CPL(rpl, CPL_PASS_ACCEPT_RPL, tid);
	} else {
		rpl5 = (struct cpl_t5_pass_accept_rpl *)__skb_put(reply_skb,
			roundup(sizeof(*rpl5), 16));
		rpl = (struct cpl_pass_accept_rpl *)rpl5;
		INIT_TP_WR_MIT_CPL(rpl5, CPL_PASS_ACCEPT_RPL, tid);
	}

#ifdef WD_TOE
	/* If SO_PRIORITY is set, we think it's a WD-TOE connection */
	if (is_wdtoe(sk)) {
		int lport;
		int idx_dev = 0;
		int ret;
		struct wdtoe_device *wd_dev;
		__u32 pip;
		__u16 pport;
		int idx;

		pip = be32_to_cpu(inet_rsk(oreq)->ir_rmt_addr);
		pport = be16_to_cpu(inet_rsk(oreq)->ir_rmt_port);
		idx = wdtoe_insert_passive_tuple(passive_conn_tuple, stid,
						 pip, pport);
		if (idx == -1)
			printk(KERN_ERR "[wdtoe] %s: unable to insert tuple in "
					"'passive_conn_tuple' array\n", __func__);

		/* now we need to insert "tid" into the ntuple table */
		ret = wdtoe_insert_passive_tuple_tid(
					passive_conn_tuple, tid, pip, pport);
		if (ret < 0)
			printk(KERN_ERR "[wdtoe] %s: could not insert tid for "
					"pip [%#x], pport [%u]\n",
					__func__, pip, pport);

		/* get the wdtoe device according to the local port */
		lport = ntohs(inet_sk(sk)->inet_sport);
		ret = wdtoe_find_listen_dev_new(listen_table, 
						&idx_dev, lport);

		if (ret != 0) {
			printk(KERN_ERR "[wdtoe] %s: could not get the listening "
					"wd_dev for port [%d]\n",
					__func__, lport);
			/* XXX error out or use toe's opt2? */
			goto toe;
		}
		wd_dev = wdtoe_dev_table[idx_dev].wd_dev;
		cplios->opt2 = resolve_options(
				wdtoe_calc_opt2(newsk, &settings, wd_dev), req);
	} else {
toe:
#endif
		cplios->opt2 = resolve_options(cplios->opt2, req);
#ifdef WD_TOE
	}	/* end of the branch if a connection is WD-TOE */ 
#endif
	/*
	 * Because we could have changed our TCP Timestamp option for this
	 * connection in resolve_options(), we need to see if we want a new TP
	 * MTU Index.  Note that this is used in calc_opt0() ...
	 */
	cplios->mtu_idx = select_mss(newsk, dst_mtu(__sk_dst_get(newsk)),
				     ntohs(req->tcpopt.mss));

	rpl->opt0 = cpu_to_be64(calc_opt0(newsk) | V_ACCEPT_MODE(0) |
				V_L2T_IDX(e->idx) |
				V_SMAC_SEL(cplios->smac_idx) |
				V_TX_CHAN(cplios->tx_c_chan));
	rpl->opt2 = htonl(cplios->opt2);

	if (CHELSIO_CHIP_VERSION(d->lldi->adapter_type) > CHELSIO_T4) {
		memset(&rpl5->iss, 0, roundup(sizeof(*rpl5)-sizeof(*rpl), 16));
		if (iph->version == 0x4)
			rpl5->iss =
				cpu_to_be32((secure_tcp_sequence_number_offload(
					inet_sk(sk)->inet_daddr,
				 	inet_sk(sk)->inet_saddr,
				 	inet_sk(sk)->inet_dport,
				 	inet_sk(sk)->inet_sport) & ~7U) - 1);
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		else
			rpl5->iss =
				cpu_to_be32((secure_tcpv6_sequence_number(
				 	ipv6_hdr(skb)->daddr.s6_addr32,
				 	ipv6_hdr(skb)->saddr.s6_addr32,
				 	inet_sk(sk)->inet_dport,
				 	inet_sk(sk)->inet_sport) & ~7U) - 1);
#endif
		/* TODO */
		//if (is_t6(d->lldi->adapter_type))
		//	rpl5->opt3 = ?;
	}

	set_wr_txq(reply_skb, CPL_PRIORITY_SETUP, cplios->port_id);
	cxgb4_sk_l2t_send(cplios->egress_dev, reply_skb, e, sk);
	kfree_skb(skb);
	return;

defer:
	mk_tid_release(reply_skb, 0, tid);
	cxgb4_ofld_send(tdev->lldev[0], reply_skb);
	skb->dev = d->egr_dev[G_SYN_INTF(ntohs(req->l2info))];
	__skb_pull(skb, sizeof(*req));
	skb_reset_mac_header(skb);
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->protocol = eth_type_trans(skb, skb->dev);
	t4_defer_reply(skb, tdev, send_deferred_tnl);
	return;

reject:
	mk_tid_release(reply_skb, 0, tid);
	cxgb4_ofld_send(tdev->lldev[0], reply_skb);
	kfree_skb(skb);
out:
	T4_TCP_INC_STATS_BH(sock_net(sk), TCP_MIB_ATTEMPTFAILS);
}

/*
 * Handle a CPL_PASS_ACCEPT_REQ message.
 */
static int do_pass_accept_req(struct tom_data *td, struct sk_buff *skb)
{
        struct cpl_pass_accept_req *req = cplhdr(skb);
        unsigned int stid = G_PASS_OPEN_TID(ntohl(req->tos_stid));
	unsigned int tid = GET_TID(req);
	void *data;
	struct listen_ctx *ctx;
	struct sock *lsk;

	data = lookup_stid(td->tids, stid);
	if (!data) {
		printk(KERN_ERR "%s: PASS_ACCEPT_REQ had unknown STID %u\n", td->tdev.name, stid);
		return CPL_RET_UNKNOWN_TID | CPL_RET_BUF_DONE;
	}
	ctx = (struct listen_ctx *)data;
	lsk = ctx->lsk;

#if VALIDATE_TID
	if (unlikely(tid >= td->tids->ntids)) {
		printk(KERN_ERR "%s: passive open TID %u too large\n",
		       td->tdev.name, tid);
		return CPL_RET_BUF_DONE;
	}
#endif

	BLOG_SKB_CB(skb)->dev = &td->tdev;
	process_cpl_msg(process_pass_accept_req, lsk, skb);
	return 0;
}

static void build_cpl_pass_accept_req(struct sk_buff *skb, int stid , u8 tos,
				      enum chip_type type)
{
	u32 l2info;
	u16 vlantag, len, hdr_len, eth_hdr_len;
	u8 intf;
	struct cpl_rx_pkt *cpl = cplhdr(skb);
	struct cpl_pass_accept_req *req;
	struct tcp_options_received tmp_opt;
	u8 *hash_location;

	/* Store values from cpl_rx_pkt in temporary location. */
	vlantag = cpl->vlan;
	len = cpl->len;
	l2info  = cpl->l2info;
	hdr_len = cpl->hdr_len;
	intf = cpl->iff;

	__skb_pull(skb , sizeof(struct cpl_pass_accept_req));

	/* We need to parse the TCP options from SYN packet.
	 * to generate cpl_pass_accept_req.
	 */
	memset(&tmp_opt, 0, sizeof tmp_opt);
	tcp_clear_options(&tmp_opt);
	t4_tcp_parse_options(skb, &tmp_opt, &hash_location, 0);

	req = (struct cpl_pass_accept_req *)__skb_push(skb, sizeof(*req));
	memset(req, 0, sizeof(*req));
	req->l2info = cpu_to_be16(V_SYN_INTF(intf) |
			 V_SYN_MAC_IDX(G_RX_MACIDX(htonl(l2info))) | F_SYN_XACT_MATCH);

	if (CHELSIO_CHIP_VERSION(type) <= CHELSIO_T5) {
		eth_hdr_len = is_t4(type) ? G_RX_ETHHDR_LEN(htonl(l2info)) :
					    G_RX_T5_ETHHDR_LEN(htonl(l2info));
		req->hdr_len = cpu_to_be32(V_SYN_RX_CHAN(G_RX_CHAN(htonl(l2info))) |
						V_TCP_HDR_LEN(G_RX_TCPHDR_LEN(htons(hdr_len))) |
						V_IP_HDR_LEN(G_RX_IPHDR_LEN(htons(hdr_len))) |
						V_ETH_HDR_LEN(eth_hdr_len));
	} else { /* T6 and later */
		eth_hdr_len = G_RX_T6_ETHHDR_LEN(htonl(l2info));
		req->hdr_len = cpu_to_be32(V_SYN_RX_CHAN(G_RX_CHAN(htonl(l2info))) |
						V_T6_TCP_HDR_LEN(G_RX_TCPHDR_LEN(htons(hdr_len))) |
						V_T6_IP_HDR_LEN(G_RX_IPHDR_LEN(htons(hdr_len))) |
						V_T6_ETH_HDR_LEN(eth_hdr_len));
	}
	req->vlan = vlantag;
	req->len = len;
	req->tos_stid = cpu_to_be32(V_PASS_OPEN_TID(stid) | V_PASS_OPEN_TOS(tos));
	req->tcpopt.mss = htons(tmp_opt.mss_clamp);
	if (tmp_opt.wscale_ok)
		req->tcpopt.wsf = tmp_opt.snd_wscale;
	req->tcpopt.tstamp = tmp_opt.saw_tstamp;
	if (tmp_opt.sack_ok)
		req->tcpopt.sack = 1;
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_PASS_ACCEPT_REQ, 0));

	return;
}

/*
 * Handler for CPL_RX_PKT message. Need to handle cpl_rx_pkt
 * messages when a filter is being used instead of server to
 * redirect a syn packet. When packets hit filter they are redirected
 * to the offload queue and driver tries to establish the connection
 * using firmware work request.
 */
static int do_rx_pkt(struct tom_data *td, struct sk_buff *skb)
{
	int stid;
	unsigned int filter;
	struct ethhdr *eh;
	struct vlan_ethhdr *vlan_eh = NULL;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct request_sock *oreq = NULL;
	struct cpl_rx_pkt *cpl = cplhdr(skb);
	struct cpl_pass_accept_req *req = cplhdr(skb);
	struct toedev *tdev = &td->tdev;
	struct toe_hash_params hash_params;
	struct listen_ctx *ctx;
	struct sock *lsk;
	struct l2t_entry *e;
	struct dst_entry *dst=NULL;
	struct net_device *egress;
	struct cpl_io_state cplios;
	void *data;
	u8 tos = 0;
	u16 window, eth_hdr_len;
	struct neighbour *neigh = NULL;

	int iff = cpl->iff;
	skb->dev = td->egr_dev[iff];

	/* Tunnel all non-SYN packets */
	if (!(cpl->l2info & cpu_to_be32(F_RXF_SYN)))
		goto reject;

	/* Tunnel all packet which did not hit the filter.
	 * Unlikely to happen.
	 */
	if (!(cpl->rss_hdr.filter_hit && cpl->rss_hdr.filter_tid))
		goto reject;

	/*
	 * Ignore new connection request (as of now) if we are in middle
	 * of shutdown
	 */
	rcu_read_lock();
	if (rcu_access_pointer(tdev->in_shutdown)) {
		rcu_read_unlock();
		dev_kfree_skb(skb);
		return 0;
	}
	rcu_read_unlock();

	/* Calculate the server tid from filter hit index from cpl_rx_pkt.
	 */
	stid = cpu_to_be32(cpl->rss_hdr.hash_val);

	data = lookup_stid(td->tids, stid);
	if (!data) {
		printk(KERN_ERR "%s: do_rx_pkt had unknown STID %u\n", td->tdev.name, stid);
		goto reject;
	}
	ctx = (struct listen_ctx *)data;
	lsk = ctx->lsk;

	if (CHELSIO_CHIP_VERSION(td->lldi->adapter_type) <= CHELSIO_T5)
		eth_hdr_len = is_t4(td->lldi->adapter_type) ?
					G_RX_ETHHDR_LEN(htonl(cpl->l2info)) :
					G_RX_T5_ETHHDR_LEN(htonl(cpl->l2info));
	else /* T6 and later */
		eth_hdr_len = G_RX_T6_ETHHDR_LEN(htonl(cpl->l2info));

	if (eth_hdr_len == ETH_HLEN) {
		eh = (struct ethhdr *)(req + 1);
		iph = (struct iphdr *)(eh + 1);
		if (cpl->vlan_ex)
			__vlan_hwaccel_put_ctag(skb, ntohs(cpl->vlan));
		else
			cpl->vlan = htons(CPL_L2T_VLAN_NONE);
	} else {
		vlan_eh = (struct vlan_ethhdr *)(req + 1);
		iph = (struct iphdr *)(vlan_eh + 1);
		skb->vlan_tci = ntohs(vlan_eh->h_vlan_TCI);
		cpl->vlan = vlan_eh->h_vlan_TCI;
	}
	BUG_ON(iph->version != 0x4);
	tos  = iph->tos;
	tcph = (struct tcphdr *)(iph + 1);
	skb_set_network_header(skb, (void *)iph - (void *)req);
	skb_set_transport_header(skb, (void *)tcph - (void *)req);

	oreq = inet_reqsk_alloc(&t4_rsk_ops, lsk);
	if (!oreq)
		goto reject;

	window = htons(tcph->window);
	tcp_rsk(oreq)->rcv_isn = ntohl(tcph->seq);
	t4_set_req_port(oreq, tcph->source, tcph->dest);
	t4_set_req_addr(oreq, iph->daddr, iph->saddr);
	t4_set_req_opt(oreq, NULL);

	dst = route_req(lsk, oreq);
	if (!dst)
		goto free_or;
	neigh = t4_dst_neigh_lookup(dst, &inet_sk(lsk)->inet_daddr);
	if (!neigh) {
		printk(KERN_INFO "%s: dst->_neighbour is NULL\n", __func__);
		goto free_dst;
	}

	memset(&cplios, 0, sizeof(struct cpl_io_state));
	if (neigh) {
		init_toe_hash_params(&hash_params, neigh->dev, neigh,
				     iph->saddr, iph->daddr, tcph->source,
				     tcph->dest, NULL, NULL, false, IPPROTO_TCP);
		egress = offload_get_phys_egress(&hash_params, TOE_OPEN);
		if (!egress || !netdev_is_offload(egress) ||
		    (TOEDEV(egress) != tdev)) {
			t4_dst_neigh_release(neigh);
			goto free_dst;
		}

		cplios.toedev = tdev;
		cplios.egress_dev = egress;

		ma_fail_do_rx_pkt_init(&cplios);

		e = cxgb4_l2t_get(td->lldi->l2t, neigh, egress , lsk->sk_priority);
		t4_dst_neigh_release(neigh);
		if (!e)
			goto free_dst;
	} else {
		printk(KERN_INFO "do_rx_pkt: dst->_neighbour is NULL\n");
		goto free_dst;
	}
	/* Calcuate filter portion for LE region. */
	filter = cpu_to_be32(cxgb4_select_ntuple(cplios.egress_dev, e));

	/* Synthesize cpl_pass_accept_req. We have everything except the TID.
	 * Once firmware sends a reply with TID we update the TID field in cpl
	 * and pass it through regular cpl_pass_accept_req process in driver.
	 */
	build_cpl_pass_accept_req(skb, stid, tos, td->lldi->adapter_type);

	if (mk_fw_pass_open_req(td, skb, oreq, filter, window, e, &cplios) < 0)
		goto free_l2t;

	cxgb4_l2t_release(e);
	dst_release(dst);
	t4_reqsk_free(oreq);
	return 0;

free_l2t:
	cxgb4_l2t_release(e);
free_dst:
	dst_release(dst);
free_or:
	t4_reqsk_free(oreq);
reject:
	if (ma_fail_do_rx_pkt(td, skb))
		return 0;

	__skb_pull(skb , sizeof(struct cpl_pass_accept_req));
	skb_reset_mac_header(skb);
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->protocol = eth_type_trans(skb, skb->dev);
	if (unlikely(cpl->vlan_ex))
		__vlan_hwaccel_put_ctag(skb, ntohs(cpl->vlan));
	netif_receive_skb(skb);
	return 0;
}

/*
 * Add a passively open socket to its parent's accept queue.  Note that the
 * child may be in any state by now, including TCP_CLOSE.  We can guarantee
 * though that it has not been orphaned yet.
 */
static void add_pass_open_to_parent(struct sock *child, struct sock *lsk,
				    struct toedev *dev)
{
	struct request_sock *oreq;

	/*
	 * If the server is closed it has already killed its embryonic
	 * children.  There is nothing further to do about child.
	 */
	if (lsk->sk_state != TCP_LISTEN)
		return;

	oreq = CPL_IO_STATE(child)->passive_reap_next;
	CPL_IO_STATE(child)->passive_reap_next = NULL;

	reqsk_queue_removed(&inet_csk(lsk)->icsk_accept_queue, oreq);
	synq_remove(child);

	if (sk_acceptq_is_full(lsk) && !TOM_TUNABLE(dev, soft_backlog_limit)) {
		T4_NET_INC_STATS_BH(sock_net(lsk), LINUX_MIB_LISTENOVERFLOWS);
		T4_NET_INC_STATS_BH(sock_net(lsk), LINUX_MIB_LISTENDROPS);
		t4_reqsk_free(oreq);
		add_to_reap_list(child);
	} else {
		inet_csk_reqsk_queue_add(lsk, oreq, child);
		sk_data_ready_compat(lsk, 0);
	}
}

/*
 * This is run from a listener's backlog to add a child socket to its accept
 * queue.  Note that at this point the child is not locked and we intentionally
 * do not bother locking it as the only fields we may be using are
 * sk_user_data, and the open request and there aren't any concurrent users
 * for them.
 */
static void bl_add_pass_open_to_parent(struct sock *lsk, struct sk_buff *skb)
{
	struct sock *child = skb->sk;

	skb->sk = NULL;
	add_pass_open_to_parent(child, lsk, BLOG_SKB_CB(skb)->dev);
	kfree_skb(skb);
}

/*
 * Called when a connection is established to translate the TCP options
 * reported by HW to Linux's native format.
 */
static void assign_rxopt(struct sock *sk, unsigned int opt)
{
	const struct tom_data *d;
	struct tcp_sock *tp = tcp_sk(sk);
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	d = TOM_DATA(cplios->toedev);

	MSS_CLAMP(tp)	      = d->mtus[G_TCPOPT_MSS(opt)] - 40;
	tp->mss_cache         = MSS_CLAMP(tp);
	tp->tcp_header_len    = sizeof(struct tcphdr);
	TSTAMP_OK(tp)         = G_TCPOPT_TSTAMP(opt);
	SACK_OK(tp)           = G_TCPOPT_SACK(opt);
	WSCALE_OK(tp)         = G_TCPOPT_WSCALE_OK(opt);
	SND_WSCALE(tp)        = G_TCPOPT_SND_WSCALE(opt);
	if (!WSCALE_OK(tp))
		RCV_WSCALE(tp) = 0;
	if (TSTAMP_OK(tp)) {
		tp->tcp_header_len += TCPOLEN_TSTAMP_ALIGNED;
		tp->mss_cache -= TCPOLEN_TSTAMP_ALIGNED;
	} else if (cplios->opt2 & F_TSTAMPS_EN) {
		cplios->opt2 &= ~F_TSTAMPS_EN;
		cplios->mtu_idx = G_TCPOPT_MSS(opt);
	}
}

/*
 * Completes some final bits of initialization for just established connections
 * and changes their state to TCP_ESTABLISHED.
 *
 * snd_isn here is the ISN after the SYN, i.e., the true ISN + 1.
 */
static void make_established(struct sock *sk, u32 snd_isn, unsigned int opt)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tp->pushed_seq = tp->write_seq = tp->snd_nxt = tp->snd_una = snd_isn;
	inet_sk(sk)->inet_id = tp->write_seq ^ jiffies;
	assign_rxopt(sk, opt);

	/*
	 * Causes the first RX_DATA_ACK to supply any Rx credits we couldn't
	 * pass through opt0.
	 */
	if (tp->rcv_wnd > (M_RCV_BUFSIZ << 10))
		tp->rcv_wup -= tp->rcv_wnd - (M_RCV_BUFSIZ << 10);

	dst_confirm(sk->sk_dst_cache);

	/*
	 * tcp_poll() does not lock socket, make sure initial values are
	 * committed before changing to ESTABLISHED.
	 */
	smp_mb();
	tcp_set_state(sk, TCP_ESTABLISHED);
}

/*
 * Process a CPL_PASS_ESTABLISH message.  XXX a lot of the locking doesn't work
 * if we are in TCP_SYN_RECV due to crossed SYNs
 */
static int do_pass_establish(struct tom_data *td, struct sk_buff *skb)
{
	struct cpl_pass_establish *req = cplhdr(skb);
	struct sock *lsk, *sk;
	struct toedev *tdev;
        unsigned int hwtid = GET_TID(req);

        sk = lookup_tid(td->tids, hwtid);

	VALIDATE_SOCK(sk);

	bh_lock_sock(sk);
	if (unlikely(sock_owned_by_user(sk))) {
		// This can only happen in simultaneous opens.  XXX TBD
		kfree_skb(skb);
	} else {
		// Complete socket initialization now that we have the SND_ISN
		void *data;
		unsigned int stid;
		struct cpl_io_state *cplios = CPL_IO_STATE(sk);

		tdev = cplios->toedev;
		cplios->wr_max_credits = cplios->wr_credits =
			min_t(unsigned int, td->max_wr_credits,
				TOM_TUNABLE(tdev, max_wr_credits));
		cplios->wr_unacked = 0;
		make_established(sk, ntohl(req->snd_isn), ntohs(req->tcp_opt));

		stid = G_PASS_OPEN_TID(ntohl(req->tos_stid));
#ifdef WD_TOE
		/*
		 * Once the connection established, we can mark the entry
		 * in the passive table not used any more
		 */
		wdtoe_remove_passive_conn_tuple(passive_conn_tuple, stid, hwtid);
#endif
		sk->sk_state_change(sk);
		if (unlikely(sk->sk_socket)) {   // simultaneous opens only
			sk_wake_async(sk, 0, POLL_OUT);
		}

		/*
		 * The state for the new connection is now up to date.
		 * Next check if we should add the connection to the parent's
		 * accept queue.  When the parent closes it resets connections
		 * on its SYN queue, so check if we are being reset.  If so we
		 * don't need to do anything more, the coming ABORT_RPL will
		 * destroy this socket.  Otherwise move the connection to the
		 * accept queue.
		 *
		 * Note that we reset the synq before closing the server so if
		 * we are not being reset the stid is still open.
		 */
		if (unlikely(synq_empty(sk))) {
			/* removed from synq */
			kfree_skb(skb);
			goto unlock;
		}

		data = lookup_stid(td->tids, stid);
		lsk = ((struct listen_ctx *)data)->lsk;

		bh_lock_sock(lsk);
		if (likely(!sock_owned_by_user(lsk))) {
			kfree_skb(skb);
			add_pass_open_to_parent(sk, lsk, tdev);
		} else {
			skb->sk = sk;
			BLOG_SKB_CB(skb)->dev = tdev;
			BLOG_SKB_CB(skb)->backlog_rcv = bl_add_pass_open_to_parent;
			__sk_add_backlog(lsk, skb);
		}
		bh_unlock_sock(lsk);
	}
unlock:
	bh_unlock_sock(sk);
	return 0;
}

#define __FIXUP_WR_MIT_CPL(w, cpl, tid) do { \
        (w)->wr.wr_mid = \
	htonl(V_FW_WR_LEN16(G_FW_WR_LEN16(ntohl((w)->wr.wr_mid))) | \
	V_FW_WR_FLOWID(tid)); \
        OPCODE_TID(w) = htonl(MK_OPCODE_TID(cpl, tid)); \
} while (0)

#define __FIXUP_FLOWC_WR(flowc, tid) do { \
	(flowc)->flowid_len16 = \
	htonl(V_FW_WR_LEN16(G_FW_WR_LEN16(ntohl((flowc)->flowid_len16))) | \
	V_FW_WR_FLOWID(tid)); \
} while(0)

/*
 * Fill in the right TID for CPL messages waiting in the out-of-order queue
 * and send them to the TOE.
 */
static void fixup_and_send_ofo(struct sock *sk, unsigned int tid)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct sk_buff *skb;
	struct tcp_sock *tp = tcp_sk(sk);

	while ((skb = __skb_dequeue(&tp->out_of_order_queue)) != NULL) {
		struct fw_flowc_wr *flowc = cplhdr(skb);
		struct cpl_close_con_req *p = cplhdr(skb);

		if (G_FW_WR_OP(ntohl(flowc->op_to_nparams)) == FW_FLOWC_WR)
			__FIXUP_FLOWC_WR(flowc, tid);
		else
			__FIXUP_WR_MIT_CPL(p, p->ot.opcode, tid);
		cxgb4_ofld_send(cplios->egress_dev, skb);
	}
}

/*
 * Adjust buffers already in write queue after a SYN_SENT->ESTABLISHED
 * transition.  For TX_DATA we need to adjust the start sequence numbers, and
 * for other packets we need to adjust the TID.  TX_DATA packets don't have
 * headers yet and so not TIDs.
 */
static void fixup_pending_writeq_buffers(struct sock *sk)
{
	struct sk_buff *skb;
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int tid = cplios->tid;

	skb_queue_walk(&cplios->tx_queue, skb) {
		if (ULP_SKB_CB(skb)->flags & ULPCB_FLAG_NEED_HDR) {
			ULP_SKB_CB(skb)->seq = tp->write_seq;
			tp->write_seq += skb->len + ulp_extra_len(skb) +
						skb_ulp_len_adjust(skb);
		} else {
			struct cpl_close_con_req *p = cplhdr(skb);

			__FIXUP_WR_MIT_CPL(p, p->ot.opcode, tid);
		}
	}
}

/*
 * Updates socket state from an active establish CPL message.  Runs with the
 * socket lock held.
 */
static void sock_act_establish(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct cpl_act_establish *req = cplhdr(skb);
	u32 rcv_isn = ntohl(req->rcv_isn);	/* real RCV_ISN + 1 */
	struct tcp_sock *tp = tcp_sk(sk);

	if (unlikely(sk->sk_state != TCP_SYN_SENT))
		printk(KERN_ERR "TID %u expected SYN_SENT, found %d\n",
		       cplios->tid, sk->sk_state);

	tp->rcv_tstamp = tcp_time_stamp;
	cplios->delack_seq = tp->copied_seq = tp->rcv_wup = tp->rcv_nxt = rcv_isn;
	make_established(sk, ntohl(req->snd_isn), ntohs(req->tcp_opt));

#ifdef CONFIG_SECURITY_NETWORK
	security_inet_conn_estab(sk, tcphdr_skb);
#endif

	/*
	 * Now that we finally have a TID send any CPL messages that we had to
	 * defer for lack of a TID.
	 */
	if (skb_queue_len(&tp->out_of_order_queue))
		fixup_and_send_ofo(sk, cplios->tid);

	if (likely(!sock_flag(sk, SOCK_DEAD))) {
		sk->sk_state_change(sk);
		sk_wake_async(sk, 0, POLL_OUT);
	}

	kfree_skb(skb);

	/*
	 * Currently the send queue must be empty at this point because the
	 * socket layer does not send anything before a connection is
	 * established.  To be future proof though we handle the possibility
	 * that there are pending buffers to send (either TX_DATA or
	 * CLOSE_CON_REQ).  First we need to adjust the sequence number of the
	 * buffers according to the just learned write_seq, and then we send
	 * them on their way.
	 */
	fixup_pending_writeq_buffers(sk);
	if (t4_push_frames(sk, 1))
		sk->sk_write_space(sk);
}

/*
 * Process a CPL_ACT_ESTABLISH message.
 */
static int do_act_establish(struct tom_data *td, struct sk_buff *skb)
{
	struct cpl_act_establish *req = cplhdr(skb);
	unsigned int tid = GET_TID(req);
	unsigned int atid = G_TID_TID(ntohl(req->tos_atid));
	struct sock *sk;
	struct cpl_io_state *cplios;
	struct toedev *tdev;

	sk = lookup_tid(td->tids, tid);
	if (sk) {
		/*
		 * If socket associated with this tid is already waiting for
		 * CPL_ABORT_RPL i.e. connection is going away anyways then,
		 * this CPL_ACT_ESTABLISH has likely arrived late in the game.
		 * We can ignore this CPL_ACT_ESTABLISH assuming that CPL_ABORT_RPL
		 * will arrive and subsequent necessary clean-up would occur.
		 *
		 * The only known sceanrio for this as of now is:
		 * socket was associated with this tid in neg. advice from CPL_ACT_OPEN_RPL
		 * so as to send CPL_ABORT_REQ on correct tid and subsequently
		 * process the CPL_ABORT_RPL.
		 */
		if (sk->sk_state == TCP_SYN_SENT &&
		    cplios_flag(sk, CPLIOS_ABORT_RPL_PENDING))
			return 0;

		printk(KERN_ERR "%s: tid (%d) already in use, sk_state = %d\n",
				__func__, tid, sk->sk_state);
		return CPL_RET_UNKNOWN_TID | CPL_RET_BUF_DONE;
	}

	cplios = (struct cpl_io_state *)lookup_atid(td->tids, atid);
	VALIDATE_SOCK(cplios);
	sk = cplios->sk;
	tdev = cplios->toedev;

	/*
	 * It's OK if the TID is currently in use, the owning socket may have
	 * backlogged its last CPL message(s).  Just take it away.
	 */
	cplios->tid = tid;
	cxgb4_insert_tid(td->tids, sk, tid, sk->sk_family);
	cxgb4_free_atid(td->tids, atid);
	kref_put(&cplios->kref, t4_cplios_release);

#ifdef WD_TOE
	/* once the active connection is established, we delete the entry */
	wdtoe_remove_conn_tuple(conn_tuple, atid);
#endif

	process_cpl_msg(sock_act_establish, sk, skb);
	return 0;
}

#define S_CPL_FW4_ACK_FLOWID    0
#define M_CPL_FW4_ACK_FLOWID    0xffffff
#define V_CPL_FW4_ACK_FLOWID(x) ((x) << S_CPL_FW4_ACK_FLOWID)
#define G_CPL_FW4_ACK_FLOWID(x) \
    (((x) >> S_CPL_FW4_ACK_FLOWID) & M_CPL_FW4_ACK_FLOWID)
 
/*
 * Process an acknowledgment of WR completion.  Advance snd_una and send the
 * next batch of work requests from the write queue.
 */
static void wr_ack(struct sock *sk, struct sk_buff *skb)
{
        struct cpl_io_state *cplios = CPL_IO_STATE(sk);
        struct tcp_sock *tp = tcp_sk(sk);
        struct cpl_fw4_ack *hdr = (struct cpl_fw4_ack *)cplhdr(skb);
        u8 credits = hdr->credits;
        u32 snd_una = ntohl(hdr->snd_una);

        cplios->wr_credits += credits;

        /*
         * If the last write request in the queue with a request completion
         * flag has been consumed, reset our bookeepping.
         */
        if (cplios->wr_unacked > cplios->wr_max_credits - cplios->wr_credits)
                cplios->wr_unacked = cplios->wr_max_credits - cplios->wr_credits;

        while (credits) {
                struct sk_buff *p = peek_wr(sk);

                if (unlikely(!p)) {
#ifdef WD_TOE
			int ret;
			int dev_idx = 0;
			int tbl_idx = 0;
			struct wdtoe_stack_info_entry *stack_info;

			ret = wdtoe_find_dev_by_tid(wdtoe_dev_table, 
							&dev_idx,
							&tbl_idx,
							cplios->tid);
			if(ret == 0) {
				/*
				printk(KERN_INFO "[wdtoe] WR_ACK [%u] for TID"
						"[%u] for WD-TOE connection"
						"dev_idx [%d]\n",
						credits, cplios->tid, dev_idx);
				*/

				stack_info = wdtoe_dev_table[dev_idx].wd_dev
								->k_stack_info;
				/* XXX need to replace with atomic operation */
				atomic_add(credits, 
				  &stack_info->conn_info[tbl_idx].cur_credits);
				/*
				printk(KERN_INFO "[wdtoe] returning credits "
						"[%u] for TID [%u], dev_idx "
						"[%d] tbl_idx [%d], "
						"cur_credits [%u]\n",
						credits, cplios->tid, 
						dev_idx, tbl_idx, 
						atomic_read(&stack_info->
						conn_info[tbl_idx].
						cur_credits));
				*/
				goto wdtoe_ack_out;
			}
#endif

                        printk(KERN_ERR "%u WR_ACK credits for TID %u with "
                               "nothing pending, state %u\n",
                               credits, cplios->tid, sk->sk_state);
#ifdef WD_TOE
wdtoe_ack_out:
#endif
                        break;
                }
                if (unlikely(credits < p->csum)) {
#if DEBUG_WR > 1
                        struct tx_data_wr *w = cplhdr(p);

                        printk(KERN_ERR
                               "TID %u got %u WR credits, need %u, len %u, "
                               "main body %u, seq # %u, ACK una %u,"
                               " ACK nxt %u, WR_AVAIL %u, WRs pending %u\n",
                               cplios->tid, credits, p->csum, p->len,
                               p->len - p->data_len,
                               ntohl(w->sndseq), snd_una, ntohl(hdr->snd_nxt),
                               cplios->wr_credits, count_pending_wrs(sk) - credits);
#endif
                        p->csum -= credits;
                        break;
                } else {
                        dequeue_wr(sk);
                        credits -= p->csum;
                        free_wr_skb(sk, p);
                }
        }

#if DEBUG_WR
        check_wr_invariants(sk);
#endif

        if (hdr->flags & CPL_FW4_ACK_FLAGS_SEQVAL) {
                if (unlikely(before(snd_una, tp->snd_una))) {
#if VALIDATE_SEQ
                        struct tom_data *d = TOM_DATA(cplios->toedev);

                        printk(KERN_ERR "%s: unexpected sequence # %x in WR_ACK "
                                "for TID %u, snd_una %x\n", (&d->tdev)->name, snd_una,
                                cplios->tid, tp->snd_una);
#endif
			kfree_skb(skb);
                        return;
                }

                if (tp->snd_una != snd_una) {
                        tp->snd_una = snd_una;
                        dst_confirm(sk->sk_dst_cache);
                        tp->rcv_tstamp = tcp_time_stamp;
                        if ((tp->snd_una == tp->snd_nxt) &&
                                !cplios_flag(sk, CPLIOS_TX_FAILOVER))
                                        cplios_reset_flag(sk, CPLIOS_TX_WAIT_IDLE);
                }

		ma_fail_wr_ack(sk);
	}

	if (hdr->flags & CPL_FW4_ACK_FLAGS_FLOWC) {
		if (cplios_flag(sk, CPLIOS_TX_FAILOVER)) {
			struct cpl_io_state *cplios = CPL_IO_STATE(sk);
			struct l2t_entry *e = cplios->l2t_entry;
			if ( cplios->tx_c_chan != e->lport)
				send_failover_flowc_wr(sk);
		}
	}

	if (hdr->flags & CPL_FW4_ACK_FLAGS_CH) {
			cplios_reset_flag(sk, CPLIOS_TX_WAIT_IDLE);
			cplios_reset_flag(sk, CPLIOS_TX_FAILOVER);
	}

        /*
         * If there's more data queued up, see if we can get it into the write
         * queue ...  If we're able to push any data into the write queue,
         * free up socket send buffer space.
         */
        if (skb_queue_len(&cplios->tx_queue) && t4_push_frames(sk, 0))
                sk->sk_write_space(sk);
	kfree_skb(skb);
}

#ifdef UDP_OFFLOAD
static void uo_wr_ack(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct cpl_fw4_ack *hdr = (struct cpl_fw4_ack *)cplhdr(skb);
	u8 credits = hdr->credits;

	if (!cplios) {
		kfree_skb(skb);
		return;
	}

	cplios->wr_credits += credits;

	/*
	 * If the last write request in the queue with a request completion
	 * flag has been consumed, reset our bookeepping.
	 */
	if (cplios->wr_unacked > cplios->wr_max_credits - cplios->wr_credits)
		cplios->wr_unacked = cplios->wr_max_credits - cplios->wr_credits;

	while (credits) {
		struct sk_buff *p = peek_wr(sk);

		if (unlikely(!p)) {
			printk(KERN_ERR "%u WR_ACK credits for TID %u with "
			"nothing pending, state %u\n",
			credits, cplios->tid, sk->sk_state);
			break;
		}
		if (unlikely(credits < p->csum)) {
			p->csum -= credits;
			break;
		} else {
			dequeue_wr(sk);
			credits -= p->csum;
			free_wr_skb(sk, p);
		}
	}

	if (cplios_flag(sk, CPLIOS_CLOSE_CON_REQUESTED) &&
				 cplios->wr_credits  == cplios->wr_max_credits) {
		cxgb4_free_uotid(TOM_DATA(cplios->toedev)->tids, cplios->tid);
		CPL_IO_STATE(sk) = NULL;
		kfree(cplios);
		sock_put(sk);
		kfree_skb(skb);
		return;
	}

	if (sk->sk_family == AF_INET) {
		if (skb_queue_len(&cplios->tx_queue) &&
			!t4_udp_push_frames(sk))
				sk->sk_write_space(sk);
	}
#ifdef CONFIG_UDPV6_OFFLOAD
	else if (sk->sk_family == AF_INET6) {
		if (skb_queue_len(&cplios->tx_queue) &&
			!chelsio_udp_v6_push_pending_frames(sk))
				sk->sk_write_space(sk);
	}
#endif /* CONFIG_UDPV6_OFFLOAD */

	kfree_skb(skb);
}
#endif

/*
 * Handler for TX_DATA_ACK CPL messages.
 */
static int do_fw4_ack(struct tom_data *td, struct sk_buff *skb)
{
	struct cpl_fw4_ack *rpl = (struct cpl_fw4_ack *)cplhdr(skb);
	struct sock *sk;
	unsigned int hwtid = G_CPL_FW4_ACK_FLOWID(ntohl(OPCODE_TID(rpl)));

#ifdef UDP_OFFLOAD
	if (hwtid >= td->tids->uotid_base) {
		sk = lookup_uotid(td->tids, hwtid);
		VALIDATE_SOCK(sk);
		skb_shinfo(skb)->gso_type = SKB_GSO_UDP;
		process_cpl_msg(uo_wr_ack, sk, skb);
		/*
		 * when the sk->sk_sndbuf limit is reached, the
		 * sock_alloc_send_skb will sleep for sndbuf. This need to
		 * be woke up as we will be freeing some skb as part this
		 * WR ACK handling
		 */
		if (sk_has_sleepers(sk)) {
			clear_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
			wake_up_interruptible(sk_sleep(sk));
		}
		return 0;
	}
#endif

	sk = lookup_tid(td->tids, hwtid);
	VALIDATE_SOCK(sk);
	process_cpl_msg (wr_ack, sk, skb);

	return 0;
}

#if 0
/*
 * Handler for TRACE_PKT CPL messages.  Just sink these packets.
 */
static int do_trace_pkt(struct tom_data *td, struct sk_buff *skb)
{
	__kfree_skb(skb);
	return 0;
}
#endif

/*
 * Disconnect offloaded established but not yet accepted connections sitting
 * on a server's accept_queue.  We just send an ABORT_REQ at this point and
 * finish off the disconnect later as we may need to wait for the ABORT_RPL.
 */
void t4_disconnect_acceptq(struct sock *listen_sk)
{
	struct request_sock **pprev;

	pprev = ACCEPT_QUEUE(listen_sk);
	while (*pprev) {
		struct request_sock *req = *pprev;

		if ((req->rsk_ops == RSK_OPS(&t4_rsk_ops)) ||
		    (req->rsk_ops == RSK_OPS(&t4_rsk6_ops))) {       // one of ours
			struct sock *child = req->sk;

			*pprev = req->dl_next;
			sk_acceptq_removed(listen_sk);
			t4_reqsk_free(req);
			sock_hold(child);      // need to survive past inet_csk_destroy_sock()
			local_bh_disable();
			bh_lock_sock(child);
			release_tcp_port(child);
			reset_listen_child(child);
			bh_unlock_sock(child);
			local_bh_enable();
			sock_put(child);
		} else
			pprev = &req->dl_next;
	}
}

/*
 * Reset offloaded connections sitting on a server's syn queue.  As above
 * we send ABORT_REQ and finish off when we get ABORT_RPL.
 */
void t4_reset_synq(struct sock *listen_sk)
{
	struct sock **nextsk = &synq_next(listen_sk);

	/*
	 * Note: the while predicate below is a little tricky because the
	 * fields used to implement the doubly linked list have been hijacked
	 * out of the (struct tcp_sock) portion of the socket.  If the fields
	 * were solely ours to use, then the test of "*nextsk != listen_sk"
	 * would be enough.  But when we empty the SYN queue, the state of
	 * those hijacked fields are reset to the values expected by Linux
	 * and "*nextsk" will no longer have any legitimate meaning for us.
	 * Thus the double predicate of testing for both the SYN queue being
	 * empty (which is implemented in a Linux version-dependent fashion)
	 * and making sure the next socket to process isn't our listen
	 * socket ...
	 */
	while (!synq_empty(listen_sk) && *nextsk != listen_sk) {
		struct sock *child = *nextsk;

		if ((child->sk_prot == &t4_tcp_prot.proto) ||
		    (child->sk_prot == &t4_tcp_v6_prot.proto)) {
			/* one of ours */
			cleanup_syn_rcv_conn(child, listen_sk);
			sock_hold(child);      // need to survive past inet_csk_destroy_sock()
			local_bh_disable();
			bh_lock_sock(child);
			release_tcp_port(child);
			reset_listen_child(child);
			bh_unlock_sock(child);
			local_bh_enable();
			sock_put(child);
		} else {
			/* some other offloaded socket ... */
			nextsk = &synq_next(*nextsk);
		}
	}
}

/* Maximum Immediate command memory write length is 256 bytes */
#define NUM_ULP_TX_SC_IMM_PPODS (256 / PPOD_SIZE)

int t4_setup_ppods(struct sock *sk, const struct ddp_gather_list *gl,
		   unsigned int nppods, unsigned int tag, unsigned int maxoff,
		   unsigned int pg_off, unsigned int color)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	unsigned int i, j, pidx;
	struct pagepod *p;
	struct sk_buff *skb;
	struct ulp_mem_io *req;
	struct ulptx_idata *sc;
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int tid = cplios->tid;
	const struct tom_data *td = TOM_DATA(cplios->toedev);
	unsigned int ppod_addr = tag * PPOD_SIZE + td->ddp_llimit;
	unsigned int len, podchunk;
	__be32 cmd = htonl(V_ULPTX_CMD(ULP_TX_MEM_WRITE));

	if (is_t4(td->lldi->adapter_type))
		cmd |= htonl(V_ULP_MEMIO_ORDER(1));
	else
		cmd |= htonl(V_T5_ULP_MEMIO_IMM(1));

	for (i = 0; i < nppods; ppod_addr += podchunk) {
		unsigned int ppodout = 0;

		podchunk = ((nppods-i) >= NUM_ULP_TX_SC_IMM_PPODS) ?
					  NUM_ULP_TX_SC_IMM_PPODS : (nppods-i);
		podchunk *= PPOD_SIZE;
		len = roundup(sizeof(*req) + 2*sizeof(*sc) + podchunk, 16);
		skb = alloc_ctrl_skb(cplios->ctrl_skb_cache, len);
		if (!skb)
			return -ENOMEM;

		set_wr_txq(skb, CPL_PRIORITY_CONTROL, cplios->port_id);
		req = (struct ulp_mem_io *)__skb_put(skb, len);
		INIT_ULPTX_WR(req, len, 0, 0);
		req->cmd = cmd;
		req->dlen = htonl(V_ULP_MEMIO_DATA_LEN(podchunk / 32));
		req->len16 = htonl(DIV_ROUND_UP(len-sizeof(req->wr), 16));
		req->lock_addr = htonl(V_ULP_MEMIO_ADDR(ppod_addr >> 5));
		sc = (struct ulptx_idata *)(req+1);
		sc->cmd_more = htonl(V_ULPTX_CMD(ULP_TX_SC_IMM));
		sc->len = htonl(podchunk);
		p = (struct pagepod *)(sc + 1);

		do {
			pidx = 4 * i;
			if (likely(i < nppods - NUM_SENTINEL_PPODS)) {
				p->vld_tid_pgsz_tag_color = 
					cpu_to_be64(F_PPOD_VALID | V_PPOD_TID(tid) |
						V_PPOD_TAG(tag) |
						V_PPOD_COLOR(color));
				p->len_offset = cpu_to_be64(V_PPOD_LEN(maxoff) | V_PPOD_OFST(pg_off));
				p->rsvd = 0;
				for (j = 0; j < 5; ++j, ++pidx)
					p->addr[j] = pidx < gl->nelem ?
				     		cpu_to_be64(gl->phys_addr[pidx]) : 0;
			} else
				p->vld_tid_pgsz_tag_color = 0;   /* mark sentinel page pods invalid */
			p++;
			ppodout += PPOD_SIZE;
			i++;
		} while (ppodout < podchunk);
		sc = (struct ulptx_idata *)p;
		sc->cmd_more = htonl(V_ULPTX_CMD(ULP_TX_SC_NOOP));
		sc->len = htonl(0);
		send_or_defer(sk, tp, skb, 0);
	}
	return 0;
}

/* 
 * Build a CPL_RX_DATA_ACK message as payload of a ULP_TX_PKT command.
 */
static void mk_rx_data_ack_ulp(struct sock *sk, struct cpl_rx_data_ack *ack,
			       unsigned int tid,
			       unsigned int credits)
{
	struct ulp_txpkt *txpkt = (struct ulp_txpkt *)ack;
	struct ulptx_idata *sc = (struct ulptx_idata *)(txpkt + 1);
	u32 dack;

	dack = t4_select_delack(sk);

	txpkt->cmd_dest = htonl(V_ULPTX_CMD(ULP_TX_PKT) | V_ULP_TXPKT_DEST(0));
	txpkt->len = htonl(DIV_ROUND_UP(sizeof(*ack), 16));
	sc->cmd_more = htonl(V_ULPTX_CMD(ULP_TX_SC_IMM));
	sc->len = htonl(sizeof(*ack) - sizeof(struct work_request_hdr));
	OPCODE_TID(ack) = htonl(MK_OPCODE_TID(CPL_RX_DATA_ACK, tid));
	ack->credit_dack = htonl(F_RX_MODULATE_RX | F_RX_DACK_CHANGE |
				 V_RX_DACK_MODE(dack) |
				 V_RX_CREDITS(credits));
	sc = (struct ulptx_idata *)(ack + 1);
	sc->cmd_more = htonl(V_ULPTX_CMD(ULP_TX_SC_NOOP));
	sc->len = htonl(0);
}

int t4_cancel_ddpbuf(struct sock *sk, unsigned int bufidx)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	unsigned int wrlen;
	struct sk_buff *skb;
	struct ulptx_idata *aligner;
	struct cpl_set_tcb_field *req;
	struct ddp_state *p = DDP_STATE(sk);
	u64 mask = V_TF_DDP_ACTIVE_BUF(1ULL) |
			V_TF_DDP_INDICATE_OUT(1ULL) |
			V_TF_DDP_BUF0_VALID(1ULL) |
			V_TF_DDP_BUF1_VALID(1ULL) |
			V_TF_DDP_BUF0_INDICATE(1ULL) |
			V_TF_DDP_BUF1_INDICATE(1ULL);

	/* DDP buffer 0 is only used for indicate size */
	BUG_ON(!bufidx);

	wrlen = roundup(sizeof(*req) + sizeof(*aligner), 16);

	skb = alloc_ctrl_skb(cplios->ctrl_skb_cache, wrlen);
	if (!skb)
		return -ENOMEM;

	__set_tcb_field(sk, skb, W_TCB_RX_DDP_FLAGS, mask,
			V_TF_DDP_ACTIVE_BUF(1ULL) | V_TF_DDP_INDICATE_OUT(1ULL),
			DDP_COOKIE_OFFSET, 0);

	p->get_tcb_count++;

	cxgb4_ofld_send(cplios->egress_dev, skb);

	return 0;
}

/*
 * Sends a compound WR containing all the CPL messages needed to program the
 * two HW DDP buffers, namely optionally setting up the length and offset of
 * each buffer, programming the DDP flags, and sending RX_DATA_ACK.
 */
int t4_setup_ddpbufs(struct sock *sk, unsigned int len0, unsigned int offset0,
		      unsigned int len1, unsigned int offset1,
		      u64 ddp_flags, u64 flag_mask)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	unsigned int wrlen;
	struct work_request_hdr *wr;
	struct ulptx_idata *aligner;
	struct cpl_set_tcb_field *req;
	struct cpl_rx_data_ack *ack;
	struct sk_buff *skb;

	if (ma_fail_t4_send_rx_credits(sk))
		return -EINVAL;

	wrlen = roundup(2*(sizeof(*req) + sizeof(*aligner)), 16);
	skb = alloc_ctrl_skb(cplios->ctrl_skb_cache, wrlen);
	if (!skb)
		return -ENOMEM;

	if (len0)
		t4_set_ddp_buf(sk, 0, offset0, len0);
	if (len1)
		t4_set_ddp_buf(sk, 1, offset1, len1);

	set_wr_txq(skb, CPL_PRIORITY_CONTROL, cplios->port_id);

	req = (struct cpl_set_tcb_field *)__skb_put(skb, wrlen);
	INIT_ULPTX_WR(req, wrlen, 0, 0);

        wr = (struct work_request_hdr *)req;
        wr++;
        req = (struct cpl_set_tcb_field *)wr;
	mk_set_tcb_field_ulp(cplios, req, W_TCB_RX_DDP_FLAGS, flag_mask,
			     ddp_flags, 0, 1);

	aligner = (struct ulptx_idata *)(req + 1);
	ack = (struct cpl_rx_data_ack *)(aligner + 1);
	mk_rx_data_ack_ulp(sk, ack, cplios->tid, 0);

	cxgb4_ofld_send(cplios->egress_dev, skb);

	return 0;
}

/*
 * Sends a compound WR containing all the CPL messages needed to program the
 * the DDP indicate, and sending RX_DATA_ACK.
 */
void t4_setup_indicate_modrx(struct sock *sk)
{
        struct cpl_io_state *cplios = CPL_IO_STATE(sk);
        struct tcp_sock *tp = tcp_sk(sk);
        unsigned int wrlen;
        struct work_request_hdr *wr;
        struct ulp_txpkt *txpkt;
        struct ulptx_idata *sc;
        struct cpl_set_tcb_field *req;
        struct cpl_rx_data_ack *ack;
        struct sk_buff *skb;

	if (ma_fail_t4_send_rx_credits(sk))
		return;

        wrlen = sizeof(*wr) +
                sizeof(*txpkt) + sizeof(*sc) + (sizeof(*req) - sizeof(*wr)) +
                (sizeof(*txpkt) + sizeof(*sc) + sizeof(*ack));
        skb = alloc_ctrl_skb(cplios->ctrl_skb_cache, wrlen);
	BUG_ON(!skb);
        set_wr_txq(skb, CPL_PRIORITY_CONTROL, cplios->port_id);

        req = (struct cpl_set_tcb_field *)__skb_put(skb, wrlen);
        INIT_ULPTX_WR(req, wrlen, 0, 0);

        wr = (struct work_request_hdr *)req;
        wr++;
        req = (struct cpl_set_tcb_field *)wr;
        mk_set_tcb_field_ulp(cplios, req, W_TCB_RX_DDP_FLAGS, V_TF_DDP_INDICATE_OUT(1ULL) |
                                V_TF_DDP_BUF0_VALID(1ULL) | V_TF_DDP_BUF1_VALID(1ULL) |
                                V_TF_DDP_BUF0_INDICATE(1ULL) | V_TF_DDP_BUF1_INDICATE(1ULL),
                             V_TF_DDP_BUF0_INDICATE(1ULL), DDP_COOKIE_INDOUT, 0);

	sc = (struct ulptx_idata *)(req + 1);
	ack = (struct cpl_rx_data_ack *)(sc + 1);
	mk_rx_data_ack_ulp(sk, ack, cplios->tid,
		tp->copied_seq - tp->rcv_wup);
	tp->rcv_wup = tp->copied_seq;

        cxgb4_ofld_send(cplios->egress_dev, skb);
}

/*
 * Handler for CPL_FW6_MSG.
 */
static int do_fw6_msg(struct tom_data *td, struct sk_buff *skb)
{
	struct cpl_io_state *cplios;
	struct sock *sk;
	struct cpl_fw6_msg *p = cplhdr(skb);

	if (p->type == FW6_TYPE_OFLD_CONNECTION_WR_RPL) {
		struct cpl_fw6_msg_ofld_connection_wr_rpl *req =
			(struct cpl_fw6_msg_ofld_connection_wr_rpl *)p->data;
		if (req->t_state == TCP_SYN_SENT && (req->retval == FW_ENOMEM ||
					req->retval == FW_EADDRINUSE)) {
			cplios = lookup_atid(td->tids, htonl(req->tid));
			VALIDATE_SOCK(cplios);
			skb->sk = cplios->sk;
			t4_defer_reply(skb, cplios->toedev,
				       deferred_tnl_connect);
			return 0;
		} else if(req->t_state == TCP_SYN_SENT && req->retval == FW_SUCCESS) {
			unsigned long atid = (unsigned long)req->cookie;
			cplios = lookup_atid(td->tids, atid);
			VALIDATE_SOCK(cplios);
			ma_fail_do_fw6_msg(cplios->sk, skb);
			return 0;
		} else if (req->t_state == TCP_SYN_RECV) {
			struct sk_buff *rpl_skb;
			struct cpl_pass_accept_req *cpl;
			rpl_skb = (struct sk_buff *)(uintptr_t)be64_to_cpu(req->cookie);
			if (req->retval == FW_EADDRINUSE) {
				__kfree_skb(rpl_skb);
			} else if (req->retval == FW_ENOMEM) {
				__skb_pull(rpl_skb, sizeof(*cpl));
				skb_reset_mac_header(rpl_skb);
				rpl_skb->ip_summed = CHECKSUM_UNNECESSARY;
				rpl_skb->protocol = eth_type_trans(rpl_skb, rpl_skb->dev);
				netif_receive_skb(rpl_skb);
			} else {
				unsigned int stid;
				struct listen_ctx *ctx;
				struct sock *lsk;
				cpl = (struct cpl_pass_accept_req *)cplhdr(rpl_skb);
				OPCODE_TID(cpl) =
					 htonl(MK_OPCODE_TID(CPL_PASS_ACCEPT_REQ,
									 htonl(req->tid)));
				stid = G_PASS_OPEN_TID(ntohl(cpl->tos_stid));
				ctx = (struct listen_ctx *)lookup_stid(td->tids, stid);
				if (ctx) {
					lsk = ctx->lsk;
					BLOG_SKB_CB(rpl_skb)->dev = &td->tdev;
					process_cpl_msg(process_pass_accept_req, lsk, rpl_skb);
				} else {
					cxgb4_remove_tid(td->tids, 0, htonl(req->tid),
							 AF_INET);
					__kfree_skb(rpl_skb);
				}
			}
		}
	} else if (p->type == FW_TYPE_PI_ERR) {

		/* iscsi needs it */
		struct fw_pi_error *pi_err = (struct fw_pi_error *)p->data;
		unsigned int tid = G_FW_WR_FLOWID(ntohl(pi_err->flowid_len16));

        	sk = lookup_tid(td->tids, tid);

		if (!t4_cpl_iscsi_callback(td, sk, skb, CPL_FW6_MSG))
			return 0;
	}
	kfree_skb(skb);
	return 0;
}

static int lro_init_desc(struct napi_struct *napi, const struct pkt_gl *gl,
			 struct sock *sk, unsigned int tid, const __be64 *rsp)
{
	struct sk_buff *skb;
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);

	skb = cxgb4_pktgl_to_skb(napi, gl, RX_PULL_LEN, RX_PULL_LEN);
	if (unlikely(!skb))
		return -1;

	/* Copy RSS header */
	__skb_push(skb, sizeof(struct rss_header));
	skb_copy_to_linear_data(skb, rsp, sizeof(struct rss_header));

	cplios->lro_skb = skb;
	sock_hold(sk);
	skb->sk = sk;
	return 0;
}

static void lro_add_packet(struct sk_buff *skb,
			   const struct pkt_gl *gl)
{
	struct skb_shared_info *ssi;
	int nr_frags = skb_shinfo(skb)->nr_frags;
	int cpl_hdr_size = sizeof(struct cpl_tx_data);

	/* Append the data to the skb frags */
	ssi = skb_shinfo(skb);
	skb_frag_set_page(skb, nr_frags, gl->frags[0].page);
	ssi->frags[nr_frags].page_offset = gl->frags[0].offset +
					   cpl_hdr_size;
	ssi->frags[nr_frags].size = gl->frags[0].size - cpl_hdr_size;
	if (gl->nfrags > 1)
		memcpy(&ssi->frags[nr_frags + 1], &gl->frags[1],
		       (gl->nfrags - 1) * sizeof(skb_frag_t));
	ssi->nr_frags += gl->nfrags;

	skb->len += gl->tot_len - cpl_hdr_size;
	skb->data_len += gl->tot_len - cpl_hdr_size;
	skb->truesize += gl->tot_len - cpl_hdr_size;

	/* Get a reference for the last page, we don't own it */
	get_page(gl->frags[gl->nfrags - 1].page);

}

void t4_lro_flush(struct t4_lro_mgr *lro_mgr,
		  struct sk_buff *skb)
{
	struct sock *sk = skb->sk;
	struct cpl_io_state *cplios;

	if (skb->next || skb->prev)
		__skb_unlink(skb, &lro_mgr->lroq);
	cplios = CPL_IO_STATE(sk);
	sock_put(sk);
	skb->sk = NULL;
	if (cplios->ulp_mode == ULP_MODE_ISCSI && fp_iscsi_lro_proc_rx) {
		process_cpl_msg(fp_iscsi_lro_proc_rx, sk, skb);
	} else {	
		skb_gl_set(skb, NULL);	/* indicates packet is RX_DATA */
		process_cpl_msg(new_rx_data, sk, skb);
	}

	lro_mgr->lro_pkts++;
	lro_mgr->lro_session_cnt--;
	cplios->lro_skb = NULL;
}

int t4_lro_receive_gl(struct cpl_io_state *cplios,
		      struct napi_struct *napi,
		      const struct pkt_gl *gl,
		      struct t4_lro_mgr *lro_mgr,
		      const __be64 *rsp)
{
	const struct cpl_tx_data *rpl = gl->va;
	unsigned int tid = G_TID(ntohl(OPCODE_TID(rpl)));
	struct sock *sk = cplios->sk;
	struct sk_buff *skb;
	int cpl_hdr_size = sizeof(struct cpl_tx_data);

	/* Check if we have already started LRO for this session */
	if ((cplios->tid == tid) && cplios->lro_skb)
		goto add_packet;

start_lro:
	/* Did we reach the limit of maximum sessions to aggreagate */
	if (lro_mgr->lro_session_cnt >= MAX_LRO_SESSIONS)
		goto out;

	/* Start LROing the packets of this connection */
	if (lro_init_desc(napi, gl, sk, tid, rsp))
		goto out;
	lro_mgr->lro_merged++;
	lro_mgr->lro_session_cnt++;
	skb = cplios->lro_skb;
	__skb_queue_tail(&lro_mgr->lroq, skb);
	return 0;

add_packet:
	skb = cplios->lro_skb;
	/* Check if this packet can be aggregated. ie
	 * toal lenght should not exceed 64K and
	 * total frags count should not exceed MAX_SKB_FRAGS */
	if (((skb->len + gl->tot_len - cpl_hdr_size) > 65535) ||
	    ((skb_shinfo(skb)->nr_frags + gl->nfrags) >= MAX_SKB_FRAGS)) {
		/* Flush the so far aggregated packet */
		t4_lro_flush(lro_mgr, skb);
		goto start_lro;
	}

	lro_add_packet(skb, gl);
	lro_mgr->lro_merged++;
	return 0;

out:
	return -1;
}

void t4_lro_flush_all(struct t4_lro_mgr *lro_mgr)
{
	struct sk_buff *skb;

	while ((skb = __skb_dequeue(&lro_mgr->lroq)) != NULL)
		t4_lro_flush(lro_mgr, skb);
	__skb_queue_head_init(&lro_mgr->lroq);
}

int t4_init_sk_filter(void)
{
	/*
	 * Initialize Drop All filter.
	 * Below BUG_ON() is left for now since a simple drop filter for
	 * offload is not more than 1 Filter instruction long.
	 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
	/* 3.17 */
	BUG_ON(ARRAY_SIZE(drop_insnsi) != 1);
	drop_bpf = bpf_prog_alloc(bpf_prog_size(ARRAY_SIZE(drop_insnsi)), GFP_KERNEL);
	if (!drop_bpf)
		goto err;

	drop_bpf->len = ARRAY_SIZE(drop_insnsi);
	memcpy(&drop_bpf->insnsi, drop_insnsi, sizeof(drop_insnsi));
	bpf_prog_select_runtime(drop_bpf);

	drop_all = (struct sk_filter *)kmalloc(sizeof(*drop_all),
					       GFP_KERNEL);
	if (!drop_all) {
		bpf_prog_free(drop_bpf);
		goto err;
	}
	drop_all->prog = drop_bpf;

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
	/* 3.15, 3.16 */
	BUG_ON(ARRAY_SIZE(drop_insnsi) != 1);
	drop_all = (struct sk_filter *)kmalloc(sizeof(*drop_all)+
					       sizeof(drop_insnsi),
					       GFP_KERNEL);
	if (!drop_all)
		goto err;

	drop_all->len = ARRAY_SIZE(drop_insnsi);
	memcpy(&drop_all->insnsi, drop_insnsi, sizeof(drop_insnsi));
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
	/* 3.15 */
	drop_all->bpf_func = sk_run_filter_int_skb;
#else /* 3.16 */
	sk_filter_select_runtime(drop_all);
#endif /* < 3.16 */

#else /* < 3.15 */
	BUG_ON(ARRAY_SIZE(drop_insns) != 1);
	drop_all = (struct sk_filter *)kmalloc(sizeof(*drop_all)+
					       sizeof(drop_insns),
					       GFP_KERNEL);
	if (!drop_all)
		goto err;

	drop_all->len = ARRAY_SIZE(drop_insns);
	memcpy(&drop_all->insns, drop_insns, sizeof(drop_insns));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
	drop_all->bpf_func = sk_run_filter;
#endif /* >= 3.0 */
#endif /* < 3.15 */

	atomic_set(&drop_all->refcnt, 1);
	return 0;
err:
	return -1;
}

void t4_free_sk_filter(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
	if (drop_bpf)
		bpf_prog_free(drop_bpf);
#endif
	if (drop_all)
		kfree(drop_all);
}

int __init t4_init_cpl_io(void)
{
	tcphdr_skb = alloc_skb(sizeof(struct tcphdr), GFP_KERNEL);
	if (!tcphdr_skb) {
		printk(KERN_ERR
		       "Chelsio TCP offload: can't allocate sk_buff\n");
		return -1;
	}
	skb_put(tcphdr_skb, sizeof(struct tcphdr));
	skb_reset_transport_header(tcphdr_skb);
	memset(tcphdr_skb->data, 0, tcphdr_skb->len);
	/* CIPSO_V4_OPTEXIST is false for tcphdr_skb without anything extra */

	if (t4_init_sk_filter()) {
		printk(KERN_ERR
		       "Chelsio TCP offload: can't allocate sk_filter\n");
		kfree_skb(tcphdr_skb);
		return -1;
	}

	t4tom_register_cpl_handler(CPL_ACT_ESTABLISH, do_act_establish);
	t4tom_register_cpl_handler(CPL_ACT_OPEN_RPL, do_act_open_rpl);
	t4tom_register_cpl_handler(CPL_PEER_CLOSE, do_peer_close);
	t4tom_register_cpl_handler(CPL_CLOSE_CON_RPL, do_close_con_rpl);
	t4tom_register_cpl_handler(CPL_ABORT_REQ_RSS, do_abort_req);
	t4tom_register_cpl_handler(CPL_ABORT_RPL_RSS, do_abort_rpl);
	t4tom_register_cpl_handler(CPL_RX_DATA, do_rx_data);
	t4tom_register_cpl_handler(CPL_RX_DATA_DDP, do_rx_data_ddp);
	t4tom_register_cpl_handler(CPL_RX_DDP_COMPLETE, do_rx_ddp_complete);
	t4tom_register_cpl_handler(CPL_SET_TCB_RPL, do_set_tcb_rpl);
	t4tom_register_cpl_handler(CPL_PASS_ACCEPT_REQ, do_pass_accept_req);
	t4tom_register_cpl_handler(CPL_PASS_ESTABLISH, do_pass_establish);
	t4tom_register_cpl_handler(CPL_RX_URG_NOTIFY, do_rx_urg_notify); 
	t4tom_register_cpl_handler(CPL_FW6_MSG, do_fw6_msg);
	t4tom_register_cpl_handler(CPL_RX_PKT, do_rx_pkt);
	t4tom_register_cpl_handler(CPL_FW4_ACK, do_fw4_ack);
	if (ma_fail_t4_init_cpl_io())
		return -1;
	return 0;
}
