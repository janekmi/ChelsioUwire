/*
 * Copyright 2014-2015 (C) Chelsio Communications.  All rights reserved.
 *
 * Written by Kumar Sanghvi (kumaras@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Software in this file is covered under US Patent "Failover and migration
 * for full-offload network interface devices : US 8346919 B1".
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
#include <linux/workqueue.h>
#include <net/ipv6.h>
#include <net/transp_v6.h>
#include <net/ip6_route.h>
#include <net/tcp.h>
#include <net/offload.h>
#include <net/route.h>
#include <net/ip6_route.h>
#include <asm/atomic.h>
#include "common.h"
#include "defs.h"
#include "tom.h"
#include "l2t.h"
#include "clip_tbl.h"
#include "smt.h"
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

#include <net/bonding.h>

#ifdef CONFIG_T4_MA_FAILOVER

extern unsigned long long calc_opt0(struct sock *sk);
extern void sk_insert_tid(struct tom_data *d, struct sock *sk,
			  unsigned int tid);
extern void free_atid(struct tid_info *tids, unsigned int atid);
extern void __set_tcb_field(struct sock *sk, struct sk_buff *skb, u16 word,
			    u64 mask, u64 val, u8 cookie, int no_reply);
extern void send_or_defer(struct sock *sk, struct tcp_sock *tp,
				 struct sk_buff *skb, int through_l2t);
extern void t4_set_tcb_tflag(struct sock *sk, unsigned int bit_pos, int val);
extern int tx_flowc_wr_credits(struct sock *sk, int *nparamsp, int *flowclenp);
extern struct sk_buff *copy_gl_to_skb_pkt(const struct pkt_gl *gl, const __be64 *rsp,
					  u32 pktshift);
extern void t4_release_offload_resources(struct sock *sk);
extern void connection_done(struct sock *sk);

static struct sk_buff_head rx_pkts, tx_pkts;
static struct workqueue_struct *rx_pkt_workq, *tx_pkt_workq;

static void t4_ma_failover_set_tcb_rx_params(struct sock *sk, u16 word, u64 mask, u64 val,
					     u8 cookie, int no_reply)
{
	struct sk_buff *skb;

	if (sk->sk_state == TCP_CLOSE || cplios_flag(sk, CPLIOS_ABORT_SHUTDOWN))
		return;

	skb = alloc_ctrl_skb(CPL_IO_STATE(sk)->ctrl_skb_cache,
		sizeof(struct cpl_set_tcb_field));
	if (!skb) {
		printk("%s: skb allocation failure .\n", __func__);
		return;
	}

	__set_tcb_field(sk, skb, word, mask, val, cookie, no_reply);
	send_or_defer(sk, tcp_sk(sk), skb, 0);
}

/* Adapted from t4_tom:cpl_io.c */
static void t4_set_tcb_field_mafo(struct sock *sk, u16 word, u64 mask, u64 val, u8 cookie,
				  int no_reply, unsigned int prio, int ma_fail, u8 compl)
{
	struct sk_buff *skb;
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct cpl_set_tcb_field *req;

	if (sk->sk_state == TCP_CLOSE || cplios_flag(sk, CPLIOS_ABORT_SHUTDOWN))
		return;

	skb = alloc_ctrl_skb(CPL_IO_STATE(sk)->ctrl_skb_cache,
		sizeof(struct cpl_set_tcb_field));
	if (!skb) {
		printk("%s: skb allocation failure .\n", __func__);
		return;
	}

	req = (struct cpl_set_tcb_field *)__skb_put(skb, sizeof(*req));
	if (ma_fail) {
		INIT_TP_WR_MIT_CPL(req, CPL_SET_TCB_FIELD, cplios->ma_fail_info.tid);
		req->reply_ctrl = htons(V_NO_REPLY(no_reply) |
					V_REPLY_CHAN(cplios->ma_fail_info.rx_c_chan) |
					V_QUEUENO(cplios->ma_fail_info.rss_qid));
		req->word_cookie = htons(V_WORD(word) | V_COOKIE(cookie));
		req->mask = cpu_to_be64(mask);
		req->val = cpu_to_be64(val);
		if (prio == CPL_PRIORITY_CONTROL)
			set_queue(skb, (cplios->ma_fail_info.port_id << 1) | prio, sk);
		else
			set_queue(skb, (cplios->ma_fail_info.txq_idx << 1) | prio, sk);
	} else {
		INIT_TP_WR_MIT_CPL(req, CPL_SET_TCB_FIELD, cplios->tid);
		req->reply_ctrl = htons(V_NO_REPLY(no_reply) |
					V_REPLY_CHAN(cplios->rx_c_chan) |
					V_QUEUENO(cplios->rss_qid));
		req->word_cookie = htons(V_WORD(word) | V_COOKIE(cookie));
		req->mask = cpu_to_be64(mask);
		req->val = cpu_to_be64(val);
		if (prio == CPL_PRIORITY_CONTROL)
			set_queue(skb, (cplios->port_id << 1) | prio, sk);
		else
			set_queue(skb, (cplios->txq_idx << 1) | prio, sk);
	}

	if (prio == CPL_PRIORITY_DATA) {
		unsigned int credits_needed =
			DIV_ROUND_UP(sizeof(struct cpl_set_tcb_field), 16);

		if (compl)
			req->wr.wr_hi |= htonl(V_FW_WR_COMPL(compl));
		skb->csum = credits_needed;
		cplios->wr_credits -= credits_needed;
		cplios->wr_unacked += credits_needed;
		enqueue_wr_shared(sk, skb);
	}

	if (ma_fail)
		cxgb4_ofld_send(cplios->ma_fail_info.egress_dev, skb);
	else
		cxgb4_ofld_send(cplios->egress_dev, skb);
}

/* Borrowed from t4_tom:cpl_io.c */
static int t4_get_tcb(struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct cpl_get_tcb *req;
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb = alloc_skb(sizeof(*req), gfp_any());
	if (!skb)
		return -ENOMEM;

	req = (struct cpl_get_tcb *)__skb_put(skb, sizeof(*req));
	INIT_TP_WR_MIT_CPL(req, CPL_GET_TCB, cplios->tid);
	req->reply_ctrl = htons(V_REPLY_CHAN(cplios->rx_c_chan) | V_QUEUENO(cplios->rss_qid));
	req->cookie = 0;
	set_wr_txq(skb, CPL_PRIORITY_CONTROL, cplios->port_id);

	if (sk->sk_state == TCP_SYN_SENT)
		__skb_queue_tail(&tp->out_of_order_queue, skb); // defer
	else
		cxgb4_ofld_send(cplios->egress_dev, skb);

	return 0;
}

static void t4_send_abort_no_rst(struct sock *sk, int ma_fail)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct cpl_abort_req *req;
	struct sk_buff *skb;
	struct tcp_sock *tp = tcp_sk(sk);

	skb = alloc_skb(sizeof(*req), GFP_ATOMIC);
	req = (struct cpl_abort_req *)skb_put(skb, sizeof(*req));

	if (ma_fail) {
		INIT_TP_WR_MIT_CPL(req, CPL_ABORT_REQ, cplios->ma_fail_info.tid);
		set_queue(skb, (cplios->ma_fail_info.txq_idx << 1) | CPL_PRIORITY_DATA, sk);
	} else {
		INIT_TP_WR_MIT_CPL(req, CPL_ABORT_REQ, cplios->tid);
		set_queue(skb, (cplios->txq_idx << 1) | CPL_PRIORITY_DATA, sk);
	}
	req->rsvd0 = htonl(tp->snd_nxt);
	req->rsvd1 = !cplios_flag(sk, CPLIOS_TX_DATA_SENT);
	req->cmd = CPL_ABORT_NO_RST;
	cxgb4_ofld_send(ma_fail ? cplios->ma_fail_info.egress_dev : cplios->egress_dev, skb);
	return;
}

static void t4_ma_failover_drain_rx(struct sock *sk)
{
	if (DDP_STATE(sk)->ddp_setup) {
		struct ddp_state *p = DDP_STATE(sk);
		if (p->ubuf_ddp_pending) {
#ifdef DEBUG
			printk("%s: tid = %u; indicate = %u; indout_count = %u;"
			       "ubuf_ddp_pending = %u; t4_ddp_ubuf_pending(sk) = %u \n",
			       __func__, CPL_IO_STATE(sk)->tid, p->indicate,
			       p->indout_count, p->ubuf_ddp_pending,
			       t4_ddp_ubuf_pending(sk));
#endif
			p->cancel_ubuf = 1;
			if (p->cur_buf)
				t4_cancel_ddpbuf(sk, p->cur_buf);
		}
		t4_enable_ddp(sk, 0);
	}

	t4_set_tcb_field(sk, W_TCB_T_FLAGS, V_TF_RCV_COALESCE_ENABLE(1ULL) |
			 V_TF_RCV_COALESCE_PUSH(1ULL) |
			 V_TF_RCV_COALESCE_LAST_PSH(1ULL),
			 V_TF_RCV_COALESCE_ENABLE(0ULL) |
			 V_TF_RCV_COALESCE_PUSH(1ULL) |
			 V_TF_RCV_COALESCE_LAST_PSH(1ULL));

	t4_ma_failover_set_tcb_rx_params(sk, W_TCB_RCV_WND,
					 V_TCB_RCV_WND(M_TCB_RCV_WND),
					 V_TCB_RCV_WND(0ULL),
					 MA_FAILOVER_COOKIE_RCV_WND, 0);
}

inline u64 t4_tcb_get_field64(__be64 *tcb, u16 word)
{
	u64 tlo = be64_to_cpu(tcb[((31 - word) /2)]);
	u64 thi = be64_to_cpu(tcb[((31 - word) /2) - 1]);
	u64 t;
	u32 shift = 32;

	t = (thi << shift) | (tlo >> shift);

	return t;
}

/* Borrowed from t4_tom:cpl_io.c */
static inline u32 t4_tcb_get_field32(__be64 *tcb, u16 word, u32 mask, u32 shift)
{
	u32 v;
	u64 t = be64_to_cpu(tcb[(31 - word) /2]);

	if (word & 0x1)
		shift += 32;
	v = (t >> shift) & mask;
	return v;
}

/* Borrowed from t4_tom:cpl_io.c */
static inline void t4_tcb_set_field32(__be64 *tcb, u16 word, u64 mask, u32 shift, u32 val)
{
	u64 t = be64_to_cpu(tcb[(31 - word) /2]);

	if (word & 0x1)
		shift += 32;

	t &= ~(mask << shift);
	t |= ((u64)val & mask) << shift;
	tcb[(31 - word) /2] = cpu_to_be64(t);
	return;
}

u64 t4_get_tp_time_offset(struct adapter *adap, u8 offset)
{
	u64 tp_time;
	u32 tp_time_hi = 0, tp_time_lo = 0, tp_time_hi1 = 1;

	while(tp_time_hi != tp_time_hi1) {
		tp_time_hi = t4_read_reg(adap, A_TP_TIME_HI);
		tp_time_lo = t4_read_reg(adap, A_TP_TIME_LO);
		tp_time_hi1 = t4_read_reg(adap, A_TP_TIME_HI);
	}

	tp_time = tp_time_hi;
	tp_time = (tp_time << 32) | tp_time_lo;
	tp_time += (offset << 28);
	return tp_time;
}

static void process_get_tcb_rpl(struct sock *sk, struct sk_buff *skb)
{
	if(cplios_flag(sk, CPLIOS_MA_FAILOVER)) {
		struct tcp_sock *tp = tcp_sk(sk);
		struct cpl_io_state *cplios = CPL_IO_STATE(sk);
		struct cpl_get_tcb_rpl *rpl = cplhdr(skb);
		__be64 *tcb = (__be64*)(rpl + 1);
		struct ma_failover_info old_info;
		struct sk_buff *flowc_skb;
		u32 snd_scale, rcv_scale, rcv_adv;
		u32 t_state;
		u32 rcv_nxt, tx_max, snd_una_raw;
		u32 cong_ctrl, core_fin, peer_fin;
		u64 t_flags_64, tp_time_offset_failed, tp_time_offset_backup;
		int flowclen16 = 0;
		u8 timestamp_offset;

		/* cancel rx_drain_timer if already running */
		hrtimer_cancel(&cplios->ma_fail_info.rx_drain_timer);

		t_state = t4_tcb_get_field32(tcb, W_TCB_T_STATE, M_TCB_T_STATE,
					     S_TCB_T_STATE);
		rcv_nxt = t4_tcb_get_field32(tcb, W_TCB_RCV_NXT, M_TCB_RCV_NXT,
					     S_TCB_RCV_NXT);
		tx_max = t4_tcb_get_field32(tcb, W_TCB_TX_MAX, M_TCB_TX_MAX,
					    S_TCB_TX_MAX);
		snd_una_raw = t4_tcb_get_field32(tcb, W_TCB_SND_UNA_RAW,
						 M_TCB_SND_UNA_RAW,
						 S_TCB_SND_UNA_RAW);
		snd_scale = t4_tcb_get_field32(tcb, W_TCB_SND_SCALE,
					       M_TCB_SND_SCALE,
					       S_TCB_SND_SCALE);
		rcv_scale = t4_tcb_get_field32(tcb, W_TCB_RCV_SCALE,
					       M_TCB_RCV_SCALE,
					       S_TCB_RCV_SCALE);
		timestamp_offset = t4_tcb_get_field32(tcb, W_TCB_TIMESTAMP_OFFSET,
						      M_TCB_TIMESTAMP_OFFSET,
						      S_TCB_TIMESTAMP_OFFSET);
		rcv_adv = t4_tcb_get_field32(tcb, W_TCB_RCV_ADV,
					     M_TCB_RCV_ADV,
					     S_TCB_RCV_ADV);
		t_flags_64 = t4_tcb_get_field64(tcb, W_TCB_T_FLAGS);
		cong_ctrl = (t_flags_64 & (V_TF_CCTRL_SEL0(1) |
					   V_TF_CCTRL_SEL1(1))) >>
			     S_TF_CCTRL_SEL0;
		core_fin = (t_flags_64 & V_TF_CORE_FIN(1)) >> S_TF_CORE_FIN;
		peer_fin = (t_flags_64 & V_TF_PEER_FIN(1)) >> S_TF_PEER_FIN;

		tp_time_offset_failed = t4_get_tp_time_offset(netdev2adap(cplios->egress_dev),
							      timestamp_offset);
		tp_time_offset_backup = t4_get_tp_time_offset(netdev2adap(cplios->ma_fail_info.egress_dev),
						       	      timestamp_offset);

		if (time_after64(tp_time_offset_failed, tp_time_offset_backup)) {
			timestamp_offset += DIV_ROUND_UP((tp_time_offset_failed - tp_time_offset_backup),
							 1 << 28);
			timestamp_offset = timestamp_offset % 16;
		}

		if (!cplios->ma_fail_info.last_rcv_nxt) {
			/*
			 * Looks like last-rcv-nxt is not filled yet..
			 */
#ifdef DEBUG
			printk("%s: tid = %u; last_rcv_nxt = %u.. retrying..\n",
				__func__, cplios->tid, cplios->ma_fail_info.last_rcv_nxt);
#endif
			hrtimer_start(&cplios->ma_fail_info.rx_drain_timer,
				      ktime_set(5, 0),
				      HRTIMER_MODE_REL);
			goto free_skb;
		}

		if (before(tp->rcv_nxt, cplios->ma_fail_info.last_rcv_nxt +
			   cplios->ma_fail_info.rx_hdr_offset)) {
			/*
			 * Looks like there is still Rx pending on the old adapter.
			 * Retry again, in the hope that the pending Rx will get drained
			 * out.
			 */
#ifdef DEBUG
			printk("%s: cplios->tid = %u; s/w rcv_nxt = %u; h/w rcv_nxt = %u;"
				"s/w last rcv_nxt = %u; s/w rx_hdr_offset = %u\n",
				__func__, cplios->tid, tp->rcv_nxt, rcv_nxt,
				cplios->ma_fail_info.last_rcv_nxt,
				cplios->ma_fail_info.rx_hdr_offset);
#endif
			hrtimer_start(&cplios->ma_fail_info.rx_drain_timer,
				      ktime_set(5, 0),
				      HRTIMER_MODE_REL);
			goto free_skb;
		} else {
			/*
			 * Double-check and compare with h/w rcv_nxt. There is still
			 * a possibility that h/w rcv_nxt would have advanced
			 */
			if (before(tp->rcv_nxt, rcv_nxt) &&
 			    !(sk->sk_state == TCP_CLOSE_WAIT ||
			      sk->sk_state == TCP_LAST_ACK ||
			      sk->sk_state == TCP_CLOSING ||
			      sk->sk_state == TCP_FIN_WAIT2) &&
			    cplios->ma_fail_info.flags != MA_FAIL_ABORT) {
#ifdef DEBUG
					printk("%s: tid = %u; s/w rcv_nxt = %u;"
						"hw rcv_nxt = %u; likely h/w race.. \n",
						__func__, cplios->tid, tp->rcv_nxt, rcv_nxt);
#endif
					hrtimer_start(&cplios->ma_fail_info.rx_drain_timer,
						      ktime_set(5, 0),
						      HRTIMER_MODE_REL);
					goto free_skb;
			} else {
				struct ddp_state *p = DDP_STATE(sk);

				if (p && p->state == DDP_ENABLED) {
					if (p->ubuf_ddp_pending) {
#ifdef DEBUG
						printk("%s: Still tid = %u; "
							"indicate = %u; "
							"indout_count = %u; "
							"ubuf_ddp_pending = %u; "
							"t4_ddp_ubuf_pending(sk) = %u \n",
							__func__, CPL_IO_STATE(sk)->tid,
							p->indicate,
							p->indout_count,
							p->ubuf_ddp_pending,
							t4_ddp_ubuf_pending(sk));
#endif
						/* We wait for some more time since there
						 * is a possibility that rx-thread has not
						 * executed yet.
						 * However, we do this additional waiting
						 * for only 3 retries since if
						 * ubuf_ddp_pending is still set then, its
						 * quite likely that the remaining payload
						 * was not enough to consume the ddp buffer.
						 * So, we then proceed with connection move
						 * since the remaining Rx payload is already
						 * retrieved.
						 */
						if (cplios->ma_fail_info.rx_retry < 3) {
							/* wakeup rx thread again */
							sk_data_ready_compat(sk, 0);
							cplios->ma_fail_info.rx_retry++;
#ifdef DEBUG
							printk("%s:tid= %u; rx_retry= %d\n",
								__func__, cplios->tid,
								cplios->ma_fail_info.rx_retry);
#endif
							hrtimer_start(&cplios->ma_fail_info.rx_drain_timer,
								      ktime_set(10, 0),
								      HRTIMER_MODE_REL);
							goto free_skb;
						}
					}

					/* wakeup the socket if its sleeping.. */
					sk_data_ready_compat(sk, 0);
					t4_release_ddp_resources(sk);
					t4_cleanup_ddp(sk);
					p->indicate = 0;
					p->indout_count = 0;
				}
			}
		}

		if (cplios->ma_fail_info.flags != MA_FAIL_ABORT) {
			if ((t_state != tcp_state_to_flowc_state(sk->sk_state))
			    && skb_queue_len(&cplios->tx_queue)) {
#ifdef DEBUG
				printk("%s: Enqueued Tx on failed adapter... "
				       "sk_state = %d; tid = %u; tx_queue len = %d\n",
					__func__, sk->sk_state, cplios->tid,
					skb_queue_len(&cplios->tx_queue));
#endif

				cplios_reset_flag (sk, CPLIOS_TX_WAIT_IDLE);
				t4_push_frames(sk, 1);
				hrtimer_start(&cplios->ma_fail_info.rx_drain_timer,
					      ktime_set(10, 0),
					      HRTIMER_MODE_REL);
				goto free_skb;

			}



			if (after(tp->snd_nxt, tp->snd_una)) {
#ifdef DEBUG
				printk("%s: Still Tx pending....."
				       "sk_state = %d; tid = %u; \n",
					__func__, sk->sk_state, cplios->tid);
#endif
			}

		}

		if (likely(cplios->ma_fail_info.flags == MA_FAIL_OVER)) {
			if (!cplios_flag(sk, CPLIOS_TX_DATA_SENT))
				send_tx_flowc_wr(sk, 0, tp->snd_nxt, tp->rcv_nxt);
		}

		/* swap stuff */
		old_info.tid = cplios->tid;
		cplios->tid = cplios->ma_fail_info.tid;

		old_info.port_id = cplios->port_id;
		cplios->port_id = cplios->ma_fail_info.port_id;

		old_info.egress_dev = cplios->egress_dev;
		cplios->egress_dev = cplios->ma_fail_info.egress_dev;

		old_info.toedev = cplios->toedev;
		cplios->toedev = cplios->ma_fail_info.toedev;

		old_info.l2t_e = cplios->l2t_entry;
		cplios->l2t_entry = cplios->ma_fail_info.l2t_e;

		old_info.tx_c_chan = cplios->tx_c_chan;
		cplios->tx_c_chan = cplios->ma_fail_info.tx_c_chan;

		old_info.rx_c_chan = cplios->rx_c_chan;
		cplios->rx_c_chan = cplios->ma_fail_info.rx_c_chan;

		old_info.smac_idx = cplios->smac_idx;
		cplios->smac_idx = cplios->ma_fail_info.smac_idx;

		old_info.port_speed = cplios->port_speed;
		cplios->port_speed = cplios->ma_fail_info.port_speed;

		old_info.txq_idx = cplios->txq_idx;
		cplios->txq_idx = cplios->ma_fail_info.txq_idx;

		old_info.rss_qid = cplios->rss_qid;
		cplios->rss_qid = cplios->ma_fail_info.rss_qid;

		old_info.last_rcv_nxt = cplios->ma_fail_info.last_rcv_nxt;
		old_info.rcv_wnd = cplios->ma_fail_info.rcv_wnd;
		old_info.rx_hdr_offset = cplios->ma_fail_info.rx_hdr_offset;
		old_info.l2t_e_arpmiss = cplios->ma_fail_info.l2t_e_arpmiss;

		old_info.flags = (cplios->ma_fail_info.flags == MA_FAIL_OVER) ? MA_FAIL_DONE :
				  cplios->ma_fail_info.flags;
		cplios->ma_fail_info = old_info;

		cplios->wr_max_credits = cplios->wr_credits =
			min_t(unsigned int, (TOM_DATA(cplios->toedev))->max_wr_credits,
			      TOM_TUNABLE(cplios->toedev, max_wr_credits));
		cplios->wr_unacked = 0;
		smp_mb();

		/* send flowc */
		flowclen16 = tx_flowc_wr_credits(sk, NULL, NULL);
		flowc_skb = alloc_skb(flowclen16*16, GFP_ATOMIC);
		if (!flowc_skb) {
			printk("%s: flowc_skb allocation failed.. \n", __func__);
			goto free_skb;
		}

		cplios->wr_credits -= flowclen16;
		cplios->wr_unacked += flowclen16;
		flowc_skb->csum = flowclen16;
		enqueue_wr(sk, flowc_skb);
		send_tx_flowc_wr(sk, 1, tp->snd_nxt, tp->rcv_nxt);
		dev_kfree_skb(flowc_skb);

		/* optional additional */
		t4_set_tcb_field_mafo(sk, W_TCB_SND_SCALE, V_TCB_SND_SCALE(M_TCB_SND_SCALE) |
				      V_TCB_RCV_SCALE(M_TCB_RCV_SCALE << 32),
				      V_TCB_SND_SCALE((u64)snd_scale) |
				      V_TCB_RCV_SCALE(((u64)rcv_scale) << 32),
				      MA_FAILOVER_COOKIE_NEW_RCV_WND,
				      1,
				      CPL_PRIORITY_DATA,
				      0, 0);
		t4_set_tcb_field_mafo(sk, W_TCB_TIMESTAMP_OFFSET,
				      V_TCB_TIMESTAMP_OFFSET(M_TCB_TIMESTAMP_OFFSET),
				      V_TCB_TIMESTAMP_OFFSET((u64)timestamp_offset),
				      MA_FAILOVER_COOKIE_NEW_RCV_WND,
				      1,
				      CPL_PRIORITY_DATA,
				      0, 0);

		/* set tcb-fields.. */
		if (sk->sk_state == TCP_ESTABLISHED) {
			t4_set_tcb_field_mafo(sk, W_TCB_TX_MAX,
					      V_TCB_TX_MAX(M_TCB_TX_MAX) |
					      V_TCB_SND_UNA_RAW(M_TCB_SND_UNA_RAW << 32),
					      V_TCB_TX_MAX((u64)tp->snd_nxt) |
					      V_TCB_SND_UNA_RAW(((u64)(tp->snd_nxt - tp->snd_una)) << 32),
					      MA_FAILOVER_COOKIE_NEW_RCV_WND,
					      1,
					      CPL_PRIORITY_DATA,
					      0, 0);
			t4_set_tcb_field_mafo(sk, W_TCB_RCV_NXT,
					      V_TCB_RCV_NXT(M_TCB_RCV_NXT),
					      V_TCB_RCV_NXT((u64)tp->rcv_nxt),
					      MA_FAILOVER_COOKIE_NEW_RCV_WND,
					      1,
					      CPL_PRIORITY_DATA,
					      0, 0);
		} else {
			t4_set_tcb_field_mafo(sk, W_TCB_TX_MAX,
					      V_TCB_TX_MAX(M_TCB_TX_MAX) |
					      V_TCB_SND_UNA_RAW(M_TCB_SND_UNA_RAW << 32),
					      V_TCB_TX_MAX((u64)tx_max) |
					      V_TCB_SND_UNA_RAW(((u64)snd_una_raw) << 32),
					      MA_FAILOVER_COOKIE_NEW_RCV_WND,
					      1,
					      CPL_PRIORITY_DATA,
					      0, 0);
			t4_set_tcb_field_mafo(sk, W_TCB_RCV_NXT,
					      V_TCB_RCV_NXT(M_TCB_RCV_NXT),
					      V_TCB_RCV_NXT((u64)rcv_nxt),
					      MA_FAILOVER_COOKIE_NEW_RCV_WND,
					      1,
					      CPL_PRIORITY_DATA,
					      0, 0);

		}
		t4_set_tcb_field_mafo(sk, W_TCB_RCV_ADV, V_TCB_RCV_ADV(M_TCB_RCV_ADV),
				      V_TCB_RCV_ADV((u64)rcv_adv),
				      MA_FAILOVER_COOKIE_NEW_RCV_WND,
				      1,
				      CPL_PRIORITY_DATA,
				      0, 0);

		/* set state */
		t4_set_tcb_field_mafo(sk, W_TCB_T_STATE, V_TCB_T_STATE(M_TCB_T_STATE),
				      V_TCB_T_STATE((u64)t_state),
				      MA_FAILOVER_COOKIE_NEW_RCV_WND,
				      1,
				      CPL_PRIORITY_DATA,
				      0, 0);

		/* restore original congetsion control */
		t4_set_tcb_field_mafo(sk, W_TCB_T_FLAGS, 3ULL << S_TF_CCTRL_SEL0,
				      V_TF_CCTRL_SEL0((u64)cong_ctrl),
				      MA_FAILOVER_COOKIE_NEW_RCV_WND,
				      1,
				      CPL_PRIORITY_DATA,
				      0, 0);

		/* clear non-offload bit.. */
		if (sk->sk_state == TCP_ESTABLISHED) {
			t4_set_tcb_field_mafo(sk, W_TCB_T_FLAGS,
					      1ULL << S_TF_NON_OFFLOAD,
					      (u64)0 << S_TF_NON_OFFLOAD,
					      MA_FAILOVER_COOKIE_NEW_RCV_WND,
					      1,
					      CPL_PRIORITY_DATA,
					      0, 0);
		} else {
			t4_set_tcb_field_mafo(sk, W_TCB_T_FLAGS,
					      (1ULL << S_TF_NON_OFFLOAD) |
					      (1ULL << S_TF_CORE_FIN) |
					      (1ULL << S_TF_PEER_FIN),
					      ((u64)0 << S_TF_NON_OFFLOAD) |
					      ((u64)core_fin << S_TF_CORE_FIN) |
					      ((u64)peer_fin << S_TF_PEER_FIN),
					      MA_FAILOVER_COOKIE_NEW_RCV_WND,
					      1,
					      CPL_PRIORITY_DATA,
					      0, 0);
		}

		/* re-open rcv_wnd */
		t4_set_tcb_field_mafo(sk, W_TCB_RCV_WND, V_TCB_RCV_WND(M_TCB_RCV_WND),
				      V_TCB_RCV_WND((u64)(cplios->ma_fail_info.rcv_wnd -
						      cplios->ma_fail_info.rx_hdr_offset)),
				      MA_FAILOVER_COOKIE_NEW_RCV_WND,
				      1,
				      CPL_PRIORITY_DATA,
				      0, 1);

		cplios_set_flag(sk, CPLIOS_TX_DATA_SENT);
		cplios_reset_flag (sk, CPLIOS_TX_WAIT_IDLE);
		cplios_reset_flag(sk, CPLIOS_MA_FAILOVER);

		if (unlikely(cplios->ma_fail_info.flags == MA_FAIL_ABORT)) {
			t4_send_abort_no_rst(sk, 0);
		} else {
			/* kick tx.. */
			if (t4_push_frames(sk, 0))
				sk->sk_write_space(sk);

			t4_set_tcb_field_mafo(sk, W_TCB_L2T_IX,
                        	              V_TCB_L2T_IX(M_TCB_L2T_IX),
                                	      V_TCB_L2T_IX(cplios->ma_fail_info.l2t_e_arpmiss->idx),
	                                      MA_FAILOVER_COOKIE_L2TIX,
        	                              0,
                	                      CPL_PRIORITY_CONTROL,
                        	              1, 0);
		}
	}

free_skb:
	dev_kfree_skb(skb);
}

/*
 * Process a CPL_GET_TCB_RPL.
 */
static int do_get_tcb_rpl(struct tom_data *td, struct sk_buff *skb)
{
	struct sock *sk;
	struct cpl_get_tcb_rpl *rpl = cplhdr(skb);
	unsigned int hwtid = GET_TID(rpl);

	sk = lookup_tid(td->tids, hwtid);
	if (!sk)
		return CPL_RET_BUF_DONE;

	process_cpl_msg(process_get_tcb_rpl, sk, skb);
	return 0;
}

static int wait_for_ma_fail_info_close(struct sock *sk, long *timeout)
{

	int err = 0;
	long current_timeo = *timeout;
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);

	DEFINE_WAIT(wait);

	if (cplios->ma_fail_info.flags != MA_FAIL_NONE)
		current_timeo = (net_random() % (HZ / 5)) + 2;

	for (;;) {
		prepare_to_wait(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
		if (sk->sk_err) {
#ifdef DEBUG
			printk("%s: returning EPIPE; err = %d..sk_state = %d\n",
				__func__, sk->sk_err, sk->sk_state);
#endif
			err = -EPIPE;
			break;
		}

		if (!*timeout) {
#ifdef DEBUG
			printk("%s: returning EAGAIN..sk_state = %d \n",
				__func__, sk->sk_state);
#endif
			err = -EAGAIN;
			break;
		}
		if (cplios->ma_fail_info.flags == MA_FAIL_NONE)
			break;

		release_sock(sk);

		if (!sk->sk_err && (cplios->ma_fail_info.flags != MA_FAIL_NONE))
			current_timeo = schedule_timeout(current_timeo);

		lock_sock(sk);
		current_timeo = (net_random() % (HZ / 5)) + 2;

	}
	finish_wait(sk_sleep(sk), &wait);
	return err;
}

static int wait_for_ma_fail_info(struct sock *sk, long *timeout)
{

	int err = 0;
	long current_timeo = *timeout;

	DEFINE_WAIT(wait);

	if (cplios_flag(sk, CPLIOS_MA_FAILOVER))
		current_timeo = (net_random() % (HZ / 5)) + 2;

	for (;;) {
		prepare_to_wait(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
		if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN)) {
#ifdef DEBUG
			printk("%s: returning EPIPE; err = %d..sk_state = %d\n",
				__func__, sk->sk_err, sk->sk_state);
#endif
			err = -EPIPE;
			break;
		}
		if (signal_pending(current)) {
			err = sock_intr_errno(*timeout);
#ifdef DEBUG
			printk("%s: returning err = %d; sk_state = %d \n",
				__func__, err, sk->sk_state);
#endif
			break;
		}
		if (!cplios_flag(sk, CPLIOS_MA_FAILOVER))
			break;

		release_sock(sk);

		if (!sk->sk_err && !(sk->sk_shutdown & SEND_SHUTDOWN) &&
				(cplios_flag(sk, CPLIOS_MA_FAILOVER)))
			current_timeo = schedule_timeout(current_timeo);

		lock_sock(sk);
		current_timeo = (net_random() % (HZ / 5)) + 2;
	}
	finish_wait(sk_sleep(sk), &wait);
	return err;
}

static struct rtable *find_route( __be32 local_ip,
		__be32 peer_ip, __be16 local_port,
		__be16 peer_port, u8 tos)
{
	struct rtable *rt;
	struct flowi4 fl4;
	struct neighbour *neigh = NULL;

	rt = ip_route_output_ports(&init_net, &fl4, NULL, peer_ip, local_ip,
				   peer_port, local_port, IPPROTO_TCP,
				   tos, 0);
	if (IS_ERR(rt))
		return NULL;

	neigh = dst_neigh_lookup(&rt->dst, &peer_ip);
	if (!neigh)
		return NULL;

	neigh_release(neigh);
	return rt;
}

static void update_l2t(struct toedev *tdev, unsigned int req, void *data)
{
	struct tom_data *d = TOM_DATA(tdev);
	struct bond_ports *bond_ports;

	switch(req) {
	case FAILOVER_ACTIVE_SLAVE:
	case FAILOVER_PORT_DOWN:
	case FAILOVER_PORT_UP:
	case FAILOVER_PORT_RELEASE:
		bond_ports = data;
		t4_ports_failover(tdev->lldev[bond_ports->port], req,
				  bond_ports, d->lldi->l2t, 1);
		break;
	case FAILOVER_BOND_DOWN:
		bond_ports = data;
		t4_bond_port_disable(tdev->lldev[bond_ports->port], false,
				     bond_ports);
		break;
	case FAILOVER_BOND_UP:
		bond_ports = data;
		t4_bond_port_disable(tdev->lldev[bond_ports->port], true,
				     bond_ports);
		break;
	default:
		printk("%s: Unknown bond event = %d\n", __func__, req);
		return;
	}
	return;
}

int ma_fail_t4_init_cpl_io(void)
{
	t4tom_register_cpl_handler(CPL_GET_TCB_RPL, do_get_tcb_rpl);
	skb_queue_head_init(&rx_pkts);
	skb_queue_head_init(&tx_pkts);
        rx_pkt_workq = create_singlethread_workqueue("mafo_rx_pkt");
        if (!rx_pkt_workq)
                return -ENOMEM;
	tx_pkt_workq = create_singlethread_workqueue("mafo_tx_pkt");
	if (!tx_pkt_workq)
		return -ENOMEM;
	return 0;
}

void ma_fail_process_set_tcb_rpl(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_set_tcb_rpl *rpl = cplhdr(skb);
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);

	if (G_COOKIE(rpl->cookie) == MA_FAILOVER_COOKIE_RCV_WND) {
		u64 t = be64_to_cpu(rpl->oldval);
		cplios->ma_fail_info.rcv_wnd = (t >> S_TCB_RCV_WND) &
						M_TCB_RCV_WND;

		t4_ma_failover_set_tcb_rx_params(sk, W_TCB_RX_HDR_OFFSET,
						 V_TCB_RX_HDR_OFFSET(0ULL),
						 V_TCB_RX_HDR_OFFSET(1ULL),
						 MA_FAILOVER_COOKIE_RX_HDR_OFFSET,
						 0);
	} else if (G_COOKIE(rpl->cookie) == MA_FAILOVER_COOKIE_RX_HDR_OFFSET) {
		u64 t = be64_to_cpu(rpl->oldval);
		struct tcp_sock *tp = tcp_sk(sk);
		cplios->ma_fail_info.rx_hdr_offset = (t >> S_TCB_RX_HDR_OFFSET) &
							M_TCB_RX_HDR_OFFSET;
		cplios->ma_fail_info.last_rcv_nxt = tp->rcv_nxt;

		t4_ma_failover_set_tcb_rx_params(sk, W_TCB_RCV_WND,
				 V_TCB_RCV_WND(M_TCB_RCV_WND),
				 V_TCB_RCV_WND((unsigned long long)cplios->ma_fail_info.rx_hdr_offset),
				 MA_FAILOVER_COOKIE_RCV_WND, 1);
	} else if (G_COOKIE(rpl->cookie) == MA_FAILOVER_COOKIE_NEW_RCV_WND) {
		/* u64 t = be64_to_cpu(rpl->oldval); */
		struct tcp_sock *tp = tcp_sk(sk);

		/*
		 * if there is no outstanding Tx un-Acked payload then,
		 * prepare to move the connection to new adapter.
		 */
		if (!after(tp->snd_nxt, tp->snd_una))
			t4_get_tcb(sk);
	} else if(G_COOKIE(rpl->cookie) == MA_FAILOVER_COOKIE_L2TIX) {
		if (sk->sk_state != TCP_CLOSE)
			t4_send_abort_no_rst(sk, 1);
	}
}

void ma_failover_get_tcb_task(unsigned long data)
{
	struct sock *sk = (struct sock *)data;
	struct cpl_io_state *cplios;

	bh_lock_sock(sk);
	cplios = CPL_IO_STATE(sk);
	if (cplios && (!(sk->sk_state == TCP_CLOSE ||
			 sk->sk_state == TCP_TIME_WAIT))) {
		bh_unlock_sock(sk);
		t4_get_tcb(sk);
		return;
	} else
		printk("%s: sk->sk_state = %d\n", __func__, sk->sk_state);
	bh_unlock_sock(sk);
}

enum hrtimer_restart ma_failover_rx_drain_timeout(struct hrtimer *timer)
{
	struct ma_failover_info *ma_fail_info = container_of(timer,
			struct ma_failover_info, rx_drain_timer);

	tasklet_schedule(&ma_fail_info->get_tcb_task);
	return HRTIMER_NORESTART;
}

void ma_fail_active_open_rpl(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_act_open_rpl *rpl = cplhdr(skb);
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	unsigned int atid = G_TID_TID(G_AOPEN_ATID(ntohl(rpl->atid_status)));
	unsigned int tid = GET_TID(rpl);

	if (cplios_flag(sk, CPLIOS_MA_FAILOVER)) {
		struct tom_data *t = TOM_DATA(cplios->ma_fail_info.toedev);

		cplios->ma_fail_info.tid = tid;
		sk_insert_tid(t, sk, tid);
		free_atid(t->tids, atid);

		t4_set_tcb_field_mafo(sk, W_TCB_RCV_WND,
				      V_TCB_RCV_WND(M_TCB_RCV_WND),
				      V_TCB_RCV_WND(0ULL),
				      MA_FAILOVER_COOKIE_NEW_RCV_WND,
				      0,
				      CPL_PRIORITY_CONTROL,
				      1, 0);

	}
}

int ma_fail_mk_fw_act_open_req(struct sock *sk, unsigned int atid,
			       const struct l2t_entry *e)
{
	if (cplios_flag(sk, CPLIOS_MA_FAILOVER)) {
		struct sk_buff *skb;
		struct fw_ofld_connection_wr *req;
		struct cpl_io_state *cplios = CPL_IO_STATE(sk);
		struct tom_data *d = TOM_DATA(TOEDEV(cplios->ma_fail_info.egress_dev));
		unsigned short chan;
		u32 opt2;

#ifdef DEBUG
		printk("%s: 0x%x:%u->0x%x:%u; ma-failover = %d; atid = %u\n",
			__func__, htonl(inet_sk(sk)->inet_saddr),
			htons(inet_sk(sk)->inet_sport),
			htonl(inet_sk(sk)->inet_daddr),
			htons(inet_sk(sk)->inet_dport),
			cplios_flag(sk, CPLIOS_MA_FAILOVER) ? 1: 0, atid);
#endif

		skb = alloc_ctrl_skb(cplios->ctrl_skb_cache, sizeof(*req));
		if (!skb) {
			printk("%s: skb alloc failed.. \n", __func__);
			return -ENOMEM;
		}

		req = (struct fw_ofld_connection_wr *)__skb_put(skb, sizeof(*req));
		memset(req, 0, sizeof(*req));
		req->op_compl = htonl(V_WR_OP(FW_OFLD_CONNECTION_WR) |
				      V_FW_WR_COMPL(1));
		req->len16_pkd = htonl(V_FW_WR_LEN16(DIV_ROUND_UP(sizeof(*req), 16)));
		req->le.filter = cpu_to_be32(cxgb4_select_ntuple(cplios->ma_fail_info.egress_dev,
					     cplios->ma_fail_info.l2t_e));
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
					    V_L2T_IDX(cplios->ma_fail_info.l2t_e->idx) |
					    V_SMAC_SEL(cplios->ma_fail_info.smac_idx) |
					    V_TX_CHAN(cplios->ma_fail_info.tx_c_chan) |
					    F_NON_OFFLOAD);

		chan = cxgb4_port_chan((TOEDEV(cplios->ma_fail_info.egress_dev))->lldev[
					cplios->ma_fail_info.port_id]);
		opt2 = V_RX_CHANNEL(cplios->ma_fail_info.rx_c_chan) |
				    V_TX_QUEUE(d->lldi->tx_modq[chan]) |
				    F_RSS_QUEUE_VALID |
				    V_RSS_QUEUE(cplios->ma_fail_info.rss_qid);
		opt2 |= F_RX_COALESCE_VALID |
			V_RX_COALESCE(M_RX_COALESCE);

		if (cplios->ulp_mode == ULP_MODE_TCPDDP)
			opt2 |= F_RX_FC_VALID | F_RX_FC_DDP;

		if (tcp_win_scaling_enabled())
			opt2 |= F_WND_SCALE_EN;

		if (tcp_timestamps_enabled())
			opt2 |= F_TSTAMPS_EN;

		if (tcp_sack_enabled())
			opt2 |= F_SACK_EN;

		req->tcb.opt2 = htonl(opt2);
		req->cookie = (u64) atid;
		set_wr_txq(skb, CPL_PRIORITY_CONTROL, cplios->ma_fail_info.port_id);
		cxgb4_sk_l2t_send(cplios->ma_fail_info.egress_dev, skb,
				cplios->ma_fail_info.l2t_e, sk);
		return 1;
	}
	return 0;
}

void ma_fail_do_fw6_msg(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_fw6_msg *p = cplhdr(skb);
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);

	if (cplios_flag(sk, CPLIOS_MA_FAILOVER)) {
		if (p->type == FW6_TYPE_OFLD_CONNECTION_WR_RPL) {
			struct cpl_fw6_msg_ofld_connection_wr_rpl *req =
				(struct cpl_fw6_msg_ofld_connection_wr_rpl *)p->data;
			unsigned int atid = (unsigned int)req->cookie;
			struct tom_data *t = TOM_DATA(cplios->ma_fail_info.toedev);

			cplios->ma_fail_info.tid = htonl(req->tid);
			sk_insert_tid(t, sk, htonl(req->tid));
			free_atid(t->tids, atid);

			t4_set_tcb_field_mafo(sk, W_TCB_RCV_WND,
					      V_TCB_RCV_WND(M_TCB_RCV_WND),
					      V_TCB_RCV_WND(0ULL),
					      MA_FAILOVER_COOKIE_NEW_RCV_WND,
					      0,
					      CPL_PRIORITY_CONTROL,
					      1, 0);
		}
	}

}

void ma_fail_t4_connect(struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);

	cplios->ma_fail_info.tid = -1;
	cplios->ma_fail_info.toedev = NULL;
	cplios->ma_fail_info.flags = MA_FAIL_NONE;

}

void ma_fail_mk_pass_sock(struct sock *newsk)
{
	struct cpl_io_state *newcplios = CPL_IO_STATE(newsk);

	newcplios->ma_fail_info.tid = -1;
	newcplios->ma_fail_info.toedev = NULL;
	newcplios->ma_fail_info.flags = MA_FAIL_NONE;
	newcplios->ma_fail_info.last_rcv_nxt = 0;
	newcplios->ma_fail_info.rx_retry = 0;

}

void ma_fail_do_rx_pkt_init(void *data)
{
	struct cpl_io_state *cplios = (struct cpl_io_state *)data;

	cplios->ma_fail_info.tid = -1;
	cplios->ma_fail_info.toedev = NULL;
	cplios->ma_fail_info.flags = MA_FAIL_NONE;
	cplios->ma_fail_info.last_rcv_nxt = 0;
	cplios->ma_fail_info.rx_retry = 0;
}


void ma_failover_cleanup(struct sock *sk, int closed)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tid_info *tids;
	struct port_info *pi;
	unsigned int viid;
	struct tom_data *d = TOM_DATA(TOEDEV(cplios->ma_fail_info.egress_dev));

	if (closed) {
		pi = netdev_priv(cplios->egress_dev);
		cplios->ma_fail_info.flags = MA_FAIL_NONE;
	} else {
		pi = netdev_priv(cplios->ma_fail_info.egress_dev);
		tids = TOM_DATA(cplios->ma_fail_info.toedev)->tids;
		cxgb4_remove_tid(tids, cplios->ma_fail_info.port_id,
				 cplios->ma_fail_info.tid, sk->sk_family);
		cplios->ma_fail_info.flags = MA_FAIL_NONE;
		if (sk->sk_family != AF_INET) {
			cxgb4_clip_release(cplios->ma_fail_info.egress_dev,
				(const u32 *)((&inet6_sk_saddr(sk))->s6_addr),
									1);
		}
	}

	cplios->ma_fail_info.last_rcv_nxt = 0;
	cplios->ma_fail_info.rx_retry = 0;
	atomic_dec(&pi->ma_fail_data.conn_moved);
	if (!atomic_read(&pi->ma_fail_data.conn_moved)) {
		struct adapter *adap = netdev2adap(cplios->ma_fail_info.egress_dev);
		/* failover filter can be deleted now... */
		if (pi->ma_fail_data.fidx != -1) {
			cxgb4_delete_ma_failover_filter(pi->ma_fail_data.this_dev,
							0, pi->ma_fail_data.fidx);
			pi->ma_fail_data.fidx = -1;
		}

		if (pi->ma_fail_data.fidx6 != -1) {
			cxgb4_delete_ma_failover_filter(pi->ma_fail_data.this_dev,
							1, pi->ma_fail_data.fidx6);
			pi->ma_fail_data.fidx6 = -1;
		}

		/* restore old l2t config */
		if (closed) {
			viid = cxgb4_port_viid(cplios->egress_dev);
			write_ofld_smt(cplios->egress_dev, 0x0,
				       (G_FW_VIID_VIVLD(viid) << 11) | (viid & ~(1 << 7)),
				       cxgb4_tp_smt_idx(d->lldi->adapter_type, viid));
			cplios->l2t_entry->lport = cplios->port_id;
			t4_l2t_write(adap, cplios->l2t_entry, !L2T_ARPMISS);
		} else {
			viid = cxgb4_port_viid(cplios->ma_fail_info.egress_dev);
			write_ofld_smt(cplios->ma_fail_info.egress_dev, 0x0,
				       (G_FW_VIID_VIVLD(viid) << 11) | (viid & ~(1 << 7)),
				       cxgb4_tp_smt_idx(d->lldi->adapter_type, viid));
			cplios->ma_fail_info.l2t_e->lport = cplios->ma_fail_info.port_id;
			t4_l2t_write(adap, cplios->ma_fail_info.l2t_e, !L2T_ARPMISS);
		}

		skb_queue_purge(&rx_pkts);
		skb_queue_purge(&tx_pkts);

		pi->ma_fail_data.flags = MA_FAILOVER_NONE;
		((struct port_info *)netdev_priv(
			pi->ma_fail_data.backup_dev))->ma_fail_data.flags =
			MA_FAILOVER_NONE;
	}

	if (!closed)
		cxgb4_l2t_release(cplios->ma_fail_info.l2t_e);

	cxgb4_l2t_release(cplios->ma_fail_info.l2t_e_arpmiss);
}

void ma_fail_wr_ack(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (!after(tp->snd_nxt, tp->snd_una)) {
		/*
		 * if we are in ma-failover, and we have reached here,
		 * then, it means that we have retrieved all outstanding
		 * un-Acked Tx payload. Prepare to move the connection
		 * to new adapter.
		 */
		if (cplios_flag(sk, CPLIOS_MA_FAILOVER)) {
			cplios_set_flag(sk, CPLIOS_TX_WAIT_IDLE);
			t4_get_tcb(sk);
		}
	}
}

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
static void ma_fail_mk_act_open_req6(struct sock *sk, struct sk_buff *skb,
				     unsigned int qid_atid,
				     const struct l2t_entry *e)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tom_data *d = TOM_DATA(TOEDEV(cplios->ma_fail_info.egress_dev));
	unsigned short chan;
	u32 opt2;
	struct cpl_act_open_req6 *req6 = NULL;
	struct cpl_t5_act_open_req6 *t5req6 = NULL;
	struct cpl_t6_act_open_req6 *t6req6 = NULL;

	switch (CHELSIO_CHIP_VERSION(d->lldi->adapter_type)) {
	case CHELSIO_T4:
		req6 = (struct cpl_act_open_req6 *)__skb_put(skb, sizeof(*req6));
		INIT_TP_WR(req6, 0);
	break;
	case CHELSIO_T5:
		t5req6 = (struct cpl_t5_act_open_req6 *)__skb_put(skb,
								  sizeof(*t5req6));
		INIT_TP_WR(t5req6, 0);
		req6 = (struct cpl_act_open_req6 *)t5req6;
	break;
	case CHELSIO_T6:
	default:
		t6req6 = (struct cpl_t6_act_open_req6 *)__skb_put(skb,
								  sizeof(*t6req6));
		INIT_TP_WR(t6req6, 0);
		req6 = (struct cpl_act_open_req6 *)t6req6;
		t5req6 = (struct cpl_t5_act_open_req6 *)t6req6;
	break;
	}

	OPCODE_TID(req6) = htonl(MK_OPCODE_TID(CPL_ACT_OPEN_REQ6,
				qid_atid));
	set_wr_txq(skb, CPL_PRIORITY_SETUP,
		   cplios->ma_fail_info.port_id);
	req6->local_port = inet_sk(sk)->inet_sport;
	req6->peer_port = inet_sk(sk)->inet_dport;
	req6->local_ip_hi = *(__be64 *)((&inet6_sk_rcv_saddr(sk))->s6_addr);
	req6->local_ip_lo = *(__be64 *)((&inet6_sk_rcv_saddr(sk))->s6_addr + 8);
	req6->peer_ip_hi = *(__be64 *)((&inet6_sk_daddr(sk))->s6_addr);
	req6->peer_ip_lo = *(__be64 *)((&inet6_sk_daddr(sk))->s6_addr + 8);
	req6->opt0 = cpu_to_be64(calc_opt0(sk) |
				 V_L2T_IDX(e->idx) |
				 V_SMAC_SEL(cplios->ma_fail_info.smac_idx) |
				 V_TX_CHAN(cplios->ma_fail_info.tx_c_chan) |
				 F_NON_OFFLOAD | F_INJECT_TIMER);

	chan = cxgb4_port_chan((TOEDEV(cplios->ma_fail_info.egress_dev))->lldev[
				cplios->ma_fail_info.port_id]);
	opt2 = V_RX_CHANNEL(cplios->ma_fail_info.rx_c_chan) |
			    V_TX_QUEUE(d->lldi->tx_modq[chan]) |
			    F_RSS_QUEUE_VALID |
			    V_RSS_QUEUE(cplios->ma_fail_info.rss_qid);

	if (cplios->ulp_mode == ULP_MODE_TCPDDP)
		opt2 |= F_RX_FC_VALID | F_RX_FC_DDP;

	if (tcp_win_scaling_enabled())
		opt2 |= F_WND_SCALE_EN;

	if (tcp_timestamps_enabled())
		opt2 |= F_TSTAMPS_EN;

	if (tcp_sack_enabled())
		opt2 |= F_SACK_EN;

	if (is_t4(d->lldi->adapter_type)) {
		opt2 |= F_RX_COALESCE_VALID |
			V_RX_COALESCE(M_RX_COALESCE);
		req6->opt2 = htonl(opt2);
	} else {
		t5req6->rsvd = 0;
		t5req6->params = cpu_to_be64(V_FILTER_TUPLE(cxgb4_select_ntuple(cplios->ma_fail_info.egress_dev, e)));

		opt2 |= F_T5_OPT_2_VALID |
			V_RX_COALESCE(M_RX_COALESCE) |
			V_CONG_CNTRL(CONG_ALG_NEWRENO);

		t5req6->opt2 = htonl(opt2);
		if (is_t6(d->lldi->adapter_type)) {
			/* TODO */
			//t6req6->opt3 = htonl(cplios->opt3);
		}
	}
}
#endif

static void ma_fail_mk_act_open_req(struct sock *sk, struct sk_buff *skb,
				    unsigned int qid_atid,
				    const struct l2t_entry *e)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tom_data *d = TOM_DATA(TOEDEV(cplios->ma_fail_info.egress_dev));
	unsigned short chan;
	u32 opt2;
	struct cpl_act_open_req *req = NULL;
	struct cpl_t5_act_open_req *t5req = NULL;
	struct cpl_t6_act_open_req *t6req = NULL;

	switch (CHELSIO_CHIP_VERSION(d->lldi->adapter_type)) {
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
	set_wr_txq(skb, CPL_PRIORITY_SETUP,
		   cplios->ma_fail_info.port_id);
	req->local_port = inet_sk(sk)->inet_sport;
	req->peer_port = inet_sk(sk)->inet_dport;
	req->local_ip = inet_sk(sk)->inet_saddr;
	req->peer_ip = inet_sk(sk)->inet_daddr;
	req->opt0 = cpu_to_be64(calc_opt0(sk) |
				V_L2T_IDX(e->idx) |
				V_SMAC_SEL(cplios->ma_fail_info.smac_idx) |
				V_TX_CHAN(cplios->ma_fail_info.tx_c_chan) |
				F_NON_OFFLOAD | F_INJECT_TIMER);

	chan = cxgb4_port_chan((TOEDEV(cplios->ma_fail_info.egress_dev))->lldev[
				cplios->ma_fail_info.port_id]);
	opt2 = V_RX_CHANNEL(cplios->ma_fail_info.rx_c_chan) |
			    V_TX_QUEUE(d->lldi->tx_modq[chan]) |
			    F_RSS_QUEUE_VALID |
			    V_RSS_QUEUE(cplios->ma_fail_info.rss_qid);

	if (cplios->ulp_mode == ULP_MODE_TCPDDP)
		opt2 |= F_RX_FC_VALID | F_RX_FC_DDP;

	if (tcp_win_scaling_enabled())
		opt2 |= F_WND_SCALE_EN;

	if (tcp_timestamps_enabled())
		opt2 |= F_TSTAMPS_EN;

	if (tcp_sack_enabled())
		opt2 |= F_SACK_EN;

	if (is_t4(d->lldi->adapter_type)) {
		opt2 |= F_RX_COALESCE_VALID |
			V_RX_COALESCE(M_RX_COALESCE);
		req->params = cpu_to_be32(cxgb4_select_ntuple(cplios->ma_fail_info.egress_dev, e));
		req->opt2 = htonl(opt2);
	} else {
		t5req->rsvd = 0;
		t5req->params = cpu_to_be64(V_FILTER_TUPLE(cxgb4_select_ntuple(cplios->ma_fail_info.egress_dev, e)));

		opt2 |= F_T5_OPT_2_VALID |
			V_RX_COALESCE(M_RX_COALESCE) |
			V_CONG_CNTRL(CONG_ALG_NEWRENO);
		t5req->opt2 = htonl(opt2);
		if (is_t6(d->lldi->adapter_type)) {
			/* TODO */
			//t6req->opt3 = htonl(cplios->opt3);
		}
	}
}

/**
 * t4_toe_ma_failover - Carry out Multi-Adap TOE failover
 * @slave_dev: Current active network interface
 * @failed_dev: The failed network interface
 *
 *
 * Move all the offloaded connections, that were running on the
 * failed_dev over to the slave_dev.
 * Stop offload Tx for the connections being moved.
 * Also, drain the Rx on failed_dev for the connections being moved.
 * 
 * If there is outstanding un-Acked payload for the connections being
 * moved, setup a filter to retrieve it, by directing all the payload
 * to the sge's ma-failover queue.
 *
 * Finally, setup a non-offload filter on the slave_dev for the
 * connections being moved.
 */
void t4_toe_ma_failover(struct net_device *slave_dev,
			struct net_device *failed_dev,
			unsigned int bond_req, void *data)
{
	struct toedev *tdev = TOEDEV(failed_dev);
	struct tom_data *t = TOM_DATA(tdev);
	struct tid_info *tinfo = t->tids;
	struct sock *sk;
	struct cpl_io_state *cplios;
	int tid;
	unsigned int tids_in_use, tids_signalled = 0;
	unsigned int viid;

	int atid;
	struct l2t_entry *e, *e_arpmiss;
	struct sk_buff *skb;
	struct adapter *adap ;

	struct tom_data *d = TOM_DATA(TOEDEV(slave_dev));
	struct dst_entry *dst ;
	unsigned int qid_atid;
	struct port_info *pi;
	int ret = 0;
	u32 queue_id;

	tids_in_use = atomic_read(&tinfo->tids_in_use) +
		atomic_read(&tinfo->hash_tids_in_use);
	if (!tids_in_use)
		return;

	pi = netdev_priv (failed_dev);
	if (pi->ma_fail_data.flags == MA_FAILOVER) {
		printk("%s: prev MA-Failover sequence not complete; abort!\n",
			__func__);
		printk("%s: failed_dev = %s; slave_dev = %s\n",
			__func__, failed_dev->name, slave_dev->name);

		/* TODO: Restore l2t entry to original port value.. */
		return;
	}

	pi->ma_fail_data.flags = MA_FAILOVER;
	pi->ma_fail_data.this_dev = failed_dev;
	pi->ma_fail_data.backup_dev = slave_dev;

	((struct port_info *)netdev_priv(slave_dev))->ma_fail_data.flags
		= MA_FAILOVER;
	((struct port_info *)netdev_priv(slave_dev))->ma_fail_data.this_dev
		= slave_dev;
	((struct port_info *)netdev_priv(slave_dev))->ma_fail_data.backup_dev
		= failed_dev;

	for (tid = 0; tid < tinfo->ntids && tids_signalled < tids_in_use ; tid++) {
		if ((sk = lookup_tid(tinfo , tid))) {
			struct tcp_sock *tp;
			struct neighbour *neigh = NULL;
			struct neighbour *neigh_arpmiss = NULL;
			__be32 lpbk_daddr = L2T_INVALID_IP;
			int size, size6;

			sock_hold(sk);
			bh_lock_sock(sk);
			cplios = CPL_IO_STATE(sk);

			if ((sk->sk_state == TCP_SYN_RECV) ||
			    (sk->sk_state == TCP_LAST_ACK))
				goto unlock;

			if (cplios_flag(sk, CPLIOS_ABORT_REQ_RCVD) ||
					cplios_flag(sk, CPLIOS_ABORT_RPL_PENDING) ||
					cplios_flag(sk, CPLIOS_TX_FAILOVER)) {
#ifdef DEBUG
				printk("%s: tid = %u; abort-req-rcvd.. \n",
						__func__, cplios->tid);
#endif
				goto unlock;
			}

			if (cplios_flag(sk, CPLIOS_CLOSE_CON_REQUESTED)) {
				tp = tcp_sk(sk);
#ifdef DEBUG
				printk("%s: tid = %u close-con-requested.."
                                       "sk->sk_state = %d; snd_nxt = %u; "
                                       "snd_una = %u\n",
                                       __func__, cplios->tid, sk->sk_state,
                                       tp->snd_nxt, tp->snd_una);
#endif
			}

			/*
			 * make sure that we move only those connections which
			 * were running over the failed_dev
			 */
			if (cplios->egress_dev != failed_dev) {
                               printk("%s: tid = %u; egress is not failed ..\n",
                                       __func__, cplios->tid);
			       goto unlock;
			}

			/*
			 * Don't touch connections which are still in MA-Failover
			 * sequence. These are usually stuck connections. So, don't try
			 * to move them to another adapter since there is no use.
			 */
			if (unlikely(cplios_flag(sk, CPLIOS_MA_FAILOVER))) {
				tp = tcp_sk(sk);
				printk("%s: Already in MA-Failover!! "
                                       "0x%x: %u -> 0x%x: %u ; tid = %u;"
                                       "snd_nxt = %u; snd_una = %u\n",
                                       __func__, htonl(inet_sk(sk)->inet_saddr),
                                       htons(inet_sk(sk)->inet_sport),
                                       htonl(inet_sk(sk)->inet_daddr),
                                       htons(inet_sk(sk)->inet_dport),
                                       cplios->tid, tp->snd_nxt, tp->snd_una);
                               goto unlock;
                       }

			cplios_set_flag(sk, CPLIOS_MA_FAILOVER);
			cplios_set_flag(sk, CPLIOS_TX_WAIT_IDLE);
			atomic_inc(&pi->ma_fail_data.conn_moved);

			smp_mb();

			t4_ma_failover_drain_rx(sk);

			tp = tcp_sk(sk);
			if (after(tp->snd_nxt,tp->snd_una)) {
				/*
				 * there seems to be outstanding un-Acked Tx payload.
				 * Setup a filter to retrieve it.
				 */
				adap = netdev2adap(failed_dev);
				queue_id = adap->sge.failoverq.rspq.abs_id;

				if (sk->sk_family == AF_INET &&
						pi->ma_fail_data.fidx < 0) {
					ret = cxgb4_create_ma_failover_filter(
							failed_dev,
							cplios->port_id + 4,
							queue_id,
							inet_sk(sk)->inet_rcv_saddr,
							0, NULL);
					if (ret < 0) {
#ifdef T4_TRACE
						T4_TRACE1(TIDTB(sk),
							  "create-ma-failover"
							  " filter failed with"
							  "ret = %d for IPv4\n",
							  ret);
#endif
						bh_unlock_sock(sk);
						sock_put(sk);
						return;
					}
					pi->ma_fail_data.fidx = ret;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
				} else if (sk->sk_family == AF_INET6 &&
						pi->ma_fail_data.fidx6 < 0) {
					ret = cxgb4_create_ma_failover_filter(
							failed_dev,
							cplios->port_id + 4,
							queue_id, 0, 1,
							&inet6_sk_rcv_saddr(sk));
#endif
					if (ret < 0) {
#ifdef T4_TRACE
						T4_TRACE1(TIDTB(sk),
							  "create-ma-failover"
							  " filter failed with"
							  "ret = %d for IPv6\n",
							  ret);
#endif
						bh_unlock_sock(sk);
						sock_put(sk);
						return;
					}
					pi->ma_fail_data.fidx6 = ret;
				}
			}

			kref_get(&cplios->kref);
			atid = cxgb4_alloc_atid(d->tids, cplios);
			if (atid < 0) {
#ifdef T4_TRACE
				T4_TRACE1(TIDTB(sk),
                                         "Failed to allocate atid = %d\n", atid);
#endif

				bh_unlock_sock(sk);
				sock_put(sk);
				return;
			}
			cplios->sk = sk;
			cplios->ma_fail_info.flags = MA_FAIL_OVER;
			cplios->ma_fail_info.egress_dev = slave_dev;
			tasklet_init(&cplios->ma_fail_info.get_tcb_task,
					ma_failover_get_tcb_task,
					(unsigned long)sk);
			hrtimer_init(&cplios->ma_fail_info.rx_drain_timer,
					CLOCK_MONOTONIC, HRTIMER_MODE_REL);
			cplios->ma_fail_info.rx_drain_timer.function =
				ma_failover_rx_drain_timeout;


			dst = __sk_dst_get(sk);
			if (sk->sk_family == AF_INET)
				neigh = t4_dst_neigh_lookup(dst, &inet_sk(sk)->inet_daddr);
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
			else
				neigh = t4_dst_neigh_lookup(dst, &inet6_sk_daddr(sk));
#endif
			if (!neigh) {
#ifdef T4_TRACE
				T4_TRACE0(TIDTB(sk), "dst->_neighbour is NULL\n");
#endif
				bh_unlock_sock(sk);
				sock_put(sk);
				return;
			}

			e = cxgb4_l2t_get(d->lldi->l2t, neigh,
					  slave_dev, sk->sk_priority);
			t4_dst_neigh_release(neigh);
			if (!e) {
#ifdef T4_TRACE
				T4_TRACE1(TIDTB(sk), "Failed to get l2t entry = %d\n", 1);
#endif
				bh_unlock_sock(sk);
				sock_put(sk);
				return;
			}

			memcpy(e->dmac, cplios->l2t_entry->dmac, sizeof(u8) * 6);
			e->state = 0;
			adap = netdev2adap(slave_dev);
			t4_l2t_write(adap, e, !L2T_ARPMISS);

			/* Setup dummy l2t entry with arp-miss bit set on failed adapter */
			neigh_arpmiss = t4_dst_neigh_lookup(dst, &lpbk_daddr);
			if (!neigh_arpmiss) {
#ifdef T4_TRACE
				T4_TRACE0(TIDTB(sk), "dst->_neighbour is NULL\n");
#endif
				bh_unlock_sock(sk);
				sock_put(sk);
				return;
			}

			e_arpmiss = cxgb4_l2t_get(t->lldi->l2t, neigh_arpmiss,
						  failed_dev, sk->sk_priority);
			t4_dst_neigh_release(neigh_arpmiss);
			if (!e_arpmiss) {
				printk("%s: did not get dummy l2t entry... \n\n", __func__);
				bh_unlock_sock(sk);
				sock_put(sk);
				return;
			}
			e_arpmiss->dmac[0] = 0xd;
			e_arpmiss->dmac[1] = 0xe;
			e_arpmiss->dmac[2] = 0xa;
			e_arpmiss->dmac[3] = 0xa;
			e_arpmiss->dmac[4] = 0xe;
			e_arpmiss->dmac[5] = 0xd;
			e_arpmiss->state = 0;
			adap = netdev2adap(failed_dev);
			t4_l2t_write(adap, e_arpmiss, L2T_ARPMISS);

			if (sk->sk_family != AF_INET) {
				if (cxgb4_clip_get(slave_dev, (const u32 *)
				    ((&inet6_sk_saddr(sk))->s6_addr), 1)) {
					bh_unlock_sock(sk);
					sock_put(sk);
					return;
				}
			}

			switch (CHELSIO_CHIP_VERSION(d->lldi->adapter_type)) {
			case CHELSIO_T4:
				size = sizeof(struct cpl_act_open_req);
				size6 = sizeof(struct cpl_act_open_req6);
			break;
			case CHELSIO_T5:
				size = sizeof(struct cpl_t5_act_open_req);
				size6 = sizeof(struct cpl_t5_act_open_req6);
			break;
			case CHELSIO_T6:
			default:
				size = sizeof(struct cpl_t6_act_open_req);
				size6 = sizeof(struct cpl_t6_act_open_req6);
			break;
			}

			if (sk->sk_family == AF_INET)
				skb = alloc_skb(size, GFP_ATOMIC | __GFP_NOFAIL);
			else
				skb = alloc_skb(size6, GFP_ATOMIC | __GFP_NOFAIL);

			skb->sk = sk;
			cplios->ma_fail_info.toedev = TOEDEV(slave_dev);
			cplios->ma_fail_info.tid = atid;
			cplios->ma_fail_info.l2t_e = e;
			cplios->ma_fail_info.l2t_e_arpmiss = e_arpmiss;
			cplios->ma_fail_info.tx_c_chan =
				cxgb4_port_chan(slave_dev);
			cplios->ma_fail_info.rx_c_chan = 0;
			cplios->ma_fail_info.smac_idx =
				cxgb4_tp_smt_idx(d->lldi->adapter_type,
						 cxgb4_port_viid(slave_dev));

			if (netdev_is_offload(slave_dev)) {
				cplios->ma_fail_info.port_id =
					((struct port_info *)netdev_priv(slave_dev))->port_id;
				cplios->ma_fail_info.port_speed =
					((struct port_info *)netdev_priv(slave_dev))->link_cfg.speed;
			}

			cplios->ma_fail_info.txq_idx =
				cplios->ma_fail_info.port_id*d->lldi->ntxq/d->lldi->nchan;
			cplios->ma_fail_info.rss_qid =
				d->lldi->rxq_ids[cplios->ma_fail_info.port_id*
				d->lldi->nrxq/d->lldi->nchan];

			qid_atid = cplios->ma_fail_info.rss_qid << 14;
			qid_atid |= (unsigned int)atid;

			if (sk->sk_family == AF_INET)
				ma_fail_mk_act_open_req(sk, skb, qid_atid, e);
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
			else
				ma_fail_mk_act_open_req6(sk, skb, qid_atid, e);
#endif
			cxgb4_sk_l2t_send(cplios->ma_fail_info.egress_dev, skb, e, sk);

			tids_signalled++;
unlock:
			bh_unlock_sock(sk);
			sock_put(sk);
		}
	}

	viid = cxgb4_port_viid(failed_dev);
	write_ofld_smt(failed_dev, 0x0, (0 << 11) | (viid & ~(1 << 7)),
		       cxgb4_tp_smt_idx(t->lldi->adapter_type, viid));
	update_l2t(tdev, bond_req, data);
}

int ma_fail_chelsio_sendpage(struct sock *sk, long timeo)
{
	int err;

	if (cplios_flag(sk, CPLIOS_MA_FAILOVER)) {
		err = wait_for_ma_fail_info(sk, &timeo);
		if (cplios_flag(sk, CPLIOS_MA_FAILOVER)) {
			release_sock(sk);
#ifdef DEBUG
			printk("%s: returning as ma-failover still exists.. tid = %u\n",
				__func__, CPL_IO_STATE(sk)->tid);
#endif
			return 1;
		}
	}
	return 0;
}

int ma_fail_chelsio_sendmsg(struct sock *sk, long timeo)
{
	int err;

	if (cplios_flag(sk, CPLIOS_MA_FAILOVER)) {
		err = wait_for_ma_fail_info(sk, &timeo);
		if (cplios_flag(sk, CPLIOS_MA_FAILOVER)) {
			release_sock(sk);
#ifdef DEBUG
			printk("%s: returning as ma-failover still exists.. tid = %u\n",
				__func__, CPL_IO_STATE(sk)->tid);
#endif
			return 1;
		}
	}
	return 0;
}

int ma_fail_chelsio_shutdown(struct sock *sk)
{
	if (cplios_flag(sk, CPLIOS_MA_FAILOVER))
		return 1;

	return 0;
}

int ma_fail_chelsio_close(struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);

	if (cplios_flag(sk, CPLIOS_MA_FAILOVER) ||
	    cplios->ma_fail_info.flags != MA_FAIL_NONE) {
		long timeo = 200;
		struct cpl_io_state *cplios = CPL_IO_STATE(sk);

		wait_for_ma_fail_info_close(sk, &timeo);
		if (cplios_flag(sk, CPLIOS_MA_FAILOVER) ||
		    cplios->ma_fail_info.flags != MA_FAIL_NONE) {
			release_sock(sk);
#ifdef DEBUG
			printk("%s: returning as ma-failover still exists.. tid = %u\n",
				__func__, cplios->tid);
#endif
			return 1;
		}
	}
	return 0;

}

int ma_fail_t4_send_reset(struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	int ret = 0;

	if (cplios_flag(sk, CPLIOS_MA_FAILOVER) ||
	    cplios->ma_fail_info.flags != MA_FAIL_NONE) {
		cplios_set_flag(sk, CPLIOS_ABORT_RPL_PENDING);
		ret = 1;
	}

	return ret;
}

int ma_fail_do_peer_fin(struct sock *sk, int state)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	int ret = 0;

	switch (state) {
	case TCP_FIN_WAIT2:
		/*
		 * If we are in ma-failover then, this conn is gone. Cleanup on
		 * failed adapter. Also, abort the non-offload mode act-open
		 * connection on new adapter
		 */
		if (cplios_flag(sk, CPLIOS_MA_FAILOVER) ||
		    cplios->ma_fail_info.flags != MA_FAIL_NONE) {
			if (cplios->ma_fail_info.flags == MA_FAIL_OVER) {
				struct tid_info *tids;
				tids = TOM_DATA(cplios->ma_fail_info.toedev)->tids;

				cplios->ma_fail_info.flags = MA_FAIL_ABORT;

				if (hrtimer_active(&cplios->ma_fail_info.rx_drain_timer))
					hrtimer_cancel(&cplios->ma_fail_info.rx_drain_timer);
				t4_get_tcb(sk);
				ret = 1;
			} else if (cplios->ma_fail_info.flags == MA_FAIL_DONE) {
				cplios_set_flag(sk, CPLIOS_ABORT_RPL_PENDING);
				ret = 1;
			}
		}
	}
	return ret;
}

int ma_fail_process_close_con_rpl(struct sock *sk, int state)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	int ret = 0;

	switch (state) {
	case TCP_CLOSING:
	case TCP_LAST_ACK:
		/*
		 * If we are in ma-failover then, this conn is gone. Cleanup on
		 * failed adapter. Also, abort the non-offload mode act-open
		 * connection on new adapter
		 */
		if (cplios_flag(sk, CPLIOS_MA_FAILOVER) ||
		    cplios->ma_fail_info.flags != MA_FAIL_NONE) {
			if (cplios->ma_fail_info.flags == MA_FAIL_OVER ) {
				struct tid_info *tids;
				tids = TOM_DATA(cplios->ma_fail_info.toedev)->tids;

				cplios->ma_fail_info.flags = MA_FAIL_ABORT;

				if (hrtimer_active(&cplios->ma_fail_info.rx_drain_timer))
					hrtimer_cancel(&cplios->ma_fail_info.rx_drain_timer);
				t4_get_tcb(sk);
				ret = 1;
			} else if (cplios->ma_fail_info.flags == MA_FAIL_DONE) {
				cplios_set_flag(sk, CPLIOS_ABORT_RPL_PENDING);
				ret = 1;
			}
		}
		break;
	}
	return ret;
}

int ma_fail_process_abort_rpl(struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);

	if (sk->sk_state == TCP_CLOSE)
		return 1;

	if (cplios_flag(sk, CPLIOS_MA_FAILOVER) ||
			cplios->ma_fail_info.flags == MA_FAIL_DONE) {
		ma_failover_cleanup(sk, 0);

		if (cplios_flag(sk, CPLIOS_ABORT_RPL_PENDING)) {
			struct sk_buff *skb = alloc_skb(sizeof(struct cpl_abort_req), GFP_ATOMIC);
			if (!skb) {
				printk("%s: skb is NULL .. \n", __func__);
				return 1;
			}

			t4_send_reset(sk, CPL_ABORT_NO_RST, skb);
		}
		return 1;
	}


	if (cplios_flag(sk, CPLIOS_MA_FAILOVER) ||
			cplios->ma_fail_info.flags == MA_FAIL_ABORT) {
		ma_failover_cleanup(sk, 0);
		cplios_set_flag(sk, CPLIOS_ABORT_RPL_PENDING);
	}

	return 0;
}

int ma_fail_process_abort_req(struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	int ret = 0;

	if (cplios_flag(sk, CPLIOS_MA_FAILOVER) ||
	    cplios->ma_fail_info.flags != MA_FAIL_NONE) {
		if (cplios->ma_fail_info.flags == MA_FAIL_OVER) {
			struct tid_info *tids;
			tids = TOM_DATA(cplios->ma_fail_info.toedev)->tids;

			cplios->ma_fail_info.flags = MA_FAIL_ABORT;
			if (hrtimer_active(&cplios->ma_fail_info.rx_drain_timer))
				hrtimer_cancel(&cplios->ma_fail_info.rx_drain_timer);
			t4_get_tcb(sk);
			ret = 1;
		}  else if (cplios->ma_fail_info.flags == MA_FAIL_DONE) {
			cplios->ma_fail_info.flags = MA_FAIL_ABORT;
                        ret = 1;
                }

	}
	return ret;
}

int ma_fail_t4_send_rx_credits(struct sock *sk)
{
	if (cplios_flag(sk, CPLIOS_MA_FAILOVER)) {
		/*
		 * We don't want to send rx-data-ack during failover, and thereby,
		 * allowing rcv_wnd to re-open. We, in fact, want the rcv_wnd
		 * to stay on zero till the time ma-failover is complete.
		 * So, simply return from here.
		 */
		return 1;
	}

	return 0;
}

static void process_rx_pkts(struct work_struct *work)
{
        struct sk_buff *skb = NULL;
	const struct net_device_ops *ops;
	struct netdev_queue *txq;
	unsigned long flags;

        while ((skb = skb_dequeue(&rx_pkts))) {
		ops = skb->dev->netdev_ops;
		txq = netdev_get_tx_queue(skb->dev, skb_get_queue_mapping(skb));

		if (netif_tx_queue_stopped(txq)) {
			dev_kfree_skb(skb);
			continue;
		}

		/*
		 * This traffic is most likely for the connection which still
		 * exists on the failed_adapter. This will eventually get
		 * looped-back in t4_eth_xmit so as to reach the failed_dev
		 */
		local_irq_save(flags);
		__netif_tx_lock(txq, smp_processor_id());

		if (ops->ndo_start_xmit(skb, skb->dev) != NETDEV_TX_OK) {
#ifdef DEBUG
			printk("%s: error in xmit...\n", __func__);
#endif
			__netif_tx_unlock(txq);
			local_irq_restore(flags);
			dev_kfree_skb(skb);
			continue;
		}

		__netif_tx_unlock(txq);
		local_irq_restore(flags);
        }
}

static DECLARE_WORK(rx_pkt_work, process_rx_pkts);

int ma_fail_do_rx_pkt(void *td_ptr, struct sk_buff *skb)
{
	struct ethhdr *eh;
	struct vlan_ethhdr *vlan_eh = NULL;
	struct iphdr *iph;
	struct cpl_rx_pkt *cpl;
	struct rss_header *rss;
	struct net_device *egress = NULL;
	struct port_info *pi;
	u16 eth_hdr_len;
	struct tom_data *td = (struct tom_data *)td_ptr;
	static int queue_index;

	pi = netdev_priv(skb->dev);
	if (pi->ma_fail_data.flags == MA_FAILOVER) {
		/*
		 * if we are in MA-Failover, then we are here because of traffic
		 * coming from peer while the connections on new adapter are still
		 * in non-offload mode.
		 *
		 * Now, this traffic can be either Rx payload from peer, OR
		 * Acks for Tx sent out from new adapter.
		 */
		rss = (void *)skb->data;
		cpl = (void *)(rss);

		if (CHELSIO_CHIP_VERSION(td->lldi->adapter_type) <= CHELSIO_T5)
			eth_hdr_len = is_t4(td->lldi->adapter_type) ?
						G_RX_ETHHDR_LEN(htonl(cpl->l2info)) :
						G_RX_T5_ETHHDR_LEN(htonl(cpl->l2info));
		else /* T6 and later */
			eth_hdr_len = G_RX_T6_ETHHDR_LEN(htonl(cpl->l2info));

		if (eth_hdr_len == ETH_HLEN) {
			u8 *eth_preamble = (u8 *)(cpl + 1);
			eh = (struct ethhdr *)(eth_preamble + 8);
			iph = (struct iphdr *)(eh + 1);
		} else {
			u8 *eth_preamble = (u8 *)(cpl + 1);
			vlan_eh = (struct vlan_ethhdr *)(eth_preamble + 8);
			iph = (struct iphdr *)(vlan_eh + 1);
			skb->vlan_tci = ntohs(cpl->vlan);
		}

		if (!((iph->version == 0x4) || (iph->version == 0x6)))
			goto free_skb;

		__skb_pull(skb, sizeof(struct cpl_rx_pkt) + (sizeof(u8)*8));
		skb_reset_mac_header(skb);
		skb_reset_network_header(skb);
		skb_reset_transport_header(skb);
		egress = pi->ma_fail_data.backup_dev;
		skb->dev = egress;
		skb->cb[0] = CPL_RX_PKT;

		if (cpl->vlan_ex) {
			skb = t4_vlan_insert_tag(skb, htons(ETH_P_8021Q),
						 ntohs(cpl->vlan));
			if (!skb) {
				printk("%s: failed in vlan_insert_tag..\n", __func__);
				return 1;
			}
		}

		queue_index = (queue_index + 1) % egress->real_num_tx_queues;
		skb_set_queue_mapping(skb, queue_index);
		skb_queue_tail(&rx_pkts, skb);
		queue_work(rx_pkt_workq, &rx_pkt_work);
		return 1;

free_skb:
		dev_kfree_skb(skb);
		return 1;
	} else if (pi->ma_fail_data.flags == MA_FAILOVER_TRANS) {
#ifdef DEBUG
		printk("%s: In MA_FAILOVER_TRANS.. drop packets..\n", __func__);
#endif
		dev_kfree_skb(skb);
		return 1;
	} else {
		/*
		 * If we are doing MA-Failover test, and we have arrived here
		 * then, we are dealing with a race described below:-
		 * - We have a server running on DUT which creates a server tid
		 *   on both Active and Standby adapter.
		 * - Link down happens on Active slave. However, any or all of
		 *   below events are not processed yet (which would happen in
		 *   below sequence):-
		 *   1) Link down event handling by NIC driver
		 *   2) Change of Active slave by Bonding driver
		 *   3) Processing Failover event by TOM driver
		 * - Since any of above is not processed yet, DUT would start
		 *   receiving traffic from peer on Standby adapter since,
		 *   there is a server filter present corresponding to the
		 *   offloaded server.
		 * - Now, this is an interim state, and the above 3 events would
		 *   eventually get processed. Till the time the last event (3)
		 *   is processed, we should drop incoming packets sneaking in
		 *   as cpl-rx-pkt.
		 * - Below is a rudimentary hack to figure out if the interface
		 *   on which the cpl-rx-pkt is received is part of MA-Failover.
		 *   If it is then, we move the corresponding port-info to
		 *   interim state MA_FAILOVER_TRANS during which we drop all
		 *   incoming cpl-rx-pkt.
		 *   We do this because we know that after above list 3 events
		 *   are processed then, MA-Failover sequence would eventually
		 *   take over.
		 * - Nevertheless, below is still a rudimentary hack and may not
		 *   work for all possible bonding combinations for MA-Failover.
		 */
		rcu_read_lock();
		if (skb->dev->flags & IFF_SLAVE) {
			struct net_device *bond_dev = netdev_master_upper_dev_get_rcu(skb->dev);
			struct bonding *bond = (struct bonding *)netdev_priv(bond_dev);
			struct toedev *slave_tdev = NULL;
			struct slave *slave;
			int slaves = 0, mafo = 0;
			bond_list_iter bond_list_iter __attribute__((unused));

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0)
			read_lock_bh(&bond->lock);
#endif
			bond_for_each_slave_rcu_compat(bond, slave, bond_list_iter) {
				slaves++;
				if (!slave_tdev)
					slave_tdev = TOEDEV(slave->dev);
				else if (slave_tdev != TOEDEV(slave->dev))
					mafo = 1;
			}
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0)
			read_unlock_bh(&bond->lock);
#endif

			if (slaves == 2 && mafo == 1) {
				pi->ma_fail_data.flags = MA_FAILOVER_TRANS;
				rcu_read_unlock();
				dev_kfree_skb(skb);
				return 1;
			}
		}
		rcu_read_unlock();
	}

	return 0;
}


static void process_tx_pkts(struct work_struct *work)
{
        struct sk_buff *skb = NULL;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct dst_entry *dst = NULL;
	static int queue_index;
	struct rtable *rt;
	struct neighbour *neigh = NULL;
	struct cpl_rx_pkt *cpl;
	struct netdev_queue *txq;
#ifdef CONFIG_TCPV6_OFFLOAD
	const struct ipv6hdr *ip6h;
#endif
	int err = 0;

        while ((skb = skb_dequeue(&tx_pkts))) {
		cpl = cplhdr(skb);
		iph = (struct iphdr *)skb_network_header(skb);
		tcph = (struct tcphdr *)skb_transport_header(skb);

		if (iph->version == 0x4) {
			rt = find_route(iph->saddr, iph->daddr, tcph->source,
					tcph->dest, iph->tos);
			if (!rt)
				goto free_skb;
			dst = &rt->dst;
			neigh = t4_dst_neigh_lookup(dst, &iph->daddr);
			if (!neigh) {
				dst_release(dst);
				goto free_skb;
			}
		}
#ifdef CONFIG_TCPV6_OFFLOAD
		else if (iph->version == 0x6) {
			struct flowi6 fl6;

			ip6h = (const struct ipv6hdr *)iph;
			memset(&fl6, 0, sizeof(fl6));
			fl6.flowi6_proto = IPPROTO_TCP;
			fl6.saddr = ip6h->saddr;
			fl6.daddr = ip6h->daddr;
			fl6.fl6_dport = tcph->dest;
			fl6.fl6_sport = tcph->source;

			dst = ip6_route_output(&init_net, NULL, &fl6);
			if (!dst)
				goto free_skb;
			neigh = t4_dst_neigh_lookup(dst, &ip6h->daddr);
			if (!neigh) {
				dst_release(dst);
				goto free_skb;
			}
		}
#endif

		__skb_pull(skb, sizeof(struct  cpl_rx_pkt) + (sizeof(u8)*8) );
		skb_reset_mac_header(skb);
		skb_reset_network_header(skb);
		skb_reset_transport_header(skb);
		skb_copy_to_linear_data(skb, neigh->ha,  sizeof(u8) * 6);

		if (cpl->vlan_ex) {
			skb = t4_vlan_insert_tag(skb, htons(ETH_P_8021Q),
					         ntohs(cpl->vlan));
			if (!skb) {
				printk("%s: failed in vlan_insert_tag..\n", __func__);
				t4_dst_neigh_release(neigh);
				dst_release(dst);
				continue;
			}
		}

get_next_tx_queue:
		queue_index = (queue_index + 1) % skb->dev->real_num_tx_queues;
		skb_set_queue_mapping(skb, queue_index);
		txq = netdev_get_tx_queue(skb->dev, skb_get_queue_mapping(skb));

		if (netif_tx_queue_stopped(txq))
			goto get_next_tx_queue;

		if ((err = dev_queue_xmit(skb)) != NET_XMIT_SUCCESS) {
#ifdef DEBUG
			printk("%s: error in xmit...err = %d\n", __func__, err);
#endif
		}

		t4_dst_neigh_release(neigh);
		dst_release(dst);
		continue;

free_skb:
		dev_kfree_skb(skb);
	}
}

static DECLARE_WORK(tx_pkt_work, process_tx_pkts);

/**
 * t4tom_ma_failover_handler - process outstanding un-Acked Tx payload
 *
 * In ma-failover, here we get the outstanding un-Acked Tx payload retrieved
 * from the connection on failed_dev via creating a filter which redirects
 * it to the sge's ma-failover queue.
 * Send it out over the new adapter to the peer.
 */
int t4tom_ma_failover_handler(void *handle, const __be64 *rsp,
			      const struct pkt_gl *gl)
{

	struct ethhdr *eh = NULL;
	struct vlan_ethhdr *vlan_eh = NULL;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct rss_header *rss;
	struct cpl_rx_pkt *cpl;
	struct port_info *pi;
	struct tom_data *td = handle;
	struct sk_buff *skb;
	u16 eth_hdr_len;
	int iff;

	skb = copy_gl_to_skb_pkt(gl , rsp, td->lldi->sge_pktshift);
	if (skb == NULL)
		return 0;


	rss = (void *)skb->data;
	cpl = (void *)(rss);
	iff = cpl->iff;
	pi = netdev_priv(td->egr_dev[iff]);

	if (CHELSIO_CHIP_VERSION(td->lldi->adapter_type) <= CHELSIO_T5)
		eth_hdr_len = is_t4(td->lldi->adapter_type) ?
					G_RX_ETHHDR_LEN(htonl(cpl->l2info)) :
					G_RX_T5_ETHHDR_LEN(htonl(cpl->l2info));
	else /* T6 and later */
		eth_hdr_len = G_RX_T6_ETHHDR_LEN(htonl(cpl->l2info));

	if (eth_hdr_len == ETH_HLEN) {
		u8 *eth_preamble = (u8 *)(cpl + 1);
		eh = (struct ethhdr *)(eth_preamble + 8);
		iph = (struct iphdr *)(eh + 1);
	} else {
		u8 *eth_preamble = (u8 *)(cpl + 1);
		vlan_eh = (struct vlan_ethhdr *)(eth_preamble + 8);
		iph = (struct iphdr *)(vlan_eh + 1);
		skb->vlan_tci = ntohs(cpl->vlan);
	}

	if (!((iph->version == 0x4) || (iph->version == 0x6)))
		goto free_skb;

	tcph = (struct tcphdr *)(iph + 1);
	skb_set_network_header(skb, (void *)iph - (void *)cpl);
	skb_set_transport_header(skb, (void *)tcph - (void *)cpl);
	skb->dev = pi->ma_fail_data.backup_dev;
	skb_queue_tail(&tx_pkts, skb);
	queue_work(tx_pkt_workq, &tx_pkt_work);
	return 0;

free_skb:
	dev_kfree_skb(skb);
	return 0;
}
#endif
