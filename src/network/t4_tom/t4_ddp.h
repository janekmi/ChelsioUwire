/*
 * Definitions for TCP DDP.
 *
 * Copyright (C) 2006-2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef T4_DDP_H
#define T4_DDP_H

#include "t4_msg.h"
#include "t4_ddp_state.h"
#include "cpl_io_state.h"

/*
 * Returns 1 if a UBUF DMA buffer might be active.
 */
static inline int t4_ddp_ubuf_pending(struct sock *sk)
{
	struct ddp_state *p = DDP_STATE(sk);

	/* When the TOM_TUNABLE(ddp) is enabled, we're always in ULP_MODE DDP,
	 * but DDP_STATE() is only valid if the connection actually enabled
	 * DDP.
	 */
	if (!p->ddp_setup)
		return 0;

	return (p->buf_state[1].flags & DDP_BF_NOCOPY);
}

static inline bool t4_ddp_indicate_ok(struct ddp_state *p)
{
	return !p->indicate && !p->indout_count && !p->ubuf_ddp_pending;
}

static inline void t4_ddp_post_indicate(struct sock *sk)
{
	struct ddp_state *p = DDP_STATE(sk);

	if (p->ddp_setup && t4_ddp_indicate_ok(p)) {
		p->indicate = tcp_sk(sk)->rcv_nxt;
		t4_setup_indicate_modrx(sk);
		p->indout_count++;
	}
}

static inline bool t4_ddp_cancel_push_disable(struct sock *sk, bool waitall)
{
	return waitall && t4_ddp_ubuf_pending(sk) &&
		skb_queue_empty(&sk->sk_receive_queue) &&
		!(sk->sk_err || (sk->sk_state == TCP_CLOSE) || sk_no_receive(sk));
}

int t4_setup_ppods(struct sock *sk, const struct ddp_gather_list *gl,
		   unsigned int nppods, unsigned int tag, unsigned int maxoff,
		   unsigned int pg_off, unsigned int color);
int t4_alloc_ppods(struct tom_data *td, unsigned int n);
void t4_free_ppods(struct tom_data *td, unsigned int tag, unsigned int n);
void t4_free_ddp_gl(struct sock *sk, unsigned int idx);
int t4_pin_pages(struct pci_dev *pdev, unsigned long uaddr, size_t len,
		 struct ddp_gather_list **newgl,
		 struct ddp_state *p);
int t4_map_pages(struct pci_dev *pdev, unsigned long uaddr, size_t len,
                 struct ddp_gather_list **newgl,
                 struct ddp_state *p);
int t4_post_ubuf(struct sock *sk, struct msghdr *msg, int nonblock,
		 int rcv_flags);
void t4_cancel_ubuf(struct sock *sk, long *timeo);
int t4_enter_ddp(struct sock *sk, unsigned int indicate_size, unsigned int waitall, int nonblock);
void t4_cleanup_ddp(struct sock *sk);
void t4_release_ddp_resources(struct sock *sk);
int t4_cancel_ddpbuf(struct sock *sk, unsigned int bufidx);
int t4_setup_ddpbufs(struct sock *sk, unsigned int len0, unsigned int offset0,
		     unsigned int len1, unsigned int offset1,
		     u64 ddp_flags, u64 flag_mask);

static inline void t4_shutdown_ddp(struct sock *sk)
{
	t4_disable_ddp(sk);
	t4_release_ddp_resources(sk);
	t4_cleanup_ddp(sk);
}

#endif  /* T4_DDP_H */
