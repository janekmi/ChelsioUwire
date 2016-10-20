/*
 * libilro.h: Chelsio iSCSI LRO functions for T4/5 iSCSI driver.
 *
 * Copyright (c) 2014 Chelsio Communications, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Written by: Karen Xie (kxie@chelsio.com)
 */

#ifndef	__LIBILRO_H__
#define	__LIBILRO_H__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/skbuff.h>

#define LRO_FLUSH_TOTALLEN_MAX	65535
struct cxgbi_rx_lro_cb {
	struct sock *sk;
	unsigned int pdu_totallen;
	unsigned char lro_on;
	unsigned char pdu_cnt;
	unsigned char pdu_idx_off;
	unsigned char frag_idx_off;
};

struct cxgbi_rx_pdu_cb {
	unsigned int seq;
	unsigned int ddigest;
	unsigned short pdulen;
	unsigned short flags;
	unsigned char pi_flags;
	unsigned char frags;
	unsigned char filler[2];
};

#define LRO_SKB_MAX_HEADROOM  \
		(sizeof(struct cxgbi_rx_lro_cb) + \
		 MAX_SKB_FRAGS * sizeof(struct cxgbi_rx_pdu_cb))

#define LRO_SKB_MIN_HEADROOM  \
		(sizeof(struct cxgbi_rx_lro_cb) + \
		 sizeof(struct cxgbi_rx_pdu_cb))

#define cxgbi_skb_rx_lro_cb(skb)	((struct cxgbi_rx_lro_cb *)skb->head)
#define cxgbi_skb_rx_pdu_cb(skb,i)	\
	((struct cxgbi_rx_pdu_cb *)(skb->head + sizeof(struct cxgbi_rx_lro_cb) \
					+ i * sizeof(struct cxgbi_rx_pdu_cb)))

static inline void  cxgbi_lro_skb_dump(struct sk_buff *skb)
{
	struct skb_shared_info *ssi = skb_shinfo(skb);
	struct cxgbi_rx_lro_cb *lro_cb = cxgbi_skb_rx_lro_cb(skb);
	struct cxgbi_rx_pdu_cb *pdu_cb = cxgbi_skb_rx_pdu_cb(skb, 0);
	int pdu_max = lro_cb->pdu_cnt + lro_cb->pdu_idx_off;
	int i;

	pr_info("skb 0x%p, head 0x%p, 0x%p, len %u,%u, frags %u.\n",
		skb, skb->head, skb->data, skb->len, skb->data_len,
		ssi->nr_frags);
	pr_info("skb 0x%p, lro_cb, sk 0x%p, pdu %u, %u, lro_on %d, off %u,%u.\n",
		skb, lro_cb->sk, lro_cb->pdu_cnt, lro_cb->pdu_totallen,
		lro_cb->lro_on, lro_cb->pdu_idx_off, lro_cb->frag_idx_off);

	for (i = 0; i < pdu_max; i++, pdu_cb++)
		pr_info("skb 0x%p, pdu %d, %u, f 0x%x, seq 0x%x, dcrc 0x%x, "
			"frags %u, pi f 0x%x.\n",
			skb, i, pdu_cb->pdulen, pdu_cb->flags, pdu_cb->seq,
			pdu_cb->ddigest, pdu_cb->frags, pdu_cb->pi_flags);
	for (i = 0; i < ssi->nr_frags; i++)
		pr_info("skb 0x%p, frag %d, off %u, sz %u.\n",
			skb, i, ssi->frags[i].page_offset, ssi->frags[i].size);
}

#endif	/*__LIBILRO_H__*/
