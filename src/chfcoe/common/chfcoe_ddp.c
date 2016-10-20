/*
 *  Copyright (C) 2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

/*
 * Description:
 * 	This file contains DDP & page pod related modules.
 */

#ifndef __LITTLE_ENDIAN_BITFIELD
#define __LITTLE_ENDIAN_BITFIELD
#endif

#include "chfcoe_defs.h"
#define be32_to_cpu	chfcoe_be32_to_cpu
#include <t4_msg.h>
#include <t4_regs_values.h>
#include <t4fw_interface.h>
#include <t4_chip_type.h>
#include "chfcoe_proto.h"
#include "chfcoe_ddp.h"
#include "chfcoe_lnode.h"
#include "chfcoe_xchg.h"
#include "chfcoe_lib.h"

#define CHFCOE_IQID_START	0x31

static inline int chfcoe_ctrl_send(struct chfcoe_port_info *pi, 
		chfcoe_fc_buffer_t *fr, uint8_t chan)
{
	if (chfcoe_unlikely(!chfcoe_is_imm(fr)))
		chfcoe_err(pi, "not imm: skb len %d\n", chfcoe_fc_len(fr));

	return pi->adap->lld_ops->send_frame(fr, pi->os_dev, chan);
}

/*
 * Allocate n page pods.  Returns -1 on failure or the page pod tag.
 */
static inline int chfcoe_alloc_ppods(struct chfcoe_port_info *pi,
		struct chfcoe_lnode *lnode, unsigned int n)
{
	struct chfcoe_adap_info *adap = pi->adap;
	unsigned int i, j;
	uint8_t *ppod_map = adap->ppod_map;

	if (chfcoe_unlikely(!ppod_map)) {
		CHFCOE_ASSERT(0);
		return -1;
	}

	chfcoe_spin_lock(adap->lock);

	/*
	 * Look for n consecutive available page pods.
	 * Make sure to guard from scanning beyond the table.
	 */
	for (i = 0; i + n - 1 < adap->nppods; ) {
		for (j = 0; j < n; ++j)		/* scan ppod_map[i..i+n-1] */
			if (ppod_map[i + j]) {
				i = i + j + 1;
				goto next;
			}

		chfcoe_memset(&ppod_map[i], 1, n);   /* allocate range */
		lnode->stats.n_ppod_used += n;
		chfcoe_spin_unlock(adap->lock);
		return i;
next:		;
	}

	chfcoe_spin_unlock(adap->lock);

	return -1;
}

void chfcoe_free_ppods(struct chfcoe_port_info *pi, struct chfcoe_lnode *lnode,
		unsigned int tag, unsigned int n)
{
	struct chfcoe_adap_info *adap = pi->adap;

	chfcoe_spin_lock(adap->lock);
	/* Cache this index for optimization. */
	adap->last_freed_ppod = tag;

	/* clear the ppod map. */
	chfcoe_memset(&adap->ppod_map[tag], 0, n);
	lnode->stats.n_ppod_used -= n;
	chfcoe_spin_unlock(adap->lock);
}

static inline void chfcoe_clear_ddp(struct chfcoe_ddp *ddp)
{
	chfcoe_memset(ddp, 0, sizeof(*ddp));
	ddp->tid = CHFCOE_TID_INVALID;
}

static inline void chfcoe_init_ddp(struct chfcoe_ddp *ddp)
{
	ddp->tid = CHFCOE_TID_INVALID;
}

static inline int chfcoe_free_tcb(struct chfcoe_port_info *pi, 
		struct chfcoe_lnode *lnode, unsigned int tid, int chan)
{
	struct chfcoe_adap_info *adap = pi->adap;
	struct fw_pofcoe_tcb_wr *wr;
	chfcoe_fc_buffer_t *fr;
	int err;

	if (tid == CHFCOE_TID_INVALID) {
		chfcoe_err(pi, "%s(): invalid tid\n", __func__);
		return -CHFCOE_INVAL;
	}

	fr = chfcoe_fc_ctrl_alloc(sizeof(*wr));
	if (!fr) {
		chfcoe_err(pi, "fcoe_hdr: frame alloc failed\n");
		return -CHFCOE_NOMEM;
	}

	wr = (struct fw_pofcoe_tcb_wr *)chfcoe_fc_hdr(fr);
	wr->op_compl = chfcoe_htonl(V_FW_WR_OP(FW_POFCOE_TCB_WR) | F_FW_WR_COMPL);
	wr->equiq_to_len16 = chfcoe_htonl(V_FW_WR_LEN16(
				CHFCOE_DIV_ROUND_UP(sizeof(*wr), 16)));
	wr->tid_to_port = chfcoe_htonl(V_FW_POFCOE_TCB_WR_TID(tid) |
			V_FW_POFCOE_TCB_WR_PORT(pi->port_num) |
			F_FW_POFCOE_TCB_WR_FREE);
	wr->cookie = 0;
	wr->iqid = chfcoe_htons(adap->rxq_ids[pi->port_num * pi->nqsets + 
			chan]);
	chfcoe_dbg(pi, "chfcoe_free_tcb(): iqid 0x%x, cpu %d\n", wr->iqid, 
			chfcoe_smp_id());

	err = chfcoe_ctrl_send(pi, fr, chan);
	if (err) {
		chfcoe_err(pi, "free tcb send failed, err %d\n", err);
		return err;
	}

	chfcoe_atomic_inc(lnode->stats.n_tid_free);

	return err;
}

static inline int split_ddp_queue(struct chfcoe_port_info *pi)
{
	int qidx, qhalf;

	qidx = chfcoe_smp_id() % pi->nqsets;
	qhalf = pi->nqsets / 2;

	return (qidx > qhalf) ? (qidx - qhalf) : qidx;
}

int chfcoe_ddp_done(struct chfcoe_port_info *pi, chfcoe_ioreq_t *tgtreq)
{
	struct chfcoe_adap_info *adap = pi->adap;
	struct chfcoe_ddp *ddp = NULL;
	chfcoe_xchg_cb_t *xchg = tgtreq->xchg;
	uint16_t xid = xchg->xid;
	unsigned int tid;
	int len = 0, err = 0, tag, nppods;
	uint8_t chan;
	void *mlock;

	if (xid >= CHFCOE_MAX_XID) {
		chfcoe_err(pi, "ddp_done: xid 0x%x out-of-range\n", xid);
        	return -CHFCOE_INVAL;
	}

	ddp = &tgtreq->ddp;

	if (!(ddp->flags & CHFCOE_DDP_VALID)) {
		chfcoe_err(pi, "ddp_done: xid 0x%x has invalid ddp\n", xid);
		return -CHFCOE_INVAL;
	}

	tid = ddp->tid;
	tag = ddp->ppod_tag;
	nppods = ddp->nppods;

	chfcoe_dbg(pi, "ddp_done: xid %x tid:%x len:%d tag:%d flags:%x\n",
			xid, ddp->tid, len, ddp->ppod_tag, ddp->flags);
	
	if (!(ddp->flags & CHFCOE_DDP_ERROR))
		len = tgtreq->xfrd_len;


	adap->tid2xid[tid].req = NULL;

	chan = split_ddp_queue(pi);
	mlock = pi->txqlock[chan];
	chfcoe_mutex_lock(mlock);
	err = chfcoe_free_tcb(pi, xchg->ln, tid, chan);
	if (err)
		goto err;

err:
	chfcoe_mutex_unlock(mlock);

	chfcoe_free_ppods(pi, xchg->ln, tag, nppods);

	/* this ret value may be used when we send multiple xfer_ready or
	 * when in multiphase mode
	 */
	return (err) ? : len;
}

int chfcoe_ddp_disable(struct chfcoe_adap_info *adap)
{
	if (adap->tid2xid) {
		chfcoe_mem_free(adap->tid2xid);
		adap->tid2xid = NULL;
	}

	adap->ddp_thres = -1;

	return 0;
}

int chfcoe_adap_ddp_init(struct chfcoe_adap_info *adap)
{
	unsigned int i;
	struct chfcoe_port_info *pi;

	for (i=0; i<adap->nports; i++) {
		pi = CHFCOE_PTR_OFFSET(adap->pi, (i * chfcoe_port_info_size));

		chfcoe_mutex_init(pi->ddp_mutex);
		chfcoe_head_init(&pi->tid_list);
		chfcoe_spin_lock_init(pi->tid_list_lock);
		pi->tid_list_len = 0;
	}

	CHFCOE_ASSERT(adap->ntids);	

	/* Allocate TID to XID mapping table */
	adap->tid2xid = chfcoe_mem_alloc(adap->ntids * 
			sizeof(struct chfcoe_tid_to_xid));
	if (!adap->tid2xid) {
		chfcoe_ddp_disable(adap);
		return -CHFCOE_NOMEM;
	}

	return 0;
}

static inline int 
calc_ddp_credits(unsigned int nppods)
{
	unsigned int n_full = (nppods / NUM_IMM_PPODS);
	int credits = n_full * WR_CRED_MAX_PPODS;
	unsigned int last_ppod_len = (nppods % NUM_IMM_PPODS) * CHFCOE_PPOD_SIZE;
	unsigned int last_len;

	if (last_ppod_len) {
		last_len = sizeof(struct ulp_mem_io) +
				sizeof(struct ulptx_idata) + last_ppod_len;
		credits += CHFCOE_DIV_ROUND_UP(last_len, X_IDXSIZE_UNIT);
	}

	/* For TCB allocation */
	credits += CHFCOE_DIV_ROUND_UP(sizeof(struct fw_pofcoe_tcb_wr),
				X_IDXSIZE_UNIT);

	return credits;
}


static inline int chfcoe_alloc_tcb(struct chfcoe_port_info *pi, 
		fc_header_t *fh, chfcoe_ioreq_t *tgtreq, struct chfcoe_ddp *ddp)
{
	struct chfcoe_adap_info *adap = pi->adap;
	struct fw_pofcoe_tcb_wr *wr;
	chfcoe_fc_buffer_t *fr;
	chfcoe_xchg_cb_t *xchg = tgtreq->xchg;
	int err;

	fr = chfcoe_fc_ctrl_alloc(sizeof(*wr));
	if (!fr) {
		chfcoe_err(adap, "fcoe_hdr: frame alloc failed\n");
		return -CHFCOE_NOMEM;
	}

	wr = (struct fw_pofcoe_tcb_wr *)chfcoe_fc_hdr(fr);

	wr->op_compl = chfcoe_htonl(V_FW_WR_OP(FW_POFCOE_TCB_WR) | 
			F_FW_WR_COMPL);
	wr->equiq_to_len16 = chfcoe_htonl(V_FW_WR_LEN16(
				CHFCOE_DIV_ROUND_UP(sizeof(*wr), 16)));
	wr->tid_to_port = chfcoe_htonl(V_FW_POFCOE_TCB_WR_PORT(pi->port_num) | 
				F_FW_POFCOE_TCB_WR_ALLOC);
	/* Already byte ordered */
	wr->x_id = chfcoe_htons(xchg->xid);

	wr->vlan_id = chfcoe_htons(xchg->ln->vlan_id);

	wr->s_id = 0;
	wr->d_id = 0;

	chfcoe_memcpy(&wr->s_id, fh->s_id, 3);
	chfcoe_memcpy(&wr->d_id, fh->d_id, 3);

	wr->cookie = (uint64_t)tgtreq;

	wr->tag = chfcoe_htonl(V_PPOD_TAG(ddp->ppod_tag + pi->adap->toe_nppods));
	wr->xfer_len = chfcoe_htonl(tgtreq->sreq.buff_len);

	wr->iqid = chfcoe_htons(adap->rxq_ids[pi->port_num * pi->nqsets + 
			ddp->chan]);
	chfcoe_dbg(pi, "%s(): tag 0x%x, iqid 0x%x, cpu %d\n", __func__, ddp->ppod_tag + pi->adap->toe_nppods, 
			wr->iqid, chfcoe_smp_id());

	err = chfcoe_ctrl_send(pi, fr, ddp->chan);
	if (err) {
		chfcoe_err(pi, "alloc tcb send failed, err %d\n", err);
		return err;
	}
	
	return CHFCOE_SUCCESS;
}

int chfcoe_get_chip_type(struct chfcoe_adap_info *adap);

static inline int __chfcoe_setup_ppods(struct chfcoe_port_info *pi, 
		chfcoe_ioreq_t *tgtreq, struct chfcoe_ddp *ddp)
{
	struct chfcoe_adap_info *adap = pi->adap;
	unsigned int i;
	int j, pidx, idx, sgidx, ipod;
	struct chfcoe_pagepod *p;
	chfcoe_fc_buffer_t *fr;
	struct fw_pofcoe_ulptx_wr *mwr;
	struct ulp_mem_io *wr;
	struct ulptx_idata *sc;
	unsigned int tid = 0;
	unsigned int color = 0;
	unsigned int nppods = ddp->nppods;
	int tag = ddp->ppod_tag + adap->toe_nppods;
	unsigned int maxoff = tgtreq->sreq.buff_len;
	unsigned int pg0_off, pgoff, pglen;
	unsigned int ppod_addr = adap->ddp_llimit + ddp->ppod_tag * CHFCOE_PPOD_SIZE;
	unsigned int len, podchunk, sglen, totlen = 0;
	struct chfcoe_sgel *sge = tgtreq->sreq.os_sge;
	int sgc = tgtreq->sreq.nsge_map;
	chfcoe_dma_addr_t addr, ppod_gl[NUM_IMM_PPODS + 1], cmn_gl = 0;
	uint8_t *to, err = CHFCOE_SUCCESS;
	uint32_t cmd = chfcoe_htonl(V_ULPTX_CMD(ULP_TX_MEM_WRITE));

	if (is_t4(chfcoe_get_chip_type(adap)))
		cmd |= chfcoe_htonl(V_ULP_MEMIO_ORDER(1));
	else
		cmd |= chfcoe_htonl(V_T5_ULP_MEMIO_IMM(1));

	addr = chfcoe_sg_dma_addr(sge);
	pg0_off = addr & ~os_page_mask;
	sglen = chfcoe_sg_dma_len(sge);
	idx = 0;
	sgidx = 0;
	for (i = 0; i < nppods; ppod_addr += podchunk) {
		unsigned int ppodout = 0;

		podchunk = ((nppods - i) >= NUM_IMM_PPODS) ?
			NUM_IMM_PPODS: (nppods - i);
		podchunk *= CHFCOE_PPOD_SIZE;

		len = sizeof(*wr) + sizeof(*sc) + podchunk;
		fr = chfcoe_fc_ctrl_alloc(len);
		if (!fr) {
			chfcoe_err(adap, "fcoe_hdr: frame alloc failed\n");
			return -CHFCOE_NOMEM;
		}

		to = (uint8_t *)chfcoe_fc_hdr(fr);
		mwr = (struct fw_pofcoe_ulptx_wr *)to;
		mwr->op_pkd = chfcoe_htonl(V_FW_WR_OP(FW_POFCOE_ULPTX_WR));
		mwr->equiq_to_len16 = chfcoe_htonl(V_FW_WR_LEN16(
					CHFCOE_DIV_ROUND_UP(len, 16)));
		wr = (struct ulp_mem_io *)to;
		wr->cmd = cmd;
		wr->dlen = chfcoe_htonl(V_ULP_MEMIO_DATA_LEN(podchunk / 32));
		wr->len16 = chfcoe_htonl(CHFCOE_DIV_ROUND_UP(len - sizeof(wr->wr), 16));
		wr->lock_addr = chfcoe_htonl(V_ULP_MEMIO_ADDR(ppod_addr >> 5));
		sc = (struct ulptx_idata *)(wr + 1);
		sc->cmd_more = chfcoe_htonl(V_ULPTX_CMD(ULP_TX_SC_IMM));
		sc->len = chfcoe_htonl(podchunk);
		p = (struct chfcoe_pagepod *)(sc + 1);

		do {
			ipod = 0;
			chfcoe_memset(ppod_gl, 0, sizeof(ppod_gl));
			if (cmn_gl)
				ppod_gl[ipod++] = cmn_gl;
			while (sglen) {
				/* get the offset of length of current buffer */
				pgoff = addr & ~os_page_mask;
				pglen = min(((unsigned int)os_page_size - pgoff), 
						sglen);
				/*
				 * all but the 1st buffer (j == 0)
				 * must be aligned on os_page_size
				 */
				if ((idx != 0) && (pgoff)) {
					chfcoe_err(pi, "case 1: buffer %d of %d"
						       	" not aligned\n",	
							idx, sgidx);
					err = -CHFCOE_INVAL;
					goto err;
				}
				/*
				 * all but the last buffer 
				 * ((i == (sgc - 1)) && (pglen == len))
				 * must end at os_page_size
				 */
				if (((sgidx != (sgc - 1)) || (pglen != sglen))
						&& ((pglen + pgoff) != os_page_size)) {
					chfcoe_err(pi, "case 2: buffer %d of %d"
						       	" not aligned\n",
							idx, sgidx);
					err = -CHFCOE_INVAL;
					goto err;
				}

				ppod_gl[ipod++] = addr - pgoff;
				sglen -= pglen;
				addr += pglen;
				totlen += pglen;
				idx++;

				if (!sglen) {
					if (++sgidx == sgc)
						break;
					sge = chfcoe_sg_next(sge);
					addr = chfcoe_sg_dma_addr(sge);
					sglen = chfcoe_sg_dma_len(sge);
				}

				if (ipod == NUM_IMM_PPODS + 1) {
					cmn_gl = ppod_gl[NUM_IMM_PPODS];
					break;
				}
			}

			if (chfcoe_likely(i < nppods - NUM_SENTINEL_PPODS)) {
				p->vld_tid_pgsz_tag_color =
					chfcoe_cpu_to_be64(F_PPOD_VALID |
							V_PPOD_TID(tid) |
							V_PPOD_TAG(tag) |
							V_PPOD_COLOR(color));
				p->len_offset = chfcoe_cpu_to_be64(V_PPOD_LEN(maxoff) |
						V_PPOD_OFST(pg0_off));
				p->rsvd = 0;
				for (j=0, pidx=0; j< 5; ++j, ++pidx) {
					p->addr[j] = ppod_gl[pidx] ?
					chfcoe_cpu_to_be64(ppod_gl[pidx]) : 0;
				}
			} else {
				/* mark sentinel page pods invalid */
				p->vld_tid_pgsz_tag_color = 0;
			}
			p++;
			ppodout += CHFCOE_PPOD_SIZE;
			i++;

		} while (ppodout < podchunk);

		err = chfcoe_ctrl_send(pi, fr, ddp->chan);
		if (err) {
			chfcoe_err(pi, "alloc tcb send failed, err %d\n", 
					err);
			return err;
		}
	}

	if (totlen != maxoff) {
		chfcoe_err(pi, "%s(): totlen %u, bufflen %u\n", __func__, 
				totlen, maxoff);
		CHFCOE_ASSERT(0);
		err = -CHFCOE_INVAL;
	}

err:
	return err;
}

int chfcoe_ddp_setup(struct chfcoe_port_info *pi, chfcoe_ioreq_t *tgtreq,
		chfcoe_fc_buffer_t *fb)
{
	struct chfcoe_adap_info *adap = pi->adap;
	struct chfcoe_ddp *ddp = &tgtreq->ddp;
	chfcoe_xchg_cb_t *xchg = tgtreq->xchg;
	struct chfcoe_lnode *ln = xchg->ln;
	void *sgl = tgtreq->sreq.os_sge, *mlock;
	unsigned int offset;
	uint16_t rx_id = xchg->xid;
	int nppods, npages, tag, err = 0;
	fc_header_t *fh = (fc_header_t *)chfcoe_fc_hdr(fb);

	if (!sgl || !adap) {
		chfcoe_err(pi, "invalid args: sgl %p, adap %p\n", sgl, adap);
		return -CHFCOE_INVAL;
	}

	if (rx_id >= CHFCOE_MAX_XID) {
		chfcoe_err(pi, "xid=0x%x out-of-range\n", rx_id);
		return -CHFCOE_INVAL;
	}

	offset = chfcoe_sg_dma_addr(sgl) & ~os_page_mask;
	npages = (offset + tgtreq->sreq.buff_len + os_page_size - 1) >> os_page_shift;
	if (offset)
		chfcoe_info(pi, "offset %u, buflen %d, npages %d\n", 
				offset, tgtreq->sreq.buff_len, npages);

	if (npages >= CHFCOE_MAX_PAGE_CNT) {
		chfcoe_err(pi, "too many pages, xid %x, npages %d > max %d\n",
				rx_id, npages, CHFCOE_MAX_PAGE_CNT);
		return -CHFCOE_INVAL;
	}

	nppods = chfcoe_pages2ppods(npages);

	tag = chfcoe_alloc_ppods(pi, ln, nppods);
	if (tag < 0) {
		chfcoe_err(pi, "Failed to allocate %d ppods"
				" xid:0x%x\n", nppods, rx_id);
		err = -CHFCOE_INVAL;
		goto err0;
	}

	chfcoe_init_ddp(ddp);
	if (ddp->flags & CHFCOE_DDP_VALID) {
		chfcoe_err(pi, "xid=0x%x, ddp is valid\n", rx_id);
		err = -CHFCOE_INVAL;
		chfcoe_free_ppods(pi, ln, tag, nppods);
		goto err0;
	}

	ddp->ppod_tag = tag;
	ddp->nppods = nppods;
	ddp->flags |= CHFCOE_DDP_VALID;

	ddp->chan = split_ddp_queue(pi);
	chfcoe_fc_txq(fb) = ddp->chan;
	mlock = pi->txqlock[ddp->chan];
	chfcoe_mutex_lock(mlock);
	err = chfcoe_alloc_tcb(pi, fh, tgtreq, ddp);
	if (err) {
		chfcoe_err(adap, "chfcoe_alloc_tcb() failed\n");
		chfcoe_mutex_unlock(mlock);
		goto err1;
	}

	err = __chfcoe_setup_ppods(pi, tgtreq, ddp);
	if (err) {
		chfcoe_err(pi, "__chfcoe_setup_ppods() failed\n");
		chfcoe_mutex_unlock(mlock);
		goto err2;
	}

	chfcoe_mutex_unlock(mlock);
	return tag;
err2:
	ddp->flags &= ~CHFCOE_DDP_VALID;
	err = chfcoe_free_tcb(pi, ln, ddp->tid, ddp->chan);
	if (err)
		chfcoe_err(pi, "bad state. tid escaped for xid 0x%x\n", rx_id);

err1:	
	chfcoe_free_ppods(pi, ln, tag, nppods);
err0:
	chfcoe_dbg(adap, "EXIT %s:xid 0x%x\n", __func__, rx_id);
	return err;
}

#define chfcoe_wr_retval(_wr)			\
	(G_FW_CMD_RETVAL(chfcoe_ntohl(((struct fw_cmd_hdr *)(_wr))->lo)))

int chfcoe_pofcoe_tcb_wr_handler(struct chfcoe_adap_info *adap, 
		const uint64_t *rsp)
{
	struct chfcoe_port_info *pi = NULL;
	struct chfcoe_lnode *lnode;
	chfcoe_ioreq_t *tgtreq = NULL;
	chfcoe_xchg_cb_t *xchg = NULL;
	struct cpl_fw6_msg *msg = (struct cpl_fw6_msg *)&rsp[1];
	struct fw_pofcoe_tcb_wr *wr = NULL;
	struct chfcoe_ddp *ddp = NULL;
	uint32_t tid = 0, retfw;
	uint8_t port_id = 0;

	if (*((uint8_t *)msg->data) != FW_POFCOE_TCB_WR) {
		chfcoe_warn(adap, "%s(): ignoring bad wr 0x%x", __func__, 
				*((uint8_t *)msg->data));
		return 0;
	}

	wr = (struct fw_pofcoe_tcb_wr *)msg->data;

	if ((retfw = chfcoe_wr_retval(wr)) != FW_SUCCESS) {
		/* TCB allocation failed, fall back to software DDP */
	}

	port_id = G_FW_POFCOE_TCB_WR_PORT(chfcoe_be32_to_cpu(wr->tid_to_port));
	pi = CHFCOE_PTR_OFFSET(adap->pi, (port_id * chfcoe_port_info_size));

	/* Called for a TCB free */
	if (G_FW_POFCOE_TCB_WR_FREE(chfcoe_be32_to_cpu(wr->tid_to_port))) {
		chfcoe_dbg(adap, "tid free\n");
		return 0;
	}

	tgtreq = (chfcoe_ioreq_t *)wr->cookie;
	ddp = &tgtreq->ddp;
	xchg = tgtreq->xchg;
	lnode = xchg->ln;

	tid = G_FW_POFCOE_TCB_WR_TID(chfcoe_be32_to_cpu(wr->tid_to_port));
	if (tid > adap->ntids - 1) {
		chfcoe_err(pi, "tid %x out of bounds (port:%d)\n",
				tid, port_id);
		CHFCOE_ASSERT(0);
       		goto err;
	}

	ddp->tid = tid;
	chfcoe_atomic_inc(lnode->stats.n_tid_alloc);

	adap->tid2xid[tid].req = tgtreq;
err:

	return 0;
}

static inline chfcoe_xchg_cb_t *chfcoe_lookup_ddp(
		struct chfcoe_adap_info *adap, unsigned int tid,
		struct chfcoe_port_info **pinfo)
{
	struct chfcoe_ddp *ddp = 0;
	struct chfcoe_port_info *pi;
	chfcoe_xchg_cb_t *xchg;
	chfcoe_ioreq_t *tgtreq;
	uint16_t xid = 0;

	*pinfo = NULL;
	if (tid >= adap->ntids) {
		chfcoe_err(pi, "tid 0x%x out of bounds\n", tid);
		return NULL;
	}

	tgtreq = adap->tid2xid[tid].req;
	if (!tgtreq) {
		chfcoe_err(adap, "tid2xid is corrupt, tid 0x%x, ioreq %p\n",
				tid, tgtreq);
		return NULL;
	}

	ddp = &tgtreq->ddp;
	xchg = tgtreq->xchg;
	pi = xchg->ln->pi;

	if (ddp->tid == tid  && (ddp->flags & CHFCOE_DDP_VALID)) {
		*pinfo = pi;
	} else {
		chfcoe_err(pi, "xid 0x%x tids don't match, ddp->tid 0x%x,"
			       " tid:0x%x, flags 0x%x\n", xid, ddp->tid, 
			       tid, ddp->flags);
		xchg = NULL;
	}

	return xchg;
}

int chfcoe_cplrx_fcoe_ddp_handler(struct chfcoe_adap_info *adap, 
		const uint64_t *rsp)
{
	struct cpl_rx_fcoe_ddp *cfcoe_ddp = NULL;
	struct chfcoe_ddp *ddp = NULL;
	struct chfcoe_port_info *pi;
	chfcoe_xchg_cb_t *xchg;
	chfcoe_ioreq_t *tgtreq;
	uint32_t tid = 0;
	uint16_t xid = 0;

	cfcoe_ddp = (void *)&rsp[1];
	tid = GET_TID(cfcoe_ddp);

	xchg = chfcoe_lookup_ddp(adap, tid, &pi);
	if (!xchg) {
		chfcoe_err(pi, "xid=0x%x ddp lookup failed for tid:%x\n",
			xid, tid);
		return 0;
	}

	tgtreq = xchg->cbarg;
       	ddp = &tgtreq->ddp;

	chfcoe_warn(pi, "DDP Error, xid:%x tid:%x report:%x"
			 " vld:%x\n", xid, tid,
			 chfcoe_be32_to_cpu(cfcoe_ddp->ddp_report),
			 chfcoe_be32_to_cpu(cfcoe_ddp->ddpvld));

	ddp->flags |= CHFCOE_DDP_ERROR;

	return 0;
}

static inline void chfcoe_ddp_fr_init(struct chfcoe_port_info *pi,
		chfcoe_fc_buffer_t *fr, chfcoe_ioreq_t *tgtreq,
		struct cpl_fcoe_hdr *cfcoe_hdr)
{
	struct proto_ethhdr_novlan *eh;
	struct proto_fcoe_hdr *fcoeh;
	struct proto_fcoe_crc_eof *fcoet;
	chfcoe_xchg_cb_t *xchg = tgtreq->xchg;
	fc_header_t *fh;
	uint8_t rctl;
	uint32_t fctl;

	chfcoe_fcb_cb(fr)->port = pi->port_num;
	chfcoe_fcb_cb(fr)->vlan_tci = xchg->ln->vlan_id;
	rctl = G_CPL_FCOE_HDR_RCTL(chfcoe_be32_to_cpu(cfcoe_hdr->rctl_fctl));
	fctl = G_CPL_FCOE_HDR_FCTL(chfcoe_be32_to_cpu(cfcoe_hdr->rctl_fctl));

	eh = (struct proto_ethhdr_novlan *)chfcoe_fc_hdr(fr);
	eh->et = chfcoe_htons(PROTO_ETH_P_FCOE);

	fcoeh = (struct proto_fcoe_hdr *)(eh + 1);
	chfcoe_memset(fcoeh, 0, sizeof(*fcoeh));
	fcoeh->fcoe_sof = cfcoe_hdr->sof;

	fh = (fc_header_t *)(fcoeh + 1);
	fh->r_ctl = rctl;
	chfcoe_hton24(fh->d_id, xchg->ln->nport_id);
	chfcoe_hton24(fh->s_id, xchg->rn->nport_id);

	fh->cs_ctl_pri = cfcoe_hdr->cs_ctl;
	fh->type = cfcoe_hdr->type;
	chfcoe_memcpy(fh->f_ctl, ((char *)&cfcoe_hdr->rctl_fctl) + 1, 3);
	fh->seq_id = cfcoe_hdr->seq_id;
	fh->df_ctl = cfcoe_hdr->df_ctl;
	fh->seq_cnt = cfcoe_hdr->seq_cnt;
	fh->ox_id = cfcoe_hdr->oxid;
	fh->rx_id = chfcoe_htons(xchg->xid);
	fh->params = cfcoe_hdr->param;

	fcoet = (struct proto_fcoe_crc_eof *)(fh + 1);
	chfcoe_memset(fcoet, 0, sizeof(*fcoet));
	fcoet->fcoe_eof = cfcoe_hdr->eof;

	return;
}

int chfcoe_cplrx_fcoe_hdr_handler(struct chfcoe_adap_info *adap,
		const uint64_t *rsp)
{
	struct chfcoe_port_info *pi;
	struct chfcoe_lnode *lnode;
	chfcoe_fc_buffer_t *fr;
	struct cpl_fcoe_hdr *cfcoe_hdr;
	struct chfcoe_ddp *ddp;
	unsigned int tid;
	uint16_t xid;
	chfcoe_xchg_cb_t *xchg;
	chfcoe_ioreq_t *tgtreq;
	uint32_t fctl;
	uint8_t rctl;

	cfcoe_hdr = (void *)&rsp[1];
	tid = GET_TID(cfcoe_hdr);

	xchg = chfcoe_lookup_ddp(adap, tid, &pi);
	if (!xchg) {
		chfcoe_err(pi, "ddp lookup failed for tid:%x\n", tid);
		return 0;
	}

	tgtreq = xchg->cbarg;
       	ddp = &tgtreq->ddp;
	xid = xchg->xid;
	lnode = xchg->ln;

	if (ddp->flags & CHFCOE_DDP_ERROR) {
		goto exit;
	}

	rctl = G_CPL_FCOE_HDR_RCTL(chfcoe_be32_to_cpu(cfcoe_hdr->rctl_fctl));
	fctl = G_CPL_FCOE_HDR_FCTL(chfcoe_be32_to_cpu(cfcoe_hdr->rctl_fctl));


	if (proto_fc_sof_is_init(cfcoe_hdr->sof)) {
		xchg->seq_id = cfcoe_hdr->seq_id;
		xchg->seq_cnt = chfcoe_ntohs(cfcoe_hdr->seq_cnt);
	} else if (xchg->seq_id != cfcoe_hdr->seq_id || 
			xchg->seq_cnt != chfcoe_ntohs(cfcoe_hdr->seq_cnt)) {
		chfcoe_err(adap, "%s:seq_id or seq_cnt mismatch fr oxid %x, rxid "
				"%x, fr_seq_id %u, xchg_seq_id %u, fr_seq_cnt %u, "
				"xchg_seq_cnt %u\n", __func__, 
				chfcoe_ntohs(cfcoe_hdr->oxid), xid,
				cfcoe_hdr->seq_id, xchg->seq_id, 
				chfcoe_ntohs(cfcoe_hdr->seq_cnt), xchg->seq_cnt);
		return 0;
	}

	tgtreq->xfrd_len += chfcoe_ntohs(cfcoe_hdr->len);

	if (fctl & PROTO_FC_END_SEQ) {
		fr = chfcoe_fc_ctrl_alloc(sizeof(struct proto_fcoe_fr_hdr) +
				sizeof(struct proto_fcoe_crc_eof));
		if (!fr) {
			chfcoe_err(adap, "fcoe_hdr: frame alloc failed\n");
			goto exit;
		}
		
		chfcoe_ddp_fr_init(pi, fr, tgtreq, cfcoe_hdr);
		adap->queue_frame(adap, fr, chfcoe_skb_data(fr), chfcoe_skb_len(fr),
				chfcoe_fcb_cb(fr)->port,
				chfcoe_fcb_cb(fr)->vlan_tci, 
				V_RX_MACIDX(lnode->fcoe_mac_idx));
		chfcoe_atomic_inc(lnode->stats.n_ddp_qd);
	} else
		xchg->seq_cnt++;

exit:
	return 0;
}
