/*
 * Copyright (c) 2006-2010 Chelsio, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#if HAVE_CONFIG_H
#  include <config.h>
#endif				/* HAVE_CONFIG_H */

#include <stdio.h>
#include <syslog.h>
#include <pthread.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <infiniband/opcode.h>
#include "libcxgb4.h"
#include "cxgb4-abi.h"

static void insert_recv_cqe(struct t4_wq *wq, struct t4_cq *cq)
{
	struct t4_cqe cqe;

	PDBG("%s wq %p cq %p sw_cidx %u sw_pidx %u\n", __func__,
	     wq, cq, cq->sw_cidx, cq->sw_pidx);
	memset(&cqe, 0, sizeof(cqe));
	cqe.rss.opcode = CPL_RDMA_CQE;
	cqe.u.rdma.header = cpu_to_be32(V_CQE_STATUS(T4_ERR_SWFLUSH) |
			         V_CQE_OPCODE(FW_RI_SEND) |
				 V_CQE_TYPE(0) |
				 V_CQE_SWCQE(1) |
				 V_CQE_QPID(wq->sq.qid));
	cqe.bits_type_ts = cpu_to_be64(V_CQE_GENBIT((u64)cq->gen));
	cq->sw_queue[cq->sw_pidx] = cqe;
	t4_swcq_produce(cq);
}

int c4iw_flush_rq(struct t4_wq *wq, struct t4_cq *cq, int count)
{
	int flushed = 0;
	int in_use = wq->rq.in_use - count;

	BUG_ON(in_use < 0);
	PDBG("%s wq %p cq %p rq.in_use %u skip count %u\n", __func__,
	     wq, cq, wq->rq.in_use, count);
	while (in_use--) {
		insert_recv_cqe(wq, cq);
		flushed++;
	}
	return flushed;
}

static void insert_sq_cqe(struct t4_wq *wq, struct t4_cq *cq,
		          struct t4_swsqe *swcqe)
{
	struct t4_cqe cqe;

	PDBG("%s wq %p cq %p sw_cidx %u sw_pidx %u\n", __func__,
	     wq, cq, cq->sw_cidx, cq->sw_pidx);
	memset(&cqe, 0, sizeof(cqe));
	cqe.rss.opcode = CPL_RDMA_CQE;
	cqe.u.rdma.header = cpu_to_be32(V_CQE_STATUS(T4_ERR_SWFLUSH) |
			         V_CQE_OPCODE(swcqe->opcode) |
			         V_CQE_TYPE(1) |
			         V_CQE_SWCQE(1) |
			         V_CQE_QPID(wq->sq.qid));
	CQE_WRID_SQ_IDX(&cqe) = swcqe->idx;
	cqe.bits_type_ts = cpu_to_be64(V_CQE_GENBIT((u64)cq->gen));
	cq->sw_queue[cq->sw_pidx] = cqe;
	t4_swcq_produce(cq);
}

static void advance_oldest_read(struct t4_wq *wq);

void c4iw_flush_sq(struct c4iw_qp *qhp)
{
	unsigned short flushed = 0;
	struct t4_wq *wq = &qhp->wq;
	struct c4iw_cq *chp = to_c4iw_cq(qhp->ibv_qp.send_cq);
	struct t4_cq *cq = &chp->cq;
	int idx;
	struct t4_swsqe *swsqe;
	
	if (wq->sq.flush_cidx == -1)
		wq->sq.flush_cidx = wq->sq.cidx;
	idx = wq->sq.flush_cidx;
	BUG_ON(idx >= wq->sq.size);
	while (idx != wq->sq.pidx) {
		swsqe = &wq->sq.sw_sq[idx];
		BUG_ON(swsqe->flushed);
		swsqe->flushed = 1;
		insert_sq_cqe(wq, cq, swsqe);
		if (wq->sq.oldest_read == swsqe) {
			BUG_ON(swsqe->opcode != FW_RI_READ_REQ);
			advance_oldest_read(wq);
		}
		flushed++;
		if (++idx == wq->sq.size)
			idx = 0;
	}
	wq->sq.flush_cidx += flushed;
	if (wq->sq.flush_cidx >= wq->sq.size)
		wq->sq.flush_cidx -= wq->sq.size;
}

static void flush_completed_wrs(struct t4_wq *wq, struct t4_cq *cq)
{
	struct t4_swsqe *swsqe;
	unsigned short cidx;
 
	if (wq->sq.flush_cidx == -1)
		wq->sq.flush_cidx = wq->sq.cidx;
	cidx = wq->sq.flush_cidx;
	BUG_ON(cidx >= wq->sq.size);

	while (cidx != wq->sq.pidx) {
		swsqe = &wq->sq.sw_sq[cidx];
		if (!swsqe->signaled) {
			if (++cidx == wq->sq.size)
				cidx = 0;
		} else if (swsqe->complete) {

			BUG_ON(swsqe->flushed);

			/*
			 * Insert this completed cqe into the swcq.
			 */
			PDBG("%s moving cqe into swcq sq idx %u cq idx %u\n",
			     __func__, cidx, cq->sw_pidx);

			swsqe->cqe.u.rdma.header |= htonl(V_CQE_SWCQE(1));
			cq->sw_queue[cq->sw_pidx] = swsqe->cqe;
			t4_swcq_produce(cq);
			swsqe->flushed = 1;
			if (++cidx == wq->sq.size)
				cidx = 0;
			wq->sq.flush_cidx = cidx;
		} else
			break;
	}
}

static void create_read_req_cqe(struct t4_wq *wq, struct t4_cqe *hw_cqe,
				struct t4_cqe *read_cqe)
{
	read_cqe->rss = hw_cqe->rss;
	read_cqe->u.rdma.u.scqe.cidx = wq->sq.oldest_read->idx;
	read_cqe->u.rdma.len = ntohl(wq->sq.oldest_read->read_len);
	read_cqe->u.rdma.header = htonl(V_CQE_QPID(CQE_QPID(hw_cqe)) |
				 V_CQE_SWCQE(SW_CQE(hw_cqe)) |
				 V_CQE_OPCODE(FW_RI_READ_REQ) |
				 V_CQE_TYPE(1));
	read_cqe->bits_type_ts = hw_cqe->bits_type_ts;
}

static void advance_oldest_read(struct t4_wq *wq)
{

	u32 rptr = wq->sq.oldest_read - wq->sq.sw_sq + 1;

	if (rptr == wq->sq.size)
		rptr = 0;
	while (rptr != wq->sq.pidx) {
		wq->sq.oldest_read = &wq->sq.sw_sq[rptr];

		if (wq->sq.oldest_read->opcode == FW_RI_READ_REQ)
			return;
		if (++rptr == wq->sq.size)
			rptr = 0;
	}
	wq->sq.oldest_read = NULL;
}

/*
 * Move all CQEs from the HWCQ into the SWCQ.
 * Deal with out-of-order and/or completions that complete
 * prior unsignalled WRs.
 */
void c4iw_flush_hw_cq(struct c4iw_cq *chp)
{
	struct t4_cqe *hw_cqe, *swcqe, read_cqe;
	struct c4iw_qp *qhp;
	struct t4_swsqe *swsqe;
	int ret;

	PDBG("%s  cqid 0x%x\n", __func__, chp->cq.cqid);
	ret = t4_next_hw_cqe(&chp->cq, &hw_cqe);

	/*
	 * This logic is similar to poll_cq(), but not quite the same
	 * unfortunately.  Need to move pertinent HW CQEs to the SW CQ but
	 * also do any translation magic that poll_cq() normally does.
	 */
	while (!ret) {
		qhp = get_qhp(chp->rhp, CQE_QPID(hw_cqe));

		/*
		 * drop CQEs with no associated QP
		 */
		if (qhp == NULL)
			goto next_cqe;

		if (CQE_OPCODE(hw_cqe) == FW_RI_TERMINATE)
			goto next_cqe;

		if (CQE_OPCODE(hw_cqe) == FW_RI_READ_RESP) {

			/*
			 * If we have reached here because of async
			 * event or other error, and have egress error
			 * then drop
			 */
			if (CQE_TYPE(hw_cqe) == 1) {
				syslog(LOG_CRIT,"%s: got egress error in read-response, dropping!\n", __func__);
				goto next_cqe;
			}

			/*
			 * drop peer2peer RTR reads.
			 */
			if (CQE_WRID_STAG(hw_cqe) == 1)
				goto next_cqe;

			/*
			 * Eat completions for unsignaled read WRs.
			 */
			if (!qhp->wq.sq.oldest_read->signaled) {
				advance_oldest_read(&qhp->wq);
				goto next_cqe;
			}

			/*
			 * Don't write to the HWCQ, create a new read req CQE
			 * in local memory and move it into the swcq.
			 */
			create_read_req_cqe(&qhp->wq, hw_cqe, &read_cqe);
			hw_cqe = &read_cqe;
			advance_oldest_read(&qhp->wq);
		}

		/* if its a SQ completion, then do the magic to move all the
		 * unsignaled and now in-order completions into the swcq.
		 */
		if (SQ_TYPE(hw_cqe)) {
			int idx = CQE_WRID_SQ_IDX(hw_cqe);

			BUG_ON(idx >= qhp->wq.sq.size);
			swsqe = &qhp->wq.sq.sw_sq[idx];
			swsqe->cqe = *hw_cqe;
			swsqe->complete = 1;
			flush_completed_wrs(&qhp->wq, &chp->cq);
		} else {
			swcqe = &chp->cq.sw_queue[chp->cq.sw_pidx];
			*swcqe = *hw_cqe;
			swcqe->u.rdma.header |= cpu_to_be32(V_CQE_SWCQE(1));
			t4_swcq_produce(&chp->cq);
		}
next_cqe:
		t4_hwcq_consume(&chp->cq);
		ret = t4_next_hw_cqe(&chp->cq, &hw_cqe);
	}
}

static int cqe_completes_wr(struct t4_cqe *cqe, struct t4_wq *wq)
{
	if (CQE_OPCODE(cqe) == FW_RI_TERMINATE)
		return 0;

	if ((CQE_OPCODE(cqe) == FW_RI_RDMA_WRITE) && RQ_TYPE(cqe))
		return 0;

	if ((CQE_OPCODE(cqe) == FW_RI_READ_RESP) && SQ_TYPE(cqe))
		return 0;

	if (CQE_SEND_OPCODE(cqe) && RQ_TYPE(cqe) && t4_rq_empty(wq))
		return 0;
	return 1;
}

void c4iw_count_rcqes(struct t4_cq *cq, struct t4_wq *wq, int *count)
{
	struct t4_cqe *cqe;
	u32 ptr;

	*count = 0;
	ptr = cq->sw_cidx;
	BUG_ON(ptr >= cq->size);
	while (ptr != cq->sw_pidx) {
		cqe = &cq->sw_queue[ptr];
		if (RQ_TYPE(cqe) && (CQE_OPCODE(cqe) != FW_RI_READ_RESP) &&
		    (CQE_QPID(cqe) == wq->sq.qid) && cqe_completes_wr(cqe, wq))
			(*count)++;
		if (++ptr == cq->size)
			ptr = 0;
	}
	PDBG("%s cq %p count %d\n", __func__, cq, *count);
}

static void dump_cqe(void *arg)
{
	u64 *p = arg;
	syslog(LOG_NOTICE, "cxgb4 err cqe %016llx %016llx %016llx %016llx\n",
	       (long long)be64_to_cpu(p[0]),
	       (long long)be64_to_cpu(p[1]),
	       (long long)be64_to_cpu(p[2]),
	       (long long)be64_to_cpu(p[3]));
}

/*
 * poll_cq
 *
 * Caller must:
 *     check the validity of the first CQE,
 *     supply the wq assicated with the qpid.
 *
 * credit: cq credit to return to sge.
 * cqe_flushed: 1 iff the CQE is flushed.
 * cqe: copy of the polled CQE.
 *
 * return value:
 *    0		    CQE returned ok.
 *    -EAGAIN       CQE skipped, try again.
 *    -EOVERFLOW    CQ overflow detected.
 */
static int poll_cq(struct t4_wq *wq, struct t4_cq *cq, struct t4_cqe *cqe,
	           u8 *cqe_flushed, u64 *cookie, u32 *credit)
{
	int ret = 0;
	struct t4_cqe *hw_cqe, read_cqe;

	*cqe_flushed = 0;
	*credit = 0;

	ret = t4_next_cqe(cq, &hw_cqe);
	if (ret)
		return ret;

	PDBG("%s CQE OVF %u qpid 0x%0x genbit %u type %u status 0x%0x"
	     " opcode 0x%0x len 0x%0x wrid_hi_stag 0x%x wrid_low_msn 0x%x\n",
	     __func__, CQE_OVFBIT(hw_cqe), CQE_QPID(hw_cqe),
	     CQE_GENBIT(hw_cqe), CQE_TYPE(hw_cqe), CQE_STATUS(hw_cqe),
	     CQE_OPCODE(hw_cqe), CQE_LEN(hw_cqe), CQE_WRID_HI(hw_cqe),
	     CQE_WRID_LOW(hw_cqe));

	/*
	 * skip cqe's not affiliated with a QP.
	 */
	if (wq == NULL) {
		ret = -EAGAIN;
		goto skip_cqe;
	}

	/*
	 * Gotta tweak READ completions:
	 *	1) the cqe doesn't contain the sq_wptr from the wr.
	 *	2) opcode not reflected from the wr.
	 *	3) read_len not reflected from the wr.
	 *	4) T4 HW (for now) inserts target read response failures which
	 * 	   need to be skipped.
	 */
	if (CQE_OPCODE(hw_cqe) == FW_RI_READ_RESP) {

		/*
		 * If we have reached here because of async
		 * event or other error, and have egress error
		 * then drop
		 */
		if (CQE_TYPE(hw_cqe) == 1) {
			syslog(LOG_CRIT,"%s: got egress error in read-response, dropping!\n", __func__);
			if (CQE_STATUS(hw_cqe))
				t4_set_wq_in_error(wq);
			ret = -EAGAIN;
			goto skip_cqe;
		}

		/*
		 * If this is an unsolicited read response, then the read
		 * was generated by the kernel driver as part of peer-2-peer
		 * connection setup, or a target read response failure.
		 * So skip the completion.
		 */
		if (CQE_WRID_STAG(hw_cqe) == 1) {
			if (CQE_STATUS(hw_cqe))
				t4_set_wq_in_error(wq);
			ret = -EAGAIN;
			goto skip_cqe;
		}

		/*
		 * Eat completions for unsignaled read WRs.
		 */
		if (!wq->sq.oldest_read->signaled) {
			advance_oldest_read(wq);
			ret = -EAGAIN;
			goto skip_cqe;
		}

		/*
		 * Don't write to the HWCQ, so create a new read req CQE
		 * in local memory.
		 */
		create_read_req_cqe(wq, hw_cqe, &read_cqe);
		hw_cqe = &read_cqe;
		advance_oldest_read(wq);
	}

	if (CQE_OPCODE(hw_cqe) == FW_RI_TERMINATE) {
		ret = -EAGAIN;
		goto skip_cqe;
	}

	if (CQE_STATUS(hw_cqe) || t4_wq_in_error(wq)) {
		*cqe_flushed = (CQE_STATUS(hw_cqe) == T4_ERR_SWFLUSH);
		wq->error = 1;

		if (!*cqe_flushed && CQE_STATUS(hw_cqe)) {
			dump_cqe(hw_cqe);
		}
		BUG_ON((cqe_flushed == 0) && !SW_CQE(hw_cqe));
		goto proc_cqe;
	}

	/*
	 * RECV completion.
	 */
	if (RQ_TYPE(hw_cqe)) {

		/*
		 * HW only validates 4 bits of MSN.  So we must validate that
		 * the MSN in the SEND is the next expected MSN.  If its not,
		 * then we complete this with T4_ERR_MSN and mark the wq in
		 * error.
		 */

		if (t4_rq_empty(wq)) {
			t4_set_wq_in_error(wq);
			ret = -EAGAIN;
			goto skip_cqe;
		}
		if (unlikely((CQE_WRID_MSN(hw_cqe) != (wq->rq.msn)))) {
			t4_set_wq_in_error(wq);
			hw_cqe->u.rdma.header |=
						htonl(V_CQE_STATUS(T4_ERR_MSN));
			goto proc_cqe;
		}
		goto proc_cqe;
	}

	/*
	 * If we get here its a send completion.
	 *
	 * Handle out of order completion. These get stuffed
	 * in the SW SQ. Then the SW SQ is walked to move any
	 * now in-order completions into the SW CQ.  This handles
	 * 2 cases:
	 *	1) reaping unsignaled WRs when the first subsequent
	 *	   signaled WR is completed.
	 *	2) out of order read completions.
	 */
	if (!SW_CQE(hw_cqe) && (CQE_WRID_SQ_IDX(hw_cqe) != wq->sq.cidx)) {
		struct t4_swsqe *swsqe;
		int idx =  CQE_WRID_SQ_IDX(hw_cqe);

		PDBG("%s out of order completion going in sw_sq at idx %u\n",
		     __func__, idx);
		BUG_ON(idx >= wq->sq.size);
		swsqe = &wq->sq.sw_sq[idx];
		swsqe->cqe = *hw_cqe;
		swsqe->complete = 1;
		ret = -EAGAIN;
		goto flush_wq;
	}

proc_cqe:
	*cqe = *hw_cqe;

	/*
	 * Reap the associated WR(s) that are freed up with this
	 * completion.
	 */
	if (SQ_TYPE(hw_cqe)) {
		int idx = CQE_WRID_SQ_IDX(hw_cqe);
		BUG_ON(idx >= wq->sq.size);

		/*
		 * Account for any unsignaled completions completed by
		 * this signaled completion.  In this case, cidx points
		 * to the first unsignaled one, and idx points to the
		 * signaled one.  So adjust in_use based on this delta.
		 * if this is not completing any unsigned wrs, then the
		 * delta will be 0. Handle wrapping also!
		 */
		if (idx < wq->sq.cidx)
			wq->sq.in_use -= wq->sq.size + idx - wq->sq.cidx;
		else
			wq->sq.in_use -= idx - wq->sq.cidx;
		BUG_ON(wq->sq.in_use <= 0 || wq->sq.in_use >= wq->sq.size);

		wq->sq.cidx = (u16)idx;
		PDBG("%s completing sq idx %u\n", __func__, wq->sq.cidx);
		*cookie = wq->sq.sw_sq[wq->sq.cidx].wr_id;
		t4_sq_consume(wq);
	} else {
		PDBG("%s completing rq idx %u\n", __func__, wq->rq.cidx);
		BUG_ON(wq->rq.cidx >= wq->rq.size);
		*cookie = wq->rq.sw_rq[wq->rq.cidx].wr_id;
		BUG_ON(t4_rq_empty(wq));
		t4_rq_consume(wq);
		goto skip_cqe;
	}

flush_wq:
	/*
	 * Flush any completed cqes that are now in-order.
	 */
	flush_completed_wrs(wq, cq);

skip_cqe:
	if (SW_CQE(hw_cqe)) {
		PDBG("%s cq %p cqid 0x%x skip sw cqe cidx %u\n",
		     __func__, cq, cq->cqid, cq->sw_cidx);
		t4_swcq_consume(cq);
	} else {
		PDBG("%s cq %p cqid 0x%x skip hw cqe cidx %u\n",
		     __func__, cq, cq->cqid, cq->cidx);
		t4_hwcq_consume(cq);
	}
	return ret;
}

static struct c4iw_raw_qp *find_raw_qp(struct c4iw_raw_srq *srq, struct t4_iqe *iqe)
{
	u32 fid = be32_to_cpu(iqe->rss_hdr.hash_val) - srq->rhp->fid_base +
		  srq->rhp->nhpfids;
	return srq->rhp->fid2ptr[fid];
}

static void cp_iqe_to_rcq(struct c4iw_raw_qp *rqp, struct t4_iqe *iqe, u64 wr_id)
{
	struct t4_cq *cq = &rqp->rcq->cq;

	cq->swiq_queue[cq->swiq_pidx].iqe = *iqe;
	cq->swiq_queue[cq->swiq_pidx].qid = rqp->txq.qid;
	cq->swiq_queue[cq->swiq_pidx].wr_id = wr_id;
	t4_swiq_produce(cq);
}

static int poll_swiq(struct c4iw_cq *chp, struct ibv_wc *wc)
{
	struct t4_iqe *iqe;
	struct t4_cq *cq = &chp->cq;
	u64 hw_tstamp;

	iqe = &cq->swiq_queue[cq->swiq_cidx].iqe;

	memset(wc, 0, sizeof *wc);
	wc->vendor_err = ntohs(iqe->rx_pkt.err_vec);
	wc->wr_id = cq->swiq_queue[cq->swiq_cidx].wr_id;
	wc->opcode = IBV_WC_RECV;
	wc->byte_len = ntohs(iqe->rx_pkt.len);
	wc->qp_num = cq->swiq_queue[cq->swiq_cidx].qid;
	wc->pkey_index = iqe->rx_pkt.vlan_ex ? ntohs(iqe->rx_pkt.vlan) : 0xfff;

	hw_tstamp = CQE_TS(iqe);
	wc->imm_data = htonl ((u32) (hw_tstamp & 0xFFFFFFFF));
	wc->src_qp = htonl ((u32) (hw_tstamp >> 32));
	t4_swiq_consume(cq);
	return 0;
}

/*
 * Get one iq entry from the iq and map it to a CQE.
 *
 * Returns:
 *	0			cqe returned
 *	-ENODATA		EMPTY;
 *	-EAGAIN			caller must try again
 *	any other -errno	fatal error
 */
static int raw_poll_iq(struct c4iw_cq *chp, struct ibv_wc *wc, int peek)
{
	struct t4_iqe *iqe;
	struct c4iw_raw_qp *rqp;
	struct c4iw_raw_srq *uninitialized_var(srq);
	u64 hw_tstamp;
	int ret;
	struct t4_raw_fl *f;

	/*
	 * If we have any pending IQEs from an SRQ, then process them first.
	 */
	if (chp->cq.swiq_in_use)
		return poll_swiq(chp, wc);

	ret = t4_next_iqe(chp->iq, &iqe);
	if (ret)
		return ret;

	if (chp->iq->shared) {
		srq = iq_to_raw_srq(chp->iq);
		pthread_spin_lock(&srq->lock);
		rqp = find_raw_qp(srq, iqe);
		f = &srq->fl;
		if (!rqp) {
			fprintf(stderr, "iqe for unknown endpoint: opcode 0x%x "
			     "csum_calc %u vlan_ex %u vlan 0x%04x "
			     "len %d err_vec 0x%x newbuf %d dma_len %d\n",
			     iqe->rx_pkt.opcode,
			     iqe->rx_pkt.csum_calc, iqe->rx_pkt.vlan_ex,
			     iqe->rx_pkt.vlan_ex ? ntohs(iqe->rx_pkt.vlan) :
						   0xfff,
			     ntohs(iqe->rx_pkt.len), ntohs(iqe->rx_pkt.err_vec),
			     IQE_DATA_NEWBUF(iqe), IQE_DATA_DMA_LEN(iqe));
			ret = -EAGAIN;
			goto skip;
		}
		if (rqp->rcq != chp) {
			cp_iqe_to_rcq(rqp, iqe, f->sw_queue[f->cidx]);
			ret = -EAGAIN;
			goto skip;
		}
	} else {
		rqp = iq_to_raw_qp(chp->iq);
		pthread_spin_lock(&rqp->lock);
		f = &rqp->fl;
	}

	PDBG("%s opcode 0x%x csum_calc %u vlan_ex %u vlan 0x%04x "
	     "len %d err_vec 0x%x newbuf %d dma_len %d\n",
	     __func__, iqe->rx_pkt.opcode,
	     iqe->rx_pkt.csum_calc, iqe->rx_pkt.vlan_ex,
	     iqe->rx_pkt.vlan_ex ? ntohs(iqe->rx_pkt.vlan) : 0xfff,
	     ntohs(iqe->rx_pkt.len), ntohs(iqe->rx_pkt.err_vec),
	     IQE_DATA_NEWBUF(iqe), IQE_DATA_DMA_LEN(iqe));

	memset(wc, 0, sizeof *wc);
	wc->sl = IQE_DATA_NEWBUF(iqe);
	wc->vendor_err = ntohs(iqe->rx_pkt.err_vec);
	wc->wr_id = f->sw_queue[f->cidx];
	wc->opcode = IBV_WC_RECV;
	wc->byte_len = ntohs(iqe->rx_pkt.len);
	wc->qp_num = rqp->txq.qid;
	wc->pkey_index = iqe->rx_pkt.vlan_ex ? ntohs(iqe->rx_pkt.vlan) : 0xfff;

	hw_tstamp = CQE_TS(iqe);
	wc->imm_data = htonl ((u32) (hw_tstamp & 0xFFFFFFFF));
	wc->src_qp = htonl ((u32) (hw_tstamp >> 32));

skip:
	if (!peek) {
		t4_iq_consume(chp->iq);
		if (!f->packed) {
			t4_raw_fl_consume(f);
		} else if (IQE_DATA_NEWBUF(iqe)) {
			if (f->first_skipped) {
				t4_raw_fl_consume(f);
				if (!ret)
					 wc->wr_id = f->sw_queue[f->cidx];
			} else {
				f->first_skipped = 1;
			}
		}
	}
	if (chp->iq->shared)
		pthread_spin_unlock(&srq->lock);
	else
		pthread_spin_unlock(&rqp->lock);
	return ret;
}

/*
 * poll_raw_cq
 *
 * Caller must:
 *     check the validity of the first CQE,
 *     supply the wq assicated with the qpid.
 *
 * credit: cq credit to return to sge.
 * cqe_flushed: 1 iff the CQE is flushed.
 * cqe: copy of the polled CQE.
 *
 * return value:
 *    0		    CQE returned ok.
 *    -EAGAIN       CQE skipped, try again.
 *    -EOVERFLOW    CQ overflow detected.
 */
static int raw_poll_cq(struct t4_cqe *cqe, struct c4iw_cq *chp,
		       struct ibv_wc *wc)
{
	struct c4iw_raw_qp *rqp;
	int ret;
	int i;

	rqp = get_raw_qp(chp->rhp, RAW_QPID(cqe));
	if (rqp) {
		pthread_spin_lock(&rqp->lock);

		i = rqp->txq.cidx;
		while (i != rqp->txq.pidx) {
			t4_txq_consume(&rqp->txq);
			if (rqp->txq.sw_queue[i].signaled)
				break;
			if (++i == rqp->txq.size)
				i = 0;
		}
		assert(i != rqp->txq.pidx);

		INC_STAT(cqe);
		wc->wr_id = rqp->txq.sw_queue[i].wr_id;
		wc->qp_num = rqp->txq.qid;
		wc->vendor_err = 0;
		wc->wc_flags = 0;
		wc->opcode = IBV_WC_SEND;
		wc->status = IBV_WC_SUCCESS;
		pthread_spin_unlock(&rqp->lock);
		ret = 0;
	} else
		ret = -EAGAIN;
	t4_hwcq_consume(&chp->cq);
	return ret;
}

/*
 * Get one cq entry from c4iw and map it to openib.
 *
 * Returns:
 *	0			cqe returned
 *	-ENODATA		EMPTY;
 *	-EAGAIN			caller must try again
 *	any other -errno	fatal error
 */
static int c4iw_poll_cq_one(struct c4iw_cq *chp, struct ibv_wc *wc)
{
	struct c4iw_qp *qhp = NULL;
	struct t4_cqe uninitialized_var(cqe), *rd_cqe;
	struct t4_wq *wq;
	u32 credit = 0;
	u8 cqe_flushed;
	u64 cookie = 0;
	int ret;

	ret = t4_next_cqe(&chp->cq, &rd_cqe);
	if (ret == -ENODATA && chp->iq)
		return raw_poll_iq(chp, wc, 0);
	if (ret) {
#ifdef STALL_DETECTION
		if (ret == -ENODATA && stall_to && !dumped) {
			struct timeval t;
			
			gettimeofday(&t, NULL);
			if ((t.tv_sec - chp->time.tv_sec) > stall_to) {
				dump_state();
				dumped = 1;
			}
		}
#endif
		return ret;
	}

	if (CQE_QPTYPE(rd_cqe) == RAW)
		return raw_poll_cq(rd_cqe, chp, wc);
#ifdef STALL_DETECTION
	gettimeofday(&chp->time, NULL);
#endif

	qhp = get_qhp(chp->rhp, CQE_QPID(rd_cqe));
	if (!qhp)
		wq = NULL;
	else {
		pthread_spin_lock(&qhp->lock);
		wq = &(qhp->wq);
	}
	ret = poll_cq(wq, &(chp->cq), &cqe, &cqe_flushed, &cookie, &credit);
	if (ret)
		goto out;

	INC_STAT(cqe);
	wc->wr_id = cookie;
	wc->qp_num = qhp->wq.sq.qid;
	wc->vendor_err = CQE_STATUS(&cqe);
	wc->wc_flags = 0;

	PDBG("%s qpid 0x%x type %d opcode %d status 0x%x wrid hi 0x%x "
	     "lo 0x%x cookie 0x%llx\n", __func__,
	     CQE_QPID(&cqe), CQE_TYPE(&cqe),
	     CQE_OPCODE(&cqe), CQE_STATUS(&cqe), CQE_WRID_HI(&cqe),
	     CQE_WRID_LOW(&cqe), (unsigned long long)cookie);

	if (CQE_TYPE(&cqe) == 0) {
		if (!CQE_STATUS(&cqe))
			wc->byte_len = CQE_LEN(&cqe);
		else
			wc->byte_len = 0;
		wc->opcode = IBV_WC_RECV;
	} else {
		switch (CQE_OPCODE(&cqe)) {
		case FW_RI_RDMA_WRITE:
			wc->opcode = IBV_WC_RDMA_WRITE;
			break;
		case FW_RI_READ_REQ:
			wc->opcode = IBV_WC_RDMA_READ;
			wc->byte_len = CQE_LEN(&cqe);
			break;
		case FW_RI_SEND:
		case FW_RI_SEND_WITH_SE:
		case FW_RI_SEND_WITH_INV:
		case FW_RI_SEND_WITH_SE_INV:
			wc->opcode = IBV_WC_SEND;
			break;
		case FW_RI_BIND_MW:
			wc->opcode = IBV_WC_BIND_MW;
			break;
		default:
			PDBG("Unexpected opcode %d "
			     "in the CQE received for QPID=0x%0x\n",
			     CQE_OPCODE(&cqe), CQE_QPID(&cqe));
			ret = -EINVAL;
			goto out;
		}
	}

	if (cqe_flushed)
		wc->status = IBV_WC_WR_FLUSH_ERR;
	else {

		switch (CQE_STATUS(&cqe)) {
		case T4_ERR_SUCCESS:
			wc->status = IBV_WC_SUCCESS;
			break;
		case T4_ERR_STAG:
			wc->status = IBV_WC_LOC_ACCESS_ERR;
			break;
		case T4_ERR_PDID:
			wc->status = IBV_WC_LOC_PROT_ERR;
			break;
		case T4_ERR_QPID:
		case T4_ERR_ACCESS:
			wc->status = IBV_WC_LOC_ACCESS_ERR;
			break;
		case T4_ERR_WRAP:
			wc->status = IBV_WC_GENERAL_ERR;
			break;
		case T4_ERR_BOUND:
			wc->status = IBV_WC_LOC_LEN_ERR;
			break;
		case T4_ERR_INVALIDATE_SHARED_MR:
		case T4_ERR_INVALIDATE_MR_WITH_MW_BOUND:
			wc->status = IBV_WC_MW_BIND_ERR;
			break;
		case T4_ERR_CRC:
		case T4_ERR_MARKER:
		case T4_ERR_PDU_LEN_ERR:
		case T4_ERR_OUT_OF_RQE:
		case T4_ERR_DDP_VERSION:
		case T4_ERR_RDMA_VERSION:
		case T4_ERR_DDP_QUEUE_NUM:
		case T4_ERR_MSN:
		case T4_ERR_TBIT:
		case T4_ERR_MO:
		case T4_ERR_MSN_RANGE:
		case T4_ERR_IRD_OVERFLOW:
		case T4_ERR_OPCODE:
		case T4_ERR_INTERNAL_ERR:
			wc->status = IBV_WC_FATAL_ERR;
			break;
		case T4_ERR_SWFLUSH:
			wc->status = IBV_WC_WR_FLUSH_ERR;
			break;
		default:
			PDBG("Unexpected cqe_status 0x%x for QPID=0x%0x\n",
			     CQE_STATUS(&cqe), CQE_QPID(&cqe));
			wc->status = IBV_WC_FATAL_ERR;
		}
	}
	if (wc->status && wc->status != IBV_WC_WR_FLUSH_ERR)
		syslog(LOG_NOTICE, "cxgb4 app err cqid %u qpid %u "
			"type %u opcode %u status 0x%x\n",
			chp->cq.cqid, CQE_QPID(&cqe), CQE_TYPE(&cqe),
			CQE_OPCODE(&cqe), CQE_STATUS(&cqe));
out:
	if (wq)
		pthread_spin_unlock(&qhp->lock);
	return ret;
}

static inline int cq_notempty(struct c4iw_cq *chp)
{
	return t4_cq_notempty(&chp->cq) ||
	       (chp->iq ? t4_iq_notempty(chp->iq) : 0);
}

static int peek_raw_cq(struct c4iw_cq *chp, struct ibv_wc *wc)
{
	int err;

	pthread_spin_lock(&chp->lock);
	err = raw_poll_iq(chp, wc, 1);
	pthread_spin_unlock(&chp->lock);

	if (err) {
		if (err == -ENODATA) {
			err = 0;
		}
	} else {
		err = 1;
	}
	return err;
}

int c4iw_poll_cq(struct ibv_cq *ibcq, int num_entries, struct ibv_wc *wc)
{
	struct c4iw_cq *chp;
	int npolled;
	int err = 0;

	chp = to_c4iw_cq(ibcq);

	if (t4_cq_in_error(&chp->cq)) {
		t4_reset_cq_in_error(&chp->cq);
		c4iw_flush_qps(chp->rhp);
	}

	if (!num_entries)
		return cq_notempty(chp);

	if (num_entries == -1 && chp->iq)
		return peek_raw_cq(chp, wc);

	pthread_spin_lock(&chp->lock);
	for (npolled = 0; npolled < num_entries; ++npolled) {
		do {
			err = c4iw_poll_cq_one(chp, wc + npolled);
		} while (err == -EAGAIN);
		if (err)
			break;
	}
	pthread_spin_unlock(&chp->lock);
	return !err || err == -ENODATA ? npolled : err;
}

int c4iw_arm_cq(struct ibv_cq *ibcq, int solicited)
{
	struct c4iw_cq *chp;
	int ret;

	INC_STAT(arm);
	chp = to_c4iw_cq(ibcq);
	pthread_spin_lock(&chp->lock);
	ret = t4_arm_cq(&chp->cq, solicited);
	if (!ret && chp->iq)
		ret = t4_arm_iq(chp->iq);
	pthread_spin_unlock(&chp->lock);
	return ret;
}
