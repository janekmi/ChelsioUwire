/*
 *  Copyright (C) 2008-2014 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description:
 *
 */

#include <csio_hw.h>
#include <csio_wr.h>
#include <csio_mb.h>
#include <csio_defs.h>
#include <csio_t4_ioctl.h>

int csio_intr_coalesce_cnt = 0;		/* value:SGE_INGRESS_RX_THRESHOLD[0] */
static int csio_sge_thresh_reg = 0;	/* SGE_INGRESS_RX_THRESHOLD[0] */

int csio_intr_coalesce_time = 10;	/* value:A_SGE_TIMER_VALUE_1 */
static int csio_sge_timer_reg = 1;

#define csio_set_flbuf_size(_hw, _reg, _val)				      \
do {									      \
	t4_write_reg(&((_hw)->adap), A_SGE_FL_BUFFER_SIZE##_reg, (_val));	      \
} while(0)

static void
csio_get_flbuf_size(struct csio_hw *hw, struct csio_sge *sge, uint32_t reg)
{
	sge->sge_fl_buf_size[reg] = t4_read_reg(&hw->adap, A_SGE_FL_BUFFER_SIZE0 +
							reg * sizeof(uint32_t));
}

csio_retval_t
csio_get_sge_q_info(struct csio_hw *hw, void *buffer, uint32_t buffer_len)
{
	struct csio_wrm *wrm = csio_hw_to_wrm(hw);
	csio_q_info_t *q_info = buffer;
	struct csio_q *q = NULL;

	if (buffer_len < sizeof(csio_q_info_t))
		return CSIO_NOMEM;

	/* Is it vaild queue? */
	if (q_info->q_idx > wrm->num_q)
		return CSIO_INVAL;

	q = wrm->q_arr[q_info->q_idx];

	/* Populate the information. */
	q_info->pidx = q->pidx;
	q_info->cidx = q->cidx;
	q_info->vstart = (uintptr_t)q->vstart;
	q_info->size = q->size;
	q_info->inc_idx = q->inc_idx;
	q_info->wr_sz = q->wr_sz;
	q_info->credits = q->credits;

	if (q->type == CSIO_INGRESS) {
		struct csio_iq *iq = &q->un.iq;
		csio_iq_t *iq_info = &q_info->un.iq_info;
		
		q_info->type = CHSTOR_INGRESS;

		iq_info->iqid = iq->iqid;
		iq_info->physiqid = iq->physiqid;
		iq_info->genbit = iq->genbit;
		iq_info->flq_idx = iq->flq_idx;
	}
	else if (q->type == CSIO_EGRESS) {
		struct csio_eq *eq = &q->un.eq;
		csio_eq_t *eq_info = &q_info->un.eq_info;
		struct csio_qstatus_page *stp = (struct csio_qstatus_page *)
								q->vwrap;
		q_info->type = CHSTOR_EGRESS;
		q_info->cidx = csio_ntohs(stp->cidx);
		eq_info->eqid = eq->eqid;
		eq_info->physeqid = eq->physeqid;
		eq_info->aqid = eq->aqid;
	}
	else if (q->type == CSIO_FREELIST) {
		struct csio_fl *flq = &q->un.fl;
		csio_fl_t *flq_info = &q_info->un.fl_info;
		
		q_info->type = CHSTOR_FREELIST;

		flq_info->flid = flq->flid;
		flq_info->packen = flq->packen;
		flq_info->offset = flq->offset;
		flq_info->sreg = flq->sreg;
	}

	q_info->stats.n_qentry		= q->stats.n_qentry;
	q_info->stats.n_qempty		= q->stats.n_qempty;
	q_info->stats.n_qfull		= q->stats.n_qfull;
	q_info->stats.n_qwrap		= q->stats.n_qwrap;
	q_info->stats.n_tot_reqs	= q->stats.n_tot_reqs;
	q_info->stats.n_eq_wr_split	= q->stats.n_eq_wr_split;
	q_info->stats.n_tot_rsps	= q->stats.n_tot_rsps;
	q_info->stats.n_rsp_unknown	= q->stats.n_rsp_unknown;
	q_info->stats.n_stray_comp	= q->stats.n_stray_comp;
	q_info->stats.n_flq_refill	= q->stats.n_flq_refill;


	return CSIO_SUCCESS;
} /* csio_get_sge_q_info */

csio_retval_t
csio_get_sge_flq_buf_info(struct csio_hw *hw, void *buffer, uint32_t buffer_len)
{
	struct csio_wrm *wrm = csio_hw_to_wrm(hw);
	csio_fl_dma_info_t *fl_dma_info = buffer;
	struct csio_q *q = NULL;
	struct csio_dma_buf *buf = NULL;

	if (buffer_len < sizeof(csio_fl_dma_info_t))
		return CSIO_NOMEM;

	/* Is it vaild queue? */
	if (fl_dma_info->q_idx > wrm->num_q)
		return CSIO_INVAL;

	q = wrm->q_arr[fl_dma_info->q_idx];

	/* Is it Free-List Queue & does it have FL-buffer? */
	if (q->type != CSIO_FREELIST || !q->un.fl.bufs)
		return CSIO_INVAL;
	/* Is it the valid fl-entry? */
	if (fl_dma_info->fl_entry > q->credits)
		return CSIO_INVAL;

	/* Get the FL-buffer*/
	buf = &q->un.fl.bufs[fl_dma_info->fl_entry];

	if (!buf->vaddr)
		return CSIO_INVAL;

	fl_dma_info->vaddr = (uintptr_t)buf->vaddr;
	fl_dma_info->paddr = (uint64_t)csio_phys_addr(buf->paddr);
	fl_dma_info->len = buf->len;

	return CSIO_SUCCESS;	
} /* csio_get_sge_q_info */


/* Free list buffer size */
static inline uint32_t
csio_wr_fl_bufsz(struct csio_sge *sge, struct csio_dma_buf *buf)
{
	return sge->sge_fl_buf_size[csio_phys_addr(buf->paddr) & 0xF];
}

/* Size of the egress queue status page */
static inline uint32_t
csio_wr_qstat_pgsz(struct csio_hw *hw)
{
	return (hw->wrm.sge.sge_control & F_EGRSTATUSPAGESIZE) ?  128 : 64;
}

/* Ring freelist doorbell */
static inline void
csio_wr_ring_fldb(struct csio_hw *hw, struct csio_q *flq)
{
	/*
	 * Ring the doorbell only when we have atleast CSIO_QCREDIT_SZ
	 * number of bytes in the freelist queue. This translates to atleast
	 * 8 freelist buffer pointers (since each pointer is 8 bytes).
	 */
	if (flq->inc_idx >= 8) {
		u32 val;

		if (is_t4(hw->adap.params.chip))
			val = V_PIDX(flq->inc_idx / 8);
		else
			val = V_PIDX_T5(flq->inc_idx / 8) | F_DBTYPE;
		val |= F_DBPRIO;

		/*
		 * Make sure all memory writes to the Free List queue are
		 * committed before we tell the hardware about them.
		 */
		csio_wmb();

		if (unlikely(flq->bar2_addr == NULL)) {
			t4_write_reg(&hw->adap, MYPF_REG(A_SGE_PF_KDOORBELL),
				     val | V_QID(flq->un.fl.flid));
		} else {
			writel(val | V_QID(flq->bar2_qid),
				flq->bar2_addr + SGE_UDB_KDOORBELL);
			csio_wmb();
		}

		flq->inc_idx &= 7;
	}
}

/* Write a 0 cidx increment value to enable SGE interrupts for this queue */
static void
csio_wr_sge_intr_enable(struct csio_hw *hw, uint16_t iqid)
{
	t4_write_reg(&hw->adap, MYPF_REG(A_SGE_PF_GTS), V_CIDXINC(0) |
			  V_INGRESSQID(iqid)	|
			  V_TIMERREG(X_TIMERREG_RESTART_COUNTER));
	return;
}

/*
 *     csio_bar2_address - return the BAR2 address for an SGE Queue's Registers
 *     @adapter: the adapter
 *     @qid: the SGE Queue ID
 *     @qtype: the SGE Queue Type (Egress or Ingress)
 *     @pbar2_qid: BAR2 Queue ID or 0 for Queue ID inferred SGE Queues
 *
 *     Returns the BAR2 address for the SGE Queue Registers associated with
 *     @qid.  If BAR2 SGE Registers aren't available, returns NULL.  Also
 *     returns the BAR2 Queue ID to be used with writes to the BAR2 SGE
 *     Queue Registers.  If the BAR2 Queue ID is 0, then "Inferred Queue ID"
 *     Registers are supported (e.g. the Write Combining Doorbell Buffer).
 */
static void __iomem *csio_bar2_address(struct adapter *adapter, unsigned int qid,
				       enum t4_bar2_qtype qtype,
				       unsigned int *pbar2_qid)
{
	u64 bar2_qoffset;
	int ret;

	ret = t4_bar2_sge_qregs(adapter, qid, qtype, 0,
				&bar2_qoffset, pbar2_qid);
	if (ret)
		return NULL;

	return adapter->bar2 + bar2_qoffset;
}

/*
 * csio_wr_fill_fl - Populate the FL buffers of a FL queue.
 * @hw: HW module.
 * @flq: Freelist queue.
 *
 * Fill up freelist buffer entries with buffers of size specified
 * in the size register.
 *
 */
static csio_retval_t
csio_wr_fill_fl(struct csio_hw *hw, struct csio_q *flq)
{
	struct csio_wrm *wrm = csio_hw_to_wrm(hw);
	struct csio_sge *sge = &wrm->sge;
	__be64 *d = (__be64 *)(flq->vstart);
	struct csio_dma_buf *buf = &flq->un.fl.bufs[0];
	uint64_t paddr;
	int sreg = flq->un.fl.sreg;
	int n = flq->credits;

	while (n--) {
		buf->len = sge->sge_fl_buf_size[sreg];
		buf->vaddr = csio_dma_pool_alloc(&buf->dmahdl, hw->os_dev,
						 buf->len, 16,
						 &buf->paddr, CSIO_MNOWAIT);
		if (!buf->vaddr) {
			csio_err(hw, "Could only fill %d buffers!\n", n + 1);
			/* TODO: Free up existing allocated buffers */
			return CSIO_NOMEM;
		}

		paddr = csio_phys_addr(buf->paddr) | (sreg & 0xF);

		*d++ = csio_cpu_to_be64(paddr);
		buf++;
	}

	return CSIO_SUCCESS;
}

/*
 * csio_wr_update_fl -
 * @hw: HW module.
 * @flq: Freelist queue.
 *
 *
 */
static inline void
csio_wr_update_fl(struct csio_hw *hw, struct csio_q *flq, uint16_t n)
{
#ifdef __CSIO_SW_DDP__
	struct csio_wrm *wrm = csio_hw_to_wrm(hw);
	struct csio_sge *sge = &wrm->sge;
	__be64 *d = (__be64 *)((uintptr_t)(flq->vstart) +
						(flq->pidx * sizeof(__be64)));
	struct csio_dma_buf *buf = &flq->un.fl.bufs[flq->pidx];
	uint64_t paddr;
	int sreg = flq->un.fl.sreg;

	while (n--) {
		buf->len = sge->sge_fl_buf_size[sreg];
		buf->vaddr = csio_dma_pool_alloc(&buf->dmahdl, hw->os_dev,
						 buf->len, 16,
						 &buf->paddr, CSIO_MNOWAIT);
		if (!buf->vaddr) {
			csio_err(hw, "Could only fill %d buffers!\n", n + 1);
			/* TODO: Free up existing allocated buffers */
			return;
		}

		paddr = csio_phys_addr(buf->paddr) | (sreg & 0xF);

		*d++ = csio_cpu_to_be64(paddr);
		buf++;
		flq->pidx++;

		if (csio_unlikely(flq->pidx >= flq->credits)) {
			flq->pidx = 0;
			buf = &flq->un.fl.bufs[0];
			d = (__be64 *)(flq->vstart);
		}
		flq->inc_idx++;
	}
#else
	flq->inc_idx += n;
	flq->pidx += n;
	if (csio_unlikely(flq->pidx >= flq->credits))
		flq->pidx -= (uint16_t)flq->credits;
#endif /* __CSIO_SW_DDP__ */

	CSIO_INC_STATS(flq, n_flq_refill);

	return;
}

/*
 * csio_wr_alloc_q - Allocate a WR queue and initialize it.
 * @hw: HW module
 * @qsize: Size of the queue in bytes
 * @wrsize: Since of WR in this queue, if fixed.
 * @type: Type of queue (Ingress/Egress/Freelist)
 * @owner: Module that owns this queue.
 * @nflb: Number of freelist buffers for FL.
 * @sreg: What is the FL buffer size register?
 * @md_idx: Memory descriptor index to be used for the Freelist bufs.
 * @iq_int_handler: Ingress queue handler in INTx mode.
 *
 * This function allocates and sets up a queue for the caller
 * of size qsize, aligned at the required boundary. This is subject to
 * be free entries being available in the queue array. If one is found,
 * it is initialized with the allocated queue, marked as being used (owner),
 * and a handle returned to the caller in form of the queue's index
 * into the q_arr array.
 * If user has indicated a freelist (by specifying nflb > 0), create
 * another queue (with its own index into q_arr) for the freelist. Allocate
 * memory for DMA buffer metadata (vaddr, len etc). Save off the freelist
 * idx in the ingress queue's flq.idx. This is how a Freelist is associated
 * with its owning ingress queue.
 */
int
csio_wr_alloc_q(struct csio_hw *hw, uint32_t qsize, uint32_t wrsize,
		uint16_t type, void *owner, uint32_t nflb, int sreg,
		int md_idx, iq_handler_t iq_intx_handler)
{
	struct csio_wrm *wrm = csio_hw_to_wrm(hw);
	struct csio_q	*q, *flq;
	int		free_idx = wrm->free_qidx;
	int		ret_idx = free_idx;
	uint32_t	qsz;
	int flq_idx;

	if (free_idx >= wrm->num_q) {
		csio_err(hw, "No more free queues.\n");
		return -1;
	}
	
	switch (type) {
	case CSIO_EGRESS:
		qsz = CSIO_ALIGN(qsize, CSIO_QCREDIT_SZ) +
							csio_wr_qstat_pgsz(hw);
		break;
	case CSIO_INGRESS:
		switch (wrsize) {
		case 16: case 32: case 64: case 128:	break;
		default:
			csio_err(hw, "Invalid Ingress queue WR size:%d\n",
				    wrsize);
			return -1;
		}
				
		/*
		 * Number of elements must be a multiple of 16
		 * So this includes status page size
		 */
		qsz = CSIO_ALIGN(qsize/wrsize, 16) * wrsize;

		break;
	case CSIO_FREELIST:
		qsz = CSIO_ALIGN(qsize/wrsize, 8) * wrsize +
							csio_wr_qstat_pgsz(hw);
		break;
	default:
		csio_err(hw, "Invalid queue type: 0x%x\n", type);
		return -1;
	}

	q = wrm->q_arr[free_idx];

	/* All queues have to be aligned at X_BASEADDRESS_ALIGN */
	q->vstart = csio_dma_alloc(&q->dmahdl, hw->os_dev, qsz,
				     X_BASEADDRESS_ALIGN, &q->pstart,
				     CSIO_MWAIT);
	if (!q->vstart) {
		csio_err(hw, "Failed to allocate DMA memory for "
			"queue at id: %d size: %d\n", free_idx, qsize);
		return -1;
	}

	/*
	 * We need to zero out the contents, importantly for ingress,
	 * since we start with a generatiom bit of 1 for ingress.
	 */
	csio_memset(q->vstart, 0, qsz);

	q->type		= type;
	q->owner	= owner;
	q->pidx 	= q->cidx = q->inc_idx = 0;
	q->size		= qsz;
	q->wr_sz	= wrsize;	/* If using fixed size WRs */

	wrm->free_qidx++;

	if (type == CSIO_INGRESS) {
		/* Since queue area is set to zero */
		q->un.iq.genbit	= 1;

		/*
		 * Ingress queue status page size is always the size of
		 * the ingress queue entry.
		 */
		q->credits	= (qsz - q->wr_sz) / q->wr_sz;
		q->vwrap 	= (void *)((uintptr_t)(q->vstart) + qsz
							- q->wr_sz);

		/* Allocate memory for FL if requested */
		if (nflb > 0) {
			if (md_idx >= CSIO_MAX_MEM_DESCS) {
				csio_err(hw, "Incorrect mem descriptor %d for"
					    " IQ idx:%d\n", md_idx, free_idx);
				return -1;
			}

			flq_idx = csio_wr_alloc_q(hw, nflb * sizeof(__be64),
						  sizeof(__be64), CSIO_FREELIST,
						  owner, 0,
						  sreg,
						  0, NULL);
			if (flq_idx == -1) {
				csio_err(hw, "Failed to allocate FL queue"
					    " for IQ idx:%d\n", free_idx);
				return -1;
			}

			/* Associate the new FL with the Ingress quue */
			q->un.iq.flq_idx = flq_idx;
			
			flq = wrm->q_arr[q->un.iq.flq_idx];
			flq->un.fl.bufs = csio_alloc(
					     csio_md(hw, md_idx),
					     flq->credits *
						sizeof(struct csio_dma_buf),
					     CSIO_MNOWAIT);
			if (!flq->un.fl.bufs) {
				csio_err(hw, "Failed to allocate FL queue bufs"
					    " for IQ idx:%d\n", free_idx);
				return -1;
			}

			/* Cache memory desc index to be used for freeing */
			flq->un.fl.md_idx = md_idx;

			/*
			 * Disable free list packing for now. In case we need it
			 * later, this field has to be made equal to 1
			 */
			flq->un.fl.packen = 0;
			flq->un.fl.offset = 0;
			flq->un.fl.sreg = sreg;

			/* Fill up the free list buffers */
			if (csio_wr_fill_fl(hw, flq))
				return -1;
			
			/*
			 * Make sure in a FLQ, atleast 1 credit (8 FL buffers)
			 * remains unpopulated,otherwise HW thinks
			 * FLQ is empty.
			 */
			flq->pidx = flq->inc_idx = flq->credits - 8;
		} else {
			q->un.iq.flq_idx = -1;
		}

		/* Associate the IQ INTx handler. */
		q->un.iq.iq_intx_handler = iq_intx_handler;

		csio_q_iqid(hw, ret_idx) = CSIO_MAX_QID;

	} else if (type == CSIO_EGRESS) {
		q->credits = (qsz - csio_wr_qstat_pgsz(hw)) / CSIO_QCREDIT_SZ;
		q->vwrap   = (void *)((uintptr_t)(q->vstart) + qsz
						- csio_wr_qstat_pgsz(hw));
		csio_q_eqid(hw, ret_idx) = CSIO_MAX_QID;
	} else { /* Freelist */
		q->credits = (qsz - csio_wr_qstat_pgsz(hw)) / sizeof(__be64);
		q->vwrap   = (void *)((uintptr_t)(q->vstart) + qsz
						- csio_wr_qstat_pgsz(hw));
		csio_q_flid(hw, ret_idx) = CSIO_MAX_QID;
	}

	return ret_idx;
}

/*
 * csio_wr_iq_create_rsp - Response handler for IQ creation.
 * @hw: The HW module.
 * @mbp: Mailbox.
 * @iq_idx: Ingress queue that got created.
 *
 * Handle FW_IQ_CMD mailbox completion. Save off the assigned IQ/FL ids.
 */
csio_retval_t
csio_wr_iq_create_rsp(struct csio_hw *hw, struct fw_iq_cmd *rsp, int iq_idx)
{
	struct csio_iq_params iqp;
	uint32_t iq_id;
	int flq_idx;

	csio_memset(&iqp, 0, sizeof(struct csio_iq_params));

	csio_mb_iq_alloc_write_rsp(rsp, &iqp);

	csio_q_iqid(hw, iq_idx)		= iqp.iqid;
	csio_q_physiqid(hw, iq_idx)	= iqp.physiqid;
	csio_q_pidx(hw, iq_idx) 	= csio_q_cidx(hw, iq_idx) = 0;
	csio_q_inc_idx(hw, iq_idx)	= 0;

	csio_q_bar2qaddr(hw, iq_idx)	= csio_bar2_address(&hw->adap,
						csio_q_iqid(hw, iq_idx),
						T4_BAR2_QTYPE_INGRESS,
						&csio_q_bar2qid(hw, iq_idx));

	/* Actual iq-id. */
	iq_id = iqp.iqid - hw->wrm.fw_iq_start;

	/* Set the iq-id to iq map table. */
	if(iq_id >= CSIO_MAX_IQ) {
		csio_err(hw, "Exceeding MAX_IQ(%d) supported!"
				" iq_id:%d rel_iq_id:%d fw_iq_start:%d\n",
				CSIO_MAX_IQ, iq_id,
				iqp.iqid, hw->wrm.fw_iq_start);
		return CSIO_INVAL;
	}
	csio_q_set_intr_map(hw, iq_idx, iq_id);

	/*
	 * During FW_IQ_CMD, FW sets interrupt_sent bit to 1 in the SGE
	 * ingress context of this queue. This will block interrupts to
	 * this queue until the next GTS write. Therefore, we do a
	 * 0-cidx increment GTS write for this queue just to clear the
	 * interrupt_sent bit. This will re-enable interrupts to this
	 * queue.
	 */
	csio_wr_sge_intr_enable(hw, iqp.physiqid);

	if ((flq_idx = csio_q_iq_flq_idx(hw, iq_idx)) != -1) {
		struct csio_q *flq = hw->wrm.q_arr[flq_idx];

		csio_q_flid(hw, flq_idx) = iqp.fl0id;
		csio_q_cidx(hw, flq_idx) = 0;
		csio_q_pidx(hw, flq_idx)    = csio_q_credits(hw, flq_idx) - 8;
		csio_q_inc_idx(hw, flq_idx) = csio_q_credits(hw, flq_idx) - 8;

		csio_q_bar2qaddr(hw, flq_idx) = csio_bar2_address(&hw->adap,
							csio_q_flid(hw, flq_idx),
							T4_BAR2_QTYPE_EGRESS,
							&csio_q_bar2qid(hw, flq_idx));

		/* Now update SGE about the buffers allocated during init */
		csio_wr_ring_fldb(hw, flq);
	}

	return CSIO_SUCCESS;
}

/*
 * csio_wr_iq_create - Configure an Ingress queue with FW.
 * @hw: The HW module.
 * @iq_idx: Ingress queue index in the WR module.
 * @vec: MSIX vector.
 * @portid: PCIE Channel to be associated with this queue.
 * @async: Is this a FW asynchronous message handling queue?
 *
 * This API configures an ingress queue with FW by issuing a FW_IQ_CMD mailbox
 * with alloc/write bits set.
 */
csio_retval_t
csio_wr_iq_create(struct csio_hw *hw, int iq_idx,
		  uint32_t vec, uint8_t portid, bool async)
{
	struct adapter *adap = &hw->adap;
	struct fw_iq_cmd c;
	struct csio_iq_params iqp;
	int flq_idx, ret;

	csio_memset(&iqp, 0, sizeof(struct csio_iq_params));
	csio_q_portid(hw, iq_idx) = portid;

	switch (hw->intr_mode) {
		case CSIO_IM_INTX:
		case CSIO_IM_MSI:
			/* For interrupt forwarding queue only */
			if (hw->intr_iq_idx == iq_idx)
				iqp.iqandst	= X_INTERRUPTDESTINATION_PCIE;
			else
				iqp.iqandst	= X_INTERRUPTDESTINATION_IQ;
			iqp.iqandstindex	=
				csio_q_physiqid(hw, hw->intr_iq_idx);
			break;
		case CSIO_IM_MSIX:
			iqp.iqandst		= X_INTERRUPTDESTINATION_PCIE;
			iqp.iqandstindex 	= (uint16_t)vec;
			break;
		case CSIO_IM_NONE:
			/*
			 * OS Interrupts should be enabled
			 * before this function call.
			 */
			return CSIO_INVAL;
	}

	/* Pass in the ingress queue cmd parameters */
	iqp.pfn 		= hw->pfn;
	iqp.vfn 		= 0;
	iqp.iq_start 		= 1;
	iqp.viid 		= 0;
	iqp.type 		= FW_IQ_TYPE_FL_INT_CAP;
	iqp.iqasynch 		= async;
	if (csio_intr_coalesce_cnt)
		iqp.iqanus	= X_UPDATESCHEDULING_COUNTER_OPTTIMER;
	else
		iqp.iqanus	= X_UPDATESCHEDULING_TIMER;
	iqp.iqanud 		= X_UPDATEDELIVERY_INTERRUPT;
	iqp.iqpciech		= portid;
	iqp.iqintcntthresh	= (uint8_t)csio_sge_thresh_reg;

	switch (csio_q_wr_sz(hw, iq_idx)) {
		case 16: iqp.iqesize = 0; break;
		case 32: iqp.iqesize = 1; break;
		case 64: iqp.iqesize = 2; break;
		case 128: iqp.iqesize = 3; break;
	}

	iqp.iqsize 		= csio_q_size(hw, iq_idx) /
						csio_q_wr_sz(hw, iq_idx);
	iqp.iqaddr 		= csio_phys_addr(csio_q_pstart(hw, iq_idx));
	
	if ((flq_idx = csio_q_iq_flq_idx(hw, iq_idx)) != -1) {
		enum chip_type chip = CHELSIO_CHIP_VERSION(adap->params.chip);
		struct csio_q *flq = hw->wrm.q_arr[flq_idx];
		
		iqp.fl0paden 	= 1;
		iqp.fl0packen 	= flq->un.fl.packen? 1 : 0;
		iqp.fl0fbmin 	= chip <= CHELSIO_T5 ?
			X_FETCHBURSTMIN_128B : X_FETCHBURSTMIN_64B;
		iqp.fl0fbmax 	= chip <= CHELSIO_T5 ?
			X_FETCHBURSTMAX_512B : X_FETCHBURSTMAX_256B;
		iqp.fl0size	= csio_q_size(hw, flq_idx) / CSIO_QCREDIT_SZ;
		iqp.fl0addr 	= csio_phys_addr(csio_q_pstart(hw, flq_idx));
	}
	
	csio_mb_iq_alloc_write(&c, &iqp);

	ret = t4_wr_mbox(adap, adap->mbox, &c, sizeof(c), &c);
	if (ret) {
		csio_err(hw, "IQ cmd returned 0x%x!\n", ret);
		return CSIO_INVAL;
	}

	return csio_wr_iq_create_rsp(hw, &c, iq_idx);
}

/*
 * csio_wr_eq_create_rsp - Response handler for EQ creation.
 * @hw: The HW module.
 * @rsp: Mailbox response.
 * @eq_idx: Egress queue that got created.
 *
 * Handle FW_EQ_OFLD_CMD mailbox completion. Save off the assigned EQ ids.
 */
csio_retval_t
csio_wr_eq_create_rsp(struct csio_hw *hw, struct fw_eq_ofld_cmd *rsp, int eq_idx)
{
	struct csio_eq_params eqp;

	csio_memset(&eqp, 0, sizeof(struct csio_eq_params));

	csio_mb_eq_ofld_alloc_write_rsp(rsp, &eqp);

	csio_q_eqid(hw, eq_idx)	= (uint16_t)eqp.eqid;
	csio_q_physeqid(hw, eq_idx) = (uint16_t)eqp.physeqid;
	csio_q_pidx(hw, eq_idx)	= csio_q_cidx(hw, eq_idx) = 0;
	csio_q_inc_idx(hw, eq_idx) = 0;

	return CSIO_SUCCESS;
}

/*
 * csio_wr_eq_create - Configure an Egress queue with FW.
 * @hw: HW module.
 * @eq_idx: Egress queue index in the WR module.
 * @iq_idx: Associated ingress queue index.
 *
 * This API configures a offload egress queue with FW by issuing a
 * FW_EQ_OFLD_CMD  (with alloc + write ) mailbox.
 */
csio_retval_t
csio_wr_eq_create(struct csio_hw *hw, int eq_idx, int iq_idx, uint8_t portid)
{
	struct adapter *adap = &hw->adap;
	struct csio_wrm *wrm	    = csio_hw_to_wrm(hw);
	struct csio_q   *q	      = wrm->q_arr[eq_idx];
	struct fw_eq_ofld_cmd c;
	int ret;
	struct csio_eq_params eqp;

	csio_memset(&eqp, 0, sizeof(struct csio_eq_params));

	eqp.pfn			= hw->pfn;
	eqp.vfn			= 0;
	eqp.eqstart		= 1;
	eqp.hostfcmode		= X_HOSTFCMODE_STATUS_PAGE;
	eqp.iqid		= csio_q_iqid(hw, iq_idx);
	eqp.fbmin		= X_FETCHBURSTMIN_64B;
	eqp.fbmax		= X_FETCHBURSTMAX_512B;
	eqp.cidxfthresh		= 0;		/* REVISIT */
	eqp.pciechn		= portid;
	eqp.eqsize 		= csio_q_size(hw, eq_idx) / CSIO_QCREDIT_SZ;
	eqp.eqaddr 		= csio_phys_addr(csio_q_pstart(hw, eq_idx));

	csio_mb_eq_ofld_alloc_write(&c, &eqp);

	ret = t4_wr_mbox(adap, adap->mbox, &c, sizeof(c), &c);
	if (ret) {
		csio_err(hw, "EQ OFLD cmd returned 0x%x!\n", ret);
		return CSIO_INVAL;
	}

	q->bar2_addr = csio_bar2_address(adap, G_FW_EQ_OFLD_CMD_EQID(ntohl(c.eqid_pkd)),
					 T4_BAR2_QTYPE_EGRESS,
					 &q->bar2_qid);

	return csio_wr_eq_create_rsp(hw, &c, eq_idx);
}

/*
 * csio_wr_iq_destroy - Free an ingress queue.
 * @hw: The HW module.
 * @iq_idx: Ingress queue index to destroy
 *
 * This API frees an ingress queue by issuing the FW_IQ_CMD
 * with the free bit set.
 */
csio_retval_t
csio_wr_iq_destroy(struct csio_hw *hw, int iq_idx)
{
	struct adapter *adap = &hw->adap;
	struct fw_iq_cmd c;
	struct csio_iq_params iqp;
	int flq_idx, ret;

	csio_memset(&iqp, 0, sizeof(struct csio_iq_params));

	iqp.pfn 	= hw->pfn;
	iqp.vfn 	= 0;
	iqp.iqid	= csio_q_iqid(hw, iq_idx);
	iqp.type 	= FW_IQ_TYPE_FL_INT_CAP;

	if ((flq_idx = csio_q_iq_flq_idx(hw, iq_idx)) != -1)
		iqp.fl0id = csio_q_flid(hw, flq_idx);
	else
		iqp.fl0id = 0xFFFF;

	iqp.fl1id = 0xFFFF;

	csio_mb_iq_free(&c, &iqp);

	ret = t4_wr_mbox(adap, adap->mbox, &c, sizeof(c), &c);
	if (ret) {
		csio_dbg(hw, "IQ (free) cmd returned 0x%x!\n", ret);
		return ret;
	}

	return CSIO_SUCCESS;
}

/*
 * csio_wr_eq_destroy - Free an Egress queue.
 * @hw: The HW module.
 * @eq_idx: Egress queue index to destroy
 *
 * This API frees an Egress queue by issuing the FW_EQ_OFLD_CMD
 * with the free bit set.
 */
static csio_retval_t
csio_wr_eq_destroy(struct csio_hw *hw, int eq_idx)
{
	struct adapter *adap = &hw->adap;
	struct fw_eq_ofld_cmd c;
	struct csio_eq_params eqp;
	int ret;

	csio_memset(&eqp, 0, sizeof(struct csio_eq_params));

	eqp.pfn 	= hw->pfn;
	eqp.vfn 	= 0;
	eqp.eqid	= csio_q_eqid(hw, eq_idx);

	csio_mb_eq_ofld_free(&c, &eqp);

	ret = t4_wr_mbox(adap, adap->mbox, &c, sizeof(c), &c);
	if (ret) {
		csio_dbg(hw, "EQ (free) cmd returned 0x%x!\n", ret);
		return ret;
	}

	return CSIO_SUCCESS;
}

/*
 * csio_wr_cleanup_eq_stpg - Cleanup Egress queue status page
 * @hw: HW module
 * @qidx: Egress queue index
 *
 * Cleanup the Egress queue status page.
 */
static void
csio_wr_cleanup_eq_stpg(struct csio_hw *hw, int qidx)
{
	struct csio_q	*q = csio_hw_to_wrm(hw)->q_arr[qidx];
	struct csio_qstatus_page *stp = (struct csio_qstatus_page *)q->vwrap;

	csio_memset(stp, 0, sizeof(*stp));
}

/*
 * csio_wr_cleanup_iq_ftr - Cleanup Footer entries in IQ
 * @hw: HW module
 * @qidx: Ingress queue index
 *
 * Cleanup the footer entries in the given ingress queue,
 * set to 1 the internal copy of genbit.
 */
static void
csio_wr_cleanup_iq_ftr(struct csio_hw *hw, int qidx)
{
	struct csio_wrm *wrm 	= csio_hw_to_wrm(hw);
	struct csio_q	*q 	= wrm->q_arr[qidx];
	void *wr;
	struct csio_iqwr_footer *ftr;
	uint32_t i = 0;

	/* set to 1 since we are just about zero out genbit */
	q->un.iq.genbit = 1;

	for (i = 0; i < q->credits; i++) {
		/* Get the WR */
		wr = (void *)((uintptr_t)q->vstart +
					   (i * q->wr_sz));
		/* Get the footer */
		ftr = (struct csio_iqwr_footer *)((uintptr_t)wr +
					  (q->wr_sz - sizeof(*ftr)));
		/* Zero out footer */
		csio_memset(ftr, 0, sizeof(*ftr));
	}
}

csio_retval_t
csio_wr_destroy_queues(struct csio_hw *hw, bool cmd)
{
	int i, flq_idx;
	struct csio_q *q;
	struct csio_wrm *wrm = csio_hw_to_wrm(hw);
	enum csio_oss_error rv;

	for (i = 0; i < wrm->free_qidx; i++) {
		q = wrm->q_arr[i];

		switch (q->type) {
		case CSIO_EGRESS:
			if (csio_q_eqid(hw, i) != CSIO_MAX_QID) {
				csio_wr_cleanup_eq_stpg(hw, i);
				if (!cmd) {
					csio_q_eqid(hw, i) = CSIO_MAX_QID;
					continue;
				}

				rv = csio_wr_eq_destroy(hw, i);
				/* FW could be dead, so quit issuing MB */
				if ((rv == CSIO_BUSY) || (rv == CSIO_TIMEOUT))
					cmd = CSIO_FALSE;

				csio_q_eqid(hw, i) = CSIO_MAX_QID;
			}
		case CSIO_INGRESS:
			if (csio_q_iqid(hw, i) != CSIO_MAX_QID) {
				csio_wr_cleanup_iq_ftr(hw, i);
				if (!cmd) {
					csio_q_iqid(hw, i) = CSIO_MAX_QID;
					if ((flq_idx = csio_q_iq_flq_idx(hw, i))
									 != -1)
						csio_q_flid(hw, flq_idx) =
								CSIO_MAX_QID;
					continue;
				}

				rv = csio_wr_iq_destroy(hw, i);
				/* FW could be dead, so quit issuing MB */
				if ((rv == CSIO_BUSY) || (rv == CSIO_TIMEOUT))
					cmd = CSIO_FALSE;

				csio_q_iqid(hw, i) = CSIO_MAX_QID;
				if ((flq_idx = csio_q_iq_flq_idx(hw, i)) != -1)
					csio_q_flid(hw, flq_idx) = CSIO_MAX_QID;
			}
		default:
			break;
		}
	}

	hw->flags &= ~CSIO_HWF_Q_FW_ALLOCED;

	return CSIO_SUCCESS;
}

/*
 * csio_wr_get - Get requested size of WR entry/entries from queue.
 * @hw: HW module.
 * @qidx: Index of queue.
 * @size: Cumulative size of Work request(s).
 * @wrp: Work request pair.
 *
 * If requested credits are available, return the start address of the
 * work request in the work request pair. Set pidx accordingly and
 * return.
 *
 * NOTE about WR pair:
 * ==================
 * A WR can start towards the end of a queue, and then continue at the
 * beginning, since the queue is considered to be circular. This will
 * require a pair of address/size to be passed back to the caller -
 * hence Work request pair format.
 */
csio_retval_t
csio_wr_get(struct csio_hw *hw, int qidx, uint32_t size,
	    struct csio_wr_pair *wrp)
{
	struct csio_wrm *wrm 		= csio_hw_to_wrm(hw);
	struct csio_q	*q 		= wrm->q_arr[qidx];
	void *cwr			= (void *)((uintptr_t)(q->vstart) +
						   (q->pidx * CSIO_QCREDIT_SZ));
	struct csio_qstatus_page *stp	= (struct csio_qstatus_page *)
								q->vwrap;
	uint16_t cidx 			= q->cidx = csio_ntohs(stp->cidx);
	uint16_t pidx 			= q->pidx;
	uint32_t req_sz			= CSIO_ALIGN(size, CSIO_QCREDIT_SZ);
	int req_credits			= req_sz / CSIO_QCREDIT_SZ;
	int credits;

	CSIO_DB_ASSERT(q->owner != NULL);
	CSIO_DB_ASSERT((qidx >= 0) && (qidx < wrm->free_qidx));
	CSIO_DB_ASSERT(cidx <= q->credits);

	/* Calculate credits */
	if (pidx > cidx) {
		credits = q->credits - (pidx - cidx) - 1;
	} else if (cidx > pidx) {
		credits = cidx - pidx - 1;
	} else {
		/* cidx == pidx, empty queue */
		credits = q->credits;
		CSIO_INC_STATS(q, n_qempty);
	}

	/*
	 * Check if we have enough credits.
	 * credits = 1 implies queue is full.
	 */
	if (!credits || (req_credits > credits)) {
		csio_dbg(hw, "Queue ID:%d is full or", qidx);
		csio_dbg(hw, " not enough credits, req=%d credits = %d\n",
			req_credits, credits);
		CSIO_INC_STATS(q, n_qfull);
		return CSIO_BUSY;
	}

	/*
	 * If we are here, we have enough credits to satisfy the
	 * request. Check if we are near the end of q, and if WR spills over.
	 * If it does, use the first addr/size to cover the queue until
	 * the end. Fit the remainder portion of the request at the top
	 * of queue and return it in the second addr/len. Set pidx
	 * accordingly.
	 */
	if (csio_unlikely(((uintptr_t)cwr + req_sz) > (uintptr_t)(q->vwrap))) {
		wrp->addr1 	= cwr;
		wrp->size1 	= (uint32_t)((uintptr_t)q->vwrap -
				  (uintptr_t)cwr);
		wrp->addr2 	= q->vstart;
		wrp->size2 	= req_sz - wrp->size1;
		q->pidx		= (uint16_t)
				  (CSIO_ALIGN(wrp->size2, CSIO_QCREDIT_SZ) /
				   CSIO_QCREDIT_SZ);
		CSIO_INC_STATS(q, n_qwrap);
		CSIO_INC_STATS(q, n_eq_wr_split);
	} else {
		wrp->addr1 	= cwr;
		wrp->size1 	= req_sz;
		wrp->addr2 	= NULL;
		wrp->size2 	= 0;
		q->pidx 	+= (uint16_t)req_credits;
		/* We are the end of queue, roll back pidx to top of queue */
		if (csio_unlikely(q->pidx == q->credits)) {
			q->pidx = 0;
			CSIO_INC_STATS(q, n_qwrap);
		}
	}

	q->inc_idx = (uint16_t)req_credits;

	CSIO_INC_STATS(q, n_tot_reqs);

	return CSIO_SUCCESS;
}

/*
 * csio_wr_copy_to_wrp - Copies given data into WR.
 * @data_buf - Data buffer
 * @wrp - Work request pair.
 * @wr_off - Work request offset.	
 * @data_len - Data length.
 *
 * Copies the given data in Work Request. Work request pair(wrp) specifies
 * address information of Work request.
 * Returns: none
 */
void
csio_wr_copy_to_wrp(void *data_buf, struct csio_wr_pair *wrp,
		   uint32_t wr_off, uint32_t data_len)
{
	uint32_t nbytes;

	/* Number of space available in buffer addr1 of WRP */
	nbytes = ((wrp->size1 - wr_off) >= data_len) ?
		 data_len : (wrp->size1 - wr_off);

	csio_memcpy((uint8_t *) wrp->addr1 + wr_off, data_buf, nbytes);
	data_len -= nbytes;

	/* Write the remaining data from the begining of circular buffer */
	if (data_len) {
		CSIO_DB_ASSERT(data_len <= wrp->size2);
		CSIO_DB_ASSERT(wrp->addr2 != NULL);
		csio_memcpy(wrp->addr2, (uint8_t *) data_buf + nbytes,
			    data_len);
	}
}

/*
 * csio_wr_issue - Notify chip of Work request.
 * @hw: HW module.
 * @qidx: Index of queue.
 * @prio: 0: Low priority, 1: High priority
 *
 * Rings the SGE Doorbell by writing the current producer index of the passed
 * in queue into the register.
 *
 */
csio_retval_t
csio_wr_issue(struct csio_hw *hw, int qidx, bool prio)
{
	struct csio_wrm *wrm 		= csio_hw_to_wrm(hw);
	struct csio_q	*q 		= wrm->q_arr[qidx];
	u32 val;

	CSIO_DB_ASSERT((qidx >= 0) && (qidx < wrm->free_qidx));

	if (is_t4(hw->adap.params.chip))
		val = V_PIDX(q->inc_idx);
	else
		val = V_PIDX_T5(q->inc_idx) | F_DBTYPE;
	val |= V_DBPRIO(prio);

	csio_wmb();
	/* Ring SGE Doorbell writing q->pidx into it */
	t4_write_reg(&hw->adap, MYPF_REG(A_SGE_PF_KDOORBELL),
		     val | V_QID(q->un.eq.physeqid));

	q->inc_idx = 0;

	return CSIO_SUCCESS;
}

static inline uint32_t
csio_wr_avail_qcredits(struct csio_q *q)
{
	if (q->pidx > q->cidx)
		return q->pidx - q->cidx;
	else if (q->cidx > q->pidx)
		return q->credits - (q->cidx - q->pidx);
	else
		return 0;	/* cidx == pidx, empty queue */
}

/*
 * csio_wr_inval_flq_buf - Invalidate a free list buffer entry.
 * @hw: HW module.
 * @flq: The freelist queue.
 *
 * Invalidate the driver's version of a freelist buffer entry,
 * without freeing the associated the DMA memory. The entry
 * to be invalidated is picked up from the current Free list
 * queue cidx.
 *
 */
static inline void
csio_wr_inval_flq_buf(struct csio_hw *hw, struct csio_q *flq)
{
	flq->cidx++;
	if (flq->cidx == flq->credits) {
		flq->cidx = 0;
		CSIO_INC_STATS(flq, n_qwrap);
	}
	return;
}

/*
 * csio_wr_process_fl - Process a freelist completion.
 * @hw: HW module.
 * @q: The ingress queue attached to the Freelist.
 * @wr: The freelist completion WR in the ingress queue.
 * @len_to_qid: The lower 32-bits of the first flit of the RSP footer
 * @iq_handler: Caller's handler for this completion.
 * @priv: Private pointer of caller
 *
 * The freelist queue associated with this ingress completion is
 * picked up based on the last freelist queue cidx. If the freelist
 * entry spans more than one freelist buffer, a scatter list
 * comprising of these buffers are sent in the form of a locally
 * defined array flb.flbufs. There are 2 cases when it comes to
 * freeing the freelist buffer: immediate and deferred:
 *
 * (1) Immediate is the case when buffer packing is enabled. In this case,
 * each freelist buffer can have more than 1 completion. As a result,
 * the caller has to copy the buffer contents before returning
 * back the WR module, since the buffer will be freed immediately.
 *
 * (2) If buffer packing is not enabled, the caller can keep the freelist
 * around, as it is not freed on return to the WR module. The caller
 * has to make a private copy of the freelist buffer descriptor 'flb',
 * but need not copy the contents of the freelist buffers themselves.
 * When the caller is done using this freelist buffer array, the
 * routine csio_wr_free_flbuf() is called, passing the copied 'flb'.
 * to free the buffers described in the array. This is the deferred
 * freeing case.
 *
 */
static inline void
csio_wr_process_fl(struct csio_hw *hw, struct csio_q *q,
		   void *wr, uint32_t len_to_qid,
		   void (*iq_handler)(struct csio_hw *, void *,
				      uint32_t, struct csio_fl_dma_buf *,
		   		      void *),
		   void *priv)
{
	struct csio_wrm *wrm = csio_hw_to_wrm(hw);
	struct csio_sge *sge = &wrm->sge;
	struct csio_fl_dma_buf flb;
	struct csio_dma_buf *buf, *fbuf;
	uint32_t bufsz, len, lastlen = 0;
	int n;
	struct csio_q *flq = hw->wrm.q_arr[q->un.iq.flq_idx];

	CSIO_DB_ASSERT(flq != NULL);

	len = len_to_qid;

	if (len & F_IQWRF_NEWBUF) {
		if (flq->un.fl.offset > 0) {
			csio_wr_inval_flq_buf(hw, flq);
			flq->un.fl.offset = 0;
		}
		len = G_IQWRF_LEN(len);
	}

	CSIO_DB_ASSERT(len != 0);

	flb.totlen = len;

	/* Consume all freelist buffers used for len bytes */
	for (n = 0, fbuf = flb.flbufs; ; n++, fbuf++) {
		buf = &flq->un.fl.bufs[flq->cidx];
		bufsz = csio_wr_fl_bufsz(sge, buf);

		/* Copy FL DMA buffer to return location */
		csio_memcpy(&fbuf->dmahdl, &buf->dmahdl,
			    sizeof(csio_dma_obj_t));
		csio_memcpy(&fbuf->paddr, &buf->paddr, sizeof(csio_physaddr_t));
		fbuf->vaddr	= buf->vaddr;

		flb.offset 	= flq->un.fl.offset;
		lastlen = CSIO_MIN(bufsz, len);
		fbuf->len	= lastlen;
		len -= lastlen;
		if (!len)
			break;
		csio_wr_inval_flq_buf(hw, flq);
	}

	flb.defer_free = flq->un.fl.packen? 0 : 1;

	iq_handler(hw, wr, q->wr_sz - sizeof(struct csio_iqwr_footer),
		   &flb, priv);

	if (flq->un.fl.packen)
		flq->un.fl.offset += CSIO_ALIGN(lastlen, sge->csio_fl_align);
	else
		csio_wr_inval_flq_buf(hw, flq);

	return;
}

/*
 * csio_is_new_iqwr - Is this a new Ingress queue entry ?
 * @q: Ingress quueue.
 * @ftr: Ingress queue WR SGE footer.
 *
 * The entry is new if our generation bit matches the corresponding
 * bit in the footer of the current WR.
 */
static inline bool
csio_is_new_iqwr(struct csio_q *q, struct csio_iqwr_footer *ftr)
{
	return (q->un.iq.genbit == (ftr->u.type_gen >> S_IQWRF_GEN));
}

/*
 * csio_wr_iq_entries - Do we have any new Ingress entries?
 * @hw: HE pointer
 * @qidx: Index of queue.
 *
 */
bool
csio_wr_iq_entries(struct csio_hw *hw, int qidx)
{
	struct csio_q *q 	= hw->wrm.q_arr[qidx];
	void *wr		= (void *)((uintptr_t)q->vstart +
					   (q->cidx * q->wr_sz));
	struct csio_iqwr_footer *ftr;

	/* Get the footer */
	ftr = (struct csio_iqwr_footer *)((uintptr_t)wr +
					  (q->wr_sz - sizeof(*ftr)));
	return csio_is_new_iqwr(q, ftr);
}

/*
 * csio_wr_process_iq - Process elements in Ingress queue.
 * @hw:  HW pointer
 * @qidx: Index of queue
 * @iq_handler: Handler for this queue
 * @priv: Caller's private pointer
 *
 * This routine walks through every entry of the ingress queue, calling
 * the provided iq_handler with the entry, until the generation bit
 * flips.
 */
enum csio_oss_error
csio_wr_process_iq(struct csio_hw *hw, struct csio_q *q,
		   void (*iq_handler)(struct csio_hw *, void *,
				      uint32_t, struct csio_fl_dma_buf *,
				      void *),
		   void *priv)
{
	struct csio_wrm *wrm 	= csio_hw_to_wrm(hw);
	void *wr		= (void *)((uintptr_t)q->vstart +
					   (q->cidx * q->wr_sz));
	struct csio_iqwr_footer *ftr;
	uint32_t wr_type, fw_qid, qid;
	struct csio_q *q_completed;
	struct csio_q *flq 	= csio_iq_has_fl(q) ?
					 wrm->q_arr[q->un.iq.flq_idx] : NULL;
	enum csio_oss_error rv = CSIO_SUCCESS;

	/* Get the footer */
	ftr = (struct csio_iqwr_footer *)((uintptr_t)wr +
					  (q->wr_sz - sizeof(*ftr)));
	
	/*
	 * When q wrapped around last time, driver should have inverted
	 * ic.genbit as well.
	 */
	while (csio_is_new_iqwr(q, ftr)) {

		CSIO_DB_ASSERT(((uintptr_t)wr + q->wr_sz) <=
						(uintptr_t)q->vwrap);
		csio_rmb();
		wr_type = G_IQWRF_TYPE(ftr->u.type_gen);

		switch (wr_type) {
		case X_RSPD_TYPE_CPL:

			/* Subtract footer from WR len */
			iq_handler(hw, wr, q->wr_sz - sizeof(*ftr), NULL, priv);
			break;
		case X_RSPD_TYPE_FLBUF:
			csio_wr_process_fl(hw, q, wr,
					   csio_ntohl(ftr->pldbuflen_qid),
					   iq_handler, priv);
			break;
		case X_RSPD_TYPE_INTR:
			fw_qid = csio_ntohl(ftr->pldbuflen_qid);
			qid = fw_qid - wrm->fw_iq_start;
			q_completed = hw->wrm.intr_map[qid];

			if (csio_unlikely(qid ==
					csio_q_physiqid(hw, hw->intr_iq_idx))) {
				/*
				 * We are already in the Forward Interrupt
				 * Interrupt Queue Service! Do-not service
				 * again!
				 *
				 */
			} else {
						
				CSIO_DB_ASSERT(q_completed);
				CSIO_DB_ASSERT(
					q_completed->un.iq.iq_intx_handler);
			
				/* Call the queue handler. */
				q_completed->un.iq.iq_intx_handler(hw, NULL,
						0, NULL,
						(void *)q_completed);
			}
			break;
		default:
			/* wr_type == others */
			csio_dbg(hw, "IQ WR type 0x%x currently unsupported\n",
				    wr_type);
			CSIO_INC_STATS(q, n_rsp_unknown);
			break;
		}

		/**
		 * Ingress *always* has fixed size WR entries. Therefore,
		 * there should always be complete WRs towards the end of
		 * queue.
		 */
		if (((uintptr_t)wr + q->wr_sz) == (uintptr_t)q->vwrap) {

			/* Roll over to start of queue */
			q->cidx = 0;
			wr 	= q->vstart;

			/* Toggle genbit */
			q->un.iq.genbit ^= 0x1;

			CSIO_INC_STATS(q, n_qwrap);
		} else {
			q->cidx++;
			wr	= (void *)((uintptr_t)(q->vstart) +
					   (q->cidx * q->wr_sz));
		}

		ftr = (struct csio_iqwr_footer *)((uintptr_t)wr +
						  (q->wr_sz - sizeof(*ftr)));
		q->inc_idx++;

	} /* while (q->un.iq.genbit == hdr->genbit) */

	/*
	 * We need to re-arm SGE interrupts in case we got a stray interrupt,
	 * especially in msix mode. With INTx, this may be a common occurence.
	 */
	if (csio_unlikely(!q->inc_idx)) {
		CSIO_INC_STATS(q, n_stray_comp);
		rv = CSIO_INVAL;
		goto restart;
	}

	/* Replenish free list buffers if pending falls below low water mark */
	if (flq) {
		uint32_t avail  = csio_wr_avail_qcredits(flq);
		/* REVISIT: Need to tune low water mark */
		if (avail <= 16) {
			/* Make sure in FLQ, atleast 1 credit (8 FL buffers)
			 * remains unpopulated otherwise HW thinks
			 * FLQ is empty.
			 */
			csio_wr_update_fl(hw, flq, (flq->credits - 8) - avail);
			csio_wr_ring_fldb(hw, flq);
		}
	}

restart:
	/* Now inform SGE about our incremental index value */
	/*
	 * If we don't have access to the new User GTS (T5+), use the old
	 * doorbell mechanism; otherwise use the new BAR2 mechanism.
	 */
	if (unlikely(q->bar2_addr == NULL))
		t4_write_reg(&hw->adap, MYPF_REG(A_SGE_PF_GTS), V_CIDXINC(q->inc_idx) |
				  V_INGRESSQID(q->un.iq.physiqid)	|
				  V_TIMERREG(csio_sge_timer_reg));
	else {
		writel(V_CIDXINC(q->inc_idx) | V_TIMERREG(csio_sge_timer_reg) |
		       V_INGRESSQID(q->bar2_qid),
		       q->bar2_addr + SGE_UDB_GTS);
		csio_wmb();
	}

	q->stats.n_tot_rsps += q->inc_idx;

	q->inc_idx = 0;

	return rv;
}

csio_retval_t
csio_wr_process_iq_idx(struct csio_hw *hw, int qidx,
		   void (*iq_handler)(struct csio_hw *, void *,
				      uint32_t, struct csio_fl_dma_buf *,
				      void *),
		   void *priv)
{
	struct csio_wrm *wrm 	= csio_hw_to_wrm(hw);
	struct csio_q	*iq 	= wrm->q_arr[qidx];

	return csio_wr_process_iq(hw, iq, iq_handler, priv);
}

static int
csio_closest_timer(struct csio_sge *s, int time)
{
	int i, delta, match = 0, min_delta = CSIO_INT_MAX;

	for (i = 0; i < CSIO_ARRAY_SIZE(s->timer_val); i++) {
		delta = time - s->timer_val[i];
		if (delta < 0)
			delta = -delta;
		if (delta < min_delta) {
			min_delta = delta;
			match = i;
		}
	}
	return match;
}

static int
csio_closest_thresh(struct csio_sge *s, int cnt)
{
	int i, delta, match = 0, min_delta = CSIO_INT_MAX;

	for (i = 0; i < CSIO_ARRAY_SIZE(s->counter_val); i++) {
		delta = cnt - s->counter_val[i];
		if (delta < 0)
			delta = -delta;
		if (delta < min_delta) {
			min_delta = delta;
			match = i;
		}
	}
	return match;
}

static void
csio_wr_fixup_host_params(struct csio_hw *hw)
{
	uint32_t clsz = csio_cacheline_sz(hw->os_dev);

	/*
	 * Fix up various Host-Dependent Parameters like Page Size, Cache
	 * Line Size, etc.  The firmware default is 4KB Page Size and
	 * 64B Cache Line Size.
	 */
	t4_fixup_host_params_compat(&hw->adap, CSIO_PAGE_SIZE, clsz,
				    T5_LAST_REV);

	/* default value of rx_dma_offset of the NIC driver */
	t4_set_reg_field(&hw->adap, A_SGE_CONTROL,
			 V_PKTSHIFT(M_PKTSHIFT),
			 V_PKTSHIFT(CSIO_SGE_RX_DMA_OFFSET));
}

static void
csio_init_intr_coalesce_parms(struct csio_hw *hw)
{
	struct csio_wrm *wrm = csio_hw_to_wrm(hw);
	struct csio_sge *sge = &wrm->sge;

	csio_sge_thresh_reg = csio_closest_thresh(sge, csio_intr_coalesce_cnt);
	if (csio_intr_coalesce_cnt) {
#if 1
		csio_sge_thresh_reg = 0;	
#endif
		csio_info(hw, "Setting interrupt coalesce count to %d"
		      	  " (closest threshold register: %d)\n",
			  sge->counter_val[csio_sge_thresh_reg],
			  csio_sge_thresh_reg);
#if 1
		csio_info(hw, "Disabling interrupt coalesce timer\n");
		csio_sge_timer_reg = X_TIMERREG_RESTART_COUNTER;
		return;
#endif
	} else
		csio_info(hw, "Enabling Timer-based interrupt coalescing\n");

	csio_sge_timer_reg = csio_closest_timer(sge, csio_intr_coalesce_time);
	csio_info(hw, "Setting interrupt coalesce time to %d us"
		       " (closest timer register: %d)\n",
		  sge->timer_val[csio_sge_timer_reg], csio_sge_timer_reg);
}
	
/*
 * csio_wr_get_sge - Get SGE register values.
 * @hw: HW module.
 *
 * Used by non-master functions and by master-functions relying on config file.
 */
static void
csio_wr_get_sge(struct csio_hw *hw)
{
	struct csio_wrm *wrm = csio_hw_to_wrm(hw);
	struct csio_sge *sge = &wrm->sge;
	uint32_t ingpad;
	int i;
	u32 timer_value_0_and_1, timer_value_2_and_3, timer_value_4_and_5;
	u32 ingress_rx_threshold;

	sge->sge_control = t4_read_reg(&hw->adap, A_SGE_CONTROL);

	ingpad = G_INGPADBOUNDARY(sge->sge_control);

	switch (ingpad) {
		case X_INGPCIEBOUNDARY_32B:
			sge->csio_fl_align = 32; break;
		case X_INGPCIEBOUNDARY_64B:
			sge->csio_fl_align = 64; break;
		case X_INGPCIEBOUNDARY_128B:
			sge->csio_fl_align = 128; break;
		case X_INGPCIEBOUNDARY_256B:
			sge->csio_fl_align = 256; break;
		case X_INGPCIEBOUNDARY_512B:
			sge->csio_fl_align = 512; break;
		case X_INGPCIEBOUNDARY_1024B:
			sge->csio_fl_align = 1024; break;
		case X_INGPCIEBOUNDARY_2048B:
			sge->csio_fl_align = 2048; break;
		case X_INGPCIEBOUNDARY_4096B:
			sge->csio_fl_align = 4096; break;
	}

	for (i = 0; i < CSIO_SGE_FL_SIZE_REGS; i++)
		csio_get_flbuf_size(hw, sge, i);

	timer_value_0_and_1 = t4_read_reg(&hw->adap, A_SGE_TIMER_VALUE_0_AND_1);
	timer_value_2_and_3 = t4_read_reg(&hw->adap, A_SGE_TIMER_VALUE_2_AND_3);
	timer_value_4_and_5 = t4_read_reg(&hw->adap, A_SGE_TIMER_VALUE_4_AND_5);

	sge->timer_val[0] = (uint16_t)csio_core_ticks_to_us(hw,
					G_TIMERVALUE0(timer_value_0_and_1));
	sge->timer_val[1] = (uint16_t)csio_core_ticks_to_us(hw,
					G_TIMERVALUE1(timer_value_0_and_1));
	sge->timer_val[2] = (uint16_t)csio_core_ticks_to_us(hw,
					G_TIMERVALUE2(timer_value_2_and_3));
	sge->timer_val[3] = (uint16_t)csio_core_ticks_to_us(hw,
					G_TIMERVALUE3(timer_value_2_and_3));
	sge->timer_val[4] = (uint16_t)csio_core_ticks_to_us(hw,
					G_TIMERVALUE4(timer_value_4_and_5));
	sge->timer_val[5] = (uint16_t)csio_core_ticks_to_us(hw,
					G_TIMERVALUE5(timer_value_4_and_5));

	ingress_rx_threshold = t4_read_reg(&hw->adap, A_SGE_INGRESS_RX_THRESHOLD);
	sge->counter_val[0] = G_THRESHOLD_0(ingress_rx_threshold);
	sge->counter_val[1] = G_THRESHOLD_1(ingress_rx_threshold);
	sge->counter_val[2] = G_THRESHOLD_2(ingress_rx_threshold);
	sge->counter_val[3] = G_THRESHOLD_3(ingress_rx_threshold);

	csio_init_intr_coalesce_parms(hw);
}

/*
 * csio_wr_set_sge - Initialize SGE registers
 * @hw: HW module.
 *
 * Used by Master function to initialize SGE registers in the absence
 * of a config file.
 */
static void
csio_wr_set_sge(struct csio_hw *hw)
{
	struct csio_wrm *wrm = csio_hw_to_wrm(hw);
	struct csio_sge *sge = &wrm->sge;
	int i;

	/*
	 * Set up our basic SGE mode to deliver CPL messages to our Ingress
	 * Queue and Packet Date to the Free List.
	 */
	t4_set_reg_field(&hw->adap, A_SGE_CONTROL, F_RXPKTCPLMODE, F_RXPKTCPLMODE);

	sge->sge_control = t4_read_reg(&hw->adap, A_SGE_CONTROL);

	/* sge->csio_fl_align is set up by csio_wr_fixup_host_params(). */

	/*
	 * Set up to drop DOORBELL writes when the DOORBELL FIFO overflows
	 * and generate an interrupt when this occurs so we can recover.
	 */
	if (is_t4(hw->adap.params.chip)) {
		t4_set_reg_field(&hw->adap, A_SGE_DBFIFO_STATUS,
				 V_HP_INT_THRESH(M_HP_INT_THRESH) |
				 V_LP_INT_THRESH(M_LP_INT_THRESH),
				 V_HP_INT_THRESH(CSIO_SGE_DBFIFO_INT_THRESH) |
				 V_LP_INT_THRESH(CSIO_SGE_DBFIFO_INT_THRESH));
	} else {
		t4_set_reg_field(&hw->adap, A_SGE_DBFIFO_STATUS,
				 V_LP_INT_THRESH_T5(M_LP_INT_THRESH_T5),
				 V_LP_INT_THRESH_T5(CSIO_SGE_DBFIFO_INT_THRESH));

		t4_set_reg_field(&hw->adap, A_SGE_DBFIFO_STATUS2,
				 V_HP_INT_THRESH_T5(M_HP_INT_THRESH_T5),
				 V_HP_INT_THRESH_T5(CSIO_SGE_DBFIFO_INT_THRESH));
	}

	t4_set_reg_field(&hw->adap, A_SGE_DOORBELL_CONTROL, F_ENABLE_DROP,
			   F_ENABLE_DROP);

	/* A_SGE_FL_BUFFER_SIZE0 is set up by csio_wr_fixup_host_params(). */

	csio_set_flbuf_size(hw, 1, CSIO_SGE_FLBUF_SIZE1);
	t4_write_reg(&hw->adap, A_SGE_FL_BUFFER_SIZE2,
		     (CSIO_SGE_FLBUF_SIZE2 + sge->csio_fl_align - 1)
		     & ~(sge->csio_fl_align - 1));
	t4_write_reg(&hw->adap, A_SGE_FL_BUFFER_SIZE3,
		     (CSIO_SGE_FLBUF_SIZE3 + sge->csio_fl_align - 1)
		     & ~(sge->csio_fl_align - 1));
	csio_set_flbuf_size(hw, 4, CSIO_SGE_FLBUF_SIZE4);
	csio_set_flbuf_size(hw, 5, CSIO_SGE_FLBUF_SIZE5);
	csio_set_flbuf_size(hw, 6, CSIO_SGE_FLBUF_SIZE6);
	csio_set_flbuf_size(hw, 7, CSIO_SGE_FLBUF_SIZE7);
	csio_set_flbuf_size(hw, 8, CSIO_SGE_FLBUF_SIZE8);

	for (i = 0; i < CSIO_SGE_FL_SIZE_REGS; i++)
		csio_get_flbuf_size(hw, sge, i);

	/* Initialize interrupt coalescing attributes */
	sge->timer_val[0] = CSIO_SGE_TIMER_VAL_0;
	sge->timer_val[1] = CSIO_SGE_TIMER_VAL_1;
	sge->timer_val[2] = CSIO_SGE_TIMER_VAL_2;
	sge->timer_val[3] = CSIO_SGE_TIMER_VAL_3;
	sge->timer_val[4] = CSIO_SGE_TIMER_VAL_4;
	sge->timer_val[5] = CSIO_SGE_TIMER_VAL_5;

	sge->counter_val[0] = CSIO_SGE_INT_CNT_VAL_0;
	sge->counter_val[1] = CSIO_SGE_INT_CNT_VAL_1;
	sge->counter_val[2] = CSIO_SGE_INT_CNT_VAL_2;
	sge->counter_val[3] = CSIO_SGE_INT_CNT_VAL_3;

	t4_write_reg(&hw->adap, A_SGE_INGRESS_RX_THRESHOLD,
		     V_THRESHOLD_0(sge->counter_val[0]) |
		     V_THRESHOLD_1(sge->counter_val[1]) |
		     V_THRESHOLD_2(sge->counter_val[2]) |
		     V_THRESHOLD_3(sge->counter_val[3]));

	t4_write_reg(&hw->adap, A_SGE_TIMER_VALUE_0_AND_1,
		   V_TIMERVALUE0(csio_us_to_core_ticks(hw, sge->timer_val[0])) |
		   V_TIMERVALUE1(csio_us_to_core_ticks(hw, sge->timer_val[1])));

	t4_write_reg(&hw->adap, A_SGE_TIMER_VALUE_2_AND_3,
		   V_TIMERVALUE2(csio_us_to_core_ticks(hw, sge->timer_val[2])) |
		   V_TIMERVALUE3(csio_us_to_core_ticks(hw, sge->timer_val[3])));

	t4_write_reg(&hw->adap, A_SGE_TIMER_VALUE_4_AND_5,
		   V_TIMERVALUE4(csio_us_to_core_ticks(hw, sge->timer_val[4])) |
		   V_TIMERVALUE5(csio_us_to_core_ticks(hw, sge->timer_val[5])));

	csio_init_intr_coalesce_parms(hw);
}

void
csio_wr_sge_init(struct csio_hw *hw)
{
	/*
	 * If we are master and chip is not initialized:
	 *    - If we plan to use the config file, we need to fixup some
	 *      host specific registers, and read the rest of the SGE
	 *      configuration.
	 *    - If we dont plan to use the config file, we need to initialize
	 *      SGE entirely, including fixing the host specific registers.
	 * If we are master and chip is initialized, just read and work off of
	 *      the already initialized SGE values.
 	 * If we arent the master, we are only allowed to read and work off of
	 *      the already initialized SGE values.
	 *
	 * Therefore, before calling this function, we assume that the master-
	 * ship of the card, state and whether to use config file or not, have
	 * already been decided.
	 */
	if (csio_is_hw_master(hw)) {
		if (hw->fw_state != DEV_STATE_INIT)
			csio_wr_fixup_host_params(hw);
		
		if (hw->flags & CSIO_HWF_USING_SOFT_PARAMS)
			csio_wr_get_sge(hw);
		else
			csio_wr_set_sge(hw);
	} else
		csio_wr_get_sge(hw);
}

/*****************************************************************************/
/* Entry points for WR module                                                */
/*****************************************************************************/
/*
 * csio_wrm_init - Initialize Work request module.
 * @wrm: WR module
 * @hw: HW pointer
 *
 * Allocates memory for an array of queue pointers starting at q_arr.
 * The number of queues should have already been set up by
 * OS-dependent code. 'free_qidx' indicates index of first free
 * queue entry.
 */
csio_retval_t
csio_wrm_init(struct csio_wrm *wrm, struct csio_hw *hw)
{
	int i;

	/*
	 * OS-dependent code should have set up num_q.
	 */
	if (!wrm->num_q) {
		csio_err(hw, "Num queues is not set\n");
		return CSIO_INVAL;
	}

	wrm->q_arr = csio_alloc(csio_md(hw, CSIO_Q_ARR_MD),
				sizeof(struct csio_q *) * wrm->num_q,
				CSIO_MWAIT);
	if (!wrm->q_arr)
		goto err;

	for (i = 0; i < wrm->num_q; i++) {
		wrm->q_arr[i] = csio_alloc(csio_md(hw, CSIO_Q_MD),
					   sizeof(struct csio_q),
					   CSIO_MWAIT);
		if (!wrm->q_arr[i]) {
			while(--i >= 0)
				csio_free(csio_md(hw, CSIO_Q_MD),
					  wrm->q_arr[i]);
			goto err_free_arr;
		}
	}
	wrm->free_qidx 	= 0;

	return CSIO_SUCCESS;

err_free_arr:
	csio_free(csio_md(hw, CSIO_Q_ARR_MD), wrm->q_arr);
err:
	return CSIO_NOMEM;
}

/*
 * csio_wrm_exit - Initialize Work request module.
 * @wrm: WR module
 * @hw: HW module
 *
 * Uninitialize WR module. Free q_arr and pointers in it.
 * We have the additional job of freeing the DMA memory associated
 * with the queues.
 */
void
csio_wrm_exit(struct csio_wrm *wrm, struct csio_hw *hw)
{
	int i;
	uint32_t j;
	struct csio_q *q;
	struct csio_dma_buf *buf;

	for (i = 0; i < wrm->num_q; i++) {
		q = wrm->q_arr[i];
		
		if (wrm->free_qidx && (i < wrm->free_qidx)) {
			if (q->type == CSIO_FREELIST) {
				if (!q->un.fl.bufs)
					continue;
				for (j = 0; j < q->credits; j++) {
					buf = &q->un.fl.bufs[j];
					if (!buf->vaddr)
						continue;
					csio_dma_pool_free(&buf->dmahdl,
							   buf->vaddr);
				}
				csio_free(csio_md(hw, q->un.fl.md_idx),
					  q->un.fl.bufs);
			}
			csio_dma_free(&q->dmahdl, q->vstart);
		}

		csio_free(csio_md(hw, CSIO_Q_MD), q);
	}
	hw->flags &= ~CSIO_HWF_Q_MEM_ALLOCED;

	csio_free(csio_md(hw, CSIO_Q_ARR_MD), wrm->q_arr);

	return;
}
