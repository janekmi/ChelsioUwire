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

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/cpumask.h>

#include <csio_os_hw.h>
#include <csio_os_defs.h>
#include <csio_version.h>

static irqreturn_t
csio_nondata_isr(int irq, void *dev_id)
{
	struct csio_os_hw *oshw = (struct csio_os_hw *) dev_id;
	struct csio_hw *hw;

	if (unlikely(!oshw)) {
		printk(KERN_INFO "csiostor: Error/MB ISR received NULL oshw\n");
		return IRQ_NONE;
	}

	hw = csio_oshw_to_hw(oshw);
	if (unlikely(pci_channel_offline(oshw->pdev))) {
		CSIO_INC_STATS(hw, n_pcich_offline);
		return IRQ_NONE;
	}	

	csio_hw_slow_intr_handler(hw);
	return IRQ_HANDLED;
}

/*
 * csio_fwevt_handler - Common FW event handler routine.
 * @hw: HW module.
 *
 * This is the ISR for FW events. It is shared b/w MSIX
 * and INTx handlers.
 */
static void
csio_fwevt_handler(struct csio_hw *hw)
{
	enum csio_oss_error rv;
	unsigned long flags;

	rv = csio_fwevtq_handler(hw);
	
	csio_spin_lock_irqsave(hw, &hw->lock, flags);
	if (rv == CSIO_SUCCESS && !(hw->flags & CSIO_HWF_FWEVT_PENDING)) {
		hw->flags |= CSIO_HWF_FWEVT_PENDING;
		csio_spin_unlock_irqrestore(hw, &hw->lock, flags);
		csio_work_schedule(&hw->evtq_work);
		return;
	}
	csio_spin_unlock_irqrestore(hw, &hw->lock, flags);

	if (rv != CSIO_SUCCESS)
		csio_dbg(hw, "FW events are pending to be processed\n");
	return;

} /* csio_fwevt_handler */

/*
 * csio_fwevt_isr() - FW events MSIX ISR
 * @irq:	
 * @dev_id:
 *
 * Process WRs on the FW event queue.
 *
 */
static irqreturn_t
csio_fwevt_isr(int irq, void *dev_id)
{
	struct csio_os_hw *oshw = (struct csio_os_hw *) dev_id;

	if (unlikely(!oshw)) {
		printk(KERN_INFO
			"csiostor: FW event ISR received NULL oshw\n");
		return IRQ_NONE;
	}

	if (unlikely(pci_channel_offline(oshw->pdev))) {
		CSIO_INC_STATS(csio_oshw_to_hw(oshw), n_pcich_offline);
		return IRQ_NONE;
	}

	csio_fwevt_handler(csio_oshw_to_hw(oshw));

	return IRQ_HANDLED;
}

/*
 * csio_fwevt_isr() - INTx wrapper for handling FW events.
 * @irq:	
 * @dev_id:
 */
void
csio_os_fwevt_intx_handler(struct csio_hw *hw, void *wr, uint32_t len,
			   struct csio_fl_dma_buf *flb, void *priv)
{
	csio_fwevt_handler(hw);
	return;
} /* csio_os_fwevt_intx_handler */

/*
 * csio_os_scsi_cmpl_handler - OS wrapper for completion handler for SCSI.
 * @hw: HW module.
 * @wr: The completed WR from the ingress queue.
 * @len: Length of the WR.
 * @flb: Freelist buffer array.
 *
 * This is a wrapper around the generic WR completion handler
 * for SCSI - csio_scsi_cmpl_handler(). This wrapper takes a lock around
 * the completion event to be sent to the ioreq.
 */
static void
csio_os_scsi_cmpl_handler(struct csio_hw *hw, void *wr, uint32_t len,
			struct csio_fl_dma_buf *flb, void *cbfn_q)
{
	struct csio_ioreq *ioreq;
	uint8_t *scsiwr;
	uint8_t subop;
	void *cmnd;
	unsigned long flags;

	ioreq = csio_scsi_cmpl_handler(hw, wr, len, flb, NULL, &scsiwr);
	if (likely(ioreq)) {
		if (unlikely(*scsiwr == FW_SCSI_ABRT_CLS_WR)) {
			subop = G_FW_SCSI_ABRT_CLS_WR_SUB_OPCODE(
					((struct fw_scsi_abrt_cls_wr *)
					    scsiwr)->sub_opcode_to_chk_all_io);

			csio_scsi_dbg(hw, "%s cmpl recvd ioreq:%p status:%d\n",
				    subop ? "Close" : "Abort",
				    ioreq, ioreq->wr_status);

			csio_spin_lock_irqsave(hw, &hw->lock, flags);
			if (subop)
				csio_scsi_closed(ioreq,
						 (struct csio_list *)cbfn_q);
			else
				csio_scsi_aborted(ioreq,
						  (struct csio_list *)cbfn_q);
			/*
			 * We call scsi_done for I/Os that driver thinks aborts
			 * have timed out. If there is a race caused by FW
			 * completing abort at the exact same time that the
			 * driver has deteced the abort timeout, the following
			 * check prevents calling of scsi_done twice for the
			 * same command: once from the eh_abort_handler, another
			 * from csio_scsi_isr_handler(). This also avoids the
			 * need to check if csio_scsi_osreq(req) is NULL in the
			 * fast path.
			 */
			cmnd = csio_scsi_osreq(ioreq);
			if (unlikely(cmnd == NULL))
				csio_deq_elem(ioreq);

			csio_spin_unlock_irqrestore(hw, &hw->lock, flags);

			if (unlikely(cmnd == NULL))
				csio_put_scsi_ioreq_lock(hw,
						csio_hw_to_scsim(hw), ioreq);
		} else {
			csio_spin_lock_irqsave(hw, &hw->lock, flags);
			csio_scsi_completed(ioreq, (struct csio_list *)cbfn_q);
			csio_spin_unlock_irqrestore(hw, &hw->lock, flags);
		}
	}
	
	return;
}

/**
 * csio_scsi_isr_handler() - Common SCSI ISR handler.
 * @iq: Ingress queue pointer.
 *
 * Processes SCSI completions on the SCSI IQ indicated by scm->iq_idx
 * by calling csio_wr_process_iq_idx. If there are completions on the isr_cbfn_q,
 * yank them out into a local queue and call their io_cbfns. Once done,
 * add these completions onto the freelist. Kick off the worker thread.
 * This routine is shared b/w MSIX and INTx.
 */
static inline irqreturn_t
csio_scsi_isr_handler(struct csio_q *iq)
{
	struct csio_hw *hw = (struct csio_hw *)iq->owner;
	struct csio_list cbfn_q;
	struct csio_list *tmp;
	struct csio_scsim *scm;
	struct csio_ioreq *ioreq;
	int isr_completions = 0;

	csio_head_init(&cbfn_q);

	scm = csio_hw_to_scsim(hw);

	if (likely(csio_wr_process_iq(
				hw, iq, csio_os_scsi_cmpl_handler, &cbfn_q)
							 == CSIO_SUCCESS)) {
		csio_scsi_vdbg(hw, "ISR found SCSI completions on x%x\n",
			    iq->un.iq.physiqid);
	} else {
		csio_scsi_vdbg(hw, "No SCSI completions found on x%x\n",
			    iq->un.iq.physiqid);
		return IRQ_NONE;
	}

	/* Call back the completion routines */
	csio_list_for_each(tmp, &cbfn_q) {
		ioreq = (struct csio_ioreq *)tmp;
		isr_completions++;
		ioreq->io_cbfn(hw, ioreq);
#ifdef __CSIO_DDP_SUPPORT__
		/* Release ddp buffer if used for this req */
		if (unlikely(ioreq->dcopy))
			csio_put_scsi_ddp_list_lock(hw, scm, &ioreq->gen_list,
						    ioreq->nsge);
#endif		
	}

	if (isr_completions) {
		/* Return the ioreqs back to ioreq->freelist */
		csio_put_scsi_ioreq_list_lock(hw, scm, &cbfn_q,
					      isr_completions);
	}

	return IRQ_HANDLED;
}

/*
 * csio_scsi_isr() - SCSI MSIX handler
 * @irq:	
 * @dev_id:
 *
 * This is the top level SCSI MSIX handler. Calls csio_scsi_isr_handler()
 * for handling SCSI completions.
 */
static irqreturn_t
csio_scsi_isr(int irq, void *dev_id)
{
	struct csio_q *iq = (struct csio_q *) dev_id;
	struct csio_hw *hw;
	struct csio_os_hw *oshw;

	if (unlikely(!iq)) {
		printk(KERN_INFO
			"csiostor: SCSI ISR received NULL queue pointer\n");
		return IRQ_NONE;
	}

	hw = (struct csio_hw *)iq->owner;
	oshw = csio_hw_to_os(hw);

	csio_scsi_vdbg(hw, "SCSI ISR on cpu:%d q:%d\n", smp_processor_id(),
		    iq->un.iq.physiqid);

	if (unlikely(pci_channel_offline(oshw->pdev))) {
		CSIO_INC_STATS(hw, n_pcich_offline);
		return IRQ_NONE;
	}

	csio_scsi_isr_handler(iq);

	return IRQ_HANDLED;
}

/*
 * csio_scsi_isr() - SCSI INTx handler
 * @irq:	
 * @dev_id:
 *
 * This is the top level SCSI MSIX handler. Calls csio_scsi_isr_handler()
 * for handling SCSI completions.
 */
void
csio_os_scsi_intx_handler(struct csio_hw *hw, void *wr, uint32_t len,
			struct csio_fl_dma_buf *flb, void *priv)
{
	struct csio_q *iq = priv;
	
	csio_scsi_isr_handler(iq);

	return;
} /* csio_os_scsi_intx_handler */

/*
 * csio_fcoe_isr() - INTx/MSI interrupt service routine for FCoE.
 * @irq:	
 * @dev_id:
 *
 *
 */
static irqreturn_t
csio_fcoe_isr(int irq, void *dev_id)
{
	struct csio_os_hw *oshw = (struct csio_os_hw *) dev_id;
	struct csio_hw *hw = NULL;
	struct csio_q *intx_q = NULL;
	irqreturn_t rv = IRQ_NONE;

	if (unlikely(!oshw)) {
		printk(KERN_INFO "csiostor: NULL oshw in INTx handler\n");
		goto out;
	}

	hw = csio_oshw_to_hw(oshw);

	if (unlikely(pci_channel_offline(oshw->pdev))) {
		CSIO_INC_STATS(hw, n_pcich_offline);
		goto out;
	}

	/* Disable the interrupt for this PCI function. */
	if (hw->intr_mode == CSIO_IM_INTX)
		t4_write_reg(&hw->adap, MYPF_REG(A_PCIE_PF_CLI), 0);

	/*
	 * The read in the following function will flush the
	 * above write.
	 */
	if (csio_hw_slow_intr_handler(hw))
		rv = IRQ_HANDLED;

	/* Get the INTx Forward interrupt IQ. */
	intx_q = csio_get_q(hw, hw->intr_iq_idx);

	CSIO_DB_ASSERT(intx_q);

	/* IQ handler is not possible for intx_q, hence pass in NULL */
	if (likely(csio_wr_process_iq(hw, intx_q, NULL, NULL)
							== CSIO_SUCCESS))
		rv = IRQ_HANDLED;

out:
	return rv;
}

/*
 * csio_iscsi_isr() - INTx/MSI interrupt service routine for iSCSI.
 * @irq:	
 * @dev_id:
 *
 *
 */
static irqreturn_t
csio_iscsi_isr(int irq, void *dev_id)
{
	return IRQ_HANDLED;
}

#define CSIO_FCOE_EXTRA_VECS	0	/* Extra FCoE vectors */
#define CSIO_ISCSI_EXTRA_VECS	0

static int
csio_extra_msix_vecs(struct csio_hw *hw)
{
	int extra = csio_is_fcoe(hw)?
			 CSIO_FCOE_EXTRA_VECS : CSIO_ISCSI_EXTRA_VECS;
	return (extra + CSIO_EXTRA_VECS);
}

#define csio_extra_msix_desc(_desc, _len, _str, _arg1, _arg2, _arg3)	\
do {									\
	memset((_desc), 0, (_len) + 1);					\
	snprintf((_desc), (_len), (_str), (_arg1), (_arg2), (_arg3));	\
} while (0)

static void
csio_add_msix_desc(struct csio_os_hw *oshw)
{
	int i;
	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	struct csio_msix_entries *entryp = &oshw->msix_entries[0];
	int k = csio_extra_msix_vecs(hw);
	int len = sizeof(entryp->desc) - 1;
	int cnt = oshw->num_sqsets + k;

	/* Non-data vector */
	csio_extra_msix_desc(entryp->desc, len, "csio-%02x:%02x:%x-nondata",
			     CSIO_PCI_BUS(oshw), CSIO_PCI_DEV(oshw),
			     CSIO_PCI_FUNC(oshw));
	entryp++;
	csio_extra_msix_desc(entryp->desc, len, "csio-%02x:%02x:%x-fwevt",
			     CSIO_PCI_BUS(oshw), CSIO_PCI_DEV(oshw),
			     CSIO_PCI_FUNC(oshw));
	entryp++;

	/* Name SCSI vecs */
	for (i = k; i < cnt; i++, entryp++) {
		memset(entryp->desc, 0, len + 1);
		snprintf(entryp->desc, len, "csio-%02x:%02x:%x-scsi%d",
			 CSIO_PCI_BUS(oshw), CSIO_PCI_DEV(oshw),
			 CSIO_PCI_FUNC(oshw), i - csio_extra_msix_vecs(hw));
	}
	return;
}

csio_retval_t
csio_request_irqs(struct csio_os_hw *oshw)
{
	int rv, i, j, k = 0;
	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	struct csio_msix_entries *entryp = &oshw->msix_entries[0];
	struct csio_scsi_cpu_info *info;
	
	/* Allocate interrupt line for INTx, or MSI, if enabled */
	if (hw->intr_mode != CSIO_IM_MSIX) {
		/*
		 * FCoE and iSCSI have their own line interrupt handlers,
		 * since switching on the mode in the ISR itself is expensive.
		 */
		rv = request_irq(oshw->pdev->irq, csio_is_fcoe(hw)?
					csio_fcoe_isr : csio_iscsi_isr,
				 	(hw->intr_mode == CSIO_IM_MSI) ?
							0: IRQF_SHARED,
					KBUILD_MODNAME, oshw);
		if (rv) {
			if (hw->intr_mode == CSIO_IM_MSI)
				pci_disable_msi(oshw->pdev);
			csio_err(hw, "Failed to allocate interrupt line.\n");
			return CSIO_INVAL;
		}

		goto out;
	}

	/* Add the MSIX vector descriptions */
	csio_add_msix_desc(oshw);

	rv = request_irq(entryp[k].vector, csio_nondata_isr, 0,
			 entryp[k].desc, oshw);
	if (rv) {
		csio_err(hw, "MSI-X IRQ request failed for vector "
			    "%d error:%d\n", entryp[k].vector, rv);
		goto err;
	}
	
	entryp[k++].dev_id = (void *)oshw;

	rv = request_irq(entryp[k].vector, csio_fwevt_isr, 0,
			 entryp[k].desc, oshw);
	if (rv) {
		csio_err(hw, "MSI-X IRQ request failed for vector "
			    "%d error:%d\n", entryp[k].vector, rv);
		goto err;
	}

	entryp[k++].dev_id = (void *)oshw;

	/* Allocate IRQs for SCSI */
	for (i = 0; i < hw->num_t4ports; i++) {
		info = &oshw->scsi_cpu_info[i];
		for (j = 0; j < info->max_cpus; j++, k++) {
			struct csio_scsi_qset *sqset = &oshw->sqset[i][j];
			struct csio_q *q = hw->wrm.q_arr[sqset->iq_idx];

			rv = request_irq(entryp[k].vector, csio_scsi_isr, 0,
					 entryp[k].desc, q);
			if (rv) {
				csio_err(hw,
					"MSI-X IRQ request failed for vector "
			    		"%d error:%d\n", entryp[k].vector, rv);
				goto err;
			}

			entryp[k].dev_id = (void *)q;

			csio_dbg(hw, "SCSI msix vec:%d q:%p idx:%x aff:0x%x\n",
				  entryp[k].vector, q, k, (1 << j));

		} /* for all scsi cpus */
	} /* for all ports */

out:
	hw->os_flags |= CSIO_HWOSF_INTR_ENABLED;

	return CSIO_SUCCESS;

err:
	for (i = 0; i < k; i++) {
		entryp = &oshw->msix_entries[i];
		free_irq(entryp->vector, entryp->dev_id);
	}
	pci_disable_msix(oshw->pdev);

	return CSIO_INVAL;
}

static void
csio_disable_msix(struct csio_os_hw *oshw, bool free)
{
	int i;
	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	struct csio_msix_entries *entryp;
	int extra = csio_extra_msix_vecs(hw);
	int cnt = oshw->num_sqsets + extra;

	if (free) {
		for (i = 0; i < cnt; i++) {
			entryp = &oshw->msix_entries[i];
			free_irq(entryp->vector, entryp->dev_id);
		}
	}
	pci_disable_msix(oshw->pdev);

	return;
}

/* Reduce per-port max possible CPUs */
static void
csio_reduce_sqsets(struct csio_os_hw *oshw, int cnt)
{
	int i;
	struct csio_scsi_cpu_info *info;
	struct csio_hw *hw = csio_oshw_to_hw(oshw);

	while (cnt < oshw->num_sqsets) {
		for (i = 0; i < hw->num_t4ports; i++) {
			info = &oshw->scsi_cpu_info[i];
			if (info->max_cpus > 1) {
				info->max_cpus--;
				oshw->num_sqsets--;
				if (oshw->num_sqsets <= cnt)
					break;
			}
		}
	}

	csio_dbg(hw, "Reduced sqsets to %d\n", oshw->num_sqsets);
}

static csio_retval_t
csio_enable_msix(struct csio_os_hw *oshw)
{
	int rv, i, j, k, n, min, cnt;
	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	struct csio_msix_entries *entryp;
	struct msix_entry *entries;
	int extra = csio_extra_msix_vecs(hw);
	struct csio_scsi_cpu_info *info;

	min = hw->num_t4ports + extra;
	cnt = oshw->num_sqsets + extra;

	/* Max vectors required based on #niqs configured in fw */
	if (hw->flags & CSIO_HWF_USING_SOFT_PARAMS || !csio_is_hw_master(hw))
		cnt = CSIO_MIN(hw->cfg_niq, cnt);

	entries = kzalloc(sizeof(struct msix_entry) * cnt, GFP_KERNEL);
	if (!entries)
		return CSIO_NOMEM;

	for (i = 0; i < cnt; i++)
		entries[i].entry = (uint16_t)i;
	
	csio_dbg(hw, "FW supp #niq:%d, trying %d msix's\n", hw->cfg_niq, cnt);

	while ((rv = pci_enable_msix(oshw->pdev, entries, cnt)) >= min)
		cnt = rv;
	if (!rv) {
		if (cnt < (oshw->num_sqsets + extra)) {
			csio_dbg(hw, "Only got %d MSIX vectors. "
				 "Reducing sqsets to %d\n", cnt, cnt - extra);
			csio_reduce_sqsets(oshw, cnt - extra);
		}
	} else {
		if (rv > 0) {
			pci_disable_msix(oshw->pdev);
			csio_err(hw, "only %d MSI-X vectors left,"
			    " not using MSI-X\n", rv);
		}

		kfree(entries);
		return CSIO_NOMEM;
	}

	/* Save off vectors */
	for (i = 0; i < cnt; i++) {
		entryp = &oshw->msix_entries[i];
		entryp->vector = entries[i].vector;
	}

	/* Distribute vectors */
	k = 0;
	csio_set_nondata_intr_idx(hw, entries[k++].entry);
	csio_set_fwevt_intr_idx(hw, entries[k++].entry);

	for (i = 0; i < hw->num_t4ports; i++) {
		info = &oshw->scsi_cpu_info[i];

		for (j = 0; j < oshw->num_scsi_msix_cpus; j++) {
			n = (j % info->max_cpus) +  k;
			oshw->sqset[i][j].intr_idx = entries[n].entry;

			csio_dbg(hw, "%d:%d sqset[%d][%d].intr_idx = %d\n",
				  k, n, i, j, oshw->sqset[i][j].intr_idx);
		}

		k += info->max_cpus;
	}

	kfree(entries);
	return CSIO_SUCCESS;
}

void
csio_intr_enable(struct csio_os_hw *oshw)
{
	struct csio_hw *hw = csio_oshw_to_hw(oshw);

	hw->intr_mode = CSIO_IM_NONE;
	hw->os_flags &= ~CSIO_HWOSF_INTR_ENABLED;

	/* Try MSIX, then MSI or fall back to INTx */
	if ((csio_msi == 2) && !csio_enable_msix(oshw))
		hw->intr_mode = CSIO_IM_MSIX;
	else {
		/* Max iqs required based on #niqs configured in fw */
		if (hw->flags & CSIO_HWF_USING_SOFT_PARAMS ||
			!csio_is_hw_master(hw)) {
			int extra = CSIO_EXTRA_MSI_IQS;
		
			if (hw->cfg_niq < (oshw->num_sqsets + extra)) {
				csio_dbg(hw, "Only %d niqs available. "
					 "Reducing sqsets to %d\n", hw->cfg_niq,
					 hw->cfg_niq - extra);
				csio_reduce_sqsets(oshw, hw->cfg_niq - extra);
			}
		}

		if ((csio_msi == 1) && !pci_enable_msi(oshw->pdev))
			hw->intr_mode = CSIO_IM_MSI;
		else {
			hw->intr_mode = CSIO_IM_INTX;
			hw->intx_type = csio_intx_type(hw);
		}
	}	

	csio_dbg(hw, "Using %s interrupt mode.\n",
	 	(hw->intr_mode == CSIO_IM_MSIX)? "MSIX" :
		((hw->intr_mode == CSIO_IM_MSI)? "MSI" : "INTx" ));
	return;
}

void
csio_intr_disable(struct csio_os_hw *oshw, bool free)
{
	csio_hw_intr_disable(csio_oshw_to_hw(oshw));

	switch (csio_oshw_to_hw(oshw)->intr_mode) {
		case CSIO_IM_MSIX:
			csio_disable_msix(oshw, free);
			break;	
		case CSIO_IM_MSI:
			if (free)
				free_irq(oshw->pdev->irq, oshw);
			pci_disable_msi(oshw->pdev);
			break;
		case CSIO_IM_INTX:
			if (free)
				free_irq(oshw->pdev->irq, oshw);
			break;
		default:
			break;
	}
	csio_oshw_to_hw(oshw)->intr_mode = CSIO_IM_NONE;
	csio_oshw_to_hw(oshw)->os_flags &= ~CSIO_HWOSF_INTR_ENABLED;

	return;
}
