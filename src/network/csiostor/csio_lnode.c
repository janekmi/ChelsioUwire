/*
 *  Copyright (C) 2008-2014 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: This file implements the common lnode functions.
 *
 */

#include <csio_hw.h>
#include <csio_lnode.h>

/* REVISIT: ISCSI */

int
csio_scan_done(struct csio_lnode *ln, unsigned long ticks,
		unsigned long time, unsigned long max_scan_ticks,
		unsigned long delta_scan_ticks)
{
	int rv = 0;

	if (time >= max_scan_ticks)
		return 1;

	if (!ln->tgt_scan_tick)
		ln->tgt_scan_tick = ticks;

	if (((ticks - ln->tgt_scan_tick) >= delta_scan_ticks)) {
		if (!ln->last_scan_ntgts)
			ln->last_scan_ntgts = ln->n_scsi_tgts;
		else {
			if (ln->last_scan_ntgts == ln->n_scsi_tgts)
				return 1;

			ln->last_scan_ntgts = ln->n_scsi_tgts;
		}
		ln->tgt_scan_tick = ticks;
	}
	return rv;
}

/*
 * csio_notify_lnodes:
 * @hw: HW module
 * @note: Notification
 *
 * Called from the HW SM to fan out notifications to the
 * Lnode SM. Since the HW SM is entered with lock held,
 * there is no need to hold locks here.
 *
 */
void
csio_notify_lnodes(struct csio_hw *hw, csio_ln_notify_t note)
{
	struct csio_list *tmp;
	struct csio_lnode *ln;

	csio_dbg(hw, "Notifying all nodes of event %d\n", note);

	/* Traverse children lnodes list and send evt */
	csio_list_for_each(tmp, &hw->sln_head) {
		ln = (struct csio_lnode *) tmp;

		switch (note) {
		case CSIO_LN_NOTIFY_HWREADY:

			if (csio_is_fcoe(hw)) {
				csio_lnf_start(csio_lnode_to_fcoe(ln));
			} else { /* iSCSI */
				return;
			}

			break;	

		case CSIO_LN_NOTIFY_HWRESET:
		case CSIO_LN_NOTIFY_HWREMOVE:

			if (csio_is_fcoe(hw)) {
				csio_lnf_close(csio_lnode_to_fcoe(ln));
			} else { /* iSCSI */
#ifdef __CSIO_FOISCSI_ENABLED__
				csio_lni_down(csio_lnode_to_iscsi(ln));
#endif
			}
			break;	

		case CSIO_LN_NOTIFY_HWSTOP:

			if (csio_is_fcoe(hw)) {
				csio_lnf_stop(csio_lnode_to_fcoe(ln));
			} else { /* iSCSI */
#ifdef __CSIO_FOISCSI_ENABLED__
				csio_lni_down(csio_lnode_to_iscsi(ln));
				return;
#endif
			}

			break;	
		default:
			break;

		}
	}
	return;
}

/*
 * csio_disable_lnodes:
 * @hw: HW module
 * @portid:port id
 * @disable: disable/enable flag.
 * If disable=1, disables all lnode hosted on given physical port.
 * otherwise enables all the lnodes on given phsysical port.
 * This routine need to called with hw lock held.
 */
void
csio_disable_lnodes(struct csio_hw *hw, uint8_t portid, bool disable)
{
	struct csio_list *tmp;
	struct csio_lnode *ln;

	csio_dbg(hw, "Notifying event to all nodes of port:%d\n", portid);

	/* Traverse sibling lnodes list and send evt */
	csio_list_for_each(tmp, &hw->sln_head) {
		ln = (struct csio_lnode *) tmp;
		if (ln->portid != portid)
			continue;

		if (csio_is_fcoe(hw)) {
			if (disable)
				csio_lnf_stop(csio_lnode_to_fcoe(ln));
			else
				csio_lnf_start(csio_lnode_to_fcoe(ln));
		} else { /* iSCSI */
			return;
		}
	}
	return;
}

/* Entry points */
csio_retval_t
csio_lnode_init(struct csio_lnode *ln, struct csio_hw *hw,
		struct csio_lnode *pln)
{
	int rv = -CSIO_INVAL;

	/* Link this lnode to hw */
	csio_lnode_to_hw(ln) 	= hw;

	/* Link child to parent if child lnode */
	if (pln)
		ln->pln = pln;
	else
		ln->pln = NULL;

	/* Initialize scsi_tgt and timers to zero */
	ln->n_scsi_tgts = 0;
	ln->last_scan_ntgts = 0;
	ln->tgt_scan_tick = 0;

	/* Initialize rnode list */
	csio_head_init(&ln->rnhead);
	csio_head_init(&ln->cln_head);

	/* Initialize log level for debug */
	ln->params.log_level 	= hw->params.log_level;
	
	if (csio_is_fcoe(hw)) {
		csio_lnode_to_fcoe(ln)->ln = ln;
		if (csio_lnf_init(csio_lnode_to_fcoe(ln)))
			goto err;
	} else {
#ifdef __CSIO_FOISCSI_ENABLED__
		csio_lnode_to_iscsi(ln)->ln = ln;
		if (csio_lni_init(csio_lnode_to_iscsi(ln)))
			goto err;
#endif
	}

#ifdef __CSIO_TARGET__
	ln->tgt_hdl = NULL;
#endif /* __CSIO_TARGET__ */

	/* Add lnode to list of sibling or children lnodes */
	csio_spin_lock_irq(hw, &hw->lock);
	csio_enq_at_tail(pln? &pln->cln_head : &hw->sln_head, ln);
	if (pln)
		pln->num_vports++;
	csio_spin_unlock_irq(hw, &hw->lock);

	hw->num_lns++;

	return CSIO_SUCCESS;
err:
	csio_lnode_to_hw(ln) = NULL;
	return rv;
}

void
csio_lnode_exit(struct csio_lnode *ln)
{
	struct csio_hw *hw = csio_lnode_to_hw(ln);

	if (csio_is_fcoe(hw)) {
		csio_lnf_exit(csio_lnode_to_fcoe(ln));
	} else { /* iSCSI */
#ifdef __CSIO_FOISCSI_ENABLED__
		csio_lni_exit(csio_lnode_to_iscsi(ln));
#endif
	}

	/* Remove this lnode from hw->sln_head */
	csio_spin_lock_irq(hw, &hw->lock);
	csio_deq_elem(ln);

	/* If it is children lnode, decrement the
	 * counter in its parent lnode
	 */
	if (ln->pln)
		ln->pln->num_vports--;

	/* Update root lnode pointer */
	if (csio_list_empty(&hw->sln_head))
		hw->rln = NULL;
	else
		hw->rln = (struct csio_lnode *)csio_list_next(&hw->sln_head);
		
	csio_spin_unlock_irq(hw, &hw->lock);

#ifdef __CSIO_TARGET__
	CSIO_DB_ASSERT(ln->tgt_hdl == NULL);
#endif /* __CSIO_TARGET__ */

	csio_lnode_to_hw(ln) 	= NULL;
	hw->num_lns--;

	return;
}
