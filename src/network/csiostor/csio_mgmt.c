/*
 *  Copyright (C) 2008-2014 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in
 * this release for licensing terms and conditions.
 *
 * Description: This file implements the FCOE management interface function.
 *
 */

#include <csio_defs.h>
#include <csio_hw.h>
#include <csio_mgmt.h>
#include <csio_lnode.h>
#include <csio_rnode.h>

/*
 * csio_mgmt_req_lookup - Lookup the given IO req exist in Active Q.
 * mgmt - mgmt module
 * @io_req - io request
 *
 * Return - CSIO_SUCCESS:if given IO Req exists in active Q.
 *	    CSIO_INVAL  :if lookup fails.
 */
enum csio_oss_error
csio_mgmt_req_lookup(struct csio_mgmtm *mgmtm, struct csio_ioreq *io_req)
{
	struct csio_list *tmp;

	/* Lookup ioreq in the ACTIVEQ */
	csio_list_for_each(tmp, &mgmtm->active_q) {
		if(io_req == (struct csio_ioreq *) tmp) {
			return CSIO_SUCCESS;
		}
	}
	return CSIO_INVAL;
}

/*
 * csio_mgmts_tmo_handler - MGMT IO Timeout handler.
 * @data - Event data.
 *
 * Return - none.
 */
static void
csio_mgmt_tmo_handler(uintptr_t data)
{
	struct csio_mgmtm *mgmtm = (struct csio_mgmtm *) data;
	struct csio_list *tmp;	
	struct csio_ioreq     *io_req;		/* io request */


	csio_dbg(mgmtm->hw, "Mgmt timer invoked!\n");

	csio_spin_lock_irq(mgmtm->hw, &mgmtm->hw->lock);

	csio_list_for_each(tmp, &mgmtm->active_q) {
		io_req = (struct csio_ioreq *) tmp;
		io_req->tmo -= CSIO_MIN(io_req->tmo, ECM_MIN_TMO);

		if(!io_req->tmo) {
			/* Dequeue the request from retry Q. */
			tmp = csio_list_prev(tmp);
			csio_deq_elem(io_req);
			if(io_req->io_cbfn) {
				/* io_req will be freed by completion handler */
				io_req->wr_status = CSIO_TIMEOUT;
				io_req->io_cbfn(mgmtm->hw, io_req);
			}
			else {
				CSIO_DB_ASSERT(0);
			}	
		}
	}

	/* If retry queue is not empty, re-arm timer */	
	if(!csio_list_empty(&mgmtm->active_q))	
		csio_timer_start(&mgmtm->mgmt_timer, ECM_MIN_TMO);
	csio_spin_unlock_irq(mgmtm->hw, &mgmtm->hw->lock);
	return;
}



/*
 * csio_map_fw_retval - Maps FW retval into driver retval.
 *
 * Returns: driver retval value.
 */
csio_retval_t
csio_map_fw_retval(uint8_t fw_ret)
{
	switch(fw_ret) {
	case FW_SUCCESS: return CSIO_SUCCESS;	
	case FW_EPERM:	 return CSIO_NOPERM;
	case FW_EINVAL:	 return CSIO_INVAL;
	case FW_EIO:	 return CSIO_EIO; 	
	case FW_EAGAIN:  return CSIO_RETRY; 	
	case FW_ENOMEM:	 return CSIO_NOMEM;
	case FW_EBUSY:	 return CSIO_BUSY;
	case FW_ENOSYS:	 return CSIO_NOSUPP;
	case FW_EPROTO:	 return CSIO_EPROTO;
	default :	 return CSIO_INVAL;
	}
}


void
csio_mgmtm_cleanup(struct csio_mgmtm *mgmtm)
{
	struct csio_hw *hw = mgmtm->hw;
	struct csio_ioreq *io_req;
	struct csio_list *tmp;	
	uint32_t count;

	count = 30;
	/* Wait for all outstanding req to complete gracefully */
	while ((!csio_list_empty(&mgmtm->active_q)) && count--) {
		csio_spin_unlock_irq(hw, &hw->lock);
		csio_msleep(2000);
		csio_spin_lock_irq(hw, &hw->lock);
	}

	/* release outstanding req from ACTIVEQ */
	csio_list_for_each(tmp, &mgmtm->active_q) {
		io_req = (struct csio_ioreq *) tmp;
		tmp = csio_list_prev(tmp);
		csio_deq_elem(io_req);
		mgmtm->stats.n_active--;
		if (io_req->io_cbfn) {
			/* io_req will be freed by completion handler */
			io_req->wr_status = CSIO_TIMEOUT;
			io_req->io_cbfn(mgmtm->hw, io_req);
		}
	}
}

/*
 * csio_mgmt_init - Mgmt module init entry point
 * @mgmtsm - mgmt module
 * @hw 	 - HW module
 *
 * Initialize mgmt timer, resource wait queue, active queue,
 * completion q. Allocate Egress and Ingress
 * WR queues and save off the queue index returned by the WR
 * module for future use. Allocate and save off mgmt reqs in the
 * mgmt_req_freelist for future use. Make sure their SM is initialized
 * to uninit state.
 * Returns: CSIO_SUCCESS - on success
 *   	    CSIO_NOMEM   - on error.
 */
csio_retval_t
csio_mgmtm_init(struct csio_mgmtm *mgmtm, struct csio_hw *hw)
{

	csio_head_init(&mgmtm->active_q);
	csio_head_init(&mgmtm->cbfn_q);
	csio_timer_init(&mgmtm->mgmt_timer,
				csio_mgmt_tmo_handler,(void *)mgmtm);
	mgmtm->hw = hw;
	/*mgmtm->iq_idx = hw->fwevt_iq_idx;*/
	csio_dbg(hw, "MGMT module init done\n");
	return CSIO_SUCCESS;
}

/*
 * csio_mgmtm_exit - MGMT module exit entry point
 * @mgmtsm - mgmt module
 *
 * This function called during MGMT module uninit.
 * Stop timers, free ioreqs allocated.
 * Returns: None
 *
 */
void
csio_mgmtm_exit(struct csio_mgmtm *mgmtm)
{
#if 0
	struct csio_ioreq *io_req;
	struct csio_list *tmp;	

	/* release outstanding req from cbfnQ */
	csio_list_for_each(tmp, &mgmtm->cbfn_q) {
		io_req = (struct csio_ioreq *) tmp;

		tmp = csio_list_prev(tmp);
		csio_deq_elem(io_req);

		if(io_req->io_cbfn) {
			/* io_req will be freed by completion handler */
			io_req->wr_status = CSIO_TIMEOUT;
			io_req->io_cbfn(mgmtm->hw, io_req);
		}	
	}
#endif
	csio_timer_stop(&mgmtm->mgmt_timer);
	csio_dbg(mgmtm->hw, "MGMT module exit done\n");
	return;
}
