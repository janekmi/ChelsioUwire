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
#include <csio_os_init.h>
#include <csio_hw.h>
#include <csio_lnode.h>
#include <csio_rnode.h>
#include <csio_os_rnode.h>
#include <csio_os_foiscsi.h>

static void csio_rnism_uninit(struct csio_rnode_iscsi *, csio_rni_evt_t evt);
static void csio_rnism_login(struct csio_rnode_iscsi *, csio_rni_evt_t evt);
static void csio_rnism_ready(struct csio_rnode_iscsi *, csio_rni_evt_t);
static void csio_rnism_cleanup(struct csio_rnode_iscsi *rni, csio_rni_evt_t evt);
static void csio_rnism_logout(struct csio_rnode_iscsi *rni, csio_rni_evt_t evt);
static void csio_rnism_recovery(struct csio_rnode_iscsi *rni, csio_rni_evt_t evt);

int
csio_rnism_in_ready(struct csio_rnode_iscsi *rni)
{
	return csio_match_state(rni, csio_rnism_ready);
}

int
csio_rnism_in_uninit(struct csio_rnode_iscsi *rni)
{
	return csio_match_state(rni, csio_rnism_uninit);
}

int csio_rnism_in_recovery(struct csio_rnode_iscsi *rni)
{
	return csio_match_state(rni, csio_rnism_recovery);
}

int csio_rnism_in_cleanup(struct csio_rnode_iscsi *rni)
{
	return csio_match_state(rni, csio_rnism_cleanup);
}

int csio_rnism_in_logout(struct csio_rnode_iscsi *rni)
{
	return csio_match_state(rni, csio_rnism_logout);
}

int csio_rnism_in_login(struct csio_rnode_iscsi *rni)
{
	return csio_match_state(rni, csio_rnism_login);
}


static void csio_rnism_uninit(struct csio_rnode_iscsi *rni, csio_rni_evt_t evt)
{
	struct csio_rnode *rn = rni->rn;
	struct csio_lnode *ln = csio_rnode_to_lnode(rn);
	struct csio_lnode_iscsi *lni = csio_lnode_to_iscsi(ln);
	struct csio_hw *hw = csio_lnode_to_hw(ln);
	int notify_up = 1, rni_gone = 0;
	unsigned int op = 0;

	csio_dbg(csio_lnode_to_hw(csio_rnode_to_lnode(rni->rn)),
		"%s: Session {id [0x%x], handle [0x%x], event [0x%x], "
		"cached event [0x%x].\n",
		__FUNCTION__, rni->sess_id, rni->sess_handle, evt, rni->cached_evnt);
	
	switch (evt) {
	case CSIO_RNIE_FREE:
		if (rni->cached_evnt == CSIO_RNIE_LOGGED_OUT ||
			rni->cached_evnt == CSIO_RNIE_LOGOUT_FAILED ||
			rni->cached_evnt == CSIO_RNIE_LOGIN_FAILED ) {

			if (csio_lnode_to_iscsi(ln)->logout_all &&
					csio_lnode_to_iscsi(ln)->num_sessions)
				notify_up = 0;

			if (notify_up) {
				if (rni->sess_type == FW_FOISCSI_SESSION_TYPE_NORMAL &&
						rni->cached_evnt == CSIO_RNIE_LOGIN_FAILED) {
					op = ISCSI_LOGIN_TO_TARGET;
				} else if ((rni->sess_type == FW_FOISCSI_SESSION_TYPE_NORMAL) &&
						(rni->cached_evnt == CSIO_RNIE_LOGGED_OUT ||
						rni->cached_evnt == CSIO_RNIE_LOGOUT_FAILED)) {
					op = LOGOUT_FROM_TARGET;
				} else if (rni->sess_type == FW_FOISCSI_SESSION_TYPE_DISCOVERY) {
					op = ISCSI_DISC_TARGS;
				}
				
				csio_foiscsi_transport_event_handler(hw,
						op, rni->login_info.status, rni->node_id,
						&rni->login_info);
			}
			csio_put_rni(rni);
			rni_gone = 1;
#ifdef __CSIO_DEBUG__
			atomic_dec(&lni->mtx_cnt);
			BUG_ON(atomic_read(&lni->mtx_cnt) < 0);
#endif
			csio_mutex_unlock(&lni->lni_mtx);
			//csio_dbg(hw, "%s: Logged out from session-id [%d].\n",
			//		__FUNCTION__, sess_id);
		}

		if (!rni_gone)
			csio_put_rni(rni);
		
		break;

	case CSIO_RNIE_INIT:
		csio_set_state(&rni->sm, csio_rnism_login);
		break;

	case CSIO_RNIE_RECOVERY_TIMEDOUT:
	case CSIO_RNIE_LOGGED_OUT:
		break;

	default:
		csio_warn(hw, "%s: Unhandled event [%d] sent to session-id [%d] rni [%p]\n",
				__FUNCTION__, evt, rni->sess_id, rni);
		CSIO_DB_ASSERT(0);
		break;
	}
	return;
}

static void csio_rnism_cleanup(struct csio_rnode_iscsi *rni, csio_rni_evt_t evt)
{
	struct csio_rnode *rn = rni->rn;
	struct csio_os_rnode *osrn = csio_rnode_to_os(rn);
	struct csio_lnode *ln = csio_rnode_to_lnode(rn);
	struct csio_lnode_iscsi *lni = csio_lnode_to_iscsi(ln);
	struct csio_hw *hw = csio_lnode_to_hw(ln);
	
	csio_dbg(csio_lnode_to_hw(ln), "%s: Session [0x%x], event [0x%x], "
			"cevent [0x%x]\n",
			__FUNCTION__, rni->sess_id, evt,
			rni->cached_evnt);
	
	switch (evt) {
	case CSIO_RNIE_IN_CLEANUP:
		/*csio_dbg(hw, "%s: flushing all pending works for session-id [%d].\n", __FUNCTION__, rni->sess_id);
		flush_scheduled_work();*/
		csio_queue_work(&lni->workq, &osrn->rsess->foiscsi_cleanup);
		break;

	case CSIO_RNIE_CLEANUP_COMPL:
		if ((rni->cached_evnt != CSIO_RNIE_LOGIN_FAILED) &&
			(rni->sess_type == FW_FOISCSI_SESSION_TYPE_NORMAL) &&
			csio_hw_to_ops(hw)->os_rn_unreg_rnode)
			csio_hw_to_ops(hw)->os_rn_unreg_rnode(rn);
				
		csio_set_state(&rni->sm, csio_rnism_uninit);
		csio_post_event(&rni->sm, CSIO_RNIE_FREE);
		break;
	
	default:
		csio_warn(hw, "%s: Unhandled event [%d] sent to session-id [%d] rni [%p]\n",
				__FUNCTION__, evt, rni->sess_id, rni);
		CSIO_DB_ASSERT(0);	
		break;
	}

	return;
}

static void csio_rnism_ready(struct csio_rnode_iscsi *rni, csio_rni_evt_t evt)
{
	struct csio_rnode *rn = rni->rn;
	struct csio_lnode *ln = csio_rnode_to_lnode(rn);
	struct csio_hw *hw = csio_lnode_to_hw(ln);

	csio_dbg(hw, "%s: Session [0x%x], ready event [0x%x]\n",
		__FUNCTION__, rni->sess_id, evt);

	switch (evt) {

	case CSIO_RNIE_IN_LOGOUT:
		csio_set_state(&rni->sm, csio_rnism_logout);
		csio_post_event(&rni->sm, evt);
		break;
	
	case CSIO_RNIE_IN_RECOVERY:
		csio_set_state(&rni->sm, csio_rnism_recovery);
		csio_post_event(&rni->sm, evt);
		break;

	case CSIO_RNIE_SCSI_SCAN_FINISHED:
		csio_dbg(hw, "%s: Device scan finished\n", __FUNCTION__);
		csio_foiscsi_transport_event_handler(hw, ISCSI_LOGIN_TO_TARGET,
				CSIO_SUCCESS, rni->node_id, &rni->login_info);
#ifdef __CSIO_DEBUG__
		atomic_dec(&csio_lnode_to_iscsi(ln)->mtx_cnt);
		BUG_ON(atomic_read(&csio_lnode_to_iscsi(ln)->mtx_cnt) < 0);
#endif
		csio_mutex_unlock(&csio_lnode_to_iscsi(ln)->lni_mtx);
		break;
	
	case CSIO_RNIE_IN_SCSI:
		break;

	default:
		csio_warn(hw, "%s: Unhandled event [%d] sent to session-id [%d] rni [%p]\n",
				__FUNCTION__, evt, rni->sess_id, rni);
		CSIO_DB_ASSERT(0);	
		break;
	}
	return;
}

static void csio_rnism_login(struct csio_rnode_iscsi *rni, csio_rni_evt_t evt)
{
	struct csio_rnode *rn = rni->rn;
	struct csio_os_rnode *osrn = csio_rnode_to_os(rn);
	struct csio_lnode *ln = csio_rnode_to_lnode(rn);
	struct csio_lnode_iscsi *lni = csio_lnode_to_iscsi(ln);
	struct csio_hw *hw = csio_lnode_to_hw(ln);
	unsigned int node_id = rni->node_id;
	unsigned long flags;

	csio_dbg(csio_lnode_to_hw(ln), "%s: Session [0x%x], event [0x%x]\n",
			__FUNCTION__, rni->sess_id, evt);

	rni->cached_evnt = evt;
	
	switch (evt) {
	case CSIO_RNIE_IN_LOGIN:

		csio_dbg(hw, "issue ctrl work_request\n");
		if (csio_issue_foiscsi_ctrl_wr(hw, &rni->login_info, rn,
					FW_FOISCSI_WR_SUBOP_ADD,
					lni->inode_flowid, rni->login_info.inode_id, 0)) {
			csio_foiscsi_transport_event_handler(hw, ISCSI_LOGIN_TO_TARGET,
					CSIO_NOMEM, node_id, &rni->login_info);
			csio_set_state(&rni->sm, csio_rnism_uninit);
			csio_post_event(&rni->sm, CSIO_RNIE_FREE);
		}
		break;

	case CSIO_RNIE_LOGGED_IN:
		if (rni->sess_type == FW_FOISCSI_SESSION_TYPE_DISCOVERY) {
			csio_foiscsi_transport_event_handler(hw, ISCSI_DISC_TARGS, rni->wr_status,
					 rni->node_id, &rni->login_info);
			csio_set_state(&rni->sm, csio_rnism_uninit);
			csio_post_event(&rni->sm, CSIO_RNIE_FREE);
#ifdef __CSIO_DEBUG__
			atomic_dec(&lni->mtx_cnt);
			BUG_ON(atomic_read(&lni->mtx_cnt) < 0);
#endif
			csio_mutex_unlock(&csio_lnode_to_iscsi(ln)->lni_mtx);
		} else {
			csio_hw_to_ops(hw)->os_rn_reg_rnode(rn);
			foiscsi_unblock_session(rni);
		}
		break;

	case CSIO_RNIE_LOGIN_FAILED:
		csio_set_state(&rni->sm, csio_rnism_cleanup);
		csio_post_event(&rni->sm, CSIO_RNIE_CLEANUP_COMPL);
		break;

	case CSIO_RNIE_SCSI_UNBLOCKED:
		csio_dbg(hw, "%s: Scanning for devices\n", __FUNCTION__);
		csio_spin_lock_irqsave(hw, &hw->lock, flags);
		csio_lnode_to_iscsi(ln)->nscans++;
		rni->flags |= CSIO_RNI_SCAN_PENDING;
		csio_set_state(&rni->sm, csio_rnism_ready);
		csio_spin_unlock_irqrestore(hw, &hw->lock, flags);
		
		csio_work_schedule(&osrn->rsess->foiscsi_scan);
		break;

			
	default:
		csio_warn(hw, "%s: Unhandled event [%d] sent to session-id [%d] rni [%p]\n",
				__FUNCTION__, evt, rni->sess_id, rni);
		CSIO_DB_ASSERT(0);	
		break;
	}
	return;

}

static void csio_rnism_logout(struct csio_rnode_iscsi *rni, csio_rni_evt_t evt)
{
	struct csio_rnode *rn = rni->rn;
	/*struct csio_os_rnode *osrn = csio_rnode_to_os(rn);*/
	struct csio_lnode *ln = csio_rnode_to_lnode(rn);
	struct csio_hw *hw = csio_lnode_to_hw(ln);
	unsigned int node_id = rni->node_id;

	csio_dbg(csio_lnode_to_hw(ln), "%s: Session [0x%x], event [0x%x]\n",
			__FUNCTION__, rni->sess_id, evt);

	rni->cached_evnt = evt;

	switch (evt) {
	case CSIO_RNIE_IN_LOGOUT:
		foiscsi_unblock_session(rni);
		break;

	case CSIO_RNIE_LOGGED_OUT:
	case CSIO_RNIE_LOGOUT_FAILED:
		csio_set_state(&rni->sm, csio_rnism_cleanup);
		csio_post_event(&rni->sm, CSIO_RNIE_IN_CLEANUP);
		break;
	
	case CSIO_RNIE_SCSI_UNBLOCKED:
		if (csio_issue_foiscsi_ctrl_wr(hw, NULL, rn, FW_FOISCSI_WR_SUBOP_DEL,
				rni->sess_handle, rni->node_id, rni->sess_handle)) {
			csio_foiscsi_transport_event_handler(hw, LOGOUT_FROM_TARGET,
					CSIO_NOMEM, node_id, &rni->login_info);
		}
		break;

	default:
		csio_warn(hw, "%s: Unhandled event [%d] sent to session-id [%d] rni [%p]\n",
				__FUNCTION__, evt, rni->sess_id, rni);
		CSIO_DB_ASSERT(0);	
		break;
	}
	return;
}

static void csio_rnism_recovery(struct csio_rnode_iscsi *rni, csio_rni_evt_t evt)
{
	struct csio_rnode *rn = rni->rn;
	struct csio_lnode *ln = csio_rnode_to_lnode(rn);
	struct csio_hw *hw = csio_lnode_to_hw(ln);

	csio_dbg(csio_lnode_to_hw(csio_rnode_to_lnode(rni->rn)),
			"%s: Session [0x%x], event [0x%x]\n",
			__FUNCTION__, rni->sess_id, evt);

	rni->cached_evnt = evt;

	switch (evt) {
	case CSIO_RNIE_IN_RECOVERY:
		foiscsi_block_session(rni);
		break;
	
	case CSIO_RNIE_IN_LOGOUT:
		csio_set_state(&rni->sm, csio_rnism_logout);
		csio_post_event(&rni->sm, evt);
		break;

	case CSIO_RNIE_LOGGED_IN:
		foiscsi_unblock_session(rni);
		break;
	
	case CSIO_RNIE_RECOVERY_TIMEDOUT:
		csio_set_state(&rni->sm, csio_rnism_cleanup);
		foiscsi_unblock_session(rni);
		break;

	case CSIO_RNIE_SCSI_BLOCKED:
		/* indicate fw that session is blocked */
		if (csio_issue_foiscsi_ctrl_wr(hw, NULL, rn, FW_FOISCSI_WR_SUBOP_MOD,
				rni->sess_handle, rni->node_id, rni->sess_handle))
			CSIO_DB_ASSERT(0);
		break;

	case CSIO_RNIE_SCSI_UNBLOCKED:
		csio_dbg(hw, "%s: device online\n", __FUNCTION__);
		csio_set_state(&rni->sm, csio_rnism_ready);
		csio_post_event(&rni->sm, CSIO_RNIE_IN_SCSI);
		break;

	default:
		csio_warn(hw, "%s: Unhandled event [%d] sent to session-id [%d] rni [%p]\n",
				__FUNCTION__, evt, rni->sess_id, rni);
		CSIO_DB_ASSERT(0);
		break;
	}
	return;
}

/**
 * csio_rni_fwevt_handler - FW event handler.
 * @rni: iscsi rnode
 *
 */
void
csio_rni_fwevt_handler(struct csio_rnode_iscsi *rni, struct fw_rdev_wr *rdev_wr)
{
	csio_dbg(csio_lnode_to_hw(csio_rnode_to_lnode(rni->rn)),
		"%s: Session [0x%x], event [0x%x]\n",
		__FUNCTION__, rni ? rni->sess_id: -1,
		rdev_wr ? rdev_wr->event_cause: -1);
	return;
}

csio_retval_t
csio_rni_init(struct csio_rnode_iscsi *rni)
{
	struct csio_rnode *rn = NULL;
	struct csio_os_rnode *osrn = NULL;
	struct csio_lnode *ln = NULL;
	struct csio_os_lnode *osln = NULL;
	struct Scsi_Host *shost = NULL;
	struct foiscsi_cls_session *rsess = NULL;

	
	rn = csio_iscsi_to_rnode(rni);
	ln = csio_rnode_to_lnode(rn);
	osln = csio_lnode_to_os(ln);
	shost = csio_osln_to_shost(osln);

	rsess =  csio_alloc(csio_md(ln->hwp, CSIO_ISCSI_RSESS_MD),
			sizeof(struct foiscsi_cls_session), CSIO_MNOWAIT);
	if (!rsess)
		return CSIO_NOMEM;

	memset(rsess, 0, sizeof(*rsess));
	
	osrn = csio_rnode_to_os(rn);
	osrn->rsess = rsess;
	rsess->osrn = (void *)osrn;

	csio_work_init(&osrn->rsess->foiscsi_block, __foiscsi_block_session,
			(void *)osrn, (void *)NULL, NULL);
	csio_work_init(&osrn->rsess->foiscsi_unblock, __foiscsi_unblock_session,
			(void *)osrn, (void *)NULL, NULL);
	csio_work_init(&osrn->rsess->foiscsi_scan, foiscsi_scan_session,
			(void *)osrn, (void *)NULL, NULL);
	csio_work_init(&osrn->rsess->foiscsi_cleanup, foiscsi_session_cleanup,
			(void *)osrn, (void *)NULL, NULL);
	
	csio_init_state(&rni->sm, csio_rnism_uninit, csio_hw_to_tbuf(ln->hwp));

	return CSIO_SUCCESS;
}

void
csio_rni_exit(struct csio_rnode_iscsi *rni)
{
	struct csio_rnode *rn = csio_iscsi_to_rnode(rni);
	struct csio_hw *hw = csio_lnode_to_hw(rn->lnp);
	struct csio_os_rnode *osrn = csio_rnode_to_os(rn);

#if 0
	/* This cleanup was not present when this was originally coded,
	   and while it has no noticeable side effects, disable until
	   further investigation */
	csio_work_cleanup(&osrn->rsess->foiscsi_cleanup);
	csio_dbg(hw, "%s: foiscsi_cleanup cleaned up\n", __FUNCTION__);
#endif

	csio_work_cleanup(&osrn->rsess->foiscsi_scan);
	csio_dbg(hw, "%s: foiscsi_scan cleaned up\n", __FUNCTION__);
	
	csio_work_cleanup(&osrn->rsess->foiscsi_block);
	csio_dbg(hw, "%s: foiscsi_block cleaned up\n", __FUNCTION__);
	
	csio_work_cleanup(&osrn->rsess->foiscsi_unblock);
	csio_dbg(hw, "%s: foiscsi_unblock cleaned up\n", __FUNCTION__);

	csio_free(csio_md(hw, CSIO_ISCSI_RSESS_MD), osrn->rsess);

	rni->os_ops = NULL;

	return;
}

