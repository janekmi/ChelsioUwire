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
#include <csio_version.h>
#include <csio_foiscsi_ioctl.h>
#include <csio_stor_ioctl.h>
#include <csio_foiscsi.h>
#include <csio_os_foiscsi.h>


void foiscsi_session_cleanup(void *data)
{
	struct csio_os_rnode *osrn = NULL;
	struct csio_rnode_iscsi *rni = NULL;
	struct csio_lnode *ln = NULL;
	struct csio_hw *hw = NULL;
	struct csio_os_lnode *osln = NULL;
	struct Scsi_Host *shost = NULL;
	struct foiscsi_cls_session *rsess = NULL;
	unsigned long flags;

	osrn = (struct csio_os_rnode *)data;
	rsess = osrn->rsess;

	rni = csio_rnode_to_iscsi(&osrn->rnode);
	ln = csio_rnode_to_lnode(rni->rn);
	osln = csio_lnode_to_os(ln);
	shost = csio_osln_to_shost(osln);
	hw = csio_lnode_to_hw(ln);

	csio_spin_lock_irqsave(hw, &hw->lock, flags);
	csio_foiscsi_cleanup_rnode_io(csio_hw_to_scsim(hw), rni->rn);
	csio_spin_unlock_irqrestore(hw, &hw->lock, flags);

	csio_dbg(hw, "%s: rni->flags [0x%x].\n", __FUNCTION__, rni->flags);
	if (rni->flags & CSIO_RNI_SCAN_PENDING)
		cancel_work_sync(&osrn->rsess->foiscsi_scan.work);
	
	scsi_remove_target(&osrn->rsess->dev);
	csio_dbg(hw, "%s: Remove target, session-id [%d].\n", __FUNCTION__, rni->sess_id);

	csio_post_event(&rni->sm, CSIO_RNIE_CLEANUP_COMPL);
	
	return;
}

void __foiscsi_block_session(void *data)
{
	struct csio_os_rnode *osrn;
	struct csio_rnode *rn = NULL;
	struct csio_rnode_iscsi *rni = NULL;
	struct foiscsi_cls_session *rsess = NULL;
	struct csio_hw *hw = NULL;

	osrn = (struct csio_os_rnode *)data;
	rsess = osrn->rsess;
	rn = &osrn->rnode;
	rni = csio_rnode_to_iscsi(rn);
	hw = csio_lnode_to_hw(rn->lnp);
	csio_dbg(hw, "%s: Blocking sess_id [0x%x], sess_handle [0x%x], io_handle [0x%x]\n",
			__FUNCTION__, rni->sess_id, rni->sess_handle, rni->io_handle);

	scsi_target_block(&osrn->rsess->dev);

	switch (rni->cached_evnt) {
	case CSIO_RNIE_IN_LOGOUT:
	case CSIO_RNIE_IN_RECOVERY:
		csio_post_event(&rni->sm, CSIO_RNIE_SCSI_BLOCKED);
		break;
	 default:
		csio_warn(hw, "%s: Unhandled event:%d sent to rni:%p\n",
				__FUNCTION__, rni->cached_evnt, rni);
		CSIO_DB_ASSERT(0);
		break;
	}

	csio_dbg(hw, "%s: Blocked sess_id [0x%x], sess_handle [0x%x], io_handle [0x%x]\n",
			__FUNCTION__, rni->sess_id, rni->sess_handle, rni->io_handle);
}


void __foiscsi_unblock_session(void *data)
{
	struct csio_lnode *ln;
	struct csio_lnode_iscsi *lni;
	struct csio_os_rnode *osrn;
	struct csio_os_lnode *osln;
	struct Scsi_Host *shost;
	struct csio_rnode_iscsi *rni;
	struct csio_hw  *hw;
	struct csio_os_hw *oshw;
	struct foiscsi_cls_session *rsess = NULL;
	
	osrn = (struct csio_os_rnode *)data;
	rsess = osrn->rsess;
	ln = osrn->rnode.lnp;
	lni = csio_lnode_to_iscsi(ln);
	osln = csio_lnode_to_os(ln);
	shost = csio_osln_to_shost(osln);
	rni = csio_rnode_to_iscsi(&osrn->rnode);
	hw = csio_lnode_to_hw(ln);
	oshw = csio_hw_to_os(hw);

	csio_dbg(hw, "%s: Unblocking sess_id [0x%x], sess_handle [0x%x], io_handle [0x%x]\n",
			__FUNCTION__, rni->sess_id, rni->sess_handle, rni->io_handle);

	switch (rni->cached_evnt) {
	case CSIO_RNIE_LOGGED_IN:
	case CSIO_RNIE_IN_RECOVERY:
		csio_scsi_target_unblock(&rsess->dev, SDEV_RUNNING);
		break;
	case CSIO_RNIE_IN_LOGOUT:
	case CSIO_RNIE_RECOVERY_TIMEDOUT:
		csio_scsi_target_unblock(&rsess->dev, SDEV_TRANSPORT_OFFLINE);
		break;
	default:
		csio_warn(hw, "%s: Unhandled event:%d sent to rni:%p\n",
				__FUNCTION__, rni->cached_evnt, rni);
		CSIO_DB_ASSERT(0);
		break;
	}

	if (rni->cached_evnt == CSIO_RNIE_RECOVERY_TIMEDOUT)
		csio_post_event(&rni->sm, CSIO_RNIE_IN_CLEANUP);
	else
		csio_post_event(&rni->sm, CSIO_RNIE_SCSI_UNBLOCKED);

	csio_dbg(hw, "%s: Unblocked sess_id [0x%x], sess_handle [0x%x], io_handle [0x%x]\n",
			__FUNCTION__, rni->sess_id, rni->sess_handle, rni->io_handle);
}

void foiscsi_scan_session(void *data)
{
	struct csio_os_rnode *osrn = (struct csio_os_rnode *)data;
	struct csio_rnode *rn = &osrn->rnode;
	struct csio_lnode *ln = csio_rnode_to_lnode(rn);
	struct csio_lnode_iscsi *lni = csio_lnode_to_iscsi(ln);
	struct csio_rnode_iscsi *rni = csio_rnode_to_iscsi(rn);
	struct csio_hw *hw = csio_lnode_to_hw(ln);
	unsigned long flags;

	/* target_id must be unique */
	scsi_scan_target(&osrn->rsess->dev, 0, ((rni->node_id << 13) | rni->sess_id),
			SCAN_WILD_CARD, 1);

	csio_spin_lock_irqsave(hw, &hw->lock, flags);
	lni->nscans--;
	rni->flags &= ~CSIO_RNI_SCAN_PENDING;
	csio_spin_unlock_irqrestore(hw, &hw->lock, flags);

	csio_post_event(&rni->sm, CSIO_RNIE_SCSI_SCAN_FINISHED);
}

/*
int csio_iscsi_scan_finished(struct Scsi_Host *shost, unsigned long time)
{
	struct csio_os_lnode *osln = shost_priv(shost);
	struct csio_lnode *ln = csio_osln_to_ln(osln);
	struct csio_lnode_iscsi *lni = csio_lnode_to_iscsi(ln);
	struct csio_hw *hw = csio_lnode_to_hw(ln);
	struct csio_rnode_iscsi *rni = NULL;
	unsigned long flags;
	int rc;

	csio_spin_lock_irqsave(hw, &hw->lock, flags);
	rc = !(lni->nscans) ? 1 : 0;
	csio_spin_unlock_irqrestore(hw, &hw->lock, flags);

		
	return rc;
}
*/

int csio_iscsi_session_chkready(struct csio_rnode *rn)
{
	struct csio_rnode_iscsi *rni = NULL;
	int rc = 0;
	
	if (unlikely(!rn)) {
		rc = DID_NO_CONNECT << 16;
		goto out;
	}
	
	rni = csio_rnode_to_iscsi(rn);
	
	if (likely(csio_rnism_in_ready(rni)))
		rc = 0;
	else if (csio_rnism_in_recovery(rni))
		rc = DID_IMM_RETRY << 16;
	else if (csio_rnism_in_logout(rni))
		rc = DID_NO_CONNECT << 16;
	else if (csio_rnism_in_uninit(rni))
		rc = DID_TRANSPORT_FAILFAST << 16;
	else
		rc = DID_NO_CONNECT << 16;

	if (csio_rnism_in_login(rni) ||
		csio_rnism_in_recovery(rni) ||
		csio_rnism_in_logout(rni) ||
		csio_rnism_in_cleanup(rni) ||
		csio_rnism_in_uninit(rni))
		csio_dbg(csio_lnode_to_hw(csio_rnode_to_lnode(rn)),
			"%s: in %s, rc [%d]\n", __FUNCTION__,
			csio_rnism_in_login(rni) ? "login" :
			csio_rnism_in_recovery(rni) ? "recovery" :
			csio_rnism_in_logout(rni) ? "logout" :
			csio_rnism_in_cleanup(rni) ? "cleanup" :
			csio_rnism_in_uninit(rni) ? "uninit" :
			"unknown", rc);
out:
	return rc;
}

static void csio_rni_dev_release(struct device *dev)
{
	struct csio_os_rnode *osrn = (struct csio_os_rnode *)dev->platform_data;
	struct csio_rnode *rn = &osrn->rnode;
	struct csio_lnode *ln = csio_rnode_to_lnode(rn);
	struct csio_os_lnode *osln = csio_lnode_to_os(ln);
	struct Scsi_Host *shost = csio_osln_to_shost(osln);
	
	scsi_host_put(shost);
	csio_dbg(ln->hwp, "%s: rni [%p], device released for session [%d].\n",
			__FUNCTION__, csio_rnode_to_iscsi(rn),
			csio_rnode_to_iscsi(rn)->sess_id);
	return;
}

void csio_rni_reg_rnode(struct csio_rnode *rn)
{
	struct csio_lnode *ln = csio_rnode_to_lnode(rn);
	struct csio_rnode_iscsi *rni = csio_rnode_to_iscsi(rn);
	struct csio_os_rnode *osrn = csio_rnode_to_os(rn);
	struct csio_lnode_iscsi *lni = csio_lnode_to_iscsi(ln);
	struct csio_os_lnode *osln = csio_lnode_to_os(ln);
	struct Scsi_Host *shost = csio_osln_to_shost(osln);
	int err;

	scsi_host_get(shost);
	osrn->rsess->dev.parent = &shost->shost_gendev;
	osrn->rsess->dev.release = csio_rni_dev_release;
	osrn->rsess->dev.platform_data = (void *)osrn;
	device_initialize(&osrn->rsess->dev);

	dev_set_name(&osrn->rsess->dev, "csio-iscsi-dev%d", rni->sess_handle);
	err = device_add(&osrn->rsess->dev);
	if (err) {
		csio_dbg(ln->hwp,"%s: Unable to register device for rni [%p], sess_id [%d].\n",
				__FUNCTION__, rni, rni->sess_id);
		return;
	}

	ln->num_reg_rnodes++;
	lni->num_sessions++;
	if (!try_module_get(THIS_MODULE))
		CSIO_DB_ASSERT(0);

	return;
}

void csio_rni_unreg_rnode(struct csio_rnode *rn)
{
	struct csio_lnode *ln = csio_rnode_to_lnode(rn);
	struct csio_lnode_iscsi *lni = csio_lnode_to_iscsi(rn->lnp);
	struct csio_os_rnode *osrn = csio_rnode_to_os(rn);
#ifdef __CSIO_DEBUG__
	struct csio_hw *hw = csio_lnode_to_hw(rn->lnp);
#endif

	lni->num_sessions--;
	ln->num_reg_rnodes--;

	csio_dbg(hw, "%s: Number of sessions [%d], rnodes [%d].\n",
			__FUNCTION__, lni->num_sessions,
			ln->num_reg_rnodes);
	
	device_del(&osrn->rsess->dev);
	put_device(&osrn->rsess->dev);

	module_put(THIS_MODULE);
	
	return;
}

int csio_iscsi_send_logout(struct csio_hw *hw, struct csio_rnode *rn)
{
	struct csio_rnode_iscsi *rni;
	struct csio_lnode *ln = csio_rnode_to_lnode(rn);
	struct csio_os_lnode *osln = NULL;

	osln = csio_lnode_to_os(ln);

	rni = csio_rnode_to_iscsi(rn);


	csio_post_event(&rni->sm, CSIO_RNIE_IN_LOGOUT);

	return CSIO_SUCCESS;
}

void csio_foiscsi_ctrl_del(struct csio_rnode *rn, u8 status)
{
 	struct csio_hw *hw = csio_lnode_to_hw(csio_rnode_to_lnode(rn));
	struct csio_rnode_iscsi *rni = csio_rnode_to_iscsi(rn);
	unsigned long flags;

	csio_spin_lock_irqsave(hw, &hw->lock, flags);
	
	/* GLUE CHANGE */
	csio_post_event(&rni->sm, CSIO_RNIE_LOGGED_OUT);

	csio_spin_unlock_irqrestore(hw, &hw->lock, flags);

	return;
}
