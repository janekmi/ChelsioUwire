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
 * 	This chfcoe_vn2vn.c file contains VN2VN mode routines
 *
 * Authors:
 * 	Praveen M <praveenm@chelsio.com>
 */

#include "chfcoe_defs.h"
#include "chfcoe_adap.h"
#include "chfcoe_proto.h"
#include "chfcoe_lnode.h"
#include "chfcoe_vn2vn.h"

extern int chfcoe_vlanid;

void
chfcoe_vn2vn_update_rnode(struct chfcoe_vn2vn *vn2vn, 
		struct chfcoe_vn2vn_parms *rcv_parms)
{
	struct chfcoe_port_parms rdev_entry;

	chfcoe_memset(&rdev_entry, 0, sizeof(struct chfcoe_port_parms));
	rdev_entry.nport_id = rcv_parms->luid;
	chfcoe_memcpy(rdev_entry.mac, rcv_parms->mac, 6);
	chfcoe_memcpy(rdev_entry.vn_mac, rcv_parms->vn_mac, 6);
	chfcoe_memcpy(rdev_entry.wwpn, rcv_parms->wwpn, 8);
	chfcoe_memcpy(rdev_entry.wwnn, rcv_parms->wwnn, 8);
	rdev_entry.max_fcoe_sz = rcv_parms->max_fcoe_sz;

	/* lnode event handler */
	chfcoe_lnode_evt_handler(vn2vn->ln, CHFCOE_LN_EVT_RDEV,
			&rdev_entry);
}

void
chfcoe_vn2vn_down(struct chfcoe_vn2vn *vn2vn) 
{
	chfcoe_lnode_evt_handler(vn2vn->ln, CHFCOE_LN_EVT_LINK_DOWN, 0);
}

void
chfcoe_vn2vn_up(struct chfcoe_vn2vn *vn2vn) 
{
	struct chfcoe_port_parms lport_parms;
	struct chfcoe_port_info *pi = vn2vn->pi;

	chfcoe_memset(&lport_parms, 0, sizeof(struct chfcoe_port_parms));
	lport_parms.nport_id = vn2vn->luid;
	chfcoe_memcpy(lport_parms.mac, pi->phy_mac, 6);
	chfcoe_memcpy(lport_parms.vn_mac, vn2vn->vn_mac, 6);
	chfcoe_memcpy(lport_parms.wwpn, vn2vn->wwpn, 8);
	chfcoe_memcpy(lport_parms.wwnn, vn2vn->wwnn, 8);
	lport_parms.max_fcoe_sz = PROTO_MAX_FCOE_SIZE;

	chfcoe_lnode_evt_handler(vn2vn->ln, CHFCOE_LN_EVT_LINK_UP, 
			&lport_parms);
}

chfcoe_retval_t
chfcoe_vn2vn_send_probe_reply(struct chfcoe_vn2vn *vn2vn, 
		struct chfcoe_vn2vn_parms *rcv_parms) 
{
	struct proto_fip_nport_probe *rep;	
	chfcoe_fc_buffer_t 	*fb;
	struct chfcoe_port_info *pi = vn2vn->pi;
	struct chfcoe_adap_info	*adap = pi->adap;

	fb = chfcoe_fip_buffer_alloc(sizeof(struct proto_fip_nport_probe));
	if (!fb) {
		return CHFCOE_NOMEM;
	}	

	/*
	 * Fill the cpl_tx_pkt and get the point pointing past it so 
	 * that we can fill teh rest of the frame
	 */
	rep  = (struct proto_fip_nport_probe *)
		chfcoe_fill_cpl_tx(fb, adap->pf, 
				sizeof(struct proto_fip_nport_probe), 
				pi->port_num, (vn2vn->vlan_id |
				pi->dcb_prio << VLAN_PRIO_SHIFT));

	chfcoe_fill_fip_hdr(rep, rcv_parms->mac, pi->phy_mac, 
		PROTO_FIP_OP_VN2VN, PROTO_FIP_SC_VN_PROBE_REP, 
		sizeof(rep->desc), 0);
	chfcoe_fill_fip_mac_desc(&rep->desc.mac, pi->phy_mac);
	chfcoe_fill_fip_name_desc(&rep->desc.wwnn, vn2vn->wwnn);
	chfcoe_fill_fip_vn_desc(&rep->desc.vn, vn2vn->vn_mac, vn2vn->luid, 
			vn2vn->wwpn);

	adap->lld_ops->send_frame(fb, pi->os_dev, chfcoe_smp_id());
	CHFCOE_INC_STATS(vn2vn, probe_reply_sent);
	return CHFCOE_SUCCESS;
}

chfcoe_retval_t
chfcoe_vn2vn_send_probe_req(struct chfcoe_vn2vn *vn2vn) 
{
	struct proto_fip_nport_probe *req;	
	chfcoe_fc_buffer_t 	*fb;
	struct chfcoe_port_info *pi = vn2vn->pi;
	struct chfcoe_adap_info	*adap = pi->adap;
	uint8_t dmac[6] = PROTO_FIP_ALL_VN2VN_MACS;


	fb = chfcoe_fip_buffer_alloc(sizeof(struct proto_fip_nport_probe));
	if (!fb) {
		chfcoe_dbg(pi, "port:%x failed to alloc for probe req\n", 
				pi->port_num);
		return CHFCOE_NOMEM;
	}	
	chfcoe_dbg(pi, "port:%x VN2VN send probe req\n", pi->port_num);

	/*
	 * Fill the cpl_tx_pkt and get the point pointing past it so 
	 * that we can fill teh rest of the frame
	 */
	req  = (struct proto_fip_nport_probe *)
		chfcoe_fill_cpl_tx(fb, adap->pf, 
				sizeof(struct proto_fip_nport_probe), 
				pi->port_num, (vn2vn->vlan_id |
				pi->dcb_prio << VLAN_PRIO_SHIFT));

	chfcoe_fill_fip_hdr(req, dmac, pi->phy_mac, PROTO_FIP_OP_VN2VN,
		PROTO_FIP_SC_VN_PROBE_REQ, sizeof(req->desc), 0);
	chfcoe_fill_fip_mac_desc(&req->desc.mac, pi->phy_mac);
	chfcoe_fill_fip_name_desc(&req->desc.wwnn, vn2vn->wwnn);
	chfcoe_fill_fip_vn_desc(&req->desc.vn, vn2vn->vn_mac, vn2vn->luid, 
			vn2vn->wwpn);

	adap->lld_ops->send_frame(fb, pi->os_dev, chfcoe_smp_id());
	CHFCOE_INC_STATS(vn2vn, probes_sent);
	return CHFCOE_SUCCESS;
}

chfcoe_retval_t
chfcoe_vn2vn_send_claim_rsp(struct chfcoe_vn2vn *vn2vn, 
		struct chfcoe_vn2vn_parms *rcv_parms) 
{
	struct proto_fip_nport_claim *rsp;	
	chfcoe_fc_buffer_t 	*fb;
	struct chfcoe_port_info *pi = vn2vn->pi;
	struct chfcoe_adap_info	*adap = pi->adap;
	uint16_t flags;
	uint16_t claim_reqsz;

	/*Discard proto_fc_ns for now..Unable to fit into immediate data */
	claim_reqsz = sizeof(struct proto_fip_nport_claim) - 
		sizeof(struct proto_fip_fc4_desc);

	fb = chfcoe_fip_buffer_alloc(claim_reqsz);
	if (!fb) {
		return CHFCOE_NOMEM;
	}	

	/*
	 * Fill the cpl_tx_pkt and get the point pointing past it so 
	 * that we can fill teh rest of the frame
	 */
	rsp  = (struct proto_fip_nport_claim *)
		chfcoe_fill_cpl_tx(fb, adap->pf, 
			claim_reqsz, 
			pi->port_num, (vn2vn->vlan_id |
			pi->dcb_prio << VLAN_PRIO_SHIFT));

	flags = 0;
	chfcoe_fill_fip_hdr(rsp, rcv_parms->mac, pi->phy_mac, 
		PROTO_FIP_OP_VN2VN, PROTO_FIP_SC_VN_CLAIM_REP, 
		sizeof(rsp->desc) - sizeof(struct proto_fip_fc4_desc), flags);
	chfcoe_fill_fip_mac_desc(&rsp->desc.mac, pi->phy_mac);
	chfcoe_fill_fip_name_desc(&rsp->desc.wwnn, vn2vn->wwnn);
	chfcoe_fill_fip_vn_desc(&rsp->desc.vn, vn2vn->vn_mac, vn2vn->luid, 
			vn2vn->wwpn);
	chfcoe_fill_fip_size_desc(&rsp->desc.size, PROTO_MAX_FCOE_SIZE);

	adap->lld_ops->send_frame(fb, pi->os_dev, chfcoe_smp_id());
	CHFCOE_INC_STATS(vn2vn, claims_sent);
	return CHFCOE_SUCCESS;
}

chfcoe_retval_t
chfcoe_vn2vn_send_claim_req(struct chfcoe_vn2vn *vn2vn) 
{
	struct proto_fip_nport_claim *req;	
	chfcoe_fc_buffer_t 	*fb;
	struct chfcoe_port_info *pi = vn2vn->pi;
	struct chfcoe_adap_info	*adap = pi->adap;
	uint8_t dmac[6] = PROTO_FIP_ALL_VN2VN_MACS;
	uint16_t claim_reqsz;

	/*Discard proto_fc_ns for now..Unable to fit into immediate data */
	claim_reqsz = sizeof(struct proto_fip_nport_claim) - 
		sizeof(struct proto_fip_fc4_desc);

	fb = chfcoe_fip_buffer_alloc(claim_reqsz);
	if (!fb) {
		return CHFCOE_NOMEM;
	}	

	/*
	 * Fill the cpl_tx_pkt and get the point pointing past it so 
	 * that we can fill teh rest of the frame
	 */
	req  = (struct proto_fip_nport_claim *)
		chfcoe_fill_cpl_tx(fb, adap->pf, 
			claim_reqsz, 
			pi->port_num, (vn2vn->vlan_id |
			pi->dcb_prio << VLAN_PRIO_SHIFT));

	chfcoe_fill_fip_hdr(req, dmac, pi->phy_mac, PROTO_FIP_OP_VN2VN,
		PROTO_FIP_SC_VN_CLAIM_NOTIFY, (sizeof(req->desc)
		- sizeof(struct proto_fip_fc4_desc)), 0);

	chfcoe_fill_fip_mac_desc(&req->desc.mac, pi->phy_mac);
	chfcoe_fill_fip_name_desc(&req->desc.wwnn, vn2vn->wwnn);
	chfcoe_fill_fip_vn_desc(&req->desc.vn, vn2vn->vn_mac, vn2vn->luid, 
			vn2vn->wwpn);
	chfcoe_fill_fip_size_desc(&req->desc.size, PROTO_MAX_FCOE_SIZE);

	adap->lld_ops->send_frame(fb, pi->os_dev, chfcoe_smp_id());
	CHFCOE_INC_STATS(vn2vn, claims_sent);
	return CHFCOE_SUCCESS;
}

chfcoe_retval_t
chfcoe_vn2vn_send_beacon(struct chfcoe_vn2vn *vn2vn) 
{
	struct proto_fip_beacon *req;	
	chfcoe_fc_buffer_t 	*fb;
	struct chfcoe_port_info *pi = vn2vn->pi;
	struct chfcoe_adap_info	*adap = pi->adap;
	uint8_t dmac[6] = PROTO_FIP_ALL_VN2VN_MACS;

	fb = chfcoe_fip_buffer_alloc(sizeof(struct proto_fip_beacon));
	if (!fb) {
		return CHFCOE_NOMEM;
	}	

	/*
	 * Fill the cpl_tx_pkt and get the point pointing past it so 
	 * that we can fill teh rest of the frame
	 */
	req  = (struct proto_fip_beacon *)
		chfcoe_fill_cpl_tx(fb, adap->pf, 
				sizeof(struct proto_fip_beacon), 
				pi->port_num, (vn2vn->vlan_id |
				pi->dcb_prio << VLAN_PRIO_SHIFT));

	chfcoe_fill_fip_hdr(req, dmac, vn2vn->vn_mac, 
		PROTO_FIP_OP_VN2VN, 
		PROTO_FIP_SC_VN_BEACON, sizeof(req->desc), 0);
	chfcoe_fill_fip_mac_desc(&req->desc.mac, pi->phy_mac);
	chfcoe_fill_fip_name_desc(&req->desc.wwnn, vn2vn->wwnn);
	chfcoe_fill_fip_vn_desc(&req->desc.vn, vn2vn->vn_mac, vn2vn->luid, 
			vn2vn->wwpn);

	adap->lld_ops->send_frame(fb, pi->os_dev, chfcoe_smp_id());
	CHFCOE_INC_STATS(vn2vn, beacons_sent);
	return CHFCOE_SUCCESS;
}


void chfcoe_vn2vn_state_proc(struct chfcoe_vn2vn *vn2vn, enum vn2vn_evt evt, 
			struct chfcoe_vn2vn_parms *rcv_parms)
{
	chfcoe_dbg(foo, "vn2vn sm port:%d state:%d evt:%d\n",
			vn2vn->pi->port_num, vn2vn->state, evt);

	if (evt == CHFCOE_VN2VN_STOP_EVT) {
		vn2vn->state = CHFCOE_VN2VN_OFFLINE_STATE;
		chfcoe_vn2vn_down(vn2vn);
		return;
	}

	switch(vn2vn->state) {
	case CHFCOE_VN2VN_UINIT_STATE:
		if (evt == CHFCOE_VN2VN_START_EVT) {
			/* Send 2 probe request */		
			chfcoe_vn2vn_send_probe_req(vn2vn);
			chfcoe_vn2vn_send_probe_req(vn2vn);

			vn2vn->state = CHFCOE_VN2VN_PROBE_STATE;
			chfcoe_schedule_delayed_work(vn2vn->probe_timer,
					PROTO_FIP_ANNONCE_WAIT);
		}
		if (evt == CHFCOE_VN2VN_PROBE_TMO_EVT) {
			/* Choose another luid */
			vn2vn->luid = (vn2vn->luid + 1) & LUID_MASK;
			proto_fip_vn2vn_set_mac(vn2vn->vn_mac, vn2vn->luid);

			/* Send 2 probe request */		
			chfcoe_vn2vn_send_probe_req(vn2vn);
			chfcoe_vn2vn_send_probe_req(vn2vn);

			vn2vn->state = CHFCOE_VN2VN_PROBE_STATE;
			chfcoe_schedule_delayed_work(vn2vn->probe_timer,
					PROTO_FIP_ANNONCE_WAIT);
		}	
		break;
	case CHFCOE_VN2VN_PROBE_STATE:

		if (evt == CHFCOE_VN2VN_PROBE_TMO_EVT) {
			/* Send claim notification */
			chfcoe_vn2vn_send_claim_req(vn2vn);
			vn2vn->state = CHFCOE_VN2VN_CLAIM_STATE;
			chfcoe_schedule_delayed_work(vn2vn->probe_timer,
					PROTO_FIP_ANNONCE_WAIT);
			break;
		}

		if (!rcv_parms) {
		      	chfcoe_dbg(pi, "vn2vn sm port:%d invalid vn2vn param "
				"recv in evt:%d in state:%d\n", evt, 
				vn2vn->state);
			CHFCOE_INC_STATS(vn2vn, ignore_evt);
			break;
		}

		/* Send probe req, when recving P2P claim or P2P beacon 
		   when we are operating in Multi point mode */
		if (rcv_parms->fip_flags & PROTO_FIP_FL_REC_OR_P2P) {
			if (evt == CHFCOE_VN2VN_CLAIM_NOTIFY_EVT ||
				evt == CHFCOE_VN2VN_BEACON_RCV_EVT) {
				chfcoe_vn2vn_send_probe_req(vn2vn);
			}	
		}

		/* Ignore events recv'd on different luids */
		if ((vn2vn->luid != rcv_parms->luid) && 
		     ((evt == CHFCOE_VN2VN_PROBE_REQ_EVT) || 
		     (evt == CHFCOE_VN2VN_CLAIM_NOTIFY_EVT) ||
		     (evt == CHFCOE_VN2VN_BEACON_RCV_EVT))) {
		      	chfcoe_dbg(pi, "vn2vn sm port:%d invalid vn2vn param "
				"recv in evt:%d in state:%d\n", 
				vn2vn->pi->port_num, evt, vn2vn->state);
			CHFCOE_INC_STATS(vn2vn, ignore_evt);
		      	break;
		}	

		/* select new luid, if events recv'd on same luids */
		if ((vn2vn->luid == rcv_parms->luid) && 
		     ((evt == CHFCOE_VN2VN_PROBE_REQ_EVT) || 
		     (evt == CHFCOE_VN2VN_PROBE_REP_EVT) || 
		     (evt == CHFCOE_VN2VN_CLAIM_NOTIFY_EVT) ||
		     (evt == CHFCOE_VN2VN_BEACON_RCV_EVT))) {
		
		      	chfcoe_dbg(pi, "vn2vn sm port:%d "
				"recv in evt:%d on same luid in state:%d\n", 
				vn2vn->pi->port_num, evt, vn2vn->state);

			/* If both local & remote node luids are not recorded
			 * ones, then retain local luid by sending probe reply 
			 * if local wwpn is higher than remote node.
			 */
			if (evt == CHFCOE_VN2VN_PROBE_REQ_EVT && 
			    !(rcv_parms->fip_flags & PROTO_FIP_FL_REC_OR_P2P) &&
			    (chfcoe_wwn_to_u64(vn2vn->wwpn) > 
			     chfcoe_wwn_to_u64(rcv_parms->wwpn))) {
				chfcoe_vn2vn_send_probe_reply(vn2vn, rcv_parms);
				break;
			}	

			vn2vn->state = CHFCOE_VN2VN_UINIT_STATE;
			chfcoe_schedule_delayed_work(vn2vn->probe_timer,
					PROTO_FIP_PROBE_WAIT);
		      	break;
		}
		break;
	case CHFCOE_VN2VN_CLAIM_STATE:
		if (evt == CHFCOE_VN2VN_PROBE_TMO_EVT) {
			/* Send beacon */
			chfcoe_vn2vn_send_beacon(vn2vn);
			chfcoe_schedule_delayed_work(vn2vn->beacon_timer,
					PROTO_FIP_BEACON_PERIOD);
			vn2vn->state = CHFCOE_VN2VN_READY_STATE;
			chfcoe_vn2vn_up(vn2vn);
			break;
		}

		if (!rcv_parms) {
		      	chfcoe_dbg(pi, "vn2vn sm port:%d invalid vn2vn param "
				"recv in evt:%d in state:%d\n", 
				vn2vn->pi->port_num, evt, vn2vn->state);
			CHFCOE_INC_STATS(vn2vn, ignore_evt);
			break;
		}
		/* Send probe req, when recving P2P claim or P2P beacon 
		   when we are operating in Multi point mode */
		if (rcv_parms->fip_flags & PROTO_FIP_FL_REC_OR_P2P) {
			if (evt == CHFCOE_VN2VN_CLAIM_NOTIFY_EVT ||
				evt == CHFCOE_VN2VN_BEACON_RCV_EVT) {
				chfcoe_vn2vn_send_probe_req(vn2vn);
				break;
			}	
		}

		/* select new luid, if events recv'd on same luids */
		if ((vn2vn->luid == rcv_parms->luid) && 
		     ((evt == CHFCOE_VN2VN_PROBE_REQ_EVT) || 
		     (evt == CHFCOE_VN2VN_CLAIM_NOTIFY_EVT) ||
		     (evt == CHFCOE_VN2VN_BEACON_RCV_EVT))) {
		
		      	chfcoe_dbg(pi, "vn2vn sm port:%d "
				"recv in evt:%d on same luid in state:%d\n", 
				vn2vn->pi->port_num, evt, vn2vn->state);

			/* If probe request recv'd has same luid, then 
			 * retain local luid by sending probe reply 
			 * if local wwpn is higher than remote node.
			 */
			if (evt == CHFCOE_VN2VN_PROBE_REQ_EVT) {
				chfcoe_vn2vn_send_probe_reply(vn2vn, rcv_parms);
				break;
			}	

		     	if (((evt == CHFCOE_VN2VN_CLAIM_NOTIFY_EVT) ||
		     	    (evt == CHFCOE_VN2VN_BEACON_RCV_EVT)) && 
			    (chfcoe_wwn_to_u64(vn2vn->wwpn) > 
			     chfcoe_wwn_to_u64(rcv_parms->wwpn))) {
				chfcoe_vn2vn_send_claim_req(vn2vn);
				break;
			}	
			/* Terminate virtual link */
			//chfcoe_lnode_down(ln);
			vn2vn->state = CHFCOE_VN2VN_UINIT_STATE;
			chfcoe_schedule_delayed_work(vn2vn->probe_timer,
					PROTO_FIP_PROBE_WAIT);
		      	break;
		}
		
		/* if recv claim notification from remote node, 
		 * update rnode entries 
		 * Send claim response to remote node */
		if ((vn2vn->luid != rcv_parms->luid) && 
		     (evt == CHFCOE_VN2VN_CLAIM_NOTIFY_EVT)) {
			chfcoe_vn2vn_send_claim_rsp(vn2vn, rcv_parms);
			chfcoe_vn2vn_update_rnode(vn2vn, rcv_parms);
			break;
		}
		     
		/* if recv claim response from remote node, 
		 * update rnode entries */
		if ((vn2vn->luid != rcv_parms->luid) && 
		     (evt == CHFCOE_VN2VN_CLAIM_RESP_EVT)) {
			chfcoe_vn2vn_update_rnode(vn2vn, rcv_parms);
			break;
		}
		break;

	case CHFCOE_VN2VN_READY_STATE:
		if (evt == CHFCOE_VN2VN_BEACON_TMO_EVT) {
			chfcoe_vn2vn_send_beacon(vn2vn);
			chfcoe_schedule_delayed_work(vn2vn->beacon_timer,
						PROTO_FIP_BEACON_PERIOD);
			break;
		}

		if (!rcv_parms) {
		      	chfcoe_dbg(pi, "vn2vn sm port:%d invalid vn2vn param "
				"recv in evt:%d in state:%d\n", 
				vn2vn->pi->port_num, evt, vn2vn->state);
			CHFCOE_INC_STATS(vn2vn, ignore_evt);
			break;
		}

		/* Send probe req, when recving P2P claim or P2P beacon 
		   when we are operating in Multi point mode */
		if(rcv_parms->fip_flags & PROTO_FIP_FL_REC_OR_P2P) {
			if (evt == CHFCOE_VN2VN_CLAIM_NOTIFY_EVT ||
				evt == CHFCOE_VN2VN_BEACON_RCV_EVT) {
				chfcoe_vn2vn_send_probe_req(vn2vn);
				break;
			}	
		}
		/* select new luid, if events recv'd on same luids */
		if ((vn2vn->luid == rcv_parms->luid) && 
		     ((evt == CHFCOE_VN2VN_PROBE_REQ_EVT) || 
		     (evt == CHFCOE_VN2VN_CLAIM_NOTIFY_EVT) ||
		     (evt == CHFCOE_VN2VN_BEACON_RCV_EVT))) {
		
		      	chfcoe_dbg(pi, "vn2vn sm port:%d "
				"recv in evt:%d on same luid in state:%d\n", 
				vn2vn->pi->port_num, evt, vn2vn->state);

			/* If probe request recv'd has same luid, then 
			 * retain local luid by sending probe reply 
			 * if local wwpn is higher than remote node.
			 */
			if (evt == CHFCOE_VN2VN_PROBE_REQ_EVT) {
				chfcoe_vn2vn_send_probe_reply(vn2vn, rcv_parms);
				break;
			}	

		     	if (((evt == CHFCOE_VN2VN_CLAIM_NOTIFY_EVT) ||
		     	    (evt == CHFCOE_VN2VN_BEACON_RCV_EVT)) && 
			    (chfcoe_wwn_to_u64(vn2vn->wwpn) > 
			     chfcoe_wwn_to_u64(rcv_parms->wwpn))) {
				chfcoe_vn2vn_send_claim_req(vn2vn);
				break;
			}	
			/* Terminate virtual link */
			//chfcoe_lnode_down(ln);
			vn2vn->state = CHFCOE_VN2VN_UINIT_STATE;
			chfcoe_schedule_delayed_work(vn2vn->probe_timer,
					PROTO_FIP_PROBE_WAIT);
		      	break;
		}

		/* if recv claim notification from remote node, 
		 * update rnode entries 
		 * Send claim response to remote node */
		if ((vn2vn->luid != rcv_parms->luid) && 
		     (evt == CHFCOE_VN2VN_CLAIM_NOTIFY_EVT)) {
			chfcoe_vn2vn_send_claim_rsp(vn2vn, rcv_parms);
			chfcoe_vn2vn_update_rnode(vn2vn, rcv_parms);
			break;
		}

		/* If event is BEACON_RCV, send
		   claim response only if rnode doesn't
		   exist */
		break;
	case CHFCOE_VN2VN_OFFLINE_STATE:
		if (evt == CHFCOE_VN2VN_START_EVT || 
				CHFCOE_VN2VN_PROBE_TMO_EVT) {

			unsigned long ts;
			/* Defer sending vn2vn probe till 
			 * stop_tmo interval elapse. Otherwise peer VN doesn't
			 * know if local VN came back online after 
			 * linkdown.
			 */
			ts = os_jiffies();
			if (vn2vn->stop_tmo && 
				os_time_after(vn2vn->stop_tmo, ts)) {
				chfcoe_dbg(pi, "Deferring probe: jiffies %d "
					"stop_tmo %d \n", ts, vn2vn->stop_tmo);
				chfcoe_schedule_delayed_work(vn2vn->probe_timer,
						(vn2vn->stop_tmo - ts));
				vn2vn->stop_tmo = 0;
				break;
			}
			chfcoe_dbg(pi, "sending probe: jiffies %d "
					"stop_tmo %d\n", ts, 
					vn2vn->stop_tmo);
			/* Send 2 probe request */		
			chfcoe_vn2vn_send_probe_req(vn2vn);
			chfcoe_vn2vn_send_probe_req(vn2vn);

			vn2vn->state = CHFCOE_VN2VN_PROBE_STATE;
			chfcoe_schedule_delayed_work(vn2vn->probe_timer,
					PROTO_FIP_ANNONCE_WAIT);
		}
		break;
	default:
		break;
	}
}	

void chfcoe_vn2vn_probe_tmo(void *data)
{
	struct chfcoe_vn2vn *vn2vn = (struct chfcoe_vn2vn *) data;
	struct chfcoe_port_info *pi = vn2vn->pi;

	chfcoe_mutex_lock(pi->mtx_lock);
	chfcoe_vn2vn_state_proc(vn2vn, CHFCOE_VN2VN_PROBE_TMO_EVT, NULL);
	chfcoe_mutex_unlock(pi->mtx_lock);
}

void chfcoe_vn2vn_beacon_tmo(void *data)
{
	struct chfcoe_vn2vn *vn2vn = (struct chfcoe_vn2vn *) data;
	struct chfcoe_port_info *pi = vn2vn->pi;

	chfcoe_mutex_lock(pi->mtx_lock);
	chfcoe_vn2vn_state_proc(vn2vn, CHFCOE_VN2VN_BEACON_TMO_EVT, NULL);
	chfcoe_mutex_unlock(pi->mtx_lock);
}

struct chfcoe_vn2vn *
chfcoe_alloc_vn2vn(struct chfcoe_port_info *pi, uint16_t vlan_id)
{
	struct chfcoe_vn2vn *vn2vn;

	vn2vn = chfcoe_mem_alloc(chfcoe_vn2vn_size);
	if (!vn2vn) {
		chfcoe_err(pi, "port:%d Alloc of vn2vn node failed\n", 
				pi->port_num);
		return NULL;
	}

	vn2vn->probe_timer = CHFCOE_PTR_OFFSET(vn2vn, sizeof(struct chfcoe_vn2vn));
	vn2vn->probe_timer->work = CHFCOE_PTR_OFFSET(vn2vn, sizeof(struct chfcoe_vn2vn)
			+ sizeof(chfcoe_dwork_t));
	vn2vn->beacon_timer = CHFCOE_PTR_OFFSET(vn2vn, sizeof(struct chfcoe_vn2vn) + chfcoe_dwork_size);
	vn2vn->beacon_timer->work = CHFCOE_PTR_OFFSET(vn2vn, sizeof(struct chfcoe_vn2vn)
			+ chfcoe_dwork_size + sizeof(chfcoe_dwork_t));
	/* Update vn2vn fields */
	vn2vn->pi = pi;
	vn2vn->vlan_id = vlan_id;
	vn2vn->ln = chfcoe_lnode_create(vn2vn, CHFCOE_VN2VN, pi);
	if (!vn2vn->ln) {
		chfcoe_err(pi, "Alloc of vn2vn lnode failed \n");
		chfcoe_mem_free(vn2vn);
		return NULL;
	}
	vn2vn->state =  CHFCOE_VN2VN_UINIT_STATE;

	/* Generate luid from last 3 bytes of mac addr */
	vn2vn->luid = chfcoe_ntoh24(&pi->phy_mac[3]) &  LUID_MASK;
	chfcoe_memcpy(vn2vn->wwnn, pi->wwnn, 8);
	chfcoe_memcpy(vn2vn->wwpn, pi->wwpn, 8);
	chfcoe_memcpy(vn2vn->mac, pi->phy_mac, 6);
	proto_fip_vn2vn_set_mac(vn2vn->vn_mac, vn2vn->luid);
	chfcoe_memset(&vn2vn->stats, 0, sizeof(struct chfcoe_vn2vn_stats));

	chfcoe_init_delayed_work(vn2vn->probe_timer, chfcoe_vn2vn_probe_tmo, vn2vn);
	chfcoe_init_delayed_work(vn2vn->beacon_timer, chfcoe_vn2vn_beacon_tmo, vn2vn);

	/* Update the vn2vn list in port info */
	chfcoe_mutex_lock(pi->mtx_lock);
	chfcoe_enq_at_tail(&pi->vn2vn_head, vn2vn);
	pi->num_vn2vn++;
	chfcoe_mutex_unlock(pi->mtx_lock);
	chfcoe_dbg(pi, "port:%d created vn2vn node with luid:%x vlan:%d\n",
			pi->port_num, vn2vn->luid, vlan_id);

	return vn2vn;
} /* chfcoe_alloc_vn2vn */
static void 
chfcoe_process_vn2vn_fip(chfcoe_fc_buffer_t *pld, 
		struct chfcoe_vn2vn_parms *rcv_parms)
{
	struct proto_ethhdr_novlan *eh = (struct proto_ethhdr_novlan *) 
					chfcoe_fc_data_ptr(pld);
	struct proto_fip_header *fip_hdr = (struct proto_fip_header *) (eh + 1);
	uint16_t desc_len	= chfcoe_ntohs(fip_hdr->fip_dl_len);
	uint32_t len = 0;	
	struct proto_fip_desc *desc = (struct proto_fip_desc *) (fip_hdr + 1);
	struct proto_fip_mac_desc *mac_desc;
	struct proto_fip_wwn_desc *wwn_desc;
	struct proto_fip_vn_desc *vn_desc;
	struct proto_fip_size_desc *size_desc;

	rcv_parms->fip_flags = chfcoe_ntohs(fip_hdr->fip_flags);
	while (len < desc_len) {
		switch (desc->fip_dtype) {
		case PROTO_FIP_DT_MAC:
			mac_desc = (struct proto_fip_mac_desc *)desc;
			chfcoe_memcpy(rcv_parms->mac, mac_desc->fd_mac, 6);
			break;

		case PROTO_FIP_DT_NAME:
			wwn_desc = (struct proto_fip_wwn_desc *)desc;
			chfcoe_memcpy(rcv_parms->wwnn, &wwn_desc->fd_wwn, 6);
			break;

		case PROTO_FIP_DT_VN_ID:
			vn_desc = (struct proto_fip_vn_desc *) desc;
			chfcoe_memcpy(rcv_parms->vn_mac, &vn_desc->fd_mac, 6);
			chfcoe_memcpy(rcv_parms->wwpn, &vn_desc->fd_wwpn, 8);
			rcv_parms->luid = chfcoe_ntoh24(vn_desc->fd_fc_id);
			break;
		case PROTO_FIP_DT_FCOE_SIZE:
			size_desc = (struct proto_fip_size_desc *) desc;
			rcv_parms->max_fcoe_sz = chfcoe_htons(size_desc->fd_size);
			break;
		default:
			break;
		}
		len += desc->fip_dlen;
		desc = (void *) desc + (desc->fip_dlen * 4);
	}
}


void
chfcoe_recv_vn2vn_fip(struct chfcoe_adap_info *adap, uint16_t fip_subop,
		uint8_t port_num, chfcoe_fc_buffer_t *pld, uint32_t vlan)
{
	enum vn2vn_evt evt;
	struct chfcoe_port_info *pi  	= CHFCOE_PTR_OFFSET(adap->pi, (port_num * chfcoe_port_info_size));
	struct chfcoe_vn2vn *vn2vn;
	struct chfcoe_vn2vn_parms rcv_parms;

	chfcoe_process_vn2vn_fip(pld, &rcv_parms);

	switch (fip_subop) {
	case PROTO_FIP_SC_VN_PROBE_REQ:
		evt = CHFCOE_VN2VN_PROBE_REQ_EVT;
		break;
	case PROTO_FIP_SC_VN_PROBE_REP:
		evt = CHFCOE_VN2VN_PROBE_REP_EVT;
		break;
	case PROTO_FIP_SC_VN_CLAIM_NOTIFY:
		evt = CHFCOE_VN2VN_CLAIM_NOTIFY_EVT;
		break;
	case PROTO_FIP_SC_VN_CLAIM_REP:
		evt = CHFCOE_VN2VN_CLAIM_RESP_EVT;
		break;
	case PROTO_FIP_SC_VN_BEACON:
		evt = CHFCOE_VN2VN_BEACON_RCV_EVT;
		break;
	default:
		chfcoe_err(pi, "port:%d Invalid vn2vn fip_subop 0x%x\n", 
				pi->port_num, fip_subop);
		return;
	}

	/* locate vn2vn based on vlan and instantiate new vn2vn if
	 * not found */
	vn2vn = chfcoe_get_vn2vn(pi, NULL, vlan);
	if (!vn2vn) {
		return;
	}

	chfcoe_mutex_lock(pi->mtx_lock);
	/* enter the vn2vn state machine */
	chfcoe_vn2vn_state_proc(vn2vn, evt, &rcv_parms);
	chfcoe_mutex_unlock(pi->mtx_lock);
}

struct chfcoe_vn2vn *
chfcoe_get_vn2vn(struct chfcoe_port_info *pi, uint8_t *mac, uint16_t vlan_id)
{
        struct chfcoe_list	*tmp;
	struct chfcoe_vn2vn 	*vn2vn;

	chfcoe_mutex_lock(pi->mtx_lock);
	if (!pi->num_vn2vn) {
		chfcoe_mutex_unlock(pi->mtx_lock);
		return NULL;
	}

	chfcoe_list_for_each(tmp, &pi->vn2vn_head) {
		vn2vn  = (struct chfcoe_vn2vn *) tmp;
		if (mac && !chfcoe_memcmp(vn2vn->mac, mac, 6)) {
			if (vn2vn->vlan_id == vlan_id) {
				chfcoe_mutex_unlock(pi->mtx_lock);
				return vn2vn;
			}
		}
		else {
			if (vn2vn->vlan_id == vlan_id) {
				chfcoe_mutex_unlock(pi->mtx_lock);
				return vn2vn;
			}
		}	
	}
	chfcoe_dbg(pi, "port:%x Could not find vn2vn vlan:%d\n", 
			pi->port_num, vlan_id);
	chfcoe_mutex_unlock(pi->mtx_lock);
	return NULL;
} /* chfcoe_get_vn2vn */

struct chfcoe_vn2vn *
chfcoe_get_vn2vn_vnmac(struct chfcoe_port_info *pi, uint8_t *mac, 
		uint16_t vlan_id)
{
        struct chfcoe_list	*tmp;
	struct chfcoe_vn2vn 	*vn2vn;

	chfcoe_mutex_lock(pi->mtx_lock);
	if (!pi->num_vn2vn) {
		chfcoe_mutex_unlock(pi->mtx_lock);
		return NULL;
	}

	chfcoe_list_for_each(tmp, &pi->vn2vn_head) {
		vn2vn  = (struct chfcoe_vn2vn *) tmp;
		if (!chfcoe_memcmp(vn2vn->vn_mac, mac, 6)) {
			if (vn2vn->vlan_id == vlan_id) {
				chfcoe_mutex_unlock(pi->mtx_lock);
				return vn2vn;
			}
		}
	}
	chfcoe_dbg(pi, "port:%x Could not find vn2vn vnmac vlan:%d\n", 
			pi->port_num, vlan_id);
	chfcoe_mutex_unlock(pi->mtx_lock);
	return NULL;
} /* chfcoe_get_vn2vn */

chfcoe_retval_t
chfcoe_start_vn2vn(struct chfcoe_port_info *pi)
{
	struct chfcoe_list *tmp;
	struct chfcoe_vn2vn *vn2vn;

	chfcoe_mutex_lock(pi->mtx_lock);
	/* Send start evt on all local vn2vn nodes */
        chfcoe_list_for_each(tmp, &pi->vn2vn_head) {
		vn2vn  = (struct chfcoe_vn2vn *) tmp;
		chfcoe_vn2vn_state_proc(vn2vn, CHFCOE_VN2VN_START_EVT, NULL);
	}
	chfcoe_mutex_unlock(pi->mtx_lock);
	return CHFCOE_SUCCESS;
}

chfcoe_retval_t
chfcoe_stop_vn2vn(struct chfcoe_port_info *pi)
{
	struct chfcoe_list *tmp;
	struct chfcoe_vn2vn *vn2vn;

	chfcoe_mutex_lock(pi->mtx_lock);
	/* Send stop evt on all local vn2vn nodes */
        chfcoe_list_for_each(tmp, &pi->vn2vn_head) {
		vn2vn  = (struct chfcoe_vn2vn *) tmp;
		vn2vn->stop_tmo = os_jiffies() + PROTO_FIP_BEACON_PERIOD * 3;
		chfcoe_dbg(pi, "stop_vn2vn: jiffies %d stop_tmo %d\n",
			os_jiffies(), vn2vn->stop_tmo);
		chfcoe_vn2vn_state_proc(vn2vn, CHFCOE_VN2VN_STOP_EVT, NULL);
		chfcoe_cancel_delayed_work_sync(vn2vn->probe_timer);	
		chfcoe_cancel_delayed_work_sync(vn2vn->beacon_timer);
	}
	chfcoe_mutex_unlock(pi->mtx_lock);
	return CHFCOE_SUCCESS;
}

chfcoe_retval_t
chfcoe_vn2vn_init(struct chfcoe_port_info *pi)
{
	chfcoe_head_init(&pi->vn2vn_head);
	/* Allocate vn2vn instance */
	if (chfcoe_alloc_vn2vn(pi, chfcoe_vlanid))
		return CHFCOE_SUCCESS;

	return CHFCOE_NOMEM;
}	

chfcoe_retval_t
chfcoe_vn2vn_exit(struct chfcoe_port_info *pi)
{
	struct chfcoe_vn2vn *vn2vn = NULL;
	while (!chfcoe_list_empty(&pi->vn2vn_head)) {
		chfcoe_deq_from_head(&pi->vn2vn_head, &vn2vn);
		if (vn2vn->ln)
			chfcoe_lnode_destroy(vn2vn->ln);
		chfcoe_mem_free(vn2vn);
		CHFCOE_DEC_STATS(pi, n_vn2vn);
		pi->num_vn2vn--;
	}	
	return CHFCOE_SUCCESS;
}
