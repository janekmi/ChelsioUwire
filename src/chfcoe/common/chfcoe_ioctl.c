/*
 *  Copyright (C) 2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include "chfcoe_lnode.h"
#include "chfcoe_rnode.h"
#include "chfcoe_proto.h"
#include "chfcoe_defs.h"
#include <t4fw_interface.h>
#include <csio_stor_ioctl.h>
#include <csio_fcoe_ioctl.h>
#include <csio_t4_ioctl.h>

static chfcoe_fcf_t *chfcoe_get_next_fcf(struct chfcoe_adap_info *adap, 
		uint32_t fcfi)
{
	chfcoe_port_info_t *pi = adap->pi;
	chfcoe_fcf_t *fcf;
	struct chfcoe_list *next, *start;
	int i, pidx, port;
	uint16_t vlanid;

	chfcoe_dbg(adap, "%s: fcfi 0x%x\n", __func__, fcfi);
	if (fcfi == CHFCOE_INVALID_IDX) {
		pidx = 0;
nextfcf:
		for (i=pidx; i<adap->nports; i++) {
			pi = CHFCOE_PTR_OFFSET(adap->pi, 
					(i * chfcoe_port_info_size));
			if (chfcoe_list_empty(&pi->fcf_head))
				continue;

			fcf = (chfcoe_fcf_t *) chfcoe_list_next(&pi->fcf_head);
			chfcoe_dbg(adap, "found fcf: port %d\n", fcf->port_num);
			return fcf;
		}

		return NULL;
	}
		
	port = fcfi & 0xf;
	vlanid = fcfi >> 4;
	pi = CHFCOE_PTR_OFFSET(adap->pi, port * chfcoe_port_info_size);
	chfcoe_list_for_each_safe(start, next, &pi->fcf_head) {
		fcf = (chfcoe_fcf_t *)start;
		if (fcf->vlan_id == vlanid) {
			if (next != &pi->fcf_head)
				return (chfcoe_fcf_t *)next;
			pidx = ++port;
			goto nextfcf;
		}
	}

	return NULL;
}

static int chfcoe_get_fcf_info(struct chfcoe_adap_info *adap, void *buffer,
                uint32_t buffer_len)
{
	csio_fcf_info_t *fcf_info = buffer;
	chfcoe_fcf_t *fcf = NULL;
	struct fw_fcoe_fcf_stats  *fcfstats;
	chfcoe_fcf_stats_t *fstats;
	chfcoe_port_stats_t *pstats;

	if (buffer_len < sizeof(*fcf_info))
		return -CHFCOE_NOMEM;

	if (adap == NULL) {
		chfcoe_err(adap, "adap is NULL\n");
		return -CHFCOE_INVAL;
	}

	if (fcf_info == NULL)
		return -CHFCOE_INVAL;

	fcf = chfcoe_get_next_fcf(adap, fcf_info->fcfi);
	if (!fcf) {
		fcf_info->fcfi = CHFCOE_INVALID_IDX;
		return 0;
	}

	pstats = &fcf->pi->stats;
	fcf_info->priority      = fcf->fcf_prio;
	fcf_info->vf_id         = fcf->vf_id;
	fcf_info->vlan_id       = fcf->vlan_id;
	fcf_info->max_fcoe_size = fcf->max_fcoe_size;
	fcf_info->fka_adv       = fcf->fka_adv_prd / 1000;
	fcf_info->fpma          = 1;
	fcf_info->spma          = 0;
	fcf_info->portid        = fcf->port_num;
	fcf_info->fcfi          = fcf->port_num | fcf->vlan_id << 4;

	chfcoe_memcpy(&fcf_info->mac, &fcf->fcf_mac, 6);
	chfcoe_memcpy(&fcf_info->fc_map, &fcf->fc_map, 3);
	chfcoe_memcpy(&fcf_info->name_id, &fcf->fab_wwn, 8);
	chfcoe_memcpy(&fcf_info->fabric, &fcf->fab_wwn, 8);

	fstats = &fcf->stats;
	fcfstats = &fcf_info->fcf_stats;
	fcfstats->fip_tx_bytes = fstats->n_fip_tx_bytes;
	fcfstats->fip_tx_fr = fstats->n_fip_tx_fr;
	fcfstats->fcf_ka = fstats->n_fcf_ka_sent;
	fcfstats->mcast_adv_rcvd = fstats->n_fcf_mcast_adv_rcvd;
	fcfstats->ucast_adv_rcvd = fstats->n_fcf_ucast_adv_rcvd;
	fcfstats->sol_sent = fstats->n_sol_sent;
	fcfstats->vlan_req = fstats->n_vlan_req;
	fcfstats->vlan_rpl = fstats->n_vlan_rpl;
	fcfstats->clr_vlink = fstats->n_clr_vlink;
	fcfstats->link_down = 0;
	fcfstats->link_up  = 0;
	fcfstats->logo = fstats->n_logo;
	fcfstats->flogi_req = fstats->n_flogi_req;
	fcfstats->flogi_rpl = fstats->n_flogi_rpl;
	fcfstats->fdisc_req = fstats->n_fdisc_req;
	fcfstats->fdisc_rpl = fstats->n_fdisc_rpl;
	fcfstats->fka_prd_chg = fstats->n_adv_prd_chg;
	fcfstats->fc_map_chg = fstats->n_fc_map_chg;
	fcfstats->vfid_chg = fstats->n_vf_id_chg;
	fcfstats->no_fka_req = fstats->n_fka_not_req;
	fcfstats->no_vnp = fstats->n_out_of_vnp;

	return CHFCOE_SUCCESS;
}

static chfcoe_retval_t chfcoe_get_port_info(struct chfcoe_adap_info *adap,
		void *buffer, uint32_t buffer_len)
{
	chfcoe_port_info_t *pi = adap->pi;
	csio_port_info_t *port_info = buffer;
	struct fw_fcoe_port_stats  *portstats = &port_info->port_stats;
	chfcoe_port_stats_t *pstats;

	chfcoe_dbg(adap, "%s: portid %d\n", __func__, port_info->portid);
	if (buffer_len < sizeof(csio_port_info_t))
		return -CHFCOE_NOMEM;

	if (port_info->portid >= adap->nports)
		return -CHFCOE_INVAL;

	pi = CHFCOE_PTR_OFFSET(adap->pi, (port_info->portid * 
				chfcoe_port_info_size));
	pstats = &pi->stats;
	portstats->tx_ucast_frames = pstats->n_fcoe_tx_fr + pstats->n_fip_tx_fr;
	portstats->rx_ucast_frames = pstats->n_fcoe_rx_fr + pstats->n_fip_rx_fr
						+ pstats->n_unknown_fr;
	portstats->rx_err_frames = pstats->n_unknown_fr + pstats->n_fip_drop;

	return CHFCOE_SUCCESS;
}

static struct chfcoe_lnode *chfcoe_get_next_lnode_by_handle(
		struct chfcoe_adap_info *adap, uint64_t handle)
{
	chfcoe_port_info_t *pi = adap->pi;
	struct chfcoe_lnode *lnode;
	struct chfcoe_lnode *hdl_lnode = (struct chfcoe_lnode *)handle;
	struct chfcoe_list *next, *start;
	int i, lidx;

	chfcoe_dbg(adap, "%s: handle 0x%x\n", __func__, (uint32_t)handle);

	if (!handle) {
		lidx = 0;
nextlnode:
		for (i=lidx; i<adap->nports; i++) {
			pi = CHFCOE_PTR_OFFSET(adap->pi, (i * chfcoe_port_info_size));

			if (chfcoe_list_empty(&pi->ln_head)) {
				lnode = pi->root_ln;
				if(lnode != NULL) {
					chfcoe_dbg(adap, "found lnode: nport id 0x%x\n", 
						lnode->nport_id);
					return lnode;
				} else {
					continue;
				}
			}

			lnode = (struct chfcoe_lnode *)chfcoe_list_next(&pi->ln_head);
			chfcoe_dbg(adap, "found lnode: nport id 0x%x\n", 
					lnode->nport_id);

			return lnode;
		}

		return NULL;
	}
		
	for (i= hdl_lnode->port_num; i<adap->nports; i++) {
		pi = CHFCOE_PTR_OFFSET(adap->pi, (i * chfcoe_port_info_size));

		if (chfcoe_list_empty(&pi->ln_head)) {

			if(i <= hdl_lnode->port_num) {
				continue;
			} else {
				lidx = i;
				goto nextlnode;
			}
		}

		chfcoe_list_for_each_safe(start, next, &pi->ln_head) {
			if (handle == (uint64_t)start) { 
				if (next != &pi->ln_head) {
					lnode = (struct chfcoe_lnode *)next;
					chfcoe_dbg(pi, "found lnode: nport id"
							" 0x%x\n", 
							lnode->nport_id);
					return lnode;
				}

				lidx = i + 1;
				goto nextlnode;
			}
		}
	}

	return NULL;
}

static struct chfcoe_lnode *chfcoe_get_lnode_by_id(
		struct chfcoe_adap_info *adap, uint32_t id)
{
	chfcoe_port_info_t *pi = adap->pi;
	struct chfcoe_list *entry, *tmp;
	struct chfcoe_lnode *lnode;
	int i;

	for (i=0; i<adap->nports; i++) {
		pi = CHFCOE_PTR_OFFSET(adap->pi, (i * chfcoe_port_info_size));
		chfcoe_list_for_each_safe(entry, tmp, &pi->ln_head) {
			lnode = (struct chfcoe_lnode *)entry;
			if (lnode->nport_id == id)
				return lnode;
		}
	}

	return NULL;
}

static struct chfcoe_lnode *chfcoe_get_lnode_by_wwpn(
		struct chfcoe_adap_info *adap, uint8_t *wwpn)
{
	chfcoe_port_info_t *pi = adap->pi;
	struct chfcoe_list *entry, *tmp;
	struct chfcoe_lnode *lnode;
	int i;

	for (i=0; i<adap->nports; i++) {
		pi = CHFCOE_PTR_OFFSET(adap->pi, (i * chfcoe_port_info_size));
		chfcoe_list_for_each_safe(entry, tmp, &pi->ln_head) {
			lnode = (struct chfcoe_lnode *)entry;
			if (!chfcoe_memcmp(lnode->wwpn, wwpn, 8))
				return lnode;
		}
	}

	return NULL;
}

static void chfcoe_copy_lnode_stats(csio_fcoe_lnode_t *lnf_info,
		chfcoe_lnode_stats_t *lnode_stats)
{
	csio_lnode_fcoestats_t *lnfinfo_stats = &lnf_info->stats;

	lnfinfo_stats->n_link_up        = lnode_stats->n_link_up;
	lnfinfo_stats->n_link_down      = lnode_stats->n_link_down;
	lnfinfo_stats->n_err            = lnode_stats->n_err;
	lnfinfo_stats->n_err_nomem      = lnode_stats->n_err_nomem;
	lnfinfo_stats->n_inval_parm     = lnode_stats->n_inval_parm;
	lnfinfo_stats->n_evt_unexp      = 0;
	lnfinfo_stats->n_evt_drop       = 0;
	lnfinfo_stats->n_rnode_match    = lnode_stats->n_rnode_match;
	lnfinfo_stats->n_dev_loss_tmo   = lnode_stats->n_dev_loss_tmo;
	lnfinfo_stats->n_fdmi_err       = lnode_stats->n_fdmi_err;

	return;
}

static inline void chfcoe_ntoh_sp(struct csio_service_parms *lnsp, 
		struct csio_service_parms *sp)
{
	struct csio_cmn_sp *csp, *lcsp;
	struct csio_class_sp *cp, *lcp;

	chfcoe_memset(sp, 0, sizeof(struct csio_service_parms));
	csp = &sp->csp;
	lcsp = &lnsp->csp;
	csp->bb_credit  = chfcoe_ntohs(lcsp->bb_credit);
	csp->word1_flags = chfcoe_ntohs(lcsp->word1_flags);
	csp->sp_tot_seq  = chfcoe_ntohs(lcsp->sp_tot_seq);    /* seq. we accept */
	csp->sp_rel_off  = chfcoe_ntohs(lcsp->sp_rel_off);
	csp->e_d_tov  = chfcoe_ntohl(lcsp->e_d_tov);
	csp->rcv_sz  = chfcoe_ntohs(lcsp->rcv_sz);

	cp = &sp->clsp[2];
	lcp = &lnsp->clsp[2];
	cp->serv_option = lcp->serv_option;
	cp->rcv_data_sz = chfcoe_ntohs(lcp->rcv_data_sz);
	cp->concurrent_seq  = chfcoe_ntohs(lcp->concurrent_seq);
	cp->openseq_per_xchg = chfcoe_ntohs(lcp->openseq_per_xchg);

}

static void chfcoe_lnode_stateto_str(struct chfcoe_lnode *lnode, char *state)
{
	if (lnode->state >= CHFCOE_LN_ST_UNINIT && 
			lnode->state <= CHFCOE_LN_ST_NS)
		os_strcpy(state, chfcoe_lnode_state_str[lnode->state]);
	else
		os_strcpy(state, chfcoe_lnode_state_str[0]);
}

static void chfcoe_copy_lnode_info(csio_fcoe_lnode_t *lnf_info, 
		struct chfcoe_lnode *lnode)
{
	struct csio_service_parms sp;

	lnf_info->portid        = lnode->pi->port_num;
	lnf_info->dev_num       = lnode->dev_num;
	lnf_info->vnp_flowid    = lnode->nport_id;
	lnf_info->fcf_flowid    = 0;
	lnf_info->nport_id      = lnode->nport_id;

	lnf_info->is_vport      = 0;
	lnf_info->num_vports    = 0;

	chfcoe_memcpy(lnf_info->mac, lnode->fcoe_mac, 6);

	lnf_info->num_reg_rnodes= chfcoe_rn_count(lnode);
	lnf_info->flags         = lnode->flags;

	/* Set the handle for this lnodeinfo */
	lnf_info->opq_handle    = (uintptr_t)lnode;

	chfcoe_ntoh_sp(&lnode->sp, &sp);
	chfcoe_memcpy(sp.wwpn, lnode->wwpn, 8);
	chfcoe_memcpy(sp.wwnn, lnode->wwnn, 8);
	chfcoe_memcpy(&lnf_info->ln_sparm, &sp,
			sizeof(struct csio_service_parms));

	chfcoe_copy_lnode_stats(lnf_info, &lnode->lnode_stats);

	chfcoe_lnode_stateto_str(lnode, lnf_info->state);

	/* Events */
	lnf_info->max_lnf_events= 0;
	lnf_info->cur_evt       = 0;
	lnf_info->prev_evt      = 0;

	return;
}

static void chfcoe_copy_rnode_stats(csio_fcoe_rnode_t *rnf_info, 
		chfcoe_rnode_stats_t *rn_stats)
{
	csio_rnode_stats_t *rninfo_stats = &rnf_info->rnode_stats;

	rninfo_stats->n_lun_rst         = rn_stats->n_lun_rst;
	rninfo_stats->n_lun_rst_fail    = rn_stats->n_lun_rst_fail;
	rninfo_stats->n_tgt_rst         = rn_stats->n_tgt_rst;
	rninfo_stats->n_tgt_rst_fail    = rn_stats->n_tgt_rst_fail;

	return;
}

static void chfcoe_copy_rnf_stats(csio_fcoe_rnode_t *rnf_info,
		chfcoe_rnode_stats_t *rnf_stats __attribute__((unused)))
{
	csio_rnode_fcoestats_t *rnfinfo_stats = &rnf_info->rnf_stats;

	rnfinfo_stats->n_err 		= 0;
	rnfinfo_stats->n_err_inval 	= 0;
	rnfinfo_stats->n_err_nomem 	= 0;
	rnfinfo_stats->n_evt_unexp 	= 0;
	rnfinfo_stats->n_evt_drop 	= 0;

	return;
}

static void chfcoe_rnode_stateto_str(struct chfcoe_rnode *rnode, char *state)
{
	if (rnode->state > CHFCOE_RN_ST_SCR)
		os_strcpy(state, "UNKNOWN");
	else
		os_strcpy(state, chfcoe_rnode_state_str[rnode->state]);
}

static void chfcoe_copy_rnode_info(csio_fcoe_rnode_t *rnf_info, 
		struct chfcoe_lnode *lnode, struct chfcoe_rnode *rnode)
{
	struct csio_service_parms *sp;
	struct csio_cmn_sp *csp;
	struct csio_class_sp *clsp;

	rnf_info->ssn_flowid    = rnode->nport_id;
	rnf_info->vnp_flowid    = lnode->nport_id;
	rnf_info->nport_id      = rnode->nport_id;
	rnf_info->fcp_flags     = rnode->fcp_flags;

	if (rnode->mode & PROTO_FCP_SPPF_INIT_FCN &&
			rnode->mode & PROTO_FCP_SPPF_TARG_FCN)
		os_strcpy(rnf_info->role, "Initiator & Target");
	else if (rnode->mode & PROTO_FCP_SPPF_INIT_FCN)
		os_strcpy(rnf_info->role, "Initiator");
	else if (rnode->mode & PROTO_FCP_SPPF_TARG_FCN)
		os_strcpy(rnf_info->role, "Target");
	else if (rnode->nport_id == PROTO_FC_FID_FLOGI)
		os_strcpy(rnf_info->role, "Fabric");
	else if (rnode->nport_id == PROTO_FC_FID_DIR_SERV)
		os_strcpy(rnf_info->role, "Name-Server");
	else
		os_strcpy(rnf_info->role, "N-Port");

	chfcoe_memcpy(&rnf_info->rn_sparm, &rnode->sp,
			sizeof(struct csio_service_parms));
	sp = &rnf_info->rn_sparm;
	chfcoe_memset(sp, 0, sizeof(struct csio_service_parms));
	chfcoe_memcpy(sp->wwpn, rnode->wwpn, 8);
	chfcoe_memcpy(sp->wwnn, rnode->wwnn, 8);
	csp = &sp->csp;
	clsp = &sp->clsp[2];    /* only class-3 supported */

	csp->e_d_tov  = rnode->e_d_tov;
	csp->rcv_sz  = rnode->max_pldlen;

	clsp->serv_option = PROTO_FC_CPC_VALID >> 8;
	if (G_SP_CLASS_SUPPORT(clsp->serv_option)) {
		chfcoe_dbg(rnode, "Class 3 supported\n");
	}
	clsp->rcv_data_sz = rnode->max_pldlen;
	clsp->concurrent_seq  = rnode->max_seq;

	chfcoe_copy_rnode_stats(rnf_info, &rnode->stats);
	chfcoe_copy_rnf_stats(rnf_info, &rnode->stats);

	chfcoe_rnode_stateto_str(rnode, rnf_info->state);

	/* Events */
	rnf_info->max_rnf_events= 0;
	rnf_info->cur_evt       = 0;
	rnf_info->prev_evt      = 0;

	return;
}

static chfcoe_retval_t chfcoe_get_lnode_info(struct chfcoe_adap_info *adap,
	       void *buffer, uint32_t buffer_len)
{
	csio_fcoe_lnode_t *lnf_info = buffer;
	struct chfcoe_lnode *lnode;

	if (buffer_len < sizeof(csio_fcoe_lnode_t))
		return -CHFCOE_NOMEM;

	lnode = chfcoe_get_next_lnode_by_handle(adap, lnf_info->opq_handle);
	if (!lnode) {
		lnf_info->opq_handle = 0;
		return 0;
	}

	chfcoe_copy_lnode_info(lnf_info, lnode);

	return CHFCOE_SUCCESS;
}

static chfcoe_retval_t chfcoe_get_lnode_info_by_fcid(
		struct chfcoe_adap_info *adap, void *buffer, 
		uint32_t buffer_len)
{
	csio_fcoe_lnode_t *lnf_info = buffer;
	struct chfcoe_lnode *lnode;

	if (buffer_len < sizeof(csio_fcoe_lnode_t))
		return -CHFCOE_NOMEM;

	if (lnf_info->nport_id) {
		lnode = chfcoe_get_lnode_by_id(adap, lnf_info->nport_id);
	} else if (lnf_info->vnp_flowid) {
		lnode = chfcoe_get_lnode_by_id(adap, lnf_info->vnp_flowid);
	} else if (chfcoe_wwn_to_u64(lnf_info->ln_sparm.wwpn) != 0) {
		lnode = chfcoe_get_lnode_by_wwpn(adap, lnf_info->ln_sparm.wwpn);
	} else if (chfcoe_wwn_to_u64(lnf_info->ln_sparm.wwnn) != 0) {
		return -CHFCOE_NOSUPP;
	} else {
		chfcoe_err(adap, "lnode_by_fcid: no search type found\n");
		return -CHFCOE_INVAL;
	}

	if (!lnode)
		return -CHFCOE_INVAL;

	chfcoe_copy_lnode_info(lnf_info, lnode);

	return CHFCOE_SUCCESS;
}

static struct chfcoe_rnode *chfcoe_get_rnode_by_wwpn(
		struct chfcoe_lnode *lnode, uint8_t *wwpn)
{
	struct chfcoe_rnode *rnhead = (struct chfcoe_rnode *)&lnode->rn_head;
	struct chfcoe_rnode *rnode = NULL;
	struct chfcoe_list *entry;

	chfcoe_read_lock_bh(lnode->rn_lock);
	chfcoe_list_for_each(entry, &rnhead->rnlist) {
		rnode = (struct chfcoe_rnode *)entry;

		if (!chfcoe_memcmp(rnode->wwpn, wwpn, 8))
			break;
		else
			rnode = NULL;

	}
	chfcoe_read_unlock_bh(lnode->rn_lock);

	return rnode;
}

static chfcoe_retval_t chfcoe_get_rnode_info_by_fcid(
		struct chfcoe_adap_info *adap, 
		void *buffer, uint32_t buffer_len)
{
	csio_fcoe_rnode_t *rnf_info = buffer;
	struct chfcoe_lnode *lnode;
	struct chfcoe_rnode *rnode;

	if (buffer_len < sizeof(csio_fcoe_rnode_t))
		return -CHFCOE_NOMEM;

	lnode = chfcoe_get_lnode_by_id(adap, rnf_info->vnp_flowid);
	if (!lnode)
		return -CHFCOE_INVAL;

	if (rnf_info->nport_id) {
		rnode = chfcoe_rn_lookup_portid(lnode, rnf_info->nport_id);
	} else if (rnf_info->ssn_flowid) {
		return -CHFCOE_NOSUPP;
	} else if (chfcoe_wwn_to_u64(rnf_info->rn_sparm.wwpn) != 0) {
		rnode = chfcoe_get_rnode_by_wwpn(lnode, rnf_info->rn_sparm.wwpn);
	} else if (chfcoe_wwn_to_u64(rnf_info->rn_sparm.wwnn) != 0) {
		return -CHFCOE_NOSUPP;
	} else {
		chfcoe_err(adap, "rnode_by_fcid: no search type found\n");
		return -CHFCOE_INVAL;
	}

	if (!rnode)
		return -CHFCOE_INVAL;

	chfcoe_copy_rnode_info(rnf_info, lnode, rnode);

	return CHFCOE_SUCCESS;
}

static struct chfcoe_rnode *chfcoe_get_next_rnode(struct chfcoe_lnode *lnode,
		uint32_t id)
{
	struct chfcoe_rnode *rnhead = (struct chfcoe_rnode *)&lnode->rn_head;
	struct chfcoe_rnode *rnode = NULL;
	struct chfcoe_list *entry, *next;

	chfcoe_read_lock_bh(lnode->rn_lock);
	chfcoe_list_for_each_safe(entry, next, &rnhead->rnlist) {
		rnode = (struct chfcoe_rnode *)entry;
		if (id == CHFCOE_INVALID_IDX)
			break;

		if (rnode->nport_id == id && next != &rnhead->rnlist) {
			rnode = (struct chfcoe_rnode *)next;
			break;
		} else
			rnode = NULL;
	}
	chfcoe_read_unlock_bh(lnode->rn_lock);

	return rnode;
}

static chfcoe_retval_t chfcoe_get_rnode_info(struct chfcoe_adap_info *adap,
		void *buffer, uint32_t buffer_len)
{	
	csio_fcoe_rnode_t *rnf_info = buffer;
	struct chfcoe_lnode *lnode;
	struct chfcoe_rnode *rnode;

	if (buffer_len < sizeof(csio_fcoe_rnode_t))
		return -CHFCOE_NOMEM;

	/* vnp_flowid is set to n-port id */
	lnode = chfcoe_get_lnode_by_id(adap, rnf_info->vnp_flowid);
	if (!lnode)
		return -CHFCOE_INVAL;

	rnode = chfcoe_get_next_rnode(lnode, rnf_info->ssn_flowid);
	if (!rnode)
		return -CHFCOE_INVAL;

	chfcoe_copy_rnode_info(rnf_info, lnode, rnode);

	return CHFCOE_SUCCESS;
}

static chfcoe_retval_t chfcoe_get_stats(struct chfcoe_adap_info *adap __attribute__((unused)),
		void *buffer __attribute__((unused)),
	       	uint32_t buffer_len __attribute__((unused)))
{
	return -CHFCOE_NOSUPP;
}

/*
 * chfcoe_fcoe_ioctl_handler - Chelsio POFCoE IOCTL handler
 * @adap - Adapter Information
 * @opcode - FCoE IOCTL opcode
 */
chfcoe_retval_t chfcoe_fcoe_ioctl_handler(struct chfcoe_adap_info *adap, 
		uint32_t opcode, void *buffer, uint32_t buffer_len)
{
	chfcoe_retval_t rv = CHFCOE_SUCCESS;

	switch (opcode) {
	case CSIO_FCOE_GET_FCF_INFO:
		rv = chfcoe_get_fcf_info(adap, buffer, buffer_len);
		break;

	case CSIO_FCOE_GET_PORT_INFO:
		rv = chfcoe_get_port_info(adap, buffer, buffer_len);
		break;

	case CSIO_FCOE_GET_LNODE_INFO:
		rv = chfcoe_get_lnode_info(adap, buffer, buffer_len);
		break;

	case CSIO_FCOE_GET_LNODE_INFO_BY_FCID:
		rv = chfcoe_get_lnode_info_by_fcid(adap, buffer, buffer_len);
		break;

	case CSIO_FCOE_GET_RNODE_INFO:
		rv = chfcoe_get_rnode_info(adap, buffer, buffer_len);
		break;

	case CSIO_FCOE_GET_RNODE_INFO_BY_FCID:
		rv = chfcoe_get_rnode_info_by_fcid(adap, buffer, buffer_len);
		break;

	case CSIO_FCOE_GET_STATS:
		rv = chfcoe_get_stats(adap, buffer, buffer_len);
		break;

	default:
		rv = -CHFCOE_NOSUPP;
		break;
	} /* switch */

	return rv;
}

static int chfcoe_copy_adap_info(struct chfcoe_adap_info *adap,
		void *buffer, uint32_t buffer_len)
{
	csio_adapter_info_t *info = buffer;

	if (buffer_len < sizeof(csio_adapter_info_t))
		return -CHFCOE_NOMEM;

	chfcoe_memset(info, 0, sizeof(csio_adapter_info_t));
	info->adapter_handle = (uintptr_t)adap;

	return CHFCOE_SUCCESS;
}

/*
 *  * chfcoe_adap_ioctl_handler - Partial Offload FCoE IOCTL handler
 *   * @adap - Adapter information structure
 *    * @opcode - IOCTL opcode
 *     */
chfcoe_retval_t chfcoe_adap_ioctl_handler(struct chfcoe_adap_info *adap, 
		uint32_t opcode, void *buffer, uint32_t buffer_len)
{
	chfcoe_retval_t rv = CHFCOE_SUCCESS;

	switch (opcode) {
	case CSIO_HW_PROBE:
		rv = chfcoe_copy_adap_info(adap, buffer, buffer_len);
		break;
	
	default:
		return -CHFCOE_NOSUPP;
	}

	return rv;
} /* chfcoe_adap_ioctl_handler */

