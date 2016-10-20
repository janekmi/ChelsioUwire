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
 * 	This chfcoe_fip.c file contains fcoe fip implementation
 *
 * Authors:
 * 	Deepti Vadde <deepti@chelsio.com>
 */

#include "chfcoe_fcf.h"
#include "chfcoe_lnode.h"
#include "chfcoe_rnode.h"
#include "chfcoe_proto.h"
#include "chfcoe_defs.h"
#include "chfcoe_vn2vn.h"
#include "chfcoe_xchg.h"
/*
 * Frame tx related functions
 */
extern chfcoe_fc_buffer_t *
chfcoe_fip_buffer_alloc(size_t payload_len);
extern struct chfcoe_rnode *
chfcoe_get_rnode(struct chfcoe_lnode *lnode, uint32_t port_id, 
		struct chfcoe_port_parms *rdevp);

void *
chfcoe_fill_cpl_tx(chfcoe_fc_buffer_t *p, uint8_t pf, size_t payload_len,
		   uint8_t port_num, uint16_t vlan_id);

extern const unsigned long cpl_tx_pkt_xt_size;

chfcoe_retval_t
chfcoe_do_fip_solicitation(struct chfcoe_fcf *fcf,
		uint8_t fip_subop __attribute__((unused)))
{
	struct proto_fip_sol 	*sol;
	chfcoe_fc_buffer_t 	*p;
	struct chfcoe_port_info	*pi = fcf->pi;
	struct chfcoe_adap_info *adap = pi->adap;
	uint8_t mac[6] = PROTO_FIP_ALL_FCF_MACS;
	/* First allocate the memory for the cpltx_pkt 
	 * as well as frame */
	p = chfcoe_fip_buffer_alloc(sizeof(struct proto_fip_sol));
	if (!p) {
		chfcoe_err(0, "fip buffer alloc failed\n");
		return CHFCOE_RETRY;
	}

	/*
	 * Fill the cpl_tx_pkt and get the point pointing past it so 
	 * that we can fill teh rest of the frame
	 */
	sol = (struct proto_fip_sol *)chfcoe_fill_cpl_tx(p, adap->pf, 
		sizeof(struct proto_fip_sol), pi->port_num, 
		(fcf->vlan_id | pi->dcb_prio << VLAN_PRIO_SHIFT));
	
	/* Now fill the frame */

	chfcoe_memset(sol, 0, sizeof(struct proto_fip_sol));

	if (fcf)
        	chfcoe_memcpy(sol->eth.dmac, fcf->fcf_mac, 6);
	else 
        	chfcoe_memcpy(sol->eth.dmac, mac, 6);

        chfcoe_memcpy(sol->eth.smac, pi->phy_mac, 6);
        sol->eth.et		= chfcoe_htons(ETH_P_PROTO_FIP);

        sol->fip.fip_ver 	= PROTO_FIP_VER_ENCAPS(1);
        sol->fip.fip_op 	= chfcoe_htons(PROTO_FIP_OP_DISC);
        sol->fip.fip_subcode 	= PROTO_FIP_SC_SOL;
        sol->fip.fip_dl_len 	= chfcoe_htons(sizeof(sol->desc) / PROTO_FIP_BPW);
        sol->fip.fip_flags 	= chfcoe_htons(PROTO_FIP_FL_FPMA);

        sol->desc.mac.fd_desc.fip_dtype = PROTO_FIP_DT_MAC;
        sol->desc.mac.fd_desc.fip_dlen 	= sizeof(sol->desc.mac) / PROTO_FIP_BPW;
        chfcoe_memcpy(sol->desc.mac.fd_mac, pi->phy_mac, 6);

        sol->desc.wwnn.fd_desc.fip_dtype = PROTO_FIP_DT_NAME;
        sol->desc.wwnn.fd_desc.fip_dlen  = sizeof(sol->desc.wwnn) / PROTO_FIP_BPW;

        chfcoe_memcpy(&sol->desc.wwnn.fd_wwn, fcf->fab_wwn, 8);

        sol->desc.size.fd_desc.fip_dtype = PROTO_FIP_DT_FCOE_SIZE;
        sol->desc.size.fd_desc.fip_dlen  = sizeof(sol->desc.size) / PROTO_FIP_BPW;
        sol->desc.size.fd_size 		 = chfcoe_htons(PROTO_MAX_FCOE_SIZE);

	/* Now increment the stats */
	CHFCOE_INC_STATS(fcf, n_sol_sent);
	CHFCOE_INC_STATS(fcf, n_fip_tx_fr);
	fcf->stats.n_fip_tx_bytes += sizeof(struct proto_fip_sol);

	/* Now transmit the frame */
	return adap->lld_ops->send_frame(p, pi->os_dev, chfcoe_smp_id());
} /*chfcoe_do_fip_soiliciation */

static chfcoe_retval_t
chfcoe_send_fcf_ka(struct chfcoe_fcf *fcf)
{
	struct proto_fip_fcf_ka	*ka;
	chfcoe_fc_buffer_t 	*p;
	struct chfcoe_port_info	*pi = fcf->pi;
	struct chfcoe_adap_info *adap = pi->adap;
	
	/* First allocate the memory for the cpltx_pkt 
	 * as well as frame */
	p = chfcoe_fip_buffer_alloc(sizeof(struct proto_fip_fcf_ka));
	if (!p) {
		chfcoe_err(0, "fip buffer alloc failed\n");
		return CHFCOE_RETRY;
	}
	
	/*
	 * Fill the cpl_tx_pkt and get the point pointing past it so 
	 * that we can fill teh rest of the frame
	 */
	ka = (struct proto_fip_fcf_ka *)chfcoe_fill_cpl_tx(p, adap->pf, sizeof(struct proto_fip_fcf_ka), pi->port_num, (fcf->vlan_id | pi->dcb_prio << VLAN_PRIO_SHIFT));
	
	/* Now fill the frame */
	chfcoe_memset(ka, 0, sizeof(struct proto_fip_fcf_ka));

        chfcoe_memcpy(ka->eth.dmac, fcf->fcf_mac, 6);
        chfcoe_memcpy(ka->eth.smac, pi->phy_mac, 6);
        ka->eth.et		= chfcoe_htons(ETH_P_PROTO_FIP);

        ka->fip.fip_ver 	= PROTO_FIP_VER_ENCAPS(1);
        ka->fip.fip_op 		= chfcoe_htons(PROTO_FIP_OP_CTRL);
        ka->fip.fip_subcode 	= PROTO_FIP_SC_KEEP_ALIVE;
        ka->fip.fip_dl_len 	= chfcoe_htons(sizeof(ka->desc) / PROTO_FIP_BPW);
        ka->fip.fip_flags 	= chfcoe_htons(PROTO_FIP_FL_FPMA);

        ka->desc.mac.fd_desc.fip_dtype = PROTO_FIP_DT_MAC;
        ka->desc.mac.fd_desc.fip_dlen 	= sizeof(ka->desc.mac) / PROTO_FIP_BPW;
        chfcoe_memcpy(ka->desc.mac.fd_mac, pi->phy_mac, 6);

	CHFCOE_INC_STATS(fcf, n_fcf_ka_sent);
	CHFCOE_INC_STATS(fcf, n_fip_tx_fr);
	fcf->stats.n_fip_tx_bytes += sizeof(struct proto_fip_fcf_ka);
	/* Now transmit the frame */
	return adap->lld_ops->send_frame(p, pi->os_dev, chfcoe_smp_id());
} /*chfcoe_send_fcf_ka */

static chfcoe_retval_t
chfcoe_sched_ka_timer(struct chfcoe_fcf *fcf)
{
	return chfcoe_schedule_delayed_work(fcf->fcf_ka_timer_work, fcf->fka_adv_prd);
} /* chfcoe_sched_ka_timer */

void 
chfcoe_fcf_ka_cbfn(void *data)
{
	struct chfcoe_fcf *fcf = (struct chfcoe_fcf *)data;
	chfcoe_retval_t rv = CHFCOE_INVAL;
	CHFCOE_ASSERT(fcf);
	if (fcf->state == CHFCOE_FCF_ST_ONLINE) {
		rv = chfcoe_send_fcf_ka(fcf);
	}
	/* RE-arm the timer */
	chfcoe_sched_ka_timer(fcf);
} /* chfcoe_fcf_ka_cbfn */

static chfcoe_retval_t
chfcoe_validate_fip_adv(void *desc_pld, uint32_t desc_len, 
		      	uint32_t fip_flags, uint32_t vlan, 
			struct chfcoe_fcf **found_fcf, struct chfcoe_port_info *pi)
{
	uint32_t len = 0, exp_desc_bm = 0, cur_adv_prd, new_adv_prd;

	struct proto_fip_desc *desc = desc_pld;
	struct proto_fip_pri_desc *pri_desc = NULL;
	struct proto_fip_mac_desc *mac_desc = NULL;
	struct proto_fip_wwn_desc *wwn_desc = NULL;
	struct proto_fip_fab_desc *fab_desc = NULL;
	struct proto_fip_fka_desc *fka_desc = NULL;
	struct chfcoe_fcf	  *fcf      = NULL;
	struct chfcoe_list	*fcf_tmp;
	uint8_t pri_chk, mac_chk, wwn_chk, fab_vfid_chk; 
	uint8_t fab_map_chk, vlan_chk, fcf_found = 0;
	
	exp_desc_bm = ((1 << PROTO_FIP_DT_MAC) | (1 << PROTO_FIP_DT_NAME) | 
		      (1 << PROTO_FIP_DT_PRI) | (1 << PROTO_FIP_DT_FAB) | 
		      (1 << PROTO_FIP_DT_FKA));

	while (len < desc_len) {
		switch (desc->fip_dtype) {
		case PROTO_FIP_DT_PRI:
			exp_desc_bm &= ~(1 << PROTO_FIP_DT_PRI);
			pri_desc = (struct proto_fip_pri_desc *)desc;
			break;

		case PROTO_FIP_DT_MAC:
			exp_desc_bm &= ~(1 << PROTO_FIP_DT_MAC);
			mac_desc = (struct proto_fip_mac_desc *)desc;
			break;

		case PROTO_FIP_DT_NAME:
			exp_desc_bm &= ~(1 << PROTO_FIP_DT_NAME);
			wwn_desc = (struct proto_fip_wwn_desc *)desc;
			break;

		case PROTO_FIP_DT_FAB:
			exp_desc_bm &= ~(1 << PROTO_FIP_DT_FAB);
			fab_desc = (struct proto_fip_fab_desc *)desc;
			break;

		case PROTO_FIP_DT_FKA:
			exp_desc_bm &= ~(1 << PROTO_FIP_DT_FKA);
			fka_desc = (struct proto_fip_fka_desc *)desc;
			break;

		default:
			break;
		}
		len += desc->fip_dlen;
		desc = (void *) desc + (desc->fip_dlen * 4);
	}

	if (exp_desc_bm)  {
		return 1;
	}


	chfcoe_list_for_each(fcf_tmp, &pi->fcf_head) {
		fcf = (struct chfcoe_fcf *)fcf_tmp;
		mac_chk = 
			chfcoe_memcmp(fcf->fcf_mac, mac_desc->fd_mac, 6);
		wwn_chk = 
			chfcoe_memcmp(fcf->fab_wwn, &wwn_desc->fd_wwn,8);
		fab_map_chk = 
			chfcoe_memcmp(fcf->fc_map, fab_desc->fd_map, 3);

		if (fcf->vf_id == fab_desc->fd_vfid)
			fab_vfid_chk = 1;

		if (fcf->fcf_prio == pri_desc->fd_pri)
			pri_chk = 1;
		else 
			/* Just update the priority value for now */
			fcf->fcf_prio = pri_desc->fd_pri;

		if (fcf->vlan_id == (uint16_t) vlan)
			vlan_chk = 1;
		if (!mac_chk && !wwn_chk) {
			fcf_found = 1;

			/* We can potentially reuse the same FCF for the 
			 * scenarios of VFID and FC-MAP changing
			 */
			if (!fab_vfid_chk) {
				fcf->vf_id = fab_desc->fd_vfid;
				CHFCOE_INC_STATS(fcf, n_vf_id_chg);
			}

			if (wwn_chk) {
				chfcoe_memcpy(fcf->fab_wwn, 
					&fab_desc->fd_wwn, 8);
			}

			if (fab_map_chk) {
				chfcoe_memcpy(fcf->fc_map, 
					&fab_desc->fd_map, 3);
				CHFCOE_INC_STATS(fcf, n_fc_map_chg);
			}

			/* Check if the KA is not required */
			if (fka_desc->d) {
				chfcoe_cancel_delayed_work(fcf->fcf_ka_timer_work);
				fcf->fka_adv_prd 	= 0;
				CHFCOE_INC_STATS(fcf, n_fka_not_req);
			} else {
				cur_adv_prd = fcf->fka_adv_prd;
				new_adv_prd = chfcoe_ntohl(fka_desc->fd_fka_period);

				if (cur_adv_prd != new_adv_prd) {
					fcf->fka_adv_prd = new_adv_prd ;
					if (!(fip_flags & PROTO_FIP_FL_SOL)) {
						chfcoe_sched_ka_timer(fcf);
					}
					CHFCOE_INC_STATS(fcf,
							n_adv_prd_chg);
				}
			}
			break;
		}
	}

	*found_fcf = fcf_found ? fcf : NULL;

	return CHFCOE_SUCCESS;
} /* fcoe_validate_fip_adv */
chfcoe_retval_t
chfcoe_rcv_fip_adv(struct chfcoe_adap_info *adap, uint8_t port_num,
		   struct proto_fip_header *fip_hdr, uint32_t vlan)
{	
	struct chfcoe_port_info *pi = CHFCOE_PTR_OFFSET(adap->pi, (port_num * chfcoe_port_info_size));
	chfcoe_retval_t rv	= CHFCOE_INVAL;
	uint16_t fip_dlen	= chfcoe_ntohs(fip_hdr->fip_dl_len);
	uint16_t fip_flags	= chfcoe_ntohs(fip_hdr->fip_flags);
	struct proto_fip_desc *desc_pld = (void *) fip_hdr + 
					sizeof(struct proto_fip_header);
	uint16_t exp_flags = PROTO_FIP_FL_FPMA | PROTO_FIP_FL_AVAIL | 
        		     PROTO_FIP_FL_SOL | PROTO_FIP_FL_FPORT;
	struct chfcoe_fcf *fcf = NULL;
	struct chfcoe_lnode *ln;	
	
	if (fip_flags != exp_flags) {
		CHFCOE_INC_STATS(pi, n_fip_drop);
		return(rv);
	}
	rv = chfcoe_validate_fip_adv(desc_pld, fip_dlen, fip_flags, 
				     vlan, &fcf, pi);
	if (rv) {
		chfcoe_err(pi, "port:%d invalid ucast adv recv\n", 
				pi->port_num);
		CHFCOE_INC_STATS(pi, n_fip_drop);
		return CHFCOE_INVAL;
	}

	if (fcf == NULL) {
		chfcoe_err(pi, "port:%d No FCF found\n", 
				pi->port_num);
		CHFCOE_INC_STATS(pi, n_fip_drop);
		return CHFCOE_INVAL;
	}	
	CHFCOE_INC_STATS(fcf, n_fcf_ucast_adv_rcvd);
	fcf->state = CHFCOE_FCF_ST_ONLINE;
	
	ln =  chfcoe_fcf_to_ln(fcf);
	if (!ln) {
		/* Alloc one lnode per fcf initially */
		chfcoe_fcf_to_ln(fcf) = chfcoe_lnode_create(fcf,
				CHFCOE_FCF, pi);
		if (chfcoe_fcf_to_ln(fcf) == NULL) {
			chfcoe_err(pi, "port:%d failed alloc lnode for fcf\n", 
				pi->port_num);
			CHFCOE_INC_STATS(pi, n_nomem);
			CHFCOE_INC_STATS(pi, n_fip_drop);
			return CHFCOE_NOMEM;
		}
		ln =  chfcoe_fcf_to_ln(fcf);
	}
	chfcoe_lnode_evt_handler(ln, CHFCOE_LN_EVT_LINK_UP, NULL);
	return CHFCOE_SUCCESS;
} /* chfcoe_rcv_fip_adv */

chfcoe_retval_t
chfcoe_rcv_mcast_fip_adv(struct chfcoe_adap_info *adap, uint8_t port_num,
		   struct proto_fip_header *fip_hdr, uint32_t vlan)
{
	chfcoe_retval_t rv		= CHFCOE_INVAL;
	struct chfcoe_port_info *pi = CHFCOE_PTR_OFFSET(adap->pi, (port_num * chfcoe_port_info_size));
	struct chfcoe_fcf 	*fcf 	= NULL;
	uint16_t fip_dlen		= chfcoe_ntohs(fip_hdr->fip_dl_len);
	uint16_t fip_flags		= chfcoe_ntohs(fip_hdr->fip_flags);
	struct fip_desc *desc_pld 	= (void *) fip_hdr + 
					  sizeof(struct proto_fip_header);
	uint16_t exp_flags 		= PROTO_FIP_FL_FPMA | PROTO_FIP_FL_AVAIL | 
        		     		  PROTO_FIP_FL_FPORT;

	if (fip_flags != exp_flags) {
		CHFCOE_INC_STATS(pi, n_fip_drop);
		return(rv);
	}
	rv = chfcoe_validate_fip_adv(desc_pld, fip_dlen, fip_flags, 
				     vlan, &fcf, pi);

	if (rv) {
		chfcoe_err(pi, "port:%d invalid ucast adv recv\n", 
				pi->port_num);
		CHFCOE_INC_STATS(pi, n_fip_drop);
		return(rv);
	}
	if (fcf == NULL) {

		/* Have to get Multicast advertisements to discover FCFs. Using
		 * just soliciation and Unicast advertisements does not work
		 * for non-default VLAN as first a VLAN Request has to be send.
		 * Use Multicast advertisments also for keeping the virtual 
		 * link alive 
		 */
		/* Assumption here is that there is only one FCF behind a port. 
		 */
		
		/* 
		 * By default there will be one FCF allocated at port_init stage.
		 * So instead of allocating a new FCF for every multicast advertisement,
		 * check if we can use the already existing FCF 
		 */
		fcf = chfcoe_alloc_fcf(pi);	/* Alloc FCF */
		if (!fcf) {
			CHFCOE_INC_STATS(pi, n_fip_drop);
			return(rv);
		}
		rv = chfcoe_init_fcf(fcf, desc_pld, fip_dlen);
		fcf->vlan_id = vlan;
		fcf->mcast_fip_adv_rcvd = 1;

		chfcoe_dbg(pi,"Found new FCF Node:0x%x%x%x%x%x%x%x%x\n",
		fcf->fab_wwn[0], fcf->fab_wwn[1], 
		fcf->fab_wwn[2], fcf->fab_wwn[3], 
		fcf->fab_wwn[4], fcf->fab_wwn[5], 
		fcf->fab_wwn[6], fcf->fab_wwn[7]);

		CHFCOE_INC_STATS(fcf, n_fcf_mcast_adv_rcvd);
		
		return (chfcoe_do_fip_solicitation(fcf, PROTO_FIP_SC_SOL));
	} else {
		if (fcf->state != CHFCOE_FCF_ST_ONLINE) { 
			/* REcvd mcast adv on offline fcf 
			 * Rstart with solicitation
			 */
			rv = chfcoe_do_fip_solicitation(fcf, PROTO_FIP_SC_SOL);
		}
		CHFCOE_INC_STATS(fcf, n_fcf_mcast_adv_rcvd);
	}

	return rv;

} /* chfcoe_chk_mcast_fip_adv */

uint8_t
chfcoe_validate_fabric_srv_parms(
		struct chfcoe_lnode *ln __attribute__((unused)),
		struct proto_ls_logi *flogi_parms)
{
	uint8_t rval = PROTO_LS_RJT_EXPL_NONE;
	uint16_t max_fr_size;

	max_fr_size = chfcoe_ntohs(flogi_parms->sp.csp.rcv_sz) &
                		PROTO_FC_SP_BB_DATA_MASK;
	if ((max_fr_size < 256) || 
	    (max_fr_size > 2112)) {
		rval = PROTO_LS_RJT_EXPL_SPARM_RCV_SIZE;
	}
	if (!G_FABRIC_PORT(chfcoe_ntohs(flogi_parms->sp.csp.word1_flags))) {
		rval = PROTO_LS_RJT_EXPL_SPARM_OPTIONS;
	}

	if (G_FC_SP(chfcoe_ntohs(flogi_parms->sp.csp.word1_flags))) {
		rval = PROTO_LS_RJT_EXPL_SPARM_OPTIONS;
	}

	if (!G_SP_CLASS_SUPPORT(flogi_parms->sp.clsp[2].serv_option)) {
		rval = PROTO_LS_RJT_EXPL_SPARM_OPTIONS;
	}

	if (!G_SEQ_DEL(flogi_parms->sp.clsp[2].serv_option)) {
		rval = PROTO_LS_RJT_EXPL_SPARM_OPTIONS;
	}

	return(rval);
} /* chfcoe_validate_fabric_srv_parms */

chfcoe_retval_t
chfcoe_handle_fabric_login_rsp(struct chfcoe_adap_info *adap, uint8_t port_num,
                   chfcoe_fc_buffer_t *pld, uint32_t vlan)
{
	chfcoe_retval_t rv		= CHFCOE_INVAL;
	struct chfcoe_port_info *pi = CHFCOE_PTR_OFFSET(adap->pi, (port_num * chfcoe_port_info_size));
	struct chfcoe_fcf 	*fcf 	= NULL;
	struct chfcoe_vn2vn 	*vn2vn 	= NULL;
	struct chfcoe_lnode 	*ln	= NULL;

	struct proto_fip_virt_ln_rsp *els_rsp = (struct proto_fip_virt_ln_rsp *)
						chfcoe_fc_data_ptr(pld);
	struct proto_ethhdr_novlan *eh = 	(struct proto_ethhdr_novlan *)
						chfcoe_fc_data_ptr(pld);
	/* Strip FIP header send FLOGI RSP packet to FC2 layer */
	if (adap->fip_mode == CHFCOE_VN2VN || adap->fip_mode == CHFCOE_FIP_BOTH)
	{
		vn2vn = chfcoe_get_vn2vn(pi, eh->dmac, vlan);
		if (vn2vn) {
			chfcoe_fcb_pull_rx(pld, 
				(CHFCOE_OFFSETOF(struct proto_fip_virt_ln_req, 
				 desc.logi.fc_hdr)));
			chfcoe_fc_sof(pld) = PROTO_FC_SOF_I3;
			chfcoe_fc_eof(pld) = PROTO_FC_EOF_T;
			chfcoe_xchg_recv(vn2vn->ln, pld);
			return CHFCOE_SUCCESS;
		}
		return rv;
	}
	if (adap->fip_mode == CHFCOE_FCF || adap->fip_mode == CHFCOE_FIP_BOTH) {
		fcf = chfcoe_get_fcf(pi, eh->smac, vlan);
		if (!fcf) {
			chfcoe_err(pi, "port:%d No FCF found\n", 
				pi->port_num);
			CHFCOE_INC_STATS(pi, n_fip_drop);
			return rv;
		}	
		ln = chfcoe_fcf_to_ln(fcf);
		if (!ln) {
			chfcoe_err(pi, "port:%d No lnode attached to FCF\n", 
				pi->port_num);
			CHFCOE_INC_STATS(pi, n_fip_drop);
			return rv;
		}
		if (fcf->fka_adv_prd) {
			chfcoe_sched_ka_timer(fcf);
		}
		chfcoe_memcpy(ln->fcoe_mac, 
			els_rsp->desc.mac.fd_mac, 6);
		ln->nport_id = chfcoe_ntoh24(els_rsp->desc.logi.fc_hdr.d_id);
		chfcoe_info(adap, "lnode:0x%x assigned on port %d\n", 
				ln->nport_id, ln->port_num);
		chfcoe_fcb_pull_rx(pld, 
			(CHFCOE_OFFSETOF(struct proto_fip_virt_ln_req, 
			 desc.logi.fc_hdr)));
		chfcoe_fc_sof(pld) = PROTO_FC_SOF_I3;
		chfcoe_fc_eof(pld) = PROTO_FC_EOF_T;
		chfcoe_xchg_recv(ln, pld);
		chfcoe_fcb_free(pld);
		return CHFCOE_SUCCESS;
	}

	CHFCOE_INC_STATS(fcf, n_virt_ln_rpl);
	return rv;

} /* handle_fabric_login_rsp */
static void 
chfcoe_fip_cvl_recv(struct chfcoe_adap_info *adap, uint8_t port_num, 
		chfcoe_fc_buffer_t *pld, uint16_t vlan_id)
{

	struct chfcoe_port_info *pi = CHFCOE_PTR_OFFSET(adap->pi, (port_num * chfcoe_port_info_size));
	struct chfcoe_fcf 	*fcf 	= NULL;
	struct chfcoe_lnode 	*ln	= NULL;
	uint8_t fd_mac[6];
	uint8_t wwnn[8];

	struct proto_fip_clr_virt_lnk *cvl = 	(
			struct proto_fip_clr_virt_lnk *)  chfcoe_fc_data_ptr(pld);
	struct proto_ethhdr_novlan *eh =
		(struct proto_ethhdr_novlan *)  chfcoe_fc_data_ptr(pld);

	chfcoe_memcpy(fd_mac, cvl->desc.mac.fd_mac, 6);
	chfcoe_memcpy(wwnn, &cvl->desc.wwnn.fd_wwn, 8);
	
	fcf = chfcoe_get_fcf(pi, eh->smac, vlan_id);
	if (!fcf) {
		chfcoe_err(pi, "port:%d No FCF found\n", 
				pi->port_num);
		CHFCOE_INC_STATS(pi, n_fip_drop);
		return ;
	}
	ln = chfcoe_fcf_to_ln(fcf);
	if (!ln) {
		chfcoe_err(pi, "port:%d No lnode attached to FCF found\n", 
				pi->port_num);
		CHFCOE_INC_STATS(pi, n_fip_drop);
		return ;
	}

	chfcoe_stop_fcf(fcf);
	return;
} /* chfcoe_fip_cvl_recv */

chfcoe_retval_t
chfcoe_fip_handle(struct chfcoe_adap_info *adap,
		chfcoe_fc_buffer_t *pld, uint8_t port_num,
		uint16_t vlan_id)
{
	struct proto_ethhdr_novlan *eh = (struct proto_ethhdr_novlan *) 
					chfcoe_fc_data_ptr(pld);
	struct proto_fip_header *fip_hdr = (struct proto_fip_header *) (eh + 1);

	uint16_t fip_op 		= chfcoe_ntohs(fip_hdr->fip_op);
	uint8_t fip_subop 		= fip_hdr->fip_subcode;
	struct proto_fip_desc *desc_pld = (void *) fip_hdr + 
					  sizeof(struct proto_fip_header);
	
	uint8_t fcoe_all_enode[6] = { 1, 0x10, 0x18, 1, 0, 1 };
	uint8_t mcast;
	struct chfcoe_port_info *pi = CHFCOE_PTR_OFFSET(adap->pi, (port_num * chfcoe_port_info_size));
	struct chfcoe_vn2vn *vn2vn;

	/* If the FIP opcode and sub-opcode is Unicast Advertisement... */
	chfcoe_dbg(adap, "port:%x fip_op:%x fip_subop:%d mcast:%x mpsid:%x\n",
			pi->port_num, fip_op, fip_subop, 
			chfcoe_fc_mcast(pld), chfcoe_fc_mpsid(pld));
	switch (fip_op) {
	case PROTO_FIP_OP_DISC:
		switch (fip_subop) {

		case PROTO_FIP_SC_SOL:
			CHFCOE_INC_STATS(pi, n_fip_drop);
			break;

		case PROTO_FIP_SC_ADV:
			mcast = chfcoe_memcmp(eh->dmac, fcoe_all_enode, 6);
			if (!mcast)
				chfcoe_rcv_mcast_fip_adv(adap, port_num, fip_hdr, vlan_id);
			else 
				chfcoe_rcv_fip_adv(adap, port_num, fip_hdr, vlan_id);
			break;

		default:
			break;
		}
		break;
	case PROTO_FIP_OP_LS:
		switch (fip_subop) {
		
		case PROTO_FIP_SC_REQ:
			if (adap->fip_mode == CHFCOE_FCF) {
				CHFCOE_INC_STATS(pi, n_fip_drop);
				break;
			}	
			switch (desc_pld->fip_dtype) {
                        case PROTO_FIP_DT_FLOGI:
			case PROTO_FIP_DT_LOGO:
                        case PROTO_FIP_DT_FDISC:
				vn2vn = chfcoe_get_vn2vn(pi, eh->dmac, vlan_id);
				if (!vn2vn) {
					CHFCOE_INC_STATS(pi, n_fip_drop);
					break;
				}
				chfcoe_fcb_pull_rx(pld, 
			 	(CHFCOE_OFFSETOF(struct proto_fip_virt_ln_req,
						 desc.logi.fc_hdr)));
				chfcoe_fcb_trim_rx(pld, sizeof(struct proto_fip_mac_desc));

				chfcoe_fc_sof(pld) = PROTO_FC_SOF_I3;
				chfcoe_fc_eof(pld) = PROTO_FC_EOF_T;
				chfcoe_xchg_recv(vn2vn->ln, pld);
				return CHFCOE_SUCCESS;
			default:
				break;
			}
			break;
			
		case PROTO_FIP_SC_REP:
			 switch (desc_pld->fip_dtype) {
                                case PROTO_FIP_DT_FLOGI:
                                case PROTO_FIP_DT_FDISC:
					if (!(chfcoe_handle_fabric_login_rsp(
						adap, port_num, pld,
						vlan_id)))
						return CHFCOE_SUCCESS;
					break;
					
				
				case PROTO_FIP_DT_LOGO:
				default:
					break;
			}
			break;
		}
		break;
	case PROTO_FIP_OP_CTRL:
		switch (fip_subop) {

		case PROTO_FIP_SC_CLR_VLINK:
			chfcoe_fip_cvl_recv(adap, port_num, pld, vlan_id);
			break;

		case PROTO_FIP_SC_KEEP_ALIVE:
			break;
		}
		break;

	case PROTO_FIP_OP_VLAN:

		switch (fip_subop) {

		case PROTO_FIP_SC_VL_REP:
			break;

		default:
			CHFCOE_INC_STATS(pi, n_fip_drop);
			break;
		}
		break;
	case PROTO_FIP_OP_VN2VN:
		chfcoe_recv_vn2vn_fip(adap, fip_subop,
				port_num, pld, vlan_id);
		break;

	default:
		CHFCOE_INC_STATS(pi, n_fip_drop);
		break;

	} /* switch (fip_op) */
	chfcoe_fcb_free(pld);
	return CHFCOE_SUCCESS;
} /* proto_fip_recv */

chfcoe_retval_t
chfcoe_start_fip(struct chfcoe_port_info *pi)
{
	struct chfcoe_adap_info *adap = pi->adap;
	uint8_t fcf_addr[6] = PROTO_FIP_ALL_ENODE_MACS;
	uint8_t vn2vn_addr[6] = PROTO_FIP_ALL_VN2VN_MACS;
	chfcoe_retval_t ret = 0;
	struct chfcoe_lld_ops 	*lld_ops = adap->lld_ops;
	uint16_t mpsid = 0;

	ret = lld_ops->fcoe_enable(pi->os_dev, 1);
	if (ret) {
		chfcoe_err(adap, "port:%d failed to enable fcoe device\n",
			pi->port_num);
		return ret;
	}

	/* Add mac address to mps to recv fip frames*/
	if (adap->fip_mode == CHFCOE_FCF || adap->fip_mode == CHFCOE_FIP_BOTH) {
		ret = chfcoe_adap_set_macaddr(pi, fcf_addr, &mpsid, 0);
		if (ret) {
			chfcoe_err(adap, "port:%d failed to set fcf mcast "
					"mac filter\n", pi->port_num);
			goto mac_err;
		}	
		pi->fcf_mpsid = mpsid;
	}

	if (adap->fip_mode == CHFCOE_VN2VN || adap->fip_mode == CHFCOE_FIP_BOTH)
	{	
		ret = chfcoe_adap_set_macaddr(pi, vn2vn_addr, &mpsid, 0);
		if (ret) {
			chfcoe_err(adap, "port:%d failed to set vn2vn mcast "
					"mac filter\n", pi->port_num);
			goto mac_err;
		}	
		pi->vn2vn_mpsid = mpsid;
		chfcoe_start_vn2vn(pi);
	}
	return 0;

mac_err:
	lld_ops->fcoe_enable(pi->os_dev, 0);
	return ret;
}

chfcoe_retval_t
chfcoe_stop_fip(struct chfcoe_port_info *pi)
{
	struct chfcoe_adap_info         *adap = pi->adap;
	uint8_t fcf_addr[6] = PROTO_FIP_ALL_ENODE_MACS;
	uint8_t vn2vn_addr[6] = PROTO_FIP_ALL_VN2VN_MACS;
	chfcoe_retval_t ret = 0;
	struct chfcoe_lld_ops 	*lld_ops = adap->lld_ops;
	struct chfcoe_fcf 	*fcf;
	struct chfcoe_list	*fcf_tmp, *fcf_next, fcf_list;
	uint16_t mpsid = 0;
	

	ret = lld_ops->fcoe_enable(pi->os_dev, 0);
	if (ret) {
		chfcoe_err(adap, "port:%d failed to disable fcoe device\n",
			pi->port_num);
		return ret;
	}

	/* clear mac address to stop fip frames*/
	if (adap->fip_mode == CHFCOE_FCF || adap->fip_mode == CHFCOE_FIP_BOTH) {
		ret = chfcoe_adap_set_macaddr(pi, fcf_addr, &mpsid, 1);
		if (ret) {
			chfcoe_err(adap, "port:%d failed to clear fcf mcast "
					"mac filter\n", pi->port_num);
		}	

		chfcoe_head_init(&fcf_list);
		chfcoe_mutex_lock(pi->mtx_lock);
		chfcoe_enq_list_at_tail(&fcf_list, &pi->fcf_head);
		chfcoe_mutex_unlock(pi->mtx_lock);

		/* free the fcf */
		chfcoe_list_for_each_safe(fcf_tmp, fcf_next, &fcf_list) {
			fcf = (struct chfcoe_fcf *)fcf_tmp;
			chfcoe_stop_fcf(fcf);
		}
		chfcoe_mutex_lock(pi->mtx_lock);
		chfcoe_enq_list_at_tail(&pi->fcf_head, &fcf_list);
		chfcoe_mutex_unlock(pi->mtx_lock);
	}
	if (adap->fip_mode == CHFCOE_VN2VN || adap->fip_mode == CHFCOE_FIP_BOTH)
	{	
		ret = chfcoe_adap_set_macaddr(pi, vn2vn_addr, &mpsid, 1);
		if (ret) {
			chfcoe_err(adap, "port:%d failed to clear vn2vn mcast "
					"mac filter\n", pi->port_num);
		}
		chfcoe_stop_vn2vn(pi);
	}

	return ret;
}

void chfcoe_fip_recv(void *data)
{
	struct chfcoe_port_info *pi = data;
	struct chfcoe_adap_info *adap = pi->adap;
	chfcoe_fc_buffer_t *fcb;

	while ((fcb = chfcoe_skb_dequeue(pi->fip_rx_list))) {
		chfcoe_fip_handle(adap, fcb, chfcoe_fcb_cb(fcb)->port, 
				chfcoe_fcb_cb(fcb)->vlan_tci);
	}
}
