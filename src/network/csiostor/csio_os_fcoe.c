/*
 *  Copyright (C) 2008-2014 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: This file implements the Linux FC transport
 * 		callbacks/attributes.
 *
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/mm.h>

#include <csio_os_init.h>
#include <csio_fcoe_ioctl.h>

static void
csio_vport_set_state(struct csio_lnode_fcoe *lnf);

/* Common->OS callbacks */

/*
 * csio_rnf_reg_rnode - Register a remote port with FC transport.
 * @rn: Rnode representing remote port.
 *
 * Call fc_remote_port_add() to register this remote port with FC transport.
 * If remote port is Initiator OR Target OR both, change the role appropriately.
 *
 */
void
csio_rnf_reg_rnode(struct csio_rnode *rn)
{
	struct csio_rnode_fcoe *rnf 	= csio_rnode_to_fcoe(rn);
	struct csio_os_rnode *osrn	= csio_rnode_to_os(rn);
	struct csio_lnode *ln		= csio_rnode_to_lnode(rn);
	struct csio_os_lnode *osln	= csio_lnode_to_os(ln);
	struct Scsi_Host *shost		= csio_osln_to_shost(osln);
	struct fc_rport_identifiers ids;
	struct fc_rport  *rport;
	struct csio_service_parms *sp;

	CSIO_TRACE(ln->hwp, CSIO_RNODE_MOD, CSIO_DBG_LEV,
		rnf,
		csio_rnf_flowid(rnf),
		rnf->nport_id,
		csio_lnf_flowid(csio_lnode_to_fcoe(ln)));

	ids.node_name	= wwn_to_u64(csio_rnf_wwnn(rnf));
	ids.port_name	= wwn_to_u64(csio_rnf_wwpn(rnf));
	ids.port_id	= rnf->nport_id;
	ids.roles	= FC_RPORT_ROLE_UNKNOWN;

	if (rnf->role & CSIO_RNFR_INITIATOR || rnf->role & CSIO_RNFR_TARGET) {
		rport = osrn->rport;
		CSIO_ASSERT(rport != NULL);	
		goto update_role;
	}

	osrn->rport = fc_remote_port_add(shost, 0, &ids);
	if (!osrn->rport) {
		csio_ln_err(ln, "Failed to register rport = 0x%x.\n",
					rnf->nport_id);
		return;
	}

	ln->num_reg_rnodes++;
	rport = osrn->rport;
	spin_lock_irq(shost->host_lock);
	*((struct csio_os_rnode **)rport->dd_data) = osrn;
	spin_unlock_irq(shost->host_lock);

	sp = &rnf->rn_sparm;
	rport->maxframe_size		= sp->csp.rcv_sz;
	if (G_SP_CLASS_SUPPORT(sp->clsp[2].serv_option))
	       rport->supported_classes	=  FC_COS_CLASS3;
	else
	       rport->supported_classes	=  FC_COS_UNSPECIFIED;
update_role:
	if (rnf->role & CSIO_RNFR_INITIATOR)
		ids.roles |= FC_RPORT_ROLE_FCP_INITIATOR;
	if (rnf->role & CSIO_RNFR_TARGET) {
		ids.roles |= FC_RPORT_ROLE_FCP_TARGET;
	}

	if (ids.roles != FC_RPORT_ROLE_UNKNOWN)
		fc_remote_port_rolechg(rport, ids.roles);

	osrn->scsi_id = rport->scsi_target_id;

	csio_ln_dbg(ln, "Remote port x%x role 0x%x registered\n",
		rnf->nport_id, ids.roles);

	return;
}

/*
 * csio_rnf_unreg_rnode - Unregister a remote port with FC transport.
 * @rn: Rnode representing remote port.
 *
 * Call fc_remote_port_delete() to unregister this remote port with FC
 * transport.
 *
 */
void
csio_rnf_unreg_rnode(struct csio_rnode *rn)
{
	struct csio_rnode_fcoe *rnf 	= csio_rnode_to_fcoe(rn);
	struct csio_os_rnode *osrn	= csio_rnode_to_os(rn);
	struct csio_lnode *ln		= csio_rnode_to_lnode(rn);
	struct fc_rport *rport 		= osrn->rport;

	CSIO_TRACE(ln->hwp, CSIO_RNODE_MOD, CSIO_DBG_LEV,
		rnf,
		csio_rnf_flowid(rnf),
		rnf->nport_id,
		csio_lnf_flowid(csio_lnode_to_fcoe(ln)));

	rnf->role &= ~(CSIO_RNFR_INITIATOR | CSIO_RNFR_TARGET);
	fc_remote_port_delete(rport);
	ln->num_reg_rnodes--;
	csio_ln_dbg(ln, "Remote port x%x un-registered\n", rnf->nport_id);
	return;
}

/*
 * csio_rnf_async_event - Async events from remote port.
 * @rn: Rnode representing remote port.
 *
 * Async events from remote node that FC transport/SCSI ML
 * should be made aware of.
 *
 */
void
csio_rnf_async_event(struct csio_rnode *rn, csio_rn_os_evt_t os_evt)
{
	return;
}

/*
 * csio_lnf_async_event - Async events from local port.
 * @ln: lnode representing local port.
 *
 * Async events from local node that FC transport/SCSI ML
 * should be made aware of (Eg: RSCN).
 */
void
csio_lnf_async_event(struct csio_lnode *ln, csio_ln_os_evt_t os_evt)
{
	struct csio_lnode_fcoe *lnf 	= csio_lnode_to_fcoe(ln);
	struct csio_os_lnode *osln	= csio_lnode_to_os(ln);

	switch (os_evt) {
		case CSIO_LNF_OSE_RSCN:
			/* Get payload of rscn from lnf */
			/* For each RSCN entry */
				/*
				 * fc_host_post_event(shost,
				 * 		      fc_get_event_number(),
				 * 		      FCH_EVT_RSCN,
				 * 		      rscn_entry);
				 */
			break;
		case CSIO_LNF_OSE_LINKUP:
			/* send fc_host_post_event */
			/* set vport state */
			if (csio_is_npiv_lnf(lnf)) {
				csio_vport_set_state(lnf);
			}	
			break;
		case CSIO_LNF_OSE_LINKDOWN:
			/* send fc_host_post_event */
			/* set vport state */
			if (csio_is_npiv_lnf(lnf)) {
				csio_vport_set_state(lnf);
			}	
			break;
		case CSIO_LNF_OSE_ATTRIB_UPDATE:
			csio_fchost_attr_init(osln);
			break;
		default:
			break;
	}

	return;
}

/**
 * csio_fchost_attr_init - Initialize FC transport attributes
 * @osln: Lnode.
 *
 */
void
csio_fchost_attr_init(struct csio_os_lnode *osln)
{
	struct Scsi_Host  *shost = csio_osln_to_shost(osln);
	struct csio_lnode *ln = csio_osln_to_ln(osln);
	struct csio_lnode_fcoe *lnf = csio_lnode_to_fcoe(ln);


	fc_host_node_name(shost) = wwn_to_u64(csio_lnode_wwnn(osln));
	fc_host_port_name(shost) = wwn_to_u64(csio_lnode_wwpn(osln));

	fc_host_supported_classes(shost) = FC_COS_CLASS3;
	fc_host_max_npiv_vports(shost) = csio_lnode_maxnpiv(osln);
	fc_host_supported_speeds(shost) = FC_PORTSPEED_10GBIT |
		FC_PORTSPEED_1GBIT;

	fc_host_maxframe_size(shost) = lnf->ln_sparm.csp.rcv_sz;
	memset(fc_host_supported_fc4s(shost), 0,
		sizeof(fc_host_supported_fc4s(shost)));
	fc_host_supported_fc4s(shost)[7] = 1;

	memset(fc_host_active_fc4s(shost), 0,
		sizeof(fc_host_active_fc4s(shost)));
	fc_host_active_fc4s(shost)[7] = 1;
	return;
}

/*
 * csio_get_host_port_id - sysfs entries for nport_id is
 * populated/cached from this function
 */
static void
csio_get_host_port_id(struct Scsi_Host *shost)
{
	struct csio_os_lnode *osln	= shost_priv(shost);
	struct csio_lnode	*ln	= csio_osln_to_ln(osln);
	struct csio_lnode_fcoe *lnf	= csio_lnode_to_fcoe(ln);
	struct csio_hw *hw = csio_osln_to_hw(osln);

	csio_spin_lock_irq(hw, &hw->lock);
	fc_host_port_id(shost) = lnf->nport_id;
	csio_spin_unlock_irq(hw, &hw->lock);

	return;

}

/**
 * csio_get_port_type - Return FC local port type.
 * @shost: scsi host.
 *
 */
static void
csio_get_host_port_type(struct Scsi_Host *shost)
{
	struct csio_os_lnode *osln = shost_priv(shost);
	struct csio_lnode *ln = csio_osln_to_ln(osln);
	struct csio_lnode_fcoe *lnf = csio_lnode_to_fcoe(ln);
	struct csio_hw *hw = csio_osln_to_hw(osln);

	csio_spin_lock_irq(hw, &hw->lock);
	if (csio_is_npiv_lnf(lnf))
		fc_host_port_type(shost) = FC_PORTTYPE_NPIV;
	else
		fc_host_port_type(shost) = FC_PORTTYPE_NPORT;
	csio_spin_unlock_irq(hw, &hw->lock);
}

/**
 * csio_get_port_state - Return FC local port state.
 * @shost: scsi host.
 *
 */
static void
csio_get_host_port_state(struct Scsi_Host *shost)
{
	struct csio_os_lnode *osln = shost_priv(shost);
	struct csio_lnode *ln = csio_osln_to_ln(osln);
	struct csio_lnode_fcoe *lnf = csio_lnode_to_fcoe(ln);
	struct csio_hw *hw = csio_osln_to_hw(osln);
	char state[16];

	csio_spin_lock_irq(hw, &hw->lock);

	csio_lnf_stateto_str(lnf, state);	
	if (!strcmp(state, "READY"))
		 fc_host_port_state(shost) = FC_PORTSTATE_ONLINE;
	else if (!strcmp(state, "OFFLINE"))
		/* TODO: If user taken the link offline,
		 * set FC_PORTSTATE_OFFLINE
		 */
		 fc_host_port_state(shost) = FC_PORTSTATE_LINKDOWN;
	else
		 fc_host_port_state(shost) = FC_PORTSTATE_UNKNOWN;

	csio_spin_unlock_irq(hw, &hw->lock);
}

/**
 * csio_get_host_speed - Return link speed to FC transport.
 * @shost: scsi host.
 *
 */
static void
csio_get_host_speed(struct Scsi_Host *shost)
{
	struct csio_os_lnode *osln = shost_priv(shost);
	struct csio_lnode *ln = csio_osln_to_ln(osln);
	struct csio_hw *hw = csio_osln_to_hw(osln);

	csio_spin_lock_irq(hw, &hw->lock);
	switch (hw->t4port[ln->portid].link_speed) {
		case FW_PORT_CAP_SPEED_1G:
			fc_host_speed(shost) = FC_PORTSPEED_1GBIT;
			break;
		case FW_PORT_CAP_SPEED_10G:
			fc_host_speed(shost) = FC_PORTSPEED_10GBIT;
			break;
		default:
			fc_host_speed(shost) = FC_PORTSPEED_UNKNOWN;
			break;
	}
	csio_spin_unlock_irq(hw, &hw->lock);
}

/**
 * csio_get_host_fabric_name - Return fabric name
 * @shost: scsi host.
 *
 */
static void
csio_get_host_fabric_name(struct Scsi_Host *shost)
{
	struct csio_os_lnode *osln = shost_priv(shost);
	struct csio_lnode *ln = csio_osln_to_ln(osln);
	struct csio_lnode_fcoe *lnf = csio_lnode_to_fcoe(ln);
	struct csio_rnode_fcoe *rnf = NULL;
	struct csio_hw *hw = csio_osln_to_hw(osln);

	csio_spin_lock_irq(hw, &hw->lock);
	rnf = csio_rnf_lookup_portid(lnf, FABRIC_DID);
	if (rnf)
		fc_host_fabric_name(shost) = wwn_to_u64(csio_rnf_wwnn(rnf));
	else
		fc_host_fabric_name(shost) = 0;
	csio_spin_unlock_irq(hw, &hw->lock);
}

/**
 * csio_get_host_speed - Return FC transport statistics.
 * @osln: Lnode.
 *
 */
static struct fc_host_statistics *
csio_get_stats(struct Scsi_Host *shost)
{
	struct csio_os_lnode *osln = shost_priv(shost);
	struct csio_os_hw *oshw = csio_osln_to_oshw(osln);
	struct fc_host_statistics *fhs = &oshw->fch_stats;
	struct fw_fcoe_port_stats fcoe_port_stats;
	struct csio_hw *hw = csio_osln_to_hw(osln);
	uint64_t seconds;
	
	csio_memset(&fcoe_port_stats, 0, sizeof(struct fw_fcoe_port_stats));
	csio_spin_lock_irq(hw, &hw->lock);
	csio_get_phy_port_stats(hw, osln->lnode.portid, &fcoe_port_stats);
	csio_spin_unlock_irq(hw, &hw->lock);

	fhs->tx_frames  += (fcoe_port_stats.tx_bcast_frames +
				fcoe_port_stats.tx_mcast_frames +
				fcoe_port_stats.tx_ucast_frames +
				fcoe_port_stats.tx_offload_frames);
	fhs->tx_words  += (fcoe_port_stats.tx_bcast_bytes +
				fcoe_port_stats.tx_mcast_bytes +
				fcoe_port_stats.tx_ucast_bytes +
				fcoe_port_stats.tx_offload_bytes) / CSIO_FCOE_WORD_TO_BYTE;
	fhs->rx_frames += (fcoe_port_stats.rx_bcast_frames +
				fcoe_port_stats.rx_mcast_frames +
				fcoe_port_stats.rx_ucast_frames);
	fhs->rx_words += (fcoe_port_stats.rx_bcast_bytes +
				fcoe_port_stats.rx_mcast_bytes +
				fcoe_port_stats.rx_ucast_bytes) / CSIO_FCOE_WORD_TO_BYTE;
	fhs->error_frames += fcoe_port_stats.rx_err_frames;
	fhs->fcp_input_requests +=  osln->lnode.stats.n_input_requests;
	fhs->fcp_output_requests +=  osln->lnode.stats.n_output_requests;
	fhs->fcp_control_requests +=  osln->lnode.stats.n_control_requests;
	fhs->fcp_input_megabytes +=  osln->lnode.stats.n_input_bytes >> 20;
	fhs->fcp_output_megabytes +=  osln->lnode.stats.n_output_bytes >> 20;
	fhs->link_failure_count = osln->lnode.un.lnf.stats.n_link_down;
	/* Reset stats for the device */
	seconds = csio_os_msecs();
	fhs->seconds_since_last_reset = seconds - hw->stats.n_reset_start;
	do_div(fhs->seconds_since_last_reset, 1000);

	return fhs;
}

/*
 * csio_set_rport_loss_tmo - Set the rport dev loss timeout
 * @rport: fc rport.
 * @timeout: new value for dev loss tmo.
 *
 * If timeout is non zero set the dev_loss_tmo to timeout, else set
 * dev_loss_tmo to one.
 */
static void
csio_set_rport_loss_tmo(struct fc_rport *rport, uint32_t timeout)
{
	if (timeout)
		rport->dev_loss_tmo = timeout;
	else
		rport->dev_loss_tmo = 1;
}

static void
csio_vport_set_state(struct csio_lnode_fcoe *lnf)
{
	struct csio_os_lnode *osln = csio_lnode_to_os(lnf->ln);
	struct fc_vport *fc_vport = osln->fc_vport;
	struct csio_lnode  *pln = lnf->ln->pln;
	struct csio_lnode_fcoe *plnf = csio_lnode_to_fcoe(pln);
	char state[16];

	/* Set fc vport state based on phyiscal lnode */
	csio_lnf_stateto_str(plnf, state);	
	if (strcmp(state, "READY")) {
		fc_vport_set_state(fc_vport, FC_VPORT_LINKDOWN);
		return;
	}	

	if (!(plnf->flags & CSIO_LNFFLAG_NPIVSUPP)) {
		fc_vport_set_state(fc_vport, FC_VPORT_NO_FABRIC_SUPP);
		return;
	}	

	/* Set fc vport state based on virtual lnode */
	csio_lnf_stateto_str(lnf, state);	
	if (strcmp(state, "READY")) {
		fc_vport_set_state(fc_vport, FC_VPORT_LINKDOWN);
		return;
	}
	fc_vport_set_state(fc_vport, FC_VPORT_ACTIVE);
}	

static csio_retval_t
csio_fcoe_alloc_vnp(struct csio_hw *hw, struct csio_lnode_fcoe *lnf)
{
	struct adapter *adap = &hw->adap;
	struct csio_lnode_fcoe *plnf;
	struct fw_fcoe_vnp_cmd c, *rsp;
	int retry = 0, ret;

	/* Issue VNP cmd to alloc vport */
	/* Allocate Mbox request */
	csio_spin_lock_irq(hw, &hw->lock);

	plnf = csio_lnode_to_fcoe(lnf->ln->pln);
	lnf->fcf_flowid = plnf->fcf_flowid;
	lnf->ln->portid = plnf->ln->portid;
	
	csio_fcoe_vnp_alloc_init_mb(&c, plnf->fcf_flowid, plnf->vnp_flowid, 0,
			csio_lnf_wwnn(lnf), csio_lnf_wwpn(lnf));
	
	for (retry = 0; retry < 3; retry++) {
		/* FW is expected to complete vnp cmd in immediate mode
		 * without much delay.
		 * Otherwise, there will be increase in IO latency since HW
		 * lock is held till completion of vnp mbox cmd.
		 */
		csio_spin_unlock_irq(hw, &hw->lock);
		ret = t4_wr_mbox(adap, adap->mbox, &c, sizeof(c), &c);
		if (ret != CSIO_BUSY) {
			csio_spin_lock_irq(hw, &hw->lock);
			break;
		}	
		/* Retry if mbox returns busy */
		csio_msleep(2000);
		csio_spin_lock_irq(hw, &hw->lock);
	}

	if (ret != CSIO_SUCCESS) {
		csio_ln_err(lnf->ln, "FCOE VNP ALLOC cmd returned 0x%x!\n",
				ret);
		csio_spin_unlock_irq(hw, &hw->lock);
		return ret;
	}	

	/* Process Mbox response of VNP command */
	rsp = &c;

	lnf->vnp_flowid = G_FW_FCOE_VNP_CMD_VNPI(
				csio_ntohl(rsp->gen_wwn_to_vnpi));
	csio_memcpy(csio_lnf_wwnn(lnf), rsp->vnport_wwnn, 8);
	csio_memcpy(csio_lnf_wwpn(lnf), rsp->vnport_wwpn, 8);

	csio_ln_dbg(lnf->ln, "FCOE VNPI: 0x%x\n", lnf->vnp_flowid);
	csio_ln_dbg(lnf->ln, "\tWWNN: %x%x%x%x%x%x%x%x\n",
		    lnf->ln_sparm.wwnn[0], lnf->ln_sparm.wwnn[1],
		    lnf->ln_sparm.wwnn[2], lnf->ln_sparm.wwnn[3],
		    lnf->ln_sparm.wwnn[4], lnf->ln_sparm.wwnn[5],
		    lnf->ln_sparm.wwnn[6], lnf->ln_sparm.wwnn[7]);
	csio_ln_dbg(lnf->ln, "\tWWPN: %x%x%x%x%x%x%x%x\n",
		    lnf->ln_sparm.wwpn[0], lnf->ln_sparm.wwpn[1],
		    lnf->ln_sparm.wwpn[2], lnf->ln_sparm.wwpn[3],
		    lnf->ln_sparm.wwpn[4], lnf->ln_sparm.wwpn[5],
		    lnf->ln_sparm.wwpn[6], lnf->ln_sparm.wwpn[7]);

	csio_spin_unlock_irq(hw, &hw->lock);
	return CSIO_SUCCESS;
}

static csio_retval_t
csio_fcoe_free_vnp(struct csio_hw *hw, struct csio_lnode_fcoe *lnf)
{
	struct adapter *adap = &hw->adap;
	struct fw_fcoe_vnp_cmd c;
	struct csio_lnode_fcoe *plnf;
	int retry = 0, ret;
	
	/* Issue VNP cmd to free vport */
	/* Allocate Mbox request */
	csio_spin_lock_irq(hw, &hw->lock);

	plnf = csio_lnode_to_fcoe(lnf->ln->pln);
	
	csio_fcoe_vnp_free_init_mb(&c, lnf->fcf_flowid, lnf->vnp_flowid);

	for (retry = 0; retry < 3; retry++) {
		csio_spin_unlock_irq(hw, &hw->lock);
		ret = t4_wr_mbox(adap, adap->mbox, &c, sizeof(c), &c);
		if (ret != CSIO_BUSY) {
			csio_spin_lock_irq(hw, &hw->lock);
			break;
		}	
		/* Retry if mbox returns busy */
		csio_msleep(2000);
		csio_spin_lock_irq(hw, &hw->lock);
	}

	if (ret) {
		csio_ln_err(lnf->ln, "FCOE VNP FREE cmd returned 0x%x!\n",
			       	ret);
		csio_spin_unlock_irq(hw, &hw->lock);
		return CSIO_INVAL;
	}

	csio_spin_unlock_irq(hw, &hw->lock);
	return CSIO_SUCCESS;
}

static int
csio_vport_create(struct fc_vport *fc_vport, bool disable)
{
	struct Scsi_Host *shost = fc_vport->shost;
	struct csio_os_lnode *os_pln = shost_priv(shost);
	struct csio_lnode_fcoe *lnf;
	struct csio_os_lnode *osln = NULL;
	struct csio_os_hw *oshw = csio_osln_to_oshw(os_pln);
	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	uint8_t wwn[8];
	int ret = -1;

#ifdef __CSIO_TARGET__
	/*
	 * Disable NPIV when not in initiator mode. Also see
	 * csio_rnf_verify_rparams().
	 */
	if (!csio_initiator_mode(hw)) {
		csio_err(hw, "Need initiator mode for NPIV.\n");
		goto error;
	}
#endif /* __CSIO_TARGET__ */

	osln = csio_oslnode_init(oshw, &fc_vport->dev, CSIO_FALSE, os_pln); 	
	if (!osln) {
		goto error;
	}	
	lnf = csio_lnode_to_fcoe(csio_osln_to_ln(osln));

	if (fc_vport->node_name != 0) {
		 u64_to_wwn(fc_vport->node_name, wwn);

		if (!CSIO_VALID_WWN(wwn)) {
			csio_ln_err(lnf->ln,
				    "vport create failed. Invalid wwnn\n");
			goto error;
		}
		memcpy(csio_lnf_wwnn(lnf), wwn, 8);
	}	

	if (fc_vport->port_name != 0) {
		 u64_to_wwn(fc_vport->port_name, wwn);
		
		if (!CSIO_VALID_WWN(wwn)) {
			csio_ln_err(lnf->ln,
				    "vport create failed. Invalid wwpn\n");
			goto error;
		}

		if (csio_lnf_lookup_by_wwpn(hw, wwn)) {
			csio_ln_err(lnf->ln,
			    "vport create failed. wwpn already exists\n");
			goto error;
		}
		memcpy(csio_lnf_wwpn(lnf), wwn, 8);
	}

	fc_vport_set_state(fc_vport, FC_VPORT_INITIALIZING);
	if (csio_fcoe_alloc_vnp(hw, lnf)) {
		goto error;
	}	

	*(struct csio_os_lnode **)fc_vport->dd_data = osln;
	osln->fc_vport = fc_vport;
	if (!fc_vport->node_name)
		fc_vport->node_name = wwn_to_u64(csio_lnf_wwnn(lnf));
	if (!fc_vport->port_name)
		fc_vport->port_name = wwn_to_u64(csio_lnf_wwpn(lnf));
	csio_fchost_attr_init(osln);
	return 0;
error:
	if (osln) {
		csio_oslnode_exit(osln);
	}	
	return ret;
}

static int
csio_vport_delete(struct fc_vport *fc_vport)
{
	struct csio_os_lnode *osln = *(struct csio_os_lnode **)
					fc_vport->dd_data;
	struct Scsi_Host *shost = csio_osln_to_shost(osln);
	struct csio_lnode_fcoe *lnf;
	struct csio_os_hw *oshw = csio_osln_to_oshw(osln);
	struct csio_hw *hw = csio_oshw_to_hw(oshw);

	csio_spin_lock_irq(hw, &hw->lock);
	if (csio_is_hw_removing(hw)) {
		csio_spin_unlock_irq(hw, &hw->lock);
		csio_oslnode_exit(osln);	
		return 0;
	}
	csio_spin_unlock_irq(hw, &hw->lock);

	/* Quiesce ios and send remove event to lnode */
	scsi_block_requests(shost);
	csio_spin_lock_irq(hw, &hw->lock);
	csio_scsim_cleanup_io_lnode(csio_hw_to_scsim(hw),
			csio_osln_to_ln(osln));
	lnf = csio_lnode_to_fcoe(csio_osln_to_ln(osln));

	/* Flush all the events, so that any rnode removal events
 	 * already queued are all handled, before we close the lnode.
 	 */
	csio_evtq_flush(hw);
	csio_lnf_close(lnf);	
	csio_spin_unlock_irq(hw, &hw->lock);
	scsi_unblock_requests(shost);

	/* Free vnp */
	if (fc_vport->vport_state !=  FC_VPORT_DISABLED)
		csio_fcoe_free_vnp(hw, lnf);
	csio_ln_err(lnf->ln, "vport deleted\n");
	csio_oslnode_exit(osln);	
	return 0;
}

static int
csio_vport_disable(struct fc_vport *fc_vport, bool disable)
{
	struct csio_os_lnode *osln = *(struct csio_os_lnode **)
					fc_vport->dd_data;
	struct Scsi_Host *shost = csio_osln_to_shost(osln);
	struct csio_lnode_fcoe *lnf = csio_lnode_to_fcoe(csio_osln_to_ln(osln));
	struct csio_os_hw *oshw = csio_osln_to_oshw(osln);
	struct csio_hw *hw = csio_oshw_to_hw(oshw);

	/* disable vport */
	if (disable) {
		/* Quiesce ios and send stop event to lnode */
		scsi_block_requests(shost);
		csio_spin_lock_irq(hw, &hw->lock);
		csio_scsim_cleanup_io_lnode(csio_hw_to_scsim(hw),
				csio_osln_to_ln(osln));
		lnf = csio_lnode_to_fcoe(csio_osln_to_ln(osln));
		csio_lnf_stop(lnf);	
		csio_spin_unlock_irq(hw, &hw->lock);
		scsi_unblock_requests(shost);

		/* Free vnp */
		csio_fcoe_free_vnp(hw, lnf);
		fc_vport_set_state(fc_vport, FC_VPORT_DISABLED);
		csio_ln_err(lnf->ln, "vport disabled\n");
		return 0;
	}
	else {
		/* enable vport */
		fc_vport_set_state(fc_vport, FC_VPORT_INITIALIZING);
		if (csio_fcoe_alloc_vnp(hw, lnf)) {
			csio_ln_err(lnf->ln, "vport enabled failed.\n");
			return -1;
		}	
		csio_ln_err(lnf->ln, "vport enabled\n");
		return 0;
	}	
}	

static void
csio_terminate_rport_io(struct fc_rport *rport)
{
#if 0
	struct csio_os_rnode *osrn;
	struct csio_rnode *rn;
	struct csio_rnode_fcoe *rnf;
	char state[16];

	/* TODO: Send Abort on outstanding IOs on this rnode */
	osrn = *((struct csio_os_rnode **)rport->dd_data);
	rn = &osrn->rnode;
	rnf = csio_rnode_to_fcoe(rn);
	csio_rnf_stateto_str(rnf, state);	
	csio_ln_dbg(rn->lnp, "Terminate Remote port x%x state %s\n",
			rnf->nport_id, state);
#endif
}

static void
csio_dev_loss_tmo_callbk(struct fc_rport *rport)
{
	struct csio_os_rnode *osrn;
	struct csio_rnode *rn;
	struct csio_lnode *ln;
	struct csio_hw *hw;
	struct csio_rnode_fcoe *rnf;
	struct csio_lnode_fcoe *lnf;

	osrn = *((struct csio_os_rnode **)rport->dd_data);
	rn = &osrn->rnode;
	ln = csio_rnode_to_lnode(rn);
	hw = csio_lnode_to_hw(ln);
	lnf = csio_lnode_to_fcoe(ln);
	rnf = csio_rnode_to_fcoe(rn);

	CSIO_TRACE(hw, CSIO_RNODE_MOD, CSIO_DBG_LEV,
		rnf,
		csio_rnf_flowid(rnf),
		rnf->nport_id,
		lnf->vnp_flowid);

	csio_spin_lock_irq(hw, &hw->lock);
	/* return if driver is being removed or same rnode comes back online */
	if (csio_is_hw_removing(hw) || csio_is_rnf_ready(rnf)) {
		csio_spin_unlock_irq(hw, &hw->lock);
		return;
	}
	csio_ln_dbg(ln, "devloss timeout occured on rnode:%p portid:x%x "
		"flowid:x%x\n",	rnf, rnf->nport_id, csio_rnf_flowid(rnf));
	CSIO_INC_STATS(lnf, n_dev_loss_tmo);

	/* enqueue devloss event to event worker thread to serialize all
	 * rnode events.
	 */
	if (csio_enqueue_evt(hw, CSIO_EVT_DEV_LOSS, &rnf, sizeof(rnf))) {
		CSIO_INC_STATS(hw, n_evt_drop);
		csio_spin_unlock_irq(hw, &hw->lock);
		return;
	}

	if (!(hw->flags & CSIO_HWF_FWEVT_PENDING)) {
		hw->flags |= CSIO_HWF_FWEVT_PENDING;
		csio_spin_unlock_irq(hw, &hw->lock);
		csio_work_schedule(&hw->evtq_work);
		return;
	}
	csio_spin_unlock_irq(hw, &hw->lock);
	return;
}

/* FC transport functions template - Physical port */
struct fc_function_template csio_fc_transport_funcs = {
	.show_host_node_name = 1,
	.show_host_port_name = 1,
	.show_host_supported_classes = 1,
	.show_host_supported_fc4s = 1,
	.show_host_maxframe_size = 1,

	.get_host_port_id = csio_get_host_port_id,
	.show_host_port_id = 1,

	.get_host_port_type = csio_get_host_port_type,
	.show_host_port_type = 1,

	.get_host_port_state = csio_get_host_port_state,
	.show_host_port_state = 1,

	.show_host_active_fc4s = 1,
	.get_host_speed = csio_get_host_speed,
	.show_host_speed = 1,
	.get_host_fabric_name = csio_get_host_fabric_name,
	.show_host_fabric_name = 1,

	.get_fc_host_stats = csio_get_stats,

	.dd_fcrport_size = sizeof(struct csio_os_rnode *),
	.show_rport_maxframe_size = 1,
	.show_rport_supported_classes = 1,

	.set_rport_dev_loss_tmo = csio_set_rport_loss_tmo,
	.show_rport_dev_loss_tmo = 1,

	.show_starget_port_id = 1,
	.show_starget_node_name = 1,
	.show_starget_port_name = 1,

	.dev_loss_tmo_callbk = csio_dev_loss_tmo_callbk,
	.terminate_rport_io = csio_terminate_rport_io,
	.dd_fcvport_size = sizeof(struct csio_os_lnode *),

	.vport_create = csio_vport_create,
	.vport_disable = csio_vport_disable,
	.vport_delete = csio_vport_delete,
};

/* FC transport functions template - Virtual  port */
struct fc_function_template csio_fc_transport_vport_funcs = {
	.show_host_node_name = 1,
	.show_host_port_name = 1,
	.show_host_supported_classes = 1,
	.show_host_supported_fc4s = 1,
	.show_host_maxframe_size = 1,

	.get_host_port_id = csio_get_host_port_id,
	.show_host_port_id = 1,

	.get_host_port_type = csio_get_host_port_type,
	.show_host_port_type = 1,

	.get_host_port_state = csio_get_host_port_state,
	.show_host_port_state = 1,
	.show_host_active_fc4s = 1,

	.get_host_speed = csio_get_host_speed,
	.show_host_speed = 1,

	.get_host_fabric_name = csio_get_host_fabric_name,
	.show_host_fabric_name = 1,

	.get_fc_host_stats = csio_get_stats,

	.dd_fcrport_size = sizeof(struct csio_os_rnode *),
	.show_rport_maxframe_size = 1,
	.show_rport_supported_classes = 1,

	.set_rport_dev_loss_tmo = csio_set_rport_loss_tmo,
	.show_rport_dev_loss_tmo = 1,

	.show_starget_port_id = 1,
	.show_starget_node_name = 1,
	.show_starget_port_name = 1,

	.dev_loss_tmo_callbk = csio_dev_loss_tmo_callbk,
	.terminate_rport_io = csio_terminate_rport_io,

};

/* FCOE IOCTL interfaces */

/**
 *
 * csio_os_create_npiv_vport
 * @hw - HW module
 * @buffer - IOCTL buffer
 * @len    - IOCTL buffer len
 * This routine handles the IOCTL request to create a particular NPIV
 */
int
csio_os_create_npiv_vport(struct csio_hw *hw, void *buffer,int len)
{
	npiv_params_t *npiv = (npiv_params_t *) buffer;
	struct csio_lnode_fcoe *plnf = NULL;
	struct fc_vport_identifiers vport_id;
	struct csio_os_lnode *osln = NULL;
	struct Scsi_Host *shost = NULL;

	if (len < sizeof(npiv_params_t))
		return -EINVAL;

	if (CSIO_VALID_WWN(npiv->parent_wwnn)) {
		plnf = csio_lnf_lookup_by_wwnn(hw, npiv->parent_wwnn);
		if (plnf == NULL) {
			u8 *wwn = npiv->parent_wwpn;
			csio_err(hw,
				"csio_os_create_npiv_vport: Hw(%p) "
				"Couldn't able to find parent Lnode "
				"[%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x]\n",
				hw, wwn[0], wwn[1], wwn[2],
				wwn[3], wwn[4], wwn[5], wwn[6], wwn[7]);

			npiv->npiv_status = CSIO_NPIV_WWPN_NOT_FOUND;
			return 0;
		}
	} /* if (CSIO_VALID_WWN) */
	else {
		npiv->npiv_status = CSIO_NPIV_WWPN_INVALID_FORMAT;
		return 0;
	}

	osln = csio_lnode_to_os(plnf->ln);
	shost = csio_osln_to_shost(osln);
	memset(&vport_id, 0, sizeof(vport_id));
	vport_id.port_name = wwn_to_u64(npiv->npiv_wwpn);
	vport_id.node_name = wwn_to_u64(npiv->npiv_wwnn);
	vport_id.roles = FC_PORT_ROLE_FCP_INITIATOR;
	vport_id.vport_type = FC_PORTTYPE_NPIV;
	vport_id.disable = false;
	if (!fc_vport_create(shost, 0, &vport_id)) {
       		return -EINVAL;
	}
	return 0;
} /* csio_os_create_npiv_vport */

/**
 *
 * csio_os_delete_npiv_vport
 * @hw - HW module
 * @buffer - IOCTL buffer
 * @len    - IOCTL buffer len
 * This routine handles the IOCTL request to delete particular NPIV
 */
int
csio_os_delete_npiv_vport(struct csio_hw *hw, void *buffer,int len)
{
	npiv_params_t *npiv = (npiv_params_t *) buffer;
	struct csio_lnode_fcoe *lnf = NULL;
	struct csio_os_lnode *osln = NULL;

	if (len < sizeof(npiv_params_t))
		return -EINVAL;

	if (CSIO_VALID_WWN(npiv->npiv_wwpn)) {
		lnf = csio_lnf_lookup_by_wwpn(hw, npiv->npiv_wwpn);
		if (lnf == NULL) {
			u8 *wwn = npiv->npiv_wwpn;
			csio_err(hw,
				"csio_os_delete_npiv_vport: Hw(%p) "
				"Couldn't able to find parent Lnode "
				"[%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x]\n",
				hw, wwn[0], wwn[1], wwn[2],
				wwn[3], wwn[4], wwn[5], wwn[6], wwn[7]);
			
			npiv->npiv_status = CSIO_NPIV_WWPN_NOT_FOUND;
			return 0;
		}

		if (!csio_is_npiv_lnf(lnf)) {
			npiv->npiv_status = CSIO_NPIV_WWPN_NOT_FOUND;
			return 0;
		}
	} /* if (CSIO_VALID_WWN) */
	else
		return -EINVAL;

	osln = csio_lnode_to_os(lnf->ln);
	if (fc_vport_terminate(osln->fc_vport)) {
       		return -EINVAL;
	}
	return 0;
} /* csio_os_delete_npiv_vport */

/**
 *
 * csio_os_list_npiv_vport
 * @hw - HW module
 * @buffer - IOCTL buffer
 * @len    - IOCTL buffer len
 * This routine handles the IOCTL request to list NPIV ports behind the
 * specified lnode.
 */
int
csio_os_list_npiv_vport(struct csio_hw *hw, void *buffer, int len)
{
	npiv_port_list_t *npiv		= buffer;
	struct csio_os_lnode *os_pln	= NULL;
	struct csio_lnode_fcoe 		*lnf = NULL;
	size_t req_buf_size		= 0;
	uint32_t count			= 0;

	/*
	 * We need atleast NPIV_PORT_LIST_HDR_SIZE to convey
	 * no.of NPIV/Vports available for this LNode!
	 *
	 */
	if (len < NPIV_PORT_LIST_HDR_SIZE)
		return -EINVAL;

	if (CSIO_VALID_WWN(npiv->parent_wwpn))	{
		lnf = csio_lnf_lookup_by_wwpn(hw, npiv->parent_wwpn);

		if (lnf == NULL) {
			uint8_t *wwn = npiv->parent_wwpn;

			csio_err(hw,
				"csio_os_list_npiv_vport: Hw(%p) "
				"Couldn't able to find the parent Lnode "
				"[%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x]\n",
				hw, wwn[0], wwn[1], wwn[2],
				wwn[3], wwn[4], wwn[5], wwn[6], wwn[7]);

			return -EINVAL;
		}
		os_pln = csio_lnode_to_os(lnf->ln);
	}
	else
		return -EINVAL;

	/*
	 * Acquire the lock, before traversing the LNode list!
	 *
	 */
	csio_spin_lock_irq(hw, &hw->lock);

	npiv->count = lnf->ln->num_vports;

	req_buf_size = NPIV_PORT_LIST_HDR_SIZE +
				(npiv->count * sizeof(NPIV_PORT_INFO));

	if (npiv->count && len >= req_buf_size) {
		struct csio_list *cur_cln, *next_cln;
		struct csio_lnode *cln = NULL;
		struct csio_lnode_fcoe *clnf = NULL;

		/*
		 * Traverse children lnodes.
		 *
		 */
		csio_list_for_each_safe(cur_cln, next_cln, &lnf->ln->cln_head) {
			cln	= (struct csio_lnode *) cur_cln;
			clnf	= csio_lnode_to_fcoe(cln);

			csio_memcpy(npiv->npiv_list[count].npiv_wwpn,
					csio_lnf_wwpn(clnf), 8);
			csio_memcpy(npiv->npiv_list[count].npiv_wwnn,
					csio_lnf_wwnn(clnf), 8);
			csio_memcpy(npiv->npiv_list[count].mac,
							clnf->mac, 6);
			npiv->npiv_list[count].nport_id = clnf->nport_id;

			count++;
		}

		CSIO_DB_ASSERT(count == npiv->count);
	}

	/*
	 * Release the lock.
	 *
	 */
	csio_spin_unlock_irq(hw, &hw->lock);

	return 0;
} /* csio_os_list_npiv_vport */

