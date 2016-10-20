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
#include <csio_lnode.h>
#include <csio_rnode.h>
#include <csio_fcoe_proto.h>
#include <csio_fcoe_ioctl.h>

/* Static machine forward declarations */
static void csio_rnfs_uninit(struct csio_rnode_fcoe *, csio_rnf_ev_t);
static void csio_rnfs_ready(struct csio_rnode_fcoe *, csio_rnf_ev_t);
static void csio_rnfs_offline(struct csio_rnode_fcoe *, csio_rnf_ev_t);
static void csio_rnfs_disappeared(struct csio_rnode_fcoe *, csio_rnf_ev_t);

/* FW event name */
static const char *fwevt_names[] = {
	"FW_INVALID_EVT", 	/* None */
	"PLOGI_ACC_RCVD", 	/* PLOGI_ACC_RCVD  */
	"PLOGI_RJT_RCVD", 	/* PLOGI_RJT_RCVD  */
	"PLOGI_RCVD",	  	/* PLOGI_RCVD      */
	"PLOGO_RCVD",	 	/* PLOGO_RCVD      */
	"PRLI_ACC_RCVD", 	/* PRLI_ACC_RCVD   */
	"PRLI_RJT_RCVD",  	/* PRLI_RJT_RCVD   */
	"PRLI_RCVD", 		/* PRLI_RCVD       */
	"PRLO_RCVD",		/* PRLO_RCVD       */
	"NPORT_ID_CHGD",	/* NPORT_ID_CHGD   */
	"FLOGO_RCVD",  		/* FLOGO_RCVD      */
	"CLR_VIRT_LNK_RCVD",	/* CLR_VIRT_LNK_RCVD */
	"FLOGI_ACC_RCVD", 	/* FLOGI_ACC_RCVD   */
	"FLOGI_RJT_RCVD",	/* FLOGI_RJT_RCVD   */
	"FDISC_ACC_RCVD",	/* FDISC_ACC_RCVD   */
	"FDISC_RJT_RCVD",	/* FDISC_RJT_RCVD */
	"FLOGI_TMO_MAX_RETRY",  /* FLOGI_TMO_MAX_RETRY */
	"IMPL_LOGO_ADISC_ACC",  /* IMPL_LOGO_ADISC_ACC */
	"IMPL_LOGO_ADISC_RJT",  /* IMPL_LOGO_ADISC_RJT */
	"IMPL_LOGO_ADISC_CNFLT",/* IMPL_LOGO_ADISC_CNFLT */
	"PRLI_TMO",   		/* PRLI_TMO */
	"ADISC_TMO", 		/* ADISC_TMO */
	"RSCN_DEV_LOST",	/* RSCN_DEV_LOST  */
	"SCR_ACC_RCVD", 	/* SCR_ACC_RCVD */
	"ADISC_RJT_RCVD",	/* ADISC_RJT_RCVD */
	"LOGO_SNT",		/* LOGO_SNT */
	"PROTO_ERR_IMPL_LOGO",	/* PROTO_ERR_IMPL_LOGO */
};

/* Rnode event name */
static const char *rnfevt_names[] = {
	"CSIO_RNFE_NONE", 	
	"CSIO_RNFE_LOGIN",	
	"CSIO_RNFE_DO_ADISC",
	"CSIO_RNFE_ADISC_ACC",
	"CSIO_RNFE_ADISC_REJ",
	"CSIO_RNFE_LOGGED_IN",
	"CSIO_RNFE_PRLI_DONE",
	"CSIO_RNFE_PLOGI_RECV",
	"CSIO_RNFE_PRLI_RECV",
	"CSIO_RNFE_LOGO_RECV",
	"CSIO_RNFE_PRLO_RECV",
	"CSIO_RNFE_DOWN",
	"CSIO_RNFE_CLOSE",
	"CSIO_RNFE_NAME_MISSING"
};

/* RNF event mapping */
static csio_rnf_ev_t	fwevt_to_rnfevt[] = {
	CSIO_RNFE_NONE,		/* None */	
	CSIO_RNFE_LOGGED_IN,	/* PLOGI_ACC_RCVD  */
	CSIO_RNFE_NONE, 	/* PLOGI_RJT_RCVD  */
	CSIO_RNFE_PLOGI_RECV,	/* PLOGI_RCVD	   */
	CSIO_RNFE_LOGO_RECV,	/* PLOGO_RCVD	   */
	CSIO_RNFE_PRLI_DONE,	/* PRLI_ACC_RCVD   */
	CSIO_RNFE_NONE,		/* PRLI_RJT_RCVD   */
	CSIO_RNFE_PRLI_RECV,	/* PRLI_RCVD	   */
	CSIO_RNFE_PRLO_RECV,	/* PRLO_RCVD	   */
	CSIO_RNFE_NONE,		/* NPORT_ID_CHGD   */
	CSIO_RNFE_LOGO_RECV,	/* FLOGO_RCVD	   */	
	CSIO_RNFE_NONE,		/* CLR_VIRT_LNK_RCVD */
	CSIO_RNFE_LOGGED_IN,	/* FLOGI_ACC_RCVD   */
	CSIO_RNFE_NONE,		/* FLOGI_RJT_RCVD   */
	CSIO_RNFE_LOGGED_IN,	/* FDISC_ACC_RCVD   */
	CSIO_RNFE_NONE,		/* FDISC_RJT_RCVD   */
	CSIO_RNFE_NONE,		/* FLOGI_TMO_MAX_RETRY */
	CSIO_RNFE_NONE,		/* IMPL_LOGO_ADISC_ACC */
	CSIO_RNFE_NONE,		/* IMPL_LOGO_ADISC_RJT */
	CSIO_RNFE_NONE,		/* IMPL_LOGO_ADISC_CNFLT */
	CSIO_RNFE_NONE,		/* PRLI_TMO		*/
	CSIO_RNFE_NONE,		/* ADISC_TMO		*/
	CSIO_RNFE_NAME_MISSING,	/* RSCN_DEV_LOST  */
	CSIO_RNFE_NONE,		/* SCR_ACC_RCVD	*/	
	CSIO_RNFE_NONE,		/* ADISC_RJT_RCVD */	
	CSIO_RNFE_NONE,		/* LOGO_SNT */
	CSIO_RNFE_LOGO_RECV,	/* PROTO_ERR_IMPL_LOGO */
};

#define CSIO_FWE_TO_RNFE(_evt)	((_evt > PROTO_ERR_IMPL_LOGO)?		\
						CSIO_RNFE_NONE : 	\
						fwevt_to_rnfevt[_evt])
int
csio_is_rnf_ready(struct csio_rnode_fcoe *rnf)
{
	return csio_match_state(rnf, csio_rnfs_ready);
}

int
csio_is_rnf_uninit(struct csio_rnode_fcoe *rnf)
{
	return csio_match_state(rnf, csio_rnfs_uninit);
}

/* To check whether the port is well known address or regular n-port */
static int
csio_is_rnf_wka( uint8_t rport_type)
{
	if ((rport_type == FLOGI_VFPORT) ||
		(rport_type == FDISC_VFPORT) ||
		(rport_type == NS_VNPORT) ||
		(rport_type == FDMI_VNPORT)) {
		return 1;
	}
	return 0;
}
/*****************************************************************************/
/* FCoE Rnode Protocol handling routines                                     */
/*****************************************************************************/

/**
 * csio_rnf_lookup_wwpn - Finds the rnode with the given wwpn
 * @lnf: lnode
 * @wwpn: wwpn
 *
 * Does the rnode lookup on the given lnode and wwpn. If no matching entry
 * found, NULL is returned.
 */
struct csio_rnode_fcoe *
csio_rnf_lookup_wwpn(struct csio_lnode_fcoe *lnf, uint8_t *wwpn)
{
	struct csio_rnode *rnhead = (struct csio_rnode *) &lnf->ln->rnhead;
	struct csio_list *tmp;
	struct csio_rnode *rn;
	struct csio_rnode_fcoe *rnf;

	csio_list_for_each(tmp, &rnhead->rnlist) {
		rn = (struct csio_rnode *) tmp;
		rnf = csio_rnode_to_fcoe(rn);
		if (!csio_memcmp(csio_rnf_wwpn(rnf), wwpn, 8))
			return rnf;
	}

	return NULL;
}

/**
 * csio_rnf_lookup_portid - Finds the rnode with the given portid
 * @lnf: lnode
 * @portid: port id
 *
 * Does the rnode lookup on the given lnode and portid. If no matching entry
 * found, NULL is returned.
 */
struct csio_rnode_fcoe *
csio_rnf_lookup_portid(struct csio_lnode_fcoe *lnf, uint32_t portid)
{
	struct csio_rnode *rnhead = (struct csio_rnode *) &lnf->ln->rnhead;
	struct csio_list *tmp;
	struct csio_rnode *rn;
	struct csio_rnode_fcoe *rnf;

	csio_list_for_each(tmp, &rnhead->rnlist) {
		rn = (struct csio_rnode *) tmp;
		rnf = csio_rnode_to_fcoe(rn);
		if (rnf->nport_id == portid)
			return rnf;
	}

	return NULL;
}

static int
csio_rnf_dup_flowid(struct csio_lnode *ln, uint32_t rdev_flowid,
		    uint32_t *vnp_flowid)
{
	struct csio_rnode *rnhead;
	struct csio_list *tmp, *tmp1;
	struct csio_rnode *rn;
	struct csio_lnode *ln_tmp;
	struct csio_hw *hw = csio_lnode_to_hw(ln);

	csio_list_for_each(tmp1, &hw->sln_head) {
		ln_tmp = (struct csio_lnode *) tmp1;
		if (ln_tmp == ln)
			continue;

		rnhead = (struct csio_rnode *)&ln_tmp->rnhead;
		csio_list_for_each(tmp, &rnhead->rnlist) {

			rn = (struct csio_rnode *) tmp;
			if (csio_is_rnf_ready(csio_rnode_to_fcoe(rn))) {
				if (rn->flowid == rdev_flowid) {
					*vnp_flowid = csio_lnf_flowid(
						csio_lnode_to_fcoe(ln_tmp));
					return 1;
				}
			}
		}
	}

	return 0;
}

/**
 * csio_rnf_confirm_rnode - confirms rnode based on wwpn.
 * @lnf: FCoE lnode
 * @rdev_flowid: remote device flowid
 * @rdevp: remote device params
 * This routines searches other rnode in list having same wwpn of new rnode.
 * If there is a match, then matched rnode is returned and otherwise new rnode
 * is returned.
 * returns rnode.
 */
struct csio_rnode_fcoe *
csio_rnf_confirm_rnode(struct csio_lnode_fcoe *lnf,
			uint32_t rdev_flowid,
			struct fcoe_rdev_entry *rdevp)
{
	uint8_t rport_type;
	struct csio_rnode_fcoe *rnf, *match_rnf;
	struct csio_rnode *rn;
	uint32_t vnp_flowid;
	__be32 *port_id;
	
	port_id = (__be32 *)&rdevp->r_id[0];
	rport_type = G_FW_RDEV_WR_RPORT_TYPE(rdevp->rd_xfer_rdy_to_rport_type);
	/* Drop rdev event for cntrl port */
	if (rport_type == FAB_CTLR_VNPORT) {
		csio_ln_dbg(lnf->ln, "Unhandled rport_type:%d recv in rdev evt "
				"ssni:x%x\n", rport_type, rdev_flowid);
		return NULL;
	}

	/* Lookup on flowid */
	rn = csio_rn_lookup(lnf->ln, rdev_flowid);
	if (!rn) {

		/* Drop events with duplicate flowid */
		if (csio_rnf_dup_flowid(lnf->ln, rdev_flowid, &vnp_flowid)) {
			csio_ln_warn(lnf->ln, "ssni:%x already active on"
				     " vnpi:%x", rdev_flowid, vnp_flowid);
			csio_assert_fw(csio_lnode_to_hw(lnf->ln));
			return NULL;
		}

		/* Lookup on wwpn for NPORTs */
		rnf = csio_rnf_lookup_wwpn(lnf, rdevp->wwpn);
		if (!rnf) {
			goto alloc_rnode;
		}
		/* found rnf */
		goto found_rnode;
	} else {
		rnf = csio_rnode_to_fcoe(rn);
		/*
		 * Verify rnode found for fabric ports, cntrl port
		 * There might be cases where the wwpn of these ports is NULL
		 * So checking with the nport_id
		 */
		if (csio_is_rnf_wka(rport_type)) {
			match_rnf = csio_rnf_lookup_portid(lnf, ((csio_ntohl(*port_id) >> 8) & DID_MASK));
			if (match_rnf == NULL) {
				csio_rnf_flowid(rnf) = CSIO_INVALID_IDX;
				goto alloc_rnode;
			}
			/*
			 * Now compare the wwpn to confirm that
			 * same port relogged in.If so update the matched rnf.
			 * Else, go ahead and alloc a new rnode.
			 */
			if (!csio_memcmp(csio_rnf_wwpn(match_rnf), rdevp->wwpn, 8)) {
				if (rnf == match_rnf)
					goto found_rnode;
				csio_ln_dbg(lnf->ln,
					"nport_id:x%x and wwpn:%llx match for ssni:x%x\n",
					(rnf->nport_id),
					csio_wwn_to_u64(rdevp->wwpn),rdev_flowid);
				if (csio_is_rnf_ready(rnf)) {
					csio_ln_warn(lnf->ln, "rnode is already"
						"active ssni:x%x\n",
						rdev_flowid);
					CSIO_DB_ASSERT(0);
				}
				/* update rnf */
				csio_rnf_flowid(rnf) = CSIO_INVALID_IDX;
				rnf = match_rnf;
				goto found_rnode;
			}
			csio_rnf_flowid(rnf) = CSIO_INVALID_IDX;
			goto alloc_rnode;
		}
		/* For regular N-ports */
		if (!csio_memcmp(csio_rnf_wwpn(rnf), rdevp->wwpn, 8)) {
			/* Update rnf */
			goto found_rnode;
		}

		/*
		 * FIXME: FW needs to handle this case, where same remote port
		 * name shows up as different Nport-id when fabric relogged in.
	 	 * FW needs to send NPORT_ID changed event for that remote port.
		 */

		/*
		 * Host maintains association between flowid and remote
		 * node. If same remote port relogged in, then FW needs to send
		 * rdev event using same flow_id as it used earlier session.
		 * otherwise host have to lookup existing rnodes based on wwpn.
		 */
		/* Search for rnode that have same wwpn */
		match_rnf = csio_rnf_lookup_wwpn(lnf, rdevp->wwpn);
		if (match_rnf != NULL) {
			csio_ln_dbg(lnf->ln,
				"ssni:x%x changed for rport name(wwpn):%llx "
				"did:x%x\n", rdev_flowid,
				csio_wwn_to_u64(rdevp->wwpn),
				match_rnf->nport_id);
			csio_rnf_flowid(rnf) = CSIO_INVALID_IDX;
			rnf = match_rnf;
		}
		else {
			csio_ln_dbg(lnf->ln,
				"rnode wwpn mismatch found ssni:x%x "
				"name(wwpn):%llx\n",
				rdev_flowid,
				csio_wwn_to_u64(csio_rnf_wwpn(rnf)));
			if (csio_is_rnf_ready(rnf)) {
				csio_ln_warn(lnf->ln, "rnode is already active "
					"wwpn:%llx ssni:x%x\n",
					csio_wwn_to_u64(csio_rnf_wwpn(rnf)),
					rdev_flowid);
				CSIO_DB_ASSERT(0);
			}
			csio_rnf_flowid(rnf) = CSIO_INVALID_IDX;
			goto alloc_rnode;
		}
	}

found_rnode:
	csio_ln_dbg(lnf->ln, "found rnode:%p ssni:x%x name(wwpn):%llx\n",
		rnf, rdev_flowid, csio_wwn_to_u64(rdevp->wwpn));

	/* Update flowid */
	csio_rnf_flowid(rnf) = rdev_flowid;

	/* update rdev entry */
	rnf->rdev_entry = rdevp;
	CSIO_INC_STATS(lnf, n_rnode_match);
	return rnf;

alloc_rnode:
	rn = csio_get_rn(lnf->ln, rdev_flowid);
	if (!rn) {
		return NULL;
	} 	
	rnf = csio_rnode_to_fcoe(rn);
	csio_ln_dbg(lnf->ln, "alloc rnode:%p ssni:x%x name(wwpn):%llx\n",
		rnf, rdev_flowid, csio_wwn_to_u64(rdevp->wwpn));

	/* update rdev entry */
	rnf->rdev_entry = rdevp;
	return rnf;
}

/**
 * csio_rnf_verify_rparams - verify rparams.
 * @lnf: FCoE lnode
 * @rnf: FCoE rnode
 * @rdevp: remote device params
 * returns success if rparams are verified.
 */
static csio_retval_t
csio_rnf_verify_rparams(struct csio_lnode_fcoe *lnf,
			struct csio_rnode_fcoe *rnf,
			struct fcoe_rdev_entry *rdevp)
{
	uint8_t null[8];
	uint8_t rport_type;
	uint8_t fc_class;
	__be32 *did;

	did = (__be32 *)&rdevp->r_id[0];
	rport_type = G_FW_RDEV_WR_RPORT_TYPE(rdevp->rd_xfer_rdy_to_rport_type);
	switch (rport_type) {
	case FLOGI_VFPORT:
		rnf->role = CSIO_RNFR_FABRIC;
		/* FIXME: Move this check to FW */
		if (((csio_ntohl(*did) >> 8) & DID_MASK) != FABRIC_DID) {
			csio_ln_err(lnf->ln, "ssni:x%x invalid fabric portid\n",
				csio_rnf_flowid(rnf));
			return CSIO_INVAL;
		}
		/* NPIV support */
		if (G_FW_RDEV_WR_NPIV(rdevp->vft_to_qos))
			lnf->flags |= CSIO_LNFFLAG_NPIVSUPP;
#ifdef __CSIO_TARGET__
		/* Disable NPIV support when not in initiator mode */
		if (!csio_initiator_mode(csio_lnode_to_hw(lnf->ln)))
			lnf->flags &= ~CSIO_LNFFLAG_NPIVSUPP;
#endif /* __CSIO_TARGET__ */
		break;

	case NS_VNPORT:
		rnf->role = CSIO_RNFR_NS;
		/* FIXME: Move this check to FW */
		if (((csio_ntohl(*did) >> 8) & DID_MASK) != NS_DID) {
			csio_ln_err(lnf->ln, "ssni:x%x invalid fabric portid\n",
				csio_rnf_flowid(rnf));
			return CSIO_INVAL;
		}
		break;
		
	case REG_FC4_VNPORT:
	case REG_VNPORT:
		rnf->role = CSIO_RNFR_NPORT;
		if (rdevp->event_cause == PRLI_ACC_RCVD ||
			/* TODO: Check image_pair, rsp_code .*/	
			rdevp->event_cause == PRLI_RCVD) {
			if (G_FW_RDEV_WR_TASK_RETRY_ID(rdevp->enh_disc_to_tgt))
				rnf->fcp_flags |= V_PRLI_FCP_DATA_OVERLAY(1);

			if (G_FW_RDEV_WR_RETRY(rdevp->enh_disc_to_tgt))
				rnf->fcp_flags |= V_PRLI_FCP_RETRY(1);

			if (G_FW_RDEV_WR_CONF_CMPL(rdevp->enh_disc_to_tgt))
				rnf->fcp_flags |=
					V_PRLI_FCP_CONF_COMPL_ALLOWED(1);

			if (G_FW_RDEV_WR_TGT(rdevp->enh_disc_to_tgt))
				rnf->role |= CSIO_RNFR_TARGET;

			if (G_FW_RDEV_WR_INI(rdevp->enh_disc_to_tgt))
				rnf->role |= CSIO_RNFR_INITIATOR;
		}
		
		break;

	case FDMI_VNPORT:
	case FAB_CTLR_VNPORT:	
		rnf->role = 0;
		break;	

	default:
		csio_ln_err(lnf->ln, "ssni:x%x invalid rport type recv x%x\n",
			csio_rnf_flowid(rnf), rport_type);
		return CSIO_INVAL;
	}

	/* validate wwpn/wwnn for Name server/remote port */
	/* FIXME: Move this check to FW */
	if (rport_type == REG_VNPORT || rport_type == NS_VNPORT) {
		csio_memset(null, 0, 8);
		if (!csio_memcmp(rdevp->wwnn, null, 8)) {
			csio_ln_err(lnf->ln, "ssni:x%x invalid wwnn recv from"
				"rport did:x%x\n",
				csio_rnf_flowid(rnf),
				(csio_ntohl(*did) & DID_MASK));
			return CSIO_INVAL;
		}

		if (!csio_memcmp(rdevp->wwpn, null, 8)) {
			csio_ln_err(lnf->ln, "ssni:x%x invalid wwpn recv from"
				"rport did:x%x\n",
				csio_rnf_flowid(rnf),
				(csio_ntohl(*did) & DID_MASK));
			return CSIO_INVAL;
		}

	}

	/* Copy wwnn, wwpn and nport id */
	rnf->nport_id = (csio_ntohl(*did) >> 8) & DID_MASK;
	csio_memcpy(csio_rnf_wwnn(rnf), rdevp->wwnn, 8);
	csio_memcpy(csio_rnf_wwpn(rnf), rdevp->wwpn, 8);
	rnf->rn_sparm.csp.rcv_sz = csio_ntohs(rdevp->rcv_fr_sz);
	fc_class = G_FW_RDEV_WR_CLASS(rdevp->vft_to_qos);
	rnf->rn_sparm.clsp[fc_class - 1].serv_option = V_SP_CLASS_SUPPORT(1);
	return CSIO_SUCCESS;
}


/**
 * csio_rnf_stateto_str -
 * @rnf - FCoE rnode
 * @str - state of rnode.
 *
 * This routines returns the current state of FCOE rnode.
 */
void csio_rnf_stateto_str(struct csio_rnode_fcoe *rnf, int8_t *str)
{
	if (csio_get_state(rnf) == ((csio_sm_state_t)csio_rnfs_uninit)) {
		csio_strcpy(str, "UNINIT");
		return;
	}	
	if (csio_get_state(rnf) == ((csio_sm_state_t)csio_rnfs_ready)) {
		csio_strcpy(str, "READY");
		return;
	}	
	if (csio_get_state(rnf) == ((csio_sm_state_t)csio_rnfs_offline)) {
		csio_strcpy(str, "OFFLINE");
		return;
	}	
	if (csio_get_state(rnf) == ((csio_sm_state_t)csio_rnfs_disappeared)) {
		csio_strcpy(str, "DISAPPEARED");
		return;
	}	
	csio_strcpy(str, "UNKNOWN");
}

/**
 * csio_rnf_evt_name
 * @evt - rnf event.
 *
 * This routines returns the event name of given rnf event.
 */
const char *csio_rnf_evt_name(csio_rnf_ev_t evt)
{
	const char *evt_name;
	evt_name = rnfevt_names[evt];
	return evt_name;
}

/**
 * csio_rnf_fwevt_name
 * @evt - fw event.
 *
 * This routines returns the event name of given fw event.
 */
const char *csio_rnf_fwevt_name(uint32_t evt)
{
	const char *evt_name;
	evt_name = fwevt_names[evt];
	return evt_name;
}

#ifdef __CSIO_TARGET__

static csio_retval_t
csio_rnf_tgt_prli_handler(struct csio_rnode_fcoe *rnf)
{
	enum csio_oss_error rv = CSIO_SUCCESS;
	bool acc = CSIO_FALSE;

	/*
	 * This function is called only on receipt of PRLI, and we
	 * should never received PRLI from non-initiator devices.
	 * So we reject such PRLI requests.
	 */
	if (!(rnf->role & CSIO_RNFR_INITIATOR))
		goto reject;
	
	/* Now register the session with the SCSI server. */
	rv = csio_tgt_register_session(rnf->rn);
	if (rv)
		goto reject;

	/* Succeed the PRLI */
	acc = CSIO_TRUE;
reject:
	if (csio_tgt_issue_rdev_wr(rnf->rn, acc))
		rv = CSIO_INVAL;

	return rv;
}

/*
 * csio_rnf_tgt_logo_handler - Explicit/Implicit LOGO handler.
 * @rnf: Remote port
 *
 */
static void
csio_rnf_tgt_logo_handler(struct csio_rnode_fcoe *rnf)
{
	struct csio_hw *hw = csio_lnode_to_hw(csio_rnode_to_lnode(rnf->rn));
	int work;

	/*
	 * Unregister with SCSI server. Cleanup I/Os in the rnode.
	 */
	if (rnf->role & CSIO_RNFR_INITIATOR) {
		work = csio_tgt_cleanup_io_rn(rnf->rn);
		csio_tgt_unregister_session(rnf->rn, work);
	}

	/*
	 * In pure target mode, there is no concept or requirement
	 * of device loss timer (for persistence of LUN devices) as in
	 * initiator mode. Therefore, the rnode has to be freed soon
	 * after return from the state machine, to avoid leaking rnodes
	 * that keep logging out and logging in. Therefore, we send a
	 * CLOSE event, which should put the rnode in uninit state.
	 * On return to csio_rnf_fwevt_handler() or csio_post_event_rnfs(),
	 * the rnode should be freed.
	 */
	if (!csio_initiator_mode(hw))
		csio_rnf_close(rnf);
}

/*
 * csio_rnf_tgt_handle_login - Login events handler for target mode events.
 * @rnf: Rnode
 * @evt: SM event.
 *
 * Return of 1 indicates that the calling state needs to stop processing
 * this event. Return of 0 indicates the initiator portion of the SM
 * needs to continue handling this event.
 */
static void
csio_rnf_tgt_handle_login(struct csio_rnode_fcoe *rnf, csio_rnf_ev_t evt)
{
	struct csio_lnode_fcoe *lnf =
			csio_lnode_to_fcoe(csio_rnode_to_lnode(rnf->rn));
	enum csio_oss_error ret = CSIO_SUCCESS;
	struct csio_hw *hw = csio_lnode_to_hw(csio_rnode_to_lnode(rnf->rn));

	if (!csio_target_mode(hw))
		return;

	if (evt == CSIO_RNFE_PRLI_RECV) {
		ret = csio_rnf_tgt_prli_handler(rnf);

		/* REVISIT: If we are unable to post the rdev WR, do we retry?*/
		if (ret != CSIO_SUCCESS) {
			/* Print an error for now */
			csio_ln_err(lnf->ln, "ssni:x%x Couldnt post PRLI"
					     " acc/reject ret:%d\n",
				     csio_rnf_flowid(rnf), ret);
			return;
		}
	} else {
		if (!csio_initiator_mode(hw)) {
			/*
			 * REVISIT: In pure target mode, can we ever
			 * receive PRLI_DONE  event in this state? Print
			 * an error for now, assert later.
			 */
#if 0
			CSIO_DB_ASSERT(0);
#endif
			csio_ln_err(lnf->ln, "ssni:x%x Ignoring event %d recv"
				    " in rnf state[uninit](tgt mode)\n",
				     csio_rnf_flowid(rnf), evt);
			CSIO_INC_STATS(rnf, n_evt_drop);
			return;
		}
	}
}

#endif /* __CSIO_TARGET__ */

static void
csio_rnf_os_reg_rnode(struct csio_rnode_fcoe *rnf)
{
	struct csio_hw *hw = csio_lnode_to_hw(csio_rnode_to_lnode(rnf->rn));
	struct csio_lnode_fcoe *lnf =
			csio_lnode_to_fcoe(csio_rnode_to_lnode(rnf->rn));
	struct csio_lnode *ln = csio_rnode_to_lnode(rnf->rn);
#ifdef __CSIO_TARGET__
	if (!csio_initiator_mode(hw))
		return;
#endif /* __CSIO_TARGET__ */

	csio_spin_unlock_irq(hw, &hw->lock);
	if (csio_hw_to_ops(hw)->os_rn_reg_rnode)
		csio_hw_to_ops(hw)->os_rn_reg_rnode(rnf->rn);
	csio_spin_lock_irq(hw, &hw->lock);
	
	if (rnf->role & CSIO_RNFR_TARGET)
		ln->n_scsi_tgts++;

	if (rnf->nport_id == FDMI_DID)
		csio_lnf_fdmi_start(lnf, (void *) rnf);
}

static void
csio_rnf_os_unreg_rnode(struct csio_rnode_fcoe *rnf)
{
	struct csio_hw *hw = csio_lnode_to_hw(csio_rnode_to_lnode(rnf->rn));
	struct csio_lnode *ln	= csio_rnode_to_lnode(rnf->rn);
	struct csio_list tmp_q;
	int cmpl = 0;

#ifdef __CSIO_TARGET__
	if (csio_target_mode(hw))
		csio_rnf_tgt_logo_handler(rnf);	

	if (!csio_initiator_mode(hw))
		return;
#endif /* __CSIO_TARGET__ */

	if (!csio_list_empty(&rnf->os_cmpl_q)) {
		csio_dbg(hw, "Returning completion queue I/Os\n");
		csio_head_init(&tmp_q);
		csio_enq_list_at_tail(&tmp_q, &rnf->os_cmpl_q);
		cmpl = 1;
	}

	if (rnf->role & CSIO_RNFR_TARGET) {
		ln->n_scsi_tgts--;
		ln->last_scan_ntgts--;
	}

	csio_spin_unlock_irq(hw, &hw->lock);
	if (csio_hw_to_ops(hw)->os_rn_unreg_rnode)
		csio_hw_to_ops(hw)->os_rn_unreg_rnode(rnf->rn);
	csio_spin_lock_irq(hw, &hw->lock);

	/* Cleanup I/Os that were waiting for rnode to unregister */
	if (cmpl)
		csio_scsi_cleanup_io_q(csio_hw_to_scsim(hw), &tmp_q);

}

/*****************************************************************************/
/* START: FCoE Rnode SM                                                      */
/*****************************************************************************/

/**
 * csio_rnfs_uninit -
 * @rnf - FCoE rnode
 * @evt - SM event.
 *
 */
static void
csio_rnfs_uninit(struct csio_rnode_fcoe *rnf, csio_rnf_ev_t evt)
{
	struct csio_lnode_fcoe *lnf =
			csio_lnode_to_fcoe(csio_rnode_to_lnode(rnf->rn));
	enum csio_oss_error ret = CSIO_SUCCESS;

	CSIO_INC_STATS(rnf, n_evt_sm[evt]);
	switch (evt) {

	case CSIO_RNFE_LOGGED_IN:
	case CSIO_RNFE_PLOGI_RECV:
		ret = csio_rnf_verify_rparams(lnf, rnf, rnf->rdev_entry);
		if (!ret) {
			csio_set_state(&rnf->sm, csio_rnfs_ready);
			csio_rnf_os_reg_rnode(rnf);
		} else {
			/*FIXME: Host need to send SSN cmd to free ssn_flowid */
			CSIO_INC_STATS(rnf, n_err_inval);
		}
		break;
	case CSIO_RNFE_LOGO_RECV:
		csio_ln_dbg(lnf->ln, "ssni:x%x Ignoring event %d recv "
			"in rnf state[uninit]\n", csio_rnf_flowid(rnf), evt);
		CSIO_INC_STATS(rnf, n_evt_drop);
		break;
	default:
		csio_ln_err(lnf->ln, "ssni:x%x unexp event %d recv "
			"in rnf state[uninit]\n", csio_rnf_flowid(rnf), evt);
		CSIO_INC_STATS(rnf, n_evt_unexp);
		break;
	}

	return;
}

/**
 * csio_rnfs_ready -
 * @rnf - FCoE rnode
 * @evt - SM event.
 *
 */
static void
csio_rnfs_ready(struct csio_rnode_fcoe *rnf, csio_rnf_ev_t evt)
{
	struct csio_lnode_fcoe *lnf = csio_lnode_to_fcoe
						(csio_rnode_to_lnode(rnf->rn));
	enum csio_oss_error ret = CSIO_SUCCESS;
#ifdef __CSIO_TARGET__
	struct csio_hw *hw = csio_lnode_to_hw(csio_rnode_to_lnode(rnf->rn));
#endif /* __CSIO_TARGET__ */

	CSIO_INC_STATS(rnf, n_evt_sm[evt]);
	switch (evt) {

	case CSIO_RNFE_LOGGED_IN:
	case CSIO_RNFE_PLOGI_RECV:
	
		/*FIXME: FW has done session reset with remote port and
		 * relogged into same remote port.
		 * Host needs to re-register rnode if rport params have
		 * changed.
		 */
		csio_ln_dbg(lnf->ln,
			"ssni:x%x Ignoring event %d recv from did:x%x "
			"in rnf state[ready]\n", csio_rnf_flowid(rnf), evt,
			rnf->nport_id);
		CSIO_INC_STATS(rnf, n_evt_drop);
		break;

	case CSIO_RNFE_PRLI_DONE:
	case CSIO_RNFE_PRLI_RECV:
		ret = csio_rnf_verify_rparams(lnf, rnf, rnf->rdev_entry);
		if (!ret) {
#ifdef __CSIO_TARGET__
			csio_rnf_tgt_handle_login(rnf, evt);
#endif /* __CSIO_TARGET__ */
			csio_rnf_os_reg_rnode(rnf);
		} else {
#ifdef __CSIO_TARGET__
			/*
			 * REVISIT: Do we send the RDEV WR with reject, if we
			 * didnt like something in the ingress RDEV WR in the
			 * first place? ASSERT for now.
			 */
			if (csio_target_mode(hw))
				if (evt == CSIO_RNFE_PRLI_RECV) {
					CSIO_DB_ASSERT(0);
				}
#if 0
			csio_tgt_issue_rdev_wr(rnf->rn, CSIO_FALSE);
#endif
#endif /* __CSIO_TARGET__ */
			CSIO_INC_STATS(rnf, n_err_inval);
		}
		break;
	case CSIO_RNFE_DOWN:
		csio_set_state(&rnf->sm, csio_rnfs_offline);
		csio_rnf_os_unreg_rnode(rnf);

		/* FW expected to internally aborted outstanding SCSI WRs
		 * and return all SCSI WRs to host with status "ABORTED".
		 */
		break;

	case CSIO_RNFE_LOGO_RECV:
		csio_set_state(&rnf->sm, csio_rnfs_offline);

		csio_rnf_os_unreg_rnode(rnf);

		/* FW expected to internally aborted outstanding SCSI WRs
		 * and return all SCSI WRs to host with status "ABORTED".
		 */
		break;

	case CSIO_RNFE_CLOSE:
		/* Each rnode receives CLOSE event when driver is removed or
		 * device is reset
		 * Note: All outstanding IOs on remote port need to returned
		 * to uppper layer with appropriate error before sending
		 * CLOSE event
		 */
		csio_set_state(&rnf->sm, csio_rnfs_uninit);
		csio_rnf_os_unreg_rnode(rnf);
		break;

	case CSIO_RNFE_NAME_MISSING:
		csio_set_state(&rnf->sm, csio_rnfs_disappeared);
		csio_rnf_os_unreg_rnode(rnf);
		/* FW expected to internally aborted outstanding SCSI WRs
		 * and return all SCSI WRs to host with status "ABORTED".
		 */

		break;

	default:
		csio_ln_err(lnf->ln,
			"ssni:x%x unexp event %d recv from did:x%x "
			"in rnf state[uninit]\n", csio_rnf_flowid(rnf), evt,
			rnf->nport_id);
		CSIO_INC_STATS(rnf, n_evt_unexp);
		break;
	}
	return;
}

/*
 * csio_rnfs_offline -
 * @rnf - FCoE rnode
 * @evt - SM event.
 *
 */
static void
csio_rnfs_offline(struct csio_rnode_fcoe *rnf, csio_rnf_ev_t evt)
{
	struct csio_lnode_fcoe *lnf =
			csio_lnode_to_fcoe(csio_rnode_to_lnode(rnf->rn));
	enum csio_oss_error ret = CSIO_SUCCESS;

	CSIO_INC_STATS(rnf, n_evt_sm[evt]);
	switch (evt) {

	case CSIO_RNFE_LOGGED_IN:
	case CSIO_RNFE_PLOGI_RECV:
		ret = csio_rnf_verify_rparams(lnf, rnf, rnf->rdev_entry);
		if (!ret) {
			csio_set_state(&rnf->sm, csio_rnfs_ready);
			csio_rnf_os_reg_rnode(rnf);
		}
		else {
			CSIO_INC_STATS(rnf, n_err_inval);
			csio_post_event(&rnf->sm, CSIO_RNFE_CLOSE);
		}
		break;

	case CSIO_RNFE_DOWN:
		csio_ln_dbg(lnf->ln,
			"ssni:x%x Ignoring event %d recv from did:x%x "
			"in rnf state[offline]\n", csio_rnf_flowid(rnf), evt,
			rnf->nport_id);
		CSIO_INC_STATS(rnf, n_evt_drop);
		break;

	case CSIO_RNFE_CLOSE:
		/* Each rnode receives CLOSE event when driver is removed or
		 * device is reset
		 * Note: All outstanding IOs on remote port need to returned
		 * to uppper layer with appropriate error before sending
		 * CLOSE event
		 */
		csio_set_state(&rnf->sm, csio_rnfs_uninit);
		break;

	case CSIO_RNFE_NAME_MISSING:
		csio_set_state(&rnf->sm, csio_rnfs_disappeared);
		break;

	default:
		csio_ln_err(lnf->ln,
			"ssni:x%x unexp event %d recv from did:x%x "
			"in rnf state[offline]\n", csio_rnf_flowid(rnf), evt,
			rnf->nport_id);
		CSIO_INC_STATS(rnf, n_evt_unexp);
		break;
	}

	return;
}

/**
 * csio_rnfs_disappeared -
 * @rnf - FCoE rnode
 * @evt - SM event.
 *
 */
static void
csio_rnfs_disappeared(struct csio_rnode_fcoe *rnf, csio_rnf_ev_t evt)
{
	struct csio_lnode_fcoe *lnf =
			csio_lnode_to_fcoe(csio_rnode_to_lnode(rnf->rn));
	enum csio_oss_error ret = CSIO_SUCCESS;

	CSIO_INC_STATS(rnf, n_evt_sm[evt]);
	switch (evt) {

	case CSIO_RNFE_LOGGED_IN:
	case CSIO_RNFE_PLOGI_RECV:
		ret = csio_rnf_verify_rparams(lnf, rnf, rnf->rdev_entry);
		if (!ret) {
			csio_set_state(&rnf->sm, csio_rnfs_ready);
			csio_rnf_os_reg_rnode(rnf);
		}
		else {
			CSIO_INC_STATS(rnf, n_err_inval);
			csio_post_event(&rnf->sm, CSIO_RNFE_CLOSE);
		}
		break;

	case CSIO_RNFE_CLOSE:
		/* Each rnode receives CLOSE event when driver is removed or
		 * device is reset.
		 * Note: All outstanding IOs on remote port need to returned
		 * to uppper layer with appropriate error before sending
		 * CLOSE event
		 */
		csio_set_state(&rnf->sm, csio_rnfs_uninit);
		break;

	case CSIO_RNFE_DOWN:
	case CSIO_RNFE_NAME_MISSING:
		csio_ln_dbg(lnf->ln,
			"ssni:x%x Ignoring event %d recv from did x%x"
			"in rnf state[disappeared]\n", csio_rnf_flowid(rnf),
			evt, rnf->nport_id);
		break;

	default:
		csio_ln_err(lnf->ln,
			"ssni:x%x unexp event %d recv from did x%x"
			"in rnf state[disappeared]\n", csio_rnf_flowid(rnf),
			evt, rnf->nport_id);
		CSIO_INC_STATS(rnf, n_evt_unexp);
		break;
	}

	return;
}

/*****************************************************************************/
/* END: FCoE Rnode SM                                                        */
/*****************************************************************************/

static csio_retval_t
csio_get_ssn_stats(struct csio_hw *hw, struct csio_rnode *rn,
		   csio_fcoe_rnode_t *rnf_info)
{
	struct adapter *adap = &hw->adap;
	int idx, ret;
	struct fw_fcoe_stats_cmd c;
	struct fw_fcoe_ssn_cmd_params ssnparams;
	struct csio_rnode_fcoe *rnf     = NULL;

	if (rn->flowid == CSIO_INVALID_IDX)
		return CSIO_INVAL;

	rnf = csio_rnode_to_fcoe(rn);
	ssnparams.ssni = rn->flowid;
	for (idx = 1; idx <= 3; idx++) {
		ssnparams.idx = (idx-1)*6 + 1;
		ssnparams.nstats = 6;
		if (idx == 3)
			ssnparams.nstats = 3;
		csio_fcoe_read_ssnparams_init_mb(&c, &ssnparams);
		csio_spin_unlock_irq(hw, &hw->lock);
		ret = t4_wr_mbox(adap, adap->mbox, &c, 64, &c);
		if (ret) {
			csio_printk("CSIO: Issue of FCoE PARAMS"
						"command failed!\n");
			csio_spin_lock_irq(hw, &hw->lock);
			return CSIO_INVAL;
		}
		csio_spin_lock_irq(hw, &hw->lock);

		csio_mb_process_ssnparams_rsp(&c, &ssnparams,
				&rnf_info->ssn_stats);
	}

	return CSIO_SUCCESS;
}

static void
csio_copy_rnode_stats(csio_fcoe_rnode_t *rnf_info,
		      struct csio_rnode_stats *rn_stats)
{
	csio_rnode_stats_t *rninfo_stats = &rnf_info->rnode_stats;
	
	rninfo_stats->n_lun_rst 	= rn_stats->n_lun_rst;	
	rninfo_stats->n_lun_rst_fail	= rn_stats->n_lun_rst_fail;
	rninfo_stats->n_tgt_rst		= rn_stats->n_tgt_rst;	
	rninfo_stats->n_tgt_rst_fail	= rn_stats->n_tgt_rst_fail;
	
	return;
} /* csio_copy_rnode_stats */

static void
csio_copy_rnf_stats(csio_fcoe_rnode_t *rnf_info,
		struct csio_rnode_fcoestats *rnf_stats)
{
	csio_rnode_fcoestats_t *rnfinfo_stats = &rnf_info->rnf_stats;

	rnfinfo_stats->n_err = rnf_stats->n_err;
	rnfinfo_stats->n_err_inval = rnf_stats->n_err_inval;
	rnfinfo_stats->n_err_nomem = rnf_stats->n_err_nomem;
	rnfinfo_stats->n_evt_unexp = rnf_stats->n_evt_unexp;
	rnfinfo_stats->n_evt_drop = rnf_stats->n_evt_drop;

	csio_memcpy(rnfinfo_stats->n_evt_fw, rnf_stats->n_evt_fw,
					(RSCN_DEV_LOST * sizeof(uint32_t)));
	csio_memcpy(rnfinfo_stats->n_evt_sm, rnf_stats->n_evt_sm,
				(CSIO_RNFE_MAX_EVENT * sizeof(csio_rnf_ev_t)));
	return;
} /* csio_copy_rnf_stats */

/**
 * csio_copy_fcoe_rnode_info - Get the specified lnode info.
 * @hw -
 * @rnf_info - User buffer
 * @lnf - FCoE Lnode
 * @rnf - FCoE Rnode
 */
static void
csio_copy_fcoe_rnode_info(struct csio_hw *hw, csio_fcoe_rnode_t *rnf_info,
		struct csio_lnode_fcoe *lnf, struct csio_rnode_fcoe *rnf)
{
	struct csio_rnode *rn = rnf->rn;
	uint8_t i = 0;

	csio_get_ssn_stats(hw, rn, rnf_info);
	rnf_info->ssn_flowid	= rn->flowid;
	rnf_info->vnp_flowid	= lnf->vnp_flowid;
	rnf_info->nport_id	= rnf->nport_id;
	rnf_info->fcp_flags	= rnf->fcp_flags;

	if (rnf->role & CSIO_RNFR_INITIATOR &&
		rnf->role & CSIO_RNFR_TARGET)
		csio_strcpy(rnf_info->role, "Initiator & Target");
	else if (rnf->role & CSIO_RNFR_INITIATOR)
		csio_strcpy(rnf_info->role, "Initiator");
	else if (rnf->role & CSIO_RNFR_TARGET)
		csio_strcpy(rnf_info->role, "Target");
	else if (rnf->role & CSIO_RNFR_FABRIC)
		csio_strcpy(rnf_info->role, "Fabric");
	else if (rnf->role & CSIO_RNFR_NS)
		csio_strcpy(rnf_info->role, "Name-Server");
	else
		csio_strcpy(rnf_info->role, "N-Port");

	csio_memcpy(&rnf_info->rn_sparm, &rnf->rn_sparm,
			sizeof(struct csio_service_parms));

	csio_copy_rnode_stats(rnf_info, &rn->stats);
	csio_copy_rnf_stats(rnf_info, &rnf->stats);

	csio_rnf_stateto_str(rnf, rnf_info->state);

	/* Events */
	rnf_info->max_rnf_events= (uint8_t)CSIO_RNFE_MAX_EVENT;
	rnf_info->cur_evt	= rnf->cur_evt;
	rnf_info->prev_evt	= rnf->prev_evt;	
	
	for (i = 0; i < rnf_info->max_rnf_events; i++) {
		csio_strncpy(rnf_info->rnf_evt_name[i],
				(char *)csio_rnf_evt_name(i), 32);
	}

	for (i = PLOGI_ACC_RCVD; i <= RSCN_DEV_LOST; i++) {
		csio_strncpy(rnf_info->fw_evt_name[i],
				(char *)csio_rnf_fwevt_name(i), 32);
	}

	return;
} /* csio_copy_fcoe_rnode_info */


/**
 * csio_get_rnode_info - Gets rnode information
 * @hw - FCoE rnode
 * @buffer - Buffer where rnode information to be copied.
 * @buffer_len - buffer length.
 *
 * Returns success if rnode info is copied to given buffer.
 */
csio_retval_t
csio_fcoe_get_rnode_info(struct csio_hw *hw, void *buffer, uint32_t buffer_len)
{
	csio_fcoe_rnode_t *rnf_info 	= buffer;
	struct csio_lnode *ln		= NULL;
	struct csio_lnode_fcoe *lnf	= NULL;	
	struct csio_rnode *rn		= NULL;
	struct csio_rnode_fcoe *rnf	= NULL;

	if (buffer_len < sizeof(csio_fcoe_rnode_t))
		return CSIO_NOMEM;

	csio_spin_lock_irq(hw, &hw->lock);

	lnf = csio_lnf_lookup_by_vnpi(hw, rnf_info->vnp_flowid);
	if (lnf == NULL) {
		csio_spin_unlock_irq(hw, &hw->lock);
		return CSIO_INVAL;
	}

	ln = lnf->ln;
	rn = csio_get_next_rnode(ln, rnf_info->ssn_flowid);
	if (rn == NULL) {
		csio_spin_unlock_irq(hw, &hw->lock);
		return CSIO_INVAL;
	}

	rnf = csio_rnode_to_fcoe(rn);
	csio_copy_fcoe_rnode_info(hw, rnf_info, lnf, rnf);

	csio_spin_unlock_irq(hw, &hw->lock);

	return CSIO_SUCCESS;
} /* csio_get_rnode_info */

/**
 * csio_get_rnode_info_by_fcid - Gets the specified RNode information.
 * @hw - adapter
 * @buffer - Buffer where rnode information to be copied.
 * @buffer_len - buffer length.
 *
 * Returns success if rnode info is copied to given buffer.
 */
csio_retval_t
csio_fcoe_get_rnode_info_by_fcid(struct csio_hw *hw,
		void *buffer, uint32_t buffer_len)
{
	csio_fcoe_rnode_t *rnf_info	= buffer;
	struct csio_lnode_fcoe *lnf	= NULL;
	struct csio_rnode *rn		= NULL;
	struct csio_rnode_fcoe *rnf	= NULL;	
	fc_id_t search_type		= NPORT_ID;

	if (buffer_len < sizeof(csio_fcoe_rnode_t))
		return CSIO_NOMEM;

	if (rnf_info->nport_id) {
		search_type = NPORT_ID;
	} else if (rnf_info->ssn_flowid) {
		search_type = FW_HANDLE;
	} else if (csio_wwn_to_u64(rnf_info->rn_sparm.wwpn) != 0) {
		search_type = WWPN;
	} else if (csio_wwn_to_u64(rnf_info->rn_sparm.wwnn) != 0) {
		search_type = WWNN;
	} else {
		CSIO_DB_ASSERT(CSIO_FALSE);
	}

	if (!rnf_info->vnp_flowid) {
		csio_err(hw, "Invalid Lnode VNP flowid!\n");
		return CSIO_INVAL;
	}

	csio_spin_lock_irq(hw, &hw->lock);

	lnf = csio_lnf_lookup_by_vnpi(hw, rnf_info->vnp_flowid);
	if (lnf == NULL) {
		csio_spin_unlock_irq(hw, &hw->lock);
		return CSIO_INVAL;
	}

	switch (search_type) {
		
		case NPORT_ID:
			rnf = csio_rnf_lookup_portid(lnf,
						rnf_info->ssn_flowid);
			break;
#if 0
		case FW_HANDLE:
			break;
#endif
		case WWPN:
			rnf = csio_rnf_lookup_wwpn(lnf,
					rnf_info->rn_sparm.wwpn);
			break;
#if 0
		case WWNN:
			break;
#endif
		default:
			CSIO_DB_ASSERT(CSIO_FALSE);
			break;
	}

	if (rnf == NULL) {
		csio_spin_unlock_irq(hw, &hw->lock);
		return CSIO_INVAL;
	}

	rn = rnf->rn;

	/* Copy the contents! */
	csio_copy_fcoe_rnode_info(hw, rnf_info, lnf, rnf);

	csio_spin_unlock_irq(hw, &hw->lock);

	return CSIO_SUCCESS;	
} /* csio_fcoe_get_rnode_info_by_fcid */


/*****************************************************************************/
/* Entry points */
/*****************************************************************************/


/**
 * csio_rnf_close - closes an rnode
 * @rnf: FCoE rnode
 *
 * Post event to close rnode.
 * Returns success if rnode is in UNINIT state.
 */
csio_retval_t
csio_rnf_close(struct csio_rnode_fcoe *rnf)
{
	/*
	 * All I/Os to the remote port have stopped.
	 */
	csio_post_event(&rnf->sm, CSIO_RNFE_CLOSE);
	if (csio_is_rnf_uninit(rnf))
		return CSIO_SUCCESS;
	else
		return CSIO_INVAL;
//	csio_put_rn(lnf->ln, rnf->rn);
}

/**
 * csio_rnf_devloss_handler - Device loss event handler
 * @rnf: FCoE rnode
 *
 * Post event to close rnode SM and free rnode.
 */
void
csio_rnf_devloss_handler(struct csio_rnode_fcoe *rnf)
{
	struct csio_lnode_fcoe *lnf =
			csio_lnode_to_fcoe(csio_rnode_to_lnode(rnf->rn));

	/* ignore if same rnode came back as online */
	if (csio_is_rnf_ready(rnf))
		return;

	csio_post_event(&rnf->sm, CSIO_RNFE_CLOSE);
	if (csio_is_rnf_uninit(rnf)) {
		/* Free rnf */	
		csio_put_rn(lnf->ln, rnf->rn);
	}	
}

/**
 * csio_rnf_fwevt_handler - FW event handler.
 * @rnf: FCoE rnode
 *
 * Post event to rnode SM.
 */
void
csio_rnf_fwevt_handler(struct csio_rnode_fcoe *rnf, uint8_t fwevt)
{
	struct csio_lnode_fcoe *lnf =
			csio_lnode_to_fcoe(csio_rnode_to_lnode(rnf->rn));
	csio_rnf_ev_t evt;

	evt = CSIO_FWE_TO_RNFE(fwevt);
	if (!evt) {
		csio_ln_err(lnf->ln,
			"ssni:x%x Unhandled FW Rdev event: %d\n",
			 csio_rnf_flowid(rnf), fwevt);
		CSIO_INC_STATS(rnf, n_evt_unexp);
		return;
	}
	CSIO_INC_STATS(rnf, n_evt_fw[fwevt]);

	/* Track previous & current events for debugging */
	rnf->prev_evt = rnf->cur_evt;
	rnf->cur_evt = fwevt;

	/* Post event to rnode SM */
	csio_post_event(&rnf->sm, evt);
	if (csio_is_rnf_uninit(rnf)) {
		/* Free rnf */	
		csio_put_rn(lnf->ln, rnf->rn);
	}	
	return;
}

csio_retval_t
csio_rnf_init(struct csio_rnode_fcoe *rnf)
{
#ifdef __CSIO_TRACE_SUPPORT__
	struct csio_hw *hw = csio_lnode_to_hw(csio_rnode_to_lnode(rnf->rn));

	csio_init_state(&rnf->sm, csio_rnfs_uninit, csio_hw_to_tbuf(hw));
#else
	csio_init_state(&rnf->sm, csio_rnfs_uninit, NULL);
#endif /* __CSIO_TRACE_SUPPORT__ */

	csio_head_init(&rnf->os_cmpl_q);
	csio_rnf_flowid(rnf) = CSIO_INVALID_IDX;

	return CSIO_SUCCESS;
}

void
csio_rnf_exit(struct csio_rnode_fcoe *rnf)
{
#ifdef __CSIO_DEBUG__
	struct csio_lnode_fcoe *lnf =
			csio_lnode_to_fcoe(csio_rnode_to_lnode(rnf->rn));
#endif			

	CSIO_DB_ASSERT(csio_list_empty(&rnf->os_cmpl_q));

	csio_ln_dbg(lnf->ln, "free rnode:%p ssni:x%x\n",
		rnf, csio_rnf_flowid(rnf));

	return;
}

