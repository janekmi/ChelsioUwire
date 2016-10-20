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
#include <csio_mb.h>
#include <csio_lnode.h>
#include <csio_rnode.h>
#include <csio_fcoe_proto.h>
#include <csio_fcoe_ioctl.h>
#include <csio_stor_ioctl.h>

/* List of FCF record */
int csio_max_fcf = CSIO_MAX_FCF;

/* DCBX Class of service for FCoE */
int csio_cos = 0x3;
int csio_fcoe_rnodes = 1024;
int csio_fdmi_enable = 1;

#define PORT_ID_PTR(_x)         ((uint8_t *)(&_x) + 1)

/* Lnode SM declarations */
static void csio_lnfs_uninit(struct csio_lnode_fcoe *, csio_lnf_ev_t);
static void csio_lnfs_online(struct csio_lnode_fcoe *, csio_lnf_ev_t);
static void csio_lnfs_ready(struct csio_lnode_fcoe *, csio_lnf_ev_t);
static void csio_lnfs_offline(struct csio_lnode_fcoe *, csio_lnf_ev_t);

/* LNF event names */
static const char *lnfevt_names[] = {
	"CSIO_LNFE_NONE", 	/* CSIO_LNFE_NONE */
	"CSIO_LNFE_LINK_INIT",	/* CSIO_LNFE_LINK_INIT */
	"CSIO_LNFE_NPIV_INIT", 	/* CSIO_LNFE_NPIV_INIT */
	"CSIO_LNFE_LINKUP", 	/* CSIO_LNFE_LINKUP */
	"CSIO_LNFE_FAB_INIT_DONE", /*CSIO_LNFE_FAB_INIT_DONE */	
	"CSIO_LNFE_NAME_REGD",	/* CSIO_LNFE_NAME_REGD */
	"CSIO_LNFE_SCAN", 	/* CSIO_LNFE_SCAN */
	"CSIO_LNFE_LINK_DOWN", 	/* CSIO_LNFE_LINK_DOWN */	
	"CSIO_LNFE_DOWN_LINK", 	/* CSIO_LNFE_DOWN_LINK */
	"CSIO_LNFE_LINK_DOWN_DONE",	/* CSIO_LNFE_LINK_DOWN_DONE */
	"CSIO_LNFE_LOGO", 	/* CSIO_LNFE_LOGO */
	"CSIO_LNFE_RESET", 	/* CSIO_LNFE_RESET */
	"CSIO_LNFE_CLOSE",	/* CSIO_LNFE_CLOSE */
	"CSIO_LNFE_MAX_EVENT"	/* CSIO_LNFE_MAX_EVENT */
};

/* LNF event mapping */
static csio_lnf_ev_t	fwevt_to_lnfevt[] = {
	CSIO_LNFE_NONE,		/* None */	
	CSIO_LNFE_NONE,		/* PLOGI_ACC_RCVD  */
	CSIO_LNFE_NONE, 	/* PLOGI_RJT_RCVD  */
	CSIO_LNFE_NONE,		/* PLOGI_RCVD	   */
	CSIO_LNFE_NONE,		/* PLOGO_RCVD	   */
	CSIO_LNFE_NONE,		/* PRLI_ACC_RCVD   */
	CSIO_LNFE_NONE,		/* PRLI_RJT_RCVD   */
	CSIO_LNFE_NONE,		/* PRLI_RCVD	   */
	CSIO_LNFE_NONE,		/* PRLO_RCVD	   */
	CSIO_LNFE_NONE,		/* NPORT_ID_CHGD   */
	CSIO_LNFE_LOGO,		/* FLOGO_RCVD	   */	
	CSIO_LNFE_LOGO,		/* CLR_VIRT_LNK_RCVD */
	CSIO_LNFE_FAB_INIT_DONE,/* FLOGI_ACC_RCVD   */
	CSIO_LNFE_NONE,		/* FLOGI_RJT_RCVD   */
	CSIO_LNFE_FAB_INIT_DONE,/* FDISC_ACC_RCVD   */
	CSIO_LNFE_NONE,		/* FDISC_RJT_RCVD   */
	CSIO_LNFE_NONE,		/* FLOGI_TMO_MAX_RETRY */
	CSIO_LNFE_NONE,		/* IMPL_LOGO_ADISC_ACC */
	CSIO_LNFE_NONE,		/* IMPL_LOGO_ADISC_RJT */
	CSIO_LNFE_NONE,		/* IMPL_LOGO_ADISC_CNFLT */
	CSIO_LNFE_NONE,		/* PRLI_TMO		*/
	CSIO_LNFE_NONE,		/* ADISC_TMO		*/
	CSIO_LNFE_NONE,		/* RSCN_DEV_LOST */
	CSIO_LNFE_NONE,		/* SCR_ACC_RCVD */
	CSIO_LNFE_NONE,		/* ADISC_RJT_RCVD */
	CSIO_LNFE_NONE,		/* LOGO_SNT */
	CSIO_LNFE_NONE,		/* PROTO_ERR_IMPL_LOGO */
};

#define CSIO_FWE_TO_LNFE(_evt)	((_evt > PROTO_ERR_IMPL_LOGO) ?		\
						CSIO_LNFE_NONE :	\
						fwevt_to_lnfevt[_evt])		
/*****************************************************************************/

/**
 * csio_lnf_match_by_portid - lookup lnode using given portid.
 * @hw - HW module
 * @portid - port-id.
 * Returns - If found, returns lnode matching given portid
 * otherwise returns NULL.
 */
struct csio_lnode_fcoe *
csio_lnf_lookup_by_portid(struct csio_hw *hw, uint8_t portid)
{
	struct csio_lnode *ln;
	struct csio_lnode_fcoe *lnf = csio_lnode_to_fcoe(hw->rln);
	struct csio_list *tmp;

	/* Match siblings lnode with portid */
	csio_list_for_each(tmp, &hw->sln_head) {
		ln = (struct csio_lnode *) tmp;
		lnf = csio_lnode_to_fcoe(ln);
		if (ln->portid == portid)
			return lnf;
	}

	return NULL;
}

/**
 * csio_lnf_match_by_fcfi - lookup lnode using given fcf id.
 * @hw - HW module
 * @fcfi - FCF index.
 * Returns - If found, returns lnode matching given fcf id
 * otherwise returns NULL.
 */
static struct csio_lnode_fcoe *
csio_lnf_lookup_by_fcfi(struct csio_hw *hw, uint32_t fcfi)
{
	struct csio_lnode *ln;
	struct csio_lnode_fcoe *lnf = csio_lnode_to_fcoe(hw->rln);
	struct csio_list *tmp;

	/* Match lnode with fcf_flowid */
	csio_list_for_each(tmp, &hw->sln_head) {
		ln = (struct csio_lnode *) tmp;
		lnf = csio_lnode_to_fcoe(ln);
		if (lnf->fcf_flowid == fcfi)
			return lnf;
	}

	return NULL;
}

/**
 * csio_lnf_lookup_by_vnpi - Lookup lnode using given vnp id.
 * @hw - HW module
 * @vnpi - vnp index.
 * Returns - If found, returns lnode matching given vnp id
 * otherwise returns NULL.
 */
struct csio_lnode_fcoe *
csio_lnf_lookup_by_vnpi(struct csio_hw *hw, uint32_t vnp_id)
{
	struct csio_list *tmp1, *tmp2;
	struct csio_lnode *sln = NULL, *cln = NULL;
	struct csio_lnode_fcoe *lnf = NULL;

	if (csio_list_empty(&hw->sln_head)) {
		CSIO_INC_STATS(hw, n_lnlkup_miss);
		return NULL;
	}
	/* Traverse sibling lnodes */
	csio_list_for_each(tmp1, &hw->sln_head) {
		sln = (struct csio_lnode *) tmp1;

		/* Match sibling lnode */
		lnf = csio_lnode_to_fcoe(sln);
		if (lnf->vnp_flowid == vnp_id)
			return lnf;

		if (csio_list_empty(&sln->cln_head))
			continue;

		/* Traverse children lnodes */
		csio_list_for_each(tmp2, &sln->cln_head) {
			cln = (struct csio_lnode *) tmp2;

			/* Match child lnode */
			lnf = csio_lnode_to_fcoe(cln);
			if (lnf->vnp_flowid == vnp_id)
				return lnf;
		}
	}
	CSIO_INC_STATS(hw, n_lnlkup_miss);
	return NULL;
}

/**
 * csio_lnf_lookup_by_wwpn - Lookup lnode using given wwpn.
 * @hw - HW module.
 * @wwpn - WWPN.
 * Returns - If found, returns lnode matching given wwpn
 * otherwise returns NULL.
 */
struct csio_lnode_fcoe *
csio_lnf_lookup_by_wwpn(struct csio_hw *hw, uint8_t *wwpn)
{
	struct csio_list *tmp1, *tmp2;
	struct csio_lnode *sln = NULL, *cln = NULL;
	struct csio_lnode_fcoe *lnf = NULL;

	if (csio_list_empty(&hw->sln_head)) {
		CSIO_INC_STATS(hw, n_lnlkup_miss);
		return NULL;
	}
	/* Traverse sibling lnodes */
	csio_list_for_each(tmp1, &hw->sln_head) {
		sln = (struct csio_lnode *) tmp1;

		/* Match sibling lnode */
		lnf = csio_lnode_to_fcoe(sln);
		if (!csio_memcmp(csio_lnf_wwpn(lnf), wwpn, 8))
			return lnf;

		if (csio_list_empty(&sln->cln_head))
			continue;

		/* Traverse children lnodes */
		csio_list_for_each(tmp2, &sln->cln_head) {
			cln = (struct csio_lnode *) tmp2;

			/* Match child lnode */
			lnf = csio_lnode_to_fcoe(cln);
			if (!csio_memcmp(csio_lnf_wwpn(lnf), wwpn, 8))
				return lnf;
		}
	}
	return NULL;
}


/**
 * csio_lnf_lookup_by_wwpn_ex - Lookup lnode using given wwpn.
 * @hw - HW module.
 * @wwpn - WWPN.
 * @state - Preferred state.
 * Returns - If found, returns lnode matching given wwpn
 * otherwise returns NULL.
 */
struct csio_lnode_fcoe *
csio_lnf_lookup_by_wwpn_ex(struct csio_hw *hw, uint8_t *wwpn,
			csio_sm_state_t state)
{
	struct csio_list *tmp1, *tmp2;
	struct csio_lnode *sln = NULL, *cln = NULL;
	struct csio_lnode_fcoe *lnf = NULL, *last_matched_lnf = NULL;

	if (csio_list_empty(&hw->sln_head)) {
		CSIO_INC_STATS(hw, n_lnlkup_miss);
		return NULL;
	}
	/* Traverse sibling lnodes */
	csio_list_for_each(tmp1, &hw->sln_head) {
		sln = (struct csio_lnode *) tmp1;

		/* Match sibling lnode */
		lnf = csio_lnode_to_fcoe(sln);
		if (!csio_memcmp(csio_lnf_wwpn(lnf), wwpn, 8)) {
			last_matched_lnf = lnf;

			if (csio_get_state(lnf) == state)
				return lnf;
			else
				continue;
		}

		if (csio_list_empty(&sln->cln_head))
			continue;

		/* Traverse children lnodes */
		csio_list_for_each(tmp2, &sln->cln_head) {
			cln = (struct csio_lnode *) tmp2;

			/* Match child lnode */
			lnf = csio_lnode_to_fcoe(cln);
			if (!csio_memcmp(csio_lnf_wwpn(lnf), wwpn, 8)) {
				last_matched_lnf = lnf;

				if (csio_get_state(lnf) == state)
					return lnf;
				else
					continue;		
			}
		}
	}
	return last_matched_lnf;
}



/**
 * csio_lnf_lookup_by_wwnn - Lookup lnode using given wwnn.
 * @hw - HW module.
 * @wwnn - WWNN.
 * Returns - If found, returns lnode matching given wwnn
 * otherwise returns NULL.
 */
struct csio_lnode_fcoe *
csio_lnf_lookup_by_wwnn(struct csio_hw *hw, uint8_t *wwnn)
{
	struct csio_list *tmp1;
	struct csio_lnode *sln = NULL;
	struct csio_lnode_fcoe *lnf = NULL;

	if (csio_list_empty(&hw->sln_head)) {
		CSIO_INC_STATS(hw, n_lnlkup_miss);
		return NULL;
	}
	/* Traverse sibling lnodes */
	csio_list_for_each(tmp1, &hw->sln_head) {
		sln = (struct csio_lnode *) tmp1;

		/* Match sibling lnode */
		lnf = csio_lnode_to_fcoe(sln);
		if (!csio_memcmp(csio_lnf_wwnn(lnf), wwnn, 8))
			return lnf;

		if (csio_list_empty(&sln->cln_head))
			continue;

		/* Let us NOT traverse children lnodes, because the WWNN is
		 * common across all children and *its* parent lnode (i.e.,
		 * root's sibling lnode - sln ) */
	}

	return NULL;
}

static inline void
csio_append_string_attrib(uint8_t **ptr, uint16_t type,
		uint8_t *val, uint16_t len)
{	
	struct csio_attrib_entry *ae = (struct csio_attrib_entry *) *ptr;
	ae->type = csio_htons(type);
	len += 4; 		/* includes attribute type and length */
	len = (len + 3) & ~3; 	/* should be multiple of 4 bytes */
	ae->len = csio_htons(len);
	csio_memset(ae->val.string, 0, len - 4);
	csio_memcpy(ae->val.string, val, len);
	*ptr += len;
}

static inline void
csio_append_int_attrib(uint8_t **ptr, uint16_t type,
		uint32_t val, uint16_t len)
{	
	struct csio_attrib_entry *ae = (struct csio_attrib_entry *) *ptr;
	ae->type = csio_htons(type);
	len += 4; 		/* includes attribute type and length */
	len = (len + 3) & ~3; 	/* should be multiple of 4 bytes */
	ae->len = csio_htons(len);
	ae->val.integer = csio_htonl(val);
	*ptr += len;
}

/**
 * csio_lnf_fdmi_done - FDMI registeration completion
 * @hw: HW context
 * @fdmi_req: fdmi request
 */
static void csio_lnf_fdmi_done(struct csio_hw *hw, struct csio_ioreq *fdmi_req)
{
	void *cmd;
	struct csio_lnode_fcoe *lnf = csio_lnode_to_fcoe(fdmi_req->lnode);
	
	if (fdmi_req->wr_status != FW_SUCCESS) {
		csio_ln_err(lnf->ln, "WR error in processing fdmi rpa cmd "
		    "wr status:%x", fdmi_req->wr_status);	
		CSIO_INC_STATS(lnf, n_fdmi_err);
	}

	cmd = fdmi_req->dma_buf.vaddr;
	if (csio_ntohs(csio_ct_rsp(cmd)) != CT_RESPONSE_FS_ACC) {
		csio_ln_dbg(lnf->ln, "fdmi rpa cmd rejected "
		    " reason %x expl %x\n", csio_ct_reason(cmd),
		    csio_ct_expl(cmd));
	}
}

/**
 * csio_lnf_fdmi_rhba_cbfn - RHBA completion
 * @hw: HW context
 * @fdmi_req: fdmi request
 */
static void
csio_lnf_fdmi_rhba_cbfn(struct csio_hw *hw, struct csio_ioreq *fdmi_req)
{
	void *cmd;
	uint8_t *pld;
	uint32_t len = 0;
	struct csio_lnode_fcoe *lnf = csio_lnode_to_fcoe(fdmi_req->lnode);
	struct csio_attrib_block *attrib_blk;
	uint8_t buf[64];
	uint32_t val;
	uint8_t *fc4_type;
	
	if (fdmi_req->wr_status != FW_SUCCESS) {
		csio_ln_err(lnf->ln, "WR error in processing fdmi rhba cmd "
		    "wr status:%x", fdmi_req->wr_status);	
		CSIO_INC_STATS(lnf, n_fdmi_err);
	}

	cmd = fdmi_req->dma_buf.vaddr;
	if (csio_ntohs(csio_ct_rsp(cmd)) != CT_RESPONSE_FS_ACC) {
		csio_ln_dbg(lnf->ln, "fdmi rhba cmd rejected "
		    " reason %x expl %x\n", csio_ct_reason(cmd),
		    csio_ct_expl(cmd));
	}

	if (!csio_is_rnf_ready(csio_rnode_to_fcoe(fdmi_req->rnode))) {
		CSIO_INC_STATS(lnf, n_fdmi_err);
		return;	
	}

	/* Prepare CT hdr for RPA cmd */	
	csio_memset(cmd, 0, CT_BASIC_IU_LEN);
	csio_fill_ct_iu(cmd,
			CT_GS_MGMT_SERVICE,
			CT_FDMI_HBA_MGMT_SERVER,
			csio_htons(CT_FDMI_HBA_RPA));

	/* Prepare RPA payload */
	pld = (uint8_t *) csio_ct_get_pld(cmd);
	csio_memcpy(pld, csio_lnf_wwpn(lnf), 8); /* Port name */
	pld += 8;

	/* Start appending Port attributes */
	attrib_blk = (struct csio_attrib_block *) pld;
	attrib_blk->entry_count = 0;
	len += sizeof(attrib_blk->entry_count);
	pld += sizeof(attrib_blk->entry_count);
	
	fc4_type = &buf[0];
	csio_memset(fc4_type, 0, 32);
	fc4_type[2] = 1;
	fc4_type[7] = 1;
	csio_append_string_attrib(&pld, SUPPORTED_FC4_TYPES, fc4_type , 32);
	attrib_blk->entry_count++;
	val = CSIO_HBA_PORTSPEED_1GBIT | CSIO_HBA_PORTSPEED_10GBIT;
	csio_append_int_attrib(&pld, SUPPORTED_SPEED, val , 4);
	attrib_blk->entry_count++;
	
	if (hw->t4port[lnf->ln->portid].link_speed == FW_PORT_CAP_SPEED_1G)
		val = CSIO_HBA_PORTSPEED_1GBIT;
	else if (hw->t4port[lnf->ln->portid].link_speed ==
			FW_PORT_CAP_SPEED_10G)
		val = CSIO_HBA_PORTSPEED_10GBIT;
	else
		val = CSIO_HBA_PORTSPEED_UNKNOWN;
	csio_append_int_attrib(&pld, PORT_SPEED, val , 4);
	attrib_blk->entry_count++;
	csio_append_int_attrib(&pld, MAX_FRAME_LEN, lnf->ln_sparm.csp.rcv_sz,
			4);
	attrib_blk->entry_count++;
	
	csio_strcpy(buf, "csiostor");
	csio_append_string_attrib(&pld, OS_DEVICE_NAME, buf,
				(uint16_t)csio_strlen(buf));
	attrib_blk->entry_count++;

	if (!csio_hostname(hw, buf, sizeof(buf))) {
		csio_append_string_attrib(&pld, HOST_NAME , buf,
			(uint16_t)csio_strlen(buf));
		attrib_blk->entry_count++;
	}	
	attrib_blk->entry_count = csio_ntohl(attrib_blk->entry_count);
	len = (uint32_t)(pld - (uint8_t *)cmd);
	fdmi_req->dma_buf.len = 2048;		
	/* Submit FDMI RPA request */
	csio_spin_lock_irq(hw, &hw->lock);
	if (csio_lnf_mgmt_submit_req(fdmi_req, csio_lnf_fdmi_done,
				FCOE_CT, &fdmi_req->dma_buf,
				len)) {
		CSIO_INC_STATS(lnf, n_fdmi_err);
		csio_ln_err(lnf->ln, "Failed to issue fdmi rpa req\n");
	}
	csio_spin_unlock_irq(hw, &hw->lock);
}

/**
 * csio_lnf_fdmi_dprt_cbfn - DPRT completion
 * @hw: HW context
 * @fdmi_req: fdmi request
 */
static void
csio_lnf_fdmi_dprt_cbfn(struct csio_hw *hw, struct csio_ioreq *fdmi_req)
{
	void *cmd;
	uint8_t *pld;
	uint32_t len = 0;
	struct csio_hba_identifier *id;
	struct csio_lnode_fcoe *lnf = csio_lnode_to_fcoe(fdmi_req->lnode);
	struct csio_reg_port_list *reg_pl;
	struct csio_attrib_block *attrib_blk;
	uint8_t buf[64];
	
	if (fdmi_req->wr_status != FW_SUCCESS) {
		csio_ln_err(lnf->ln, "WR error in processing fdmi dprt cmd "
		    "wr status:%x", fdmi_req->wr_status);	
		CSIO_INC_STATS(lnf, n_fdmi_err);
	}

	if (!csio_is_rnf_ready(csio_rnode_to_fcoe(fdmi_req->rnode))) {
		CSIO_INC_STATS(lnf, n_fdmi_err);
		return;
	}
	cmd = fdmi_req->dma_buf.vaddr;
	if (csio_ntohs(csio_ct_rsp(cmd)) != CT_RESPONSE_FS_ACC) {
		csio_ln_dbg(lnf->ln, "fdmi dprt cmd rejected "
		    " reason %x expl %x\n", csio_ct_reason(cmd),
		    csio_ct_expl(cmd));
	}

	/* Prepare CT hdr for RHBA cmd */	
	csio_memset(cmd, 0, CT_BASIC_IU_LEN);
	csio_fill_ct_iu(cmd,
			CT_GS_MGMT_SERVICE,
			CT_FDMI_HBA_MGMT_SERVER,
			csio_htons(CT_FDMI_HBA_RHBA));
	len = CT_BASIC_IU_LEN;
	
	/* Prepare RHBA payload */
	pld = (uint8_t *) csio_ct_get_pld(cmd);
	id = (struct csio_hba_identifier *) pld;
	csio_memcpy(id->wwpn, csio_lnf_wwpn(lnf), 8); /* HBA identifer */
	pld += 8;

	/* Register one port per hba */
	reg_pl = (struct csio_reg_port_list *) pld;
	reg_pl->entry_count = csio_ntohl(1);
	csio_memcpy(reg_pl->entry.wwpn, csio_lnf_wwpn(lnf), 8);
	pld += sizeof(*reg_pl);	
	
	/* Start appending HBA attributes hba */
	attrib_blk = (struct csio_attrib_block *) pld;
	attrib_blk->entry_count = 0;
	len += sizeof(attrib_blk->entry_count);
	pld += sizeof(attrib_blk->entry_count);
	
	csio_append_string_attrib(&pld, NODE_NAME, csio_lnf_wwnn(lnf), 8);
	attrib_blk->entry_count++;

	csio_memset(buf, 0, sizeof(buf));

	csio_strcpy(buf, "Chelsio Communications");
	csio_append_string_attrib(&pld, MANUFACTURER, buf,
			(uint16_t)csio_strlen(buf));
	attrib_blk->entry_count++;
	csio_append_string_attrib(&pld, SERIAL_NUMBER, hw->adap.params.vpd.sn,
			(uint16_t)sizeof(hw->adap.params.vpd.sn));
	attrib_blk->entry_count++;
	csio_append_string_attrib(&pld, MODEL, hw->adap.params.vpd.id,
			(uint16_t)sizeof(hw->adap.params.vpd.id));
	attrib_blk->entry_count++;
	csio_append_string_attrib(&pld, MODEL_DESCRIPTION, hw->model_desc,
			(uint16_t)csio_strlen(hw->model_desc));
	attrib_blk->entry_count++;
	csio_append_string_attrib(&pld, HARDWARE_VERSION, hw->hw_ver,
			(uint16_t)sizeof(hw->hw_ver));
	attrib_blk->entry_count++;
	/* TODO: option rom version */
	/* TODO: Driver version */
	csio_append_string_attrib(&pld, FIRMWARE_VERSION, hw->fwrev_str,
			(uint16_t)csio_strlen(hw->fwrev_str));
	attrib_blk->entry_count++;

	if (!csio_osname(hw, buf, sizeof(buf))) {
		csio_append_string_attrib(&pld, OS_NAME_VERSION , buf,
				(uint16_t)csio_strlen(buf));
		attrib_blk->entry_count++;
	}	

	csio_append_int_attrib(&pld, MAX_CT_PAYLOAD_LEN, 65536, 4);
	len = (uint32_t)(pld - (uint8_t *)cmd);
	attrib_blk->entry_count++;
	attrib_blk->entry_count = csio_ntohl(attrib_blk->entry_count);
		
	fdmi_req->dma_buf.len = 2048;		
	/* Submit FDMI RHBA request */
	csio_spin_lock_irq(hw, &hw->lock);
	if (csio_lnf_mgmt_submit_req(fdmi_req, csio_lnf_fdmi_rhba_cbfn,
				FCOE_CT, &fdmi_req->dma_buf,
				len)) {
		CSIO_INC_STATS(lnf, n_fdmi_err);
		csio_ln_err(lnf->ln, "Failed to issue fdmi rhba req\n");
	}
	csio_spin_unlock_irq(hw, &hw->lock);
}

/**
 * csio_lnf_fdmi_dhba_cbfn - DHBA completion
 * @hw: HW context
 * @fdmi_req: fdmi request
 */
static void
csio_lnf_fdmi_dhba_cbfn(struct csio_hw *hw, struct csio_ioreq *fdmi_req)
{
	struct csio_lnode_fcoe *lnf = csio_lnode_to_fcoe(fdmi_req->lnode);
	void *cmd;
	uint8_t *port_name;
	uint32_t len;

	if (fdmi_req->wr_status != FW_SUCCESS) {
		csio_ln_err(lnf->ln, "WR error in processing fdmi dhba cmd "
		    "wr status:%x", fdmi_req->wr_status);	
		CSIO_INC_STATS(lnf, n_fdmi_err);
	}

	if (!csio_is_rnf_ready(csio_rnode_to_fcoe(fdmi_req->rnode))) {
		CSIO_INC_STATS(lnf, n_fdmi_err);
		return;
	}
	cmd = fdmi_req->dma_buf.vaddr;
	if (csio_ntohs(csio_ct_rsp(cmd)) != CT_RESPONSE_FS_ACC) {
		csio_ln_dbg(lnf->ln, "fdmi dhba cmd rejected "
		    " reason %x expl %x\n", csio_ct_reason(cmd),
		    csio_ct_expl(cmd));
	}

	/* Send FDMI cmd to de-register any Port attributes if registered
	 * before
	 */	

	/* Prepare FDMI DPRT cmd */
	csio_memset(cmd, 0, CT_BASIC_IU_LEN);
	csio_fill_ct_iu(cmd,
			CT_GS_MGMT_SERVICE,
			CT_FDMI_HBA_MGMT_SERVER,
			csio_htons(CT_FDMI_HBA_DPRT));
	len = CT_BASIC_IU_LEN;
	port_name = (uint8_t *) csio_ct_get_pld(cmd);
	csio_memcpy(port_name, csio_lnf_wwpn(lnf), 8);
	len += 8;

	fdmi_req->dma_buf.len = 2048;		
	/* Submit FDMI request */
	csio_spin_lock_irq(hw, &hw->lock);
	if (csio_lnf_mgmt_submit_req(fdmi_req, csio_lnf_fdmi_dprt_cbfn,
				FCOE_CT, &fdmi_req->dma_buf,
				len)) {
		CSIO_INC_STATS(lnf, n_fdmi_err);
		csio_ln_err(lnf->ln, "Failed to issue fdmi dprt req\n");
	}
	csio_spin_unlock_irq(hw, &hw->lock);
}

/**
 * csio_lnf_fdmi_start - FDMI start.
 * @lnf: FCoE lnode
 * @context: session context
 * Issued with lock held.
 */
csio_retval_t
csio_lnf_fdmi_start(struct csio_lnode_fcoe *lnf, void *context)
{
	struct csio_ioreq *fdmi_req;
	struct csio_rnode_fcoe *fdmi_rnf = (struct csio_rnode_fcoe *) context;
	void *cmd;
	struct csio_hba_identifier *id;
	uint32_t len;
	
	if (!(lnf->flags & CSIO_LNFFLAG_FDMI_ENABLE))
		return CSIO_NOSUPP;

	if (!csio_is_rnf_ready(fdmi_rnf)) {
		CSIO_INC_STATS(lnf, n_fdmi_err);
	}

	/* Send FDMI cmd to de-register any HBA attributes if registered
	 * before
	 */	

	fdmi_req = lnf->mgmt_req;
	fdmi_req->lnode = lnf->ln;
	fdmi_req->rnode = fdmi_rnf->rn;

	/* Prepare FDMI DHBA cmd */
	cmd = fdmi_req->dma_buf.vaddr;
	csio_memset(cmd, 0, CT_BASIC_IU_LEN);
	csio_fill_ct_iu(cmd,
			CT_GS_MGMT_SERVICE,
			CT_FDMI_HBA_MGMT_SERVER,
			csio_htons(CT_FDMI_HBA_DHBA));
	len = CT_BASIC_IU_LEN;

	id = (struct csio_hba_identifier *) csio_ct_get_pld(cmd);
	csio_memcpy(id->wwpn, csio_lnf_wwpn(lnf), 8);
	len += sizeof(*id);		

	fdmi_req->dma_buf.len = 2048;		
	/* Submit FDMI request */
	if (csio_lnf_mgmt_submit_req(fdmi_req, csio_lnf_fdmi_dhba_cbfn,
				FCOE_CT, &fdmi_req->dma_buf,
				len)) {
		CSIO_INC_STATS(lnf, n_fdmi_err);
		csio_ln_err(lnf->ln, "Failed to issue fdmi dhba req\n");
	}
	return CSIO_SUCCESS;
}

/**
 * csio_fcoe_find_ct_type - This routine finds the CT request's
 * 			service type, based on the GS_Type field
 * 			in the CT command.
 * @hw: HW
 * @ct_cmd_buf: CT Command Buffer
 * @ct_cmd_len: CT Command length.
 *
 * Returns the appropiate destination nport-id for the given CT command.
 */
uint32_t
csio_fcoe_find_ct_type(struct csio_hw *hw, void *ct_cmd_buf,
			uint32_t ct_cmd_len)
{
	uint8_t *ct_cmd 	= (uint8_t *)ct_cmd_buf;
	char *gs_type_str    	= NULL;
	uint32_t ct_dest_id 	= 0;


	if (ct_cmd_len < CT_BASIC_IU_LEN) {
		CSIO_DB_ASSERT(CSIO_FALSE);
		return 0;
	}

	/*
	 * 	Basic CT_IU preamble
	 *
	 *  +------+----------+------------+------------+----------+
	 *  |Byte->|  3	      |	2	   |    1	|   0	   |
	 *  |Word  |	      |		   |	        |	   |
	 *  +------+----------+------------+------------+----------+
	 *  | 0    | Revision |		     IN_ID    		   |
	 *  +------+----------+------------+------------+----------+
	 *  | 1	   |*GS_Type* | GS_SubType |  Options   |  Reserved|
	 *  +------+----------+------------+------------+----------+
	 *  | 2	   |    Cmd/Resp code      |   Max/Residual Size   |
	 *  +------+----------+------------+------------+----------+
	 *  | 3	   | Frag. Id | Reason Code| Explanation| Vendor Sp|
	 *  +------+----------+------------+------------+----------+
	 *
	 */

	switch (ct_cmd[4]) {
		case CT_GS_MGMT_SERVICE:
			gs_type_str = "MGMT SERVICE";
			ct_dest_id = FDMI_DID;
			break;

		case CT_GS_DIR_SERVICE:
			gs_type_str = "DIR SERVICE";
			ct_dest_id = NS_DID;
			break;

		case CT_GS_FABRIC_CNTL_SERVICE:
		case CT_GS_TIME_SERVICE:
		default:
			gs_type_str = "Unsupported SERVICE";
			break;
	} /* switch (ct_cmd) */

	csio_info(hw, "CT cmd GS_TYPE:%s (%x)\n", gs_type_str, ct_dest_id);

	return ct_dest_id;
} /* csio_fcoe_find_ct_type */


/**
 * csio_lnf_vnp_read_cbfn - vnp read completion handler.
 * @hw: HW lnode
 * @rsp: Mailbox response.
 * @lnf: FCoE lnode.
 *
 * Reads vnp response and updates lnf parameters.
 */
static void
csio_lnf_vnp_read_cbfn(struct csio_hw *hw, struct fw_fcoe_vnp_cmd *rsp,
		struct csio_lnode_fcoe *lnf)
{
	struct csio_cmn_sp *csp;
	struct csio_class_sp *clsp;

	csio_spin_lock_irq(hw, &hw->lock);

	csio_memcpy(lnf->mac, rsp->vnport_mac, sizeof(lnf->mac));
	csio_memcpy(&lnf->nport_id, &rsp->vnport_mac[3],
			sizeof(uint8_t)*3);
	lnf->nport_id = csio_ntohl(lnf->nport_id);
	lnf->nport_id = lnf->nport_id>>8;

	/* Update WWNs */
	/*
	 * This may look like a duplication of what csio_fcoe_enable_link()
	 * does, but is absolutely necessary if the vnpi changes between
	 * a FCOE LINK UP and FCOE LINK DOWN.
	 */
	csio_memcpy(csio_lnf_wwnn(lnf), rsp->vnport_wwnn, 8);
	csio_memcpy(csio_lnf_wwpn(lnf), rsp->vnport_wwpn, 8);

	/* Copy common sparam */
	csp = (struct csio_cmn_sp *) rsp->cmn_srv_parms;
	lnf->ln_sparm.csp.hi_ver = csp->hi_ver;
	lnf->ln_sparm.csp.lo_ver = csp->lo_ver;
	lnf->ln_sparm.csp.bb_credit = csio_ntohs(csp->bb_credit);
	lnf->ln_sparm.csp.word1_flags = csio_ntohs(csp->word1_flags);
	lnf->ln_sparm.csp.rcv_sz = csio_ntohs(csp->rcv_sz);
	lnf->ln_sparm.csp.un1.r_a_tov = csio_ntohl(csp->un1.r_a_tov);
	lnf->ln_sparm.csp.e_d_tov = csio_ntohl(csp->e_d_tov);

	/* Copy word 0 & word 1 of class sparam */
	clsp = (struct csio_class_sp *) rsp->clsp_word_0_1;
	lnf->ln_sparm.clsp[2].serv_option = clsp->serv_option;
	lnf->ln_sparm.clsp[2].init_ctl_option = clsp->init_ctl_option;
	lnf->ln_sparm.clsp[2].rcv_ctl_option = clsp->rcv_ctl_option;
	lnf->ln_sparm.clsp[2].rcv_data_sz = csio_ntohs(clsp->rcv_data_sz);

	/* Send an event to update local attribs */
	if (csio_hw_to_ops(hw)->os_ln_async_event)
		csio_hw_to_ops(hw)->os_ln_async_event(lnf->ln,
			CSIO_LNF_OSE_ATTRIB_UPDATE);

	csio_spin_unlock_irq(hw, &hw->lock);
	return;
}

/**
 * csio_lnf_vnp_read - Read vnp params.
 * @lnf: FCoE lnode
 *
 * Issued with lock held.
 */
static csio_retval_t
csio_lnf_vnp_read(struct csio_lnode_fcoe *lnf)
{
	struct csio_hw *hw = lnf->ln->hwp;
	struct adapter *adap = &hw->adap;
	struct fw_fcoe_vnp_cmd c;
	int ret;

	/* Prepare VNP Command */
	csio_fcoe_vnp_read_init_mb(&c, lnf->fcf_flowid, lnf->vnp_flowid);

	/* Issue MBOX cmd */
	csio_spin_unlock_irq(hw, &hw->lock);
	ret = t4_wr_mbox(adap, adap->mbox, &c, sizeof(c), &c);
	if (ret) {
		csio_err(hw, "FCOE VNP read cmd returned error:0x%x\n", ret);
		csio_spin_lock_irq(hw, &hw->lock);
		return CSIO_INVAL;
	}
	csio_spin_lock_irq(hw, &hw->lock);

	csio_spin_unlock_irq(hw, &hw->lock);
	csio_lnf_vnp_read_cbfn(hw, &c, lnf);
	csio_spin_lock_irq(hw, &hw->lock);

	return CSIO_SUCCESS;
}

/**
 * csio_fcoe_enable_link - Enable fcoe link.
 * @lnf: FCoE lnode
 * @enable: enable/disable
 * Issued with lock held.
 * Issues mbox cmd to bring up FCOE link on port associated with given lnf.
 */
csio_retval_t
csio_fcoe_enable_link(struct csio_lnode_fcoe *lnf, bool enable)
{
	struct csio_hw *hw = lnf->ln->hwp;
	struct adapter *adap = &hw->adap;
	uint8_t portid;
	uint8_t sub_op;
	struct fw_fcoe_link_cmd c, *lcmd;
	int i, ret;

	portid = lnf->ln->portid;
	sub_op = enable ? FCOE_LINK_UP : FCOE_LINK_DOWN;

	csio_dbg(hw, "bringing FCOE LINK %s on Port:%d\n", sub_op ? "UP":"DOWN",
		portid);

	csio_write_fcoe_link_cond_init_mb(&c, portid, sub_op,
			(uint8_t)csio_cos, 0, 0);

	/* TODO: Poll for CSIO_MB_DEFAULT_TMO and re-issue mb_issue
	 * if returns busy.
	 */
	csio_spin_unlock_irq(hw, &hw->lock);
	ret = t4_wr_mbox(adap, adap->mbox, &c, sizeof(c), &c);
	if (ret) {
		csio_err(hw, "FCOE LINK %s cmd on port[%d] failed with "
				"ret:x%x\n", sub_op ? "UP" : "DOWN",
				portid, ret);
		csio_spin_lock_irq(hw, &hw->lock);
		return CSIO_INVAL;
	}
	csio_spin_lock_irq(hw, &hw->lock);

	if (!enable)
		goto out;

	lcmd = &c;

	csio_dbg(hw, "pmac:0x%x%x%x%x%x%x  wwnn:0x%x%x%x%x%x%x%x%x"
		 " wwpn:0x%x%x%x%x%x%x%x%x\n",
		 lcmd->phy_mac[0], lcmd->phy_mac[1], lcmd->phy_mac[2],
		 lcmd->phy_mac[3], lcmd->phy_mac[4], lcmd->phy_mac[5],
		 lcmd->vnport_wwnn[0], lcmd->vnport_wwnn[1],
		 lcmd->vnport_wwnn[2], lcmd->vnport_wwnn[3],
		 lcmd->vnport_wwnn[4], lcmd->vnport_wwnn[5],
		 lcmd->vnport_wwnn[6], lcmd->vnport_wwnn[7],
		 lcmd->vnport_wwpn[0], lcmd->vnport_wwpn[1],
		 lcmd->vnport_wwpn[2], lcmd->vnport_wwpn[3],
		 lcmd->vnport_wwpn[4], lcmd->vnport_wwpn[5],
		 lcmd->vnport_wwpn[6], lcmd->vnport_wwpn[7]);
		
	csio_memcpy(csio_lnf_wwnn(lnf), lcmd->vnport_wwnn, 8);
	csio_memcpy(csio_lnf_wwpn(lnf), lcmd->vnport_wwpn, 8);

	for (i = 0; i < CSIO_MAX_T4PORTS; i++)
		if (hw->t4port[i].portid == portid)
			csio_memcpy(hw->t4port[i].mac, lcmd->phy_mac, 6);

out:
	return CSIO_SUCCESS;
}

/**
 * csio_lnf_read_fcf_cbfn - Read fcf parameters
 * @rsp: Mailbox response.
 * @lnf: FCoE lnode
 *
 * read fcf response and Update lnf fcf information.
 */
static void
csio_lnf_read_fcf_cbfn(struct csio_hw *hw, struct fw_fcoe_fcf_cmd *rsp,
		struct csio_lnode_fcoe *lnf)
{
	struct csio_fcf_info	*fcf_info;

	csio_spin_lock_irq(hw, &hw->lock);

	fcf_info = lnf->fcfinfo;
	fcf_info->priority = G_FW_FCOE_FCF_CMD_PRIORITY(
					csio_ntohs(rsp->priority_pkd));
	fcf_info->vf_id = csio_ntohs(rsp->vf_id);
	fcf_info->vlan_id = rsp->vlan_id;
	fcf_info->max_fcoe_size = csio_ntohs(rsp->max_fcoe_size);
	fcf_info->fka_adv = csio_be32_to_cpu(rsp->fka_adv);
	fcf_info->fcfi = G_FW_FCOE_FCF_CMD_FCFI(csio_ntohl(rsp->op_to_fcfi));
	fcf_info->fpma = G_FW_FCOE_FCF_CMD_FPMA(
					rsp->fpma_to_portid);
	fcf_info->spma = G_FW_FCOE_FCF_CMD_SPMA(
					rsp->fpma_to_portid);
	fcf_info->login = G_FW_FCOE_FCF_CMD_LOGIN(
					rsp->fpma_to_portid);
	fcf_info->portid = G_FW_FCOE_FCF_CMD_PORTID(
					rsp->fpma_to_portid);
	csio_memcpy(fcf_info->fc_map, rsp->fc_map,
					sizeof(fcf_info->fc_map));
	csio_memcpy(fcf_info->mac, rsp->mac,
					sizeof(fcf_info->mac));
	csio_memcpy(fcf_info->name_id, rsp->name_id,
					sizeof(fcf_info->name_id));
	csio_memcpy(fcf_info->fabric, rsp->fabric,
				sizeof(fcf_info->fabric));
	csio_memcpy(fcf_info->spma_mac, rsp->spma_mac,
				sizeof(fcf_info->spma_mac));

	csio_spin_unlock_irq(hw, &hw->lock);
	return;
}

/**
 * csio_lnf_read_fcf_entry - Read fcf entry.
 * @lnf: FCoE lnode
 *
 * Issued with lock held.
 */
static csio_retval_t
csio_lnf_read_fcf_entry(struct csio_lnode_fcoe *lnf)
{
	struct csio_hw *hw = lnf->ln->hwp;
	struct adapter *adap = &hw->adap;
	struct fw_fcoe_fcf_cmd c;
	int ret;

	/* Get FCoE FCF information */
	csio_fw_fcoe_read_fcf_init_mb(&c, lnf->ln->portid, lnf->fcf_flowid);

	csio_spin_unlock_irq(hw, &hw->lock);
	ret = t4_wr_mbox(adap, adap->mbox, &c, sizeof(c), &c);
	if (ret) {
		csio_ln_err(lnf->ln, "FCOE FCF cmd failed with ret x%x\n",
			       	ret);
		csio_spin_lock_irq(hw, &hw->lock);
		return CSIO_INVAL;
	}
	csio_spin_lock_irq(hw, &hw->lock);
	
	csio_spin_unlock_irq(hw, &hw->lock);
	csio_lnf_read_fcf_cbfn(hw, &c, lnf);
	csio_spin_lock_irq(hw, &hw->lock);

	return CSIO_SUCCESS;
}

/**
 * csio_handle_link_up - Logical Linkup event.
 * @hw - HW module.
 * @portid - Physical port number
 * @fcfi - FCF index.
 * @vnpi - VNP index.
 * Returns - none.
 *
 * This event is received from FW, when virtual link is established between
 * Physical port[ENode] and FCF. If its new vnpi, then local node object is
 * created on this FCF and set to [ONLINE] state.
 * Lnode waits for FW_RDEV_CMD event to be received indicating that
 * Fabric login is completed and lnode moves to [READY] state.
 *
 * This called with hw lock held
 */
static void
csio_handle_link_up(struct csio_hw *hw, uint8_t portid, uint32_t fcfi,
		    uint32_t vnpi)
{
	struct csio_lnode_fcoe *lnf;
	struct csio_lnode *ln = NULL;
#ifdef __CSIO_TARGET__
	struct csio_lnode_fcoe *tlnf = NULL;
#endif /* __CSIO_TARGET__ */
	
	/* Lookup lnode based on vnpi */
	lnf = csio_lnf_lookup_by_vnpi(hw, vnpi);
	if (!lnf) {
		/* Pick lnode based on portid */
		lnf = csio_lnf_lookup_by_portid(hw, portid);
		if (!lnf) {
			csio_err(hw, "failed to lookup fcoe lnode on port:%d\n",
				portid);
			CSIO_DB_ASSERT(0);
			return;
		}

		/* Check if lnode has valid vnp flowid */
		if (lnf->vnp_flowid != CSIO_INVALID_IDX) {
#ifdef __CSIO_TARGET__
			/* Save off the original lnf reference */
			tlnf = lnf;
#endif /* __CSIO_TARGET__ */
			/* New VN-Port */
			csio_spin_unlock_irq(hw, &hw->lock);
			ln = csio_hw_to_ops(hw)->os_alloc_lnode(hw);
			csio_spin_lock_irq(hw, &hw->lock);
			if (!ln) {
				csio_err(hw, "failed to allocate fcoe lnode"
					"for port:%d vnpi:x%x\n", portid, vnpi);
				CSIO_DB_ASSERT(0);
				return;
			}
			lnf = csio_lnode_to_fcoe(ln);
			lnf->ln->portid = portid;

#ifdef __CSIO_TARGET__
			/*
			 * Copy WWPN and WWNN from the existing lnode as it
			 * will remain the same for a given port
			 */
			csio_memcpy(csio_lnf_wwnn(lnf), csio_lnf_wwnn(tlnf), 8);
			csio_memcpy(csio_lnf_wwpn(lnf), csio_lnf_wwpn(tlnf), 8);

			/*
			 * Since we dont unregister the target with the SAL
			 * during a link-down, we will have an active instance
			 * of the SAL target with us. We just copy it over the
			 * new lnode, and invalidate the existing one. This is
			 * to avoid duplicate registrations with SAL, without an
			 * intervening unreg.
			 */
			lnf->ln->tgt_hdl = tlnf->ln->tgt_hdl;
			tlnf->ln->tgt_hdl = NULL;
#endif /* __CSIO_TARGET__ */
		}
		lnf->vnp_flowid = vnpi;	
		lnf->ln->dev_num &= ~0xFFFF;
		lnf->ln->dev_num |= vnpi;
	}

	/*Initialize fcfi */
	lnf->fcf_flowid = fcfi;

	csio_info(hw, "Port:%d - FCOE LINK UP\n", portid);
	csio_dbg(hw, "vnpi:x%x\n", vnpi);	

	CSIO_INC_STATS(lnf, n_link_up);

	/* Send LINKUP event to SM */
	csio_post_event(&lnf->sm, CSIO_LNFE_LINKUP);
	return;
}

/**
 * csio_post_event_rnfs
 * @lnf - FCOE lnode
 * @evt - Given rnode event
 * Returns - none
 *
 * Posts given rnode event to all FCOE rnodes connected with given Lnode.
 * This routine is invoked when lnode receives LINK_DOWN/DOWN_LINK/CLOSE
 * event.
 *
 * This called with hw lock held
 */
static void
csio_post_event_rnfs(struct csio_lnode_fcoe *lnf, csio_rnf_ev_t evt)
{
	struct csio_rnode *rnhead = (struct csio_rnode *) &lnf->ln->rnhead;
	struct csio_list *tmp, *next;
	struct csio_rnode *rn;
	struct csio_rnode_fcoe *rnf;

	csio_list_for_each_safe(tmp, next, &rnhead->rnlist) {
		rn = (struct csio_rnode *) tmp;
		rnf = csio_rnode_to_fcoe(rn);
		csio_post_event(&rnf->sm, evt);

#ifdef __CSIO_TARGET__
		/* Free up rnodes that dont need to exist */
		if (csio_is_rnf_uninit(rnf))
			csio_put_rn(lnf->ln, rnf->rn);
#endif /* __CSIO_TARGET__ */

	}
}

/**
 * csio_cleanup_rnfs
 * @lnf - FCOE lnode
 * Returns - none
 *
 * Frees all FCOE rnodes connected with given Lnode.
 *
 * This called with hw lock held
 */
static void
csio_cleanup_rnfs(struct csio_lnode_fcoe *lnf)
{
	struct csio_rnode *rnhead = (struct csio_rnode *) &lnf->ln->rnhead;
	struct csio_list *tmp, *next_rn;
	struct csio_rnode *rn;

	csio_list_for_each_safe(tmp, next_rn, &rnhead->rnlist) {
		rn = (struct csio_rnode *) tmp;
		csio_put_rn(lnf->ln, rn);
	}

}

/**
 * csio_post_event_lnfs
 * @lnf - FCOE lnode
 * @evt - Given lnode event
 * Returns - none
 *
 * Posts given lnode event to all FCOE lnodes connected with given Lnode.
 * This routine is invoked when lnode receives LINK_DOWN/DOWN_LINK/CLOSE
 * event.
 *
 * This called with hw lock held
 */
static void
csio_post_event_lnfs(struct csio_lnode_fcoe *lnf, csio_lnf_ev_t evt)
{
	struct csio_list *tmp;
	struct csio_lnode *cln, *sln;
	struct csio_lnode_fcoe *clnf;
	
	/* If NPIV lnode, send evt only to that and return */
	if (csio_is_npiv_lnf(lnf)) {
		csio_post_event(&lnf->sm, evt);
		return;
	}

	sln = lnf->ln;
	/* Traverse children lnodes list and send evt */
	csio_list_for_each(tmp, &sln->cln_head) {
		cln = (struct csio_lnode *) tmp;
		clnf = csio_lnode_to_fcoe(cln);
		csio_post_event(&clnf->sm, evt);
	}

	/* Send evt to parent lnode */
	csio_post_event(&lnf->sm, evt);
}

/**
 * csio_lnf_down - Lcoal nport is down
 * @lnf - FCOE Lnode
 * Returns - none
 *
 * Sends LINK_DOWN events to Lnode and its associated NPIVs lnodes.
 *
 * This called with hw lock held
 */
void
csio_lnf_down(struct csio_lnode_fcoe *lnf)
{
	csio_post_event_lnfs(lnf, CSIO_LNFE_LINK_DOWN);
}

/**
 * csio_handle_link_down - Logical Linkdown event.
 * @hw - HW module.
 * @portid - Physical port number
 * @fcfi - FCF index.
 * @vnpi - VNP index.
 * Returns - none
 *
 * This event is received from FW, when virtual link goes down between
 * Physical port[ENode] and FCF. Lnode and its associated NPIVs lnode hosted on
 * this vnpi[VN-Port] will be de-instantiated.
 *
 * This called with hw lock held
 */
static void
csio_handle_link_down(struct csio_hw *hw, uint8_t portid, uint32_t fcfi,
		      uint32_t vnpi)
{
	struct csio_fcf_info *fp;
	struct csio_lnode_fcoe *lnf;

	/* Lookup lnode based on vnpi */
	lnf = csio_lnf_lookup_by_vnpi(hw, vnpi);
	if (lnf) {
       		fp = lnf->fcfinfo;
		CSIO_INC_STATS(lnf, n_link_down);

		/*Warn if linkdown received if lnode is not in ready state */
		if (!csio_is_lnf_ready(lnf)) {
			csio_ln_warn(lnf->ln,
				"warn: FCOE link is already in offline "
				"Ignoring Fcoe linkdown event on portid %d\n",
				 portid);
			CSIO_INC_STATS(lnf, n_evt_drop);
			return;
		}
		
		/* Verify portid */
		if (fp->portid != portid) {
			csio_ln_warn(lnf->ln,
				"warn: FCOE linkdown recv with "
				"invalid port %d\n", portid);
			CSIO_INC_STATS(lnf, n_evt_drop);
			return;
		}

		/* verify fcfi */	
		if (lnf->fcf_flowid != fcfi) {
			csio_ln_warn(lnf->ln,
				"warn: FCOE linkdown recv with "
				"invalid fcfi x%x\n", fcfi);
			CSIO_INC_STATS(lnf, n_evt_drop);
			return;
		}

		csio_info(hw, "Port:%d - FCOE LINK DOWN\n", portid);
		csio_dbg(hw, "vnpi:x%x\n", vnpi);	

		/* Send LINK_DOWN event to lnode s/m */
		csio_lnf_down(lnf);
		
		return;
	}
	else {
		csio_warn(hw, "warn: FCOE linkdown recv with invalid "
			"vnpi x%x\n", vnpi);
		CSIO_INC_STATS(hw, n_evt_drop);
	}
	return;
}

/**
 * csio_is_lnf_ready - Checks FCOE lnode is in ready state.
 * @lnf: Lnode FCoE module
 *
 * Returns True if FCOE lnode is in ready state.
 */
int
csio_is_lnf_ready(struct csio_lnode_fcoe *lnf)
{
	return (csio_get_state(lnf) == ((csio_sm_state_t)csio_lnfs_ready));
}

/*****************************************************************************/
/* START: FCoE Lnode SM                                                      */
/*****************************************************************************/
/*
 * csio_lnfs_uninit - The request in uninit state.
 * @lnf - FCOE lnode.
 * @evt - Event to be processed.
 *
 * Process the given lnode event which is currently in "uninit" state.
 * Invoked with HW lock held.
 * Return - none.
 */
static void
csio_lnfs_uninit(struct csio_lnode_fcoe *lnf, csio_lnf_ev_t evt)
{
	struct csio_hw *hw = csio_lnode_to_hw(lnf->ln);
	struct csio_lnode_fcoe *rlnf = csio_lnode_to_fcoe(hw->rln);
	enum csio_oss_error rv;

	CSIO_INC_STATS(lnf, n_evt_sm[evt]);
	switch (evt) {

	case CSIO_LNFE_LINKUP:
#ifdef __CSIO_TARGET__
		/* TODO: Handle the error from csio_tgt_register */
		/*
		 * We could already have an active target with SAL, if
		 * we got here due to an existing portname coming up
		 * with a different vnp_flowid. We would not have
		 * unregistered with SAL, to persist the LUN mapping.
		 * In such situations, tgt_hdl would not be NULL,
		 * and we avoid duplicate registrations.
		 */
		if (csio_target_mode(hw) && !lnf->ln->tgt_hdl)
			if (csio_tgt_register(lnf->ln)) {
				CSIO_DB_ASSERT(0);
			}
#endif /* __CSIO_TARGET__ */
		csio_set_state(&lnf->sm, csio_lnfs_online);
		/* Read FCF only for physical lnode */
		if (csio_is_phys_lnf(lnf)) {
			rv = csio_lnf_read_fcf_entry(lnf);
			if (rv != CSIO_SUCCESS) {
			/* TODO: Send HW RESET event */
				CSIO_INC_STATS(lnf, n_err);
				break;
			}

			/* Add FCF record */
			csio_enq_at_tail(&rlnf->fcf_lsthead,
						&lnf->fcfinfo->list);
		}

		rv = csio_lnf_vnp_read(lnf);
		if (rv != CSIO_SUCCESS) {
			/* TODO: Send HW RESET event */
			CSIO_INC_STATS(lnf, n_err);
		}		
		break;

	case CSIO_LNFE_DOWN_LINK:
	case CSIO_LNFE_CLOSE:
		break;

	default:
		csio_ln_err(lnf->ln, "unexp lnf event %d recv from did:x%x in "
			"lnf state[uninit].\n", evt, lnf->nport_id);
		CSIO_INC_STATS(lnf, n_evt_unexp);
		break;
	} /* switch event */

	return;
}

/*
 * csio_lnfs_online - The request in online state.
 * @lnf - FCOE lnode.
 * @evt - Event to be processed.
 *
 * Process the given lnode event which is currently in "online" state.
 * Invoked with HW lock held.
 * Return - none.
 */
static void
csio_lnfs_online(struct csio_lnode_fcoe *lnf, csio_lnf_ev_t evt)
{
	struct csio_hw *hw = csio_lnode_to_hw(lnf->ln);

	CSIO_INC_STATS(lnf, n_evt_sm[evt]);
	switch (evt) {

	case CSIO_LNFE_LINKUP:
		csio_ln_warn(lnf->ln, "warn: FCOE link is up already "
			"Ignoring linkup on port:%d\n", lnf->ln->portid);
		CSIO_INC_STATS(lnf, n_evt_drop);
		break;

	case CSIO_LNFE_FAB_INIT_DONE:
		csio_set_state(&lnf->sm, csio_lnfs_ready);

		if (csio_hw_to_ops(hw)->os_ln_async_event) {
			csio_spin_unlock_irq(hw, &hw->lock);
			csio_hw_to_ops(hw)->os_ln_async_event(lnf->ln,
					CSIO_LNF_OSE_LINKUP);
			csio_spin_lock_irq(hw, &hw->lock);
		}	

		break;

	case CSIO_LNFE_LINK_DOWN:
#ifdef __CSIO_TARGET__
		if (csio_target_mode(hw))
			csio_tgt_unregister(lnf->ln);
#endif /* __CSIO_TARGET__ */
		/* Fall through */
	case CSIO_LNFE_DOWN_LINK:
		csio_set_state(&lnf->sm, csio_lnfs_uninit);
		if (csio_is_phys_lnf(lnf)) {
			/* Remove FCF entry */
			csio_deq_elem(&lnf->fcfinfo->list);
		}
		break;

	default:
		csio_ln_err(lnf->ln, "unexp lnf event %d recv from did:x%x in "
			"lnf state[uninit].\n", evt, lnf->nport_id);
		CSIO_INC_STATS(lnf, n_evt_unexp);
/*		CSIO_DB_ASSERT(0); */
			
		break;
	} /* switch event */

	return;
}

/*
 * csio_lnfs_ready - The request in ready state.
 * @lnf - FCOE lnode.
 * @evt - Event to be processed.
 *
 * Process the given lnode event which is currently in "ready" state.
 * Invoked with HW lock held.
 * Return - none.
 */
static void
csio_lnfs_ready(struct csio_lnode_fcoe *lnf, csio_lnf_ev_t evt)
{
	struct csio_hw *hw = csio_lnode_to_hw(lnf->ln);

	CSIO_INC_STATS(lnf, n_evt_sm[evt]);
	switch (evt) {

	case CSIO_LNFE_FAB_INIT_DONE:
		csio_ln_dbg(lnf->ln, "ignoring event %d recv from did x%x"
			"in lnf state[ready].\n", evt, lnf->nport_id);
		CSIO_INC_STATS(lnf, n_evt_drop);
		break;

	case CSIO_LNFE_LINK_DOWN:
		csio_set_state(&lnf->sm, csio_lnfs_offline);
		csio_post_event_rnfs(lnf, CSIO_RNFE_DOWN);	

		if (csio_hw_to_ops(hw)->os_ln_async_event) {
			csio_spin_unlock_irq(hw, &hw->lock);
			csio_hw_to_ops(hw)->os_ln_async_event(lnf->ln,
					CSIO_LNF_OSE_LINKDOWN);
			csio_spin_lock_irq(hw, &hw->lock);
		}	
		if (csio_is_phys_lnf(lnf)) {
			/* Remove FCF entry */
			csio_deq_elem(&lnf->fcfinfo->list);
		}
		break;

	case CSIO_LNFE_DOWN_LINK:
		csio_set_state(&lnf->sm, csio_lnfs_offline);
		/*
		 * REVISIT:Need to free ELSCT/SCSI queues here
		 * with a WR module function that calls
		 * csio_mb_iq/eq_ofld_free().
		 * We could send the MB's in immediate mode,
		 * since this event typically comes from a user
		 * context (reset/PCI remove).
		 */
		csio_post_event_rnfs(lnf, CSIO_RNFE_DOWN);	

		/* Host need to issue aborts in case if FW has not returned
		 * WRs with status "ABORTED"
		 */
		if (csio_hw_to_ops(hw)->os_ln_async_event) {
			csio_hw_to_ops(hw)->os_ln_async_event(lnf->ln,
					CSIO_LNF_OSE_LINKDOWN);
		}		
		if (csio_is_phys_lnf(lnf)) {
			/* Remove FCF entry */
			csio_deq_elem(&lnf->fcfinfo->list);
		}
		break;

	case CSIO_LNFE_CLOSE:
		csio_set_state(&lnf->sm, csio_lnfs_uninit);
		/* TODO: For NPIV lnode, send mbox cmd to delete vnp */
		csio_post_event_rnfs(lnf, CSIO_RNFE_CLOSE);	
		break;

	case CSIO_LNFE_LOGO:
		/* FIXME: If Fabric logo received  send offline events to
		 * NPIV lnodes and rnodes connected to NPIV lnodes.
		 */	
		csio_set_state(&lnf->sm, csio_lnfs_offline);
		csio_post_event_rnfs(lnf, CSIO_RNFE_DOWN);	
		break;

	default:
		csio_ln_err(lnf->ln, "unexp lnf event %d recv from did:x%x in "
			"lnf state[uninit].\n", evt, lnf->nport_id);
		CSIO_INC_STATS(lnf, n_evt_unexp);
		CSIO_DB_ASSERT(0);
		break;
	} /* switch event */

	return;
}

/*
 * csio_lnfs_offline - The request in offline state.
 * @lnf - FCOE lnode.
 * @evt - Event to be processed.
 *
 * Process the given lnode event which is currently in "offline" state.
 * Invoked with HW lock held.
 * Return - none.
 */
static void
csio_lnfs_offline(struct csio_lnode_fcoe *lnf, csio_lnf_ev_t evt)
{
	struct csio_hw *hw = csio_lnode_to_hw(lnf->ln);
	struct csio_lnode_fcoe *rlnf = csio_lnode_to_fcoe(hw->rln);
	enum csio_oss_error rv;

	CSIO_INC_STATS(lnf, n_evt_sm[evt]);
	switch (evt) {

	case CSIO_LNFE_LINKUP:
		csio_set_state(&lnf->sm, csio_lnfs_online);
		/* Read FCF only for physical lnode */
		if (csio_is_phys_lnf(lnf)) {
			rv = csio_lnf_read_fcf_entry(lnf);
			if (rv != CSIO_SUCCESS) {
			/* TODO: Send HW RESET event */
				CSIO_INC_STATS(lnf, n_err);
				break;
			}

			/* Add FCF record */
			csio_enq_at_tail(&rlnf->fcf_lsthead,
						&lnf->fcfinfo->list);
		}

		rv = csio_lnf_vnp_read(lnf);
		if (rv != CSIO_SUCCESS) {
			/* TODO: Send HW RESET event */
			CSIO_INC_STATS(lnf, n_err);
		}		
		break;

	case CSIO_LNFE_LINK_DOWN:
	case CSIO_LNFE_DOWN_LINK:
	case CSIO_LNFE_LOGO:
	case CSIO_LNFE_RESET:
		csio_ln_dbg(lnf->ln, "ignoring event %d recv from did x%x"
			"in lnf state[offline].\n", evt, lnf->nport_id);
		CSIO_INC_STATS(lnf, n_evt_drop);
		break;

	case CSIO_LNFE_CLOSE:
		csio_set_state(&lnf->sm, csio_lnfs_uninit);
		/* TODO: For NPIV lnode, send mbox cmd to delete vnp */
		csio_post_event_rnfs(lnf, CSIO_RNFE_CLOSE);
		break;

	default:
		csio_ln_err(lnf->ln, "unexp lnf event %d recv from did:x%x in "
			"lnf state[offline].\n", evt, lnf->nport_id);
		CSIO_INC_STATS(lnf, n_evt_unexp);
		CSIO_DB_ASSERT(0);
		break;
	} /* switch event */

	return;
}

/*****************************************************************************/
/* END: FCoE Lnode SM                                                        */
/*****************************************************************************/

static void
csio_free_fcfinfo(void *p)
{
	struct csio_lnode_fcoe *lnf = (struct csio_lnode_fcoe *)p;
	struct csio_hw *hw = csio_lnode_to_hw(lnf->ln);

	csio_free(csio_md(hw, CSIO_FCOE_FCF_MD), lnf->fcfinfo);
	return;
}

/*****************************************************************************/
/* Helper routines for debugfs */
/*****************************************************************************/

/**
 * csio_fcoe_get_next_fcf - Gets next FCF record.
 * @hw: HW module
 * @fcfi: Given fcfi index
 * This routine returns the next FCF record from given fcfi index. If given
 * fcfi is set to CSIO_INVALID_IDX, it will return first FCF record.
 */
struct csio_fcf_info *csio_fcoe_get_next_fcf(struct csio_hw *hw, uint32_t fcfi)
{
	struct csio_list *tmp, *tmp_next;
	struct csio_lnode_fcoe *plnf;
	struct csio_fcf_info *fcf;
	
	if (!hw->rln)
		return NULL;

	plnf = csio_lnode_to_fcoe(hw->rln);

	if (csio_list_empty(&plnf->fcf_lsthead)) {
		return NULL;
	}

	csio_list_for_each_safe(tmp, tmp_next, &plnf->fcf_lsthead) {
		fcf = (struct csio_fcf_info *) tmp;
		if (fcfi == CSIO_INVALID_IDX) {
			return fcf;
		}
		if (fcf->fcfi == fcfi && tmp_next != &plnf->fcf_lsthead) {
			fcf = (struct csio_fcf_info *) tmp_next;
			return fcf;
		}
	}

	return NULL;
}


/**
 * csio_fcoe_get_next_lnode_by_handle - Gets next Lnode.
 * @hw: HW module
 * @handle: Opaque handle (to user app). For us, its the addr of lnode itself.
 * This routine returns the next lnode from given lnode handle. If given
 * vnpi is set to CSIO_INVALID_IDX, it will return first lnode.
 */
static struct csio_lnode *
csio_fcoe_get_next_lnode_by_handle(struct csio_hw *hw,
				uint64_t handle)
{
	struct csio_list *cur_ln, *next_ln;
	struct csio_lnode *sln = NULL;
	struct csio_lnode_fcoe *lnf = NULL;

	if (csio_list_empty(&hw->sln_head))
		return NULL;

	/* Traverse sibling lnodes */
	csio_list_for_each_safe(cur_ln, next_ln, &hw->sln_head) {
		sln = (struct csio_lnode *) cur_ln;

		/* Match sibling lnode */
		lnf = csio_lnode_to_fcoe(sln);

		if (handle == 0) {
			return sln;
		}

		if (lnf == (struct csio_lnode_fcoe *)((uintptr_t)handle) &&
				next_ln != &hw->sln_head) {
			sln = (struct csio_lnode *) next_ln;
			return sln;
		}		
	}

	return NULL;

} /* csio_fcoe_get_next_lnode_by_handle */


/**
 * csio_fcoe_get_next_lnode - Gets next Lnode.
 * @hw: HW module
 * @vnpi: Given vnpi index
 * This routine returns the next lnode from given vnpi index. If given
 * vnpi is set to CSIO_INVALID_IDX, it will return first lnode.
 */
struct csio_lnode *csio_fcoe_get_next_lnode(struct csio_hw *hw, uint32_t vnpi)
{
	struct csio_list *cur_ln, *next_ln, *cur_cln, *next_cln;
	struct csio_lnode *sln = NULL, *cln = NULL, *nln;
	struct csio_lnode_fcoe *lnf = NULL;

	if (csio_list_empty(&hw->sln_head))
		return NULL;

	/* Traverse sibling lnodes */
	csio_list_for_each_safe(cur_ln, next_ln, &hw->sln_head) {
		sln = (struct csio_lnode *) cur_ln;

		/* Match sibling lnode */
		lnf = csio_lnode_to_fcoe(sln);

		/* Skip if the lnf in uninit state */
		if(csio_get_state(lnf) == ((csio_sm_state_t)csio_lnfs_uninit))
			continue;

		if (vnpi == CSIO_INVALID_IDX) {
			return sln;
		}

		if (csio_list_empty(&sln->cln_head)) {
			if (lnf->vnp_flowid == vnpi && next_ln !=
			    &hw->sln_head) {
				nln = (struct csio_lnode *) next_ln;
				/* Skip if the lnf in uninit state */
				if(csio_get_state(csio_lnode_to_fcoe(nln))
					== ((csio_sm_state_t)csio_lnfs_uninit))
					continue;
				sln = (struct csio_lnode *) next_ln;
				return sln;
			}
			continue;
		}

		/* Traverse children lnodes */
		csio_list_for_each_safe(cur_cln, next_cln, &sln->cln_head) {
			cln = (struct csio_lnode *) cur_cln;

			/* Match child lnode */
			lnf = csio_lnode_to_fcoe(cln);

			/* Skip if the lnf in uninit state */
			if(csio_get_state(lnf) ==
					((csio_sm_state_t)csio_lnfs_uninit))
				continue;

			if (lnf->vnp_flowid == vnpi && next_cln !=
				&sln->cln_head) {
				nln = (struct csio_lnode *) next_cln;
				/* Skip if the lnf in uninit state */
				if(csio_get_state(csio_lnode_to_fcoe(nln))
					== ((csio_sm_state_t)csio_lnfs_uninit))
					continue;
				cln = (struct csio_lnode *) next_cln;
				return cln;
			}
		}
	}
	return NULL;
}


/**
 * csio_lnf_stateto_str - Get current state of FCOE lnode.
 * @rnf - FCoE rnode
 * @str - state of lnode.
 *
 */
void csio_lnf_stateto_str(struct csio_lnode_fcoe *lnf, int8_t *str)
{
	if (csio_get_state(lnf) == ((csio_sm_state_t)csio_lnfs_uninit)) {
		csio_strcpy(str, "UNINIT");
		return;
	}	
	if (csio_get_state(lnf) == ((csio_sm_state_t)csio_lnfs_ready)) {
		csio_strcpy(str, "READY");
		return;
	}	
	if (csio_get_state(lnf) == ((csio_sm_state_t)csio_lnfs_offline)) {
		csio_strcpy(str, "OFFLINE");
		return;
	}	
	csio_strcpy(str, "UNKNOWN");
} /* csio_lnf_stateto_str */

/**
 * csio_get_phy_port_stats - Get FCOE phy port stats
 * @hw: HW module
 * @portid - Physical port number
 * @port_stats - Stats structure to be filled up
 *
 * This function should always be called with hw->lock held
 */
csio_retval_t
csio_get_phy_port_stats(struct csio_hw *hw, uint8_t portid,
				struct fw_fcoe_port_stats *port_stats)
{
	struct adapter *adap = &hw->adap;
	struct fw_fcoe_stats_cmd c;
	struct fw_fcoe_port_cmd_params portparams;
	int idx, ret;

	portparams.portid = portid;

	for (idx = 1; idx <= 3; idx++) {
		portparams.idx = (idx-1)*6 + 1;
		portparams.nstats = 6;
		if (idx == 3)
			portparams.nstats = 4;
		csio_fcoe_read_portparams_init_mb(&c, &portparams);
		csio_spin_unlock_irq(hw, &hw->lock);
		ret = t4_wr_mbox(adap, adap->mbox, &c, 64, &c);
		if (ret) {
			csio_printk("CSIO: FCoE PARAMS command failed,"
				       " err %d!\n", ret);
			csio_spin_lock_irq(hw, &hw->lock);
			return CSIO_INVAL;
		}
		csio_spin_lock_irq(hw, &hw->lock);
		csio_mb_process_portparams_rsp(&c, &portparams, port_stats);
	}
	return CSIO_SUCCESS;
}


static csio_retval_t
csio_get_fcf_stats(struct csio_hw *hw,struct csio_fcf_info *fcf,
					csio_fcf_info_t *fcf_info)
{
	struct adapter *adap = &hw->adap;
	struct fw_fcoe_stats_cmd c;
	struct fw_fcoe_fcf_cmd_params fcfparams;
	int idx, ret;
	
	fcfparams.fcfi = fcf->fcfi;
	for (idx = 1; idx <= 2; idx++) {
		fcfparams.idx = (idx-1)*6 + 1;
		fcfparams.nstats = 6;
		if (idx == 2)
			fcfparams.nstats = 1;		
		csio_fcoe_read_fcfparams_init_mb(&c, &fcfparams);
		csio_spin_unlock_irq(hw, &hw->lock);
		ret = t4_wr_mbox(adap, adap->mbox, &c, 64, &c);
		if (ret) {
			csio_printk("CSIO: Issue of FCoE PARAMS"
					"command failed!, err %d\n", ret);
			csio_spin_lock_irq(hw, &hw->lock);
			return CSIO_INVAL;
		}
		csio_spin_lock_irq(hw, &hw->lock);
		csio_mb_process_fcfparams_rsp(&c, &fcfparams,
				&fcf_info->fcf_stats);
	}
	return CSIO_SUCCESS;
}


static csio_retval_t
csio_get_vnp_stats(struct csio_hw *hw,  struct csio_lnode *ln,
					csio_fcoe_lnode_t *lnf_info)
{
	struct adapter *adap = &hw->adap;
	struct fw_fcoe_stats_cmd c;
	struct fw_fcoe_vnp_cmd_params vpnparams;
	int idx, ret;
	struct csio_lnode_fcoe *lnf = NULL;

	lnf = csio_lnode_to_fcoe(ln);
	
	if (lnf->vnp_flowid == CSIO_INVALID_IDX )
		return CSIO_INVAL;

	vpnparams.vnpi = lnf->vnp_flowid;
	for (idx = 1; idx <= 2; idx++) {
		vpnparams.idx = (idx-1)*6 + 1;
		vpnparams.nstats = 6;
		if (idx == 2)
			vpnparams.nstats = 2;
		csio_fcoe_read_vnpparams_init_mb(&c, &vpnparams);
		csio_spin_unlock_irq(hw, &hw->lock);
		ret = t4_wr_mbox(adap, adap->mbox, &c, 64, &c);
	       	if (ret) {
			csio_printk("CSIO: Issue of FCoE PARAMS"
					"command failed!, err %d\n", ret);
			csio_spin_lock_irq(hw, &hw->lock);
			return CSIO_INVAL;
		}
		csio_spin_lock_irq(hw, &hw->lock);
		csio_mb_process_vnpparams_rsp(&c, &vpnparams,
				&lnf_info->vnp_stats);
	}
	return CSIO_SUCCESS;
}

static void
csio_copy_lnf_stats(csio_fcoe_lnode_t *lnf_info,
		struct csio_lnode_fcoestats *lnf_stats)
{
	csio_lnode_fcoestats_t *lnfinfo_stats = &lnf_info->stats;
	
	lnfinfo_stats->n_link_up	= lnf_stats->n_link_up;
	lnfinfo_stats->n_link_down	= lnf_stats->n_link_down;
	lnfinfo_stats->n_err		= lnf_stats->n_err;
	lnfinfo_stats->n_err_nomem	= lnf_stats->n_err_nomem;
	lnfinfo_stats->n_inval_parm	= lnf_stats->n_inval_parm;
	lnfinfo_stats->n_evt_unexp	= lnf_stats->n_evt_unexp;
	lnfinfo_stats->n_evt_drop	= lnf_stats->n_evt_drop;
	lnfinfo_stats->n_rnode_match	= lnf_stats->n_rnode_match;
	lnfinfo_stats->n_dev_loss_tmo	= lnf_stats->n_dev_loss_tmo;
	lnfinfo_stats->n_fdmi_err	= lnf_stats->n_fdmi_err;

	csio_memcpy(lnfinfo_stats->n_evt_fw, lnf_stats->n_evt_fw,
			(RSCN_DEV_LOST * sizeof(uint32_t)));
	csio_memcpy(lnfinfo_stats->n_evt_sm, lnf_stats->n_evt_sm,
			(CSIO_LNFE_MAX_EVENT * sizeof(csio_lnf_ev_t)));
	return;
} /* csio_copy_lnf_stats */

/**
 * csio_copy_fcoe_lnode_info - Get the specified lnode info.
 * @hw - HW module
 * @lnf_info - User buffer
 * @lnf - FCoE Lnode
 */
static void
csio_copy_fcoe_lnode_info(struct csio_hw *hw, csio_fcoe_lnode_t *lnf_info,
			struct csio_lnode_fcoe *lnf)
{
	struct csio_lnode *ln = lnf->ln;	
	int i = 0;

	csio_get_vnp_stats(hw, lnf->ln, lnf_info);

	lnf_info->portid	= ln->portid;
	lnf_info->dev_num	= ln->dev_num;
	lnf_info->vnp_flowid	= lnf->vnp_flowid;
	lnf_info->fcf_flowid	= lnf->fcf_flowid;
	lnf_info->nport_id	= lnf->nport_id;

	lnf_info->is_vport	= csio_is_npiv_lnf(lnf);
	lnf_info->num_vports	= ln->num_vports;

	csio_memcpy(lnf_info->mac, lnf->mac, 6);

	lnf_info->num_reg_rnodes= ln->num_reg_rnodes;
	lnf_info->flags 	= lnf->flags;

	/* Set the handle for this lnodeinfo */
	lnf_info->opq_handle	= (uintptr_t)lnf;

	csio_memcpy(&lnf_info->ln_sparm, &lnf->ln_sparm,
			sizeof(struct csio_service_parms));

	csio_copy_lnf_stats(lnf_info, &lnf->stats);

	csio_lnf_stateto_str(lnf, lnf_info->state);

	/* Events */
	lnf_info->max_lnf_events= (uint8_t)CSIO_LNFE_MAX_EVENT;
	lnf_info->cur_evt	= lnf->cur_evt;
	lnf_info->prev_evt	= lnf->prev_evt;	
	lnf_info->sess_ofld	= 1;
	
	for (i = 0; i < lnf_info->max_lnf_events; i++) {
		csio_strncpy(lnf_info->lnf_evt_name[i],
				(char *)csio_lnf_evt_name(i), 32);
	}

	for (i = PLOGI_ACC_RCVD; i <= RSCN_DEV_LOST; i++) {
		csio_strncpy(lnf_info->fw_evt_name[i],
				(char *)csio_rnf_fwevt_name(i), 32);
	}

	return;
} /* csio_copy_fcoe_lnode_info */

/**
 * csio_fcoe_get_lnode_info_by_fcid - Get the specified lnode info.
 * @hw - HW module
 * @buffer - Buffer where fcoe lnode info to be copied.
 * @len - buffer length
 */
static csio_retval_t
csio_fcoe_get_lnode_info_by_fcid(struct csio_hw *hw, void *buffer, uint32_t buffer_len)
{
	csio_fcoe_lnode_t *lnf_info = buffer;
	struct csio_lnode *ln = NULL;
	struct csio_lnode_fcoe *lnf = NULL;
	fc_id_t search_type = NPORT_ID;

	if (buffer_len < sizeof(csio_fcoe_lnode_t))
		return CSIO_NOMEM;

	if (lnf_info->nport_id) {
		search_type = NPORT_ID;
	} else if (lnf_info->vnp_flowid) {
		search_type = FW_HANDLE;
	} else if (csio_wwn_to_u64(lnf_info->ln_sparm.wwpn) != 0) {
		search_type = WWPN;
	} else if (csio_wwn_to_u64(lnf_info->ln_sparm.wwnn) != 0) {
		search_type = WWNN;
	} else {
		CSIO_DB_ASSERT(CSIO_FALSE);
	}

	csio_spin_lock_irq(hw, &hw->lock);
	
	switch (search_type) {
#if 0		
		case NPORT_ID:
			break;
#endif
		case FW_HANDLE:
			lnf = csio_lnf_lookup_by_vnpi(hw, lnf_info->vnp_flowid);
			break;

		case WWPN:
			lnf = csio_lnf_lookup_by_wwpn_ex(hw,
					lnf_info->ln_sparm.wwpn,
					(csio_sm_state_t)csio_lnfs_ready);
			break;
#if 0
		case WWNN:
			break;
#endif
		default:
			CSIO_DB_ASSERT(CSIO_FALSE);
			break;
	}

	if (lnf == NULL) {
		csio_spin_unlock_irq(hw, &hw->lock);
		return CSIO_INVAL;
	}

	ln = lnf->ln;

	/* Copy the contents! */
	csio_copy_fcoe_lnode_info(hw, lnf_info, lnf);

	csio_spin_unlock_irq(hw, &hw->lock);

	return CSIO_SUCCESS;
} /* csio_fcoe_get_lnode_info_by_fcid */


/**
 * csio_fcoe_get_lnode_info - Get fcoe lnode.
 * @hw - HW module
 * @buffer - Buffer where fcoe lnode info to be copied.
 * @len - buffer length
 */
csio_retval_t
csio_fcoe_get_lnode_info(struct csio_hw *hw, void *buffer, uint32_t buffer_len)
{
	csio_fcoe_lnode_t *lnf_info = buffer;
	struct csio_lnode *ln = NULL;
	struct csio_lnode_fcoe *lnf = NULL;

	if (buffer_len < sizeof(csio_fcoe_lnode_t))
		return CSIO_NOMEM;

	csio_spin_lock_irq(hw, &hw->lock);

	ln = csio_fcoe_get_next_lnode_by_handle(hw, lnf_info->opq_handle);
	
	if (ln == NULL) {
		csio_spin_unlock_irq(hw, &hw->lock);
		lnf_info->opq_handle = 0;
		return 0;
	}

	lnf = csio_lnode_to_fcoe(ln);
	csio_copy_fcoe_lnode_info(hw, lnf_info, lnf);

	csio_spin_unlock_irq(hw, &hw->lock);

	return CSIO_SUCCESS;
} /* csio_get_lnode_info */

static csio_retval_t
csio_fcoe_get_port_info(struct csio_hw *hw, void *buffer, uint32_t buffer_len)
{
	csio_port_info_t *port_info = buffer;
	if (buffer_len < sizeof(csio_port_info_t))
		return CSIO_NOMEM;

	csio_spin_lock_irq(hw, &hw->lock);

	csio_get_phy_port_stats(hw, port_info->portid, &port_info->port_stats) ;

	csio_spin_unlock_irq(hw, &hw->lock);

	return CSIO_SUCCESS;
}

/*
 * csio_fcoe_get_fcf_info - Get fcf info.
 * @hw - HW module
 * @buffer - Buffer where fcf info to be copied.
 * @len - buffer length
 */
csio_retval_t
csio_fcoe_get_fcf_info(struct csio_hw *hw, void *buffer, uint32_t buffer_len)
{
	csio_fcf_info_t *fcf_info = buffer;
	struct csio_fcf_info *fcf = NULL;
	enum csio_oss_error rv;
	struct csio_lnode_fcoe *lnf;

	if (buffer_len < sizeof(csio_fcf_info_t))
		return CSIO_NOMEM;

	if (hw == NULL) {
		csio_printk("HW is NULL\n");
		return CSIO_INVAL;
	}

	if (fcf_info == NULL)
		return CSIO_INVAL;

	csio_spin_lock_irq(hw, &hw->lock);
	fcf = csio_fcoe_get_next_fcf(hw, fcf_info->fcfi);
	
	if (fcf == NULL) {
		csio_spin_unlock_irq(hw, &hw->lock);
		fcf_info->fcfi = CSIO_INVALID_IDX;
		return 0;
	}

	lnf = csio_lnf_lookup_by_fcfi(hw, fcf->fcfi);
	csio_spin_unlock_irq(hw, &hw->lock);

	if (lnf == NULL)
		return CSIO_INVAL;

	
	csio_spin_lock_irq(hw, &hw->lock);
	rv = csio_lnf_read_fcf_entry(lnf);
	if (rv != CSIO_SUCCESS) {
		csio_spin_unlock_irq(hw, &hw->lock);
		csio_printk("CSIO : Failed to read FCF Params\n");
		return rv;
	}
	csio_spin_unlock_irq(hw, &hw->lock);

	csio_spin_lock_irq(hw, &hw->lock);
	csio_get_fcf_stats(hw, fcf, fcf_info);
	
	fcf_info->priority 	= fcf->priority;
	fcf_info->vf_id 	= fcf->vf_id;
	fcf_info->vlan_id 	= fcf->vlan_id;
	fcf_info->max_fcoe_size = fcf->max_fcoe_size;
	fcf_info->fka_adv 	= fcf->fka_adv;
	fcf_info->fpma 		= fcf->fpma;
	fcf_info->spma 		= fcf->spma;
	fcf_info->login 	= fcf->login;
	fcf_info->portid 	= fcf->portid;
	fcf_info->fcfi 		= fcf->fcfi;

	csio_memcpy(&fcf_info->spma_mac, &fcf->spma_mac, 6);
	csio_memcpy(&fcf_info->mac, &fcf->mac, 6);
	csio_memcpy(&fcf_info->fc_map, &fcf->fc_map, 3);
	csio_memcpy(&fcf_info->name_id, &fcf->name_id, 8);
	csio_memcpy(&fcf_info->fabric, &fcf->fabric, 8);
	csio_spin_unlock_irq(hw, &hw->lock);

	return CSIO_SUCCESS;
} /* csio_get_fcf_info */

/**
 * csio_lnf_evt_name - Returns event name for given event.
 * @evt - lnf event.
 *
 */
const char *csio_lnf_evt_name(csio_lnf_ev_t evt)
{
	const char *evt_name;
	evt_name = lnfevt_names[evt];
	return evt_name;
}

/**
 * csio_fcoe_get_stats - Get FCoE HW stats.
 * @hw - HW module
 * @buffer - Buffer where FCoE HW stats to be copied.
 * @len - buffer length
 */
static csio_retval_t
csio_fcoe_get_stats(struct csio_hw *hw, void *buffer, uint32_t buffer_len)
{
	csio_tp_fcoe_stats_t *stats_channel = buffer;

	if (buffer_len < (sizeof(csio_tp_fcoe_stats_t) * 4))
		return CSIO_NOMEM;

	csio_hw_get_fcoe_stats(hw, 0,
			(struct tp_fcoe_stats *)&stats_channel[0]);
	csio_hw_get_fcoe_stats(hw, 1,
			(struct tp_fcoe_stats *)&stats_channel[1]);
	csio_hw_get_fcoe_stats(hw, 2,
			(struct tp_fcoe_stats *)&stats_channel[2]);
	csio_hw_get_fcoe_stats(hw, 3,
			(struct tp_fcoe_stats *)&stats_channel[3]);

	return CSIO_SUCCESS;
}/* csio_get_fcoe_stats */


/**
 *	csio_read_fcoe_boot_hdr - reads the FCoE boot header information.
 *	@hw: the HW module
 *	@boot_hdr_buffer: buffer to store the FCoE boot header
 *	@buf_size: buffer size.
 *
 *	Reads the FCoE boot header information from the adapter FLASH memory.	
 */
void
csio_read_fcoe_boot_hdr(struct csio_hw *hw, void *boot_hdr_buffer,
				size_t buf_size)
{
	uint32_t buffer[64], addr = FLASH_FCOE_CRASH_START;

	CSIO_DB_ASSERT(buf_size >= sizeof(fcoe_boot_info_hdr_t));
	CSIO_DB_ASSERT(sizeof(buffer) >= buf_size);

	csio_memset(buffer, 0, sizeof(buffer));
	csio_memset(boot_hdr_buffer, 0, buf_size);

	csio_hw_read_flash(hw, addr, CSIO_ARRAY_SIZE(buffer), buffer, 0);

	csio_memcpy(boot_hdr_buffer, (uint8_t *)buffer,
				CSIO_MIN(buf_size, sizeof(buffer)));
	
	return;
} /* csio_read_fcoe_boot_hdr */

/**
 *	csio_read_fcoe_bootdev_info - reads the FCoE boot targets/device
 *				      information.
 *	@hw: the HW module
 *	@boot_hdr_buffer: buffer to store the FCoE boot targets/device
 *	@buf_size: buffer size.
 *
 *	Reads the FCoE boot target/device information from the adapter
 *	FLASH memory.	
 */
void
csio_read_fcoe_bootdev_info(struct csio_hw *hw, void *boot_dev_buffer,
				size_t buf_size)
{
	uint32_t buffer[64];
	uint32_t addr = FLASH_FCOE_CRASH_START +
				CSIO_OFFSETOF(CBFEStruct, BootDevice);

	/*CSIO_DB_ASSERT(buf_size >= sizeof(fcoe_boot_info_hdr_t));*/
	CSIO_DB_ASSERT(sizeof(buffer) >= buf_size);

	csio_memset(buffer, 0, sizeof(buffer));
	csio_memset(boot_dev_buffer, 0, buf_size);

	csio_hw_read_flash(hw, addr, CSIO_ARRAY_SIZE(buffer), buffer, 0);
	
	csio_memcpy(boot_dev_buffer, (uint8_t *)buffer,
			MAX_OS_FCOE_DEVICES * sizeof(fcoe_boot_dev_info_t));

	return;
} /* csio_read_fcoe_bootdev_info */

/**
 *	csio_erase_fcoe_boot_info - erases the FCoE boot information.
 *	@hw: the HW module
 *
 *	Erases the complete FCoE boot information from the adapter
 *	FLASH memory.	
 */
csio_retval_t
csio_erase_fcoe_boot_info(struct csio_hw *hw)
{
	uint32_t start_sec = FLASH_FCOE_CRASH_START_SEC;
	uint32_t end_sec = FLASH_FCOE_CRASH_START_SEC
				+ FLASH_FCOE_CRASH_NSECS - 1;

	return csio_hw_flash_erase_sectors(hw, start_sec, end_sec);
} /* csio_erase_fcoe_boot_info */
	
/**
 *	csio_write_fcoe_bootdev_info - Writes the FCoE boot target(s)
 *					information.
 *	@hw: the HW module
 *	@boot_dev_info: FCoE Boot target/device information.
 *	@buf_size: Buffer size
 *
 *	Writes the FCoE boot target/device information to the adapter
 *	FLASH memory.	
 */
csio_retval_t
csio_write_fcoe_bootdev_info(struct csio_hw *hw, void *boot_dev_info,
							size_t buf_size)
{
	enum csio_oss_error ret;
	uint8_t boot_buf[256];
	uint32_t addr = FLASH_FCOE_CRASH_START +
				CSIO_OFFSETOF(CBFEStruct, BootDevice);

	csio_memset(boot_buf, 0, 256);
	/*CSIO_DB_ASSERT(buf_size ==
			sizeof(BootDeviceInfo) * MAX_OS_FCOE_DEVICES);*/
	CSIO_DB_ASSERT((buf_size % sizeof(BootDeviceInfo)) == 0);

	csio_memcpy(boot_buf, boot_dev_info, buf_size);

	ret = t4_write_flash(&hw->adap, addr, 256, boot_buf, 0);

	return ret;
} /* csio_write_fcoe_bootdev_info */


/**
 * csio_fcoe_ioctl_handler - Chelsio FCoE IOCTL handler
 * @hw - HW module
 * @opcode - FCoE IOCTL opcode
 *
 */
csio_retval_t
csio_fcoe_ioctl_handler(struct csio_hw *hw, uint32_t opcode, void *buffer,
		uint32_t buffer_len)
{
	enum csio_oss_error rv = CSIO_SUCCESS;

	switch (opcode) {
		case CSIO_FCOE_GET_FCF_INFO:
			rv = csio_fcoe_get_fcf_info(hw, buffer, buffer_len);
			break;
		case CSIO_FCOE_GET_PORT_INFO:
			rv = csio_fcoe_get_port_info(hw, buffer, buffer_len);
			break;

		case CSIO_FCOE_GET_LNODE_INFO:
			rv = csio_fcoe_get_lnode_info(hw, buffer, buffer_len);
			break;

		case CSIO_FCOE_GET_LNODE_INFO_BY_FCID:
			rv = csio_fcoe_get_lnode_info_by_fcid(hw,
							buffer, buffer_len);
			break;

		case CSIO_FCOE_GET_RNODE_INFO:
			rv = csio_fcoe_get_rnode_info(hw, buffer, buffer_len);
			break;

		case CSIO_FCOE_GET_RNODE_INFO_BY_FCID:
			rv = csio_fcoe_get_rnode_info_by_fcid(hw,
							buffer, buffer_len);
			break;
			
		case CSIO_FCOE_GET_STATS:
			rv = csio_fcoe_get_stats(hw, buffer, buffer_len);
			break;

		default:
			rv = CSIO_INVAL;
			break;
	} /* switch */
	return rv;
} /* csio_fcoe_ioctl_handler */


/*****************************************************************************/
/* Entry points */
/*****************************************************************************/

/*
 * csio_lnf_mgmt_wr_handler -Mgmt Work Request handler.
 * @wr - WR.
 * @len - WR len.
 * This handler is invoked when an outstanding mgmt WR is completed.
 * Its invoked in the context of FW event worker thread for every
 * mgmt event received.
 * Return - none.
 */
static void
csio_lnf_mgmt_wr_handler(struct csio_hw *hw, void *wr, uint32_t len)
{
	struct csio_mgmtm *mgmtm = csio_hw_to_mgmtm(hw);
	struct csio_ioreq *io_req = NULL;
	struct fw_fcoe_els_ct_wr *wr_cmd;


	wr_cmd = (struct fw_fcoe_els_ct_wr *) wr;

	if (len < sizeof(struct fw_fcoe_els_ct_wr)) {
		csio_err(mgmtm->hw, "Error:Invalid ELS CT WR length recv."
			"len:%x\n",len);
			mgmtm->stats.n_err++;
		return;
	}

	/* Warn if immediate data is set */
	if (G_FW_FCOE_ELS_CT_WR_IMMDLEN(
				csio_be32_to_cpu(*((__be32 *)wr_cmd)))) {
		csio_dbg(mgmtm->hw, "Warn:Not expected to recv imm data"
				"in WR\n");
	}

	csio_dbg(mgmtm->hw, "Recv FW WR(IQ) op:%x len:%d io_hndl:%llx\n",
		*((uint8_t *) wr_cmd), len, wr_cmd->cookie);

	csio_vdbg(mgmtm->hw, "############### ELS WR dump #################\n");
	CSIO_DUMP_BUF((uint8_t *) wr_cmd, sizeof(struct fw_fcoe_els_ct_wr));


	io_req = (struct csio_ioreq *) ((uintptr_t) wr_cmd->cookie);
	io_req->dma_buf.len = csio_be16_to_cpu(wr_cmd->xfer_cnt);
	io_req->wr_status = csio_wr_status(wr_cmd);

	/* lookup ioreq exists in our active Q */
	csio_spin_lock_irq(hw, &hw->lock);
	if (csio_mgmt_req_lookup(mgmtm, io_req) != CSIO_SUCCESS) {
		csio_err(mgmtm->hw, "Error- Invalid IO handle recv in WR."
			"handle: %p\n", io_req);
		mgmtm->stats.n_err++;
		csio_spin_unlock_irq(hw, &hw->lock);
		return;
	}

	mgmtm = csio_hw_to_mgmtm(hw);

	/* Dequeue from active queue */
	csio_deq_elem(io_req);
	mgmtm->stats.n_active--;
	csio_spin_unlock_irq(hw, &hw->lock);

	if (io_req->io_cbfn) {
		/* io_req will be freed by completion handler */
		io_req->io_cbfn(hw, io_req);
	}
	return;
}

/**
 * csio_fcoe_fwevt_handler - Chelsio FCoE FW event handler
 * @hw - HW module
 * @cpl_op - CPL opcode
 * @cmd - FW cmd/WR.
 *
 * Process recv cmd/WR message from FW.
 * TODO: Need to differentiate FW cmd or FW WR recv.
 */
void
csio_fcoe_fwevt_handler(struct csio_hw *hw, __u8 cpl_op, __be64 *cmd)
{
	struct csio_lnode_fcoe *lnf;
	struct csio_rnode_fcoe *rnf;
	uint8_t portid, opcode = *(uint8_t *)cmd;
	struct fw_fcoe_link_cmd *lcmd;
	struct fw_wr_hdr * wr;
	struct fw_rdev_wr *rdev_wr;
	enum fw_fcoe_link_status lstatus;
	uint32_t fcfi, rdev_flowid, vnpi;
	csio_lnf_ev_t evt;

	if (cpl_op == CPL_FW6_MSG && opcode == FW_FCOE_LINK_CMD) {

		lcmd = (struct fw_fcoe_link_cmd *)cmd;
		lstatus = lcmd->lstatus;
		portid = G_FW_FCOE_LINK_CMD_PORTID(
					csio_ntohl(lcmd->op_to_portid));
		fcfi = G_FW_FCOE_LINK_CMD_FCFI(
					csio_ntohl(lcmd->sub_opcode_fcfi));
		vnpi = G_FW_FCOE_LINK_CMD_VNPI(
					csio_ntohl(lcmd->vnpi_pkd));	

		if (lstatus == FCOE_LINKUP) {

			/* HW lock here */
			csio_spin_lock_irq(hw, &hw->lock);
			csio_handle_link_up(hw, portid, fcfi, vnpi);
			csio_spin_unlock_irq(hw, &hw->lock);
			/* HW un lock here */

		} else if (lstatus == FCOE_LINKDOWN) {

			/* HW lock here */
			csio_spin_lock_irq(hw, &hw->lock);
			csio_handle_link_down(hw, portid, fcfi, vnpi);
			csio_spin_unlock_irq(hw, &hw->lock);
			/* HW un lock here */
		} else {
			csio_warn(hw, "Unexpected FCOE LINK status:0x%x recv\n",
					lcmd->lstatus);
			CSIO_INC_STATS(hw, n_cpl_unexp);
		}
	} else if (cpl_op == CPL_FW6_PLD) {
		wr = (struct fw_wr_hdr *) (cmd + 4);
		if (G_FW_WR_OP(csio_be32_to_cpu(wr->hi))
			== FW_RDEV_WR) {

			rdev_wr = (struct fw_rdev_wr *) (cmd + 4);
			CSIO_TRACE(hw, CSIO_HW_MOD, CSIO_DBG_LEV,
				csio_be64_to_cpu(cmd[4]),
			   	csio_be64_to_cpu(cmd[6]),
			   	csio_be64_to_cpu(cmd[7]),
				csio_be64_to_cpu(cmd[8]));

			rdev_flowid = G_FW_RDEV_WR_FLOWID(
					csio_ntohl(rdev_wr->alloc_to_len16));
			vnpi = G_FW_RDEV_WR_ASSOC_FLOWID(
				    csio_ntohl(rdev_wr->flags_to_assoc_flowid));

			csio_dbg(hw, "FW_RDEV_WR: flowid:x%x ev_cause:x%x "
				"vnpi:0x%x\n", rdev_flowid,
				rdev_wr->event_cause, vnpi);
			
			if (rdev_wr->protocol != PROT_FCOE) {
				csio_err(hw, "FW_RDEV_WR: invalid proto:x%x "
					"recv with flowid:x%x\n",
					rdev_wr->protocol,
					rdev_flowid);
				CSIO_INC_STATS(hw, n_evt_drop);
				return;
			}

			/* HW lock here */
			csio_spin_lock_irq(hw, &hw->lock);
			lnf = csio_lnf_lookup_by_vnpi(hw, vnpi);
			if (!lnf) {
				csio_err(hw, "FW_DEV_WR: invalid vnpi:x%x recv "
					"with flowid:x%x\n", vnpi, rdev_flowid);
				CSIO_INC_STATS(hw, n_evt_drop);
				csio_spin_unlock_irq(hw, &hw->lock);
				return;
			}

			rnf = csio_rnf_confirm_rnode(lnf, rdev_flowid,
					&rdev_wr->u.fcoe_rdev);
			if (!rnf) {
				csio_ln_dbg(lnf->ln,
			     	    	"Failed to confirm rnode "
					"for flowid:x%x\n", rdev_flowid);
				CSIO_INC_STATS(hw, n_evt_drop);
				csio_spin_unlock_irq(hw, &hw->lock);
				return;
			}

			/* save previous event for debugging */
			lnf->prev_evt = lnf->cur_evt;
			lnf->cur_evt = rdev_wr->event_cause;	
			CSIO_INC_STATS(lnf, n_evt_fw[rdev_wr->event_cause]);

			/* Translate all the fabric events to lnode SM events */
			evt = CSIO_FWE_TO_LNFE(rdev_wr->event_cause);
			if (evt) {
				csio_ln_dbg(lnf->ln,
					"Posting event to lnode event:%d "
					"cause:%d flowid:x%x\n", evt,
					rdev_wr->event_cause, rdev_flowid);
				csio_post_event(&lnf->sm, evt);
			}

			/* Handover event to rnf SM here. */
			csio_rnf_fwevt_handler(rnf, rdev_wr->event_cause);

			csio_spin_unlock_irq(hw, &hw->lock);
		}
		else {
			csio_warn(hw, "unexpected WR op(0x%x) recv\n",
			     	G_FW_WR_OP(csio_be32_to_cpu((wr->hi))));
			CSIO_INC_STATS(hw, n_cpl_unexp);
		}
	} else if (cpl_op == CPL_FW6_MSG) {
		wr = (struct fw_wr_hdr *) (cmd);
		if (G_FW_WR_OP(csio_be32_to_cpu(wr->hi))
			== FW_FCOE_ELS_CT_WR) {
			csio_lnf_mgmt_wr_handler(hw, wr,
					sizeof(struct fw_fcoe_els_ct_wr));
		}		
		else {
			csio_warn(hw, "unexpected WR op(0x%x) recv\n",
			     	G_FW_WR_OP(csio_be32_to_cpu((wr->hi))));
			CSIO_INC_STATS(hw, n_cpl_unexp);
		}
	} else {
		csio_warn(hw, "unexpected CPL op(0x%x) recv\n", opcode);
		CSIO_INC_STATS(hw, n_cpl_unexp);
	}

	return;
}

/**
 * csio_lnf_start - Brings up lnode.
 * @lnf: FCoE lnode
 *
 * This routine brings fcoe linkup on the port associated with given
 * lnode. FCOE LINK UP cmd is issued which kickstart firmware FIP discovery
 * on that port.
 * Host receives FCOE link status LINKUP or LINKDOWN from fw event queue
 * for each virtual link between an Enode and the FCF.
 * Issued with hw lock held.
 */
enum csio_oss_error
csio_lnf_start(struct csio_lnode_fcoe *lnf)
{
	enum csio_oss_error rv = CSIO_SUCCESS;
	if (csio_is_phys_lnf(lnf) && !(lnf->flags & CSIO_LNFFLAG_LINK_ENABLE)) {
		rv = csio_fcoe_enable_link(lnf, 1);
		lnf->flags |= CSIO_LNFFLAG_LINK_ENABLE;
	}

	return rv;
}

#ifdef __CSIO_TARGET__

/**
 * csio_lnf_stop - Stop lnode.
 * @lnf: FCoE lnode
 *
 * This routine is invoked by HW module to stop lnode and its associated NPIV
 * lnodes.  Issued with hw lock held. Should never be called as part of
 * FW event handler worker (see comment in function).
 *
 * In target mode, all new I/Os emerge from the initiator end. To quiesce
 * these I/Os, the link has to be first brought down. Subsequently, the
 * state machines need to be notified.
 */
void
csio_lnf_stop(struct csio_lnode_fcoe *lnf)
{
	struct csio_hw *hw = csio_lnode_to_hw(lnf->ln);

	if (csio_is_phys_lnf(lnf) && (lnf->flags & CSIO_LNFFLAG_LINK_ENABLE)) {
		csio_fcoe_enable_link(lnf, 0);
		lnf->flags &= ~CSIO_LNFFLAG_LINK_ENABLE;
	}

#if 0
	/*
	 * Wait until all FW events are flushed before we post the SM event.
	 * Assumption here is this function will never get called from the
	 * rdev handler thread, else we will end up with a deadlock.
	 */
	csio_evtq_flush(hw);
#endif

	csio_post_event_lnfs(lnf, CSIO_LNFE_DOWN_LINK);
	if (csio_target_mode(hw))
		csio_tgt_unregister(lnf->ln);
	csio_ln_dbg(lnf->ln, "stoping lnf :%p\n", lnf);
}

#else

/**
 * csio_lnf_stop - Stop lnode.
 * @lnf: FCoE lnode
 *
 * This routine is invoked by HW module to stop lnode and its associated NPIV
 * lnodes.
 * Issued with hw lock held.
 */
void
csio_lnf_stop(struct csio_lnode_fcoe *lnf)
{
	csio_post_event_lnfs(lnf, CSIO_LNFE_DOWN_LINK);
	if (csio_is_phys_lnf(lnf) && (lnf->flags & CSIO_LNFFLAG_LINK_ENABLE)) {
		csio_fcoe_enable_link(lnf, 0);
		lnf->flags &= ~CSIO_LNFFLAG_LINK_ENABLE;
	}
	csio_ln_dbg(lnf->ln, "stoping lnf :%p\n", lnf);
	return;
}

#endif /* __CSIO_TARGET__ */

/**
 * csio_lnf_close - close lnode.
 * @lnf: FCoE lnode
 *
 * This routine is invoked by HW module to close lnode and its associated NPIV
 * lnodes. Lnode and its associated NPIV lnodes are set to [UNINIT] state.
 */
void
csio_lnf_close(struct csio_lnode_fcoe *lnf)
{
#ifdef __CSIO_TARGET__
	struct csio_hw *hw = csio_lnode_to_hw(lnf->ln);
#endif /* __CSIO_TARGET__ */

	csio_post_event_lnfs(lnf, CSIO_LNFE_CLOSE);
	if (csio_is_phys_lnf(lnf)) {
		lnf->vnp_flowid = CSIO_INVALID_IDX;
	}
#ifdef __CSIO_TARGET__
	if (csio_target_mode(hw))
		csio_tgt_unregister(lnf->ln);
#endif /* __CSIO_TARGET__ */

	csio_ln_dbg(lnf->ln, "closed lnf :%p\n", lnf);
	return;
}

/*
 * csio_lnf_prep_ecwr - Prepare ELS/CT WR.
 * @io_req - IO request.
 * @wr_len - WR len
 * @immd_len - WR immediate data
 * @sub_op - Sub opcode
 * @sid - source portid.
 * @did - destination portid
 * @flow_id - flowid
 * @fw_wr - ELS/CT WR to be prepared.
 * Returns: CSIO_SUCCESS - on success
 */
static csio_retval_t
csio_lnf_prep_ecwr(struct csio_ioreq *io_req, uint32_t wr_len,
		      uint32_t immd_len, uint8_t sub_op, uint32_t sid,
		      uint32_t did, uint32_t flow_id, uint8_t *fw_wr)
{
	struct fw_fcoe_els_ct_wr *wr;
	__be32 port_id;

	wr  = (struct fw_fcoe_els_ct_wr *) fw_wr;
	wr->op_immdlen = csio_cpu_to_be32(V_FW_WR_OP(FW_FCOE_ELS_CT_WR) |
					  V_FW_FCOE_ELS_CT_WR_IMMDLEN(immd_len)
					  );

	wr_len =  CSIO_ROUNDUP(wr_len, 16);
	wr->flowid_len16 = csio_cpu_to_be32(V_FW_WR_FLOWID(flow_id) |
				   	  V_FW_WR_LEN16(wr_len));
	wr->els_ct_type = sub_op;
	wr->ctl_pri = 0;
	wr->cp_en_class = 0;
	wr->cookie = io_req->fw_handle;
	wr->iqid = csio_cpu_to_be16(csio_q_physiqid(
			io_req->lnode->hwp, io_req->iq_idx));
	wr->fl_to_sp =  V_FW_FCOE_ELS_CT_WR_SP(1);
	wr->tmo_val = (uint8_t) io_req->tmo;
	port_id = csio_htonl(sid);
	csio_memcpy(wr->l_id, PORT_ID_PTR(port_id), 3);
	port_id = csio_htonl(did);
	csio_memcpy(wr->r_id, PORT_ID_PTR(port_id), 3);

	/* Prepare RSP SGL */
	wr->rsp_dmalen = csio_cpu_to_be32(io_req->dma_buf.len);
	wr->rsp_dmaaddr = csio_cpu_to_be64(
				csio_phys_addr(io_req->dma_buf.paddr));
	return CSIO_SUCCESS;
}

/*
 * csio_lnf_mgmt_submit_req - Post elsct work request.
 * @mgmtm - mgmtm
 * @io_req - io request.
 * @sub_op - ELS or CT request type
 * @pld - Dma Payload buffer
 * @pld_len - Payload len
 * Prepares ELSCT Work request and sents it to FW.
 * Returns: CSIO_SUCCESS - on success
 */
static csio_retval_t
csio_lnf_mgmt_submit_wr(struct csio_mgmtm *mgmtm, struct csio_ioreq *io_req,
		uint8_t sub_op, struct csio_dma_buf *pld,
		uint32_t pld_len)
{
	struct csio_wr_pair wrp;
	struct csio_lnode_fcoe *lnf = csio_lnode_to_fcoe(io_req->lnode);
	struct csio_rnode_fcoe *rnf = csio_rnode_to_fcoe(io_req->rnode);
	struct	csio_hw	*hw = mgmtm->hw;	
	struct ulptx_sgl dsgl;
	uint32_t wr_size = 0;
	uint8_t im_len = 0;
	uint32_t wr_off = 0;

	enum csio_oss_error ret = CSIO_SUCCESS;

	/* Calculate WR Size for this ELS REQ */	
	wr_size = sizeof(struct fw_fcoe_els_ct_wr);

	/* Send as immediate data if pld < 256 */
	if (pld_len < 256) {
		wr_size += CSIO_ALIGN(pld_len, 8);
		im_len = (uint8_t)pld_len;
	}
	else {
		wr_size += sizeof(struct ulptx_sgl);
	}	

	/* Roundup WR size in units of 16 bytes */
	wr_size = CSIO_ALIGN(wr_size, 16);

	/* Get WR to send ELS REQ */
	ret = csio_wr_get(hw, mgmtm->eq_idx, wr_size, &wrp);
	if (ret != CSIO_SUCCESS) {
		csio_err(hw, "Failed to get WR for ec_req %p ret:%d\n",
			io_req, ret);
		return ret;
	}

	/* TODO: Set ELS Timeout and Arm timer */
	/* ec_req->io_req.io_cbfn = csio_elsct_elsreq_cmpl; */
	
	/* Prepare Generic WR used by all ELS/CT cmd */
	csio_lnf_prep_ecwr(io_req, wr_size, im_len, sub_op,
				lnf->nport_id, rnf->nport_id,
				csio_rnf_flowid(rnf),
			     	&io_req->fw_wr[0]);

	/* Copy ELS/CT WR CMD */
	csio_wr_copy_to_wrp(&io_req->fw_wr[0], &wrp, wr_off,
			sizeof(struct fw_fcoe_els_ct_wr));
	wr_off += sizeof(struct fw_fcoe_els_ct_wr);

	/* Copy payload to Immediate section of WR */
	if (im_len)
		csio_wr_copy_to_wrp(pld->vaddr, &wrp, wr_off, im_len);
	else {
		/* Program DSGL to dma payload */
		dsgl.cmd_nsge = csio_htonl(V_ULPTX_CMD(ULP_TX_SC_DSGL) |
				F_ULP_TX_SC_MORE |
				V_ULPTX_NSGE(1));
		dsgl.len0 = csio_cpu_to_be32(pld_len);
		dsgl.addr0 = csio_cpu_to_be64(
					 csio_phys_addr(pld->paddr));
		csio_wr_copy_to_wrp(&dsgl, &wrp, CSIO_ALIGN(wr_off, 8),
				   sizeof(struct ulptx_sgl));
	}

	CSIO_DUMP_WR(mgmtm->hw, wrp);
	CSIO_TRACE(mgmtm->hw, CSIO_HW_MOD, CSIO_DBG_LEV,
		   io_req,
		   ((uint64_t) csio_rnf_flowid(rnf) |
		   (uint64_t) lnf->nport_id << 24 | rnf->nport_id),	
		   *((uint64_t *) pld->vaddr),
		   0);

	/* Issue work request to xmit ELS/CT req to FW */
	csio_wr_issue(mgmtm->hw, mgmtm->eq_idx, CSIO_FALSE);
	return ret;	
}

/*
 * csio_mgmt_cancel_req - Cancel the given fcoe mgmt request.
 * @io_req  - io request to be cancelled.
 * @abort_flag - If set, aborts the given mgmt request.
 * This function cancels the given mgmt request and sends
 * abort wr if abort_flag is set.
 * This called with hw lock held
 * Returns: CSIO_SUCCESS - on success
 */
csio_retval_t
csio_lnf_mgmt_cancel_req(struct csio_ioreq *io_req, uint8_t abort_flag)
{
	struct csio_mgmtm *mgmtm = csio_hw_to_mgmtm(
			csio_lnode_to_hw(io_req->lnode));

	/* Return, If the request is already in process of aborting/closing */
	if (!csio_mgmt_req_lookup(mgmtm, io_req))
		return CSIO_SUCCESS;

	/* Dequeue from active queue */
	csio_deq_elem(io_req);
	mgmtm->stats.n_active--;

	/* If abort_flag is set, send Abort wr to fw. */
	if (abort_flag) {
	/* REVISIT: Sending Abort not required since FW times ELS/CT */	
/*		
		csio_mgmt_abort_wr(mgmtm, io_req);
		csio_enq_at_tail(&mgmtm->abort_q, &io_req->sm.sm_list);
		mgmtm->stats.n_abort_req++;
*/		
	}	

	return CSIO_SUCCESS;
}

/*
 * csio_lnf_mgmt_submit_req - Submit FCOE Mgmt request.
 * @io_req - IO Request
 * @io_cbfn - Completion handler.
 * @req_type - ELS or CT request type
 * @pld - Dma Payload buffer
 * @pld_len - Payload len
 *
 *
 * This API used submit managment ELS/CT request.
 * This called with hw lock held
 * Returns: CSIO_SUCCESS - on success
 *	    CSIO_NOMEM	- on error.
 */
csio_retval_t
csio_lnf_mgmt_submit_req(struct csio_ioreq *io_req,
		void (*io_cbfn) (struct csio_hw *, struct csio_ioreq *),
		enum fcoe_cmn_type req_type, struct csio_dma_buf *pld,
		uint32_t pld_len)
{
	struct csio_hw *hw = csio_lnode_to_hw(io_req->lnode);
	struct csio_mgmtm *mgmtm = csio_hw_to_mgmtm(hw);
	enum csio_oss_error rv;

	io_req->io_cbfn = io_cbfn;	/* Upper layer callback handler */
	io_req->fw_handle = (uintptr_t) (io_req);
	/* TODO: ELS Timeout: Filled by caller. */
	io_req->retry_cnt = 0;
	io_req->max_retries = 0;  /* TODO: MAX_ELS_RETRY; */
	io_req->eq_idx = mgmtm->eq_idx;
	io_req->iq_idx = mgmtm->iq_idx;	

	rv = csio_lnf_mgmt_submit_wr(mgmtm, io_req, req_type, pld, pld_len);
	if (rv == CSIO_SUCCESS) {
		csio_enq_at_tail(&mgmtm->active_q, &io_req->sm.sm_list);
		mgmtm->stats.n_active++;
	}
	return rv;
}

/**
 * csio_lnf_fdmi_init - FDMI Init entry point.
 * @lnf: FCoE lnode
 */
static csio_retval_t
csio_lnf_fdmi_init(struct csio_lnode_fcoe *lnf)
{
	struct csio_hw *hw = csio_lnode_to_hw(lnf->ln);
	struct csio_dma_buf	*dma_buf;

	/* Allocate MGMT request required for FDMI */
	lnf->mgmt_req = csio_alloc(csio_md(hw, CSIO_MGMTREQ_MD),
				sizeof(struct csio_ioreq),
				CSIO_MNOWAIT);
	if (!lnf->mgmt_req) {
		csio_ln_err(lnf->ln, "Failed to alloc ioreq for FDMI\n");
		CSIO_INC_STATS(hw, n_err_nomem);
		return CSIO_NOMEM;
	}

	/* Allocate Dma buffers for FDMI response Payload */
	dma_buf = &lnf->mgmt_req->dma_buf;
	dma_buf->vaddr = csio_dma_alloc(&dma_buf->dmahdl, hw->os_dev,
					2048, 8,
					&dma_buf->paddr, CSIO_MNOWAIT);

	if (!dma_buf->vaddr) {
		csio_err(hw, "Failed to alloc DMA buffer for FDMI!\n");
		csio_free(csio_md(hw, CSIO_MGMTREQ_MD), lnf->mgmt_req);
		lnf->mgmt_req = NULL;
		return CSIO_NOMEM;
	}

	dma_buf->len = 2048;
	lnf->flags |= CSIO_LNFFLAG_FDMI_ENABLE;
	return CSIO_SUCCESS;
}	

/**
 * csio_lnf_fdmi_exit - FDMI exit entry point.
 * @lnf: FCoE lnode
 */
static csio_retval_t
csio_lnf_fdmi_exit(struct csio_lnode_fcoe *lnf)
{
	struct csio_hw *hw = csio_lnode_to_hw(lnf->ln);
	struct csio_dma_buf	*dma_buf;

	if (!lnf->mgmt_req)
		return CSIO_SUCCESS;

	dma_buf = &lnf->mgmt_req->dma_buf;
	if (dma_buf->vaddr)	
		csio_dma_free(&dma_buf->dmahdl, dma_buf->vaddr);
	
	csio_free(csio_md(hw, CSIO_MGMTREQ_MD), lnf->mgmt_req);
	return CSIO_SUCCESS;
}	
	
/**
 * csio_lnf_init - Init entry point.
 * @lnf: FCoE lnode
 */
csio_retval_t
csio_lnf_init(struct csio_lnode_fcoe *lnf)
{
	int rv = CSIO_INVAL;
	struct csio_lnode_fcoe *rlnf, *plnf;
	struct csio_hw *hw = csio_lnode_to_hw(lnf->ln);

	csio_init_state(&lnf->sm, csio_lnfs_uninit, csio_hw_to_tbuf(hw));
	lnf->vnp_flowid = CSIO_INVALID_IDX;
	lnf->fcf_flowid = CSIO_INVALID_IDX;

	if (csio_is_root_lnf(lnf)) {

		/* This is the lnode used during initialization */

		lnf->fcfinfo = csio_alloc(csio_md(hw, CSIO_FCOE_FCF_MD),
					 sizeof(struct csio_fcf_info),
					 CSIO_MNOWAIT);
		if (!lnf->fcfinfo) {
			csio_ln_err(lnf->ln, "Failed to alloc FCF record\n");
			CSIO_INC_STATS(hw, n_err_nomem);
			goto err;
		}

		csio_head_init(&lnf->fcf_lsthead);	
		csio_kref_init(&lnf->fcfinfo->kref, (void *)lnf,
			       csio_free_fcfinfo);

		if (csio_fdmi_enable && csio_lnf_fdmi_init(lnf))
			goto err;
		
	} else { /* Either a non-root physical or a virtual lnode */

		/*
		 * THe rest is common for non-root physical and NPIV lnodes.
		 * Just get references to all other modules
		 */
		rlnf = csio_root_lnf(lnf);

		if (csio_is_npiv_lnf(lnf)) {
			/* NPIV */
			plnf = csio_parent_lnf(lnf);
			csio_kref_get(&plnf->fcfinfo->kref);
			lnf->fcfinfo = plnf->fcfinfo;
		} else {
			/* Another non-root physical lnode (FCF) */
			lnf->fcfinfo = csio_alloc(csio_md(hw, CSIO_FCOE_FCF_MD),
						  sizeof(struct csio_fcf_info),
						  CSIO_MNOWAIT);
			if (!lnf->fcfinfo) {
				csio_ln_err(lnf->ln,
					"Failed to alloc FCF info\n");
				CSIO_INC_STATS(hw, n_err_nomem);
				goto err;
			}
			csio_kref_init(&lnf->fcfinfo->kref, (void *)lnf,
				       csio_free_fcfinfo);

			if (csio_fdmi_enable && csio_lnf_fdmi_init(lnf))
				goto err;
		}

	} /* if (!csio_is_root_lnf(lnf)) */

	return CSIO_SUCCESS;
err:
	return rv;
}

/**
 * csio_lnf_exit - Exit entry point.
 * @lnf: FCoE lnode
 *
 */
void
csio_lnf_exit(struct csio_lnode_fcoe *lnf)
{
	struct csio_lnode_fcoe *plnf;

	csio_cleanup_rnfs(lnf);
	if (csio_is_npiv_lnf(lnf)) {
		plnf = csio_parent_lnf(lnf);
		csio_kref_put(&plnf->fcfinfo->kref);
	}	
	else {
		csio_kref_put(&lnf->fcfinfo->kref);
		if (csio_fdmi_enable)
			csio_lnf_fdmi_exit(lnf);
	}	
	lnf->fcfinfo = NULL;

	return;
}
