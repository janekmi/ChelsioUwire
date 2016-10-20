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
 * 	This chfcoe_lnode.c file contains fcoe local node creation, deletion,
 * 	state machine processing and other utility functions.
 */

#include "chfcoe_lnode.h"
#include "chfcoe_rnode.h"
#include "chfcoe_proto.h"
#include "chfcoe_io.h"
#include "chfcoe_xchg.h"

extern int chfcoe_fip_xmit(struct chfcoe_lnode *lnode,
                struct chfcoe_rnode *rnode, chfcoe_fc_buffer_t *fr);

extern unsigned int chfcoe_node_num; 

/* FC4 handlers */
fc4_handler_t fc4_handlers[PROTO_FC_TYPE_FCP + 0x01];

/**
 * chfcoe_register_fc4() - Registers FC upper layer protocol handler.
 * @fc4_type - FC4 type
 * @fc4_hndl - FC4 handler
 */
void chfcoe_register_fc4(enum proto_fc_fh_type fc4_type, fc4_handler_t fc4_hndl)
{
	if (fc4_type <= PROTO_FC_TYPE_FCP)
		fc4_handlers[fc4_type] = fc4_hndl;
}	

/**
 * chfcoe_fc_get_sp() - Initialize default service parameter.
 * @sp - FC Service parameter
 */
void chfcoe_fc_get_sp(struct chfcoe_lnode *lnode, 
		struct csio_service_parms *sp)
{
	struct csio_cmn_sp *csp;
	struct csio_class_sp *cp;

	chfcoe_memset(sp, 0, sizeof(struct csio_service_parms));
	csp = &sp->csp;	
	csp->hi_ver = PROTO_FC_PH_VER3;
	csp->lo_ver = PROTO_FC_PH_VER3;
	csp->bb_credit  = chfcoe_htons(10);
	csp->word1_flags = chfcoe_htons(PROTO_FC_SP_FT_CIRO);
	csp->sp_tot_seq  = chfcoe_htons(255);    /* seq. we accept */
	csp->sp_rel_off  = chfcoe_htons(0x1f);
	csp->e_d_tov  = chfcoe_htonl(2000);
	csp->rcv_sz = chfcoe_htons(lnode->max_pldlen);
	cp = &sp->clsp[2];
	cp->serv_option = chfcoe_htons(PROTO_FC_CPC_VALID | PROTO_FC_CPC_SEQ);
	cp->rcv_data_sz = chfcoe_htons(lnode->max_pldlen);
	cp->concurrent_seq  = chfcoe_htons(255);
	cp->openseq_per_xchg = chfcoe_htons(1);
}

int chfc_set_maxfs(struct chfcoe_lnode *lnode)
{
	int old_mfs;
	int mfs, rc = -CHFCOE_INVAL;

	old_mfs = lnode->max_pldlen;
	mfs = os_netdev_mtu(lnode->pi->os_dev) - 
		sizeof(struct proto_fcoe_hdr) - 
		sizeof(struct proto_fc_fr_hdr) -
		sizeof(struct proto_fcoe_fr_trlr);

	if (mfs >= PROTO_FC_MIN_MAX_PAYLOAD) {
		if (mfs > PROTO_FC_MAX_PAYLOAD)
			mfs = PROTO_FC_MAX_PAYLOAD;
		mfs &= ~(512 - 1);
		lnode->max_pldlen = mfs;
		rc = 0;
		chfcoe_info(lnode, "lnode 0x%x: set mfs to %d, mtu %d\n", 
				lnode->nport_id, lnode->max_pldlen, 
				os_netdev_mtu(lnode->pi->os_dev));
	} else
		chfcoe_err(lnode, "lnode 0x%x: mtu too small %d\n", 
				lnode->nport_id,
				os_netdev_mtu(lnode->pi->os_dev));

	return rc;
}

/**
 * chfcoe_lnode_alloc() - Allocate local node.
 * @pi - port information
 *
 * This routine is called to allocate lnode with unique WWPN and
 * return the same. It also registers with target(SAL) layer. 
 */
struct chfcoe_lnode * 
chfcoe_lnode_alloc(struct chfcoe_port_info *pi)
{
	struct chfcoe_lnode *lnode;
	struct chfcoe_adap_info *adap;
	struct csio_service_parms sp;

	lnode = chfcoe_mem_alloc(chfcoe_lnode_size);
	if (!lnode)
		return NULL;

	lnode->rn_lock = CHFCOE_PTR_OFFSET(lnode, sizeof(struct chfcoe_lnode));
	lnode->ln_mutex = CHFCOE_PTR_OFFSET(lnode, sizeof(struct chfcoe_lnode) + os_rwlock_size);
	lnode->stats.n_tid_alloc = CHFCOE_PTR_OFFSET(lnode, sizeof(struct chfcoe_lnode) + os_rwlock_size +
				   os_mutex_size);
	lnode->stats.n_tid_free = CHFCOE_PTR_OFFSET(lnode, sizeof(struct chfcoe_lnode) + os_rwlock_size +
				   os_mutex_size + os_atomic_size);
	lnode->stats.n_ddp_data = CHFCOE_PTR_OFFSET(lnode, sizeof(struct chfcoe_lnode) + os_rwlock_size +
				   os_mutex_size + (2 * os_atomic_size));
	lnode->stats.n_ddp_qd = CHFCOE_PTR_OFFSET(lnode, sizeof(struct chfcoe_lnode) + os_rwlock_size +
				   os_mutex_size + (3 * os_atomic_size));
	lnode->stats.n_xfer_rdy= CHFCOE_PTR_OFFSET(lnode, sizeof(struct chfcoe_lnode) + os_rwlock_size +
				   os_mutex_size + (4 * os_atomic_size));

	chfcoe_head_init(&lnode->cln_head);
	chfcoe_head_init(&lnode->rn_head);
	chfcoe_head_init(&lnode->rn_head_drain);
	chfcoe_head_init(&lnode->ctbuf_head);
	chfcoe_rwlock_init(lnode->rn_lock);
	chfcoe_mutex_init(lnode->ln_mutex);
	adap = chfcoe_pi_to_adap(pi);
	lnode->adap = adap;
	lnode->pi = pi;
	lnode->port_num = pi->port_num;
	chfcoe_memcpy(lnode->wwnn, pi->wwnn, 8);
	chfcoe_memcpy(lnode->wwpn, pi->wwpn, 8);
	chfcoe_get_wwpn(lnode->wwpn, lnode->wwnn, pi->num_ln);
	chfcoe_info(lnode, "Created lnode:%p portid:x%x name(wwpn):%llx\n", lnode, 
			pi->port_num, chfcoe_wwn_to_u64(lnode->wwpn));

	/* Fill common service parameters */
	if (chfc_set_maxfs(lnode))
		goto err;

	chfcoe_fc_get_sp(lnode, &sp);
	chfcoe_memset(&lnode->sp, 0, sizeof(struct csio_service_parms));
	chfcoe_memcpy(&lnode->sp, &sp, sizeof(struct csio_service_parms));
	
	chfcoe_spin_lock_bh(pi->lock);
	if (!pi->root_ln)
		pi->root_ln = lnode;
	chfcoe_spin_unlock_bh(pi->lock);
	
	/* Register with target layer */
	if (!lnode->tgt_hdl)
		chfcoe_tgt_register(lnode);

	lnode->state = CHFCOE_LN_ST_UNINIT;
	return lnode;
err:
	chfcoe_mem_free(lnode);
	return NULL;
}

/**
 * chfcoe_lnode_init() - Initialize local node.
 * @ln - lnode
 * @ctrl_dev - FCoE control context.
 * @fip_type - FCF/VN2VN
 * @pln - parent lnode valid only for NPIV lnode.
 *
 * This routine is called to link FCoE control context with lnode and
 * initialize FCoE MAC. Control context will have FIP FCF or FIP VN2VN
 * context information.
 */
void
chfcoe_lnode_init(struct chfcoe_lnode *ln, void *ctrl_dev, 
		enum fip_mode_type fip_type, struct chfcoe_lnode *pln)
{
	struct chfcoe_port_info *pi;
	struct chfcoe_fcf *fcf;
	struct chfcoe_vn2vn *vn2vn;

	if (fip_type == CHFCOE_FCF) {
		fcf = (struct chfcoe_fcf *)ctrl_dev;
		pi = chfcoe_fcf_to_pi(fcf);
		chfcoe_memcpy(ln->fcf_mac, fcf->fcf_mac, 6);
		ln->vlan_id = fcf->vlan_id;	
		chfcoe_memcpy(ln->fcoe_mac, pi->phy_mac, 6);
	} else {
		vn2vn = (struct chfcoe_vn2vn *)ctrl_dev;
		pi = vn2vn->pi;
		ln->vlan_id = vn2vn->vlan_id;	
		ln->nport_id = vn2vn->luid;
		chfcoe_memcpy(ln->fcoe_mac, vn2vn->vn_mac, 6);
	}

	ln->fip_ctrl = ctrl_dev;
	ln->fip_type = fip_type;

	/* For NPIV,add lnode to list of children lnodes */
	if (pln) {
		chfcoe_mutex_lock(pi->mtx_lock);
		chfcoe_enq_at_tail(&pln->cln_head, ln);
		pln->num_vports++;
		chfcoe_mutex_unlock(pi->mtx_lock);
		ln->pln = pln;
	} else
		ln->pln = NULL;
} /* chfcoe_lnode_init */

/**
 * chfcoe_lnode_create() - Create local node.
 * @ctrl_dev - FCoE control context.
 * @fip_type - FCF/VN2VN
 * @pi - port information
 */
struct chfcoe_lnode *
chfcoe_lnode_create(void *ctrl_dev, enum fip_mode_type fip_type, 
		 struct chfcoe_port_info *pi)
{
	struct chfcoe_lnode *pln;

	chfcoe_spin_lock_bh(pi->lock);
	pln = chfcoe_list_empty(&pi->ln_head) ? pi->root_ln : NULL;
	chfcoe_spin_unlock_bh(pi->lock);

	if (!pln) {
		pln = pi->root_ln;
		/* Allocate new lnode if root lnode already attached to 
		 * fip device. 
		 */
		if (pln->fip_ctrl) {
			pln = chfcoe_lnode_alloc(pi);
		}	
		else {
			chfcoe_lnode_init(pln, ctrl_dev, fip_type, NULL);
			return pln;
		}	
	}	

	/* Attach fip ctrl to lnode */
	chfcoe_lnode_init(pln, ctrl_dev, fip_type, NULL);
	chfcoe_spin_lock_bh(pi->lock);
	chfcoe_enq_at_tail(&pi->ln_head, pln);
	pi->num_ln++;
	chfcoe_spin_unlock_bh(pi->lock);

	/* Register with target layer */
	if (!pln->tgt_hdl) {
		if (chfcoe_tgt_register(pln) != 0) {
			chfcoe_lnode_destroy(pln);
			return NULL;
		}	
	}	
	return pln;
}

/**
 * chfcoe_lnode_exit() - de-initialize local node.
 * @ln - lnode
 */
void
chfcoe_lnode_exit(struct chfcoe_lnode *ln)
{
	struct chfcoe_port_info 	*pi = NULL;
	struct chfcoe_list *entry, *next;
	pi = ln->pi;
	/* Remove this lnode from list */
	chfcoe_spin_lock_bh(pi->lock);

	/* If it is children lnode, decrement the
	 * counter in its parent lnode
	 */
	chfcoe_deq_elem(ln);
	pi->num_ln--;
	if (ln->pln)
		ln->pln->num_vports--;

	chfcoe_spin_unlock_bh(pi->lock);
	ln->fip_ctrl = NULL;
	ln->pln = NULL;
	ln->flags = 0;
	/* Free ct buffer list */
	chfcoe_list_for_each_safe(entry, next, &ln->ctbuf_head) {
		chfcoe_deq_elem(entry);
		chfcoe_mem_free(entry);
	}
	return;
} /* chfcoe_lnode_exit */

/**
 * chfcoe_lnode_destroy() - destroys local node.
 * @lnode - lnode
 * Local nodes other than root lnodes will be destroyed.
 * Root lnodes will be destroyed only during unload.
 */
void 
chfcoe_lnode_destroy(struct chfcoe_lnode *lnode)
{
	struct chfcoe_port_info *pi = lnode->pi;
	struct chfcoe_list *entry, *next;

	chfcoe_mutex_lock(lnode->ln_mutex);
	if (lnode->state != CHFCOE_LN_ST_OFFLINE) {
		chfcoe_err(adap, "destroy lnode:0x%x in invalid state:%d\n",
				lnode->nport_id, lnode->state);
	}
	chfcoe_mutex_unlock(lnode->ln_mutex);

	/* Destroy only non-root lnode only */
	if (pi->root_ln != lnode) {
		chfcoe_lnode_exit(lnode);
		if (lnode->tgt_hdl)  
			chfcoe_tgt_unregister(lnode);
		chfcoe_mem_free(lnode);
	}
	else {
		/* Free ct buffer list */
		chfcoe_list_for_each_safe(entry, next, &lnode->ctbuf_head) {
			chfcoe_deq_elem(entry);
			chfcoe_mem_free(entry);
		}
		lnode->fip_ctrl = NULL;
		lnode->pln = NULL;
		lnode->flags = 0;
	}
}

/**
 * chfcoe_get_lnode() - Returns local node.
 * @pi - port information
 * @fcb - FC buffer
 *
 * Called in data path to return the local node matching
 * received frame. 
 */
struct chfcoe_lnode *chfcoe_get_lnode(struct chfcoe_port_info *pi, 
		chfcoe_fc_buffer_t *fcb)
{
        struct chfcoe_list	*ln_list;
	struct chfcoe_lnode *ln;
	uint16_t mpsid = chfcoe_fc_mpsid(fcb);

	/* return lnode if there is exists single lnode on that port */
	if (chfcoe_likely(pi->num_ln == 1)) {
		return pi->root_ln;
	}

	/* return lnode matching MPS id */
	chfcoe_spin_lock(pi->lock);
	chfcoe_list_for_each(ln_list, &pi->ln_head) {
		ln = (struct chfcoe_lnode *) ln_list;
		if (ln->fcoe_mac_idx == mpsid) {
			chfcoe_spin_unlock(pi->lock);
			return ln;
		}
	}
	chfcoe_spin_unlock(pi->lock);
	return NULL;
}

/**
 * chfcoe_lnode_down() - Link down handling on local node.
 * @lnode - local node
 *
 */
void chfc_lnode_down(struct chfcoe_lnode *lnode)
{
	struct chfcoe_list *rnhead = &lnode->rn_head, *entry;
	struct chfcoe_rnode *rnode;
	unsigned int index;

	chfcoe_info(lnode, "lnode %d:0x%x:DOWN\n", 
			lnode->port_num, lnode->nport_id);
	
	for (index = 0; index < chfcoe_node_num; index++)
		chfcoe_flush_workers(index);
	
	chfcoe_write_lock_bh(lnode->rn_lock);
	while (!chfcoe_list_empty(rnhead)) {
		chfcoe_deq_from_tail(rnhead, &entry);
		rnode = (struct chfcoe_rnode *)entry;
		chfcoe_enq_at_tail(&lnode->rn_head_drain, &rnode->rnlist);
		chfcoe_write_unlock_bh(lnode->rn_lock);
		chfcoe_rnode_destroy(rnode);
		chfcoe_write_lock_bh(lnode->rn_lock);
	}
	chfcoe_write_unlock_bh(lnode->rn_lock);

	lnode->state = CHFCOE_LN_ST_OFFLINE;
	lnode->nport_id = 0;
	return;
}

/**
 * chfc_els_resp_send() - Sends ELS response
 * @lnode - local node
 * @rnode - remote node
 * @fr -  FC Frame to transmitted.
 * @fr_rx - Received FC frame.
 */
int chfc_els_resp_send(struct chfcoe_lnode *lnode, struct chfcoe_rnode *rnode,
		chfcoe_fc_buffer_t *fr, chfcoe_fc_buffer_t *fr_rx, bool fip)
{
	chfcoe_xchg_cb_t *xchg = NULL;
	fc_header_t *hdr;
	int err;

	hdr = (fc_header_t *)chfcoe_fc_data_ptr(fr_rx);

	proto_fc_fill_fc_hdr(chfcoe_fc_hdr(fr), PROTO_FC_RCTL_ELS_REP,	
			chfcoe_ntoh24(hdr->s_id),
		       	lnode->nport_id, PROTO_FC_TYPE_ELS,
			PROTO_FC_EX_CTX | PROTO_FC_LAST_SEQ |
			PROTO_FC_END_SEQ, 0);

	if (rnode) {
		xchg = chfcoe_get_xchg(rnode);
		if (!xchg) {
			return CHFCOE_NOMEM;
		}
		chfcoe_xchg_init(xchg, NULL, NULL, rnode, lnode->nport_id,
				chfcoe_ntoh24(hdr->s_id), chfcoe_ntohs(hdr->ox_id), xchg->xid, 1, 0);
	}
	else {
		xchg = chfcoe_mem_alloc(chfcoe_xchg_ioreq_size);
		if (!xchg) {
			return CHFCOE_NOMEM;
		}
		chfcoe_xchg_mem_init(xchg, 0xffff);
		xchg->sid = lnode->nport_id;
		xchg->did = chfcoe_ntoh24(hdr->s_id);
		xchg->ox_id = chfcoe_ntohs(hdr->ox_id);
		xchg->rx_id = 0xffff;
		xchg->seq_id = 0;
		xchg->seq_cnt = 0;
	}

	if (!fip)
		err = chfcoe_xchg_send(lnode, rnode, fr, xchg);
	else {
		err = chfcoe_xchg_build(lnode, fr, xchg);
		if (!err)
			err = chfcoe_fip_xmit(lnode, rnode, fr);
	}

	if (rnode) {
		chfcoe_put_xchg(xchg);
	}
	else {
		chfcoe_mem_free(xchg);
	}

	return err;
}

/**
 * chfc_lnode_resp_send() - Prepares ELS header for ELS cmd and sends 
 *			    ELS response.
 * @lnode - local node
 * @rnode - remote node
 * @fr_rx - Received FC frame
 * @cmd - ELS cmd
 * @reason - reason code
 * @expln - explanation code
 */
int chfc_lnode_resp_send(struct chfcoe_lnode *lnode, struct chfcoe_rnode *rnode,
		chfcoe_fc_buffer_t *fr_rx, uint32_t cmd, uint8_t reason,
		uint8_t expln)
{
	struct proto_fc_els_cmd *pl;
	struct proto_ls_rjt *rjt;
	chfcoe_fc_buffer_t *fr;

	switch (cmd) {
	case PROTO_ELS_CMD_CODE_LS_RJT:
		fr = chfcoe_fc_buffer_alloc(PAYLOAD_SZ(sizeof(*rjt)), CHFCOE_ATOMIC);
		if (!fr)
			goto reject;

		pl = proto_fc_frame_payload_get(fr, PAYLOAD_SZ(sizeof(*rjt)));
		pl->op = PROTO_ELS_CMD_CODE_LS_RJT;
		rjt = &pl->un.proto_ls_rjt;
		rjt->reason_code = reason;
		rjt->reason_exp = expln;
		break;
	case PROTO_ELS_CMD_CODE_ACC:
		fr = chfcoe_fc_buffer_alloc(PROTO_ELS_DESC_SIZE, CHFCOE_ATOMIC);
		if (!fr)
			goto reject;

		pl = proto_fc_frame_payload_get(fr, PROTO_ELS_DESC_SIZE);
		pl->op = PROTO_ELS_CMD_CODE_ACC;
		break;
	default:
		goto reject;
	}

	return chfc_els_resp_send(lnode, rnode, fr, fr_rx, 0);

reject:
	return -CHFCOE_NOMEM; 
}

/**
 * chfc_elsct_build() - Build ELSCT frame.
 * @lnode - local node
 * @fr - FC frame buffer
 * @cmd - ELS cmd
 * @did - destination id.
 * @cb - Callback handler.
 * @timeout - cmd timeout.
 */
int chfc_elsct_build(struct chfcoe_lnode *lnode, 
                chfcoe_fc_buffer_t *fr, uint32_t cmd, uint32_t did,
                void (*cb)(chfcoe_fc_buffer_t *, void *), void *arg, 
		uint32_t timeout __attribute__((unused)))
{
	chfcoe_xchg_cb_t *xchg;
	enum proto_fc_rctl r_ctl;
	enum proto_fc_fh_type type;
	struct chfcoe_rnode *rn = arg;

	if ((cmd >= PROTO_ELS_CMD_CODE_LS_RJT) &&
			(cmd <= PROTO_ELS_CMD_CODE_AUTH_ELS)) {
		r_ctl = PROTO_FC_RCTL_ELS_REQ;
		type = PROTO_FC_TYPE_ELS;
		chfc_els_build(lnode, fr, cmd);
	} else {
		r_ctl = PROTO_FC_RCTL_DD_UNSOL_CTL;
		type = PROTO_FC_TYPE_CT;
		chfc_ct_build(lnode, fr, cmd);
	}

	proto_fc_fill_fc_hdr(chfcoe_fc_hdr(fr), r_ctl, did, lnode->nport_id, type,
			PROTO_FC_FIRST_SEQ | PROTO_FC_END_SEQ |
			PROTO_FC_SEQ_INIT, 0);

	xchg = chfcoe_get_xchg(rn);
	if (!xchg)
		return CHFCOE_NOMEM;	

	chfcoe_xchg_init(xchg, cb, xchg, rn, lnode->nport_id, did,
			xchg->xid, 0xffff, 1, 0);

	xchg->timeo = 0; 
	xchg->cbarg1 = arg;

	return chfcoe_xchg_build(lnode, fr, xchg);
}

/**
 * chfc_elsct_build_tx() - Build ELSCT frame and transmit ELSCT frame.
 * @lnode - local node
 * @fr - FC frame buffer
 * @cmd - ELS cmd
 * @did - destination id.
 * @cb - Callback handler.
 * @timeout - cmd timeout.
 */
int chfc_elsct_build_tx(struct chfcoe_lnode *lnode, struct chfcoe_rnode *rnode,
                chfcoe_fc_buffer_t *fr, uint32_t cmd, uint32_t did,
                void (*cb)(chfcoe_fc_buffer_t *, void *), void *arg, 
		uint32_t timeout __attribute__((unused)))
{
	chfcoe_xchg_cb_t *xchg;
	enum proto_fc_rctl r_ctl;
	enum proto_fc_fh_type type;

	if ((cmd >= PROTO_ELS_CMD_CODE_LS_RJT) &&
			(cmd <= PROTO_ELS_CMD_CODE_AUTH_ELS)) {
		r_ctl = PROTO_FC_RCTL_ELS_REQ;
		type = PROTO_FC_TYPE_ELS;
		chfc_els_build(lnode, fr, cmd);
	} else {
		r_ctl = PROTO_FC_RCTL_DD_UNSOL_CTL;
		type = PROTO_FC_TYPE_CT;
		chfc_ct_build(lnode, fr, cmd);
	}

	proto_fc_fill_fc_hdr(chfcoe_fc_hdr(fr), r_ctl, did, lnode->nport_id, type,
			PROTO_FC_FIRST_SEQ | PROTO_FC_END_SEQ |
			PROTO_FC_SEQ_INIT, 0);

	xchg = chfcoe_get_xchg(rnode);
	if (!xchg)
		return CHFCOE_NOMEM;	

	chfcoe_xchg_init(xchg, cb, xchg, rnode, lnode->nport_id, did,
			xchg->xid, 0xffff, 1, 0);

	xchg->timeo = 0; 
	xchg->cbarg1 = arg;

	return chfcoe_xchg_send(lnode, rnode, fr, xchg);
}

/**
 * chfcoe_lnode_send_elsct() - Send ELSCT frame
 * @lnode - local node
 * @did - destination id.
 * @cmd - ELS cmd
 * @cb - Callback handler.
 */
void chfcoe_lnode_send_elsct(struct chfcoe_rnode *rnode, uint32_t did, 
		uint8_t cmd, uint32_t plsize, 
		void (*cb)(chfcoe_fc_buffer_t *, void *))
{
	struct chfcoe_lnode *lnode = rnode->lnode;
	chfcoe_fc_buffer_t *fr;
	int err;

	fr = chfcoe_fc_buffer_alloc(plsize, CHFCOE_ATOMIC);
	if (!fr)
		goto reject;

	err = chfc_elsct_build_tx(lnode, rnode, fr, cmd, did, cb, lnode, 
			2 * lnode->r_a_tov);
reject:
	return;
}

/**
 * chfcoe_lnode_scr_cb() - SCR Response handing.
 * @fr_rx - FC frame containing SCR response.
 * @arg - Callback data.
 */
void chfcoe_lnode_scr_cb(chfcoe_fc_buffer_t *fr_rx, void *arg)
{
	chfcoe_xchg_cb_t *xchg = arg;
	struct chfcoe_lnode *lnode = xchg->cbarg1;
	uint8_t *pl;

	chfcoe_mutex_lock(lnode->ln_mutex);
	pl = proto_fc_frame_payload_get_rx(fr_rx, sizeof(uint8_t));
	if (pl && *pl == PROTO_ELS_CMD_CODE_ACC) {
	} else {
		;
	}

	chfcoe_put_xchg(xchg);
	chfcoe_mutex_unlock(lnode->ln_mutex);
	return;
}

/**
 * chfcoe_els_check_state() - Checks local node state for ELS frames 
 * 			      received.
 * @lnode - local node
 * @rnode - Remote node
 * @cmd - ELS command
 * @rjt - returns reject code
 *
 * Returns appropriate reason code based on lnode state.
 */
int chfcoe_els_check_state(struct chfcoe_lnode *lnode, 
		struct chfcoe_rnode *rnode, uint32_t cmd,
		struct proto_elsct_rjt *rjt)
{
	switch (cmd) {
	case PROTO_ELS_CMD_CODE_PLOGI:
		if (lnode->state < CHFCOE_LN_ST_ONLINE) {
			rjt->reason = PROTO_LS_RJT_LOGICAL_BSY;
			rjt->expln = PROTO_LS_RJT_EXPL_NONE;
		}
		break;
	case PROTO_ELS_CMD_CODE_LOGO:
	case PROTO_ELS_CMD_CODE_PRLI:
	case PROTO_ELS_CMD_CODE_RTV:
	case PROTO_ELS_CMD_CODE_PRLO:
	case PROTO_ELS_CMD_CODE_ADISC:
		if (!rnode) {
			rjt->reason = PROTO_LS_RJT_UNABLE_TPC;
			rjt->expln = PROTO_LS_RJT_EXPL_PORT_LOGIN_REQ;
		}
		break;
	default:
		if (!rnode) {
			chfcoe_err(lnode, "rnode lookup failed for cmd"
					" 0x%x\n", cmd);
			return -1;
		}
		break;
	}

	return (rjt->reason);
}

/**
 * chfcoe_lnode_fcf_sm() - Local node FCF state-machine entry point.
 * @ln - local node
 * @evt - Event received
 * @evt_msg - Event message
 *
 * This is lnode FCF based state machine which acts on event received and 
 * changes next state. Need to invoked with mutext lock held.
 */
void chfcoe_lnode_fcf_sm(struct chfcoe_lnode *ln, chfcoe_ln_evt_t evt,
			void *evt_msg __attribute__((unused)))
{
	struct chfcoe_rnode *rn;
	struct proto_elsct_rjt rjt = {0, 0};
	int ret;
	chfcoe_dbg(ln, "lnode(f)sm 0x:%x state:%x evt:%x\n",
			ln->nport_id, ln->state, evt);
	switch (ln->state) {
	case CHFCOE_LN_ST_UNINIT:
		if (evt == CHFCOE_LN_EVT_LINK_UP) {
			rn = chfcoe_get_rnode(ln, PROTO_FABRIC_DID, NULL);
			if (!rn) {
				chfcoe_err(ln, "lnode(f)sm 0x:%x failed to "
					"alloc fabric rnode state:%x evt:%x\n",
					ln->state, evt);
				return;
			}

			rn->type = CHFCOE_RNFR_FABRIC;
               		chfcoe_rnode_fcf_sm(rn, CHFCOE_RN_EVT_UP, NULL);
			ln->state = CHFCOE_LN_ST_AWAIT_LOGIN;
		}
		break;
	case CHFCOE_LN_ST_AWAIT_LOGIN:

		if (evt == CHFCOE_LN_EVT_LOGIN_DONE) {
			chfcoe_adap_set_macaddr(ln->pi, ln->fcoe_mac, 
					&ln->fcoe_mac_idx, 0);
			rn = chfcoe_get_rnode(ln, PROTO_FC_FID_DIR_SERV, NULL);
			if (!rn) {
				chfcoe_err(ln, "lnode(f)sm 0x:%x failed to "
					"alloc NS rnode state:%x evt:%x\n",
					ln->state, evt);
				return;
			}
			rn->type = CHFCOE_RNFR_NS;
               		chfcoe_rnode_fcf_sm(rn, CHFCOE_RN_EVT_UP, NULL);
			ln->state = CHFCOE_LN_ST_ONLINE;
		}
		break;
	case CHFCOE_LN_ST_ONLINE:
		if (evt == CHFCOE_LN_EVT_NS_DONE) {
			rn = chfcoe_get_rnode(ln, PROTO_FC_FID_FCTRL, NULL);
			if (!rn) {
				chfcoe_err(ln, "lnode(f)sm 0x:%x failed to "
					"alloc SCR state:%x evt:%x\n",
					ln->state, evt);
				return;
			}
			chfcoe_lnode_send_elsct(rn, PROTO_FC_FID_FCTRL,
					PROTO_ELS_CMD_CODE_SCR,	
					PAYLOAD_SZ(sizeof(struct proto_scr)),
					chfcoe_lnode_scr_cb);
			rn->state = CHFCOE_RN_ST_READY;
			rn->type = CHFCOE_RNFR_NPORT;
		}
		if (evt == CHFCOE_LN_EVT_ELS) {
			chfcoe_fc_buffer_t *fr = (chfcoe_fc_buffer_t *) evt_msg;
			struct chfcoe_rnode *rn;
			fc_header_t *fh = (fc_header_t *)chfcoe_fc_data_ptr(fr);
			int cmd = *((uint8_t *)proto_fc_frame_payload_get_rx(fr, 
						sizeof(uint8_t)));
			
			rn = chfcoe_rn_lookup_portid(ln, 
					chfcoe_ntoh24(fh->s_id));
			
			if ((ret = chfcoe_els_check_state(ln, rn, cmd, &rjt))) {
				if (ret < 0)
					goto drop;
				goto reject;
			}
			if (!rn && cmd != PROTO_ELS_CMD_CODE_PLOGI) {
				chfcoe_err(ln, "lnode:0x%x ELS cmd:%x recv "
					"from unknown rnode:0x%x\n", 
					ln->nport_id, cmd, 
					chfcoe_ntoh24(fh->s_id));
				break;
			}	
			switch (cmd) {
			case PROTO_ELS_CMD_CODE_PLOGI:
				if (!rn) {
					rn = chfcoe_get_rnode(ln, 
							chfcoe_ntoh24(fh->s_id), NULL);
					if (!rn)
						return;
				}
				chfcoe_rnode_fcf_sm(rn,  
					CHFCOE_RN_EVT_PLOGI_RECVD, evt_msg);
				break;
			case PROTO_ELS_CMD_CODE_LOGO:
				chfcoe_rnode_fcf_sm(rn, 
					CHFCOE_RN_EVT_LOGO_RECVD, evt_msg);
				break;
			case PROTO_ELS_CMD_CODE_PRLI:
				chfcoe_rnode_fcf_sm(rn,  
					CHFCOE_RN_EVT_PRLI_RECVD, evt_msg);
				break;
			case PROTO_ELS_CMD_CODE_PRLO:
				chfcoe_rnode_fcf_sm(rn,  
					CHFCOE_RN_EVT_PRLO_RECVD, evt_msg);
				break;
			case PROTO_ELS_CMD_CODE_RTV:
				chfcoe_rnode_fcf_sm(rn, 
					CHFCOE_RN_EVT_RTV_RECVD, evt_msg);
				break;
			case PROTO_ELS_CMD_CODE_ADISC:
				chfcoe_rnode_fcf_sm(rn, 
					CHFCOE_RN_EVT_ADISC_RECVD, evt_msg);
				break;
			case PROTO_ELS_CMD_CODE_RRQ:
				chfcoe_rnode_fcf_sm(rn, 
					CHFCOE_RN_EVT_RRQ_RECVD, evt_msg);
				break;
			case PROTO_ELS_CMD_CODE_RSCN:
				chfcoe_rnode_fcf_sm(rn, 
					CHFCOE_RN_EVT_RSCN_RECVD, evt_msg);
				break;
			default:
				break;
			}
			return;
reject:
			chfcoe_dbg(lnode, "lnode(f) sm 0x%x: rjt cmd:0x%x "
				"reason 0x%x, expln 0x%x\n", ln->nport_id, 
				cmd, rjt.reason, rjt.expln);
			chfc_lnode_resp_send(ln, NULL, fr, 
				PROTO_ELS_CMD_CODE_LS_RJT, rjt.reason, 
				rjt.expln);
drop:
			return;
		}
		if (evt == CHFCOE_LN_EVT_LINK_DOWN) {
			chfcoe_adap_set_macaddr(ln->pi, ln->fcoe_mac, NULL, 1);
			chfc_lnode_down(ln);
		}	
		break;
	case CHFCOE_LN_ST_OFFLINE:
		if (evt == CHFCOE_LN_EVT_LINK_UP) {
			rn = chfcoe_get_rnode(ln, PROTO_FABRIC_DID, NULL);
			if (!rn) {
				chfcoe_err(ln, "lnode(f)sm 0x:%x failed to "
					"alloc fabric rnode state:%x evt:%x\n",
					ln->state, evt);
				return;
			}

			rn->type = CHFCOE_RNFR_FABRIC;
               		chfcoe_rnode_fcf_sm(rn, CHFCOE_RN_EVT_UP, NULL);
			ln->state = CHFCOE_LN_ST_AWAIT_LOGIN;
		}
		break;
	default:
		break;
	}
}

/**
 * chfcoe_post_event_rnode() - Post event to all rnodes of given lnode.
 * @ln - local node 
 * @evt - event
 * Returns - none
 *
 * Posts given rnode event to all rnodes connected with given Lnode.
 * This routine is invoked when lnode receives LINK_DOWN/DOWN_LINK/CLOSE
 * event.
 *
 * This called with mutex held  
 */
static void
chfcoe_post_event_rnode(struct chfcoe_lnode *ln, chfcoe_rn_evt_t evt)
{
	struct chfcoe_rnode *rnhead = (struct chfcoe_rnode *) &ln->rn_head;
        struct chfcoe_list *tmp, *next;
	struct chfcoe_rnode *rn;

	chfcoe_list_for_each_safe(tmp, next, &rnhead->rnlist) {
		rn = (struct chfcoe_rnode *) tmp;
                chfcoe_rnode_vn2vn_sm(rn, evt, NULL);

	}
}

/**
 * chfcoe_lnode_vn2vn_sm() - Local node VN2VN state-machine entry point.
 * @ln - local node
 * @evt - Event received
 * @evt_msg - Event message
 *
 * This is lnode VN2VN based state machine which acts on event received and 
 * changes next state.Need to invoked with mutext lock held.
 */
void chfcoe_lnode_vn2vn_sm(struct chfcoe_lnode *ln, chfcoe_ln_evt_t evt,
		void *evt_msg)
{
	struct chfcoe_port_parms *portp = (struct chfcoe_port_parms *)
		evt_msg;

	chfcoe_dbg(ln, "lnode(v)sm 0x:%x state:%x evt:%x\n",
			ln->nport_id, ln->state, evt);
	switch (ln->state) {
	case CHFCOE_LN_ST_UNINIT:
		if (evt == CHFCOE_LN_EVT_LINK_UP) {
			ln->state = CHFCOE_LN_ST_ONLINE;
			ln->nport_id = portp->nport_id;
			chfcoe_memcpy(ln->fcoe_mac, portp->vn_mac, 6);
			chfcoe_adap_set_macaddr(ln->pi, ln->fcoe_mac, 
					&ln->fcoe_mac_idx, 0);
			chfcoe_post_event_rnode(ln, CHFCOE_RN_EVT_UP);
			break;
		}
		if (evt == CHFCOE_LN_EVT_RDEV) {
			if(!chfcoe_confirm_rnode(ln, portp)) {
				chfcoe_err(ln, "lnode(v)sm 0x:%x failed to "
					"confirm rnode:0x%x name(wwpn):%llx\n",
					ln->nport_id, portp->nport_id, 
					chfcoe_wwn_to_u64(portp->wwpn));
			}	
			break;
		}
		chfcoe_dbg(ln, "lnode(v)sm 0x:%x droping invalid evt:%x recv "
				"in state :%x\n", ln->nport_id ,evt, ln->state);
		break;
	case CHFCOE_LN_ST_ONLINE:
		if (evt == CHFCOE_LN_EVT_RDEV) {
			struct chfcoe_rnode *rn;
			rn = chfcoe_confirm_rnode(ln, portp);
			if (!rn) {
				chfcoe_err(ln, "lnode(v)sm 0x:%x failed to "
					"confirm rnode:0x%x name(wwpn):%llx\n",
					ln->nport_id, portp->nport_id, 
					chfcoe_wwn_to_u64(portp->wwpn));
				return;
			}
			else {
				/* Remote node trying to relogin here. 
				 * Handle like implicit logout from rnode
				 * by destroying exiting rnode and creating 
				 * new one.
				 */
				if (rn->state != CHFCOE_RN_ST_UNINIT)
					chfcoe_rnode_remove_destroy(rn);
				rn = chfcoe_confirm_rnode(ln, portp);
				if (!rn) 
					return;
	                	chfcoe_rnode_vn2vn_sm(rn, CHFCOE_RN_EVT_UP,
						NULL);
			}
			break;
		}
		if (evt == CHFCOE_LN_EVT_ELS) {
			chfcoe_fc_buffer_t *fr = (chfcoe_fc_buffer_t *) evt_msg;
			struct chfcoe_rnode *rn;
			fc_header_t *fh = (fc_header_t *)chfcoe_fc_data_ptr(fr);
			int cmd = *((uint8_t *)proto_fc_frame_payload_get_rx(fr, 
						sizeof(uint8_t)));
			rn = chfcoe_rn_lookup_portid(ln, 
					chfcoe_ntoh24(fh->s_id));
			if (!rn) {
				chfcoe_err(ln, "lnode:0x%x ELS cmd:%x recv "
					"from unknown rnode:0x%x\n", 
					ln->nport_id, cmd, 
					chfcoe_ntoh24(fh->s_id));
				break;
			}	
			
			switch (cmd) {
			case PROTO_ELS_CMD_CODE_FLOGI:
				chfcoe_rnode_vn2vn_sm(rn,  
					CHFCOE_RN_EVT_FLOGI_RECVD, evt_msg);
				break;
			case PROTO_ELS_CMD_CODE_PLOGI:
				chfcoe_rnode_vn2vn_sm(rn,  
					CHFCOE_RN_EVT_PLOGI_RECVD, evt_msg);
				break;
			case PROTO_ELS_CMD_CODE_LOGO:
				chfcoe_rnode_vn2vn_sm(rn, 
					CHFCOE_RN_EVT_DOWN, evt_msg);
				break;
			case PROTO_ELS_CMD_CODE_PRLI:
				chfcoe_rnode_vn2vn_sm(rn,  
					CHFCOE_RN_EVT_PRLI_RECVD, evt_msg);
				break;
			case PROTO_ELS_CMD_CODE_PRLO:
				chfcoe_rnode_vn2vn_sm(rn,  
					CHFCOE_RN_EVT_PRLO_RECVD, evt_msg);
				break;
			case PROTO_ELS_CMD_CODE_RTV:
				chfcoe_rnode_vn2vn_sm(rn, 
					CHFCOE_RN_EVT_RTV_RECVD, evt_msg);
				break;
			case PROTO_ELS_CMD_CODE_ADISC:
				chfcoe_rnode_vn2vn_sm(rn, 
					CHFCOE_RN_EVT_ADISC_RECVD, evt_msg);
				break;
			case PROTO_ELS_CMD_CODE_RRQ:
				chfcoe_rnode_vn2vn_sm(rn, 
					CHFCOE_RN_EVT_RRQ_RECVD, evt_msg);
				break;
			}
			break;
		}
		if (evt == CHFCOE_LN_EVT_LINK_DOWN) {
			chfcoe_adap_set_macaddr(ln->pi, ln->fcoe_mac, NULL, 1);
			chfc_lnode_down(ln);
			ln->state = CHFCOE_LN_ST_OFFLINE;
			break;
		}	
		chfcoe_dbg(ln, "lnode s/m: droping invalid evt:%x recv in state"
				":%x nport_id:%x\n", evt, ln->state, 
				ln->nport_id);
		break;
	case CHFCOE_LN_ST_OFFLINE:
		if (evt == CHFCOE_LN_EVT_LINK_UP) {
			ln->state = CHFCOE_LN_ST_ONLINE;
			ln->nport_id = portp->nport_id;
			chfcoe_memcpy(ln->fcoe_mac, portp->vn_mac, 6);
			chfcoe_adap_set_macaddr(ln->pi, ln->fcoe_mac, 
					&ln->fcoe_mac_idx, 0);
			chfcoe_post_event_rnode(ln, CHFCOE_RN_EVT_UP);
			break;
		}
		if (evt == CHFCOE_LN_EVT_RDEV) {
			if(!chfcoe_confirm_rnode(ln, portp)) {
				chfcoe_err(ln, "lnode(v)sm 0x:%x failed to "
					"confirm rnode:0x%x name(wwpn):%llx\n",
					ln->nport_id, portp->nport_id, 
					chfcoe_wwn_to_u64(portp->wwpn));
			}	
			break;
		}
		chfcoe_dbg(ln, "lnode(v)sm 0x%x: droping invalid evt:%x recv "
				"in state:%x\n", ln->nport_id, evt, 
				ln->state);
		break;
	}
}

/**
 * chfcoe_lnode_evt_handler() - Local node event handler.
 * @ln - local node
 * @evt - Event received
 * @evt_msg - Event message
 */
void chfcoe_lnode_evt_handler(struct chfcoe_lnode *ln, 
		chfcoe_ln_evt_t evt, void *evt_msg)
{
	chfcoe_mutex_lock(ln->ln_mutex);
	if (ln->fip_type == CHFCOE_FCF)
		chfcoe_lnode_fcf_sm(ln, evt, evt_msg);
	else	
		chfcoe_lnode_vn2vn_sm(ln, evt, evt_msg);
	chfcoe_mutex_unlock(ln->ln_mutex);
}

/**
 * chfc_lnode_recv_req() - ELS frame receive handler.
 * @lnode - local node
 * @fr - Received FC frame buffer
 */
void chfc_lnode_recv_req(struct chfcoe_lnode *lnode, chfcoe_fc_buffer_t *fr)
{
        fc_header_t *fh;

        fh = (fc_header_t *)chfcoe_fc_data_ptr(fr);

	chfcoe_mutex_lock(lnode->ln_mutex);
        if (!(fh->type == PROTO_FC_TYPE_ELS &&
                        fh->r_ctl == PROTO_FC_RCTL_ELS_REQ))
		goto reject;

	if (lnode->fip_type != CHFCOE_FCF) 
		chfcoe_lnode_vn2vn_sm(lnode, CHFCOE_LN_EVT_ELS, fr);
	else 	
		chfcoe_lnode_fcf_sm(lnode, CHFCOE_LN_EVT_ELS, fr);
reject:
	chfcoe_mutex_unlock(lnode->ln_mutex);
	return;
}
