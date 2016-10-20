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
 * 	This chfcoe_rnode.c file contains fcoe remote node creation/deletion, 
 * 	state machine and helper rnode routines.
 *
 */

#include "chfcoe_rnode.h"
#include "chfcoe_xchg.h"
#include "chfcoe_io.h"

extern int chfcoe_fip_xmit(struct chfcoe_lnode *lnode, 
		struct chfcoe_rnode *rnode, chfcoe_fc_buffer_t *fr);
void chfcoe_rnode_free_work(void *data);
static int chfc_rnode_do_gpn_ft(struct chfcoe_rnode *rnode, 
		uint8_t area, uint8_t domain, uint8_t fmt);

extern unsigned int chfcoe_node_num;
extern struct chfcoe_node_info node_info[2];

unsigned long chfcoe_node_index = 1;

/**
 * chfcoe_get_rnode() - Returns the rnode with the given portid 
 * @ln: lnode
 * @portid: port id
 * @rdevp: remote device paramaters
 *
 * If no matching entry found, new rnode will be allocated and 
 * initialized using given port paramters.
 */
struct chfcoe_rnode *
chfcoe_get_rnode(struct chfcoe_lnode *lnode, uint32_t port_id,
		struct chfcoe_port_parms *rdevp)
{
	struct chfcoe_rnode *rnode;
	struct chfcoe_port_info *pi = lnode->pi;
	size_t size;
	unsigned int node_index = 0;
	int i = 0;

	rnode = chfcoe_rn_lookup_portid(lnode, port_id);
	if (rnode) {
		return rnode;
	} else {
		if (chfcoe_node_num > 1) {

			if (chfcoe_test_and_clear_bit(0, &chfcoe_node_index))
				node_index = 1;
			else  {
				chfcoe_set_bit(0, &chfcoe_node_index);
				node_index = 0;
			}
		}else {
			node_index = 0;
		}

		rnode = chfcoe_mem_alloc_node(chfcoe_rnode_size, node_info[node_index].node_id);
		if(!rnode) {
			chfcoe_err(pi, "lnode:0x%x failed to alloc rnode:0x%x\n", 
				lnode->nport_id, port_id);
			return NULL;
		}
		chfcoe_atomic_inc(pi->n_active_rnode);
		chfcoe_memset(rnode, 0, chfcoe_rnode_size);	
		rnode->lock = CHFCOE_PTR_OFFSET(rnode, sizeof(struct chfcoe_rnode)); 
		rnode->refcnt = CHFCOE_PTR_OFFSET(rnode, sizeof(struct chfcoe_rnode) + os_spinlock_size);
		rnode->rnode_free_work = CHFCOE_PTR_OFFSET(rnode, sizeof(struct chfcoe_rnode) + os_spinlock_size
				+ (os_atomic_size)); 
		rnode->rnode_free_work->work = CHFCOE_PTR_OFFSET(rnode, sizeof(struct chfcoe_rnode) + os_spinlock_size
				+ (os_atomic_size) + sizeof(chfcoe_dwork_t)); 

		rnode->submit_pending = chfcoe_mem_alloc_node(os_atomic_size, node_info[node_index].node_id);
		if (!rnode->submit_pending)
		       goto err0;	
		rnode->nport_id = port_id;
		rnode->node_index = node_index;

		size = (sizeof(void *) * (CHFCOE_MAX_XID + 1));
		rnode->xchg_tbl = chfcoe_mem_alloc_node(size, node_info[rnode->node_index].node_id);

		if (!rnode->xchg_tbl) {
			chfcoe_err(adap, "port:%d lnode:0x%x rnode:0x%x xchg tbl alloc failed\n", 
					pi->port_num, lnode->nport_id, rnode->nport_id);
			goto err1;
		}

		size = chfcoe_xchg_ioreq_size;
		for (i = 0; i < CHFCOE_MAX_XID; i++) {
			rnode->xchg_tbl[i] = chfcoe_mem_alloc_node(size, node_info[rnode->node_index].node_id);
			if (!rnode->xchg_tbl[i]) {
				chfcoe_err(adap, "port:%d lnode:0x%x rnode:0x%x xchg alloc failed\n", 
						pi->port_num, lnode->nport_id, rnode->nport_id);
				goto err2;
			}
		}
		rnode->xchg_tbl[CHFCOE_MAX_XID] = NULL;

		chfcoe_rnode_init(rnode, lnode, rdevp);
		return rnode;
	}

err2:
	for (i -= 1; i >= 0; i--)
		chfcoe_mem_free(rnode->xchg_tbl[i]);
	chfcoe_mem_free(rnode->xchg_tbl);
err1:
	chfcoe_mem_free(rnode->submit_pending);
err0:
	chfcoe_mem_free(rnode);
	chfcoe_atomic_dec(pi->n_active_rnode);

	return NULL;
}


/**
 * chfcoe_rnode_free() - Frees up remote node
 * @rnode: remote node
 *
 */
void chfcoe_rnode_free(struct chfcoe_rnode *rnode)
{
	struct chfcoe_lnode *lnode = rnode->lnode;
	struct chfcoe_port_info *pi = lnode->pi;
	int i;

	chfcoe_write_lock_bh(lnode->rn_lock);
	if (chfcoe_atomic_dec_and_test(rnode->refcnt)) {
		chfcoe_deq_elem(rnode);
		chfcoe_write_unlock_bh(lnode->rn_lock);
		
		/* Free xchg */
		for (i = 0; i < CHFCOE_MAX_XID; i++)
			chfcoe_mem_free(rnode->xchg_tbl[i]);
		chfcoe_mem_free(rnode->xchg_tbl);

		chfcoe_info(lnode, "lnode:0x%x free rnode:0x%x\n", 
			lnode->nport_id, rnode->nport_id);

		chfcoe_mem_free(rnode->submit_pending);
		chfcoe_mem_free(rnode);
		chfcoe_atomic_dec(pi->n_active_rnode);
		return;
	}
	chfcoe_write_unlock_bh(lnode->rn_lock);

}

/*
 * chfcoe_rnode_init() - Initialize rnode
 * @rnode: remote node
 * @lnode: lcoal node
 * @rdevp: remote port parameters
 */
void
chfcoe_rnode_init(struct chfcoe_rnode *rnode, struct chfcoe_lnode *lnode,
		struct chfcoe_port_parms *rdevp)
{
	rnode->mode = 0;

	rnode->lnode = lnode;
	rnode->state = CHFCOE_RN_ST_UNINIT;
	rnode->max_pldlen = PROTO_FC_MIN_MAX_PAYLOAD;

	if (lnode->fip_type == CHFCOE_FCF) {
		chfcoe_memcpy(rnode->vn_mac, lnode->fcf_mac, 6);
	}
	else if(rdevp && lnode->fip_type == CHFCOE_VN2VN) { 
		chfcoe_memcpy(rnode->vn_mac, rdevp->vn_mac, 6);
		chfcoe_memcpy(rnode->mac, rdevp->mac, 6);
		chfcoe_memcpy(rnode->wwnn, rdevp->wwnn, 8);
		chfcoe_memcpy(rnode->wwpn, rdevp->wwpn, 8);
	}	

	chfcoe_memcpy(rnode->smac, lnode->fcoe_mac, 6);
	chfcoe_head_init(&rnode->ioreq_activeq);
	chfcoe_spin_lock_init(rnode->lock);
	chfcoe_init_delayed_work(rnode->rnode_free_work, chfcoe_rnode_free_work, rnode);
	chfcoe_atomic_set(rnode->submit_pending, 0);
	chfcoe_atomic_set(rnode->refcnt, 1);
	rnode->ssn_hdl = NULL;

	chfcoe_info(lnode, "lnode:0x%x created rnode:0x%x node id:%d index:%u\n", 
			lnode->nport_id, rnode->nport_id,
			node_info[rnode->node_index].node_id, rnode->node_index);
	chfcoe_write_lock_bh(lnode->rn_lock);
	chfcoe_enq_at_tail(&lnode->rn_head, &rnode->rnlist);
	chfcoe_write_unlock_bh(lnode->rn_lock);

	return;
}

/*
 * chfcoe_rn_count() - Return number of remote ports under lnode
 * @lnode: lcoal node
 */
int chfcoe_rn_count(struct chfcoe_lnode *ln)
{
	struct chfcoe_rnode *rnhead = (struct chfcoe_rnode *) &ln->rn_head;
	struct chfcoe_list *tmp;
	int count = 0;

	chfcoe_read_lock_bh(ln->rn_lock);
	chfcoe_list_for_each(tmp, &rnhead->rnlist) 
		count++;
	chfcoe_read_unlock_bh(ln->rn_lock);

	return count;
}

/**
 * __chfcoe_lookup_portid() - Finds the rnode with the given portid 
 * @ln: lnode
 * @portid: port id
 *
 * Uses lockless lookup of rnode.
 */
struct chfcoe_rnode *
__chfcoe_rn_lookup_portid(struct chfcoe_lnode *ln, uint32_t portid)
{
	struct chfcoe_list *tmp;
	struct chfcoe_rnode *rn = NULL;
	
	chfcoe_list_for_each(tmp, &ln->rn_head) {
		rn = (struct chfcoe_rnode *) tmp;
		if (rn->nport_id == portid) {
			return rn;
		}
	}
	return NULL;
}

/**
 * chfcoe_lookup_portid() - Finds the rnode with the given portid 
 * @ln: lnode
 * @portid: port id
 *
 * Does the rnode lookup with lock held on given lnode. 
 */
struct chfcoe_rnode *
chfcoe_rn_lookup_portid(struct chfcoe_lnode *ln, uint32_t portid)
{
	struct chfcoe_rnode *rn = NULL;

	chfcoe_read_lock_bh(ln->rn_lock);
	rn = __chfcoe_rn_lookup_portid(ln, portid);
	chfcoe_read_unlock_bh(ln->rn_lock);

	return rn;

}

/**
 * chfcoe_rnode_destroy() - Destroys rnode
 * @rnode - remote node
 *
 */
void chfcoe_rnode_destroy(struct chfcoe_rnode *rnode)
{
	rnode->state = CHFCOE_RN_ST_OFFLINE;
	
	
	while(chfcoe_atomic_read(rnode->submit_pending)) {
		chfcoe_err(adap, "unable to destroy rnode 0x%x:0x%x "
				"due to pending reqs:%d\n",
				rnode->lnode->nport_id,
				rnode->nport_id,
				chfcoe_atomic_read(rnode->submit_pending));
		chfcoe_msleep(1000);
	}
	
	if (rnode->ssn_hdl) {
		chfcoe_dbg(adap, "unregister rnode 0x%x:0x%x\n", 
				rnode->lnode->nport_id,
				rnode->nport_id);
		chfcoe_tgt_tm_close_rn_reqs(rnode, 0, 0);
		chfcoe_tgt_unregister_session(rnode);
	}
	else {
		chfcoe_rnode_free(rnode);
	}

	return;
}

/**
 * chfcoe_rnode_remove_destroy() - removes given rnode from lnode and 
 * 				   destroys same rnode.
 * @rnode - remote node
 *
 */
void chfcoe_rnode_remove_destroy(struct chfcoe_rnode *rnode)
{
	struct chfcoe_lnode *lnode = rnode->lnode;

	chfcoe_flush_workers(rnode->node_index);
	chfcoe_write_lock_bh(lnode->rn_lock);
	chfcoe_deq_elem(rnode);
	chfcoe_enq_at_tail(&lnode->rn_head_drain, &rnode->rnlist);
	chfcoe_write_unlock_bh(lnode->rn_lock);

	chfcoe_rnode_destroy(rnode);
}

/**
 * chfcoe_rnode_prlo_recv() - Handles PRLO receive
 * @rnode - remote node
 *
 * All outstanding commands belonging to given rnode are cleaned up
 * and session is unregistered with target layer.
 */
void chfcoe_rnode_prlo_recv(struct chfcoe_rnode *rnode)
{
	struct chfcoe_lnode *lnode = rnode->lnode;

	if (!rnode->ssn_hdl)
		return;

	chfcoe_flush_workers(rnode->node_index);

	chfcoe_write_lock_bh(lnode->rn_lock);
	chfcoe_atomic_inc(rnode->refcnt);
	chfcoe_clear_bit(CHFCOE_RNODE_ULP_READY, &rnode->flags);
	chfcoe_write_unlock_bh(lnode->rn_lock);

	while(chfcoe_atomic_read(rnode->submit_pending)) {
		chfcoe_err(adap, "rnode destroy pending%d %p 0x%x\n",
				chfcoe_atomic_read(rnode->submit_pending), rnode, rnode->nport_id);
		chfcoe_msleep(1000);
	}

	chfcoe_tgt_tm_close_rn_reqs(rnode, 0, 0);
	chfcoe_tgt_unregister_session(rnode);

}


void chfc_rnode_elsct_retry(struct chfcoe_rnode *rnode)
{
	rnode->retries++;
	if (rnode->retries > CHFCOE_MAX_PROTO_RETRY) {
		if (rnode->nport_id == PROTO_FC_FID_DIR_SERV) {
			chfcoe_rnode_remove_destroy(rnode); 
		}
		return;
	}

	switch (rnode->state) {
	case CHFCOE_RN_ST_AWAIT_PLOGI_RESP:
		break;

	case CHFCOE_RN_ST_RNN_ID:
	case CHFCOE_RN_ST_RSNN_NN:
	case CHFCOE_RN_ST_RSPN_ID:
	case CHFCOE_RN_ST_RFT_ID:
	case CHFCOE_RN_ST_RFF_ID:
	case CHFCOE_RN_ST_GPN_FT:
		break;
	}
}

/**
 * chfc_rnode_gpn_ft_cb() - Handles GPN FT response
 * @fr_rx - Received frame
 * @arg - callback data.
 *
 */
static void chfc_rnode_gpn_ft_cb(chfcoe_fc_buffer_t *fr, void *arg)
{
	fc_header_t * fc_hdr = (fc_header_t *) chfcoe_fc_data_ptr(fr);
	chfcoe_xchg_cb_t *xchg = arg;
	struct chfcoe_rnode *rnode = xchg->cbarg1, *rn;
	struct chfcoe_lnode *lnode = rnode->lnode;
	struct chfcoe_list *entry, *next;
	struct chfcoe_list *seq; 
	struct gpn_ft_acc *resp;
	struct chfcoe_list tmp;
	struct fc_ct_cmd *pmbl;
	chfcoe_bufl_t *gpnft_rsp;
	struct gpn_ft_acc rem_data;
	int pl_len = chfcoe_fc_data_len(fr) - sizeof(fc_header_t);
	void *pl_data = NULL;
	int found;
	unsigned int rem = 0, len = 0;
	uint32_t port_id;

	chfcoe_dbg(rnode, "0x%x: gpnft_cb f_ctl:%x seqcnt:%x pl_len:%lu\n", 
			lnode->nport_id, chfcoe_ntoh24(fc_hdr->f_ctl),
			chfcoe_ntohs(fc_hdr->seq_cnt), pl_len);

	pl_data = fc_hdr + 1;
	chfcoe_mutex_lock(lnode->ln_mutex);
	if (chfcoe_fc_sof(fr) == PROTO_FC_SOF_I3 && 
		chfcoe_list_empty(&lnode->ctbuf_head)) {
		pmbl = proto_fc_frame_payload_get_rx(fr, PROTO_CT_IU_PMBL_SIZE);
		if (chfcoe_ntohs(pmbl->op) != PROTO_CT_RESP_FS_ACC) {
			chfcoe_err(rnode, "0x%x: GPN FT reject received\n",
					lnode->nport_id);
			/* free xchg */
			goto gpnft_err;
		}
		pl_len -= PROTO_CT_IU_PMBL_SIZE;
		pl_data += PROTO_CT_IU_PMBL_SIZE;
	}

	/* Allocate buffer to copy resp recv'd either single or multi 
	 * frames */
	gpnft_rsp = chfcoe_mem_alloc(pl_len + sizeof(chfcoe_bufl_t));
	if (!gpnft_rsp)  {
		chfcoe_err(rnode, "lnode 0x%x: failed to alloc gpn_ft pld\n",
				lnode->nport_id);
		/* free xchg */
		goto gpnft_err;
	}

	chfcoe_dbg(rnode, "lnode 0x%x: gpn_ft alloc pld:%p len:%d\n",
				lnode->nport_id, gpnft_rsp, pl_len);
	gpnft_rsp->pld = gpnft_rsp + 1;
	gpnft_rsp->pld_len = pl_len;
	chfcoe_memcpy(gpnft_rsp->pld,  pl_data, pl_len); 

	/* Add it list till last frame recv'd*/
	chfcoe_enq_at_tail(&lnode->ctbuf_head, gpnft_rsp);

	if (!(chfcoe_ntoh24(fc_hdr->f_ctl) & PROTO_FC_END_SEQ)) {
		chfcoe_mutex_unlock(lnode->ln_mutex);
		return;
	}	

	chfcoe_head_init(&tmp);
	chfcoe_write_lock_bh(lnode->rn_lock);
	chfcoe_list_for_each_safe(entry, next, &lnode->rn_head) {
		rn = (struct chfcoe_rnode *)entry;
		if (rn->nport_id == PROTO_FC_FID_FCTRL || 
			rn->nport_id == PROTO_FC_FID_DIR_SERV ||
			rn->nport_id == PROTO_FC_FID_FLOGI) {
			continue;
		}

		found = 0;
		rem = 0;
		chfcoe_list_for_each(seq, &lnode->ctbuf_head) {
			gpnft_rsp = (chfcoe_bufl_t *)seq;
			if (!rem) {
				resp = gpnft_rsp->pld;
				rem = gpnft_rsp->pld_len;
			}
			else {
				/* Get remaining GPN_FT resp  */
				len = CHFCOE_MIN((sizeof(*resp) - rem), 
						gpnft_rsp->pld_len);
				if (len < sizeof(*resp))
					break;

				chfcoe_dbg(rnode, "0x%x: copy rem gpnft resp "
					"len:%d\n", lnode->nport_id, len); 
				chfcoe_memcpy((void *)&rem_data + rem, 
					gpnft_rsp->pld, len);
				resp = &rem_data;
				port_id = chfcoe_ntoh24(resp->port_id);
				if (rn->nport_id == port_id) {
					found = 1;
					if (chfcoe_memcmp(rn->wwpn, resp->wwpn, 8)) {
						chfcoe_dbg(rnode, "gpn_ft cb: "
					       	" wwpn changed for rnode"
					       	" 0x%x\n", port_id);
						found = 0;
					}
					break;
				}

				if (resp->flags & PROTO_NS_ID_LAST)
					break;

				/* Move to next GPN_FT resp payload  */
				resp = gpnft_rsp->pld + len;
				rem = gpnft_rsp->pld_len - len;
			}
			chfcoe_dbg(rnode, "0x%x: parsing gpnft resp:%p "
					"len:%d\n", lnode->nport_id, resp, rem); 

			while (rem >= sizeof(*resp)) {
				port_id = chfcoe_ntoh24(resp->port_id);
				if (rn->nport_id == port_id) {
					found = 1;
					if (chfcoe_memcmp(rn->wwpn, resp->wwpn, 8)) {
						chfcoe_dbg(rnode, "gpn_ft cb: "
					       	" wwpn changed for rnode"
					       	" 0x%x\n", port_id);
						found = 0;
					}
					break;
				}

				if (resp->flags & PROTO_NS_ID_LAST)
					break;

				rem -= sizeof(*resp);
				resp++;
			}
			if (found)
				break;

			/* Save partial GPN FT response */
			if (rem) 
				chfcoe_memcpy(&rem_data, resp, rem);

		}	
		if (!found) {
			chfcoe_info(rnode, "0x%x: rnode 0x%x"
				       " not found in Name server\n", 
				       lnode->nport_id, rn->nport_id);
			chfcoe_deq_elem(rn);
			chfcoe_enq_at_tail(&tmp, &rn->rnlist);
		}
	}
	chfcoe_write_unlock_bh(lnode->rn_lock);

	while (!chfcoe_list_empty(&tmp)) {
		chfcoe_deq_from_head(&tmp, &entry);
		rn = (struct chfcoe_rnode *)entry;
		chfcoe_write_lock_bh(lnode->rn_lock);
		chfcoe_enq_at_tail(&lnode->rn_head_drain, &rn->rnlist);
		chfcoe_write_unlock_bh(lnode->rn_lock);
		chfcoe_rnode_destroy(rn);
	}

gpnft_err:
	chfcoe_list_for_each_safe(entry, next, &lnode->ctbuf_head) {
		chfcoe_deq_elem(entry);
		gpnft_rsp = (chfcoe_bufl_t *)entry;
		chfcoe_dbg(rnode, "lnode 0x%x: gpn_ft free pld:%p\n",
				lnode->nport_id, gpnft_rsp);
		chfcoe_mem_free(gpnft_rsp);
	}
	chfcoe_head_init(&lnode->ctbuf_head);
	chfcoe_dbg(rnode, "lnode 0x%x: gpn_ft cb, done\n", lnode->nport_id);
	lnode->flags &= ~CHFCOE_LN_DISC_PENDING;
	if (lnode->flags & CHFCOE_LN_DISC_RESTART) {
		lnode->flags &= ~CHFCOE_LN_DISC_RESTART;
		if (chfc_rnode_do_gpn_ft(rnode, 0, 0, 
			PROTO_RSCN_ADDR_FMT_FAB) == CHFCOE_SUCCESS)
			lnode->flags |= CHFCOE_LN_DISC_PENDING;
	}
	chfcoe_put_xchg(xchg);
	chfcoe_mutex_unlock(lnode->ln_mutex);
	return;
}

void chfcoe_rnode_send_elsct(struct chfcoe_rnode *rnode, 
		uint16_t cmd, int plsize, 
		void (*cb)(chfcoe_fc_buffer_t *, void *))
{
	struct chfcoe_lnode *lnode = rnode->lnode;
	chfcoe_fc_buffer_t *fr;
	int err;

	fr = chfcoe_fc_buffer_alloc(plsize, CHFCOE_ATOMIC);
	if (!fr) {
		chfcoe_err(lnode, "0x%x: failed to alloc elsct req buf for "
			"rnode 0x%x:\n", lnode->nport_id, rnode->nport_id);
		goto out;    
	}	

	err = chfc_elsct_build_tx(lnode, rnode, fr, cmd,
			rnode->nport_id, cb, 
			rnode, 3 * rnode->r_a_tov);
	chfcoe_dbg(lnode, "0x%x:0x%x send elsct cmd:%x\n",
			lnode->nport_id, rnode->nport_id, cmd);
out:
	return;
}

/**
 * chfcoe_rnode_rffid_cb() - Handles RFF ID response
 * @fr_rx - Received frame
 * @arg - callback data.
 *
 */
static void chfcoe_rnode_rffid_cb(chfcoe_fc_buffer_t *fr, void *arg)
{
	chfcoe_xchg_cb_t *xchg = arg;
	struct chfcoe_lnode *lnode = xchg->ln;
	struct chfcoe_rnode *rnode = xchg->cbarg1;
	fc_header_t *fh;
	struct fc_ct_cmd *pmbl;

	chfcoe_dbg(lnode, "0x%x:0x%x recv rffid resp\n",
			lnode->nport_id, rnode->nport_id);
	chfcoe_mutex_lock(lnode->ln_mutex);
	fh = (fc_header_t *)chfcoe_fc_data_ptr(fr);
	pmbl = proto_fc_frame_payload_get_rx(fr, PROTO_CT_IU_PMBL_SIZE);

	if (pmbl && fh->type == PROTO_FC_TYPE_CT &&
			pmbl->gs_type == PROTO_CT_GS_DIR_SERVICE &&
			pmbl->gs_subtype == PROTO_CT_DIR_SERVICE_NS &&
			chfcoe_ntohs(pmbl->op) == PROTO_CT_RESP_FS_ACC) {
		chfcoe_rnode_fcf_sm(rnode, CHFCOE_RN_EVT_READY, NULL);
		chfcoe_lnode_fcf_sm(lnode, CHFCOE_LN_EVT_NS_DONE, NULL);
	}
	else {
		chfcoe_err(lnode, "lnode 0x%x:rffid ft invalid opcode recv\n", 
			lnode->nport_id);
	}	

	chfcoe_put_xchg(xchg);
	chfcoe_mutex_unlock(lnode->ln_mutex);
}

/**
 * chfcoe_rnode_rftid_cb() - Handles RFT ID response
 * @fr_rx - Received frame
 * @arg - callback data.
 *
 */
static void chfcoe_rnode_rftid_cb(chfcoe_fc_buffer_t *fr, void *arg)
{
	chfcoe_xchg_cb_t *xchg = arg;
	struct chfcoe_lnode *lnode = xchg->ln;
	struct chfcoe_rnode *rnode = xchg->cbarg1;
	fc_header_t *fh;
	struct fc_ct_cmd *pmbl;

	chfcoe_dbg(lnode, "0x%x:0x%x recv rftid resp\n",
			lnode->nport_id, rnode->nport_id);
	chfcoe_mutex_lock(lnode->ln_mutex);
	fh = (fc_header_t *)chfcoe_fc_data_ptr(fr);
	pmbl = proto_fc_frame_payload_get_rx(fr, PROTO_CT_IU_PMBL_SIZE);

	if (pmbl && fh->type == PROTO_FC_TYPE_CT &&
			pmbl->gs_type == PROTO_CT_GS_DIR_SERVICE &&
			pmbl->gs_subtype == PROTO_CT_DIR_SERVICE_NS &&
			chfcoe_ntohs(pmbl->op) == PROTO_CT_RESP_FS_ACC) {
		chfcoe_rnode_send_elsct(rnode, PROTO_CT_NS_RFF_ID,
				PAYLOAD_CT_SZ(sizeof(struct rff_id)),
				chfcoe_rnode_rffid_cb);
	}	
	else {
		chfcoe_err(lnode, "lnode 0x%x rftid cb invalid cmd recv from "
			"rnode:0x%x\n", lnode->nport_id, rnode->nport_id);
	}	
	chfcoe_put_xchg(xchg);
	chfcoe_mutex_unlock(lnode->ln_mutex);
}

/**
 * chfcoe_rnode_rnnid_cb() - Handles RNN ID response
 * @fr_rx - Received frame
 * @arg - callback data.
 *
 */
static void chfcoe_rnode_rnnid_cb(chfcoe_fc_buffer_t *fr, void *arg)
{
	chfcoe_xchg_cb_t *xchg = arg;
	struct chfcoe_lnode *lnode = xchg->ln;
	struct chfcoe_rnode *rnode = xchg->cbarg1;
	fc_header_t *fh;
	struct fc_ct_cmd *pmbl;

	chfcoe_dbg(lnode, "0x%x:0x%x recv rnnid resp\n",
			lnode->nport_id, rnode->nport_id);
	chfcoe_mutex_lock(lnode->ln_mutex);
	fh = (fc_header_t *)chfcoe_fc_data_ptr(fr);
	pmbl = proto_fc_frame_payload_get_rx(fr, PROTO_CT_IU_PMBL_SIZE);

	if (pmbl && fh->type == PROTO_FC_TYPE_CT &&
			pmbl->gs_type == PROTO_CT_GS_DIR_SERVICE &&
			pmbl->gs_subtype == PROTO_CT_DIR_SERVICE_NS &&
			chfcoe_ntohs(pmbl->op) == PROTO_CT_RESP_FS_ACC) {
		chfcoe_rnode_send_elsct(rnode, PROTO_CT_NS_RFT_ID,
				PAYLOAD_CT_SZ(sizeof(struct rft_id)),
				chfcoe_rnode_rftid_cb);
	}	
	else {
		chfcoe_err(lnode, "lnode 0x%x rnnid cb invalid cmd recv from "
			"rnode:0x%x\n", lnode->nport_id, rnode->nport_id);
	}	
	chfcoe_put_xchg(xchg);
	chfcoe_mutex_unlock(lnode->ln_mutex);
}

/**
 * chfcoe_rnode_do_nsreg() - Starts Nameserver registerations.
 * @rnode - Remote node
 *
 */
void chfcoe_rnode_do_nsreg(struct chfcoe_rnode *rnode)
{
	chfcoe_rnode_send_elsct(rnode, PROTO_CT_NS_RNN_ID, 
			PAYLOAD_CT_SZ(sizeof(struct rnn_id)),
			chfcoe_rnode_rnnid_cb);
}

/**
 * chfc_get_maxframe() - returns max fc payload size
 * @sp - service parameter
 * @ln_max - lnode max frame size
 */
unsigned int chfc_get_maxframe(struct csio_service_parms *sp,
		unsigned int ln_max)
{
	unsigned int mfs;

	mfs = chfcoe_ntohs(sp->csp.rcv_sz) & 0x0fff;
	if (mfs >= PROTO_FC_MIN_MAX_PAYLOAD && mfs < ln_max)
		ln_max = mfs;
	mfs = chfcoe_ntohs(sp->clsp[3 - 1].rcv_data_sz);
	if (mfs >= PROTO_FC_MIN_MAX_PAYLOAD && mfs < ln_max)
		ln_max = mfs;
	return ln_max;
}

/**
 * chfc_rnode_process_plogi() - Process PLOGI payload
 * @rnode - Remote node
 * @fr - Received frame
 */
static int chfc_rnode_process_plogi(struct chfcoe_rnode *rnode,
                chfcoe_fc_buffer_t *fr)
{
	struct chfcoe_rnode *fnode;
        struct proto_fc_els_cmd *pl;
        struct csio_service_parms *sp;
        struct csio_cmn_sp *csp;
        struct csio_class_sp *clsp;
        unsigned int tov, plsize;
        uint16_t csp_seq, clsp_seq;

        plsize = sizeof(*sp) + PROTO_ELS_DESC_SIZE;
        pl = proto_fc_frame_payload_get_rx(fr, plsize);
        if (!pl) {
		chfcoe_err(lnode, "lnode 0x%x plogi invalid cmd recv from "
			"rnode:0x%x\n", rnode->lnode->nport_id, 
			rnode->nport_id);
                return -CHFCOE_INVAL;
	}	

        sp = &pl->un.proto_ls_logi.sp;

        chfcoe_memcpy(rnode->wwpn, sp->wwpn, 8);
        chfcoe_memcpy(rnode->wwnn, sp->wwnn, 8);

        csp = &sp->csp;
        clsp = &sp->clsp[2];    /* only class-3 supported */

        if (!(chfcoe_ntohs(clsp->serv_option) & PROTO_FC_CPC_VALID))
                return -CHFCOE_INVAL;

	if (rnode->lnode->fip_type == CHFCOE_FCF) {
		fnode = chfcoe_rn_lookup_portid(rnode->lnode, PROTO_FABRIC_DID);
		if (!fnode)
			return -CHFCOE_INVAL;

		rnode->e_d_tov = fnode->e_d_tov;
		rnode->r_a_tov = fnode->r_a_tov;
	} else {
		rnode->e_d_tov = PROTO_DEF_E_D_TOV;
		rnode->r_a_tov = PROTO_DEF_R_A_TOV;
	}

        tov = chfcoe_ntohl(csp->e_d_tov);
        if (chfcoe_ntohs(csp->word1_flags) & PROTO_FC_SP_FT_EDTR)
                tov /= 1000000;
        if (tov > rnode->e_d_tov)
                rnode->e_d_tov = tov;
        csp_seq = chfcoe_ntohs(csp->un1.s1.maxsq);
        clsp_seq = chfcoe_ntohs(clsp->concurrent_seq);
        if (clsp_seq < csp_seq)
                csp_seq = clsp_seq;
        rnode->max_seq = (csp_seq < 255) ? csp_seq : 255;
        rnode->max_pldlen = chfc_get_maxframe(sp, rnode->lnode->max_pldlen);
	chfcoe_info(rnode, "rnode 0x%x: set max payload to %d,"
			" lnode 0x%x max payload %d\n", 
			rnode->nport_id, rnode->max_pldlen, 
			rnode->lnode->nport_id, rnode->lnode->max_pldlen);

	return 0;
}

/**
 * chfc_rnode_plogi_cb() - Handles PLOGI response
 * @fr - Received frame
 * @arg - callback data.
 *
 */
static void chfc_rnode_plogi_cb(chfcoe_fc_buffer_t *fr, void *arg)
{
	chfcoe_xchg_cb_t *xchg = arg;
	struct chfcoe_lnode *lnode = xchg->ln;
	struct chfcoe_rnode *rnode = xchg->cbarg1;
	int err;
	struct proto_fc_els_cmd *plogi_cmd;

	chfcoe_mutex_lock(lnode->ln_mutex);
	plogi_cmd = proto_fc_frame_payload_get_rx(fr, PROTO_ELS_DESC_SIZE);
	if (!plogi_cmd) {
		chfcoe_err(lnode, "lnode 0x%x invalid cmd received from "
			"rnode:0x%x\n", lnode->nport_id, rnode->nport_id);
		goto plogi_err;
	}	

	chfcoe_dbg(lnode, "lnode 0x%x plogi reply op:%d recv from rnode 0x%x\n",
			lnode->nport_id, plogi_cmd->op, rnode->nport_id);
	if (plogi_cmd->op != PROTO_ELS_CMD_CODE_ACC) {
		chfcoe_err(lnode, "lnode 0x%x plogi failed reason:%x "
			"rnode:0x%x\n", lnode->nport_id, plogi_cmd->op, 
			rnode->nport_id);
		if (rnode->lnode->fip_type != CHFCOE_FCF)
			chfcoe_rnode_vn2vn_sm(rnode,
					CHFCOE_RN_EVT_PLOGI_REJ_RECVD,
					NULL);
		goto plogi_err;
	}
	err = chfc_rnode_process_plogi(rnode, fr);
	if (rnode->lnode->fip_type != CHFCOE_FCF) {
		chfcoe_rnode_vn2vn_sm(rnode, 
			(err ? CHFCOE_RN_EVT_PLOGI_REJ_RECVD : 
			CHFCOE_RN_EVT_PLOGI_ACC_RECVD),
			NULL);
		goto plogi_err;
	} else  {
		if (!err) {
			chfcoe_rnode_fcf_sm(rnode, 
				(err ? CHFCOE_RN_EVT_PLOGI_REJ_RECVD : 
				CHFCOE_RN_EVT_PLOGI_ACC_RECVD),
				NULL);
		}
		goto plogi_err;
	}
plogi_err:	
	chfcoe_put_xchg(xchg);
	chfcoe_mutex_unlock(lnode->ln_mutex);
}

/**
 * chfc_rnode_do_plogi() - Starts plogi request
 * @lnode - local node
 * @did - destination id
 */
void chfc_rnode_do_plogi(struct chfcoe_lnode *lnode, uint32_t did)
{
	struct chfcoe_rnode *rnode;
	chfcoe_fc_buffer_t *fr;
	int err;

	rnode = chfcoe_get_rnode(lnode, did, NULL);
	if (!rnode)
		goto reject;

	if (did == PROTO_FC_FID_DIR_SERV)
		rnode->type = CHFCOE_RNFR_NS;

	fr = chfcoe_fc_buffer_alloc(PAYLOAD_SZ(sizeof(struct proto_ls_logi)), CHFCOE_ATOMIC);
	if (!fr) {
		chfcoe_err(lnode, "0x%x: failed to alloc plog req buf for "
			"rnode 0x%x:\n", lnode->nport_id, rnode->nport_id);
		goto reject;
	}

	err = chfc_elsct_build_tx(rnode->lnode, rnode, fr, 
			PROTO_ELS_CMD_CODE_PLOGI,
			rnode->nport_id, chfc_rnode_plogi_cb, rnode,
			2 * rnode->r_a_tov);

	chfcoe_dbg(lnode, "0x%x:0x%x sent plogi\n",
			lnode->nport_id, rnode->nport_id);

reject:
	return;
}

/**
 * chfc_rnode_flogi_cmpl() - Handles FLOGI response
 * @fr - Received frame
 * @arg - callback data.
 *
 */
static void chfc_rnode_flogi_cmpl(chfcoe_fc_buffer_t *fr, void *arg)
{
	chfcoe_xchg_cb_t *xchg = arg;
	struct proto_fc_els_cmd *flogi_cmd;
	struct csio_service_parms *sp, *rn_sp;
        struct csio_class_sp *clsp;
	struct chfcoe_lnode *lnode = xchg->ln;
	struct chfcoe_rnode *rnode = xchg->cbarg1;
	chfcoe_fcf_t *fcf;

	chfcoe_mutex_lock(lnode->ln_mutex);
	flogi_cmd = proto_fc_frame_payload_get_rx(fr, PROTO_ELS_DESC_SIZE);

	if (!flogi_cmd) {
		chfcoe_err(lnode, "lnode 0x%x invalid cmd received from "
			"rnode:0x%x\n", lnode->nport_id, rnode->nport_id);
		goto out;
	}	

	chfcoe_dbg(lnode, "0x%x:0x%x flogi resp op:%d recv\n",
			lnode->nport_id, flogi_cmd->op, rnode->nport_id);
	if (flogi_cmd->op != PROTO_ELS_CMD_CODE_ACC) {
		chfcoe_err(lnode, "lnode 0x%x flogi failed reason:%x "
			"rnode:0x%x\n", lnode->nport_id, flogi_cmd->op, 
			rnode->nport_id);
		chfcoe_rnode_vn2vn_sm(rnode, CHFCOE_RN_EVT_FLOGI_REJ_RECVD,
				NULL);
		goto out;
	}

	flogi_cmd = proto_fc_frame_payload_get_rx(fr, 
			(sizeof(*sp) + PROTO_ELS_DESC_SIZE));
	if (!flogi_cmd) {
		chfcoe_err(lnode, "lnode 0x%x invalid flogi pld recv from "
			"rnode:0x%x\n", lnode->nport_id, rnode->nport_id);
		goto out;
	}	
        sp = &flogi_cmd->un.proto_ls_logi.sp;
	rn_sp = &rnode->sp;
        clsp = &sp->clsp[2];

	if (!(chfcoe_ntohs(clsp->serv_option) & PROTO_FC_CPC_VALID)) {
		chfcoe_err(lnode, "lnode 0x%x flogi class 3 not supported for "
			"rnode:0x%x\n", lnode->nport_id, rnode->nport_id);
		goto out;
	}
	
	rn_sp->csp.hi_ver = sp->csp.hi_ver;
	rn_sp->csp.lo_ver = sp->csp.lo_ver;
	rn_sp->csp.bb_credit = chfcoe_ntohs(sp->csp.bb_credit);
	rn_sp->csp.word1_flags = chfcoe_ntohs(sp->csp.word1_flags);
	rn_sp->csp.rcv_sz = chfcoe_ntohs(sp->csp.rcv_sz);
	rn_sp->csp.un1.r_a_tov = chfcoe_ntohl(sp->csp.un1.r_a_tov);
	rn_sp->csp.e_d_tov = chfcoe_ntohl(sp->csp.e_d_tov);

        chfcoe_memcpy(rnode->wwpn, sp->wwpn, 8);
        chfcoe_memcpy(rnode->wwnn, sp->wwnn, 8);

	if (lnode->fip_type != CHFCOE_FCF) {
		chfcoe_rnode_vn2vn_sm(rnode, CHFCOE_RN_EVT_FLOGI_ACC_RECVD,
				NULL);
	} else {
		fcf = lnode->fip_ctrl;
		fcf->max_fcoe_size = chfcoe_ntohs(sp->csp.rcv_sz);
		chfcoe_rnode_fcf_sm(rnode, CHFCOE_RN_EVT_FLOGI_ACC_RECVD,
				NULL);
	}

out:
	chfcoe_put_xchg(xchg);
	chfcoe_mutex_unlock(lnode->ln_mutex);
	return;
}

/**
 * chfc_rnode_do_flogi() - Send flogi request
 * @lnode - local node
 * @rnode - remote node
 * @did - destination id
 */
void chfc_rnode_do_flogi(struct chfcoe_lnode *lnode, struct chfcoe_rnode *rnode)
{
	chfcoe_fc_buffer_t *fr;
	int err;

	fr = chfcoe_fip_els_buffer_alloc(
		PAYLOAD_SZ(sizeof(struct proto_ls_logi)));
	if (!fr) {
		chfcoe_err(lnode, "0x%x: failed to alloc flogi req buf "
			" for rnode 0x%x:\n", lnode->nport_id, rnode->nport_id);
		goto reject;
	}	

	err = chfc_elsct_build(rnode->lnode, fr, 
			PROTO_ELS_CMD_CODE_FLOGI,
			rnode->nport_id, chfc_rnode_flogi_cmpl, rnode,
			2 * rnode->r_a_tov);

	chfcoe_dbg(lnode, "0x%x:0x%x sent flogi\n",
			lnode->nport_id, rnode->nport_id);
	chfcoe_fip_xmit(lnode, rnode, fr);
	return;
reject:
	return;
}

/**
 * chfc_rnode_do_gpn_ft() - Send GPN FT request
 * @rnode - remote node
 * @area  -  area code
 * @domain - domain code
 * @fmt - 
 */
static int chfc_rnode_do_gpn_ft(struct chfcoe_rnode *rnode, 
		uint8_t area, uint8_t domain, uint8_t fmt)
{
	struct chfcoe_lnode *lnode = rnode->lnode;
	struct chfcoe_rnode *rn = NULL;
	chfcoe_fc_buffer_t *fr;
	struct fc_ct_cmd *iu;
	struct gpn_ft *gpn_ft;
	chfcoe_xchg_cb_t *xchg;
	int err = 0;

	chfcoe_dbg(lnode, "0x%x send gpn_ft to rnode 0x%x: fmt:%d\n", 
			lnode->nport_id, rnode->nport_id, fmt);
	fr = chfcoe_fc_buffer_alloc(PAYLOAD_CT_SZ(sizeof(struct gpn_ft)), CHFCOE_ATOMIC);
	if (!fr) {
		chfcoe_err(lnode, "0x%x: failed to alloc gpnid_ft req buf "
			" for rnode 0x%x:\n", lnode->nport_id, rnode->nport_id);
		err = CHFCOE_NOMEM;
		goto reject;
	}	

	iu = fc_ct_preamble_build(fr, PROTO_CT_NS_GPN_FT, 
			sizeof(struct gpn_ft));
	gpn_ft = &iu->un.gpn_ft;
	chfcoe_memset(gpn_ft, 0, sizeof(struct gpn_ft));
	gpn_ft->fc4_type = PROTO_FC_TYPE_FCP;

	switch (fmt) {
	case PROTO_RSCN_ADDR_FMT_PORT:
	case PROTO_RSCN_ADDR_FMT_AREA:
		gpn_ft->flag = 1;
		gpn_ft->area_scope = area;
		gpn_ft->domain_scope = domain;
		break;
	case PROTO_RSCN_ADDR_FMT_DOM:
		gpn_ft->domain_scope = domain;
		break;
	}

	proto_fc_fill_fc_hdr(chfcoe_fc_hdr(fr), PROTO_FC_RCTL_DD_UNSOL_CTL,
			PROTO_FC_FID_DIR_SERV,
			lnode->nport_id, PROTO_FC_TYPE_CT,
			PROTO_FC_FIRST_SEQ | PROTO_FC_END_SEQ |
			PROTO_FC_SEQ_INIT, 0);

	rn = chfcoe_rn_lookup_portid(lnode, PROTO_FC_FID_DIR_SERV);
	if (!rn) {
		chfcoe_err(0, "rnode0x%x lookup failed\n", PROTO_FC_FID_DIR_SERV);
		err = CHFCOE_INVAL;
		goto reject;
	}

	xchg = chfcoe_get_xchg(rn);
	if (!xchg) {
		err = CHFCOE_NOMEM;
		goto reject;
	}

	chfcoe_xchg_init(xchg, chfc_rnode_gpn_ft_cb, xchg, rn, 
			lnode->nport_id, PROTO_FC_FID_DIR_SERV, 
			xchg->xid, 0xffff, 1, 0);
	xchg->timeo = 0;
	xchg->cbarg1 = rn;

	err = chfcoe_xchg_send(lnode, rn, fr, xchg);

	chfcoe_dbg(lnode, "0x%x: gpn_ft sent\n", lnode->nport_id);
reject:
	return err;
}

/**
 * chfc_rnode_handle_flogi_req() - Handles FLOGI request
 * @rnode - Remote node
 * @fr - Received frame
 */
void chfc_rnode_handle_flogi_req(struct chfcoe_rnode *rnode,
		chfcoe_fc_buffer_t *fr_rx)
{
	struct chfcoe_lnode *lnode = rnode->lnode;
	chfcoe_fc_buffer_t *fr;
	struct proto_fc_els_cmd *pl;
	struct csio_service_parms *sp;
	int err;

	chfcoe_dbg(lnode, "0x%x: recv flogi from rnode 0x%x:\n", 
			lnode->nport_id, rnode->nport_id);

	fr = chfcoe_fip_els_buffer_alloc(PAYLOAD_SZ(sizeof(*sp)));
	if (!fr) {
		chfcoe_err(lnode, "0x%x: failed to alloc flogi resp buf "
			" for rnode 0x%x:\n", lnode->nport_id, rnode->nport_id);
		goto reject;
	}	

	pl = proto_fc_frame_payload_get(fr, PAYLOAD_SZ(sizeof(*sp)));
	pl->op = PROTO_ELS_CMD_CODE_ACC;
	sp = &pl->un.proto_ls_logi.sp;

	chfcoe_memcpy(sp, &lnode->sp, sizeof(lnode->sp));
	chfcoe_memcpy(sp->wwpn, lnode->wwpn, sizeof(lnode->wwpn));
	chfcoe_memcpy(sp->wwnn, lnode->wwnn, sizeof(lnode->wwnn));

	err = chfc_els_resp_send(rnode->lnode, rnode, fr, fr_rx, 1);
	if (err) {
		chfcoe_err(lnode, "0x%x: failed to send flogi acc for "
			"rnode 0x%x:\n", lnode->nport_id, rnode->nport_id);
	}
	return;
reject:
	return;
}

/**
 * chfc_rnode_handle_plogi_req() - Handles PLOGI request
 * @rnode - Remote node
 * @fr - Received frame
 */
void chfc_rnode_handle_plogi_req(struct chfcoe_rnode *rnode,
		chfcoe_fc_buffer_t *fr_rx)
{
	struct chfcoe_lnode *lnode = rnode->lnode;
	chfcoe_fc_buffer_t *fr;
	struct proto_fc_els_cmd *pl;
	struct csio_service_parms *sp;
	struct csio_cmn_sp *csp;
	struct csio_class_sp *clsp;
	int err;

	chfcoe_dbg(lnode, "0x%x: recv plogi from rnode 0x%x:\n", 
			lnode->nport_id, rnode->nport_id);
	err = chfc_rnode_process_plogi(rnode, fr_rx);
	if (err) {
		chfcoe_err(lnode, "0x%x: failed to process plogi from "
			" rnode 0x%x:\n", lnode->nport_id, rnode->nport_id);
		goto reject;
	}	

	fr = chfcoe_fc_buffer_alloc(PAYLOAD_SZ(sizeof(*sp)), CHFCOE_ATOMIC);
	if (!fr) {
		chfcoe_err(lnode, "0x%x: failed to alloc plogi resp buf "
			" for rnode 0x%x:\n", lnode->nport_id, rnode->nport_id);
		goto reject; 
	}	

	pl = proto_fc_frame_payload_get(fr, PAYLOAD_SZ(sizeof(*sp)));
	pl->op = PROTO_ELS_CMD_CODE_ACC;
	sp = &pl->un.proto_ls_logi.sp;

	chfcoe_memcpy(sp, &lnode->sp, sizeof(lnode->sp));
	chfcoe_memcpy(sp->wwpn, lnode->wwpn, sizeof(lnode->wwpn));
	chfcoe_memcpy(sp->wwnn, lnode->wwnn, sizeof(lnode->wwnn));

	csp = &sp->csp;
	clsp = &sp->clsp[2]; /* only class-3 supported */
	csp->e_d_tov = chfcoe_htonl((uint32_t)rnode->e_d_tov);
	csp->rcv_sz = chfcoe_htons(lnode->max_pldlen);
	clsp->concurrent_seq = chfcoe_htons(rnode->max_seq);
	clsp->rcv_data_sz = chfcoe_htons(lnode->max_pldlen);

	err = chfc_els_resp_send(rnode->lnode, rnode, fr, fr_rx, 0);
	if (err) {
		chfcoe_err(lnode, "0x%x: failed to send plogi acc for "
			" rnode 0x%x:\n", lnode->nport_id, rnode->nport_id);
	}

	return;
reject:
	return;
}

/**
 * chfc_rnode_handle_prli_req() - Handles PRLI request
 * @rnode - Remote node
 * @fr - Received frame
 */
static void chfc_rnode_handle_prli_req(struct chfcoe_rnode *rnode,
		chfcoe_fc_buffer_t *fr_rx)
{
	struct chfcoe_lnode *lnode = rnode->lnode;
	struct proto_fc_els_cmd *pl;
	struct proto_prli *prli, *rprli;
	int pl_len, err;
	chfcoe_fc_buffer_t *fr;
	uint8_t resp, pg_len, npages;
	uint32_t params;

	chfcoe_dbg(lnode, "0x%x: recv prli from rnode 0x%x:\n", 
			lnode->nport_id, rnode->nport_id);

	if (CHFCOE_SUCCESS != chfcoe_tgt_register_session(rnode)) {
		chfcoe_err(lnode, "0x%x: failed to register sess for "
			"rnode 0x%x:\n", lnode->nport_id, rnode->nport_id);
		goto reject;
	}	

	chfcoe_set_bit(CHFCOE_RNODE_ULP_READY, &rnode->flags);
	
	pl = proto_fc_frame_payload_get_rx(fr_rx, 4);
	if (!pl) {
		chfcoe_err(lnode, "0x%x: invalid prli req recv from "
			"rnode 0x%x:\n", lnode->nport_id, rnode->nport_id);
		goto reject;
	}	
	pg_len = pl->byte1;
	pl_len = (pl->byte2 << 8) | pl->byte3;
	prli = &pl->un.proto_prli;

	fr = chfcoe_fc_buffer_alloc(pl_len, CHFCOE_ATOMIC);
	if (!fr) {
		chfcoe_err(lnode, "0x%x: failed to alloc prli resp frame for "
			"rnode 0x%x:\n", lnode->nport_id, rnode->nport_id);
		goto reject;
	}	

	pl = proto_fc_frame_payload_get(fr, pl_len);
	pl->op = PROTO_ELS_CMD_CODE_ACC;
	pl->byte1 = pg_len;
	pl->byte2 = (pl_len >> 8);
	pl->byte3 = pl_len & 0xff;

	rprli = &pl->un.proto_prli;

	pl_len -= 4;
	npages = pl_len / pg_len;
	while (npages) {
		rprli->type = prli->type;
		rprli->proc_flags = 0;

		switch (prli->type) {
		case 0:
			resp = (prli->proc_flags & PROTO_FC_SPP_EST_IMG_PAIR) ?
				PROTO_FC_SPP_RESP_INVL : PROTO_FC_SPP_RESP_ACK;
		case PROTO_FC_TYPE_FCP:
			params = chfcoe_ntohl(prli->serv_parms_flags);
			if (params & PROTO_FCP_SPPF_RETRY)
				rnode->fcp_flags |= PROTO_FCP_SPPF_RETRY;
			if (params & PROTO_FCP_SPPF_INIT_FCN)
				rnode->mode |= PROTO_FCP_SPPF_INIT_FCN;
			if (params & PROTO_FCP_SPPF_TARG_FCN)
				rnode->mode |= PROTO_FCP_SPPF_TARG_FCN;

			rprli->serv_parms_flags = 
				chfcoe_htonl(PROTO_FCP_SPPF_TARG_FCN |	
					PROTO_FCP_SPPF_RD_XRDY_DIS);
			rprli->proc_flags |= prli->proc_flags & PROTO_FC_SPP_EST_IMG_PAIR;
			resp = PROTO_FC_SPP_RESP_ACK;
			break;
		default:
			resp = (prli->proc_flags & PROTO_FC_SPP_EST_IMG_PAIR) ?
				PROTO_FC_SPP_RESP_CONF : PROTO_FC_SPP_RESP_INVL;
		}
		rprli->proc_flags |= resp;
		pl_len -= pg_len;
		rprli = (struct proto_prli *)((char *)rprli + pg_len);
		prli = (struct proto_prli *)((char *)prli + pg_len);
		npages--;
	}

	err = chfc_els_resp_send(rnode->lnode, rnode, fr, fr_rx, 0);
	if (err) {
		chfcoe_err(lnode, "0x%x: failed to send prli acc for "
			" rnode 0x%x:\n", lnode->nport_id, rnode->nport_id);
	}
	return;

reject:
	return;
}

/**
 * chfc_rnode_handle_prlo_req() - Handles PRLO request
 * @rnode - Remote node
 * @fr - Received frame
 */
void chfc_rnode_handle_prlo_req(struct chfcoe_rnode *rnode, 
		chfcoe_fc_buffer_t *fr_rx)
{
	struct chfcoe_lnode *lnode = rnode->lnode;
	struct proto_fc_els_cmd *pl;
	struct proto_prlo *prlo;
	int pl_len, err;
	chfcoe_fc_buffer_t *fr;

	chfcoe_dbg(lnode, "0x%x: recv prlo from rnode 0x%x:\n", 
			lnode->nport_id, rnode->nport_id);

	pl = proto_fc_frame_payload_get_rx(fr_rx, 4);
	if (!pl) {
		chfcoe_err(lnode, "0x%x: invalid prlo req recv from "
			"rnode 0x%x:\n", lnode->nport_id, rnode->nport_id);
		goto reject;
	}	
	pl_len = (pl->byte2 << 8) | pl->byte3;

	if (pl_len != 20) {
		chfcoe_err(lnode, "0x%x: invalid prlo payload recv from "
			"rnode 0x%x:\n", lnode->nport_id, rnode->nport_id);
		goto reject;
	}
	
	fr = chfcoe_fc_buffer_alloc(pl_len, CHFCOE_ATOMIC);
	if (!fr) {
		chfcoe_err(lnode, "0x%x: failed to alloc prlo resp buf for "
			"rnode 0x%x:\n", lnode->nport_id, rnode->nport_id);
		goto reject;
	}	

	pl = proto_fc_frame_payload_get(fr, pl_len);
	pl->op = PROTO_ELS_CMD_CODE_ACC;
	pl->byte1 = 0x10;
	pl->byte2 = (pl_len >> 8);
	pl->byte3 = pl_len & 0xff;

	prlo = &pl->un.proto_prlo;
	prlo->type = prlo->type;
	prlo->proc_flags = PROTO_FC_SPP_RESP_ACK;
	
	rnode->fcp_flags = 0;
	rnode->mode = 0;

	err = chfc_els_resp_send(rnode->lnode, rnode, fr, fr_rx, 0);
	if (err) {
		chfcoe_err(lnode, "0x%x: failed to send prlo acc for "
			" rnode 0x%x:\n", lnode->nport_id, rnode->nport_id);
	}
	
	chfcoe_rnode_prlo_recv(rnode);
	
	chfcoe_dbg(lnode, "0x%x: recv prlo acc from rnode 0x%x:\n", 
			lnode->nport_id, rnode->nport_id);
	return;

reject:
	chfcoe_dbg(lnode, "0x%x: recv prlo rej from rnode 0x%x:\n", 
			lnode->nport_id, rnode->nport_id);
	return;
}

/**
 * chfc_rnode_handle_logo_req() - Handles LOGO request
 * @rnode - Remote node
 * @fr - Received frame
 */
void chfc_rnode_handle_logo_req(struct chfcoe_rnode *rnode, 
		chfcoe_fc_buffer_t *fr_rx)
{
	struct chfcoe_lnode *lnode = rnode->lnode;
	struct proto_fc_els_cmd *pl;
	struct proto_logo *logo;
	int pl_len, err;

	chfcoe_dbg(lnode, "0x%x: recv logo from rnode 0x%x:\n", 
			lnode->nport_id, rnode->nport_id);

	pl_len = sizeof(*logo) + 4;
	pl = proto_fc_frame_payload_get_rx(fr_rx, 4);
	if (!pl) {
		chfcoe_err(lnode, "0x%x: invalid logo req recv from "
			"rnode 0x%x:\n", lnode->nport_id, rnode->nport_id);
		goto reject;
	}	
	logo = &pl->un.proto_logo;
	
	if (chfcoe_memcmp(rnode->wwpn, logo->wwpn, 8)) {
		chfcoe_err(lnode, "0x%x: logo recv from wrong rnode 0x%x:\n", 
			lnode->nport_id, rnode->nport_id);
	}

	err = chfc_lnode_resp_send(rnode->lnode, NULL, fr_rx, 
			PROTO_ELS_CMD_CODE_ACC, 0, 0);
	if (err) {
		chfcoe_err(lnode, "0x%x: failed to send logo acc for "
			" rnode 0x%x:\n", lnode->nport_id, rnode->nport_id);
	}

	chfcoe_dbg(lnode, "0x%x: recv logo acc from rnode 0x%x:\n", 
			lnode->nport_id, rnode->nport_id);

	chfcoe_rnode_remove_destroy(rnode);

reject:
	return;
}

/**
 * chfc_rnode_handle_rtv_req() - Handles RTV request
 * @rnode - Remote node
 * @fr - Received frame
 */
static void chfc_rnode_handle_rtv_req(struct chfcoe_rnode *rnode,
		chfcoe_fc_buffer_t *fr_rx)
{
	struct chfcoe_lnode *lnode = rnode->lnode;
	struct proto_fc_els_cmd *pl;
	struct proto_rtv_resp *resp;
	chfcoe_fc_buffer_t *fr;
	int err;

	fr = chfcoe_fc_buffer_alloc(sizeof(*resp) + PROTO_ELS_DESC_SIZE, CHFCOE_ATOMIC);
	if (!fr) {
		chfcoe_err(lnode, "0x%x: failed to alloc rtv req buf for "
			"rnode 0x%x:\n", lnode->nport_id, rnode->nport_id);
		goto reject;
	}	

	pl = proto_fc_frame_payload_get(fr, sizeof(*resp) + 
			PROTO_ELS_DESC_SIZE);
	if (!pl) {
		chfcoe_err(lnode, "0x%x: invalid rtv req recv from "
			"rnode 0x%x:\n", lnode->nport_id, rnode->nport_id);
		goto reject;
	}	
	pl->op = PROTO_ELS_CMD_CODE_ACC;
	resp = &pl->un.proto_rtv_resp;
	resp->r_a_tov = chfcoe_htonl(rnode->r_a_tov);
	resp->e_d_tov = chfcoe_htonl(rnode->e_d_tov);

	err = chfc_els_resp_send(rnode->lnode, rnode, fr, fr_rx, 0);
	if (err) {
		chfcoe_err(lnode, "0x%x: failed to send rtv acc for "
			" rnode 0x%x:\n", lnode->nport_id, rnode->nport_id);
	}
	chfcoe_dbg(lnode, "0x%x: recv rtv acc from rnode 0x%x:\n", 
			lnode->nport_id, rnode->nport_id);
	return;

reject:
	chfcoe_dbg(lnode, "0x%x: recv rtv rej from rnode 0x%x:\n", 
			lnode->nport_id, rnode->nport_id);
	return;
}

/**
 * chfc_rnode_handle_rscn_req() - Handles RSCN request
 * @rnode - Remote node
 * @fr - Received frame
 */
static void chfc_rnode_handle_rscn_req(struct chfcoe_rnode *rnode, 
		chfcoe_fc_buffer_t *fr_rx)
{
	struct chfcoe_lnode *lnode = rnode->lnode;
	struct proto_fc_els_cmd *pl;
	struct proto_rscn *rscn;
	int err, pg_len, pl_len, npages;

	pl = proto_fc_frame_payload_get_rx(fr_rx, PAYLOAD_SZ(sizeof(*rscn)));
	if (!pl) {
		chfcoe_err(lnode, "0x%x: invalid rscn req recv from "
			"rnode 0x%x:\n", lnode->nport_id, rnode->nport_id);
		goto reject;
	}	

	rscn = &pl->un.proto_rscn;
	pg_len = pl->byte1;
	pl_len = (pl->byte2 << 8) | pl->byte3;

	pl_len -= 4;
	npages = pl_len / pg_len;
	chfcoe_info(lnode, "lnode 0x%x: port %d: recv rscn, npages %d\n",
			lnode->nport_id, lnode->port_num, npages);

	err = chfc_lnode_resp_send(rnode->lnode, NULL, fr_rx, 
			PROTO_ELS_CMD_CODE_ACC, 0, 0);
	if (err) {
		chfcoe_err(lnode, "0x%x: failed to send rscn acc\n",
			lnode->nport_id);
		goto reject;
	}

	if (npages) {
		if (!(lnode->flags & CHFCOE_LN_DISC_PENDING)) {
			if (chfc_rnode_do_gpn_ft(rnode, 0, 0, 
				PROTO_RSCN_ADDR_FMT_FAB) == CHFCOE_SUCCESS)
				lnode->flags |= CHFCOE_LN_DISC_PENDING;
		}
		else
			lnode->flags |= CHFCOE_LN_DISC_RESTART;
	}	
	chfcoe_dbg(lnode, "lnode 0x%x: rscn done\n", lnode->nport_id);
	return;

reject:
	chfcoe_err(lnode, "lnode 0x%x: rscn rejected\n", lnode->nport_id);
	return;
}

/**
 * chfc_rnode_handle_adisc_req() - Handles ADISC request
 * @rnode - Remote node
 * @fr - Received frame
 */
void chfc_rnode_handle_adisc_req(struct chfcoe_rnode *rnode,
		chfcoe_fc_buffer_t *fr_rx)
{
	struct chfcoe_lnode *lnode = rnode->lnode;
	struct proto_fc_els_cmd *pl;
	struct proto_adisc *resp;
	chfcoe_fc_buffer_t *fr;
	int err;

	fr = chfcoe_fc_buffer_alloc(sizeof(*resp) + PROTO_ELS_DESC_SIZE, CHFCOE_ATOMIC);
	if (!fr) {
		chfcoe_err(lnode, "0x%x: failed to alloc adisc req buf for "
			"rnode 0x%x:\n", lnode->nport_id, rnode->nport_id);
		goto reject;
	}	

	pl = proto_fc_frame_payload_get(fr, sizeof(*resp));
	__chfc_adisc_build(rnode->lnode, fr);
	pl->op = PROTO_ELS_CMD_CODE_ACC;

	err = chfc_els_resp_send(rnode->lnode, rnode, fr, fr_rx, 0);
	if (err) {
		chfcoe_err(lnode, "0x%x: failed to send adisc acc for "
			" rnode 0x%x:\n", lnode->nport_id, rnode->nport_id);
	}
	chfcoe_dbg(lnode, "0x%x: recv adisc acc from rnode 0x%x:\n", 
			lnode->nport_id, rnode->nport_id);
	return;

reject:
	chfcoe_dbg(lnode, "0x%x: recv adisc rej from rnode 0x%x:\n", 
			lnode->nport_id, rnode->nport_id);
	return;
}

/**
 * chfc_rnode_handle_rrq_req() - Handles RRQ request
 * @rnode - Remote node
 * @fr - Received frame
 */
void chfc_rnode_handle_rrq_req(struct chfcoe_rnode *rnode,
		chfcoe_fc_buffer_t *fr_rx)
{
	struct proto_fc_els_cmd *pl;
	struct proto_ls_acc *acc;
	fc_header_t *hdr;
	chfcoe_fc_buffer_t *fr_tx;

	chfcoe_dbg(lnode, "0x%x: recv rrq acc from rnode 0x%x:\n", 
			rnode->lnode->nport_id, rnode->nport_id);

	hdr = (fc_header_t *)chfcoe_fc_data_ptr(fr_rx);

	fr_tx = chfcoe_fc_buffer_alloc(sizeof(*acc), CHFCOE_ATOMIC);
	if (!fr_tx) {
		chfcoe_err(lnode, "0x%x: failed alloc rrq resp buf for "
			"rnode 0x%x:\n", rnode->lnode->nport_id, 
			rnode->nport_id);
		goto reject;
	}	

	pl = proto_fc_frame_payload_get(fr_tx, sizeof(*acc));
	pl->op = PROTO_ELS_CMD_CODE_ACC;

	chfc_els_resp_send(rnode->lnode, rnode, fr_tx, fr_rx, 0);
	return;

reject:
	chfcoe_dbg(lnode, "0x%x: recv rrq rej from rnode 0x%x:\n", 
			rnode->lnode->nport_id, rnode->nport_id);
	return;
}

/**
 * chfcoe_is_rnf_ready() - returns TRUE if rnode is ready state.
 * @rn - Remote node
 */
static inline int chfcoe_is_rnf_ready(struct chfcoe_rnode *rn)
{
	return (rn->state == CHFCOE_RN_ST_READY);
}

/**
 * chfcoe_is_rnf_uninit() - returns TRUE if rnode is uninit state.
 * @rn - Remote node
 */
static inline int chfcoe_is_rnf_uninit(struct chfcoe_rnode *rn)
{
	return (rn->state == CHFCOE_RN_ST_UNINIT);
}

/**
 * chfcoe_is_rnf_uninit() - returns TRUE if rnode port id is well 
 * 			    known address.
 * @rn - Remote node
 */
static inline int chfcoe_is_rnf_wka(uint32_t port_id)
{
	if ((port_id & PROTO_WK_DID_MASK) == PROTO_WK_DID_MASK)
		return 1;
	return 0;
}

/*****************************************************************************/
/* FCoE Rnode Protocol handling routines                                     */
/*****************************************************************************/

/**
 * chfcoe_rnf_lookup_wwpn - Finds the rnode with the given wwpn 
 * @ln: lnode
 * @wwpn: wwpn
 *
 * Does the rnode lookup on the given lnode and wwpn. If no matching entry 
 * found, NULL is returned.
 */
struct chfcoe_rnode *
chfcoe_rn_lookup_wwpn(struct chfcoe_lnode *ln, uint8_t *wwpn)
{
	struct chfcoe_rnode *rnhead = (struct chfcoe_rnode *) &ln->rn_head;
	struct chfcoe_list *tmp;
	struct chfcoe_rnode *rn;

	chfcoe_list_for_each(tmp, &rnhead->rnlist) {
		rn = (struct chfcoe_rnode *) tmp;
		if (!chfcoe_memcmp(rn->wwpn, wwpn, 8))
			return rn;
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
struct chfcoe_rnode *
chfcoe_rnf_lookup_portid(struct chfcoe_lnode *ln, uint32_t portid)
{
	struct chfcoe_rnode *rnhead = (struct chfcoe_rnode *) &ln->rn_head;
	struct chfcoe_list *tmp;
	struct chfcoe_rnode *rn;

	chfcoe_list_for_each(tmp, &rnhead->rnlist) {
		rn = (struct chfcoe_rnode *) tmp;
		if (rn->nport_id == portid)
			return rn;
	}

	return NULL;
}

/**
 * chfcoe_onfirm_rnode - confirms rnode based on wwpn.
 * @ln: FCoE lnode
 * @rdevp: remote device params
 * This routines searches other rnode in list having same wwpn of new rnode.
 * If there is a match, then matched rnode is returned and otherwise new rnode 
 * is returned.
 * returns rnode.
 */
struct chfcoe_rnode * 
chfcoe_confirm_rnode(struct chfcoe_lnode *ln, struct chfcoe_port_parms *rdevp)
{
	struct chfcoe_rnode *rnf, *match_rnf;
	uint32_t port_id;
	
	port_id = rdevp->nport_id;
	/* Lookup on nport_id */
	rnf = chfcoe_rnf_lookup_portid(ln, port_id);
	if (!rnf) {

		/* Lookup on wwpn for NPORTs */
		rnf = chfcoe_rn_lookup_wwpn(ln, rdevp->wwpn);
		if (!rnf) {
			goto alloc_rnode;
		}
		/* found rnf */
		goto found_rnode;
	} else {
		/*
		 * Verify rnode found for fabric ports, cntrl port
		 * There might be cases where the wwpn of these ports is NULL
		 * So checking with the nport_id
		 */
		if (chfcoe_is_rnf_wka(port_id)) {
			/*
			 * Now compare the wwpn to confirm that
			 * same port relogged in.If so update the matched rnf.
			 * Else, go ahead and alloc a new rnode.
			 */
			if (!chfcoe_memcmp(rnf->wwpn, rdevp->wwpn, 8)) {
				goto found_rnode;
			}
			rnf->nport_id = CHFCOE_INVALID_IDX;
			goto alloc_rnode;
		}
		/* For regular N-ports */
		if (!chfcoe_memcmp(rnf->wwpn, rdevp->wwpn, 8)) {
			/* Update rnf */
			goto found_rnode;
		}

		/* Search for rnode that have same wwpn */ 
		match_rnf = chfcoe_rn_lookup_wwpn(ln, rdevp->wwpn);
		if (match_rnf != NULL) {
			chfcoe_dbg(ln, 
				"nportid:x%x changed for rport name(wwpn):%llx "
				"did:x%x\n", port_id, 
				chfcoe_wwn_to_u64(rdevp->wwpn),
				match_rnf->nport_id);
			rnf->nport_id = CHFCOE_INVALID_IDX;
			rnf = match_rnf;
		}
		else {
			chfcoe_dbg(ln, 
				"rnode wwpn mismatch found nportid:x%x "
				"name(wwpn):%llx\n",
				port_id, 
				chfcoe_wwn_to_u64(rnf->wwpn));
			if (chfcoe_is_rnf_ready(rnf)) {
				chfcoe_warn(ln, "rnode is already active "
					"wwpn:%llx portid:x%x\n", 
					chfcoe_wwn_to_u64(rnf->wwpn),
					port_id);
			}
			rnf->nport_id = CHFCOE_INVALID_IDX;
			goto alloc_rnode;
		}
	}

found_rnode:
	chfcoe_dbg(ln, "found rnode:%p nportid:x%x name(wwpn):%llx\n",
		rnf, port_id, chfcoe_wwn_to_u64(rdevp->wwpn));

	/* update rnode */
	rnf->nport_id = port_id;
	chfcoe_memcpy(rnf->vn_mac, rdevp->vn_mac, 6);
	chfcoe_memcpy(rnf->mac, rdevp->mac, 6);
	chfcoe_memcpy(rnf->wwnn, rdevp->wwnn, 8);
	chfcoe_memcpy(rnf->wwpn, rdevp->wwpn, 8);
	ln->lnode_stats.n_rnode_match++;
	return rnf;

alloc_rnode:
	rnf = chfcoe_get_rnode(ln, port_id, rdevp);
	if (!rnf) {
		return NULL;
	} 	
	chfcoe_dbg(ln, "alloc rnode:%p ssni:x%x name(wwpn):%llx\n",
		rnf, port_id, chfcoe_wwn_to_u64(rdevp->wwpn));

	return rnf;
}

/**
 * chfcoe_rnode_fcf_sm() - remote node FCF state-machine entry point.
 * @rn - remote node
 * @evt - Event received
 * @evt_msg - Event message
 *
 * This is rnode FCF based state machine which acts on event received and 
 * changes next state.Need to invoked with mutext lock held.
 */
void chfcoe_rnode_fcf_sm(struct chfcoe_rnode *rn, chfcoe_rn_evt_t evt, 
		void *evt_msg)
{
	struct chfcoe_lnode *ln = rn->lnode;
	fc_header_t *fh;
	chfcoe_dbg(ln, "rnode(f) sm: 0x%x:0x%x state:%x evt:%x\n",
			ln->nport_id, rn->nport_id, rn->state, evt);
	switch (rn->state) {
	case CHFCOE_RN_ST_UNINIT:
		if (evt == CHFCOE_RN_EVT_UP) {
			if (rn->type == CHFCOE_RNFR_FABRIC) {
				chfc_rnode_do_flogi(rn->lnode, rn);
				rn->state = CHFCOE_RN_ST_AWAIT_FLOGI;
			}	
			else {
				chfc_rnode_do_plogi(rn->lnode, rn->nport_id);
				rn->state = CHFCOE_RN_ST_AWAIT_PLOGI_RESP;
			}
		}
		if (evt == CHFCOE_RN_EVT_PLOGI_RECVD) {
			chfc_rnode_handle_plogi_req(rn, 
				(chfcoe_fc_buffer_t *)evt_msg); 
			rn->state = CHFCOE_RN_ST_PLOGI_DONE;
		}
		break;
	case CHFCOE_RN_ST_AWAIT_FLOGI:
		if (evt == CHFCOE_RN_EVT_FLOGI_REJ_RECVD) {
			chfc_rnode_do_flogi(rn->lnode, rn);
		}

		if (evt == CHFCOE_RN_EVT_FLOGI_ACC_RECVD) {

			rn->cur_event |= (1 << CHFCOE_RN_EVT_FLOGI_ACC_RECVD);
			chfcoe_lnode_fcf_sm(ln, 
					CHFCOE_LN_EVT_LOGIN_DONE, NULL);
			rn->state = CHFCOE_RN_ST_READY;
		}
		break;
	case CHFCOE_RN_ST_AWAIT_PLOGI_RESP:
		if (evt == CHFCOE_RN_EVT_PLOGI_ACC_RECVD) {
			if (rn->type == CHFCOE_RNFR_NS) {
				chfcoe_rnode_do_nsreg(rn);
			}
			rn->state = CHFCOE_RN_ST_PLOGI_DONE;
		}
		if (evt == CHFCOE_RN_EVT_PLOGI_REJ_RECVD) {
			chfc_rnode_do_plogi(rn->lnode, rn->nport_id);
		}
		break;
	case CHFCOE_RN_ST_PLOGI_DONE:
		if (evt == CHFCOE_RN_EVT_PRLI_RECVD) {
			chfc_rnode_handle_prli_req(rn, 
				(chfcoe_fc_buffer_t *)evt_msg); 
			rn->state = CHFCOE_RN_ST_READY;
		}
		if (evt == CHFCOE_RN_EVT_READY) {
			rn->state = CHFCOE_RN_ST_READY;
		}	
		break;
	case CHFCOE_RN_ST_READY:
		switch (evt) {
		case CHFCOE_RN_EVT_RTV_RECVD:
			chfc_rnode_handle_rtv_req(rn, 
					(chfcoe_fc_buffer_t *)evt_msg); 
			break;
		case CHFCOE_RN_EVT_ADISC_RECVD:
			chfc_rnode_handle_adisc_req(rn, 
					(chfcoe_fc_buffer_t *)evt_msg); 
			break;
		case CHFCOE_RN_EVT_RRQ_RECVD:
			chfc_rnode_handle_rrq_req(rn, 
					(chfcoe_fc_buffer_t *)evt_msg); 
			break;
		case CHFCOE_RN_EVT_RSCN_RECVD:
			chfc_rnode_handle_rscn_req(rn, 
					(chfcoe_fc_buffer_t *)evt_msg); 
			break;
		case CHFCOE_RN_EVT_LOGO_RECVD:
			chfc_rnode_handle_logo_req(rn, 
					(chfcoe_fc_buffer_t *)evt_msg); 
			break;
		case CHFCOE_RN_EVT_PRLO_RECVD:
			chfc_rnode_handle_prlo_req(rn, 
					(chfcoe_fc_buffer_t *)evt_msg); 
			rn->state = CHFCOE_RN_ST_OFFLINE;
			break;
		case CHFCOE_RN_EVT_PLOGI_RECVD:	
			/* Session reinstatement */
			chfcoe_warn(rnode, "rnode(f) sm:0x%x:0x%x recv plogi "
				"on existing session\n", 
				ln->nport_id, rn->nport_id, rn->state);
        		fh = (fc_header_t *)chfcoe_fc_data_ptr( 
				((chfcoe_fc_buffer_t *) evt_msg));
			chfcoe_rnode_remove_destroy(rn);
			rn = chfcoe_get_rnode(ln, 
				chfcoe_ntoh24(fh->s_id), NULL);
			if (rn) {
				chfc_rnode_handle_plogi_req(rn,
					(chfcoe_fc_buffer_t *) evt_msg);
				rn->state = CHFCOE_RN_ST_PLOGI_DONE;
			}
			break;
		default:
			chfcoe_dbg(ln, "rnode(f) sm: 0x%x:0x%x dropping "
				"invalid evt:%x recv in state:%x\n",
				ln->nport_id, rn->nport_id, evt, rn->state);
		}
		break;

	case CHFCOE_RN_ST_OFFLINE:
		if (evt == CHFCOE_RN_EVT_LOGO_RECVD) {
			chfc_rnode_handle_logo_req(rn, 
					(chfcoe_fc_buffer_t *)evt_msg); 
			break;
		}
		break;
	default:
		chfcoe_dbg(ln, "rnode(f) sm: 0x%x:0x%x dropping "
				"invalid evt:%x recv in state:%x\n",
				ln->nport_id, rn->nport_id, evt, rn->state);
		break;
	}
}

/**
 * chfcoe_rnode_vn2vn_sm() - remote node VN2VN state-machine entry point.
 * @rn - remote node
 * @evt - Event received
 * @evt_msg - Event message
 *
 * This is rnode VN2VN based state machine which acts on event received and 
 * changes next state.Need to invoked with mutext lock held.
 */
void chfcoe_rnode_vn2vn_sm(struct chfcoe_rnode *rn, chfcoe_rn_evt_t evt, 
		void *evt_msg)
{
	struct chfcoe_lnode *ln = rn->lnode;
	fc_header_t *fh;
	chfcoe_dbg(ln, "rnode(v) sm: 0x%x:0x%x state:%x evt:%x\n",
			ln->nport_id, rn->nport_id, rn->state, evt);
	switch (rn->state) {
	case CHFCOE_RN_ST_UNINIT:
		if (evt == CHFCOE_RN_EVT_FLOGI_RECVD) {
			chfc_rnode_handle_flogi_req(rn, 
				(chfcoe_fc_buffer_t *)evt_msg); 
			chfc_rnode_do_flogi(rn->lnode, rn);
			rn->state = CHFCOE_RN_ST_AWAIT_FLOGI;
			rn->cur_event = (1 << CHFCOE_RN_EVT_FLOGI_RECVD);
		}
		break;
	case CHFCOE_RN_ST_AWAIT_FLOGI:
		if (evt == CHFCOE_RN_EVT_FLOGI_RECVD) {
			chfc_rnode_handle_flogi_req(rn, 
				(chfcoe_fc_buffer_t *)evt_msg); 
			rn->cur_event |= (1 << CHFCOE_RN_EVT_FLOGI_RECVD);
		}
		if (evt == CHFCOE_RN_EVT_FLOGI_REJ_RECVD) {
			chfc_rnode_do_flogi(rn->lnode, rn);
		}
		if (evt == CHFCOE_RN_EVT_FLOGI_ACC_RECVD) {
			rn->cur_event |= (1 << CHFCOE_RN_EVT_FLOGI_ACC_RECVD);
		}

		if (rn->cur_event == ((1 << CHFCOE_RN_EVT_FLOGI_ACC_RECVD) | 
				(1 << CHFCOE_RN_EVT_FLOGI_RECVD))) {
			 if (chfcoe_wwn_to_u64(ln->wwpn) > 
				 chfcoe_wwn_to_u64(rn->wwpn)) {
				chfc_rnode_do_plogi(rn->lnode, rn->nport_id);
				rn->state = CHFCOE_RN_ST_AWAIT_PLOGI_RESP;
			 }
			 else {
				rn->state = CHFCOE_RN_ST_AWAIT_PLOGI;
			 }
		}
		break;
	case CHFCOE_RN_ST_AWAIT_PLOGI:
		if (evt == CHFCOE_RN_EVT_PLOGI_RECVD) {
			chfc_rnode_handle_plogi_req(rn, 
				(chfcoe_fc_buffer_t *)evt_msg); 
			rn->state = CHFCOE_RN_ST_PLOGI_DONE;
		}
		break;
	case CHFCOE_RN_ST_AWAIT_PLOGI_RESP:
		if (evt == CHFCOE_RN_EVT_PLOGI_ACC_RECVD) {
			rn->state = CHFCOE_RN_ST_PLOGI_DONE;
		}
		if (evt == CHFCOE_RN_EVT_PLOGI_REJ_RECVD) {
			chfc_rnode_do_plogi(rn->lnode, rn->nport_id);
		}
		break;
	case CHFCOE_RN_ST_PLOGI_DONE:
		if (evt == CHFCOE_RN_EVT_PRLI_RECVD) {
			chfc_rnode_handle_prli_req(rn, 
				(chfcoe_fc_buffer_t *)evt_msg); 
			rn->state = CHFCOE_RN_ST_READY;
		}
		break;
	case CHFCOE_RN_ST_READY:
		switch (evt) {
		case CHFCOE_RN_EVT_PRLO_RECVD:
			chfc_rnode_handle_prlo_req(rn, 
					(chfcoe_fc_buffer_t *)evt_msg); 
			rn->state = CHFCOE_RN_ST_OFFLINE;
			break;
		case CHFCOE_RN_EVT_RTV_RECVD:
			chfc_rnode_handle_rtv_req(rn, 
					(chfcoe_fc_buffer_t *)evt_msg); 
			break;
		case CHFCOE_RN_EVT_ADISC_RECVD:
			chfc_rnode_handle_adisc_req(rn, 
					(chfcoe_fc_buffer_t *)evt_msg); 
			break;
		case CHFCOE_RN_EVT_RRQ_RECVD:
			chfc_rnode_handle_rrq_req(rn, 
					(chfcoe_fc_buffer_t *)evt_msg); 
			break;
		case CHFCOE_RN_EVT_LOGO_RECVD:
			chfc_rnode_handle_logo_req(rn, 
					(chfcoe_fc_buffer_t *)evt_msg); 
			break;
		case CHFCOE_RN_EVT_PLOGI_RECVD:	
        		fh = (fc_header_t *)chfcoe_fc_data_ptr( 
				((chfcoe_fc_buffer_t *) evt_msg));
			chfcoe_rnode_remove_destroy(rn);
			rn = chfcoe_get_rnode(ln, 
				chfcoe_ntoh24(fh->s_id), NULL);
			if (rn) {
				chfc_rnode_handle_plogi_req(rn,
					(chfcoe_fc_buffer_t *) evt_msg);
				rn->state = CHFCOE_RN_ST_PLOGI_DONE;
			}
			break;
		default:
			chfcoe_dbg(ln, "rnode(v) sm: 0x%x:0x%x dropping "
				"invalid evt:%x recv in state:%x\n",
				ln->nport_id, rn->nport_id, evt, rn->state);
		}
		break;

	case CHFCOE_RN_ST_OFFLINE:
		if (evt == CHFCOE_RN_EVT_LOGO_RECVD) {
			chfc_rnode_handle_logo_req(rn, 
					(chfcoe_fc_buffer_t *)evt_msg); 
			break;
		}
		break;
	default:
		chfcoe_dbg(ln, "rnode(v) sm: 0x%x:0x%x dropping "
				"invalid evt:%x recv in state:%x\n",
				ln->nport_id, rn->nport_id, evt, rn->state);
		break;
	}
}

