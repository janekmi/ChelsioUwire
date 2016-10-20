/*
 *  Copyright (C) 2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include "chfcoe_xchg.h"

extern fc4_handler_t fc4_handlers[];

int chfcoe_fcb_xmit(struct chfcoe_lnode *, struct chfcoe_rnode *,
		chfcoe_fc_buffer_t *);

/* XCHG Timer routines */
void chfcoe_xchg_timer_sched(chfcoe_xchg_cb_t *xchg)
{
	chfcoe_atomic_inc(xchg->xchg_refcnt);
	chfcoe_queue_delayed_work(chfcoe_workq, xchg->xchg_work, xchg->timeo);
}

static inline bool
chfcoe_xchg_timer_cancel(chfcoe_xchg_cb_t *xchg)
{
	int ret = chfcoe_cancel_delayed_work(xchg->xchg_work);

	if (ret)
		chfcoe_put_xchg(xchg);

	return ret;
}

void chfcoe_err_work_fn_control(void *data)
{
	chfcoe_xchg_cb_t *xchg = data;
	
	chfcoe_dbg(pi, "err work fn control called\n");	
	chfcoe_put_xchg(xchg);
}

int chfcoe_xchg_build(struct chfcoe_lnode *ln __attribute__((unused)),
	       	chfcoe_fc_buffer_t *fb, chfcoe_xchg_cb_t *xchg)
{
	fc_header_t *fc_hdr = (fc_header_t *) chfcoe_fc_hdr(fb);
	uint32_t f_ctl = chfcoe_ntoh24(fc_hdr->f_ctl);

	if (xchg->seq_cnt) 
		chfcoe_fc_sof(fb) = PROTO_FC_SOF_N3;
	else
		chfcoe_fc_sof(fb) = PROTO_FC_SOF_I3;

	if (f_ctl & PROTO_FC_END_SEQ) 
		chfcoe_fc_eof(fb) = PROTO_FC_EOF_T;	
	else 
		chfcoe_fc_eof(fb) = PROTO_FC_EOF_N;
	
	fc_hdr->ox_id = chfcoe_htons(xchg->ox_id);
	fc_hdr->rx_id = chfcoe_htons(xchg->rx_id); 
	fc_hdr->seq_cnt = chfcoe_htons(xchg->seq_cnt);
	fc_hdr->seq_id = xchg->seq_id;
	xchg->seq_cnt++;
	
	return CHFCOE_SUCCESS;
}

int chfcoe_xchg_send(struct chfcoe_lnode *ln, struct chfcoe_rnode *rn,
		chfcoe_fc_buffer_t *fb,	chfcoe_xchg_cb_t *xchg)
{
	fc_header_t *fc_hdr = (fc_header_t *) chfcoe_fc_hdr(fb);
	uint32_t f_ctl = chfcoe_ntoh24(fc_hdr->f_ctl);

	if (xchg->seq_cnt) 
		chfcoe_fc_sof(fb) = PROTO_FC_SOF_N3;
	else
		chfcoe_fc_sof(fb) = PROTO_FC_SOF_I3;

	if (f_ctl & PROTO_FC_END_SEQ) 
		chfcoe_fc_eof(fb) = PROTO_FC_EOF_T;	
	else 
		chfcoe_fc_eof(fb) = PROTO_FC_EOF_N;
	
	fc_hdr->ox_id = chfcoe_htons(xchg->ox_id);
	fc_hdr->rx_id = chfcoe_htons(xchg->rx_id); 
	fc_hdr->seq_cnt = chfcoe_htons(xchg->seq_cnt);
	fc_hdr->seq_id = xchg->seq_id;
	xchg->seq_cnt++;
	
	return chfcoe_fcb_xmit(ln, rn, fb);
}


static int chfcoe_post_abts_rsp(chfcoe_fc_buffer_t *rx_fb, struct chfcoe_rnode *rn,
		enum proto_fc_rctl rsp, uint16_t rjt_rsn, uint16_t rjt_expl)
{
	chfcoe_fc_buffer_t *tx_fb = NULL;
	fc_header_t *tx_fc_hdr, *rx_fc_hdr;
	struct proto_fc_ba_rjt *ba_rjt;
	struct proto_fc_ba_acc *ba_acc;
	struct chfcoe_lnode *ln = rn->lnode;
	uint32_t f_ctl = 0;
	
	rx_fc_hdr = (fc_header_t *) chfcoe_fc_data_ptr(rx_fb);

	if (rsp == PROTO_FC_RCTL_BA_ACC) {
		tx_fb = chfcoe_fc_buffer_alloc(sizeof(*ba_acc), CHFCOE_ATOMIC);
		if (!tx_fb) {
			tx_fb = chfcoe_fc_buffer_alloc(sizeof(*ba_acc), CHFCOE_NOATOMIC);
			if (!tx_fb) {
				chfcoe_err(0, "fc buffer alloc failed\n");
				return CHFCOE_NOMEM;
			}
		}
		tx_fc_hdr = (fc_header_t *) chfcoe_fc_hdr(tx_fb);
		
		ba_acc = proto_fc_frame_payload_get(tx_fb, sizeof(*ba_acc));
		ba_acc->ba_seq_id_val = 0;
		ba_acc->ba_seq_id = rx_fc_hdr->seq_id;
		ba_acc->ba_ox_id = rx_fc_hdr->ox_id;
		ba_acc->ba_rx_id = rx_fc_hdr->rx_id; 	
		ba_acc->ba_low_seq_cnt = 0;		
		ba_acc->ba_high_seq_cnt = 0xffff;

	}
	else {
		tx_fb = chfcoe_fc_buffer_alloc(sizeof(*ba_rjt), CHFCOE_ATOMIC);
		if (!tx_fb) { 
			return CHFCOE_NOMEM;
		}
		tx_fc_hdr = (fc_header_t *) chfcoe_fc_hdr(tx_fb);
		
		ba_rjt = proto_fc_frame_payload_get(tx_fb, sizeof(*ba_rjt));
		ba_rjt->br_reason = rjt_rsn;
		ba_rjt->br_explan = rjt_expl;
		ba_rjt->br_vendor = 0;
	}

	f_ctl = PROTO_FC_LAST_SEQ | PROTO_FC_END_SEQ | PROTO_FC_SEQ_INIT;

	if (!(chfcoe_ntoh24(rx_fc_hdr->f_ctl) & PROTO_FC_EX_CTX))
			f_ctl |= PROTO_FC_EX_CTX;

	proto_fc_fill_fc_hdr(chfcoe_fc_hdr(tx_fb), rsp, chfcoe_ntoh24(rx_fc_hdr->s_id),
		     chfcoe_ntoh24(rx_fc_hdr->d_id), FC_TYPE_BLS, f_ctl, 0);	

	tx_fc_hdr->ox_id = rx_fc_hdr->ox_id;
	tx_fc_hdr->rx_id = rx_fc_hdr->rx_id; 
	tx_fc_hdr->seq_id = 2;
	tx_fc_hdr->seq_cnt = 0;
	
	chfcoe_fc_sof(tx_fb) = PROTO_FC_SOF_I3;
	chfcoe_fc_eof(tx_fb) = PROTO_FC_EOF_T;

	return chfcoe_fcb_xmit(ln, rn, tx_fb);

}

int chfcoe_match_xchg(chfcoe_xchg_cb_t *xchg, fc_header_t *fc_hdr)
{

	if ((xchg->ox_id != chfcoe_ntohs(fc_hdr->ox_id)))
		return CHFCOE_INVAL;

	if (xchg->sid != chfcoe_ntoh24(fc_hdr->d_id))
		return CHFCOE_INVAL;

	if (xchg->did != chfcoe_ntoh24(fc_hdr->s_id))
		return CHFCOE_INVAL;

	if ((chfcoe_ntohs(fc_hdr->rx_id) != PROTO_FC_XID_UNKNOWN) 
			&& (xchg->rx_id != chfcoe_ntohs(fc_hdr->rx_id)))
		return CHFCOE_INVAL;
	
	return CHFCOE_SUCCESS;
}


static chfcoe_xchg_cb_t *chfcoe_find_xchg(struct chfcoe_rnode *rn, fc_header_t *fc_hdr)
{
	chfcoe_xchg_cb_t *xchg = NULL;
	int xid = -1;
	
	while((xid = chfcoe_find_next_bit(rn->fc_xchg_bm, CHFCOE_MAX_XID,
					xid + 1)) < CHFCOE_MAX_XID) {
		xchg = CHFCOE_XID_TO_XCHG(rn, xid);

		if (xchg && (xchg->ox_id == chfcoe_ntohs(fc_hdr->ox_id))) {  
			if (chfcoe_match_xchg(xchg, fc_hdr) == CHFCOE_SUCCESS) {
				return xchg;
			}
		}			
	}
	chfcoe_dbg(ln, "ABTS recv oxid 0x%x rxid 0x%x xchg find failed nportid 0x%x\n",
			chfcoe_ntohs(fc_hdr->ox_id), chfcoe_ntohs(fc_hdr->rx_id), chfcoe_ntoh24(fc_hdr->s_id));
	return NULL; 
}

static void chfcoe_xchg_abts_handler(struct chfcoe_lnode *ln __attribute__ ((unused)),
		chfcoe_fc_buffer_t *rx_fb)
{
	fc_header_t *rx_fc_hdr;
	enum proto_fc_rctl rsp = PROTO_FC_RCTL_BA_RJT;
	uint16_t xid;
	chfcoe_xchg_cb_t *xchg = NULL;
	uint32_t f_ctl;
	struct chfcoe_rnode *rn = NULL;
	chfcoe_ioreq_t *tgtreq = NULL;
	uint8_t xchg_cbfn = 0;

	rx_fc_hdr = (fc_header_t *)chfcoe_fc_data_ptr(rx_fb);
	f_ctl = chfcoe_ntoh24(rx_fc_hdr->f_ctl); 
	
	rn = chfcoe_fc_rnode(rx_fb);	
	chfcoe_spin_lock(rn->lock);
	if (chfcoe_ntohs(rx_fc_hdr->rx_id) == PROTO_FC_XID_UNKNOWN) {
		xchg = chfcoe_find_xchg(rn, rx_fc_hdr);
	}
	else {	
		xid = (f_ctl & PROTO_FC_EX_CTX) ? chfcoe_ntohs(rx_fc_hdr->ox_id): chfcoe_ntohs(rx_fc_hdr->rx_id);

		if ((xid < CHFCOE_MAX_XID) && chfcoe_test_bit(xid, rn->fc_xchg_bm)) {
			xchg = CHFCOE_XID_TO_XCHG(rn, xid);

			if (chfcoe_match_xchg(xchg, rx_fc_hdr) != CHFCOE_SUCCESS) {
				chfcoe_err(ln, "ABTS recv oxid 0x%x rxid 0x%x xchg freed\n",
						chfcoe_ntohs(rx_fc_hdr->ox_id), chfcoe_ntohs(rx_fc_hdr->rx_id));
				xchg = NULL;
			}
			
		}
	}

	if (xchg) {

		if (chfcoe_test_and_set_bit(CHFCOE_XCHG_ST_ABORTED, &xchg->state)) {
			chfcoe_spin_unlock(rn->lock);
			rsp = PROTO_FC_RCTL_BA_RJT;
			chfcoe_err(ln, "ABTS recv oxid 0x%x rxid 0x%x xchg already aborted\n",
					chfcoe_ntohs(rx_fc_hdr->ox_id), chfcoe_ntohs(rx_fc_hdr->rx_id));
			goto post_rsp;
		}
		
		if (chfcoe_test_bit(CHFCOE_XCHG_ST_FCP, &xchg->state)) {
			tgtreq = xchg->cbarg; 
			if ((!tgtreq) || (!chfcoe_test_bit(CHFCOE_RNODE_ULP_READY, &rn->flags))) {
				chfcoe_spin_unlock(rn->lock);
				chfcoe_err(ln, "ABTS recv oxid 0x%x rxid 0x%x ioreq already aborted %p\n",
						chfcoe_ntohs(rx_fc_hdr->ox_id), chfcoe_ntohs(rx_fc_hdr->rx_id), tgtreq);
				rsp = PROTO_FC_RCTL_BA_RJT;
				goto post_rsp;
			}

			xchg->timeo = CHFCOE_XCHG_ERR_TIMEOUT1;

			if (xchg->cbfn) {
				xchg_cbfn = 1;
				chfcoe_atomic_inc(xchg->xchg_refcnt);
			}
		}

		rsp = PROTO_FC_RCTL_BA_ACC;
	}else {
		rsp = PROTO_FC_RCTL_BA_RJT;
	}
	chfcoe_spin_unlock(rn->lock);

post_rsp:
	if (rsp == PROTO_FC_RCTL_BA_ACC) {

		chfcoe_post_abts_rsp(rx_fb, rn,	PROTO_FC_RCTL_BA_ACC, 0, 0);
		if (xchg_cbfn) {
			xchg->cbfn(rx_fb, xchg->cbarg);	
			chfcoe_queue_delayed_work(chfcoe_workq, xchg->xchg_work, xchg->timeo);
		}

	}else {
		chfcoe_post_abts_rsp(rx_fb, rn,	PROTO_FC_RCTL_BA_ACC, 0, 0);
	}
}

static inline void 
chfcoe_xchg_bls_handler(struct chfcoe_lnode *ln, chfcoe_fc_buffer_t *fb)
{
	fc_header_t *fc_hdr = (fc_header_t *)chfcoe_fc_data_ptr(fb);
	uint32_t f_ctl;
	
	f_ctl = chfcoe_ntoh24(fc_hdr->f_ctl);

	if (!(f_ctl & PROTO_FC_SEQ_CTX)) { 
		switch(fc_hdr->r_ctl) {
		case PROTO_FC_RCTL_BA_ACC:
		case PROTO_FC_RCTL_BA_RJT:
			chfcoe_dbg(ln->adap, "received abort response\n");
			break;
		case PROTO_FC_RCTL_BA_ABTS:
			chfcoe_xchg_abts_handler(ln, fb);
			break;
		default:
			break;
		}
	}	
}

static inline void 
chfcoe_xchg_originator(struct chfcoe_lnode *ln, chfcoe_fc_buffer_t *fb)
{
	fc_header_t *fc_hdr = (fc_header_t *)chfcoe_fc_data_ptr(fb);
	chfcoe_xchg_cb_t *xchg = NULL;
	enum proto_fc_sof sof;
	struct chfcoe_rnode *rn = NULL;
	uint16_t xid;

	/* Get rnode pointer */
	chfcoe_read_lock(ln->rn_lock);
	rn = __chfcoe_rn_lookup_portid(ln, chfcoe_ntoh24(fc_hdr->s_id));

	if (chfcoe_likely(rn)) {
		chfcoe_atomic_inc(rn->refcnt);
	}
	else {
		chfcoe_read_unlock(ln->rn_lock);
		chfcoe_err(ln->adap, "rnode:0x%x lookup failed ox_id 0x%x rx_id 0x%x\n",
				chfcoe_ntoh24(fc_hdr->s_id), chfcoe_ntohs(fc_hdr->ox_id),
				chfcoe_ntohs(fc_hdr->rx_id));
		return;
	}	
	chfcoe_read_unlock(ln->rn_lock);

	xid = chfcoe_ntohs(fc_hdr->ox_id);

	if (chfcoe_likely((xid < CHFCOE_MAX_XID) && chfcoe_test_bit(xid, rn->fc_xchg_bm)))
		xchg = CHFCOE_XID_TO_XCHG(rn, xid);

	if (chfcoe_unlikely(!xchg)) {
		chfcoe_err(ln->adap, "rnode:0x%x xchg lookup failed ox_id 0x%x rx_id 0x%x\n",
				chfcoe_ntoh24(fc_hdr->s_id), chfcoe_ntohs(fc_hdr->ox_id),
				chfcoe_ntohs(fc_hdr->rx_id));
		goto out;
	}

	if (chfcoe_unlikely(chfcoe_test_bit(CHFCOE_XCHG_ST_ABORTED, &xchg->state)))
		goto out;

	if ((xchg->sid != 0) && (xchg->sid != chfcoe_ntoh24(fc_hdr->d_id)))
		goto out;

	if ((xchg->did != chfcoe_ntoh24(fc_hdr->s_id)) &&
			xchg->did != PROTO_FC_FID_FLOGI)
		goto out;
	
	if (xchg->rx_id == PROTO_FC_XID_UNKNOWN)
		xchg->rx_id = chfcoe_ntohs(fc_hdr->rx_id);
	else if (xchg->rx_id != chfcoe_ntohs(fc_hdr->ox_id))
		goto out;
	
	if (chfcoe_unlikely((xchg->ox_id != chfcoe_ntohs(fc_hdr->ox_id))))
		goto out;

	sof = chfcoe_fc_sof(fb);
	if (proto_fc_sof_is_init(sof)) {
		xchg->seq_id = fc_hdr->seq_id;
		xchg->seq_cnt = chfcoe_ntohs(fc_hdr->seq_cnt);
		chfcoe_set_bit(CHFCOE_XCHG_ST_FIRST_FRAME, &xchg->state);
	}
	else if ((xchg->seq_id != fc_hdr->seq_id) || (xchg->seq_cnt != chfcoe_ntohs(fc_hdr->seq_cnt))
			|| (!chfcoe_test_bit(CHFCOE_XCHG_ST_FIRST_FRAME, &xchg->state))) {
		chfcoe_err(ln->adap, "rnode:0x%x seq error fr_seq_id %u, fr_seq_cnt %u fr_oxid 0x%x fr_rxid 0x%x" 
				" xchg_seq_id %u xchg_seq_cnt %u\n",
				chfcoe_ntoh24(fc_hdr->s_id),
				fc_hdr->seq_id, chfcoe_ntohs(fc_hdr->seq_cnt),
				chfcoe_ntohs(fc_hdr->ox_id), chfcoe_ntohs(fc_hdr->rx_id),
				xchg->seq_id, xchg->seq_cnt);	       
		goto out;
	}
	
	xchg->seq_cnt++;

	if (xchg->cbfn)
		xchg->cbfn(fb, xchg->cbarg);
out:
	chfcoe_rnode_free(rn);
}

static inline void 
chfcoe_xchg_responder(struct chfcoe_lnode *ln, chfcoe_fc_buffer_t *fb)
{
	fc_header_t *fc_hdr = (fc_header_t *) chfcoe_fc_data_ptr(fb);
	chfcoe_xchg_cb_t *xchg = NULL;
        enum proto_fc_sof sof;
	uint16_t xid;
	struct chfcoe_rnode *rn = chfcoe_fc_rnode(fb);
	
	xid = chfcoe_ntohs(fc_hdr->rx_id);
	
	if (xid == PROTO_FC_XID_UNKNOWN) {
		switch (fc_hdr->type) {
		case PROTO_FC_TYPE_ELS:
			(fc4_handlers[PROTO_FC_TYPE_ELS])(ln, fb);
			return;
			break;
		case PROTO_FC_TYPE_FCP: 
			(fc4_handlers[PROTO_FC_TYPE_FCP])(ln, fb);
			return;
			break;
		default:
			chfcoe_err(ln->adap, "TYPE 0x%x not implemented\n", fc_hdr->type);
			return;
		}
	}
	

	if (chfcoe_likely((xid < CHFCOE_MAX_XID) && chfcoe_test_bit(xid, rn->fc_xchg_bm)))
		xchg = CHFCOE_XID_TO_XCHG(rn, xid);
	
	if (chfcoe_unlikely(!xchg)) {
		chfcoe_err(ln->adap, "rnode:0x%x xchg lookup failed ox_id 0x%x rx_id 0x%x\n",
				chfcoe_ntoh24(fc_hdr->s_id), chfcoe_ntohs(fc_hdr->ox_id),
				chfcoe_ntohs(fc_hdr->rx_id));
		goto out;
	}

	if (chfcoe_unlikely(chfcoe_test_bit(CHFCOE_XCHG_ST_ABORTED, &xchg->state)))
		goto out;

	if (chfcoe_unlikely(xchg->sid != chfcoe_ntoh24(fc_hdr->d_id)))
		goto out;

	if (chfcoe_unlikely((xchg->did != chfcoe_ntoh24(fc_hdr->s_id))))
		goto out;

	if (chfcoe_unlikely((xchg->ox_id != chfcoe_ntohs(fc_hdr->ox_id))))
		goto out;
	
	if (chfcoe_unlikely((xchg->rx_id != chfcoe_ntohs(fc_hdr->rx_id))))
		goto out;

	if (chfcoe_test_bit(CHFCOE_XCHG_ST_DDP, &xchg->state)) {
		if (chfcoe_likely(xchg->cbfn))
			xchg->cbfn(fb, xchg->cbarg);
		return;
	}
	
	sof = chfcoe_fc_sof(fb);
	if (proto_fc_sof_is_init(sof)) {
		xchg->seq_id = fc_hdr->seq_id;
		xchg->seq_cnt = chfcoe_ntohs(fc_hdr->seq_cnt);
		chfcoe_set_bit(CHFCOE_XCHG_ST_FIRST_FRAME, &xchg->state);
	}
	else if (chfcoe_unlikely((xchg->seq_id != fc_hdr->seq_id) || (xchg->seq_cnt != chfcoe_ntohs(fc_hdr->seq_cnt))
				|| (!chfcoe_test_bit(CHFCOE_XCHG_ST_FIRST_FRAME, &xchg->state)))) {
		chfcoe_err(ln->adap, "rnode:0x%x seq error fr_seq_id %u, fr_seq_cnt %u fr_oxid 0x%x fr_rxid 0x%x" 
				" xchg_seq_id %u xchg_seq_cnt %u\n",
				chfcoe_ntoh24(fc_hdr->s_id),
				fc_hdr->seq_id, chfcoe_ntohs(fc_hdr->seq_cnt),
				chfcoe_ntohs(fc_hdr->ox_id), chfcoe_ntohs(fc_hdr->rx_id),
				xchg->seq_id, xchg->seq_cnt);	       
		goto out;
	}
	
	xchg->seq_cnt++;
	
	if (chfcoe_likely(xchg->cbfn))
		xchg->cbfn(fb, xchg->cbarg);
out:
	return;
}

void chfcoe_xchg_recv(struct chfcoe_lnode *ln, chfcoe_fc_buffer_t *fb)
{
	fc_header_t *fc_hdr = (fc_header_t *) chfcoe_fc_data_ptr(fb);
	uint32_t f_ctl;
	
	f_ctl = chfcoe_ntoh24(fc_hdr->f_ctl);

	switch (chfcoe_fc_eof(fb)) {
	case PROTO_FC_EOF_T:
		if (f_ctl & PROTO_FC_END_SEQ)
		        chfcoe_fcb_trim_rx(fb, PROTO_FC_FILL(f_ctl));	
	case PROTO_FC_EOF_N:
		if (chfcoe_likely(!(f_ctl & PROTO_FC_SEQ_CTX))) {
			/* Frame sent by sequence Initiator */
			if (chfcoe_likely(fc_hdr->type != FC_TYPE_BLS))  {
				if (chfcoe_likely(!(f_ctl & PROTO_FC_EX_CTX)))
					/* Frame sent by Exchange originator and
					 * Sequense Initiator */
					chfcoe_xchg_responder(ln, fb);
				else
					/* Frame sent by Exchange Responder and
					 * Sequence Initiator */
					chfcoe_xchg_originator(ln, fb);
			}
			else
				/* Received basic link service */
				chfcoe_xchg_bls_handler(ln, fb);
			
			break;

		}
		/* Else fall through free buffer */

	default:
		chfcoe_err(ln->adap, "Frame EOF 0x%x f_ctl 0x%x\n", chfcoe_fc_eof(fb), f_ctl);
	}
}
