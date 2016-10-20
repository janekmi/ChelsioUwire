/*
 *  Copyright (C) 2015 Chelsio Communications.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef __CSIO_TARGET__
#include <chfcoe_adap.h>
#include <chfcoe_lnode.h>
#include <chfcoe_rnode.h>
#include <chfcoe_proto.h>
#include <chfcoe_xchg.h>
#include <chfcoe_io.h>
#include <csio_sal_api.h>
#include <chfcoe_ddp.h>

csio_sal_ops_t *sal_ops = NULL;

void *chfcoe_get_pdev(struct chfcoe_adap_info *adap); 
struct sk_buff;
void chfcoe_skb_destructor(struct sk_buff *skb);
void chfcoe_pkts_xmit(struct chfcoe_rnode *rn, chfcoe_fc_buffer_t *fb);

#ifdef __CSIO_DEBUG__
static inline void
chfcoe_tgt_dump_buffer(uint8_t *buf, uint32_t buf_len)
{
        uint32_t ii = 0;

        for (ii = 0; ii < buf_len ; ii++) {
                if(!(ii & 0xF))
                        csio_printk("\n0x%p:", (buf + ii));
                if(!(ii & 0x7))
                        csio_printk(" 0x%02x", buf[ii]);
                else
                        csio_printk("%02x", buf[ii]);
        }

        printk("\n");
}

static inline void
chfcoe_dump_fcp_cmd(struct chfcoe_adap_info *adap,struct csio_fcp_cmnd *fcp_cmd,
		  struct csio_tgtreq *tgtreq)
{
	chfcoe_vdbg(adap, "FCP cmd: %p\n", fcp_cmd);
	chfcoe_vdbg(adap, "\tlun: 0x%x%x%x%x%x%x%x%x cmdref:0x%x pri_ta:0x%x\n",
		    fcp_cmd->lun[0], fcp_cmd->lun[1], fcp_cmd->lun[2],
		    fcp_cmd->lun[3], fcp_cmd->lun[4], fcp_cmd->lun[5],
		    fcp_cmd->lun[6], fcp_cmd->lun[7], fcp_cmd->cmdref,
		    fcp_cmd->pri_ta);
	chfcoe_vdbg(adap, "req:%p flowc:0x%x tm_flags:0x%x dl:0x%x cdb:%x\n",
		 tgtreq, tgtreq->req_flowid, fcp_cmd->tm_flags,
		 csio_be32_to_cpu(fcp_cmd->dl), fcp_cmd->cdb[0]);

	chfcoe_vdbg(adap,"\tcdb: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",
		    fcp_cmd->cdb[0], fcp_cmd->cdb[1], fcp_cmd->cdb[2],
		    fcp_cmd->cdb[3], fcp_cmd->cdb[4], fcp_cmd->cdb[5],
		    fcp_cmd->cdb[6], fcp_cmd->cdb[7], fcp_cmd->cdb[8],
		    fcp_cmd->cdb[9], fcp_cmd->cdb[10], fcp_cmd->cdb[11],
		    fcp_cmd->cdb[12], fcp_cmd->cdb[13], fcp_cmd->cdb[14],
		    fcp_cmd->cdb[15]);
}

#define CHFCOE_TGT_DUMP_BUF(__buf, __len) chfcoe_tgt_dump_buffer((__buf), (__len))
#else
#define CHFCOE_TGT_DUMP_BUF(__buf, __len)
#define chfcoe_dump_fcp_cmd(__h, __c, __t)
#endif

/* Should be called only for initiator rnodes */
chfcoe_retval_t
chfcoe_tgt_register_session(struct chfcoe_rnode *rn)
{
	csio_sal_reg_params_t params;
	struct chfcoe_lnode *ln = rn->lnode;

	if (rn->ssn_hdl) {
		chfcoe_dbg(adap, "Attempt to register a pre-registered rnode"
				":%p, Ignoring for now...\n", rn);
		return CHFCOE_SUCCESS;
	}

	if (!sal_ops) {
		chfcoe_err(adap, "register session failed: invalid sal_ops\n");
		return CHFCOE_NOSUPP;
	}	

	if (!ln->tgt_hdl) {
		chfcoe_err(adap, "register session failed: invalid target "
				"handle\n");
		return CHFCOE_INVAL;
	}	

	params.prot = CSIO_SAL_PROT_FCOE;
	chfcoe_memcpy(params.un.fcoe_params.wwpn, rn->wwpn, 8); 
	chfcoe_memcpy(params.un.fcoe_params.wwnn, rn->wwnn, 8);

	params.priv = (void *)rn;

	rn->ssn_hdl = sal_ops->sal_reg_ssn(ln->tgt_hdl, &params);

	if (rn->ssn_hdl == NULL) {
		chfcoe_err(adap, "sal register session failed\n");
		return CHFCOE_INVAL;
	}	

	return CHFCOE_SUCCESS;
}

void
chfcoe_tgt_unregister_session(struct chfcoe_rnode *rn)
{
	csio_ssn_handle_t ssn_hdl;

	if (!sal_ops)
		return;
	if (rn->ssn_hdl) {
		ssn_hdl = rn->ssn_hdl;
		rn->ssn_hdl = NULL;
		sal_ops->sal_unreg_ssn(ssn_hdl);
	}

}

void chfcoe_rnode_free_work(void *data)
{
	struct chfcoe_rnode *rnode = data;

	if (!chfcoe_list_empty(&rnode->ioreq_activeq)) {
		chfcoe_err(pi, "rnode free active reqs rnode:0x%x\n", rnode->nport_id);
		chfcoe_queue_delayed_work(chfcoe_workq,
			       	rnode->rnode_free_work, 10000);
		return;
	}

	chfcoe_info(pi, "rnode destroyed rnode nportid 0x%x\n", rnode->nport_id);
	chfcoe_rnode_free(rnode);
}

void chfcoe_sal_sess_unreg_done(void *data)
{
	struct chfcoe_rnode *rnode = data;

	chfcoe_dbg(pi, "unreg session cb 0x%x %p\n", rnode->nport_id, rnode);
	chfcoe_queue_delayed_work(chfcoe_workq, rnode->rnode_free_work, 0);

}

chfcoe_retval_t
chfcoe_tgt_register(struct chfcoe_lnode *ln)
{
	csio_sal_lport_params_t params;

	if (!sal_ops) {
		chfcoe_err(ln, "register target failed: invalid sal_ops\n");
		return CHFCOE_NOSUPP;
	}	

	chfcoe_memcpy(params.un.fcoe_params.wwpn, ln->wwpn, 8);
	chfcoe_memcpy(params.un.fcoe_params.wwnn, ln->wwnn, 8);

	ln->tgt_hdl = sal_ops->sal_reg_tgt(&params);

	if (ln->tgt_hdl == NULL) {
		chfcoe_err(ln, "sal register target failed\n");
		return CHFCOE_INVAL;
	}

	return CHFCOE_SUCCESS;
}

void
chfcoe_tgt_unregister(struct chfcoe_lnode *ln)
{
	if (!sal_ops)
		return;

	if (ln->tgt_hdl) {
		sal_ops->sal_unreg_tgt(ln->tgt_hdl);
	}

	ln->tgt_hdl = NULL;
}

void chfcoe_tgt_tm_close_rn_reqs(struct chfcoe_rnode *rn,
		uint64_t lun, uint8_t match_lun)
{
	struct chfcoe_list *tmp;
	chfcoe_ioreq_t *tgtreq;
        chfcoe_xchg_cb_t *xchg;

	chfcoe_spin_lock(rn->lock);
	chfcoe_list_for_each(tmp, &rn->ioreq_activeq) {
		tgtreq = (chfcoe_ioreq_t *) tmp;
		if (match_lun && (tgtreq->lun != lun))
			continue;
		
		xchg = tgtreq->xchg;
		if (!chfcoe_test_and_set_bit(CHFCOE_XCHG_ST_ABORTED, &xchg->state)) {
			xchg->timeo =  CHFCOE_XCHG_ERR_TIMEOUT1;
			chfcoe_set_bit(CHFCOE_XCHG_ST_ABORTED, &xchg->state);
			chfcoe_xchg_timer_sched(xchg);
		}
	}
	chfcoe_spin_unlock(rn->lock);
}


static void
chfcoe_tgt_tm_close_ln_reqs(chfcoe_ioreq_t *tgtreq, uint8_t match_lun)
{
	chfcoe_xchg_cb_t *xchg = tgtreq->xchg;
	struct chfcoe_lnode *ln = xchg->ln;
	struct chfcoe_list *tmp;
	struct chfcoe_rnode *rn;

	chfcoe_read_lock_bh(ln->rn_lock);
	/* Close I/Os on all initiators under lnode/target */
	chfcoe_list_for_each(tmp, &ln->rn_head) {
		rn = (struct chfcoe_rnode *)tmp;
		if (rn->ssn_hdl)
			chfcoe_tgt_tm_close_rn_reqs(rn, tgtreq->lun, match_lun);
	}
	chfcoe_read_unlock_bh(ln->rn_lock);
}

static inline int
chfcoe_tgt_issue_tm_rsp(chfcoe_ioreq_t *tgtreq, csio_tm_st_t tm_status)
{
	chfcoe_fc_buffer_t *fb;
	chfcoe_xchg_cb_t *xchg = tgtreq->xchg;
	struct chfcoe_lnode *ln = xchg->ln;
	struct proto_fcp_tmresp *fcp_resp;
	size_t rsp_len = sizeof(struct proto_fcp_tmresp);    /* normally upto fcp_resp->rsp_len */
	int i = 0;

	chfcoe_xchg_rst_seq(xchg);
	fb = chfcoe_fc_buffer_alloc(rsp_len, CHFCOE_ATOMIC);

	if (!fb) {
		for (i = 0; i < 5; i++) {
			fb = chfcoe_fc_buffer_alloc(rsp_len, CHFCOE_NOATOMIC);
			if (fb) {
				break;
			}
		}
		if (!fb) {
			chfcoe_err(ln, "Failed to alloc fc buffer\n");
			return CHFCOE_RETRY;
		}
	}

	fcp_resp = proto_fc_frame_payload_get(fb, rsp_len);
	chfcoe_memset(fcp_resp, 0, rsp_len);
	fcp_resp->flags |= PROTO_FCP_RSP_LEN_VAL;
	fcp_resp->rsp_len = chfcoe_cpu_to_be32(8);
	
	switch (tm_status) {
		case CSIO_SAL_TM_ST_SUCCESS:
			fcp_resp->rsp_code = PROTO_FCP_TMF_CMPL;
			break;
		case CSIO_SAL_TM_ST_INVALID_LUN:
			fcp_resp->rsp_code = PROTO_FCP_TMF_INVALID_LUN;
			break;
		case CSIO_SAL_TM_ST_FAILED:
			fcp_resp->rsp_code = PROTO_FCP_TMF_FAILED;
			break;
		default:
			fcp_resp->rsp_code = PROTO_FCP_TMF_REJECTED;
	}

	proto_fc_fill_fc_hdr(chfcoe_fc_hdr(fb), PROTO_FC_RCTL_DD_CMD_STATUS, xchg->did, xchg->sid,
			PROTO_FC_TYPE_FCP,
			PROTO_FC_EX_CTX | PROTO_FC_LAST_SEQ | PROTO_FC_END_SEQ,
			0);
	
	if (chfcoe_test_bit(CHFCOE_XCHG_ST_ABORTED, &xchg->state)) {
		chfcoe_fcb_free(fb);
		return CHFCOE_CANCELLED;
	}

	chfcoe_xchg_send(ln, xchg->rn, fb, xchg);
	
	chfcoe_err(adap, "req %p TM op %d done,status: 0x%x rsp sent \n", tgtreq,
			tgtreq->sreq.tm_op, tm_status);

	return CHFCOE_SUCCESS;
}

void chfcoe_err_work_fn_data(void *data)
{
	chfcoe_ioreq_t *tgtreq = (chfcoe_ioreq_t *)data;
	chfcoe_xchg_cb_t *xchg = tgtreq->xchg;
	struct chfcoe_lnode *ln = xchg->ln;
	struct chfcoe_rnode *rn = xchg->rn;
	struct chfcoe_port_info *pi = ln->pi;
	csio_cmd_handle_t cmd;

	chfcoe_dbg(ln, "ioreq err work fn called tgtreq %p state:%u lun:%llu "
		"req_len:%u xfrd_len:%u max_xfer_len:%u data_dir:%u\n",
		tgtreq, tgtreq->state, tgtreq->lun, tgtreq->req_len,
		tgtreq->xfrd_len, tgtreq->max_xfer_len, 
		tgtreq->sreq.data_direction);
	
	if (chfcoe_test_bit(CHFCOE_XCHG_ST_ERR_TIMEOUT1, &xchg->state)) {
		chfcoe_spin_lock(rn->lock);
		if (chfcoe_likely(chfcoe_atomic_dec_and_test(xchg->xchg_refcnt))) {
			chfcoe_deq_elem(tgtreq);
			__chfcoe_free_xchg(xchg);
		}
		chfcoe_spin_unlock(rn->lock);
	}else {
		if (tgtreq->sreq.data_direction == CHFCOE_CMD_DATA_WRITE) {
			if (chfcoe_test_and_clear_bit(CHFCOE_XCHG_ST_DDP, &xchg->state))
				chfcoe_ddp_done(pi, tgtreq);
			
			chfcoe_mutex_lock(xchg->xchg_mutex);
			if (chfcoe_test_bit(CHFCOE_XCHG_ST_W_XFER, &xchg->state)) {
				chfcoe_dbg(ln, "ioreq err work fn ABORTING WRITE %p\n", tgtreq);
				chfcoe_clear_bit(CHFCOE_XCHG_ST_FIRST_FRAME, &xchg->state);
				chfcoe_clear_bit(CHFCOE_XCHG_ST_W_XFER, &xchg->state);
				tgtreq->sreq.req_status = CSIO_DRV_ST_FAILED;
				cmd = chfcoe_tgt_get_sal_ref(tgtreq);
				chfcoe_mutex_unlock(xchg->xchg_mutex);
				sal_ops->sal_rcv_data(cmd, tgtreq->sreq.req_status);
			} else {
				chfcoe_mutex_unlock(xchg->xchg_mutex);
			}
		}
		chfcoe_set_bit(CHFCOE_XCHG_ST_ERR_TIMEOUT1, &xchg->state);
		xchg->timeo = CHFCOE_XCHG_ERR_TIMEOUT2;
		chfcoe_queue_delayed_work(chfcoe_workq, xchg->xchg_work, xchg->timeo);
	}
}

/*
 * chfcoe_sal_free: Indication that SCSI server has freed this I/O.
 * @sreq: The SAL request
 * @cmd: The SCSI server's command.
 *
 * SAL API indicating I/O request is free at the SCSI server.
 */

void
chfcoe_sal_free(csio_sal_req_t *sreq)
{
	chfcoe_ioreq_t *tgtreq = (chfcoe_ioreq_t *)sreq->drv_req;
	chfcoe_xchg_cb_t *xchg = tgtreq->xchg;
	struct chfcoe_rnode *rn = xchg->rn;

	chfcoe_spin_lock(rn->lock);
	if (chfcoe_likely(chfcoe_atomic_dec_and_test(xchg->xchg_refcnt))) {
		chfcoe_deq_elem(tgtreq);
		__chfcoe_free_xchg(xchg);
	}
	chfcoe_spin_unlock(rn->lock);
}

void
chfcoe_sal_tm_done(csio_sal_req_t *sreq, csio_tm_st_t tm_status,
		csio_cmd_handle_t mcmd __attribute__((unused)))
{
	chfcoe_ioreq_t *tgtreq = (chfcoe_ioreq_t *)sreq->drv_req;

	chfcoe_err(adap, "req %p TM op %d done,status: 0x%x\n", tgtreq,
			tgtreq->sreq.tm_op, tm_status);

	chfcoe_tgt_issue_tm_rsp(tgtreq, tm_status);

	chfcoe_sal_free(&tgtreq->sreq);
}


static inline void chfcoe_init_rsp(chfcoe_ioreq_t *tgtreq, struct proto_fcp_resp *fcp_resp,
		uint16_t sense_buffer_len)
{
	chfcoe_xchg_cb_t *xchg = tgtreq->xchg;
        uint32_t dl;
	
	dl = tgtreq->req_len - tgtreq->xfrd_len;
	if (dl) {
		fcp_resp->flags |= PROTO_FCP_RESID_UNDER;
		fcp_resp->resid = chfcoe_cpu_to_be32(dl);
	}

	if (tgtreq->sreq.scsi_status) {
		fcp_resp->scsi_status = tgtreq->sreq.scsi_status;
		CHFCOE_INC_STATS(xchg->ln, n_err_sal_rsp);
	}

	if (sense_buffer_len > 0) {
		/* 
		 * Copy sense data into rsvd1, instead of sns_data, since we
		 * dont include response code.
		 */
		chfcoe_memcpy(&fcp_resp->rsvd1, tgtreq->sreq.sense_buffer, sense_buffer_len);
		fcp_resp->flags |= PROTO_FCP_SNS_LEN_VAL;
		fcp_resp->sns_len = chfcoe_cpu_to_be32(sense_buffer_len);
	}
}

csio_tret_t
chfcoe_sal_rsp(csio_sal_req_t *sreq)
{
	chfcoe_ioreq_t *tgtreq = (chfcoe_ioreq_t *)sreq->drv_req;
	chfcoe_fc_buffer_t *fb = NULL;
        size_t rsp_len = 24; 	/* normally upto fcp_resp->rsp_len */
	uint8_t state;
	uint16_t sense_buffer_len = 0;
	chfcoe_xchg_cb_t *xchg = tgtreq->xchg;
	struct chfcoe_lnode *ln = xchg->ln;
	fc_header_t *fc_hdr = NULL;
	
	if (chfcoe_unlikely(chfcoe_test_bit(CHFCOE_XCHG_ST_ABORTED, &xchg->state)))
		return CSIO_TINVAL;

	state = chfcoe_ioreq_get_state(tgtreq);
	chfcoe_ioreq_set_state(tgtreq, CHFCOE_IO_ST_RSP_SENT);
	chfcoe_xchg_next_seq(xchg);

	if ((tgtreq->sreq.sense_buffer != NULL) && 
			(tgtreq->sreq.sense_buffer_len > 0)) {

		sense_buffer_len = tgtreq->sreq.sense_buffer_len > 128 ?
			128 : tgtreq->sreq.sense_buffer_len;

		rsp_len += sense_buffer_len;
	}

	fb = chfcoe_fc_buffer_alloc(rsp_len, CHFCOE_ATOMIC);
	if (chfcoe_unlikely(!fb)) {
		chfcoe_err(ln, "Failed to alloc fc buffer\n");
		for (;;) {
			fb = chfcoe_fc_buffer_alloc(rsp_len, CHFCOE_NOATOMIC);
			if (!fb)
				chfcoe_schedule();
			else {
				break;
			}
		}
	}	

#ifdef __CHFCOE_SCSI_PERF__
	
	if (tgtreq->sreq.data_direction == CHFCOE_CMD_DATA_READ) {
		atomic64_inc(&pi->stats.reads);
		atomic64_add(tgtreq->xfrd_len, &pi->stats.rbytes);
	}else if (tgtreq->sreq.data_direction == CHFCOE_CMD_DATA_WRITE) {
		atomic64_inc(&pi->stats.writes);
		atomic64_add(tgtreq->xfrd_len, &pi->stats.wbytes);
	}
#endif
	fc_hdr = chfcoe_fc_hdr(fb);

	chfcoe_init_rsp(tgtreq, (struct proto_fcp_resp *)(fc_hdr + 1), sense_buffer_len);
	
	proto_fc_fill_fc_hdr(fc_hdr, PROTO_FC_RCTL_DD_CMD_STATUS, xchg->did, xchg->sid,
		PROTO_FC_TYPE_FCP,
		PROTO_FC_EX_CTX | PROTO_FC_LAST_SEQ | PROTO_FC_END_SEQ,
		0);

	chfcoe_xchg_send(ln, xchg->rn, fb, xchg);
	
	chfcoe_tgtreq_cleanup(tgtreq);
	
	return CSIO_TSUCCESS;
}

csio_tret_t
chfcoe_sal_acc(csio_sal_req_t *sreq)
{
	chfcoe_ioreq_t *tgtreq = (chfcoe_ioreq_t *)sreq->drv_req;
	chfcoe_fc_buffer_t *fb = NULL;
	struct proto_fcp_xfer_rdy *fcp_xfer_rdy;
	chfcoe_xchg_cb_t *xchg = tgtreq->xchg;
	struct chfcoe_lnode *ln = xchg->ln;
	struct chfcoe_port_info *pi = ln->pi;
	int tag;
	
	if (chfcoe_unlikely(chfcoe_test_bit(CHFCOE_XCHG_ST_ABORTED, &xchg->state)))
		return CSIO_TINVAL;

	chfcoe_xchg_rst_seq(xchg);

	fb = chfcoe_fc_buffer_alloc(sizeof(struct proto_fcp_xfer_rdy), CHFCOE_ATOMIC);

	if (chfcoe_unlikely(!fb)) {
		fb = chfcoe_fc_buffer_alloc(sizeof(struct proto_fcp_xfer_rdy), CHFCOE_NOATOMIC);
		if (!fb) {
			chfcoe_err(ln, "Failed to alloc fc buffer\n");
			return CSIO_TINVAL;
		}
	}

	fcp_xfer_rdy = proto_fc_frame_payload_get(fb, sizeof(struct proto_fcp_xfer_rdy));
	chfcoe_memset(fcp_xfer_rdy, 0, sizeof(struct proto_fcp_xfer_rdy));

	fcp_xfer_rdy->data_ro = 0; 
	fcp_xfer_rdy->burst_len = chfcoe_htonl(sreq->buff_len);

	proto_fc_fill_fc_hdr(chfcoe_fc_hdr(fb), PROTO_FC_RCTL_DD_DATA_DESC, xchg->did, xchg->sid,
			PROTO_FC_TYPE_FCP,
			PROTO_FC_EX_CTX | PROTO_FC_END_SEQ | PROTO_FC_SEQ_INIT,
			0);
	
	if (sreq->nsge_map > 0) {
		if ((tag = chfcoe_ddp_setup(pi, tgtreq, fb)) >= 0) {
			chfcoe_set_bit(CHFCOE_XCHG_ST_DDP, &xchg->state);
		}else {
		}
	}

	chfcoe_mutex_lock(xchg->xchg_mutex);
	if (chfcoe_unlikely(chfcoe_test_bit(CHFCOE_XCHG_ST_ABORTED, &xchg->state))) {
		chfcoe_mutex_unlock(xchg->xchg_mutex);
		chfcoe_fcb_free(fb);
		return CSIO_TINVAL;
	}
	chfcoe_ioreq_set_state(tgtreq, CHFCOE_IO_ST_DATA_XFER);
	chfcoe_set_bit(CHFCOE_XCHG_ST_W_XFER, &xchg->state);
	chfcoe_mutex_unlock(xchg->xchg_mutex);

	chfcoe_xchg_send(ln, xchg->rn, fb, xchg);
	
	chfcoe_atomic_inc(ln->stats.n_xfer_rdy);
	return CSIO_TSUCCESS;	
}

static inline int split_read_queue(struct chfcoe_port_info *pi,                          
               uint32_t data_len)
{
	struct chfcoe_adap_info *adap = pi->adap;
	int qidx, qhalf;

	if (data_len >= (uint32_t)adap->ddp_thres) {
		qidx = chfcoe_smp_id() % pi->nqsets;
		qhalf = pi->nqsets / 2;
		qidx = (qidx > qhalf) ? qidx : qidx + qhalf;
	} else
		qidx = chfcoe_smp_id();

	return qidx;
}

csio_tret_t
chfcoe_sal_xmit(csio_sal_req_t *sreq)
{
	chfcoe_ioreq_t *tgtreq = (chfcoe_ioreq_t *)sreq->drv_req;
	chfcoe_xchg_cb_t *xchg = tgtreq->xchg;
	struct chfcoe_lnode *ln = xchg->ln;
	struct chfcoe_rnode *rn = xchg->rn;
	uint32_t rem = 0, fr_len = 0, sg_len = 0, xfer_len = 0, frame_off = 0, page_dma_len = 0;
	chfcoe_dma_addr_t dma_addr, page_dma_addr;
	uint16_t sense_buffer_len = 0;
	uint16_t fill_bytes[2] = {0, 0};
	fc_header_t *fc_hdr[2] = {NULL, NULL};
	void *sgel = NULL;
	chfcoe_fc_buffer_t *fb = NULL;

	if (chfcoe_unlikely(chfcoe_test_bit(CHFCOE_XCHG_ST_ABORTED, &xchg->state)))
		return CSIO_TINVAL;

	chfcoe_ioreq_set_state(tgtreq, CHFCOE_IO_ST_DATA_XFER);
	rem = sreq->data_len;
	sgel = tgtreq->sreq.os_sge;
	page_dma_len = chfcoe_sg_len(sgel);
	sg_len = page_dma_len;
	
	while(chfcoe_unlikely(chfcoe_pci_map_page(tgtreq->sreq.os_dev, sgel, &page_dma_addr)))
				chfcoe_schedule();
	
	dma_addr = page_dma_addr;
	chfcoe_xchg_rst_seq(xchg);
	tgtreq->txq = split_read_queue(ln->pi, rem);
	fr_len = tgtreq->max_xfer_len;

	while (rem) {
		if (!sg_len) {
			sgel = chfcoe_sg_next(sgel);
			page_dma_len = chfcoe_sg_len(sgel);
			sg_len = page_dma_len;
			
			while(chfcoe_unlikely(chfcoe_pci_map_page(tgtreq->sreq.os_dev, sgel, &page_dma_addr)))
				chfcoe_schedule();
			dma_addr = page_dma_addr;
		}

		xfer_len = CHFCOE_MIN(fr_len, rem);
		xfer_len = CHFCOE_MIN(xfer_len, sg_len);

		rem -= xfer_len;
		sg_len -= xfer_len;
		tgtreq->xfrd_len += xfer_len;

		if (rem) {
			fb = chfcoe_fc_buffer_alloc(0, CHFCOE_ATOMIC);
			if (chfcoe_unlikely(!fb)) {
				chfcoe_err(ln, "Failed to alloc fc buffer\n");
				for (;;) {
					fb = chfcoe_fc_buffer_alloc(0, CHFCOE_NOATOMIC);
					if (!fb)
						chfcoe_schedule();
					else {
						break;
					}
				}
			}

			chfcoe_fc_dma_addr(fb) = dma_addr;
			chfcoe_fc_dma_len(fb) = xfer_len;
			chfcoe_fc_txq(fb) = tgtreq->txq;

			proto_fc_fill_fc_hdr(chfcoe_fc_hdr(fb), PROTO_FC_RCTL_DD_SOL_DATA, xchg->did, 
					xchg->sid,
					PROTO_FC_TYPE_FCP,
					(PROTO_FC_EX_CTX | PROTO_FC_REL_OFF), frame_off);

			if (!sg_len) {
				chfcoe_fc_pdev(fb) = tgtreq->sreq.os_dev;
				chfcoe_fc_sg_page(fb) = chfcoe_sg_page(sgel);
				chfcoe_fc_page_dma_addr(fb) = page_dma_addr;
				chfcoe_fc_page_dma_len(fb) = page_dma_len;
				chfcoe_fc_dtr(fb, chfcoe_skb_destructor);
			}

			chfcoe_xchg_send(ln, xchg->rn, fb, xchg);
		}else {
			if ((tgtreq->sreq.sense_buffer != NULL) && 
					(tgtreq->sreq.sense_buffer_len > 0)) {

				sense_buffer_len = tgtreq->sreq.sense_buffer_len > 128 ?
					128 : tgtreq->sreq.sense_buffer_len;
			}

			fill_bytes[0] = xfer_len % 4;
			if (fill_bytes[0]) {
				fill_bytes[0] = 4 - fill_bytes[0];
			}

			fill_bytes[1] = (24 + sense_buffer_len) % 4;
			if (fill_bytes[1]) {
				fill_bytes[1] = 4 - fill_bytes[1];
			}

			fb = chfcoe_fc_buffer_alloc_pkts(fill_bytes, fc_hdr, sense_buffer_len);

			proto_fc_fill_fc_hdr(fc_hdr[0], PROTO_FC_RCTL_DD_SOL_DATA, xchg->did, 
					xchg->sid,
					PROTO_FC_TYPE_FCP,
					(PROTO_FC_EX_CTX | PROTO_FC_REL_OFF |
					 PROTO_FC_END_SEQ), frame_off);

			fc_hdr[0]->ox_id = chfcoe_htons(xchg->ox_id);
			fc_hdr[0]->rx_id = chfcoe_htons(xchg->rx_id); 
			fc_hdr[0]->seq_cnt = chfcoe_htons(xchg->seq_cnt);
			fc_hdr[0]->seq_id = xchg->seq_id;
			fc_hdr[0]->f_ctl[2] |= ((fill_bytes[0]) & 0x3);


			chfcoe_init_rsp(tgtreq, (struct proto_fcp_resp *)(fc_hdr[1] + 1), sense_buffer_len);

			proto_fc_fill_fc_hdr(fc_hdr[1], PROTO_FC_RCTL_DD_CMD_STATUS, xchg->did, xchg->sid,
					PROTO_FC_TYPE_FCP,
					PROTO_FC_EX_CTX | PROTO_FC_LAST_SEQ | PROTO_FC_END_SEQ,
					0);

			fc_hdr[1]->ox_id = chfcoe_htons(xchg->ox_id);
			fc_hdr[1]->rx_id = chfcoe_htons(xchg->rx_id); 
			fc_hdr[1]->seq_cnt = chfcoe_htons(0);
			fc_hdr[1]->seq_id = 1;
			fc_hdr[1]->f_ctl[2] |= ((fill_bytes[1]) & 0x3);

			chfcoe_fc_dma_addr(fb) = dma_addr;
			chfcoe_fc_dma_len(fb) = xfer_len;
			chfcoe_fc_txq(fb) = tgtreq->txq;	

			chfcoe_fc_pdev(fb) = tgtreq->sreq.os_dev;
			chfcoe_fc_sg_page(fb) = chfcoe_sg_page(sgel);
			chfcoe_fc_page_dma_addr(fb) = page_dma_addr;
			chfcoe_fc_page_dma_len(fb) = page_dma_len;
			chfcoe_fc_dtr(fb, chfcoe_skb_destructor);
			
			chfcoe_pkts_xmit(rn, fb);

			chfcoe_tgtreq_cleanup(tgtreq);

			break;
		}

		frame_off += xfer_len;

		if (sg_len)
			dma_addr += xfer_len;
	}

	return CSIO_TSUCCESS;
}

csio_tret_t
chfcoe_sal_get_param(csio_sal_param_type_t ptype, csio_sal_params_t *params)
{
	struct chfcoe_rnode *rn = NULL;
	csio_tret_t ret = CSIO_TNOSUPP;

	switch (ptype) {
	case CSIO_SAL_SESSION_PARAM:
		rn = params->cmdhdr.dev_handle;
		if (rn) {
			params->prot = CSIO_SAL_PROT_FCOE;
			chfcoe_memcpy(params->un.fcoe_params.wwpn, rn->wwpn, 8);
			chfcoe_memcpy(params->un.fcoe_params.wwnn, rn->wwnn, 8);
			ret = CSIO_TSUCCESS;
		}
		break;
	default:
		ret = CSIO_TNOSUPP;
	}
	return ret;
}

/* initialize protocol ops */
csio_proto_ops_t sal_proto_ops = {
	.sal_target_add= NULL,
	.sal_target_remove = NULL,
	.sal_target_enable = NULL,
	.sal_set_param = NULL,
	.sal_get_param = chfcoe_sal_get_param,
	.sal_control_send = NULL,
	.sal_xmit = chfcoe_sal_xmit,
	.sal_rsp = chfcoe_sal_rsp,
	.sal_acc = chfcoe_sal_acc,
	.sal_tm_done = chfcoe_sal_tm_done,
	.sal_free = chfcoe_sal_free,
	.sal_sess_unreg_done = chfcoe_sal_sess_unreg_done,
};

static void
chfcoe_free_err_tgtreq(chfcoe_ioreq_t *tgtreq)
{
	chfcoe_xchg_cb_t *xchg = tgtreq->xchg;
	chfcoe_put_xchg(xchg);
}


static inline void
chfcoe_tgt_start_tm(struct chfcoe_ioreq *tgtreq,
		csio_sal_cmd_t *scmd)
{
	csio_tret_t ret;
	csio_cmd_handle_t cmd;
	chfcoe_xchg_cb_t *xchg = tgtreq->xchg;
	struct chfcoe_rnode *rn = xchg->rn;

	chfcoe_spin_lock(rn->lock);
	chfcoe_enq_at_tail(&rn->ioreq_activeq, &tgtreq->list);
	chfcoe_spin_unlock(rn->lock);
	
	chfcoe_ioreq_set_state(tgtreq, CHFCOE_IO_ST_SAL_TM_SENT);
	ret = sal_ops->sal_rcv_tm(rn->ssn_hdl, scmd, &cmd);
	if (ret != CSIO_TSUCCESS) {
		chfcoe_err(adap, "sal_rcv_tm failed\n");
		chfcoe_sal_free(&tgtreq->sreq);
		return;
	}
	
}

/* Hand off command to SAL - called int softirq context */
static inline void
chfcoe_tgt_start_cmd(chfcoe_ioreq_t *tgtreq, csio_sal_cmd_t *scmd)
{
	csio_cmd_handle_t cmd;
	chfcoe_xchg_cb_t *xchg = tgtreq->xchg;
	struct chfcoe_rnode *rn = xchg->rn;
	cmd = sal_ops->sal_rcv_cmd(rn->ssn_hdl, scmd);

	if (chfcoe_unlikely(cmd == NULL)) {
		chfcoe_err(adap, "sal_rvd_cmd failed\n");
		chfcoe_free_err_tgtreq(tgtreq);
		return;
	}
	chfcoe_tgt_set_sal_ref(tgtreq, cmd);
	chfcoe_ioreq_set_state(tgtreq, CHFCOE_IO_ST_SAL_CMD_SENT);

	chfcoe_spin_lock(rn->lock);
	chfcoe_enq_at_tail(&rn->ioreq_activeq, &tgtreq->list);
	chfcoe_spin_unlock(rn->lock);

	sal_ops->sal_start_cmd(cmd);
}

static inline uint32_t 
chfcoe_copy_buffer_to_sglist(void *buf, uint32_t len,
		void *sg, uint32_t *nents,
		uint32_t *offset)
{
	uint32_t rem = len;
	uint32_t copy_len = 0;
	uint32_t off, sg_bytes;
	void *page_addr;

	while((rem > 0) && sg) {
		if (*offset >= chfcoe_sg_len(sg)) {
			if(!(*nents))
				break;
			--(*nents);
			*offset -= chfcoe_sg_len(sg);
			sg = chfcoe_sg_next(sg);
			continue;
		}

		sg_bytes = CHFCOE_MIN(rem, chfcoe_sg_len(sg) - *offset);
		off = *offset + chfcoe_sg_offset(sg);
		sg_bytes = CHFCOE_MIN(sg_bytes, (uint32_t)(os_page_size - (off & ~os_page_mask)));
		page_addr = chfcoe_kmap((char *)chfcoe_sg_page(sg) +
				(os_structpage_size * (off >> os_page_shift)));

		chfcoe_memcpy((char *)page_addr + (off & ~os_page_mask), buf, sg_bytes);
		chfcoe_kunmap(page_addr);
		buf = (char *)buf + sg_bytes;
		*offset += sg_bytes;
		rem -= sg_bytes;
		copy_len += sg_bytes;

	}

	return copy_len;
}

static inline void chfcoe_tgt_fcp_ddp_handler(chfcoe_ioreq_t *tgtreq)
{
	chfcoe_xchg_cb_t *xchg = tgtreq->xchg;
	struct chfcoe_lnode *lnode = xchg->ln;
	struct chfcoe_port_info *pi = lnode->pi;
	csio_cmd_handle_t cmd;

	chfcoe_clear_bit(CHFCOE_XCHG_ST_W_XFER, &xchg->state);
	chfcoe_ioreq_set_state(tgtreq, CHFCOE_IO_ST_SAL_DATA_SENT);
	tgtreq->sreq.req_status = CSIO_DRV_ST_SUCCESS;
	cmd = chfcoe_tgt_get_sal_ref(tgtreq);

	chfcoe_atomic_inc(lnode->stats.n_ddp_data);
	chfcoe_mutex_unlock(xchg->xchg_mutex);

	if (chfcoe_test_and_clear_bit(CHFCOE_XCHG_ST_DDP, &xchg->state))
		chfcoe_ddp_done(pi, tgtreq);

	sal_ops->sal_rcv_data(cmd, tgtreq->sreq.req_status);

	return;
}

/* FCP handler for solicited FCP_DATA */
static inline void
chfcoe_tgt_fcp_data_handler(chfcoe_fc_buffer_t *fb, chfcoe_ioreq_t *tgtreq)
{
	fc_header_t *fc_hdr;
	void *sg;
	csio_cmd_handle_t cmd;
	void *buf_addr;
	uint32_t len, offset, bytes_done = 0, nents;
	uint32_t f_ctl;
	chfcoe_xchg_cb_t *xchg = tgtreq->xchg;
	
	chfcoe_mutex_lock(xchg->xchg_mutex);

	if (chfcoe_unlikely(chfcoe_test_bit(CHFCOE_XCHG_ST_ABORTED, &xchg->state) || 
				(!chfcoe_test_bit(CHFCOE_XCHG_ST_W_XFER, &xchg->state)))) {
		chfcoe_mutex_unlock(xchg->xchg_mutex);
		return;
	}

	if (chfcoe_test_bit(CHFCOE_XCHG_ST_DDP, &xchg->state)) {
		chfcoe_tgt_fcp_ddp_handler(tgtreq);
		return;
	}
	
	fc_hdr = (fc_header_t *) chfcoe_fc_data_ptr(fb);
	f_ctl = chfcoe_ntoh24(fc_hdr->f_ctl);
	if (chfcoe_unlikely(!(f_ctl & PROTO_FC_REL_OFF))) {
		chfcoe_err(0, "req %p invalid fctl 0x%x\n",
				tgtreq, f_ctl);
		goto unlock;
	}

	len = chfcoe_fc_data_len(fb);
	if (chfcoe_unlikely(len <= sizeof(fc_header_t))) {
		chfcoe_err(0, "req %p invalid frame len %u\n",
				tgtreq, len);
		goto unlock;
	}
	len -= sizeof(fc_header_t);

	offset = chfcoe_ntohl(fc_hdr->params);
	if (chfcoe_unlikely(offset >= tgtreq->sreq.buff_len)) {
		chfcoe_err(0, "req %p invalid offset %u len %u\n",
				tgtreq, offset, tgtreq->sreq.buff_len);
		goto unlock;
	}

	if (chfcoe_unlikely(offset + len > tgtreq->sreq.buff_len))
		len = tgtreq->sreq.buff_len - offset; 

	sg = tgtreq->sreq.os_sge;
	nents = tgtreq->sreq.nsge; 
	buf_addr = fc_hdr + 1;

	bytes_done = chfcoe_copy_buffer_to_sglist(buf_addr, len, sg, &nents, &offset);
	tgtreq->xfrd_len += bytes_done;

	if(chfcoe_unlikely(bytes_done != len)) {
		chfcoe_err(0, "req %p len %u,%u\n",
				tgtreq, len, bytes_done);
	}
	
	if((f_ctl & PROTO_FC_END_SEQ) &&
			(tgtreq->sreq.write_data_len == (int64_t)tgtreq->xfrd_len)) {
		chfcoe_clear_bit(CHFCOE_XCHG_ST_FIRST_FRAME, &xchg->state);
		chfcoe_clear_bit(CHFCOE_XCHG_ST_W_XFER, &xchg->state);
		chfcoe_ioreq_set_state(tgtreq, CHFCOE_IO_ST_SAL_DATA_SENT);
		tgtreq->sreq.req_status = CSIO_DRV_ST_SUCCESS;
		cmd = chfcoe_tgt_get_sal_ref(tgtreq);
		chfcoe_mutex_unlock(xchg->xchg_mutex);
		sal_ops->sal_rcv_data(cmd, tgtreq->sreq.req_status);
	}else {
		chfcoe_mutex_unlock(xchg->xchg_mutex);
	}

	return;
unlock:
	chfcoe_mutex_unlock(xchg->xchg_mutex);
}

static inline void 
chfcoe_tgt_abts_handler(chfcoe_ioreq_t *tgtreq)
{
	csio_sal_cmd_t scmd;
	csio_cmd_handle_t cmd2;
	csio_tret_t ret;
	chfcoe_xchg_cb_t *xchg = tgtreq->xchg; 

	chfcoe_memset(&scmd, 0, sizeof(scmd));
	scmd.tm_op = CSIO_SAL_TM_ABORT_TASK;
	scmd.tag = (uint64_t)tgtreq;
	scmd.priv = NULL;
	
	scmd.atomic = 1;

	chfcoe_err(adap, "lnode:0x%x rnode0x%x Aborting req %p, cmd %u, len %u, xfer len %u,%u,%d tag:0x%llx at SAL.\n",
			xchg->ln->nport_id, xchg->rn->nport_id,
			tgtreq,	tgtreq->sreq.data_direction, tgtreq->req_len, tgtreq->xfrd_len,
			xchg->seq_cnt, chfcoe_test_bit(CHFCOE_XCHG_ST_FIRST_FRAME, &xchg->state),
			scmd.tag);
	CHFCOE_INC_STATS(xchg->ln, n_abrt_tsk);
	
	/* Do not tamper with the original SAL reference of this request */
	ret = sal_ops->sal_rcv_tm(xchg->rn->ssn_hdl, &scmd, &cmd2);
	if (ret != CSIO_TSUCCESS) {
		chfcoe_dbg(adap, "Abort: sal_rcv_tm failed %d\n", ret);
		return;
	}
}


/* FCP exchange recv sequence handler */
static void
chfcoe_tgt_fcp_recv_seq(chfcoe_fc_buffer_t *fb, void *arg)
{
	fc_header_t *fc_hdr;
	chfcoe_ioreq_t *tgtreq = (chfcoe_ioreq_t *) arg;

	fc_hdr = (fc_header_t *) chfcoe_fc_data_ptr(fb);

	switch (fc_hdr->r_ctl) {
	case PROTO_FC_RCTL_DD_SOL_DATA:
		chfcoe_tgt_fcp_data_handler(fb, tgtreq);
		break;
	case PROTO_FC_RCTL_BA_ABTS:
		chfcoe_tgt_abts_handler(tgtreq);
		break;
	default:
		chfcoe_err(tgtreq->lnode, "unhandled FC frame rctl:0x%x\n", fc_hdr->r_ctl);
		break;
	}
}


/* FCP handler for incoming FCoE-SCSI commands */
static inline void
chfcoe_tgt_fcp_cmd_handler(struct chfcoe_adap_info *adap, 
	chfcoe_ioreq_t *tgtreq, chfcoe_fc_buffer_t *fb)
{
	struct proto_fcp_cmnd *fcp_cmd;
	csio_sal_cmd_t scmd;
	chfcoe_xchg_cb_t *xchg = tgtreq->xchg;
	
	chfcoe_memset(&scmd, 0, sizeof(scmd));
	fcp_cmd = proto_fc_frame_payload_get_rx(fb, sizeof(*fcp_cmd));
	chfcoe_dump_fcp_cmd(adap, fcp_cmd, tgtreq);

	if (chfcoe_unlikely(fcp_cmd->flags & PROTO_FCP_CFL_LEN_MASK)) {
		chfcoe_err(0, "cdb len flag 0x%x\n", fcp_cmd->flags);
		chfcoe_free_err_tgtreq(tgtreq);
		return;
	}
	
	switch (fcp_cmd->flags & (PROTO_FCP_CFL_RDDATA | PROTO_FCP_CFL_WRDATA)) {
	case PROTO_FCP_CFL_RDDATA:
		tgtreq->sreq.data_direction = CHFCOE_CMD_DATA_READ;
		break;
	case PROTO_FCP_CFL_WRDATA:
		tgtreq->sreq.data_direction = CHFCOE_CMD_DATA_WRITE;
		break;
	case 0:
		tgtreq->sreq.data_direction = CHFCOE_CMD_DATA_NONE;
		break;
	default:
		chfcoe_err(0, "invalid data direction flag 0x%x\n", fcp_cmd->flags);
		chfcoe_free_err_tgtreq(tgtreq);
		return;
	}
	
	/* Cache FCP CMD requested data length and task attributes here */
	tgtreq->req_len = chfcoe_be32_to_cpu(fcp_cmd->dl);
	tgtreq->sreq.ta = fcp_cmd->pri_ta;
	tgtreq->sreq.prot = CSIO_SAL_PROT_FCOE;
	tgtreq->sreq.os_dev = chfcoe_get_pdev(adap);
	tgtreq->sreq.sops = sal_ops;
	tgtreq->sreq.drv_req = tgtreq;
	
#ifdef __CSIO_DEBUG__
	tgtreq->sreq.rsvd1 = fcp_cmd->cdb[0];
#endif
	scmd.cdb = fcp_cmd->cdb;
	scmd.scdb = sizeof(fcp_cmd->cdb);
	scmd.lun = fcp_cmd->lun;
	tgtreq->lun = *((__be64 *)fcp_cmd->lun);
	scmd.slun = sizeof(fcp_cmd->lun);
	scmd.tag = (uint64_t)tgtreq;
	scmd.priv = (void *)&tgtreq->sreq;
	scmd.atomic = 1;

	if (chfcoe_likely(!fcp_cmd->tm_flags)) {
		scmd.tm_op = tgtreq->sreq.tm_op = 0;
		chfcoe_tgt_start_cmd(tgtreq, &scmd);
	} else {
		chfcoe_err(adap, "TM req %p flags:0x%x \n",
				tgtreq, fcp_cmd->tm_flags);

		switch(fcp_cmd->tm_flags) {
		case PROTO_FCP_TMF_ABT_TASK_SET: 
			scmd.tm_op = CSIO_SAL_TM_ABORT_TASK_SET;
			/* Close I/Os on this I-T nexus on this LUN */
			chfcoe_tgt_tm_close_rn_reqs(xchg->rn, tgtreq->lun, 0);
			CHFCOE_INC_STATS(xchg->ln, n_abrt_tsk_set);
			break;
		case PROTO_FCP_TMF_CLR_TASK_SET:
			scmd.tm_op = CSIO_SAL_TM_CLEAR_TASK_SET;
			/* Close I/Os on this I-T nexus on this LUN */
			chfcoe_tgt_tm_close_rn_reqs(xchg->rn, tgtreq->lun, 0);
			CHFCOE_INC_STATS(xchg->ln, n_clr_tsk_set);
			break;
		case PROTO_FCP_TMF_LUN_RESET:
			scmd.tm_op = CSIO_SAL_TM_LUN_RESET;
			/* Close I/Os on all I-T nexuses on this LUN */
			chfcoe_tgt_tm_close_ln_reqs(tgtreq, 1);
			CHFCOE_INC_STATS(xchg->ln, n_lun_rst);
			break;
		case PROTO_FCP_TMF_TGT_RESET:   
			scmd.tm_op = CSIO_SAL_TM_TARGET_RESET;
			/* Close I/Os on all I-T nexuses */
			chfcoe_tgt_tm_close_ln_reqs(tgtreq, 0);
			CHFCOE_INC_STATS(xchg->ln, n_tgt_rst);
			break;
		case PROTO_FCP_TMF_CLR_ACA:
			scmd.tm_op = CSIO_SAL_TM_CLEAR_ACA;
			CHFCOE_INC_STATS(xchg->ln, n_clr_aca);
			break;
		default:
			chfcoe_err(adap, "Unknown TM request opcode: 0x%x\n",
				 fcp_cmd->tm_flags);
			chfcoe_free_err_tgtreq(tgtreq);
			return;
		}

		tgtreq->sreq.tm_op = scmd.tm_op;
		chfcoe_tgt_start_tm(tgtreq, &scmd);
	}
}

void chfcoe_tgtreq_cleanup(void *data)
{
	chfcoe_ioreq_t *tgtreq = (chfcoe_ioreq_t *)data;
	csio_cmd_handle_t cmd;

	chfcoe_ioreq_set_state(tgtreq, CHFCOE_IO_ST_SAL_DONE_SENT);
	cmd = chfcoe_tgt_get_sal_ref(tgtreq);
	tgtreq->sreq.req_status = CSIO_DRV_ST_SUCCESS;

	sal_ops->sal_cmd_done(cmd, &tgtreq->sreq);
}

void chfcoe_tgt_recv_cmd(struct chfcoe_lnode *ln, chfcoe_fc_buffer_t *fb)
{
	struct chfcoe_rnode *rn = NULL;
	fc_header_t *fc_hdr;
	chfcoe_ioreq_t *tgtreq;
	chfcoe_xchg_cb_t *xchg;

	fc_hdr = (fc_header_t *) chfcoe_fc_data_ptr(fb);
	rn = chfcoe_fc_rnode(fb);

	switch (fc_hdr->r_ctl) {
	case PROTO_FC_RCTL_DD_UNSOL_CMD:
		xchg = chfcoe_get_xchg(rn);
		if (chfcoe_unlikely(!xchg)) {
			chfcoe_err(ln, "failed to alloc xid\n");
			break;
		}
		tgtreq = xchg->tgtreq;

		tgtreq->xchg = xchg;

		tgtreq->max_xfer_len = rn->max_pldlen & ~(512 - 1);

		chfcoe_xchg_init(xchg, chfcoe_tgt_fcp_recv_seq, tgtreq, rn,
				chfcoe_ntoh24(fc_hdr->d_id), chfcoe_ntoh24(fc_hdr->s_id),
				chfcoe_ntohs(fc_hdr->ox_id), xchg->xid, 0,
				chfcoe_fc_worker_id(fb));
		chfcoe_tgt_fcp_cmd_handler(ln->adap, tgtreq, fb);
		break;
	default :
		chfcoe_err(ln, "unhandled FC frame rctl:0x%x\n", fc_hdr->r_ctl);
		break;
	}
}

chfcoe_retval_t
chfcoe_tgt_init(void)
{
	/* register with SSAL */
	sal_ops = csio_sal_register_proto(&sal_proto_ops, CSIO_SAL_PROT_FCOE);
	if (sal_ops == NULL) {
		chfcoe_err(adap, "Registration with Chelsio Target SAL "
				"failed\n");
		return CHFCOE_INVAL;
	}

	/* register recv handler for FCP cmd */
	chfcoe_register_fc4(PROTO_FC_TYPE_FCP, chfcoe_tgt_recv_cmd);
	
	chfcoe_info(adap, "Registered with Chelsio Target SAL\n");
        return CHFCOE_SUCCESS;
}

void
chfcoe_tgt_exit(void)
{
	csio_sal_unregister_proto(CSIO_SAL_PROT_FCOE);
	return;
}
#endif /* __CSIO_TARGET__ */
