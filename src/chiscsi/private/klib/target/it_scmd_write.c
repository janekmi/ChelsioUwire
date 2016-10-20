#include <iscsi_target_api.h>
#include "iscsi_target_private.h"

int it_scmd_write_init(chiscsi_scsi_command *sc, iscsi_pdu *pdu)
{
	iscsi_session *sess = sc->sc_sess;
	iscsi_connection *conn = sc->sc_conn;
	chiscsi_scsi_write_cb *wcb = &sc->sc_cb.wcb;
	chiscsi_scsi_write_burst_cb *wburst;
	iscsi_portal *portal = conn->c_portal;
	unsigned int xferlen = sc->sc_xfer_len;
	unsigned int datalen = GET_PDU_DATA_SEGMENT_LENGTH(pdu);
	unsigned int firstburst = sess->setting.first_burst;
	unsigned char initialR2T = sess->setting.initial_r2t;
	unsigned char immediate_data = sess->setting.immediate_data;
	int i, rv = 0;

	if (!immediate_data && datalen) {
		pdu->p_flag |= ISCSI_PDU_FLAG_REJECT;
		os_log_info("itt 0x%x W, unexpected immediate data %u, reject!\n",
                         	sc->sc_itt, datalen);
		rv = iscsi_target_xmt_reject(pdu, ISCSI_REJECT_REASON_PROTOCOL_ERROR);
		return rv;
	}

	if (datalen > firstburst) {
		pdu->p_flag |= ISCSI_PDU_FLAG_DATA_SKIP;
		os_log_info("itt 0x%x W: immediate %u > firstburst %u!\n",
				sc->sc_itt, datalen, firstburst);
		sc_incorrect_amount_of_data(sc);
		scmd_fpriv_set_bit(sc, CH_SFP_XFER_ERR_BIT);
		sc->sc_xfer_left = 0;
		/*UNH fix 16.3.2, return error*/
                return -ISCSI_EINVAL;
	}

 	if (datalen && (sc->sc_flag & SC_FLAG_T10DIF)) {
		unsigned int num_sector = datalen/((1 << lu_sect_shift) + 8);
		/* datalen include pi bytes also. we need
		 * to reduce it to keep same as DIX handling */
		datalen -= (num_sector << 3);
	}

	sc->sc_xfer_cnt = datalen;
	wcb->w_immediate = datalen;
	if (!initialR2T && !GET_PDU_F(pdu)) {
		wcb->w_unsolicited =
			 firstburst < xferlen ? firstburst : xferlen;
		wcb->w_unsolicited -= datalen;

		/* add write bytes to portal count for immediate data */
		portal_counter_add(portal->os_data, wcb->w_immediate, WR_B_CTR);
		sess->s_perf_info.write_bytes += wcb->w_immediate;
	}

	/* firstburst has more data to come in */
	wburst = &wcb->w_burst_unsol;
	wburst->wb_ttt = ISCSI_INVALID_TAG;
	if (wcb->w_unsolicited) {
		wburst->wb_offset = wcb->w_immediate;
		wburst->wb_burstlen = wcb->w_unsolicited;
		wburst->wb_dlen = 0;
	}

	/* set R2T ttt to be invalid */
	wburst = &wcb->w_bursts[0];
	wcb->w_r2t_offset = wcb->w_immediate + wcb->w_unsolicited;
	for (i = 0; i < ISCSI_SESSION_MAX_OUTSTANDING_R2T; i++, wburst++)
		wburst->wb_ttt = ISCSI_INVALID_TAG;

	return 0;
}

/* send as many R2Ts as we can for this scsi command */
int it_scmd_write_xmt_r2t(chiscsi_scsi_command *sc)
{
	iscsi_connection *conn = sc->sc_conn;
	iscsi_session *sess = sc->sc_sess;
	chiscsi_scsi_write_cb *wcb = &sc->sc_cb.wcb;
	chiscsi_sgl *sc_sgl = &sc->sc_sgl;
	unsigned int maxburst = sess->setting.max_burst;
	unsigned int count_save = wcb->w_r2t_count;
	int async = scmd_fpriv_test_bit(sc, CH_SFP_LU_QUEUE_BIT) ? 1:0;
	unsigned int maxoff, sgcnt, sgidx, npages;
	chiscsi_sgvec *sgl, *sg;
	int multiphase  = scmd_fpriv_test_bit(sc, CH_SFP_LU_MULTIPHASE_BIT) ? 1:0;
        chiscsi_target_lun_class *lclass = sc->lu_class;
	void *pi_info = NULL;

	/* Get current values of sglist */
	if (async && !is_chelsio_lun_class(lclass)) os_lock_irq(sc->sc_lock);
	maxoff = sc_sgl->sgl_boff + sc_sgl->sgl_length;
	sgl = (chiscsi_sgvec *)sc_sgl->sgl_vecs;
	sgcnt = sc_sgl->sgl_vecs_nr;
	if (async && !is_chelsio_lun_class(lclass)) os_unlock_irq(sc->sc_lock);

	/* are we done with immediate and unsolicited data ? */
	if (sc->sc_xfer_cnt < (wcb->w_immediate + wcb->w_unsolicited))
		return 0;

	while ((wcb->w_r2t_count < sess->setting.max_r2t) &&
		(wcb->w_r2t_offset < maxoff)) {

		unsigned int ridx = wcb->w_r2tsn % sess->setting.max_r2t;
		chiscsi_scsi_write_burst_cb *wburst = &wcb->w_bursts[ridx];
		unsigned int xferlen = maxoff - wcb->w_r2t_offset;
		unsigned int ttt;
		iscsi_pdu *pdu;
		int     rv;
		unsigned int pi_len = 0;

		if (!xferlen)
			break;

		ttt = sc->sc_ddp_tag;
		xferlen = MINIMUM(xferlen, maxburst);

		if (sc->pi_info.prot_op == ISCSI_PI_OP_SCSI_PROT_READ_PASS) {
			/* How many pi bytes along with xferlen so that its
			 * remain less then maxburst */
			pi_len = (xferlen >> lu_sect_shift) << 3;

			if ((xferlen + pi_len) > maxburst) {
				xferlen = (xferlen - pi_len) &
						~((1 << lu_sect_shift) - 1);
				pi_len = (xferlen >> lu_sect_shift) << 3;
			}
			pi_info = &sc->pi_info;
		}

		if (multiphase) {
			unsigned int dummy;

			npages = (xferlen + os_page_size - 1) >> os_page_shift;
			if (sc->sc_ddp_tag != ISCSI_INVALID_TAG &&
			    scmd_fpriv_test_bit(sc, CH_SFP_BUF_DDP_MAPPED_BIT)) {
				/* last tag will be released in scmd free*/
				iscsi_target_task_tag_release_woff(sc->sc_odev, 
								sc->sc_ddp_tag);
				scmd_fpriv_clear_bit(sc, CH_SFP_BUF_DDP_MAPPED_BIT);
				sc->sc_ddp_tag = ISCSI_INVALID_TAG;
			}
			sgidx = chiscsi_sglist_find_boff(sgl, sgcnt, 
						wcb->w_r2t_offset, &dummy); 
			if (sgidx >= sgcnt)
				return -ISCSI_EINVAL;
			sg = sgl + sgidx;
		
			/* new sgcnt should be calculated from the offset
			 * until which we are done
			*/
			if (sgcnt > sgidx)	
				sgcnt -= sgidx;   
			sgcnt = MINIMUM(sgcnt, npages);
			rv = iscsi_target_task_tag_get_woff(sc->sc_sock, sc->sc_idx, 
					wcb->w_r2tsn, sgcnt, sg, sc->sc_xfer_len, wcb->w_r2t_offset, 
					xferlen, &sc->sc_sw_tag, &sc->sc_ddp_tag, pi_info,
					&sc->ppod_info);
			if (rv < 0) {
				os_log_debug(ISCSI_DBG_TARGET_API,
					"DDP setup failed: sgcnt %u wcb offset %u maxoff %u xferlen %u sc->sc_ddp_tag 0x%x \n",
						sgcnt, wcb->w_r2t_offset, maxoff, 
						xferlen, sc->sc_ddp_tag);
				scmd_fpriv_set_bit(sc, CH_SFP_BUF_DDP_MAPPED_BIT);
			}
			ttt = sc->sc_ddp_tag;
		} else {
			if (sc->sc_ddp_tag == ISCSI_INVALID_TAG) {
				/* set up ddp */
				rv = iscsi_tag_reserve(sc);
				if (rv < 0)
					return rv;
				ttt = sc->sc_ddp_tag;
				os_log_debug(ISCSI_DBG_DDP,
					"conn 0x%p, sc 0x%p, 0x%x, r2t 0, "
					"0x%x->0x%x, %u+%u/%u.\n",
					conn, sc, sc->sc_itt, sc->sc_ddp_tag,
					ttt, wcb->w_r2t_offset, xferlen,
					sc->sc_xfer_len);
			} else if (wcb->w_r2tsn) {
				rv = iscsi_tag_update_r2tsn(sc,
					wcb->w_r2tsn %
					ISCSI_SESSION_MAX_OUTSTANDING_R2T,
					&ttt);
				if (rv < 0)
					return rv;
				os_log_debug(ISCSI_DBG_DDP,
					"conn 0x%p, sc 0x%p, 0x%x, r2t %u, "
					"0x%x->0x%x, %u+%u/%u.\n",
					conn, sc, sc->sc_itt, wcb->w_r2tsn,
					sc->sc_ddp_tag, ttt,
					wcb->w_r2t_offset, xferlen,
					sc->sc_xfer_len);
			}
		}

		wburst->wb_ttt = ttt;
		wburst->wb_burstlen = xferlen;
		wburst->wb_offset = wcb->w_r2t_offset;
		wburst->wb_datasn = 0;
		wburst->wb_dlen = 0;

		if ((sgl->sg_flag & CHISCSI_SG_SBUF_DMA_ONLY) &&
		    !scmd_fpriv_test_bit(sc, CH_SFP_BUF_DDP_MAPPED_BIT)) {
			chiscsi_target_lun_class *lclass = sc->lu_class;

			os_log_info("%s: conn 0x%p, sc 0x%p, 0x%x, %u+%u/%u, "
				    "ddp NOT setup, fail write.\n",
				__func__, conn, sc, sc->sc_itt,
				wcb->w_r2t_offset, xferlen, sc->sc_xfer_len);
			scmd_fpriv_set_bit(sc, CH_SFP_XFER_ERR_BIT);
			sc_rw_error(sc);
			sc->sc_state = CH_SC_STATE_STATUS;
			sc->sc_flag |= SC_FLAG_CMD_ABORT;
			scmd_set_timestamp(sc, CH_SCMD_TM_FP_ABORT);

			os_log_debug(ISCSI_DBG_TARGET_API,
				"%s: fp_abort, sc 0x%p, sn 0x%x, itt 0x%x.\n",
				__func__, sc, sc->sc_cmdsn, sc->sc_itt);

			lclass->fp_scsi_cmd_abort(sc);

			return 0;
		}

		/* send next R2T */
		pdu = iscsi_pdu_get(conn, 0, 0, 0);
		if (!pdu)
			return -ISCSI_ENOMEM;
		pdu->p_saveq = sc->sc_queue[CH_SCMD_PDU_SENTQ];

		pdu->p_opcode = ISCSI_OPCODE_READY_TO_TRANSFER;

		SET_PDU_OPCODE(pdu, ISCSI_OPCODE_READY_TO_TRANSFER);
		SET_PDU_ITT(pdu, sc->sc_itt);
		SET_PDU_TTT(pdu, ttt);
		SET_PDU_F(pdu);
		SET_PDU_R2TSN(pdu, wcb->w_r2tsn);
		if (sc->pi_info.prot_op == ISCSI_PI_OP_SCSI_PROT_READ_PASS) {
			SET_PDU_BUFFER_OFFSET(pdu, wcb->w_r2t_offset +
				((wcb->w_r2t_offset  >> lu_sect_shift) << 3));
			SET_PDU_DESIRED_DATA_XFER_LENGTH(pdu, xferlen + pi_len);
		} else {
			SET_PDU_BUFFER_OFFSET(pdu, wcb->w_r2t_offset);
			SET_PDU_DESIRED_DATA_XFER_LENGTH(pdu, xferlen);
		}
		SET_PDU_STATSN(pdu, conn->c_statsn);
		pdu->p_sn = conn->c_statsn;
		SET_PDU_EXPCMDSN(pdu, sess->s_expcmdsn);
		SET_PDU_MAXCMDSN(pdu, sess->s_maxcmdsn);

		pdu->p_ppod_skb_list = sc->ppod_info.pskb_list;
		sc->ppod_info.pskb_list = NULL;

#if 0
		os_log_info("%s: pdu 0x%p, pdu->p_ppod_skb_list 0x%p\n",
			__func__, pdu, pdu->p_ppod_skb_list);
#endif

		os_log_debug(ISCSI_DBG_SCSI_COMMAND,
			"itt 0x%x r2t_offset %u xferlen %u ttt %u \n", 
			sc->sc_itt, wcb->w_r2t_offset, xferlen, ttt);
		rv = iscsi_connection_send_pdu(conn, pdu);
		if (rv < 0)
			return rv;

		wcb->w_r2t_count++;
		wcb->w_r2t_offset += xferlen;
		uint_serial_inc(wcb->w_r2tsn);
	}

	return wcb->w_r2t_count - count_save;
}

int iscsi_target_pdu_data_out_bhs_rcv(iscsi_pdu *pdu)
{
	iscsi_connection *conn = pdu->p_conn;
	iscsi_session *sess = conn->c_sess;
	chiscsi_queue *scq;
	chiscsi_scsi_command *sc; 
	chiscsi_scsi_write_cb *wcb;
	chiscsi_scsi_write_burst_cb *wburst;
	unsigned int itt = GET_PDU_ITT(pdu);
        unsigned int ttt = GET_PDU_TTT(pdu);
        unsigned int offset = GET_PDU_BUFFER_OFFSET(pdu);
	int wb_idx = 0;
	int rv = 0;

	if (!sess || conn->c_state != CONN_STATE_FFP) {
		iscsi_node *node = sess ? sess->s_node : NULL;

		os_log_info("%s:%s, conn 0x%p, s %u, sess 0x%p, error.\n",
			node ? node->n_name : "?", 
                        sess ? sess->s_peer_name : "?",
			conn, conn->c_state, sess);
		pdu->p_flag |= ISCSI_PDU_FLAG_DATA_SKIP;
		return -ISCSI_EINVAL;
	}

	/* already checked */
	if (pdu->p_scmd)
		return 0;

#if 0
	if (ttt != ISCSI_INVALID_TAG) {
		unsigned int sw_tag, idx, r2tsn;

		sw_tag = iscsi_tag_get_sw_tag(conn->c_isock, ttt); 
		iscsi_tag_decode_sw_tag(sw_tag, &idx, &r2tsn);
	}
#endif

 	scq = sess->s_queue[SESS_SCMDQ_NEW];
	//scmd_qsearch_by_ITT(nolock, scq, sc, itt);
	for (sc = scq->q_head; sc; sc = sc->sc_next)
		if (sc->sc_itt == itt && sc->sc_state < CH_SC_STATE_STATUS)
			break;
	if (!sc) {
		for (sc = scq->q_head; sc; sc = sc->sc_next)
			if (sc->sc_itt == itt)
				break;
		if (sc) {
			os_log_info("%s:%s: data_out 0x%x, sc 0x%p, s %u, 0x%x\n",
				sess->s_node ? sess->s_node->n_name : "?",
				sess->s_peer_name, itt, sc->sc_state,
				sc->sc_status);

			if (sc->sc_status) {
				pdu->p_flag |= ISCSI_PDU_FLAG_DATA_SKIP | 
						ISCSI_PDU_FLAG_DROP;
				return 0;
			}
			chiscsi_scsi_command_display(sc, 1);	
		} else
			os_log_info("%s:%s: data_out 0x%x, NO scsi task.\n",
				sess->s_node ? sess->s_node->n_name : "?",
				sess->s_peer_name, itt);
	}
		
	if (!sc) {
		pdu->p_flag |= ISCSI_PDU_FLAG_DATA_SKIP;
		iscsi_target_xmt_reject(pdu,
			ISCSI_REJECT_REASON_INVALID_PDU_FIELD);
		return -ISCSI_EINVAL;
	} 

	/* save the scsi command */
	pdu->p_scmd = (void *)sc; 

	/* command is being aborted, just drop data */
	if ((sc->sc_flag & SC_FLAG_TMF_ABORT) ||
	     scmd_fpriv_test_bit(sc, CH_SFP_XFER_ERR_BIT)) {
		pdu->p_flag |= ISCSI_PDU_FLAG_DATA_SKIP;
		return 0;
	}

	/* find the burst this one belongs to */
	wcb = &sc->sc_cb.wcb;
	if (ttt == ISCSI_INVALID_TAG) {
 		wburst = &wcb->w_burst_unsol;
	} else {
		wburst = &wcb->w_bursts[0];
		for (; wb_idx < sess->setting.max_r2t && wburst->wb_ttt != ttt;
			wb_idx++, wburst++)
			;
		if (wb_idx == sess->setting.max_r2t) {
			pdu->p_flag |= ISCSI_PDU_FLAG_DATA_SKIP;
			os_log_info("data_out, 0x%p, itt 0x%x, invalid ttt 0x%x, reject, max r2t %u.\n",
					sc, itt, ttt, sess->setting.max_r2t);

			wburst = &wcb->w_bursts[0];
			for (wb_idx = 0; wb_idx < sess->setting.max_r2t;
				wb_idx++, wburst++)
				os_log_info("%d, ttt 0x%x, off %u,%u,%u.\n",
					wb_idx, wburst->wb_ttt,
					wburst->wb_offset, wburst->wb_dlen,
					wburst->wb_burstlen);
				
			iscsi_target_xmt_reject(pdu, ISCSI_REJECT_REASON_INVALID_PDU_FIELD);
			return -ISCSI_EINVAL;
		}
		wb_idx++;
	}
	pdu->p_scmd_burst = (void *)wburst;

	if (pdu->p_flag & ISCSI_PDU_FLAG_PI_RCVD) {
		chiscsi_sgvec *sgl = (chiscsi_sgvec *)sc->lsc_sc_protsgl.sgl_vecs;
		unsigned int pi_offset;

#if 0
		os_log_info("%s: sc 0x%p, pdu->p_datalen %u, pi_len %u, "
			"pi rcvd in sc_flag 0x%x\n",
			__func__, sc, pdu->p_datalen,
			pdu->pi_info.pi_len, (sc->sc_flag & SC_FLAG_T10DIX));
#endif

		if (pdu->p_flag & ISCSI_PDU_FLAG_PI_DDPD)
			goto continue_data;
		if (pdu->p_flag & ISCSI_PDU_FLAG_PI_ERR) {
			chiscsi_target_lun_class *lclass = sc->lu_class;

			os_log_error("conn 0x%p: pi err in data_out data\n",
				conn);
			/* T10DIF TODO Send check condition. For now abort
 			   the command. */

			scmd_fpriv_set_bit(sc, CH_SFP_XFER_ERR_BIT);
			sc_rw_error(sc);
			sc->sc_state = CH_SC_STATE_STATUS;
			sc->sc_flag |= SC_FLAG_CMD_ABORT;	
			scmd_set_timestamp(sc, CH_SCMD_TM_FP_ABORT);

			os_log_debug(ISCSI_DBG_TARGET_API,
				"%s: fp_abort, sc 0x%p, sn 0x%x, itt 0x%x.\n",
				__func__, sc, sc->sc_cmdsn, sc->sc_itt);

			lclass->fp_scsi_cmd_abort(sc);
			return -ISCSI_EINVAL;
		}
		/* Setup buffer to read pi */

		/* we know pdu->pi_info.pi_len pi bytes have arrived in this
 		 * response.
		 * Now copy sgl to hold pi_len bytes, from location
		 * sc->lsc_sc_protsgl.sgl_vecs to pdu->p_prot_sglist.
		 * isock->sk_read_pdu_pi() will copy the pi bytes from
		 * DIF cpl to pdu->p_prot_sglist */

		if (sc->pi_info.interval == ISCSI_SCSI_PI_INTERVAL_512)
			pi_offset = (offset >> 9) << 3;
		else /* 4K sector */
			pi_offset = (offset >> 12) << 3;

#if 0
		os_log_info(
			"%s: setup buffer for pi, sc 0x%p, "
			"sc_lba 0x%x, sg_length %u, "
			"vecs_nr %u, offset %u, prot_op %u, interval %u, "
			"dif_type %u, guard %u, pi_offset %u\n",
			__func__, sc, sc->sc_lba, sgl->sg_length,
			sc->lsc_sc_protsgl.sgl_vecs_nr, offset,
			sc->pi_info.prot_op, sc->pi_info.interval,
			sc->pi_info.dif_type, sc->pi_info.guard,
			pi_offset);
#endif

		iscsi_pdu_pi_sglist_setup_by_offset(pdu, pi_offset, sgl,
			sc->lsc_sc_protsgl.sgl_vecs_nr);
	} else if (sc->sc_flag & SC_FLAG_T10DIX) {
		/* PI not received but command expects pi data */
		chiscsi_target_lun_class *lclass = sc->lu_class;

		os_log_error("%s: Expecting PI but didnt rcvd, sc_lba 0x%x\n",
			__func__, sc->sc_lba);
		scmd_fpriv_set_bit(sc, CH_SFP_XFER_ERR_BIT);
		sc_rw_error(sc);
		sc->sc_state = CH_SC_STATE_STATUS;
		sc->sc_flag |= SC_FLAG_CMD_ABORT;
		scmd_set_timestamp(sc, CH_SCMD_TM_FP_ABORT);

		os_log_debug(ISCSI_DBG_TARGET_API,
			"%s: fp_abort, sc 0x%p, sn 0x%x, itt 0x%x.\n",
			__func__, sc, sc->sc_cmdsn, sc->sc_itt);

		lclass->fp_scsi_cmd_abort(sc);
		return 0;
	}

continue_data:
	if (pdu->p_flag & ISCSI_PDU_FLAG_DATA_DDPED) {
		os_log_debug(ISCSI_DBG_DDP,
			"conn 0x%p, sc 0x%p, 0x%x,0x%x, %u+%u/%u IS ddp'ed.\n",
			conn, sc, itt, ttt, offset, pdu->p_datalen,
			sc->sc_xfer_len);
		return 0;
	} else {
		if (scmd_fpriv_test_bit(sc, CH_SFP_BUF_DDP_MAPPED_BIT)) {
			os_log_debug(ISCSI_DBG_DDP,
				"%s: conn 0x%p, sc 0x%p, 0x%x,0x%x, "
				"%u+%u/%u NOT ddp'ed.\n",
				__func__, conn, sc, itt, ttt, offset,
				pdu->p_datalen, sc->sc_xfer_len);
		}
		/* set up the data buffer */
		if (scmd_fpriv_test_bit(sc, CH_SFP_CHLU_SINK_BIT)) {
			pdu->p_flag |= ISCSI_PDU_FLAG_DATA_SKIP;
			return 0;
		} else if (sc->sc_sgl.sgl_vecs) {
			chiscsi_sgvec *sgl = (chiscsi_sgvec *)sc->sc_sgl.sgl_vecs;
			if ((sgl->sg_flag & CHISCSI_SG_SBUF_DMA_ONLY) && !(sc->sc_flag & SC_FLAG_CMD_ABORT)) {
				chiscsi_target_lun_class *lclass = sc->lu_class;
				scmd_fpriv_set_bit(sc, CH_SFP_XFER_ERR_BIT);
				sc_rw_error(sc);
				sc->sc_state = CH_SC_STATE_STATUS;
				sc->sc_flag |= SC_FLAG_CMD_ABORT;	
				scmd_set_timestamp(sc, CH_SCMD_TM_FP_ABORT);

				os_log_debug(ISCSI_DBG_TARGET_API,
					"%s: fp_abort, sc 0x%p, sn 0x%x, itt 0x%x.\n",
					__func__, sc, sc->sc_cmdsn, sc->sc_itt);

				lclass->fp_scsi_cmd_abort(sc);
				return -ISCSI_ENOMEM;
			}
			rv = iscsi_pdu_sglist_setup_by_offset(pdu,
					offset - sc->sc_sgl.sgl_boff,
					(chiscsi_sgvec *)sc->sc_sgl.sgl_vecs,
					sc->sc_sgl.sgl_vecs_nr);
			if (rv < 0) {
				os_log_info("sc itt 0x%x, pdu off %u, len %u, no buffer find.\n",
					sc->sc_itt, offset, pdu->p_datalen);
				return rv;
			}
		} else
			os_log_warn("sc itt 0x%x, data out pdu len %u, no buf.\n",
			     		sc->sc_itt, pdu->p_datalen);

		if (!pdu->p_sgcnt_used) {
			os_log_warn("sc itt 0x%x, data out pdu len %u, no buf, alloc.\n",
			     		sc->sc_itt, pdu->p_datalen);
			pdu->p_flag |= ISCSI_PDU_FLAG_LOCKED;
                        return (iscsi_pdu_alloc_data_buffer(pdu, pdu->p_datalen));
		}
	}

	return 0;
}

int iscsi_target_write_burst_complete(chiscsi_scsi_command *sc)
{
	int rv = 0;
	chiscsi_scsi_write_cb *wcb = &sc->sc_cb.wcb;
	unsigned int max_offset = sc->sc_sgl.sgl_boff + sc->sc_sgl.sgl_length;

	/* burst complete */
	if (wcb->w_r2t_count)
		wcb->w_r2t_count--;

	if (wcb->w_r2t_offset < max_offset)
		rv = it_scmd_write_xmt_r2t(sc);
        else if ((sc->sc_xfer_cnt == max_offset) &&
                !(sc->sc_flag & SC_FLAG_TMF_ABORT)) {

		/* release the ddp tag */
		chiscsi_scsi_command_release_ddp_tag(sc);	

		os_log_debug(ISCSI_DBG_SCSI_COMMAND,
			"sc itt 0x%x, W, -> exe_ready.\n",
			sc->sc_itt);

		sc->sc_state = CH_SC_STATE_EXE_READY;
	}

	return rv;
}

int iscsi_target_rcv_data_out(iscsi_pdu *pdu)
{
	iscsi_connection *conn = pdu->p_conn;
	iscsi_session *sess = conn->c_sess;
	iscsi_portal *portal = conn->c_portal;
	chiscsi_scsi_command *sc = pdu->p_scmd;
        chiscsi_scsi_write_burst_cb *wburst = pdu->p_scmd_burst;
	chiscsi_scsi_write_cb *wcb;
	unsigned int offset = GET_PDU_BUFFER_OFFSET(pdu);
	unsigned int datasn = GET_PDU_DATASN(pdu);
        unsigned int ttt = GET_PDU_TTT(pdu);
	unsigned int dlen = pdu->p_datalen;
	int rv = 0;

	if (pdu->p_flag & ISCSI_PDU_FLAG_DROP)
		return 0;

	pdu->p_offset = offset;

	/* handle data digset error? */
	if (pdu->p_flag & ISCSI_PDU_FLAG_ERR_DATA_DIGEST) {
		scmd_fpriv_set_bit(sc, CH_SFP_XFER_ERR_BIT);
		sc_data_digest_error(sc);
		return 0;
	}

	if(!wburst){
		os_log_info("data_out itt 0x%x, NO burst found.\n",
			sc->sc_itt, rv);
		//pdu->p_flag &= ~ISCSI_PDU_FLAG_LOCKED;
                //sc->sc_state = CH_SC_STATE_STATUS;
                //sc_unexpected_unsolicited_data(sc);   
                //iscsi_target_scsi_command_respond(sc);
                return -ISCSI_EINVAL;
        }
 	wcb = &sc->sc_cb.wcb;

        if (pdu->p_flag & ISCSI_PDU_FLAG_RX_CMPL) {
		/* t6 garantees the in order data, so no need to check */
		if (offset > sc->sc_xfer_cnt) {
               		sc->sc_xfer_left -= sc->sc_xfer_cnt - offset;
               		sc->sc_xfer_cnt = offset;
		}
		wburst->wb_dlen = offset - wburst->wb_offset;
		wburst->wb_datasn = datasn;

		goto done;
	}

	/* only support in-order data */
        if ((wburst->wb_offset + wburst->wb_dlen)!= offset) {
		os_log_warn("data_out, itt 0x%x, ttt 0x%x, off %u != %u+%u.\n",
				sc->sc_itt, ttt, offset, wburst->wb_offset,
				wburst->wb_dlen);
		
                iscsi_pdu_display((void *) pdu, NULL, 0, 1);

		return -ISCSI_EINVAL;
        }

	if (wburst->wb_datasn != datasn) {
		os_log_warn("data_out, itt 0x%x, ttt 0x%x, offset %u, datasn %u != %u.\n",
				sc->sc_itt, ttt, offset, datasn, wburst->wb_datasn);
		return -ISCSI_EINVAL;
        }

	if ((wburst->wb_dlen + pdu->p_datalen) >  wburst->wb_burstlen) {
		pdu->p_flag |= ISCSI_PDU_FLAG_DATA_SKIP;
                os_log_warn("data_out, xfer error, itt 0x%x, ttt 0x%x, off %u, dlen %u > %u/%u.\n",
			    sc->sc_itt, ttt, offset, pdu->p_datalen, 
			    wburst->wb_dlen, wburst->wb_burstlen);
		if (!scmd_fpriv_test_bit(sc, CH_SFP_XFER_ERR_BIT)) {
			int i;

			scmd_fpriv_set_bit(sc, CH_SFP_XFER_ERR_BIT);
			sc_incorrect_amount_of_data(sc);
			/* reset all xfer sequences */
			for (i = 0; i < ISCSI_SESSION_MAX_OUTSTANDING_R2T; i++)
				wcb->w_bursts[i].wb_dlen = wcb->w_bursts[i].wb_burstlen;
		}
		return -ISCSI_EINVAL;
		return 0; /*UNH ffp 16.3.6-fixed by adding xmt_r2t_check_error fn*/
	}

done:
	uint_serial_inc(wburst->wb_datasn);
	wburst->wb_dlen += pdu->p_datalen;

	/* check F-bit */
        if (GET_PDU_F(pdu)) {
		if (wburst->wb_dlen < wburst->wb_burstlen) {
			os_log_warn("data_out: F bit, rcv %u/%u , itt 0x%x, ttt 0x%x, offset %u, len %u.\n",
				wburst->wb_dlen, wburst->wb_burstlen, sc->sc_itt, ttt, offset,
				pdu->p_datalen);
			CLR_PDU_F(pdu);
#ifdef __STRICT_RFC__
			return -ISCSI_EINVAL;
#endif
                }
        } else if (wburst->wb_dlen == wburst->wb_burstlen) {
		os_log_warn("data_out, no F bit, rcv %u/%u, itt 0x%x, ttt 0x%x, pdu %u+%u.\n",
				wburst->wb_dlen, wburst->wb_burstlen, sc->sc_itt,
				ttt, offset, pdu->p_datalen);
		SET_PDU_F(pdu);
#ifdef __STRICT_RFC__
		return -ISCSI_EINVAL;
#endif
        }

	/* add the write data length for portal Wrote bytes */
	if (portal)
		portal_counter_add(portal->os_data, dlen, WR_B_CTR);
	sess->s_perf_info.write_bytes += dlen;

	sc->sc_xfer_cnt += dlen;
	sc->sc_xfer_left -= dlen;

	if (pdu->p_flag & ISCSI_PDU_FLAG_LOCKED) {
		os_log_info("%s: pdu locked.\n", __func__);
	}

	/* burst complete and this is the last pdu of the burst */
        if (GET_PDU_F(pdu) && (wburst->wb_dlen == wburst->wb_burstlen)) {
		rv = iscsi_target_write_burst_complete(sc);
	}

	return rv;
}

/* Check errors before transmitting r2t */
static int it_xmt_r2t_check_errors(chiscsi_scsi_command *sc)
{
        iscsi_session *sess = sc->sc_sess;
        chiscsi_queue *q = sess->s_queue[SESS_SCMDQ_NEW];

        /* send check condition*/
	if (scmd_fpriv_test_bit(sc, CH_SFP_XFER_ERR_BIT)) {
                sc->sc_state = CH_SC_STATE_STATUS;
                return -ISCSI_EINVAL;
        } else if (sc->sc_flag & SC_FLAG_TMF_ABORT ||
		   scmd_fpriv_test_bit(sc, CH_SFP_TMF_SENSE_BIT)) {

                /* SCST sends response for aborted commands as well, so abort
                 * path is different.
                 */
/*                if (scmd_fpriv_test_bit(sc, CH_SFP_LU_TYPE_SCST_BIT)) {
                        sc->sc_state = CH_SC_STATE_EXECUTING;
                        return 1;
                }*/

                /* if it was tmf abort then dequeue this sc */
                scmd_dequeue(nolock, q, sc);
                sc->sc_state = CH_SC_STATE_DONE;
                return 1;
        }

        return 0;
}

int it_scmd_write_continue(chiscsi_scsi_command *sc)
{
	chiscsi_target_lun_class *lclass = sc->lu_class;
	int async = scmd_fpriv_test_bit(sc, CH_SFP_LU_QUEUE_BIT) ? 1:0;
	int rv = 0;
	unsigned int max_offset = 0;

	os_log_debug(ISCSI_DBG_SCSI_COMMAND, 
		"sc 0x%p, W, itt 0x%x, flag 0x%x, state 0x%x, fscsi 0x%x.\n",
		sc, sc->sc_itt, sc->sc_flag, sc->sc_state, sc->sc_fscsi);

sc_abort_err_check:
	if (sc->sc_state != CH_SC_STATE_CLOSED && sc->sc_state != CH_SC_STATE_DONE) {
		if (sc->sc_flag & SC_FLAG_TMF_ABORT)
			iscsi_target_scsi_command_check_tmf_condition(sc);
		else if (!sc->sc_status && sc->sc_state < CH_SC_STATE_STATUS) {
                        it_scmd_exe_check_error(sc); 
		}
		if (sc->sc_status && sc->sc_state < CH_SC_STATE_STATUS) {
			os_log_debug(ISCSI_DBG_SCSI_COMMAND,
				"sc 0x%p itt 0x%x, W, 0x%x, s %d->STATUS, 0x%x,0x%lx,0x%lx.\n",
				sc, sc->sc_itt, sc->sc_status, sc->sc_state,
				sc->sc_flag, sc->sc_fscsi, sc->sc_fpriv);
			sc->sc_state = CH_SC_STATE_STATUS;
			scmd_fpriv_set_bit(sc, CH_SFP_XFER_ERR_BIT);
			sc->sc_xfer_len = sc->sc_xfer_left = 0;
		}
	}
	
	switch(sc->sc_state) {
	case CH_SC_STATE_CLOSED:
		break;
	case CH_SC_STATE_INITIALIZED:
sc_state_initialized:
		os_log_debug(ISCSI_DBG_SCSI_COMMAND,
			"sc itt 0x%x, W, initialized -> buffer_wait.\n",
			sc->sc_itt);
		/* get write buffer from backend */
		if (async && !is_chelsio_lun_class(lclass)) os_lock_irq(sc->sc_lock);
		scmd_fscsi_set_bit(sc, CH_SFSCSI_HOLD_BIT);
		max_offset = sc->sc_sgl.sgl_boff + sc->sc_sgl.sgl_length;
		if (sc->sc_xfer_cnt == max_offset) 
			scmd_fscsi_clear_bit(sc, CH_SFSCSI_BUF_READY_BIT);
		sc->sc_state = CH_SC_STATE_W_BUFFER_WAIT;
		if (async && !is_chelsio_lun_class(lclass)) os_unlock_irq(sc->sc_lock);

		scmd_set_timestamp(sc, CH_SCMD_TM_FP_CDB_RCVED);

		os_log_debug(ISCSI_DBG_TARGET_API,
			"%s: fp_cdb_rcvd, sc 0x%p, sn 0x%x, itt 0x%x.\n",
			__func__, sc, sc->sc_cmdsn, sc->sc_itt);

		rv = lclass->fp_scsi_cmd_cdb_rcved(sc);
		if (rv < 0) {
			/* Buffer alloc failed, check if status is set. */
			if (sc->sc_status) {
				os_log_info("buffer alloc failed, status set, " 
					"W itt 0x%x\n",	sc->sc_itt);
				scmd_fscsi_clear_bit(sc, CH_SFSCSI_HOLD_BIT);
				sc->sc_state = CH_SC_STATE_STATUS;
			}
			break;
		}
		/* fall through to check if the buffer is already ready */
	case CH_SC_STATE_W_BUFFER_WAIT:
		if (async && !is_chelsio_lun_class(lclass)) os_lock_irq(sc->sc_lock);
		max_offset = sc->sc_sgl.sgl_boff + sc->sc_sgl.sgl_length;
		if (scmd_fscsi_test_bit(sc, CH_SFSCSI_BUF_READY_BIT)) {
			os_log_debug(ISCSI_DBG_SCSI_COMMAND,
				"sc itt 0x%x, W, buffer wait -> ready.\n",
				sc->sc_itt);
			if (sc->sc_xfer_cnt == max_offset) 
				scmd_fscsi_clear_bit(sc, CH_SFSCSI_BUF_READY_BIT);
			sc->sc_state = CH_SC_STATE_W_BUFFER_READY;
			if (async && !is_chelsio_lun_class(lclass))
				os_unlock_irq(sc->sc_lock);
			/* fall through to CH_SC_STATE_W_BUFFER_READY */
		} else if (scmd_fscsi_test_bit(sc, CH_SFSCSI_EXECUTED_BIT)) {
			/* it is possible that the backend has no buffer to
			 * offer and wants to be done with it */
			os_log_info("%s: itt 0x%x BUFFER_WAIT, executed.\n",
				__func__, sc->sc_itt);
			chiscsi_scsi_command_display(sc, 1);	

			sc->sc_xfer_left = 0;
                	sc->sc_state = CH_SC_STATE_STATUS;
	                iscsi_target_scsi_command_check_execution_status(sc);
			iscsi_target_scsi_command_check_tmf_condition(sc);

			if (async && !is_chelsio_lun_class(lclass))
				os_unlock_irq(sc->sc_lock);

			goto sc_state_status;
		} else {
			if (async && !is_chelsio_lun_class(lclass))
				os_unlock_irq(sc->sc_lock);
			break;
		}
	case CH_SC_STATE_W_BUFFER_READY:
sc_state_w_buffer_ready:
		os_log_debug(ISCSI_DBG_SCSI_COMMAND,
			"sc itt 0x%x, W, buffer_ready -> xfer.\n", sc->sc_itt);
		if (async && !is_chelsio_lun_class(lclass)) os_lock_irq(sc->sc_lock);
		sc->sc_state = CH_SC_STATE_W_XFER;
		/*if abort was requested between any of above states*/
		if (sc->sc_flag & SC_FLAG_CMD_ABORT)
			sc->sc_state = CH_SC_STATE_STATUS;
		if (async && !is_chelsio_lun_class(lclass)) os_unlock_irq(sc->sc_lock);

		/* Bug fix UNH ffp 1.2, 1.3 Dont fall through since other 
		   checks need to be done before sending r2t */
		goto sc_abort_err_check;
	case CH_SC_STATE_W_XFER:
                rv = it_xmt_r2t_check_errors(sc);
                if (rv) {
			/* rv < 0 -> xfer err, state status, else state done*/
                        if (rv < 0)
                                goto sc_state_status;
                } else {
                        rv = it_scmd_write_xmt_r2t(sc);
		}
                break;
	case CH_SC_STATE_EXE_READY:
		if (scmd_fpriv_test_bit(sc, CH_SFP_RWIO_BIT) ||
		    (sc->sc_flag & SC_FLAG_PASSTHRU) ||	
		    (scmd_fpriv_test_bit(sc, CH_SFP_LU_PASSTHRU_BIT))) {
			os_log_debug(ISCSI_DBG_SCSI_COMMAND,
				"sc itt 0x%x, W, rwio, exe_ready -> executing.\n",
				sc->sc_itt);
			if (async && !is_chelsio_lun_class(lclass)) os_lock_irq(sc->sc_lock);
			max_offset = sc->sc_sgl.sgl_boff + sc->sc_sgl.sgl_length;
			scmd_fscsi_set_bit(sc, CH_SFSCSI_HOLD_BIT);	
			scmd_fscsi_clear_bit(sc, CH_SFSCSI_EXECUTED_BIT);
			if (sc->sc_xfer_cnt == max_offset) 
				scmd_fscsi_clear_bit(sc, CH_SFSCSI_BUF_READY_BIT);
			sc->sc_state = CH_SC_STATE_EXECUTING;
			if (async && !is_chelsio_lun_class(lclass)) os_unlock_irq(sc->sc_lock);
			/*
 			 * release the reference to the write buffers, the
 			 * backend is expecting to free those buffers after
 			 * execution.
			 */
			it_scmd_release_backend_buffers(sc, sc->sc_xfer_cnt);
			break;
		} else {
			os_log_debug(ISCSI_DBG_SCSI_COMMAND,
				"sc itt 0x%x, W, non-rwio, exe_ready -> executing.\n",
				sc->sc_itt);
			sc->sc_state = CH_SC_STATE_EXECUTING;
			iscsi_target_lu_scsi_non_rwio_cmd_respond(sc);

			iscsi_target_scsi_command_done(sc, 0);
			/* fall through to CH_SC_STATE_EXECUTING */
		}
	case CH_SC_STATE_EXECUTING:
		if (async && !is_chelsio_lun_class(lclass)) os_lock_irq(sc->sc_lock);
		if (scmd_fscsi_test_bit(sc, CH_SFSCSI_EXECUTED_BIT)) {
	                iscsi_target_scsi_command_check_execution_status(sc);
			iscsi_target_scsi_command_check_tmf_condition(sc);

                	if (sc->sc_state == CH_SC_STATE_STATUS) {
				if (async && !is_chelsio_lun_class(lclass)) os_unlock_irq(sc->sc_lock);
                        	goto sc_state_status;
                	} else if (sc->sc_state == CH_SC_STATE_DONE) {
				if (async && !is_chelsio_lun_class(lclass)) os_unlock_irq(sc->sc_lock);
                        	goto sc_state_done;
			}
			os_log_debug(ISCSI_DBG_SCSI_COMMAND,
				"sc itt 0x%x, W, executed.\n", sc->sc_itt);
			scmd_fscsi_clear_bit(sc, CH_SFSCSI_EXECUTED_BIT);
			/* if there is no error in execution */
			max_offset = sc->sc_sgl.sgl_boff + sc->sc_sgl.sgl_length;
			if (scmd_fpriv_test_bit(sc, CH_SFP_BUF_LAST_BIT) &&
				(sc->sc_xfer_cnt == max_offset)) {
				os_log_debug(ISCSI_DBG_SCSI_COMMAND,
					"sc itt 0x%x, W, executing -> status.\n",
					sc->sc_itt);
				sc->sc_state = CH_SC_STATE_STATUS;
				if (async && !is_chelsio_lun_class(lclass)) os_unlock_irq(sc->sc_lock);
				rv = it_scmd_send_sense_status(sc);
			} else {
				os_log_debug(ISCSI_DBG_SCSI_COMMAND,
					"sc itt 0x%x, W, executing -> initialized.\n",
					sc->sc_itt);
				sc->sc_state = CH_SC_STATE_INITIALIZED;
				if (async && !is_chelsio_lun_class(lclass)) os_unlock_irq(sc->sc_lock);
				goto sc_state_initialized;
			}
		} else if (scmd_fscsi_test_bit(sc, CH_SFSCSI_BUF_READY_BIT)) {
			sc->sc_state = CH_SC_STATE_W_BUFFER_READY;
			if (async && !is_chelsio_lun_class(lclass)) os_unlock_irq(sc->sc_lock);
			goto sc_state_w_buffer_ready;
		} else {
			if (async && !is_chelsio_lun_class(lclass)) os_unlock_irq(sc->sc_lock);
			os_log_debug(ISCSI_DBG_SCSI_COMMAND,
				"sc itt 0x%x, W, executing.\n", sc->sc_itt);
			break;
		}
sc_state_status:
	case CH_SC_STATE_STATUS:
		rv = it_scmd_send_sense_status(sc);
		sc->sc_state = CH_SC_STATE_DONE;
		if (!sc->sc_next &&
		    !scmd_fpriv_test_bit(sc, CH_SFP_CHLU_BIT) &&
		    scmd_fpriv_test_bit(sc, CH_SFP_LU_PASSTHRU_BIT)) {
			os_log_debug(ISCSI_DBG_TARGET_API,
				"sc 0x%p, itt 0x%x, flag 0x%x, w sent nop_in.\n",
				sc, sc->sc_itt, sc->sc_flag);
			it_xmt_nop_in(sc->sc_conn, 1, 0, 0, 0, NULL, NULL);
		}
		break;
	case CH_SC_STATE_DONE:
sc_state_done:
		if (scmd_fscsi_test_bit(sc, CH_SFSCSI_STATUS_ACKED_BIT))
			it_scmd_acked(sc);
		break;
	}

	return rv;
}
