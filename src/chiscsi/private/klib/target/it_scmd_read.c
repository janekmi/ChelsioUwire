#include <iscsi_target_api.h>
#include "iscsi_target_private.h"

int it_scmd_read_init(chiscsi_scsi_command *sc)
{
	iscsi_session *sess = sc->sc_sess;
	chiscsi_scsi_read_cb *rcb = &sc->sc_cb.rcb;

	rcb->r_maxburst = sess->setting.max_burst;
	return 0;
}

int it_scmd_read_send_data_in_pdus(chiscsi_scsi_command * sc)
{
	iscsi_session *sess = (iscsi_session *)sc->sc_sess;
	iscsi_connection *conn = (iscsi_connection *)sc->sc_conn;
	chiscsi_queue *sendq = (chiscsi_queue *)conn->c_queue[CONN_PDUQ_SEND];
	iscsi_portal *portal = conn->c_portal;
	chiscsi_scsi_read_cb *rcb = &sc->sc_cb.rcb;
	chiscsi_sgvec *sgl;
	chiscsi_sgvec *sg = rcb->r_sg;
	chiscsi_sgvec *prot_sg = NULL;
	iscsi_pdu *pdu = NULL;
	unsigned int sgmax;
	int async = scmd_fpriv_test_bit(sc, CH_SFP_LU_QUEUE_BIT) ? 1 : 0;
	int overflow = sc->sc_flag & SC_FLAG_XFER_OVERFLOW;
	unsigned int sgoff = rcb->r_sgoffset;
	unsigned int xferlen;
	unsigned int maxoffset;
	int rv = 0;
	int blk_len = sc->sc_blk_cnt << lu_sect_shift;
	chiscsi_target_lun_class *lclass = sc->lu_class;
	unsigned int prot_nvecs = 0, pi_len = 0, pi_sg_offset = 0;
	unsigned int pi_offset = 0;
	/* No iso if DIF is enabled */
	unsigned int iso = (!(sc->pi_info.prot_op == \
			ISCSI_PI_OP_SCSI_PROT_WRITE_PASS) &&
			iscsi_conn_get_iso_max(conn));

	if (async && !is_chelsio_lun_class(lclass)) os_lock_irq(sc->sc_lock);
	sgl = (chiscsi_sgvec *)sc->sc_sgl.sgl_vecs;
	sgmax = sc->sc_sgl.sgl_vecs_nr;

	if (sgmax && !sgl) {
		os_log_error("R itt 0x%x, %u+%u/%u, SGL %u, 0x%p,0x%p, %u!\n",
			sc->sc_itt, sc->sc_sgl.sgl_boff, sc->sc_sgl.sgl_length,
			sc->sc_xfer_len, sgmax, sgl, sc->sc_sgl.sgl_vec_last,
			rcb->r_offset);
		return -ISCSI_EINVAL;
	}

	xferlen = sc->sc_sgl.sgl_boff + sc->sc_sgl.sgl_length;
	if (async && !is_chelsio_lun_class(lclass)) os_unlock_irq(sc->sc_lock);

	/* all current buffers are sent */

	if (rcb->r_offset >= xferlen) {
		rcb->r_sg = NULL;
		goto data_sent;
	}
	xferlen -= rcb->r_offset;
	
	/* Check for overflow */
	if (sc->sc_xfer_left < xferlen && overflow)	
		xferlen = sc->sc_xfer_left;
	
	if (sgmax && !sg) {
		rv = chiscsi_sglist_find_boff(sgl, sgmax, rcb->r_offset, &sgoff);
		if (rv >= sgmax) {
			os_log_warn("R itt 0x%x, NO sg %u/%u.\n",
				sc->sc_itt, rcb->r_offset,
				sc->sc_xfer_len);
			return -ISCSI_EINVAL;
		}
		sg = sgl + rv;
		rcb->r_sg = sg;
		sgoff = rcb->r_sgoffset = rcb->r_offset - sg->sg_boff;
	}

	/* construct all data_in bursts in one shot */
	while (xferlen) {
		unsigned int plen = MINIMUM(xferlen, conn->c_pdudatalen_tmax);
		unsigned int nvecs = 1;
		unsigned int dlen;
		unsigned int max_num_pdu, num_pdu = 1, mpdu;

		if (sc->pi_info.prot_op == ISCSI_PI_OP_SCSI_PROT_WRITE_PASS) {
			/* pi is going over wire so ensure that data+pi is
			 * always within pdu boudary i.e. less than
			 * conn->c_pdudatalen_tmax */
			pi_len = (plen >> lu_sect_shift) << 3;

			if ((plen + pi_len) > conn->c_pdudatalen_tmax) {
				plen = (plen - pi_len) &
						~((1 << lu_sect_shift) - 1);
				pi_len = (plen >> lu_sect_shift) << 3;
			}
		}
		mpdu = plen;
		if (iso && (xferlen > plen)) {
			/* Use ISO */
			/* How many pdu can be sent within ISO limit.
			 * Accomodate hdr size and digest size also while
			 * calculatng number of pdus. */
			max_num_pdu = iscsi_conn_get_iso_max(conn)/
					(plen + ISCSI_BHS_SIZE + (ISCSI_PDU_DIGEST_SIZE << 1));
			num_pdu = (xferlen + plen - 1)/plen;
			if (num_pdu > max_num_pdu)
				num_pdu = max_num_pdu;

			plen = MINIMUM(plen*num_pdu, xferlen);
		}

		sg = rcb->r_sg;

		if (sgmax) {
			dlen = sg->sg_length - sgoff;
			for (sg = sg->sg_next; sg && dlen < plen; sg = sg->sg_next) {
				dlen += sg->sg_length;
				nvecs++;
			}
			if (dlen < plen) {
				os_log_error("sc R itt 0x%x, not enought data %u < %u.\n",
						sc->sc_itt, dlen, plen);
				return -ISCSI_EINVAL;
			
			}
		}

#if 0
		if (sc->lsc_sc_protsgl.sgl_vecs_nr) {
			/* pi enabled for this command */
			os_log_info("%s: xferlen %u, dlen %u, plen %u, "
				"data nvecs %u, prot sgl_length %u, "
				"prot nvecs %u, sgoff %u, sgmax %u, "
				"rcb->r_offset %u\n",
				__func__, xferlen, dlen, plen, nvecs,
				sc->lsc_sc_protsgl.sgl_length,
				sc->lsc_sc_protsgl.sgl_vecs_nr, sgoff, sgmax,
				rcb->r_offset);
		}
#endif

		/* Use rcb->r_offset to find the pi offset in pi sgl for the
 		 * pdu. rcb->r_offset indicates how much data we have sent till
 		 * now. plen indicates how much we are sending now. use it to
 		 * derive pi len for the pdu. */
		if (sc->lsc_sc_protsgl.sgl_vecs_nr) {
			unsigned int r_pi_len = 0, sgcnt;

			pi_offset = (rcb->r_offset >> lu_sect_shift) << 3;
			pi_len = (plen >> lu_sect_shift) << 3;

			/* seek pi_offset in sc->lsc_sc_protsgl */
			prot_sg = (chiscsi_sgvec *) sc->lsc_sc_protsgl.sgl_vecs;
			sgcnt = sc->lsc_sc_protsgl.sgl_vecs_nr;
			pi_sg_offset = pi_offset;
			for (; prot_sg && sgcnt; prot_sg = prot_sg->sg_next) {
				if (pi_sg_offset < prot_sg->sg_length) {
					pi_sg_offset += prot_sg->sg_offset;
					break;
				}
				sgcnt--;
				pi_sg_offset -= prot_sg->sg_length;
			}
			if (!prot_sg) {
				os_log_error("sc R itt 0x%x, Expecting pi but not pi not present\n",
						sc->sc_itt);
				goto no_pi; /* T10DIF TODO */
			}

			/* pi_sg_offset is pointing to the beginning of pi
 			 * in prot_sg for the current pdu */
			/* Count how many nvecs needed for pi_len */
			if (pi_len <= (os_page_size - pi_sg_offset))
				prot_nvecs = 1;
			else {
				r_pi_len = pi_len -
					(os_page_size - pi_sg_offset);
				prot_nvecs = 1 +
					((r_pi_len + os_page_size -1) >> \
						os_page_shift);
			}
		}
no_pi:
		pdu = iscsi_pdu_get(conn, nvecs + prot_nvecs, 0, 0);
                if (!pdu) {
			os_log_error("sc R data-in pdu nvecs %u OOM.\n", nvecs);
			return -ISCSI_ENOMEM;
		}
		pdu->p_saveq = sc->sc_queue[CH_SCMD_PDU_SENTQ];

		pdu->p_sgcnt_used = nvecs + prot_nvecs;

		if (sgmax) {
			int i;

			sg = rcb->r_sg;
			dlen = sg->sg_length - sgoff;
			memcpy(&pdu->p_sglist[0], sg, sizeof(chiscsi_sgvec));
			pdu->p_sglist[0].sg_length = dlen;
			pdu->p_sglist[0].sg_offset += sgoff;
			if (sg->sg_addr)
				pdu->p_sglist[0].sg_addr += sgoff;
			if (sg->sg_dma_addr)
				pdu->p_sglist[0].sg_dma_addr += sgoff;

			for (i = 1; i < nvecs; i++) {
				sgoff = 0;
				sg = sg->sg_next;
				dlen += sg->sg_length;
				memcpy(&pdu->p_sglist[i], sg,
					sizeof(chiscsi_sgvec));
			}

			/* last vec not used up */
			if (dlen > plen) {
				nvecs--;
				pdu->p_sglist[nvecs].sg_length -= dlen - plen;
				sgoff += pdu->p_sglist[nvecs].sg_length;
				rcb->r_sg = sg;
			} else {
				sgoff = 0;
				rcb->r_sg = sg->sg_next;
			}

			/* Copy pi sg in pdu->p_sglist */
			if (prot_nvecs) {
				unsigned int copied_len;

				if (dlen > plen)
					nvecs++;

				memcpy(&pdu->p_sglist[nvecs], prot_sg,
							sizeof(chiscsi_sgvec));

				copied_len = MINIMUM(pi_len,
					(os_page_size - pi_sg_offset));
				pdu->p_sglist[nvecs].sg_length =
						copied_len;
				pdu->p_sglist[nvecs].sg_offset = pi_sg_offset;
				if (prot_sg->sg_addr)
					pdu->p_sglist[nvecs].sg_addr +=
						(pi_sg_offset - prot_sg->sg_offset);
				if (prot_sg->sg_dma_addr)
					pdu->p_sglist[nvecs].sg_dma_addr +=
						(pi_sg_offset - prot_sg->sg_offset);

				/* Copy remaining prot_sg and  modify last sg
 				 * to adjust sg length */
				for (i = 1; i < prot_nvecs; i++) {
					prot_sg = prot_sg->sg_next;
					copied_len += prot_sg->sg_length;
					memcpy(&pdu->p_sglist[i + nvecs], prot_sg,
						sizeof(chiscsi_sgvec));
				}
				if (copied_len > pi_len) {
					/* last vector is not completely used */
					pdu->p_sglist[nvecs + prot_nvecs - 1].
						sg_length -= (copied_len - pi_len);
				}

				/* fill-in other pi fields in pdu */
				memcpy(&pdu->pi_info, &sc->pi_info,
					sizeof(struct cxgbi_pdu_pi_info));
				pdu->pi_info.pi_sgcnt = prot_nvecs;
				pdu->pi_info.pi_len = pi_len;
				pdu->pi_info.ref_tag = sc->sc_lba;
				pdu->pi_info.pi_offset = pi_offset;
			}
		} else {
			/* linear buffer */
			pdu->p_sglist[0].sg_addr =
				(unsigned char *)sc->sc_sgl.sgl_vecs + sgoff;
                        pdu->p_sglist[0].sg_length = plen;
			sgoff += plen;
		}

		pdu->p_opcode = ISCSI_OPCODE_SCSI_DATA_IN;
		pdu->p_sn = conn->c_statsn;
		pdu->p_pdulen = mpdu;

		SET_PDU_OPCODE(pdu, ISCSI_OPCODE_SCSI_DATA_IN);
		if (sc->pi_info.prot_op == ISCSI_PI_OP_SCSI_PROT_WRITE_PASS)
			SET_PDU_DATA_SEGMENT_LENGTH(pdu, (plen + pi_len));
		else
			SET_PDU_DATA_SEGMENT_LENGTH(pdu, plen);
		SET_PDU_LUN(pdu, sc->sc_lun);
		SET_PDU_ITT(pdu, sc->sc_itt);
		SET_PDU_TTT(pdu, ISCSI_INVALID_TAG);
		SET_PDU_EXPCMDSN(pdu, sess->s_expcmdsn);
		SET_PDU_MAXCMDSN(pdu, sess->s_maxcmdsn);
		SET_PDU_DATASN(pdu, rcb->r_datasn);
		SET_PDU_BUFFER_OFFSET(pdu, rcb->r_offset);

		/* add read bytes for portal  */
		if (portal)
			portal_counter_add(portal->os_data, plen, RD_B_CTR);
		sess->s_perf_info.read_bytes += plen;

		iscsi_pdu_enqueue(nolock, sendq, pdu);

		xferlen -= plen;
		rcb->r_datasn += num_pdu;
		rcb->r_offset += plen;
		sc->sc_xfer_left -= plen;	/* required for overflow */

		if (rcb->r_offset &&
		    ((rcb->r_offset == sc->sc_xfer_len) || 
		     (rcb->r_offset % rcb->r_maxburst) == 0))
			SET_PDU_F(pdu);

		if (num_pdu > 1) {
			unsigned int fslice = !GET_PDU_BUFFER_OFFSET(pdu);
			unsigned int lslice = !!GET_PDU_F(pdu);

			/* using iso */
			pdu->p_flag |= ISCSI_PDU_FLAG_TX_ISO;
			pdu->iso_info.flags = fslice | (lslice << 1);
			pdu->iso_info.num_pdu = num_pdu;
			pdu->iso_info.mpdu = mpdu;
			/* Burst size is data remained to be sent + data len
 			 * in current iso */
			pdu->iso_info.burst_size = xferlen + plen;
			/* If DIX case, then DO NOT INCLUDE PI_LEN IN ISO */
			/* ISO DIF CASE TODO */

			/* update data lenth and iscsi hdr len in iso transfer
 			 * later when updating crc related length. i.e.
 			 * in iscsi_pdu_prepare_to_send(). Now put
 			 * only data len */
			pdu->iso_info.segment_offset =
					GET_PDU_BUFFER_OFFSET(pdu);
			pdu->iso_info.datasn_offset = 0;
			pdu->iso_info.buffer_offset = 0;
		}

		/* this is done late otherwise NIC HCRC get screwed */
		iscsi_pdu_prepare_to_send(pdu);
	}

	rcb->r_sgoffset = sgoff;
	sc->sc_xfer_cnt = rcb->r_offset;
		
data_sent:
	if ((rcb->r_offset < sc->sc_xfer_len) &&
		!(blk_len < sc->sc_xfer_len)) {

		if (sc->sc_state == CH_SC_STATE_R_XFER) {
			iscsi_connection_push_pdus(conn);
		
			if (async && !is_chelsio_lun_class(lclass))
				os_lock_irq(sc->sc_lock);

			/* If no additional execution_status has arrived 
 			 * then clear the flag*/
			maxoffset = sc->sc_sgl.sgl_boff + sc->sc_sgl.sgl_length;
			if (maxoffset == sc->sc_xfer_cnt)
				scmd_fscsi_clear_bit(sc, CH_SFSCSI_READ_BUF_BIT);

			if (async && !is_chelsio_lun_class(lclass))
			os_unlock_irq(sc->sc_lock);

			/* read buffer sent, since there is no way to check on
 			 * if the data-in pdu is received or not on the 
 			 * initiator, we send a nop-in to the initiator. Once we
 			 * receives the nop-out response, we can be sure the
 			 * data pdus are received by the initiator
 			 */
			if ((maxoffset < sc->sc_xfer_len) &&
			    !scmd_fpriv_test_bit(sc, CH_SFP_CHLU_BIT) &&
			    !scmd_fscsi_test_bit(sc, CH_SFSCSI_READ_BUF_BIT)) {
				/* use ttt so that we can verify the xfer_cnt */
				it_xmt_nop_in(conn, 1, 0, 0, rcb->r_offset,
						(void *)sc, NULL);
				os_log_debug(ISCSI_DBG_TARGET_API,
					"itt 0x%x, R, offset %u, sent nop_in.\n",
					sc->sc_itt, rcb->r_offset);
			}
		}
	} else {
		os_log_debug(ISCSI_DBG_SCSI_COMMAND,
			"itt 0x%x, R offset %u/%u + %u, -> status.\n",
			sc->sc_itt, sc->sc_xfer_cnt, sc->sc_sgl.sgl_boff,
			sc->sc_sgl.sgl_length);

		sc->sc_state = CH_SC_STATE_STATUS;

		/* piggyback the status if there is no sense data */
	    	if (pdu && sc->sc_sense_key == SCSI_SENSE_NO_SENSE) {
			uint_serial_inc(sess->s_maxcmdsn);

			SET_PDU_F(pdu);
			SET_PDU_S(pdu);
			SET_PDU_RESPONSE(pdu, sc->sc_response);
			SET_PDU_STATUS(pdu, sc->sc_status);
			uint_serial_inc(conn->c_statsn);
			sc->sc_statsn = conn->c_statsn;
			SET_PDU_STATSN(pdu, sc->sc_statsn);

			if ((rcb->r_offset < sc->sc_xfer_len) &&
				(blk_len < sc->sc_xfer_len)) {
				sc->sc_xfer_residualcount = 
					sc->sc_xfer_len - blk_len;
				sc->sc_flag |= SC_FLAG_XFER_UNDERFLOW;
			}

			SET_PDU_RESIDUAL_COUNT(pdu, sc->sc_xfer_residualcount);
			if (sc->sc_flag & SC_FLAG_XFER_OVERFLOW)
				SET_PDU_O(pdu);
			else if (sc->sc_flag & SC_FLAG_XFER_UNDERFLOW)
				SET_PDU_U(pdu);

			os_log_debug(ISCSI_DBG_SCSI_COMMAND,
				"itt 0x%x, R, piggy back status -> DONE.\n",
				sc->sc_itt);

			/* header CRC needs to be recalculated */
			iscsi_pdu_prepare_to_send(pdu);

			iscsi_connection_push_pdus(conn);
			sc->sc_state = CH_SC_STATE_DONE;

		} else {
			os_log_debug(ISCSI_DBG_SCSI_COMMAND,
				"itt 0x%x, R, new status pdu -> DONE.\n",
				sc->sc_itt);

			iscsi_connection_push_pdus(conn);
			/* send out status pdu */
			rv = it_scmd_send_sense_status(sc);	
			sc->sc_state = CH_SC_STATE_DONE;
		}
	}

	return rv;
}

void it_scmd_read_buffer_acked(chiscsi_scsi_command *sc, unsigned int ttt)
{
	chiscsi_scsi_read_cb *rcb = &sc->sc_cb.rcb;

	os_log_debug(ISCSI_DBG_TARGET_API,
		"%s itt 0x%x, xfer acked 0x%lx\n",
			__func__, sc->sc_itt, rcb->r_acked);
	rcb->r_acked = ttt;
	it_scmd_release_backend_buffers(sc, rcb->r_acked);
}

int it_scmd_read_continue(chiscsi_scsi_command *sc)
{
	chiscsi_target_lun_class *lclass = sc->lu_class;
	int async = scmd_fpriv_test_bit(sc, CH_SFP_LU_QUEUE_BIT) ? 1 : 0;
	int passthru = 0;
	chiscsi_scsi_read_cb *rcb = &sc->sc_cb.rcb;
	chiscsi_sgl *sc_sgl = &sc->sc_sgl;
	int rv = 0;

	if (scmd_fpriv_test_bit(sc, CH_SFP_LU_PASSTHRU_BIT) ||
	    (sc->sc_flag & SC_FLAG_PASSTHRU))
		passthru = 1;

	os_log_debug(ISCSI_DBG_SCSI_COMMAND,
		"sc 0x%p, R, itt 0x%x, flag 0x%x, state 0x%x, f 0x%x,0x%x.\n",
		sc, sc->sc_itt, sc->sc_flag, sc->sc_state, sc->sc_fscsi,
		sc->sc_fpriv);

	if (sc->sc_state != CH_SC_STATE_CLOSED && sc->sc_state != CH_SC_STATE_DONE) {
		if (sc->sc_flag & SC_FLAG_TMF_ABORT)
			iscsi_target_scsi_command_check_tmf_condition(sc);
		else if (!sc->sc_status && sc->sc_state < CH_SC_STATE_STATUS) {
			it_scmd_exe_check_error(sc);
		}
		if (sc->sc_status && sc->sc_state < CH_SC_STATE_STATUS) {
			os_log_debug(ISCSI_DBG_SCSI_COMMAND,
				"sc 0x%p itt 0x%x, R, 0x%x, s %d->STATUS, 0x%x,0x%lx,0x%lx.\n",
				sc, sc->sc_itt, sc->sc_status, sc->sc_state,
				sc->sc_flag, sc->sc_fscsi, sc->sc_fpriv);

			sc->sc_state = CH_SC_STATE_STATUS;
			sc->sc_xfer_len = sc->sc_xfer_left = 0;
		}
	}

	switch(sc->sc_state) {
	case CH_SC_STATE_CLOSED:	
		break;
	case CH_SC_STATE_INITIALIZED:
		break;
	case CH_SC_STATE_EXE_READY:
		if ( scmd_fpriv_test_bit(sc, CH_SFP_RWIO_BIT) || 
		     (sc->sc_flag & SC_FLAG_PASSTHRU) ||
		     ( scmd_fpriv_test_bit(sc, CH_SFP_LU_PASSTHRU_BIT) &&
		       !(scmd_fpriv_test_bit(sc, CH_SFP_LU_TYPE_SCST_BIT) &&
			(sc->sc_cmd[0] == SCSI_OPCODE_REPORT_LUNS)) ) ) {
			os_log_debug(ISCSI_DBG_SCSI_COMMAND,
				"sc itt 0x%x, R, rwio exe_ready -> executing.\n",
				sc->sc_itt);

			if (async && !is_chelsio_lun_class(lclass)) os_lock_irq(sc->sc_lock);	
			sc->sc_state = CH_SC_STATE_EXECUTING;
			scmd_fscsi_set_bit(sc, CH_SFSCSI_HOLD_BIT);
			scmd_fscsi_clear_bit(sc, CH_SFSCSI_EXECUTED_BIT);
			if (async && !is_chelsio_lun_class(lclass)) os_unlock_irq(sc->sc_lock);
			//os_debug_msg("R itt 0x%x, call fp_cdb_rcv.\n", sc->sc_itt);
			scmd_set_timestamp(sc, CH_SCMD_TM_FP_CDB_RCVED);

			os_log_debug(ISCSI_DBG_TARGET_API,
				"%s: fp_cdb_rcvd, sc 0x%p, sn 0x%x, itt 0x%x.\n",
				__func__, sc, sc->sc_cmdsn, sc->sc_itt);

			rv = lclass->fp_scsi_cmd_cdb_rcved(sc);
			if (rv < 0) {
				scmd_fscsi_clear_bit(sc, CH_SFSCSI_HOLD_BIT);
				sc_rw_error(sc);
                        }
		} else {
			os_log_debug(ISCSI_DBG_SCSI_COMMAND,
				"sc itt 0x%x, R, non-rwio exe_ready -> executing.\n",
				sc->sc_itt);

			iscsi_target_lu_scsi_non_rwio_cmd_respond(sc);
			sc->sc_state = CH_SC_STATE_R_XFER;
			iscsi_target_scsi_command_done(sc, 0);
		}
		break;
	case CH_SC_STATE_EXECUTING:
		/* wait for read to be executed */
		if (async && !is_chelsio_lun_class(lclass)) os_lock_irq(sc->sc_lock);	
		if (scmd_fscsi_test_bit(sc, CH_SFSCSI_EXECUTED_BIT)) {
			os_log_debug(ISCSI_DBG_SCSI_COMMAND,
				"sc itt 0x%x, R, executing -> xfer_ready.\n",
				sc->sc_itt);

			scmd_fscsi_clear_bit(sc, CH_SFSCSI_EXECUTED_BIT);
			scmd_fscsi_set_bit(sc, CH_SFSCSI_BUF_READY_BIT);
			sc->sc_state = CH_SC_STATE_R_XFER;
			if (async && !is_chelsio_lun_class(lclass)) os_unlock_irq(sc->sc_lock);
			/* fall through to CH_SC_STATE_R_XFER */
			goto sc_state_xfer;
		} else {
			//os_debug_msg("sc itt 0x%x, R, executing ...\n", sc->sc_itt);
			if (async && !is_chelsio_lun_class(lclass)) os_unlock_irq(sc->sc_lock);
		}
		break;
	case CH_SC_STATE_R_XFER:
sc_state_xfer:
		/* new read buffers available */
		/* CH_SFSCSI_READ_BUF_BIT is set only for ALL passthru cmds
		   chelsio devices types handle non-rw io cmds hence dont set it*/
		if (((passthru && (rcb->r_offset <= (sc_sgl->sgl_boff + sc_sgl->sgl_length)) &&
				scmd_fscsi_test_bit(sc, CH_SFSCSI_READ_BUF_BIT)) || 
				((rcb->r_offset <= (sc_sgl->sgl_boff + sc_sgl->sgl_length)) &&
				!passthru)) || 
				(sc->sc_cmd[0] == SCSI_OPCODE_REPORT_LUNS)){
			os_log_debug(ISCSI_DBG_SCSI_COMMAND,
				"sc itt 0x%x, R, xfer new read buffer, %u <= %u+%u.\n",
				sc->sc_itt, rcb->r_offset, sc_sgl->sgl_boff,
				sc_sgl->sgl_length);

			/* this enables scsi responses having data and
			 * sense to go through. This happens with tapes.
			 */
			if (!sc->sc_sgl.sgl_vecs) {
				iscsi_target_scsi_command_check_execution_status(sc);

				if (sc->sc_sense_key != SCSI_SENSE_NO_SENSE) {
					sc->sc_xfer_len = sc->sc_xfer_left = 0;
					sc->sc_state = CH_SC_STATE_STATUS;
				}
			}

			iscsi_target_scsi_command_check_tmf_condition(sc);

			if (sc->sc_state == CH_SC_STATE_STATUS)
				goto sc_state_status;
			else if (sc->sc_state == CH_SC_STATE_DONE)
				goto sc_state_done;

			rv = it_scmd_read_send_data_in_pdus(sc);
			if (!rv) {
				if (sc->sc_state == CH_SC_STATE_STATUS)
					goto sc_state_status;
				else if (sc->sc_state == CH_SC_STATE_DONE)
					goto sc_state_done;
			}
		}
		break;
	case CH_SC_STATE_STATUS:
sc_state_status:
		rv = it_scmd_send_sense_status(sc);	
		sc->sc_state = CH_SC_STATE_DONE;
		break;
	case CH_SC_STATE_DONE:
sc_state_done:
		if (scmd_fscsi_test_bit(sc, CH_SFSCSI_STATUS_ACKED_BIT))
			it_scmd_acked(sc);
		break;
default:
		return -ISCSI_EINVAL;
	}
	return rv;
}
