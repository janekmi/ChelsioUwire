/*
 * iscsi scsi command managment
 */

#include <iscsi_target_api.h>
#include "iscsi_target_private.h"
#include <common/iscsi_target_notif.h>

void it_scmd_acked(chiscsi_scsi_command *sc)
{
	iscsi_session *sess = sc->sc_sess;
	chiscsi_queue *scq = sess->s_queue[SESS_SCMDQ_NEW];

	os_log_debug(ISCSI_DBG_SCSI_COMMAND,
		"%s:%s, itt 0x%x,%u, f 0x%x, done -> closed.\n",
		sess->s_node ? sess->s_node->n_name : "?", sess->s_peer_name,
		sc->sc_itt, sc->sc_idx, sc->sc_flag);

	/* If cmd abort called by backend, send abort status*/
	it_scmd_release_backend_buffers(sc, sc->sc_xfer_cnt);
	
	scmd_set_timestamp(sc, CH_SCMD_TM_STATE_2_CLOSED);
	sc->sc_state = CH_SC_STATE_CLOSED;
	scmd_ch_qremove(nolock, scq, sc);

	os_lock_irq(sc->sc_lock);
	if (scmd_fpriv_test_bit(sc, CH_SFP_LU_SCSI_RELEASE_WAIT))
		sc->sc_flag |= SC_FLAG_RELEASE_WAIT;
	os_unlock_irq(sc->sc_lock);

	chiscsi_scsi_command_release(sc, sess->s_queue[SESS_SCMDQ_FREE]);
}

int it_scmd_state_abortable(chiscsi_scsi_command *sc)
{
        switch (sc->sc_state) {
                /*abortable states*/
                case CH_SC_STATE_CLOSED:
                case CH_SC_STATE_INITIALIZED:
                        return 1;
                /*All others non abortable */
                default:
                        return 0;
        }
}

int iscsi_target_pdu_scsi_command_bhs_rcv(iscsi_pdu *pdu)
{
	iscsi_connection *conn = pdu->p_conn;
	iscsi_session *sess = conn->c_sess;
	iscsi_node *node;
	chiscsi_target_lun_class *lclass;
	chiscsi_scsi_command *sc = NULL;
	chiscsi_queue *q;
	iscsi_portal *portal = conn->c_portal;
	unsigned int itt = GET_PDU_ITT(pdu);
	unsigned int xferlen = GET_PDU_DATA_XFER_LENGTH(pdu);
	int read = GET_PDU_R(pdu);
	int rv = 0;

	if (conn->c_state != CONN_STATE_FFP) {
		os_log_info("itt 0x%x, conn state not FFP, %d.\n",
			itt, conn->c_state);
		goto err_out;
	}
	node = sess->s_node;

	q = sess->s_queue[SESS_SCMDQ_NEW];
	/* validate parameters */
	if (itt == ISCSI_INVALID_TAG) {
		os_log_info("%s:%s, invalid itt 0x%x, reject.\n",
			node ? node->n_name : "?", sess->s_peer_name, itt);
		rv = iscsi_target_xmt_reject(pdu,
			ISCSI_REJECT_REASON_INVALID_PDU_FIELD);
		pdu->p_flag |= ISCSI_PDU_FLAG_REJECT;
		goto err_out;
	}

	if (!GET_PDU_F(pdu) && !GET_PDU_W(pdu)) {
		os_log_info("%s:%s, itt 0x%x: no F or W set, reject.\n",
			node ? node->n_name : "?", sess->s_peer_name, itt);
		rv = iscsi_target_xmt_reject(pdu,
			ISCSI_REJECT_REASON_PROTOCOL_ERROR);
		pdu->p_flag |= ISCSI_PDU_FLAG_REJECT;
		goto err_out;
	}

	if (!read && !GET_PDU_W(pdu) && xferlen) {
		os_log_info("%s:%s, itt 0x%x: no R/W, ignore xfer %u.\n",
			node ? node->n_name : "?", sess->s_peer_name, itt,
			xferlen);
		xferlen = 0;
	}

	/* bi-directional not supported */
	if (read && (GET_PDU_W(pdu))) {
		os_log_info("%s:%s, itt 0x%x: bidirectional, reject.\n",
			node ? node->n_name : "?", sess->s_peer_name, itt);
		rv = iscsi_target_xmt_reject(pdu,
			 ISCSI_REJECT_REASON_CMD_NOT_SUPPORTED);
		pdu->p_flag |= ISCSI_PDU_FLAG_REJECT;
		goto err_out;
	}


	sc = chiscsi_scsi_command_alloc(conn, xferlen);
	if (!sc) {
		os_log_info("%s:%s, itt 0x%x, sess 0x%p, OOM.\n",
			node ? node->n_name : "?", sess->s_peer_name,
			itt, sess);
		iscsi_pdu_display((void *) pdu, NULL, 0, 1);
		return -ISCSI_ENOMEM;
	}

	/* save the pdu until session thread get a chance to look at it */
	scmd_set_timestamp(sc, CH_SCMD_TM_STATE_2_CLOSED);
	sc->sc_state = CH_SC_STATE_CLOSED;
	sc->sc_sock = conn->c_isock;
	sc->sc_sess = sess;
	sc->sc_tclass_sess_priv = sess->s_tclass_sess_priv;
	 /* copy is required since struct iscsi_session is not public */
	sc->pthru_sess = sess->scst_session;
	sc->sc_conn = conn;
	sc->sc_ieps = &conn->c_isock->s_tcp;
	sc->sc_offload_pdev = os_socket_get_offload_pci_device(sc->sc_sock);
	sc->sc_thp_id = (unsigned char)thread_id(sess->s_thinfo.thp->th_common);
	sc->sc_cmdsn = GET_PDU_CMDSN(pdu);
	sc->sc_itt = itt;
	sc->sc_lun = GET_PDU_LUN(pdu);
	sc->sc_xfer_len = sc->sc_xfer_left = xferlen;
	sc->sc_cmdlen = 16;
	memcpy(sc->sc_cmd, GET_PDU_CDB_DATA_PTR(pdu), 16);
	if (GET_PDU_I(pdu))
		sc->sc_flag |= SC_FLAG_IMMEDIATE_CMD;
	scmd_set_timestamp(sc, CH_SCMD_TM_BHS_RCVED);

	if (conn->c_isock->s_mode & ISCSI_OFFLOAD_MODE_T10DIX)
		sc->sc_flag |= SC_FLAG_T10DIX;

	rv = iscsi_acl_scsi_command_check(sc);	
	if (rv < 0)
		goto err_out;
	if (sc->sc_flag & SC_FLAG_LUN_OOR) {
		int lun = node->lu_cnt;
		/*
		 * If scst is registered, then obtain scst's target class
		 * from one of the scst lun.
		 */
		if (node->scst_target)
			for (lun=0; lun<node->lu_cnt; lun++)
				if (node->lu_list[lun]->class->property &
						(1 << LUN_CLASS_TYPE_SCST_BIT))
					break;
		if (lun<node->lu_cnt)
			sc->lu_class = lclass = node->lu_list[lun]->class;
		else
			sc->lu_class = lclass =
				chiscsi_target_lun_class_default( node->tclass);

		if (!(lclass->property & (1 << LUN_CLASS_SCSI_PASS_THRU_BIT))) {
			os_log_info( "%s:%s, itt 0x%x, lun OOR %u,%u/%u, op 0x%x.\n",
				node->n_name, sess->s_peer_name, itt,
				sc->sc_lun, sc->sc_lun_acl, node->lu_cnt,
				sc->sc_cmd[0]);

			if (sc->sc_cmd[0] == SCSI_OPCODE_INQUIRY) {
				sc->sc_lun = sc->sc_lun_acl = 0;
				//sc->sc_flag &= ~SC_FLAG_LUN_OOR;
			}
		}
	} else
		sc->lu_class = lclass = node->lu_list[sc->sc_lun_acl]->class;

	if (!lclass) {
		os_log_error( "%s:%s, itt 0x%x, no lun class %u,%u/%u, op 0x%x.\n",
				node->n_name, sess->s_peer_name, itt,
				sc->sc_lun, sc->sc_lun_acl, node->lu_cnt,
				sc->sc_cmd[0]);
		rv = -ISCSI_EINVAL;
		goto err_out;
	}

	if (lclass->property & (1 << LUN_CLASS_HAS_CMD_QUEUE_BIT))
		scmd_fpriv_set_bit(sc, CH_SFP_LU_QUEUE_BIT);
	if (lclass->property & (1 << LUN_CLASS_SCSI_PASS_THRU_BIT))
		scmd_fpriv_set_bit(sc, CH_SFP_LU_PASSTHRU_BIT);
	if (lclass->property & (1 << LUN_CLASS_MULTI_PHASE_DATA_BIT))
		scmd_fpriv_set_bit(sc, CH_SFP_LU_MULTIPHASE_BIT);
	if (lclass->property & (1 << LUN_CLASS_TYPE_SCST_BIT))
		scmd_fpriv_set_bit(sc, CH_SFP_LU_TYPE_SCST_BIT);
	if (lclass->property & (1 << LUN_CLASS_CMD_RELEASE_WAIT_BIT))
		scmd_fpriv_set_bit(sc, CH_SFP_LU_SCSI_RELEASE_WAIT);

	if (!(sc->sc_flag & SC_FLAG_LUN_OOR)) {
		if (lclass->property & (1 << LUN_CLASS_CHELSIO_BIT))
			scmd_fpriv_set_bit(sc, CH_SFP_CHLU_BIT);

		if (!(lclass->property & (1 << LUN_CLASS_SCSI_PASS_THRU_BIT))) {
			/* parse the cdb for sector info. */
			it_chelsio_target_check_opcode(sc);

			if (scmd_fpriv_test_bit(sc, CH_SFP_RWIO_BIT) &&
			    chiscsi_target_lun_flag_test(
						node->lu_list[sc->sc_lun_acl],
						LUN_NULLRW_BIT))
				/* no allocation if lun configured NULLRW */
				scmd_fpriv_set_bit(sc, CH_SFP_CHLU_SINK_BIT);

			if (scmd_fpriv_test_bit(sc, CH_SFP_PROT_BIT)) {
				/* Command needs pi */
				sc->sc_flag |= SC_FLAG_T10DIF;
			}
		}
	}
	if (scmd_fpriv_test_bit(sc, CH_SFP_PROT_BIT)) {
		/* It means xferlen includes number of pi bytes. Lets continue
		 * doing all calculations only on data bytes because, we add
		 * appropriate number of pi bytes later. */
		unsigned int num_sector = xferlen/((1 << lu_sect_shift) + 8);
		/* How many pi bytes in xferlen? */
		xferlen -= (num_sector << 3);
		sc->sc_xfer_len = sc->sc_xfer_left = xferlen;
	}

	/* if neither read nor write, mark as read to move to respond state */
	if (GET_PDU_W(pdu)) {
		sc->sc_flag |= SC_FLAG_WRITE;
	
                /* increment the write_command counter for this portal */
		if (portal)
			portal_counter_inc(portal->os_data, WR_CMD_CTR);
		sess->s_perf_info.write_cmd_cnt++;

		rv = it_scmd_write_init(sc, pdu);
	} else {
		sc->sc_flag |= SC_FLAG_READ;
	
                /* increment the read_command counter for this portal */
		if (portal)
			portal_counter_inc(portal->os_data, RD_CMD_CTR);
		sess->s_perf_info.read_cmd_cnt++;

		rv = it_scmd_read_init(sc);
	} 

	if (rv < 0 || (pdu->p_flag & ISCSI_PDU_FLAG_REJECT)) {
		os_log_info("%s:%s, itt 0x%x: pdu 0x%p, prep %d, f 0x%x.\n",
			node->n_name, sess->s_peer_name, itt, pdu, rv,
			pdu->p_flag);
		goto err_out;
	}

	if (scmd_fpriv_test_bit(sc, CH_SFP_XFER_ERR_BIT)) {
		pdu->p_flag |= ISCSI_PDU_FLAG_DATA_SKIP;
		goto done;
	}

	scmd_set_timestamp(sc, CH_SCMD_TM_STATE_2_INIT);
	sc->sc_state = CH_SC_STATE_INITIALIZED;

	os_log_debug(ISCSI_DBG_SCSI_COMMAND,
			"%s:%s, task 0x%p, 0x%x, f 0x%x, state -> INITIALIZED.\n",
			node->n_name, sess->s_peer_name, sc, sc->sc_itt,
			sc->sc_flag);

	it_scmd_lun_check_error(sc, 0);
	if (sc->sc_status) {
		pdu->p_flag |= ISCSI_PDU_FLAG_DATA_SKIP;
		goto done;
	}

	/*
	 * for read, the next step is read execution,
	 * so do it in session thread to maintain the scsi command sequence 
	 */
	if (sc->sc_flag & SC_FLAG_READ) {
		os_log_debug(ISCSI_DBG_SCSI_COMMAND,
			"%s:%s, task 0x%p, 0x%x, read initialized -> exe_ready.\n",
			node->n_name, sess->s_peer_name, sc, sc->sc_itt);
		scmd_set_timestamp(sc, CH_SCMD_TM_STATE_2_EXE_READY);
		sc->sc_state = CH_SC_STATE_EXE_READY;
	}
	
	/* for write, get the buffer from the storage driver ASAP */
	if ((sc->sc_flag & SC_FLAG_WRITE) &&
	    ((sc->sc_flag & SC_FLAG_PASSTHRU) ||
	     scmd_fpriv_test_bit(sc, CH_SFP_RWIO_BIT) ||
	     scmd_fpriv_test_bit(sc, CH_SFP_LU_PASSTHRU_BIT))) {
		rv = it_scmd_write_continue(sc);
                if (rv < 0) {
			os_log_info("%s:%s, itt 0x%x, W %u, backend %d,0x%x.\n",
				node->n_name, sess->s_peer_name,
				sc->sc_itt, xferlen, rv, sc->sc_status);
			/* Check if status is set by backend already. */
			if (sc->sc_status) {
				pdu->p_flag |= ISCSI_PDU_FLAG_DATA_SKIP;
				goto done;
			}
                        goto err_out;
		}
                goto done;
        }

	if (sc->sc_xfer_len &&
	    !scmd_fpriv_test_bit(sc, CH_SFP_RWIO_BIT) &&
	    !(sc->sc_flag & SC_FLAG_PASSTHRU) &&
	    (!scmd_fpriv_test_bit(sc, CH_SFP_LU_PASSTHRU_BIT) ||
	     (scmd_fpriv_test_bit(sc, CH_SFP_LU_TYPE_SCST_BIT) &&
	      sc->sc_cmd[0] == SCSI_OPCODE_REPORT_LUNS))) {
		/* allocate the buffer ourselves */
		scmd_fpriv_set_bit(sc, CH_SFP_BUF_LOCAL_BIT);
		rv = chiscsi_scsi_command_allocate_local_data(sc);
		if (rv < 0) {
			os_log_info("%s:%s, itt 0x%x, %u, local OOM.\n",
				node->n_name, sess->s_peer_name,
				sc->sc_itt, xferlen);
			goto err_out;
		}

		os_log_debug(ISCSI_DBG_SCSI_COMMAND,
			"%s:%s, itt 0x%x, non-rwio initialized -> exe_ready.\n",
			node->n_name, sess->s_peer_name, sc->sc_itt);
		scmd_set_timestamp(sc, CH_SCMD_TM_STATE_2_EXE_READY);
		sc->sc_state = CH_SC_STATE_EXE_READY;
	}

done:
	scmd_enqueue_by_cmdsn(nolock, q, sc);
	pdu->p_scmd = sc;

	/* set up the data buffer */
	if (pdu->p_datalen && !sc->sc_status) {
		if (scmd_fpriv_test_bit(sc, CH_SFP_CHLU_SINK_BIT)) {
			pdu->p_flag |= ISCSI_PDU_FLAG_DATA_SKIP;
			return 0;
		} else if (sc->sc_sgl.sgl_vecs) {

			/* Setup pi buffer */
			if (pdu->p_flag & ISCSI_PDU_FLAG_PI_RCVD) {
				chiscsi_sgvec *sgl = (chiscsi_sgvec *)sc->\
						lsc_sc_protsgl.sgl_vecs;
				if (pdu->p_flag & ISCSI_PDU_FLAG_PI_DDPD)
					goto continue_data;
				if (pdu->p_flag & ISCSI_PDU_FLAG_PI_ERR) {
					os_log_error("%s: "
					   "pi err in rcvd data\n", __func__);
					/* T10DIF TODO send check condition */
				}
				pdu->pi_info.interval = sc->pi_info.interval;
				pdu->pi_info.guard = sc->pi_info.guard;
				if (conn->difdix_mode &
					ISCSI_OFFLOAD_T10DIXDIF) /* DIF */
					pdu->pi_info.prot_op =
						ISCSI_PI_OP_SCSI_PROT_READ_PASS;
				else /* DIX */
					pdu->pi_info.prot_op =
					      ISCSI_PI_OP_SCSI_PROT_READ_INSERT;

				iscsi_pdu_pi_sglist_setup_by_offset(pdu, 0, sgl,
					sc->lsc_sc_protsgl.sgl_vecs_nr);
			}
continue_data:
			rv = iscsi_pdu_sglist_setup_by_offset(pdu, 0,
				(chiscsi_sgvec *)sc->sc_sgl.sgl_vecs,
				sc->sc_sgl.sgl_vecs_nr);
			if (rv < 0) {
				os_log_error("%s:%s, itt 0x%x, %u/%u, no pdu buf.\n",
					node->n_name, sess->s_peer_name, itt,
					pdu->p_datalen, xferlen);
				chiscsi_scsi_command_display(sc, 1);
				scmd_ch_qremove(nolock, q, sc);
				goto err_out;
			}	
		} else
			os_log_warn("%s:%s, itt 0x%x, pdu len %u, no buf.\n",
				node->n_name, sess->s_peer_name, sc->sc_itt,
				pdu->p_datalen);

		if (!pdu->p_sgcnt_used) {
                        pdu->p_flag |= ISCSI_PDU_FLAG_LOCKED;
                        return (iscsi_pdu_alloc_data_buffer(pdu, pdu->p_datalen));
                }
	}
	return 0;

err_out:
	if (sc)
		chiscsi_scsi_command_release(sc, sess->s_queue[SESS_SCMDQ_FREE]);
	pdu->p_scmd = NULL;
	pdu->p_flag |= ISCSI_PDU_FLAG_DATA_SKIP;
	return rv;
}

int iscsi_target_rcv_scsi_command(iscsi_pdu *pdu)
{
	chiscsi_scsi_command *sc = pdu->p_scmd;

	if (!sc) {
		os_log_info("scsi_cmd pdu 0x%p, sc NULL.\n", pdu, sc);
		return -ISCSI_ENOMEM;
	}

	/* handle data digset error? */
	if (pdu->p_flag & ISCSI_PDU_FLAG_ERR_DATA_DIGEST) {
		scmd_fpriv_set_bit(sc, CH_SFP_XFER_ERR_BIT);
		sc_data_digest_error(sc);
		return 0;
	}

	/* being aborted, skip execution */
        if (pdu->p_flag & ISCSI_PDU_FLAG_TMF_ABORT) {
		iscsi_session *sess = sc->sc_sess;
		iscsi_node *node = sess ? sess->s_node : NULL;

		sc->sc_flag |= SC_FLAG_TMF_ABORT;
		if (pdu->p_flag & ISCSI_PDU_FLAG_TMF_SENSE)
			scmd_fpriv_set_bit(sc, CH_SFP_TMF_SENSE_BIT);

		//os_log_debug(ISCSI_DBG_SCSI_COMMAND,
		os_log_info(
			"%s:%s, sess 0x%p, 0x%p, itt 0x%x, lun %u, TMF abort.\n",
			node ? node->n_name : "?",
			sess ? sess->s_peer_name : "?", sess, sc, sc->sc_itt,
			sc->sc_lun);
		return 0;
	} 

	/* ??? could it be possible that sc == NULL here ??? */

	if (sc->sc_flag & SC_FLAG_WRITE) {
		/* write */
		if (pdu->p_flag & ISCSI_PDU_FLAG_LOCKED) {
			chiscsi_queue *pduq = (chiscsi_queue *)sc->sc_queue[CH_SCMD_PDUQ];
			iscsi_pdu_enqueue_by_offset(nolock, pduq, pdu);
		}

		/* only has immediate data? */
		if (sc->sc_xfer_cnt == sc->sc_xfer_len)
			iscsi_target_write_burst_complete(sc);
	} 
	return 0;
}

/*
 * execute
 */
#define ISCSI_SESSION_RESCAN_WAIT_CMD_MAX	100
static int it_lu_check_rescan_needed(chiscsi_scsi_command *sc)
{
	iscsi_session *sess = sc->sc_sess;
	unsigned char opcode = sc->sc_cmd[0];

	if (!iscsi_sess_flag_test(sess, SESS_FLAG_DEVICE_RESCAN_BIT))
		return 0;

	if (SCSI_RESCAN_CMD(opcode)) {
		iscsi_sess_flag_clear(sess, SESS_FLAG_DEVICE_RESCAN_BIT);
		sess->s_counter = 0;
		return 0;
	} else if (opcode == SCSI_OPCODE_REQUEST_SENSE) {
		sc_luns_changed(sc);
		sc->sc_status = SCSI_STATUS_GOOD;
		iscsi_sess_flag_clear(sess, SESS_FLAG_DEVICE_RESCAN_BIT);
		return 1;
	} else if (opcode == SCSI_OPCODE_RELEASE_6 ||
		   opcode == SCSI_OPCODE_RELEASE_10) {
		/* let release pass */
		return 0;
	} else {
		sess->s_counter++;
		if (sess->s_counter >= ISCSI_SESSION_RESCAN_WAIT_CMD_MAX) {
			os_log_debug(ISCSI_DBG_SCSI_COMMAND,
				"%s:%s, lun need rescan, rcv %u > %u cmd.\n",
				sess->s_node ? sess->s_node->n_name : "?",
				sess->s_peer_name, sess->s_counter,
				ISCSI_SESSION_RESCAN_WAIT_CMD_MAX);
			iscsi_sess_flag_set(sess, SESS_FLAG_CLOSE_BIT);
		}
		sc_luns_changed(sc);
		iscsi_sess_flag_clear(sess, SESS_FLAG_DEVICE_RESCAN_BIT);
		return 1;
	}
}

static int it_lu_check_lun_offline(chiscsi_scsi_command *sc, chiscsi_target_lun *lu)
{
	unsigned char opcode = sc->sc_cmd[0];

	if (SCSI_NOLUN_CMD(opcode))
		return 0;

	if (chiscsi_target_lun_flag_test(lu, LUN_OFFLINE_BIT)) {
		sc_luns_changed(sc);
		return 1;
	}

	return 0;
}

static int it_lu_check_reservation_conflict(chiscsi_scsi_command *sc, chiscsi_target_lun *lu)
{
	iscsi_session *sess = sc->sc_sess;
	int ret=0;

	if(lu->rsv.pr_type == STM_RES_PERSISTENT) {
		if((sc->sc_cmd[0] == SCSI_OPCODE_RESERVE_6)||
		   (sc->sc_cmd[0] == SCSI_OPCODE_RELEASE_6) ||
		   (sc->sc_cmd[0] == SCSI_OPCODE_RESERVE_10)||
		   (sc->sc_cmd[0] == SCSI_OPCODE_RELEASE_10))
			return 1;

		ret = stm_persistent_reserve_check(sc,lu);
		if(ret == 1)
		{
		//	sc_lun_reservation_conflict(sc);
			sc->sc_response = ISCSI_RESPONSE_COMPLETED;
			sc->sc_status = SCSI_STATUS_RESERVATION_CONFLICT;
			sc->sc_sense_key = SCSI_SENSE_NO_SENSE;
			os_log_debug(ISCSI_DBG_SCSI_COMMAND,
				"%s:%s, lu %u, reserved, itt 0x%x.\n",
				sess->s_node->n_name, sess->s_peer_name,
				sc->sc_lun, sc->sc_itt);
			return 1;
		}
		return 0;
	}

	if(lu->rsv.pr_type == STM_RES_STANDARD) {
		if (chiscsi_target_lun_flag_test(lu, LUN_RESERVED_BIT) &&
				(lu->rsv.rsvd_sess_hndl != (unsigned long)sess) &&
				(!(SCSI_CMD_ALLOWED_IN_RESERVATION(sc->sc_cmd))) ) {
			iscsi_node *node = sess->s_node;
			if(sc->sc_cmd[0] == SCSI_OPCODE_PERSISTENT_RESERVE_OUT)
				return 0;
			sc_lun_reservation_conflict(sc);
			os_log_debug(ISCSI_DBG_SCSI_COMMAND,
				"%s:%s, lu %u, reserved, itt 0x%x.\n",
				node->n_name, sess->s_peer_name, sc->sc_lun,
				sc->sc_itt);
			return 1;
		}
	}
	return 0;
}

static int it_lu_check_acl_rw_conflict(chiscsi_scsi_command *sc,
					chiscsi_target_lun *lu)
{
	if (!scmd_fpriv_test_bit(sc, CH_SFP_RWIO_BIT))
		return 0;

	if (sc->sc_flag & SC_FLAG_WRITE) {
		if (chiscsi_target_lun_flag_test(lu, LUN_RO_BIT)) {
			sc_read_only(sc);
			return 1;
		}

		if (!(sc->sc_flag & SC_FLAG_LUN_ACL_W)) {
			iscsi_session *sess = sc->sc_sess;
			iscsi_node *node = (iscsi_node *)sess->s_node;

			sc_read_only(sc);

			os_chiscsi_notify_event(CHISCSI_ACL_DENY,
				"No write permission. lun=%d, Initiator:%s, Target:%s",
				sc->sc_lun, sess->s_peer_name, node->n_name);
			return 1;
		}
	}

	return 0;
}

void it_scmd_lun_check_error(chiscsi_scsi_command *sc, int first_time)
{
	chiscsi_target_lun *lu = NULL;
	iscsi_session *sess = sc->sc_sess;
	iscsi_node *node = sess ? sess->s_node : NULL;

	if (scmd_fpriv_test_bit(sc, CH_SFP_LU_PASSTHRU_BIT) ||
	    (sc->sc_flag & SC_FLAG_PASSTHRU) ||
	    (sc->sc_flag & SC_FLAG_LUN_OOR))
		return;

	if (sc->sc_status)
		return;

 	lu = iscsi_target_session_lun_get(sc->sc_sess, sc->sc_lun_acl);
	if (!lu) {
		os_log_info("%s:%s: itt 0x%x, lun %d, no LUN.\n",
			node ? node->n_name : "?",
			sess ? sess->s_peer_name : "?", sc->sc_itt, sc->sc_lun);

		if (scmd_fscsi_test_bit(sc, CH_SFSCSI_HOLD_BIT)) {
			os_log_debug(ISCSI_DBG_SCSI_COMMAND,
				"sc:0x%lx itt:0x%x state:%d posted to bkend\n",
				sc, sc->sc_itt, sc->sc_state);
			goto done;
		}
		sc_luns_changed(sc);
		goto done;
	}
	
	/* is the target waiting for a rescan ? */
	if (first_time && it_lu_check_rescan_needed(sc)) {
		os_log_info("%s:%s: itt 0x%x, lun %d, rescan.\n",
			node ? node->n_name : "?",
			sess ? sess->s_peer_name : "?", sc->sc_itt, sc->sc_lun);
		goto done;
	}

	/* is lun exists */
	if (it_lu_check_lun_offline(sc, lu)) {
		os_log_info("%s:%s: itt 0x%x, lun %d, offline.\n",
			node ? node->n_name : "?",
			sess ? sess->s_peer_name : "?", sc->sc_itt, sc->sc_lun);
		sc_luns_changed(sc);
		goto done;
	}

	/* reservation checks
	 * Force to send a read response instead of a data in
	 */
	switch (sc->sc_cmd[0] && 
		!scmd_fpriv_test_bit(sc, CH_SFP_LU_PASSTHRU_BIT) &&
		!(sc->sc_flag & SC_FLAG_PASSTHRU)) {
		case SCSI_OPCODE_PERSISTENT_RESERVE_IN:
		case SCSI_OPCODE_REQUEST_SENSE:
		case SCSI_OPCODE_REPORT_LUNS:
		case SCSI_OPCODE_INQUIRY:
			break;
		case SCSI_OPCODE_PERSISTENT_RESERVE_OUT:
		{
			unsigned char cmd = sc->sc_cmd[1] & 0x1f;
			if (cmd == STM_SA_REGISTER ||
			    cmd == STM_SA_REGISTER_IGNORE)
				break;
			if (it_lu_check_reservation_conflict(sc, lu)) {
				os_log_info("%s:%s: itt 0x%x, lun %d, rsv cflt\n",
					node ? node->n_name : "?",
					sess ? sess->s_peer_name : "?",
					sc->sc_itt, sc->sc_lun);
				goto done;
			}
			break;
		}
		default:
			if (it_lu_check_reservation_conflict(sc, lu)) {
				os_log_info("%s:%s: itt 0x%x, lun %d, rsv cft\n",
					node ? node->n_name : "?",
					sess ? sess->s_peer_name : "?",
					sc->sc_itt, sc->sc_lun);
				goto done;
			}
                        break;
	}

	/* ACL checks */
	if (it_lu_check_acl_rw_conflict(sc, lu)) {
		os_log_info("%s:%s: itt 0x%x, lun %d, acl.\n",
			node ? node->n_name : "?",
			sess ? sess->s_peer_name : "?", sc->sc_itt, sc->sc_lun);
		goto done;
	}
	
done:
	iscsi_target_session_lun_put(lu);
}

void it_scmd_exe_check_error(chiscsi_scsi_command *sc)
{
	if (sc->sc_status)
		return;

	it_scmd_lun_check_error(sc, 0);
	if (sc->sc_status)
		return; 

	if (scmd_fpriv_test_bit(sc, CH_SFP_XFER_ERR_BIT)) {
		iscsi_session *sess = sc->sc_sess;
		iscsi_node *node = sess ? sess->s_node : NULL;

		os_log_info("%s:%s, itt 0x%x, xfer %u,%u error.\n",
			node ? node->n_name : "?", 
                        sess ? sess->s_peer_name : "?", sc->sc_itt,
			sc->sc_xfer_len, sc->sc_xfer_left);
		sc->sc_xfer_len = sc->sc_xfer_left = 0;
	}
}

void iscsi_target_scsi_command_check_tmf_condition(chiscsi_scsi_command *sc)
{
	if (!(sc->sc_flag & SC_FLAG_TMF_ABORT)) 
		return;

	if (scmd_fscsi_test_bit(sc, CH_SFSCSI_HOLD_BIT)) {
		iscsi_session *sess = sc->sc_sess;

		/* if backend is already working on it, let it finish */
		os_log_debug(ISCSI_DBG_SCSI_COMMAND,
			"%s:%s, itt 0x%x,%u, tmf, still executing.\n",
			sess->s_node ? sess->s_node->n_name : "?",
			sess->s_peer_name, sc->sc_itt, sc->sc_idx);

		return;
	} 

	if (scmd_fpriv_test_bit(sc, CH_SFP_TMF_SENSE_BIT)) {
		os_log_debug(ISCSI_DBG_SCSI_COMMAND,
			"sc itt 0x%x, tmf abort -> status.\n",
			sc->sc_itt);
		sc_device_reset(sc);
		scmd_set_timestamp(sc, CH_SCMD_TM_STATE_2_STATUS);
		sc->sc_state = CH_SC_STATE_STATUS;

	} else {
		iscsi_connection *conn = sc->sc_conn;

		os_log_debug(ISCSI_DBG_SCSI_COMMAND,
			"sc itt 0x%x, tmf abort -> done.\n",
			sc->sc_itt);

		sc->sc_statsn = conn->c_statsn;
		scmd_set_timestamp(sc, CH_SCMD_TM_STATE_2_DONE);
		sc->sc_state = CH_SC_STATE_DONE;
	}
	os_log_debug(ISCSI_DBG_SCSI_COMMAND,
		"sc 0x%p itt 0x%x, s %u, f 0x%x,0x%lx,0x%lx tmf abort.\n",
		sc, sc->sc_itt, sc->sc_state, sc->sc_flag, sc->sc_fscsi,
		sc->sc_fpriv);
}

/*
 * iscsi_target_scsi_command_done --
 *	called when a scsi command is done
 */
void iscsi_target_scsi_command_check_execution_status(chiscsi_scsi_command *sc)
{
	if (sc->sc_status == SCSI_STATUS_RESERVATION_CONFLICT ) {
		os_log_debug(ISCSI_DBG_SCSI_COMMAND | ISCSI_DBG_TARGET_API,
			"sc itt 0x%x, reservation conflict -> status.\n",
			sc->sc_itt);
		scmd_set_timestamp(sc, CH_SCMD_TM_STATE_2_STATUS);
		sc->sc_state = CH_SC_STATE_STATUS;
	} else 	if (sc->sc_status == SCSI_STATUS_CHECK_CONDITION) {
		os_log_debug(ISCSI_DBG_SCSI_COMMAND,
			"sc itt 0x%x, Check condition -> status.\n",
			sc->sc_itt);
		scmd_set_timestamp(sc, CH_SCMD_TM_STATE_2_STATUS);
		sc->sc_state = CH_SC_STATE_STATUS;
	}
}

/*
 * it_scmd_release_backend_buffers() releases the sgl upto max_offset. 
 */
void it_scmd_release_backend_buffers(chiscsi_scsi_command *sc,
				unsigned int max_offset)
{
	chiscsi_target_lun_class *lclass = sc->lu_class;
	chiscsi_sgl *sc_sgl = &sc->sc_sgl;
	int async = scmd_fpriv_test_bit(sc, CH_SFP_LU_QUEUE_BIT) ? 1:0;
	int j;

	/* local buffer, if not pass-through and not RWIO */
	if (scmd_fpriv_test_bit(sc, CH_SFP_BUF_LOCAL_BIT)) {
		return;
	}

	/* backend requested abort */
        if (scmd_fscsi_test_bit(sc, CH_SFSCSI_ABORT_REQ_BIT)) {
		scmd_fscsi_clear_bit(sc, CH_SFSCSI_ABORT_REQ_BIT);

		if (lclass->fp_scsi_cmd_abort_status) {
			unsigned int sgcnt = sc_sgl->sgl_vecs_nr;
			unsigned char *buf = sc_sgl->sgl_vecs;

			scmd_set_timestamp(sc, CH_SCMD_TM_FP_ABORT_STATUS);
			sc_sgl->sgl_vecs_nr = 0;
			sc_sgl->sgl_boff += sc_sgl->sgl_length;
			sc_sgl->sgl_length = 0;
			sc_sgl->sgl_vecs = NULL;
			sc_sgl->sgl_vec_last = NULL;

			os_log_debug(ISCSI_DBG_TARGET_API, 
				"%s: fp_abort_status, sc 0x%p, lu %u, sn 0x%x, itt 0x%x.\n",
				__func__, sc, sc->sc_lun, sc->sc_cmdsn, sc->sc_itt);

			lclass->fp_scsi_cmd_abort_status(sc->sc_lun,
				sc->sc_cmdsn, sc->sc_itt, sgcnt,
				buf, sc->sc_sdev_hndl);
		}
		return;
	}


	/* already returned, no more buffer left */
	if (!sc_sgl->sgl_vecs) {
		/* The below code is for only reads and non-multiphase
		 * mode. This is for reads like TEST_UNIT_READY in passthru,
		 * which has 0 buffer and only status.
		 */
		if ((sc->sc_flag & SC_FLAG_READ) &&
			(scmd_fpriv_test_bit(sc, CH_SFP_LU_PASSTHRU_BIT)) &&
			(!scmd_fpriv_test_bit(sc, CH_SFP_LU_MULTIPHASE_BIT))) {
			os_log_debug(ISCSI_DBG_TARGET_API, 
				"%s: fp_xfer_status, sc 0x%p, sn 0x%x, itt 0x%x.\n",
				__func__, sc, sc->sc_cmdsn, sc->sc_itt);

			lclass->fp_scsi_cmd_data_xfer_status(sc, NULL,
						0, 0, 0);
		}
		return;
	}

	/* Lock here since we need to check sc_sgl in else statement */
        if (async  && !is_chelsio_lun_class(lclass)) os_lock_irq(sc->sc_lock);
	if (!scmd_fpriv_test_bit(sc, CH_SFP_LU_MULTIPHASE_BIT)) {
		unsigned int boff = sc_sgl->sgl_boff;
		unsigned int len = sc_sgl->sgl_length;
		unsigned int sgcnt = sc_sgl->sgl_vecs_nr;
		unsigned char *buf = sc_sgl->sgl_vecs;
		int blk_len = sc->sc_blk_cnt << lu_sect_shift;

		/* should return all of the buffers we have */
		if (max_offset != sc->sc_xfer_len &&
		    !(blk_len < sc->sc_xfer_len) &&
		    !(sc->sc_flag & SC_FLAG_TMF_ABORT) && !sc->sc_status) {
			os_log_warn("itt 0x%x, sgl %u, release buflen %u != total %u.\n",
				sc->sc_itt, sc_sgl->sgl_vecs_nr,
				max_offset, sc->sc_xfer_len);
		}

		sc_sgl->sgl_vecs_nr = 0;
		sc_sgl->sgl_boff += sc_sgl->sgl_length;
		sc_sgl->sgl_length = 0;
		sc_sgl->sgl_vecs = NULL;
		sc_sgl->sgl_vec_last = NULL;

		if (async  && !is_chelsio_lun_class(lclass)) os_unlock_irq(sc->sc_lock);
		/* return data buffers back to the backend storage */
		scmd_set_timestamp(sc, CH_SCMD_TM_FP_DATA_XFER_STATUS);
		os_log_debug(ISCSI_DBG_TARGET_API, 
			"%s: fp_xfer_status, sc 0x%p, sn 0x%x, itt 0x%x.\n",
			__func__, sc, sc->sc_cmdsn, sc->sc_itt);
		lclass->fp_scsi_cmd_data_xfer_status(sc, buf, sgcnt, boff, len);
	} else if (max_offset > sc_sgl->sgl_boff) {
		/* multi-phase data LUN, return what we sent so far */
		unsigned int maxlen = max_offset - sc_sgl->sgl_boff;
		chiscsi_sgvec *head, *tail, *prev, *sg;

		sg = (chiscsi_sgvec *)sc_sgl->sgl_vecs;
		head = tail = sg;
		

		/* when xfer_left is 0, we need to free the whole of remaning buffer */
		if (sc->sc_flag & SC_FLAG_XFER_OVERFLOW) {
			os_log_debug(ISCSI_DBG_TARGET_API, 
				"xfer_cnt(max_offset) %u maxlen %u sc_sgl len %u sc->sc_xfer_left %u \n", 
				max_offset, maxlen, sc_sgl->sgl_length, sc->sc_xfer_left);
			if (sc->sc_xfer_left == 0) 
				maxlen = sc_sgl->sgl_length;
		}

		while (maxlen) {
			unsigned int blen;
			/* find the end of the burst */
			for (prev=sg, sg=sg->sg_next, j=1; sg;
				j++, prev=sg, sg = sg->sg_next)
				if (sg->sg_flag & CHISCSI_SG_SBUF_LISTHEAD)
					break;
			tail = prev;
			if (sg)
				blen = sg->sg_boff - head->sg_boff;
			else
				blen = sc_sgl->sgl_length;

			os_log_debug(ISCSI_DBG_TARGET_API,
					"itt 0x%x, release sgl, %u, %u+%u/%u.\n",
					sc->sc_itt, j, head->sg_boff, blen, maxlen);
			if (blen > maxlen && !(sc->sc_flag & SC_FLAG_XFER_OVERFLOW)) {
				os_log_warn("itt 0x%x, release sgl, sgcnt %u, off %u, len %u > %u.\n",
				sc->sc_itt, j, head->sg_boff, blen, maxlen);
				chiscsi_sgl_display("sgl", sc_sgl, 1, 0);
			}

			sc_sgl->sgl_vecs_nr -= j;
			sc_sgl->sgl_boff += blen;
			sc_sgl->sgl_length -= blen;
			sc_sgl->sgl_vecs = (unsigned char *)sg;
			if (!sc_sgl->sgl_vecs_nr)
				sc_sgl->sgl_vec_last = NULL;	
	
			if (async  && !is_chelsio_lun_class(lclass)) os_unlock_irq(sc->sc_lock);

			scmd_set_timestamp(sc, CH_SCMD_TM_FP_DATA_XFER_STATUS);
			os_log_debug(ISCSI_DBG_TARGET_API, 
				"%s: fp_xfer_status, sc 0x%p, sn 0x%x, itt 0x%x.\n",
				__func__, sc, sc->sc_cmdsn, sc->sc_itt);

			lclass->fp_scsi_cmd_data_xfer_status(sc,
					 (unsigned char *)head, j,
					head->sg_boff, blen);
	
			maxlen -= blen;	
			head = tail = sg;
        		if (async  && !is_chelsio_lun_class(lclass)) os_lock_irq(sc->sc_lock);
		}
       		if (async  && !is_chelsio_lun_class(lclass)) os_unlock_irq(sc->sc_lock);
		/* chiscsi_sgl_display("rel_backend_buf 2", sc_sgl, 1, 0); */
	}
}

/*
 * add more sgl to chiscsi_scsi_command
 * NOTE:
 * - no locking is done
 * - no checking is done
 */
static int it_scmd_save_backend_buffers(chiscsi_scsi_command *sc,
				chiscsi_sgvec *sgl, unsigned int sgcnt,
				unsigned int offset, unsigned int buflen)
{
	chiscsi_sgl *sc_sgl = &sc->sc_sgl;
	chiscsi_sgvec *sg = sgl;
	chiscsi_sgvec *sg_prev = NULL;
	unsigned int boff = offset;
	int i;

	os_log_debug(ISCSI_DBG_TARGET_API,
		"sgl 0x%p sgl_flag 0x%x boff %u vec 0x%p sgl_len %d, "
		"sgl_vecs_nr 0x%u\n", sgl, sgl->sg_flag, boff, sc_sgl->sgl_vecs,
		sg->sg_length, sgcnt);

	/* save the sgl */
	sgl->sg_flag |= CHISCSI_SG_SBUF_LISTHEAD;
	for (i = 0; i < sgcnt; i++, boff += sg->sg_length, sg_prev=sg, sg++) {
		if (sg_prev) sg_prev->sg_next = sg;
		sg->sg_boff = boff;
		
#if 0
		os_log_debug( ISCSI_DBG_SCSI_COMMAND | ISCSI_DBG_TARGET_API,
			"i=%d sg_addr 0x%p, sg_dma_addr 0x%p sg_next 0x%p\n",
			i, sg->sg_addr, sg->sg_dma_addr, sg );
#endif

		/* support sg_dma_addr + sg_length without the sg_offset */
		if (!sg->sg_addr && (sg->sg_flag & CHISCSI_SG_SBUF_DMABLE)) 
			sg->sg_flag |= CHISCSI_SG_SBUF_DMA_ONLY;
	}
	sg_prev->sg_flag |= CHISCSI_SG_SBUF_LISTTAIL;

	if (boff != (offset + buflen))
		return -ISCSI_EINVAL;

	/* there could be buffers already there, be careful not to
	   over-write that info. */
	if (!sc_sgl->sgl_vecs) {
		sc_sgl->sgl_vecs = (unsigned char *)sgl;
		sc_sgl->sgl_boff = offset;
		sc_sgl->sgl_length = buflen;
		sc_sgl->sgl_vecs_nr = sgcnt;
		sc_sgl->sgl_vec_last = sg_prev;

		os_log_debug(ISCSI_DBG_TARGET_API,
			"sgl_vecs 0x%p sgl_boff 0x%x sgl_length %d, sgl_vecs_nr 0x%u, sgl_vecs_last 0x%p\n",
			sc_sgl->sgl_vecs, sc_sgl->sgl_boff, sc_sgl->sgl_length, 
			sc_sgl->sgl_vecs_nr, sc_sgl->sgl_vec_last);
	} else {
		sc_sgl->sgl_length += buflen;
		sc_sgl->sgl_vecs_nr += sgcnt;
		sc_sgl->sgl_vec_last->sg_next = sgl;
		sc_sgl->sgl_vec_last = sg_prev;
	
                os_log_debug(ISCSI_DBG_TARGET_API,
                        "sgl_length %d, sgl_vecs_nr 0x%u, sgl_vecs_last 0x%p\n",
                        sc_sgl->sgl_length, sc_sgl->sgl_vecs_nr, sc_sgl->sgl_vec_last);
	}

	return 0;
}

void iscsi_target_scsi_command_done(chiscsi_scsi_command *sc, int err)
{
	int async = scmd_fpriv_test_bit(sc, CH_SFP_LU_QUEUE_BIT) ? 1:0;
	unsigned int state;
	iscsi_session *sess;
	iscsi_connection *conn;

	os_log_debug(ISCSI_DBG_SCSI_COMMAND,
		"sc itt 0x%x, done. err %d, flag 0x%x, state %u, xfer %u/%u.\n",
		sc->sc_itt, err, sc->sc_flag, sc->sc_state,
		sc->sc_xfer_left, sc->sc_xfer_len);

	if (err && !sc->sc_status) {
		if (err == -ISCSI_EIO) 
			sc_rw_error(sc);
		else
			sc_invalid_address(sc);	
	}

	if (async) os_lock_irq(sc->sc_lock);

	scmd_fscsi_set_bit(sc, CH_SFSCSI_EXECUTED_BIT);
	scmd_fscsi_clear_bit(sc, CH_SFSCSI_HOLD_BIT);

	state = sc->sc_state;
	sess = sc->sc_sess;
	conn = sc->sc_conn;

	if (!conn || !sess ||
	    scmd_fscsi_test_bit(sc, CH_SFSCSI_FORCE_RELEASE_BIT)) {
		os_log_info("%s: sess 0x%p, conn 0x%p gone, sc 0x%p, itt 0x%x, "
			    "s 0x%x, fscsi 0x%lx, force release.\n",
			     __func__, sess, conn, sc, sc->sc_itt, sc->sc_state,
			     sc->sc_fscsi);
		if (async) os_unlock_irq(sc->sc_lock);
		chiscsi_scsi_command_release(sc, NULL);
	} else if(iscsi_sess_flag_test(sess, SESS_FLAG_CLOSE_BIT) ||
		iscsi_conn_flag_test(conn, CONN_FLAG_CLOSED_BIT)) {
		os_log_info("%s: sess 0x%p, conn 0x%p closing, sc 0x%p, "
			    "itt 0x%x, s 0x%x, fscsi 0x%lx.\n",
			     __func__, sess, conn, sc, sc->sc_itt, sc->sc_state,
			     sc->sc_fscsi);
		if (async) os_unlock_irq(sc->sc_lock);
	} else {
		if (async) os_unlock_irq(sc->sc_lock);

		os_log_debug(ISCSI_DBG_SCSI_COMMAND,
			     "it sess 0x%p, conn 0x%p, sc 0x%p, itt 0x%x, "
			     "state %u, sync %d, done, push along.\n",
			     sc->sc_sess, sc->sc_conn, sc, sc->sc_itt,
			     sc->sc_state, async);
		if (async) {
			iscsi_schedule_session(sess);
		} else {
			if (sc->sc_flag & SC_FLAG_READ)
				it_scmd_read_continue(sc);
			else
				it_scmd_write_continue(sc);
			if (sc->sc_state && sc->sc_state == state) {
				os_log_warn("%s: sc 0x%p, itt 0x%x, stuck?\n",
					__func__, sc, sc->sc_itt);
				chiscsi_scsi_command_display(sc, 1);
			}
		}
	}
}

/* Abort scsi command, initiated by Backend Storage
   This function does following
        - send error status to the initiator 
        - clean up the iscsi scsi command
*/
int chiscsi_scsi_cmd_abort(chiscsi_scsi_command *sc)
{
        os_log_debug(ISCSI_DBG_TARGET_API,
                "%s: itt 0x%x, f 0x%x, s %u, rsp 0x%x,0x%x, sense %u,0x%x,0x%x,0x%x.\n",
                __func__, sc->sc_itt, sc->sc_flag, sc->sc_state, sc->sc_status,
		sc->sc_response, sc->sc_sense_buflen, sc->sc_sense_key,
		sc->sc_sense_asc, sc->sc_sense_ascq);

	scmd_set_timestamp(sc, CH_SCMD_TM_CHISCSI_ABORT);
	
	/*set the flag indiacting that backend requested cmd abort */
	sc->sc_flag |= SC_FLAG_CMD_ABORT;
	scmd_fscsi_set_bit(sc, CH_SFSCSI_ABORT_REQ_BIT);
	scmd_set_timestamp(sc, CH_SCMD_TM_STATE_2_STATUS);
        sc->sc_state = CH_SC_STATE_STATUS;

	if (!sc->sc_sense_key && !sc->sc_sense_buflen) {
                os_log_info("%s: itt 0x%x, f 0x%x, s %u, no sense, rsp 0x%x,0x%x.\n",
                	__func__, sc->sc_itt, sc->sc_flag, sc->sc_state,
			sc->sc_status, sc->sc_response);
		
		if (!sc->sc_status)
        		sc->sc_status = SCSI_STATUS_CHECK_CONDITION;
		sc->sc_sense_key = SCSI_SENSE_ABORTED_COMMAND;
		if (sc->sc_flag & SC_FLAG_WRITE)
			sc->sc_sense_asc = 0xC; /* write error */
		else
			sc->sc_sense_asc = 0x11; /* read error */
		
	}

        iscsi_target_scsi_command_done(sc, 0);
        return 0;
}

/* Called by backend in response to fp_scsi_cmd_abort() */
int chiscsi_scsi_cmd_abort_status(chiscsi_scsi_command *sc)
{
	scmd_set_timestamp(sc, CH_SCMD_TM_CHISCSI_ABORT_STATUS);
	/* being aborted, send sense info, else then we are done */
	if (sc->sc_flag & SC_FLAG_TMF_ABORT) {
                if (scmd_fpriv_test_bit(sc, CH_SFP_TMF_SENSE_BIT)) {
                        os_log_debug(ISCSI_DBG_TARGET_API,
                                "sc itt 0x%x, flag 0x%x, state %u tmf abort -> status.\n",
                                sc->sc_itt, sc->sc_flag, sc->sc_state);
			scmd_set_timestamp(sc, CH_SCMD_TM_STATE_2_STATUS);
                        sc->sc_state = CH_SC_STATE_STATUS;

                } else {
                        iscsi_connection *conn = sc->sc_conn;

                        os_log_debug(ISCSI_DBG_TARGET_API,
                                "sc itt 0x%x, flag 0x%x, state %u, tmf abort -> done.\n",
                                 sc->sc_itt, sc->sc_flag, sc->sc_state);

                        sc->sc_statsn = conn->c_statsn;
			scmd_set_timestamp(sc, CH_SCMD_TM_STATE_2_DONE);
                        sc->sc_state = CH_SC_STATE_DONE;
                }
        } else if (sc->sc_flag & SC_FLAG_SESS_ABORT) {
	/* if session abort, send sense info */
		os_log_debug(ISCSI_DBG_TARGET_API,
                                "sc itt 0x%x, sg 0x%x, state %u, sess abort -> status.\n",
                                sc->sc_itt, sc->sc_flag, sc->sc_state);
		scmd_set_timestamp(sc, CH_SCMD_TM_STATE_2_STATUS);
                sc->sc_state = CH_SC_STATE_STATUS;
	}

        iscsi_target_scsi_command_done(sc, 0);
        return 0;
}


/*
 * check the data buffers returned from backend:
 * for read:
 * 	- iscsi calls fp_scsi_cmd_cdb_rcved(), and
 * 	- the backend should returns the filled data buffer via
 * 	   chiscsi_scsi_cmd_execution_status()
 * for write:
 * 	- iscsi calls iscsi calls fp_scsi_cmd_cdb_rcved(), and
 * 	- the backend should returns the data buffer via
 * 	  chiscsi_scsi_cmd_buffer_ready()
 */
static int it_scmd_check_buffer(const char *fname, chiscsi_scsi_command *sc,
				unsigned char *buf, unsigned int sgcnt,
				unsigned int offset, unsigned int buflen)
{
	chiscsi_sgl *sc_sgl = &sc->sc_sgl;
	unsigned int new_off = offset + buflen;
	int async = scmd_fpriv_test_bit(sc, CH_SFP_LU_QUEUE_BIT) ? 1:0;
	chiscsi_target_lun_class *lclass = sc->lu_class;

	/* error checking */
	if (async  && !is_chelsio_lun_class(lclass))
		os_lock_irq(sc->sc_lock);

	if(!sc->sc_xfer_len)
		goto done;

	if (!buf) {
		os_log_info("%s: itt 0x%x, data buf NULL, %u+%u/%u.\n",
			fname, sc->sc_itt, offset, buflen, sc->sc_xfer_len);
		goto err_out;
	}
		
	if (!sgcnt) {
		/* allow single buffer for all of the data requested */
		if (!offset && buflen == sc->sc_xfer_len &&
		    !sc_sgl->sgl_boff && !sc_sgl->sgl_length) {
			sc_sgl->sgl_length = buflen;
			sc_sgl->sgl_vecs = buf;
			goto done;
		} else {
			os_log_info("%s: itt 0x%x, sg 0, exp. sgl, %u+%u/%u.\n",
				fname, sc->sc_itt, offset, buflen,
				sc->sc_xfer_len);
			goto err_out;
		}
	}

	/* overflow and underflow flags are mutually exclusive */
	if ((sc->sc_flag & SC_FLAG_XFER_OVERFLOW) && 
		(sc->sc_flag & SC_FLAG_XFER_UNDERFLOW)) {
		os_log_info("%s: itt 0x%x, Overflow/Underflow flag, mutually exclusive.\n",
			fname, sc->sc_itt);
		goto err_out;
	}

	/* No overflow flag set */
	if (sc->sc_xfer_len && (sc->sc_xfer_len < new_off) &&
	    !(sc->sc_flag & SC_FLAG_XFER_OVERFLOW)) {
		os_log_info("%s: itt 0x%x, buf overflow, %u!=%u+%u.\n",
			fname, sc->sc_itt, sc->sc_xfer_len, offset, buflen);
		goto err_out;
	}

	/* Underflow */
	if (sc->sc_xfer_len > new_off &&
		!scmd_fpriv_test_bit(sc, CH_SFP_LU_MULTIPHASE_BIT) &&  
		!(sc->sc_flag & SC_FLAG_XFER_UNDERFLOW) &&
		!(sc->sc_flag & SC_FLAG_READ)) {
		os_log_info("%s: itt 0x%x, buf underflow, %u!=%u+%u.\n",
			fname, sc->sc_itt, sc->sc_xfer_len, offset, buflen);
		goto err_out;
	}

	if ((sc_sgl->sgl_boff + sc_sgl->sgl_length) != offset) {
		os_log_info("%s: itt 0x%x, buf off %u+%u, exp. %u+%u.\n",
			fname, sc->sc_itt, offset, buflen, sc_sgl->sgl_boff,
			sc_sgl->sgl_length);
		goto err_out;
	}

	if (it_scmd_save_backend_buffers(sc, (chiscsi_sgvec *)buf,
					sgcnt, offset, buflen) < 0) {
		chiscsi_sgvec *sg = (chiscsi_sgvec *)buf;

		sg += sgcnt - 1;
		os_log_info("%s: itt 0x%x, buflen does not match, %u!=%u+%u.\n",
			fname, sc->sc_itt, sg->sg_boff + sg->sg_length,
			offset, buflen);
		goto err_out;
	}
	
done:
	if (sc->sc_xfer_len == new_off)
		scmd_fpriv_set_bit(sc, CH_SFP_BUF_LAST_BIT);

	if (async  && !is_chelsio_lun_class(lclass)) os_unlock_irq(sc->sc_lock);
	return 0;

err_out:
	if (async  && !is_chelsio_lun_class(lclass)) os_unlock_irq(sc->sc_lock);
	return -ISCSI_EINVAL;
}

static int it_scmd_check_executed_buffer(const char *fname,
				chiscsi_scsi_command *sc,
				unsigned char *buf, unsigned int sgcnt,
				unsigned int offset, unsigned int buflen)
{
	chiscsi_sgl *sc_sgl = &sc->sc_sgl;
	unsigned int new_off = offset + buflen;
	int async = scmd_fpriv_test_bit(sc, CH_SFP_LU_QUEUE_BIT) ? 1:0;
	chiscsi_target_lun_class *lclass = sc->lu_class;

	/* error checking */
	if (async  && !is_chelsio_lun_class(lclass))
		os_lock_irq(sc->sc_lock);
		
	if (sc->sc_xfer_len < new_off) {
		os_log_info("%s: itt 0x%x, buf overflow, %u!=%u+%u.\n",
			fname, sc->sc_itt, sc->sc_xfer_len, offset, buflen);
		sc->sc_flag |= SC_FLAG_XFER_OVERFLOW;
	}
	if (sc->sc_xfer_len > new_off &&
		!scmd_fpriv_test_bit(sc, CH_SFP_LU_MULTIPHASE_BIT)) {
		os_log_info("%s: itt 0x%x, buf underflow, %u!=%u+%u.\n",
			fname, sc->sc_itt, sc->sc_xfer_len, offset, buflen);
		sc->sc_flag |= SC_FLAG_XFER_UNDERFLOW;
	}

	if (offset > sc_sgl->sgl_boff || new_off > sc_sgl->sgl_boff) {
		os_log_info("%s: itt 0x%x, %u+%u > current sgl %u+%u.\n",
			fname, sc->sc_itt, offset, buflen, sc_sgl->sgl_boff,
			sc_sgl->sgl_length);
		goto err_out;
	}
	
	if (async  && !is_chelsio_lun_class(lclass)) os_unlock_irq(sc->sc_lock);
	return 0;

err_out:
	if (async  && !is_chelsio_lun_class(lclass)) os_unlock_irq(sc->sc_lock);
	return -ISCSI_EINVAL;
}

/*
 * chiscsi_scsi_cmd_buffer_ready() is only called for write scsi commands.
 *
 * The first callback happens when iscsi calls fp_scsi_cmd_cdb_rcved().
 *
 * There could be subsequent callbacks for the multi-phase data LUNs as the
 * memory become available.
 */
int chiscsi_scsi_cmd_buffer_ready(chiscsi_scsi_command *sc,
				unsigned char *buf, unsigned int sgcnt,
				unsigned int offset, unsigned int buflen)
{
	iscsi_session *sess = (iscsi_session *)sc->sc_sess;
	int rv;

	os_log_debug(ISCSI_DBG_TARGET_API,
		"itt 0x%x, buf ready. flag 0x%x, state %u, xfer %u, buf %u/%u+%u.\n",
		 sc->sc_itt, sc->sc_flag, sc->sc_state,
		sc->sc_xfer_len, sc->sc_sgl.sgl_boff, offset, buflen);

	scmd_set_timestamp(sc, CH_SCMD_TM_CHISCSI_BUFFER_READY);
	scmd_fscsi_set_bit(sc, CH_SFSCSI_BUF_READY_BIT);
	scmd_fscsi_clear_bit(sc, CH_SFSCSI_HOLD_BIT);

	if (sc->sc_status)
		return 0;

	rv = it_scmd_check_buffer(__func__, sc, buf, sgcnt, offset, buflen);
	if (rv < 0 && !sc->sc_status)
		return rv;

	/* A response always needs to be sent*/
	if (sess && scmd_fpriv_test_bit(sc, CH_SFP_LU_QUEUE_BIT))
		iscsi_schedule_session(sess);
	else
		it_scmd_write_continue(sc);
	return 0;
}

/*
 * chiscsi_scsi_cmd_execution_status() are called for both read and write
 * scsi commands.
 *
 * for read:
 * 	- iscsi calls fp_scsi_cmd_cdb_rcved(), and
 * 	- the backend should returns the filled data buffer via
 * 	   chiscsi_scsi_cmd_execution_status()
 *
 * for write:
 * 	- iscsi calls fp_scsi_cmd_data_xfer_status() to execute the write
 * 	  the write data, and
 * 	- the backend does the write, free the buffer and return the status
 * 	- NOTE: the write buffers could be already freed at this point.
 */
int chiscsi_scsi_cmd_execution_status(chiscsi_scsi_command *sc,
				unsigned char *buf, unsigned int sgcnt,
				unsigned int offset, unsigned int buflen)
{
	int async = scmd_fpriv_test_bit(sc, CH_SFP_LU_QUEUE_BIT) ? 1:0;
	int rv;

	os_log_debug(ISCSI_DBG_TARGET_API,
		"itt 0x%x, exe status. flag 0x%x, state %u, xfer %u, %u+%u.\n",
		sc->sc_itt, sc->sc_flag, sc->sc_state,
		sc->sc_xfer_len, offset, buflen);

	scmd_set_timestamp(sc, CH_SCMD_TM_CHISCSI_EXE_STATUS);
	scmd_fscsi_clear_bit(sc, CH_SFSCSI_HOLD_BIT);

	if (async) os_lock_irq(sc->sc_lock);
	if ((sc->sc_flag & SC_FLAG_TMF_ABORT) || sc->sc_status) {
		os_log_info("%s: sc 0x%p, itt 0x%x, f 0x%x, abort.\n",
			__func__, sc, sc->sc_itt, sc->sc_flag);
		if (async) os_unlock_irq(sc->sc_lock);

		goto done;
	}
	if (async) os_unlock_irq(sc->sc_lock);

	if (sc->sc_flag & SC_FLAG_READ) {
		rv = it_scmd_check_buffer(__func__, sc, buf, sgcnt, offset,
					buflen);
		scmd_fscsi_set_bit(sc, CH_SFSCSI_READ_BUF_BIT);
	} else
		rv = it_scmd_check_executed_buffer(__func__, sc, buf, sgcnt,
					offset, buflen);

	if (rv < 0 && !sc->sc_status) {
		os_log_info("itt 0x%x, flag 0x%x, state %u, check buffer %d.\n",
			sc->sc_itt, sc->sc_flag, sc->sc_state, rv);
		chiscsi_scsi_command_display(sc, 1);
		return rv;
	}

done:
	iscsi_target_scsi_command_done(sc, 0);
	return 0;
}


int it_scmd_send_sense_status(chiscsi_scsi_command *sc)
{
	iscsi_connection *conn = (iscsi_connection *)sc->sc_conn;
        iscsi_session *sess = (iscsi_session *)sc->sc_sess;
	unsigned int senselen = 0;
	iscsi_pdu *pdu;
	int rv;

	if (sc->sc_state != CH_SC_STATE_STATUS)
		return 0;

	uint_serial_inc(sess->s_maxcmdsn);

	if (sc->sc_sense_key || sc->sc_sense_buf[0])
		senselen = SCSI_SENSE_BUFFERSIZE + 2;

	pdu = iscsi_pdu_get(conn, 0, 0, senselen);
	if (!pdu)
		return -ISCSI_ENOMEM;
	pdu->p_saveq = sc->sc_queue[CH_SCMD_PDU_SENTQ];

	pdu->p_opcode = ISCSI_OPCODE_SCSI_RESPONSE;

	SET_PDU_OPCODE(pdu, ISCSI_OPCODE_SCSI_RESPONSE);
	SET_PDU_ITT(pdu, sc->sc_itt);
	SET_PDU_RESPONSE(pdu, sc->sc_response);
	SET_PDU_STATUS(pdu, sc->sc_status);
	SET_PDU_F(pdu);

	if (sc->sc_response != ISCSI_RESPONSE_COMPLETED) {
		if (sc->sc_flag & SC_FLAG_XFER_OVERFLOW)
                                SET_PDU_O(pdu);
		else if (sc->sc_flag & SC_FLAG_XFER_UNDERFLOW)
                                SET_PDU_U(pdu);
	}

	if (sc->sc_flag & SC_FLAG_WRITE) {
		chiscsi_scsi_write_cb *wcb = &sc->sc_cb.wcb;
		SET_PDU_EXPDATASN(pdu, wcb->w_r2tsn);
	} else {
		chiscsi_scsi_read_cb *rcb = &sc->sc_cb.rcb;
		SET_PDU_EXPDATASN(pdu, rcb->r_datasn);
	}

	uint_serial_inc(conn->c_statsn);
	pdu->p_sn = conn->c_statsn;
	sc->sc_statsn = conn->c_statsn;
	SET_PDU_STATSN(pdu, sc->sc_statsn);

	SET_PDU_EXPCMDSN(pdu, sess->s_expcmdsn);
	SET_PDU_MAXCMDSN(pdu, sess->s_maxcmdsn);

	if (senselen) {
		unsigned char *bufp = pdu->p_sglist[0].sg_addr;

		memset(bufp, 0, senselen);
		SET_PDU_AHS_AND_DATA_LENGTH(pdu, senselen);

		*((unsigned short *) bufp) = os_htons(SCSI_SENSE_BUFFERSIZE);
		bufp += 2;

		if (sc->sc_sense_buf[0]) {
			memcpy(bufp, sc->sc_sense_buf, SCSI_SENSE_BUFFERSIZE);
		} else {
			bufp[0] = 0xf0;
			bufp[2] = sc->sc_sense_key;
			bufp[7] = 0xa;
			bufp[12] = sc->sc_sense_asc;
			bufp[13] = sc->sc_sense_ascq;
		}
	}

	iscsi_conn_flag_set(conn, CONN_FLAG_TX_PUSH_BIT);

	rv = iscsi_connection_send_pdu(conn, pdu);
	if (rv < 0) {
		return rv;
	}

	os_log_debug(ISCSI_DBG_SCSI_COMMAND,
		     "it sess 0x%lx, sc 0x%p itt 0x%x, STATUS -> DONE.\n",
		     sc->sc_sess, sc, sc->sc_itt);

	scmd_set_timestamp(sc, CH_SCMD_TM_STATE_2_DONE);
	sc->sc_state = CH_SC_STATE_DONE;
	
	return 0;
}

void it_scmd_pdtest_check(chiscsi_scsi_command *sc)
{
#ifdef __UIT_PDTEST_CHECK__
	chiscsi_sgl *sc_sgl = &sc->sc_sgl;
	chiscsi_sgvec *sg = (chiscsi_sgvec *)sc_sgl->sgl_vecs;
	unsigned char *cdb = sc->sc_cmd;
	unsigned char *byte;

	if (!pdtest_check || !sc_sgl->sgl_boff)
		return;

	byte = sg->sg_addr;

	if (byte[0] != cdb[5] || byte[1] != cdb[4] || byte[2] != cdb[3] ||
	    byte[3] != cdb[2]) {
		unsigned int sgcnt = sc_sgl->sgl_vecs_nr;
		int i;

		os_log_info("pdtest, itt 0x%x, LBA mismatch.\n", sc->sc_itt);
		chiscsi_scsi_command_display(sc, 1);
		iscsi_display_byte_string("cdb", sc->sc_cmd, 0, 16, NULL, 0);
		for (i = 0; i < sgcnt; i++, sg++) {
			os_log_info("pdtest, itt 0x%x, sg %d/%u, %u.\n",
				sc->sc_itt, i, sgcnt, sg->sg_length);
			iscsi_display_byte_string("sg", sg->sg_addr, 0,
						sg->sg_length, NULL, 0);
		}
	}
#endif
}
