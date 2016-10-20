/*
 *  tmf.c -- TMF Request/Response
 */

#include <iscsi_target_api.h>
#include "iscsi_target_private.h"

void iscsi_tmf_free(iscsi_tmf *p)
{
	os_free(p->p_lock);
	os_free(p);
}

static iscsi_tmf *iscsi_tmf_alloc(void)
{
	iscsi_tmf *ptmf = os_alloc(sizeof(iscsi_tmf), 1, 1);

	if (!ptmf)
		return NULL;

	ptmf->p_lock = os_alloc(os_lock_size, 1, 1);
	if (!ptmf->p_lock) {
		os_free(ptmf);
		return NULL;
	}

	os_lock_init(ptmf->p_lock);
	return ptmf;
}

static iscsi_tmf *tmf_save(iscsi_pdu *pdu)
{
	iscsi_connection *conn = (iscsi_connection *)pdu->p_conn;
	iscsi_session *sess = conn->c_sess;
	chiscsi_queue *tmfq = sess->s_queue[SESS_TMFQ];
	iscsi_tmf *ptmf = iscsi_tmf_alloc();

	if (!ptmf)
		return NULL;

	ptmf->p_itt = pdu->p_itt;
	ptmf->p_func = GET_PDU_TMF_FUNCTION(pdu);
	ptmf->p_lun = GET_PDU_LUN(pdu);
	ptmf->p_flag = ISCSI_PDU_FLAG_TMF_POSTPONED;
	ptmf->p_conn = conn;
	ptmf->p_sess = conn->c_sess;
	ptmf->p_sn = pdu->p_sn;
	iscsi_tmf_enqueue(nolock, tmfq, ptmf);
	return ptmf;
}

/* process a task management function request pdu */
int it_send_tmf_response(iscsi_connection *conn, unsigned int itt,
			unsigned char response)
{
	iscsi_session *sess;
	iscsi_pdu *tpdu;
	int     rv;

	if (!conn || !conn->c_sess)
		return -ISCSI_EINVAL;

 	sess = conn->c_sess;
	tpdu = iscsi_pdu_get(conn, 0, 0, 0);
	if (!tpdu)
		return -ISCSI_ENOMEM;

	tpdu->p_opcode = ISCSI_OPCODE_TMF_RESPONSE;

	SET_PDU_OPCODE(tpdu, ISCSI_OPCODE_TMF_RESPONSE);
	SET_PDU_F(tpdu);
	SET_PDU_ITT(tpdu, itt);
	uint_serial_inc(conn->c_statsn);
	SET_PDU_STATSN(tpdu, conn->c_statsn);
	tpdu->p_sn = conn->c_statsn;

	SET_PDU_EXPCMDSN(tpdu, sess->s_expcmdsn);
	SET_PDU_MAXCMDSN(tpdu, sess->s_maxcmdsn);
	SET_PDU_RESPONSE(tpdu, response);

	rv = iscsi_connection_send_pdu(conn, tpdu);
	return rv;
}

static void it_tmf_abort_single_scmd(chiscsi_scsi_command *sc, iscsi_pdu *tmf)
{
	chiscsi_target_lun_class *lclass = sc->lu_class;
	int async = scmd_fpriv_test_bit(sc, CH_SFP_LU_QUEUE_BIT) ? 1:0;

	os_log_info("tmf aborting sc %d, 0x%x, %u,%u,%u, s %u, f 0x%x,0x%lx,0x%lx.\n",
		sc->sc_idx, sc->sc_itt, sc->sc_xfer_len, sc->sc_xfer_left,
		sc->sc_xfer_cnt, sc->sc_state, sc->sc_flag, sc->sc_fscsi,
		sc->sc_fpriv);

//	chiscsi_scsi_command_display(sc, 1);

	if (async) os_lock_irq(sc->sc_lock);

	sc->sc_flag |= SC_FLAG_TMF_ABORT;
	if (!tmf)
		scmd_fpriv_set_bit(sc, CH_SFP_TMF_SENSE_BIT);
	else {
		iscsi_session *sess = sc->sc_sess;
		uint_serial_inc(sess->s_maxcmdsn);
	}

	if (lclass && (lclass->property & (1 << LUN_CLASS_CHELSIO_BIT)) &&
	    !(lclass->property & (1 << LUN_CLASS_TYPE_SCST_BIT))) {
		/* if buffer ready phase then abort, else send tmf to storage driver */

		if (sc->sc_state > CH_SC_STATE_INITIALIZED &&
		    sc->sc_state < CH_SC_STATE_DONE) {
			scmd_set_timestamp(sc, CH_SCMD_TM_FP_ABORT);
			if (async) os_unlock_irq(sc->sc_lock);
			os_log_info("sc 0x%p, itt 0x%x, tmf forward to backend.\n", 
				sc, sc->sc_itt);
                	lclass->fp_scsi_cmd_abort(sc);
        	} else {
			if (async) os_unlock_irq(sc->sc_lock);
			os_log_info("sc 0x%p, itt 0x%x, tmf -> done.\n", 
				sc, sc->sc_itt);
		} 
	}
	else if (async) os_unlock_irq(sc->sc_lock);
}

static int tmf_abort_task(iscsi_pdu *tmf, unsigned char func,
			     unsigned char ibit)
{
	unsigned int refcmdsn = GET_PDU_TMF_REFCMDSN(tmf);
	unsigned int rtt = GET_PDU_TMF_REF_TASK_TAG(tmf);
	iscsi_connection *conn = (iscsi_connection *)tmf->p_conn;
	iscsi_session *sess = conn->c_sess;
	chiscsi_scsi_command *sc = NULL;
	iscsi_pdu *pdu = NULL;

	/*search for the scsi task */
	sc = iscsi_session_find_scmd_by_itt(sess, conn, rtt, 1);

	os_log_info("tmf abort task, rtt 0x%x, refcmdsn 0x%x, sc 0x%p.\n",
			rtt, refcmdsn, sc);
	
	/* refcmdsn not reached yet*/
	if (uint_serial_compare(refcmdsn, tmf->p_sn) > 0) {
		/* response -> Task does not exist. RFC 10.6.1, abort task(c)*/
		os_log_info("tmf abort task, conn 0x%p, ref 0x%x > cmd 0x%x.\n",
			     conn, refcmdsn, tmf->p_sn);
		tmf->p_offset = ISCSI_RESPONSE_TMF_INVALID_TASK;
		return 0;
	} else if (uint_serial_compare(refcmdsn, tmf->p_sn) == 0) {
		/* the task was created by an immediate command */
		if (sc && !(sc->sc_flag & SC_FLAG_IMMEDIATE_CMD)) {
			os_log_info("tmf abort task, sc 0x%p, NOT immediate.\n",
				sc);
			sc = NULL;
		}

		if (!sc && !pdu) {
	                tmf->p_offset = ISCSI_RESPONSE_TMF_INVALID_TASK;
        	        return 0;
        	}
	} else {
		/* non-immediate command */
		if (!sc && !pdu) {
			 /*refcmdsn within range, but task not found*/
			 /*response - > function complete. RFC 10.6.1, abort task (b) */
			tmf->p_offset = ISCSI_RESPONSE_TMF_COMPLETE;
			return 0;
		}
	}

	/* RFC 3720, 10.5.1 */
	if (pdu && pdu->p_opcode == ISCSI_OPCODE_TMF_REQUEST) {
		pdu->p_offset = ISCSI_RESPONSE_TMF_FUNCTION_REJECTED;
		return 0;
	}

	if (sc) {
                chiscsi_target_lun_class *lclass = sc->lu_class;
		iscsi_tmf *ptmf = NULL;

		if (!(lclass->property & (1 << LUN_CLASS_CHELSIO_BIT)) ||
			(lclass->property & (1 << LUN_CLASS_TYPE_SCST_BIT))) {
			ptmf = tmf_save(tmf);
			if (!ptmf) {
				os_log_info("%s: TMF OOM.\n",
					 sess->s_peer_name);
				return -ISCSI_ENOMEM;
			}
			ptmf->p_task = sc;
			tmf->p_flag |= ISCSI_PDU_FLAG_TMF_POSTPONED;
		}

		it_tmf_abort_single_scmd(sc, tmf);

		os_log_debug(ISCSI_DBG_TARGET_API,
                	"sc 0x%p, itt 0x%x, sending tmf abrt_task to"
			" storage driver %s.\n",
			sc, sc->sc_itt, lclass->class_name);

		scmd_set_timestamp(sc, CH_SCMD_TM_FP_TMF);
                lclass->fp_tmf_execute(sess->s_tclass_sess_priv,
				(unsigned long)ptmf, ibit, func,
                                sc->sc_lun, sc);		

	} else if (pdu) {
		pdu->p_flag |= ISCSI_PDU_FLAG_TMF_ABORT;
	}

	return 0;
}

static int it_tmf_task_set(iscsi_pdu *tmf, unsigned char func,
			   unsigned char ibit)
{
	unsigned int lun = GET_PDU_LUN(tmf);
	iscsi_connection *conn = (iscsi_connection *)tmf->p_conn;
	iscsi_session *sess = conn->c_sess;
	iscsi_node *node = sess->s_node;
	chiscsi_target_lun *lu = iscsi_target_lu_find(node, lun);
	chiscsi_target_lun_class *lclass;	
	chiscsi_scsi_command *sc = NULL;
	iscsi_pdu *pdu = NULL;
	chiscsi_queue *scq = sess->s_queue[SESS_SCMDQ_NEW];
	iscsi_tmf *ptmf = NULL;

	os_log_info("tmf abort task set, %s, lun %u.\n", node->n_name, lun);

	lclass = lu ? lu->class : NULL;	
	if (!lclass) {
		lclass = chiscsi_target_lun_class_default(node->tclass);
		if (!lclass) {
			pdu->p_offset = ISCSI_RESPONSE_TMF_INVALID_LUN;
			os_log_info("pdu 0x%p, unable to find lun class!\n", pdu);
			return -ISCSI_EINVAL;
		}
	}

	if (!(lclass->property & (1 << LUN_CLASS_CHELSIO_BIT)) ||
		(lclass->property & (1 << LUN_CLASS_TYPE_SCST_BIT))) {
		ptmf = tmf_save(tmf);
		if (!ptmf) {
			os_log_info("%s: TMF abort task OOM.\n",
					sess->s_peer_name);
			return -ISCSI_ENOMEM;
		}
		tmf->p_flag |= ISCSI_PDU_FLAG_TMF_POSTPONED;
	}

	for (sc = scq->q_head; sc; sc = sc->sc_next) {
		if (uint_serial_compare(tmf->p_sn, sc->sc_cmdsn) > 0 &&
		    sc->sc_lun == lun) {
			os_log_info("tmf task set, lun %u, sc 0x%p.\n",
				lun, sc);
			it_tmf_abort_single_scmd(sc, tmf);
			scmd_set_timestamp(sc, CH_SCMD_TM_FP_TMF);
		}
	}

	os_log_debug(ISCSI_DBG_TARGET_API,
		"sending tmf task set(%d) to storage driver %s.\n",
		func, lclass->class_name);

        lclass->fp_tmf_execute(sess->s_tclass_sess_priv, (unsigned long)ptmf,
			 ibit, func, lun, NULL);

	return 0;
}

static int it_tmf_lu_reset(iscsi_pdu *tmf, unsigned char func,
			   unsigned char ibit)
{
	unsigned int lun = GET_PDU_LUN(tmf);
	iscsi_connection *my_conn = (iscsi_connection *)tmf->p_conn;
	iscsi_session *my_sess = my_conn->c_sess;
	iscsi_node *node = my_sess->s_node;
	chiscsi_queue *sessq = node->n_queue[NODE_SESSQ];
	chiscsi_target_lun *lu = iscsi_target_lu_find(node, lun);
	chiscsi_target_lun_class *lclass;	
	iscsi_session *sess;
	chiscsi_scsi_command *sc = NULL;
	chiscsi_queue *scq = my_sess->s_queue[SESS_SCMDQ_NEW];
	iscsi_tmf *ptmf = NULL;

	os_log_info("tmf lun reset, %s, lun %u.\n", node->n_name, lun);

	lclass = lu ? lu->class : NULL;	
	if (!lclass) {
		lclass = chiscsi_target_lun_class_default(node->tclass);
		if (!lclass) {
			tmf->p_offset = ISCSI_RESPONSE_TMF_INVALID_LUN;
			os_log_info("pdu 0x%p, unable to find lun class!\n", tmf);
			return -ISCSI_EINVAL;
		}
	}

	if (!(lclass->property & (1 << LUN_CLASS_CHELSIO_BIT)) ||
		(lclass->property & (1 << LUN_CLASS_TYPE_SCST_BIT))) {
		ptmf = tmf_save(tmf);
		if (!ptmf) {
			os_log_info("%s: TMF lu reset OOM.\n",
					my_sess->s_peer_name);
			return -ISCSI_ENOMEM;
		}
		tmf->p_flag |= ISCSI_PDU_FLAG_TMF_POSTPONED;
	}

	os_lock(sessq->q_lock);
	/* proporgate abort to other sessions */
	for (sess = sessq->q_head; sess; sess = sess->s_next) {
		iscsi_meta_ptr *mptr;
		chiscsi_queue *resetq = sess->s_queue[SESS_RESETQ];

		if (sess == my_sess)
			continue;

		os_log_info("tmf lun reset, sess 0x%p, inform sess 0x%p.\n",
				my_sess, sess);

		mptr = os_alloc(sizeof(iscsi_meta_ptr),1, 1); 
		if (mptr) {
			mptr->m_val[0] = func;
			mptr->m_val[1] = lun;
			mptr->m_val[2] = ibit;
			meta_ptr_enqueue(lock, resetq, mptr);
			iscsi_sess_flag_set(sess, SESS_FLAG_TARGET_RESET_BIT);
		} else 
			iscsi_sess_flag_set(sess, SESS_FLAG_CLOSE_BIT);
		
		iscsi_schedule_session(sess);
	}
	os_unlock(sessq->q_lock);

	/* abort task of this session */
	for (sc = scq->q_head; sc; sc = sc->sc_next) {
		if (sc->sc_lun == lun) {
			 os_log_info("tmf lun reset, lun %u, sc 0x%p.\n",
					lun, sc);
			it_tmf_abort_single_scmd(sc, tmf);
			scmd_set_timestamp(sc, CH_SCMD_TM_FP_TMF);
		}
	}

	os_log_debug(ISCSI_DBG_TARGET_API,
		"sending tmf lu_reset(%d) sent to storage driver %s.\n",
		func, lclass->class_name);

        lclass->fp_tmf_execute(my_sess->s_tclass_sess_priv, (unsigned long)ptmf,
				ibit, func, lun, NULL);

	iscsi_target_lu_reserve_clear(node, lun);
	tmf->p_offset = ISCSI_RESPONSE_TMF_COMPLETE;
	return 0;
}

static int it_tmf_target_reset(iscsi_pdu *tmf, unsigned char func,
			       unsigned char ibit)
{
	iscsi_connection *conn = (iscsi_connection *)tmf->p_conn;
	iscsi_session *my_sess = conn->c_sess;
	iscsi_node *node = my_sess->s_node;
	chiscsi_queue *sessq = node->n_queue[NODE_SESSQ];
	chiscsi_target_lun_class *lclass;	
	iscsi_session *sess;
	chiscsi_queue *scq = my_sess->s_queue[SESS_SCMDQ_NEW];
	chiscsi_scsi_command *sc;
	iscsi_tmf *ptmf = NULL;

	os_log_info("tmf target reset 0x%x, %s.\n", func, node->n_name);

	lclass = chiscsi_target_lun_class_default(node->tclass);
	if (!lclass) {
		tmf->p_offset = ISCSI_RESPONSE_TMF_INVALID_LUN;
		os_log_info("pdu 0x%p, unable to find lun class!\n", tmf);
		return -ISCSI_EINVAL;
	}

	if (!(lclass->property & (1 << LUN_CLASS_CHELSIO_BIT)) ||
		(lclass->property & (1 << LUN_CLASS_TYPE_SCST_BIT))) {
		ptmf = tmf_save(tmf);
		if (!ptmf) {
			os_log_info("%s: TMF lu reset OOM.\n",
					my_sess->s_peer_name);
			return -ISCSI_ENOMEM;
		}
		tmf->p_flag |= ISCSI_PDU_FLAG_TMF_POSTPONED;
	}

	os_lock(sessq->q_lock);
	/* proporgate abort to other sessions */
	for (sess = sessq->q_head; sess; sess = sess->s_next) {
		iscsi_meta_ptr *mptr;
		chiscsi_queue *resetq = sess->s_queue[SESS_RESETQ];

		if (sess == my_sess)
			continue;

		os_log_info("tmf target reset, inform sess 0x%p.\n", sess);
		mptr = os_alloc(sizeof(iscsi_meta_ptr),1, 1); 
		if (mptr) {
			mptr->m_val[0] = func;
			mptr->m_val[1] = 0;
			mptr->m_val[2] = ibit;
			meta_ptr_enqueue(lock, resetq, mptr);
		} else 
			iscsi_sess_flag_set(sess, SESS_FLAG_CLOSE_BIT);

		iscsi_sess_flag_set(sess, SESS_FLAG_TARGET_RESET_BIT);
		if (func == ISCSI_TMF_FUNCTION_TARGET_COLD_RESET)
			iscsi_sess_flag_set(sess, SESS_FLAG_CLOSE_BIT);

		iscsi_schedule_session(sess);
	}
	os_unlock(sessq->q_lock);

	/* abort task of this session */
	for (sc = scq->q_head; sc; sc = sc->sc_next) {
		if (func == ISCSI_TMF_FUNCTION_TARGET_COLD_RESET ||
		    uint_serial_compare(tmf->p_sn, sc->sc_cmdsn) > 0) {
			os_log_info("tmf target reset, abort sc 0x%p.\n", sc);
			it_tmf_abort_single_scmd(sc, tmf);
			scmd_set_timestamp(sc, CH_SCMD_TM_FP_TMF);
		}
	}
 
	os_log_debug(ISCSI_DBG_TARGET_API,
		"sending tmf target_reset(%d) to storage driver %s.\n",
		 func, lclass->class_name);

	lclass->fp_tmf_execute(my_sess->s_tclass_sess_priv, (unsigned long)ptmf,
				 ibit, func, -1, NULL);

	iscsi_target_reserve_clear(node);
	tmf->p_offset = ISCSI_RESPONSE_TMF_COMPLETE;
	return 0;
}

int it_rcv_tmf_request(iscsi_pdu * pdu)
{
	unsigned char ibit = GET_PDU_I(pdu);
	unsigned char function = GET_PDU_TMF_FUNCTION(pdu);
	iscsi_connection *conn = (iscsi_connection *)pdu->p_conn;
	iscsi_session *sess = conn ? conn->c_sess : NULL;
	iscsi_node *node = sess ? sess->s_node : NULL;
	int     rv;

	/* rfc 3270: 10.5, 10.6 */
	os_log_warn("conn 0x%p, rcv tmf func %u, ibit %u, sn 0x%x, %s,%s.\n",
			conn, function, ibit, pdu->p_sn,
			sess ? sess->s_peer_name : "II",
			node ? node->n_name : "IT");

	switch (function) {
		case  ISCSI_TMF_FUNCTION_CLEAR_ACA:
		case  ISCSI_TMF_FUNCTION_TASK_REASSIGN:
			pdu->p_offset = ISCSI_RESPONSE_TMF_NOT_SUPPORTED;
			break;
		case  ISCSI_TMF_FUNCTION_ABORT_TASK:
			rv = tmf_abort_task(pdu, function, ibit);
			if (rv < 0)
				return rv;
			break;

		case  ISCSI_TMF_FUNCTION_ABORT_TASK_SET:
		case  ISCSI_TMF_FUNCTION_CLEAR_TASK_SET:
			rv = it_tmf_task_set(pdu, function, ibit);
			if (rv < 0)
				return rv;
			break;

		case  ISCSI_TMF_FUNCTION_LOGICAL_UNIT_RESET:
			rv = it_tmf_lu_reset(pdu, function, ibit);
			if (rv < 0)
				return rv;
			break;

		case  ISCSI_TMF_FUNCTION_TARGET_WARM_RESET:
		case  ISCSI_TMF_FUNCTION_TARGET_COLD_RESET:
			rv = it_tmf_target_reset(pdu, function, ibit);
			if (rv < 0)
				return rv;
			break;

		default:
			pdu->p_offset = ISCSI_RESPONSE_TMF_FUNCTION_REJECTED;
	}

	/* send the tmf complete after the session processing is done */
	if (pdu->p_flag & ISCSI_PDU_FLAG_TMF_POSTPONED) 
		return 0;

	return (it_send_tmf_response(conn, pdu->p_itt, pdu->p_offset));
}

int chiscsi_tmf_execution_done(unsigned long hndl, unsigned char tmf_response,
			       chiscsi_scsi_command *sc)
{
	iscsi_tmf *ptmf = (iscsi_tmf *)hndl;

	if (!ptmf) {
		os_log_info("%s: tmf hndl NULL.\n", __func__);
		return -ISCSI_EINVAL;
	}

	os_lock_irq(ptmf->p_lock);

//	os_log_debug(ISCSI_DBG_TARGET_API,
	os_log_info(
		"%s: ptmf 0x%p, itt 0x%x, resp 0x%x, 0x%p, 0x%p, task 0x%p,"
		" 0x%p.\n",
		__func__, ptmf, ptmf->p_itt, tmf_response, ptmf->p_conn,
		ptmf->p_sess, ptmf->p_task, sc);

	ptmf->p_flag &= ~ISCSI_PDU_FLAG_TMF_POSTPONED;
	ptmf->p_resp = tmf_response;

	if (ptmf->p_task != sc)
		os_log_info("%s: task 0x%p vs. 0x%p.\n",
			 __func__, ptmf->p_task, sc);

	if (sc) {
		sc->sc_state = CH_SC_STATE_DONE;
		scmd_set_timestamp(sc, CH_SCMD_TM_CHISCSI_TMF_DONE);
		scmd_fscsi_clear_bit(sc, CH_SFSCSI_HOLD_BIT);
	}

	if (ptmf->p_sess)
		iscsi_schedule_session(ptmf->p_sess);

	os_unlock_irq(ptmf->p_lock);
	
#if 0
	/*except task still allegiant, for all tmf function, scsi cmd should
	  be done */
	if (tmf_response != ISCSI_RESPONSE_TMF_TASK_STILL_ALLEGIANT) {
		sc->sc_state = CH_SC_STATE_DONE;
		iscsi_target_scsi_command_done(sc, 0);
	}
	/* no else yet, TMF_REASSIGN is not supported until ERL2) */
#endif
	return 0;
}

void target_session_tmf_reset(iscsi_session *sess)
{
	iscsi_meta_ptr *mptr;
	iscsi_meta_ptr *mptr_warm = NULL, *mptr_cold = NULL;
	chiscsi_queue *resetq = sess->s_queue[SESS_RESETQ];
	unsigned char func = 0, ibit = 0;
	int cold_reset = 0, warm_reset = 0;
	chiscsi_scsi_command *sc = NULL;
	chiscsi_queue *scq = NULL;
	chiscsi_queue *connq = sess->s_queue[SESS_CONNQ];
	iscsi_connection *conn;

	//MS Cluster - RFC 5208
	for (conn = connq->q_head; conn; conn = conn->c_next) {
		it_xmt_asyncmsg(conn, 
				ISCSI_ASYNC_EVENT_ALL_ACTIVE_TASKS_TERMINATED,
				0, 0, NULL);
	}

	/* target reset over-rides lu reset */
	os_lock(resetq->q_lock);
	for (mptr = resetq->q_head; mptr; mptr = mptr->m_next) {
		/* either lu reset or target reset */
		func = mptr->m_val[1];
		if (func == ISCSI_TMF_FUNCTION_TARGET_WARM_RESET) {
			warm_reset = 1;
			mptr_warm = mptr;
		} else if (func == ISCSI_TMF_FUNCTION_TARGET_COLD_RESET) {
			cold_reset = 1;
			mptr_cold = mptr;
		}
	}

	if (cold_reset) {
		/* keep the very last target cold reset */
		func = ISCSI_TMF_FUNCTION_TARGET_COLD_RESET;
		ibit = mptr_cold->m_val[2];
	} else if (warm_reset) {
		/* keep the very last target warm reset */
		func = ISCSI_TMF_FUNCTION_TARGET_WARM_RESET;
		ibit = mptr_warm->m_val[2];
	}

	if (cold_reset || warm_reset) {
		meta_ptr_dequeue(nolock, resetq, mptr);
		while (mptr) {
			os_free(mptr);
			meta_ptr_dequeue(nolock, resetq, mptr);
		}
	}
	os_unlock(resetq->q_lock);

	/* target reset */
	if (cold_reset || warm_reset) {
		/* abort all scsi task, need send sense back */
		chiscsi_queue *scq = sess->s_queue[SESS_SCMDQ_NEW];
		chiscsi_scsi_command *sc;

		os_log_info("sess 0x%p, target reset, abort %u.\n",
				sess, scq->q_cnt);
		for (sc = scq->q_head; sc; sc = sc->sc_next) {
			os_log_info("sess 0x%p, target reset, abort sc 0x%p.\n",
					sess, sc);
			it_tmf_abort_single_scmd(sc, NULL);
		}
		return;
	}

	/* lu reset */
	os_lock(resetq->q_lock);
	meta_ptr_dequeue(nolock, resetq, mptr);
	os_unlock(resetq->q_lock);
	while (mptr) {
		unsigned int lun = mptr->m_val[1];
		func = mptr->m_val[0];
		ibit = mptr->m_val[2];
		os_free(mptr);

		/* abort all scsi task, need send sense back */
		scq = sess->s_queue[SESS_SCMDQ_NEW];
		os_log_info("sess 0x%p, lun %u reset, abort sc %u.\n",
				sess, lun, scq->q_cnt);
		for (sc = scq->q_head; sc; sc = sc->sc_next) {
			if (sc->sc_lun == lun) {
				os_log_info("lun reset, abort sc 0x%p.\n", sc);
				it_tmf_abort_single_scmd(sc, NULL);
			}
		}
		
		os_lock(resetq->q_lock);
		meta_ptr_dequeue(nolock, resetq, mptr);
		os_unlock(resetq->q_lock);
	}
}
