/*
 * iscsi_target.c -- iscsi target pdu processing
 */

#include <iscsi_auth_api.h>

#include <iscsi_target_api.h>
#include "iscsi_target_private.h"
#ifndef __KERNEL__
#include <arpa/inet.h>
#endif
#include <common/iscsi_target_notif.h>

extern chiscsi_queue *it_portal_q;
extern iscsi_node *it_target_dflt;	/* default target */

int     iscsi_target_session_close(iscsi_session *);

/*
 * Target TX PDUs
 */

/* send a reject pdu */
int iscsi_target_xmt_reject(iscsi_pdu * pdu, int reason)
{
	iscsi_connection *conn = pdu->p_conn;
	iscsi_session *sess = conn->c_sess;
	iscsi_pdu *tpdu;
	int     len, ahslen = (GET_PDU_TOTAL_AHS_LENGTH(pdu) * 4);
	int     rv;

	len = ISCSI_BHS_SIZE + ahslen;

	tpdu = iscsi_pdu_get(conn, 0, 0, len);
	if (!tpdu)
		return -ISCSI_ENOMEM;

	tpdu->p_opcode = ISCSI_OPCODE_REJECT;

	SET_PDU_I(tpdu);
	SET_PDU_F(tpdu);
	SET_PDU_OPCODE(tpdu, ISCSI_OPCODE_REJECT);
	SET_PDU_REJECT_REASON(tpdu, reason);
	uint_serial_inc(conn->c_statsn);
	SET_PDU_STATSN(tpdu, conn->c_statsn);
	tpdu->p_sn = conn->c_statsn;
	SET_PDU_DATA_SEGMENT_LENGTH(tpdu, len);
	if (sess) {
		SET_PDU_EXPCMDSN(tpdu, sess->s_expcmdsn);
		SET_PDU_MAXCMDSN(tpdu, sess->s_maxcmdsn);
	}

	memcpy(tpdu->p_sglist[0].sg_addr, pdu->p_bhs, ISCSI_BHS_SIZE);
	if (ahslen) {
		unsigned char *tmp_ptr;
		tmp_ptr = tpdu->p_sglist[0].sg_addr + ISCSI_BHS_SIZE;
		memcpy(tmp_ptr, pdu->p_ahs, ahslen);
	}

	rv = iscsi_connection_send_pdu(conn, tpdu);

	return rv;
}

/* 
 * it_xmt_nop_in -- send a nop in pdu.
 * The trigger party inidcates that it wants a reply by setting ITT/TTT
 * to a value different from 0xFFFFFFFF
 *
 *  In case of multiphase, nop-in is used to get ack for given data-in pdu. 
 *  offset in the read data is sent as ttt in that case.
 */
int it_xmt_nop_in(iscsi_connection *conn, int reply, int priority,
			unsigned int len, unsigned int offset, void *scmd,
			unsigned int *ttt)
{
	iscsi_session *sess;
	unsigned int tag;
	unsigned int statsn = conn->c_statsn;
	iscsi_pdu *pdu;
	int rv;

	if (!conn)
		return 0;

	sess = conn->c_sess;
	pdu = iscsi_pdu_get(conn, 0, 0, len);
	if (!pdu)
		return -ISCSI_ENOMEM;

	if (reply || offset) {
		tag = offset ? offset : iscsi_session_next_non_cmd_tag(sess);
		if (ttt)
			*ttt = tag;
	} else
 		tag = ISCSI_INVALID_TAG;
		
	pdu->p_opcode = ISCSI_OPCODE_NOP_IN;
	pdu->p_saveq = conn->c_queue[CONN_PDUQ_SENTREQ];

	SET_PDU_OPCODE(pdu, ISCSI_OPCODE_NOP_IN);
	SET_PDU_F(pdu);
	if (priority)
		SET_PDU_I(pdu);
	SET_PDU_ITT(pdu, ISCSI_INVALID_TAG);
	SET_PDU_TTT(pdu, tag);
	/* RFC 6.1.4.2.
 	 * Status/Response not acknowledged for a long time.  The target MAY
 	 * issue a NOP-IN (with a valid Target Transfer Tag or otherwise)
 	 * that carries the next status sequence number it is going to use
 	 * in the StatSN field.
 	 */
	uint_serial_inc(statsn);
	SET_PDU_STATSN(pdu, statsn);
	pdu->p_sn = statsn;
	SET_PDU_EXPCMDSN(pdu, sess->s_expcmdsn);
	SET_PDU_MAXCMDSN(pdu, sess->s_maxcmdsn);
	SET_PDU_AHS_AND_DATA_LENGTH(pdu, len);

	pdu->p_scmd = scmd;
	rv = iscsi_connection_send_pdu(conn, pdu);

	return rv;
}

int it_xmt_asyncmsg(iscsi_connection * conn, unsigned char event,
			   unsigned long long lun, unsigned int len,
			   unsigned char *buf)
{
	iscsi_pdu *pdu;
	int     rv;

	pdu = iscsi_pdu_get(conn, 0, 0, len);
	if (!pdu)
		return -ISCSI_ENOMEM;

	pdu->p_opcode = ISCSI_OPCODE_ASYNC_MESSAGE;

	SET_PDU_OPCODE(pdu, ISCSI_OPCODE_ASYNC_MESSAGE);
	//SET_PDU_I(pdu);
	SET_PDU_F(pdu);
	SET_PDU_ITT(pdu, ISCSI_INVALID_TAG);
	if (conn->c_sess) {
		SET_PDU_EXPCMDSN(pdu, conn->c_sess->s_expcmdsn);
		SET_PDU_MAXCMDSN(pdu, conn->c_sess->s_maxcmdsn);
	}
	uint_serial_inc(conn->c_statsn);
	SET_PDU_STATSN(pdu, conn->c_statsn);
	pdu->p_sn = conn->c_statsn;
	SET_PDU_ASYNC_EVENT(pdu, event);

	if (event == ISCSI_ASYNC_EVENT_SCSI) {
		SET_PDU_LUN(pdu, lun);
	}

	if (len && buf) {
		rv = chiscsi_sglist_copy_bufdata(buf, len,
				 pdu->p_sglist, pdu->p_sgcnt_used);
		SET_PDU_DATA_SEGMENT_LENGTH(pdu, len);
	}

	rv = iscsi_connection_send_pdu(conn, pdu);

	return rv;
}

/*
 * Target RX PDUs
 */

/*
 * Logout Exchange
 */

STATIC int it_rcv_logout_request(iscsi_pdu * pdu)
{
	iscsi_connection *conn = pdu->p_conn;
	iscsi_connection *loconn = conn;
	iscsi_session *sess = conn->c_sess;
	iscsi_pdu *tpdu;
	unsigned short cid = GET_PDU_CID(pdu);
	unsigned char reason = GET_PDU_LOGOUT_REASON(pdu);
	unsigned char response = ISCSI_RESPONSE_LOGOUT_SUCCESS;
	int     rv;

	tpdu = iscsi_pdu_get(conn, 0, 0, 0);
	if (!tpdu)
		return -ISCSI_ENOMEM;

	tpdu->p_opcode = ISCSI_OPCODE_LOGOUT_RESPONSE;

	if ((sess->s_type == ISCSI_SESSION_TYPE_DISCOVERY) &&
	    (reason != ISCSI_LOGOUT_REASON_CLOSE_SESSION)) {
		os_log_warn
			("logout, discovery conn, unexpected reason 0x%x, reject!\n",
			 reason);
		rv = iscsi_target_xmt_reject(pdu, ISCSI_REJECT_REASON_PROTOCOL_ERROR);
		return rv;
	}

	if ((reason != ISCSI_LOGOUT_REASON_CLOSE_SESSION)
	    && (cid != conn->c_cid)) {
		chiscsi_queue *q = conn->c_sess->s_queue[SESS_CONNQ];
		iscsi_conn_qsearch_by_cid(lock, q, loconn, cid);
		if (!loconn){
			os_chiscsi_notify_event(CHISCSI_LOGOUT_FAILURE,
	                        "Initiator=%s, Target=%s", sess->s_peer_name, sess->s_node->n_name);
			response = ISCSI_RESPONSE_LOGOUT_INVALID_CID;
		}
		else if (loconn->c_sess &&
			 (loconn->c_sess->s_type ==
			  ISCSI_SESSION_TYPE_NORMAL)) {
#ifndef __LABTEST__
			os_log_info
				("initiator %s close connection cid 0x%x.\n",
				 loconn->c_sess->s_peer_name, cid);
#endif
		}
	}

	if (reason == ISCSI_LOGOUT_REASON_REMOVE_CONNECTION_FOR_RECOVERY) {
		/* not supported */
		response = ISCSI_RESPONSE_LOGOUT_NO_RECOVERY;
		loconn = NULL;
	}

	if (reason == ISCSI_LOGOUT_REASON_CLOSE_SESSION) {
		chiscsi_queue *connq = sess->s_queue[SESS_CONNQ];
		iscsi_connection *connp;

#ifndef __LABTEST__
		if (sess->s_type == ISCSI_SESSION_TYPE_NORMAL) {
			os_log_info("initiator %s close session.\n",
				    sess->s_peer_name);
		}
#endif
		if (sess->s_type == ISCSI_SESSION_TYPE_NORMAL){
		        os_chiscsi_notify_event(CHISCSI_LOGOUT_SUCCESS,
		                "Initiator=%s, Target=%s", sess->s_peer_name, sess->s_node->n_name);
		}

		os_lock_os_data(sess->os_data);
		iscsi_sess_flag_set(sess, SESS_FLAG_CLOSE_BIT);
		os_unlock_os_data(sess->os_data);
		/* close all other connections too */
		os_lock(connq->q_lock);
		for (connp = connq->q_head; connp; connp = connp->c_next) {
			iscsi_conn_flag_set(connp, CONN_FLAG_CLOSE_BIT);
			connp->c_state = CONN_STATE_LOGOUT;
		}
		os_unlock(connq->q_lock);
	}

	SET_PDU_OPCODE(tpdu, ISCSI_OPCODE_LOGOUT_RESPONSE);
	SET_PDU_F(tpdu);
	SET_PDU_ITT(tpdu, GET_PDU_ITT(pdu));
	uint_serial_inc(conn->c_statsn);
	SET_PDU_STATSN(tpdu, conn->c_statsn);
	tpdu->p_sn = conn->c_statsn;
	SET_PDU_EXPCMDSN(tpdu, conn->c_sess->s_expcmdsn);
	SET_PDU_MAXCMDSN(tpdu, conn->c_sess->s_maxcmdsn);
/*
    SET_PDU_LOGOUT_TIME2WAIT(tpdu, conn->c_sess->s_time2wait);
    SET_PDU_LOGOUT_TIME2RETAIN(tpdu, conn->c_sess->s_time2retain); 
*/
	SET_PDU_RESPONSE(tpdu, response);

	rv = iscsi_connection_send_pdu(conn, tpdu);

	if (loconn) {
		sess->s_conn_cnt--;
		iscsi_conn_flag_set(loconn, CONN_FLAG_CLOSE_BIT);
		loconn->c_state = CONN_STATE_LOGOUT;
	}

	return rv;
}

/*
 *  Nop-In/Nop-Out
 */
STATIC int it_rcv_nop_out(iscsi_pdu * pdu)
{
	iscsi_connection *conn = pdu->p_conn;
	iscsi_session	*sess = conn->c_sess;
	chiscsi_sgvec *sgl = pdu->p_sglist;

	/* if ping request, send response */
	if (GET_PDU_ITT(pdu) != ISCSI_INVALID_TAG) {
		iscsi_pdu *tpdu;
		unsigned int sgcnt = pdu->p_sgcnt_used;
		unsigned int dlen = GET_PDU_DATA_SEGMENT_LENGTH(pdu);
		int     i;

		if (iscsi_test_mode_on(iscsi_test_mode,
					ISCSI_TST_BIT_DROP_NOPOUT)) {
			os_log_info("%s: conn 0x%p, itt 0x%x, test drop.\n",
				__func__, conn, GET_PDU_ITT(pdu));
			return 0;
		}

		/* the length of the ping data is limited to
		 * MaxRecvDataSegmentLength */
		if (dlen > conn->c_pdudatalen_tmax) {
			unsigned int len, diff;
			for (i = 0, len = 0; i < pdu->p_sgcnt_used; i++) {
				len += sgl[i].sg_length;
				if (len > conn->c_pdudatalen_tmax)
					break;
			}
			diff = len - conn->c_pdudatalen_tmax;
			sgl[i].sg_length -= diff;
			if (sgl[i].sg_length)
				sgcnt = i + 1;
			else
				sgcnt = i;
			
			dlen = conn->c_pdudatalen_tmax;
		}

		/* complete cmd, incr. cmd window */
		if (!GET_PDU_I(pdu))
			uint_serial_inc(sess->s_maxcmdsn);

		tpdu = iscsi_pdu_get(conn, 0, 0, dlen);
		if (!tpdu)
			return -ISCSI_ENOMEM;

		tpdu->p_opcode = ISCSI_OPCODE_NOP_IN;

		SET_PDU_OPCODE(tpdu, ISCSI_OPCODE_NOP_IN);
		SET_PDU_F(tpdu);
		SET_PDU_ITT(tpdu, GET_PDU_ITT(pdu));
		SET_PDU_TTT(tpdu, ISCSI_INVALID_TAG);
		uint_serial_inc(conn->c_statsn);
		SET_PDU_STATSN(tpdu, conn->c_statsn);
		tpdu->p_sn = conn->c_statsn;
		SET_PDU_EXPCMDSN(tpdu, sess->s_expcmdsn);
		SET_PDU_MAXCMDSN(tpdu, sess->s_maxcmdsn);

		SET_PDU_DATA_SEGMENT_LENGTH(tpdu, dlen);

		/* copy ping data */
		if (dlen) {
			int rv;
			rv = chiscsi_sglist_copy_sgdata(0, sgl, sgcnt,
                                        tpdu->p_sglist, tpdu->p_sgcnt_used);
                	if (rv < 0) return rv;
		}

		return (iscsi_connection_send_pdu(conn, tpdu));
	}

	/* if ping response, match against pending ping */
	if (GET_PDU_TTT(pdu) != ISCSI_INVALID_TAG) {
		unsigned int tag = GET_PDU_TTT(pdu);
		unsigned int datalen, expdatalen;
		iscsi_pdu *reqpdu;
		chiscsi_queue *q = conn->c_queue[CONN_PDUQ_SENTREQ];

		/* find matching nop out pdu */
		reqpdu = q->q_head;
		while (reqpdu) {
			if ((GET_PDU_OPCODE(reqpdu) == ISCSI_OPCODE_NOP_IN) &&
			    (GET_PDU_TTT(reqpdu) == tag))
				break;
			reqpdu = reqpdu->p_next;
		}

		if (!reqpdu) {
			os_log_info
				("NOP_OUT: no matching nop in pdu 0x%x, ignore.\n",
				 tag);
			return 0;
		}

		iscsi_pdu_ch_qremove(nolock, q, reqpdu);
		iscsi_conn_flag_clear(conn, CONN_FLAG_PINGED_BIT);

		datalen = GET_PDU_DATA_SEGMENT_LENGTH(pdu);
		expdatalen = GET_PDU_DATA_SEGMENT_LENGTH(reqpdu);
		if (datalen != expdatalen)
			os_log_info
				("NOP_OUT: conn 0x%p datalen mismatch %u != %u\n",
				 conn, expdatalen, datalen);
		if (chiscsi_sglist_compare
		    (pdu->p_sglist, pdu->p_sgcnt_used, reqpdu->p_sglist,
		     reqpdu->p_sgcnt_used))
			os_log_info("NOP_OUT: conn 0x%p data mismatch\n", conn);

		/*currently we are not using this function */	
		if (reqpdu->p_scmd) {
			it_scmd_read_buffer_acked(
				(chiscsi_scsi_command *)reqpdu->p_scmd,
				GET_PDU_TTT(reqpdu));
		}

		iscsi_pdu_done(reqpdu);
		return 0;
	}

	return 0;
}

/*
 * SNACK Request
 */
STATIC int it_rcv_snack_request(iscsi_pdu * pdu)
{
	int     rv;
	/* send SNACK reject so UNH script will be happy */
	//rv = iscsi_target_xmt_reject(pdu, ISCSI_REJECT_REASON_CMD_NOT_SUPPORTED);
	rv = iscsi_target_xmt_reject(pdu, ISCSI_REJECT_REASON_SNACK_REJECT);
	return rv;
}

/*
 * Target conn/sess closing
 */

/* the calling routing should hold session lock if there is any */
int iscsi_target_connection_close(iscsi_connection * conn)
{
	iscsi_session *sess = conn->c_sess;


	/* the connection could be the listening server or the an iscsi conn. */
	if (conn->c_state == CONN_STATE_FFP && sess && 
	    sess->s_type != ISCSI_SESSION_TYPE_DISCOVERY) {
		chiscsi_queue *connq = sess->s_queue[SESS_CONNQ];
		/* inform initiator the sess/conn is being dropped */
		iscsi_conn_flag_set(conn, CONN_FLAG_TX_PUSH_BIT);
		os_log_debug(ISCSI_DBG_CONN,
			"conn 0x%p, close, xmit async, %d.\n",
			conn, connq->q_cnt);
		if (connq->q_cnt > 1)
			it_xmt_asyncmsg(conn,
					ISCSI_ASYNC_EVENT_TARGET_PDU_DROP_CONN,
					0, 0, NULL);
		else
			it_xmt_asyncmsg(conn,
					ISCSI_ASYNC_EVENT_TARGET_PDU_DROP_SESS,
					0, 0, NULL);
	}
	conn->c_state = CONN_STATE_CLOSING;
	iscsi_connection_closing(conn);
	return 0;
}

int iscsi_target_session_close(iscsi_session * sess)
{
	if (!sess->s_node)
        	return -ISCSI_ENULL;

	if (sess->s_type == ISCSI_SESSION_TYPE_NORMAL) {
		if (iscsi_sess_flag_test(sess, SESS_FLAG_FFP_BIT)) {
			iscsi_node *node = sess->s_node;
			chiscsi_target_class *tclass = node->tclass;
			chiscsi_queue *scq = sess->s_queue[SESS_SCMDQ_NEW];
			chiscsi_scsi_command *sc = NULL;

			iscsi_target_lu_reserve_clear_by_session(sess);

			/* abort all outstanding scsi commands*/
	                for (sc = scq->q_head; sc; sc = sc->sc_next) {
				chiscsi_target_lun_class *lclass = sc->lu_class;
				if (!it_scmd_state_abortable(sc) && 
					lclass->fp_scsi_cmd_abort) {
					sc->sc_flag |= SC_FLAG_SESS_ABORT;
					scmd_set_timestamp(sc, CH_SCMD_TM_FP_ABORT);
					lclass->fp_scsi_cmd_abort(sc);
					os_log_info("abort sc cmd scmd itt 0x%u \n", 
						sc->sc_itt);
				}
			}

			if (tclass->fp_session_removed)
				 tclass->fp_session_removed((unsigned long)sess,
							sess->s_peer_name,
							node->n_name);
		}
	}
	return (iscsi_session_free(sess));
}

static int rx_pdu_validate_opcode(iscsi_pdu *pdu)
{
	iscsi_connection *conn = pdu->p_conn;

	if (!(IS_INITIATOR_OPCODE(pdu->p_opcode))) {
		os_log_info("rcv non-initiator opcode 0x%02x.\n",
			pdu->p_opcode);
#if 0
		rv = iscsi_target_xmt_reject(pdu,
				ISCSI_REJECT_REASON_CMD_NOT_SUPPORTED);
#endif
		return -ISCSI_EIO;
	}

	if (conn->c_state == CONN_STATE_FFP) { 
		iscsi_session *sess = conn->c_sess;

		if (sess->s_type == ISCSI_SESSION_TYPE_DISCOVERY &&
			pdu->p_opcode != ISCSI_OPCODE_TEXT_REQUEST &&
			pdu->p_opcode != ISCSI_OPCODE_LOGOUT_REQUEST) {

			os_log_info("rcv opcode 0x%02x during discovery.\n",
				pdu->p_opcode);

			return -ISCSI_EIO;
		}
	} else if (conn->c_state == CONN_STATE_LOGOUT) { 
		os_log_info("rcv opcode 0x%02x during logout.\n",
				pdu->p_opcode);
		return -ISCSI_EIO;
	}

	if (conn->c_state < CONN_STATE_FFP &&
			pdu->p_opcode != ISCSI_OPCODE_LOGIN_REQUEST) {
		iscsi_session *sess = conn->c_sess;
		iscsi_pdu *tpdu;

		/* RFC3720, 3.2.3:
		 * A target receiving any PDU except a Login request before
		 * the Login phase is started MUST immediately terminate the
		 * connection.
		 * Once the Login phase has started, a target receiving a
		 * non-login pdu MUST send a login reject (with status 
		 * "invalid during login") and then disconnect.
		 */

		if (conn->c_state <= CONN_STATE_LOGIN) {
			os_log_info("rcv non-login opcode 0x%02x before login phase.\n",
				pdu->p_opcode);
			return -ISCSI_EIO;
		}

		tpdu = iscsi_pdu_get(conn, 0, 0, 0);
		if (!tpdu)
			return -ISCSI_ENOMEM;
		tpdu->p_opcode = ISCSI_OPCODE_LOGIN_RESPONSE;
		tpdu->p_sn = 0;
		SET_PDU_OPCODE(tpdu, ISCSI_OPCODE_LOGIN_RESPONSE);
		SET_PDU_LOGIN_VERSION_MAX(tpdu, conn->login.version);
		SET_PDU_LOGIN_VERSION_ACTIVE(tpdu, conn->login.version);
		if (sess)
			SET_PDU_LOGIN_ISID(tpdu, sess->s_isid);
		SET_PDU_ITT(tpdu, conn->c_text_tag);
		CLR_PDU_LOGIN_T(tpdu);
		SET_PDU_LOGIN_CSG(tpdu, 0);

		SET_PDU_STATSN(tpdu, 0);
		SET_PDU_EXPCMDSN(tpdu, 0);
		SET_PDU_MAXCMDSN(tpdu, 0);
		SET_PDU_LOGIN_STATUS_CLASS(tpdu,
				ISCSI_LOGIN_STATUS_CLASS_INITIATOR_ERROR);
		SET_PDU_LOGIN_STATUS_DETAIL(tpdu,
				ISCSI_LOGIN_STATUS_DETAIL_INVALID_REQUEST);
		iscsi_connection_send_pdu(conn, tpdu);
		return -ISCSI_EIO;
	}
	return 0;
}

static int rx_pdu_validate_header_digest(iscsi_pdu *pdu)
{
	iscsi_connection *conn = pdu->p_conn;

	if (!pdu->p_hdlen)
		return 0;

	if (!(conn->c_offload_mode & ISCSI_OFFLOAD_MODE_CRC))
		if (iscsi_header_digest_check(pdu)) 
			pdu->p_flag |= ISCSI_PDU_FLAG_ERR_HDR_DIGEST;

	if (pdu->p_flag & ISCSI_PDU_FLAG_ERR_HDR_DIGEST) {
		iscsi_session *sess = conn->c_sess;

		os_log_info("sess %s conn 0x%p, header digest error.\n",
			sess ? sess->s_peer_name : "x", conn);
		iscsi_pdu_display((void *) pdu, NULL, 0, 1);
		return -ISCSI_EIO;
	}

	return 0;
}

static int rx_pdu_validate_data_digest(iscsi_pdu *pdu)
{
	iscsi_connection *conn = pdu->p_conn;

	if (!pdu->p_ddlen)
		return 0;

	if (!(conn->c_offload_mode & ISCSI_OFFLOAD_MODE_CRC)) {
		if (iscsi_data_digest_check(pdu))
			pdu->p_flag |= ISCSI_PDU_FLAG_ERR_DATA_DIGEST;
	}

	if (pdu->p_flag & ISCSI_PDU_FLAG_ERR_DATA_DIGEST) {
		iscsi_session *sess = conn->c_sess;

		os_log_info("sess %s conn 0x%p, data digest error.\n",
			sess->s_peer_name, conn);
		iscsi_pdu_display((void *) pdu, NULL, 0, 1);
		return -ISCSI_EIO;
	}

	return 0;
}

static int rx_pdu_validate_cmdsn(iscsi_pdu *pdu)
{
	iscsi_connection *conn = pdu->p_conn;
	iscsi_session *sess = conn->c_sess;
	unsigned int expcmdsn;
	unsigned int cmdsn = pdu->p_sn;

	if (pdu->p_opcode == ISCSI_OPCODE_LOGIN_REQUEST ||
	    pdu->p_opcode == ISCSI_OPCODE_SCSI_DATA_OUT ||
	    pdu->p_opcode == ISCSI_OPCODE_SNACK_REQUEST)
		return 0;

	if (GET_PDU_I(pdu) || !sess)
		return 0;

	expcmdsn = sess->s_expcmdsn;
	if (!(iscsi_test_mode_on(iscsi_test_mode,
				ISCSI_TST_BIT_NOUPD_EXPCMDSN)) &&
	    cmdsn == expcmdsn) {
		uint_serial_inc(sess->s_expcmdsn);
		return 0;
	}

	if (uint_serial_compare(cmdsn, expcmdsn) < 0 ||
	    uint_serial_compare(cmdsn, sess->s_maxcmdsn) > 0) {
		pdu->p_flag |= ISCSI_PDU_FLAG_OOR;
		pdu->p_flag |= ISCSI_PDU_FLAG_DATA_SKIP;

		if (pdu->p_opcode == ISCSI_OPCODE_SCSI_COMMAND) {
			unsigned int itt = GET_PDU_ITT(pdu);
			chiscsi_scsi_command *sc = iscsi_session_find_scmd_by_itt(
						sess, conn, itt, 1);

			if (!sc) {
				os_log_info("sess %s, pdu op 0x%x, itt 0x%x, "
					"sn 0x%x, 0x%x ~ 0x%x, drop.\n",
					sess->s_peer_name, pdu->p_opcode, itt,
					cmdsn, expcmdsn, sess->s_maxcmdsn);
				return 0;
			}

			os_log_info("sess %s, pdu op 0x%x, itt 0x%x, "
				"sn 0x%x, 0x%x ~ 0x%x, sc 0x%p.\n",
				sess->s_peer_name, pdu->p_opcode, itt, cmdsn,
				expcmdsn, sess->s_maxcmdsn, sc);
			if (sc->sc_state >= CH_SC_STATE_STATUS)
				/* re-send the response */
				sc->sc_state = CH_SC_STATE_STATUS;
			else
				chiscsi_scsi_command_display(sc, 1);
			return 0;
		}	

		/* out of range, drop */
		os_log_info("sess %s, pdu op 0x%x, sn 0x%x, OOR 0x%x ~ 0x%x.\n",
			sess->s_peer_name, pdu->p_opcode, cmdsn, expcmdsn,
			sess->s_maxcmdsn);
		iscsi_display_byte_string("PDU BHS", pdu->p_bhs,
					0, ISCSI_BHS_SIZE, NULL, 0);


		return 0;
	}

	/* within range, but not the next yet */
	if (iscsi_test_mode_on(iscsi_test_mode, ISCSI_TST_BIT_NOUPD_EXPCMDSN) ||
	    sess->s_queue[SESS_CONNQ]->q_cnt == 1) {
		os_log_warn("sess %s,0x%p,%u cmdsn hole 0x%x (0x%x ~ 0x%x), close.\n",
			sess->s_peer_name,
			sess, sess->s_queue[SESS_CONNQ]->q_cnt,
			cmdsn, expcmdsn, sess->s_maxcmdsn);
		return -ISCSI_EIO;
	} 

#if 0
	os_log_info("sess %s,0x%p,%u cmdsn hole 0x%x (0x%x ~ 0x%x), halt.\n",
			sess->s_peer_name,
			sess, sess->s_queue[SESS_CONNQ]->q_cnt,
			cmdsn, expcmdsn, sess->s_maxcmdsn);
#endif

	return 1;
}

static void it_session_check_scmd_acked(iscsi_session *sess, int force)
{
	chiscsi_queue *q = sess->s_queue[SESS_SCMDQ_NEW];
	chiscsi_scsi_command *sc, *scnext;

	for (sc = q->q_head; sc; sc = scnext) {
		iscsi_connection *conn = sc->sc_conn;

		scnext = sc->sc_next;
		if (sc->sc_state != CH_SC_STATE_DONE)
			continue;

		if (uint_serial_compare(sc->sc_statsn, conn->c_expstatsn) < 0)
			scmd_fscsi_set_bit(sc, CH_SFSCSI_STATUS_ACKED_BIT);
		else if (force) {
			os_log_info("scmd 0x%p, done, 0x%x/0x%x release.\n",
				sc, sc->sc_statsn, conn->c_expstatsn);
			scmd_fscsi_set_bit(sc, CH_SFSCSI_STATUS_ACKED_BIT);
		}

		if (scmd_fscsi_test_bit(sc, CH_SFSCSI_STATUS_ACKED_BIT))
			it_scmd_acked(sc);
	}
}

static int rx_pdu_update_statsn(iscsi_pdu *pdu)
{
	iscsi_connection *conn = pdu->p_conn;
	iscsi_session *sess = conn->c_sess;
	unsigned int expstatsn = GET_PDU_EXPSTATSN(pdu);
	unsigned int max = conn->c_statsn;

	if (!sess)
		return 0;

	uint_serial_inc(max);
	if (uint_serial_compare(expstatsn, max) > 0) {
		os_log_info("conn 0x%p, expstatsn jump %u > %u/%u, ignore.\n",
			conn, expstatsn, max, conn->c_statsn);
		return 0;
	}

	if (uint_serial_compare(expstatsn, conn->c_expstatsn) <= 0)
		return 0;

	conn->c_expstatsn = expstatsn;
	it_session_check_scmd_acked(sess, 0);
	iscsi_connection_clean_sentq(conn, conn->c_expstatsn);

	return 0;
}

static int rx_pdu_ffp_validate_bhs(iscsi_pdu *pdu)
{
	int rv;

	rv = rx_pdu_validate_cmdsn(pdu);
	if (rv < 0)
		return rv;
	if (rv) {
		iscsi_connection *conn = pdu->p_conn;

		pdu->p_flag |= ISCSI_PDU_FLAG_BHS_PROC_DELAY;
		iscsi_conn_flag_set(conn, CONN_FLAG_RX_READY_BIT);
		return 0;
	}
	if (!(pdu->p_flag & ISCSI_PDU_FLAG_OOR))
		/* update statsn */
		rx_pdu_update_statsn(pdu);
	return 0;
}

static int rx_pdu_proc_header(iscsi_pdu *pdu)
{
	iscsi_connection *conn = pdu->p_conn;
	int rv = 0;

	pdu->p_sglist = conn->rx_sglist;
	pdu->p_sgcnt_total = ISCSI_RX_PDU_SGCNT;

	if (pdu->p_opcode == ISCSI_OPCODE_SCSI_COMMAND) {
		rv = iscsi_target_pdu_scsi_command_bhs_rcv(pdu);
	} else if (pdu->p_opcode == ISCSI_OPCODE_SCSI_DATA_OUT) {
		rv = iscsi_target_pdu_data_out_bhs_rcv(pdu);
	} else if (pdu->p_datalen) {
		//os_log_info("pdu 0x%02x alloc buffer %u.\n", pdu->p_opcode, pdu->p_datalen);
		pdu->p_sgcnt_used = 1;
		rv = chiscsi_sglist_add_buffer(pdu->p_sglist, pdu->p_datalen, 1);
	}
	return rv;
}

static inline int rx_pdu_delayed_header_proc(iscsi_pdu *pdu)
{
	iscsi_connection *conn = pdu->p_conn;
	int rv;

	if (!(pdu->p_flag & ISCSI_PDU_FLAG_BHS_PROC_DELAY)) {
		os_log_info("conn 0x%p, pdu 0x%p, NOT delayed.\n", conn, pdu);
		return 0;
	}

	pdu->p_flag &= ~ISCSI_PDU_FLAG_BHS_PROC_DELAY;
	if (conn->c_state >= CONN_STATE_FFP) {
		rv = rx_pdu_ffp_validate_bhs(pdu);
		if (rv < 0)
			return rv;
		if (pdu->p_flag & ISCSI_PDU_FLAG_BHS_PROC_DELAY)
			return 0;
	}

	if (!(pdu->p_flag & ISCSI_PDU_FLAG_OOR)) {
		/* process the bhs */
		rv = rx_pdu_proc_header(pdu);
		if (rv < 0) {
			os_log_info("%u/%u, delay proc_header error.\n",
				pdu->p_offset, pdu->p_totallen);
			return rv;
		}
	}

	return 0;
}

static int rx_pdu_proc_data(iscsi_pdu *pdu)
{
	iscsi_connection *conn = pdu->p_conn;
	iscsi_session *sess = conn->c_sess;
	int rv = 0;

	switch (pdu->p_opcode) {
		case ISCSI_OPCODE_SCSI_COMMAND:
			rv = iscsi_target_rcv_scsi_command(pdu);
			break;
		case ISCSI_OPCODE_SCSI_DATA_OUT:
			rv = iscsi_target_rcv_data_out(pdu);
			break;
		case ISCSI_OPCODE_LOGIN_REQUEST:
			rv = it_rcv_login_request(pdu);
			break;
		case ISCSI_OPCODE_LOGOUT_REQUEST:
			rv = it_rcv_logout_request(pdu);
			break;
		case ISCSI_OPCODE_NOP_OUT:
			 if (!(pdu->p_flag & ISCSI_PDU_FLAG_TMF_ABORT))
				rv = it_rcv_nop_out(pdu);
			break;
		case ISCSI_OPCODE_TMF_REQUEST:
			os_log_info("conn 0x%p, sess 0x%p, rcv tmf, 0x%x.\n",
				conn, sess, pdu->p_sn);
			iscsi_session_display(sess, 1);
			rv = it_rcv_tmf_request(pdu);
			break;
		case ISCSI_OPCODE_TEXT_REQUEST:
			rv = target_rcv_text_request(pdu);
			break;
		case ISCSI_OPCODE_SNACK_REQUEST:
			rv = it_rcv_snack_request(pdu);
			break;
		default:
			return -ISCSI_EIO;
	}
	return rv;
}

static void conn_rx_pdu_init(iscsi_connection *conn)
{
	iscsi_pdu *pdu = &conn->c_pdu_rx;

	if (pdu->p_sgcnt_used) {
		int i;
		chiscsi_sgvec *sg = pdu->p_sglist;

		for (i = 0; i < pdu->p_sgcnt_used; i++, sg++)
			if (sg->sg_flag & CHISCSI_SG_BUF_ALLOC)
				os_free(sg->sg_addr);
		memset(conn->rx_sglist, 0,
			ISCSI_RX_PDU_SGCNT * sizeof(chiscsi_sgvec));
	}

	memset(pdu, 0, sizeof(*pdu));

	pdu->p_conn = conn;
	pdu->p_itt = ISCSI_INVALID_TAG;
	
	pdu->p_bhs = pdu->p_head;
        pdu->p_hdigest = (unsigned int *) (&(pdu->p_head[ISCSI_BHS_SIZE]));
        pdu->p_ddigest = (unsigned int *) (&(pdu->p_tail[ISCSI_PDU_MAX_PAD_SIZE]));
	pdu->p_prot_sglist = pdu->p_pi_sglist;
	pdu->p_pi_sgcnt_total = ISCSI_PDU_PI_SGBUF_COUNT;
}

static int conn_rx(iscsi_connection *conn)
{
	iscsi_pdu *pdu = &conn->c_pdu_rx;
	iscsi_socket *isock = conn->c_isock;
	int in_login = (conn->c_state < CONN_STATE_FFP) ? 1 : 0;
	int rv = 0;

	if (!isock || conn->c_state < CONN_STATE_LOGIN ||
	    conn->c_state > CONN_STATE_CLOSING) {
		os_log_info("conn rx 0x%p, bad state 0x%x, isock 0x%p.\n",
			conn, conn->c_state, isock);
		return -ISCSI_EIO;
        }

read_pdu:
	while (!pdu->p_totallen || pdu->p_offset < pdu->p_totallen) {
		unsigned int hlen = ISCSI_BHS_SIZE + pdu->p_ahslen +
				pdu->p_hdlen;

		if (pdu->p_offset < hlen) { 
			rv = isock->sk_read_pdu_header(isock, pdu);
			if (rv <= 0)
				return rv;

			/* one more time for ahs and header digest */
			hlen = ISCSI_BHS_SIZE + pdu->p_ahslen + pdu->p_hdlen;
			if (pdu->p_offset < hlen) { 
				rv = isock->sk_read_pdu_header(isock, pdu);
				if (rv <= 0)
					return rv;
				hlen = ISCSI_BHS_SIZE + pdu->p_ahslen +
					pdu->p_hdlen;
			}

			if (pdu->p_offset < hlen)
				continue;

			os_log_debug(ISCSI_DBG_PDU_RX,
				"conn 0x%p, rcv pdu 0x%p, op 0x%x, cmdsn 0x%x, itt 0x%x, %u,%u.\n",
				conn, pdu, pdu->p_opcode, pdu->p_sn,
				pdu->p_itt, pdu->p_datalen, pdu->p_totallen);

			rv = rx_pdu_validate_header_digest(pdu);
			if (rv < 0) {
				os_log_info("conn 0x%p, pdu 0x%p, %u/%u, hcrc erro.\n", 
					conn, pdu, pdu->p_offset,
					pdu->p_totallen);
				return rv;
			}

			rv = rx_pdu_validate_opcode(pdu);
			if (rv < 0) {
				os_log_info("conn 0x%p, pdu 0x%p, %u/%u, opcode error.\n",
					conn, pdu, pdu->p_offset,
					pdu->p_totallen);
				return rv;
			}

			/* 0 valid, 1 cmdsn hole */
			if (!in_login) { 
				rv = rx_pdu_ffp_validate_bhs(pdu);
				if (rv < 0)
					return rv;
				if (pdu->p_flag & ISCSI_PDU_FLAG_BHS_PROC_DELAY)
					return 0;
				/* pdu need to be dropped */
				if (pdu->p_flag & ISCSI_PDU_FLAG_OOR)
					goto read_pdu_data;
			}

			/* process the bhs */
			rv = rx_pdu_proc_header(pdu);
			if (rv < 0)
				return rv;
		}

		/* header could be already read */
		if (pdu->p_flag & ISCSI_PDU_FLAG_BHS_PROC_DELAY) {
			rv = rx_pdu_delayed_header_proc(pdu);
			if (rv < 0)
				return rv;
			if (pdu->p_flag & ISCSI_PDU_FLAG_BHS_PROC_DELAY)
				return 0;
		}

		/* read data */
read_pdu_data:
		if (pdu->p_offset < pdu->p_totallen) { 
			rv = isock->sk_read_pdu_data(isock, pdu);
			if (rv <= 0)
				return rv;
		}

		/* read pi if available */
		if (pdu->pi_info.prot_op) {
			/* Before calling it here, we have ensured that
 			 * the pdu->p_prot_sglist is holding valid sgls */
			rv = isock->sk_read_pdu_pi(isock, pdu);
		}
	}

//	iscsi_pdu_display((void *) pdu, NULL, 0, 1);

	/* pdu is complete */
	if (pdu->p_flag & ISCSI_PDU_FLAG_BHS_PROC_DELAY) {
		rv = rx_pdu_delayed_header_proc(pdu);
		if (rv < 0)
			return rv;
		if (pdu->p_flag & ISCSI_PDU_FLAG_BHS_PROC_DELAY)
			return 0;
	}

	pdu->p_offset = 0;
	if (pdu->p_flag & ISCSI_PDU_FLAG_OOR)
		goto done;

	if (pdu->p_datalen) {
		rv = rx_pdu_validate_data_digest(pdu);
		if (rv < 0) {
			rv = iscsi_target_xmt_reject(pdu,
					ISCSI_REJECT_REASON_DATA_DIGEST_ERROR);
			/* for Scsi Data-Out PDU, a recovery R2T will
			 * be sent when the pdu is processed */
			if (pdu->p_opcode != ISCSI_OPCODE_SCSI_DATA_OUT)
				goto done;
		}
		if (pdu->p_flag & ISCSI_PDU_FLAG_ERR_DATA_PAD) {
			os_log_info("conn 0x%p, pdu 0x%p, pad error, reset.\n",
                                	conn, pdu);
			return -ISCSI_EIO;
		}
	}

	rv = rx_pdu_proc_data(pdu);
	if (rv < 0)
		return rv;

done:
	conn_rx_pdu_init(conn);

	if (rv < 0)
		return rv;

	if (in_login && conn->c_state == CONN_STATE_FFP) {
		iscsi_conn_flag_set(conn, CONN_FLAG_RX_READY_BIT);
		return 0;
	}

	goto read_pdu;
}

STATIC int it_connection_timeout_check(iscsi_connection *conn, int ackn)
{
	/* no timeout */
	if (!conn->c_timeout && !ackn)
		return 0;

	if (iscsi_conn_flag_testnclear(conn, CONN_FLAG_BUSY_BIT) ||
	    iscsi_conn_flag_test(conn, CONN_FLAG_RX_READY_BIT)) {
		conn_timeout_clear(conn);
		return 0;
	}

	if (iscsi_conn_flag_test(conn, CONN_FLAG_CLOSE_BIT))
		return 1;

	conn->c_idle++;
	if (conn->c_timeout && conn->c_idle >= conn->c_timeout) {
		if (!iscsi_conn_flag_test(conn, CONN_FLAG_PINGED_BIT)) {
			if (it_xmt_nop_in(conn, 1, 0, 0, 0, NULL, NULL) < 0) {
				os_log_info("conn 0x%p nop in failed.\n", conn);
				iscsi_conn_flag_set(conn, CONN_FLAG_CLOSE_BIT);
				return 1;
			}
			iscsi_conn_flag_set(conn, CONN_FLAG_PINGED_BIT);
			conn->c_idle = 0;
		} else if (!(iscsi_conn_flag_test(conn, CONN_FLAG_RX_READY_BIT))) {
			iscsi_conn_flag_set(conn, CONN_FLAG_TIMEOUT_BIT);
			return 1;
		}
	} else if (ackn && conn->c_idle >= ISCSI_SESSION_CH_SCMD_ACK_WAIT_TIME &&
		!iscsi_conn_flag_test(conn, CONN_FLAG_PINGED_BIT)) {
		if (it_xmt_nop_in(conn, 1, 0, 0, 0, NULL, NULL) < 0) {
			os_log_info("conn 0x%p nop in failed.\n", conn);
			iscsi_conn_flag_set(conn, CONN_FLAG_CLOSE_BIT);
			return 1;
		}
		iscsi_conn_flag_set(conn, CONN_FLAG_PINGED_BIT);
		conn->c_idle = 0;
	}

	return 0;
}

/*
 * Target Thread Processing Loop
 * There are 1 + N thread for iscsi target processing:
 * - 1 main/login thread which handles the login requests from the initiator
 * - N worker/session thread which handles the sessions complete the login 
 *	stage and are in the FFP state.
 * 	N is # of CPUs (including HT) in the system
 */

/* 
 *
 * target main thread processing -- accept and iscsi login 
 *
 */
STATIC int it_main_accept_connection(iscsi_connection * lconn)
{
	if (iscsi_conn_flag_test(lconn, CONN_FLAG_CLOSED_BIT)) {
		iscsi_connection_destroy(lconn);
	} else if (iscsi_conn_flag_test(lconn, CONN_FLAG_CLOSE_BIT)) {
		iscsi_target_connection_close(lconn);
	} else if (iscsi_conn_flag_testnclear(lconn, CONN_FLAG_RX_READY_BIT)) {
		iscsi_connection *conn;
		int     rv;
		iscsi_thread *thp = th_main_ptr;

		while (!(iscsi_test_mode_on(iscsi_test_mode,
					ISCSI_TST_BIT_PAUSE_ACCEPT)) &&
			(iscsi_connection_accept(lconn, &conn)) >= 0) {
			/* the tcp connection is already closed */
			if (!conn)
				continue;

			/* save the connection */
			rv = iscsi_thread_add_data(thp, &conn->c_thinfo, conn);
			if (rv < 0) {
				iscsi_conn_flag_set(conn, CONN_FLAG_CLOSE_BIT);
				iscsi_target_connection_close(conn);
			} else {
				iscsi_conn_flag_set(conn, CONN_FLAG_THREAD_BIT);
				/* setup connection to wait for login */
				conn->c_state = CONN_STATE_LOGIN;
				conn->c_text_tag = ISCSI_INVALID_TAG;
				conn->c_portal = lconn->c_portal;
				conn->c_timeout = lconn->c_portal->p_timeout;

				/* force a read */
				iscsi_conn_flag_set(conn,
						    CONN_FLAG_RX_READY_BIT);
				mask_list_set_bit(conn->c_thinfo.mlist,
						  conn->c_thinfo.mpos);
				iscsi_thread_flag_set(thp,
						      THREAD_FLAG_WORK_BIT);
				conn_rx_pdu_init(conn);
			}
		}
	}
	return 0;
}

STATIC int it_main_login_connection(iscsi_connection * conn)
{
	int     rv = 0;
	iscsi_session *sess = conn->c_sess;

	if (sess && iscsi_sess_flag_test(sess, SESS_FLAG_CLOSE_BIT)) {
		return (iscsi_target_session_close(sess));
	}

	if (iscsi_conn_flag_test(conn, CONN_FLAG_CLOSED_BIT)) {
		goto out;
	}

	/* normal connection */
	if (iscsi_conn_flag_test(conn, CONN_FLAG_CLOSE_BIT)) {
		goto out;
	}

	rv = iscsi_connection_push_pdus(conn);
	if (rv < 0) {
		os_log_info("%s conn 0x%p push pdus failed %d.\n", __func__, conn, rv);
		goto out;
	}

	/* login callbacks from the storage driver */
        if (iscsi_conn_flag_testnclear(conn, CONN_FLAG_LOGIN_CALLBACK_BIT)) {
		rv = target_login_respond(conn);
		if (rv < 0) {
			os_log_info("%s conn 0x%p callback, rv %d.\n", __func__, conn, rv);
			goto out;
		}
	}

	if (iscsi_conn_flag_testnclear(conn, CONN_FLAG_RX_READY_BIT)) {
		rv = conn_rx(conn);
		sess = conn->c_sess;
		if (rv < 0)
			goto out;
		iscsi_conn_flag_set(conn, CONN_FLAG_BUSY_BIT);
	}

	/* login successful, move the connection to a worker thread */
	if (!(iscsi_conn_flag_test(conn, CONN_FLAG_CLOSE_BIT)) &&
	    (conn->c_state == CONN_STATE_FFP)) {
		sess = conn->c_sess;
		if (sess->s_type == ISCSI_SESSION_TYPE_NORMAL) {
			rv = chiscsi_scsi_command_pool_init(
					sess->s_queue[SESS_SCMDQ_FREE],
					(sess->s_scmdqlen << 1) + 1);
                        if (rv < 0) {
				os_log_info("sess 0x%p scmd pool failed, %d.\n",
					 sess, rv);
				goto out;
			}
			sess->s_scmdmax = rv;
#ifndef __LABTEST__
			os_log_info("%s: %s login, q %u, conn 0x%p,0x%p,%u.\n",
				((iscsi_node *) sess->s_node)->n_name,
				sess->s_peer_name, conn->c_isock->s_cpuno,
				conn, sess, sess->s_queue[SESS_CONNQ]->q_cnt);
#endif
			/*
	 		 * payload is aligned to 512, if only header or data
			 * digest is enabled, adjust payload size, so the max
			 * tx pdu size is 8-byte aligned.
			 */
			if ((iscsi_perf_params & ISCSI_PERF_ALIGN8) &&
			    (conn->c_hdigest_len + conn->c_ddigest_len) & 7) {
				conn->c_pdudatalen_tmax -= 4; 
				os_log_info("conn 0x%p, crc %u,%u, tx -> %u.\n",
						conn, conn->c_hdigest_len,
						conn->c_ddigest_len,
						conn->c_pdudatalen_tmax);
			}
		}

		if (iscsi_conn_flag_test(conn, CONN_FLAG_LEADING_CONN_BIT)) {
			iscsi_node *node = sess->s_node;
			chiscsi_target_class *tclass = node->tclass;

			if (sess->s_type == ISCSI_SESSION_TYPE_NORMAL)
        			os_chiscsi_notify_event(CHISCSI_LOGIN_SUCCESS,
			        	"Initiator=%s, Target=%s",
					sess->s_peer_name,
					sess->s_node->n_name);

			if (sess->s_type == ISCSI_SESSION_TYPE_NORMAL &&
			    tclass->fp_session_added &&
			    !(sess->s_flag & SESS_FLAG_API_SESS_ADDED)) {
				sess->s_flag |= SESS_FLAG_API_SESS_ADDED;
				sess->s_tclass_sess_priv = tclass->fp_session_added(
						(unsigned long)sess,
						sess->s_isid,
						sess->s_peer_name,
						node->n_name);
			}

			iscsi_sess_flag_set(sess, SESS_FLAG_FFP_BIT);
		}

		/* save the connection count for this session */
		sess->s_conn_cnt = sess->s_queue[SESS_CONNQ]->q_cnt;

		/* distribute sess/conn to a worker thread */
		rv = iscsi_distribute_connection(conn);
		if (rv < 0) {
			os_log_info("%s conn 0x%p distribute, rv %d.\n",
				__func__, conn, rv);
			goto out;
		}

		return 0;
	}
out:
	sess = conn->c_sess;
	if (rv < 0) {
		iscsi_conn_flag_set(conn, CONN_FLAG_CLOSE_BIT);
		iscsi_conn_flag_set(conn, CONN_FLAG_RST_BIT);
	}

	if (iscsi_conn_flag_test(conn, CONN_FLAG_CLOSE_BIT))
		iscsi_target_connection_close(conn);

	if (iscsi_conn_flag_test(conn, CONN_FLAG_CLOSED_BIT)) {
		iscsi_connection_destroy(conn);

		/* close session, when there is no more connections */
		if (iscsi_session_empty(sess)) {
			iscsi_sess_flag_set(sess, SESS_FLAG_CLOSE_BIT);
			rv = iscsi_target_session_close(sess);
		}
	}

	return rv;
}

int it_main_process_connection(void *arg)
{
	iscsi_connection *conn = (iscsi_connection *) arg;

	/* listening socket */
	if (conn->c_state == CONN_STATE_LISTEN) {
		return it_main_accept_connection(conn);
	}
	/* normal iscsi connection */
	return (it_main_login_connection(conn));
}

/* 
 * target main thread processing -- update accepted connection's timeout value 
 */
int it_main_connection_timeout_update(void *arg)
{
	iscsi_connection *conn = (iscsi_connection *) arg;
	if (conn->c_state != CONN_STATE_LISTEN) {
		iscsi_session *sess = conn->c_sess;
		if (sess) {
			unsigned int tag;
			int     rv = -ISCSI_EINVAL;

			rv = iscsi_target_portal_find(sess->s_node,
						       conn->c_portal, &tag,
						       &conn->c_timeout);
			if (rv < 0) {
				/* portal is gone */
				os_log_info
					("%s, conn 0x%p, portal removed, closing.\n",
					 sess ? sess->s_peer_name : " ", conn);
				iscsi_conn_flag_set(conn, CONN_FLAG_CLOSE_BIT);
				iscsi_conn_flag_set(conn, CONN_FLAG_RST_BIT);
				iscsi_target_connection_close(conn);
			}
		} 
#if 0
		else /* take from the portal */
			conn->c_timeout = conn->c_portal->p_timeout;
#endif
	}
	return 0;
}

/* 
 * target main thread processing -- connection timeout check 
 */
int it_main_connection_timeout_check(void *arg)
{
	iscsi_connection *conn = (iscsi_connection *) arg;

	if (iscsi_conn_flag_test(conn, CONN_FLAG_CLOSE_BIT))
		goto close;

	/* accepted, but still in login phase */
	if (conn->c_state >= CONN_STATE_CONNECTED &&
	    conn->c_state < CONN_STATE_FFP) {
		conn->c_idle++;
		if (conn->c_idle >= iscsi_login_complete_time) {
			os_log_info(
			"conn 0x%p, s 0x%x, in login for %u sec. close.\n",
				conn, conn->c_state, conn->c_idle);
			iscsi_conn_flag_set(conn, CONN_FLAG_CLOSE_BIT);
			iscsi_conn_flag_set(conn, CONN_FLAG_RST_BIT);
			goto close;
		}
	}
		

	if (conn->c_state == CONN_STATE_FFP &&
	    !iscsi_conn_flag_test(conn, CONN_FLAG_CLOSE_BIT)) {
		if (it_connection_timeout_check(conn, 0)) {
			/* check rx one last time */
			if (iscsi_conn_flag_test(conn, CONN_FLAG_RX_READY_BIT)) {
				conn_timeout_clear(conn);
			} else {
				os_log_info
					("%s, conn 0x%p, timed %u >= %u, closing.\n",
					 conn->c_sess ? conn->c_sess->
					 s_peer_name : " ", conn, conn->c_idle,
					 conn->c_timeout);
				iscsi_conn_flag_set(conn, CONN_FLAG_CLOSE_BIT);
				iscsi_conn_flag_set(conn, CONN_FLAG_RST_BIT);
			}
		}
	}

close:
	if (iscsi_conn_flag_test(conn, CONN_FLAG_CLOSE_BIT))
		iscsi_target_connection_close(conn);
	return 0;
}

/* 
 *
 * target worker thread processing -- iscsi activities 
 *
 */

/* 
 * target worker thread processing -- iscsi activities 
 */
static int it_session_node_check(iscsi_session *sess)
{
	iscsi_connection *conn = NULL;
	chiscsi_queue *connq = sess->s_queue[SESS_CONNQ];
	iscsi_node *node = sess->s_node;
	int close_cnt = 0;
	int i;

	if (iscsi_sess_flag_testnclear(sess, SESS_FLAG_NODE_ACL_CHNG_BIT)) {
		sess->acl = NULL;
		if (iscsi_acl_session_check(sess) < 0) {
			os_log_info("sess 0x%p, target %s acl changed.\n",
				sess, node->n_name);
			iscsi_sess_flag_set(sess, SESS_FLAG_CLOSE_BIT);
			close_cnt = connq->q_cnt;
			goto done;
		}
	}

	if (iscsi_sess_flag_testnclear(sess, SESS_FLAG_NODE_PORTAL_CHNG_BIT)) {
		for (conn = connq->q_head; conn; conn = conn->c_next) {
			for (i = 0; i < node->portal_cnt; i++)
 				if (node->portal_list[i].portal == conn->c_portal)
					break;
			/* no match find */
			if (i == node->portal_cnt) {
				os_log_info("conn 0x%p, portal removed.\n", conn);
				iscsi_conn_flag_set(conn, CONN_FLAG_CLOSE_BIT);
				close_cnt++;
			}
		}
	}

	/* lun added/removed/moved:
	 * terminate the session to force a session recovery
	 */
	if (iscsi_sess_flag_testnclear(sess, SESS_FLAG_NODE_LUN_CHNG_BIT)) {
		os_log_info("sess 0x%p, target %s lun order changed.\n",
				sess, node->n_name);
		iscsi_sess_flag_set(sess, SESS_FLAG_CLOSE_BIT);
		close_cnt = connq->q_cnt;
		goto done;
        }

	/*
	 * lun change triggers SESS_FLAG_DEVICE_RESCAN_BIT, which is handled
 	 * at scsi command execution time
 	 */
/*
	if (iscsi_sess_flag_test(sess, SESS_FLAG_NODE_LU_CHNG_BIT)) {
	}
*/

done:
	return close_cnt;
}

static void it_session_check_tmf_done(iscsi_session *sess)
{
	chiscsi_queue *q = sess->s_queue[SESS_TMFQ];
	iscsi_tmf *ptmf = q->q_head;

	if (!ptmf)
		return;

	while (ptmf) {
		iscsi_tmf *next = ptmf->p_next;

		os_lock_irq(ptmf->p_lock);
		if (!(ptmf->p_flag & ISCSI_PDU_FLAG_TMF_POSTPONED)) {
			os_unlock_irq(ptmf->p_lock);
			iscsi_tmf_ch_qremove(nolock, q, ptmf);
			if (!iscsi_sess_flag_test(sess, SESS_FLAG_CLOSE_BIT))
				it_send_tmf_response(ptmf->p_conn,
						ptmf->p_itt, ptmf->p_resp);
			iscsi_tmf_free(ptmf);
               } else
                       os_unlock_irq(ptmf->p_lock);
		ptmf = next;
	}
}

int it_worker_process_session(void *arg)
{
	iscsi_session *sess = arg;
	iscsi_node *node;
	chiscsi_queue *connq = NULL;
	iscsi_connection *conn=NULL, *cnext=NULL;
	chiscsi_queue *q;
	chiscsi_scsi_command *sc, *scnext;
	unsigned int expcmdsn;
	int     rv = 0;

	if (!sess)
		return 0;

	connq = sess->s_queue[SESS_CONNQ];
	node = sess->s_node;

	if (iscsi_sess_flag_test(sess, SESS_FLAG_CLOSE_BIT)) {
		os_log_debug(ISCSI_DBG_SESS,
			"sess 0x%p, needs to be closed.\n", sess);
		goto done;
	}

	/* wait until the target refreshing is done */
	if (iscsi_node_flag_test(node, NODE_FLAG_UPDATING_BIT)) {
		os_log_debug(ISCSI_DBG_SESS,
			"sess 0x%p, %s, target %s being updated.\n",
			sess, sess->s_peer_name, node->n_name);
		iscsi_schedule_session(sess);
		return 0;
	}

	if (iscsi_node_flag_test(node, NODE_FLAG_OFFLINE_BIT)) {
		 os_log_debug(ISCSI_DBG_SESS,
			"sess 0x%p, target node offline.\n", sess);
		iscsi_sess_flag_set(sess, SESS_FLAG_CLOSE_BIT);
		goto done;
	}

	/* target lun or portal changed? */
	rv = it_session_node_check(sess);
	if (rv > 0) {
		os_log_debug(ISCSI_DBG_SESS,
			"sess 0x%p, node check failed %d.\n", sess, rv);
		goto done;
	}

	if (iscsi_sess_flag_test(sess, SESS_FLAG_TARGET_RESET_BIT)) {
		iscsi_sess_flag_clear(sess, SESS_FLAG_TARGET_RESET_BIT);
		os_log_info("sess 0x%p, %s DEVICE RESET.\n",
			sess, sess->s_peer_name);
		/* device reset override lun reset */
		target_session_tmf_reset(sess);
	}

	it_session_check_tmf_done(sess);
	
	/* process cmd by cmdsn.
 	 * in MCS case, keep looping through connections as long as we are
 	 * making progress (i.e., new cmdsn are valid and ready to be executed)
 	 */
	do {
		expcmdsn = sess->s_expcmdsn;

		/* push tx, read rx */
		for (conn = connq->q_head; conn; conn = conn->c_next) {
			if (!(conn_ready_for_session_process(conn)))
				continue;

			rv = iscsi_connection_push_pdus(conn);
			if (rv < 0) {
				os_log_info("twrk, conn 0x%p, push pdu %d.\n",
						conn, rv);
				iscsi_conn_flag_set(conn, CONN_FLAG_CLOSE_BIT);
				continue;
			}

			if (iscsi_conn_flag_testnclear(conn,
						CONN_FLAG_RX_READY_BIT)) {
				rv = conn_rx(conn);
				if (rv < 0) {
					os_log_info("twrk, conn 0x%p, read pdu %d.\n",
							conn, rv);
					iscsi_conn_flag_set(conn,
							CONN_FLAG_CLOSE_BIT);
					continue;
				}
				iscsi_conn_flag_set(conn, CONN_FLAG_BUSY_BIT);

				rv = iscsi_connection_push_pdus(conn);
				if (rv < 0) {
					os_log_info("twrk, conn 0x%p, push pdu %d.\n",
						conn, rv);
					iscsi_conn_flag_set(conn,
							CONN_FLAG_CLOSE_BIT);
				}
			}
		}
	} while (!iscsi_sess_flag_test(sess, SESS_FLAG_CLOSE_BIT) &&
		 connq->q_cnt > 1 && expcmdsn != sess->s_expcmdsn);

	q = sess->s_queue[SESS_SCMDQ_NEW];
	for (sc = q->q_head; sc; sc = scnext) {
		scnext = sc->sc_next;
		conn = sc->sc_conn;
#if 0
		/* failed PDU - send check condition and send abort to backend*/
		if (failed_pdu && (failed_pdu->p_scmd == sc) && 
			!(sc->sc_flag & SC_FLAG_CMD_ABORT)) {
		        chiscsi_target_lun_class *lclass = sc->lu_class;
			chiscsi_sgl *ssgl = &sc->sc_sgl;
			os_log_debug(ISCSI_DBG_SCSI_COMMAND,
				"DDP failed: chiscsi_sgl 0x%p, %u+%u, nr %u, vec 0x%p,0x%p.\n",
				ssgl, ssgl->sgl_boff, ssgl->sgl_length, ssgl->sgl_vecs_nr,
				ssgl->sgl_vecs, ssgl->sgl_vec_last);
			scmd_fpriv_set_bit(sc, CH_SFP_XFER_ERR_BIT);
			sc_rw_error(sc);
			scmd_set_timestamp(sc, CH_SCMD_TM_STATE_2_STATUS);
			sc->sc_state = CH_SC_STATE_STATUS;
			sc->sc_flag |= SC_FLAG_CMD_ABORT;
			scmd_set_timestamp(sc, CH_SCMD_TM_FP_ABORT);
			lclass->fp_scsi_cmd_abort(sc);
		}
#endif
		iscsi_conn_flag_set(conn, CONN_FLAG_TX_PUSH_BIT);
		if (sc->sc_flag & SC_FLAG_READ) {
			it_scmd_read_continue(sc);
		} else
			it_scmd_write_continue(sc);
	}

done:
	it_session_check_tmf_done(sess);

	if (iscsi_sess_flag_test(sess, SESS_FLAG_CLOSE_BIT)) {
		/* session is closing, clean up pending commands */
		if (iscsi_msg_debug_level_on(ISCSI_DBG_SESS))
			iscsi_session_display(sess, 1);
		it_session_check_scmd_acked(sess, 1);
	}

	for (conn = connq->q_head; conn; conn = cnext) {
		cnext = conn->c_next;

		if (!iscsi_conn_flag_test(conn, CONN_FLAG_FFP_READY_BIT))
			continue;

		if (iscsi_sess_flag_test(sess, SESS_FLAG_CLOSE_BIT)) {
			iscsi_conn_flag_set(conn, CONN_FLAG_CLOSE_BIT);
		} else if (!iscsi_conn_flag_test(conn, CONN_FLAG_CLOSE_BIT)) {
			rv = iscsi_connection_push_pdus(conn);
			if (rv < 0) {
				os_log_info("%s conn 0x%p, push pdu failed %d.\n",
					 __func__, conn, rv);
				iscsi_conn_flag_set(conn, CONN_FLAG_CLOSE_BIT);
			}
		}

		if (iscsi_conn_flag_test(conn, CONN_FLAG_CLOSE_BIT)) {
			iscsi_target_connection_close(conn);
		}
		if (iscsi_conn_flag_test(conn, CONN_FLAG_CLOSED_BIT)) {
			iscsi_connection_destroy(conn);
		}
	}

	if (iscsi_session_empty(sess)) {
		node = sess->s_node;

		os_log_debug(ISCSI_DBG_SESS,
			"sess 0x%p empty, closing, t %s, sess left %u.\n",
			sess, node->n_name, node->n_queue[NODE_SESSQ]->q_cnt);

		if (iscsi_msg_debug_level_on(ISCSI_DBG_SESS) &&
		    !iscsi_sess_flag_test(sess, SESS_FLAG_CLOSE_BIT))
			iscsi_session_display(sess, 1);
				
		iscsi_sess_flag_set(sess, SESS_FLAG_CLOSE_BIT);
		rv = iscsi_target_session_close(sess);
	}

	return rv;
}

/* 
 * target worker thread processing -- update connection's timeout value 
 */
int it_worker_session_timeout_update(void *arg)
{
	iscsi_session *sess = arg;
	chiscsi_queue *connq;
	iscsi_connection *conn, *cnext;

	if (!sess || iscsi_sess_flag_test(sess, SESS_FLAG_CLOSE_BIT))
		return 0;

	connq = sess->s_queue[SESS_CONNQ];
	for (conn = connq->q_head; conn; conn = cnext) {
		cnext = conn->c_next;
		if (conn_ready_for_session_process(conn)) {
			iscsi_session *sess = conn->c_sess;
			unsigned int tag;
			int     rv;
			rv = iscsi_target_portal_find(sess->s_node,
						       conn->c_portal, &tag,
						       &conn->c_timeout);
			if (rv < 0) {
				os_log_info
					("%s, conn 0x%p, portal removed, closing.\n",
					 sess ? sess->s_peer_name : " ", conn);
				/* portal is gone */
				iscsi_conn_flag_set(conn, CONN_FLAG_CLOSE_BIT);
				iscsi_conn_flag_set(conn, CONN_FLAG_RST_BIT);
				iscsi_target_connection_close(conn);
			}
		}
	}

	if (iscsi_session_empty(sess)) {
		iscsi_sess_flag_set(sess, SESS_FLAG_CLOSE_BIT);
		iscsi_target_session_close(sess);
	}

	return 0;
}

/* 
 * target worker thread processing -- connection timeout check 
 */
int it_worker_session_timeout_check(void *arg)
{
	iscsi_session *sess = arg;
	chiscsi_queue *connq = sess->s_queue[SESS_CONNQ];
	chiscsi_queue *scq = sess->s_queue[SESS_SCMDQ_NEW];
	iscsi_connection *conn, *cnext;

	if (!sess || iscsi_sess_flag_test(sess, SESS_FLAG_CLOSE_BIT))
		return 0;

	for (conn = connq->q_head; conn; conn = cnext) {
		cnext = conn->c_next;
		if (!(conn_ready_for_session_process(conn)))
			continue;

		if (it_connection_timeout_check(conn, scq->q_cnt)) {
			/* check rx one last time */
			if (iscsi_conn_flag_test(conn, CONN_FLAG_RX_READY_BIT)) {
				conn_timeout_clear(conn);
			} else {
				os_log_info("conn 0x%p timeout %u >= %u.\n",
					    conn, conn->c_idle,
					    conn->c_timeout);
				iscsi_conn_flag_set(conn, CONN_FLAG_CLOSE_BIT);
				iscsi_conn_flag_set(conn, CONN_FLAG_RST_BIT);
			}
		}
		if (iscsi_conn_flag_test(conn, CONN_FLAG_CLOSE_BIT))
			iscsi_target_connection_close(conn);
	}

	if (iscsi_session_empty(sess)) {
		iscsi_sess_flag_set(sess, SESS_FLAG_CLOSE_BIT);
		iscsi_target_session_close(sess);
	}

	return 0;
}
