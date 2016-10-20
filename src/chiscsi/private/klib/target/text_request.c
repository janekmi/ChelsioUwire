/*
 * text_request.c -- text request/response
 */

#include <iscsi_target_api.h>
#include "iscsi_target_private.h"

static void set_text_response_bhs(iscsi_pdu *pdu, unsigned int dlen)
{
	iscsi_connection *conn = (iscsi_connection *)pdu->p_conn;
	iscsi_session *sess = conn->c_sess;

	pdu->p_opcode = ISCSI_OPCODE_TEXT_RESPONSE;
	
	SET_PDU_OPCODE(pdu, ISCSI_OPCODE_TEXT_RESPONSE);
	SET_PDU_ITT(pdu, conn->c_text_itt);
	SET_PDU_TTT(pdu, conn->c_text_tag);
	uint_serial_inc(conn->c_statsn);
	SET_PDU_STATSN(pdu, conn->c_statsn);
	pdu->p_sn = conn->c_statsn;

	SET_PDU_EXPCMDSN(pdu, sess->s_expcmdsn);
	SET_PDU_MAXCMDSN(pdu, sess->s_maxcmdsn);
	SET_PDU_DATA_SEGMENT_LENGTH(pdu, dlen);
}

static int send_text_response(iscsi_connection *conn, int ibit, int fbit)
{
	iscsi_session *sess = conn->c_sess;
	iscsi_pdu *pdu = NULL;
	int rv;

	if (!ibit)
		uint_serial_inc(sess->s_maxcmdsn);

	if (conn->c_datap_cnt <= conn->c_datap_max) {
		unsigned int dlen = conn->c_datap_max - conn->c_datap_cnt;
		int cbit = 0;

		if (dlen > conn->c_pdudatalen_tmax)
			dlen = conn->c_pdudatalen_tmax;

		pdu = iscsi_pdu_get(conn, 0, 0, dlen);
		if (!pdu)
			return -ISCSI_ENOMEM;

		if (dlen) {
			/* copy data into the pdu payload */
			rv = chiscsi_sglist_copy_bufdata(
					conn->c_datap + conn->c_datap_cnt,
					dlen,
					pdu->p_sglist,
					pdu->p_sgcnt_used);
			if (rv < 0)
				goto free_pdu;
			conn->c_datap_cnt += dlen;

			if (conn->c_datap_cnt < conn->c_datap_max) {
				cbit = 1;
				fbit = 0;
			} else {
				cbit = 0;
				fbit = 1;
			}
		}

		if ((cbit || !fbit) && conn->c_text_tag == ISCSI_INVALID_TAG) {
			conn->c_text_tag = iscsi_session_next_non_cmd_tag(sess);
			if (conn->c_text_tag == ISCSI_INVALID_TAG) {
				rv = -ISCSI_EFULL;
				goto free_pdu;
			}
		} else if (fbit)
			conn->c_text_tag = ISCSI_INVALID_TAG;

		set_text_response_bhs(pdu, dlen);

		if (ibit)
			SET_PDU_I(pdu);

		if (cbit)
			SET_PDU_C(pdu);
		else {
			os_free(conn->c_datap);
	        	conn->c_datap = NULL;
        	        conn->c_datap_max = conn->c_datap_cnt = 0;
			conn->c_text_tag = ISCSI_INVALID_TAG;

			if (fbit)
				SET_PDU_F(pdu);
			else
				CLR_PDU_F(pdu);
		}

		rv = iscsi_connection_send_pdu(conn, pdu);
		if (rv < 0)
			goto free_pdu;
	} 

	if  ((conn->c_datap_cnt == conn->c_datap_max) && conn->c_datap) {
		os_free(conn->c_datap);
		conn->c_datap = NULL;
		conn->c_datap_cnt = conn->c_datap_max = 0;
	}

	return 0;	

free_pdu:
	iscsi_pdu_done(pdu);
	return rv;
}

static int send_empty_text_response(iscsi_connection *conn, int ibit, int fbit)
{
	iscsi_session *sess = conn->c_sess;
	iscsi_pdu *pdu = iscsi_pdu_get(conn, 0, 0, 0);
	int rv;

	if (!pdu)
		return -ISCSI_ENOMEM; 

	if (fbit && !ibit)
		uint_serial_inc(sess->s_maxcmdsn);

	/* get ttt before set text response */
	if (fbit) {
		SET_PDU_F(pdu);
	} else {
		CLR_PDU_F(pdu);
		if (conn->c_text_tag == ISCSI_INVALID_TAG) {
		        conn->c_text_tag = iscsi_session_next_non_cmd_tag(sess);
		}
	}
	
	set_text_response_bhs(pdu, 0);

	if (ibit)
		SET_PDU_I(pdu);

	rv = iscsi_connection_send_pdu(conn, pdu);
	if (rv < 0) {
		iscsi_pdu_done(pdu);
		return rv;
	}

	return 0;
}

static int size_node_info_text(iscsi_node *node)
{
	int rv, len;
	iscsi_keyval *kvp;

	kvp = node->n_keys[NODE_KEYS_CONNECTION] + ISCSI_KEY_CONN_TARGET_NAME;
	rv = iscsi_kvp_size_text(kvp);
	if (rv < 0) return rv;
	len = rv;

	kvp = node->n_keys[NODE_KEYS_CONNECTION] + ISCSI_KEY_CONN_TARGET_ADDRESS;
	rv = iscsi_kvp_size_text(kvp);
	if (rv < 0) return rv;
	len += rv;
	return len;	
}

static int write_node_info_text(iscsi_node *node, iscsi_connection *conn)
{
	char *buf = conn->c_datap + conn->c_datap_cnt;
	int buflen = conn->c_datap_max - conn->c_datap_cnt;
	iscsi_keyval *kvp;
	int rv;

	/*target name*/
	kvp = node->n_keys[NODE_KEYS_CONNECTION] + ISCSI_KEY_CONN_TARGET_NAME;
	rv = iscsi_kvp_write_text(buflen, buf, kvp, 
				  ISCSI_KV_WRITE_NO_SEPERATOR, 0, 0);
	if (rv < 0) 
		return rv;
	buf += rv;
	buflen -= rv;
	conn->c_datap_cnt += rv;

	/*target address*/
	kvp = node->n_keys[NODE_KEYS_CONNECTION] + ISCSI_KEY_CONN_TARGET_ADDRESS;
	rv = iscsi_kvp_write_text(buflen, buf, kvp, 
				  ISCSI_KV_WRITE_NO_SEPERATOR, 0, 0);
	if (rv < 0) 
		return rv;
	conn->c_datap_cnt += rv;

	return rv;
}

static int proc_send_targets_all(iscsi_connection *conn, int ibit, int fbit)
{
	iscsi_session *sess = conn->c_sess;
	chiscsi_queue *nodeq = iscsi_nodeq;
	iscsi_node *node = NULL;
	iscsi_keyval *kvp = conn->c_keys + ISCSI_KEY_CONN_SEND_TARGETS;
	char *buf;
	int len = 0;
	int rv = 0;
	int alltarget = 0;

	if (sess->s_type == ISCSI_SESSION_TYPE_NORMAL) {
		/* SendTargets = ALL not allowed in normal session */
		kvp->kv_flags |= ISCSI_KV_FLAG_SEND |
				 ISCSI_KV_FLAG_DROP_AFTER_SEND |
				 ISCSI_KV_FLAG_REJECT;
		rv = iscsi_kvp_size_text(kvp);
		if (rv < 0)
			return rv;
		len += rv;
	} else { 

		/* all available targets */
		alltarget = 1;
		os_lock(nodeq->q_lock);
		for (node = iscsi_nodeq->q_head; node; node = node->n_next) {
			rv = size_node_info_text(node);
			if (rv < 0)
				break;
			len += rv;
		} 
		os_unlock(nodeq->q_lock);
	}

	conn->c_datap = os_alloc(len, 1, 1);
	if (!conn->c_datap)
		return -ISCSI_ENOMEM;
	conn->c_datap_max = len;
	conn->c_datap_cnt = 0;
	
	/* construct the response buffer */
	if (alltarget) {
		buf = conn->c_datap;
		*buf = 0;
		os_lock(nodeq->q_lock);
		 for (node = nodeq->q_head; node; node = node->n_next) {
			if (iscsi_node_flag_test(node, NODE_FLAG_OFFLINE_BIT)) {
				continue;
			}
			if (node->tclass->fp_discovery_target_accessible) {
				rv = node->tclass->fp_discovery_target_accessible(0UL, 
						sess->s_peer_name, node->n_name,
						&conn->c_isock->s_tcp);
				if (!rv)
					continue;
			}
			if (iscsi_node_acl_enable(node)) {
				rv = iscsi_acl_target_accessible(node,
					sess->s_peer_name,
					&conn->c_isock->s_tcp);
				if (!rv) 
					continue;
			}
			rv = write_node_info_text(node, conn);
			if (rv < 0)
				break;
		}
		os_unlock(nodeq->q_lock);
		if (rv < 0)
			return rv;
	} else { 
		buf = conn->c_datap + conn->c_datap_cnt;
		*buf = 0;
		rv = iscsi_connection_keys_send(conn->c_keys, buf, len);
		if (rv < 0)
			return rv;

		len -= rv;
		conn->c_datap_cnt += rv;
	}

	conn->c_datap_max = conn->c_datap_cnt;
	conn->c_datap_cnt = 0;

	return (send_text_response(conn, ibit, fbit));
}

static int single_node_discovery(iscsi_connection *conn, iscsi_node *node)
{
	int rv, len;

	rv = size_node_info_text(node);
	if (rv < 0)
		return rv;
	len = rv;

	conn->c_datap = os_alloc(len, 1, 1);
	if (!conn->c_datap)
		return -ISCSI_ENOMEM;
	conn->c_datap_max = len;
	conn->c_datap_cnt = 0;
	
	*conn->c_datap = 0;
	rv = write_node_info_text(node, conn);
	if (rv < 0)
		return rv;

	conn->c_datap_max = rv;
	conn->c_datap_cnt = 0;
	return 0;
}

static int proc_send_targets_specified(iscsi_connection *conn, int ibit, int fbit)
{
	iscsi_session *sess = conn->c_sess;
	iscsi_node *node = sess->s_node;
	iscsi_keyval *kvp = conn->c_keys + ISCSI_KEY_CONN_SEND_TARGETS;
	int rv;

	if (sess->s_type == ISCSI_SESSION_TYPE_NORMAL) {
		if (os_strcmp(node->n_name, kvp->kv_valp->v_str[0])) {
			node = NULL;
		}
	} else {
		 node = (iscsi_node *)iscsi_node_find_by_name(
						kvp->kv_valp->v_str[0]);
		if (node && iscsi_node_acl_enable(node)) { 
			rv = iscsi_acl_target_accessible(node,
					sess->s_peer_name,
					&conn->c_isock->s_tcp);
			if (!rv) 
				node = NULL;
		}
	}

	if (node) {
		rv = single_node_discovery(conn, node);
		if (rv < 0) return rv;
		return (send_text_response(conn, ibit, fbit));
	}

	return 0;
}

static int proc_send_targets_session(iscsi_connection *conn, int ibit, int fbit)
{
	iscsi_session *sess = conn->c_sess;
	iscsi_node *node = sess->s_node;
	int rv;

	if (sess->s_type != ISCSI_SESSION_TYPE_NORMAL) 
		return (send_empty_text_response(conn, ibit, fbit));
	else {
	
		if (node) {
			rv = single_node_discovery(conn, node);
			if (rv < 0) return rv;
			return (send_text_response(conn, ibit, fbit));
		}
	}

	return 0;
}

static int proc_text_negotiation(iscsi_connection *conn, int ibit, int fbit)
{
	iscsi_session *sess = conn->c_sess;
	chiscsi_queue *pairq = conn->c_queue[CONN_PAIRQ];
	iscsi_keyval *kvp;
	int i, len = 0, rv;

	/* Discovery, only SendTargets is allowed */
	if (sess->s_type == ISCSI_SESSION_TYPE_DISCOVERY) {
                for (i = 0, kvp = conn->c_keys; i < ISCSI_KEY_CONN_COUNT;
                     i++, kvp++) {
                        if (kvp->kv_valp)
                                kvp->kv_flags |= ISCSI_KV_FLAG_IRRELEVANT |
                                        ISCSI_KV_FLAG_DROP_AFTER_SEND |
                                        ISCSI_KV_FLAG_SEND;
                }
	} 
	
	/*fixed: synced with iscsi-devel*/	
	for (i = 0, kvp = conn->c_keys; i < ISCSI_KEY_CONN_COUNT;
	     i++, kvp++) {
		if (kvp->kv_valp && 
		    !(kvp->kv_flags & ISCSI_KV_FLAG_SENT) && 
		    (kvp->kv_def->property & ISCSI_KEY_SENDER_TARGET) &&
		    ((kvp->kv_flags & ISCSI_KV_FLAG_RESPONSE) ||
		     (!(kvp->kv_def->property & ISCSI_KEY_DECLARATIVE) &&
		      (kvp->kv_flags & ISCSI_KV_FLAG_COMPUTED))))
			kvp->kv_flags |= ISCSI_KV_FLAG_SEND;
	}

	if (pairq->q_head) {
		rv = iscsi_string_pairq_size_response(pairq,
					ISCSI_KV_FLAG_NOTUNDERSTOOD);
		if (rv < 0)
			return rv;
		len += rv;
	}

	rv = iscsi_kvlist_size_text(ISCSI_KEY_CONN_COUNT, conn->c_keys);
	if (rv < 0)
		return rv;
	len += rv;

	if (!len) 
		return (send_empty_text_response(conn, ibit, fbit));

	conn->c_datap = os_alloc(len, 1, 1);
	if (!conn->c_datap)
		return -ISCSI_ENOMEM;
	conn->c_datap_max = len;
	conn->c_datap_cnt = 0;

	if (pairq->q_head) {
		*conn->c_datap = 0;
		rv = iscsi_string_pairq_write_text(pairq, conn->c_datap,
						ISCSI_KV_FLAG_NOTUNDERSTOOD);
		if (rv < 0)
			return rv;
		len -= rv;
		conn->c_datap_cnt += rv;
	}

	*(conn->c_datap + conn->c_datap_cnt) = 0;
	rv = iscsi_connection_keys_send(conn->c_keys,
					conn->c_datap + conn->c_datap_cnt,
					len);
	if (rv < 0)
		return rv;
	//len -= rv;    
        conn->c_datap_cnt += rv;

	conn->c_datap_max = conn->c_datap_cnt;
	conn->c_datap_cnt = 0;

	/* send response */
	return (send_text_response(conn, ibit, fbit));
}

int target_rcv_text_request(iscsi_pdu *pdu)
{
	int     rv = 0, i;
	int     sendtarget = 0;
	int     otherkeys = 0;
	unsigned char reject_code = 0;
	unsigned int itt, ttt, dlen;
	char *buf = NULL;
	unsigned int buflen = 0;
	iscsi_connection *conn = (iscsi_connection *)pdu->p_conn;
	iscsi_keyval *kvp, *kv_conn = NULL;
	chiscsi_queue *q = conn->c_queue[CONN_PDUQ_TMP];
	chiscsi_queue *pairq = conn->c_queue[CONN_PAIRQ];
//	iscsi_session *sess = conn->c_sess;
	int ibit = GET_PDU_I(pdu) ? 1 : 0;
	int fbit = GET_PDU_F(pdu) ? 1 : 0;


	itt = GET_PDU_ITT(pdu);
	ttt = GET_PDU_TTT(pdu);
	dlen = GET_PDU_DATA_SEGMENT_LENGTH(pdu);

	/* C and F cannot be both set */
	if (GET_PDU_C(pdu) && GET_PDU_F(pdu)) {
		os_log_info("TEXT_REQ, both C, F bits set.\n", ibit);
		rv = iscsi_target_xmt_reject(pdu, 
				ISCSI_REJECT_REASON_PROTOCOL_ERROR);
		return rv;
	}

	/* if ttt valid, send next response */
	if (ttt != ISCSI_INVALID_TAG) {
		if (ttt != conn->c_text_tag) {
			os_log_info
				("TEXT_REQ: ttt mismatch, exp. 0x%x got 0x%x, reject.\n",
				 conn->c_text_tag, ttt);
			rv = iscsi_target_xmt_reject(pdu,
				   ISCSI_REJECT_REASON_INVALID_PDU_FIELD);
			return rv;
		}
		conn->c_text_itt = itt;
		if (dlen) {
			os_log_info
				("TEXT_REQ: ttt 0x%x, dlen %u, exp 0, reject.\n",
				 ttt, dlen);
			rv = iscsi_target_xmt_reject(pdu,
				   ISCSI_REJECT_REASON_INVALID_PDU_FIELD);
			return rv;
		}
		rv = send_text_response(conn, ibit, fbit);
		if (rv < 0)
			return rv;
		goto finish;
	} else {
		conn->c_text_itt = itt;
		/* must be new request */
		if (conn->c_text_tag != ISCSI_INVALID_TAG) {
			/* release old ttt but dont assign new yet */
			conn->c_text_tag = ISCSI_INVALID_TAG;

			/* release all the text pdus accumulated so far */
			iscsi_pduq_free_all(q, NULL);

			if (conn->c_keys) {
				iscsi_connection_key_free(conn->c_keys);
				conn->c_keys = NULL;
			}

			if (conn->c_datap) {
				os_free(conn->c_datap);
				conn->c_datap = NULL;
				conn->c_datap_cnt = conn->c_datap_max = 0;
			}

		}
	}

	/* if C send empty response to get rest of request */
	if (GET_PDU_C(pdu)) {
		os_log_info("text request C bit NOT supported.\n", 0);
                return -ISCSI_EIO;

		if (dlen) {
			iscsi_pdu_enqueue(nolock, q, pdu);
			pdu->p_flag |= ISCSI_PDU_FLAG_LOCKED;
		}
		return (send_empty_text_response(conn, ibit, fbit));
	}

	/* parse text */
	if (q->q_head) {
		iscsi_pdu *tmppdu;
		unsigned int offset = 0;
		if (dlen) {
			pdu->p_flag |= ISCSI_PDU_FLAG_LOCKED;
			iscsi_pdu_enqueue(nolock, q, pdu);
		}

		/* set up the p_offset */
		for (tmppdu = q->q_head; tmppdu;
		     offset += tmppdu->p_datalen, tmppdu = tmppdu->p_next) 
			tmppdu->p_offset = offset;

		rv = iscsi_pduq_data_to_one_buffer(q, &buf);
		/* pdu payload to buffer failed? */
		if (rv < 0)
			return rv;
		buflen = rv;

		/* release all text pdus accumulated so far */
		iscsi_pduq_free_all(q, pdu);

	} else if (dlen) {
		rv = iscsi_pdu_data_to_one_buffer(pdu, &buf);
		if (rv < 0)
			return rv;
		buflen = rv;
	}

	/*fix UNH ffp 17.6, let text keys take effect*/
	if (!buflen) {
		send_empty_text_response(conn, ibit, fbit);
		goto finish;
	}

	kv_conn = iscsi_connection_key_alloc();
	if (!kv_conn) {
		rv = -ISCSI_ENOMEM;
		goto cleanup;
	}

	rv = iscsi_kv_text_to_string_pairq(buflen, (char *) buf, pairq, NULL,
					   0);
	if (rv < 0)
		goto cleanup;

	rv = iscsi_connection_key_decode(ISCSI_TARGET, conn->c_state, kv_conn,
					 pairq, NULL, 0);
	if (rv < 0)
		goto cleanup;

	/* if there are still keys left, check if session keys */

	/* if there is any duplicate keys, reset the negotiations */
	for (i = 0, kvp = kv_conn; i < ISCSI_KEY_CONN_COUNT; i++, kvp++) {
		if (kvp->kv_rcvcnt && (kvp->kv_flags & ISCSI_KV_FLAG_DUPLICATE)) {
			reject_code = ISCSI_REJECT_REASON_PROTOCOL_ERROR;
			goto reject;
		}
	}

	/* if there is any declaratives we rejected, reset the negotiations */
	for (i = 0, kvp = kv_conn; i < ISCSI_KEY_CONN_COUNT; i++, kvp++) {
		if (kvp->kv_rcvcnt &&
		    (kvp->kv_flags & ISCSI_KV_FLAG_REJECT) &&
		    (kvp->kv_def->property & ISCSI_KEY_DECLARATIVE)) {
			reject_code = ISCSI_REJECT_REASON_NEGOTIATION_RESET;
			goto reject;
		}
	}

	/* save the negotiated keys */
	if (conn->c_keys) {
		rv = iscsi_kvlist_merge_value(0, ISCSI_KEY_CONN_COUNT, kv_conn,
					      conn->c_keys);
		if (rv < 0) {
			/* probably re-negotiations */
			reject_code = ISCSI_REJECT_REASON_PROTOCOL_ERROR;
			os_log_info("Re-negotiations Reject\n","");
			goto reject;
		}
	} else {
		conn->c_keys = kv_conn;
		kv_conn = NULL;
	}

	for (kvp = conn->c_keys, i = 0; i < ISCSI_KEY_CONN_COUNT; i++, kvp++) {
		if (kvp->kv_rcvcnt) {
			if (i == ISCSI_KEY_CONN_SEND_TARGETS)
				sendtarget = 1;
			else
				otherkeys++;
		}
	}

	/* sendTarget should be the one and only, else reject */
	if (sendtarget && otherkeys) {
		os_log_info("TEXT_REQ: sendTarget with other keys, reject.\n",
			    otherkeys);
		reject_code = ISCSI_REJECT_REASON_PROTOCOL_ERROR;
		goto reject;
	}

	if (sendtarget) {
		iscsi_value *vp;
		int len = 0;
		if (pairq->q_head) {
                	rv = iscsi_string_pairq_size_response(pairq,
                        	                ISCSI_KV_FLAG_NOTUNDERSTOOD);
	                if (rv < 0)	
        	                return rv;
                	len += rv;
        	}
		kvp = conn->c_keys + ISCSI_KEY_CONN_SEND_TARGETS;
		vp = kvp->kv_valp;
		if (vp && !(kvp->kv_flags & ISCSI_KV_FLAG_SENT)) {
			switch(vp->v_num[0]) {
			case ISCSI_SEND_TARGETS_ALL:
				rv = proc_send_targets_all(conn, ibit, fbit);
				break;
			case ISCSI_SEND_TARGETS_SPECIFIED:
				rv = proc_send_targets_specified(conn, ibit, fbit);
				break;
			case ISCSI_SEND_TARGETS_SESSION:
				rv = proc_send_targets_session(conn, ibit, fbit);
				break;
			}
			if (rv < 0)
				goto cleanup;
		}

	} else if (otherkeys) {
		rv = proc_text_negotiation(conn, ibit, fbit);
	}

	/* response sent */
finish:
	/* exchange is done, the keys re-negotiated should take effect */
	if (fbit && conn->c_keys) {
		kvp = conn->c_keys + 
		      ISCSI_KEY_CONN_MAX_RECV_DATA_SEGMENT_LENGTH;
		if (kvp->kv_valp && !(kvp->kv_flags & ISCSI_KV_FLAG_RESPONSE)) {
			os_log_info("TEXT_REQ: peer %s -> %u.\n",
				    kvp->kv_name, kvp->kv_valp->v_num[0]);
			conn->c_pdudatalen_tmax = kvp->kv_valp->v_num[0];
			iscsi_conn_adjust_pdudatalen_tmax(conn);
		}
		kv_conn = conn->c_keys;
		conn->c_keys = NULL;
	}

	goto cleanup;

reject:
	rv = iscsi_target_xmt_reject(pdu, reject_code);

cleanup:
	if (kv_conn) {
		iscsi_connection_key_free(kv_conn);
	}
	if (pairq) {
		iscsi_empty_string_pairq(pairq);
	}
	if (buf)
		os_free(buf);

	return rv;
}
