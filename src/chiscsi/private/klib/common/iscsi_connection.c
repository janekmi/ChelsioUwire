/*
 * iscsi_connection.c -- iscsi connection struct manipulation
 */

#include <common/os_builtin.h>
#include <common/iscsi_socket.h>
#include <iscsi_structs.h>
#include <iscsi_global.h>
#include <iscsi_connection_keys.h>
#include <iscsi_socket_api.h>
#include <iscsi_auth_api.h>
#include <iscsi_target_api.h>

int iscsi_connection_display(iscsi_connection * conn, char *buff, int buflen,
			     int summary)
{
	char	buffer[80];
	char	*buf = buff;
	int     baselen;
	int 	len;

	if (buff) {
 		baselen = len = os_strlen(buff);
		if (len >= buflen)
			goto done;
	}

	if (!buff) {
		buf = buffer;
		baselen = len = 0;
	}

	len += sprintf(buf + len, "CONN 0x%p: tm %u/%u,\n",
			conn, conn->c_idle,
			conn->c_timeout);
	if (!buff) {
		os_log_info("%s", buf);
		buf = buffer;
		len = 0;
	}

	len += sprintf(buf + len, "     cid 0x%x, offload %u, crc %u,%u,\n",
		       conn->c_cid, conn->c_offload_mode,
		       conn->c_hdigest_len, conn->c_ddigest_len);
	if (!buff) {
		os_log_info("%s", buf);
		buf = buffer;
		len = 0;
	}
	if (buff && len >= buflen)
		goto done;

	len += sprintf(buf + len,
		       "     state %u, flag 0x%lx, statsn %u,%u, dlen %u,%u.\n",
		       conn->c_state, conn->c_fbits,
		       conn->c_statsn, conn->c_expstatsn,
		       conn->c_pdudatalen_tmax, conn->c_pdudatalen_rmax);
	if (!buff) {
		os_log_info("%s", buf);
		buf = buffer;
		len = 0;
	}
	if (buff && len >= buflen)
		goto done;

	len += os_socket_display(conn->c_isock, buf + len, buflen - len);

done:
	return buff ? (len - baselen) : 0;
}

STATIC void iscsi_connection_init(iscsi_connection *conn)
{
	conn->c_state = CONN_STATE_CLOSED;
	conn->c_text_tag = ISCSI_INVALID_TAG;
	conn->c_pdudatalen_tmax =
		iscsi_connection_key_get_default
		(ISCSI_KEY_CONN_MAX_RECV_DATA_SEGMENT_LENGTH);
	conn->c_pdudatalen_rmax =
		iscsi_connection_key_get_default
		(ISCSI_KEY_CONN_MAX_RECV_DATA_SEGMENT_LENGTH);
	conn->c_pdu_rx.p_conn = conn;
}

iscsi_connection *iscsi_connection_create(void)
{
	iscsi_connection *conn = os_alloc(ISCSI_CONNECTION_SIZE, 1, 1);
	int i;

	if (!conn)
		return NULL;
	/* os_alloc does memset() */

	if (!(conn->os_data = os_data_init((void *)conn))) {
		os_free(conn);
		return NULL;
	}
	for (i = 0; i < CONN_Q_MAX; i++) {
		ch_queue_alloc(conn->c_queue[i]);
	}
	iscsi_stats_inc(ISCSI_STAT_CONN);

	iscsi_connection_init(conn);
	os_log_debug(ISCSI_DBG_CONN, "create conn. 0x%p\n", conn);
	return conn;

q_lock_fail:
	for (i = 0; i < CONN_Q_MAX; i++) {
		ch_queue_free(conn->c_queue[i]);
	}
	os_data_free(conn->os_data);
	os_free(conn);
	return NULL;
}

/* destroy an iscsi_connection structure */
STATIC int iscsi_connection_cleanup(iscsi_connection *conn)
{
	iscsi_session *sess = conn->c_sess;
	int     i;

	os_log_debug(ISCSI_DBG_CONN,
			"cleanup conn 0x%p, sess 0x%p\n", conn, sess);


	if (sess) {
		chiscsi_queue *connq = sess->s_queue[SESS_CONNQ];
		conn->c_sess = NULL;
		iscsi_conn_ch_qremove(lock, connq, conn);
	}

	if (conn->c_isock) {
		iscsi_socket_destroy(conn->c_isock);
		conn->c_isock = NULL;
	}

	if (conn->c_rxpdu) {
		iscsi_pdu_done(conn->c_rxpdu);
		conn->c_rxpdu = NULL;
	}

	conn->c_pdupool_max = 0;
	for (i = CONN_PDUQ_TMP; i < CONN_PAIRQ; i++) {
		iscsi_pduq_free_all(conn->c_queue[i], NULL);
	}
	iscsi_connection_pdu_pool_release(conn);

	if (conn->c_auth)
		iscsi_auth_connection_free(conn->c_auth);

	if (conn->c_keys)
		iscsi_connection_key_free(conn->c_keys);

	if (conn->c_datap)
		os_free(conn->c_datap);

	return 0;
}

int iscsi_connection_destroy(iscsi_connection * conn)
{
	int i;
	iscsi_session *sess = conn->c_sess;

	os_log_debug(ISCSI_DBG_CONN, "destroy conn 0x%p\n", conn);

	/* the conn. is handled by a worker thread */
	if (iscsi_conn_flag_testnclear(conn, CONN_FLAG_THREAD_BIT)) {
		iscsi_thread_remove_data(&conn->c_thinfo, conn);
	} else if (sess) {
		chiscsi_queue *q = sess->s_queue[SESS_TMFQ];
		iscsi_tmf *ptmf = q->q_head;

		for (ptmf = q->q_head; ptmf; ptmf = ptmf->p_next) {
			if (ptmf->p_conn == conn)
				ptmf->p_conn = NULL;
		}

		iscsi_scmdq_free_by_conn(sess->s_queue[SESS_SCMDQ_NEW], conn);
	}

	conn->c_state = CONN_STATE_CLOSED;

	iscsi_connection_cleanup(conn);
	iscsi_stats_dec(ISCSI_STAT_CONN);
	for (i = 0; i < CONN_Q_MAX; i++) {
		ch_queue_free(conn->c_queue[i]);
	}
	os_data_free(conn->os_data);
	os_free(conn);
	return 0;
}

int iscsi_connection_closing(iscsi_connection * conn)
{
	iscsi_session *sess = conn->c_sess;

	os_log_debug(ISCSI_DBG_CONN,
		"closing conn 0x%p, sess 0x%p\n", conn, sess);

	iscsi_conn_flag_set(conn, CONN_FLAG_CLOSING_BIT);
	/* close socket */
	iscsi_socket_close(conn->c_isock,
			iscsi_conn_flag_test(conn, CONN_FLAG_RST_BIT) ? 1 : 0);

	return 0;
}

int iscsi_conn_portal_remove(chiscsi_queue *sessq)
{
	iscsi_session *sess;

	os_lock(sessq->q_lock);
	for (sess = sessq->q_head; sess; sess = sess->s_next)	{
		if(sess) {
			chiscsi_queue *connq = sess->s_queue[SESS_CONNQ];
			iscsi_connection *conn;
			for (conn = connq->q_head; conn; conn = conn->c_next)
				conn->c_portal = NULL;
		}
	}
	os_unlock(sessq->q_lock);

	return 0;
}
/* not used, disabling */
/*
int iscsi_connection_reset(iscsi_connection *conn)
{
	os_log_debug(ISCSI_DBG_CONN, "reset conn 0x%p\n", conn);
	iscsi_connection_closing(conn);
	iscsi_connection_cleanup(conn);

	memset(conn, 0, ISCSI_CONNECTION_SIZE);
	iscsi_connection_init(conn);
	return 0;
}
*/

int iscsi_connection_is_ffp(void *arg)
{
        iscsi_connection *conn = (iscsi_connection *) arg;
        /* into ffp or error */
        return (iscsi_conn_flag_test(conn, CONN_FLAG_FFP_READY_BIT) ||
                iscsi_conn_flag_test(conn, CONN_FLAG_CLOSE_BIT));
}

/* send an iscsi pdu on a connection */
int iscsi_connection_send_pdu(iscsi_connection * conn, iscsi_pdu * pdu)
{
	chiscsi_queue *q = conn->c_queue[CONN_PDUQ_SEND];

	iscsi_pdu_prepare_to_send(pdu);
	iscsi_pdu_enqueue(nolock, q, pdu);

	return iscsi_connection_push_pdus(conn);
}

int iscsi_connection_push_pdus(iscsi_connection * conn)
{
	iscsi_socket *isock = conn->c_isock;

	if (!isock->s_txhold) {
		iscsi_conn_flag_set(conn, CONN_FLAG_TX_PUSH_BIT);
		return (iscsi_connection_write_pdu(conn));
	} else
		os_log_debug(ISCSI_DBG_PDU_TX,
			"conn 0x%p, fb 0x%x, s 0x%x, hold 0x%x, tmax %u\n",
			conn, conn->c_fbits, conn->c_state, isock->s_txhold,
			conn->c_pdudatalen_tmax);

	return 0;
}

/* go through the connection's sentq and clean up. */
void iscsi_connection_clean_sentq(iscsi_connection *conn, unsigned int sn)
{
	chiscsi_queue *q = conn->c_queue[CONN_PDUQ_SENT];
	iscsi_pdu *pdu, *pnext;

	for (pdu = q->q_head; pdu; pdu = pnext) {
		pnext = pdu->p_next;
		if (uint_serial_compare(pdu->p_sn, sn) < 0) {
			os_log_debug(ISCSI_DBG_PDU,
				     "conn 0x%p, tx pdu 0x%p, opcode 0x%x, sn 0x%x < 0x%x, free.\n",
				     conn, pdu, pdu->p_opcode, pdu->p_sn, sn);
			iscsi_pdu_ch_qremove(nolock, q, pdu);
			if (pdu->p_conn != conn) {
				os_log_error("pdu 0x%p, conn 0x%p != 0x%p.\n", pdu, pdu->p_conn, conn);
			}
			iscsi_pdu_done(pdu);
		} else
			break;
	}
}
