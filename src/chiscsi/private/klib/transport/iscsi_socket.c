/* 
 * sockets-based iscsi pdu read/write
 */

#include <common/os_builtin.h>
#include <common/os_export.h>
#include <common/iscsi_control.h>
#include <common/iscsi_common.h>
#include <iscsi_control_defs.h>
#include <iscsi_structs.h>
#include <iscsi_global.h>

/*
 * iscsi socket APIs
 */
void iscsi_socket_destroy(iscsi_socket *isock)
{
	if (isock)
		os_socket_destroy(isock);
}

void iscsi_socket_close(iscsi_socket *isock, int rst)
{
	if (isock) {
		if (rst)
			isock->s_flag |= ISCSI_SOCKET_RST;
		os_socket_release(isock);
	}
}

iscsi_connection *iscsi_connection_listen(struct tcp_endpoint *ep)
{
	iscsi_socket *isock;
	iscsi_connection *conn;

	isock = os_socket_listen(ep, 1024);
	if (!isock)
		return NULL;

	/* create a new connection */
	conn = iscsi_connection_create();
	if (!conn) {
		os_socket_release(isock);
		return NULL;
	}

	conn->c_isock = isock;
	conn->c_state = CONN_STATE_LISTEN;
	isock->s_appdata = conn;

	return conn;
}

int iscsi_connection_accept(iscsi_connection *conn, iscsi_connection **conn_pp)
{
	iscsi_socket *isock = NULL;
	iscsi_connection *newconn;
	int rv;

	*conn_pp = NULL;

	if (conn->c_state != CONN_STATE_LISTEN)
		return -ISCSI_EINVAL_STATE;

	/* create a new connection */
	newconn = iscsi_connection_create();
	if (!newconn)
		return -ISCSI_ENOMEM;

	rv = os_socket_accept(conn->c_isock, newconn, &isock);
	if (rv < 0 || !isock)
		goto free_conn;

	newconn->c_isock = isock;
	newconn->c_state = CONN_STATE_CONNECTED;

	os_log_debug(ISCSI_DBG_CONN,
		"accepted conn 0x%p, isock 0x%p,%s offloaded.\n",
		newconn, isock,
		(isock->s_flag & ISCSI_SOCKET_OFFLOADED) ? "" : " NOT");

	*conn_pp = newconn;

	return 1;

free_conn:
	iscsi_connection_destroy(newconn);
	return rv;
}

int iscsi_connection_write_pdu(iscsi_connection * conn)
{
	iscsi_socket *isock = conn->c_isock;
	int	rv;

	if ((conn->c_state < CONN_STATE_LOGIN) ||
	    (conn->c_state >= CONN_STATE_CLOSING) ||
	    !isock ||
	    (isock->s_flag & ISCSI_SOCKET_TX_CLOSED)) {
		return -ISCSI_EIO;
	}
	rv = isock->sk_write_pdus(isock,
				  conn->c_queue[CONN_PDUQ_SEND],
				  conn->c_queue[CONN_PDUQ_SENT]);

	return rv < 0 ? rv : 0;
}

int iscsi_connection_adjust_offload_mode(iscsi_connection *conn)
{
	iscsi_session *sess = conn->c_sess;
	iscsi_node *node = sess->s_node;
	iscsi_socket *isock = conn->c_isock;
	unsigned char mode = iscsi_offload_mode;
	int force = 0;
	int rv;

	/* if non-offloaded conn, no offload crc or ddp */
	if (!(isock->s_flag & ISCSI_SOCKET_OFFLOADED) || !isock->s_odev) {
		isock->s_flag &= ~ISCSI_SOCKET_OFFLOADED;
		return ISCSI_OFFLOAD_MODE_NIC;
	}

	conn->difdix_mode = 0;
	if (iscsi_node_has_dif_dix_enabled_lun(node, LUN_T10DIX_BIT))
		conn->difdix_mode = ISCSI_OFFLOAD_T10DIX;
	if (iscsi_node_has_dif_dix_enabled_lun(node, LUN_T10DIF_BIT))
		conn->difdix_mode |= ISCSI_OFFLOAD_T10DIXDIF;

	if (mode == ISCSI_OFFLOAD_MODE_AUTO) {
#if 0
		if (conn->c_hdigest_len || conn->c_ddigest_len ||
		    conn->difdix_mode)
			mode = ISCSI_OFFLOAD_MODE_ULP;
		else
			mode = ISCSI_OFFLOAD_MODE_TOE;
#else
		/* default to ULP mode always */
		mode = ISCSI_OFFLOAD_MODE_ULP;
#endif
	}

	if (!chiscsi_target_is_chelsio(node->tclass)) {
		if (mode != ISCSI_OFFLOAD_MODE_ULP) 
			os_log_info("chiscsi api force ULP 0x%x -> 0x%x.\n",
                                mode, ISCSI_OFFLOAD_MODE_ULP);
		mode = ISCSI_OFFLOAD_MODE_ULP;
		force = 1;
	}
#ifdef __TEST_PREMAPPED_SKB__
	else if (!(mode & ISCSI_OFFLOAD_MODE_ULP)) {
		os_log_info("chiscsi premap force ULP 0x%x -> 0x%x.\n",
			mode, ISCSI_OFFLOAD_MODE_ULP);
		mode = ISCSI_OFFLOAD_MODE_ULP;
		force = 1;
	}
#endif

	if (iscsi_sess_flag_test(sess, SESS_FLAG_CHELSIO_PEER))
		isock->s_flag |= ISCSI_SOCKET_QUICKACK;

	if (mode == ISCSI_OFFLOAD_MODE_ULP && conn->difdix_mode)
		mode |= ISCSI_OFFLOAD_MODE_T10DIX;
	else
		mode &= ~ISCSI_OFFLOAD_MODE_T10DIX;

	rv = os_socket_set_offload_mode(isock,
				force ? (mode | ISCSI_OFFLOAD_MODE_FORCE) :
					mode,
				conn->c_hdigest_len, conn->c_ddigest_len,
				conn->difdix_mode);
	if (rv < 0)
		return rv;

	if (force && rv != mode)
		os_log_info("%s: conn 0x%p, 0x%x -> 0x%x, force %d.\n",
			__func__, conn, mode, rv, force);

	conn->c_offload_mode = rv; 
	return conn->c_offload_mode;
}

/*
 * iscsi connection TCP callbacks 
 */

void iscsi_socket_state_change(iscsi_socket * isock)
{
	if (isock) {
		iscsi_connection *conn = isock->s_appdata;

		os_log_debug((ISCSI_DBG_CONN),
			"conn 0x%p, isock 0x%p, 0x%x, state change.\n",
			conn, isock, isock->s_flag);

		if (conn && (isock->s_flag & ISCSI_SOCKET_TX_CLOSED)) {
			iscsi_conn_flag_set(conn, CONN_FLAG_CLOSED_BIT);
			iscsi_conn_flag_set(conn, CONN_FLAG_CLOSE_BIT);
			iscsi_schedule_connection(conn);
		} else if (conn && conn->c_state != CONN_STATE_CLOSING) {
			iscsi_conn_flag_set(conn, CONN_FLAG_CLOSE_BIT);
			iscsi_schedule_connection(conn);
		}
	}
}

void iscsi_socket_data_ready(iscsi_socket * isock)
{
	if (isock) {
		iscsi_connection *conn = isock->s_appdata;

		if (conn && !iscsi_conn_flag_test(conn, CONN_FLAG_CLOSE_BIT)) {
			os_log_debug(ISCSI_DBG_PDU_RX,
				"conn 0x%p data ready.\n", conn);
			iscsi_conn_flag_set(conn, CONN_FLAG_RX_READY_BIT);
			iscsi_schedule_connection(conn);
		}
	}
}

void iscsi_socket_write_space(iscsi_socket * isock, int r2t)
{
	if (isock) {
		iscsi_connection *conn = isock->s_appdata;

		if (conn && !iscsi_conn_flag_test(conn, CONN_FLAG_CLOSE_BIT)) {
			os_log_debug(ISCSI_DBG_PDU_RX,
				"conn 0x%p write space.\n", conn);
			if (r2t)
				os_data_counter_inc(conn->os_data);
			iscsi_schedule_connection(conn);
		}
	}
}

int iscsi_socket_init(void)
{
	return 0;
}

int iscsi_socket_cleanup(void)
{
	return 0;
}
