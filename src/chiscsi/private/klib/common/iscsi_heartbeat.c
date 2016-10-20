/*
 * iscsi heartbeat timer
 */

#include <common/iscsi_common.h>
#include <iscsi_structs.h>
#include <iscsi_global.h>

static void *iscsi_heartbeat = NULL;
int     iscsi_heartbeat_check = 1;

STATIC void iscsi_heartbeat_timer_pop(unsigned long data)
{
	/* wake up all thread */
	if (iscsi_heartbeat_check) {
		iscsi_thread_wakeup_all(THREAD_FLAG_TIMEOUT_CHECK_BIT);
	}
	/* restart the timer */
	os_timer_start(iscsi_heartbeat, 1, iscsi_heartbeat_timer_pop);
}

void iscsi_heartbeat_stop(void)
{
	if (iscsi_heartbeat) {
		os_timer_stop(iscsi_heartbeat);
		os_timer_free(iscsi_heartbeat);
		iscsi_heartbeat = NULL;
	}
}

int iscsi_heartbeat_start(void)
{
	iscsi_heartbeat = os_timer_alloc(1);
	if (!iscsi_heartbeat)
		return -ISCSI_ENOMEM;
	os_timer_init(iscsi_heartbeat, NULL);
	os_timer_start(iscsi_heartbeat, 1, iscsi_heartbeat_timer_pop);
	return 0;
}

int iscsi_connection_timeout_check(iscsi_connection * conn,
				   int (*fp_ping) (iscsi_connection *))
{
	/* no timeout */
	if (!conn->c_timeout)
		return 0;

	if (iscsi_conn_flag_testnclear(conn, CONN_FLAG_BUSY_BIT) ||
	    iscsi_conn_flag_test(conn, CONN_FLAG_RX_READY_BIT)) {
		conn_timeout_clear(conn);
		return 0;
	}

	conn->c_idle++;
	if (!iscsi_conn_flag_test(conn, CONN_FLAG_FFP_READY_BIT) ||
	    !fp_ping) {
		if (conn->c_idle >= conn->c_timeout) {
			iscsi_conn_flag_set(conn, CONN_FLAG_TIMEOUT_BIT);
			return 1;
		}
		return 0;
	}

	if (conn->c_idle >= conn->c_timeout) {
		chiscsi_queue *q = conn->c_queue[CONN_PDUQ_SEND];
		/* if there is pdu queued up for tx, wait for later */
		if (q->q_head) {
			conn->c_idle = 0;
			return 0;
		}

		if (!iscsi_conn_flag_test(conn, CONN_FLAG_PINGED_BIT)) {
			/* if there is no pdus queued up for tx, and
			   sending ping failed */
			if (fp_ping(conn) < 0) {
				os_log_info("conn 0x%p, ping failed, close.\n",
						conn);
				iscsi_conn_flag_set(conn, CONN_FLAG_CLOSE_BIT);
				return 1;
			}
			iscsi_conn_flag_set(conn, CONN_FLAG_PINGED_BIT);
			conn->c_idle = 0;

		} else if (!(iscsi_conn_flag_test(conn, CONN_FLAG_RX_READY_BIT))) {
			/* pinged but have not received a response */
			iscsi_conn_flag_set(conn, CONN_FLAG_TIMEOUT_BIT);
			return 1;
		}
	}

	return 0;
}
