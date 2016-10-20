/*
 * iscsi_session.c -- iscsi session struct manipulation
 */

#include <common/os_builtin.h>
#include <iscsi_structs.h>
#include <iscsi_global.h>
#include <iscsi_session_keys.h>
#include <iscsi_socket_api.h>
#include <iscsi_auth_api.h>
#include <iscsi_target_api.h>

void iscsi_session_display(iscsi_session *sess, int debug)
{
	chiscsi_queue *connq;
	iscsi_node *node;
	iscsi_connection *conn;

	if (!sess)
		return;

	connq = sess->s_queue[SESS_CONNQ];
	node = sess->s_node;

	os_log_info("session 0x%p,%s %s/%s.",
		sess, iscsi_sess_flag_test(sess, SESS_FLAG_CLOSE_BIT) ? 
			"closing" : "",
		sess->s_peer_name, node ? node->n_name : "?");
	os_log_info("        f 0x%lx, %s, conn %u/%u, sn 0x%x~0x%x, win %u.\n",
		sess->s_fbits, sess->s_thinfo.thp ?
			thread_name(sess->s_thinfo.thp->th_common) : "?",
		connq->q_cnt, sess->s_conn_cnt, sess->s_expcmdsn,
		sess->s_maxcmdsn, sess->s_cmdwin);

	if (!debug)
		return;

	for (conn = connq->q_head; conn; conn = conn->c_next)
		iscsi_connection_display(conn, NULL, 0, 0);

}

void    iscsi_session_remove_from_node(iscsi_session *);

unsigned int iscsi_session_next_non_cmd_tag(iscsi_session *sess)
{
	++sess->s_task_tag;
	if (sess->s_task_tag == ISCSI_INVALID_TAG)
		sess->s_task_tag = 0;
	return sess->s_task_tag;
}

/* allocate/setup an iscsi_session structure */
iscsi_session *iscsi_session_alloc(void)
{
	int     i;
	iscsi_session *sess;

	sess = os_alloc(ISCSI_SESSION_SIZE, 1, 1);
	if (!sess)
		return NULL;
	/* os_alloc does memset() */

	if (!(sess->os_data = os_data_init((void *)sess)))
		goto os_data_fail;

	for (i = 0; i < SESS_Q_MAX; i++) {
		ch_queue_alloc(sess->s_queue[i]);
	}

	iscsi_stats_inc(ISCSI_STAT_SESS);

	/* Start the Non CMD itt offset from a safe offset */
	sess->s_task_tag = 0xffff0000;
	os_log_debug(ISCSI_DBG_SESS, "alloc session 0x%p\n", sess);
	return sess;

q_lock_fail:
	for (i = 0; i < SESS_Q_MAX; i++) {
		ch_queue_free(sess->s_queue[i]);
	}
	os_data_free(sess->os_data);
os_data_fail:
	os_free(sess);
	return NULL;
}

/* destroy an iscsi_session structure */
int iscsi_session_free(iscsi_session * sess)
{
	chiscsi_queue *q;
	iscsi_meta_ptr *mptr;
	chiscsi_scsi_command *sc;
	int i;

	os_log_debug(ISCSI_DBG_SESS, "free session 0x%p\n", sess);

	iscsi_sess_flag_clear(sess, SESS_FLAG_FFP_BIT);

	q = sess->s_queue[SESS_TMFQ];
	if (q && q->q_cnt) {
		/* keep the session until backend is done with tmf */
		iscsi_sess_flag_set(sess, SESS_FLAG_TMFQ_PEND_BIT);
		os_log_info("%s: sess 0x%p, wait for TMF to finish.\n",
				__func__, sess);
	} else {
		if (iscsi_sess_flag_testnclear(sess, SESS_FLAG_THREAD_BIT))
			iscsi_thread_remove_data(&sess->s_thinfo, sess);

		if (iscsi_sess_flag_testnclear(sess, SESS_FLAG_TMFQ_PEND_BIT)) {
			os_log_info("%s: sess 0x%p, TMF finished.\n",
					__func__, sess);
			goto free_last;
		}
       }

	iscsi_session_remove_from_node(sess);

	q = sess->s_queue[SESS_CONNQ];
	if (q && q->q_cnt) {
		iscsi_connection *conn;

		iscsi_conn_dequeue(nolock, q, conn);
		while (conn) {
			iscsi_connection_closing(conn);
			iscsi_connection_destroy(conn);
			iscsi_conn_dequeue(nolock, q, conn);
		}
	}

	/* assert (numconn == 0) */
	/* assert (connlist == NULL) */
	/* command cleanup? */
	/* ddp unmapping? */
	/* tag releasing? */


	q = sess->s_queue[SESS_RESETQ];
	os_lock(q->q_lock);
	meta_ptr_dequeue(nolock, q, mptr);
	while (mptr) {
		os_free(mptr);
		meta_ptr_dequeue(nolock, q, mptr);
	}
	os_unlock(q->q_lock);

	if (sess->s_keys)
		iscsi_session_key_free(sess->s_keys);

	if (sess->s_auth)
		iscsi_auth_session_free(sess->s_auth);

	if (sess->acl_lun_list)
		os_free(sess->acl_lun_list);

free_last:
	if (!iscsi_sess_flag_test(sess, SESS_FLAG_TMFQ_PEND_BIT)) {
		if(sess->s_queue[SESS_SCMDQ_NEW])
			iscsi_scmdq_free_all(sess->s_queue[SESS_SCMDQ_NEW]);

		q = sess->s_queue[SESS_SCMDQ_FREE];
		scmd_dequeue(nolock, q, sc);
		while(sc) {
			chiscsi_scsi_command_release(sc, NULL);
			scmd_dequeue(nolock, q, sc);
		}

		for (i = 0; i < SESS_Q_MAX; i++) {
			ch_queue_free(sess->s_queue[i]);
		}
		os_data_free(sess->os_data);

		os_free(sess);
		iscsi_stats_dec(ISCSI_STAT_SESS);
	}
	return 0;
}

int iscsi_session_is_ffp(void *arg)
{
	iscsi_session *sess = (iscsi_session *)arg;

	/* into ffp or error */
        return (iscsi_sess_flag_test(sess, SESS_FLAG_FFP_BIT) ||
                iscsi_sess_flag_test(sess, SESS_FLAG_CLOSE_BIT));
}

int iscsi_session_add_connection(iscsi_session * sess, iscsi_connection * conn)
{
	chiscsi_queue *connq = sess->s_queue[SESS_CONNQ];

	if (iscsi_sess_flag_test(sess, SESS_FLAG_CLOSE_BIT)) {
		os_log_warn
			("failed to add conn to sess 0x%p, flag 0x%lx closing.\n",
			 sess, sess->s_fbits);
		return -ISCSI_EINVAL;
	}

	os_lock(connq->q_lock);
	iscsi_conn_enqueue(nolock, connq, conn);
	conn->c_sess = sess;
	if (connq->q_cnt == 1) {
		iscsi_conn_flag_set(conn, CONN_FLAG_LEADING_CONN_BIT);
	}
	os_unlock(connq->q_lock);
	return 0;
}

iscsi_connection *iscsi_session_find_connection_by_cid(iscsi_session * sess,
						       unsigned short cid)
{
	chiscsi_queue *connq = sess->s_queue[SESS_CONNQ];
	iscsi_connection *conn;
	iscsi_conn_qsearch_by_cid(lock, connq, conn, cid);
	return conn;
}

/**
 * iscsi_session_get_next_cid -- return next available connection id
 */
unsigned short iscsi_session_get_next_cid(iscsi_session * sess)
{
	unsigned short cid;
	chiscsi_queue *connq = sess->s_queue[SESS_CONNQ];
	iscsi_connection *conn;

	do {
		iscsi_conn_qsearch_by_cid(lock, connq, conn, sess->s_next_cid);
		sess->s_next_cid++;
	} while (conn);

	cid = sess->s_next_cid++;
	return cid;
}

void iscsi_session_schedule_close(iscsi_session * sess)
{
	iscsi_sess_flag_set(sess, SESS_FLAG_CLOSE_BIT);

	if (iscsi_sess_flag_test(sess, SESS_FLAG_THREAD_BIT))
		iscsi_schedule_session(sess);
	else {
		chiscsi_queue *connq = sess->s_queue[SESS_CONNQ];
		iscsi_connection *conn;

		if (!connq) {
			os_log_info("sess 0x%p schedule close, connq NULL.\n",
					sess);
			return;
		}

		for (conn = connq->q_head; conn; conn = conn->c_next) {
			iscsi_conn_flag_set(conn, CONN_FLAG_CLOSE_BIT);
			iscsi_schedule_connection(conn);
		}
	}
}

/*
 *
 */
void iscsi_session_remove_from_node(iscsi_session * sess)
{
	chiscsi_queue *q;
	iscsi_node *node = sess->s_node;

	if (!node)
		return;

	sess->s_node = NULL;
	q = node->n_queue[NODE_SESSQ];

	os_lock(q->q_lock);
	session_ch_qremove(nolock, q, sess);
	if (!q->q_head) {
		os_unlock(q->q_lock);
		os_data_wake_up_ackq(node->os_data);
	} else {
		os_unlock(q->q_lock);
	}
}

void iscsi_session_add_to_node(iscsi_session * sess, iscsi_node * node)
{
	chiscsi_queue *q = node->n_queue[NODE_SESSQ];

	session_enqueue(lock, q, sess);
	sess->s_node = node;
}
