/*
 * iscsi_thread.c -- thread management
 */

#include <common/os_builtin.h>
#include <common/iscsi_common.h>
#include <common/iscsi_control.h>
#include <iscsi_structs.h>
#include <iscsi_global.h>
#include <iscsi_socket_api.h>

/* 
 *
 * iscsi_masked_list queue
 *
 */
static iscsi_masked_list *iscsi_masked_list_alloc(void)
{
	iscsi_masked_list *mlist;
	int     offset = sizeof(iscsi_masked_list);

	mlist = os_alloc(ISCSI_MASKED_LIST_SIZE, 0, 1);
	if (!mlist)
		return NULL;
	/* os_alloc does memset() */

	mlist->l_lock = os_alloc(os_lock_size, 0, 1);
	if (!mlist->l_lock) {
		os_free(mlist);
		return NULL;
	}
	os_lock_init(mlist->l_lock);
	offset += os_lock_size;

	return mlist;
}

int iscsi_thread_add_data(iscsi_thread *thp, iscsi_thread_entry *info,
			 void *data)
{
	chiscsi_queue *mlq = thp->th_dataq;
	int     i, qpos = 0;
	unsigned long mask, availmask;
	iscsi_masked_list *mlist;

	info->thp = NULL;
	info->mlist = NULL;

find_mlist:
	os_lock(mlq->q_lock);
	for (mlist = mlq->q_head; mlist; mlist = mlist->l_next, qpos++) {
		if (mlist->l_mask_valid != iscsi_ulong_mask_max)
			break;
	}

	if (!mlist) {
		mlist = iscsi_masked_list_alloc();
		if (!mlist) {
			os_log_info("thp %s, alloc mlist OOM.\n",
				thread_name(thp->th_common));
			os_unlock(mlq->q_lock);
			return -ISCSI_ENOMEM;
		}

		masked_list_enqueue(nolock, mlq, mlist);
	}
	os_unlock(mlq->q_lock);

	os_lock(mlist->l_lock);
	availmask = mlist->l_mask_valid ^ iscsi_ulong_mask_max;
	if (!availmask) {
		os_unlock(mlist->l_lock);
		goto find_mlist;
	}

	for (i = 0, mask = 1; i < ISCSI_BITMASK_BIT_MAX; i++, mask <<= 1) {
		if ((availmask & mask))
			break;
	}

	mlist->l_list[i] = data;
	//mlist->l_mask_valid |= 1 << i;
	os_set_bit_atomic(&mlist->l_mask_valid, i);
	os_unlock(mlist->l_lock);

	os_data_counter_inc(thp->os_data);

	info->mlist = mlist;
	info->mpos = i;
	info->thp = thp;

	os_log_debug(ISCSI_DBG_THREAD,
			"thp %s, add mlist 0x%p, bit %d = 0x%p, total %u.\n",
			thread_name(thp->th_common), mlist, i, data,
			os_data_counter_read(thp->os_data));

	return 0;
}

int iscsi_thread_remove_data(iscsi_thread_entry *info, void *data)
{
	iscsi_thread *thp = info->thp;
	iscsi_masked_list *mlist = info->mlist;
	int bit = info->mpos;
	
	if (!thp || !mlist) {
		os_log_debug(ISCSI_DBG_THREAD,
			"thp 0x%p remove 0x%p, mlist 0x%p.\n",
			thp, data, mlist);
		return 0;
	}
	info->thp = NULL;
	info->mlist = NULL;

	os_lock(mlist->l_lock);
	os_clear_bit_atomic(&mlist->l_mask_valid, bit);
	os_clear_bit_atomic(&mlist->l_mask_work, bit);
	if (mlist->l_list[bit] != data)
		os_log_warn("thp 0x%p remove mlist %d 0x%p != 0x%p.\n",
				thp, bit, mlist->l_list[bit], data);
	mlist->l_list[bit] = NULL;
	os_unlock(mlist->l_lock);

	os_data_counter_dec(thp->os_data);

	os_log_debug(ISCSI_DBG_THREAD,
			"thp %s, remove mlist 0x%p, bit %d, 0x%p, total %u.\n",
			thread_name(thp->th_common), mlist, bit, data,
			os_data_counter_read(thp->os_data));
	return 0;
}

int iscsi_masked_list_queue_cleanup(chiscsi_queue * mlq, int force)
{
	iscsi_masked_list *mlist, *mnext;

	os_lock(mlq->q_lock);
	for (mlist = mlq->q_head; mlq->q_cnt > 1 && mlist; mlist = mnext) {
		mnext = mlist->l_next;
		if (force || !mlist->l_mask_valid) {
			masked_list_ch_qremove(nolock, mlq, mlist);
		} 
	}
	os_unlock(mlq->q_lock);

	return 0;
}

/* 
 *
 * thread
 *
 */

int iscsi_thread_dummy_function(void *arg)
{
	return 0;
}

/* display */
#define show_thread_info(thp,buf,len) \
	len += sprintf(buf + len, "\t%s: %d.\n", \
			thread_name(thp->th_common), \
			os_data_counter_read(thp->os_data));

int iscsi_thread_display(char *buf, int buflen, int detail)
{
	int	baselen = buf ? os_strlen(buf) : 0;
	int     len = baselen;
	int     i;
	iscsi_thread *thp;

	if (!buf || !buflen)
		return 0;

	len += sprintf(buf + len, "worker = %u.\n", iscsi_worker_thread_cnt);
	/* main thread */
	thp = th_main_ptr;
	show_thread_info(thp, buf, len);
	if (len >= buflen)
		goto done;

	/* worker thread */
	for (i = 0; i < iscsi_worker_thread_cnt; i++) {
		thp = iscsi_thread_index(th_worker_ptr, i);
		show_thread_info(thp, buf, len);
		if (len >= buflen)
			goto done;
	}

done:
	if (len >= buflen) len = buflen;
	return (len - baselen);
}


/* allocate and initialize thread struct */
iscsi_thread *iscsi_thread_create(int cnt)
{
	int     i;
	int     size = cnt * ISCSI_THREAD_SIZE;
	int     offset = 0;
	iscsi_thread *head, *tmp;

	head = os_alloc(size, 1, 1);
	if (!head)
		return NULL;
	/* os_alloc does memset() */

	for (i = 0; i < cnt; i++) {
		iscsi_thread *thp = iscsi_thread_index(head, i);
		if (!(thp->os_data = os_data_init((void *)thp)))
			goto os_data_fail;

		os_data_counter_set(thp->os_data, 0);
		offset += sizeof(iscsi_thread);
		ch_queue_alloc(thp->th_dataq);

		thread_farg(thp->th_common) = (void *) thp;
		thread_finit(thp->th_common) = iscsi_thread_dummy_function;
		thread_fproc(thp->th_common) = iscsi_thread_dummy_function;
		thread_ftest(thp->th_common) = iscsi_thread_dummy_function;
		thread_fdone(thp->th_common) = iscsi_thread_dummy_function;
		thread_id(thp->th_common) = i;
	}

	return head;
q_lock_fail:
os_data_fail:
	for (i = 0; i < cnt; i++) {
		tmp = iscsi_thread_index(head, i);
		ch_queue_free(tmp->th_dataq);
		os_data_free(tmp->os_data);
	}
	os_free(head);
	return NULL;
}

/* free thread struct */
void iscsi_thread_destroy(iscsi_thread * thlist, int cnt)
{
	int     i;

	if (!(thlist))
		return;

	for (i = 0; i < cnt; i++) {
		iscsi_thread *thp = iscsi_thread_index(thlist, i);
		iscsi_masked_list *mlist;

		masked_list_dequeue(nolock, thp->th_dataq, mlist);
		while (mlist) {
			os_free(mlist->l_lock);
			os_free(mlist);
			masked_list_dequeue(nolock, thp->th_dataq, mlist);
		}

		os_data_free(thp->os_data);
		ch_queue_free(thp->th_dataq);
	}
	os_free(thlist);
}

/*
 * thread start/stop/exit/wakeup
 */

/* set the thread flag if fbit >= 0, then wake up the thread */
int iscsi_thread_wakeup_all(int fbit)
{
	int     i;
	iscsi_thread *thp = th_main_ptr;

	/* wake up all thread */
	if (th_main_ptr) {
		if (iscsi_thread_flag_test(thp, THREAD_FLAG_UP_BIT)) {
			if (fbit >= 0)
				iscsi_thread_flag_set(thp, fbit);
			os_data_kthread_wakeup(thp->os_data);
		}
	}
	if (th_worker_ptr) {
		for (i = 0; i < iscsi_worker_thread_cnt; i++) {
			thp = iscsi_thread_index(th_worker_ptr, i);
			if (iscsi_thread_flag_test (thp, THREAD_FLAG_UP_BIT)) {
				if (fbit >= 0)
					iscsi_thread_flag_set(thp, fbit);
				os_data_kthread_wakeup(thp->os_data);
			}
		}
	}

	return 0;
}

int iscsi_thread_stop(iscsi_thread * thlist, int max)
{
	int     i;

	if (!thlist || !max)
		return 0;

	for (i = 0; i < max; i++) {
		iscsi_thread *thp = iscsi_thread_index(thlist, i);
		if (iscsi_thread_flag_test(thp, THREAD_FLAG_UP_BIT)) {
			int     rv;
			rv = os_kthread_stop(thp->os_data);
			if (rv < 0)
				break;
			iscsi_thread_flag_clear(thp, THREAD_FLAG_UP_BIT);
		}
	}
	return i;
}

int iscsi_thread_start(iscsi_thread * thlist, int max)
{
	int     i;
	if (!thlist || !max)
		return 0;
	for (i = 0; i < max; i++) {
		iscsi_thread *thp = iscsi_thread_index(thlist, i);
		int     rv;
		if (iscsi_thread_flag_test(thp, THREAD_FLAG_UP_BIT))
			continue;
		rv = os_kthread_create(thp->os_data, &thp->th_common);
		if (rv < 0)
			break;
		rv = os_kthread_start(thp->os_data);
		if (rv < 0)
			break;
		iscsi_thread_flag_set(thp, THREAD_FLAG_UP_BIT);
	}
	return i;
}


int iscsi_thread_exit(void *arg)
{
	iscsi_thread *thp = (iscsi_thread *) arg;
	return (iscsi_thread_flag_test(thp, THREAD_FLAG_STOP_BIT));
}

/*
 * some thread works common to both initiator and target
 */
int iscsi_thread_abort_all_sessions(iscsi_thread * thp)
{
	iscsi_masked_list *mlist;

	for (mlist = thp->th_dataq->q_head; mlist; mlist = mlist->l_next) {
		int     i;
		iscsi_session *sess;
		if (!mlist->l_mask_valid)
			continue;
		for (i = 0; i < ISCSI_BITMASK_BIT_MAX; i++) {
			sess = mlist->l_list[i];
			if (sess) {
				iscsi_session_free(sess);
				mlist->l_list[i] = NULL;
			}
		}
		mlist->l_mask_valid = 0;
		mlist->l_mask_work = 0;
	}
	return 0;
}

int iscsi_thread_abort_all_connections(iscsi_thread * thp)
{
	iscsi_masked_list *mlist;
	chiscsi_queue *q = thp->th_dataq;

	for (mlist = q->q_head; mlist; mlist = mlist->l_next) {
		int     i;
		iscsi_session *sess;
		iscsi_connection *conn;

		if (!mlist->l_mask_valid)
			continue;

		for (i = 0; i < ISCSI_BITMASK_BIT_MAX; i++) {
			conn = mlist->l_list[i];
			if (conn) {
				sess = conn->c_sess;
				iscsi_connection_closing(conn);
				iscsi_connection_destroy(conn);
				mlist->l_list[i] = NULL;
				if (sess && !sess->s_queue[SESS_CONNQ]->q_cnt) {
					iscsi_session_free(sess);
				}
			}
		}
		mlist->l_mask_valid = 0;
		mlist->l_mask_work = 0;
	}
	return 0;
}

/*
 * thread new job scheduler
 */

STATIC iscsi_thread *iscsi_thread_find_least_loaded(iscsi_thread * thlist,
						    unsigned int th_max)
{
	int     i, idx;
	int     min, cnt;
	iscsi_thread *thp = thlist;

	/* just do a linear search to see which thread has least number */
	idx = 0;
	min = os_data_counter_read(thp->os_data);
	for (i = 1; i < th_max; i++) {
		iscsi_thread *thp = iscsi_thread_index(thlist, i);
		cnt = os_data_counter_read(thp->os_data);

		if (min > cnt) {
			min = cnt;
			idx = i;
		}
	}

	return (iscsi_thread_index(thlist, idx));
}

/* distribute session to a session thread */
int iscsi_distribute_session(iscsi_thread *thlist, iscsi_session *sess, unsigned char hint)
{
	iscsi_thread *thp;
	int rv;

	os_lock_irq_os_data(sess->os_data);
	if (iscsi_sess_flag_testnclear(sess, SESS_FLAG_THREAD_BIT)) {
		os_log_debug(ISCSI_DBG_THREAD,
			"sess 0x%p, removed from old thread %s.\n",
			sess, thread_name(sess->s_thinfo.thp->th_common));
		iscsi_thread_remove_data(&sess->s_thinfo, sess);
	}
	os_unlock_irq_os_data(sess->os_data);

	if (hint < iscsi_worker_thread_cnt)
		thp = iscsi_thread_index(thlist, hint);
	else
		thp = iscsi_thread_find_least_loaded(thlist, iscsi_worker_thread_cnt);
	rv = iscsi_thread_add_data(thp, &sess->s_thinfo, sess);

	if (rv < 0) {
		os_log_info("sess 0x%p, add to thread %s failed %d.\n", 
		     sess, thread_name(thp->th_common), rv);
		return rv;
	}

	iscsi_sess_flag_set(sess, SESS_FLAG_THREAD_BIT);

	os_log_debug(ISCSI_DBG_THREAD,
			"distribute sess 0x%p, %u -> %s, total %u.\n",
			sess, hint, thread_name(thp->th_common),
			os_data_counter_read(thp->os_data));

	return 0;
}

/* distribute connection to session thread */
int iscsi_distribute_connection(iscsi_connection * conn)
{
	iscsi_thread *thp;
	iscsi_session *sess = conn->c_sess;
	int     rv;

	/* remove from login thread */
	os_lock_irq_os_data(conn->os_data);
	if (iscsi_conn_flag_testnclear(conn, CONN_FLAG_THREAD_BIT)) {
		iscsi_thread_remove_data(&conn->c_thinfo, conn);
	}
	os_unlock_irq_os_data(conn->os_data);

	/* add to worker thread */
	if (!iscsi_sess_flag_test(sess, SESS_FLAG_THREAD_BIT)) {
		iscsi_socket *isock = conn->c_isock;
		if (iscsi_worker_policy == ISCSI_WORKER_POLICY_QSET)
			rv = iscsi_distribute_session(th_worker_ptr, sess,
				isock ? isock->s_cpuno :
					iscsi_worker_thread_cnt);
		else
			rv = iscsi_distribute_session(th_worker_ptr, sess,
						iscsi_worker_thread_cnt);
		if (rv < 0)
			return rv;
	}

	thp = sess->s_thinfo.thp;
	//os_log_debug(ISCSI_DBG_THREAD,
	os_log_info(
		"distribute conn 0x%p, %u, sess 0x%p -> %s, total %u.\n",
		conn, sess->s_queue[SESS_CONNQ]->q_cnt, sess,
		thread_name(thp->th_common),
		os_data_counter_read(thp->os_data));
	
	/* CONN_FLAG_FFP_READY will enable worker thread to work on the conn */
	iscsi_conn_flag_set(conn, CONN_FLAG_FFP_READY_BIT);
	/* force a read first */
	iscsi_conn_flag_set(conn, CONN_FLAG_RX_READY_BIT);
	iscsi_schedule_session(sess);

	return 0;
}

static void inline thread_set_n_wake(iscsi_thread_entry *thinfo)
{
	mask_list_set_bit(thinfo->mlist, thinfo->mpos);
	if (!(iscsi_thread_flag_testnset(thinfo->thp, THREAD_FLAG_WORK_BIT)))
		os_data_kthread_wakeup(thinfo->thp->os_data);
}

void iscsi_schedule_session(iscsi_session * sess)
{
	if (!sess) 
		return;

	if (iscsi_sess_flag_test(sess, SESS_FLAG_THREAD_BIT)) {
		thread_set_n_wake(&sess->s_thinfo);
	} else 
		os_log_warn("sess 0x%p has NO thread, not scheduled.\n", sess);
}

void iscsi_schedule_connection(iscsi_connection *conn)
{
	iscsi_session *sess;

	if (!conn) 
		return;

	sess = conn->c_sess;
	if (iscsi_conn_flag_test(conn, CONN_FLAG_THREAD_BIT)) {
		thread_set_n_wake(&conn->c_thinfo);
	} else if (sess && iscsi_sess_flag_test(sess, SESS_FLAG_THREAD_BIT)) {
		thread_set_n_wake(&sess->s_thinfo);
	} else
		os_log_warn("conn 0x%p, sess 0x%p NO thread, not scheduled.\n",
			 	conn, sess);
}
