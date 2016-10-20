#include <iscsi_target_api.h>
#include "iscsi_target_private.h"

/*
 * Main(login) thread: accept TCP connections, and handle login
 * request once the connection moves to FFP stage, the connection
 * is handed to one of the worker thread
 */

int     it_main_connection_timeout_update(void *);
int     it_main_process_connection(void *);
int     it_main_connection_timeout_check(void *);

STATIC int it_main_thread_processing(void *arg)
{
	iscsi_thread *thp = (iscsi_thread *) arg;
	chiscsi_queue *mlq = thp->th_dataq;

	thread_process_mlistq(thp, mlq,
			      it_main_process_connection,
			      it_main_connection_timeout_update,
			      it_main_connection_timeout_check);

	return 0;
}

STATIC int it_main_thread_has_work(void *arg)
{
	iscsi_thread *thp = (iscsi_thread *) arg;
	return (iscsi_thread_has_work(thp));
}

STATIC int it_main_thread_done(void *arg)
{
	iscsi_thread *thp = (iscsi_thread *) arg;
	iscsi_thread_flag_clear(thp, THREAD_FLAG_UP_BIT);
	iscsi_thread_flag_clear(thp, THREAD_FLAG_STOP_BIT);
	iscsi_thread_abort_all_connections(thp);
	return 0;
}

int iscsi_target_main_thread_start(iscsi_thread * thlist, int max)
{
	int     i;
	if (!thlist || !max)
		return 0;

	for (i = 0; i < max; i++) {
		iscsi_thread *thp = iscsi_thread_index(thlist, i);
		thread_timeout(thp->th_common) = 20;
		thread_fproc(thp->th_common) = it_main_thread_processing;
		thread_ftest(thp->th_common) = it_main_thread_has_work;
		thread_fdone(thp->th_common) = it_main_thread_done;
	}

	return (iscsi_thread_start(thlist, max));
}

/*
 * Worker(session) thread: handles all iscsi connections passed login stage
 */
int     it_worker_session_timeout_update(void *);
int     it_worker_process_session(void *);
int     it_worker_session_timeout_check(void *);

STATIC int it_worker_thread_processing(void *arg)
{
	iscsi_thread *thp = (iscsi_thread *) arg;
	chiscsi_queue *mlq = thp->th_dataq;

	thread_process_mlistq(thp, mlq,
			      it_worker_process_session,
			      it_worker_session_timeout_update,
			      it_worker_session_timeout_check);
	return 0;
}

STATIC int it_worker_thread_has_work(void *arg)
{
	iscsi_thread *thp = (iscsi_thread *) arg;
	return (iscsi_thread_has_work(thp));
}

STATIC int it_worker_thread_done(void *arg)
{
	iscsi_thread *thp = (iscsi_thread *) arg;
	iscsi_thread_abort_all_sessions(thp);
	return 0;
}

int iscsi_target_worker_thread_start(iscsi_thread * thlist, int max)
{
	int     i;
	if (!thlist || !max)
		return 0;

	for (i = 0; i < max; i++) {
		iscsi_thread *thp = iscsi_thread_index(thlist, i);

		/* thread holds sessions */
		iscsi_thread_flag_set(thp, THREAD_FLAG_DATA_SESS_BIT);

		thread_timeout(thp->th_common) = 10;
		thread_fproc(thp->th_common) = it_worker_thread_processing;
		thread_ftest(thp->th_common) = it_worker_thread_has_work;
		thread_fdone(thp->th_common) = it_worker_thread_done;
	}

	return (iscsi_thread_start(thlist, max));
}

/*
 * iscsi target LU worker thread for LUNs operating in the synchrous mode
 * (i.e., VFS)
 */
void iscsi_target_scmd_assign_lu_worker(chiscsi_scsi_command *sc)
{
	/* a simple hash for now */
//	int i = sc->sc_lun % iscsi_tlu_worker_thread_cnt;
	unsigned int i = os_counter_read(lu_worker_last) %
				iscsi_tlu_worker_thread_cnt;
	iscsi_thread *thp = iscsi_thread_index(th_tlu_ptr, i);

	os_counter_inc(lu_worker_last);
	scmd_fscsi_set_bit(sc, CH_SFSCSI_HOLD_BIT);
	if (!sc->lsc_next) {
		sc->lsc_tlu = i;
                scmd_fpriv_set_bit(sc, CH_SFP_TLU_THREAD_BIT);
		chiscsi_target_lun_scmd_enqueue(lock, thp->th_dataq, sc);
	}

	os_log_debug(ISCSI_DBG_THREAD,
		"sc 0x%p, itt 0x%x, -> lu worker %d.\n",
		sc, sc->sc_itt, i);

	os_data_kthread_wakeup(thp->os_data);
}

void iscsi_target_scmd_remove_from_lu_worker(chiscsi_scsi_command *sc)
{
	iscsi_thread *thp = iscsi_thread_index(th_tlu_ptr, sc->lsc_tlu);

	scmd_fpriv_clear_bit(sc, CH_SFP_TLU_THREAD_BIT);
	chiscsi_target_lun_scmd_ch_qremove(lock, thp->th_dataq, sc);
}

static int it_lu_thread_processing(void *arg)
{
	iscsi_thread *thp = (iscsi_thread *) arg;
	chiscsi_scsi_command *sc;

	chiscsi_target_lun_scmd_dequeue(lock, thp->th_dataq, sc);
	while (sc) {
		scmd_fpriv_clear_bit(sc, CH_SFP_TLU_THREAD_BIT);

		os_log_debug(ISCSI_DBG_THREAD,
			"%s: sc 0x%p, itt 0x%x.\n",
			 thread_name(thp->th_common), sc, sc->sc_itt);
		/*
		 * CH_SFSCSI_HOLD_BIT will be cleared by the callback
		 * chiscsi_scsi_cmd_execution_status()
		 */
		os_lock_irq(sc->sc_lock);
		if (!scmd_fscsi_test_bit(sc, CH_SFSCSI_FORCE_RELEASE_BIT)) {
			os_unlock_irq(sc->sc_lock);
			sc->lu_class->fp_queued_scsi_cmd_exe(sc);
		} else {
			os_log_info("%s: sess 0x%lx, conn 0x%lx, sc 0x%p, "
				"itt 0x%x, s 0x%x, fscsi 0x%lx, release.\n",
				__func__, sc->sc_sess, sc->sc_conn, sc,
				sc->sc_itt, sc->sc_state, sc->sc_fscsi);
			os_unlock_irq(sc->sc_lock);
                	chiscsi_scsi_command_release(sc, NULL);
		}

		chiscsi_target_lun_scmd_dequeue(lock, thp->th_dataq, sc);
	}

	return 0;
}

static int it_lu_thread_has_work(void *arg)
{
	iscsi_thread *thp = (iscsi_thread *) arg;
	return (thp->th_dataq->q_cnt);
}

static int it_lu_thread_done(void *arg)
{
	iscsi_thread *thp = (iscsi_thread *) arg;
	iscsi_thread_flag_clear(thp, THREAD_FLAG_UP_BIT);
	iscsi_thread_flag_clear(thp, THREAD_FLAG_STOP_BIT);
	//iscsi_thread_abort_all_connections(thp);
	return 0;
}

int iscsi_target_lu_thread_start(iscsi_thread * thlist, int max)
{
	int     i;

	if (!thlist || !max)
		return 0;

	for (i = 0; i < max; i++) {
		iscsi_thread *thp = iscsi_thread_index(thlist, i);

		thread_timeout(thp->th_common) = 20;
		thread_fproc(thp->th_common) = it_lu_thread_processing;
		thread_ftest(thp->th_common) = it_lu_thread_has_work;
		thread_fdone(thp->th_common) = it_lu_thread_done;
	}
	return (iscsi_thread_start(thlist, max));
}
