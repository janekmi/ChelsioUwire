#include <iscsi_target_api.h>
#include "iscsi_target_private.h"

/* default target, used for discovery */
iscsi_node *it_target_dflt = NULL;
/* all the target portals */
chiscsi_queue *it_portal_q = NULL;

chiscsi_queue *it_sc_pend_q = NULL;	/* pending free */

chiscsi_queue *it_lu_q = NULL;	/* all luns for chelsio target */

extern chiscsi_target_class tclass_chelsio;

int iscsi_target_init(void)
{
	int     rv;

	ch_queue_alloc(it_portal_q);
	if (!it_portal_q)
		return -ISCSI_ENOMEM;

	ch_queue_alloc(it_lu_q);
	if (!it_lu_q)
		return -ISCSI_ENOMEM;

	ch_queue_alloc(it_sc_pend_q);
	if (!it_sc_pend_q)
		return -ISCSI_ENOMEM;

	rv = target_class_init();
	if (rv < 0)
		return rv;

	/* start all thread */
	rv = iscsi_target_main_thread_start(th_main_ptr, 1);
	if (rv != 1)
		return -ISCSI_EINVAL;

	rv = iscsi_target_worker_thread_start(th_worker_ptr,
					      iscsi_worker_thread_cnt);
	if (rv != iscsi_worker_thread_cnt)
		return -ISCSI_EINVAL;

	rv = iscsi_target_lu_thread_start(th_tlu_ptr,
					iscsi_tlu_worker_thread_cnt);
	if (rv != iscsi_tlu_worker_thread_cnt)
		return -ISCSI_EINVAL;

	/* bring up default chelsio target */
	rv = chiscsi_target_class_register(&tclass_chelsio);
	if (rv < 0)
		return -ISCSI_EINVAL;

	return 0;

q_lock_fail:
	ch_queue_free(it_portal_q);
	ch_queue_free(it_lu_q);
	ch_queue_free(it_sc_pend_q);
	return -ISCSI_ENOMEM;
}

void iscsi_target_cleanup(void)
{
	if (it_target_dflt) {
		iscsi_node_remove(it_target_dflt, 0, NULL, 0);
		it_target_dflt = NULL;
	}
	iscsi_node_remove(NULL, 0, NULL, 0);

	chiscsi_target_class_deregister(tclass_chelsio.class_name);

	target_class_cleanup();

	if (it_portal_q) {
		iscsi_portal *p;
		for (p = it_portal_q->q_head; p; p = p->p_next) {
			char tbuf[80];

			tcp_endpoint_sprintf(&p->p_ep, tbuf);
			os_log_error("orphaned portal %s.\n", tbuf);
		}
		ch_queue_free(it_portal_q);
		it_portal_q = NULL;
	}

	if (it_lu_q) {
if (it_lu_q->q_cnt)
	os_log_error("global luq %u.\n", it_lu_q->q_cnt);
		ch_queue_free(it_lu_q);
		it_lu_q = NULL;
	}

	/* stop all thread */
	iscsi_thread_stop(th_main_ptr, 1);
	iscsi_thread_stop(th_worker_ptr, iscsi_worker_thread_cnt);
	iscsi_thread_stop(th_tlu_ptr, iscsi_tlu_worker_thread_cnt);

	if (it_sc_pend_q && it_sc_pend_q->q_cnt) {
		chiscsi_scsi_command *sc;	

		os_log_info("it sc pendq clean up %u.\n", it_sc_pend_q->q_cnt);
		scmd_dequeue(lock, it_sc_pend_q, sc);
		while (sc) {
			chiscsi_scsi_cmd_ready_to_release(sc);
			scmd_dequeue(lock, it_sc_pend_q, sc);
		}
		ch_queue_free(it_sc_pend_q);
		it_sc_pend_q = NULL;
	}
}
