/*
 * iscsi_global.c -- iscsi globals
 */

#include <common/iscsi_common.h>
#include <iscsi_structs.h>
#include <iscsi_control_api.h>
#include <iscsi_target_api.h>

/* debug */
unsigned int iscsi_msg_level = 0;	/* ERR, WARN is always on*/
unsigned long iscsi_msg_debug_level = 0UL;

/* iscsi driver options */
char    iscsi_target_vendor_id[ISCSI_TARGET_VENDOR_ID_MAXLEN + 1] =
	ISCSI_TARGET_VENDOR_ID_DFLT;
char    iscsi_chelsio_ini_idstr[ISCSI_ALIAS_LEN_MAX + 1] = "cxgb4i";
unsigned char iscsi_offload_mode = ISCSI_OFFLOAD_MODE_DEFAULT;
unsigned char iscsi_worker_policy = ISCSI_WORKER_POLICY_DEFAULT;
unsigned char iscsi_perf_params = 0; /* ISCSI_PERF_ALIGN8; */
unsigned char iscsi_auth_order = ISCSI_AUTH_ORDER_CHAP_FIRST;
unsigned char iscsi_acl_order = ISCSI_ACL_ORDER_CONFIG_FIRST;
unsigned char iscsi_ha_mode = 0;

/* Discovery CHAP options */
unsigned char disc_auth_method = ISCSI_DISC_AUTH_METHOD_NONE;
unsigned char disc_auth_chap_policy = ISCSI_DISC_AUTH_POLICY_ONEWAY;
char disc_auth_chap_target[ISCSI_CHAP_CHALLENGE_LENGTH_MAX] = {0};
char disc_auth_chap_initiator[ISCSI_CHAP_CHALLENGE_LENGTH_MAX] = {0};

unsigned int iscsi_max_redirect = ISCSI_MAX_REDIRECT_DEFAULT;

/* max. time allowd for an initiator to complete login */
unsigned int iscsi_login_complete_time = ISCSI_LOGIN_COMPLETE_TIME_DEFAULT;

/* simulate testing conditions */
unsigned int iscsi_test_mode = 0;

#ifdef __UIT_PDTEST_CHECK__
unsigned char pdtest_check = 0;
#endif

/* iscsi node queues */
chiscsi_queue *iscsi_nodeq = NULL;

/* iscsi threads */
iscsi_thread *th_main_ptr = NULL;
iscsi_thread *th_worker_ptr = NULL;
unsigned int iscsi_worker_thread_cnt = 0;
void *lu_worker_last = NULL;

/*
 * iscsi threads for target LUNs which operates in synchrous mode
 * for example, FILE mode IOs.
 */
iscsi_thread *th_tlu_ptr = NULL;
unsigned int iscsi_tlu_worker_thread_cnt = 0;
extern unsigned int iscsi_lu_worker_thread;

/* iscsi connection/session management */

int iscsi_global_settings_display(char *buf, int buflen, int detail)
{
	int     baselen = os_strlen(buf);
	int 	len = baselen;

#if 0
	len += sprintf(buf + len, "\tiscsi_offload_mode=%s\n",
		      iscsi_offload_mode_val2str(iscsi_offload_mode));
#endif
	len += sprintf(buf + len, "\tiscsi_auth_order=%s\n",
			iscsi_auth_order_val2str(iscsi_auth_order));
	len += sprintf(buf + len, "\tiscsi_acl_order=%s\n",
			iscsi_acl_order_val2str(iscsi_acl_order));
	if (os_strcmp(iscsi_target_vendor_id, ISCSI_TARGET_VENDOR_ID_DFLT))
		len += sprintf(buf + len, "\tiscsi_target_vendor_id=%s\n",
				iscsi_target_vendor_id);
	len += sprintf(buf + len, "\tiscsi_login_complete_time=%u\n",
			iscsi_login_complete_time);
	len += sprintf(buf + len, "\tDISC_AuthMethod=%s\n",
			iscsi_disc_auth_val2str(disc_auth_method));
	len += sprintf(buf + len, "\tDISC_Auth_CHAP_Policy=%s\n",
			iscsi_disc_auth_policy_val2str(disc_auth_chap_policy));
	len += sprintf(buf + len, "\tDISC_Auth_CHAP_Target=%s\n",
			disc_auth_chap_target);
	len += sprintf(buf + len, "\tDISC_Auth_CHAP_Initiator=%s\n",
			disc_auth_chap_initiator);
	len += sprintf(buf + len, "\tiscsi_chelsio_ini_idstr=%s\n",
			iscsi_chelsio_ini_idstr);
	/* make the following invisible */
#if 0
	len += sprintf(buf + len, "\tiscsi_HA_mode=%s\n",
		      iscsi_boolean_val2str(iscsi_ha_mode));
	len += sprintf(buf + len, "\tiscsi_perf_params=0x%x\n",
			iscsi_perf_params);
	len += sprintf(buf + len, "\tiscsi_worker_policy=%s\n",
			iscsi_worker_policy_val2str(iscsi_worker_policy));
	len += sprintf(buf + len, "\tiscsi_verbose_level=0x%x,0x%lx\n",
		       iscsi_msg_level, iscsi_msg_debug_level);
	len += sprintf(buf + len, "\tiscsi_test_mode=0x%x\n", iscsi_test_mode);
#endif

#ifdef __UIT_PDTEST_CHECK__
	len += sprintf(buf + len, "\tpdtest_check=%u\n", pdtest_check);
#endif

	if (detail) {
		;
	}

	return (len - baselen);
}

void iscsi_globals_cleanup(void)
{
	if (!iscsi_worker_thread_cnt)
		return;

	if (th_main_ptr) {
		iscsi_thread_destroy(th_main_ptr, 1);
		th_main_ptr = NULL;
	}
	if (th_worker_ptr) {
		iscsi_thread_destroy(th_worker_ptr, iscsi_worker_thread_cnt);
		th_worker_ptr = NULL;
	}

	if (th_tlu_ptr) {
		iscsi_thread_destroy(th_tlu_ptr, iscsi_tlu_worker_thread_cnt);
		th_tlu_ptr = NULL;
	}

	if (lu_worker_last) {
		os_free(lu_worker_last);
		lu_worker_last = NULL;
        }

	if (iscsi_nodeq) {
		ch_queue_free(iscsi_nodeq);
		iscsi_nodeq = NULL;
	}

	iscsi_worker_thread_cnt = 0;
}

int iscsi_globals_init(int ncpu)
{
	int i;

	iscsi_worker_thread_cnt = ncpu;
	if (!iscsi_lu_worker_thread)
		iscsi_tlu_worker_thread_cnt = ncpu;
	else
		iscsi_tlu_worker_thread_cnt = iscsi_lu_worker_thread;

	ch_queue_alloc(iscsi_nodeq);
	if (!iscsi_nodeq)
		goto err_out;

	th_main_ptr = iscsi_thread_create(1);
	if (!(th_main_ptr))
		goto err_out;

	sprintf(thread_name(th_main_ptr->th_common), "ch_tmain");
	th_main_ptr->th_common.id = iscsi_worker_thread_cnt;

	th_worker_ptr = iscsi_thread_create(iscsi_worker_thread_cnt);
	if (!th_worker_ptr)
		goto err_out;

	for (i = 0; i < iscsi_worker_thread_cnt; i++) {
		iscsi_thread *thp = iscsi_thread_index(th_worker_ptr, i);
		sprintf(thread_name(thp->th_common), "ch_tworker_%d", i);
		thp->th_common.id = i;
	}

	/* target lu worker threads */
	lu_worker_last = os_alloc(os_counter_size, 1, 1);
	if (!lu_worker_last)
		goto err_out;
        os_counter_set(lu_worker_last, 0);

	th_tlu_ptr = iscsi_thread_create(iscsi_tlu_worker_thread_cnt);
	if (!th_tlu_ptr)
		goto err_out;

	for (i = 0; i < iscsi_tlu_worker_thread_cnt; i++) {
		iscsi_thread *thp = iscsi_thread_index(th_tlu_ptr, i);
		sprintf(thread_name(thp->th_common), "ch_tlu_%d", i);
		thp->th_common.id = i;
	}

	return 0;

q_lock_fail:
err_out:
	iscsi_globals_cleanup();
	return -ISCSI_ENOMEM;
}
