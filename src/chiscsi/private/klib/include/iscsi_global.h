#ifndef __ISCSI_GLOBAL__
#define __ISCSI_GLOBAL__

#include "iscsi_thread.h"

/* original, keep duplicate in /includes/common/os_data.h consistent */
typedef enum _os_data_parent {
	OS_DATA_UNSET=0,
	OS_DATA_ISCSI_THREAD,
	OS_DATA_ISCSI_NODE,
	OS_DATA_ISCSI_SESS,
	OS_DATA_ISCSI_CONN,
	OS_DATA_ISCSI_LUN,
	OS_DATA_ISCSI_PORTAL,
	OS_DATA_ISCSI_SCSI_CMD,
} os_data_parent;

/*original, keep duplicate in /includes/common/os_data.h consistent */
enum iscsi_portal_counters {
	RD_B_CTR=0,
	WR_B_CTR,
	RD_CMD_CTR,
	WR_CMD_CTR,
	MAX_PORTAL_STATS,
};

/* iscsi control parameters */
extern char iscsi_target_vendor_id[];
extern char iscsi_chelsio_ini_idstr[];
extern unsigned char iscsi_offload_mode;
extern unsigned char iscsi_perf_params;
extern unsigned char iscsi_worker_policy;

extern unsigned char iscsi_auth_order;
extern unsigned char iscsi_acl_order;
extern unsigned char iscsi_ha_mode;
extern unsigned int iscsi_max_redirect;

extern unsigned int iscsi_msg_level;
extern unsigned long iscsi_msg_debug_level;

extern unsigned int iscsi_test_mode;
extern unsigned int iscsi_login_complete_time;

extern unsigned char disc_auth_method;
extern unsigned char disc_auth_chap_policy;
extern char disc_auth_chap_target[];
extern char disc_auth_chap_initiator[];


#ifdef __UIT_PDTEST_CHECK__
extern unsigned char pdtest_check;
#endif

/* internal */
extern int iscsi_heartbeat_check;

/* iscsi node queues */
extern chiscsi_queue *iscsi_nodeq;

/* iscsi threads */
extern iscsi_thread *th_main_ptr;
extern iscsi_thread *th_worker_ptr;
extern unsigned int iscsi_worker_thread_cnt;

extern iscsi_thread *th_tlu_ptr;
extern void *lu_worker_last;
extern unsigned int iscsi_tlu_worker_thread_cnt;

extern unsigned int lu_sect_shift;

/* for any bit mask, iscsi uses unsigned long */
extern const unsigned long iscsi_ulong_mask_max;
extern const unsigned int iscsi_ulong_mask_bits;
extern const unsigned int iscsi_ulong_mask_shift;

/* queue depth */
int     iscsi_global_settings_display(char *, int, int);

#endif
