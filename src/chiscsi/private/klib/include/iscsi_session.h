#ifndef __ISCSI_SESSION_H__
#define __ISCSI_SESSION_H__

#include <common/iscsi_tag.h>

enum session_flag_bits {
	SESS_FLAG_THREAD_BIT,	/* session has a processing thread */
	SESS_FLAG_FFP_BIT,	/* session established */
	SESS_FLAG_CLOSE_BIT,
	SESS_FLAG_NODE_PORTAL_CHNG_BIT,

	SESS_FLAG_NODE_LUN_CHNG_BIT,
	SESS_FLAG_NODE_ACL_CHNG_BIT,
	SESS_FLAG_LU_RESET_BIT,	/* target: LU reset */
	SESS_FLAG_DEVICE_RESET_BIT,	/* target: device reset */

	SESS_FLAG_DEVICE_RESCAN_BIT,	/* target: device need to be rescaned */
        SESS_FLAG_TARGET_RESET_BIT,
	SESS_FLAG_TMFQ_PEND_BIT,
        SESS_FLAG_CHELSIO_PEER
};

enum iscsi_session_qtypes {
	SESS_CONNQ,
	SESS_RESETQ,
	SESS_TMFQ,

	/* queues for scsi commands */
	SESS_SCMDQ_NEW,
	SESS_SCMDQ_FREE,

	SESS_Q_MAX
};

struct iscsi_session {
	void *scst_session;	/* This should remain in the first place to
					enable easy access in lu_scst.c. */
	/* os dependent part */
	void   *os_data;
	chiscsi_queue *s_queue[SESS_Q_MAX];
	/* os independent part */
	iscsi_session *s_next;

	char    s_peer_name[256];
	iscsi_node *s_node;
	iscsi_thread_entry s_thinfo;
	iscsi_keyval *s_keys;

	unsigned char s_flag;
#define SESS_FLAG_API_SESS_ADDED	0x1
	unsigned char s_type;
	unsigned short s_tsih;
	unsigned long s_fbits;
	unsigned char s_isid[6];
	unsigned int s_portalgrouptag;
	
	unsigned long s_tclass_sess_priv;

	/* valid cmdsn window: expcmdsn ~ maxcmdsn, inclusive */
	unsigned int s_expcmdsn;
	unsigned int s_maxcmdsn;
	unsigned int s_cmdwin;

	unsigned int s_next_cid;
	/* Keep track of conn count for this session */
	unsigned int s_conn_cnt; 
	unsigned int s_counter;

	struct iscsi_session_settings setting;

	unsigned int s_task_tag;	/* for nop-in and text req/resp */
	unsigned int s_scmdqlen;
	unsigned int s_scmdmax;
	
	struct chiscsi_perf_info s_perf_info;

	void   *s_auth;

	iscsi_target_acl *acl;
	unsigned int acl_lu_cnt;
	unsigned int acl_lun_max;
	unsigned int *acl_lun_list;
};

#define ISCSI_SESSION_SIZE	(sizeof(iscsi_session))

#define session_enqueue(L,Q,P) \
			ch_enqueue_tail(L,iscsi_session,s_next,Q,P)
#define session_dequeue(L,Q,P) \
			ch_dequeue_head(L,iscsi_session,s_next,Q,P)
#define session_ch_qremove(L,Q,P) \
			ch_qremove(L,iscsi_session,s_next,Q,P)
#define session_qsearch_by_peername(L,Q,P,S) \
		ch_qsearch_by_field_string(L,iscsi_session,s_next,Q,P,s_peer_name,S)

#define iscsi_sess_flag_set(sess,bit)	\
			os_set_bit_atomic(&((sess)->s_fbits),bit)
#define iscsi_sess_flag_clear(sess,bit) \
			os_clear_bit_atomic(&((sess)->s_fbits),bit)
#define iscsi_sess_flag_test(sess,bit)	\
			os_test_bit_atomic(&((sess)->s_fbits),bit)
#define iscsi_sess_flag_testnset(sess,bit)	\
			os_test_and_set_bit_atomic(&((sess)->s_fbits),bit)
#define iscsi_sess_flag_testnclear(sess,bit) \
			os_test_and_clear_bit_atomic(&((sess)->s_fbits),bit)

static inline int iscsi_session_empty(iscsi_session * sess)
{
	int     conn_cnt = 1;
	if (sess) {
		chiscsi_queue *connq = sess->s_queue[SESS_CONNQ];
		os_lock(connq->q_lock);
		conn_cnt = connq->q_cnt;
		os_unlock(connq->q_lock);
	}
	return (!conn_cnt);
}

void iscsi_session_display(iscsi_session *, int detail);

/* allocation & free */
iscsi_session *iscsi_session_alloc(void);
int     iscsi_session_free(iscsi_session *);

int     iscsi_session_add_connection(iscsi_session *, iscsi_connection *);
iscsi_connection *iscsi_session_find_connection_by_cid(iscsi_session *,
						       unsigned short);

unsigned short iscsi_session_get_next_cid(iscsi_session *);
int     iscsi_session_clean_sentq(iscsi_session *);

unsigned int iscsi_session_next_non_cmd_tag(iscsi_session *);

/* */
void    iscsi_session_schedule_close(iscsi_session *);
int	iscsi_session_is_ffp(void *);

/* session - node */
void    iscsi_session_remove_from_node(iscsi_session *);
void    iscsi_session_add_to_node(iscsi_session *, iscsi_node *);

#endif /* ifndef __ISCSI_SESSION_H__ */
