#ifndef __ISCSI_STRUCT_H__
#define __ISCSI_STRUCT_H__

#include <common/iscsi_lib_export.h>

//#include "chiscsi_queue.h"
#include "iscsi_thread.h"
#include "iscsi_text.h"

/*
 * configuration flag (used for change on the fly)
 */
#define ISCSI_CONFIG_FLAG_ADD		0x1
#define ISCSI_CONFIG_FLAG_REMOVE	0x2
#define ISCSI_CONFIG_FLAG_CHANGED	0x4
#define ISCSI_CONFIG_FLAG_INVALID	0x8

#define ISCSI_CONFIG_MASK	\
	(ISCSI_CONFIG_FLAG_ADD | \
	 ISCSI_CONFIG_FLAG_REMOVE | \
	 ISCSI_CONFIG_FLAG_CHANGED | \
	 ISCSI_CONFIG_FLAG_INVALID )


/*
 * base structs
 */

typedef struct iscsi_meta_ptr iscsi_meta_ptr;
typedef struct iscsi_table iscsi_table;

#define ISCSI_META_PTR_VALUE_COUNT	3
struct iscsi_meta_ptr {
	iscsi_meta_ptr *m_next;
	void   *m_datap;
	unsigned int m_val[ISCSI_META_PTR_VALUE_COUNT];
};

#define meta_ptr_enqueue(L,Q,P)	\
			ch_enqueue_tail(L,iscsi_meta_ptr,m_next,Q,P)
#define meta_ptr_dequeue(L,Q,P)	\
			ch_dequeue_head(L,iscsi_meta_ptr,m_next,Q,P)
#define meta_ptr_ch_qremove(L,Q,P)	\
			ch_qremove(L,iscsi_meta_ptr,m_next,Q,P)
#define meta_ptr_qsearch_by_datap(L,Q,P,V)	\
			ch_qsearch_by_field_value(L,iscsi_meta_ptr,m_next,Q,P,m_datap,V)

#define ISCSI_TABLE_DEFAULT_INCR	8
struct iscsi_table {
	/* os dependent part */
	void   *tbl_lock;
	/* os independent part */
	unsigned int tbl_size;
	unsigned int tbl_used;
	void  **tbl_entry;
};
#define ISCSI_TABLE_SIZE	(sizeof(iscsi_table) + os_lock_size)

#define for_each_table_entry(tbl, idx) \
		for (idx = 0; idx < (tbl)->tbl_size; idx++)

/* 
 * common iSCSI data structs
 */

typedef struct iscsi_isid iscsi_isid;
typedef struct iscsi_portal iscsi_portal;
typedef struct iscsi_node iscsi_node;
typedef struct iscsi_session iscsi_session;
typedef struct iscsi_connection iscsi_connection;

struct iscsi_isid {
	unsigned char t;
	unsigned char a;
	unsigned char c;
	unsigned char filler[1];
	unsigned short b;
	unsigned short d;
};

/*
 * other iSCSI structs defined
 */
#include <iscsi_portal.h>
#include <iscsi_pdu_defs.h>
#include <iscsi_node.h>
#include <iscsi_session.h>
#include <iscsi_connection.h>
#include <iscsi_sgvec_api.h>
#include <iscsi_scsi_command_api.h>

/*
 * struct function prototypes
 */

/* iscsi table */
void   *iscsi_enlarge_memory(void *, unsigned int, unsigned int, int);
void    iscsi_table_free(iscsi_table *, void (*fp_free_elem) (void *));
iscsi_table *iscsi_table_alloc(unsigned int);
int     iscsi_table_remove_element_by_ptr(iscsi_table *, void *);
int     iscsi_table_remove_element_by_idx(iscsi_table *, void *, int);
void   *iscsi_table_find_element_by_idx(iscsi_table *, int);
int     iscsi_table_add_element_by_idx(iscsi_table *, void *, int, int);
int     iscsi_table_add_element(iscsi_table *, void *, unsigned int);

/* iscsi thread */
int     iscsi_thread_add_data(iscsi_thread *, iscsi_thread_entry *, void *);
int     iscsi_thread_remove_data(iscsi_thread_entry *, void *);
int     iscsi_masked_list_queue_cleanup(chiscsi_queue *, int);
iscsi_thread *iscsi_thread_create(int);
void    iscsi_thread_destroy(iscsi_thread *, int);
int     iscsi_thread_start(iscsi_thread *, int);
int     iscsi_thread_stop(iscsi_thread *, int);
int     iscsi_thread_wakeup_all(int);
int     iscsi_thread_dummy_function(void *);

int     iscsi_distribute_connection(iscsi_connection *);
void    iscsi_schedule_session(iscsi_session *);
void    iscsi_schedule_connection(iscsi_connection *);
int     iscsi_thread_abort_all_connections(iscsi_thread *);
int     iscsi_thread_abort_all_sessions(iscsi_thread *);

void    iscsi_shutdown(void);

/* debug */
int     iscsi_display_byte_string(char *, unsigned char *, int, int, char *,
				  int);

/* provided by heartbeat */
int iscsi_connection_timeout_check(iscsi_connection *, 
				int (*)(iscsi_connection *));
#endif /* ifndef __ISCSI_STRUCT_H__ */
