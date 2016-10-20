
#ifndef __ISCSI_COMMON_H__
#define __ISCSI_COMMON_H__

#include <common/iscsi_defs.h>
#include <common/iscsi_error.h>
#include <common/iscsi_debug.h>

/*
 * iSCSI statistics
 */

/* index into stats array iscsi_stats[] */
/* the corresponding name string is defined in kernel/common/os_common.c */
enum iscsi_stats_type {
	ISCSI_STAT_SESS,
	ISCSI_STAT_CONN,
	ISCSI_STAT_SBUF_RX,
	ISCSI_STAT_SBUF_TX,
	ISCSI_STAT_MEM,
	ISCSI_STAT_MEMPAGE,
	ISCSI_STAT_GL,

	ISCSI_STAT_MAX
};

enum log_bit {
	ISCSI_LOG_BIT_MEM,
	ISCSI_LOG_BIT_LOCK,
	ISCSI_LOG_BIT_THREAD,
	ISCSI_LOG_BIT_INITIATOR,
	ISCSI_LOG_BIT_TARGET,
	ISCSI_LOG_BIT_SESSION,
	ISCSI_LOG_BIT_CONNECTION,
	ISCSI_LOG_BIT_CONN_TX,
	ISCSI_LOG_BIT_CONN_RX,
	ISCSI_LOG_BIT_SOCKET,
	ISCSI_LOG_BIT_PDU,
	ISCSI_LOG_BIT_SCMD,
	ISCSI_LOG_BIT_CH_SCMD_RWIO
};

#define ISCSI_LOG_LEVEL_DFLT		0

/* 
 * iscsi common data structs
 */

/* thread common info. */
typedef struct iscsi_thread_common iscsi_thread_common;
struct iscsi_thread_common {
	char    name[40];
	unsigned int timeout;
	unsigned int id;
	void   *farg;
	int     (*finit) (void *);
	int     (*fproc) (void *);
	int     (*ftest) (void *);
	int     (*fdone) (void *);
};
#define thread_name(th_common)    (th_common).name
#define thread_timeout(th_common) (th_common).timeout
#define thread_id(th_common)	  (th_common).id
#define thread_farg(th_common)    (th_common).farg
#define thread_finit(th_common)   (th_common).finit
#define thread_fproc(th_common)   (th_common).fproc
#define thread_ftest(th_common)   (th_common).ftest
#define thread_fdone(th_common)   (th_common).fdone


#endif /* ifndef __ISCSI_COMMON_H__ */
