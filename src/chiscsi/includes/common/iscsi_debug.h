#ifndef __ISCSI_DEBUG_H__
#define __ISCSI_DEBUG_H__

#include <common/iscsi_common.h>

/* log message level */
enum msg_level {
	ISCSI_MSG_ERR,
	ISCSI_MSG_WARN,
	ISCSI_MSG_INFO,
	ISCSI_MSG_DEBUG
};

/* debug message level, level should be less than # of bits in an unsigned long */
enum debug_level {
	ISCSI_DBG_MEM,
	ISCSI_DBG_MEM_PAGE,
	ISCSI_DBG_LOCK,
	ISCSI_DBG_WAIT,

	ISCSI_DBG_THREAD,
	ISCSI_DBG_CONFIG,
	ISCSI_DBG_NODE,
	ISCSI_DBG_SESS,

	ISCSI_DBG_CONN,
	ISCSI_DBG_PDU,
	ISCSI_DBG_PDU_TX,
	ISCSI_DBG_PDU_RX,

	ISCSI_DBG_SCSI,
	ISCSI_DBG_SCSI_COMMAND,
	ISCSI_DBG_TRANSPORT,
	ISCSI_DBG_TRANSPORT_MEM,

	ISCSI_DBG_ULP,
	ISCSI_DBG_NETDEV,
	ISCSI_DBG_ISNS,
	ISCSI_DBG_TARGET_API,

	ISCSI_DBG_TARGET_SCST,
	ISCSI_DBG_MODULE,
	ISCSI_DBG_DDP,
	ISCSI_DBG_PREMAP,
};

int	os_printf(const char *fmt, ...);
void    __os_log_msg(const char *, int, const char *, ...);

/* !!NOTE: the use of __VA_ARGS__ in the following macro requires 
   one mandatory parameter after fmt. */
#define os_log_error(fmt,...) \
	__os_log_msg(__func__, ISCSI_MSG_ERR, fmt, __VA_ARGS__)

#define os_log_warn(fmt,...) \
	__os_log_msg(__func__, ISCSI_MSG_WARN, fmt, __VA_ARGS__)

#define os_log_info(fmt,...) \
	__os_log_msg(__func__, ISCSI_MSG_INFO, fmt, __VA_ARGS__)

int	iscsi_msg_debug_level_on(int);
#define os_log_debug(dbglevel,fmt,...)	\
	do { \
		if (iscsi_msg_debug_level_on(dbglevel)) \
			__os_log_msg(__func__, ISCSI_MSG_DEBUG, fmt, __VA_ARGS__); \
	} while(0)

void    os_log_error_code(int, const char *, ...);

void    __os_debug_msg(const char *, const char *, ...);
#define os_debug_msg(fmt,...)	\
	__os_debug_msg(__FUNCTION__, fmt, __VA_ARGS__)

enum test_mode_bit {
	ISCSI_TST_BIT_NOUPD_EXPCMDSN,
	ISCSI_TST_BIT_NOZCOPY_DMA,
	ISCSI_TST_BIT_DROP_SCSI,
	ISCSI_TST_BIT_DROP_NOPOUT,
	ISCSI_TST_BIT_PAUSE_ACCEPT,
};

#define iscsi_test_mode_on(v, bit)	((v) & (1 << (bit)))

#endif /* ifndef __ISCSI_DEBUG_H__ */
